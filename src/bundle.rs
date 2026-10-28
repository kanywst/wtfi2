//! `wtfi --bundle`: recorded sweeps as one Markdown document for an AI agent.

use crate::history::{self, Record, Snapshot};
use crate::platform::LogLine;
use serde_json::Value;
use std::hash::{BuildHasher, RandomState};

/// Newest full sweeps to include; older ones are counted, not shown.
const MAX_SWEEPS: usize = 12;
const MAX_TIMELINE: usize = 200;
/// OS log is read for the newest episodes only, from a little before each began.
const LOG_EPISODES: usize = 5;
const LOG_LEAD_SECS: u64 = 120;
const LOG_MAX_SECS: u64 = 720;
const LOG_MAX_LINES: usize = 150;
/// Lines kept from before an episode began; the rest of the budget goes after it.
const LOG_LEAD_LINES: usize = 30;
/// Total time `--bundle` spends reading OS logs.
const LOG_BUDGET: std::time::Duration = std::time::Duration::from_secs(60);
/// A recorder that planned to sweep in N seconds but didn't within N+60 wasn't running.
const GAP_SLACK_SECS: u64 = 60;
/// Assumed spacing for records that don't say (one-shot runs, older history).
const UNKNOWN_INTERVAL_SECS: u64 = 600;

type Field = fn(&Record) -> Option<f64>;

/// One run of consecutive unhealthy sweeps.
#[derive(Debug, Clone, PartialEq)]
pub struct Episode {
    pub start: u64,
    /// The first healthy sweep after it, if there was one.
    pub end: Option<u64>,
    /// The last unhealthy sweep in it.
    pub last: u64,
    /// The recorder stopped before it ended, so its true length is unknown.
    pub cut: bool,
    pub worst: String,
    pub first_break: Option<String>,
    pub headline: String,
    pub sweeps: usize,
}

pub fn episodes(records: &[Record]) -> Vec<Episode> {
    let mut out: Vec<Episode> = Vec::new();
    let mut open = false;
    let mut prev: Option<&Record> = None;
    for r in records {
        if open && prev.is_some_and(|p| is_gap(p, r)) {
            out.last_mut().unwrap().cut = true;
            open = false;
        }
        prev = Some(r);
        // Only partly measured: neither proof of recovery nor of an outage.
        if r.partial {
            continue;
        }
        match r.status.as_str() {
            "ok" => {
                if open {
                    out.last_mut().unwrap().end = Some(r.ts);
                    open = false;
                }
                continue;
            }
            "warn" | "fail" => {}
            _ => continue,
        }
        if !open {
            out.push(Episode {
                start: r.ts,
                end: None,
                last: r.ts,
                cut: false,
                worst: r.status.clone(),
                first_break: r.first_break.clone(),
                headline: r.headline.clone(),
                sweeps: 0,
            });
            open = true;
        }
        let e = out.last_mut().unwrap();
        e.sweeps += 1;
        e.last = r.ts;
        if rank(&r.status) > rank(&e.worst) {
            e.worst = r.status.clone();
            e.first_break = r.first_break.clone();
            e.headline = r.headline.clone();
        }
    }
    out
}

fn rank(status: &str) -> u8 {
    match status {
        "fail" => 3,
        "warn" => 2,
        "ok" => 0,
        _ => 1,
    }
}

/// Spans where the recorder said when it would sweep next and then didn't.
pub fn gaps(records: &[Record]) -> Vec<(u64, u64)> {
    records
        .windows(2)
        .filter(|w| is_gap(&w[0], &w[1]))
        .map(|w| (w[0].ts, w[1].ts))
        .collect()
}

fn is_gap(a: &Record, b: &Record) -> bool {
    b.ts > a.ts + a.interval_s.unwrap_or(UNKNOWN_INTERVAL_SECS) + GAP_SLACK_SECS
}

/// Whether nothing has been recorded since `last` for longer than its planned interval.
fn stale(last: &Record, now: u64) -> bool {
    now > last.ts + last.interval_s.unwrap_or(UNKNOWN_INTERVAL_SECS) + GAP_SLACK_SECS
}

pub type LogReader<'a> = &'a dyn Fn(u64, u64) -> Result<Vec<LogLine>, String>;

/// `redact` salts the masks; pass the same state to get the same tags across calls.
pub fn build(
    records: &[Record],
    sweeps: &[Snapshot],
    since: u64,
    redact: Option<&RandomState>,
    log: LogReader,
) -> String {
    let owned: Vec<Record> = records.iter().filter(|r| r.ts >= since).cloned().collect();
    let sweeps: Vec<&Snapshot> = sweeps.iter().filter(|s| s.ts >= since).collect();
    let redactor = redact.map(|state| Redactor::new(state, &sweeps));
    let mut out = String::new();

    out.push_str("# wtfi network report\n\n");
    out.push_str(&format!(
        "Recorded by wtfi {} on {} ({}). Times are UTC.\n\n",
        env!("CARGO_PKG_VERSION"),
        std::env::consts::OS,
        std::env::consts::ARCH,
    ));
    let (Some(first), Some(last)) = (owned.first(), owned.last()) else {
        out.push_str("No sweeps were recorded in this window. Run `wtfi --record --every 30s` and try again after the next outage.\n");
        return out;
    };
    out.push_str(&format!(
        "Window: {} to {}, {} sweeps.\n",
        history::utc(first.ts),
        history::utc(last.ts),
        owned.len()
    ));
    if redact.is_some() {
        out.push_str("SSIDs, MAC addresses, public IPv4 addresses other than the probe anchors, this machine's IPv6 addresses and portal query strings are masked.\n");
    }

    let now = history::now_secs();
    let mut eps = episodes(&owned);
    if stale(last, now)
        && let Some(e) = eps.last_mut().filter(|e| e.end.is_none())
    {
        e.cut = true;
    }
    out.push_str("\n## Episodes\n\n");
    let partial = owned.iter().filter(|r| r.partial).count();
    if eps.is_empty() && partial == 0 {
        out.push_str("Every sweep in this window was healthy.\n");
    } else if eps.is_empty() {
        out.push_str(&format!(
            "No outage was measured, but {partial} sweeps were only partly measured.\n"
        ));
    } else {
        out.push_str("| Start | Duration | Sweeps | Worst | First break | Headline |\n");
        out.push_str("| --- | --- | --- | --- | --- | --- |\n");
        for e in &eps {
            let duration = match e.end {
                Some(end) => span(end.saturating_sub(e.start)),
                None if e.cut => format!(
                    "at least {}, then the recorder stopped",
                    span(e.last.saturating_sub(e.start))
                ),
                None => format!("ongoing at {}", history::utc(last.ts)),
            };
            out.push_str(&format!(
                "| {} | {duration} | {} | {} | {} | {} |\n",
                history::utc(e.start),
                e.sweeps,
                e.worst,
                e.first_break.as_deref().unwrap_or("—"),
                e.headline
            ));
        }
    }

    let mut gaps = gaps(&owned);
    if stale(last, now) {
        gaps.push((last.ts, now));
    }
    if !gaps.is_empty() {
        out.push_str("\n## Recorder not running\n\n");
        out.push_str(
            "No data for these spans (machine asleep, recorder stopped). They are not outages.\n\n",
        );
        for (from, to) in gaps {
            out.push_str(&format!(
                "- {} to {} ({})\n",
                history::utc(from),
                history::utc(to),
                span(to - from)
            ));
        }
    }

    out.push_str("\n## Latency and signal\n\n");
    out.push_str(
        "| Metric | Samples | p50 | Worst 5% | Worst |\n| --- | --- | --- | --- | --- |\n",
    );
    let rows: [(&str, Field, bool, usize); 4] = [
        ("Gateway RTT (ms)", |r| r.gateway_ms, true, 1),
        ("Internet RTT (ms)", |r| r.wan_ms, true, 1),
        ("Internet loss (%)", |r| r.wan_loss_pct, true, 1),
        ("Wi-Fi RSSI (dBm)", |r| r.rssi_dbm, false, 0),
    ];
    for (label, get, higher_is_worse, dp) in rows {
        let mut v: Vec<f64> = owned.iter().filter_map(get).collect();
        v.sort_by(f64::total_cmp);
        if !higher_is_worse {
            v.reverse();
        }
        match (pct(&v, 50.0), pct(&v, 95.0), v.last()) {
            (Some(p50), Some(p95), Some(worst)) => out.push_str(&format!(
                "| {label} | {} | {p50:.dp$} | {p95:.dp$} | {worst:.dp$} |\n",
                v.len()
            )),
            _ => out.push_str(&format!("| {label} | 0 | — | — | — |\n")),
        }
    }

    out.push_str("\n## Timeline\n\nOne line per run of identical state; `×N` is how many sweeps it lasted.\n\n```text\n");
    let timeline = timeline(&owned);
    if timeline.len() > MAX_TIMELINE {
        out.push_str(&format!(
            "({} older lines omitted)\n",
            timeline.len() - MAX_TIMELINE
        ));
    }
    for line in timeline
        .iter()
        .skip(timeline.len().saturating_sub(MAX_TIMELINE))
    {
        out.push_str(line);
        out.push('\n');
    }
    out.push_str("```\n");

    out.push_str("\n## Full sweeps around each change\n\n");
    if sweeps.is_empty() {
        out.push_str("None recorded in this window.\n");
    } else {
        let skip = sweeps.len().saturating_sub(MAX_SWEEPS);
        if skip > 0 {
            out.push_str(&format!("{skip} older sweeps omitted.\n\n"));
        }
        for s in &sweeps[skip..] {
            let mut sweep = s.sweep.clone();
            prune(&mut sweep);
            if let Some(r) = &redactor {
                r.sweep(&mut sweep);
            }
            out.push_str(&format!(
                "<sweep at=\"{}\">\n\n```json\n{}\n```\n\n</sweep>\n\n",
                history::utc(s.ts),
                serde_json::to_string(&sweep).unwrap_or_default()
            ));
        }
    }

    if !eps.is_empty() {
        out.push_str("\n## OS network log\n\nWi-Fi, DHCP, interface and DNS events the OS logged around the newest episodes. Repeated lines are collapsed.\n");
        let started = std::time::Instant::now();
        for e in eps.iter().skip(eps.len().saturating_sub(LOG_EPISODES)) {
            let from = e.start.saturating_sub(LOG_LEAD_SECS);
            let to = e.end.unwrap_or(last.ts).min(e.start + LOG_MAX_SECS) + 60;
            out.push_str(&format!(
                "\n### {} to {}\n\n",
                history::utc(from),
                history::utc(to)
            ));
            if started.elapsed() > LOG_BUDGET {
                out.push_str("Skipped: reading the OS log was taking too long.\n");
                continue;
            }
            let focus = history::utc(e.start);
            match log(from, to) {
                Ok(lines) if lines.is_empty() => out.push_str("Nothing logged.\n"),
                Ok(lines) => out.push_str(&log_block(&lines, focus.get(11..19), redactor.as_ref())),
                Err(e) => out.push_str(&format!("Couldn't read the OS log: {e}\n")),
            }
        }
    }

    out.push_str(PROMPT);
    match redactor {
        Some(r) => r.text(&out),
        None => out,
    }
}

/// A fenced block of collapsed, capped and (when asked) masked log lines.
/// `focus` (`HH:MM:SS`) keeps the cap centred on when an episode began.
pub fn log_block(lines: &[LogLine], focus: Option<&str>, redactor: Option<&Redactor>) -> String {
    let at = focus.map_or(0, |t| {
        lines
            .iter()
            .position(|l| l.time.as_str() >= t)
            .unwrap_or(lines.len())
    });
    let (before, after) = (collapse(&lines[..at]), collapse(&lines[at..]));
    let lead = &before[before
        .len()
        .saturating_sub(LOG_LEAD_LINES.min(LOG_MAX_LINES))..];
    let skipped = before.len() - lead.len();
    let lines: Vec<String> = lead.iter().chain(&after).cloned().collect();
    let mut out = String::from("```text\n");
    if skipped > 0 {
        out.push_str(&format!("({skipped} earlier lines omitted)\n"));
    }
    for line in lines.iter().take(LOG_MAX_LINES) {
        match redactor {
            Some(r) => out.push_str(&r.text(&r.log_line(line))),
            None => out.push_str(line),
        }
        out.push('\n');
    }
    if lines.len() > LOG_MAX_LINES {
        out.push_str(&format!(
            "({} more lines omitted)\n",
            lines.len() - LOG_MAX_LINES
        ));
    }
    out.push_str("```\n");
    out
}

/// Consecutive identical lines become one, with `×N`.
fn collapse(lines: &[LogLine]) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let l = &lines[i];
        let run = lines[i..]
            .iter()
            .take_while(|o| o.source == l.source && o.message == l.message)
            .count();
        let tail = if run > 1 {
            format!(" ×{run}")
        } else {
            String::new()
        };
        out.push(format!("{} {}: {}{tail}", l.time, l.source, l.message));
        i += run;
    }
    out
}

fn timeline(records: &[Record]) -> Vec<String> {
    let mut lines = Vec::new();
    let mut i = 0;
    while i < records.len() {
        let r = &records[i];
        let same = |o: &Record| {
            o.status == r.status && o.first_break == r.first_break && o.headline == r.headline
        };
        // A run stops at a recorder gap, so it never spans time nobody measured.
        let run = 1 + records[i..]
            .windows(2)
            .take_while(|w| same(&w[1]) && !is_gap(&w[0], &w[1]))
            .count();
        let tail = if run > 1 {
            format!("  ×{run} until {}", history::utc(records[i + run - 1].ts))
        } else {
            String::new()
        };
        lines.push(format!("{}{tail}", history::line(r)));
        i += run;
    }
    lines
}

fn pct(sorted: &[f64], p: f64) -> Option<f64> {
    let i = ((p / 100.0) * (sorted.len() as f64 - 1.0)).round() as usize;
    sorted.get(i).copied()
}

fn span(secs: u64) -> String {
    match secs {
        s if s < 60 => format!("{s}s"),
        s if s < 3600 => format!("{}m {}s", s / 60, s % 60),
        s => format!("{}h {}m", s / 3600, s / 60 % 60),
    }
}

/// Drop nulls and empty arrays so each sweep costs fewer tokens.
fn prune(v: &mut Value) {
    match v {
        Value::Object(map) => {
            map.retain(|_, x| !x.is_null() && !matches!(x, Value::Array(a) if a.is_empty()));
            map.values_mut().for_each(prune);
        }
        Value::Array(a) => a.iter_mut().for_each(prune),
        _ => {}
    }
}

/// Addresses wtfi probes itself; masking them would only hide what was measured.
const ANCHORS: [&str; 6] = [
    "1.1.1.1",
    "1.0.0.1",
    "8.8.8.8",
    "8.8.4.4",
    "9.9.9.9",
    "149.112.112.112",
];

pub struct Redactor<'a> {
    state: &'a RandomState,
    ssids: Vec<String>,
    swaps: Vec<(String, String)>,
}

impl<'a> Redactor<'a> {
    pub fn new(state: &'a RandomState, sweeps: &[&Snapshot]) -> Self {
        let mut r = Redactor {
            state,
            ssids: Vec::new(),
            swaps: Vec::new(),
        };
        for s in sweeps {
            let Some(hops) = s.sweep["path"].as_array() else {
                continue;
            };
            let iface = hops
                .iter()
                .find(|h| h["id"] == "host")
                .and_then(|h| metric(h, "Interface"));
            for h in hops {
                if h["id"] == "link"
                    && let Some(ssid) = h["subtitle"].as_str()
                    && Some(ssid) != iface
                    && !r.ssids.iter().any(|s| s == ssid)
                {
                    r.ssids.push(ssid.into());
                }
                for m in h["metrics"].as_array().into_iter().flatten() {
                    let Some(value) = m["value"].as_str().filter(|v| !v.is_empty()) else {
                        continue;
                    };
                    let masked = match m["label"].as_str() {
                        Some("IPv6" | "Public IP" | "Tunnel IP") => mask_ip(value),
                        Some("Portal") => match value.split_once('?') {
                            Some((base, _)) => format!("{base}?…"),
                            None => continue,
                        },
                        _ => continue,
                    };
                    if !r.swaps.iter().any(|(k, _)| k == value) {
                        r.swaps.push((value.into(), masked));
                    }
                }
            }
        }
        r.swaps.sort_by_key(|(k, _)| std::cmp::Reverse(k.len()));
        r
    }

    /// Mask a sweep in place: its SSID field, then every string in it.
    pub fn sweep(&self, v: &mut Value) {
        if let Some(hops) = v["path"].as_array_mut() {
            for h in hops.iter_mut().filter(|h| h["id"] == "link") {
                let ssid = h["subtitle"].as_str().map(str::to_string);
                if let Some(ssid) = ssid.filter(|s| self.ssids.contains(s)) {
                    h["subtitle"] = self.ssid(&ssid).into();
                }
            }
        }
        self.strings(v);
    }

    fn strings(&self, v: &mut Value) {
        match v {
            Value::String(s) => *s = self.text(s),
            Value::Array(a) => a.iter_mut().for_each(|x| self.strings(x)),
            Value::Object(m) => m.values_mut().for_each(|x| self.strings(x)),
            _ => {}
        }
    }

    /// Learned addresses and portal URLs, other public IPv4s, and MACs.
    pub fn text(&self, text: &str) -> String {
        let mut out = text.to_string();
        for (k, v) in &self.swaps {
            out = out.replace(k.as_str(), v);
        }
        self.macs(&mask_public_v4(&out))
    }

    /// SSIDs named in a log line, in the forms configd, wpa_supplicant and NetworkManager print.
    pub fn log_line(&self, line: &str) -> String {
        let mut line = line.to_string();
        for known in self.ssids.iter().filter(|s| s.chars().count() >= 4) {
            line = replace_word(&line, known, &self.ssid(known));
        }
        if [" NetworkManager: ", " wpa_supplicant: ", " iwd: "]
            .iter()
            .any(|s| line.contains(s))
        {
            line = self.quoted(&line);
        }
        let lower = line.to_ascii_lowercase();
        let b = line.as_bytes();
        let mut out = String::with_capacity(line.len());
        let (mut at, mut from) = (0, 0);
        while let Some(k) = lower[from..].find("ssid").map(|k| k + from) {
            from = k + 4;
            if lower[..k]
                .chars()
                .next_back()
                .is_some_and(|c| c.is_ascii_alphabetic())
            {
                continue;
            }
            let mut v = k + 4;
            if matches!(b.get(v), Some(b'\'' | b'"')) && lower[v + 1..].starts_with(" value ") {
                v += 7;
            }
            let key_end = v;
            while matches!(b.get(v), Some(b' ' | b'=' | b':')) {
                v += 1;
            }
            let (start, end) = match b.get(v) {
                Some(&q @ (b'\'' | b'"')) => {
                    let end = line[v + 1..]
                        .find(q as char)
                        .map_or(line.len(), |j| v + 1 + j);
                    (v + 1, end)
                }
                _ if v == key_end => continue,
                _ => {
                    let tail = &line[v..];
                    let end = tail
                        .find(" BSSID ")
                        .or_else(|| tail.find([' ', ',', ')', ';']))
                        .map_or(line.len(), |j| v + j);
                    (v, end)
                }
            };
            let name = &line[start..end];
            if name.is_empty() || name.starts_with('<') || name.starts_with("ssid-") {
                continue;
            }
            out.push_str(&line[at..start]);
            out.push_str(&self.ssid(name));
            at = end;
            from = end;
        }
        out.push_str(&line[at..]);
        out
    }

    /// Every `'…'` value, which is how these daemons quote SSIDs and connection names.
    fn quoted(&self, line: &str) -> String {
        let mut out = String::with_capacity(line.len());
        let mut rest = line;
        while let Some(i) = rest.find('\'') {
            let Some(j) = rest[i + 1..].find('\'') else {
                break;
            };
            let name = &rest[i + 1..i + 1 + j];
            out.push_str(&rest[..=i]);
            if name.is_empty() || name.starts_with('<') || name.starts_with("ssid-") {
                out.push_str(name);
            } else {
                out.push_str(&self.ssid(name));
            }
            out.push('\'');
            rest = &rest[i + j + 2..];
        }
        out.push_str(rest);
        out
    }

    fn ssid(&self, name: &str) -> String {
        format!("ssid-{}", self.tag(name))
    }

    fn tag(&self, s: &str) -> String {
        format!("{:04x}", self.state.hash_one(s) & 0xffff)
    }

    fn macs(&self, text: &str) -> String {
        let mut out = String::with_capacity(text.len());
        let mut rest = text;
        while let Some((i, mac)) = find_mac(rest) {
            out.push_str(&rest[..i]);
            let canonical: Vec<String> = mac
                .split([':', '-'])
                .map(|g| format!("{:0>2}", g.to_ascii_lowercase()))
                .collect();
            out.push_str(&format!("mac-{}", self.tag(&canonical.join(":"))));
            rest = &rest[i + mac.len()..];
        }
        out.push_str(rest);
        out
    }
}

/// Replace `word` only where it isn't part of a longer word.
fn replace_word(text: &str, word: &str, with: &str) -> String {
    let edge = |c: Option<char>| c.is_none_or(|c| !c.is_alphanumeric());
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(i) = rest.find(word) {
        out.push_str(&rest[..i]);
        let after = &rest[i + word.len()..];
        let whole = edge(out.chars().next_back()) && edge(after.chars().next());
        out.push_str(if whole { with } else { word });
        rest = after;
    }
    out.push_str(rest);
    out
}

fn metric<'a>(hop: &'a Value, label: &str) -> Option<&'a str> {
    hop["metrics"]
        .as_array()?
        .iter()
        .find(|m| m["label"] == label)?["value"]
        .as_str()
}

/// Keep the network part: `/24` for IPv4, `/64` for IPv6.
fn mask_ip(ip: &str) -> String {
    let addr = ip.split('/').next().unwrap_or(ip);
    match addr.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => {
            let o = v4.octets();
            format!("{}.{}.{}.x", o[0], o[1], o[2])
        }
        Ok(std::net::IpAddr::V6(v6)) => {
            let s = v6.segments();
            format!("{:x}:{:x}:{:x}:{:x}::x", s[0], s[1], s[2], s[3])
        }
        Err(_) => "x".into(),
    }
}

fn mask_public_v4(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(i) = rest.find(|c: char| c.is_ascii_digit()) {
        let len = rest[i..]
            .find(|c: char| !c.is_ascii_digit() && c != '.')
            .unwrap_or(rest.len() - i);
        let token = &rest[i..i + len];
        let end = token.match_indices('.').nth(3).map_or(len, |(j, _)| j);
        let addr = &token[..end];
        out.push_str(&rest[..i]);
        match addr.parse::<std::net::Ipv4Addr>() {
            Ok(ip) if is_public(ip) && !ANCHORS.contains(&addr) => {
                out.push_str(&mask_ip(addr));
                out.push_str(&token[end..]);
            }
            _ => out.push_str(token),
        }
        rest = &rest[i + len..];
    }
    out.push_str(rest);
    out
}

fn is_public(ip: std::net::Ipv4Addr) -> bool {
    let o = ip.octets();
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_documentation()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_multicast()
        || o[0] == 100 && (64..128).contains(&o[1]))
}

/// The first MAC address (`:` or `-`, leading zeros optional) and where it starts.
fn find_mac(text: &str) -> Option<(usize, &str)> {
    let b = text.as_bytes();
    let hex = |i: usize| b.get(i).is_some_and(u8::is_ascii_hexdigit);
    (0..b.len()).find_map(|start| {
        if !hex(start) || start > 0 && (hex(start - 1) || matches!(b[start - 1], b':' | b'-')) {
            return None;
        }
        let mut i = start;
        let mut sep = None;
        for g in 0..6 {
            let n = (i..i + 3).take_while(|&j| hex(j)).count();
            if !(1..=2).contains(&n) {
                return None;
            }
            i += n;
            if g < 5 {
                let s = *b.get(i)?;
                if !matches!(s, b':' | b'-') || sep.is_some_and(|p| p != s) {
                    return None;
                }
                sep = Some(s);
                i += 1;
            }
        }
        let clean_end = b
            .get(i)
            .is_none_or(|c| !c.is_ascii_hexdigit() && Some(*c) != sep);
        clean_end.then(|| (start, &text[start..i]))
    })
}

const PROMPT: &str = "
## What I need from you

The data above was recorded by wtfi, a network-path diagnostic, while my connection was failing or slow. Each sweep probes the path in order: host (my machine), link (Wi-Fi), gateway (my router), wan (reachability of public anchors), dns, captive (portal check), and a vpn hop when a tunnel is up. `first_break` is the first hop that failed; `evidence` says how each hop was measured.

1. For each episode, say which layer broke first (the OS network log, when present, often shows the Wi-Fi or DHCP event behind it) and what most likely caused it. Quote the records or sweep fields you rely on.
2. Say whether the episodes share a cause or look unrelated.
3. Keep what the data shows apart from what you infer, and say when it can't decide between causes.
4. List concrete next steps, most likely fix first, and what I should capture next time to settle what is still open.
";

#[cfg(test)]
mod tests {
    use super::*;

    fn no_log(_: u64, _: u64) -> Result<Vec<LogLine>, String> {
        Ok(Vec::new())
    }

    fn line(time: &str, message: &str) -> LogLine {
        LogLine {
            time: time.into(),
            source: "configd".into(),
            message: message.into(),
        }
    }

    #[test]
    fn os_log_is_read_around_each_episode_and_collapsed() {
        let r = [
            rec(1000, "ok", None, None),
            rec(1010, "fail", Some("link"), None),
            rec(5000, "ok", None, None),
        ];
        let asked = std::cell::RefCell::new(Vec::new());
        let log = |from, to| {
            asked.borrow_mut().push((from, to));
            Ok(vec![
                line(
                    "00:16:48",
                    "en0: SSID Cafe Wifi BSSID 00:11:22:33:44:55 Security NONE",
                ),
                line("00:16:49", "DHCP en0: RENEW"),
                line("00:16:49", "DHCP en0: RENEW"),
                line(
                    "00:16:50",
                    "DNS 203.0.113.9 failed, 9.9.9.9 ok, router 192.168.1.1",
                ),
                line("00:16:51", "server 93.184.215.14 unreachable"),
            ])
        };
        let out = build(&r, &[], 0, Some(&RandomState::new()), &log);
        assert_eq!(
            *asked.borrow(),
            [(890, 1790)],
            "2 min before, capped 12 min after, +1 min"
        );
        assert!(out.contains("DHCP en0: RENEW ×2"), "{out}");
        assert!(
            !out.contains("Cafe Wifi") && !out.contains("00:11:22"),
            "{out}"
        );
        assert!(
            out.contains("SSID ssid-") && out.contains("BSSID mac-"),
            "{out}"
        );
        assert!(out.contains("93.184.215.x unreachable"), "{out}");
        assert!(
            out.contains("9.9.9.9 ok") && out.contains("192.168.1.1"),
            "{out}"
        );

        let failing = |_, _| Err("log: permission denied".to_string());
        let out = build(&r, &[], 0, Some(&RandomState::new()), &failing);
        assert!(out.contains("Couldn't read the OS log: log: permission denied"));
        assert!(build(&r, &[], 0, None, &log).contains("Cafe Wifi"));
    }

    #[test]
    fn a_long_log_says_how_much_it_dropped() {
        let lines: Vec<LogLine> = (0..LOG_MAX_LINES + 7)
            .map(|i| line("00:00:00", &format!("event {i}")))
            .collect();
        let block = log_block(&lines, None, None);
        assert!(
            block.contains("event 149\n(7 more lines omitted)"),
            "{block}"
        );
    }

    #[test]
    fn the_cap_keeps_the_lines_around_the_break() {
        let lines: Vec<LogLine> = (0..400)
            .map(|i| {
                line(
                    &format!("00:{:02}:{:02}", i / 60, i % 60),
                    &format!("event {i}"),
                )
            })
            .collect();
        let block = log_block(&lines, Some("00:05:00"), None);
        assert!(block.contains("(270 earlier lines omitted)"), "{block}");
        assert!(
            block.contains("event 270\n") && block.contains("event 300\n"),
            "{block}"
        );
        assert!(
            block.contains("event 399\n") && !block.contains("more lines omitted"),
            "{block}"
        );
    }

    #[test]
    fn network_manager_names_are_masked_without_an_ssid_keyword() {
        let state = RandomState::new();
        let r = Redactor::new(&state, &[]);
        let out = r.log_line("12:00:00 NetworkManager: <info> device (wlan0): Activation: (wifi) access point 'Foo Bar' has security");
        assert!(
            !out.contains("Foo Bar") && out.contains("access point 'ssid-"),
            "{out}"
        );
        let kept = "12:00:00 configd: DHCP en0: status = 'media inactive'";
        assert_eq!(
            r.log_line(kept),
            kept,
            "other sources keep their quoted values"
        );
    }

    #[test]
    fn ssids_are_masked_in_every_log_form() {
        let state = RandomState::new();
        let s = sweep_with("Known Net", "198.51.100.77", "x");
        let r = Redactor::new(&state, &[&s]);
        for (input, leak) in [
            (
                "Trying to associate with SSID 'My Home' freq=5180",
                "My Home",
            ),
            (
                "wlan0: SME: Trying to authenticate (SSID='My Home' freq=2412 MHz)",
                "My Home",
            ),
            (
                "CTRL-EVENT-SSID-TEMP-DISABLED id=0 ssid=\"My Home\" auth_failures=1",
                "My Home",
            ),
            ("Config: added 'ssid' value 'My Home'", "My Home"),
            ("en0: SSID Cafe Wifi BSSID x", "Cafe Wifi"),
            ("ssid: \\xe8\\x87\\xaa\\xe5 connected", "xe8"),
            ("roamed to Known Net on ch 36", "Known Net"),
        ] {
            let out = r.log_line(input);
            assert!(!out.contains(leak), "{input:?} -> {out:?}");
            assert!(out.contains("ssid-"), "{input:?} -> {out:?}");
        }
        assert!(
            r.log_line("CTRL-EVENT-SSID-TEMP-DISABLED id=0")
                .contains("-TEMP-DISABLED")
        );
        for same in [
            "en0: no SSID",
            "NetworkID <redacted> SSID <redacted>",
            "BSSID 00:11:22:33:44:55",
        ] {
            assert_eq!(r.log_line(same), same);
        }
        assert!(
            r.log_line("SSID 自宅のWi-Fi BSSID x")
                .starts_with("SSID ssid-")
        );
    }

    fn rec(ts: u64, status: &str, brk: Option<&str>, interval: Option<u64>) -> Record {
        Record {
            ts,
            status: status.into(),
            first_break: brk.map(Into::into),
            headline: format!("{status} headline"),
            gateway_ms: Some(ts as f64),
            wan_ms: None,
            wan_loss_pct: None,
            rssi_dbm: None,
            interval_s: interval,
            partial: false,
        }
    }

    #[test]
    fn unhealthy_runs_become_episodes() {
        let r = [
            rec(0, "ok", None, None),
            rec(10, "warn", Some("wan"), None),
            rec(20, "fail", Some("dns"), None),
            rec(30, "ok", None, None),
            rec(40, "fail", Some("gateway"), None),
        ];
        let e = episodes(&r);
        assert_eq!(e.len(), 2);
        assert_eq!((e[0].start, e[0].end, e[0].sweeps), (10, Some(30), 2));
        assert_eq!(e[0].worst, "fail");
        assert_eq!(
            e[0].first_break.as_deref(),
            Some("dns"),
            "named by the worst sweep"
        );
        assert_eq!((e[1].start, e[1].end), (40, None));
    }

    #[test]
    fn a_recorder_gap_ends_an_episode_instead_of_stretching_it() {
        let r = [
            rec(0, "ok", None, Some(30)),
            rec(30, "fail", Some("dns"), Some(5)),
            rec(35, "fail", Some("dns"), Some(5)),
            rec(9000, "ok", None, Some(30)),
        ];
        let e = episodes(&r);
        assert_eq!((e[0].end, e[0].last, e[0].cut), (None, 35, true));
        let out = build(&r, &[], 0, None, &no_log);
        assert!(
            out.contains("at least 5s, then the recorder stopped"),
            "{out}"
        );
        let row = out.lines().find(|l| l.contains("| dns |")).unwrap();
        assert!(!row.contains("2h"), "{row}");
    }

    #[test]
    fn a_timeline_run_stops_at_a_recorder_gap() {
        let r = [
            rec(0, "fail", Some("dns"), Some(30)),
            rec(30, "fail", Some("dns"), Some(30)),
            rec(28_800, "fail", Some("dns"), Some(30)),
        ];
        let t = timeline(&r);
        assert_eq!(t.len(), 2, "{t:?}");
        assert!(t[0].ends_with("×2 until 1970-01-01 00:00:30Z"), "{}", t[0]);
    }

    #[test]
    fn a_partial_sweep_neither_starts_nor_ends_an_episode() {
        let mut middle = rec(10, "ok", None, None);
        middle.partial = true;
        let r = [
            rec(0, "fail", Some("dns"), None),
            middle,
            rec(20, "fail", Some("dns"), None),
            rec(30, "ok", None, None),
        ];
        let e = episodes(&r);
        assert_eq!(e.len(), 1, "{e:?}");
        assert_eq!((e[0].start, e[0].end), (0, Some(30)));
        let mut lone = rec(10, "warn", None, None);
        lone.partial = true;
        assert!(episodes(&[rec(0, "ok", None, None), lone, rec(20, "ok", None, None)]).is_empty());
    }

    #[test]
    fn a_stale_tail_is_not_called_ongoing() {
        let now = history::now_secs();
        let old = [rec(now - 86_400, "fail", Some("dns"), Some(30))];
        let out = build(&old, &[], 0, None);
        assert!(!out.contains("ongoing"), "{out}");
        assert!(
            out.contains("then the recorder stopped") && out.contains("## Recorder not running"),
            "{out}"
        );
        let fresh = [rec(now - 5, "fail", Some("dns"), Some(30))];
        assert!(build(&fresh, &[], 0, None).contains("ongoing at"));
    }

    #[test]
    fn small_losses_and_rtts_keep_a_decimal() {
        let mut r = rec(0, "ok", None, None);
        r.gateway_ms = Some(0.4);
        r.wan_loss_pct = Some(0.4);
        let out = build(&[r], &[], 0, None);
        assert!(
            out.contains("| Gateway RTT (ms) | 1 | 0.4 | 0.4 | 0.4 |"),
            "{out}"
        );
        assert!(
            out.contains("| Internet loss (%) | 1 | 0.4 | 0.4 | 0.4 |"),
            "{out}"
        );
    }

    #[test]
    fn an_empty_address_is_not_a_mask() {
        let s = Snapshot {
            ts: 0,
            sweep: serde_json::json!({ "path": [{ "id": "host", "metrics": [{ "label": "IPv6", "value": "" }] }] }),
        };
        let state = RandomState::new();
        assert_eq!(Redactor::new(&state, &[&s]).text("abc"), "abc");
    }

    #[test]
    fn unmeasured_sweeps_are_not_outages() {
        let r = [
            rec(0, "ok", None, None),
            rec(10, "skipped", None, None),
            rec(20, "ok", None, None),
        ];
        assert!(episodes(&r).is_empty());
    }

    #[test]
    fn rssi_reports_its_weakest_readings_as_worst() {
        let mut r: Vec<Record> = (0..20).map(|i| rec(i, "ok", None, None)).collect();
        for (i, x) in r.iter_mut().enumerate() {
            x.rssi_dbm = Some(-40.0 - i as f64);
        }
        let out = build(&r, &[], 0, None, &no_log);
        assert!(
            out.contains("| Wi-Fi RSSI (dBm) | 20 | -50 | -58 | -59 |"),
            "{out}"
        );
    }

    #[test]
    fn only_a_missed_planned_sweep_is_a_gap() {
        let r = [
            rec(0, "ok", None, Some(30)),
            rec(30, "ok", None, Some(30)),
            rec(1000, "ok", None, None),
            rec(1500, "ok", None, None),
            rec(9000, "ok", None, None),
        ];
        assert_eq!(
            gaps(&r),
            [(30, 1000), (1500, 9000)],
            "without an interval, assume 10 minutes"
        );
    }

    #[test]
    fn identical_sweeps_collapse_in_the_timeline() {
        let r = [
            rec(0, "ok", None, None),
            rec(1, "ok", None, None),
            rec(2, "fail", Some("dns"), None),
            rec(3, "ok", None, None),
        ];
        let t = timeline(&r);
        assert_eq!(t.len(), 3);
        assert!(t[0].ends_with("×2 until 1970-01-01 00:00:01Z"), "{}", t[0]);
    }

    #[test]
    fn percentiles_use_nearest_rank() {
        let v: Vec<f64> = (1..=100).map(f64::from).collect();
        assert_eq!(pct(&v, 50.0), Some(51.0));
        assert_eq!(pct(&v, 95.0), Some(95.0));
        assert_eq!(pct(&[], 50.0), None);
    }

    #[test]
    fn macs_are_found_only_whole() {
        assert_eq!(
            find_mac("bssid a4:83:E7:12:34:56 x"),
            Some((6, "a4:83:E7:12:34:56"))
        );
        assert_eq!(
            find_mac("aa-bb-cc-dd-ee-ff"),
            Some((0, "aa-bb-cc-dd-ee-ff"))
        );
        assert_eq!(
            find_mac("bssid a4:83:e7:2:34:56,"),
            Some((6, "a4:83:e7:2:34:56"))
        );
        for none in [
            "fe80::1:2:3:4:5",
            "0a4:83:e7:12:34:56",
            "12:34:56",
            "2026-10-28 11:27:33",
            "aa:bb:cc:dd:ee:ff:00",
            "a:b:c:d:e-f",
        ] {
            assert_eq!(find_mac(none), None, "{none}");
        }
        assert_eq!(
            find_mac("あaa:bb:cc:dd:ee:ffい"),
            Some((3, "aa:bb:cc:dd:ee:ff"))
        );
    }

    #[test]
    fn public_ipv4_is_masked_but_anchors_and_private_ranges_are_not() {
        assert_eq!(
            mask_public_v4(
                "hop 3 93.184.215.14 · dst 93.184.215.14.53 ok, 8.8.8.8 and 10.0.0.1, 100.64.1.1."
            ),
            "hop 3 93.184.215.x · dst 93.184.215.x.53 ok, 8.8.8.8 and 10.0.0.1, 100.64.1.1."
        );
        assert_eq!(
            mask_public_v4("v1.2 at 日本93.184.215.14語"),
            "v1.2 at 日本93.184.215.x語"
        );
    }

    fn sweep_with(ssid: &str, public: &str, portal: &str) -> Snapshot {
        Snapshot {
            ts: 5,
            sweep: serde_json::json!({
                "status": "fail",
                "path": [
                    { "id": "host", "metrics": [
                        { "label": "Interface", "value": "en0" },
                        { "label": "IPv6", "value": "2001:db8:1:2::1" },
                        { "label": "IPv6", "value": "2001:db8:1:2:aaaa:bbbb:cccc:dddd" }
                    ]},
                    { "id": "link", "subtitle": ssid, "metrics": [] },
                    { "id": "uplink", "metrics": [{ "label": "hop 3", "value": "93.184.215.14 · 12 ms" }] },
                    { "id": "wan", "subtitle": "1.1.1.1 (Cloudflare)", "metrics": [{ "label": "Public IP", "value": public }] },
                    { "id": "vpn", "metrics": [{ "label": "Tunnel IP", "value": "2606:4700:110:8::5" }] },
                    { "id": "captive", "metrics": [{ "label": "Portal", "value": portal }] }
                ]
            }),
        }
    }

    fn redacted(ssid: &str) -> String {
        let s = sweep_with(
            ssid,
            "198.51.100.77",
            "http://portal.example/login?mac=00:11:22:33:44:55&t=abc",
        );
        build(
            &[rec(5, "fail", Some("captive"), None)],
            &[s],
            0,
            Some(&RandomState::new()),
            &no_log,
        )
    }

    #[test]
    fn redaction_masks_identity_but_keeps_shape() {
        let out = redacted("Home Net");
        for leak in [
            "Home Net",
            "198.51.100.77",
            "aaaa:bbbb",
            "2001:db8:1:2::1\"",
            "110:8::5",
            "00:11:22:33:44:55",
            "t=abc",
            "93.184.215.14",
        ] {
            assert!(!out.contains(leak), "{leak} leaked:\n{out}");
        }
        for kept in [
            "198.51.100.x",
            "2001:db8:1:2::x",
            "2606:4700:110:8::x",
            "http://portal.example/login?…",
            "\"subtitle\":\"ssid-",
            "93.184.215.x",
            "1.1.1.1 (Cloudflare)",
        ] {
            assert!(out.contains(kept), "{kept} missing:\n{out}");
        }
    }

    #[test]
    fn awkward_ssids_are_masked_without_touching_the_rest() {
        let out = redacted(r#"Bob's "Home" \ Net"#);
        assert!(!out.contains("Bob's"), "{out}");
        let out = redacted("Internet");
        assert!(out.contains("| Internet RTT (ms) |"), "{out}");
        assert!(!out.contains("\"subtitle\":\"Internet\""), "{out}");
        let out = redacted("ok");
        assert!(out.contains("\"status\":\"fail\""), "{out}");
    }

    #[test]
    fn the_same_salt_gives_the_same_tags() {
        let state = RandomState::new();
        let s = [sweep_with("Home Net", "198.51.100.77", "x")];
        let tag = |out: String| out.split("ssid-").nth(1).unwrap()[..4].to_string();
        let a = build(&[rec(5, "fail", None, None)], &s, 0, Some(&state), &no_log);
        let b = build(&[rec(5, "fail", None, None)], &s, 0, Some(&state), &no_log);
        assert_eq!(tag(a), tag(b));
    }

    #[test]
    fn an_interface_name_is_not_mistaken_for_an_ssid() {
        let mut s = sweep_with("en0", "198.51.100.77", "x");
        s.sweep["path"][1]["subtitle"] = "en0".into();
        let out = build(
            &[rec(5, "ok", None, None)],
            &[s],
            0,
            Some(&RandomState::new()),
            &no_log,
        );
        assert!(out.contains("\"subtitle\":\"en0\""));
    }

    #[test]
    fn no_redact_leaves_everything() {
        let s = sweep_with("Home Net", "198.51.100.77", "x");
        let out = build(&[rec(5, "fail", None, None)], &[s], 0, None, &no_log);
        assert!(out.contains("Home Net") && out.contains("198.51.100.77"));
    }

    #[test]
    fn timestamps_going_backwards_dont_panic() {
        let r = [rec(100, "fail", None, None), rec(90, "ok", None, None)];
        assert!(build(&r, &[], 0, None, &no_log).contains("| 0s |"));
    }

    #[test]
    fn the_window_drops_older_data_and_the_prompt_comes_last() {
        let r = [
            rec(0, "fail", Some("dns"), None),
            rec(100, "ok", None, None),
        ];
        let out = build(&r, &[], 50, Some(&RandomState::new()), &no_log);
        assert!(
            !out.contains("## Episodes\n\n|"),
            "the old outage is outside the window"
        );
        assert!(out.trim_end().ends_with("what is still open."));
        let empty = build(&r, &[], 500, Some(&RandomState::new()), &no_log);
        assert!(empty.contains("No sweeps were recorded"));
    }
}
