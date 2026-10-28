//! `wtfi --bundle`: recorded sweeps as one Markdown document for an AI agent.

use crate::history::{self, Record, Snapshot};
use serde_json::Value;
use std::hash::{BuildHasher, RandomState};

/// Newest full sweeps to include; older ones are counted, not shown.
const MAX_SWEEPS: usize = 12;
const MAX_TIMELINE: usize = 200;
/// A recorder that planned to sweep in N seconds but didn't within N+60 wasn't running.
const GAP_SLACK_SECS: u64 = 60;

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
    a.interval_s
        .is_some_and(|planned| b.ts > a.ts + planned + GAP_SLACK_SECS)
}

/// `redact` salts the masks; pass the same state to get the same tags across calls.
pub fn build(
    records: &[Record],
    sweeps: &[Snapshot],
    since: u64,
    redact: Option<&RandomState>,
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

    let eps = episodes(&owned);
    out.push_str("\n## Episodes\n\n");
    if eps.is_empty() {
        out.push_str("Every sweep in this window was healthy.\n");
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

    let gaps = gaps(&owned);
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
    let rows: [(&str, Field, bool); 4] = [
        ("Gateway RTT (ms)", |r| r.gateway_ms, true),
        ("Internet RTT (ms)", |r| r.wan_ms, true),
        ("Internet loss (%)", |r| r.wan_loss_pct, true),
        ("Wi-Fi RSSI (dBm)", |r| r.rssi_dbm, false),
    ];
    for (label, get, higher_is_worse) in rows {
        let mut v: Vec<f64> = owned.iter().filter_map(get).collect();
        v.sort_by(f64::total_cmp);
        if !higher_is_worse {
            v.reverse();
        }
        match (pct(&v, 50.0), pct(&v, 95.0), v.last()) {
            (Some(p50), Some(p95), Some(worst)) => out.push_str(&format!(
                "| {label} | {} | {p50:.0} | {p95:.0} | {worst:.0} |\n",
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

    out.push_str(PROMPT);
    match redactor {
        Some(r) => r.text(&out),
        None => out,
    }
}

fn timeline(records: &[Record]) -> Vec<String> {
    let mut lines = Vec::new();
    let mut i = 0;
    while i < records.len() {
        let r = &records[i];
        let run = records[i..]
            .iter()
            .take_while(|o| {
                o.status == r.status && o.first_break == r.first_break && o.headline == r.headline
            })
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
                    let Some(value) = m["value"].as_str() else {
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

1. For each episode, say which layer broke first and what most likely caused it. Quote the records or sweep fields you rely on.
2. Say whether the episodes share a cause or look unrelated.
3. Keep what the data shows apart from what you infer, and say when it can't decide between causes.
4. List concrete next steps, most likely fix first, and what I should capture next time to settle what is still open.
";

#[cfg(test)]
mod tests {
    use super::*;

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
        let out = build(&r, &[], 0, None);
        assert!(
            out.contains("at least 5s, then the recorder stopped"),
            "{out}"
        );
        let row = out.lines().find(|l| l.contains("| dns |")).unwrap();
        assert!(!row.contains("2h"), "{row}");
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
        let out = build(&r, &[], 0, None);
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
            rec(9000, "ok", None, None),
        ];
        assert_eq!(gaps(&r), [(30, 1000)], "no interval, no claim");
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
        let a = build(&[rec(5, "fail", None, None)], &s, 0, Some(&state));
        let b = build(&[rec(5, "fail", None, None)], &s, 0, Some(&state));
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
        );
        assert!(out.contains("\"subtitle\":\"en0\""));
    }

    #[test]
    fn no_redact_leaves_everything() {
        let s = sweep_with("Home Net", "198.51.100.77", "x");
        let out = build(&[rec(5, "fail", None, None)], &[s], 0, None);
        assert!(out.contains("Home Net") && out.contains("198.51.100.77"));
    }

    #[test]
    fn timestamps_going_backwards_dont_panic() {
        let r = [rec(100, "fail", None, None), rec(90, "ok", None, None)];
        assert!(build(&r, &[], 0, None).contains("| 0s |"));
    }

    #[test]
    fn the_window_drops_older_data_and_the_prompt_comes_last() {
        let r = [
            rec(0, "fail", Some("dns"), None),
            rec(100, "ok", None, None),
        ];
        let out = build(&r, &[], 50, Some(&RandomState::new()));
        assert!(
            !out.contains("## Episodes\n\n|"),
            "the old outage is outside the window"
        );
        assert!(out.trim_end().ends_with("what is still open."));
        let empty = build(&r, &[], 500, Some(&RandomState::new()));
        assert!(empty.contains("No sweeps were recorded"));
    }
}
