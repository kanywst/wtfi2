//! `wtfi --bundle`: recorded sweeps as one Markdown document for an AI agent.

use crate::history::{self, Record, Snapshot};
use serde_json::Value;
use std::collections::HashMap;
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
    pub worst: String,
    pub first_break: Option<String>,
    pub headline: String,
    pub sweeps: usize,
}

pub fn episodes(records: &[Record]) -> Vec<Episode> {
    let mut out: Vec<Episode> = Vec::new();
    let mut open = false;
    for r in records {
        if r.status == "ok" {
            if open {
                out.last_mut().unwrap().end = Some(r.ts);
                open = false;
            }
            continue;
        }
        if !open {
            out.push(Episode {
                start: r.ts,
                end: None,
                worst: r.status.clone(),
                first_break: r.first_break.clone(),
                headline: r.headline.clone(),
                sweeps: 0,
            });
            open = true;
        }
        let e = out.last_mut().unwrap();
        e.sweeps += 1;
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
        .filter_map(|w| {
            let planned = w[0].interval_s?;
            (w[1].ts > w[0].ts + planned + GAP_SLACK_SECS).then_some((w[0].ts, w[1].ts))
        })
        .collect()
}

pub fn build(records: &[Record], sweeps: &[Snapshot], since: u64, redact: bool) -> String {
    let owned: Vec<Record> = records.iter().filter(|r| r.ts >= since).cloned().collect();
    let sweeps: Vec<&Snapshot> = sweeps.iter().filter(|s| s.ts >= since).collect();
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
    if redact {
        out.push_str("SSIDs, public IPs, IPv6 host bits, MAC addresses and portal query strings are masked.\n");
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
                Some(end) => span(end - e.start),
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
    out.push_str("| Metric | Samples | p50 | p95 | Max |\n| --- | --- | --- | --- | --- |\n");
    let rows: [(&str, Field); 4] = [
        ("Gateway RTT (ms)", |r| r.gateway_ms),
        ("Internet RTT (ms)", |r| r.wan_ms),
        ("Internet loss (%)", |r| r.wan_loss_pct),
        ("Wi-Fi RSSI (dBm)", |r| r.rssi_dbm),
    ];
    for (label, get) in rows {
        let mut v: Vec<f64> = owned.iter().filter_map(get).collect();
        v.sort_by(f64::total_cmp);
        match (pct(&v, 50.0), pct(&v, 95.0), v.last()) {
            (Some(p50), Some(p95), Some(max)) => out.push_str(&format!(
                "| {label} | {} | {p50:.0} | {p95:.0} | {max:.0} |\n",
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
            out.push_str(&format!(
                "<sweep at=\"{}\">\n\n```json\n{}\n```\n\n</sweep>\n\n",
                history::utc(s.ts),
                serde_json::to_string(&sweep).unwrap_or_default()
            ));
        }
    }

    out.push_str(PROMPT);
    if redact {
        Redactor::new(&sweeps).apply(&out)
    } else {
        out
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

struct Redactor {
    state: RandomState,
    swaps: HashMap<String, String>,
}

impl Redactor {
    fn new(sweeps: &[&Snapshot]) -> Self {
        let mut r = Redactor {
            state: RandomState::new(),
            swaps: HashMap::new(),
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
                {
                    let tag = format!("ssid-{}", r.tag(ssid));
                    r.swaps.insert(ssid.into(), tag);
                }
                if let Some(ip) = metric(h, "Public IP") {
                    r.swaps.insert(ip.into(), mask_ip(ip));
                }
                if let Some(ip) = metric(h, "IPv6") {
                    r.swaps.insert(ip.into(), mask_ip(ip));
                }
                if let Some(url) = metric(h, "Portal")
                    && let Some((base, _)) = url.split_once('?')
                {
                    r.swaps.insert(url.into(), format!("{base}?…"));
                }
            }
        }
        r
    }

    fn tag(&self, s: &str) -> String {
        format!("{:04x}", self.state.hash_one(s) & 0xffff)
    }

    fn apply(&self, text: &str) -> String {
        let mut keys: Vec<&String> = self.swaps.keys().collect();
        keys.sort_by_key(|k| std::cmp::Reverse(k.len()));
        let mut out = text.to_string();
        for k in keys {
            out = out.replace(k.as_str(), &self.swaps[k]);
        }
        self.macs(&out)
    }

    fn macs(&self, text: &str) -> String {
        let mut out = String::with_capacity(text.len());
        let mut rest = text;
        while let Some((i, mac)) = find_mac(rest) {
            out.push_str(&rest[..i]);
            out.push_str(&format!("mac-{}", self.tag(&mac.to_ascii_lowercase())));
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

/// The first `aa:bb:cc:dd:ee:ff` (any case, `:` or `-`) and where it starts.
fn find_mac(text: &str) -> Option<(usize, &str)> {
    let b = text.as_bytes();
    (0..b.len().saturating_sub(16)).find_map(|i| {
        let w = &b[i..i + 17];
        let sep = w[2];
        let ok = (sep == b':' || sep == b'-')
            && (0..6).all(|g| w[g * 3].is_ascii_hexdigit() && w[g * 3 + 1].is_ascii_hexdigit())
            && (0..5).all(|g| w[g * 3 + 2] == sep)
            && (i == 0 || !b[i - 1].is_ascii_hexdigit() && b[i - 1] != sep)
            && b.get(i + 17)
                .is_none_or(|c| !c.is_ascii_hexdigit() && *c != sep);
        ok.then(|| (i, &text[i..i + 17]))
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
        assert_eq!(find_mac("fe80::1:2:3:4:5"), None);
        assert_eq!(find_mac("0a4:83:e7:12:34:56"), None);
        assert_eq!(find_mac("12:34:56"), None);
    }

    fn sweep_with(ssid: &str, public: &str, portal: &str) -> Snapshot {
        Snapshot {
            ts: 5,
            sweep: serde_json::json!({
                "status": "fail",
                "path": [
                    { "id": "host", "metrics": [
                        { "label": "Interface", "value": "en0" },
                        { "label": "IPv6", "value": "2001:db8:1:2:aaaa:bbbb:cccc:dddd" }
                    ]},
                    { "id": "link", "subtitle": ssid, "metrics": [] },
                    { "id": "wan", "metrics": [{ "label": "Public IP", "value": public }] },
                    { "id": "captive", "metrics": [{ "label": "Portal", "value": portal }] }
                ]
            }),
        }
    }

    #[test]
    fn redaction_masks_identity_but_keeps_shape() {
        let s = sweep_with(
            "Home Net",
            "198.51.100.77",
            "http://portal.example/login?mac=00:11:22:33:44:55&t=abc",
        );
        let out = build(&[rec(5, "fail", Some("captive"), None)], &[s], 0, true);
        for leak in [
            "Home Net",
            "198.51.100.77",
            "aaaa:bbbb",
            "00:11:22:33:44:55",
            "t=abc",
        ] {
            assert!(!out.contains(leak), "{leak} leaked:\n{out}");
        }
        assert!(out.contains("198.51.100.x"));
        assert!(out.contains("2001:db8:1:2::x"));
        assert!(out.contains("http://portal.example/login?…"));
        assert!(out.contains("\"subtitle\":\"ssid-"));
    }

    #[test]
    fn an_interface_name_is_not_mistaken_for_an_ssid() {
        let mut s = sweep_with("en0", "198.51.100.77", "x");
        s.sweep["path"][1]["subtitle"] = "en0".into();
        let out = build(&[rec(5, "ok", None, None)], &[s], 0, true);
        assert!(out.contains("\"subtitle\":\"en0\""));
    }

    #[test]
    fn no_redact_leaves_everything() {
        let s = sweep_with("Home Net", "198.51.100.77", "x");
        let out = build(&[rec(5, "fail", None, None)], &[s], 0, false);
        assert!(out.contains("Home Net") && out.contains("198.51.100.77"));
    }

    #[test]
    fn the_window_drops_older_data_and_the_prompt_comes_last() {
        let r = [
            rec(0, "fail", Some("dns"), None),
            rec(100, "ok", None, None),
        ];
        let out = build(&r, &[], 50, true);
        assert!(
            !out.contains("## Episodes\n\n|"),
            "the old outage is outside the window"
        );
        assert!(out.trim_end().ends_with("what is still open."));
        let empty = build(&r, &[], 500, true);
        assert!(empty.contains("No sweeps were recorded"));
    }
}
