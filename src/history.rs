//! Sweep history on disk (`--record` / `--history`), one JSON line per sweep.

use crate::diagnose::Verdict;
use crate::json::{hop_id_str, status_str};
use crate::model::{Hop, HopId, Path};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

/// Past this size the file is cut back to its newer half.
const MAX_BYTES: u64 = 4 * 1024 * 1024;

/// One finished sweep, flattened to the numbers a trend is drawn from.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Record {
    /// Unix seconds.
    pub ts: u64,
    pub status: String,
    pub first_break: Option<String>,
    pub headline: String,
    pub gateway_ms: Option<f64>,
    pub wan_ms: Option<f64>,
    pub wan_loss_pct: Option<f64>,
    pub rssi_dbm: Option<f64>,
}

impl Record {
    pub fn new(path: &Path, verdict: &Verdict, ts: u64) -> Self {
        let latency = |id| path.get(id).and_then(|h: &Hop| h.latency_ms);
        Record {
            ts,
            status: status_str(verdict.status).into(),
            first_break: path.first_break().map(|h| hop_id_str(h.id)),
            headline: verdict.headline.clone(),
            gateway_ms: latency(HopId::Gateway),
            wan_ms: latency(HopId::Wan),
            wan_loss_pct: path.get(HopId::Wan).and_then(|h| h.loss_pct),
            rssi_dbm: path.get(HopId::Link).and_then(rssi_dbm),
        }
    }

    pub fn now(path: &Path, verdict: &Verdict) -> Self {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Self::new(path, verdict, ts)
    }
}

fn rssi_dbm(link: &Hop) -> Option<f64> {
    link.metrics
        .iter()
        .find(|m| m.label == "RSSI")
        .and_then(|m| m.value.split_whitespace().next())
        .and_then(|s| s.parse().ok())
}

/// `$WTFI_HISTORY`, else `$XDG_STATE_HOME/wtfi/history.jsonl`, else
/// `~/.local/state/wtfi/history.jsonl` (macOS included).
pub fn default_path() -> Option<PathBuf> {
    let var = |k| std::env::var_os(k).filter(|v| !v.is_empty());
    if let Some(p) = var("WTFI_HISTORY") {
        return Some(p.into());
    }
    let state = var("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| var("HOME").map(|h| PathBuf::from(h).join(".local/state")))?;
    Some(state.join("wtfi").join("history.jsonl"))
}

pub fn append(file: &std::path::Path, record: &Record) -> io::Result<()> {
    if let Some(dir) = file.parent() {
        fs::create_dir_all(dir)?;
    }
    if fs::metadata(file).is_ok_and(|m| m.len() > MAX_BYTES) {
        trim(file)?;
    }
    let mut line = serde_json::to_string(record).map_err(io::Error::other)?;
    line.push('\n');
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(file)?
        .write_all(line.as_bytes())
}

/// Keep the newer half. Written via rename so a crash can't truncate it.
fn trim(file: &std::path::Path) -> io::Result<()> {
    let text = fs::read_to_string(file)?;
    let lines: Vec<&str> = text.lines().collect();
    let keep = &lines[lines.len().div_ceil(2)..];
    let tmp = file.with_extension("jsonl.tmp");
    fs::write(&tmp, keep.join("\n") + "\n")?;
    fs::rename(tmp, file)
}

/// The newest `n` records, oldest first. Unparseable lines are skipped.
pub fn load(file: &std::path::Path, n: usize) -> io::Result<Vec<Record>> {
    let text = match fs::read_to_string(file) {
        Ok(t) => t,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut records: Vec<Record> = text
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    let skip = records.len().saturating_sub(n);
    records.drain(..skip);
    Ok(records)
}

pub fn render(records: &[Record]) -> String {
    if records.is_empty() {
        return "No recorded sweeps yet. Run `wtfi --record` (or `wtfi -w --record`) to start.\n"
            .into();
    }
    let ms = |v: Option<f64>| v.map_or("—".into(), |v| format!("{v:.0} ms"));
    let mut out = String::new();
    for r in records {
        let wan = match r.wan_loss_pct.filter(|l| *l > 0.0) {
            Some(l) => format!("{} {l:.0}%", ms(r.wan_ms)),
            None => ms(r.wan_ms),
        };
        out.push_str(&format!(
            "{}  {:<7}  {:<8}  gw {:>7}  wan {:>11}  {:>8}  {}\n",
            utc(r.ts),
            r.status,
            r.first_break.as_deref().unwrap_or("—"),
            ms(r.gateway_ms),
            wan,
            r.rssi_dbm.map_or("—".into(), |v| format!("{v:.0} dBm")),
            r.headline,
        ));
    }
    let count = |s: &str| records.iter().filter(|r| r.status == s).count();
    out.push_str(&format!(
        "\n{} sweeps · {} ok · {} warn · {} fail\n",
        records.len(),
        count("ok"),
        count("warn"),
        count("fail"),
    ));
    out
}

/// `YYYY-MM-DD HH:MM:SSZ` (UTC; local time would need a tz database).
fn utc(ts: u64) -> String {
    let (days, secs) = (ts / 86_400, ts % 86_400);
    // Howard Hinnant's days-to-civil.
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}Z",
        secs / 3600,
        secs / 60 % 60,
        secs % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(ts: u64, status: &str) -> Record {
        Record {
            ts,
            status: status.into(),
            first_break: None,
            headline: "All good".into(),
            gateway_ms: Some(3.0),
            wan_ms: Some(18.0),
            wan_loss_pct: None,
            rssi_dbm: Some(-52.0),
        }
    }

    fn tempfile(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("wtfi-history-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir.join("nested").join("history.jsonl")
    }

    #[test]
    fn appended_records_come_back_in_order() {
        let f = tempfile("order");
        for ts in 1..=3 {
            append(&f, &record(ts, "ok")).unwrap();
        }
        let got: Vec<u64> = load(&f, 10).unwrap().iter().map(|r| r.ts).collect();
        assert_eq!(got, [1, 2, 3]);
        let got: Vec<u64> = load(&f, 2).unwrap().iter().map(|r| r.ts).collect();
        assert_eq!(got, [2, 3], "load keeps the newest n");
    }

    #[test]
    fn a_missing_file_is_an_empty_history() {
        assert!(load(&tempfile("missing"), 10).unwrap().is_empty());
    }

    #[test]
    fn a_torn_line_costs_only_itself() {
        let f = tempfile("torn");
        append(&f, &record(1, "ok")).unwrap();
        fs::OpenOptions::new()
            .append(true)
            .open(&f)
            .unwrap()
            .write_all(b"{\"ts\":2,\"sta\n")
            .unwrap();
        append(&f, &record(3, "fail")).unwrap();
        let got: Vec<u64> = load(&f, 10).unwrap().iter().map(|r| r.ts).collect();
        assert_eq!(got, [1, 3]);
    }

    #[test]
    fn an_oversized_file_is_cut_to_its_newer_half() {
        let f = tempfile("trim");
        append(&f, &record(0, "ok")).unwrap();
        let line = fs::read_to_string(&f).unwrap();
        let n = (MAX_BYTES as usize / line.len()) + 2;
        fs::write(&f, line.repeat(n)).unwrap();
        append(&f, &record(99, "fail")).unwrap();
        let got = load(&f, usize::MAX).unwrap();
        assert!(got.len() < n, "trim should have dropped the older half");
        assert_eq!(
            got.last().unwrap().ts,
            99,
            "the new record survives the trim"
        );
        assert!(fs::metadata(&f).unwrap().len() <= MAX_BYTES);
    }

    #[test]
    fn timestamps_render_as_utc() {
        assert_eq!(utc(0), "1970-01-01 00:00:00Z");
        assert_eq!(utc(951_782_400), "2000-02-29 00:00:00Z");
        assert_eq!(utc(1_792_078_245), "2026-10-15 15:30:45Z");
    }

    #[test]
    fn render_tallies_statuses() {
        let out = render(&[record(0, "ok"), record(1, "fail"), record(2, "ok")]);
        assert!(out.contains("3 sweeps · 2 ok · 0 warn · 1 fail"), "{out}");
        assert!(out.contains("-52 dBm"));
    }

    #[test]
    fn a_record_reads_the_numbers_off_the_path() {
        use crate::model::Metric;
        let mut path = crate::engine::skeleton();
        path.get_mut(HopId::Gateway).unwrap().latency_ms = Some(2.5);
        let link = path.get_mut(HopId::Link).unwrap();
        link.metrics.push(Metric::new("RSSI", "-61 dBm"));
        let verdict = crate::diagnose::diagnose(&path);
        let r = Record::new(&path, &verdict, 7);
        assert_eq!(r.gateway_ms, Some(2.5));
        assert_eq!(r.rssi_dbm, Some(-61.0));
        assert_eq!(r.wan_ms, None);
    }
}
