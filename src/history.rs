//! Sweep history on disk (`--record` / `--history`), one JSON line per sweep,
//! plus full sweeps from around each change of state in `sweeps.jsonl`.

use crate::diagnose::Verdict;
use crate::json::{hop_id_str, status_str};
use crate::model::{Fault, Hop, HopId, Path};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

/// Past this size the file is cut back to its newer half.
const MAX_BYTES: u64 = 4 * 1024 * 1024;
const SWEEPS_MAX_BYTES: u64 = 16 * 1024 * 1024;
/// Failed snapshot writes kept for retry; older ones are dropped.
const MAX_UNWRITTEN: usize = 4;
/// While broken, keep a full sweep at least this often.
const RESNAPSHOT_SECS: u64 = 600;

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
    /// Planned seconds until the next sweep, set by `--every`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interval_s: Option<u64>,
    /// Some hop never reported (the sweep hit its deadline or a tool didn't run).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub partial: bool,
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
            interval_s: None,
            partial: path.hops.iter().any(|h| h.fault == Some(Fault::Unobserved)),
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

/// A full sweep (the `--json` document) and when it ran.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Snapshot {
    pub ts: u64,
    pub sweep: Value,
}

pub fn sweeps_path(history: &std::path::Path) -> PathBuf {
    history.with_file_name("sweeps.jsonl")
}

/// Appends records, and full sweeps on either side of every change of state.
pub struct Log {
    file: PathBuf,
    state: Option<String>,
    held: Option<Snapshot>,
    /// Snapshots whose write failed, retried first so the real edge still lands.
    unwritten: Vec<Snapshot>,
    last_snapshot: u64,
}

impl Log {
    pub fn open(file: PathBuf) -> Self {
        let last: Option<Record> = last_line(&file);
        Log {
            state: last.as_ref().map(state_of),
            last_snapshot: last_line::<Snapshot>(&sweeps_path(&file))
                .map(|s| s.ts)
                .or_else(|| modified_secs(&sweeps_path(&file)))
                .unwrap_or(0),
            file,
            held: None,
            unwritten: Vec::new(),
        }
    }

    pub fn push(&mut self, record: &Record, sweep: Value) -> io::Result<()> {
        let appended = append(&self.file, record).map_err(|e| at(&self.file, e));
        let snapshot = Snapshot {
            ts: record.ts,
            sweep,
        };
        let state = state_of(record);
        let changed = self.state.as_ref() != Some(&state);
        let stale = record.status == "fail"
            && record.ts >= self.last_snapshot + RESNAPSHOT_SECS
            && self.unwritten.is_empty();
        self.state = Some(state);
        if changed || stale {
            let before = self.held.take();
            if changed && let Some(before) = before {
                self.unwritten.push(before);
            }
            self.unwritten.push(snapshot);
            let excess = self.unwritten.len().saturating_sub(MAX_UNWRITTEN);
            self.unwritten.drain(..excess);
            self.last_snapshot = record.ts;
        } else {
            self.held = Some(snapshot);
        }
        let to = sweeps_path(&self.file);
        while let Some(next) = self.unwritten.first() {
            append_line(&to, next, SWEEPS_MAX_BYTES).map_err(|e| at(&to, e))?;
            self.unwritten.remove(0);
        }
        appended
    }
}

fn at(file: &std::path::Path, e: io::Error) -> io::Error {
    io::Error::new(e.kind(), format!("{}: {e}", file.display()))
}

/// The last parseable line, read from the file's tail.
fn last_line<T: serde::de::DeserializeOwned>(file: &std::path::Path) -> Option<T> {
    let mut f = fs::File::open(file).ok()?;
    let len = f.metadata().ok()?.len();
    f.seek(SeekFrom::Start(len.saturating_sub(64 * 1024)))
        .ok()?;
    let mut tail = Vec::new();
    f.read_to_end(&mut tail).ok()?;
    String::from_utf8_lossy(&tail)
        .lines()
        .rev()
        .find_map(|l| serde_json::from_str(l).ok())
}

fn modified_secs(file: &std::path::Path) -> Option<u64> {
    let modified = fs::metadata(file).ok()?.modified().ok()?;
    Some(modified.duration_since(UNIX_EPOCH).ok()?.as_secs())
}

fn state_of(r: &Record) -> String {
    format!(
        "{}|{}|{}",
        r.status,
        r.first_break.as_deref().unwrap_or(""),
        r.headline
    )
}

/// Every snapshot taken at or after `since`, oldest first.
pub fn load_sweeps(history: &std::path::Path, since: u64) -> io::Result<Vec<Snapshot>> {
    Ok(read_lines(&sweeps_path(history))?
        .into_iter()
        .filter(|s: &Snapshot| s.ts >= since)
        .collect())
}

pub fn append(file: &std::path::Path, record: &Record) -> io::Result<()> {
    append_line(file, record, MAX_BYTES)
}

fn append_line<T: Serialize>(file: &std::path::Path, record: &T, max: u64) -> io::Result<()> {
    if let Some(dir) = file.parent() {
        fs::create_dir_all(dir)?;
    }
    if fs::metadata(file).is_ok_and(|m| m.len() > max) {
        trim(file)?;
    }
    let mut out = OpenOptions::new()
        .create(true)
        .read(true)
        .append(true)
        .open(file)?;
    let mut line = serde_json::to_string(record).map_err(io::Error::other)?;
    // Don't glue this record onto a line a killed process left unterminated.
    if out.metadata()?.len() > 0 {
        let mut last = [0u8; 1];
        out.seek(SeekFrom::End(-1))?;
        out.read_exact(&mut last)?;
        if last[0] != b'\n' {
            line.insert(0, '\n');
        }
    }
    line.push('\n');
    out.write_all(line.as_bytes())
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
    let mut records: Vec<Record> = read_lines(file)?;
    let skip = records.len().saturating_sub(n);
    records.drain(..skip);
    Ok(records)
}

fn read_lines<T: serde::de::DeserializeOwned>(file: &std::path::Path) -> io::Result<Vec<T>> {
    let text = match fs::read_to_string(file) {
        Ok(t) => t,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    Ok(text
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect())
}

pub fn render(records: &[Record]) -> String {
    if records.is_empty() {
        return "No recorded sweeps yet. Run `wtfi --record` (or `wtfi -w --record`) to start.\n"
            .into();
    }
    let mut out = String::new();
    for r in records {
        out.push_str(&line(r));
        out.push('\n');
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

/// One record as a table row, without the newline.
pub fn line(r: &Record) -> String {
    let ms = |v: Option<f64>| v.map_or("—".into(), |v| format!("{v:.0} ms"));
    let wan = match r.wan_loss_pct.filter(|l| *l > 0.0) {
        Some(l) => format!("{} {l:.0}%", ms(r.wan_ms)),
        None => ms(r.wan_ms),
    };
    format!(
        "{}  {:<7}  {:<8}  gw {:>7}  wan {:>11}  {:>8}  {}",
        utc(r.ts),
        r.status,
        r.first_break.as_deref().unwrap_or("—"),
        ms(r.gateway_ms),
        wan,
        r.rssi_dbm.map_or("—".into(), |v| format!("{v:.0} dBm")),
        if r.partial {
            format!("{} (partial sweep)", r.headline)
        } else {
            r.headline.clone()
        },
    )
}

/// `YYYY-MM-DD HH:MM:SSZ` (UTC; local time would need a tz database).
pub fn utc(ts: u64) -> String {
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
            interval_s: None,
            partial: false,
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
            .write_all(b"{\"ts\":2,\"sta")
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
    fn full_sweeps_are_kept_around_each_change_only() {
        let f = tempfile("sweeps");
        let mut log = Log::open(f.clone());
        let statuses = ["ok", "ok", "ok", "fail", "fail", "ok"];
        for (ts, status) in statuses.iter().enumerate() {
            let r = record(ts as u64, status);
            log.push(&r, serde_json::json!({ "n": ts })).unwrap();
        }
        let ts: Vec<u64> = load_sweeps(&f, 0).unwrap().iter().map(|s| s.ts).collect();
        assert_eq!(ts, [0, 2, 3, 4, 5], "first, then both sides of each change");
        assert_eq!(load(&f, 10).unwrap().len(), 6, "every record still lands");
        assert_eq!(load_sweeps(&f, 4).unwrap().len(), 2);
    }

    #[test]
    fn a_long_outage_is_resnapshotted() {
        let f = tempfile("resnapshot");
        let mut log = Log::open(f.clone());
        for ts in (0..=1200).step_by(300) {
            log.push(&record(ts, "fail"), Value::Null).unwrap();
        }
        let ts: Vec<u64> = load_sweeps(&f, 0).unwrap().iter().map(|s| s.ts).collect();
        assert_eq!(ts, [0, 600, 1200]);
    }

    #[test]
    fn a_reopened_log_remembers_the_last_state() {
        let f = tempfile("reopen");
        Log::open(f.clone())
            .push(&record(0, "fail"), Value::Null)
            .unwrap();
        Log::open(f.clone())
            .push(&record(1, "fail"), Value::Null)
            .unwrap();
        Log::open(f.clone())
            .push(&record(2, "ok"), Value::Null)
            .unwrap();
        let ts: Vec<u64> = load_sweeps(&f, 0).unwrap().iter().map(|s| s.ts).collect();
        assert_eq!(
            ts,
            [0, 2],
            "a one-shot run can't hold, so it only skips repeats"
        );
    }

    #[test]
    fn reopening_on_a_short_cadence_still_resnapshots_a_long_outage() {
        let f = tempfile("cadence");
        for ts in (0..=1500).step_by(300) {
            Log::open(f.clone())
                .push(&record(ts, "fail"), Value::Null)
                .unwrap();
        }
        let ts: Vec<u64> = load_sweeps(&f, 0).unwrap().iter().map(|s| s.ts).collect();
        assert_eq!(ts, [0, 600, 1200]);
    }

    #[test]
    fn snapshots_stay_in_order_around_a_resnapshot() {
        let f = tempfile("resnapshot-order");
        let mut log = Log::open(f.clone());
        for (ts, status) in [(0, "fail"), (300, "fail"), (600, "fail"), (605, "ok")] {
            log.push(&record(ts, status), Value::Null).unwrap();
        }
        let ts: Vec<u64> = load_sweeps(&f, 0).unwrap().iter().map(|s| s.ts).collect();
        assert_eq!(ts, [0, 600, 605]);
    }

    #[test]
    fn a_failed_snapshot_write_is_retried_on_the_next_sweep() {
        let f = tempfile("retry");
        let mut log = Log::open(f.clone());
        log.push(&record(0, "ok"), Value::Null).unwrap();
        let sweeps = sweeps_path(&f);
        fs::remove_file(&sweeps).unwrap();
        fs::create_dir(&sweeps).unwrap();
        let err = log.push(&record(10, "fail"), Value::Null).unwrap_err();
        assert!(err.to_string().contains("sweeps.jsonl"), "{err}");
        fs::remove_dir(&sweeps).unwrap();
        log.push(&record(20, "fail"), Value::Null).unwrap();
        let ts: Vec<u64> = load_sweeps(&f, 0).unwrap().iter().map(|s| s.ts).collect();
        assert_eq!(
            ts,
            [10],
            "the real edge lands once the file is writable again"
        );
    }

    #[test]
    fn a_failed_history_write_still_snapshots_the_edge() {
        let f = tempfile("history-fails");
        let mut log = Log::open(f.clone());
        log.push(&record(0, "ok"), Value::Null).unwrap();
        log.push(&record(5, "ok"), Value::Null).unwrap();
        fs::remove_file(&f).unwrap();
        fs::create_dir(&f).unwrap();
        assert!(log.push(&record(10, "fail"), Value::Null).is_err());
        let ts: Vec<u64> = load_sweeps(&f, 0).unwrap().iter().map(|s| s.ts).collect();
        assert_eq!(ts, [0, 5, 10], "both sides of the edge are kept");
    }

    #[test]
    fn an_unwritable_sweeps_file_doesnt_grow_the_queue_forever() {
        let f = tempfile("queue");
        let mut log = Log::open(f.clone());
        fs::create_dir_all(sweeps_path(&f)).unwrap();
        for (i, status) in ["ok", "fail"].iter().cycle().take(20).enumerate() {
            let _ = log.push(&record(i as u64, status), Value::Null);
        }
        assert!(log.unwritten.len() <= MAX_UNWRITTEN);
    }

    #[test]
    fn a_steady_degradation_is_not_resnapshotted() {
        let f = tempfile("warn");
        let mut log = Log::open(f.clone());
        for ts in (0..=1200).step_by(300) {
            log.push(&record(ts, "warn"), Value::Null).unwrap();
        }
        assert_eq!(load_sweeps(&f, 0).unwrap().len(), 1);
    }

    #[test]
    fn timestamps_render_as_utc() {
        assert_eq!(utc(0), "1970-01-01 00:00:00Z");
        assert_eq!(utc(951_782_400), "2000-02-29 00:00:00Z");
        assert_eq!(utc(1_792_078_245), "2026-10-15 15:30:45Z");
    }

    #[test]
    fn a_cut_off_sweep_is_marked_partial() {
        let mut path = crate::engine::skeleton();
        path.get_mut(HopId::Wan).unwrap().fault = Some(Fault::Unobserved);
        let verdict = crate::diagnose::diagnose(&path);
        let r = Record::new(&path, &verdict, 7);
        assert!(r.partial);
        assert!(line(&r).ends_with("(partial sweep)"));
        assert!(
            serde_json::to_string(&record(0, "ok"))
                .unwrap()
                .find("partial")
                .is_none()
        );
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
