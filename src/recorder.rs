//! `wtfi --record --every`: keep sweeping on a cadence without the dashboard.

use crate::diagnose::diagnose;
use crate::history::{self, Record};
use crate::model::{Path, Status};
use std::future::Future;
use std::io::Write;
use std::time::Duration;
use tokio::time::Instant;

/// The cadence while something is broken, so an outage gets fine-grained edges.
pub const FAST: Duration = Duration::from_secs(5);
/// Idle time between sweeps even when one overran its period.
pub const MIN_GAP: Duration = Duration::from_secs(2);

/// A period after the last start, but never right on the heels of a long sweep.
pub fn next_start(started: Instant, period: Duration, now: Instant) -> Instant {
    let due = started
        .checked_add(period)
        .unwrap_or(now + Duration::from_secs(86_400));
    due.max(now + MIN_GAP)
}

pub fn next_wait(every: Duration, status: Status) -> Duration {
    if status == Status::Fail {
        every.min(FAST)
    } else {
        every
    }
}

pub async fn run<F, Fut>(every: Duration, file: &std::path::Path, mut sweep: F)
where
    F: FnMut(usize) -> Fut,
    Fut: Future<Output = Path>,
{
    let mut n = 0;
    loop {
        let started = tokio::time::Instant::now();
        let period = record(every, file, &sweep(n).await);
        n = n.wrapping_add(1);
        tokio::time::sleep_until(next_start(started, period, tokio::time::Instant::now())).await;
    }
}

/// Append and print one sweep; returns the period until the next one starts.
pub fn record(every: Duration, file: &std::path::Path, path: &Path) -> Duration {
    let verdict = diagnose(path);
    let wait = next_wait(every, verdict.status);
    let mut record = Record::now(path, &verdict);
    record.interval_s = Some(wait.as_secs());
    if let Err(e) = history::append(file, &record) {
        let _ = writeln!(
            std::io::stderr(),
            "wtfi: could not record to {}: {e}",
            file.display()
        );
    }
    // Best effort: a closed stdout must not stop the recording.
    let _ = writeln!(std::io::stdout(), "{}", history::line(&record));
    wait
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::skeleton;
    use crate::model::HopId;

    #[test]
    fn trouble_tightens_the_cadence() {
        let every = Duration::from_secs(30);
        assert_eq!(next_wait(every, Status::Ok), every);
        assert_eq!(next_wait(every, Status::Fail), FAST);
        assert_eq!(
            next_wait(every, Status::Warn),
            every,
            "a steady degradation isn't an outage"
        );
        assert_eq!(next_wait(every, Status::Skipped), every);
        let quick = Duration::from_secs(2);
        assert_eq!(
            next_wait(quick, Status::Fail),
            quick,
            "never slower than asked"
        );
    }

    #[test]
    fn a_long_sweep_still_gets_a_breather() {
        let t0 = Instant::now();
        let fast = Duration::from_secs(5);
        assert_eq!(next_start(t0, fast, t0 + Duration::from_secs(1)), t0 + fast);
        assert!(
            next_start(t0, Duration::MAX, t0) > t0,
            "a huge --every doesn't overflow"
        );
        assert_eq!(
            next_start(t0, fast, t0 + Duration::from_secs(16)),
            t0 + Duration::from_secs(18),
            "a 16s sweep on a broken network isn't followed by another at once"
        );
    }

    #[test]
    fn each_sweep_lands_in_the_file_with_its_interval() {
        let dir = std::env::temp_dir().join(format!("wtfi-recorder-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let file = dir.join("history.jsonl");
        let every = Duration::from_secs(60);
        let mut path = skeleton();
        for hop in &mut path.hops {
            hop.status = Status::Ok;
        }
        assert_eq!(record(every, &file, &path), every);
        path.get_mut(HopId::Wan).unwrap().status = Status::Fail;
        assert_eq!(record(every, &file, &path), FAST);
        let got = history::load(&file, 10).unwrap();
        let intervals: Vec<_> = got.iter().map(|r| r.interval_s).collect();
        assert_eq!(intervals, [Some(60), Some(5)]);
        assert_eq!(got[1].status, "fail");
    }
}
