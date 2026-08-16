//! Low-level, no-root network measurement helpers shared by probes.
//!
//! macOS raw ICMP sockets require root, so we lean on primitives that work
//! unprivileged: the setuid `ping` binary for ICMP RTT, and plain TCP connects
//! (which also exercise the real forwarding path better than ICMP for WAN).

use crate::model::{Hop, Metric, Status};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::process::Command;
use tokio::time::timeout;

/// Result of a single latency measurement.
///
/// "Couldn't measure at all" is deliberately not a variant here: that's a
/// property of a whole burst, not a sample, and [`Quality::is_empty`] carries
/// it — which keeps a failed *tool* from ever being counted as a lost *packet*.
#[derive(Debug, Clone, Copy)]
pub enum Probe {
    /// Reached, with round-trip time.
    Up(Duration),
    /// No response within the timeout.
    Timeout,
}

impl Probe {
    pub fn ms(self) -> Option<f64> {
        match self {
            Probe::Up(d) => Some(d.as_secs_f64() * 1000.0),
            _ => None,
        }
    }
    pub fn is_up(self) -> bool {
        matches!(self, Probe::Up(_))
    }
}

/// Loss share that counts as degradation.
///
/// Deliberately above "one sample went missing" in a short burst: a lone
/// dropped ICMP echo is normal noise on any Wi-Fi network, and a diagnostic
/// that cries wolf is worse than one that stays quiet. Two drops out of five
/// is not noise.
pub const LOSS_WARN_PCT: f64 = 25.0;

/// Aggregate quality of a *burst* of samples, not just a single "is it up".
///
/// A single probe can only answer "reachable?". The failure the tool exists to
/// catch — full bars, every hop green, yet nothing loads — is a path that is
/// reachable but *lossy* or *unstable*. That only shows up across several
/// samples, so probes send a burst and grade the aggregate.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Quality {
    /// How many samples were sent. Zero means the measurement never ran.
    pub sent: u32,
    /// Round-trip times of the samples that came back, in send order.
    pub rtts_ms: Vec<f64>,
}

impl Quality {
    /// Aggregate a set of individually-taken samples (e.g. TCP handshakes).
    pub fn from_samples(samples: &[Probe]) -> Self {
        Quality {
            sent: samples.len() as u32,
            rtts_ms: samples.iter().filter_map(|p| p.ms()).collect(),
        }
    }

    /// True when nothing was measured at all (the probe tool failed to run).
    pub fn is_empty(&self) -> bool {
        self.sent == 0
    }

    pub fn received(&self) -> u32 {
        self.rtts_ms.len() as u32
    }

    /// Percentage of samples that never came back. `None` if nothing was sent.
    pub fn loss_pct(&self) -> Option<f64> {
        if self.sent == 0 {
            return None;
        }
        let lost = self.sent.saturating_sub(self.received());
        Some(f64::from(lost) / f64::from(self.sent) * 100.0)
    }

    /// Mean round-trip time over the samples that came back.
    pub fn avg_ms(&self) -> Option<f64> {
        if self.rtts_ms.is_empty() {
            return None;
        }
        Some(self.rtts_ms.iter().sum::<f64>() / self.rtts_ms.len() as f64)
    }

    /// Jitter as the mean absolute difference between successive round trips
    /// (the IPDV definition `ping` itself reports as `stddev`-adjacent).
    ///
    /// Dropped samples are simply absent, so "successive" means successive
    /// *replies*, not successive sends — the same simplification every ping
    /// implementation makes. Needs at least two replies to mean anything.
    pub fn jitter_ms(&self) -> Option<f64> {
        if self.rtts_ms.len() < 2 {
            return None;
        }
        let total: f64 = self.rtts_ms.windows(2).map(|w| (w[1] - w[0]).abs()).sum();
        Some(total / (self.rtts_ms.len() - 1) as f64)
    }

    /// Grade the burst. `jitter_warn_ms` is per-hop: a LAN round trip should be
    /// rock steady, while a WAN one is allowed to wobble.
    ///
    /// Grades no worse than [`Status::Warn`] on purpose — loss is degradation,
    /// never a break. `Fail` stays reserved for "nothing got through at all",
    /// so a lossy-but-alive hop can't be mistaken for the point of failure.
    pub fn grade(&self, jitter_warn_ms: f64) -> Status {
        let lossy = self.loss_pct().is_some_and(|l| l >= LOSS_WARN_PCT);
        let jittery = self.jitter_ms().is_some_and(|j| j >= jitter_warn_ms);
        if lossy || jittery {
            Status::Warn
        } else {
            Status::Ok
        }
    }

    /// Plain-language evidence for the verdict, e.g. `40% packet loss`.
    /// `None` when the burst was clean or never measured.
    pub fn complaint(&self, jitter_warn_ms: f64) -> Option<String> {
        let loss = self
            .loss_pct()
            .filter(|l| *l >= LOSS_WARN_PCT)
            .map(|l| format!("{l:.0}% packet loss"));
        let jitter = self
            .jitter_ms()
            .filter(|j| *j >= jitter_warn_ms)
            .map(|j| format!("±{j:.0} ms jitter"));
        match (loss, jitter) {
            (Some(l), Some(j)) => Some(format!("{l} and {j}")),
            (Some(l), None) => Some(l),
            (None, Some(j)) => Some(j),
            (None, None) => None,
        }
    }
}

/// Fold a burst's quality onto a hop: structured fields for the diagnosis
/// engine, metrics for the human. Returns the quality grade so the caller can
/// combine it with its own reachability/latency grading.
pub fn apply_quality(hop: &mut Hop, q: &Quality, jitter_warn_ms: f64) -> Status {
    hop.loss_pct = q.loss_pct();
    hop.jitter_ms = q.jitter_ms();
    if let Some(loss) = q.loss_pct() {
        let st = if loss >= LOSS_WARN_PCT {
            Status::Warn
        } else {
            Status::Ok
        };
        let lost = q.sent.saturating_sub(q.received());
        let value = format!("{loss:.0}% ({lost}/{} lost)", q.sent);
        hop.metrics.push(Metric::new("Loss", value).with_status(st));
    }
    if let Some(j) = q.jitter_ms() {
        let st = if j >= jitter_warn_ms {
            Status::Warn
        } else {
            Status::Ok
        };
        hop.metrics
            .push(Metric::new("Jitter", format!("±{j:.1} ms")).with_status(st));
    }
    q.grade(jitter_warn_ms)
}

/// Send `count` ICMP echoes `interval` apart and aggregate the replies.
///
/// Uses the system `ping`/`ping6` binary (setuid, so no sudo). `zone` carries
/// the scope id for a link-local IPv6 target (`fe80::1%en0`), without which the
/// kernel can't pick an egress interface.
///
/// `wait` bounds the burst so a black-holed target costs a bounded amount of
/// time rather than `count * timeout`. Only `ping(8)` can enforce that itself
/// (`-t`); `ping6(8)` has no timeout option at all — its `-t` is an unrelated
/// boolean — so the v6 burst is bounded from out here instead.
///
/// Output is parsed regardless of exit status: `ping` exits non-zero on 100%
/// loss, and "everything was lost" is a result we very much want to report.
/// A run that produced neither replies *nor* a tally is treated as unmeasured
/// rather than as total loss — `ping` reports pre-transmit failures (no route,
/// interface torn down, interval refused) on stderr with an empty stdout, and
/// a probe that never left the machine must not be reported as packet loss.
pub async fn ping_burst(
    addr: IpAddr,
    zone: Option<&str>,
    count: u32,
    interval: Duration,
    wait: Duration,
) -> Quality {
    let secs = wait.as_secs().max(1).to_string();
    let count_s = count.to_string();
    // Three decimals: `ping` accepts down to 0.002s unprivileged, and rounding
    // a sub-50ms interval to `0.0` would get the whole burst rejected.
    let interval_s = format!("{:.3}", interval.as_secs_f64());
    let (bin, target) = match addr {
        IpAddr::V4(v4) => ("ping", v4.to_string()),
        IpAddr::V6(v6) => match zone {
            Some(z) => ("ping6", format!("{v6}%{z}")),
            None => ("ping6", v6.to_string()),
        },
    };
    let is_v6 = addr.is_ipv6();
    let mut cmd = Command::new(bin);
    cmd.args(["-c", &count_s]);
    if !is_v6 {
        // `ping6` would swallow the value as a `hops` positional and then fail
        // to resolve it, sending nothing at all.
        cmd.args(["-t", &secs]);
    }
    // A single sample needs no spacing, and `ping` refuses intervals below
    // 0.002s for non-root.
    if count > 1 {
        cmd.args(["-i", &interval_s]);
    }
    cmd.arg(&target).kill_on_drop(true);

    // Ceiling for the whole child: what `-t` already does for v4, and the only
    // thing bounding v6. Padded so it can't pre-empt `ping`'s own tally.
    let budget = wait + interval * count + Duration::from_secs(1);
    let out = match timeout(budget, cmd.output()).await {
        Ok(Ok(o)) => o,
        _ => return Quality::default(),
    };

    let text = String::from_utf8_lossy(&out.stdout);
    let rtts_ms = parse_ping_times(&text);
    // Prefer ping's own tally: `-t` can cut a burst short, so the number we
    // asked for isn't necessarily the number that went out.
    let sent = match parse_ping_sent(&text) {
        Some(n) => n,
        // No tally and no replies: the tool never got going.
        None if rtts_ms.is_empty() => return Quality::default(),
        None => count,
    };
    // Clamp rather than raise `sent`: duplicate replies (`(DUP!)`) are already
    // filtered out, but any other surplus must not be able to manufacture a
    // clean bill of health by making `received >= sent`.
    let keep = (sent as usize).min(rtts_ms.len());
    Quality {
        sent,
        rtts_ms: rtts_ms[..keep].to_vec(),
    }
}

/// Pull every `time=3.456 ms` out of ping output, in reply order.
///
/// Duplicate replies are skipped: a duplicating switch or a bridge loop makes
/// `ping` print more replies than it sent, and counting those as distinct
/// samples would report a genuinely broken LAN as loss-free.
fn parse_ping_times(text: &str) -> Vec<f64> {
    text.lines()
        .filter(|line| !line.contains("(DUP!)"))
        .filter_map(|line| {
            let rest = line.split_once("time=")?.1;
            rest.split_whitespace().next()?.parse::<f64>().ok()
        })
        .collect()
}

/// Read the transmitted count out of ping's `N packets transmitted, …` tally.
fn parse_ping_sent(text: &str) -> Option<u32> {
    let idx = text.find(" packets transmitted")?;
    text[..idx]
        .rsplit(|c: char| c.is_whitespace())
        .find(|w| !w.is_empty())?
        .parse::<u32>()
        .ok()
}

/// Measure the time to complete a TCP handshake to `addr`.
pub async fn tcp_connect(addr: SocketAddr, wait: Duration) -> Probe {
    let start = Instant::now();
    match timeout(wait, TcpStream::connect(addr)).await {
        Ok(Ok(_stream)) => Probe::Up(start.elapsed()),
        Ok(Err(_)) => Probe::Timeout,
        Err(_) => Probe::Timeout,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A realistic macOS `ping -c 5` transcript with two packets dropped.
    const LOSSY: &str = "\
PING 192.168.0.1 (192.168.0.1): 56 data bytes
64 bytes from 192.168.0.1: icmp_seq=0 ttl=64 time=3.456 ms
Request timeout for icmp_seq 1
64 bytes from 192.168.0.1: icmp_seq=2 ttl=64 time=9.456 ms
Request timeout for icmp_seq 3
64 bytes from 192.168.0.1: icmp_seq=4 ttl=64 time=5.456 ms

--- 192.168.0.1 ping statistics ---
5 packets transmitted, 3 packets received, 40.0% packet loss
round-trip min/avg/max/stddev = 3.456/6.123/9.456/2.483 ms";

    #[test]
    fn parses_every_ping_time_in_order() {
        assert_eq!(parse_ping_times(LOSSY), vec![3.456, 9.456, 5.456]);
    }

    #[test]
    fn no_time_field_yields_no_samples() {
        assert!(parse_ping_times("Request timeout for icmp_seq 0").is_empty());
    }

    #[test]
    fn duplicate_replies_do_not_manufacture_a_clean_bill_of_health() {
        // A duplicating switch or bridge loop makes ping print more replies
        // than it sent. Counting those as samples would report 0% loss on a
        // LAN that is in fact dropping most of the originals.
        let dup = "\
PING 192.168.0.1 (192.168.0.1): 56 data bytes
64 bytes from 192.168.0.1: icmp_seq=0 ttl=64 time=3.4 ms
64 bytes from 192.168.0.1: icmp_seq=0 ttl=64 time=3.9 ms (DUP!)
64 bytes from 192.168.0.1: icmp_seq=0 ttl=64 time=4.1 ms (DUP!)
Request timeout for icmp_seq 1
Request timeout for icmp_seq 2

--- 192.168.0.1 ping statistics ---
3 packets transmitted, 3 packets received, +2 duplicates, -0.0% packet loss";
        assert_eq!(parse_ping_times(dup), vec![3.4], "DUPs are not samples");
        let q = Quality {
            sent: parse_ping_sent(dup).unwrap(),
            rtts_ms: parse_ping_times(dup),
        };
        assert!(
            q.loss_pct().unwrap() > LOSS_WARN_PCT,
            "two of three originals were lost, got {:?}",
            q.loss_pct()
        );
    }

    #[test]
    fn parses_transmitted_count() {
        assert_eq!(parse_ping_sent(LOSSY), Some(5));
        assert_eq!(parse_ping_sent("no summary here"), None);
    }

    #[test]
    fn quality_reports_loss_and_jitter() {
        let q = Quality {
            sent: parse_ping_sent(LOSSY).unwrap(),
            rtts_ms: parse_ping_times(LOSSY),
        };
        assert_eq!(q.received(), 3);
        assert_eq!(q.loss_pct(), Some(40.0));
        // |9.456-3.456| + |5.456-9.456| = 6 + 4, over 2 gaps.
        assert_eq!(q.jitter_ms(), Some(5.0));
        assert!((q.avg_ms().unwrap() - 6.122_666).abs() < 1e-3);
    }

    #[test]
    fn total_loss_is_100_percent_not_missing() {
        // The whole point: a black-holed path must report 100% loss rather
        // than looking like "we never measured".
        let q = Quality {
            sent: 5,
            rtts_ms: vec![],
        };
        assert_eq!(q.loss_pct(), Some(100.0));
        assert_eq!(q.avg_ms(), None);
        assert_eq!(q.jitter_ms(), None);
        assert!(!q.is_empty());
    }

    #[test]
    fn a_run_that_never_transmitted_is_unmeasured_not_total_loss() {
        // `ping` reports pre-transmit failures (no route, interface gone,
        // interval refused) on stderr and leaves stdout empty. Falling back to
        // the requested count there would invent "100% packet loss" for a probe
        // that never left the machine.
        assert!(parse_ping_times("").is_empty());
        assert_eq!(parse_ping_sent(""), None);
    }

    #[test]
    fn unmeasured_burst_reports_nothing_rather_than_perfect() {
        // A `ping` binary that never ran must not read as 0% loss.
        let q = Quality::default();
        assert!(q.is_empty());
        assert_eq!(q.loss_pct(), None);
    }

    #[test]
    fn single_reply_has_no_jitter() {
        let q = Quality {
            sent: 1,
            rtts_ms: vec![4.2],
        };
        assert_eq!(q.jitter_ms(), None);
        assert_eq!(q.loss_pct(), Some(0.0));
    }

    /// Live check that the real `ping` invocation still behaves the way the
    /// parser assumes: `-i 0.2` is accepted unprivileged, and a black-holed
    /// target still prints a tally we can read despite the non-zero exit.
    /// Opt-in (`cargo test -- --ignored`) since it needs a network.
    #[tokio::test]
    #[ignore = "needs network; run manually with --ignored"]
    async fn live_burst_to_a_blackhole_reports_total_loss() {
        // TEST-NET-1 (RFC 5737) — reserved for documentation, never routed.
        let addr: IpAddr = "192.0.2.1".parse().unwrap();
        let q = ping_burst(
            addr,
            None,
            5,
            Duration::from_millis(200),
            Duration::from_secs(3),
        )
        .await;
        assert!(!q.is_empty(), "the ping binary should have run");
        assert_eq!(q.sent, 5);
        assert_eq!(q.loss_pct(), Some(100.0));
    }

    /// `ping6` has no timeout flag — its `-t` is an unrelated boolean, so a
    /// `-t <secs>` would be eaten as a `hops` positional and the burst would
    /// send nothing while looking like total loss. A v6 burst to a documentation
    /// address must come back *unmeasured*, never as fabricated packet loss.
    #[tokio::test]
    #[ignore = "needs network; run manually with --ignored"]
    async fn live_v6_burst_never_reports_fabricated_loss() {
        // 2001:db8::/32 (RFC 3849) — documentation only, never routed.
        let addr: IpAddr = "2001:db8::1".parse().unwrap();
        let q = ping_burst(
            addr,
            None,
            5,
            Duration::from_millis(200),
            Duration::from_secs(2),
        )
        .await;
        assert!(
            q.is_empty() || q.loss_pct() == Some(100.0),
            "a v6 burst must be unmeasured or genuinely lost, got {q:?}"
        );
        assert!(
            q.rtts_ms.is_empty(),
            "nothing can come back from a documentation prefix"
        );
    }

    #[test]
    fn quality_from_samples_counts_timeouts_as_loss() {
        let q = Quality::from_samples(&[
            Probe::Up(Duration::from_millis(10)),
            Probe::Timeout,
            Probe::Up(Duration::from_millis(30)),
            Probe::Timeout,
        ]);
        assert_eq!(q.sent, 4);
        assert_eq!(q.loss_pct(), Some(50.0));
        assert_eq!(q.jitter_ms(), Some(20.0));
    }
}
