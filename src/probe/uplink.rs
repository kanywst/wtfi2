//! The path between your gateway and the internet.
//!
//! Everything from your modem through your ISP's access network and out across
//! transit used to collapse into a single edge of the diagram. So when the WAN
//! probe found nothing reachable, the most wtfi could say was "the break is
//! past your router" — which is the part you already knew, and leaves the
//! actual question (is it my equipment or theirs?) unanswered.
//!
//! A bounded TTL sweep turns that one edge back into hops. Where the replies
//! stop is where the path stops, and *which* hop that is decides who you should
//! be calling.
//!
//! Only runs when something upstream is already wrong: it costs seconds, and
//! on a healthy network it would only confirm what the WAN probe just proved.

use crate::model::{Fault, Hop, HopId, Layer, Metric, Status};
use std::net::IpAddr;
use std::time::{Duration, Instant};
use tokio::process::Command;

/// Swept towards the same address the WAN probe treats as primary, so the two
/// findings describe one path rather than two.
const TARGET: &str = "1.1.1.1";

/// How far to look. Far enough to clear your own equipment and your ISP's edge
/// — which is where the answer lives — and no further: every unanswered hop
/// costs a full `WAIT`, and the sweep has to fit inside the probe deadline.
const MAX_TTL: u8 = 6;
/// One probe per hop. The question here is *where the path stops*, not how
/// good it is; quality is the WAN probe's job and it measures it properly.
const QUERIES: u8 = 1;
/// Seconds to wait per probe. Routers that answer at all answer quickly.
const WAIT_SECS: u8 = 1;

/// Ceiling on the whole probe, both sweeps included.
///
/// Has to sit under the engine's per-probe deadline: the sweep is what locates
/// the break, so being cut off mid-way is worst precisely when a break exists.
/// An all-silent sweep costs `MAX_TTL * WAIT_SECS`, so this leaves room for
/// process startup and little else — which is the point of the retry rule
/// below rather than simply running two sweeps.
const BUDGET: Duration = Duration::from_secs(7);
/// Below this there isn't room for a sweep worth running, so the retry is
/// skipped rather than started and truncated.
const MIN_SWEEP: Duration = Duration::from_secs(2);

/// One time-to-live step of the sweep.
#[derive(Debug, Clone, PartialEq)]
pub struct TtlHop {
    pub ttl: u8,
    /// Who answered, or `None` when the hop stayed silent.
    pub addr: Option<IpAddr>,
    pub rtt_ms: Option<f64>,
}

pub async fn probe() -> Hop {
    let mut hop = Hop::new(HopId::Uplink, Layer::Internet, "Uplink");
    hop.subtitle = Some(format!("path to {TARGET}"));

    let deadline = Instant::now() + BUDGET;

    // ICMP first: high-port UDP, which traceroute uses by default, is dropped
    // by plenty of NATs and firewalls that pass ICMP perfectly well — and a
    // sweep that dies at hop 1 because of the probe protocol would invent the
    // exact fault this module exists to locate.
    let mut hops = sweep(&["-P", "icmp"], remaining(deadline)).await;
    // Retry over UDP only when there is genuinely time left. A sweep that
    // produced nothing because the flag was refused fails in milliseconds; one
    // that produced nothing because every hop stayed silent has already spent
    // the budget, and running it again would only overrun the deadline to
    // re-learn the same silence.
    if hops.is_empty() {
        let left = remaining(deadline);
        if left >= MIN_SWEEP {
            hops = sweep(&[], left).await;
        }
    }

    let target: IpAddr = TARGET.parse().expect("TARGET is a literal address");
    grade(&mut hop, &hops, target);
    hop
}

/// Turn the sweep into a verdict about where the path stops. Pure, so the
/// reasoning is testable without a network to break.
fn grade(hop: &mut Hop, hops: &[TtlHop], target: IpAddr) {
    for h in hops {
        let value = match (h.addr, h.rtt_ms) {
            (Some(addr), Some(ms)) => format!("{addr}  {ms:.1} ms"),
            (Some(addr), None) => addr.to_string(),
            (None, _) => "*".to_string(),
        };
        let status = if h.addr.is_some() {
            Status::Ok
        } else {
            Status::Warn
        };
        hop.metrics
            .push(Metric::new(format!("hop {}", h.ttl), value).with_status(status));
    }

    if hops.is_empty() {
        hop.status = Status::Warn;
        hop.fault = Some(Fault::Unobserved);
        hop.summary = Some("Couldn't trace the path — traceroute produced nothing".into());
        return;
    }

    if hops.iter().any(|h| h.addr == Some(target)) {
        // The path is intact all the way to the target, so whatever the WAN
        // probe hit is specific to the service rather than to the route.
        hop.status = Status::Ok;
        hop.latency_ms = hops.iter().rev().find_map(|h| h.rtt_ms);
        hop.summary = Some(format!(
            "Path to {target} is intact over {} hops — the route is fine, so the failure is specific to what was tested",
            hops.len()
        ));
        return;
    }

    let Some(last) = hops.iter().rev().find(|h| h.addr.is_some()) else {
        // Not even the first hop answered. That is your own router, and the
        // gateway probe owns that verdict — say what was seen and let it.
        hop.status = Status::Warn;
        hop.fault = Some(Fault::Unobserved);
        hop.summary =
            Some("No hop answered the trace, including your own router — nothing to locate".into());
        return;
    };

    let silent = hops.len().saturating_sub(last.ttl as usize);
    let addr = last.addr.expect("filtered on addr being present");
    if last.ttl <= 1 {
        // Hop 1 is your own router, and it answered. Nothing beyond it did, so
        // the break is on the link between your router and your provider — the
        // modem/ONU, the WAN cable, or the line itself.
        hop.fail(
            Fault::UplinkDiesAtModem,
            format!(
                "Dies immediately past your router — {addr} replied at hop 1 and nothing beyond it did, over {silent} further hops"
            ),
        );
    } else {
        // Replies got somewhere inside the provider's network and stopped.
        // That is the strongest statement this tool can make about whose
        // equipment is at fault, and it is a statement worth quoting to them.
        hop.fail(
            Fault::UplinkDiesInIsp,
            format!(
                "Dies past hop {} — the last reply came from {addr}, then {silent} hops of silence",
                last.ttl
            ),
        );
    }
}

/// Run one bounded sweep and parse it. Output is read regardless of exit
/// status: traceroute exits non-zero when it never reaches the target, which
/// is precisely the run whose output we want.
async fn sweep(extra: &[&str], budget: Duration) -> Vec<TtlHop> {
    let max = MAX_TTL.to_string();
    let queries = QUERIES.to_string();
    let wait = WAIT_SECS.to_string();
    let mut cmd = Command::new("traceroute");
    cmd.args(["-n", "-m", &max, "-q", &queries, "-w", &wait]);
    cmd.args(extra);
    cmd.arg(TARGET).kill_on_drop(true);

    match tokio::time::timeout(budget, cmd.output()).await {
        Ok(Ok(out)) => parse(&String::from_utf8_lossy(&out.stdout)),
        _ => Vec::new(),
    }
}

fn remaining(deadline: Instant) -> Duration {
    deadline.saturating_duration_since(Instant::now())
}

/// Parse `traceroute -n` output.
///
/// ```text
/// traceroute to 1.1.1.1 (1.1.1.1), 6 hops max, 52 byte packets
///  1  192.168.0.1  3.456 ms
///  2  203.0.113.1  12.345 ms
///  3  *
/// ```
///
/// The header line has no leading hop number, so requiring one to parse as a
/// TTL skips it without a special case.
fn parse(text: &str) -> Vec<TtlHop> {
    text.lines()
        .filter_map(|line| {
            let mut toks = line.split_whitespace();
            let ttl: u8 = toks.next()?.parse().ok()?;
            let rest: Vec<&str> = toks.collect();
            let addr = rest.iter().find_map(|t| parse_addr(t));
            // The round trip is whatever precedes the first `ms`. Annotations
            // traceroute appends after it (`!H`, `!N`, `!`) are deliberately
            // ignored: they qualify *how* a hop replied, and for locating
            // where the path stops, a reply is a reply.
            let rtt_ms = rest
                .windows(2)
                .find(|w| w[1] == "ms")
                .and_then(|w| w[0].parse().ok());
            Some(TtlHop { ttl, addr, rtt_ms })
        })
        .collect()
}

/// Addresses are bare under `-n`, but tolerate the parenthesised form so a
/// sweep that somehow ran without it still parses.
fn parse_addr(tok: &str) -> Option<IpAddr> {
    tok.trim_matches(['(', ')']).parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hops(spec: &[(u8, Option<&str>)]) -> Vec<TtlHop> {
        spec.iter()
            .map(|(ttl, addr)| TtlHop {
                ttl: *ttl,
                addr: addr.map(|a| a.parse().unwrap()),
                rtt_ms: addr.map(|_| 12.0),
            })
            .collect()
    }

    fn graded(spec: &[(u8, Option<&str>)]) -> Hop {
        let mut hop = Hop::new(HopId::Uplink, Layer::Internet, "Uplink");
        grade(&mut hop, &hops(spec), "1.1.1.1".parse().unwrap());
        hop
    }

    /// The whole point. "The break is past your router" is the part the reader
    /// already knew; naming the hop it stops at, and the address that last
    /// answered, is something they can act on — and quote to their ISP.
    #[test]
    fn a_break_inside_the_isp_names_the_hop_it_dies_at() {
        let hop = graded(&[
            (1, Some("192.168.0.1")),
            (2, Some("203.0.113.1")),
            (3, None),
            (4, None),
            (5, None),
            (6, None),
        ]);
        assert_eq!(hop.status, Status::Fail);
        assert_eq!(hop.fault, Some(Fault::UplinkDiesInIsp));
        let summary = hop.summary.unwrap();
        assert!(summary.contains("hop 2"), "got: {summary}");
        assert!(summary.contains("203.0.113.1"), "got: {summary}");
    }

    /// Only your own router answered: the break is on the link between it and
    /// your provider, which is your modem, your WAN cable or the line — a
    /// different call to make than "something inside the ISP is down".
    #[test]
    fn a_break_at_the_modem_is_distinguished_from_one_inside_the_isp() {
        let hop = graded(&[(1, Some("192.168.0.1")), (2, None), (3, None), (4, None)]);
        assert_eq!(hop.fault, Some(Fault::UplinkDiesAtModem));
        assert!(
            hop.summary
                .unwrap()
                .contains("immediately past your router")
        );
    }

    /// If the route reaches the target, the WAN failure was never about the
    /// route — and saying so stops the reader chasing their ISP.
    #[test]
    fn an_intact_path_clears_the_route_of_blame() {
        let hop = graded(&[
            (1, Some("192.168.0.1")),
            (2, Some("203.0.113.1")),
            (3, Some("1.1.1.1")),
        ]);
        assert_eq!(hop.status, Status::Ok);
        assert_eq!(hop.fault, None);
        assert!(hop.summary.unwrap().contains("specific to what was tested"));
    }

    /// Silence at every hop includes your own router, which the gateway probe
    /// already owns. Claiming a location from it would be inventing one.
    #[test]
    fn total_silence_locates_nothing_rather_than_guessing() {
        let hop = graded(&[(1, None), (2, None), (3, None)]);
        assert_eq!(hop.status, Status::Warn);
        assert_eq!(hop.fault, Some(Fault::Unobserved));
    }

    #[test]
    fn a_sweep_that_never_ran_is_unobserved_not_a_break() {
        let mut hop = Hop::new(HopId::Uplink, Layer::Internet, "Uplink");
        grade(&mut hop, &[], "1.1.1.1".parse().unwrap());
        assert_eq!(hop.status, Status::Warn);
        assert_eq!(hop.fault, Some(Fault::Unobserved));
        assert_ne!(
            hop.status,
            Status::Fail,
            "nothing was seen, so nothing broke"
        );
    }

    #[test]
    fn every_ttl_step_is_recorded_for_the_reader() {
        let hop = graded(&[(1, Some("192.168.0.1")), (2, None)]);
        assert_eq!(hop.metrics.len(), 2);
        assert_eq!(hop.metrics[0].label, "hop 1");
        assert!(hop.metrics[0].value.contains("192.168.0.1"));
        assert_eq!(hop.metrics[1].value, "*");
    }

    const TRACE: &str = "traceroute to 1.1.1.1 (1.1.1.1), 6 hops max, 52 byte packets
 1  192.168.0.1  3.456 ms
 2  203.0.113.1  12.345 ms
 3  *
 4  *
 5  198.51.100.9  41.2 ms
 6  *";

    #[test]
    fn traceroute_output_parses_into_ttl_steps() {
        let parsed = parse(TRACE);
        assert_eq!(parsed.len(), 6, "the header line must not become a hop");
        assert_eq!(parsed[0].ttl, 1);
        assert_eq!(parsed[0].addr.unwrap().to_string(), "192.168.0.1");
        assert_eq!(parsed[0].rtt_ms, Some(3.456));
        assert_eq!(parsed[2].addr, None);
        assert_eq!(parsed[4].addr.unwrap().to_string(), "198.51.100.9");
    }

    /// A hop that replies with an unreachable still replied. The annotation
    /// qualifies *how*, and for locating where the path stops that doesn't
    /// change the answer.
    #[test]
    fn annotated_replies_still_count_as_replies() {
        let parsed = parse(" 3  203.0.113.5  19.1 ms !H");
        assert_eq!(parsed[0].addr.unwrap().to_string(), "203.0.113.5");
        assert_eq!(parsed[0].rtt_ms, Some(19.1));
    }

    #[test]
    fn a_multi_query_line_takes_the_first_round_trip() {
        let parsed = parse(" 2  203.0.113.1  12.3 ms  14.9 ms  13.1 ms");
        assert_eq!(parsed[0].rtt_ms, Some(12.3));
    }

    #[test]
    fn noise_and_empty_output_yield_no_hops() {
        assert!(parse("").is_empty());
        assert!(parse("traceroute: unknown host\n").is_empty());
        assert!(parse("some unrelated line\n").is_empty());
    }

    /// The sweep has to fit inside the engine's per-probe deadline even when
    /// every single hop stays silent, or the thing that locates the break gets
    /// cut off precisely when the break exists. This covers *both* sweeps,
    /// since the retry shares the same budget rather than getting its own.
    #[test]
    fn the_worst_case_sweep_fits_the_probe_deadline() {
        assert!(
            BUDGET < crate::engine::PROBE_DEADLINE,
            "total budget {BUDGET:?} must fit in {:?}",
            crate::engine::PROBE_DEADLINE
        );
    }

    /// An all-silent sweep must be able to run to its full depth inside the
    /// budget — otherwise the timeout truncates the very evidence that locates
    /// the break, and every outage would read as "couldn't trace the path".
    #[test]
    fn a_fully_silent_sweep_fits_the_budget() {
        let worst = Duration::from_secs((MAX_TTL * WAIT_SECS) as u64);
        assert!(
            worst < BUDGET,
            "an all-silent sweep takes {worst:?}, budget is {BUDGET:?}"
        );
    }

    /// And when that happens there must be no room left for a retry: running
    /// the second sweep would overrun the deadline only to re-learn the same
    /// silence.
    #[test]
    fn a_spent_budget_leaves_no_room_for_a_retry() {
        let worst = Duration::from_secs((MAX_TTL * WAIT_SECS) as u64);
        assert!(
            BUDGET - worst < MIN_SWEEP,
            "a sweep that ran to full depth must not trigger a retry"
        );
    }
}
