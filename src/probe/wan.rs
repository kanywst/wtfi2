//! WAN / internet reachability probe.
//!
//! Uses real TCP handshakes to well-known anycast resolvers on :443 — this
//! exercises the actual forwarding path and needs no root, unlike raw ICMP.
//! Runs IPv4 and IPv6 concurrently to expose asymmetric blackholing, then, once
//! IPv4 is known to work, repeats the handshake a few times to tell a healthy
//! uplink from one that is technically up but dropping traffic.

use super::net::{Probe, Quality, apply_quality, tcp_connect};
use crate::model::{Hop, HopId, Layer, Metric, Status};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

const V4: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
const V6: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111));

/// Handshakes per sweep, counting the reachability probe itself.
const SAMPLES: u32 = 5;
/// Spacing, so the samples cover a slice of time rather than one instant.
const SPACING: Duration = Duration::from_millis(100);
/// Ceiling for *every* handshake, reachability probe included.
///
/// It has to be one number: if the follow-up samples were held to a tighter
/// deadline than the probe that declared the path up, a merely slow uplink
/// would be reported as a lossy one — "80% of connections never complete" for
/// a link where every connection completes, just not quickly.
const SAMPLE_WAIT: Duration = Duration::from_secs(3);
/// Wall-clock ceiling on the follow-up sampling, so a path that dies right
/// after the first success can't stretch the sweep past the dashboard's tick.
///
/// It is a real ceiling because no sample is *started* unless its own worst
/// case still fits inside it — checking only the start time would let a single
/// timed-out handshake overshoot by most of [`SAMPLE_WAIT`]. The cost is that
/// a dying path yields a short burst, which is reported as what it is: a loss
/// figure over the handshakes actually attempted.
const SAMPLE_BUDGET: Duration = Duration::from_millis(3600);

const _: () = assert!(
    SAMPLE_BUDGET.as_millis() >= SPACING.as_millis() + SAMPLE_WAIT.as_millis(),
    "the budget must admit at least one full-length follow-up sample"
);

/// The public internet is allowed to wobble more than your own LAN. Sized so a
/// single latency spike can't trip it: mean IPDV over `n` samples turns one
/// spike of `S` into roughly `2S/(n-1)`, i.e. `S/2` at five samples.
const JITTER_WARN_MS: f64 = 120.0;

pub async fn probe() -> Hop {
    let mut hop = Hop::new(HopId::Wan, Layer::Internet, "Internet");
    hop.subtitle = Some("1.1.1.1".into());

    let (v4, v6) = tokio::join!(
        tcp_connect(SocketAddr::new(V4, 443), SAMPLE_WAIT),
        tcp_connect(SocketAddr::new(V6, 443), SAMPLE_WAIT),
    );

    // IPv4 is the critical path; IPv6 absence is common and only a soft note.
    push_family(&mut hop, "IPv4", v4, Status::Fail);
    push_family(&mut hop, "IPv6", v6, Status::Warn);

    match (v4.is_up(), v6.is_up()) {
        // IPv4 is up, so reachability is settled and the open question is
        // quality. IPv4-only is the common, healthy case on home LANs — note
        // the missing IPv6 without crying wolf about reachability.
        (true, dual_stack) => {
            let q = sample_quality(v4).await;
            // Always `Some`: this arm means the first handshake succeeded, and
            // `sample_quality` keeps it as sample one.
            let avg = q.avg_ms().unwrap_or_default();
            hop.latency_ms = Some(avg);
            hop.status = apply_quality(&mut hop, &q, JITTER_WARN_MS);
            let family = if dual_stack { "IPv4 + IPv6" } else { "IPv4" };
            hop.summary = Some(match (q.complaint(JITTER_WARN_MS), dual_stack) {
                (Some(c), _) => format!(
                    "Reachable over {family} but the uplink is unhealthy — {c} over {} handshakes",
                    q.sent
                ),
                (None, true) => format!("Reachable over IPv4 + IPv6 ({avg:.0} ms)"),
                (None, false) => {
                    format!("Reachable over IPv4 ({avg:.0} ms) · no IPv6 on this network")
                }
            });
        }
        (false, true) => {
            hop.status = Status::Warn;
            hop.latency_ms = v6.ms();
            hop.summary = Some("IPv6-only reachable — IPv4 path is blackholed".into());
        }
        (false, false) => {
            hop.status = Status::Fail;
            hop.summary =
                Some("No TCP path to the internet — the break is past your router".into());
        }
    }
    hop
}

/// Follow the successful reachability handshake with more of the same, spaced
/// out, so loss and jitter are measured over a slice of time rather than one
/// instant. Reuses the first handshake as sample one — it already happened,
/// and it was taken under the same deadline as the rest.
///
/// Stops early once [`SAMPLE_BUDGET`] can no longer fit a whole sample. A path
/// that dies right after that first success would otherwise cost every
/// remaining sample its full timeout, and a short honest burst beats a long one
/// that overruns the sweep.
async fn sample_quality(first: Probe) -> Quality {
    let deadline = Instant::now() + SAMPLE_BUDGET;
    let mut samples = Vec::with_capacity(SAMPLES as usize);
    samples.push(first);
    // The worst case of the *whole* iteration has to fit, not just its start:
    // a handshake that times out takes SAMPLE_WAIT no matter how much budget
    // is left when it begins.
    while (samples.len() as u32) < SAMPLES && Instant::now() + SPACING + SAMPLE_WAIT <= deadline {
        tokio::time::sleep(SPACING).await;
        samples.push(tcp_connect(SocketAddr::new(V4, 443), SAMPLE_WAIT).await);
    }
    Quality::from_samples(&samples)
}

fn push_family(hop: &mut Hop, label: &str, p: Probe, down: Status) {
    let (val, st) = match p {
        Probe::Up(d) => (format!("{:.0} ms", d.as_secs_f64() * 1000.0), Status::Ok),
        Probe::Timeout => ("unreachable".into(), down),
    };
    hop.metrics.push(Metric::new(label, val).with_status(st));
}
