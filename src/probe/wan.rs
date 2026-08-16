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
use std::time::Duration;

const V4: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
const V6: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111));

/// Handshakes per sweep, counting the reachability probe itself.
const SAMPLES: u32 = 5;
/// Spacing, so the samples cover a slice of time rather than one instant.
const SPACING: Duration = Duration::from_millis(100);
/// Per-sample ceiling. The path is already known to work by this point, so a
/// handshake this slow is indistinguishable from a dropped one.
const SAMPLE_WAIT: Duration = Duration::from_secs(1);
/// The public internet is allowed to wobble more than your own LAN.
const JITTER_WARN_MS: f64 = 60.0;

pub async fn probe() -> Hop {
    let mut hop = Hop::new(HopId::Wan, Layer::Internet, "Internet");
    hop.subtitle = Some("1.1.1.1".into());

    let wait = Duration::from_secs(3);
    let (v4, v6) = tokio::join!(
        tcp_connect(SocketAddr::new(V4, 443), wait),
        tcp_connect(SocketAddr::new(V6, 443), wait),
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
            let avg = q.avg_ms().or_else(|| v4.ms()).unwrap_or(0.0);
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
/// instant. Reuses the first handshake as sample one — it already happened.
///
/// A path that dies right after that first success costs the remaining samples
/// their full timeout; that is the worst case, and it is also precisely the
/// case worth waiting for.
async fn sample_quality(first: Probe) -> Quality {
    let mut samples = Vec::with_capacity(SAMPLES as usize);
    samples.push(first);
    while (samples.len() as u32) < SAMPLES {
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
