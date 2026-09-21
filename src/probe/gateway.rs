//! L3 gateway probe: can we reach the default router, and cleanly?
//!
//! ICMP is the first choice — it needs no open port and measures the router
//! itself rather than a service on it. But plenty of routers (hotel, campus,
//! enterprise, some ISP-supplied gear) are configured to drop echo requests,
//! and grading those as dead is a serious false positive: the gateway is the
//! first hop in the chain, so a wrong verdict here owns the whole report and
//! sends you to reboot a router that was working the entire time. So silence
//! on ICMP is not a conclusion, it is a reason to ask again over TCP.

use super::net::{Quality, apply_quality, ping_burst, tcp_connect};
use crate::model::{Fault, Hop, HopId, Layer, Metric, Status};
use crate::platform::RouteInfo;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

/// Echoes per sweep. Enough that two drops (the degradation threshold) means
/// something, few enough to finish well inside the dashboard's re-probe tick.
const SAMPLES: u32 = 5;
/// Spacing between echoes: wide enough that the burst samples a slice of time
/// rather than one instant, short enough to finish in under a second.
const INTERVAL: Duration = Duration::from_millis(200);
/// Hard ceiling on the whole burst, so a silent router costs a bounded wait.
const BUDGET: Duration = Duration::from_secs(3);
/// A round trip inside your own house should be steady, but Wi-Fi power save
/// routinely parks one packet. Mean IPDV over `n` samples turns a single spike
/// of `S` into roughly `2S/(n-1)` — `S/2` at five samples — so this sits above
/// what one 100 ms stall can produce and only trips on sustained wobble.
const JITTER_WARN_MS: f64 = 60.0;
/// Above this the router itself is the bottleneck, loss or no loss.
const SLOW_MS: f64 = 50.0;

/// Ports to try when ICMP draws a blank, in the order a home gateway is most
/// likely to have them open: its admin UI, then its DNS forwarder.
const TCP_PORTS: [u16; 3] = [443, 80, 53];
/// Per-handshake ceiling for the TCP fallback. Short, because a router on your
/// own LAN answers in single-digit milliseconds or not at all, and the whole
/// fallback has to fit in what is left of the probe deadline after ICMP has
/// already spent its budget.
const TCP_WAIT: Duration = Duration::from_millis(800);
/// Handshakes in the TCP fallback burst, counting the one that found the port.
const TCP_SAMPLES: usize = 3;
/// Spacing for the fallback burst.
const TCP_INTERVAL: Duration = Duration::from_millis(150);

pub async fn probe(route: &RouteInfo) -> Hop {
    let mut hop = Hop::new(HopId::Gateway, Layer::Network, "Gateway");
    hop.subtitle = route.gateway.map(|g| g.to_string());

    if let Some(mtu) = route.mtu {
        let m = Metric::new("MTU", mtu.to_string());
        hop.metrics.push(if mtu < 1500 {
            m.with_status(Status::Warn)
        } else {
            m
        });
    }
    let Some(gw) = route.gateway else {
        hop.fail(
            Fault::NoGateway,
            "No default gateway — you have no route off this machine",
        );
        return hop;
    };

    let icmp = ping_burst(gw, route.gateway_zone.as_deref(), SAMPLES, INTERVAL, BUDGET).await;
    hop.evidence = Some(format!(
        "{} ICMP echoes to {gw}, {}ms apart",
        icmp.sent,
        INTERVAL.as_millis()
    ));

    // ICMP said nothing — either every echo was dropped, or `ping` never ran.
    // Ask again over TCP before drawing any conclusion from the silence.
    let q = if icmp.avg_ms().is_some() {
        icmp
    } else {
        let fallback = tcp_fallback(gw, route.gateway_zone.as_deref(), &TCP_PORTS).await;
        // Asked of the fallback rather than recomputed here, so the summary
        // can't drift from what was actually attempted.
        let tcp_attempted = !matches!(fallback, TcpFallback::Declined);
        match fallback {
            TcpFallback::Answered(port, tcp) => {
                // The router is alive over TCP. *Why* ICMP said nothing
                // depends on whether any echo left the machine: "filtered"
                // asserts the router saw one and dropped it, which a `ping`
                // that never ran tells us nothing about. Reporting a local
                // tool failure as router behaviour is the same bug class
                // `ping_burst` was written to avoid, one layer up.
                let icmp_note = if icmp.is_empty() {
                    "no reply (the ping tool didn't run)"
                } else {
                    "filtered (echoes sent, none answered)"
                };
                hop.metrics
                    .push(Metric::new("ICMP", icmp_note).with_status(Status::Warn));
                hop.metrics
                    .push(Metric::new("Probed", format!("TCP :{port}")));
                hop.evidence = Some(format!(
                    "{} ICMP echoes to {gw} (all unanswered), then {} TCP handshakes to :{port}",
                    icmp.sent, tcp.sent
                ));
                tcp
            }
            _ if icmp.is_empty() => {
                // No echoes went out *and* no handshake completed. We never
                // measured anything, so we cannot claim the router is down.
                hop.status = Status::Warn;
                hop.fault = Some(Fault::Unobserved);
                hop.evidence = Some(if tcp_attempted {
                    format!("ICMP to {gw} never ran, and no TCP handshake completed either")
                } else {
                    format!("ICMP to {gw} never ran; a link-local gateway can't be tried over TCP")
                });
                hop.summary = Some(if tcp_attempted {
                    "Couldn't probe the gateway over ICMP or TCP — its state is unknown".into()
                } else {
                    "Couldn't probe the gateway over ICMP, and a link-local gateway can't be \
                     cross-checked over TCP — its state is unknown"
                        .to_string()
                });
                return hop;
            }
            _ => {
                // Echoes went out and none came back. Say what was actually
                // tried: on a link-local IPv6 gateway that is ICMP alone,
                // because the TCP fallback can't reach `fe80::` without a
                // scope id and declined rather than guessing.
                hop.evidence = Some(if tcp_attempted {
                    format!(
                        "{} ICMP echoes to {gw}, then TCP :{}",
                        icmp.sent,
                        TCP_PORTS.map(|p| p.to_string()).join("/:")
                    )
                } else {
                    format!(
                        "{} ICMP echoes to {gw}; no TCP cross-check is possible on a link-local gateway",
                        icmp.sent
                    )
                });
                hop.fail(
                    Fault::GatewaySilent,
                    silent_summary(icmp.sent, tcp_attempted),
                );
                apply_quality(&mut hop, &icmp, JITTER_WARN_MS);
                return hop;
            }
        }
    };

    // Always `Some`: every path reaching here produced at least one reply.
    let avg = q.avg_ms().unwrap_or_default();
    let latency = if avg > SLOW_MS {
        Status::Warn
    } else {
        Status::Ok
    };
    hop.latency_ms = Some(avg);
    hop.metrics
        .push(Metric::new("RTT", format!("{avg:.1} ms avg")).with_status(latency));

    // A hop can be slow, lossy, or both; take whichever reads worse.
    let quality = apply_quality(&mut hop, &q, JITTER_WARN_MS);
    hop.status = quality.max(latency);
    hop.summary = Some(match (q.complaint(JITTER_WARN_MS), latency) {
        (Some(c), _) => format!(
            "Router answers ({avg:.0} ms) but the local path is unhealthy — {c} over {} probes",
            q.sent
        ),
        (None, Status::Warn) => format!("Router is sluggish — {avg:.0} ms round trip"),
        (None, _) => format!("Router reachable in {avg:.0} ms"),
    });
    hop
}

/// What a silent router's summary may claim, given what was actually tried.
///
/// Pure so the claim can be tested without a router to stay silent at: the bug
/// this guards is a summary asserting three TCP handshakes on a link-local
/// gateway where the fallback declined to send any.
fn silent_summary(pings: u32, tcp_attempted: bool) -> String {
    if tcp_attempted {
        format!(
            "Router isn't answering — {pings} pings and TCP :{} all went unanswered",
            TCP_PORTS.map(|p| p.to_string()).join("/:")
        )
    } else {
        format!(
            "Router isn't answering — {pings} pings went unanswered, and a link-local gateway can't be reached over TCP to cross-check"
        )
    }
}

/// What the TCP fallback did — reported by the fallback itself rather than
/// re-derived at the call site.
///
/// The caller used to recompute the decline condition (`zone.is_none()`)
/// independently, which is two sources of truth about what was tried: a second
/// decline reason added here would have left the summary quietly claiming TCP
/// was attempted when it wasn't — the exact bug the summary fix addressed.
enum TcpFallback {
    /// A port answered, and here is a burst measured against it.
    Answered(u16, Quality),
    /// Every port was tried and none answered.
    Silent,
    /// Nothing was sent: a link-local IPv6 gateway can't be reached without
    /// the scope id `SocketAddr` cannot carry.
    Declined,
}

/// Ask the router over TCP when it won't answer ICMP.
///
/// Returns the port that answered and a burst measured against it, or `None`
/// if nothing did. A link-local IPv6 gateway is skipped: reaching `fe80::1`
/// needs the scope id that [`SocketAddr`] cannot carry, and a handshake sent
/// without it fails for a reason that has nothing to do with the router — a
/// false "silent" is exactly what this function exists to prevent.
async fn tcp_fallback(gw: IpAddr, zone: Option<&str>, ports: &[u16]) -> TcpFallback {
    if zone.is_some() {
        return TcpFallback::Declined;
    }
    // Try the candidates at once rather than in series: the ports that aren't
    // open cost a full TCP_WAIT each, and three of those in a row would not
    // fit in what ICMP left of the probe deadline.
    let found = futures::future::join_all(ports.iter().map(|&port| async move {
        (port, tcp_connect(SocketAddr::new(gw, port), TCP_WAIT).await)
    }))
    .await
    .into_iter()
    .find_map(|(port, probe)| probe.is_up().then_some((port, probe)));

    let Some((port, first)) = found else {
        return TcpFallback::Silent;
    };
    // Reuse the handshake that found the port as sample one, the way the WAN
    // probe does — it already happened, under the same deadline as the rest.
    let mut samples = vec![first];
    while samples.len() < TCP_SAMPLES {
        tokio::time::sleep(TCP_INTERVAL).await;
        samples.push(tcp_connect(SocketAddr::new(gw, port), TCP_WAIT).await);
    }
    TcpFallback::Answered(port, Quality::from_samples(&samples))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    /// The false positive this fallback exists to stop: a router that drops
    /// ICMP echo (hotel, campus, enterprise, some ISP gear) used to be graded
    /// `Fail` outright. The gateway is the first hop in the chain, so that
    /// verdict owned the whole report and sent you to reboot a router that was
    /// working the entire time.
    #[tokio::test]
    async fn a_router_that_only_answers_tcp_is_reachable_not_dead() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let TcpFallback::Answered(found, q) =
            tcp_fallback("127.0.0.1".parse().unwrap(), None, &[port]).await
        else {
            panic!("an open port must be found");
        };
        assert_eq!(found, port);
        assert_eq!(q.sent, TCP_SAMPLES as u32);
        assert_eq!(q.loss_pct(), Some(0.0), "a local listener drops nothing");
        assert!(q.avg_ms().is_some(), "the burst must yield a round trip");
    }

    #[tokio::test]
    async fn a_genuinely_silent_router_still_reports_nothing() {
        // Port 1 rather than a freed ephemeral port: the ephemeral range is
        // exactly what the other tests in this file bind, so releasing one and
        // expecting it to stay closed races against a concurrent test being
        // handed the same number. Nothing binds :1, and loopback refuses
        // instantly rather than making the test wait out TCP_WAIT.
        assert!(matches!(
            tcp_fallback("127.0.0.1".parse().unwrap(), None, &[1]).await,
            TcpFallback::Silent
        ));
    }

    /// A handshake to `fe80::1` without its scope id fails for a reason that
    /// has nothing to do with the router, so the fallback must decline rather
    /// than manufacture the false "silent" it exists to prevent.
    #[tokio::test]
    async fn a_link_local_gateway_declines_the_tcp_fallback() {
        let gw: IpAddr = "fe80::1".parse().unwrap();
        // Declined, not Silent: the difference is what stops the summary
        // claiming handshakes that were never sent.
        assert!(matches!(
            tcp_fallback(gw, Some("en0"), &TCP_PORTS).await,
            TcpFallback::Declined
        ));
    }

    /// The summary must only claim what was tried. `tcp_fallback` declines
    /// outright for a link-local IPv6 gateway — the normal shape of a SLAAC
    /// router, and exactly the ICMP-dropping case this fallback targets — so
    /// the old wording reported three TCP handshakes where none were sent.
    #[test]
    fn a_link_local_gateway_is_not_claimed_to_have_been_tried_over_tcp() {
        let summary = silent_summary(5, false);
        assert!(!summary.contains("443"), "got: {summary}");
        assert!(summary.contains("link-local"), "got: {summary}");
        assert!(summary.contains("5 pings"), "got: {summary}");
    }

    #[test]
    fn a_routable_gateway_reports_both_transports() {
        let summary = silent_summary(5, true);
        assert!(summary.contains("443"), "got: {summary}");
        assert!(summary.contains("5 pings"), "got: {summary}");
    }

    /// Port order is the order a home gateway is most likely to answer on; if
    /// it ever stops matching the doc comment, the doc comment is the bug.
    #[test]
    fn tcp_ports_are_tried_admin_ui_first() {
        assert_eq!(TCP_PORTS, [443, 80, 53]);
    }
}
