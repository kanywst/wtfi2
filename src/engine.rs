//! Orchestration: fan probes out concurrently and stream graded hops back.
//!
//! The engine seeds a canonical path skeleton, then runs every probe in
//! parallel. Each finished hop is pushed onto a channel the moment it lands, so
//! the live dashboard fills in out of order as results arrive, and the
//! one-shot mode simply drains the same channel.

use crate::model::{Fault, Hop, HopId, Layer, Path, Status};
use crate::platform::{self, Platform, PlatformError};
use crate::probe;
use std::net::IpAddr;
use std::time::Duration;
use tokio::sync::mpsc;

/// The canonical hop order of the connectivity chain, host → internet.
pub const CHAIN: [HopId; 6] = [
    HopId::Host,
    HopId::Link,
    HopId::Gateway,
    HopId::Wan,
    HopId::Dns,
    HopId::Captive,
];

/// A freshly seeded path with every hop pending, in chain order.
pub fn skeleton() -> Path {
    let mut hops = vec![host_hop()];
    hops.push(Hop::new(HopId::Link, Layer::Link, "Wi-Fi"));
    hops.push(Hop::new(HopId::Gateway, Layer::Network, "Gateway"));
    hops.push(Hop::new(HopId::Wan, Layer::Internet, "Internet"));
    hops.push(Hop::new(HopId::Dns, Layer::Application, "DNS"));
    hops.push(Hop::new(HopId::Captive, Layer::Application, "Portal"));
    Path { hops }
}

/// Ceiling on any one probe.
///
/// Every probe sizes its own sampling to finish well inside this; the deadline
/// is the backstop for the tool underneath wedging (`system_profiler` has, and
/// a resolver pointed at a black hole will). Without it one stuck probe holds
/// the scan channel open, which stalls the one-shot report and costs the live
/// dashboard its re-probe cadence — during exactly the outage it is meant to
/// be showing you.
pub(crate) const PROBE_DEADLINE: Duration = Duration::from_secs(8);

/// Ceiling on a whole sweep.
///
/// Each probe is bounded individually, so this only catches a task that never
/// sends at all: the channel closes when the last sender drops, and one leaked
/// sender would otherwise hang the CLI forever.
pub const SWEEP_DEADLINE: Duration = Duration::from_secs(20);

/// The hop a probe leaves behind when it overruns [`PROBE_DEADLINE`].
///
/// Graded `Warn`, never `Fail`: a probe that never answered observed nothing,
/// and "we couldn't measure this" must not be dressed up as "this is broken".
fn unmeasured(id: HopId, layer: Layer, title: &str, note: &str) -> Hop {
    let mut hop = Hop::new(id, layer, title);
    hop.status = Status::Warn;
    hop.fault = Some(Fault::Unobserved);
    hop.summary = Some(note.to_string());
    hop
}

/// Run a probe under [`PROBE_DEADLINE`] and send whatever it produced, falling
/// back to `unmeasured` so the hop always reaches a terminal state — otherwise
/// the dashboard waits forever on a hop that is never coming.
async fn send_bounded(
    tx: mpsc::UnboundedSender<Hop>,
    unmeasured: Hop,
    probe: impl Future<Output = Option<Hop>>,
) {
    let hop = tokio::time::timeout(PROBE_DEADLINE, probe)
        .await
        .ok()
        .flatten()
        .unwrap_or(unmeasured);
    let _ = tx.send(hop);
}

/// Whether the WAN result is worth spending a TTL sweep on.
///
/// The sweep costs seconds, so it is not part of every run. It earns them only
/// when the question it answers — *where* past your router does this stop? —
/// is actually open: when nothing is reachable, or when the path answers
/// handshakes without carrying traffic. A merely slow or lossy uplink is
/// already described by the WAN probe, which measures quality properly; a
/// one-probe-per-hop sweep would add nothing.
fn needs_uplink_sweep(wan: &Hop) -> bool {
    wan.status == Status::Fail || wan.fault == Some(Fault::HandshakeOnly)
}

/// Emit a path that stops at the link: the Link hop carries `status`, `fault`
/// and `summary`, and everything downstream is skipped because there is
/// nothing left to measure it over.
///
/// The three arguments travel together so a stalled sweep can never ship a
/// status without the code and the prose that explain it.
fn send_stalled(tx: &mpsc::UnboundedSender<Hop>, status: Status, fault: Fault, summary: String) {
    for mut hop in skeleton().hops {
        match hop.id {
            HopId::Host => continue,
            HopId::Link => {
                hop.status = status;
                hop.fault = Some(fault);
                hop.summary = Some(summary.clone());
            }
            _ => hop.status = Status::Skipped,
        }
        let _ = tx.send(hop);
    }
}

/// The unmeasured `You` hop the skeleton starts from, before the host probe
/// has said what address this machine actually holds.
fn host_hop() -> Hop {
    let mut h = Hop::new(HopId::Host, Layer::Link, "You");
    h.subtitle = Some("this Mac".into());
    h
}

/// Measure local addressing, falling back to the primary interface when there
/// is no default route to name one. That fallback is the point: a link that
/// came up and never got a lease has no route *because* of the fault, and it
/// is the state most worth reporting.
fn probe_host(iface: Option<String>, gateway: Option<IpAddr>) -> Hop {
    let platform = platform::current();
    let iface = iface.or_else(|| platform.primary_interface().ok());
    match iface {
        Some(iface) => probe::host::probe(&platform, &iface, gateway),
        None => {
            let mut hop = host_hop();
            hop.status = Status::Warn;
            hop.fault = Some(Fault::Unobserved);
            hop.summary = Some("Couldn't tell which interface to inspect".into());
            hop
        }
    }
}

/// Spawn all probes; returns a receiver of hops as they complete.
pub fn spawn() -> mpsc::UnboundedReceiver<Hop> {
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        // Nothing can be measured without a platform module, and an unmeasured
        // hop is unknown rather than broken. Probing anyway would grade every
        // refusal as a network fault.
        if let Some(reason) = platform::UNSUPPORTED_OS {
            let mut host = host_hop();
            host.status = Status::Skipped;
            host.fault = Some(Fault::Unobserved);
            let _ = tx.send(host);
            send_stalled(&tx, Status::Skipped, Fault::Unobserved, reason.into());
            return;
        }

        let route = match tokio::task::spawn_blocking(|| platform::current().route()).await {
            Ok(Ok(route)) => route,
            // The routing table was read and had no default route: nothing
            // downstream can be measured. Record it as *no route*, not as "not
            // associated" — you can be perfectly associated to an AP and still
            // have no lease, and the two faults have different fixes.
            Ok(Err(PlatformError::NoNetwork)) => {
                // Still measure the host: "no route" and "no lease" look
                // identical from the routing table, and the host hop is the
                // only place that can tell them apart.
                //
                // Bounded like every other probe. It shells out to
                // `networksetup` and `ifconfig`, and awaiting it unbounded
                // here would hold the sweep before `send_stalled` ever runs —
                // leaving every downstream hop Pending, which the one-shot CLI
                // survives via its outer deadline but the live dashboard does
                // not: it would sit on "scanning" forever.
                let host = tokio::time::timeout(
                    PROBE_DEADLINE,
                    tokio::task::spawn_blocking(|| probe_host(None, None)),
                )
                .await
                .ok()
                .and_then(Result::ok)
                .unwrap_or_else(|| {
                    unmeasured(
                        HopId::Host,
                        Layer::Link,
                        "You",
                        "Couldn't read this machine's addresses",
                    )
                });
                let _ = tx.send(host);
                send_stalled(
                    &tx,
                    Status::Fail,
                    Fault::NoRoute,
                    "No default route — the link is up but nothing routes off this machine".into(),
                );
                return;
            }
            // The routing table could not be read at all, so the network was
            // never observed. Grading that as an outage would report a working
            // connection as broken on the strength of our own blindness.
            Ok(Err(e)) => {
                let mut host = host_hop();
                host.status = Status::Skipped;
                host.fault = Some(Fault::Unobserved);
                let _ = tx.send(host);
                send_stalled(
                    &tx,
                    Status::Skipped,
                    Fault::Unobserved,
                    format!("Couldn't read the routing table — {e}"),
                );
                return;
            }
            Err(e) => {
                let mut host = host_hop();
                host.status = Status::Skipped;
                host.fault = Some(Fault::Unobserved);
                let _ = tx.send(host);
                send_stalled(
                    &tx,
                    Status::Skipped,
                    Fault::Unobserved,
                    format!("The route lookup didn't finish — {e}"),
                );
                return;
            }
        };

        // Host addressing.
        let iface_host = route.interface.clone();
        let gw_host = route.gateway;
        let tx_host = tx.clone();
        tokio::spawn(send_bounded(
            tx_host,
            unmeasured(
                HopId::Host,
                Layer::Link,
                "You",
                "Couldn't read this machine's addresses",
            ),
            async move {
                tokio::task::spawn_blocking(move || probe_host(Some(iface_host), gw_host))
                    .await
                    .ok()
            },
        ));

        // L2 link telemetry is a blocking platform call that can be slow
        // (`system_profiler` takes seconds) and has been known to wedge.
        let iface = route.interface.clone();
        let tx_link = tx.clone();
        tokio::spawn(send_bounded(
            tx_link,
            unmeasured(
                HopId::Link,
                Layer::Link,
                "Wi-Fi",
                "Link telemetry timed out — the Wi-Fi state is unknown, not bad",
            ),
            async move {
                tokio::task::spawn_blocking(move || {
                    probe::link::probe(&platform::current(), &iface)
                })
                .await
                .ok()
            },
        ));

        // Gateway.
        let tx_gw = tx.clone();
        let route_gw = route.clone();
        tokio::spawn(send_bounded(
            tx_gw,
            unmeasured(
                HopId::Gateway,
                Layer::Network,
                "Gateway",
                "The gateway probe didn't finish — the router's state is unknown",
            ),
            async move { Some(probe::gateway::probe(&route_gw).await) },
        ));

        // WAN, and — only if it finds trouble — the TTL sweep that says where
        // in the uplink the trouble is.
        let tx_wan = tx.clone();
        tokio::spawn(async move {
            let hop = tokio::time::timeout(PROBE_DEADLINE, probe::wan::probe())
                .await
                .unwrap_or_else(|_| {
                    unmeasured(
                        HopId::Wan,
                        Layer::Internet,
                        "Internet",
                        "The internet probe didn't finish — reachability is unknown",
                    )
                });

            if needs_uplink_sweep(&hop) {
                // Seed the pending hop *before* the WAN result lands. The
                // dashboard renders a verdict as soon as every hop is
                // terminal, so sending the WAN failure first would flash
                // "your ISP is down" and only then narrow it down — the same
                // reason the VPN hop is seeded up front.
                let _ = tx_wan.send(Hop::new(HopId::Uplink, Layer::Internet, "Uplink"));
                let tx_up = tx_wan.clone();
                tokio::spawn(send_bounded(
                    tx_up,
                    unmeasured(
                        HopId::Uplink,
                        Layer::Internet,
                        "Uplink",
                        "Couldn't trace the path past your router",
                    ),
                    async { Some(probe::uplink::probe().await) },
                ));
            }
            let _ = tx_wan.send(hop);
        });

        // DNS.
        let tx_dns = tx.clone();
        tokio::spawn(send_bounded(
            tx_dns,
            unmeasured(
                HopId::Dns,
                Layer::Application,
                "DNS",
                "The DNS probe didn't finish — resolution is unknown",
            ),
            async {
                // The configured resolvers come from a blocking platform call;
                // read them here rather than in the fan-out so a slow `scutil`
                // delays only the DNS hop.
                let nameservers = tokio::task::spawn_blocking(|| {
                    platform::current().resolvers().map(|r| r.nameservers)
                })
                .await
                .ok()
                .and_then(Result::ok)
                .unwrap_or_default();
                Some(probe::dns::probe(&nameservers).await)
            },
        ));

        // VPN / tunnel — conditional: only a hop when a tunnel is active. Seed a
        // pending hop up front so a finished base chain can't run the diagnosis
        // (and briefly mis-blame the ISP for a full-tunnel outage) before the
        // VPN result lands. The blocking platform calls (scutil/ifconfig/ps) are
        // bounded like the link probe so a hung tool can't hold the scan channel
        // open forever — on timeout we still emit a terminal (warn) hop.
        // The tunnel lookup failed, so we cannot say whether a VPN is carrying
        // this traffic. Emit the hop anyway, marked unobserved: a silently
        // absent VPN hop reads as "no VPN", which is what lets a dead
        // full-tunnel outage get reported as the ISP's fault.
        if route.tunnel_unreadable {
            let mut hop = Hop::new(HopId::Vpn, Layer::Network, "VPN");
            hop.status = Status::Warn;
            hop.fault = Some(Fault::Unobserved);
            hop.summary =
                Some("Couldn't tell whether a VPN is active — the tunnel lookup failed".into());
            let _ = tx.send(hop);
        }

        if route.tunnel_active {
            let mut pending = Hop::new(HopId::Vpn, Layer::Network, "VPN");
            pending.subtitle = route.tunnel_iface.clone();
            let _ = tx.send(pending);

            let tx_vpn = tx.clone();
            let route_vpn = route.clone();
            tokio::spawn(send_bounded(
                tx_vpn,
                unmeasured(
                    HopId::Vpn,
                    Layer::Network,
                    "VPN",
                    "VPN telemetry timed out — the tunnel's state is unknown",
                ),
                async move {
                    tokio::task::spawn_blocking(move || {
                        probe::vpn::probe(&platform::current(), &route_vpn)
                    })
                    .await
                    .ok()
                },
            ));
        }

        // Captive portal.
        let tx_cap = tx;
        tokio::spawn(send_bounded(
            tx_cap,
            unmeasured(
                HopId::Captive,
                Layer::Application,
                "Portal",
                "The portal probe didn't finish — interception is unknown",
            ),
            async { Some(probe::captive::probe().await) },
        ));
    });
    rx
}

/// Run every probe and collect the completed path (one-shot mode).
pub async fn run_once() -> Path {
    run_once_within(SWEEP_DEADLINE).await
}

/// [`run_once`] with an explicit ceiling on the whole sweep.
///
/// Draining the channel to exhaustion is only safe while every sender is
/// guaranteed to drop; `deadline` makes the CLI answer *something* even if one
/// never does. Hops that never landed are reported as unmeasured rather than
/// left `Pending`, so a truncated sweep can't render as "Scanning your
/// connection…" in a report that has already stopped scanning.
pub async fn run_once_within(deadline: Duration) -> Path {
    let mut path = skeleton();
    let mut rx = spawn();
    let sleep = tokio::time::sleep(deadline);
    tokio::pin!(sleep);
    loop {
        tokio::select! {
            hop = rx.recv() => match hop {
                Some(hop) => path.upsert(hop),
                None => break,
            },
            _ = &mut sleep => break,
        }
    }
    for hop in &mut path.hops {
        if hop.status == Status::Pending {
            hop.status = Status::Warn;
            hop.fault = Some(Fault::Unobserved);
            hop.summary = Some("The sweep ended before this hop reported".into());
        }
    }
    path
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The uplink sweep is spawned *after* the WAN probe reports, so the two
    /// budgets stack on one sweep clock — each capped at `PROBE_DEADLINE`, but
    /// in series. Nothing pinned that composition: the uplink probe's own
    /// tests only cover its two internal sweeps against `PROBE_DEADLINE`, not
    /// this WAN-then-Uplink chain against the sweep-level one.
    #[test]
    fn a_wan_failure_and_its_uplink_sweep_both_fit_one_sweep() {
        let stacked = PROBE_DEADLINE + PROBE_DEADLINE;
        assert!(
            stacked < SWEEP_DEADLINE,
            "WAN then Uplink is {stacked:?}, which must fit in {SWEEP_DEADLINE:?}"
        );
    }

    /// A sweep that gets cut short must still hand back a path whose every hop
    /// has settled. A leftover `Pending` renders as "Scanning your
    /// connection…" in a report that has already stopped scanning, and leaves
    /// the live dashboard waiting on a hop that is never coming.
    #[tokio::test]
    async fn a_truncated_sweep_still_settles_every_hop() {
        let path = run_once_within(Duration::from_millis(1)).await;
        let unsettled: Vec<_> = path
            .hops
            .iter()
            .filter(|h| !h.status.is_terminal())
            .map(|h| h.id)
            .collect();
        assert!(unsettled.is_empty(), "left pending: {unsettled:?}");
    }

    /// And what it hands back must say the hops were *unmeasured*, not graded.
    #[tokio::test]
    async fn a_truncated_sweep_reports_the_gap_rather_than_a_verdict() {
        let path = run_once_within(Duration::from_millis(1)).await;
        assert!(
            path.hops.iter().any(|h| h.fault == Some(Fault::Unobserved)),
            "a sweep this short cannot have measured anything"
        );
        assert!(
            !path.hops.iter().any(|h| h.status == Status::Fail),
            "nothing was observed, so nothing may be called broken"
        );
    }
}
