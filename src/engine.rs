//! Orchestration: fan probes out concurrently and stream graded hops back.
//!
//! The engine seeds a canonical path skeleton, then runs every probe in
//! parallel. Each finished hop is pushed onto a channel the moment it lands, so
//! the live dashboard fills in out of order as results arrive, and the
//! one-shot mode simply drains the same channel.

use crate::model::{Hop, HopId, Layer, Path, Status};
use crate::platform::{self, Platform};
use crate::probe;
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

fn host_hop() -> Hop {
    let mut h = Hop::new(HopId::Host, Layer::Link, "You");
    h.status = Status::Ok;
    h.subtitle = Some("this Mac".into());
    h
}

/// Spawn all probes; returns a receiver of hops as they complete.
pub fn spawn() -> mpsc::UnboundedReceiver<Hop> {
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        let _ = tx.send(host_hop());

        let route = tokio::task::spawn_blocking(|| platform::current().route())
            .await
            .ok()
            .and_then(Result::ok);

        let Some(route) = route else {
            // No default route: link is down, everything downstream is moot.
            // Source correctly-typed hops from the skeleton; fail the link and
            // skip everything downstream.
            for mut hop in skeleton().hops {
                match hop.id {
                    HopId::Host => continue,
                    HopId::Link => {
                        hop.status = Status::Fail;
                        hop.summary = Some("No active network interface / default route".into());
                    }
                    _ => hop.status = Status::Skipped,
                }
                let _ = tx.send(hop);
            }
            return;
        };

        // L2 link telemetry is a blocking `system_profiler` call that can be
        // slow (multi-second) and has been known to wedge. Bound it so a hung
        // call degrades the Link hop instead of freezing the whole run.
        let iface = route.interface.clone();
        let tx_link = tx.clone();
        tokio::spawn(async move {
            let handle = tokio::task::spawn_blocking(move || {
                probe::link::probe(&platform::current(), &iface)
            });
            let hop = match tokio::time::timeout(Duration::from_secs(8), handle).await {
                Ok(Ok(hop)) => hop,
                _ => {
                    let mut hop = Hop::new(HopId::Link, Layer::Link, "Wi-Fi");
                    hop.status = Status::Warn;
                    hop.summary = Some("Link telemetry timed out (system_profiler slow)".into());
                    hop
                }
            };
            let _ = tx_link.send(hop);
        });

        // Gateway.
        let tx_gw = tx.clone();
        let route_gw = route.clone();
        tokio::spawn(async move {
            let _ = tx_gw.send(probe::gateway::probe(&route_gw).await);
        });

        // WAN.
        let tx_wan = tx.clone();
        tokio::spawn(async move {
            let _ = tx_wan.send(probe::wan::probe().await);
        });

        // DNS.
        let tx_dns = tx.clone();
        tokio::spawn(async move {
            let _ = tx_dns.send(probe::dns::probe().await);
        });

        // VPN / tunnel — conditional: only a hop when a tunnel is active. Seed a
        // pending hop up front so a finished base chain can't run the diagnosis
        // (and briefly mis-blame the ISP for a full-tunnel outage) before the
        // VPN result lands. The blocking platform calls (scutil/ifconfig/ps) are
        // bounded like the link probe so a hung tool can't hold the scan channel
        // open forever — on timeout we still emit a terminal (warn) hop.
        if route.tunnel_active {
            let mut pending = Hop::new(HopId::Vpn, Layer::Network, "VPN");
            pending.subtitle = route.tunnel_iface.clone();
            let _ = tx.send(pending);

            let tx_vpn = tx.clone();
            let route_vpn = route.clone();
            tokio::spawn(async move {
                let handle = tokio::task::spawn_blocking(move || {
                    probe::vpn::probe(&platform::current(), &route_vpn)
                });
                let hop = match tokio::time::timeout(Duration::from_secs(8), handle).await {
                    Ok(Ok(hop)) => hop,
                    _ => {
                        let mut hop = Hop::new(HopId::Vpn, Layer::Network, "VPN");
                        hop.status = Status::Warn;
                        hop.summary =
                            Some("VPN telemetry timed out (scutil/ifconfig/ps slow)".into());
                        hop
                    }
                };
                let _ = tx_vpn.send(hop);
            });
        }

        // Captive portal.
        let tx_cap = tx;
        tokio::spawn(async move {
            let _ = tx_cap.send(probe::captive::probe().await);
        });
    });
    rx
}

/// Run every probe and collect the completed path (one-shot mode).
pub async fn run_once() -> Path {
    let mut path = skeleton();
    let mut rx = spawn();
    while let Some(hop) = rx.recv().await {
        path.upsert(hop);
    }
    path
}
