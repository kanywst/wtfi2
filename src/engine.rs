//! Orchestration: fan probes out concurrently and stream graded hops back.
//!
//! The engine seeds a canonical path skeleton, then runs every probe in
//! parallel. Each finished hop is pushed onto a channel the moment it lands, so
//! the live dashboard fills in out of order as results arrive, and the
//! one-shot mode simply drains the same channel.

use crate::model::{Hop, HopId, Layer, Path, Status};
use crate::platform::{self, Platform};
use crate::probe;
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
            let mut link = Hop::new(HopId::Link, Layer::Link, "Wi-Fi");
            link.status = Status::Fail;
            link.summary = Some("No active network interface / default route".into());
            let _ = tx.send(link);
            for id in [HopId::Gateway, HopId::Wan, HopId::Dns, HopId::Captive] {
                let mut h = Hop::new(id, Layer::Network, "—");
                h.status = Status::Skipped;
                let _ = tx.send(h);
            }
            return;
        };

        // L2 link telemetry is a blocking `system_profiler` call.
        let iface = route.interface.clone();
        let tx_link = tx.clone();
        tokio::task::spawn_blocking(move || {
            let p = platform::current();
            let _ = tx_link.send(probe::link::probe(&p, &iface));
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
        if let Some(slot) = path.get_mut(hop.id) {
            *slot = hop;
        }
    }
    path
}
