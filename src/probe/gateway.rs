//! L3 gateway probe: can we reach the default router, and cleanly?

use super::net::{apply_quality, ping_burst};
use crate::model::{Hop, HopId, Layer, Metric, Status};
use crate::platform::RouteInfo;
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
        hop.status = Status::Fail;
        hop.summary = Some("No default gateway — you have no route off this machine".into());
        return hop;
    };

    let q = ping_burst(gw, route.gateway_zone.as_deref(), SAMPLES, INTERVAL, BUDGET).await;

    if q.is_empty() {
        hop.status = Status::Warn;
        hop.summary = Some("Couldn't run ICMP probe to the gateway".into());
        return hop;
    }

    let Some(avg) = q.avg_ms() else {
        // Every echo was dropped: the router is silent, not merely lossy.
        hop.status = Status::Fail;
        hop.summary = Some("Router isn't answering — LAN is up but the gateway is silent".into());
        apply_quality(&mut hop, &q, JITTER_WARN_MS);
        return hop;
    };

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
            "Router answers ({avg:.0} ms) but the local path is unhealthy — {c} over {} pings",
            q.sent
        ),
        (None, Status::Warn) => format!("Router is sluggish — {avg:.0} ms round trip"),
        (None, _) => format!("Router reachable in {avg:.0} ms"),
    });
    hop
}
