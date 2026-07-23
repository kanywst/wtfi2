//! VPN / overlay-tunnel hop.
//!
//! Only added to the path when a tunnel is active (the engine gates on
//! [`RouteInfo::tunnel_active`]). It reports what the tunnel is and whether it
//! carries *all* traffic (full-tunnel) or only some routes (split-tunnel) —
//! full-tunnel is what makes a VPN outage masquerade as an ISP outage, so the
//! diagnosis engine keys off the `Mode` metric this hop records.

use crate::model::{Hop, HopId, Layer, Metric, Status};
use crate::platform::{Platform, RouteInfo};

pub fn probe(platform: &impl Platform, route: &RouteInfo) -> Hop {
    let mut hop = Hop::new(HopId::Vpn, Layer::Network, "VPN");
    let info = platform.vpn().unwrap_or_default();

    // Prefer the enriched interface; fall back to what the route probe saw in
    // case the tunnel changed between the two reads.
    let iface = info
        .interface
        .clone()
        .or_else(|| route.tunnel_iface.clone());

    // Full-tunnel = the tunnel owns the default route, so everything egresses
    // through it. Split-tunnel = it only claims specific routes.
    let full_tunnel = iface
        .as_deref()
        .map(|i| i == route.interface)
        .unwrap_or(false);
    let mode = if full_tunnel {
        "full-tunnel"
    } else {
        "split-tunnel"
    };

    hop.subtitle = info.vendor.clone().or_else(|| iface.clone());
    if let Some(i) = &iface {
        hop.metrics.push(Metric::new("Interface", i.clone()));
    }
    if let Some(ip) = info.local_ip {
        hop.metrics.push(Metric::new("Tunnel IP", ip.to_string()));
    }
    hop.metrics.push(Metric::new("Mode", mode));
    if let Some(v) = &info.vendor {
        hop.metrics.push(Metric::new("Vendor", v.clone()));
    }

    // Tunnel present and addressed → healthy. Present but unaddressed → warn:
    // the interface is up but not actually carrying traffic yet.
    if info.local_ip.is_some() || info.active {
        hop.status = Status::Ok;
        let where_ = iface.as_deref().unwrap_or("the tunnel");
        let vendor = info
            .vendor
            .as_deref()
            .map(|v| format!("{v} "))
            .unwrap_or_default();
        hop.summary = Some(if full_tunnel {
            format!("{vendor}full-tunnel VPN on {where_} — all traffic is routed through it")
        } else {
            format!("{vendor}split-tunnel VPN on {where_} — only some routes use it")
        });
    } else {
        hop.status = Status::Warn;
        hop.summary =
            Some("Tunnel interface is up but has no address — not carrying traffic".into());
    }
    hop
}
