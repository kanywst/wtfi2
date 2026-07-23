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
    if info.active && info.local_ip.is_some() {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::{LinkInfo, PlatformError, ResolverInfo, VpnInfo};

    struct MockPlatform(VpnInfo);
    impl Platform for MockPlatform {
        fn route(&self) -> Result<RouteInfo, PlatformError> {
            Ok(RouteInfo::default())
        }
        fn link(&self, _: &str) -> Result<LinkInfo, PlatformError> {
            Ok(LinkInfo::default())
        }
        fn resolvers(&self) -> Result<ResolverInfo, PlatformError> {
            Ok(ResolverInfo::default())
        }
        fn vpn(&self) -> Result<VpnInfo, PlatformError> {
            Ok(self.0.clone())
        }
    }

    fn route_on(iface: &str) -> RouteInfo {
        RouteInfo {
            interface: iface.to_string(),
            ..Default::default()
        }
    }

    fn mode(hop: &Hop) -> &str {
        hop.metrics
            .iter()
            .find(|m| m.label == "Mode")
            .map(|m| m.value.as_str())
            .unwrap_or("")
    }

    #[test]
    fn full_tunnel_when_vpn_owns_default_route() {
        let vpn = VpnInfo {
            active: true,
            interface: Some("utun4".into()),
            local_ip: Some("100.86.1.2".parse().unwrap()),
            vendor: Some("Tailscale".into()),
        };
        // The default route is on the tunnel → full-tunnel.
        let hop = probe(&MockPlatform(vpn), &route_on("utun4"));
        assert_eq!(hop.status, Status::Ok);
        assert_eq!(mode(&hop), "full-tunnel");
        assert!(hop.summary.unwrap().contains("full-tunnel"));
    }

    #[test]
    fn split_tunnel_when_default_route_stays_off_the_tunnel() {
        let vpn = VpnInfo {
            active: true,
            interface: Some("utun4".into()),
            local_ip: Some("10.8.0.2".parse().unwrap()),
            vendor: None,
        };
        let hop = probe(&MockPlatform(vpn), &route_on("en0"));
        assert_eq!(hop.status, Status::Ok);
        assert_eq!(mode(&hop), "split-tunnel");
    }

    #[test]
    fn active_but_unaddressed_tunnel_warns() {
        // Interface is up in the network state but hasn't been assigned an
        // address — it isn't actually carrying traffic, so don't claim Ok.
        let vpn = VpnInfo {
            active: true,
            interface: Some("utun4".into()),
            local_ip: None,
            vendor: None,
        };
        let hop = probe(&MockPlatform(vpn), &route_on("en0"));
        assert_eq!(hop.status, Status::Warn);
        assert!(hop.summary.unwrap().contains("no address"));
    }
}
