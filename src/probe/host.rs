//! The `You` hop: what address this machine was actually given.
//!
//! This used to be a static "you exist" placeholder reading `this Mac`, which
//! meant the very first node in the chain carried no evidence at all — and it
//! hid a whole class of outage. A link can associate, a gateway can appear in
//! the routing table, and the machine can still have been handed nothing
//! usable. That is a break *before* the gateway, and diagnosing it as "your
//! router isn't responding" sends you to reboot the wrong box.

use crate::model::{Fault, Hop, HopId, Layer, Metric, Status};
use crate::platform::{AddrInfo, Platform};
use std::net::IpAddr;

/// Grade the local addressing on `interface`, cross-checked against `gateway`
/// when the routing table named one.
pub fn probe(platform: &dyn Platform, interface: &str, gateway: Option<IpAddr>) -> Hop {
    let mut hop = Hop::new(HopId::Host, Layer::Link, "You");

    let addrs = match platform.addrs(interface) {
        Ok(a) => a,
        Err(e) => {
            // Unknown, not broken: the machine's addressing is whatever it is,
            // we just couldn't read it.
            hop.status = Status::Warn;
            hop.fault = Some(Fault::Unobserved);
            hop.subtitle = Some(interface.to_string());
            hop.summary = Some(format!("Couldn't read this machine's addresses — {e}"));
            return hop;
        }
    };

    grade(&mut hop, interface, &addrs, gateway);
    hop
}

/// Pure grading, so every branch below is testable without an OS underneath.
fn grade(hop: &mut Hop, interface: &str, addrs: &AddrInfo, gateway: Option<IpAddr>) {
    hop.metrics
        .push(Metric::new("Interface", interface.to_string()));

    if let Some((ip, prefix)) = addrs.v4 {
        hop.subtitle = Some(format!("{ip}/{prefix}"));
        hop.metrics
            .push(Metric::new("IPv4", format!("{ip}/{prefix}")));
        // A CGNAT address on your own LAN means the ISP is sharing one public
        // address between subscribers: inbound connections and port forwarding
        // will not work, and no amount of router fiddling changes that.
        if super::net::is_cgnat(IpAddr::V4(ip)) {
            hop.metrics.push(
                Metric::new("NAT", "carrier-grade (100.64.0.0/10)").with_status(Status::Warn),
            );
        }
    }
    for v6 in &addrs.v6 {
        hop.metrics.push(Metric::new("IPv6", v6.to_string()));
    }

    // DHCPv4 never answered, so macOS autoconfigured. Whether that is a break
    // depends on IPv6: a routable v6 address means traffic still has a way
    // out, and failing the earliest hop in the chain would hand the whole
    // verdict to a fault that isn't stopping anything.
    if addrs.is_self_assigned() {
        if addrs.v6.is_empty() {
            hop.fail(
                Fault::SelfAssignedAddr,
                "Self-assigned address — DHCP never answered, so nothing can be reached",
            );
        } else {
            hop.status = Status::Warn;
            hop.fault = Some(Fault::SelfAssignedAddr);
            hop.summary = Some(
                "DHCPv4 never answered (self-assigned address), but IPv6 is configured — anything IPv4-only will fail".into(),
            );
        }
        return;
    }

    if addrs.v4.is_none() && addrs.v6.is_empty() {
        hop.subtitle = Some(interface.to_string());
        hop.fail(
            Fault::NoAddress,
            "No address on this interface — the link is up but unconfigured",
        );
        return;
    }

    // An address and a gateway that share no subnet cannot talk to each other,
    // however healthy each is on its own.
    //
    // Graded like the self-assigned case, and for the same reason: it is a
    // break only when there is no other way out. Left at `Warn` it lost the
    // verdict to the gateway's own collateral failure downstream, which says
    // "Your router isn't responding — reboot the router" at `Confidence::
    // Likely` while this hop already holds the certain, specific cause.
    // `first_break` looks only at `Fail`, and `Host` sorts before `Gateway`.
    if let Some(gw) = gateway
        && addrs.v4_contains(gw) == Some(false)
    {
        hop.metrics.push(
            Metric::new("Gateway", format!("{gw} (outside your subnet)")).with_status(Status::Warn),
        );
        let note = format!(
            "Your address and your gateway ({gw}) are on different subnets — they can't reach each other"
        );
        if addrs.v6.is_empty() {
            hop.fail(Fault::GatewayOffSubnet, note);
        } else {
            hop.status = Status::Warn;
            hop.fault = Some(Fault::GatewayOffSubnet);
            hop.summary = Some(format!("{note}, though IPv6 still has a path out"));
        }
        return;
    }

    hop.status = Status::Ok;
    hop.summary = Some(match (addrs.v4, addrs.v6.is_empty()) {
        (Some((ip, prefix)), false) => format!("{ip}/{prefix} · dual stack"),
        (Some((ip, prefix)), true) => format!("{ip}/{prefix} · IPv4 only"),
        (None, _) => "IPv6 only".to_string(),
    });
    if addrs.v4.is_none() {
        hop.subtitle = Some("IPv6 only".into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addrs(v4: Option<(&str, u8)>, v6: &[&str]) -> AddrInfo {
        AddrInfo {
            v4: v4.map(|(ip, p)| (ip.parse().unwrap(), p)),
            v6: v6.iter().map(|s| s.parse().unwrap()).collect(),
        }
    }

    fn graded(a: &AddrInfo, gateway: Option<&str>) -> Hop {
        let mut hop = Hop::new(HopId::Host, Layer::Link, "You");
        grade(&mut hop, "en0", a, gateway.map(|g| g.parse().unwrap()));
        hop
    }

    /// The outage class this hop was added for. DHCP never answered, so the
    /// machine autoconfigured — and because `Host` is the earliest hop in the
    /// chain, this now owns the verdict instead of the router downstream
    /// getting blamed for not answering a machine that can't address it.
    #[test]
    fn a_self_assigned_address_is_a_break_at_the_host() {
        let hop = graded(&addrs(Some(("169.254.13.7", 16)), &[]), None);
        assert_eq!(hop.status, Status::Fail);
        assert_eq!(hop.fault, Some(Fault::SelfAssignedAddr));
        assert!(hop.summary.unwrap().contains("DHCP"));
    }

    /// …but only when there is no other way out. DHCPv4 glitching while IPv6
    /// RA/SLAAC keeps working is a real and ordinary state, and failing the
    /// earliest hop in the chain would hand the whole verdict to a fault that
    /// isn't stopping anything.
    #[test]
    fn a_self_assigned_v4_with_working_v6_degrades_rather_than_breaks() {
        let hop = graded(&addrs(Some(("169.254.13.7", 16)), &["2001:db8::5"]), None);
        assert_eq!(hop.status, Status::Warn);
        assert_eq!(hop.fault, Some(Fault::SelfAssignedAddr));
        let summary = hop.summary.unwrap();
        assert!(summary.contains("IPv6 is configured"), "got: {summary}");
        assert!(summary.contains("IPv4-only will fail"), "got: {summary}");
    }

    #[test]
    fn a_normal_dhcp_lease_is_healthy_and_says_what_it_got() {
        let hop = graded(&addrs(Some(("192.168.0.15", 24)), &[]), Some("192.168.0.1"));
        assert_eq!(hop.status, Status::Ok);
        assert_eq!(hop.subtitle.as_deref(), Some("192.168.0.15/24"));
        assert!(hop.summary.unwrap().contains("IPv4 only"));
    }

    /// Both ends can be individually healthy and still unable to talk — and
    /// on IPv4 alone that is total unreachability, so it has to be a `Fail`.
    /// Left at `Warn` the verdict went to the gateway's collateral failure
    /// ("reboot the router") while this hop already held the certain cause.
    #[test]
    fn a_gateway_outside_the_subnet_is_a_break() {
        let hop = graded(&addrs(Some(("192.168.0.15", 24)), &[]), Some("10.0.0.1"));
        assert_eq!(hop.status, Status::Fail);
        assert_eq!(hop.fault, Some(Fault::GatewayOffSubnet));
        assert!(hop.summary.unwrap().contains("different subnets"));
    }

    /// With IPv6 configured there is still a path out, so it degrades rather
    /// than breaking — the same test the self-assigned branch applies.
    #[test]
    fn a_gateway_outside_the_subnet_only_warns_when_ipv6_works() {
        let hop = graded(
            &addrs(Some(("192.168.0.15", 24)), &["2001:db8::5"]),
            Some("10.0.0.1"),
        );
        assert_eq!(hop.status, Status::Warn);
        assert_eq!(hop.fault, Some(Fault::GatewayOffSubnet));
        assert!(hop.summary.unwrap().contains("IPv6 still has a path"));
    }

    #[test]
    fn a_gateway_inside_a_wider_subnet_is_fine() {
        // /16 puts 192.168.1.1 in range where /24 would not.
        let hop = graded(&addrs(Some(("192.168.0.15", 16)), &[]), Some("192.168.1.1"));
        assert_eq!(hop.status, Status::Ok);
    }

    #[test]
    fn an_unaddressed_interface_is_a_break() {
        let hop = graded(&addrs(None, &[]), None);
        assert_eq!(hop.status, Status::Fail);
        assert_eq!(hop.fault, Some(Fault::NoAddress));
    }

    #[test]
    fn an_ipv6_only_host_is_healthy() {
        let hop = graded(&addrs(None, &["2001:db8::5"]), None);
        assert_eq!(hop.status, Status::Ok);
        assert_eq!(hop.subtitle.as_deref(), Some("IPv6 only"));
    }

    /// Carrier-grade NAT explains a whole class of "my port forwarding does
    /// nothing" that no amount of router fiddling will fix.
    #[test]
    fn a_cgnat_lease_is_called_out() {
        let hop = graded(&addrs(Some(("100.80.4.9", 10)), &[]), None);
        assert!(
            hop.metrics
                .iter()
                .any(|m| m.label == "NAT" && m.value.contains("carrier-grade")),
            "got: {:?}",
            hop.metrics
        );
    }
}
