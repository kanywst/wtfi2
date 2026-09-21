//! The connectivity path: an ordered chain of hops from the host to the
//! internet. This is the model the topology diagram renders.

use super::Status;

/// OSI-ish layer a hop lives at, used for grouping and coloring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layer {
    /// L2 — Wi-Fi / physical link.
    Link,
    /// L3 — local routing, gateway, VPN.
    Network,
    /// L3/L4 — WAN / internet reachability.
    Internet,
    /// L7 — DNS, captive portal, application.
    Application,
}

impl Layer {
    pub fn label(self) -> &'static str {
        match self {
            Layer::Link => "L2 Link",
            Layer::Network => "L3 Network",
            Layer::Internet => "WAN",
            Layer::Application => "L7 App",
        }
    }
}

/// Stable identity of a hop, so probes can update the right node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HopId {
    Host,
    Link,
    Gateway,
    /// Overlay VPN / tunnel hop — only present when a tunnel is active. Sits
    /// between the local gateway and the WAN because traffic is encapsulated
    /// here before it egresses to the internet.
    Vpn,
    /// The path between the local gateway and the internet — your modem, your
    /// ISP's access network, transit. Only present when something upstream is
    /// already broken, because that is the only time it is worth the seconds
    /// it costs to sweep.
    Uplink,
    Wan,
    Dns,
    Captive,
}

/// Why a hop is not healthy, as a code rather than as prose.
///
/// Probes record *what they observed*; the diagnosis engine turns that into a
/// human verdict. Without a code the two ends drift, because the engine has to
/// re-derive a cause the probe already knew — and then the verdict can
/// contradict the evidence printed right under it. That is exactly how a
/// missing default route came out as "your machine isn't associated with an
/// access point", which is a different fault with a different fix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    /// The OS tools wtfi reads the network through could not be run, so
    /// nothing about the network was observed. Emphatically not the same as
    /// observing that the network is down.
    Unobserved,
    /// Not associated with any access point at all.
    NotAssociated,
    /// DHCP never answered, so IPv4 autoconfiguration took over
    /// (`169.254.0.0/16`). The interface looks configured and reaches nothing.
    SelfAssignedAddr,
    /// The interface has no address at all.
    NoAddress,
    /// The configured address and the default gateway share no subnet, so
    /// they cannot reach each other however healthy each one is.
    GatewayOffSubnet,
    /// Associated, but there is no default route off this machine — typically
    /// a DHCP lease that never arrived.
    NoRoute,
    /// No default gateway in the routing table.
    NoGateway,
    /// The gateway is in the routing table but answers nothing.
    GatewaySilent,
    /// The trace stops immediately past your own router: the break is on the
    /// link between it and your provider — modem/ONU, WAN cable, or the line.
    UplinkDiesAtModem,
    /// The trace gets into the provider's network and stops there.
    UplinkDiesInIsp,
    /// No transport-layer path to the internet.
    NoInternet,
    /// The internet is reachable, but this network filters specific
    /// destinations. A property of the network you are on, not an outage.
    TargetBlocked,
    /// Every TCP handshake completes, but no real request does — something on
    /// the path answers connections without carrying them.
    HandshakeOnly,
    /// The system resolver returned no answer.
    ResolverDead,
    /// The system resolver answers, but not truthfully — it synthesises
    /// results for names that don't exist, or substitutes its own address for
    /// a public one.
    ResolverHijacked,
    /// A captive portal is intercepting traffic.
    PortalIntercept,
    /// A tunnel interface is up but is not carrying traffic.
    TunnelDown,
}

impl Fault {
    /// Stable lowercase code for `--json` consumers.
    pub fn code(self) -> &'static str {
        match self {
            Fault::Unobserved => "unobserved",
            Fault::NotAssociated => "not_associated",
            Fault::SelfAssignedAddr => "self_assigned_addr",
            Fault::NoAddress => "no_address",
            Fault::GatewayOffSubnet => "gateway_off_subnet",
            Fault::NoRoute => "no_route",
            Fault::NoGateway => "no_gateway",
            Fault::GatewaySilent => "gateway_silent",
            Fault::UplinkDiesAtModem => "uplink_dies_at_modem",
            Fault::UplinkDiesInIsp => "uplink_dies_in_isp",
            Fault::NoInternet => "no_internet",
            Fault::TargetBlocked => "target_blocked",
            Fault::HandshakeOnly => "handshake_only",
            Fault::ResolverDead => "resolver_dead",
            Fault::ResolverHijacked => "resolver_hijacked",
            Fault::PortalIntercept => "portal_intercept",
            Fault::TunnelDown => "tunnel_down",
        }
    }
}

/// A named key/value measurement attached to a hop.
#[derive(Debug, Clone)]
pub struct Metric {
    pub label: String,
    pub value: String,
    /// Optional per-metric status, e.g. IPv6 down while IPv4 is up.
    pub status: Option<Status>,
}

impl Metric {
    pub fn new(label: impl Into<String>, value: impl Into<String>) -> Self {
        Metric {
            label: label.into(),
            value: value.into(),
            status: None,
        }
    }

    pub fn with_status(mut self, s: Status) -> Self {
        self.status = Some(s);
        self
    }
}

/// One node in the connectivity chain.
#[derive(Debug, Clone)]
pub struct Hop {
    pub id: HopId,
    pub layer: Layer,
    /// Short node label for the diagram, e.g. `Gateway`.
    pub title: String,
    /// Address / identity subtitle, e.g. `192.168.0.1`.
    pub subtitle: Option<String>,
    pub status: Status,
    /// What went wrong, as a code the diagnosis engine can match on. `None`
    /// when the hop is healthy, or when it is degraded in a way the hop's own
    /// [`Hop::summary`] already describes well enough.
    pub fault: Option<Fault>,
    /// One-line human summary shown in the detail panel.
    pub summary: Option<String>,
    /// What this hop actually did to reach its conclusion — how many probes,
    /// to where, over how long.
    ///
    /// A verdict without this is an assertion: the reader has to take "your
    /// ISP is down" on trust, with no way to tell a thorough measurement from
    /// a single timed-out packet. Stating the method is what turns it into a
    /// diagnosis they can check, argue with, or quote to someone else.
    pub evidence: Option<String>,
    /// Round-trip latency in milliseconds, when meaningful.
    pub latency_ms: Option<f64>,
    /// Share of probe samples that never came back, when the hop was measured
    /// with a burst. A reachable hop can still be losing a quarter of its
    /// packets, which is what "everything is green but nothing loads" means.
    pub loss_pct: Option<f64>,
    /// Variation between successive round trips, in milliseconds.
    pub jitter_ms: Option<f64>,
    pub metrics: Vec<Metric>,
}

impl Hop {
    pub fn new(id: HopId, layer: Layer, title: impl Into<String>) -> Self {
        Hop {
            id,
            layer,
            title: title.into(),
            subtitle: None,
            status: Status::Pending,
            fault: None,
            summary: None,
            evidence: None,
            latency_ms: None,
            loss_pct: None,
            jitter_ms: None,
            metrics: Vec::new(),
        }
    }

    /// Mark the hop broken, with the reason recorded both as a code the
    /// diagnosis engine matches on and as the prose the human reads. Going
    /// through one call keeps the two from drifting apart.
    pub fn fail(&mut self, fault: Fault, summary: impl Into<String>) {
        self.status = Status::Fail;
        self.fault = Some(fault);
        self.summary = Some(summary.into());
    }
}

/// The ordered connectivity chain plus a computed verdict.
#[derive(Debug, Clone, Default)]
pub struct Path {
    pub hops: Vec<Hop>,
}

impl Path {
    pub fn get(&self, id: HopId) -> Option<&Hop> {
        self.hops.iter().find(|h| h.id == id)
    }

    pub fn get_mut(&mut self, id: HopId) -> Option<&mut Hop> {
        self.hops.iter_mut().find(|h| h.id == id)
    }

    /// Replace the hop with the same id, or insert it in chain order.
    ///
    /// Conditional hops (e.g. the VPN tunnel) aren't in the seed skeleton, so
    /// they land here for the first time and must slot into the right place —
    /// ordered by [`HopId`] position — rather than being dropped or appended.
    pub fn upsert(&mut self, hop: Hop) {
        if let Some(slot) = self.get_mut(hop.id) {
            *slot = hop;
            return;
        }
        let pos = self
            .hops
            .iter()
            .position(|h| (h.id as usize) > (hop.id as usize))
            .unwrap_or(self.hops.len());
        self.hops.insert(pos, hop);
    }

    /// The first hop (closest to the host) that is broken, if any.
    /// This is "where the connection died".
    ///
    /// Ordered by [`HopId`] position in the chain rather than vec order, so the
    /// result is stable even if probes ever land out of order — matching how
    /// the diagnosis engine selects the worst warning.
    pub fn first_break(&self) -> Option<&Hop> {
        self.hops
            .iter()
            .filter(|h| h.status == Status::Fail)
            .min_by_key(|h| h.id as usize)
    }

    /// True once every hop has a terminal status.
    pub fn is_complete(&self) -> bool {
        self.hops.iter().all(|h| h.status.is_terminal())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_break_returns_earliest_fail() {
        let mut p = Path::default();
        let mut g = Hop::new(HopId::Gateway, Layer::Network, "Gateway");
        g.status = Status::Ok;
        let mut d = Hop::new(HopId::Dns, Layer::Application, "DNS");
        d.status = Status::Fail;
        let mut w = Hop::new(HopId::Wan, Layer::Internet, "WAN");
        w.status = Status::Fail;
        p.hops = vec![g, w, d];
        // WAN comes before DNS in the vec, so it is the first break.
        assert_eq!(p.first_break().unwrap().id, HopId::Wan);
    }

    #[test]
    fn first_break_uses_chain_order_not_vec_order() {
        // Fails inserted out of chain order: Dns before Gateway in the vec.
        let mut d = Hop::new(HopId::Dns, Layer::Application, "DNS");
        d.status = Status::Fail;
        let mut g = Hop::new(HopId::Gateway, Layer::Network, "Gateway");
        g.status = Status::Fail;
        let p = Path { hops: vec![d, g] };
        // Gateway is earlier in the chain, so it wins regardless of vec order.
        assert_eq!(p.first_break().unwrap().id, HopId::Gateway);
    }

    #[test]
    fn upsert_inserts_conditional_hop_in_chain_order() {
        let mut p = Path {
            hops: vec![
                Hop::new(HopId::Gateway, Layer::Network, "Gateway"),
                Hop::new(HopId::Wan, Layer::Internet, "Internet"),
            ],
        };
        // A VPN hop isn't in the seed; it must land between Gateway and Wan.
        p.upsert(Hop::new(HopId::Vpn, Layer::Network, "VPN"));
        let ids: Vec<_> = p.hops.iter().map(|h| h.id).collect();
        assert_eq!(ids, vec![HopId::Gateway, HopId::Vpn, HopId::Wan]);
    }

    #[test]
    fn upsert_replaces_existing_hop_in_place() {
        let mut p = Path {
            hops: vec![Hop::new(HopId::Vpn, Layer::Network, "VPN")],
        };
        let mut updated = Hop::new(HopId::Vpn, Layer::Network, "VPN");
        updated.status = Status::Ok;
        p.upsert(updated);
        assert_eq!(p.hops.len(), 1);
        assert_eq!(p.hops[0].status, Status::Ok);
    }

    /// `fail` is the only way a probe should break a hop, so the code and the
    /// prose can never be set independently and drift apart.
    #[test]
    fn fail_records_the_code_alongside_the_prose() {
        let mut h = Hop::new(HopId::Gateway, Layer::Network, "Gateway");
        h.fail(Fault::GatewaySilent, "Router isn't answering");
        assert_eq!(h.status, Status::Fail);
        assert_eq!(h.fault, Some(Fault::GatewaySilent));
        assert_eq!(h.summary.as_deref(), Some("Router isn't answering"));
    }

    #[test]
    fn fault_codes_are_stable_and_distinct() {
        // `--json` consumers branch on these strings.
        let all = [
            Fault::Unobserved,
            Fault::NotAssociated,
            Fault::SelfAssignedAddr,
            Fault::NoAddress,
            Fault::GatewayOffSubnet,
            Fault::NoRoute,
            Fault::NoGateway,
            Fault::GatewaySilent,
            Fault::UplinkDiesAtModem,
            Fault::UplinkDiesInIsp,
            Fault::NoInternet,
            Fault::TargetBlocked,
            Fault::HandshakeOnly,
            Fault::ResolverDead,
            Fault::ResolverHijacked,
            Fault::PortalIntercept,
            Fault::TunnelDown,
        ];
        let mut codes: Vec<_> = all.iter().map(|f| f.code()).collect();
        codes.sort_unstable();
        let len = codes.len();
        codes.dedup();
        assert_eq!(codes.len(), len, "fault codes must be distinct");
    }

    #[test]
    fn skipped_hops_count_as_complete() {
        // A real outage skips downstream hops; the path must still be
        // "complete" so the dashboard renders a verdict instead of spinning.
        let mut link = Hop::new(HopId::Link, Layer::Link, "Wi-Fi");
        link.status = Status::Fail;
        let mut gw = Hop::new(HopId::Gateway, Layer::Network, "Gateway");
        gw.status = Status::Skipped;
        let p = Path {
            hops: vec![link, gw],
        };
        assert!(p.is_complete());
    }
}
