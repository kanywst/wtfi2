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
    Wan,
    Dns,
    Captive,
    Internet,
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
    /// One-line human summary shown in the detail panel.
    pub summary: Option<String>,
    /// Round-trip latency in milliseconds, when meaningful.
    pub latency_ms: Option<f64>,
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
            summary: None,
            latency_ms: None,
            metrics: Vec::new(),
        }
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
