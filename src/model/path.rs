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

    /// The first hop (closest to the host) that is broken, if any.
    /// This is "where the connection died".
    pub fn first_break(&self) -> Option<&Hop> {
        self.hops.iter().find(|h| h.status == Status::Fail)
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
}
