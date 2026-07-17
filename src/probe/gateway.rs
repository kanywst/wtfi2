//! L3 gateway probe: can we reach the default router?

use super::net::{ping, Probe};
use crate::model::{Hop, HopId, Layer, Metric, Status};
use crate::platform::RouteInfo;
use std::time::Duration;

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
    if route.tunnel_active {
        if let Some(t) = &route.tunnel_iface {
            hop.metrics
                .push(Metric::new("Tunnel", t.clone()).with_status(Status::Warn));
        }
    }

    let Some(gw) = route.gateway else {
        hop.status = Status::Fail;
        hop.summary = Some("No default gateway — you have no route off this machine".into());
        return hop;
    };

    match ping(gw, Duration::from_secs(2)).await {
        Probe::Up(d) => {
            let ms = d.as_secs_f64() * 1000.0;
            hop.latency_ms = Some(ms);
            hop.status = if ms > 50.0 { Status::Warn } else { Status::Ok };
            hop.summary = Some(format!("Router reachable in {ms:.0} ms"));
            hop.metrics
                .push(Metric::new("RTT", format!("{ms:.1} ms")).with_status(hop.status));
        }
        Probe::Timeout => {
            hop.status = Status::Fail;
            hop.summary =
                Some("Router isn't answering — LAN is up but the gateway is silent".into());
        }
        Probe::Error => {
            hop.status = Status::Warn;
            hop.summary = Some("Couldn't run ICMP probe to the gateway".into());
        }
    }
    hop
}
