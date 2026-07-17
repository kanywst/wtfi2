//! WAN / internet reachability probe.
//!
//! Uses real TCP handshakes to well-known anycast resolvers on :443 — this
//! exercises the actual forwarding path and needs no root, unlike raw ICMP.
//! Runs IPv4 and IPv6 concurrently to expose asymmetric blackholing.

use super::net::{tcp_connect, Probe};
use crate::model::{Hop, HopId, Layer, Metric, Status};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

const V4: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
const V6: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111));

pub async fn probe() -> Hop {
    let mut hop = Hop::new(HopId::Wan, Layer::Internet, "Internet");
    hop.subtitle = Some("1.1.1.1".into());

    let wait = Duration::from_secs(3);
    let (v4, v6) = tokio::join!(
        tcp_connect(SocketAddr::new(V4, 443), wait),
        tcp_connect(SocketAddr::new(V6, 443), wait),
    );

    // IPv4 is the critical path; IPv6 absence is common and only a soft note.
    push_family(&mut hop, "IPv4", v4, Status::Fail);
    push_family(&mut hop, "IPv6", v6, Status::Warn);

    match (v4.is_up(), v6.is_up()) {
        (true, true) => {
            hop.status = Status::Ok;
            hop.latency_ms = v4.ms();
            hop.summary = Some(format!(
                "Reachable over IPv4 + IPv6 ({:.0} ms)",
                v4.ms().unwrap_or(0.0)
            ));
        }
        (true, false) => {
            // IPv4-only is the common, healthy case on home LANs — don't cry
            // wolf. Note the missing IPv6 without downgrading reachability.
            hop.status = Status::Ok;
            hop.latency_ms = v4.ms();
            hop.summary = Some(format!(
                "Reachable over IPv4 ({:.0} ms) · no IPv6 on this network",
                v4.ms().unwrap_or(0.0)
            ));
        }
        (false, true) => {
            hop.status = Status::Warn;
            hop.latency_ms = v6.ms();
            hop.summary = Some("IPv6-only reachable — IPv4 path is blackholed".into());
        }
        (false, false) => {
            hop.status = Status::Fail;
            hop.summary =
                Some("No TCP path to the internet — the break is past your router".into());
        }
    }
    hop
}

fn push_family(hop: &mut Hop, label: &str, p: Probe, down: Status) {
    let (val, st) = match p {
        Probe::Up(d) => (format!("{:.0} ms", d.as_secs_f64() * 1000.0), Status::Ok),
        Probe::Timeout => ("unreachable".into(), down),
        Probe::Error => ("error".into(), Status::Warn),
    };
    hop.metrics.push(Metric::new(label, val).with_status(st));
}
