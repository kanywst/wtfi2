//! Scripted sweeps for recording the README demo (`--demo`, `demo` feature).
//!
//! A recording of a real sweep publishes the network it ran on: the public
//! address, the SSID, the ISP's hop addresses. This feeds the dashboard a
//! fixed sequence instead, built only from documentation addresses (RFC 5737
//! `192.0.2.0/24`) and public anycast resolvers, so the GIF can be re-recorded
//! anywhere without leaking anything. It never touches the network.
//!
//! Compiled only with `--features demo`, so released binaries don't carry it.

use crate::model::{Fault, Hop, HopId, Layer, Metric, Status};
use std::time::Duration;
use tokio::sync::mpsc;

/// Sweep `n`'s hops, each with the delay after the previous one. Sweeps 1 and
/// 2 of every four lose DNS, so a recording shows a healthy path, a break that
/// holds long enough to read, and the recovery.
pub fn sweep(n: usize) -> Vec<(Duration, Hop)> {
    // Deterministic wobble so the sparklines move without a real network.
    let jitter = [0.0, 1.4, 0.6, 2.1, 0.9][n % 5];
    let dns_down = matches!(n % 4, 1 | 2);
    let ms = Duration::from_millis;

    let mut host = Hop::new(HopId::Host, Layer::Link, "You");
    host.subtitle = Some("192.0.2.15/24".into());
    host.status = Status::Ok;
    host.summary = Some("192.0.2.15/24 · IPv4 only".into());

    let mut link = Hop::new(HopId::Link, Layer::Link, "Wi-Fi");
    let rssi = -50 - (n % 3) as i32;
    link.subtitle = Some("demo-wifi".into());
    link.status = Status::Ok;
    link.summary = Some(format!("Excellent · {rssi} dBm (SNR {} dB)", rssi + 88));
    link.metrics
        .push(Metric::new("RSSI", format!("{rssi} dBm")).with_status(Status::Ok));

    let mut gateway = Hop::new(HopId::Gateway, Layer::Network, "Gateway");
    let gw_ms = 3.6 + jitter;
    gateway.subtitle = Some("192.0.2.1".into());
    gateway.status = Status::Ok;
    gateway.latency_ms = Some(gw_ms);
    gateway.summary = Some(format!("Router reachable in {gw_ms:.0} ms"));
    gateway.evidence = Some("5 ICMP echoes to 192.0.2.1, 200ms apart".into());

    let mut wan = Hop::new(HopId::Wan, Layer::Internet, "Internet");
    let wan_ms = 7.2 + jitter * 2.0;
    wan.subtitle = Some("1.1.1.1 (Cloudflare)".into());
    wan.status = Status::Ok;
    wan.latency_ms = Some(wan_ms);
    wan.summary = Some(format!(
        "Reachable over IPv4 ({wan_ms:.0} ms via Cloudflare) · no IPv6 on this network"
    ));

    let mut dns = Hop::new(HopId::Dns, Layer::Application, "DNS");
    dns.subtitle = Some("192.0.2.1".into());
    let mut captive = Hop::new(HopId::Captive, Layer::Application, "Portal");
    captive.subtitle = Some("captive check".into());
    if dns_down {
        dns.fail(
            Fault::ResolverDead,
            "Your resolver gave no answer within 3s, but public DNS works — misconfigured or unreachable resolver",
        );
        dns.evidence = Some(
            "cloudflare.com. asked of 3 resolvers under a 3s deadline (2 answered), plus one nonexistent-name check"
                .into(),
        );
        captive.status = Status::Skipped;
        captive.summary =
            Some("No portal — nothing answered on port 80, and a portal would have".into());
    } else {
        let dns_ms = 10.0 + jitter;
        dns.status = Status::Ok;
        dns.latency_ms = Some(dns_ms);
        dns.summary = Some(format!("Resolving fast ({dns_ms:.0} ms)"));
        captive.status = Status::Ok;
        captive.summary = Some("No portal — traffic flows clean to the internet".into());
    }

    vec![
        (ms(80), host),
        (ms(220), link),
        (ms(600), gateway),
        (ms(500), wan),
        (ms(if dns_down { 900 } else { 300 }), dns),
        (ms(300), captive),
    ]
}

/// Stand-in for [`crate::engine::spawn`]: plays sweep `n` in real time.
pub fn spawn(n: usize) -> mpsc::UnboundedReceiver<Hop> {
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        for (delay, hop) in sweep(n) {
            tokio::time::sleep(delay).await;
            if tx.send(hop).is_err() {
                return;
            }
        }
    });
    rx
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diagnose::diagnose;
    use crate::engine::skeleton;

    fn verdict(n: usize) -> crate::diagnose::Verdict {
        let mut path = skeleton();
        for (_, hop) in sweep(n) {
            path.upsert(hop);
        }
        assert!(path.is_complete(), "sweep {n} must resolve every hop");
        diagnose(&path)
    }

    /// The demo is only worth recording if the real diagnosis engine reads it
    /// the way the README says: healthy, then a DNS-only break.
    #[test]
    fn sweeps_go_healthy_then_a_dns_break_then_recover() {
        assert_eq!(verdict(0).status, Status::Ok);
        for n in [1, 2] {
            let broken = verdict(n);
            assert_eq!(broken.status, Status::Fail);
            assert_eq!(broken.source, Some(HopId::Dns));
        }
        assert_eq!(verdict(3).status, Status::Ok);
    }

    /// Nothing a recording shows may identify a real network.
    #[test]
    fn only_documentation_and_public_resolver_addresses_appear() {
        for n in 0..4 {
            for (_, hop) in sweep(n) {
                let text = format!("{:?}", hop);
                for tok in text.split(|c: char| !(c.is_ascii_digit() || c == '.')) {
                    if let Ok(ip) = tok.parse::<std::net::Ipv4Addr>() {
                        let [a, b, c, _] = ip.octets();
                        assert!(
                            (a, b, c) == (192, 0, 2) || ip == std::net::Ipv4Addr::new(1, 1, 1, 1),
                            "sweep {n} leaks {ip}"
                        );
                    }
                }
            }
        }
    }
}
