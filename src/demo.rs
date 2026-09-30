//! Scripted sweeps for recording the README GIFs (`--demo`, `demo` feature).
//!
//! A recording of a real sweep publishes the network it ran on: the public
//! address, the SSID, the ISP's hop addresses. This feeds the dashboard and
//! the one-shot report fixed sequences instead, built only from documentation
//! addresses (RFC 5737: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`)
//! and the public anycast resolvers wtfi really probes, so the GIFs can be
//! re-recorded anywhere without leaking anything. It never touches the
//! network.
//!
//! Compiled only with `--features demo`, so released binaries don't carry it.

use crate::engine::skeleton;
use crate::model::{Fault, Hop, HopId, Layer, Metric, Path, Status};
use crate::probe::uplink::{self, TtlHop};
use std::time::Duration;
use tokio::sync::mpsc;

/// What a scripted run shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scenario {
    /// `wtfi -w`: healthy, a DNS-only outage for two sweeps, then recovery.
    Cycle,
    /// Every hop healthy.
    Healthy,
    /// DNS down, everything else fine.
    DnsDown,
    /// The trace gets into the ISP's network and dies there.
    IspDown,
}

impl Scenario {
    /// `--demo` with no value picks the scenario that suits the mode.
    pub fn parse(value: &str, watch: bool) -> Option<Self> {
        Some(match value {
            "" if watch => Scenario::Cycle,
            "" | "healthy" => Scenario::Healthy,
            "dns" => Scenario::DnsDown,
            "isp" => Scenario::IspDown,
            _ => return None,
        })
    }

    /// The hops of sweep `n`, each with the delay after the previous one.
    pub fn sweep(self, n: usize) -> Vec<(Duration, Hop)> {
        match self {
            Scenario::Cycle if matches!(n % 4, 1 | 2) => build(n, Break::Dns),
            Scenario::Cycle | Scenario::Healthy => build(n, Break::None),
            Scenario::DnsDown => build(n, Break::Dns),
            Scenario::IspDown => build(n, Break::Isp),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Break {
    None,
    Dns,
    Isp,
}

fn build(n: usize, brk: Break) -> Vec<(Duration, Hop)> {
    // Deterministic wobble so the sparklines move without a real network.
    let jitter = [0.0, 1.4, 0.6, 2.1, 0.9][n % 5];
    let ms = Duration::from_millis;

    let mut host = Hop::new(HopId::Host, Layer::Link, "You");
    host.subtitle = Some("192.0.2.15/24".into());
    host.status = Status::Ok;
    host.summary = Some("192.0.2.15/24 · IPv4 only".into());
    host.metrics.push(Metric::new("Interface", "en0"));
    host.metrics.push(Metric::new("IPv4", "192.0.2.15/24"));

    let mut link = Hop::new(HopId::Link, Layer::Link, "Wi-Fi");
    let rssi = -50 - (n % 3) as i32;
    link.subtitle = Some("demo-wifi".into());
    link.status = Status::Ok;
    link.summary = Some(format!("Excellent · {rssi} dBm (SNR {} dB)", rssi + 88));
    link.metrics
        .push(Metric::new("RSSI", format!("{rssi} dBm")).with_status(Status::Ok));
    link.metrics
        .push(Metric::new("Channel", "44 (5GHz) / 80MHz"));
    link.metrics.push(Metric::new("PHY", "802.11ax"));
    link.metrics.push(Metric::new("Tx Rate", "1201 Mbps"));

    let mut gateway = Hop::new(HopId::Gateway, Layer::Network, "Gateway");
    let gw_ms = 3.6 + jitter;
    gateway.subtitle = Some("192.0.2.1".into());
    gateway.status = Status::Ok;
    gateway.latency_ms = Some(gw_ms);
    gateway.loss_pct = Some(0.0);
    gateway.jitter_ms = Some(0.4);
    gateway.summary = Some(format!("Router reachable in {gw_ms:.0} ms"));
    gateway.evidence = Some("5 ICMP echoes to 192.0.2.1, 200ms apart".into());
    gateway
        .metrics
        .push(Metric::new("RTT", format!("{gw_ms:.1} ms avg")).with_status(Status::Ok));
    gateway
        .metrics
        .push(Metric::new("Loss", "0% (0/5 lost)").with_status(Status::Ok));
    gateway
        .metrics
        .push(Metric::new("Jitter", "±0.4 ms").with_status(Status::Ok));

    let mut wan = Hop::new(HopId::Wan, Layer::Internet, "Internet");
    let mut dns = Hop::new(HopId::Dns, Layer::Application, "DNS");
    dns.subtitle = Some("192.0.2.1".into());
    dns.metrics.push(Metric::new("Resolvers", "192.0.2.1"));
    let mut captive = Hop::new(HopId::Captive, Layer::Application, "Portal");
    captive.subtitle = Some("captive check".into());
    let skip_portal = |captive: &mut Hop| {
        captive.status = Status::Skipped;
        captive.summary =
            Some("No portal — nothing answered on port 80, and a portal would have".into());
    };

    if brk == Break::Isp {
        wan.subtitle = Some("5 targets".into());
        wan.fail(
            Fault::NoInternet,
            "No TCP path to the internet — 3 independent networks (Cloudflare, Google, Quad9) all refused across 5 addresses, so the break is past your router",
        );
        wan.evidence = Some(
            "5 handshakes to :443 across 3 independent networks, and one HTTPS request that did not complete"
                .into(),
        );
        for op in [
            "Cloudflare",
            "Google",
            "Quad9",
            "Cloudflare v6",
            "Google v6",
        ] {
            wan.metrics
                .push(Metric::new(op, "unreachable").with_status(Status::Fail));
        }
        dns.fail(Fault::ResolverDead, "Name resolution is failing everywhere");
        dns.evidence = Some(
            "cloudflare.com. asked of 3 resolvers under a 3s deadline (0 answered), plus one nonexistent-name check"
                .into(),
        );
        for r in ["System", "Cloudflare", "Google"] {
            dns.metrics
                .push(Metric::new(r, "failed").with_status(Status::Fail));
        }
        skip_portal(&mut captive);
        // Graded by the real Uplink reasoning: two hops answer, the second
        // inside the provider, then silence.
        let trace: Vec<TtlHop> = (1..=6)
            .map(|ttl| {
                let addr = match ttl {
                    1 => Some("192.0.2.1"),
                    2 => Some("203.0.113.1"),
                    _ => None,
                };
                TtlHop {
                    ttl,
                    addr: addr.map(|a| a.parse().expect("literal address")),
                    rtt_ms: addr.map(|_| 3.0 + f64::from(ttl) * 4.1),
                }
            })
            .collect();
        let up = uplink::from_sweep(&trace);
        return vec![
            (ms(80), host),
            (ms(220), link),
            (ms(600), gateway),
            (ms(1400), wan),
            (ms(200), dns),
            (ms(200), captive),
            (ms(900), up),
        ];
    }

    let wan_ms = 7.2 + jitter * 2.0;
    wan.subtitle = Some("1.1.1.1 (Cloudflare)".into());
    wan.status = Status::Ok;
    wan.latency_ms = Some(wan_ms);
    wan.summary = Some(format!(
        "Reachable over IPv4 ({wan_ms:.0} ms via Cloudflare) · no IPv6 on this network"
    ));
    wan.evidence = Some(
        "5 handshakes to :443 across 3 independent networks, and one HTTPS request that completed"
            .into(),
    );
    for (op, v) in [
        ("Cloudflare", format!("{wan_ms:.0} ms")),
        ("Google", format!("{:.0} ms", wan_ms + 1.0)),
        ("Quad9", format!("{:.0} ms", wan_ms + 2.0)),
        ("Cloudflare v6", "unreachable".into()),
        ("Google v6", "unreachable".into()),
    ] {
        wan.metrics.push(Metric::new(op, v));
    }
    wan.metrics.push(Metric::new("Public IP", "203.0.113.76"));

    if brk == Break::Dns {
        dns.fail(
            Fault::ResolverDead,
            "Your resolver gave no answer within 3s, but public DNS works — misconfigured or unreachable resolver",
        );
        dns.evidence = Some(
            "cloudflare.com. asked of 3 resolvers under a 3s deadline (2 answered), plus one nonexistent-name check"
                .into(),
        );
        dns.metrics
            .push(Metric::new("System", "failed").with_status(Status::Fail));
        dns.metrics
            .push(Metric::new("Cloudflare", "9 ms").with_status(Status::Ok));
        dns.metrics
            .push(Metric::new("Google", "13 ms").with_status(Status::Ok));
        skip_portal(&mut captive);
    } else {
        let dns_ms = 10.0 + jitter;
        dns.status = Status::Ok;
        dns.latency_ms = Some(dns_ms);
        dns.summary = Some(format!("Resolving fast ({dns_ms:.0} ms)"));
        dns.evidence = Some(
            "cloudflare.com. asked of 3 resolvers under a 3s deadline (3 answered), plus one nonexistent-name check"
                .into(),
        );
        dns.metrics
            .push(Metric::new("System", format!("{dns_ms:.0} ms")).with_status(Status::Ok));
        dns.metrics
            .push(Metric::new("Cloudflare", "9 ms").with_status(Status::Ok));
        dns.metrics
            .push(Metric::new("Google", "13 ms").with_status(Status::Ok));
        captive.status = Status::Ok;
        captive.summary = Some("No portal — traffic flows clean to the internet".into());
    }

    vec![
        (ms(80), host),
        (ms(220), link),
        (ms(600), gateway),
        (ms(500), wan),
        (ms(if brk == Break::Dns { 900 } else { 300 }), dns),
        (ms(300), captive),
    ]
}

/// Stand-in for [`crate::engine::spawn`]: plays sweep `n` in real time.
pub fn spawn(scenario: Scenario, n: usize) -> mpsc::UnboundedReceiver<Hop> {
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        for (delay, hop) in scenario.sweep(n) {
            tokio::time::sleep(delay).await;
            if tx.send(hop).is_err() {
                return;
            }
        }
    });
    rx
}

/// Stand-in for [`crate::engine::run_once_within`]: the one-shot report's
/// path, arriving at the pace a real sweep would.
pub async fn run_once(scenario: Scenario) -> Path {
    let mut path = skeleton();
    for (delay, hop) in scenario.sweep(0) {
        tokio::time::sleep(delay).await;
        path.upsert(hop);
    }
    path
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diagnose::{Verdict, diagnose};

    fn verdict(scenario: Scenario, n: usize) -> Verdict {
        let mut path = skeleton();
        for (_, hop) in scenario.sweep(n) {
            path.upsert(hop);
        }
        assert!(
            path.is_complete(),
            "{scenario:?} sweep {n} must resolve every hop"
        );
        diagnose(&path)
    }

    /// The demo is only worth recording if the real diagnosis engine reads it
    /// the way the README says: healthy, then a DNS-only break, then recovery.
    #[test]
    fn the_dashboard_cycle_goes_healthy_then_a_dns_break_then_recovers() {
        assert_eq!(verdict(Scenario::Cycle, 0).status, Status::Ok);
        for n in [1, 2] {
            let broken = verdict(Scenario::Cycle, n);
            assert_eq!(broken.status, Status::Fail);
            assert_eq!(broken.source, Some(HopId::Dns));
        }
        assert_eq!(verdict(Scenario::Cycle, 3).status, Status::Ok);
    }

    #[test]
    fn the_isp_scenario_is_blamed_on_the_isp_by_the_real_engine() {
        let v = verdict(Scenario::IspDown, 0);
        assert_eq!(v.status, Status::Fail);
        assert_eq!(v.source, Some(HopId::Uplink));
        assert!(
            v.cause.contains("203.0.113.1"),
            "the verdict should quote the last hop that answered: {}",
            v.cause
        );
    }

    #[test]
    fn scenario_names_parse_and_default_by_mode() {
        assert_eq!(Scenario::parse("", true), Some(Scenario::Cycle));
        assert_eq!(Scenario::parse("", false), Some(Scenario::Healthy));
        assert_eq!(Scenario::parse("isp", false), Some(Scenario::IspDown));
        assert_eq!(Scenario::parse("nope", false), None);
    }

    /// Nothing a recording shows may identify a real network.
    #[test]
    fn only_documentation_and_probed_resolver_addresses_appear() {
        let allowed = |ip: std::net::Ipv4Addr| {
            let [a, b, c, _] = ip.octets();
            matches!((a, b, c), (192, 0, 2) | (198, 51, 100) | (203, 0, 113))
                || ip == std::net::Ipv4Addr::new(1, 1, 1, 1)
        };
        for scenario in [Scenario::Cycle, Scenario::IspDown] {
            for n in 0..4 {
                for (_, hop) in scenario.sweep(n) {
                    let text = format!("{hop:?}");
                    for tok in text.split(|c: char| !(c.is_ascii_digit() || c == '.')) {
                        if let Ok(ip) = tok.parse::<std::net::Ipv4Addr>() {
                            assert!(allowed(ip), "{scenario:?} sweep {n} leaks {ip}");
                        }
                    }
                }
            }
        }
    }
}
