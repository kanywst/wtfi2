//! WAN / internet reachability probe.
//!
//! Uses real TCP handshakes to well-known anycast resolvers on :443 — this
//! exercises the actual forwarding path and needs no root, unlike raw ICMP.
//! Runs IPv4 and IPv6 concurrently to expose asymmetric blackholing, then, once
//! IPv4 is known to work, repeats the handshake a few times to tell a healthy
//! uplink from one that is technically up but dropping traffic.
//!
//! Each family is tried against *several operators*, not one. A single target
//! cannot tell "the internet is unreachable" from "this network blocks that
//! address" — and the difference is the whole verdict. Corporate egress
//! policy, national filtering and a flapping anycast route all make one
//! provider vanish while the internet is fine; reporting that as "your ISP is
//! down", confidently, is a lie the reader has no way to catch.

use super::net::{Probe, Quality, apply_quality, tcp_connect};
use crate::model::{Fault, Hop, HopId, Layer, Metric, Status};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

/// A reachability target, named so the report can say which operator went
/// quiet rather than quoting a bare address.
struct Target {
    label: &'static str,
    addr: IpAddr,
}

/// Three operators on three different networks. Independence is the point: if
/// they disagree, the disagreement itself is the finding.
const V4: [Target; 3] = [
    Target {
        label: "Cloudflare",
        addr: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
    },
    Target {
        label: "Google",
        addr: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
    },
    Target {
        label: "Quad9",
        addr: IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
    },
];

const V6: [Target; 2] = [
    Target {
        label: "Cloudflare v6",
        addr: IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)),
    },
    Target {
        label: "Google v6",
        addr: IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888)),
    },
];

const PORT: u16 = 443;

/// Handshakes per sweep, counting the reachability probe itself.
const SAMPLES: u32 = 5;
/// Spacing, so the samples cover a slice of time rather than one instant.
const SPACING: Duration = Duration::from_millis(100);
/// Ceiling for *every* handshake, reachability probe included.
///
/// It has to be one number: if the follow-up samples were held to a tighter
/// deadline than the probe that declared the path up, a merely slow uplink
/// would be reported as a lossy one — "80% of connections never complete" for
/// a link where every connection completes, just not quickly.
const SAMPLE_WAIT: Duration = Duration::from_secs(3);
/// Wall-clock ceiling on the follow-up sampling, so a path that dies right
/// after the first success can't stretch the sweep past the dashboard's tick.
///
/// It is a real ceiling because no sample is *started* unless its own worst
/// case still fits inside it — checking only the start time would let a single
/// timed-out handshake overshoot by most of [`SAMPLE_WAIT`]. The cost is that
/// a dying path yields a short burst, which is reported as what it is: a loss
/// figure over the handshakes actually attempted.
const SAMPLE_BUDGET: Duration = Duration::from_millis(3600);

const _: () = assert!(
    SAMPLE_BUDGET.as_millis() >= SPACING.as_millis() + SAMPLE_WAIT.as_millis(),
    "the budget must admit at least one full-length follow-up sample"
);

/// The public internet is allowed to wobble more than your own LAN. Sized so a
/// single latency spike can't trip it: mean IPDV over `n` samples turns one
/// spike of `S` into roughly `2S/(n-1)`, i.e. `S/2` at five samples.
const JITTER_WARN_MS: f64 = 120.0;

/// One family's results: which targets answered, and how fast.
struct Family {
    reached: Vec<(&'static str, Probe)>,
}

impl Family {
    fn up(&self) -> impl Iterator<Item = (&'static str, Probe)> + '_ {
        self.reached.iter().filter(|(_, p)| p.is_up()).copied()
    }
    fn down(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.reached
            .iter()
            .filter(|(_, p)| !p.is_up())
            .map(|(l, _)| *l)
    }
    fn any_up(&self) -> bool {
        self.reached.iter().any(|(_, p)| p.is_up())
    }
    /// The quickest target that answered — the one worth sampling further,
    /// since a slow target would spend the budget without measuring the path.
    fn best(&self) -> Option<(&'static str, IpAddr, Probe)> {
        let (label, probe) = self.up().min_by(|a, b| {
            a.1.ms()
                .unwrap_or(f64::MAX)
                .total_cmp(&b.1.ms().unwrap_or(f64::MAX))
        })?;
        let addr = addr_of(label)?;
        Some((label, addr, probe))
    }
}

fn addr_of(label: &str) -> Option<IpAddr> {
    V4.iter()
        .chain(V6.iter())
        .find(|t| t.label == label)
        .map(|t| t.addr)
}

pub async fn probe() -> Hop {
    let mut hop = Hop::new(HopId::Wan, Layer::Internet, "Internet");

    let (v4, v6) = tokio::join!(reach(&V4), reach(&V6));

    hop.subtitle = Some(match v4.best() {
        Some((label, addr, _)) => format!("{addr} ({label})"),
        None => format!("{} targets", V4.len() + V6.len()),
    });

    for (label, probe) in v4.reached.iter().chain(v6.reached.iter()) {
        let (value, status) = match probe {
            Probe::Up(d) => (format!("{:.0} ms", d.as_secs_f64() * 1000.0), Status::Ok),
            Probe::Timeout => ("unreachable".into(), Status::Warn),
        };
        hop.metrics
            .push(Metric::new(*label, value).with_status(status));
    }

    match (v4.any_up(), v6.any_up()) {
        (true, dual_stack) => {
            // Reachability is settled; the open questions are quality and
            // whether any *individual* operator is being filtered.
            let (label, addr, first) = v4.best().expect("any_up means a target answered");
            let q = sample_quality(addr, first).await;
            let avg = q.avg_ms().unwrap_or_default();
            hop.latency_ms = Some(avg);
            let quality = apply_quality(&mut hop, &q, JITTER_WARN_MS);
            let blocked = blocked_targets(&v4, &v6);
            hop.status = quality.max(block_status(&blocked));
            if !blocked.is_empty() {
                hop.fault = Some(Fault::TargetBlocked);
            }
            hop.summary = Some(summarise(label, avg, dual_stack, &q, &blocked));
        }
        (false, true) => {
            hop.status = Status::Warn;
            hop.latency_ms = v6.best().and_then(|(_, _, p)| p.ms());
            hop.summary = Some(format!(
                "IPv6-only reachable — all {} IPv4 targets are blackholed",
                V4.len()
            ));
        }
        (false, false) => {
            // Every operator, on every family, independently silent. That is
            // as strong as this probe can make the claim, and it is what makes
            // "the break is past your router" worth saying out loud.
            hop.fail(
                Fault::NoInternet,
                format!(
                    "No TCP path to the internet — {} independent targets ({}) all refused, so the break is past your router",
                    V4.len() + V6.len(),
                    operators()
                ),
            );
        }
    }
    hop
}

/// Which targets look filtered rather than simply absent.
///
/// A family that is down *entirely* is not filtering — it is a family this
/// network doesn't carry. Having no IPv6 at all is the ordinary case on a home
/// LAN, and flagging it as blocked egress would put a warning on most healthy
/// networks; the "no IPv6 on this network" note already covers it. Only a
/// *partial* failure, where some operators answer and others don't, is
/// evidence that something is picking destinations.
fn blocked_targets<'a>(v4: &'a Family, v6: &'a Family) -> Vec<&'a str> {
    let mut blocked: Vec<&str> = v4.down().collect();
    if v6.any_up() {
        blocked.extend(v6.down());
    }
    blocked
}

/// A blocked target on an otherwise-working uplink is a warning, never a
/// break: the internet is demonstrably reachable, you just can't reach *that*.
fn block_status(blocked: &[&str]) -> Status {
    if blocked.is_empty() {
        Status::Ok
    } else {
        Status::Warn
    }
}

/// The distinct operators behind the targets, for the outage message. The
/// point of the message is *how many independent networks* stayed silent, so
/// listing the same operator twice for its two address families would inflate
/// exactly the number that makes the claim credible.
fn operators() -> String {
    let mut names: Vec<&str> = Vec::new();
    for t in V4.iter().chain(V6.iter()) {
        let name = t.label.trim_end_matches(" v6");
        if !names.contains(&name) {
            names.push(name);
        }
    }
    names.join(", ")
}

fn summarise(label: &str, avg: f64, dual_stack: bool, q: &Quality, blocked: &[&str]) -> String {
    let family = if dual_stack { "IPv4 + IPv6" } else { "IPv4" };
    if let Some(c) = q.complaint(JITTER_WARN_MS) {
        return format!(
            "Reachable over {family} but the uplink is unhealthy — {c} over {} handshakes",
            q.sent
        );
    }
    if !blocked.is_empty() {
        // The uplink works, so this is about *this network's* filtering, not
        // about your connection being down. Saying which operator is missing
        // is the whole point of probing more than one.
        return format!(
            "Reachable via {label} ({avg:.0} ms), but this network blocks {} — filtered egress, not an outage",
            blocked.join(" and ")
        );
    }
    if dual_stack {
        format!("Reachable over IPv4 + IPv6 ({avg:.0} ms via {label})")
    } else {
        format!("Reachable over IPv4 ({avg:.0} ms via {label}) · no IPv6 on this network")
    }
}

/// Handshake every target in a family at once.
async fn reach(targets: &[Target]) -> Family {
    let reached = futures::future::join_all(targets.iter().map(|t| async move {
        (
            t.label,
            tcp_connect(SocketAddr::new(t.addr, PORT), SAMPLE_WAIT).await,
        )
    }))
    .await;
    Family { reached }
}

/// Follow the successful reachability handshake with more of the same, spaced
/// out, so loss and jitter are measured over a slice of time rather than one
/// instant. Reuses the first handshake as sample one — it already happened,
/// and it was taken under the same deadline as the rest.
///
/// Stops early once [`SAMPLE_BUDGET`] can no longer fit a whole sample. A path
/// that dies right after that first success would otherwise cost every
/// remaining sample its full timeout, and a short honest burst beats a long one
/// that overruns the sweep.
async fn sample_quality(addr: IpAddr, first: Probe) -> Quality {
    let deadline = Instant::now() + SAMPLE_BUDGET;
    let mut samples = Vec::with_capacity(SAMPLES as usize);
    samples.push(first);
    // The worst case of the *whole* iteration has to fit, not just its start:
    // a handshake that times out takes SAMPLE_WAIT no matter how much budget
    // is left when it begins.
    while (samples.len() as u32) < SAMPLES && Instant::now() + SPACING + SAMPLE_WAIT <= deadline {
        tokio::time::sleep(SPACING).await;
        samples.push(tcp_connect(SocketAddr::new(addr, PORT), SAMPLE_WAIT).await);
    }
    Quality::from_samples(&samples)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn family(entries: &[(&'static str, Option<u64>)]) -> Family {
        Family {
            reached: entries
                .iter()
                .map(|(label, ms)| {
                    (
                        *label,
                        match ms {
                            Some(ms) => Probe::Up(Duration::from_millis(*ms)),
                            None => Probe::Timeout,
                        },
                    )
                })
                .collect(),
        }
    }

    /// The claim this probe exists to earn. One target cannot distinguish "the
    /// internet is gone" from "this network blocks Cloudflare", and the old
    /// probe asserted the former, with `Confidence::Likely`, on the strength
    /// of a single address.
    #[test]
    fn independent_targets_are_what_makes_the_outage_claim_honest() {
        assert!(
            V4.len() >= 3,
            "a single operator cannot distinguish an outage from a block"
        );
        let networks: std::collections::HashSet<_> = V4
            .iter()
            .map(|t| t.label)
            .chain(V6.iter().map(|t| t.label))
            .collect();
        assert_eq!(
            networks.len(),
            V4.len() + V6.len(),
            "targets must be distinct operators, not one operator twice"
        );
    }

    #[test]
    fn the_fastest_reachable_target_is_the_one_sampled() {
        // Sampling a slow target would spend the budget without measuring the
        // path the rest of your traffic actually takes.
        let f = family(&[
            ("Cloudflare", Some(90)),
            ("Google", Some(12)),
            ("Quad9", None),
        ]);
        let (label, _, _) = f.best().unwrap();
        assert_eq!(label, "Google");
    }

    #[test]
    fn a_blocked_target_on_a_working_uplink_warns_and_names_it() {
        let q = Quality {
            sent: 5,
            rtts_ms: vec![10.0, 11.0, 10.5, 11.2, 10.8],
        };
        let summary = summarise("Google", 10.7, false, &q, &["Cloudflare"]);
        assert!(summary.contains("blocks Cloudflare"), "got: {summary}");
        assert!(
            summary.contains("not an outage"),
            "the uplink demonstrably works: {summary}"
        );
        assert_eq!(block_status(&["Cloudflare"]), Status::Warn);
        assert_eq!(block_status(&[]), Status::Ok);
    }

    #[test]
    fn a_clean_uplink_says_which_target_it_measured() {
        let q = Quality {
            sent: 5,
            rtts_ms: vec![10.0, 11.0, 10.5, 11.2, 10.8],
        };
        let summary = summarise("Quad9", 10.7, true, &q, &[]);
        assert!(summary.contains("Quad9"), "got: {summary}");
        assert!(summary.contains("IPv4 + IPv6"));
    }

    /// Quality trumps a block in the summary: a lossy uplink is the more
    /// urgent thing to say, and it is about the connection rather than about
    /// one operator being filtered.
    #[test]
    fn an_unhealthy_uplink_owns_the_summary_over_a_block() {
        let lossy = Quality {
            sent: 5,
            rtts_ms: vec![10.0],
        };
        let summary = summarise("Google", 10.0, false, &lossy, &["Cloudflare"]);
        assert!(summary.contains("unhealthy"), "got: {summary}");
    }

    #[test]
    fn family_reports_which_targets_went_quiet() {
        let f = family(&[("Cloudflare", None), ("Google", Some(12)), ("Quad9", None)]);
        assert!(f.any_up());
        let down: Vec<_> = f.down().collect();
        assert_eq!(down, vec!["Cloudflare", "Quad9"]);
    }

    #[test]
    fn a_family_with_nothing_up_reports_nothing_up() {
        let f = family(&[("Cloudflare", None), ("Google", None)]);
        assert!(!f.any_up());
        assert!(f.best().is_none());
    }

    /// The outage message's whole weight is "N independent networks went
    /// quiet", so counting one operator twice for its two address families
    /// would inflate the number that makes the claim credible.
    #[test]
    fn operators_are_listed_once_each_without_family_suffixes() {
        let names = operators();
        assert!(!names.contains("v6"), "got: {names}");
        let listed: Vec<&str> = names.split(", ").collect();
        let mut unique = listed.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), listed.len(), "duplicated operator in {names}");
        assert_eq!(listed, vec!["Cloudflare", "Google", "Quad9"]);
    }

    /// Having no IPv6 at all is the ordinary case on a home LAN. Counting it
    /// as filtered egress would put a warning on most healthy networks — and
    /// the summary already says "no IPv6 on this network".
    #[test]
    fn an_absent_ipv6_family_is_not_reported_as_filtering() {
        let v4 = family(&[
            ("Cloudflare", Some(12)),
            ("Google", Some(14)),
            ("Quad9", Some(13)),
        ]);
        let v6 = family(&[("Cloudflare v6", None), ("Google v6", None)]);
        assert!(blocked_targets(&v4, &v6).is_empty());
        assert_eq!(block_status(&blocked_targets(&v4, &v6)), Status::Ok);
    }

    /// A *partial* v6 failure is different: the family works, so one operator
    /// missing from it is evidence something is picking destinations.
    #[test]
    fn a_partial_ipv6_failure_is_reported_as_filtering() {
        let v4 = family(&[
            ("Cloudflare", Some(12)),
            ("Google", Some(14)),
            ("Quad9", Some(13)),
        ]);
        let v6 = family(&[("Cloudflare v6", Some(15)), ("Google v6", None)]);
        assert_eq!(blocked_targets(&v4, &v6), vec!["Google v6"]);
    }

    #[test]
    fn a_blocked_ipv4_operator_is_reported_whatever_ipv6_does() {
        let v4 = family(&[
            ("Cloudflare", None),
            ("Google", Some(14)),
            ("Quad9", Some(13)),
        ]);
        let v6 = family(&[("Cloudflare v6", None), ("Google v6", None)]);
        assert_eq!(blocked_targets(&v4, &v6), vec!["Cloudflare"]);
    }
}
