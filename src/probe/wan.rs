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

use super::net::{Probe, Quality, apply_quality, is_cgnat, tcp_connect};
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

/// Cloudflare's trace endpoint, reached by IP so no name has to resolve —
/// which keeps this check working during exactly the DNS failures it needs to
/// see past. It answers in `key=value` lines, one of which is the address the
/// far end saw the request come from.
const TRACE_BY_IP: &str = "https://1.1.1.1/cdn-cgi/trace";
/// The same endpoint by name, for the case where the IP literal is refused
/// (a TLS stack that won't match an IP SAN, a proxy that insists on SNI).
const TRACE_BY_NAME: &str = "https://one.one.one.one/cdn-cgi/trace";
/// Ceiling on the *whole* verified-request check, both URLs included.
///
/// It has to cover both, not each. Tried sequentially at a full deadline
/// apiece, this check alone could take as long as the engine's entire
/// per-probe budget — and then `sample_quality` still runs after the join.
/// The hop would time out and be replaced by a generic "reachability is
/// unknown", silently discarding the `HandshakeOnly` finding in exactly the
/// middlebox scenario it exists to catch, where a stalled HTTPS exchange is
/// the *expected* shape.
const TRACE_BUDGET: Duration = Duration::from_millis(3500);
/// Below this there isn't room for a request worth making, so the by-name
/// retry is skipped rather than started and cut off.
const MIN_TRACE: Duration = Duration::from_millis(1200);

/// What one real, complete request through the uplink found.
struct Egress {
    /// The address the far end saw — your public IP.
    public_ip: Option<IpAddr>,
    /// A full HTTPS exchange completed: TLS negotiated against a certificate
    /// that chains, and a body came back in the shape it should be.
    ///
    /// This is the difference between "a SYN was answered" and "the internet
    /// works". A middlebox can complete a handshake to anything; it cannot
    /// produce Cloudflare's certificate.
    verified: bool,
}

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

    let (v4, v6, egress) = tokio::join!(reach(&V4), reach(&V6), verify_egress());

    // Falling back through v6 matters: an IPv6-only network is the case where
    // the reader most needs to see *which* address is carrying traffic, and it
    // was the one showing a bare target count.
    hop.subtitle = Some(match v4.best().or_else(|| v6.best()) {
        Some((label, addr, _)) => format!("{addr} ({label})"),
        None => format!("{} targets", V4.len() + V6.len()),
    });

    // An unreached target is graded by what its silence contributes to *this
    // hop*, which is not the same as what it means for its own family.
    let any_reachable = v4.any_up() || v6.any_up();
    for family in [&v4, &v6] {
        for (label, probe) in &family.reached {
            let value = match probe {
                Probe::Up(d) => format!("{:.0} ms", d.as_secs_f64() * 1000.0),
                Probe::Timeout => "unreachable".to_string(),
            };
            let metric = Metric::new(*label, value);
            hop.metrics.push(
                match target_status(probe.is_up(), family.any_up(), any_reachable) {
                    Some(status) => metric.with_status(status),
                    None => metric,
                },
            );
        }
    }

    if let Some(ip) = egress.public_ip {
        hop.metrics.push(Metric::new("Public IP", ip.to_string()));
        if is_cgnat(ip) {
            hop.metrics.push(
                Metric::new("NAT", "carrier-grade — inbound connections can't reach you")
                    .with_status(Status::Warn),
            );
        }
    }

    hop.evidence = Some(evidence(
        v4.reached.len() + v6.reached.len(),
        egress.verified,
    ));

    match (v4.any_up(), v6.any_up()) {
        (true, dual_stack) => {
            // Reachability is settled; the open questions are quality, whether
            // any *individual* operator is being filtered, and whether those
            // handshakes actually mean anything.
            let (label, addr, first) = v4.best().expect("any_up means a target answered");
            let q = sample_quality(addr, first).await;
            let avg = q.avg_ms().unwrap_or_default();
            hop.latency_ms = Some(avg);
            let quality = apply_quality(&mut hop, &q, JITTER_WARN_MS);
            let blocked = blocked_targets(&v4, &v6);
            let handshake_only = handshake_only(&v4, &v6, &egress);
            hop.status = quality.max(block_status(&blocked)).max(if handshake_only {
                Status::Warn
            } else {
                Status::Ok
            });
            // Whichever finding is the more serious owns the code; a path that
            // answers handshakes but carries nothing is worse news than one
            // operator being filtered.
            if handshake_only {
                hop.fault = Some(Fault::HandshakeOnly);
                hop.summary = Some(
                    "Every handshake completes but no real request does — something is answering connections on the path without carrying them".into(),
                );
            } else {
                // The code follows the branch `summarise` took, reported by
                // `summarise` itself. When a quality complaint owns the prose
                // the block goes unmentioned, and a `--json` consumer reading
                // `target_blocked` off a hop whose text never says so has been
                // told two different things.
                let (summary, reports_block) = summarise(label, avg, dual_stack, &q, &blocked);
                if reports_block {
                    hop.fault = Some(Fault::TargetBlocked);
                }
                hop.summary = Some(summary);
            }
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
                    "No TCP path to the internet — {} independent networks ({}) all refused across {} addresses, so the break is past your router",
                    operator_count(),
                    operators(),
                    V4.len() + V6.len()
                ),
            );
        }
    }
    hop
}

/// How an individual target's result should read next to the hop's own status.
///
/// `-v` and `--json` both render per-metric status, so this has to agree with
/// the headline above it in both directions:
///
/// - nothing reachable anywhere: the hop fails, so its measurements are
///   `Fail` too — five yellow "Warn" lines under a red headline is the
///   evidence contradicting the verdict in the case this tool is most careful
///   about;
/// - a family that works but is missing an operator: `Warn`, the filtering
///   this probe exists to surface;
/// - a family this network simply doesn't carry while another one works: no
///   status at all. An IPv4-only home LAN is the most common config there is,
///   and marking its two IPv6 lines red under a green `Ok` hop is the same
///   contradiction reversed. It mirrors `blocked_targets`, which for the same
///   reason declines to call an absent family "filtered".
fn target_status(up: bool, family_any_up: bool, any_reachable: bool) -> Option<Status> {
    if up {
        Some(Status::Ok)
    } else if !any_reachable {
        Some(Status::Fail)
    } else if family_any_up {
        Some(Status::Warn)
    } else {
        None
    }
}

/// Whether the uplink answers handshakes without carrying traffic.
///
/// A TCP handshake proves only that *something* on the path replied to a SYN.
/// Interception appliances and some portals reply to everything, so a hop can
/// be entirely green while nothing works — the failure a topology diagram is
/// least able to show you.
///
/// The claim is only made when **every** target answered and the verified
/// request still didn't complete. A partial failure has a simpler explanation
/// already reported (filtering), and one request can fail on its own for
/// reasons that say nothing about the path; demanding unanimity on one side
/// and silence on the other keeps this from crying wolf.
fn handshake_only(v4: &Family, v6: &Family, egress: &Egress) -> bool {
    let all_answered = v4.down().next().is_none() && (!v6.any_up() || v6.down().next().is_none());
    v4.any_up() && all_answered && !egress.verified
}

/// One complete request through the uplink: the check that makes a green hop
/// mean something, and the only place a public address can come from.
async fn verify_egress() -> Egress {
    let unverified = Egress {
        public_ip: None,
        verified: false,
    };
    let Ok(client) = reqwest::Client::builder().build() else {
        return unverified;
    };
    let deadline = Instant::now() + TRACE_BUDGET;
    // By IP first, so this keeps working when name resolution doesn't — the
    // case it most needs to see past.
    for url in [TRACE_BY_IP, TRACE_BY_NAME] {
        let left = deadline.saturating_duration_since(Instant::now());
        // A by-IP attempt that failed because the TLS stack wouldn't match an
        // IP SAN fails fast, leaving room for the by-name retry. One that
        // stalled has already spent the budget, and starting a second request
        // would only push the hop past the deadline that discards its finding.
        if left < MIN_TRACE {
            break;
        }
        let Ok(resp) = client.get(url).timeout(left).send().await else {
            continue;
        };
        if !resp.status().is_success() {
            continue;
        }
        let Ok(body) = resp.text().await else {
            continue;
        };
        // The body has to be the shape it should be. A captive portal can
        // return 200 to anything; it cannot return this.
        if let Some(ip) = parse_trace(&body) {
            return Egress {
                public_ip: Some(ip),
                verified: true,
            };
        }
    }
    unverified
}

/// Pull the `ip=` line out of a `cdn-cgi/trace` response.
fn parse_trace(body: &str) -> Option<IpAddr> {
    body.lines()
        .find_map(|l| l.trim().strip_prefix("ip="))
        .and_then(|v| v.trim().parse().ok())
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
/// What this probe actually did, for the report's evidence line.
///
/// The verified request has to be described by its outcome, not asserted.
/// `handshake_only` is *defined* by `!verified`, so a fixed "plus one verified
/// HTTPS request" was guaranteed to contradict the cause printed beside it
/// whenever `HandshakeOnly` fired — in exactly the case the evidence matters
/// most.
fn evidence(addresses: usize, verified: bool) -> String {
    format!(
        "{addresses} handshakes to :{PORT} across {} independent networks, and one HTTPS request that {}",
        operator_count(),
        if verified {
            "completed"
        } else {
            "did not complete"
        }
    )
}

/// How many distinct operators back the targets. The outage message's whole
/// weight is "N independent networks went quiet", so this must count networks
/// and not addresses — two families of one operator are one network.
fn operator_count() -> usize {
    operators().split(", ").count()
}

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

/// The summary, plus whether it is the one that actually reports the block.
///
/// Returned rather than sniffed back out of the rendered English: gating
/// `Fault::TargetBlocked` on `summary.contains("blocks")` coupled the fault
/// code to a literal string, so rewording this function — to the fault's own
/// doc-comment word "filters", say — would silently stop setting the code, the
/// dedicated verdict arm would never fire, and the reader would fall back to
/// "check for background traffic" with the filtered operator unmentioned in
/// both the verdict and `--json`.
fn summarise(
    label: &str,
    avg: f64,
    dual_stack: bool,
    q: &Quality,
    blocked: &[&str],
) -> (String, bool) {
    let family = if dual_stack { "IPv4 + IPv6" } else { "IPv4" };
    if let Some(c) = q.complaint(JITTER_WARN_MS) {
        return (
            format!(
                "Reachable over {family} but the uplink is unhealthy — {c} over {} handshakes",
                q.sent
            ),
            false,
        );
    }
    if !blocked.is_empty() {
        // The uplink works, so this is about *this network's* filtering, not
        // about your connection being down. Saying which operator is missing
        // is the whole point of probing more than one.
        return (
            format!(
                "Reachable via {label} ({avg:.0} ms), but this network blocks {} — filtered egress, not an outage",
                blocked.join(" and ")
            ),
            true,
        );
    }
    let clean = if dual_stack {
        format!("Reachable over IPv4 + IPv6 ({avg:.0} ms via {label})")
    } else {
        format!("Reachable over IPv4 ({avg:.0} ms via {label}) · no IPv6 on this network")
    };
    (clean, false)
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
        let (summary, _) = summarise("Google", 10.7, false, &q, &["Cloudflare"]);
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
        let (summary, _) = summarise("Quad9", 10.7, true, &q, &[]);
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
        let (summary, _) = summarise("Google", 10.0, false, &lossy, &["Cloudflare"]);
        assert!(summary.contains("unhealthy"), "got: {summary}");
    }

    /// The outage message's weight is "N independent networks went quiet", so
    /// it must count networks, not addresses. Counting both families of the
    /// same operator inflates exactly the number that makes the claim
    /// credible — the inflation the operator-dedup test already guards.
    #[test]
    fn the_outage_count_matches_the_operators_it_lists() {
        assert_eq!(operator_count(), operators().split(", ").count());
        assert_eq!(operator_count(), 3);
        assert!(
            operator_count() < V4.len() + V6.len(),
            "two families of one operator are one network"
        );
    }

    /// The fault code must follow the branch `summarise` took, not the words
    /// it produced. Gated on `summary.contains("blocks")`, rewording the
    /// sentence would silently stop setting `TargetBlocked`, the dedicated
    /// verdict arm would never fire, and the filtered operator would go
    /// unmentioned in both the verdict and `--json`.
    #[test]
    fn the_block_flag_follows_the_branch_not_the_wording() {
        let clean = Quality {
            sent: 5,
            rtts_ms: vec![10.0, 11.0, 10.5, 11.2, 10.8],
        };
        let lossy = Quality {
            sent: 5,
            rtts_ms: vec![10.0],
        };
        assert!(summarise("Google", 10.7, false, &clean, &["Cloudflare"]).1);
        // A quality complaint owns the prose, so the block goes unmentioned —
        // and the code must not claim it either.
        assert!(!summarise("Google", 10.0, false, &lossy, &["Cloudflare"]).1);
        assert!(!summarise("Google", 10.7, false, &clean, &[]).1);
    }

    /// A per-target metric has to agree with the headline above it, in both
    /// directions — `-v` and `--json` render each one's own status.
    #[test]
    fn a_target_reads_as_what_its_silence_means_for_the_hop() {
        // Nothing reachable anywhere: the hop fails, so five yellow "Warn"
        // lines under a red headline would be evidence contradicting it.
        assert_eq!(target_status(false, false, false), Some(Status::Fail));
        // A working family missing one operator: the filtering this exists to
        // surface.
        assert_eq!(target_status(false, true, true), Some(Status::Warn));
        // A family this network doesn't carry while another works — an
        // IPv4-only home LAN, the most common config there is. Marking its
        // IPv6 lines red under a green `Ok` hop is the same contradiction
        // reversed, so it gets no status at all.
        assert_eq!(target_status(false, false, true), None);
        assert_eq!(target_status(true, true, true), Some(Status::Ok));
    }

    fn egress(verified: bool) -> Egress {
        Egress {
            public_ip: None,
            verified,
        }
    }

    fn all_up() -> Family {
        family(&[
            ("Cloudflare", Some(12)),
            ("Google", Some(14)),
            ("Quad9", Some(13)),
        ])
    }

    /// The failure a topology diagram is least able to show: every node green,
    /// nothing works. A handshake proves only that *something* answered a SYN,
    /// and interception appliances answer everything.
    #[test]
    fn handshakes_without_a_real_request_are_caught() {
        let v6 = family(&[("Cloudflare v6", None), ("Google v6", None)]);
        assert!(handshake_only(&all_up(), &v6, &egress(false)));
    }

    #[test]
    fn a_verified_request_clears_the_suspicion() {
        let v6 = family(&[("Cloudflare v6", None), ("Google v6", None)]);
        assert!(!handshake_only(&all_up(), &v6, &egress(true)));
    }

    /// One request can fail on its own for reasons that say nothing about the
    /// path, so the claim needs every target to have answered. A partial
    /// failure already has a simpler explanation — filtering — and reporting
    /// both would be two verdicts for one observation.
    #[test]
    fn a_partial_block_is_filtering_not_a_fake_uplink() {
        let v4 = family(&[
            ("Cloudflare", None),
            ("Google", Some(14)),
            ("Quad9", Some(13)),
        ]);
        let v6 = family(&[("Cloudflare v6", None), ("Google v6", None)]);
        assert!(!handshake_only(&v4, &v6, &egress(false)));
    }

    #[test]
    fn nothing_reachable_is_an_outage_not_a_fake_uplink() {
        let dead = family(&[("Cloudflare", None), ("Google", None), ("Quad9", None)]);
        let v6 = family(&[("Cloudflare v6", None), ("Google v6", None)]);
        assert!(!handshake_only(&dead, &v6, &egress(false)));
    }

    /// The check runs inside the same join as the reachability probes, and
    /// `sample_quality` runs after it. If the whole probe can outlast the
    /// engine's per-probe deadline, `send_bounded` replaces the hop with a
    /// generic "reachability is unknown" — discarding the `HandshakeOnly`
    /// finding in exactly the middlebox case where a stalled HTTPS exchange is
    /// the expected shape, and which this check exists to catch.
    #[test]
    fn the_whole_probe_fits_the_engine_deadline_in_the_worst_case() {
        // The join is bounded by its slowest arm; sampling follows it.
        let worst = TRACE_BUDGET.max(SAMPLE_WAIT) + SAMPLE_BUDGET;
        assert!(
            worst < crate::engine::PROBE_DEADLINE,
            "worst case {worst:?} must fit in {:?}",
            crate::engine::PROBE_DEADLINE
        );
    }

    /// And the budget covers *both* URLs, not one each — otherwise a stalled
    /// by-IP attempt and a stalled by-name retry would double it.
    #[test]
    fn a_spent_trace_budget_leaves_no_room_for_the_retry() {
        assert!(
            TRACE_BUDGET - MIN_TRACE < MIN_TRACE + MIN_TRACE,
            "the retry must not be able to double the budget"
        );
        assert!(
            MIN_TRACE < TRACE_BUDGET,
            "the first attempt must get a turn"
        );
    }

    /// `handshake_only` is *defined* by `!egress.verified`, so an evidence
    /// line claiming "one verified HTTPS request" was guaranteed to contradict
    /// the cause printed beside it whenever `HandshakeOnly` fired — in exactly
    /// the case the evidence matters most.
    #[test]
    fn the_evidence_cannot_claim_a_request_that_did_not_complete() {
        // The state that fires HandshakeOnly is exactly the state below.
        let v6 = family(&[("Cloudflare v6", None), ("Google v6", None)]);
        assert!(handshake_only(&all_up(), &v6, &egress(false)));

        let unverified = evidence(5, false);
        assert!(unverified.contains("did not complete"), "got: {unverified}");
        assert!(
            !unverified.contains("verified"),
            "must not read as a completed request: {unverified}"
        );
        assert!(evidence(5, true).contains("completed"));
    }

    #[test]
    fn the_trace_response_yields_the_public_address() {
        let body =
            "fl=123abc\nh=one.one.one.one\nip=203.0.113.7\nts=1700000000\nvisit_scheme=https\n";
        assert_eq!(
            parse_trace(body).map(|ip| ip.to_string()),
            Some("203.0.113.7".to_string())
        );
    }

    /// A portal can return 200 to anything; it cannot return this. Anything
    /// that isn't the expected shape must leave `verified` false rather than
    /// being taken as proof the uplink carries traffic.
    #[test]
    fn a_body_that_is_not_a_trace_response_yields_nothing() {
        assert_eq!(parse_trace("<html>Sign in to continue</html>"), None);
        assert_eq!(parse_trace(""), None);
        assert_eq!(parse_trace("ip=not-an-address"), None);
    }

    #[test]
    fn a_cgnat_public_address_is_recognised() {
        assert!(is_cgnat("100.80.4.9".parse().unwrap()));
        assert!(!is_cgnat("203.0.113.7".parse().unwrap()));
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
