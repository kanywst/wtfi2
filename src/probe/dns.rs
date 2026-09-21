//! L7 DNS probe: does name resolution work, is it fast, and is it honest?
//!
//! Benchmarks the system resolver against Cloudflare and Google so we can tell
//! "DNS is down" from "your ISP's resolver is slow" from "everything's fine",
//! and names the resolvers it actually measured — "System: failed" is not much
//! use when you can't tell whether that's your router, a stale corporate
//! resolver or a VPN's.
//!
//! Speed alone is not health, though. A resolver that answers instantly with
//! the wrong address is the fastest one on the network, and grading only on
//! latency marks it green. So the answers are checked too.

use crate::model::{Fault, Hop, HopId, Layer, Metric, Status};
use hickory_resolver::TokioResolver;
use hickory_resolver::config::{CLOUDFLARE, GOOGLE, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use std::net::IpAddr;
use std::time::{Duration, Instant};

const QUERY: &str = "cloudflare.com.";

/// Ceiling for a single resolver, applied to *every* bench.
///
/// It has to be one number. Held to hickory's defaults (5 s over 2 attempts,
/// per configured nameserver) the system bench alone can run past ten seconds
/// — long enough to outlast every other probe in the sweep and to break the
/// live dashboard's re-probe cadence during exactly the DNS outage it is meant
/// to be showing you. And comparing a resolver measured under one deadline
/// against two measured under a tighter one is not a benchmark.
const QUERY_WAIT: Duration = Duration::from_secs(3);
/// One shot per resolver: a retry would double the ceiling, and "it didn't
/// answer the first time" is already the signal worth reporting.
const QUERY_ATTEMPTS: usize = 1;
/// Ceiling on the system bench *as a whole*, not per nameserver.
///
/// hickory applies `QUERY_WAIT` to each configured nameserver in turn, so a
/// host with three or more — a VPN-pushed resolver plus two ISP fallbacks, or
/// dual-stack pairs — can still outrun the engine's per-probe deadline. The
/// engine would then report the whole hop as unmeasured, which is the worse
/// of the two wrong answers: a resolver that is merely slow becomes a gap in
/// the evidence rather than the finding it actually is.
///
/// Sized so the probe (whose benches all run concurrently) stays inside
/// `PROBE_DEADLINE` with room to spare.
const SYSTEM_BENCH_BUDGET: Duration = Duration::from_secs(6);

struct Bench {
    label: &'static str,
    latency: Option<f64>,
    ok: bool,
    /// Addresses returned, so the *answer* can be checked and not just the
    /// clock.
    addrs: Vec<IpAddr>,
}

/// A resolver that answers, but not truthfully.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Hijack {
    /// A name that cannot exist resolved anyway — the resolver is synthesising
    /// answers instead of returning NXDOMAIN.
    Nxdomain,
    /// A public name resolved to an address on a private network. Nothing
    /// legitimate does this for `cloudflare.com`; a portal or an interception
    /// appliance does.
    PrivateAnswer,
}

pub async fn probe(nameservers: &[IpAddr]) -> Hop {
    let mut hop = Hop::new(HopId::Dns, Layer::Application, "DNS");

    let (system, cf, google, synthesised) = tokio::join!(
        bench_system(),
        bench_upstream("Cloudflare", ResolverConfig::udp_and_tcp(&CLOUDFLARE)),
        bench_upstream("Google", ResolverConfig::udp_and_tcp(&GOOGLE)),
        system_answers_nonexistent_name(),
    );

    hop.subtitle = Some(describe(nameservers));
    hop.latency_ms = system.latency;
    if !nameservers.is_empty() {
        hop.metrics.push(Metric::new(
            "Resolvers",
            nameservers
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", "),
        ));
    }

    for b in [&system, &cf, &google] {
        let (val, st) = match (b.ok, b.latency) {
            (true, Some(ms)) => (format!("{ms:.0} ms"), latency_status(ms)),
            _ => ("failed".into(), Status::Fail),
        };
        hop.metrics.push(Metric::new(b.label, val).with_status(st));
    }

    hop.evidence = Some(format!(
        "{QUERY} asked of 3 resolvers under a {}s deadline ({} answered), plus one nonexistent-name check",
        QUERY_WAIT.as_secs(),
        [&system, &cf, &google].iter().filter(|b| b.ok).count()
    ));

    let hijacked = detect_hijack(&system, &[&cf, &google], synthesised);
    grade(&mut hop, &system, &cf, &google, hijacked);
    hop
}

/// Turn the resolver list into the hop's subtitle.
fn describe(nameservers: &[IpAddr]) -> String {
    match nameservers {
        [] => "system resolver".to_string(),
        [one] => one.to_string(),
        [first, rest @ ..] => format!("{first} +{} more", rest.len()),
    }
}

/// Decide what the hop reports. Pure, so every branch is testable without a
/// resolver to lie to us.
fn grade(hop: &mut Hop, system: &Bench, cf: &Bench, google: &Bench, hijacked: Option<Hijack>) {
    // A dead resolver outranks a dishonest one: "it answers wrongly" is not a
    // finding you can make about a resolver that didn't answer. The NXDOMAIN
    // check is a *separate* query from the bench, so with one attempt and no
    // retry the bench can time out while the bogus-name query still gets a
    // synthesised reply — which used to report a wholly dead resolver as
    // merely "sluggish but dishonest".
    let hijacked = hijacked.filter(|_| system.ok);

    // Otherwise hijacking is checked before latency, because a hijacked
    // resolver is fast: it answers from a table instead of doing the work, and
    // grading on the clock alone marks the one resolver you must not trust as
    // the healthiest thing in the report.
    if let Some(kind) = hijacked {
        match kind {
            // Answers substituted for a public name: you are being intercepted,
            // which means you are not really online.
            Hijack::PrivateAnswer => {
                hop.fail(
                    Fault::ResolverHijacked,
                    format!(
                        "Your resolver is lying — it answers {QUERY} with a private address, so something is intercepting your traffic"
                    ),
                );
            }
            // Synthesised NXDOMAIN: typically ISP search/ad redirection. It is
            // dishonest and it breaks software that relies on NXDOMAIN, but the
            // network still works, so it is a warning and not a break.
            Hijack::Nxdomain => {
                hop.status = Status::Warn;
                hop.fault = Some(Fault::ResolverHijacked);
                hop.summary = Some(
                    "Your resolver invents answers for names that don't exist — NXDOMAIN hijacking, usually ISP ad/search redirection".into(),
                );
            }
        }
        return;
    }

    // The system resolver is what your apps actually use — grade on it, but
    // use the public resolvers as context for the cause.
    hop.status = match (system.ok, system.latency) {
        (true, Some(ms)) => latency_status(ms),
        _ => {
            hop.fault = Some(Fault::ResolverDead);
            Status::Fail
        }
    };

    hop.summary = Some(match (system.ok, system.latency) {
        (true, Some(ms)) if ms <= 50.0 => format!("Resolving fast ({ms:.0} ms)"),
        (true, Some(ms)) => format!("Resolving but slow ({ms:.0} ms)"),
        // "No answer in time" rather than "dead": with several nameservers
        // configured, the budget can expire on a resolver that would have
        // answered from a later one. Slow past the point of usefulness is
        // still the honest description of that.
        _ if cf.ok || google.ok => format!(
            "Your resolver gave no answer within {}s, but public DNS works — misconfigured or unreachable resolver",
            SYSTEM_BENCH_BUDGET.as_secs()
        ),
        _ => "Name resolution is failing everywhere".into(),
    });
}

/// Compare the system resolver's *answer* against the public ones.
///
/// A public baseline is required before claiming substitution: without one we
/// cannot tell an interception appliance from a network where the name simply
/// resolves differently, and "your resolver is lying" is far too strong a claim
/// to make on a guess.
fn detect_hijack(system: &Bench, public: &[&Bench], synthesised: bool) -> Option<Hijack> {
    let baseline_is_public = public
        .iter()
        .any(|b| b.ok && !b.addrs.is_empty() && b.addrs.iter().all(|ip| !is_private(*ip)));
    if baseline_is_public && system.addrs.iter().any(|ip| is_private(*ip)) {
        return Some(Hijack::PrivateAnswer);
    }
    synthesised.then_some(Hijack::Nxdomain)
}

/// Addresses that cannot legitimately be the answer for a public name.
fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private() || v4.is_link_local() || v4.is_loopback() || v4.is_unspecified()
        }
        // fc00::/7 unique-local and fe80::/10 link-local — the latter being
        // the direct analogue of the v4 169.254 case caught above, and AAAA
        // answers reach here through the same path as A records.
        IpAddr::V6(v6) => {
            let head = v6.segments()[0];
            (head & 0xfe00) == 0xfc00
                || (head & 0xffc0) == 0xfe80
                || v6.is_loopback()
                || v6.is_unspecified()
        }
    }
}

fn latency_status(ms: f64) -> Status {
    if ms <= 80.0 { Status::Ok } else { Status::Warn }
}

fn failed(label: &'static str) -> Bench {
    Bench {
        label,
        latency: None,
        ok: false,
        addrs: Vec::new(),
    }
}

fn system_resolver() -> Option<TokioResolver> {
    let mut builder = TokioResolver::builder_tokio().ok()?;
    builder.options_mut().timeout = QUERY_WAIT;
    builder.options_mut().attempts = QUERY_ATTEMPTS;
    builder.build().ok()
}

async fn bench_system() -> Bench {
    let Some(resolver) = system_resolver() else {
        return failed("System");
    };
    // Bounded here rather than left to the engine: a hop reporting "the
    // resolver gave no answer in time" is a finding, while one the engine
    // times out is just a hole where a finding should be.
    tokio::time::timeout(SYSTEM_BENCH_BUDGET, time_lookup("System", resolver, QUERY))
        .await
        .unwrap_or_else(|_| failed("System"))
}

async fn bench_upstream(label: &'static str, config: ResolverConfig) -> Bench {
    let mut builder = TokioResolver::builder_with_config(config, TokioRuntimeProvider::default());
    builder.options_mut().timeout = QUERY_WAIT;
    builder.options_mut().attempts = QUERY_ATTEMPTS;
    match builder.build() {
        Ok(resolver) => time_lookup(label, resolver, QUERY).await,
        Err(_) => failed(label),
    }
}

/// Ask the system resolver for a name that cannot exist. An honest resolver
/// returns NXDOMAIN; one that returns an address is synthesising answers.
///
/// The label is random rather than a fixed sentinel, so a resolver cannot be
/// tuned to answer this specific probe honestly while hijacking everything
/// else, and so repeated runs can't be served from a cached answer.
async fn system_answers_nonexistent_name() -> bool {
    let Some(resolver) = system_resolver() else {
        return false;
    };
    let name = format!("wtfi-{:016x}.com.", random_label());
    matches!(resolver.lookup_ip(name).await, Ok(ans) if ans.iter().next().is_some())
}

/// A per-run random value. Sourced from the clock rather than a dependency:
/// this needs to be unpredictable to a resolver, not cryptographically random.
fn random_label() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
        .wrapping_mul(0x9e37_79b9_7f4a_7c15)
}

async fn time_lookup(label: &'static str, resolver: TokioResolver, query: &str) -> Bench {
    let start = Instant::now();
    match resolver.lookup_ip(query).await {
        Ok(ans) if ans.iter().next().is_some() => Bench {
            label,
            latency: Some(start.elapsed().as_secs_f64() * 1000.0),
            ok: true,
            addrs: ans.iter().collect(),
        },
        _ => failed(label),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bench(label: &'static str, ok: bool, addrs: &[&str]) -> Bench {
        Bench {
            label,
            latency: ok.then_some(12.0),
            ok,
            addrs: addrs.iter().map(|s| s.parse().unwrap()).collect(),
        }
    }

    fn graded(system: Bench, cf: Bench, google: Bench, hijacked: Option<Hijack>) -> Hop {
        let mut hop = Hop::new(HopId::Dns, Layer::Application, "DNS");
        grade(&mut hop, &system, &cf, &google, hijacked);
        hop
    }

    /// The gap this closes: a hijacked resolver is the *fastest* one on the
    /// network, because it answers from a table instead of doing the work.
    /// Grading on the clock alone marked the one resolver you must not trust
    /// as the healthiest thing in the report.
    #[test]
    fn a_fast_liar_is_not_graded_as_healthy() {
        let hop = graded(
            bench("System", true, &["192.168.0.1"]),
            bench("Cloudflare", true, &["104.16.132.229"]),
            bench("Google", true, &["104.16.132.229"]),
            Some(Hijack::PrivateAnswer),
        );
        assert_eq!(hop.status, Status::Fail);
        assert_eq!(hop.fault, Some(Fault::ResolverHijacked));
        assert!(hop.summary.unwrap().contains("lying"));
    }

    /// Synthesised NXDOMAIN is dishonest and breaks software that relies on
    /// NXDOMAIN, but the network still works — so it warns rather than
    /// claiming a break that isn't there.
    #[test]
    fn nxdomain_hijacking_warns_rather_than_breaking() {
        let hop = graded(
            bench("System", true, &["104.16.132.229"]),
            bench("Cloudflare", true, &["104.16.132.229"]),
            bench("Google", true, &["104.16.132.229"]),
            Some(Hijack::Nxdomain),
        );
        assert_eq!(hop.status, Status::Warn);
        assert_eq!(hop.fault, Some(Fault::ResolverHijacked));
    }

    #[test]
    fn a_private_answer_against_a_public_baseline_is_a_hijack() {
        let system = bench("System", true, &["10.0.0.1"]);
        let cf = bench("Cloudflare", true, &["104.16.132.229"]);
        let google = bench("Google", true, &["104.16.132.229"]);
        assert_eq!(
            detect_hijack(&system, &[&cf, &google], false),
            Some(Hijack::PrivateAnswer)
        );
    }

    /// Without a public resolver to compare against there is no baseline, and
    /// "your resolver is lying" is much too strong a claim to make on a guess
    /// — a network where every resolver is unreachable is not a hijacked one.
    #[test]
    fn no_public_baseline_means_no_hijack_claim() {
        let system = bench("System", true, &["10.0.0.1"]);
        let dead_cf = bench("Cloudflare", false, &[]);
        let dead_google = bench("Google", false, &[]);
        assert_eq!(
            detect_hijack(&system, &[&dead_cf, &dead_google], false),
            None
        );
    }

    #[test]
    fn matching_public_answers_are_not_a_hijack() {
        let system = bench("System", true, &["104.16.132.229"]);
        let cf = bench("Cloudflare", true, &["104.16.132.229"]);
        let google = bench("Google", true, &["104.16.133.229"]);
        // Different CDN edges are normal; only a *private* answer is damning.
        assert_eq!(detect_hijack(&system, &[&cf, &google], false), None);
    }

    /// The NXDOMAIN check is a separate query from the bench, so with one
    /// attempt and no retry the bench can time out while the bogus-name query
    /// still gets a synthesised reply. Reporting that as "sluggish but
    /// dishonest" hides a resolver that is wholly dead — and "it answers
    /// wrongly" is not a finding you can make about one that didn't answer.
    #[test]
    fn a_dead_resolver_outranks_a_hijack_finding_on_another_query() {
        let hop = graded(
            failed("System"),
            bench("Cloudflare", true, &["104.16.132.229"]),
            bench("Google", true, &["104.16.132.229"]),
            Some(Hijack::Nxdomain),
        );
        assert_eq!(hop.status, Status::Fail);
        assert_eq!(hop.fault, Some(Fault::ResolverDead));
    }

    #[test]
    fn a_dead_system_resolver_still_reports_dead() {
        let hop = graded(
            failed("System"),
            bench("Cloudflare", true, &["104.16.132.229"]),
            bench("Google", true, &["104.16.132.229"]),
            None,
        );
        assert_eq!(hop.status, Status::Fail);
        assert_eq!(hop.fault, Some(Fault::ResolverDead));
        assert!(hop.summary.unwrap().contains("public DNS works"));
    }

    #[test]
    fn a_healthy_resolver_stays_healthy() {
        let hop = graded(
            bench("System", true, &["104.16.132.229"]),
            bench("Cloudflare", true, &["104.16.132.229"]),
            bench("Google", true, &["104.16.132.229"]),
            None,
        );
        assert_eq!(hop.status, Status::Ok);
        assert_eq!(hop.fault, None);
    }

    /// "System: failed" is not much use when you can't tell whether that is
    /// your router, a stale corporate resolver, or a VPN's.
    #[test]
    fn the_subtitle_names_the_resolvers_actually_in_use() {
        assert_eq!(describe(&[]), "system resolver");
        assert_eq!(describe(&["192.168.0.1".parse().unwrap()]), "192.168.0.1");
        let two = ["192.168.0.1".parse().unwrap(), "8.8.8.8".parse().unwrap()];
        assert!(describe(&two).contains("192.168.0.1"));
    }

    #[test]
    fn private_ranges_are_recognised() {
        for ip in [
            "10.0.0.1",
            "192.168.1.1",
            "172.16.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "fd00::1",
            // The v6 analogue of 169.254: an AAAA substitution reaches here
            // through the same path as an A record, so both must be caught.
            "fe80::1",
        ] {
            assert!(is_private(ip.parse().unwrap()), "{ip} should be private");
        }
        for ip in ["1.1.1.1", "104.16.132.229", "2606:4700::1111"] {
            assert!(!is_private(ip.parse().unwrap()), "{ip} should be public");
        }
    }
}
