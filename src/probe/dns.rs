//! L7 DNS probe: does name resolution work, and is it fast or hijacked?
//!
//! Benchmarks the system resolver against Cloudflare and Google so we can tell
//! "DNS is down" from "your ISP's resolver is slow" from "everything's fine".

use crate::model::{Fault, Hop, HopId, Layer, Metric, Status};
use hickory_resolver::TokioResolver;
use hickory_resolver::config::{CLOUDFLARE, GOOGLE, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use std::time::{Duration, Instant};

const QUERY: &str = "cloudflare.com.";

struct Bench {
    label: &'static str,
    latency: Option<f64>,
    ok: bool,
}

pub async fn probe() -> Hop {
    let mut hop = Hop::new(HopId::Dns, Layer::Application, "DNS");

    let (system, cf, google) = tokio::join!(
        bench_system(),
        bench_upstream("Cloudflare", ResolverConfig::udp_and_tcp(&CLOUDFLARE)),
        bench_upstream("Google", ResolverConfig::udp_and_tcp(&GOOGLE)),
    );

    hop.subtitle = Some("system resolver".into());
    hop.latency_ms = system.latency;

    for b in [&system, &cf, &google] {
        let (val, st) = match (b.ok, b.latency) {
            (true, Some(ms)) => (format!("{ms:.0} ms"), latency_status(ms)),
            _ => ("failed".into(), Status::Fail),
        };
        hop.metrics.push(Metric::new(b.label, val).with_status(st));
    }

    // The system resolver is what your apps actually use — grade on it, but
    // use the public resolvers as context for the cause.
    hop.status = match (system.ok, system.latency) {
        (true, Some(ms)) => latency_status(ms),
        // System resolver is dead either way; the cf/google split only shapes
        // the cause text below.
        _ => {
            hop.fault = Some(Fault::ResolverDead);
            Status::Fail
        }
    };

    hop.summary = Some(match (system.ok, system.latency) {
        (true, Some(ms)) if ms <= 50.0 => format!("Resolving fast ({ms:.0} ms)"),
        (true, Some(ms)) => format!("Resolving but slow ({ms:.0} ms)"),
        _ if cf.ok || google.ok => {
            "System resolver is dead, but public DNS works — misconfigured resolver".into()
        }
        _ => "Name resolution is failing everywhere".into(),
    });

    hop
}

fn latency_status(ms: f64) -> Status {
    if ms <= 80.0 { Status::Ok } else { Status::Warn }
}

fn failed(label: &'static str) -> Bench {
    Bench {
        label,
        latency: None,
        ok: false,
    }
}

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

async fn bench_system() -> Bench {
    let Ok(mut builder) = TokioResolver::builder_tokio() else {
        return failed("System");
    };
    builder.options_mut().timeout = QUERY_WAIT;
    builder.options_mut().attempts = QUERY_ATTEMPTS;
    match builder.build() {
        Ok(resolver) => time_lookup("System", resolver).await,
        Err(_) => failed("System"),
    }
}

async fn bench_upstream(label: &'static str, config: ResolverConfig) -> Bench {
    let mut builder = TokioResolver::builder_with_config(config, TokioRuntimeProvider::default());
    builder.options_mut().timeout = QUERY_WAIT;
    builder.options_mut().attempts = QUERY_ATTEMPTS;
    match builder.build() {
        Ok(resolver) => time_lookup(label, resolver).await,
        Err(_) => failed(label),
    }
}

async fn time_lookup(label: &'static str, resolver: TokioResolver) -> Bench {
    let start = Instant::now();
    match resolver.lookup_ip(QUERY).await {
        Ok(ans) if ans.iter().next().is_some() => Bench {
            label,
            latency: Some(start.elapsed().as_secs_f64() * 1000.0),
            ok: true,
        },
        _ => Bench {
            label,
            latency: None,
            ok: false,
        },
    }
}
