//! L7 captive-portal probe.
//!
//! Two independent signals, run concurrently, because the obvious one stops
//! working in the case that matters most.
//!
//! The obvious one is Apple's plain-HTTP hotspot-detect endpoint: a clean
//! network returns `Success`, and a login page or a 302 means a portal. But it
//! is reached *by hostname*, so it needs the system resolver — and hijacking
//! the system resolver is how captive portals usually announce themselves.
//! When DNS goes, this check goes with it, and the portal is missed at exactly
//! the moment it is the answer.
//!
//! So it is backed by a DNS-free one: a plain HTTP request to an address that
//! cannot exist on the public internet. Nothing legitimate can answer it, so
//! any HTTP reply at all is proof that something on the path is intercepting
//! port 80.

use crate::model::{Fault, Hop, HopId, Layer, Metric, Status};
use std::time::Duration;

const HOTSPOT: &str = "http://captive.apple.com/hotspot-detect.html";
const EXPECTED: &str = "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>";

/// TEST-NET-1 (RFC 5737): reserved for documentation and never routed on the
/// public internet. Nothing legitimate is listening here, so a reply is not
/// ambiguous — it is an interceptor. No name is resolved to reach it, which is
/// the entire point.
const UNROUTABLE: &str = "http://192.0.2.1/";

/// The hotspot endpoint needs to survive a slow-but-working network.
const HOTSPOT_WAIT: Duration = Duration::from_secs(4);
/// The interception probe is expected to time out on every healthy network, so
/// it is held short. It runs concurrently with the hotspot check and so adds
/// no wall-clock cost.
const INTERCEPT_WAIT: Duration = Duration::from_secs(2);

/// What the hotspot endpoint had to say.
enum Hotspot {
    /// Answered with exactly the sentinel body: no portal.
    Clean,
    /// Answered with something else — a redirect or a login page.
    Portal(Option<Metric>),
    /// Never answered. On its own this says nothing about portals: it is what
    /// a dead uplink *and* a hijacked resolver both look like.
    Unreachable,
}

pub async fn probe() -> Hop {
    let mut hop = Hop::new(HopId::Captive, Layer::Application, "Portal");
    hop.subtitle = Some("captive check".into());

    let client = match reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
    {
        Ok(c) => c,
        Err(_) => {
            hop.status = Status::Warn;
            hop.fault = Some(Fault::Unobserved);
            hop.summary = Some("Couldn't build HTTP client".into());
            return hop;
        }
    };

    let (hotspot, intercepted) = tokio::join!(
        check_hotspot(&client),
        check_interception(&client, UNROUTABLE)
    );
    hop.evidence = Some(format!(
        "hotspot check against {HOTSPOT}, plus a DNS-free port-80 probe to {UNROUTABLE}"
    ));
    grade(&mut hop, hotspot, intercepted);
    hop
}

/// Combine the two signals. Pure, so the decision that matters is testable
/// without a network or a portal to stand in front of one.
fn grade(hop: &mut Hop, hotspot: Hotspot, intercepted: Option<u16>) {
    // The DNS-free signal is read first: it is the one that still works when a
    // portal has taken the resolver down with it, which is the common case.
    if let Some(status) = intercepted {
        hop.fail(
            Fault::PortalIntercept,
            "Something is intercepting HTTP — a portal is standing between you and the internet",
        );
        hop.metrics.push(
            Metric::new("Intercepted", format!("HTTP {status} from 192.0.2.1"))
                .with_status(Status::Fail),
        );
        return;
    }

    match hotspot {
        Hotspot::Portal(detail) => {
            hop.fail(
                Fault::PortalIntercept,
                "Captive portal is intercepting the hotspot check",
            );
            hop.metrics.extend(detail);
        }
        Hotspot::Clean => {
            hop.status = Status::Ok;
            hop.summary = Some("No portal — traffic flows clean to the internet".into());
        }
        // Neither probe drew a reply. That is not "we couldn't check": a
        // portal would have answered the interception probe, and none did. So
        // this positively rules a portal out and leaves the upstream break
        // owning the verdict — a stronger statement than the old "skipped,
        // see upstream failure", which said nothing at all.
        Hotspot::Unreachable => {
            hop.status = Status::Skipped;
            hop.summary =
                Some("No portal — nothing answered on port 80, and a portal would have".into());
        }
    }
}

async fn check_hotspot(client: &reqwest::Client) -> Hotspot {
    let Ok(resp) = client.get(HOTSPOT).timeout(HOTSPOT_WAIT).send().await else {
        return Hotspot::Unreachable;
    };
    let status = resp.status();
    let redirect_to = resp
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    if status.is_redirection() {
        return Hotspot::Portal(
            redirect_to.map(|url| Metric::new("Portal", url).with_status(Status::Fail)),
        );
    }
    // A body we couldn't read is not a body that said the wrong thing. Both
    // used to land on `Portal`, so a connection dropping mid-read on a
    // portal-free network reported "sign in to the Wi-Fi" — and because a
    // detected portal outranks every upstream break, that verdict took over
    // the whole report, sending the reader to look for a login page that
    // doesn't exist.
    let Ok(body) = resp.text().await else {
        return Hotspot::Unreachable;
    };
    if body.trim() == EXPECTED {
        Hotspot::Clean
    } else {
        Hotspot::Portal(Some(
            Metric::new("HTTP", status.as_u16().to_string()).with_status(Status::Warn),
        ))
    }
}

/// Ask an address that cannot answer, and report the status code if one does.
async fn check_interception(client: &reqwest::Client, url: &str) -> Option<u16> {
    client
        .get(url)
        .timeout(INTERCEPT_WAIT)
        .send()
        .await
        .ok()
        .map(|r| r.status().as_u16())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn graded(hotspot: Hotspot, intercepted: Option<u16>) -> Hop {
        let mut hop = Hop::new(HopId::Captive, Layer::Application, "Portal");
        grade(&mut hop, hotspot, intercepted);
        hop
    }

    /// The regression this probe was rebuilt for. Portals routinely hijack
    /// DNS, which kills the hostname-based hotspot check — so the portal went
    /// undetected, the diagnosis engine's "a portal outranks the upstream
    /// break it caused" rule never fired, and the verdict blamed the ISP.
    #[test]
    fn a_portal_that_took_dns_with_it_is_still_caught() {
        let hop = graded(Hotspot::Unreachable, Some(302));
        assert_eq!(hop.status, Status::Fail);
        assert_eq!(hop.fault, Some(Fault::PortalIntercept));
    }

    /// An address that cannot exist answered, so the reply is an interceptor
    /// and the evidence has to say which address made that provable.
    #[test]
    fn the_interception_evidence_names_the_impossible_address() {
        let hop = graded(Hotspot::Clean, Some(200));
        assert!(
            hop.metrics.iter().any(|m| m.value.contains("192.0.2.1")),
            "got: {:?}",
            hop.metrics
        );
    }

    #[test]
    fn a_clean_network_stays_clean() {
        let hop = graded(Hotspot::Clean, None);
        assert_eq!(hop.status, Status::Ok);
        assert_eq!(hop.fault, None);
    }

    #[test]
    fn a_hijacked_hotspot_response_is_a_portal() {
        let hop = graded(Hotspot::Portal(None), None);
        assert_eq!(hop.status, Status::Fail);
        assert_eq!(hop.fault, Some(Fault::PortalIntercept));
    }

    /// Silence on both probes rules a portal *out*: a portal would have
    /// answered the interception probe. The old code called this "skipped —
    /// no HTTP path to test", which told the reader nothing.
    #[test]
    fn total_silence_rules_a_portal_out_rather_than_giving_up() {
        let hop = graded(Hotspot::Unreachable, None);
        assert_eq!(hop.status, Status::Skipped);
        assert_eq!(hop.fault, None, "ruling a portal out is not a fault");
        let summary = hop.summary.unwrap();
        assert!(summary.contains("No portal"), "got: {summary}");
    }
}
