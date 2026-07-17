//! L7 captive-portal probe.
//!
//! Hits Apple's plain-HTTP hotspot-detect endpoint with redirects disabled.
//! A clean network returns `Success`; anything else (a login page body or a
//! 302 to a portal) means a captive portal is intercepting traffic.

use crate::model::{Hop, HopId, Layer, Metric, Status};
use std::time::Duration;

const ENDPOINT: &str = "http://captive.apple.com/hotspot-detect.html";
const EXPECTED: &str = "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>";

pub async fn probe() -> Hop {
    let mut hop = Hop::new(HopId::Captive, Layer::Application, "Portal");
    hop.subtitle = Some("captive check".into());

    let client = match reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(4))
        .build()
    {
        Ok(c) => c,
        Err(_) => {
            hop.status = Status::Warn;
            hop.summary = Some("Couldn't build HTTP client".into());
            return hop;
        }
    };

    match client.get(ENDPOINT).send().await {
        Ok(resp) => {
            let status = resp.status();
            let redirect_to = resp
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
            let body = resp.text().await.unwrap_or_default();

            if status.is_redirection() {
                hop.status = Status::Fail;
                hop.summary = Some("Captive portal is redirecting you to a login page".into());
                if let Some(url) = redirect_to {
                    hop.metrics
                        .push(Metric::new("Portal", url).with_status(Status::Fail));
                }
            } else if body.trim() == EXPECTED {
                hop.status = Status::Ok;
                hop.summary = Some("No portal — traffic flows clean to the internet".into());
            } else {
                hop.status = Status::Fail;
                hop.summary = Some("A portal is intercepting HTTP (unexpected response)".into());
                hop.metrics.push(
                    Metric::new("HTTP", status.as_u16().to_string()).with_status(Status::Warn),
                );
            }
        }
        Err(_) => {
            // Can't even reach the endpoint — that's a WAN/DNS problem, not a
            // portal. Report neutral so the upstream break owns the verdict.
            hop.status = Status::Skipped;
            hop.summary = Some("Skipped — no HTTP path to test (see upstream failure)".into());
        }
    }
    hop
}
