//! Root-cause reasoning.
//!
//! The old wtfi printed a flat checklist and left the human to correlate it.
//! This engine walks the completed [`Path`], finds where connectivity actually
//! dies, and turns the surrounding evidence into a single plain verdict plus a
//! concrete fix — the thing you actually wanted to know.

use crate::model::{HopId, Path, Status};

/// Confidence in a verdict, surfaced so the UI can hedge honestly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    Certain,
    Likely,
    Guess,
}

/// The engine's conclusion about the current network state.
#[derive(Debug, Clone)]
pub struct Verdict {
    /// Overall severity, mirroring the worst meaningful hop.
    pub status: Status,
    /// One-line headline, e.g. `DNS resolution is failing`.
    pub headline: String,
    /// Why it's happening, in plain language.
    pub cause: String,
    /// A concrete next action, when we have one.
    pub fix: Option<String>,
    pub confidence: Confidence,
}

/// Derive a verdict from a (ideally complete) path.
pub fn diagnose(path: &Path) -> Verdict {
    // 0. Still probing — don't render a health claim from half the evidence.
    if path.hops.iter().any(|h| h.status == Status::Pending) {
        return Verdict {
            status: Status::Pending,
            headline: "Scanning your connection…".into(),
            cause: "Probing each hop from your Wi-Fi link out to the internet.".into(),
            fix: None,
            confidence: Confidence::Guess,
        };
    }

    // 1. The connection is broken somewhere: explain the *first* break, since
    //    everything downstream is just collateral.
    if let Some(broken) = path.first_break() {
        return explain_break(path, broken.id);
    }

    // 2. Nothing is broken — surface the worst degradation, if any.
    if let Some(warn) = path
        .hops
        .iter()
        .filter(|h| h.status == Status::Warn)
        .min_by_key(|h| h.id as usize)
    {
        return explain_warn(path, warn.id);
    }

    // 3. Clean bill of health.
    Verdict {
        status: Status::Ok,
        headline: "You're fully online".into(),
        cause: "Every hop from your Wi-Fi to the internet is healthy.".into(),
        fix: None,
        confidence: Confidence::Certain,
    }
}

fn hop_status(path: &Path, id: HopId) -> Status {
    path.get(id).map(|h| h.status).unwrap_or(Status::Skipped)
}

fn explain_break(path: &Path, id: HopId) -> Verdict {
    let (headline, cause, fix, confidence) = match id {
        HopId::Link => (
            "Wi-Fi link is down",
            "Your machine isn't associated with an access point. There's no L2 link to diagnose above.".to_string(),
            Some("Toggle Wi-Fi off/on, or pick a network in the Wi-Fi menu.".to_string()),
            Confidence::Certain,
        ),
        HopId::Gateway => {
            // Link up but the router won't answer.
            let link_note = match path.get(HopId::Link).and_then(|h| h.summary.clone()) {
                Some(s) => format!(" Link looks like: {s}."),
                None => String::new(),
            };
            (
                "Your router isn't responding",
                format!("You're associated to Wi-Fi but the default gateway isn't answering pings, so nothing leaves your LAN.{link_note}"),
                Some("Reboot the router, or check that you actually got a DHCP lease.".to_string()),
                Confidence::Likely,
            )
        }
        HopId::Wan => (
            "Your ISP / uplink is down",
            "The router answers locally, but nothing beyond it is reachable — the break is between your router and the internet.".to_string(),
            Some("Check the modem/ONU lights; this is usually an ISP or WAN-cable outage, not your Mac.".to_string()),
            Confidence::Likely,
        ),
        HopId::Dns => {
            let wan_ok = hop_status(path, HopId::Wan) == Status::Ok;
            let cause = if wan_ok {
                "Raw internet works (IPs are reachable) but name resolution fails — a classic DNS-only outage."
            } else {
                "Name resolution is failing and the WAN looks shaky too."
            };
            (
                "DNS resolution is failing",
                cause.to_string(),
                Some("Switch resolvers to 1.1.1.1 / 8.8.8.8, or flush the DNS cache.".to_string()),
                Confidence::Likely,
            )
        }
        HopId::Captive => (
            "A captive portal is blocking you",
            "DNS and routing work, but a hotspot login page is intercepting your traffic — you're not really online yet.".to_string(),
            Some("Open http://captive.apple.com in a browser and sign in.".to_string()),
            Confidence::Certain,
        ),
        HopId::Internet | HopId::Host => (
            "You're offline",
            "The connectivity chain is broken end-to-end.".to_string(),
            None,
            Confidence::Guess,
        ),
    };

    Verdict {
        status: Status::Fail,
        headline: headline.to_string(),
        cause,
        fix,
        confidence,
    }
}

fn explain_warn(path: &Path, id: HopId) -> Verdict {
    let summary = path
        .get(id)
        .and_then(|h| h.summary.clone())
        .unwrap_or_default();
    let (headline, cause, fix) = match id {
        HopId::Link => (
            "Weak Wi-Fi signal",
            format!("You're online, but the link is marginal — {summary}. Expect stalls and retransmits."),
            Some("Move closer to the AP or switch to 5 GHz.".to_string()),
        ),
        HopId::Wan => (
            "Internet is up but degraded",
            format!("Reachable, but quality is poor — {summary}."),
            Some("Check for background traffic or a congested uplink.".to_string()),
        ),
        HopId::Dns => (
            "DNS is slow",
            format!("Resolution works but is sluggish — {summary}."),
            Some("Try a faster resolver like 1.1.1.1.".to_string()),
        ),
        _ => (
            "Minor degradation",
            summary,
            None,
        ),
    };
    Verdict {
        status: Status::Warn,
        headline: headline.to_string(),
        cause,
        fix,
        confidence: Confidence::Likely,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Hop, Layer};

    fn hop(id: HopId, layer: Layer, s: Status) -> Hop {
        let mut h = Hop::new(id, layer, "x");
        h.status = s;
        h
    }

    #[test]
    fn dns_only_outage_is_pinpointed() {
        let p = Path {
            hops: vec![
                hop(HopId::Link, Layer::Link, Status::Ok),
                hop(HopId::Gateway, Layer::Network, Status::Ok),
                hop(HopId::Wan, Layer::Internet, Status::Ok),
                hop(HopId::Dns, Layer::Application, Status::Fail),
            ],
        };
        let v = diagnose(&p);
        assert_eq!(v.status, Status::Fail);
        assert!(v.headline.contains("DNS"));
        assert!(v.cause.contains("Raw internet works"));
    }

    #[test]
    fn earliest_break_wins_over_downstream() {
        let p = Path {
            hops: vec![
                hop(HopId::Link, Layer::Link, Status::Ok),
                hop(HopId::Gateway, Layer::Network, Status::Fail),
                hop(HopId::Wan, Layer::Internet, Status::Fail),
                hop(HopId::Dns, Layer::Application, Status::Fail),
            ],
        };
        let v = diagnose(&p);
        assert!(v.headline.contains("router"));
    }

    #[test]
    fn all_ok_is_clean() {
        let p = Path {
            hops: vec![
                hop(HopId::Link, Layer::Link, Status::Ok),
                hop(HopId::Gateway, Layer::Network, Status::Ok),
                hop(HopId::Wan, Layer::Internet, Status::Ok),
                hop(HopId::Dns, Layer::Application, Status::Ok),
            ],
        };
        assert_eq!(diagnose(&p).status, Status::Ok);
    }
}
