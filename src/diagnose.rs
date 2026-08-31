//! Root-cause reasoning.
//!
//! The old wtfi printed a flat checklist and left the human to correlate it.
//! This engine walks the completed [`Path`], finds where connectivity actually
//! dies, and turns the surrounding evidence into a single plain verdict plus a
//! concrete fix — the thing you actually wanted to know.

use crate::model::{HopId, Path, Status};
use crate::probe::net::LOSS_WARN_PCT;

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
    // 0. No platform module: every hop is skipped, which would otherwise fall
    //    all the way through to the clean bill of health below. Absence of
    //    evidence is not health.
    if let Some(reason) = crate::platform::UNSUPPORTED_OS {
        return Verdict {
            status: Status::Skipped,
            headline: "Can't diagnose on this OS".into(),
            cause: reason.into(),
            fix: None,
            confidence: Confidence::Certain,
        };
    }

    // 1. Still probing — don't render a health claim from half the evidence.
    if path.hops.iter().any(|h| h.status == Status::Pending) {
        return Verdict {
            status: Status::Pending,
            headline: "Scanning your connection…".into(),
            cause: "Probing each hop from your Wi-Fi link out to the internet.".into(),
            fix: None,
            confidence: Confidence::Guess,
        };
    }

    // 2. A positively-detected captive portal wins over any upstream break it
    //    caused. Portals blackhole direct TCP to 1.1.1.1:443, so the WAN hop
    //    fails first in the chain — but "sign in to the Wi-Fi" is the real,
    //    actionable root cause, not "your ISP is down".
    if hop_status(path, HopId::Captive) == Status::Fail {
        return explain_break(path, HopId::Captive);
    }

    // 3. Otherwise the connection is broken somewhere: explain the *first*
    //    break, since everything downstream is just collateral.
    if let Some(broken) = path.first_break() {
        return explain_break(path, broken.id);
    }

    // 4. Nothing is broken — surface the worst degradation, if any.
    if let Some(warn) = path
        .hops
        .iter()
        .filter(|h| h.status == Status::Warn)
        .min_by_key(|h| h.id as usize)
    {
        return explain_warn(path, warn.id);
    }

    // 5. Clean bill of health.
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

/// Whether an active full-tunnel VPN is present — the tunnel that would make a
/// WAN failure the VPN's fault rather than the ISP's. Keyed off the `Mode`
/// metric the VPN probe records.
fn vpn_is_full_tunnel(path: &Path) -> bool {
    path.get(HopId::Vpn).is_some_and(|h| {
        h.metrics
            .iter()
            .any(|m| m.label == "Mode" && m.value == "full-tunnel")
    })
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
        HopId::Wan => {
            // A full-tunnel VPN carries *all* egress, so a dead tunnel looks
            // exactly like an ISP outage from the WAN probe's point of view.
            // Reframe the verdict instead of blaming the ISP outright.
            if vpn_is_full_tunnel(path) {
                (
                    "Internet is down — through your VPN",
                    "The router answers locally, but nothing beyond it is reachable. A full-tunnel VPN is active, so this is most likely the tunnel, not your ISP.".to_string(),
                    Some("Disconnect the VPN and re-test — if it comes back, the tunnel was the problem.".to_string()),
                    Confidence::Likely,
                )
            } else {
                (
                    "Your ISP / uplink is down",
                    "The router answers locally, but nothing beyond it is reachable — the break is between your router and the internet.".to_string(),
                    Some("Check the modem/ONU lights; this is usually an ISP or WAN-cable outage, not your Mac.".to_string()),
                    Confidence::Likely,
                )
            }
        }
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
        // Defensive: the VPN probe currently grades only Ok/Warn, so a VPN hop
        // is never itself the `first_break`. A full-tunnel VPN outage instead
        // surfaces through the `HopId::Wan` reframe above. Kept for exhaustive-
        // ness and in case the probe gains a hard-fail signal later.
        HopId::Vpn => (
            "Your VPN tunnel is down",
            "A VPN tunnel is present but isn't carrying traffic, so anything routed through it is cut off.".to_string(),
            Some("Reconnect or quit the VPN client, then re-test.".to_string()),
            Confidence::Likely,
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

/// Packet loss measured at a hop, when it's high enough to be the story rather
/// than background noise. Reads the structured field the probes record, so the
/// verdict never has to re-parse its own prose.
fn loss_at(path: &Path, id: HopId) -> Option<f64> {
    path.get(id)
        .and_then(|h| h.loss_pct)
        .filter(|l| *l >= LOSS_WARN_PCT)
}

fn explain_warn(path: &Path, id: HopId) -> Verdict {
    let summary = path
        .get(id)
        .and_then(|h| h.summary.clone())
        .unwrap_or_default();
    let (headline, cause, fix) = match id {
        HopId::Link => {
            // A marginal signal is only half the story; say what it's already
            // costing when the gateway burst shows the damage.
            let cost = loss_at(path, HopId::Gateway)
                .map(|l| format!(" It's already costing you {l:.0}% packet loss to the router."))
                .unwrap_or_default();
            (
                "Weak Wi-Fi signal",
                format!(
                    "You're online, but the link is marginal — {summary}.{cost} Expect stalls and retransmits."
                ),
                Some("Move closer to the AP or switch to 5 GHz.".to_string()),
            )
        }
        HopId::Gateway => match loss_at(path, HopId::Gateway) {
            Some(l) => {
                // Every hop is "up", so a checklist would call this healthy.
                // Strong signal plus lossy LAN rules distance out and points at
                // interference, congestion or the router itself.
                let signal = path
                    .get(HopId::Link)
                    .filter(|h| h.status == Status::Ok)
                    .and_then(|h| h.summary.clone())
                    .map(|s| format!(" The signal itself is fine ({s}), so this isn't distance."))
                    .unwrap_or_default();
                (
                    "Your local network is dropping packets",
                    format!(
                        "Every hop is technically up, but {l:.0}% of probes to your own router never came back.{signal} That alone stalls pages, calls and streams while everything still looks online."
                    ),
                    Some(
                        "Switch to 5 GHz or a quieter channel, move off a crowded band, and power-cycle the router if it persists.".to_string(),
                    ),
                )
            }
            // Degraded without qualifying loss means slow or jittery; the
            // hop's own summary already says which, so don't guess here.
            None => (
                "Your router is answering poorly",
                format!("The LAN works, but the hop to your own router is degraded — {summary}."),
                Some("Check for a saturated LAN or a router that needs a restart.".to_string()),
            ),
        },
        HopId::Wan => match loss_at(path, HopId::Wan) {
            Some(l) => {
                // Chain order means the gateway wasn't an earlier warning, so
                // in practice the LAN is always clean here and the loss starts
                // past your own kit — worth saying out loud. Guarded anyway so
                // a future gateway grade can't make the claim retroactively.
                let lan = if hop_status(path, HopId::Gateway) == Status::Ok {
                    " Your LAN is clean — the router answers every probe — so this starts past your own equipment."
                } else {
                    ""
                };
                (
                    "Your uplink is dropping packets",
                    format!(
                        "The internet is reachable, but {l:.0}% of connections through it never complete.{lan}"
                    ),
                    Some(
                        "Usually ISP congestion or a flaky modem/ONU — power-cycle the modem, and report persistent loss to your ISP.".to_string(),
                    ),
                )
            }
            None => (
                "Internet is up but degraded",
                format!("Reachable, but quality is poor — {summary}."),
                Some("Check for background traffic or a congested uplink.".to_string()),
            ),
        },
        HopId::Dns => (
            "DNS is slow",
            format!("Resolution works but is sluggish — {summary}."),
            Some("Try a faster resolver like 1.1.1.1.".to_string()),
        ),
        _ => ("Minor degradation", summary, None),
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

    /// A path of skipped hops has no break and no warning, so without the
    /// platform guard it reaches the clean bill of health and calls an OS wtfi
    /// cannot even probe "fully online". No-op on a supported OS.
    #[test]
    fn an_unsupported_os_is_never_called_healthy() {
        if crate::platform::UNSUPPORTED_OS.is_none() {
            return;
        }
        let v = diagnose(&Path::default());
        assert_eq!(v.status, Status::Skipped);
        assert_ne!(v.headline, "You're fully online");
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
    fn captive_portal_overrides_upstream_wan_fail() {
        // Portals blackhole TCP to 1.1.1.1, so WAN fails first in the chain —
        // but the portal is the real, actionable cause.
        let p = Path {
            hops: vec![
                hop(HopId::Link, Layer::Link, Status::Ok),
                hop(HopId::Gateway, Layer::Network, Status::Ok),
                hop(HopId::Wan, Layer::Internet, Status::Fail),
                hop(HopId::Dns, Layer::Application, Status::Skipped),
                hop(HopId::Captive, Layer::Application, Status::Fail),
            ],
        };
        let v = diagnose(&p);
        assert!(
            v.headline.to_lowercase().contains("portal"),
            "expected portal verdict, got: {}",
            v.headline
        );
    }

    #[test]
    fn full_tunnel_vpn_reframes_wan_outage() {
        use crate::model::Metric;
        let mut vpn = hop(HopId::Vpn, Layer::Network, Status::Ok);
        vpn.metrics.push(Metric::new("Mode", "full-tunnel"));
        let p = Path {
            hops: vec![
                hop(HopId::Link, Layer::Link, Status::Ok),
                hop(HopId::Gateway, Layer::Network, Status::Ok),
                vpn,
                hop(HopId::Wan, Layer::Internet, Status::Fail),
            ],
        };
        let v = diagnose(&p);
        assert!(
            v.headline.contains("VPN"),
            "full-tunnel VPN should own a WAN outage, got: {}",
            v.headline
        );
        assert!(v.fix.as_deref().unwrap().contains("Disconnect the VPN"));
    }

    #[test]
    fn split_tunnel_vpn_leaves_wan_outage_as_isp() {
        use crate::model::Metric;
        let mut vpn = hop(HopId::Vpn, Layer::Network, Status::Ok);
        vpn.metrics.push(Metric::new("Mode", "split-tunnel"));
        let p = Path {
            hops: vec![
                hop(HopId::Gateway, Layer::Network, Status::Ok),
                vpn,
                hop(HopId::Wan, Layer::Internet, Status::Fail),
            ],
        };
        // Split-tunnel doesn't carry the default route, so a WAN outage is
        // still the ISP's, not the tunnel's.
        assert!(diagnose(&p).headline.contains("ISP"));
    }

    fn lossy(id: HopId, layer: Layer, loss_pct: f64) -> Hop {
        let mut h = hop(id, layer, Status::Warn);
        h.loss_pct = Some(loss_pct);
        h
    }

    #[test]
    fn lossy_lan_is_diagnosed_even_though_every_hop_is_up() {
        // The whole point of measuring loss: nothing is broken, a checklist
        // would say "all good", but the network is unusable.
        let p = Path {
            hops: vec![
                hop(HopId::Link, Layer::Link, Status::Ok),
                lossy(HopId::Gateway, Layer::Network, 40.0),
                hop(HopId::Wan, Layer::Internet, Status::Ok),
                hop(HopId::Dns, Layer::Application, Status::Ok),
            ],
        };
        let v = diagnose(&p);
        assert_eq!(v.status, Status::Warn);
        assert!(
            v.headline.contains("dropping packets"),
            "expected a loss verdict, got: {}",
            v.headline
        );
        assert!(v.cause.contains("40%"), "cause must quote the loss");
    }

    #[test]
    fn strong_signal_with_lossy_lan_rules_out_distance() {
        // Full bars but unusable — the verdict must say the signal is fine so
        // the user stops walking towards the router.
        let mut link = hop(HopId::Link, Layer::Link, Status::Ok);
        link.summary = Some("Excellent · -45 dBm".into());
        let p = Path {
            hops: vec![link, lossy(HopId::Gateway, Layer::Network, 40.0)],
        };
        let v = diagnose(&p);
        assert!(v.cause.contains("-45 dBm"));
        assert!(v.cause.contains("isn't distance"));
    }

    #[test]
    fn weak_link_owns_the_verdict_but_quotes_the_loss_it_causes() {
        // Both hops warn; the link is earlier in the chain and is the cause,
        // while the gateway loss is the evidence of what it costs.
        let mut link = hop(HopId::Link, Layer::Link, Status::Warn);
        link.summary = Some("Weak · -82 dBm".into());
        let p = Path {
            hops: vec![link, lossy(HopId::Gateway, Layer::Network, 60.0)],
        };
        let v = diagnose(&p);
        assert!(v.headline.contains("Weak Wi-Fi"));
        assert!(
            v.cause.contains("60% packet loss"),
            "link verdict should quote the damage, got: {}",
            v.cause
        );
    }

    #[test]
    fn clean_lan_with_lossy_wan_blames_the_uplink() {
        let p = Path {
            hops: vec![
                hop(HopId::Link, Layer::Link, Status::Ok),
                hop(HopId::Gateway, Layer::Network, Status::Ok),
                lossy(HopId::Wan, Layer::Internet, 40.0),
                hop(HopId::Dns, Layer::Application, Status::Ok),
            ],
        };
        let v = diagnose(&p);
        assert!(
            v.headline.contains("uplink"),
            "expected an uplink verdict, got: {}",
            v.headline
        );
        assert!(v.cause.contains("LAN is clean"));
        assert!(v.fix.as_deref().unwrap().contains("ISP"));
    }

    #[test]
    fn loss_below_the_threshold_is_not_the_story() {
        // A single dropped echo is Wi-Fi noise. If a probe still grades the hop
        // as degraded, the verdict must fall back to the generic explanation
        // rather than claiming packet loss.
        let mut gw = hop(HopId::Gateway, Layer::Network, Status::Warn);
        gw.loss_pct = Some(LOSS_WARN_PCT - 5.0);
        gw.summary = Some("Router is sluggish — 120 ms round trip".into());
        let p = Path {
            hops: vec![hop(HopId::Link, Layer::Link, Status::Ok), gw],
        };
        let v = diagnose(&p);
        assert!(
            !v.headline.contains("dropping packets"),
            "sub-threshold loss must not be reported as loss, got: {}",
            v.headline
        );
        // The verdict defers to the hop's own summary rather than guessing.
        assert!(v.cause.contains("sluggish"));
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
