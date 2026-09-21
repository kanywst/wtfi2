//! Root-cause reasoning.
//!
//! The old wtfi printed a flat checklist and left the human to correlate it.
//! This engine walks the completed [`Path`], finds where connectivity actually
//! dies, and turns the surrounding evidence into a single plain verdict plus a
//! concrete fix — the thing you actually wanted to know.

use crate::model::{Fault, HopId, Path, Status};
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

    // 1. Nothing was measured: every hop skipped. Absence of evidence is not
    //    health, so this must not fall through to the clean bill below. The
    //    reason, when there is one, is whatever the Link hop recorded.
    //
    //    The host hop is exempt only while it is *not* a finding. It used to be
    //    a static "you exist" stub and so was excluded wholesale; now that it
    //    is a real measurement, a failed one has to own the verdict rather than
    //    be read as an absence of evidence.
    if path
        .hops
        .iter()
        .filter(|h| h.id != HopId::Host)
        .all(|h| h.status == Status::Skipped)
        && path.get(HopId::Host).is_none_or(|h| h.status <= Status::Ok)
    {
        return Verdict {
            status: Status::Skipped,
            headline: "Nothing was measured".into(),
            cause: path
                .get(HopId::Link)
                .and_then(|h| h.summary.clone())
                .unwrap_or_else(|| "No hop reported a result.".into()),
            fix: None,
            confidence: Confidence::Certain,
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

/// Whether the tunnel lookup failed, leaving us unable to say if a VPN is
/// carrying this traffic. Not the same as "there is no VPN", and the
/// difference decides whether an outage past the router can be pinned on the
/// ISP at all.
fn vpn_state_unknown(path: &Path) -> bool {
    path.get(HopId::Vpn)
        .is_some_and(|h| h.fault == Some(Fault::Unobserved))
}

/// What the TTL sweep actually saw, quoted into the verdict so the claim
/// carries its evidence rather than asking to be trusted.
fn uplink_evidence(path: &Path) -> String {
    path.get(HopId::Uplink)
        .and_then(|h| h.summary.clone())
        .unwrap_or_default()
}

fn explain_break(path: &Path, id: HopId) -> Verdict {
    // The probe already decided *what* went wrong; this only turns the code
    // into prose. Re-deriving the cause here is how the verdict used to
    // contradict the evidence printed underneath it.
    let fault = path.get(id).and_then(|h| h.fault);
    let (headline, cause, fix, confidence) = match (id, fault) {
        (HopId::Link, Some(Fault::NoRoute)) => (
            "No route off this machine",
            "The Wi-Fi link is up, but there's no default route — so nothing can leave this Mac. That is almost always a DHCP lease that never arrived, not a signal problem.".to_string(),
            Some("Renew the DHCP lease (System Settings → Network → Details → TCP/IP → Renew DHCP Lease), or rejoin the network.".to_string()),
            Confidence::Likely,
        ),
        (HopId::Link, _) => (
            "Wi-Fi link is down",
            "Your machine isn't associated with an access point. There's no L2 link to diagnose above.".to_string(),
            Some("Toggle Wi-Fi off/on, or pick a network in the Wi-Fi menu.".to_string()),
            Confidence::Certain,
        ),
        // The routing table has no gateway at all — there is no router to
        // blame for not answering, because nothing was ever asked.
        (HopId::Gateway, Some(Fault::NoGateway)) => (
            "You have no default gateway",
            "The link is up and you have an address, but the routing table has no gateway — so traffic has nowhere to go even inside your own house.".to_string(),
            Some("Renew the DHCP lease, or check for a static IP configured without a router address.".to_string()),
            Confidence::Certain,
        ),
        (HopId::Gateway, _) => {
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
        // The sweep located the break, so the verdict stops guessing. These
        // sit before the WAN arm in the chain, so `first_break` reaches them
        // first and the vaguer "something past your router" never runs.
        // A full-tunnel VPN owns the default route, so the sweep traces
        // *through the tunnel*: "hop 1 = your own router" is only true over
        // the physical WAN. Without this the Uplink arms would tell you to
        // check your modem, or report an outage to your ISP, for a tunnel
        // whose own upstream degraded — and because Uplink precedes Wan in the
        // chain, the Wan arm's existing VPN reframe never gets to run.
        (HopId::Uplink, _) if vpn_is_full_tunnel(path) => (
            "The path through your VPN breaks upstream",
            format!("{} But a full-tunnel VPN owns your default route, so this traced through the tunnel, not your own line — the hops named are the tunnel's path, not your ISP's.", uplink_evidence(path)),
            Some("Disconnect the VPN and re-run. If the path comes back, the tunnel was the problem — your own line and your ISP aren't involved.".to_string()),
            Confidence::Likely,
        ),
        // Same hedge the Wan arm makes, for the same reason. The VPN probe and
        // the WAN failure are independent events, so both can time out in one
        // run — and `vpn_is_full_tunnel` needs a `Mode` metric that an
        // unmeasured VPN hop doesn't have. Without this the verdict says
        // "report the outage to your ISP" at `Likely` for a trace that may
        // have gone through a dead tunnel still owning the default route, and
        // because `Uplink` precedes `Wan` the Wan arm's own hedge never runs.
        (HopId::Uplink, _) if vpn_state_unknown(path) => (
            "The path past your router breaks, but a VPN may be in the way",
            format!("{} wtfi couldn't read whether a VPN is carrying your traffic, and a tunnel that owns the default route would have been traced instead of your own line — so the hops named may not be your ISP's at all.", uplink_evidence(path)),
            Some("If you're on a VPN, disconnect it and re-run before reporting anything to your ISP.".to_string()),
            Confidence::Guess,
        ),
        (HopId::Uplink, Some(Fault::UplinkDiesAtModem)) => (
            "The break is on your line, not inside your ISP",
            format!("Your router answers, but nothing past it does — and the trace stops at the very first step outside your house. {} That points at the modem/ONU, the WAN cable, or the line itself rather than at your provider's network.", uplink_evidence(path)),
            Some("Check the modem/ONU lights and reseat the WAN cable. If the lights say the line is down, that is what to report.".to_string()),
            Confidence::Likely,
        ),
        (HopId::Uplink, Some(Fault::UplinkDiesInIsp)) => (
            "The break is inside your ISP's network",
            format!("Your equipment is forwarding fine — the trace gets out of your house and then stops. {} Nothing you own is between you and that point.", uplink_evidence(path)),
            Some("Not your Mac and not your router. Report the outage to your ISP and quote the last hop that answered, from the Uplink detail below.".to_string()),
            Confidence::Likely,
        ),
        (HopId::Uplink, _) => (
            "The path past your router is broken",
            uplink_evidence(path),
            None,
            Confidence::Guess,
        ),
        (HopId::Wan, _) => {
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
            } else if vpn_state_unknown(path) {
                // We couldn't read the tunnel state, and a dead full-tunnel
                // VPN is indistinguishable from an ISP outage from here. Name
                // both rather than picking the one we can't rule out.
                (
                    "Nothing past your router is reachable",
                    "The router answers locally but nothing beyond it does. wtfi couldn't read whether a VPN is carrying your traffic, and a dead full-tunnel VPN looks exactly like this — so the ISP is not the only candidate.".to_string(),
                    Some("If you're on a VPN, disconnect it and re-test. If not, check the modem/ONU lights.".to_string()),
                    Confidence::Guess,
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
        // Resolution succeeds — it just lies. Reporting that as "name
        // resolution is failing … a classic DNS-only outage" describes the
        // opposite symptom, and sends the reader chasing an outage that isn't
        // happening while the interception goes unmentioned.
        (HopId::Dns, Some(Fault::ResolverHijacked)) => (
            "Your DNS answers are being substituted",
            "Name resolution works, but your resolver returns a private address for a public name — something on this network is redirecting your traffic to itself.".to_string(),
            Some("If this is a hotel or public network, sign in first. Otherwise set your resolver to 1.1.1.1 or 8.8.8.8 and re-test.".to_string()),
            Confidence::Likely,
        ),
        (HopId::Dns, _) => {
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
        (HopId::Captive, _) => (
            "A captive portal is blocking you",
            "DNS and routing work, but a hotspot login page is intercepting your traffic — you're not really online yet.".to_string(),
            Some("Open http://captive.apple.com in a browser and sign in.".to_string()),
            Confidence::Certain,
        ),
        // Defensive: the VPN probe currently grades only Ok/Warn, so a VPN hop
        // is never itself the `first_break`. A full-tunnel VPN outage instead
        // surfaces through the `HopId::Wan` reframe above. Kept for exhaustive-
        // ness and in case the probe gains a hard-fail signal later.
        (HopId::Vpn, _) => (
            "Your VPN tunnel is down",
            "A VPN tunnel is present but isn't carrying traffic, so anything routed through it is cut off.".to_string(),
            Some("Reconnect or quit the VPN client, then re-test.".to_string()),
            Confidence::Likely,
        ),
        // DHCP never answered, so macOS autoconfigured. Every hop downstream
        // will fail too, but they are all collateral: nothing can be reached
        // from an address nothing else shares.
        (HopId::Host, Some(Fault::SelfAssignedAddr)) => (
            "DHCP never gave you an address",
            "Your Mac fell back to a self-assigned 169.254 address, which can't reach anything beyond this machine. The Wi-Fi link is fine; the lease is what's missing.".to_string(),
            Some("Renew the DHCP lease (System Settings → Network → Details → TCP/IP → Renew DHCP Lease). If that fails, the router's DHCP server is the problem, not your Mac.".to_string()),
            Confidence::Certain,
        ),
        (HopId::Host, Some(Fault::NoAddress)) => (
            "This machine has no IP address",
            "The interface is up but unconfigured — no IPv4 lease and no routable IPv6.".to_string(),
            Some("Renew the DHCP lease, or check for a static configuration that was left half-filled.".to_string()),
            Confidence::Certain,
        ),
        (HopId::Host, Some(Fault::GatewayOffSubnet)) => (
            "Your address and your router don't match",
            "Your machine and its default gateway are configured on different subnets, so they can't reach each other at all — the router will look unresponsive because nothing you send can arrive.".to_string(),
            Some("Renew the DHCP lease, or clear a static IP left over from a different network.".to_string()),
            Confidence::Certain,
        ),
        (HopId::Host, _) => (
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

    // A hop we failed to measure is unknown, not degraded. Falling through to
    // the arms below would dress a wedged probe up as a diagnosis — "DNS is
    // slow" for a resolver that was never successfully timed.
    if path.get(id).and_then(|h| h.fault) == Some(Fault::Unobserved) {
        // Count them rather than asserting everything else reported. A
        // sweep-level deadline takes several hops down at once, and only the
        // earliest one reaches this arm — so claiming the rest checked in
        // would contradict the detail panel printed right underneath.
        let unmeasured: Vec<&str> = path
            .hops
            .iter()
            .filter(|h| h.fault == Some(Fault::Unobserved))
            .map(|h| h.title.as_str())
            .collect();
        let scope = match unmeasured.len() {
            0 | 1 => "The rest of the path reported, so this hop is unknown rather than unhealthy — don't read it either way.".to_string(),
            n => format!(
                "{n} hops went unmeasured ({}), so this is a gap in the evidence rather than a finding about your network.",
                unmeasured.join(", ")
            ),
        };
        return Verdict {
            status: Status::Warn,
            headline: "Part of the path couldn't be measured".into(),
            cause: format!("{summary}. {scope}"),
            fix: Some(
                "Re-run wtfi. If it keeps timing out, the OS tool that probe depends on is wedged."
                    .into(),
            ),
            confidence: Confidence::Certain,
        };
    }

    // Hops other than the one being explained may also have gone unmeasured.
    // `diagnose` only ever hands over the earliest Warn hop, so without this
    // the headline would describe a genuine degradation while silently
    // dropping the fact that part of the path was never looked at — the same
    // headline/detail contradiction as the branch above, in the omission
    // direction.
    let elsewhere: Vec<&str> = path
        .hops
        .iter()
        .filter(|h| h.id != id && h.fault == Some(Fault::Unobserved))
        .map(|h| h.title.as_str())
        .collect();
    let gap = if elsewhere.is_empty() {
        String::new()
    } else {
        format!(
            " Separately, {} went unmeasured, so this verdict doesn't account for {}.",
            elsewhere.join(" and "),
            if elsewhere.len() == 1 { "it" } else { "them" }
        )
    };

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
        // Every hop is green and nothing works — the exact failure a topology
        // diagram cannot show you, so the verdict has to say it in words.
        // Ahead of both arms below: "the path carries nothing" outranks "the
        // path is lossy" and "the path is filtered".
        HopId::Wan if path.get(id).and_then(|h| h.fault) == Some(Fault::HandshakeOnly) => (
            "Something is answering for the internet",
            "Every connection completes, but no real request does. A device on the path is replying to handshakes without carrying the traffic — an interception appliance, a misbehaving proxy, or a portal you haven't signed in to.".to_string(),
            Some("If this is a hotel or public network, open a browser and look for a sign-in page. Otherwise check for a proxy or filtering appliance between you and the internet.".to_string()),
        ),
        // Filtered egress is a property of the network you're on, not a
        // quality problem with your connection. Without this arm the headline
        // feature of the multi-operator probe never reached the verdict: it
        // fell through to "Internet is up but degraded ... check for
        // background traffic", the wrong complaint with the wrong remedy.
        HopId::Wan if path.get(id).and_then(|h| h.fault) == Some(Fault::TargetBlocked) => (
            "This network filters where you can go",
            format!("{summary}. Your uplink itself is fine — it reaches the internet, just not everything on it."),
            Some("Expected on corporate or guest Wi-Fi. If it isn't, check for a filtering appliance or a DNS/firewall policy on the router.".to_string()),
        ),
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
        // Synthesised NXDOMAIN. The hop's own summary says "invents answers";
        // the headline used to say "DNS is slow", which is a different
        // complaint about a resolver that may well be fast.
        HopId::Dns if path.get(id).and_then(|h| h.fault) == Some(Fault::ResolverHijacked) => (
            "Your resolver invents answers",
            format!("{summary}. Nothing is down, but anything relying on a name genuinely not existing — VPN split-horizon checks, some installers, search fallbacks — will misbehave."),
            Some("Set your resolver to 1.1.1.1 or 9.9.9.9 if the redirection gets in your way.".to_string()),
        ),
        HopId::Dns => (
            "DNS is slow",
            format!("Resolution works but is sluggish — {summary}."),
            Some("Try a faster resolver like 1.1.1.1.".to_string()),
        ),
        HopId::Host => (
            "Your addressing is off",
            summary.clone(),
            Some("Check the interface's IP configuration — a static address left over from another network does this.".to_string()),
        ),
        _ => ("Minor degradation", summary, None),
    };
    Verdict {
        status: Status::Warn,
        headline: headline.to_string(),
        cause: format!("{cause}{gap}"),
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

    /// A chain where nothing ran has no break and no warning, so without the
    /// guard it reaches the clean bill of health and calls a connection that
    /// was never measured "fully online".
    #[test]
    fn a_chain_that_never_ran_is_not_called_healthy() {
        let mut link = hop(HopId::Link, Layer::Link, Status::Skipped);
        link.summary = Some("no platform module for this OS".into());
        let p = Path {
            hops: vec![
                hop(HopId::Host, Layer::Link, Status::Ok),
                link,
                hop(HopId::Gateway, Layer::Network, Status::Skipped),
                hop(HopId::Wan, Layer::Internet, Status::Skipped),
                hop(HopId::Dns, Layer::Application, Status::Skipped),
                hop(HopId::Captive, Layer::Application, Status::Skipped),
            ],
        };
        let v = diagnose(&p);
        assert_eq!(v.status, Status::Skipped);
        assert_ne!(v.headline, "You're fully online");
        // The reason travels from the hop that recorded it, not from a second
        // copy of the platform check living in here.
        assert!(v.cause.contains("no platform module"));
    }

    /// The regression this whole `Fault` mechanism exists for: the engine
    /// records "no default route", and the verdict used to answer "you aren't
    /// associated with an access point" — a different fault, with a fix
    /// (toggle Wi-Fi) that does nothing for a missing DHCP lease.
    #[test]
    fn a_missing_route_is_not_reported_as_a_dead_wifi_link() {
        let mut link = hop(HopId::Link, Layer::Link, Status::Fail);
        link.fault = Some(Fault::NoRoute);
        let p = Path {
            hops: vec![link, hop(HopId::Gateway, Layer::Network, Status::Skipped)],
        };
        let v = diagnose(&p);
        assert!(
            !v.headline.contains("link is down"),
            "a routing fault must not be announced as a link fault, got: {}",
            v.headline
        );
        assert!(v.cause.contains("DHCP"), "got: {}", v.cause);
        assert!(v.fix.as_deref().unwrap().contains("DHCP"));
    }

    /// The other side of the same coin: a genuinely disassociated link keeps
    /// the link verdict.
    #[test]
    fn a_disassociated_link_still_reads_as_a_dead_link() {
        let mut link = hop(HopId::Link, Layer::Link, Status::Fail);
        link.fault = Some(Fault::NotAssociated);
        let p = Path { hops: vec![link] };
        let v = diagnose(&p);
        assert!(v.headline.contains("Wi-Fi link is down"), "{}", v.headline);
    }

    /// "The table has no gateway" and "the gateway won't answer" are different
    /// faults: one has nothing to ping, the other pinged and got silence.
    #[test]
    fn a_missing_gateway_is_not_reported_as_a_silent_router() {
        let mut gw = hop(HopId::Gateway, Layer::Network, Status::Fail);
        gw.fault = Some(Fault::NoGateway);
        let p = Path {
            hops: vec![hop(HopId::Link, Layer::Link, Status::Ok), gw],
        };
        let v = diagnose(&p);
        assert!(v.headline.contains("no default gateway"), "{}", v.headline);
        assert!(
            !v.cause.contains("answering pings"),
            "nothing was pinged, so don't claim it: {}",
            v.cause
        );
    }

    /// A `scutil` that wouldn't run used to leave the VPN hop absent, which
    /// reads as "no VPN" — and that is the only thing standing between a dead
    /// full-tunnel VPN and a verdict blaming the ISP for it.
    #[test]
    fn an_unreadable_tunnel_stops_the_isp_being_blamed_outright() {
        let mut vpn = hop(HopId::Vpn, Layer::Network, Status::Warn);
        vpn.fault = Some(Fault::Unobserved);
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
            !v.headline.contains("ISP"),
            "the ISP can't be named while the tunnel is unreadable: {}",
            v.headline
        );
        assert_eq!(v.confidence, Confidence::Guess);
        assert!(v.fix.as_deref().unwrap().contains("VPN"));
    }

    /// …but a readable, absent VPN still lets the ISP verdict stand.
    #[test]
    fn a_readable_absence_of_vpn_leaves_the_isp_verdict_intact() {
        let p = Path {
            hops: vec![
                hop(HopId::Gateway, Layer::Network, Status::Ok),
                hop(HopId::Wan, Layer::Internet, Status::Fail),
            ],
        };
        assert!(diagnose(&p).headline.contains("ISP"));
    }

    /// A probe that overran its deadline observed nothing. Reporting that as
    /// "DNS is slow" would be a diagnosis invented out of a missing
    /// measurement — the exact failure mode `Fault` exists to prevent.
    #[test]
    fn an_unmeasured_hop_is_not_reported_as_a_degraded_one() {
        let mut dns = hop(HopId::Dns, Layer::Application, Status::Warn);
        dns.fault = Some(Fault::Unobserved);
        dns.summary = Some("The DNS probe didn't finish".into());
        let p = Path {
            hops: vec![
                hop(HopId::Link, Layer::Link, Status::Ok),
                hop(HopId::Gateway, Layer::Network, Status::Ok),
                hop(HopId::Wan, Layer::Internet, Status::Ok),
                dns,
            ],
        };
        let v = diagnose(&p);
        assert_eq!(v.status, Status::Warn);
        assert!(
            !v.headline.contains("slow"),
            "an unmeasured resolver was never timed, so don't call it slow: {}",
            v.headline
        );
        assert!(v.cause.contains("unknown rather than unhealthy"));
    }

    /// A sweep-level deadline takes several hops down at once, but only the
    /// earliest reaches `explain_warn`. Claiming "the rest reported" would put
    /// a false statement in the headline, contradicting the detail panel
    /// printed right underneath it.
    #[test]
    fn several_unmeasured_hops_are_counted_not_waved_away() {
        let mut hops = Vec::new();
        for id in [HopId::Link, HopId::Gateway, HopId::Wan] {
            let mut h = hop(id, Layer::Internet, Status::Warn);
            h.fault = Some(Fault::Unobserved);
            h.summary = Some("The sweep ended before this hop reported".into());
            hops.push(h);
        }
        let v = diagnose(&Path { hops });
        assert!(
            v.cause.contains("3 hops went unmeasured"),
            "got: {}",
            v.cause
        );
        assert!(
            !v.cause.contains("rest of the path reported"),
            "must not claim hops reported when they did not: {}",
            v.cause
        );
    }

    /// With a single gap the original wording is accurate, and keeping it
    /// avoids "1 hops went unmeasured".
    #[test]
    fn a_lone_unmeasured_hop_still_says_the_rest_reported() {
        let mut dns = hop(HopId::Dns, Layer::Application, Status::Warn);
        dns.fault = Some(Fault::Unobserved);
        dns.summary = Some("The DNS probe didn't finish".into());
        let p = Path {
            hops: vec![
                hop(HopId::Link, Layer::Link, Status::Ok),
                hop(HopId::Gateway, Layer::Network, Status::Ok),
                dns,
            ],
        };
        assert!(diagnose(&p).cause.contains("rest of the path reported"));
    }

    /// `diagnose` only hands `explain_warn` the earliest Warn hop, so an
    /// unmeasured hop further along used to vanish from the headline entirely
    /// while still showing as unmeasured in the detail panel below. Same
    /// headline/detail contradiction, in the omission direction.
    #[test]
    fn a_degraded_hop_still_reports_a_gap_further_along() {
        let mut link = hop(HopId::Link, Layer::Link, Status::Warn);
        link.summary = Some("Weak · -82 dBm".into());
        let mut dns = hop(HopId::Dns, Layer::Application, Status::Warn);
        dns.fault = Some(Fault::Unobserved);
        let p = Path {
            hops: vec![link, hop(HopId::Gateway, Layer::Network, Status::Ok), dns],
        };
        let v = diagnose(&p);
        assert!(v.headline.contains("Weak Wi-Fi"), "got: {}", v.headline);
        assert!(v.cause.contains("went unmeasured"), "got: {}", v.cause);
    }

    /// With nothing unmeasured the cause stays clean — no trailing clause.
    #[test]
    fn a_fully_measured_path_adds_no_gap_note() {
        let mut link = hop(HopId::Link, Layer::Link, Status::Warn);
        link.summary = Some("Weak · -82 dBm".into());
        let p = Path {
            hops: vec![link, hop(HopId::Gateway, Layer::Network, Status::Ok)],
        };
        assert!(!diagnose(&p).cause.contains("went unmeasured"));
    }

    /// A lease that never arrived is a break at the *host*, earlier in the
    /// chain than anything downstream. Before the host hop measured anything,
    /// this network read as "your router isn't responding" — sending you to
    /// reboot a router that was answering everyone else just fine.
    #[test]
    fn a_self_assigned_address_owns_the_verdict_over_the_router() {
        let mut host = hop(HopId::Host, Layer::Link, Status::Fail);
        host.fault = Some(Fault::SelfAssignedAddr);
        let p = Path {
            hops: vec![
                host,
                hop(HopId::Link, Layer::Link, Status::Ok),
                hop(HopId::Gateway, Layer::Network, Status::Fail),
                hop(HopId::Wan, Layer::Internet, Status::Fail),
            ],
        };
        let v = diagnose(&p);
        assert!(v.headline.contains("DHCP"), "got: {}", v.headline);
        assert!(!v.headline.contains("router"), "got: {}", v.headline);
        assert_eq!(v.confidence, Confidence::Certain);
    }

    /// The host hop is a real measurement now, so a failed one must not be
    /// swallowed by the "nothing was measured" guard that used to exempt it.
    #[test]
    fn a_failed_host_hop_is_not_read_as_an_absence_of_evidence() {
        let mut host = hop(HopId::Host, Layer::Link, Status::Fail);
        host.fault = Some(Fault::NoAddress);
        let p = Path {
            hops: vec![
                host,
                hop(HopId::Link, Layer::Link, Status::Skipped),
                hop(HopId::Gateway, Layer::Network, Status::Skipped),
            ],
        };
        let v = diagnose(&p);
        assert_eq!(v.status, Status::Fail);
        assert_ne!(v.headline, "Nothing was measured");
    }

    /// …while a healthy host hop still lets that guard do its job.
    #[test]
    fn a_healthy_host_hop_does_not_block_the_nothing_measured_verdict() {
        let p = Path {
            hops: vec![
                hop(HopId::Host, Layer::Link, Status::Ok),
                hop(HopId::Link, Layer::Link, Status::Skipped),
                hop(HopId::Gateway, Layer::Network, Status::Skipped),
            ],
        };
        assert_eq!(diagnose(&p).headline, "Nothing was measured");
    }

    /// The gateway's own probe fails as collateral here, and its arm says
    /// "reboot the router" at `Likely` — while the host hop already holds the
    /// certain, specific cause. `Host` sorts before `Gateway`, so grading this
    /// as a break is what lets the right evidence win.
    #[test]
    fn a_gateway_off_subnet_beats_the_routers_collateral_failure() {
        let mut host = hop(HopId::Host, Layer::Link, Status::Fail);
        host.fault = Some(Fault::GatewayOffSubnet);
        let mut gw = hop(HopId::Gateway, Layer::Network, Status::Fail);
        gw.fault = Some(Fault::GatewaySilent);
        let p = Path {
            hops: vec![host, hop(HopId::Link, Layer::Link, Status::Ok), gw],
        };
        let v = diagnose(&p);
        assert!(v.headline.contains("don't match"), "got: {}", v.headline);
        assert!(
            !v.fix.as_deref().unwrap().contains("Reboot"),
            "the router is fine; it just can't be reached"
        );
        assert_eq!(v.confidence, Confidence::Certain);
    }

    /// A hijacked resolver *answers* — it just lies. Reporting that as "name
    /// resolution is failing … a classic DNS-only outage" describes the
    /// opposite symptom and never mentions the interception the hop detected.
    #[test]
    fn a_hijacked_resolver_is_not_reported_as_an_outage() {
        let mut dns = hop(HopId::Dns, Layer::Application, Status::Fail);
        dns.fault = Some(Fault::ResolverHijacked);
        let p = Path {
            hops: vec![
                hop(HopId::Gateway, Layer::Network, Status::Ok),
                hop(HopId::Wan, Layer::Internet, Status::Ok),
                dns,
            ],
        };
        let v = diagnose(&p);
        assert!(v.headline.contains("substituted"), "got: {}", v.headline);
        assert!(!v.cause.contains("resolution fails"), "got: {}", v.cause);
    }

    /// And the Warn side: synthesised NXDOMAIN is dishonesty, not slowness.
    #[test]
    fn nxdomain_hijacking_is_not_reported_as_slowness() {
        let mut dns = hop(HopId::Dns, Layer::Application, Status::Warn);
        dns.fault = Some(Fault::ResolverHijacked);
        dns.summary = Some("Your resolver invents answers for names that don't exist".into());
        let p = Path {
            hops: vec![
                hop(HopId::Gateway, Layer::Network, Status::Ok),
                hop(HopId::Wan, Layer::Internet, Status::Ok),
                dns,
            ],
        };
        let v = diagnose(&p);
        assert!(
            v.headline.contains("invents answers"),
            "got: {}",
            v.headline
        );
        assert!(!v.headline.contains("slow"), "got: {}", v.headline);
    }

    /// The headline feature of the multi-operator probe has to reach the
    /// verdict. Without its own arm it fell through to "Internet is up but
    /// degraded … check for background traffic" — the wrong complaint, with a
    /// remedy that does nothing about filtered egress.
    #[test]
    fn a_filtered_target_gets_its_own_verdict() {
        let mut wan = hop(HopId::Wan, Layer::Internet, Status::Warn);
        wan.fault = Some(Fault::TargetBlocked);
        wan.summary =
            Some("Reachable via Google (12 ms), but this network blocks Cloudflare".into());
        let p = Path {
            hops: vec![
                hop(HopId::Gateway, Layer::Network, Status::Ok),
                wan,
                hop(HopId::Dns, Layer::Application, Status::Ok),
            ],
        };
        let v = diagnose(&p);
        assert!(v.headline.contains("filters"), "got: {}", v.headline);
        assert!(v.cause.contains("Cloudflare"), "got: {}", v.cause);
        assert!(
            !v.fix.as_deref().unwrap().contains("background traffic"),
            "filtered egress is not a congestion problem"
        );
    }

    /// Every hop green and nothing working is the one failure the topology
    /// diagram cannot show, so the verdict has to say it in words — and it has
    /// to outrank the lossy-uplink arm, because a path that carries nothing is
    /// worse news than a path that carries most things.
    #[test]
    fn a_path_that_only_answers_handshakes_is_named_as_such() {
        let mut wan = hop(HopId::Wan, Layer::Internet, Status::Warn);
        wan.fault = Some(Fault::HandshakeOnly);
        wan.loss_pct = Some(40.0);
        let p = Path {
            hops: vec![
                hop(HopId::Host, Layer::Link, Status::Ok),
                hop(HopId::Link, Layer::Link, Status::Ok),
                hop(HopId::Gateway, Layer::Network, Status::Ok),
                wan,
            ],
        };
        let v = diagnose(&p);
        assert!(
            v.headline.contains("answering for the internet"),
            "{}",
            v.headline
        );
        assert!(!v.headline.contains("dropping packets"), "{}", v.headline);
        assert!(v.fix.as_deref().unwrap().contains("sign-in page"));
    }

    /// The verdict this whole hop exists to replace. "Your ISP / uplink is
    /// down — check the modem lights" is the part the reader already knew;
    /// once the sweep has located the break, the verdict has to use it.
    #[test]
    fn a_located_break_replaces_the_vague_isp_verdict() {
        let mut uplink = hop(HopId::Uplink, Layer::Internet, Status::Fail);
        uplink.fault = Some(Fault::UplinkDiesInIsp);
        uplink.summary = Some(
            "Dies past hop 2 — the last reply came from 203.0.113.1, then 4 hops of silence".into(),
        );
        let p = Path {
            hops: vec![
                hop(HopId::Host, Layer::Link, Status::Ok),
                hop(HopId::Link, Layer::Link, Status::Ok),
                hop(HopId::Gateway, Layer::Network, Status::Ok),
                uplink,
                hop(HopId::Wan, Layer::Internet, Status::Fail),
            ],
        };
        let v = diagnose(&p);
        assert!(
            v.headline.contains("inside your ISP"),
            "got: {}",
            v.headline
        );
        assert!(
            !v.headline.contains("uplink is down"),
            "got: {}",
            v.headline
        );
        // The claim has to carry its evidence, not ask to be trusted.
        assert!(v.cause.contains("203.0.113.1"), "got: {}", v.cause);
    }

    /// Dying at the first step outside the house is a different call to make
    /// than dying inside the provider's network — one is your modem, the
    /// other is theirs.
    #[test]
    fn a_break_at_the_modem_gets_its_own_verdict() {
        let mut uplink = hop(HopId::Uplink, Layer::Internet, Status::Fail);
        uplink.fault = Some(Fault::UplinkDiesAtModem);
        uplink.summary = Some("Dies immediately past your router".into());
        let p = Path {
            hops: vec![
                hop(HopId::Gateway, Layer::Network, Status::Ok),
                uplink,
                hop(HopId::Wan, Layer::Internet, Status::Fail),
            ],
        };
        let v = diagnose(&p);
        assert!(v.headline.contains("on your line"), "got: {}", v.headline);
        assert!(v.fix.as_deref().unwrap().contains("modem"));
    }

    /// The sweep sits before the WAN hop in the chain, so `first_break` must
    /// reach it first — that ordering is what makes the located verdict win.
    #[test]
    fn the_uplink_hop_precedes_the_wan_hop_in_the_chain() {
        assert!((HopId::Uplink as usize) < (HopId::Wan as usize));
        assert!((HopId::Gateway as usize) < (HopId::Uplink as usize));
    }

    /// The Wan arm has checked `vpn_is_full_tunnel` since the VPN hop landed,
    /// but Uplink sits *before* Wan in the chain, so `first_break` reaches it
    /// first and that reframe never runs. The sweep traces over whatever owns
    /// the default route — the tunnel — so "hop 1 is your own router" is
    /// simply untrue, and the verdict would send you to your modem or your
    /// ISP for a VPN fault.
    #[test]
    fn a_full_tunnel_vpn_reframes_the_uplink_verdict_too() {
        let mut vpn = hop(HopId::Vpn, Layer::Network, Status::Ok);
        vpn.metrics
            .push(crate::model::Metric::new("Mode", "full-tunnel"));
        let mut uplink = hop(HopId::Uplink, Layer::Internet, Status::Fail);
        uplink.fault = Some(Fault::UplinkDiesInIsp);
        uplink.summary = Some("Dies past hop 2 — the last reply came from 100.64.0.1".into());
        let p = Path {
            hops: vec![
                hop(HopId::Gateway, Layer::Network, Status::Ok),
                vpn,
                uplink,
                hop(HopId::Wan, Layer::Internet, Status::Fail),
            ],
        };
        let v = diagnose(&p);
        assert!(v.headline.contains("VPN"), "got: {}", v.headline);
        assert!(
            !v.fix.as_deref().unwrap().contains("modem"),
            "a VPN fault must not send the reader to their modem"
        );
        assert!(v.cause.contains("through the tunnel"), "got: {}", v.cause);
    }

    /// A split-tunnel VPN does not own the default route, so the sweep really
    /// did trace your own line and the located verdict stands.
    #[test]
    fn a_split_tunnel_vpn_leaves_the_uplink_verdict_alone() {
        let mut vpn = hop(HopId::Vpn, Layer::Network, Status::Ok);
        vpn.metrics
            .push(crate::model::Metric::new("Mode", "split-tunnel"));
        let mut uplink = hop(HopId::Uplink, Layer::Internet, Status::Fail);
        uplink.fault = Some(Fault::UplinkDiesInIsp);
        uplink.summary = Some("Dies past hop 2".into());
        let p = Path {
            hops: vec![hop(HopId::Gateway, Layer::Network, Status::Ok), vpn, uplink],
        };
        assert!(diagnose(&p).headline.contains("inside your ISP"));
    }

    /// The VPN probe and the WAN failure are independent events, so both can
    /// time out in one run. `vpn_is_full_tunnel` needs a `Mode` metric an
    /// unmeasured VPN hop doesn't have, so without a hedge the verdict says
    /// "report the outage to your ISP" at `Likely` for a trace that may have
    /// gone through a dead tunnel — and `Uplink` preceding `Wan` means that
    /// arm's own hedge never gets to run.
    #[test]
    fn an_unknown_vpn_state_hedges_the_uplink_verdict_too() {
        let mut vpn = hop(HopId::Vpn, Layer::Network, Status::Warn);
        vpn.fault = Some(Fault::Unobserved);
        let mut uplink = hop(HopId::Uplink, Layer::Internet, Status::Fail);
        uplink.fault = Some(Fault::UplinkDiesInIsp);
        uplink.summary = Some("Dies past hop 2.".into());
        let p = Path {
            hops: vec![
                hop(HopId::Gateway, Layer::Network, Status::Ok),
                vpn,
                uplink,
                hop(HopId::Wan, Layer::Internet, Status::Fail),
            ],
        };
        let v = diagnose(&p);
        assert_eq!(v.confidence, Confidence::Guess);
        assert!(
            !v.fix.as_deref().unwrap().contains("Report the outage"),
            "don't send the reader to their ISP on an unread tunnel: {:?}",
            v.fix
        );
        assert!(v.cause.contains("may not be your ISP"), "got: {}", v.cause);
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
