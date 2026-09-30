//! Parsing helpers and heuristics shared by every real [`super::Platform`].
//!
//! Whatever a platform reads its facts *with*, some conclusions are drawn the
//! same way: which address is only link-local, and which VPN a tunnel belongs
//! to. Keeping one copy means a vendor added for one OS reaches the others.

use std::net::IpAddr;

/// Parse an address token, dropping any `%zone` scope suffix (`fe80::1%utun4`).
pub(super) fn parse_addr(tok: &str) -> Option<IpAddr> {
    tok.split('%').next()?.parse().ok()
}

pub(super) fn is_link_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_link_local(),
        // fe80::/10 — the top 10 bits are 1111111010.
        IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) == 0xfe80,
    }
}

/// Best-effort vendor guess from a tunnel's local address. Tailscale hands out
/// addresses from the 100.64.0.0/10 CGNAT block, which is a strong signal on a
/// tunnel interface. Anything else stays unlabelled rather than guessing wrong.
pub(super) fn vendor_from_ip(ip: IpAddr) -> Option<&'static str> {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            (a == 100 && (64..=127).contains(&b)).then_some("Tailscale")
        }
        IpAddr::V6(_) => None,
    }
}

/// Map a running-process list (`ps -axo comm=`) to a known VPN vendor by its
/// background daemon. More specific vendors are listed before the generic
/// `wireguard`/`openvpn` engines they may be built on, so the first match wins
/// the right label (e.g. Mullvad-over-WireGuard reports as `Mullvad`).
pub(super) fn vendor_from_processes(ps: &str) -> Option<&'static str> {
    // (lowercase substring to find in a process path, vendor label).
    const CLIENTS: &[(&str, &str)] = &[
        ("tailscaled", "Tailscale"),
        ("warp-svc", "Cloudflare WARP"),
        ("cloudflarewarp", "Cloudflare WARP"),
        ("nordvpn", "NordVPN"),
        ("mullvad", "Mullvad"),
        ("protonvpn", "Proton VPN"),
        ("expressvpn", "ExpressVPN"),
        ("vpnagentd", "Cisco AnyConnect"),
        ("acwebsecagent", "Cisco AnyConnect"),
        ("pangps", "GlobalProtect"),
        ("openconnect", "OpenConnect"),
        ("wireguard", "WireGuard"),
        ("openvpn", "OpenVPN"),
    ];
    let low = ps.to_lowercase();
    CLIENTS
        .iter()
        .find(|(needle, _)| low.contains(needle))
        .map(|&(_, vendor)| vendor)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vendor_detects_tailscale_cgnat() {
        assert_eq!(
            vendor_from_ip("100.86.1.2".parse().unwrap()),
            Some("Tailscale")
        );
        // A plain private-range tunnel address stays unlabelled.
        assert_eq!(vendor_from_ip("10.8.0.2".parse().unwrap()), None);
    }

    #[test]
    fn vendor_detects_client_processes() {
        let ps = "/usr/sbin/cfprefsd\n\
                  /Applications/Mullvad VPN.app/Contents/Resources/mullvad-daemon\n\
                  /usr/libexec/wifid";
        assert_eq!(vendor_from_processes(ps), Some("Mullvad"));
        // A vendor with its own daemon wins over the generic engine it's built on.
        assert_eq!(
            vendor_from_processes("/usr/local/bin/tailscaled --state=/x"),
            Some("Tailscale")
        );
        assert_eq!(
            vendor_from_processes("/usr/sbin/openvpn --config x.ovpn"),
            Some("OpenVPN")
        );
        // No VPN client running → no label.
        assert_eq!(
            vendor_from_processes("/usr/sbin/bluetoothd\n/usr/libexec/nsurlsessiond"),
            None
        );
    }
}
