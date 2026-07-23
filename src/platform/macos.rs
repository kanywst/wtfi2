//! macOS platform implementation.
//!
//! Gathers facts from first-party read-only tools that work **without sudo** on
//! macOS 26 (Tahoe):
//!
//! - `route -n get default` — gateway, interface, MTU
//! - `system_profiler SPAirPortDataType` — RSSI, noise, channel, PHY, security
//! - `scutil --dns` — configured resolvers
//!
//! Note: since macOS 14 the OS redacts SSID/BSSID unless the calling app holds
//! Location permission, so those fields are best-effort. RSSI/noise are not
//! redacted, which is what actually matters for signal diagnosis.

use super::{LinkInfo, Platform, PlatformError, ResolverInfo, RouteInfo, VpnInfo};
use std::net::IpAddr;
use std::process::Command;

pub struct MacOs;

impl MacOs {
    pub fn new() -> Self {
        MacOs
    }
}

impl Default for MacOs {
    fn default() -> Self {
        Self::new()
    }
}

fn run(cmd: &str, args: &[&str]) -> Result<String, PlatformError> {
    let out = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| PlatformError::Command(format!("{cmd}: {e}")))?;
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

impl Platform for MacOs {
    fn route(&self) -> Result<RouteInfo, PlatformError> {
        let text = run("route", &["-n", "get", "default"])?;
        let mut info = match parse_route(&text) {
            Ok(i) => i,
            // No IPv4 default route — fall back to the IPv6 table so an
            // IPv6-only network isn't reported as fully offline.
            Err(_) => {
                let v6 = run("route", &["-n", "get", "-inet6", "default"])?;
                parse_route(&v6)?
            }
        };
        if let Ok(tun) = run("scutil", &["--nwi"])
            && let Some(iface) = detect_tunnel(&tun)
        {
            info.tunnel_active = true;
            info.tunnel_iface = Some(iface);
        }
        Ok(info)
    }

    fn link(&self, interface: &str) -> Result<LinkInfo, PlatformError> {
        // `system_profiler SPAirPortDataType` always describes the Wi-Fi card,
        // regardless of which interface owns the default route. If the route
        // isn't the Wi-Fi device (e.g. wired Ethernet with Wi-Fi still idle),
        // don't grade this link by the Wi-Fi signal.
        let wifi_dev = run("networksetup", &["-listallhardwareports"])
            .ok()
            .and_then(|t| wifi_device(&t));
        if let Some(dev) = &wifi_dev
            && dev != interface
        {
            return Ok(LinkInfo {
                interface: interface.to_string(),
                is_wifi: false,
                ..Default::default()
            });
        }
        // Prefer CoreWLAN: instant, no multi-second system_profiler spawn.
        if let Some(info) = super::corewlan::read_link(interface) {
            return Ok(info);
        }
        // Fallback when CoreWLAN yields nothing (rare / unusual setups).
        let text = run("system_profiler", &["SPAirPortDataType"])?;
        let mut info = parse_airport(&text);
        info.interface = interface.to_string();
        Ok(info)
    }

    fn resolvers(&self) -> Result<ResolverInfo, PlatformError> {
        let text = run("scutil", &["--dns"])?;
        Ok(parse_resolvers(&text))
    }

    fn vpn(&self) -> Result<VpnInfo, PlatformError> {
        // `scutil --nwi` lists interfaces that are part of the *active* network
        // state, so a utun here is a real tunnel, not one of the idle utun0-3
        // devices macOS always keeps around.
        let nwi = run("scutil", &["--nwi"])?;
        let Some(iface) = detect_tunnel(&nwi) else {
            return Ok(VpnInfo::default());
        };
        let local_ip = run("ifconfig", &[&iface])
            .ok()
            .and_then(|t| parse_ifconfig_inet(&t));
        // Vendor: a running VPN client's daemon name is the most reliable
        // sudo-free signal — the tunnel interface is an opaque `utunN` for
        // nearly every vendor. Fall back to the tunnel address range.
        let vendor = run("ps", &["-axo", "comm="])
            .ok()
            .and_then(|ps| vendor_from_processes(&ps))
            .or_else(|| local_ip.and_then(vendor_from_ip))
            .map(str::to_string);
        Ok(VpnInfo {
            active: true,
            interface: Some(iface),
            vendor,
            local_ip,
        })
    }
}

// ---- pure parsers (unit-tested against real macOS 26 output) ----

fn parse_route(text: &str) -> Result<RouteInfo, PlatformError> {
    let mut info = RouteInfo::default();
    let mut header: Option<Vec<&str>> = None;
    for line in text.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("gateway:") {
            // A link-local IPv6 gateway carries a zone id: `fe80::1%en0`.
            // Split it off so the address parses, and keep the zone for ping.
            let (addr, zone) = match rest.trim().split_once('%') {
                Some((a, z)) => (a, Some(z.to_string())),
                None => (rest.trim(), None),
            };
            info.gateway = addr.parse().ok();
            info.gateway_zone = zone;
        } else if let Some(rest) = t.strip_prefix("interface:") {
            info.interface = rest.trim().to_string();
        } else if t.starts_with("recvpipe") {
            header = Some(t.split_whitespace().collect());
        } else if let Some(cols) = &header {
            // The single data row directly under the stats header.
            let vals: Vec<&str> = t.split_whitespace().collect();
            if vals.len() == cols.len() {
                if let Some(i) = cols.iter().position(|c| *c == "mtu") {
                    info.mtu = vals[i].parse().ok();
                }
                header = None;
            }
        }
    }
    if info.interface.is_empty() {
        return Err(PlatformError::NoNetwork);
    }
    Ok(info)
}

/// Parse the Wi-Fi device name from `networksetup -listallhardwareports`.
///
/// ```text
/// Hardware Port: Wi-Fi
/// Device: en0
/// ```
fn wifi_device(text: &str) -> Option<String> {
    let mut in_wifi = false;
    for line in text.lines() {
        let t = line.trim();
        if let Some(port) = t.strip_prefix("Hardware Port:") {
            in_wifi = matches!(port.trim(), "Wi-Fi" | "AirPort");
        } else if in_wifi && let Some(dev) = t.strip_prefix("Device:") {
            return Some(dev.trim().to_string());
        }
    }
    None
}

/// The first active tunnel interface in `scutil --nwi`. With multiple
/// concurrent tunnels this reports only one; the common case is a single VPN.
fn detect_tunnel(nwi: &str) -> Option<String> {
    nwi.lines()
        .filter_map(|l| l.trim().split(':').next().map(str::trim))
        .find(|w| w.starts_with("utun") || w.starts_with("tun") || w.starts_with("tap"))
        .map(str::to_string)
}

fn parse_airport(text: &str) -> LinkInfo {
    let mut info = LinkInfo {
        is_wifi: false,
        ..Default::default()
    };
    let mut in_current = false;
    for line in text.lines() {
        let t = line.trim();
        if t == "Current Network Information:" {
            in_current = true;
            continue;
        }
        if t == "Other Local Wi-Fi Networks:" {
            break;
        }
        if !in_current {
            continue;
        }
        // The SSID is the block header key (`SSID:` with nothing after it).
        // macOS renders it as `<redacted>:` without Location permission.
        if let Some((k, v)) = t.split_once(':') {
            let (k, v) = (k.trim(), v.trim());
            match k {
                "PHY Mode" => info.phy_mode = Some(v.to_string()),
                "Security" => info.security = Some(v.to_string()),
                "Transmit Rate" => info.tx_rate_mbps = v.parse().ok(),
                "Channel" => {
                    let (ch, band, width) = parse_channel(v);
                    info.channel = ch;
                    info.band = band;
                    info.width_mhz = width;
                    info.is_wifi = true;
                }
                "Signal / Noise" => {
                    let (s, n) = parse_signal_noise(v);
                    info.rssi_dbm = s;
                    info.noise_dbm = n;
                    info.is_wifi = true;
                }
                _ => {
                    if v.is_empty() && k != "<redacted>" && !k.is_empty() {
                        info.ssid = Some(k.to_string());
                        info.is_wifi = true;
                    } else if k == "<redacted>" && v.is_empty() {
                        info.is_wifi = true;
                    }
                }
            }
        }
    }
    info
}

/// `40 (5GHz, 80MHz)` -> (Some(40), Some("5GHz"), Some(80))
fn parse_channel(v: &str) -> (Option<u32>, Option<String>, Option<u32>) {
    let num = v.split_whitespace().next().and_then(|s| s.parse().ok());
    let (mut band, mut width) = (None, None);
    if let Some(paren) = v.split_once('(').map(|(_, r)| r.trim_end_matches(')')) {
        for part in paren.split(',') {
            let p = part.trim();
            if p.ends_with("GHz") {
                band = Some(p.to_string());
            } else if let Some(w) = p.strip_suffix("MHz") {
                width = w.trim().parse().ok();
            }
        }
    }
    (num, band, width)
}

/// `-50 dBm / -88 dBm` -> (Some(-50), Some(-88))
fn parse_signal_noise(v: &str) -> (Option<i32>, Option<i32>) {
    let mut it = v.split('/');
    let sig = it
        .next()
        .and_then(|s| s.split_whitespace().next())
        .and_then(|s| s.parse().ok());
    let noise = it
        .next()
        .and_then(|s| s.split_whitespace().next())
        .and_then(|s| s.parse().ok());
    (sig, noise)
}

/// Pull the tunnel's local address out of `ifconfig <iface>`, preferring IPv4.
///
/// Falls back to a global IPv6 address for IPv6-only tunnels, skipping the
/// `fe80::` link-local that every interface carries (which says nothing about
/// the tunnel). Any `%zone` scope suffix is stripped before parsing.
///
/// ```text
/// utun4: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1400
///     inet 100.86.1.2 --> 100.86.1.2 netmask 0xffffffff
/// ```
fn parse_ifconfig_inet(text: &str) -> Option<IpAddr> {
    let mut v6_fallback = None;
    for line in text.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("inet ") {
            if let Some(ip) = rest.split_whitespace().next().and_then(parse_addr) {
                return Some(ip); // IPv4 wins outright.
            }
        } else if let Some(rest) = t.strip_prefix("inet6 ")
            && v6_fallback.is_none()
            && let Some(ip) = rest.split_whitespace().next().and_then(parse_addr)
            && !is_link_local(ip)
        {
            v6_fallback = Some(ip);
        }
    }
    v6_fallback
}

/// Parse an address token, dropping any `%zone` scope suffix (`fe80::1%utun4`).
fn parse_addr(tok: &str) -> Option<IpAddr> {
    tok.split('%').next()?.parse().ok()
}

fn is_link_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_link_local(),
        // fe80::/10 — the top 10 bits are 1111111010.
        IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) == 0xfe80,
    }
}

/// Best-effort vendor guess from a tunnel's local address. Tailscale hands out
/// addresses from the 100.64.0.0/10 CGNAT block, which is a strong signal on a
/// tunnel interface. Anything else stays unlabelled rather than guessing wrong.
fn vendor_from_ip(ip: IpAddr) -> Option<&'static str> {
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
fn vendor_from_processes(ps: &str) -> Option<&'static str> {
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

fn parse_resolvers(text: &str) -> ResolverInfo {
    let mut ns = Vec::new();
    for line in text.lines() {
        let t = line.trim();
        if let Some(rest) = t.split_once(':')
            && rest.0.trim().starts_with("nameserver[")
            && let Ok(ip) = rest.1.trim().parse()
            && !ns.contains(&ip)
        {
            ns.push(ip);
        }
    }
    ResolverInfo { nameservers: ns }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROUTE: &str = "   route to: default
  destination: default
         mask: default
      gateway: 192.168.0.1
    interface: en0
        flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
   recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire
         0         0         0         0         0         0      1500         0 ";

    const AIRPORT: &str = "          Current Network Information:
            <redacted>:
              PHY Mode: 802.11ac
              Channel: 40 (5GHz, 80MHz)
              Country Code: JP
              Network Type: Infrastructure
              Security: WPA2 Personal
              Signal / Noise: -50 dBm / -88 dBm
              Transmit Rate: 585
              MCS Index: 7
          Other Local Wi-Fi Networks:";

    const DNS: &str = "  nameserver[0] : 192.168.0.1
  nameserver[0] : 192.168.0.1";

    #[test]
    fn route_parses_gateway_iface_mtu() {
        let r = parse_route(ROUTE).unwrap();
        assert_eq!(r.gateway.unwrap().to_string(), "192.168.0.1");
        assert_eq!(r.interface, "en0");
        assert_eq!(r.mtu, Some(1500));
    }

    #[test]
    fn airport_parses_signal_and_channel() {
        let l = parse_airport(AIRPORT);
        assert_eq!(l.rssi_dbm, Some(-50));
        assert_eq!(l.noise_dbm, Some(-88));
        assert_eq!(l.snr_db(), Some(38));
        assert_eq!(l.channel, Some(40));
        assert_eq!(l.band.as_deref(), Some("5GHz"));
        assert_eq!(l.width_mhz, Some(80));
        assert_eq!(l.phy_mode.as_deref(), Some("802.11ac"));
        assert_eq!(l.tx_rate_mbps, Some(585));
        assert!(l.is_wifi);
        assert!(l.ssid.is_none(), "redacted SSID must stay None");
    }

    #[test]
    fn resolvers_dedup() {
        let r = parse_resolvers(DNS);
        assert_eq!(r.nameservers.len(), 1);
        assert_eq!(r.nameservers[0].to_string(), "192.168.0.1");
    }

    #[test]
    fn route_strips_ipv6_zone() {
        let text = "      gateway: fe80::1%en0\n    interface: en0";
        let r = parse_route(text).unwrap();
        assert_eq!(r.gateway.unwrap().to_string(), "fe80::1");
        assert_eq!(r.gateway_zone.as_deref(), Some("en0"));
    }

    #[test]
    fn ifconfig_inet_parsed() {
        let text = "utun4: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1400\n\
                    \tinet 100.86.1.2 --> 100.86.1.2 netmask 0xffffffff\n\
                    \tinet6 fe80::1%utun4 prefixlen 64";
        assert_eq!(parse_ifconfig_inet(text).unwrap().to_string(), "100.86.1.2");
    }

    #[test]
    fn ifconfig_prefers_ipv4_over_ipv6() {
        // Link-local v6 comes first in the output, but IPv4 must still win.
        let text = "utun4: flags=8051 mtu 1400\n\
                    \tinet6 fe80::1%utun4 prefixlen 64\n\
                    \tinet 100.86.1.2 --> 100.86.1.2 netmask 0xffffffff\n\
                    \tinet6 fd7a:115c:a1e0::1 prefixlen 48";
        assert_eq!(parse_ifconfig_inet(text).unwrap().to_string(), "100.86.1.2");
    }

    #[test]
    fn ifconfig_falls_back_to_global_ipv6() {
        // IPv6-only tunnel: skip the link-local, keep the global address.
        let text = "utun6: flags=8051 mtu 1400\n\
                    \tinet6 fe80::abcd%utun6 prefixlen 64 scopeid 0x1d\n\
                    \tinet6 fd7a:115c:a1e0::53 prefixlen 48";
        assert_eq!(
            parse_ifconfig_inet(text).unwrap().to_string(),
            "fd7a:115c:a1e0::53"
        );
    }

    #[test]
    fn ifconfig_link_local_only_is_none() {
        let text = "utun7: flags=8051 mtu 1400\n\tinet6 fe80::1%utun7 prefixlen 64";
        assert_eq!(parse_ifconfig_inet(text), None);
    }

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

    #[test]
    fn detect_tunnel_finds_utun() {
        let nwi = "Network information\n\n\
                   IPv4 network interface information\n\
                   \t  en0 : flags : 0x5 (IPv4,DNS)\n\
                   \tutun4 : flags : 0x5 (IPv4,DNS)\n\n\
                   \tNetwork interfaces: en0 utun4";
        assert_eq!(detect_tunnel(nwi).as_deref(), Some("utun4"));
    }

    #[test]
    fn wifi_device_parsed() {
        let text = "Hardware Port: Ethernet\nDevice: en5\n\n\
                    Hardware Port: Wi-Fi\nDevice: en0\nEthernet Address: aa:bb";
        assert_eq!(wifi_device(text).as_deref(), Some("en0"));
    }
}
