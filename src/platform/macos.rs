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

use super::{LinkInfo, Platform, PlatformError, ResolverInfo, RouteInfo};
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
        if let Ok(tun) = run("scutil", &["--nwi"]) {
            if let Some(iface) = detect_tunnel(&tun) {
                info.tunnel_active = true;
                info.tunnel_iface = Some(iface);
            }
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
        if let Some(dev) = &wifi_dev {
            if dev != interface {
                return Ok(LinkInfo {
                    interface: interface.to_string(),
                    is_wifi: false,
                    ..Default::default()
                });
            }
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
        } else if in_wifi {
            if let Some(dev) = t.strip_prefix("Device:") {
                return Some(dev.trim().to_string());
            }
        }
    }
    None
}

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

fn parse_resolvers(text: &str) -> ResolverInfo {
    let mut ns = Vec::new();
    for line in text.lines() {
        let t = line.trim();
        if let Some(rest) = t.split_once(':') {
            if rest.0.trim().starts_with("nameserver[") {
                if let Ok(ip) = rest.1.trim().parse() {
                    if !ns.contains(&ip) {
                        ns.push(ip);
                    }
                }
            }
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
    fn wifi_device_parsed() {
        let text = "Hardware Port: Ethernet\nDevice: en5\n\n\
                    Hardware Port: Wi-Fi\nDevice: en0\nEthernet Address: aa:bb";
        assert_eq!(wifi_device(text).as_deref(), Some("en0"));
    }
}
