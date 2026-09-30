//! Linux platform implementation.
//!
//! Reads the same facts as the macOS module, from tools and files that work
//! **without root** on a stock distribution:
//!
//! - `ip -j route` / `ip -j addr` / `ip -j -d link` — rtnetlink: default
//!   route, addresses, tunnel interfaces. `/proc/net/route` when `ip` is
//!   missing (minimal containers).
//! - `iw dev <if> link|info|survey dump` — nl80211: association, signal,
//!   frequency, bitrate, channel width, noise. `/proc/net/wireless` when `iw`
//!   is missing.
//! - `/etc/resolv.conf`, or systemd-resolved's upstream list when that file
//!   only names the local stub.
//!
//! Unlike macOS, nothing here is redacted: `iw` reports the SSID and BSSID to
//! any user.

use super::shared::{is_link_local, parse_addr, vendor_from_ip, vendor_from_processes};
use super::{AddrInfo, LinkInfo, Platform, PlatformError, ResolverInfo, RouteInfo, VpnInfo};
use serde_json::Value;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::process::Command;

pub struct Linux;

impl Linux {
    pub fn new() -> Self {
        Linux
    }
}

impl Default for Linux {
    fn default() -> Self {
        Self::new()
    }
}

/// Run a read-only tool and return its stdout.
///
/// Same contract as the macOS module's: a tool that refused to run is a
/// failure to observe (`Command`), never evidence of an outage.
fn run(cmd: &str, args: &[&str]) -> Result<String, PlatformError> {
    let out = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| PlatformError::Command(format!("{cmd}: {e}")))?;
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    if !out.status.success() && stdout.trim().is_empty() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let detail = stderr
            .lines()
            .map(str::trim)
            .find(|l| !l.is_empty())
            .unwrap_or("no output");
        return Err(PlatformError::Command(format!("{cmd}: {detail}")));
    }
    Ok(stdout)
}

fn read(path: &str) -> Result<String, PlatformError> {
    std::fs::read_to_string(path).map_err(|e| PlatformError::Command(format!("{path}: {e}")))
}

fn is_wireless(iface: &str) -> bool {
    let base = Path::new("/sys/class/net").join(iface);
    base.join("wireless").exists() || base.join("phy80211").exists()
}

impl Platform for Linux {
    fn route(&self) -> Result<RouteInfo, PlatformError> {
        let mut info = match run("ip", &["-j", "route", "show", "default"]) {
            Ok(v4) => match parse_ip_route(&v4) {
                Some(i) => i,
                // No IPv4 default: an IPv6-only network is still a network.
                None => run("ip", &["-j", "-6", "route", "show", "default"])
                    .ok()
                    .and_then(|t| parse_ip_route(&t))
                    .ok_or(PlatformError::NoNetwork)?,
            },
            // `ip` itself is missing or refused: the kernel's own table still
            // answers for IPv4.
            Err(e) => read("/proc/net/route")
                .map_err(|_| e)
                .and_then(|t| parse_proc_route(&t).ok_or(PlatformError::NoNetwork))?,
        };
        info.mtu = read(&format!("/sys/class/net/{}/mtu", info.interface))
            .ok()
            .and_then(|t| t.trim().parse().ok());
        match run("ip", &["-j", "-d", "link", "show", "up"]) {
            Err(_) => info.tunnel_unreadable = true,
            Ok(links) => {
                if let Some((iface, _)) = detect_tunnel(&links) {
                    info.tunnel_active = true;
                    info.tunnel_iface = Some(iface);
                }
            }
        }
        Ok(info)
    }

    fn link(&self, interface: &str) -> Result<LinkInfo, PlatformError> {
        if !is_wireless(interface) {
            return Ok(LinkInfo {
                interface: interface.to_string(),
                is_wifi: false,
                ..Default::default()
            });
        }
        let mut info = match run("iw", &["dev", interface, "link"]) {
            Ok(text) if text.trim_start().starts_with("Not connected") => {
                return Err(PlatformError::NoNetwork);
            }
            // Anything else we can't read is unknown, not "not associated".
            Ok(text) => parse_iw_link(&text)
                .ok_or_else(|| PlatformError::Parse("unreadable `iw dev link`".into()))?,
            // No `iw`: the wireless extensions table still has the signal.
            Err(e) => read("/proc/net/wireless")
                .ok()
                .and_then(|t| parse_proc_wireless(&t, interface))
                .ok_or(e)?,
        };
        info.interface = interface.to_string();
        if let Some(width) = run("iw", &["dev", interface, "info"])
            .ok()
            .and_then(|t| parse_iw_info_width(&t))
        {
            info.width_mhz = Some(width);
        }
        if info.noise_dbm.is_none() {
            info.noise_dbm = run("iw", &["dev", interface, "survey", "dump"])
                .ok()
                .and_then(|t| parse_survey_noise(&t));
        }
        Ok(info)
    }

    fn addrs(&self, interface: &str) -> Result<AddrInfo, PlatformError> {
        let text = run("ip", &["-j", "addr", "show", "dev", interface])?;
        parse_ip_addr(&text).ok_or_else(|| PlatformError::Parse("unreadable `ip -j addr`".into()))
    }

    fn primary_interface(&self) -> Result<String, PlatformError> {
        let mut names: Vec<String> = std::fs::read_dir("/sys/class/net")
            .map_err(|e| PlatformError::Command(format!("/sys/class/net: {e}")))?
            .filter_map(|e| e.ok()?.file_name().into_string().ok())
            .collect();
        names.sort();
        names
            .into_iter()
            .find(|n| is_wireless(n))
            .ok_or_else(|| PlatformError::Parse("no Wi-Fi interface".into()))
    }

    fn resolvers(&self) -> Result<ResolverInfo, PlatformError> {
        let conf = parse_resolv_conf(&read("/etc/resolv.conf")?);
        // systemd-resolved points every app at its local stub. The stub is
        // what gets queried, but naming it tells the reader nothing — the
        // upstream list is what they can act on.
        if !conf.is_empty() && conf.iter().all(is_resolved_stub) {
            let upstream = read("/run/systemd/resolve/resolv.conf")
                .map(|t| parse_resolv_conf(&t))
                .unwrap_or_default();
            if !upstream.is_empty() {
                return Ok(ResolverInfo {
                    nameservers: upstream,
                });
            }
        }
        Ok(ResolverInfo { nameservers: conf })
    }

    fn vpn(&self) -> Result<VpnInfo, PlatformError> {
        let links = run("ip", &["-j", "-d", "link", "show", "up"])?;
        let Some((iface, kind)) = detect_tunnel(&links) else {
            return Ok(VpnInfo::default());
        };
        let local_ip = run("ip", &["-j", "addr", "show", "dev", &iface])
            .ok()
            .and_then(|t| tunnel_local_ip(&t));
        let vendor = vendor_from_processes(&process_names())
            .or_else(|| local_ip.and_then(vendor_from_ip))
            // In-kernel WireGuard has no daemon to name it.
            .or_else(|| (kind.as_deref() == Some("wireguard")).then_some("WireGuard"))
            .map(str::to_string);
        Ok(VpnInfo {
            active: true,
            interface: Some(iface),
            local_ip,
            vendor,
        })
    }
}

/// Every process name, from `/proc/<pid>/comm`. Read directly rather than via
/// `ps`, whose flags differ between procps and BusyBox.
fn process_names() -> String {
    let Ok(dir) = std::fs::read_dir("/proc") else {
        return String::new();
    };
    dir.filter_map(|e| {
        let e = e.ok()?;
        e.file_name().to_str()?.parse::<u32>().ok()?;
        std::fs::read_to_string(e.path().join("comm")).ok()
    })
    .collect()
}

// ---- pure parsers (unit-tested against real Linux output) ----

fn json(text: &str) -> Option<Vec<Value>> {
    match serde_json::from_str(text.trim()).ok()? {
        Value::Array(a) => Some(a),
        _ => None,
    }
}

/// The preferred default route from `ip -j route show default`: the lowest
/// metric wins, as it does in the kernel.
fn parse_ip_route(text: &str) -> Option<RouteInfo> {
    let routes = json(text)?;
    let best = routes
        .iter()
        .filter(|r| r["dev"].is_string())
        .min_by_key(|r| r["metric"].as_u64().unwrap_or(0))?;
    let interface = best["dev"].as_str()?.to_string();
    let gateway: Option<IpAddr> = best["gateway"].as_str().and_then(|g| g.parse().ok());
    // A link-local IPv6 gateway is only reachable through the interface that
    // learned it; `ip` leaves the zone implicit in `dev`.
    let gateway_zone = gateway
        .filter(|g| g.is_ipv6() && is_link_local(*g))
        .map(|_| interface.clone());
    Some(RouteInfo {
        interface,
        gateway,
        gateway_zone,
        ..Default::default()
    })
}

/// The IPv4 default route from `/proc/net/route`, whose addresses are
/// little-endian hex.
///
/// ```text
/// Iface   Destination Gateway  Flags RefCnt Use Metric Mask     MTU Window IRTT
/// wlan0   00000000    0100A8C0 0003  0      0   600    00000000 0   0      0
/// ```
fn parse_proc_route(text: &str) -> Option<RouteInfo> {
    text.lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            (f.len() >= 8 && f[1] == "00000000" && f[7] == "00000000").then_some(f)
        })
        .min_by_key(|f| f[6].parse::<u32>().unwrap_or(0))
        .map(|f| {
            let gw = u32::from_str_radix(f[2], 16).ok().filter(|g| *g != 0);
            RouteInfo {
                interface: f[0].to_string(),
                gateway: gw.map(|g| IpAddr::V4(Ipv4Addr::from(g.swap_bytes()))),
                ..Default::default()
            }
        })
}

/// The first up tunnel in `ip -j -d link show up`, with its link kind.
///
/// Matched by the driver kind where the kernel reports one, and by name for
/// the common userspace clients, so a Docker bridge or veth — up, virtual, and
/// nothing to do with a VPN — never qualifies.
fn detect_tunnel(text: &str) -> Option<(String, Option<String>)> {
    json(text)?.iter().find_map(|l| {
        let name = l["ifname"].as_str()?;
        let kind = l["linkinfo"]["info_kind"].as_str();
        let by_kind = matches!(kind, Some("tun" | "wireguard"));
        let by_name = ["tun", "tap", "wg", "tailscale", "utun", "ppp"]
            .iter()
            .any(|p| name.starts_with(p));
        (by_kind || by_name).then(|| (name.to_string(), kind.map(str::to_string)))
    })
}

fn addr_infos(text: &str) -> Vec<Value> {
    json(text)
        .unwrap_or_default()
        .iter()
        .flat_map(|l| l["addr_info"].as_array().cloned().unwrap_or_default())
        .collect()
}

/// Addresses from `ip -j addr show dev <if>`. `None` when the output isn't the
/// JSON `ip` promises, so an unreadable answer can't pass for "no address".
fn parse_ip_addr(text: &str) -> Option<AddrInfo> {
    json(text)?;
    let mut info = AddrInfo::default();
    for a in addr_infos(text) {
        let Some(ip) = a["local"].as_str().and_then(|s| s.parse::<IpAddr>().ok()) else {
            continue;
        };
        match ip {
            // The first is the primary; later ones are aliases.
            IpAddr::V4(v4) if info.v4.is_none() => {
                let prefix = a["prefixlen"].as_u64().unwrap_or(32).min(32) as u8;
                info.v4 = Some((v4, prefix));
            }
            IpAddr::V6(v6) if !is_link_local(ip) => info.v6.push(v6),
            _ => {}
        }
    }
    Some(info)
}

/// A tunnel's own address, preferring IPv4 and skipping link-local IPv6.
fn tunnel_local_ip(text: &str) -> Option<IpAddr> {
    let a = parse_ip_addr(text)?;
    a.v4.map(|(ip, _)| IpAddr::V4(ip))
        .or_else(|| a.v6.first().map(|v6| IpAddr::V6(*v6)))
}

/// Parse `iw dev <if> link`. `None` for `Not connected.` — the interface is up
/// but associated with nothing.
///
/// ```text
/// Connected to 00:11:22:33:44:55 (on wlan0)
///         SSID: HomeNet
///         freq: 5180.0
///         signal: -53 dBm
///         tx bitrate: 866.7 MBit/s VHT-MCS 9 80MHz short GI VHT-NSS 2
/// ```
fn parse_iw_link(text: &str) -> Option<LinkInfo> {
    let first = text.lines().next()?.trim();
    let bssid = first
        .strip_prefix("Connected to ")?
        .split_whitespace()
        .next()
        .map(str::to_string);
    let mut info = LinkInfo {
        bssid,
        is_wifi: true,
        ..Default::default()
    };
    for line in text.lines().skip(1) {
        let Some((k, v)) = line.trim().split_once(':') else {
            continue;
        };
        let v = v.trim();
        match k.trim() {
            "SSID" => info.ssid = Some(v.to_string()),
            "freq" => {
                if let Some(mhz) = v.parse::<f64>().ok().map(|f| f as u32) {
                    info.channel = channel_of(mhz);
                    info.band = band_of(mhz).map(str::to_string);
                }
            }
            "signal" => info.rssi_dbm = v.split_whitespace().next().and_then(|s| s.parse().ok()),
            "tx bitrate" => {
                info.tx_rate_mbps = v
                    .split_whitespace()
                    .next()
                    .and_then(|s| s.parse::<f64>().ok())
                    .map(|r| r as u32);
                info.phy_mode = phy_of(v).map(str::to_string);
                info.width_mhz = v
                    .split_whitespace()
                    .find_map(|t| t.strip_suffix("MHz")?.parse().ok());
            }
            _ => {}
        }
    }
    Some(info)
}

/// The generation from the MCS family `iw` names in a bitrate line. Legacy
/// rates carry none, and are left unlabelled rather than guessed.
fn phy_of(bitrate: &str) -> Option<&'static str> {
    let toks: Vec<&str> = bitrate.split_whitespace().collect();
    let has = |p: &str| toks.contains(&p);
    if has("EHT-MCS") {
        Some("802.11be")
    } else if has("HE-MCS") {
        Some("802.11ax")
    } else if has("VHT-MCS") {
        Some("802.11ac")
    } else if has("MCS") {
        Some("802.11n")
    } else {
        None
    }
}

fn channel_of(mhz: u32) -> Option<u32> {
    match mhz {
        2484 => Some(14),
        2412..=2472 => Some((mhz - 2407) / 5),
        5160..=5885 => Some((mhz - 5000) / 5),
        5955..=7115 => Some((mhz - 5950) / 5),
        _ => None,
    }
}

/// Labels match CoreWLAN's, so a report reads the same on either OS.
fn band_of(mhz: u32) -> Option<&'static str> {
    match mhz {
        2400..=2500 => Some("2GHz"),
        4900..=5900 => Some("5GHz"),
        5925..=7125 => Some("6GHz"),
        _ => None,
    }
}

/// Channel width from `iw dev <if> info`:
/// `channel 36 (5180 MHz), width: 80 MHz, center1: 5210 MHz`.
fn parse_iw_info_width(text: &str) -> Option<u32> {
    text.lines().find_map(|l| {
        let rest = l.trim().strip_prefix("channel ")?;
        let w = rest.split_once("width:")?.1.trim();
        w.split_whitespace().next()?.parse().ok()
    })
}

/// Noise floor of the channel in use, from `iw dev <if> survey dump`. Drivers
/// that don't report one simply leave it out.
fn parse_survey_noise(text: &str) -> Option<i32> {
    text.split("Survey data from").find_map(|block| {
        if !block.contains("[in use]") {
            return None;
        }
        block.lines().find_map(|l| {
            let v = l.trim().strip_prefix("noise:")?;
            v.split_whitespace().next()?.parse().ok()
        })
    })
}

/// Signal and noise from `/proc/net/wireless`, the fallback when `iw` is
/// missing.
///
/// ```text
/// Inter-| sta-|   Quality        |   Discarded packets
///  face | tus | link level noise |  nwid  crypt   frag
///  wlan0: 0000   56.  -54.  -256        0      0      0
/// ```
///
/// `-256` is the driver saying "no noise reading", not a noise floor.
fn parse_proc_wireless(text: &str, iface: &str) -> Option<LinkInfo> {
    let line = text
        .lines()
        .find(|l| l.trim_start().starts_with(&format!("{iface}:")))?;
    let f: Vec<&str> = line.split(':').nth(1)?.split_whitespace().collect();
    let num = |i: usize| -> Option<i32> {
        f.get(i)?
            .trim_end_matches('.')
            .parse::<f64>()
            .ok()
            .map(|v| v as i32)
    };
    let rssi = num(2).filter(|v| *v < 0);
    let noise = num(3).filter(|v| *v < 0 && *v > -256);
    Some(LinkInfo {
        is_wifi: true,
        rssi_dbm: rssi,
        noise_dbm: noise,
        ..Default::default()
    })
}

fn parse_resolv_conf(text: &str) -> Vec<IpAddr> {
    let mut ns = Vec::new();
    for line in text.lines() {
        let mut toks = line.split_whitespace();
        if toks.next() == Some("nameserver")
            && let Some(ip) = toks.next().and_then(parse_addr)
            && !ns.contains(&ip)
        {
            ns.push(ip);
        }
    }
    ns
}

fn is_resolved_stub(ip: &IpAddr) -> bool {
    matches!(ip, IpAddr::V4(v4) if v4.octets() == [127, 0, 0, 53] || v4.octets() == [127, 0, 0, 54])
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROUTE: &str = r#"[{"dst":"default","gateway":"192.168.1.1","dev":"wlp2s0","protocol":"dhcp","prefsrc":"192.168.1.23","metric":600,"flags":[]},{"dst":"default","gateway":"10.0.0.1","dev":"enp3s0","protocol":"dhcp","metric":100,"flags":[]}]"#;

    #[test]
    fn route_prefers_the_lowest_metric() {
        let r = parse_ip_route(ROUTE).unwrap();
        assert_eq!(r.interface, "enp3s0");
        assert_eq!(r.gateway.unwrap().to_string(), "10.0.0.1");
        assert_eq!(r.gateway_zone, None);
    }

    #[test]
    fn a_link_local_v6_gateway_is_zoned_to_its_interface() {
        let text = r#"[{"dst":"default","gateway":"fe80::1","dev":"wlan0","protocol":"ra","metric":600,"flags":[]}]"#;
        let r = parse_ip_route(text).unwrap();
        assert_eq!(r.gateway.unwrap().to_string(), "fe80::1");
        assert_eq!(r.gateway_zone.as_deref(), Some("wlan0"));
    }

    #[test]
    fn an_empty_table_is_no_route() {
        assert!(parse_ip_route("[]").is_none());
        assert!(parse_ip_route("").is_none());
    }

    #[test]
    fn proc_route_decodes_little_endian_hex() {
        let text = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
                    docker0\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0\n\
                    wlan0\t00000000\t0100A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n";
        let r = parse_proc_route(text).unwrap();
        assert_eq!(r.interface, "wlan0");
        assert_eq!(r.gateway.unwrap().to_string(), "192.168.0.1");
    }

    #[test]
    fn tunnels_are_found_by_kind_or_name_and_bridges_are_not() {
        let text = r#"[
            {"ifname":"lo","flags":["LOOPBACK","UP","LOWER_UP"]},
            {"ifname":"docker0","flags":["UP"],"linkinfo":{"info_kind":"bridge"}},
            {"ifname":"wg-home","flags":["POINTOPOINT","NOARP","UP","LOWER_UP"],"linkinfo":{"info_kind":"wireguard"}}
        ]"#;
        assert_eq!(
            detect_tunnel(text),
            Some(("wg-home".into(), Some("wireguard".into())))
        );
        let ts = r#"[{"ifname":"tailscale0","flags":["UP"],"linkinfo":{"info_kind":"tun"}}]"#;
        assert_eq!(detect_tunnel(ts).unwrap().0, "tailscale0");
        let none = r#"[{"ifname":"veth1a2b","flags":["UP"],"linkinfo":{"info_kind":"veth"}}]"#;
        assert_eq!(detect_tunnel(none), None);
    }

    const ADDR: &str = r#"[{"ifindex":3,"ifname":"wlan0","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],"mtu":1500,"operstate":"UP","addr_info":[
        {"family":"inet","local":"192.168.1.23","prefixlen":24,"scope":"global","dynamic":true},
        {"family":"inet","local":"192.168.1.99","prefixlen":24,"scope":"global","secondary":true},
        {"family":"inet6","local":"2001:db8::23","prefixlen":64,"scope":"global"},
        {"family":"inet6","local":"fe80::1c2:3ff:fe45:6789","prefixlen":64,"scope":"link"}]}]"#;

    #[test]
    fn addrs_keep_the_primary_v4_and_routable_v6() {
        let a = parse_ip_addr(ADDR).unwrap();
        let (ip, prefix) = a.v4.unwrap();
        assert_eq!((ip.to_string().as_str(), prefix), ("192.168.1.23", 24));
        assert_eq!(a.v6.len(), 1, "link-local must not count as an address");
        assert_eq!(a.v6[0].to_string(), "2001:db8::23");
    }

    #[test]
    fn a_self_assigned_lease_is_seen() {
        let text = r#"[{"ifname":"wlan0","addr_info":[{"family":"inet","local":"169.254.13.7","prefixlen":16}]}]"#;
        assert!(parse_ip_addr(text).unwrap().is_self_assigned());
    }

    #[test]
    fn unreadable_addr_output_is_not_no_address() {
        assert!(parse_ip_addr("Device \"wlan9\" does not exist.").is_none());
    }

    #[test]
    fn tunnel_ip_prefers_v4() {
        let text = r#"[{"ifname":"tailscale0","addr_info":[
            {"family":"inet6","local":"fd7a:115c:a1e0::1","prefixlen":128},
            {"family":"inet","local":"100.86.1.2","prefixlen":32}]}]"#;
        assert_eq!(tunnel_local_ip(text).unwrap().to_string(), "100.86.1.2");
    }

    const IW_VHT: &str = "Connected to 00:11:22:33:44:55 (on wlan0)
\tSSID: HomeNet
\tfreq: 5180.0
\tRX: 1433853 bytes (6264 packets)
\tTX: 181433 bytes (1227 packets)
\tsignal: -53 dBm
\trx bitrate: 866.7 MBit/s VHT-MCS 9 80MHz short GI VHT-NSS 2
\ttx bitrate: 650.0 MBit/s VHT-MCS 7 80MHz short GI VHT-NSS 2
\tbss flags: short-slot-time
\tdtim period: 1
\tbeacon int: 100
";

    #[test]
    fn iw_link_parses_signal_channel_and_rate() {
        let l = parse_iw_link(IW_VHT).unwrap();
        assert!(l.is_wifi);
        assert_eq!(l.ssid.as_deref(), Some("HomeNet"));
        assert_eq!(l.bssid.as_deref(), Some("00:11:22:33:44:55"));
        assert_eq!(l.rssi_dbm, Some(-53));
        assert_eq!(l.channel, Some(36));
        assert_eq!(l.band.as_deref(), Some("5GHz"));
        assert_eq!(l.width_mhz, Some(80));
        assert_eq!(l.tx_rate_mbps, Some(650));
        assert_eq!(l.phy_mode.as_deref(), Some("802.11ac"));
    }

    #[test]
    fn iw_link_reads_he_and_legacy_rates() {
        let he = "Connected to aa:bb:cc:dd:ee:ff (on wlp0s20f3)\n\
                  \tSSID: x\n\tfreq: 2437\n\tsignal: -71 dBm\n\
                  \ttx bitrate: 286.7 MBit/s 40MHz HE-MCS 11 HE-NSS 2 HE-GI 0 HE-DCM 0\n";
        let l = parse_iw_link(he).unwrap();
        assert_eq!(l.phy_mode.as_deref(), Some("802.11ax"));
        assert_eq!((l.channel, l.band.as_deref()), (Some(6), Some("2GHz")));
        assert_eq!(l.width_mhz, Some(40));

        let legacy = "Connected to aa:bb:cc:dd:ee:ff (on wlan0)\n\ttx bitrate: 54.0 MBit/s\n";
        let l = parse_iw_link(legacy).unwrap();
        assert_eq!(l.tx_rate_mbps, Some(54));
        assert_eq!(l.phy_mode, None, "a legacy rate names no generation");
    }

    #[test]
    fn not_connected_is_not_associated() {
        assert!(parse_iw_link("Not connected.\n").is_none());
    }

    #[test]
    fn six_ghz_channels_are_numbered_from_5950() {
        assert_eq!(channel_of(5975), Some(5));
        assert_eq!(band_of(5975), Some("6GHz"));
        assert_eq!(channel_of(2484), Some(14));
    }

    #[test]
    fn iw_info_gives_the_channel_width() {
        let text = "Interface wlan0\n\tifindex 3\n\ttype managed\n\
                    \tchannel 36 (5180 MHz), width: 80 MHz, center1: 5210 MHz\n\ttxpower 22.00 dBm\n";
        assert_eq!(parse_iw_info_width(text), Some(80));
    }

    #[test]
    fn survey_noise_comes_from_the_channel_in_use() {
        let text = "Survey data from wlan0\n\tfrequency:\t\t\t5170 MHz\n\tnoise:\t\t\t\t-97 dBm\n\
                    Survey data from wlan0\n\tfrequency:\t\t\t5180 MHz [in use]\n\tnoise:\t\t\t\t-92 dBm\n\
                    \tchannel active time:\t\t92 ms\n";
        assert_eq!(parse_survey_noise(text), Some(-92));
        assert_eq!(
            parse_survey_noise("Survey data from wlan0\n\tfrequency: 5180 MHz [in use]\n"),
            None
        );
    }

    #[test]
    fn proc_wireless_ignores_the_no_noise_sentinel() {
        let text = "Inter-| sta-|   Quality        |   Discarded packets               | Missed | WE\n \
                    face | tus | link level noise |  nwid  crypt   frag  retry   misc | beacon | 22\n \
                    wlan0: 0000   56.  -54.  -256        0      0      0      0      0        0\n";
        let l = parse_proc_wireless(text, "wlan0").unwrap();
        assert_eq!(l.rssi_dbm, Some(-54));
        assert_eq!(l.noise_dbm, None);
        assert!(parse_proc_wireless(text, "wlan1").is_none());
    }

    #[test]
    fn resolv_conf_dedups_and_drops_comments() {
        let text = "# Generated by NetworkManager\nsearch lan\nnameserver 192.168.1.1\n\
                    nameserver 192.168.1.1\nnameserver fe80::1%wlan0\noptions edns0\n";
        let ns = parse_resolv_conf(text);
        assert_eq!(ns.len(), 2);
        assert_eq!(ns[0].to_string(), "192.168.1.1");
        assert_eq!(ns[1].to_string(), "fe80::1");
    }

    #[test]
    fn the_resolved_stub_is_recognised() {
        let ns = parse_resolv_conf("nameserver 127.0.0.53\noptions edns0 trust-ad\n");
        assert!(ns.iter().all(is_resolved_stub));
        assert!(!is_resolved_stub(&"192.168.1.1".parse().unwrap()));
    }
}
