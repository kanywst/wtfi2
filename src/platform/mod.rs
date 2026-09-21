//! Platform abstraction layer.
//!
//! Each OS provides a [`Platform`] implementation that gathers raw, low-level
//! network facts (link telemetry, default route, resolvers). The probe engine
//! consumes these facts and never touches OS-specific commands directly, so a
//! new OS only needs a new `Platform` impl — nothing above this layer changes.

use std::net::IpAddr;

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(target_os = "macos")]
mod corewlan;

#[cfg(not(target_os = "macos"))]
pub mod unsupported;

/// Why wtfi refuses to probe on this OS, or `None` when it is supported.
/// macOS is the only real [`Platform`] impl today.
pub const UNSUPPORTED_OS: Option<&str> = if cfg!(target_os = "macos") {
    None
} else {
    Some("wtfi has no platform module for this OS yet — macOS only for now")
};

/// Physical / link-layer (L2) facts about the active Wi-Fi interface.
#[derive(Debug, Clone, Default)]
pub struct LinkInfo {
    /// Interface name backing the default route, e.g. `en0`.
    pub interface: String,
    /// SSID, or `None` when the OS redacts it (missing Location permission).
    pub ssid: Option<String>,
    /// BSSID (AP MAC), or `None` when redacted.
    pub bssid: Option<String>,
    /// Received signal strength in dBm (negative; closer to 0 is stronger).
    pub rssi_dbm: Option<i32>,
    /// Noise floor in dBm.
    pub noise_dbm: Option<i32>,
    /// Channel number.
    pub channel: Option<u32>,
    /// Channel band label, e.g. `5GHz`.
    pub band: Option<String>,
    /// Channel width in MHz.
    pub width_mhz: Option<u32>,
    /// PHY mode, e.g. `802.11ax`.
    pub phy_mode: Option<String>,
    /// Security type, e.g. `WPA3 Personal`.
    pub security: Option<String>,
    /// Negotiated transmit rate in Mbps.
    pub tx_rate_mbps: Option<u32>,
    /// True when a wired/other link is active instead of Wi-Fi.
    pub is_wifi: bool,
}

impl LinkInfo {
    /// Signal-to-noise ratio in dB, when both values are known.
    pub fn snr_db(&self) -> Option<i32> {
        match (self.rssi_dbm, self.noise_dbm) {
            (Some(s), Some(n)) => Some(s - n),
            _ => None,
        }
    }
}

/// Default-route (L3) facts.
#[derive(Debug, Clone, Default)]
pub struct RouteInfo {
    pub interface: String,
    pub gateway: Option<IpAddr>,
    /// Scope/zone id for a link-local IPv6 gateway (e.g. `en0` in `fe80::1%en0`).
    pub gateway_zone: Option<String>,
    pub mtu: Option<u32>,
    /// True when a VPN/tunnel interface (utun/tailscale) owns a route.
    pub tunnel_active: bool,
    pub tunnel_iface: Option<String>,
    /// True when the tunnel lookup itself failed, so `tunnel_active == false`
    /// means "we couldn't tell" rather than "there is no tunnel".
    ///
    /// The distinction matters downstream: a dead full-tunnel VPN looks
    /// exactly like an ISP outage, and the only thing that stops wtfi blaming
    /// the ISP for it is knowing the tunnel is there. Silently treating an
    /// unreadable tunnel as an absent one hands back the confident wrong
    /// answer the fault codes exist to prevent.
    pub tunnel_unreadable: bool,
}

/// Addresses configured on an interface.
///
/// Separate from [`RouteInfo`] because it answers a different question: the
/// route says where traffic goes, this says whether you were given a place to
/// send it *from*. A machine with a self-assigned `169.254` address has an
/// interface, a link and often a gateway entry, and still cannot talk to
/// anything — a state the route alone cannot describe.
#[derive(Debug, Clone, Default)]
pub struct AddrInfo {
    /// IPv4 address and its prefix length, e.g. `192.168.0.15/24`.
    pub v4: Option<(std::net::Ipv4Addr, u8)>,
    /// Routable IPv6 addresses. Link-local `fe80::` is excluded: every
    /// interface has one whether or not the network works.
    pub v6: Vec<std::net::Ipv6Addr>,
}

impl AddrInfo {
    /// True when IPv4 autoconfiguration took over because DHCP never answered
    /// (RFC 3927, `169.254.0.0/16`). The interface looks configured and can
    /// reach nothing.
    pub fn is_self_assigned(&self) -> bool {
        self.v4.is_some_and(|(ip, _)| ip.is_link_local())
    }

    /// Whether `other` falls inside the configured IPv4 subnet. A gateway that
    /// doesn't is unreachable no matter how healthy it is.
    pub fn v4_contains(&self, other: IpAddr) -> Option<bool> {
        let (ip, prefix) = self.v4?;
        let IpAddr::V4(other) = other else {
            return None;
        };
        // A /0 would shift by 32, which is UB-adjacent in Rust (it panics in
        // debug). Treat it as "everything is inside", which is what /0 means.
        let mask = if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix.min(32))
        };
        Some(u32::from(ip) & mask == u32::from(other) & mask)
    }
}

/// Resolver configuration facts.
#[derive(Debug, Clone, Default)]
pub struct ResolverInfo {
    pub nameservers: Vec<IpAddr>,
}

/// VPN / overlay-tunnel facts. Distinct from [`RouteInfo::tunnel_active`],
/// which only says *whether* a tunnel exists; this describes it.
#[derive(Debug, Clone, Default)]
pub struct VpnInfo {
    /// True when a tunnel interface is part of the active network state.
    pub active: bool,
    /// Tunnel interface backing it, e.g. `utun4`.
    pub interface: Option<String>,
    /// The tunnel-assigned local address, when configured.
    pub local_ip: Option<IpAddr>,
    /// Best-effort vendor label inferred from the tunnel address, e.g.
    /// `Tailscale` for the 100.64.0.0/10 CGNAT range. `None` when unknown.
    pub vendor: Option<String>,
}

/// Errors from platform data acquisition.
#[derive(Debug)]
pub enum PlatformError {
    /// A required command was not found or failed to spawn.
    Command(String),
    /// The command ran but its output could not be parsed as expected.
    Parse(String),
    /// No default route / no active network.
    NoNetwork,
    /// No platform module for this OS. Distinct from `NoNetwork`: the network
    /// may well be fine, wtfi just can't see it here.
    Unsupported,
}

impl std::fmt::Display for PlatformError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PlatformError::Command(c) => write!(f, "command failed: {c}"),
            PlatformError::Parse(m) => write!(f, "parse error: {m}"),
            PlatformError::NoNetwork => write!(f, "no active network / default route"),
            PlatformError::Unsupported => {
                write!(f, "unsupported platform: no module for this OS")
            }
        }
    }
}

impl std::error::Error for PlatformError {}

/// OS-specific gatherer of raw network facts.
pub trait Platform: Send + Sync {
    /// Resolve the default route (gateway + interface + MTU).
    fn route(&self) -> Result<RouteInfo, PlatformError>;
    /// Gather link-layer telemetry for the given interface.
    fn link(&self, interface: &str) -> Result<LinkInfo, PlatformError>;
    /// Read the addresses configured on an interface.
    fn addrs(&self, interface: &str) -> Result<AddrInfo, PlatformError>;
    /// The interface to inspect when there is no default route to name one.
    /// Without this, the state worth diagnosing most — a link that came up but
    /// never got an address — would be the state wtfi cannot look at.
    fn primary_interface(&self) -> Result<String, PlatformError>;
    /// Read the configured DNS resolvers.
    fn resolvers(&self) -> Result<ResolverInfo, PlatformError>;
    /// Describe the active VPN/overlay tunnel, if any. An inactive result
    /// (`VpnInfo::active == false`) is normal, not an error.
    fn vpn(&self) -> Result<VpnInfo, PlatformError>;
}

/// Return the platform implementation for the current OS.
#[cfg(target_os = "macos")]
pub fn current() -> impl Platform {
    macos::MacOs::new()
}

/// Return the platform implementation for the current OS.
#[cfg(not(target_os = "macos"))]
pub fn current() -> impl Platform {
    unsupported::Unsupported
}
