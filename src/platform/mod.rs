//! Platform abstraction layer.
//!
//! Each OS provides a [`Platform`] implementation that gathers raw, low-level
//! network facts (link telemetry, default route, resolvers). The probe engine
//! consumes these facts and never touches OS-specific commands directly, so a
//! new OS only needs a new `Platform` impl — nothing above this layer changes.

use std::net::IpAddr;

#[cfg(target_os = "macos")]
pub mod macos;

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
    pub mtu: Option<u32>,
    /// True when a VPN/tunnel interface (utun/tailscale) owns a route.
    pub tunnel_active: bool,
    pub tunnel_iface: Option<String>,
}

/// Resolver configuration facts.
#[derive(Debug, Clone, Default)]
pub struct ResolverInfo {
    pub nameservers: Vec<IpAddr>,
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
}

impl std::fmt::Display for PlatformError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PlatformError::Command(c) => write!(f, "command failed: {c}"),
            PlatformError::Parse(m) => write!(f, "parse error: {m}"),
            PlatformError::NoNetwork => write!(f, "no active network / default route"),
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
    /// Read the configured DNS resolvers.
    fn resolvers(&self) -> Result<ResolverInfo, PlatformError>;
}

/// Return the platform implementation for the current OS.
#[cfg(target_os = "macos")]
pub fn current() -> impl Platform {
    macos::MacOs::new()
}
