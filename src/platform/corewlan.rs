//! CoreWLAN link source (macOS).
//!
//! Reads the associated Wi-Fi state directly from `CWWiFiClient` /
//! `CWInterface`. This is effectively instant, unlike the multi-second
//! `system_profiler SPAirPortDataType` spawn, so the live dashboard fills the
//! Wi-Fi node immediately.
//!
//! RSSI / noise / channel / PHY / security / tx-rate are available without
//! sudo or Location permission. SSID / BSSID stay `nil` on an unsigned binary
//! (macOS gates them behind Location authorization), which we handle the same
//! way as a redacted `system_profiler` reading.

use super::LinkInfo;
use objc2_core_wlan::{CWChannelBand, CWChannelWidth, CWPHYMode, CWSecurity, CWWiFiClient};

/// Read the current Wi-Fi link via CoreWLAN, or `None` if unavailable / not
/// associated (the caller then falls back to `system_profiler`).
pub fn read_link(interface: &str) -> Option<LinkInfo> {
    // SAFETY: standard CoreWLAN accessors; each returns nil/0 on error, which
    // we treat as "unknown". No mutation, no main-thread requirement.
    unsafe {
        let client = CWWiFiClient::sharedWiFiClient();
        let iface = client.interface()?;

        let rssi = iface.rssiValue();
        let ssid = iface.ssid();
        // rssi == 0 with no SSID means "not associated" — let the fallback speak.
        if rssi == 0 && ssid.is_none() {
            return None;
        }

        let mut info = LinkInfo {
            interface: interface.to_string(),
            is_wifi: true,
            rssi_dbm: Some(rssi as i32),
            noise_dbm: Some(iface.noiseMeasurement() as i32),
            ssid: ssid.map(|s| s.to_string()),
            bssid: iface.bssid().map(|s| s.to_string()),
            phy_mode: phy_mode_str(iface.activePHYMode()),
            security: security_str(iface.security()),
            ..Default::default()
        };

        let tx = iface.transmitRate();
        if tx > 0.0 {
            info.tx_rate_mbps = Some(tx.round() as u32);
        }

        if let Some(ch) = iface.wlanChannel() {
            let n = ch.channelNumber();
            if n > 0 {
                info.channel = Some(n as u32);
            }
            info.band = band_str(ch.channelBand());
            info.width_mhz = width_mhz(ch.channelWidth());
        }

        Some(info)
    }
}

fn phy_mode_str(m: CWPHYMode) -> Option<String> {
    let s = match m.0 {
        1 => "802.11a",
        2 => "802.11b",
        3 => "802.11g",
        4 => "802.11n",
        5 => "802.11ac",
        6 => "802.11ax",
        _ => return None,
    };
    Some(s.to_string())
}

/// Human labels aligned with `system_profiler` so link grading (weak-security
/// detection) behaves identically across both sources.
fn security_str(s: CWSecurity) -> Option<String> {
    let s = match s.0 {
        0 => "None",
        1 => "WEP",
        2 => "WPA Personal",
        3 => "WPA/WPA2 Personal",
        4 => "WPA2 Personal",
        5 => "Personal",
        7 => "WPA Enterprise",
        8 => "WPA/WPA2 Enterprise",
        9 => "WPA2 Enterprise",
        10 => "Enterprise",
        11 => "WPA3 Personal",
        12 => "WPA3 Enterprise",
        13 => "WPA3 Transition",
        _ => return None,
    };
    Some(s.to_string())
}

fn band_str(b: CWChannelBand) -> Option<String> {
    let s = match b.0 {
        1 => "2GHz",
        2 => "5GHz",
        3 => "6GHz",
        _ => return None,
    };
    Some(s.to_string())
}

fn width_mhz(w: CWChannelWidth) -> Option<u32> {
    match w.0 {
        1 => Some(20),
        2 => Some(40),
        3 => Some(80),
        4 => Some(160),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phy_modes_map() {
        assert_eq!(phy_mode_str(CWPHYMode(5)).as_deref(), Some("802.11ac"));
        assert_eq!(phy_mode_str(CWPHYMode(6)).as_deref(), Some("802.11ax"));
        assert_eq!(phy_mode_str(CWPHYMode(0)), None);
    }

    #[test]
    fn security_maps_align_with_system_profiler_labels() {
        assert_eq!(
            security_str(CWSecurity(4)).as_deref(),
            Some("WPA2 Personal")
        );
        assert_eq!(
            security_str(CWSecurity(11)).as_deref(),
            Some("WPA3 Personal")
        );
        // WEP must be detectable as weak by the link grader.
        assert!(security_str(CWSecurity(1)).unwrap().contains("WEP"));
    }

    #[test]
    fn channel_band_and_width_map() {
        assert_eq!(band_str(CWChannelBand(2)).as_deref(), Some("5GHz"));
        assert_eq!(width_mhz(CWChannelWidth(3)), Some(80));
        assert_eq!(width_mhz(CWChannelWidth(0)), None);
    }
}
