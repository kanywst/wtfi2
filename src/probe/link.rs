//! L2 link probe: turn raw [`LinkInfo`] into a graded hop.

use crate::model::{Hop, HopId, Layer, Metric, Status};
use crate::platform::{LinkInfo, Platform, PlatformError};

/// Assess the Wi-Fi link for `interface` using the platform layer.
pub fn probe(platform: &dyn Platform, interface: &str) -> Hop {
    let mut hop = Hop::new(HopId::Link, Layer::Link, "Wi-Fi");
    match platform.link(interface) {
        Ok(info) if info.is_wifi => grade(&mut hop, &info),
        Ok(mut info) => {
            // Associated interface but not Wi-Fi (wired / unknown).
            info.interface = interface.to_string();
            hop.status = Status::Ok;
            hop.title = "Link".into();
            hop.subtitle = Some(interface.to_string());
            hop.summary = Some("Wired or non-Wi-Fi link is up".into());
        }
        Err(PlatformError::NoNetwork) => {
            hop.status = Status::Fail;
            hop.summary = Some("Not associated with any access point".into());
        }
        Err(e) => {
            hop.status = Status::Warn;
            hop.summary = Some(format!("Couldn't read link telemetry: {e}"));
        }
    }
    hop
}

fn grade(hop: &mut Hop, info: &LinkInfo) {
    hop.subtitle = Some(info.ssid.clone().unwrap_or_else(|| info.interface.clone()));

    let rssi = info.rssi_dbm;
    let snr = info.snr_db();

    // Grade primarily on RSSI, cross-checked by SNR.
    hop.status = match (rssi, snr) {
        (Some(r), _) if r >= -67 => Status::Ok,
        (Some(r), Some(s)) if r >= -75 && s >= 20 => Status::Ok,
        (Some(r), _) if r >= -75 => Status::Warn,
        (Some(_), _) => Status::Warn,
        (None, _) => Status::Ok, // no signal data (e.g. wired) — don't punish
    };

    hop.summary = Some(match (rssi, snr) {
        (Some(r), Some(s)) => format!("{} · {r} dBm (SNR {s} dB)", signal_word(r)),
        (Some(r), None) => format!("{} · {r} dBm", signal_word(r)),
        _ => "Link up".into(),
    });

    if let Some(r) = rssi {
        hop.metrics
            .push(Metric::new("RSSI", format!("{r} dBm")).with_status(hop.status));
    }
    if let Some(n) = info.noise_dbm {
        hop.metrics.push(Metric::new("Noise", format!("{n} dBm")));
    }
    if let Some(s) = snr {
        hop.metrics.push(Metric::new("SNR", format!("{s} dB")));
    }
    if let (Some(ch), band) = (info.channel, info.band.clone()) {
        let w = info
            .width_mhz
            .map(|w| format!(" / {w}MHz"))
            .unwrap_or_default();
        hop.metrics.push(Metric::new(
            "Channel",
            format!(
                "{ch}{}{w}",
                band.map(|b| format!(" ({b})")).unwrap_or_default()
            ),
        ));
    }
    if let Some(p) = &info.phy_mode {
        hop.metrics.push(Metric::new("PHY", p.clone()));
    }
    if let Some(sec) = &info.security {
        let weak = sec.contains("WEP") || sec.contains("WPA ") || sec == "WPA";
        let m = Metric::new("Security", sec.clone());
        hop.metrics
            .push(if weak { m.with_status(Status::Warn) } else { m });
    }
    if let Some(tx) = info.tx_rate_mbps {
        hop.metrics
            .push(Metric::new("Tx Rate", format!("{tx} Mbps")));
    }
    if info.ssid.is_none() {
        hop.metrics
            .push(Metric::new("SSID", "hidden (grant Location access)").with_status(Status::Warn));
    }
}

fn signal_word(rssi: i32) -> &'static str {
    match rssi {
        r if r >= -55 => "Excellent",
        r if r >= -67 => "Good",
        r if r >= -75 => "Fair",
        _ => "Weak",
    }
}
