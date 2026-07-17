//! Low-level, no-root network measurement helpers shared by probes.
//!
//! macOS raw ICMP sockets require root, so we lean on primitives that work
//! unprivileged: the setuid `ping` binary for ICMP RTT, and plain TCP connects
//! (which also exercise the real forwarding path better than ICMP for WAN).

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::process::Command;
use tokio::time::timeout;

/// Result of a single latency measurement.
#[derive(Debug, Clone, Copy)]
pub enum Probe {
    /// Reached, with round-trip time.
    Up(Duration),
    /// No response within the timeout.
    Timeout,
    /// Could not even attempt (tool missing, bad address).
    Error,
}

impl Probe {
    pub fn ms(self) -> Option<f64> {
        match self {
            Probe::Up(d) => Some(d.as_secs_f64() * 1000.0),
            _ => None,
        }
    }
    pub fn is_up(self) -> bool {
        matches!(self, Probe::Up(_))
    }
}

/// ICMP-ping an address via the system `ping`/`ping6` binary (setuid, no sudo).
///
/// `zone` carries the scope id for a link-local IPv6 target (`fe80::1%en0`),
/// without which the kernel can't pick an egress interface.
pub async fn ping(addr: IpAddr, zone: Option<&str>, wait: Duration) -> Probe {
    let secs = wait.as_secs().max(1).to_string();
    let (bin, target) = match addr {
        IpAddr::V4(v4) => ("ping", v4.to_string()),
        IpAddr::V6(v6) => match zone {
            Some(z) => ("ping6", format!("{v6}%{z}")),
            None => ("ping6", v6.to_string()),
        },
    };
    let out = Command::new(bin)
        .args(["-c", "1", "-t", &secs, &target])
        .output()
        .await;
    let out = match out {
        Ok(o) => o,
        Err(_) => return Probe::Error,
    };
    if !out.status.success() {
        return Probe::Timeout;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    parse_ping_ms(&text)
        .map(|ms| Probe::Up(Duration::from_secs_f64(ms / 1000.0)))
        .unwrap_or(Probe::Timeout)
}

/// Pull `time=3.456 ms` out of ping output.
fn parse_ping_ms(text: &str) -> Option<f64> {
    let idx = text.find("time=")?;
    text[idx + 5..]
        .split_whitespace()
        .next()?
        .parse::<f64>()
        .ok()
}

/// Measure the time to complete a TCP handshake to `addr`.
pub async fn tcp_connect(addr: SocketAddr, wait: Duration) -> Probe {
    let start = Instant::now();
    match timeout(wait, TcpStream::connect(addr)).await {
        Ok(Ok(_stream)) => Probe::Up(start.elapsed()),
        Ok(Err(_)) => Probe::Timeout,
        Err(_) => Probe::Timeout,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ping_time() {
        let line = "64 bytes from 192.168.0.1: icmp_seq=0 ttl=64 time=3.456 ms";
        assert_eq!(parse_ping_ms(line), Some(3.456));
    }

    #[test]
    fn no_time_field_is_none() {
        assert_eq!(parse_ping_ms("Request timeout for icmp_seq 0"), None);
    }
}
