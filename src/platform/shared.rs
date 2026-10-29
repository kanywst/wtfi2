//! Parsing helpers and heuristics shared by every real [`super::Platform`].
//!
//! Whatever a platform reads its facts *with*, some conclusions are drawn the
//! same way: which address is only link-local, and which VPN a tunnel belongs
//! to. Keeping one copy means a vendor added for one OS reaches the others.

use super::PlatformError;
use std::io::Read;
use std::net::IpAddr;
use std::process::{Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

/// Ceiling on one system tool: past the probe's own deadline nobody is waiting for it.
pub(super) const TOOL_DEADLINE: Duration = crate::engine::PROBE_DEADLINE;

/// How long an OS log read may take before it is abandoned.
pub(super) const LOG_DEADLINE: Duration = Duration::from_secs(30);

/// [`output_within`], treating a non-zero exit with no output as an error.
/// The third value says why a non-zero exit may have cut the output short.
pub(super) fn run_bounded(
    cmd: &str,
    args: &[&str],
    deadline: Duration,
) -> Result<(String, String, Option<String>), PlatformError> {
    let (status, out, err) = output_within(cmd, args, deadline)?;
    if !status.success() && out.trim().is_empty() {
        let why = err.trim();
        return Err(PlatformError::Command(if why.is_empty() {
            format!("{cmd}: {status}")
        } else {
            format!("{cmd}: {why}")
        }));
    }
    let early = (!status.success()).then(|| match err.trim() {
        "" => format!("{cmd} exited with {status}"),
        why => format!("{cmd}: {why}"),
    });
    Ok((out, err, early))
}

/// Run `cmd`, killing it at `deadline`; returns its status, stdout and stderr.
pub(super) fn output_within(
    cmd: &str,
    args: &[&str],
    deadline: Duration,
) -> Result<(ExitStatus, String, String), PlatformError> {
    let fail = |e: std::io::Error| PlatformError::Command(format!("{cmd}: {e}"));
    let mut child = Command::new(cmd)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(fail)?;
    let out = drain(Box::new(child.stdout.take().unwrap()));
    let err = drain(Box::new(child.stderr.take().unwrap()));
    let start = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().map_err(fail)? {
            break status;
        }
        if start.elapsed() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(PlatformError::Command(format!(
                "{cmd}: gave up after {}s",
                deadline.as_secs()
            )));
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    // A helper the tool left behind can hold the pipes open past the deadline.
    let until = Instant::now()
        + deadline
            .saturating_sub(start.elapsed())
            .max(Duration::from_millis(100));
    match (out.collect(until), err.collect(until)) {
        (Some(out), Some(err)) => Ok((status, out, err)),
        _ => Err(PlatformError::Command(format!(
            "{cmd}: output still open after exit"
        ))),
    }
}

struct Drain {
    buf: Arc<Mutex<Vec<u8>>>,
    done: mpsc::Receiver<()>,
}

impl Drain {
    /// Everything the pipe carried, or `None` if it wasn't read to the end by `until`.
    fn collect(self, until: Instant) -> Option<String> {
        self.done
            .recv_timeout(until.saturating_duration_since(Instant::now()))
            .ok()?;
        let buf = self.buf.lock().ok()?.clone();
        Some(String::from_utf8_lossy(&buf).into_owned())
    }
}

fn drain(mut pipe: Box<dyn Read + Send>) -> Drain {
    let buf = Arc::new(Mutex::new(Vec::new()));
    let (tx, done) = mpsc::channel();
    let sink = buf.clone();
    std::thread::spawn(move || {
        let mut chunk = [0u8; 8192];
        loop {
            match pipe.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    if let Ok(mut b) = sink.lock() {
                        b.extend_from_slice(&chunk[..n]);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                // Dropping `tx` unsent marks the read as incomplete.
                Err(_) => return,
            }
        }
        let _ = tx.send(());
    });
    Drain { buf, done }
}

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
    fn a_wedged_tool_is_killed_at_its_deadline() {
        let (status, out, err) = output_within(
            "sh",
            &["-c", "echo hi; echo oops >&2; exit 3"],
            TOOL_DEADLINE,
        )
        .unwrap();
        assert_eq!(
            (status.code(), out.trim(), err.trim()),
            (Some(3), "hi", "oops")
        );
        let start = Instant::now();
        let slow = output_within("sleep", &["5"], Duration::from_millis(200));
        assert!(matches!(slow, Err(PlatformError::Command(m)) if m.contains("gave up")));
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn a_helper_holding_the_pipe_doesnt_outlast_the_deadline() {
        let start = Instant::now();
        let held = output_within(
            "sh",
            &["-c", "echo hi; (sleep 5 &) ; exit 0"],
            Duration::from_millis(500),
        );
        assert!(
            matches!(held, Err(PlatformError::Command(m)) if m.contains("still open")),
            "half-read output isn't passed off as complete"
        );
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "{:?}",
            start.elapsed()
        );
    }

    #[test]
    fn tools_get_no_stdin() {
        let (_, out, _) = output_within("sh", &["-c", "cat; echo done"], TOOL_DEADLINE).unwrap();
        assert_eq!(out.trim(), "done");
    }

    #[test]
    fn a_silent_failure_is_an_error() {
        let silent = run_bounded("sh", &["-c", "exit 3"], LOG_DEADLINE);
        assert!(matches!(silent, Err(PlatformError::Command(m)) if m.contains("3")));
        let (out, _, early) = run_bounded("sh", &["-c", "echo hi; exit 1"], LOG_DEADLINE).unwrap();
        assert_eq!(out.trim(), "hi", "output wins over the exit code");
        assert!(early.is_some(), "but the early exit is reported");
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
}
