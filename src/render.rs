//! One-shot text report: an ANSI topology diagram + verdict + per-hop detail.

use crate::diagnose::{Confidence, Verdict};
use crate::model::{Path, Status};

/// Minimal ANSI palette, toggleable for `--no-color` / non-TTY.
struct Palette {
    on: bool,
}

impl Palette {
    fn paint(&self, code: &str, s: &str) -> String {
        if self.on {
            format!("\x1b[{code}m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }
    fn status(&self, st: Status, s: &str) -> String {
        self.paint(status_code(st), s)
    }
    fn dim(&self, s: &str) -> String {
        self.paint("2", s)
    }
    fn bold(&self, s: &str) -> String {
        self.paint("1", s)
    }
}

fn status_code(st: Status) -> &'static str {
    match st {
        Status::Ok => "32",      // green
        Status::Warn => "33",    // yellow
        Status::Fail => "31",    // red
        Status::Pending => "36", // cyan
        Status::Skipped => "90", // bright black
    }
}

/// Render the full report to a string.
pub fn report(path: &Path, verdict: &Verdict, verbose: bool, color: bool) -> String {
    let p = Palette { on: color };
    let mut out = String::new();

    out.push('\n');
    out.push_str(&p.bold(" wtfi "));
    out.push_str(&p.dim("· what the f*ck internet\n\n"));

    out.push_str(&topology(path, &p));
    out.push_str("\n\n");
    out.push_str(&verdict_block(path, verdict, &p));
    out.push('\n');
    out.push_str(&detail(path, &p, verbose));

    out
}

/// The headline: a horizontal chain of nodes with the break marked.
fn topology(path: &Path, p: &Palette) -> String {
    let mut line = String::from("  ");
    let mut broke = false;
    for (i, hop) in path.hops.iter().enumerate() {
        if i > 0 {
            // The connector inherits the worse of the two adjacent statuses,
            // and turns into an explicit break glyph at the first failure.
            let prev = path.hops[i - 1].status;
            let sev = prev.max(hop.status);
            let conn = if !broke && hop.status == Status::Fail {
                broke = true;
                p.status(Status::Fail, " ─✗─ ")
            } else {
                p.status(sev, " ─── ")
            };
            line.push_str(&conn);
        }
        let node = format!("{} {}", hop.status.glyph(), hop.title);
        line.push_str(&p.status(hop.status, &node));
    }
    line
}

/// What the hop behind the verdict actually measured, when it recorded it.
fn verdict_evidence(path: &Path, v: &Verdict) -> Option<String> {
    path.get(v.source?)?.evidence.clone()
}

fn verdict_block(path: &Path, v: &Verdict, p: &Palette) -> String {
    let mut s = String::new();
    let tag = match v.status {
        Status::Ok => "  ALL GOOD ",
        Status::Warn => "  DEGRADED ",
        // Nothing measured is not the same as measured-and-broken. Exhaustive
        // on purpose: a catch-all arm is how Skipped ended up here as BROKEN.
        Status::Skipped => "  UNKNOWN  ",
        Status::Pending => "  SCANNING ",
        Status::Fail => "  BROKEN   ",
    };
    s.push_str(&p.status(v.status, &p.bold(tag)));
    s.push_str(&p.bold(&format!("{} {}\n", v.status.glyph(), v.headline)));
    s.push_str(&format!("            {}\n", p.dim(&v.cause)));
    if let Some(fix) = &v.fix {
        s.push_str(&format!(
            "            {} {}\n",
            p.status(Status::Ok, "→"),
            fix
        ));
    }
    // What the claim rests on. Without it the reader has no way to tell a
    // thorough measurement from a single timed-out packet.
    if let Some(evidence) = verdict_evidence(path, v) {
        s.push_str(&format!(
            "            {} {}\n",
            p.dim("evidence:"),
            p.dim(&evidence)
        ));
    }
    let conf = match v.confidence {
        Confidence::Certain => "",
        Confidence::Likely => "  (likely cause)",
        Confidence::Guess => "  (best guess)",
    };
    if !conf.is_empty() {
        s.push_str(&p.dim(&format!("           {conf}\n")));
    }
    s
}

fn detail(path: &Path, p: &Palette, verbose: bool) -> String {
    let mut s = String::new();
    // The host hop is listed like any other: it carries this machine's address,
    // subnet and DHCP state now, which is the first thing you want when the
    // question is "is it me?".
    for hop in &path.hops {
        let head = format!(
            "  {} {:<9} {}",
            hop.status.glyph(),
            hop.title,
            hop.subtitle.clone().unwrap_or_default(),
        );
        s.push_str(&p.status(hop.status, &head));
        s.push('\n');
        if let Some(sum) = &hop.summary {
            s.push_str(&format!("      {}\n", p.dim(sum)));
        }
        if verbose {
            // Every hop's method, not just the one that owns the verdict: in
            // verbose mode the reader is checking the working, and a metric
            // means little without knowing how it was taken.
            if let Some(evidence) = &hop.evidence {
                s.push_str(&format!("      {}\n", p.dim(&format!("↳ {evidence}"))));
            }
            for m in &hop.metrics {
                let v = match m.status {
                    Some(st) => p.status(st, &m.value),
                    None => m.value.clone(),
                };
                s.push_str(&format!(
                    "      {} {}\n",
                    p.dim(&format!("{}:", m.label)),
                    v
                ));
            }
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diagnose::diagnose;
    use crate::model::{Hop, HopId, Layer, Metric, Path};

    fn ok(id: HopId, layer: Layer, title: &str) -> Hop {
        let mut h = Hop::new(id, layer, title);
        h.status = Status::Ok;
        h
    }

    #[test]
    fn lossy_path_reports_degraded_even_with_no_broken_hop() {
        // End-to-end through the real diagnosis and renderer: no hop is down,
        // so the topology stays unbroken, yet the report must not say "all
        // good" — it has to name the loss and where it is.
        let mut gw = ok(HopId::Gateway, Layer::Network, "Gateway");
        gw.status = Status::Warn;
        gw.loss_pct = Some(40.0);
        gw.summary = Some("Router answers (4 ms) but the local path is unhealthy".into());
        gw.metrics
            .push(Metric::new("Loss", "40% (2/5 lost)").with_status(Status::Warn));
        let path = Path {
            hops: vec![
                ok(HopId::Link, Layer::Link, "Wi-Fi"),
                gw,
                ok(HopId::Wan, Layer::Internet, "Internet"),
                ok(HopId::Dns, Layer::Application, "DNS"),
            ],
        };
        let out = report(&path, &diagnose(&path), true, false);
        assert!(
            out.contains("DEGRADED"),
            "must not read as all-good:\n{out}"
        );
        assert!(out.contains("dropping packets"));
        assert!(out.contains("40%"));
        assert!(!out.contains("─✗─"), "nothing is broken, so no break glyph");
    }

    /// A verdict the reader can't check is one they have to take on trust,
    /// and "your ISP is down" is far too strong a claim to hand over without
    /// the method behind it.
    #[test]
    fn the_verdict_shows_what_the_owning_hop_measured() {
        let mut wan = ok(HopId::Wan, Layer::Internet, "Internet");
        wan.status = Status::Fail;
        wan.fault = Some(crate::model::Fault::NoInternet);
        wan.summary = Some("No TCP path to the internet".into());
        wan.evidence = Some("5 handshakes to :443 across 3 independent operators".into());
        let path = Path {
            hops: vec![
                ok(HopId::Link, Layer::Link, "Wi-Fi"),
                ok(HopId::Gateway, Layer::Network, "Gateway"),
                wan,
            ],
        };
        let out = report(&path, &diagnose(&path), false, false);
        assert!(out.contains("evidence:"), "no evidence line:\n{out}");
        assert!(
            out.contains("3 independent operators"),
            "the method must be quoted:\n{out}"
        );
    }

    /// A hop with nothing to say about its method must not print an empty
    /// label — a bare "evidence:" is worse than none.
    #[test]
    fn a_hop_without_evidence_prints_no_evidence_line() {
        let mut gw = ok(HopId::Gateway, Layer::Network, "Gateway");
        gw.status = Status::Fail;
        gw.fault = Some(crate::model::Fault::GatewaySilent);
        let path = Path {
            hops: vec![ok(HopId::Link, Layer::Link, "Wi-Fi"), gw],
        };
        let out = report(&path, &diagnose(&path), false, false);
        assert!(!out.contains("evidence:"), "got:\n{out}");
    }

    /// In verbose mode the reader is checking the working, so every hop's
    /// method is shown — not just the one that owns the verdict.
    #[test]
    fn verbose_shows_the_method_for_every_hop() {
        let mut gw = ok(HopId::Gateway, Layer::Network, "Gateway");
        gw.evidence = Some("5 ICMP echoes to 192.168.0.1".into());
        let mut dns = ok(HopId::Dns, Layer::Application, "DNS");
        dns.evidence = Some("3 resolvers queried".into());
        let path = Path {
            hops: vec![ok(HopId::Link, Layer::Link, "Wi-Fi"), gw, dns],
        };
        let out = report(&path, &diagnose(&path), true, false);
        assert!(out.contains("5 ICMP echoes"), "got:\n{out}");
        assert!(out.contains("3 resolvers queried"), "got:\n{out}");
        // …and stays out of the way when it isn't asked for.
        let terse = report(&path, &diagnose(&path), false, false);
        assert!(!terse.contains("5 ICMP echoes"), "got:\n{terse}");
    }

    #[test]
    fn vpn_hop_renders_in_topology_and_detail() {
        // A conditional VPN hop sits between Gateway and Internet and must show
        // up in both the topology chain and the per-hop detail block.
        let mut vpn = ok(HopId::Vpn, Layer::Network, "VPN");
        vpn.subtitle = Some("Tailscale".into());
        vpn.summary = Some("Tailscale full-tunnel VPN on utun4".into());
        vpn.metrics.push(Metric::new("Mode", "full-tunnel"));
        let path = Path {
            hops: vec![
                ok(HopId::Link, Layer::Link, "Wi-Fi"),
                ok(HopId::Gateway, Layer::Network, "Gateway"),
                vpn,
                ok(HopId::Wan, Layer::Internet, "Internet"),
                ok(HopId::Dns, Layer::Application, "DNS"),
            ],
        };
        let out = report(&path, &diagnose(&path), true, false);
        assert!(out.contains("VPN"), "topology/detail must name the VPN hop");
        assert!(out.contains("Tailscale full-tunnel VPN on utun4"));
        // Chain order: VPN between Gateway and Internet.
        let g = out.find("Gateway").unwrap();
        let v = out.find("VPN").unwrap();
        let i = out.find("Internet").unwrap();
        assert!(
            g < v && v < i,
            "VPN must render between Gateway and Internet"
        );
    }
}
