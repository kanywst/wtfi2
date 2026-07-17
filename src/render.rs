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
    out.push_str(&verdict_block(verdict, &p));
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

fn verdict_block(v: &Verdict, p: &Palette) -> String {
    let mut s = String::new();
    let tag = match v.status {
        Status::Ok => "  ALL GOOD ",
        Status::Warn => "  DEGRADED ",
        _ => "  BROKEN   ",
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
    for hop in &path.hops {
        if hop.id == crate::model::HopId::Host {
            continue;
        }
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
