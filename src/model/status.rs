//! Probe outcome status with an ordered severity.

use std::cmp::Ordering;

/// Outcome of a single probe / hop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Not yet run (live dashboard shows a spinner).
    Pending,
    /// Deliberately not run on this platform / config.
    Skipped,
    /// Healthy.
    Ok,
    /// Working but degraded (weak signal, slow DNS, IPv6 down…).
    Warn,
    /// Broken — this is where connectivity dies.
    Fail,
}

impl Status {
    /// Higher = worse. Used to find the first/worst break in the path.
    pub fn severity(self) -> u8 {
        match self {
            Status::Pending => 0,
            Status::Skipped => 0,
            Status::Ok => 1,
            Status::Warn => 2,
            Status::Fail => 3,
        }
    }

    /// A single glyph for compact rendering.
    pub fn glyph(self) -> &'static str {
        match self {
            Status::Pending => "…",
            Status::Skipped => "–",
            Status::Ok => "✓",
            Status::Warn => "!",
            Status::Fail => "✗",
        }
    }

    /// Whether the probe has settled. `Skipped` counts as settled — otherwise
    /// an outage (which legitimately skips downstream hops) would leave the
    /// live dashboard stuck on "scanning" and never render a verdict.
    pub fn is_terminal(self) -> bool {
        !matches!(self, Status::Pending)
    }
}

impl PartialOrd for Status {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Status {
    fn cmp(&self, other: &Self) -> Ordering {
        self.severity().cmp(&other.severity())
    }
}
