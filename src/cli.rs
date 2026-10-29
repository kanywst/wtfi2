//! Command-line surface.

use clap::Parser;

/// What The F*ck Internet — pinpoint exactly where your connection dies.
#[derive(Debug, Parser)]
#[command(name = "wtfi", version, about, long_about = None)]
pub struct Cli {
    /// Live dashboard: re-probe continuously and watch the path in real time.
    #[arg(short = 'w', long = "watch")]
    pub watch: bool,

    /// Emit the diagnosis as JSON instead of a human report.
    #[arg(long = "json", conflicts_with = "watch")]
    pub json: bool,

    /// Show every metric for every hop, not just the summary.
    #[arg(short = 'v', long = "verbose")]
    pub verbose: bool,

    /// Append each finished sweep to the history file.
    #[arg(long = "record")]
    pub record: bool,

    /// With --record: keep sweeping every DURATION (30s, 5m) without the dashboard.
    #[arg(long = "every", value_name = "DURATION", value_parser = parse_duration, requires = "record", conflicts_with_all = ["watch", "json"])]
    pub every: Option<std::time::Duration>,

    /// Print the newest N recorded sweeps (default 20) instead of probing.
    #[arg(long = "history", value_name = "N", num_args = 0..=1, default_missing_value = "20", conflicts_with_all = ["watch", "record"])]
    pub history: Option<usize>,

    /// Print recorded sweeps from the last SINCE (default 24h) as Markdown to paste into an AI agent.
    #[arg(long = "bundle", value_name = "SINCE", num_args = 0..=1, default_missing_value = "24h", value_parser = parse_duration, conflicts_with_all = ["watch", "record", "history", "json"])]
    pub bundle: Option<std::time::Duration>,

    /// With --bundle: keep SSIDs, public IPs and portal URLs unmasked.
    #[arg(long = "no-redact", requires = "bundle")]
    pub no_redact: bool,

    /// Serve the recorded history to an AI agent as an MCP server on stdio.
    #[arg(long = "mcp", conflicts_with_all = ["watch", "record", "history", "json", "bundle"])]
    pub mcp: bool,

    /// Disable ANSI color in the text report.
    #[arg(long = "no-color")]
    pub no_color: bool,

    /// Give up on the whole sweep after this many seconds and report what
    /// landed. Individual probes are bounded well below this already; raise it
    /// only on a network so slow that whole probes are timing out.
    #[arg(long = "timeout", value_name = "SECS", default_value_t = crate::engine::SWEEP_DEADLINE.as_secs())]
    pub timeout_secs: u64,

    /// Replay a scripted sweep instead of probing: `healthy`, `dns` or `isp`.
    /// Bare `--demo` cycles healthy → DNS outage → recovery under `-w`.
    #[cfg(feature = "demo")]
    #[arg(long = "demo", hide = true, value_name = "SCENARIO", num_args = 0..=1, default_missing_value = "")]
    pub demo: Option<String>,
}

impl Cli {
    /// The sweep ceiling, floored at one second so `--timeout 0` can't turn
    /// every run into an instant "nothing was measured".
    pub fn sweep_deadline(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.timeout_secs.max(1))
    }
}

/// `90`, `90s`, `5m`, `2h` or `1d`.
pub fn parse_duration(s: &str) -> Result<std::time::Duration, String> {
    let s = s.trim();
    let (num, unit) = s.split_at(s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len()));
    let n: u64 = num.parse().map_err(|_| format!("not a duration: {s:?}"))?;
    let scale = match unit {
        "" | "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86_400,
        _ => return Err(format!("unknown unit {unit:?} (use s, m, h or d)")),
    };
    let secs = n.checked_mul(scale).ok_or("too long")?;
    if secs == 0 {
        return Err("must be at least 1s".into());
    }
    Ok(std::time::Duration::from_secs(secs))
}

impl Cli {
    pub fn parse_args() -> Self {
        Cli::parse()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn durations_parse_with_or_without_a_unit() {
        assert_eq!(parse_duration("90"), Ok(Duration::from_secs(90)));
        assert_eq!(parse_duration("30s"), Ok(Duration::from_secs(30)));
        assert_eq!(parse_duration("5m"), Ok(Duration::from_secs(300)));
        assert_eq!(parse_duration("2h"), Ok(Duration::from_secs(7200)));
        assert_eq!(parse_duration("1d"), Ok(Duration::from_secs(86_400)));
        for bad in [
            "",
            "m",
            "0",
            "5x",
            "-3",
            "1.5h",
            "999999999999999d",
            "99999999999999999999",
        ] {
            assert!(parse_duration(bad).is_err(), "{bad:?} should be rejected");
        }
    }
}
