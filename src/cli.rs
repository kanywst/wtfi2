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

    /// Disable ANSI color in the text report.
    #[arg(long = "no-color")]
    pub no_color: bool,

    /// Give up on the whole sweep after this many seconds and report what
    /// landed. Individual probes are bounded well below this already; raise it
    /// only on a network so slow that whole probes are timing out.
    #[arg(long = "timeout", value_name = "SECS", default_value_t = crate::engine::SWEEP_DEADLINE.as_secs())]
    pub timeout_secs: u64,
}

impl Cli {
    /// The sweep ceiling, floored at one second so `--timeout 0` can't turn
    /// every run into an instant "nothing was measured".
    pub fn sweep_deadline(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.timeout_secs.max(1))
    }
}

impl Cli {
    pub fn parse_args() -> Self {
        Cli::parse()
    }
}
