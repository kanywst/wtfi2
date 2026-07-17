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
}

impl Cli {
    pub fn parse_args() -> Self {
        Cli::parse()
    }
}
