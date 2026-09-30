//! Live TUI dashboard (ratatui). Implemented after the core is validated.

mod dashboard;

pub use dashboard::run;
#[cfg(feature = "demo")]
pub use dashboard::run_demo;
