//! Domain model shared across probes, the diagnosis engine, and the UI.

mod path;
mod status;

pub use path::{Fault, Hop, HopId, Layer, Metric, Path};
pub use status::Status;
