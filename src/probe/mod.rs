//! Probes: each turns some slice of the network into a graded [`Hop`].
//!
//! Probes are plain async (or sync, for the platform-backed link probe)
//! functions rather than a trait object, because they take heterogeneous
//! inputs and all converge on the same output type — a `Hop` the engine
//! streams to the UI.

pub mod captive;
pub mod dns;
pub mod gateway;
pub mod link;
pub mod net;
pub mod vpn;
pub mod wan;
