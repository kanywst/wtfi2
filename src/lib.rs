//! wtfi2 — What The F*ck Internet.
//!
//! A live, visual network-path diagnostic. It probes every hop from your Wi-Fi
//! link out to the internet, renders the chain as a topology diagram, and tells
//! you in one line where the connection died and how to fix it.

pub mod cli;
pub mod diagnose;
pub mod engine;
pub mod json;
pub mod model;
pub mod platform;
pub mod probe;
pub mod render;
pub mod ui;
