//! OpenReach session wiring.
//!
//! Composes the media/transport/input crates into runnable sessions:
//! - [`host::run_host`] — headless host (capture → encode → transport; input inject).
//! - [`viewer::ViewerSession`] — UI-agnostic viewer (transport → decode; input send),
//!   driven by the winit/wgpu viewer app.
//! - [`signal::SignalClient`] — the spike's `signal-dev` signaling seam.

pub mod host;
pub mod signal;
pub mod viewer;

pub use host::{run_host, HostConfig};
pub use viewer::{ViewerConfig, ViewerSession, ViewerUpdate};
