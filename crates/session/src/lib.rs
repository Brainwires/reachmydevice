//! OpenReach session wiring.
//!
//! Composes the media/transport/input crates into runnable sessions:
//! - [`host::run_host`] — headless host (capture → encode → transport; input inject).
//! - [`viewer::ViewerSession`] — UI-agnostic viewer (transport → decode; input send),
//!   driven by the winit/wgpu viewer app.
//! - [`signal::Signaling`] — signaling backend trait, implemented by the LAN
//!   [`signal::SignalClient`] and the [`rendezvous::RendezvousClient`] (Phase 2).
//! - [`identity`] — device keypair identity + TOFU trust store.

pub mod account;
pub mod audio;
pub mod clipboard;
pub mod filexfer;
pub mod host;
pub mod identity;
pub mod rendezvous;
pub mod signal;
pub mod viewer;

pub use account::{AccountClient, DeviceInfo};
pub use filexfer::{FileEvent, FileTransferConfig};
pub use host::{run_host, run_host_reporting, HostConfig, HostStatus};
pub use identity::DeviceIdentity;
pub use signal::{SignalClient, Signaling};
pub use viewer::{ViewerConfig, ViewerSession, ViewerUpdate};
