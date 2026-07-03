//! Sans-IO WebRTC driver loop (runs on the transport thread).
//!
//! Owns the `rtc` `RTCPeerConnection`, the UDP socket, the H.264 RTP
//! packetizer/depacketizer, and the data channel, and pumps the sans-IO state
//! machine: drain [`DriverCmd`]s, `poll_write` → socket, socket → `handle_read`,
//! advance timers, drain `poll_event`/`poll_read` → [`TransportEvent`]s. Also
//! enables GCC and publishes its target bitrate.
//!
//! TODO(phase1): full implementation. Signature is frozen (see `lib.rs`).

use crate::{DriverCmd, TransportConfig, TransportEvent};
use std::sync::atomic::AtomicU32;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::Arc;

/// Run the driver loop until [`DriverCmd::Shutdown`] or the command channel closes.
pub(crate) fn run(
    config: TransportConfig,
    cmd_rx: Receiver<DriverCmd>,
    event_tx: Sender<TransportEvent>,
    bitrate_bps: Arc<AtomicU32>,
) -> anyhow::Result<()> {
    let _ = (config, cmd_rx, event_tx, bitrate_bps);
    anyhow::bail!("transport driver not yet implemented")
}
