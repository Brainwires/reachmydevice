//! ReachMyDevice transport — WebRTC over the sans-IO `rtc` fork (ADR-0003).
//!
//! The `rtc` `RTCPeerConnection` is `!Send` and `&mut self`-driven, so it lives
//! on a dedicated OS thread running the sans-IO driver loop ([`driver`]). The
//! rest of the app talks to it through this `Send` [`Transport`] handle:
//! commands go in over a channel, [`TransportEvent`]s come out over another.
//!
//! Signaling is transport-agnostic: the driver surfaces local SDP/ICE as
//! [`TransportEvent::LocalSignal`] for the app to deliver to the peer, and the
//! app feeds the peer's signaling back via [`Transport::feed_signal`]. For the
//! spike the app carries these over `signal-dev`; in Phase 2 over the rendezvous
//! WebSocket. Media/data are always end-to-end encrypted (DTLS-SRTP) — the
//! relay only sees ciphertext.

use bytes::Bytes;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

pub mod driver;

/// Which end of the session this peer is.
///
/// The **host** offers and sends the video track; the **viewer** answers and
/// receives it. Both ends use the (bidirectional) data channel — the host
/// creates it, the viewer sends input over it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportRole {
    Host,
    Viewer,
}

/// Video codec for the RTP send track (host side).
///
/// A transport-local mirror of `rmd_codec::VideoCodec`, kept here so the
/// transport doesn't link the (C) codec crate. The host registers the matching
/// SDP codec; the fork's payloader is selected automatically from the MIME type.
/// The viewer's receive path is always H.264 (AV1 has no pure-Rust decoder and is
/// consumed only by the browser WASM viewer).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum VideoCodec {
    #[default]
    H264,
    Av1,
}

/// A single ICE server: one or more URLs sharing an optional credential.
///
/// STUN servers carry no credential; a TURN server carries the `username` /
/// `credential` pair (for coturn's `--use-auth-secret` these are the ephemeral
/// `<expiry>:<id>` username and its HMAC). Mirrors the browser's `RTCIceServer`
/// and the rendezvous `/api/ice` JSON, so the same shape flows everywhere.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct IceServer {
    pub urls: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<String>,
}

impl IceServer {
    /// A credential-less server (STUN, or a URL-only manual entry).
    pub fn urls(urls: Vec<String>) -> Self {
        Self {
            urls,
            username: None,
            credential: None,
        }
    }
}

/// Transport setup.
#[derive(Clone, Debug)]
pub struct TransportConfig {
    pub role: TransportRole,
    /// ICE servers (STUN + optional credentialed TURN). See [`IceServer`].
    pub ice_servers: Vec<IceServer>,
    /// Local UDP bind address (use port 0 to let the OS choose).
    pub bind_addr: SocketAddr,
    /// Initial encoder bitrate target (bits/sec); GCC adjusts from here.
    pub video_bitrate_bps: u32,
    /// Codec the host advertises + packetizes for its send track. Ignored by the
    /// viewer (which always receives H.264). Defaults to H.264.
    pub video_codec: VideoCodec,
}

/// A signaling message exchanged with the peer (opaque to the relay).
///
/// Serialized as a single JSON line: `{"type":"offer","data":"<sdp>"}` etc.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "lowercase")]
pub enum SignalMsg {
    Offer(String),
    Answer(String),
    Candidate(String),
}

/// Something the driver produced for the app to act on.
#[derive(Debug)]
pub enum TransportEvent {
    /// Local SDP/ICE to deliver to the peer via signaling.
    LocalSignal(SignalMsg),
    /// ICE connected and DTLS established (media/data can flow).
    Connected,
    /// The peer connection dropped.
    Disconnected,
    /// A reassembled H.264 access unit from the remote track (viewer side).
    Video { annexb: Bytes, ts_hint: u64 },
    /// A data-channel message (control / input).
    Data(Bytes),
    /// The remote peer requested a keyframe via RTCP (PLI/FIR) — typically after
    /// packet loss left it unable to decode. The host should force an IDR so the
    /// viewer recovers immediately instead of waiting for the next periodic
    /// keyframe (~2s), which is what leaves the "last update" stale after a loss.
    KeyframeRequested,
}

/// Commands from the [`Transport`] handle to the driver thread.
pub(crate) enum DriverCmd {
    /// Encoded H.264 access unit to send on the video track (host side).
    Video {
        annexb: Bytes,
        is_keyframe: bool,
        ts_micros: u64,
    },
    /// Bytes to send on the data channel.
    Data(Bytes),
    /// Signaling received from the peer.
    Signal(SignalMsg),
    /// Request an ICE restart (host initiates renegotiation to recover the
    /// connection after a network change).
    IceRestart,
    /// Release the host's TURN allocation now (Refresh with lifetime 0) and ack on
    /// the sender once done (or given up). The driver keeps running relay-less and
    /// stops retrying the allocation: the process is about to exit or `exec`.
    ReleaseTurn(mpsc::Sender<()>),
    /// Tear down and exit the driver loop.
    Shutdown,
}

/// Command senders of every live host driver, so [`release_turn_allocations`] can
/// reach them from anywhere in the process. Keyed by a per-driver id; a driver
/// removes itself when its thread exits.
static HOST_DRIVERS: Mutex<Vec<(u64, mpsc::Sender<DriverCmd>)>> = Mutex::new(Vec::new());
/// Source of [`HOST_DRIVERS`] ids.
static NEXT_DRIVER_ID: AtomicU64 = AtomicU64::new(0);

/// Ask every live host transport driver to release its TURN allocation, and block
/// until all of them confirm or `timeout` passes (best effort; never hangs longer).
///
/// Call this before the process exits or `exec`s itself (no destructors run on an
/// `exec`), so coturn drops the allocation now instead of holding it for its full
/// lifetime. Otherwise the next process, which allocates from the same 5-tuple, is
/// answered 437 (Allocation Mismatch) and runs relay-less. After the release a
/// driver keeps running, just without a relay.
pub fn release_turn_allocations(timeout: Duration) {
    let deadline = Instant::now() + timeout;
    let senders: Vec<mpsc::Sender<DriverCmd>> = match HOST_DRIVERS.lock() {
        Ok(drivers) => drivers.iter().map(|(_, tx)| tx.clone()).collect(),
        Err(poisoned) => poisoned
            .into_inner()
            .iter()
            .map(|(_, tx)| tx.clone())
            .collect(),
    };
    let (ack_tx, ack_rx) = mpsc::channel();
    let pending = senders
        .iter()
        .filter(|tx| tx.send(DriverCmd::ReleaseTurn(ack_tx.clone())).is_ok())
        .count();
    drop(ack_tx);
    for _ in 0..pending {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() || ack_rx.recv_timeout(left).is_err() {
            tracing::debug!("transport: TURN release did not confirm before the timeout");
            return;
        }
    }
}

/// Add a host driver's command sender to [`HOST_DRIVERS`]; returns its id.
fn register_host_driver(tx: mpsc::Sender<DriverCmd>) -> u64 {
    let id = NEXT_DRIVER_ID.fetch_add(1, Ordering::Relaxed);
    match HOST_DRIVERS.lock() {
        Ok(mut drivers) => drivers.push((id, tx)),
        Err(poisoned) => poisoned.into_inner().push((id, tx)),
    }
    id
}

/// Remove a host driver from [`HOST_DRIVERS`] (its thread is exiting).
fn unregister_host_driver(id: u64) {
    match HOST_DRIVERS.lock() {
        Ok(mut drivers) => drivers.retain(|(i, _)| *i != id),
        Err(poisoned) => poisoned.into_inner().retain(|(i, _)| *i != id),
    }
}

/// Cloneable command side of the transport.
///
/// Holds only `Send` senders, so it can be cloned to any thread (the encode
/// thread, the UI thread) that needs to push video/data/signaling or read the
/// GCC bitrate. The event *consumer* side lives on a single [`Transport`].
#[derive(Clone)]
pub struct TransportSender {
    cmd_tx: mpsc::Sender<DriverCmd>,
    bitrate_bps: Arc<AtomicU32>,
}

impl TransportSender {
    /// Queue an encoded H.264 access unit for sending (host).
    pub fn send_video(&self, annexb: Bytes, is_keyframe: bool, ts_micros: u64) {
        let _ = self.cmd_tx.send(DriverCmd::Video {
            annexb,
            is_keyframe,
            ts_micros,
        });
    }

    /// Queue bytes for the data channel (both roles).
    pub fn send_data(&self, data: Bytes) {
        let _ = self.cmd_tx.send(DriverCmd::Data(data));
    }

    /// Feed a signaling message received from the peer.
    pub fn feed_signal(&self, msg: SignalMsg) {
        let _ = self.cmd_tx.send(DriverCmd::Signal(msg));
    }

    /// Request an ICE restart (host only) to recover the connection after a
    /// network change. No-op on the viewer, which recovers via the host's offer.
    pub fn request_ice_restart(&self) {
        let _ = self.cmd_tx.send(DriverCmd::IceRestart);
    }

    /// Latest GCC target bitrate (bits/sec) — feed this to the encoder.
    pub fn target_bitrate_bps(&self) -> u32 {
        self.bitrate_bps.load(Ordering::Relaxed)
    }
}

/// Owning handle to the transport driver thread and its event stream.
///
/// The event receiver is single-consumer, so `Transport` is not shared across
/// threads — keep it on one thread and hand [`TransportSender`] clones (via
/// [`Transport::sender`]) to the others. Convenience command methods delegate to
/// the inner sender for the owning thread's use.
pub struct Transport {
    sender: TransportSender,
    event_rx: mpsc::Receiver<TransportEvent>,
    handle: Option<JoinHandle<()>>,
}

impl Transport {
    /// Spawn the driver thread and return the owning handle.
    pub fn spawn(config: TransportConfig) -> anyhow::Result<Self> {
        let (cmd_tx, cmd_rx) = mpsc::channel();
        let (event_tx, event_rx) = mpsc::channel();
        let bitrate_bps = Arc::new(AtomicU32::new(config.video_bitrate_bps));
        let driver_bitrate = bitrate_bps.clone();
        // Host drivers hold a TURN allocation: register them so the process can
        // release it before it exits or re-execs (see `release_turn_allocations`).
        let registry_id =
            (config.role == TransportRole::Host).then(|| register_host_driver(cmd_tx.clone()));

        let spawned = std::thread::Builder::new()
            .name("rmd-transport".into())
            .spawn(move || {
                if let Err(e) = driver::run(config, cmd_rx, event_tx, driver_bitrate) {
                    tracing::error!("transport driver exited with error: {e:?}");
                }
                if let Some(id) = registry_id {
                    unregister_host_driver(id);
                }
            });
        let handle = match spawned {
            Ok(h) => h,
            Err(e) => {
                if let Some(id) = registry_id {
                    unregister_host_driver(id);
                }
                return Err(e.into());
            }
        };

        Ok(Self {
            sender: TransportSender {
                cmd_tx,
                bitrate_bps,
            },
            event_rx,
            handle: Some(handle),
        })
    }

    /// A cloneable command handle for other threads.
    pub fn sender(&self) -> TransportSender {
        self.sender.clone()
    }

    /// Non-blocking event poll.
    pub fn try_event(&self) -> Option<TransportEvent> {
        self.event_rx.try_recv().ok()
    }

    /// Blocking event poll with a timeout.
    pub fn recv_event_timeout(&self, timeout: Duration) -> Option<TransportEvent> {
        self.event_rx.recv_timeout(timeout).ok()
    }

    // Convenience command methods for the owning thread (delegate to the sender).

    /// Queue an encoded H.264 access unit for sending (host).
    pub fn send_video(&self, annexb: Bytes, is_keyframe: bool, ts_micros: u64) {
        self.sender.send_video(annexb, is_keyframe, ts_micros);
    }

    /// Queue bytes for the data channel (both roles).
    pub fn send_data(&self, data: Bytes) {
        self.sender.send_data(data);
    }

    /// Feed a signaling message received from the peer.
    pub fn feed_signal(&self, msg: SignalMsg) {
        self.sender.feed_signal(msg);
    }

    /// Request an ICE restart (host only) to recover after a network change.
    pub fn request_ice_restart(&self) {
        self.sender.request_ice_restart();
    }

    /// Latest GCC target bitrate (bits/sec).
    pub fn target_bitrate_bps(&self) -> u32 {
        self.sender.target_bitrate_bps()
    }
}

impl Drop for Transport {
    fn drop(&mut self) {
        let _ = self.sender.cmd_tx.send(DriverCmd::Shutdown);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signal_msg_json_roundtrip() {
        let msg = SignalMsg::Offer("v=0...".to_string());
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(json, r#"{"type":"offer","data":"v=0..."}"#);
        let back: SignalMsg = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, SignalMsg::Offer(s) if s == "v=0..."));
    }
}
