//! Viewer session: transport (receive) → decode, and input → transport.
//!
//! UI-agnostic. Owns the transport (WebRTC answerer / video receiver), the
//! signaling client, a control/event pump thread, and a decode thread. The
//! viewer *app* drives winit/wgpu and simply polls [`ViewerSession::poll_update`]
//! for decoded frames and connection state, and calls [`ViewerSession::send_input`].

use crate::clipboard::ClipboardSync;
use crate::filexfer::{FileEvent, FileTransferConfig, FileTransfers};
use crate::signal::Signaling;
use bytes::Bytes;
use openreach_codec as codec;
use openreach_protocol as proto;
use openreach_protocol::pb::envelope::Payload;
use openreach_transport::{
    Transport, TransportConfig, TransportEvent, TransportRole, TransportSender,
};
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;
use std::time::Duration;

/// Viewer configuration.
#[derive(Clone, Debug)]
pub struct ViewerConfig {
    pub device_name: String,
    /// ICE server URLs (STUN/TURN); empty for LAN/loopback.
    pub ice_servers: Vec<String>,
    /// Local UDP bind address (`0.0.0.0:0`, or `127.0.0.1:0` for loopback).
    pub bind_addr: String,
    /// Play host audio if the host streams it. Off by default.
    pub enable_audio: bool,
    /// This device's 32-byte ed25519 public key, for unattended-access proof.
    /// Empty for anonymous (LAN/dev) connections.
    pub identity_public_key: Vec<u8>,
    /// Signature over the access-proof message (see `identity::access_proof`).
    /// Empty when `identity_public_key` is empty.
    pub identity_proof: Vec<u8>,
}

impl Default for ViewerConfig {
    fn default() -> Self {
        Self {
            device_name: "openreach-viewer".to_string(),
            ice_servers: Vec::new(),
            bind_addr: "0.0.0.0:0".to_string(),
            enable_audio: false,
            identity_public_key: Vec::new(),
            identity_proof: Vec::new(),
        }
    }
}

/// An update surfaced to the viewer UI.
pub enum ViewerUpdate {
    Connected,
    Disconnected,
    /// A decoded RGBA frame ready to upload to a texture.
    Frame(codec::DecodedFrame),
    /// The host accepted (`true`) or rejected the pairing (version handshake).
    Paired(bool),
    /// Round-trip latency measured from a data-channel `Ping`/`Pong` exchange.
    Latency(Duration),
    /// A file-transfer event (incoming offer, progress, completion, failure).
    File(FileEvent),
    /// The host's available displays (for the multi-monitor picker).
    Displays(Vec<proto::DisplayDescriptor>),
}

/// Running viewer session.
pub struct ViewerSession {
    sender: TransportSender,
    updates: Receiver<ViewerUpdate>,
    /// Queue a local file to send to the host.
    file_cmd: Sender<PathBuf>,
}

impl ViewerSession {
    /// Spawn the transport + pump + decode threads with the given signaling backend.
    pub fn start(cfg: ViewerConfig, signal: Box<dyn Signaling>) -> anyhow::Result<Self> {
        let bind_addr = cfg
            .bind_addr
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid bind_addr {:?}: {e}", cfg.bind_addr))?;
        let transport = Transport::spawn(TransportConfig {
            role: TransportRole::Viewer,
            ice_servers: cfg.ice_servers.clone(),
            bind_addr,
            video_bitrate_bps: 8_000_000, // viewer doesn't encode; nominal
        })?;
        let sender = transport.sender();

        let (updates_tx, updates) = mpsc::channel();
        let (annexb_tx, annexb_rx) = mpsc::channel::<(Bytes, u64)>();

        // Decode thread: Annex-B access units -> RGBA frames.
        {
            let updates_tx = updates_tx.clone();
            std::thread::Builder::new()
                .name("openreach-decode".into())
                .spawn(move || {
                    let mut decoder = match codec::new_decoder() {
                        Ok(d) => d,
                        Err(e) => {
                            tracing::error!(error=%e, "decoder init failed");
                            return;
                        }
                    };
                    while let Ok((annexb, _ts)) = annexb_rx.recv() {
                        match decoder.decode(&annexb) {
                            Ok(Some(frame)) => {
                                if updates_tx.send(ViewerUpdate::Frame(frame)).is_err() {
                                    break;
                                }
                            }
                            Ok(None) => {}
                            Err(e) => tracing::trace!(error=%e, "decode error"),
                        }
                    }
                })?;
        }

        // Clipboard sync: forward local clipboard changes to the host and apply
        // the host's. The handle moves into the pump thread so inbound updates
        // can be applied there.
        let clipboard = {
            let sender = transport.sender();
            ClipboardSync::spawn(move |env| sender.send_data(Bytes::from(proto::encode(&env))))
        };

        // File transfer: manager lives in the pump thread. Sends are queued from
        // the UI thread via `file_cmd`; events surface as `ViewerUpdate::File`.
        let (file_cmd_tx, file_cmd_rx) = mpsc::channel::<PathBuf>();
        let (file_ev_tx, file_ev_rx) = mpsc::channel::<FileEvent>();
        let mut files = {
            let sender = transport.sender();
            let out = Arc::new(move |env: proto::Envelope| {
                sender.send_data(Bytes::from(proto::encode(&env)))
            });
            FileTransfers::new(out, file_ev_tx, FileTransferConfig::default())
        };

        // Pump thread: owns the transport, bridges signaling, routes media to decode.
        {
            let device_name = cfg.device_name.clone();
            let enable_audio = cfg.enable_audio;
            let id_pubkey = cfg.identity_public_key.clone();
            let id_proof = cfg.identity_proof.clone();
            std::thread::Builder::new()
                .name("openreach-viewer-pump".into())
                .spawn(move || {
                    // Audio playback lives on this thread (cpal stream is !Send).
                    let mut audio = if enable_audio {
                        match crate::audio::AudioPlayback::start() {
                            Ok(p) => {
                                tracing::info!("audio playback enabled");
                                Some(p)
                            }
                            Err(e) => {
                                tracing::warn!(error=%e, "audio playback unavailable");
                                None
                            }
                        }
                    } else {
                        None
                    };
                    loop {
                        while let Some(msg) = signal.try_recv() {
                            transport.feed_signal(msg);
                        }
                        while let Ok(path) = file_cmd_rx.try_recv() {
                            if let Err(e) = files.send_file(path) {
                                tracing::warn!(error=%e, "failed to start file send");
                            }
                        }
                        while let Ok(ev) = file_ev_rx.try_recv() {
                            let _ = updates_tx.send(ViewerUpdate::File(ev));
                        }
                        let Some(ev) = transport.recv_event_timeout(Duration::from_millis(4)) else {
                            continue;
                        };
                        match ev {
                            TransportEvent::LocalSignal(msg) => {
                                let _ = signal.send(&msg);
                            }
                            TransportEvent::Connected => {
                                // Introduce ourselves; host validates our version and
                                // (if it enforces unattended access) our identity proof.
                                let hello = if !id_pubkey.is_empty() && !id_proof.is_empty() {
                                    proto::hello_authenticated(
                                        &device_name,
                                        proto::Role::Viewer,
                                        0,
                                        id_pubkey.clone(),
                                        id_proof.clone(),
                                    )
                                } else {
                                    proto::hello(&device_name, proto::Role::Viewer, 0)
                                };
                                transport.send_data(Bytes::from(proto::encode(&hello)));
                                let _ = updates_tx.send(ViewerUpdate::Connected);
                            }
                            TransportEvent::Disconnected => {
                                let _ = updates_tx.send(ViewerUpdate::Disconnected);
                            }
                            TransportEvent::Video { annexb, ts_hint } => {
                                let _ = annexb_tx.send((annexb, ts_hint));
                            }
                            TransportEvent::Data(bytes) => {
                                if let Ok(env) = proto::decode(&bytes) {
                                    match env.payload {
                                        Some(Payload::HelloAck(ack)) => {
                                            if !ack.accepted {
                                                tracing::warn!(reason=%ack.reason, "host rejected pairing");
                                            }
                                            let _ = updates_tx.send(ViewerUpdate::Paired(ack.accepted));
                                        }
                                        // Pong echoes the timestamp we stamped into our Ping;
                                        // the elapsed monotonic time is the data-channel RTT.
                                        Some(Payload::Pong(p)) => {
                                            let now = proto::monotonic_micros();
                                            let rtt = now.saturating_sub(p.t_micros);
                                            let _ = updates_tx
                                                .send(ViewerUpdate::Latency(Duration::from_micros(rtt)));
                                        }
                                        Some(Payload::Clipboard(update)) => {
                                            clipboard.apply_remote(update);
                                        }
                                        Some(Payload::DisplayList(list)) => {
                                            let _ = updates_tx
                                                .send(ViewerUpdate::Displays(list.displays));
                                        }
                                        Some(Payload::Audio(frame)) => {
                                            if let Some(a) = audio.as_mut() {
                                                a.push_packet(&frame.opus, frame.seq);
                                            }
                                        }
                                        Some(p) => {
                                            // File-transfer payloads route to the manager.
                                            files.handle(&p);
                                        }
                                        None => {}
                                    }
                                }
                            }
                        }
                    }
                })?;
        }

        Ok(Self {
            sender,
            updates,
            file_cmd: file_cmd_tx,
        })
    }

    /// Non-blocking poll for the next UI update.
    pub fn poll_update(&self) -> Option<ViewerUpdate> {
        self.updates.try_recv().ok()
    }

    /// Queue a local file to send to the host. Progress and completion arrive as
    /// [`ViewerUpdate::File`].
    pub fn send_file(&self, path: PathBuf) {
        let _ = self.file_cmd.send(path);
    }

    /// Ask the host to switch the captured display (multi-monitor).
    pub fn select_display(&self, id: u32) {
        let env = proto::select_display(id);
        self.sender.send_data(Bytes::from(proto::encode(&env)));
    }

    /// Ask the host for a fresh keyframe (e.g. after switching displays).
    pub fn request_keyframe(&self) {
        let env = proto::request_keyframe();
        self.sender.send_data(Bytes::from(proto::encode(&env)));
    }

    /// Send an input event to the host over the control channel.
    pub fn send_input(&self, event: proto::input_event::Event) {
        let env = proto::input(event);
        self.sender.send_data(Bytes::from(proto::encode(&env)));
    }

    /// Send a latency probe: a `Ping` stamped with the current monotonic clock.
    ///
    /// The host answers with a `Pong` echoing the timestamp; the pump thread then
    /// surfaces the round-trip time as [`ViewerUpdate::Latency`]. Call this on a
    /// timer (e.g. once per second) from the UI loop.
    pub fn send_ping(&self) {
        let env = proto::ping(proto::monotonic_micros());
        self.sender.send_data(Bytes::from(proto::encode(&env)));
    }
}
