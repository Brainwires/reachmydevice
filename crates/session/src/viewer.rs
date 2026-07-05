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
use rmd_codec as codec;
use rmd_protocol as proto;
use rmd_protocol::pb::envelope::Payload;
use rmd_transport::{
    SignalMsg, Transport, TransportConfig, TransportEvent, TransportRole, TransportSender,
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
    /// This device's identity. When present, the viewer proves possession of it
    /// to hosts that enforce unattended access — the proof is signed at connect
    /// time and bound to this session's DTLS fingerprint. `None` for anonymous
    /// (LAN/dev) connections.
    pub identity: Option<Arc<crate::identity::DeviceIdentity>>,
}

impl Default for ViewerConfig {
    fn default() -> Self {
        Self {
            device_name: "rmd-viewer".to_string(),
            ice_servers: Vec::new(),
            bind_addr: "0.0.0.0:0".to_string(),
            enable_audio: false,
            identity: None,
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
    /// The host's cryptographically-proven identity for this session (bound to the
    /// DTLS fingerprint). `verified=false` means the proof failed — treat as a
    /// possible MITM. Use this key (not the registry's) for TOFU/SAS.
    HostIdentity {
        public_key: Vec<u8>,
        device_id: String,
        verified: bool,
    },
}

/// Running viewer session.
pub struct ViewerSession {
    sender: TransportSender,
    updates: Receiver<ViewerUpdate>,
    /// Queue a local file to send to the host.
    file_cmd: Sender<PathBuf>,
    /// Count of audio frames received from the host over the data channel
    /// (incremented regardless of whether playback is enabled).
    audio_rx: Arc<std::sync::atomic::AtomicU64>,
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
                .name("rmd-decode".into())
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

        let audio_rx = Arc::new(std::sync::atomic::AtomicU64::new(0));

        // Pump thread: owns the transport, bridges signaling, routes media to decode.
        {
            let device_name = cfg.device_name.clone();
            let enable_audio = cfg.enable_audio;
            let identity = cfg.identity.clone();
            let audio_rx = audio_rx.clone();
            std::thread::Builder::new()
                .name("rmd-viewer-pump".into())
                .spawn(move || {
                    // Audio playback lives on this thread (cpal stream is !Send).
                    // Only compiled into builds with the `audio` feature.
                    #[cfg(feature = "audio")]
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
                    #[cfg(not(feature = "audio"))]
                    if enable_audio {
                        tracing::warn!(
                            "audio requested but this build has no `audio` feature; \
                             rebuild with `--features audio` to hear host audio"
                        );
                    }
                    // Our own DTLS fingerprint, learned from the answer we emit;
                    // signed into the access proof to bind it to this session.
                    let mut local_fingerprint: Option<String> = None;
                    // The host's DTLS fingerprint, from the offer we receive; the
                    // host's identity proof must be bound to it (authenticates the
                    // real endpoint against a MITM relay).
                    let mut host_fingerprint: Option<String> = None;
                    loop {
                        while let Some(msg) = signal.try_recv() {
                            if let SignalMsg::Offer(json) = &msg {
                                if let Some(fp) =
                                    crate::identity::fingerprint_from_session_json(json)
                                {
                                    host_fingerprint = Some(fp);
                                }
                            }
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
                                // Learn our own DTLS fingerprint from the answer we send.
                                if let SignalMsg::Answer(json) = &msg {
                                    if let Some(fp) =
                                        crate::identity::fingerprint_from_session_json(json)
                                    {
                                        local_fingerprint = Some(fp);
                                    }
                                }
                                let _ = signal.send(&msg);
                            }
                            TransportEvent::Connected => {
                                // Introduce ourselves; host validates our version and
                                // (if it enforces unattended access) our identity proof,
                                // which is bound to this session's DTLS fingerprint.
                                let hello = if let Some(id) = identity.as_ref() {
                                    let binding =
                                        local_fingerprint.clone().unwrap_or_default();
                                    let proof = id.access_proof(binding.as_bytes());
                                    proto::hello_authenticated(
                                        &device_name,
                                        proto::Role::Viewer,
                                        0,
                                        id.public_key_bytes().to_vec(),
                                        proof.to_vec(),
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
                                            // Verify the host's identity proof, bound
                                            // to the host's DTLS fingerprint.
                                            if !ack.host_public_key.is_empty()
                                                && !ack.host_proof.is_empty()
                                            {
                                                let binding = host_fingerprint
                                                    .clone()
                                                    .unwrap_or_default();
                                                let update = match crate::identity::verify_access_proof(
                                                    &ack.host_public_key,
                                                    &ack.host_proof,
                                                    binding.as_bytes(),
                                                ) {
                                                    Ok(device_id) => ViewerUpdate::HostIdentity {
                                                        public_key: ack.host_public_key.clone(),
                                                        device_id,
                                                        verified: true,
                                                    },
                                                    Err(e) => {
                                                        tracing::warn!(error=%e, "host identity proof INVALID — possible MITM");
                                                        ViewerUpdate::HostIdentity {
                                                            public_key: ack.host_public_key.clone(),
                                                            device_id: String::new(),
                                                            verified: false,
                                                        }
                                                    }
                                                };
                                                let _ = updates_tx.send(update);
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
                                            audio_rx.fetch_add(
                                                1,
                                                std::sync::atomic::Ordering::Relaxed,
                                            );
                                            #[cfg(feature = "audio")]
                                            if let Some(a) = audio.as_mut() {
                                                a.push_packet(&frame.opus, frame.seq);
                                            }
                                            #[cfg(not(feature = "audio"))]
                                            let _ = &frame;
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
            audio_rx,
        })
    }

    /// Number of audio frames received from the host so far (over the real data
    /// channel). Used to confirm cross-machine audio delivery.
    pub fn audio_frames_received(&self) -> u64 {
        self.audio_rx.load(std::sync::atomic::Ordering::Relaxed)
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
