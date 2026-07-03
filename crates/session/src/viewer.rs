//! Viewer session: transport (receive) → decode, and input → transport.
//!
//! UI-agnostic. Owns the transport (WebRTC answerer / video receiver), the
//! signaling client, a control/event pump thread, and a decode thread. The
//! viewer *app* drives winit/wgpu and simply polls [`ViewerSession::poll_update`]
//! for decoded frames and connection state, and calls [`ViewerSession::send_input`].

use crate::signal::SignalClient;
use bytes::Bytes;
use openreach_codec as codec;
use openreach_protocol as proto;
use openreach_protocol::pb::envelope::Payload;
use openreach_transport::{
    Transport, TransportConfig, TransportEvent, TransportRole, TransportSender,
};
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

/// Viewer configuration.
#[derive(Clone, Debug)]
pub struct ViewerConfig {
    pub signal_addr: String,
    pub device_name: String,
}

impl Default for ViewerConfig {
    fn default() -> Self {
        Self {
            signal_addr: "127.0.0.1:9000".to_string(),
            device_name: "openreach-viewer".to_string(),
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
}

/// Running viewer session.
pub struct ViewerSession {
    sender: TransportSender,
    updates: Receiver<ViewerUpdate>,
}

impl ViewerSession {
    /// Connect signaling, spawn the transport + pump + decode threads.
    pub fn start(cfg: ViewerConfig) -> anyhow::Result<Self> {
        let transport = Transport::spawn(TransportConfig {
            role: TransportRole::Viewer,
            ice_servers: Vec::new(),
            bind_addr: "0.0.0.0:0".parse().unwrap(),
            video_bitrate_bps: 8_000_000, // viewer doesn't encode; nominal
        })?;
        let sender = transport.sender();
        let signal = SignalClient::connect(&cfg.signal_addr)?;

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

        // Pump thread: owns the transport, bridges signaling, routes media to decode.
        {
            let device_name = cfg.device_name.clone();
            std::thread::Builder::new()
                .name("openreach-viewer-pump".into())
                .spawn(move || {
                    loop {
                        while let Some(msg) = signal.try_recv() {
                            transport.feed_signal(msg);
                        }
                        let Some(ev) = transport.recv_event_timeout(Duration::from_millis(4)) else {
                            continue;
                        };
                        match ev {
                            TransportEvent::LocalSignal(msg) => {
                                let _ = signal.send(&msg);
                            }
                            TransportEvent::Connected => {
                                // Introduce ourselves; host validates our version.
                                let hello =
                                    proto::hello(&device_name, proto::Role::Viewer, 0);
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
                                    if let Some(Payload::HelloAck(ack)) = env.payload {
                                        if !ack.accepted {
                                            tracing::warn!(reason=%ack.reason, "host rejected pairing");
                                        }
                                        let _ = updates_tx.send(ViewerUpdate::Paired(ack.accepted));
                                    }
                                }
                            }
                        }
                    }
                })?;
        }

        Ok(Self { sender, updates })
    }

    /// Non-blocking poll for the next UI update.
    pub fn poll_update(&self) -> Option<ViewerUpdate> {
        self.updates.try_recv().ok()
    }

    /// Send an input event to the host over the control channel.
    pub fn send_input(&self, event: proto::input_event::Event) {
        let env = proto::input(event);
        self.sender.send_data(Bytes::from(proto::encode(&env)));
    }
}
