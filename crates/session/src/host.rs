//! Host session: capture → encode → transport (send), and control data → input.
//!
//! Headless. Spawns capture (its own queue), an encode thread, the transport
//! driver (its own thread), and runs the control/event loop here. The host is
//! the WebRTC offerer and the video sender; it validates the viewer's protocol
//! version, injects the viewer's input, and answers Ping with Pong.

use crate::signal::Signaling;
use bytes::Bytes;
use openreach_capture as capture;
use openreach_codec as codec;
use openreach_input as input;
use openreach_protocol as proto;
use openreach_protocol::pb::envelope::Payload;
use openreach_transport::{
    Transport, TransportConfig, TransportEvent, TransportRole, TransportSender,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;

/// Host configuration.
#[derive(Clone, Debug)]
pub struct HostConfig {
    pub display_index: usize,
    pub width: u32,
    pub height: u32,
    pub fps: u32,
    pub bitrate_bps: u32,
    pub device_name: String,
    /// ICE server URLs (STUN/TURN); empty for LAN/loopback.
    pub ice_servers: Vec<String>,
    /// Local UDP bind address for the transport (e.g. `0.0.0.0:0`, or
    /// `127.0.0.1:0` for a same-host loopback session).
    pub bind_addr: String,
}

impl Default for HostConfig {
    fn default() -> Self {
        Self {
            display_index: 0,
            width: 1920,
            height: 1080,
            fps: 30,
            bitrate_bps: 8_000_000,
            device_name: "openreach-host".to_string(),
            ice_servers: Vec::new(),
            bind_addr: "0.0.0.0:0".to_string(),
        }
    }
}

/// Run the host session with the given signaling backend. Blocks until stopped.
pub fn run_host(cfg: HostConfig, signal: Box<dyn Signaling>) -> anyhow::Result<()> {
    let bind_addr = cfg
        .bind_addr
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid bind_addr {:?}: {e}", cfg.bind_addr))?;
    let transport = Transport::spawn(TransportConfig {
        role: TransportRole::Host,
        ice_servers: cfg.ice_servers.clone(),
        bind_addr,
        video_bitrate_bps: cfg.bitrate_bps,
    })?;

    // Capture -> frame channel.
    let (frame_tx, frame_rx) = mpsc::channel();
    let _capture = capture::start_capture(
        capture::CaptureConfig {
            width: cfg.width,
            height: cfg.height,
            fps: cfg.fps,
            show_cursor: true,
        },
        cfg.display_index,
        frame_tx,
    )?;

    // Force a keyframe on start and whenever a viewer (re)connects.
    let force_keyframe = Arc::new(AtomicBool::new(true));

    // Encode thread: frames -> H.264 -> transport, with GCC-driven bitrate.
    spawn_encode_thread(&cfg, transport.sender(), force_keyframe.clone(), frame_rx)?;

    // Input injector (best effort; needs Accessibility permission).
    let mut injector = match input::new_injector() {
        Ok(i) => Some(i),
        Err(e) => {
            tracing::warn!(error=%e, "input injection unavailable (grant Accessibility?)");
            None
        }
    };

    tracing::info!(device = %cfg.device_name, "host ready; waiting for a viewer to connect");

    // Control / event loop: forward peer signaling in, react to transport events.
    loop {
        while let Some(msg) = signal.try_recv() {
            transport.feed_signal(msg);
        }
        // Block briefly on transport events so the loop isn't a busy-spin.
        let Some(ev) = transport.recv_event_timeout(Duration::from_millis(4)) else {
            continue;
        };
        match ev {
            TransportEvent::LocalSignal(msg) => {
                if let Err(e) = signal.send(&msg) {
                    tracing::warn!(error=%e, "failed to send local signaling");
                }
            }
            TransportEvent::Connected => {
                // Visible session indicator (tray comes later).
                tracing::warn!("★ REMOTE SESSION ACTIVE ★");
                force_keyframe.store(true, Ordering::Relaxed);
            }
            TransportEvent::Disconnected => tracing::warn!("remote session ended"),
            TransportEvent::Data(bytes) => {
                handle_control(&bytes, &transport, &mut injector, &cfg.device_name);
            }
            TransportEvent::Video { .. } => {} // host does not receive video
        }
    }
}

fn spawn_encode_thread(
    cfg: &HostConfig,
    sender: TransportSender,
    force_keyframe: Arc<AtomicBool>,
    frame_rx: mpsc::Receiver<capture::Frame>,
) -> anyhow::Result<()> {
    let enc_cfg = codec::EncoderConfig {
        width: cfg.width,
        height: cfg.height,
        fps: cfg.fps,
        bitrate_bps: cfg.bitrate_bps,
    };
    std::thread::Builder::new()
        .name("openreach-encode".into())
        .spawn(move || {
            let mut encoder = match codec::new_encoder(enc_cfg) {
                Ok(e) => e,
                Err(e) => {
                    tracing::error!(error=%e, "encoder init failed");
                    return;
                }
            };
            while let Ok(frame) = frame_rx.recv() {
                // Track the GCC target so the stream adapts to the link.
                encoder.set_target_bitrate(sender.target_bitrate_bps());
                let force = force_keyframe.swap(false, Ordering::Relaxed);
                match encoder.encode(
                    &frame.data,
                    frame.width,
                    frame.height,
                    frame.bytes_per_row,
                    frame.capture_ts_micros,
                    force,
                ) {
                    Ok(Some(ef)) => {
                        sender.send_video(ef.data, ef.is_keyframe, ef.capture_ts_micros)
                    }
                    Ok(None) => {}
                    Err(e) => tracing::warn!(error=%e, "encode error"),
                }
            }
            tracing::info!("encode thread ended (capture closed)");
        })?;
    Ok(())
}

/// Handle one control-channel message from the viewer.
fn handle_control(
    bytes: &[u8],
    transport: &Transport,
    injector: &mut Option<Box<dyn input::Injector>>,
    device_name: &str,
) {
    let env = match proto::decode(bytes) {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!(error=%e, "undecodable control message");
            return;
        }
    };
    match env.payload {
        Some(Payload::Hello(h)) => match proto::check_compatibility(env.protocol_major) {
            Ok(()) => {
                let ack = proto::hello_ack_ok(device_name, 0);
                transport.send_data(Bytes::from(proto::encode(&ack)));
                tracing::info!(viewer = %h.device_name, "viewer paired (version ok)");
            }
            Err(e) => {
                let ack = proto::hello_ack_reject(format!("{e}"));
                transport.send_data(Bytes::from(proto::encode(&ack)));
                tracing::warn!(error=%e, "rejected incompatible viewer");
            }
        },
        Some(Payload::Input(ie)) => {
            if let (Some(inj), Some(ev)) = (injector.as_deref_mut(), ie.event) {
                if let Err(e) = inj.inject(&ev) {
                    tracing::trace!(error=%e, "inject failed");
                }
            }
        }
        Some(Payload::Ping(p)) => {
            let pong = proto::pong(p.t_micros);
            transport.send_data(Bytes::from(proto::encode(&pong)));
        }
        _ => {}
    }
}
