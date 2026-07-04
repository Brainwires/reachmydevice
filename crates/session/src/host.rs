//! Host session: capture → encode → transport (send), and control data → input.
//!
//! Headless. Spawns capture (its own queue), an encode thread, the transport
//! driver (its own thread), and runs the control/event loop here. The host is
//! the WebRTC offerer and the video sender; it validates the viewer's protocol
//! version, injects the viewer's input, and answers Ping with Pong.

use crate::clipboard::ClipboardSync;
use crate::filexfer::{FileEvent, FileTransferConfig, FileTransfers};
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
    // Whether a viewer is connected. Video is only encoded/sent while true, so we
    // don't blast RTP before DTLS-SRTP is ready (and we save CPU when idle).
    let connected = Arc::new(AtomicBool::new(false));

    // Encode thread: frames -> H.264 -> transport, with GCC-driven bitrate.
    spawn_encode_thread(
        &cfg,
        transport.sender(),
        force_keyframe.clone(),
        connected.clone(),
        frame_rx,
    )?;

    // Input injector (best effort; needs Accessibility permission).
    let mut injector = match input::new_injector() {
        Ok(i) => Some(i),
        Err(e) => {
            tracing::warn!(error=%e, "input injection unavailable (grant Accessibility?)");
            None
        }
    };

    // Clipboard sync: forward local clipboard changes to the viewer and apply
    // the viewer's. Sends before a viewer connects are dropped by the transport.
    let clipboard = {
        let sender = transport.sender();
        ClipboardSync::spawn(move |env| sender.send_data(Bytes::from(proto::encode(&env))))
    };

    // File transfer (receive side; files land in the download dir). Events are
    // logged since the host is headless.
    let (file_ev_tx, file_ev_rx) = mpsc::channel();
    let mut files = {
        let sender = transport.sender();
        let out = Arc::new(move |env: proto::Envelope| {
            sender.send_data(Bytes::from(proto::encode(&env)))
        });
        FileTransfers::new(out, file_ev_tx, FileTransferConfig::default())
    };

    tracing::info!(device = %cfg.device_name, "host ready; waiting for a viewer to connect");

    // Control / event loop: forward peer signaling in, react to transport events.
    loop {
        while let Some(msg) = signal.try_recv() {
            transport.feed_signal(msg);
        }
        while let Ok(ev) = file_ev_rx.try_recv() {
            log_file_event(ev);
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
                connected.store(true, Ordering::Relaxed);
                force_keyframe.store(true, Ordering::Relaxed);
            }
            TransportEvent::Disconnected => {
                tracing::warn!("remote session ended");
                connected.store(false, Ordering::Relaxed);
            }
            TransportEvent::Data(bytes) => {
                handle_control(
                    &bytes,
                    &transport,
                    &mut injector,
                    &clipboard,
                    &mut files,
                    &cfg.device_name,
                );
            }
            TransportEvent::Video { .. } => {} // host does not receive video
        }
    }
}

fn spawn_encode_thread(
    cfg: &HostConfig,
    sender: TransportSender,
    force_keyframe: Arc<AtomicBool>,
    connected: Arc<AtomicBool>,
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
                // Only encode/send while a viewer is connected (avoids sending RTP
                // before DTLS-SRTP is up, and saves CPU when idle).
                if !connected.load(Ordering::Relaxed) {
                    continue;
                }
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
#[allow(clippy::too_many_arguments)]
fn handle_control(
    bytes: &[u8],
    transport: &Transport,
    injector: &mut Option<Box<dyn input::Injector>>,
    clipboard: &ClipboardSync,
    files: &mut FileTransfers,
    device_name: &str,
) {
    let env = match proto::decode(bytes) {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!(error=%e, "undecodable control message");
            return;
        }
    };
    let Some(payload) = env.payload else {
        return;
    };
    // File-transfer payloads are handled by the transfer manager.
    if files.handle(&payload) {
        return;
    }
    match payload {
        Payload::Hello(h) => match proto::check_compatibility(env.protocol_major) {
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
        Payload::Input(ie) => {
            if let (Some(inj), Some(ev)) = (injector.as_deref_mut(), ie.event) {
                if let Err(e) = inj.inject(&ev) {
                    tracing::trace!(error=%e, "inject failed");
                }
            }
        }
        Payload::Ping(p) => {
            let pong = proto::pong(p.t_micros);
            transport.send_data(Bytes::from(proto::encode(&pong)));
        }
        Payload::Clipboard(update) => clipboard.apply_remote(update),
        _ => {}
    }
}

/// Log a file-transfer event (the host is headless; the viewer surfaces these
/// in its UI).
fn log_file_event(ev: FileEvent) {
    match ev {
        FileEvent::Offered { name, size, .. } => {
            tracing::info!(%name, size, "incoming file")
        }
        FileEvent::Completed { path, .. } => {
            if let Some(p) = path {
                tracing::warn!(path = %p.display(), "file received");
            }
        }
        FileEvent::Failed { reason, .. } => tracing::warn!(%reason, "file transfer failed"),
        FileEvent::Progress { .. } => {}
    }
}
