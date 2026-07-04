//! Host session: capture → encode → transport (send), and control data → input.
//!
//! Headless. Spawns capture (its own queue), an encode thread, the transport
//! driver (its own thread), and runs the control/event loop here. The host is
//! the WebRTC offerer and the video sender; it validates the viewer's protocol
//! version, injects the viewer's input, and answers Ping with Pong.

use crate::audio::AudioCapture;
use crate::clipboard::ClipboardSync;
use crate::filexfer::{FileEvent, FileTransferConfig, FileTransfers};
use crate::signal::Signaling;
use bytes::Bytes;
use std::sync::atomic::AtomicU64;
use openreach_capture as capture;
use openreach_codec as codec;
use openreach_input as input;
use openreach_protocol as proto;
use openreach_protocol::pb::envelope::Payload;
use openreach_transport::{
    SignalMsg, Transport, TransportConfig, TransportEvent, TransportRole, TransportSender,
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
    /// Stream host audio (Opus) to the viewer. Off by default — see `audio.rs`
    /// for the current source (default input device) and transport caveats.
    pub enable_audio: bool,
    /// Require viewers to prove an authorized device identity before a session
    /// is accepted (unattended-access gate). When false, any viewer that
    /// completes the handshake is accepted (LAN/dev convenience).
    pub require_authorization: bool,
    /// Authorized viewer `device_id`s (32-hex-char fingerprints). Only consulted
    /// when `require_authorization` is set.
    pub authorized_device_ids: Vec<String>,
    /// This host's identity. When present, the host proves possession of it —
    /// bound to the session's DTLS fingerprint — in its `HelloAck`, so the viewer
    /// can authenticate the real endpoint (closes first-connect MITM).
    pub identity: Option<std::sync::Arc<crate::identity::DeviceIdentity>>,
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
            enable_audio: false,
            require_authorization: false,
            authorized_device_ids: Vec::new(),
            identity: None,
        }
    }
}

/// Host-side access policy for unattended operation.
struct AccessControl {
    require: bool,
    authorized: std::collections::HashSet<String>,
}

impl AccessControl {
    /// Decide whether a `Hello` is authorized. `binding` is the DTLS fingerprint
    /// of the actual session (from the viewer's answer), which the proof must be
    /// signed over — defeating proof-replay by a malicious relay. Returns `Ok`
    /// to accept, or an error whose message is the rejection reason.
    fn authorize(&self, hello: &proto::Hello, binding: &[u8]) -> Result<(), String> {
        if !self.require {
            return Ok(());
        }
        if hello.public_key.is_empty() || hello.signature.is_empty() {
            return Err("authorization required but viewer sent no identity proof".into());
        }
        let device_id =
            crate::identity::verify_access_proof(&hello.public_key, &hello.signature, binding)
                .map_err(|e| format!("identity proof rejected: {e}"))?;
        if self.authorized.contains(&device_id) {
            Ok(())
        } else {
            Err(format!("device {device_id} is not authorized"))
        }
    }
}

/// High-level host session state, reported to an optional observer (e.g. a tray
/// companion) so a UI can reflect whether a remote is connected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostStatus {
    /// Ready, no viewer connected.
    Waiting,
    /// A viewer is connected (remote session active).
    Active,
    /// The viewer disconnected; back to waiting.
    Ended,
}

/// Run the host session with the given signaling backend. Blocks until stopped.
pub fn run_host(cfg: HostConfig, signal: Box<dyn Signaling>) -> anyhow::Result<()> {
    run_host_reporting(cfg, signal, |_| {})
}

/// Like [`run_host`], but invokes `on_status` on each [`HostStatus`] transition.
/// The callback runs on the session thread and must not block.
pub fn run_host_reporting<F>(
    cfg: HostConfig,
    signal: Box<dyn Signaling>,
    on_status: F,
) -> anyhow::Result<()>
where
    F: Fn(HostStatus),
{
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

    // Force a keyframe on start and whenever a viewer (re)connects.
    let force_keyframe = Arc::new(AtomicBool::new(true));

    // Capture -> frame channel. The controller owns the capture session so it
    // can restart on a different display (multi-monitor) without disturbing the
    // encode thread, which keeps reading the same channel.
    let (frame_tx, frame_rx) = mpsc::channel();
    let capture_cfg = capture::CaptureConfig {
        width: cfg.width,
        height: cfg.height,
        fps: cfg.fps,
        show_cursor: true,
    };
    let mut capture_ctl = CaptureController::start(
        capture_cfg,
        cfg.display_index,
        frame_tx,
        force_keyframe.clone(),
    )?;
    // Whether a viewer is connected. Video is only encoded/sent while true, so we
    // don't blast RTP before DTLS-SRTP is ready (and we save CPU when idle).
    let connected = Arc::new(AtomicBool::new(false));

    // Unattended-access policy.
    let access = AccessControl {
        require: cfg.require_authorization,
        authorized: cfg.authorized_device_ids.iter().cloned().collect(),
    };
    // An unattended host must stay reachable, so inhibit system idle sleep for
    // the host's lifetime (opt out with OPENREACH_NO_KEEPAWAKE). Held in `_keep_awake`.
    let _keep_awake = if access.require {
        tracing::info!(
            authorized = access.authorized.len(),
            "unattended access ENFORCED: only authorized devices may connect"
        );
        (std::env::var("OPENREACH_NO_KEEPAWAKE").is_err())
            .then(|| crate::power::prevent_sleep("OpenReach unattended host"))
    } else {
        tracing::warn!("unattended access gate OFF: any viewer completing the handshake is accepted");
        None
    };

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

    // Optional audio capture (default off). Held alive for the session; the
    // callback sends Opus frames only while a viewer is connected.
    let _audio = if cfg.enable_audio {
        let sender = transport.sender();
        let connected = connected.clone();
        let seq = Arc::new(AtomicU64::new(0));
        match AudioCapture::start(48_000, move |pkt| {
            if connected.load(Ordering::Relaxed) {
                let s = seq.fetch_add(1, Ordering::Relaxed);
                sender.send_data(Bytes::from(proto::encode(&proto::audio_frame(pkt, s))));
            }
        }) {
            Ok(c) => {
                tracing::info!("audio capture enabled (host -> viewer)");
                Some(c)
            }
            Err(e) => {
                tracing::warn!(error=%e, "audio capture unavailable; continuing without audio");
                None
            }
        }
    } else {
        None
    };

    tracing::info!(device = %cfg.device_name, "host ready; waiting for a viewer to connect");
    on_status(HostStatus::Waiting);

    // The viewer's DTLS fingerprint (from its answer), used to bind its access
    // proof to this session.
    let mut remote_fingerprint: Option<String> = None;
    // Our own DTLS fingerprint, from the offer we emit — the value the host signs
    // into its identity proof so the viewer can authenticate this endpoint.
    let mut local_fingerprint: Option<String> = None;

    // Control / event loop: forward peer signaling in, react to transport events.
    loop {
        while let Some(msg) = signal.try_recv() {
            if let SignalMsg::Answer(json) = &msg {
                if let Some(fp) = crate::identity::fingerprint_from_session_json(json) {
                    remote_fingerprint = Some(fp);
                }
            }
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
                if let SignalMsg::Offer(json) = &msg {
                    if let Some(fp) = crate::identity::fingerprint_from_session_json(json) {
                        local_fingerprint = Some(fp);
                    }
                }
                if let Err(e) = signal.send(&msg) {
                    tracing::warn!(error=%e, "failed to send local signaling");
                }
            }
            TransportEvent::Connected => {
                // Visible session indicator (also surfaced to the tray companion).
                tracing::warn!("★ REMOTE SESSION ACTIVE ★");
                connected.store(true, Ordering::Relaxed);
                force_keyframe.store(true, Ordering::Relaxed);
                on_status(HostStatus::Active);
            }
            TransportEvent::Disconnected => {
                tracing::warn!("remote session ended");
                connected.store(false, Ordering::Relaxed);
                on_status(HostStatus::Ended);
            }
            TransportEvent::Data(bytes) => {
                handle_control(
                    &bytes,
                    &transport,
                    &mut injector,
                    &clipboard,
                    &mut files,
                    &mut capture_ctl,
                    &access,
                    remote_fingerprint.as_deref().unwrap_or_default().as_bytes(),
                    cfg.identity.as_deref(),
                    local_fingerprint.as_deref().unwrap_or_default().as_bytes(),
                    &cfg.device_name,
                );
            }
            TransportEvent::Video { .. } => {} // host does not receive video
        }
    }
}

/// Owns the live capture session and can restart it on another display
/// (multi-monitor). The encode thread reads a stable frame channel, so switching
/// displays only swaps the producer — the encoded output size is unchanged
/// (the backend scales each display to the configured dimensions).
struct CaptureController {
    config: capture::CaptureConfig,
    frame_tx: mpsc::Sender<capture::Frame>,
    displays: Vec<capture::DisplayInfo>,
    current: usize,
    /// Kept alive to keep capturing; dropped (then replaced) on a display switch.
    _handle: Box<dyn capture::CaptureSession>,
    force_keyframe: Arc<AtomicBool>,
}

impl CaptureController {
    fn start(
        config: capture::CaptureConfig,
        display_index: usize,
        frame_tx: mpsc::Sender<capture::Frame>,
        force_keyframe: Arc<AtomicBool>,
    ) -> anyhow::Result<Self> {
        let displays = capture::list_displays().unwrap_or_default();
        let handle = capture::start_capture(config.clone(), display_index, frame_tx.clone())?;
        Ok(Self {
            config,
            frame_tx,
            displays,
            current: display_index,
            _handle: handle,
            force_keyframe,
        })
    }

    /// The host's displays as protocol descriptors (id = enumeration index).
    fn descriptors(&self) -> Vec<proto::DisplayDescriptor> {
        self.displays
            .iter()
            .map(|d| proto::DisplayDescriptor {
                id: d.index as u32,
                width: d.width,
                height: d.height,
                name: format!("Display {}", d.index + 1),
                primary: d.index == 0,
            })
            .collect()
    }

    /// Switch capture to display `id` (a no-op if already current or invalid).
    fn select(&mut self, id: u32) {
        let idx = id as usize;
        if idx == self.current {
            return;
        }
        if idx >= self.displays.len().max(1) {
            tracing::warn!(id, "select_display: no such display");
            return;
        }
        match capture::start_capture(self.config.clone(), idx, self.frame_tx.clone()) {
            Ok(handle) => {
                self._handle = handle; // dropping the old session stops it
                self.current = idx;
                self.force_keyframe.store(true, Ordering::Relaxed);
                tracing::info!(display = idx, "switched captured display");
            }
            Err(e) => tracing::warn!(error=%e, id, "failed to switch display"),
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
    capture_ctl: &mut CaptureController,
    access: &AccessControl,
    channel_binding: &[u8],
    host_identity: Option<&crate::identity::DeviceIdentity>,
    local_fingerprint: &[u8],
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
        Payload::Hello(h) => {
            // 1. Protocol compatibility, then 2. unattended-access authorization.
            let decision = proto::check_compatibility(env.protocol_major)
                .map_err(|e| format!("{e}"))
                .and_then(|()| access.authorize(&h, channel_binding));
            match decision {
                Ok(()) => {
                    // Prove the host's identity bound to this DTLS session so the
                    // viewer can authenticate the real endpoint (closes A2 MITM).
                    let ack = match host_identity {
                        Some(id) => proto::hello_ack_ok_signed(
                            device_name,
                            0,
                            id.public_key_bytes().to_vec(),
                            id.access_proof(local_fingerprint).to_vec(),
                        ),
                        None => proto::hello_ack_ok(device_name, 0),
                    };
                    transport.send_data(Bytes::from(proto::encode(&ack)));
                    // Advertise the host's displays so the viewer can switch monitors.
                    let list = proto::display_list(capture_ctl.descriptors());
                    transport.send_data(Bytes::from(proto::encode(&list)));
                    tracing::info!(viewer = %h.device_name, "viewer accepted");
                }
                Err(reason) => {
                    let ack = proto::hello_ack_reject(reason.clone());
                    transport.send_data(Bytes::from(proto::encode(&ack)));
                    tracing::warn!(%reason, viewer = %h.device_name, "rejected viewer");
                }
            }
        }
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
        Payload::RequestKeyframe(_) => capture_ctl.force_keyframe.store(true, Ordering::Relaxed),
        Payload::SelectDisplay(sel) => capture_ctl.select(sel.id),
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

#[cfg(test)]
mod tests {
    use super::AccessControl;
    use crate::identity::DeviceIdentity;
    use openreach_protocol as proto;
    use std::collections::HashSet;

    /// Build a viewer `Hello` carrying an access proof bound to `binding`.
    fn authed_hello(id: &DeviceIdentity, binding: &[u8]) -> proto::Hello {
        let env = proto::hello_authenticated(
            "viewer",
            proto::Role::Viewer,
            0,
            id.public_key_bytes().to_vec(),
            id.access_proof(binding).to_vec(),
        );
        match env.payload.unwrap() {
            proto::pb::envelope::Payload::Hello(h) => h,
            _ => unreachable!(),
        }
    }

    #[test]
    fn authorize_accepts_bound_proof_and_rejects_mitm() {
        let id = DeviceIdentity::generate().unwrap();
        let fp = b"SHA-256 AA:BB:CC";
        let hello = authed_hello(&id, fp);

        let mut authorized = HashSet::new();
        authorized.insert(id.device_id());
        let access = AccessControl {
            require: true,
            authorized,
        };

        // Correct device + matching session fingerprint → accepted.
        assert!(access.authorize(&hello, fp).is_ok());

        // Same proof but a DIFFERENT fingerprint (a relay that MITM'd the DTLS
        // and had to present its own cert) → rejected.
        assert!(access.authorize(&hello, b"SHA-256 99:88:77").is_err());
    }

    #[test]
    fn authorize_rejects_unknown_device_and_missing_proof() {
        let id = DeviceIdentity::generate().unwrap();
        let fp = b"SHA-256 AA:BB:CC";
        let access = AccessControl {
            require: true,
            authorized: HashSet::new(), // empty → nobody authorized
        };
        assert!(access.authorize(&authed_hello(&id, fp), fp).is_err());

        // No proof at all is rejected when authorization is required.
        let bare = match proto::hello("v", proto::Role::Viewer, 0).payload.unwrap() {
            proto::pb::envelope::Payload::Hello(h) => h,
            _ => unreachable!(),
        };
        assert!(access.authorize(&bare, fp).is_err());
    }

    #[test]
    fn authorize_is_open_when_not_required() {
        let access = AccessControl {
            require: false,
            authorized: HashSet::new(),
        };
        let bare = match proto::hello("v", proto::Role::Viewer, 0).payload.unwrap() {
            proto::pb::envelope::Payload::Hello(h) => h,
            _ => unreachable!(),
        };
        assert!(access.authorize(&bare, b"").is_ok());
    }
}
