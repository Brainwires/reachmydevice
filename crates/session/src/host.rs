//! Host session: capture → encode → transport (send), and control data → input.
//!
//! Headless. Spawns capture (its own queue), an encode thread, the transport
//! driver (its own thread), and runs the control/event loop here. The host is
//! the WebRTC offerer and the video sender; it validates the viewer's protocol
//! version, injects the viewer's input, and answers Ping with Pong.

#[cfg(feature = "audio")]
use crate::audio::AudioCapture;
use crate::clipboard::ClipboardSync;
use crate::filexfer::{FileEvent, FileTransferConfig, FileTransfers};
use crate::signal::Signaling;
use bytes::Bytes;
use rmd_capture as capture;
use rmd_codec as codec;
use rmd_input as input;
use rmd_protocol as proto;
use rmd_protocol::pb::envelope::Payload;
use rmd_transport::{
    IceServer, SignalMsg, Transport, TransportConfig, TransportEvent, TransportRole,
    TransportSender,
};
#[cfg(feature = "audio")]
use std::sync::atomic::AtomicU64;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

/// Map the codec crate's `VideoCodec` to the transport's local mirror (the
/// transport deliberately doesn't link the codec crate).
pub(crate) fn to_transport_codec(c: codec::VideoCodec) -> rmd_transport::VideoCodec {
    match c {
        codec::VideoCodec::H264 => rmd_transport::VideoCodec::H264,
        codec::VideoCodec::Av1 => rmd_transport::VideoCodec::Av1,
    }
}

/// Map the codec crate's `VideoCodec` to the protocol enum (for the HelloAck
/// announcement + the viewer's decode-capability check).
pub(crate) fn to_proto_codec(c: codec::VideoCodec) -> proto::VideoCodec {
    match c {
        codec::VideoCodec::H264 => proto::VideoCodec::H264,
        codec::VideoCodec::Av1 => proto::VideoCodec::Av1,
    }
}

/// Reject a viewer that cannot decode the codec this host is sending. An empty
/// `supported_video_codecs` means a MINOR<5 peer, which is H.264-only — so an
/// AV1 host correctly refuses it, and an H.264 host accepts it.
fn check_codec_compatible(h: &proto::Hello, host_codec: proto::VideoCodec) -> Result<(), String> {
    let supported: Vec<i32> = if h.supported_video_codecs.is_empty() {
        vec![proto::VideoCodec::H264 as i32]
    } else {
        h.supported_video_codecs.clone()
    };
    if supported.contains(&(host_codec as i32)) {
        Ok(())
    } else {
        Err(format!(
            "viewer cannot decode the host's video codec ({:?}); \
             it supports {:?}",
            host_codec, supported
        ))
    }
}

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
    pub ice_servers: Vec<IceServer>,
    /// Local UDP bind address for the transport (e.g. `0.0.0.0:0`, or
    /// `127.0.0.1:0` for a same-host loopback session).
    pub bind_addr: String,
    /// Stream host audio (Opus) to the viewer. Off by default — see `audio.rs`
    /// for the current source (default input device) and transport caveats.
    pub enable_audio: bool,
    /// Video codec to encode with. Default H.264 (symmetric, browser-decodable).
    /// `VideoCodec::Av1` uses the pure-Rust rav1e encoder (requires the codec
    /// crate's `av1` feature) for browser viewers, which decode AV1 themselves.
    pub video_codec: codec::VideoCodec,
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
    /// Optional connection password (RealVNC-style shared secret). When set, a
    /// viewer must supply the matching password in its `Hello` before the session
    /// is authorized; when `None`, no password is required. Independent of the
    /// device-identity allowlist — both can apply. Set via `rmdd set password`.
    pub connect_password: Option<String>,
}

impl Default for HostConfig {
    fn default() -> Self {
        Self {
            display_index: 0,
            width: 1920,
            height: 1080,
            fps: 30,
            bitrate_bps: 8_000_000,
            device_name: "rmd-host".to_string(),
            ice_servers: Vec::new(),
            bind_addr: "0.0.0.0:0".to_string(),
            enable_audio: false,
            video_codec: codec::VideoCodec::default(),
            require_authorization: false,
            authorized_device_ids: Vec::new(),
            identity: None,
            connect_password: None,
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
        video_codec: to_transport_codec(cfg.video_codec),
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
    // Whether a viewer's DTLS session is up. Tracks connection lifecycle.
    let connected = Arc::new(AtomicBool::new(false));
    // Whether the connected viewer has been AUTHORIZED (sent a Hello we accepted).
    // This is the security boundary: no screen is encoded/streamed, no input is
    // injected, and no file/clipboard/display action is applied until it's true.
    // Reset to false on every (re)connect, so each session must re-authorize.
    let authorized = Arc::new(AtomicBool::new(false));

    // Unattended-access policy.
    let access = AccessControl {
        require: cfg.require_authorization,
        authorized: cfg.authorized_device_ids.iter().cloned().collect(),
    };
    // An unattended host must stay reachable, so inhibit system idle sleep for
    // the host's lifetime (opt out with RMD_NO_KEEPAWAKE). Held in `_keep_awake`.
    let _keep_awake = if access.require {
        tracing::info!(
            authorized = access.authorized.len(),
            "unattended access ENFORCED: only authorized devices may connect"
        );
        (std::env::var("RMD_NO_KEEPAWAKE").is_err())
            .then(|| crate::power::prevent_sleep("ReachMyDevice unattended host"))
    } else {
        tracing::warn!(
            "unattended access gate OFF: any viewer completing the handshake is accepted"
        );
        None
    };

    // Digital-zoom crop rect (viewer-driven, via `SetZoom`). Shared by the encode
    // thread (which crops+scales the video to it) and the input path (which remaps
    // pointer coords through it, so taps land inside the zoomed region). Default:
    // no zoom (full screen).
    let zoom = Arc::new(Mutex::new(codec::CropRect::FULL));

    // Encode thread: frames -> H.264 -> transport, with GCC-driven bitrate.
    // Gated on `authorized`, so screen content is never streamed to a peer that
    // has completed DTLS but not been authorized.
    spawn_encode_thread(
        &cfg,
        transport.sender(),
        force_keyframe.clone(),
        authorized.clone(),
        frame_rx,
        zoom.clone(),
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

    // Optional audio capture (default off, and only in builds compiled with the
    // `audio` feature). Held alive for the session; the callback sends Opus frames
    // only while a viewer is connected.
    #[cfg(feature = "audio")]
    let _audio = if cfg.enable_audio {
        let sender = transport.sender();
        let authorized = authorized.clone();
        let seq = Arc::new(AtomicU64::new(0));
        match AudioCapture::start(48_000, move |pkt| {
            if authorized.load(Ordering::Relaxed) {
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
    #[cfg(not(feature = "audio"))]
    if cfg.enable_audio {
        tracing::warn!(
            "audio requested but this build has no `audio` feature; \
             rebuild with `--features audio` to enable host->viewer Opus audio"
        );
    }

    tracing::info!(device = %cfg.device_name, "host ready; waiting for a viewer to connect");
    on_status(HostStatus::Waiting);

    // The viewer's DTLS fingerprint (from its answer), used to bind its access
    // proof to this session.
    let mut remote_fingerprint: Option<String> = None;
    // Our own DTLS fingerprint, from the offer we emit — the value the host signs
    // into its identity proof so the viewer can authenticate this endpoint.
    let mut local_fingerprint: Option<String> = None;
    // Tracks the authorized-state edge so we surface "session active" only once,
    // when the viewer actually becomes authorized (not merely DTLS-connected).
    let mut was_authorized = false;

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
        // A different viewer device just took over. Tear down the current peer
        // connection and rebuild with a fresh offer aimed at the newcomer, rather
        // than letting it answer the previous viewer's stale offer (which stalls
        // the first attempt until the old PC times out). See `RendezvousClient`.
        if signal.take_peer_switched() {
            tracing::info!("viewer switched device; rebuilding session with a fresh offer");
            transport.request_ice_restart();
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
                // DTLS is up, but the viewer is NOT trusted yet — it must send a
                // Hello we accept. Until then no capture, no video, no input.
                connected.store(true, Ordering::Relaxed);
                authorized.store(false, Ordering::Relaxed);
                was_authorized = false;
                tracing::info!("viewer connected (DTLS); awaiting authorization");
            }
            TransportEvent::Disconnected => {
                tracing::warn!("remote session ended");
                connected.store(false, Ordering::Relaxed);
                authorized.store(false, Ordering::Relaxed);
                was_authorized = false;
                // Stop capturing so nothing is grabbed (and the OS screen-share
                // indicator clears) while no viewer is connected.
                capture_ctl.pause();
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
                    &authorized,
                    remote_fingerprint.as_deref().unwrap_or_default().as_bytes(),
                    cfg.identity.as_deref(),
                    local_fingerprint.as_deref().unwrap_or_default().as_bytes(),
                    &cfg.device_name,
                    to_proto_codec(cfg.video_codec),
                    cfg.connect_password.as_deref(),
                    &zoom,
                );
                // The viewer just became authorized (accepted Hello) — surface the
                // active session once, and start streaming.
                if authorized.load(Ordering::Relaxed) && !was_authorized {
                    was_authorized = true;
                    tracing::warn!("★ REMOTE SESSION ACTIVE ★");
                    on_status(HostStatus::Active);
                }
            }
            TransportEvent::Video { .. } => {} // host does not receive video
            TransportEvent::KeyframeRequested => {
                // The viewer's RTCP (PLI/FIR) asked for a fresh keyframe after loss.
                // Force an IDR so it recovers now rather than waiting for the next
                // periodic keyframe. Cheap and idempotent (a swap-once flag).
                capture_ctl.force_keyframe.store(true, Ordering::Relaxed);
            }
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
    /// The live capture session while a viewer is connected. `None` while idle —
    /// capturing is stopped so nothing is grabbed (and macOS drops its
    /// "screen is being shared" indicator) when no one is controlling.
    handle: Option<Box<dyn capture::CaptureSession>>,
    force_keyframe: Arc<AtomicBool>,
}

impl CaptureController {
    /// Prepare the controller **without** starting capture. Enumerates displays
    /// (metadata only — no capture stream, so no sharing indicator) and waits for
    /// [`resume`](Self::resume) when a viewer connects.
    fn start(
        config: capture::CaptureConfig,
        display_index: usize,
        frame_tx: mpsc::Sender<capture::Frame>,
        force_keyframe: Arc<AtomicBool>,
    ) -> anyhow::Result<Self> {
        let displays = capture::list_displays().unwrap_or_default();
        Ok(Self {
            config,
            frame_tx,
            displays,
            current: display_index,
            handle: None,
            force_keyframe,
        })
    }

    /// Start capturing the current display (viewer connected). Idempotent.
    fn resume(&mut self) {
        if self.handle.is_some() {
            return;
        }
        match capture::start_capture(self.config.clone(), self.current, self.frame_tx.clone()) {
            Ok(h) => {
                self.handle = Some(h);
                self.force_keyframe.store(true, Ordering::Relaxed);
                tracing::info!(display = self.current, "capture started (viewer connected)");
            }
            Err(e) => tracing::error!(error=%e, "failed to start capture on viewer connect"),
        }
    }

    /// Stop capturing (viewer disconnected) — drops the session, so the OS-level
    /// screen-capture indicator goes away while idle. Idempotent.
    fn pause(&mut self) {
        if self.handle.take().is_some() {
            tracing::info!("capture stopped (no viewer connected)");
        }
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

    /// Set whether the OS cursor is baked into the captured video, restarting the
    /// live stream if the setting actually changed while capturing. A viewer that
    /// renders its own cursor asks for `false` so the pointer isn't subject to the
    /// video pipeline's latency (it draws the cursor locally instead). A no-op when
    /// unchanged, so re-Hellos on the same session don't churn the capture.
    fn set_show_cursor(&mut self, show: bool) {
        if self.config.show_cursor == show {
            return;
        }
        self.config.show_cursor = show;
        if self.handle.is_none() {
            return; // not capturing yet — the next resume() picks up the new config
        }
        match capture::start_capture(self.config.clone(), self.current, self.frame_tx.clone()) {
            Ok(handle) => {
                self.handle = Some(handle); // dropping the old session stops it
                self.force_keyframe.store(true, Ordering::Relaxed);
                tracing::info!(show_cursor = show, "capture cursor visibility changed");
            }
            Err(e) => tracing::warn!(error=%e, "failed to restart capture for cursor change"),
        }
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
        self.current = idx;
        // Only (re)start the stream if we're currently capturing (a viewer is
        // connected); otherwise just remember the choice for the next `resume`.
        if self.handle.is_none() {
            return;
        }
        match capture::start_capture(self.config.clone(), idx, self.frame_tx.clone()) {
            Ok(handle) => {
                self.handle = Some(handle); // dropping the old session stops it
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
    authorized: Arc<AtomicBool>,
    frame_rx: mpsc::Receiver<capture::Frame>,
    zoom: Arc<Mutex<codec::CropRect>>,
) -> anyhow::Result<()> {
    let enc_cfg = codec::EncoderConfig {
        width: cfg.width,
        height: cfg.height,
        fps: cfg.fps,
        bitrate_bps: cfg.bitrate_bps,
    };
    let video_codec = cfg.video_codec;
    std::thread::Builder::new()
        .name("rmd-encode".into())
        .spawn(move || {
            let mut encoder = match codec::new_encoder(video_codec, enc_cfg) {
                Ok(e) => e,
                Err(e) => {
                    tracing::error!(error=%e, "encoder init failed");
                    return;
                }
            };
            // Reused across frames; only does work when a zoom is active.
            let mut scaler = codec::Scaler::new();
            while let Ok(mut frame) = frame_rx.recv() {
                // Keep-latest: if we fell behind (encoding slower than capture, or a
                // slow link backing the pipeline up), skip straight to the newest
                // captured frame and drop the stale ones. The capture→encode channel
                // is unbounded and FIFO, so without this the encoder perpetually
                // works on old frames and latency grows without bound ("minutes
                // behind"). A screen share only ever wants the freshest frame;
                // dropping *raw* frames is safe (unlike dropping encoded P-frames,
                // which would corrupt the stream) — it just lowers the effective FPS.
                let mut dropped = 0u32;
                while let Ok(newer) = frame_rx.try_recv() {
                    frame = newer;
                    dropped += 1;
                }
                if dropped > 0 {
                    tracing::trace!(dropped, "encode: dropped stale frames to stay live");
                }
                // Only encode/send once the viewer is authorized (never stream the
                // screen to an unauthorized peer; also avoids RTP before SRTP is up
                // and saves CPU when idle).
                if !authorized.load(Ordering::Relaxed) {
                    continue;
                }
                // Track the GCC target so the stream adapts to the link.
                encoder.set_target_bitrate(sender.target_bitrate_bps());
                let force = force_keyframe.swap(false, Ordering::Relaxed);
                // Digital zoom: crop the requested sub-rect and scale it back to
                // the frame's own size, so the wire resolution never changes. When
                // there's no zoom (the common case), `crop_scale` returns None and
                // we encode the frame untouched — zero added cost.
                let rect = *zoom.lock().unwrap();
                let (data, width, height, stride) = match scaler.crop_scale(
                    &frame.data,
                    frame.width,
                    frame.height,
                    frame.bytes_per_row,
                    rect,
                    frame.width,
                    frame.height,
                ) {
                    Some(scaled) => (scaled, frame.width, frame.height, frame.width * 4),
                    None => (
                        frame.data.as_ref(),
                        frame.width,
                        frame.height,
                        frame.bytes_per_row,
                    ),
                };
                match encoder.encode(
                    data,
                    width,
                    height,
                    stride,
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
/// The authorization gate, as a pure predicate so a regression test can pin the
/// exact allowlist. Before a viewer is authorized (its `Hello` accepted), ONLY a
/// `Hello` may be processed; every other control message — input injection, file
/// transfer, clipboard, keyframe, display switch, ping — must be dropped. This is
/// what actually enforces `require_authorization`; the HelloAck alone gates
/// nothing. A future refactor that widens this (e.g. lets `Input` through before
/// authorization) re-opens the pre-auth-RCE hole, so it is tested exhaustively.
fn authorization_permits(payload: &Payload, authorized: bool) -> bool {
    authorized || matches!(payload, Payload::Hello(_))
}

/// Whether a viewer's supplied connection password satisfies the host's. `None`
/// configured → no password required (always ok). Constant-time comparison.
fn verify_connect_password(configured: Option<&str>, supplied: &str) -> bool {
    match configured {
        None => true,
        Some(expected) => ct_eq(expected.as_bytes(), supplied.as_bytes()),
    }
}

/// Constant-time byte comparison (length may leak; a password's length is not the
/// secret). Avoids a timing oracle on the password compare.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

// This dispatcher legitimately depends on the whole session's control surface
// (transport, injector, clipboard, files, capture, access, identity, codec); the
// authorization gate added one more. Splitting it would only scatter that state.
#[allow(clippy::too_many_arguments)]
fn handle_control(
    bytes: &[u8],
    transport: &Transport,
    injector: &mut Option<Box<dyn input::Injector>>,
    clipboard: &ClipboardSync,
    files: &mut FileTransfers,
    capture_ctl: &mut CaptureController,
    access: &AccessControl,
    authorized: &AtomicBool,
    channel_binding: &[u8],
    host_identity: Option<&crate::identity::DeviceIdentity>,
    local_fingerprint: &[u8],
    device_name: &str,
    host_codec: proto::VideoCodec,
    connect_password: Option<&str>,
    zoom: &Mutex<codec::CropRect>,
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

    // AUTHORIZATION GATE. Only a `Hello` is processed before the viewer is
    // authorized; every other message (input injection, file transfer, clipboard,
    // display switch, keyframe/ping) is dropped until an accepted Hello sets
    // `authorized`. This is what actually enforces `require_authorization` — the
    // HelloAck alone gates nothing.
    if !authorization_permits(&payload, authorized.load(Ordering::Relaxed)) {
        tracing::debug!("dropping control message from unauthorized viewer");
        return;
    }

    // File-transfer payloads are handled by the transfer manager (only reached
    // once authorized, per the gate above).
    if files.handle(&payload) {
        return;
    }
    match payload {
        Payload::Hello(h) => {
            // 1. Protocol compatibility, 2. the viewer can decode our codec, then
            // 3. unattended-access authorization.
            let decision = proto::check_compatibility(env.protocol_major)
                .map_err(|e| format!("{e}"))
                .and_then(|()| check_codec_compatible(&h, host_codec))
                .and_then(|()| access.authorize(&h, channel_binding));
            // 4. Connection password (RealVNC-style). Checked separately from the
            // chain above so a missing/wrong password gets a *distinguishable* ack
            // (`password_required`), prompting the viewer to ask + retry — but only
            // once the device-identity checks passed, so we never prompt an
            // otherwise-rejected peer.
            if decision.is_ok() && !verify_connect_password(connect_password, &h.password) {
                authorized.store(false, Ordering::Relaxed);
                let ack = proto::hello_ack_password_required("connection password required");
                transport.send_data(Bytes::from(proto::encode(&ack)));
                tracing::warn!(viewer = %h.device_name, "viewer needs a connection password");
                return;
            }
            match decision {
                Ok(()) => {
                    // Authorize this session: unblocks input/capture/video/file/
                    // clipboard handling and starts the screen stream.
                    authorized.store(true, Ordering::Relaxed);
                    // If the viewer renders its own cursor, drop the OS cursor from
                    // the capture (set before resume so the stream starts cursor-less)
                    // — the pointer is then lag-free client-side, not pipelined video.
                    let client_cursor = h.features & proto::FEATURE_CLIENT_CURSOR != 0;
                    capture_ctl.set_show_cursor(!client_cursor);
                    capture_ctl.resume();
                    // Prove the host's identity bound to this DTLS session so the
                    // viewer can authenticate the real endpoint (closes A2 MITM).
                    let ack = match host_identity {
                        Some(id) => proto::hello_ack_ok_signed(
                            device_name,
                            0,
                            id.public_key_bytes().to_vec(),
                            id.access_proof(local_fingerprint).to_vec(),
                            host_codec,
                        ),
                        None => proto::hello_ack_ok(device_name, 0, host_codec),
                    };
                    transport.send_data(Bytes::from(proto::encode(&ack)));
                    // Advertise the host's displays so the viewer can switch monitors.
                    let list = proto::display_list(capture_ctl.descriptors());
                    transport.send_data(Bytes::from(proto::encode(&list)));
                    tracing::info!(viewer = %h.device_name, "viewer accepted");
                }
                Err(reason) => {
                    // Stay unauthorized: the peer's subsequent messages keep being
                    // dropped, and no screen is streamed.
                    authorized.store(false, Ordering::Relaxed);
                    let ack = proto::hello_ack_reject(reason.clone());
                    transport.send_data(Bytes::from(proto::encode(&ack)));
                    tracing::warn!(%reason, viewer = %h.device_name, "rejected viewer");
                }
            }
        }
        Payload::Input(ie) => {
            if let (Some(inj), Some(mut ev)) = (injector.as_deref_mut(), ie.event) {
                // Remap pointer coords through the active zoom crop: the viewer
                // sends coords normalized over the *visible* (cropped) region, so
                // `screen = crop.origin + coord * crop.size`. Non-positional events
                // (scroll/key) pass through. `sanitized()` makes a full rect a no-op.
                let rect = zoom.lock().unwrap().sanitized();
                if !rect.is_full() {
                    use proto::input_event::Event;
                    match &mut ev {
                        Event::MouseMove(m) => {
                            m.x = rect.x + m.x * rect.w;
                            m.y = rect.y + m.y * rect.h;
                        }
                        Event::MouseButton(b) => {
                            b.x = rect.x + b.x * rect.w;
                            b.y = rect.y + b.y * rect.h;
                        }
                        _ => {}
                    }
                }
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
        Payload::SetZoom(z) => {
            *zoom.lock().unwrap() = codec::CropRect {
                x: z.x,
                y: z.y,
                w: z.w,
                h: z.h,
            }
            .sanitized();
        }
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
    use super::{
        authorization_permits, check_codec_compatible, verify_connect_password, AccessControl,
    };
    use crate::identity::DeviceIdentity;
    use rmd_protocol as proto;
    use rmd_protocol::pb::envelope::Payload;
    use std::collections::HashSet;

    fn hello_payload() -> Payload {
        proto::hello("v", proto::Role::Viewer, 0).payload.unwrap()
    }

    /// Regression guard for the pre-authorization RCE hole: before a viewer is
    /// authorized, EVERY control message except `Hello` must be dropped. If a
    /// refactor lets any of these through pre-auth, this fails.
    #[test]
    fn authorization_gate_drops_every_non_hello_before_auth() {
        use proto::pb;
        // The sensitive control surface a peer could abuse before authorizing:
        // input injection, clipboard, file transfer, keyframe, display switch,
        // ping, view-only, audio. None may be processed while unauthorized.
        let gated: Vec<Payload> = vec![
            Payload::Input(pb::InputEvent::default()),
            Payload::Clipboard(pb::ClipboardUpdate::default()),
            Payload::FileOffer(pb::FileOffer::default()),
            Payload::FileChunk(pb::FileChunk::default()),
            Payload::SelectDisplay(pb::SelectDisplay::default()),
            Payload::RequestKeyframe(pb::RequestKeyframe::default()),
            Payload::Ping(pb::Ping::default()),
            Payload::ViewOnly(pb::ViewOnly::default()),
            Payload::Audio(pb::AudioFrame::default()),
        ];
        for p in &gated {
            assert!(
                !authorization_permits(p, false),
                "{p:?} must be dropped before authorization"
            );
            // Once authorized, the same messages are allowed through.
            assert!(
                authorization_permits(p, true),
                "{p:?} must pass once authorized"
            );
        }

        // A `Hello` is the ONLY message allowed pre-authorization (it's how a
        // viewer authorizes in the first place); it also passes post-auth.
        let hello = hello_payload();
        assert!(authorization_permits(&hello, false), "Hello must pass pre-auth");
        assert!(authorization_permits(&hello, true), "Hello must pass post-auth");
    }

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
    fn connect_password_gate() {
        // No password configured → any supplied value passes (feature off).
        assert!(verify_connect_password(None, ""));
        assert!(verify_connect_password(None, "whatever"));
        // Configured → exact match required (case-sensitive, constant-time).
        assert!(verify_connect_password(Some("taco"), "taco"));
        assert!(!verify_connect_password(Some("taco"), "Taco"));
        assert!(!verify_connect_password(Some("taco"), ""));
        assert!(!verify_connect_password(Some("taco"), "tacos"));
        assert!(!verify_connect_password(Some("taco"), "tac"));
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

    /// A synthetic BGRA frame with a moving gradient (mirrors `tests/pipeline.rs`).
    fn synthetic_bgra(w: u32, h: u32, seq: u64) -> Vec<u8> {
        let mut buf = vec![0u8; (w * h * 4) as usize];
        let o = (seq as u32).wrapping_mul(7);
        for y in 0..h {
            for x in 0..w {
                let i = ((y * w + x) * 4) as usize;
                buf[i] = ((x + o) % 256) as u8;
                buf[i + 1] = ((y + o) % 256) as u8;
                buf[i + 2] = ((x + y + o) % 256) as u8;
                buf[i + 3] = 255;
            }
        }
        buf
    }

    /// The stream half of the authorization gate: the real `spawn_encode_thread`
    /// must send NO video to a connected-but-unauthorized peer, and start streaming
    /// only once `authorized` flips true. Runs the actual encoder over a real
    /// loopback WebRTC transport (no screen/OS permissions needed).
    #[test]
    fn encode_thread_streams_no_video_until_authorized() {
        use super::{spawn_encode_thread, HostConfig};
        use rmd_capture::{Frame, PixelFormat};
        use rmd_transport::{
            Transport, TransportConfig, TransportEvent, TransportRole,
        };
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::mpsc;
        use std::sync::Arc;
        use std::time::{Duration, Instant};

        fn drain(t: &Transport) -> Vec<TransportEvent> {
            let mut out = Vec::new();
            while let Some(ev) = t.try_event() {
                out.push(ev);
            }
            out
        }
        // Bridge signaling both ways and tally any video the viewer receives.
        fn pump(host: &Transport, viewer: &Transport, hc: &mut bool, vc: &mut bool, video: &mut usize) {
            for ev in drain(host) {
                match ev {
                    TransportEvent::LocalSignal(s) => viewer.feed_signal(s),
                    TransportEvent::Connected => *hc = true,
                    _ => {}
                }
            }
            for ev in drain(viewer) {
                match ev {
                    TransportEvent::LocalSignal(s) => host.feed_signal(s),
                    TransportEvent::Connected => *vc = true,
                    TransportEvent::Video { .. } => *video += 1,
                    _ => {}
                }
            }
        }

        let (w, h) = (320u32, 240u32);
        let mk = |role| {
            Transport::spawn(TransportConfig {
                role,
                ice_servers: Vec::new(),
                bind_addr: "127.0.0.1:0".parse().unwrap(),
                video_bitrate_bps: 1_500_000,
                video_codec: Default::default(),
            })
            .expect("transport")
        };
        let host = mk(TransportRole::Host);
        let viewer = mk(TransportRole::Viewer);

        let (mut hc, mut vc, mut video) = (false, false, 0usize);
        let connect_deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < connect_deadline && !(hc && vc) {
            pump(&host, &viewer, &mut hc, &mut vc, &mut video);
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(hc && vc, "peers did not connect");

        // Spawn the REAL encode thread, initially unauthorized.
        let cfg = HostConfig { width: w, height: h, fps: 30, ..Default::default() };
        let authorized = Arc::new(AtomicBool::new(false));
        let force_keyframe = Arc::new(AtomicBool::new(true));
        let (frame_tx, frame_rx) = mpsc::channel::<Frame>();
        spawn_encode_thread(
            &cfg,
            host.sender(),
            force_keyframe,
            authorized.clone(),
            frame_rx,
            std::sync::Arc::new(std::sync::Mutex::new(codec::CropRect::FULL)),
        )
        .expect("encode thread");

        let mk_frame = |seq: u64| Frame {
            width: w,
            height: h,
            bytes_per_row: w * 4,
            format: PixelFormat::Bgra,
            data: synthetic_bgra(w, h, seq).into(),
            capture_ts_micros: seq * 33_000,
        };

        // Phase 1 — UNAUTHORIZED: feed frames for ~2s; the peer must get zero video.
        let mut seq = 0u64;
        let unauth_deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < unauth_deadline {
            frame_tx.send(mk_frame(seq)).unwrap();
            seq += 1;
            pump(&host, &viewer, &mut hc, &mut vc, &mut video);
            std::thread::sleep(Duration::from_millis(33));
        }
        assert_eq!(video, 0, "video leaked to an UNAUTHORIZED peer");

        // Phase 2 — AUTHORIZE: the same encoder must now stream to the peer.
        authorized.store(true, Ordering::Relaxed);
        let auth_deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < auth_deadline && video == 0 {
            frame_tx.send(mk_frame(seq)).unwrap();
            seq += 1;
            pump(&host, &viewer, &mut hc, &mut vc, &mut video);
            std::thread::sleep(Duration::from_millis(33));
        }
        assert!(video > 0, "authorized peer never received video");
    }

    fn hello_with_codecs(codecs: Vec<i32>) -> proto::Hello {
        let mut h = match proto::hello("v", proto::Role::Viewer, 0).payload.unwrap() {
            proto::pb::envelope::Payload::Hello(h) => h,
            _ => unreachable!(),
        };
        h.supported_video_codecs = codecs;
        h
    }

    #[test]
    fn codec_negotiation_matches_intersection() {
        use proto::VideoCodec;
        // A native viewer (H.264 only) ↔ H.264 host: accepted.
        let native = hello_with_codecs(vec![VideoCodec::H264 as i32]);
        assert!(check_codec_compatible(&native, VideoCodec::H264).is_ok());
        // Native viewer ↔ AV1 host: rejected (it can't decode AV1).
        assert!(check_codec_compatible(&native, VideoCodec::Av1).is_err());
        // A browser viewer advertising [AV1, H264] ↔ AV1 host: accepted.
        let browser = hello_with_codecs(vec![VideoCodec::Av1 as i32, VideoCodec::H264 as i32]);
        assert!(check_codec_compatible(&browser, VideoCodec::Av1).is_ok());
        assert!(check_codec_compatible(&browser, VideoCodec::H264).is_ok());
        // A legacy MINOR<5 peer (empty list) is treated as H.264-only.
        let legacy = hello_with_codecs(vec![]);
        assert!(check_codec_compatible(&legacy, VideoCodec::H264).is_ok());
        assert!(check_codec_compatible(&legacy, VideoCodec::Av1).is_err());
    }
}
