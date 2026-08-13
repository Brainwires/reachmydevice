//! System-mode **capture agent**: the per-session screen source.
//!
//! `rmdd agent` runs inside one graphical session (as the `gdm` greeter, then as
//! the logged-in user) and does nothing but capture+encode the screen and stream
//! encoded H.264 to the [broker](crate::broker) over the Unix socket. It holds no
//! identity or token — those live in the broker — so the greeter's ephemeral home
//! is a non-issue.
//!
//! The capture backend is auto-detected from the session's own environment (the
//! same `rmd_capture` logic the single-process host uses), so whichever session
//! the user selected at the greeter (GNOME/Wayland, X11, Plasma…) is captured with
//! the right backend without any agent-side branching.
//!
//! Capture is gated: the agent does not grab the screen until the broker sends
//! `SetCapturing(true)` (i.e. a viewer is authorized), so nothing is captured — and
//! no OS screen-share indicator lit — while no one is watching.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::mpsc;

use rmd_ipc::{AgentMsg, BackendKind, BrokerMsg, DisplayDesc, SessionPhase};
use tokio::sync::mpsc as tmpsc;

use crate::host::CaptureController;

/// How the agent captures + encodes. Read from the environment (set by the
/// `rmd-agent` unit / `/etc/xdg/autostart` entry) with sensible defaults.
pub struct AgentConfig {
    pub width: u32,
    pub height: u32,
    pub fps: u32,
    pub bitrate_bps: u32,
    pub video_codec: rmd_codec::VideoCodec,
    pub capture_source: rmd_capture::CaptureSource,
    pub display_index: usize,
}

impl AgentConfig {
    pub fn from_env() -> Self {
        let u32_env = |k: &str, d: u32| {
            std::env::var(k)
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(d)
        };
        AgentConfig {
            width: u32_env("RMD_WIDTH", 1920),
            height: u32_env("RMD_HEIGHT", 1080),
            fps: u32_env("RMD_FPS", 30),
            bitrate_bps: u32_env("RMD_BITRATE", 8_000_000),
            // H.264 by default (matches the broker's transport default). AV1 would
            // need both sides configured; a follow-up passes the codec via the unit.
            video_codec: rmd_codec::VideoCodec::H264,
            capture_source: match std::env::var("RMD_CAPTURE_SOURCE").as_deref() {
                Ok("virtual") => rmd_capture::CaptureSource::Virtual,
                _ => rmd_capture::CaptureSource::Monitor,
            },
            display_index: u32_env("RMD_DISPLAY_INDEX", 0) as usize,
        }
    }
}

/// Which session phase this agent is in — greeter (running as the DM's greeter
/// user) or a logged-in user session. Informational for the broker's handover
/// logging; derived from the real uid matching a known greeter account.
fn detect_phase() -> SessionPhase {
    // SAFETY: getuid is always safe.
    let uid = unsafe { libc::getuid() };
    for name in ["gdm", "sddm", "lightdm"] {
        if uid_of(name) == Some(uid) {
            return SessionPhase::Greeter;
        }
    }
    SessionPhase::User
}

fn uid_of(name: &str) -> Option<u32> {
    let cname = std::ffi::CString::new(name).ok()?;
    // SAFETY: read pw_uid immediately from the returned static buffer.
    unsafe {
        let pw = libc::getpwnam(cname.as_ptr());
        if pw.is_null() { None } else { Some((*pw).pw_uid) }
    }
}

/// Map the capture backend selection to the wire enum (best-effort, for the
/// broker's telemetry — mirrors `rmd_capture`'s internal detection).
fn detect_backend() -> BackendKind {
    if std::env::var_os("WAYLAND_DISPLAY").is_none() {
        return BackendKind::X11;
    }
    let is_gnome = std::env::var("XDG_CURRENT_DESKTOP")
        .map(|d| d.to_ascii_lowercase().contains("gnome"))
        .unwrap_or(false);
    if is_gnome {
        BackendKind::GnomeWayland
    } else {
        BackendKind::OtherWayland
    }
}

/// Control commands the socket-reader forwards to the capture-control thread
/// (which owns the non-`Send` [`CaptureController`]).
enum CaptureCmd {
    SetCapturing(bool),
    Select(u32),
    SetShowCursor(bool),
}

/// Run the capture agent: connect to the broker, announce the session, then
/// capture+encode and stream frames until the broker or session goes away.
pub fn run_agent(cfg: AgentConfig) -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(run_agent_async(cfg))
}

async fn run_agent_async(cfg: AgentConfig) -> anyhow::Result<()> {
    let sock = rmd_ipc::socket_path();
    let stream = tokio::net::UnixStream::connect(&sock)
        .await
        .map_err(|e| anyhow::anyhow!("agent: connect {}: {e}", sock.display()))?;
    tracing::info!(socket = %sock.display(), "agent: connected to broker");
    let (mut rd, mut wr) = stream.into_split();

    // Enumerate displays + geometry for the Hello (best-effort).
    let displays: Vec<DisplayDesc> = rmd_capture::list_displays()
        .unwrap_or_default()
        .iter()
        .map(|d| DisplayDesc {
            id: d.index as u32,
            width: d.width,
            height: d.height,
            name: format!("Display {}", d.index + 1),
            primary: d.index == 0,
        })
        .collect();
    let monitor_rect = rmd_capture::primary_monitor_rect().map(|r| rmd_ipc::MonitorRect {
        ox: r.ox,
        oy: r.oy,
        mw: r.mw,
        mh: r.mh,
        dw: r.dw,
        dh: r.dh,
    });
    let hello = AgentMsg::Hello {
        phase: detect_phase(),
        backend: detect_backend(),
        // SAFETY: getuid is always safe.
        uid: unsafe { libc::getuid() },
        monitor_rect,
        displays,
    };
    rmd_ipc::write_msg(&mut wr, &hello).await?;

    // Shared control state read by the encode loop.
    let bitrate = Arc::new(AtomicU32::new(cfg.bitrate_bps));
    let force_keyframe = Arc::new(AtomicBool::new(true));

    // Encoded frames flow encode-thread -> async writer -> socket.
    let (enc_tx, mut enc_rx) = tmpsc::unbounded_channel::<rmd_codec::EncodedFrame>();
    // Capture control flows socket-reader -> capture-control thread.
    let (ctrl_tx, ctrl_rx) = mpsc::channel::<CaptureCmd>();

    // Capture-control thread: owns the (non-Send) CaptureController and applies
    // resume/pause/select/cursor commands. Also owns the frame channel feeding the
    // encode thread.
    let (frame_tx, frame_rx) = mpsc::channel::<rmd_capture::Frame>();
    let capture_cfg = rmd_capture::CaptureConfig {
        width: cfg.width,
        height: cfg.height,
        fps: cfg.fps,
        show_cursor: true,
        restore_token: None,
        capture_source: cfg.capture_source,
    };
    let fk_capture = force_keyframe.clone();
    let display_index = cfg.display_index;
    std::thread::Builder::new()
        .name("rmd-agent-capture".into())
        .spawn(move || {
            let mut ctl = match CaptureController::start(
                capture_cfg,
                display_index,
                frame_tx,
                fk_capture,
                None, // stateless: no identity, so no restore-token persistence
            ) {
                Ok(c) => c,
                Err(e) => {
                    tracing::error!(error=%e, "agent: capture init failed");
                    return;
                }
            };
            while let Ok(cmd) = ctrl_rx.recv() {
                match cmd {
                    CaptureCmd::SetCapturing(true) => ctl.resume(),
                    CaptureCmd::SetCapturing(false) => ctl.pause(),
                    CaptureCmd::Select(id) => ctl.select(id),
                    CaptureCmd::SetShowCursor(show) => ctl.set_show_cursor(show),
                }
            }
            tracing::info!("agent: capture-control thread ended");
        })?;

    // Encode thread: frames -> H.264 -> enc_tx. Bitrate + keyframe are driven by
    // the broker via the shared atomics.
    spawn_agent_encode_thread(&cfg, force_keyframe.clone(), bitrate.clone(), frame_rx, enc_tx)?;

    // Writer task: encoded frames -> socket.
    let writer = tokio::spawn(async move {
        while let Some(ef) = enc_rx.recv().await {
            let msg = AgentMsg::Video {
                annexb: ef.data.to_vec(),
                is_keyframe: ef.is_keyframe,
                capture_ts_micros: ef.capture_ts_micros,
            };
            if rmd_ipc::write_msg(&mut wr, &msg).await.is_err() {
                break;
            }
        }
        let _ = tokio::io::AsyncWriteExt::shutdown(&mut wr).await;
    });

    // Reader loop: broker control -> capture-control thread / atomics.
    loop {
        match rmd_ipc::read_msg::<_, BrokerMsg>(&mut rd).await {
            Ok(BrokerMsg::SetCapturing(on)) => {
                let _ = ctrl_tx.send(CaptureCmd::SetCapturing(on));
            }
            Ok(BrokerMsg::SetBitrate(bps)) => bitrate.store(bps, Ordering::Relaxed),
            Ok(BrokerMsg::ForceKeyframe) => force_keyframe.store(true, Ordering::Relaxed),
            Ok(BrokerMsg::SelectDisplay(id)) => {
                let _ = ctrl_tx.send(CaptureCmd::Select(id));
            }
            Ok(BrokerMsg::SetShowCursor(show)) => {
                let _ = ctrl_tx.send(CaptureCmd::SetShowCursor(show));
            }
            Err(_) => break, // broker closed
        }
    }
    tracing::info!("agent: broker connection closed; exiting");
    writer.abort();
    Ok(())
}

/// Agent-side encode loop: mirrors the host's encode thread but writes to the IPC
/// channel and takes bitrate from a broker-driven atomic. No digital zoom (a
/// viewer-zoom relay is a follow-up).
fn spawn_agent_encode_thread(
    cfg: &AgentConfig,
    force_keyframe: Arc<AtomicBool>,
    bitrate: Arc<AtomicU32>,
    frame_rx: mpsc::Receiver<rmd_capture::Frame>,
    enc_tx: tmpsc::UnboundedSender<rmd_codec::EncodedFrame>,
) -> anyhow::Result<()> {
    let enc_cfg = rmd_codec::EncoderConfig {
        width: cfg.width,
        height: cfg.height,
        fps: cfg.fps,
        bitrate_bps: cfg.bitrate_bps,
    };
    let video_codec = cfg.video_codec;
    std::thread::Builder::new()
        .name("rmd-agent-encode".into())
        .spawn(move || {
            let mut encoder = match rmd_codec::new_encoder(video_codec, enc_cfg) {
                Ok(e) => e,
                Err(e) => {
                    tracing::error!(error=%e, "agent: encoder init failed");
                    return;
                }
            };
            while let Ok(mut frame) = frame_rx.recv() {
                // Keep-latest: skip to the newest frame so latency can't grow.
                while let Ok(newer) = frame_rx.try_recv() {
                    frame = newer;
                }
                encoder.set_target_bitrate(bitrate.load(Ordering::Relaxed));
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
                        if enc_tx.send(ef).is_err() {
                            break; // writer/socket gone
                        }
                    }
                    Ok(None) => {}
                    Err(e) => tracing::warn!(error=%e, "agent: encode error"),
                }
            }
            tracing::info!("agent: encode thread ended (capture closed)");
        })?;
    Ok(())
}
