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

/// Lock-gated capture. In the auto-login deployment the session boots logged-in
/// but is kept **locked** for physical security; an authenticated remote viewer
/// unlocks it (no password — logind lets a session's own user unlock it, the same
/// path fingerprint readers use), and it re-locks on disconnect. Enabled by
/// `RMD_SESSION_LOCK=1` (set by the agent unit); a no-op otherwise, so a normal
/// interactive login is never touched.
///
/// SECURITY CAVEAT: with auto-login there is a brief (~1–2s) window at boot between
/// the session starting unlocked and the first lock taking effect (gnome-shell's
/// screensaver must be ready first — see [`lock`](Self::lock)'s retry). A physical
/// attacker with a USB HID-injection tool could act in that window. It's small and
/// self-closing; a box facing a physical-attack threat should use manual login (no
/// auto-login) instead, which removes the window entirely. Documented in
/// README-LINUX.md.
struct SessionGate {
    enabled: bool,
    session_id: Option<String>,
    /// Held `systemd-inhibit --what=idle` child, so GNOME's idle timer can't
    /// re-lock the screen mid-session while a viewer is connected.
    idle_inhibit: Option<std::process::Child>,
}

impl SessionGate {
    fn new() -> Self {
        let enabled = matches!(std::env::var("RMD_SESSION_LOCK").as_deref(), Ok("1"));
        let session_id = std::env::var("XDG_SESSION_ID")
            .ok()
            .filter(|s| !s.is_empty())
            .or_else(detect_session_id);
        if enabled && session_id.is_none() {
            tracing::warn!("RMD_SESSION_LOCK set but no logind session id found; lock-gating disabled");
        }
        Self { enabled, session_id, idle_inhibit: None }
    }

    fn loginctl(&self, verb: &str) {
        let Some(id) = &self.session_id else { return };
        let ok = std::process::Command::new("loginctl")
            .arg(verb)
            .arg(id)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if ok {
            tracing::info!(session = %id, "session {verb}");
        } else {
            tracing::warn!(session = %id, "loginctl {verb} failed");
        }
    }

    /// Whether logind reports the session locked.
    fn is_locked(&self) -> bool {
        let Some(id) = &self.session_id else { return false };
        std::process::Command::new("loginctl")
            .args(["show-session", id, "-p", "LockedHint", "--value"])
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "yes")
            .unwrap_or(false)
    }

    /// Lock the session and keep retrying until it actually takes. Right after
    /// (auto-)login gnome-shell's screensaver may not be ready yet and silently
    /// drops the lock request, leaving the box unlocked — so we re-issue the lock
    /// and poll `LockedHint` until it sticks (bounded, ~18s).
    fn lock(&mut self) {
        if !self.enabled {
            return;
        }
        if self.is_locked() {
            return;
        }
        for round in 0..6 {
            self.loginctl("lock-session");
            for _ in 0..6 {
                std::thread::sleep(std::time::Duration::from_millis(500));
                if self.is_locked() {
                    if round > 0 {
                        tracing::info!("session locked (took {} retr{})", round + 1, if round == 0 { "y" } else { "ies" });
                    }
                    return;
                }
            }
        }
        tracing::warn!("session did not lock after retries (gnome-shell not ready?)");
    }

    /// Unlock the session (viewer connected) and inhibit the idle-lock. Returns
    /// after a short delay so gnome-shell has dismissed the lock shield before
    /// capture starts (mutter inhibits ScreenCast until then).
    fn unlock(&mut self) {
        if !self.enabled {
            return;
        }
        self.loginctl("unlock-session");
        if self.idle_inhibit.is_none() {
            match std::process::Command::new("systemd-inhibit")
                .args([
                    "--what=idle",
                    "--who=rmdd",
                    "--why=remote session active",
                    "--mode=block",
                    "sleep",
                    "infinity",
                ])
                .spawn()
            {
                Ok(child) => self.idle_inhibit = Some(child),
                Err(e) => tracing::warn!(error=%e, "could not inhibit idle-lock"),
            }
        }
        // Let gnome-shell drop the lock shield before we try to capture.
        std::thread::sleep(std::time::Duration::from_millis(500));
    }

    /// Release the idle inhibitor (viewer gone).
    fn release_idle(&mut self) {
        if let Some(mut child) = self.idle_inhibit.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Best-effort: find this user's graphical seat0 session via logind, when
/// `XDG_SESSION_ID` isn't in the service environment.
fn detect_session_id() -> Option<String> {
    // SAFETY: getuid is always safe.
    let uid = unsafe { libc::getuid() };
    let out = std::process::Command::new("loginctl")
        .args(["list-sessions", "--no-legend", "--no-pager"])
        .output()
        .ok()?;
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        // Columns: SESSION UID USER SEAT ...
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() >= 4 && cols[1] == uid.to_string() && cols[3] == "seat0" {
            return Some(cols[0].to_string());
        }
    }
    None
}

/// Control commands the socket-reader forwards to the capture-control thread
/// (which owns the non-`Send` [`CaptureController`]).
enum CaptureCmd {
    SetCapturing(bool),
    Select(u32),
    SetShowCursor(bool),
}

/// Is this a display-manager greeter (login screen) session? The greeter cannot be
/// captured via ScreenCast (mutter inhibits it behind the lock shield — it needs
/// the privileged RemoteDesktop handover API we don't implement yet), so the agent
/// must not run there: it would only churn and, with lock-gating on, try to lock
/// the greeter itself.
fn is_greeter_session() -> bool {
    // logind's session class is authoritative.
    if let Ok(id) = std::env::var("XDG_SESSION_ID") {
        if let Ok(out) = std::process::Command::new("loginctl")
            .args(["show-session", &id, "-p", "Class", "--value"])
            .output()
        {
            if String::from_utf8_lossy(&out.stdout).trim() == "greeter" {
                return true;
            }
        }
    }
    if matches!(std::env::var("XDG_SESSION_CLASS").as_deref(), Ok("greeter")) {
        return true;
    }
    // Heuristic fallback: GDM's greeter runs from an ephemeral gdm home.
    matches!(std::env::var("HOME"), Ok(h) if h.starts_with("/run/gdm") || h.contains("gdm-greeter"))
}

/// Run the capture agent: connect to the broker, announce the session, then
/// capture+encode and stream frames until the broker or session goes away.
pub fn run_agent(cfg: AgentConfig) -> anyhow::Result<()> {
    if is_greeter_session() {
        // Exit cleanly with a distinct code; the unit's RestartPreventExitStatus=3
        // stops systemd from restart-looping us in the greeter.
        tracing::info!(
            "agent: greeter/login-screen session — capture needs the RemoteDesktop \
             handover API (unsupported); not running here"
        );
        std::process::exit(3);
    }
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
    let capture_thread = std::thread::Builder::new()
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
            // Lock-gating (auto-login deployment): keep the auto-logged-in session
            // locked at rest; unlock only while a viewer is connected.
            let mut gate = SessionGate::new();
            gate.lock();
            while let Ok(cmd) = ctrl_rx.recv() {
                match cmd {
                    CaptureCmd::SetCapturing(true) => {
                        // Unlock (passwordless) + inhibit idle-lock BEFORE capture,
                        // so mutter stops inhibiting ScreenCast.
                        gate.unlock();
                        ctl.resume();
                    }
                    CaptureCmd::SetCapturing(false) => {
                        ctl.pause();
                        gate.release_idle();
                        gate.lock();
                    }
                    CaptureCmd::Select(id) => ctl.select(id),
                    CaptureCmd::SetShowCursor(show) => ctl.set_show_cursor(show),
                }
            }
            // Thread ending (agent shutting down): drop capture and re-lock so we
            // never leave the session unlocked behind us.
            drop(ctl);
            gate.release_idle();
            gate.lock();
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

    // SIGTERM arrives on logout/shutdown (the session's graphical-session.target
    // stops us). Handle it so we tear capture down cleanly instead of being killed
    // mid-stream — an abruptly-abandoned mutter ScreenCast session can stall GNOME
    // session teardown (a ~minute-long "stop job" hang on shutdown).
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;

    // Reader loop: broker control -> capture-control thread / atomics.
    loop {
        tokio::select! {
            _ = sigterm.recv() => {
                tracing::info!("agent: SIGTERM; stopping capture and exiting");
                break;
            }
            msg = rmd_ipc::read_msg::<_, BrokerMsg>(&mut rd) => {
                match msg {
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
        }
    }
    // Clean teardown: stop capturing, then close the control channel and join the
    // capture thread so the CaptureController is dropped (mutter Session.Stop runs)
    // BEFORE the process exits — no dangling ScreenCast session for GNOME to wait on.
    let _ = ctrl_tx.send(CaptureCmd::SetCapturing(false));
    drop(ctrl_tx);
    let _ = capture_thread.join();
    writer.abort();
    tracing::info!("agent: exited cleanly");
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
