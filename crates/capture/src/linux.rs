//! Linux X11 screen capture backend.
//!
//! Uses `XGetImage` (via `x11rb`) to grab the root window each frame. This is the
//! simple, universally-available path; `XShm` (MIT-SHM shared memory) is the
//! future optimization to avoid the per-frame copy over the X socket.
//!
//! Capture is at the display's native resolution (the encoder takes its
//! dimensions from the frame, so `config.width/height` are advisory on X11). The
//! server delivers 32-bpp ZPixmap data as **BGRX** on little-endian TrueColor
//! visuals — byte-compatible with our BGRA `Frame` (the codec ignores the 4th
//! byte). Wayland is a separate backend (PipeWire portal) — not this file.

use crate::{
    CaptureConfig, CaptureError, CaptureSession, DisplayInfo, Frame, FrameSink, PixelFormat,
};
use bytes::Bytes;
use rmd_protocol::monotonic_micros;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::Once;
use std::time::{Duration, Instant};
use x11rb::connection::Connection;
use x11rb::protocol::xproto::{ConnectionExt, ImageFormat};

/// Resolve `DISPLAY`/`XAUTHORITY` so `rmdd` can capture the local desktop even
/// when started over SSH (which inherits neither). Idempotent (runs once).
///
/// If the current environment already connects, it's left untouched (respects a
/// user-set `DISPLAY`/`XAUTHORITY`). Otherwise it tries `:0`/`:1` and searches the
/// usual Xauthority cookie locations, using the first (display, cookie) pair that
/// actually authenticates against the running X server.
fn ensure_x_env() {
    static INIT: Once = Once::new();
    INIT.call_once(discover_x_env);
}

fn discover_x_env() {
    // Fast path: the current env already reaches a server.
    if x11rb::connect(None).is_ok() {
        return;
    }

    let display_set = std::env::var("DISPLAY").ok().filter(|s| !s.is_empty());
    let displays: Vec<String> = match &display_set {
        Some(d) => vec![d.clone()],
        None => vec![":0".to_string(), ":1".to_string()],
    };

    // Candidate cookie files, most-specific first.
    let mut cookies: Vec<PathBuf> = Vec::new();
    if let Some(x) = std::env::var_os("XAUTHORITY") {
        cookies.push(x.into());
    }
    if let Some(home) = std::env::var_os("HOME") {
        cookies.push(Path::new(&home).join(".Xauthority"));
    }
    if let Ok(uid) = self_uid() {
        let run = PathBuf::from(format!("/run/user/{uid}"));
        collect_auth_files(&run, &mut cookies); // .mutter-Xwaylandauth.*, xauth_*
        collect_auth_files(&run.join("gdm"), &mut cookies);
    }
    for p in [
        "/var/run/lightdm/root/:0",
        "/var/lib/lightdm/.Xauthority",
        "/var/run/sddm/xauth",
    ] {
        cookies.push(PathBuf::from(p));
    }

    for d in &displays {
        for c in &cookies {
            if !c.exists() {
                continue;
            }
            std::env::set_var("DISPLAY", d);
            std::env::set_var("XAUTHORITY", c);
            if x11rb::connect(None).is_ok() {
                tracing::info!(display = %d, xauthority = %c.display(),
                    "auto-discovered X session for capture (set DISPLAY/XAUTHORITY yourself to override)");
                return;
            }
        }
    }

    // Nothing authenticated — restore the caller's DISPLAY so the eventual error
    // message is about their setup, not our probing.
    match display_set {
        Some(d) => std::env::set_var("DISPLAY", d),
        None => std::env::remove_var("DISPLAY"),
    }
}

/// Turn a raw X-connection failure into an actionable error that names the usual
/// cause (no desktop session logged in) and both fixes (auto-login or log in).
fn x_help_error(underlying: &str) -> CaptureError {
    let user = std::env::var("USER").unwrap_or_else(|_| "<user>".to_string());
    CaptureError::Backend(format!(
        "X11 screen capture couldn't reach a desktop session ({underlying}).\n\n\
         This almost always means no graphical session is logged in (the machine may be \
         sitting at the login screen), so there's nothing to capture and its X cookie \
         isn't yours. Fix it one of two ways:\n  \
         1. Log in to the desktop as {user} (on the monitor, or via VNC), OR\n  \
         2. Enable auto-login so a session starts at boot — for GDM, in \
            /etc/gdm3/custom.conf set:\n       \
            [daemon]\n       AutomaticLoginEnable=true\n       AutomaticLogin={user}\n       \
            WaylandEnable=false      # X11 session; required for capture\n     \
            then `sudo reboot`.\n\n  \
         Notes: capture needs an Xorg (X11) session — a Wayland desktop is only \
         partially visible (XWayland apps). Started over SSH? `rmdd` auto-detects \
         DISPLAY/XAUTHORITY once a session exists; otherwise set them, or run \
         `xhost +SI:localuser:{user}` in a desktop terminal."
    ))
}

/// This process's real uid, for `/run/user/<uid>` — via `/proc/self` (no libc).
fn self_uid() -> std::io::Result<u32> {
    use std::os::unix::fs::MetadataExt;
    Ok(std::fs::metadata("/proc/self")?.uid())
}

/// Add any Xauthority-like files in `dir` (e.g. `.mutter-Xwaylandauth.*`, `xauth_*`).
fn collect_auth_files(dir: &Path, out: &mut Vec<PathBuf>) {
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let n = e.file_name();
            let n = n.to_string_lossy();
            if n.contains("auth") || n.contains("Xauth") {
                out.push(e.path());
            }
        }
    }
}

/// Warn honestly when running under Wayland: X11 capture works via XWayland but
/// may miss native-Wayland windows/overlays; full Wayland needs the PipeWire
/// portal backend (roadmap). Silent partial capture would be worse than a note.
fn warn_if_wayland() {
    if std::env::var_os("WAYLAND_DISPLAY").is_some() {
        tracing::warn!(
            "WAYLAND_DISPLAY is set: capturing via XWayland (X11). Native-Wayland \
             surfaces may not be captured; a PipeWire/xdg-desktop-portal backend is \
             the roadmap for full Wayland support."
        );
    }
}

/// Enumerate X screens as displays.
pub fn list_displays() -> anyhow::Result<Vec<DisplayInfo>> {
    warn_if_wayland();
    ensure_x_env();
    let (conn, _) = x11rb::connect(None).map_err(|e| x_help_error(&e.to_string()))?;
    Ok(conn
        .setup()
        .roots
        .iter()
        .enumerate()
        .map(|(index, screen)| DisplayInfo {
            index,
            width: screen.width_in_pixels as u32,
            height: screen.height_in_pixels as u32,
        })
        .collect())
}

/// Running capture; dropping / [`stop`](CaptureSession::stop) ends the thread.
pub struct LinuxCaptureSession {
    stop: Arc<AtomicBool>,
}

impl CaptureSession for LinuxCaptureSession {
    fn stop(self: Box<Self>) {
        // Dropping signals the capture thread to exit (see `Drop`).
    }
}

impl Drop for LinuxCaptureSession {
    fn drop(&mut self) {
        // Tell the capture thread to stop, so dropping the session actually ends
        // the X11 grab (not just an explicit `stop()` call).
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// Start capturing screen `display_index` at `config.fps`.
pub fn start_capture(
    config: CaptureConfig,
    display_index: usize,
    sink: FrameSink,
) -> anyhow::Result<Box<dyn CaptureSession>> {
    ensure_x_env();
    // Validate the screen exists up front (surfaces errors to the caller).
    {
        let (conn, _) = x11rb::connect(None).map_err(|e| x_help_error(&e.to_string()))?;
        if display_index >= conn.setup().roots.len() {
            return Err(CaptureError::NoSuchDisplay(display_index).into());
        }
    }

    let stop = Arc::new(AtomicBool::new(false));
    let stop_thread = stop.clone();
    let fps = config.fps.max(1);

    std::thread::Builder::new()
        .name("rmd-x11-capture".into())
        .spawn(move || {
            // Own the connection on the capture thread.
            let (conn, _default_screen) = match x11rb::connect(None) {
                Ok(c) => c,
                Err(e) => {
                    tracing::error!("{}", x_help_error(&e.to_string()));
                    return;
                }
            };
            let screen = &conn.setup().roots[display_index];
            let root = screen.root;
            let width = screen.width_in_pixels;
            let height = screen.height_in_pixels;
            let frame_interval = Duration::from_micros(1_000_000 / fps as u64);

            tracing::info!(display_index, width, height, fps, "X11 capture started");

            while !stop_thread.load(Ordering::Relaxed) {
                let t0 = Instant::now();

                // get_image (ConnectionError) and reply (ReplyError) have distinct
                // error types, so handle them in two steps.
                let cookie =
                    match conn.get_image(ImageFormat::Z_PIXMAP, root, 0, 0, width, height, !0) {
                        Ok(c) => c,
                        Err(e) => {
                            tracing::warn!(error = %e, "XGetImage request failed; dropping frame");
                            std::thread::sleep(frame_interval);
                            continue;
                        }
                    };
                let reply = match cookie.reply() {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::warn!(error = %e, "XGetImage reply failed; dropping frame");
                        std::thread::sleep(frame_interval);
                        continue;
                    }
                };

                // Robust stride: rows are padded to the scanline unit by the server.
                let h = height as usize;
                let bytes_per_row = if h > 0 { reply.data.len() / h } else { 0 };

                let frame = Frame {
                    width: width as u32,
                    height: height as u32,
                    bytes_per_row: bytes_per_row as u32,
                    format: PixelFormat::Bgra,
                    data: Bytes::from(reply.data),
                    capture_ts_micros: monotonic_micros(),
                };
                if sink.send(frame).is_err() {
                    tracing::debug!("frame sink closed; stopping capture");
                    break;
                }

                // Pace to the target fps.
                if let Some(rem) = frame_interval.checked_sub(t0.elapsed()) {
                    std::thread::sleep(rem);
                }
            }
            tracing::info!("X11 capture stopped");
        })?;

    Ok(Box::new(LinuxCaptureSession { stop }))
}
