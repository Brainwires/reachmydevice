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
use std::sync::Arc;
use std::sync::Once;
use std::sync::atomic::{AtomicBool, Ordering};
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
            // SAFETY (edition 2024): env mutation is only unsound with concurrent
            // readers; this is single-threaded X-session probing at capture init.
            unsafe {
                std::env::set_var("DISPLAY", d);
                std::env::set_var("XAUTHORITY", c);
            }
            if x11rb::connect(None).is_ok() {
                tracing::info!(display = %d, xauthority = %c.display(),
                    "auto-discovered X session for capture (set DISPLAY/XAUTHORITY yourself to override)");
                return;
            }
        }
    }

    // Nothing authenticated — restore the caller's DISPLAY so the eventual error
    // message is about their setup, not our probing.
    // SAFETY (edition 2024): single-threaded capture-init probe (see above).
    match display_set {
        Some(d) => unsafe { std::env::set_var("DISPLAY", d) },
        None => unsafe { std::env::remove_var("DISPLAY") },
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
            WaylandEnable=false\n     \
            then `sudo reboot`.\n\n  \
         Notes: this X11/XGetImage path needs an Xorg session (hence \
         WaylandEnable=false above). On a normal Wayland session you don't need it — \
         `rmdd` captures the full desktop through the PipeWire/xdg-desktop-portal \
         backend automatically. Started over SSH? `rmdd` auto-detects \
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

/// Warn when the X11 backend is used on a Wayland session. This only happens with
/// `RMD_FORCE_X11=1`, since the default routes Wayland to the PipeWire/portal
/// backend ([`crate::wayland`]) which captures the full desktop. XWayland-based
/// X11 capture misses native-Wayland surfaces, so point the user back to it.
fn warn_if_wayland() {
    if std::env::var_os("WAYLAND_DISPLAY").is_some() {
        tracing::warn!(
            "WAYLAND_DISPLAY is set but the X11 (XWayland) capture backend is in use \
             (RMD_FORCE_X11); native-Wayland surfaces won't be captured. Unset \
             RMD_FORCE_X11 to use the PipeWire/xdg-desktop-portal backend, which \
             captures the full Wayland desktop."
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

/// The root window's *current* width/height via `GetGeometry`, or `None` if the
/// query fails. Unlike `conn.setup().roots[..].width_in_pixels` (a snapshot taken
/// when the client connected), this reflects live resizes — essential under
/// XWayland, where mutter resizes the root after connect and on every RandR change.
fn current_root_size<C: Connection>(conn: &C, root: x11rb::protocol::xproto::Window) -> Option<(u16, u16)> {
    let geom = conn.get_geometry(root).ok()?.reply().ok()?;
    Some((geom.width, geom.height))
}

/// Target size that fits `src` inside the `cap` box, preserving aspect ratio and
/// never upscaling. A zero cap dimension (or zero source) means "no cap" — returns
/// the source size unchanged.
fn fit_within(src_w: u16, src_h: u16, cap_w: u32, cap_h: u32) -> (u16, u16) {
    if cap_w == 0 || cap_h == 0 || src_w == 0 || src_h == 0 {
        return (src_w, src_h);
    }
    let factor = (cap_w as f64 / src_w as f64)
        .min(cap_h as f64 / src_h as f64)
        .min(1.0);
    let w = ((src_w as f64 * factor).round() as u16).max(1);
    let h = ((src_h as f64 * factor).round() as u16).max(1);
    (w, h)
}

/// Area-average downscale of a BGRA image (`src_stride` bytes per row, which may
/// exceed `src_w*4` due to scanline padding) to a tightly-packed `dst_w`x`dst_h`
/// BGRA buffer. `dst` must be `<=` `src` in both dimensions. Averaging (not
/// nearest-neighbour) keeps downscaled text legible. O(src_pixels).
fn downscale_bgra(
    src: &[u8],
    src_w: usize,
    src_h: usize,
    src_stride: usize,
    dst_w: usize,
    dst_h: usize,
) -> Vec<u8> {
    let mut acc = vec![0u32; dst_w * dst_h * 4];
    let mut cnt = vec![0u32; dst_w * dst_h];
    for sy in 0..src_h {
        let dy = sy * dst_h / src_h;
        let row = &src[sy * src_stride..sy * src_stride + src_w * 4];
        for sx in 0..src_w {
            let dx = sx * dst_w / src_w;
            let di = dy * dst_w + dx;
            let s = &row[sx * 4..sx * 4 + 4];
            let a = di * 4;
            acc[a] += s[0] as u32;
            acc[a + 1] += s[1] as u32;
            acc[a + 2] += s[2] as u32;
            acc[a + 3] += s[3] as u32;
            cnt[di] += 1;
        }
    }
    let mut out = vec![0u8; dst_w * dst_h * 4];
    for i in 0..dst_w * dst_h {
        let c = cnt[i].max(1);
        let a = i * 4;
        out[a] = (acc[a] / c) as u8;
        out[a + 1] = (acc[a + 1] / c) as u8;
        out[a + 2] = (acc[a + 2] / c) as u8;
        out[a + 3] = (acc[a + 3] / c) as u8;
    }
    out
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
    // Encode-size cap (A1): honor the configured width/height by area-downscaling
    // captured frames to fit, matching the macOS and Wayland backends (where the
    // configured size already takes effect). A zero or >= native cap means "send
    // native" — we never upscale.
    let cap_w = config.width;
    let cap_h = config.height;

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
            let frame_interval = Duration::from_micros(1_000_000 / fps as u64);

            // The connection-setup dimensions (`screen.width_in_pixels`) are a
            // snapshot from connect time. Under XWayland/mutter the root window is
            // resized *after* the client connects (and any RandR change resizes it
            // mid-session), so a GetImage rectangle sized from the setup can exceed
            // the live root and fail `BadMatch` on every frame. Query the current
            // root geometry instead, falling back to the setup dims if that fails.
            let (mut width, mut height) = current_root_size(&conn, root)
                .unwrap_or((screen.width_in_pixels, screen.height_in_pixels));

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
                        // A `BadMatch` here almost always means the root was resized
                        // out from under us (common right after connect on XWayland,
                        // or on any live resolution/output change). Re-query the
                        // geometry so capture self-heals instead of dropping every
                        // subsequent frame with a stale size.
                        if let Some((w, h)) = current_root_size(&conn, root) {
                            if (w, h) != (width, height) {
                                tracing::info!(
                                    old_width = width, old_height = height,
                                    new_width = w, new_height = h,
                                    "root geometry changed; updating capture size"
                                );
                                width = w;
                                height = h;
                            }
                        }
                        tracing::warn!(error = %e, width, height,
                            "XGetImage reply failed; dropping frame");
                        std::thread::sleep(frame_interval);
                        continue;
                    }
                };

                // Robust stride: rows are padded to the scanline unit by the server.
                let h = height as usize;
                let bytes_per_row = if h > 0 { reply.data.len() / h } else { 0 };

                // A1: honor the configured encode size by area-downscaling to fit
                // (aspect-preserving, never upscaling), so `width`/`height` take
                // effect on X11 like they do on macOS/Wayland. A no-op when the cap
                // is 0 or >= the captured size.
                let (dw, dh) = fit_within(width, height, cap_w, cap_h);
                let frame = if (dw, dh) != (width, height)
                    && bytes_per_row >= width as usize * 4
                    && reply.data.len() >= bytes_per_row * h
                {
                    let scaled = downscale_bgra(
                        &reply.data,
                        width as usize,
                        height as usize,
                        bytes_per_row,
                        dw as usize,
                        dh as usize,
                    );
                    Frame {
                        width: dw as u32,
                        height: dh as u32,
                        bytes_per_row: dw as u32 * 4,
                        format: PixelFormat::Bgra,
                        data: Bytes::from(scaled),
                        capture_ts_micros: monotonic_micros(),
                    }
                } else {
                    Frame {
                        width: width as u32,
                        height: height as u32,
                        bytes_per_row: bytes_per_row as u32,
                        format: PixelFormat::Bgra,
                        data: Bytes::from(reply.data),
                        capture_ts_micros: monotonic_micros(),
                    }
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
