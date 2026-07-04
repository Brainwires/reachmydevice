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
use openreach_protocol::monotonic_micros;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use x11rb::connection::Connection;
use x11rb::protocol::xproto::{ConnectionExt, ImageFormat};

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
    let (conn, _) = x11rb::connect(None).map_err(|e| {
        CaptureError::Backend(format!(
            "{e} (no reachable X server; under Wayland ensure XWayland is running)"
        ))
    })?;
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
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// Start capturing screen `display_index` at `config.fps`.
pub fn start_capture(
    config: CaptureConfig,
    display_index: usize,
    sink: FrameSink,
) -> anyhow::Result<Box<dyn CaptureSession>> {
    // Validate the screen exists up front (surfaces errors to the caller).
    {
        let (conn, _) = x11rb::connect(None).map_err(|e| CaptureError::Backend(format!("{e}")))?;
        if display_index >= conn.setup().roots.len() {
            return Err(CaptureError::NoSuchDisplay(display_index).into());
        }
    }

    let stop = Arc::new(AtomicBool::new(false));
    let stop_thread = stop.clone();
    let fps = config.fps.max(1);

    std::thread::Builder::new()
        .name("openreach-x11-capture".into())
        .spawn(move || {
            // Own the connection on the capture thread.
            let (conn, _default_screen) = match x11rb::connect(None) {
                Ok(c) => c,
                Err(e) => {
                    tracing::error!(error = %e, "X11 connect failed");
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
