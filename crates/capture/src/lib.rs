//! ReachMyDevice screen capture.
//!
//! Platform-neutral [`Frame`] producer. A [`CaptureSession`] delivers BGRA
//! frames to a [`FrameSink`] (an mpsc channel) on an internal thread; the codec
//! crate consumes them. Handing frames across the crate boundary as plain bytes
//! (rather than a platform image handle) keeps capture and codec decoupled and
//! makes each platform backend drop-in.
//!
//! Backends: macOS ScreenCaptureKit ([`mac`]); Linux X11/XGetImage ([`linux`])
//! and Wayland via PipeWire + xdg-desktop-portal ([`wayland`]), chosen at runtime
//! per `WAYLAND_DISPLAY`. Windows is not yet implemented and returns
//! [`CaptureError::Unsupported`].

use bytes::Bytes;
use std::sync::mpsc::Sender;

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod mac;
#[cfg(target_os = "linux")]
pub mod mutter;
#[cfg(target_os = "linux")]
pub mod wayland;

/// Which Linux capture backend fits this session.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum SessionKind {
    /// Xorg (or forced): X11 `XGetImage` ([`linux`]).
    X11,
    /// GNOME Wayland: mutter's direct ScreenCast API ([`mutter`]) — no consent
    /// prompt, clean teardown.
    GnomeWayland,
    /// Other Wayland (KDE, wlroots, …): xdg-desktop-portal ScreenCast ([`wayland`]).
    OtherWayland,
}

/// Choose the capture backend. `RMD_FORCE_X11=1` forces X11; `RMD_WAYLAND_BACKEND`
/// (`mutter`|`portal`) overrides the Wayland pick; otherwise GNOME (by
/// `XDG_CURRENT_DESKTOP`) uses the mutter-direct backend and everything else the
/// portal.
#[cfg(target_os = "linux")]
fn session_kind() -> SessionKind {
    if std::env::var_os("RMD_FORCE_X11").is_some_and(|v| v == "1") {
        return SessionKind::X11;
    }
    if std::env::var_os("WAYLAND_DISPLAY").is_none() {
        return SessionKind::X11;
    }
    match std::env::var("RMD_WAYLAND_BACKEND").ok().as_deref() {
        Some("portal") => return SessionKind::OtherWayland,
        Some("mutter") => return SessionKind::GnomeWayland,
        _ => {}
    }
    let is_gnome = std::env::var("XDG_CURRENT_DESKTOP")
        .unwrap_or_default()
        .split(':')
        .any(|d| d.eq_ignore_ascii_case("GNOME"));
    if is_gnome {
        SessionKind::GnomeWayland
    } else {
        SessionKind::OtherWayland
    }
}

/// Pixel layout of a [`Frame`]. Only BGRA (8:8:8:8) in v1; the codec expects it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PixelFormat {
    /// 32-bit BGRA, 8 bits per channel. macOS `kCVPixelFormatType_32BGRA`.
    Bgra,
}

/// A capturable display, as enumerated by [`list_displays`].
#[derive(Clone, Debug)]
pub struct DisplayInfo {
    /// 0-based enumeration order; pass to [`start_capture`] as `display_index`.
    pub index: usize,
    /// Pixel width of the display.
    pub width: u32,
    /// Pixel height of the display.
    pub height: u32,
}

/// The captured output's rectangle within the desktop bounding box (logical
/// pixels), for multi-monitor absolute-pointer mapping in the input crate.
///
/// An absolute pointer device is mapped by the compositor across the *whole*
/// desktop bounding box, so to land a click on the captured output the input
/// backend translates the viewer's normalized `[0,1]` coordinates (relative to
/// that one output) into a fraction of the full desktop using this rect.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct MonitorRect {
    /// Captured output origin X within the desktop bounding box.
    pub ox: f64,
    /// Captured output origin Y within the desktop bounding box.
    pub oy: f64,
    /// Captured output width.
    pub mw: f64,
    /// Captured output height.
    pub mh: f64,
    /// Full desktop bounding-box width.
    pub dw: f64,
    /// Full desktop bounding-box height.
    pub dh: f64,
}

/// The captured output's placement within the desktop bounding box, if it can be
/// determined. Currently only the GNOME/mutter backend reports geometry (via
/// `DisplayConfig.GetCurrentState`); other backends return `None`, which the
/// input crate treats as "single output spanning the whole desktop".
pub fn primary_monitor_rect() -> Option<MonitorRect> {
    #[cfg(target_os = "linux")]
    {
        if session_kind() == SessionKind::GnomeWayland {
            return mutter::primary_monitor_rect_blocking();
        }
        None
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// How to capture. Width/height are the encoded output size (the backend scales
/// the display to fit); `fps` caps the delivered frame rate.
/// Which Wayland desktop-portal source to capture. Ignored by the X11/macOS
/// backends (they always capture the real display).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum CaptureSource {
    /// Capture the real physical monitor — shown both locally and remotely
    /// (dual-use). Requires a display to be present; the session drops if the
    /// only monitor is physically unplugged.
    #[default]
    Monitor,
    /// Ask the compositor for a virtual monitor that exists with no physical
    /// display attached (headless). Survives an unplugged monitor, but is a
    /// separate output from any attached display.
    Virtual,
}

#[derive(Clone, Debug)]
pub struct CaptureConfig {
    pub width: u32,
    pub height: u32,
    pub fps: u32,
    pub show_cursor: bool,
    /// Wayland capture source (see [`CaptureSource`]); ignored elsewhere.
    pub capture_source: CaptureSource,
    /// Opaque portal restore token from a previous session (Wayland only). When
    /// present, the xdg-desktop-portal ScreenCast backend re-grants the same
    /// source without re-prompting the user; `None` prompts (first run). Ignored
    /// by the macOS/X11 backends.
    pub restore_token: Option<String>,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            width: 1920,
            height: 1080,
            fps: 30,
            show_cursor: true,
            capture_source: CaptureSource::Monitor,
            restore_token: None,
        }
    }
}

/// One captured frame: tightly-or-padded BGRA bytes plus geometry.
///
/// `data.len() == bytes_per_row * height`. `bytes_per_row` may exceed
/// `width * 4` when the backend pads rows for alignment — consumers must stride
/// by `bytes_per_row`, not `width * 4`.
pub struct Frame {
    pub width: u32,
    pub height: u32,
    pub bytes_per_row: u32,
    pub format: PixelFormat,
    pub data: Bytes,
    /// Host-process monotonic capture time; see [`rmd_protocol::monotonic_micros`].
    pub capture_ts_micros: u64,
}

impl std::fmt::Debug for Frame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Frame")
            .field("width", &self.width)
            .field("height", &self.height)
            .field("bytes_per_row", &self.bytes_per_row)
            .field("format", &self.format)
            .field("data_len", &self.data.len())
            .field("capture_ts_micros", &self.capture_ts_micros)
            .finish()
    }
}

/// Where captured frames are delivered. If the receiver is dropped or lagging,
/// backends drop frames rather than block the capture callback.
pub type FrameSink = Sender<Frame>;

/// Where captured **audio** is delivered: chunks of mono 48 kHz `i16` PCM
/// (desktop/system audio). Dropped/lagging receivers cause samples to be dropped.
pub type AudioSink = Sender<Vec<i16>>;

/// A running capture. Dropping it (or calling [`CaptureSession::stop`]) ends capture.
///
/// Not required to be `Send`: platform stream objects may be thread-affine, so
/// the owner keeps the handle on the thread that created it. Frames still flow
/// across threads via the [`FrameSink`] channel, which is `Send`.
pub trait CaptureSession {
    /// Stop capture and release the stream.
    fn stop(self: Box<Self>);

    /// The portal restore token issued for this session, if the backend obtained
    /// a (possibly refreshed) one worth persisting for next time. Only the Wayland
    /// backend returns a value; others use the default `None`.
    fn restore_token(&self) -> Option<String> {
        None
    }
}

/// Errors from capture setup.
#[derive(Debug, thiserror::Error)]
pub enum CaptureError {
    #[error("screen capture is not yet supported on this platform (Windows backend pending)")]
    Unsupported,
    #[error("no display at index {0}")]
    NoSuchDisplay(usize),
    #[error("capture backend error: {0}")]
    Backend(String),
}

/// Enumerate capturable displays.
pub fn list_displays() -> anyhow::Result<Vec<DisplayInfo>> {
    #[cfg(target_os = "macos")]
    {
        mac::list_displays()
    }
    #[cfg(target_os = "linux")]
    {
        match session_kind() {
            SessionKind::X11 => linux::list_displays(),
            SessionKind::GnomeWayland => mutter::list_displays(),
            SessionKind::OtherWayland => wayland::list_displays(),
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Err(CaptureError::Unsupported.into())
    }
}

/// Start capturing `display_index` per `config`, delivering frames to `sink`.
pub fn start_capture(
    config: CaptureConfig,
    display_index: usize,
    sink: FrameSink,
) -> anyhow::Result<Box<dyn CaptureSession>> {
    #[cfg(target_os = "macos")]
    {
        mac::start_capture(config, display_index, sink)
    }
    #[cfg(target_os = "linux")]
    {
        match session_kind() {
            SessionKind::X11 => linux::start_capture(config, display_index, sink),
            SessionKind::GnomeWayland => {
                // Prefer mutter-direct (no prompt, clean teardown), but fall back
                // to the portal if the private ScreenCast API isn't actually there
                // — e.g. a session mis-detected as GNOME (M5cap).
                if mutter::screencast_available() {
                    mutter::start_capture(config, display_index, sink)
                } else {
                    tracing::warn!(
                        "org.gnome.Mutter.ScreenCast unavailable; falling back to \
                         xdg-desktop-portal capture (a consent prompt may appear)"
                    );
                    wayland::start_capture(config, display_index, sink)
                }
            }
            SessionKind::OtherWayland => wayland::start_capture(config, display_index, sink),
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (config, display_index, sink);
        Err(CaptureError::Unsupported.into())
    }
}

/// Start capturing **desktop/system audio** (mono, 48 kHz `i16`) to `sink`.
///
/// macOS: ScreenCaptureKit system-audio (the real desktop mix). Other platforms
/// return [`CaptureError::Unsupported`] — callers fall back to a device source.
pub fn start_audio_capture(
    display_index: usize,
    sink: AudioSink,
) -> anyhow::Result<Box<dyn CaptureSession>> {
    #[cfg(target_os = "macos")]
    {
        mac::start_audio_capture(display_index, sink)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (display_index, sink);
        Err(CaptureError::Unsupported.into())
    }
}
