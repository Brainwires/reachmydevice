//! OpenReach screen capture.
//!
//! Platform-neutral [`Frame`] producer. A [`CaptureSession`] delivers BGRA
//! frames to a [`FrameSink`] (an mpsc channel) on an internal thread; the codec
//! crate consumes them. Handing frames across the crate boundary as plain bytes
//! (rather than a platform image handle) keeps capture and codec decoupled and
//! makes the Linux/Windows backends (Phase 3) drop-in.
//!
//! macOS backend: ScreenCaptureKit (see [`mac`]). Other platforms return
//! [`CaptureError::Unsupported`] until Phase 3.

use bytes::Bytes;
use std::sync::mpsc::Sender;

#[cfg(target_os = "macos")]
pub mod mac;

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

/// How to capture. Width/height are the encoded output size (the backend scales
/// the display to fit); `fps` caps the delivered frame rate.
#[derive(Clone, Debug)]
pub struct CaptureConfig {
    pub width: u32,
    pub height: u32,
    pub fps: u32,
    pub show_cursor: bool,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            width: 1920,
            height: 1080,
            fps: 30,
            show_cursor: true,
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
    /// Host-process monotonic capture time; see [`openreach_protocol::monotonic_micros`].
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

/// A running capture. Dropping it (or calling [`CaptureSession::stop`]) ends capture.
///
/// Not required to be `Send`: platform stream objects may be thread-affine, so
/// the owner keeps the handle on the thread that created it. Frames still flow
/// across threads via the [`FrameSink`] channel, which is `Send`.
pub trait CaptureSession {
    /// Stop capture and release the stream.
    fn stop(self: Box<Self>);
}

/// Errors from capture setup.
#[derive(Debug, thiserror::Error)]
pub enum CaptureError {
    #[error("screen capture is not yet supported on this platform (Phase 3)")]
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
    #[cfg(not(target_os = "macos"))]
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
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (config, display_index, sink);
        Err(CaptureError::Unsupported.into())
    }
}
