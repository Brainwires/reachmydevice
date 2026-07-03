//! macOS screen capture backend (ScreenCaptureKit).
//!
//! Built directly on the pure-Rust `objc2` framework bindings (ADR-0005) rather
//! than the `screencapturekit` convenience crate, whose mandatory `apple-metal`
//! dependency runs a Swift bridge build that is broken against the current SDK.
//!
//! The flow mirrors the ScreenCaptureKit Objective-C API:
//! [`SCShareableContent`] enumerates displays (via an async completion handler we
//! bridge to a channel), an [`SCContentFilter`] + [`SCStreamConfiguration`] drive
//! an [`SCStream`], and a custom [`StreamOutput`] class (defined with
//! [`define_class!`]) receives sample buffers on a `dispatch2` serial queue. Each
//! sample's locked BGRA bytes are copied into a [`Frame`] and pushed to the sink.
//!
//! Requires the **Screen Recording** TCC permission (see
//! `docs/macos-permissions.md`); the first `start_capture` triggers the prompt.

use crate::{
    CaptureConfig, CaptureError, CaptureSession, DisplayInfo, Frame, FrameSink, PixelFormat,
};
use bytes::Bytes;
use openreach_protocol::monotonic_micros;
use std::sync::mpsc;
use std::time::Duration;

use block2::RcBlock;
use dispatch2::{DispatchQueue, DispatchQueueAttr, DispatchRetained};
use objc2::rc::Retained;
use objc2::runtime::{NSObject, NSObjectProtocol, ProtocolObject};
use objc2::{define_class, msg_send, AnyThread, DefinedClass};
use objc2_core_media::{CMSampleBuffer, CMTime};
use objc2_core_video::{
    kCVPixelFormatType_32BGRA, CVPixelBufferGetBaseAddress, CVPixelBufferGetBytesPerRow,
    CVPixelBufferGetHeight, CVPixelBufferGetWidth, CVPixelBufferLockBaseAddress,
    CVPixelBufferLockFlags, CVPixelBufferUnlockBaseAddress,
};
use objc2_foundation::{NSArray, NSError};
use objc2_screen_capture_kit::{
    SCContentFilter, SCDisplay, SCShareableContent, SCStream, SCStreamConfiguration,
    SCStreamDelegate, SCStreamOutput, SCStreamOutputType, SCWindow,
};

/// How long to wait for ScreenCaptureKit's async `SCShareableContent` fetch.
const SHAREABLE_CONTENT_TIMEOUT: Duration = Duration::from_secs(5);

/// Frames kept in the capture queue. Small enough to bound latency; large enough
/// to absorb jitter between the capture queue and the encoder.
const QUEUE_DEPTH: isize = 6;

// ---------------------------------------------------------------------------
// Custom SCStreamOutput / SCStreamDelegate class
// ---------------------------------------------------------------------------

define_class!(
    // SAFETY:
    // - The superclass `NSObject` has no subclassing requirements.
    // - `StreamOutput` does not implement `Drop` (its only ivar, a `FrameSink`,
    //   is dropped automatically by the generated `dealloc`).
    #[unsafe(super(NSObject))]
    #[name = "OpenReachStreamOutput"]
    #[ivars = FrameSink]
    struct StreamOutput;

    /// Required by both ScreenCaptureKit protocols below.
    unsafe impl NSObjectProtocol for StreamOutput {}

    /// `SCStreamOutput`: receives captured sample buffers on the sample handler
    /// queue we register in [`start_capture`].
    unsafe impl SCStreamOutput for StreamOutput {
        #[unsafe(method(stream:didOutputSampleBuffer:ofType:))]
        fn stream_did_output_sample_buffer(
            &self,
            _stream: &SCStream,
            sample_buffer: &CMSampleBuffer,
            output_type: SCStreamOutputType,
        ) {
            self.handle_sample_buffer(sample_buffer, output_type);
        }
    }

    /// `SCStreamDelegate`: all methods are optional. We conform so the same
    /// object can serve as the stream's delegate; we only handle stop (logged).
    unsafe impl SCStreamDelegate for StreamOutput {
        #[unsafe(method(stream:didStopWithError:))]
        fn stream_did_stop_with_error(&self, _stream: &SCStream, error: &NSError) {
            tracing::warn!(
                "SCStream stopped with error: {}",
                error.localizedDescription()
            );
        }
    }
);

impl StreamOutput {
    /// Create an output/delegate object owning `sink`.
    fn new(sink: FrameSink) -> Retained<Self> {
        let this = Self::alloc().set_ivars(sink);
        // SAFETY: `NSObject`'s designated initializer; no extra invariants.
        unsafe { msg_send![super(this), init] }
    }

    /// Copy the sample's locked BGRA bytes into a [`Frame`] and forward it.
    ///
    /// Runs on the capture (dispatch) queue. Must never panic or block: on any
    /// error we drop the frame and return.
    fn handle_sample_buffer(
        &self,
        sample_buffer: &CMSampleBuffer,
        output_type: SCStreamOutputType,
    ) {
        // We only registered the screen output; ignore audio/microphone samples.
        if output_type != SCStreamOutputType::Screen {
            return;
        }

        // A sample without an image buffer is a status-only frame (idle/blank).
        // SAFETY: FFI call; returns `None` when there is no backing image buffer.
        let Some(image_buffer) = (unsafe { sample_buffer.image_buffer() }) else {
            return;
        };
        // `CVImageBuffer` is a type alias for `CVPixelBuffer`; use it directly.
        let pixel_buffer = &*image_buffer;

        // SAFETY: FFI. Lock read-only so ScreenCaptureKit can keep sharing the
        // IOSurface; we must pair this with an unlock below.
        let lock_status =
            unsafe { CVPixelBufferLockBaseAddress(pixel_buffer, CVPixelBufferLockFlags::ReadOnly) };
        if lock_status != 0 {
            tracing::warn!("CVPixelBufferLockBaseAddress failed ({lock_status}); dropping frame");
            return;
        }

        // These accessors are safe wrappers in objc2-core-video; the returned
        // geometry/pointer is meaningful only while the base address is locked.
        let width = CVPixelBufferGetWidth(pixel_buffer);
        let height = CVPixelBufferGetHeight(pixel_buffer);
        let bytes_per_row = CVPixelBufferGetBytesPerRow(pixel_buffer);
        let base = CVPixelBufferGetBaseAddress(pixel_buffer);

        let frame = if base.is_null() || width == 0 || height == 0 {
            None
        } else {
            let len = bytes_per_row * height;
            // SAFETY: `base` points to `bytes_per_row * height` bytes of locked,
            // contiguous pixel data (single-plane BGRA); it stays valid until we
            // unlock. We copy out immediately so the slice never outlives the lock.
            let data = Bytes::copy_from_slice(unsafe {
                std::slice::from_raw_parts(base.cast::<u8>(), len)
            });
            Some(Frame {
                width: width as u32,
                height: height as u32,
                bytes_per_row: bytes_per_row as u32,
                format: PixelFormat::Bgra,
                data,
                capture_ts_micros: monotonic_micros(),
            })
        };

        // SAFETY: matches the lock above with the same flags.
        unsafe { CVPixelBufferUnlockBaseAddress(pixel_buffer, CVPixelBufferLockFlags::ReadOnly) };

        if let Some(frame) = frame {
            // Non-blocking: if the encoder is gone or lagging we drop the frame
            // rather than stall the capture queue.
            if self.ivars().send(frame).is_err() {
                tracing::debug!("frame sink closed; frame dropped");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Session handle
// ---------------------------------------------------------------------------

/// Live ScreenCaptureKit session. Dropping (or [`stop`](CaptureSession::stop))
/// ends capture.
///
/// Holds the stream plus the output/delegate object and the dispatch queue so
/// they outlive capture. Not `Send` — these ObjC objects stay on the creating
/// thread; frames still cross threads via the `Send` [`FrameSink`].
pub struct MacCaptureSession {
    stream: Retained<SCStream>,
    // Kept alive for the duration of capture even though not read directly.
    _output: Retained<StreamOutput>,
    _queue: DispatchRetained<DispatchQueue>,
}

impl CaptureSession for MacCaptureSession {
    fn stop(self: Box<Self>) {
        // Fire-and-forget stop; the completion handler carries any error, which
        // is non-fatal at teardown.
        // SAFETY: FFI; `None` handler is permitted.
        unsafe { self.stream.stopCaptureWithCompletionHandler(None) };
    }
}

// ---------------------------------------------------------------------------
// Shareable-content fetch (async completion handler -> channel)
// ---------------------------------------------------------------------------

/// Moves a `Retained<SCShareableContent>` from the completion-handler thread to
/// the caller.
///
/// SAFETY: `SCShareableContent` is an immutable snapshot; ScreenCaptureKit
/// permits reading its `displays`/`windows` from any thread, so transferring
/// ownership across the channel is sound.
struct SendContent(Retained<SCShareableContent>);
unsafe impl Send for SendContent {}

/// Fetch the shareable content, blocking on the async completion handler.
fn fetch_shareable_content() -> anyhow::Result<Retained<SCShareableContent>> {
    let (tx, rx) = mpsc::channel::<Result<SendContent, String>>();

    let handler = RcBlock::new(
        move |content: *mut SCShareableContent, error: *mut NSError| {
            // SAFETY: ScreenCaptureKit passes either a valid content pointer or a
            // valid error pointer (never both null in practice).
            let result = if let Some(content) = unsafe { Retained::retain(content) } {
                Ok(SendContent(content))
            } else {
                let msg = unsafe { error.as_ref() }
                    .map(|e| e.localizedDescription().to_string())
                    .unwrap_or_else(|| "unknown SCShareableContent error".to_owned());
                Err(msg)
            };
            // Receiver may have timed out and gone away; ignore send errors.
            let _ = tx.send(result);
        },
    );

    // SAFETY: FFI; the handler is retained by ScreenCaptureKit for the call.
    unsafe { SCShareableContent::getShareableContentWithCompletionHandler(&handler) };

    match rx.recv_timeout(SHAREABLE_CONTENT_TIMEOUT) {
        Ok(Ok(content)) => Ok(content.0),
        Ok(Err(msg)) => Err(CaptureError::Backend(msg).into()),
        Err(_) => Err(CaptureError::Backend(
            "timed out waiting for SCShareableContent (Screen Recording permission?)".to_owned(),
        )
        .into()),
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Enumerate displays via `SCShareableContent`.
pub fn list_displays() -> anyhow::Result<Vec<DisplayInfo>> {
    let content = fetch_shareable_content()?;
    // SAFETY: FFI accessor returning a retained array of displays.
    let displays = unsafe { content.displays() };
    Ok(displays
        .to_vec()
        .into_iter()
        .enumerate()
        .map(|(index, display)| DisplayInfo {
            index,
            // SAFETY: FFI accessors; width/height are in points.
            width: unsafe { display.width() } as u32,
            height: unsafe { display.height() } as u32,
        })
        .collect())
}

/// Start capturing the display at `display_index`.
pub fn start_capture(
    config: CaptureConfig,
    display_index: usize,
    sink: FrameSink,
) -> anyhow::Result<Box<dyn CaptureSession>> {
    let content = fetch_shareable_content()?;
    // SAFETY: FFI accessor returning a retained array of displays.
    let displays = unsafe { content.displays() };
    let display: Retained<SCDisplay> = displays
        .to_vec()
        .into_iter()
        .nth(display_index)
        .ok_or(CaptureError::NoSuchDisplay(display_index))?;

    // Content filter: the whole display, excluding no windows.
    let no_windows: Retained<NSArray<SCWindow>> = NSArray::new();
    // SAFETY: FFI init; `display` and `no_windows` are valid for the call.
    let filter = unsafe {
        SCContentFilter::initWithDisplay_excludingWindows(
            SCContentFilter::alloc(),
            &display,
            &no_windows,
        )
    };

    // Stream configuration.
    // SAFETY: FFI init + property setters on a freshly allocated config.
    let stream_config = unsafe {
        let cfg = SCStreamConfiguration::init(SCStreamConfiguration::alloc());
        cfg.setWidth(config.width as usize);
        cfg.setHeight(config.height as usize);
        // minimumFrameInterval = 1/fps seconds caps the delivered frame rate.
        let fps = config.fps.max(1) as i32;
        cfg.setMinimumFrameInterval(CMTime::new(1, fps));
        cfg.setPixelFormat(kCVPixelFormatType_32BGRA);
        cfg.setShowsCursor(config.show_cursor);
        cfg.setQueueDepth(QUEUE_DEPTH);
        cfg
    };

    // Output/delegate object owning the sink.
    let output = StreamOutput::new(sink);
    let delegate = ProtocolObject::from_ref(&*output);
    let stream_output: &ProtocolObject<dyn SCStreamOutput> = ProtocolObject::from_ref(&*output);

    // SAFETY: FFI init with a valid filter/config and our delegate object.
    let stream = unsafe {
        SCStream::initWithFilter_configuration_delegate(
            SCStream::alloc(),
            &filter,
            &stream_config,
            Some(delegate),
        )
    };

    // Serial queue for sample delivery — keeps frames ordered and off the main
    // thread.
    let queue = DispatchQueue::new("com.openreach.capture", DispatchQueueAttr::SERIAL);

    // SAFETY: FFI; registers our output for screen samples on `queue`.
    unsafe {
        stream
            .addStreamOutput_type_sampleHandlerQueue_error(
                stream_output,
                SCStreamOutputType::Screen,
                Some(&queue),
            )
            .map_err(|e| CaptureError::Backend(format!("addStreamOutput: {e:?}")))?;
    }

    // Start capture; log any async start error.
    let start_handler = RcBlock::new(move |error: *mut NSError| {
        if let Some(error) = unsafe { error.as_ref() } {
            tracing::warn!("SCStream start failed: {}", error.localizedDescription());
        }
    });
    // SAFETY: FFI; handler is retained for the call.
    unsafe { stream.startCaptureWithCompletionHandler(Some(&start_handler)) };

    tracing::info!(
        display_index,
        width = config.width,
        height = config.height,
        fps = config.fps,
        "ScreenCaptureKit capture started"
    );

    Ok(Box::new(MacCaptureSession {
        stream,
        _output: output,
        _queue: queue,
    }))
}
