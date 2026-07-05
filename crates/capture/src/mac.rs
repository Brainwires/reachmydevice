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
    AudioSink, CaptureConfig, CaptureError, CaptureSession, DisplayInfo, Frame, FrameSink,
    PixelFormat,
};
use bytes::Bytes;
use rmd_protocol::monotonic_micros;
use std::sync::mpsc;
use std::time::Duration;

use block2::RcBlock;
use dispatch2::{DispatchQueue, DispatchQueueAttr, DispatchRetained};
use objc2::rc::Retained;
use objc2::runtime::{NSObject, NSObjectProtocol, ProtocolObject};
use objc2::{define_class, msg_send, AnyThread, DefinedClass};
use objc2_core_audio_types::AudioBufferList;
use objc2_core_media::{
    kCMSampleBufferFlag_AudioBufferList_Assure16ByteAlignment, CMBlockBuffer, CMSampleBuffer, CMTime,
};
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

/// Upper bound on a single captured frame's byte length (guards the OS-supplied
/// `bytes_per_row * height` against overflow/corruption before `from_raw_parts`).
/// 512 MiB comfortably covers an 8K BGRA frame (~256 MiB) with headroom.
const MAX_FRAME_BYTES: usize = 512 * 1024 * 1024;

/// Upper bound on a single audio buffer's byte length (same rationale).
const MAX_AUDIO_BYTES: usize = 8 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Custom SCStreamOutput / SCStreamDelegate class
// ---------------------------------------------------------------------------

define_class!(
    // SAFETY:
    // - The superclass `NSObject` has no subclassing requirements.
    // - `StreamOutput` does not implement `Drop` (its only ivar, a `FrameSink`,
    //   is dropped automatically by the generated `dealloc`).
    #[unsafe(super(NSObject))]
    #[name = "ReachMyDeviceStreamOutput"]
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

        // Guard the length arithmetic on OS-supplied geometry: reject null base,
        // zero/absurd dimensions, and any `bytes_per_row * height` that overflows
        // or exceeds a sane cap, so `from_raw_parts` can never be handed a bogus len.
        let len = bytes_per_row.checked_mul(height);
        let frame = match len {
            Some(len)
                if !base.is_null()
                    && width != 0
                    && height != 0
                    && len != 0
                    && len <= MAX_FRAME_BYTES =>
            {
                // SAFETY: `base` points to `len` (= bytes_per_row * height) bytes of
                // locked, contiguous single-plane BGRA data, valid until we unlock
                // below; we copy out immediately so the slice never outlives the lock.
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
            }
            _ => {
                tracing::debug!(width, height, bytes_per_row, "implausible frame geometry; dropped");
                None
            }
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
    let queue = DispatchQueue::new("com.rmd.capture", DispatchQueueAttr::SERIAL);

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

// ---------------------------------------------------------------------------
// Desktop audio (ScreenCaptureKit system audio) — isolated from video capture
// ---------------------------------------------------------------------------

/// Requested capture sample rate; SCK resamples the system mix to this.
const AUDIO_RATE: isize = 48_000;

define_class!(
    // SAFETY: superclass `NSObject` has no subclassing requirements; the only
    // ivar (an `AudioSink`) is dropped by the generated `dealloc`.
    #[unsafe(super(NSObject))]
    #[name = "ReachMyDeviceAudioOutput"]
    #[ivars = AudioSink]
    struct AudioStreamOutput;

    unsafe impl NSObjectProtocol for AudioStreamOutput {}

    unsafe impl SCStreamOutput for AudioStreamOutput {
        #[unsafe(method(stream:didOutputSampleBuffer:ofType:))]
        fn stream_did_output_sample_buffer(
            &self,
            _stream: &SCStream,
            sample_buffer: &CMSampleBuffer,
            output_type: SCStreamOutputType,
        ) {
            if output_type == SCStreamOutputType::Audio {
                self.handle_audio(sample_buffer);
            }
        }
    }

    unsafe impl SCStreamDelegate for AudioStreamOutput {
        #[unsafe(method(stream:didStopWithError:))]
        fn stream_did_stop_with_error(&self, _stream: &SCStream, error: &NSError) {
            tracing::warn!("audio SCStream stopped: {}", error.localizedDescription());
        }
    }
);

impl AudioStreamOutput {
    fn new(sink: AudioSink) -> Retained<Self> {
        let this = Self::alloc().set_ivars(sink);
        // SAFETY: NSObject designated initializer.
        unsafe { msg_send![super(this), init] }
    }

    /// Extract mono `i16` PCM from an audio CMSampleBuffer and forward it.
    ///
    /// Runs on the audio dispatch queue; never panics or blocks.
    fn handle_audio(&self, sample_buffer: &CMSampleBuffer) {
        let mut abl = AudioBufferList {
            mNumberBuffers: 1,
            mBuffers: [objc2_core_audio_types::AudioBuffer {
                mNumberChannels: 0,
                mDataByteSize: 0,
                mData: std::ptr::null_mut(),
            }],
        };
        let mut size_needed: usize = 0;
        let mut block_buffer: *mut CMBlockBuffer = std::ptr::null_mut();

        // SAFETY: FFI. Fills `abl` and hands us a retained CMBlockBuffer that owns
        // the sample memory `abl.mBuffers[0].mData` points into; we take ownership
        // below so it is released once we've copied the samples out.
        let status = unsafe {
            sample_buffer.audio_buffer_list_with_retained_block_buffer(
                &mut size_needed,
                &mut abl,
                std::mem::size_of::<AudioBufferList>(),
                None,
                None,
                kCMSampleBufferFlag_AudioBufferList_Assure16ByteAlignment,
                &mut block_buffer,
            )
        };
        if status != 0 || block_buffer.is_null() {
            return;
        }
        // Take ownership so the backing memory is released when this drops.
        // SAFETY: the call returned a +1-retained CMBlockBuffer.
        let _block = unsafe { Retained::from_raw(block_buffer) };

        let buffer = &abl.mBuffers[0];
        let byte_size = buffer.mDataByteSize as usize;
        // Reject a null pointer or an implausible byte size before deriving a
        // slice length from the OS-supplied value.
        if buffer.mData.is_null() || byte_size == 0 || byte_size > MAX_AUDIO_BYTES {
            return;
        }
        let channels = buffer.mNumberChannels.max(1) as usize;
        let n_f32 = byte_size / std::mem::size_of::<f32>();
        // SAFETY: `mData` points to `mDataByteSize` (`byte_size`) bytes of Float32
        // PCM, valid while `_block` is alive; `n_f32` floats fit within it. We copy
        // out immediately, so the slice never outlives `_block`.
        let samples = unsafe { std::slice::from_raw_parts(buffer.mData.cast::<f32>(), n_f32) };

        let to_i16 = |s: f32| (s.clamp(-1.0, 1.0) * 32767.0) as i16;
        let mono: Vec<i16> = if channels <= 1 {
            samples.iter().map(|&s| to_i16(s)).collect()
        } else {
            // Interleaved multi-channel → average to mono.
            samples
                .chunks(channels)
                .map(|f| to_i16(f.iter().copied().sum::<f32>() / channels as f32))
                .collect()
        };

        if !mono.is_empty() && self.ivars().send(mono).is_err() {
            tracing::debug!("audio sink closed; samples dropped");
        }
    }
}

/// Start ScreenCaptureKit **system-audio** capture on `display_index`.
///
/// A dedicated audio-only `SCStream` (no screen output registered) so it never
/// disturbs the video capture path. Delivers mono 48 kHz `i16` to `sink`.
pub fn start_audio_capture(
    display_index: usize,
    sink: AudioSink,
) -> anyhow::Result<Box<dyn CaptureSession>> {
    let content = fetch_shareable_content()?;
    // SAFETY: FFI accessor returning a retained array of displays.
    let displays = unsafe { content.displays() };
    let display: Retained<SCDisplay> = displays
        .to_vec()
        .into_iter()
        .nth(display_index)
        .ok_or(CaptureError::NoSuchDisplay(display_index))?;

    let no_windows: Retained<NSArray<SCWindow>> = NSArray::new();
    // SAFETY: FFI init; args valid for the call.
    let filter = unsafe {
        SCContentFilter::initWithDisplay_excludingWindows(
            SCContentFilter::alloc(),
            &display,
            &no_windows,
        )
    };

    // SAFETY: FFI init + setters. capturesAudio drives the system-audio path;
    // we keep video minimal (1×1) since no screen output is registered.
    let stream_config = unsafe {
        let cfg = SCStreamConfiguration::init(SCStreamConfiguration::alloc());
        cfg.setCapturesAudio(true);
        cfg.setSampleRate(AUDIO_RATE);
        cfg.setChannelCount(1);
        cfg.setExcludesCurrentProcessAudio(true);
        cfg.setWidth(2);
        cfg.setHeight(2);
        cfg
    };

    let output = AudioStreamOutput::new(sink);
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

    let queue = DispatchQueue::new("com.rmd.audio", DispatchQueueAttr::SERIAL);

    // SAFETY: FFI; registers our output for AUDIO samples on `queue`.
    unsafe {
        stream
            .addStreamOutput_type_sampleHandlerQueue_error(
                stream_output,
                SCStreamOutputType::Audio,
                Some(&queue),
            )
            .map_err(|e| CaptureError::Backend(format!("addStreamOutput(audio): {e:?}")))?;
    }

    let start_handler = RcBlock::new(move |error: *mut NSError| {
        if let Some(error) = unsafe { error.as_ref() } {
            tracing::warn!("audio SCStream start failed: {}", error.localizedDescription());
        }
    });
    // SAFETY: FFI; handler retained for the call.
    unsafe { stream.startCaptureWithCompletionHandler(Some(&start_handler)) };

    tracing::info!(display_index, "ScreenCaptureKit desktop-audio capture started");

    Ok(Box::new(MacAudioSession {
        stream,
        _output: output,
        _queue: queue,
    }))
}

/// Live desktop-audio SCStream; dropping/stopping ends capture.
pub struct MacAudioSession {
    stream: Retained<SCStream>,
    _output: Retained<AudioStreamOutput>,
    _queue: DispatchRetained<DispatchQueue>,
}

impl CaptureSession for MacAudioSession {
    fn stop(self: Box<Self>) {
        // SAFETY: FFI; `None` handler is permitted.
        unsafe { self.stream.stopCaptureWithCompletionHandler(None) };
    }
}
