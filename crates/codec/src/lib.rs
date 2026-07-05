//! ReachMyDevice video codec.
//!
//! Trait-based [`Encoder`]/[`Decoder`] abstraction with pluggable backends. The
//! Phase-1 backend is **software H.264** ([`software`], via `openh264`); a
//! VideoToolbox hardware backend is the next increment behind the same traits
//! (see `docs/decisions.md` ADR-0007).
//!
//! - Encoder input: **BGRA** bytes (as produced by the capture crate).
//! - Encoder output / decoder input: **H.264 Annex-B** access units.
//! - Decoder output: **RGBA8** bytes (tightly packed, ready for a wgpu texture).
//!
//! The encoder/decoder are single-threaded and thread-affine (they wrap a native
//! codec); the host keeps the encoder on its encode thread and the viewer keeps
//! the decoder on its decode thread. Frames cross threads as [`EncodedFrame`]
//! (which is `Send`).

use bytes::Bytes;

#[cfg(feature = "audio")]
pub mod audio;
pub mod software;

#[cfg(feature = "audio")]
pub use audio::{
    AudioDecoder, AudioEncoder, AUDIO_CHANNELS, AUDIO_FRAME_SAMPLES, AUDIO_SAMPLE_RATE,
};

/// Video codecs ReachMyDevice can negotiate. v1 wires H.264 only; VP8/VP9/H.265 are
/// extension points behind the same traits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VideoCodec {
    H264,
}

/// Encoder settings. `width`/`height` must match the frames handed to
/// [`Encoder::encode`]; a mismatch triggers a backend re-init.
#[derive(Clone, Copy, Debug)]
pub struct EncoderConfig {
    pub width: u32,
    pub height: u32,
    pub fps: u32,
    /// Initial target bitrate (bits/sec). Adjust at runtime via
    /// [`Encoder::set_target_bitrate`] (GCC-driven).
    pub bitrate_bps: u32,
}

impl Default for EncoderConfig {
    fn default() -> Self {
        Self {
            width: 1920,
            height: 1080,
            fps: 30,
            bitrate_bps: 8_000_000,
        }
    }
}

/// One encoded access unit (H.264 Annex-B).
#[derive(Clone)]
pub struct EncodedFrame {
    /// Annex-B bytes (start-code-delimited NAL units). For a keyframe this
    /// includes SPS/PPS ahead of the IDR slice.
    pub data: Bytes,
    /// True if this access unit is an IDR (decodable without prior frames).
    pub is_keyframe: bool,
    /// Capture timestamp carried through for end-to-end latency accounting.
    pub capture_ts_micros: u64,
}

impl std::fmt::Debug for EncodedFrame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncodedFrame")
            .field("bytes", &self.data.len())
            .field("is_keyframe", &self.is_keyframe)
            .field("capture_ts_micros", &self.capture_ts_micros)
            .finish()
    }
}

/// A decoded frame as tightly-packed RGBA8 (`data.len() == width * height * 4`).
pub struct DecodedFrame {
    pub width: u32,
    pub height: u32,
    pub data: Bytes,
}

impl std::fmt::Debug for DecodedFrame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecodedFrame")
            .field("width", &self.width)
            .field("height", &self.height)
            .field("bytes", &self.data.len())
            .finish()
    }
}

/// A video encoder. Not `Send`: the backend is thread-affine, so create and use
/// it on one thread. Encoded output ([`EncodedFrame`]) is `Send` and crosses to
/// the transport thread via a channel.
pub trait Encoder {
    /// Encode one BGRA frame.
    ///
    /// `stride` is the source's bytes-per-row (may exceed `width * 4` for padded
    /// captures). Returns `None` when the backend emitted no output for this
    /// frame (e.g. rate-control frame skip). Set `force_keyframe` to emit an IDR
    /// (e.g. on a viewer join or a decoder PLI).
    fn encode(
        &mut self,
        bgra: &[u8],
        width: u32,
        height: u32,
        stride: u32,
        capture_ts_micros: u64,
        force_keyframe: bool,
    ) -> anyhow::Result<Option<EncodedFrame>>;

    /// Set the target bitrate (bits/sec), typically from the transport's GCC
    /// estimate. Backends may apply this lazily / with a small threshold.
    fn set_target_bitrate(&mut self, bps: u32);
}

/// A video decoder. Not `Send`; keep it on the viewer's decode thread.
pub trait Decoder {
    /// Decode one Annex-B access unit into an RGBA frame. Returns `None` if the
    /// decoder needs more data before it can emit a picture.
    fn decode(&mut self, annexb: &[u8]) -> anyhow::Result<Option<DecodedFrame>>;
}

/// Construct the default (software H.264) encoder.
pub fn new_encoder(config: EncoderConfig) -> anyhow::Result<Box<dyn Encoder>> {
    Ok(Box::new(software::OpenH264Encoder::new(config)?))
}

/// Construct the default (software H.264) decoder.
pub fn new_decoder() -> anyhow::Result<Box<dyn Decoder>> {
    Ok(Box::new(software::OpenH264Decoder::new()?))
}

/// Scan an Annex-B buffer for an IDR (NAL type 5) — i.e. a keyframe.
///
/// Walks 3- and 4-byte start codes and inspects each NAL header's low 5 bits.
pub(crate) fn contains_idr(annexb: &[u8]) -> bool {
    let mut i = 0;
    while i + 3 < annexb.len() {
        // Match a start code: 00 00 01 or 00 00 00 01.
        let (is_start, hdr) = if annexb[i] == 0 && annexb[i + 1] == 0 && annexb[i + 2] == 1 {
            (true, i + 3)
        } else if i + 4 < annexb.len()
            && annexb[i] == 0
            && annexb[i + 1] == 0
            && annexb[i + 2] == 0
            && annexb[i + 3] == 1
        {
            (true, i + 4)
        } else {
            (false, 0)
        };
        if is_start && hdr < annexb.len() {
            let nal_type = annexb[hdr] & 0x1f;
            if nal_type == 5 {
                return true;
            }
            i = hdr + 1;
        } else {
            i += 1;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idr_detected_in_annexb() {
        // start code + NAL header with type 5 (IDR).
        let buf = [0, 0, 0, 1, 0x65, 0xaa, 0xbb];
        assert!(contains_idr(&buf));
        // type 1 (non-IDR slice) only.
        let buf = [0, 0, 1, 0x41, 0x00];
        assert!(!contains_idr(&buf));
    }
}
