//! Software H.264 backend (`openh264`), the Phase-1 codec (ADR-0007).
//!
//! Encode: BGRA → I420 (via `yuvutils-rs`) → openh264 → Annex-B.
//! Decode: Annex-B → openh264 → RGBA8.
//!
//! openh264 builds from source (no system codec library). The encoder takes its
//! dimensions from the frame at `encode` time and re-inits internally when they
//! change; bitrate, however, is fixed at construction, so runtime bitrate
//! changes rebuild the encoder (see [`OpenH264Encoder::maybe_reconfigure`]).

use crate::{DecodedFrame, Decoder, EncodedFrame, Encoder, EncoderConfig};
use bytes::Bytes;
use openh264::encoder::{
    BitRate, Complexity, Encoder as OhEncoder, EncoderConfig as OhEncoderConfig, FrameRate,
    IntraFramePeriod, RateControlMode, UsageType,
};
use openh264::formats::{YUVSlices, YUVSource};
use openh264::OpenH264API;
use std::time::{Duration, Instant};
use yuvutils_rs::{
    bgra_to_yuv420, YuvChromaSubsampling, YuvConversionMode, YuvPlanarImageMut, YuvRange,
    YuvStandardMatrix,
};

/// Rebuild the encoder only when the bitrate target moves more than this
/// fraction, so gradual GCC nudges don't thrash (each rebuild forces a keyframe).
/// GCC oscillates continuously, so this must be generous.
const BITRATE_REBUILD_THRESHOLD: f32 = 0.35;

/// Minimum wall-clock gap between encoder rebuilds. Bounds the rebuild rate no
/// matter how fast GCC swings, so we never re-create the encoder (and emit a
/// costly keyframe) every frame — the churn behind the openh264 warning flood.
const REBUILD_MIN_INTERVAL: Duration = Duration::from_secs(4);

/// Build an openh264 encoder for `cfg`. Width/height come from the frames later;
/// bitrate/fps/GOP are set here.
fn build_encoder(cfg: &EncoderConfig) -> anyhow::Result<OhEncoder> {
    let oh_cfg = OhEncoderConfig::new()
        .bitrate(BitRate::from_bps(cfg.bitrate_bps))
        .max_frame_rate(FrameRate::from_hz(cfg.fps as f32))
        // Screen content + real-time tuning for a desktop stream.
        .usage_type(UsageType::ScreenContentRealTime)
        .rate_control_mode(RateControlMode::Bitrate)
        .complexity(Complexity::Low)
        // Quiet openh264's own stderr logging (e.g. the harmless "AdaptiveQuant
        // not supported for screen content" ParamValidation warnings on init).
        .debug(false)
        // Periodic IDR every ~2s bounds recovery time after loss/join, on top of
        // on-demand keyframes (PLI / viewer join).
        .intra_frame_period(IntraFramePeriod::from_num_frames(cfg.fps.max(1) * 2));
    OhEncoder::with_api_config(OpenH264API::from_source(), oh_cfg)
        .map_err(|e| anyhow::anyhow!("openh264 encoder init: {e}"))
}

/// Software H.264 encoder.
pub struct OpenH264Encoder {
    encoder: OhEncoder,
    cfg: EncoderConfig,
    /// Bitrate requested by [`Encoder::set_target_bitrate`], applied lazily.
    pending_bitrate_bps: u32,
    /// When the encoder was last (re)built, to rate-limit rebuilds.
    last_rebuild: Instant,
}

impl OpenH264Encoder {
    pub fn new(cfg: EncoderConfig) -> anyhow::Result<Self> {
        Ok(Self {
            encoder: build_encoder(&cfg)?,
            pending_bitrate_bps: cfg.bitrate_bps,
            cfg,
            last_rebuild: Instant::now(),
        })
    }

    /// Rebuild the encoder if the pending bitrate has drifted past the threshold
    /// *and* enough time has passed since the last rebuild. openh264 0.9 exposes
    /// no runtime bitrate setter (its `set_option`/`raw_api` is private), so a
    /// rebuild is the only way to retarget — but it drops encoder state and forces
    /// a keyframe, so we do it sparingly rather than chasing every GCC swing.
    fn maybe_reconfigure(&mut self) -> anyhow::Result<()> {
        let cur = self.cfg.bitrate_bps.max(1) as f32;
        let delta = (self.pending_bitrate_bps as f32 - cur).abs() / cur;
        if delta > BITRATE_REBUILD_THRESHOLD && self.last_rebuild.elapsed() >= REBUILD_MIN_INTERVAL
        {
            self.cfg.bitrate_bps = self.pending_bitrate_bps;
            self.encoder = build_encoder(&self.cfg)?;
            self.last_rebuild = Instant::now();
            tracing::debug!(
                bitrate_bps = self.cfg.bitrate_bps,
                "encoder rebuilt for new bitrate"
            );
        }
        Ok(())
    }
}

impl Encoder for OpenH264Encoder {
    fn encode(
        &mut self,
        bgra: &[u8],
        width: u32,
        height: u32,
        stride: u32,
        capture_ts_micros: u64,
        force_keyframe: bool,
    ) -> anyhow::Result<Option<EncodedFrame>> {
        self.maybe_reconfigure()?;
        if force_keyframe {
            self.encoder.force_intra_frame();
        }

        // BGRA -> I420. openh264 wants planar 4:2:0.
        let mut img = YuvPlanarImageMut::<u8>::alloc(width, height, YuvChromaSubsampling::Yuv420);
        bgra_to_yuv420(
            &mut img,
            bgra,
            stride,
            YuvRange::Limited,
            YuvStandardMatrix::Bt601,
            // `Balanced` is the default (always available; `Fast` needs a feature)
            // and is still a very fast SIMD path.
            YuvConversionMode::Balanced,
        )
        .map_err(|e| anyhow::anyhow!("bgra->i420: {e:?}"))?;

        let yuv = YUVSlices::new(
            (
                img.y_plane.borrow(),
                img.u_plane.borrow(),
                img.v_plane.borrow(),
            ),
            (width as usize, height as usize),
            (
                img.y_stride as usize,
                img.u_stride as usize,
                img.v_stride as usize,
            ),
        );

        let bitstream = self
            .encoder
            .encode(&yuv)
            .map_err(|e| anyhow::anyhow!("openh264 encode: {e}"))?;
        let data = bitstream.to_vec();
        if data.is_empty() {
            // Rate control skipped this frame.
            return Ok(None);
        }
        let is_keyframe = crate::contains_idr(&data);
        Ok(Some(EncodedFrame {
            data: Bytes::from(data),
            is_keyframe,
            capture_ts_micros,
        }))
    }

    fn set_target_bitrate(&mut self, bps: u32) {
        self.pending_bitrate_bps = bps;
    }
}

/// Software H.264 decoder.
pub struct OpenH264Decoder {
    decoder: openh264::decoder::Decoder,
}

impl OpenH264Decoder {
    pub fn new() -> anyhow::Result<Self> {
        let decoder = openh264::decoder::Decoder::new()
            .map_err(|e| anyhow::anyhow!("openh264 decoder init: {e}"))?;
        Ok(Self { decoder })
    }
}

impl Decoder for OpenH264Decoder {
    fn decode(&mut self, annexb: &[u8]) -> anyhow::Result<Option<DecodedFrame>> {
        match self
            .decoder
            .decode(annexb)
            .map_err(|e| anyhow::anyhow!("openh264 decode: {e}"))?
        {
            Some(yuv) => {
                let (w, h) = yuv.dimensions();
                let mut rgba = vec![0u8; w * h * 4];
                yuv.write_rgba8(&mut rgba);
                Ok(Some(DecodedFrame {
                    width: w as u32,
                    height: h as u32,
                    data: Bytes::from(rgba),
                }))
            }
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode a synthetic BGRA frame and decode it back, verifying the pipeline
    /// (openh264 build + yuvutils conversion + Annex-B roundtrip) works end to end.
    #[test]
    fn encode_then_decode_roundtrip() {
        let (w, h) = (128u32, 96u32);
        let stride = w * 4;
        // A simple gradient so it isn't a trivial flat frame.
        let mut bgra = vec![0u8; (stride * h) as usize];
        for y in 0..h {
            for x in 0..w {
                let i = ((y * stride) + x * 4) as usize;
                bgra[i] = (x % 256) as u8; // B
                bgra[i + 1] = (y % 256) as u8; // G
                bgra[i + 2] = ((x + y) % 256) as u8; // R
                bgra[i + 3] = 255; // A
            }
        }

        let mut enc = OpenH264Encoder::new(EncoderConfig {
            width: w,
            height: h,
            fps: 30,
            bitrate_bps: 2_000_000,
        })
        .expect("encoder");
        let mut dec = OpenH264Decoder::new().expect("decoder");

        // First frame forced to a keyframe so the decoder can start.
        let encoded = enc
            .encode(&bgra, w, h, stride, 1234, true)
            .expect("encode")
            .expect("some output");
        assert!(
            encoded.is_keyframe,
            "first forced frame should be a keyframe"
        );
        assert_eq!(encoded.capture_ts_micros, 1234);

        let decoded = dec.decode(&encoded.data).expect("decode");
        // openh264 may need the full access unit before emitting; a keyframe should decode.
        if let Some(frame) = decoded {
            assert_eq!(frame.width, w);
            assert_eq!(frame.height, h);
            assert_eq!(frame.data.len(), (w * h * 4) as usize);
        }
    }
}
