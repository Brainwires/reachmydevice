//! Pure-Rust AV1 encoder backend (`rav1e`).
//!
//! Encode: BGRA → I420 (via `yuvutils-rs`) → rav1e → AV1 OBU bitstream
//! (low-overhead format, as the WebRTC AV1 RTP payloader expects).
//!
//! This is **encode only**. No pure-Rust AV1 *decoder* with a usable library API
//! exists (rav1d is a C-ABI drop-in for libdav1d), so AV1 is consumed by the
//! browser WASM viewer — which decodes AV1 itself — not by a native viewer. A
//! native viewer always negotiates H.264 (see [`crate::VideoCodec`]).
//!
//! rav1e is tuned here for low-latency real-time screen capture: the fastest
//! speed preset, `low_latency`, single-frame lookahead, and on-demand keyframes.
//! Bitrate changes rebuild the context (which starts a fresh keyframe), mirroring
//! the openh264 backend.

use crate::{DecodedFrame, EncodedFrame, Encoder, EncoderConfig};
use bytes::Bytes;
use rav1e::prelude::{
    ChromaSampling, Config, Context, EncoderConfig as Rav1eConfig, EncoderStatus, FrameParameters,
    FrameType, FrameTypeOverride, PixelRange, Rational,
};
use std::collections::HashMap;
use yuvutils_rs::{
    YuvChromaSubsampling, YuvConversionMode, YuvPlanarImageMut, YuvRange, YuvStandardMatrix,
    bgra_to_yuv420,
};

/// Rebuild the encoder only when the bitrate target moves more than this
/// fraction (each rebuild forces a keyframe), matching the openh264 backend.
const BITRATE_REBUILD_THRESHOLD: f32 = 0.20;

/// Build a rav1e config + context for `cfg`. Width/height are fixed per context,
/// so a resolution change (like a bitrate change) rebuilds it.
fn build_context(cfg: &EncoderConfig, width: u32, height: u32) -> anyhow::Result<Context<u8>> {
    // Fastest preset for real-time; low_latency + single-frame lookahead keep the
    // pipeline delay to ~1 frame. A ~2 s max keyframe interval bounds recovery on
    // top of on-demand keyframes (viewer join / PLI).
    let mut enc = Rav1eConfig::with_speed_preset(10);
    enc.width = width as usize;
    enc.height = height as usize;
    enc.bit_depth = 8;
    enc.chroma_sampling = ChromaSampling::Cs420;
    enc.pixel_range = PixelRange::Limited;
    enc.low_latency = true;
    enc.min_key_frame_interval = 0;
    enc.max_key_frame_interval = u64::from(cfg.fps.max(1)) * 2;
    enc.speed_settings.rdo_lookahead_frames = 1;
    // Target bitrate (bits/sec). rav1e's rate control fills toward this.
    enc.bitrate = cfg.bitrate_bps.max(1) as i32;
    // Frame rate as a rational, for rate control's time base.
    enc.time_base = Rational::new(1, u64::from(cfg.fps.max(1)));

    let config = Config::new()
        .with_encoder_config(enc)
        .with_threads(num_worker_threads());
    config
        .new_context::<u8>()
        .map_err(|e| anyhow::anyhow!("rav1e context init: {e:?}"))
}

/// A small, bounded worker-thread count so a single encoder doesn't monopolize
/// the machine (rav1e parallelizes tiles/frames across these).
fn num_worker_threads() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get().clamp(1, 4))
        .unwrap_or(1)
}

/// Pure-Rust AV1 encoder.
pub struct Rav1eEncoder {
    ctx: Context<u8>,
    cfg: EncoderConfig,
    /// Dimensions the current context was built for (rebuild on change).
    dims: (u32, u32),
    /// Bitrate requested by [`Encoder::set_target_bitrate`], applied lazily.
    pending_bitrate_bps: u32,
    /// Map rav1e's monotonic input frame number → the capture timestamp we were
    /// handed, so the emitted packet (possibly for an earlier frame) carries the
    /// right end-to-end timestamp.
    ts_by_frameno: HashMap<u64, u64>,
    /// Next input frame number (rav1e assigns these in send order).
    next_frameno: u64,
}

impl Rav1eEncoder {
    pub fn new(cfg: EncoderConfig) -> anyhow::Result<Self> {
        let dims = (cfg.width.max(2), cfg.height.max(2));
        let ctx = build_context(&cfg, dims.0, dims.1)?;
        Ok(Self {
            ctx,
            pending_bitrate_bps: cfg.bitrate_bps,
            cfg,
            dims,
            ts_by_frameno: HashMap::new(),
            next_frameno: 0,
        })
    }

    /// Rebuild the context if bitrate drifted past the threshold or the frame
    /// dimensions changed. A rebuild starts a fresh keyframe.
    fn maybe_reconfigure(&mut self, width: u32, height: u32) -> anyhow::Result<()> {
        let cur = self.cfg.bitrate_bps.max(1) as f32;
        let bitrate_drift = (self.pending_bitrate_bps as f32 - cur).abs() / cur;
        let dims_changed = self.dims != (width, height);
        if bitrate_drift > BITRATE_REBUILD_THRESHOLD || dims_changed {
            self.cfg.bitrate_bps = self.pending_bitrate_bps;
            self.dims = (width, height);
            self.ctx = build_context(&self.cfg, width, height)?;
            self.ts_by_frameno.clear();
            self.next_frameno = 0;
            tracing::debug!(
                bitrate_bps = self.cfg.bitrate_bps,
                width,
                height,
                "rav1e context rebuilt"
            );
        }
        Ok(())
    }
}

impl Encoder for Rav1eEncoder {
    fn encode(
        &mut self,
        bgra: &[u8],
        width: u32,
        height: u32,
        stride: u32,
        capture_ts_micros: u64,
        force_keyframe: bool,
    ) -> anyhow::Result<Option<EncodedFrame>> {
        self.maybe_reconfigure(width, height)?;

        // BGRA -> I420 (rav1e wants planar 4:2:0), same path as the H.264 backend.
        let mut img = YuvPlanarImageMut::<u8>::alloc(width, height, YuvChromaSubsampling::Yuv420);
        bgra_to_yuv420(
            &mut img,
            bgra,
            stride,
            YuvRange::Limited,
            YuvStandardMatrix::Bt601,
            YuvConversionMode::Balanced,
        )
        .map_err(|e| anyhow::anyhow!("bgra->i420: {e:?}"))?;

        let mut frame = self.ctx.new_frame();
        frame.planes[0].copy_from_raw_u8(img.y_plane.borrow(), img.y_stride as usize, 1);
        frame.planes[1].copy_from_raw_u8(img.u_plane.borrow(), img.u_stride as usize, 1);
        frame.planes[2].copy_from_raw_u8(img.v_plane.borrow(), img.v_stride as usize, 1);

        let frameno = self.next_frameno;
        self.next_frameno += 1;
        self.ts_by_frameno.insert(frameno, capture_ts_micros);

        // Send the frame, forcing a key frame on demand (viewer join / PLI).
        let send_result = if force_keyframe {
            let fp = FrameParameters {
                frame_type_override: FrameTypeOverride::Key,
                opaque: None,
                t35_metadata: Box::new([]),
            };
            self.ctx.send_frame((frame, fp))
        } else {
            self.ctx.send_frame(frame)
        };
        send_result.map_err(|e| anyhow::anyhow!("rav1e send_frame: {e:?}"))?;

        // Pull at most one packet (steady state is 1-in-1-out under low_latency;
        // the first few frames may return NeedMoreData while the pipeline fills).
        match self.ctx.receive_packet() {
            Ok(pkt) => {
                let is_keyframe = pkt.frame_type == FrameType::KEY;
                let ts = self
                    .ts_by_frameno
                    .remove(&pkt.input_frameno)
                    .unwrap_or(capture_ts_micros);
                Ok(Some(EncodedFrame {
                    data: Bytes::from(pkt.data),
                    is_keyframe,
                    capture_ts_micros: ts,
                }))
            }
            Err(EncoderStatus::NeedMoreData) => Ok(None),
            Err(e) => Err(anyhow::anyhow!("rav1e receive_packet: {e:?}")),
        }
    }

    fn set_target_bitrate(&mut self, bps: u32) {
        self.pending_bitrate_bps = bps;
    }
}

/// AV1 has no pure-Rust decoder with a library API, so this decoder is a stub that
/// exists only to keep the trait object uniform. It is never constructed for a
/// real session ([`crate::new_decoder`] rejects AV1). Present so `av1` builds
/// don't need conditional trait wiring elsewhere.
#[allow(dead_code)]
pub(crate) struct Av1DecodeUnavailable;

#[allow(dead_code)]
impl Av1DecodeUnavailable {
    pub(crate) fn decode(&mut self, _obu: &[u8]) -> anyhow::Result<Option<DecodedFrame>> {
        anyhow::bail!("AV1 decode is browser-only")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode several synthetic BGRA frames and assert rav1e produces AV1 OBU
    /// output, with the forced first frame marked a keyframe. (There is no
    /// pure-Rust AV1 decoder, so the round-trip decode is validated in-browser.)
    #[test]
    fn rav1e_encodes_av1_obus_with_keyframe() {
        let (w, h) = (160u32, 128u32);
        let stride = w * 4;
        let mut bgra = vec![0u8; (stride * h) as usize];
        for y in 0..h {
            for x in 0..w {
                let i = ((y * stride) + x * 4) as usize;
                bgra[i] = (x % 256) as u8;
                bgra[i + 1] = (y % 256) as u8;
                bgra[i + 2] = ((x + y) % 256) as u8;
                bgra[i + 3] = 255;
            }
        }

        let mut enc = Rav1eEncoder::new(EncoderConfig {
            width: w,
            height: h,
            fps: 30,
            bitrate_bps: 2_000_000,
        })
        .expect("rav1e encoder");

        // Drive frames until the pipeline emits a packet, then assert it's a
        // non-empty keyframe (the first frame was force-keyed).
        let mut got_keyframe = false;
        let mut total_bytes = 0usize;
        for idx in 0..12 {
            let force = idx == 0;
            if let Some(ef) = enc
                .encode(&bgra, w, h, stride, 1000 + idx as u64, force)
                .expect("encode")
            {
                total_bytes += ef.data.len();
                assert!(!ef.data.is_empty(), "empty AV1 packet");
                if ef.is_keyframe {
                    got_keyframe = true;
                }
            }
        }
        assert!(got_keyframe, "rav1e never emitted a keyframe");
        assert!(total_bytes > 0, "rav1e produced no output");
    }
}
