//! Host-side digital zoom: crop a sub-rect of a captured BGRA frame and scale it
//! back up to the frame's own dimensions, so the encoded stream shows a magnified
//! region of the screen (see the plan / `SetZoom`). The output keeps the original
//! width/height, so the wire resolution never changes and the encoder never
//! re-inits.
//!
//! We pack the crop into a tightly-packed buffer first (the capture frame may be
//! row-padded — `bytes_per_row > width*4`), then hand it to `fast_image_resize`
//! (SIMD). Buffers are reused across frames to avoid per-frame allocation.

use fast_image_resize::images::{Image, ImageRef};
use fast_image_resize::{FilterType, PixelType, ResizeAlg, ResizeOptions, Resizer};

/// Normalized crop rectangle in [0,1] over the source frame. `{0,0,1,1}` is the
/// identity (no zoom).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CropRect {
    pub x: f64,
    pub y: f64,
    pub w: f64,
    pub h: f64,
}

impl CropRect {
    pub const FULL: CropRect = CropRect {
        x: 0.0,
        y: 0.0,
        w: 1.0,
        h: 1.0,
    };

    /// Sanitize a rect that arrived over the wire: clamp to [0,1] and keep it
    /// on-screen. A degenerate or full rect collapses to [`CropRect::FULL`].
    pub fn sanitized(self) -> CropRect {
        let w = self.w.clamp(0.0, 1.0);
        let h = self.h.clamp(0.0, 1.0);
        if !(w > 0.0 && h > 0.0) || (w >= 1.0 && h >= 1.0) {
            return CropRect::FULL;
        }
        let x = self.x.clamp(0.0, 1.0 - w);
        let y = self.y.clamp(0.0, 1.0 - h);
        CropRect { x, y, w, h }
    }

    /// Is this effectively "no zoom"? (crop covers the whole frame)
    pub fn is_full(&self) -> bool {
        self.w >= 1.0 && self.h >= 1.0
    }
}

/// Reusable BGRA crop+scaler. Holds the SIMD resizer and scratch buffers.
pub struct Scaler {
    resizer: Resizer,
    src_tight: Vec<u8>, // packed crop region, BGRA
    dst: Vec<u8>,       // scaled output, BGRA, out_w*out_h*4
}

impl Default for Scaler {
    fn default() -> Self {
        Self::new()
    }
}

impl Scaler {
    pub fn new() -> Self {
        Self {
            resizer: Resizer::new(),
            src_tight: Vec::new(),
            dst: Vec::new(),
        }
    }

    /// Crop `rect` out of the source BGRA frame and scale it to `out_w × out_h`.
    /// Returns a tightly-packed BGRA buffer (`stride == out_w*4`). Returns `None`
    /// if the rect is effectively full (caller should encode the frame as-is) or
    /// on any sizing error (caller falls back to the uncropped frame).
    #[allow(clippy::too_many_arguments)]
    pub fn crop_scale(
        &mut self,
        src: &[u8],
        src_w: u32,
        src_h: u32,
        src_stride: u32,
        rect: CropRect,
        out_w: u32,
        out_h: u32,
    ) -> Option<&[u8]> {
        let rect = rect.sanitized();
        if rect.is_full() || src_w == 0 || src_h == 0 || out_w == 0 || out_h == 0 {
            return None;
        }
        // Crop rectangle in source pixels (rounded, kept in-bounds, ≥1px).
        let cx = ((rect.x * src_w as f64).round() as u32).min(src_w - 1);
        let cy = ((rect.y * src_h as f64).round() as u32).min(src_h - 1);
        let cw = ((rect.w * src_w as f64).round() as u32)
            .max(1)
            .min(src_w - cx);
        let ch = ((rect.h * src_h as f64).round() as u32)
            .max(1)
            .min(src_h - cy);

        // Pack the crop into a tight BGRA buffer (source may be row-padded).
        let row_bytes = (cw * 4) as usize;
        self.src_tight.resize(row_bytes * ch as usize, 0);
        let stride = src_stride as usize;
        for row in 0..ch as usize {
            let sy = cy as usize + row;
            let so = sy * stride + cx as usize * 4;
            let src_row = src.get(so..so + row_bytes)?;
            let do_ = row * row_bytes;
            self.src_tight[do_..do_ + row_bytes].copy_from_slice(src_row);
        }

        self.dst.resize((out_w * out_h * 4) as usize, 0);
        let src_img = ImageRef::new(cw, ch, &self.src_tight, PixelType::U8x4).ok()?;
        let mut dst_img =
            Image::from_slice_u8(out_w, out_h, &mut self.dst, PixelType::U8x4).ok()?;
        let opts = ResizeOptions::new().resize_alg(ResizeAlg::Convolution(FilterType::Bilinear));
        self.resizer.resize(&src_img, &mut dst_img, &opts).ok()?;
        Some(&self.dst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_collapses_full_and_degenerate_to_full() {
        assert!(CropRect::FULL.sanitized().is_full());
        assert!(
            CropRect {
                x: 0.0,
                y: 0.0,
                w: 0.0,
                h: 0.5
            }
            .sanitized()
            .is_full()
        );
        assert!(
            CropRect {
                x: 0.2,
                y: 0.2,
                w: 1.0,
                h: 1.0
            }
            .sanitized()
            .is_full()
        );
    }

    #[test]
    fn sanitize_keeps_crop_on_screen() {
        // A rect that would spill past the right/bottom edge is nudged in-bounds.
        let r = CropRect {
            x: 0.9,
            y: 0.9,
            w: 0.5,
            h: 0.5,
        }
        .sanitized();
        assert!((r.w - 0.5).abs() < 1e-9 && (r.h - 0.5).abs() < 1e-9);
        assert!(r.x + r.w <= 1.0 + 1e-9 && r.y + r.h <= 1.0 + 1e-9);
        assert!((r.x - 0.5).abs() < 1e-9 && (r.y - 0.5).abs() < 1e-9);
    }

    #[test]
    fn full_rect_skips_scaling() {
        let mut s = Scaler::new();
        let src = vec![0u8; 8 * 8 * 4];
        assert!(
            s.crop_scale(&src, 8, 8, 8 * 4, CropRect::FULL, 8, 8)
                .is_none()
        );
    }

    #[test]
    fn crop_scale_produces_output_and_honors_stride() {
        // 4x2 BGRA source with row padding (stride 4*4 + 8). Left half red, right
        // half blue; crop the left half and scale to 4x2 — expect ~red throughout.
        let (w, h) = (4u32, 2u32);
        let stride = (w * 4 + 8) as usize;
        let mut src = vec![0u8; stride * h as usize];
        for y in 0..h as usize {
            for x in 0..w as usize {
                let o = y * stride + x * 4;
                let (b, r) = if x < 2 { (0, 255) } else { (255, 0) };
                src[o] = b; // B
                src[o + 1] = 0; // G
                src[o + 2] = r; // R
                src[o + 3] = 255; // A
            }
        }
        let mut s = Scaler::new();
        let out = s
            .crop_scale(
                &src,
                w,
                h,
                stride as u32,
                CropRect {
                    x: 0.0,
                    y: 0.0,
                    w: 0.5,
                    h: 1.0,
                },
                w,
                h,
            )
            .expect("cropped");
        assert_eq!(out.len(), (w * h * 4) as usize);
        // Every output pixel should be dominated by red (the cropped-in half).
        for px in out.chunks_exact(4) {
            assert!(px[2] > 200, "expected red-dominant, got {px:?}");
            assert!(px[0] < 60, "expected low blue, got {px:?}");
        }
    }
}
