//! rav1e real-time benchmark (Phase-0 Spike B).
//!
//! Measures the pure-Rust AV1 encoder at 720p30 and 1080p30 on this host:
//! per-frame encode latency, achieved FPS, and average bitrate. Decides whether
//! AV1 is viable as a real-time host codec for browser viewers.
//!
//! Run: `cargo run -p rmd-codec --example av1_bench --features av1 --release`

use rmd_codec::{new_encoder, EncoderConfig, VideoCodec};
use std::time::Instant;

fn bench(width: u32, height: u32, fps: u32, bitrate_bps: u32, frames: u32) {
    let mut enc = new_encoder(
        VideoCodec::Av1,
        EncoderConfig {
            width,
            height,
            fps,
            bitrate_bps,
        },
    )
    .expect("rav1e encoder");

    // A moving synthetic pattern so every frame differs (worst-ish case: real
    // screen content is usually more compressible than this gradient churn).
    let stride = width * 4;
    let mut bgra = vec![0u8; (stride * height) as usize];

    let mut latencies = Vec::new();
    let mut total_out = 0usize;
    let mut emitted = 0u32;
    let run_start = Instant::now();

    for f in 0..frames {
        for y in 0..height {
            for x in 0..width {
                let i = ((y * stride) + x * 4) as usize;
                bgra[i] = ((x + f) % 256) as u8;
                bgra[i + 1] = ((y + f) % 256) as u8;
                bgra[i + 2] = ((x + y + f) % 256) as u8;
                bgra[i + 3] = 255;
            }
        }
        let t = Instant::now();
        let out = enc
            .encode(&bgra, width, height, stride, u64::from(f) * 33_333, f == 0)
            .expect("encode");
        let dt = t.elapsed();
        if let Some(ef) = out {
            latencies.push(dt.as_secs_f64() * 1000.0);
            total_out += ef.data.len();
            emitted += 1;
        }
    }

    let wall = run_start.elapsed().as_secs_f64();
    latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let mean = latencies.iter().sum::<f64>() / latencies.len().max(1) as f64;
    let p95 = latencies
        .get((latencies.len() as f64 * 0.95) as usize)
        .copied()
        .unwrap_or(mean);
    let achieved_fps = emitted as f64 / wall;
    let avg_bitrate_kbps = (total_out as f64 * 8.0 / 1000.0) / (emitted as f64 / fps as f64);

    println!(
        "{width}x{height}@{fps}  target={:>5}kbps | encode: mean {mean:6.1}ms  p95 {p95:6.1}ms | \
         achieved {achieved_fps:5.1} fps | out ~{avg_bitrate_kbps:6.0}kbps | frames {emitted}/{frames}",
        bitrate_bps / 1000
    );
    let realtime = mean <= (1000.0 / fps as f64);
    println!(
        "   -> {} real-time budget ({:.1}ms/frame at {fps}fps)",
        if realtime { "MEETS" } else { "MISSES" },
        1000.0 / fps as f64
    );
}

fn main() {
    println!("rav1e real-time benchmark (speed preset 10, low-latency)\n");
    bench(1280, 720, 30, 4_000_000, 120);
    bench(1920, 1080, 30, 8_000_000, 90);
}
