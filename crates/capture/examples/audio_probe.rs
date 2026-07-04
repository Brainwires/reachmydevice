//! Verify desktop-audio capture: start it, collect samples for a few seconds,
//! and report how many arrived and their RMS level. Run with audio playing.
//!
//!   cargo run -p openreach-capture --example audio_probe
//!
//! Needs the Screen Recording TCC permission (same as video capture).

use std::sync::mpsc;
use std::time::{Duration, Instant};

fn main() -> anyhow::Result<()> {
    let (tx, rx) = mpsc::channel::<Vec<i16>>();
    let _session = openreach_capture::start_audio_capture(0, tx)?;
    eprintln!("capturing desktop audio for 4s… (play something)");

    let start = Instant::now();
    let (mut chunks, mut samples, mut sum_sq, mut peak) = (0u64, 0u64, 0f64, 0i16);
    while start.elapsed() < Duration::from_secs(4) {
        if let Ok(chunk) = rx.recv_timeout(Duration::from_millis(200)) {
            chunks += 1;
            samples += chunk.len() as u64;
            for s in chunk {
                sum_sq += (s as f64) * (s as f64);
                peak = peak.max(s.abs());
            }
        }
    }

    let rms = if samples > 0 {
        (sum_sq / samples as f64).sqrt()
    } else {
        0.0
    };
    println!("RESULT chunks={chunks} samples={samples} rms={rms:.1} peak={peak}");
    anyhow::ensure!(samples > 0, "no audio samples captured");
    Ok(())
}
