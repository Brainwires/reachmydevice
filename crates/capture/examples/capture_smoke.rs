//! Capture smoke test.
//!
//! Lists displays, captures the primary display for ~2s, and reports frame
//! geometry and rate. Run on macOS with **Screen Recording** permission granted
//! (System Settings → Privacy & Security → Screen & System Audio Recording):
//!
//! ```sh
//! cargo run -p rmd-capture --example capture_smoke
//! ```
//!
//! Zero frames almost always means the permission has not been granted (or the
//! binary needs to be restarted after granting).

use rmd_capture::{list_displays, start_capture, CaptureConfig};
use std::sync::mpsc;
use std::time::{Duration, Instant};

fn main() -> anyhow::Result<()> {
    let displays = list_displays()?;
    println!("displays ({}):", displays.len());
    for d in &displays {
        println!("  [{}] {}x{}", d.index, d.width, d.height);
    }
    if displays.is_empty() {
        anyhow::bail!("no displays found");
    }

    let (tx, rx) = mpsc::channel();
    let cfg = CaptureConfig {
        width: 1280,
        height: 720,
        fps: 30,
        show_cursor: true,
    };
    println!(
        "\nstarting capture of display 0 at {}x{}@{}...",
        cfg.width, cfg.height, cfg.fps
    );
    let session = start_capture(cfg, 0, tx)?;

    let start = Instant::now();
    let mut count = 0u32;
    let mut first_frame_at = None;
    while start.elapsed() < Duration::from_secs(2) {
        if let Ok(frame) = rx.recv_timeout(Duration::from_millis(500)) {
            if first_frame_at.is_none() {
                first_frame_at = Some(start.elapsed());
            }
            count += 1;
            if count <= 3 || count % 30 == 0 {
                println!(
                    "  frame {count}: {}x{} bpr={} bytes={} ts={}us",
                    frame.width,
                    frame.height,
                    frame.bytes_per_row,
                    frame.data.len(),
                    frame.capture_ts_micros
                );
            }
        }
    }
    session.stop();

    println!(
        "\ncaptured {count} frames in ~2s (~{} fps); first frame at {:?}",
        count / 2,
        first_frame_at
    );
    if count == 0 {
        anyhow::bail!("no frames captured — grant Screen Recording permission and retry");
    }
    Ok(())
}
