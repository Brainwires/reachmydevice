//! OpenReach host agent (spike).
//!
//! Headless: captures the screen, encodes H.264, streams it over WebRTC, and
//! injects the viewer's input. Configured via environment variables (a proper
//! CLI/service wrapper comes in Phase 3):
//!
//! | env | default | meaning |
//! |-----|---------|---------|
//! | `OPENREACH_SIGNAL_ADDR` | `127.0.0.1:9000` | signal-dev relay address |
//! | `OPENREACH_DISPLAY`     | `0`              | display index to capture |
//! | `OPENREACH_WIDTH`       | `1920`           | encoded width |
//! | `OPENREACH_HEIGHT`      | `1080`           | encoded height |
//! | `OPENREACH_FPS`         | `30`             | capture/encode fps |
//! | `OPENREACH_BITRATE`     | `8000000`        | initial bitrate (bps) |
//! | `OPENREACH_NAME`        | hostname         | this device's name |
//!
//! Requires **Screen Recording** (capture) and **Accessibility** (input)
//! permissions on macOS — see `docs/macos-permissions.md`.

use openreach_session::{run_host, HostConfig};

fn env_or<T: std::str::FromStr>(key: &str, default: T) -> T {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cfg = HostConfig {
        signal_addr: std::env::var("OPENREACH_SIGNAL_ADDR")
            .unwrap_or_else(|_| "127.0.0.1:9000".to_string()),
        display_index: env_or("OPENREACH_DISPLAY", 0),
        width: env_or("OPENREACH_WIDTH", 1920),
        height: env_or("OPENREACH_HEIGHT", 1080),
        fps: env_or("OPENREACH_FPS", 30),
        bitrate_bps: env_or("OPENREACH_BITRATE", 8_000_000),
        device_name: std::env::var("OPENREACH_NAME").unwrap_or_else(|_| {
            std::env::var("HOSTNAME").unwrap_or_else(|_| "openreach-host".to_string())
        }),
    };

    tracing::info!(
        signal = %cfg.signal_addr,
        display = cfg.display_index,
        res = format!("{}x{}@{}", cfg.width, cfg.height, cfg.fps),
        "starting OpenReach host"
    );
    run_host(cfg)
}
