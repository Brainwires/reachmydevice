//! OpenReach host agent (spike).
//!
//! Headless: captures the screen, encodes H.264, streams it over WebRTC, and
//! injects the viewer's input. Configured via environment variables:
//!
//! | env | default | meaning |
//! |-----|---------|---------|
//! | `OPENREACH_DISPLAY`     | `0`         | display index to capture |
//! | `OPENREACH_WIDTH/HEIGHT/FPS/BITRATE` | 1920/1080/30/8000000 | encode params |
//! | `OPENREACH_NAME`        | hostname    | this device's name |
//! | `OPENREACH_ICE`         | (none)      | comma-separated STUN/TURN URLs |
//! | `OPENREACH_RENDEZVOUS_URL` | (none)   | `wss://host/ws` — use rendezvous if set |
//! | `OPENREACH_TOKEN`       | (none)      | device bearer token (rendezvous mode) |
//! | `OPENREACH_SIGNAL_ADDR` | `127.0.0.1:9000` | LAN signal-dev relay (fallback) |
//!
//! Requires **Screen Recording** (capture) and **Accessibility** (input)
//! permissions on macOS — see `docs/macos-permissions.md`.

use anyhow::Context;
use openreach_session::rendezvous::RendezvousClient;
use openreach_session::{run_host, HostConfig, SignalClient, Signaling};

fn env_or<T: std::str::FromStr>(key: &str, default: T) -> T {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn ice_servers() -> Vec<String> {
    std::env::var("OPENREACH_ICE")
        .map(|s| {
            s.split(',')
                .map(|x| x.trim().to_string())
                .filter(|x| !x.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// Build the signaling backend: rendezvous WebSocket if configured, else LAN relay.
/// `peer` is the device to address (None for the host — it learns the viewer).
fn build_signaling(peer: Option<String>) -> anyhow::Result<Box<dyn Signaling>> {
    if let Ok(url) = std::env::var("OPENREACH_RENDEZVOUS_URL") {
        let token = std::env::var("OPENREACH_TOKEN")
            .context("OPENREACH_TOKEN is required in rendezvous mode")?;
        tracing::info!(%url, "signaling via rendezvous");
        Ok(Box::new(RendezvousClient::connect(&url, &token, peer)?))
    } else {
        let addr =
            std::env::var("OPENREACH_SIGNAL_ADDR").unwrap_or_else(|_| "127.0.0.1:9000".to_string());
        tracing::info!(%addr, "signaling via LAN relay");
        Ok(Box::new(SignalClient::connect(&addr)?))
    }
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cfg = HostConfig {
        display_index: env_or("OPENREACH_DISPLAY", 0),
        width: env_or("OPENREACH_WIDTH", 1920),
        height: env_or("OPENREACH_HEIGHT", 1080),
        fps: env_or("OPENREACH_FPS", 30),
        bitrate_bps: env_or("OPENREACH_BITRATE", 8_000_000),
        device_name: std::env::var("OPENREACH_NAME").unwrap_or_else(|_| {
            std::env::var("HOSTNAME").unwrap_or_else(|_| "openreach-host".to_string())
        }),
        ice_servers: ice_servers(),
        bind_addr: std::env::var("OPENREACH_BIND").unwrap_or_else(|_| "0.0.0.0:0".to_string()),
        enable_audio: std::env::var("OPENREACH_AUDIO").is_ok(),
    };

    tracing::info!(
        display = cfg.display_index,
        res = format!("{}x{}@{}", cfg.width, cfg.height, cfg.fps),
        "starting OpenReach host"
    );
    // The host is the offerer; it learns the viewer's id from the rendezvous hello.
    let signaling = build_signaling(None)?;
    run_host(cfg, signaling)
}
