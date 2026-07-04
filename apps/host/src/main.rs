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

use openreach_session::rendezvous::RendezvousClient;
use openreach_session::{run_host, HostConfig, SignalClient, Signaling};

#[cfg(feature = "tray")]
mod tray;

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

/// Load authorized viewer `device_id`s for unattended access. Reads
/// `OPENREACH_AUTHORIZED_KEYS` (or `~/.config/openreach/authorized_keys`): one
/// device_id per line, `#` comments and blanks ignored.
fn authorized_device_ids() -> Vec<String> {
    let path = std::env::var("OPENREACH_AUTHORIZED_KEYS")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_default();
            std::path::PathBuf::from(home).join(".config/openreach/authorized_keys")
        });
    match std::fs::read_to_string(&path) {
        Ok(s) => s
            .lines()
            .map(|l| l.split('#').next().unwrap_or("").trim().to_string())
            .filter(|l| !l.is_empty())
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// Read the device bearer token, preferring a `0600` file over the environment
/// (env vars leak via `ps e` / `/proc/<pid>/environ`). File path from
/// `OPENREACH_TOKEN_FILE`, else `~/.config/openreach/token`.
fn read_token() -> anyhow::Result<zeroize::Zeroizing<String>> {
    let path = std::env::var("OPENREACH_TOKEN_FILE")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_default();
            std::path::PathBuf::from(home).join(".config/openreach/token")
        });
    if let Ok(s) = std::fs::read_to_string(&path) {
        return Ok(zeroize::Zeroizing::new(s.trim().to_string()));
    }
    if let Ok(s) = std::env::var("OPENREACH_TOKEN") {
        tracing::warn!(
            "using OPENREACH_TOKEN from the environment (visible in process listings); \
             prefer a 0600 token file at {}",
            path.display()
        );
        return Ok(zeroize::Zeroizing::new(s));
    }
    anyhow::bail!(
        "no device token: create {} (0600) or set OPENREACH_TOKEN_FILE / OPENREACH_TOKEN",
        path.display()
    )
}

/// Build the signaling backend: rendezvous WebSocket if configured, else LAN relay.
/// `peer` is the device to address (None for the host — it learns the viewer).
fn build_signaling(peer: Option<String>) -> anyhow::Result<Box<dyn Signaling>> {
    if let Ok(url) = std::env::var("OPENREACH_RENDEZVOUS_URL") {
        let token = read_token()?;
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
        // Unattended access is enforced when explicitly requested or when an
        // authorized-keys list is present.
        require_authorization: std::env::var("OPENREACH_REQUIRE_AUTH").is_ok()
            || !authorized_device_ids().is_empty(),
        authorized_device_ids: authorized_device_ids(),
    };

    tracing::info!(
        display = cfg.display_index,
        res = format!("{}x{}@{}", cfg.width, cfg.height, cfg.fps),
        "starting OpenReach host"
    );
    // The host is the offerer; it learns the viewer's id from the rendezvous hello.
    let signaling = build_signaling(None)?;

    // Desktop tray companion when built with `--features tray` and requested via
    // `OPENREACH_TRAY=1`; otherwise run headless (the default, and the only
    // option on servers without a display).
    #[cfg(feature = "tray")]
    if std::env::var("OPENREACH_TRAY").is_ok() {
        return tray::run_with_tray(cfg, signaling);
    }

    run_host(cfg, signaling)
}
