//! ReachMyDevice host agent (spike).
//!
//! Headless: captures the screen, encodes H.264, streams it over WebRTC, and
//! injects the viewer's input. Configured via environment variables:
//!
//! | env | default | meaning |
//! |-----|---------|---------|
//! | `RMD_DISPLAY`     | `0`         | display index to capture |
//! | `RMD_WIDTH/HEIGHT/FPS/BITRATE` | 1920/1080/30/8000000 | encode params |
//! | `RMD_NAME`        | hostname    | this device's name |
//! | `RMD_ICE`         | (none)      | comma-separated STUN/TURN URLs |
//! | `RMD_RENDEZVOUS_URL` | (none)   | `wss://host/ws` — use rendezvous if set |
//! | `RMD_TOKEN`       | (none)      | device bearer token (rendezvous mode) |
//! | `RMD_SIGNAL_ADDR` | `127.0.0.1:9000` | LAN signal-dev relay (fallback) |
//!
//! Requires **Screen Recording** (capture) and **Accessibility** (input)
//! permissions on macOS — see `docs/macos-permissions.md`.

use rmd_session::rendezvous::RendezvousClient;
use rmd_session::{run_host, HostConfig, SignalClient, Signaling};

#[cfg(feature = "tray")]
mod tray;

fn env_or<T: std::str::FromStr>(key: &str, default: T) -> T {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn ice_servers() -> Vec<String> {
    std::env::var("RMD_ICE")
        .map(|s| {
            s.split(',')
                .map(|x| x.trim().to_string())
                .filter(|x| !x.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// Load authorized viewer `device_id`s for unattended access. Reads
/// `RMD_AUTHORIZED_KEYS` (or `~/.config/rmd/authorized_keys`): one
/// device_id per line, `#` comments and blanks ignored.
fn authorized_device_ids() -> Vec<String> {
    let path = std::env::var("RMD_AUTHORIZED_KEYS")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_default();
            std::path::PathBuf::from(home).join(".config/rmd/authorized_keys")
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

/// Load (or first-run create) this host's device identity, used to prove the
/// host's identity to viewers (bound to the DTLS session). Encrypted at rest when
/// `RMD_KEY_PASSPHRASE` is set.
fn load_host_identity() -> Option<std::sync::Arc<rmd_session::DeviceIdentity>> {
    let home = std::env::var("HOME").ok()?;
    let path = std::path::PathBuf::from(home).join(".config/rmd/identity.key");
    match rmd_session::DeviceIdentity::load_or_create(&path) {
        Ok(id) => {
            tracing::info!(device_id = %id.device_id(), "host identity loaded");
            Some(std::sync::Arc::new(id))
        }
        Err(e) => {
            tracing::warn!(error=%e, "could not load host identity; viewers can't verify this host");
            None
        }
    }
}

/// Read the device bearer token, preferring a `0600` file over the environment
/// (env vars leak via `ps e` / `/proc/<pid>/environ`). File path from
/// `RMD_TOKEN_FILE`, else `~/.config/rmd/token`.
fn read_token() -> anyhow::Result<zeroize::Zeroizing<String>> {
    let path = std::env::var("RMD_TOKEN_FILE")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_default();
            std::path::PathBuf::from(home).join(".config/rmd/token")
        });
    if let Ok(s) = std::fs::read_to_string(&path) {
        return Ok(zeroize::Zeroizing::new(s.trim().to_string()));
    }
    if let Ok(s) = std::env::var("RMD_TOKEN") {
        tracing::warn!(
            "using RMD_TOKEN from the environment (visible in process listings); \
             prefer a 0600 token file at {}",
            path.display()
        );
        return Ok(zeroize::Zeroizing::new(s));
    }
    anyhow::bail!(
        "no device token: create {} (0600) or set RMD_TOKEN_FILE / RMD_TOKEN",
        path.display()
    )
}

/// Video codec from `RMD_CODEC` (`h264` default, or `av1`). AV1 is the pure-Rust
/// rav1e encoder for browser viewers and requires the host built with
/// `--features av1`; otherwise encoder init fails with a clear message.
fn video_codec_from_env() -> rmd_codec::VideoCodec {
    match std::env::var("RMD_CODEC")
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
    {
        "av1" => rmd_codec::VideoCodec::Av1,
        _ => rmd_codec::VideoCodec::H264,
    }
}

/// Build the signaling backend: rendezvous WebSocket if configured, else LAN relay.
/// `peer` is the device to address (None for the host — it learns the viewer).
fn build_signaling(peer: Option<String>) -> anyhow::Result<Box<dyn Signaling>> {
    if let Ok(url) = std::env::var("RMD_RENDEZVOUS_URL") {
        let token = read_token()?;
        tracing::info!(%url, "signaling via rendezvous");
        Ok(Box::new(RendezvousClient::connect(&url, &token, peer)?))
    } else {
        let addr =
            std::env::var("RMD_SIGNAL_ADDR").unwrap_or_else(|_| "127.0.0.1:9000".to_string());
        tracing::info!(%addr, "signaling via LAN relay");
        Ok(Box::new(SignalClient::connect(&addr)?))
    }
}

fn main() -> anyhow::Result<()> {
    // Lightweight flags before any setup, so `--version` works for install checks.
    for a in std::env::args().skip(1) {
        match a.as_str() {
            "--version" | "-V" => {
                println!("rmdd {}", env!("CARGO_PKG_VERSION"));
                return Ok(());
            }
            "--help" | "-h" => {
                println!(
                    "rmdd {} — ReachMyDevice host agent (daemon)\n\n\
                     Configured via environment variables:\n  \
                     RMD_RENDEZVOUS_URL  wss://<host>/ws (rendezvous signaling)\n  \
                     RMD_TOKEN           this device's bearer token\n  \
                     RMD_NAME            device name (default: hostname)\n  \
                     RMD_CODEC           h264 (default) | av1\n  \
                     RMD_ICE             STUN/TURN URL(s)\n\n\
                     Run with no args after setting the env to start the host.",
                    env!("CARGO_PKG_VERSION")
                );
                return Ok(());
            }
            _ => {}
        }
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cfg = HostConfig {
        display_index: env_or("RMD_DISPLAY", 0),
        width: env_or("RMD_WIDTH", 1920),
        height: env_or("RMD_HEIGHT", 1080),
        fps: env_or("RMD_FPS", 30),
        bitrate_bps: env_or("RMD_BITRATE", 8_000_000),
        device_name: std::env::var("RMD_NAME").unwrap_or_else(|_| {
            std::env::var("HOSTNAME").unwrap_or_else(|_| "rmd-host".to_string())
        }),
        ice_servers: ice_servers(),
        bind_addr: std::env::var("RMD_BIND").unwrap_or_else(|_| "0.0.0.0:0".to_string()),
        enable_audio: std::env::var("RMD_AUDIO").is_ok(),
        video_codec: video_codec_from_env(),
        // Unattended access is enforced when explicitly requested or when an
        // authorized-keys list is present.
        require_authorization: std::env::var("RMD_REQUIRE_AUTH").is_ok()
            || !authorized_device_ids().is_empty(),
        authorized_device_ids: authorized_device_ids(),
        // The host's own identity, presented (DTLS-bound) to viewers so they can
        // authenticate this endpoint. Persisted under the config dir.
        identity: load_host_identity(),
    };

    tracing::info!(
        display = cfg.display_index,
        res = format!("{}x{}@{}", cfg.width, cfg.height, cfg.fps),
        "starting ReachMyDevice host"
    );
    // The host is the offerer; it learns the viewer's id from the rendezvous hello.
    let signaling = build_signaling(None)?;

    // Desktop tray companion when built with `--features tray` and requested via
    // `RMD_TRAY=1`; otherwise run headless (the default, and the only
    // option on servers without a display).
    #[cfg(feature = "tray")]
    if std::env::var("RMD_TRAY").is_ok() {
        return tray::run_with_tray(cfg, signaling);
    }

    run_host(cfg, signaling)
}
