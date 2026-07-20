//! ReachMyDevice host agent (spike).
//!
//! Headless: captures the screen, encodes H.264, streams it over WebRTC, and
//! injects the viewer's input. Configured via environment variables:
//!
//! | env | default | meaning |
//! |-----|---------|---------|
//! | `RMD_DISPLAY`     | `0`         | display index to capture |
//! | `RMD_WIDTH/HEIGHT/FPS/BITRATE` | 1920/1080/30/8000000 | encode params (also `rmdd set width/height/fps/bitrate <v>`, which wins over the env) |
//! | `RMD_NAME`        | hostname    | this device's name |
//! | `RMD_ICE`         | (none)      | comma-separated STUN/TURN URLs |
//! | `RMD_RENDEZVOUS_URL` | (none)   | `wss://host/ws` — use rendezvous if set |
//! | `RMD_TOKEN`       | (none)      | device bearer token (rendezvous mode) |
//! | `RMD_SIGNAL_ADDR` | `127.0.0.1:9000` | LAN signal-dev relay (fallback) |
//!
//! Requires **Screen Recording** (capture) and **Accessibility** (input)
//! permissions on macOS — see `docs/macos-permissions.md`.

use rmd_session::rendezvous::RendezvousClient;
use rmd_session::{HostConfig, HostStatus, SignalClient, Signaling, run_host_reporting};
use rmd_transport::IceServer;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

mod service;

#[cfg(feature = "tray")]
mod tray;

fn env_or<T: std::str::FromStr>(key: &str, default: T) -> T {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Resolve a tunable in precedence order: the encrypted settings store
/// (`rmdd set <skey> …`) first, then the `RMD_*` env var, then the built-in
/// default. Lets video params be persisted per-host without an env var.
fn setting_or_env_or<T: std::str::FromStr>(
    settings: Option<&rmd_session::settings::SettingsStore>,
    skey: &str,
    env_key: &str,
    default: T,
) -> T {
    settings
        .and_then(|s| s.get(skey))
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| env_or(env_key, default))
}

/// Assemble the host's ICE servers: any manual `RMD_ICE` URLs first, then the
/// STUN/TURN servers the rendezvous mints for this device (`/api/ice`) when in
/// rendezvous mode. A fetch failure is logged and skipped — the session still
/// runs, just without a relay (so cross-NAT viewers may not connect).
fn ice_servers(rendezvous_url: Option<&str>, token: Option<&str>) -> Vec<IceServer> {
    let mut servers: Vec<IceServer> = std::env::var("RMD_ICE")
        .map(|s| {
            s.split(',')
                .map(|x| x.trim())
                .filter(|x| !x.is_empty())
                .map(|u| IceServer::urls(vec![u.to_string()]))
                .collect()
        })
        .unwrap_or_default();

    if let (Some(url), Some(tok)) = (rendezvous_url, token) {
        let base = rmd_session::account::rest_base_from_ws(url);
        match rmd_session::AccountClient::new(&base).ice_servers(tok) {
            Ok(mut fetched) if !fetched.is_empty() => {
                tracing::info!(count = fetched.len(), "fetched ICE servers from rendezvous");
                servers.append(&mut fetched);
            }
            Ok(_) => {}
            Err(e) => tracing::warn!(
                error = %e,
                "could not fetch ICE servers from rendezvous; continuing without a relay"
            ),
        }
    }
    servers
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
fn identity_path() -> std::path::PathBuf {
    let home = std::env::var("HOME").unwrap_or_default();
    std::path::PathBuf::from(home).join(".config/rmd/identity.key")
}

fn load_host_identity() -> Option<std::sync::Arc<rmd_session::DeviceIdentity>> {
    match rmd_session::DeviceIdentity::load_or_create(&identity_path()) {
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

/// Read the device bearer token. Preference order: the encrypted settings store
/// (`rmdd set token …`), then a `0600` file (`RMD_TOKEN_FILE` or
/// `~/.config/rmd/token`), then `RMD_TOKEN` env (which leaks via `ps e` /
/// `/proc/<pid>/environ`, so it warns).
fn read_token(
    settings: Option<&rmd_session::settings::SettingsStore>,
) -> anyhow::Result<zeroize::Zeroizing<String>> {
    if let Some(tok) = settings
        .and_then(|s| s.get(rmd_session::settings::KEY_TOKEN))
        .filter(|t| !t.is_empty())
    {
        return Ok(zeroize::Zeroizing::new(tok.to_string()));
    }
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

/// Log a clear "not set up yet" message and block forever. A supervised daemon
/// missing its config must not *exit* — an exit restart-loops under systemd/launchd.
/// Instead it parks here (no busy loop) until the service is stopped (SIGTERM),
/// then dies cleanly. The user configures it with `rmdd set …` then `rmdd restart`.
fn park_unconfigured(reason: &str) -> ! {
    tracing::warn!(
        "rmdd is not set up ({reason}). Configure it, then (re)start the service:\n  \
         rmdd set rendezvous_url wss://<your-rendezvous>/ws\n  \
         rmdd set token <device-token>\n  \
         rmdd set password <connection-password>    # optional but recommended\n  \
         rmdd restart\n\
         Idling — won't auto-exit, so the service won't restart-loop. Stop the service to exit."
    );
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}

/// Handle the `rmdd set|unset|list` settings subcommands. These load (or
/// first-run create) the device identity, open the encrypted settings store, and
/// mutate it — then exit without starting a session. `list` prints keys only,
/// never values.
fn run_settings_command(args: &[String]) -> anyhow::Result<()> {
    use rmd_session::settings::SettingsStore;
    let id = rmd_session::DeviceIdentity::load_or_create(&identity_path())?;
    let path = SettingsStore::default_path();
    let mut store = SettingsStore::load(&id, &path)?;
    match args[0].as_str() {
        "set" => {
            let key = args
                .get(1)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| anyhow::anyhow!("usage: rmdd set <key> <value>"))?;
            let value = args
                .get(2)
                .ok_or_else(|| anyhow::anyhow!("usage: rmdd set <key> <value>"))?;
            store.set(key.clone(), value.clone());
            store.save(&id, &path)?;
            println!("set '{key}' ({})", path.display());
        }
        "unset" => {
            let key = args
                .get(1)
                .ok_or_else(|| anyhow::anyhow!("usage: rmdd unset <key>"))?;
            if store.remove(key) {
                store.save(&id, &path)?;
                println!("unset '{key}'");
            } else {
                println!("no such setting: '{key}'");
            }
        }
        "list" => {
            let keys: Vec<&str> = store.keys().collect();
            if keys.is_empty() {
                println!("(no settings stored)");
            } else {
                println!("settings ({}):", path.display());
                for k in keys {
                    println!("  {k}");
                }
            }
        }
        other => anyhow::bail!("unknown subcommand '{other}' (expected set | unset | list)"),
    }
    Ok(())
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
fn build_signaling(
    peer: Option<String>,
    rendezvous_url: Option<&str>,
    token: Option<&str>,
    session_active: Arc<AtomicBool>,
) -> anyhow::Result<Box<dyn Signaling>> {
    if let Some(url) = rendezvous_url {
        let token =
            token.ok_or_else(|| anyhow::anyhow!("rendezvous mode requires a device token"))?;
        tracing::info!(%url, "signaling via rendezvous");
        // Pass the session-active flag so the rendezvous client's watchdog can
        // safely restart the (host) process if its DNS resolver wedges, without
        // tearing down a live peer-to-peer session.
        Ok(Box::new(RendezvousClient::connect(
            url,
            token,
            peer,
            Some(session_active),
        )?))
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
                     Commands:\n  \
                     rmdd                 start the host\n  \
                     rmdd set <k> <v>     store a secret setting (encrypted at rest)\n  \
                     rmdd unset <k>       remove a setting\n  \
                     rmdd list            list setting keys (values never printed)\n\n\
                     Daemon (background service — systemd --user / launchd):\n  \
                     rmdd enable          install + enable autostart, start it\n  \
                     rmdd disable         disable autostart\n  \
                     rmdd status          show service status\n  \
                     rmdd start           start the service (no-op if running)\n  \
                     rmdd stop            stop the service\n  \
                     rmdd restart         restart the service\n  \
                     rmdd log [-f]        show the service log (-f to follow)\n\n\
                     Settings (via `rmdd set`):\n  \
                     rendezvous_url  wss://<host>/ws — enables rendezvous mode\n  \
                     token           device bearer token (rendezvous mode)\n  \
                     password        connection password a viewer must enter\n\n\
                     Env (override the store):\n  \
                     RMD_RENDEZVOUS_URL  wss://<host>/ws (rendezvous signaling)\n  \
                     RMD_NAME            device name (default: hostname)\n  \
                     RMD_CODEC           h264 (default) | av1\n  \
                     RMD_ICE             STUN/TURN URL(s)\n\n\
                     Note: `set <k> <v>` takes the value inline, so it can appear in \
                     shell history; clear it or use a subshell if that matters.",
                    env!("CARGO_PKG_VERSION")
                );
                return Ok(());
            }
            _ => {}
        }
    }

    // Settings subcommands (`rmdd set|unset|list …`) run and exit before any
    // session setup, like the flags above.
    let args: Vec<String> = std::env::args().skip(1).collect();
    if matches!(
        args.first().map(String::as_str),
        Some("set") | Some("unset") | Some("list")
    ) {
        return run_settings_command(&args);
    }
    // Daemon management (`rmdd enable|disable|status|start|stop|restart`) — routes
    // to the platform init system (systemd --user / launchd). Runs and exits.
    if matches!(
        args.first().map(String::as_str),
        Some("enable")
            | Some("disable")
            | Some("status")
            | Some("start")
            | Some("stop")
            | Some("restart")
            | Some("log")
    ) {
        return service::run_command(&args);
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    // Load the device identity once, then open the encrypted settings store with
    // it (both the host-identity presentation and the settings share the identity).
    let identity = load_host_identity();
    let settings =
        identity.as_ref().and_then(|id| {
            match rmd_session::settings::SettingsStore::load(
                id.as_ref(),
                &rmd_session::settings::SettingsStore::default_path(),
            ) {
                Ok(s) => Some(s),
                Err(e) => {
                    tracing::warn!(error = %e, "could not open settings store; ignoring it");
                    None
                }
            }
        });

    // Read the rendezvous URL + device token once; both the ICE-server fetch and
    // the signaling client use them. URL + token come from the settings store
    // first (`rmdd set rendezvous_url … / set token …`), then env, so a bare
    // `rmdd` works once configured.
    let rendezvous_url = settings
        .as_ref()
        .and_then(|s| s.get(rmd_session::settings::KEY_RENDEZVOUS_URL))
        .filter(|u| !u.is_empty())
        .map(str::to_string)
        .or_else(|| std::env::var("RMD_RENDEZVOUS_URL").ok());
    // Whether we're actually configured to serve. A supervised daemon that isn't
    // set up must NOT exit (that restart-loops under systemd/launchd) — it parks and
    // waits to be stopped. Configured = a rendezvous URL + a readable token, OR an
    // explicit LAN relay (`RMD_SIGNAL_ADDR`) for the dev flow.
    let lan_dev = std::env::var("RMD_SIGNAL_ADDR").is_ok();
    let token = match &rendezvous_url {
        Some(_) => match read_token(settings.as_ref()) {
            Ok(t) => Some(t),
            Err(_) => park_unconfigured("a rendezvous URL is set but no device token"),
        },
        None if lan_dev => None,
        None => park_unconfigured("no rendezvous URL or device token configured"),
    };
    let token_str = token.as_deref().map(|z| z.as_str());

    // Optional connection password (RealVNC-style). From the settings store only.
    let connect_password = settings
        .as_ref()
        .and_then(|s| s.get(rmd_session::settings::KEY_PASSWORD))
        .filter(|p| !p.is_empty())
        .map(str::to_string);
    if connect_password.is_some() {
        tracing::info!("connection password required for this host");
    }

    use rmd_session::settings as sset;
    let sref = settings.as_ref();
    let cfg = HostConfig {
        display_index: env_or("RMD_DISPLAY", 0),
        width: setting_or_env_or(sref, sset::KEY_WIDTH, "RMD_WIDTH", 1920),
        height: setting_or_env_or(sref, sset::KEY_HEIGHT, "RMD_HEIGHT", 1080),
        fps: setting_or_env_or(sref, sset::KEY_FPS, "RMD_FPS", 30),
        bitrate_bps: setting_or_env_or(sref, sset::KEY_BITRATE, "RMD_BITRATE", 8_000_000),
        device_name: std::env::var("RMD_NAME").unwrap_or_else(|_| {
            std::env::var("HOSTNAME").unwrap_or_else(|_| "rmd-host".to_string())
        }),
        ice_servers: ice_servers(rendezvous_url.as_deref(), token_str),
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
        identity,
        connect_password,
    };

    tracing::info!(
        display = cfg.display_index,
        res = format!("{}x{}@{}", cfg.width, cfg.height, cfg.fps),
        "starting ReachMyDevice host"
    );
    // Whether a viewer session is currently active — watched by the rendezvous
    // client so its wedged-resolver watchdog never restarts us mid-session.
    let session_active = Arc::new(AtomicBool::new(false));

    // The host is the offerer; it learns the viewer's id from the rendezvous hello.
    let signaling = build_signaling(
        None,
        rendezvous_url.as_deref(),
        token_str,
        session_active.clone(),
    )?;

    // Desktop tray companion when built with `--features tray` and requested via
    // `RMD_TRAY=1`; otherwise run headless (the default, and the only
    // option on servers without a display).
    #[cfg(feature = "tray")]
    if std::env::var("RMD_TRAY").is_ok() {
        return tray::run_with_tray(cfg, signaling);
    }

    run_host_reporting(cfg, signaling, move |s| {
        session_active.store(matches!(s, HostStatus::Active), Ordering::Relaxed);
    })
}
