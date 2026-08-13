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
use std::time::{Duration, Instant};

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
/// rendezvous mode.
///
/// The relay candidate is allocated from these **once** at transport startup and
/// reused for the process's lifetime, so a fetch that fails here leaves the host
/// relay-less until it is restarted — cross-NAT viewers then can't connect at all.
/// A transient blip at startup is common (a reboot racing the rendezvous, a
/// briefly-wedged macOS resolver, a Cloudflare 5xx), so we **retry with backoff**
/// for a bounded window (`RMD_ICE_FETCH_MAX_WAIT` seconds, default 120) before
/// falling back to a relay-less start. A 401 (an expired token) is re-minted in
/// place via the identity-key refresher and the fetch retried once.
fn ice_servers(
    rendezvous_url: Option<&str>,
    token: Option<&str>,
    refresher: Option<&rmd_session::rendezvous::TokenRefresher>,
) -> (Vec<IceServer>, Option<String>) {
    let mut servers: Vec<IceServer> = std::env::var("RMD_ICE")
        .map(|s| {
            s.split(',')
                .map(|x| x.trim())
                .filter(|x| !x.is_empty())
                .map(|u| IceServer::urls(vec![u.to_string()]))
                .collect()
        })
        .unwrap_or_default();

    let mut refreshed_token = None;
    if let (Some(url), Some(tok)) = (rendezvous_url, token) {
        let base = rmd_session::account::rest_base_from_ws(url);
        let client = rmd_session::AccountClient::new(&base);
        // The token we authenticate with; may be re-minted once on a 401 mid-loop.
        let mut auth = tok.to_string();
        let deadline = Instant::now() + Duration::from_secs(env_or("RMD_ICE_FETCH_MAX_WAIT", 120));
        let mut backoff = Duration::from_secs(1);
        loop {
            let mut fetched = client.ice_servers(&auth);
            // If the token was rejected (401), re-mint it via the identity key and
            // retry so the relay works even when the token expired before boot. Only
            // once — a second 401 means the fresh token is bad too, so don't spin.
            if is_http_unauthorized(&fetched) && refreshed_token.is_none() {
                if let Some(new_token) = refresher.and_then(|r| r()) {
                    tracing::info!("ICE fetch got 401; refreshed token and retrying");
                    fetched = client.ice_servers(&new_token);
                    auth = new_token.clone();
                    refreshed_token = Some(new_token);
                }
            }
            match fetched {
                Ok(mut list) if !list.is_empty() => {
                    tracing::info!(count = list.len(), "fetched ICE servers from rendezvous");
                    servers.append(&mut list);
                    break;
                }
                // The deployment advertises no ICE servers — a valid answer, not a
                // failure; don't spin retrying it.
                Ok(_) => break,
                Err(e) => {
                    if Instant::now() >= deadline {
                        tracing::warn!(
                            error = %e,
                            "could not fetch ICE servers from rendezvous after retries; \
                             continuing without a relay (cross-NAT viewers may not connect)"
                        );
                        break;
                    }
                    tracing::warn!(error = %e, "ICE server fetch failed; retrying in {backoff:?}");
                    std::thread::sleep(backoff);
                    backoff = (backoff * 2).min(Duration::from_secs(15));
                }
            }
        }
    }
    (servers, refreshed_token)
}

/// Whether an account-client result is an HTTP 401 (token rejected). The client
/// surfaces status codes in the error text (see `account::run`), so match on that.
fn is_http_unauthorized<T>(result: &anyhow::Result<T>) -> bool {
    result
        .as_ref()
        .err()
        .is_some_and(|e| e.to_string().contains("HTTP 401"))
}

/// Current wall-clock time in unix seconds (for signing a token-refresh request).
fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Re-mint the device bearer token via a key-authenticated refresh and persist it
/// to the encrypted settings store (under the load-modify-save lock). Returns the
/// fresh token, or `None` on failure. Used by both the ICE fetch and the
/// rendezvous client's 401 hook.
fn refresh_and_persist_token(
    rest_base: &str,
    identity: &rmd_session::DeviceIdentity,
) -> Option<String> {
    let new = match rmd_session::AccountClient::new(rest_base).refresh_token(identity, now_unix()) {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(error = %e, "device token refresh failed");
            return None;
        }
    };
    // Persist to the encrypted settings store (best-effort) so restarts and the
    // ICE fetch pick up the new token too.
    let path = rmd_session::settings::SettingsStore::default_path();
    match rmd_session::settings::lock(&path) {
        Ok(_lock) => match rmd_session::settings::SettingsStore::load(identity, &path) {
            Ok(mut store) => {
                store.set(rmd_session::settings::KEY_TOKEN, new.clone());
                if let Err(e) = store.save(identity, &path) {
                    tracing::warn!(error = %e, "could not persist refreshed token");
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "could not open settings to persist refreshed token")
            }
        },
        Err(e) => tracing::warn!(error = %e, "could not lock settings to persist refreshed token"),
    }
    tracing::info!("re-minted device bearer token via identity-key refresh");
    Some(new)
}

/// The earliest coturn credential expiry (unix seconds) across the credentialed
/// TURN servers, if any. The rendezvous mints ephemeral coturn creds whose
/// username is `<expiry>:<id>` (see `rmd_transport::IceServer` docs), so the leading
/// field is the expiry. `None` when there's no credentialed TURN server (STUN-only
/// or a manual `RMD_ICE` list) or the format isn't recognised.
fn earliest_turn_expiry(servers: &[IceServer]) -> Option<u64> {
    servers
        .iter()
        .filter(|s| s.urls.iter().any(|u| u.starts_with("turn:")))
        .filter_map(|s| s.username.as_deref())
        .filter_map(|u| u.split(':').next()?.parse::<u64>().ok())
        .min()
}

/// Keep the host's TURN relay credential fresh. rmdd allocates its relay candidate
/// **once** at startup and never refreshes it, so a host up longer than the
/// credential's lifetime (`RMD_TURN_TTL` on the server) silently loses its relay:
/// it stays connected but cross-NAT viewers can no longer reach it. Rather than
/// re-allocate on the live media path, we restart the process **in place** shortly
/// before the credential expires — a fresh start re-fetches ICE and re-allocates —
/// and only while **no session is active**, so an in-progress connection is never
/// interrupted. Reuses the same supervised-relaunch path as the DNS watchdog. A
/// no-op when there's no credentialed TURN server (LAN/dev, STUN-only).
fn spawn_turn_refresh(servers: &[IceServer], session_active: Arc<AtomicBool>) {
    /// Restart this long before the credential lapses (leaves margin to reconnect).
    const LEAD: u64 = 300;
    /// Refuse to schedule a refresh nearer than this — guards against a mis-parsed
    /// or already-expired timestamp turning into a restart loop.
    const MIN_LEAD: u64 = 600;

    let Some(expiry) = earliest_turn_expiry(servers) else {
        return;
    };
    let now = now_unix().max(0) as u64;
    if expiry <= now + MIN_LEAD {
        tracing::warn!(
            expiry,
            now,
            "TURN credential expiry too soon or unrecognised; not scheduling a refresh"
        );
        return;
    }
    tracing::info!(
        expiry,
        in_secs = expiry.saturating_sub(now),
        "scheduling TURN credential refresh before expiry"
    );
    std::thread::spawn(move || {
        loop {
            let now = now_unix().max(0) as u64;
            let refresh_at = expiry.saturating_sub(LEAD);
            if now < refresh_at {
                // Nap until refresh time, capped so we re-check periodically.
                std::thread::sleep(Duration::from_secs((refresh_at - now).min(3600)));
                continue;
            }
            // Past refresh time: wait for an idle moment, then restart for fresh creds.
            if session_active.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_secs(30));
                continue;
            }
            tracing::info!(
                expiry,
                "refreshing TURN credential before it expires — restarting host in place"
            );
            rmd_session::rendezvous::restart_in_place();
        }
    });
}

/// Load authorized viewer `device_id`s for unattended access. Reads
/// `RMD_AUTHORIZED_KEYS` (or `~/.config/rmd/authorized_keys`): one
/// device_id per line, `#` comments and blanks ignored.
fn authorized_device_ids() -> Vec<String> {
    let path = std::env::var("RMD_AUTHORIZED_KEYS")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| rmd_session::settings::config_dir().join("authorized_keys"));
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
    rmd_session::settings::config_dir().join("identity.key")
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
        .unwrap_or_else(|_| rmd_session::settings::config_dir().join("token"));
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

/// Refuse to run an internet-reachable host that has no access control at all.
/// Like [`park_unconfigured`], this parks instead of exiting so a supervised
/// daemon doesn't restart-loop; the operator fixes it by setting a credential
/// (or opting into an open relay) and restarting.
fn park_open_relay() -> ! {
    tracing::error!(
        "refusing to serve: this host is reachable through a rendezvous but has no \
         access control (no connect password, no authorized-keys, RMD_REQUIRE_AUTH \
         unset). Anyone who learns its device_id could take full control. Set one of:\n  \
         rmdd set password <connection-password>       # RealVNC-style password\n  \
         echo <viewer-device-id> >> ~/.config/rmd/authorized_keys   # allowlist\n  \
         RMD_REQUIRE_AUTH=1                             # require an authorized identity\n\
         Or set RMD_ALLOW_OPEN_RELAY=1 to intentionally run an open host, then restart.\n\
         Idling — won't auto-exit, so the service won't restart-loop. Stop the service to exit."
    );
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}

/// Whether a host must fail closed (park) because it is an open relay: reachable
/// through a rendezvous with no access control and no explicit opt-in. Kept as a
/// pure predicate (env/IO resolved by the caller) so the exact fail-closed rule is
/// pinned by a regression test — mirrors `session::host::authorization_permits` /
/// `verify_connect_password`. `require_authorization` already folds in
/// `RMD_REQUIRE_AUTH` and a non-empty authorized-keys list.
fn should_park_open_relay(
    has_rendezvous: bool,
    require_authorization: bool,
    has_connect_password: bool,
    allow_open_relay: bool,
) -> bool {
    has_rendezvous && !require_authorization && !has_connect_password && !allow_open_relay
}

/// Handle the `rmdd set|unset|list` settings subcommands. These load (or
/// first-run create) the device identity, open the encrypted settings store, and
/// mutate it — then exit without starting a session. `list` prints keys only,
/// never values.
fn run_settings_command(args: &[String]) -> anyhow::Result<()> {
    use rmd_session::settings::SettingsStore;
    let id = rmd_session::DeviceIdentity::load_or_create(&identity_path())?;
    let path = SettingsStore::default_path();
    // Hold the settings lock across load-modify-save so this can't race the
    // running host's automatic restore-token refresh (M4).
    let _lock = rmd_session::settings::lock(&path)?;
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

/// `rmdd setup-input`: grant the daemon access to `/dev/uinput` so it can inject
/// native keyboard/mouse (works on X11 and every Wayland compositor, no per-app
/// consent prompt). This is the one step that needs root, done via `sudo` here so
/// the daemon itself stays unprivileged. Idempotent.
#[cfg(target_os = "linux")]
fn run_setup_input() -> anyhow::Result<()> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    const RULE_PATH: &str = "/etc/udev/rules.d/60-rmd-uinput.rules";
    const RULE: &str = "# Installed by `rmdd setup-input`. Lets the active-session user open\n\
        # /dev/uinput so rmdd can inject remote keyboard/mouse (native, no prompt).\n\
        KERNEL==\"uinput\", SUBSYSTEM==\"misc\", TAG+=\"uaccess\", GROUP=\"input\", MODE=\"0660\", OPTIONS+=\"static_node=uinput\"\n";

    let writable = || std::fs::OpenOptions::new().write(true).open("/dev/uinput").is_ok();
    if writable() {
        println!("/dev/uinput is already accessible — native input is ready.");
        return Ok(());
    }

    // Already set up on a prior run/install? The udev rule is world-readable, so
    // we detect this WITHOUT sudo — so repeat `setup-input` runs and installer
    // upgrades never re-prompt for a password (the rule just isn't live in this
    // session/boot yet).
    if std::path::Path::new(RULE_PATH).exists() {
        println!("Native input already set up (udev rule present) — no changes needed.");
        println!("If input isn't native yet, log out and back in, then:  rmdd restart");
        return Ok(());
    }

    println!("Setting up native input (uinput). This needs root once; sudo will");
    println!("prompt for your password.\n");

    // Install the udev rule (piped through `sudo tee`).
    let mut tee = Command::new("sudo")
        .args(["tee", RULE_PATH])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .map_err(|e| anyhow::anyhow!("run sudo (is it installed?): {e}"))?;
    tee.stdin
        .take()
        .expect("piped stdin")
        .write_all(RULE.as_bytes())?;
    if !tee.wait()?.success() {
        anyhow::bail!("failed to write {RULE_PATH}");
    }

    // Load the module now + on every boot, then reapply rules to the live node.
    let sudo = |a: &[&str]| -> anyhow::Result<()> {
        if !Command::new("sudo").args(a).status()?.success() {
            anyhow::bail!("`sudo {}` failed", a.join(" "));
        }
        Ok(())
    };
    sudo(&["modprobe", "uinput"])?;
    sudo(&["sh", "-c", "echo uinput > /etc/modules-load.d/rmd-uinput.conf"])?;
    // Add the user to the `input` group too, so /dev/uinput is openable even on a
    // headless/no-seat boot where logind's `uaccess` ACL grants no active session
    // (audit B5). Best-effort; takes effect on next login. The udev `uaccess` tag
    // covers the normal graphical-session case.
    if let Ok(user) = std::env::var("USER") {
        if !user.is_empty() && user != "root" {
            if let Err(e) = sudo(&["usermod", "-aG", "input", &user]) {
                tracing::warn!(error = %e, %user, "could not add user to `input` group (headless input may need it)");
            }
        }
    }
    sudo(&["udevadm", "control", "--reload-rules"])?;
    sudo(&["udevadm", "trigger", "/dev/uinput"])?;

    // logind applies the uaccess ACL a moment after the trigger, so poll briefly
    // before deciding — otherwise we'd falsely claim it isn't ready.
    let mut ok = false;
    for _ in 0..20 {
        if writable() {
            ok = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    if ok {
        println!("\n\u{2713} Native input configured — /dev/uinput is accessible now.");
        println!("  Apply it to the running host:  rmdd restart");
    } else {
        println!("\n\u{2713} udev rule installed; it takes effect on your next login or reboot.");
        println!("  Try now:  rmdd restart  (the host will use native input if it can open /dev/uinput,");
        println!("  otherwise it falls back to X11 XTest). If it stays on the fallback, log out and back in.");
    }
    Ok(())
}

// On non-Linux, `setup-input` is a silent no-op — native input needs no such
// setup on macOS (CGEvent) or the future Windows backend, so the verb is
// intentionally undocumented and produces no output there.
#[cfg(not(target_os = "linux"))]
fn run_setup_input() -> anyhow::Result<()> {
    Ok(())
}

/// `rmdd setup-linux [input|display]`: one-time machine setup for headless remote
/// access. With no target it does both. `input` arms native uinput input;
/// `display` makes a monitor connector survive an unplug (or arms a headless
/// virtual display when nothing is attached). Root steps go through `sudo` so the
/// daemon stays unprivileged. The old `setup-input` verb maps here (input only).
#[cfg(target_os = "linux")]
fn run_setup_linux(args: &[String]) -> anyhow::Result<()> {
    let verb = args.first().map(String::as_str).unwrap_or("setup-linux");
    let sub = args.get(1).map(String::as_str);
    let (do_input, do_display, do_system) = match (verb, sub) {
        // Hidden back-compat alias: `setup-input` == input only.
        ("setup-input", _) => (true, false, false),
        (_, None) | (_, Some("both") | Some("all")) => (true, true, false),
        (_, Some("input")) => (true, false, false),
        (_, Some("display")) => (false, true, false),
        (_, Some("system")) => (false, false, true),
        (_, Some(other)) => anyhow::bail!(
            "unknown setup-linux target '{other}' \
             (expected: input | display | system, or omit for input+display)"
        ),
    };
    // System mode installs the broker/agent split (remote login-screen access). It
    // needs the same machine-level uinput enablement as `input`, plus the system
    // user, state dir, and units, so run the input half first.
    if do_system {
        run_setup_input()?;
        println!();
        return run_setup_system();
    }
    if do_input {
        run_setup_input()?;
    }
    if do_display {
        if do_input {
            println!();
        }
        run_setup_display()?;
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn run_setup_linux(_args: &[String]) -> anyhow::Result<()> {
    Ok(())
}

/// `setup-linux system`: install the broker/agent split for remote login-screen
/// access + seamless greeter→user handover. Creates the dedicated non-root `rmd`
/// user, the `/var/lib/rmd` state dir (migrating this user's device identity into
/// it), and the broker (system) + agent (global user) units. Never auto-starts or
/// reboots — prints next steps, matching `setup-linux display`.
#[cfg(target_os = "linux")]
fn run_setup_system() -> anyhow::Result<()> {
    let exe = std::env::current_exe()
        .map_err(|e| anyhow::anyhow!("cannot resolve rmdd path: {e}"))?;
    let exe = exe.to_string_lossy().to_string();
    let user = std::env::var("USER").unwrap_or_default();

    println!("Setting up ReachMyDevice system mode (broker + per-session agent)…\n");

    // 1. Dedicated non-root system user + group; `input` group for /dev/uinput.
    sudo_run(&[
        "sh",
        "-c",
        "getent group rmd >/dev/null 2>&1 || groupadd --system rmd",
    ])?;
    sudo_run(&[
        "sh",
        "-c",
        "id -u rmd >/dev/null 2>&1 || useradd --system --no-create-home \
         --shell /usr/sbin/nologin -g rmd -G input -c 'ReachMyDevice broker' rmd",
    ])?;
    sudo_run(&["usermod", "-aG", "input", "rmd"])?;

    // 2. State + config dirs, owned by rmd, not world-readable.
    sudo_run(&["mkdir", "-p", "/var/lib/rmd", "/etc/rmd"])?;
    sudo_run(&["chown", "rmd:rmd", "/var/lib/rmd", "/etc/rmd"])?;
    sudo_run(&["chmod", "0700", "/var/lib/rmd", "/etc/rmd"])?;

    // 3. Migrate this user's device identity/token so the broker keeps the same
    //    device (no re-enrollment). key.env (passphrase) goes to /etc/rmd, read by
    //    the broker unit's EnvironmentFile.
    let cfg = rmd_session::settings::config_dir();
    let migrate = |name: &str, dest_dir: &str| -> anyhow::Result<()> {
        let src = cfg.join(name);
        if src.exists() {
            let bytes = std::fs::read(&src)?;
            let dest = format!("{dest_dir}/{name}");
            sudo_write_file(&dest, &bytes)?;
            sudo_run(&["chown", "rmd:rmd", &dest])?;
            sudo_run(&["chmod", "0600", &dest])?;
            println!("  migrated {name} -> {dest}");
        }
        Ok(())
    };
    for f in ["identity.key", "settings.enc", "token", "authorized_keys"] {
        migrate(f, "/var/lib/rmd")?;
    }
    migrate("key.env", "/etc/rmd")?;

    // 4. Broker system unit (dedicated user; uinput via the `input` supplementary
    //    group; /run/rmd for the agent socket).
    let broker_unit = format!(
        "# Generated by `rmdd setup-linux system`.\n\
         [Unit]\n\
         Description=ReachMyDevice broker (system remote-desktop endpoint)\n\
         After=network-online.target\n\
         Wants=network-online.target\n\n\
         [Service]\n\
         Type=simple\n\
         User=rmd\n\
         Group=rmd\n\
         SupplementaryGroups=input\n\
         Environment=RMD_STATE_DIR=/var/lib/rmd\n\
         EnvironmentFile=-/etc/rmd/key.env\n\
         ExecStart={exe} broker\n\
         Restart=always\n\
         RestartSec=3\n\
         TimeoutStopSec=5\n\
         RuntimeDirectory=rmd\n\
         RuntimeDirectoryMode=0755\n\
         NoNewPrivileges=true\n\
         ProtectSystem=strict\n\
         ProtectHome=true\n\
         ReadWritePaths=/var/lib/rmd\n\
         PrivateTmp=true\n\n\
         [Install]\n\
         WantedBy=graphical.target\n"
    );
    sudo_write_file("/etc/systemd/system/rmd-broker.service", broker_unit.as_bytes())?;

    // 5. Agent unit — a *system-wide user unit* (/etc/systemd/user), so it runs in
    //    EVERY graphical session: the gdm greeter (login screen) and, after login,
    //    the user's session. Bound to graphical-session.target so it inherits each
    //    session's environment and auto-detects the right capture backend.
    let agent_unit = format!(
        "# Generated by `rmdd setup-linux system`.\n\
         [Unit]\n\
         Description=ReachMyDevice capture agent (per-session screen source)\n\
         After=graphical-session.target\n\
         PartOf=graphical-session.target\n\n\
         [Service]\n\
         Type=simple\n\
         ExecStart={exe} agent\n\
         Restart=always\n\
         RestartSec=3\n\
         TimeoutStopSec=5\n\n\
         [Install]\n\
         WantedBy=graphical-session.target\n"
    );
    sudo_write_file("/etc/systemd/user/rmd-agent.service", agent_unit.as_bytes())?;

    // 6. Group membership so the greeter (gdm) and this user can reach the broker
    //    socket under /run/rmd (group rmd). Effective on next session start.
    sudo_run(&[
        "sh",
        "-c",
        "id -u gdm >/dev/null 2>&1 && usermod -aG rmd gdm || true",
    ])?;
    if !user.is_empty() && user != "root" {
        sudo_run(&["usermod", "-aG", "rmd", &user])?;
    }

    // 7. Reload + enable (do NOT start: starting now would race the still-running
    //    per-user service for the same device token, and the group changes need a
    //    fresh session anyway).
    sudo_run(&["systemctl", "daemon-reload"])?;
    sudo_run(&["systemctl", "enable", "rmd-broker.service"])?;
    sudo_run(&["systemctl", "--global", "enable", "rmd-agent.service"])?;

    println!("\n✓ System mode installed (broker + agent units enabled, not started).");
    println!("Next steps — verify remote access still works, THEN:");
    println!("  1. Stop the per-user host so it doesn't fight the broker for the device:");
    println!("       rmdd disable");
    println!("  2. Reboot so the greeter + your session pick up the `rmd` group:");
    println!("       sudo reboot");
    println!("  After reboot the broker runs at boot and you can reach the LOGIN SCREEN remotely.");
    Ok(())
}

/// A connected physical display connector discovered under `/sys/class/drm`.
#[cfg(target_os = "linux")]
struct DrmConnector {
    /// sysfs entry name, e.g. `card1-HDMI-A-2`.
    sysfs: String,
    /// kernel connector name for `video=`/`drm.edid_firmware=`, e.g. `HDMI-A-2`.
    name: String,
}

/// Run a command via sudo, bailing with a clear message if it fails.
#[cfg(target_os = "linux")]
fn sudo_run(args: &[&str]) -> anyhow::Result<()> {
    use std::process::Command;
    if !Command::new("sudo").args(args).status()?.success() {
        anyhow::bail!("`sudo {}` failed", args.join(" "));
    }
    Ok(())
}

/// Write `contents` to a root-owned `dest` via `sudo tee` (dir created first).
#[cfg(target_os = "linux")]
fn sudo_write_file(dest: &str, contents: &[u8]) -> anyhow::Result<()> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    if let Some(parent) = std::path::Path::new(dest).parent() {
        sudo_run(&["mkdir", "-p", &parent.to_string_lossy()])?;
    }
    let mut tee = Command::new("sudo")
        .args(["tee", dest])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .map_err(|e| anyhow::anyhow!("run sudo (is it installed?): {e}"))?;
    tee.stdin.take().expect("piped stdin").write_all(contents)?;
    if !tee.wait()?.success() {
        anyhow::bail!("failed to write {dest}");
    }
    Ok(())
}

/// `rmdd setup-linux display`: make the desktop survive a monitor unplug.
///
/// Mechanism (validated live; see the project memory): force the real connector
/// to always report connected with its captured EDID, so the compositor keeps
/// allocating a framebuffer at the native mode whether or not the panel is
/// physically attached. That means: capture the connector's EDID into
/// `/lib/firmware/edid/`, and add `drm.edid_firmware=<conn>:…` + `video=<conn>:…e`
/// kernel parameters (persisted in the bootloader). With no display attached at
/// all, arm a VKMS virtual display instead. Never reboots — prints instructions.
#[cfg(target_os = "linux")]
fn run_setup_display() -> anyhow::Result<()> {
    use std::path::Path;
    println!("Setting up display persistence (keep the desktop alive across a monitor unplug).");

    // 1. Enumerate DRM connectors; classify connected physical outputs.
    let drm = Path::new("/sys/class/drm");
    let mut connected: Vec<DrmConnector> = Vec::new();
    let mut saw_any = false;
    if let Ok(rd) = std::fs::read_dir(drm) {
        for entry in rd.flatten() {
            let sysfs = entry.file_name().to_string_lossy().to_string();
            // Entries look like `card1-HDMI-A-2`; skip the card device nodes and
            // render nodes (`card1`, `renderD128`).
            let Some((card, conn)) = sysfs.split_once('-') else { continue };
            if !card.starts_with("card") {
                continue;
            }
            // Only real, forceable output types (skip Virtual/Writeback/etc.).
            let is_physical = ["HDMI", "DP", "eDP", "DVI", "VGA", "LVDS", "DSI"]
                .iter()
                .any(|p| conn.starts_with(p));
            if !is_physical {
                continue;
            }
            saw_any = true;
            let status = std::fs::read_to_string(entry.path().join("status")).unwrap_or_default();
            if status.trim() == "connected" {
                connected.push(DrmConnector { sysfs: sysfs.clone(), name: conn.to_string() });
            }
        }
    }

    if connected.is_empty() {
        if saw_any {
            println!("No physical display is currently connected.");
        } else {
            println!("No physical display connectors found (headless machine).");
        }
        println!("Arming a headless virtual display (VKMS) instead.\n");
        return setup_headless_vkms();
    }

    // Prefer an external output over a laptop panel (eDP/LVDS/DSI) when both are up.
    connected.sort_by_key(|c| {
        ["eDP", "LVDS", "DSI"].iter().any(|p| c.name.starts_with(p)) as u8
    });
    let target = &connected[0];
    println!("Target connector: {} ({})", target.name, target.sysfs);

    // 2. Native mode from the connector's `modes` file (first line = preferred).
    let modes = std::fs::read_to_string(drm.join(&target.sysfs).join("modes")).unwrap_or_default();
    let mode = modes
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("1920x1080")
        .to_string();
    // 3. Read the live EDID (world-readable in sysfs); it must be non-empty.
    let edid = std::fs::read(drm.join(&target.sysfs).join("edid")).unwrap_or_default();
    if edid.is_empty() {
        anyhow::bail!(
            "the connected display exposes no EDID ({}/edid is empty); can't persist it. \
             Try a different cable/port, or arm a virtual display: rmdd setup-linux display \
             with no monitor attached.",
            target.sysfs
        );
    }

    // 4. Install the EDID blob under /lib/firmware/edid (root-owned).
    let blob_rel = format!("edid/rmd-{}.bin", target.name.to_ascii_lowercase());
    let blob_abs = format!("/lib/firmware/{blob_rel}");
    println!("Capturing EDID ({} bytes) -> {blob_abs}", edid.len());
    sudo_write_file(&blob_abs, &edid)?;

    // 5. Kernel params: force the connector connected at its native mode, always
    //    reporting the captured EDID (`e` forces enabled regardless of hotplug).
    let params = vec![
        format!("drm.edid_firmware={}:{}", target.name, blob_rel),
        format!("video={}:{}@60e", target.name, mode),
    ];

    // 6. Persist to the bootloader (GRUB), or print the params for others.
    persist_kernel_params(&params)?;

    // 7. Early-KMS: if the DRM driver loads from the initramfs, the EDID blob must
    //    be inside it too — refresh the initramfs (best-effort).
    maybe_refresh_initramfs(&target.sysfs);

    println!("\n\u{2713} Display persistence armed for {}.", target.name);
    println!("  Params added: {}", params.join("  "));
    println!(
        "\n  IMPORTANT: this only takes effect after a REBOOT, and a bad display\n  \
         parameter can leave you without a local console. VERIFY REMOTE ACCESS WORKS\n  \
         FIRST (connect once, confirm you can get back in), THEN reboot on your own\n  \
         schedule. This tool never reboots for you."
    );
    Ok(())
}

/// Add `params` to `GRUB_CMDLINE_LINUX_DEFAULT` in `/etc/default/grub`
/// (idempotent; timestamped backup) and regenerate the grub config. If GRUB
/// isn't in use, print the exact parameters for the operator to add manually.
#[cfg(target_os = "linux")]
fn persist_kernel_params(params: &[String]) -> anyhow::Result<()> {
    use std::path::Path;
    const GRUB: &str = "/etc/default/grub";
    if !Path::new(GRUB).exists() {
        println!("\n{GRUB} not found — this machine doesn't use GRUB.");
        println!("Add these kernel parameters with your bootloader, then reboot:");
        for p in params {
            println!("    {p}");
        }
        return Ok(());
    }

    let original = std::fs::read_to_string(GRUB)?;
    // Which params are missing from the file already (idempotency)?
    let missing: Vec<&String> = params.iter().filter(|p| !original.contains(p.as_str())).collect();
    if missing.is_empty() {
        println!("GRUB already carries the display parameters — no changes needed.");
        return Ok(());
    }

    // Splice the missing params into GRUB_CMDLINE_LINUX_DEFAULT="…".
    let key = "GRUB_CMDLINE_LINUX_DEFAULT=";
    let mut edited = String::with_capacity(original.len() + 128);
    let mut spliced = false;
    for line in original.lines() {
        let trimmed = line.trim_start();
        if !spliced && trimmed.starts_with(key) {
            if let Some(updated) = splice_cmdline(trimmed, key, &missing) {
                edited.push_str(&updated);
                edited.push('\n');
                spliced = true;
                continue;
            }
        }
        edited.push_str(line);
        edited.push('\n');
    }
    if !spliced {
        // No such line — append one.
        let added: Vec<String> = missing.iter().map(|s| s.to_string()).collect();
        edited.push_str(&format!("{key}\"{}\"\n", added.join(" ")));
    }

    // Timestamped backup, then write + regenerate.
    println!("Backing up {GRUB} and adding: {}", missing.iter().map(|s| s.as_str()).collect::<Vec<_>>().join("  "));
    sudo_run(&["sh", "-c", &format!("cp -n {GRUB} {GRUB}.rmd-bak.$(date +%Y%m%d%H%M%S)")])?;
    sudo_write_file(GRUB, edited.as_bytes())?;
    regenerate_grub()?;
    Ok(())
}

/// Insert `missing` params into a `GRUB_CMDLINE_LINUX_DEFAULT="…"` line, keeping
/// the existing contents. Returns `None` if the line isn't quoted as expected.
#[cfg(target_os = "linux")]
fn splice_cmdline(line: &str, key: &str, missing: &[&String]) -> Option<String> {
    let rest = line.strip_prefix(key)?;
    let inner = rest.strip_prefix('"')?.strip_suffix('"')?;
    let mut items: Vec<String> = inner.split_whitespace().map(str::to_string).collect();
    for m in missing {
        if !items.iter().any(|i| i == *m) {
            items.push((*m).clone());
        }
    }
    Some(format!("{key}\"{}\"", items.join(" ")))
}

/// Regenerate the GRUB config using whichever tool this distro ships.
#[cfg(target_os = "linux")]
fn regenerate_grub() -> anyhow::Result<()> {
    use std::path::Path;
    if which("update-grub") {
        return sudo_run(&["update-grub"]);
    }
    if which("grub2-mkconfig") {
        let cfg = ["/boot/grub2/grub.cfg", "/boot/efi/EFI/fedora/grub.cfg"]
            .into_iter()
            .find(|p| Path::new(p).exists())
            .unwrap_or("/boot/grub2/grub.cfg");
        return sudo_run(&["grub2-mkconfig", "-o", cfg]);
    }
    if which("grub-mkconfig") {
        return sudo_run(&["grub-mkconfig", "-o", "/boot/grub/grub.cfg"]);
    }
    println!(
        "  (couldn't find update-grub/grub2-mkconfig — regenerate your grub config manually.)"
    );
    Ok(())
}

/// If the connector's DRM driver is loaded from the initramfs (early-KMS), the
/// EDID firmware must be embedded there too — refresh it. Best-effort/no-op if
/// the tooling or driver name can't be determined.
#[cfg(target_os = "linux")]
fn maybe_refresh_initramfs(sysfs: &str) {
    use std::path::Path;
    // Driver name via /sys/class/drm/<card>/device/driver symlink basename.
    let card = sysfs.split('-').next().unwrap_or("");
    let driver_link = Path::new("/sys/class/drm").join(card).join("device/driver");
    let driver = std::fs::read_link(&driver_link)
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()));
    let Some(driver) = driver else { return };

    // Debian/Ubuntu: is the module inside the current initramfs?
    let release = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
    let initrd = format!("/boot/initrd.img-{}", release.trim());
    if which("lsinitramfs") && Path::new(&initrd).exists() {
        let listed = std::process::Command::new("lsinitramfs")
            .arg(&initrd)
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains(&format!("{driver}.ko")))
            .unwrap_or(false);
        if listed {
            println!("Driver `{driver}` loads from the initramfs (early-KMS); refreshing it so the EDID blob is included.");
            if let Err(e) = sudo_run(&["update-initramfs", "-u"]) {
                tracing::warn!(error = %e, "update-initramfs failed; you may need to rebuild the initramfs manually");
            }
        }
    }
    // Other distros (dracut/mkinitcpio): the EDID blob under /lib/firmware is
    // usually picked up on the next scheduled initramfs build; we don't force it.
}

/// Arm a VKMS (virtual kernel modesetting) display for a truly headless box (no
/// physical connectors). Loads `vkms` at boot so the compositor always has an
/// output to render to. Reserved for the no-outputs case — on a machine with a
/// real GPU, VKMS can enumerate ahead of it and blank the real console.
#[cfg(target_os = "linux")]
fn setup_headless_vkms() -> anyhow::Result<()> {
    const CONF: &str = "/etc/modules-load.d/rmd-vkms.conf";
    if std::path::Path::new(CONF).exists() {
        println!("VKMS already armed ({CONF}) — no changes needed.");
    } else {
        sudo_write_file(
            CONF,
            b"# Installed by `rmdd setup-linux display`. Loads a virtual display\n\
              # (VKMS) at boot so a headless host always has a framebuffer to capture.\n\
              vkms\n",
        )?;
        // Load it now too, so it's usable without a reboot where possible.
        if let Err(e) = sudo_run(&["modprobe", "vkms"]) {
            tracing::warn!(error = %e, "modprobe vkms failed now; it will load on next boot");
        }
    }
    println!("\n\u{2713} Headless virtual display (VKMS) armed.");
    println!(
        "  Note: a compositor enumerates outputs at session start, so if it was\n  \
         already running you must reboot (or restart the display manager) for the\n  \
         virtual output to appear. VERIFY REMOTE ACCESS before relying on it."
    );
    Ok(())
}

/// Whether an executable is found on `PATH`.
#[cfg(target_os = "linux")]
fn which(bin: &str) -> bool {
    std::process::Command::new("sh")
        .args(["-c", &format!("command -v {bin} >/dev/null 2>&1")])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
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
    refresh_token: Option<rmd_session::rendezvous::TokenRefresher>,
) -> anyhow::Result<Box<dyn Signaling>> {
    if let Some(url) = rendezvous_url {
        let token =
            token.ok_or_else(|| anyhow::anyhow!("rendezvous mode requires a device token"))?;
        tracing::info!(%url, "signaling via rendezvous");
        // Pass the session-active flag so the rendezvous client's watchdog can
        // safely restart the (host) process if its DNS resolver wedges, without
        // tearing down a live peer-to-peer session. The refresh hook lets the
        // client re-mint an expired token (401) on its own.
        Ok(Box::new(RendezvousClient::connect(
            url,
            token,
            peer,
            Some(session_active),
            refresh_token,
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
                // Documented on Linux only (native input needs a one-time
                // /dev/uinput grant); silent no-op / omitted elsewhere.
                #[cfg(target_os = "linux")]
                let setup_help = "  rmdd setup-linux [input|display|system]\n                       \
                     one-time machine setup (sudo). input: native uinput; display:\n                       \
                     survive a monitor unplug / arm a headless virtual display;\n                       \
                     system: broker + per-session agent for remote LOGIN-SCREEN\n                       \
                     access (GDM) and greeter->user handover. Omit target = input+display.\n\n";
                #[cfg(not(target_os = "linux"))]
                let setup_help = "";
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
                     {}\
                     Settings (via `rmdd set`):\n  \
                     rendezvous_url  wss://<host>/ws — enables rendezvous mode\n  \
                     token           device bearer token (rendezvous mode)\n  \
                     password        connection password a viewer must enter\n  \
                     capture_source  monitor (default) | virtual (headless)\n  \
                     fps             capture frame-rate cap (default 30)\n  \
                     width, height   encode size cap in px (backend downscales to fit)\n\n\
                     Env (override the store):\n  \
                     RMD_RENDEZVOUS_URL  wss://<host>/ws (rendezvous signaling)\n  \
                     RMD_NAME            device name (default: hostname)\n  \
                     RMD_CODEC           h264 (default) | av1\n  \
                     RMD_ICE             STUN/TURN URL(s)\n\n\
                     Note: `set <k> <v>` takes the value inline, so it can appear in \
                     shell history; clear it or use a subshell if that matters.",
                    env!("CARGO_PKG_VERSION"),
                    setup_help,
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
    // One-time privileged machine setup so remote access works headless: native
    // input (uinput) and display persistence across monitor unplug. The daemon
    // itself runs unprivileged; this verb shells out via sudo for the root steps.
    // `setup-input` is kept as a hidden back-compat alias (input only).
    if matches!(
        args.first().map(String::as_str),
        Some("setup-linux") | Some("setup-input")
    ) {
        return run_setup_linux(&args);
    }
    // System-mode capture agent (Linux, opt-in): connects to the broker's Unix
    // socket, captures the current graphical session, and streams encoded H.264.
    // Holds no identity/token (those live in the broker), so it's safe to run in
    // the ephemeral greeter session. See `rmdd setup-linux system`.
    #[cfg(target_os = "linux")]
    if matches!(args.first().map(String::as_str), Some("agent")) {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "info".into()),
            )
            .init();
        return rmd_session::agent::run_agent(rmd_session::agent::AgentConfig::from_env());
    }

    // System-mode broker (Linux, opt-in): the always-on network endpoint. It shares
    // the full daemon setup below (identity/token/ICE/signaling) and only differs in
    // the final run call, so it falls through rather than returning here.
    let broker_mode =
        cfg!(target_os = "linux") && matches!(args.first().map(String::as_str), Some("broker"));

    // Any other unrecognized first argument is a mistake, not a request to start
    // the daemon — bail rather than silently serving (M15). A bare `rmdd` (no
    // args) still starts the host; `--version`/`--help` returned above; `broker`
    // falls through to the daemon setup.
    if let Some(first) = args.first() {
        if !broker_mode {
            anyhow::bail!("unknown command '{first}' — run `rmdd --help` for usage");
        }
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
    let mut token = match &rendezvous_url {
        Some(_) => match read_token(settings.as_ref()) {
            Ok(t) => Some(t),
            Err(_) => park_unconfigured("a rendezvous URL is set but no device token"),
        },
        None if lan_dev => None,
        None => park_unconfigured("no rendezvous URL or device token configured"),
    };

    // A hook the rendezvous client (and the ICE fetch below) call on a 401 to
    // re-mint an expired/rotated bearer token by proving possession of the device
    // identity key — so a long-running host recovers on its own. Needs both a
    // rendezvous URL and an identity; `None` (LAN/dev, or no identity) disables it.
    let token_refresher: Option<rmd_session::rendezvous::TokenRefresher> =
        match (rendezvous_url.as_deref(), identity.as_ref()) {
            (Some(url), Some(id)) => {
                let rest_base = rmd_session::account::rest_base_from_ws(url);
                let id = id.clone();
                Some(std::sync::Arc::new(move || {
                    refresh_and_persist_token(&rest_base, &id)
                }))
            }
            _ => None,
        };

    // Fetch ICE servers now (before building the config). If the token is already
    // expired the fetch 401s and triggers a refresh; use the refreshed token for
    // the rest of startup (and signaling), not just the persisted copy.
    let (ice, refreshed) = ice_servers(
        rendezvous_url.as_deref(),
        token.as_deref().map(|z| z.as_str()),
        token_refresher.as_ref(),
    );
    if let Some(new_token) = refreshed {
        token = Some(zeroize::Zeroizing::new(new_token));
    }
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
        ice_servers: ice,
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
        // Reuse a prior Wayland ScreenCast grant so capture doesn't re-prompt the
        // user every session; the host refreshes this in the store as needed.
        screencast_restore_token: sref
            .and_then(|s| s.get(sset::KEY_SCREENCAST_RESTORE_TOKEN))
            .filter(|t| !t.is_empty())
            .map(str::to_string),
        // Wayland capture source: `virtual` for headless boxes, else `monitor`
        // (dual-use, the default). `rmdd set capture_source virtual|monitor`.
        capture_source: match sref
            .and_then(|s| s.get(sset::KEY_CAPTURE_SOURCE))
            .map(|v| v.trim().to_ascii_lowercase())
            .as_deref()
        {
            Some("virtual") => rmd_capture::CaptureSource::Virtual,
            _ => rmd_capture::CaptureSource::Monitor,
        },
    };

    // Fail closed on an open relay. An internet-reachable host (connected to a
    // rendezvous) with no access control whatsoever — no authorization gate
    // (`require_authorization` already folds in RMD_REQUIRE_AUTH and a non-empty
    // authorized-keys list) and no connect password — would grant full screen
    // capture + input injection to anyone who learns its device_id, which the
    // system does not treat as a secret. Refuse to serve unless the operator sets
    // a credential, or explicitly opts into an open relay. LAN/dev signaling
    // (no rendezvous URL) is unaffected.
    if should_park_open_relay(
        rendezvous_url.is_some(),
        cfg.require_authorization,
        cfg.connect_password.is_some(),
        std::env::var("RMD_ALLOW_OPEN_RELAY").is_ok(),
    ) {
        park_open_relay();
    }

    tracing::info!(
        display = cfg.display_index,
        res = format!("{}x{}@{}", cfg.width, cfg.height, cfg.fps),
        "starting ReachMyDevice host"
    );
    // Whether a viewer session is currently active — watched by the rendezvous
    // client so its wedged-resolver watchdog never restarts us mid-session.
    let session_active = Arc::new(AtomicBool::new(false));

    // Keep the TURN relay credential fresh: restart in place (when idle) before it
    // lapses, since the relay is allocated once at startup and never refreshed.
    // No-op unless we actually have a credentialed TURN server.
    spawn_turn_refresh(&cfg.ice_servers, session_active.clone());

    // The host is the offerer; it learns the viewer's id from the rendezvous hello.
    let signaling = build_signaling(
        None,
        rendezvous_url.as_deref(),
        token_str,
        session_active.clone(),
        token_refresher,
    )?;

    // Desktop tray companion when built with `--features tray` and requested via
    // `RMD_TRAY=1`; otherwise run headless (the default, and the only
    // option on servers without a display).
    #[cfg(feature = "tray")]
    if std::env::var("RMD_TRAY").is_ok() {
        return tray::run_with_tray(cfg, signaling);
    }

    // System-mode broker: identical setup, but the video plane is fed by
    // per-session agents over the Unix socket (enables remote login-screen access
    // and greeter->user handover). Falls through to the local host otherwise.
    #[cfg(target_os = "linux")]
    if broker_mode {
        return rmd_session::broker::run_broker(cfg, signaling, move |s| {
            session_active.store(matches!(s, HostStatus::Active), Ordering::Relaxed);
        });
    }

    run_host_reporting(cfg, signaling, move |s| {
        session_active.store(matches!(s, HostStatus::Active), Ordering::Relaxed);
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn turn(username: Option<&str>) -> IceServer {
        IceServer {
            urls: vec!["turn:1.2.3.4:3478?transport=udp".to_string()],
            username: username.map(str::to_string),
            credential: username.map(|_| "cred".to_string()),
        }
    }

    #[test]
    fn earliest_turn_expiry_parses_leading_timestamp() {
        // coturn REST username is `<expiry>:<id>`.
        assert_eq!(
            earliest_turn_expiry(&[turn(Some("1700000000:42"))]),
            Some(1_700_000_000)
        );
    }

    #[test]
    fn earliest_turn_expiry_takes_the_minimum_across_servers() {
        let servers = vec![turn(Some("1700000900:1")), turn(Some("1700000100:2"))];
        assert_eq!(earliest_turn_expiry(&servers), Some(1_700_000_100));
    }

    #[test]
    fn earliest_turn_expiry_none_for_stun_or_credentialless() {
        // STUN-only (no username) and manual URL-only entries carry no expiry.
        assert_eq!(earliest_turn_expiry(&[turn(None)]), None);
        assert_eq!(
            earliest_turn_expiry(&[IceServer::urls(vec!["stun:1.2.3.4:3478".to_string()])]),
            None
        );
    }

    #[test]
    fn earliest_turn_expiry_none_for_unparseable_username() {
        // A non-timestamp leading field must not yield a bogus (tiny) expiry.
        assert_eq!(earliest_turn_expiry(&[turn(Some("not-a-timestamp:x"))]), None);
    }

    #[test]
    fn open_relay_parks_only_when_reachable_and_uncontrolled() {
        // (has_rendezvous, require_authorization, has_connect_password, allow_open_relay)
        // The one and only park case: internet-reachable with zero access control.
        assert!(should_park_open_relay(true, false, false, false));

        // Any single mitigation exempts it.
        assert!(!should_park_open_relay(false, false, false, false)); // LAN/dev, no rendezvous
        assert!(!should_park_open_relay(true, true, false, false)); // auth gate / authorized-keys
        assert!(!should_park_open_relay(true, false, true, false)); // connect password set
        assert!(!should_park_open_relay(true, false, false, true)); // explicit RMD_ALLOW_OPEN_RELAY

        // A fully-configured, opted-in host never parks regardless of combination.
        assert!(!should_park_open_relay(true, true, true, true));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn splice_cmdline_appends_and_is_idempotent() {
        let key = "GRUB_CMDLINE_LINUX_DEFAULT=";
        let p1 = "video=HDMI-A-2:1680x1050@60e".to_string();
        let p2 = "drm.edid_firmware=HDMI-A-2:edid/rmd-hdmi-a-2.bin".to_string();
        let missing: Vec<&String> = vec![&p1, &p2];

        // Appends into the existing quoted value, preserving what's there.
        let line = "GRUB_CMDLINE_LINUX_DEFAULT=\"quiet splash\"";
        let out = splice_cmdline(line, key, &missing).unwrap();
        assert_eq!(
            out,
            "GRUB_CMDLINE_LINUX_DEFAULT=\"quiet splash video=HDMI-A-2:1680x1050@60e drm.edid_firmware=HDMI-A-2:edid/rmd-hdmi-a-2.bin\""
        );

        // Re-splicing an already-updated line adds nothing (idempotent).
        assert_eq!(splice_cmdline(&out, key, &missing).unwrap(), out);

        // An empty existing value yields just the new params (no leading space).
        let empty = splice_cmdline("GRUB_CMDLINE_LINUX_DEFAULT=\"\"", key, &missing).unwrap();
        assert_eq!(
            empty,
            "GRUB_CMDLINE_LINUX_DEFAULT=\"video=HDMI-A-2:1680x1050@60e drm.edid_firmware=HDMI-A-2:edid/rmd-hdmi-a-2.bin\""
        );

        // A malformed (unquoted) line is rejected so the caller can append instead.
        assert!(splice_cmdline("GRUB_CMDLINE_LINUX_DEFAULT=quiet", key, &missing).is_none());
    }
}
