//! Server configuration, read from the environment.

use std::net::SocketAddr;

/// Rendezvous server configuration.
#[derive(Clone, Debug)]
pub struct Config {
    /// Address to bind the HTTP/WebSocket listener.
    pub bind_addr: SocketAddr,
    /// SQLite connection URL, e.g. `sqlite:rmd.db?mode=rwc`.
    pub database_url: String,
    /// Default for the runtime `open_registration` setting, used only to seed the
    /// DB on first boot (see `db::seed_settings`). The live value is the DB row.
    pub allow_open_registration: bool,
    /// Bearer token guarding the admin endpoints (e.g. flipping registration).
    /// `None` disables the admin API entirely (no token → no admin surface).
    pub admin_token: Option<String>,
    /// Bearer token required to create the **first** account over HTTP. `None`
    /// means the legacy behavior (first account bootstraps freely) — set this on
    /// any internet-reachable deployment to prevent a first-account land-grab.
    pub bootstrap_token: Option<String>,
    /// Name of the forwarding header set by a *trusted* ingress (e.g.
    /// `cf-connecting-ip` behind Cloudflare, `x-real-ip` behind nginx). When set,
    /// the real client IP is taken **only** from this header; when `None`, only
    /// the socket peer is trusted and client-supplied forwarding headers are
    /// ignored (prevents IP-spoofed fail2ban bypass / rate-limit evasion).
    pub trusted_proxy_header: Option<String>,
    /// Lifetime for newly issued device bearer tokens, in seconds. `None` = no
    /// expiry (legacy). Existing tokens are unaffected; this only stamps new ones.
    pub token_ttl_secs: Option<u64>,
    /// TURN configuration (all-or-nothing). When set, `/api/ice` mints ephemeral
    /// coturn credentials so browser/host peers can relay through NAT.
    pub turn: Option<TurnConfig>,
}

/// coturn `--use-auth-secret` (REST-API) parameters for minting time-limited
/// TURN credentials shared with the relay.
#[derive(Clone, Debug)]
pub struct TurnConfig {
    /// Shared secret matching coturn's `--static-auth-secret`.
    pub secret: String,
    /// Public host/IP clients dial for STUN/TURN (e.g. `67.217.246.238`).
    pub host: String,
    /// TURN/STUN listener port (coturn default `3478`).
    pub port: u16,
    /// Credential lifetime in seconds (default 12h).
    pub ttl_secs: u64,
}

impl Config {
    /// Read config from environment variables with sane defaults.
    ///
    /// | env | default |
    /// |-----|---------|
    /// | `RMD_RZ_ADDR` | `0.0.0.0:8080` |
    /// | `DATABASE_URL` | `sqlite:rmd.db?mode=rwc` |
    /// | `RMD_RZ_OPEN_REGISTRATION` | `false` (secure by default) |
    pub fn from_env() -> Self {
        let bind_addr = std::env::var("RMD_RZ_ADDR")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or_else(|| "0.0.0.0:8080".parse().unwrap());
        let database_url =
            std::env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite:rmd.db?mode=rwc".to_string());
        // Closed by default: an operator must explicitly opt into open signup.
        // (Provision the first account with the CLI / RMD_RZ_OPEN_REGISTRATION=1.)
        let allow_open_registration = std::env::var("RMD_RZ_OPEN_REGISTRATION")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false);
        // Optional admin bearer token (guards runtime settings changes). Absent →
        // the admin API is disabled.
        let admin_token = std::env::var("RMD_RZ_ADMIN_TOKEN")
            .ok()
            .filter(|s| !s.is_empty());
        // Optional first-account bootstrap gate. Absent → legacy free bootstrap.
        let bootstrap_token = std::env::var("RMD_RZ_BOOTSTRAP_TOKEN")
            .ok()
            .filter(|s| !s.is_empty());
        // Trusted ingress forwarding header (lower-cased for case-insensitive
        // lookup). Absent → don't trust any forwarding header (peer IP only).
        let trusted_proxy_header = std::env::var("RMD_TRUSTED_PROXY_HEADER")
            .ok()
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty());
        // Device-token lifetime. Default 90 days; `RMD_RZ_TOKEN_TTL=0` disables
        // expiry (legacy no-expiry tokens).
        let token_ttl_secs = match std::env::var("RMD_RZ_TOKEN_TTL")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
        {
            Some(0) => None,
            Some(n) => Some(n),
            None => Some(90 * 24 * 3600),
        };
        // TURN relay is OFF by default. Enabling it is a deliberate operator
        // decision because relayed media flows through — and uses the bandwidth
        // of — this server. It requires `RMD_TURN_ENABLED=1` **and** a shared
        // secret + public host; otherwise `/api/ice` returns STUN-only (peer-to-
        // peer, no relay). A dangling secret alone never enables relay.
        let turn_enabled = std::env::var("RMD_TURN_ENABLED")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false);
        let turn = if turn_enabled {
            match (
                std::env::var("RMD_TURN_SECRET")
                    .ok()
                    .filter(|s| !s.is_empty()),
                std::env::var("RMD_TURN_HOST")
                    .ok()
                    .filter(|s| !s.is_empty()),
            ) {
                (Some(secret), Some(host)) => Some(TurnConfig {
                    secret,
                    host,
                    port: std::env::var("RMD_TURN_PORT")
                        .ok()
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(3478),
                    // Short by default (10 min): a leaked/shared credential is
                    // useful only briefly, and the broker mints fresh creds per
                    // session. Raise via RMD_TURN_TTL if clients are long-lived.
                    ttl_secs: std::env::var("RMD_TURN_TTL")
                        .ok()
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(600),
                }),
                _ => {
                    tracing::warn!(
                        "RMD_TURN_ENABLED is set but RMD_TURN_SECRET/RMD_TURN_HOST are \
                         missing — TURN relay stays disabled (STUN-only)"
                    );
                    None
                }
            }
        } else {
            None
        };
        Self {
            bind_addr,
            database_url,
            allow_open_registration,
            admin_token,
            bootstrap_token,
            trusted_proxy_header,
            token_ttl_secs,
            turn,
        }
    }
}
