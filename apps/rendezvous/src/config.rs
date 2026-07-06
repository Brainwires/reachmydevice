//! Server configuration, read from the environment.

use std::net::SocketAddr;

/// Rendezvous server configuration.
#[derive(Clone, Debug)]
pub struct Config {
    /// Address to bind the HTTP/WebSocket listener.
    pub bind_addr: SocketAddr,
    /// SQLite connection URL, e.g. `sqlite:rmd.db?mode=rwc`.
    pub database_url: String,
    /// Whether new-user registration is open (vs. invite/admin-only).
    pub allow_open_registration: bool,
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
        // TURN is enabled only when both a shared secret and a public host are
        // configured; otherwise `/api/ice` returns STUN-only.
        let turn = match (
            std::env::var("RMD_TURN_SECRET").ok().filter(|s| !s.is_empty()),
            std::env::var("RMD_TURN_HOST").ok().filter(|s| !s.is_empty()),
        ) {
            (Some(secret), Some(host)) => Some(TurnConfig {
                secret,
                host,
                port: std::env::var("RMD_TURN_PORT")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(3478),
                ttl_secs: std::env::var("RMD_TURN_TTL")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(43_200),
            }),
            _ => None,
        };
        Self {
            bind_addr,
            database_url,
            allow_open_registration,
            turn,
        }
    }
}
