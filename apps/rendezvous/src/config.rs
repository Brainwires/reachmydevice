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
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "sqlite:rmd.db?mode=rwc".to_string());
        // Closed by default: an operator must explicitly opt into open signup.
        // (Provision the first account with the CLI / RMD_RZ_OPEN_REGISTRATION=1.)
        let allow_open_registration = std::env::var("RMD_RZ_OPEN_REGISTRATION")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false);
        Self {
            bind_addr,
            database_url,
            allow_open_registration,
        }
    }
}
