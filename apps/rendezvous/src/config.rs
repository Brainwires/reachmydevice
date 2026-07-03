//! Server configuration, read from the environment.

use std::net::SocketAddr;

/// Rendezvous server configuration.
#[derive(Clone, Debug)]
pub struct Config {
    /// Address to bind the HTTP/WebSocket listener.
    pub bind_addr: SocketAddr,
    /// SQLite connection URL, e.g. `sqlite:openreach.db?mode=rwc`.
    pub database_url: String,
    /// Whether new-user registration is open (vs. invite/admin-only).
    pub allow_open_registration: bool,
}

impl Config {
    /// Read config from environment variables with sane defaults.
    ///
    /// | env | default |
    /// |-----|---------|
    /// | `OPENREACH_RZ_ADDR` | `0.0.0.0:8080` |
    /// | `DATABASE_URL` | `sqlite:openreach.db?mode=rwc` |
    /// | `OPENREACH_RZ_OPEN_REGISTRATION` | `true` |
    pub fn from_env() -> Self {
        let bind_addr = std::env::var("OPENREACH_RZ_ADDR")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or_else(|| "0.0.0.0:8080".parse().unwrap());
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "sqlite:openreach.db?mode=rwc".to_string());
        let allow_open_registration = std::env::var("OPENREACH_RZ_OPEN_REGISTRATION")
            .map(|v| v != "false" && v != "0")
            .unwrap_or(true);
        Self {
            bind_addr,
            database_url,
            allow_open_registration,
        }
    }
}
