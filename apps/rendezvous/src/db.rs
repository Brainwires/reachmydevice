//! Database pool, migrations, and shared application state.

use crate::config::Config;
use sqlx::sqlite::{SqlitePool, SqlitePoolOptions};
use std::sync::Arc;

/// Shared state handed to every handler.
#[derive(Clone)]
pub struct AppState {
    pub pool: SqlitePool,
    pub config: Arc<Config>,
    /// Live WebSocket signaling hub (device pairing + relay).
    pub hub: Arc<crate::signaling::Hub>,
    /// Per-username login throttle (credential-stuffing backoff).
    pub throttle: Arc<crate::throttle::LoginThrottle>,
}

/// Open the SQLite pool and run migrations.
pub async fn connect_and_migrate(url: &str) -> anyhow::Result<SqlitePool> {
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(url)
        .await?;
    sqlx::migrate!("./migrations").run(&pool).await?;
    Ok(pool)
}

// --- runtime settings (see migrations/0002_settings.sql) -------------------

/// Whether `/api/register` accepts new accounts (the first account always
/// bootstraps regardless — see `api::register_user`).
pub const SETTING_OPEN_REGISTRATION: &str = "open_registration";

/// Read a runtime setting value, if present.
pub async fn get_setting(pool: &SqlitePool, key: &str) -> sqlx::Result<Option<String>> {
    sqlx::query_scalar("SELECT value FROM settings WHERE key = ?")
        .bind(key)
        .fetch_optional(pool)
        .await
}

/// Upsert a runtime setting value.
pub async fn set_setting(pool: &SqlitePool, key: &str, value: &str) -> sqlx::Result<()> {
    sqlx::query(
        "INSERT INTO settings (key, value) VALUES (?, ?) \
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
    )
    .bind(key)
    .bind(value)
    .execute(pool)
    .await?;
    Ok(())
}

/// Seed runtime settings from their env-derived defaults on first boot, without
/// clobbering values an operator has already changed (`INSERT OR IGNORE`).
pub async fn seed_settings(pool: &SqlitePool, cfg: &Config) -> sqlx::Result<()> {
    sqlx::query("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)")
        .bind(SETTING_OPEN_REGISTRATION)
        .bind(bool_str(cfg.allow_open_registration))
        .execute(pool)
        .await?;
    Ok(())
}

/// Canonical string form for a boolean setting.
pub fn bool_str(b: bool) -> &'static str {
    if b {
        "true"
    } else {
        "false"
    }
}

/// Parse a stored setting string as a boolean (`"true"`/`"1"` → true).
pub fn parse_bool(s: &str) -> bool {
    s == "true" || s == "1"
}

/// Insert a new account **iff** the `users` table is empty (first-account
/// bootstrap) or `open` is true. A single atomic statement so concurrent
/// first-account requests can't both slip through the bootstrap window.
/// Returns the number of rows inserted (0 = refused because signup is closed).
/// A `UNIQUE` violation (username taken) surfaces as `Err`.
pub async fn create_user_if_allowed(
    pool: &SqlitePool,
    username: &str,
    password_hash: &str,
    open: bool,
) -> sqlx::Result<u64> {
    let res = sqlx::query(
        "INSERT INTO users (username, password_hash, created_at) \
         SELECT ?, ?, ? \
         WHERE (SELECT COUNT(*) FROM users) = 0 OR ? = 1",
    )
    .bind(username)
    .bind(password_hash)
    .bind(now_unix())
    .bind(open as i64)
    .execute(pool)
    .await?;
    Ok(res.rows_affected())
}

/// Current unix time in seconds.
pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn test_cfg(url: &str) -> Config {
        Config {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            database_url: url.to_string(),
            allow_open_registration: false,
            admin_token: None,
            turn: None,
        }
    }

    #[tokio::test]
    async fn registration_bootstrap_then_gated_by_toggle() {
        // Shared in-memory DB (survives across the pool's connections).
        let url = "sqlite:file:regtest_bootstrap?mode=memory&cache=shared";
        let pool = connect_and_migrate(url).await.unwrap();
        let cfg = test_cfg(url); // allow_open_registration = false
        seed_settings(&pool, &cfg).await.unwrap();

        // Seeded from the (closed) env default.
        assert_eq!(
            get_setting(&pool, SETTING_OPEN_REGISTRATION).await.unwrap().as_deref(),
            Some("false")
        );

        // Empty table → first account bootstraps even though signup is closed.
        assert_eq!(create_user_if_allowed(&pool, "alice", "h1", false).await.unwrap(), 1);
        // Now a user exists and signup is closed → refused.
        assert_eq!(create_user_if_allowed(&pool, "bob", "h2", false).await.unwrap(), 0);
        // Flip the runtime toggle on → allowed again.
        set_setting(&pool, SETTING_OPEN_REGISTRATION, bool_str(true)).await.unwrap();
        assert!(parse_bool(
            &get_setting(&pool, SETTING_OPEN_REGISTRATION).await.unwrap().unwrap()
        ));
        assert_eq!(create_user_if_allowed(&pool, "bob", "h2", true).await.unwrap(), 1);
        // Duplicate username → UNIQUE violation (not a silent 0-rows).
        let err = create_user_if_allowed(&pool, "alice", "h3", true).await.unwrap_err();
        assert!(matches!(err, sqlx::Error::Database(d) if d.is_unique_violation()));
    }
}
