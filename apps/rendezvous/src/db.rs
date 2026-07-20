//! Database pool, migrations, and shared application state.

use crate::config::Config;
use rmd_entitlement::RelayEntitlement;
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
    /// Caps concurrent Argon2 verifications. Each verify costs 64 MiB / 3 passes,
    /// so an unbounded flood of auth'd endpoints would OOM a small VPS. This bounds
    /// the in-flight count; excess requests queue on the permit instead.
    pub argon2_gate: Arc<tokio::sync::Semaphore>,
    /// Short-lived, single-use WebSocket tickets (keeps long-lived bearer tokens
    /// out of `/ws?…` URLs and proxy logs). Keyed ticket → (device_id, expiry).
    pub ws_tickets: Arc<crate::auth::TicketStore>,
    /// Per-user cache of the current ephemeral TURN credential. `/api/ice` reuses
    /// a still-valid cred instead of minting a fresh one every call, which caps
    /// credential churn (an authed device can't spew unbounded shareable creds).
    /// user_id → (username, credential, expiry_unix).
    #[allow(clippy::type_complexity)]
    pub ice_cache: Arc<std::sync::Mutex<std::collections::HashMap<i64, (String, String, i64)>>>,
    /// Relay-access policy. The open-source default is `AllowAll`; a private
    /// plugin can inject a paid policy (see `AppState::new`).
    pub entitlement: Arc<dyn RelayEntitlement>,
    /// How a presented bearer credential on the device-facing endpoints
    /// (`/api/ice`, `/api/ws-ticket`, `/ws`) is resolved to an identity. The
    /// default [`crate::resolver::DeviceTokenResolver`] accepts device tokens
    /// only; a plugin overrides this field to also accept, e.g., member JWTs.
    pub credential_resolver: Arc<dyn crate::resolver::CredentialResolver>,
    /// Optional observer of the signaling session lifecycle (connect/disconnect),
    /// so a plugin can persist per-account activity. Default `None`.
    pub session_observer: Option<Arc<dyn crate::resolver::SessionObserver>>,
    /// WebAuthn relying party, when passkeys are configured (`RMD_RZ_WEBAUTHN_*`).
    /// `None` disables the passkey routes at runtime.
    #[cfg(feature = "passkeys")]
    pub webauthn: Option<Arc<webauthn_rs::Webauthn>>,
    /// In-memory store of in-progress passkey ceremonies.
    #[cfg(feature = "passkeys")]
    pub webauthn_reg: Arc<crate::webauthn::ChallengeStore>,
}

impl AppState {
    /// Assemble shared state around an already-opened pool and a relay policy.
    ///
    /// The default binary passes `rmd_entitlement::allow_all()`; a paid build
    /// injects its own [`RelayEntitlement`] here without touching this crate.
    pub fn new(pool: SqlitePool, config: Config, entitlement: Arc<dyn RelayEntitlement>) -> Self {
        // Cap concurrent Argon2 to a few permits — enough for real login
        // concurrency on a small box, far below what would exhaust its RAM.
        let argon2_permits = std::thread::available_parallelism()
            .map(|n| n.get().clamp(2, 4))
            .unwrap_or(2);
        Self {
            pool,
            config: Arc::new(config),
            hub: Arc::new(crate::signaling::Hub::new()),
            throttle: Arc::new(crate::throttle::LoginThrottle::new()),
            argon2_gate: Arc::new(tokio::sync::Semaphore::new(argon2_permits)),
            ws_tickets: Arc::new(crate::auth::TicketStore::new()),
            ice_cache: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            entitlement,
            // Open-source defaults: device-token auth, no activity observer. A
            // paid build overrides these `pub` fields after construction, so the
            // `new` signature stays stable for every caller.
            credential_resolver: Arc::new(crate::resolver::DeviceTokenResolver),
            session_observer: None,
            #[cfg(feature = "passkeys")]
            webauthn: crate::webauthn::from_env(),
            #[cfg(feature = "passkeys")]
            webauthn_reg: Arc::new(crate::webauthn::ChallengeStore::default()),
        }
    }
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
    if b { "true" } else { "false" }
}

/// Parse a stored setting string as a boolean (`"true"`/`"1"` → true).
pub fn parse_bool(s: &str) -> bool {
    s == "true" || s == "1"
}

/// Insert a new account, in one atomic statement so concurrent first-account
/// requests can't both slip through. It succeeds when:
///   - the `users` table is empty **and** `allow_bootstrap` is true (first-account
///     bootstrap — gated by a bootstrap token when one is configured, see
///     `api::register_user`), or
///   - `open` is true (runtime open-registration).
/// Returns rows inserted (0 = refused). A `UNIQUE` violation (username taken)
/// surfaces as `Err`.
#[allow(clippy::doc_lazy_continuation)]
pub async fn create_user_if_allowed(
    pool: &SqlitePool,
    username: &str,
    password_hash: &str,
    open: bool,
    allow_bootstrap: bool,
) -> sqlx::Result<u64> {
    let res = sqlx::query(
        "INSERT INTO users (username, password_hash, created_at) \
         SELECT ?, ?, ? \
         WHERE ((SELECT COUNT(*) FROM users) = 0 AND ? = 1) OR ? = 1",
    )
    .bind(username)
    .bind(password_hash)
    .bind(now_unix())
    .bind(allow_bootstrap as i64)
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
            bootstrap_token: None,
            trusted_proxy_header: None,
            token_ttl_secs: None,
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
            get_setting(&pool, SETTING_OPEN_REGISTRATION)
                .await
                .unwrap()
                .as_deref(),
            Some("false")
        );

        // Empty table but bootstrap gated off (a bootstrap token is required and
        // wasn't presented) → refused even though the table is empty.
        assert_eq!(
            create_user_if_allowed(&pool, "x", "h0", false, false)
                .await
                .unwrap(),
            0
        );
        // Empty table + bootstrap allowed → first account bootstraps though closed.
        assert_eq!(
            create_user_if_allowed(&pool, "alice", "h1", false, true)
                .await
                .unwrap(),
            1
        );
        // Now a user exists and signup is closed → refused (bootstrap no longer applies).
        assert_eq!(
            create_user_if_allowed(&pool, "bob", "h2", false, true)
                .await
                .unwrap(),
            0
        );
        // Flip the runtime toggle on → allowed again.
        set_setting(&pool, SETTING_OPEN_REGISTRATION, bool_str(true))
            .await
            .unwrap();
        assert!(parse_bool(
            &get_setting(&pool, SETTING_OPEN_REGISTRATION)
                .await
                .unwrap()
                .unwrap()
        ));
        assert_eq!(
            create_user_if_allowed(&pool, "bob", "h2", true, false)
                .await
                .unwrap(),
            1
        );
        // Duplicate username → UNIQUE violation (not a silent 0-rows).
        let err = create_user_if_allowed(&pool, "alice", "h3", true, false)
            .await
            .unwrap_err();
        assert!(matches!(err, sqlx::Error::Database(d) if d.is_unique_violation()));
    }
}
