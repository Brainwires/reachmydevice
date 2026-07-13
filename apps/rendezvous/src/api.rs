//! HTTP API: user registration, device registration (token issuance), and the
//! user-scoped device list.
//!
//! - User-scoped endpoints authenticate with HTTP Basic (`username:password`).
//! - Device registration authenticates the owning user in the body and returns a
//!   long-lived device **bearer token** used for the signaling WebSocket.

use crate::auth;
use crate::db::{now_unix, AppState};
use crate::error::{AppError, AppResult};
use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::Json;
use base64::Engine;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sqlx::SqlitePool;

// --- request/response bodies ----------------------------------------------

#[derive(Deserialize)]
pub struct RegisterUser {
    username: String,
    password: String,
}

#[derive(Deserialize)]
pub struct RegisterDevice {
    username: String,
    password: String,
    device_id: String,
    name: String,
    /// Device identity public key (base64), stored for TOFU display.
    public_key: String,
    #[serde(default = "default_role")]
    role: String,
}

fn default_role() -> String {
    "both".to_string()
}

#[derive(Serialize)]
pub struct DeviceToken {
    token: String,
    device_id: String,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct DeviceRow {
    device_id: String,
    name: String,
    public_key: String,
    role: String,
    created_at: i64,
    last_seen: Option<i64>,
}

// --- handlers --------------------------------------------------------------

/// `POST /api/register` — create a new account.
///
/// The **first** account always bootstraps (an empty server is unusable
/// otherwise); once any user exists, new sign-ups require the runtime
/// `open_registration` setting to be on. The check + insert is a single atomic
/// statement so concurrent first-account requests can't both slip through the
/// bootstrap window.
pub async fn register_user(
    State(state): State<AppState>,
    Json(body): Json<RegisterUser>,
) -> AppResult<Json<serde_json::Value>> {
    if body.username.trim().is_empty() || body.password.len() < 8 {
        return Err(AppError::BadRequest(
            "username required; password must be at least 8 chars".into(),
        ));
    }
    let open = registration_open(&state).await?;
    let hash = auth::hash_password(&body.password).map_err(AppError::Internal)?;
    match crate::db::create_user_if_allowed(&state.pool, &body.username, &hash, open).await {
        // No row inserted → users exist and signup is closed.
        Ok(0) => Err(AppError::RegistrationClosed),
        Ok(_) => Ok(Json(serde_json::json!({ "status": "created" }))),
        // UNIQUE violation → username taken.
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
            Err(AppError::Conflict("username already taken".into()))
        }
        Err(e) => Err(AppError::Db(e)),
    }
}

/// Current runtime value of the open-registration flag: the DB `settings` row,
/// falling back to the env-seeded config default if the row is somehow absent.
async fn registration_open(state: &AppState) -> AppResult<bool> {
    match crate::db::get_setting(&state.pool, crate::db::SETTING_OPEN_REGISTRATION).await? {
        Some(v) => Ok(crate::db::parse_bool(&v)),
        None => Ok(state.config.allow_open_registration),
    }
}

#[derive(Deserialize)]
pub struct SetRegistration {
    enabled: bool,
}

/// `GET /api/registration` — public: is new-account signup currently open?
pub async fn get_registration(
    State(state): State<AppState>,
) -> AppResult<Json<serde_json::Value>> {
    Ok(Json(serde_json::json!({ "open": registration_open(&state).await? })))
}

/// `POST /api/admin/registration` — flip signup open/closed. Admin bearer token.
pub async fn set_registration(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<SetRegistration>,
) -> AppResult<Json<serde_json::Value>> {
    require_admin(&state, &headers)?;
    crate::db::set_setting(
        &state.pool,
        crate::db::SETTING_OPEN_REGISTRATION,
        crate::db::bool_str(body.enabled),
    )
    .await?;
    tracing::info!(open = body.enabled, "open_registration changed via admin API");
    Ok(Json(serde_json::json!({ "open": body.enabled })))
}

/// `POST /api/devices` — register/refresh a device and issue a bearer token.
pub async fn register_device(
    State(state): State<AppState>,
    Json(body): Json<RegisterDevice>,
) -> AppResult<Json<DeviceToken>> {
    let user_id = authenticate_user(&state, &body.username, &body.password).await?;

    // Find or create the device, enforcing single ownership.
    let existing: Option<(i64, i64)> =
        sqlx::query_as("SELECT id, user_id FROM devices WHERE device_id = ?")
            .bind(&body.device_id)
            .fetch_optional(&state.pool)
            .await?;
    let device_pk = match existing {
        Some((_, owner)) if owner != user_id => {
            return Err(AppError::Conflict(
                "device already registered to another account".into(),
            ))
        }
        Some((id, _)) => {
            sqlx::query("UPDATE devices SET name = ?, public_key = ?, role = ? WHERE id = ?")
                .bind(&body.name)
                .bind(&body.public_key)
                .bind(&body.role)
                .bind(id)
                .execute(&state.pool)
                .await?;
            id
        }
        None => {
            let res = sqlx::query(
                "INSERT INTO devices (user_id, device_id, name, public_key, role, created_at) \
                 VALUES (?, ?, ?, ?, ?, ?)",
            )
            .bind(user_id)
            .bind(&body.device_id)
            .bind(&body.name)
            .bind(&body.public_key)
            .bind(&body.role)
            .bind(now_unix())
            .execute(&state.pool)
            .await?;
            res.last_insert_rowid()
        }
    };

    // Issue a fresh bearer token (store only its hash).
    let token = auth::generate_token();
    sqlx::query("INSERT INTO device_tokens (device_pk, token_hash, created_at) VALUES (?, ?, ?)")
        .bind(device_pk)
        .bind(auth::hash_token(&token))
        .bind(now_unix())
        .execute(&state.pool)
        .await?;

    Ok(Json(DeviceToken {
        token,
        device_id: body.device_id,
    }))
}

/// `GET /api/devices` — list the authenticated user's devices (Basic auth).
pub async fn list_devices(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<Vec<DeviceRow>>> {
    let (username, password) = basic_auth(&headers)?;
    let user_id = authenticate_user(&state, &username, &password).await?;
    let rows = sqlx::query_as::<_, DeviceRow>(
        "SELECT device_id, name, public_key, role, created_at, last_seen \
         FROM devices WHERE user_id = ? ORDER BY created_at",
    )
    .bind(user_id)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(rows))
}

/// `DELETE /api/devices/:device_id` — remove a device (Basic auth).
pub async fn delete_device(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(device_id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    let (username, password) = basic_auth(&headers)?;
    let user_id = authenticate_user(&state, &username, &password).await?;
    let res = sqlx::query("DELETE FROM devices WHERE user_id = ? AND device_id = ?")
        .bind(user_id)
        .bind(&device_id)
        .execute(&state.pool)
        .await?;
    if res.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    Ok(Json(serde_json::json!({ "status": "deleted" })))
}

#[derive(Deserialize)]
pub struct RenameDevice {
    name: String,
}

/// `PATCH /api/devices/:device_id` — rename a device (Basic auth). Only the
/// display name changes; the token, key, and role are untouched.
pub async fn rename_device(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(device_id): Path<String>,
    Json(body): Json<RenameDevice>,
) -> AppResult<Json<serde_json::Value>> {
    let (username, password) = basic_auth(&headers)?;
    let user_id = authenticate_user(&state, &username, &password).await?;
    let name = body.name.trim();
    if name.is_empty() {
        return Err(AppError::BadRequest("name required".into()));
    }
    let res = sqlx::query("UPDATE devices SET name = ? WHERE user_id = ? AND device_id = ?")
        .bind(name)
        .bind(user_id)
        .bind(&device_id)
        .execute(&state.pool)
        .await?;
    if res.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    Ok(Json(serde_json::json!({ "status": "renamed" })))
}

// --- ICE / TURN ------------------------------------------------------------

#[derive(Deserialize)]
pub struct IceQuery {
    token: String,
}

/// `GET /api/ice?token=…` — the ICE servers a peer should use for this session.
///
/// When TURN is configured, returns a `stun:` entry plus a `turn:` entry with
/// **ephemeral** coturn `--use-auth-secret` credentials: `username` is
/// `<expiry-unix>:rmd` and `credential` is `base64(HMAC-SHA1(secret, username))`,
/// valid for `ttl_secs`. Otherwise falls back to a public STUN so peers can at
/// least gather server-reflexive candidates. Requires a valid device token, so
/// only registered devices can obtain relay credentials.
pub async fn ice_servers(
    State(state): State<AppState>,
    Query(q): Query<IceQuery>,
) -> AppResult<Json<serde_json::Value>> {
    // Authenticate the device and resolve its owning user (also refreshes
    // `last_seen`). Only registered devices can even reach the relay gate.
    let user_id = match user_id_for_token(&state.pool, &q.token).await? {
        Some(id) => id,
        None => return Err(AppError::Unauthorized),
    };

    // Ask the relay-entitlement policy whether this user may use TURN. The
    // open-source default (`AllowAll`) always allows; a paid build gates on an
    // active subscription + fair-use. A denial is *not* an error — we still hand
    // back STUN so the session can go peer-to-peer — but we annotate the reason
    // so the console can prompt the user to subscribe.
    let decision = state.entitlement.allow_relay(user_id).await;

    let mut servers: Vec<serde_json::Value> = Vec::new();
    let mut relay_denied: Option<&'static str> = None;
    match &state.config.turn {
        Some(turn) => {
            let (host, port) = (&turn.host, turn.port);
            // The coturn STUN endpoint is always safe to hand out (no bandwidth
            // cost); only the relaying `turn:` creds are gated.
            servers.push(serde_json::json!({ "urls": [format!("stun:{host}:{port}")] }));
            if decision.allowed() {
                let expiry = now_unix() as u64 + turn.ttl_secs;
                let username = format!("{expiry}:rmd");
                // HMAC accepts a key of any length, so this never fails.
                let mut mac = Hmac::<Sha1>::new_from_slice(turn.secret.as_bytes())
                    .expect("HMAC accepts keys of any length");
                mac.update(username.as_bytes());
                let credential = base64::engine::general_purpose::STANDARD
                    .encode(mac.finalize().into_bytes());
                servers.push(serde_json::json!({
                    "urls": [
                        format!("turn:{host}:{port}?transport=udp"),
                        format!("turn:{host}:{port}?transport=tcp"),
                    ],
                    "username": username,
                    "credential": credential,
                }));
            } else {
                relay_denied = decision.reason();
            }
        }
        None => {
            servers.push(serde_json::json!({ "urls": ["stun:stun.l.google.com:19302"] }));
        }
    }

    let mut resp = serde_json::json!({ "ice_servers": servers });
    // 402-style hint (kept in the 200 body so STUN-only clients still work):
    // present only when TURN is configured but withheld for this user.
    if let Some(reason) = relay_denied {
        resp["relay"] = serde_json::json!({ "allowed": false, "reason": reason });
    }
    Ok(Json(resp))
}

// --- auth helpers ----------------------------------------------------------

/// Resolve `(username, password)` → user id, verifying the Argon2 hash, with a
/// per-username lockout/backoff on repeated failures.
async fn authenticate_user(state: &AppState, username: &str, password: &str) -> AppResult<i64> {
    if let Err(retry) = state.throttle.check(username) {
        return Err(AppError::TooManyRequests(retry));
    }
    let row: Option<(i64, String)> =
        sqlx::query_as("SELECT id, password_hash FROM users WHERE username = ?")
            .bind(username)
            .fetch_optional(&state.pool)
            .await?;
    match row {
        Some((id, hash)) if auth::verify_password(password, &hash) => {
            state.throttle.record_success(username);
            Ok(id)
        }
        _ => {
            state.throttle.record_failure(username);
            Err(AppError::Unauthorized)
        }
    }
}

/// Require a valid admin bearer token (`RMD_RZ_ADMIN_TOKEN`). When no admin token
/// is configured on the server, the admin API is disabled entirely (Unauthorized).
fn require_admin(state: &AppState, headers: &HeaderMap) -> AppResult<()> {
    let expected = state
        .config
        .admin_token
        .as_deref()
        .ok_or(AppError::Unauthorized)?;
    let presented = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(AppError::Unauthorized)?;
    if ct_eq(presented.as_bytes(), expected.as_bytes()) {
        Ok(())
    } else {
        Err(AppError::Unauthorized)
    }
}

/// Constant-time byte comparison (length may leak; token length is not secret).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Parse an HTTP Basic `Authorization` header into `(username, password)`.
fn basic_auth(headers: &HeaderMap) -> AppResult<(String, String)> {
    let raw = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Basic "))
        .ok_or(AppError::Unauthorized)?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(raw)
        .map_err(|_| AppError::Unauthorized)?;
    let text = String::from_utf8(decoded).map_err(|_| AppError::Unauthorized)?;
    let (user, pass) = text.split_once(':').ok_or(AppError::Unauthorized)?;
    Ok((user.to_string(), pass.to_string()))
}

/// Refresh a device's `last_seen` (a heartbeat while it's connected to `/ws`), so
/// the console/viewer "online" indicator stays accurate for a long-lived host.
pub async fn touch_last_seen(pool: &SqlitePool, device_id: &str) {
    let _ = sqlx::query("UPDATE devices SET last_seen = ? WHERE device_id = ?")
        .bind(now_unix())
        .bind(device_id)
        .execute(pool)
        .await;
}

/// Resolve a device bearer token → the owning account's `user_id`, if the token
/// is valid and unexpired. Also stamps the device's `last_seen`. Used by the ICE
/// endpoint, where the relay-entitlement policy is keyed by user.
pub async fn user_id_for_token(pool: &SqlitePool, token: &str) -> AppResult<Option<i64>> {
    let token_hash = auth::hash_token(token);
    let now = now_unix();
    let row: Option<(i64, i64)> = sqlx::query_as(
        "SELECT d.user_id, d.id \
         FROM device_tokens t JOIN devices d ON d.id = t.device_pk \
         WHERE t.token_hash = ? AND (t.expires_at IS NULL OR t.expires_at > ?)",
    )
    .bind(&token_hash)
    .bind(now)
    .fetch_optional(pool)
    .await?;
    if let Some((user_id, device_pk)) = row {
        sqlx::query("UPDATE devices SET last_seen = ? WHERE id = ?")
            .bind(now)
            .bind(device_pk)
            .execute(pool)
            .await
            .ok();
        Ok(Some(user_id))
    } else {
        Ok(None)
    }
}

/// Resolve a device bearer token → its `device_id`, if valid and unexpired.
/// Also stamps `last_seen`. Used by the signaling WebSocket auth.
pub async fn device_id_for_token(pool: &SqlitePool, token: &str) -> AppResult<Option<String>> {
    let token_hash = auth::hash_token(token);
    let now = now_unix();
    let row: Option<(String, i64)> = sqlx::query_as(
        "SELECT d.device_id, d.id \
         FROM device_tokens t JOIN devices d ON d.id = t.device_pk \
         WHERE t.token_hash = ? AND (t.expires_at IS NULL OR t.expires_at > ?)",
    )
    .bind(&token_hash)
    .bind(now)
    .fetch_optional(pool)
    .await?;
    if let Some((device_id, device_pk)) = row {
        sqlx::query("UPDATE devices SET last_seen = ? WHERE id = ?")
            .bind(now)
            .bind(device_pk)
            .execute(pool)
            .await
            .ok();
        Ok(Some(device_id))
    } else {
        Ok(None)
    }
}
