//! HTTP API: user registration, device registration (token issuance), and the
//! user-scoped device list.
//!
//! - User-scoped endpoints authenticate with HTTP Basic (`username:password`).
//! - Device registration authenticates the owning user in the body and returns a
//!   long-lived device **bearer token** used for the signaling WebSocket.

use crate::auth;
use crate::db::{now_unix, AppState};
use crate::error::{AppError, AppResult};
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::Json;
use base64::Engine;
use serde::{Deserialize, Serialize};
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
pub async fn register_user(
    State(state): State<AppState>,
    Json(body): Json<RegisterUser>,
) -> AppResult<Json<serde_json::Value>> {
    if !state.config.allow_open_registration {
        return Err(AppError::RegistrationClosed);
    }
    if body.username.trim().is_empty() || body.password.len() < 8 {
        return Err(AppError::BadRequest(
            "username required; password must be at least 8 chars".into(),
        ));
    }
    let hash = auth::hash_password(&body.password).map_err(AppError::Internal)?;
    let res =
        sqlx::query("INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)")
            .bind(&body.username)
            .bind(&hash)
            .bind(now_unix())
            .execute(&state.pool)
            .await;
    match res {
        Ok(_) => Ok(Json(serde_json::json!({ "status": "created" }))),
        // UNIQUE violation → username taken.
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
            Err(AppError::Conflict("username already taken".into()))
        }
        Err(e) => Err(AppError::Db(e)),
    }
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
