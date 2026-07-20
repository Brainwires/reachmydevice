//! WebAuthn (passkey) sign-in — compiled only under the `passkeys` feature.
//!
//! Passwordless console login: a signed-in user registers a passkey, then can
//! authenticate with it later; a verified assertion mints a session token (see
//! [`crate::api::mint_user_session`]) that the console uses as a Bearer.
//!
//! Active only when `RMD_RZ_WEBAUTHN_RP_ID` + `RMD_RZ_WEBAUTHN_ORIGIN` are set —
//! otherwise [`from_env`] returns `None` and the routes 404, so an unconfigured
//! deployment behaves exactly as before.

use crate::api;
use crate::db::AppState;
use crate::error::{AppError, AppResult};
use axum::Json;
use axum::extract::State;
use axum::http::HeaderMap;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use webauthn_rs::prelude::*;

/// Build a [`Webauthn`] from env, or `None` when passkeys aren't configured.
pub fn from_env() -> Option<Arc<Webauthn>> {
    let rp_id = std::env::var("RMD_RZ_WEBAUTHN_RP_ID")
        .ok()
        .filter(|s| !s.is_empty())?;
    let origin = std::env::var("RMD_RZ_WEBAUTHN_ORIGIN")
        .ok()
        .filter(|s| !s.is_empty())?;
    let origin = match Url::parse(&origin) {
        Ok(u) => u,
        Err(e) => {
            tracing::error!(error = %e, "RMD_RZ_WEBAUTHN_ORIGIN is not a valid URL; passkeys disabled");
            return None;
        }
    };
    let mut b = match WebauthnBuilder::new(&rp_id, &origin) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(error = %e, "invalid webauthn config; passkeys disabled");
            return None;
        }
    };
    // Optional extra allowed origins (e.g. the apex + `app.` subdomain), CSV.
    if let Ok(extra) = std::env::var("RMD_RZ_WEBAUTHN_EXTRA_ORIGINS") {
        for o in extra.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            if let Ok(u) = Url::parse(o) {
                b = b.append_allowed_origin(&u);
            }
        }
    }
    match b.rp_name("ReachMyDevice").build() {
        Ok(w) => {
            tracing::info!(rp_id, "passkeys enabled");
            Some(Arc::new(w))
        }
        Err(e) => {
            tracing::error!(error = %e, "webauthn build failed; passkeys disabled");
            None
        }
    }
}

const CH_TTL: Duration = Duration::from_secs(300);

/// In-memory store of in-progress ceremony state, keyed by an opaque id returned
/// to the client between the start and finish calls (single-use, short TTL).
#[derive(Default)]
pub struct ChallengeStore {
    reg: Mutex<HashMap<String, (i64, PasskeyRegistration, Instant)>>,
    auth: Mutex<HashMap<String, (i64, PasskeyAuthentication, Instant)>>,
}

impl ChallengeStore {
    fn put_reg(&self, uid: i64, s: PasskeyRegistration) -> String {
        let id = crate::auth::generate_token();
        let now = Instant::now();
        let mut m = self.reg.lock().unwrap();
        m.retain(|_, (_, _, e)| *e > now);
        m.insert(id.clone(), (uid, s, now + CH_TTL));
        id
    }
    fn take_reg(&self, id: &str) -> Option<(i64, PasskeyRegistration)> {
        let mut m = self.reg.lock().unwrap();
        m.remove(id)
            .filter(|(_, _, e)| *e > Instant::now())
            .map(|(u, s, _)| (u, s))
    }
    fn put_auth(&self, uid: i64, s: PasskeyAuthentication) -> String {
        let id = crate::auth::generate_token();
        let now = Instant::now();
        let mut m = self.auth.lock().unwrap();
        m.retain(|_, (_, _, e)| *e > now);
        m.insert(id.clone(), (uid, s, now + CH_TTL));
        id
    }
    fn take_auth(&self, id: &str) -> Option<(i64, PasskeyAuthentication)> {
        let mut m = self.auth.lock().unwrap();
        m.remove(id)
            .filter(|(_, _, e)| *e > Instant::now())
            .map(|(u, s, _)| (u, s))
    }
}

fn wa_err(e: WebauthnError) -> AppError {
    tracing::warn!(error = %e, "webauthn ceremony error");
    AppError::BadRequest("passkey verification failed".into())
}

fn cred_id_b64(id: &CredentialID) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(id.as_ref())
}

fn ser_err<E: std::fmt::Display>(e: E) -> AppError {
    AppError::Internal(anyhow::anyhow!("passkey (de)serialize: {e}"))
}

fn webauthn(state: &AppState) -> AppResult<&Webauthn> {
    state.webauthn.as_deref().ok_or(AppError::NotFound)
}

async fn username_of(pool: &sqlx::SqlitePool, user_id: i64) -> AppResult<String> {
    let row: Option<(String,)> = sqlx::query_as("SELECT username FROM users WHERE id = ?")
        .bind(user_id)
        .fetch_optional(pool)
        .await?;
    row.map(|(u,)| u).ok_or(AppError::Unauthorized)
}

async fn load_passkeys(pool: &sqlx::SqlitePool, user_id: i64) -> AppResult<Vec<Passkey>> {
    let rows: Vec<(String,)> =
        sqlx::query_as("SELECT passkey FROM webauthn_credentials WHERE user_id = ?")
            .bind(user_id)
            .fetch_all(pool)
            .await?;
    Ok(rows
        .into_iter()
        .filter_map(|(j,)| serde_json::from_str(&j).ok())
        .collect())
}

// --- registration (requires an existing signed-in session) -----------------

/// `POST /api/webauthn/register/start` — begin adding a passkey to the caller's
/// account. Returns the creation options + a one-time ceremony `state` id.
pub async fn register_start(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<serde_json::Value>> {
    let wa = webauthn(&state)?;
    let user_id = api::authed_user(&state, &headers).await?;
    let username = username_of(&state.pool, user_id).await?;
    let uuid = Uuid::from_u128(user_id as u64 as u128);
    let existing: Vec<CredentialID> = load_passkeys(&state.pool, user_id)
        .await?
        .iter()
        .map(|p| p.cred_id().clone())
        .collect();
    let exclude = if existing.is_empty() {
        None
    } else {
        Some(existing)
    };
    let (ccr, reg) = wa
        .start_passkey_registration(uuid, &username, &username, exclude)
        .map_err(wa_err)?;
    let id = state.webauthn_reg.put_reg(user_id, reg);
    Ok(Json(serde_json::json!({ "state": id, "options": ccr })))
}

#[derive(Deserialize)]
pub struct RegisterFinish {
    state: String,
    #[serde(default)]
    name: Option<String>,
    credential: RegisterPublicKeyCredential,
}

/// `POST /api/webauthn/register/finish` — verify + store the new passkey.
pub async fn register_finish(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<RegisterFinish>,
) -> AppResult<Json<serde_json::Value>> {
    let wa = webauthn(&state)?;
    let user_id = api::authed_user(&state, &headers).await?;
    let (owner, reg) = state
        .webauthn_reg
        .take_reg(&body.state)
        .ok_or(AppError::Unauthorized)?;
    if owner != user_id {
        return Err(AppError::Unauthorized);
    }
    let passkey = wa
        .finish_passkey_registration(&body.credential, &reg)
        .map_err(wa_err)?;
    let cred_id = cred_id_b64(passkey.cred_id());
    let json = serde_json::to_string(&passkey).map_err(ser_err)?;
    let name = body
        .name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    sqlx::query(
        "INSERT INTO webauthn_credentials (user_id, credential_id, passkey, name, created_at) \
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(user_id)
    .bind(&cred_id)
    .bind(&json)
    .bind(name)
    .bind(crate::db::now_unix())
    .execute(&state.pool)
    .await?;
    Ok(Json(serde_json::json!({ "status": "registered" })))
}

// --- authentication (passwordless login) -----------------------------------

#[derive(Deserialize)]
pub struct LoginStart {
    username: String,
}

/// `POST /api/webauthn/login/start` — begin a passkey login for `username`.
pub async fn login_start(
    State(state): State<AppState>,
    Json(body): Json<LoginStart>,
) -> AppResult<Json<serde_json::Value>> {
    let wa = webauthn(&state)?;
    let row: Option<(i64,)> = sqlx::query_as("SELECT id FROM users WHERE username = ?")
        .bind(&body.username)
        .fetch_optional(&state.pool)
        .await?;
    let user_id = row.map(|(u,)| u).ok_or(AppError::Unauthorized)?;
    let passkeys = load_passkeys(&state.pool, user_id).await?;
    if passkeys.is_empty() {
        return Err(AppError::Unauthorized);
    }
    let (rcr, auth) = wa.start_passkey_authentication(&passkeys).map_err(wa_err)?;
    let id = state.webauthn_reg.put_auth(user_id, auth);
    Ok(Json(serde_json::json!({ "state": id, "options": rcr })))
}

#[derive(Deserialize)]
pub struct LoginFinish {
    state: String,
    credential: PublicKeyCredential,
}

/// `POST /api/webauthn/login/finish` — verify the assertion and mint a session
/// token the console uses as `Authorization: Bearer`.
pub async fn login_finish(
    State(state): State<AppState>,
    Json(body): Json<LoginFinish>,
) -> AppResult<Json<serde_json::Value>> {
    let wa = webauthn(&state)?;
    let (user_id, auth) = state
        .webauthn_reg
        .take_auth(&body.state)
        .ok_or(AppError::Unauthorized)?;
    let result = wa
        .finish_passkey_authentication(&body.credential, &auth)
        .map_err(wa_err)?;
    let cid = cred_id_b64(result.cred_id());
    if result.needs_update() {
        // Persist the advanced sign counter for the credential that authenticated.
        if let Some((j,)) = sqlx::query_as::<_, (String,)>(
            "SELECT passkey FROM webauthn_credentials WHERE user_id = ? AND credential_id = ?",
        )
        .bind(user_id)
        .bind(&cid)
        .fetch_optional(&state.pool)
        .await?
            && let Ok(mut pk) = serde_json::from_str::<Passkey>(&j)
        {
            pk.update_credential(&result);
            if let Ok(nj) = serde_json::to_string(&pk) {
                let _ = sqlx::query(
                    "UPDATE webauthn_credentials SET passkey = ?, last_used_at = ? \
                     WHERE user_id = ? AND credential_id = ?",
                )
                .bind(&nj)
                .bind(crate::db::now_unix())
                .bind(user_id)
                .bind(&cid)
                .execute(&state.pool)
                .await;
            }
        }
    } else {
        let _ = sqlx::query(
            "UPDATE webauthn_credentials SET last_used_at = ? \
             WHERE user_id = ? AND credential_id = ?",
        )
        .bind(crate::db::now_unix())
        .bind(user_id)
        .bind(&cid)
        .execute(&state.pool)
        .await;
    }
    let session = api::mint_user_session(&state.pool, user_id).await?;
    let username = username_of(&state.pool, user_id).await?;
    Ok(Json(
        serde_json::json!({ "session": session, "username": username }),
    ))
}

// --- credential management -------------------------------------------------

/// `GET /api/webauthn/credentials` — list the caller's registered passkeys.
pub async fn list_credentials(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<serde_json::Value>> {
    webauthn(&state)?;
    let user_id = api::authed_user(&state, &headers).await?;
    let rows: Vec<(i64, Option<String>, i64, Option<i64>)> = sqlx::query_as(
        "SELECT id, name, created_at, last_used_at FROM webauthn_credentials \
         WHERE user_id = ? ORDER BY created_at",
    )
    .bind(user_id)
    .fetch_all(&state.pool)
    .await?;
    let creds: Vec<_> = rows
        .into_iter()
        .map(|(id, name, created, last)| {
            serde_json::json!({ "id": id, "name": name, "created_at": created, "last_used_at": last })
        })
        .collect();
    Ok(Json(serde_json::json!({ "credentials": creds })))
}

#[derive(Deserialize)]
pub struct DeleteCred {
    id: i64,
}

/// `POST /api/webauthn/credentials/delete` — remove one of the caller's passkeys.
pub async fn delete_credential(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(b): Json<DeleteCred>,
) -> AppResult<Json<serde_json::Value>> {
    webauthn(&state)?;
    let user_id = api::authed_user(&state, &headers).await?;
    let res = sqlx::query("DELETE FROM webauthn_credentials WHERE id = ? AND user_id = ?")
        .bind(b.id)
        .bind(user_id)
        .execute(&state.pool)
        .await?;
    if res.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    Ok(Json(serde_json::json!({ "deleted": b.id })))
}
