//! Pluggable credential resolution for the device-facing endpoints.
//!
//! The device-facing endpoints (`/api/ice`, `/api/ws-ticket`, `/ws`) authenticate
//! a presented bearer credential and resolve it to an identity. By default that is
//! a device token — the open-source behavior. A private plugin can inject a
//! [`CredentialResolver`] that *additionally* accepts other credentials (e.g.
//! tenant-signed member JWTs) without forking the core, by overriding the field on
//! [`crate::AppState`] after construction.
//!
//! Like [`rmd_entitlement::RelayEntitlement`], the trait returns a boxed future so
//! it stays object-safe (`dyn CredentialResolver`) with no proc-macro dependency.

use crate::api;
use rmd_entitlement::BoxFuture;
use sqlx::SqlitePool;

/// An identity resolved from a presented bearer credential.
#[derive(Clone, Debug)]
pub struct ResolvedCredential {
    /// Attribution / entitlement key. For a device token this is the owning
    /// `user_id`; for a tenant member JWT it is the platform account's admin
    /// `user_id` (so relay usage + billing roll up to the account).
    pub user_id: i64,
    /// The signaling address used as the [`crate::signaling::Hub`] peer key
    /// (analogous to `device_id`). For a device token this is its `device_id`;
    /// for a member JWT it is a namespaced id such as `t:<account_id>:<sub>`.
    pub signaling_id: String,
}

/// Resolves a raw bearer credential to a [`ResolvedCredential`], or `None` to
/// reject it (the caller returns 401). Injected via [`crate::AppState`]; the
/// open-source default is [`DeviceTokenResolver`].
pub trait CredentialResolver: Send + Sync {
    /// Resolve `bearer`. A resolver that doesn't recognize the credential should
    /// return `None` (or fall through to device tokens) rather than erroring.
    fn resolve<'a>(
        &'a self,
        pool: &'a SqlitePool,
        bearer: &'a str,
    ) -> BoxFuture<'a, Option<ResolvedCredential>>;
}

/// The open-source default: device tokens only. Behaves exactly as the pre-seam
/// code did — a single indexed `device_tokens` lookup that also stamps `last_seen`.
/// A DB error resolves to `None` (fail-closed → 401) rather than a 500; the auth
/// path prefers denial to leaking a server error.
pub struct DeviceTokenResolver;

impl CredentialResolver for DeviceTokenResolver {
    fn resolve<'a>(
        &'a self,
        pool: &'a SqlitePool,
        bearer: &'a str,
    ) -> BoxFuture<'a, Option<ResolvedCredential>> {
        Box::pin(async move {
            match api::resolve_device_token(pool, bearer).await {
                Ok(Some((user_id, device_id))) => Some(ResolvedCredential {
                    user_id,
                    signaling_id: device_id,
                }),
                _ => None,
            }
        })
    }
}

/// Observes the signaling session lifecycle (connect / disconnect) so a plugin can
/// persist per-account activity. The default is `None` (no observer).
///
/// Callbacks fire on the socket's async task, so they **must not block**: a plugin
/// implementation should offload any I/O (e.g. `tokio::spawn` a DB write, or push
/// onto a channel drained elsewhere).
pub trait SessionObserver: Send + Sync {
    fn on_connect(&self, user_id: i64, signaling_id: &str);
    fn on_disconnect(&self, user_id: i64, signaling_id: &str);
}
