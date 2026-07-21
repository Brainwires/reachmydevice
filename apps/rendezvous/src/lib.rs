//! ReachMyDevice rendezvous server library.
//!
//! Self-hostable signaling + device registry. The binary ([`main`](../main.rs))
//! is a thin wrapper over [`init_state`] + [`router`]; exposing them as a library
//! lets integration tests start the server in-process.
//!
//! See the crate docs / `docs/vps-deployment.md` for the deployment model.

use axum::http::{HeaderMap, StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use std::sync::Arc;
use tower_governor::GovernorLayer;
use tower_governor::governor::GovernorConfigBuilder;
use tower_http::services::ServeDir;

pub mod api;
pub mod auth;
pub mod config;
pub mod db;
pub mod error;
pub mod resolver;
pub mod security;
pub mod signaling;
pub mod throttle;
#[cfg(feature = "passkeys")]
pub mod webauthn;

pub use config::Config;
pub use db::AppState;
// The relay-entitlement seam. The default is open (`allow_all`); a private paid
// build injects its own policy via `AppState::new` + `router_with`.
pub use rmd_entitlement::{BoxFuture, RelayDecision, RelayEntitlement, allow_all};
// The credential-resolution + session-observation seams. The defaults accept
// device tokens only and observe nothing; a paid build overrides the `AppState`
// fields to also accept member JWTs and persist activity.
pub use resolver::{CredentialResolver, DeviceTokenResolver, ResolvedCredential, SessionObserver};

/// Open the SQLite pool, run migrations, and seed runtime settings.
///
/// Split out from [`init_state`] so a paid build can open the pool, hand it to
/// its own entitlement provider, and assemble state via [`AppState::new`].
pub async fn open_pool(cfg: &Config) -> anyhow::Result<sqlx::SqlitePool> {
    let pool = db::connect_and_migrate(&cfg.database_url).await?;
    // Seed runtime settings (e.g. open_registration) from env defaults on first
    // boot, without clobbering operator changes.
    db::seed_settings(&pool, cfg).await?;
    Ok(pool)
}

/// Open + migrate the database and construct shared state with the **default,
/// open** relay policy. Paid builds compose the pieces themselves instead (see
/// [`open_pool`] + [`AppState::new`] + [`router_with`]).
pub async fn init_state(cfg: Config) -> anyhow::Result<AppState> {
    let pool = open_pool(&cfg).await?;
    Ok(AppState::new(pool, cfg, allow_all()))
}

/// Build the router with all routes + middleware (rate limiting, tracing).
pub fn router(state: AppState) -> Router {
    router_with(state, Router::new())
}

/// Like [`router`], but merges an `extra` set of already-stateful routes a
/// private plugin supplies (e.g. Stripe checkout/webhook/portal). The extra
/// routes sit behind the same rate-limit / auth-logging / tracing layers.
pub fn router_with(state: AppState, extra: Router) -> Router {
    // Config needed by the shared layers before `state` is moved into the router.
    let trusted_header: Option<Arc<str>> =
        state.config.trusted_proxy_header.as_deref().map(Arc::from);
    let cfg = state.config.clone();

    // Per-IP rate limiting on all routes (protects auth + signaling connect),
    // keyed by the *trust-resolved* client IP so it's a real per-client limit
    // rather than one global bucket behind the ingress proxy.
    let governor = Arc::new(
        GovernorConfigBuilder::default()
            // Replenish 1 token/sec (was 1 per 5s) with a 60-token burst (was 20).
            // This budget now guards ONLY the auth/signaling/API surface — the static
            // web-viewer bundle is mounted OUTSIDE it (below), so a page load no longer
            // spends a dozen tokens on WASM/JS/icon fetches. Login brute-force is
            // separately bounded by the per-username `throttle`, so this can be generous.
            .per_second(1)
            .burst_size(60)
            .key_extractor(security::TrustedIpKeyExtractor {
                trusted_header: trusted_header.clone(),
            })
            .finish()
            .expect("valid governor config"),
    );

    // Sensitive surface — auth, device management, ICE/TURN creds, signaling. The
    // per-IP GovernorLayer wraps ONLY this router; the static web-viewer bundle is
    // mounted afterwards so its many asset fetches never touch the rate budget.
    let limited = Router::new()
        // `/` is host-aware: the apex (reachmy.dev) serves the marketing landing
        // page; `app.reachmy.dev` (and any other host) serves the web console.
        .route("/", get(root))
        .route("/health", get(health))
        // The `curl https://reachmy.dev/install.sh | sh` one-liner.
        .route("/install.sh", get(install_script))
        .route("/api/register", post(api::register_user))
        // Public: whether new-account signup is currently open (for UI + ops).
        .route("/api/registration", get(api::get_registration))
        // Admin: flip signup open/closed at runtime (RMD_RZ_ADMIN_TOKEN bearer).
        .route("/api/admin/registration", post(api::set_registration))
        .route(
            "/api/devices",
            post(api::register_device).get(api::list_devices),
        )
        .route(
            "/api/devices/{device_id}",
            delete(api::delete_device).patch(api::rename_device),
        )
        // ICE/TURN servers (STUN + ephemeral coturn creds) for an authed device.
        .route("/api/ice", get(api::ice_servers))
        // One-time WebSocket ticket (keeps bearer tokens out of `/ws?…` URLs).
        .route("/api/ws-ticket", get(api::ws_ticket))
        .route("/ws", get(signaling::ws_handler))
        // Stateless direct-pairing mailbox (no account) — QR/PAKE flow.
        .route("/pair", get(signaling::ws_pair_handler));

    // Passkey (WebAuthn) sign-in routes — only compiled with `--features passkeys`,
    // and further gated at runtime by `RMD_RZ_WEBAUTHN_*` (unset ⇒ handlers 404).
    #[cfg(feature = "passkeys")]
    let limited = limited
        .route(
            "/api/webauthn/register/start",
            post(webauthn::register_start),
        )
        .route(
            "/api/webauthn/register/finish",
            post(webauthn::register_finish),
        )
        .route("/api/webauthn/login/start", post(webauthn::login_start))
        .route("/api/webauthn/login/finish", post(webauthn::login_finish))
        .route("/api/webauthn/credentials", get(webauthn::list_credentials))
        .route(
            "/api/webauthn/credentials/delete",
            post(webauthn::delete_credential),
        );

    // Bind the core state (Router<AppState> → Router<()>), merge the plugin's
    // already-stateful routes, then apply the auth log + per-IP rate limiter.
    let limited = limited
        .with_state(state)
        .merge(extra)
        .layer(axum::middleware::from_fn_with_state(
            cfg,
            security::log_auth_failures,
        ))
        .layer(GovernorLayer { config: governor });

    // The WASM/WebGPU browser viewer, served from trunk's `dist/` at `/app` when a
    // built bundle is present (see RMD_WEBVIEWER_DIR). A single page load pulls a
    // dozen static files (WASM, JS, index.html, ext.js, icons, manifest, favicons);
    // mounting it AFTER the GovernorLayer keeps those asset fetches OUT of the per-IP
    // rate budget — otherwise a couple of refreshes exhaust the burst meant to guard
    // the auth/signaling endpoints and the whole app starts returning 429s. If no
    // bundle is built into this deployment, `/app` returns a friendly notice.
    let webviewer_dir =
        std::env::var("RMD_WEBVIEWER_DIR").unwrap_or_else(|_| "web-viewer-dist".to_string());
    let app = if std::path::Path::new(&webviewer_dir).is_dir() {
        // One nest_service serves `/app` and everything under `/app/…`.
        let serve = ServeDir::new(&webviewer_dir).append_index_html_on_directories(true);
        limited.nest_service("/app", serve)
    } else {
        limited
            .route("/app", get(webviewer_unavailable))
            .route("/app/", get(webviewer_unavailable))
    };

    app.layer(tower_http::trace::TraceLayer::new_for_http())
}

/// Serve the app on an already-bound listener (keeps `axum` out of callers).
pub async fn serve(state: AppState, listener: tokio::net::TcpListener) -> anyhow::Result<()> {
    serve_router(router(state), listener).await
}

/// Serve an already-built router (used by a paid build that composed its own
/// routes via [`router_with`]).
pub async fn serve_router(app: Router, listener: tokio::net::TcpListener) -> anyhow::Result<()> {
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;
    Ok(())
}

/// Host-aware `/`: the apex domain gets the public landing page; every other host
/// (the `app.` subdomain, localhost, an IP) is redirected to the web app at
/// `/app/` — the WASM viewer, which is now the single sign-in / device-management
/// / connect UI. It supersedes the old static `console.html` (kept in the tree
/// only for reference; it lacked the browser Connect flow).
async fn root(headers: HeaderMap) -> axum::response::Response {
    let host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if is_apex_host(host) {
        axum::response::Html(landing_html()).into_response()
    } else {
        axum::response::Redirect::temporary("/app/").into_response()
    }
}

/// The landing-page HTML. If `RMD_LANDING_FILE` is set and readable, it's served
/// from there (so the page can be updated by swapping a bind-mounted file — no
/// rebuild, mirroring how `RMD_WEBVIEWER_DIR` hot-swaps `/app`); otherwise the
/// copy embedded at build time. Read per request — the apex page is low-traffic.
fn landing_html() -> String {
    if let Ok(path) = std::env::var("RMD_LANDING_FILE") {
        if let Ok(contents) = std::fs::read_to_string(&path) {
            return contents;
        }
        tracing::warn!(%path, "RMD_LANDING_FILE unreadable; using embedded landing page");
    }
    include_str!("landing.html").to_string()
}

/// Whether a `Host` header names the bare apex domain (landing page), as opposed
/// to the `app.` console subdomain. Port and case are ignored.
fn is_apex_host(host: &str) -> bool {
    let h = host.split(':').next().unwrap_or("").to_ascii_lowercase();
    matches!(h.as_str(), "reachmy.dev" | "www.reachmy.dev")
}

/// Serve the host install one-liner script (`curl https://reachmy.dev/install.sh`).
///
/// Reads `RMD_INSTALL_SH` (a mounted file) if set + readable, so the script can be
/// updated without rebuilding the binary; otherwise falls back to the version
/// compiled in at build time.
async fn install_script() -> impl IntoResponse {
    let body = std::env::var("RMD_INSTALL_SH")
        .ok()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .unwrap_or_else(|| include_str!("../../../deploy/release/install.sh").to_string());
    (
        [(header::CONTENT_TYPE, "text/x-shellscript; charset=utf-8")],
        body,
    )
}

/// Placeholder when the web-viewer bundle wasn't built into this deployment.
async fn webviewer_unavailable() -> impl IntoResponse {
    (
        StatusCode::NOT_FOUND,
        axum::response::Html(
            "<!doctype html><meta charset=utf-8><title>Web viewer</title>\
             <body style=\"font:16px system-ui;max-width:40rem;margin:4rem auto;padding:0 1rem\">\
             <h1>Web viewer not installed</h1><p>This ReachMyDevice deployment was built \
             without the WASM web viewer bundle. Build it with <code>trunk build --release</code> \
             in <code>apps/web-viewer</code> and set <code>RMD_WEBVIEWER_DIR</code>, or use the \
             native app from <a href=\"https://github.com/Brainwires/reachmydevice/releases\">Releases</a>.</p>",
        ),
    )
}

/// Liveness probe.
async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok", "service": "rmd-rendezvous" }))
}
