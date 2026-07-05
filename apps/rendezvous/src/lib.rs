//! ReachMyDevice rendezvous server library.
//!
//! Self-hostable signaling + device registry. The binary ([`main`](../main.rs))
//! is a thin wrapper over [`init_state`] + [`router`]; exposing them as a library
//! lets integration tests start the server in-process.
//!
//! See the crate docs / `docs/vps-deployment.md` for the deployment model.

use axum::http::{header, HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use std::sync::Arc;
use tower_governor::governor::GovernorConfigBuilder;
use tower_governor::GovernorLayer;
use tower_http::services::ServeDir;

pub mod api;
pub mod auth;
pub mod config;
pub mod db;
pub mod error;
pub mod signaling;
pub mod throttle;

pub use config::Config;
pub use db::AppState;

/// Open + migrate the database and construct shared state.
pub async fn init_state(cfg: Config) -> anyhow::Result<AppState> {
    let pool = db::connect_and_migrate(&cfg.database_url).await?;
    Ok(AppState {
        pool,
        config: Arc::new(cfg),
        hub: Arc::new(signaling::Hub::new()),
        throttle: Arc::new(throttle::LoginThrottle::new()),
    })
}

/// Build the router with all routes + middleware (rate limiting, tracing).
pub fn router(state: AppState) -> Router {
    // Per-IP rate limiting on all routes (protects auth + signaling connect).
    let governor = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(5)
            .burst_size(20)
            .finish()
            .expect("valid governor config"),
    );

    let mut app = Router::new()
        // `/` is host-aware: the apex (reachmy.dev) serves the marketing landing
        // page; `app.reachmy.dev` (and any other host) serves the web console.
        .route("/", get(root))
        .route("/health", get(health))
        // The `curl https://reachmy.dev/install.sh | sh` one-liner.
        .route("/install.sh", get(install_script))
        .route("/api/register", post(api::register_user))
        .route(
            "/api/devices",
            post(api::register_device).get(api::list_devices),
        )
        .route("/api/devices/{device_id}", delete(api::delete_device))
        .route("/ws", get(signaling::ws_handler))
        // Stateless direct-pairing mailbox (no account) — QR/PAKE flow.
        .route("/pair", get(signaling::ws_pair_handler));

    // The WASM/WebGPU browser viewer, served from trunk's `dist/` at `/app` when a
    // built bundle is present (see RMD_WEBVIEWER_DIR). If it isn't built into this
    // deployment, `/app` returns a friendly notice instead of a 404.
    let webviewer_dir =
        std::env::var("RMD_WEBVIEWER_DIR").unwrap_or_else(|_| "web-viewer-dist".to_string());
    app = if std::path::Path::new(&webviewer_dir).is_dir() {
        let serve = ServeDir::new(&webviewer_dir).append_index_html_on_directories(true);
        app.nest_service("/app", serve.clone())
            .nest_service("/app/", serve)
    } else {
        app.route("/app", get(webviewer_unavailable))
            .route("/app/", get(webviewer_unavailable))
    };

    app.layer(GovernorLayer { config: governor })
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(state)
}

/// Serve the app on an already-bound listener (keeps `axum` out of callers).
pub async fn serve(state: AppState, listener: tokio::net::TcpListener) -> anyhow::Result<()> {
    let app = router(state);
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;
    Ok(())
}

/// Host-aware `/`: the apex domain gets the public landing page; every other host
/// (the `app.` console subdomain, localhost, an IP) gets the web console.
async fn root(headers: HeaderMap) -> axum::response::Html<&'static str> {
    let host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if is_apex_host(host) {
        axum::response::Html(include_str!("landing.html"))
    } else {
        axum::response::Html(include_str!("console.html"))
    }
}

/// Whether a `Host` header names the bare apex domain (landing page), as opposed
/// to the `app.` console subdomain. Port and case are ignored.
fn is_apex_host(host: &str) -> bool {
    let h = host.split(':').next().unwrap_or("").to_ascii_lowercase();
    matches!(h.as_str(), "reachmy.dev" | "www.reachmy.dev")
}

/// Serve the host install one-liner script (`curl https://reachmy.dev/install.sh`).
async fn install_script() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/x-shellscript; charset=utf-8")],
        include_str!("../../../deploy/release/install.sh"),
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
