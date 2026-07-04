//! OpenReach rendezvous server library.
//!
//! Self-hostable signaling + device registry. The binary ([`main`](../main.rs))
//! is a thin wrapper over [`init_state`] + [`router`]; exposing them as a library
//! lets integration tests start the server in-process.
//!
//! See the crate docs / `docs/vps-deployment.md` for the deployment model.

use axum::routing::{delete, get, post};
use axum::{Json, Router};
use std::sync::Arc;
use tower_governor::governor::GovernorConfigBuilder;
use tower_governor::GovernorLayer;

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

    Router::new()
        .route("/", get(root))
        .route("/health", get(health))
        .route("/api/register", post(api::register_user))
        .route(
            "/api/devices",
            post(api::register_device).get(api::list_devices),
        )
        .route("/api/devices/{device_id}", delete(api::delete_device))
        .route("/ws", get(signaling::ws_handler))
        .layer(GovernorLayer { config: governor })
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

/// The web console (account + device management), embedded in the binary.
async fn root() -> axum::response::Html<&'static str> {
    axum::response::Html(include_str!("console.html"))
}

/// Liveness probe.
async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok", "service": "openreach-rendezvous" }))
}
