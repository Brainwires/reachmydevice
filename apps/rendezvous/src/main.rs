//! OpenReach rendezvous server (Phase 2).
//!
//! Self-hostable signaling + device registry for a 1 vCPU / 1 GB VPS:
//! - an account model (users own device lists; devices authenticate with tokens),
//! - a WebSocket signaling relay that pairs a viewer with a host and forwards
//!   opaque SDP/ICE between them (it never sees session plaintext — media/data
//!   are DTLS-SRTP end-to-end encrypted),
//! - and, alongside coturn in the docker-compose, STUN/TURN for NAT traversal.
//!
//! Config is via environment (see [`config::Config`]).

use axum::routing::{delete, get, post};
use axum::{Json, Router};
use std::net::SocketAddr;
use std::sync::Arc;
use tower_governor::governor::GovernorConfigBuilder;
use tower_governor::GovernorLayer;

mod api;
mod auth;
mod config;
mod db;
mod error;
mod signaling;

use config::Config;
use db::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,openreach_rendezvous=debug".into()),
        )
        .init();

    let cfg = Config::from_env();
    let pool = db::connect_and_migrate(&cfg.database_url).await?;
    let state = AppState {
        pool,
        config: Arc::new(cfg.clone()),
        hub: Arc::new(signaling::Hub::new()),
    };

    // Per-IP rate limiting on all routes (protects auth + signaling connect).
    let governor = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(5)
            .burst_size(20)
            .finish()
            .expect("valid governor config"),
    );

    let app = Router::new()
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
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(cfg.bind_addr).await?;
    tracing::info!(addr = %cfg.bind_addr, "OpenReach rendezvous listening");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

/// Liveness probe.
async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok", "service": "openreach-rendezvous" }))
}
