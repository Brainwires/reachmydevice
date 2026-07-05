//! ReachMyDevice rendezvous server (Phase 2) — binary entrypoint.
//!
//! Thin wrapper over the [`rmd_rendezvous`] library. Config is via
//! environment (see [`rmd_rendezvous::Config`]).

use rmd_rendezvous::{init_state, serve, Config};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,rmd_rendezvous=debug".into()),
        )
        .init();

    let cfg = Config::from_env();
    let addr = cfg.bind_addr;
    let state = init_state(cfg).await?;

    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "ReachMyDevice rendezvous listening");
    serve(state, listener).await
}
