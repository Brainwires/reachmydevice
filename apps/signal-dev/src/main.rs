//! OpenReach dev signaling helper (spike only): relays SDP/ICE between two LAN peers. TODO(phase1).
fn main() {
    tracing_subscriber::fmt().with_env_filter(
        tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| "info".into()),
    ).init();
    tracing::info!("openreach-signal-dev: scaffold");
}
