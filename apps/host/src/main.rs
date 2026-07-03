//! OpenReach host agent (spike). TODO(phase1): capture -> encode -> transport, input injection.
fn main() {
    tracing_subscriber::fmt().with_env_filter(
        tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| "info".into()),
    ).init();
    tracing::info!("openreach-host: scaffold");
}
