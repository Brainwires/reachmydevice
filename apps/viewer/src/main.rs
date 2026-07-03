//! OpenReach viewer (spike). TODO(phase1): transport -> decode -> wgpu render, input capture.
fn main() {
    tracing_subscriber::fmt().with_env_filter(
        tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| "info".into()),
    ).init();
    tracing::info!("openreach-viewer: scaffold");
}
