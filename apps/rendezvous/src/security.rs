//! Security-event logging for external hardening (e.g. fail2ban).
//!
//! Emits a stable, greppable log line on every authentication failure so an
//! operator can ban abusive source IPs at the firewall. This complements — it
//! does not replace — the in-process rate limiter (`tower_governor`) and the
//! per-account login throttle (`throttle`).
//!
//! Scope: this hardens the **auth-abuse** surface (bad tokens/passwords hammering
//! the API and `/ws`). It is **not** a volumetric-DDoS mitigation — a bandwidth
//! flood saturates the link upstream of any host-level firewall rule.
//!
//! The line format is intentionally fixed (`ship deploy/fail2ban/` matches it):
//!
//! ```text
//! <ts>  WARN rmd_security: auth-fail ip=<client-ip> path=<path> method=<method>
//! ```

use axum::extract::{ConnectInfo, Request};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use std::net::SocketAddr;

/// Best-effort real client IP. Behind Cloudflare/Caddy the socket peer is the
/// proxy, so prefer the forwarded headers (set by the trusted reverse proxy);
/// fall back to the connection's peer address.
pub fn client_ip(headers: &HeaderMap, peer: Option<SocketAddr>) -> String {
    let first_header = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    };
    first_header("cf-connecting-ip")
        .or_else(|| first_header("x-forwarded-for"))
        .or_else(|| first_header("x-real-ip"))
        .unwrap_or_else(|| peer.map(|p| p.ip().to_string()).unwrap_or_else(|| "-".into()))
}

/// Middleware: log a `rmd_security` warning for any `401 Unauthorized` response
/// (bad device token on `/ws` or `/api/ice`, bad HTTP Basic on the account API).
pub async fn log_auth_failures(req: Request, next: Next) -> Response {
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0);
    let ip = client_ip(req.headers(), peer);
    let path = req.uri().path().to_string();
    let method = req.method().clone();

    let resp = next.run(req).await;

    if resp.status() == StatusCode::UNAUTHORIZED {
        tracing::warn!(target: "rmd_security", "auth-fail ip={ip} path={path} method={method}");
    }
    resp
}
