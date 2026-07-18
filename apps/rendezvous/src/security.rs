//! Security-event logging + trusted-proxy client-IP resolution.
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

use crate::config::Config;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use std::net::SocketAddr;
use std::sync::Arc;
use tower_governor::key_extractor::KeyExtractor;
use tower_governor::GovernorError;

/// Real client IP, resolved under an explicit trust model (fixes the
/// spoofable-`X-Forwarded-For` problem):
///
/// - `trusted_header = Some(name)` — the deployment sits behind a trusted ingress
///   (Cloudflare tunnel / nginx) that overwrites `name` (e.g. `cf-connecting-ip`)
///   with the authentic client IP. Use it; fall back to the socket peer if absent.
/// - `trusted_header = None` — trust **nothing** from headers; use the socket peer
///   only. A client-supplied `X-Forwarded-For` can no longer forge the IP used for
///   logging/fail2ban or dodge the rate limiter.
pub fn client_ip(
    headers: &HeaderMap,
    peer: Option<SocketAddr>,
    trusted_header: Option<&str>,
) -> String {
    if let Some(name) = trusted_header {
        if let Some(ip) = headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
        {
            return ip.to_string();
        }
    }
    peer.map(|p| p.ip().to_string())
        .unwrap_or_else(|| "-".into())
}

/// `tower_governor` key extractor that buckets by the trust-resolved client IP
/// (see [`client_ip`]). Without this, the default peer-IP extractor buckets every
/// request behind the ingress under one key — a single global bucket that both
/// DoSes legitimate users and gives an attacker no real per-client limit.
#[derive(Clone)]
pub struct TrustedIpKeyExtractor {
    /// Lower-cased trusted forwarding header name, or `None` for peer-IP only.
    pub trusted_header: Option<Arc<str>>,
}

impl KeyExtractor for TrustedIpKeyExtractor {
    type Key = String;

    fn extract<T>(&self, req: &Request<T>) -> Result<Self::Key, GovernorError> {
        let peer = req
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|c| c.0);
        Ok(client_ip(
            req.headers(),
            peer,
            self.trusted_header.as_deref(),
        ))
    }
}

/// Middleware: log a `rmd_security` warning for any `401 Unauthorized` response
/// (bad device token on `/ws` or `/api/ice`, bad HTTP Basic on the account API).
pub async fn log_auth_failures(
    State(config): State<Arc<Config>>,
    req: Request,
    next: Next,
) -> Response {
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0);
    let ip = client_ip(req.headers(), peer, config.trusted_proxy_header.as_deref());
    let path = req.uri().path().to_string();
    let method = req.method().clone();

    let resp = next.run(req).await;

    if resp.status() == StatusCode::UNAUTHORIZED {
        tracing::warn!(target: "rmd_security", "auth-fail ip={ip} path={path} method={method}");
    }
    resp
}
