//! Account & device REST client for the rendezvous server.
//!
//! A small *blocking* HTTP client (built on `ureq`) that the native viewer app
//! uses to sign in, enumerate the user's devices, register **itself** to obtain a
//! signaling bearer token, and remove devices. It is deliberately UI-agnostic and
//! synchronous; the viewer app runs these calls on a background thread so the GUI
//! never blocks on the network.
//!
//! The server's shapes (see `apps/rendezvous/src/api.rs`):
//! - `POST /api/register` `{username, password}` — open account creation.
//! - `POST /api/devices` `{username, password, device_id, name, public_key, role}`
//!   → `{token, device_id}` — register/refresh a device, issuing a bearer token.
//! - `GET /api/devices` (HTTP Basic) → `[DeviceInfo]`.
//! - `DELETE /api/devices/{device_id}` (HTTP Basic).
//!
//! The WebSocket signaling endpoint (`GET /ws?token=…`) lives on the same origin;
//! [`AccountClient::ws_url`] derives it from the one base URL the caller supplies.

use base64::Engine;
use serde::Deserialize;

/// One of the authenticated user's registered devices, as returned by
/// `GET /api/devices`. Mirrors the server's `DeviceRow` JSON.
#[derive(Clone, Debug, Deserialize)]
pub struct DeviceInfo {
    /// Stable device id (public-key fingerprint prefix).
    pub device_id: String,
    /// Human-friendly name chosen at registration.
    pub name: String,
    /// The device identity public key (hex), stored for TOFU display.
    pub public_key: String,
    /// `"host"`, `"viewer"`, or `"both"`.
    pub role: String,
    /// Account/device creation time (unix seconds).
    pub created_at: i64,
    /// Last time the device authenticated to signaling (unix seconds), if ever.
    #[serde(default)]
    pub last_seen: Option<i64>,
}

impl DeviceInfo {
    /// Whether this device can act as a host (i.e. is connectable *to*).
    pub fn is_connectable(&self) -> bool {
        matches!(self.role.as_str(), "host" | "both")
    }
}

/// The `/api/ice` response: ICE servers the rendezvous minted for a device.
#[derive(Deserialize)]
struct IceConfig {
    #[serde(default)]
    ice_servers: Vec<rmd_transport::IceServer>,
}

/// Derive the REST origin (`http(s)://…`) from a `ws(s)://…/ws` signaling URL,
/// so a host/viewer that only knows `RMD_RENDEZVOUS_URL` can reach `/api/ice`.
pub fn rest_base_from_ws(ws_url: &str) -> String {
    let s = ws_url.trim_end_matches('/');
    let s = s.strip_suffix("/ws").unwrap_or(s);
    if let Some(rest) = s.strip_prefix("wss://") {
        format!("https://{rest}")
    } else if let Some(rest) = s.strip_prefix("ws://") {
        format!("http://{rest}")
    } else {
        s.to_string()
    }
}

/// Blocking client for the rendezvous account/device REST API.
///
/// Cheap to [`Clone`] (an `Agent` is a reference-counted connection pool), so it
/// can be handed to a worker thread per request.
#[derive(Clone)]
pub struct AccountClient {
    /// REST origin with any trailing slash trimmed, e.g. `https://host:8443`.
    base: String,
    agent: ureq::Agent,
}

impl AccountClient {
    /// Build a client for a rendezvous server at `base_url`
    /// (e.g. `https://app.reachmy.dev`). The scheme is preserved; a
    /// trailing slash, if present, is trimmed.
    pub fn new(base_url: &str) -> Self {
        Self {
            base: base_url.trim_end_matches('/').to_string(),
            agent: ureq::AgentBuilder::new()
                .timeout_connect(std::time::Duration::from_secs(10))
                .timeout(std::time::Duration::from_secs(20))
                .build(),
        }
    }

    /// The REST base origin (no trailing slash).
    pub fn base_url(&self) -> &str {
        &self.base
    }

    /// Derive the signaling WebSocket URL (`ws(s)://…/ws`) from the REST base.
    ///
    /// `https` maps to `wss` and `http` to `ws`; any other scheme is passed
    /// through unchanged (with `/ws` appended).
    pub fn ws_url(&self) -> String {
        let ws_base = if let Some(rest) = self.base.strip_prefix("https://") {
            format!("wss://{rest}")
        } else if let Some(rest) = self.base.strip_prefix("http://") {
            format!("ws://{rest}")
        } else {
            self.base.clone()
        };
        format!("{ws_base}/ws")
    }

    /// Create a new account. Fails if registration is closed or the name is taken.
    pub fn register(&self, user: &str, pass: &str) -> anyhow::Result<()> {
        let url = format!("{}/api/register", self.base);
        run(self
            .agent
            .post(&url)
            .send_json(ureq::json!({ "username": user, "password": pass })))?;
        Ok(())
    }

    /// Fetch ICE servers (STUN + TURN with ephemeral credentials) minted by the
    /// rendezvous for this device `token` (`GET /api/ice`). Returns an empty list
    /// if the deployment advertises none; errors only on transport/HTTP failure.
    pub fn ice_servers(&self, token: &str) -> anyhow::Result<Vec<rmd_transport::IceServer>> {
        let url = format!("{}/api/ice?token={}", self.base, token);
        let resp = run(self.agent.get(&url).call())?;
        Ok(resp.into_json::<IceConfig>()?.ice_servers)
    }

    /// List the user's registered devices (HTTP Basic auth).
    pub fn list_devices(&self, user: &str, pass: &str) -> anyhow::Result<Vec<DeviceInfo>> {
        let url = format!("{}/api/devices", self.base);
        let resp = run(self
            .agent
            .get(&url)
            .set("Authorization", &basic_auth(user, pass))
            .call())?;
        Ok(resp.into_json::<Vec<DeviceInfo>>()?)
    }

    /// Register (or refresh) a device under this account and return its freshly
    /// issued signaling bearer **token**. `role` is `"host"`, `"viewer"`, or
    /// `"both"`.
    pub fn register_device(
        &self,
        user: &str,
        pass: &str,
        device_id: &str,
        name: &str,
        public_key: &str,
        role: &str,
    ) -> anyhow::Result<String> {
        let url = format!("{}/api/devices", self.base);
        let resp = run(self.agent.post(&url).send_json(ureq::json!({
            "username": user,
            "password": pass,
            "device_id": device_id,
            "name": name,
            "public_key": public_key,
            "role": role,
        })))?;
        #[derive(Deserialize)]
        struct TokenResp {
            token: String,
        }
        Ok(resp.into_json::<TokenResp>()?.token)
    }

    /// Delete a device from the account (HTTP Basic auth).
    pub fn delete_device(&self, user: &str, pass: &str, device_id: &str) -> anyhow::Result<()> {
        let url = format!("{}/api/devices/{device_id}", self.base);
        run(self
            .agent
            .delete(&url)
            .set("Authorization", &basic_auth(user, pass))
            .call())?;
        Ok(())
    }
}

/// Build an HTTP Basic `Authorization` header value from credentials.
fn basic_auth(user: &str, pass: &str) -> String {
    let token = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"));
    format!("Basic {token}")
}

/// Turn a `ureq` result into an `anyhow` one, surfacing HTTP error status codes
/// and the server's error body as a readable message (instead of a bare status).
fn run(result: Result<ureq::Response, ureq::Error>) -> anyhow::Result<ureq::Response> {
    match result {
        Ok(resp) => Ok(resp),
        Err(ureq::Error::Status(code, resp)) => {
            let body = resp.into_string().unwrap_or_default();
            let detail = extract_error(&body);
            anyhow::bail!("server returned HTTP {code}: {detail}")
        }
        Err(ureq::Error::Transport(t)) => {
            anyhow::bail!("could not reach server: {t}")
        }
    }
}

/// Best-effort pull of a human message out of the server's JSON error body,
/// falling back to the raw (trimmed) text.
fn extract_error(body: &str) -> String {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
        for key in ["error", "message", "detail"] {
            if let Some(s) = v.get(key).and_then(|x| x.as_str()) {
                return s.to_string();
            }
        }
    }
    let trimmed = body.trim();
    if trimmed.is_empty() {
        "(no details)".to_string()
    } else {
        trimmed.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ws_url_maps_scheme() {
        assert_eq!(
            AccountClient::new("https://host.example").ws_url(),
            "wss://host.example/ws"
        );
        assert_eq!(
            AccountClient::new("http://127.0.0.1:8080/").ws_url(),
            "ws://127.0.0.1:8080/ws"
        );
    }

    #[test]
    fn base_url_trims_trailing_slash() {
        assert_eq!(
            AccountClient::new("https://host/").base_url(),
            "https://host"
        );
    }

    #[test]
    fn basic_auth_encodes_credentials() {
        // "user:pass" -> base64
        assert_eq!(basic_auth("user", "pass"), "Basic dXNlcjpwYXNz");
    }

    #[test]
    fn connectable_roles() {
        let mk = |role: &str| DeviceInfo {
            device_id: "d".into(),
            name: "n".into(),
            public_key: "k".into(),
            role: role.into(),
            created_at: 0,
            last_seen: None,
        };
        assert!(mk("host").is_connectable());
        assert!(mk("both").is_connectable());
        assert!(!mk("viewer").is_connectable());
    }
}
