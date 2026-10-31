//! WebSocket signaling: authenticate a device, then relay opaque SDP/ICE to a
//! named peer device.
//!
//! The server routes signaling **metadata** (offer/answer/ICE) between two paired
//! devices; it never sees session **content** — screen/input/files travel over
//! DTLS-SRTP end-to-end, so even the TURN relay only ever handles ciphertext.
//!
//! ## Wire protocol (JSON text frames)
//! Client → server: `{"to":"<device_id>","payload":<opaque>}` — relay `payload`
//! to device `<device_id>`.
//! Server → client: `{"from":"<device_id>","payload":<opaque>}` — an incoming
//! relayed payload; or `{"error":"..."}`.
//!
//! Auth: the client presents a one-time `?ticket=` (preferred) or a bearer
//! `?token=` on the upgrade request; the credential is resolved to an identity via
//! the pluggable [`crate::resolver::CredentialResolver`] (device tokens by default)
//! before the socket is accepted.
//!
//! Authorization: a frame is only forwarded when the target peer belongs to the
//! **same account** (`user_id`) as the sender — a member of one account can't push
//! offers/ICE at, or probe the presence of, another account's devices. `from` is
//! always server-set from the sender's resolved identity (never client-supplied).
//! Each socket's relay frames are also rate-limited (see [`FrameLimiter`]); frames
//! over the limit are dropped, the socket stays open.

use crate::db::AppState;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::response::{IntoResponse, Response};
use futures::{SinkExt, StreamExt};
use serde::Deserialize;
use std::collections::HashMap;
use std::time::Instant;
use tokio::sync::Mutex;
use tokio::sync::mpsc;

/// A member of a pairing room: `(member_id, outbound sender)`.
type RoomMember = (u64, mpsc::UnboundedSender<String>);

/// A connected signaling peer: who it belongs to and how to reach it.
struct Peer {
    /// The authenticated account/user the peer resolved to (relay scope key).
    user_id: i64,
    tx: mpsc::UnboundedSender<String>,
}

/// Why [`Hub::relay`] did not deliver a frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayError {
    /// No peer with that signaling id is connected.
    Offline,
    /// The target is connected but belongs to a different account than the sender.
    /// Never forwarded; indistinguishable from `Offline` to the sender (no presence
    /// probing across accounts).
    CrossAccount,
}

/// Sustained relay-frame rate a single signaling socket may send, in frames per
/// second. Legitimate signaling is an offer/answer plus a few dozen trickled ICE
/// candidates per (re)negotiation, well inside this.
pub const RELAY_FRAMES_PER_SEC: f64 = 16.0;
/// Burst allowance per socket (the token bucket's capacity): lets a full ICE
/// gather + offer go out at once without throttling.
pub const RELAY_BURST: f64 = 64.0;

/// Per-connection token bucket for inbound relay frames. Starts full; refills at
/// [`RELAY_FRAMES_PER_SEC`] up to [`RELAY_BURST`]. Over-limit frames are dropped by
/// the caller (not forwarded) rather than closing the socket, so a client that
/// briefly bursts just loses the excess instead of its session.
pub struct FrameLimiter {
    tokens: f64,
    last: Instant,
    rate_per_sec: f64,
    burst: f64,
}

impl FrameLimiter {
    pub fn new() -> Self {
        Self::with_limits(RELAY_FRAMES_PER_SEC, RELAY_BURST)
    }

    pub fn with_limits(rate_per_sec: f64, burst: f64) -> Self {
        Self {
            tokens: burst,
            last: Instant::now(),
            rate_per_sec,
            burst,
        }
    }

    /// Try to spend one token now. `true` = frame allowed.
    pub fn allow(&mut self) -> bool {
        self.allow_at(Instant::now())
    }

    /// [`allow`](Self::allow) with an explicit clock (tests).
    pub fn allow_at(&mut self, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.last);
        self.last = now;
        self.tokens = (self.tokens + elapsed.as_secs_f64() * self.rate_per_sec).min(self.burst);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

impl Default for FrameLimiter {
    fn default() -> Self {
        Self::new()
    }
}

/// Tracks which device_ids are currently connected and how to reach them, plus
/// ephemeral 2-party **pairing rooms** keyed by a one-time code (no accounts).
#[derive(Default)]
pub struct Hub {
    peers: Mutex<HashMap<String, Peer>>,
    /// code → up to two members. Used by the stateless direct-pairing flow
    /// (QR/PAKE); the relay only forwards opaque ciphertext.
    rooms: Mutex<HashMap<String, Vec<RoomMember>>>,
    next_member: std::sync::atomic::AtomicU64,
}

impl Hub {
    pub fn new() -> Self {
        Self::default()
    }

    /// Join the pairing room for `code`. Returns this connection's member id, or
    /// `None` if the room already has two members. Notifies the existing member
    /// that a peer joined.
    async fn join_room(&self, code: &str, tx: mpsc::UnboundedSender<String>) -> Option<u64> {
        let mut rooms = self.rooms.lock().await;
        let members = rooms.entry(code.to_string()).or_default();
        if members.len() >= 2 {
            return None;
        }
        let id = self
            .next_member
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        // Notify *both* sides that the room now has a peer, so each knows to send
        // its first pairing message (the newcomer learns an existing peer is here;
        // the waiter learns the newcomer arrived).
        let already_present = !members.is_empty();
        for (_, other) in members.iter() {
            let _ = other.send(r#"{"peer":"joined"}"#.to_string());
        }
        if already_present {
            let _ = tx.send(r#"{"peer":"joined"}"#.to_string());
        }
        members.push((id, tx));
        Some(id)
    }

    /// Forward an opaque frame to the *other* member(s) of the pairing room.
    async fn relay_room(&self, code: &str, from_id: u64, text: String) {
        let rooms = self.rooms.lock().await;
        if let Some(members) = rooms.get(code) {
            for (id, tx) in members {
                if *id != from_id {
                    let _ = tx.send(text.clone());
                }
            }
        }
    }

    /// Leave a pairing room; notify the remaining peer and drop empty rooms.
    async fn leave_room(&self, code: &str, id: u64) {
        let mut rooms = self.rooms.lock().await;
        if let Some(members) = rooms.get_mut(code) {
            members.retain(|(mid, _)| *mid != id);
            for (_, tx) in members.iter() {
                let _ = tx.send(r#"{"peer":"left"}"#.to_string());
            }
            if members.is_empty() {
                rooms.remove(code);
            }
        }
    }

    /// Register a connected device under the account it authenticated as;
    /// replaces any prior connection for that id.
    async fn register(&self, device_id: String, user_id: i64, tx: mpsc::UnboundedSender<String>) {
        self.peers
            .lock()
            .await
            .insert(device_id, Peer { user_id, tx });
    }

    /// Remove a device's connection (only if `tx` still matches — avoids evicting
    /// a newer connection that replaced this one).
    async fn unregister(&self, device_id: &str, tx: &mpsc::UnboundedSender<String>) {
        let mut peers = self.peers.lock().await;
        if let Some(existing) = peers.get(device_id) {
            if existing.tx.same_channel(tx) {
                peers.remove(device_id);
            }
        }
    }

    /// Forward a text frame from a peer of account `from_user_id` to `to`. Only
    /// delivered when the target is online AND belongs to the same account: the
    /// relay is scoped to the authenticated account, so cross-account routing is
    /// dropped (in a single-account self-host every peer shares the account, so
    /// this is a no-op there). A target whose outbound channel is gone counts as
    /// offline.
    async fn relay(&self, from_user_id: i64, to: &str, text: String) -> Result<(), RelayError> {
        let peers = self.peers.lock().await;
        match peers.get(to) {
            Some(peer) if peer.user_id != from_user_id => Err(RelayError::CrossAccount),
            Some(peer) => peer.tx.send(text).map_err(|_| RelayError::Offline),
            None => Err(RelayError::Offline),
        }
    }

    /// Number of connected peers (metrics / tests).
    pub async fn online_count(&self) -> usize {
        self.peers.lock().await.len()
    }

    /// Whether a specific signaling id is currently connected.
    pub async fn is_online(&self, id: &str) -> bool {
        self.peers.lock().await.contains_key(id)
    }

    /// Snapshot of every currently-connected signaling id. A plugin filters this
    /// (e.g. by a `t:<account_id>:` prefix) to compute an account's live sessions.
    pub async fn online_peers(&self) -> Vec<String> {
        self.peers.lock().await.keys().cloned().collect()
    }
}

/// Query string on the WS upgrade. Prefer `?ticket=<one-time>` (from
/// `GET /api/ws-ticket`) so the long-lived bearer token never rides in the URL
/// (H3); `?token=<bearer>` stays accepted for existing clients.
#[derive(Deserialize)]
pub struct WsAuth {
    #[serde(default)]
    ticket: Option<String>,
    #[serde(default)]
    token: Option<String>,
}

/// Inbound client frame (public for fuzz harnesses).
#[derive(Deserialize)]
pub struct RelayFrame {
    pub to: String,
    pub payload: serde_json::Value,
}

/// `GET /ws?token=...` — upgrade to the signaling socket after authenticating.
pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    Query(auth): Query<WsAuth>,
) -> Response {
    // Authenticate before accepting the socket: a one-time ticket (preferred,
    // carries the full resolved credential) or a bearer credential resolved via
    // the pluggable resolver (device token by default; member JWT in a paid build).
    let cred = if let Some(ticket) = auth.ticket.as_deref() {
        match state.ws_tickets.redeem(ticket) {
            Some(cred) => cred,
            None => return crate::error::AppError::Unauthorized.into_response(),
        }
    } else if let Some(token) = auth.token.as_deref() {
        match state.credential_resolver.resolve(&state.pool, token).await {
            Some(cred) => cred,
            None => return crate::error::AppError::Unauthorized.into_response(),
        }
    } else {
        return crate::error::AppError::Unauthorized.into_response();
    };
    ws.on_upgrade(move |socket| handle_socket(socket, state, cred))
}

async fn handle_socket(
    socket: WebSocket,
    state: AppState,
    cred: crate::resolver::ResolvedCredential,
) {
    let signaling_id = cred.signaling_id;
    let user_id = cred.user_id;
    let (mut sink, mut stream) = socket.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();

    state
        .hub
        .register(signaling_id.clone(), user_id, tx.clone())
        .await;
    // Notify the activity observer (plugin-supplied) that a session came online.
    // The callback must not block — a plugin offloads any I/O.
    if let Some(obs) = &state.session_observer {
        obs.on_connect(user_id, &signaling_id);
    }
    tracing::info!(device = %signaling_id, "signaling connected");

    // Pump relayed messages out to this device, and send a keepalive Ping every
    // 30s so an idle connection (a host waiting for a viewer) isn't dropped by an
    // intermediary idle timeout — Cloudflare's tunnel kills idle WebSockets at
    // ~100s. Any frame resets that timer; the peer (tungstenite) auto-answers Pong.
    let mut send_task = tokio::spawn(async move {
        let mut keepalive = tokio::time::interval(std::time::Duration::from_secs(30));
        keepalive.tick().await; // consume the immediate first tick
        loop {
            tokio::select! {
                msg = rx.recv() => match msg {
                    Some(text) => {
                        if sink.send(Message::Text(text.into())).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                },
                _ = keepalive.tick() => {
                    if sink.send(Message::Ping(Vec::new().into())).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    // Read this device's frames and relay them to the addressed peer — only within
    // the sender's own account, and no faster than the per-socket frame limit.
    let hub = state.hub.clone();
    let me = signaling_id.clone();
    let mut recv_task = tokio::spawn(async move {
        let mut limiter = FrameLimiter::new();
        // Count over-limit drops so the log line fires once per episode, not per frame.
        let mut throttled: u64 = 0;
        while let Some(Ok(msg)) = stream.next().await {
            let Message::Text(text) = msg else {
                if matches!(msg, Message::Close(_)) {
                    break;
                }
                continue;
            };
            if !limiter.allow() {
                throttled += 1;
                if throttled == 1 {
                    tracing::warn!(from = %me, "relay frame rate limit exceeded; dropping frames");
                }
                continue;
            }
            if throttled > 0 {
                tracing::debug!(from = %me, dropped = throttled, "relay frame rate limit cleared");
                throttled = 0;
            }
            let frame: RelayFrame = match serde_json::from_str(&text) {
                Ok(f) => f,
                Err(e) => {
                    tracing::debug!(error = %e, "bad relay frame");
                    continue;
                }
            };
            // `from` is always this socket's authenticated identity — never taken
            // from the client frame.
            let out = serde_json::json!({ "from": me, "payload": frame.payload }).to_string();
            match hub.relay(user_id, &frame.to, out).await {
                Ok(()) => {}
                Err(RelayError::Offline) => {
                    tracing::debug!(from = %me, to = %frame.to, "relay target offline");
                }
                Err(RelayError::CrossAccount) => {
                    tracing::warn!(from = %me, to = %frame.to, "dropped cross-account relay frame");
                }
            }
        }
    });

    // Heartbeat: refresh last_seen every 30s so the "online" dot stays green while
    // the device is actually connected (last_seen is otherwise only set on connect).
    let hb_pool = state.pool.clone();
    let hb_dev = signaling_id.clone();
    let heartbeat = tokio::spawn(async move {
        let mut iv = tokio::time::interval(std::time::Duration::from_secs(30));
        iv.tick().await;
        loop {
            iv.tick().await;
            crate::api::touch_last_seen(&hb_pool, &hb_dev).await;
        }
    });

    // When either I/O task ends, tear down the others and unregister.
    tokio::select! {
        _ = &mut send_task => { recv_task.abort(); heartbeat.abort(); }
        _ = &mut recv_task => { send_task.abort(); heartbeat.abort(); }
    }
    state.hub.unregister(&signaling_id, &tx).await;
    if let Some(obs) = &state.session_observer {
        obs.on_disconnect(user_id, &signaling_id);
    }
    tracing::info!(device = %signaling_id, "signaling disconnected");
}

/// Query string on the pairing WS upgrade: `?code=<ephemeral rendezvous code>`.
#[derive(Deserialize)]
pub struct PairAuth {
    code: String,
}

/// A frame on the pairing socket: `{"payload":<opaque>}` — forwarded verbatim to
/// the room's other member. The relay never inspects `payload` (it's the PAKE
/// exchange / confirmation / E2EE-bootstrap, opaque by design).
#[derive(Deserialize)]
pub struct PairFrame {
    payload: serde_json::Value,
}

/// `GET /pair?code=...` — join an ephemeral 2-party pairing room (no account).
/// The relay is a blind mailbox: it matches two parties by `code` and forwards
/// their opaque frames. Trust comes from the QR seed / PAKE code, not the relay.
pub async fn ws_pair_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    Query(auth): Query<PairAuth>,
) -> Response {
    // Bound the code length so a client can't allocate an arbitrary room key.
    if auth.code.is_empty() || auth.code.len() > 128 {
        return crate::error::AppError::BadRequest("invalid pairing code".into()).into_response();
    }
    ws.on_upgrade(move |socket| handle_pair_socket(socket, state, auth.code))
}

async fn handle_pair_socket(socket: WebSocket, state: AppState, code: String) {
    let (mut sink, mut stream) = socket.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();

    let Some(member_id) = state.hub.join_room(&code, tx).await else {
        // Room full: tell the client and close.
        let _ = sink
            .send(Message::Text(r#"{"error":"pairing room full"}"#.into()))
            .await;
        return;
    };
    tracing::info!("pairing peer joined a room");

    let mut send_task = tokio::spawn(async move {
        while let Some(text) = rx.recv().await {
            if sink.send(Message::Text(text.into())).await.is_err() {
                break;
            }
        }
    });

    let hub = state.hub.clone();
    let room = code.clone();
    let mut recv_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = stream.next().await {
            let Message::Text(text) = msg else {
                if matches!(msg, Message::Close(_)) {
                    break;
                }
                continue;
            };
            let frame: PairFrame = match serde_json::from_str(&text) {
                Ok(f) => f,
                Err(e) => {
                    tracing::debug!(error = %e, "bad pairing frame");
                    continue;
                }
            };
            let out = serde_json::json!({ "payload": frame.payload }).to_string();
            hub.relay_room(&room, member_id, out).await;
        }
    });

    tokio::select! {
        _ = &mut send_task => recv_task.abort(),
        _ = &mut recv_task => send_task.abort(),
    }
    state.hub.leave_room(&code, member_id).await;
    tracing::info!("pairing peer left");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn pairing_room_relays_between_two_members_and_rejects_third() {
        let hub = Hub::new();
        let (txa, mut rxa) = mpsc::unbounded_channel();
        let (txb, mut rxb) = mpsc::unbounded_channel();

        let a = hub.join_room("code1", txa).await.unwrap();
        let b = hub.join_room("code1", txb).await.unwrap();
        // Both sides are told a peer is present.
        assert_eq!(rxa.recv().await.unwrap(), r#"{"peer":"joined"}"#);
        assert_eq!(rxb.recv().await.unwrap(), r#"{"peer":"joined"}"#);

        // A → B and B → A relay to the *other* member only.
        hub.relay_room("code1", a, "hello".into()).await;
        assert_eq!(rxb.recv().await.unwrap(), "hello");
        hub.relay_room("code1", b, "hi".into()).await;
        assert_eq!(rxa.recv().await.unwrap(), "hi");

        // A third party can't join a full room.
        let (txc, _rxc) = mpsc::unbounded_channel();
        assert!(hub.join_room("code1", txc).await.is_none());

        // Leaving notifies the remaining peer.
        hub.leave_room("code1", a).await;
        assert_eq!(rxb.recv().await.unwrap(), r#"{"peer":"left"}"#);
    }

    #[tokio::test]
    async fn hub_presence_reflects_register_and_unregister() {
        let hub = Hub::new();
        let (tx, _rx) = mpsc::unbounded_channel();
        let id = "t:1:alice";
        assert!(!hub.is_online(id).await);
        hub.register(id.to_string(), 1, tx.clone()).await;
        assert!(hub.is_online(id).await);
        assert_eq!(hub.online_count().await, 1);
        assert_eq!(hub.online_peers().await, vec![id.to_string()]);
        hub.unregister(id, &tx).await;
        assert!(!hub.is_online(id).await);
        assert_eq!(hub.online_count().await, 0);
    }

    /// The relay is scoped to the sender's account: a peer in account 1 can reach
    /// another account-1 peer (host→viewer and viewer→host alike, including the
    /// web viewer's `v:` and a tenant member's `t:` ids) but a frame addressed to
    /// an account-2 device is dropped, not delivered — and reported exactly like
    /// an offline target would be to the sender (no cross-account presence probe).
    #[tokio::test]
    async fn relay_is_scoped_to_the_senders_account() {
        let hub = Hub::new();
        let (tx_host1, mut rx_host1) = mpsc::unbounded_channel();
        let (tx_view1, mut rx_view1) = mpsc::unbounded_channel();
        let (tx_host2, mut rx_host2) = mpsc::unbounded_channel();
        hub.register("host1".into(), 1, tx_host1).await;
        hub.register("v:1:abcd".into(), 1, tx_view1).await;
        hub.register("host2".into(), 2, tx_host2).await;

        // Same account, both directions.
        assert_eq!(hub.relay(1, "host1", "offer".into()).await, Ok(()));
        assert_eq!(rx_host1.recv().await.unwrap(), "offer");
        assert_eq!(hub.relay(1, "v:1:abcd", "answer".into()).await, Ok(()));
        assert_eq!(rx_view1.recv().await.unwrap(), "answer");

        // Cross-account: dropped, nothing reaches the target.
        assert_eq!(
            hub.relay(1, "host2", "offer".into()).await,
            Err(RelayError::CrossAccount)
        );
        assert_eq!(
            hub.relay(2, "host1", "offer".into()).await,
            Err(RelayError::CrossAccount)
        );
        assert!(
            rx_host2.try_recv().is_err(),
            "account-2 host must get nothing"
        );
        assert!(
            rx_host1.try_recv().is_err(),
            "account-1 host must get nothing"
        );

        // Unknown target is offline.
        assert_eq!(
            hub.relay(1, "nobody", "x".into()).await,
            Err(RelayError::Offline)
        );
    }

    /// The per-socket token bucket: a burst of `RELAY_BURST` passes, the next is
    /// dropped, and tokens come back at `RELAY_FRAMES_PER_SEC` (capped at burst).
    #[test]
    fn frame_limiter_allows_burst_then_refills() {
        let mut l = FrameLimiter::with_limits(10.0, 5.0);
        let t0 = Instant::now();
        for _ in 0..5 {
            assert!(l.allow_at(t0), "burst must pass");
        }
        assert!(!l.allow_at(t0), "over burst must be dropped");
        // 100 ms at 10/s refills exactly one token.
        let t1 = t0 + Duration::from_millis(100);
        assert!(l.allow_at(t1));
        assert!(!l.allow_at(t1));
        // A long idle refills to the cap, no further.
        let t2 = t1 + Duration::from_secs(60);
        for _ in 0..5 {
            assert!(l.allow_at(t2));
        }
        assert!(!l.allow_at(t2));
        // Defaults are the documented ones.
        let d = FrameLimiter::new();
        assert_eq!(d.burst, RELAY_BURST);
        assert_eq!(d.rate_per_sec, RELAY_FRAMES_PER_SEC);
    }
}
