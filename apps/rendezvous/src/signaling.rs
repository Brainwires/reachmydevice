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

use crate::db::AppState;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::response::{IntoResponse, Response};
use futures::{SinkExt, StreamExt};
use serde::Deserialize;
use std::collections::HashMap;
use tokio::sync::mpsc;
use tokio::sync::Mutex;

/// A member of a pairing room: `(member_id, outbound sender)`.
type RoomMember = (u64, mpsc::UnboundedSender<String>);

/// Tracks which device_ids are currently connected and how to reach them, plus
/// ephemeral 2-party **pairing rooms** keyed by a one-time code (no accounts).
#[derive(Default)]
pub struct Hub {
    peers: Mutex<HashMap<String, mpsc::UnboundedSender<String>>>,
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

    /// Register a connected device; replaces any prior connection for that id.
    async fn register(&self, device_id: String, tx: mpsc::UnboundedSender<String>) {
        self.peers.lock().await.insert(device_id, tx);
    }

    /// Remove a device's connection (only if `tx` still matches — avoids evicting
    /// a newer connection that replaced this one).
    async fn unregister(&self, device_id: &str, tx: &mpsc::UnboundedSender<String>) {
        let mut peers = self.peers.lock().await;
        if let Some(existing) = peers.get(device_id) {
            if existing.same_channel(tx) {
                peers.remove(device_id);
            }
        }
    }

    /// Forward a text frame to `to`. Returns false if the target is offline.
    async fn relay(&self, to: &str, text: String) -> bool {
        let peers = self.peers.lock().await;
        match peers.get(to) {
            Some(tx) => tx.send(text).is_ok(),
            None => false,
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

    state.hub.register(signaling_id.clone(), tx.clone()).await;
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

    // Read this device's frames and relay them to the addressed peer.
    let hub = state.hub.clone();
    let me = signaling_id.clone();
    let mut recv_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = stream.next().await {
            let Message::Text(text) = msg else {
                if matches!(msg, Message::Close(_)) {
                    break;
                }
                continue;
            };
            let frame: RelayFrame = match serde_json::from_str(&text) {
                Ok(f) => f,
                Err(e) => {
                    tracing::debug!(error = %e, "bad relay frame");
                    continue;
                }
            };
            let out = serde_json::json!({ "from": me, "payload": frame.payload }).to_string();
            if !hub.relay(&frame.to, out).await {
                tracing::debug!(from = %me, to = %frame.to, "relay target offline");
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
        hub.register(id.to_string(), tx.clone()).await;
        assert!(hub.is_online(id).await);
        assert_eq!(hub.online_count().await, 1);
        assert_eq!(hub.online_peers().await, vec![id.to_string()]);
        hub.unregister(id, &tx).await;
        assert!(!hub.is_online(id).await);
        assert_eq!(hub.online_count().await, 0);
    }
}
