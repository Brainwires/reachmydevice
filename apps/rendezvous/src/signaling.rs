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
//! Auth: the device presents its bearer token as `?token=<token>` on the upgrade
//! request; it is validated against `device_tokens` before the socket is accepted.

use crate::db::AppState;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::response::{IntoResponse, Response};
use futures::{SinkExt, StreamExt};
use serde::Deserialize;
use std::collections::HashMap;
use tokio::sync::mpsc;
use tokio::sync::Mutex;

/// Tracks which device_ids are currently connected and how to reach them.
#[derive(Default)]
pub struct Hub {
    peers: Mutex<HashMap<String, mpsc::UnboundedSender<String>>>,
}

impl Hub {
    pub fn new() -> Self {
        Self::default()
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

    /// Number of connected devices (used by the Phase 2 integration test / metrics).
    #[allow(dead_code)]
    pub async fn online_count(&self) -> usize {
        self.peers.lock().await.len()
    }
}

/// Query string on the WS upgrade: `?token=<device bearer token>`.
#[derive(Deserialize)]
pub struct WsAuth {
    token: String,
}

/// Inbound client frame.
#[derive(Deserialize)]
struct RelayFrame {
    to: String,
    payload: serde_json::Value,
}

/// `GET /ws?token=...` — upgrade to the signaling socket after authenticating.
pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    Query(auth): Query<WsAuth>,
) -> Response {
    // Authenticate the device token before accepting the socket.
    let device_id = match crate::api::device_id_for_token(&state.pool, &auth.token).await {
        Ok(Some(id)) => id,
        _ => return crate::error::AppError::Unauthorized.into_response(),
    };
    ws.on_upgrade(move |socket| handle_socket(socket, state, device_id))
}

async fn handle_socket(socket: WebSocket, state: AppState, device_id: String) {
    let (mut sink, mut stream) = socket.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();

    state.hub.register(device_id.clone(), tx.clone()).await;
    tracing::info!(device = %device_id, "signaling connected");

    // Pump relayed messages out to this device.
    let mut send_task = tokio::spawn(async move {
        while let Some(text) = rx.recv().await {
            if sink.send(Message::Text(text.into())).await.is_err() {
                break;
            }
        }
    });

    // Read this device's frames and relay them to the addressed peer.
    let hub = state.hub.clone();
    let me = device_id.clone();
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

    // When either task ends, tear down the other and unregister.
    tokio::select! {
        _ = &mut send_task => recv_task.abort(),
        _ = &mut recv_task => send_task.abort(),
    }
    state.hub.unregister(&device_id, &tx).await;
    tracing::info!(device = %device_id, "signaling disconnected");
}
