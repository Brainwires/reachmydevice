//! Rendezvous WebSocket signaling client (Phase 2).
//!
//! Speaks the rendezvous server's relay protocol
//! (`{"to":..,"payload":..}` / `{"from":..,"payload":..}`) over an
//! authenticated WebSocket, and presents the same [`Signaling`] interface as the
//! LAN [`SignalClient`](crate::signal::SignalClient) so the host/viewer sessions
//! are unchanged.
//!
//! Because the rendezvous relay is **addressed** (unlike the LAN broadcast), the
//! viewer targets the host's `device_id`; the host learns the viewer's id from
//! the viewer's initial `hello`. The host is the WebRTC offerer, so its early
//! offer/candidates are buffered until it learns the peer id, then flushed.
//!
//! The client runs a current-thread tokio runtime on its own thread and bridges
//! to the synchronous session loops via channels.

use crate::signal::Signaling;
use futures::{SinkExt, StreamExt};
use openreach_transport::SignalMsg;
use serde::{Deserialize, Serialize};
use std::sync::mpsc as std_mpsc;
use std::sync::Mutex;
use tokio::sync::mpsc as tok_mpsc;
use tokio_tungstenite::tungstenite::Message;

/// The opaque `payload` we relay through the server.
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
enum Payload {
    /// Presence announce so the host learns the viewer's device_id.
    Hello,
    /// A wrapped signaling message.
    Signal { msg: SignalMsg },
}

#[derive(Serialize)]
struct Outbound<'a> {
    to: &'a str,
    payload: Payload,
}

#[derive(Deserialize)]
struct Inbound {
    from: String,
    payload: Payload,
}

/// Rendezvous signaling client.
pub struct RendezvousClient {
    out_tx: tok_mpsc::UnboundedSender<SignalMsg>,
    inbound: Mutex<std_mpsc::Receiver<SignalMsg>>,
}

impl RendezvousClient {
    /// Connect to `ws_url` (e.g. `wss://host/ws`) authenticating with `token`.
    ///
    /// `peer_device_id` is the id to address (the viewer passes the host's id; the
    /// host passes `None` and learns the viewer's id from its `hello`).
    pub fn connect(
        ws_url: &str,
        token: &str,
        peer_device_id: Option<String>,
    ) -> anyhow::Result<Self> {
        let url = format!("{ws_url}?token={token}");
        let (out_tx, out_rx) = tok_mpsc::unbounded_channel::<SignalMsg>();
        let (in_tx, in_rx) = std_mpsc::channel::<SignalMsg>();

        std::thread::Builder::new()
            .name("openreach-rendezvous".into())
            .spawn(move || {
                let rt = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(e) => {
                        tracing::error!(error=%e, "rendezvous runtime build failed");
                        return;
                    }
                };
                if let Err(e) = rt.block_on(run(url, peer_device_id, out_rx, in_tx)) {
                    tracing::error!(error=%e, "rendezvous client ended");
                }
            })?;

        Ok(Self {
            out_tx,
            inbound: Mutex::new(in_rx),
        })
    }
}

impl Signaling for RendezvousClient {
    fn send(&self, msg: &SignalMsg) -> anyhow::Result<()> {
        self.out_tx
            .send(msg.clone())
            .map_err(|_| anyhow::anyhow!("rendezvous client closed"))
    }
    fn try_recv(&self) -> Option<SignalMsg> {
        self.inbound.lock().ok()?.try_recv().ok()
    }
}

/// The async client loop: connect, (optionally) announce, relay both ways.
async fn run(
    url: String,
    mut peer: Option<String>,
    mut out_rx: tok_mpsc::UnboundedReceiver<SignalMsg>,
    in_tx: std_mpsc::Sender<SignalMsg>,
) -> anyhow::Result<()> {
    let (ws, _resp) = tokio_tungstenite::connect_async(&url).await?;
    let (mut write, mut read) = ws.split();
    tracing::info!("rendezvous connected");

    // Outbound messages we can't address yet (host, before it knows the viewer).
    let mut pending: Vec<SignalMsg> = Vec::new();

    // The viewer (which knows the target upfront) re-announces until the host is
    // online and replies; otherwise an early `hello` sent before the host's socket
    // registers would be dropped by the relay and the pairing would never form.
    let is_viewer = peer.is_some();
    let mut received_any = false;
    let mut announce = tokio::time::interval(std::time::Duration::from_millis(500));

    loop {
        tokio::select! {
            // Re-announce presence (viewer only, until we hear back). First tick is immediate.
            _ = announce.tick(), if is_viewer && !received_any => {
                if let Some(to) = &peer {
                    let hello = serde_json::to_string(&Outbound { to, payload: Payload::Hello })?;
                    write.send(Message::text(hello)).await?;
                }
            }
            // Session wants to send a signaling message.
            maybe = out_rx.recv() => {
                let Some(msg) = maybe else { break; }; // sender dropped
                match &peer {
                    Some(to) => {
                        let text = serde_json::to_string(&Outbound { to, payload: Payload::Signal { msg } })?;
                        write.send(Message::text(text)).await?;
                    }
                    None => pending.push(msg), // buffer until we learn the peer
                }
            }
            // Frame from the relay.
            frame = read.next() => {
                let Some(frame) = frame else { break; }; // socket closed
                let Message::Text(text) = frame? else { continue; };
                let Ok(inbound) = serde_json::from_str::<Inbound>(text.as_str()) else {
                    tracing::debug!("bad rendezvous frame");
                    continue;
                };
                received_any = true;
                // Learn/lock the peer id on first contact and flush anything buffered.
                if peer.is_none() {
                    peer = Some(inbound.from.clone());
                    for msg in pending.drain(..) {
                        let text = serde_json::to_string(&Outbound {
                            to: inbound.from.as_str(),
                            payload: Payload::Signal { msg },
                        })?;
                        write.send(Message::text(text)).await?;
                    }
                }
                if let Payload::Signal { msg } = inbound.payload {
                    if in_tx.send(msg).is_err() {
                        break; // consumer gone
                    }
                }
            }
        }
    }
    Ok(())
}
