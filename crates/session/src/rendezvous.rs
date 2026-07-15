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
use rmd_transport::SignalMsg;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc as std_mpsc;
use std::sync::{Arc, Mutex};
use std::time::Instant;
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
    /// Set by the relay loop when the addressed peer becomes a *different* viewer
    /// device (a "switch"); consumed by the host via [`Signaling::take_peer_switched`].
    peer_switched: Arc<AtomicBool>,
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
        session_active: Option<Arc<AtomicBool>>,
    ) -> anyhow::Result<Self> {
        let url = format!("{ws_url}?token={token}");
        let (out_tx, out_rx) = tok_mpsc::unbounded_channel::<SignalMsg>();
        let (in_tx, in_rx) = std_mpsc::channel::<SignalMsg>();
        let peer_switched = Arc::new(AtomicBool::new(false));
        let peer_switched_thread = peer_switched.clone();

        std::thread::Builder::new()
            .name("rmd-rendezvous".into())
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
                if let Err(e) = rt.block_on(run(
                    url,
                    peer_device_id,
                    out_rx,
                    in_tx,
                    session_active,
                    peer_switched_thread,
                )) {
                    tracing::error!(error=%e, "rendezvous client ended");
                }
            })?;

        Ok(Self {
            out_tx,
            inbound: Mutex::new(in_rx),
            peer_switched,
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
    fn take_peer_switched(&self) -> bool {
        self.peer_switched.swap(false, Ordering::Relaxed)
    }
}

/// Restart the process **in place** to shed a wedged system DNS resolver, without
/// depending on a supervisor. On Unix we `exec` ourselves: same PID (so a launchd/
/// systemd `KeepAlive` supervisor doesn't double-launch us) but a fresh process
/// image + resolver connection. If `exec` fails (or non-Unix), fall back to `exit(1)`
/// so a supervisor, if any, still relaunches us. Never returns.
fn restart_for_fresh_resolver() -> ! {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        if let Ok(exe) = std::env::current_exe() {
            let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
            // `exec` only returns on error.
            let err = std::process::Command::new(&exe).args(&args).exec();
            tracing::error!(error = %err, "re-exec failed; exiting for a supervisor to relaunch");
        }
    }
    std::process::exit(1);
}

/// The async client loop: connect the signaling WebSocket and relay both ways,
/// **reconnecting with backoff** whenever it drops. A long-lived host's socket
/// WILL be reset (idle timeout, a Cloudflare/proxy blip, a rendezvous restart);
/// without this the client thread just exits and the host silently goes dark
/// (still running, but unreachable — no new viewer can signal it). Relay state
/// (the host's offer + candidates, the learned peer) is preserved across
/// reconnects so a (re)announcing viewer still completes the handshake.
async fn run(
    url: String,
    mut peer: Option<String>,
    mut out_rx: tok_mpsc::UnboundedReceiver<SignalMsg>,
    in_tx: std_mpsc::Sender<SignalMsg>,
    session_active: Option<Arc<AtomicBool>>,
    peer_switched: Arc<AtomicBool>,
) -> anyhow::Result<()> {
    use std::time::Duration;

    // Watchdog: a macOS host that lives through a network blip can end up with a
    // permanently wedged system DNS resolver (`getaddrinfo` returns "nodename nor
    // servname" forever) that only a fresh process clears — so the host stays alive
    // but unreachable. If we can't reach the rendezvous for this long AND no session
    // is active, exit so the supervisor (launchd/systemd KeepAlive) relaunches us
    // with a clean resolver. `None` (the viewer) never self-restarts.
    const WATCHDOG: Duration = Duration::from_secs(150);
    // Bound each connect attempt. A wedged macOS resolver makes the `getaddrinfo`
    // inside `connect_async` block FOREVER without ever erroring, so without this cap
    // the loop hangs on one `.await` and the watchdog below (which only runs when a
    // connect *returns* a failure) never gets a chance to fire — the host stays alive
    // but permanently unreachable. A timeout turns that hang into a normal, countable
    // retry.
    const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
    // Tear down a connection that has gone silent. A half-open socket (peer/NAT
    // vanished with no RST) can leave `read.next()` blocked for many minutes before
    // the OS write path finally errors. We ping every 30s; if we hear *nothing* back
    // (not even a pong) for this long, treat the socket as dead and reconnect rather
    // than sit there looking connected but delivering nothing.
    const LIVENESS: Duration = Duration::from_secs(90);
    let mut first_fail: Option<Instant> = None;

    // The viewer (which knows the target upfront) re-announces until the host is
    // online and replies; the host learns the viewer's id from its `hello`.
    let is_viewer = peer.is_some();
    // State that must survive reconnects (see doc comment).
    let mut pending: Vec<SignalMsg> = Vec::new();
    let mut last_offer: Option<SignalMsg> = None;
    let mut sent_candidates: Vec<SignalMsg> = Vec::new();
    let mut backoff = Duration::from_secs(1);

    // Why the relay loop stopped.
    enum Stop {
        SessionEnded,
        SocketClosed,
    }

    loop {
        // (Re)connect + re-authenticate (registers this device's socket again).
        // `connect_async` is wrapped in a timeout so a wedged resolver can't hang the
        // loop indefinitely (see CONNECT_TIMEOUT); a timeout is treated as a connect
        // failure so it counts toward the watchdog like any other unreachable state.
        let attempt = tokio::time::timeout(
            CONNECT_TIMEOUT,
            tokio_tungstenite::connect_async(&url),
        )
        .await;
        let ws = match attempt {
            Ok(Ok((ws, _resp))) => ws,
            failed => {
                match &failed {
                    Ok(Err(e)) => {
                        tracing::warn!(error = %e, "rendezvous connect failed; retrying in {backoff:?}")
                    }
                    Err(_elapsed) => tracing::warn!(
                        "rendezvous connect timed out after {CONNECT_TIMEOUT:?} \
                         (possibly a wedged DNS resolver); retrying in {backoff:?}"
                    ),
                    Ok(Ok(_)) => unreachable!("Ok(Ok(_)) is the success arm above"),
                }
                let since = first_fail.get_or_insert_with(Instant::now);
                if let Some(active) = &session_active {
                    if since.elapsed() >= WATCHDOG && !active.load(Ordering::Relaxed) {
                        tracing::error!(
                            secs = since.elapsed().as_secs(),
                            "rendezvous unreachable for too long with no active session — \
                             restarting in place for a fresh DNS resolver"
                        );
                        restart_for_fresh_resolver();
                    }
                }
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(30));
                continue;
            }
        };
        first_fail = None;
        backoff = Duration::from_secs(1);
        let (mut write, mut read) = ws.split();
        tracing::info!("rendezvous connected");

        // Per-connection: viewers must re-announce on a fresh socket; a keepalive
        // ping keeps the connection off idle-timeout kill lists.
        let mut received_any = false;
        // Liveness: bumped on every inbound frame (including pong replies to our
        // keepalive ping). If it goes stale past LIVENESS the socket is dead.
        let mut last_recv = Instant::now();
        let mut announce = tokio::time::interval(Duration::from_millis(500));
        let mut keepalive = tokio::time::interval(Duration::from_secs(30));
        keepalive.reset(); // don't fire immediately on connect

        // Non-`move` async block: borrows the state by &mut so it PERSISTS across
        // reconnects. `?` errors surface here (→ reconnect) instead of killing the
        // whole client.
        let stop: anyhow::Result<Stop> = async {
            loop {
                tokio::select! {
                    _ = announce.tick(), if is_viewer && !received_any => {
                        if let Some(to) = &peer {
                            let hello = serde_json::to_string(&Outbound { to, payload: Payload::Hello })?;
                            write.send(Message::text(hello)).await?;
                        }
                    }
                    _ = keepalive.tick() => {
                        // A dead half-open socket won't error on write for minutes;
                        // catch it by the absence of any reply since the last ping.
                        if last_recv.elapsed() >= LIVENESS {
                            tracing::warn!(
                                secs = last_recv.elapsed().as_secs(),
                                "rendezvous silent past liveness deadline; reconnecting"
                            );
                            return Ok(Stop::SocketClosed);
                        }
                        write.send(Message::Ping(Vec::new().into())).await?;
                    }
                    maybe = out_rx.recv() => {
                        let Some(msg) = maybe else { return Ok(Stop::SessionEnded); };
                        match &msg {
                            SignalMsg::Offer(_) => { last_offer = Some(msg.clone()); sent_candidates.clear(); }
                            SignalMsg::Candidate(_) => sent_candidates.push(msg.clone()),
                            _ => {}
                        }
                        match &peer {
                            Some(to) => {
                                let text = serde_json::to_string(&Outbound { to, payload: Payload::Signal { msg } })?;
                                write.send(Message::text(text)).await?;
                            }
                            None => pending.push(msg),
                        }
                    }
                    frame = read.next() => {
                        let Some(frame) = frame else { return Ok(Stop::SocketClosed); };
                        // Any frame (text, pong, ping) proves the socket is alive.
                        last_recv = Instant::now();
                        let Message::Text(text) = frame? else { continue; };
                        let Ok(inbound) = serde_json::from_str::<Inbound>(text.as_str()) else {
                            tracing::debug!("bad rendezvous frame");
                            continue;
                        };
                        received_any = true;
                        // Treat a `hello` from a *new* peer as first contact (the host
                        // re-learns the viewer after a reconnect / a different viewer).
                        let first_contact = peer.as_deref() != Some(inbound.from.as_str());
                        // A genuine device *switch*: a DIFFERENT viewer takes over an
                        // already-learned peer (host only; `is_viewer` hosts start with
                        // `peer == None`, so the initial connect is not a switch). The
                        // cached `last_offer`/`sent_candidates` describe the OLD viewer's
                        // peer connection; replaying them to the newcomer forces a fragile
                        // stale-offer → answer → rebuild dance that routinely stalls on the
                        // first attempt (until the old PC finally hits its ICE timeout).
                        // Instead drop the stale state and flag the host to mint a FRESH
                        // offer (→ `request_ice_restart` → rebuild); that offer is routed
                        // to the new peer and completes in one clean exchange.
                        let switched = !is_viewer && first_contact && peer.is_some();
                        if switched {
                            last_offer = None;
                            sent_candidates.clear();
                            peer_switched.store(true, Ordering::Relaxed);
                            tracing::info!(
                                from = %inbound.from,
                                "rendezvous: viewer switched device; requesting a fresh offer"
                            );
                        }
                        if first_contact {
                            peer = Some(inbound.from.clone());
                            for msg in pending.drain(..) {
                                let text = serde_json::to_string(&Outbound {
                                    to: inbound.from.as_str(),
                                    payload: Payload::Signal { msg },
                                })?;
                                write.send(Message::text(text)).await?;
                            }
                        }
                        match inbound.payload {
                            Payload::Signal { msg } => {
                                if in_tx.send(msg).is_err() {
                                    return Ok(Stop::SessionEnded);
                                }
                            }
                            // Re-announce (page refresh / reconnect): replay the current
                            // offer + candidates so the handshake completes.
                            Payload::Hello if !first_contact => {
                                if let (Some(to), Some(offer)) = (peer.as_ref(), last_offer.as_ref()) {
                                    for m in std::iter::once(offer).chain(sent_candidates.iter()) {
                                        let text = serde_json::to_string(&Outbound {
                                            to,
                                            payload: Payload::Signal { msg: m.clone() },
                                        })?;
                                        write.send(Message::text(text)).await?;
                                    }
                                    tracing::info!(
                                        candidates = sent_candidates.len(),
                                        "rendezvous: viewer re-announced; replayed offer"
                                    );
                                }
                            }
                            Payload::Hello => {}
                        }
                    }
                }
            }
        }
        .await;

        match stop {
            Ok(Stop::SessionEnded) => return Ok(()), // session dropped the channel — stop.
            Ok(Stop::SocketClosed) => tracing::warn!("rendezvous socket closed; reconnecting"),
            Err(e) => tracing::warn!(error = %e, "rendezvous connection lost; reconnecting"),
        }
        tokio::time::sleep(backoff).await;
    }
}
