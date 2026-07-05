//! ReachMyDevice dev signaling relay (spike only).
//!
//! A minimal newline-delimited TCP relay standing in for the Phase-2 rendezvous
//! server. Every line a client sends is forwarded verbatim to every *other*
//! connected client. The host and viewer each connect, then exchange opaque
//! JSON signaling messages (SDP offer/answer + ICE candidates) through it. The
//! relay never inspects the payload.
//!
//! Usage:
//! ```sh
//! RMD_SIGNAL_ADDR=0.0.0.0:9000 cargo run -p rmd-signal-dev
//! ```
//! Then point both host and viewer at `ws://<this-host>:9000` equivalent (raw
//! TCP here). Replaced by the axum WebSocket rendezvous in Phase 2.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::broadcast;

/// One relayed line, tagged with its sender so we don't echo it back.
#[derive(Clone, Debug)]
struct Relayed {
    from: u64,
    line: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let addr =
        std::env::var("RMD_SIGNAL_ADDR").unwrap_or_else(|_| "0.0.0.0:9000".to_string());
    let listener = TcpListener::bind(&addr).await?;
    tracing::info!(%addr, "signal-dev relay listening");

    // Fan-out bus: every client publishes here and subscribes to it.
    let (tx, _rx) = broadcast::channel::<Relayed>(256);
    let next_id = Arc::new(AtomicU64::new(1));

    loop {
        let (socket, peer) = listener.accept().await?;
        let id = next_id.fetch_add(1, Ordering::Relaxed);
        let tx = tx.clone();
        let rx = tx.subscribe();
        tracing::info!(client = id, %peer, "client connected");
        tokio::spawn(async move {
            if let Err(e) = handle_client(socket, id, tx, rx).await {
                tracing::info!(client = id, error = %e, "client disconnected");
            } else {
                tracing::info!(client = id, "client disconnected");
            }
        });
    }
}

async fn handle_client(
    socket: tokio::net::TcpStream,
    id: u64,
    tx: broadcast::Sender<Relayed>,
    mut rx: broadcast::Receiver<Relayed>,
) -> anyhow::Result<()> {
    let (read_half, mut write_half) = socket.into_split();
    let mut lines = BufReader::new(read_half).lines();

    loop {
        tokio::select! {
            // Inbound from this client -> publish to the bus.
            maybe_line = lines.next_line() => {
                match maybe_line? {
                    Some(line) => {
                        if line.trim().is_empty() { continue; }
                        tracing::debug!(client = id, bytes = line.len(), "relay line");
                        // A lagging/closed bus is non-fatal for this reader.
                        let _ = tx.send(Relayed { from: id, line });
                    }
                    None => break, // EOF
                }
            }
            // Bus -> forward to this client (skip our own messages).
            relayed = rx.recv() => {
                match relayed {
                    Ok(msg) if msg.from != id => {
                        write_half.write_all(msg.line.as_bytes()).await?;
                        write_half.write_all(b"\n").await?;
                    }
                    Ok(_) => {} // our own echo; skip
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!(client = id, dropped = n, "signaling receiver lagged");
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        }
    }
    Ok(())
}
