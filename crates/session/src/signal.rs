//! Signaling client for the spike's `signal-dev` relay.
//!
//! A newline-delimited JSON [`SignalMsg`] stream over TCP. A reader thread pushes
//! inbound messages to a channel; [`SignalClient::send`] writes outbound ones.
//! This is the seam that Phase 2 replaces with the rendezvous WebSocket — the
//! rest of the session only sees [`SignalMsg`].

use openreach_transport::SignalMsg;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};

/// A signaling transport: the LAN relay ([`SignalClient`]) or the rendezvous
/// WebSocket ([`crate::rendezvous::RendezvousClient`]). The host/viewer sessions
/// are generic over this so they work in either mode.
pub trait Signaling: Send {
    /// Deliver a signaling message to the peer.
    fn send(&self, msg: &SignalMsg) -> anyhow::Result<()>;
    /// Non-blocking receive of an inbound signaling message.
    fn try_recv(&self) -> Option<SignalMsg>;
}

impl Signaling for SignalClient {
    fn send(&self, msg: &SignalMsg) -> anyhow::Result<()> {
        SignalClient::send(self, msg)
    }
    fn try_recv(&self) -> Option<SignalMsg> {
        SignalClient::try_recv(self)
    }
}

/// Connected signaling client.
pub struct SignalClient {
    /// Write side of the TCP stream (line-buffered by us).
    writer: Arc<Mutex<TcpStream>>,
    /// Inbound messages decoded from the relay.
    inbound: Receiver<SignalMsg>,
}

impl SignalClient {
    /// Connect to `addr` (e.g. `"192.168.1.10:9000"`) and start the reader thread.
    pub fn connect(addr: &str) -> anyhow::Result<Self> {
        let stream = TcpStream::connect(addr)?;
        stream.set_nodelay(true).ok();
        let reader_stream = stream.try_clone()?;
        let writer = Arc::new(Mutex::new(stream));

        let (tx, inbound) = mpsc::channel();
        std::thread::Builder::new()
            .name("openreach-signal-rx".into())
            .spawn(move || {
                let mut lines = BufReader::new(reader_stream).lines();
                while let Some(Ok(line)) = lines.next() {
                    if line.trim().is_empty() {
                        continue;
                    }
                    match serde_json::from_str::<SignalMsg>(&line) {
                        Ok(msg) => {
                            if tx.send(msg).is_err() {
                                break; // consumer gone
                            }
                        }
                        Err(e) => tracing::warn!(error=%e, line=%line, "bad signaling line"),
                    }
                }
                tracing::info!("signaling reader ended");
            })?;

        Ok(Self { writer, inbound })
    }

    /// Send a signaling message to the peer (via the relay).
    pub fn send(&self, msg: &SignalMsg) -> anyhow::Result<()> {
        let mut line = serde_json::to_string(msg)?;
        line.push('\n');
        let mut w = self.writer.lock().unwrap();
        w.write_all(line.as_bytes())?;
        w.flush()?;
        Ok(())
    }

    /// Non-blocking receive of an inbound signaling message.
    pub fn try_recv(&self) -> Option<SignalMsg> {
        self.inbound.try_recv().ok()
    }
}
