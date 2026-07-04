//! Verify the rendezvous WebSocket + relay work through a (Cloudflare) tunnel.
//!
//! Connects two real `RendezvousClient`s to a deployed rendezvous, has one send
//! a signaling message addressed to the other, and confirms it is relayed.
//! Proves the WSS path (incl. any proxy) and the server's relay end-to-end.
//!
//! Env: `OPENREACH_RZV_URL` (e.g. `wss://openreach.brainwires.dev/ws`),
//! `OPENREACH_TOK_A`, `OPENREACH_TOK_B`, `OPENREACH_DEV_B` (device id of B).

use openreach_session::rendezvous::RendezvousClient;
use openreach_session::Signaling;
use openreach_transport::SignalMsg;
use std::time::{Duration, Instant};

fn main() -> anyhow::Result<()> {
    let url = std::env::var("OPENREACH_RZV_URL")?;
    let tok_a = std::env::var("OPENREACH_TOK_A")?;
    let tok_b = std::env::var("OPENREACH_TOK_B")?;
    let dev_b = std::env::var("OPENREACH_DEV_B")?;

    // A knows B's id (like a viewer targeting a host); B learns A from the hello.
    let a = RendezvousClient::connect(&url, &tok_a, Some(dev_b))?;
    let b = RendezvousClient::connect(&url, &tok_b, None)?;

    let deadline = Instant::now() + Duration::from_secs(15);
    let mut last_send = Instant::now() - Duration::from_secs(1);
    let mut delivered = false;

    while Instant::now() < deadline && !delivered {
        // A repeatedly offers to B until B (which had to learn A first) receives it.
        if last_send.elapsed() >= Duration::from_millis(400) {
            a.send(&SignalMsg::Offer("relay-check".into()))?;
            last_send = Instant::now();
        }
        if let Some(SignalMsg::Offer(s)) = b.try_recv() {
            if s == "relay-check" {
                delivered = true;
            }
        }
        // Drain A's inbound too (B never sends here).
        let _ = a.try_recv();
        std::thread::sleep(Duration::from_millis(20));
    }

    if delivered {
        println!("RESULT ok: WS + relay work through the tunnel (A -> server -> B delivered)");
        Ok(())
    } else {
        anyhow::bail!("message was NOT relayed through the tunnel within 15s")
    }
}
