//! Headless viewer for automated testing.
//!
//! Connects like the real viewer (via the LAN signaling relay), but has no
//! window — it decodes incoming frames with [`ViewerSession`] and reports how
//! many arrived. Used to validate the full host→viewer pipeline (real capture →
//! encode → transport → decode) without a display or GPU.
//!
//! Env: `OPENREACH_SIGNAL_ADDR` (default `127.0.0.1:9000`),
//! `OPENREACH_BIND` (default `0.0.0.0:0`), `OPENREACH_ICE` (comma-separated),
//! `OPENREACH_TEST_SECS` (default `12`). Exits non-zero if no frames decode.

use openreach_session::rendezvous::RendezvousClient;
use openreach_session::{SignalClient, Signaling, ViewerConfig, ViewerSession, ViewerUpdate};
use std::time::{Duration, Instant};

/// Rendezvous WebSocket if `OPENREACH_RENDEZVOUS_URL` is set, else the LAN relay.
fn build_signaling() -> anyhow::Result<Box<dyn Signaling>> {
    if let Ok(url) = std::env::var("OPENREACH_RENDEZVOUS_URL") {
        let token = std::env::var("OPENREACH_TOKEN")?;
        let peer = std::env::var("OPENREACH_PEER_DEVICE_ID")?;
        Ok(Box::new(RendezvousClient::connect(
            &url,
            &token,
            Some(peer),
        )?))
    } else {
        let addr =
            std::env::var("OPENREACH_SIGNAL_ADDR").unwrap_or_else(|_| "127.0.0.1:9000".into());
        Ok(Box::new(SignalClient::connect(&addr)?))
    }
}

fn main() -> anyhow::Result<()> {
    let secs: u64 = std::env::var("OPENREACH_TEST_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(12);

    let cfg = ViewerConfig {
        device_name: "headless-viewer".into(),
        ice_servers: std::env::var("OPENREACH_ICE")
            .map(|s| {
                s.split(',')
                    .map(|x| x.trim().to_string())
                    .filter(|x| !x.is_empty())
                    .collect()
            })
            .unwrap_or_default(),
        bind_addr: std::env::var("OPENREACH_BIND").unwrap_or_else(|_| "0.0.0.0:0".into()),
        enable_audio: std::env::var("OPENREACH_AUDIO").is_ok(),
    };

    let signaling = build_signaling()?;
    let session = ViewerSession::start(cfg, signaling)?;

    let start = Instant::now();
    let (mut connected, mut frames, mut first, mut dims) = (false, 0u32, None, None);
    while start.elapsed() < Duration::from_secs(secs) {
        while let Some(u) = session.poll_update() {
            match u {
                ViewerUpdate::Connected => {
                    connected = true;
                    eprintln!("[headless] connected");
                }
                ViewerUpdate::Paired(ok) => eprintln!("[headless] paired={ok}"),
                ViewerUpdate::Frame(f) => {
                    frames += 1;
                    if first.is_none() {
                        first = Some(start.elapsed());
                    }
                    dims = Some((f.width, f.height));
                }
                ViewerUpdate::Disconnected => eprintln!("[headless] disconnected"),
                ViewerUpdate::Latency(rtt) => eprintln!("[headless] rtt={rtt:?}"),
                ViewerUpdate::File(ev) => eprintln!("[headless] file {ev:?}"),
                ViewerUpdate::Displays(d) => eprintln!("[headless] displays={}", d.len()),
            }
        }
        std::thread::sleep(Duration::from_millis(5));
    }

    println!(
        "RESULT connected={connected} frames={frames} dims={dims:?} first_frame_after={first:?}"
    );
    anyhow::ensure!(frames > 0, "no frames decoded end-to-end");
    Ok(())
}
