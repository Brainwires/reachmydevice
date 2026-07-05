//! End-to-end signaling test through the real rendezvous server.
//!
//! Starts the actual `rmd-rendezvous` axum server in-process, registers a
//! user + two devices over HTTP (getting real bearer tokens), then drives two
//! `Transport`s whose signaling flows entirely through the real
//! `RendezvousClient` → WebSocket → server relay → other `RendezvousClient`.
//! Asserts both peers connect and a data-channel message is delivered — proving
//! the whole Phase-2 signaling path, not just an in-process bridge.

use rmd_rendezvous::{init_state, serve, Config};
use rmd_session::rendezvous::RendezvousClient;
use rmd_session::Signaling;
use rmd_transport::{Transport, TransportConfig, TransportEvent, TransportRole};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

/// Minimal blocking HTTP/1.1 request against the local server. Returns (status, body).
fn http(
    addr: SocketAddr,
    method: &str,
    path: &str,
    body: Option<&str>,
    auth: Option<&str>,
) -> (u16, String) {
    let mut s = TcpStream::connect(addr).unwrap();
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n");
    if let Some(a) = auth {
        req.push_str(&format!("Authorization: {a}\r\n"));
    }
    if let Some(b) = body {
        req.push_str(&format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            b.len()
        ));
    }
    req.push_str("\r\n");
    if let Some(b) = body {
        req.push_str(b);
    }
    s.write_all(req.as_bytes()).unwrap();
    let mut resp = String::new();
    s.read_to_string(&mut resp).unwrap();
    let status = resp
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    let body = resp
        .split_once("\r\n\r\n")
        .map(|(_, b)| b)
        .unwrap_or("")
        .to_string();
    (status, body)
}

/// Register a device and return its bearer token.
fn register_device(addr: SocketAddr, device_id: &str) -> String {
    let body = format!(
        r#"{{"username":"e2e","password":"password123","device_id":"{device_id}","name":"{device_id}","public_key":"PK"}}"#
    );
    let (status, resp) = http(addr, "POST", "/api/devices", Some(&body), None);
    assert_eq!(status, 200, "device register failed: {resp}");
    let v: serde_json::Value = serde_json::from_str(&resp).unwrap();
    v["token"].as_str().unwrap().to_string()
}

fn drain(t: &Transport) -> Vec<TransportEvent> {
    let mut out = Vec::new();
    while let Some(ev) = t.try_event() {
        out.push(ev);
    }
    out
}

#[test]
fn connect_two_peers_through_real_rendezvous() {
    // --- start the real server in-process on an ephemeral port ---
    let db_path = std::env::temp_dir().join(format!("or-e2e-{}.db", std::process::id()));
    let _ = std::fs::remove_file(&db_path);
    let db_url = format!("sqlite:{}?mode=rwc", db_path.display());

    let (addr_tx, addr_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            let cfg = Config {
                bind_addr: "127.0.0.1:0".parse().unwrap(),
                database_url: db_url,
                allow_open_registration: true,
            };
            let state = init_state(cfg).await.unwrap();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            addr_tx.send(listener.local_addr().unwrap()).unwrap();
            serve(state, listener).await.unwrap();
        });
    });
    let addr = addr_rx.recv_timeout(Duration::from_secs(5)).unwrap();

    // --- register a user + two devices, get real tokens ---
    let (s, _) = http(
        addr,
        "POST",
        "/api/register",
        Some(r#"{"username":"e2e","password":"password123"}"#),
        None,
    );
    assert_eq!(s, 200, "user register failed");
    let host_token = register_device(addr, "host-device");
    let viewer_token = register_device(addr, "viewer-device");

    let ws_url = format!("ws://{addr}/ws");

    // --- rendezvous signaling clients (host learns the viewer; viewer targets host) ---
    let host_rzv = RendezvousClient::connect(&ws_url, &host_token, None).unwrap();
    let viewer_rzv =
        RendezvousClient::connect(&ws_url, &viewer_token, Some("host-device".to_string())).unwrap();

    // --- two transports; all signaling flows through the rendezvous clients ---
    let host = Transport::spawn(TransportConfig {
        role: TransportRole::Host,
        ice_servers: Vec::new(),
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        video_bitrate_bps: 1_000_000,
    })
    .unwrap();
    let viewer = Transport::spawn(TransportConfig {
        role: TransportRole::Viewer,
        ice_servers: Vec::new(),
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        video_bitrate_bps: 1_000_000,
    })
    .unwrap();

    let deadline = Instant::now() + Duration::from_secs(20);
    let mut host_connected = false;
    let mut viewer_connected = false;
    let mut data_delivered = false;
    let mut last_send = Instant::now();

    while Instant::now() < deadline && !(host_connected && viewer_connected && data_delivered) {
        // host transport <-> host rendezvous client
        for ev in drain(&host) {
            match ev {
                TransportEvent::LocalSignal(msg) => host_rzv.send(&msg).unwrap(),
                TransportEvent::Connected => host_connected = true,
                TransportEvent::Data(b) if b.as_ref() == b"ping-through-rendezvous" => {
                    data_delivered = true
                }
                _ => {}
            }
        }
        while let Some(msg) = host_rzv.try_recv() {
            host.feed_signal(msg);
        }

        // viewer transport <-> viewer rendezvous client
        for ev in drain(&viewer) {
            match ev {
                TransportEvent::LocalSignal(msg) => viewer_rzv.send(&msg).unwrap(),
                TransportEvent::Connected => viewer_connected = true,
                _ => {}
            }
        }
        while let Some(msg) = viewer_rzv.try_recv() {
            viewer.feed_signal(msg);
        }

        // Once connected, the viewer sends a data-channel message to the host.
        if host_connected
            && viewer_connected
            && !data_delivered
            && last_send.elapsed() >= Duration::from_millis(150)
        {
            viewer.send_data(bytes::Bytes::from_static(b"ping-through-rendezvous"));
            last_send = Instant::now();
        }

        std::thread::sleep(Duration::from_millis(2));
    }

    let _ = std::fs::remove_file(&db_path);
    assert!(
        host_connected && viewer_connected,
        "peers did not connect through the rendezvous server (host={host_connected} viewer={viewer_connected})"
    );
    assert!(
        data_delivered,
        "data channel message was not delivered end-to-end through the rendezvous"
    );
}
