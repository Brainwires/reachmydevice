//! End-to-end direct-pairing test: start the real rendezvous, then pair two
//! fresh device identities over the stateless `/pair` mailbox using a shared
//! code — SPAKE2, key confirmation, and identity exchange, all through the relay
//! (which only forwards opaque frames). Proves pairing.rs + the mailbox + the
//! pairing client work together with no accounts.

use openreach_rendezvous::{init_state, serve, Config};
use openreach_session::pairing::generate_pairing_code;
use openreach_session::pairing_client::pair_pake;
use openreach_session::DeviceIdentity;
use std::time::Duration;

#[test]
fn two_devices_pair_over_the_stateless_relay() {
    // --- start the real server in-process on an ephemeral port ---
    let db_path = std::env::temp_dir().join(format!("or-pair-e2e-{}.db", std::process::id()));
    let _ = std::fs::remove_file(&db_path);
    let db_url = format!("sqlite:{}?mode=rwc", db_path.display());

    let (addr_tx, addr_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            let cfg = Config {
                bind_addr: "127.0.0.1:0".parse().unwrap(),
                database_url: db_url,
                allow_open_registration: false, // pairing needs no account
            };
            let state = init_state(cfg).await.unwrap();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            addr_tx.send(listener.local_addr().unwrap()).unwrap();
            serve(state, listener).await.unwrap();
        });
    });
    let addr = addr_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let ws_base = format!("ws://{addr}");

    // --- pair two devices with a shared code ---
    let code = generate_pairing_code().unwrap();
    let id_a = DeviceIdentity::generate().unwrap();
    let id_b = DeviceIdentity::generate().unwrap();

    let rt = tokio::runtime::Runtime::new().unwrap();
    let (ra, rb) = rt.block_on(async {
        let a = pair_pake(&ws_base, &code, &id_a, "device-a");
        let b = pair_pake(&ws_base, &code, &id_b, "device-b");
        tokio::join!(a, b)
    });

    let a_view = ra.expect("device A pairing failed");
    let b_view = rb.expect("device B pairing failed");

    // Each learned the *other's* authenticated identity.
    assert_eq!(a_view.device_id, id_b.device_id());
    assert_eq!(a_view.public_key, id_b.public_key_bytes());
    assert_eq!(a_view.name, "device-b");
    assert_eq!(b_view.device_id, id_a.device_id());
    assert_eq!(b_view.public_key, id_a.public_key_bytes());
    assert_eq!(b_view.name, "device-a");

    let _ = std::fs::remove_file(&db_path);
}

#[test]
fn mismatched_code_fails_to_pair() {
    let db_path = std::env::temp_dir().join(format!("or-pair-bad-{}.db", std::process::id()));
    let _ = std::fs::remove_file(&db_path);
    let db_url = format!("sqlite:{}?mode=rwc", db_path.display());
    let (addr_tx, addr_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            let cfg = Config {
                bind_addr: "127.0.0.1:0".parse().unwrap(),
                database_url: db_url,
                allow_open_registration: false,
            };
            let state = init_state(cfg).await.unwrap();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            addr_tx.send(listener.local_addr().unwrap()).unwrap();
            serve(state, listener).await.unwrap();
        });
    });
    let addr = addr_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let ws_base = format!("ws://{addr}");

    // Same channel (so they meet), different secret (wrong PAKE password).
    let id_a = DeviceIdentity::generate().unwrap();
    let id_b = DeviceIdentity::generate().unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (ra, rb) = rt.block_on(async {
        let a = pair_pake(&ws_base, "77-rightsecret", &id_a, "a");
        let b = pair_pake(&ws_base, "77-wrongsecret", &id_b, "b");
        tokio::join!(a, b)
    });
    // At least one side must reject (confirmation mismatch).
    assert!(ra.is_err() || rb.is_err(), "mismatched code must not pair");
    let _ = std::fs::remove_file(&db_path);
}
