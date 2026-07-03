//! Proof that a relay in the media path sees only ciphertext.
//!
//! We interpose a transparent UDP relay between the two peers by rewriting every
//! ICE candidate (trickled and any embedded in SDP) to point at the relay, so
//! all ICE/DTLS/SRTP/SCTP traffic flows through it — exactly the position a TURN
//! relay occupies. The relay records every datagram it forwards. We then send a
//! unique **plaintext canary** over the data channel and assert:
//!
//! 1. both peers connect (so the relay path actually works),
//! 2. the relay forwarded a non-trivial amount of traffic (it was really in path),
//! 3. the peer receives the canary (end-to-end delivery works), and
//! 4. the canary bytes never appear in anything the relay saw — i.e. the relay
//!    only ever handled DTLS-SRTP ciphertext, never session content.

use bytes::Bytes;
use openreach_transport::{SignalMsg, Transport, TransportConfig, TransportEvent, TransportRole};
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// A distinctive plaintext string that must never appear on the wire.
const CANARY: &[u8] = b"OPENREACH-PLAINTEXT-CANARY-9f3a2c71-do-not-leak";

/// Transparent UDP relay: learns the two peer addresses from inbound traffic and
/// cross-forwards, recording every datagram payload.
fn spawn_relay(
    record: Arc<Mutex<Vec<u8>>>,
    packet_count: Arc<Mutex<usize>>,
    stop: Arc<AtomicBool>,
) -> SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind relay");
    sock.set_read_timeout(Some(Duration::from_millis(50))).ok();
    let addr = sock.local_addr().unwrap();
    std::thread::spawn(move || {
        let mut peers: Vec<SocketAddr> = Vec::new();
        let mut buf = [0u8; 4096];
        while !stop.load(Ordering::Relaxed) {
            let Ok((n, src)) = sock.recv_from(&mut buf) else {
                continue;
            };
            record.lock().unwrap().extend_from_slice(&buf[..n]);
            *packet_count.lock().unwrap() += 1;
            if !peers.contains(&src) && peers.len() < 2 {
                peers.push(src);
            }
            if let Some(other) = peers.iter().find(|p| **p != src) {
                sock.send_to(&buf[..n], other).ok();
            }
        }
    });
    addr
}

/// Rewrite the ip/port of every `candidate:...` occurrence to the relay address.
/// The ip is the token two before `typ`, the port the token immediately before.
fn rewrite_candidates(s: &str, relay: SocketAddr) -> String {
    let sep = if s.contains("\r\n") { "\r\n" } else { "\n" };
    s.split(sep)
        .map(|line| {
            if !line.contains("candidate:") {
                return line.to_string();
            }
            let mut toks: Vec<String> = line.split(' ').map(String::from).collect();
            if let Some(i) = toks.iter().position(|t| t == "typ") {
                if i >= 2 {
                    toks[i - 2] = relay.ip().to_string();
                    toks[i - 1] = relay.port().to_string();
                }
            }
            toks.join(" ")
        })
        .collect::<Vec<_>>()
        .join(sep)
}

/// Rewrite whichever signaling message carries candidate addresses.
fn rewrite_signal(msg: SignalMsg, relay: SocketAddr) -> SignalMsg {
    match msg {
        SignalMsg::Offer(s) => SignalMsg::Offer(rewrite_candidates(&s, relay)),
        SignalMsg::Answer(s) => SignalMsg::Answer(rewrite_candidates(&s, relay)),
        SignalMsg::Candidate(s) => SignalMsg::Candidate(rewrite_candidates(&s, relay)),
    }
}

fn drain(t: &Transport) -> Vec<TransportEvent> {
    let mut out = Vec::new();
    while let Some(ev) = t.try_event() {
        out.push(ev);
    }
    out
}

#[test]
fn relay_only_sees_ciphertext() {
    let record = Arc::new(Mutex::new(Vec::<u8>::new()));
    let packet_count = Arc::new(Mutex::new(0usize));
    let stop = Arc::new(AtomicBool::new(false));
    let relay = spawn_relay(record.clone(), packet_count.clone(), stop.clone());

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

    let deadline = Instant::now() + Duration::from_secs(15);
    let mut host_connected = false;
    let mut viewer_connected = false;
    let mut canary_delivered = false;
    let mut last_canary_send = Instant::now();

    while Instant::now() < deadline && !(canary_delivered && host_connected && viewer_connected) {
        for ev in drain(&host) {
            match ev {
                // Host's signaling -> rewrite candidates -> feed viewer.
                TransportEvent::LocalSignal(msg) => viewer.feed_signal(rewrite_signal(msg, relay)),
                TransportEvent::Connected => host_connected = true,
                // Host receives the viewer's canary over the data channel.
                TransportEvent::Data(bytes) if bytes.as_ref() == CANARY => canary_delivered = true,
                _ => {}
            }
        }
        for ev in drain(&viewer) {
            match ev {
                TransportEvent::LocalSignal(msg) => host.feed_signal(rewrite_signal(msg, relay)),
                TransportEvent::Connected => viewer_connected = true,
                _ => {}
            }
        }

        // Once connected, the viewer sends the plaintext canary to the host.
        // Resend periodically: the SCTP data channel opens a little after ICE
        // connects, so a single early send can be dropped.
        if host_connected
            && viewer_connected
            && !canary_delivered
            && last_canary_send.elapsed() >= Duration::from_millis(150)
        {
            viewer.send_data(Bytes::from_static(CANARY));
            last_canary_send = Instant::now();
        }

        std::thread::sleep(Duration::from_millis(2));
    }

    stop.store(true, Ordering::Relaxed);

    let seen = record.lock().unwrap();
    let packets = *packet_count.lock().unwrap();

    eprintln!(
        "DIAG host_connected={host_connected} viewer_connected={viewer_connected} \
         canary_delivered={canary_delivered} relay_packets={packets} relay_bytes={}",
        seen.len()
    );

    assert!(
        host_connected && viewer_connected,
        "peers failed to connect through the relay"
    );
    // The relay must actually have carried the traffic (not a direct P2P bypass).
    assert!(
        packets > 10,
        "relay only saw {packets} packets — traffic likely bypassed it"
    );
    assert!(canary_delivered, "canary was not delivered end-to-end");
    // The crux: the relay handled only ciphertext.
    assert!(
        !contains_subslice(&seen, CANARY),
        "PLAINTEXT LEAK: the canary appeared in relayed traffic ({} bytes seen)",
        seen.len()
    );
}

/// True if `haystack` contains `needle` as a contiguous subsequence.
fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}
