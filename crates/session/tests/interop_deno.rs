//! Interop: ReachMyDevice's host stack against a Deno WebRTC viewer.
//!
//! The host is what `rmdd` runs on the wire, minus capture and input: the
//! rmd-transport Host role (offer, H.264 send track, `control` data channel,
//! GCC/TWCC, the sans-IO driver), rmd-protocol `Envelope` framing on the data
//! channel, and real openh264 encode of synthetic BGRA frames (no screen
//! capture, no input injection, no OS permissions). The viewer is
//! `examples/interop-deno/viewer.ts`, running on the Brainwires Deno fork's
//! `RTCPeerConnection` (`ext/webrtc`): an independent peer/ICE/socket layer and
//! the W3C API over the same webrtc-rs-rtc engine fork.
//!
//! Everything is on 127.0.0.1. Signaling is the `SignalMsg` JSON-lines shape
//! over the Deno process's stdin/stdout.
//!
//! Asserts: ICE + DTLS connect on both sides; Hello -> HelloAck and Ping/Pong
//! in both directions over the data channel; H.264 RTP depacketized by the
//! viewer into access units whose first keyframe carries SPS + PPS + IDR (the
//! viewer checks the SPS size) and which decode here with openh264 at the sent
//! size; a clean close (the viewer's Bye arrives before its data channel
//! closes, the host sees the session end, the Deno process exits 0).
//!
//! Needs a Deno build with `ext/webrtc` (the fork's train/denext26 or later):
//!
//! ```sh
//! RMD_INTEROP_DENO=/path/to/deno \
//!   cargo test -p rmd-session --test interop_deno -- --ignored --nocapture
//! ```

use base64::Engine as _;
use bytes::Bytes;
use rmd_codec::{EncoderConfig, VideoCodec, new_decoder, new_encoder};
use rmd_protocol as proto;
use rmd_protocol::pb::envelope::Payload;
use rmd_transport::{SignalMsg, Transport, TransportConfig, TransportEvent, TransportRole};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

const W: u32 = 320;
const H: u32 = 240;
const HOST_PING_T: u64 = 0x5eed_0000_1234;

/// A synthetic BGRA frame with a moving gradient (mirrors `tests/pipeline.rs`).
fn synthetic_bgra(w: u32, h: u32, seq: u64) -> Vec<u8> {
    let mut buf = vec![0u8; (w * h * 4) as usize];
    let o = (seq as u32).wrapping_mul(7);
    for y in 0..h {
        for x in 0..w {
            let i = ((y * w + x) * 4) as usize;
            buf[i] = ((x + o) % 256) as u8;
            buf[i + 1] = ((y + o) % 256) as u8;
            buf[i + 2] = ((x + y + o) % 256) as u8;
            buf[i + 3] = 255;
        }
    }
    buf
}

/// One line the Deno viewer wrote on stdout.
#[derive(serde::Deserialize, Debug)]
struct ViewerLine {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    data: serde_json::Value,
}

fn spawn_viewer(deno: &str) -> (Child, ChildStdin, mpsc::Receiver<ViewerLine>) {
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/interop-deno/viewer.ts")
        .canonicalize()
        .expect("examples/interop-deno/viewer.ts");
    let mut child = Command::new(deno)
        .args(["run", "--no-config", "--allow-net=127.0.0.1", "--allow-env"])
        .arg(&script)
        .env("RMD_INTEROP_WIDTH", W.to_string())
        .env("RMD_INTEROP_HEIGHT", H.to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn deno");
    let stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else { break };
            match serde_json::from_str::<ViewerLine>(&line) {
                Ok(v) => {
                    if tx.send(v).is_err() {
                        break;
                    }
                }
                Err(e) => eprintln!("[host] unparsable viewer line ({e}): {line}"),
            }
        }
    });
    (child, stdin, rx)
}

fn send_line(stdin: &mut ChildStdin, msg: &SignalMsg) {
    let mut line = serde_json::to_string(msg).unwrap();
    line.push('\n');
    stdin.write_all(line.as_bytes()).expect("write to deno");
    stdin.flush().unwrap();
}

#[derive(Default)]
struct Seen {
    host_connected: bool,
    viewer_connected: bool,
    hello: Option<proto::Hello>,
    host_pong_ok: bool,
    viewer_ready: Option<serde_json::Value>,
    aus: Vec<Bytes>,
    bye: Option<String>,
    host_disconnected: bool,
    keyframe_requests: u32,
    viewer_closed: Option<serde_json::Value>,
}

#[test]
#[ignore = "needs a Deno build with ext/webrtc: set RMD_INTEROP_DENO and run with --ignored"]
fn host_stack_interops_with_deno_viewer() {
    let deno = std::env::var("RMD_INTEROP_DENO")
        .expect("set RMD_INTEROP_DENO to a deno binary with ext/webrtc");

    let host = Transport::spawn(TransportConfig {
        role: TransportRole::Host,
        ice_servers: Vec::new(),
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        video_bitrate_bps: 1_500_000,
        video_codec: Default::default(),
    })
    .expect("host transport");
    let (mut child, mut stdin, lines) = spawn_viewer(&deno);

    let mut encoder = new_encoder(
        VideoCodec::H264,
        EncoderConfig {
            width: W,
            height: H,
            fps: 30,
            bitrate_bps: 1_500_000,
        },
    )
    .expect("encoder");

    let mut seen = Seen::default();
    let mut seq = 0u64;
    let mut last_send = Instant::now();
    let mut close_sent = false;
    let deadline = Instant::now() + Duration::from_secs(40);
    let mut close_at: Option<Instant> = None;

    while Instant::now() < deadline {
        // Host transport -> viewer (signaling) / test state.
        while let Some(ev) = host.try_event() {
            match ev {
                TransportEvent::LocalSignal(msg) => {
                    if !seen.host_disconnected {
                        send_line(&mut stdin, &msg);
                    }
                }
                TransportEvent::Connected => seen.host_connected = true,
                TransportEvent::Disconnected => {
                    seen.host_disconnected = true;
                    eprintln!(
                        "[host] session ended {:?} after the close request",
                        close_at.map(|t| t.elapsed())
                    );
                }
                TransportEvent::Data(bytes) => {
                    let env = proto::decode(&bytes).expect("viewer sent a valid Envelope");
                    proto::check_compatibility(env.protocol_major).expect("protocol major");
                    match env.payload {
                        Some(Payload::Hello(h)) => {
                            assert_eq!(h.role, proto::Role::Viewer as i32, "Hello role");
                            seen.hello = Some(h);
                            host.send_data(Bytes::from(proto::encode(&proto::hello_ack_ok(
                                "rmd-interop-host",
                                0,
                                proto::VideoCodec::H264,
                            ))));
                            host.send_data(Bytes::from(proto::encode(&proto::ping(HOST_PING_T))));
                        }
                        Some(Payload::Ping(p)) => {
                            host.send_data(Bytes::from(proto::encode(&proto::pong(p.t_micros))));
                        }
                        Some(Payload::Pong(p)) => {
                            assert_eq!(p.t_micros, HOST_PING_T, "Pong must echo our Ping");
                            seen.host_pong_ok = true;
                        }
                        Some(Payload::Bye(b)) => seen.bye = Some(b.reason),
                        other => panic!("unexpected payload from viewer: {other:?}"),
                    }
                }
                TransportEvent::KeyframeRequested => seen.keyframe_requests += 1,
                TransportEvent::Video { .. } => panic!("host never receives video"),
            }
        }

        // Viewer -> host.
        while let Ok(line) = lines.try_recv() {
            match line.kind.as_str() {
                "answer" | "candidate" => {
                    let json = serde_json::json!({ "type": line.kind, "data": line.data });
                    let msg: SignalMsg = serde_json::from_value(json).unwrap();
                    host.feed_signal(msg);
                }
                "connected" => seen.viewer_connected = true,
                "au" => {
                    let b64 = line.data.as_str().unwrap();
                    let au = base64::engine::general_purpose::STANDARD
                        .decode(b64)
                        .unwrap();
                    seen.aus.push(Bytes::from(au));
                }
                "ready" => seen.viewer_ready = Some(line.data),
                "closed" => seen.viewer_closed = Some(line.data),
                "fail" => panic!("deno viewer failed: {}", line.data),
                other => eprintln!("[host] viewer line {other}: {}", line.data),
            }
        }

        // Stream frames while connected (forced IDR on the first one).
        if seen.host_connected && !close_sent && last_send.elapsed() >= Duration::from_millis(33) {
            let bgra = synthetic_bgra(W, H, seq);
            if let Ok(Some(ef)) = encoder.encode(&bgra, W, H, W * 4, seq * 33_333, seq == 0) {
                host.send_video(ef.data, ef.is_keyframe, ef.capture_ts_micros);
            }
            seq += 1;
            last_send = Instant::now();
        }

        // Everything checked: ask the viewer to close.
        if !close_sent
            && seen.viewer_ready.is_some()
            && seen.host_pong_ok
            && seen.aus.len() >= 5
            && seen.keyframe_requests > 0
        {
            send_line_raw(&mut stdin, r#"{"type":"close"}"#);
            close_sent = true;
            close_at = Some(Instant::now());
        }
        if seen.viewer_closed.is_some() && seen.host_disconnected {
            break;
        }
        std::thread::sleep(Duration::from_millis(2));
    }

    // The viewer process ends on its own after a clean close.
    let status = wait_child(&mut child, Duration::from_secs(10));
    drop(host); // joins the driver thread

    eprintln!(
        "[host] outcome: host_connected={} viewer_connected={} hello={:?} host_pong_ok={} \
         ready={:?} access_units={} keyframe_requests={} bye={:?} host_disconnected={} viewer_closed={:?}\n\
         [host] deno exit: {status:?}",
        seen.host_connected,
        seen.viewer_connected,
        seen.hello,
        seen.host_pong_ok,
        seen.viewer_ready,
        seen.aus.len(),
        seen.keyframe_requests,
        seen.bye,
        seen.host_disconnected,
        seen.viewer_closed,
    );
    assert!(
        seen.host_connected,
        "host never reached Connected (ICE+DTLS)"
    );
    assert!(seen.viewer_connected, "Deno viewer never reached connected");
    let hello = seen.hello.as_ref().expect("no Hello from the viewer");
    assert_eq!(hello.device_name, "deno-interop-viewer");
    assert_eq!(
        hello.supported_video_codecs,
        vec![proto::VideoCodec::H264 as i32]
    );
    assert!(seen.host_pong_ok, "viewer did not answer the host's Ping");
    // The viewer's RTCP PLI (Deno.webrtc.requestKeyFrame) reaches the host as a
    // keyframe request (the KeyFrameRequests interceptor the host registers).
    assert!(
        seen.keyframe_requests > 0,
        "the viewer's PLI never reached the host"
    );
    let ready = seen
        .viewer_ready
        .as_ref()
        .expect("viewer never reported ready");
    assert_eq!(ready["keyframe"]["width"], W);
    assert_eq!(ready["keyframe"]["height"], H);

    // The access units the viewer depacketized decode with openh264.
    let mut decoder = new_decoder(VideoCodec::H264).expect("decoder");
    let mut decoded = 0;
    for au in &seen.aus {
        if let Ok(Some(frame)) = decoder.decode(au) {
            assert_eq!((frame.width, frame.height), (W, H));
            decoded += 1;
        }
    }
    assert!(
        decoded > 0,
        "none of {} forwarded access units decoded",
        seen.aus.len()
    );

    assert_eq!(
        seen.bye.as_deref(),
        Some("deno-interop done"),
        "the viewer's Bye must arrive before its data channel closes"
    );
    assert!(seen.host_disconnected, "host did not see the session end");
    let closed = seen
        .viewer_closed
        .as_ref()
        .expect("viewer did not report a clean close");
    assert_eq!(closed["dataChannel"], "closed");
    assert_eq!(closed["connection"], "closed");
    assert!(
        matches!(status, Some(s) if s.success()),
        "deno viewer did not exit cleanly: {status:?}"
    );
    eprintln!(
        "[host] PASS: {} access units forwarded, {decoded} decoded at {W}x{H}; ready={ready}",
        seen.aus.len()
    );
}

fn send_line_raw(stdin: &mut ChildStdin, line: &str) {
    stdin.write_all(line.as_bytes()).unwrap();
    stdin.write_all(b"\n").unwrap();
    stdin.flush().unwrap();
}

fn wait_child(child: &mut Child, timeout: Duration) -> Option<std::process::ExitStatus> {
    let until = Instant::now() + timeout;
    while Instant::now() < until {
        if let Ok(Some(s)) = child.try_wait() {
            return Some(s);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let _ = child.kill();
    let _ = child.wait();
    None
}
