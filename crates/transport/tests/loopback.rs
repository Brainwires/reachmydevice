//! End-to-end loopback proof for the sans-IO WebRTC driver.
//!
//! Spins up a `Host` and a `Viewer` [`Transport`] on `127.0.0.1:0`, bridges
//! their signaling in-process, and drives a full session: ICE/DTLS connect, an
//! H.264 keyframe host→viewer, and a bidirectional data-channel exchange. No
//! STUN — loopback host candidates are sufficient.

use std::time::{Duration, Instant};

use bytes::Bytes;
use rmd_transport::{Transport, TransportConfig, TransportEvent, TransportRole};

/// Build a synthetic but structurally-valid Annex-B H.264 access unit: an SPS,
/// a PPS, and a large IDR slice. The IDR is deliberately > MTU so it exercises
/// FU-A fragmentation and reassembly across multiple RTP packets. The bytes are
/// not decodable video, but the packetizer/depacketizer only inspect NAL types
/// and start codes, so this fully exercises the media path.
fn synthetic_keyframe() -> Bytes {
    const START: [u8; 4] = [0x00, 0x00, 0x00, 0x01];
    let mut au = Vec::new();

    // SPS (nal_ref_idc=3, type=7 => 0x67)
    au.extend_from_slice(&START);
    au.push(0x67);
    au.extend_from_slice(&[0x42, 0xe0, 0x1f, 0x8c, 0x8d, 0x40]);

    // PPS (nal_ref_idc=3, type=8 => 0x68)
    au.extend_from_slice(&START);
    au.push(0x68);
    au.extend_from_slice(&[0xce, 0x3c, 0x80]);

    // IDR slice (nal_ref_idc=3, type=5 => 0x65), padded large to force FU-A.
    au.extend_from_slice(&START);
    au.push(0x65);
    au.extend(std::iter::repeat_n(0xAB, 3000));

    Bytes::from(au)
}

/// Orchestration state accumulated while pumping both transports.
#[derive(Default)]
struct Bridge {
    host_connected: bool,
    viewer_connected: bool,
    video_annexb: Option<Bytes>,
    host_data: Vec<Bytes>,
    viewer_data: Vec<Bytes>,
}

impl Bridge {
    /// Drain all currently-pending events from both sides, forwarding local
    /// signaling to the peer and recording everything else.
    fn pump(&mut self, host: &Transport, viewer: &Transport) {
        while let Some(ev) = host.try_event() {
            match ev {
                TransportEvent::LocalSignal(msg) => viewer.feed_signal(msg),
                TransportEvent::Connected => self.host_connected = true,
                TransportEvent::Disconnected => self.host_connected = false,
                TransportEvent::Data(d) => self.host_data.push(d),
                TransportEvent::Video { .. } => {} // host never receives video
            }
        }
        while let Some(ev) = viewer.try_event() {
            match ev {
                TransportEvent::LocalSignal(msg) => host.feed_signal(msg),
                TransportEvent::Connected => self.viewer_connected = true,
                TransportEvent::Disconnected => self.viewer_connected = false,
                TransportEvent::Video { annexb, .. } => {
                    if self.video_annexb.is_none() {
                        self.video_annexb = Some(annexb);
                    }
                }
                TransportEvent::Data(d) => self.viewer_data.push(d),
            }
        }
    }
}

fn config(role: TransportRole) -> TransportConfig {
    TransportConfig {
        role,
        ice_servers: vec![], // loopback host candidates only
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        video_bitrate_bps: 1_500_000,
    }
}

#[test]
fn loopback_connect_video_and_data() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .with_test_writer()
        .try_init();

    let host = Transport::spawn(config(TransportRole::Host)).expect("spawn host");
    let viewer = Transport::spawn(config(TransportRole::Viewer)).expect("spawn viewer");

    let mut bridge = Bridge::default();

    // Phase 1: both peers reach Connected.
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline && !(bridge.host_connected && bridge.viewer_connected) {
        bridge.pump(&host, &viewer);
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(
        bridge.host_connected && bridge.viewer_connected,
        "both peers should connect (host={}, viewer={})",
        bridge.host_connected,
        bridge.viewer_connected
    );

    // Phase 2: host streams a keyframe; the SampleBuilder only flushes a sample
    // once a *later*-timestamp packet arrives, so we resend on a cadence with an
    // advancing timestamp until the viewer surfaces the reassembled access unit.
    let frame = synthetic_keyframe();
    let video_deadline = Instant::now() + Duration::from_secs(8);
    let mut ts_micros = 0u64;
    while Instant::now() < video_deadline && bridge.video_annexb.is_none() {
        host.send_video(frame.clone(), true, ts_micros);
        ts_micros += 33_000; // ~30 fps
        for _ in 0..7 {
            bridge.pump(&host, &viewer);
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    let received = bridge
        .video_annexb
        .as_ref()
        .expect("viewer should receive a reassembled H.264 access unit");
    assert!(
        received.starts_with(&[0x00, 0x00, 0x00, 0x01]),
        "reassembled video must start with an Annex-B start code, got {:02x?}",
        &received[..received.len().min(8)]
    );
    // The large IDR payload should have survived FU-A round-tripping.
    assert!(
        received.windows(8).any(|w| w == [0xAB; 8]),
        "reassembled access unit should contain the IDR payload"
    );

    // Phase 3a: viewer → host over the data channel.
    viewer.send_data(Bytes::from_static(b"hello"));
    let data_deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < data_deadline && !bridge.host_data.iter().any(|d| d.as_ref() == b"hello")
    {
        bridge.pump(&host, &viewer);
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(
        bridge.host_data.iter().any(|d| d.as_ref() == b"hello"),
        "host should receive the viewer's data-channel message"
    );

    // Phase 3b: host → viewer over the same (bidirectional) channel.
    host.send_data(Bytes::from_static(b"world"));
    let data_deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < data_deadline
        && !bridge.viewer_data.iter().any(|d| d.as_ref() == b"world")
    {
        bridge.pump(&host, &viewer);
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(
        bridge.viewer_data.iter().any(|d| d.as_ref() == b"world"),
        "viewer should receive the host's data-channel message"
    );

    // Phase 4: clean shutdown — dropping the handles joins the driver threads.
    drop(host);
    drop(viewer);
}
