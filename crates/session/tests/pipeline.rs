//! Headless end-to-end media-pipeline test.
//!
//! Proves the spike's core claim — capture-shaped BGRA frames survive
//! **encode → WebRTC transport (RTP + DTLS-SRTP over loopback) → decode** — with
//! the real openh264 codec on both ends and the real `rtc` transport, without a
//! screen, window, or OS permissions. (Screen capture, input injection, and
//! on-glass rendering are validated separately on-device; see the Phase 1 report.)

use rmd_codec::{new_decoder, new_encoder, EncoderConfig, VideoCodec};
use rmd_transport::{SignalMsg, Transport, TransportConfig, TransportEvent, TransportRole};
use std::time::{Duration, Instant};

/// Drain all currently-available events from a transport.
fn drain(t: &Transport) -> Vec<TransportEvent> {
    let mut out = Vec::new();
    while let Some(ev) = t.try_event() {
        out.push(ev);
    }
    out
}

/// A synthetic BGRA frame with a moving gradient (so it isn't a static image).
fn synthetic_bgra(w: u32, h: u32, seq: u64) -> Vec<u8> {
    let mut buf = vec![0u8; (w * h * 4) as usize];
    let o = (seq as u32).wrapping_mul(7);
    for y in 0..h {
        for x in 0..w {
            let i = ((y * w + x) * 4) as usize;
            buf[i] = ((x + o) % 256) as u8; // B
            buf[i + 1] = ((y + o) % 256) as u8; // G
            buf[i + 2] = ((x + y + o) % 256) as u8; // R
            buf[i + 3] = 255; // A
        }
    }
    buf
}

#[test]
fn end_to_end_encode_transport_decode() {
    let (w, h) = (320u32, 240u32);

    let host = Transport::spawn(TransportConfig {
        role: TransportRole::Host,
        ice_servers: Vec::new(),
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        video_bitrate_bps: 1_500_000,
        video_codec: Default::default(),
    })
    .expect("host transport");
    let viewer = Transport::spawn(TransportConfig {
        role: TransportRole::Viewer,
        ice_servers: Vec::new(),
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        video_bitrate_bps: 1_500_000,
        video_codec: Default::default(),
    })
    .expect("viewer transport");

    let mut encoder = new_encoder(
        VideoCodec::H264,
        EncoderConfig {
            width: w,
            height: h,
            fps: 30,
            bitrate_bps: 1_500_000,
        },
    )
    .expect("encoder");
    let mut decoder = new_decoder(VideoCodec::H264).expect("decoder");

    let deadline = Instant::now() + Duration::from_secs(15);
    let mut host_connected = false;
    let mut viewer_connected = false;
    let mut decoded_dims: Option<(u32, u32)> = None;
    let mut seq = 0u64;
    let mut last_send = Instant::now();

    while Instant::now() < deadline && decoded_dims.is_none() {
        // Bridge signaling both directions.
        for ev in drain(&host) {
            match ev {
                TransportEvent::LocalSignal(SignalMsg::Offer(s)) => {
                    viewer.feed_signal(SignalMsg::Offer(s))
                }
                TransportEvent::LocalSignal(SignalMsg::Answer(s)) => {
                    viewer.feed_signal(SignalMsg::Answer(s))
                }
                TransportEvent::LocalSignal(SignalMsg::Candidate(s)) => {
                    viewer.feed_signal(SignalMsg::Candidate(s))
                }
                TransportEvent::Connected => host_connected = true,
                _ => {}
            }
        }
        for ev in drain(&viewer) {
            match ev {
                TransportEvent::LocalSignal(SignalMsg::Offer(s)) => {
                    host.feed_signal(SignalMsg::Offer(s))
                }
                TransportEvent::LocalSignal(SignalMsg::Answer(s)) => {
                    host.feed_signal(SignalMsg::Answer(s))
                }
                TransportEvent::LocalSignal(SignalMsg::Candidate(s)) => {
                    host.feed_signal(SignalMsg::Candidate(s))
                }
                TransportEvent::Connected => viewer_connected = true,
                TransportEvent::Video { annexb, .. } => {
                    if let Ok(Some(frame)) = decoder.decode(&annexb) {
                        decoded_dims = Some((frame.width, frame.height));
                    }
                }
                _ => {}
            }
        }

        // Once connected, stream frames. The SampleBuilder only flushes an access
        // unit when a later-timestamp packet arrives, so we send continuously.
        if host_connected && viewer_connected && last_send.elapsed() >= Duration::from_millis(33) {
            let bgra = synthetic_bgra(w, h, seq);
            if let Ok(Some(ef)) = encoder.encode(&bgra, w, h, w * 4, seq * 33_000, seq == 0) {
                host.send_video(ef.data, ef.is_keyframe, ef.capture_ts_micros);
            }
            seq += 1;
            last_send = Instant::now();
        }

        std::thread::sleep(Duration::from_millis(2));
    }

    assert!(host_connected && viewer_connected, "peers did not connect");
    assert_eq!(
        decoded_dims,
        Some((w, h)),
        "viewer did not decode a frame end-to-end"
    );
}
