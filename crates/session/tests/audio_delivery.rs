//! Headless end-to-end **audio delivery** test — the audio analog of
//! `pipeline.rs`.
//!
//! Proves that audio survives **Opus encode → WebRTC data channel (SCTP over
//! DTLS, loopback) → Opus decode** with the real `codec::audio` codec on both
//! ends and the real `rtc` transport — no audio device, no speaker, no OS
//! permission. A synthetic tone stands in for the capture device exactly as
//! `pipeline.rs` uses a synthetic frame for the screen (the capture *device* and
//! speaker output are the OS/hardware boundaries, validated separately on-device;
//! everything between them — encode, real network transport, decode — is proven
//! here).

// The whole test needs the C Opus codec; it compiles to nothing in the default
// (pure-Rust) build. Run with `cargo test -p rmd-session --features audio`.
#![cfg(feature = "audio")]

use bytes::Bytes;
use rmd_codec::{AudioDecoder, AudioEncoder, AUDIO_FRAME_SAMPLES, AUDIO_SAMPLE_RATE};
use rmd_protocol as proto;
use rmd_transport::{Transport, TransportConfig, TransportEvent, TransportRole};
use std::time::{Duration, Instant};

fn drain(t: &Transport) -> Vec<TransportEvent> {
    let mut out = Vec::new();
    while let Some(ev) = t.try_event() {
        out.push(ev);
    }
    out
}

/// One 20 ms frame of a 440 Hz tone at 48 kHz mono, phase-continuous via `seq`.
fn synthetic_tone(seq: u64) -> Vec<i16> {
    let step = 2.0 * std::f32::consts::PI * 440.0 / AUDIO_SAMPLE_RATE as f32;
    let base = (seq as usize * AUDIO_FRAME_SAMPLES) as f32;
    (0..AUDIO_FRAME_SAMPLES)
        .map(|i| (((base + i as f32) * step).sin() * 12000.0) as i16)
        .collect()
}

#[test]
fn audio_survives_encode_transport_decode() {
    let host = Transport::spawn(TransportConfig {
        role: TransportRole::Host,
        ice_servers: Vec::new(),
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        video_bitrate_bps: 1_500_000,
    })
    .expect("host transport");
    let viewer = Transport::spawn(TransportConfig {
        role: TransportRole::Viewer,
        ice_servers: Vec::new(),
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        video_bitrate_bps: 1_500_000,
    })
    .expect("viewer transport");

    let mut encoder = AudioEncoder::new(24_000).expect("opus encoder");
    let mut decoder = AudioDecoder::new().expect("opus decoder");

    let deadline = Instant::now() + Duration::from_secs(15);
    let (mut host_connected, mut viewer_connected) = (false, false);
    let mut send_seq = 0u64;
    let mut last_send = Instant::now();

    // Received-audio accumulators.
    let mut recv_frames = 0u64;
    let mut recv_energy = 0.0_f64;
    const WANT_FRAMES: u64 = 25; // ~0.5 s of audio delivered end-to-end

    while Instant::now() < deadline && recv_frames < WANT_FRAMES {
        for ev in drain(&host) {
            match ev {
                TransportEvent::LocalSignal(msg) => viewer.feed_signal(msg),
                TransportEvent::Connected => host_connected = true,
                _ => {}
            }
        }
        for ev in drain(&viewer) {
            match ev {
                TransportEvent::LocalSignal(msg) => host.feed_signal(msg),
                TransportEvent::Connected => viewer_connected = true,
                TransportEvent::Data(bytes) => {
                    // The real delivered bytes → protocol envelope → Opus → PCM.
                    if let Ok(env) = proto::decode(&bytes) {
                        if let Some(proto::pb::envelope::Payload::Audio(a)) = env.payload {
                            if let Ok(pcm) = decoder.decode(Some(&a.opus), false) {
                                recv_frames += 1;
                                recv_energy += pcm.iter().map(|&s| (s as f64).powi(2)).sum::<f64>();
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        // Once connected, stream Opus audio frames over the data channel.
        if host_connected && viewer_connected && last_send.elapsed() >= Duration::from_millis(20) {
            let pcm = synthetic_tone(send_seq);
            if let Ok(packet) = encoder.encode(&pcm) {
                let env = proto::audio_frame(packet, send_seq);
                host.send_data(Bytes::from(proto::encode(&env)));
            }
            send_seq += 1;
            last_send = Instant::now();
        }

        std::thread::sleep(Duration::from_millis(2));
    }

    assert!(host_connected && viewer_connected, "peers did not connect");
    assert!(
        recv_frames >= WANT_FRAMES,
        "only {recv_frames}/{WANT_FRAMES} audio frames delivered end-to-end"
    );
    // The delivered, decoded audio must carry real signal energy (the tone
    // survived the real transport), not silence.
    let avg = recv_energy / (recv_frames * AUDIO_FRAME_SAMPLES as u64) as f64;
    assert!(
        avg > 1_000_000.0,
        "delivered audio was silent/degraded (avg={avg:.0})"
    );
}
