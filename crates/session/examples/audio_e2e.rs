//! Full real-audio end-to-end: **real macOS system-audio capture → Opus →
//! real WebRTC/DTLS-SRTP transport → Opus decode**, in one run.
//!
//! Unlike `tests/audio_delivery.rs` (synthetic tone), the source here is the
//! actual OS audio device via `capture::start_audio_capture` (ScreenCaptureKit).
//! Play something on the host, then run:
//!
//!   cargo run -p openreach-session --example audio_e2e
//!
//! Reports how many audio frames were delivered end-to-end and their energy —
//! non-zero energy proves real captured audio survived the whole chain. The only
//! link not exercised is the physical speaker (a human-ear step).

use bytes::Bytes;
use openreach_codec::{AudioDecoder, AudioEncoder, AUDIO_FRAME_SAMPLES};
use openreach_protocol as proto;
use openreach_transport::{Transport, TransportConfig, TransportEvent, TransportRole};
use std::collections::VecDeque;
use std::sync::mpsc;
use std::time::{Duration, Instant};

fn drain(t: &Transport) -> Vec<TransportEvent> {
    let mut out = Vec::new();
    while let Some(ev) = t.try_event() {
        out.push(ev);
    }
    out
}

fn main() -> anyhow::Result<()> {
    // Real OS audio capture (mono 48 kHz i16).
    let (cap_tx, cap_rx) = mpsc::channel::<Vec<i16>>();
    let _capture = openreach_capture::start_audio_capture(0, cap_tx)?;
    eprintln!("real desktop-audio capture started; play something…");

    let host = Transport::spawn(TransportConfig {
        role: TransportRole::Host,
        ice_servers: Vec::new(),
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        video_bitrate_bps: 1_500_000,
    })?;
    let viewer = Transport::spawn(TransportConfig {
        role: TransportRole::Viewer,
        ice_servers: Vec::new(),
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        video_bitrate_bps: 1_500_000,
    })?;

    let mut encoder = AudioEncoder::new(24_000)?;
    let mut decoder = AudioDecoder::new()?;
    let mut pending: VecDeque<i16> = VecDeque::new();
    let mut seq = 0u64;

    let (mut host_conn, mut view_conn) = (false, false);
    let (mut recv_frames, mut recv_energy) = (0u64, 0.0_f64);
    let deadline = Instant::now() + Duration::from_secs(12);

    while Instant::now() < deadline && recv_frames < 100 {
        for ev in drain(&host) {
            match ev {
                TransportEvent::LocalSignal(m) => viewer.feed_signal(m),
                TransportEvent::Connected => host_conn = true,
                _ => {}
            }
        }
        for ev in drain(&viewer) {
            match ev {
                TransportEvent::LocalSignal(m) => host.feed_signal(m),
                TransportEvent::Connected => view_conn = true,
                TransportEvent::Data(bytes) => {
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

        // Buffer captured samples into 20 ms frames and send once connected.
        while let Ok(chunk) = cap_rx.try_recv() {
            pending.extend(chunk);
        }
        if host_conn && view_conn {
            while pending.len() >= AUDIO_FRAME_SAMPLES {
                let frame: Vec<i16> = pending.drain(..AUDIO_FRAME_SAMPLES).collect();
                if let Ok(packet) = encoder.encode(&frame) {
                    host.send_data(Bytes::from(proto::encode(&proto::audio_frame(packet, seq))));
                    seq += 1;
                }
            }
        }

        std::thread::sleep(Duration::from_millis(2));
    }

    let rms = if recv_frames > 0 {
        (recv_energy / (recv_frames * AUDIO_FRAME_SAMPLES as u64) as f64).sqrt()
    } else {
        0.0
    };
    println!(
        "RESULT connected={} audio_frames_delivered={recv_frames} decoded_rms={rms:.1}",
        host_conn && view_conn
    );
    anyhow::ensure!(host_conn && view_conn, "transports did not connect");
    anyhow::ensure!(recv_frames > 0, "no audio delivered end-to-end");
    Ok(())
}
