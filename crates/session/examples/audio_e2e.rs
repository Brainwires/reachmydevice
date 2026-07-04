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

    // Optional: also play the round-tripped audio out the speaker (PLAY=1), so a
    // human can hear the full loop. Our own output is excluded from capture
    // (excludesCurrentProcessAudio), so it doesn't feed back.
    let mut playback = if std::env::var("PLAY").is_ok() {
        match openreach_session::audio::AudioPlayback::start() {
            Ok(p) => {
                eprintln!("playback ON — you should hear the captured audio round-tripped");
                Some(p)
            }
            Err(e) => {
                eprintln!("playback unavailable: {e}");
                None
            }
        }
    } else {
        None
    };

    let (mut host_conn, mut view_conn) = (false, false);
    let (mut recv_frames, mut recv_energy) = (0u64, 0.0_f64);
    // Run longer when playing so a human can actually hear the round trip.
    let secs = if playback.is_some() { 12 } else { 6 };
    let frame_cap = if playback.is_some() { u64::MAX } else { 100 };
    let deadline = Instant::now() + Duration::from_secs(secs);

    while Instant::now() < deadline && recv_frames < frame_cap {
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
                            if let Some(p) = playback.as_mut() {
                                p.push_packet(&a.opus, a.seq);
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
