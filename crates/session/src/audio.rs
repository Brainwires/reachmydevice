//! Optional audio: host capture → Opus → viewer playback (opt-in, default off).
//!
//! Real end-to-end path: capture → Opus (`codec::audio`) → data channel → Opus
//! decode → cpal playback, with a dependency-free resampler + mono downmix
//! (codec and resampler are unit-tested).
//!
//! **Source.** [`AudioCapture`] prefers real **desktop/system audio** — what's
//! actually playing on the host — via the platform backend
//! ([`openreach_capture::start_audio_capture`], ScreenCaptureKit on macOS). It
//! falls back to the default **input device** (cpal) only where desktop capture
//! isn't available (e.g. Linux) or is denied. macOS desktop capture requires the
//! Screen Recording permission — the same one the host already needs for video.
//!
//! **Transport.** Frames ride the reliable/ordered data channel (no loss, but
//! latency can accrue under congestion). A dedicated Opus RTP track is a future
//! optimization; the decoder's PLC path is already wired for it.
//!
//! It is **opt-in** (`enable_audio`) and off by default — a deliberate product
//! choice (a host shouldn't broadcast its audio unless asked), which also keeps
//! the proven video path unaffected.

use codec::{AudioDecoder, AudioEncoder, AUDIO_FRAME_SAMPLES, AUDIO_SAMPLE_RATE};
use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use openreach_codec as codec;
use std::collections::VecDeque;
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};

/// Host-side capture: default input device → mono 48 kHz → Opus packets.
///
/// Holds the live capture source (kept alive by this struct) and an encode thread.
pub struct AudioCapture {
    _source: AudioSource,
}

/// The kept-alive capture handle. `Desktop` is real system audio (macOS
/// ScreenCaptureKit); `Device` is the cpal fallback (microphone / default input);
/// `Synthetic` is a generated tone (headless hosts / cross-machine delivery
/// tests, where no capture device exists). All are RAII guards.
#[allow(dead_code)]
enum AudioSource {
    Desktop(Box<dyn openreach_capture::CaptureSession>),
    Device(cpal::Stream),
    Synthetic,
}

impl AudioCapture {
    /// Start capturing. `on_packet` is called with each Opus packet (~50/sec).
    ///
    /// Prefers real **desktop/system audio** (what's playing on the host) via the
    /// platform capture backend; falls back to the default input device where
    /// desktop capture isn't available.
    pub fn start<F>(bitrate_bps: i32, on_packet: F) -> anyhow::Result<Self>
    where
        F: Fn(Vec<u8>) + Send + 'static,
    {
        // Synthetic source: a generated 440 Hz tone, for headless hosts with no
        // capture device (e.g. proving cross-machine audio delivery). Opt-in.
        if std::env::var("OPENREACH_AUDIO_SYNTH").is_ok() {
            tracing::info!("audio source: synthetic 440 Hz tone");
            let (tx, rx) = mpsc::channel::<Vec<i16>>();
            std::thread::Builder::new()
                .name("openreach-audio-synth".into())
                .spawn(move || {
                    let step = 2.0 * std::f32::consts::PI * 440.0 / 48_000.0;
                    let mut phase = 0.0_f32;
                    loop {
                        let frame: Vec<i16> = (0..960)
                            .map(|_| {
                                let s = (phase.sin() * 12000.0) as i16;
                                phase += step;
                                s
                            })
                            .collect();
                        if tx.send(frame).is_err() {
                            break;
                        }
                        std::thread::sleep(std::time::Duration::from_millis(20));
                    }
                })
                .ok();
            spawn_encode(48_000, bitrate_bps, rx, on_packet);
            return Ok(Self {
                _source: AudioSource::Synthetic,
            });
        }

        // Preferred path: desktop/system audio (mono 48 kHz i16 from the backend).
        let (desk_tx, desk_rx) = mpsc::channel::<Vec<i16>>();
        match openreach_capture::start_audio_capture(0, desk_tx) {
            Ok(handle) => {
                tracing::info!("audio source: desktop (system audio)");
                spawn_encode(48_000, bitrate_bps, desk_rx, on_packet);
                return Ok(Self {
                    _source: AudioSource::Desktop(handle),
                });
            }
            Err(e) => tracing::info!(
                "desktop audio capture unavailable ({e}); using default input device"
            ),
        }

        let host = cpal::default_host();
        let device = host
            .default_input_device()
            .ok_or_else(|| anyhow::anyhow!("no default input device"))?;
        let config = device.default_input_config()?;
        let in_rate = config.sample_rate().0;
        let in_channels = config.channels() as usize;
        tracing::info!(
            rate = in_rate,
            channels = in_channels,
            "audio capture: default input device"
        );

        // cpal callback → raw mono i16 at the device rate → encode thread.
        let (raw_tx, raw_rx) = mpsc::channel::<Vec<i16>>();
        let err_fn = |e| tracing::warn!(error=%e, "audio input stream error");

        let stream = match config.sample_format() {
            cpal::SampleFormat::F32 => {
                let tx = raw_tx.clone();
                device.build_input_stream(
                    &config.into(),
                    move |data: &[f32], _| {
                        let _ = tx.send(downmix_f32(data, in_channels));
                    },
                    err_fn,
                    None,
                )?
            }
            cpal::SampleFormat::I16 => {
                let tx = raw_tx.clone();
                device.build_input_stream(
                    &config.into(),
                    move |data: &[i16], _| {
                        let _ = tx.send(downmix_i16(data, in_channels));
                    },
                    err_fn,
                    None,
                )?
            }
            other => anyhow::bail!("unsupported input sample format: {other:?}"),
        };
        stream.play()?;

        spawn_encode(in_rate, bitrate_bps, raw_rx, on_packet);
        Ok(Self {
            _source: AudioSource::Device(stream),
        })
    }
}

/// Resample to 48 kHz, chunk into 960-sample frames, Opus-encode, emit.
fn spawn_encode<F>(in_rate: u32, bitrate_bps: i32, raw_rx: Receiver<Vec<i16>>, on_packet: F)
where
    F: Fn(Vec<u8>) + Send + 'static,
{
    std::thread::Builder::new()
        .name("openreach-audio-encode".into())
        .spawn(move || {
            let mut encoder = match AudioEncoder::new(bitrate_bps) {
                Ok(e) => e,
                Err(e) => {
                    tracing::error!(error=%e, "opus encoder init failed");
                    return;
                }
            };
            let mut resampler = LinearResampler::new(in_rate, AUDIO_SAMPLE_RATE);
            let mut pending: VecDeque<i16> = VecDeque::new();
            while let Ok(chunk) = raw_rx.recv() {
                resampler.push(&chunk, &mut pending);
                while pending.len() >= AUDIO_FRAME_SAMPLES {
                    let frame: Vec<i16> = pending.drain(..AUDIO_FRAME_SAMPLES).collect();
                    match encoder.encode(&frame) {
                        Ok(pkt) => on_packet(pkt),
                        Err(e) => tracing::trace!(error=%e, "opus encode failed"),
                    }
                }
            }
        })
        .ok();
}

/// Viewer-side playback: Opus packets → mono 48 kHz → default output device.
pub struct AudioPlayback {
    decoder: AudioDecoder,
    /// Decoded samples resampled to the output rate, consumed by the cpal callback.
    buffer: Arc<Mutex<VecDeque<i16>>>,
    out_rate: u32,
    resampler: LinearResampler,
    last_seq: Option<u64>,
    /// Real samples the output device callback actually pulled and wrote (i.e.
    /// handed to CoreAudio/ALSA for the speaker) — excludes underrun silence.
    played: Arc<std::sync::atomic::AtomicU64>,
    _stream: cpal::Stream,
}

impl AudioPlayback {
    pub fn start() -> anyhow::Result<Self> {
        let host = cpal::default_host();
        let device = host
            .default_output_device()
            .ok_or_else(|| anyhow::anyhow!("no default output device"))?;
        let config = device.default_output_config()?;
        let out_rate = config.sample_rate().0;
        let out_channels = config.channels() as usize;
        tracing::info!(
            rate = out_rate,
            channels = out_channels,
            "audio playback: default output device"
        );

        let buffer = Arc::new(Mutex::new(VecDeque::<i16>::new()));
        let played = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let err_fn = |e| tracing::warn!(error=%e, "audio output stream error");
        use std::sync::atomic::Ordering;

        let stream = match config.sample_format() {
            cpal::SampleFormat::F32 => {
                let buf = buffer.clone();
                let played = played.clone();
                device.build_output_stream(
                    &config.into(),
                    move |data: &mut [f32], _| {
                        let mut b = buf.lock().unwrap();
                        let mut real = 0u64;
                        for frame in data.chunks_mut(out_channels) {
                            let s = match b.pop_front() {
                                Some(v) => {
                                    real += 1;
                                    v
                                }
                                None => 0, // underrun → silence
                            };
                            let v = s as f32 / 32768.0;
                            for c in frame.iter_mut() {
                                *c = v; // mono fanned across channels
                            }
                        }
                        played.fetch_add(real, Ordering::Relaxed);
                    },
                    err_fn,
                    None,
                )?
            }
            cpal::SampleFormat::I16 => {
                let buf = buffer.clone();
                let played = played.clone();
                device.build_output_stream(
                    &config.into(),
                    move |data: &mut [i16], _| {
                        let mut b = buf.lock().unwrap();
                        let mut real = 0u64;
                        for frame in data.chunks_mut(out_channels) {
                            let s = match b.pop_front() {
                                Some(v) => {
                                    real += 1;
                                    v
                                }
                                None => 0,
                            };
                            for c in frame.iter_mut() {
                                *c = s;
                            }
                        }
                        played.fetch_add(real, Ordering::Relaxed);
                    },
                    err_fn,
                    None,
                )?
            }
            other => anyhow::bail!("unsupported output sample format: {other:?}"),
        };
        stream.play()?;

        Ok(Self {
            decoder: AudioDecoder::new()?,
            buffer,
            out_rate,
            resampler: LinearResampler::new(AUDIO_SAMPLE_RATE, out_rate),
            last_seq: None,
            played,
            _stream: stream,
        })
    }

    /// Real samples the audio output device has pulled and written so far — the
    /// last software-observable point before the physical speaker.
    pub fn samples_played(&self) -> u64 {
        self.played.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Decode one received Opus packet and enqueue it for playback. `seq` gaps
    /// trigger a single PLC frame so playback stays aligned.
    pub fn push_packet(&mut self, opus: &[u8], seq: u64) {
        // Conceal exactly one dropped frame on a gap (data channel is reliable,
        // so this mainly guards reordering / restart transients).
        if let Some(prev) = self.last_seq {
            if seq == prev + 2 {
                if let Ok(plc) = self.decoder.decode(None, false) {
                    self.enqueue(&plc);
                }
            }
        }
        self.last_seq = Some(seq);
        match self.decoder.decode(Some(opus), false) {
            Ok(pcm) => self.enqueue(&pcm),
            Err(e) => tracing::trace!(error=%e, "opus decode failed"),
        }
    }

    fn enqueue(&mut self, pcm48: &[i16]) {
        let mut out = VecDeque::new();
        self.resampler.push(pcm48, &mut out);
        let mut b = self.buffer.lock().unwrap();
        // Cap latency: drop the oldest if the buffer grows beyond ~400 ms.
        let cap = (self.out_rate as usize / 1000) * 400;
        b.extend(out);
        while b.len() > cap {
            b.pop_front();
        }
    }
}

/// Cheap linear resampler for a mono i16 stream. Not audiophile-grade, but fine
/// for voice/desktop audio and dependency-free.
struct LinearResampler {
    in_rate: u32,
    out_rate: u32,
    /// Fractional read position into the input, carried across chunks.
    pos: f64,
    /// Last sample of the previous chunk, for interpolation across boundaries.
    prev: i16,
    primed: bool,
}

impl LinearResampler {
    fn new(in_rate: u32, out_rate: u32) -> Self {
        Self {
            in_rate,
            out_rate,
            pos: 0.0,
            prev: 0,
            primed: false,
        }
    }

    /// Resample `input` and append the result to `out`.
    fn push(&mut self, input: &[i16], out: &mut VecDeque<i16>) {
        if input.is_empty() {
            return;
        }
        if self.in_rate == self.out_rate {
            out.extend(input.iter().copied());
            return;
        }
        let ratio = self.in_rate as f64 / self.out_rate as f64;
        if !self.primed {
            self.prev = input[0];
            self.primed = true;
        }
        // `pos` indexes into a virtual stream [prev, input...].
        while self.pos < input.len() as f64 {
            let i = self.pos.floor() as isize;
            let frac = self.pos - self.pos.floor();
            let a = if i < 0 { self.prev } else { input[i as usize] };
            let b = if (i + 1) < input.len() as isize {
                input[(i + 1) as usize]
            } else {
                input[input.len() - 1]
            };
            let s = a as f64 + (b as f64 - a as f64) * frac;
            out.push_back(s.round().clamp(-32768.0, 32767.0) as i16);
            self.pos += ratio;
        }
        self.pos -= input.len() as f64;
        self.prev = input[input.len() - 1];
    }
}

/// Interleaved f32 → mono i16.
fn downmix_f32(data: &[f32], channels: usize) -> Vec<i16> {
    if channels <= 1 {
        return data.iter().map(|&s| (s * 32767.0) as i16).collect();
    }
    data.chunks(channels)
        .map(|f| {
            let avg = f.iter().copied().sum::<f32>() / channels as f32;
            (avg * 32767.0) as i16
        })
        .collect()
}

/// Interleaved i16 → mono i16.
fn downmix_i16(data: &[i16], channels: usize) -> Vec<i16> {
    if channels <= 1 {
        return data.to_vec();
    }
    data.chunks(channels)
        .map(|f| (f.iter().map(|&s| s as i32).sum::<i32>() / channels as i32) as i16)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use openreach_protocol as proto;

    /// End-to-end audio pipeline in software: PCM → Opus encode → `AudioFrame`
    /// wire envelope → decode envelope → Opus decode → PCM. This exercises every
    /// stage under our control (everything except the OS capture syscall and the
    /// physical speaker) and asserts a real signal survives the round trip.
    #[test]
    fn audio_pipeline_pcm_through_wire_to_pcm() {
        let mut enc = AudioEncoder::new(24_000).unwrap();
        let mut dec = AudioDecoder::new().unwrap();

        // A continuous 440 Hz tone, sent as a stream of 20 ms frames so we can
        // measure steady-state fidelity past Opus's initial encoder delay.
        let freq = 440.0_f32;
        let mut phase = 0.0_f32;
        let step = 2.0 * std::f32::consts::PI * freq / AUDIO_SAMPLE_RATE as f32;

        let mut in_energy = 0.0_f64;
        let mut out_energy = 0.0_f64;
        for frame_idx in 0..10 {
            let pcm: Vec<i16> = (0..AUDIO_FRAME_SAMPLES)
                .map(|_| {
                    let s = (phase.sin() * 12000.0) as i16;
                    phase += step;
                    s
                })
                .collect();

            // Encode → wrap in the protocol AudioFrame → serialize (the wire).
            let packet = enc.encode(&pcm).unwrap();
            let env = proto::audio_frame(packet.clone(), frame_idx);
            let wire = proto::encode(&env);

            // Decode the envelope → the Opus packet must survive byte-for-byte.
            let back = proto::decode(&wire).unwrap();
            let audio = match back.payload.unwrap() {
                proto::pb::envelope::Payload::Audio(a) => a,
                other => panic!("expected AudioFrame, got {other:?}"),
            };
            assert_eq!(audio.opus, packet, "opus packet corrupted on the wire");
            assert_eq!(audio.seq, frame_idx);

            // Opus decode → PCM of the right length.
            let out = dec.decode(Some(&audio.opus), false).unwrap();
            assert_eq!(out.len(), AUDIO_FRAME_SAMPLES);

            // Accumulate energy past the first two frames (encoder priming/delay).
            if frame_idx >= 2 {
                in_energy += pcm.iter().map(|&s| (s as f64).powi(2)).sum::<f64>();
                out_energy += out.iter().map(|&s| (s as f64).powi(2)).sum::<f64>();
            }
        }

        // In steady state a lossy-but-faithful codec preserves most of the tone's
        // energy — the recovered stream is real audio, not silence or garbage.
        let ratio = out_energy / in_energy;
        assert!(
            (0.5..=1.5).contains(&ratio),
            "recovered audio energy ratio out of range: {ratio:.3}"
        );
    }

    #[test]
    fn resampler_passthrough_when_equal() {
        let mut r = LinearResampler::new(48_000, 48_000);
        let mut out = VecDeque::new();
        r.push(&[1, 2, 3, 4], &mut out);
        assert_eq!(out.into_iter().collect::<Vec<_>>(), vec![1, 2, 3, 4]);
    }

    #[test]
    fn resampler_downsamples_length() {
        // 48k -> 24k should roughly halve the sample count over a long input.
        let mut r = LinearResampler::new(48_000, 24_000);
        let input: Vec<i16> = (0..4800).map(|i| (i % 100) as i16).collect();
        let mut out = VecDeque::new();
        r.push(&input, &mut out);
        let n = out.len();
        assert!((2300..=2500).contains(&n), "unexpected resample length {n}");
    }

    #[test]
    fn downmix_stereo_to_mono() {
        let stereo = [1.0f32, -1.0, 0.5, 0.5];
        let mono = downmix_f32(&stereo, 2);
        assert_eq!(mono.len(), 2);
        assert_eq!(mono[0], 0); // (1 + -1)/2 = 0
    }
}
