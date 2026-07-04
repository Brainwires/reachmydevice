//! Optional audio: host capture → Opus → viewer playback (default off).
//!
//! **Status / honesty note.** This wires a real, end-to-end audio path — cpal
//! capture, Opus (via `codec::audio`), transport over the data channel, cpal
//! playback — and is unit-tested at the codec layer. Two caveats remain,
//! documented rather than hidden:
//!
//! 1. **Source.** Capture uses the host's *default input device* (typically the
//!    microphone). True desktop-audio loopback — what a remote-desktop user
//!    usually wants — needs a platform monitor source (ScreenCaptureKit audio on
//!    macOS, a PipeWire/PulseAudio monitor on Linux) and is a follow-up.
//! 2. **Transport.** Frames ride the reliable/ordered data channel, so there is
//!    no loss but latency can accrue under congestion. A dedicated Opus RTP
//!    track is the production optimization; the decoder's PLC path is already in
//!    place for it.
//!
//! Because of this it is **opt-in** (`enable_audio`) and off by default, so the
//! proven video path is never affected.

use codec::{AudioDecoder, AudioEncoder, AUDIO_FRAME_SAMPLES, AUDIO_SAMPLE_RATE};
use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use openreach_codec as codec;
use std::collections::VecDeque;
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};

/// Host-side capture: default input device → mono 48 kHz → Opus packets.
///
/// Holds the live cpal stream (kept alive by this struct) and an encode thread.
pub struct AudioCapture {
    _stream: cpal::Stream,
}

impl AudioCapture {
    /// Start capturing. `on_packet` is called with each Opus packet (~50/sec).
    pub fn start<F>(bitrate_bps: i32, on_packet: F) -> anyhow::Result<Self>
    where
        F: Fn(Vec<u8>) + Send + 'static,
    {
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
        Ok(Self { _stream: stream })
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
        let err_fn = |e| tracing::warn!(error=%e, "audio output stream error");

        let stream = match config.sample_format() {
            cpal::SampleFormat::F32 => {
                let buf = buffer.clone();
                device.build_output_stream(
                    &config.into(),
                    move |data: &mut [f32], _| {
                        let mut b = buf.lock().unwrap();
                        for frame in data.chunks_mut(out_channels) {
                            let s = b.pop_front().unwrap_or(0);
                            let v = s as f32 / 32768.0;
                            for c in frame.iter_mut() {
                                *c = v; // mono fanned across channels
                            }
                        }
                    },
                    err_fn,
                    None,
                )?
            }
            cpal::SampleFormat::I16 => {
                let buf = buffer.clone();
                device.build_output_stream(
                    &config.into(),
                    move |data: &mut [i16], _| {
                        let mut b = buf.lock().unwrap();
                        for frame in data.chunks_mut(out_channels) {
                            let s = b.pop_front().unwrap_or(0);
                            for c in frame.iter_mut() {
                                *c = s;
                            }
                        }
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
            _stream: stream,
        })
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
