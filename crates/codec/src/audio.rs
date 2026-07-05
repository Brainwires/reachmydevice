//! Opus audio encode/decode (host → viewer).
//!
//! Fixed to the real-time-friendly configuration used across ReachMyDevice:
//! 48 kHz, mono, 20 ms frames (960 samples/frame). Each encoded frame is a
//! self-contained Opus packet carried in an `AudioFrame` protocol message.
//!
//! libopus itself is loss-tolerant; the current transport sends audio on the
//! (reliable) data channel, so packets are not actually dropped — a dedicated
//! RTP audio track is the future optimization. The decoder's PLC path is still
//! wired (`decode(None, …)`) for when that lands.

use anyhow::Context;
use audiopus::coder::{Decoder, Encoder};
use audiopus::{Application, Channels, SampleRate};

/// Audio sample rate (Hz).
pub const AUDIO_SAMPLE_RATE: u32 = 48_000;
/// Channel count (mono keeps bandwidth and complexity down for v1).
pub const AUDIO_CHANNELS: u16 = 1;
/// Samples per channel in one 20 ms frame at 48 kHz.
pub const AUDIO_FRAME_SAMPLES: usize = 960;
/// Upper bound on an encoded Opus packet.
const MAX_PACKET: usize = 4000;

/// Opus encoder for one mono 48 kHz stream.
pub struct AudioEncoder {
    inner: Encoder,
    buf: Vec<u8>,
}

impl AudioEncoder {
    /// Create an encoder tuned for general audio at `bitrate_bps`.
    pub fn new(bitrate_bps: i32) -> anyhow::Result<Self> {
        let mut inner = Encoder::new(SampleRate::Hz48000, Channels::Mono, Application::Audio)
            .context("create opus encoder")?;
        inner
            .set_bitrate(audiopus::Bitrate::BitsPerSecond(bitrate_bps))
            .context("set opus bitrate")?;
        Ok(Self {
            inner,
            buf: vec![0u8; MAX_PACKET],
        })
    }

    /// Encode exactly [`AUDIO_FRAME_SAMPLES`] mono samples into an Opus packet.
    pub fn encode(&mut self, pcm: &[i16]) -> anyhow::Result<Vec<u8>> {
        anyhow::ensure!(
            pcm.len() == AUDIO_FRAME_SAMPLES,
            "opus frame must be {AUDIO_FRAME_SAMPLES} samples, got {}",
            pcm.len()
        );
        let n = self
            .inner
            .encode(pcm, &mut self.buf)
            .context("opus encode")?;
        Ok(self.buf[..n].to_vec())
    }
}

/// Opus decoder producing mono 48 kHz PCM.
pub struct AudioDecoder {
    inner: Decoder,
}

impl AudioDecoder {
    pub fn new() -> anyhow::Result<Self> {
        let inner =
            Decoder::new(SampleRate::Hz48000, Channels::Mono).context("create opus decoder")?;
        Ok(Self { inner })
    }

    /// Decode one Opus packet into mono PCM samples. Pass `None` to invoke
    /// packet-loss concealment for a missing frame.
    pub fn decode(&mut self, packet: Option<&[u8]>, fec: bool) -> anyhow::Result<Vec<i16>> {
        use audiopus::packet::Packet;
        use audiopus::MutSignals;
        let mut out = vec![0i16; AUDIO_FRAME_SAMPLES];
        let input = match packet {
            Some(bytes) => Some(Packet::try_from(bytes).context("wrap opus packet")?),
            None => None,
        };
        let signals = self
            .inner
            .decode(input, MutSignals::try_from(&mut out[..]).unwrap(), fec)
            .context("opus decode")?;
        out.truncate(signals);
        Ok(out)
    }
}

impl Default for AudioDecoder {
    fn default() -> Self {
        Self::new().expect("opus decoder init")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opus_roundtrip_frame() {
        let mut enc = AudioEncoder::new(24_000).unwrap();
        let mut dec = AudioDecoder::new().unwrap();

        // A 440 Hz sine wave over one 20 ms frame.
        let pcm: Vec<i16> = (0..AUDIO_FRAME_SAMPLES)
            .map(|i| {
                let t = i as f32 / AUDIO_SAMPLE_RATE as f32;
                ((2.0 * std::f32::consts::PI * 440.0 * t).sin() * 12000.0) as i16
            })
            .collect();

        let packet = enc.encode(&pcm).unwrap();
        assert!(!packet.is_empty(), "encoder produced no bytes");
        assert!(packet.len() < 1000, "unexpectedly large packet");

        let decoded = dec.decode(Some(&packet), false).unwrap();
        assert_eq!(decoded.len(), AUDIO_FRAME_SAMPLES, "wrong decoded length");

        // Opus is lossy, but a tone should retain substantial energy.
        let energy: f64 = decoded.iter().map(|&s| (s as f64).powi(2)).sum();
        assert!(energy > 1_000_000.0, "decoded frame lost too much energy");
    }

    #[test]
    fn rejects_wrong_frame_size() {
        let mut enc = AudioEncoder::new(24_000).unwrap();
        assert!(enc.encode(&[0i16; 512]).is_err());
    }
}
