# ReachMyDevice — Validation Log

Evidence that the system works end-to-end, on real hardware and across the real
internet. Automated tests run in CI; the on-fleet runs below were executed
manually against the deployed rendezvous.

## Automated (CI — macOS + Linux)
| Test | What it proves |
|------|----------------|
| `rmd-protocol` unit tests | versioned wire format, handshake accept/reject, v1 messages |
| `rmd-codec` roundtrip | real openh264 encode → decode |
| `rmd-transport` `loopback_connect_video_and_data` | ICE + DTLS-SRTP connect, H.264 RTP, bidirectional data channel |
| `rmd-transport` `relay_only_sees_ciphertext` | an interposed relay carries traffic but a plaintext canary never appears in it (E2EE) |
| `rmd-transport` srflx (ignored, network) | STUN binding discovers a real public reflexive address |
| `rmd-session` `pipeline` | real encode → transport → real decode, headless |
| `rmd-session` `rendezvous_e2e` | two peers connect through the **real rendezvous server** (in-process) over WebSockets |
| Linux CI (Xvfb) | X11 `capture_smoke` + XTest `input_smoke` on a headless X server |

## On-fleet (real hardware)

### macOS full pipeline (this Mac)
ScreenCaptureKit capture → openh264 → transport → decode. See the Phase 1 report.

### Linux full pipeline (`biscuits`, Ubuntu 24.04, x86_64)
Real X11 capture (Xvfb) → host → transport → headless viewer decode, loopback:
**589 frames @ 1280×720 (~29 fps), first frame 2.34 s.** X11 capture: 60 frames
@ ~30 fps; XTest input: injected pointer landed exactly at screen centre.

### Cross-NAT session (the headline result)
`biscuits` (cloud, public IP behind a stateful firewall) as **host** ↔ this Mac
(home NAT) as **viewer**, signaling via the **deployed rendezvous**
`wss://openreach.brainwires.dev/ws` (behind a Cloudflare tunnel), media traversing
NAT via **STUN server-reflexive candidates + hole-punching**, DTLS-SRTP encrypted:

```
Mac viewer:   connected=true  frames=1290  1280×720  first_frame=1.89s   (~30 fps / 45 s)
biscuits host: ★ REMOTE SESSION ACTIVE ★
```

This exercises the entire thesis: **screen capture → hardware/software H.264 →
NAT-traversed, end-to-end-encrypted WebRTC → decode**, with a self-hosted
rendezvous and no third-party cloud in the media path.

### Cross-NAT session **with audio** (2026-07-04)
Same fleet — `biscuits` host ↔ this Mac viewer via the deployed rendezvous — with
**audio enabled on both ends** (`RMD_AUDIO=1`). The host had no capture
device (headless cloud box), so it transmitted a synthetic 440 Hz tone
(`RMD_AUDIO_SYNTH=1`) through the real Opus encoder; the viewer decoded it
off the real data channel:

```
biscuits host: X11 capture started · "audio source: synthetic 440 Hz tone" · ★ REMOTE SESSION ACTIVE ★
Mac viewer:    connected=true  frames=786  audio_frames=1300  1280×720
```

**1300 Opus audio frames were encoded on one machine, carried over the real
internet through NAT-traversed DTLS-SRTP, and decoded on another** — audio
delivery proven end-to-end on real hardware, alongside video.

### Real system-audio capture → transport → decode (2026-07-04, macOS)
With Screen Recording granted, real **ScreenCaptureKit system-audio capture** was
confirmed and then run through the whole stack:

```
audio_probe (capture only):  chunks=179 samples=171840 rms=553.4 peak=9716
audio_e2e (full chain):      connected=true audio_frames_delivered=100 decoded_rms=524.8
audio_e2e PLAY=1 (+speaker):  audio_frames_delivered=589 decoded_rms=942.5 speaker_samples_written=562240
```

`audio_e2e` captures the **actual audio playing on the host** via ScreenCaptureKit,
Opus-encodes it, sends it over the real WebRTC/DTLS-SRTP transport, decodes it on
the peer (real, **non-silent** energy), and — with `PLAY=1` — plays it back through
the cpal output device. `speaker_samples_written=562240` is the count of real
samples the **audio output device callback (CoreAudio) actually pulled and wrote**
(~11.7 s at 48 kHz); CoreAudio only pulls when the device is actively outputting,
so this confirms the audio reached the OS speaker-output path. The chain is thus
verified in software end-to-end: **real OS capture → encode → encrypted transport
→ decode → samples written to the output device**. The only element beyond
software observation is the physical speaker cone / human ear. Reproduce:
`cargo run -p rmd-capture --example audio_probe` and
`PLAY=1 cargo run -p rmd-session --example audio_e2e` (with audio playing).

**Human confirmation (2026-07-04):** with `PLAY=1`, the operator heard the host's
own ambient audio (cooling fans) round-tripped through capture → Opus → encrypted
transport → decode → speaker. The final physical transduction — the only element
beyond software observation — is confirmed audible. The audio subsystem is now
verified **fully end-to-end, real source through real speaker, on real hardware.**

### Rendezvous deployment
`rmd-rendezvous` runs in Docker on `biscuits` behind the existing Cloudflare
tunnel; the web console + REST API + WebSocket signaling are all reachable at
`https://openreach.brainwires.dev` and verified: `/health` 200, account
register → device token, `GET /api/devices`, and a real WebSocket relay
(`A → server → B`) through the tunnel.

## Not yet measured / open
- **Glass-to-glass latency** (needs a physical display + camera, or the in-UI
  Ping/Pong RTT the viewer HUD will add). Connection setup was ~1.9 s; steady-state
  frame rate ~30 fps at 1280×720.
- **TURN relay fallback** on the fleet (P2P/STUN succeeded, so TURN wasn't exercised;
  coturn is present on `biscuits`).
- 1080p30 bitrate/CPU under the VideoToolbox hardware encoder (software path used so far).
