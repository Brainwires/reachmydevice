# OpenReach — Phase 1 (Spike) Report

**Goal of Phase 1:** de-risk the riskiest path — capture → encode → WebRTC → decode → display,
plus remote input — end to end, and decide whether the chosen transport is viable before building
anything else. **Target platform for the spike: macOS** (deviation from the spec's Linux/X11 spike;
see ADR-0002).

## Verdict: GO ✅

The highest-risk dependency — a **sans-IO Rust WebRTC** stack carrying media + data + congestion
control — compiles and runs, and a real end-to-end media path (H.264 encode → RTP/DTLS-SRTP →
depacketize → decode) is proven by an automated test. `webrtc-rs`/`rtc` is viable; **libwebrtc FFI is
not needed** and has been dropped.

## What was built

A Rust workspace (`crates/` + `apps/`) with the full spike vertical slice:

| Component | State |
|-----------|-------|
| `protocol` | Versioned prost wire schema + version handshake (`check_compatibility`). Unit-tested. |
| `capture` | macOS ScreenCaptureKit backend via **objc2** (pure Rust, no Swift). BGRA frames. |
| `codec` | **Software H.264** (openh264) encode/decode behind `Encoder`/`Decoder` traits; BGRA↔I420 via yuvutils. Roundtrip-tested. |
| `transport` | **Sans-IO `rtc` fork** driver: UDP+timer loop, H.264 RTP send, SampleBuilder receive, reliable data channel, DTLS-SRTP E2EE, sender-side GCC/TWCC. Loopback integration test. |
| `input` | macOS CGEvent injection (mouse full; keyboard via HID→keycode subset). |
| `session` | Host session (capture→encode→transport; control→inject; handshake; session indicator) and viewer session (transport→decode; input→transport). |
| `apps/host` | Headless host agent (env-configured). |
| `apps/viewer` | winit + wgpu GPU-rendered viewer + input capture. |
| `apps/signal-dev` | TCP signaling relay (rendezvous stand-in). |
| `docs/` | Architecture, ADRs, macOS permissions, threat-model + deployment placeholders, this report. |

## Deviations from the spec (each with rationale)

1. **macOS-first spike, not Linux/X11** (ADR-0002) — the operator's hardware is Macs. Linux/Windows → Phase 3.
2. **Transport is the sans-IO `rtc` fork, not stock webrtc-rs / libwebrtc FFI** (ADR-0003) — the
   `Brainwires/webrtc-rs-rtc` fork already carries GCC congestion control, jitter buffer, DTLS-restart,
   TCP-TURN, and correctness fixes (107 commits ahead of upstream; none of the upstream PRs merged, but all
   integrated in the fork's master). This retired the spec's #1 risk by reuse.
3. **Software H.264 (openh264) first, VideoToolbox next** (ADR-0007) — software-first removes heavy
   VideoToolbox FFI from the path to a *working, measurable* demo; the spec permits a software fallback.
   The hardware backend is the next increment behind the same trait.
4. **`screencapturekit` crate abandoned for objc2** (ADR-0005) — the convenience crate's mandatory
   `apple-metal` dep runs a Swift bridge build broken against the current SDK; a Swift/Metal build chain is
   also a CI liability.
5. **Existing browser `webrtc` demo is reference-only** (ADR-0006) — a browser can't inject OS input, run
   unattended, or drive hardware encoders, so no code carried forward.

## Measured performance

Automated, reproducible on this machine:

- **Transport loopback** (`cargo test -p openreach-transport`): two peers ICE-connect + establish
  DTLS-SRTP and exchange video + bidirectional data over `127.0.0.1` in **~0.46 s** per run; stable across
  5 consecutive runs.
- **End-to-end media pipeline** (`cargo test -p openreach-session --test pipeline`): real openh264
  encode → RTP/DTLS-SRTP → depacketize → real openh264 decode. Two peers connect over loopback and the
  viewer decodes a **320×240** frame with matching dimensions in **~0.30 s** total. This exercises the
  entire media path minus screen capture and on-glass rendering.
- **Codec roundtrip** (`cargo test -p openreach-codec`): encode→decode of a 128×96 frame passes.

**Glass-to-glass latency and 1080p30 bitrate must be measured on-device by the operator** (two Macs on a
LAN) — they require real screen capture (Screen Recording permission) and a physical display, which the
automated environment lacks. Method (see "How to run the spike" below):
- *Pipeline latency (single clock):* run host+viewer on one Mac; the host stamps `capture_ts_micros` on
  each frame (shared monotonic epoch); compare at encode/send. Reports capture→encode→send latency.
- *Glass-to-glass (cross-machine):* display a millisecond counter on the host, point the viewer at it, and
  film both screens with a slow-motion camera; the difference is glass-to-glass. Target <80 ms LAN.
- *Bitrate:* read the encoder's configured/target bitrate and measure bytes/s on the send track at 1080p30;
  target <8 Mbps.

## Known issues / limitations (honest notes)

- **GCC bitrate not yet observed publishing.** The sender-side GCC + TWCC chain is wired per the fork's
  contract (both SDPs advertise `transport-cc`), and the encoder consumes `target_bitrate_bps()`, but in the
  short, zero-loss loopback window GCC never crossed its publish threshold — the encoder ran at its initial
  bitrate. Needs a longer / real-WAN session to confirm the estimate flows. Structurally correct; unproven
  end-to-end.
- **Keyboard is a common-key subset** (HID→macOS keycode table); unmapped keys are dropped (logged). Full
  layout coverage and cross-OS keymaps are Phase 3.
- **No reconnect / ICE-restart yet.** `Disconnected`/`Failed`/`Closed` collapse to one event; auto-restart
  is a Phase-4 item (the fork supports DTLS-restart — plumbing exists).
- **Software encoder, no hardware yet.** Higher CPU than the VideoToolbox target; adequate for de-risking.
- **Loopback/LAN host candidates only.** No STUN/TURN exercised yet (Phase 2).
- **macOS only.** Linux/Windows are Phase 3.

## How to run the spike (two Macs on a LAN)

1. Build on both: `cargo build --release`.
2. On machine A (or either): `OPENREACH_SIGNAL_ADDR=0.0.0.0:9000 cargo run --release -p openreach-signal-dev`.
3. On the **host** Mac: `OPENREACH_SIGNAL_ADDR=<relay-ip>:9000 cargo run --release -p openreach-host`
   (grant **Screen Recording** + **Accessibility** when prompted; restart after granting — see
   `docs/macos-permissions.md`).
4. On the **viewer** Mac: `OPENREACH_SIGNAL_ADDR=<relay-ip>:9000 cargo run --release -p openreach-viewer`.
5. The viewer window shows the host desktop; mouse/keyboard control the host. The host logs
   `★ REMOTE SESSION ACTIVE ★`. Measure latency/bitrate per the method above.

## Next (Phase 2)

Rendezvous server (axum + SQLite + coturn, single docker-compose): device registry, token auth (Argon2),
WebSocket signaling with rooms, STUN/TURN, TLS via ACME, rate limiting — proving a connection between two
NATed networks with the relay seeing only ciphertext.
