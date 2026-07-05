# ReachMyDevice — Architecture Overview

ReachMyDevice is a self-hostable, end-to-end-encrypted remote KVM (keyboard/video/mouse) system:
a **host agent** on the controlled machine, a **viewer** on the controlling machine, and a
self-hostable **rendezvous** server for signaling + NAT traversal. P2P when possible, TURN-relayed
when not, with the relay only ever seeing ciphertext.

This document tracks the intended end-state architecture and marks what exists today (Phase 1 spike).

## Component map

```
                          ┌─────────────────────────┐
                          │   Rendezvous (Phase 2)  │   self-hosted, 1 vCPU / 1 GB VPS
                          │  axum + SQLite + coturn │
                          │  registry · signaling   │
                          │  STUN · TURN (relay)    │
                          └───────────┬─────────────┘
             signaling (WSS)          │          signaling (WSS)
        ┌───────────────────────------┘          └───────────────────────┐
        │                                                                 │
┌───────▼─────────┐        E2EE media + data (DTLS-SRTP)        ┌─────────▼───────┐
│   Host agent    │◄═══════════════ WebRTC (P2P / TURN) ═══════►│     Viewer      │
│  (controlled)   │                                             │  (controlling)  │
│                 │                                             │                 │
│ capture ─┐      │                                             │  ┌─► decode ─►  │
│          ▼      │   H.264 video track  (host → viewer)        │  │   wgpu       │
│  codec (encode) ├────────────────────────────────────────────┼──┘   render     │
│          │      │                                             │                 │
│  input   ◄──────┤   input events (data channel, bidir ctrl)   ├──◄ input capture│
│ (inject) │      │◄────────────────────────────────────────────┤   (winit)      │
│          │      │   clipboard · files · audio (Phase 4)       │                 │
└──────────┴──────┘                                             └─────────────────┘
```

## Crate map (Rust workspace)

| Crate / app            | Responsibility                                                              | Status |
|------------------------|-----------------------------------------------------------------------------|--------|
| `crates/protocol`      | Versioned wire schema (prost): handshake, input, clipboard/file/multimon/control. | ✅ |
| `crates/transport`     | WebRTC over the sans-IO `rtc` fork: driver loop, video track, data channel, GCC, **host+srflx ICE gathering**, signaling trait. | ✅ |
| `crates/capture`       | `Capturer` trait + backends: **macOS ScreenCaptureKit**, **Linux X11**. (Windows/Wayland TODO) | ✅ |
| `crates/codec`         | `Encoder`/`Decoder` traits + **software H.264 (openh264)**. (VideoToolbox/HW TODO) | ✅ |
| `crates/input`         | `Injector` trait + backends: **macOS CGEvent**, **Linux XTest**. (Windows/Wayland TODO) | ✅ |
| `crates/session`       | Host + viewer wiring; signaling (LAN + rendezvous WS); device identity + TOFU; account client. | ✅ |
| `apps/host`            | Headless host agent (rendezvous or LAN signaling, STUN/TURN, session indicator). | ✅ |
| `apps/viewer`          | winit + wgpu viewer; egui UI (login/device-list/connect/HUD) landing.        | 🔄 |
| `apps/rendezvous`      | axum + SQLite: accounts/tokens (Argon2), WS relay, rate limiting, **web console**. Deployed. | ✅ |
| `apps/signal-dev`      | LAN signaling helper (rendezvous stand-in for local dev).                    | ✅ |
| coturn (in compose)    | STUN + TURN for NAT traversal.                                              | ✅ |

## Data flow (host → viewer video)

1. **capture**: ScreenCaptureKit `SCStream` → `CVPixelBuffer` frames → normalized `Frame`.
2. **codec (encode)**: VideoToolbox `VTCompressionSession` H.264 real-time → Annex B NAL units.
   Bitrate driven at runtime by the transport's GCC estimate (adaptive bitrate).
3. **transport (send)**: written as WebRTC samples on an H.264 video track; DTLS-SRTP encrypts;
   ICE picks P2P or TURN.
4. **transport (recv)**: viewer reads the remote track → depacketized H.264 NAL units.
5. **codec (decode)**: VideoToolbox `VTDecompressionSession` → BGRA.
6. **render**: uploaded as a `wgpu` texture, drawn in the winit window.

## Input flow (viewer → host)

winit input events → `protocol::InputEvent` (prost) → reliable ordered **data channel** →
host → CGEvent injection. View-only mode simply drops the input channel.

## Transport substrate

Built on **`Brainwires/webrtc-rs-rtc`** (the sans-IO `rtc` fork), pinned as a git dependency.
Chosen for GCC congestion control (adaptive bitrate), jitter buffering, DTLS-restart (reconnect),
and testability. The `transport` crate owns the UDP-socket + timer **driver loop** that pumps the
sans-IO state machine. See `docs/decisions.md` for the full rationale and the fork history.

## Security model (target)

- **E2EE via DTLS-SRTP** — relay/TURN sees only ciphertext.
- **Device identity = keypair**, generated on first run; pairing via short auth string / PIN (TOFU).
- **Rendezvous accounts**: Argon2 password hashing; devices authenticate with tokens.
- **Unattended access** gated by per-host password or pre-authorized viewer keys.
- **Visible session indicator** on the host whenever a remote session is active.

Full threat model: `docs/threat-model.md` (Phase 5).

## Extension points (v1 non-goals, plumbing noted)

Mobile/web clients, session recording, multi-user, viewer→host audio, printing, Wake-on-LAN.
None are built; interfaces are kept narrow so they can be added without reshaping the core.
