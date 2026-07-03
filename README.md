# OpenReach

**Self-hostable, end-to-end-encrypted remote desktop / KVM-over-IP.** A clean, ownable replacement for
RealVNC's departed cloud tier: install a host agent on the machine you want to reach, a viewer anywhere
else, point both at your own rendezvous server on a cheap VPS, and get a low-latency encrypted session —
**P2P when possible, relayed when not, with no third-party cloud and no subscription.**

> **Status: Phase 1 (de-risking spike), macOS-first.** Not yet usable. See
> [`docs/architecture.md`](docs/architecture.md) and [`docs/decisions.md`](docs/decisions.md).

## Components

- **Host agent** (`apps/host`) — captures screen + audio, injects input, runs unattended.
- **Viewer** (`apps/viewer`) — displays the remote desktop (GPU-accelerated), sends input.
- **Rendezvous** (Phase 2) — self-hostable signaling + device registry + STUN/TURN (axum + SQLite + coturn).

## How it fits together

Native Rust workspace. Screen is captured, hardware-encoded to H.264, and sent over **WebRTC**
(the sans-IO [`rtc`](https://github.com/Brainwires/webrtc-rs-rtc) fork) with **DTLS-SRTP** encryption and
**GCC** adaptive bitrate; input travels a reliable data channel. The rendezvous/TURN server only ever sees
ciphertext. Direct LAN connections work even when the rendezvous server is unreachable.

## Build

```sh
cargo build            # whole workspace
cargo test             # unit + integration tests
cargo clippy --all-targets
```

Requires a recent stable Rust toolchain and `protoc` (for the `protocol` crate). macOS spike additionally
requires granting **Screen Recording** and **Accessibility** permissions — see
[`docs/macos-permissions.md`](docs/macos-permissions.md).

Developer guide: [`docs/HACKING.md`](docs/HACKING.md).

## License

Dual-licensed under MIT or Apache-2.0.
