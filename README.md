# OpenReach

**Self-hostable, end-to-end-encrypted remote desktop / KVM-over-IP.** A clean, ownable replacement for
RealVNC's departed cloud tier: install a host agent on the machine you want to reach, a viewer anywhere
else, point both at your own rendezvous server on a cheap VPS, and get a low-latency encrypted session —
**P2P when possible, relayed when not, with no third-party cloud and no subscription.**

> **Status:** macOS + Linux hosts/viewers working end-to-end; rendezvous deployable via Docker.
> **A real cross-NAT session is proven** (host on a cloud box ↔ viewer behind home NAT, signaling through
> a self-hosted rendezvous, media STUN-traversed and DTLS-SRTP encrypted — see
> [`docs/validation.md`](docs/validation.md)). Windows/Wayland, some v1 features, and the desktop UI are
> in progress.

## Components

- **Host agent** (`apps/host`) — captures the screen, hardware/software H.264-encodes it, streams it over
  WebRTC, and injects the viewer's keyboard/mouse. Headless; runs unattended.
- **Viewer** (`apps/viewer`) — GPU-accelerated (winit + wgpu) display of the remote desktop; sends input.
- **Rendezvous** (`apps/rendezvous`) — self-hostable signaling + device registry + **web console**
  (axum + SQLite), paired with **coturn** for STUN/TURN. Ships as Docker + a Cloudflare-tunnel or
  Caddy/ACME deployment.

## How it fits together

Native Rust workspace. Screen → **H.264** → **WebRTC** (the sans-IO
[`rtc`](https://github.com/Brainwires/webrtc-rs-rtc) fork) with **DTLS-SRTP** encryption, **ICE** NAT
traversal (host + STUN server-reflexive candidates), and **GCC** adaptive bitrate; input + control travel a
reliable data channel. The rendezvous/TURN servers only ever see **ciphertext** (proven by an automated
test). Direct LAN connections work even when the rendezvous is unreachable.

Platform backends: macOS (ScreenCaptureKit + CGEvent), Linux/X11 (XGetImage + XTest). Software H.264
(openh264) today; VideoToolbox/NVENC/etc. behind the same trait next.

## Quick start (self-hosted)

1. **Deploy the rendezvous** on a VPS (`deploy/docker-compose.yml`, or the single container behind an
   existing Cloudflare tunnel). See [`docs/vps-deployment.md`](docs/vps-deployment.md). It serves a web
   console at `https://<your-domain>/`.
2. **Create an account** in the console (or `POST /api/register`), then register your host + viewer devices
   to get bearer tokens.
3. **Run the host** on the machine to control:
   ```sh
   OPENREACH_RENDEZVOUS_URL=wss://<domain>/ws OPENREACH_TOKEN=<host-token> \
     OPENREACH_ICE=stun:stun.l.google.com:19302  cargo run --release -p openreach-host
   ```
4. **Run the viewer** anywhere, pointing at the host's device id (a full login/device-list UI is landing;
   the env-var path works today).

## Build

```sh
cargo build --all-targets
cargo test --all
cargo clippy --all-targets -- -D warnings
```

Needs a recent stable Rust toolchain and `protoc`. On Linux also install the X11/nasm dev packages (see
`.github/workflows/ci.yml`). macOS hosts require **Screen Recording** + **Accessibility** permissions
([`docs/macos-permissions.md`](docs/macos-permissions.md)).

## Docs
Architecture · Decisions (ADRs) · Threat model · Validation log · VPS deployment · Permissions · HACKING —
all in [`docs/`](docs). Developer guide: [`docs/HACKING.md`](docs/HACKING.md).

## License

Dual-licensed under MIT or Apache-2.0.
