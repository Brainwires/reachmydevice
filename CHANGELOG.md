# Changelog

All notable changes to OpenReach. Format loosely follows Keep a Changelog.

## [Unreleased]

### Working end-to-end
- **Cross-NAT remote-desktop session proven** over the real internet: a host on a
  cloud box and a viewer behind home NAT connect via a self-hosted rendezvous,
  media STUN-traversed and DTLS-SRTP encrypted (1290 frames @ 1280×720; see
  `docs/validation.md`).
- **Self-hostable rendezvous deployed**: accounts (Argon2), device tokens, WebSocket
  signaling relay, per-IP rate limiting, and a **web console** — served in one
  Docker container behind a Cloudflare tunnel (or Caddy/ACME).

### Added
- `protocol`: versioned prost wire format + handshake; input events; v1 messages
  (clipboard, file transfer, multi-monitor, request-keyframe, view-only).
- `transport`: WebRTC over the sans-IO `rtc` fork — driver loop, H.264 video, data
  channel, GCC adaptive bitrate, DTLS-SRTP; **host + STUN server-reflexive ICE
  candidate gathering** for NAT traversal. Loopback, ciphertext-only, and srflx tests.
- `capture`: macOS ScreenCaptureKit (objc2) + Linux X11 (XGetImage) backends.
- `codec`: software H.264 (openh264) encode/decode behind `Encoder`/`Decoder` traits.
- `input`: macOS CGEvent + Linux XTest injection; HID→keycode maps incl. keypad.
- `session`: host + viewer wiring; LAN + rendezvous WebSocket signaling; device
  identity keypair + TOFU trust store; account/device REST client.
- `apps`: headless `host`, winit/wgpu `viewer` (egui UI landing), `rendezvous`
  (+ web console), `signal-dev`.
- Deploy: docker-compose (rendezvous + coturn + Caddy/ACME), host service units
  (systemd + launchd), release CI (per-platform artifacts + signing hooks).
- Docs: architecture, ADRs, threat model, validation log, VPS deployment, macOS
  permissions, HACKING.

### Known gaps / roadmap
- Desktop viewer UI (egui login/device-list/HUD) in progress; host tray pending.
- Reconnect / ICE-restart on blips; clipboard/file-transfer/audio/multi-monitor
  wiring; VideoToolbox/hardware encode; Windows (DXGI/SendInput) + Wayland
  (PipeWire/libei) backends; unattended-access gating; native installers.
