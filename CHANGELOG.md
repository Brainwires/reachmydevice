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
- **Special keys**: PrintScreen/ScrollLock/Pause/Insert/Menu and the extended
  function row (F13+) added to both the macOS and Linux HID→keycode maps.
- **Multi-monitor**: the host enumerates and advertises its displays; the viewer
  shows a picker and switches the captured monitor on demand (`DisplayList` /
  `SelectDisplay`), with capture restarted transparently to the encode thread.
- **Audio (Opus, host→viewer), opt-in / default-off**: real end-to-end path —
  cpal capture → Opus (`codec::audio`) → data channel → Opus decode → cpal
  playback, with a dependency-free linear resampler and mono downmix. Codec and
  resampler are unit-tested. **Honest caveats** (see `session/audio.rs`): capture
  uses the default *input* device (true desktop-audio loopback is a platform
  follow-up), and frames ride the reliable data channel (a dedicated Opus RTP
  track is the latency optimization). Off by default so video is never affected;
  enable with `OPENREACH_AUDIO=1` on host and viewer.
- **Clipboard sync** (bidirectional, text): each side polls the OS clipboard and
  forwards changes over the control channel; an FNV-1a content hash breaks the
  echo loop. (`session/clipboard.rs`)
- **File transfer** (resumable, integrity-checked): windowed, ack-paced streaming
  over the reliable data channel; a dropped receiver leaves a `.part` that a fresh
  offer resumes from; SHA-256 prefix verified on completion; offered names are
  sanitized against path traversal. Drop a file on the viewer window to send.
  (`session/filexfer.rs`)
- **Reconnect / ICE-restart on network blips**: on a connection drop the host
  automatically restarts ICE (fresh credentials + re-gathered candidates) and
  renegotiates; the viewer rides out a grace window for the host to recover. Only
  a terminal close, or exhausted restarts, ends the session. A manual
  `request_ice_restart()` is also exposed. (`transport/driver.rs`)
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
