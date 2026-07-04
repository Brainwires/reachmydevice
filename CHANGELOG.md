# Changelog

All notable changes to OpenReach. Format loosely follows Keep a Changelog.

## [Unreleased]

### Security hardening (branch `security-hardening`)
- **Supply chain:** the webrtc-rs-rtc fork is now a pinned **git submodule** (was a
  moving branch dep) → offline/reproducible builds; `cargo-deny`/`cargo-audit` +
  CycloneDX SBOM + pinned toolchain + signed release artifacts.
- **Identity key at rest:** encrypted (Argon2id + XChaCha20-Poly1305) when a
  passphrase is set, zeroized in memory, restrictive perms on Windows too.
- **First-connect MITM (A2) closed:** the host proves its identity **bound to the
  DTLS session** in `HelloAck`; the viewer authenticates/TOFU-pins that proven key
  and refuses on failure. Symmetric to the unattended proof.
- **Rendezvous:** registration **closed by default**, Argon2id params pinned, and a
  per-username **login lockout** with backoff.
- **File integrity:** full 32-byte SHA-256 (was a truncated 64-bit prefix).
- **Always-on host:** inhibits system idle sleep so it stays reachable.
- **Memory-safety + fuzzing:** all `unsafe` (capture FFI) reviewed + length-guarded
  and documented (`docs/unsafe-audit.md`); `cargo-fuzz` targets for the untrusted
  parsers + stable no-panic regression tests in CI.
- **Direct QR/PAKE pairing (new):** establish trust device-to-device with no server
  account — a **QR seed-transfer** (co-located) or a **SPAKE2 short code** (remote),
  over a **stateless relay mailbox** (`/pair?code=…`). Two devices pair end-to-end
  with no accounts (proven by `pairing_e2e`); wormhole-style `<channel>-<secret>`
  codes; terminal QR for headless hosts. Remaining: the viewer's QR/scan screen.

### Working end-to-end
- **Cross-NAT remote-desktop session proven** over the real internet: a host on a
  cloud box and a viewer behind home NAT connect via a self-hosted rendezvous,
  media STUN-traversed and DTLS-SRTP encrypted (1290 frames @ 1280×720; see
  `docs/validation.md`).
- **Self-hostable rendezvous deployed**: accounts (Argon2), device tokens, WebSocket
  signaling relay, per-IP rate limiting, and a **web console** — served in one
  Docker container behind a Cloudflare tunnel (or Caddy/ACME).

### Added
- **Unattended-access gate (DTLS-channel-bound)**: a host with
  `require_authorization` accepts a session only from a viewer that presents a
  valid ed25519 **access proof** whose derived `device_id` is in the host's
  `authorized_keys`. The proof is signed over the session's **DTLS fingerprint**,
  so a malicious rendezvous that MITMs the transport is rejected (the fingerprint
  it must present no longer matches the signed one) — closing the earlier
  proof-replay residual. Enabled by populating `~/.config/openreach/authorized_keys`
  (or `OPENREACH_AUTHORIZED_KEYS`) or `OPENREACH_REQUIRE_AUTH=1`; off for LAN/dev.
  Accept/MITM-reject and proof-binding are unit-tested. See threat-model A4.
- **`deploy/install-host.sh`**: one-command host install — builds, installs the
  binary + service unit (systemd/launchd), and seeds the config dir.
- **Host tray companion** (`--features tray`, opt-in via `OPENREACH_TRAY=1`): a
  menu-bar/system-tray icon that goes green while a remote is connected, with a
  Quit item. The session runs on a background thread and reports state
  (`HostStatus`) to the tray, which owns the main thread (required on macOS).
  Feature-gated so headless/server hosts build without GTK/winit.
- **Special keys**: PrintScreen/ScrollLock/Pause/Insert/Menu and the extended
  function row (F13+) added to both the macOS and Linux HID→keycode maps.
- **Multi-monitor**: the host enumerates and advertises its displays; the viewer
  shows a picker and switches the captured monitor on demand (`DisplayList` /
  `SelectDisplay`), with capture restarted transparently to the encode thread.
- **Audio (Opus, host→viewer), opt-in / default-off**: real end-to-end path —
  capture → Opus (`codec::audio`) → data channel → Opus decode → cpal playback,
  with a dependency-free resampler and mono downmix (codec + resampler
  unit-tested). Capture prefers real **desktop/system audio** via ScreenCaptureKit
  on macOS (`capture::start_audio_capture`, extracting PCM from audio
  `CMSampleBuffer`s), falling back to the default input device where unavailable.
  macOS desktop capture uses the Screen Recording permission the host already
  needs; verified to that permission boundary (`examples/audio_probe`). Transport
  is the reliable data channel for now (a dedicated Opus RTP track is the latency
  optimization). Off by default; enable with `OPENREACH_AUDIO=1` on host + viewer.
  **Delivery is proven end-to-end** by `tests/audio_delivery.rs` — a synthetic
  tone survives Opus encode → the real WebRTC/DTLS-SRTP data channel → Opus
  decode between two live transports, the exact standard `pipeline.rs` sets for
  video (the capture *device* and speaker are the on-device boundaries).
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
