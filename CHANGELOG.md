# Changelog

All notable changes to OpenReach. Format loosely follows Keep a Changelog.

## [Unreleased]

### Security hardening (branch `security-hardening`)
Seven workstreams (A–G). Every change is build-, clippy-, and test-clean; the
threat model (`docs/threat-model.md`) records the mitigations and residuals.

- **A — Supply chain & build integrity.** The `webrtc-rs-rtc` fork is now a pinned
  **git submodule** (was a moving branch dep) → offline/reproducible builds and the
  code present locally for audit. Added `deny.toml` + `cargo-deny`/`cargo-audit` CI
  gate (forbids any external git source), a CycloneDX **SBOM**, a pinned toolchain,
  and **signed** (minisign) reproducible release artifacts.
- **D — Secrets & key-at-rest.** The ed25519 identity key is **encrypted at rest**
  (Argon2id → XChaCha20-Poly1305) when a passphrase is set, **zeroized** in memory
  (seed/key/token buffers), and gets restrictive perms on **Windows** too (was
  unix-only). The host device token is read from a `0600` file rather than an env var.
- **C — Account/TOFU hardening + first-connect MITM (A2) closed.** The host proves
  its identity **bound to the session's DTLS fingerprint** in `HelloAck`; the viewer
  accepts only a proof that is valid **and** matches the device it selected **and**
  the key pinned for it — otherwise it refuses the session. Rendezvous registration
  is **closed by default**, Argon2id params are pinned (64 MiB/t=3/p=1), and a
  **per-username login lockout** with exponential backoff was added.
- **F — Correctness.** File-transfer integrity uses the **full 32-byte SHA-256**
  (was a truncated 64-bit prefix). An always-on host **inhibits system idle sleep**
  (IOKit / systemd-inhibit / SetThreadExecutionState) so it stays reachable.
- **E — Memory-safety & fuzzing.** All `unsafe` (the capture FFI) is reviewed,
  length-guarded against OS-supplied values, and documented (`docs/unsafe-audit.md`).
  `cargo-fuzz` targets for the untrusted parsers (protobuf decode, file-transfer,
  signaling frame) + stable no-panic regression tests (~100k inputs) run in CI.
- **B — Direct QR/PAKE pairing (new subsystem).** Establish trust device-to-device
  with **no server account**: a **QR seed-transfer** (co-located) or a **SPAKE2 short
  code** (remote), over a **stateless relay mailbox** (`/pair?code=…`). Wormhole-style
  `<channel>-<secret>` codes keep the secret off the relay; terminal QR for headless
  hosts. Two devices pair end-to-end with no accounts (`tests/pairing_e2e.rs`), and
  it's wired into the **viewer GUI** (generate/enter a code → pair → TOFU-pin). The
  co-located camera-scan screen remains (needs camera hardware).
- **G — Independent security review** (`/security-review`) found and we **fixed two
  HIGH-confidence auth-bypass bugs** in the new crypto: (1) a **reflectable PAKE
  confirmation** — the symmetric tag could be echoed by an attacker who didn't know
  the code — replaced with **directional, constant-time** confirmation; (2) the
  viewer verified the host proof but didn't bind it to the **expected** host, so a
  DTLS-MITM relay's own key passed — now checked against the selected device + pinned
  key. A full external audit + pen test remains (third-party).

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
  **Verified fully end-to-end on real hardware**: real ScreenCaptureKit desktop
  capture → Opus → WebRTC/DTLS-SRTP → decode → speaker, with a human confirming the
  audible round-trip (`docs/validation.md`); also delivered cross-NAT (biscuits→Mac,
  1300 Opus frames) and covered by `tests/audio_delivery.rs`.
- **Clipboard sync** (bidirectional, text): each side polls the OS clipboard and
  forwards changes over the control channel; an FNV-1a content hash breaks the
  echo loop. (`session/clipboard.rs`)
- **File transfer** (resumable, integrity-checked): windowed, ack-paced streaming
  over the reliable data channel; a dropped receiver leaves a `.part` that a fresh
  offer resumes from; the **full SHA-256** is verified on completion; offered names
  are sanitized against path traversal. Drop a file on the viewer window to send.
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
Done since the first cut: full egui viewer + host tray, reconnect/ICE-restart,
clipboard, resumable file transfer, audio (incl. real desktop capture), multi-monitor,
unattended-access gating, install helper. Still open:
- **External security audit + pen test** (third-party) — the `/security-review` pass
  is done and its findings fixed, but an independent audit of the vendored WebRTC
  fork's crypto is the trust-establishing step.
- **Pairing:** the co-located **camera QR-scan** screen in the viewer (needs camera
  hardware); the code-based PAKE path is fully wired.
- **Platform backends:** Windows (DXGI/SendInput) + Wayland (PipeWire/libei);
  VideoToolbox/hardware encode; native installers (deb/dmg/msi).
- **High-assurance (deferred):** hardware-backed keys (TPM/Secure Enclave), a
  dedicated Opus RTP audio track, and any FIPS/CSfC/Common-Criteria certification.
