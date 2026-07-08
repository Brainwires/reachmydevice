# Changelog

All notable changes to ReachMyDevice. Format loosely follows Keep a Changelog.

## [Unreleased]

## [0.2.5] - 2026-07-08

Connection passwords, an encrypted host settings store, and a rendezvous
sign-up fix.

### Added
- **Connection password (RealVNC-style).** A host can require a shared password
  that a viewer must enter before the session is authorized — independent of, and
  composable with, the device-identity allowlist. Set it with `rmdd set password
  <value>`. The host asks only when one is set: it replies to the first Hello with
  a `password_required` ack, the viewer prompts (native egui field / browser
  prompt) and re-sends the Hello with the password over the existing connection
  (no reconnect). Wrong passwords re-prompt. Protocol bumped to MINOR 6
  (`Hello.password`, `HelloAck.password_required`; backward-compatible).
- **Encrypted host settings store + `rmdd set|unset|list`.** Secret host settings
  live in `~/.config/rmd/settings.enc`, encrypted at rest (XChaCha20-Poly1305)
  under a key derived from the device identity — no extra passphrase, `0600`.
  `rmdd list` prints keys only. The device **token** now reads from the store
  (`rmdd set token …`), falling back to the `0600` token file / `RMD_TOKEN`.
- **Runtime sign-up toggle (rendezvous).** `open_registration` is now a DB-backed
  setting (seeded from `RMD_RZ_OPEN_REGISTRATION`), flippable without a redeploy
  via `POST /api/admin/registration` (guarded by `RMD_RZ_ADMIN_TOKEN`); `GET
  /api/registration` reports the current state.

### Fixed
- **First-account bootstrap (rendezvous).** `POST /api/register` refused *all*
  sign-ups when registration was closed — including the very first account on an
  empty server, making a fresh deploy un-bootstrappable without forcing
  registration open. The first account now always bootstraps (atomically);
  once any user exists, the `open_registration` setting is enforced.

## [0.2.4] - 2026-07-08

Security release: the host now actually enforces unattended-access
authorization, and the viewer refuses a host it can't authenticate.

### Security
- **Enforce authorization on the host control channel (was bypassable).** The
  unattended-access gate (`RMD_REQUIRE_AUTH` + authorized-device list) was only
  used to shape the `HelloAck` reply — it did not gate the dangerous handlers, so
  a peer that completed DTLS could inject keyboard/mouse, drop files, set the
  clipboard, switch displays, and receive the screen stream **without** (or
  despite a rejected) authorization. Authorization is now a per-session state:
  until an accepted `Hello` sets it, every non-`Hello` message is dropped, no
  screen is captured or streamed, and no input is injected; it resets on each
  (re)connect. This makes `RMD_REQUIRE_AUTH` actually restrict who can control the
  host. (Host is still trusted-LAN-oriented by default — the rendezvous device
  token remains the access credential; use the allowlist for internet exposure.)
- **Viewer refuses a session with an unverifiable host identity.** When the
  host's `HelloAck` identity proof fails verification (possible MITM), the viewer
  now hard-fails (no `Paired`) instead of logging a warning and continuing.

### Added
- **Explicit `RMD_TURN_ENABLED` switch (relay off by default).** TURN relay uses
  the rendezvous server's bandwidth (media relays through it when peers can't
  connect directly), so enabling it is now one deliberate operator decision:
  `/api/ice` hands out TURN only when `RMD_TURN_ENABLED=1` **and** a secret +
  host are set — a dangling secret alone no longer enables relay. Default (and
  any fresh deploy) is **STUN-only, peer-to-peer, zero relay bandwidth**. The
  active mode is logged at startup.
- **Security-event logging + fail2ban integration.** The rendezvous emits a
  stable `rmd_security: auth-fail ip=… path=… method=…` line on every auth
  failure (bad device token on `/ws` or `/api/ice`, bad HTTP Basic on the account
  API), with the real client IP from `CF-Connecting-IP`/`X-Forwarded-For`.
  `deploy/fail2ban/` ships a ready filter + jail + README. Layered on the
  existing per-IP rate limiter and per-account login throttle; scoped to
  auth-abuse hardening (not volumetric-DDoS mitigation).

### Tests
- **Authorization-gate regression coverage (both halves).** An exhaustive test
  pins the control-gate allowlist (only `Hello` is processed before auth; input,
  clipboard, file, keyframe, display-switch, ping, view-only, and audio are all
  dropped), and an integration test runs the real encode thread over a loopback
  WebRTC transport to prove an unauthorized peer receives zero video until
  authorization flips on — so a future refactor can't silently re-open the hole.

## [0.2.3] - 2026-07-07

Web-app polish, on-demand capture, and reliable reconnects.

### Added
- **Rename devices** in the web app (pencil button per host) — new
  `PATCH /api/devices/:id` updates the display name only (token/key/role kept).
- **Rotate the view 90°** in the browser session (handy on phones: view a
  landscape desktop in landscape on a portrait screen). Cycles 0/90/180/270°;
  pointer coordinates are un-rotated so input still lands correctly.
- **Auto-refresh the device list** when the tab/window regains focus, so online
  dots reflect reality without a manual Refresh.

### Changed
- **One web UI.** `app.reachmy.dev` now redirects to the web app at `/app/` (the
  WASM viewer — sign in, manage devices, connect); the legacy static
  `console.html` is retired. The landing page has a single "Open the web app" CTA.
- **Device list is an address book** — only connectable hosts are shown;
  viewer-only clients (this browser and others) are hidden.

### Fixed
- **Screen capture is now on-demand.** `rmdd` opened the ScreenCaptureKit/X11
  stream at launch and kept it open, so macOS showed "your screen is being
  shared" even with nobody connected. Capture now starts on the first viewer
  connect and stops on disconnect. Also adds the missing `Drop` impls so dropping
  a capture session actually stops the stream (macOS + Linux).
- **Reliable reconnects.** A reloaded viewer sometimes couldn't reconnect (needing
  an `rmdd` restart): the host re-offered the instant the connection dropped, but
  the reloaded browser re-attaches to `/ws` a moment later and the relay doesn't
  buffer for an offline peer, so the offer was lost. The host now caches the
  current offer + trickled candidates and replays them on the viewer's `hello`
  (every page load) — offer-on-(re)join.
- **Installer noise.** `install.sh` no longer prints a spurious
  `printf: write error: Broken pipe` while resolving the release.

## [0.2.2] - 2026-07-06

The browser viewer works end-to-end: a browser connects to a native host over the
vendored sans-IO WebRTC fork, across NAT, with a relay fallback and clean
reconnects.

### Added
- **TURN relay for cross-NAT / browser connectivity.** The rendezvous now serves
  `GET /api/ice` (device-token auth), minting **ephemeral** coturn
  `--use-auth-secret` credentials (username `<expiry>:rmd`, credential
  `base64(HMAC-SHA1(secret, username))`) alongside STUN — configured via
  `RMD_TURN_SECRET` / `RMD_TURN_HOST` / `RMD_TURN_PORT` / `RMD_TURN_TTL`
  (STUN-only when unset). The host (`rmdd`), native viewer, and browser viewer all
  fetch `/api/ice` and use the returned servers, so peers can relay through NAT
  instead of failing when only private/`.local` candidates exist. Transport ICE
  config gained credentials (`IceServer { urls, username, credential }`).

  This closes the second wall of the first real browser↔host session: Chrome
  obfuscates its host candidate as an mDNS `.local` name (the fork drops it) and
  the host had no relay, so no candidate pair formed. A shared TURN relay fixes it.

### Fixed
- **Browser viewer WebRTC handshake.** The native host encodes the offer/answer
  `data` as a JSON `RTCSessionDescription` (`{"type","sdp"}`, matching `rtc`'s serde
  form), which the native viewer decodes symmetrically. The WASM viewer had broken
  that contract in both directions — passing the whole JSON blob into
  `setRemoteDescription` (Chrome rejected it with `Expect line: v=`) and replying
  with raw SDP the host couldn't parse. It now unwraps the SDP on receive and wraps
  the answer on send, matching the native peer. First bug surfaced by a real
  simultaneous host+browser session; the fork's SDP marshaling was correct.
- **Rendezvous keepalive.** The signaling `/ws` now sends a WebSocket Ping every 30s
  so Cloudflare's ~100s idle timeout no longer silently drops a long-idle host, and a
  `last_seen` heartbeat keeps the console's online indicator fresh.
- **Reconnect loses input control.** Reconnection used an ICE restart on the
  long-lived peer connection (swaps ICE creds, keeps DTLS/SCTP). A reloaded browser
  brings fresh DTLS + a new SCTP association that can't graft onto the old
  connection, so video renegotiated but the host's `control` data channel never
  re-opened — killing keyboard/mouse until `rmdd` was restarted. The transport now
  rebuilds a **fresh peer connection per session** (new DTLS + `control` channel +
  offer) on drop, so a reconnecting/reloaded viewer always gets working input.
- **H.264 encoder rebuild churn.** The encoder was fully rebuilt whenever GCC's
  bitrate target drifted >20% — which happens continuously — flooding logs with
  openh264 `ParamValidation` warnings and forcing wasteful keyframes. Rebuilds now
  need a 35% sustained drift and a 4s minimum interval, and openh264 logging is
  silenced.

## [0.2.1] - 2026-07-06

Distribution + first-run polish (all publicly installable now that the repo is public).

- **Unix CLI names:** the host daemon is **`rmdd`**, the client/viewer is **`rmd`**
  (package names unchanged). `rmd`/`rmdd` gained `--version`/`--help`.
- **Installer overhaul (`install.sh`):** prebuilt (default) *or* source install; the
  system-requirements check runs only for source builds and never blocks a prebuilt.
  Installs to `~/.local/bin` (no sudo) and auto-adds it to the shell PATH. Re-runnable
  (upgrades, or reports "up to date"); `--uninstall`, `--help`, and flag equivalents.
  Signature *or* SHA-256-over-HTTPS verification with no required external tool.
- **`linux-arm64` prebuilt** for arm64 SBCs (Orange Pi 5B, Raspberry Pi 4/5 on a
  64-bit OS), cross-compiled with `cross` (glibc-2.31 baseline → Pi-OS portable).
- **Host over SSH:** the Linux capture backend now **auto-discovers `DISPLAY`/
  `XAUTHORITY`** (tries `:0`/`:1` + the usual cookie locations), so `rmdd` started
  over SSH captures the local desktop with no env prefix.
- The rendezvous serves `/install.sh` from a mounted file (fast updates, no rebuild).

## [0.2.0] - 2026-07-05

Pure-Rust default build, a browser viewer, and a public landing page.

### Pure-Rust toolchain (C removed from the default build)
- **protoc → `protox`.** The protobuf schema now compiles with the pure-Rust
  `protox` at build time; no `protoc` binary is required anywhere (dropped from the
  build scripts, CI, and the release workflow / Docker image).
- **Audio is opt-in.** Opus (`audiopus`, C libopus via CMake) + `cpal` moved behind
  `--features audio` in `rmd-codec`/`rmd-session` (forwarded by `rmd-host`/
  `rmd-viewer`). Runtime behaviour is unchanged (audio was already off by default);
  the default build no longer needs CMake/libopus. `RMD_AUDIO=1` on a feature-built
  binary still enables host→viewer Opus.
- **minisign CLI → `rsign2`.** Release signing prefers the pure-Rust `rsign2`
  (identical minisign signature format), falling back to the `minisign` C CLI. The
  pinned public key and users' verification are unchanged.
- **Payoff: universal macOS builds.** With the C bits gated off, **Apple-Silicon
  (arm64) macOS cross-builds now succeed** (previously blocked by the audiopus
  CMake step) — the release ships both Intel and Apple-Silicon macOS binaries.

### Video codecs
- **Codec abstraction.** `VideoCodec { H264 (default), Av1 }` behind the existing
  `Encoder`/`Decoder` traits with a single dispatch chokepoint. H.264 remains the
  symmetric default (native encode+decode, browser-decodable).
- **Pure-Rust AV1 encoder (`rav1e`), opt-in via `--features av1`** and `RMD_CODEC=av1`.
  Encode-only: there is no pure-Rust AV1 *decoder* with a library API, so AV1 is for
  browser viewers (which decode it themselves); native viewers always use H.264.
  **Caveat:** `rav1e` (speed preset 10) is **not real-time** for full-motion desktop
  on typical CPUs (≈366 ms/frame at 720p on an Intel Mac) — it's for low-motion
  content or strong hardware, not a real-time default. See `examples/av1_bench.rs`.
- **In-band codec negotiation** (protocol MINOR 5): `Hello.supported_video_codecs`
  + `HelloAck.video_codec`. The host announces its codec and cleanly rejects a
  viewer that can't decode it (legacy peers are treated as H.264-only).

### Browser viewer (`apps/web-viewer`, WASM)
- A **no-install browser viewer**: authenticates to the rendezvous over WebSocket
  (the exact native `/ws` relay protocol), acts as the WebRTC answerer to a native
  host, shows the browser-decoded H.264 in a `<video>` element, and sends mouse/
  keyboard input over the control data channel as `rmd-protocol` protobufs. Built
  with `trunk` (~245 KB wasm). _Preview: live browser↔host WebRTC interop is not yet
  validated end-to-end; a wgpu-canvas render path is a planned follow-up._

### Landing page + hosting
- **Host-based routing** in the rendezvous: the apex `reachmy.dev` serves a public
  **landing page** (explains the app, links downloads + the console + the web
  viewer); `app.reachmy.dev` serves the existing console. `/install.sh` serves the
  `curl | sh` installer; `/app` serves the web-viewer bundle (`tower-http` ServeDir,
  `.wasm` as `application/wasm`). The Docker image builds + bundles the viewer; the
  reference Caddy deploy serves both hostnames.

## [0.1.0] - 2026-07-05

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
  proof-replay residual. Enabled by populating `~/.config/rmd/authorized_keys`
  (or `RMD_AUTHORIZED_KEYS`) or `RMD_REQUIRE_AUTH=1`; off for LAN/dev.
  Accept/MITM-reject and proof-binding are unit-tested. See threat-model A4.
- **`deploy/install-host.sh`**: one-command host install — builds, installs the
  binary + service unit (systemd/launchd), and seeds the config dir.
- **Host tray companion** (`--features tray`, opt-in via `RMD_TRAY=1`): a
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
  optimization). Off by default; enable with `RMD_AUDIO=1` on host + viewer.
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
