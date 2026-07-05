# ReachMyDevice

**Self-hostable, end-to-end-encrypted remote desktop / KVM-over-IP.** A clean, ownable replacement for
RealVNC's departed cloud tier: install a host agent on the machine you want to reach, a viewer anywhere
else, point both at your own rendezvous server on a cheap VPS, and get a low-latency encrypted session —
**P2P when possible, relayed when not, with no third-party cloud and no subscription.**

> **Status:** macOS + Linux hosts/viewers working end-to-end, with a full egui viewer UI, reconnect,
> clipboard, resumable file transfer, audio (real desktop capture → speaker), and multi-monitor.
> **A real cross-NAT session is proven** (host on a cloud box ↔ viewer behind home NAT, signaling through
> a self-hosted rendezvous, media STUN-traversed and DTLS-SRTP encrypted — see
> [`docs/validation.md`](docs/validation.md)). Windows/Wayland backends and hardware encode are next.

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

## Security

ReachMyDevice is built so the machine that introduces your devices — the rendezvous — is **untrusted for
session content**. Everything below is implemented; see [`docs/threat-model.md`](docs/threat-model.md) for
the adversary model and residual risks.

**End-to-end encryption**
- Media (**SRTP**) and the control/data channel (**SCTP-over-DTLS**) are encrypted **host↔viewer**; keys are
  negotiated per session and never shared with the rendezvous or TURN relay.
- The relay only ever forwards **ciphertext** — asserted by an automated test that a plaintext canary never
  appears in relayed bytes.

**Device identity & key protection**
- Each device has a long-lived **ed25519** identity; its public-key fingerprint is the `device_id`.
- The private key is **encrypted at rest** (Argon2id → XChaCha20-Poly1305) when a passphrase is set,
  **zeroized** in memory, and stored with owner-only permissions (unix `0600` **and** Windows ACL).

**Authenticating the peer (anti-MITM)**
- **Host identity proof:** the host signs a proof **bound to the session's DTLS fingerprint**; the viewer
  accepts it only if it's valid **and** matches the device it selected **and** the key pinned for that host —
  so a malicious relay can neither swap the host's key nor DTLS-MITM the session on reconnect.
- **TOFU** pins a host's key on first use with a 6-digit **SAS** to compare out-of-band; a later key change
  is refused.
- **Direct QR/PAKE pairing** (no account): establish trust device-to-device via a **QR seed-transfer** (when
  co-located) or a **SPAKE2 short code** (remote), exchanged over a stateless relay mailbox. The code's
  secret never reaches the relay, and confirmation is directional + constant-time (reflection-safe).

**Unattended access**
- A host can require an **authorized-keys** allow-list; a viewer must present an ed25519 **access proof
  bound to the DTLS fingerprint**, so an unauthorized device — or a relay replaying a captured proof — is
  rejected. A visible on-host indicator (and optional tray) shows when a remote is connected.

**Self-hosted rendezvous hardening**
- Passwords hashed with **Argon2id** (pinned params); device tokens stored only as SHA-256 hashes;
  **registration closed by default**; **per-username login lockout** with backoff plus per-IP rate limiting;
  TLS via Caddy/ACME or Cloudflare.

**Supply chain & assurance**
- The WebRTC fork is a **pinned git submodule** (offline/reproducible builds, no external git deps),
  gated by **cargo-deny/cargo-audit**, with a **CycloneDX SBOM**, a pinned toolchain, and **signed** releases.
- All `unsafe` (confined to the macOS capture FFI) is reviewed + length-guarded ([`docs/unsafe-audit.md`](docs/unsafe-audit.md));
  the untrusted-input parsers are **fuzzed** (`cargo-fuzz`) with stable no-panic tests in CI.
- An **independent security-review pass** was run against this codebase (it found and we fixed two
  authentication-bypass bugs in the pairing/host-proof crypto). A full third-party audit is recommended
  before high-stakes use.

> Full formal certification (FIPS / NSA CSfC / Common Criteria) and hardware-backed keys (TPM / Secure
> Enclave) are **out of scope** today; the design meets their technical prerequisites.

## Install

**Prebuilt (macOS Apple Silicon, Linux x86_64):**

```sh
curl -fsSL https://raw.githubusercontent.com/Brainwires/reachmydevice/main/deploy/release/install.sh | sh
```

Detects your OS/arch, downloads the latest **signed** release, verifies it
(minisign if installed, otherwise SHA-256), and installs `rmd-viewer` +
`rmd-host` into `~/.local/bin`. macOS builds are **unsigned** (no Apple
Developer ID yet) — on first launch right-click → *Open*, or
`xattr -d com.apple.quarantine ~/.local/bin/rmd-viewer`.

Other download options on the [Releases](https://github.com/Brainwires/reachmydevice/releases)
page: a `.dmg` (viewer `.app`) for macOS, `.deb` packages (host + rendezvous) for
Debian/Ubuntu, and plain `.tar.gz` archives — each with a minisign `.minisig`.

**Build from source** (any platform, and the **only** route on **Windows** — see
[Build](#build)). How releases are produced: [`deploy/release/README.md`](deploy/release/README.md).

## Quick start (self-hosted)

1. **Deploy the rendezvous** on a VPS (`deploy/docker-compose.yml`, or the single container behind an
   existing Cloudflare tunnel). See [`docs/vps-deployment.md`](docs/vps-deployment.md). It serves a web
   console at `https://<your-domain>/`.
2. **Create an account** in the console (or `POST /api/register`), then register your host + viewer devices
   to get bearer tokens.
3. **Run the host** on the machine to control:
   ```sh
   RMD_RENDEZVOUS_URL=wss://<domain>/ws RMD_TOKEN=<host-token> \
     RMD_ICE=stun:stun.l.google.com:19302  cargo run --release -p rmd-host
   ```
4. **Run the viewer** anywhere and pick the host from the device list, or **pair directly with no account**
   from the viewer's *Pair a device* screen (share a one-time code — QR/PAKE). The env-var path also works
   for scripted/headless viewers.

## Build

The WebRTC transport is vendored as a **git submodule**, so clone with it:

```sh
git clone --recurse-submodules <repo>      # or: git submodule update --init --recursive
cargo build --all-targets
cargo test --all
cargo clippy --all-targets -- -D warnings
```

Needs the pinned Rust toolchain (`rust-toolchain.toml`) and `protoc`. On Linux also install the X11/nasm
dev packages (see `.github/workflows/ci.yml`). macOS hosts require **Screen Recording** + **Accessibility**
permissions ([`docs/macos-permissions.md`](docs/macos-permissions.md)).

## Docs
Architecture · Decisions (ADRs) · [Threat model](docs/threat-model.md) · [Unsafe audit](docs/unsafe-audit.md) ·
[Validation log](docs/validation.md) · VPS deployment · Permissions · HACKING — all in [`docs/`](docs).
Developer guide: [`docs/HACKING.md`](docs/HACKING.md).

## License

Dual-licensed under MIT or Apache-2.0.
