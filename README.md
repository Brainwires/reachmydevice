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

- **Host agent** (`apps/host`) — captures the screen, **pure-Rust** encodes it (H.264 by default; optional
  AV1 via `rav1e`, `--features av1`), streams it over WebRTC, and injects the viewer's keyboard/mouse.
  Headless; runs unattended. Ships for macOS (Intel + Apple Silicon) and Linux.
- **Viewer** (`apps/viewer`) — GPU-accelerated (winit + wgpu) native display of the remote desktop; sends input.
- **Web viewer** (`apps/web-viewer`) — a **no-install browser viewer** (WASM): connects over WebRTC and
  decodes H.264 in the browser. Served at `/app` by the rendezvous. _Preview in 0.2.0._
- **Rendezvous** (`apps/rendezvous`) — self-hostable signaling + device registry + **web console** +
  **public landing page** (axum + SQLite), paired with **coturn** for STUN/TURN. Ships as Docker + a
  Cloudflare-tunnel or Caddy/ACME deployment.

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
(minisign if installed, otherwise SHA-256), and installs the client **`rmd`** +
the host daemon **`rmdd`** into `~/.local/bin` (add it to your `PATH`). macOS
builds are **unsigned** (no Apple Developer ID yet) — on first launch right-click →
*Open*, or `xattr -d com.apple.quarantine ~/.local/bin/rmd`.

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
3. **Run the host daemon** (`rmdd`) on the machine to control:
   ```sh
   rmdd set rendezvous_url wss://<domain>/ws
   rmdd set token <host-token>
   rmdd set password <a-connection-password>   # optional; viewers must enter it
   rmdd                                          # or: rmdd enable  — run as a background service
   ```
   Secrets go in `rmdd`'s **encrypted settings store** (above); every knob also has an
   env var — see [Configuration](#configuration). (From a source checkout instead:
   `cargo run --release -p rmd-host`.)
4. **Run the viewer** (`rmd`) anywhere and pick the host from the device list, or **pair directly with no account**
   from the viewer's *Pair a device* screen (share a one-time code — QR/PAKE). The env-var path also works
   for scripted/headless viewers.

## Configuration

`rmdd` resolves each setting in this order: **encrypted settings store**
(`rmdd set <key> <value>` — recommended for secrets; never appears in `ps`) →
**environment variable** → built-in default.

**Host (`rmdd`)**

| Variable | Default | Meaning | `rmdd set` key |
|---|---|---|---|
| `RMD_RENDEZVOUS_URL` | — | Rendezvous `wss://…/ws`; enables rendezvous mode | `rendezvous_url` |
| `RMD_TOKEN` / `RMD_TOKEN_FILE` | — | Device bearer token (prefer the store or a `0600` file — env leaks in `ps`) | `token` |
| `RMD_NAME` | hostname | Device name shown to viewers | — |
| `RMD_ICE` | — | Comma-separated STUN/TURN URLs | — |
| `RMD_BIND` | `0.0.0.0:0` | Transport UDP bind address. **On a firewalled/public host, pin a fixed port and open it** — a random port is blocked, forcing ICE onto the relay | — |
| `RMD_DISPLAY` | `0` | Display index to capture | — |
| `RMD_WIDTH` / `RMD_HEIGHT` | `1920` / `1080` | Capture/encode size (advisory on X11 — native resolution wins) | `width` / `height` |
| `RMD_FPS` | `30` | Frame rate | `fps` |
| `RMD_BITRATE` | `8000000` | Target bitrate in bps (GCC adapts down) | `bitrate` |
| `RMD_CODEC` | `h264` | `h264` \| `av1` (AV1 needs `--features av1`) | — |
| `RMD_AUDIO` | off | Set to enable host→viewer Opus audio | — |
| `RMD_KEY_PASSPHRASE` | — | Encrypt the device identity key at rest | — |
| `RMD_AUTHORIZED_KEYS` | `~/.config/rmd/authorized_keys` | Allow-list file for unattended access | — |
| `RMD_REQUIRE_AUTH` | off | Force the unattended-access gate (auto-on when the allow-list exists) | — |
| `RMD_NO_KEEPAWAKE` | off | Don't inhibit system sleep | — |
| `RMD_TRAY` | off | `=1` runs the desktop tray (needs `--features tray`) | — |
| `RMD_SIGNAL_ADDR` | `127.0.0.1:9000` | LAN dev signaling relay (used when no rendezvous URL is set) | — |

The connection password is store-only: `rmdd set password <pw>`. On Linux, X11
capture/input use **`DISPLAY`** / **`XAUTHORITY`** — point them at the target server
(e.g. `DISPLAY=:99` for a headless Xvfb).

**Run `rmdd` as a background service** (per-user; systemd `--user` on Linux, launchd
on macOS):

```sh
rmdd enable        # install + enable autostart + start
# disable | status | start | stop | restart | log [-f]
```

**Viewer (`rmd`):** `RMD_SERVER` (account server, default `https://app.reachmy.dev`),
`RMD_TOKEN` + `RMD_PEER_DEVICE_ID` (scripted/headless connect), `RMD_BIND`.

**Rendezvous server:** `RMD_RZ_ADDR`, `RMD_TURN_ENABLED` / `RMD_TURN_HOST` /
`RMD_TURN_PORT` / `RMD_TURN_SECRET` / `RMD_TURN_TTL`, `RMD_RZ_ADMIN_TOKEN`,
`RMD_RZ_OPEN_REGISTRATION`, `RMD_WEBVIEWER_DIR`, `DATABASE_URL` — see
[`deploy/.env.example`](deploy/.env.example) and
[`docs/vps-deployment.md`](docs/vps-deployment.md).

**Installer** (`install.sh`): `RMD_MODE`, `RMD_PREFIX`, `RMD_VERSION`, `RMD_SERVICE`
(set up the service), `RMD_NO_PATH`, `RMD_FORCE`, `RMD_PURGE` — see the script header.

## Build

The WebRTC transport is vendored as a **git submodule**, so clone with it:

```sh
git clone --recurse-submodules <repo>      # or: git submodule update --init --recursive
cargo build --all-targets
cargo test --all
cargo clippy --all-targets -- -D warnings
```

Needs only the pinned Rust toolchain (`rust-toolchain.toml`) — the default build is **pure Rust**
(no `protoc`, no CMake): the protobuf schema compiles with `protox`. Optional features pull extra
tooling: `--features av1` (host AV1 encode via rav1e) and `nasm` for its SIMD, and `--features audio`
(Opus) needs CMake. On Linux install the X11 dev packages (see `.github/workflows/ci.yml`). macOS hosts
require **Screen Recording** + **Accessibility** permissions ([`docs/macos-permissions.md`](docs/macos-permissions.md)).

The **browser viewer** (`apps/web-viewer`, WASM) is built separately with
[`trunk`](https://trunkrs.dev): `cd apps/web-viewer && trunk build --release --public-url /app/`.

## Docs
Architecture · Decisions (ADRs) · [Threat model](docs/threat-model.md) · [Unsafe audit](docs/unsafe-audit.md) ·
[Validation log](docs/validation.md) · VPS deployment · Permissions · HACKING — all in [`docs/`](docs).
Developer guide: [`docs/HACKING.md`](docs/HACKING.md).

## License

Dual-licensed under MIT or Apache-2.0.
