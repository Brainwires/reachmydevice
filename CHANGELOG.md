# Changelog

All notable changes to ReachMyDevice. Format loosely follows Keep a Changelog.

## [Unreleased]

### Fixed
- **Three-finger scroll (and mouse wheel) now respect the view rotation.** The scroll
  delta was sent in raw screen space, so in a rotated view (landscape) it scrolled the
  wrong axis — portrait (no rotation) worked by luck. It's now rotated into host space
  with the same transform `norm()` applies to cursor/tap positions.

### Changed
- **Web-viewer: the header stays a fixed top bar in every orientation.** Rotating the
  view (esp. the 180° flip) no longer moves the toolbar to the opposite edge or rotates
  its controls — only the video, cursor, gestures and on-screen keyboard rotate; the
  app frame stays put. The flipped-portrait video now fills the area below the header,
  rotated in place.
- **Web-viewer keeps the session alive when the page loses focus.** Backgrounding a
  tab / switching apps no longer tears the connection down (it did before, which on
  desktop killed a perfectly good session and on mobile — where `visibilitychange`
  fires constantly — cycled reconnects and re-prompted the connection password). The
  session now stays connected through a blur; auto-reconnect happens **only on
  regaining focus** when the session isn't already healthy.

## [0.2.17] - 2026-07-14

### Security (rendezvous)
Full hardening pass on the rendezvous TURN-credential broker (from a security audit),
so it can safely front first-party apps as a shared STUN/TURN service:

- **Trusted-proxy client IP.** The real client IP (for the rate limiter + auth-failure
  logging) is now taken **only** from a configured `RMD_TRUSTED_PROXY_HEADER`
  (e.g. `cf-connecting-ip`); a client-supplied `X-Forwarded-For` can no longer forge
  the IP to dodge limits or poison fail2ban. Unset ⇒ socket-peer only.
- **Real per-client rate limiting.** `tower_governor` now keys on the trust-resolved
  client IP instead of the ingress-proxy IP (which had collapsed every request into one
  global bucket).
- **Tokens out of URLs.** `GET /api/ice` accepts `Authorization: Bearer` (the `?token=`
  query is a deprecated fallback), and `/ws` accepts a short-lived single-use ticket
  from `GET /api/ws-ticket`, so long-lived bearer tokens stop leaking into proxy/access
  logs and `Referer`.
- **First-account land-grab closed.** `RMD_RZ_BOOTSTRAP_TOKEN` gates first-account
  creation (and provisioning while signup is closed); without it the empty-table
  bootstrap no longer lets a stranger claim the instance.
- **Argon2 DoS bounded.** Password verification runs under a small concurrency semaphore
  on the blocking pool, so an auth-endpoint flood can't OOM/peg a small VPS.
- **TURN credentials are user-bound + short-lived.** Minted username is now
  `<expiry>:<user_id>` (was a shared constant) with a **600s** default TTL (`RMD_TURN_TTL`),
  and `/api/ice` reuses a cached live credential per user rather than minting unbounded
  shareable creds.
- **Device tokens expire + rotate.** New tokens get a default **90-day** expiry
  (`RMD_RZ_TOKEN_TTL`, `0` = none); re-registering a device invalidates its prior tokens.

Backward compatible: existing clients keep working via the `?token=` fallbacks.

### Security (coturn deployment)
- Documented + shipped a coturn lockdown: **`--denied-peer-ip`** for RFC1918 / loopback /
  link-local (incl. the `169.254.169.254` cloud-metadata address) / multicast / CGNAT +
  IPv6 ULA/link-local (closes the open-relay / SSRF hole), and coturn-native
  **`--unauthorized-ratelimit`** to throttle credential-guessing floods per source IP.

## [0.2.16] - 2026-07-14

### Fixed
- **Host no longer wedges into a permanently unreachable state after a network blip.**
  The rendezvous reconnect loop called `connect_async` with no timeout. On macOS a
  network interruption can leave the system resolver wedged, so the `getaddrinfo`
  inside that connect blocks *forever* without ever erroring — the loop hung on a
  single `.await`, and the existing "unreachable too long" watchdog (which only runs
  when a connect *returns a failure*) never fired. The host stayed alive but dark: no
  viewer could reach it, and only a manual restart cleared it. Each connect attempt is
  now bounded by a **15s timeout**, so a wedged resolver counts as a normal failure
  that feeds the watchdog, which then re-execs in place for a fresh resolver.
- **Dead half-open rendezvous sockets are now detected.** If the connection silently
  went away (peer/NAT dropped with no RST), the read side could block for minutes
  before the OS surfaced a write error. A **90s liveness deadline** — no inbound frame,
  not even a keepalive pong — now tears the socket down and reconnects promptly.

### Changed
- Web-viewer touch polish: three-finger scroll is **3× faster** (1:1 felt sluggish);
  the local cursor **re-orients immediately when the view is rotated** (previously it
  waited for the next mouse move); and a gesture that has ever had 3+ fingers no longer
  lurches the pinch-zoom during its transient two-finger phases.

### Documentation
- README gains a **Configuration** section documenting every host/viewer environment
  variable and its `rmdd set` settings-store key. Notably `RMD_BIND`: on a
  firewalled/public host, pin the transport UDP port and open it — a random ephemeral
  port is blocked, which forces ICE onto the (flaky) relay instead of a direct path.

## [0.2.15] - 2026-07-13

### Added
- **Daemon management built into `rmdd`.** `rmdd enable | disable | status | start |
  stop | restart | log [-f]` manage the host as a background service via the
  platform init system — **systemd `--user`** on Linux, a **launchd** agent on
  macOS — all per-user (no sudo). The generated unit runs bare `rmdd`, which reads
  its config from the encrypted settings store, so **no token is ever written into a
  unit file or plist**. `rmdd log` tails `journalctl --user -u rmd-host` (Linux) or
  the agent log (macOS). The installer gains an optional prompt (or `RMD_SERVICE=1`)
  that sets this up by delegating to `rmdd enable`.
- On Linux the generated unit captures the caller's `DISPLAY` (so `DISPLAY=:99 rmdd
  enable` targets a headless Xvfb), enables lingering (starts at boot, survives
  logout), and uses `Restart=always`.

### Changed
- **An unconfigured daemon no longer exits — it idles.** Previously a host missing
  its rendezvous URL / device token exited with an error, which **restart-looped**
  under a supervisor. It now logs the exact `rmdd set …` steps and parks (no busy
  loop) until the service is stopped, so enabling the service before configuring it
  is safe. (Dev LAN mode via `RMD_SIGNAL_ADDR` is unchanged.)

### Fixed
- **Reliable rapid cross-NAT reconnects.** The TURN relay was re-allocated on every
  session rebuild, but a second Allocate on the same socket 5-tuple is rejected by
  coturn (Allocation Mismatch) while the previous allocation lingers, dropping
  reconnects to relay-less (which fails on symmetric NAT). The relay is now allocated
  once for the socket's lifetime and re-advertised per session; reconnects also skip
  the ~4s Allocate handshake.
- **Lag-free cursor.** The host now drops the OS cursor from the captured video when
  the viewer advertises it renders its own (`FEATURE_CLIENT_CURSOR` in the Hello), so
  the pointer isn't subject to the encode → jitter-buffer → decode pipeline. The
  web-viewer draws a local pointer that tracks touch instantly and rotates with the
  video. (Client half already deployed to `/app`.)

## [0.2.14] - 2026-07-13

### Fixed
- **Host now allocates its own TURN relay candidate — reliable cross-NAT
  connections.** The sans-IO `rtc` fork has no TURN client, and the host's manual
  candidate gather only produced `host` + `srflx` candidates (it skipped `turn:`
  URLs, assuming "ICE handles it" — it doesn't). So a viewer behind symmetric NAT /
  CGNAT had no reachable path: the host's srflx mapping wouldn't accept the viewer
  relay's inbound and there was no host-side relay to fall back on, which showed up
  as the host being **available but every connect spinning forever** (worst on
  cellular). The host now drives an `rtc-turn` client on its transport socket:
  Allocate on coturn → advertise a `relay` candidate → transparently frame media to
  peers that need the relay (with coturn permissions), refreshing the allocation for
  the session. Additive and regression-safe: outbound stays direct by default and
  only routes through the relay for a peer once relayed data is actually received,
  so a working host/srflx path is untouched. A failed/absent allocation just runs
  relay-less as before.

## [0.2.13] - 2026-07-13

### Fixed
- **Host now answers the viewer's keyframe requests, so a lost frame recovers
  immediately instead of staying stale.** After packet loss the browser sends an
  RTCP Picture Loss Indication (PLI/FIR) asking for a fresh keyframe, but the host
  ignored all incoming RTCP — so when the *last* frame of a burst was lost and
  couldn't be repaired by NACK retransmission, the viewer showed a stale frame
  (out of sync with the real screen) until the next periodic keyframe (~2s later).
  The host now decodes PLI/FIR and forces an IDR right away. This is worst at the
  start of a session (loss is highest before congestion control converges), which
  matches the "dropped last update, smooths out over time" symptom. Requests
  coalesce through the existing swap-once keyframe flag, so sustained loss can't
  cause a keyframe storm.

## [0.2.12] - 2026-07-13

### Changed
- **DNS-wedge watchdog now self-recovers instead of just exiting.** When the host
  can't reach the rendezvous for 150s with no active session (the wedged-resolver
  case), it now **re-execs itself in place** (`exec`, same PID) to get a fresh DNS
  resolver, rather than `exit(1)` and relying on a launchd/systemd `KeepAlive`
  supervisor. So a host started **by hand** (e.g. a clamshell Mac) recovers on its
  own instead of going dark. Still supervisor-friendly — re-exec keeps the same PID,
  so it won't double-launch under `KeepAlive`. Falls back to `exit(1)` only if
  `exec` fails.

## [0.2.11] - 2026-07-11

### Fixed
- **Shift no longer leaks onto the key after a shifted one (macOS host).** The Mac
  input injector only set the `CGEvent` modifier flags when `modifiers != 0`; because
  a fresh `CGEvent` inherits the current modifier state, a shifted key (e.g. a
  one-shot Shift) left its Shift flag on the *next* key, which had `modifiers == 0`
  and therefore skipped `set_flags` entirely — so "Shift then a" then "b" produced
  "Ab" on the client but "AB" on the host. The injector now always writes the exact
  per-event flags (empty when there are no modifiers), so each key carries only its
  own modifiers. (Linux/X11 drives modifiers via separate key events and is
  unaffected here; making the web-viewer's bitmask work on X11 is a separate item.)

## [0.2.10] - 2026-07-11

Host resilience: recover from a wedged system DNS resolver.

### Fixed
- **Host no longer goes dark until manually restarted after a network blip.** On a
  long-running macOS host, a transient network event can permanently wedge the
  process's system DNS resolver (`getaddrinfo` returns "nodename nor servname" for
  hours, even though the network is fine and a fresh process resolves instantly), so
  the daemon stays alive but unreachable and no viewer can connect. The rendezvous
  client now runs a watchdog: if it can't reach the rendezvous for 150s **and no
  viewer session is active**, it exits so the supervisor (launchd/systemd
  `KeepAlive`) relaunches it with a clean resolver. A live peer-to-peer session is
  never torn down (the guard skips the restart while a session is active), and
  viewers never self-restart.

## [0.2.9] - 2026-07-10

Phone-control round 1: host-side pinch-zoom and drag-select for the browser viewer.

### Added
- **Pinch-to-zoom now magnifies the real desktop, host-side.** The browser no longer
  pinch-zooms its own (blurry) rendering of the video. Instead a two-finger pinch/pan
  sends the host a crop rectangle (`SetZoom`); `rmdd` crops that region of the captured
  screen and scales it back to full frame before encoding, so you get a crisp,
  re-encoded zoom of the actual screen. The host applies the *same* rectangle to remap
  pointer coordinates, so taps land accurately inside the zoomed region and cursor
  motion gets finer the more you zoom — built for hitting small targets on a big screen
  from a phone. Two fingers zoom (pinch) and pan (drag) together; pinch back out to
  return to the full screen. (Protocol MINOR 7; older hosts ignore `SetZoom`.)
- **Drag-select / drag-and-drop from touch.** A one-finger long-press (default) or
  double-tap-and-hold arms a left-button-down that's held through the drag and released
  on lift — so you can select text and drag on the remote desktop. The trigger is
  user-selectable from a new toolbar toggle (LP / 2T) and persists across sessions.

### Changed
- The browser viewer now captures **every** touch on the video (`touch-action:none`,
  non-zoomable viewport): all one/two/three-finger gestures are handled in-app rather
  than partly by the browser. Existing gestures are unchanged — one-finger tap/drag
  (left-click / move cursor), quick two-finger tap (right-click), three-finger swipe
  (scroll).

## [0.2.8] - 2026-07-10

Reconnect-stability release, plus browser-viewer polish.

### Fixed
- **Host no longer deadlocks on reconnect after idle.** When a backgrounded viewer's
  browser rebuilt its PeerConnection and re-announced, the rendezvous replayed the
  host's cached offer; the viewer answered, but the host's connection was already
  past `have-local-offer`, so it failed with `set remote answer: from stable
  applying false answer` and stalled forever. The host now rebuilds with a fresh
  offer (new ICE/DTLS credentials) on a post-negotiation answer — mirroring the
  viewer's existing second-offer path — so idle reconnects complete cleanly.
- **Browser viewer keeps video pinned to the live edge.** WebRTC playout latency no
  longer creeps up over a session (or after a background/resume): the receiver is
  asked to keep its buffer minimal, and a once-a-second monitor drains any
  accumulated jitter-buffer delay by briefly speeding playback — frames are never
  dropped, playback catches back up to live.
- **On-screen keyboard and video sit correctly in rotated views.** Both are kept
  below the fixed header and the keyboard is sized to the video's rendered width, so
  the keys no longer slide under the toolbar or off-centre.
- **Swipe typing surfaces rare-but-real words** (e.g. "pig"): the frequency prior was
  softened and the suggestion list widened so a clean gesture for an uncommon word
  isn't buried by common look-alikes.

## [0.2.7] - 2026-07-09

Mobile browser-viewer overhaul, and a fix for unbounded video latency.

### Added
- **Full on-screen keyboard in the browser viewer.** A rendered QWERTY + symbols
  layer with sticky modifiers (Ctrl/Alt/Super/Shift), Esc/Tab/arrows/Ctrl-Alt-Del,
  and per-key press feedback (click sound + haptic + flash). It **rotates with the
  view** (the OS keyboard can't) and follows the system light/dark theme.
- **Touch gestures (trackpad semantics) in the browser viewer.** A one-finger
  drag moves the cursor by a relative delta; a one-finger tap left-clicks in
  place; a quick two-finger tap right-clicks; a three-finger swipe scrolls; and a
  two-finger pinch zooms the view.
- **Auto-reconnect in the browser viewer.** A backgrounded phone that drops the
  media/socket now rebuilds the session on resume instead of freezing until
  refreshed.
- **`rmdd set fps|width|height|bitrate <v>`.** Video encode parameters are now
  stored settings (store → `RMD_*` env → default), tunable per host without
  environment variables.
- **`RMD_LANDING_FILE`.** The rendezvous serves the apex landing page from a
  bind-mounted file when set, so it can be updated without a rebuild (mirroring
  `RMD_WEBVIEWER_DIR` for `/app`).

### Fixed
- **Unbounded video latency ("minutes behind").** The host now drops stale
  captured frames and always encodes the freshest one (keep-latest on the
  capture→encode queue), so the remote and local screens stay in sync when the
  link or encoder can't keep up.
- Landing page: the RMD logo renders as a proper square (it was stretched into a
  rectangle), and the redundant header CTA is hidden on mobile.

## [0.2.6] - 2026-07-09

More platforms and a smoother host setup.

### Added
- **ARM builds — Raspberry Pi 4/5, Orange Pi 5B, Apple Silicon.** Every release
  now ships `macos-x86_64`, `macos-arm64`, `linux-x86_64`, and `linux-arm64`
  (the Linux arm64 build cross-compiles the full host + viewer + rendezvous).
- **`rmdd set rendezvous_url <wss://…>`.** The rendezvous URL is now a stored
  setting alongside `token` and `password`, so a bare `rmdd` connects with no
  environment variables. (`RMD_RENDEZVOUS_URL` still overrides.)

### Changed
- `install.sh` clears the macOS Gatekeeper quarantine flag on the (already
  minisign/SHA-verified) binaries automatically, instead of printing a warning.
- The web app hides "Create account" when the server has registration closed
  (it checks `GET /api/registration`).

### Fixed
- Cross-built Linux arm64 `.deb`s now package (skip host-`strip` on cross builds).

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
