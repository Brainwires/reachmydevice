# OpenReach — Architecture Decision Record

Each entry: decision, context, rationale, and consequences. Newest concerns first.

## ADR-0001 — Language & workspace: Rust, single cargo workspace

**Decision.** Host, viewer, and (later) rendezvous are Rust, in one workspace with shared crates
(`protocol`, `transport`, `capture`, `codec`, `input`, `session`).
**Rationale.** Native OS input injection, unattended background services, hardware-codec control, and
no browser sandbox — none achievable from a web runtime. Shared crates keep host/viewer wire-compatible.
**Consequences.** Heavy platform FFI (ScreenCaptureKit, VideoToolbox, CGEvent, later DXGI/X11). Accepted.

## ADR-0002 — Spike platform: macOS first (deviates from spec)

**Decision.** The Phase-1 de-risking spike targets macOS 13+ (ScreenCaptureKit + VideoToolbox + CGEvent),
not Linux/X11 as the spec's execution plan suggested.
**Context.** The spec de-risks on Linux/X11; the operator's available hardware is two+ Macs on a LAN.
**Rationale.** De-risk on hardware we can actually run and measure on. Linux/X11 and Windows move to Phase 3.
**Consequences.** More FFI/permission friction (TCC: Screen Recording + Accessibility) up front. Documented
in `docs/macos-permissions.md`.

## ADR-0003 — Transport: sans-IO `rtc` fork (`Brainwires/webrtc-rs-rtc`), not libwebrtc FFI

**Decision.** The `transport` crate builds on the **sans-IO** `webrtc-rs/rtc` fork maintained at
`Brainwires/webrtc-rs-rtc`, pinned as a git dependency. libwebrtc FFI is dropped.
**Context.** The spec named webrtc-rs media/adaptive-bitrate maturity as the #1 risk, with libwebrtc FFI
as the fallback. Investigation found two Brainwires forks carrying substantial self-owned work:
- `Brainwires/webrtc-rs-rtc` (sans-IO): **107 commits ahead** of upstream — GCC sender-side bandwidth
  estimator, JitterBuffer, DTLS-restart after ICE restart, TCP TURN, RTX/FEC routing, RTP bounds checks,
  SCTP/RTCP RFC compliance, datachannel fixes.
- `Brainwires/webrtc-rs` (async): 32 ahead — datachannel-video, mDNS, TCP-ICE, driver robustness.

None of the ~24 upstream PRs (`webrtc-rs/webrtc` #785–#798, `webrtc-rs/rtc` #76–#85) merged upstream, but
all changes are integrated into each fork's `master`.
**Rationale.** GCC (the hard "adaptive bitrate driven by congestion feedback" requirement) exists **only**
in the sans-IO fork. It also uniquely carries jitter buffering and DTLS-restart (reconnect-on-blip). Sans-IO
is the more complete and more deterministically testable of the two (serves the CI integration-test
requirement). The transport risk the spec flagged is therefore largely retired by reuse.
**Consequences.** The `transport` crate owns the UDP-socket + timer **driver loop** (sans-IO does no I/O).
mDNS (LAN discovery, Phase 3) will be ported from the async fork into our I/O layer. *Contingency:* if the
sans-IO driver loop blocks the Phase-1 timeline, fall back to the async fork for the spike and revisit GCC
before Phase 2.

## ADR-0004 — Wire format: Protobuf via `prost`

**Decision.** Control/data-channel messages use Protobuf (`prost`), with a `ProtocolVersion` handshake as
the first message.
**Rationale.** Best schema-evolution/versioning story ("versioned from day one" — a v1 viewer must cleanly
reject an incompatible host via field-number-stable evolution). Cross-language, enabling a future web-viewer
extension point without reformatting the wire.
**Consequences.** A `build.rs` + `.proto` toolchain (`protoc` available in dev/CI). Accepted.

## ADR-0005 — macOS bindings: the `objc2-*` framework crates

**Decision.** Use the `objc2-*` framework crates (`objc2-screen-capture-kit`, `objc2-video-toolbox`,
`objc2-core-media`, `objc2-core-video`, `objc2-foundation`) as the primary FFI layer.
**Rationale.** Actively maintained, idiomatic, single consistent objc runtime.
**Consequences.** Fallbacks if binding friction is high: `cidre` (ergonomic VT+SCK) or the `screencapturekit`
crate. Validating compile-and-capture is the first spike task. *(Revisit if the primary proves impractical.)*
**Update (capture built).** The `screencapturekit` convenience crate was tried first and **abandoned**: it
has a *mandatory* (non-optional) `apple-metal` dependency whose build.rs runs a Swift bridge build that is
broken against the current SDK (`MTLSamplerReductionMode` unresolved), and a mandatory Swift/Metal build
chain is a CI/portability liability regardless. The capture backend is now the objc2 family as decided here:
a custom `SCStreamOutput`/`SCStreamDelegate` via `define_class!`, `SCShareableContent`'s async fetch bridged
to a channel, and CVPixelBuffer lock→copy→unlock. SCK's objc2 features gate by *module* (`SCStream`,
`SCShareableContent`), not per class. See `crates/capture/src/mac.rs`.

## ADR-0007 — Codec: software H.264 (openh264) first, VideoToolbox next

**Decision.** The `codec` crate defines `Encoder`/`Decoder` traits and ships a **software H.264**
backend (`openh264`, which builds from source — no system lib) for the Phase-1 pipeline, with
`yuvutils-rs` for BGRA↔I420 conversion. A **VideoToolbox hardware** backend is the immediate next
increment behind the same traits.
**Context.** ADR-0005 targets VideoToolbox. The Phase-1 *goal*, though, is to prove the end-to-end
pipeline (capture→encode→transport→decode→display) and measure latency; hardware encode is an
optimization on top. The spec explicitly permits a software fallback (x264/openh264).
**Rationale.** Software-first is the lower-risk sequencing: it removes heavy VideoToolbox FFI from the
critical path to a *working* demo, and openh264 encode/decode is portable (also serves Linux/Windows in
Phase 3). Once the pipeline is proven and measured, the VideoToolbox backend swaps in behind the trait
to hit the 1080p30/<8 Mbps hardware target.
**Consequences.** Higher CPU during the spike; a per-frame BGRA→I420 conversion. Both acceptable at
720p/1080p30 for de-risking. VideoToolbox remains the macOS production target (tracked, not dropped).

## ADR-0006 — Reference-only asset: the browser `webrtc` demo

**Decision.** The existing `~/Source/Brainwires/webrtc` (React `getDisplayMedia` client + 14-line Node `ws`
broadcast server) is **reference-only** — no code carries forward.
**Rationale.** A browser cannot inject OS input, run unattended, drive hardware encoders, or capture the
secure desktop. Kept for its signaling message shapes (offer/answer/candidate) and as a network smoke test.
**Consequences.** Rendezvous is built fresh in Rust/axum; viewer is native Rust (winit/wgpu). Not web/Electron.
