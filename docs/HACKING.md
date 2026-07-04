# HACKING — OpenReach developer guide

## Prerequisites
- Rust (pinned in `rust-toolchain.toml`), `protoc` (Protobuf compiler) for the `protocol` crate.
- macOS 13+ for the spike. Grant **Screen Recording** + **Accessibility** (see `macos-permissions.md`).

## Clone (submodule required)
The WebRTC transport (`rtc` fork) is vendored as a **git submodule** at
`third_party/webrtc-rs-rtc`, so the build needs it checked out:
```sh
git clone --recurse-submodules <repo>
# already cloned without it?
git submodule update --init --recursive
```
Builds are then offline/reproducible — no crates.io/git fetch for the transport.

## Layout
- `crates/` — shared libraries (`protocol`, `transport`, `capture`, `codec`, `input`, `session`).
- `apps/` — binaries: `host`, `viewer`, `signal-dev`.
- `docs/` — architecture, decisions (ADRs), permissions, threat model, deployment.

## Common commands
```sh
cargo build                       # build everything
cargo test -p openreach-protocol  # test one crate
cargo clippy --all-targets --all-features
cargo fmt --all
# Fuzzing (needs nightly + `cargo install cargo-fuzz`):
cd fuzz && cargo +nightly fuzz run protocol_decode   # or filexfer_handle / relay_frame
RUST_LOG=debug cargo run -p openreach-host    # run host with debug logs
```

## Transport (sans-IO rtc fork)
`crates/transport` is built on `Brainwires/webrtc-rs-rtc` (sans-IO). The crate owns the UDP + timer
driver loop that pumps the state machine. See `docs/decisions.md` ADR-0003. Reference examples live in
the fork under `examples/examples/` (notably `play-from-disk-h26x`, `data-channels-offer-answer`).

## Spike run (two LAN machines)
1. On both machines: `cargo build --release`.
2. Start `signal-dev` on one machine (rendezvous stand-in).
3. Start `openreach-host` on machine A; `openreach-viewer` on machine B; they exchange SDP/ICE via signal-dev.
4. Grant macOS permissions when prompted. Confirm live screen + remote control; read latency logs.

## Logging & debug bundles
Structured logging via `tracing`. `RUST_LOG` controls verbosity. Debug-bundle export: Phase 5.
