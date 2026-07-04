# OpenReach — Validation Log

Evidence that the system works end-to-end, on real hardware and across the real
internet. Automated tests run in CI; the on-fleet runs below were executed
manually against the deployed rendezvous.

## Automated (CI — macOS + Linux)
| Test | What it proves |
|------|----------------|
| `openreach-protocol` unit tests | versioned wire format, handshake accept/reject, v1 messages |
| `openreach-codec` roundtrip | real openh264 encode → decode |
| `openreach-transport` `loopback_connect_video_and_data` | ICE + DTLS-SRTP connect, H.264 RTP, bidirectional data channel |
| `openreach-transport` `relay_only_sees_ciphertext` | an interposed relay carries traffic but a plaintext canary never appears in it (E2EE) |
| `openreach-transport` srflx (ignored, network) | STUN binding discovers a real public reflexive address |
| `openreach-session` `pipeline` | real encode → transport → real decode, headless |
| `openreach-session` `rendezvous_e2e` | two peers connect through the **real rendezvous server** (in-process) over WebSockets |
| Linux CI (Xvfb) | X11 `capture_smoke` + XTest `input_smoke` on a headless X server |

## On-fleet (real hardware)

### macOS full pipeline (this Mac)
ScreenCaptureKit capture → openh264 → transport → decode. See the Phase 1 report.

### Linux full pipeline (`biscuits`, Ubuntu 24.04, x86_64)
Real X11 capture (Xvfb) → host → transport → headless viewer decode, loopback:
**589 frames @ 1280×720 (~29 fps), first frame 2.34 s.** X11 capture: 60 frames
@ ~30 fps; XTest input: injected pointer landed exactly at screen centre.

### Cross-NAT session (the headline result)
`biscuits` (cloud, public IP behind a stateful firewall) as **host** ↔ this Mac
(home NAT) as **viewer**, signaling via the **deployed rendezvous**
`wss://openreach.brainwires.dev/ws` (behind a Cloudflare tunnel), media traversing
NAT via **STUN server-reflexive candidates + hole-punching**, DTLS-SRTP encrypted:

```
Mac viewer:   connected=true  frames=1290  1280×720  first_frame=1.89s   (~30 fps / 45 s)
biscuits host: ★ REMOTE SESSION ACTIVE ★
```

This exercises the entire thesis: **screen capture → hardware/software H.264 →
NAT-traversed, end-to-end-encrypted WebRTC → decode**, with a self-hosted
rendezvous and no third-party cloud in the media path.

### Rendezvous deployment
`openreach-rendezvous` runs in Docker on `biscuits` behind the existing Cloudflare
tunnel; the web console + REST API + WebSocket signaling are all reachable at
`https://openreach.brainwires.dev` and verified: `/health` 200, account
register → device token, `GET /api/devices`, and a real WebSocket relay
(`A → server → B`) through the tunnel.

## Not yet measured / open
- **Glass-to-glass latency** (needs a physical display + camera, or the in-UI
  Ping/Pong RTT the viewer HUD will add). Connection setup was ~1.9 s; steady-state
  frame rate ~30 fps at 1280×720.
- **TURN relay fallback** on the fleet (P2P/STUN succeeded, so TURN wasn't exercised;
  coturn is present on `biscuits`).
- 1080p30 bitrate/CPU under the VideoToolbox hardware encoder (software path used so far).
