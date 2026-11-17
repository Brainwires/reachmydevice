# Interop: ReachMyDevice host ↔ a Deno WebRTC viewer

A headless, loopback-only check that ReachMyDevice's host stack and an independent WebRTC
implementation talk to each other: the host side is what `rmdd` puts on the wire, and the viewer is
a small Deno program on the `RTCPeerConnection` of the Brainwires Deno fork (`ext/webrtc`).

Both ends sit on the same engine fork,
[Brainwires/webrtc-rs-rtc](https://github.com/Brainwires/webrtc-rs-rtc), but share nothing above it:
Deno has its own peer, ICE, socket and timer layer, the W3C API, and its own data channel, RTP and
SCTP handling around the engine, so this catches what the in-process
`crates/transport/tests/loopback.rs` (rmd-transport on both ends) cannot.

## What runs

| Side   | Code                                   | What it is                                                                                                                                                                                                         |
| ------ | -------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| host   | `crates/session/tests/interop_deno.rs` | rmd-transport's Host role (offer, H.264 send track, `control` data channel, GCC + TWCC), rmd-protocol `Envelope`s, real openh264 encode of synthetic BGRA frames (320x240). No screen capture, no input injection. |
| viewer | `examples/interop-deno/viewer.ts`      | Deno `RTCPeerConnection` bound to 127.0.0.1 (`Deno.webrtc.createNetwork({ bindAddresses: ["127.0.0.1"] })`), the received track read with `Deno.webrtc.readRtp`.                                                   |

Signaling is rmd-transport's `SignalMsg` JSON lines (`{"type":"offer","data":…}`) over the Deno
process's stdin and stdout; its log goes to stderr.

## What it asserts

1. **ICE and DTLS connect**: the host's `TransportEvent::Connected` and the viewer's
   `connectionState === "connected"`.
2. **The data channel carries rmd-protocol both ways**: the viewer's `Hello` (role viewer, H.264)
   gets an accepting `HelloAck` (video codec H.264); the host's `Ping` gets the viewer's `Pong`, and
   the viewer's `Ping` gets the host's `Pong`, each echoing `t_micros`. The viewer encodes and
   decodes the protobuf `Envelope` by hand, so the framing is checked independently of prost.
3. **H.264 RTP depacketizes into decodable access units**: the viewer depacketizes RTP (RFC 6184
   single NAL unit, STAP-A, FU-A) into Annex-B access units, requires the first keyframe to carry
   SPS + PPS + IDR, and parses the SPS to the expected 320x240. It forwards the access units from
   that keyframe on to the host side, which decodes them with openh264 and checks the size.
4. **A keyframe request reaches the host**: after the first keyframe the viewer sends an RTCP PLI
   (`Deno.webrtc.requestKeyFrame`), as a browser does after a loss, and the host must surface it as
   `TransportEvent::KeyframeRequested` (the path that forces an IDR to recover frozen video).
5. **A clean close on both sides**: the viewer sends `Bye`, closes the data channel (the `Bye` must
   reach the host before the channel closes), waits for the channel's `close` event, closes the
   connection and exits 0; the host sees the session end (`TransportEvent::Disconnected`) and its
   driver thread joins. The host notices the end through ICE (about 5 s): a peer's DTLS
   `close_notify` does not change the W3C connection state.

## Run it

You need a Deno build with `ext/webrtc` (the Brainwires fork, `train/denext26` or later):

```sh
RMD_INTEROP_DENO=/path/to/deno \
  cargo test -p rmd-session --test interop_deno -- --ignored --nocapture
```

The test is `#[ignore]`d so CI without that Deno skips it. Nothing binds beyond 127.0.0.1 and
nothing needs OS permissions: the Deno side runs with `--allow-net=127.0.0.1 --allow-env` only.

`RMD_INTEROP_TIMEOUT_MS` (default 30000) bounds the viewer; the host gives up after 40 s.
