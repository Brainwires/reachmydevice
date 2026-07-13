//! ReachMyDevice wire protocol.
//!
//! A single versioned [`pb::Envelope`] is the unit on the control/data channel.
//! The wire format is Protobuf (via `prost`); see `proto/rmd.proto` and
//! `docs/decisions.md` ADR-0004 for why.
//!
//! ## Versioning contract
//! Every [`pb::Envelope`] carries the sender's protocol version. Two peers are
//! compatible iff their **major** versions match; a mismatch must be rejected
//! (a v1 viewer cleanly refuses an incompatible host). Use
//! [`check_compatibility`] on the first [`pb::Hello`] received.

use prost::Message;

/// Generated Protobuf types (`package rmd.v1`).
pub mod pb {
    include!(concat!(env!("OUT_DIR"), "/rmd.v1.rs"));
}

pub use pb::{
    envelope, input_event, AudioFrame, Bye, ClipboardKind, ClipboardUpdate, DisplayDescriptor,
    DisplayList, Envelope, FileAck, FileCancel, FileChunk, FileComplete, FileOffer, Hello,
    HelloAck, InputEvent, KeyEvent, MouseButton, MouseMove, MouseScroll, Ping, Pong,
    RequestKeyframe, Role, SelectDisplay, SetZoom, VideoCodec, ViewOnly,
};

/// Protocol major version. **Incompatible across mismatches** — bump only on a
/// breaking wire change.
pub const PROTOCOL_MAJOR: u32 = 1;
/// Protocol minor version. Backward-compatible additions bump this.
/// MINOR 1 added clipboard/file-transfer/multi-monitor/session-control messages;
/// MINOR 2 added the Opus `AudioFrame`;
/// MINOR 3 replaced `FileComplete.sha256_prefix` (64-bit) with a full `sha256`;
/// MINOR 4 added the host identity proof to `HelloAck` (first-connect MITM);
/// MINOR 5 added video-codec negotiation (`Hello.supported_video_codecs`,
///   `HelloAck.video_codec`) for the AV1 (browser) / H.264 split;
/// MINOR 6 added the connection password (`Hello.password`,
///   `HelloAck.password_required`);
/// MINOR 7 added digital zoom (`SetZoom`: viewer-driven crop rect the host
///   magnifies and remaps pointer coords through).
pub const PROTOCOL_MINOR: u32 = 7;

/// Errors from encoding/decoding or handshake validation.
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("failed to decode message: {0}")]
    Decode(#[from] prost::DecodeError),

    #[error("incompatible protocol major: local={local} remote={remote}")]
    IncompatibleMajor { local: u32, remote: u32 },

    #[error("envelope had no payload")]
    EmptyEnvelope,
}

/// Keyboard modifier bitmask carried in [`pb::KeyEvent::modifiers`].
///
/// Platform-neutral bits; each input backend maps to/from native flags.
pub mod modifiers {
    pub const SHIFT: u32 = 1 << 0;
    pub const CONTROL: u32 = 1 << 1;
    pub const ALT: u32 = 1 << 2; // Option on macOS
    pub const META: u32 = 1 << 3; // Command on macOS, Super on Linux, Win key on Windows
    pub const CAPS_LOCK: u32 = 1 << 4;
}

/// Build an [`Envelope`] stamped with this build's protocol version.
pub fn envelope(payload: pb::envelope::Payload) -> Envelope {
    Envelope {
        protocol_major: PROTOCOL_MAJOR,
        protocol_minor: PROTOCOL_MINOR,
        payload: Some(payload),
    }
}

/// Encode an [`Envelope`] to bytes for a single data-channel message.
pub fn encode(env: &Envelope) -> Vec<u8> {
    env.encode_to_vec()
}

/// Decode a single data-channel message into an [`Envelope`].
pub fn decode(bytes: &[u8]) -> Result<Envelope, ProtocolError> {
    Ok(Envelope::decode(bytes)?)
}

/// Validate a peer's advertised major version against ours.
///
/// Returns `Ok(())` when compatible, or [`ProtocolError::IncompatibleMajor`]
/// otherwise — the caller should answer with a rejecting [`HelloAck`] and close.
pub fn check_compatibility(remote_major: u32) -> Result<(), ProtocolError> {
    if remote_major == PROTOCOL_MAJOR {
        Ok(())
    } else {
        Err(ProtocolError::IncompatibleMajor {
            local: PROTOCOL_MAJOR,
            remote: remote_major,
        })
    }
}

// --- Hello feature bits (the `Hello.features` bitmask) --------------------

/// The viewer renders its own mouse cursor locally (from the position it commands),
/// so the host should NOT bake the OS cursor into the captured video. This removes
/// the cursor from the encode→jitter-buffer→decode pipeline, so the pointer tracks
/// the user's finger/mouse with zero perceived lag. A host that predates this bit
/// just keeps drawing the cursor into the frame (harmless — the viewer then shows
/// both, but old behavior is unchanged).
pub const FEATURE_CLIENT_CURSOR: u64 = 1 << 0;

// --- Convenience constructors ---------------------------------------------

/// The decodable-codec list a native peer advertises. Native endpoints decode
/// H.264 only (AV1 is browser-decode-only); the browser viewer builds its own
/// `Hello` with `[AV1, H264]`.
fn native_supported_codecs() -> Vec<i32> {
    vec![VideoCodec::H264 as i32]
}

/// A `Hello` envelope announcing our identity/role (no access proof).
pub fn hello(device_name: impl Into<String>, role: Role, features: u64) -> Envelope {
    envelope(pb::envelope::Payload::Hello(Hello {
        device_name: device_name.into(),
        role: role as i32,
        features,
        public_key: Vec::new(),
        signature: Vec::new(),
        supported_video_codecs: native_supported_codecs(),
        password: String::new(),
    }))
}

/// A `Hello` carrying an unattended-access proof (`public_key` + `signature`
/// over the access-proof message). Used when the viewer has a device identity
/// and the host may require authorization.
pub fn hello_authenticated(
    device_name: impl Into<String>,
    role: Role,
    features: u64,
    public_key: Vec<u8>,
    signature: Vec<u8>,
) -> Envelope {
    envelope(pb::envelope::Payload::Hello(Hello {
        device_name: device_name.into(),
        role: role as i32,
        features,
        public_key,
        signature,
        supported_video_codecs: native_supported_codecs(),
        password: String::new(),
    }))
}

/// Attach a connection `password` to a `Hello` envelope (no-op on other
/// payloads). The viewer builds its normal Hello, then wraps it with this on the
/// re-send after the host asks for a password.
pub fn with_password(mut env: Envelope, password: impl Into<String>) -> Envelope {
    if let Some(pb::envelope::Payload::Hello(h)) = env.payload.as_mut() {
        h.password = password.into();
    }
    env
}

/// An accepting `HelloAck` (no host identity proof — LAN/dev). `video_codec` is
/// the codec the host is sending on the RTP track.
pub fn hello_ack_ok(
    device_name: impl Into<String>,
    features: u64,
    video_codec: VideoCodec,
) -> Envelope {
    envelope(pb::envelope::Payload::HelloAck(HelloAck {
        accepted: true,
        reason: String::new(),
        device_name: device_name.into(),
        features,
        host_public_key: Vec::new(),
        host_proof: Vec::new(),
        video_codec: video_codec as i32,
        password_required: false,
    }))
}

/// An accepting `HelloAck` carrying the host's identity proof bound to this
/// session's DTLS fingerprint, so the viewer can authenticate the real endpoint.
pub fn hello_ack_ok_signed(
    device_name: impl Into<String>,
    features: u64,
    host_public_key: Vec<u8>,
    host_proof: Vec<u8>,
    video_codec: VideoCodec,
) -> Envelope {
    envelope(pb::envelope::Payload::HelloAck(HelloAck {
        accepted: true,
        reason: String::new(),
        device_name: device_name.into(),
        features,
        host_public_key,
        host_proof,
        video_codec: video_codec as i32,
        password_required: false,
    }))
}

/// A rejecting `HelloAck` carrying the reason (e.g. version mismatch).
pub fn hello_ack_reject(reason: impl Into<String>) -> Envelope {
    envelope(pb::envelope::Payload::HelloAck(HelloAck {
        accepted: false,
        reason: reason.into(),
        device_name: String::new(),
        features: 0,
        host_public_key: Vec::new(),
        host_proof: Vec::new(),
        video_codec: VideoCodec::Unspecified as i32,
        password_required: false,
    }))
}

/// A rejecting `HelloAck` that specifically signals a connection password is
/// required (or the supplied one was wrong), so the viewer prompts and retries.
pub fn hello_ack_password_required(reason: impl Into<String>) -> Envelope {
    envelope(pb::envelope::Payload::HelloAck(HelloAck {
        accepted: false,
        reason: reason.into(),
        device_name: String::new(),
        features: 0,
        host_public_key: Vec::new(),
        host_proof: Vec::new(),
        video_codec: VideoCodec::Unspecified as i32,
        password_required: true,
    }))
}

/// Wrap an [`InputEvent`] in an envelope.
pub fn input(event: input_event::Event) -> Envelope {
    envelope(pb::envelope::Payload::Input(InputEvent {
        event: Some(event),
    }))
}

/// A `Ping` stamped with a monotonic microsecond timestamp.
pub fn ping(t_micros: u64) -> Envelope {
    envelope(pb::envelope::Payload::Ping(Ping { t_micros }))
}

/// A `Pong` echoing a ping's timestamp.
pub fn pong(t_micros: u64) -> Envelope {
    envelope(pb::envelope::Payload::Pong(Pong { t_micros }))
}

/// A text clipboard update (loop-guarded by `seq`/`origin_hash`).
pub fn clipboard_text(text: impl Into<String>, seq: u64) -> Envelope {
    let data = text.into().into_bytes();
    let origin_hash = fnv1a(&data);
    envelope(pb::envelope::Payload::Clipboard(ClipboardUpdate {
        kind: ClipboardKind::Text as i32,
        data,
        seq,
        origin_hash,
    }))
}

/// Announce a file transfer. The receiver replies with [`file_ack`] at the
/// offset to start from (0 for a fresh transfer, `>0` to resume a partial one).
pub fn file_offer(
    transfer_id: impl Into<String>,
    name: impl Into<String>,
    size: u64,
    mime: impl Into<String>,
) -> Envelope {
    envelope(pb::envelope::Payload::FileOffer(FileOffer {
        transfer_id: transfer_id.into(),
        name: name.into(),
        size,
        mime: mime.into(),
    }))
}

/// A chunk of file data at `offset` within the transfer.
pub fn file_chunk(transfer_id: impl Into<String>, offset: u64, data: Vec<u8>) -> Envelope {
    envelope(pb::envelope::Payload::FileChunk(FileChunk {
        transfer_id: transfer_id.into(),
        offset,
        data,
    }))
}

/// Flow-control / resume ack: "I have up to `offset` bytes; send from there."
pub fn file_ack(transfer_id: impl Into<String>, offset: u64) -> Envelope {
    envelope(pb::envelope::Payload::FileAck(FileAck {
        transfer_id: transfer_id.into(),
        offset,
    }))
}

/// Signal that all bytes have been sent, carrying the **full** 32-byte SHA-256
/// of the file for a collision-resistant integrity check.
pub fn file_complete(transfer_id: impl Into<String>, sha256: [u8; 32]) -> Envelope {
    envelope(pb::envelope::Payload::FileComplete(FileComplete {
        transfer_id: transfer_id.into(),
        sha256: sha256.to_vec(),
    }))
}

/// Abort a transfer.
pub fn file_cancel(transfer_id: impl Into<String>, reason: impl Into<String>) -> Envelope {
    envelope(pb::envelope::Payload::FileCancel(FileCancel {
        transfer_id: transfer_id.into(),
        reason: reason.into(),
    }))
}

/// Request an IDR/keyframe from the host.
pub fn request_keyframe() -> Envelope {
    envelope(pb::envelope::Payload::RequestKeyframe(RequestKeyframe {}))
}

/// Toggle view-only on the host (input suppressed while enabled).
pub fn view_only(enabled: bool) -> Envelope {
    envelope(pb::envelope::Payload::ViewOnly(ViewOnly { enabled }))
}

/// Host → viewer: one Opus audio packet (48 kHz mono, 20 ms).
pub fn audio_frame(opus: Vec<u8>, seq: u64) -> Envelope {
    envelope(pb::envelope::Payload::Audio(AudioFrame { opus, seq }))
}

/// Host → viewer: advertise the available displays.
pub fn display_list(displays: Vec<DisplayDescriptor>) -> Envelope {
    envelope(pb::envelope::Payload::DisplayList(DisplayList { displays }))
}

/// Ask the host to switch the captured display.
pub fn select_display(id: u32) -> Envelope {
    envelope(pb::envelope::Payload::SelectDisplay(SelectDisplay { id }))
}

/// Viewer → host: set the digital-zoom crop rect (normalized [0,1]). The host
/// crops+scales the screen to this rect and remaps pointer coords through it.
/// `{0,0,1,1}` is the identity (no zoom).
pub fn set_zoom(x: f64, y: f64, w: f64, h: f64) -> Envelope {
    envelope(pb::envelope::Payload::SetZoom(SetZoom { x, y, w, h }))
}

/// 64-bit FNV-1a hash — a cheap content fingerprint for the clipboard loop guard.
pub fn fnv1a(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// Microseconds since a process-global monotonic epoch.
///
/// All ReachMyDevice crates call this one function so that timestamps produced in
/// different crates within the **same process** share an epoch and are directly
/// comparable (e.g. capture→encode→send stage latency on the host). It is *not*
/// comparable across processes or machines — cross-process latency is measured
/// via data-channel Ping/Pong RTT or externally (see the Phase 1 report).
pub fn monotonic_micros() -> u64 {
    use std::sync::OnceLock;
    use std::time::Instant;
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    let epoch = EPOCH.get_or_init(Instant::now);
    epoch.elapsed().as_micros() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_hello() {
        let env = hello("mac-mini", Role::Host, 0);
        let bytes = encode(&env);
        let decoded = decode(&bytes).unwrap();
        assert_eq!(decoded.protocol_major, PROTOCOL_MAJOR);
        match decoded.payload.unwrap() {
            pb::envelope::Payload::Hello(h) => {
                assert_eq!(h.device_name, "mac-mini");
                assert_eq!(h.role, Role::Host as i32);
            }
            other => panic!("wrong payload: {other:?}"),
        }
    }

    #[test]
    fn connection_password_round_trips() {
        // with_password attaches the password; empty until set.
        let plain = hello("web-viewer", Role::Viewer, 0);
        match plain.payload.clone().unwrap() {
            pb::envelope::Payload::Hello(h) => assert!(h.password.is_empty()),
            _ => unreachable!(),
        }
        let env = decode(&encode(&with_password(plain, "taco"))).unwrap();
        match env.payload.unwrap() {
            pb::envelope::Payload::Hello(h) => assert_eq!(h.password, "taco"),
            other => panic!("wrong payload: {other:?}"),
        }

        // hello_ack_password_required sets the distinguishing flag; reject doesn't.
        let req = decode(&encode(&hello_ack_password_required("need password"))).unwrap();
        match req.payload.unwrap() {
            pb::envelope::Payload::HelloAck(a) => assert!(a.password_required && !a.accepted),
            other => panic!("wrong payload: {other:?}"),
        }
        let rej = decode(&encode(&hello_ack_reject("bad version"))).unwrap();
        match rej.payload.unwrap() {
            pb::envelope::Payload::HelloAck(a) => assert!(!a.password_required),
            other => panic!("wrong payload: {other:?}"),
        }
    }

    #[test]
    fn roundtrip_input_mouse_move() {
        let env = input(input_event::Event::MouseMove(MouseMove { x: 0.5, y: 0.25 }));
        let decoded = decode(&encode(&env)).unwrap();
        match decoded.payload.unwrap() {
            pb::envelope::Payload::Input(ie) => match ie.event.unwrap() {
                input_event::Event::MouseMove(m) => {
                    assert!((m.x - 0.5).abs() < f64::EPSILON);
                    assert!((m.y - 0.25).abs() < f64::EPSILON);
                }
                other => panic!("wrong input event: {other:?}"),
            },
            other => panic!("wrong payload: {other:?}"),
        }
    }

    #[test]
    fn same_major_is_compatible() {
        assert!(check_compatibility(PROTOCOL_MAJOR).is_ok());
    }

    #[test]
    fn different_major_is_rejected() {
        let err = check_compatibility(PROTOCOL_MAJOR + 1).unwrap_err();
        assert!(matches!(err, ProtocolError::IncompatibleMajor { .. }));
    }

    #[test]
    fn decoding_garbage_errors_not_panics() {
        // A malformed byte string should surface a decode error, never panic.
        let res = decode(&[0xff, 0xff, 0xff, 0xff, 0x7f]);
        assert!(res.is_err());
    }

    #[test]
    fn clipboard_roundtrip_and_loop_guard() {
        let env = clipboard_text("hello world", 7);
        let decoded = decode(&encode(&env)).unwrap();
        match decoded.payload.unwrap() {
            pb::envelope::Payload::Clipboard(c) => {
                assert_eq!(c.kind, ClipboardKind::Text as i32);
                assert_eq!(c.data, b"hello world");
                assert_eq!(c.seq, 7);
                // origin_hash is the content fingerprint used to break sync loops.
                assert_eq!(c.origin_hash, fnv1a(b"hello world"));
            }
            other => panic!("wrong payload: {other:?}"),
        }
    }

    #[test]
    fn v1_control_messages_roundtrip() {
        assert!(matches!(
            decode(&encode(&request_keyframe()))
                .unwrap()
                .payload
                .unwrap(),
            pb::envelope::Payload::RequestKeyframe(_)
        ));
        assert!(matches!(
            decode(&encode(&select_display(2))).unwrap().payload.unwrap(),
            pb::envelope::Payload::SelectDisplay(d) if d.id == 2
        ));
        assert!(matches!(
            decode(&encode(&view_only(true))).unwrap().payload.unwrap(),
            pb::envelope::Payload::ViewOnly(v) if v.enabled
        ));
    }

    #[test]
    fn ping_pong_preserves_timestamp() {
        let t = 1_234_567_890u64;
        let decoded = decode(&encode(&ping(t))).unwrap();
        match decoded.payload.unwrap() {
            pb::envelope::Payload::Ping(p) => assert_eq!(p.t_micros, t),
            other => panic!("wrong payload: {other:?}"),
        }
    }
}
