//! OpenReach wire protocol.
//!
//! A single versioned [`pb::Envelope`] is the unit on the control/data channel.
//! The wire format is Protobuf (via `prost`); see `proto/openreach.proto` and
//! `docs/decisions.md` ADR-0004 for why.
//!
//! ## Versioning contract
//! Every [`pb::Envelope`] carries the sender's protocol version. Two peers are
//! compatible iff their **major** versions match; a mismatch must be rejected
//! (a v1 viewer cleanly refuses an incompatible host). Use
//! [`check_compatibility`] on the first [`pb::Hello`] received.

use prost::Message;

/// Generated Protobuf types (`package openreach.v1`).
pub mod pb {
    include!(concat!(env!("OUT_DIR"), "/openreach.v1.rs"));
}

pub use pb::{
    envelope, input_event, Bye, Envelope, Hello, HelloAck, InputEvent, KeyEvent, MouseButton,
    MouseMove, MouseScroll, Ping, Pong, Role,
};

/// Protocol major version. **Incompatible across mismatches** — bump only on a
/// breaking wire change.
pub const PROTOCOL_MAJOR: u32 = 1;
/// Protocol minor version. Backward-compatible additions bump this.
pub const PROTOCOL_MINOR: u32 = 0;

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

// --- Convenience constructors ---------------------------------------------

/// A `Hello` envelope announcing our identity/role.
pub fn hello(device_name: impl Into<String>, role: Role, features: u64) -> Envelope {
    envelope(pb::envelope::Payload::Hello(Hello {
        device_name: device_name.into(),
        role: role as i32,
        features,
    }))
}

/// An accepting `HelloAck`.
pub fn hello_ack_ok(device_name: impl Into<String>, features: u64) -> Envelope {
    envelope(pb::envelope::Payload::HelloAck(HelloAck {
        accepted: true,
        reason: String::new(),
        device_name: device_name.into(),
        features,
    }))
}

/// A rejecting `HelloAck` carrying the reason (e.g. version mismatch).
pub fn hello_ack_reject(reason: impl Into<String>) -> Envelope {
    envelope(pb::envelope::Payload::HelloAck(HelloAck {
        accepted: false,
        reason: reason.into(),
        device_name: String::new(),
        features: 0,
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

/// Microseconds since a process-global monotonic epoch.
///
/// All OpenReach crates call this one function so that timestamps produced in
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
    fn ping_pong_preserves_timestamp() {
        let t = 1_234_567_890u64;
        let decoded = decode(&encode(&ping(t))).unwrap();
        match decoded.payload.unwrap() {
            pb::envelope::Payload::Ping(p) => assert_eq!(p.t_micros, t),
            other => panic!("wrong payload: {other:?}"),
        }
    }
}
