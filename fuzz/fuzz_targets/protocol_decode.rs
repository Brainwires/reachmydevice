//! Fuzz the protobuf `Envelope` decoder — the single entry point for every
//! message received from an untrusted peer over the data channel. Must never
//! panic on arbitrary bytes; malformed input should return `Err`.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = openreach_protocol::decode(data);
});
