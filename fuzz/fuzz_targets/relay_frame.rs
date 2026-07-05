//! Fuzz the rendezvous WebSocket frame parser — attacker-controlled JSON on the
//! signaling socket. Must never panic on arbitrary UTF-8.
#![no_main]
use libfuzzer_sys::fuzz_target;
use rmd_rendezvous::signaling::RelayFrame;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = serde_json::from_str::<RelayFrame>(s);
    }
});
