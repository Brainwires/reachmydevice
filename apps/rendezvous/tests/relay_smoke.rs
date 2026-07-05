//! Stable companion to the `relay_frame` cargo-fuzz target: feed random JSON to
//! the signaling frame parser and assert it never panics.

use rmd_rendezvous::signaling::RelayFrame;

fn xorshift(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

#[test]
fn relay_frame_parse_never_panics() {
    let seeds = [
        "{}",
        r#"{"to":"x"}"#,
        r#"{"to":"x","payload":{}}"#,
        r#"{"to":123,"payload":[1,2,3]}"#,
        "not json",
        "[]",
        "null",
        &"a".repeat(10_000),
    ];
    for s in seeds {
        let _ = serde_json::from_str::<RelayFrame>(s);
    }

    // Random near-JSON byte soup.
    let mut state: u64 = 0xF00D_BABE_1234_5678;
    for _ in 0..20_000 {
        let len = (xorshift(&mut state) % 200) as usize;
        let bytes: Vec<u8> = (0..len).map(|_| xorshift(&mut state) as u8).collect();
        if let Ok(s) = std::str::from_utf8(&bytes) {
            let _ = serde_json::from_str::<RelayFrame>(s);
        }
    }
}
