//! Stable-runnable companion to the `openreach-fuzz` cargo-fuzz targets: feed a
//! large volume of pseudo-random bytes to the protobuf `decode` entry point and
//! assert it never panics (malformed input must return `Err`, not crash). This
//! runs in normal CI; the libFuzzer targets under `fuzz/` explore deeper.

/// Deterministic xorshift64 PRNG (no `rand` dependency, reproducible corpus).
fn xorshift(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

#[test]
fn decode_never_panics_on_random_bytes() {
    let mut state = 0x9E37_79B9_7F4A_7C15;
    let mut buf = Vec::with_capacity(512);
    for _ in 0..50_000 {
        let len = (xorshift(&mut state) % 400) as usize;
        buf.clear();
        while buf.len() < len {
            buf.extend_from_slice(&xorshift(&mut state).to_le_bytes());
        }
        buf.truncate(len);
        // Must not panic; result is irrelevant.
        let _ = openreach_protocol::decode(&buf);
    }
}

#[test]
fn decode_survives_valid_prefix_plus_garbage() {
    // Start from a real encoded envelope, then flip/append random bytes — the
    // "almost valid" cases that trip naive parsers.
    let base = openreach_protocol::encode(&openreach_protocol::ping(42));
    let mut state = 0x1234_5678_9ABC_DEF0;
    for _ in 0..20_000 {
        let mut b = base.clone();
        // Truncate at a random point and/or append junk.
        let cut = (xorshift(&mut state) as usize) % (b.len() + 1);
        b.truncate(cut);
        let extra = (xorshift(&mut state) % 32) as usize;
        for _ in 0..extra {
            b.push(xorshift(&mut state) as u8);
        }
        let _ = openreach_protocol::decode(&b);
    }
}
