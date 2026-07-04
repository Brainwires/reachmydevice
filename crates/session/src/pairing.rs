//! Direct device pairing — a QR seed-transfer (co-located) and a SPAKE2 PAKE
//! (remote), establishing a shared pairing key **without trusting the relay**.
//!
//! - **QR seed-transfer:** the presenter shows a [`PairingTicket`] — its identity
//!   key + a 256-bit one-time `seed` + a relay locator + an expiry. The QR pixels
//!   are the confidential channel, so the seed transfers MITM-free; both sides
//!   HKDF it, bound to the sorted identity keys, into a shared key.
//! - **SPAKE2 PAKE:** both sides run SPAKE2 over a short human-transferred code —
//!   MITM-safe even over the untrusted relay (an attacker gets one online guess).
//!   The result is HKDF-bound to both identity keys.
//!
//! Either way the output is a 32-byte pairing key. A short [`confirmation`] tag
//! lets the two sides detect a mismatch (wrong code / wrong seed) before trusting
//! it. The key then authenticates the subsequent session and/or issues the
//! minimal stored anchor for unattended reconnection.

use hkdf::Hkdf;
use sha2::Sha256;
use spake2::{Ed25519Group, Identity, Password, Spake2};
use zeroize::Zeroizing;

/// Ticket format magic ("OpenReach Pairing v1").
const TICKET_MAGIC: &[u8; 4] = b"ORP1";
/// Domain-separation tag for all pairing key derivations.
const PAIR_TAG: &[u8] = b"openreach-pairing-v1";

/// A QR pairing ticket: everything a scanner needs to derive the shared key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PairingTicket {
    /// The presenter's ed25519 identity public key.
    pub identity_pubkey: [u8; 32],
    /// A 256-bit one-time secret — the trust root, carried in the QR pixels.
    pub seed: [u8; 32],
    /// Relay locator (WebSocket URL, or an ephemeral rendezvous code).
    pub relay: String,
    /// Expiry (seconds since the Unix epoch); scanners reject stale tickets.
    pub expiry_unix: u64,
}

impl PairingTicket {
    /// Create a fresh ticket with a random seed.
    pub fn new(
        identity_pubkey: [u8; 32],
        relay: impl Into<String>,
        expiry_unix: u64,
    ) -> anyhow::Result<Self> {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).map_err(|e| anyhow::anyhow!("getrandom: {e}"))?;
        Ok(Self {
            identity_pubkey,
            seed,
            relay: relay.into(),
            expiry_unix,
        })
    }

    /// Compact binary encoding (`MAGIC ‖ pubkey ‖ seed ‖ expiry ‖ relay`).
    pub fn encode(&self) -> Vec<u8> {
        let relay = self.relay.as_bytes();
        let mut out = Vec::with_capacity(4 + 32 + 32 + 8 + 2 + relay.len());
        out.extend_from_slice(TICKET_MAGIC);
        out.extend_from_slice(&self.identity_pubkey);
        out.extend_from_slice(&self.seed);
        out.extend_from_slice(&self.expiry_unix.to_le_bytes());
        out.extend_from_slice(&(relay.len() as u16).to_le_bytes());
        out.extend_from_slice(relay);
        out
    }

    /// Decode a binary ticket.
    pub fn decode(bytes: &[u8]) -> anyhow::Result<Self> {
        let fixed = 4 + 32 + 32 + 8 + 2;
        anyhow::ensure!(
            bytes.len() >= fixed && &bytes[..4] == TICKET_MAGIC,
            "not an OpenReach pairing ticket"
        );
        let mut o = 4;
        let identity_pubkey: [u8; 32] = bytes[o..o + 32].try_into().unwrap();
        o += 32;
        let seed: [u8; 32] = bytes[o..o + 32].try_into().unwrap();
        o += 32;
        let expiry_unix = u64::from_le_bytes(bytes[o..o + 8].try_into().unwrap());
        o += 8;
        let rlen = u16::from_le_bytes(bytes[o..o + 2].try_into().unwrap()) as usize;
        o += 2;
        anyhow::ensure!(bytes.len() >= o + rlen, "truncated pairing ticket");
        let relay = String::from_utf8(bytes[o..o + rlen].to_vec())
            .map_err(|_| anyhow::anyhow!("relay is not valid UTF-8"))?;
        Ok(Self {
            identity_pubkey,
            seed,
            relay,
            expiry_unix,
        })
    }

    /// Hex string suitable for a QR payload or a copyable code.
    pub fn to_code(&self) -> String {
        hex::encode(self.encode())
    }

    /// Parse a hex code back into a ticket.
    pub fn from_code(s: &str) -> anyhow::Result<Self> {
        Self::decode(&hex::decode(s.trim())?)
    }

    /// Whether the ticket has expired as of `now_unix`.
    pub fn is_expired(&self, now_unix: u64) -> bool {
        now_unix > self.expiry_unix
    }
}

/// HKDF-SHA256(ikm, salt=PAIR_TAG, info=sorted(pubkeys)) → 32-byte key. Sorting
/// the keys means both devices derive the same key regardless of who scanned.
fn kdf(ikm: &[u8], pubkey_a: &[u8; 32], pubkey_b: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut keys = [pubkey_a, pubkey_b];
    keys.sort();
    let mut info = Vec::with_capacity(64);
    info.extend_from_slice(keys[0]);
    info.extend_from_slice(keys[1]);
    let hk = Hkdf::<Sha256>::new(Some(PAIR_TAG), ikm);
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(&info, okm.as_mut()).expect("32 is a valid HKDF length");
    okm
}

/// Derive the shared pairing key from a QR ticket's seed, bound to both identities.
pub fn derive_key_from_seed(
    seed: &[u8; 32],
    pubkey_a: &[u8; 32],
    pubkey_b: &[u8; 32],
) -> Zeroizing<[u8; 32]> {
    kdf(seed, pubkey_a, pubkey_b)
}

/// A **directional** confirmation tag over a pairing key. Each side sends the tag
/// for *its own* role and verifies the tag for the *peer's* role; because the two
/// roles produce different tags, a party that doesn't hold the key cannot pass the
/// check by reflecting the tag it received. Roles are assigned deterministically
/// by [`role_label`] (whoever has the lexicographically-smaller public key is the
/// "initiator"), so both sides agree without negotiation.
pub fn confirmation(key: &[u8; 32], role: &[u8]) -> [u8; 16] {
    let hk = Hkdf::<Sha256>::new(Some(b"openreach-pairing-confirm-v2"), key);
    let mut tag = [0u8; 16];
    hk.expand(role, &mut tag)
        .expect("16 is a valid HKDF length");
    tag
}

/// Deterministic role labels `(ours, peers)` from the two public keys: the
/// smaller key is the "initiator". Both sides compute the same split.
pub fn role_labels(our_pubkey: &[u8; 32], peer_pubkey: &[u8; 32]) -> (&'static [u8], &'static [u8]) {
    if our_pubkey < peer_pubkey {
        (b"initiator", b"responder")
    } else {
        (b"responder", b"initiator")
    }
}

/// Constant-time equality for the fixed-size confirmation tags.
pub fn tags_equal(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Render a pairing ticket as a compact Unicode QR code for a terminal, so a
/// headless host can display its pairing QR (the GUI viewer renders an image).
/// The QR encodes the ticket's hex code — scanning it recovers the ticket.
pub fn render_qr_terminal(ticket: &PairingTicket) -> anyhow::Result<String> {
    use qrcode::render::unicode;
    let qr = qrcode::QrCode::new(ticket.to_code().as_bytes())
        .map_err(|e| anyhow::anyhow!("qr encode: {e}"))?;
    Ok(qr
        .render::<unicode::Dense1x2>()
        .quiet_zone(true)
        .build())
}

/// Alphabet for the pairing-code secret: lowercase minus ambiguous letters
/// (i, l, o, u) plus digits 2–9 — easy to read aloud / type. 31 symbols.
const CODE_ALPHABET: &[u8] = b"abcdefghjkmnpqrstvwxyz23456789";

/// Generate a human-transferable pairing code: `"<channel>-<secret>"`.
///
/// The **channel** (a short number) is a *public* rendezvous id — it routes the
/// relay mailbox and the relay sees it. The **secret** (~40 bits) is the SPAKE2
/// password and is **never** sent to the relay. Splitting them this way (à la
/// Magic Wormhole) is what keeps a low-entropy code safe over an untrusted relay:
/// the relay can't brute-force the PAKE because it never learns the secret.
pub fn generate_pairing_code() -> anyhow::Result<String> {
    let mut raw = [0u8; 10];
    getrandom::getrandom(&mut raw).map_err(|e| anyhow::anyhow!("getrandom: {e}"))?;
    let channel = (u16::from(raw[0]) << 8 | u16::from(raw[1])) % 1000; // 0..999
    let secret: String = raw[2..]
        .iter()
        .map(|&b| CODE_ALPHABET[b as usize % CODE_ALPHABET.len()] as char)
        .collect();
    Ok(format!("{channel}-{secret}"))
}

/// Split a pairing code into `(channel, secret)` on the first `-`. The channel is
/// the relay-mailbox room; the secret is the PAKE password.
pub fn split_code(code: &str) -> anyhow::Result<(String, String)> {
    let (channel, secret) = code
        .trim()
        .split_once('-')
        .ok_or_else(|| anyhow::anyhow!("pairing code must be <channel>-<secret>"))?;
    anyhow::ensure!(
        !channel.is_empty() && !secret.is_empty(),
        "empty channel or secret in pairing code"
    );
    Ok((channel.to_string(), secret.to_string()))
}

/// In-progress SPAKE2 exchange (holds the secret state until finished).
pub struct PakeExchange(Spake2<Ed25519Group>);

/// Begin a SPAKE2 exchange from a short shared `code`. Returns the state and the
/// outbound message to send to the peer over the relay.
pub fn pake_start(code: &str) -> (PakeExchange, Vec<u8>) {
    let (state, msg) = Spake2::<Ed25519Group>::start_symmetric(
        &Password::new(code.as_bytes()),
        &Identity::new(PAIR_TAG),
    );
    (PakeExchange(state), msg)
}

/// Finish the SPAKE2 exchange with the peer's message, then bind the result to
/// both identity keys → the shared pairing key. (SPAKE2 alone yields a key even
/// on a wrong code; use [`confirmation`] to detect that before trusting it.)
pub fn pake_finish(
    exchange: PakeExchange,
    peer_msg: &[u8],
    pubkey_a: &[u8; 32],
    pubkey_b: &[u8; 32],
) -> anyhow::Result<Zeroizing<[u8; 32]>> {
    let key = exchange
        .0
        .finish(peer_msg)
        .map_err(|e| anyhow::anyhow!("PAKE failed: {e:?}"))?;
    Ok(kdf(&key, pubkey_a, pubkey_b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ticket_roundtrip_and_expiry() {
        let t = PairingTicket::new([7u8; 32], "wss://relay/ws#abc", 1_000).unwrap();
        let back = PairingTicket::decode(&t.encode()).unwrap();
        assert_eq!(t, back);
        let back2 = PairingTicket::from_code(&t.to_code()).unwrap();
        assert_eq!(t, back2);
        assert!(!t.is_expired(999));
        assert!(t.is_expired(1_001));
        assert!(PairingTicket::decode(b"nope").is_err());
    }

    #[test]
    fn ticket_renders_a_terminal_qr() {
        let t = PairingTicket::new([3u8; 32], "42-abc", 9_999).unwrap();
        let qr = render_qr_terminal(&t).unwrap();
        // A real QR: multi-line block art containing the module glyphs.
        assert!(qr.lines().count() > 10);
        assert!(qr.contains('█') || qr.contains('▀') || qr.contains('▄'));
    }

    #[test]
    fn seed_transfer_agrees_regardless_of_scan_order() {
        let (pa, pb) = ([1u8; 32], [2u8; 32]);
        let seed = [42u8; 32];
        // Presenter derives (pa, pb); scanner derives (pb, pa). Same key (sorted).
        let ka = derive_key_from_seed(&seed, &pa, &pb);
        let kb = derive_key_from_seed(&seed, &pb, &pa);
        assert_eq!(*ka, *kb);
        // Same key + same role label → same tag; different roles → different tags
        // (this directionality is what defeats a reflection attack).
        assert_eq!(confirmation(&ka, b"initiator"), confirmation(&kb, b"initiator"));
        assert_ne!(confirmation(&ka, b"initiator"), confirmation(&ka, b"responder"));
        // A different seed yields a different key.
        let kc = derive_key_from_seed(&[43u8; 32], &pa, &pb);
        assert_ne!(*ka, *kc);
    }

    #[test]
    fn pairing_code_generates_and_splits() {
        let code = generate_pairing_code().unwrap();
        let (channel, secret) = split_code(&code).unwrap();
        assert!(channel.chars().all(|c| c.is_ascii_digit()));
        assert!(secret.len() >= 6);
        // Two codes differ.
        assert_ne!(generate_pairing_code().unwrap(), generate_pairing_code().unwrap());
        // Malformed input rejected.
        assert!(split_code("nodash").is_err());
        assert!(split_code("-secret").is_err());
        assert!(split_code("42-").is_err());
    }

    #[test]
    fn pake_agrees_on_matching_code_and_differs_on_mismatch() {
        let (pa, pb) = ([9u8; 32], [8u8; 32]);

        // Matching code → both sides derive the same key.
        let (sa, ma) = pake_start("7-crossbow-mullet");
        let (sb, mb) = pake_start("7-crossbow-mullet");
        let ka = pake_finish(sa, &mb, &pa, &pb).unwrap();
        let kb = pake_finish(sb, &ma, &pa, &pb).unwrap();
        assert_eq!(*ka, *kb, "matching code must agree");
        // Directional confirmation: each side's own-role tag equals the other's
        // expected peer-role tag.
        let (a_role, _b_role) = role_labels(&pa, &pb);
        assert_eq!(confirmation(&ka, a_role), confirmation(&kb, a_role));
        assert!(tags_equal(&confirmation(&ka, a_role), &confirmation(&kb, a_role)));

        // Mismatched code → keys differ (confirmation tags won't match).
        let (sc, mc) = pake_start("right-code");
        let (sd, md) = pake_start("wrong-code");
        let kc = pake_finish(sc, &md, &pa, &pb).unwrap();
        let kd = pake_finish(sd, &mc, &pa, &pb).unwrap();
        assert_ne!(*kc, *kd, "mismatched code must not agree");
        assert!(!tags_equal(
            &confirmation(&kc, a_role),
            &confirmation(&kd, a_role)
        ));
    }

    #[test]
    fn reflected_tag_does_not_pass_directional_check() {
        // An attacker who doesn't hold the key receives our tag and echoes it.
        // With directional tags, the echoed (our-role) tag is NOT the peer-role
        // tag we verify against, so the reflection fails.
        let key = [5u8; 32];
        let our_tag = confirmation(&key, b"initiator");
        let expected_peer = confirmation(&key, b"responder");
        assert!(!tags_equal(&our_tag, &expected_peer), "reflection must not pass");
    }
}
