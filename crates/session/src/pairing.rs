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

/// A short confirmation tag over a pairing key, exchanged out of the derived key
/// so both sides can detect a mismatch (wrong code / seed) before trusting it.
pub fn confirmation(key: &[u8; 32]) -> [u8; 16] {
    let hk = Hkdf::<Sha256>::new(Some(b"openreach-pairing-confirm-v1"), key);
    let mut tag = [0u8; 16];
    hk.expand(&[], &mut tag).expect("16 is a valid HKDF length");
    tag
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
    fn seed_transfer_agrees_regardless_of_scan_order() {
        let (pa, pb) = ([1u8; 32], [2u8; 32]);
        let seed = [42u8; 32];
        // Presenter derives (pa, pb); scanner derives (pb, pa). Same key (sorted).
        let ka = derive_key_from_seed(&seed, &pa, &pb);
        let kb = derive_key_from_seed(&seed, &pb, &pa);
        assert_eq!(*ka, *kb);
        assert_eq!(confirmation(&ka), confirmation(&kb));
        // A different seed yields a different key.
        let kc = derive_key_from_seed(&[43u8; 32], &pa, &pb);
        assert_ne!(*ka, *kc);
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
        assert_eq!(confirmation(&ka), confirmation(&kb));

        // Mismatched code → keys differ (confirmation tags won't match).
        let (sc, mc) = pake_start("right-code");
        let (sd, md) = pake_start("wrong-code");
        let kc = pake_finish(sc, &md, &pa, &pb).unwrap();
        let kd = pake_finish(sd, &mc, &pa, &pb).unwrap();
        assert_ne!(*kc, *kd, "mismatched code must not agree");
        assert_ne!(confirmation(&kc), confirmation(&kd));
    }
}
