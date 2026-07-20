//! Password hashing (Argon2) and device bearer tokens.
//!
//! - Passwords are hashed with Argon2 (PHC string stored in `users.password_hash`).
//! - Device tokens are high-entropy random strings; only their SHA-256 hash is
//!   stored (`device_tokens.token_hash`), so a DB leak doesn't reveal live tokens.

use argon2::password_hash::rand_core::{OsRng, RngCore};
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use sha2::{Digest, Sha256};

/// Explicitly pinned Argon2id parameters (don't rely on `Argon2::default()`,
/// whose values can shift across crate versions). 64 MiB / 3 passes / 1 lane —
/// above the OWASP minimum, comfortable for a small VPS. Existing hashes still
/// verify: their parameters are read from the stored PHC string.
fn argon2() -> Argon2<'static> {
    let params = Params::new(64 * 1024, 3, 1, None).expect("valid argon2 params");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// Hash a password into an Argon2id PHC string.
pub fn hash_password(password: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    argon2()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| anyhow::anyhow!("argon2 hash: {e}"))
}

/// Verify a password against a stored PHC string (constant-time in Argon2;
/// parameters are taken from the stored hash, so old hashes still verify).
pub fn verify_password(password: &str, phc: &str) -> bool {
    match PasswordHash::new(phc) {
        Ok(parsed) => argon2()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

/// Generate a new opaque device token (256 bits, hex-encoded).
pub fn generate_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// SHA-256 hex of a token, for storage/lookup.
pub fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// How long a WebSocket ticket is valid — just long enough to open the socket.
const TICKET_TTL: Duration = Duration::from_secs(30);

/// Short-lived, single-use tickets that authorize a `/ws` upgrade without putting
/// a long-lived bearer token in the URL (which leaks into proxy/access logs and
/// `Referer`). A client first proves its bearer token to `GET /api/ws-ticket`,
/// then opens `GET /ws?ticket=<one-time>`; the ticket is consumed on redeem.
///
/// The ticket carries the full [`ResolvedCredential`] (not just a `device_id`), so
/// the `/ws` handler has both the signaling address (Hub peer key) and the
/// attribution `user_id` a session observer needs — without re-resolving.
#[derive(Default)]
pub struct TicketStore {
    inner: Mutex<HashMap<String, (crate::resolver::ResolvedCredential, Instant)>>,
}

impl TicketStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Mint a one-time ticket for `cred`, valid for [`TICKET_TTL`].
    pub fn issue(&self, cred: &crate::resolver::ResolvedCredential) -> String {
        let ticket = generate_token();
        let mut m = self.inner.lock().unwrap();
        let now = Instant::now();
        // Opportunistic cleanup so the map can't grow without bound.
        m.retain(|_, (_, exp)| *exp > now);
        m.insert(ticket.clone(), (cred.clone(), now + TICKET_TTL));
        ticket
    }

    /// Redeem a ticket, returning its [`ResolvedCredential`] if valid and
    /// unexpired. The ticket is removed (single use) whether or not it had expired.
    pub fn redeem(&self, ticket: &str) -> Option<crate::resolver::ResolvedCredential> {
        let mut m = self.inner.lock().unwrap();
        match m.remove(ticket) {
            Some((cred, exp)) if exp > Instant::now() => Some(cred),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_roundtrip() {
        let phc = hash_password("correct horse battery staple").unwrap();
        assert!(verify_password("correct horse battery staple", &phc));
        assert!(!verify_password("wrong", &phc));
    }

    #[test]
    fn token_hash_is_stable_and_distinct() {
        let t1 = generate_token();
        let t2 = generate_token();
        assert_ne!(t1, t2, "tokens must be unique");
        assert_eq!(hash_token(&t1), hash_token(&t1));
        assert_ne!(hash_token(&t1), hash_token(&t2));
    }

    #[test]
    fn ticket_roundtrips_resolved_credential_and_is_single_use() {
        let store = TicketStore::new();
        let cred = crate::resolver::ResolvedCredential {
            user_id: 7,
            signaling_id: "dev-abc".into(),
        };
        let ticket = store.issue(&cred);
        let got = store.redeem(&ticket).expect("valid ticket redeems");
        assert_eq!(got.user_id, 7);
        assert_eq!(got.signaling_id, "dev-abc");
        // Single use: a second redeem of the same ticket fails.
        assert!(store.redeem(&ticket).is_none());
    }
}
