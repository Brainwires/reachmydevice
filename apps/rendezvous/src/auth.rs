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
}
