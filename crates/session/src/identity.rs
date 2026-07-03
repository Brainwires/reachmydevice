//! Device identity: a long-lived ed25519 keypair generated on first run.
//!
//! The keypair is the device's stable identity. Its public-key fingerprint is the
//! `device_id` used with the rendezvous server, and a **short authentication
//! string** ([`DeviceIdentity::sas`]) derived from both peers' public keys lets a
//! human confirm a first connection out-of-band (TOFU). After that first
//! confirmation the peer is remembered (see [`known_peers`]).
//!
//! The private key never leaves the device and is not shared with the rendezvous
//! server — the server only stores the public key for display.

use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use std::path::Path;

/// A device's long-lived identity keypair.
pub struct DeviceIdentity {
    signing: SigningKey,
}

impl DeviceIdentity {
    /// Generate a fresh keypair from the OS CSPRNG.
    pub fn generate() -> anyhow::Result<Self> {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).map_err(|e| anyhow::anyhow!("getrandom: {e}"))?;
        Ok(Self {
            signing: SigningKey::from_bytes(&seed),
        })
    }

    /// Public key as hex (stored on the rendezvous server; shown for TOFU).
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.signing.verifying_key().to_bytes())
    }

    /// SHA-256 fingerprint (hex) of the public key.
    pub fn fingerprint(&self) -> String {
        let mut h = Sha256::new();
        h.update(self.signing.verifying_key().to_bytes());
        hex::encode(h.finalize())
    }

    /// Stable device id: the first 16 bytes (32 hex chars) of the fingerprint.
    pub fn device_id(&self) -> String {
        self.fingerprint()[..32].to_string()
    }

    /// A 6-digit short authentication string over both peers' public keys.
    ///
    /// Both sides sort the two keys and hash them, so they compute the **same**
    /// number; the humans compare it out-of-band on first connect (TOFU).
    pub fn sas(&self, peer_public_key_hex: &str) -> String {
        let mut keys = [self.public_key_hex(), peer_public_key_hex.to_string()];
        keys.sort();
        let mut h = Sha256::new();
        h.update(keys[0].as_bytes());
        h.update(keys[1].as_bytes());
        let digest = h.finalize();
        // First 3 bytes -> 0..16_777_216 -> 6 decimal digits.
        let n = u32::from(digest[0]) << 16 | u32::from(digest[1]) << 8 | u32::from(digest[2]);
        format!("{:06}", n % 1_000_000)
    }

    /// Load the identity from `path`, or generate + save a new one if absent.
    pub fn load_or_create(path: &Path) -> anyhow::Result<Self> {
        if path.exists() {
            let hex_seed = std::fs::read_to_string(path)?;
            let bytes = hex::decode(hex_seed.trim())?;
            let seed: [u8; 32] = bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("identity file is not a 32-byte key"))?;
            Ok(Self {
                signing: SigningKey::from_bytes(&seed),
            })
        } else {
            let id = Self::generate()?;
            id.save(path)?;
            Ok(id)
        }
    }

    /// Persist the private seed (hex) to `path` with restrictive permissions.
    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, hex::encode(self.signing.to_bytes()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }
}

/// A simple TOFU trust store (a `known_peers` file: `device_id public_key_hex`).
pub mod known_peers {
    use std::path::Path;

    /// Look up a previously-trusted peer's public key.
    pub fn get(path: &Path, device_id: &str) -> Option<String> {
        let content = std::fs::read_to_string(path).ok()?;
        for line in content.lines() {
            if let Some((id, key)) = line.split_once(' ') {
                if id == device_id {
                    return Some(key.trim().to_string());
                }
            }
        }
        None
    }

    /// Remember a peer (appends). Returns whether it was newly added.
    pub fn add(path: &Path, device_id: &str, public_key_hex: &str) -> anyhow::Result<bool> {
        if get(path, device_id).is_some() {
            return Ok(false);
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        writeln!(f, "{device_id} {public_key_hex}")?;
        Ok(true)
    }

    /// TOFU check: `Ok(true)` if new (added), `Ok(false)` if known & matching,
    /// `Err` if the stored key differs (possible MITM — refuse).
    pub fn trust_on_first_use(
        path: &Path,
        device_id: &str,
        public_key_hex: &str,
    ) -> anyhow::Result<bool> {
        match get(path, device_id) {
            Some(known) if known == public_key_hex => Ok(false),
            Some(_) => anyhow::bail!(
                "device {device_id} presented a DIFFERENT key than remembered — refusing (possible MITM)"
            ),
            None => add(path, device_id, public_key_hex),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_is_stable_and_ids_derive() {
        let id = DeviceIdentity::generate().unwrap();
        assert_eq!(id.device_id().len(), 32);
        assert_eq!(id.fingerprint().len(), 64);
        assert_eq!(id.public_key_hex().len(), 64);
        // device_id is a prefix of the fingerprint.
        assert!(id.fingerprint().starts_with(&id.device_id()));
    }

    #[test]
    fn sas_matches_from_both_sides() {
        let a = DeviceIdentity::generate().unwrap();
        let b = DeviceIdentity::generate().unwrap();
        // Both peers compute the same SAS over the (sorted) key pair.
        assert_eq!(a.sas(&b.public_key_hex()), b.sas(&a.public_key_hex()));
    }

    #[test]
    fn tofu_detects_key_change() {
        let dir = std::env::temp_dir().join(format!("or-tofu-{}", std::process::id()));
        let path = dir.join("known_peers");
        let _ = std::fs::remove_file(&path);
        assert!(known_peers::trust_on_first_use(&path, "dev1", "keyAAA").unwrap()); // new
        assert!(!known_peers::trust_on_first_use(&path, "dev1", "keyAAA").unwrap()); // known, ok
        assert!(known_peers::trust_on_first_use(&path, "dev1", "keyBBB").is_err()); // changed -> refuse
        let _ = std::fs::remove_dir_all(&dir);
    }
}
