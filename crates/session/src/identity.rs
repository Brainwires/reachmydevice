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

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use std::path::Path;

/// Domain-separation tag for the unattended-access proof-of-possession. The
/// viewer signs `TAG || public_key || 0x00 || channel_binding`; verifying it
/// under the presented public key proves the sender holds the matching private
/// key (and thus owns the `device_id`, a hash of that public key), and the
/// `channel_binding` (the session's DTLS certificate fingerprint) ties the proof
/// to *this* connection so a malicious relay cannot replay it into another.
pub const AUTH_PROOF_TAG: &[u8] = b"openreach-access-proof-v2";

/// The message a device signs to prove key possession for host access, bound to
/// a channel value. `binding` is the DTLS fingerprint of this session; pass an
/// empty slice only for unauthenticated LAN/dev flows.
pub fn access_proof_message(public_key: &[u8], binding: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(AUTH_PROOF_TAG.len() + public_key.len() + binding.len() + 1);
    m.extend_from_slice(AUTH_PROOF_TAG);
    m.extend_from_slice(public_key);
    m.push(0); // separator so key/binding can't be shifted into each other
    m.extend_from_slice(binding);
    m
}

/// Derive the stable `device_id` (32 hex chars) from raw public-key bytes.
pub fn device_id_from_public_key(public_key: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(public_key);
    hex::encode(h.finalize())[..32].to_string()
}

/// Verify an access proof: `signature` over [`access_proof_message`] (with
/// `binding`) under `public_key`. Returns the proven `device_id` on success.
pub fn verify_access_proof(
    public_key: &[u8],
    signature: &[u8],
    binding: &[u8],
) -> anyhow::Result<String> {
    let key_bytes: [u8; 32] = public_key
        .try_into()
        .map_err(|_| anyhow::anyhow!("public key must be 32 bytes"))?;
    let vk = VerifyingKey::from_bytes(&key_bytes).map_err(|e| anyhow::anyhow!("bad key: {e}"))?;
    let sig_bytes: [u8; 64] = signature
        .try_into()
        .map_err(|_| anyhow::anyhow!("signature must be 64 bytes"))?;
    let sig = Signature::from_bytes(&sig_bytes);
    vk.verify(&access_proof_message(public_key, binding), &sig)
        .map_err(|e| anyhow::anyhow!("signature invalid: {e}"))?;
    Ok(device_id_from_public_key(public_key))
}

/// Extract the DTLS certificate fingerprint from an SDP blob (the
/// `a=fingerprint:<hash> <value>` attribute), normalized to uppercase for a
/// stable channel-binding value. Returns `None` if absent.
pub fn dtls_fingerprint_from_sdp(sdp: &str) -> Option<String> {
    for line in sdp.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("a=fingerprint:") {
            // rest = "sha-256 AB:CD:...". Keep hash + value, normalized.
            return Some(rest.trim().to_ascii_uppercase());
        }
    }
    None
}

/// Extract the DTLS fingerprint from a signaling payload — the JSON of an
/// `RTCSessionDescription` (`{"type":..,"sdp":".."}`) carried in a `SignalMsg`.
pub fn fingerprint_from_session_json(json: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    dtls_fingerprint_from_sdp(v.get("sdp")?.as_str()?)
}

/// A device's long-lived identity keypair.
#[derive(Clone)]
pub struct DeviceIdentity {
    signing: SigningKey,
}

impl std::fmt::Debug for DeviceIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the private key; the public device_id is safe.
        f.debug_struct("DeviceIdentity")
            .field("device_id", &self.device_id())
            .finish()
    }
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

    /// Raw 32-byte public key.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    /// Sign a message with the device's private key (64-byte ed25519 signature).
    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.signing.sign(msg).to_bytes()
    }

    /// Produce the unattended-access proof: a signature over
    /// [`access_proof_message`] of this device's own public key, bound to the
    /// given channel value (this session's DTLS fingerprint; empty for LAN/dev).
    pub fn access_proof(&self, binding: &[u8]) -> [u8; 64] {
        self.sign(&access_proof_message(&self.public_key_bytes(), binding))
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
    fn access_proof_verifies_and_binds_device_id() {
        let id = DeviceIdentity::generate().unwrap();
        let pk = id.public_key_bytes();
        let binding = b"sha-256 AA:BB:CC";
        let proof = id.access_proof(binding);
        // A valid proof (same binding) yields the device's own id.
        let got = verify_access_proof(&pk, &proof, binding).unwrap();
        assert_eq!(got, id.device_id());
        assert_eq!(got, device_id_from_public_key(&pk));

        // A DIFFERENT channel binding (relay-swapped DTLS fingerprint) fails —
        // this is what defeats proof-replay by a malicious rendezvous.
        assert!(verify_access_proof(&pk, &proof, b"sha-256 99:88:77").is_err());

        // A tampered signature is rejected.
        let mut bad = proof;
        bad[0] ^= 0xFF;
        assert!(verify_access_proof(&pk, &bad, binding).is_err());

        // Another device's key doesn't validate this signature.
        let other = DeviceIdentity::generate().unwrap();
        assert!(verify_access_proof(&other.public_key_bytes(), &proof, binding).is_err());
    }

    #[test]
    fn parses_dtls_fingerprint_from_sdp() {
        let sdp = "v=0\r\na=group:BUNDLE 0\r\na=fingerprint:sha-256 ab:cd:ef\r\nm=video\r\n";
        assert_eq!(
            dtls_fingerprint_from_sdp(sdp).as_deref(),
            Some("SHA-256 AB:CD:EF")
        );
        assert_eq!(dtls_fingerprint_from_sdp("v=0\r\n"), None);
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
