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

use argon2::Argon2;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use std::path::Path;
use zeroize::Zeroizing;

/// Env var holding the passphrase used to encrypt the identity key at rest.
/// When set, the key file is wrapped (Argon2id + XChaCha20-Poly1305); when
/// absent, the key is stored in plaintext (with a loud warning) so headless
/// hosts still start — the hardware-backed (TPM/Enclave) option is the future
/// answer for non-exportable unattended keys.
pub const KEY_PASSPHRASE_ENV: &str = "RMD_KEY_PASSPHRASE";

/// Magic header identifying an encrypted (wrapped) identity file.
const WRAP_MAGIC: &[u8; 4] = b"ORK1";
const WRAP_SALT_LEN: usize = 16;
const WRAP_NONCE_LEN: usize = 24;

/// Derive a 32-byte wrapping key from a passphrase + salt via Argon2id.
fn derive_wrap_key(passphrase: &[u8], salt: &[u8]) -> anyhow::Result<Zeroizing<[u8; 32]>> {
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::default()
        .hash_password_into(passphrase, salt, key.as_mut())
        .map_err(|e| anyhow::anyhow!("argon2 kdf: {e}"))?;
    Ok(key)
}

/// Encrypt a 32-byte seed under `passphrase` → `MAGIC ‖ salt ‖ nonce ‖ ct+tag`.
fn wrap_seed(seed: &[u8; 32], passphrase: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut salt = [0u8; WRAP_SALT_LEN];
    let mut nonce = [0u8; WRAP_NONCE_LEN];
    getrandom::getrandom(&mut salt).map_err(|e| anyhow::anyhow!("getrandom: {e}"))?;
    getrandom::getrandom(&mut nonce).map_err(|e| anyhow::anyhow!("getrandom: {e}"))?;
    let key = derive_wrap_key(passphrase, &salt)?;
    let cipher = XChaCha20Poly1305::new(key.as_ref().into());
    let ct = cipher
        .encrypt(XNonce::from_slice(&nonce), seed.as_ref())
        .map_err(|_| anyhow::anyhow!("identity key encryption failed"))?;
    let mut out = Vec::with_capacity(4 + WRAP_SALT_LEN + WRAP_NONCE_LEN + ct.len());
    out.extend_from_slice(WRAP_MAGIC);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt a wrapped identity blob back to the 32-byte seed.
fn unwrap_seed(blob: &[u8], passphrase: &[u8]) -> anyhow::Result<Zeroizing<[u8; 32]>> {
    let header = 4 + WRAP_SALT_LEN + WRAP_NONCE_LEN;
    anyhow::ensure!(
        blob.len() > header && &blob[..4] == WRAP_MAGIC,
        "not a wrapped identity file"
    );
    let salt = &blob[4..4 + WRAP_SALT_LEN];
    let nonce = &blob[4 + WRAP_SALT_LEN..header];
    let ct = &blob[header..];
    let key = derive_wrap_key(passphrase, salt)?;
    let cipher = XChaCha20Poly1305::new(key.as_ref().into());
    let pt = cipher
        .decrypt(XNonce::from_slice(nonce), ct)
        .map_err(|_| anyhow::anyhow!("wrong passphrase or corrupt identity file"))?;
    let seed: [u8; 32] = pt
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("decrypted seed is not 32 bytes"))?;
    Ok(Zeroizing::new(seed))
}

/// Restrict a file to the current user (unix `0600`; Windows ACL). Reused by the
/// settings store, which holds the same class of at-rest secrets.
pub(crate) fn restrict_perms(path: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(windows)]
    {
        // Break ACL inheritance and grant only the current user full control.
        if let Ok(user) = std::env::var("USERNAME") {
            let _ = std::process::Command::new("icacls")
                .arg(path)
                .args(["/inheritance:r", "/grant:r"])
                .arg(format!("{user}:F"))
                .output();
        }
    }
    Ok(())
}

/// Domain-separation tag for the unattended-access proof-of-possession. The
/// viewer signs `TAG || public_key || 0x00 || channel_binding`; verifying it
/// under the presented public key proves the sender holds the matching private
/// key (and thus owns the `device_id`, a hash of that public key), and the
/// `channel_binding` (the session's DTLS certificate fingerprint) ties the proof
/// to *this* connection so a malicious relay cannot replay it into another.
pub const AUTH_PROOF_TAG: &[u8] = b"rmd-access-proof-v2";

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
        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom::getrandom(seed.as_mut()).map_err(|e| anyhow::anyhow!("getrandom: {e}"))?;
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

    /// Derive a 32-byte subkey from the device's secret key via HKDF-SHA256.
    /// Used to encrypt device-local at-rest data (the settings store) with a key
    /// bound to this identity and needing no separate passphrase — the data is as
    /// protected as the identity key file itself. The secret never leaves here.
    pub fn derive_subkey(&self, info: &[u8]) -> Zeroizing<[u8; 32]> {
        let ikm = Zeroizing::new(self.signing.to_bytes());
        let hk = hkdf::Hkdf::<Sha256>::new(None, ikm.as_ref());
        let mut okm = Zeroizing::new([0u8; 32]);
        hk.expand(info, okm.as_mut())
            .expect("hkdf-sha256 expand of 32 bytes never fails");
        okm
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
    ///
    /// If `RMD_KEY_PASSPHRASE` is set the file is encrypted at rest; a
    /// legacy plaintext file is read (with a warning) and transparently upgraded
    /// to the encrypted form when a passphrase is available.
    pub fn load_or_create(path: &Path) -> anyhow::Result<Self> {
        let passphrase = std::env::var(KEY_PASSPHRASE_ENV).ok();
        if !path.exists() {
            let id = Self::generate()?;
            id.save(path)?;
            return Ok(id);
        }

        let data = std::fs::read(path)?;
        let wrapped = data.starts_with(WRAP_MAGIC);
        let seed: Zeroizing<[u8; 32]> = if wrapped {
            let pass = passphrase.as_deref().ok_or_else(|| {
                anyhow::anyhow!("identity is encrypted; set {KEY_PASSPHRASE_ENV}")
            })?;
            unwrap_seed(&data, pass.as_bytes())?
        } else {
            // Legacy plaintext hex.
            let hex_seed = Zeroizing::new(String::from_utf8_lossy(&data).trim().to_string());
            let bytes = Zeroizing::new(hex::decode(hex_seed.as_str())?);
            let s: [u8; 32] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("identity file is not a 32-byte key"))?;
            if passphrase.is_none() {
                tracing::warn!(
                    "identity key stored in PLAINTEXT — set {KEY_PASSPHRASE_ENV} to encrypt at rest"
                );
            }
            Zeroizing::new(s)
        };

        let id = Self {
            signing: SigningKey::from_bytes(&seed),
        };
        // Opportunistically upgrade a legacy plaintext file once a passphrase exists.
        if !wrapped && passphrase.is_some() {
            tracing::info!("upgrading plaintext identity key to encrypted-at-rest");
            id.save(path)?;
        }
        Ok(id)
    }

    /// Persist the private seed to `path` with restrictive permissions —
    /// encrypted (Argon2id + XChaCha20-Poly1305) when a passphrase is set, else
    /// plaintext hex with a warning.
    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let seed = Zeroizing::new(self.signing.to_bytes());
        let bytes = match std::env::var(KEY_PASSPHRASE_ENV).ok() {
            Some(pass) => wrap_seed(&seed, pass.as_bytes())?,
            None => {
                tracing::warn!(
                    "writing identity key in PLAINTEXT — set {KEY_PASSPHRASE_ENV} to encrypt at rest"
                );
                hex::encode(seed.as_ref()).into_bytes()
            }
        };
        std::fs::write(path, &bytes)?;
        restrict_perms(path)?;
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
    fn key_wrap_roundtrip_and_rejects_wrong_passphrase() {
        let id = DeviceIdentity::generate().unwrap();
        let seed = id.signing.to_bytes();
        let blob = wrap_seed(&seed, b"correct horse battery").unwrap();
        assert_eq!(&blob[..4], WRAP_MAGIC);
        assert_ne!(
            &blob[4..],
            &seed[..],
            "seed must not appear in the wrapped blob"
        );
        // Correct passphrase recovers the exact seed.
        assert_eq!(*unwrap_seed(&blob, b"correct horse battery").unwrap(), seed);
        // Wrong passphrase → AEAD failure.
        assert!(unwrap_seed(&blob, b"wrong").is_err());
        // A plaintext (non-magic) blob is not accepted as wrapped.
        assert!(unwrap_seed(b"not-a-wrapped-key-blob-xxxxxxxxxxxxxxxxxxxxxx", b"x").is_err());
    }

    #[test]
    fn save_load_roundtrip_is_stable() {
        let dir = std::env::temp_dir().join(format!("or-id-{}", std::process::id()));
        let path = dir.join("identity.key");
        let _ = std::fs::remove_dir_all(&dir);
        let id = DeviceIdentity::load_or_create(&path).unwrap();
        let again = DeviceIdentity::load_or_create(&path).unwrap();
        assert_eq!(id.public_key_hex(), again.public_key_hex());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "identity file must be user-only");
        }
        let _ = std::fs::remove_dir_all(&dir);
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
