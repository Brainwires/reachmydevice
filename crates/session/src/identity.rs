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
//!
//! # At-rest protection
//!
//! The private seed is stored in `identity.key`, **encrypted by default**
//! (Argon2id + XChaCha20-Poly1305, see [`DeviceIdentity::save`]). The wrapping
//! passphrase comes from the first of these that yields one:
//!
//! 1. the `RMD_KEY_PASSPHRASE` env var ([`KEY_PASSPHRASE_ENV`]);
//! 2. a `key.env` file next to the key holding the same `RMD_KEY_PASSPHRASE=…`;
//! 3. the OS keyring (macOS Keychain / Windows Credential Manager / Linux
//!    Secret Service): a random passphrase generated on first use and stored
//!    under [`KEYRING_SERVICE`]/[`KEYRING_ENTRY`], so the key is encrypted
//!    without any operator setup and the passphrase never touches the disk in
//!    plaintext.
//!
//! When none applies (typically a headless host with no keyring — a systemd
//! system service without a Secret Service / D-Bus session) the key is stored in
//! **plaintext** with a loud warning and a hint to set `RMD_KEY_PASSPHRASE`. The
//! settings store is encrypted under a subkey of this seed, so in that fallback
//! the stored device token and connection password are only as protected as the
//! `0600` file permissions. The hardware-backed (TPM/Enclave) option is the
//! future answer for non-exportable unattended keys.
//!
//! An existing identity is never regenerated: if the key file is encrypted and no
//! source yields the right passphrase, loading fails (so the host does not
//! silently de-register from the rendezvous under a new `device_id`).

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use std::path::Path;
use zeroize::Zeroizing;

/// Env var holding the passphrase used to encrypt the identity key at rest.
/// Highest-priority passphrase source (see the module docs for the full order):
/// when set it is used for both wrapping and unwrapping, ahead of `key.env` and
/// the OS keyring, so existing deployments that provision it (systemd
/// `EnvironmentFile`) are unaffected by the keyring default.
pub const KEY_PASSPHRASE_ENV: &str = "RMD_KEY_PASSPHRASE";

/// OS-keyring *service* name under which the auto-generated identity-key
/// passphrase is stored (shown by Keychain Access / `secret-tool` / Credential
/// Manager). Shared by every binary of the same OS user (`rmdd` and `rmd`), which
/// also share `identity.key`.
pub const KEYRING_SERVICE: &str = "com.brainwires.rmd";

/// OS-keyring *entry* (account / username) name of the identity-key passphrase.
pub const KEYRING_ENTRY: &str = "identity-key-passphrase";

/// Magic header identifying an encrypted (wrapped) identity file.
const WRAP_MAGIC: &[u8; 4] = b"ORK1";
const WRAP_SALT_LEN: usize = 16;
const WRAP_NONCE_LEN: usize = 24;

/// Which source a wrapping passphrase came from. Logged (never the value) so an
/// operator can tell which of env / `key.env` / keyring is in force.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PassphraseSource {
    Env,
    KeyEnvFile,
    OsKeyring,
}

impl std::fmt::Display for PassphraseSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            PassphraseSource::Env => KEY_PASSPHRASE_ENV,
            PassphraseSource::KeyEnvFile => "key.env",
            PassphraseSource::OsKeyring => "OS keyring",
        })
    }
}

/// Resolve an operator-provided identity-key passphrase (sources 1–2; the OS
/// keyring is layered on by [`resolve_wrap_passphrase`] /
/// [`resolve_unwrap_passphrase`]). Prefers `RMD_KEY_PASSPHRASE` from the
/// environment (how the daemon gets it, via its systemd `EnvironmentFile`), and
/// otherwise reads a `key.env` file sitting next to the key (same
/// `RMD_KEY_PASSPHRASE=…` line). Without this fallback the `rmdd` CLI can't open
/// an encrypted key from a plain shell — `rmdd set/list` would fail "identity is
/// encrypted" while the service worked. `config_dir` is the directory holding
/// `identity.key` (i.e. `~/.config/rmd`).
fn explicit_passphrase(config_dir: Option<&Path>) -> Option<(Zeroizing<String>, PassphraseSource)> {
    if let Ok(v) = std::env::var(KEY_PASSPHRASE_ENV) {
        if !v.is_empty() {
            return Some((Zeroizing::new(v), PassphraseSource::Env));
        }
    }
    let content = Zeroizing::new(std::fs::read_to_string(config_dir?.join("key.env")).ok()?);
    content
        .lines()
        .find_map(parse_key_env_line)
        .map(|p| (Zeroizing::new(p), PassphraseSource::KeyEnvFile))
}

/// The OS keyring as a passphrase source. Every call runs on a dedicated thread:
/// the Linux Secret Service backend blocks on an internal async executor and
/// can deadlock when invoked from a thread that is inside a tokio runtime
/// (keyring-rs #132), and a panicking platform backend must surface as
/// "unavailable" rather than take the daemon down.
mod os_keyring {
    use super::{KEYRING_ENTRY, KEYRING_SERVICE};
    use zeroize::Zeroizing;

    #[cfg(any(target_os = "macos", target_os = "linux", windows))]
    fn on_thread<T: Send + 'static>(
        f: impl FnOnce() -> anyhow::Result<T> + Send + 'static,
    ) -> anyhow::Result<T> {
        std::thread::Builder::new()
            .name("rmd-keyring".into())
            .spawn(f)
            .map_err(|e| anyhow::anyhow!("spawn keyring thread: {e}"))?
            .join()
            .map_err(|_| anyhow::anyhow!("OS keyring backend panicked"))?
    }

    #[cfg(any(target_os = "macos", target_os = "linux", windows))]
    fn entry() -> anyhow::Result<keyring::Entry> {
        keyring::Entry::new(KEYRING_SERVICE, KEYRING_ENTRY)
            .map_err(|e| anyhow::anyhow!("OS keyring: {e}"))
    }

    /// Read the stored passphrase: `Ok(None)` when the store is reachable but
    /// holds no (or an empty) entry; `Err` when the store itself is unavailable.
    #[cfg(any(target_os = "macos", target_os = "linux", windows))]
    fn read(entry: &keyring::Entry) -> anyhow::Result<Option<Zeroizing<String>>> {
        match entry.get_password() {
            Ok(p) if !p.is_empty() => Ok(Some(Zeroizing::new(p))),
            Ok(_) | Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(anyhow::anyhow!("OS keyring: {e}")),
        }
    }

    /// Fetch the passphrase if the keyring holds one. Never creates an entry.
    #[cfg(any(target_os = "macos", target_os = "linux", windows))]
    pub(super) fn get() -> anyhow::Result<Option<Zeroizing<String>>> {
        on_thread(|| read(&entry()?))
    }

    /// Fetch the passphrase, generating + storing a random one on first use.
    #[cfg(any(target_os = "macos", target_os = "linux", windows))]
    pub(super) fn get_or_create() -> anyhow::Result<Zeroizing<String>> {
        on_thread(|| {
            let entry = entry()?;
            if let Some(existing) = read(&entry)? {
                return Ok(existing);
            }
            let mut raw = Zeroizing::new([0u8; 32]);
            getrandom::getrandom(raw.as_mut()).map_err(|e| anyhow::anyhow!("getrandom: {e}"))?;
            let fresh = Zeroizing::new(hex::encode(raw.as_ref()));
            entry
                .set_password(&fresh)
                .map_err(|e| anyhow::anyhow!("OS keyring: {e}"))?;
            // Read back and use *what the store holds*, not the local value: a
            // key must only ever be wrapped under a passphrase the keyring has
            // demonstrably persisted (a store that accepts a write it won't keep
            // would otherwise lock the identity out on the next start), and if two
            // processes raced the first-run create the one the store kept wins.
            read(&entry)?.ok_or_else(|| {
                anyhow::anyhow!("OS keyring accepted the passphrase but did not persist it")
            })
        })
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    pub(super) fn get() -> anyhow::Result<Option<Zeroizing<String>>> {
        let _ = (KEYRING_SERVICE, KEYRING_ENTRY);
        Err(anyhow::anyhow!(
            "OS keyring is not supported on this platform"
        ))
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    pub(super) fn get_or_create() -> anyhow::Result<Zeroizing<String>> {
        Err(anyhow::anyhow!(
            "OS keyring is not supported on this platform"
        ))
    }
}

/// Resolve the passphrase to **wrap** (write) the identity key under, in the
/// module-documented order: env, `key.env`, then the OS keyring (creating a
/// random passphrase there on first use). `Err` carries the reason no passphrase
/// is available — the caller falls back to plaintext and must say so loudly.
fn resolve_wrap_passphrase(
    config_dir: Option<&Path>,
) -> anyhow::Result<(Zeroizing<String>, PassphraseSource)> {
    if let Some(explicit) = explicit_passphrase(config_dir) {
        return Ok(explicit);
    }
    os_keyring::get_or_create().map(|p| (p, PassphraseSource::OsKeyring))
}

/// Resolve the passphrase to **unwrap** (read) an encrypted identity key: env,
/// `key.env`, then the OS keyring — read-only, so a keyring that has lost its
/// entry is reported, never silently replaced with a fresh (useless) passphrase.
/// `Err` means no passphrase is available at all; the caller must fail the load
/// rather than regenerate the identity.
fn resolve_unwrap_passphrase(
    config_dir: Option<&Path>,
) -> anyhow::Result<(Zeroizing<String>, PassphraseSource)> {
    if let Some(explicit) = explicit_passphrase(config_dir) {
        return Ok(explicit);
    }
    match os_keyring::get() {
        Ok(Some(p)) => Ok((p, PassphraseSource::OsKeyring)),
        Ok(None) => anyhow::bail!(
            "identity key is encrypted but no passphrase is available: {KEY_PASSPHRASE_ENV} is \
             unset, there is no key.env, and the OS keyring has no `{KEYRING_SERVICE}` / \
             `{KEYRING_ENTRY}` entry (deleted, or a different OS user/keychain?) — restore the \
             passphrase or set {KEY_PASSPHRASE_ENV}; do NOT delete the key, that discards this \
             device's identity and its rendezvous registration"
        ),
        Err(e) => anyhow::bail!(
            "identity key is encrypted but the OS keyring is unavailable ({e}) and \
             {KEY_PASSPHRASE_ENV} is unset — set {KEY_PASSPHRASE_ENV} (or key.env next to the \
             key) to the wrapping passphrase"
        ),
    }
}

/// Parse one `key.env` line into the passphrase value, tolerating a leading
/// `export ` and single- or double-quoted values. Only the surrounding quote
/// pair is stripped — whitespace or quotes *inside* a quoted value are preserved
/// verbatim, so a passphrase like `"  spaces  "` survives intact (M10).
fn parse_key_env_line(line: &str) -> Option<String> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let line = line
        .strip_prefix("export ")
        .map(str::trim_start)
        .unwrap_or(line);
    let rest = line.strip_prefix(KEY_PASSPHRASE_ENV)?;
    // Require the key to be followed immediately by `=` (so `RMD_KEY_PASSPHRASE_X`
    // doesn't match `RMD_KEY_PASSPHRASE`).
    let val = rest.strip_prefix('=')?;
    // A quoted value keeps its interior exactly; an unquoted value is trimmed.
    let val = if (val.starts_with('"') && val.ends_with('"') && val.len() >= 2)
        || (val.starts_with('\'') && val.ends_with('\'') && val.len() >= 2)
    {
        &val[1..val.len() - 1]
    } else {
        val.trim()
    };
    (!val.is_empty()).then(|| val.to_string())
}

// Argon2id parameters for wrapping the identity key, PINNED explicitly. They
// match the `argon2` 0.5 crate defaults in force when the `ORK1` format shipped,
// so existing wrapped files still open — but pinning them means a future bump of
// the crate's *default* params can never lock an already-wrapped key out (M3).
// Change these only alongside a format-version bump + migration.
const ARGON2_M_COST: u32 = 19 * 1024; // 19 MiB
const ARGON2_T_COST: u32 = 2;
const ARGON2_P_COST: u32 = 1;

/// Argon2id configured with our pinned parameters (see the constants above).
fn wrap_argon2() -> anyhow::Result<Argon2<'static>> {
    let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(32))
        .map_err(|e| anyhow::anyhow!("argon2 params: {e}"))?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

/// Derive a 32-byte wrapping key from a passphrase + salt via Argon2id.
fn derive_wrap_key(passphrase: &[u8], salt: &[u8]) -> anyhow::Result<Zeroizing<[u8; 32]>> {
    let mut key = Zeroizing::new([0u8; 32]);
    wrap_argon2()?
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

/// Atomically write a secret file: unique temp sibling created `O_EXCL` at mode
/// `0600`, fully written + fsync'd, then renamed over `path` (dir fsync'd for
/// durability). This guarantees the file is never half-written after a crash
/// (B6/M1) and never momentarily world-readable before perms are tightened (M2),
/// and the unique temp name lets concurrent writers not collide (M4). Reused by
/// the settings store, which holds the same class of at-rest secret.
pub(crate) fn atomic_write_secret(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    use std::io::Write;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // Unique per-process, per-call temp name so two writers never share a temp.
    static CTR: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = CTR.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let ext = format!("tmp.{}.{n}", std::process::id());
    let tmp = path.with_extension(ext);

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600); // 0600 from creation — never a wider window (M2).
    }
    let write = (|| -> std::io::Result<()> {
        let mut f = opts.open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?; // durable before the rename
        Ok(())
    })();
    if let Err(e) = write {
        let _ = std::fs::remove_file(&tmp);
        return Err(e.into());
    }
    // Tighten perms on the temp before the rename so the final file is born
    // restricted. On unix this re-asserts the 0600 the create-mode already set
    // (belt-and-suspenders); on Windows (no create-mode) it's how the ACL gets
    // applied at all.
    restrict_perms(&tmp)?;
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e.into());
    }
    // Best-effort: fsync the directory so the rename itself survives a crash.
    #[cfg(unix)]
    {
        if let Some(parent) = path.parent() {
            if let Ok(dir) = std::fs::File::open(parent) {
                let _ = dir.sync_all();
            }
        }
    }
    Ok(())
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
        // Surface failures loudly — silently leaving a secret world-readable is
        // worse than a warning the operator can act on.
        match std::env::var("USERNAME") {
            Ok(user) => match std::process::Command::new("icacls")
                .arg(path)
                .args(["/inheritance:r", "/grant:r"])
                .arg(format!("{user}:F"))
                .output()
            {
                Ok(out) if !out.status.success() => tracing::warn!(
                    path = %path.display(),
                    stderr = %String::from_utf8_lossy(&out.stderr).trim(),
                    "icacls could not restrict permissions on a secret file"
                ),
                Err(e) => {
                    tracing::warn!(error = %e, path = %path.display(), "failed to run icacls to restrict a secret file")
                }
                _ => {}
            },
            Err(_) => tracing::warn!(
                path = %path.display(),
                "USERNAME unset; cannot restrict permissions on a secret file"
            ),
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

/// Domain-separation tag for the token-refresh proof (`POST /api/token/refresh`).
/// A device signs `TAG || public_key || timestamp_be` with its identity key to
/// prove possession and re-mint an expired bearer token without the account
/// password. Must match the server's constant of the same name.
pub const TOKEN_REFRESH_TAG: &[u8] = b"rmd-token-refresh-v1";

/// The message a device signs to prove key possession for a token refresh, bound
/// to `timestamp` (unix seconds) so the server can bound replay.
pub fn token_refresh_message(public_key: &[u8], timestamp: i64) -> Vec<u8> {
    let mut m = Vec::with_capacity(TOKEN_REFRESH_TAG.len() + public_key.len() + 8);
    m.extend_from_slice(TOKEN_REFRESH_TAG);
    m.extend_from_slice(public_key);
    m.extend_from_slice(&timestamp.to_be_bytes());
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

    /// Load the identity from `path`, or generate + save a new one **only if the
    /// file is absent**.
    ///
    /// - An encrypted file is unwrapped with the first passphrase source that
    ///   yields one (env, `key.env`, OS keyring — see the module docs). If none
    ///   does, or the passphrase is wrong, this **fails**: the identity is never
    ///   regenerated over an existing file, since a new `device_id` would silently
    ///   de-register the host from the rendezvous.
    /// - A legacy plaintext file is read and transparently upgraded to the
    ///   encrypted form when any passphrase source (including a freshly created
    ///   keyring entry) is available; otherwise it stays plaintext with a warning.
    pub fn load_or_create(path: &Path) -> anyhow::Result<Self> {
        // Best-effort cross-process serialization (same advisory lock the settings
        // store uses, on `identity.lock`): two first-run starters (`rmdd` service +
        // a concurrent `rmdd set`) must not each mint a keyring passphrase and wrap
        // the key under the one the store then overwrites. Failing to lock (e.g. a
        // read-only config dir holding a provisioned key) must not block a load.
        let _lock = crate::settings::lock(path).ok();
        let config_dir = path.parent();
        if !path.exists() {
            let id = Self::generate()?;
            id.save(path)?;
            return Ok(id);
        }

        let data = std::fs::read(path)?;
        if data.starts_with(WRAP_MAGIC) {
            // Encrypted: decrypt or fail — never fall through to regeneration.
            let (pass, source) = resolve_unwrap_passphrase(config_dir)?;
            let seed = unwrap_seed(&data, pass.as_bytes()).map_err(|e| {
                anyhow::anyhow!(
                    "{e} (passphrase source: {source}); refusing to regenerate the identity"
                )
            })?;
            return Ok(Self {
                signing: SigningKey::from_bytes(&seed),
            });
        }

        // Legacy plaintext hex.
        let hex_seed = Zeroizing::new(String::from_utf8_lossy(&data).trim().to_string());
        let bytes = Zeroizing::new(hex::decode(hex_seed.as_str())?);
        let seed: Zeroizing<[u8; 32]> = Zeroizing::new(
            bytes
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("identity file is not a 32-byte key"))?,
        );
        let id = Self {
            signing: SigningKey::from_bytes(&seed),
        };
        // Opportunistically upgrade a legacy plaintext file once a passphrase
        // exists — including the keyring's, minted right here on first use.
        match resolve_wrap_passphrase(config_dir) {
            Ok((pass, source)) => {
                tracing::info!(
                    passphrase_source = %source,
                    "upgrading plaintext identity key to encrypted-at-rest"
                );
                id.save_with(path, Some(pass.as_bytes()))?;
            }
            Err(reason) => tracing::warn!(
                %reason,
                "identity key stored in PLAINTEXT (no OS keyring) — set {KEY_PASSPHRASE_ENV} (or key.env next to the key) to encrypt at rest"
            ),
        }
        Ok(id)
    }

    /// Persist the private seed to `path` with restrictive permissions —
    /// encrypted (Argon2id + XChaCha20-Poly1305) under the resolved passphrase
    /// (env, `key.env`, or an OS-keyring passphrase created on first use), else
    /// plaintext hex with a warning when no keyring is available either.
    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        match resolve_wrap_passphrase(path.parent()) {
            Ok((pass, source)) => {
                tracing::info!(passphrase_source = %source, "identity key encrypted at rest");
                self.save_with(path, Some(pass.as_bytes()))
            }
            Err(reason) => {
                tracing::warn!(
                    %reason,
                    "writing identity key in PLAINTEXT (no OS keyring) — set {KEY_PASSPHRASE_ENV} (or key.env next to the key) to encrypt at rest"
                );
                self.save_with(path, None)
            }
        }
    }

    /// Write the seed to `path`: wrapped under `passphrase` when given, else
    /// plaintext hex. Split from [`save`](Self::save) so a caller that already
    /// resolved the passphrase (the load-time upgrade) doesn't hit the keyring
    /// twice.
    fn save_with(&self, path: &Path, passphrase: Option<&[u8]>) -> anyhow::Result<()> {
        let seed = Zeroizing::new(self.signing.to_bytes());
        let bytes = match passphrase {
            Some(pass) => Zeroizing::new(wrap_seed(&seed, pass)?),
            None => Zeroizing::new(hex::encode(seed.as_ref()).into_bytes()),
        };
        // Atomic + 0600-from-creation, so a crash can't corrupt the identity and
        // the (possibly plaintext) key is never briefly world-readable.
        atomic_write_secret(path, &bytes)
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
    fn token_refresh_proof_verifies_and_binds_timestamp() {
        let id = DeviceIdentity::generate().unwrap();
        let pk = id.public_key_bytes();
        let ts = 1_700_000_000i64;
        let msg = token_refresh_message(&pk, ts);
        // The message layout is TAG ‖ public_key ‖ timestamp_be (the server rebuilds
        // it identically); check the prefix + length so a client/server drift trips.
        assert!(msg.starts_with(TOKEN_REFRESH_TAG));
        assert_eq!(msg.len(), TOKEN_REFRESH_TAG.len() + 32 + 8);
        // A signature over it verifies under the device's own key…
        let sig = ed25519_dalek::Signature::from_bytes(&id.sign(&msg));
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&pk).unwrap();
        assert!(vk.verify(&msg, &sig).is_ok());
        // …but not over a message with a different timestamp (replay binding).
        assert!(
            vk.verify(&token_refresh_message(&pk, ts + 1), &sig)
                .is_err()
        );
    }

    #[test]
    fn key_env_line_parsing() {
        let p = KEY_PASSPHRASE_ENV;
        // Plain, export-prefixed, and quoted forms.
        assert_eq!(
            parse_key_env_line(&format!("{p}=hunter2")).as_deref(),
            Some("hunter2")
        );
        assert_eq!(
            parse_key_env_line(&format!("export {p}=hunter2")).as_deref(),
            Some("hunter2")
        );
        assert_eq!(
            parse_key_env_line(&format!("{p}=\"hunter2\"")).as_deref(),
            Some("hunter2")
        );
        assert_eq!(
            parse_key_env_line(&format!("{p}='hunter2'")).as_deref(),
            Some("hunter2")
        );
        // Interior whitespace/quotes preserved inside a quoted value.
        assert_eq!(
            parse_key_env_line(&format!("{p}=\"  a b  \"")).as_deref(),
            Some("  a b  ")
        );
        // Unquoted value is trimmed.
        assert_eq!(
            parse_key_env_line(&format!("{p}=  spaced  ")).as_deref(),
            Some("spaced")
        );
        // Comments, blanks, other keys, empty values, and near-miss keys are ignored.
        assert_eq!(parse_key_env_line(&format!("# {p}=x")), None);
        assert_eq!(parse_key_env_line(""), None);
        assert_eq!(parse_key_env_line(&format!("{p}=")), None);
        assert_eq!(parse_key_env_line(&format!("{p}_OTHER=x")), None);
        assert_eq!(parse_key_env_line("SOMETHING_ELSE=x"), None);
    }

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

    /// Fresh scratch dir for one test. Tests that exercise `load_or_create`
    /// without a `key.env` would otherwise reach the developer's real OS keyring
    /// (and on macOS trigger an ACL prompt for every rebuilt test binary), so
    /// every such test either writes a `key.env` here or installs the in-memory
    /// test keyring below.
    fn scratch_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("rmd-id-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_key_env(dir: &Path, passphrase: &str) {
        std::fs::write(
            dir.join("key.env"),
            format!("{KEY_PASSPHRASE_ENV}={passphrase}\n"),
        )
        .unwrap();
    }

    fn is_wrapped(path: &Path) -> bool {
        std::fs::read(path).unwrap().starts_with(WRAP_MAGIC)
    }

    #[test]
    fn save_load_roundtrip_is_stable() {
        let dir = scratch_dir("roundtrip");
        let path = dir.join("identity.key");
        write_key_env(&dir, "correct horse battery");
        let id = DeviceIdentity::load_or_create(&path).unwrap();
        assert!(
            is_wrapped(&path),
            "a passphrase source exists → encrypted at rest"
        );
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
    fn legacy_plaintext_key_is_upgraded_under_explicit_passphrase() {
        let dir = scratch_dir("legacy");
        let path = dir.join("identity.key");
        let id = DeviceIdentity::generate().unwrap();
        // A pre-keyring, pre-passphrase install: plaintext hex seed on disk.
        std::fs::write(&path, hex::encode(id.signing.to_bytes())).unwrap();
        assert!(!is_wrapped(&path));
        write_key_env(&dir, "hunter2");
        let loaded = DeviceIdentity::load_or_create(&path).unwrap();
        assert_eq!(
            loaded.public_key_hex(),
            id.public_key_hex(),
            "same identity"
        );
        assert!(is_wrapped(&path), "legacy plaintext key re-wrapped on load");
        // And the wrapped file opens under that passphrase from then on.
        let again = DeviceIdentity::load_or_create(&path).unwrap();
        assert_eq!(again.public_key_hex(), id.public_key_hex());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn wrong_passphrase_fails_and_never_regenerates() {
        let dir = scratch_dir("wrongpass");
        let path = dir.join("identity.key");
        write_key_env(&dir, "original");
        let id = DeviceIdentity::load_or_create(&path).unwrap();
        let on_disk = std::fs::read(&path).unwrap();
        // The operator rotates the env to a passphrase that doesn't open the file.
        write_key_env(&dir, "rotated");
        let err = DeviceIdentity::load_or_create(&path)
            .unwrap_err()
            .to_string();
        assert!(err.contains("wrong passphrase"), "got: {err}");
        assert_eq!(
            std::fs::read(&path).unwrap(),
            on_disk,
            "a failed decrypt must leave the identity file untouched"
        );
        // Restoring the passphrase recovers the very same identity.
        write_key_env(&dir, "original");
        let back = DeviceIdentity::load_or_create(&path).unwrap();
        assert_eq!(back.public_key_hex(), id.public_key_hex());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// In-memory stand-in for the OS keyring, installed process-wide for the
    /// test binary so no test can reach a real Keychain / Secret Service. Unlike
    /// `keyring::mock` it persists across `Entry` instances (like a real store)
    /// and can be switched "offline" to model a headless host.
    #[cfg(any(target_os = "macos", target_os = "linux", windows))]
    mod test_keyring {
        use keyring::credential::{Credential, CredentialApi, CredentialBuilderApi};
        use std::collections::BTreeMap;
        use std::sync::Mutex;
        use std::sync::atomic::{AtomicBool, Ordering};

        static STORE: Mutex<BTreeMap<(String, String), Vec<u8>>> = Mutex::new(BTreeMap::new());
        static AVAILABLE: AtomicBool = AtomicBool::new(true);

        struct Cred {
            key: (String, String),
        }

        impl CredentialApi for Cred {
            fn set_secret(&self, secret: &[u8]) -> keyring::Result<()> {
                STORE
                    .lock()
                    .unwrap()
                    .insert(self.key.clone(), secret.to_vec());
                Ok(())
            }
            fn get_secret(&self) -> keyring::Result<Vec<u8>> {
                STORE
                    .lock()
                    .unwrap()
                    .get(&self.key)
                    .cloned()
                    .ok_or(keyring::Error::NoEntry)
            }
            fn delete_credential(&self) -> keyring::Result<()> {
                STORE
                    .lock()
                    .unwrap()
                    .remove(&self.key)
                    .map(|_| ())
                    .ok_or(keyring::Error::NoEntry)
            }
            fn as_any(&self) -> &dyn std::any::Any {
                self
            }
        }

        struct Builder;

        impl CredentialBuilderApi for Builder {
            fn build(
                &self,
                _target: Option<&str>,
                service: &str,
                user: &str,
            ) -> keyring::Result<Box<Credential>> {
                if !AVAILABLE.load(Ordering::SeqCst) {
                    return Err(keyring::Error::NoStorageAccess(
                        "test keyring offline (headless)".into(),
                    ));
                }
                Ok(Box::new(Cred {
                    key: (service.to_string(), user.to_string()),
                }))
            }
            fn as_any(&self) -> &dyn std::any::Any {
                self
            }
        }

        pub fn install() {
            static ONCE: std::sync::Once = std::sync::Once::new();
            ONCE.call_once(|| keyring::set_default_credential_builder(Box::new(Builder)));
        }

        pub fn set_available(available: bool) {
            AVAILABLE.store(available, Ordering::SeqCst);
        }

        pub fn get(service: &str, user: &str) -> Option<String> {
            STORE
                .lock()
                .unwrap()
                .get(&(service.to_string(), user.to_string()))
                .map(|b| String::from_utf8(b.clone()).unwrap())
        }

        pub fn delete(service: &str, user: &str) {
            STORE
                .lock()
                .unwrap()
                .remove(&(service.to_string(), user.to_string()));
        }
    }

    /// The default (no env, no `key.env`) path end to end: keyring-minted
    /// passphrase, legacy migration, lost-entry refusal, and headless fallback.
    /// One sequential test because the store's availability toggle is global.
    #[cfg(any(target_os = "macos", target_os = "linux", windows))]
    #[test]
    fn keyring_default_wraps_migrates_and_never_regenerates() {
        if std::env::var_os(KEY_PASSPHRASE_ENV).is_some() {
            eprintln!("skipping: {KEY_PASSPHRASE_ENV} is set in this environment");
            return;
        }
        test_keyring::install();
        test_keyring::set_available(true);
        test_keyring::delete(KEYRING_SERVICE, KEYRING_ENTRY);

        // (a) First run: the key is created encrypted under a passphrase the
        // keyring minted — 32 random bytes, hex — and reloads with it.
        let dir = scratch_dir("keyring-fresh");
        let path = dir.join("identity.key");
        let id = DeviceIdentity::load_or_create(&path).unwrap();
        assert!(is_wrapped(&path), "default must be encrypted at rest");
        let pass = test_keyring::get(KEYRING_SERVICE, KEYRING_ENTRY).expect("entry minted");
        assert_eq!(pass.len(), 64);
        assert!(pass.bytes().all(|b| b.is_ascii_hexdigit()));
        let data = std::fs::read(&path).unwrap();
        assert_eq!(
            *unwrap_seed(&data, pass.as_bytes()).unwrap(),
            id.signing.to_bytes(),
            "file is wrapped under exactly the keyring passphrase"
        );
        let again = DeviceIdentity::load_or_create(&path).unwrap();
        assert_eq!(again.public_key_hex(), id.public_key_hex());
        assert_eq!(
            test_keyring::get(KEYRING_SERVICE, KEYRING_ENTRY).unwrap(),
            pass,
            "a later load reuses the entry, never re-mints"
        );

        // (b) Legacy plaintext key + keyring available → upgraded on load under
        // the keyring passphrase, same identity.
        let legacy_dir = scratch_dir("keyring-legacy");
        let legacy_path = legacy_dir.join("identity.key");
        let legacy = DeviceIdentity::generate().unwrap();
        std::fs::write(&legacy_path, hex::encode(legacy.signing.to_bytes())).unwrap();
        let loaded = DeviceIdentity::load_or_create(&legacy_path).unwrap();
        assert_eq!(loaded.public_key_hex(), legacy.public_key_hex());
        assert!(is_wrapped(&legacy_path), "legacy key migrated via keyring");
        assert_eq!(
            *unwrap_seed(&std::fs::read(&legacy_path).unwrap(), pass.as_bytes()).unwrap(),
            legacy.signing.to_bytes()
        );

        // (c) Keyring reachable but the entry is gone (and no env/key.env):
        // load FAILS, the file is untouched, and no replacement entry is minted
        // (that would be useless for this file and mask the loss).
        test_keyring::delete(KEYRING_SERVICE, KEYRING_ENTRY);
        let on_disk = std::fs::read(&path).unwrap();
        let err = DeviceIdentity::load_or_create(&path)
            .unwrap_err()
            .to_string();
        assert!(err.contains("no passphrase is available"), "got: {err}");
        assert_eq!(std::fs::read(&path).unwrap(), on_disk);
        assert!(
            test_keyring::get(KEYRING_SERVICE, KEYRING_ENTRY).is_none(),
            "unwrap path must be read-only on the keyring"
        );
        // Explicit sources still outrank the keyring: supplying the original
        // passphrase via key.env opens the file.
        write_key_env(&dir, &pass);
        let back = DeviceIdentity::load_or_create(&path).unwrap();
        assert_eq!(back.public_key_hex(), id.public_key_hex());
        std::fs::remove_file(dir.join("key.env")).unwrap();

        // (d) Keyring unavailable (headless) + wrapped file → fail, untouched.
        test_keyring::set_available(false);
        let err = DeviceIdentity::load_or_create(&path)
            .unwrap_err()
            .to_string();
        assert!(err.contains("keyring is unavailable"), "got: {err}");
        assert_eq!(std::fs::read(&path).unwrap(), on_disk);

        // (e) Keyring unavailable + no file → plaintext fallback; it still
        // starts, and reloads the same identity while still headless.
        let headless_dir = scratch_dir("keyring-headless");
        let headless_path = headless_dir.join("identity.key");
        let h = DeviceIdentity::load_or_create(&headless_path).unwrap();
        assert!(
            !is_wrapped(&headless_path),
            "headless fallback is plaintext"
        );
        assert_eq!(
            hex::decode(std::fs::read_to_string(&headless_path).unwrap().trim()).unwrap(),
            h.signing.to_bytes()
        );
        let h2 = DeviceIdentity::load_or_create(&headless_path).unwrap();
        assert_eq!(h2.public_key_hex(), h.public_key_hex());
        assert!(!is_wrapped(&headless_path));

        // (f) The keyring comes back → that plaintext key is upgraded on the next
        // load under a newly minted entry.
        test_keyring::set_available(true);
        let h3 = DeviceIdentity::load_or_create(&headless_path).unwrap();
        assert_eq!(h3.public_key_hex(), h.public_key_hex());
        assert!(is_wrapped(&headless_path));
        let minted = test_keyring::get(KEYRING_SERVICE, KEYRING_ENTRY).expect("re-minted");
        assert_ne!(minted, pass);
        assert_eq!(
            *unwrap_seed(&std::fs::read(&headless_path).unwrap(), minted.as_bytes()).unwrap(),
            h.signing.to_bytes()
        );

        test_keyring::delete(KEYRING_SERVICE, KEYRING_ENTRY);
        for d in [&dir, &legacy_dir, &headless_dir] {
            let _ = std::fs::remove_dir_all(d);
        }
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
