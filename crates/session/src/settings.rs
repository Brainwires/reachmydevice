//! Encrypted, device-local key→value settings store for the host daemon.
//!
//! Holds secret host settings — the rendezvous `token`, the connection
//! `password`, and any future keys — encrypted at rest under a key derived from
//! the device identity (HKDF; see [`DeviceIdentity::derive_subkey`]). It therefore
//! needs no separate passphrase and is as protected as the identity key file
//! itself. Managed from the CLI via `rmdd set <key> <value>`.
//!
//! On-disk format: `MAGIC ‖ nonce(24) ‖ XChaCha20-Poly1305(serde_json(map))`.

use crate::identity::{restrict_perms, DeviceIdentity};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// HKDF info string binding the store key to its purpose (domain separation).
const SETTINGS_INFO: &[u8] = b"rmd-settings-v1";
/// File magic for the encrypted settings blob.
const MAGIC: &[u8; 4] = b"RSS1";
const NONCE_LEN: usize = 24;

/// Well-known setting keys.
pub const KEY_TOKEN: &str = "token";
pub const KEY_PASSWORD: &str = "password";
/// Rendezvous signaling WebSocket URL (e.g. `wss://reachmy.dev/ws`). When set,
/// the host uses rendezvous mode with the stored `token`.
pub const KEY_RENDEZVOUS_URL: &str = "rendezvous_url";

/// Video encode parameters. Each overrides its `RMD_*` env default when set, so
/// they can be tuned persistently via `rmdd set <key> <value>` (e.g.
/// `rmdd set fps 20` on a weak link).
pub const KEY_FPS: &str = "fps";
pub const KEY_WIDTH: &str = "width";
pub const KEY_HEIGHT: &str = "height";
pub const KEY_BITRATE: &str = "bitrate";

/// In-memory view of the settings, persisted as one encrypted blob.
#[derive(Default)]
pub struct SettingsStore {
    map: BTreeMap<String, String>,
}

impl SettingsStore {
    /// Default store path: `<config_dir>/settings.enc` (alongside `identity.key`).
    pub fn default_path() -> PathBuf {
        config_dir().join("settings.enc")
    }

    /// Load and decrypt the store at `path` using a key derived from `identity`.
    /// A missing file yields an empty store; a present-but-undecryptable file is
    /// an error (wrong identity or corruption).
    pub fn load(identity: &DeviceIdentity, path: &Path) -> anyhow::Result<Self> {
        let blob = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(e.into()),
        };
        Ok(Self {
            map: decrypt(identity, &blob)?,
        })
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.map.get(key).map(String::as_str)
    }

    pub fn set(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.map.insert(key.into(), value.into());
    }

    /// Remove `key`; returns whether it was present.
    pub fn remove(&mut self, key: &str) -> bool {
        self.map.remove(key).is_some()
    }

    /// The setting keys currently stored (sorted). Values are never exposed here.
    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.map.keys().map(String::as_str)
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Encrypt and atomically write the store to `path` (dir created; file 0600).
    pub fn save(&self, identity: &DeviceIdentity, path: &Path) -> anyhow::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let blob = encrypt(identity, &self.map)?;
        // Write to a sibling temp file then rename, so a crash never leaves a
        // half-written store.
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, &blob)?;
        restrict_perms(&tmp)?;
        std::fs::rename(&tmp, path)?;
        restrict_perms(path)?;
        Ok(())
    }
}

fn encrypt(identity: &DeviceIdentity, map: &BTreeMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let key = identity.derive_subkey(SETTINGS_INFO);
    let cipher = XChaCha20Poly1305::new(key.as_ref().into());
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce).map_err(|e| anyhow::anyhow!("getrandom: {e}"))?;
    // The plaintext holds secrets — scrub it after encrypting.
    let pt = Zeroizing::new(serde_json::to_vec(map)?);
    let ct = cipher
        .encrypt(XNonce::from_slice(&nonce), pt.as_slice())
        .map_err(|_| anyhow::anyhow!("settings encryption failed"))?;
    let mut out = Vec::with_capacity(4 + NONCE_LEN + ct.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

fn decrypt(identity: &DeviceIdentity, blob: &[u8]) -> anyhow::Result<BTreeMap<String, String>> {
    let header = 4 + NONCE_LEN;
    anyhow::ensure!(
        blob.len() > header && &blob[..4] == MAGIC,
        "not a settings file"
    );
    let nonce = &blob[4..header];
    let ct = &blob[header..];
    let key = identity.derive_subkey(SETTINGS_INFO);
    let cipher = XChaCha20Poly1305::new(key.as_ref().into());
    let pt = Zeroizing::new(
        cipher
            .decrypt(XNonce::from_slice(nonce), ct)
            .map_err(|_| anyhow::anyhow!("cannot decrypt settings (wrong identity or corrupt file)"))?,
    );
    Ok(serde_json::from_slice(&pt)?)
}

/// Config dir mirroring the host's identity/token location: `$XDG_CONFIG_HOME/rmd`
/// if set, else `$HOME/.config/rmd`.
fn config_dir() -> PathBuf {
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        if !xdg.is_empty() {
            return PathBuf::from(xdg).join("rmd");
        }
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".config").join("rmd")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::DeviceIdentity;

    fn temp_path(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("rmd-settings-{}-{}.enc", std::process::id(), tag))
    }

    #[test]
    fn roundtrip_and_wrong_identity_fails() {
        let id = DeviceIdentity::generate().unwrap();
        let path = temp_path("roundtrip");
        let _ = std::fs::remove_file(&path);

        let mut s = SettingsStore::default();
        s.set(KEY_TOKEN, "tok-123");
        s.set(KEY_PASSWORD, "taco");
        s.save(&id, &path).unwrap();

        // Same identity → values decrypt.
        let loaded = SettingsStore::load(&id, &path).unwrap();
        assert_eq!(loaded.get(KEY_TOKEN), Some("tok-123"));
        assert_eq!(loaded.get(KEY_PASSWORD), Some("taco"));
        let keys: Vec<&str> = loaded.keys().collect();
        assert_eq!(keys, vec![KEY_PASSWORD, KEY_TOKEN]); // BTreeMap → sorted

        // A different identity cannot decrypt it.
        let other = DeviceIdentity::generate().unwrap();
        assert!(SettingsStore::load(&other, &path).is_err());

        // The blob is not plaintext.
        let raw = std::fs::read(&path).unwrap();
        assert!(!raw.windows(4).any(|w| w == b"taco"));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn missing_file_is_empty_and_remove_works() {
        let id = DeviceIdentity::generate().unwrap();
        let path = temp_path("missing");
        let _ = std::fs::remove_file(&path);

        let mut s = SettingsStore::load(&id, &path).unwrap();
        assert!(s.is_empty());
        s.set(KEY_PASSWORD, "x");
        assert!(s.remove(KEY_PASSWORD));
        assert!(!s.remove(KEY_PASSWORD));
    }

    #[cfg(unix)]
    #[test]
    fn saved_file_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let id = DeviceIdentity::generate().unwrap();
        let path = temp_path("perms");
        let _ = std::fs::remove_file(&path);
        let mut s = SettingsStore::default();
        s.set(KEY_TOKEN, "t");
        s.save(&id, &path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let _ = std::fs::remove_file(&path);
    }
}
