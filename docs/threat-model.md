# OpenReach — Threat Model

Scope: the OpenReach host agent, viewer, and self-hostable rendezvous (signaling +
device registry) with coturn (STUN/TURN). This documents assets, adversaries,
trust boundaries, the guarantees the design provides, and residual risks.

## Assets
- **Session content** — the host's screen frames, injected keyboard/mouse, clipboard,
  and transferred files. The most sensitive asset.
- **Device identity keys** — each device's long-lived ed25519 private key.
- **Account credentials** — rendezvous usernames/passwords and device bearer tokens.
- **Availability** — the ability to reach and control one's own machines.

## Trust boundaries
```
[Host machine]───DTLS-SRTP (E2EE)───[Viewer machine]
      │                                   │
      └──────── signaling (WSS) ──────────┘
                     │
        [Rendezvous + TURN — UNTRUSTED for content]
```
- The **host** and **viewer** endpoints are trusted (they hold the media keys).
- The **rendezvous server** and **TURN relay** are **untrusted with respect to session
  content**: they route signaling metadata and relay ciphertext, but never possess the
  DTLS-SRTP keys.

## Adversaries & mitigations

### A1. Passive network eavesdropper (incl. a malicious/compromised TURN relay)
- **Goal:** read screen/input/clipboard/files.
- **Mitigation:** all media and the data channel are **DTLS-SRTP / DTLS-SCTP**
  end-to-end encrypted between host and viewer. The relay only ever forwards
  ciphertext — **verified by an automated test** (`relay_only_sees_ciphertext`): a
  known plaintext canary sent over the data channel never appears in relayed bytes.
- **Residual:** the relay observes traffic *metadata* (volume, timing, endpoint
  mappings) and the signaling SDP (DTLS fingerprints, ICE candidates) — not content.

### A2. Malicious/compromised rendezvous server
- **Goal:** impersonate a host to a viewer (MITM), or read content.
- **Mitigation:** content is E2EE (A1), so the server cannot read it. **The host now
  proves its identity, bound to the session's DTLS fingerprint**, in its `HelloAck`
  (an ed25519 signature over `"openreach-access-proof-v2" || host_pubkey || 0x00 ||
  dtls_fingerprint`). A valid proof is **necessary but not sufficient**: the viewer
  additionally requires the proven identity to match **both** the device the user
  selected *and the key pinned for it* (`known_peers`) — a valid self-proof over the
  relay's *own* key is rejected because it doesn't match the pinned key. So a server
  that lies about the host's key is defeated (SAS/pin mismatch), and a full-DTLS-MITM
  relay is defeated on any **reconnect** (its own key ≠ the pinned key). A changed key
  is refused (`known_peers::trust_on_first_use`).
- **Residual:** a server that performs a *full* DTLS MITM (its own cert on both legs)
  can present a self-consistent proof over its own key/fingerprint; only the **SAS /
  QR out-of-band check** catches that on the very first pairing (the SAS reflects the
  actually-negotiated endpoints, so it differs under MITM). The new QR/PAKE pairing
  path removes this window entirely for enrolled devices.

### A3. Credential theft / brute force against the rendezvous
- **Mitigation:** passwords hashed with **Argon2id** (explicitly pinned params:
  64 MiB / t=3 / p=1); device tokens stored only as **SHA-256 hashes** (a DB leak
  yields neither passwords nor live tokens). **Per-IP rate limiting** (tower_governor)
  plus a **per-username lockout with exponential backoff** on repeated password
  failures (defeats IP-rotating credential stuffing that per-IP limits miss).
  **Registration is closed by default** (`OPENREACH_RZ_OPEN_REGISTRATION` must be
  explicitly enabled). TLS everywhere via Caddy/Cloudflare.
- **Residual:** no MFA yet (optional TOTP is a tracked item — but the account system
  is being superseded by the direct QR/PAKE pairing path, which removes server-side
  credentials entirely for that flow).

### A4. Unauthorized control of a host (the core risk of any remote-access tool)
- **Mitigation:** a viewer can only reach a host it is paired with; the device token
  authenticates the signaling channel, and the DTLS handshake + TOFU authenticate the
  peer. Every active session shows a **visible host indicator** (`★ REMOTE SESSION
  ACTIVE ★`; tray state in the UI).
- **Unattended-access gate (implemented, channel-bound):** a host with
  `require_authorization` accepts a session only from a viewer whose `Hello` carries a
  valid **access proof** — an ed25519 signature over
  `"openreach-access-proof-v2" || public_key || 0x00 || dtls_fingerprint` — *and* whose
  derived `device_id` is in the host's `authorized_keys` list. The signature proves the
  viewer holds the private key for the claimed identity (not a spoofable id claim), and
  the **DTLS-fingerprint binding ties the proof to this exact session**: a malicious
  rendezvous that MITMs the DTLS must present its own certificate to the host, so the
  fingerprint the host verifies no longer matches the one the viewer signed, and the
  proof is rejected (see `host::tests::authorize_accepts_bound_proof_and_rejects_mitm`).
  Enabled by placing device_ids in `~/.config/openreach/authorized_keys` (or
  `OPENREACH_AUTHORIZED_KEYS`), or with `OPENREACH_REQUIRE_AUTH=1`.

### A5. Stolen device / extracted identity key
- **Mitigation:** the identity private key is stored `0600` in the user config dir.
  Revoking a device (delete via the console / API) invalidates its tokens server-side.
- **Residual:** no at-rest passphrase encryption of the key in v1 (OS disk encryption is
  the assumed control). Passphrase-wrapping the key is a hardening item.

### A6. Malicious peer content (a compromised host or viewer)
- **Mitigation:** input injection is gated (view-only mode; unattended gating). File
  transfers are written to a user-chosen location; clipboard sync is loop-guarded.
- **Residual:** a trusted-but-compromised peer can do what a legitimate peer can — this
  is inherent to remote control; scope trust accordingly.

## Cryptography summary
- **Transport:** DTLS 1.2+ with SRTP (media) and SCTP-over-DTLS (data channel) —
  keys negotiated per session, never shared with relays.
- **Passwords:** Argon2id, pinned 64 MiB/t=3/p=1 (PHC). **Tokens:** random 256-bit,
  stored as SHA-256.
- **Device identity:** ed25519, encrypted at rest (Argon2id + XChaCha20-Poly1305) when
  a passphrase is set. **SAS:** SHA-256 over the sorted key pair → 6 digits. **Identity
  proofs** (both directions) are ed25519 signatures bound to the session DTLS fingerprint.

## Non-goals / assumptions
- Endpoints are not hardened against a fully compromised host OS (kernel-level malware
  on either machine defeats any userspace remote-access tool).
- The rendezvous operator runs the provided hardened config (TLS, rate limiting, closed
  registration) on a maintained VPS.

## Open hardening items (tracked)
1. QR/PAKE direct-pairing path (removes the A2 first-connect window and server-side
   credentials entirely for enrolled devices).
2. Hardware-backed identity keys (TPM / Apple Secure Enclave) — non-exportable, the
   strongest answer to A5.
3. Optional per-host password / TOTP MFA as a second factor.

*(Resolved:
 — A4 unattended-access proof bound to the session DTLS fingerprint;
 — A2 host identity proof bound to DTLS on the interactive path, with TOFU pinning the
   proven key;
 — A5 identity key encrypted at rest (Argon2id + XChaCha20-Poly1305) + zeroized + Windows ACL;
 — A3 registration closed by default, Argon2id params pinned, per-username login lockout.)*
