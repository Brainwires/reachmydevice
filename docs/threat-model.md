# Threat model (Phase 5 — placeholder)

Full writeup lands in Phase 5. Invariants asserted from day one:
- Rendezvous/TURN servers see **only ciphertext** (DTLS-SRTP E2EE); they cannot read session content.
- Device identity is a long-lived keypair; viewer↔host trust is established via short-auth-string/PIN (TOFU).
- Passwords hashed with Argon2; devices authenticate with tokens.
- Unattended access is explicitly gated (per-host password or pre-authorized viewer keys).
