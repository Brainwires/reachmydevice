-- Passkeys (WebAuthn credentials) + console session tokens.

-- A registered passkey for a user. `passkey` holds the serialized webauthn-rs
-- Passkey (public key + sign counter + metadata); `credential_id` is the raw
-- credential id (base64url) used to look it up at authentication time.
CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id            INTEGER PRIMARY KEY,
    user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id TEXT    NOT NULL UNIQUE,
    passkey       TEXT    NOT NULL,
    name          TEXT,
    created_at    INTEGER NOT NULL,
    last_used_at  INTEGER
);
CREATE INDEX IF NOT EXISTS idx_webauthn_user ON webauthn_credentials(user_id);

-- Opaque, hashed console session tokens. Minted on passkey login (a passkey has
-- no password to re-send), then presented by the web console as
-- `Authorization: Bearer <token>`. Only the SHA-256 hash is stored, like device
-- tokens — a DB leak never reveals a live session token.
CREATE TABLE IF NOT EXISTS user_sessions (
    id         INTEGER PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT    NOT NULL UNIQUE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_user_sessions_hash ON user_sessions(token_hash);
