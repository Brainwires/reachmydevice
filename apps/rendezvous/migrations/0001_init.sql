-- ReachMyDevice rendezvous schema (Phase 2).
-- Accounts own devices; devices authenticate with bearer tokens. Device identity
-- is a long-lived keypair generated on the client's first run; the server stores
-- the public key for TOFU display and never holds any session key material.

PRAGMA foreign_keys = ON;

-- Registered account owners.
CREATE TABLE users (
    id            INTEGER PRIMARY KEY,
    username      TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,          -- Argon2 PHC string
    created_at    INTEGER NOT NULL           -- unix seconds
);

-- Hosts / viewers owned by a user.
CREATE TABLE devices (
    id          INTEGER PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id   TEXT    NOT NULL UNIQUE,      -- client-generated stable id (public-key fingerprint)
    name        TEXT    NOT NULL,
    public_key  TEXT    NOT NULL,             -- device identity public key (base64), for TOFU
    role        TEXT    NOT NULL DEFAULT 'both', -- 'host' | 'viewer' | 'both'
    created_at  INTEGER NOT NULL,
    last_seen   INTEGER
);
CREATE INDEX idx_devices_user ON devices(user_id);

-- Opaque bearer tokens a device presents to authenticate. Only the hash is stored.
CREATE TABLE device_tokens (
    id         INTEGER PRIMARY KEY,
    device_pk  INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    token_hash TEXT    NOT NULL UNIQUE,       -- SHA-256 hex of the bearer token
    created_at INTEGER NOT NULL,
    expires_at INTEGER                        -- NULL = no expiry
);
CREATE INDEX idx_device_tokens_hash ON device_tokens(token_hash);
