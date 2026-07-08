-- Runtime-adjustable server settings (key/value), so operator-tunable flags
-- survive restarts and can be inspected/flipped without a redeploy. Seeded from
-- the corresponding env defaults on first boot (see db::seed_settings).
--
-- Current keys:
--   open_registration = 'true' | 'false'   -- whether /api/register accepts new
--                                              accounts (the very first account
--                                              always bootstraps regardless).
CREATE TABLE settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
