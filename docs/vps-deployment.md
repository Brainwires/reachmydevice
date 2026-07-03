# VPS deployment — OpenReach rendezvous

The rendezvous unit is one `docker-compose` with three services, sized for a
**1 vCPU / 1 GB** VPS:

| service | role |
|---------|------|
| `caddy` | TLS termination + reverse proxy, **automatic Let's Encrypt/ACME** certs |
| `rendezvous` | signaling + device registry (axum + SQLite), per-IP rate limited |
| `coturn` | STUN + TURN relay for NAT traversal |

Files live in [`deploy/`](../deploy).

## 1. DNS
Point an A/AAAA record (e.g. `openreach.example.com`) at the VPS public IP.

## 2. Configure
```sh
cd deploy
cp .env.example .env
# edit .env:
#   OPENREACH_DOMAIN=openreach.example.com
#   TURN_SECRET=$(openssl rand -hex 32)
```

## 3. Firewall / ports
Open on the VPS:
- **443/tcp** and **80/tcp** — HTTPS API + WebSocket (Caddy; 80 is for ACME).
- **3478/udp + 3478/tcp** — STUN/TURN.
- **49160–49200/udp** — TURN relay range (matches `coturn` `--min-port/--max-port`).

## 4. Launch
```sh
docker compose up -d
docker compose logs -f rendezvous
curl https://openreach.example.com/health   # -> {"status":"ok",...}
```

## 5. Create your account
```sh
curl -X POST https://openreach.example.com/api/register \
  -H 'content-type: application/json' \
  -d '{"username":"me","password":"a-strong-password"}'
```
The host and viewer apps register their own device + obtain a token on first run
(Phase 3 wires the onboarding UI); the token authenticates the signaling
WebSocket at `wss://openreach.example.com/ws?token=<token>`. Set
`OPENREACH_RZ_OPEN_REGISTRATION=false` and redeploy once your account exists.

## Security posture (hardened defaults)
- **TLS everywhere** via Caddy/ACME; port 80 is ACME/redirect only.
- **Argon2** password hashing; device tokens stored only as SHA-256 hashes.
- **Per-IP rate limiting** (`tower_governor`, 5 req/s, burst 20) on all routes —
  throttles credential stuffing and signaling floods.
- **TURN uses a shared-secret** (`use-auth-secret`); the relay only forwards
  **DTLS-SRTP ciphertext** — it cannot read screen/input/file content.
- Rendezvous runs as a **non-root** user in the container; SQLite on a volume.

## Backups
State is `rendezvous_data:/data/openreach.db` (SQLite). Snapshot the volume or
run `sqlite3 openreach.db .backup` on a schedule.

## Notes / limitations (v1)
- `coturn` uses `network_mode: host` because the TURN relay needs the host UDP
  port range; standard on a single-tenant VPS.
- Short-lived TURN credential minting (HMAC of the shared secret) is the planned
  next step (`/api/turn-credentials`); clients currently take STUN/TURN config at
  connect.
- Postgres is an optional swap for SQLite at higher scale (sqlx supports both).
