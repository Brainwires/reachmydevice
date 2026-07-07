# VPS deployment — ReachMyDevice rendezvous

The rendezvous unit is one `docker-compose` with three services, sized for a
**1 vCPU / 1 GB** VPS:

| service | role |
|---------|------|
| `caddy` | TLS termination + reverse proxy, **automatic Let's Encrypt/ACME** certs |
| `rendezvous` | signaling + device registry (axum + SQLite), per-IP rate limited |
| `coturn` | STUN + TURN relay for NAT traversal |

Files live in [`deploy/`](../deploy).

## 1. DNS
Point an A/AAAA record (e.g. `rmd.example.com`) at the VPS public IP.

## 2. Configure
```sh
cd deploy
cp .env.example .env
# edit .env:
#   RMD_DOMAIN=rmd.example.com
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
curl https://rmd.example.com/health   # -> {"status":"ok",...}
```

## 5. Create your account
```sh
curl -X POST https://rmd.example.com/api/register \
  -H 'content-type: application/json' \
  -d '{"username":"me","password":"a-strong-password"}'
```
The host and viewer apps register their own device + obtain a token on first run
(Phase 3 wires the onboarding UI); the token authenticates the signaling
WebSocket at `wss://rmd.example.com/ws?token=<token>`. Set
`RMD_RZ_OPEN_REGISTRATION=false` and redeploy once your account exists.

## Security posture (hardened defaults)
- **TLS everywhere** via Caddy/ACME; port 80 is ACME/redirect only.
- **Argon2** password hashing; device tokens stored only as SHA-256 hashes.
- **Per-IP rate limiting** (`tower_governor`, 5 req/s, burst 20) on all routes —
  throttles credential stuffing and signaling floods.
- **TURN uses a shared-secret** (`use-auth-secret`); the relay only forwards
  **DTLS-SRTP ciphertext** — it cannot read screen/input/file content.
- Rendezvous runs as a **non-root** user in the container; SQLite on a volume.

## Backups
State is `rendezvous_data:/data/rmd.db` (SQLite). Snapshot the volume or
run `sqlite3 rmd.db .backup` on a schedule.

## Firewall — open the TURN ports at the PROVIDER, not just the OS

The relay only works if inbound UDP reaches coturn. On a cloud VPS there are
usually **two** firewalls; a host `ufw`/`iptables` allow is not enough if the
provider's firewall (e.g. **IONOS Cloud Panel → Network → Firewall Policies**,
AWS security groups, etc.) drops the port. Open, inbound, from any source:

| Proto | Port(s)       | Purpose                     |
|-------|---------------|-----------------------------|
| UDP   | `3478`        | STUN / TURN                 |
| TCP   | `3478`        | TURN-over-TCP fallback      |
| UDP   | `49160-49200` | TURN relay range            |

Verify from an external host: a STUN Binding to `<ip>:3478` should get a response.
If it times out while coturn answers locally, the provider firewall is the cause.

Set `RMD_TURN_HOST` / `RMD_TURN_EXTERNAL_IP` to the VPS's **direct** public IP —
a Cloudflare-proxied `RMD_DOMAIN` never reaches the UDP relay.

## Notes / limitations (v1)
- `coturn` uses `network_mode: host` because the TURN relay needs the host UDP
  port range; standard on a single-tenant VPS.
- **TURN relay is OFF by default** and controlled entirely by the relay operator.
  It's enabled only with `RMD_TURN_ENABLED=1` **and** `RMD_TURN_SECRET` +
  `RMD_TURN_HOST` set on the rendezvous. Otherwise `/api/ice` returns STUN-only:
  connections stay **peer-to-peer** and no media touches this server. Enable it
  only if you accept that relayed media (the fallback for peers that can't
  connect directly) flows through — and uses the bandwidth of — this server.
  The startup log states which mode is active.
- **Ephemeral TURN credentials** (when enabled) are minted by the rendezvous at
  `GET /api/ice` (device-token auth): HMAC-SHA1 of the shared secret over a
  short-lived `<expiry>:rmd` username. The host, native viewer, and browser
  viewer all fetch it.
- Postgres is an optional swap for SQLite at higher scale (sqlx supports both).
