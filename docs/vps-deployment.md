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
WebSocket at `wss://rmd.example.com/ws?token=<token>`.

**Registration.** The **first** account always succeeds even with registration
closed (an empty server must be bootstrappable) — so you do **not** need to force
`RMD_RZ_OPEN_REGISTRATION=true` to create it; the default (closed) is correct.
Once any account exists, new sign-ups obey the `open_registration` setting
(default off). That setting is stored in the DB (seeded from
`RMD_RZ_OPEN_REGISTRATION` on first boot) and can be flipped at runtime without a
redeploy, if you set an admin token:
```sh
# server: RMD_RZ_ADMIN_TOKEN=<a-strong-secret>
curl -s https://rmd.example.com/api/registration            # {"open":false}
curl -X POST https://rmd.example.com/api/admin/registration \
  -H "authorization: Bearer $RMD_RZ_ADMIN_TOKEN" \
  -H 'content-type: application/json' -d '{"enabled":true}'  # open it to add users
```
Leave `RMD_RZ_ADMIN_TOKEN` unset to disable the admin API entirely.

## Security posture (hardened defaults)
- **TLS everywhere** via Caddy/ACME; port 80 is ACME/redirect only.
- **Argon2** password hashing (bounded by a concurrency semaphore so an auth flood
  can't OOM a small box); device tokens stored only as SHA-256 hashes, with an
  expiry (`RMD_RZ_TOKEN_TTL`, default 90d) and rotation on re-registration.
- **Trusted-proxy client IP** — behind a proxy/tunnel, set `RMD_TRUSTED_PROXY_HEADER`
  (e.g. `cf-connecting-ip`, `x-real-ip`) so the rate limiter + auth-failure logging
  use the real client IP and a spoofed `X-Forwarded-For` can't dodge them.
- **Per-IP rate limiting** (`tower_governor`, 5 req/s, burst 20) keyed on that
  trust-resolved client IP.
- **Tokens via `Authorization: Bearer`** on `/api/ice`; one-time tickets
  (`GET /api/ws-ticket`) for `/ws` — bearer tokens stay out of URLs/logs.
- **First-account bootstrap gated** by `RMD_RZ_BOOTSTRAP_TOKEN` on any
  internet-reachable deployment (prevents a stranger claiming the empty instance).
- **TURN uses a shared-secret** (`use-auth-secret`); the relay only forwards
  **DTLS-SRTP ciphertext** — it cannot read screen/input/file content. Minted
  credentials are user-bound and short-lived (`RMD_TURN_TTL`, default 600s).
- Rendezvous runs as a **non-root** user in the container; SQLite on a volume.

### Harden coturn itself (required for a public relay)
The relay must not become an open SSRF proxy. Configure coturn with:
- **`--denied-peer-ip`** for every internal range so a credential holder can't relay
  to them: RFC1918 (`10/8`, `172.16/12`, `192.168/16`), loopback (`127/8`, `::1`),
  link-local **incl. the cloud-metadata address `169.254.0.0/16`**, multicast
  (`224.0.0.0/4`), CGNAT (`100.64/10`), and IPv6 ULA/link-local (`fc00::/7`,
  `fe80::/10`). (Modern coturn already denies loopback/multicast by default.)
- **`--unauthorized-ratelimit`** (+ `--unauthorized-ratelimit-rps`) to throttle
  per-source 401 floods (credential-guessing / reflection abuse) — coturn-native,
  no log-scraping needed. Prefer this over a fail2ban jail: coturn's default logs
  don't carry the client IP.

### Running behind an existing ingress (not the packaged Caddy)
If the host already runs a reverse proxy / Cloudflare tunnel and its own coturn,
run **only** the `rmd-rendezvous` container (bound to loopback, e.g.
`127.0.0.1:8090`) behind that ingress and point `RMD_TURN_SECRET`/`RMD_TURN_HOST`
at the existing coturn (its `--static-auth-secret` **must equal** `RMD_TURN_SECRET`).
Set `RMD_TRUSTED_PROXY_HEADER` to whatever that ingress sets (`cf-connecting-ip` for
Cloudflare), and strip query strings from its access logs.

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

## Auth hardening (fail2ban, optional)

The rendezvous already rate-limits per IP and throttles per-account logins. For
an extra layer, it logs a stable line on every auth failure
(`WARN rmd_security: auth-fail ip=… path=… method=…`), and
[`deploy/fail2ban/`](../deploy/fail2ban/README.md) ships a ready filter + jail to
ban abusive IPs. This hardens the **auth-abuse** surface only — it is not a
volumetric-DDoS mitigation (a flood saturates the link upstream of any host
firewall). Behind Cloudflare, ban at the edge (fail2ban's `cloudflare` action),
since a host `iptables` ban would only hit the proxy — see the README.

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

## Relay entitlement (pluggable; default open)

`GET /api/ice` asks a **relay-entitlement policy** whether the requesting user may
use TURN before minting credentials. The open-source default
([`crates/entitlement`](../crates/entitlement)) is `AllowAll` — every registered
device may relay, exactly as before — so self-hosting needs no configuration and
sees no behavior change.

The policy is a seam, not a fork: `AppState::new(pool, cfg, entitlement)` takes an
`Arc<dyn RelayEntitlement>`, and `router_with(state, extra)` merges extra routes.
A downstream build can inject its own policy (e.g. gate relay on a paid
subscription) without modifying this crate. When relay is withheld the endpoint
still returns STUN so sessions stay peer-to-peer, and annotates the body:

```json
{ "ice_servers": [ /* stun only */ ], "relay": { "allowed": false, "reason": "no_subscription" } }
```

Brainwires' hosted service uses such a policy; that billing layer is a **private,
separately-licensed component** and is not part of this repository.
