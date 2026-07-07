# fail2ban integration (rendezvous auth hardening)

Optional defense-in-depth: ban source IPs that repeatedly fail authentication
against the rendezvous. The server emits a stable log line per failure, and the
filter/jail here turn that into firewall bans.

**Scope — read this first.** This hardens the **auth-abuse** surface (bad
device tokens / passwords hammering the API and `/ws`). It is layered on top of
the built-in per-IP rate limiter and per-account login throttle. It is **not** a
mitigation for **volumetric (bandwidth) DDoS** — a flood saturates the network
link upstream of any host firewall, and dropping packets locally doesn't reclaim
the bandwidth. For that you need upstream scrubbing (Cloudflare / your provider),
or hide device IPs by forcing the TURN relay (`RMD_TURN_ENABLED`).

## What it matches

The rendezvous logs one line per auth failure (the `rmd_security` target):

```
2026-07-07T22:58:31.544736Z  WARN rmd_security: auth-fail ip=203.0.113.7 path=/ws method=GET
```

`ip=` is the real client IP, taken from `CF-Connecting-IP` / `X-Forwarded-For`
when behind a proxy, else the socket peer.

## Install

```bash
sudo cp deploy/fail2ban/filter.d/rmd-rendezvous.conf /etc/fail2ban/filter.d/
sudo cp deploy/fail2ban/jail.d/rmd-rendezvous.conf   /etc/fail2ban/jail.d/
# Point the jail's logpath at the rendezvous log. With the Docker json-file
# driver, the exact path is:
docker inspect --format '{{.LogPath}}' rmd-rzv
# put that in logpath, then:
sudo systemctl reload fail2ban
sudo fail2ban-client status rmd-rendezvous
```

Test the regex against real logs before enabling:

```bash
fail2ban-regex "$(docker inspect --format '{{.LogPath}}' rmd-rzv)" \
  /etc/fail2ban/filter.d/rmd-rendezvous.conf
```

## Important: banning behind a reverse proxy / Cloudflare

If the rendezvous is fronted by **Cloudflare or any reverse proxy** (the default
deployment is), the connection reaching the host comes from the **proxy**, not
the client — so a host `iptables` ban of the client's IP does **nothing**. Use
one of:

- **Cloudflare action** (recommended for the CF-fronted deployment): set
  `action = cloudflare` in the jail and provide `cfuser`/`cftoken` (a scoped API
  token) in `/etc/fail2ban/action.d/cloudflare.conf`. fail2ban then blocks the
  IP at Cloudflare's edge, where it actually connects.
- **Block at the proxy** (Caddy/nginx) instead of the host firewall.
- **iptables** works directly only when the rendezvous is **exposed without a
  proxy** (the client connects to the host).

Pick the layer that actually sees the client's traffic — that's the one where a
ban has effect.
