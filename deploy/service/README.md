# Running the ReachMyDevice host as a service (unattended access)

The host agent can run as a background service so a machine is reachable without
someone logged in and clicking. It authenticates to your rendezvous with a device
**token** (create the device in the web console) — treat the token like a password.

**Quick install:** `./deploy/install-host.sh` builds the host, installs the binary
to `~/.local/bin`, drops the right service unit (systemd user service / launchd
agent), seeds `~/.config/rmd` (env template + `authorized_keys`), and prints
the enable steps. Re-run it to upgrade. The manual steps below are the same thing
by hand.

- **Linux (systemd, per-user):** `rmd-host.service` + `rmd-host.env.example`.
  Runs in your graphical session (needs `DISPLAY` for X11 capture/input). Enable
  lingering so it starts at boot. See the header of the `.service` file.
- **macOS (launchd agent):** `com.brainwires.rmd-host.plist`. Grant Screen
  Recording + Accessibility to the binary (`docs/macos-permissions.md`).
- **Windows (service):** planned — the DXGI/SendInput backend + a Windows service
  wrapper are on the roadmap.

## Unattended access (authorize devices)

An always-on host should **not** accept just anyone who completes the handshake.
Enable the access gate so only pre-authorized devices connect:

1. On each viewer, note its **device_id** (shown in the app and the web console).
2. On the host, add those ids — one per line — to
   `~/.config/rmd/authorized_keys` (or point `RMD_AUTHORIZED_KEYS`
   elsewhere). Its presence enables enforcement automatically; you can also force
   it with `RMD_REQUIRE_AUTH=1`.
3. The host now verifies each viewer's signed **access proof** (ed25519) and
   rejects any device_id not on the list. See the threat model (A4) for the
   guarantee and its one residual (DTLS-fingerprint binding is the next step).

Every active session also shows a visible indicator (`★ REMOTE SESSION ACTIVE ★`
and the optional tray). Keep the device token and `authorized_keys` protected.
