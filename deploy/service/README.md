# Running the OpenReach host as a service (unattended access)

The host agent can run as a background service so a machine is reachable without
someone logged in and clicking. It authenticates to your rendezvous with a device
**token** (create the device in the web console) — treat the token like a password.

- **Linux (systemd, per-user):** `openreach-host.service` + `openreach-host.env.example`.
  Runs in your graphical session (needs `DISPLAY` for X11 capture/input). Enable
  lingering so it starts at boot. See the header of the `.service` file.
- **macOS (launchd agent):** `com.brainwires.openreach-host.plist`. Grant Screen
  Recording + Accessibility to the binary (`docs/macos-permissions.md`).
- **Windows (service):** planned — the DXGI/SendInput backend + a Windows service
  wrapper are on the roadmap.

Every active session shows a visible indicator; unattended-access gating (per-host
password / pre-authorized viewer keys) is being completed (see the threat model).
