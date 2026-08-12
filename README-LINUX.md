# Running ReachMyDevice headless on Linux (GNOME / Wayland)

How to make a Linux box a reliable **remote-desktop host** that keeps working when
the physical monitor is unplugged — or when it boots with no monitor at all.

This guide exists because getting there on **GNOME Wayland** means defeating *four*
independent traps, each at a different layer of the stack. If your remote session
works while a monitor is attached but dies the moment you unplug it (or after a
disconnect/reconnect while headless), this is for you.

> Tested on Ubuntu with GNOME Shell / mutter **50.1**, GDM **50.1**, Intel **i915**,
> kernel driving two HDMI outputs. The concepts apply to any GNOME/Wayland host.

---

## TL;DR

1. **Never let the desktop go headless.** Keep a **dummy HDMI "dongle"** (a cheap
   EDID emulator plug) in a spare port, *always*. A connected output = a
   framebuffer to capture.
2. **Force an encoder-safe resolution.** Many 4K dummy dongles default to
   **4096×2160**, which is **wider than the H.264 encoder's 3840 limit** → every
   frame is rejected. Pin the dongle to something **≤ 3840 wide** (we use
   **1440×900**, 16:10).
3. **Mirror both outputs** at that resolution and make the dongle the **primary /
   capture target**, so the remote view is constant whether the real monitor is
   present or not.
4. **Teach GNOME a layout for *every* monitor combination** (both-plugged *and*
   dongle-only) — GNOME picks a saved layout per connected-monitor set.
5. **Give the GDM login screen the same layout** via **`/etc/xdg/monitors.xml`**
   (the modern GDM greeter runs from an ephemeral home, so the old
   `~gdm/.config` trick no longer works).

---

## Why it breaks — the four traps

### Trap 1 — No monitor, no framebuffer (the headless problem)
On Wayland, if the compositor has **no connected output**, it allocates **no
framebuffer**. There is then literally nothing to capture, regardless of the
capture API. Unplug the only monitor and the remote desktop has nothing to show;
worse, the GNOME session can wedge until a display returns.

**Fix:** keep a **dummy HDMI dongle** permanently plugged into a second port. It
presents an EDID like a real monitor, so there is *always* a connected output and
a live framebuffer — you never enter "headless" at all.

### Trap 2 — A 4K dongle exceeds the H.264 encoder's limit
This is the subtle one that looks like everything else. Capture *starts* fine on
the dongle, then every frame fails to encode with:

```
openh264 encode: ... User Message: "Encoder max resolution 3840x2160 horizontal or 2160x3840 vertical"
PipeWire negotiated video format width=4096 height=2160
```

Many dummy dongles emulate **4096×2160**, and **4096 > 3840**, so OpenH264 rejects
the frames — the viewer connects, sees nothing, and drops. Your *real* monitor
(e.g. 2560×1440) is under the limit, which is exactly why it works when plugged in
and dies when only the dongle is left.

**Fix:** run the dongle at a resolution **≤ 3840 wide**. We use **1440×900**
(16:10, matches how the physical panel is run). 1920×1080, 1680×1050, 2560×1440,
3840×2160 all work too — anything ≤ 3840 wide.

> **Underlying code fix (TODO in rmdd):** the Wayland/mutter capture path should
> downscale/clamp frames to the encoder's max before encoding (the X11 path
> already area-downscales to the configured size). With that, *any* display
> resolution would "just work" and Trap 2 disappears. Until then, force the mode.

### Trap 3 — GNOME saves a layout *per monitor set*
mutter stores display layouts in `~/.config/monitors.xml`, one `<configuration>`
per **set of connected monitors**. A layout saved for "dongle + real monitor" does
**not** apply when only the dongle is connected — GNOME auto-generates a fresh
config for that set, and picks the dongle's **preferred** mode… which is 4096×2160
(back to Trap 2).

**Fix:** save a layout for **both** combinations — "both plugged" *and*
"dongle only" — each pinned to your safe resolution.

### Trap 4 — The GDM login screen has its own (ephemeral) config
The greeter runs as the `gdm` user with a **separate** monitor config from your
session, and GNOME **deliberately does not** sync your session's display settings
to it. Historically you copied `~/.config/monitors.xml` to
`/var/lib/gdm3/.config/monitors.xml`. **That no longer works on recent GDM**
(≈ GNOME 47+): the greeter runs from an **ephemeral tmpfs home**
(`/run/gdm3/home/gdm-greeter`, empty every boot), so `~gdm/.config` is never read.

**Fix:** install the layout at the **system XDG fallback**
**`/etc/xdg/monitors.xml`**. With no per-user config, the greeter's mutter reads
`/etc/xdg`. Your own session still uses `~/.config/monitors.xml` (user config
wins), so this only affects the login screen.

### Aside — GRUB visibility (not really fixable to "both")
On **UEFI**, GRUB draws on a **single** firmware framebuffer — there is no mirror
at the bootloader stage, so "GRUB on both monitors" isn't achievable. And on most
distros the menu is **hidden** by default (`GRUB_TIMEOUT_STYLE=hidden`,
`GRUB_TIMEOUT=0`) — that's usually why you "don't see GRUB," not the displays. See
step 5 to make the menu appear.

---

## The fix, step by step

### 0. Identify your connectors

```bash
for d in /sys/class/drm/card*-*/; do
  n=$(basename "$d")
  printf '%-24s status=%-13s mode=%s\n' "$n" "$(cat "$d/status")" "$(head -1 "$d/modes")"
done
```

You'll see kernel names like `card1-HDMI-A-1` (the DRM/kernel name is `HDMI-A-1`;
mutter/GNOME calls it `HDMI-1`). Note which is the **dongle** (often a generic
vendor and a 4096×2160 / 3840×2160 mode) and which is the **real panel**. In this
guide:

| Role         | Kernel name  | GNOME name | Notes                         |
|--------------|--------------|------------|-------------------------------|
| Dummy dongle | `HDMI-A-1`   | `HDMI-1`   | EDID emulator, defaults to 4K |
| Real monitor | `HDMI-A-2`   | `HDMI-2`   | e.g. AOC Q32V3WG5, 2560×1440  |

### 1. Plug in the dongle (and leave it)

Put the dummy HDMI dongle in a spare port and keep it there. This alone kills
Trap 1 — the machine is never headless.

### 2. Pick an encoder-safe resolution the dongle can do

List the dongle's advertised modes and choose one **≤ 3840 wide** (16:10 or 16:9):

```bash
sort -u /sys/class/drm/card1-HDMI-A-1/modes
```

We use **1440×900** (16:10, advertised by the dongle). If your dongle doesn't
advertise the exact mode you want, you can either pick one it does, or force one
with a kernel param (`video=HDMI-A-1:1680x1050@60`) — but note mutter often
overrides `video=` on hotplug, so the `monitors.xml` route below is more reliable.

### 3. Configure mirror + a dongle-only fallback

**Easy way (GUI):** *Settings → Displays* → set **Mirror**, choose **1440×900**,
make the dongle primary → *Apply*. Then unplug the real monitor and set the dongle
to 1440×900 again (this saves the "dongle-only" layout). Re-plug to restore mirror.

**Headless/automated way:** use mutter's D-Bus `ApplyMonitorsConfig`
(method `2` = persistent, writes `~/.config/monitors.xml`). A ready-made Python
helper is in the [Appendix](#appendix-applymonitorsconfig-helper). Run it once with
both plugged (mirror), then once with only the dongle (fallback).

You should end up with `~/.config/monitors.xml` containing (at least) **two**
configurations — one listing both connectors, one listing the dongle alone — both
at 1440×900. Example dongle-only block:

```xml
<configuration>
  <layoutmode>logical</layoutmode>
  <logicalmonitor>
    <x>0</x><y>0</y><scale>1</scale><primary>yes</primary>
    <monitor>
      <monitorspec>
        <connector>HDMI-1</connector>
        <vendor>BBC</vendor><product>HDP-V104</product><serial>demoset-1</serial>
      </monitorspec>
      <mode><width>1440</width><height>900</height><rate>59.901</rate></mode>
    </monitor>
  </logicalmonitor>
</configuration>
```

(Use *your* dongle's `vendor`/`product`/`serial` and the exact `<rate>` GNOME
wrote for the mirror block — copy them from the mirror config so they match.)

### 4. Make the GDM login screen match

Install the same file at the system XDG fallback (the modern-GDM fix):

```bash
sudo cp ~/.config/monitors.xml /etc/xdg/monitors.xml
sudo chmod 0644 /etc/xdg/monitors.xml
# Harmless extra coverage for older/other GDM layouts:
sudo install -o gdm -g gdm -m 0644 ~/.config/monitors.xml /var/lib/gdm3/.config/monitors.xml 2>/dev/null || true
sudo install -o gdm -g gdm -m 0644 ~/.config/monitors.xml /var/lib/gdm3/seat0/config/monitors.xml 2>/dev/null || true
```

> Re-copy after any change to your session's display layout — GNOME won't sync it
> for you.

### 5. (Optional) Make the GRUB menu visible

```bash
sudo sed -i 's/^GRUB_TIMEOUT_STYLE=hidden/GRUB_TIMEOUT_STYLE=menu/' /etc/default/grub
sudo sed -i 's/^GRUB_TIMEOUT=0/GRUB_TIMEOUT=5/'                     /etc/default/grub
sudo update-grub
```

Shows the menu for 5s on the firmware's chosen output. (Can't be mirrored — UEFI
limitation. If it lands on the invisible dongle, move the real monitor to the
firmware's boot port or set the primary display in UEFI/BIOS.)

### 6. (Optional, for a truly always-on host)

- **Never suspend:** *Settings → Power* → Automatic Suspend **Off**
  (`gsettings set org.gnome.settings-daemon.plugins.power sleep-inactive-ac-type 'nothing'`),
  or belt-and-suspenders: `sudo systemctl mask sleep.target suspend.target hibernate.target hybrid-sleep.target`.
  An always-on remote host must not sleep — a suspended box is off the network.
- **Auto-login** (if you don't need the greeter at all): *Settings → Users* →
  Automatic Login, or `AutomaticLoginEnable=true` in `/etc/gdm3/custom.conf`. Boots
  straight into the session so rmdd + the layout are live with no login step.
  (Tradeoff: physical access = desktop with no password.)

---

## Verify

1. **Login screen:** reboot → the GDM greeter shows on **both** displays at
   1440×900 (not login-on-dongle / gray-on-panel).
2. **Session:** after login, both displays mirror at 1440×900.
3. **The payoff test:** with a viewer **disconnected**, **unplug the real
   monitor**, then **reconnect the viewer**. It should stream at **1440×900** with
   no encoder crash — because the dongle stays connected (Trap 1), stays at a safe
   resolution (Traps 2/3), and rmdd captures the dongle as the primary.

Watch the host while testing:

```bash
journalctl --user -u rmd-host.service -f | \
  grep -iE "negotiated video format|Encoder max|encode error|capture start"
```

A healthy headless capture logs `negotiated video format width=1440 height=900`.
A broken one logs `width=4096 height=2160` followed by `Encoder max resolution…`.

---

## Troubleshooting: "can't connect" that *isn't* the display

Once the display is sorted, a headless host can still fail to connect for
**networking** reasons that look identical from the viewer (it just never comes
up). Rule these out before blaming the display again:

### TURN relay missing after a reboot (boot-time DNS race)
**Host log symptom:**
```
pingAllCandidates ... no candidate pairs. Connection is not possible yet.
remote mDNS candidate added, but mDNS is disabled: (....local)
```
and, at startup:
```
could not fetch ICE servers from rendezvous; continuing without a relay
error=... Dns Failed: resolve dns name '<host>:443': Temporary failure in name resolution
```

**Cause:** the host service started **before DNS was ready**, and (on older
builds) the ICE/TURN fetch was one-shot — so it ran the whole session with **no
relay**. A browser viewer only offers **mDNS `.local`** candidates, so with no
relay there is nothing to pair with → "no candidate pairs." Note: `rmd-host` runs
as a **user** service, and `network-online.target` is a **system** target, so
`Wants/After=network-online.target` in the unit is effectively a **no-op** — it
does not make a user service wait for DNS.

**Fix:** run **rmdd 0.7.0+**, which **retries** the ICE fetch (and refreshes TURN
credentials before they expire). On older builds, `rmdd restart` once DNS is up
re-fetches the relay. Confirm a healthy start:
```bash
journalctl --user -u rmd-host.service | grep -E "TURN relay candidate|fetched ICE"
```
(If you must stay on an old build, a user drop-in with an `ExecStartPre` that polls
`getent hosts <rendezvous-host>` until it resolves also works.)

### Token rejected (401) after ~a day
The rendezvous **device token has a TTL**; when it expires the server returns 401
and the host goes unreachable — a *different* failure with the *same* "can't
connect" symptom. **rmdd 0.7.0+** re-mints its token automatically by proving
possession of its identity key to the server's `POST /api/token/refresh` endpoint
(so **the rendezvous server must be on 0.7.0+ too**). Older builds need a manual
`rmdd set token <fresh>`.

### Connects, then drops after a while
Usually **bandwidth** — the default target bitrate (~8 Mbps) is too high for a
slow link, and congestion control eventually gives up. Lower it:
```bash
rmdd set bitrate 2000000   # 2 Mbps; then: rmdd restart
```
1440×900 looks fine at 2–3 Mbps.

---

## Appendix: `ApplyMonitorsConfig` helper

Applies a **mirror at 1440×900** (dongle primary) and persists it to
`monitors.xml`. Adjust `MODE`/connector names for your hardware. Run once with
both monitors plugged; for the dongle-only fallback, run again with just the
dongle and a single-monitor `logical` list.

```python
#!/usr/bin/env python3
import gi
gi.require_version('Gio', '2.0')
from gi.repository import Gio, GLib

bus = Gio.bus_get_sync(Gio.BusType.SESSION, None)
proxy = Gio.DBusProxy.new_sync(
    bus, Gio.DBusProxyFlags.NONE, None,
    'org.gnome.Mutter.DisplayConfig', '/org/gnome/Mutter/DisplayConfig',
    'org.gnome.Mutter.DisplayConfig', None)

MODE = "1440x900@59.901"   # must be an exact mode id from GetCurrentState

def serial():
    st = proxy.call_sync('GetCurrentState', None, Gio.DBusCallFlags.NONE, -1, None)
    return st.get_child_value(0).get_uint32()

# Mirror = ONE logical monitor containing BOTH connectors.
# (For dongle-only, drop HDMI-2 from the inner list.)
logical = [(0, 0, 1.0, 0, True,
            [("HDMI-1", MODE, {}), ("HDMI-2", MODE, {})])]

for method in (0, 2):   # 0 = verify, 2 = apply + save
    args = GLib.Variant('(uua(iiduba(ssa{sv}))a{sv})', (serial(), method, logical, {}))
    proxy.call_sync('ApplyMonitorsConfig', args, Gio.DBusCallFlags.NONE, -1, None)
print("mirror applied + saved")
```

Find the exact `MODE` string and connector names with:

```bash
busctl --user call org.gnome.Mutter.DisplayConfig /org/gnome/Mutter/DisplayConfig \
  org.gnome.Mutter.DisplayConfig GetCurrentState | grep -oE '"1440x900@[0-9.]+"'
```

---

## Layer cheat-sheet

| Layer            | Config it reads                          | What we do                          |
|------------------|------------------------------------------|-------------------------------------|
| UEFI / GRUB      | firmware framebuffer (single output)     | show menu 5s; can't mirror          |
| GDM greeter      | `/etc/xdg/monitors.xml` (ephemeral home) | install layout there                |
| User session     | `~/.config/monitors.xml`                 | mirror + dongle-only, 1440×900      |
| rmdd capture     | mutter primary logical monitor           | captures the dongle @ 1440×900      |
| H.264 encoder    | frame width/height                       | keep ≤ 3840 wide                     |
