# macOS permissions (host)

The macOS host needs two TCC permissions. Both are per-app and survive reboots once granted.

## 1. Screen Recording (required for capture)
- Triggered the first time the host starts a ScreenCaptureKit stream.
- Grant: **System Settings → Privacy & Security → Screen & System Audio Recording** → enable the host app.
- macOS requires the app to be **restarted** after granting before capture works.

## 2. Accessibility (required for input injection)
- Triggered the first time the host injects a CGEvent (keyboard/mouse).
- Grant: **System Settings → Privacy & Security → Accessibility** → enable the host app.

## Honest limitations (v1)
- **Secure input fields / login window / fast-user-switching lock screen** may block synthetic events —
  documented, not silently failed.
- **Host audio loopback** on macOS needs a virtual audio device (e.g. an aggregate/loopback driver).
  Deferred to v1.1 with a clear note (see spec); no silent audio failure.
- Running the host as a **launchd daemon** vs a user agent affects which desktop/session is captured;
  Phase 3 documents the chosen model.
