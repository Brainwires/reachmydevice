# OpenReach release pipeline

How OpenReach ships prebuilt binaries. Two build hosts because **a macOS `.app`/
`.dmg` can only be produced on macOS** — Linux (biscuits) can't cross-build them.

| Platform | Artifacts | Built on | Trigger |
|----------|-----------|----------|---------|
| **Linux x86_64** | raw binaries, `.tar.gz`, `.deb` (host + rendezvous) | biscuits (Linux) | `bd-webhook` on a `v*` tag push — automatic |
| **macOS (host arch)** | raw binaries, `.tar.gz`, `.app` + `.dmg` (viewer) | your Mac | run `build-macos.sh` by hand |
| **Windows** | — | — | build-from-source only (no Windows build host) |

`build-macos.sh` builds for the arch of the Mac it runs on — an **Intel** Mac
produces `macos-x86_64`, an **Apple Silicon** Mac produces `macos-arm64`. It only
ships the arch you can actually run and test. Users on the *other* Mac arch build
from source until a build host for that arch exists (or run
`OPENREACH_MAC_ARCH=arm64 build-macos.sh` to cross-build an **untested** arm64
binary from Intel).

Both build hosts publish to the **same** GitHub Release (`v<version>`), signed with
the **same** minisign key, so `install.sh` finds every platform in one place.

## Files

- `common.sh` — shared helpers (version, signing, checksums, `gh` upload).
- `build-linux.sh` — Linux artifacts + `.deb`; run on biscuits (webhook or by hand).
- `build-macos.sh` — macOS artifacts + `.app`/`.dmg`; run on a Mac.
- `install.sh` — the `curl | sh` end-user installer (detect OS/arch, verify, install).
- `setup-keys.sh` — one-time: generate the minisign signing key + pin its pubkey.
- `openreach-minisign.pub` — the committed public key (created by `setup-keys.sh`).

## One-time setup

```sh
# 1. Generate the signing key (once, on the Mac). Commits the pubkey + pins it
#    into install.sh; writes the secret key to ~/.openreach/minisign.key (0600).
deploy/release/setup-keys.sh

# 2. Copy the SAME secret key to biscuits so its webhook builds are signed too.
scp ~/.openreach/minisign.key biscuits:~/.openreach/minisign.key
ssh biscuits chmod 600 ~/.openreach/minisign.key

# 3. On biscuits, add the OpenReach repo to bd-webhook's webhook.toml:
#      [repos.openreach.tags]
#      working_dir = "/home/nightness/openreach-dev"
#      commands = [
#        { cmd = "git", args = ["fetch", "--tags", "origin"] },
#        { cmd = "git", args = ["checkout", "${TAG_NAME}"] },
#        { cmd = "git", args = ["submodule", "update", "--init", "--recursive"] },
#        { cmd = "bash", args = ["deploy/release/build-linux.sh", "${VERSION}"] },
#      ]
#    then restart bd-webhook. Point the GitHub webhook (repo Settings -> Webhooks)
#    at http://<biscuits>:3033/webhook with the shared secret, "push" events.

# 4. Commit the pubkey + patched install.sh.
git add deploy/release/openreach-minisign.pub deploy/release/install.sh
git commit -m "release: pin minisign public key"
```

## Cutting a release

```sh
# Bump the workspace version in Cargo.toml first, commit, then:
git tag v0.1.0 && git push origin v0.1.0
```

- The tag push fires `bd-webhook` on biscuits → `build-linux.sh` → Linux artifacts
  uploaded to Release `v0.1.0`.
- On your Mac, run the macOS half against the same tag:
  ```sh
  git checkout v0.1.0 && deploy/release/build-macos.sh
  ```
  It adds the `.app`/`.dmg`/tarball to the same Release.

Local dry run (build, no upload): `OPENREACH_NO_UPLOAD=1 deploy/release/build-macos.sh`.

## What users run

```sh
curl -fsSL https://raw.githubusercontent.com/Brainwires/openreach/main/deploy/release/install.sh | sh
```

Detects OS/arch, downloads the matching signed tarball, verifies it (minisign if
installed, else SHA-256), and installs to `~/.local/bin`. Windows and non-arm64
macOS / non-x86_64 Linux fall back to printed build-from-source instructions.

## Signing & verification

Releases are signed with **minisign** (Ed25519). The public key is pinned in
`install.sh` and published as `openreach-minisign.pub`. Manual check:

```sh
minisign -Vm openreach-0.1.0-linux-x86_64.tar.gz -P "$(tail -n1 openreach-minisign.pub)"
```

The secret key is **password-less** (created with `minisign -G -W`) so the webhook
host can sign non-interactively. Keep it 0600 and off every VCS/image (enforced by
`.gitignore` + `.dockerignore`). To rotate: move the old key aside, re-run
`setup-keys.sh`, re-commit the new pubkey + `install.sh`.
