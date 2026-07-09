# ReachMyDevice release pipeline

How ReachMyDevice ships prebuilt binaries. Two build hosts because **a macOS `.app`/
`.dmg` can only be produced on macOS** — Linux (biscuits) can't cross-build them.

| Platform | Artifacts | Built on | Trigger |
|----------|-----------|----------|---------|
| **macOS x86_64 + arm64** | raw binaries, `.tar.gz`, `.dmg` | a Mac (cross-builds both arches) | its own GitHub webhook, `v*` tag |
| **Linux x86_64** | raw binaries, `.tar.gz`, `.deb` (host + rendezvous) | biscuits (Linux) | its own GitHub webhook, `v*` tag |
| **Windows** | — | — | build-from-source only (no Windows build host) |

`build-macos.sh` builds **one** arch (the host's, or `RMD_MAC_ARCH=x86_64|arm64`).
The decentralized CI (`rmd-ci`'s `build-release.sh`) runs it for **both** arches
from a single Mac — the Apple SDK ships both `x86_64` and `arm64` slices, so one
machine covers all macOS users; no separate Apple-Silicon host is needed. (An
arm64 binary cross-built on Intel can't be *smoke-tested* there, but it builds
cleanly.)

Every build host publishes to the **same** GitHub Release (`v<version>`), signs
with the **same** minisign key, and writes a per-platform `SHA256SUMS-<slug>`, so
`install.sh` finds each platform independently. See `../../` note: the automated
per-host webhook build lives in the private `rmd-ci` repo.

## Files

- `common.sh` — shared helpers (version, signing, checksums, `gh` upload).
- `build-linux.sh` — Linux artifacts + `.deb`; run on biscuits (webhook or by hand).
- `build-macos.sh` — macOS artifacts + `.app`/`.dmg`; run on a Mac.
- `install.sh` — the `curl | sh` end-user installer (detect OS/arch, verify, install).
- `setup-keys.sh` — one-time: generate the minisign signing key + pin its pubkey.
- `rmd-minisign.pub` — the committed public key (created by `setup-keys.sh`).

## One-time setup

```sh
# 1. Generate the signing key (once, on the Mac). Commits the pubkey + pins it
#    into install.sh; writes the secret key to ~/.rmd/minisign.key (0600).
deploy/release/setup-keys.sh

# 2. Copy the SAME secret key to biscuits so its webhook builds are signed too.
scp ~/.rmd/minisign.key biscuits:~/.rmd/minisign.key
ssh biscuits chmod 600 ~/.rmd/minisign.key

# 3. On biscuits, add the ReachMyDevice repo to bd-webhook's webhook.toml:
#      [repos.rmd.tags]
#      working_dir = "/home/nightness/rmd-dev"
#      commands = [
#        { cmd = "git", args = ["fetch", "--tags", "origin"] },
#        { cmd = "git", args = ["checkout", "${TAG_NAME}"] },
#        { cmd = "git", args = ["submodule", "update", "--init", "--recursive"] },
#        { cmd = "bash", args = ["deploy/release/build-linux.sh", "${VERSION}"] },
#      ]
#    then restart bd-webhook. Point the GitHub webhook (repo Settings -> Webhooks)
#    at http://<biscuits>:3033/webhook with the shared secret, "push" events.

# 4. Commit the pubkey + patched install.sh.
git add deploy/release/rmd-minisign.pub deploy/release/install.sh
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

Local dry run (build, no upload): `RMD_NO_UPLOAD=1 deploy/release/build-macos.sh`.

## What users run

```sh
curl -fsSL https://raw.githubusercontent.com/Brainwires/reachmydevice/main/deploy/release/install.sh | sh
```

Detects OS/arch, downloads the matching signed tarball, verifies it (minisign if
installed, else SHA-256), and installs to `~/.local/bin`. Windows and non-arm64
macOS / non-x86_64 Linux fall back to printed build-from-source instructions.

## Signing & verification

Releases are signed with **minisign** (Ed25519). The public key is pinned in
`install.sh` and published as `rmd-minisign.pub`. Manual check:

```sh
minisign -Vm rmd-0.1.0-linux-x86_64.tar.gz -P "$(tail -n1 rmd-minisign.pub)"
```

The secret key is **password-less** (created with `minisign -G -W`) so the webhook
host can sign non-interactively. Keep it 0600 and off every VCS/image (enforced by
`.gitignore` + `.dockerignore`). To rotate: move the old key aside, re-run
`setup-keys.sh`, re-commit the new pubkey + `install.sh`.
