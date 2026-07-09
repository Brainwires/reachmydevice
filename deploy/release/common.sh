# shellcheck shell=bash
# Shared helpers for the ReachMyDevice release build scripts (build-linux.sh /
# build-macos.sh). Source this; do not execute it directly.
#
# Provides: logging, version detection, minisign signing, checksum generation,
# and GitHub Release upload — all platform-neutral.

set -euo pipefail

# --- Repo layout ------------------------------------------------------------
# REL_DIR = deploy/release ; REPO_ROOT = the workspace root.
REL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$REL_DIR/../.." && pwd)"
DIST_DIR="$REPO_ROOT/dist"

GH_REPO="${RMD_GH_REPO:-Brainwires/reachmydevice}"

# Where the minisign secret key lives on a build machine (kept out of the repo).
# Override with RMD_MINISIGN_KEY. The matching public key is committed at
# deploy/release/rmd-minisign.pub and embedded in install.sh.
MINISIGN_KEY="${RMD_MINISIGN_KEY:-$HOME/.rmd/minisign.key}"
MINISIGN_PUB="$REL_DIR/rmd-minisign.pub"

# --- Logging ----------------------------------------------------------------
log()  { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!!\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31mxx\033[0m %s\n' "$*" >&2; exit 1; }

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1${2:+ ($2)}"
}

# --- Version ----------------------------------------------------------------
# Resolve the release version. Priority:
#   1. explicit $1 argument (e.g. the webhook's ${VERSION}, "0.1.0")
#   2. $RMD_VERSION
#   3. the workspace [workspace.package] version in Cargo.toml
# A leading "v" is stripped so tags (v0.1.0) and bare versions both work.
resolve_version() {
  local v="${1:-${RMD_VERSION:-}}"
  if [[ -z "$v" ]]; then
    v="$(grep -m1 -E '^version *= *"' "$REPO_ROOT/Cargo.toml" | sed -E 's/.*"([^"]+)".*/\1/')"
  fi
  v="${v#v}"
  [[ -n "$v" ]] || die "could not resolve version"
  printf '%s' "$v"
}

# --- Signing + checksums ----------------------------------------------------
# Detached minisign signature for one file (writes <file>.minisig next to it).
# No-op with a loud warning if the secret key is absent, so a dev build still
# produces artifacts — but a real release must have the key present.
sign_file() {
  local f="$1"
  if [[ ! -f "$MINISIGN_KEY" ]]; then
    warn "no signing key at $MINISIGN_KEY — skipping signature for $(basename "$f")"
    return 0
  fi
  # Prefer rsign2 (pure Rust — keeps the release toolchain C-free); fall back to
  # the minisign C CLI. Both emit the identical minisign signature format, so a
  # signature made by either verifies against the pinned pubkey / install.sh.
  # Password-less keys make this non-interactive on the webhook build host.
  if command -v rsign >/dev/null 2>&1 &&
     rsign sign -W -s "$MINISIGN_KEY" -x "$f.minisig" \
       -c "ReachMyDevice release" "$f" >/dev/null 2>&1; then
    return 0
  fi
  if command -v minisign >/dev/null 2>&1; then
    minisign -S -s "$MINISIGN_KEY" -m "$f" -c "ReachMyDevice release" >/dev/null
    return 0
  fi
  warn "neither rsign (rsign2) nor minisign available — skipping signature for $(basename "$f")"
}

# Checksums over every file currently in $DIST_DIR (portable across GNU/BSD).
# The output filename defaults to SHA256SUMS but each build host passes a
# per-platform name (e.g. SHA256SUMS-macos-x86_64) so independent hosts never
# clobber each other's checksums on the shared GitHub Release.
write_checksums() {
  local name="${1:-SHA256SUMS}"
  ( cd "$DIST_DIR"
    if command -v sha256sum >/dev/null 2>&1; then
      sha256sum -- * > "$name"
    else
      shasum -a 256 -- * > "$name"
    fi
  )
  sign_file "$DIST_DIR/$name"
}

# Sign every artifact in $DIST_DIR except signatures/checksums themselves.
sign_all() {
  local f
  for f in "$DIST_DIR"/*; do
    case "$f" in
      *.minisig|*/SHA256SUMS|*/SHA256SUMS-*) continue ;;
    esac
    [[ -f "$f" ]] && sign_file "$f"
  done
}

# --- GitHub Release ---------------------------------------------------------
# Create the release for tag v<version> if it doesn't exist, then upload every
# file in $DIST_DIR (clobbering same-named assets so re-runs are idempotent).
# Skipped entirely when RMD_NO_UPLOAD=1 (local/dev builds).
publish_release() {
  local version="$1" tag="v${1#v}"
  if [[ "${RMD_NO_UPLOAD:-0}" == "1" ]]; then
    log "RMD_NO_UPLOAD=1 — artifacts staged in $DIST_DIR, not uploaded"
    return 0
  fi
  require_cmd gh "install GitHub CLI and run: gh auth login"

  if ! gh release view "$tag" --repo "$GH_REPO" >/dev/null 2>&1; then
    log "Creating GitHub Release $tag"
    # Independent build hosts may race to create the release; the loser gets
    # "already exists". Tolerate it — the upload below is the operation that
    # matters, and it fails loudly if the release genuinely isn't there.
    gh release create "$tag" --repo "$GH_REPO" \
      --title "ReachMyDevice $tag" \
      --generate-notes ${RMD_PRERELEASE:+--prerelease} \
      || log "release create failed (another host likely created it) — continuing"
  else
    log "Release $tag already exists — uploading/replacing assets"
  fi

  log "Uploading $(find "$DIST_DIR" -maxdepth 1 -type f | wc -l | tr -d ' ') assets"
  gh release upload "$tag" "$DIST_DIR"/* --repo "$GH_REPO" --clobber
}

# Fresh, empty dist dir.
reset_dist() { rm -rf "$DIST_DIR"; mkdir -p "$DIST_DIR"; }
