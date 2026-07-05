#!/bin/sh
# ReachMyDevice installer — downloads the latest signed release for your OS/arch,
# verifies it, and installs the binaries into ~/.local/bin (override with
# RMD_PREFIX). POSIX sh; safe to pipe:
#
#   curl -fsSL https://raw.githubusercontent.com/Brainwires/reachmydevice/main/deploy/release/install.sh | sh
#
# Env overrides:
#   RMD_PREFIX=/usr/local     install prefix (binaries go in $PREFIX/bin)
#   RMD_VERSION=v0.1.0        pin a specific release (default: latest)
#   RMD_GH_REPO=owner/repo    source repo (default: Brainwires/reachmydevice)
#
# Verification: if `minisign` is installed the release signature is checked
# against ReachMyDevice's pinned public key (below). Otherwise the SHA-256 checksum
# is verified (integrity, via HTTPS transport authenticity) and a note is printed
# on how to get full signature verification.

set -eu

GH_REPO="${RMD_GH_REPO:-Brainwires/reachmydevice}"
PREFIX="${RMD_PREFIX:-$HOME/.local}"
BINDIR="$PREFIX/bin"

# --- ReachMyDevice minisign public key (pinned) --------------------------------
# Filled in by deploy/release/setup-keys.sh at release-signing setup time.
# Until then it stays the sentinel and install falls back to checksum-only.
MINISIGN_PUB="RWQnk2aLGipco6JBuLuYSY8TCxq9PCnKfwJqXyWRWEGrsW71VOB47bxl"

say()  { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!!\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31mxx\033[0m %s\n' "$*" >&2; exit 1; }

need() { command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"; }
need uname; need tar
DL=""
if command -v curl >/dev/null 2>&1; then DL="curl -fsSL"; elif command -v wget >/dev/null 2>&1; then DL="wget -qO-"; else die "need curl or wget"; fi

# --- Detect platform -------------------------------------------------------
OS="$(uname -s)"; MACH="$(uname -m)"
case "$OS" in
  Linux)  PLAT="linux" ;;
  Darwin) PLAT="macos" ;;
  MINGW*|MSYS*|CYGWIN*|Windows_NT)
    die "Windows is build-from-source only (no prebuilt binaries).
    Install Rust + protoc, then:
      git clone --recurse-submodules https://github.com/$GH_REPO
      cd rmd && cargo build --release -p rmd-host -p rmd-viewer
    See https://github.com/$GH_REPO#build" ;;
  *) die "unsupported OS: $OS" ;;
esac
case "$MACH" in
  x86_64|amd64) ARCH="x86_64" ;;
  arm64|aarch64) ARCH="arm64" ;;
  *) ARCH="$MACH" ;;
esac

# Prebuilt slugs we may publish. Whichever the Release actually contains is
# used; a missing one falls through to a clear build-from-source error below.
SLUG="$PLAT-$ARCH"
case "$SLUG" in
  linux-x86_64|macos-x86_64|macos-arm64) : ;;
  *) die "no prebuilt binary for $SLUG. Build from source:
      git clone --recurse-submodules https://github.com/$GH_REPO
      cd rmd && cargo build --release -p rmd-host -p rmd-viewer
    See https://github.com/$GH_REPO#build" ;;
esac

# --- Resolve version -------------------------------------------------------
API="https://api.github.com/repos/$GH_REPO"
if [ -n "${RMD_VERSION:-}" ]; then
  TAG="$RMD_VERSION"; case "$TAG" in v*) : ;; *) TAG="v$TAG" ;; esac
else
  say "Resolving latest release of $GH_REPO"
  TAG="$($DL "$API/releases/latest" | grep -m1 '"tag_name"' | sed -E 's/.*"tag_name" *: *"([^"]+)".*/\1/')"
  [ -n "$TAG" ] || die "could not resolve latest release (is one published yet?)"
fi
VER="${TAG#v}"
say "Installing ReachMyDevice $TAG ($SLUG)"

TARBALL="rmd-$VER-$SLUG.tar.gz"
BASE="https://github.com/$GH_REPO/releases/download/$TAG"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
cd "$TMP"

fetch() { # url dest
  if command -v curl >/dev/null 2>&1; then curl -fsSL "$1" -o "$2"
  else wget -q "$1" -O "$2"; fi
}
say "Downloading $TARBALL"
fetch "$BASE/$TARBALL" "$TARBALL" || die "no $SLUG build in release $TAG.
    This platform may not have a prebuilt binary yet — build from source:
      git clone --recurse-submodules https://github.com/$GH_REPO
      cd rmd && cargo build --release -p rmd-host -p rmd-viewer
    See https://github.com/$GH_REPO#build"

# --- Verify ----------------------------------------------------------------
verified=""
case "$MINISIGN_PUB" in
  RWQ_RMD_PUBKEY_PLACEHOLDER) : ;;   # not yet configured
  *)
    if command -v minisign >/dev/null 2>&1; then
      fetch "$BASE/$TARBALL.minisig" "$TARBALL.minisig" || die "signature download failed"
      minisign -Vm "$TARBALL" -P "$MINISIGN_PUB" >/dev/null 2>&1 \
        && { verified="minisign"; say "Signature OK (minisign)"; } \
        || die "SIGNATURE VERIFICATION FAILED — aborting"
    fi ;;
esac
if [ -z "$verified" ]; then
  # Checksum fallback: integrity + HTTPS transport authenticity.
  if fetch "$BASE/SHA256SUMS" SHA256SUMS 2>/dev/null; then
    want="$(grep " $TARBALL\$" SHA256SUMS | awk '{print $1}')"
    if command -v sha256sum >/dev/null 2>&1; then got="$(sha256sum "$TARBALL" | awk '{print $1}')"
    else got="$(shasum -a 256 "$TARBALL" | awk '{print $1}')"; fi
    [ -n "$want" ] && [ "$want" = "$got" ] || die "CHECKSUM MISMATCH — aborting"
    verified="sha256"; say "Checksum OK (sha256)"
    warn "Install 'minisign' for full signature verification (brew install minisign / cargo install minisign)."
  else
    warn "No checksums available — proceeding on HTTPS transport trust only."
  fi
fi

# --- Install ---------------------------------------------------------------
tar xzf "$TARBALL"
SRC="rmd-$VER-$SLUG/bin"
[ -d "$SRC" ] || die "unexpected archive layout"
mkdir -p "$BINDIR"
installed=""
for b in rmd-host rmd-viewer rmd-rendezvous; do
  if [ -f "$SRC/$b" ]; then install -m 0755 "$SRC/$b" "$BINDIR/$b"; installed="$installed $b"; fi
done
say "Installed:$installed -> $BINDIR"

case ":$PATH:" in
  *":$BINDIR:"*) : ;;
  *) warn "$BINDIR is not on your PATH. Add:  export PATH=\"$BINDIR:\$PATH\"" ;;
esac

if [ "$PLAT" = macos ]; then
  warn "Unsigned build: if macOS blocks a binary, run:  xattr -d com.apple.quarantine $BINDIR/rmd-viewer"
fi
say "Done. Try:  rmd-viewer   (or rmd-host on the machine to control)"
