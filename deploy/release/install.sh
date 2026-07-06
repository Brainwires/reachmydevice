#!/bin/sh
# ReachMyDevice installer. Re-runnable: on rerun it upgrades when a newer version
# is available, or reports that the latest is already installed.
#
#   curl -fsSL https://reachmy.dev/install.sh | sh
#
# It offers two install methods:
#   * prebuilt  — download the latest signed release for your OS/arch (default)
#   * source    — build from source (runs a system-requirements check first)
# When run interactively it prompts; when piped it uses the prebuilt binaries.
#
# Installs the client `rmd` + the host daemon `rmdd` into ~/.local/bin (no sudo)
# and adds that directory to your PATH. Then validates the binaries run.
#
# Env overrides:
#   RMD_MODE=prebuilt|source   install method (default: prompt, else prebuilt)
#   RMD_PREFIX=/custom         install prefix (binaries go in $PREFIX/bin)
#   RMD_VERSION=v0.2.0         pin a specific release (prebuilt mode)
#   RMD_SRC=/path/to/checkout  build from an existing checkout (source mode)
#   RMD_FORCE=1                reinstall even if already up to date
#   RMD_NO_PATH=1              don't modify shell rc files
#   RMD_GH_REPO=owner/repo     source repo (default: Brainwires/reachmydevice)

set -eu

GH_REPO="${RMD_GH_REPO:-Brainwires/reachmydevice}"
PREFIX="${RMD_PREFIX:-$HOME/.local}"
BINDIR="$PREFIX/bin"

# Pinned minisign public key (filled by deploy/release/setup-keys.sh).
MINISIGN_PUB="RWQnk2aLGipco6JBuLuYSY8TCxq9PCnKfwJqXyWRWEGrsW71VOB47bxl"

say()  { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!!\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31mxx\033[0m %s\n' "$*" >&2; exit 1; }

need() { command -v "$1" >/dev/null 2>&1; }
have_cc() { need cc || need clang || need gcc; }

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
fetch() { if need curl; then curl -fsSL "$1" -o "$2"; else wget -q "$1" -O "$2"; fi; }
fetch_stdout() { if need curl; then curl -fsSL "$1"; else wget -qO- "$1"; fi; }

need uname || die "uname not found"

usage() {
  cat <<EOF
ReachMyDevice installer — installs the client 'rmd' + host daemon 'rmdd'.

Usage:
  curl -fsSL https://reachmy.dev/install.sh | sh                 # install (prompts method)
  curl -fsSL https://reachmy.dev/install.sh | sh -s -- [options]
  ./install.sh [options]

Options:
  --prebuilt     install prebuilt signed binaries (default)
  --source       build from source (runs a system-requirements check first)
  --force        reinstall even if already up to date
  --uninstall    remove rmd/rmdd, the installer's PATH entry, and any service unit
  --help, -h     show this help

Env: RMD_PREFIX (default ~/.local), RMD_VERSION, RMD_SRC, RMD_NO_PATH,
     RMD_PURGE (also remove ~/.config/rmd on uninstall), RMD_GH_REPO.

Installs into \$RMD_PREFIX/bin (default ~/.local/bin) — no sudo. Re-running
upgrades to the latest version, or reports that you're already up to date.
EOF
}

# Parse flags (also settable via env). Args arrive via `sh -s -- <flags>` when piped.
DO_UNINSTALL=""
for a in "$@"; do
  case "$a" in
    --help|-h)   usage; exit 0 ;;
    --uninstall) DO_UNINSTALL=1 ;;
    --source)    RMD_MODE=source ;;
    --prebuilt)  RMD_MODE=prebuilt ;;
    --force)     RMD_FORCE=1 ;;
    *) warn "ignoring unknown option: $a" ;;
  esac
done

# Remove binaries, the PATH entry we added, and any service unit. Keeps ~/.config/rmd
# unless RMD_PURGE is set (it holds device tokens / keys).
uninstall() {
  say "Uninstalling ReachMyDevice"
  removed=""
  for b in rmd rmdd rmd-rendezvous; do
    if [ -e "$BINDIR/$b" ]; then rm -f "$BINDIR/$b"; removed="$removed $b"; fi
  done
  [ -n "$removed" ] && say "Removed:$removed from $BINDIR" || say "No binaries in $BINDIR"
  for RC in "$HOME/.zshrc" "$HOME/.bashrc" "$HOME/.profile"; do
    [ -f "$RC" ] || continue
    if grep -qF "Added by the ReachMyDevice installer" "$RC" 2>/dev/null; then
      tmp="$(mktemp)"
      awk 'skip==1 && index($0,".local/bin"){skip=0; next}
           /# Added by the ReachMyDevice installer/{skip=1; next} {print}' "$RC" > "$tmp" && mv "$tmp" "$RC"
      say "Removed PATH entry from $RC"
    fi
  done
  case "$PLAT" in
    macos)
      PL="$HOME/Library/LaunchAgents/com.brainwires.rmd-host.plist"
      [ -f "$PL" ] && { launchctl unload "$PL" 2>/dev/null || true; rm -f "$PL"; say "Removed launchd agent"; } ;;
    linux)
      U="$HOME/.config/systemd/user/rmd-host.service"
      [ -f "$U" ] && { systemctl --user disable --now rmd-host 2>/dev/null || true; rm -f "$U"; systemctl --user daemon-reload 2>/dev/null || true; say "Removed systemd unit"; } ;;
  esac
  CFG="${XDG_CONFIG_HOME:-$HOME/.config}/rmd"
  if [ -d "$CFG" ]; then
    if [ -n "${RMD_PURGE:-}" ]; then rm -rf "$CFG"; say "Removed config $CFG"
    else say "Kept config $CFG  (RMD_PURGE=1 to also remove device tokens/keys)"; fi
  fi
  say "Uninstall complete."
  exit 0
}

need curl || need wget || die "need curl or wget"

# --- Detect platform -------------------------------------------------------
OS="$(uname -s)"; MACH="$(uname -m)"
case "$OS" in
  Linux)  PLAT="linux" ;;
  Darwin) PLAT="macos" ;;
  MINGW*|MSYS*|CYGWIN*|Windows_NT) die "Windows is build-from-source only — see https://github.com/$GH_REPO#build" ;;
  *) die "unsupported OS: $OS" ;;
esac
case "$MACH" in
  x86_64|amd64)  ARCH="x86_64" ;;
  arm64|aarch64) ARCH="arm64" ;;
  *) ARCH="$MACH" ;;
esac
SLUG="$PLAT-$ARCH"
PREBUILT_OK=0
case "$SLUG" in linux-x86_64|macos-x86_64|macos-arm64) PREBUILT_OK=1 ;; esac

# Uninstall short-circuits everything else (needs $PLAT + $BINDIR, now set).
if [ -n "$DO_UNINSTALL" ]; then uninstall; fi

# --- Choose install method -------------------------------------------------
# Prefer prebuilt binaries (no toolchain needed). Build from source only when the
# user asks (--source / RMD_MODE=source) or no prebuilt exists for this platform.
# The build-requirements check runs ONLY in source mode, so it never blocks a
# prebuilt install.
MODE="${RMD_MODE:-}"
if [ -z "$MODE" ]; then
  if [ "$PREBUILT_OK" = 1 ]; then
    MODE=prebuilt
  else
    MODE=source
    warn "No prebuilt binary is published for $SLUG — falling back to a source build."
    warn "Prebuilt platforms: linux-x86_64, macos-x86_64, macos-arm64.  (Pass --source to force a build.)"
  fi
fi

# --- Installed version (for the re-runnable upgrade check) ------------------
installed_version() { # -> prints version string or empty
  for b in rmd rmdd; do
    if [ -x "$BINDIR/$b" ]; then "$BINDIR/$b" --version 2>/dev/null | awk '{print $2; exit}'; return; fi
  done
  for b in rmd rmdd; do
    if need "$b"; then "$b" --version 2>/dev/null | awk '{print $2; exit}'; return; fi
  done
}
skip_if_current() { # target-version
  cur="$(installed_version || true)"
  if [ -n "$cur" ] && [ "$cur" = "$1" ] && [ -z "${RMD_FORCE:-}" ]; then
    say "ReachMyDevice $cur is already installed and up to date. Nothing to do."
    say "(Re-run with RMD_FORCE=1 to reinstall.)"
    exit 0
  fi
  if [ -n "$cur" ]; then say "Upgrading ReachMyDevice $cur -> $1"; else say "Installing ReachMyDevice $1"; fi
}

installed=""

# --- Prebuilt path ---------------------------------------------------------
install_prebuilt() {
  API="https://api.github.com/repos/$GH_REPO"
  if [ -n "${RMD_VERSION:-}" ]; then TAG="$RMD_VERSION"; case "$TAG" in v*) : ;; *) TAG="v$TAG" ;; esac
  else
    say "Resolving latest release of $GH_REPO"
    # Use /releases (newest-first) rather than /releases/latest so that
    # pre-releases are included; take the first tag_name.
    TAG="$(fetch_stdout "$API/releases" | grep -m1 '"tag_name"' | sed -E 's/.*"tag_name" *: *"([^"]+)".*/\1/')"
    [ -n "$TAG" ] || die "could not resolve a release (private repo needs a public download source — see below)"
  fi
  VER="${TAG#v}"
  skip_if_current "$VER"
  say "Prebuilt install ($SLUG), release $TAG"

  TARBALL="rmd-$VER-$SLUG.tar.gz"
  BASE="https://github.com/$GH_REPO/releases/download/$TAG"
  cd "$TMP"
  say "Downloading $TARBALL"
  fetch "$BASE/$TARBALL" "$TARBALL" || die "no $SLUG build in $TAG — try RMD_MODE=source"

  # Verify: minisign signature if available, else SHA-256 checksum.
  verified=""
  if need minisign && fetch "$BASE/$TARBALL.minisig" "$TARBALL.minisig" 2>/dev/null; then
    minisign -Vm "$TARBALL" -P "$MINISIGN_PUB" >/dev/null 2>&1 \
      && { verified=minisign; say "Signature OK (minisign)"; } || die "SIGNATURE VERIFICATION FAILED"
  fi
  if [ -z "$verified" ] && fetch "$BASE/SHA256SUMS" SHA256SUMS 2>/dev/null; then
    want="$(grep " $TARBALL\$" SHA256SUMS | awk '{print $1}')"
    if need sha256sum; then got="$(sha256sum "$TARBALL" | awk '{print $1}')"; else got="$(shasum -a 256 "$TARBALL" | awk '{print $1}')"; fi
    [ -n "$want" ] && [ "$want" = "$got" ] || die "CHECKSUM MISMATCH"
    verified=sha256; say "Checksum OK (sha256)"
    need minisign || warn "Install 'minisign' (or rsign2) for full signature verification."
  fi
  [ -n "$verified" ] || warn "No signature/checksum available — proceeding on HTTPS trust only."

  tar xzf "$TARBALL"
  SRC="rmd-$VER-$SLUG/bin"; [ -d "$SRC" ] || die "unexpected archive layout"
  mkdir -p "$BINDIR"
  # Install under the Unix names; accept both new (rmdd/rmd) and pre-rename layouts.
  if   [ -f "$SRC/rmdd" ];     then install -m 0755 "$SRC/rmdd" "$BINDIR/rmdd"; installed="$installed rmdd"
  elif [ -f "$SRC/rmd-host" ]; then install -m 0755 "$SRC/rmd-host" "$BINDIR/rmdd"; installed="$installed rmdd"; fi
  if   [ -f "$SRC/rmd" ];        then install -m 0755 "$SRC/rmd" "$BINDIR/rmd"; installed="$installed rmd"
  elif [ -f "$SRC/rmd-viewer" ]; then install -m 0755 "$SRC/rmd-viewer" "$BINDIR/rmd"; installed="$installed rmd"; fi
  say "Installed:$installed -> $BINDIR"
}

# --- Source path -----------------------------------------------------------
check_source_reqs() {
  say "Checking build requirements"
  missing=""
  need cargo || missing="$missing rust(cargo)"
  need git   || missing="$missing git"
  have_cc    || missing="$missing c-compiler"
  if [ "$PLAT" = linux ]; then
    if need pkg-config; then
      pkg-config --exists x11 xtst xext 2>/dev/null || missing="$missing x11-dev-libs"
    else missing="$missing pkg-config"; fi
  fi
  need nasm || warn "nasm not found — recommended for the default H.264 codec build."
  if [ -n "$missing" ]; then
    die "missing build requirements:$missing

  Install them, then re-run:
    Rust (all platforms):  https://rustup.rs   (curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh)
    macOS  C compiler + git:  xcode-select --install
    Linux (Debian/Ubuntu):  sudo apt-get install -y build-essential pkg-config git nasm \\
                              libx11-dev libxext-dev libxtst-dev libxdamage-dev libxcb1-dev \\
                              libxkbcommon-dev libwayland-dev"
  fi
  say "All build requirements present."
}
install_source() {
  check_source_reqs
  SRCDIR="${RMD_SRC:-}"
  if [ -z "$SRCDIR" ]; then
    SRCDIR="$TMP/src"
    say "Cloning $GH_REPO (with submodules)…"
    git clone --depth 1 --recurse-submodules "https://github.com/$GH_REPO" "$SRCDIR" >/dev/null 2>&1 \
      || die "git clone failed"
  else
    ( cd "$SRCDIR" && git submodule update --init --recursive >/dev/null 2>&1 || true )
  fi
  VER="$(grep -m1 -E '^version *= *"' "$SRCDIR/Cargo.toml" | sed -E 's/.*"([^"]+)".*/\1/')"
  [ -n "$VER" ] || VER="source"
  skip_if_current "$VER"
  say "Building rmdd + rmd from source (release) — this takes a few minutes…"
  ( cd "$SRCDIR" && cargo build --release -p rmd-host -p rmd-viewer ) || die "cargo build failed"
  mkdir -p "$BINDIR"
  install -m 0755 "$SRCDIR/target/release/rmdd" "$BINDIR/rmdd"
  install -m 0755 "$SRCDIR/target/release/rmd"  "$BINDIR/rmd"
  installed="rmdd rmd"
  say "Installed: rmdd rmd -> $BINDIR"
}

# --- Run the chosen method -------------------------------------------------
case "$MODE" in
  prebuilt) install_prebuilt ;;
  source)   install_source ;;
  *) die "unknown RMD_MODE: $MODE (use prebuilt|source)" ;;
esac

# --- Ensure ~/.local/bin is on PATH (no sudo) ------------------------------
PATH_NOTE=""
case ":$PATH:" in
  *":$BINDIR:"*) say "$BINDIR is already on your PATH." ;;
  *)
    if [ -n "${RMD_NO_PATH:-}" ]; then
      warn "$BINDIR is not on your PATH. Add:  export PATH=\"$BINDIR:\$PATH\""
    else
      case "${SHELL:-}" in */zsh) RC="$HOME/.zshrc" ;; */bash) RC="$HOME/.bashrc" ;; *) RC="$HOME/.profile" ;; esac
      LINE="export PATH=\"$BINDIR:\$PATH\""
      if [ -f "$RC" ] && grep -qF "$BINDIR" "$RC" 2>/dev/null; then :; else
        printf '\n# Added by the ReachMyDevice installer\n%s\n' "$LINE" >> "$RC"
        say "Added $BINDIR to your PATH in $RC"
      fi
      PATH_NOTE="Open a new terminal (or run: source $RC) to use rmd/rmdd."
    fi
    export PATH="$BINDIR:$PATH" ;;   # so validation below works this session
esac

# --- Validate --------------------------------------------------------------
say "Validating install"
ok=1
for b in $installed; do
  if v="$("$BINDIR/$b" --version 2>/dev/null)"; then say "  ✓ $v  ($BINDIR/$b)"; else warn "  ✗ $b failed to run"; ok=0; fi
done
[ "$ok" = 1 ] || die "validation failed — the binaries did not run"

if [ "$PLAT" = macos ]; then
  warn "Unsigned build: if macOS blocks a binary, run:  xattr -dr com.apple.quarantine $BINDIR/rmd $BINDIR/rmdd"
fi
say "Done.  Run  rmd  to view a device — or  rmdd  on the machine you want to control."
[ -z "$PATH_NOTE" ] || say "$PATH_NOTE"
