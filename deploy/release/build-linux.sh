#!/usr/bin/env bash
# Build + package + publish the ReachMyDevice Linux (x86_64) release artifacts.
#
# Runs locally on a Linux build host (e.g. biscuits), triggered by bd-webhook on
# a version-tag push. Produces, in ./dist:
#   - raw binaries:      rmd-{host,viewer,rendezvous}-linux-x86_64
#   - tarball:           rmd-<version>-linux-x86_64.tar.gz
#   - Debian packages:   rmd-host_<version>_amd64.deb, rmd-rendezvous_..._amd64.deb
#   - SHA256SUMS + a .minisig for every artifact
# then creates/updates the GitHub Release v<version> and uploads them all.
#
# Usage:
#   deploy/release/build-linux.sh [VERSION]        # VERSION defaults to workspace version
#   RMD_NO_UPLOAD=1 deploy/release/build-linux.sh   # build only, no gh upload
#
# Build deps (Debian/Ubuntu): rustup toolchain, nasm (rav1e/rav1d SIMD),
# pkg-config, libx11-dev libxext-dev libxtst-dev libxdamage-dev libxcb1-dev
# libxkbcommon-dev libwayland-dev. No protobuf-compiler (protox is pure Rust).
# cargo-deb is auto-installed if missing.

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

# Build for the host's arch by default (biscuits=x86_64, an Orange Pi/RPi=arm64);
# override with RMD_LINUX_ARCH=x86_64|arm64. For a portable arm64 binary that also
# runs on Raspberry Pi OS, run this inside a Debian *bookworm* arm64 environment
# (older glibc) rather than a bleeding-edge distro.
ARCH="${RMD_LINUX_ARCH:-$(uname -m)}"
case "$ARCH" in
  x86_64|amd64)  ARCH="x86_64"; TARGET="x86_64-unknown-linux-gnu" ;;
  aarch64|arm64) ARCH="arm64";  TARGET="aarch64-unknown-linux-gnu" ;;
  *) echo "unsupported linux arch: $ARCH (use x86_64 or arm64)" >&2; exit 1 ;;
esac
VERSION="$(resolve_version "${1:-}")"
BINS=(rmd-host rmd-viewer rmd-rendezvous)   # cargo package names
# Unix-style command name each package's binary is built + shipped as.
binname() { case "$1" in rmd-host) echo rmdd ;; rmd-viewer) echo rmd ;; *) echo "$1" ;; esac; }

log "ReachMyDevice Linux release build — version $VERSION, target $TARGET"
cd "$REPO_ROOT"
require_cmd cargo "install Rust via rustup"
# protoc is no longer needed — the protocol crate compiles its schema with the
# pure-Rust `protox` at build time.

# The vendored WebRTC fork is a submodule — make sure it's present.
git submodule update --init --recursive >/dev/null 2>&1 || true

reset_dist

# --- 1. Compile ------------------------------------------------------------
log "Building release binaries (${BINS[*]})"
PKGARGS=(); for b in "${BINS[@]}"; do PKGARGS+=(-p "$b"); done
cargo build --release --target "$TARGET" "${PKGARGS[@]}"

BINDIR="target/$TARGET/release"

# --- 2. Raw binaries -------------------------------------------------------
for b in "${BINS[@]}"; do
  bn="$(binname "$b")"
  [[ -x "$BINDIR/$bn" ]] || die "missing built binary: $BINDIR/$bn"
  cp "$BINDIR/$bn" "$DIST_DIR/$bn-linux-$ARCH"
done

# --- 3. Tarball ------------------------------------------------------------
STAGE="$(mktemp -d)"
PKG="rmd-$VERSION-linux-$ARCH"
mkdir -p "$STAGE/$PKG/bin"
for b in "${BINS[@]}"; do bn="$(binname "$b")"; install -m 0755 "$BINDIR/$bn" "$STAGE/$PKG/bin/$bn"; done
install -m 0755 deploy/install-host.sh "$STAGE/$PKG/install-host.sh"
for f in README.md LICENSE-MIT LICENSE-APACHE CHANGELOG.md; do
  [[ -f "$f" ]] && cp "$f" "$STAGE/$PKG/" || true
done
tar -C "$STAGE" -czf "$DIST_DIR/$PKG.tar.gz" "$PKG"
rm -rf "$STAGE"
log "Tarball: $PKG.tar.gz"

# --- 4. Debian packages ----------------------------------------------------
if ! command -v cargo-deb >/dev/null 2>&1; then
  log "Installing cargo-deb"
  cargo install cargo-deb --locked
fi
for pkg in rmd-host rmd-rendezvous; do
  log "Building .deb for $pkg"
  # --no-build: reuse the release binaries we just compiled.
  cargo deb -p "$pkg" --no-build --target "$TARGET" --output "$DIST_DIR/" \
    || warn "cargo deb failed for $pkg (skipping)"
done

# --- 5. Optional SBOM ------------------------------------------------------
if command -v cargo-cyclonedx >/dev/null 2>&1; then
  cargo cyclonedx --format json --all --override-filename "$DIST_DIR/rmd-sbom-linux-$ARCH" \
    >/dev/null 2>&1 || warn "SBOM generation failed (skipping)"
fi

# --- 6. Sign + checksum + publish -----------------------------------------
sign_all
write_checksums
log "Artifacts in $DIST_DIR:"; ls -la "$DIST_DIR"

publish_release "$VERSION"
log "Done: ReachMyDevice $VERSION (linux-$ARCH)"
