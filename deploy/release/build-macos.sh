#!/usr/bin/env bash
# Build + package + publish the OpenReach macOS (Apple Silicon) release artifacts.
#
# Run on a Mac (Apple Silicon). biscuits/Linux CANNOT produce these — a real .app
# and .dmg need macOS tooling. Produces, in ./dist:
#   - raw binaries:  openreach-{host,viewer}-macos-arm64
#   - tarball:       openreach-<version>-macos-arm64.tar.gz
#   - app + dmg:     OpenReach-<version>.dmg  (contains "OpenReach Viewer.app")
#   - SHA256SUMS + a .minisig for every artifact
# then creates/updates the GitHub Release v<version> and uploads them.
#
# Artifacts are UNSIGNED (no Apple Developer ID). First launch: right-click ->
# Open, or `xattr -dr com.apple.quarantine "/Applications/OpenReach Viewer.app"`.
#
# Usage:
#   deploy/release/build-macos.sh [VERSION]
#   OPENREACH_NO_UPLOAD=1 deploy/release/build-macos.sh   # build only, no gh upload

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

[[ "$(uname -s)" == "Darwin" ]] || die "build-macos.sh must run on macOS"

# Default to the arch this Mac can build AND run (tested). Apple Silicon ->
# arm64; Intel -> x86_64. Override with OPENREACH_MAC_ARCH=arm64|x86_64 to
# cross-build the other arch (produces a binary you cannot run/test here).
if [[ -n "${OPENREACH_MAC_ARCH:-}" ]]; then
  ARCH="$OPENREACH_MAC_ARCH"
elif [[ "$(sysctl -n hw.optional.arm64 2>/dev/null || echo 0)" == "1" ]]; then
  ARCH="arm64"
else
  ARCH="x86_64"
fi
case "$ARCH" in
  arm64)  TARGET="aarch64-apple-darwin" ;;
  x86_64) TARGET="x86_64-apple-darwin" ;;
  *) die "unsupported OPENREACH_MAC_ARCH: $ARCH (use arm64 or x86_64)" ;;
esac
VERSION="$(resolve_version "${1:-}")"
BINS=(openreach-host openreach-viewer)

log "OpenReach macOS release build — version $VERSION, target $TARGET"
cd "$REPO_ROOT"
require_cmd cargo "install Rust via rustup"
require_cmd protoc "brew install protobuf"
require_cmd hdiutil "part of macOS"

git submodule update --init --recursive >/dev/null 2>&1 || true
reset_dist

# --- 1. Compile ------------------------------------------------------------
log "Building release binaries (${BINS[*]})"
PKGARGS=(); for b in "${BINS[@]}"; do PKGARGS+=(-p "$b"); done
cargo build --release --target "$TARGET" "${PKGARGS[@]}"
BINDIR="target/$TARGET/release"

# --- 2. Raw binaries -------------------------------------------------------
for b in "${BINS[@]}"; do
  [[ -x "$BINDIR/$b" ]] || die "missing built binary: $BINDIR/$b"
  cp "$BINDIR/$b" "$DIST_DIR/$b-macos-$ARCH"
done

# --- 3. Tarball ------------------------------------------------------------
STAGE="$(mktemp -d)"
PKG="openreach-$VERSION-macos-$ARCH"
mkdir -p "$STAGE/$PKG/bin"
for b in "${BINS[@]}"; do install -m 0755 "$BINDIR/$b" "$STAGE/$PKG/bin/$b"; done
install -m 0755 deploy/install-host.sh "$STAGE/$PKG/install-host.sh"
for f in README.md LICENSE-MIT LICENSE-APACHE CHANGELOG.md; do
  [[ -f "$f" ]] && cp "$f" "$STAGE/$PKG/" || true
done
tar -C "$STAGE" -czf "$DIST_DIR/$PKG.tar.gz" "$PKG"
rm -rf "$STAGE"
log "Tarball: $PKG.tar.gz"

# --- 4. Viewer .app bundle -------------------------------------------------
APPNAME="OpenReach Viewer"
APPDIR="$(mktemp -d)/$APPNAME.app"
mkdir -p "$APPDIR/Contents/MacOS" "$APPDIR/Contents/Resources"
install -m 0755 "$BINDIR/openreach-viewer" "$APPDIR/Contents/MacOS/openreach-viewer"

ICON_TAG=""
if [[ -f "$REL_DIR/assets/OpenReach.icns" ]]; then
  cp "$REL_DIR/assets/OpenReach.icns" "$APPDIR/Contents/Resources/OpenReach.icns"
  ICON_TAG='<key>CFBundleIconFile</key><string>OpenReach</string>'
fi

cat > "$APPDIR/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>OpenReach Viewer</string>
  <key>CFBundleDisplayName</key><string>OpenReach Viewer</string>
  <key>CFBundleIdentifier</key><string>dev.brainwires.openreach.viewer</string>
  <key>CFBundleExecutable</key><string>openreach-viewer</string>
  <key>CFBundleVersion</key><string>$VERSION</string>
  <key>CFBundleShortVersionString</key><string>$VERSION</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>LSMinimumSystemVersion</key><string>11.0</string>
  <key>NSHighResolutionCapable</key><true/>
  $ICON_TAG
</dict>
</plist>
PLIST

# --- 5. DMG ----------------------------------------------------------------
DMGROOT="$(mktemp -d)"
cp -R "$APPDIR" "$DMGROOT/"
ln -s /Applications "$DMGROOT/Applications"
DMG="$DIST_DIR/OpenReach-$VERSION-$ARCH.dmg"
log "Building DMG"
hdiutil create -volname "OpenReach $VERSION" -srcfolder "$DMGROOT" \
  -ov -format UDZO "$DMG" >/dev/null
rm -rf "$DMGROOT" "$(dirname "$APPDIR")"

# --- 6. Optional SBOM ------------------------------------------------------
if command -v cargo-cyclonedx >/dev/null 2>&1; then
  cargo cyclonedx --format json --all --override-filename "$DIST_DIR/openreach-sbom-macos-$ARCH" \
    >/dev/null 2>&1 || warn "SBOM generation failed (skipping)"
fi

# --- 7. Sign + checksum + publish -----------------------------------------
sign_all
write_checksums
log "Artifacts in $DIST_DIR:"; ls -la "$DIST_DIR"

publish_release "$VERSION"
log "Done: OpenReach $VERSION (macos-$ARCH)"
