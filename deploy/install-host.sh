#!/usr/bin/env bash
# Install the ReachMyDevice host agent as a per-user background service.
#
# Usage:
#   ./deploy/install-host.sh [path-to-rmd-host-binary]
#
# With no argument it builds from source (cargo build --release). It installs the
# binary, the platform service unit (systemd user service on Linux, launchd agent
# on macOS), and seeds the config dir (~/.config/rmd) with an env template
# and an empty authorized_keys — then prints the next steps.
#
# Idempotent: safe to re-run to upgrade the binary.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/rmd"
BIN_DIR="$HOME/.local/bin"
BIN_NAME="rmdd"   # the host daemon binary (package rmd-host builds `rmdd`)

log() { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!!\033[0m %s\n' "$*" >&2; }

# 1. Resolve the binary (build if not provided).
if [[ $# -ge 1 ]]; then
  SRC_BIN="$1"
  [[ -x "$SRC_BIN" ]] || { warn "not executable: $SRC_BIN"; exit 1; }
else
  log "Building the host (cargo build --release)…"
  ( cd "$REPO_ROOT" && cargo build --release -p rmd-host )
  SRC_BIN="$REPO_ROOT/target/release/$BIN_NAME"
fi

# 2. Install the binary.
mkdir -p "$BIN_DIR"
install -m 0755 "$SRC_BIN" "$BIN_DIR/$BIN_NAME"
log "Installed $BIN_DIR/$BIN_NAME"

# 3. Seed config: env template + empty authorized_keys (do not clobber).
mkdir -p "$CONFIG_DIR"
chmod 700 "$CONFIG_DIR"
if [[ ! -f "$CONFIG_DIR/host.env" ]]; then
  cp "$REPO_ROOT/deploy/service/rmd-host.env.example" "$CONFIG_DIR/host.env"
  chmod 600 "$CONFIG_DIR/host.env"
  log "Wrote $CONFIG_DIR/host.env (edit it: token, name, authorized_keys)"
else
  log "Kept existing $CONFIG_DIR/host.env"
fi
if [[ ! -f "$CONFIG_DIR/authorized_keys" ]]; then
  printf '# Authorized viewer device_ids, one per line (see deploy/service/README.md).\n' \
    > "$CONFIG_DIR/authorized_keys"
  chmod 600 "$CONFIG_DIR/authorized_keys"
  log "Created $CONFIG_DIR/authorized_keys (empty = refuse all until you add ids)"
fi

# 4. Install the platform service unit.
case "$(uname -s)" in
  Linux)
    UNIT_DIR="$HOME/.config/systemd/user"
    mkdir -p "$UNIT_DIR"
    sed "s|%h/.local/bin/rmdd|$BIN_DIR/$BIN_NAME|g" \
      "$REPO_ROOT/deploy/service/rmd-host.service" > "$UNIT_DIR/rmd-host.service"
    log "Installed systemd user unit → $UNIT_DIR/rmd-host.service"
    if command -v systemctl >/dev/null; then
      systemctl --user daemon-reload || true
      cat <<EOF

Next steps (Linux):
  1. Edit $CONFIG_DIR/host.env (device token, authorized_keys).
  2. systemctl --user enable --now rmd-host
  3. (optional, start at boot without login) sudo loginctl enable-linger "$USER"
EOF
    fi
    ;;
  Darwin)
    AGENT_DIR="$HOME/Library/LaunchAgents"
    mkdir -p "$AGENT_DIR"
    sed "s|/usr/local/bin/rmdd|$BIN_DIR/$BIN_NAME|g" \
      "$REPO_ROOT/deploy/service/com.brainwires.rmd-host.plist" \
      > "$AGENT_DIR/com.brainwires.rmd-host.plist"
    log "Installed launchd agent → $AGENT_DIR/com.brainwires.rmd-host.plist"
    cat <<EOF

Next steps (macOS):
  1. Edit $CONFIG_DIR/host.env (device token, authorized_keys).
  2. Grant Screen Recording + Accessibility to $BIN_DIR/$BIN_NAME
     (System Settings → Privacy & Security; see docs/macos-permissions.md).
  3. launchctl load -w "$AGENT_DIR/com.brainwires.rmd-host.plist"
EOF
    ;;
  *)
    warn "Unsupported OS for service install; binary is at $BIN_DIR/$BIN_NAME"
    ;;
esac

log "Done."
