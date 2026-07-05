#!/usr/bin/env bash
# One-time setup of the OpenReach release signing key (minisign).
#
# Generates a password-less minisign keypair, stores the SECRET key at
# ~/.openreach/minisign.key (0600, NEVER committed), writes the public key to
# deploy/release/openreach-minisign.pub (committed), and patches the pinned
# pubkey into deploy/release/install.sh so `curl | sh` installs verify signatures.
#
# Run ONCE on the machine that holds the signing key, then copy the same secret
# key to any other build host (e.g. biscuits) so all release artifacts share one
# signing identity. Re-running refuses to clobber an existing key.
#
# Usage: deploy/release/setup-keys.sh

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

require_cmd minisign "brew install minisign  |  cargo install minisign  |  apt-get install minisign"

if [[ -f "$MINISIGN_KEY" ]]; then
  die "secret key already exists at $MINISIGN_KEY — refusing to overwrite.
    To rotate deliberately, move it aside first."
fi

mkdir -p "$(dirname "$MINISIGN_KEY")"; chmod 700 "$(dirname "$MINISIGN_KEY")"
log "Generating password-less minisign keypair"
# -W: password-less secret key (non-interactive signing on the webhook host).
minisign -G -W -s "$MINISIGN_KEY" -p "$MINISIGN_PUB"
chmod 600 "$MINISIGN_KEY"

# Extract the base64 public-key line (2nd line of the .pub file) and pin it.
PUBLINE="$(tail -n1 "$MINISIGN_PUB")"
[[ "$PUBLINE" == RWQ* || "$PUBLINE" == RW* ]] || die "unexpected pub key format: $PUBLINE"

log "Pinning public key into install.sh"
# Portable in-place edit (BSD/GNU sed differ on -i).
tmp="$(mktemp)"
sed "s|^MINISIGN_PUB=\".*\"|MINISIGN_PUB=\"$PUBLINE\"|" "$REL_DIR/install.sh" > "$tmp"
mv "$tmp" "$REL_DIR/install.sh"; chmod +x "$REL_DIR/install.sh"

log "Done."
echo
echo "  Secret key (KEEP PRIVATE, 0600):   $MINISIGN_KEY"
echo "  Public key (commit this):          $MINISIGN_PUB"
echo "  Pinned into:                       deploy/release/install.sh"
echo
echo "Next:"
echo "  1. Commit deploy/release/openreach-minisign.pub and the patched install.sh."
echo "  2. Copy $MINISIGN_KEY to the same path on biscuits (0600) so its webhook"
echo "     builds are signed with the same identity:"
echo "       scp $MINISIGN_KEY biscuits:~/.openreach/minisign.key"
echo "       ssh biscuits chmod 600 ~/.openreach/minisign.key"
