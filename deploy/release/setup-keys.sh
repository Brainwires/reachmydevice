#!/usr/bin/env bash
# One-time setup of the ReachMyDevice release signing key (minisign).
#
# Generates a password-less minisign keypair, stores the SECRET key at
# ~/.rmd/minisign.key (0600, NEVER committed), writes the public key to
# deploy/release/rmd-minisign.pub (committed), and patches the pinned
# pubkey into deploy/release/install.sh so `curl | sh` installs verify signatures.
#
# Run ONCE on the machine that holds the signing key, then copy the same secret
# key to any other build host (e.g. biscuits) so all release artifacts share one
# signing identity. Re-running refuses to clobber an existing key.
#
# Usage: deploy/release/setup-keys.sh

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

# rsign2 (pure Rust) is preferred so key generation + signing need no C tooling.
# The minisign C CLI still works as a fallback if that's what's installed.
require_cmd rsign "cargo install rsign2   (pure-Rust; or: brew/apt install minisign)"

if [[ -f "$MINISIGN_KEY" ]]; then
  die "secret key already exists at $MINISIGN_KEY — refusing to overwrite.
    To rotate deliberately, move it aside first."
fi

mkdir -p "$(dirname "$MINISIGN_KEY")"; chmod 700 "$(dirname "$MINISIGN_KEY")"
log "Generating password-less signing keypair (rsign2, minisign-compatible)"
# -W: password-less secret key (non-interactive signing on the webhook host).
# rsign2's -W uses an empty-password KDF, which rsign2 can then sign with (unlike
# minisign's -W kdf=0 keys, which rsign2 refuses to sign).
rsign generate -W -f -s "$MINISIGN_KEY" -p "$MINISIGN_PUB" -c "ReachMyDevice release signing key"
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
echo "  1. Commit deploy/release/rmd-minisign.pub and the patched install.sh."
echo "  2. Copy $MINISIGN_KEY to the same path on biscuits (0600) so its webhook"
echo "     builds are signed with the same identity:"
echo "       scp $MINISIGN_KEY biscuits:~/.rmd/minisign.key"
echo "       ssh biscuits chmod 600 ~/.rmd/minisign.key"
