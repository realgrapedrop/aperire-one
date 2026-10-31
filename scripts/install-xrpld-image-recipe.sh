#!/usr/bin/env bash
# Install the xrpld image recipe where root can run it.
#
#   sudo bash scripts/install-xrpld-image-recipe.sh
#   sudo bash scripts/install-xrpld-image-recipe.sh --refresh-only
#   sudo bash scripts/install-xrpld-image-recipe.sh --status
#
# What it installs, root-owned, 0755 directories and 0644 files:
#
#   /usr/local/lib/aperire/build-xrpld-image.sh      the build, and its proof
#   /usr/local/lib/aperire/xrpld-image/Dockerfile    the recipe
#   /usr/local/lib/aperire/xrpld-image/entrypoint.sh the image's entrypoint
#   /usr/local/lib/aperire/xrpld-image/signed-binary-sha256.sh
#       the release's xrpld binary hash, read through the signed apt chain
#
# Why not run it out of the checkout. The privilege wrapper's `build-image`
# verb runs this as root, and the checkout is a tree the account serving the
# dashboard can write. Building from there would hand that account a root
# build with its own Dockerfile and its own entrypoint, which is the same
# class of hole as a root write that follows a planted symlink (#657). The
# wrapper refuses anything here that is not a root-owned regular file in a
# root-owned directory, symlinks included, so the copy has to exist and has
# to be root's.
#
# --refresh-only updates an installation that is already here and installs
# nothing on a host that has none. That is what an update runs: adding a root
# grant to a host nobody asked that of is a widening, and an update's promise
# is that it changes what is here rather than adding what is not.
#
# Re-runnable. It compares before it writes, so a re-run on a current host
# says so and touches nothing. Nothing here starts, stops or restarts
# anything, and no image is built: this only puts files in place.
set -euo pipefail

# As root the environment chooses no path (#1206): every APERIRE_* variable
# is dropped except the one a root caller passes on purpose:
#   APERIRE_INSTALL_TREE  get-aperire.sh names the tree a staged copy serves
#                         (#764); the node and wrapper installers pass theirs on
# An account id(1) says is not root keeps them all, which is what every
# suite is. id(1) at a fixed path, never bash's $EUID (#1109).
if ! [[ "$(/usr/bin/id -u 2>/dev/null)" =~ ^[1-9][0-9]*$ ]]; then
  for _v in $(compgen -e); do
    case "$_v" in APERIRE_INSTALL_TREE) ;; APERIRE_*) unset "$_v" ;; esac
  done
fi

# Where this program and its siblings are (RECIPE_SELF), and the install tree it acts
# on (REPO_DIR): a directory and its parent from a checkout, two when it is a copy
# root staged out of the release and APERIRE_INSTALL_TREE names the tree
# (#764). Code is loaded and run from RECIPE_SELF only.
RECIPE_SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="${APERIRE_INSTALL_TREE:-$(cd "$RECIPE_SELF/.." && pwd)}"
# A variable only so the tests can point it somewhere harmless, and only for
# an account that is not root (above). The wrapper's own copy of this path is
# a constant.
DEST_DIR="${APERIRE_IMAGE_RECIPE_DIR:-/usr/local/lib/aperire}"

SRC_SCRIPT="$REPO_DIR/scripts/build-xrpld-image.sh"
SRC_CONTEXT="$REPO_DIR/scripts/xrpld-image"

MODE=install
case "${1:-}" in
  '')             ;;
  --refresh-only) MODE=refresh ;;
  --status)       MODE=status ;;
  -h|--help)      sed -n '2,/^set -euo/p' "${BASH_SOURCE[0]}" | sed '$d; s/^# \{0,1\}//'; exit 0 ;;
  *)              printf 'unknown option: %s (see --help)\n' "$1" >&2; exit 2 ;;
esac

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
info() { printf '   %s\n' "$*"; }
die()  { printf '\n\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

DEST_SCRIPT="$DEST_DIR/build-xrpld-image.sh"
DEST_CONTEXT="$DEST_DIR/xrpld-image"

if [[ "$MODE" == status ]]; then
  say "xrpld image recipe"
  for pair in "$SRC_SCRIPT:$DEST_SCRIPT" \
              "$SRC_CONTEXT/Dockerfile:$DEST_CONTEXT/Dockerfile" \
              "$SRC_CONTEXT/entrypoint.sh:$DEST_CONTEXT/entrypoint.sh" \
              "$SRC_CONTEXT/signed-binary-sha256.sh:$DEST_CONTEXT/signed-binary-sha256.sh"; do
    src="${pair%%:*}"; dest="${pair##*:}"
    if [[ ! -e "$dest" ]]; then
      info "not installed: $dest"
    elif cmp -s "$src" "$dest" 2>/dev/null; then
      info "current:       $dest"
    else
      info "DIFFERS:       $dest (this checkout has a different copy)"
    fi
  done
  exit 0
fi

[[ $EUID -eq 0 ]] || die "run with sudo: $DEST_DIR must be owned by root, or the account this recipe is run on behalf of could rewrite what root builds"

for f in "$SRC_SCRIPT" "$SRC_CONTEXT/Dockerfile" "$SRC_CONTEXT/entrypoint.sh" \
         "$SRC_CONTEXT/signed-binary-sha256.sh" "$RECIPE_SELF/release-digests-lib.sh"; do
  [[ -f "$f" ]] || die "missing from this checkout: $f"
done
# Every file is checked against the release's digests and copied from the one
# read that was checked (ADR 0024): root builds from these, so a recipe file
# the release did not ship is refused rather than installed.
# shellcheck source=scripts/release-digests-lib.sh
. "$RECIPE_SELF/release-digests-lib.sh"

if [[ "$MODE" == refresh && ! -e "$DEST_SCRIPT" ]]; then
  # Nothing to refresh. Silent success: an update runs this on every host,
  # and a host that never had the recipe is not a fault.
  exit 0
fi

say "xrpld image recipe -> $DEST_DIR"

install -d -m 0755 -o root -g root "$DEST_DIR"
install -d -m 0755 -o root -g root "$DEST_CONTEXT"

changed=0
place() { # $1 = path in the release, $2 = destination, $3 = mode
  local rel=$1 dest=$2 mode=$3 out
  if [[ -L "$dest" ]]; then
    # A symlink here is either a mistake or someone redirecting a root build.
    # Either way it is removed rather than written through.
    rm -f "$dest"
    info "removed a symlink at $dest"
  fi
  # Checked, then written beside it and renamed, never over the top, so a
  # build reading the recipe at this moment finishes on the copy it started
  # with.
  out="$(rd_install "$REPO_DIR" "$rel" "$dest" "$mode" --kinds)" || {
    # The account check not running is not a file that changed (#1111).
    rd_was_accounts "$out" \
      && die "$dest was not installed: $(rd_refused_cause "$rel in this checkout" "$out")"
    die "$dest was not installed: $rel in this checkout is not the file this release shipped, or could not be written (above)"
  }
  if [[ "$out" == same ]]; then
    info "already current: $dest"
  else
    info "installed: $dest"
    changed=1
  fi
}

place scripts/build-xrpld-image.sh "$DEST_SCRIPT" 0644
place scripts/xrpld-image/Dockerfile "$DEST_CONTEXT/Dockerfile" 0644
place scripts/xrpld-image/entrypoint.sh "$DEST_CONTEXT/entrypoint.sh" 0644
place scripts/xrpld-image/signed-binary-sha256.sh "$DEST_CONTEXT/signed-binary-sha256.sh" 0644

# The wrapper's own check, run here so a bad installation is found by the
# installer rather than by the first upgrade.
#
# Only when this actually ran as root, which in production is always (the
# gate above refuses anything else). A fixture that neuters that gate writes
# files owned by whoever ran it, and claiming those are root's would be a
# claim about a host nobody was on.
if [[ $EUID -eq 0 ]]; then
  for p in "$DEST_DIR" "$DEST_SCRIPT" "$DEST_CONTEXT" "$DEST_CONTEXT/Dockerfile" \
           "$DEST_CONTEXT/entrypoint.sh" "$DEST_CONTEXT/signed-binary-sha256.sh"; do
    [[ ! -L "$p" ]] || die "$p is a symlink; the wrapper will refuse to build from it"
    owner=$(stat -c '%u' "$p")
    [[ "$owner" == 0 ]] || die "$p is owned by uid $owner, not root; the wrapper will refuse to build from it"
    mode=$(stat -c '%a' "$p")
    (( (8#$mode & 8#022) == 0 )) || die "$p is mode $mode, writable by someone other than root; the wrapper will refuse to build from it"
  done
fi

if (( changed )); then
  info "root can now build an xrpld image from the signed package on this host."
else
  info "nothing changed; this host already had this release's recipe."
fi
info "the Advisor reaches it through the wrapper: aperire-node-wrapper.sh build-image <version>"
info "by hand:  sudo bash $DEST_SCRIPT --version <version>"
