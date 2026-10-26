#!/usr/bin/env bash
# Say whether the install tree above advisor/state is writable by anyone but
# root and its owner, and what the repair would change.
#
#   bash scripts/fix-state-ancestors.sh --check    say what the repair would do
#
# The repair itself is root's, and it runs as part of the update, which the
# refusals about the layout name:
#
#   curl -fsSL https://get.aperire.one | bash -s -- --update --force
#
# The update runs it from a copy it held to the release's digests. Root does
# not run this file: it sits in the checkout, which the login that owns it can
# change, and the shape it repairs is a tree a service account may be able to
# write (ADR 0024, #955). Run as root, it says so and changes nothing.
#
# What it does: takes group and other write off the directories above
# advisor/state, and nothing else. It does not touch advisor/state, the fleet
# corpus, any file, any group membership, or any directory above the install
# itself. scripts/state-ancestors-lib.sh has the long version and the reason
# each of those is left alone.
#
# Why it exists (#703). The Advisor's account owns advisor/state, and root
# walks through the directories above it to plant this host's tokens and its
# model config. On a host where those directories are group-writable and that
# group holds the Advisor's own account, the Advisor can rename a directory
# out from under root mid-write. Found on an aggregator whose install tree was
# 0775 owner:owner with the Advisor's account in the owner's group; the mode
# is umask 002's doing and the membership was made by hand, so neither is
# something an installer can be trusted to have prevented.

set -uo pipefail

UPDATE_LINE='curl -fsSL https://get.aperire.one | bash -s -- --update --force'
if [[ $EUID -eq 0 ]]; then
  # Before anything here is loaded: root reads nothing out of the checkout.
  echo "error: root does not run this checkout's copy of the repair: the login that owns" >&2
  echo "       the checkout can change it. The update runs the same repair from a copy it" >&2
  echo "       checked against the release. Run it as your own account:" >&2
  echo "           $UPDATE_LINE" >&2
  echo "       Nothing was changed." >&2
  exit 1
fi

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
STATE="${APERIRE_ADVISOR_STATE:-$REPO/advisor/state}"
if [[ "${1:-}" != "--check" || $# -ne 1 ]]; then
  echo "usage: bash $0 --check" >&2
  echo "       The repair is part of the update:  $UPDATE_LINE" >&2
  exit 2
fi

[[ -r "$HERE/state-ancestors-lib.sh" ]] \
  || { echo "error: $HERE/state-ancestors-lib.sh is missing from this checkout" >&2; exit 1; }
# shellcheck source=scripts/state-ancestors-lib.sh
. "$HERE/state-ancestors-lib.sh"
# Read only, as this account: the helper beside this file.
STATE_ANCESTORS_TOOL="$HERE/state-file.py"

if [[ ! -d "$STATE" ]]; then
  echo "There is no $STATE on this host, so there is no Advisor state to protect."
  echo "Nothing was changed."
  exit 0
fi

echo "== The install tree above $STATE"
state_ancestors_narrow "$REPO" "$STATE" --dry-run
rc=$?
echo
if (( rc == 0 )); then
  echo "Nothing to do on this host."
else
  echo "The update makes this repair, as root, from a copy it checked:"
  echo "  $UPDATE_LINE"
fi
exit "$rc"
