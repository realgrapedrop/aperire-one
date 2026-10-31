#!/usr/bin/env bash
# Put a peer's read token where the dashboard and the Advisor read it (#1144).
#
#   aperire-fleet-add.sh --place-token   runs it for you, as the last root step of a join
#
# That is the only way in. The token is its standard input, which the join
# opens as you and hands to the bootstrap's `--run peer-token --label <label>`.
# No curl form places a token: a piped bootstrap has no stdin to give it.
#
# Root runs it only as a copy it checked: the bootstrap's peer-token step
# stages the release and runs this file out of the stage (#897, #929).
#
# ---- what root does here ---------------------------------------------
#
# It reads the peer's token from standard input and writes exactly one file
# and the folder that file sits in:
#
#   <install>/advisor/state/peer-tokens/<label>.token   root:<group> 0640
#   <install>/advisor/state/peer-tokens                 root:<group> 0750
#
# <group> is the group of this host's own advisor/state/read.token, the one
# the dashboard and the Advisor already read it through. The file is root's on
# purpose: the Advisor narrows every peer token it OWNS to 0600 on each start,
# which would lock the dashboard out of a copy it owned.
#
# It touches nothing else. It does not read the token's file by name (the
# bootstrap's caller opens it and hands it over on a descriptor), it takes no
# path, and the label is the one argument: a-z, 0-9 and "-", starting with a
# letter or digit, up to 32 characters. No "/" and no "." can be in it, so the
# name cannot leave peer-tokens. The folder and the file are made on the
# descriptors state-file.py walks under advisor/state (no link followed, a
# regular file only), never by name. The token never goes on a command line.
#
# state-file.py is the copy staged beside this file, not the one in the tree.

set -euo pipefail

# Run as root, the environment chooses no path (#1206): every APERIRE_*
# variable is dropped except the one the bootstrap passes on purpose,
# APERIRE_INSTALL_TREE, which names the install this staged copy serves. An
# account id(1) says is not root keeps them all, which is what the suites are.
if ! [[ "$(/usr/bin/id -u 2>/dev/null)" =~ ^[1-9][0-9]*$ ]]; then
  for _v in $(compgen -e); do
    case "$_v" in APERIRE_INSTALL_TREE) ;; APERIRE_*) unset "$_v" ;; esac
  done
fi

SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# The install: the one APERIRE_INSTALL_TREE names when root runs a copy the
# bootstrap staged, else this checkout.
REPO="${APERIRE_INSTALL_TREE:-$(cd "$SELF/.." && pwd)}"
STATE="$REPO/advisor/state"
TOOL="$SELF/state-file.py"

die() { printf 'error: %s\n' "$*" >&2; exit 1; }

usage() {
  printf 'usage: place-peer-token.sh --label <label> < <token file>\n'
  printf 'Puts the token on standard input at advisor/state/peer-tokens/<label>.token: root:<group of read.token>, 0640.\n'
}

LABEL=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --label) [[ $# -ge 2 ]] || die "--label needs a value"; [[ -z "$LABEL" ]] || die "--label was given twice"; LABEL="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument '$1'. It takes --label <label>, and the token on standard input" ;;
  esac
done

# The same shape the bootstrap holds the label to, checked again here: this
# file is the one that builds a path from it. LC_ALL=C so a range follows
# ASCII and not the locale.
[[ -n "$LABEL" ]] || die "--label is required: the node whose token this is"
(
  LC_ALL=C
  [[ "$LABEL" =~ ^[a-z0-9][a-z0-9-]{0,31}$ ]]
) || die "--label takes up to 32 letters, digits and hyphens, starting with a letter or digit"

[[ "$(/usr/bin/id -u)" == 0 ]] || die "run it as root, through the bootstrap's peer-token step. aperire-fleet-add.sh --place-token does that, and hands over the token"
[[ ! -t 0 ]] || die "the token is read on standard input, and this is a terminal. Run it through aperire-fleet-add.sh --place-token, which hands it over"
[[ -f "$TOOL" ]] || die "$TOOL is missing beside this program, and it is what writes the token without following a link"
[[ -d "$STATE" && ! -L "$STATE" ]] || die "$STATE is not a folder on this host. A host with no Advisor has no use for the Advisor's copy of a peer's token"

# The group of this host's own read.token, from the descriptor the helper
# reads it on (no link followed, a regular file only). The first line is
# "<uid> <gid> <mode>"; the rest is the host's own token and is dropped here.
META="$(python3 -I "$TOOL" read "$STATE/read.token" --root "$STATE" --meta)" \
  || die "could not read which group $STATE/read.token is read through, and the token is placed in that group so the dashboard and the Advisor can read it"
META="${META%%$'\n'*}"
GID="${META#* }"; GID="${GID%% *}"
[[ "$GID" =~ ^[0-9]+$ ]] || die "the group of $STATE/read.token did not come back as a number"

# The whole of standard input, as the bytes it holds. Nothing here is an
# argument, and printf is a builtin, so the token is on no command line.
TOKEN=""
IFS= read -r -d '' TOKEN || true
[[ -n "${TOKEN//[[:space:]]/}" ]] || die "nothing came in on standard input, so there is no token to place. Nothing was written"

DEST="$STATE/peer-tokens/$LABEL.token"
python3 -I "$TOOL" mkdir "$STATE/peer-tokens" 0 "$GID" 750 --root "$STATE" \
  || die "could not make $STATE/peer-tokens (the helper's reason is above). Nothing was written"
printf '%s' "$TOKEN" | python3 -I "$TOOL" plant "$DEST" 0 "$GID" 640 --root "$STATE" --stdin \
  || die "could not place the token at $DEST (the helper's reason is above)"
printf 'placed %s, owned by root, group id %s, mode 0640\n' "$DEST" "$GID"
