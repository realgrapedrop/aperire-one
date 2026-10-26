#!/usr/bin/env bash
# Open a model-key window on every node in the fleet, from one root line here.
#
#   sudo aperire-fleet-arm                    the whole fleet
#   sudo aperire-fleet-arm --node stock-node1 one node, and only it
#   sudo aperire-fleet-arm --self-only        this host alone
#   sudo aperire-fleet-arm --fingerprint      the pairing fingerprint only,
#                                             read-only (#741): one line of
#                                             64 hex on stdout, nothing else
#
# On an aggregator whose grant predates the installed name, the same flags
# work on the tree's copy: sudo bash <install-dir>/scripts/aperire-fleet-arm.sh
#
# `aperire-fleet-arm` is this file installed root-owned in /usr/local/sbin
# by the fleet broker grant, and that installed name is the one a node's
# operator is told to run: a fixed command on root's PATH, so nobody takes a
# path for it from a page the dashboard account serves.
#
# Every run also prints the PAIRING FINGERPRINT: one value over this
# aggregator's fleet trust key and its fleet arm key. A node being paired asks
# the operator to paste it, and refuses anything but the whole value. Root's
# output here is its only reference; see "the pairing fingerprint" below.
#
# ---- why this exists ------------------------------------------------
#
# Sealing a model API key needs root on the node it is sealed to, and the
# dashboard is not root and cannot become it. What crosses that boundary is a
# window: a root-owned marker whose age the node's sealer checks, spent on the
# first seal. Opening one is a root decision, deliberately, because a program
# the dashboard could run to open its own window would be the same as no
# window at all.
#
# On one host that is one line before one seal. On a fleet it was one line per
# node, over a tunnel or an SSH session per node, in the fifteen minutes
# before the window lapsed. Thirty nodes is thirty of those, which is how an
# operator ends up leaving hosts armed. This is the same decision, taken once,
# for as many nodes as it names.
#
# ---- why the key is root's ------------------------------------------
#
# /etc/aperire/fleet-arm.key, mode 0600 root:root, made by the first of the
# things to need it: the fleet broker grant's installer, this script's first
# arming run, or the fleet broker's first pairing approval (#723), which
# hands its public half to the node it pairs. `--fingerprint` never makes it.
# Since #851 none of the three makes it on a host that has had one
# (fleet-arm.made) or has a fleet; each refuses and names the restore.
# The account the dashboard runs as cannot read it, so no dashboard, on this
# host or any other, can mint a token. The private half never leaves this
# machine and is never sent anywhere: what travels is a signature over five
# short lines that name one node, once.
#
# Each node holds only the public half, placed there by its own root:
#
#   curl -fsSL https://get.aperire.one | bash -s -- --run model-key-sealer --trust-arm-key <key>
#
# A node that was never given one refuses every token, by name. Nothing is
# trusted by default, and a node's own operator can always arm it themselves.
#
# ---- the token ------------------------------------------------------
#
# Five plain lines, signed as they are, sent as JSON with the signature:
#
#   v=1
#   issuer=<this aggregator's label>
#   target=<the node's pinned public key, from fleet.yaml>
#   nonce=<32 hex>
#   issued_at=<unix seconds>
#
# `target` is what stops a token being replayed at a different node, and it is
# checked twice on arrival: the node's dashboard refuses one addressed
# elsewhere before its sealer is reached, and the sealer, which is the thing
# that verifies the signature, compares it with the node key root stamped on
# that host. A row with no `expected_pubkey_node` in fleet.yaml is SKIPPED
# here rather than armed blind, because a token addressed to a node nobody
# pinned cannot be checked by the node that receives it. `nonce` and `issued_at` are what
# stop the same token opening a second window: each node remembers the nonces
# it has honoured, and refuses anything more than 300 seconds from its own
# clock.
#
# The token goes to the node's dashboard, over the loopback port this host
# already reaches it on (the read_origin in fleet.yaml, a tunnel), with that
# node's read token as the bearer. The dashboard checks the shape, refuses a
# token for another node, and hands it to its own root sealer, which is the
# only thing here that verifies the signature. The dashboard in the middle is
# a courier: it cannot forge a token, and it cannot arm itself.

set -euo pipefail

ETC="${APERIRE_ETC:-/etc/aperire}"

# Which install this is. Run from a checkout (scripts/ inside a tree), the
# tree it sits in. Run as the INSTALLED copy, /usr/local/sbin/aperire-fleet-arm
# (#741: the fixed name a node's operator is told to run for the pairing
# fingerprint), the install directory root recorded when it installed the
# fleet broker grant, read from $ETC/fleet-broker.conf as key=value and never
# sourced. That file is root's: one this program would read through a link,
# or that another account may write, names no directory here.
SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ "$(basename -- "$SELF_DIR")" == scripts && -d "$SELF_DIR/../dashboard" ]]; then
  REPO="$(cd "$SELF_DIR/.." && pwd)"
else
  _conf="$ETC/fleet-broker.conf"
  [[ -f "$_conf" && ! -L "$_conf" ]] \
    || { printf 'error: %s\n' "this is the installed copy, and $_conf is not there to say which install it serves. Run curl -fsSL https://get.aperire.one | bash -s -- --run fleet-broker-grant on this host" >&2; exit 1; }
  _st="$(stat -c '%u %a' -- "$_conf")"
  if ! [[ "${_st%% *}" == 0 || "${_st%% *}" == "$(/usr/bin/id -u 2>/dev/null)" ]] || (( (8#${_st##* } & 8#022) != 0 )); then
    printf 'error: %s\n' "$_conf is not root's alone, so the install it names is not one this program will act on" >&2; exit 1
  fi
  REPO="$(sed -n 's/^INSTALL_DIR=//p' "$_conf" | head -n 1)"
  REPO="${REPO%\"}"; REPO="${REPO#\"}"
  [[ "$REPO" == /* && -d "$REPO/dashboard" ]] \
    || { printf 'error: %s\n' "$_conf names no install directory with a dashboard/ in it" >&2; exit 1; }
fi
KEY="$ETC/fleet-arm.key"
ARM_FILE="$ETC/model-key.arm"
FLEET_FILE="${APERIRE_FLEET_FILE:-$REPO/dashboard/config/fleet.yaml}"
UNIT_DIR="${APERIRE_UNIT_DIR:-/etc/systemd/system}"
# What the node's sealer opens, in seconds. Printed here so one line reads the
# same on both sides; the value that governs is APERIRE_ARM_WINDOW_SEC there.
ARM_WINDOW_SEC=900
# The port install-aperire-service.sh gives a dashboard when nobody says
# otherwise. Only a fallback: the port is read from this host's own unit first.
DEFAULT_PORT=7800

say()  { printf '   %s\n' "$*"; }
info() { printf '   %s\n' "$*" >&2; }
die()  { printf 'error: %s\n' "$*" >&2; exit 1; }

ONLY_NODE=""
SELF_ONLY=0
FP_ONLY=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --node)
      [[ $# -ge 2 ]] || die "--node needs a label"
      ONLY_NODE="$2"; shift 2 ;;
    --self-only) SELF_ONLY=1; shift ;;
    --fingerprint) FP_ONLY=1; shift ;;
    -h|--help) awk '/^[^#]/{exit} NR>1{sub(/^# ?/,""); print}' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done
[[ -z "$ONLY_NODE" || $SELF_ONLY -eq 0 ]] \
  || die "--node and --self-only ask for different things; give one"
[[ $FP_ONLY -eq 0 || ( -z "$ONLY_NODE" && $SELF_ONLY -eq 0 ) ]] \
  || die "--fingerprint only prints; it arms nothing, so it takes neither --node nor --self-only"

[[ $EUID -eq 0 ]] || die "run with sudo: the fleet arm key is root's, and arming this host writes a root-owned marker"
command -v openssl >/dev/null || die "openssl is not on this host, and the token is signed with it"

WORK="$(umask 077; mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# ---- the pairing fingerprint (#741) ----------------------------------
#
# ONE value over this aggregator's fleet trust PUBLIC key and its fleet arm
# PUBLIC key. A node pairing with this aggregator asks the operator to paste
# it, and compares the whole value against what it computes from the signed
# welcome. This script, run as root, is its only reference: the dashboard's
# account is the one thing that could put a different arm key in a welcome,
# so a value the dashboard showed would be worth nothing.
#
# The trust key's private half is in dashboard/config/fleet-trust.yaml, a
# file the DASHBOARD account owns, in a directory it owns, and root reads it
# here. So it is read the way the broker reads that directory: the final name
# is never followed through a link, a FIFO cannot hold this open (O_NONBLOCK,
# then a regular-file check on the descriptor), and it is bounded. What comes
# out is only the PUBLIC half, derived here and never printed as a seed. The
# trust key being the dashboard's own is not new (it signs everything the
# aggregator sends): what this fingerprint adds is the arm key, which is
# root's.
TRUST_FILE="${APERIRE_FLEET_TRUST_FILE:-$REPO/dashboard/config/fleet-trust.yaml}"

# The public half of this aggregator's fleet trust key, base64url, on stdout.
# Returns 1 (printing nothing) when there is none this program will read.
fleet_trust_pub_b64url() {
  local der="$WORK/trust.der"
  rm -f "$der"
  python3 -I - "$TRUST_FILE" "$der" <<'PYTRUST' || return 1
import base64, os, stat, sys
path, out = sys.argv[1], sys.argv[2]
try:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
except OSError:
    sys.exit(1)
try:
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_size > 65536:
        sys.exit(1)
    data = os.read(fd, 65537)
finally:
    os.close(fd)
seed = ""
for line in data.decode("utf-8", "replace").splitlines():
    # Top level only, the rule lib/trust-bundle.ts's readOwnPrivateKey keeps.
    # The value exactly as readOwnPrivateKey reads it: trimmed, then ONE
    # quote character off each end, the first such line only.
    if line.startswith("private_key:"):
        seed = line[len("private_key:"):].strip()
        if seed[:1] in ("'", '"'):
            seed = seed[1:]
        if seed[-1:] in ("'", '"'):
            seed = seed[:-1]
        break
if not seed:
    sys.exit(1)
try:
    raw = base64.urlsafe_b64decode(seed + "=" * (-len(seed) % 4))
except Exception:
    sys.exit(1)
if len(raw) != 32:
    sys.exit(1)
fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "wb") as f:
    f.write(bytes.fromhex("302e020100300506032b657004220420") + raw)
PYTRUST
  local pub
  pub="$(openssl pkey -in "$der" -pubout -outform DER 2>/dev/null | tail -c 32 \
    | python3 -I -c 'import sys,base64; sys.stdout.write(base64.urlsafe_b64encode(sys.stdin.buffer.read()).decode().rstrip("="))')" || pub=''
  rm -f "$der"
  [[ -n "$pub" ]] || return 1
  printf '%s' "$pub"
}

# ---- BEGIN fleet_pairing_fingerprint (#741) ---------------------------
# The bash twin of fleetPairingFingerprint() in
# dashboard/types/fleet-link-contract.ts: sha256 over a fixed domain line,
# the raw trust key and the raw arm key, all 64 hex, lowercase, printed bare.
# Both keys must be the
# CANONICAL encoding of 32 bytes (the trust key base64url, the arm key plain
# base64), or there is no fingerprint. scripts/test-seal-model-key.sh runs
# this block against the contract's FLEET_PAIRING_FINGERPRINT_VECTOR, so the
# two cannot drift.
fleet_pairing_fingerprint() {  # $1 = trust key (base64url), $2 = arm key (base64)
  python3 -I - "$1" "$2" <<'PYFP'
import base64, binascii, hashlib, sys
trust_s, arm_s = sys.argv[1], sys.argv[2]
def raw(s, urlsafe):
    try:
        if urlsafe:
            b = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
            back = base64.urlsafe_b64encode(b).decode().rstrip("=")
        else:
            b = base64.b64decode(s, validate=True)
            back = base64.b64encode(b).decode()
    except (binascii.Error, ValueError):
        return None
    if len(b) != 32 or back != s:
        return None
    return b
t, a = raw(trust_s, True), raw(arm_s, False)
if t is None or a is None:
    sys.exit(1)
sys.stdout.write(hashlib.sha256(b"aperire-fleet-pairing-fingerprint/2\n" + t + a).hexdigest())
PYFP
}
# ---- END fleet_pairing_fingerprint -----------------------------------

# Prints the pairing fingerprint block, or one sentence saying why there is
# none. $1 = the arm key's public half (base64). Returns 1 when there is none.
#
# The value goes on a line of its own with nothing around it: no indent, no
# groups. One spelling everywhere it prints, so a double-click copies all of
# it and what an operator copies here is what --fingerprint prints.
print_pairing_fingerprint() {
  local trust fp
  if ! trust="$(fleet_trust_pub_b64url)"; then
    echo
    say "no pairing fingerprint: this host holds no fleet trust key that root will read at"
    say "$TRUST_FILE, so it is not an aggregator nodes pair with."
    return 1
  fi
  fp="$(fleet_pairing_fingerprint "$trust" "$1")" || {
    echo
    say "no pairing fingerprint: one of this host's two keys is not a 32-byte key."
    return 1
  }
  echo
  echo "== Pairing fingerprint"
  printf '%s\n' "$fp"
  say "A node asks for this when it pairs with this aggregator. Paste all of it there."
  return 0
}

if (( FP_ONLY )); then
  # Read-only: nothing is made, armed or sent. Stdout carries ONE line, the
  # value, 64 lowercase hex and nothing else, so
  #   FP=$(ssh aggregator sudo aperire-fleet-arm --fingerprint)
  # feeds --expect-fingerprint "$FP" on a node as it is. Everything meant for
  # a person (the label, every refusal) is on stderr. The answers are told
  # apart by exit status so the installer's closing summary can say the
  # right one:
  #   0  the fingerprint, printed
  #   2  this host holds no fleet trust key root will read: not an aggregator,
  #      or one whose broker grant predates the grant making that key
  #   3  an aggregator with no arm key yet (the broker grant's installer, the
  #      Settings page's pairing check and the first approval each make it;
  #      this never does)
  #   1  anything else, said by name
  FP_GRANT="curl -fsSL https://get.aperire.one | bash -s -- --dir $REPO --run fleet-broker-grant"
  if ! FP_TRUST="$(fleet_trust_pub_b64url)"; then
    printf 'error: no pairing fingerprint: this host holds no fleet trust key that root will read at %s. On an aggregator, the pairing grant makes it: %s\n' "$TRUST_FILE" "$FP_GRANT" >&2
    exit 2
  fi
  if [[ ! -e "$KEY" && ! -L "$KEY" ]]; then
    printf 'error: this host has no fleet arm key yet at %s, so there is no pairing fingerprint. The pairing grant makes it: %s, then run this again.\n' "$KEY" "$FP_GRANT" >&2
    exit 3
  fi
  [[ -f "$KEY" && ! -L "$KEY" ]] || die "$KEY is not a regular file; a signing key is never read through a link"
  [[ -O "$KEY" ]] || die "$KEY is not root's, so its public half is not one this host can vouch for"
  FP_ARM="$(openssl pkey -in "$KEY" -pubout -outform DER 2>/dev/null | tail -c 32 | base64 -w0)" || FP_ARM=''
  [[ -n "$FP_ARM" ]] || die "$KEY is not a usable Ed25519 private key"
  FP="$(fleet_pairing_fingerprint "$FP_TRUST" "$FP_ARM")" \
    || die "one of this host's two keys is not a 32-byte key, so there is no pairing fingerprint"
  [[ "$FP" =~ ^[0-9a-f]{64}$ ]] || die "the pairing fingerprint did not come out as 64 hex characters"
  printf 'Pairing fingerprint for this aggregator (%s). A node asks for it when it pairs.\n' \
    "$(hostname 2>/dev/null || echo this host)" >&2
  printf '%s\n' "$FP"
  exit 0
fi

# ---- the key ---------------------------------------------------------
# ---- BEGIN ensure_fleet_arm_key (one rule, two copies: #723) ----------
# Make the fleet arm key at $1 if there is none, and never touch one that is
# there. The same text lives in aperire-fleet-arm.sh and in
# aperire-fleet-broker.sh, and scripts/test-fleet-broker.sh fails if the two
# copies ever differ: the broker runs from a root-installed copy that sources
# nothing out of the tree, so a shared file would be one more program to
# install beside it.
#
# Race-free, because two root programs can now make it (#723): an approval on
# the broker and an operator's first arm. `openssl genpkey -out` on the final
# name truncates whatever is there, so two makers racing could each report a
# public key while the file ended up holding the other's. Here the key is
# generated into a fresh temp file in the same directory (mktemp: O_EXCL,
# 0600), then hard-linked to the final name with `ln -T`, which fails if that
# name exists (a file OR a directory) and never replaces it. The loser discards its own and reads the winner's.
# Whoever reports a public key reads it back from the final file.
#
# Sets FLEET_ARM_KEY_MADE=1 when this call made it, 0 when one was there.
# Returns 1, with FLEET_ARM_KEY_WHY, when it could make none and none exists.
#
# #851 review L1: whenever a plain key file is at the name, this also leaves
# fleet-arm.made beside it, root's, 0600, empty, and never replaced. It says
# this host HAS had a fleet arm key, so a key missing later was lost rather
# than never made, whatever the fleet's records say by then (no socket verb
# removes this file, and the records are ones the dashboard account can
# empty). A host whose key predates the marker gets one the next time this
# runs with the key there. The callers refuse to make a key where it is.
# The reason is read by aperire-fleet-arm.sh, which prints it; the broker
# reports a one-word state instead, because its output is facts.
# shellcheck disable=SC2034
FLEET_ARM_KEY_MADE=0
# shellcheck disable=SC2034
FLEET_ARM_KEY_WHY=''
# shellcheck disable=SC2034
ensure_fleet_arm_key() { # $1 = the key path
  local key="$1" dir tmp stale rc=0
  FLEET_ARM_KEY_MADE=0; FLEET_ARM_KEY_WHY=''
  dir="$(dirname "$key")"
  # A temp a killed maker left behind (#743 review, L3), swept first. It is a
  # root 0600 private key, and if the kill landed between the link and the
  # rm it is a second name for the LIVE key, which would outlive a later
  # rotation by rm. Only ones older than ten minutes: a maker that is still
  # running takes seconds, and its temp is not this call's to take.
  if [[ -d "$dir" ]]; then
    while IFS= read -r -d '' stale; do rm -f -- "$stale"; done \
      < <(find "$dir" -maxdepth 1 -name '.fleet-arm.key.??????' ! -type d -mmin +10 -print0 2>/dev/null)
  fi
  if [[ -e "$key" || -L "$key" ]]; then fleet_arm_mark "$key"; return 0; fi
  # Made only when absent, and its mode stated: a caller running under
  # umask 077 that let mkdir decide would leave /etc/aperire 0700, which the
  # dashboard account cannot traverse to its own env file.
  if [[ ! -d "$dir" ]]; then
    if ! mkdir -p "$dir" || ! chmod 0755 "$dir"; then
      FLEET_ARM_KEY_WHY="$dir could not be made"; return 1
    fi
  fi
  if ! tmp="$(umask 077; mktemp "$dir/.fleet-arm.key.XXXXXX" 2>/dev/null)" || [[ -z "$tmp" ]]; then
    FLEET_ARM_KEY_WHY="no temporary file could be made in $dir"; return 1
  fi
  # Generate and link in a subshell that removes the temp on its way out,
  # however it goes: a TERM from RuntimeMaxSec, an INT, or an ordinary exit.
  # A KILL cannot be trapped, and the sweep above is what answers that.
  #
  # `ln -T` (#743 review, L1): without it a DIRECTORY appearing at the key's
  # name between the check above and this line is linked INTO, ln reports
  # success, and a private key is left inside it while this call says it made
  # the key. With -T the name is the target or nothing.
  ( trap 'rm -f -- "$tmp"' EXIT
    trap 'exit 1' TERM INT HUP
    umask 077
    openssl genpkey -algorithm ed25519 -out "$tmp" 2>/dev/null || exit 2
    chmod 0600 "$tmp" || exit 2
    ln -T -- "$tmp" "$key" 2>/dev/null || exit 3
  ) || rc=$?
  rm -f -- "$tmp"
  if (( rc == 0 )); then
    FLEET_ARM_KEY_MADE=1
    fleet_arm_mark "$key"
    return 0
  fi
  if (( rc == 2 )); then
    FLEET_ARM_KEY_WHY="openssl could not generate an Ed25519 key on this host"; return 1
  fi
  # Somebody else made it between the check above and the link: theirs stands.
  if [[ -e "$key" || -L "$key" ]]; then fleet_arm_mark "$key"; return 0; fi
  FLEET_ARM_KEY_WHY="$key could not be linked into place"
  return 1
}
# fleet_arm_mark <key path>: fleet-arm.made beside a key that is a plain
# file. Created with noclobber (O_EXCL), so a name already there, a link
# included, is neither followed nor replaced. Never a failure of its caller,
# and never silent: FLEET_ARM_MARK_FAILED=1 when the marker should be there
# and could not be made, so each caller says what that leaves (#853 review).
# shellcheck disable=SC2034
FLEET_ARM_MARK_FAILED=0
fleet_arm_mark() {
  local mark
  FLEET_ARM_MARK_FAILED=0
  mark="$(dirname "$1")/fleet-arm.made"
  [[ -f "$1" && ! -L "$1" ]] || return 0
  [[ -e "$mark" || -L "$mark" ]] && return 0
  ( set -C; umask 077; : > "$mark" ) 2>/dev/null || FLEET_ARM_MARK_FAILED=1
  return 0
}
# ---- END ensure_fleet_arm_key -----------------------------------------

# Made here on an aggregator whose broker grant predates the grant making it
# and which has never approved a pairing. The grant installer and an
# approval (#723) both make it too, so on most fleets this finds it already
# there. The banner below says which, rather than claiming a key this run
# did not make.
# #851 review L3: never on a host that has had a key or has a fleet. A key
# missing there was lost, and every node paired to it trusts the old one, so
# a new one here would cut them all off with nobody asking for it. This
# program reads no record through dirsafe, so it does not parse them: any
# record file at all, or fleet-arm.made, counts. The grant installer judges
# the records exactly, and its --new-fleet-keys is the deliberate re-key.
#
# Root's own two records (the marker and fleet-nodes.conf) say the key was
# lost, and the refusal names the restore. The dashboard's two (fleet.yaml,
# fleet-links.json) only say a fleet file exists: it may hold this host's own
# row and nothing else. This program does not read them as root, so it
# refuses there too, and names the grant installer first, which reads them
# safely and makes the key when no node is paired (#853 review, L3).
if [[ ! -e "$KEY" && ! -L "$KEY" ]]; then
  _root_had='' _dash_had=''
  for _r in "$ETC/fleet-arm.made" "$ETC/fleet-nodes.conf"; do
    [[ -e "$_r" || -L "$_r" ]] && _root_had="${_root_had:+$_root_had, }$_r"
  done
  for _r in "$REPO/dashboard/config/fleet-links.json" "$FLEET_FILE"; do
    [[ -e "$_r" || -L "$_r" ]] && _dash_had="${_dash_had:+$_dash_had, }$_r"
  done
  if [[ -n "$_root_had" ]]; then
    die "this aggregator has no fleet arm key, and it has had one or has paired nodes ($_root_had). Every node paired to the old key still trusts it, so this run makes no new one and arms nothing.
     Put the key back from your backup set:
       curl -fsSL https://get.aperire.one | bash -s -- --dir $REPO --restore --from <backup set>
     Or replace it on purpose, and pair each node again:
       curl -fsSL https://get.aperire.one | bash -s -- --dir $REPO --run fleet-broker-grant --new-fleet-keys"
  elif [[ -n "$_dash_had" ]]; then
    die "this aggregator has no fleet arm key, and this program does not make one beside a fleet file ($_dash_had): it cannot tell from here whether that names a paired node. Nothing was made or armed.
     The grant installer reads it safely, and makes the key when no node is paired:
       curl -fsSL https://get.aperire.one | bash -s -- --dir $REPO --run fleet-broker-grant
     If it refuses because a node is paired, put the key back from your backup set:
       curl -fsSL https://get.aperire.one | bash -s -- --dir $REPO --restore --from <backup set>"
  fi
fi
ensure_fleet_arm_key "$KEY" || die "$FLEET_ARM_KEY_WHY"
NEW_KEY="$FLEET_ARM_KEY_MADE"
# #853 review: the marker could not be made. Not a refusal, and not silent.
if (( FLEET_ARM_MARK_FAILED )); then
  info "warning: $KEY has no fleet-arm.made beside it ($ETC could not be written), so if this key is ever"
  info "         lost, only the fleet's records will stop a new one being made in its place."
fi
[[ -f "$KEY" && ! -L "$KEY" ]] || die "$KEY is not a regular file; a signing key is never read through a link"
[[ -O "$KEY" ]] || die "$KEY is not root's; a signing key anyone else may read arms the fleet on their say-so"

PUB_B64="$(openssl pkey -in "$KEY" -pubout -outform DER 2>/dev/null | tail -c 32 | base64 -w0)" \
  || die "$KEY is not a usable Ed25519 private key"
[[ -n "$PUB_B64" ]] || die "$KEY is not a usable Ed25519 private key"
# The same computation install-model-key-sealer.sh prints on a node: the
# sha256 of the raw 32 bytes, first 16 hex. The two must agree or the
# comparison an operator is asked to make means nothing.
FINGERPRINT="$(openssl pkey -in "$KEY" -pubout -outform DER | tail -c 32 | sha256sum | cut -c1-16)"

if [[ $NEW_KEY -eq 1 ]]; then
  echo
  echo "== A fleet arm key for this aggregator, made now"
  say "$KEY  (root:root 0600, and it never leaves this host)"
  echo
  openssl pkey -in "$KEY" -pubout
  say "raw base64   $PUB_B64"
  say "fingerprint  $FINGERPRINT"
  echo
  say "Give the public half to each node, once, as root ON THAT NODE:"
  say "  curl -fsSL https://get.aperire.one | bash -s -- --run model-key-sealer --trust-arm-key $PUB_B64"
  say "It prints a fingerprint. It must read $FINGERPRINT."
else
  echo
  echo "== Fleet arm key $FINGERPRINT"
fi
# #741: on every run, so the value a node asks for is on whatever root last
# ran here. Not fatal: a host that is not an aggregator arms itself all the
# same.
print_pairing_fingerprint "$PUB_B64" || true

# ---- which row is this host ------------------------------------------
#
# The same rule the dashboard itself uses (lib/fleet-health.ts, isSelf): a
# loopback read_origin on this process's own port is this node. Read from the
# dashboard's unit rather than assumed, because a second instance on one host
# is a supported shape and its port is the only thing that tells them apart.
own_port() {
  local unit f envfile port
  for unit in aperire-server aperire-read; do
    f="$UNIT_DIR/${unit}.service"
    [[ -f "$f" ]] || continue
    envfile="$(awk -F= '/^EnvironmentFile=/{print $2; exit}' "$f")"
    envfile="${envfile#-}"
    if [[ -n "$envfile" && -r "$envfile" ]]; then
      port="$(awk -F= '/^[[:space:]]*PORT=/{print $2; exit}' "$envfile")"
      if [[ -n "$port" ]]; then printf '%s' "$port"; return 0; fi
    fi
    port="$(awk -F= '/^Environment=PORT=/{print $3; exit}' "$f")"
    if [[ -n "$port" ]]; then printf '%s' "$port"; return 0; fi
  done
  return 1
}

OWN_PORT="$(own_port || true)"
if [[ -z "$OWN_PORT" ]]; then
  OWN_PORT="$DEFAULT_PORT"
fi

row_is_self() { # $1 = read_origin
  local hostport host port
  hostport="${1#*://}"; hostport="${hostport%%/*}"
  host="${hostport%:*}"; port="${hostport##*:}"
  [[ "$hostport" == *:* ]] || port=80
  case "$host" in 127.0.0.1|localhost|::1|"[::1]") ;; *) return 1 ;; esac
  [[ "$port" == "$OWN_PORT" ]]
}

# ---- the fleet -------------------------------------------------------
#
# The minimal read the other scripts do of this file (lib/fleet-trust-job.py
# reads it the same way): one row per `- label:`, the fields that follow it
# until the next one. The dashboard's own parser is the authority on whether
# the file is valid; this needs four fields and says so per row when one is
# missing, rather than failing the whole run on a row it was not asked about.
read_fleet() {
  awk '
    function val(l) {
      sub(/^[^:]*:[[:space:]]*/, "", l)
      sub(/[[:space:]]+#.*$/, "", l)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", l)
      return l
    }
    function emit() { if (label != "") print label "\t" origin "\t" token "\t" pin }
    /^[[:space:]]*-[[:space:]]*label:/ {
      emit(); label = val($0); origin = ""; token = ""; pin = ""; next
    }
    /^[[:space:]]*read_origin:/           { origin = val($0); next }
    /^[[:space:]]*token_path:/            { token  = val($0); next }
    /^[[:space:]]*expected_pubkey_node:/  { pin    = val($0); next }
    END { emit() }
  ' "$1"
}

ROWS=()
SELF_LABEL=""
if [[ -r "$FLEET_FILE" ]]; then
  while IFS= read -r row; do
    [[ -n "$row" ]] || continue
    ROWS+=("$row")
  done < <(read_fleet "$FLEET_FILE")
  for row in ${ROWS+"${ROWS[@]}"}; do
    IFS=$'\t' read -r r_label r_origin _ _ <<<"$row"
    if [[ -n "$r_origin" ]] && row_is_self "$r_origin"; then
      SELF_LABEL="$r_label"
      break
    fi
  done
fi

# ---- this host -------------------------------------------------------
#
# Written here, not asked of anything: this is the host the key is on, and the
# marker is the same file, mode and owner install-model-key-sealer.sh --arm
# writes. A host with no Advisor takes it harmlessly and never spends it.
#
# Only when this host was asked for. "--node stock-node1" names one node, and
# a window opened here as a side effect is a window nobody asked for, left
# open on the aggregator for fifteen minutes (the lab aggregator, 2026-09-02: the seal
# went to stock-node1 and the aggregator's own row read ARMED afterwards).
echo
if [[ -z "$ONLY_NODE" || "$ONLY_NODE" == "$SELF_LABEL" ]]; then
  mkdir -p "$ETC"
  install -o root -g root -m 0600 /dev/null "$ARM_FILE"
  printf 'armed %s (%s s)\n' "${SELF_LABEL:-self}" "$ARM_WINDOW_SEC"
else
  printf 'not armed %s: --node %s did not ask for this host\n' "${SELF_LABEL:-self}" "$ONLY_NODE"
fi

if [[ $SELF_ONLY -eq 1 ]]; then
  echo
  say "--self-only: no node but this one was asked."
  exit 0
fi

if [[ ! -r "$FLEET_FILE" ]]; then
  echo
  say "no $FLEET_FILE, so this host is its own fleet. Nothing else to arm."
  exit 0
fi
if [[ ${#ROWS[@]} -eq 0 ]]; then
  echo
  say "$FLEET_FILE names no nodes. Nothing else to arm."
  exit 0
fi
if [[ -z "$SELF_LABEL" ]]; then
  info "note: no row in $FLEET_FILE has a loopback read_origin on port $OWN_PORT,"
  info "      so none of them is being treated as this host. If one of them IS this"
  info "      host it will be armed twice, which costs nothing but is worth fixing."
fi

# The name this aggregator signs under. The node prints it back and puts it in
# its own journal, so an operator reading a node can see which machine opened
# its window. Not a credential: nothing is decided by it.
ISSUER="${SELF_LABEL:-$(hostname -s 2>/dev/null || echo aggregator)}"
[[ "$ISSUER" =~ ^[A-Za-z0-9._-]{1,64}$ ]] || ISSUER="aggregator"

arm_peer() { # $1 label, $2 read_origin, $3 token_path, $4 expected_pubkey_node
  local label="$1" origin="$2" token_path="$3" pin="$4"
  local bearer nonce issued sig resp code body reason detail window

  [[ "$label" =~ ^[a-z0-9-]{1,32}$ ]] \
    || { printf 'refused %s: the label in fleet.yaml is not a fleet label\n' "$label"; return 1; }
  [[ "$origin" =~ ^http://(127\.0\.0\.1|localhost):[0-9]{1,5}$ ]] \
    || { printf 'refused %s: read_origin %s is not a bare loopback origin\n' "$label" "$origin"; return 1; }
  # A row nobody pinned cannot be armed: the token names its target by public
  # key, and the node refuses one addressed to somebody else. Without a pin
  # there is nothing to address it to, and arming "whoever answers that port"
  # is exactly the mistake the pin exists to prevent.
  [[ -n "$pin" ]] \
    || { printf 'skipped %s: no pinned key (add expected_pubkey_node to its fleet.yaml row)\n' "$label"; return 1; }
  [[ "$pin" =~ ^n[1-9A-HJ-NP-Za-km-z]{20,60}$ ]] \
    || { printf 'refused %s: expected_pubkey_node is not shaped like a node key\n' "$label"; return 1; }
  [[ -r "$token_path" ]] \
    || { printf 'refused %s: cannot read its read token at %s\n' "$label" "$token_path"; return 1; }
  bearer="$(tr -d '[:space:]' < "$token_path")"
  [[ ${#bearer} -ge 32 ]] \
    || { printf 'refused %s: the read token at %s is too short to be one\n' "$label" "$token_path"; return 1; }

  nonce="$(openssl rand -hex 16)"
  issued="$(date +%s)"
  printf 'v=1\nissuer=%s\ntarget=%s\nnonce=%s\nissued_at=%s\n' \
    "$ISSUER" "$pin" "$nonce" "$issued" > "$WORK/token"
  openssl pkeyutl -sign -inkey "$KEY" -rawin -in "$WORK/token" -out "$WORK/sig" 2>/dev/null \
    || { printf 'refused %s: this host could not sign the token\n' "$label"; return 1; }
  sig="$(base64 -w0 < "$WORK/sig")"
  # The same five fields, in the same order, as the bytes just signed. Every
  # one of them was checked above against a shape with no quote, no backslash
  # and no newline in it, so this is the whole of the escaping needed.
  printf '{"token":"v=1\\nissuer=%s\\ntarget=%s\\nnonce=%s\\nissued_at=%s\\n","signature":"%s"}' \
    "$ISSUER" "$pin" "$nonce" "$issued" "$sig" > "$WORK/body.json"

  # The bearer goes in a config file, not in an argument. A process's
  # arguments are readable in /proc for as long as it runs, and this one is a
  # token that reads a whole node.
  ( umask 077
    printf 'header = "Authorization: Bearer %s"\n' "$bearer"
    printf 'header = "Content-Type: application/json"\n'
    printf 'data-binary = "@%s"\n' "$WORK/body.json"
  ) > "$WORK/curlrc"

  if resp="$(curl -sS -X POST --max-time 20 -K "$WORK/curlrc" \
                  -w $'\n%{http_code}' "$origin/fleet/v1/model/arm" 2>"$WORK/curl.err")"; then
    :
  else
    reason="$(head -n 1 "$WORK/curl.err" | sed 's/^curl: //')"
    printf 'unreachable %s: %s\n' "$label" "${reason:-no answer on $origin}"
    return 1
  fi
  code="${resp##*$'\n'}"
  body="${resp%$'\n'*}"
  if [[ "$code" == 200 ]]; then
    window="$(sed -n 's/.*"window_s"[[:space:]]*:[[:space:]]*\([0-9]*\).*/\1/p' <<<"$body")"
    printf 'armed %s (%s s)\n' "$label" "${window:-$ARM_WINDOW_SEC}"
    return 0
  fi
  reason="$(sed -n 's/.*"error"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' <<<"$body")"
  # `error` is the class and `detail` is the sentence the node wrote for a
  # person: a sealer refusal comes back as the class `refused` and nothing
  # else, which reads on this end as a node that would not say why. Both,
  # when there are both, and bounded because it crosses from another host.
  detail="$(sed -n 's/.*"detail"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' <<<"$body" | cut -c1-200)"
  if [[ -n "$reason" && -n "$detail" ]]; then reason="$reason: $detail"; fi
  if [[ -z "$reason" && ( "$code" == 302 || "$code" == 404 ) ]]; then
    # A dashboard that predates the fleet-write API has no /fleet/v1/ route,
    # so the request falls through to page auth and comes back as a login
    # redirect (or a plain 404). That is not a refusal by name and no key on
    # that node will change it; the node runs an older build. Seen on
    # stock-node2, 2026-09-03: "HTTP 302" and the trust-arm-key advice, which
    # that node's installer did not know either.
    STALE=$((STALE + 1))
    printf 'refused %s: its dashboard has no fleet write API (HTTP %s); it runs a build older than this feature\n' "$label" "$code"
    return 1
  fi
  if [[ -z "$reason" ]]; then
    reason="HTTP $code $(tr -d '\n' <<<"$body" | cut -c1-120)"
  fi
  printf 'refused %s: %s\n' "$label" "$reason"
  return 1
}

FAILED=0
STALE=0
MATCHED=0
for row in "${ROWS[@]}"; do
  IFS=$'\t' read -r r_label r_origin r_token r_pin <<<"$row"
  [[ "$r_label" != "$SELF_LABEL" ]] || continue
  if [[ -n "$ONLY_NODE" && "$r_label" != "$ONLY_NODE" ]]; then continue; fi
  MATCHED=$((MATCHED + 1))
  arm_peer "$r_label" "$r_origin" "$r_token" "$r_pin" || FAILED=$((FAILED + 1))
done

if [[ -n "$ONLY_NODE" && $MATCHED -eq 0 ]]; then
  if [[ "$ONLY_NODE" == "$SELF_LABEL" ]]; then
    echo
    say "--node $ONLY_NODE is this host, and it is armed above."
    exit 0
  fi
  die "no node called '$ONLY_NODE' in $FLEET_FILE"
fi

echo
if [[ $FAILED -eq 0 ]]; then
  say "every node asked for is armed, for the next $((ARM_WINDOW_SEC / 60)) minutes."
  say "Seal from this dashboard's Settings page while the window is open."
  exit 0
fi

say "$FAILED node(s) did not arm."
if [[ $STALE -gt 0 ]]; then
  say "A node whose dashboard has no fleet write API runs an older build: update"
  say "that node's install first, then run this again."
fi
if [[ $STALE -lt $FAILED ]]; then
  # #720: the same order the node's own refusal gives. A paired node takes
  # the key from its pairing when its Advisor installs, so the page's Advisor
  # install command comes first and the root line last.
  say "A node that has never been given this aggregator's key refuses by name. A node"
  say "takes it from its pairing: pair it again from Add a node, or, if it was paired"
  say "before its Advisor went on and has no model yet, run the Advisor install command"
  say "Settings prints for it again. Otherwise, as root on that node:"
  say "  curl -fsSL https://get.aperire.one | bash -s -- --run model-key-sealer --trust-arm-key $PUB_B64"
fi
exit 1
