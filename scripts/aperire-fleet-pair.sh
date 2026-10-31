#!/usr/bin/env bash
# Join this node to a fleet from a one-time code — ADR 0019 phase 3, #176.
#
#   sudo bash <install-dir>/scripts/aperire-fleet-pair.sh \
#     --code APR-XXXXX-XXXXX-XXXXX-XXXXX \
#     --aggregator https://<aggregator-host> \
#     [--label <label>] [--dir <install-dir>] [--dry-run]
#     [--expect-fingerprint <pairing fingerprint>]
#
# What it does, in order, and it stops on the first thing that is not true:
#
#   1. reads this node's own read token, its advisord token if there is one,
#      and its pubkey_node from its own /read/v1/identity
#   2. asks the operator to PASTE the aggregator's pairing fingerprint
#      (#741), BEFORE it dials, and checks its shape: 64 hex once spaces are
#      removed and case is folded. A miscopy costs nothing, not even the
#      code. The fingerprint covers the fleet trust key and the fleet arm key
#      together, and root on the aggregator is the only thing that prints it
#      (aperire-fleet-arm --fingerprint)
#   3. dials the aggregator's /fleet/v1/link, with the code in the first
#      frame and no credential anywhere, and asks for the keys first
#   4. compares the paste, whole, against what it computes from the
#      aggregator's two keys. A current aggregator sends them before anyone
#      approves, so a wrong paste ends here with no passkey spent. An older
#      one sends them only in its signed answer after approval, and the
#      same paste is compared then. Not a y/N and not a prefix: a crafted
#      key can match the first few characters of one
#      On a match against the early keys it also sends a MAC of this node's
#      read token (#626), never the token, so an aggregator that already
#      reads this node over an SSH tunnel can tell it is this node before it
#      offers to move it to the link
#   5. waits, while an administrator compares this node's key against the
#      Pending row on the aggregator and approves it under a passkey. The
#      signed answer must carry the keys this node checked, byte for byte
#   6. sends this node's two tokens, and receives the label, the link
#      credential and the two loopback ports the aggregator assigned
#   7. writes three artefacts, reloads the dashboard, and prints what to run
#      if the operator wants to undo it
#
# This is root's to run: it writes a credential the dashboard account must
# own, a trust file root owns, and /etc/aperire/fleet-arm.pub. The node's own
# dashboard never pairs — a compromised node dashboard cannot join a fleet.
#
# ALSO RUN BY install.sh, as its last step, when the install was given
# --fleet-aggregator. It is invoked there exactly the way the header above
# writes it: `--code -` with the code on stdin, and never with
# --expect-fingerprint. An installer may take a plan as printed; it may not
# answer the one question trust on first use rests on.
#
# --expect-fingerprint is for an operator who already holds the value from
# the aggregator's root output and is running this without a terminal. It is
# compared exactly as a paste is; it replaces the terminal, not the check.
# (--yes, which skipped the comparison, is gone: it skipped exactly the check
# #741 is about.)
#
# Exit codes: 0 paired, 1 broke, 2 the aggregator could not confirm, 3
# refused by name, 4 the pasted fingerprint did not match or was not a
# fingerprint at all (no token was sent and nothing was written; when it was
# not a fingerprint, nothing was dialled and the code is unspent).
#
# THE CODE ON ARGV. `--code APR-...` is in /proc/<pid>/cmdline for the life
# of this process and in the shell history afterwards, on a machine the
# operator is already root on. It is accepted because a pairing code is
# one-use and fifteen minutes, and because the operator is pasting one line
# a page printed. `--code -` reads it from stdin instead, which is the
# better habit and the one scripts/fleet-link-place.sh insists on for the
# link credential, which is permanent.
set -euo pipefail

# As root the environment chooses no path or program (#1206): every
# APERIRE_* variable is dropped except the ones a root caller passes on
# purpose:
#   APERIRE_INSTALL_TREE  get-aperire.sh names the tree a staged copy pairs (#764)
#   APERIRE_INSTANCE      install.sh exports it to every step; checked below
# An account id(1) says is not root keeps them all, which is what every
# suite is. id(1) at a fixed path, never bash's $EUID (#1109).
if ! [[ "$(/usr/bin/id -u 2>/dev/null)" =~ ^[1-9][0-9]*$ ]]; then
  for _v in $(compgen -e); do
    case "$_v" in APERIRE_INSTALL_TREE|APERIRE_INSTANCE) ;; APERIRE_*) unset "$_v" ;; esac
  done
fi
# The instance names a unit file and a drop-in path, so it is held to the
# rule advisor-owner-lib.sh holds it to, under the C locale (under
# en_US.UTF-8, [a-z] matches é), and anything else is refused.
instance_name_ok() { # $1 = a name; [a-z] is held to ASCII, whatever the locale
  local LC_ALL=C
  [[ "$1" =~ ^[a-z0-9][a-z0-9-]{0,30}$ && "$1" != credcheck && "$1" != credcheck-* ]]
}
if [[ -n "${APERIRE_INSTANCE:-}" ]] && ! instance_name_ok "$APERIRE_INSTANCE"; then
  printf 'refused: APERIRE_INSTANCE=%q is not an instance name (a-z, 0-9 and -, at most 31, not credcheck)\n' "$APERIRE_INSTANCE" >&2
  exit 2
fi

SELF="${BASH_SOURCE[0]}"
say()  { printf '   %s\n' "$*"; }
info() { printf '   %s\n' "$*" >&2; }
step() { printf '\n== %s\n' "$*"; }
die()  { printf 'error: %s\n' "$*" >&2; exit 1; }
# A refusal is an outcome, not a fault: same shape as every root program in
# this tree, so a caller can tell "this host said no" from "this host broke".
refuse() { printf 'refused: %s\n' "$*" >&2; exit 3; }
# Not a refusal and not a success (#312): the aggregator could not confirm
# whether it registered this node, so nothing was written here and the
# operator has to look at the aggregator rather than assume either way. Its
# own exit code, so an automated caller can tell it from the clean refuse=3.
unconfirmed() { printf 'unconfirmed: %s\n' "$*" >&2; exit 2; }

usage() {
  awk '/^[^#]/{exit} NR>1{sub(/^# ?/,""); print}' "$SELF"
  exit "${1:-1}"
}

# Is there a terminal to ask a question on? Opened for real rather than
# tested with -r: /dev/tty is mode 0666, so -r says yes on a host with no
# controlling terminal at all (cloud-init, a CI runner) and the redirection
# then fails, taking the run with it. scripts/get-aperire.sh makes the same
# argument in its own words.
#
# Not the same question as `[ -t 0 ]`. Stdin is where the CODE arrives; the
# terminal is where the questions are asked. Conflating the two is what #336
# was.
tty_available() { ( : < /dev/tty ) 2>/dev/null; }

# The aggregator origin rule, one owner, shared with install.sh. Refused by
# name when it is missing, the way install.sh refuses a checkout with no
# term-style.sh: a tree without it is an incomplete tree, not a host to guess
# the rule on.
PAIR_SCRIPTS_DIR="$(cd "$(dirname "$SELF")" && pwd)"
[[ -r "${PAIR_SCRIPTS_DIR}/fleet-origin.sh" ]] \
  || die "${PAIR_SCRIPTS_DIR}/fleet-origin.sh is missing from this checkout, and it holds the rule for which aggregator origins this node may carry its tokens to"
# shellcheck source=scripts/fleet-origin.sh
. "${PAIR_SCRIPTS_DIR}/fleet-origin.sh"
# The reader of authn.yaml's values, shared with install.sh and the guided
# setup so a public_url written as a list is read the same way by all three
# (#1358). Refused by name, the same way.
[[ -r "${PAIR_SCRIPTS_DIR}/authn-value.sh" ]] \
  || die "${PAIR_SCRIPTS_DIR}/authn-value.sh is missing from this checkout, and it reads this node's public_url"
# shellcheck source=scripts/authn-value.sh
. "${PAIR_SCRIPTS_DIR}/authn-value.sh"
# The one reader of the Advisor's account (#809), refused by name the same
# way: a tree without it cannot say which group the trust file belongs to.
[[ -r "${PAIR_SCRIPTS_DIR}/advisor-owner-lib.sh" ]] \
  || die "${PAIR_SCRIPTS_DIR}/advisor-owner-lib.sh is missing from this checkout, and it is what reads which account this host's Advisor runs as"
# shellcheck source=scripts/advisor-owner-lib.sh
. "${PAIR_SCRIPTS_DIR}/advisor-owner-lib.sh"

# The one reader and writer root uses on files in directories the dashboard's
# account controls (#764): descriptors, no link followed. Beside this script,
# so a staged copy has its own.
STATE_TOOL="${PAIR_SCRIPTS_DIR}/state-file.py"
[[ -r "$STATE_TOOL" ]] \
  || die "$STATE_TOOL is missing from this checkout, and it is what reads the token and trust files without following a link"

CODE='' AGGREGATOR='' LABEL='' DIR='' DRY_RUN=0 EXPECT_FP=''
while [[ $# -gt 0 ]]; do
  case "$1" in
    --code)       [[ $# -ge 2 ]] || die "--code needs a value (or - to read it from stdin)"; CODE=$2; shift 2 ;;
    --aggregator) [[ $# -ge 2 ]] || die "--aggregator needs a value"; AGGREGATOR=$2; shift 2 ;;
    --label)      [[ $# -ge 2 ]] || die "--label needs a value"; LABEL=$2; shift 2 ;;
    --dir)        [[ $# -ge 2 ]] || die "--dir needs a value"; DIR=$2; shift 2 ;;
    --expect-fingerprint)
                  [[ $# -ge 2 && -n "$2" ]] || die "--expect-fingerprint needs the aggregator's pairing fingerprint"
                  EXPECT_FP=$2; shift 2 ;;
    # #741: --yes skipped the one comparison trust on first use rests on, and
    # that comparison now covers the fleet arm key too. Named rather than
    # dropped into "unknown argument", so a script that still passes it is
    # told what replaced it.
    --yes|-y)     die "--yes no longer exists: pairing never skips the fingerprint check. Paste it when asked, or pass the value root printed on the aggregator with --expect-fingerprint <fingerprint>" ;;
    --dry-run)    DRY_RUN=1; shift ;;
    -h|--help)    usage 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

# ── where ────────────────────────────────────────────────────────────────
# The install root, two levels above this script, the aperire-fleet-add.sh
# rule. --dir overrides it for a tree that is not where this copy lives.
# APERIRE_INSTALL_TREE names it when root runs a copy staged out of the
# release (#764), which lives nowhere near the tree it pairs.
REPO="${DIR:-${APERIRE_INSTALL_TREE:-$(cd "$(dirname "$SELF")/.." && pwd)}}"
[[ -d "$REPO/dashboard" ]] || die "$REPO does not look like an Aperire install (no dashboard/ in it)"
CONFIG_DIR="$REPO/dashboard/config"
# Where the walks of this command stop. ADR 0024 asks for the chain ABOVE
# dashboard/ to belong to the operator, and for dashboard/config/ to be the
# operator's too, with no service account able to create, rename or remove an
# entry in it. Nothing enforces that second half at GA (the ADR's 2026-10-05
# amendment), and the broker accepts the dashboard's account as owner, so this
# command judges the chain down to the install folder and no further. That is
# the state of the enforcement, not approval of a dashboard/ or config/ that a
# second account can write. Every write below is by descriptor either way, so
# the cost of the gap is a write that lands in a folder that was swapped, never
# one outside the install.
CONFIG_ROOT="$REPO/dashboard"
STATE_DIR="$REPO/advisor/state"
ETC="${APERIRE_ETC:-/etc/aperire}"
UNIT_DIR="${APERIRE_UNIT_DIR:-/etc/systemd/system}"
# The instance this tree is (#1205). install.sh exports it to every script it
# runs, this one included; empty is the single-node layout. A named instance's
# units, env file and port are its own, and the default instance's port is
# another dashboard's. It goes into paths root reads, so it is held to the
# name rule advisor-owner-lib.sh uses.
INSTANCE="${APERIRE_INSTANCE:-}"
if [[ -n "$INSTANCE" ]]; then
  [[ "$INSTANCE" =~ ^[a-z0-9][a-z0-9-]{0,30}$ && "$INSTANCE" != credcheck && "$INSTANCE" != credcheck-* ]] \
    || refuse "APERIRE_INSTANCE='$INSTANCE' is not an instance name (lowercase letters, digits and dashes, 31 at most). Nothing was sent and nothing was written"
fi
UNIT_SUFFIX="${INSTANCE:+-$INSTANCE}"

(( DRY_RUN )) || [[ $EUID -eq 0 ]] || die "run with sudo: this writes a credential the dashboard account must own, a root-owned trust file, and $ETC/fleet-arm.pub"

WORK="$(umask 077; mktemp -d)"
# shellcheck disable=SC2317,SC2329  # reached by the trap below, which shellcheck cannot see
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

# ── the code ─────────────────────────────────────────────────────────────
# Normalised exactly as the aggregator normalises it (lib/pairing-codes.ts):
# upper-cased, O read as zero, I and L read as one, everything outside
# Crockford base32 dropped, a leading APR taken off, twenty characters left.
# Done HERE so a mistyped code is caught on the node rather than spending a
# round trip to be told the same thing with less detail.
fold_code() { printf '%s' "$1" | tr 'OIL' '011' | tr -cd '0-9A-HJKMNP-TV-Z'; }
normalise_code() {
  local upper whole body
  upper="$(printf '%s' "$1" | tr '[:lower:]' '[:upper:]')"
  whole="$(fold_code "$upper")"
  if [[ ${#whole} -eq 20 ]]; then printf '%s' "$whole"; return 0; fi
  case "$upper" in
    APR*) body="$(fold_code "${upper#APR}")"
          if [[ ${#body} -eq 20 ]]; then printf '%s' "$body"; return 0; fi ;;
  esac
  return 1
}

if [[ "$CODE" == '-' ]]; then
  if [ -t 0 ]; then
    printf 'Paste the pairing code, then Enter: ' >&2
    read -rs CODE
    printf '\n' >&2
  else
    read -r CODE || true
  fi
fi
[[ -n "$CODE" ]] || { usage 1; }
CODE_NORM="$(normalise_code "$CODE")" \
  || die "that is not a pairing code this command can read. It is twenty characters in four groups, the way the page printed it: APR-XXXXX-XXXXX-XXXXX-XXXXX"
# The plaintext is not needed again in the form it arrived, and one copy is
# enough to keep track of.
CODE=''

# ── the aggregator ───────────────────────────────────────────────────────
# https:// only, unless the host is loopback. The same rule parseLinkConfig
# enforces on the stored URL, applied HERE so a mistake is caught before the
# code is spent rather than after. The node is the only party that holds the
# URL, so the node is the only party that can know whether the hop that
# carries its tokens is encrypted.
[[ -n "$AGGREGATOR" ]] || { usage 1; }
AGGREGATOR="${AGGREGATOR%/}"
# Both halves of the rule come from scripts/fleet-origin.sh, which is where
# P3-059's anchoring lives and where install.sh reads it from too. The
# sentences stay here, because this program refuses a dial and install.sh
# refuses a flag.
fleet_origin_scheme_ok "$AGGREGATOR" \
  || die "--aggregator must be https:// (this node's read token and its Advisor token cross on this dial). http:// is accepted only to loopback: 127.0.0.1, localhost or [::1], with an optional port and nothing else"
fleet_origin_plain_ok "$AGGREGATOR" \
  || die "--aggregator is not a plain origin (scheme, host, optional port). Give https://<host>, with no path"
AGGREGATOR_WS="$(printf '%s' "$AGGREGATOR" | sed -e 's,^https://,wss://,' -e 's,^http://,ws://,')/fleet/v1/link"

# ── the label ────────────────────────────────────────────────────────────
# Proposed, never authoritative. The aggregator refuses a collision, the
# operator may rename it before approving, and what this command writes is
# whatever it was actually given back.
# #635: remembered so "This node" below can say WHY this is the name being
# proposed -- this box's own hostname -- and say nothing extra when an
# operator (or an aggregator's minted code) already settled that question.
LABEL_IS_HOSTNAME=0
if [[ -z "$LABEL" ]]; then
  LABEL="$(hostname -s 2>/dev/null || hostname 2>/dev/null || echo node)"
  LABEL="$(printf '%s' "$LABEL" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9-' | cut -c1-32)"
  [[ -n "$LABEL" ]] || LABEL="node"
  LABEL_IS_HOSTNAME=1
fi
printf '%s' "$LABEL" | grep -Eq '^[a-z0-9-]{1,32}$' \
  || die "label \"$LABEL\" must match [a-z0-9-]{1,32}, the same rule fleet.yaml uses"

# ── this node's dashboard ────────────────────────────────────────────────
# The account and the port come from the unit, not from $SUDO_USER and not
# from a default: on a host where one operator installs and the service runs
# as another, everything this writes has to follow the service. This
# instance's unit and file, in the order install.sh's fleet_dash_port reads
# them, so the port the install waited on is the port this asks.
DASH_UNIT='' DASH_USER='' DASH_ENV_FILE='' DASH_PORT=''
for _u in "aperire-server$UNIT_SUFFIX" "aperire-read$UNIT_SUFFIX"; do
  _f="$UNIT_DIR/${_u}.service"
  [[ -f "$_f" ]] || continue
  DASH_UNIT="$_u"
  DASH_USER="$(awk -F= '/^User=/{print $2; exit}' "$_f")"
  DASH_ENV_FILE="$(awk -F= '/^EnvironmentFile=/{sub(/^-/,"",$2); print $2; exit}' "$_f")"
  DASH_PORT="$(awk -F= '/^Environment=PORT=/{print $3; exit}' "$_f")"
  break
done
if [[ -z "$DASH_PORT" ]]; then
  for _e in "$DASH_ENV_FILE" "$ETC/aperire$UNIT_SUFFIX.env"; do
    [[ -n "$_e" && -f "$_e" ]] || continue
    DASH_PORT="$(awk -F= '$1=="PORT"{sub(/^[^=]*=/,""); gsub(/"/,""); print; exit}' "$_e")"
    [[ -n "$DASH_PORT" ]] && break
  done
fi
DASH_PORT="${DASH_PORT:-7800}"
# Without a unit (a development tree, a container, pm2) the config
# directory's owner stands in. That is right only where the dashboard runs
# as the tree's owner: ADR 0024 leaves dashboard/config with the operator,
# so on a host whose dashboard is aperire-dashboard the unit is the only
# answer, and every such host has one, because the installer writes it.
if [[ -z "$DASH_USER" || "$DASH_USER" == "root" ]]; then
  DASH_USER="$(stat -c '%U' "$CONFIG_DIR" 2>/dev/null || true)"
fi
[[ -n "$DASH_USER" ]] || die "could not work out which account this node's dashboard runs as"

# ── where operators reach this node's dashboard ──────────────────────────
# The row the aggregator writes carries this, and it is the one field in the
# hello this node may honestly not know (#339).
#
# It used to be built from `socket.getfqdn()`, which on a fresh box is a name
# only that box resolves: a stock Ubuntu image answers `ubuntu-22.localhost`,
# and the fleet row then read `https://ubuntu-22.localhost/overview.html` —
# an address nobody anywhere can open. The install asks for `public_url` as
# its closing step, so at pairing time a fresh box still has the shipped
# default, which is exactly the box that pairs.
#
# So: read this node's OWN public_url, and send nothing at all when it is the
# default or otherwise names only this machine. A row with no address is an
# honest gap the operator closes by re-pairing once the host has a real name;
# a row with a `.localhost` link is a lie with a click target.
AUTHN="$CONFIG_DIR/authn.yaml"
# The reader scripts/aperire-setup.sh and install.sh use, sourced from
# scripts/authn-value.sh (#1358), which reads a list the same way for all
# three. There is no YAML parser to hand here, and this file is a map of
# scalars with the odd list. It reads $WORK/authn.yaml, the bytes one safe read
# of $AUTHN produced below (#888 N3), never the name itself: that name is in a
# folder the dashboard's account can rewrite, and root reading it follows a
# link. A YAML list, in either spelling, comes back as the comma-joined line
# the dashboard and aperire-auth read it as (#1231, #1275).
authn_value() {  # <key> -> the value as one line, or empty
  authn_file_value "$WORK/authn.yaml" "$1"
}

# The host rules that decide which public_url entry this node gives out. The
# four that read a host live in scripts/authn-value.sh (host_is_local_only and
# the three beside it), where the installer and the guided setup use them too
# (#1358), and origin_usable is this command's own question of them.
# scripts/test-fleet-pair.sh cuts the marked block out of both files and runs it
# beside the dashboard's own rules (#1275).
# >>> pair host rules >>>
# An origin this node can give out as its own address: a plain origin, a host
# `new URL()` leaves as written, and not one only this machine can open.
origin_usable() {  # <origin>
  local h
  fleet_origin_plain_ok "$1" || return 1
  h="$(origin_host "$1")"
  host_is_carryable "$h" && ! host_is_local_only "$h"
}
# <<< pair host rules <<<

# ── the tokens ───────────────────────────────────────────────────────────
command -v python3 >/dev/null || die "python3 is not on this host, and this reads its files and JSON with it"
# Root reads these names in directories the dashboard's account can rewrite,
# and then hands what it read to code that account runs. A link at the name
# must therefore never be followed. read_once opens the final name with
# O_NOFOLLOW under a walk of the parents (scripts/state-file.py), demands a
# regular file with one link and an owner from the short list below, and
# prints what it read from that one descriptor: the file is judged and used
# in the same read, with no second look at the name. Writes the file's bytes
# to $2 and "uid gid mode" to $3.
READ_UIDS="0,$(id -u)"
_u="$(id -u "$DASH_USER" 2>/dev/null || true)"; [[ -z "$_u" ]] || READ_UIDS+=",$_u"
_a="$(advisor_owner_account "$UNIT_DIR" "$INSTANCE" 2>/dev/null || true)"
if [[ -n "$_a" ]]; then
  _u="$(id -u "$_a" 2>/dev/null || true)"; [[ -z "$_u" ]] || READ_UIDS+=",$_u"
fi
read_once() {  # path bytes-out meta-out [root [uids]]
  local raw="$WORK/.read-once"
  python3 -I "$STATE_TOOL" read "$1" --meta --file-uid "${5:-$READ_UIDS}" ${4:+--root "$4"} > "$raw" || return 1
  head -n 1 "$raw" > "$3"
  tail -n +2 "$raw" > "$2"
  rm -f "$raw"
}
# read.token also accepts the install tree's owner, on a node with no Advisor
# only. The installer mints it as that account (group the dashboard's, 0640)
# before any Advisor exists, so none of the accounts above owns it then (#911).
# Once an Advisor is installed its account owns the real tokens, and a file
# the tree owner left in state/ is not one this sends (#912 review, L1).
# approve.token never gets it: the installer never makes one as the tree
# owner, and a planted one would claim an Advisor this node lacks (L2). Same
# expression as authn.yaml below; the trust file and fleet-link.json keep
# READ_UIDS.
TREE_UID="$(stat -c '%u' "$REPO")"
TOKEN_UIDS="$READ_UIDS"
[[ -n "$_a" ]] || TOKEN_UIDS+=",$TREE_UID"
read_token_file() {  # path [uids] -> prints the token, or nothing when there is no such file; 1 when refused
  local path="$1" uids="${2:-}"
  [[ -e "$path" || -L "$path" ]] || return 0
  read_once "$path" "$WORK/.token" "$WORK/.token.meta" "" "$uids" || return 1
  tr -d '[:space:]' < "$WORK/.token"
  rm -f "$WORK/.token" "$WORK/.token.meta"
}
# The chain above dashboard/ is judged here, before any file is read and long
# before anything is spent, on a node that has none of the files yet as much
# as on one that has all of them. Every plant below walks the same chain and
# would refuse after the code was spent. The fix named is the exact mode
# change, so what a refusal says to run is what makes it pass.
ANC_LINES="$(python3 -I "$STATE_TOOL" ancestors "$CONFIG_DIR/fleet-link.json" --root "$CONFIG_ROOT" 2>&1)" \
  || die "could not check the folders above $CONFIG_ROOT: $ANC_LINES"
if [[ -n "$ANC_LINES" ]]; then
  # Each kind gets the sentence and the fix that are true for it. A mode
  # change clears group-write, world-write and an ACL entry (chmod g-w sets
  # the ACL mask, which is what the kernel enforces). It clears neither a
  # folder two accounts own parts of nor a folder this could not open without
  # following a link, and a command that does not fix the refusal is worse
  # than none.
  ANC_WRITABLE=0
  while IFS=$'\t' read -r _kind _path _why; do
    info "$_why"
    case "$_kind" in
      group-write) ANC_WRITABLE=1; info "  fix: sudo chmod g-w $_path" ;;
      world-write) ANC_WRITABLE=1; info "  fix: sudo chmod o-w $_path" ;;
      acl-write)   ANC_WRITABLE=1; info "  fix: sudo chmod g-w $_path   (this also takes the write off the ACL entry)" ;;
      owner)       ANC_WRITABLE=1; info "  fix: give $_path to root or to the account that owns this install, so one account owns the path" ;;
      unwalkable)  info "  fix: $_path is a link or is not there. Run this again with --dir set to the install's real folder, and check that dashboard/config exists in it" ;;
      *)           ANC_WRITABLE=1; info "  fix: change $_path so only root and this install's owner can write to it" ;;
    esac
  done <<<"$ANC_LINES"
  if (( ANC_WRITABLE )); then
    refuse "a folder above $CONFIG_ROOT can be rewritten by an account that is not this install's owner, so this will not write the credential there. Nothing was sent and nothing was written"
  fi
  refuse "$CONFIG_DIR cannot be reached without following a link or a folder that is not there (named above), so this will not write the credential there. Nothing was sent and nothing was written"
fi
# The one read of authn.yaml, here and not earlier: the chain above dashboard/
# has just been judged, and the read is by descriptor like every other read
# of this command (#888 N3). Its owner may be the install's owner, not only
# root and the dashboard's account: ADR 0024 leaves dashboard/config with the
# operator, and an install whose dashboard runs as its own account owns this
# file as the operator. A file it will not read is not a refusal: the row
# carries no address, and the reason is said below.
AUTHN_UNREAD=''
if [[ -e "$AUTHN" || -L "$AUTHN" ]]; then
  if ! read_once "$AUTHN" "$WORK/authn.yaml" "$WORK/authn.meta" "$CONFIG_ROOT" "$READ_UIDS,$TREE_UID" 2>"$WORK/authn.err"; then
    rm -f "$WORK/authn.yaml"
    AUTHN_UNREAD="$(LC_ALL=C tr -cd '\11\12\40-\176' <"$WORK/authn.err" | head -c 300)"
  fi
fi
# public_url may name several origins, comma-separated (dashboard/auth.ts,
# scripts/aperire-auth.sh), or a YAML list that authn_value joins the same way.
# The address this node gives out is the one dashboardIdentity() gives out,
# firstUsableUrl() in dashboard/lib/authn-fields.ts (#1233): the first entry
# another machine can open, and the first entry when none is, so a default
# install keeps saying why it sends nothing. An entry is trimmed and loses its
# trailing slashes. "Can open" is asked of what this command can carry, a
# plain origin whose host is not local-only: the dashboard also accepts an
# entry with a path, but this one appends /overview.html to the origin.
PUBLIC_URL_ALL="$(authn_value public_url)"
PUBLIC_URL=''
_rest="$PUBLIC_URL_ALL,"
while [[ -n "$_rest" ]]; do
  _entry="${_rest%%,*}"; _rest="${_rest#*,}"
  _entry="${_entry#"${_entry%%[![:space:]]*}"}"; _entry="${_entry%"${_entry##*[![:space:]]}"}"
  while [[ "$_entry" == */ ]]; do _entry="${_entry%/}"; done
  [[ -n "$_entry" ]] || continue
  [[ -n "$PUBLIC_URL" ]] || PUBLIC_URL="$_entry"
  if origin_usable "$_entry"; then
    PUBLIC_URL="$_entry"
    break
  fi
done
DASHBOARD_URL=''
DASHBOARD_URL_WHY=''
if [[ -n "$AUTHN_UNREAD" ]]; then
  DASHBOARD_URL_WHY="$AUTHN is not a plain file this can read safely, so public_url was not read ($AUTHN_UNREAD)"
elif [[ -z "$PUBLIC_URL" ]]; then
  DASHBOARD_URL_WHY="this install names no public_url yet"
elif ! fleet_origin_plain_ok "$PUBLIC_URL"; then
  # Not a refusal, and deliberately so: the row carries no address, and
  # pairing continues. public_url is the dashboard's own setting, read for
  # enrollment links, and this command is not where a malformed one is
  # caught.
  DASHBOARD_URL_WHY="public_url is not a plain origin this command can carry"
elif ! host_is_carryable "$(origin_host "$PUBLIC_URL")"; then
  DASHBOARD_URL_WHY="public_url writes its host in a form this command does not carry ($PUBLIC_URL). Write the host as a name or as an address of four numbers"
elif host_is_local_only "$(origin_host "$PUBLIC_URL")"; then
  DASHBOARD_URL_WHY="public_url still names this machine only ($PUBLIC_URL)"
else
  DASHBOARD_URL="$PUBLIC_URL/overview.html"
fi

READ_TOKEN="$(read_token_file "$STATE_DIR/read.token" "$TOKEN_UIDS")" \
  || refuse "$STATE_DIR/read.token is not a plain file this can read safely (the reason is above). Nothing was sent and nothing was written"
[[ -n "$READ_TOKEN" ]] \
  || die "$STATE_DIR/read.token is missing or empty, so this node has nothing to hand the aggregator. The install is incomplete: run the installer again on this host before pairing"
# Absent is a supported state, not a refusal: this node then pairs with no
# advisor_origin, which crossCheckLinkRows accepts as both-absent.
ADVISOR_TOKEN="$(read_token_file "$STATE_DIR/approve.token")" \
  || refuse "$STATE_DIR/approve.token is not a plain file this can read safely (the reason is above). Nothing was sent and nothing was written"
HAVE_ADVISOR=0
[[ -n "$ADVISOR_TOKEN" ]] && HAVE_ADVISOR=1

# Is there an advisord unit on this host at all? The second half of "is
# there an Advisor here" (#331), beside the token above. A unit file, not a
# running service: a stopped Advisor is still an Advisor, and this question
# is about what the host is meant to have. aperire-advisord.service (with
# this instance's suffix) by that exact name: the credcheck unit (#541) is not an Advisor, and a host where
# only it was left behind has none (#809).
advisor_unit_here() {
  local adv rc=0
  adv="$(advisor_owner_account "$UNIT_DIR" "$INSTANCE")" || rc=$?
  # 3: the unit is there, its account just cannot be read. Still an Advisor;
  # the trust-file step below refuses it by name.
  [[ $rc -eq 3 || -n "$adv" ]]
}

# ── this node's identity ─────────────────────────────────────────────────
# A refusal, and this is the one refusal that is about the NODE rather than
# about the aggregator, so its sentence says so. A row with no node key
# cannot be pinned; lib/fleet-seal.ts refuses an unpinned node by name and
# lib/fleet-registry.ts fails the whole file closed on a malformed pin. A
# Pending row with no key is a row nobody can approve into anything useful,
# so it is refused here, before the code is spent.
command -v curl >/dev/null || die "curl is not on this host, and this reads the node's own identity over HTTP"
IDENTITY_URL="http://127.0.0.1:${DASH_PORT}/read/v1/identity"
# The header goes in a 0600 file under $WORK, never on curl's argv
# (P2-057): /proc/<pid>/cmdline is world-readable, so any local account that
# polled it while this ran read the node's read token off the command line.
( umask 077; printf 'header = "Authorization: Bearer %s"\n' "$READ_TOKEN" >"$WORK/curl.cfg" )
IDENTITY_RAW="$(curl -fsS --max-time 10 --config "$WORK/curl.cfg" "$IDENTITY_URL" 2>"$WORK/identity.err" || true)"
shred -u "$WORK/curl.cfg" 2>/dev/null || rm -f "$WORK/curl.cfg"
if [[ -z "$IDENTITY_RAW" ]]; then
  info "$(cat "$WORK/identity.err" 2>/dev/null || true)"
  die "this node's own dashboard did not answer $IDENTITY_URL. Start it (sudo systemctl start ${DASH_UNIT:-aperire-server$UNIT_SUFFIX}) and run this again"
fi
printf '%s' "$IDENTITY_RAW" > "$WORK/identity.json"
PUBKEY_NODE="$(python3 -I - "$WORK/identity.json" <<'PY' || true
import json, sys
with open(sys.argv[1]) as f:
    d = json.load(f)
v = d.get("pubkey_node")
if isinstance(v, str) and v:
    sys.stdout.write(v)
PY
)"
NODE_VERSION="$(python3 -I - "$WORK/identity.json" <<'PY' || true
import json, sys
with open(sys.argv[1]) as f:
    d = json.load(f)
v = d.get("build_version")
if isinstance(v, str) and v:
    sys.stdout.write(v)
PY
)"
[[ -n "$PUBKEY_NODE" ]] \
  || refuse "this node's dashboard answered, and it does not yet know this node's own key: its bridge has not reached rippled. Start the node, wait for it to answer, and run this again. Nothing was sent and the code is unspent"
printf '%s' "$PUBKEY_NODE" | grep -Eq '^n[1-9A-HJ-NP-Za-km-z]{20,60}$' \
  || refuse "this node reported \"$PUBKEY_NODE\" as its own key, which is not a validator key shape the fleet can pin"

# What this node is running, for the row and for a skew line. Absent is
# null, never a guess: an install with no stamp says so.
DASHBOARD_VERSION="$(python3 -I - "$REPO" <<'PY' || true
import json, os, sys
repo = sys.argv[1]
stamp = os.path.join(repo, ".release")
ref = os.path.join(repo, ".deploy-ref")
try:
    with open(stamp) as f:
        d = json.load(f)
    tag = d.get("tag") or d.get("commit")
    if isinstance(tag, str) and tag:
        sys.stdout.write(tag)
        raise SystemExit(0)
except (OSError, ValueError):
    pass
try:
    with open(ref) as f:
        sha = f.read().strip()
    if sha:
        sys.stdout.write("commit " + sha[:7])
except OSError:
    pass
PY
)"

# ── the fingerprint the operator compares ────────────────────────────────
# Shortened the way the Settings Node key column shortens it (first 7, an
# ellipsis, last 4), so the two values an operator holds up against each
# other are written the same way at both ends.
short_key() {
  local k="$1"
  if [[ ${#k} -le 14 ]]; then printf '%s' "$k"; else printf '%s...%s' "${k:0:7}" "${k: -4}"; fi
}

step "This node"
say "install:      $REPO"
say "dashboard:    ${DASH_UNIT:-no systemd unit}, port $DASH_PORT, account $DASH_USER"
# #635: NAME reads the same word here as the page's own column, and the
# short key's pointer names that column too -- the same rename applied to
# both, so an operator holding this terminal beside the Settings page is
# comparing labels that read alike.
if (( LABEL_IS_HOSTNAME )); then
  say "name:         $LABEL   (this box's hostname; the aggregator may rename it)"
else
  say "name:         $LABEL"
fi
say "node key:     $PUBKEY_NODE"
say "              $(short_key "$PUBKEY_NODE")   <- the NODE KEY column on the page shows this"
# Said out loud, both ways round. An operator who sees "not sent" here on a
# host they have already given a name to knows the config is not what they
# think it is, before a code is spent.
if [[ -n "$DASHBOARD_URL" ]]; then
  say "reached at:   $DASHBOARD_URL"
else
  say "reached at:   not sent ($DASHBOARD_URL_WHY)"
  say "              The fleet row will carry no address for this node. Set"
  say "              public_url in dashboard/config/authn.yaml and pair again"
  say "              to fill it in."
fi
say "Advisor:      $( ((HAVE_ADVISOR)) && echo "present, its token will cross" || echo "none on this host" )"
say "running:      ${DASHBOARD_VERSION:-unknown (this install predates release stamps)}"

if (( DRY_RUN )); then
  step "Dry run"
  say "Nothing was dialled and the code is unspent."
  say "A dry run cannot check the AGGREGATOR's pairing fingerprint: its keys arrive"
  say "only once the code is presented, and presenting it spends the code."
  say ""
  say "When you are ready, run the same line without --dry-run."
  exit 0
fi

# ── everything that can refuse, judged BEFORE the code is spent ──────────
# A refusal after the dial leaves a node paired with a half-written
# configuration, and the code cannot be used again. So the files this will
# read or replace are looked at first, and what could be refused is. Each is
# read again at the moment it is used (a read here is a check, never the
# bytes used later), and that second read can refuse too, but only for a
# change made while this ran.
#
# The root of these walks is $CONFIG_ROOT, set above.
LINK_TARGET="$CONFIG_DIR/fleet-link.json"
TRUST_FILE="$CONFIG_DIR/fleet-trust.yaml"
# The Advisor's account from its own unit by exact name, never the first
# match of a glob: that glob found the credcheck unit's User=root first, and
# the file was created on the dashboard's own group, which an Advisor on its
# own account cannot read (#809). An Advisor running as root reads every
# file, so it takes the dashboard's own group, as a host with none does.
# A unit that is there and names no User= this can read exits 3 out of the
# subshell and is refused by name below: the dashboard's own group is the
# answer for no Advisor, never for one whose account could not be read.
TRUST_GROUP="$(
  adv_user="$(advisor_owner_account "$UNIT_DIR" "$INSTANCE")" || exit 3
  if [[ -n "$adv_user" && "$adv_user" != root ]] && id -u "$adv_user" >/dev/null 2>&1; then
    dash_groups=" $(id -nG "$DASH_USER" 2>/dev/null) "
    for cand in $(id -nG "$adv_user" 2>/dev/null); do
      if [[ "$dash_groups" == *" $cand "* ]]; then printf '%s' "$cand"; exit 0; fi
    done
  fi
  id -gn "$DASH_USER" 2>/dev/null || true
)" || refuse "$(advisor_owner_unread_msg "$UNIT_DIR/aperire-advisord$UNIT_SUFFIX.service")"
if [[ -e "$LINK_TARGET" || -L "$LINK_TARGET" ]]; then
  read_once "$LINK_TARGET" "$WORK/.pre" "$WORK/.pre.meta" "$CONFIG_ROOT" \
    || refuse "$LINK_TARGET is not a plain file this can read safely (a link, a second hard link or another account's file; the reason is above). Nothing was sent and nothing was written"
fi
if [[ -e "$TRUST_FILE" || -L "$TRUST_FILE" ]]; then
  read_once "$TRUST_FILE" "$WORK/.pre" "$WORK/.pre.meta" "$CONFIG_ROOT" \
    || refuse "$TRUST_FILE is not a plain file this can read safely (a link, a second hard link or another account's file; the reason is above). Nothing was sent and nothing was written"
  read -r _ _ _pre_mode < "$WORK/.pre.meta"
  if [[ "$_pre_mode" =~ ^[0-7]{3,4}$ ]] && (( (8#$_pre_mode & ~8#640) != 0 )); then
    die "$TRUST_FILE exists with mode $_pre_mode, wider than 0640. A file that may hold this node's own signing key is refused at that mode, never silently tightened. Fix it deliberately (chmod 0640 on it) and run this again. Nothing was sent and nothing was written"
  fi
fi
rm -f "$WORK/.pre" "$WORK/.pre.meta"

# ── the terminal, refused BEFORE the dial ────────────────────────────────
# Step 2 asks a human to paste the aggregator's fingerprint, right below.
# Before pairing v2 that pause sat downstream of an administrator approving
# the Pending row under a passkey, and a run with no terminal spent the code
# AND that touch and then aborted with nothing written. The question now
# comes before the dial, and this refusal still says why before anything is
# asked.
#
# Last of the pre-dial refusals, so the ones that are about this host (a
# malformed code, a plaintext aggregator, a node that does not know its own
# key) each keep their own sentence rather than being answered by this one.
# A dry run has already exited above. --expect-fingerprint carries the value
# root printed on the aggregator, which is the one thing that replaces the
# terminal (never the comparison), and install.sh never passes it.
if [[ -z "$EXPECT_FP" ]] && ! tty_available; then
  refuse "this run has no terminal, and pairing pauses for you to paste the aggregator's pairing fingerprint. Nothing was dialled and the code is unspent. Run it again where you can paste it"
fi

# ── the pairing fingerprint, BEFORE the dial (pairing v2) ────────────────
# Asked here, before anything leaves this host, so a miscopy costs nothing:
# not the code, and never an administrator's passkey. Shape only: 64 hex
# once whitespace is gone and case is folded, the forgiveness the dial
# helper's comparison grants and nothing more. Whether it is THIS
# aggregator's fingerprint is decided after the dial, against its keys.
#
# Read from /dev/tty, never stdin: stdin is where the code arrives with
# `--code -` and from the one-line installer, and reading the paste there
# is #336 again. Echoed, because it is public, and a paste that went wrong
# into a silent prompt cannot be seen.
fp_fold() { printf '%s' "$1" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]'; }
not_a_fingerprint() {  # $1 = what it was, folded
  if [[ "$1" =~ ^[0-9a-f]*$ ]]; then
    printf 'that is not a pairing fingerprint: it is 64 characters of 0-9 and a-f, and that was %s' "${#1}"
  else
    printf 'that is not a pairing fingerprint: it is 64 characters of 0-9 and a-f, and that has other characters in it'
  fi
}
step "Confirm the aggregator"
say "Before this node calls in, paste the aggregator's PAIRING FINGERPRINT."
say "Get it on the aggregator (the machine that serves the Settings page), as root:"
say ""
say "  sudo aperire-fleet-arm --fingerprint"
say ""
say "It prints one line of 64 characters. This node checks all of it."
PASTE=''
if [[ -n "$EXPECT_FP" ]]; then
  PASTE="$(fp_fold "$EXPECT_FP")"
  if [[ ! "$PASTE" =~ ^[0-9a-f]{64}$ ]]; then
    printf 'refused: --expect-fingerprint: %s. Nothing was dialled and the code is unspent.\n' "$(not_a_fingerprint "$PASTE")" >&2
    exit 4
  fi
  say "--expect-fingerprint was given, so that value is compared instead of a paste."
else
  FP_TRIES=0
  while :; do
    printf '   Paste the pairing fingerprint, then Enter: ' >&2
    answer=''
    read -r answer </dev/tty || answer=''
    PASTE="$(fp_fold "$answer")"
    [[ "$PASTE" =~ ^[0-9a-f]{64}$ ]] && break
    FP_TRIES=$(( FP_TRIES + 1 ))
    if (( FP_TRIES >= 3 )); then
      printf 'refused: %s. None of three pastes was a pairing fingerprint, so nothing was dialled and the code is unspent. Print it again on the aggregator and run this again.\n' \
        "$(not_a_fingerprint "$PASTE")" >&2
      exit 4
    fi
    info "$(not_a_fingerprint "$PASTE"). Try again ($(( 3 - FP_TRIES )) left)."
  done
fi
answer=''

# ── the dial ─────────────────────────────────────────────────────────────
# node is what speaks WebSocket here, and the helper it runs imports the
# CONTRACT rather than holding a private copy of the frames. Resolved the
# way prepare-host.sh resolves it, because /etc/profile.d is login-shell
# only and root's PATH under sudo does not carry an nvm node.
# The node the dashboard's own unit runs comes first: it is the one that
# already works on this host. Then the accounts whose nvm it may live under,
# the dashboard's and the tree owner's. A fresh install runs the dashboard as
# aperire-dashboard (ADR 0024), which has no home and no shell to ask, while
# node sits under the operator who installed it.
resolve_node_bin() {
  local n home who
  n="$(command -v node 2>/dev/null || true)"
  [[ -n "$n" ]] && { printf '%s' "$n"; return 0; }
  if [[ -n "$DASH_UNIT" && -f "$UNIT_DIR/${DASH_UNIT}.service" ]]; then
    n="$(sed -n 's/^ExecStart=//p' "$UNIT_DIR/${DASH_UNIT}.service" | grep -oE '/[^" ]*/node' | head -1 || true)"
    [[ -n "$n" && -x "$n" ]] && { printf '%s' "$n"; return 0; }
  fi
  for who in "$DASH_USER" "$(stat -c '%U' "$REPO" 2>/dev/null || true)"; do
    [[ -n "$who" && "$who" != root && "$who" != UNKNOWN ]] || continue
    # Root runs what it finds here. A service account's home (a nologin
    # account: aperire-dashboard on a fresh install) is that account's to
    # write, so root never looks for a program in it (ADR 0024 decision 1).
    case "$(getent passwd "$who" | cut -d: -f7)" in
      */nologin|*/false) continue ;;
    esac
    home="$(getent passwd "$who" | cut -d: -f6)"
    [[ -n "$home" && -d "$home" ]] || continue
    n="$(su -s /bin/bash -c 'command -v node' "$who" 2>/dev/null || true)"
    [[ -n "$n" ]] && { printf '%s' "$n"; return 0; }
    n="$(find "$home/.nvm/versions/node" -maxdepth 3 -path '*/bin/node' -type f 2>/dev/null | sort -V | tail -1)"
    [[ -n "$n" ]] && { printf '%s' "$n"; return 0; }
  done
  return 1
}
NODE_BIN="$(resolve_node_bin)" \
  || die "node is not on this host's PATH, not in $DASH_UNIT's ExecStart, and none was found under an nvm tree. The dashboard runs on node, so one is here somewhere: put it on PATH and run this again"
[[ -f "$REPO/dashboard/node_modules/tsx/dist/cli.mjs" ]] \
  || die "$REPO/dashboard/node_modules is missing or incomplete (no tsx). Run npm ci in $REPO/dashboard and try again"
DIAL_HELPER="$REPO/dashboard/scripts/fleet-pair-dial.mjs"
[[ -f "$DIAL_HELPER" ]] || die "$DIAL_HELPER is missing; this tree is incomplete"

# Root never runs the tree's JavaScript (#764). The dial helper, its imports
# and node_modules/tsx are code the dashboard's account can write, so every
# node call below runs as that account, and what it sends back is read as
# untrusted data and checked here before root acts on it. A node already
# running as that account (a rig, an owner running this by hand without
# root) needs no drop. An account of root would drop nothing, so it is refused.
[[ "$DASH_USER" != root ]] \
  || die "the dashboard account here is root, so there is no account to run the tree's pairing code as. Run the dashboard under its own account first"
id -u "$DASH_USER" >/dev/null 2>&1 || die "the dashboard account $DASH_USER does not exist on this host"
[[ "$(id -un)" == "$DASH_USER" ]] || { command -v runuser >/dev/null && command -v setsid >/dev/null; } \
  || die "runuser or setsid not found (both are in util-linux), and this command runs the tree's pairing code as $DASH_USER rather than as root"
DASH_HOME="$(getent passwd "$DASH_USER" | cut -d: -f6)"
[[ -n "$DASH_HOME" ]] || DASH_HOME=/nonexistent
# dash_node [NAME=value ...] -- <node arguments>. Redirections stay on the
# caller's side: root opens the FIFOs and the files, and the child inherits
# the descriptors, so it never needs a path under the root-only work directory.
dash_node() {
  # A terminal on stdin is root's own, and that account's code must not get
  # it: a call whose caller redirected stdin (a pipe, a file) is untouched,
  # and one that did not is given /dev/null, so no call site can forget.
  if [[ -t 0 ]]; then dash_node_run "$@" </dev/null; else dash_node_run "$@"; fi
}
dash_node_run() {
  local -a vars=()
  while [[ $# -gt 0 && "$1" != -- ]]; do vars+=("$1"); shift; done
  shift
  if [[ "$(id -un)" == "$DASH_USER" ]]; then
    env -i PATH=/usr/local/bin:/usr/bin:/bin HOME="$DASH_HOME" ${vars[@]+"${vars[@]}"} "$NODE_BIN" "$@"
  else
    # setsid -w: the child gets a session of its own and so no controlling
    # terminal. runuser alone keeps root's, and the helper lives for up to
    # fifteen minutes, so that account's code could open /dev/tty and write
    # over the operator's screen (a forged "fingerprint matches"), or on a
    # kernel that still allows TIOCSTI push keystrokes into the shell after
    # this command ends. Not `runuser --pty`: that hands the child a fresh
    # terminal and relays the data path through it, and the job on stdin and
    # the events on the FIFOs must stay plain pipes. setsid -w also waits and
    # passes the exit status through, so nothing downstream changes.
    setsid -w runuser -u "$DASH_USER" -- env -i PATH=/usr/local/bin:/usr/bin:/bin HOME="$DASH_HOME" \
      ${vars[@]+"${vars[@]}"} "$NODE_BIN" "$@"
  fi
}
# Text from the helper or from node, shown to the operator: control
# characters (a terminal escape) are dropped and the length is bounded.
clean_text() { LC_ALL=C tr -cd '\11\12\40-\176' | head -c 2000; }

NONCE="$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
# The three secrets cross in a 0600 file under $WORK, read by path, and
# never on argv (P2-057). $WORK is mktemp -d under umask 077, so the file is
# 0600 inside a 0700 directory, and it is shredded the moment python has it.
# The values left on argv are the code's NON-secrets: a URL, a label, a
# public key, two version strings and a nonce this command minted.
( umask 077; printf '%s\n' "$CODE_NORM" "$READ_TOKEN" "$ADVISOR_TOKEN" >"$WORK/secrets" )
JOB="$(python3 -I - <<'PY' "$AGGREGATOR_WS" "$WORK/secrets" "$LABEL" "$PUBKEY_NODE" "$DASHBOARD_URL" "$HAVE_ADVISOR" "$DASHBOARD_VERSION" "$NODE_VERSION" "$NONCE" "$PASTE"
import json, sys
(ws, secrets, label, pubkey, dash_url, advisor, dashv, nodev, nonce, paste) = sys.argv[1:11]
with open(secrets) as f:
    (code, read_token, advisor_token) = (f.readline().rstrip("\n") for _ in range(3))
job = {
    "aggregator_ws": ws,
    "code": code,
    "label": label,
    "pubkey_node": pubkey,
    "advisor": advisor == "1",
    "dashboard_version": dashv or None,
    "advisord_version": None,
    "node_version": nodev or None,
    "challenge_nonce": nonce,
    # The operator's paste, shape-checked above. Public (root prints it for
    # anyone who asks the aggregator), so argv was fine for it.
    "fingerprint": paste,
    "read_token": read_token,
    "advisor_token": advisor_token or None,
    "timeout_ms": 900000,
}
# Where operators reach THIS node, worked out above from its own public_url.
# The key is left out entirely when there is no such address, rather than
# sent empty: absent is the wire's way of saying this node does not know
# (#339), and an empty string is a value the aggregator would have to refuse.
if dash_url:
    job["dashboard_url"] = dash_url
sys.stdout.write(json.dumps(job))
PY
)"
shred -u "$WORK/secrets" 2>/dev/null || rm -f "$WORK/secrets"

step "Pairing"
say "aggregator:   $AGGREGATOR"
say "endpoint:     $AGGREGATOR_WS"
say ""
say "This node checks the aggregator's keys against your fingerprint, and on the"
say "aggregator an administrator compares the node key above against the Pending"
say "row and presses Approve. This waits for both, for up to fifteen minutes,"
say "which is the life of the code."

# Two FIFOs, in a directory `mktemp -d` made under umask 077, so both are
# 0600 inside a 0700 directory owned by whoever is running this. The code,
# both tokens and the credential cross here, and nothing goes on argv or in
# the environment: that is socket-program.ts's rule, applied to the one
# boundary in this phase that is not a systemd socket.
#
# That was true of this FIFO and false of three lines elsewhere in this file
# until P2-057, which is worth remembering: the rule is only as good as the
# next person applying it. The code, both tokens and the credential all now
# cross on stdin or in a 0600 file under $WORK. /proc/<pid>/cmdline is
# world-readable to every local account on this host; /proc/<pid>/environ is
# not, but neither is a place for a secret.
#
# NOT `coproc`. Bash closes a coproc's descriptors when the child exits, so
# a helper that refuses and exits promptly (a bad signature, a refused code)
# races the read loop below and hands it EBADF instead of the events it had
# already written. Descriptors this script opens itself return EOF, which is
# the difference between reading a refusal and losing it.
#
# From dashboard/, because `--import tsx` resolves tsx from the WORKING
# DIRECTORY and not from the script's, and root's cwd when an operator runs
# this is wherever they were standing. The same reason
# scripts/fleet-link-place.sh cds before every re-read it does.
mkfifo "$WORK/to-dial" "$WORK/from-dial"
( cd "$REPO/dashboard" && exec 0<"$WORK/to-dial" 1>"$WORK/from-dial" 2>"$WORK/dial.err" \
    && dash_node -- --import tsx scripts/fleet-pair-dial.mjs ) &
DIAL_PID=$!
exec 3>"$WORK/to-dial"
exec 4<"$WORK/from-dial"
printf '%s\n' "$JOB" >&3
JOB=''

SETTLED_LABEL='' CREDENTIAL='' ARM_PUB='' READ_PORT='' ADVISOR_PORT='' TRUST_PUB='' TRUST_FP='' MATCH_SAID=0
LABEL_CHANGED=0 KEYS_CHECKED=0
while IFS= read -r line <&4; do
  # Whatever the helper writes is data. One line is bounded, and every value
  # taken from it is checked below before anything is written on its word.
  (( ${#line} <= 65536 )) || die "the dial helper wrote a line longer than 64 KiB; that is not a pairing exchange, so nothing was written"
  printf '%s' "$line" > "$WORK/ev.json"
  EV="$(python3 -I -c 'import json,sys;print(json.load(open(sys.argv[1])).get("ev",""))' "$WORK/ev.json" 2>/dev/null || true)"
  case "$EV" in
    dialing) say "dialling the aggregator..." ;;
    hello)   say "presenting the code..." ;;
    keys_matched)
      # Pairing v2: the aggregator sent its keys before approval, and they
      # match the paste. Nothing has been sent yet: the tokens wait for the
      # signed answer, which must carry these same keys.
      say "the aggregator's keys match the fingerprint you pasted."
      say "Waiting for an administrator to approve this node on the aggregator..."
      ;;
    welcome)
      read -r TRUST_PUB SETTLED_LABEL LABEL_CHANGED KEYS_CHECKED < <(python3 -I - "$WORK/ev.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
print(d.get("fleet_trust_pubkey", ""), d.get("label", ""), "1" if d.get("label_changed") else "0",
      "1" if d.get("keys_checked") else "0")
PY
)
      # Nothing is asked here any more, and nothing is written to the dial
      # helper: the paste crossed in the job before the dial, and the next
      # line it reads is the write report after `settled`.
      if [[ "$KEYS_CHECKED" == 1 ]]; then
        say "approved. The aggregator's signed answer carries the keys you checked."
      else
        # An aggregator older than the early keys: this is the first time it
        # has shown them, so the paste is compared now.
        say "approved. Comparing the aggregator's signed answer with the fingerprint you pasted..."
      fi
      if [[ "$LABEL_CHANGED" == 1 ]]; then
        say "The administrator registered this node as \"$SETTLED_LABEL\", not \"$LABEL\" as"
        say "proposed. That is theirs to choose: the aggregator resolves a link from its"
        say "credential and would refuse any other name."
      fi
      ;;
    matched)
      # Printed only now, after the comparison: the value the operator
      # pasted, read back bare, the way root prints it, so the closing
      # summary can name it.
      # The helper says it matched. Root does not take its word: the
      # fingerprint is recomputed from the two keys below, before anything
      # is written, and that value is the one printed.
      MATCH_SAID=1
      ;;
    mismatch)
      DETAIL="$(python3 -I -c 'import json,sys;d=json.load(open(sys.argv[1]));print(d.get("detail") or "that is not the pairing fingerprint")' "$WORK/ev.json" 2>/dev/null | clean_text || echo 'that is not the pairing fingerprint')"
      printf 'refused: %s\n' "$DETAIL" >&2
      info "Run the command on the aggregator again and paste exactly what it prints. If it"
      info "still does not match, stop: the keys this node was offered are not the ones root"
      info "on that aggregator holds. Mint a fresh code before trying again."
      exit 4
      ;;
    settled)
      read -r SETTLED_LABEL CREDENTIAL ARM_PUB READ_PORT ADVISOR_PORT < <(python3 -I - "$WORK/ev.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
print(d.get("label", ""), d.get("credential", ""), d.get("fleet_arm_pubkey") or "-",
      d.get("read_port", ""), d.get("advisor_port") if d.get("advisor_port") is not None else "-")
PY
)
      step "Registered as \"$SETTLED_LABEL\""
      say "read port on the aggregator:     $READ_PORT"
      say "advisor port on the aggregator:  $ADVISOR_PORT"
      break
      ;;
    settle_unconfirmed)
      DETAIL="$(python3 -I -c 'import json,sys;d=json.load(open(sys.argv[1]));print(d.get("detail") or d.get("error") or "no reason given")' "$WORK/ev.json" 2>/dev/null | clean_text || echo 'no reason given')"
      info "nothing was written on this node."
      unconfirmed "$DETAIL"
      ;;
    refused|settle_refused|aborted|failed)
      DETAIL="$(python3 -I -c 'import json,sys;d=json.load(open(sys.argv[1]));print(d.get("detail") or d.get("error") or "no reason given")' "$WORK/ev.json" 2>/dev/null | clean_text || echo 'no reason given')"
      case "$EV" in
        failed) info "$(clean_text < "$WORK/dial.err" 2>/dev/null || true)"; die "$DETAIL" ;;
        *) refuse "$DETAIL" ;;
      esac
      ;;
  esac
done

[[ -n "$CREDENTIAL" && -n "$SETTLED_LABEL" && -n "$READ_PORT" ]] \
  || { info "$(clean_text < "$WORK/dial.err" 2>/dev/null || true)"; die "the exchange ended before the aggregator said what it had written. Nothing was written here"; }
# #741: the dial helper refuses a settlement whose arm key is not the one the
# pasted fingerprint covered, so this is a second line of the same rule,
# before the first write: a node is never paired without the arm key its
# operator checked.
[[ -n "$ARM_PUB" && "$ARM_PUB" != '-' ]] \
  || refuse "the aggregator's settlement carries no fleet arm key your fingerprint covered. Nothing was written here"
# The helper ran as the dashboard's account, so everything it reported is
# checked here, as root, before it is written anywhere (#764). Shapes first.
[[ "$SETTLED_LABEL" =~ ^[a-z0-9-]{1,32}$ ]] \
  || refuse "the helper reported a node name that is not [a-z0-9-]{1,32}. Nothing was written here"
printf '%s' "$CREDENTIAL" | LC_ALL=C grep -Eq '^[!-~]{1,512}$' \
  || refuse "the helper reported a credential that is empty, too long or holds a space or control character. Nothing was written here"
valid_port() { [[ "$1" =~ ^[0-9]{1,5}$ ]] && (( 10#$1 >= 1 && 10#$1 <= 65535 )); }
valid_port "$READ_PORT" \
  || refuse "the helper reported a read port that is not a port number. Nothing was written here"
[[ "$ADVISOR_PORT" == '-' ]] || valid_port "$ADVISOR_PORT" \
  || refuse "the helper reported an advisor port that is not a port number. Nothing was written here"
# The one comparison the whole pairing rests on, done again by root: the
# fingerprint of the two keys this node is about to trust, against what the
# operator pasted. The construction is fleetPairingFingerprint in
# dashboard/types/fleet-link-contract.ts (domain line, then the raw trust key
# from canonical base64url, then the raw arm key from canonical base64, sha256
# in hex), and test-fleet-pair.sh holds both to its published vector.
TRUST_FP="$(python3 -I - "$TRUST_PUB" "$ARM_PUB" "$PASTE" <<'PY'
import base64, hashlib, re, sys
trust, arm, paste = sys.argv[1:4]
def raw(s, url):
    try:
        b = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)) if url else base64.b64decode(s)
    except Exception:
        return None
    if len(b) != 32:
        return None
    back = (base64.urlsafe_b64encode(b).decode().rstrip("=") if url else base64.b64encode(b).decode())
    return b if back == s else None
t, a = raw(trust, True), raw(arm, False)
if t is None or a is None:
    sys.exit(1)
fp = hashlib.sha256(b"aperire-fleet-pairing-fingerprint/2\n" + t + a).hexdigest()
if re.sub(r"\s+", "", paste).lower() != fp:
    sys.exit(1)
print(fp)
PY
)" || refuse "the keys the helper reported do not make the fingerprint you pasted, whatever the helper said. Nothing was written here"
(( MATCH_SAID )) || refuse "the helper never reported the fingerprint as matched. Nothing was written here"
say "fingerprint matches: $TRUST_FP"

# ── the trust file, read and judged BEFORE the credential is written (#888 N4) ──
# What can refuse here needs the aggregator's key, which arrives only with
# the settlement, so it cannot be judged before the dial. It can be judged
# before ANYTHING is written: a node that already trusts a different
# aggregator, or a trust file this cannot build back, is refused with the node
# exactly as it was, never with a credential written beside a trust file that
# was refused. The code is spent by then, and the refusal says so.
#
# This is the one read of the trust file in this command. Step 2 below plants
# the bytes built here and does not look at the name again. It leaves
# TRUST_SAME=1 when the key is already there, and otherwise the built file in
# $TRUST_TMP.
TRUST_TAIL="Nothing was written on this node. The code is already spent, so run this again with a new one."
TRUST_BYTES="$WORK/trust.read" T_MODE='' T_UID='' T_GID=''
TRUST_IN=/dev/null
if [[ -e "$TRUST_FILE" || -L "$TRUST_FILE" ]]; then
  read_once "$TRUST_FILE" "$TRUST_BYTES" "$WORK/trust.meta" "$CONFIG_ROOT" \
    || refuse "$TRUST_FILE is not a plain file this can read safely (a link, a second hard link or another account's file; the reason is above). It was not read and not written. $TRUST_TAIL"
  read -r T_UID T_GID T_MODE < "$WORK/trust.meta"
  TRUST_IN="$TRUST_BYTES"
  if [[ "$T_MODE" =~ ^[0-7]{3,4}$ ]] && (( (8#$T_MODE & ~8#640) != 0 )); then
    die "$TRUST_FILE exists with mode $T_MODE, wider than 0640 — a file that may hold this node's own signing key is refused at that mode, never silently tightened. Fix it deliberately and run this again. $TRUST_TAIL"
  fi
fi
EXISTING_PUB="$( (cd "$REPO/dashboard" && dash_node -- --import tsx --input-type=module -e "
  import { readPeerPubKey } from './lib/trust-bundle.ts';
  const k = readPeerPubKey('/dev/stdin', 'aggregator');
  if (k) process.stdout.write(k);
" < "$TRUST_IN") 2>/dev/null | head -c 512 | clean_text || true)"
if [[ -n "$EXISTING_PUB" && "$EXISTING_PUB" != "$TRUST_PUB" ]]; then
  refuse "$TRUST_FILE already trusts a different aggregator.
     it holds:   $EXISTING_PUB
     this one:   $TRUST_PUB
     A node that already trusts one aggregator is not re-pointed at another by an
     approval. If that is what you want, remove the peers.aggregator line by hand,
     and the arm key the old one handed over with it (#720), which would otherwise
     be refused as different and placed at the next Advisor install:
       sudo rm -f $ETC/fleet-arm.paired.pub $ETC/fleet-arm.pub
     then run this again. $TRUST_TAIL"
fi
TRUST_SAME=0
if [[ "$EXISTING_PUB" == "$TRUST_PUB" ]]; then
  TRUST_SAME=1
else
  TRUST_TMP="$WORK/fleet-trust.yaml"
  if [[ -n "$T_MODE" ]]; then
    python3 -I - "$TRUST_BYTES" "$TRUST_TMP" "$TRUST_PUB" <<'PY'
import sys
src, out, pub = sys.argv[1:4]
with open(src) as f:
    lines = f.read().splitlines()
written = False
result = []
for line in lines:
    result.append(line)
    if not written and line.rstrip() == "peers:":
        result.append("  aggregator: %s" % pub)
        written = True
if not written:
    if result and result[-1].strip() == "":
        result.pop()
    result.append("peers:")
    result.append("  aggregator: %s" % pub)
with open(out, "w") as f:
    f.write("\n".join(result) + "\n")
PY
  else
    printf 'peers:\n  aggregator: %s\n' "$TRUST_PUB" > "$TRUST_TMP"
  fi
  # Read back with the shipped parser, which is the TypeScript twin of
  # advisord's own AggregatorPubKey reader: the one thing both services must
  # agree on is which key is trusted.
  READBACK="$( (cd "$REPO/dashboard" && dash_node -- --import tsx --input-type=module -e "
    import { readPeerPubKey } from './lib/trust-bundle.ts';
    const k = readPeerPubKey('/dev/stdin', 'aggregator');
    if (k) process.stdout.write(k);
  " < "$TRUST_TMP") 2>/dev/null | head -c 512 | clean_text || true)"
  [[ "$READBACK" == "$TRUST_PUB" ]] \
    || die "the trust file this command built does not read back as trusting that key, so nothing was written to $TRUST_FILE. $TRUST_TAIL"
fi

# ── artefact 1: the link credential ──────────────────────────────────────
# 0600 and owned by the account the unit names. Temp-then-rename in the same
# directory, then re-read with the agent's OWN parser before the backup is
# dropped: a file this node's agent refuses must not be left in place
# looking finished. scripts/fleet-link-place.sh is the shape, and its
# comment explains why --aggregator is character-classed above.
step "Writing this node's link credential"
WROTE=()
# Every touch of a name under dashboard/config goes through state-file.py:
# the dashboard's account owns that directory, so a name there is one it can
# turn into a link at any moment, and root's open, chmod, chown, copy or
# rename by name would follow it. The old bytes are read once, from one
# descriptor, and kept in $WORK for the put-back; the backup file and the new
# credential are planted (created beside the name, owner and mode set on the
# descriptor, renamed over the name), which replaces a link and never follows
# one.
LINK_BACKUP=''
HAD_LINK=0 L_UID='' L_GID='' L_MODE=''
LINK_OLD="$WORK/link.old"
cfg_plant() {  # name uid gid mode (content on stdin). A caller that is not root cannot give a file away, so it keeps its own.
  local uid="$2" gid="$3"
  [[ $EUID -eq 0 ]] || { uid=''; gid=''; }
  python3 -I "$STATE_TOOL" plant "$1" "$uid" "$gid" "$4" --stdin --root "$CONFIG_ROOT"
}
cfg_unlink() {  # name [root]. The name is removed on the walked parent's descriptor, never by `rm`.
  python3 -I "$STATE_TOOL" unlink "$1" --root "${2:-$CONFIG_ROOT}"
}
if [[ -e "$LINK_TARGET" || -L "$LINK_TARGET" ]]; then
  read_once "$LINK_TARGET" "$LINK_OLD" "$WORK/link.old.meta" "$CONFIG_ROOT" \
    || refuse "$LINK_TARGET is not a plain file this can read safely (the reason is above). Nothing was written"
  HAD_LINK=1
  read -r L_UID L_GID L_MODE < "$WORK/link.old.meta"
  LINK_BACKUP="$LINK_TARGET.bak.$(date -u +%Y%m%dT%H%M%SZ)"
  cfg_plant "$LINK_BACKUP" "$L_UID" "$L_GID" "$L_MODE" < "$LINK_OLD" \
    || die "could not keep a copy of $LINK_TARGET, so nothing was changed"
fi
# The credential on STDIN, never on argv (P2-057). It is the most serious of
# the four secrets here: permanent until it is re-minted, protected by
# nothing but this file's mode, and a local account that read it off
# /proc/<pid>/cmdline could dial the aggregator as this node, replace its
# live link and answer the aggregator's reads with whatever it liked.
# scripts/fleet-link-place.sh takes it on stdin for exactly this reason.
( umask 077
  printf '%s' "$CREDENTIAL" >"$WORK/credential"
  python3 -I - "$WORK/link.new" "$AGGREGATOR_WS" "$SETTLED_LABEL" "$WORK/credential" <<'PY'
import json, sys
path, url, label, credfile = sys.argv[1:5]
with open(credfile) as f:
    cred = f.read()
with open(path, "w") as f:
    json.dump({"aggregator_url": url, "credential": cred, "label": label}, f, indent=2)
    f.write("\n")
PY
)
shred -u "$WORK/credential" 2>/dev/null || rm -f "$WORK/credential"
LINK_UID=''; [[ $EUID -ne 0 ]] || LINK_UID="$(id -u "$DASH_USER")"
cfg_plant "$LINK_TARGET" "$LINK_UID" '' 600 < "$WORK/link.new" \
  || { shred -u "$WORK/link.new" 2>/dev/null || rm -f "$WORK/link.new"; die "could not write $LINK_TARGET (the reason is above), and its previous contents are untouched"; }
shred -u "$WORK/link.new" 2>/dev/null || rm -f "$WORK/link.new"
LINK_COMPLAINT=''
LINK_RC=0
LINK_COMPLAINT="$( (cd "$REPO/dashboard" && dash_node APERIRE_LINK_TARGET="$LINK_TARGET" -- \
  --import tsx --input-type=module -e "
  import { loadLinkConfig } from './lib/fleet-link-agent.ts';
  const r = loadLinkConfig(process.env.APERIRE_LINK_TARGET);
  if (!r.ok) { console.error(r.reason); process.exit(1); }
") </dev/null 2>&1 1>/dev/null | clean_text; exit "${PIPESTATUS[0]}" )" || LINK_RC=$?
if (( LINK_RC != 0 )); then
  # Put back by descriptor, like everything else here (#888 N1): `rm -f` by
  # name resolves config/ again, and a config/ the dashboard's account has
  # swapped for a link would take the delete into another directory.
  PUT_BACK=1
  if (( HAD_LINK )); then
    cfg_plant "$LINK_TARGET" "$L_UID" "$L_GID" "$L_MODE" < "$LINK_OLD" || PUT_BACK=0
  else
    cfg_unlink "$LINK_TARGET" || PUT_BACK=0
  fi
  [[ -z "$LINK_BACKUP" ]] || cfg_unlink "$LINK_BACKUP" || info "could not remove the backup $LINK_BACKUP (the reason is above); it is yours to delete"
  info "$LINK_COMPLAINT"
  (( PUT_BACK )) \
    || die "the credential file this command wrote is not one this node's own agent accepts, and it could not be put back (the reason is above), so $LINK_TARGET may still hold it. Look at that folder before anything else: it may not be the one this command started in"
  die "the credential file this command wrote is not one this node's own agent accepts, so it was put back. Nothing else was written"
fi
[[ -z "$LINK_BACKUP" ]] || cfg_unlink "$LINK_BACKUP" || info "could not remove the backup $LINK_BACKUP (the reason is above); it is yours to delete"
say "$LINK_TARGET  ($DASH_USER, 0600)"
# A re-pair clears a revocation the aggregator signed for the OLD credential
# (#688). It is inert already, because it names that credential's hash and
# this one is new; removed as well, so no file on this node still reads as
# revoked. data/ is the dashboard account's too, so this is an unlink on the
# walked descriptor as well, never `rm` by name (#888 N1).
LINK_TOMBSTONE="$REPO/data/fleet-link.tombstone.json"
if [[ -e "$LINK_TOMBSTONE" || -L "$LINK_TOMBSTONE" ]]; then
  if cfg_unlink "$LINK_TOMBSTONE" "$REPO/data"; then
    say "$LINK_TOMBSTONE  (removed: the revocation it held was for the old credential)"
  else
    info "could not remove $LINK_TOMBSTONE (the reason is above). It names the old credential, so it does nothing to this one; remove it when you can"
  fi
fi
WROTE+=("$LINK_TARGET")

# ── artefact 2: the aggregator's fleet trust public key ──────────────────
# Surgical: one line under peers:, never a load-and-dump. A dump cycle
# rewrites the whole file and drops every comment in it, and this file may
# hold this node's own private_key beside the peers block.
#
# An existing peers.aggregator with a DIFFERENT key is refused, never
# overwritten: a node that already trusts one aggregator being silently
# re-pointed at another is the whole of what trust-on-first-use exists to
# make visible.
step "Trusting the aggregator's fleet key"
# The file was read ONCE, above and before the credential was written, by
# root, without following a link, and every later step works from those bytes
# and that one fstat: the mode check, the helper's read-back (handed over on
# stdin, so a helper that cannot open the name answers the way an absent file
# does and passes the check by mistake), the surgical edit and the owner and
# mode the write keeps. No later step looks at the name again. The name is in a directory the dashboard's account
# owns, and the helper below runs as that account: a link it swapped in after
# a check would have root read, edit and re-publish whatever it points at.
if (( TRUST_SAME )); then
  say "$TRUST_FILE already carries that key (peers.aggregator)"
else
  # Written by descriptor, never `install` by name: state-file.py creates the
  # file beside the name, sets owner and mode on the descriptor and renames it
  # into place, so a link left at the name is replaced and never followed.
  # Owner and mode are those of the file root read, not of whatever the name
  # is now. A new file gets root and the Advisor's shared group where root can
  # give it away, and its own account's group where it cannot (#538).
  plant_trust() {  # uid gid mode
    python3 -I "$STATE_TOOL" plant "$TRUST_FILE" "$1" "$2" "$3" --stdin --root "$CONFIG_ROOT" < "$TRUST_TMP"
  }
  TRUST_GID="$(getent group "${TRUST_GROUP:-root}" 2>/dev/null | cut -d: -f3 || true)"
  if [[ -n "$T_MODE" ]]; then
    plant_trust "$T_UID" "$T_GID" "$T_MODE" \
      || die "could not write $TRUST_FILE, and its previous contents are untouched. $LINK_TARGET is written"
    OWNER="$(id -nu "$T_UID" 2>/dev/null || echo "$T_UID"):$(getent group "$T_GID" 2>/dev/null | cut -d: -f1 || true)"
    say "$TRUST_FILE  (peers.aggregator added; $OWNER, mode $T_MODE kept)"
  elif [[ -n "$TRUST_GID" ]] && plant_trust 0 "$TRUST_GID" 640 2>/dev/null; then
    say "$TRUST_FILE  (created, root:${TRUST_GROUP:-root} 0640)"
  # Without root, $TRUST_GROUP resolved above (a group this account and
  # advisord's share) still gets to 0640 (#538): a self-owned file through
  # that group is what advisord actually reads it through, not a downgrade
  # from root ownership. Only tried when a real group was found: chgrp to a
  # group this account is not in fails the same as chgrp to root would.
  elif [[ -n "$TRUST_GROUP" && -n "$TRUST_GID" ]] \
    && plant_trust "$(id -u)" "$TRUST_GID" 640 2>/dev/null; then
    say "$TRUST_FILE  (created, $(id -un):$TRUST_GROUP 0640)"
  elif plant_trust "" "" 600; then
    # The last resort, and the one shape this file must never be found in by
    # anything but a program willing to say so out loud: 0600 through this
    # account's own group is a file advisord cannot read no matter which
    # account runs it. #538 is what a month of that looked like.
    say "$TRUST_FILE  (created $(id -un):$(id -gn) 0600, root was not available here, and"
    say "  neither was a group $(id -un) shares with advisord)"
    say "an Advisor running as another account cannot read it at that mode. Fix it with:"
    say "  sudo chown root:${TRUST_GROUP:-root} $TRUST_FILE && sudo chmod 0640 $TRUST_FILE"
  else
    die "could not write $TRUST_FILE at all. $LINK_TARGET is written"
  fi
  WROTE+=("$TRUST_FILE")
  # #868: on a host whose trust file holds a private_key, the Advisor reads
  # fleet-trust.pub.yaml beside it, not this file. That copy has to carry the
  # peers.aggregator just written, or the Advisor refuses the aggregator's
  # first push. Remade here, never left for the next update. Judged on the
  # bytes just planted (in $WORK), not by reading the name again.
  if [[ -e "$CONFIG_DIR/fleet-trust.pub.yaml" ]] || grep -q '^private_key:' "$TRUST_TMP" 2>/dev/null; then
    if [[ $EUID -eq 0 && -r "$PAIR_SCRIPTS_DIR/fleet-trust-split.sh" ]] \
       && FTS_OUT="$(bash "$PAIR_SCRIPTS_DIR/fleet-trust-split.sh" --repo "$REPO" 2>&1)"; then
      while IFS= read -r _l; do [[ -n "$_l" ]] && say "$_l"; done <<<"$FTS_OUT"
    else
      [[ -n "${FTS_OUT:-}" ]] && say "$FTS_OUT"
      say "WARNING: the Advisor reads fleet-trust.pub.yaml here, and it was not remade with the new peers.aggregator."
      say "  Fix it with: curl -fsSL https://get.aperire.one | bash -s -- --update --force"
    fi
  fi
fi

# ── the pairing record, for this node's Advisor (#991) ───────────────────
# The Advisor pins the rp_id and origins of the first trust bundle it takes,
# and refuses any later bundle that carries others. An aggregator moved to a
# new host name keeps its trust key, so this pairing takes the TRUST_SAME path
# above, and its bundles were then refused for good until someone removed the
# Advisor's trust-binding.json by hand.
#
# This record is what lets the pin move, and nothing else does. It is written
# here, by root, only after the aggregator approved this pairing under passkey,
# its signed answer verified and the operator's fingerprint paste matched. It
# names the trust key just checked and a fresh pairing id. The Advisor takes
# the next bundle signed by that key under a new rp_id once, records that it
# did, and writes it to its own ledger. Root never touches the Advisor's own
# state: the reset is the Advisor's act, on its own files.
#
# Under $ETC, root's own directory, and refused if that is not root's: a record
# another account could replace would let that account move the pin. Not
# fatal either way. Without it the Advisor keeps the binding it has.
PAIRED_RECORD="$ETC/fleet-paired.json"
if python3 -I - "$PAIRED_RECORD" "$TRUST_PUB" "$AGGREGATOR" "$SETTLED_LABEL" <<'PY'
import json, os, secrets, stat, sys, tempfile, time
path, pub, agg, label = sys.argv[1:5]
d = os.path.dirname(path)
st = os.lstat(d)
if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o022:
    sys.exit("%s is not a directory only this account can write, so the record is not written there" % d)
rec = {
    "pairing": secrets.token_hex(16),
    "paired_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "trust_pub": pub,
    "aggregator": agg,
    "label": label,
}
fd, tmp = tempfile.mkstemp(dir=d, prefix=".fleet-paired.")
try:
    os.fchmod(fd, 0o644)
    with os.fdopen(fd, "w") as f:
        json.dump(rec, f)
        f.write("\n")
    os.replace(tmp, path)
except BaseException:
    try:
        os.unlink(tmp)
    except FileNotFoundError:
        pass
    raise
PY
then
  WROTE+=("$PAIRED_RECORD")
  say "$PAIRED_RECORD  (this pairing, for the Advisor's trust binding; $(id -un), 0644)"
else
  say "could not record this pairing at $PAIRED_RECORD (the reason is above). The link works."
  say "If this node's Advisor already trusts an aggregator under another host name, it keeps"
  say "refusing this one's passkey lists until this command runs again and records it."
fi

# ── artefact 3: the fleet arm public key ─────────────────────────────────
# Through install-model-key-sealer.sh --trust-arm-key, exactly as an operator
# would type it and never as a hand-written file. That script validates the
# key, refuses a private half loudly, refreshes the installed sealer when the
# tree differs, and refuses a host that cannot name its own node key.
#
# HELD FIRST, on every host, Advisor or not (#720). This settlement is the
# one moment this node is handed the key by a source it has just checked, and
# a node with no Advisor has no sealer for --trust-arm-key to trust it for.
# --hold-arm-key keeps it root-owned under $ETC, where nothing trusts it; the
# Advisor install places it, so a node paired first and given an Advisor
# afterwards is armable from the aggregator with no shell on it. Held on a
# host that has an Advisor too, so removing and reinstalling the Advisor does
# not lose it. Not fatal: the link is written and works either way.
FLEET_ARM_HELD="$ETC/fleet-arm.paired.pub"
step "The fleet arm key"
HOLD_RC=1
if [[ "$ARM_PUB" != '-' && -n "$ARM_PUB" && -f "$PAIR_SCRIPTS_DIR/install-model-key-sealer.sh" ]]; then
  HOLD_RC=0
  APERIRE_INSTALL_TREE="$REPO" bash "$PAIR_SCRIPTS_DIR/install-model-key-sealer.sh" --hold-arm-key "$ARM_PUB" || HOLD_RC=$?
  if (( HOLD_RC == 0 )); then WROTE+=("$FLEET_ARM_HELD"); fi
fi
# A settlement with no arm key never gets this far (#741): it is refused
# above, before the first write.
if [[ ! -f "$PAIR_SCRIPTS_DIR/install-model-key-sealer.sh" ]]; then
  say "no install-model-key-sealer.sh in this tree, so the arm key was not installed."
elif (( HAVE_ADVISOR == 0 )) && ! advisor_unit_here; then
  # There is no Advisor on this host, so there was never a sealer for the
  # key to be trusted by or refused BY (#331), and none is asked (#1222):
  # asking printed the sealer's own "error: no sealer" in the middle of a
  # pairing that worked, on the order the guide teaches, node first. Read
  # off this tree rather than off the sealer's exit code. The two facts
  # together, so a host part-way through an Advisor install is not called
  # Advisor-less on a missing token alone.
  #
  # install.sh reads the first line and the "held" line back by their
  # opening words, so both keep them.
  say "no Advisor here, so there is nothing to arm and no model to seal. The link is registered and works."
  if (( HOLD_RC == 0 )); then
    # #720: the key is held, so adding the Advisor later is the whole of it.
    say "the arm key is held for it at $FLEET_ARM_HELD. Installing the Advisor"
    say "places it, and the aggregator can arm this host from then on. Nothing to run."
  elif [[ -e "$FLEET_ARM_HELD" || -L "$FLEET_ARM_HELD" ]]; then
    # #720 review: the hold was refused, and something is ALREADY held.
    # The Advisor install would place that one, which is not this
    # pairing's key, and a later --trust-arm-key would then refuse this
    # one as different. So the way on clears both before trusting.
    say "the arm key could NOT be held (the reason is above), and $FLEET_ARM_HELD"
    say "already holds another key, which installing the Advisor would place. If this"
    say "pairing's key is the right one, clear both and trust it after adding the Advisor:"
    say "  sudo rm -f $FLEET_ARM_HELD $ETC/fleet-arm.pub"
    say "  curl -fsSL https://get.aperire.one | bash -s -- --dir $REPO --run model-key-sealer --trust-arm-key <key>"
  else
    say "the arm key could not be held here, so installing the Advisor will not place"
    say "it. If you add the Advisor later, trust the key then:"
    say "  curl -fsSL https://get.aperire.one | bash -s -- --dir $REPO --run model-key-sealer --trust-arm-key <key>"
  fi
else
  ARM_RC=0
  APERIRE_INSTALL_TREE="$REPO" bash "$PAIR_SCRIPTS_DIR/install-model-key-sealer.sh" --trust-arm-key "$ARM_PUB" || ARM_RC=$?
  if (( ARM_RC == 0 )); then
    WROTE+=("$ETC/fleet-arm.pub")
    # ── and open one window, so the fleet model can land ───────────────
    #
    # ADR 0019 phase 4, #168. The aggregator pushes its sealed fleet model at
    # this node as the last act of the pairing, and the node's own sealer
    # refuses while this node is unarmed. That refusal is the whole gate and
    # it stays exactly where it is: ROOT on this host opens the window, and
    # no dashboard anywhere gained the power to.
    #
    # It is root on this machine, inside a ceremony the operator is running
    # at this keyboard right now, for fifteen minutes. The alternative is an
    # operator typing one more root line on every new node, on a product
    # whose install is meant to be one command.
    #
    # Only where there is an advisord unit to seal onto. A window opened on a
    # host with no Advisor spends nothing and closes on its own, but it would
    # also be a privileged act with no purpose, and this program does not
    # make those.
    if advisor_unit_here; then
      if APERIRE_INSTALL_TREE="$REPO" bash "$PAIR_SCRIPTS_DIR/install-model-key-sealer.sh" --arm >/dev/null 2>&1; then
        say "opened a 15-minute sealing window here, so the aggregator can hand this node"
        say "the fleet's Advisor model as its last step. An unspent window closes on its own."
      else
        # Not fatal, and named. The link is registered and works; what is
        # lost is the inherit, and Settings can push it later once somebody
        # arms this host.
        say "could not open a sealing window here, so this node will not take the fleet's"
        say "Advisor model during this pairing. Arm it and bring it up to date from Settings:"
        say "  curl -fsSL https://get.aperire.one | bash -s -- --dir $REPO --run model-key-sealer --arm"
      fi
    fi
  else
    # This host HAS an Advisor and its sealer said no. Unchanged: that is a
    # refusal with a reason above it, and it is a thing to fix.
    say "the sealer refused that key (its own reason is above). The link is registered"
    say "and works; arming this host from the aggregator needs that key, so fix it and run:"
    say "  curl -fsSL https://get.aperire.one | bash -s -- --dir $REPO --run model-key-sealer --trust-arm-key <key>"
  fi
fi

# ── tell the aggregator, then reload ─────────────────────────────────────
# Written and verified BEFORE the reload, so a reload that fails leaves a
# node that pairs on its next restart and says so.
python3 -I - "$WORK/report.json" <<'PY' "${WROTE[@]}"
import json, sys
path = sys.argv[1]
with open(path, "w") as f:
    json.dump({"ok": True, "wrote": sys.argv[2:]}, f)
PY
tr -d '\n' < "$WORK/report.json" >&3
printf '\n' >&3
# The helper sends pair_done, prints `closed` and exits. Its status is not
# what decides this run's: everything this host owns is already on disk.
wait "$DIAL_PID" 2>/dev/null || true

step "Reload"
RELOADED=0
# This instance's, never the default's: the credential is in this tree.
for _u in "aperire-server$UNIT_SUFFIX" "aperire-read$UNIT_SUFFIX"; do
  if systemctl is-active --quiet "$_u" 2>/dev/null; then
    if systemctl reload "$_u"; then
      say "reloaded $_u — the credential is read in place"
      RELOADED=1
    else
      say "could not reload $_u (its own reason is above). The credential is written;"
      say "reload or restart it yourself:  sudo systemctl reload $_u"
    fi
    break
  fi
done
if (( ! RELOADED )); then
  say "no active aperire-server$UNIT_SUFFIX or aperire-read$UNIT_SUFFIX unit here, so restart your dashboard"
  say "process to pick up the credential."
fi

step "Done"
say "label:        $SETTLED_LABEL"
say "node key:     $(short_key "$PUBKEY_NODE")"
say "aggregator:   $AGGREGATOR"
say "fingerprint:  $TRUST_FP  (pairing fingerprint, matched)"
say "ports there:  read $READ_PORT, advisor $ADVISOR_PORT"
say ""
say "This node now dials out and holds one link. Its own Settings page says so, and"
say "the aggregator's Fleet registry list shows it as \"link\" with an age once it is up."
say ""
say "To undo it from THIS host:"
say "  sudo rm $LINK_TARGET"
# Whenever the file is there, not only when this run wrote it: a key held by
# an earlier pairing is placed by the next Advisor install all the same.
if [[ -e "$FLEET_ARM_HELD" || -L "$FLEET_ARM_HELD" ]]; then say "  sudo rm $FLEET_ARM_HELD"; fi
say "  sudo systemctl reload ${DASH_UNIT:-aperire-server$UNIT_SUFFIX}"
say "That stops this node dialling. The aggregator's own row stays until an operator"
say "removes it there, which is what revokes the credential."
exit 0
