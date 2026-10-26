#!/usr/bin/env bash
# Seal the Advisor's model API key to this host, as root, exactly once per
# arming. The one privileged step in the browser model setup, and the only
# place in this project where a key is sealed.
#
#   sudo bash scripts/aperire-seal-model-key.sh   < payload      (an operator)
#   sudo bash scripts/aperire-seal-model-key.sh --reset           (an operator)
#   the dashboard, over /run/aperire/seal-model-key.sock          (the browser step)
#
# `--reset` is the only argument this program takes, and it is an OPERATOR
# verb. The dashboard cannot reach it: the socket unit behind it names this
# program with no arguments, so what arrives over the socket is a payload on
# standard input and nothing else. Unsealing a node is not something the
# unprivileged account in front may ask for.
#
# ---- why this exists ------------------------------------------------
#
# Sealing needs root and cannot be delegated. `systemd-creds encrypt` reads
# /var/lib/systemd/credential.secret, which is 0400 root:root, and a non-root
# caller gets "Failed to determine local credential host secret: Permission
# denied". Writing LoadCredentialEncrypted= into the unit and reloading systemd
# need root for the same unavoidable reason. So a key submitted in a browser,
# to a dashboard that runs unprivileged, has to cross a privilege boundary
# somewhere, and this file is that boundary: one program, no arguments, the
# whole of what the dashboard may do as root.
#
# The dashboard does not start it. It cannot: its own unit sets
# NoNewPrivileges=true and an empty CapabilityBoundingSet, and under those
# sudo refuses to run at all ("the 'no new privileges' flag is set"). So the
# privileged side is already running when the dashboard arrives: systemd
# listens on a socket the dashboard account alone may open (0600, owned by it),
# accepts one connection at a time, and starts this program as root with that
# connection as its standard input. The dashboard writes five lines and reads
# what comes back. It never names a program, a path or an argument.
#
# It is NOT a verb in the Advisor's privilege wrapper. That wrapper is the list
# of things the Advisor itself may do to a node, and putting "write a root
# credential, edit my own unit, restart myself" in it would hand the whole of
# that to the model-driven executor. The grant here belongs to the dashboard
# account instead, which the Advisor cannot reach.
#
# ---- the arming marker ----------------------------------------------
#
# The dashboard may seal once per arming, and only inside a short window. That
# is what the marker is: a root-owned empty file whose modification time is
# when it was armed. This script refuses unless it exists and is younger than
# the window, and DELETES IT as the first action after a successful seal. So a
# second attempt after a success is refused with nothing left to spend, and an
# unused arming lapses on its own.
#
# Arming needs root and there is no verb here that does it, on purpose: a
# program the dashboard can run to re-arm itself would be the same as no
# window at all. get-aperire-advisor.sh arms it, and running that again is how
# an operator opens another window.
#
# The `arm` verb below does not soften that rule, because it decides nothing.
# It RELAYS a token that root on the aggregator signed, and verifies that
# signature against a public key only root on this host can have placed
# (/etc/aperire/fleet-arm.pub). The dashboard carries the token and cannot
# mint one: the private half is on another machine, root-owned, unreadable by
# the account either dashboard runs as. So a window is still opened by root,
# once for a whole fleet instead of once per node. One token opens one window:
# it carries a nonce, it is refused more than 300 seconds either side of its
# own timestamp, and its nonce is remembered in /etc/aperire/fleet-arm.seen so
# the same token cannot open a second.
#
# A token is also for ONE HOST, and that is checked here (#184). The token
# names its target by node key, inside the bytes that were signed, and this
# program compares it with the key stamped in /etc/aperire/node-key when the
# grant was installed. Read here rather than left to the dashboard in front,
# because the dashboard is the process this whole design says must not be
# able to arm: the moment one couriers tokens addressed to other nodes, its
# own check is a check the attacker holds. The dashboard checks it too, and
# that check is the belt (it saves a root invocation); this one is the buckle.
#
# ---- the payload ----------------------------------------------------
#
# Five lines on standard input, in this order, and nothing else:
#
#   1  base_url          https://api.x.ai/v1
#   2  shape             openai | anthropic
#   3  model             grok-4
#   4  credential_name   model-api-key-xai
#   5  api key           the secret
#
# On standard input and never in the arguments, because a process's arguments
# are world-readable in /proc for as long as it runs, and never in the
# environment, which is readable to the same places and inherited by children.
# The caller cannot pass an argument even if it wanted to: what it holds is a
# socket, and the unit behind that socket names this program and nothing else.
# The refusal below is kept anyway, for the operator invocation.
#
# Nothing here prints, logs or echoes the key. The journal gets one line per
# invocation saying what happened and never what was sealed.
#
# There is a second, shorter payload, and the first line says which one has
# arrived. Exactly `arm` on line one is a fleet arm token; anything else is a
# base_url and the five lines above. A base_url can never be the bare word
# `arm`, so no seal can be read as an arm and no arm as a seal:
#
#   1  arm
#   2  the token text, base64
#   3  its Ed25519 signature, base64
#
# ---- what a seal leaves behind ---------------------------------------
#
# Three things, and the Advisor needs all three before it has a model:
#
#   the credential      $CRED_DIR/<credential_name>, sealed with systemd-creds
#   the drop-in         LoadCredentialEncrypted=<credential_name>:... in
#                       <unit>.service.d/model-credential.conf, so the key
#                       arrives at start
#   the config          <state>/model.json, which names the provider, the
#                       model and the credential, and never holds the key
#
# The credential line lives in a DROP-IN and not in the unit itself, and that
# is the whole of what makes a reset safe. systemd refuses to start a unit
# that declares a credential file which is not there: it exits 243/CREDENTIALS
# before the program runs, and the restart counter climbs. So the two things
# that must disappear together, the sealed file and the directive that loads
# it, are one file each, both written here and both removed by --reset. A main
# unit rewritten by an installer, a restore or an update carries the directive
# back; a drop-in this program owns does not.
#
# Hosts sealed before this carry the line in the main unit. Every seal and
# every reset MIGRATES them: any LoadCredentialEncrypted= line in the main
# unit pointing into $CRED_DIR is removed, and the drop-in is what remains.
# One credential is loaded either way: a unit and a drop-in declaring the same
# credential id do not refuse each other, and the drop-in, parsed last, is the
# one the service receives (measured on systemd 255). So a host part-way
# through the migration still starts.
#
# The config is written HERE, not left to the caller. The first browser seal
# on a real host (2026-09-01) sealed the key, wired the unit and restarted the
# service, and the Advisor came back reporting "no model is configured",
# because the file that tells it which model to use had never been written:
# the operator-menu path wrote it before calling this, and the browser path
# had nothing that could. A seal that leaves the Advisor without a model is
# not a seal that worked, so all three are this program's job.
#
# The state directory is read from the unit's own ExecStart line, because that
# is where the running service will look, and the file is owned by whatever
# owns that directory: the Advisor's account, not root.
#
# ---- to undo ---------------------------------------------------------
#
#   sudo aperire-seal-model-key --reset
#
# One root action, not three by-hand steps. It removes the credential, the
# drop-in and any migrated unit line, writes the config back to the honest
# no-model state, reloads systemd, clears a failed unit, restarts the Advisor
# and asks it what it now reports. Three steps done by hand, one of them
# forgotten, is a dead Advisor that the dashboard reads as installed-but-down
# with no reason it can name (#446).
#
# It refuses while a break-glass window is open: a window is an operator part
# way through something, and taking the model out from under it is the wrong
# moment. A service that does not answer has no window to protect (windows
# live in the running process and a restart ends them), so an Advisor that is
# down does not block its own repair.
#
# It writes no ledger entry. Nothing here does: the record of a model change
# is the Advisor's own observation of its configuration (see
# internal/ledger/ledger.go on KindModelConfigured), and a program that
# performed the change does not get to write the record of it. What this
# leaves is a fact for the record to quote: <state>/model-change.json, naming
# the operator who reset it or the arming a seal was made under. The Advisor
# reads it at its next start, attaches it to the entry it writes from what it
# OBSERVED, and deletes it.

set -euo pipefail

CRED_DIR="${APERIRE_CRED_DIR:-/etc/aperire/creds}"
ARM_FILE="${APERIRE_ARM_FILE:-/etc/aperire/model-key.arm}"
# Fifteen minutes. Long enough to paste a key, test it against the provider and
# approve with a passkey; short enough that an arming forgotten on a shared box
# is not a standing invitation.
ARM_WINDOW_SEC="${APERIRE_ARM_WINDOW_SEC:-900}"
# The fleet arm key this host trusts, and the nonces it has already honoured.
# Both root-owned under /etc: the pub file is the trust root of the arm path,
# and the seen file is what stops one token opening two windows.
FLEET_ARM_PUB="${APERIRE_FLEET_ARM_PUB:-/etc/aperire/fleet-arm.pub}"
FLEET_ARM_SEEN="${APERIRE_FLEET_ARM_SEEN:-/etc/aperire/fleet-arm.seen}"
# This host's own node key, stamped by install-model-key-sealer.sh from what
# the node itself answered. An arm token's `target` is compared with it, so
# without it this program cannot tell a token addressed here from one
# addressed to the machine next to it, and refuses every one.
NODE_KEY_FILE="${APERIRE_NODE_KEY_FILE:-/etc/aperire/node-key}"
# What a node key looks like: base58 (no 0, O, I or l), leading `n`. The same
# shape aperire-fleet-add.sh pins and aperire-fleet-arm.sh addresses a token
# to, stated here because this is where the address is finally checked.
NODE_KEY_RE='^n[1-9A-HJ-NP-Za-km-z]{20,60}$'
# How far an arm token's own timestamp may be from this host's clock, either
# way. Not configurable: a host that would accept an older token is a host
# where a captured token keeps working, and that is not a local decision.
ARM_TOKEN_SKEW_SEC=300
# The base_url rules, as variables because bash reads a quoted pattern as a
# literal. Inside the brackets a backslash is itself, so [^[:space:]"\] reads:
# not whitespace, not a double quote, not a backslash.
BASE_URL_HTTPS_RE='^https://[^[:space:]"\\]+$'
BASE_URL_LOOPBACK_RE='^http://(127\.0\.0\.1|localhost)(:[0-9]{1,5})?(/[^[:space:]"\\]*)?$'
UNIT_DIR="${APERIRE_UNIT_DIR:-/etc/systemd/system}"
ADVISORD_UNIT="aperire-advisord${APERIRE_INSTANCE:+-$APERIRE_INSTANCE}"
UNIT="$UNIT_DIR/${ADVISORD_UNIT}.service"
# The credential directive, in a file of its own. Added by a seal, removed by
# a reset, and never edited into the unit the installer writes.
DROPIN_DIR="$UNIT.d"
DROPIN="$DROPIN_DIR/model-credential.conf"
# Which aggregator opened the window a seal was made under, written by the arm
# verb and read by the seal one step later, so the record of a key arriving can
# say where it came from (#447). Root-owned beside the marker it belongs to,
# and removed everywhere that marker is.
ARM_ISSUER_FILE="${APERIRE_ARM_ISSUER_FILE:-${ARM_FILE}.issuer}"
# How far apart the issuer and the marker may be and still be one window. The
# arm verb writes them one line apart; anything else is an issuer left over
# from an earlier window beside a marker somebody else wrote.
ARM_ISSUER_PAIR_SEC=5
# Where this program leaves what it just did, for the Advisor to quote on the
# entry it writes from its own observation. Written into the directory that
# holds the model config, which is the directory the service reads.
CHANGE_FILE_NAME=model-change.json
# Where the Advisor answers, when the unit does not say. The installer writes
# --addr on the ExecStart line; this is the default it writes.
DEFAULT_ADVISOR_ADDR=127.0.0.1:7810
TAG=aperire-seal-model-key
# What sweep_stale_plain_keys removed, declared here so every path that prints
# it has something to print, including the ones that refuse before it runs.
SWEPT=()

# The state helper (#703). Every file this program writes under the Advisor's
# state directory, and every read it makes of the token in there, goes
# through it: it does the create, the ownership, the mode and the read on a
# descriptor opened relative to a descriptor on the directory, rather than on
# a name the Advisor's own account can swap for a link between root's calls.
#
# Resolved from /usr/local/sbin, where install-model-key-sealer.sh puts a
# root-owned copy beside this program on the full install and on the
# --trust-arm-key refresh. A checkout copy is used ONLY when this program is
# itself being run out of a checkout (setup-advisor-model.sh and
# reseal-model-key.sh do that, under sudo), which adds no trust that run does
# not already have. The installed copy wins either way, because it is the one
# the dashboard's account cannot rewrite.
#
# Never taken from the environment (#1148). This program is root, and the file
# STATE_TOOL names is run by it: a variable set in a root shell the login
# started would choose that file. Where this program sits decides, in this
# order, and an installed name that is not what the installer put there is
# refused rather than passed over for the next one: a regular file, not a link,
# owned by root, writable by neither group nor other. A suite that needs a
# stand-in puts a state-file.py beside its own copy of this program.
STATE_TOOL=""
STATE_TOOL_WHY=""
STATE_TOOL_INSTALLED=/usr/local/sbin/aperire-state-file
STATE_FILE_UID=0
installed_file_ok() { # $1 = a path root is about to run or source
  local meta
  [[ -f "$1" && ! -L "$1" && -r "$1" ]] || return 1
  meta="$(stat -c '%u:%a' -- "$1" 2>/dev/null)" || return 1
  [[ "${meta%%:*}" == "$STATE_FILE_UID" ]] && (( (8#${meta##*:} & 8#022) == 0 ))
}
# Bash itself, no dirname: this has to resolve with a PATH that holds
# nothing, as a unit with a bare environment can have.
_src_dir="${BASH_SOURCE[0]}"
if [[ "$_src_dir" == */* ]]; then _src_dir="${_src_dir%/*}"; else _src_dir=.; fi
# CDPATH emptied: a relative program path would otherwise be looked up in
# the directories the environment names, and the helper and library are
# found beside whatever directory that finds.
_sf_here="$(CDPATH='' cd -- "$_src_dir" && pwd)"
# Beside this program first, wherever this program is, because that is exactly
# how the installer places it. `aperire-state-file` is the installed name and
# never the checkout's. Then the default destination, for a program that was
# moved without its helper. Then a checkout copy, which is only reachable when
# this program is itself being run out of a checkout.
for _sf_c in "$_sf_here/aperire-state-file" "$STATE_TOOL_INSTALLED"; do
  [[ -e "$_sf_c" || -L "$_sf_c" ]] || continue
  if installed_file_ok "$_sf_c"; then
    STATE_TOOL="$_sf_c"
  else
    STATE_TOOL_WHY="$_sf_c is not a regular file owned by root that no one else can write"
  fi
  break
done
if [[ -z "$STATE_TOOL" && -z "$STATE_TOOL_WHY" && -f "$_sf_here/state-file.py" ]]; then
  STATE_TOOL="$_sf_here/state-file.py"
fi
unset _sf_c

# How this host keeps a key, and the drop-in that loads it (#708). Resolved
# exactly the way STATE_TOOL above is, and for the same reason: this program
# is copied to /usr/local/sbin and runs with no tree beside it, so the library
# is copied beside it by install-model-key-sealer.sh and the installed copy is
# the one that wins. A checkout copy is reachable only when this program is
# itself being run out of a checkout, which adds no trust that run does not
# already have.
METHOD_LIB=""
METHOD_LIB_WHY=""
METHOD_LIB_INSTALLED=/usr/local/sbin/aperire-model-key-method
# Sourced, so it is held to the same check as the helper above and for a
# stronger reason: whatever it holds runs in this shell. Not taken from the
# environment either (#1148).
for _ml_c in "$_sf_here/aperire-model-key-method" "$METHOD_LIB_INSTALLED"; do
  [[ -e "$_ml_c" || -L "$_ml_c" ]] || continue
  if installed_file_ok "$_ml_c"; then
    METHOD_LIB="$_ml_c"
  else
    METHOD_LIB_WHY="$_ml_c is not a regular file owned by root that no one else can write"
  fi
  break
done
if [[ -z "$METHOD_LIB" && -z "$METHOD_LIB_WHY" && -f "$_sf_here/model-key-method-lib.sh" ]]; then
  METHOD_LIB="$_sf_here/model-key-method-lib.sh"
fi
unset _sf_here _ml_c _src_dir
# Sourced here, at the top, rather than inside the path that needs it: a
# library this program cannot find is a fact about the host, and the host
# should hear it before a payload is read rather than half way through a seal.
# shellcheck source=scripts/model-key-method-lib.sh
if [[ -n "$METHOD_LIB" && -f "$METHOD_LIB" ]]; then . "$METHOD_LIB"; fi

method_lib_usable() {
  [[ -n "$METHOD_LIB" && -f "$METHOD_LIB" ]] || return 1
  declare -f aperire_key_method >/dev/null 2>&1 || return 1
  return 0
}

# Said before anything is written, not at the write (see the refusal block
# below). A seal that got as far as the credential and the drop-in and then
# could not plant the config is a half-seal, and the cure is to find that out
# while nothing has moved.
state_tool_usable() {
  [[ -n "$STATE_TOOL" && -f "$STATE_TOOL" ]] || return 1
  command -v python3 >/dev/null 2>&1 || return 1
  return 0
}

# state_layout_ok <state dir>. Prints nothing and returns 0 when every
# directory above that one is writable by root and its owner only; prints the
# helper's own sentences and returns 1 when it is not.
#
# "The helper is present" is not the same question, and treating it as one is
# what this closes (#703, review). A host whose install tree an account other
# than the owner can write has a perfectly good helper that REFUSES, and the
# refusal arrives at the first write. On the seal path that write is the
# config, which is planted last, so the credential and the drop-in were
# already on the host: a half-seal, and "re-run this seal" fails the same way
# for ever. On the reset path the first thing that fails is the token read,
# which used to be indistinguishable from "there is no token", so the window
# check failed OPEN and the key came off with an operator mid-ceremony.
#
# So this is asked BEFORE anything is written or removed, on both paths, and
# the refusal carries the one command that repairs the layout.
state_layout_ok() { # $1 = the Advisor's state directory
  local report
  state_tool_usable || return 1
  report="$(python3 -I "$STATE_TOOL" ancestors "$1" --root "$1" 2>&1)" || return 1
  [[ -z "$report" ]] && return 0
  printf '%s\n' "$report" | cut -f3-
  return 1
}

# The sentence every layout refusal ends with, in one place so the seal path
# and the reset path cannot drift.
layout_refusal() { # $1 = the state directory, $2 = the helper's own lines
  printf 'the install tree above %s is writable by an account that is not its owner, so nothing here may write into it: %s. Repair it with: curl -fsSL https://get.aperire.one | bash -s -- --update --force' \
    "$1" "$(tr '\n' ';' <<<"$2" | sed 's/;$//')"
}

# Every invocation says what it did, in the journal, whatever the outcome. The
# failures are the point: an operator watching a browser spinner needs the
# refusal to exist somewhere they can read it, and a seal that happened without
# an arming would be the thing worth finding later.
#
# `logger` is part of util-linux, which install-advisor-account.sh already
# requires. If it is somehow missing the line still reaches stderr rather than
# being dropped, because a silent privileged action is worse than a noisy one.
say() { # $1 = outcome word, rest = detail. Never a key, and never a value read from stdin.
  local outcome="$1"; shift
  if command -v logger >/dev/null 2>&1; then
    logger -t "$TAG" -p authpriv.notice -- "$outcome: $*" || true
  fi
  printf '%s: %s\n' "$outcome" "$*" >&2
}

die() { # $1 = outcome word for the journal, $2 = what to say
  say "$1" "$2"
  exit 1
}

# reset_and_restart_advisord $1=unit name (#541 P1-091). The same two lines
# as scripts/advisord-restart-lib.sh's advisord_reset_and_restart, restated
# here rather than sourced: this program is copied to /usr/local/sbin and
# runs with no tree beside it (see "why the program is copied out of the
# tree" above), so it has nothing to source. One helper, called at every
# restart this program performs, not a second inline copy of the two lines
# at each of them. `reset-failed` first because this program's own restarts,
# a reset or a fresh seal, can land back-to-back with an install or an
# account move inside the same run, and past the burst a bare
# `systemctl restart` is refused as repeated too quickly while this program
# goes on to report a state it never reached.
reset_and_restart_advisord() {
  # A unit still carrying the note install-advisord.sh leaves on a fresh host
  # is waiting for install-advisor-account.sh: it names an account that owns
  # nothing yet, and starting it is a crash loop that comes back at every
  # boot. The key and the config are in place for when the account step
  # starts it, and the read-back that follows reports it as not running,
  # which is true (#898 review, L1). Only while it is not running: a unit that
  # still carries the note but is up (an account step interrupted after the
  # grants, then a reboot) holds the old key in memory, and a reset or a seal
  # has to restart it like any other (#898 review, N6).
  if grep -q '^# Waiting for install-advisor-account\.sh' "$UNIT" 2>/dev/null \
     && ! systemctl is-active --quiet "$1" 2>/dev/null; then
    return 0
  fi
  systemctl reset-failed "$1" 2>/dev/null || true
  systemctl restart "$1"
}

# ---- the last line, on every path ----------------------------------
#
# The dashboard reaches this through a socket, and an exit code does not cross
# a socket. systemd hands the accepted connection to this program as its
# standard input, output and error; when it ends, the connection closes
# carrying nothing about why. So the status is PRINTED, as the last line, on
# every path including every refusal, and the reader takes it from there.
#
# One handler, installed before anything can fail, doing both jobs: the
# temporary credential goes if it is still around, and the status goes last so
# nothing is written after it. `$?` is captured on the first line because
# everything below it would overwrite it.
on_exit() {
  local rc=$?
  if [[ -n "${TMP_CRED:-}" && -e "${TMP_CRED:-}" ]]; then rm -f "$TMP_CRED"; fi
  # No TMP_CFG or TMP_CHANGE here any more (#703): the config and the change
  # file are planted through the state helper, which creates its own
  # temporary under a name nothing outside it knows and removes it itself on
  # every path that does not rename it into place.
  if [[ -n "${TMP_ARM_DIR:-}" && -d "${TMP_ARM_DIR:-}" ]]; then rm -rf "$TMP_ARM_DIR"; fi
  printf 'exit=%s\n' "$rc"
}
trap on_exit EXIT

[[ $EUID -eq 0 ]] || die refused "must run as root; sealing reads the systemd host key, which is root-only"
# One argument, and only one. The seal path takes none: what the dashboard
# holds is a socket, and the unit behind it names this program with no
# arguments, so nothing that arrives that way can ask for a reset.
RESET=0
if [[ $# -gt 0 ]]; then
  [[ $# -eq 1 && "$1" == "--reset" ]] \
    || die refused "the only argument is --reset; a seal's payload arrives on standard input"
  RESET=1
fi

# ---- what the unit says about the service it starts ------------------
#
# Read from the ExecStart line rather than guessed from a path convention,
# because that is what the running service will do. Shared by the seal and
# the reset: a reset that guessed a different config path from the one a seal
# wrote would leave a file saying a model is enabled on a host with no key.
unit_exec_line() { grep -m1 '^ExecStart=' "$UNIT" 2>/dev/null || true; }

exec_flag() { # $1 = the ExecStart line, $2 = the flag name
  sed -n "s/.*[[:space:]]--$2=\([^[:space:]]*\).*/\1/p" <<<"$1"
}

model_config_path() { # $1 = the ExecStart line. Prints the path, or fails.
  local p state
  p="$(exec_flag "$1" model-config)"
  if [[ -z "$p" ]]; then
    state="$(exec_flag "$1" state)"
    [[ -n "$state" ]] || return 1
    p="$state/model.json"
  fi
  printf '%s\n' "$p"
}

# ---- the migration ---------------------------------------------------
#
# Every credential line in the MAIN unit that points into this program's
# store, removed. Hosts sealed before the drop-in existed carry exactly one;
# a host that changed models under the old code can carry two, one of them
# naming a credential nothing reads any more. The drop-in written beside it
# is then the only declaration left.
#
# Returns 1 when there was nothing to migrate, so a caller can say which of
# the two it did. The `#` delimiter is because a path holds slashes; the path
# is this program's own $CRED_DIR, never a value from the payload.
#
# Both directives (#708). A host on the plain method declares its key with
# LoadCredential=, and a migration that only knew the encrypted spelling would
# leave that line in the unit beside the drop-in written for it, so a later
# reset would remove the drop-in and leave the unit naming a file that is gone
# (243/CREDENTIALS, and the service never starts again).
UNIT_CRED_RE="^LoadCredential\\(Encrypted\\)\\?=[^:]*:$CRED_DIR/"

# ---- the plaintext keys this store must not accumulate ---------------
#
# A key kept in the clear is a WORKING key wherever its file ends up, and two
# things used to leave one behind (#712 review, M1):
#
#   a provider switch. A seal removes the other FORM of the SAME name, so
#   sealing xai and then anthropic left model-api-key-xai.plain in the store
#   with nothing naming it, and --reset never found it because --reset only
#   knows the names the config and the drop-in carry.
#
#   a quarantine. The credential check and the installer move a key aside as
#   <name>.plain.unopenable-<ts>-<pid>, and one of the things that sends a
#   key there is a widened MODE on a key that is otherwise perfectly good.
#
# So a successful seal and a reset each sweep every plaintext key in this
# store that the name in hand does not claim. Sealed blobs are left alone:
# ciphertext bound to this machine is not a key anywhere else, and sweeping
# one would be this program deleting evidence it has no reason to touch.
#
# A glob and `rm`, not the state helper: the helper exists to stop a name
# being swapped for a link between root's own open() calls, and there is no
# open() here. `rm` unlinks the NAME and never follows a link through it, and
# the directory is refused below unless it is root's alone. The one way this
# could reach outside the store is $CRED_DIR itself being a link, which is
# checked first, on both paths.
sweep_stale_plain_keys() { # $1 = the credential name to keep, or empty for none
  local keep="$1" f base
  SWEPT=()
  [[ ! -L "$CRED_DIR" && -d "$CRED_DIR" ]] || return 0
  shopt -s nullglob
  for f in "$CRED_DIR"/*"$APERIRE_KEY_PLAIN_SUFFIX" \
           "$CRED_DIR"/*"$APERIRE_KEY_PLAIN_SUFFIX".unopenable-*; do
    base="${f##*/}"
    [[ -n "$keep" && "$base" == "$keep$APERIRE_KEY_PLAIN_SUFFIX" ]] && continue
    rm -f "$f" && SWEPT+=("$base")
  done
  shopt -u nullglob
  return 0
}

strip_unit_credential_lines() {
  [[ -f "$UNIT" ]] || return 1
  grep -q -e "$UNIT_CRED_RE" "$UNIT" || return 1
  sed -i "\\#$UNIT_CRED_RE#d" "$UNIT"
}

# ---- asking the Advisor about itself ---------------------------------
#
# Over loopback with the service's own token, which root can read. Every
# answer here is best-effort by construction: the service may be the very
# thing that is down, which is the state a reset exists to repair.
#
# Three ways to fail, and they are three different sentences to an operator:
#
#   1 = there was no way to ask: no curl on this host, or no token file to
#       ask with. Nothing was sent, so nothing about the service is known.
#   2 = it answered and refused this token. A live service whose window this
#       program cannot see, which is not the state --reset repairs.
#   3 = the request went out and nothing answered it. The crash-looping host.
#
# The token is sent as the service reads it: the file's contents with the
# whitespace taken off, compared against `Authorization: Bearer <that>` in
# authorized() in the daemon. All of it stripped rather than the newline
# alone, because a trailing space in that file would otherwise make every
# window check here fail as "did not answer" against a service that answered.
advisor_status() { # $1 = addr, $2 = token file. Prints the body, or fails.
  local token body rc
  command -v curl >/dev/null 2>&1 || return 1
  [[ -n "$2" && -r "$2" ]] || return 1
  # Read through the helper, never by name (#703 item 5). This is root
  # reading a file in a directory the Advisor's own account owns, and a
  # plain redirect would follow a symlink that account put there: root would
  # then send the target's first line to a loopback service as a bearer
  # token, and print the file it came from in a refusal. The helper refuses
  # anything that is not a single-linked regular file, and a FIFO cannot
  # park root on the open.
  state_tool_usable || return 1
  # 5 is its own answer, and it has to be: a read the helper REFUSED is not a
  # host with no token on it. Before this, a refused layout came back as 1,
  # which breakglass_open reads as "there was no way to ask", which the reset
  # path treats as "no window is open" and carries on removing the key. The
  # status line is captured rather than discarded so the caller can say what
  # was wrong (#703, review).
  local err
  if ! err="$(python3 -I "$STATE_TOOL" read "$2" 2>&1)"; then
    STATE_READ_ERROR="$err"
    return 5
  fi
  token="$(tr -d '[:space:]' <<<"$err")"
  [[ -n "$token" ]] || return 1
  rc=0
  # On curl's standard input, never its argv: /proc/<pid>/cmdline is world
  # readable (#705).
  body="$(curl -sf -m "${STATUS_PROBE_SECONDS:-4}" -H @- "http://$1/v1/status" 2>/dev/null <<<"authorization: Bearer $token")" || rc=$?
  # 22 is curl's own code for "the server answered, with 400 or worse".
  (( rc != 22 )) || return 2
  (( rc == 0 )) || return 3
  printf '%s' "$body"
}

# The one block of the status document each question needs, found by its
# two-space indent. The document is written with an indent and both blocks
# are objects at the top level, so a block ends at the first `}` in that
# column. Read this way rather than with a JSON parser because this program
# depends on nothing that is not already on a minimal host.
status_block() { # $1 = the body, $2 = the block name
  awk -v k="  \"$2\": {" 'index($0, k)==1 {inb=1} inb {print} inb && /^  \}/ {exit}' <<<"$1"
}

# 0 = a window is open, 1 = none is, 2 = nothing answered the request,
# 3 = the service answered and refused this host's own token,
# 4 = there was no way to ask at all.
breakglass_open() { # $1 = addr, $2 = token file
  local body block rc
  rc=0
  body="$(advisor_status "$1" "$2")" || rc=$?
  case "$rc" in
    0) ;;
    1) return 4 ;;
    2) return 3 ;;
    # The token could not be READ, and the helper said why. Its own code,
    # because this is the one failure that must never be read as "no window
    # is open": it is the layout refusal, and the caller refuses on it.
    5) return 5 ;;
    *) return 2 ;;
  esac
  block="$(status_block "$body" breakglass)"
  [[ -n "$block" ]] || return 2
  if grep -q '"open": true'  <<<"$block"; then return 0; fi
  if grep -q '"open": false' <<<"$block"; then return 1; fi
  return 2
}

# 0 = the config declares no model at all, 1 = it declares one (whether or
# not a credential is present for it), 2 = this could not be asked.
#
# `"configured": false` is not enough on its own to prove a reset took. Since
# it started reporting the conjunction of a valid config and a readable
# credential, that same line is also what a model with no credential on this
# host reports (P3-083), and a reset that cleared the credential but left the
# config declaring a model would read exactly like one that cleared both. What
# a reset actually needs to prove is narrower: that the config declares no
# model at all. `"name"` is published only when the config validates, model
# or no credential behind it, so its absence, not `"configured": false` on
# its own, is the specific claim this check makes.
model_reports_none() { # $1 = addr, $2 = token file
  local body block
  body="$(advisor_status "$1" "$2")" || return 2
  block="$(status_block "$body" model)"
  [[ -n "$block" ]] || return 2
  if grep -q '"name":' <<<"$block"; then return 1; fi
  if grep -q '"configured": false' <<<"$block"; then return 0; fi
  return 2
}

# 0 = the Advisor's listener answered, 1 = nothing answered within the
# budget, 2 = there was no way to ask (no curl, no token to ask with), so
# nothing is known either way.
#
# The unit is Type=simple, so systemd reads it active as soon as it has forked
# the process, tens of milliseconds before the listener is up (#1120). The
# seal's own report used to count the unit up on that first read and print
# service=active for an Advisor that could not answer yet. Asked here instead,
# five times a second, for up to APERIRE_SEAL_LISTEN_SECONDS (20). Any HTTP
# answer is a listener, a refusal of this host's token included (advisor_status
# returns 2 for it): the question here is whether something is listening, and
# the token's standing is another check's.
wait_for_listener() { # $1 = addr, $2 = token file
  local secs="${APERIRE_SEAL_LISTEN_SECONDS:-20}" end rc
  [[ "$secs" =~ ^[0-9]{1,3}$ ]] && (( 10#$secs > 0 )) || secs=20
  LISTEN_SECONDS=$((10#$secs))
  # Time, not a count of tries: a listener that accepts and never replies
  # holds each probe for its whole timeout, so a count of probes would run
  # for many times the budget. Each probe is capped at 2 seconds here, so the
  # wait ends within the budget plus one probe.
  end=$(( SECONDS + LISTEN_SECONDS ))
  while :; do
    rc=0
    STATUS_PROBE_SECONDS=2 advisor_status "$1" "$2" >/dev/null || rc=$?
    case "$rc" in
      0|2) return 0 ;;
      1|5) return 2 ;;
    esac
    (( SECONDS < end )) || return 1
    sleep 0.2
  done
}

# What the service is, read back after a restart: active only when the unit is
# active AND its listener answers. Sets state and listener, and says plainly
# on stderr when the unit is up and nothing answers.
LISTEN_SECONDS=20
read_back_service() { # $1 = unit, $2 = addr, $3 = token file. Sets state, listener.
  local _
  state=inactive
  listener=none
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    if systemctl is-active --quiet "$1"; then state=active; break; fi
    sleep 1
  done
  [[ "$state" == active ]] || return 0
  local rc=0
  wait_for_listener "$2" "$3" || rc=$?
  case "$rc" in
    0) listener=answering ;;
    2) listener=unchecked ;;
    *) state=not-answering; listener=silent
       printf '%s: %s is running, but nothing answered on %s within %s s, so the Advisor is not up yet. Read its log: journalctl -u %s -n 30 --no-pager\n' \
         "$TAG" "$1" "$2" "$LISTEN_SECONDS" "$1" >&2 ;;
  esac
}

# ---- the config, and what it says ------------------------------------
config_credential_name() { # $1 = the config path
  [[ -f "$1" ]] || return 0
  sed -n 's/.*"credential_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$1" | head -1
}

config_enabled() { # $1 = the config path
  [[ -f "$1" ]] || return 1
  grep -q '"enabled"[[:space:]]*:[[:space:]]*true' "$1"
}

# The honest no-model state. The Advisor loads its compiled defaults and then
# this file over them, and `enabled: false` fails its validation with "no
# model is configured", which is the same sentence a MISSING file produces:
# both report `configured: false`. This one is written rather than the file
# removed because it leaves nothing a reader could show, no model name and
# no key hint for a key that is gone, while keeping the file the service,
# the installer and the doctor all expect to find, with its ownership as it
# was.
write_no_model_config() { # $1 = the config path
  local dir
  dir="$(dirname "$1")"
  [[ -d "$dir" ]] || return 1
  state_tool_usable || return 1
  # Owner and group from the directory itself, which is what the
  # `chown --reference` this replaced meant, read by the helper off the
  # descriptor it already holds rather than through a second name lookup.
  printf '{\n  "enabled": false\n}\n' \
    | python3 -I "$STATE_TOOL" plant "$1" dir dir 0640 --stdin
}

# ---- what this program just did, for the record to quote -------------
#
# Not a ledger entry. The ledger is hash-chained and the Advisor writes it
# from what it OBSERVED in its own configuration; a privileged shell script
# appending to it would be both a broken chain and the wrong author. This
# carries the one thing the observer cannot see for itself: who asked, and
# under whose arming. The Advisor reads it at its next start, quotes it on
# the entry it writes, and deletes it.
write_change_file() { # $1 = config dir, $2 = via, $3 = by, $4 = issuer, $5 = credential name
  local dir="$1"
  [[ -d "$dir" ]] || return 0
  state_tool_usable || return 0
  {
    printf '{\n'
    printf '  "at": "%s",\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf '  "via": "%s",\n' "$2"
    [[ -z "$3" ]] || printf '  "by": "%s",\n' "$3"
    [[ -z "$4" ]] || printf '  "issuer": "%s",\n' "$4"
    printf '  "credential_name": "%s"\n' "$5"
    printf '}\n'
  } | python3 -I "$STATE_TOOL" plant "$dir/$CHANGE_FILE_NAME" dir dir 0640 --stdin || return 0
}

# Who ran this. The account behind the sudo when there is one, because root
# is the account every operator arrives as and names none of them. Shaped
# before it is written: it lands in a file the audit record quotes.
reset_operator() {
  local who="${SUDO_USER:-}"
  [[ -n "$who" ]] || who="$(id -un 2>/dev/null || echo root)"
  [[ "$who" =~ ^[A-Za-z0-9._-]{1,64}$ ]] || who=root
  printf '%s\n' "$who"
}

# ---- the reset verb --------------------------------------------------
#
# The whole of an unseal, as one root action: the credential, the drop-in,
# any migrated unit line and the config, then a reload, a restart and the
# Advisor's own answer about what it now has. The two by-hand steps this
# replaces were documented in this file and enforced nowhere, and one of them
# forgotten is a service that cannot start at all (#446).
#
# The order is deliberate. Everything that could refuse is asked first, so a
# refusal leaves the host exactly as it was; then every removal, so no state
# survives into the restart; then the restart; then the read-back, which is
# what is printed. Nothing here is what was attempted.
if (( RESET )); then
  [[ -f "$UNIT" ]] \
    || die refused "there is no $UNIT on this host, so there is no Advisor here to unseal"

  # Asked here, before anything is read or removed (#703). This verb removes
  # the credential and the drop-in and then writes the no-model config, and
  # without the helper that last write is the one thing that cannot happen:
  # the host would come out with the key gone and a config still declaring a
  # model. The window check ahead of it would go quiet too, because it reads
  # this host's own token through the helper and a helper it cannot find
  # reads as "there was no way to ask".
  state_tool_usable \
    || die refused "this host has no usable state-file helper beside the sealer (looked at ${STATE_TOOL:-$STATE_TOOL_INSTALLED}${STATE_TOOL_WHY:+; $STATE_TOOL_WHY}, and python3 must be installed); nothing was changed. Run: curl -fsSL https://get.aperire.one | bash -s -- --update --force"

  # The other half of the same question (#708). This verb removes a key that
  # may be kept in either of two forms, and the library is the one place that
  # knows what the second form is called. Without it a reset on a host using
  # the plain method would leave a live key on disk and report it removed.
  method_lib_usable \
    || die refused "this host has no usable model-key method library beside the sealer (looked at ${METHOD_LIB:-$METHOD_LIB_INSTALLED}${METHOD_LIB_WHY:+; $METHOD_LIB_WHY}); nothing was changed. Run: curl -fsSL https://get.aperire.one | bash -s -- --update --force"

  exec_line="$(unit_exec_line)"
  CFG_PATH="$(model_config_path "$exec_line")" \
    || die refused "the ExecStart line of $UNIT names neither --model-config= nor --state=, so this program cannot tell which config the service reads"
  CFG_DIR="$(dirname "$CFG_PATH")"
  ADVISOR_ADDR="$(exec_flag "$exec_line" addr)"
  ADVISOR_ADDR="${ADVISOR_ADDR:-$DEFAULT_ADVISOR_ADDR}"
  STATE_DIR="$(exec_flag "$exec_line" state)"
  TOKEN_FILE=""
  if [[ -n "$STATE_DIR" ]]; then TOKEN_FILE="$STATE_DIR/approve.token"; fi

  # The layout, before the window check and before any removal. On this path
  # the first thing a refused layout breaks is the READ of this host's token,
  # and a read that cannot happen used to be indistinguishable from a service
  # holding no window: the check failed open and the key came off under an
  # operator who was mid-ceremony. Asked here, so a host in that state is
  # refused with nothing touched.
  if ! LAYOUT="$(state_layout_ok "$CFG_DIR")"; then
    die refused "$(layout_refusal "$CFG_DIR" "$LAYOUT")"
  fi


  # ---- the window ----------------------------------------------------
  #
  # A window is an operator part-way through something, reading this node
  # with raised ceilings, and taking the model out from under them mid-
  # ceremony is the wrong moment. So this asks first and refuses.
  #
  # It fails OPEN, on purpose, and says which it did. A window lives in the
  # running process and a restart ends it, so a service that does not answer
  # is a service holding no window, and a crash-looping Advisor, which is
  # exactly what this verb exists to repair, can never answer. A refusal that
  # could not be got is not a reason to refuse the repair.
  bg=0
  breakglass_open "$ADVISOR_ADDR" "$TOKEN_FILE" || bg=$?
  case "$bg" in
    0) die refused "a break-glass window is open on this Advisor, so the model stays where it is. Close the window in the tab, or let it lapse, and run this again." ;;
    1) window_note="no break-glass window was open" ;;
    # Answered, and would not say. This host is UP, so a window is possible
    # and "nobody is mid-ceremony" is not a claim that can be made. It is
    # also not the state this verb exists to repair, so it refuses and names
    # the file whose contents no longer match what the service holds.
    3) die refused "the Advisor answered and refused this host's own token ($TOKEN_FILE), so whether a break-glass window is open cannot be read. That token is what the dashboard reads too: fix it, or stop the service, and run this again." ;;
    # Said apart, because they are different facts and only one of them is
    # about the service. Nothing was sent in the first: this program has no
    # curl, or the unit names no state directory to find a token in.
    4) window_note="the window could not be checked: there was no way to ask, so nothing here is a claim about the service" ;;
    # REFUSES, never "the window could not be checked". The helper would not
    # read this host's own token, and the only reason it refuses a read is
    # that the file or the path to it is not a shape root may follow. That is
    # a host whose layout has to be repaired before anything is removed, and
    # carrying on here is what took an operator's key out from under an open
    # window (#703, review). The preflight above catches the ordinary case;
    # this is the belt for a layout that changed mid-run.
    5) die refused "this host's own token ($TOKEN_FILE) could not be read, so whether a break-glass window is open cannot be known, and nothing was removed. ${STATE_READ_ERROR:-} Repair the layout with: curl -fsSL https://get.aperire.one | bash -s -- --update --force" ;;
    *) window_note="the window could not be checked: the Advisor did not answer, and a service that is not running holds no window" ;;
  esac

  # ---- what is here --------------------------------------------------
  #
  # Three places name a credential and they can disagree: the config the
  # service reads, the drop-in this program writes, and the main unit on a
  # host sealed before the drop-in existed. All three are read, because the
  # one that is missed is the one that keeps a key on the host or a directive
  # in the unit with nothing behind it.
  #
  # Both spellings of the directive are read (#708): a host on the plain
  # method declares its key with LoadCredential=, and the name has to come
  # off that line too or a reset on 22.04 finds nothing to remove and leaves
  # the key on the host. The `.plain` suffix is stripped from the name the
  # line carries, because the NAME is the credential id and the suffix
  # belongs to the path.
  mapfile -t cred_names < <(
    {
      config_credential_name "$CFG_PATH"
      [[ ! -f "$DROPIN" ]] || sed -n "s#^LoadCredential\(Encrypted\)\?=\([^:]*\):$CRED_DIR/.*#\2#p" "$DROPIN"
      sed -n "s#^LoadCredential\(Encrypted\)\?=\([^:]*\):$CRED_DIR/.*#\2#p" "$UNIT"
    } | awk 'NF && !seen[$0]++'
  )

  sealed=0
  if [[ -f "$DROPIN" ]]; then sealed=1; fi
  if grep -q -e "$UNIT_CRED_RE" "$UNIT"; then sealed=1; fi
  if config_enabled "$CFG_PATH"; then sealed=1; fi
  for n in ${cred_names[@]+"${cred_names[@]}"}; do
    # Both forms, because a host can carry either and an in-place OS upgrade
    # can leave one of each.
    if [[ -e "$CRED_DIR/$n" || -e "$CRED_DIR/$n$APERIRE_KEY_PLAIN_SUFFIX" ]]; then sealed=1; fi
  done

  # Nothing to undo is not a failure and not a restart. A reset run twice, or
  # run on a host that never had a key, says what it found and stops: the
  # Advisor is already in the state this verb produces, and bouncing a
  # healthy service to prove it would be the more expensive answer.
  if (( ! sealed )); then
    say unsealed "nothing to reset for $ADVISORD_UNIT: no sealed credential, no drop-in, and no model in $CFG_PATH"
    printf 'reset=none\n'
    printf 'already=unsealed\n'
    printf 'unit=%s\n' "$ADVISORD_UNIT"
    printf 'config=%s\n' "$CFG_PATH"
    exit 0
  fi

  # ---- the removals --------------------------------------------------
  removed=()
  removed_files=()
  for n in ${cred_names[@]+"${cred_names[@]}"}; do
    # The same rule the payload's credential_name must pass. A name that
    # cannot pass it was not written by this program, and a removal driven by
    # it would be this program deleting a path somebody else chose.
    if [[ ! "$n" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] || [[ "$n" == *".."* ]]; then
      say reset "a credential name in $CFG_PATH is not a bare name; left alone"
      continue
    fi
    # Both forms of the same credential (#708). A host that changed OS
    # version, or that was restored onto a different one, can carry a sealed
    # blob and a plaintext key under the same name, and a reset that took
    # only the form this host would write today would leave the other one
    # sitting there. The plaintext one is a live key anywhere, so leaving it
    # is the worse half.
    n_removed=0
    for f in "$CRED_DIR/$n" "$CRED_DIR/$n$APERIRE_KEY_PLAIN_SUFFIX"; do
      if [[ -e "$f" ]]; then
        rm -f "$f"
        removed_files+=("${f#"$CRED_DIR/"}")
        n_removed=1
      fi
    done
    # The NAME once, whichever forms of it came off, because this list is what
    # the change file records as the credential and a credential is its name.
    (( n_removed )) && removed+=("$n")
  done

  # And every plaintext key left in the store under any other name, including
  # the quarantines nothing ever declares (#712 review M1). An unseal that
  # left a working key on the host would be the wrong half of the job done.
  sweep_stale_plain_keys ""
  [[ ${#SWEPT[@]} -eq 0 ]] || removed_files+=("${SWEPT[@]}")

  dropin_state=absent
  if [[ -f "$DROPIN" ]]; then rm -f "$DROPIN"; dropin_state=removed; fi
  # Only when this program leaves it empty. Another drop-in on the same unit
  # is somebody else's decision about this service.
  rmdir "$DROPIN_DIR" 2>/dev/null || true

  migrated=no
  if strip_unit_credential_lines; then migrated=yes; fi

  # Reached only when the layout passed the preflight above and then changed,
  # or when the helper itself went missing mid-run. The old sentence here said
  # the state directory "is not on this host", which is the one thing it is
  # not: write_no_model_config returns non-zero for a missing directory, a
  # missing helper OR a refused layout, and on this path the host has just
  # lost its credential, so a wrong cause sends the operator to the wrong fix.
  write_no_model_config "$CFG_PATH" \
    || die failed "the credential and the drop-in are gone, but $CFG_PATH could not be rewritten, so the config still names a credential this host no longer has. Check that $CFG_DIR exists and that the install tree above it is writable only by root and its owner (curl -fsSL https://get.aperire.one | bash -s -- --update --force), then run --reset again"

  write_change_file "$CFG_DIR" reset "$(reset_operator)" "" "${removed[0]:-${cred_names[0]:-none}}"

  # ---- and back up ---------------------------------------------------
  systemctl daemon-reload
  # reset_and_restart_advisord resets before it restarts, and not
  # conditional on anything. The host this verb exists for has been
  # crash-looping: past StartLimitBurst the unit is in failed state, a bare
  # `systemctl restart` answers "start request repeated too quickly" and
  # starts nothing, and a reset that did all the removals and then reported
  # the service down would be the same defect one step along.
  #
  # Reported, not fatal. Under `set -e` a refused restart would end this run
  # right here, printing no status lines at all, and an operator who had just
  # asked for a reset would be looking at nothing. Everything below still
  # runs, reads back what is true, and ends non-zero on it.
  if ! reset_and_restart_advisord "$ADVISORD_UNIT"; then
    say reset "systemctl refused to restart $ADVISORD_UNIT; the removals are done and the service is not up"
  fi

  read_back_service "$ADVISORD_UNIT" "$ADVISOR_ADDR" "$TOKEN_FILE"

  # What it REPORTS, which is the only claim worth printing. `unchecked` is
  # its own word: a host with no curl, or a service that is up and not yet
  # answering, must not read as a confirmed no-model state.
  model_state=unchecked
  if [[ "$state" == active ]]; then
    for _ in 1 2 3; do
      rc=0
      model_reports_none "$ADVISOR_ADDR" "$TOKEN_FILE" || rc=$?
      case "$rc" in
        0) model_state=none; break ;;
        1) model_state=configured; break ;;
        *) sleep 1 ;;
      esac
    done
  fi

  say reset "credential ${removed[*]:-none} (files ${removed_files[*]:-none}) for $ADVISORD_UNIT, drop-in $dropin_state, unit line migrated $migrated, config $CFG_PATH, service $state, model $model_state, $window_note"
  printf 'reset=%s\n' "${removed[*]:-none}"
  printf 'swept=%s\n' "${SWEPT[*]:-none}"
  printf 'unit=%s\n' "$ADVISORD_UNIT"
  printf 'config=%s\n' "$CFG_PATH"
  printf 'dropin=%s\n' "$dropin_state"
  printf 'migrated=%s\n' "$migrated"
  printf 'service=%s\n' "$state"
  printf 'listener=%s\n' "$listener"
  printf 'model=%s\n' "$model_state"
  [[ "$state" == active ]] || exit 1
  [[ "$model_state" != configured ]] || exit 1
  exit 0
fi

# ---- which payload is this -----------------------------------------
#
# One line decides, and it is read before anything else is looked at. Exactly
# `arm` is a fleet arm token; anything else is the base_url of the five-line
# seal, and is handed to that path below unchanged.
IFS= read -r LINE1 || die refused "the payload was empty"

if [[ "$LINE1" == arm ]]; then
  # ---- the arm verb ------------------------------------------------
  #
  # Two more lines, then this program has everything: a token root on the
  # aggregator signed, and the signature. It opens a window and does nothing
  # else. It never reaches the seal below, never touches a credential and
  # never sees a key.
  IFS= read -r ARM_TOKEN_B64 || die refused "the arm payload ended before the token"
  IFS= read -r ARM_SIG_B64   || die refused "the arm payload ended before the signature"

  # The trust root, checked before a byte is decoded or written. Absent is its
  # own sentence, not "the signature is wrong": one is a host nobody has
  # joined to a fleet, the other is a token that does not belong here, and
  # they send an operator to different places.
  #
  # The remedy leads with what the aggregator's own page can get to (#720): a
  # node takes this key from its pairing, and its Advisor install places it.
  # The root line stays last, for a node paired before that was true.
  [[ -f "$FLEET_ARM_PUB" ]] \
    || die refused "this node trusts no fleet arm key (no $FLEET_ARM_PUB). A node takes it from its pairing: pair it again from the aggregator's Add a node, or, if it was paired before its Advisor went on and has no model yet, run the Advisor install command the page prints for it again. By hand, as root on this node: curl -fsSL https://get.aperire.one | bash -s -- --run model-key-sealer --trust-arm-key <key>"
  # And it has to belong to the account running this, which on any real host
  # is root: whoever can write this file can arm this host whenever they like.
  # The dashboard account cannot write /etc/aperire today, so this is a second
  # lock on a door already shut, and it costs one stat.
  [[ -O "$FLEET_ARM_PUB" ]] \
    || die refused "$FLEET_ARM_PUB is not owned by the account this sealer runs as (root, on a real host), so it is not a trust root"
  arm_pub_mode="$(stat -c %a "$FLEET_ARM_PUB" 2>/dev/null || echo 777)"
  if (( 8#$arm_pub_mode & 8#022 )); then
    die refused "$FLEET_ARM_PUB is mode $arm_pub_mode; a fleet arm key that group or others may write arms this host on their say-so"
  fi

  # And this host's own name, before a token is looked at, because without it
  # no token can be judged at all. Absent is a refusal rather than a skipped
  # check: skipping it is exactly the hole (#184). The host is not stranded
  # by it, because its own operator can still arm it with --arm.
  [[ -f "$NODE_KEY_FILE" ]] \
    || die refused "this host has not stamped its own node key (no $NODE_KEY_FILE), so it cannot tell whether an arm token is addressed to it. Stamp it: curl -fsSL https://get.aperire.one | bash -s -- --refresh-node-key"
  # Same two stats as the trust root above, for the same reason: whoever may
  # write this file re-addresses every token this host is ever sent.
  [[ -O "$NODE_KEY_FILE" ]] \
    || die refused "$NODE_KEY_FILE is not owned by the account this sealer runs as (root, on a real host), so it is not this host's own answer about itself"
  node_key_mode="$(stat -c %a "$NODE_KEY_FILE" 2>/dev/null || echo 777)"
  if (( 8#$node_key_mode & 8#022 )); then
    die refused "$NODE_KEY_FILE is mode $node_key_mode; a node key that group or others may write lets them re-address every arm token this host is sent"
  fi
  THIS_NODE_KEY="$(tr -d '[:space:]' < "$NODE_KEY_FILE")"
  [[ "$THIS_NODE_KEY" =~ $NODE_KEY_RE ]] \
    || die refused "$NODE_KEY_FILE does not hold a node key. Stamp it again: curl -fsSL https://get.aperire.one | bash -s -- --refresh-node-key"

  umask 077
  TMP_ARM_DIR="$(mktemp -d)"
  printf '%s' "$ARM_TOKEN_B64" | base64 -d > "$TMP_ARM_DIR/token" 2>/dev/null \
    || die refused "the arm token is not base64"
  printf '%s' "$ARM_SIG_B64" | base64 -d > "$TMP_ARM_DIR/sig" 2>/dev/null \
    || die refused "the arm token's signature is not base64"

  # Verified before one field is read out of it, so nothing below is acting on
  # text this host has not authenticated. openssl announces a good signature
  # on stdout, and stdout here is the socket the dashboard parses as
  # `key=value` lines, so every byte of the tool's own output is discarded.
  openssl pkeyutl -verify -pubin -inkey "$FLEET_ARM_PUB" -rawin \
      -in "$TMP_ARM_DIR/token" -sigfile "$TMP_ARM_DIR/sig" >/dev/null 2>&1 \
    || die refused "the arm token is not signed by the fleet arm key this node trusts"

  # Plain key=value lines, read by name, and read only after the signature
  # held: `target` decides whether this host acts, so it must be a field this
  # host has authenticated rather than one the courier could set.
  #
  # A repeated key takes the LAST value here and the FIRST in the dashboard's
  # parser, which cannot disagree in practice: both read the same signed
  # bytes, and a token carrying two `target=` lines was minted by the
  # aggregator's own root, which writes one.
  ARM_V=""; ARM_ISSUER=""; ARM_TARGET=""; ARM_NONCE=""; ARM_ISSUED=""
  while IFS='=' read -r arm_k arm_v; do
    case "$arm_k" in
      v)         ARM_V="$arm_v" ;;
      issuer)    ARM_ISSUER="$arm_v" ;;
      target)    ARM_TARGET="$arm_v" ;;
      nonce)     ARM_NONCE="$arm_v" ;;
      issued_at) ARM_ISSUED="$arm_v" ;;
    esac
  done < "$TMP_ARM_DIR/token"

  [[ "$ARM_V" == 1 ]] \
    || die refused "arm token version '$ARM_V' is not 1, which is the only version this sealer speaks"

  # ---- who the token is for ----------------------------------------
  #
  # Before the nonce is consulted or spent, so a token that was never for
  # this host costs it nothing it has to remember. `target` is inside the
  # signed bytes, so nobody between the aggregator and here can re-address
  # one: the signature above and this comparison are one property in two
  # halves, and neither is worth much alone.
  #
  # A token with no target is refused as well. An unaddressed token is one
  # that opens a window on whichever node receives it, which is the same
  # thing as no address at all.
  [[ -n "$ARM_TARGET" ]] \
    || die refused "the arm token names no target; a token is minted for one host, and this one honours no token that names none"
  # Shaped before it is printed, because the mismatch below says what it saw.
  [[ "$ARM_TARGET" =~ $NODE_KEY_RE ]] \
    || die refused "the arm token's target is not shaped like a node key"
  [[ "$ARM_TARGET" == "$THIS_NODE_KEY" ]] \
    || die refused "that arm token is addressed to another node: it names $ARM_TARGET and this host is $THIS_NODE_KEY"
  # Shapes, because the issuer is printed back on the same stream the
  # dashboard parses and the nonce becomes a line in a file this reads later.
  [[ "$ARM_ISSUER" =~ ^[A-Za-z0-9._-]{1,64}$ ]] \
    || die refused "the arm token names no usable issuer"
  [[ "$ARM_NONCE" =~ ^[0-9a-fA-F]{16,128}$ ]] \
    || die refused "the arm token's nonce is not hex"
  [[ "$ARM_ISSUED" =~ ^[0-9]{1,12}$ ]] \
    || die refused "the arm token's issued_at is not a timestamp"

  arm_now="$(date +%s)"
  arm_drift=$(( arm_now - ARM_ISSUED ))
  # Either way. A token from the future is a clock that moved or a token that
  # was minted to outlive its window, and neither is a token to act on.
  if (( arm_drift < 0 )); then arm_drift=$(( -arm_drift )); fi
  if (( arm_drift > ARM_TOKEN_SKEW_SEC )); then
    die refused "arm token is stale (${arm_drift}s from this host's clock, limit ${ARM_TOKEN_SKEW_SEC}s)"
  fi

  # One `nonce issued_at` per line. Matched on the nonce alone, so a line
  # from before the timestamp was recorded still counts.
  if [[ -f "$FLEET_ARM_SEEN" ]] && grep -qE "^${ARM_NONCE}( |$)" "$FLEET_ARM_SEEN"; then
    die refused "arm token already used"
  fi

  # The nonce is written BEFORE the marker, on purpose. Interrupted between
  # the two, this host has a spent nonce and no window, which fails closed; the
  # other order would leave a window and a token that could open another.
  #
  # No lock. The socket in front of this accepts one connection at a time, and
  # two operators racing the same token would only re-open a window that is
  # already open, which is nothing gained.
  # Made only when it is absent, and with its mode stated: the umask above is
  # 077 for the files written here, and a /etc/aperire created 0700 would be
  # a directory the dashboard account cannot traverse to the env file systemd
  # hands it at start.
  arm_seen_dir="$(dirname "$FLEET_ARM_SEEN")"
  [[ -d "$arm_seen_dir" ]] || { mkdir -p "$arm_seen_dir"; chmod 0755 "$arm_seen_dir"; }
  printf '%s %s\n' "$ARM_NONCE" "$ARM_ISSUED" >> "$FLEET_ARM_SEEN"
  chown root:root "$FLEET_ARM_SEEN" 2>/dev/null || true
  chmod 0600 "$FLEET_ARM_SEEN"
  # Bounded by age, in the units of what it protects: a token older than the
  # skew is refused as stale before this record is consulted, so a nonce
  # older than twice the skew can never be re-accepted and need not be kept.
  # A count would be a replay window in the wrong units (#182). Lines with no
  # timestamp are from before it was recorded and are dropped with the rest.
  # Written to the side and moved, never redirected into the file being read,
  # and the mode re-stated after the move.
  awk -v cutoff=$(( arm_now - 2 * ARM_TOKEN_SKEW_SEC )) \
    '$2 ~ /^[0-9]+$/ && $2 + 0 >= cutoff' "$FLEET_ARM_SEEN" > "$TMP_ARM_DIR/seen"
  mv -f "$TMP_ARM_DIR/seen" "$FLEET_ARM_SEEN"
  chown root:root "$FLEET_ARM_SEEN" 2>/dev/null || true
  chmod 0600 "$FLEET_ARM_SEEN"

  # Exactly what `install-model-key-sealer.sh --arm` writes, so there is one
  # kind of window on this host and one thing that spends it.
  arm_file_dir="$(dirname "$ARM_FILE")"
  [[ -d "$arm_file_dir" ]] || { mkdir -p "$arm_file_dir"; chmod 0755 "$arm_file_dir"; }
  # Who opened it, written BEFORE the marker and removed wherever the marker
  # is. The seal one step later quotes this in the fact it leaves for the
  # audit record, so a key arriving on a node can say which aggregator moved
  # it (#447). Absence reads as an arming opened on this host, which is what
  # `--arm` is, so a lost or cleared file understates rather than invents.
  printf '%s\n' "$ARM_ISSUER" > "$ARM_ISSUER_FILE"
  chown root:root "$ARM_ISSUER_FILE" 2>/dev/null || true
  chmod 0600 "$ARM_ISSUER_FILE"
  install -o root -g root -m 0600 /dev/null "$ARM_FILE"

  say armed "fleet arm token from issuer $ARM_ISSUER, window ${ARM_WINDOW_SEC}s"
  printf 'armed=1\n'
  printf 'window_s=%s\n' "$ARM_WINDOW_SEC"
  printf 'issuer=%s\n' "$ARM_ISSUER"
  exit 0
fi

# ---- the payload ---------------------------------------------------
#
# The WHOLE request, before anything is decided about it. Read positionally:
# there is no parser, no names to spoof and no line that can be made to mean a
# different field by what is in it. The first line is already in hand: it was
# read above to tell a seal from an arm, and it is a base_url precisely
# because it was not the word `arm`.
#
# Read here, above the window, because the caller is a socket and a program
# that decides between two reads breaks the connection under whoever is still
# writing (#454). The window check below refused after line one, the dashboard
# was still writing lines two to five, and the refusal this program had
# already put on the wire went with the broken write: the operator was told
# the sealer could not be reached, on a host where it had answered. Nothing is
# judged and nothing is written until the request is in hand.
#
# The bound on a caller that writes one line and then stalls is the unit's
# own RuntimeMaxSec=180 (install-model-key-sealer.sh), which is the bound it
# always was: this program has never had a reader that could not be made to
# wait, and the socket in front of it is 0600 to one account.
BASE_URL="$LINE1"
IFS= read -r SHAPE      || die refused "the payload ended before shape"
IFS= read -r MODEL      || die refused "the payload ended before model"
IFS= read -r CRED_NAME  || die refused "the payload ended before credential_name"
IFS= read -r KEY        || die refused "the payload ended before the key"

# ---- the window ----------------------------------------------------
#
# Absent and expired are the same refusal and two different sentences. They
# have different causes and different fixes, and a browser that says "not
# armed" to an operator who armed it twelve minutes ago sends them looking in
# the wrong place.
if [[ ! -f "$ARM_FILE" ]]; then
  die unarmed "no arming marker at $ARM_FILE, so nothing may be sealed from the dashboard. Arm this host first: curl -fsSL https://get.aperire.one | bash -s -- --run model-key-sealer --arm (the Advisor install command does it too)."
fi
# The same two checks the arm verb makes on its trust root, because this
# marker IS the trust root of a seal: a file the dashboard account could have
# created is a window the dashboard opened for itself. Not reachable while
# /etc/aperire is 0755 root, but that is a directory mode, and this project
# has met the permissions accident twice (#171, #113). Two stats make the
# property the program's own (#181).
[[ -O "$ARM_FILE" ]] \
  || die unarmed "$ARM_FILE is not owned by the account this sealer runs as (root, on a real host), so it is not an arming"
arm_file_mode="$(stat -c %a "$ARM_FILE" 2>/dev/null || echo 777)"
if (( 8#$arm_file_mode & 8#022 )); then
  die unarmed "$ARM_FILE is mode $arm_file_mode; a marker that group or others may write is not an arming"
fi
armed_at="$(stat -c %Y "$ARM_FILE" 2>/dev/null || echo 0)"
now="$(date +%s)"
age=$(( now - armed_at ))
# A marker with a modification time in the future is not a fresh arming: it is
# a clock that moved, or a file somebody touched. Treated as expired, because
# the safe reading of "I cannot tell how old this is" is "too old".
if (( age < 0 || age > ARM_WINDOW_SEC )); then
  rm -f "$ARM_FILE" "$ARM_ISSUER_FILE"
  die expired "the arming window closed ${age}s after it opened (limit ${ARM_WINDOW_SEC}s). The marker has been removed. Arm this host again: curl -fsSL https://get.aperire.one | bash -s -- --run model-key-sealer --arm (the Advisor install command does it too)."
fi

# ---- what the payload says -----------------------------------------
#
# The request is in hand (above the window check, and for the reason given
# there). What follows is what it may hold, which is judged only now that
# there is a window to spend on it.
#
# Whitespace around a pasted key is the ordinary mistake, and systemd-creds
# would seal it happily. It then fails much later as an opaque HTTP header
# error, which is a bad way to find out.
KEY="${KEY//[$'\t\r\n ']/}"

[[ -n "$KEY" ]] || die refused "the key is empty"
[[ "$KEY" =~ ^[[:print:]]+$ ]] \
  || die refused "the key holds a character that cannot go in an HTTP header; retype it rather than pasting"

case "$SHAPE" in
  openai|anthropic) ;;
  *) die refused "shape must be openai or anthropic" ;;
esac

# https, or loopback for a local runner. The same rule the Advisor's own config
# validation applies, stated here as well because this is where the value stops
# being a request and starts being host configuration.
# Anchored at both ends, and nothing that is whitespace, a quote or a
# backslash: this value is written into JSON below, and the dashboard's
# matching rule (SEAL_FIELD_RULES in model-seal.ts) is the same one. A prefix
# glob here once let a base_url carry a second line (#179); the frame above
# holds only because no field may hold a line break, and a line break is
# whitespace.
[[ "$BASE_URL" =~ $BASE_URL_HTTPS_RE || "$BASE_URL" =~ $BASE_URL_LOOPBACK_RE ]] \
  || die refused "base_url must be https, or loopback for a local runner, with no spaces, quotes or backslashes"

# A bare name, because it becomes a file name under $CRED_DIR and a systemd
# credential name in the unit. Anything with a slash, a dot-dot or a space is
# a path or a second directive, not a name.
[[ "$CRED_NAME" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ && "$CRED_NAME" != *".."* ]] \
  || die refused "credential_name must be a bare name of letters, digits, dot, dash or underscore"

# And not the one suffix this store spells its other form with (#712 review).
# A name ending in `.plain` puts a SEALED blob at exactly the path a plaintext
# key lives at: the sweep above would read that ciphertext as a key to remove,
# and the installer's re-wire would read it as a key to load verbatim. The
# suffix comes from the method library, so there is one declaration of it.
[[ "$CRED_NAME" != *"$APERIRE_KEY_PLAIN_SUFFIX" ]] \
  || die refused "credential_name may not end in $APERIRE_KEY_PLAIN_SUFFIX; that suffix is how this store tells a key kept in the clear from a sealed blob"

[[ -n "$MODEL" && "$MODEL" =~ ^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$ ]] \
  || die refused "model must be a plain model identifier"

# ---- the unit this is for ------------------------------------------
#
# Sealing for a service that is not here produces a credential nothing loads
# and a success nobody can act on. Checked before anything is written, so a
# refusal leaves the host exactly as it was.
[[ -f "$UNIT" ]] \
  || die refused "there is no $UNIT on this host, so a sealed key would have no service to load it"

# Where that service reads its model config from. The installer writes
# `--state=<dir>` on the ExecStart line and the service derives model.json
# from it; an explicit `--model-config=<file>` wins if one is there. Both are
# read from the unit rather than guessed from a path convention, and found
# before the seal, so a unit this cannot read leaves the host as it was.
exec_line="$(unit_exec_line)"
CFG_PATH="$(model_config_path "$exec_line")" \
  || die refused "the ExecStart line of $UNIT names no --state= directory, so there is nowhere to write the model config"
CFG_DIR="$(dirname "$CFG_PATH")"
[[ -d "$CFG_DIR" ]] \
  || die refused "the Advisor's state directory $CFG_DIR is not on this host, so the model config has nowhere to go"

# Asked here, with nothing written yet, because the config is planted LAST:
# the credential and the drop-in land before it, so a helper discovered
# missing at the plant would leave this host half sealed (#703). The remedy
# names the installer, which is the one place that puts a root-owned copy of
# the helper beside this program.
state_tool_usable \
  || die refused "this host has no usable state-file helper beside the sealer (looked at ${STATE_TOOL:-$STATE_TOOL_INSTALLED}${STATE_TOOL_WHY:+; $STATE_TOOL_WHY}, and python3 must be installed); run: curl -fsSL https://get.aperire.one | bash -s -- --update --force"

# And which of the two ways this host keeps a key (#708), asked in the same
# breath and for the same reason: the library decides the path the key lands
# at and the directive that loads it, and a host without it cannot be sealed
# correctly either way.
method_lib_usable \
  || die refused "this host has no usable model-key method library beside the sealer (looked at ${METHOD_LIB:-$METHOD_LIB_INSTALLED}${METHOD_LIB_WHY:+; $METHOD_LIB_WHY}); run: curl -fsSL https://get.aperire.one | bash -s -- --update --force"

# And the layout, which is the other half of "can this program write the
# config". The helper being present says nothing about whether the walk to
# $CFG_DIR will be allowed, and the config is planted LAST: a layout
# discovered at that write leaves this host with the credential and the
# drop-in in place and no config, which "re-run this seal" cannot mend
# because the re-run fails at the same step (#703, review).
if ! LAYOUT="$(state_layout_ok "$CFG_DIR")"; then
  die refused "$(layout_refusal "$CFG_DIR" "$LAYOUT")"
fi

# ---- which method, and where the key lands --------------------------
#
# Measured, never assumed (#708). On systemd 250 or newer with systemd-creds
# on the PATH the key is encrypted to this machine; on anything older it is
# kept as a root-only file. The credential NAME is the same either way, so the
# Advisor reads $CREDENTIALS_DIRECTORY/<name> and knows nothing about which of
# the two put it there. Only the path and the directive differ.
METHOD="$(aperire_key_method)"
CRED_PATH="$(aperire_key_blob_path "$CRED_DIR" "$CRED_NAME" "$METHOD")"
# The form this host is NOT writing, for the same name. Removed after a
# successful seal below.
OTHER_METHOD=sealed
[[ "$METHOD" == sealed ]] && OTHER_METHOD=plain
OTHER_PATH="$(aperire_key_blob_path "$CRED_DIR" "$CRED_NAME" "$OTHER_METHOD")"

# ---- seal ----------------------------------------------------------
umask 077
# Before `mkdir -p`, which follows a link at that name and reports success
# about somebody else's directory.
[[ ! -L "$CRED_DIR" ]] \
  || die refused "$CRED_DIR is a symbolic link, and a key is never written through one; nothing was written"
mkdir -p "$CRED_DIR"
chmod 0700 "$CRED_DIR"

# Asked AFTER the directory is made and BEFORE a key is written into it
# (#708). On the plain method what lands here is a usable key rather than a
# blob that is inert anywhere else, so the directory holding it has to be
# root's alone, and the check has to be of the directory this program is about
# to write into rather than of the name it used to reach it. `mkdir -p`
# follows a symlink at that name and `chmod` does not change an owner, so
# neither line above is evidence of anything; this is.
# Ownership is asked as `-O`, "owned by the account running this program",
# rather than as uid 0 spelled out. On a host the two are the same thing,
# because this program refuses to run as anything but root, and the question
# that actually matters is whether the directory belongs to the privileged
# account writing into it. Asked this way it is also a question a test suite
# can put a real answer to, which uid 0 is not.
creds_dir_refusal() {
  local st mode
  [[ ! -L "$CRED_DIR" ]] \
    || { printf 'is a symbolic link, and a key is never written through one'; return 0; }
  [[ -d "$CRED_DIR" ]] \
    || { printf 'is not a directory'; return 0; }
  [[ -O "$CRED_DIR" ]] \
    || { printf 'is not owned by the account this program runs as'; return 0; }
  st="$(stat -c '%a' "$CRED_DIR" 2>/dev/null)" \
    || { printf 'could not be read'; return 0; }
  mode="$st"
  (( 8#$mode & 8#077 )) \
    && { printf 'is mode %s, and anything but 0700 lets another account reach what is in it' "$mode"; return 0; }
  return 1
}
if CRED_DIR_WHY="$(creds_dir_refusal)"; then
  die refused "$CRED_DIR $CRED_DIR_WHY; nothing was written. Repair it with: sudo chown root:root $CRED_DIR && sudo chmod 0700 $CRED_DIR"
fi

# Written to a temporary file in the same directory and moved into place, so a
# failure part-way through never leaves half a credential where a whole one
# was. printf, not echo: the key is data and echo interprets some of it.
#
# Only the sealed path needs a temporary of its own, because systemd-creds is
# handed a NAME to write to. The plain path is planted through the state
# helper, which does its own create, own, chmod and rename on a descriptor it
# holds on the directory: what lands there is a key in the clear, and a name
# opened twice is a window for a link to stand in the second time.
if [[ "$METHOD" == sealed ]]; then
  TMP_CRED="$(mktemp "$CRED_DIR/.seal.XXXXXXXX")"
  if ! printf '%s' "$KEY" | systemd-creds encrypt --name="$CRED_NAME" - "$TMP_CRED" 2>/dev/null; then
    # Deliberately not passing the tool's own stderr through. It is usually
    # harmless, and "usually" is not a property to rely on for a process that
    # was just handed a secret on stdin.
    die refused "systemd-creds could not seal the key on this host"
  fi
  chmod 0600 "$TMP_CRED"
  chown root:root "$TMP_CRED" 2>/dev/null || true
  mv -f "$TMP_CRED" "$CRED_PATH"
  # Moved, so there is nothing left for the exit handler to remove.
  TMP_CRED=""
else
  # The fallback. No encryption step, because there is nothing on this host to
  # encrypt with: systemd-creds holds the host key and it is not here. The
  # protection is the file mode, the directory above it, and the fact that
  # nothing between the create and the name is ever resolved by name. The key
  # crosses on a pipe, never as an argument: /proc/<pid>/cmdline is world
  # readable.
  if ! printf '%s' "$KEY" | python3 -I "$STATE_TOOL" plant "$CRED_PATH" dir dir 0600 --stdin; then
    die refused "the key could not be written to $CRED_DIR on this host"
  fi
fi
# The hint the Model row shows afterwards: first six and last four, the
# shape every provider console uses to tell two keys apart. Only for a key
# long enough that ten characters give nothing away, and only when the key is
# made of the characters provider keys are made of, so what lands in the JSON
# below needs no escaping. It is the one thing derived from the key that
# outlives it, and it is written into the config, never the credential.
KEY_HINT=""
if (( ${#KEY} >= 24 )) && [[ "$KEY" =~ ^[A-Za-z0-9._-]+$ ]]; then
  KEY_HINT="${KEY:0:6}…${KEY: -4}"
fi
# The one thing that proves the plain path wrote what it was given, computed
# while the key is still in hand and compared with the file below. The hash is
# not the key and does not outlive this run.
KEY_SUM=""
if [[ "$METHOD" == plain ]] && command -v sha256sum >/dev/null 2>&1; then
  KEY_SUM="$(printf '%s' "$KEY" | sha256sum | awk '{print $1}')"
fi
KEY=""
unset KEY

# Read back before the directive that loads it is ever written (#541). This
# host just wrote the file itself, so the read is expected to succeed every
# time; it is here for the run where it does not, which a silent success would
# turn into a drop-in the unit can never start with. Nothing about the
# plaintext is printed either way: the sealed check discards it to /dev/null,
# and the plain check compares a hash it computed before the key was dropped.
if [[ "$METHOD" == sealed ]]; then
  if ! systemd-creds decrypt --name="$CRED_NAME" "$CRED_PATH" /dev/null 2>/dev/null; then
    rm -f "$CRED_PATH"
    die refused "the key was sealed but would not read back on this host; nothing was wired in"
  fi
else
  # Read back through the helper, not with a redirect: the point of the read
  # is to prove the bytes at that NAME are the ones just planted, and a
  # redirect follows whatever is standing there.
  BACK_SUM=""
  [[ -n "$KEY_SUM" ]] && BACK_SUM="$(python3 -I "$STATE_TOOL" read "$CRED_PATH" 2>/dev/null | sha256sum | awk '{print $1}')"
  if [[ -n "$KEY_SUM" && "$BACK_SUM" != "$KEY_SUM" ]]; then
    rm -f "$CRED_PATH"
    die refused "the key was written but did not read back the same on this host; nothing was wired in"
  fi
  if [[ ! -s "$CRED_PATH" ]]; then
    rm -f "$CRED_PATH"
    die refused "the key was written and the file is empty; nothing was wired in"
  fi
fi
KEY_SUM=""
unset KEY_SUM

# The other form of the same credential, gone. A sealed blob left behind is
# inert on any other machine; a plaintext key left behind is a live key, and
# the two have to be removed with the same hand or an in-place OS upgrade
# leaves one of them lying about (#708).
rm -f "$OTHER_PATH"

# And every OTHER plaintext key in the store, whatever name it is under
# (#712 review M1). This is the line that closes a provider switch: the key
# just written is the only one in the clear this host keeps.
sweep_stale_plain_keys "$CRED_NAME"

# ---- who opened the window this is being sealed under ---------------
#
# Read BEFORE the marker is spent, because the two are removed together. The
# same two checks the marker itself gets: a file the dashboard account could
# have written is a claim about provenance the dashboard made about itself,
# and this one ends up quoted in an audit record. Anything that does not pass
# is treated as absent, which reads as an arming opened on this host.
# And one check the marker itself does not need: the two are written
# together, one line apart, so an issuer that is not the same age as the
# marker beside it belongs to an EARLIER window. There is a third writer of
# this marker (aperire-fleet-arm.sh arms this host locally), and a window
# that lapsed with no seal attempted leaves its issuer behind, so without
# this a local arming could be recorded as a push from an aggregator that
# armed nothing. A false provenance claim in a hash-chained record is worse
# than no claim at all.
SEAL_ISSUER=""
if [[ -f "$ARM_ISSUER_FILE" && -O "$ARM_ISSUER_FILE" ]]; then
  issuer_mode="$(stat -c %a "$ARM_ISSUER_FILE" 2>/dev/null || echo 777)"
  issuer_at="$(stat -c %Y "$ARM_ISSUER_FILE" 2>/dev/null || echo 0)"
  issuer_age=$(( armed_at - issuer_at ))
  (( issuer_age >= 0 )) || issuer_age=$(( -issuer_age ))
  if (( ! (8#$issuer_mode & 8#022) )) && (( issuer_age <= ARM_ISSUER_PAIR_SEC )); then
    SEAL_ISSUER="$(tr -d '[:space:]' < "$ARM_ISSUER_FILE")"
    [[ "$SEAL_ISSUER" =~ ^[A-Za-z0-9._-]{1,64}$ ]] || SEAL_ISSUER=""
  fi
fi

# ---- spend the arming ----------------------------------------------
#
# Here, and not at the end. Everything below is wiring that can be re-run
# safely; the seal above cannot, and this is the moment after which a second
# call must be refused. A failure in the wiring leaves a sealed key and a
# spent window, which is the honest state: the secret did cross. The issuer
# beside it goes at the same moment: a provenance file that outlived its
# window would let the next seal name an aggregator that armed nothing.
rm -f "$ARM_FILE" "$ARM_ISSUER_FILE"

# ---- wire it in, in a file this program owns ------------------------
#
# A drop-in, not the unit. The directive and the credential file have to
# disappear together or the service cannot start at all, and a directive in
# the unit belongs to whoever writes the unit next: an installer, an update,
# a restore. This one is written here, removed by --reset, and carried across
# an update by being a file of its own.
#
# Written whole every time, so a re-seal under a different credential name
# leaves one declaration rather than two, and the migration below takes the
# old line out of the unit. The credential a previous seal left in $CRED_DIR
# is not deleted here: sealing a new key has never revoked the old one, and
# --reset is the verb that removes keys.
mkdir -p "$DROPIN_DIR"
chmod 0755 "$DROPIN_DIR"
# The text comes from the method library, which is also where
# install-advisord.sh gets it: two programs write this file, and a byte of
# drift between them is a re-run of the installer rewriting a file the sealer
# would have left alone (#708).
aperire_key_dropin_text "$CRED_NAME" "$CRED_PATH" "$METHOD" aperire-seal-model-key > "$DROPIN"
chown root:root "$DROPIN" 2>/dev/null || true
chmod 0644 "$DROPIN"

# And the hosts that already carry the line in the unit itself, which is
# every host sealed before this. Migrated by the next seal or by --reset, so
# an operator has to do nothing for it to happen. A unit and a drop-in naming
# the same credential id do not refuse each other, and the drop-in is the one
# the service receives (measured on systemd 255), so a host between the two
# states still starts.
MIGRATED=no
if strip_unit_credential_lines; then MIGRATED=yes; fi

# ---- the config the service reads --------------------------------------
#
# The same file, with the same fields, that the operator-menu path writes.
# Owned by whatever owns the state directory, because the Advisor reads it
# from its own account and root-owned files in its state are a permissions
# accident waiting to be diagnosed. Planted through the state helper (#703),
# so the create, the ownership, the mode and the move onto the name all
# happen on one descriptor and the service never reads half a config. Every
# value here was validated above; the key is not among them and is already
# gone.
#
# Built into a variable first, and planted below the change file, because the
# ORDER is what matters here and the plant is now one call rather than three.
CFG_JSON="$(cat <<JSON
{
  "enabled": true,
  "shape": "$SHAPE",
  "base_url": "$BASE_URL",
  "model": "$MODEL",
  "credential_name": "$CRED_NAME",
  "key_hint": "$KEY_HINT",
  "max_tokens": 16000,
  "timeout_sec": 300
}
JSON
)"

# The fact the Advisor cannot observe for itself: that this configuration
# arrived through a seal, and under whose arming. It writes the ledger entry
# from what it sees in the file; this is what that entry quotes (#447).
#
# BEFORE the config, not after. A running Advisor is watching that file on a
# short tick, and between the two writes it can see the new configuration,
# write the entry with no provenance on it, and leave this note for the
# restart to drop as belonging to nothing.
if [[ -n "$SEAL_ISSUER" ]]; then
  write_change_file "$CFG_DIR" fleet-push "" "$SEAL_ISSUER" "$CRED_NAME"
else
  write_change_file "$CFG_DIR" seal "" "" "$CRED_NAME"
fi

printf '%s\n' "$CFG_JSON" \
  | python3 -I "$STATE_TOOL" plant "$CFG_PATH" dir dir 0640 --stdin \
  || die failed "the model configuration could not be written to $CFG_PATH; the credential and the drop-in are in place, so re-run this seal"

systemctl daemon-reload

# ---- restart, and read it back --------------------------------------
#
# The key is handed to the service at start, so until it restarts the Advisor
# is still running without a model. What this prints is what was READ BACK
# afterwards, never what was attempted.
#
# reset_and_restart_advisord, not a bare restart (#541 P1-091): this is one
# seal in a run that may have already installed, moved the account and
# restarted the unit more than once, and past the burst a bare restart would
# be refused as repeated too quickly while this program went on to read back
# a state the unit never reached.
reset_and_restart_advisord "$ADVISORD_UNIT"

ADVISOR_ADDR="$(exec_flag "$exec_line" addr)"
ADVISOR_ADDR="${ADVISOR_ADDR:-$DEFAULT_ADVISOR_ADDR}"
STATE_DIR="$(exec_flag "$exec_line" state)"
TOKEN_FILE=""
if [[ -n "$STATE_DIR" ]]; then TOKEN_FILE="$STATE_DIR/approve.token"; fi
read_back_service "$ADVISORD_UNIT" "$ADVISOR_ADDR" "$TOKEN_FILE"

say sealed "credential $CRED_NAME for $ADVISORD_UNIT, method $METHOD at $CRED_PATH, swept ${SWEPT[*]:-none}, model $MODEL at $BASE_URL, config $CFG_PATH, drop-in $DROPIN, unit line migrated $MIGRATED, service $state, listener $listener"

printf 'sealed=%s\n' "$CRED_NAME"
# What came off with it. Never silent: a plaintext key this program removed is
# a key an operator may still think they have (#712 review M1).
printf 'swept=%s\n' "${SWEPT[*]:-none}"
# Which of the two this host used. A line the readers on the other side of the
# socket ignore unless they know it (dashboard/lib/model-seal.ts takes the
# lines it names and no others), so adding it breaks nothing and a host can
# still be asked what it did.
printf 'method=%s\n' "$METHOD"
printf 'unit=%s\n' "$ADVISORD_UNIT"
printf 'config=%s\n' "$CFG_PATH"
printf 'dropin=%s\n' "$DROPIN"
printf 'migrated=%s\n' "$MIGRATED"
printf 'service=%s\n' "$state"
printf 'listener=%s\n' "$listener"
[[ "$state" == active ]] || exit 1
