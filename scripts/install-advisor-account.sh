#!/usr/bin/env bash
# Move the Advisor onto its own account, with no docker group and no sudo at
# all: ADR 0007's option D1, reached through a root socket (ADR 0025).
#
# What this is actually for. Today the Advisor runs as your login account,
# which is in the docker group. Docker group membership is root-equivalent:
# that account can mount the host filesystem into a container and reach
# everything the privilege wrapper exists to constrain. So the wrapper is an
# allow-list and an audit trail, and the compact says so in plain words rather
# than implying a boundary that is not there.
#
# After this, the account the Advisor runs as:
#
#   - cannot reach Docker at all, so it cannot go around the wrapper
#   - holds no sudo rule, and runs with NoNewPrivileges on every systemd,
#     249 included: the one thing it may do as root is connect to its own
#     socket, where root checks its uid, takes one verb from a fixed table
#     and runs the root-owned wrapper copy
#   - cannot list your home directory; it is granted passage to the repository
#     and nothing else, by an ACL rather than by joining your group
#   - never shows the validator token to the model: the wrapper strips it as
#     root, before returning anything
#   - owns its own state and evidence, and nothing else on this host
#
# The wrapper becomes the whole of what the Advisor can do, which is what the
# code has claimed all along.
#
#   curl -fsSL https://get.aperire.one | bash -s -- --run advisor-account
#
# Re-runnable. Verifies the service still works through the new arrangement and
# puts the old one back automatically if it does not. Changes nothing about the
# node itself.
#
# A host with no node to drive (an aggregator, or a box that watches others)
# moves too: the account and the sandbox are the same, and it simply gets no
# socket and no --wrapper, because there is nothing for a wrapper to act on.
#
# Environment:
#
#   APERIRE_ACCOUNT    the account the Advisor will run as.
#                      Default: aperire-advisor — a name chosen so it does not
#                      collide with a person. The account is created as a
#                      system account with no login shell and no home
#                      directory; if one of that name already exists and looks
#                      the same way, it is adopted.
#
#                      An account that looks like a person's — a login shell,
#                      SSH keys in its home, or membership of the docker group
#                      — is refused rather than adopted, because adopting one
#                      would hand the Advisor whatever that person can reach
#                      and would put this script in the position of changing
#                      an operator's own account. Set this variable to a name
#                      no one logs in as if that happens.
#
#   APERIRE_INSTANCE   which dashboard/Advisor pairing on this host to move
#                      (ADR 0009). Empty is the single-instance layout.
#   APERIRE_ADVISOR_PORT / APERIRE_PORT
#                      the Advisor's and the dashboard's ports for this
#                      instance. Default 7810 and 7800.
#   APERIRE_NODE_CONTAINER
#                      the node container this Advisor watches. Discovered
#                      from the wrapper configuration when unset.

set -euo pipefail

# ── No systemd floor ─────────────────────────────────────────────────────
# This script used to refuse systemd 249 (Ubuntu 22.04): any seccomp directive
# in a unit forces no_new_privs onto a non-root User= service there, sudo
# refuses under it, and the account's one sudo rule was how it reached the
# node. There is no sudo rule now (ADR 0025). The account connects to a root
# socket, which needs no privilege, so the unit below runs NoNewPrivileges and
# the full syscall filter on 249 and 255 alike.

# Where this program and the libraries it loads sit, and the install tree it
# acts on. The same directory and its parent when an operator runs it from the
# tree. An update runs a checked copy instead (get-aperire.sh stages this
# program and every file it loads or runs, each read once and matched against
# the release's digests, into a directory only root can write; #779 review,
# L1), and names the tree it acts on with APERIRE_INSTALL_TREE. Nothing root
# sources or runs is then read out of the tree.
SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="${APERIRE_INSTALL_TREE:-$(cd "$SELF_DIR/.." && pwd)}"

# The one rule about who may write advisor/knowledge-fleet. Sourced here and
# not at the step that uses it: a checkout missing this file would otherwise
# be a "command not found" exit halfway down, after the sudoers rule is
# installed and before the unit is rewritten.
[[ -r "$SELF_DIR/fleet-corpus-perms.sh" ]] \
  || { echo "error: $SELF_DIR/fleet-corpus-perms.sh is missing from this checkout" >&2; exit 1; }
# shellcheck source=scripts/fleet-corpus-perms.sh
. "$SELF_DIR/fleet-corpus-perms.sh"

# The one place that names aperire-advisord's failure-recovery unit AND the
# one place that writes it (P2-093), sourced here so this script cannot
# name it on OnFailure= without also being able to write it.
[[ -r "$SELF_DIR/advisord-credcheck-lib.sh" ]] \
  || { echo "error: $SELF_DIR/advisord-credcheck-lib.sh is missing from this checkout" >&2; exit 1; }
# shellcheck source=scripts/advisord-credcheck-lib.sh
. "$SELF_DIR/advisord-credcheck-lib.sh"
[[ -r "$SELF_DIR/advisord-restart-lib.sh" ]] \
  || { echo "error: $SELF_DIR/advisord-restart-lib.sh is missing from this checkout" >&2; exit 1; }
# shellcheck source=scripts/advisord-restart-lib.sh
. "$SELF_DIR/advisord-restart-lib.sh"
# The one rule this account's grant rests on (ADR 0024): the program root runs
# for it is a root-owned copy outside the tree, placed only after a check that
# no service account can write the copy it came from. The same library writes
# the socket that grant is reached through (ADR 0025).
[[ -r "$SELF_DIR/trusted-path-lib.sh" ]] \
  || { echo "error: $SELF_DIR/trusted-path-lib.sh is missing from this checkout" >&2; exit 1; }
# shellcheck source=scripts/trusted-path-lib.sh
. "$SELF_DIR/trusted-path-lib.sh"
# The broker behind the socket is a root program, placed only through the
# release's own digests (ADR 0024 lane 2), the same check every grant
# installer copies its program through.
[[ -r "$SELF_DIR/release-digests-lib.sh" ]] \
  || { echo "error: $SELF_DIR/release-digests-lib.sh is missing from this checkout" >&2; exit 1; }
# shellcheck source=scripts/release-digests-lib.sh
. "$SELF_DIR/release-digests-lib.sh"
# The one rule about who reads the fleet trust key (#868): the dashboard's
# alone, with a public half beside it for this account.
[[ -r "$SELF_DIR/fleet-trust-split.sh" ]] \
  || { echo "error: $SELF_DIR/fleet-trust-split.sh is missing from this checkout" >&2; exit 1; }
# shellcheck source=scripts/fleet-trust-split.sh
. "$SELF_DIR/fleet-trust-split.sh"

# Resolved further down, once the unit and the dashboard's account are known:
# an explicit APERIRE_ACCOUNT, else the account a previous run already moved
# the service onto, else the default. See "Choosing the account".
ACCOUNT="${APERIRE_ACCOUNT:-}"
DEFAULT_ACCOUNT=aperire-advisor
# An explicit name goes into the unit's User= and Group=, so it is held to the
# shape useradd takes (the same rule install-advisord.sh holds it to): a
# newline in it would write unit lines. Only root sets it, so this is
# hardening and not a boundary.
if [[ -n "$ACCOUNT" && ! "$ACCOUNT" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; then
  echo "error: the account name must be lowercase letters, digits, dashes and underscores, up to 32, not starting with a digit or dash" >&2
  exit 2
fi
# The instance this account serves — same variable the other installers
# take, so a second node's Advisor moves onto its own account without
# touching the first one's unit (ADR 0009).
INSTANCE="${APERIRE_INSTANCE:-}"
# The name ends up in /usr/local/sbin, /etc/sudoers.d and the unit's name, so
# it is held to the rule install-advisord.sh holds it to.
if ! trusted_valid_instance "$INSTANCE"; then
  echo "error: instance name must be lowercase letters, digits and dashes" >&2
  exit 2
fi
SUFFIX="${INSTANCE:+-$INSTANCE}"
ADVISOR_PORT="${APERIRE_ADVISOR_PORT:-7810}"
# A variable only so a test can point a whole run at a fake directory (same
# override install-advisord.sh and install-model-key-sealer.sh already take).
UNIT_DIR="${APERIRE_UNIT_DIR:-/etc/systemd/system}"
UNIT_NAME="aperire-advisord${SUFFIX}"
UNIT="$UNIT_DIR/${UNIT_NAME}.service"
BACKUP="${UNIT}.before-account"
# install-advisord.sh keeps a login Advisor here before it writes the waiting
# unit over it (#898 review, R2). Read only: this script never writes it, and
# it is not the marker above.
LOGIN_COPY="${UNIT}.login-before-stack"
# The recovery unit named on OnFailure= below (#541). This script rewrites
# the unit that names it, so it also ensures the recovery unit itself
# exists: write_advisord_credcheck_unit (advisord-credcheck-lib.sh, sourced
# above) is the one place that copies its program and writes it, which is
# what makes it impossible for this script to name a unit that install-advisord.sh
# never got a chance to write first (a host moved onto its own account
# before install-advisord.sh ever ran otherwise got an OnFailure= naming
# nothing).
CREDCHECK_UNIT_NAME="aperire-advisord-credcheck${SUFFIX}"
DASH_UNIT="aperire-server${SUFFIX}"
# The dashboard this Advisor reads through (ADR 0008), taken from the host's
# own record rather than from a constant. install-aperire-service.sh writes
# this instance's port into /etc/aperire/aperire<suffix>.env and never
# overwrites it, so that file is what a :7900 node host says about itself.
#
# A constant here was #461: a bare re-run on a PORT=7900 host rewrote a
# working unit with --dash-read-url=http://127.0.0.1:7800, reported success,
# and the Advisor came back reading a closed port. install-advisord.sh:46
# already reads that file, for the same failure on 2026-08-14; this is the
# same resolution order, with the instance's own file read first.
DASH_PORT="${APERIRE_PORT:-}"
DASH_PORT_FROM="APERIRE_PORT in this run's environment"
if [[ -z "$DASH_PORT" ]]; then
  DASH_ENV_FILES=("/etc/aperire/aperire${SUFFIX}.env")
  [[ -n "$SUFFIX" ]] && DASH_ENV_FILES+=(/etc/aperire/aperire.env)
  for _e in "${DASH_ENV_FILES[@]}"; do
    [[ -r "$_e" ]] || continue
    DASH_PORT="$(awk -F= '$1=="PORT"{sub(/^[^=]*=/,""); gsub(/"/,""); print; exit}' "$_e")"
    if [[ -n "$DASH_PORT" ]]; then DASH_PORT_FROM="$_e"; break; fi
  done
fi
if [[ -z "$DASH_PORT" ]]; then
  DASH_PORT=7800
  DASH_PORT_FROM="the default, because nothing on this host names a port"
fi

# Same as install-advisord.sh: name the container this Advisor watches, from
# the deployment the wrapper config already discovered. Native has no
# container at all, so this stays empty on KIND=native rather than naming
# the systemd unit as one, the same lying flag #396 was filed over, and this
# script rewrites the unit the account move runs on, which is exactly the
# native host the whole move is strongest for.
# The wrapper configuration, read the way the wrapper's own parser reads it:
# comment and empty lines skipped, the key is everything before the first =,
# the value everything after it, and a last line with no newline is a line.
# A key set twice is refused below, before anything changes, as the wrapper
# refuses it, so the two can never read different values out of one file
# (#806 review: a SERVICE=none with no newline after it was "none" here and
# the line before it to the wrapper).
WCONF=/etc/aperire/node-wrapper.conf
wconf_value() { # $1 = key; prints its value, or nothing
  [[ -r "$WCONF" ]] || return 0
  awk -v want="$1" '/^#/ || $0 == "" { next }
    { k = $0; sub(/=.*/, "", k); if (k == want) { v = $0; sub(/^[^=]*=/, "", v); s = v } }
    END { printf "%s", s }' "$WCONF"
}
WCONF_DUPS=""
if [[ -r "$WCONF" ]]; then
  WCONF_DUPS="$(awk '/^#/ || $0 == "" { next }
    { k = $0; sub(/=.*/, "", k); if (n[k]++ == 1) printf "%s ", k }' "$WCONF")"
fi
NODE_KIND="$(wconf_value KIND)"
# Only the exact word `none` is a host with no node (install-node-wrapper.sh
# --no-node writes it on every aggregator); anything else, a value with stray
# whitespace included, is read as a node, so a doubtful file gets every node
# check rather than none (#806).
NODE_SERVICE="$(wconf_value SERVICE)"
NODE_CONTAINER="${APERIRE_NODE_CONTAINER:-}"
if [[ "$NODE_KIND" != native && -z "$NODE_CONTAINER" && "$NODE_SERVICE" != none && -r "$WCONF" ]]; then
  NODE_CONTAINER="$NODE_SERVICE"
fi
# The sudo rule an older release wrote for this instance. Nothing writes one
# now (ADR 0025); this run removes it once the Advisor is running on the
# socket, and names it until then.
SUDOERS="/etc/sudoers.d/aperire-advisor${SUFFIX}"
# The copy the socket's broker runs: /usr/local/sbin/aperire-node-wrapper, or
# ...-<instance> for a second pairing. Never the file in this checkout. The
# checkout belongs to the operator and, until the dashboard has its own
# account, to the dashboard too, and a grant naming a file either can rewrite
# is root on demand for whoever rewrites it (#673).
WRAPPER="$(trusted_wrapper_path "$INSTANCE")"
# Instance-scoped, like the copy: a second pairing's Advisor has its own
# socket, bound to its own account.
SOCK="$(trusted_socket_path "$INSTANCE")"
CONF=/etc/aperire/node-wrapper.conf

# Whether there is a node here for a wrapper to drive. An aggregator, or a box
# that watches others, has no wrapper configuration and moves all the same:
# the account and the sandbox, with no socket and no --wrapper. Node-only
# steps below (the wrapper copy, the socket, the config closer, the refusal on
# the node's directory, the wrapper checks) are skipped there, and say so.
HAS_NODE=0
[[ -f "$CONF" ]] && HAS_NODE=1
# A wrapper configuration is not a node. An aggregator has one, written by
# install-node-wrapper.sh --no-node with SERVICE=none, so its Advisor gets the
# socket and the host reads behind it (unit state, the journal, memory, disk),
# and every node verb refuses there by design. HAS_NODE above decides the
# socket, the wrapper copy and the probe through them; RUNS_NODE decides the
# steps that act on a node's config and deployment. Read as one flag, a host
# with SERVICE=none had its socket probed with a node verb, its /dev/null
# taken for a node config and /dev for that config's directory, and every
# move reverted (#806).
RUNS_NODE=$HAS_NODE
[[ "$NODE_SERVICE" == none ]] && RUNS_NODE=0
NODE_DIR=""

TOKEN="$REPO/advisor/state/approve.token"
STATE="$REPO/advisor/state"
EVIDENCE="$REPO/advisor/evidence"
# Where a signature-verified knowledge bundle from the aggregator lands (ADR
# 0017). The service replaces this directory whole, by rename, so it writes
# the directory itself and not only files inside it.
KNOWFLEET="$REPO/advisor/knowledge-fleet"

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
info() { printf '   %s\n' "$*"; }
die()  { printf '\n\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "run with sudo: this creates an account and a root socket for it"

# The one argument: --hand-trees-back gives advisor/state, advisor/evidence and
# advisor/knowledge-fleet back to the account that owns the install tree, and
# does nothing else (#1121). It is the step the undo instructions below name,
# so the trees are fixed here and an operator never types a root chown over
# paths the Advisor's account writes.
HAND_BACK=0
case "${1:-}" in
  "") ;;
  --hand-trees-back) [[ $# -eq 1 ]] || die "--hand-trees-back takes no other argument"; HAND_BACK=1 ;;
  *) die "unknown argument: $1. The only one this takes is --hand-trees-back; everything else is set by APERIRE_ACCOUNT and APERIRE_INSTANCE." ;;
esac
# Before anything changes. The wrapper refuses this file outright, and a
# reader here that picked one of the two values would be guessing which one
# the wrapper meant.
[[ -z "$WCONF_DUPS" ]] \
  || die "$WCONF sets ${WCONF_DUPS% } more than once. The wrapper refuses a file like that, and nothing
   here was changed. Keep one line for each key and run this again."

# Everything this script needs, named once and checked before it changes
# anything. A missing tool discovered halfway through is a half-migrated
# service; discovered here it is one apt-get.
need() {
  local missing=()
  for t in "$@"; do command -v "$t" >/dev/null || missing+=("$t"); done
  if (( ${#missing[@]} )); then
    die "missing: ${missing[*]}
   On Debian or Ubuntu:  sudo apt-get install -y acl sudo systemd util-linux python3
   On RHEL or Fedora:    sudo dnf install -y acl sudo systemd util-linux python3"
  fi
}
need useradd groupadd usermod runuser setfacl systemctl awk python3 install getent

# Whether this run wrote the socket units. A first run that fails takes them
# back; a re-run leaves them, because the Advisor already running may stand
# on them. The sudo rule an older release wrote is never touched until the
# very end, after the Advisor has come back on the socket, so no undo has to
# put it back.
SOCKET_WRITTEN=0
take_back_socket() {
  (( SOCKET_WRITTEN )) || return 0
  trusted_remove_socket_units "$INSTANCE"
  info "the socket this run wrote is taken back"
}

# The waiting unit after a refused or undone move: stopped and not enabled.
# $1 says what happened to the unit. The disable is checked, so a failure is
# reported and the operator gets the command, not "left stopped and disabled".
leave_waiting_unit_stopped() {
  if systemctl disable --now "${UNIT_NAME}" >/dev/null 2>&1; then
    info "$1, and the service is left stopped and disabled."
    info "install-advisor-stack.sh, or this script again, starts it once the move works."
  else
    info "$1, but \`systemctl disable --now ${UNIT_NAME}\` failed, so it may still be"
    info "enabled and would start as an account that owns nothing at the next boot. Run:"
    info "  sudo systemctl disable --now ${UNIT_NAME}"
  fi
  if [[ -f "$LOGIN_COPY" ]]; then
    info "the unit that named the login before the stack wrote this one is kept at"
    info "$LOGIN_COPY; copy it back over the unit to return to that Advisor."
  fi
}

precheck_fail() {
  printf '\n\033[1;31m== Undoing\033[0m\n'
  # Same reading as revert() below, on the path that fires first. Every grant
  # above is idempotent, so on a re-run this run re-applied what was already
  # here and none of it is this run's to take back: the service running right
  # now stands on all three. Taking them back left an Advisor that could not
  # chdir into its own working directory, under output that said nothing had
  # changed (#420).
  if (( PREINSTALLED )); then
    info "nothing was taken back. The socket, the traversal ACL and the"
    info "ownership of the state directories belong to the arrangement that"
    info "was already running here, not to this run, and they are untouched."
  else
    take_back_socket
    setfacl -n -x "u:$ACCOUNT" "$HOME_DIR" 2>/dev/null || true
    if [[ -d "$NODE_DIR" ]]; then setfacl -n -x "u:$ACCOUNT" "$NODE_DIR" 2>/dev/null || true; fi
    give_trees_back "$TREE_OWNER" "$STATE" "$EVIDENCE" "$KNOWFLEET" || true
    # Through state_own_file, never a bare chmod on the name (#652). This
    # undo runs when a RE-RUN fails, so $STATE may already belong to a live
    # Advisor account from an earlier successful move, which is the same
    # window #420 itself is about: a symlink swapped onto $TOKEN in it would
    # have a bare chmod force mode 0600 onto whatever root-owned file it
    # names. A refusal here is not fatal, unlike the token loop above: this
    # path is already reverting, and the message it is about to die with is
    # the one worth reading.
    state_own_file "$TOKEN" "" "" 0600 || true
    info "the socket, the traversal ACL and the state ownership this run"
    info "granted are taken back; the $ACCOUNT account owns nothing now."
  fi
  if (( ${WAS_WAITING:-0} )); then
    # The stack's first step enabled the waiting unit and nothing has started
    # it. Left enabled it starts at the next boot as an account that owns
    # nothing, the crash loop revert() already avoids (#898 review, N1). There
    # was never a running service here, so the line below would not be true.
    # Nothing of this run's was running. On the login-unit path the Advisor
    # the operator had was stopped by hand before the stack ran.
    leave_waiting_unit_stopped "the waiting unit is kept; no service of this run was running"
  else
    info "nothing was changed about the running service; it never stopped."
  fi
  die "$1"
}

# ── Re-owning a file inside a directory this account controls (#652) ──────
#
# advisor/state belongs to the account this script builds. That account can put
# anything it likes at a name this script re-owns by hand, and every plain
# `chown path` and `chmod path` here runs as root and follows a symlink to
# whatever it points at. The token loop below was the worst of them: it hands
# the target's OWNER to the Advisor's account, not merely its group, so the
# account could name /etc/shadow, wait for the documented repair re-run, and be
# given the file.
#
# `chown -h` is not the fix on its own. It closes the chown half, because -h
# acts on the link and never its target, but Linux has no `chmod -h`
# (chmod(1): it "changes the permissions of the pointed-to file"), and these
# two tokens genuinely need mode 0640 or the dashboard cannot read them. So the
# #645 answer for reveal.window, drop the chmod, is not available here.
# Neither is its other answer, replant a fresh inode: these files hold live
# secrets that cannot be recreated empty.
#
# What closes it is doing both through a file DESCRIPTOR rather than a path:
#
#   lstat  the name, and refuse anything that is not already a regular file
#   open   O_NOFOLLOW|O_NONBLOCK, so a symlink swapped in first fails the open
#          outright rather than being followed
#   fstat  the descriptor: regular file, link count exactly 1, same device and
#          inode the lstat saw. A hard link planted in the gap, which O_NOFOLLOW
#          does nothing about because a hard link IS the inode, is caught by the
#          link count; a file substituted between the two calls is caught by the
#          identity check.
#   fchown, fchmod  on that descriptor. Neither can be redirected afterwards:
#          the kernel resolved the path once, and everything after operates on
#          the inode that resolution produced. There is no second lookup for a
#          racer to win, which is the whole difference from check-then-act.
#
# Refuses loudly rather than skipping. A symlink or a hard link at one of these
# names is never a legitimate state for this directory to be in, and quietly
# carrying on would leave a token the dashboard cannot read with nothing said
# about why. Never reads the file: reading a token through a link an attacker
# aimed would copy the target's content into a place it can read.
#
# python3 is already a hard requirement of this script (the `need` line above),
# so this introduces no new dependency on any host.
#
# Takes NUMERIC ids, resolved by the caller through getent. The reveal.window
# plant below spells its group the same way and for the same reason: getent is
# the one lookup this script trusts, it runs after the group-creation block has
# made the names real, and keeping the resolution in the shell means these
# functions never need a name service of their own.
#
# The work itself lives in scripts/state-file.py, one copy for the four sites
# in three scripts that need it (#661). It is a file and not a function here
# because get-aperire-advisor.sh reaches its plant through `sudo`, which execs
# a program and cannot be handed a shell function.
STATE_FILE_TOOL="$SELF_DIR/state-file.py"
[[ -r "$STATE_FILE_TOOL" ]] || die "$STATE_FILE_TOOL not found; this script and it ship together"

state_own_file() { # $1 = path, $2 = uid or "" to leave the owner alone, $3 = gid or "", $4 = octal mode or ""
  python3 -I "$STATE_FILE_TOOL" own "$1" "${2:-}" "${3:-}" "${4:-}"
}

# The undo's hand-back of the three trees, by descriptor (#1048). It was a
# `chown -R` by name over trees the Advisor's account writes (and, for the
# corpus, the dashboard's too). chown -R follows no link, but it changes a
# hard link to a file outside the tree like any other entry, so an account that
# could write a tree could hand root a second name for a file it could read and
# have it given to the tree owner. find only lists; every name it prints is
# then walked component by component by state-file.py own-many, opened
# O_NOFOLLOW, and a link or a hard link is refused and named, not followed.
# Owner and group only; modes stay as they are. Returns 1 when any entry was
# refused or the owner could not be resolved, and the caller keeps going: this
# runs on a path that is already undoing.
#
# The same walk the other way is the forward hand-over (#1121): the account is
# the Advisor's and GIVE_GROUP names the shared group, set for that one call.
# Unset, the group is the account's own, which is what an undo wants.
#
# GIVE_TOP_MODE is the forward hand-over's other half: the top directory of each
# tree is set to this mode in the same walk, by fchmod on the descriptor that
# walk opened, where it was a `chmod` by name after the hand-over (#1150). The
# account owns the tree from the moment it is handed over, and chmod follows a
# link, so a link put at the name in between had root change its target. Only
# the top directory: every entry below keeps the mode it has.
GIVE_GROUP=""
GIVE_TOP_MODE=""
give_trees_back() { # $1 = account, rest = directories
  local who="$1" uid gid d top list rc=0
  shift
  uid="$(id -u "$who" 2>/dev/null || true)"
  gid="$(getent group "${GIVE_GROUP:-$who}" 2>/dev/null | head -1 | cut -d: -f3 || true)"
  [[ -n "$gid" || -n "${GIVE_GROUP:-}" ]] || gid="$(id -g "$who" 2>/dev/null || true)"
  if [[ ! "$uid" =~ ^[0-9]+$ || ! "$gid" =~ ^[0-9]+$ ]]; then
    info "could not resolve $who${GIVE_GROUP:+:$GIVE_GROUP} to a uid and gid, so the Advisor's directories were not handed over"
    return 1
  fi
  for d in "$@"; do
    [[ -d "$d" ]] || continue
    # The tree as it stands now, each entry by device and inode, written
    # before anything is handed over (#1152). The walk below re-owns an entry
    # only if it is the one recorded here: the paths find prints a moment
    # later are proposals, and a root-owned file the account moved into the
    # tree in between is named and left, not given to the receiver. This
    # closes what moves in during the hand-over; it cannot say what was
    # already there when the record was taken.
    list="$(mktemp)" || { info "could not record $d before handing it over, so it was left as it was"; rc=1; continue; }
    find "$d" -printf '%D:%i:%p\0' > "$list" 2>/dev/null
    find "$d" -print0 2>/dev/null \
      | python3 -I "$STATE_FILE_TOOL" own-many "$uid" "$gid" "" --root "$(dirname -- "$d")" --list "$list" || rc=1
    if [[ -n "${GIVE_TOP_MODE:-}" ]]; then
      # GNU chmod keeps a directory's setgid bit for an octal mode and fchmod
      # does not, so a directory that has it is asked for with it.
      top="$GIVE_TOP_MODE"; [[ ! -g "$d" ]] || top="2${GIVE_TOP_MODE#0}"
      # Said here, for the directory this call re-owned and set the mode on,
      # and not by the caller for every directory it passed. An entry inside
      # it that was refused is named above and does not make this line false:
      # the directory itself moved. A directory the walk refused prints
      # nothing.
      if printf '%s\0' "$d" \
          | python3 -I "$STATE_FILE_TOOL" own-many "$uid" "$gid" "$top" --root "$(dirname -- "$d")" --list "$list"; then
        info "$d -> $who:${GIVE_GROUP:-$who}, mode $top"
      else
        rc=1
      fi
    fi
    rm -f -- "$list"
  done
  (( rc == 0 )) || info "some entries were left as they were (named above): a directory, or something inside one"
  return "$rc"
}

# The create half of the same rule. `install` is not an alternative to it: GNU
# install chmods the PATH after creating the file, so the account that owns
# advisor/state can swap a link in and have root chmod its target instead
# (#661, and the long form in state-file.py's own header).
state_plant_file() { # $1 = path, $2 = uid or "", $3 = gid or "", $4 = octal mode, $5 = --stdin to take content from a pipe
  python3 -I "$STATE_FILE_TOOL" plant "$1" "${2:-}" "${3:-}" "${4:-}" ${5:+"$5"}
}

# The undo is answered here, before the unit is looked for and before
# anything is placed or granted: --hand-trees-back hands three directories to
# the tree's owner and does nothing else. It once sat after the wrapper and
# the socket's broker were placed as root, so it could place two programs, or
# refuse over one of them, and then say it had changed nothing (#1150).
#
# The account that runs the dashboard. It has to keep reading the Advisor's
# service token, so the two need a shared group rather than a shared identity.
#
# The dashboard unit is aperire-server on a full node, but a read-only fleet
# peer runs aperire-read instead — the same read API with no interactive UI,
# which is the common member of a fleet. Try both (instance-suffixed), take the
# first that exists, and fall back to the sudo caller if neither does. The awk
# result is assigned WITHOUT a pipeline: a missing unit or one with no User=
# then degrades to the fallback, rather than tripping `set -o pipefail` and
# aborting the whole migration silently — which is exactly what a read-only
# peer hit, an empty exit 2 with no message to say why.
DASH_USER=""
for _u in "aperire-server${SUFFIX}" "aperire-read${SUFFIX}"; do
  _f="/etc/systemd/system/${_u}.service"
  [[ -r "$_f" ]] || continue
  DASH_USER=$(awk -F= '/^User=/{print $2; exit}' "$_f")
  if [[ -n "$DASH_USER" ]]; then DASH_UNIT="$_u"; break; fi
done
DASH_USER=${DASH_USER:-${SUDO_USER:-root}}
info "dashboard runs as: $DASH_USER (unit: $DASH_UNIT)"
# Who owns the install tree, read from the tree. On a host installed before
# ADR 0024 it is the dashboard's account too; on a fresh one the dashboard
# runs as aperire-dashboard, which has no home, and the tree stays the
# operator's. The passage this script grants runs through the tree owner's
# home, and an undo hands the Advisor's directories back to the tree owner,
# whom install-advisord.sh ran the Advisor as before the move.
# A tree is never root's on a real install (the bootstrap refuses one), so
# root here means the answer is no use, and the operator who ran this, then
# the dashboard's account, stand in.
TREE_OWNER="$(stat -c '%U' "$REPO" 2>/dev/null || true)"
if [[ -z "$TREE_OWNER" || "$TREE_OWNER" == UNKNOWN || "$TREE_OWNER" == root ]]; then
  TREE_OWNER="${SUDO_USER:-}"
  [[ -n "$TREE_OWNER" && "$TREE_OWNER" != root ]] || TREE_OWNER="$DASH_USER"
fi
if (( HAND_BACK )); then
  say "Handing the Advisor's directories back to $TREE_OWNER"
  info "advisor/state, advisor/evidence and advisor/knowledge-fleet under $REPO"
  give_trees_back "$TREE_OWNER" "$STATE" "$EVIDENCE" "$KNOWFLEET" \
    || die "some of the directories were left as they were (named above): a link, or a file with a second name, is never changed. Remove or replace what is named and run this again."
  info "done. Nothing else was changed; the unit, the socket and the account are as they were."
  exit 0
fi

[[ -f "$UNIT" ]]  || die "$UNIT not found; run scripts/install-advisord.sh first"
if (( HAS_NODE )); then
  # Placed here, before anything is granted, so a refusal leaves this host
  # exactly as it was, and a socket is never written in front of a path with
  # nothing behind it. The broker beside it, by the same checked copy.
  say "Placing the wrapper, and the broker that runs it for the socket"
  trusted_place_node_wrapper "$REPO" "$INSTANCE" \
    || die "the wrapper was not placed, and nothing was changed. The lines above
   name the file and the account that can write it. Root will not run a copy a
   service account can change: make it writable by its owner only, then run
   this again."
  trusted_place_broker "$REPO" \
    || die "the socket's broker was not placed, and nothing was granted. The lines
   above say why: a broker in this tree that is not the one the release
   shipped is never copied as root."
  # Read back, not assumed: the socket below is only a boundary if root owns
  # exactly these files and nobody else can write them.
  for _f in "$WRAPPER" "$(trusted_broker_path)"; do
    [[ "$(stat -c '%u %a' "$_f" 2>/dev/null)" == "0 755" ]] \
      || die "$_f is $(stat -c '%U:%G %a' "$_f" 2>/dev/null || echo missing), not root 0755; nothing was granted"
  done
  if (( RUNS_NODE )); then
    NODE_DIR=$(wconf_value CONFIG_FILE)
    NODE_DIR=$(dirname "${NODE_DIR:-/nonexistent/x}")
  fi
  # The directory this run refuses the account and takes the refusal back
  # from. A config path at the root of a system tree (/dev/null, /etc/x) names
  # a directory the whole host runs on, never a node's own, so it is never
  # touched: refusing an account /dev or /etc is breaking the host, not
  # closing a config (#806).
  case "$NODE_DIR" in
    /|/dev|/dev/*|/proc|/proc/*|/sys|/sys/*|/etc|/usr|/usr/*|/bin|/sbin|/lib|/lib64|/var|/run|/tmp|/home|/root|.)
      info "the node config's directory is $NODE_DIR, which is not a node's own; no ACL is set on it"
      NODE_DIR="" ;;
  esac
else
  say "No node here"
  info "$CONF is not here, so there is no node for a wrapper to act on. The"
  info "Advisor still gets its own account and the same sandbox, and no socket."
fi

# Printed, not assumed: this number goes into the unit the Advisor reads the
# dashboard through, and the run that got it wrong said nothing about it.
info "dashboard port: $DASH_PORT (from $DASH_PORT_FROM)"

# ── Choosing the account ────────────────────────────────────────────────
# The account this service runs as is the whole security boundary, so the
# name is picked deliberately rather than defaulted into.
#
# A shell that cannot log in, no SSH keys, no docker: an account that exists
# to own a process. Anything else is somebody's, and adopting somebody's
# account gives the Advisor whatever they can reach — and puts this script in
# the business of editing an operator's own groups on a validator host.
is_nologin_shell() {
  case "$1" in
    /usr/sbin/nologin|/sbin/nologin|/bin/false|/usr/bin/false|'') return 0 ;;
    *) return 1 ;;
  esac
}
# Reports the human-looking traits of an existing account, one per line, and
# says nothing at all about an account that has none — so the caller can both
# decide and explain.
human_traits() {
  local a="$1" line shell home
  id -u "$a" >/dev/null 2>&1 || return 0
  line="$(getent passwd "$a" || true)"
  shell="$(printf '%s' "$line" | cut -d: -f7)"
  home="$(printf '%s' "$line" | cut -d: -f6)"
  is_nologin_shell "$shell" || echo "it can log in (shell: $shell)"
  if [[ -n "$home" && -d "$home" ]]; then
    [[ -s "$home/.ssh/authorized_keys" ]] && echo "somebody signs in with it (SSH keys in $home/.ssh/authorized_keys)"
  fi
  return 0
}
in_docker_group() { id -nG "$1" 2>/dev/null | tr ' ' '\n' | grep -qx docker; }

if [[ -z "$ACCOUNT" ]]; then
  # A previous run of this script already chose an account and wrote it into
  # the unit — keep it, or a re-run would create a second account and migrate
  # a working install for no reason.
  #
  # A User= line is not on its own evidence of that: install-advisord.sh writes
  # the DASHBOARD's account there, which on this lab's hosts is a person. So the
  # unit's account is only adopted when it is neither that account nor anything
  # that looks like somebody's.
  #
  # Both predicates below pass for an account that does not exist, so a unit
  # naming an account somebody has since deleted keeps the name and the
  # account is recreated below. That is deliberate: the unit, the sudoers rule
  # and the state directory all already refer to that name.
  PREV_ACCOUNT="$(awk -F= '/^User=/{print $2; exit}' "$UNIT" 2>/dev/null || true)"
  if [[ -n "$PREV_ACCOUNT" && "$PREV_ACCOUNT" != "$DASH_USER" ]] \
     && [[ -z "$(human_traits "$PREV_ACCOUNT")" ]] && ! in_docker_group "$PREV_ACCOUNT"; then
    ACCOUNT="$PREV_ACCOUNT"
    info "keeping the account this Advisor already runs as: $ACCOUNT"
  fi
fi
ACCOUNT="${ACCOUNT:-$DEFAULT_ACCOUNT}"
info "advisor will run as: $ACCOUNT"
# What an older run of this script could leave on /dev on a host with no node
# (#806 review): a refusal for this account on the whole directory, or the
# mask a failed run left behind it. Repaired here, on /dev alone.
trusted_repair_dev_acl "$ACCOUNT"

# Is this a re-run on a host where the move has ALREADY happened? It decides
# what reverting means.
#
# On a first run, undoing is "take back everything I just granted": the
# sudoers rule, the traversal ACL, the ownership of the state directories.
# On a re-run those same grants are what the RUNNING service depends on, and
# taking them back leaves a service that cannot chdir into its own working
# directory, cannot read its own token and cannot reach the wrapper, with the
# old unit file in place saying everything is fine. Measured on a lab host
# during the #30 native lab: a re-run whose last check failed left the Advisor
# in a crash loop, 200/CHDIR, and nothing in the revert's own output said the
# grants had gone with it.
#
# So a re-run reverts the unit and nothing else. Read before the unit is
# rewritten, since that is what makes it readable at all.
PREINSTALLED=0
# The unit as it stands now, before this run rewrites it: still the waiting
# unit install-advisord.sh wrote on a fresh host, or not. A waiting unit is
# never started by anything this script puts back (#898 review, L1).
WAS_WAITING=0
grep -q '^# Waiting for install-advisor-account\.sh' "$UNIT" 2>/dev/null && WAS_WAITING=1
# Named and finished, not only named: install-advisord.sh writes a unit that
# names the account before the account exists and says so in a note that this
# script's own unit does not carry (#893). On that first run the grants below
# are this run's to take back, whatever the unit already says.
if [[ "$(systemctl show "$UNIT_NAME" -p User --value 2>/dev/null)" == "$ACCOUNT" ]] \
   && (( ! WAS_WAITING )); then
  PREINSTALLED=1
  info "this Advisor already runs as $ACCOUNT, so reverting would restore the unit only"
fi

# An aperire-svc already on this host is adopted by name below, and every
# member of it reads the Advisor's tokens (approve.token, read.token,
# reveal.window) once they move onto it. An uninstall --keep leaves the group
# for the files it kept, and before ADR 0024 a dashboard ran as the operator's
# login and was put in it; neither an uninstall nor a move to the dashboard's
# own account takes that login out (#1023 review, M1). So the group is adopted
# only when everyone in it is an account an install puts there: this
# Advisor's, this dashboard's, and the accounts the other Aperire units on
# this host run as. Anyone else is named, and nothing here changes.
_svc_line="$(getent group aperire-svc 2>/dev/null || true)"
if [[ -n "$_svc_line" ]]; then
  _allowed=" $ACCOUNT $DASH_USER "
  for _f in "$UNIT_DIR"/aperire-server*.service "$UNIT_DIR"/aperire-read*.service \
            "$UNIT_DIR"/aperire-advisord.service "$UNIT_DIR"/aperire-advisord-*.service; do
    [[ "$_f" == *credcheck* ]] && continue   # the recovery unit runs as root
    [[ -f "$_f" && "$_f" != "$UNIT" ]] || continue
    _u="$(awk -F= '/^[[:space:]]*User[[:space:]]*=/{v=$2; gsub(/[[:space:]]/,"",v)} END{print v}' "$_f" 2>/dev/null || true)"
    [[ -n "$_u" ]] && _allowed+="$_u "
  done
  # The listed members, and every account whose PRIMARY group it is, which
  # the member list does not show (_tp_group_others, trusted-path-lib.sh).
  _strangers=()
  for _m in $(cut -d: -f4 <<<"$_svc_line" | tr ',' ' ') $(_tp_group_others "" "$(cut -d: -f3 <<<"$_svc_line")"); do
    [[ "$_allowed" == *" $_m "* || " ${_strangers[*]} " == *" $_m "* ]] || _strangers+=("$_m")
  done
  if (( ${#_strangers[@]} )); then
    die "the aperire-svc group is already here and lists ${_strangers[*]}, which no Aperire
   install puts there. Every member of aperire-svc reads the Advisor's tokens, so it
   is not adopted with them in it. Nothing about the account has been changed.

   Take each one out (an account whose own group it is needs another primary
   group: sudo usermod -g <group> <name>), then run this again:
$(for _m in "${_strangers[@]}"; do printf '     sudo gpasswd -d %s aperire-svc\n' "$_m"; done)"
  fi
fi

say "Creating the account"
if id -u "$ACCOUNT" >/dev/null 2>&1; then
  TRAITS="$(human_traits "$ACCOUNT")"
  if [[ -n "$TRAITS" ]]; then
    die "$ACCOUNT already exists and belongs to a person, by the look of it:
$(printf '%s\n' "$TRAITS" | sed 's/^/     - /')

   This script would otherwise adopt it, and the Advisor would inherit
   everything that person can reach — which is the opposite of what it is for.
   Nothing has been changed.

   Give the Advisor an account of its own instead:
     sudo APERIRE_ACCOUNT=$DEFAULT_ACCOUNT bash $0

   Any name nobody logs in as will do; it is created here, as a system account
   with no login shell and no home directory."
  fi
  if in_docker_group "$ACCOUNT"; then
    die "$ACCOUNT already exists and is in the docker group, which is
   root-equivalent — it can mount this host into a container and reach
   everything the wrapper exists to constrain. Adopting it would make the
   boundary this script installs decorative. Nothing has been changed.

   Give the Advisor an account of its own:
     sudo APERIRE_ACCOUNT=$DEFAULT_ACCOUNT bash $0

   Or, only if you are certain no person uses $ACCOUNT, take it out of the
   group first:  sudo gpasswd -d $ACCOUNT docker"
  fi
  info "$ACCOUNT already exists — no login shell, no keys, no docker; adopting it"
else
  # A system account: no login shell, no home directory to accumulate things
  # in, no password. It exists to own a process and two directories.
  NOLOGIN=""
  for candidate in /usr/sbin/nologin /sbin/nologin /bin/false /usr/bin/false; do
    [[ -x "$candidate" ]] && { NOLOGIN=$candidate; break; }
  done
  [[ -n "$NOLOGIN" ]] || die "no nologin shell found; cannot create an account that cannot log in"
  useradd --system --no-create-home --shell "$NOLOGIN" "$ACCOUNT"
  info "created $ACCOUNT (system account, no login, no home)"
fi

# The one thing it must NOT have, asserted again after creation rather than
# assumed from it — the whole arrangement rests on this being false.
if in_docker_group "$ACCOUNT"; then
  die "$ACCOUNT is in the docker group, which is root-equivalent and defeats this entirely."
fi
info "not in the docker group — confirmed"

# A group both accounts are in, so the dashboard can read the token the Advisor
# generates. The alternative is a world-readable token, which is what the
# service-token work removed.
SHARED=aperire-svc
getent group "$SHARED" >/dev/null || { groupadd --system "$SHARED"; info "created group $SHARED"; }
usermod -aG "$SHARED" "$ACCOUNT"
if [[ "$DASH_USER" != "root" ]]; then usermod -aG "$SHARED" "$DASH_USER"; fi
info "$ACCOUNT and $DASH_USER share group $SHARED, for the service token only"

# The running dashboard, before anything moves onto that group (#996).
#
# It reads read.token and, on a node, fleet-trust.yaml through its group
# list, and Linux fixes that list when a process starts. Everything below
# moves both onto $SHARED. A dashboard started before it was in $SHARED (a
# first Advisor, or a restart after an Advisor-only uninstall deleted the
# group) was locked out of both from that move until its restart at the end:
# 14 s on a lab node, every fleet read of the node refused. So when /proc
# says the running dashboard lacks the group, it restarts here instead, and
# the restart at the end is skipped. When /proc cannot say, nothing changes:
# the restart at the end still happens.
#
# And when /proc says the running dashboard already holds the group (#1035),
# nothing needs a restart at all: it reads the tokens through the group it has,
# and a restart costs an aggregator every fleet read for about 24 s. That
# answer is kept in DASH_HOLDS_GROUP and the restart at the end honours it.
# Three outcomes, then: holds it (no restart), lacks it (restart now), could
# not tell (restart at the end).
DASH_RESTARTED_EARLY=0
DASH_HOLDS_GROUP=0
if [[ "$DASH_USER" != "root" ]] && systemctl list-unit-files "${DASH_UNIT}.service" >/dev/null 2>&1; then
  _shared_gid="$(getent group "$SHARED" | cut -d: -f3)"
  _dash_pid="$(systemctl show "${DASH_UNIT}.service" -p MainPID --value 2>/dev/null || true)"
  _dash_can_tell=0
  if [[ "$_shared_gid" =~ ^[0-9]+$ && "$_dash_pid" =~ ^[1-9][0-9]*$ && -r "$TP_PROC_DIR/$_dash_pid/status" ]]; then
    _dash_can_tell=1
    if awk '/^(Groups|Gid):/ { for (i = 2; i <= NF; i++) if ($i == g) f = 1 } END { exit !f }' \
         g="$_shared_gid" "$TP_PROC_DIR/$_dash_pid/status" 2>/dev/null; then
      DASH_HOLDS_GROUP=1
    fi
  fi
  if (( _dash_can_tell && ! DASH_HOLDS_GROUP )); then
    say "Restarting the dashboard to pick up the shared group, before anything moves onto it"
    info "it started before it was in $SHARED, and the Advisor's tokens are about to move"
    info "onto that group; restarted now, it reads them throughout."
    systemctl restart "${DASH_UNIT}"
    command sleep 4
    if systemctl is-active --quiet "${DASH_UNIT}"; then
      info "dashboard restarted"
    else
      info "the dashboard did not come back. Check: journalctl -u ${DASH_UNIT} -n 40"
    fi
    DASH_RESTARTED_EARLY=1
  fi
fi

say "Granting traversal, and only traversal"
# The repository lives under a home directory that is 0750, so a separate
# account cannot reach it at all — it could not even exec its own binary. The
# obvious fix, adding the account to the operator's group, is the wrong one:
# it would hand over read access to everything in that home, including
# rippled.cfg and the validator token in it.
#
# An ACL says the precise thing instead. `--x` is permission to pass through a
# directory without permission to list it, which is exactly the relationship
# wanted here: walk to the repository, see nothing else on the way.
command -v setfacl >/dev/null || die "setfacl not found; install acl:  sudo apt-get install -y acl"
HOME_DIR=$(getent passwd "$TREE_OWNER" | cut -d: -f6)
[[ -d "$HOME_DIR" ]] || die "could not find the home directory for $TREE_OWNER, who owns $REPO"

# -n: never recompute the mask, which could hand back a write another named
# entry had masked off. The precheck below reads the passage back.
setfacl -n -m "u:$ACCOUNT:--x" "$HOME_DIR"
info "$HOME_DIR: $ACCOUNT may pass through, and may not list it"

# The config file's own mode comes first, because the directory ACL below is
# not the load-bearing part.
#
# A stock Docker Compose deployment creates rippled.cfg mode 0644. On a host
# with no other accounts that is invisible; this script is what changes that,
# by adding an account and giving it traversal through the operator's home. The
# traversal grant is correct and minimal, but if it ends at a world-readable
# config then the new account reads the validator token directly and the
# wrapper's redaction is decoration. Denying the directory does not help — a
# file readable by everyone is readable through any other path to it.
#
# So the file is closed before the directory is, and closing it is delegated to
# the script that knows how: the file must stay readable by whatever group the
# node reads it as, which is discovered from the running node rather than
# assumed. Assuming it is how a validator was once left unable to open its own
# configuration.
#
# Told which account, by name. Left to work it out, that script reads User=
# from the unit, and at this point the unit has not been rewritten yet: it
# still names the operator, who owns the config. On every fresh install that
# resolved the operator as "the Advisor", tried to close the file to its own
# owner, failed its verify and reverted, and the daily verify then flagged
# the file as world-readable for as long as the host lived (#154).
CONFIG_CLOSED=0
CLOSER="$SELF_DIR/close-node-config-exposure.sh"
if (( RUNS_NODE )) && [[ -f "$CLOSER" ]]; then
  # The closer asks the wrapper to read the config back; it is handed the
  # root-owned copy placed above, never a wrapper out of the tree.
  if APERIRE_ACCOUNT="$ACCOUNT" APERIRE_CLOSER_WRAPPER="$WRAPPER" bash "$CLOSER" --apply; then
    CONFIG_CLOSED=1
  else
    # Not fatal. That script refuses to tighten anything it cannot verify the
    # node still reads, and reverts itself if a check fails, so a failure here
    # leaves the config exactly as it was, never half-applied. The account
    # arrangement is still worth completing, and this can be run later. The
    # reason is in its output above; this does not guess at it.
    info ""
    info "NOTE: the node config was left as it is. The reason is printed above."
    info "  Nothing was half-applied. Once that is resolved, run:"
    info "    curl -fsSL https://get.aperire.one | bash -s -- --run node-config-exposure --account $ACCOUNT --apply"
  fi
fi

# And an explicit refusal on the directory holding the node's config.
#
# That directory contains rippled.cfg, which contains [validator_token] — the
# key this validator signs with, and the one thing §7 says the Advisor must
# never read. Everything the Advisor legitimately needs from those files now
# comes through the wrapper: `show-config` returns the configuration with the
# key material stripped as root, and `artefact-hashes` returns digests so the
# rollback precondition can be judged without the file being opened here.
#
# So the account is refused the directory outright. §7 stops depending on this
# service's own code choosing not to look, and becomes something the kernel
# enforces.
if (( RUNS_NODE )) && [[ -n "$NODE_DIR" && -d "$NODE_DIR" ]]; then
  setfacl -m "u:$ACCOUNT:---" "$NODE_DIR"
  info "$NODE_DIR: $ACCOUNT is refused outright"
  info "  it reads that config only as the wrapper's redacted copy, and judges"
  info "  backups from digests the wrapper computes"
fi

say "Handing over the state it owns"
# State, evidence and the fleet knowledge corpus are the only things it
# writes. Everything else in the repository stays owned by you and read-only
# to it — including advisor/knowledge/, which is your words and stays yours.
for d in "$STATE" "$EVIDENCE"; do
  mkdir -p "$d"
done
# By descriptor, not `chown -R` by name (#1121): both trees are the login's
# until this runs and the Advisor's account writes them from then on, and
# chown -R changes a hard link to a file outside them like any other entry.
# An entry that is a link, or has a second name, is named and left as it is,
# and the move carries on: that is the point of the walk, and the entries
# that matter to the move (reveal.window, the tokens) are re-owned or replaced
# by name-safe steps below.
GIVE_GROUP="$SHARED" GIVE_TOP_MODE=0750 give_trees_back "$ACCOUNT" "$STATE" "$EVIDENCE" \
  || info "the entries named above were left as they were. If the Advisor needs to write one of them it will say so; remove it and run this again."

# The corpus is the one of the three that a SECOND account writes. The
# dashboard promotes a proposal into it while the Advisor replaces it whole
# by rename to apply a bundle (ADR 0017), so handing it over at 0750 like the
# two above locks the dashboard out. That is what #248 was: install.sh runs
# install-aperire-service.sh first, that installer had already made the
# corpus group-writable and setgid, and the line here took the group write
# straight back, so the next Promote was refused on a host both installers
# had just run clean. It left 2750 rather than 0750, because GNU chmod keeps
# a directory's setgid bit for an octal mode: the corpus read as shared while
# one account could write it.
#
# One function decides that shape now, and both installers call it, so the
# order they run in stops mattering. scripts/fleet-corpus-perms.sh has the
# whole decision table.
mkdir -p "$KNOWFLEET/base" "$KNOWFLEET/local"
info "$KNOWFLEET -> $ACCOUNT:$SHARED"
if ! fc_hand_over "$KNOWFLEET" "$ACCOUNT" "$SHARED" "$DASH_USER"; then
  # Never fatal. What a corpus the dashboard cannot write costs is the
  # Promote button, not the Advisor and not this migration; fc_hand_over has
  # already printed which part of it did not land.
  info "NOTE: the fleet corpus was not left writable by $DASH_USER; see above."
fi

# The dashboard reads TWO of the Advisor's tokens through the shared group:
# approve.token (the ceremony) and read.token (the read surface a fleet
# aggregator authenticates against). Both must be group-readable or the service
# that depends on them fails silently — a read.token left at 0600 disables the
# read surface entirely, and the peer's Overview goes dark on the aggregator
# with no error on this side. The `chown -R` above already re-owned them; only
# approve.token used to be re-moded, which is exactly how read.token was left at
# 0600. Both, now. Writable only by the Advisor, never world-readable.
#
# Through state_own_file, never a plain `chown`/`chmod` on the name (#652).
# This directory belongs to the account being built, so the name and the file
# are two different things here: see that function's own header for why a
# descriptor is the only way to change one without the other being able to
# redirect it.
#
# The ids are resolved once, here, and an empty one is fatal rather than
# passed on. state_own_file reads an empty value as "leave this half alone",
# which is right for the undo path's mode-only call and quietly wrong here: a
# getent that answered nothing would hand the token a group and no owner, or
# neither, and report success. The bare `chown` this replaced would have
# failed loudly on the same input.
# ── the install tree above advisor/state (#703) ──────────────────────
#
# Before anything below plants or re-owns a file in there, because every one
# of those runs through scripts/state-file.py and the helper refuses a chain
# whose directories an account other than root or the owner can write. A host
# in that state gets the refusal at the FIRST seal otherwise, which is hours
# later and three hops from the cause.
#
# Found on an aggregator: the install tree was 0775 owner:owner and the
# owner's group held the Advisor's own account, so the Advisor could rename
# a directory root walks through. Neither half is an installer's doing (the
# mode is umask 002, the membership was made by hand), so this repairs rather
# than assumes. Idempotent, and never fatal: it says what is left and the
# refusal names the same script.
if [[ -r "$SELF_DIR/state-ancestors-lib.sh" ]]; then
  # shellcheck source=scripts/state-ancestors-lib.sh
  . "$SELF_DIR/state-ancestors-lib.sh"
  # The helper root runs is the one beside this script, which is the checked
  # copy root staged when it is root, never the tree's (#952).
  STATE_ANCESTORS_TOOL="$SELF_DIR/state-file.py"
  echo "== The install tree above $REPO/advisor/state"
  state_ancestors_narrow "$REPO" "$REPO/advisor/state" || true
fi

tok_uid="$(getent passwd "$ACCOUNT" | cut -d: -f3)"
tok_gid="$(getent group "$SHARED" | cut -d: -f3)"
[[ -n "$tok_uid" && -n "$tok_gid" ]] \
  || precheck_fail "could not resolve $ACCOUNT:$SHARED to a uid and gid, so the Advisor's
   tokens cannot be handed over. Nothing was written to either of them."
for tok in "$TOKEN" "$STATE/read.token"; do
  [[ -e "$tok" || -L "$tok" ]] || continue
  # precheck_fail, not die. This runs AFTER the recursive hand-over of the
  # state directories a few lines up, so on a first run the Advisor's own
  # account already owns $STATE while the unit still names the dashboard's.
  # Stopping with a plain die there would leave exactly the half-moved host
  # #420 is about. This takes the same branch every later check takes: give
  # the grants back on a first run, leave them alone on a re-run, where they
  # belong to the arrangement already running.
  state_own_file "$tok" "$tok_uid" "$tok_gid" 0640 \
    || precheck_fail "$(basename "$tok") could not be handed to $ACCOUNT safely; the line
   above says what was found at $tok. Nothing was written to it and nothing at
   all was done to whatever it points at, though the recursive hand-over just
   above did re-own the link itself along with the rest of the directory.
   Remove or replace that file, then run this script again."
  info "$(basename "$tok") -> 0640 $ACCOUNT:$SHARED, so the dashboard can still read it"
done

# advisor/state/reveal.window (#641), replanted here, never adopted.
#
# Who this touches: scripts/install-advisord.sh is the OTHER planter, always
# root, always `install -o root -m 0640` (a fresh inode every run, never a
# write to one that already exists), and scripts/install-advisor-stack.sh
# runs it immediately before this script whenever the account move is
# requested (the default; run_advisord_install then run_account_install),
# which is what both the documented curl one-liner and
# `install.sh --with-advisor` actually run. dashboard/lib/fleet-write-api.ts's
# readAdvisorRevealWindowFacts, called through server.ts's advisor/reveal
# route, is the only reader, and it trusts nothing about this file beyond
# one lstat: owner root, exactly one name, not group/world-writable, younger
# than 900s.
#
# The `chown -R` a few lines up already took this file from root to
# $ACCOUNT, along with everything else under $STATE, and that is exactly
# backwards for the one file in this directory whose whole point is that
# the account being built here cannot open it. Earlier code put it back to
# root here, on every account move, on whatever it found at this path,
# never checking that was the file install-advisord.sh actually planted.
# The account this move builds owns $STATE outright (0750 $ACCOUNT:$SHARED)
# and can write ordinary files into it, not just symlinks; a file it
# substituted at this path, with a fresh mtime, would have passed every
# check advisorRevealWindowOpen makes once that line handed it back to
# root, on the next unrelated account move (an account rename, a wipe
# reinstall, this project's own "recreate installs if needed" standard).
#
# Recording this file's owner and identity before the `chown -R` above, then
# only re-rooting the same file afterward, was one option, but it rests the
# decision on whether this path was ALREADY root-owned before this script
# touched it, and that branch would go untested (see #420). Unlinking
# whatever is here and replanting a fresh marker needs no such check, and it
# is the same idea install-advisord.sh's own plant already uses for the
# identical file: "this is a clock, and touching it IS the re-arm. Running
# the curl one-liner a second time is exactly how the Add an Advisor card's
# 'the window has closed' copy box tells an operator to recover"
# (install-advisord.sh, beside its own `install -o root` call).
#
# This is a genuine widening, not a free lunch, and worth saying plainly
# rather than past it: every standalone run of THIS script — the repair
# command install-node-wrapper.sh, verify-after-restart.sh and
# aperire-fleet-broker.sh's own error text all tell an operator to run —
# now opens a fresh 900-second window as a side effect, where the old
# re-root code only ever carried an existing window's age through. The
# trade is accepted because the fact the window represents ("a human with
# real sudo stood at this box") is exactly the fact any root-required run
# of this script already proves on its own: `[[ $EUID -eq 0 ]]` above
# refuses anything else, and nothing unattended reaches this script. Traced
# across every caller in this tree (install.sh, get-aperire.sh,
# aperire-update.sh, the credcheck OnFailure unit, aperire-fleet-broker.sh,
# install-node-wrapper.sh): the one automated path that runs install.sh at
# all is aperire-update.sh's rollback, and its own call deliberately omits
# --with-advisor by name (aperire-update.sh, beside that call) so it never
# reaches install-advisor-stack.sh or this script; every other appearance
# of this script's name in that search is a printed remedy or a comment,
# never an execution. So the only way to open a window here is the same
# sudo an operator was always going to type to run this script for some
# other reason, which is the same bar the window already stood on.
#
# It also keeps the happy path intact: install-advisor-stack.sh runs
# install-advisord.sh's plant and this move back to back in one invocation,
# so the window this line opens is, in the ordinary case, the very one that
# plant just opened, replanted rather than merely carried through.
#
# Planted on a descriptor, not with `install` (#661). This line read
# `install -o root -g <gid> -m 0640 /dev/null "$STATE/reveal.window"` until
# that residual was closed, on the reasoning that one process leaves no gap
# for a racer. It leaves one: GNU install opens the file O_CREAT|O_EXCL and
# then sets its owner and mode through the PATH again (strace, coreutils 9.4:
# openat O_EXCL, fchmod(fd), fchownat(path, AT_SYMLINK_NOFOLLOW),
# fchmodat(path) with no nofollow flag at all). The account that owns $STATE
# can unlink the fresh file and put a symlink at the same name inside that
# window, and root's last call then chmods the link's target to 0640. The
# racer in scripts/test-install-advisor-account.sh wins that most attempts,
# 39 to 150 out of 150 across runs, on this project's box and on a two-core
# CI runner. The
# descriptor path has no second lookup to win: the file is created relative
# to a directory descriptor, owned and moded on the descriptor the create
# returned, and renamed onto this name with renameat, which follows neither
# side.
#
# Numeric gid, not the name `$SHARED` resolves to, for the same reason
# state_own_file takes numeric ids: `getent` above is the one name lookup
# this script trusts, it runs after the group-creation block has made
# `$SHARED` real, and the helper then needs no name service of its own.
shared_gid="$(getent group "$SHARED" | cut -d: -f3)"
[[ -n "$shared_gid" ]] || die "the group $SHARED has no gid, so the reveal window has no group to be read through"
state_plant_file "$STATE/reveal.window" 0 "$shared_gid" 0640 \
  || die "could not plant $STATE/reveal.window"
info "reveal.window replanted: root:$SHARED 0640, fresh as of this run"

# And the fleet trust file, for the same reason and a costlier failure.
#
# advisord verifies every pushed credential bundle against the aggregator's
# public key, which lives nowhere else but here. Leave this owned and grouped
# to the dashboard user — its shape before this script ran — and the account
# created above cannot open it. Every push then fails with a 403 naming a path,
# and the operator meets that as "your passkey is not enrolled" at a ceremony
# on a node that looked healthy. That is the 2026-08-19 stock-node2 failure,
# and it survived because nothing checked.
#
# But on an aggregator the same file holds the private key that signs every
# bundle and job, and the account created above has no business reading that
# (#868, ADR 0024 row 19). So the file is split: a file with a private_key
# stays the dashboard user's alone at 0600, and fleet-trust.pub.yaml beside
# it carries the public half and the same peers, root:$SHARED 0640 (root
# creates it; the dashboard account never needs it), for this account. A node's
# file holds no key and is root's, on $SHARED, 0640 (it is made root's here when
# the dashboard runs as an account of its own, #1187). fleet-trust-split.sh does
# both, through
# state-file.py, so no root chown here follows a name the dashboard account
# can swap.
if [[ -e "$REPO/dashboard/config/fleet-trust.yaml" ]]; then
  fts_rc=0
  # This run restarts the Advisor on its unit's binary further down, so the
  # key is narrowed when that binary reads the public file, whatever process
  # is running right now.
  fts_out="$(FTS_ADVISOR_UNIT="$UNIT_NAME" FTS_UNIT_DIR="$UNIT_DIR" FTS_ADVISOR_RESTARTING=1 \
    fts_converge "$REPO" "$DASH_USER" "$SHARED" "$STATE_FILE_TOOL" 2>&1)" || fts_rc=$?
  while IFS= read -r _l; do [[ -n "$_l" ]] && info "$_l"; done <<<"$fts_out"
  # Not fatal: the public file is written before the key file is narrowed,
  # so a run that stops here has changed nothing the Advisor relies on. Not
  # quiet either: verify-after-restart.sh goes red on the same shape.
  (( fts_rc == 0 )) \
    || info "WARNING: fleet-trust.yaml is not in its target shape (above). Once fixed: curl -fsSL https://get.aperire.one | bash -s -- --update --force"
else
  info "no dashboard/config/fleet-trust.yaml yet. The pairing grant or aperire-fleet-add.sh makes it"
fi

if (( HAS_NODE )); then
  say "One socket, one account, one program behind it"
  # The only way this account reaches root (ADR 0025). The socket is root's
  # with this account's own group, mode 0660, so no other account can open
  # it; the broker behind it checks the caller's uid as well, takes one verb
  # from a fixed table with no paths and no free-form words, and runs the
  # wrapper copy placed above. Nothing here is a sudo rule: this account
  # holds none, and its unit runs NoNewPrivileges.
  # Set before the write, not after: a socket that is written and then fails
  # its read-back is this run's to take back too.
  SOCKET_WRITTEN=1
  trusted_write_socket_units "$INSTANCE" "$ACCOUNT" \
    || precheck_fail "the Advisor's socket did not come up as written; the lines above say
   what was found. Read: systemctl status $(trusted_socket_unit "$INSTANCE")"
  info "$SOCK: $ACCOUNT alone may connect"
fi

say "Proving it works before touching the running service"
# Everything above is reversible and has not affected the running Advisor. The
# checks below establish that the new arrangement can work at all — so a
# problem here costs nothing, instead of being discovered by a service that
# will not come back up.
# Defined above, beside the first thing that can call it (#652): the token
# hand-over can refuse, and it has to refuse the same way every later check
# does rather than leaving a half-handed-over state directory behind.

runuser -u "$ACCOUNT" -- test -x "$REPO/advisor/bin/aperire-advisord" \
  || precheck_fail "$ACCOUNT still cannot reach its own binary at $REPO/advisor/bin/aperire-advisord"
info "can reach its binary"

runuser -u "$ACCOUNT" -- test -w "$STATE" \
  || precheck_fail "$ACCOUNT cannot write its own state directory"
info "can write its state"

# One call through the socket with the Advisor's own client, as an account,
# and under no_new_privs where this host can set it: the state systemd 249
# forces on the unit below, and the one sudo could never work in. Run as the
# account, never as root: it is the tree's binary.
NNP=()
if command -v setpriv >/dev/null 2>&1 && setpriv --no-new-privs true 2>/dev/null; then
  NNP=(setpriv --no-new-privs)
fi
call_as() { # $1 = account, rest = the verb and its words
  local who="$1"; shift
  runuser -u "$who" -- "${NNP[@]}" "$REPO/advisor/bin/aperire-advisord" \
    --wrapper="$WRAPPER" --wrapper-socket="$SOCK" --wrapper-call "$@"
}

# The verb every probe of the socket asks. `resources` answers on every host
# shape: it reads memory and load, needs no node, and the wrapper serves it
# with SERVICE=none as with a node. A node verb (`inspect` was the one) is
# refused by the wrapper itself on a host with no node, so a probe asking one
# there could never pass and every aggregator's move reverted (#806). The
# node verbs are proven further down, on a host that runs one.
PROBE_VERB=resources

if (( HAS_NODE )); then
  # The one that matters most: the socket actually answers this account, and
  # the wrapper answers behind it. Without this the service starts and then
  # cannot reach root at all, which is what a namespace failure looks like
  # from the outside and is much harder to tell apart.
  if ! call_as "$ACCOUNT" "$PROBE_VERB" >/dev/null 2>&1; then
    precheck_fail "$ACCOUNT cannot reach the wrapper through its socket.
   Try it by hand to see why:
     sudo runuser -u $ACCOUNT -- $REPO/advisor/bin/aperire-advisord --wrapper=$WRAPPER --wrapper-socket=$SOCK --wrapper-call $PROBE_VERB"
  fi
  info "reaches the wrapper through its socket, and it answered"

  # And nobody else does. The dashboard's account is the one most worth
  # proving: it shares a group with this one for the tokens, and must not
  # share this. Asked with the same verb, one the wrapper answers here, so a
  # refusal can only be the socket's or the broker's. Asked with a node verb
  # on a host with no node, the wrapper's own refusal passed this check
  # whether the socket admitted the dashboard or not.
  if [[ "$DASH_USER" != root ]] && call_as "$DASH_USER" "$PROBE_VERB" >/dev/null 2>&1; then
    precheck_fail "$DASH_USER, the dashboard's account, reached the wrapper through $SOCK.
   Only $ACCOUNT may. Read: stat $SOCK; systemctl cat $(trusted_socket_service "$INSTANCE")"
  fi
  info "$DASH_USER cannot reach it"
fi

# The one docker query in this tree that is right to read a failure as its
# answer, and worth saying why (#142). Everywhere else the question is "what
# is running here", where a refusal is not an absence. Here the question is
# "can this account run docker", and a refusal IS the answer: it is what the
# account is supposed to meet. The case that would make it a lie, a daemon
# that is down making an account in the docker group look walled off, is not
# left to this call: in_docker_group above refuses that account outright, and
# reads group membership rather than the daemon.
if runuser -u "$ACCOUNT" -- docker ps >/dev/null 2>&1; then
  precheck_fail "$ACCOUNT can reach Docker directly, which defeats the whole arrangement"
fi
info "cannot reach Docker directly"

if (( RUNS_NODE )); then
  NODE_CFG=$(wconf_value CONFIG_FILE)
  if runuser -u "$ACCOUNT" -- test -r "$NODE_CFG" 2>/dev/null; then
    precheck_fail "$ACCOUNT can still read $NODE_CFG directly.
   Everything it needs from that file comes through the wrapper now, so this
   should be refused. Check with:  getfacl $NODE_DIR"
  fi
  info "cannot read the node config directly"

  # The check above is satisfied by the directory ACL alone, so it would pass on
  # a config that is still readable by everyone — the account simply cannot walk
  # to it by that path. A file open to the world is open by any other path to it,
  # so assert the file's own mode too.
  CFG_MODE=$(stat -c '%a' "$NODE_CFG" 2>/dev/null || echo "")
  if [[ "${CFG_MODE: -1}" =~ [4567] ]]; then
    if [[ "$CONFIG_CLOSED" -eq 1 ]]; then
      precheck_fail "$NODE_CFG is still mode $CFG_MODE — readable by every account
   on this host — even though closing it reported success. The directory ACL
   hides it from one path, not from all of them."
    fi
    info "NOTE: $NODE_CFG is mode $CFG_MODE, readable by every account here."
    info "  The directory ACL keeps $ACCOUNT from walking to it, but the file"
    info "  itself is open. With the node running:"
    info "    curl -fsSL https://get.aperire.one | bash -s -- --run node-config-exposure --account $ACCOUNT --apply"
  else
    info "the node config is mode $CFG_MODE — not readable by other accounts"
  fi

  # And the route that replaces it. Refusing the directory must not cost the
  # upgrade path its rollback precondition.
  if ! call_as "$ACCOUNT" artefact-hashes node-config >/dev/null 2>&1; then
    precheck_fail "$ACCOUNT cannot get config digests through the wrapper, so the
   upgrade path would fail its own rollback precondition. Try it by hand:
     sudo runuser -u $ACCOUNT -- $REPO/advisor/bin/aperire-advisord --wrapper=$WRAPPER --wrapper-socket=$SOCK --wrapper-call artefact-hashes node-config"
  fi
  info "can judge backups from wrapper-computed digests"

  # And the check that matters: what the model is shown has the token removed.
  # Root runs the root-owned copy directly here; it is the same program the
  # socket runs.
  if "$WRAPPER" show-config 2>/dev/null | grep -qE '^[A-Za-z0-9+/]{40,}={0,2}$'; then
    precheck_fail "show-config returned something shaped like key material; the redaction is not holding"
  fi
  info "the redacted config carries no key material"
fi

if runuser -u "$ACCOUNT" -- ls "$HOME_DIR" >/dev/null 2>&1; then
  precheck_fail "$ACCOUNT can list $HOME_DIR; the traversal ACL granted more than passage"
fi
info "cannot list $HOME_DIR — passage only"

# The checks above ran as the account but NOT inside the sandbox the unit will
# impose. That gap is exactly where the first attempt at this failed: the
# account was fine, and the unit still died at 226/NAMESPACE because a mount
# option removed the directories out from under it. So run the real thing in a
# throwaway unit carrying the same properties first, NoNewPrivileges and the
# syscall filter included, which is the state sudo could never work in on
# systemd 249 and the socket has to. If the sandbox is wrong, this is where it
# shows, and the Advisor has not been stopped.
# The knowledge swap is rehearsed here and not only the writable state dir:
# applying a bundle renames directories INSIDE knowledge-fleet, and a unit
# that grants the wrong path fails that rename after a push has already
# verified — on the node, where it reads as a broken aggregator.
say "Proving the sandbox itself works"
if ! command -v systemd-run >/dev/null; then
  info "systemd-run not available; skipping the sandbox rehearsal"
else
  SANDBOX_LOG=$(mktemp)
  REHEARSE="test -w '$STATE' && mkdir '$KNOWFLEET/.rehearsal' && mv '$KNOWFLEET/.rehearsal' '$KNOWFLEET/.rehearsal2' && rmdir '$KNOWFLEET/.rehearsal2'"
  if (( HAS_NODE )); then
    REHEARSE="'$REPO/advisor/bin/aperire-advisord' --wrapper='$WRAPPER' --wrapper-socket='$SOCK' --wrapper-call $PROBE_VERB >/dev/null && $REHEARSE"
  fi
  if systemd-run --quiet --wait --collect --pipe \
       --uid="$ACCOUNT" \
       --property=ProtectSystem=strict \
       --property=ProtectHome=read-only \
       --property=PrivateTmp=true \
       --property=NoNewPrivileges=true \
       --property=RestrictSUIDSGID=true \
       --property=CapabilityBoundingSet= \
       --property="RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6" \
       --property=SystemCallArchitectures=native \
       --property=SystemCallFilter=@system-service \
       --property="SystemCallFilter=~@privileged @resources" \
       --property="SystemCallFilter=setrlimit prlimit64 chown fchown fchownat lchown" \
       --property=ReadWritePaths="$STATE $EVIDENCE $KNOWFLEET" \
       --property=WorkingDirectory="$REPO/advisor" \
       -- /bin/sh -c "$REHEARSE" \
       >"$SANDBOX_LOG" 2>&1; then
    if (( HAS_NODE )); then
      info "the socket, the wrapper, a writable state directory and a knowledge swap all work inside the sandbox, NoNewPrivileges included"
    else
      info "a writable state directory and a knowledge swap work inside the sandbox, NoNewPrivileges included"
    fi
    rm -f "$SANDBOX_LOG"
  else
    printf '\n   what the rehearsal reported:\n'
    sed 's/^/     /' "$SANDBOX_LOG" | head -12
    rm -f "$SANDBOX_LOG"
    precheck_fail "the sandbox the unit would impose breaks the service.
   Nothing was changed about the running Advisor. The output above is from a
   throwaway unit carrying the same settings."
  fi
fi

say "The recovery unit OnFailure= is about to name"
# Written, or refreshed, before the unit below can name it (P2-093): the
# unit this script writes carries OnFailure=$CREDCHECK_UNIT_NAME.service a
# few lines down, and a host that reaches this script before
# install-advisord.sh has ever run would otherwise get that reference with
# nothing behind it.
# Status 1 whatever the cause: the place helper returns 6 for the account check
# not running (#1111), which the update path tells apart, and this script's own
# exit status is not that contract.
write_advisord_credcheck_unit "$REPO" "$UNIT_DIR" "$CREDCHECK_UNIT_NAME" "$INSTANCE" || exit 1

say "Rewriting the unit"
# What a failed check below puts back: this unit exactly as it is now. It is
# NOT $BACKUP. That file is the unit from before the ACCOUNT MOVE, and on a
# re-run restoring it would put a working dedicated-account Advisor back on
# the operator's account with no socket, while every grant it needs stays
# granted. Held outside /etc/systemd/system so nothing else on this host
# has to learn to clean it up.
PRE_RUN_UNIT=$(mktemp)
trap 'rm -f "$PRE_RUN_UNIT"' EXIT
cp -a "$UNIT" "$PRE_RUN_UNIT"

# The marker, written once and never again.
#
# install-advisord.sh:375 reads this file as the marker that the account move
# happened and refuses to rewrite the unit while it is there; harden-advisord.sh
# :58 refuses on it too; verify-after-restart.sh:147 concludes from it; and this
# script prints "sudo cp -a $BACKUP $UNIT" as the documented undo. Rewriting it
# on every run made it "the unit before the LAST run" instead, so after the run
# that found #461 it held the unit with the dead port, and the undo would have
# put that back.
#
# What that file holds is read rather than assumed. Every host that ran this
# script twice before this change has a copy from the LAST run in it, which on
# a host that had already moved is the hardened unit, account and all. Keeping
# it is still right, it is the only copy there is, but calling it "the unit
# from before the move" would be this script claiming content it never opened.
MARKER_WRITTEN=0
KEPT_POST_MOVE=0
# On a fresh host the copy kept here is the waiting unit itself: it already
# names the account, so there was no earlier unit to keep (#898 review, L2).
KEPT_WAITING=0
if [[ -e "$BACKUP" ]]; then
  KEPT_USER=""
  [[ -r "$BACKUP" ]] && KEPT_USER=$(awk -F= '/^User=/{print $2; exit}' "$BACKUP")
  grep -q '^# Waiting for install-advisor-account\.sh' "$BACKUP" 2>/dev/null && KEPT_WAITING=1
  info "a copy of the unit is already kept at $BACKUP; left as it is"
  if (( KEPT_WAITING )) && [[ -f "$LOGIN_COPY" ]]; then
    info "  it is the waiting unit the stack wrote, already naming $ACCOUNT:"
    info "  copying it back starts nothing that works. The unit that named the login"
    info "  before the stack replaced it is kept at $LOGIN_COPY."
  elif (( KEPT_WAITING )); then
    info "  it is the waiting unit a fresh install wrote, already naming $ACCOUNT:"
    info "  there was no earlier unit to restore, and copying it back starts nothing"
    info "  that works."
  elif [[ -n "$KEPT_USER" && "$KEPT_USER" == "$ACCOUNT" ]]; then
    KEPT_POST_MOVE=1
    info "  it names User=$KEPT_USER, so it is from a run after the account move"
    info "  and not from before it: restoring it by hand puts back a unit that"
    info "  still runs as $ACCOUNT."
  fi
else
  cp -a "$UNIT" "$BACKUP"
  MARKER_WRITTEN=1
  if (( WAS_WAITING )); then
    KEPT_WAITING=1
    if [[ -f "$LOGIN_COPY" ]]; then
      info "the waiting unit kept at $BACKUP already named $ACCOUNT; the unit that"
      info "named the login before the stack replaced it is kept at $LOGIN_COPY"
    else
      info "the waiting unit kept at $BACKUP: this host had no earlier unit, the"
      info "one install-advisord.sh wrote already named $ACCOUNT"
    fi
  else
    info "the unit from before the account move kept at $BACKUP"
  fi
fi

CREDS=$(grep -E '^LoadCredential' "$UNIT" || true)
{
  printf '[Unit]\n'
  printf 'Description=Aperire Advisor (read-only state service)\n'
  printf 'After=network-online.target\nWants=network-online.target\n'
  # Same two inequalities, same numbers, as install-advisord.sh's own
  # template (#541 P1-091): RestartSec * (Burst - 1) < StartLimitIntervalSec
  # so the limit is reachable (3 * 4 = 12 < 30), and RestartSec * (Burst - 1)
  # >= the longest legitimate transient so an ordinary reboot does not land
  # here on its own: advisord's own startup (token, read token, bind) is
  # all local and does not wait on the dashboard, so 12s of runway is not
  # racing a cold dashboard start. A credential that will not decrypt on
  # this host lands the unit in `failed` instead of restarting every three
  # seconds forever, and OnFailure= hands it to the one program that tells
  # that failure apart from every other kind.
  printf 'StartLimitIntervalSec=30\nStartLimitBurst=5\n'
  printf 'OnFailure=%s.service\n\n' "$CREDCHECK_UNIT_NAME"
  printf '[Service]\n'
  if [[ -n "$CREDS" ]]; then printf '%s\n' "$CREDS"; fi
  printf 'Type=simple\n'
  printf 'User=%s\nGroup=%s\n' "$ACCOUNT" "$ACCOUNT"
  printf 'SupplementaryGroups=%s\n' "$SHARED"
  printf 'WorkingDirectory=%s/advisor\n' "$REPO"
  # --wrapper-socket is what makes the docker group unnecessary: the one
  # docker read this service performs goes through the wrapper like everything
  # else, and the wrapper is reached through its root socket (ADR 0025). A host
  # with no node names neither: there is nothing for a wrapper to act on.
  WRAPPER_FLAGS=""
  if (( HAS_NODE )); then WRAPPER_FLAGS=" --wrapper=$WRAPPER --wrapper-socket=$SOCK"; fi
  printf 'ExecStart=%s/advisor/bin/aperire-advisord --addr=127.0.0.1:%s%s --dash-read-url=http://127.0.0.1:%s --state=%s/advisor/state%s\n' \
    "$REPO" "$ADVISOR_PORT" "${NODE_CONTAINER:+ --container=$NODE_CONTAINER}" "$DASH_PORT" "$REPO" "$WRAPPER_FLAGS"
  printf 'Restart=always\nRestartSec=3\n'
  # The service drains on SIGTERM — it finishes the questions already running,
  # up to 60 seconds. This must stay LARGER than that window, or systemd
  # SIGKILLs through the drain and the answer is lost anyway.
  printf 'TimeoutStopSec=75\n\n'
  # Everything is read-only except the three directories this service owns.
  # Reaching them at all depends on the traversal ACL granted above; this only
  # decides what is writable once reached.
  #
  # Not the node's directories and not /var/lib/aperire, which this unit named
  # while the wrapper ran through sudo as a child of it and so inside its mount
  # namespace. The wrapper runs in its own root service behind the socket now
  # (ADR 0025), so this service needs no write anywhere it does not own.
  printf 'ReadWritePaths=%s/advisor/state %s/advisor/evidence %s/advisor/knowledge-fleet\n' "$REPO" "$REPO" "$REPO"
  # True on every systemd, 249 included. It used to have to stay false, because
  # sudo was the only way this service reached the node and sudo refuses under
  # it. Connecting to a socket needs no privilege at all.
  printf 'NoNewPrivileges=true\n'
  printf 'PrivateTmp=true\n'
  # 0027: files 0640, directories 0750. Without it the service creates
  # world-readable files by default, and what this one creates is the audit
  # ledger, the run transcripts and the credential store. systemd-analyze
  # flags the omission by name.
  printf 'UMask=0027\n'
  printf 'ProtectSystem=strict\n'
  # read-only, NOT tmpfs. tmpfs replaces /home with an empty filesystem before
  # ReadWritePaths is applied, so state and evidence — which live under it —
  # stop existing inside the namespace and the unit dies with 226/NAMESPACE
  # before it runs a line of code. read-only leaves the tree visible and lets
  # ReadWritePaths punch through for the two directories that need writing.
  # The account still cannot READ anything else under there: that is enforced
  # by the traversal ACL above, which is a permission, not a mount option.
  printf 'ProtectHome=read-only\n'
  printf 'ProtectKernelTunables=true\n'
  printf 'ProtectKernelModules=true\n'
  printf 'ProtectKernelLogs=true\n'
  printf 'ProtectControlGroups=true\n'
  printf 'ProtectClock=true\n'
  printf 'RestrictSUIDSGID=true\n'
  printf 'RestrictNamespaces=true\n'
  printf 'LockPersonality=true\n'
  printf 'CapabilityBoundingSet=\n'
  printf 'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\n'
  printf 'SystemCallArchitectures=native\n'
  # The same filter install-advisord.sh writes, and the same two exceptions
  # for the same reasons (the Go runtime raises RLIMIT_NOFILE at start;
  # the service sets the group on the tokens it writes). It could not be
  # here while the node was reached through sudo, which is setuid and PAM.
  # Through the socket it is one connect(), and the filter runs on systemd
  # 249 as it does on 255.
  printf 'SystemCallFilter=@system-service\n'
  printf 'SystemCallFilter=~@privileged @resources\n'
  printf 'SystemCallFilter=setrlimit prlimit64 chown fchown fchownat lchown\n'
  printf '\n'
  printf '[Install]\n'
  printf 'WantedBy=multi-user.target\n'
} > "$UNIT"
chmod 644 "$UNIT"

revert() {
  printf '\n\033[1;31m== Reverting\033[0m\n'
  cp "$PRE_RUN_UNIT" "$UNIT"
  chmod 644 "$UNIT"
  if (( MARKER_WRITTEN )); then
    # This run wrote it and this run did not finish, so the move it claims did
    # not happen. Left behind, it would stop install-advisord.sh from ever
    # rewriting this unit again.
    rm -f "$BACKUP"
    info "the marker this run wrote at $BACKUP is gone with it: the move did not happen here."
  fi
  if (( PREINSTALLED )); then
    # The grants below are not this run's to take back: the service that was
    # already here runs on them. See PREINSTALLED above. That includes a sudo
    # rule an older release wrote: this run removes it only at the very end,
    # after the Advisor is back on the socket, so it is still here.
    info "the unit is back. The socket, any sudo rule an older release left,"
    info "the traversal ACL and the state ownership are left alone: they belong"
    info "to the arrangement that was already on this host, not to this run."
  else
    take_back_socket
    setfacl -n -x "u:$ACCOUNT" "$HOME_DIR" 2>/dev/null || true
    if [[ -d "$NODE_DIR" ]]; then setfacl -n -x "u:$ACCOUNT" "$NODE_DIR" 2>/dev/null || true; fi
    give_trees_back "$TREE_OWNER" "$STATE" "$EVIDENCE" "$KNOWFLEET" || true
    # Through state_own_file, never a bare chmod on the name (#652). This
    # undo runs when a RE-RUN fails, so $STATE may already belong to a live
    # Advisor account from an earlier successful move, which is the same
    # window #420 itself is about: a symlink swapped onto $TOKEN in it would
    # have a bare chmod force mode 0600 onto whatever root-owned file it
    # names. A refusal here is not fatal, unlike the token loop above: this
    # path is already reverting, and the message it is about to die with is
    # the one worth reading.
    state_own_file "$TOKEN" "" "" 0600 || true
  fi
  systemctl daemon-reload
  if (( WAS_WAITING )); then
    # The previous state was stopped: the unit names an account that owned
    # nothing until this run. Starting it is a crash loop that returns at
    # every boot, so it is stopped and not enabled until the move is done.
    leave_waiting_unit_stopped "the waiting unit is back, as it was before this run"
  else
    advisord_reset_and_restart "${UNIT_NAME}" || true
    command sleep 4
    if systemctl is-active --quiet "${UNIT_NAME}"; then
      info "the previous arrangement is back and the service is running."
    else
      info "the previous unit is back but the service is NOT running. Check:"
      info "  journalctl -u ${UNIT_NAME} -n 40 --no-pager"
    fi
  fi
  if (( PREINSTALLED )); then
    info "$ACCOUNT still owns $STATE and $EVIDENCE, still reaches whatever it"
    info "reached before, and still passes through $HOME_DIR. Those are the"
    info "same things it had before this run started."
  else
    info "the $ACCOUNT account was left in place; it owns nothing now."
  fi
  die "$1"
}

say "Restarting"
systemctl daemon-reload
advisord_reset_and_restart "${UNIT_NAME}"
# A unit written waiting is enabled by install-advisord.sh, and an undo of an
# earlier run of this script disables it again. Enabled here, once it has been
# started as the account, so it comes back after a boot either way.
if (( WAS_WAITING )); then systemctl enable "${UNIT_NAME}" >/dev/null 2>&1 || true; fi
command sleep 5

# ── Verification. Each check is one thing that must still be true, and one
# thing that must now be false. Writing the unit is not the same as it working.
say "Checking the new arrangement"
# Read through state-file.py, not by name (#703 item 5). The directory this
# run has just handed to the Advisor's own account is the directory this
# token sits in, so from here on a plain redirect is root following a link
# that account chose, and the first line of whatever it points at would go
# out as a bearer token.
TOK=$(python3 -I "$STATE_FILE_TOOL" read "$TOKEN" 2>/dev/null | tr -d '\n' || true)
[[ -n "$TOK" ]] || revert "could not read the service token to run the checks"

systemctl is-active --quiet "${UNIT_NAME}" \
  || revert "the service did not come back up as $ACCOUNT"
info "running as $(systemctl show "$UNIT_NAME" -p User --value)"

# The token reaches curl on its standard input (-H @-), never on its argv,
# where any account on the host can read it in /proc (#705).
curl -sf -o /dev/null -H @- "http://127.0.0.1:${ADVISOR_PORT}/v1/status" <<<"authorization: Bearer $TOK" \
  || revert "the service is up but /v1/status did not answer"
info "answers on loopback"

# The important one. The profile comes from a read this account can no longer
# make on its own, `docker inspect` on a container host and `systemctl show`
# plus the package database on a native one, so a profile here proves the
# wrapper route works.
#
# Which field carries the node's identity depends on the shape. A native
# profile has no container and never will: its identity is the unit and the
# package (#30, #397). Asking for a container on a native host got an empty
# string, read that as "the wrapper route is broken", and reverted a run that
# had in fact worked, on a lab host during the native lab.
#
# Read from /v1/status, not /v1/check. The check endpoint answers a different
# question, whether a newer node release exists, and on a native host it
# refuses outright because the release registry it asks is keyed on an image
# repository. That refusal says nothing about whether this account can read
# the deployment, which is the only thing being proven here.
#
# Only where a node runs. On a host with SERVICE=none there is no deployment
# to profile, the status carries none, and reading that as a broken route
# reverted a move that had worked (#806). Its socket was proven above, with
# the same verb, as this account and inside the sandbox.
if (( RUNS_NODE )); then
  PROFILE=$(curl -s -H @- "http://127.0.0.1:${ADVISOR_PORT}/v1/status" <<<"authorization: Bearer $TOK" \
    | python3 -I -c 'import sys,json
p = (json.load(sys.stdin).get("profile") or {})
print((p.get("unit") or "") if p.get("kind") == "native" else (p.get("container") or ""))' 2>/dev/null || true)
  [[ -n "$PROFILE" ]] \
    || revert "the service can no longer read the deployment through the wrapper — check:
     sudo runuser -u $ACCOUNT -- $REPO/advisor/bin/aperire-advisord --wrapper=$WRAPPER --wrapper-socket=$SOCK --wrapper-call inspect"
  info "reads the deployment through the wrapper's socket, with no docker access and no sudo ($PROFILE)"
fi

# And the thing that must now be impossible. Same reading as the precheck
# above: the question is the account's capability, so a docker that refuses
# it is the answer rather than an absence, and group membership is checked
# separately where a stopped daemon cannot flatter it.
if runuser -u "$ACCOUNT" -- docker ps >/dev/null 2>&1; then
  revert "$ACCOUNT can still reach Docker directly, which defeats the whole arrangement"
fi
info "cannot reach Docker directly — confirmed"

# The dashboard has to keep working, or the tab goes dark.
DASH_OK=no
if [[ "$DASH_USER" != "root" ]] && runuser -u "$DASH_USER" -- test -r "$TOKEN"; then DASH_OK=yes; fi
[[ "$DASH_OK" == yes ]] \
  || revert "$DASH_USER can no longer read the service token, so the dashboard cannot reach the Advisor"
info "$DASH_USER can still read the service token"

# The sudo rule an older release wrote, gone now that the Advisor has come
# back on the socket and answered through it (ADR 0025). Last, so every undo
# above could still hand a reverted unit the rule it was started with.
if [[ -e "$SUDOERS" || -L "$SUDOERS" ]]; then
  rm -f -- "$SUDOERS"
  info "removed $SUDOERS: the Advisor holds no sudo rule"
fi

# The fleet's node tokens, moved onto the group the Advisor now shares with the
# dashboard (#1024). An aggregator's /etc/aperire/fleet-tokens was written
# before this Advisor existed, so its entries are on the dashboard's own group
# and the Advisor, joining aperire-svc, cannot read a single one. Added to an
# aggregator that already has nodes, the first Advisor reached none of them
# until somebody ran a regroup by hand.
#
# By descriptor, never by name: the broker writes into this directory as root
# on the dashboard account's behalf, and a chown -R by name over a tree an
# account can write follows whatever that account swaps in. state-file.py
# own-many walks each path component by component, opens it O_NOFOLLOW and
# re-owns the descriptor, so a link at any name is refused and named. Only the
# group changes; owner and mode stay as the broker set them. The directory and
# the files directly in it, as install-aperire-service.sh gives them back the
# other way when an Advisor-only uninstall removes this group.
#
# After the early check on the running dashboard (#996, #1035), and not before:
# the dashboard reads these on every call through its group list, so moving
# them to a group it was not yet in would drop its fleet reads. That check has
# restarted a dashboard that lacked the group, or found one that holds it. The
# one case it cannot settle is /proc not saying (no running dashboard, or
# nothing to read), where the restart at the end follows this; with no process
# to answer from, there is no read to drop in the meantime.
_ft_dir=/etc/aperire/fleet-tokens
if [[ "$DASH_USER" != "root" && -d "$_ft_dir" && ! -L "$_ft_dir" && "$tok_gid" =~ ^[0-9]+$ ]]; then
  _ftl=()
  mapfile -d '' _ftl < <(find "$_ft_dir" -maxdepth 1 \( -type d -o -type f \) ! -gid "$tok_gid" -print0 2>/dev/null)
  if (( ${#_ftl[@]} )); then
    say "Giving the Advisor the fleet's node tokens"
    if printf '%s\0' "${_ftl[@]}" | python3 -I "$STATE_FILE_TOOL" own-many "" "$tok_gid" "" --root "$(dirname "$_ft_dir")"; then
      info "$_ft_dir: ${#_ftl[@]} entr$( (( ${#_ftl[@]} == 1 )) && echo y || echo ies) now on $SHARED, so the Advisor reads every node's token"
    else
      info "NOTE: some of $_ft_dir could not be moved onto $SHARED (named above);"
      info "the Advisor cannot read those nodes' tokens until they are."
    fi
  fi
fi

say "Done"
if (( RUNS_NODE )); then
  info "the Advisor runs as $ACCOUNT with NoNewPrivileges, holds no sudo rule,"
  info "and reaches the node only through $SOCK, where root runs the wrapper."
elif (( HAS_NODE )); then
  info "the Advisor runs as $ACCOUNT with NoNewPrivileges and no sudo rule."
  info "There is no node here; it reads this host (unit state, the journal,"
  info "memory, disk) only through $SOCK, where root runs the wrapper."
else
  info "the Advisor runs as $ACCOUNT with NoNewPrivileges and no sudo rule."
  info "There is no node here, so it has no socket and no wrapper to reach."
fi
info ""
info "Your own shell will not see the $SHARED group until it is replaced."
info "Group membership is fixed when a process is created, so an SSH session"
info "that was open before this ran keeps the list it started with — and \`id\`"
info "will disagree with itself: \`id -nG $DASH_USER\` reads the group file and"
info "says yes, \`id -nG\` reports this process and says no."
info ""
info "The services are unaffected either way; systemd starts them fresh. What"
info "you will notice is reading advisor/state, advisor/evidence, or running"
info "\`go build ./...\` in advisor/, which walks into evidence/."
info ""
info "  log out and back in                     — permanent"
info "  newgrp $SHARED                    — a subshell with the group"
info "  sg $SHARED -c '<command>'         — one command with the group"
info ""
info "If you use tmux or screen, a new pane inherits from the server process,"
info "which is also older than the group. Restart the server, or reconnect."
info ""
if (( KEPT_WAITING )) && [[ -f "$LOGIN_COPY" ]]; then
  info "the copy kept at $BACKUP is the waiting unit the stack wrote, and it"
  info "already names $ACCOUNT, so putting it back starts nothing that works."
  info "The Advisor you had before the stack is the unit kept at:"
  info "  $LOGIN_COPY"
  info "to go back to it by hand:"
  info "  sudo cp -a $LOGIN_COPY $UNIT"
  info "  sudo systemctl disable --now $(trusted_socket_unit "$INSTANCE")"
  info "  curl -fsSL https://get.aperire.one | bash -s -- --run advisor-account --hand-trees-back${INSTANCE:+ --instance $INSTANCE}"
  info "  sudo systemctl daemon-reload && sudo systemctl restart ${UNIT_NAME}"
  info "To take the Advisor off the host instead, use the uninstaller:"
  info "  curl -fsSL https://get.aperire.one/uninstall | bash -s -- --role=advisor"
elif (( KEPT_WAITING )); then
  info "there was no earlier unit to restore: the copy kept at $BACKUP is the"
  info "waiting unit a fresh install wrote, and it already names $ACCOUNT, so"
  info "putting it back would start a service that cannot work. To take the"
  info "Advisor off the host, use the uninstaller:"
  info "  curl -fsSL https://get.aperire.one/uninstall | bash -s -- --role=advisor"
elif (( KEPT_POST_MOVE )); then
  info "the kept copy of the unit is at:"
  info "  $BACKUP"
  info "it is from a run after the account move, as the line above said, so the"
  info "commands below restore a unit that still runs as $ACCOUNT. Undoing the"
  info "move itself means the three lines under it, and a unit written by"
  info "scripts/install-advisord.sh with this file removed first."
else
  info "the unit from before the account move is kept at:"
  info "  $BACKUP"
fi
if (( ! KEPT_WAITING )); then
  info "to undo by hand:"
  info "  sudo cp -a $BACKUP $UNIT"
  if (( HAS_NODE )); then
    info "  sudo systemctl disable --now $(trusted_socket_unit "$INSTANCE")"
  fi
  info "  curl -fsSL https://get.aperire.one | bash -s -- --run advisor-account --hand-trees-back${INSTANCE:+ --instance $INSTANCE}"
  info "  sudo systemctl daemon-reload && sudo systemctl restart ${UNIT_NAME}"
fi
echo
# Group membership applies to new processes, not running ones, so the
# dashboard is still using the group list it had at startup and cannot read the
# token yet. Restart it here rather than leaving a note: by this point the
# Advisor tab is already returning "no advisor token readable", and an
# instruction printed under a wall of success text is one nobody reads.
if (( DASH_HOLDS_GROUP )); then
  # #1035. The restart exists for a dashboard that started before it joined
  # the group. This one did not: /proc showed the group on its process before
  # anything moved, so it has read every token through it all along. Nothing
  # about it changed, and restarting it would drop every fleet read for about
  # 24 s on an aggregator.
  say "Leaving the dashboard running"
  info "it already holds the shared group ($SHARED), so it reads the token as it is;"
  info "no restart is needed."
elif (( ! DASH_RESTARTED_EARLY )) && [[ "$DASH_USER" != "root" ]] && systemctl list-unit-files "${DASH_UNIT}.service" >/dev/null 2>&1; then
  say "Restarting the dashboard to pick up the shared group"
  info "group membership applies to new processes, and this host could not show"
  info "whether the running dashboard has the group yet, so it restarts to be sure."
  systemctl restart "${DASH_UNIT}"
  command sleep 4
  if systemctl is-active --quiet "${DASH_UNIT}"; then
    info "dashboard restarted"
  else
    info "the dashboard did not come back — check: journalctl -u ${DASH_UNIT} -n 40"
  fi
fi
systemd-analyze security "${UNIT_NAME}" --no-pager 2>/dev/null | tail -3 || true
