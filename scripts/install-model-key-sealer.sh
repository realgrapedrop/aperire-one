#!/usr/bin/env bash
# Let the dashboard seal a model API key, and nothing else.
#
#   curl -fsSL https://get.aperire.one | bash -s -- --run model-key-sealer          install the grant
#   curl -fsSL https://get.aperire.one | bash -s -- --run model-key-sealer --arm    and open a window
#   curl -fsSL https://get.aperire.one | bash -s -- --run model-key-sealer --remove take it back off
#   curl -fsSL https://get.aperire.one | bash -s -- --run model-key-sealer --trust-arm-key <key>
#                                                          trust an aggregator
#                                                          to open windows here
#   --hold-arm-key <key>                                   keep the key a
#                                                          pairing handed this
#                                                          node, for a sealer
#                                                          installed later
#                                                          (the pairing's own
#                                                          step, not typed)
#   curl -fsSL https://get.aperire.one | bash -s -- --refresh-node-key
#                                                          re-read this host's
#                                                          own node key (root
#                                                          runs the release's
#                                                          checked copy of this
#                                                          script, not the tree's)
#   ... --node-key <pubkey_node>                           state it, for a host
#                                                          whose node is down
#
# What this grants, exactly: the account the dashboard runs as may open one
# private socket. Behind that socket is one program, running as root, which
# takes no arguments, reads a key on standard input, seals it to this host,
# wires it into the Advisor's unit and restarts the Advisor. It may do that
# once per arming, and arming is not one of the things it can do.
#
# ---- why a socket, and not sudo -------------------------------------
#
# Sudo cannot be the boundary here. The dashboard's own unit sets
# NoNewPrivileges=true and an empty CapabilityBoundingSet, and under those sudo
# refuses before it does anything at all:
#
#   sudo: The "no new privileges" flag is set, which prevents sudo from
#         running as root.
#
# That hardening is not negotiable; it is most of what makes the dashboard a
# safe thing to run on a validator. So the privileged side cannot be STARTED by
# the dashboard. It has to be running already, and the dashboard has to reach
# it: systemd listens on /run/aperire/seal-model-key.sock, owned by the
# dashboard account and mode 0600, accepts one connection at a time, and starts
# the sealer as root with that connection as its standard input, output and
# error. The dashboard writes five lines and reads what comes back. It names no
# program, no path and no argument, because it holds none.
#
# ---- the fleet arm key ----------------------------------------------
#
# A window is opened by root, and on a fleet the root who opens it is on the
# aggregator: `scripts/aperire-fleet-arm.sh` there signs one short token per
# node and posts it, and each node's sealer verifies the signature before it
# writes its own marker. This is how a node learns whose tokens to believe:
#
#   curl -fsSL https://get.aperire.one | bash -s -- --run model-key-sealer --trust-arm-key <key>
#
# <key> is either the raw 32-byte public key in base64, exactly as
# aperire-fleet-arm.sh prints it, or the path to a PEM public key file. It is
# written to /etc/aperire/fleet-arm.pub, root-owned and readable by everyone,
# because a public key is public and the sealer refuses one that anybody but
# root may WRITE. The fingerprint is printed so an operator can compare it
# with the one the aggregator printed, rather than trusting a copy and paste
# they cannot check.
#
# Nothing is trusted by default. A host with no such file refuses every arm
# token by name, and its own operator can still arm it with --arm.
#
# ---- the key a pairing hands over, held for later (#720) -------------
#
# aperire-fleet-pair.sh is where a node is handed the aggregator's arm key,
# inside the settlement, after the operator has pasted the aggregator's
# pairing fingerprint (#741): one value over the fleet trust key AND this arm
# key, printed only by root on the aggregator, and matched in full by the
# node before it sends a token or writes a byte. A node
# paired before it has an Advisor has no sealer yet, and --trust-arm-key
# refuses there. So the pairing also runs this program, from the copy it
# staged, with:
#
#   --hold-arm-key <key>
#
# which checks the key the same way and keeps it at
# /etc/aperire/fleet-arm.paired.pub, root-owned, 0644. Nothing reads that file
# except this script: the sealer never looks at it, so holding a key trusts
# nothing. The grant install (a run with no flags, or --arm, which is what
# every Advisor install runs) places it as fleet-arm.pub once this host has a
# sealer and knows its own node key. --refresh-node-key places it too, for a
# host whose node was down at install time.
#
# That is the whole trust path: root on this node took the key from a pairing
# the operator confirmed, and root on this node places it. No dashboard, no
# fetch and no key from anywhere else is involved, and an existing
# fleet-arm.pub that differs is never replaced by it.
#
# The held copy belongs to the pairing, not to the sealer, so --remove leaves
# it. An Advisor removed and installed again on a node that is still paired
# takes the key back, and the install says so with its fingerprint. To end the
# pairing, remove the link credential and this file together (the pair command
# prints both lines).
#
# ---- this host's own node key ---------------------------------------
#
# An arm token names the one node it is for, by node key, inside the bytes the
# aggregator signed. The sealer compares that with /etc/aperire/node-key and
# refuses a token addressed anywhere else (#184), so this is where that file
# is written: the node is asked who it is, over its own loopback admin RPC
# (`server_info`, `pubkey_node`), which is the same answer the read API
# publishes and aperire-fleet-add.sh pins.
#
# Asked of the NODE, never of a dashboard. The dashboard is the process that
# must not be able to arm, and a host whose name a dashboard could choose is a
# host whose arm tokens a dashboard could re-address.
#
# The address is loopback only and comes from /etc/aperire/node-wrapper.conf,
# where the Advisor's wrapper install records it (APERIRE_NODE_ADMIN_RPC
# moves it for an account that is not root, never for root). A node that is down at install time is not a reason
# to guess: `--node-key <pubkey_node>` states it, and `--refresh-node-key`
# reads it again later. A key that changed is stamped again the same way, and
# every token cut for the old one is refused from that moment.
#
# --trust-arm-key REFUSES on a host with no stamp and no answer. Trusting an
# aggregator to open windows here, while being unable to tell which node a
# token names, is the hole this file exists to close.
#
# ---- why the program is copied out of the tree ----------------------
#
# The dashboard runs as the operator's own account, and the checkout is that
# account's files. A unit naming a script inside the checkout would be a unit
# naming a file the dashboard account can rewrite, which is not a narrow grant
# at all: it is root, for anything running as that account. So the sealer is
# installed to /usr/local/sbin, owned by root and writable only by root, and
# the service unit names that copy.
#
# The Advisor's root socket follows the same rule (ADR 0024, ADR 0025): its
# broker runs the root-owned copy at /usr/local/sbin/aperire-node-wrapper, not
# the file in the tree, because "the grantee cannot write the tree" held only
# while nothing else that can write it was a service account.

set -euo pipefail

# As root the environment chooses no path or program (#1206): every
# APERIRE_* variable is dropped except the ones a root caller passes on
# purpose:
#   APERIRE_INSTALL_TREE  get-aperire.sh and the pairing name the tree a staged copy serves (#764)
#   APERIRE_INSTANCE      get-aperire.sh and install-advisor-stack.sh pass it; checked below
# APERIRE_NODE_ADMIN_RPC is dropped with the rest: no root caller sets it,
# and --node-key is how an operator states the node's key. An account id(1)
# says is not root keeps them all, which is what every suite is. id(1) at a
# fixed path, never bash's $EUID (#1109).
if ! [[ "$(/usr/bin/id -u 2>/dev/null)" =~ ^[1-9][0-9]*$ ]]; then
  for _v in $(compgen -e); do
    case "$_v" in APERIRE_INSTALL_TREE|APERIRE_INSTANCE) ;; APERIRE_*) unset "$_v" ;; esac
  done
fi

# The instance names units and paths, so it is held to the rule
# advisor-owner-lib.sh holds it to, and anything else is refused (#1206).
instance_name_ok() { # $1 = a name; [a-z] is held to ASCII, whatever the locale
  local LC_ALL=C
  [[ "$1" =~ ^[a-z0-9][a-z0-9-]{0,30}$ && "$1" != credcheck && "$1" != credcheck-* ]]
}
if [[ -n "${APERIRE_INSTANCE:-}" ]] && ! instance_name_ok "$APERIRE_INSTANCE"; then
  printf 'refused: APERIRE_INSTANCE=%q is not an instance name (a-z, 0-9 and -, at most 31, not credcheck)\n' "$APERIRE_INSTANCE" >&2
  exit 2
fi

# Where this program and its siblings are (SEALER_SELF), and the install tree it acts
# on (REPO): a directory and its parent from a checkout, two when it is a copy
# root staged out of the release and APERIRE_INSTALL_TREE names the tree
# (#764). Code is loaded and run from SEALER_SELF only.
SEALER_SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="${APERIRE_INSTALL_TREE:-$(cd "$SEALER_SELF/.." && pwd)}"
SRC="$REPO/scripts/aperire-seal-model-key.sh"
# Every copy into a root location is checked against the release's digests
# and made from the one read that was checked (ADR 0024).
# shellcheck source=scripts/release-digests-lib.sh
. "$SEALER_SELF/release-digests-lib.sh"
# Whose account this is, from id(1) at a fixed path and never from bash's $EUID,
# which bash imports from the environment (#1109). This program is root, and
# DEST, METHOD_LIB_DEST and the credential check's path below are where it
# places, replaces and removes files, so a variable set in a root shell the
# login started must not choose them (#1148). Only an account that is not root,
# which is what the suites are, may move them. An id that cannot be read is
# root's answer.
SEALER_RUN_UID="$(/usr/bin/id -u 2>/dev/null)" || SEALER_RUN_UID=0
sealer_paths_movable() { [[ "$SEALER_RUN_UID" =~ ^[0-9]+$ && "$SEALER_RUN_UID" != 0 ]]; }
DEST=/usr/local/sbin/aperire-seal-model-key
if sealer_paths_movable; then DEST="${APERIRE_SEALER_PATH:-$DEST}"; fi
# The sealer's own dependency, and the credential check's (#703). Every file
# either of them writes under advisor/state goes through it, so it is copied
# out of the checkout exactly as they are and for exactly the same reason: a
# root program resolving a helper inside a tree the grantee can rewrite is
# that grantee's root. Refreshed wherever $DEST is refreshed, and never
# resolved from the checkout by a program running out of /usr/local/sbin.
STATE_TOOL_SRC="$REPO/scripts/state-file.py"
# Defaulted from $DEST's own directory, not spelled out: a run pointed at a
# harmless destination must not reach into the real /usr/local/sbin. Not read
# from APERIRE_STATE_TOOL_DEST (#1127): root places the helper wherever this
# names, and a variable the login set would choose that place.
STATE_TOOL_DEST="${DEST%/*}/aperire-state-file"
# The sealer's other dependency (#708): the one place that says whether this
# host seals a key with systemd-creds or keeps it as a root-only file, and the
# one place that writes the drop-in either way. Copied out of the checkout for
# the same reason as the helper above, on the same compare, to the same
# directory. The credential check reads the same installed copy.
METHOD_LIB_SRC="$REPO/scripts/model-key-method-lib.sh"
METHOD_LIB_DEST="${DEST%/*}/aperire-model-key-method"
if sealer_paths_movable; then METHOD_LIB_DEST="${APERIRE_KEY_METHOD_LIB_DEST:-$METHOD_LIB_DEST}"; fi

# install_method_lib: same shape as install_state_tool below, 0644 rather than
# 0755 because nothing executes it. It is sourced.
install_method_lib() {
  [[ -f "$METHOD_LIB_SRC" ]] \
    || die "$METHOD_LIB_SRC is missing from this checkout; the sealer cannot tell which method this host uses without it"
  if [[ "$METHOD_LIB_SRC" -ef "$METHOD_LIB_DEST" ]]; then
    say "$METHOD_LIB_DEST is the copy in the tree; left alone"
    return 0
  fi
  rd_place "$REPO" scripts/model-key-method-lib.sh "$METHOD_LIB_DEST" 0644 \
    || die "the method library was not installed, and the sealer cannot tell which method this host uses without it"
}

# install_state_tool: put the helper beside whatever was just installed, or
# leave a matching copy alone. Printed either way, because the drift this
# closes (#185) is invisible when nothing says which copy is running.
install_state_tool() {
  [[ -f "$STATE_TOOL_SRC" ]] \
    || die "$STATE_TOOL_SRC is missing from this checkout; the sealer cannot write state without it"
  # Same file on both ends means a test has pointed the destination at the
  # tree. `install` there truncates the source before it reads it, which
  # leaves a zero-length helper and every seal after it refused.
  if [[ "$STATE_TOOL_SRC" -ef "$STATE_TOOL_DEST" ]]; then
    say "$STATE_TOOL_DEST is the copy in the tree; left alone"
    return 0
  fi
  rd_place "$REPO" scripts/state-file.py "$STATE_TOOL_DEST" 0755 \
    || die "the state helper was not installed, and the sealer cannot write state without it"
}
SOCK="${APERIRE_SEAL_SOCKET:-/run/aperire/seal-model-key.sock}"
# The previous shape. Root-owned, so it outlives an upgrade unless something
# takes it away, and it grants a path the dashboard cannot use.
LEGACY_SUDOERS="${APERIRE_SEALER_SUDOERS:-/etc/sudoers.d/aperire-model-key}"
ETC="${APERIRE_ETC:-/etc/aperire}"
ARM_FILE="$ETC/model-key.arm"
# Who opened the window, when an aggregator did. Written by the sealer's arm
# verb, spent with the marker, and cleared by --arm below so a window opened
# on this host can never be reported as somebody else's.
ARM_ISSUER_FILE="$ARM_FILE.issuer"
# The fleet arm key this host trusts, and the nonces its sealer has honoured.
# Written by --trust-arm-key, read by the sealer, taken away by --remove.
FLEET_ARM_PUB="$ETC/fleet-arm.pub"
FLEET_ARM_SEEN="$ETC/fleet-arm.seen"
# The arm key a pairing handed this node, held until there is a sealer to
# place it for (#720). Written by --hold-arm-key, read only by this script.
FLEET_ARM_HELD_NAME=fleet-arm.paired.pub
FLEET_ARM_HELD="$ETC/$FLEET_ARM_HELD_NAME"
# A PEM Ed25519 public key is 113 bytes. Anything past this is not one.
FLEET_ARM_HELD_MAX=4096
# What the sealer compares an arm token's `target` with, and where the node's
# loopback admin RPC is recorded. Both under $ETC, so a host that is torn down
# with --remove loses them together with everything else this installed.
NODE_KEY_FILE="$ETC/node-key"
WCONF="$ETC/node-wrapper.conf"
# A named instance (APERIRE_INSTANCE) has a wrapper configuration of its own,
# and its node is not the default one (#949). The stamp, though, is one file
# per host ($NODE_KEY_FILE), read by one sealer. So:
#   - on a host whose default instance runs a node, the stamp stays that
#     node's. An instance's run that stamped its own node would flip the file
#     between two keys on every run of either, and each flip refuses every
#     arm token cut for the other. It says so, by name, and leaves it.
#   - on a host with no default node (no default configuration, or one that
#     says SERVICE=none), the instance's node is the node, and its
#     configuration is found by the rule the wrapper installer writes it by,
#     trusted_wrapper_conf, asked of the library rather than spelled again.
#     Missing, it is refused by name: the default file is not this node's.
# As root the library's directory overrides are dropped, as
# get-aperire-advisor.sh drops them.
SEALER_INSTANCE="${APERIRE_INSTANCE:-}"
STAMP_HOST_NOTE=""
if [[ -n "$SEALER_INSTANCE" ]]; then
  [[ -r "$SEALER_SELF/trusted-path-lib.sh" ]] \
    || { echo "error: $SEALER_SELF/trusted-path-lib.sh is missing, so the wrapper configuration of instance '$SEALER_INSTANCE' cannot be found. Nothing was changed." >&2; exit 1; }
  _inst_conf=""
  # shellcheck disable=SC2016  # the inner shell's own positional parameters
  _inst_conf="$(bash -c 'u=$(/usr/bin/id -u 2>/dev/null); [[ "$u" =~ ^[0-9]+$ && "$u" != 0 ]] || unset APERIRE_SBIN_DIR APERIRE_CONF_DIR
    . "$1" && trusted_valid_instance "$2" && trusted_wrapper_conf "$2" "$3"' _ \
    "$SEALER_SELF/trusted-path-lib.sh" "$SEALER_INSTANCE" "$WCONF")" || _inst_conf=""
  if [[ -z "$_inst_conf" ]]; then
    echo "error: '$SEALER_INSTANCE' is not an instance name (lowercase letters, digits and dashes). Nothing was changed." >&2
    exit 2
  fi
  if [[ -f "$WCONF" && "$(sed -n 's/^SERVICE=//p' "$WCONF" | head -1)" != none ]]; then
    STAMP_HOST_NOTE="the node-key stamp is one per host, and this host's default node holds it ($WCONF names that node). Instance '$SEALER_INSTANCE' is not stamped, so a fleet arm token is honoured here only when it names the default node."
  else
    WCONF="$_inst_conf"
  fi
fi
# Base58, leading `n`, no 0, O, I or l. The shape aperire-fleet-add.sh pins
# and aperire-fleet-arm.sh addresses a token to.
NODE_KEY_RE='^n[1-9A-HJ-NP-Za-km-z]{20,60}$'
UNIT_DIR="${APERIRE_UNIT_DIR:-/etc/systemd/system}"

SOCKET_UNIT=aperire-seal-model-key.socket
SERVICE_UNIT='aperire-seal-model-key@.service'
# The Advisor's unit, and the drop-in the sealer writes beside it to load a
# sealed key. Named here because a stale one is checked for below.
ADVISORD_UNIT="aperire-advisord${APERIRE_INSTANCE:+-$APERIRE_INSTANCE}"
ADVISORD_DROPIN="$UNIT_DIR/${ADVISORD_UNIT}.service.d/model-credential.conf"

ARM=0
REMOVE=0
TRUST_ARM_KEY=""
HOLD_ARM_KEY=""
REFRESH_NODE_KEY=0
NODE_KEY=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --arm)    ARM=1; shift ;;
    --remove) REMOVE=1; shift ;;
    --trust-arm-key)
      [[ $# -ge 2 ]] || { echo "--trust-arm-key needs a value: the base64 key, or a path to a PEM public key" >&2; exit 2; }
      TRUST_ARM_KEY="$2"; shift 2 ;;
    --hold-arm-key)
      [[ $# -ge 2 ]] || { echo "--hold-arm-key needs a value: the base64 key the pairing was handed" >&2; exit 2; }
      HOLD_ARM_KEY="$2"; shift 2 ;;
    --refresh-node-key) REFRESH_NODE_KEY=1; shift ;;
    --node-key)
      [[ $# -ge 2 ]] || { echo "--node-key needs a value: this node's pubkey_node, as its own server_info reports it" >&2; exit 2; }
      NODE_KEY="$2"; shift 2 ;;
    -h|--help) awk '/^[^#]/{exit} NR>1{sub(/^# ?/,""); print}' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

# One job per run. Trusting a key and installing the grant are different
# decisions taken at different times by possibly different people, and a run
# that quietly did both would be a run whose failure halfway is hard to read.
if [[ -n "$TRUST_ARM_KEY" ]] && (( ARM || REMOVE || REFRESH_NODE_KEY )); then
  echo "--trust-arm-key is a run of its own; give it alone" >&2
  exit 2
fi
if [[ -n "$HOLD_ARM_KEY" ]] && { (( ARM || REMOVE || REFRESH_NODE_KEY )) || [[ -n "$TRUST_ARM_KEY$NODE_KEY" ]]; }; then
  echo "--hold-arm-key is a run of its own; give it alone" >&2
  exit 2
fi
if (( REFRESH_NODE_KEY )) && (( ARM || REMOVE )); then
  echo "--refresh-node-key is a run of its own; give it alone" >&2
  exit 2
fi
# --node-key is not a job, it is the answer to a question the other jobs ask.
# With --remove there is no question, so it is a flag that would do nothing.
if [[ -n "$NODE_KEY" ]] && (( REMOVE )); then
  echo "--node-key does nothing with --remove; --remove takes the stamped key away" >&2
  exit 2
fi
if [[ -n "$NODE_KEY" ]] && [[ ! "$NODE_KEY" =~ $NODE_KEY_RE ]]; then
  echo "--node-key '$NODE_KEY' is not shaped like a node key (base58, starting with 'n')" >&2
  exit 2
fi

say()  { printf '   %s\n' "$*"; }
die()  { printf 'error: %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "run with sudo: this installs a program as root and two systemd units"

# The old sudoers rule, wherever this script finds one. It is dead weight on
# every host that has it: sudo cannot run inside the dashboard's unit at all.
# Removed on install and on removal, and said out loud both times, because a
# grant nobody can use is still a grant somebody has to read and explain.
drop_legacy_sudoers() {
  [[ -f "$LEGACY_SUDOERS" ]] || return 0
  rm -f "$LEGACY_SUDOERS"
  say "removed $LEGACY_SUDOERS"
  say "  the old sudo grant. The dashboard's unit forbids sudo (NoNewPrivileges),"
  say "  so that rule never worked and nothing needs it now."
}

# ---- what this host answers when asked who it is -------------------
#
# Sets NODE_KEY_FOUND, or NODE_KEY_WHY and returns 1. Called directly and
# never through `$( )`: a command substitution is a subshell, and a subshell
# cannot hand a variable back to the run that started it.
#
# NODE_KEY_NONODE separates the two ways there is no key: a node that could
# not be asked, and a host that runs no node at all. They read differently to
# an operator and one of them is not a problem.
NODE_KEY_FOUND=""
NODE_KEY_WHY=""
NODE_KEY_NONODE=0
resolve_node_key() {
  local rpc body key
  NODE_KEY_FOUND=""; NODE_KEY_WHY=""; NODE_KEY_NONODE=0

  # What the operator stated wins. It is the answer for a host whose node is
  # stopped, and for one where the admin RPC is somewhere this cannot guess.
  if [[ -n "$NODE_KEY" ]]; then NODE_KEY_FOUND="$NODE_KEY"; return 0; fi

  rpc="${APERIRE_NODE_ADMIN_RPC:-}"
  if [[ -z "$rpc" && -r "$WCONF" ]]; then
    # An aggregator. install-node-wrapper.sh --no-node writes SERVICE=none
    # here, beside an ADMIN_RPC of port 0 that nothing is listening on, so
    # without this the honest answer "there is no node on this host" would
    # arrive as "the node did not answer" and four lines of advice about
    # starting it. install-can-delete-timer.sh reads the same line for the
    # same reason. An explicit APERIRE_NODE_ADMIN_RPC still wins: whoever
    # sets it is naming a node this file does not know about.
    if [[ "$(sed -n 's/^SERVICE=//p' "$WCONF" | head -1)" == none ]]; then
      NODE_KEY_NONODE=1
      NODE_KEY_WHY="this host runs no node ($WCONF says SERVICE=none), so no arm token can be addressed to it"
      return 1
    fi
    rpc="$(sed -n 's/^ADMIN_RPC=//p' "$WCONF" | head -1)"
  fi
  if [[ -z "$rpc" && -n "$SEALER_INSTANCE" && ! -e "$WCONF" ]]; then
    NODE_KEY_WHY="instance '$SEALER_INSTANCE' has no wrapper configuration ($WCONF), so its node's admin RPC address is not known here"
    return 1
  fi
  if [[ -z "$rpc" ]]; then
    NODE_KEY_WHY="no admin RPC address to ask: $WCONF names none and APERIRE_NODE_ADMIN_RPC is unset"
    return 1
  fi
  # Loopback, as every other admin call in this project is. Asking a remote
  # endpoint who THIS host is would be asking a different machine, and taking
  # its answer as this host's name is the whole of the bug.
  if [[ ! "$rpc" =~ ^http://(127\.0\.0\.1|localhost|\[::1\]):[0-9]+$ ]]; then
    NODE_KEY_WHY="ADMIN_RPC '$rpc' is not loopback, and a remote endpoint cannot answer for this host"
    return 1
  fi
  if ! body="$(curl -sS --max-time 8 --data '{"method":"server_info","params":[{}]}' "$rpc" 2>/dev/null)"; then
    NODE_KEY_WHY="the node did not answer on $rpc"
    return 1
  fi
  # rippled pretty-prints, so the newlines go first and the field is read off
  # one line. The shape check below is what makes this safe to write out.
  key="$(tr -d '\n' <<<"$body" | sed -n 's/.*"pubkey_node"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
  if [[ -z "$key" ]]; then
    NODE_KEY_WHY="the node answered on $rpc but reported no pubkey_node; it may still be starting"
    return 1
  fi
  if [[ ! "$key" =~ $NODE_KEY_RE ]]; then
    NODE_KEY_WHY="the answer on $rpc is not shaped like a node key"
    return 1
  fi
  NODE_KEY_FOUND="$key"
}

# Root-owned and world-readable, like the fleet arm key beside it: a node key
# is public, and what the sealer checks is who may WRITE it. Whoever can
# rewrite this file re-addresses every arm token this host is ever sent.
stamp_node_key() { # $1 = the node key
  local tmp
  mkdir -p "$ETC"
  tmp="$(mktemp)"
  printf '%s\n' "$1" > "$tmp"
  install -o root -g root -m 0644 "$tmp" "$NODE_KEY_FILE"
  rm -f "$tmp"
}

# What is stamped now, or empty if this host has no usable stamp.
stamped_node_key() {
  local k
  [[ -f "$NODE_KEY_FILE" ]] || return 1
  k="$(tr -d '[:space:]' < "$NODE_KEY_FILE")"
  [[ "$k" =~ $NODE_KEY_RE ]] || return 1
  printf '%s' "$k"
}

# The line that stamps this host's own node key again, as an operator types it
# (#935). Root runs a checked copy of this script through the bootstrap, never
# the one in the tree, so the hint is the bootstrap's flag and not a path in
# the checkout. The tree is named, shell-quoted, when it is not where the
# bootstrap looks by default: its owner's home, under aperire-one.
refresh_node_key_line() { # $1 = more flags, e.g. "--node-key <pubkey_node>"
  local owner home dir=""
  owner="$(stat -c %U "$REPO" 2>/dev/null || true)"
  home="$(getent passwd "$owner" 2>/dev/null | cut -d: -f6 || true)"
  [[ -n "$home" && "$REPO" == "$home/aperire-one" ]] || dir=" --dir $(printf '%q' "$REPO")"
  # The instance whose node this run asked, when it is that node the stamp
  # names (#949). Not on a host whose default node holds the stamp.
  local inst=""
  [[ -n "$SEALER_INSTANCE" && -z "$STAMP_HOST_NOTE" ]] && inst=" --instance $SEALER_INSTANCE"
  printf 'curl -fsSL https://get.aperire.one | bash -s -- --refresh-node-key%s%s%s' "${1:+ $1}" "$inst" "$dir"
}

# What the sealer program itself checks of a file it trusts (-O, and no group
# or other write bit), so that what this script claims about a file is what the
# program will find. Prints "owner:group mode" and returns 0 when it would pass.
sealer_would_trust() { # $1 = a file
  local meta mode
  meta="$(stat -c '%U:%G %a' "$1" 2>/dev/null)" || { printf 'unreadable'; return 1; }
  printf '%s' "$meta"
  [[ -O "$1" ]] || return 1
  mode="${meta##* }"
  (( (8#$mode & 8#022) == 0 ))
}

# A stamp that holds a different key from the one just read (#935). Every arm
# token cut for the old key stops working at that moment, and nothing else
# would say so. One copy, for --refresh-node-key and for the install's stamp.
say_node_key_changed() { # $1 = the key that was stamped
  say ""
  say "it was $1"
  say "every arm token cut for that key is refused here from now on. Update this"
  say "node's expected_pubkey_node on the aggregator before arming it again."
}

# ---- an arm key, checked, whichever way it arrived -----------------
#
# One copy of the rule, used by --trust-arm-key, --hold-arm-key and the
# placement of a held key. Writes <dir>/key.pem, or sets ARM_WHY and returns
# 1: the placement runs inside a grant install that must not die on it, so
# nothing here exits.
ARM_WHY=""
arm_pem_from_material() { # $1 = the key text (PEM or base64), $2 = a private work directory
  local material="$1" pem="$2/key.pem" raw size
  ARM_WHY=""
  # The mistake worth catching loudly. The aggregator's private key on every
  # node is the fleet's arming decision handed to every node's operator, and
  # the two files sit side by side in /etc/aperire on the machine it came from.
  case "$material" in
    *"PRIVATE KEY"*)
      ARM_WHY="that is a PRIVATE key. The aggregator keeps that file; this host takes the
     public half only (fleet-arm.pub, or the base64 aperire-fleet-arm.sh printed)."
      return 1 ;;
  esac

  if [[ "$material" == *"BEGIN PUBLIC KEY"* ]]; then
    printf '%s\n' "$material" > "$pem"
  else
    # The raw 32 bytes, base64. Wrapped back into a PEM by prefixing the
    # twelve DER bytes that say "this is an Ed25519 public key". They are the
    # same bytes openssl writes, and reading the result back below checks it.
    raw="$2/key.raw"
    if ! printf '%s' "$material" | tr -d '[:space:]' | base64 -d > "$raw" 2>/dev/null; then
      ARM_WHY="that is neither a PEM public key file nor base64"
      return 1
    fi
    size="$(stat -c %s "$raw")"
    if [[ "$size" -ne 32 ]]; then
      ARM_WHY="an Ed25519 public key is 32 bytes; this decodes to $size"
      return 1
    fi
    printf '\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00' > "$2/key.der"
    cat "$raw" >> "$2/key.der"
    if ! openssl pkey -pubin -inform DER -in "$2/key.der" -out "$pem" 2>/dev/null; then
      ARM_WHY="those 32 bytes are not a usable Ed25519 public key"
      return 1
    fi
  fi

  if ! openssl pkey -pubin -in "$pem" -noout 2>/dev/null; then
    ARM_WHY="that public key does not parse; pass the file aperire-fleet-arm.sh printed"
    return 1
  fi
  if ! openssl pkey -pubin -in "$pem" -noout -text 2>/dev/null | grep -q 'ED25519'; then
    ARM_WHY="that is not an Ed25519 key, and an arm token is signed with Ed25519"
    return 1
  fi
}

# The key itself, as DER in base64, so two encodings of one key compare equal.
arm_der() { openssl pkey -pubin -in "$1" -outform DER 2>/dev/null | base64 -w0 || true; }
# The fingerprint aperire-fleet-arm.sh prints on the aggregator: sha256 of the
# raw 32 bytes, first 16 hex. The two must be one computation.
arm_fp() { openssl pkey -pubin -in "$1" -outform DER 2>/dev/null | tail -c 32 | sha256sum | cut -c1-16; }

# Where the key goes, and the one rule about what is already there (P2-056).
#
# Whoever can rewrite fleet-arm.pub can arm this host at will, so silently
# re-pointing it is the one write in this script that hands away a durable
# capability. The same rule aperire-fleet-pair.sh applies to an existing
# peers.aggregator: a host that already trusts one aggregator is not moved to
# another by an automated step. Compared as the KEY rather than as the file,
# so the same key in a different encoding is idempotent rather than a
# refusal. Sets ARM_WHY and returns 1; writes nothing on the way to either.
write_trusted_arm_key() { # $1 = a checked PEM
  local have_der want_der
  ARM_WHY=""
  mkdir -p "$ETC"
  if [[ -f "$FLEET_ARM_PUB" ]]; then
    have_der="$(arm_der "$FLEET_ARM_PUB")"
    want_der="$(arm_der "$1")"
    if [[ -z "$have_der" ]]; then
      ARM_WHY="$FLEET_ARM_PUB exists and is not a public key this host can read.
     Look at it, then remove it by hand if it is rubbish, and run this again."
      return 1
    fi
    if [[ "$have_der" != "$want_der" ]]; then
      ARM_WHY="$FLEET_ARM_PUB already trusts a different aggregator's arm key.
     it holds:   $(arm_fp "$FLEET_ARM_PUB")
     this one:   $(arm_fp "$1")
     Whoever holds that key can open an arm window on this host, so this step does
     not replace one with another. If the fleet really did rotate its arm key,
     remove the file by hand and run this again:
       sudo rm $FLEET_ARM_PUB
     The held copy at $FLEET_ARM_HELD is rewritten to the key trusted next,
     so it cannot bring the old one back. Nothing was written."
      return 1
    fi
  fi
  # The held copy follows the key root trusts, BEFORE that key is written
  # (#720 review, M1). Otherwise a rotation done here (remove fleet-arm.pub,
  # trust the new key) would leave the pairing's old key held, and the next
  # --remove and reinstall would place the old key again, silently. Written
  # first so that a refusal here changes nothing this host trusts.
  if ! sync_held_arm_key "$1"; then
    return 1
  fi
  # 0644: a public key is public, and the sealer's own check is about who may
  # WRITE it. Root-owned, because that check refuses a file owned by anyone
  # else. Whoever can rewrite this file can arm this host at will.
  #
  # Checked by hand, not left to set -e: every caller runs this as `f || ...`,
  # and bash turns errexit off inside a function called that way, so a failed
  # write here would otherwise fall through and be reported as trusted.
  if ! install -o root -g root -m 0644 "$1" "$FLEET_ARM_PUB"; then
    ARM_WHY="could not write $FLEET_ARM_PUB (install's own reason is above)"
    return 1
  fi
  # Whatever this host had honoured under the previous key means nothing under
  # a new one, and keeping it would only refuse a fresh token that happened to
  # reuse a nonce.
  rm -f "$FLEET_ARM_SEEN"
}

# The held copy, made to hold exactly $1 (a checked PEM). A no-op when it
# already does. Replaces whatever sits at that name (plant renames over it
# without following a link), because root is deciding right now which key
# this host trusts. Sets ARM_WHY and returns 1 on any failure; every command
# is checked by hand, since callers run it as `f || ...`.
sync_held_arm_key() {
  local work rc=0
  if ! work="$(umask 077; mktemp -d)" || [[ -z "$work" || ! -d "$work" ]]; then
    ARM_WHY="could not make a private temporary directory, so $FLEET_ARM_HELD was not updated and nothing was trusted"
    return 1
  fi
  if ! etc_safe dir 2> "$work/why"; then
    ARM_WHY="$(head -1 "$work/why"). Nothing was trusted."
    rm -rf "$work"
    return 1
  fi
  etc_safe read "$FLEET_ARM_HELD_NAME" "$FLEET_ARM_HELD_MAX" > "$work/have.pem" 2>/dev/null || rc=$?
  if (( rc == 0 )) && [[ -n "$(arm_der "$work/have.pem")" && "$(arm_der "$work/have.pem")" == "$(arm_der "$1")" ]]; then
    rm -rf "$work"
    return 0
  fi
  if [[ ! -f "$STATE_TOOL_SRC" ]]; then
    ARM_WHY="$STATE_TOOL_SRC is missing from this checkout, so $FLEET_ARM_HELD could not be kept in step. Nothing was trusted."
    rm -rf "$work"
    return 1
  fi
  if ! python3 -I "$SEALER_SELF/state-file.py" plant "$FLEET_ARM_HELD" "$(id -u)" "$(id -g)" 0644 --stdin \
       < "$1" 2> "$work/why"; then
    ARM_WHY="could not write $FLEET_ARM_HELD: $(head -1 "$work/why"). Nothing was trusted."
    rm -rf "$work"
    return 1
  fi
  rm -rf "$work"
}

# ---- $ETC, read and checked on descriptors (#720) ------------------
#
# The held key is read by root and then trusted, so it is read the way every
# root read of a trust file in this tree is: the directory opened without
# following a link and checked on that descriptor (owned by the account
# running this, which on a host is root, and writable by nobody else), then
# the file opened relative to it, O_NOFOLLOW and O_NONBLOCK, and checked on
# its own descriptor (a regular file, same owner, nobody else may write it,
# one name, bounded). Nothing is checked by one name and then read by another.
#
#   etc_safe dir                  is $ETC a directory only its owner writes
#   etc_safe read <name> <max>    that, and print one file in it
#
# Exit 0 yes, 3 absent (the file, or $ETC itself on a read), 1 refused with
# one sentence on stderr. Compared with the effective uid rather than with 0,
# the same as the sealer's own -O, so the suite can run it unprivileged.
ETC_SAFE_PY='
import errno, os, stat, sys
etc, op = sys.argv[1], sys.argv[2]
me = os.geteuid()
def no(msg):
    sys.stderr.write(msg + "\n")
    sys.exit(1)
try:
    dfd = os.open(etc, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
except OSError as e:
    if e.errno == errno.ENOENT and op == "read":
        sys.exit(3)
    no("%s is not a directory this can open without following a link (%s)" % (etc, e.strerror))
st = os.fstat(dfd)
if st.st_uid != me:
    no("%s is owned by uid %d, not by the account running this (uid %d)" % (etc, st.st_uid, me))
if st.st_mode & 0o022:
    no("%s is mode %o, and a directory that group or others may write lets them swap what is in it"
       % (etc, stat.S_IMODE(st.st_mode)))
if op == "dir":
    sys.exit(0)
name, limit = sys.argv[3], int(sys.argv[4])
path = os.path.join(etc, name)
try:
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dfd)
except OSError as e:
    if e.errno == errno.ENOENT:
        sys.exit(3)
    if e.errno == errno.ELOOP:
        no("%s is a symbolic link, and a trust key is never read through one" % path)
    no("%s could not be opened (%s)" % (path, e.strerror))
st = os.fstat(fd)
if not stat.S_ISREG(st.st_mode):
    no("%s is not a regular file" % path)
if st.st_uid != me:
    no("%s is owned by uid %d, not by the account running this (uid %d)" % (path, st.st_uid, me))
if st.st_mode & 0o022:
    no("%s is mode %o, and a key that group or others may write is theirs to choose"
       % (path, stat.S_IMODE(st.st_mode)))
if st.st_nlink != 1:
    no("%s has %d names, so it can be changed through another one" % (path, st.st_nlink))
data = b""
while len(data) <= limit:
    chunk = os.read(fd, 65536)
    if not chunk:
        break
    data += chunk
if len(data) > limit:
    no("%s is larger than %d bytes, which no public key is" % (path, limit))
sys.stdout.buffer.write(data)
'
etc_safe() { python3 -I -c "$ETC_SAFE_PY" "$ETC" "$@"; }

# ---- the held key, placed (#720) ------------------------------------
#
# Called by a grant install (a run with no flags, or --arm) once the sealer
# and the node-key stamp are in place, and by --refresh-node-key. Never fatal
# to either: a grant that installed and cannot place the key is still a grant
# that seals, and install-advisor-stack.sh reads this script's exit status as
# "can the browser seal here". So every way through returns, and says why.
#
# Places only where there is no fleet-arm.pub. One that is there and differs
# is left exactly as it is: a key an operator trusted by hand is not
# overwritten by one a pairing handed over, in either order.
place_held_arm_key() {
  local work rc=0 held_fp have_fp
  [[ -e "$FLEET_ARM_HELD" || -L "$FLEET_ARM_HELD" ]] || return 0
  echo
  echo "== The fleet arm key this node was handed when it paired"
  if [[ ! -f "$DEST" ]]; then
    say "held at $FLEET_ARM_HELD; placed when the sealer is installed here."
    return 0
  fi
  # Checked by hand: this runs as `place_held_arm_key || true`, where errexit
  # is off, and an empty $work would send every path below to /.
  if ! work="$(umask 077; mktemp -d)" || [[ -z "$work" || ! -d "$work" ]]; then
    say "not placed: could not make a private temporary directory"
    return 1
  fi
  etc_safe read "$FLEET_ARM_HELD_NAME" "$FLEET_ARM_HELD_MAX" > "$work/held.pem" 2> "$work/why" || rc=$?
  if (( rc == 3 )); then
    rm -rf "$work"
    return 0
  fi
  if (( rc != 0 )); then
    say "not placed: $(head -1 "$work/why")"
    say "nothing was trusted. Look at it, and pair this node again if it is not what"
    say "the pairing wrote."
    rm -rf "$work"
    return 1
  fi
  if ! arm_pem_from_material "$(cat "$work/held.pem")" "$work"; then
    say "not placed: $FLEET_ARM_HELD does not hold a usable key: $ARM_WHY"
    rm -rf "$work"
    return 1
  fi
  held_fp="$(arm_fp "$work/key.pem")"
  if [[ -f "$FLEET_ARM_PUB" ]]; then
    if [[ -n "$(arm_der "$FLEET_ARM_PUB")" && "$(arm_der "$FLEET_ARM_PUB")" == "$(arm_der "$work/key.pem")" ]]; then
      say "$FLEET_ARM_PUB already holds it (fingerprint $held_fp)"
      rm -rf "$work"
      return 0
    fi
    have_fp="$(arm_fp "$FLEET_ARM_PUB")"
    say "left as it is: $FLEET_ARM_PUB already trusts ${have_fp:-a key this cannot read},"
    say "and $FLEET_ARM_HELD holds $held_fp. Nothing was replaced."
    say "Trust whichever one is this fleet's key now, which rewrites the held copy to"
    say "match. To keep the one already trusted and drop the held copy:"
    say "  sudo rm $FLEET_ARM_HELD"
    say "To trust the held one instead:"
    say "  sudo rm $FLEET_ARM_PUB && curl -fsSL https://get.aperire.one | bash -s -- --dir $REPO --run model-key-sealer"
    rm -rf "$work"
    return 1
  fi
  # The same refusal --trust-arm-key makes (#184): a host that cannot tell
  # which node a token names is not given a key that makes tokens believable.
  if ! stamped_node_key >/dev/null; then
    say "not placed yet: this host does not know its own node key, so it could not"
    say "tell whether an arm token is addressed to it. Once the node answers:"
    say "  $(refresh_node_key_line)"
    say "which places it."
    rm -rf "$work"
    return 1
  fi
  # $ETC is checked again right before the write: install(1) works by name,
  # which is safe only in a directory nobody but root can change.
  if ! etc_safe dir 2> "$work/why"; then
    say "not placed: $(head -1 "$work/why")"
    rm -rf "$work"
    return 1
  fi
  if ! write_trusted_arm_key "$work/key.pem"; then
    say "not placed: $ARM_WHY"
    rm -rf "$work"
    return 1
  fi
  rm -rf "$work"
  say "$FLEET_ARM_PUB  (root:root 0644, from $FLEET_ARM_HELD)"
  say "fingerprint  $held_fp"
  say "the aggregator this node paired with can now open a sealing window here, for"
  say "a token addressed to this node and no other."
}

if [[ $REMOVE -eq 1 ]]; then
  systemctl disable --now "$SOCKET_UNIT" >/dev/null 2>&1 || true
  rm -f "$UNIT_DIR/$SOCKET_UNIT" "$UNIT_DIR/$SERVICE_UNIT" "$DEST" "$ARM_FILE"
  systemctl daemon-reload >/dev/null 2>&1 || true
  say "removed $UNIT_DIR/$SOCKET_UNIT and $UNIT_DIR/$SERVICE_UNIT"
  say "removed $DEST"
  # The state helper is shared with the credential check (#703), so it goes
  # only when nothing else is left that needs it. Taking it while credcheck
  # is still installed would leave that program unable to write the one note
  # it exists to leave, on the run where a credential has just gone.
  _credcheck="${DEST%/*}/aperire-advisord-credcheck"
  if sealer_paths_movable; then _credcheck="${APERIRE_CREDCHECK_SBIN:-$_credcheck}"; fi
  if [[ -f "$STATE_TOOL_DEST" ]]; then
    if [[ -f "$_credcheck" ]]; then
      say "left $STATE_TOOL_DEST in place; $_credcheck still uses it"
    else
      rm -f "$STATE_TOOL_DEST"
      say "removed $STATE_TOOL_DEST"
    fi
  fi
  # The method library is shared the same way (#708), and goes on the same
  # rule: the credential check reads it to judge either form of credential.
  if [[ -f "$METHOD_LIB_DEST" ]]; then
    if [[ -f "$_credcheck" ]]; then
      say "left $METHOD_LIB_DEST in place; $_credcheck still uses it"
    else
      rm -f "$METHOD_LIB_DEST"
      say "removed $METHOD_LIB_DEST"
    fi
  fi
  # The trust root goes too, and the nonces with it. Leaving a fleet arm key
  # behind on a host whose sealer is gone is a grant nobody can see being
  # used.
  if [[ -f "$FLEET_ARM_PUB" || -f "$FLEET_ARM_SEEN" ]]; then
    rm -f "$FLEET_ARM_PUB" "$FLEET_ARM_SEEN"
    say "removed $FLEET_ARM_PUB (this host now trusts no fleet arm key)"
  fi
  # The key the pairing handed over stays (#720). It is the pairing's, not the
  # sealer's: the sealer never reads it, and a node that is still paired and
  # gets an Advisor again should be armable from its aggregator without a
  # shell. Said out loud, so it is not a grant nobody can see, and the grant
  # install that places it again prints its fingerprint when it does.
  if [[ -e "$FLEET_ARM_HELD" ]]; then
    say "kept $FLEET_ARM_HELD, the arm key this node was handed when it paired."
    say "  nothing trusts it now. An Advisor installed here again places it. To end"
    say "  the pairing as well, remove it with the link credential:"
    say "    sudo rm $FLEET_ARM_HELD"
  fi
  # The stamp goes with them. It is only ever read by the sealer, to decide
  # whether a token is addressed here, and a sealer that is gone reads nothing.
  if [[ -f "$NODE_KEY_FILE" ]]; then
    rm -f "$NODE_KEY_FILE"
    say "removed $NODE_KEY_FILE (the node key an arm token was checked against)"
  fi
  drop_legacy_sudoers
  say "the dashboard can no longer seal a key. The operator ceremony still can:"
  say "  bash $REPO/scripts/setup-advisor-model.sh"
  exit 0
fi

# ---- --refresh-node-key: this host's own name, read again ----------
#
# For a key that changed (a node rebuilt from a new key pair), and for a host
# that was installed while its node was down. Its own run, because it changes
# which tokens this host will honour and that deserves to be a decision.
if [[ $REFRESH_NODE_KEY -eq 1 ]]; then
  echo
  echo "== This host's own node key"
  [[ -z "$STAMP_HOST_NOTE" ]] || say "$STAMP_HOST_NOTE"
  WAS="$(stamped_node_key || true)"
  if ! resolve_node_key; then
    if (( NODE_KEY_NONODE )); then
      die "$NODE_KEY_WHY.
     There is nothing to stamp here. If this host does run a node, state its key:
       $(refresh_node_key_line '--node-key <pubkey_node>')"
    fi
    die "this host cannot say what its own node key is: $NODE_KEY_WHY
     Start the node and run this again, or state the key:
       $(refresh_node_key_line '--node-key <pubkey_node>')"
  fi
  stamp_node_key "$NODE_KEY_FOUND"
  say "$NODE_KEY_FILE  (root:root 0644)"
  say "$NODE_KEY_FOUND"
  if [[ -n "$WAS" && "$WAS" != "$NODE_KEY_FOUND" ]]; then
    say_node_key_changed "$WAS"
  else
    say "an arm token addressed to any other node is refused here."
  fi
  # The node was down when the grant went on, so a key the pairing handed
  # over could not be placed then (#720). It can now.
  place_held_arm_key || true
  exit 0
fi

# ---- --hold-arm-key: the key a pairing handed over, kept (#720) ------
#
# aperire-fleet-pair.sh runs this with the key from a settlement it has
# verified against the fleet trust key the operator just compared by
# fingerprint. It needs no sealer and no node key, because holding a key
# trusts nothing: the sealer never reads this file. The grant install places
# it, under every check --trust-arm-key makes.
#
# A different key already held is refused, never replaced: the same rule, and
# the same reason, as an existing fleet-arm.pub.
if [[ -n "$HOLD_ARM_KEY" ]]; then
  echo
  echo "== The fleet arm key this node was handed, held for its Advisor"
  HOLD_TMP="$(umask 077; mktemp -d)"
  trap 'rm -rf "$HOLD_TMP"' EXIT
  arm_pem_from_material "$HOLD_ARM_KEY" "$HOLD_TMP" || die "$ARM_WHY"
  [[ -f "$STATE_TOOL_SRC" ]] \
    || die "$STATE_TOOL_SRC is missing from this checkout, and the key is written through it. Nothing was written."
  mkdir -p "$ETC"
  etc_safe dir 2> "$HOLD_TMP/why" \
    || die "$(head -1 "$HOLD_TMP/why"). A key kept there is not root's alone. Nothing was written."
  held_rc=0
  etc_safe read "$FLEET_ARM_HELD_NAME" "$FLEET_ARM_HELD_MAX" > "$HOLD_TMP/have.pem" 2> "$HOLD_TMP/why" || held_rc=$?
  case "$held_rc" in
    0)
      if [[ "$(arm_der "$HOLD_TMP/have.pem")" == "$(arm_der "$HOLD_TMP/key.pem")" ]]; then
        say "$FLEET_ARM_HELD already holds that key (fingerprint $(arm_fp "$HOLD_TMP/key.pem"))"
        exit 0
      fi
      die "$FLEET_ARM_HELD already holds a different arm key.
     it holds:   $(arm_fp "$HOLD_TMP/have.pem")
     this one:   $(arm_fp "$HOLD_TMP/key.pem")
     A key held here becomes a key this host trusts when its Advisor is installed,
     so this step does not replace one with another. If the fleet really did rotate
     its arm key, remove the held copy, and the trusted key if the old one is
     there too, then run this again:
       sudo rm -f $FLEET_ARM_HELD $FLEET_ARM_PUB
     Nothing was written." ;;
    3) ;;
    *) die "$(head -1 "$HOLD_TMP/why").
     Look at it, remove it by hand if it is not what a pairing wrote, and run this
     again. Nothing was written." ;;
  esac
  # On descriptors, not by name: created 0600 under a random name, owned and
  # moded on its descriptor, renamed into place relative to the directory
  # checked above (scripts/state-file.py plant says why install(1) is not).
  python3 -I "$SEALER_SELF/state-file.py" plant "$FLEET_ARM_HELD" "$(id -u)" "$(id -g)" 0644 --stdin \
      < "$HOLD_TMP/key.pem" 2> "$HOLD_TMP/why" \
    || die "could not write $FLEET_ARM_HELD: $(head -1 "$HOLD_TMP/why")"
  say "$FLEET_ARM_HELD  ($(id -un):$(id -gn) 0644)"
  say "fingerprint  $(arm_fp "$HOLD_TMP/key.pem")"
  say "held, not trusted: the sealer never reads this file. The Advisor install"
  say "places it as $FLEET_ARM_PUB, so the aggregator can arm this node from then on."
  exit 0
fi

# ---- --trust-arm-key: whose windows this host will open -------------
#
# Validated before anything is written: a file that does not parse, or parses
# as something other than an Ed25519 public key, would install cleanly and
# then refuse every arm token this host is ever sent, from a place nobody
# thinks to look.
if [[ -n "$TRUST_ARM_KEY" ]]; then
  echo
  echo "== The fleet arm key this host will trust"
  TRUST_TMP="$(umask 077; mktemp -d)"
  trap 'rm -rf "$TRUST_TMP"' EXIT
  PEM="$TRUST_TMP/key.pem"

  material="$TRUST_ARM_KEY"
  if [[ -f "$TRUST_ARM_KEY" ]]; then
    material="$(cat "$TRUST_ARM_KEY")"
  fi
  arm_pem_from_material "$material" "$TRUST_TMP" || die "$ARM_WHY"

  # The program this key is for. A key trusted by a sealer that predates the
  # arm verb is a key trusted by nothing: that sealer reads the arm payload's
  # first line as a base_url and refuses it as a seal (seen on stock-node1,
  # 2026-09-03: the source was current, /usr/local/sbin was not). So the
  # installed copy is refreshed from the tree here when it differs, exactly
  # as a full run does, and an absent one is a host this has never installed
  # on, which is the wrong order.
  [[ -f "$DEST" ]] \
    || die "no sealer at $DEST; run this script without flags first, then trust the key"
  _placed="$(rd_install "$REPO" scripts/aperire-seal-model-key.sh "$DEST" 0755)" \
    || die "$DEST was not refreshed, so the key was not trusted either: a sealer that predates the arm verb trusts it for nothing"
  if [[ "$_placed" == placed ]]; then
    SEALER_NOTE="$DEST refreshed from the tree, so it reads arm tokens"
  else
    SEALER_NOTE="$DEST already matches the release"
  fi
  # The helper travels with it, on the same compare (#703). A sealer refreshed
  # past a release whose state writes moved onto the helper, with no helper
  # beside it, is the 2026-09-03 shape again: current source, stale host.
  install_state_tool
  install_method_lib

  # The address the sealer will check tokens against, before the key that
  # makes them believable is written. A host that trusts an aggregator to open
  # windows here, and cannot tell which node a token names, is the hole this
  # check closes (#184), so this is a refusal, not a warning, and nothing is
  # written on the way to it.
  #
  # An existing stamp is kept: this flag is the upgrade path for a node that
  # already has one, and re-reading it would make the flag fail on a host
  # whose node happens to be stopped for maintenance.
  if NODE_KEY_STAMPED="$(stamped_node_key)" && [[ -z "$NODE_KEY" ]]; then
    NODE_KEY_NOTE="checked against $NODE_KEY_STAMPED, the node key already stamped here"
  elif resolve_node_key; then
    stamp_node_key "$NODE_KEY_FOUND"
    NODE_KEY_STAMPED="$NODE_KEY_FOUND"
    NODE_KEY_NOTE="checked against $NODE_KEY_FOUND, stamped in $NODE_KEY_FILE"
  elif (( NODE_KEY_NONODE )); then
    # Not a failure to fix. An aggregator is never sent an arm token: it opens
    # its own window with a marker, and aperire-fleet-arm.sh skips its own row
    # rather than posting to it. A key trusted here could never be used.
    # The installed name where the fleet broker grant placed it (#812). A grant
    # older than the program gets the update first, which places it, never
    # the checkout's copy run as root (#929): the same line the page prints.
    ARM_SELF="curl -fsSL https://get.aperire.one | bash -s -- --update --force && test -x /usr/local/sbin/aperire-fleet-arm && sudo aperire-fleet-arm --self-only"
    [[ -x "${APERIRE_FLEET_ARM_PROGRAM:-/usr/local/sbin/aperire-fleet-arm}" ]] \
      && ARM_SELF="sudo aperire-fleet-arm --self-only"
    die "$NODE_KEY_WHY, so there is no aggregator key for it to hold.
     This host opens its own window:
       $ARM_SELF
     If it does run a node, state that node's key:
       curl -fsSL https://get.aperire.one | bash -s -- --dir $REPO --run model-key-sealer --trust-arm-key <key> --node-key <pubkey_node>"
  else
    die "this host does not know its own node key, so it cannot tell whether an arm
     token is addressed to it, and a host in that state must not be given an
     aggregator's arm key.
       $NODE_KEY_WHY
     Start the node and run this again, or state the key:
       curl -fsSL https://get.aperire.one | bash -s -- --dir $REPO --run model-key-sealer --trust-arm-key <key> --node-key <pubkey_node>"
  fi

  # An existing key that DIFFERS is refused, not overwritten (P2-056);
  # write_trusted_arm_key says why, once, for this path and the held key's.
  write_trusted_arm_key "$PEM" || die "$ARM_WHY"
  fp="$(arm_fp "$FLEET_ARM_PUB")"
  say "$FLEET_ARM_PUB  (root:root 0644)"
  say "fingerprint  $fp"
  say "compare that with the fingerprint aperire-fleet-arm.sh printed on the aggregator."
  say "they must match; if they do not, this host is trusting the wrong machine."
  say ""
  say "$SEALER_NOTE"
  say "$NODE_KEY_NOTE"
  say "this host will now open a fifteen-minute window when that aggregator asks,"
  say "for a token addressed to this node and no other."
  say "--arm still works here."
  exit 0
fi

[[ -f "$SRC" ]] || die "no sealer at $SRC; this tree is incomplete"
command -v systemctl >/dev/null || die "systemctl not found, and the grant is a socket unit"

# The account the dashboard runs as, from its own unit. Not $SUDO_USER: on a
# host where one operator installs and the service runs as another, the grant
# has to follow the service.
DASH_USER=""
for _u in aperire-server aperire-read; do
  _f="$UNIT_DIR/${_u}.service"
  [[ -f "$_f" ]] || continue
  DASH_USER=$(awk -F= '/^User=/{print $2; exit}' "$_f")
  [[ -n "$DASH_USER" ]] && break
done
DASH_USER="${DASH_USER:-${SUDO_USER:-}}"
[[ -n "$DASH_USER" ]] \
  || die "could not work out which account the dashboard runs as; no aperire-server unit and no SUDO_USER"
[[ "$DASH_USER" != root ]] \
  || die "the dashboard runs as root on this host, which needs no grant and should not have one"
getent passwd "$DASH_USER" >/dev/null || die "there is no account called '$DASH_USER'"

echo
echo "== The sealer, as root"
# Copied, not linked. A symlink into the tree would put the grantee back in
# charge of what root runs.
rd_place "$REPO" scripts/aperire-seal-model-key.sh "$DEST" 0755 \
  || die "the sealer was not installed, so nothing below was written either"
install_state_tool
install_method_lib
say "an update refreshes this copy; run by hand, it is checked against the release this host is on"

echo
echo "== One socket, one account, one program behind it"
TMPS=$(mktemp)
TMPV=$(mktemp)
trap 'rm -f "$TMPS" "$TMPV"' EXIT

cat > "$TMPS" <<EOF
# Written by scripts/install-model-key-sealer.sh
#
# The dashboard account may open this socket and nothing else. Behind it is one
# root program that takes no arguments, reads a key on standard input, seals it
# once per arming and cannot arm itself.
[Unit]
Description=Aperire: the dashboard's way to ask for one model key to be sealed
Documentation=file:$DEST

[Socket]
ListenStream=$SOCK
SocketUser=$DASH_USER
SocketGroup=$DASH_USER
SocketMode=0600
# systemd creates the parent directory of a filesystem socket before binding,
# with this mode. Nothing declares /run/aperire as a RuntimeDirectory, so no
# unit stopping takes it away underneath this one.
DirectoryMode=0755
# One connection at a time, each its own instance, each ending when the program
# does. A seal is not a service to talk to; it is one question and one answer.
Accept=yes
MaxConnections=1

[Install]
WantedBy=sockets.target
EOF

cat > "$TMPV" <<EOF
# Written by scripts/install-model-key-sealer.sh
[Unit]
Description=Aperire: seal one model API key (connection %i)
Documentation=file:$DEST
# A [Unit] key: under [Service] systemd 255 logs "Unknown key name" and
# ignores it (seen on stock-node1). With SuccessExitStatus=1 below, a refusal
# is not a failure, and this lets a finished instance be unloaded rather
# than sit in \`systemctl --failed\` for ever.
CollectMode=inactive-or-failed

[Service]
# Root, and honestly so. \`systemd-creds encrypt\` reads the systemd host key,
# which is 0400 root:root, and writing LoadCredentialEncrypted= into the
# Advisor's unit needs root for the same unavoidable reason. This is the one
# program that runs this way on the dashboard's behalf, it takes no arguments,
# and the socket in front of it is the only way to reach it.
#
# Deliberately not hardened further: it writes a root credential, edits a unit
# and calls systemctl, so ProtectSystem= and friends would only break it. What
# constrains it is that it is ONE program, with no arguments and a window that
# is spent on first use, not a sandbox.
ExecStart=$DEST
# The accepted connection is this program's three streams. The payload arrives
# on standard input; its fields and its refusals go back the same way. An exit
# code does not cross a socket, which is why the program prints \`exit=\` last.
# Its journal line is written with logger and is unaffected by this.
StandardInput=socket
StandardOutput=socket
StandardError=socket
# A bound, so a sealer that never returns cannot hold a connection open for
# ever. It restarts the Advisor and waits ten seconds for it, on top of a drain
# that can take a minute, so this is generous on purpose.
RuntimeMaxSec=180
# A refusal is an outcome, not a failure. The sealer exits 1 for "no window",
# "expired", "bad shape" and "the Advisor did not come back", and it has
# already said which in the journal and on the socket. Left as a failure,
# every refused attempt sat in \`systemctl --failed\` for ever (observed on the
# lab box: CollectMode= alone, which is set in [Unit] above, does not unload
# an Accept=yes instance while the socket holds it), and a host with a
# permanently failed unit is what the verifier flags. What still counts as a
# failure is the bound above firing.
SuccessExitStatus=1
EOF

install -o root -g root -m 0644 "$TMPS" "$UNIT_DIR/$SOCKET_UNIT"
install -o root -g root -m 0644 "$TMPV" "$UNIT_DIR/$SERVICE_UNIT"
say "$UNIT_DIR/$SOCKET_UNIT   ($SOCK, $DASH_USER only, mode 0600)"
say "$UNIT_DIR/$SERVICE_UNIT  (runs $DEST as root, no arguments)"

systemctl daemon-reload
# Restarted, not merely enabled: on a re-run the unit text may have changed,
# and an already-listening socket would go on serving the old one.
systemctl enable "$SOCKET_UNIT" >/dev/null
# DirectoryMode= above applies only to a directory systemd creates. The node
# wrapper may have made this one first, under its own umask, and then the
# dashboard cannot traverse it to its own socket (#171). Said here, every run.
install -d -m 0755 -o root -g root "$(dirname "$SOCK")"
systemctl restart "$SOCKET_UNIT"

drop_legacy_sudoers

# ---- a credential directive with nothing behind it ------------------
#
# systemd refuses to start a unit that declares a credential file which is
# not there: 243/CREDENTIALS, before the program runs, with the restart
# counter climbing (#446). The drop-in and the sealed file belong together
# and the sealer removes them together, but an uninstall that took
# /etc/aperire/creds away leaves the drop-in behind, and the next Advisor
# installed on this host would come up unable to start with no reason it
# could name. Checked on every install, which is the run that precedes that
# start.
if [[ -f "$ADVISORD_DROPIN" ]]; then
  # Either spelling (#712 review L2). A host that cannot seal declares its
  # key with LoadCredential=, and matching only the encrypted one left the
  # exact state this block exists to repair: a drop-in naming a key file that
  # is gone, and a unit that cannot start at all.
  stale_cred="$(sed -n 's#^LoadCredential\(Encrypted\)\?=[^:]*:\(.*\)$#\2#p' "$ADVISORD_DROPIN" | head -1)"
  if [[ -n "$stale_cred" && ! -e "$stale_cred" ]]; then
    rm -f "$ADVISORD_DROPIN"
    rmdir "$(dirname "$ADVISORD_DROPIN")" 2>/dev/null || true
    systemctl daemon-reload
    say "removed $ADVISORD_DROPIN"
    say "  it loaded $stale_cred, which is not on this host. A unit that"
    say "  declares a credential that is missing cannot start at all. Seal a"
    say "  key again from the dashboard and the drop-in comes back with it."
  fi
fi

# The grant has to work for the account it names, not just parse. Without this
# the dashboard discovers it at the end of a ceremony an operator was watching.
systemctl is-active --quiet "$SOCKET_UNIT" \
  || die "$SOCKET_UNIT did not come up. Read: systemctl status $SOCKET_UNIT"
[[ -S "$SOCK" ]] \
  || die "$SOCKET_UNIT is active but there is no socket at $SOCK.
     Read: systemctl status $SOCKET_UNIT"
owner_mode="$(stat -c '%U %a' "$SOCK" 2>/dev/null || true)"
[[ "$owner_mode" == "$DASH_USER 600" ]] \
  || die "$SOCK is '$owner_mode', not '$DASH_USER 600'.
     Either the dashboard cannot open it, or somebody else can."
# As the dashboard account, not as root: root can see a socket in a directory
# the dashboard cannot traverse, and that was exactly the case on aperire1
# (#171). A test -e from that account needs search on every directory above.
runuser -u "$DASH_USER" -- test -e "$SOCK" 2>/dev/null \
  || die "$SOCK exists but $DASH_USER cannot reach it.
     Read: stat -c '%A %U' $(dirname "$SOCK")"
say "checked: $SOCK is listening, owned by $DASH_USER, mode 600, reachable as $DASH_USER"

echo
echo "== This host's own node key"
[[ -z "$STAMP_HOST_NOTE" ]] || say "$STAMP_HOST_NOTE"
# Not fatal. The seal path and --arm do not need this, and refusing to install
# the grant because a node is down would trade a working local ceremony for a
# fleet feature the host may never use. What it must never do is install
# quietly and leave an operator to discover it at the far end of a fleet arm,
# so a host that could not be asked says so and says both ways to fix it.
if resolve_node_key; then
  # Read before it is written: the wrapper is repaired first now, so this
  # branch is reached on hosts that used to keep their stamp, and a stamp that
  # held a different key is re-addressed by this write (#935).
  WAS_NODE_KEY="$(stamped_node_key || true)"
  stamp_node_key "$NODE_KEY_FOUND"
  say "$NODE_KEY_FILE  (root:root 0644)"
  say "$NODE_KEY_FOUND"
  if [[ -n "$WAS_NODE_KEY" && "$WAS_NODE_KEY" != "$NODE_KEY_FOUND" ]]; then
    say_node_key_changed "$WAS_NODE_KEY"
  else
    say "an arm token addressed to any other node is refused here."
  fi
elif (( NODE_KEY_NONODE )); then
  say "$NODE_KEY_WHY."
  say "nothing to stamp. This host opens its own window with --arm."
elif KEPT_NODE_KEY="$(stamped_node_key)"; then
  # A stamp from an earlier run is still there, and this run could not ask the
  # node again. The old text said the opposite of what was on disk (#935).
  # Said only as far as it is true: the owner and mode are read, not assumed,
  # and a token is honoured only when the program would find a trust root.
  stamp_ok=1
  if kept_meta="$(sealer_would_trust "$NODE_KEY_FILE")"; then
    stamp_ok=0
    say "kept: $NODE_KEY_FILE  ($kept_meta) still holds the key stamped earlier"
  else
    say "kept: $NODE_KEY_FILE  ($kept_meta) still holds the key stamped earlier, but the"
    say "sealer will not trust a file with that owner or mode. Stamping it again writes it right."
  fi
  say "$KEPT_NODE_KEY"
  say "this run could not ask the node again: $NODE_KEY_WHY"
  if [[ ! -f "$FLEET_ARM_PUB" ]]; then
    say "this host trusts no fleet arm key yet ($FLEET_ARM_PUB), so every fleet arm token is"
    say "refused until it is paired."
    [[ ! -f "$FLEET_ARM_HELD" ]] || say "the arm key its pairing handed over is placed next."
  elif sealer_would_trust "$FLEET_ARM_PUB" >/dev/null; then
    if (( stamp_ok == 0 )); then
      say "an arm token addressed to that key is still honoured here."
    else
      # The sealer refuses a stamp it does not own or that others can write
      # (a link reads as mode 777), whatever the trust root says.
      say "every fleet arm token is refused until the stamp is written again, which the"
      say "line below does once the node is up (or with --node-key, now)."
    fi
  else
    say "$FLEET_ARM_PUB has an owner or mode the sealer will not trust, so every fleet arm"
    say "token is refused until that is put right."
  fi
  say "If this node's key has changed since it was stamped, stamp it again once the node is up:"
  say "  $(refresh_node_key_line)"
else
  say "not stamped: $NODE_KEY_WHY"
  say "sealing and --arm are unaffected. Fleet arm tokens are refused until this"
  say "host knows its own key. Once the node is up:"
  say "  $(refresh_node_key_line)"
  say "or state it now:"
  say "  $(refresh_node_key_line '--node-key <pubkey_node>')"
fi

# The moment this host gains a sealer is the moment a key its pairing handed
# over can be trusted (#720). Every Advisor install runs this script, so a
# node paired before its Advisor is armable from the aggregator from here on,
# with no command beyond the Advisor's own one-liner. After the stamp, which
# it needs; never fatal, because the grant above is installed either way.
place_held_arm_key || true

if [[ $ARM -eq 1 ]]; then
  echo
  echo "== A window, for the next fifteen minutes"
  mkdir -p "$ETC"
  # This window is this host's own. Any issuer left beside the marker belongs
  # to a window an aggregator opened earlier, and a seal made under THIS one
  # must not be recorded as having come from there.
  rm -f "$ARM_ISSUER_FILE"
  install -o root -g root -m 0600 /dev/null "$ARM_FILE"
  say "$ARM_FILE"
  say "the dashboard may seal ONE key before this lapses. Re-run this with --arm"
  say "to open another; the dashboard cannot open one itself."
fi
