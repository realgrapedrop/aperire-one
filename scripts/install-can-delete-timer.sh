#!/usr/bin/env bash
# Install the ledger-store rotation window, issue #79.
#
# What gets installed:
#   /usr/local/lib/aperire/aperire-can-delete.sh   the window itself
#   /etc/aperire/can-delete.conf                   which node, which port
#   aperire-can-delete.service                     one run
#   aperire-can-delete.timer                       one run a day, 04:00 local
#
# The script is COPIED out of the repository rather than run from it. It runs
# as root on a schedule, and a root timer pointed at a path the dashboard
# account can write is a way to become root. The cost is that a repository
# update does not reach it: re-run this script after one.
#
# The timer is only ENABLED if the node's config already has
# `advisory_delete=1`. Without that, rippled ignores can_delete entirely and
# the window would fail loudly every day for a reason the operator has not
# been given a chance to fix. In that case everything is installed, the timer
# is left stopped, and the two remaining steps are printed.
#
# Idempotent. Safe to re-run.
#
# Usage (an install and an update run this themselves; by hand, it is a step of
# the bootstrap, which runs the release's checked copy of this program):
#   curl -fsSL https://get.aperire.one | bash -s -- --run rotation-timer
#
# Where the node comes from, in this order, and each one only fills in what the
# one before it left empty:
#
#   1. APERIRE_NODE_SERVICE / _ADMIN_RPC / _CONFIG / _KIND in the environment
#   2. /etc/aperire/node-wrapper.conf   the Advisor's wrapper configuration,
#      detected from the running deployment when the Advisor was installed
#   3. /etc/aperire/node.conf           written by
#      scripts/install-aperire-node.sh for the node it deployed
#   4. a native systemd unit, xrpld.service then rippled.service. "Found"
#      means loaded (systemctl's LoadState), not necessarily running. Its
#      admin RPC comes from its own config's [port_rpc_admin_local] stanza
#      and is confirmed with server_info, the same discipline #278 already
#      holds a container's ports to: named, then asked, never guessed
#   5. docker, asked for a running node container, for the name and, when
#      exactly one of its loopback ports answers server_info, the admin RPC
#      too
#
# 3 and 5 are #270: a co-located host whose node came from this repository and
# that runs no Advisor has no wrapper configuration, so every one of those
# installs ended with "no node container name" and no rotation window.
#
# 5's admin RPC is #278: naming the container was never the whole answer, and
# a docker that already knows the published ports was still asked to be told
# the right one by hand every time. Every node this project installs
# publishes two loopback ports (5005 the admin RPC, 6006 the admin
# WebSocket), so counting loopback mappings refuses on the project's own node
# shape. The port is confirmed by asking it, the same server_info call the
# rest of this script makes, not by counting: whichever loopback port answers
# JSON-RPC is the admin RPC, and the WebSocket port does not.
#
# Step 4 is the native design (the 2026-09-15 native xrpld support
# design, lane 5). A host with neither a wrapper conf, a node conf, nor a
# running docker at all still gets a rotation window, because nothing above
# this step requires docker to exist: KIND=container is the only thing that
# ever calls it, checked at each call site rather than gated once at the top.
#
# Naming the node by hand is a flag of the same step (#1068). The bootstrap holds
# each value to its shape before any root call and hands it on as the variable
# this program reads, because sudo drops one the operator set:
#
#   curl -fsSL https://get.aperire.one | bash -s -- --run rotation-timer \
#     --service xrpldstock --admin-rpc http://127.0.0.1:5005 \
#     --config /path/to/rippled.cfg
#
# On a native host named by hand this way, add --kind native too: with SERVICE
# already filled in, step 4 never runs, and nothing else here can tell a unit
# name from a container name.

set -euo pipefail

# As root the environment chooses no path (#1206): every APERIRE_* variable
# is dropped except the ones a root caller passes on purpose:
#   APERIRE_INSTALL_TREE    install.sh exports it; get-aperire.sh names the
#                           tree a staged copy serves (#764)
#   APERIRE_NODE_SERVICE, APERIRE_NODE_ADMIN_RPC, APERIRE_NODE_CONFIG,
#   APERIRE_NODE_KIND       --run rotation-timer passes them from its
#                           --service, --admin-rpc, --config and --kind
# An account id(1) says is not root keeps them all, which is what every
# suite is. id(1) at a fixed path, never the uid bash imports from its
# environment (#1109).
if ! [[ "$(/usr/bin/id -u 2>/dev/null)" =~ ^[1-9][0-9]*$ ]]; then
  for _v in $(compgen -e); do
    case "$_v" in APERIRE_INSTALL_TREE|APERIRE_NODE_SERVICE|APERIRE_NODE_ADMIN_RPC|APERIRE_NODE_CONFIG|APERIRE_NODE_KIND) ;; APERIRE_*) unset "$_v" ;; esac
  done
fi

die() { printf 'install-can-delete-timer: %s\n' "$*" >&2; exit 1; }
# Exit 3 means "this host has no node", an answer and not a failure: a host
# with a relay and no node (an aggregator) has nothing to rotate, and install.sh
# reads the status to say so instead of warning (#913). It is only ever said on
# positive evidence: the Advisor's own SERVICE=none, or every probe answered and
# found nothing (node_absence_proven below). A docker that would not answer, a
# container this script could not name, or a stopped one is exit 1 or 4, because
# the host may have a node this run could not see.
# Exit 4 is a refusal the operator can settle by naming the node (SERVICE= and
# ADMIN_RPC= in node.conf), so install.sh can say how. Everything else is 1.
no_node() { printf 'install-can-delete-timer: %s\n' "$*" >&2; exit 3; }
die_name() { printf 'install-can-delete-timer: %s\n' "$*" >&2; exit 4; }

[[ $EUID -eq 0 ]] || die "must run as root (sudo bash $0)"

# Where this program and its siblings are (CD_SELF), and the install tree it acts
# on (REPO_DIR): a directory and its parent from a checkout, two when it is a copy
# root staged out of the release and APERIRE_INSTALL_TREE names the tree
# (#764). Code is loaded and run from CD_SELF only.
CD_SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="${APERIRE_INSTALL_TREE:-$(cd "$CD_SELF/.." && pwd)}"
SRC="$REPO_DIR/scripts/aperire-can-delete.sh"
UNIT_SRC="$REPO_DIR/scripts/aperire-can-delete.service"
TIMER_SRC="$REPO_DIR/scripts/aperire-can-delete.timer"
DOCKER_LIB="$CD_SELF/docker-ask-lib.sh"
DIGESTS_LIB="$CD_SELF/release-digests-lib.sh"
for f in "$SRC" "$UNIT_SRC" "$TIMER_SRC" "$DOCKER_LIB" "$DIGESTS_LIB"; do
  [[ -f "$f" ]] || die "missing $f, run this from a full checkout"
done

command -v flock  >/dev/null 2>&1 || die "flock is required (apt-get install util-linux)"
command -v curl   >/dev/null 2>&1 || die "curl is required (apt-get install curl)"
# docker is required only on a container host. docker_ask already reads "not
# installed" as an absence, not a refusal, so nothing here gates on it before
# knowing which kind of host this is; the KIND=container branches below check
# for it at the point each of them actually needs it.

# ── Where the node is ────────────────────────────────────────────────────
# shellcheck source=scripts/docker-ask-lib.sh
. "$DOCKER_LIB"

WCONF=/etc/aperire/node-wrapper.conf
NCONF=/etc/aperire/node.conf
SERVICE="${APERIRE_NODE_SERVICE:-}"
ADMIN_RPC="${APERIRE_NODE_ADMIN_RPC:-}"
# The one-line fix for a node this run could not place (#1068). A root shell
# started with sudo has no environment of the operator's (env_reset drops
# APERIRE_NODE_SERVICE), so naming the node in a variable never reached this
# program. The bootstrap's own step takes the node by name instead, through its
# allow-list, and runs the release's checked copy of this program with the
# values in its environment. $1 = the service when it is known, $2 = the admin
# RPC when it is.
fix_line() {
  printf 'curl -fsSL https://get.aperire.one | bash -s -- --run rotation-timer --service %s --admin-rpc %s' \
    "${1:-<container-or-unit>}" "${2:-http://127.0.0.1:<admin-port>}"
}
NODE_CFG="${APERIRE_NODE_CONFIG:-}"
# KIND is container or native. Neither wrapper conf nor node conf carries it
# yet (that lands with the wrapper's own KIND support), so this is read the
# same fill-if-empty way in case either one gains the key later, and it is
# also set explicitly by whichever branch below finds the node.
KIND="${APERIRE_NODE_KIND:-}"
read_node_conf() { # $1 = the file
  local f="$1"
  [[ -r "$f" ]] || return 0
  [[ -n "$SERVICE"   ]] || SERVICE=$(sed -n 's/^SERVICE=//p'      "$f" | head -1)
  [[ -n "$ADMIN_RPC" ]] || ADMIN_RPC=$(sed -n 's/^ADMIN_RPC=//p'  "$f" | head -1)
  [[ -n "$NODE_CFG"  ]] || NODE_CFG=$(sed -n 's/^CONFIG_FILE=//p' "$f" | head -1)
  [[ -n "$KIND"      ]] || KIND=$(sed -n 's/^KIND=//p'            "$f" | head -1)
  printf 'reading the node from %s\n' "$f"
}
read_node_conf "$WCONF"
# SERVICE=none is the Advisor's word for a host that runs no node at all, and
# it is an answer: stop here rather than reading a second file, checking for
# a native unit, or asking docker, any of which could find somebody else's
# node or container.
[[ "$SERVICE" != "none" ]] || no_node "$WCONF says this host runs no node (SERVICE=none); there is nothing to rotate"
read_node_conf "$NCONF"

# Nothing recorded yet. Check for a native unit before asking docker: a host
# with the vendor's package installed and no Advisor and no node.conf is
# exactly #270's case, one deployment shape later. xrpld.service is the
# current vendor package, rippled.service the legacy one still on some
# hosts; whichever is loaded wins and the other is never tried, the same
# "found it, do not also guess" rule the container path below holds to.
# "Found" means loaded, not necessarily running: a stopped native node still
# answers this, and confirming it answers server_info is the next step.
if [[ -z "$SERVICE" ]] && command -v systemctl >/dev/null 2>&1; then
  for _unit in xrpld.service rippled.service; do
    _load=$(systemctl show "$_unit" --property=LoadState --value 2>&1) || _load=''
    [[ "$_load" == loaded ]] || continue
    case "$_unit" in
      xrpld.service)   _native_cfg=/etc/xrpld/xrpld.cfg ;;
      rippled.service) _native_cfg=/etc/opt/ripple/rippled.cfg ;;
    esac
    printf 'no node recorded on this host; systemd names one native unit: %s\n' "$_unit"
    SERVICE="$_unit"
    KIND=native
    [[ -n "$NODE_CFG" ]] || NODE_CFG="$_native_cfg"
    if [[ -z "$ADMIN_RPC" ]]; then
      [[ -r "$NODE_CFG" ]] \
        || die "the unit '$_unit' is loaded and its config is not readable at $NODE_CFG"
      # [port_rpc_admin_local]: read the same way [node_db] is read elsewhere
      # in this tree, a next-'[' ends the stanza.
      _rpc_port=$(awk '
        /^[[:space:]]*\[port_rpc_admin_local\][[:space:]]*$/ { inb=1; next }
        inb && /^[[:space:]]*\[/                             { inb=0 }
        inb && /^[[:space:]]*port[[:space:]]*=/ {
          sub(/^[^=]*=[[:space:]]*/, ""); sub(/[[:space:]]+$/, ""); print; exit
        }
      ' "$NODE_CFG")
      _rpc_ip=$(awk '
        /^[[:space:]]*\[port_rpc_admin_local\][[:space:]]*$/ { inb=1; next }
        inb && /^[[:space:]]*\[/                             { inb=0 }
        inb && /^[[:space:]]*ip[[:space:]]*=/ {
          sub(/^[^=]*=[[:space:]]*/, ""); sub(/[[:space:]]+$/, ""); print; exit
        }
      ' "$NODE_CFG")
      [[ -n "$_rpc_port" ]] \
        || die "the unit '$_unit' is loaded and $NODE_CFG names no [port_rpc_admin_local] port; nothing here names its admin RPC"
      # A stanza naming a port is not proof the node listens there (it could
      # be commented out of [server], or serve wss instead of an admin API):
      # confirmed by asking, same as the container path's #278 discipline.
      _candidate="http://${_rpc_ip:-127.0.0.1}:${_rpc_port}"
      _body="$(curl -sS -m 3 -d '{"method":"server_info","params":[{}]}' "$_candidate/" 2>/dev/null || true)"
      [[ "$_body" == *'"result"'* ]] \
        || die "the unit '$_unit' is loaded and $NODE_CFG names ${_candidate} as its admin RPC, and it did not answer server_info"
      ADMIN_RPC="$_candidate"
      printf '%s names %s as the admin RPC, confirmed by server_info\n' "$NODE_CFG" "$ADMIN_RPC"
    fi
    break
  done
fi

# Still nothing: ask docker what is running, the way the
# preflight does, through the one library that tells a refused answer from an
# absence (#140, #142): a docker that would not answer must not read as "no
# node here", and a name guessed out of a refusal would point a root timer at
# a container that may not be the node.
if [[ -z "$SERVICE" ]]; then
  DOCKER_SAID=''; DOCKER_ASK=0
  # {{.Ports}} rides along in the same row: docker already knows this
  # container's published port mappings, and asking for them here costs
  # nothing extra and needs no second call through docker_ask (#278).
  DOCKER_SAID="$(docker_ask '{{.Names}}\t{{.Image}}\t{{.Ports}}')" || DOCKER_ASK=$?
  # A container created from a digest shows an image ID; read its name back,
  # and treat a refused read like a refused ps (#896).
  if [[ $DOCKER_ASK -eq 0 ]]; then
    DOCKER_SAID="$(docker_resolve_image_ids "$DOCKER_SAID")" || DOCKER_ASK=$?
  fi
  case $DOCKER_ASK in
    0) FOUND=()
       while IFS= read -r line; do
         [[ -n "$line" ]] && FOUND+=("$line")
       done < <(printf '%s\n' "$DOCKER_SAID" | grep -aiE 'rippled|xrpld|xahaud' || true)
       if   [[ ${#FOUND[@]} -eq 1 ]]; then
         SERVICE="$(printf '%s' "${FOUND[0]}" | awk -F'\t' '{print $1}')"
         KIND=container
         printf 'no node recorded on this host; docker names one running node container: %s\n' "$SERVICE"
         # The published port mappings for that same container, still from the
         # one docker_ask row above. Every node this project installs
         # publishes two loopback ports (the admin RPC and the admin
         # WebSocket), so which one is the admin RPC is confirmed by asking
         # it, not by counting mappings: the same server_info call this
         # script makes further down is made against each loopback port in
         # turn, and the one that answers JSON-RPC is the one kept. None
         # answering, or more than one, is refused by name rather than
         # guessed, since a root timer pointed at the wrong port is worse
         # than no timer.
         if [[ -z "$ADMIN_RPC" ]]; then
           PORTS="$(printf '%s' "${FOUND[0]}" | awk -F'\t' '{print $3}')"
           LOOPBACK=()
           IFS=',' read -ra PORT_PARTS <<< "$PORTS"
           for part in "${PORT_PARTS[@]}"; do
             part="${part//[[:space:]]/}"
             if [[ "$part" =~ ^127\.0\.0\.1:([0-9]+)-([0-9]+)-\>[0-9]+-[0-9]+/tcp$ ]]; then
               # the range form: 127.0.0.1:A-B->C-D/tcp. Only the host side
               # (A-B) is dialled from here, so only it is expanded.
               for ((_p = BASH_REMATCH[1]; _p <= BASH_REMATCH[2]; _p++)); do
                 LOOPBACK+=("$_p")
               done
             elif [[ "$part" =~ ^127\.0\.0\.1:([0-9]+)-\>[0-9]+/tcp$ ]]; then
               LOOPBACK+=("${BASH_REMATCH[1]}")
             fi
           done
           if [[ ${#LOOPBACK[@]} -gt 0 ]]; then
             ANSWERED=()
             for _p in "${LOOPBACK[@]}"; do
               _body="$(curl -sS -m 3 -d '{"method":"server_info","params":[{}]}' "http://127.0.0.1:${_p}/" 2>/dev/null || true)"
               [[ "$_body" == *'"result"'* ]] && ANSWERED+=("$_p")
             done
             SEEN=(); for _p in "${LOOPBACK[@]}"; do SEEN+=("127.0.0.1:${_p}"); done
             if   [[ ${#ANSWERED[@]} -eq 1 ]]; then
               ADMIN_RPC="http://127.0.0.1:${ANSWERED[0]}"
               printf 'docker publishes %d loopback port(s) for %s; 127.0.0.1:%s answers server_info\n' \
                 "${#LOOPBACK[@]}" "$SERVICE" "${ANSWERED[0]}"
             elif [[ ${#ANSWERED[@]} -eq 0 ]]; then
               die_name "the node's container is '${SERVICE}' and docker publishes ${#LOOPBACK[@]} loopback port(s) for it (${SEEN[*]}), and none of them answered server_info. Name the one that is the admin RPC: $(fix_line "$SERVICE" 'http://127.0.0.1:<one-of-them>')"
             else
               ANSWERED_SEEN=(); for _p in "${ANSWERED[@]}"; do ANSWERED_SEEN+=("127.0.0.1:${_p}"); done
               die_name "the node's container is '${SERVICE}' and ${#ANSWERED[@]} of its loopback ports answered server_info (${ANSWERED_SEEN[*]}), and this script must not pick one: a root timer that talks to the wrong port is worse than no timer. Name the one that is the admin RPC: $(fix_line "$SERVICE" 'http://127.0.0.1:<one-of-them>')"
             fi
           fi
         fi
       elif [[ ${#FOUND[@]} -gt 1 ]]; then
         NAMES=()
         for line in "${FOUND[@]}"; do NAMES+=("$(printf '%s' "$line" | awk -F'\t' '{print $1}')"); done
         die_name "docker is running ${#FOUND[@]} node containers here (${NAMES[*]}), and this script must not pick one: a root timer that talks to the wrong node is worse than no timer. Name it: $(fix_line '<container>' '')"
       fi ;;
    1) : ;;   # a true absence: no docker, or no daemon. The refusal below says it
    2) die_name "docker is installed here and would not say what is running (${DOCKER_SAID}). That is not an absence, so nothing is guessed: run this again as root, or name the node: $(fix_line '' '')" ;;
  esac
fi

# Nothing named a node. "This host has none" is said only when every place a
# node could be has been asked and answered: docker (or no docker installed at
# all), the unit files, the process table. A probe that cannot answer leaves the
# question open, and an open question is a refusal, never an absence.
ABSENCE_WHY=""
node_absence_proven() {
  local all line p body
  if command -v docker >/dev/null 2>&1; then
    [[ ${DOCKER_ASK:-1} -eq 0 ]] \
      || { ABSENCE_WHY="docker is installed here and its daemon did not answer (${DOCKER_SAID:-no reason given}), so a node container cannot be ruled out"; return 1; }
    all="$(docker_ask '{{.Names}}\t{{.Image}}\t{{.Ports}}' -a)" \
      || { ABSENCE_WHY="docker would not list all containers (${all:-no reason given})"; return 1; }
    if printf '%s\n' "$all" | grep -aiqE 'rippled|xrpld|xahaud'; then
      ABSENCE_WHY="docker has a container made from a node image that is not running or was not named by a conf"
      return 1
    fi
    # A node under a name and image this script does not know: any published
    # loopback port that answers server_info is one.
    while IFS= read -r p; do
      [[ -n "$p" ]] || continue
      body="$(curl -sS -m 3 -d '{"method":"server_info","params":[{}]}' "http://127.0.0.1:${p}/" 2>/dev/null || true)"
      # rippled's own server_info reply, not any JSON that says "result".
      if [[ "$body" == *'"result"'* && "$body" == *'"build_version"'* && "$body" == *'"server_state"'* ]]; then
        ABSENCE_WHY="a container publishes 127.0.0.1:${p} and it answers server_info, so it is a node this script was not told about"
        return 1
      fi
    done < <(printf '%s\n' "$all" | grep -aoE '127\.0\.0\.1:[0-9]+' | cut -d: -f2 | sort -un)
  fi
  if command -v systemctl >/dev/null 2>&1; then
    line="$(systemctl list-unit-files 2>/dev/null | grep -E '^(xrpld|rippled|xahaud)[^ ]*\.service' || true)"
    if [[ -n "$line" ]]; then
      ABSENCE_WHY="systemd has a node unit (${line%% *})"
      return 1
    fi
  fi
  if command -v pgrep >/dev/null 2>&1; then
    # By the command line's executable, not the process name: a current node
    # renames itself (xrpld-main), so -x never finds it. The pattern is the
    # first word of the command line only (a version or .bin suffix is allowed),
    # so an editor or grep with the
    # node's config path as an argument, and this script, do not match.
    if pgrep -f '^([^ ]*/)?(rippled|xrpld|xahaud)[^ /]*( |$)' >/dev/null 2>&1; then
      ABSENCE_WHY="a node process (rippled, xrpld or xahaud) is running"
      return 1
    fi
  else
    ABSENCE_WHY="pgrep is not here, so the process table cannot be read"
    return 1
  fi
  return 0
}
if [[ -z "$SERVICE" ]]; then
  if node_absence_proven; then
    no_node "no node found. This host has no ${NCONF} (the node installer writes one), no ${WCONF} (the Advisor's wrapper does), no node unit in systemd, no node process, and docker (where installed) answered and holds no node container, so there is no rotation window to install. If a node does run here, name it: $(fix_line '' '')"
  fi
  die_name "no node was named, and this run cannot say the host has none: ${ABSENCE_WHY}. Name it: $(fix_line '' '')"
fi
[[ -n "$ADMIN_RPC" ]] || die_name "the node is '${SERVICE}' and nothing here names its admin RPC. Name its admin RPC (it must be loopback): $(fix_line "$SERVICE" '')"

# Defaults to container: every conf this script wrote before native existed
# looks exactly like a container conf with no KIND line, and it must keep
# reading as one.
KIND="${KIND:-container}"
[[ "$KIND" == container || "$KIND" == native ]] \
  || die "KIND '$KIND' must be container or native"

if [[ "$KIND" == native ]]; then
  [[ "$SERVICE" =~ ^[A-Za-z0-9._-]+$ ]] || die "SERVICE '$SERVICE' is not a unit name"
else
  [[ "$SERVICE" =~ ^[A-Za-z0-9._-]+$ ]] || die "SERVICE '$SERVICE' is not a container name"
fi
[[ "$ADMIN_RPC" =~ ^http://(127\.0\.0\.1|localhost|\[::1\]):[0-9]+$ ]] \
  || die "ADMIN_RPC '$ADMIN_RPC' must be loopback: can_delete is an admin call and does not leave this host"

# The rotation log source. On native it is the cfg's own [debug_logfile],
# proven readable and non-empty here rather than discovered silent at the
# first 04:00 window: a log source that answers "unknown" every time is the
# rotation guard's worst failure (see the design note), because "unknown"
# is the one verdict that never refuses a restart.
LOG_FILE=''
LOG_LINES=5000
if [[ "$KIND" == native ]]; then
  [[ -n "$NODE_CFG" && -r "$NODE_CFG" ]] \
    || die "KIND=native but no readable node config is named; pass APERIRE_NODE_CONFIG=/path/to/cfg"
  LOG_FILE=$(awk '
    /^[[:space:]]*\[debug_logfile\][[:space:]]*$/ { inb=1; next }
    inb && /^[[:space:]]*\[/                      { inb=0 }
    inb && NF && $0 !~ /^[[:space:]]*#/ {
      sub(/^[[:space:]]+/, ""); sub(/[[:space:]]+$/, ""); print; exit
    }
  ' "$NODE_CFG")
  [[ -n "$LOG_FILE" ]] \
    || die "$NODE_CFG names no [debug_logfile]; the rotation guard would have no log to read and that is refused here, not discovered during the first window"
  [[ -r "$LOG_FILE" ]] \
    || die "$NODE_CFG names $LOG_FILE as its debug log and it is not readable by $(id -un)"
  [[ -s "$LOG_FILE" ]] \
    || die "$LOG_FILE is empty; the log source has to answer before a timer is pointed at it"
else
  command -v docker >/dev/null 2>&1 \
    || die "the node's container is '${SERVICE}' and docker is not installed here to confirm it"
  docker inspect "$SERVICE" >/dev/null 2>&1 \
    || die "no container named '$SERVICE' on this host, check the name before installing a timer that will talk to it"
fi

# ── Install ──────────────────────────────────────────────────────────────
# The program and both units are checked against the release's digests and
# copied from the one read that was checked (ADR 0024). A refusal stops here,
# before a conf or a timer points at a program that is not the release's.
# shellcheck source=scripts/release-digests-lib.sh
. "$DIGESTS_LIB"
install -d -m 0755 /usr/local/lib/aperire
rd_place "$REPO_DIR" scripts/aperire-can-delete.sh /usr/local/lib/aperire/aperire-can-delete.sh 0755 >/dev/null \
  || die "the rotation program was not installed; nothing else was written"
rd_place "$REPO_DIR" scripts/aperire-can-delete.service /etc/systemd/system/aperire-can-delete.service 0644 >/dev/null \
  || die "the rotation unit was not installed; the program is in place and no timer points at it"
rd_place "$REPO_DIR" scripts/aperire-can-delete.timer /etc/systemd/system/aperire-can-delete.timer 0644 >/dev/null \
  || die "the rotation timer was not installed; the program and its unit are in place and nothing schedules them"

install -d -m 0755 /etc/aperire
umask 0077
cat > /etc/aperire/can-delete.conf <<EOF
# Written by scripts/install-can-delete-timer.sh. Read, never sourced.
#
# KIND           container (docker) or native (a systemd-managed package).
#                Decides which log source and command rotation_state() uses,
#                and whether can_delete talks to a container's admin RPC or
#                a native node's.
# SERVICE        the node's container name (KIND=container), or its systemd
#                unit (KIND=native), for reading its log
# ADMIN_RPC      loopback admin RPC, for can_delete and server_info
# LOG_FILE       (native only) the cfg's own [debug_logfile], read with
#                \`tail\` rather than a container's timestamped \`docker logs\`
# LOG_LINES      (native only) how many lines of LOG_FILE to read each check.
#                A line count, not a duration, so it bounds the READ and not
#                the window. What expires a stale "rotating" line is the
#                line's own timestamp, read after the match and aged against
#                the same 240-minute bound aperire-node-wrapper.sh uses, so
#                both readers of this log agree about the node in front of
#                them. Keep this bounded, and treat a rotation stuck at
#                "rotating" as a finding to look into, not routine
# LOCK           held for the whole window; aperire-node-wrapper.sh takes the
#                same lock before it stops the node
# ARM_GRACE      seconds a rotation gets to start after being authorised.
#                Nothing within this means none was due, and the store is
#                disarmed again
# ROTATION_HOLD  seconds to hold the lock while a rotation runs. Past this the
#                lock is released and the node's own log is what keeps a
#                restart out, and that log check has its own bound,
#                ROTATION_STALE_MIN in scripts/aperire-node-wrapper.sh
#                (240 minutes), past which nothing blocks a restart at all.
#                Both are uncalibrated. Time a real rotation on this node
#                ("rotating" to "finished rotation") and keep ROTATION_STALE_MIN
#                above it.
# LOOKBACK       (container only) how far back to read the node's log for a
#                rotation
KIND=$KIND
SERVICE=$SERVICE
ADMIN_RPC=$ADMIN_RPC
LOG_FILE=$LOG_FILE
LOG_LINES=$LOG_LINES
LOCK=/run/aperire/node-rotation.lock
ARM_GRACE=300
ROTATION_HOLD=5400
LOOKBACK=24h
EOF
chown root:root /etc/aperire/can-delete.conf
chmod 0640 /etc/aperire/can-delete.conf
umask 0022

systemctl daemon-reload

printf 'installed:\n'
printf '  /usr/local/lib/aperire/aperire-can-delete.sh\n'
printf '  /etc/aperire/can-delete.conf\n'
printf '  aperire-can-delete.service + .timer\n\n'

# ── Normalize [node_db]: exactly one advisory_delete line (issue #81) ─────
# The stock xrpld/xahaud rippled.cfg ships a commented example block carrying a
# stray advisory_delete=0. A real online_delete added above it leaves the block
# with TWO advisory_delete lines, and rippled tolerates the duplicate and picks
# one (last-wins). A tool that flips the first line to 1 while a trailing =0
# remains would restart the node believing rotation is gated when it is not, so
# the duplicate must go before advisory_delete is ever set. dedup-nodedb.sh
# keeps the first line, truncate-writes to preserve the config's owner and mode
# (a bind-mounted validator config is not handed to rippled under a new owner),
# and is a no-op at one line or none. Tolerated on failure for the same reason
# the timer install itself is: this is a node the installer did not deploy and
# may not be able to reconfigure. A duplicate we cannot clear here is caught
# again, and refused loudly, by enable-advisory-delete.sh (issue #79) before any
# flip, so nothing is silently ungated either way.
DEDUP="$CD_SELF/dedup-nodedb.sh"
if [[ -n "$NODE_CFG" && -f "$NODE_CFG" ]]; then
  if [[ -w "$NODE_CFG" && -f "$DEDUP" ]]; then
    # Root rewrites this file, so a service account must not be able to change
    # it or a directory above it (ADR 0024): the same trusted-path judgment
    # every other root write is held to. Anything but a clean answer (a
    # refusal, a fault, the account check not running, even the pre-migration
    # tolerance) skips the rewrite and says why (#1132). The rewrite itself is
    # then done on a descriptor, so a link put at the name later is not
    # followed either.
    dedup_rc=0
    if declare -F trusted_path_check >/dev/null 2>&1; then
      trusted_path_check "$NODE_CFG" "$REPO_DIR" || dedup_rc=$?
    else
      dedup_rc=1
    fi
    if [[ $dedup_rc -ne 0 ]]; then
      printf '  !! %s was not normalized: root will not rewrite a file the trusted-path check did not clear (named above)\n' "$NODE_CFG"
      printf '     Give the file and the directories above it to root, or take the write from the account named,\n'
      printf '     then run this again. enable-advisory-delete.sh will refuse a duplicate if one remains.\n\n'
    elif ! bash "$DEDUP" "$NODE_CFG"; then
      printf '  !! could not normalize [node_db] in %s\n' "$NODE_CFG"
      printf '     enable-advisory-delete.sh will refuse a duplicate if one remains.\n\n'
    fi
  else
    printf '  note: %s not writable here, skipping [node_db] normalization\n\n' "$NODE_CFG"
  fi
fi

# ── Enable, but only if the node will listen ─────────────────────────────
advisory=''
if [[ -n "$NODE_CFG" && -r "$NODE_CFG" ]]; then
  advisory=$(awk '
    /^[[:space:]]*\[node_db\][[:space:]]*$/ { inb = 1; next }
    inb && /^[[:space:]]*\[/               { inb = 0 }
    inb && /^[[:space:]]*advisory_delete[[:space:]]*=/ {
      sub(/^[^=]*=[[:space:]]*/, ""); sub(/[[:space:]]+$/, ""); print; exit
    }
  ' "$NODE_CFG")
fi

# The config on disk says what the node will do NEXT start. What it is doing
# now is a different question, and the RPC is the only one that answers it.
live=unknown
if body=$(curl -sS --max-time 10 --data '{"method":"can_delete","params":[{}]}' "$ADMIN_RPC" 2>/dev/null); then
  if printf '%s' "$body" | grep -q 'notEnabled'; then live=off; else
    printf '%s' "$body" | grep -q '"can_delete"' && live=on
  fi
fi

if [[ "$live" == on ]]; then
  systemctl enable --now aperire-can-delete.timer
  printf 'The running node has advisory_delete on. The timer is enabled.\n\n'
  printf 'Next window:  systemctl list-timers aperire-can-delete.timer\n'
  printf 'Right now:    sudo /usr/local/lib/aperire/aperire-can-delete.sh --status\n'
  exit 0
fi

# --now, matching the enable above. `enable --now` both enables at boot and
# starts the timer; a bare `disable` only removes the boot symlink, so a timer
# that was already running kept running and kept firing at 04:00 against a
# node this script had just said on screen it was not watching. Observed on
# aperire2 during the native lab: UnitFileState=disabled, ActiveState=active,
# NextElapseUSecRealtime tomorrow at 04:00, under a paragraph saying NOT
# enabled (#416).
#
# Every container-to-native conversion reaches this, because the native
# installer hardens the shipped config to advisory_delete = 0 while the window
# from the host's container days is still installed. The word "enabled" now
# means the same thing in both branches.
systemctl disable --now aperire-can-delete.timer >/dev/null 2>&1 || true
cat <<EOF
The timer is installed but NOT enabled, because this node is still rotating
on its own$([[ "$live" == off ]] && printf ' (the node answered can_delete with "not enabled")' || printf " (the node did not answer, so this could not be confirmed either way)").$( [[ -n "$advisory" ]] && printf '\nIts config file says advisory_delete=%s.' "$advisory" )

Finish it in this order:

  1. curl -fsSL https://get.aperire.one | bash -s -- --run advisory-delete ${NODE_CFG:+--config $NODE_CFG}
  2. Restart the node, when no rotation is in flight. Until step 1 takes
     effect the node still rotates unannounced, so check first:
         $( [[ "$KIND" == native ]] \
             && printf "tail -n 500 %s | grep -E 'rotating|finished rotation'" "$LOG_FILE" \
             || printf "docker logs --tail 500 %s | grep -E 'rotating|finished rotation'" "$SERVICE" )
  3. curl -fsSL https://get.aperire.one | bash -s -- --update --force      (this step, again)

Step 3 will find advisory_delete on and enable the timer.
EOF
