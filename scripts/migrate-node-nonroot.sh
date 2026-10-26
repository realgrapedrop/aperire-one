#!/usr/bin/env bash
# Move a node that was installed before #31 onto the non-root user, on a host
# that already has one running.
#
#   sudo bash scripts/migrate-node-nonroot.sh                    # report only
#   sudo bash scripts/migrate-node-nonroot.sh --apply            # make the change
#   sudo bash scripts/migrate-node-nonroot.sh --hand-store-back  # give the store back to root
#
# Report mode changes nothing, and reports whatever the host will let it read.
# Run it first, while the node is still up: a report that refused to report
# until the node was stopped was a first step nobody could take (#435).
#
# ── What changes ──────────────────────────────────────────────────────────
#
#   the account       `xrpld` is created if this host has no such account,
#                     preferring uid 997 gid 997, the ids the node image
#                     itself uses (scripts/node-user-lib.sh)
#   <dir>/data        chowned to that account, recursively. It is the only
#                     writable thing the container gets, and a node that does
#                     not own it cannot open its own store
#   the node config   its GROUP moves to that account, so the node reads it
#                     the way container-root used to read it through group
#                     root. The mode is not touched: a chmod recalculates the
#                     ACL mask, and on a host where the relay holds a read
#                     entry on this file that is how the connection-count
#                     charts go blank
#   docker-compose.yml
#                     gains `user:` and the two /etc/xrpld mounts, patched in
#                     place. The old file is kept beside it as a dated .bak,
#                     the same name and predicate the wrapper's
#                     restore-compose accepts
#
# ── What it refuses ───────────────────────────────────────────────────────
#
#   the node is running     it must be stopped first, by hand. Chowning a
#                           store underneath a running node changes what it
#                           can write mid-write, and starting it again is the
#                           operator's call, not this script's
#   the store is rotating   the same guard every stop in this project takes.
#                           A node stopped inside a NuDB rotation came back
#                           with an empty store and rebuilt from genesis
#                           (#79). The lock is taken for the whole run, so the
#                           scheduled window cannot start under it either
#   the verdict cannot be   and that is not the same as idle (#442). The
#   read                    verdict comes from the privilege wrapper, which
#                           needs its own configuration, and a host with a
#                           node and no Advisor has none. --apply refuses
#                           rather than proceeding on a question it could not
#                           ask; --rotation-checked-by-hand is how an operator
#                           who has read the node's own log says so
#   a path is missing       the install directory, the config, data/. A
#                           migration that invents a missing path is a
#                           migration onto a host it has not understood
#   data/ is a symlink      a store on a second disk is an ordinary
#                           arrangement, and `chown -R` through a symlink is
#                           how a migration reaches outside the node's own
#                           directories. It names the target and stops
#
# Idempotent. A second run finds the account, the ownership and the compose
# already right and changes nothing.
#
# ── Putting it back ───────────────────────────────────────────────────────
#
# The run prints both halves, with the real paths filled in. It is:
#
#   sudo docker compose -f <compose> stop
#   sudo cp <compose>.<stamp>.bak <compose>
#   curl -fsSL https://get.aperire.one | bash -s -- --run migrate-node --hand-store-back
#   sudo chgrp root <config>            # what container-root read it as
#   sudo docker compose -f <compose> up -d
#
# The store goes back with --hand-store-back (#1148), entry by entry on a
# descriptor, the way it went over, and not with a `chown -R` you type: a
# recursive chown by name changes a hard link to a file outside the store like
# any other entry, and the node's account writes this tree. It does that and
# nothing else, takes the same node-stopped and rotation guards as --apply, and
# the path is the one the compose file names, not one you give it.
#
# Nothing outside <dir> and the node's own config is touched by either
# direction.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONF=/etc/aperire/node-wrapper.conf
NODE_CONF=/etc/aperire/node.conf
ROTATION_LOCK=/run/aperire/node-rotation.lock
ROTATION_LOCK_WAIT=45
APPLY=0
PUT_BACK=0
ROT_BY_HAND=0
for arg in "$@"; do
  case "$arg" in
    --apply) APPLY=1 ;;
    --hand-store-back) PUT_BACK=1 ;;
    --rotation-checked-by-hand) ROT_BY_HAND=1 ;;
    # The comment block, however long it grows. A line number here drifts every
    # time the header gains a paragraph, and the first thing an operator sees
    # from -h becomes `set -euo pipefail` and the path constants under it.
    -h|--help) sed -n '2,${/^#/!q;p;}' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument '$arg' (--apply, --hand-store-back, --rotation-checked-by-hand, or nothing for a report)" >&2; exit 2 ;;
  esac
done
if ((PUT_BACK && APPLY)); then
  echo "--hand-store-back gives the store back to root and --apply gives it to the node: two different jobs, run one at a time" >&2
  exit 2
fi
# Giving the store back takes every guard --apply takes (the node stopped, no
# rotation in flight, or the operator's word that there is none), so it runs
# through the same code and diverges at the first thing --apply would change.
((PUT_BACK)) && APPLY=1

die()  { echo "  error: $*" >&2; exit 1; }
say()  { echo; echo "== $*"; }
info() { echo "   $*"; }

[[ $EUID -eq 0 ]] || die "run with sudo: it changes file ownership and creates a system account"

[[ -r "${HERE}/node-user-lib.sh" ]] \
  || die "${HERE}/node-user-lib.sh is missing from this checkout"
# shellcheck source=scripts/node-user-lib.sh
. "${HERE}/node-user-lib.sh"

# The ACL-carrying helper this script shares with aperire-node-wrapper.sh's
# set-config, enable-advisory-delete.sh and configure-rippled-paths.sh (#545).
[[ -r "${HERE}/config-write-lib.sh" ]] \
  || die "${HERE}/config-write-lib.sh is missing from this checkout"
# shellcheck source=scripts/config-write-lib.sh
. "${HERE}/config-write-lib.sh"

# ── What this host has ────────────────────────────────────────────────────
# Read, never sourced. These files decide what gets chowned, so a shell
# metacharacter in one of them stays data.
conf_value() { # $1 = key, $2 = file
  [[ -r "$2" ]] || return 0
  awk -F= -v k="$1" '$1==k {sub(/^[^=]*=/,""); print; exit}' "$2"
}

# Either file will do, and a box with a node and no Advisor only has the
# second one. install-aperire-node.sh always writes /etc/aperire/node.conf;
# /etc/aperire/node-wrapper.conf only exists where the Advisor's privilege
# wrapper was installed, and the node installer's own suite asserts a plain
# container run writes none. Pointing an operator at install-node-wrapper.sh
# to migrate a node-only box would be a dead end.
#
# The wrapper's file wins where both are there: it is the one that names the
# compose file outright, and it is what every other script on the box reads.
SOURCED_FROM=''
KIND='' SERVICE='' CONFIG_FILE='' COMPOSE_FILE=''
if [[ -f "$CONF" ]]; then
  SOURCED_FROM="$CONF"
  KIND=$(conf_value KIND "$CONF")
  SERVICE=$(conf_value SERVICE "$CONF")
  CONFIG_FILE=$(conf_value CONFIG_FILE "$CONF")
  COMPOSE_FILE=$(conf_value COMPOSE_FILE "$CONF")
fi
if [[ -z "$SERVICE" || -z "$COMPOSE_FILE" ]] && [[ -f "$NODE_CONF" ]]; then
  [[ -n "$SOURCED_FROM" ]] && SOURCED_FROM="${SOURCED_FROM} and ${NODE_CONF}" || SOURCED_FROM="$NODE_CONF"
  [[ -z "$KIND" ]]        && KIND=$(conf_value KIND "$NODE_CONF")
  [[ -z "$SERVICE" ]]     && SERVICE=$(conf_value SERVICE "$NODE_CONF")
  [[ -z "$CONFIG_FILE" ]] && CONFIG_FILE=$(conf_value CONFIG_FILE "$NODE_CONF")
  # node.conf names no compose file. The container itself does: compose
  # stamps the file it was started from onto the container as a label, which
  # is a stronger source than a path this script would otherwise guess at.
  if [[ -z "$COMPOSE_FILE" && -n "$SERVICE" ]] && command -v docker >/dev/null 2>&1; then
    # The `|| COMPOSE_FILE=''` is the reason this run says anything at all on
    # the host it is meant for. `docker compose down`, which is the stop these
    # instructions name, removes the container, so this inspect exits
    # non-zero, and under `set -euo pipefail` a failing pipeline in an
    # assignment ends the script right here: no message, no report, status 1,
    # on the exact sequence the deployment guide prints.
    COMPOSE_FILE=$(docker inspect "$SERVICE" \
      --format '{{ index .Config.Labels "com.docker.compose.project.config_files"}}' 2>/dev/null | cut -d, -f1) \
      || COMPOSE_FILE=''
  fi
  # A removed container carries no label, and this script only ever runs
  # against a node that has been stopped, so the label cannot be the only way
  # to the file. scripts/install-aperire-node.sh writes config/ and the
  # compose side by side under one directory, so the config named above is a
  # second way to the same file. It is a candidate, not an answer: the two
  # store-mount checks below refuse it if it belongs to some other node.
  if [[ -z "$COMPOSE_FILE" && -n "$CONFIG_FILE" ]]; then
    BESIDE_CONFIG="$(dirname "$(dirname "$CONFIG_FILE")")/docker-compose.yml"
    [[ -f "$BESIDE_CONFIG" ]] && COMPOSE_FILE="$BESIDE_CONFIG"
  fi
fi

[[ -n "$SOURCED_FROM" ]] \
  || die "neither $CONF nor $NODE_CONF is here, so which node this host runs is not something this script can read. Install the node with scripts/install-aperire-node.sh, or the Advisor's wrapper with scripts/install-node-wrapper.sh, and run this again"

[[ "$KIND" == container || -z "$KIND" ]] \
  || die "this host runs a ${KIND} node. The vendor's own unit already runs it as User=xrpld, so there is nothing here to migrate"
[[ -n "$SERVICE" && "$SERVICE" != none ]] || die "$SOURCED_FROM names no node container (SERVICE=${SERVICE:-<unset>})"
[[ -n "$COMPOSE_FILE" && -f "$COMPOSE_FILE" ]] || die "the deployment file for ${SERVICE} could not be found (COMPOSE_FILE=${COMPOSE_FILE:-<unset>}). It is read from $CONF, from the container's own compose label while the container is still there, or from docker-compose.yml beside the directory holding ${CONFIG_FILE:-the node config}"
[[ -n "$CONFIG_FILE" && -f "$CONFIG_FILE" ]] || die "$SOURCED_FROM names CONFIG_FILE=${CONFIG_FILE:-<unset>}, which is not a file here"

DIR=$(dirname "$COMPOSE_FILE")
DATA_DIR="${DIR}/data"

say "What this host is running"
info "read from   : $SOURCED_FROM"
info "container   : $SERVICE"
info "compose     : $COMPOSE_FILE"
info "config      : $CONFIG_FILE"
info "store       : $DATA_DIR"

# The store, found rather than assumed. A compose that keeps its data
# somewhere else is a compose this script has not understood, and chowning
# the wrong tree is not a mistake it can take back.
[[ -d "$DATA_DIR" ]] \
  || die "$DATA_DIR is not a directory. This script only migrates the layout scripts/install-aperire-node.sh writes, where the store is data/ beside the compose file"
[[ ! -L "$DATA_DIR" ]] \
  || die "$DATA_DIR is a symbolic link to $(readlink -f "$DATA_DIR" 2>/dev/null || echo '<unreadable>'). A recursive chown through it would reach outside this node's own directories. Move the store or chown it by hand, then run this again"
grep -qF ":/var/lib/xrpld" "$COMPOSE_FILE" \
  || die "$COMPOSE_FILE does not mount anything at /var/lib/xrpld, so which directory the node writes its store to is not something this script can read out of it"
grep -qF -e "${DATA_DIR}:/var/lib/xrpld" "$COMPOSE_FILE" \
  || die "$COMPOSE_FILE mounts something other than ${DATA_DIR} at /var/lib/xrpld. Migrate that host by hand: this script would chown a directory the node does not use"

# ── The compose file's own explanation of itself ──────────────────────────
#
# The migration patches the deployment in place rather than re-rendering it,
# which is right: a per-host edit (a corrected peer mapping, a different memory
# cap) would be reverted by a re-render, and that is a test row. The comment
# block above `name:` came from whichever release rendered the file, so a
# migrated compose ran the node as a non-root account under a header still
# explaining why the store has to be root-owned (#438). Three lines apart, in
# one file, and the comments are the part an operator reads when they open it
# to find out why it looks like that.
#
# So the header is replaced with the one this release ships, rendered with the
# same five values the installer renders it with, and every line from `name:`
# down is left exactly as it is.
COMPOSE_TEMPLATE="${HERE}/templates/aperire-node.compose.yml"

# The node's own log, as a path on THIS host. Read from the config rather than
# composed from what the shipped template happens to say: a host this
# installer did not set up, which is the host --apply is most often run on,
# names its log wherever its operator put it. The declared path is a container
# path, and the only mount that maps back to the host is the store, so
# anything outside it cannot be pointed at from here and is said rather than
# guessed.
node_log_host_path() {
  local declared
  declared=$(awk '
    /^[[:space:]]*\[debug_logfile\][[:space:]]*$/ { getline; gsub(/^[[:space:]]+|[[:space:]]+$/, ""); print; exit }
  ' "$CONFIG_FILE" 2>/dev/null)
  [[ -n "$declared" ]] || return 1
  # The config is the login's, so a declared path with a .. in it could name a
  # file anywhere the login chose, and the path is printed as a command to run.
  case "$declared" in
    */..|*/../*) return 1 ;;
    /var/lib/xrpld/*) printf '%s%s' "$DATA_DIR" "${declared#/var/lib/xrpld}" ;;
    *) return 1 ;;
  esac
}

compose_image_tag() {  # the tag the running deployment names, @TAG@'s value
  sed -n 's#^[[:space:]]*image:[[:space:]]*[^:[:space:]]*:\([^[:space:]]*\).*#\1#p' "$COMPOSE_FILE" | head -1
}

compose_header_ids() {  # "uid gid" to render the header with
  local u g
  if [[ -n "${NODE_UID:-}" && -n "${NODE_GID:-}" ]]; then
    printf '%s %s' "$NODE_UID" "$NODE_GID"; return 0
  fi
  u=$(sed -nE 's/^[[:space:]]*user:[[:space:]]*"([0-9]+):([0-9]+)".*/\1/p' "$COMPOSE_FILE" | head -1)
  g=$(sed -nE 's/^[[:space:]]*user:[[:space:]]*"([0-9]+):([0-9]+)".*/\2/p' "$COMPOSE_FILE" | head -1)
  printf '%s %s' "${u:-997}" "${g:-997}"
}

compose_header_of() {  # $1 = a compose file; everything above its `name:` line
  grep -q '^name:' "$1" || return 1
  sed -n '1,/^name:/p' "$1" | sed '$d'
}

compose_header_rendered() {  # the current template's header, same sed as the installer
  local uid gid
  [[ -r "$COMPOSE_TEMPLATE" ]] || return 1
  read -r uid gid < <(compose_header_ids)
  sed -e "s#@NAME@#${SERVICE}#g" \
      -e "s#@DIR@#${DIR}#g" \
      -e "s#@TAG@#$(compose_image_tag)#g" \
      -e "s#@UID@#${uid}#g" \
      -e "s#@GID@#${gid}#g" \
      "$COMPOSE_TEMPLATE" > "$TMP_HEADER_SRC"
  compose_header_of "$TMP_HEADER_SRC"
}

# compose_header_state: how the file's header compares with what this release
# renders, one word, so every caller reads the same fact instead of folding
# two different absences into "current" (#467):
#   current      already this release's header
#   stale        an older release's header; the apply rewrites it
#   no-name      the file has no `name:` line at all, so there is nothing to
#                read a header out of and nowhere safe to anchor one on. Not
#                this release's header either way, and left alone rather than
#                guessed at, the same caution the unreadable-compose refusal
#                elsewhere in this script takes
#   no-template  this checkout carries no template to compare against; a true
#                no-op, not a verdict on the file
compose_header_state() {
  local now want
  now=$(compose_header_of "$COMPOSE_FILE") || { printf 'no-name'; return 0; }
  want=$(compose_header_rendered) || { printf 'no-template'; return 0; }
  if [[ "$now" == "$want" ]]; then
    printf 'current'
  else
    printf 'stale'
  fi
}

TMP_HEADER_SRC=$(mktemp)
# What root recorded of the store and the two config files before it changed
# anything (#1152), removed with everything else on the way out.
LIST_STORE=""; LIST_CONFIG=""; LIST_VALIDATORS=""
trap 'rm -f "$TMP_HEADER_SRC" "$LIST_STORE" "$LIST_CONFIG" "$LIST_VALIDATORS"' EXIT

# ── The node must be stopped ──────────────────────────────────────────────
say "Is the node stopped"
if command -v docker >/dev/null 2>&1 && docker inspect "$SERVICE" >/dev/null 2>&1; then
  RUNSTATE=$(docker inspect -f '{{.State.Status}}' "$SERVICE" 2>/dev/null || echo unknown)
else
  RUNSTATE=absent
fi
info "container state: $RUNSTATE"
NODE_RUNNING=0
[[ "$RUNSTATE" == running ]] && NODE_RUNNING=1
# The refusal belongs to --apply. Report mode changes nothing, so it has no
# reason to refuse, and refusing was how the documented first step became a
# command nobody could run: every node worth migrating is running when its
# operator reads about migrating it (#435). The report says at the end that
# the node has to be stopped, which is the sentence that was missing.
if ((NODE_RUNNING)) && ((APPLY)); then
  say "Refusing: the node is running"
  info "stop it first, and start it again yourself when this has finished:"
  info "    sudo docker compose -f ${COMPOSE_FILE} stop     # stop, not down: a removed"
  info "                                                    # container takes the compose"
  info "                                                    # label and the log with it"
  if ((PUT_BACK)); then
    info "    curl -fsSL https://get.aperire.one | bash -s -- --run migrate-node --hand-store-back"
    info "    sudo docker compose -f ${COMPOSE_FILE} up -d"
  else
    info "    sudo bash $0 --apply"
    info "    sudo docker compose -f ${COMPOSE_FILE} up -d    # recreates it in the new shape"
  fi
  info "changing the ownership of a store underneath a running node changes what"
  info "it can write in the middle of a write. Nothing has been changed."
  exit 1
fi

# ── The rotation guard, the same one every stop takes ─────────────────────
# Held on fd 9 for the rest of the run, so the scheduled window cannot start
# while the store is being chowned either.
say "Store rotation"
if ((APPLY)); then
  install -d -m 0755 "$(dirname "$ROTATION_LOCK")"
  exec 9>"$ROTATION_LOCK"
  if ! flock -w "$ROTATION_LOCK_WAIT" 9; then
    die "the scheduled store-rotation window holds $ROTATION_LOCK. It is bounded and releases on its own; try again in a few minutes, or check: systemctl status aperire-can-delete.service"
  fi
elif [[ -e "$ROTATION_LOCK" ]]; then
  # Probed, never held, and never fatal: a report that died because a window
  # was running would be the same first step nobody can take. Three answers,
  # because "could not look" is not "free", the same three the window's own
  # --status prints.
  if flock -n 8 8<"$ROTATION_LOCK" 2>/dev/null; then
    info "rotation lock: free"
  else
    info "rotation lock: HELD, a rotation window or a node stop is running right now"
  fi
fi

# The verdict, and WHERE it came from. Not being able to read it is not the
# same as reading it and finding nothing (#442): the wrapper needs its own
# configuration, a host with a node and no Advisor has none, and the empty
# string it returns there used to land in the arm that proceeds. A 46 GB store
# was migrated under exactly that on aperire4, with nothing standing between
# it and #79.
#
# The verdict has one reader in this project and this is not it: the wrapper's
# rotation-state is where the log patterns, the stale bound and the container
# and native branches live. This asks that reader, keeps its exit status
# (which `| head -1` used to swallow), and says plainly when there was nobody
# to ask.
ROT_SOURCE='' ROT_STATE='' ROT_WHY='' ROT_UNREADABLE=''
WRAPPER_SH="${HERE}/aperire-node-wrapper.sh"
if [[ -f "$CONF" && -r "$WRAPPER_SH" ]]; then
  ROT_ERR=$(mktemp)
  ROT_RC=0
  # --wait: the read with no time limit (#1043). This is the guard in front
  # of touching a store, and a slow log cut into "unknown" would let it pass.
  ROT_RAW=$(bash "$WRAPPER_SH" rotation-state --wait 2>"$ROT_ERR") || ROT_RC=$?
  ROT=$(printf '%s\n' "$ROT_RAW" | head -1)
  if [[ $ROT_RC -eq 0 && -n "$ROT" ]]; then
    ROT_SOURCE="${WRAPPER_SH##*/} rotation-state"
    ROT_STATE=$(printf '%s' "$ROT" | cut -f1)
    ROT_WHY=$(printf '%s' "$ROT" | cut -f2-)
  else
    ROT_UNREADABLE=$(head -1 "$ROT_ERR")
    ROT_UNREADABLE=${ROT_UNREADABLE:-"it exited ${ROT_RC} without a verdict"}
  fi
  rm -f "$ROT_ERR"
else
  ROT_UNREADABLE="there is no ${CONF} on this host, so the wrapper has no node to answer about"
fi

if [[ -n "$ROT_SOURCE" ]]; then
  info "rotation-state: ${ROT_STATE:-unknown}  (from ${ROT_SOURCE})"
  [[ -n "$ROT_WHY" ]] && info "${ROT_WHY}"
  case "$ROT_STATE" in
    idle|clear|stale) ;;
    unknown) info "the reader answered, and could not tell: treating it the way it says, as unknown" ;;
    rotating) die "a store rotation is in flight (#79), so the store is not touched; the wrapper's line above says what stopping inside one does. Wait for it to finish, then run this again" ;;
    *) die "rotation-state answered '${ROT_STATE}', which this script does not know how to read. Not touching the store" ;;
  esac
else
  info "rotation-state: NOT ASKED, ${ROT_UNREADABLE}"
  info "so the #79 protection is not available on this host, and 'not asked' is"
  info "not 'idle'. What to read instead, with the node stopped:"
  if NODE_LOG=$(node_log_host_path) && [[ -f "$NODE_LOG" ]]; then
    info "    sudo tail -n 200 $(printf '%q' "$NODE_LOG") | grep -E 'rotating validatedSeq|finished rotation'"
  elif [[ "$RUNSTATE" != absent ]]; then
    # Named, not guessed. A refusal that points at a file which is not there
    # is an instruction an operator stops trusting.
    info "    docker logs --tail 200 ${SERVICE} | grep -E 'rotating validatedSeq|finished rotation'"
    info "(${CONFIG_FILE} names no [debug_logfile] under the store this host mounts,"
    info "so there is no copy of that log outside the container to read.)"
  else
    # Both sources gone, and that has a common cause worth saying: the old
    # printed sequence for this migration said `down`, which removes the
    # container and takes docker's json log with it. Printing `docker logs`
    # at a container that no longer exists is the same class of instruction
    # the [debug_logfile] lookup above was written to stop.
    info "    neither source is readable on this host: ${CONFIG_FILE} names no"
    info "    [debug_logfile] under the store this host mounts, and there is no"
    info "    ${SERVICE} container for docker logs to read (a container removed"
    info "    by 'docker compose down' takes its log with it)."
    info "what is still true with no container: nothing is writing the store now, so"
    info "the ownership change cannot land in the middle of a rotation. What no"
    info "reader here can tell you is whether the last stop landed inside one, and"
    info "this migration neither improves nor worsens that."
  fi
  info "a 'rotating validatedSeq' line with no 'finished rotation' after it is a"
  info "rotation that had not finished. Anything else is safe to migrate under."
  if ((APPLY)) && ((! ROT_BY_HAND)); then
    die "refusing to migrate a store while whether it is rotating is unknown (#442). Read the log above, then re-run with --rotation-checked-by-hand to say you have"
  fi
  ((ROT_BY_HAND)) && info "--rotation-checked-by-hand was passed: proceeding on your reading of that log."
fi

# ── The account ───────────────────────────────────────────────────────────
say "The account the node will run as"
if EXISTING="$(node_account_read)"; then
  IFS=$'\t' read -r NODE_USER NODE_UID NODE_GID <<< "$EXISTING"
  info "$NODE_USER already exists here: uid $NODE_UID, gid $NODE_GID"
  CREATE_ACCOUNT=0
else
  NODE_USER=$(node_account_name)
  info "no $NODE_USER account on this host yet; one will be created"
  CREATE_ACCOUNT=1
  NODE_UID='' NODE_GID=''
fi

# ── What is already true ──────────────────────────────────────────────────
DATA_OWNER=$(stat -c '%U' "$DATA_DIR")
CFG_GROUP=$(stat -c '%G' "$CONFIG_FILE")
CFG_MODE=$(stat -c '%a' "$CONFIG_FILE")
COMPOSE_HAS_USER=0
grep -qE '^[[:space:]]*user:[[:space:]]*"' "$COMPOSE_FILE" && COMPOSE_HAS_USER=1
COMPOSE_HAS_ETC=0
grep -qF ":/etc/xrpld/xrpld.cfg:ro" "$COMPOSE_FILE" && COMPOSE_HAS_ETC=1

say "What is already true"
info "data/ owner     : $DATA_OWNER"
info "config group    : $CFG_GROUP  (mode $CFG_MODE, untouched by this script)"
info "compose user:   : $( ((COMPOSE_HAS_USER)) && echo present || echo absent)"
info "compose /etc/xrpld mounts: $( ((COMPOSE_HAS_ETC)) && echo present || echo absent)"

HEADER_STATE=$(compose_header_state)
case "$HEADER_STATE" in
  no-name) info "compose header  : no 'name:' line in this file, so it is not this release's header" ;;
  stale)   info "compose header  : written before the node ran as ${NODE_USER}, and says the store must be root-owned" ;;
  *)       info "compose header  : current" ;;
esac

if [[ $APPLY -eq 0 ]]; then
  say "What --apply would do"
  ((CREATE_ACCOUNT)) && info "create the ${NODE_USER} system account (uid 997 if this host has it free)"
  info "chown -R ${NODE_USER}:${NODE_USER} ${DATA_DIR}"
  info "group ${NODE_USER} on ${CONFIG_FILE}   # and validators.txt beside it, if there is one"
  info "copy ${COMPOSE_FILE} to a dated .bak, then add user: and the /etc/xrpld mounts to it"
  case "$HEADER_STATE" in
    stale)   info "replace the comment block above 'name:' with the one this release ships, leaving every line from 'name:' down alone" ;;
    no-name) info "leave the header as it is: there is no 'name:' line to safely anchor a replacement on" ;;
  esac
  echo
  # The sentence that was missing. A report on a running node is a report,
  # and it ends by naming the one thing that has to be true before --apply
  # will do anything (#435).
  if ((NODE_RUNNING)); then
    say "Before --apply: stop the node"
    info "    sudo docker compose -f ${COMPOSE_FILE} stop"
    info "    sudo bash $0 --apply"
    info "    sudo docker compose -f ${COMPOSE_FILE} up -d"
    info "stop, not down: down removes the container, and with it the compose label"
    info "and the log this script and the rotation guard read."
  else
    info "it does not start the node. You do that, and watch it come back:"
    info "    sudo docker compose -f ${COMPOSE_FILE} up -d"
    info "re-run with --apply to make the change."
  fi
  exit 0
fi

# ── Apply ─────────────────────────────────────────────────────────────────
say "Applying"

# The store is handed over by descriptor (#1121), through the state helper
# that ships beside this script. Checked before anything is changed, so a
# host without it stops here and not after the compose file is rewritten.
command -v python3 >/dev/null 2>&1 \
  || die "python3 is needed to hand the store to ${NODE_USER} and was not found; nothing has been changed"
[[ -r "$HERE/state-file.py" ]] \
  || die "$HERE/state-file.py is missing, and it is what hands the store to ${NODE_USER}; nothing has been changed"
# The directory each path sits in, and the directories above it, are judged by
# the same rule the hand-over applies, now, while nothing has been written: a
# path that two accounts share, or that a group or the world can write, would
# refuse the hand-over below after the compose file was rewritten. The
# directory is judged too (--judge-root, #1153): the install directory is the
# operator's, not the node's, and an account that can write it can swap the
# store's name for another directory. The store itself and everything under it
# are not judged: they are the node's. Each refusal line ends with the command
# that fixes it.
refuse_shared_ancestors() { # $1 = the store or the file to be handed over
  local found _kind where why
  found="$(python3 -I "$HERE/state-file.py" ancestors "$1" --root "$(dirname -- "$1")" --judge-root 2>&1)" \
    || die "the directories above $1 could not be checked before it is handed to ${NODE_USER}: ${found}; nothing has been changed"
  [[ -z "$found" ]] && return 0
  while IFS=$'\t' read -r _kind where why; do
    info "refused: ${why:-$where}"
  done <<<"$found"
  die "the directory $1 sits in, or one above it, can be changed by an account other than root and the install's owner, so root will not change $1 through it (named above, each with the command that fixes it); run those, then this again; nothing has been changed"
}
record_for_handover() { # $1 = a path, $2 = the file to write the record to
  find "$1" -printf '%D:%i:%p\0' > "$2" 2>/dev/null
}
refuse_shared_ancestors "$DATA_DIR"

# --hand-store-back (#1148): the undo of the hand-over below, as a step. Only the
# store goes back to root, entry by entry on a descriptor from a record taken
# first, the way it went over; a hard link in it to a file outside it is named
# and left, where a recursive chown typed by name would have re-owned it.
# The compose file and the config's group are not touched here: the node is
# stopped, so they are plain files in the operator's own directory, and
# "Putting it back" names them.
if ((PUT_BACK)); then
  say "Giving the store back to root"
  # Only what the migration handed to the node's account, or what is root's
  # already: an entry the login put in the store since belongs to neither, and
  # a store the login swapped for its own would otherwise be given to root with
  # whatever ACLs and write bits its files carry. The record covers every entry
  # either way; this only narrows what is proposed against it.
  [[ "$NODE_UID" =~ ^[0-9]+$ ]] \
    || die "there is no ${NODE_USER} account on this host, so which entries of ${DATA_DIR} are the node's cannot be told; nothing has been changed"
  LIST_STORE=$(mktemp) || die "could not make the file this records the store in; nothing has been changed"
  record_for_handover "$DATA_DIR" "$LIST_STORE"
  if ! find "$DATA_DIR" \( -uid "$NODE_UID" -o -uid 0 \) -print0 \
       | python3 -I "$HERE/state-file.py" own-many 0 0 "" --root "$DIR" --judge-root --list "$LIST_STORE"; then
    die "${DATA_DIR} was not all given back to root: an entry in it is a link, has a second name, or is not what was there when this began (named above), and was left alone. Remove or replace what is named, then run this again with --hand-store-back; it changes nothing that is already right."
  fi
  info "${DATA_DIR} -> root:root, every entry that was the node's or root's, none followed through a link"
  LEFT=$(find "$DATA_DIR" ! -uid "$NODE_UID" ! -uid 0 -printf x 2>/dev/null | wc -c || true)
  if ((LEFT)); then
    info "${LEFT} entr$( ((LEFT == 1)) && echo y || echo ies) under it belong to neither ${NODE_USER} nor root and were left alone: this gives back what the migration handed over, not what was put there since"
  fi
  # The newest backup this script made: its own name (the stamp it writes, in
  # date order, with the digits spelled out because [0-9] follows the locale and
  # matches other scripts' digits under UTF-8) and nothing else. The directory is the login's, so any other
  # name there is the login's, and what is printed below is a line the operator
  # pastes into a root shell.
  PUT_BAK=""
  for _f in "${COMPOSE_FILE}".*.bak; do
    if [[ -f "$_f" && ! -L "$_f" && "$_f" =~ ^"${COMPOSE_FILE}"\.[0123456789]{8}-[0123456789]{6}\.bak$ ]]; then PUT_BAK="$_f"; fi
  done
  info "the compose file and the config's group are not changed by this. With the node still stopped, to finish putting it back:"
  if [[ -n "$PUT_BAK" ]]; then
    info "    sudo cp $(printf '%q' "$PUT_BAK") $(printf '%q' "$COMPOSE_FILE")"
  else
    info "    (no dated .bak beside ${COMPOSE_FILE}: it was already in the new shape when it was migrated, so there is no compose to copy back)"
  fi
  info "    sudo chgrp root $(printf '%q' "$CONFIG_FILE")      # what the container's root read it as"
  info "    sudo docker compose -f $(printf '%q' "$COMPOSE_FILE") up -d"
  exit 0
fi
refuse_shared_ancestors "$CONFIG_FILE"
# The group of the config is moved by descriptor too, and a descriptor walk
# does not follow a link, so a config that is one is refused here, with
# nothing yet changed, rather than after the store has been handed over.
for _f in "$CONFIG_FILE" "$(dirname -- "$CONFIG_FILE")/validators.txt"; do
  [[ ! -L "$_f" ]] \
    || die "${_f} is a symbolic link. Root changes the group of a file by descriptor and never through a link; point ${COMPOSE_FILE} at the real file, then run this again; nothing has been changed"
done

# The store and the two config files, each entry by device and inode, written
# now and held until the hand-over (#1152). The hand-over re-owns an entry only
# if it is the one recorded here: a root-owned file moved into the store after
# this point is named and left, not given to the node's account, and so is a
# config swapped for another file. This closes what changes between here and
# the hand-over; it cannot say what was already in the store when the record
# was taken. (record_for_handover is defined above, with the ancestor check.)
LIST_STORE=$(mktemp) || die "could not make the files this records the store in; nothing has been changed"
LIST_CONFIG=$(mktemp) || die "could not make the files this records the store in; nothing has been changed"
LIST_VALIDATORS=$(mktemp) || die "could not make the files this records the store in; nothing has been changed"
record_for_handover "$DATA_DIR" "$LIST_STORE"
record_for_handover "$CONFIG_FILE" "$LIST_CONFIG"
[[ ! -f "$(dirname -- "$CONFIG_FILE")/validators.txt" ]] \
  || record_for_handover "$(dirname -- "$CONFIG_FILE")/validators.txt" "$LIST_VALIDATORS"

if ((CREATE_ACCOUNT)); then
  LINE="$(node_account_ensure)" || die "could not create the ${NODE_USER} account; nothing has been changed"
  IFS=$'\t' read -r NODE_USER NODE_UID NODE_GID <<< "$LINE"
fi
[[ -n "$NODE_UID" && -n "$NODE_GID" ]] || die "the ${NODE_USER} account has no uid or gid this script could read"
info "${NODE_USER}: uid ${NODE_UID}, gid ${NODE_GID}"

# The compose file, patched in place rather than re-rendered from the
# template. Fleet compose files carry per-host edits (a corrected peer
# mapping, a different memory cap), and re-rendering would revert them
# silently.
STAMP=$(date +%Y%m%d-%H%M%S)
BACKUP="${COMPOSE_FILE}.${STAMP}.bak"
if ((COMPOSE_HAS_USER)) && ((COMPOSE_HAS_ETC)); then
  info "${COMPOSE_FILE} already has user: and the /etc/xrpld mounts; leaving it alone"
else
  cp -a "$COMPOSE_FILE" "$BACKUP"
  cmp -s "$COMPOSE_FILE" "$BACKUP" || die "the backup at ${BACKUP} does not match the original; nothing further was changed"
  cwl_prune_backups "$COMPOSE_FILE" 10
  info "kept the previous deployment at ${BACKUP}"

  COMPOSE_WAS_SNAP=$(cwl_acl_snapshot "$COMPOSE_FILE")
  TMPC=$(mktemp "${COMPOSE_FILE}.XXXXXX")
  # awk, one pass, two insertions, both anchored on a line that is already
  # there rather than on a line number:
  #   user:            goes after `init: true`, which the template has had
  #                    since it was written
  #   the two mounts   go immediately before the first mount of the config,
  #                    so they carry that line's own indentation and its own
  #                    host path. Deriving the path from the line means a
  #                    host whose config lives somewhere else still gets a
  #                    correct pair
  #
  # Each insertion is asked for separately, so a half-migrated file (the user
  # line in, the mounts not) gains the half it is missing and never a second
  # copy of the half it has.
  awk -v u="${NODE_UID}:${NODE_GID}" \
      -v did_user="${COMPOSE_HAS_USER}" -v did_mounts="${COMPOSE_HAS_ETC}" '
    { line = $0 }
    !did_user && line ~ /^[[:space:]]*init:[[:space:]]*true[[:space:]]*$/ {
      match(line, /^[[:space:]]*/)
      indent = substr(line, 1, RLENGTH)
      print line
      printf "%suser: \"%s\"\n", indent, u
      did_user = 1
      next
    }
    !did_mounts && line ~ /:\/config\/rippled\.cfg:ro[[:space:]]*$/ {
      match(line, /^[[:space:]]*/)
      indent = substr(line, 1, RLENGTH)
      src = line
      sub(/^[[:space:]]*-[[:space:]]*/, "", src)
      sub(/:\/config\/rippled\.cfg:ro[[:space:]]*$/, "", src)
      dir = src
      sub(/\/[^\/]*$/, "", dir)
      printf "%s- %s:/etc/xrpld/xrpld.cfg:ro\n", indent, src
      printf "%s- %s/validators.txt:/etc/xrpld/validators.txt:ro\n", indent, dir
      print line
      did_mounts = 1
      next
    }
    { print line }
    END {
      if (!did_user)   { print "MIGRATE-FAILED: no `init: true` line to put user: after" > "/dev/stderr"; exit 3 }
      if (!did_mounts) { print "MIGRATE-FAILED: no mount of /config/rippled.cfg to put the /etc/xrpld pair before" > "/dev/stderr"; exit 3 }
    }
  ' "$COMPOSE_FILE" > "$TMPC" || {
      rm -f "$TMPC"
      die "could not patch ${COMPOSE_FILE}: it is not the shape this script knows how to edit. The file is untouched and the store has not been handed to ${NODE_USER} yet, so either add these two things by hand and run this again, or leave the node as it is"
    }

  # Both properties asserted on the bytes that are about to be installed, not
  # on the intention. A compose that lost a hardening line while being edited
  # is the failure this project's node tests exist for.
  grep -qE '^[[:space:]]*user:[[:space:]]*"'"${NODE_UID}:${NODE_GID}"'"' "$TMPC" \
    || { rm -f "$TMPC"; die "the patched compose does not carry user: \"${NODE_UID}:${NODE_GID}\"; ${COMPOSE_FILE} is untouched"; }
  grep -qF ":/etc/xrpld/xrpld.cfg:ro" "$TMPC" \
    || { rm -f "$TMPC"; die "the patched compose does not mount the config at /etc/xrpld/xrpld.cfg; ${COMPOSE_FILE} is untouched"; }
  grep -qF "cap_drop" "$TMPC" \
    || { rm -f "$TMPC"; die "the patched compose lost its cap_drop line; ${COMPOSE_FILE} is untouched"; }

  if ! cwl_carry_permissions "$COMPOSE_FILE" "$TMPC"; then
    rm -f "$TMPC"
    die "could not carry ${COMPOSE_FILE}'s owner, group, mode and ACL onto the rewrite; ${COMPOSE_FILE} is untouched, and the store under ${DATA_DIR} has not been handed to ${NODE_USER} yet."
  fi
  mv "$TMPC" "$COMPOSE_FILE"

  COMPOSE_NOW_SNAP=$(cwl_acl_snapshot "$COMPOSE_FILE")
  if [[ "$COMPOSE_NOW_SNAP" != "$COMPOSE_WAS_SNAP" ]]; then
    if cwl_restore_from_backup "$BACKUP" "$COMPOSE_FILE"; then
      die "the rewrite changed ${COMPOSE_FILE}'s $(cwl_snapshot_describe); restored ${BACKUP} and left the compose file reading exactly as it did before this ran. The store under ${DATA_DIR} has not been handed to ${NODE_USER} yet; fix the compose file's shape by hand, then run this again"
    else
      die "the rewrite changed ${COMPOSE_FILE}'s $(cwl_snapshot_describe), AND restoring ${BACKUP} failed; the deployment file's permissions are unproven, fix ${COMPOSE_FILE} by hand from ${BACKUP} before starting the node"
    fi
  fi
  info "${COMPOSE_FILE}: user: \"${NODE_UID}:${NODE_GID}\" and the /etc/xrpld mounts added"
fi

# The header, replaced with this release's own, so a migrated file explains
# itself the way a freshly installed one does (#438). Done after the body
# patch and on the file as it now stands, so a host that was migrated by an
# earlier build (body already right, header still the old one) gets it on a
# re-run. Everything from `name:` down is copied byte for byte: a per-host
# edit lives down there, and this must never be a re-render.
#
# A file with no `name:` line at all gets its own branch rather than falling
# into "current": there is nothing above to compare, and no anchor to insert
# a header before without guessing where the deployment itself starts (#467).
# Left as it is, the same caution the unreadable-compose refusal above takes.
case "$(compose_header_state)" in
  current)
    info "${COMPOSE_FILE}: the header is already this release's; unchanged"
    ;;
  no-template)
    info "${COMPOSE_FILE}: ${COMPOSE_TEMPLATE} is not in this checkout, so the header was left as it is"
    ;;
  no-name)
    info "${COMPOSE_FILE}: no 'name:' line to safely anchor a header on; left as it is"
    ;;
  stale)
    NEW_HEADER=$(compose_header_rendered) || NEW_HEADER=''
    if [[ ! -f "$BACKUP" ]]; then
      cp -a "$COMPOSE_FILE" "$BACKUP"
      cmp -s "$COMPOSE_FILE" "$BACKUP" || die "the backup at ${BACKUP} does not match the original; the header was not touched"
      cwl_prune_backups "$COMPOSE_FILE" 10
      info "kept the previous deployment at ${BACKUP}"
    fi
    COMPOSE_WAS_SNAP=$(cwl_acl_snapshot "$COMPOSE_FILE")
    TMPH=$(mktemp "${COMPOSE_FILE}.XXXXXX")
    {
      printf '%s\n' "$NEW_HEADER"
      sed -n '/^name:/,$p' "$COMPOSE_FILE"
    } > "$TMPH"
    # The body is the thing that must not have moved. Compared before the file
    # is installed, so a header swap that ate a line of the deployment is a
    # refusal rather than a node that comes back missing a mount.
    if ! diff -q <(sed -n '/^name:/,$p' "$COMPOSE_FILE") <(sed -n '/^name:/,$p' "$TMPH") >/dev/null; then
      rm -f "$TMPH"
      die "replacing the header would have changed the deployment below it; ${COMPOSE_FILE} is untouched"
    fi
    if ! cwl_carry_permissions "$COMPOSE_FILE" "$TMPH"; then
      rm -f "$TMPH"
      die "could not carry ${COMPOSE_FILE}'s owner, group, mode and ACL onto the header rewrite; ${COMPOSE_FILE} is untouched"
    fi
    mv "$TMPH" "$COMPOSE_FILE"

    COMPOSE_NOW_SNAP=$(cwl_acl_snapshot "$COMPOSE_FILE")
    if [[ "$COMPOSE_NOW_SNAP" != "$COMPOSE_WAS_SNAP" ]]; then
      if cwl_restore_from_backup "$BACKUP" "$COMPOSE_FILE"; then
        die "the header rewrite changed ${COMPOSE_FILE}'s $(cwl_snapshot_describe); restored ${BACKUP} and left the compose file reading exactly as it did before this ran"
      else
        die "the header rewrite changed ${COMPOSE_FILE}'s $(cwl_snapshot_describe), AND restoring ${BACKUP} failed; fix ${COMPOSE_FILE} by hand from ${BACKUP} before starting the node"
      fi
    fi
    info "${COMPOSE_FILE}: the comment block above 'name:' is this release's, and nothing below it changed"
    ;;
esac

# The store, by descriptor and not by name (#1121). It was `chown -Rh`: -h
# keeps it off links, but a hard link in the store to a file outside it was
# changed like any other entry, and the node's account writes this tree. find
# only lists; state-file.py own-many opens every name it prints without
# following a link, from a walk of its parents, and refuses a link or a file
# with a second name, naming it. Owner and group only. The root is the
# install directory, the store's parent (DATA_DIR is always ${DIR}/data, never
# a mount of its own): the walk is O_NOFOLLOW from the top and every directory
# above the install is held to the ancestor rule, which --root / would have
# switched off. The compose file is already prepared, so a refusal stops here
# with the store partly handed over: the run says which entries and how to put
# the rest right.
hand_store_to_node() { # $1 = the store
  find "$1" -print0 \
    | python3 -I "$HERE/state-file.py" own-many "$NODE_UID" "$NODE_GID" "" --root "$(dirname -- "$1")" --judge-root --list "$LIST_STORE"
}
# The group alone, of one file, by the same walk (the chgrp it replaces
# followed a link at the name, in a directory the login can write).
hand_group_to_node() { # $1 = a file, $2 = what was recorded of it
  printf '%s\0' "$1" \
    | python3 -I "$HERE/state-file.py" own-many "" "$NODE_GID" "" --root "$(dirname -- "$1")" --judge-root --list "$2"
}
if ! hand_store_to_node "$DATA_DIR"; then
  die "${DATA_DIR} was not all handed to ${NODE_USER}: an entry in it is a link, has a second name, or is not what was there when this began (named above), and was left alone, so the node may not be able to write it. Remove or replace what is named, then run this again with --apply; it changes nothing that is already right."
fi
info "${DATA_DIR} -> ${NODE_USER}:${NODE_USER}, every entry, none followed through a link"

# The config's group, and the validator list beside it if the compose mounts
# one. Group only. A chmod here would recalculate the ACL mask and can drop a
# named entry's effective bits, and the relay's read on this file is exactly
# such an entry.
hand_group_to_node "$CONFIG_FILE" "$LIST_CONFIG" \
  || die "the group of ${CONFIG_FILE} was not changed: it is a link, has a second name, or is not the file that was there when this began (named above), and root leaves that as it is. The store is handed over; make ${CONFIG_FILE} a plain file that only that path names, and look at what replaced it if it was replaced, then run this again with --apply."
info "${CONFIG_FILE} -> group ${NODE_USER} (mode ${CFG_MODE}, unchanged)"
VAL_FILE="$(dirname "$CONFIG_FILE")/validators.txt"
if [[ -f "$VAL_FILE" ]]; then
  hand_group_to_node "$VAL_FILE" "$LIST_VALIDATORS" \
    || die "the group of ${VAL_FILE} was not changed: it is a link, has a second name, or is not the file that was there when this began, or did not exist then (named above), and root leaves that as it is. Make it a plain file that only that path names, and look at what put it there if it was not there before, then run this again with --apply."
  info "${VAL_FILE} -> group ${NODE_USER}"
fi

# The record of this node, so a host that was migrated says the same thing
# about itself as a host that was installed fresh. Same three keys, same
# names; a key already there is replaced, not doubled.
if [[ -f "$NODE_CONF" ]]; then
  node_conf_set() { # $1 = key, $2 = value
    if grep -qE "^$1=" "$NODE_CONF"; then
      sed -i "s#^$1=.*#$1=$2#" "$NODE_CONF"
    else
      printf '%s=%s\n' "$1" "$2" >> "$NODE_CONF"
    fi
  }
  node_conf_set NODE_USER "$NODE_USER"
  node_conf_set NODE_UID  "$NODE_UID"
  node_conf_set NODE_GID  "$NODE_GID"
  info "${NODE_CONF} records the account this node runs as"
else
  # A host this old has no node.conf to write it to (#468). The compose's own
  # user: line is the only durable copy of these ids on a host in this shape,
  # so the run says that plainly rather than leaving it unsaid.
  info "no ${NODE_CONF} on this host, so the account is recorded only in the compose file: ${NODE_USER} uid ${NODE_UID} gid ${NODE_GID}"
fi

# ── What to do now ────────────────────────────────────────────────────────
say "Done. Start the node and watch it come back"
info "    sudo docker compose -f ${COMPOSE_FILE} up -d"
info "    sudo aperire-node-wrapper config-readable"
info "    docker exec ${SERVICE} id -u        # ${NODE_UID}, not 0"
echo
info "The first start prints one 'Read-only file system' line per config file."
info "That is the image's entrypoint trying to copy a config that is already"
info "mounted where it copies it to. The node reads the operator's config."
echo
say "Putting it back"
if [[ -f "$BACKUP" ]]; then
  info "    sudo docker compose -f ${COMPOSE_FILE} stop"
  info "    sudo cp ${BACKUP} ${COMPOSE_FILE}"
else
  info "    sudo docker compose -f ${COMPOSE_FILE} stop"
  info "    # the compose was already in the new shape, so there is no new .bak"
fi
info "    curl -fsSL https://get.aperire.one | bash -s -- --run migrate-node --hand-store-back"
info "    sudo chgrp ${CFG_GROUP} ${CONFIG_FILE}"
info "    sudo docker compose -f ${COMPOSE_FILE} up -d"
