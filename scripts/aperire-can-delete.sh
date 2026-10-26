#!/usr/bin/env bash
# Authorise ONE ledger-store rotation, and watch it happen, issue #79.
#
# The problem this exists to solve
# ────────────────────────────────
# rippled prunes by rotating its NuDB store: copy the current state map
# forward, swap in a fresh writable backend, delete the old one. With
# `online_delete` alone, rippled decides when to do that, so the window
# arrives unannounced roughly every 32,768 ledgers. A node stopped inside it
# came back with an empty store and rebuilt from genesis (stock-node1,
# 2026-08-25), and a clean SIGTERM inside a 90s stop grace did not save it.
#
# The fix is not to make the interruption survivable. It is to stop rotations
# happening at times nobody chose:
#
#   [node_db]
#   advisory_delete=1
#
# With that set, rippled will not rotate until told. The gate is the
# `can_delete` admin RPC, and this script is the only thing that calls it.
#
# What the node actually does with can_delete
# ───────────────────────────────────────────
# Read from rippled's own source, not from documentation:
#
#   SHAMapStoreImp::run()
#     bool const readyToRotate = validatedSeq >= lastRotated + deleteInterval_
#         && canDelete_ >= lastRotated - 1
#         && healthWait() == HealthResult::KeepGoing;
#
#   SHAMapStoreImp ctor
#     canDelete_(std::numeric_limits<LedgerIndex>::max())   // advisory off
#     if (advisoryDelete_) canDelete_ = stateDb_.getCanDelete();
#
#   doCanDelete()  (rpc/handlers/admin/data/CanDelete.cpp)
#     "never"  -> 0
#     "always" -> UINT32_MAX
#     "now"    -> getLastRotated(), or a notReady error if that is 0
#     absent   -> returns getCanDelete() and changes nothing
#     advisory_delete off -> notEnabled error
#
# Two consequences the whole design rests on:
#
#   - `can_delete now` authorises EXACTLY ONE rotation. It sets canDelete_ to
#     the last rotated sequence L. The rotation fires, and sets lastRotated to
#     the current validated sequence V, which is a whole delete interval past
#     L. `canDelete_ >= lastRotated - 1` is now false and stays false until
#     something calls can_delete again. Nothing has to disarm it afterwards.
#   - Reading the value costs nothing: `can_delete` with no parameter is a
#     read. Only the parameterised form writes.
#
# What this script guarantees
# ───────────────────────────
# The store is never left armed while nothing is watching. Every run either
# ends with a rotation observed, or disarms before it exits, including on an
# error, a timeout or a signal, which is what the EXIT trap is for. The gap
# between arming and disarming is a few minutes once a day, it is held under
# /run/aperire/node-rotation.lock, and aperire-node-wrapper.sh takes that
# same lock before it stops the node.
#
# What it does not guarantee, stated plainly
# ──────────────────────────────────────────
# It does not make an interrupted rotation safe. Power loss or a kernel panic
# inside the window is still exposed, and advisory_delete does nothing about
# that. What changes is that the window is now roughly five minutes a day at
# a time this host chose, instead of an unannounced hour or two that a
# restart could walk into.
#
# Usage:
#   aperire-can-delete.sh            run the window (the systemd timer's job)
#   aperire-can-delete.sh --status   read and print, change nothing

set -euo pipefail

CONF=/etc/aperire/can-delete.conf

usage() {
  cat >&2 <<'EOF'
usage: aperire-can-delete.sh [--status]

  (no argument)   arm one rotation, watch it, disarm if none was due
  --status        print what the node says right now, change nothing
EOF
  exit 64
}

MODE=run
case "${1:-}" in
  '')          ;;
  --status)    MODE=status ;;
  -h|--help)   usage ;;
  *)           echo "aperire-can-delete: unknown argument '$1'" >&2; usage ;;
esac
[[ $# -le 1 ]] || usage

say() { printf '%s %s\n' "$(date -Is)" "$*"; }
die() { printf 'aperire-can-delete: %s\n' "$*" >&2; exit 1; }

# ── Configuration ─────────────────────────────────────────────────────────
# Read, do not source, for the reason aperire-node-wrapper.sh gives: a file
# that gets executed is a script, and this one is written by an installer and
# read by a root timer.
SERVICE='' ADMIN_RPC='' LOCK='' ARM_GRACE='' ROTATION_HOLD='' LOOKBACK=''
KIND='' LOG_FILE='' LOG_LINES=''
[[ -f "$CONF" ]] || die "no configuration at $CONF, run: curl -fsSL https://get.aperire.one | bash -s -- --update --force (if that says it cannot find or name the node, name it first: curl -fsSL https://get.aperire.one | bash -s -- --node-wrapper <container>, or --node-wrapper-native <unit>)"
[[ -r "$CONF" ]] || die "$CONF is not readable by $(id -un)"
while IFS= read -r line; do
  [[ -z "$line" || "$line" == \#* ]] && continue
  [[ "$line" == *=* ]] || die "$CONF: not a key=value line: $line"
  key=${line%%=*}
  val=${line#*=}
  case "$key" in
    SERVICE|ADMIN_RPC|LOCK|ARM_GRACE|ROTATION_HOLD|LOOKBACK|KIND|LOG_FILE|LOG_LINES)
      printf -v "$key" '%s' "$val" ;;
    *) die "$CONF: unexpected key '$key'" ;;
  esac
done < "$CONF"

# Defaults for the tunables, so a configuration written before they existed
# still runs. ARM_GRACE is how long a rotation gets to start after being
# authorised; on a healthy node it starts on the next validated ledger, so
# five minutes is generous. ROTATION_HOLD is how long the lock is held
# waiting for it to finish, past that the lock is released and the node's own
# log is what keeps a restart out, which is the wrapper's second mechanism.
# That second mechanism has its own bound, ROTATION_STALE_MIN in
# scripts/aperire-node-wrapper.sh, past which nothing blocks a restart. All
# three are uncalibrated guesses until a real rotation on this node has been
# timed. KIND defaults to container: every conf written before native
# existed is a container conf with no KIND line, and it must keep reading as
# one.
ARM_GRACE=${ARM_GRACE:-300}
ROTATION_HOLD=${ROTATION_HOLD:-5400}
LOOKBACK=${LOOKBACK:-24h}
LOCK=${LOCK:-/run/aperire/node-rotation.lock}
KIND=${KIND:-container}
LOG_LINES=${LOG_LINES:-5000}

# The age past which a "rotating" line with nothing after it stops counting as
# a rotation in flight.
#
# NOT configuration, and the same number as ROTATION_STALE_MIN in
# scripts/aperire-node-wrapper.sh, where the calibration is written down (two
# timed rotations, 40.5 minutes and 13.2 minutes, four hours being roughly six
# times the slowest). Two readers of the same log disagreeing about whether a
# rotation is running is worse than either bound being wrong, so the two are
# held equal by a row in scripts/test-can-delete.sh that reads both files. If
# you raise one, that row fails until you raise the other.
#
# Without it this reader had no expiry at all: a line count cannot age
# anything out, so one hung rotation read as in flight on every later run and
# no window was ever armed again, silently. Measured on aperire2 on
# 2026-09-17, where the wrapper called a five-hour-old line stale and this
# script called the same line a rotation in flight (#390).
ROTATION_STALE_MIN=240

# How often the two waits look at the node's log. Constants rather than
# configuration: they are a polling cadence, not a policy, and nothing an
# operator sets should change how closely the armed window is watched.
# scripts/test-can-delete.sh rewrites these two lines in its copy so a run
# that would take an hour takes a minute.
POLL_START=10
POLL_RUN=30

[[ "$KIND" == container || "$KIND" == native ]] \
  || die "$CONF: KIND '$KIND' must be container or native"
if [[ "$KIND" == native ]]; then
  [[ "$SERVICE" =~ ^[A-Za-z0-9._-]+$ ]] || die "$CONF: SERVICE '$SERVICE' is not a unit name"
  [[ -n "$LOG_FILE" && "$LOG_FILE" == /* ]] \
    || die "$CONF: KIND=native but LOG_FILE is not an absolute path"
  [[ "$LOG_LINES" =~ ^[0-9]+$ ]] || die "$CONF: LOG_LINES must be a line count"
else
  [[ "$SERVICE" =~ ^[A-Za-z0-9._-]+$ ]] || die "$CONF: SERVICE '$SERVICE' is not a container name"
fi
[[ "$ADMIN_RPC" =~ ^http://(127\.0\.0\.1|localhost|\[::1\]):[0-9]+$ ]] \
  || die "$CONF: ADMIN_RPC '$ADMIN_RPC' must be loopback"
[[ "$LOCK" == /* ]]                     || die "$CONF: LOCK must be an absolute path"
[[ "$ARM_GRACE"     =~ ^[0-9]+$ ]]      || die "$CONF: ARM_GRACE must be seconds"
[[ "$ROTATION_HOLD" =~ ^[0-9]+$ ]]      || die "$CONF: ROTATION_HOLD must be seconds"
[[ "$LOOKBACK" =~ ^[0-9]+[smh]$ ]]      || die "$CONF: LOOKBACK must look like 24h"

# ── Talking to the node ───────────────────────────────────────────────────

rpc() { # $1 = JSON body -> the response on stdout
  curl -sS --max-time 20 --data "$1" "$ADMIN_RPC"
}

# rippled's JSON, read without jq. jq is not on a minimal host and this runs
# on every node, so the two fields it needs are pulled by shape. Both are
# unambiguous in the responses concerned: can_delete appears once, and
# server_state appears once in server_info.
json_uint() { # $1 = body, $2 = key
  printf '%s' "$1" | grep -oE "\"$2\"[[:space:]]*:[[:space:]]*[0-9]+" | head -1 |
    grep -oE '[0-9]+$' || true
}
json_str() { # $1 = body, $2 = key
  printf '%s' "$1" | grep -oE "\"$2\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" | head -1 |
    sed -E 's/.*"([^"]*)"$/\1/' || true
}

# The rotation reading, by the same rule aperire-node-wrapper.sh uses. Kept
# separate rather than shared because this timer has to work on a node that
# never installed the Advisor, and a safety timer that depends on an optional
# component is not a safety timer. Prints "<state><TAB><detail>".
#
# $1 (optional) = only consider lines after this unix timestamp. Only the
# container path honours it in the READ (docker's --since takes a unix time);
# the native path reads LOG_FILE by line count, because the vendor's package
# gives nothing to filter a file read on. Both paths age a matched "rotating"
# line by its own stamp afterwards, which is what a line count cannot do on
# its own and is the whole of #390.
#
# The timestamp at the front of a matched line, in a form GNU date will parse.
# Two shapes, and the same two the wrapper reads. docker --timestamps puts one
# RFC 3339 field first. rippled writes its own as
# "2026-Sep-17 11:17:02.984432197 UTC", two fields with the month in the
# middle, which GNU date refuses outright, so the file case is rearranged and
# read as UTC. Measured on aperire2, 2026-09-17, from the vendor package's own
# /var/log/xrpld/debug.log.
rotation_stamp() {  # $1 = the matched log line
  local f1 f2
  read -r f1 f2 _ <<< "$1"
  if [[ "$KIND" == native ]]; then
    if [[ "$f1" =~ ^([0-9]{4})-([A-Za-z]{3})-([0-9]{1,2})$ ]]; then
      printf '%s %s %s %s UTC\n' "${BASH_REMATCH[3]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[1]}" "$f2"
    else
      printf '%s %s\n' "$f1" "$f2"
    fi
    return 0
  fi
  printf '%s\n' "$f1"
}

rotation_state() {
  local since=$LOOKBACK logs last stamp started now age
  [[ -n "${1:-}" ]] && since=$1
  if [[ "$KIND" == native ]]; then
    logs=$(tail -n "$LOG_LINES" "$LOG_FILE" 2>&1) || {
      printf 'unknown\tthe node log could not be read at %s\n' "$LOG_FILE"; return 0; }
  else
    logs=$(docker logs --timestamps --since "$since" "$SERVICE" 2>&1) || {
      printf 'unknown\tthe node log could not be read\n'; return 0; }
  fi
  last=$(printf '%s\n' "$logs" | grep -aE \
    'rotating[[:space:]]+validatedSeq|finished rotation|online_delete rotation has been unable to make progress|Process starting' \
    | tail -1) || true
  if [[ -z "$last" ]]; then
    printf 'idle\tno rotation line in the window\n'; return 0
  fi
  case "$last" in
    *"finished rotation"*)          printf 'finished\tthe rotation finished\n'; return 0 ;;
    *"unable to make progress"*)    printf 'idle\tthe rotation gave up without swapping the store\n'; return 0 ;;
    *"Process starting"*)           printf 'idle\tthe node has started since the last rotation line\n'; return 0 ;;
  esac
  # A "rotating" line with nothing after it. How old it is decides, by the
  # same bound and the same three answers the wrapper gives, so the two
  # readers of this log can never disagree about the node in front of them.
  stamp=$(rotation_stamp "$last")
  started=$(date -d "$stamp" +%s 2>/dev/null) || started=0
  now=$(date +%s)
  if (( started == 0 )); then
    printf 'rotating\ta rotation is in flight (its start time could not be read)\n'; return 0
  fi
  if (( started > now )); then
    # A stamp in the future is a clock or a timezone read wrongly, and an age
    # from it would be negative. Refusing is the safe side.
    printf 'rotating\ta rotation is in flight (its start time reads as being in the future, so its age could not be judged)\n'; return 0
  fi
  age=$(( (now - started) / 60 ))
  if (( age >= ROTATION_STALE_MIN )); then
    printf 'stale\ta rotation started %s minutes ago and never reported finishing, which is past the %s-minute bound, not treating it as in flight\n' \
      "$age" "$ROTATION_STALE_MIN"
    return 0
  fi
  printf 'rotating\ta rotation started %s minutes ago and has not finished\n' "$age"
}

# ── --status: read everything, change nothing ─────────────────────────────
if [[ "$MODE" == status ]]; then
  info=$(rpc '{"method":"server_info","params":[{}]}') || die "the node did not answer on $ADMIN_RPC"
  state=$(json_str "$info" server_state)
  # server_info carries several "seq" fields; this one has to be the validated
  # ledger's, so it is read out of that object rather than by first match.
  seq=$(printf '%s' "$info" |
    sed -n 's/.*"validated_ledger"[[:space:]]*:[[:space:]]*{[^}]*"seq"[[:space:]]*:[[:space:]]*\([0-9]*\).*/\1/p' |
    head -1)
  printf 'node          %s\n' "$SERVICE"
  printf 'server_state  %s\n' "${state:-unknown}"
  printf 'validated     %s\n' "${seq:-unknown}"
  cd_body=$(rpc '{"method":"can_delete","params":[{}]}') || cd_body=''
  if printf '%s' "$cd_body" | grep -q 'notEnabled'; then
    printf 'advisory      OFF, this node still rotates on its own, unannounced\n'
    printf 'can_delete    n/a\n'
  else
    printf 'advisory      on\n'
    printf 'can_delete    %s   (0 means disarmed, which is the resting state)\n' "$(json_uint "$cd_body" can_delete)"
  fi
  IFS=$'\t' read -r st detail < <(rotation_state)
  printf 'rotation      %s, %s\n' "$st" "$detail"
  # A probe, not a hold: flock takes the lock, exits, and releases it. Three
  # answers, because "could not look" is not "free".
  if [[ ! -e "$LOCK" ]]; then
    printf 'lock          free (no lock file yet, nothing has run a window on this host)\n'
  elif [[ ! -r "$LOCK" ]]; then
    printf 'lock          unknown (run as root to read %s)\n' "$LOCK"
  elif flock -n 8 8<"$LOCK"; then
    printf 'lock          free\n'
  else
    printf 'lock          HELD, a rotation window or a node stop is running\n'
  fi
  exit 0
fi

# ── The window ────────────────────────────────────────────────────────────

# One at a time, and never while the wrapper is stopping the node. The
# directory is shared with the dashboard's socket units and its mode is said
# outright, for the reason in aperire-node-wrapper.sh (#171).
install -d -m 0755 "$(dirname "$LOCK")"
exec 9>"$LOCK"
if ! flock -n 9; then
  say "another node operation holds $LOCK; skipping this window"
  exit 0
fi

ARMED=0
disarm() {
  local body
  body=$(rpc '{"method":"can_delete","params":[{"can_delete":"never"}]}') || {
    say "WARNING: could not disarm can_delete, the node did not answer. The store may rotate unwatched; check: systemctl start aperire-can-delete.service"
    return 0
  }
  if [[ "$(json_uint "$body" can_delete)" == "0" ]]; then
    ARMED=0
    say "disarmed (can_delete=0)"
  else
    say "WARNING: disarm did not take; the node reports can_delete=$(json_uint "$body" can_delete)"
  fi
}

# Never leave the store armed with nobody watching. This is the whole safety
# property, so it runs on every exit path, error, timeout, or signal, and
# preserves the status it was entered with rather than reporting its own.
#
# invoked indirectly by the EXIT trap below; shellcheck 0.9.x calls the body
# unreachable (SC2317), 0.10.x calls the function uninvoked (SC2329)
# shellcheck disable=SC2317,SC2329
on_exit() {
  local rc=$?
  trap - EXIT
  if (( ARMED )); then
    say "exiting while armed; disarming"
    disarm
  fi
  exit "$rc"
}
trap on_exit EXIT
trap 'exit 143' TERM
trap 'exit 130' INT

# advisory_delete=0 is a supported configuration, not a fault (ruling
# 2026-08-27: rotation safety never depends on the config value). A node
# running free rotates on its own, can_delete does nothing on it, and there is
# nothing here to authorise. Both places that can learn this end the run the
# same way, through this one function, so the two cannot drift into saying
# different things about the same node.
advisory_off_exit() {
  say "advisory_delete is off on this node, so it rotates on its own and there is nothing for this window to authorise. Nothing to do."
  exit 0
}

info=$(rpc '{"method":"server_info","params":[{}]}') || die "the node did not answer on $ADMIN_RPC"
state=$(json_str "$info" server_state)
case "$state" in
  full|proposing|validating) say "node is $state" ;;
  '') die "could not read server_state from the node" ;;
  *)
    # Not a failure. rippled itself refuses to rotate unless the node is FULL
    # and caught up (healthWait), so arming here would leave the store armed
    # against a thread that is blocked, which is precisely the state this
    # script exists to avoid.
    say "node is '$state', not caught up; not arming. The next window will try again."
    exit 0
    ;;
esac

# Ask whether there is anything to authorise BEFORE reading the node's log.
# `can_delete` with no parameter is a read: it changes nothing, costs one RPC,
# and answers notEnabled on a free-running node. rotation_state below is not
# cheap, it is `docker logs --since 24h` over a day of a validator's output
# (29 s of CPU on aperire1, every day at 04:00, to reach a refusal it could
# have had for one call), so the cheap question goes first.
probe=$(rpc '{"method":"can_delete","params":[{}]}') || die "the node did not answer the can_delete call"
if printf '%s' "$probe" | grep -q 'notEnabled'; then
  advisory_off_exit
fi

IFS=$'\t' read -r st detail < <(rotation_state)
if [[ "$st" == rotating ]]; then
  say "a rotation is already in flight; not arming. Something else authorised it."
  exit 0
fi

# Everything from here is measured against this instant, so an older
# "rotating" line in the log cannot be mistaken for the one we authorised.
t0=$(date +%s)

body=$(rpc '{"method":"can_delete","params":[{"can_delete":"now"}]}') || die "the node did not answer the can_delete call"
# The probe above normally catches this. Reaching it here means the node's
# configuration changed under the run, which is not a fault of this host
# either, so it ends the same way rather than leaving a failed unit behind.
if printf '%s' "$body" | grep -q 'notEnabled'; then
  advisory_off_exit
fi
if printf '%s' "$body" | grep -q 'notReady'; then
  say "the node has not recorded a rotation point yet; nothing to authorise. The next window will try again."
  exit 0
fi
last_rotated=$(json_uint "$body" can_delete)
[[ -n "$last_rotated" ]] || die "can_delete returned something this cannot read: $body"
ARMED=1
say "armed: can_delete=$last_rotated (authorises exactly one rotation)"

# Wait for it to start. If it does not, no rotation was due, the delete
# interval has not elapsed, and the store goes back to disarmed.
started=0
deadline=$(( t0 + ARM_GRACE ))
while (( $(date +%s) < deadline )); do
  sleep "$POLL_START"
  IFS=$'\t' read -r st detail < <(rotation_state "$t0")
  if [[ "$st" == rotating || "$st" == finished ]]; then
    started=1
    break
  fi
done

if (( ! started )); then
  say "no rotation started within ${ARM_GRACE}s, so none was due"
  disarm
  exit 0
fi

# It is running. Do not disarm: canDelete_ was already read when the rotation
# started, so clearing it now would change nothing, and the value clears
# itself the moment lastRotated moves.
ARMED=0
say "rotation started; holding the lock while it runs"

deadline=$(( $(date +%s) + ROTATION_HOLD ))
while (( $(date +%s) < deadline )); do
  IFS=$'\t' read -r st detail < <(rotation_state "$t0")
  if [[ "$st" == finished ]]; then
    say "rotation finished; the store is pruned and the node was never stopped during it"
    exit 0
  fi
  if [[ "$st" == idle ]]; then
    say "WARNING: the rotation ended without finishing ($detail). The store was not swapped; the next window will try again."
    exit 0
  fi
  sleep "$POLL_RUN"
done

# Past the hold. Release the lock rather than block restarts indefinitely,
# aperire-node-wrapper.sh reads the same log and refuses on its own.
if [[ "$KIND" == native ]]; then
  hint="tail -n 200 $LOG_FILE"
else
  hint="docker logs --tail 200 $SERVICE"
fi
say "WARNING: the rotation has run for ${ROTATION_HOLD}s and has not finished. Releasing the lock; the node wrapper still refuses to stop the node while the log says it is rotating. Check: $hint"
exit 0
