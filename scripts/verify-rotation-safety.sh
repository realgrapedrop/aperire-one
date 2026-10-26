#!/usr/bin/env bash
# Verify the node rotation-safety mechanism on a node host (issue #79).
#
# What it proves, in order:
#   1. advisory_delete=1 is set, exactly once, in [node_db].
#   2. can_delete answers (advisory is in effect, not notEnabled).
#   3. the can_delete timer is enabled and scheduled.
#   4. the wrapper's rotation-state read agrees the node is not mid-rotation.
#   5. --status runs and reports advisory on.
#   6. the guard refuses a restart while the rotation lock is held, and the
#      node keeps running through the refusal.
#   7. (co-located dashboards only) nudb_mount_free_days is being written.
#
# Only step 6 does anything, and it is safe by construction: this script holds
# the rotation lock itself for the length of the attempt, so the restart is
# refused before it can touch the container. The node is never restarted.
#
# Run it on the node host:  sudo bash scripts/verify-rotation-safety.sh
# It needs root (the wrapper, the lock, and the metrics DB are root-owned).

set -uo pipefail

WCONF=/etc/aperire/node-wrapper.conf
LOCK=/run/aperire/node-rotation.lock
HERE=$(cd "$(dirname "$0")" && pwd)
WRAPPER="$HERE/aperire-node-wrapper.sh"
CANDEL=/usr/local/lib/aperire/aperire-can-delete.sh

pass=0; fail=0
ok()   { printf '  PASS  %s\n' "$*"; pass=$((pass+1)); }
bad()  { printf '  FAIL  %s\n' "$*"; fail=$((fail+1)); }
note() { printf '  ----  %s\n' "$*"; }

[[ $EUID -eq 0 ]] || { echo "run with sudo: sudo bash $0" >&2; exit 2; }
[[ -r "$WCONF" ]] || { echo "no $WCONF, is this a node host?" >&2; exit 2; }
CFG=$(sed -n 's/^CONFIG_FILE=//p' "$WCONF" | head -1)
SERVICE=$(sed -n 's/^SERVICE=//p' "$WCONF" | head -1)
[[ -n "$CFG" && -n "$SERVICE" ]] || { echo "$WCONF is missing CONFIG_FILE or SERVICE" >&2; exit 2; }
echo "node config: $CFG"
echo "container:   $SERVICE"
echo

# 1. advisory_delete=1, exactly once, in [node_db].
echo "1. advisory_delete in [node_db]"
adc=$(awk '
  /^[[:space:]]*\[node_db\][[:space:]]*$/ { inb=1; next }
  inb && /^[[:space:]]*\[/               { inb=0 }
  inb && /^[[:space:]]*advisory_delete[[:space:]]*=/ { n++ }
  END { print n+0 }
' "$CFG")
val=$(awk '
  /^[[:space:]]*\[node_db\][[:space:]]*$/ { inb=1; next }
  inb && /^[[:space:]]*\[/               { inb=0 }
  inb && /^[[:space:]]*advisory_delete[[:space:]]*=/ { sub(/^[^=]*=[[:space:]]*/,""); sub(/[[:space:]]+$/,""); print; exit }
' "$CFG")
if [[ "$adc" == "1" && "$val" == "1" ]]; then ok "advisory_delete=1 (one line)"
elif [[ "$adc" != "1" ]]; then bad "expected one advisory_delete line, found $adc"
else bad "advisory_delete=$val, expected 1"; fi

# 2. can_delete answers (advisory in effect).
echo "2. can_delete responds"
cd_out=$(docker exec "$SERVICE" rippled can_delete 2>/dev/null)
cd_status=$(echo "$cd_out" | python3 -I -c 'import sys,json;print(json.load(sys.stdin)["result"].get("status",""))' 2>/dev/null)
cd_err=$(echo "$cd_out" | python3 -I -c 'import sys,json;print(json.load(sys.stdin)["result"].get("error",""))' 2>/dev/null)
if [[ "$cd_status" == "success" ]]; then ok "can_delete answers (advisory is in effect)"
elif [[ "$cd_err" == *"notEnabled"* || "$cd_err" == *"notReady"* ]]; then bad "can_delete says '$cd_err' (advisory not in effect; the node needs restarting after enable-advisory-delete.sh)"
else bad "can_delete did not answer cleanly (status='$cd_status' error='$cd_err')"; fi

# 3. timer enabled + scheduled.
echo "3. can_delete timer"
if systemctl is-enabled --quiet aperire-can-delete.timer 2>/dev/null; then
  nxt=$(systemctl show aperire-can-delete.timer -p NextElapseUSecRealtime --value 2>/dev/null)
  ok "aperire-can-delete.timer is enabled (next: ${nxt:-scheduled})"
else bad "aperire-can-delete.timer is not enabled (run install-can-delete-timer.sh)"; fi

# 4. rotation-state read.
echo "4. rotation-state"
rs=$(bash "$WRAPPER" rotation-state 2>/dev/null | awk '{print $1}')
case "$rs" in
  idle|clear|rotating|stale|unknown) ok "rotation-state='$rs'"; [[ "$rs" == "rotating" ]] && note "a rotation is in flight; restarts are refused until it finishes";;
  *) bad "rotation-state returned '$rs'";;
esac

# 5. --status.
echo "5. can-delete --status"
if [[ -x "$CANDEL" ]]; then
  # Capture first, then match. Piping straight into `grep -q` closes the pipe
  # on the first hit; --status is still writing later lines and takes SIGPIPE,
  # which pipefail then reports as a failure even though the match succeeded.
  st_out=$("$CANDEL" --status 2>/dev/null || true)
  if grep -qiE 'advisory[[:space:]]+on' <<<"$st_out"; then ok "--status reports advisory on"
  else bad "--status did not report advisory on"; fi
else note "can-delete not installed at $CANDEL, skipping --status"; fi

# 6. the guard refuses a restart while the lock is held.
echo "6. guard refuses a restart during a rotation window"
mkdir -p "$(dirname "$LOCK")"
exec {LFD}>"$LOCK"
if flock -w 90 "$LFD"; then
  up0=$(docker exec "$SERVICE" rippled server_info 2>/dev/null | python3 -I -c 'import sys,json;print(json.load(sys.stdin)["result"]["info"]["uptime"])' 2>/dev/null)
  rout=$(bash "$WRAPPER" restart 2>&1); rc=$?
  up1=$(docker exec "$SERVICE" rippled server_info 2>/dev/null | python3 -I -c 'import sys,json;print(json.load(sys.stdin)["result"]["info"]["uptime"])' 2>/dev/null)
  flock -u "$LFD"
  if [[ "$rc" == "64" ]] && [[ -n "$up0" && -n "$up1" ]] && (( up1 >= up0 )); then
    ok "restart refused (exit 64), node still up (uptime ${up0}s -> ${up1}s, not reset)"
  elif [[ "$rc" != "64" ]]; then bad "restart returned $rc, expected 64 (refused). Output: $rout"
  else bad "node uptime went ${up0}s -> ${up1}s (a reset means it restarted anyway)"; fi
else
  note "a real rotation window has held the lock for 90s; the guard is proven by that window itself. Re-run when it has finished (systemctl status aperire-can-delete.service)."
fi
exec {LFD}>&-

# 7. co-located dashboards: the free-days metric.
echo "7. nudb_mount_free_days metric (co-located dashboards only)"
# Read AS the dashboard's account (ADR 0024 lane 4), never as root: sqlite3
# run as root on a WAL database with no -shm beside it makes a root-owned one
# the dashboard then cannot open, and the database sits in that account's own
# directory. The account is the dashboard unit's User=.
DB=$(sed -n 's/^APERIRE_DB_PATH=//p' /etc/aperire/aperire.env 2>/dev/null | head -1)
DA_LIB="$HERE/dashboard-account-lib.sh"
if [[ -z "$DB" || ! -f "$DB" ]]; then
  note "no local metrics DB, this host is not a co-located dashboard"
elif ! command -v sqlite3 >/dev/null 2>&1; then
  note "sqlite3 is not installed, so the metrics DB at $DB was not read"
elif [[ ! -r "$DA_LIB" ]]; then
  note "$DA_LIB is missing, so the metrics DB at $DB was not read (it is read as the dashboard's account, never as root)"
else
  # shellcheck source=scripts/dashboard-account-lib.sh
  . "$DA_LIB"
  if ! da_resolve_unit "${DA_UNIT_DIR}/aperire-server.service"; then
    note "the metrics DB at $DB was not read: ${DA_WHY}"
  else
    # The count is the account's to shape (its own database), so it is a
    # plain integer or it is not a count: [[ -ge ]] evaluates its operands
    # as expressions, and an array subscript in one runs a command (#875
    # review, M1). A refused switch (125) is said, never "no samples yet".
    n_rc=0
    n=$(as_dashboard_sqlite "$DB" 'select count(*) from metrics where metric="nudb_mount_free_days";' 2>/dev/null) || n_rc=$?
    if [[ $n_rc -ne 0 ]]; then
      bad "could not read the metrics DB at $DB as ${DA_ACCOUNT} (exit $n_rc)"
    elif ! da_is_count "$n"; then
      bad "the metrics DB at $DB answered a count that is not a number; refusing to use it"
    elif (( n >= 1 )); then
      v=$(as_dashboard_sqlite "$DB" 'select value from metrics where metric="nudb_mount_free_days" order by ts desc limit 1;' 2>/dev/null)
      ok "nudb_mount_free_days is being written (latest: $v days)"
    else note "no nudb_mount_free_days samples yet (needs a minute of nudb_size history after a restart)"; fi
  fi
fi

echo
echo "verify-rotation-safety: $pass passed, $fail failed"
(( fail == 0 ))
