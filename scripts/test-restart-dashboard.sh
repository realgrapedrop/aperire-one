#!/usr/bin/env bash
# restart-dashboard.sh signals the dashboard's MainPID and reads its error log
# AS the account the unit names in User= (ADR 0024 lane 4).
#
#   bash scripts/test-restart-dashboard.sh
#
# No root and no real unit. The "dashboard" is a sleep this suite starts.
# systemctl is a fake that reports it as the MainPID and, once it is gone,
# starts a new one, the way Restart=always would. sudo and runuser are fakes
# that log who they switched to, then run the command as this suite.
set -uo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"

PASS=0 FAIL=0
ok()  { printf '  ok    %s\n' "$1"; PASS=$((PASS + 1)); }
bad() { printf '  FAIL  %s\n     %s\n' "$1" "${2:-}"; FAIL=$((FAIL + 1)); }
is()  { if [[ "$2" == "$3" ]]; then ok "$1"; else bad "$1" "got: [$2] | want: [$3]"; fi; }
has() { if [[ "$2" == *"$3"* ]]; then ok "$1"; else bad "$1" "got: $2 | want substring: $3"; fi; }

ME="$(id -un)"
IS_ROOT=0; [[ "$(id -u)" == 0 ]] && IS_ROOT=1
RIG="$TMP/install"
UNITS="$TMP/units"
STATE="$TMP/state"
mkdir -p "$RIG/scripts" "$RIG/dashboard" "$RIG/data/logs" "$UNITS" "$STATE" "$TMP/bin"
cp "$REPO_DIR/scripts/restart-dashboard.sh" "$REPO_DIR/scripts/advisor-owner-lib.sh" "$RIG/scripts/"
sed -e "s#^DA_UNIT_DIR=/etc/systemd/system\$#DA_UNIT_DIR=${UNITS}#" -e "s#^DA_UPDATE_CONF=/etc/aperire/update.conf\$#DA_UPDATE_CONF=${DA_TEST_UPDATE_CONF:-/nonexistent/update.conf}#" \
  "$REPO_DIR/scripts/dashboard-account-lib.sh" > "$RIG/scripts/dashboard-account-lib.sh"
grep -q "^DA_UNIT_DIR=${UNITS}\$" "$RIG/scripts/dashboard-account-lib.sh" \
  || { echo "DA_UNIT_DIR rewrite did not land in dashboard-account-lib.sh" >&2; exit 1; }

# Called only through the trap below, which shellcheck cannot see.
# shellcheck disable=SC2317
cleanup() {
  [[ -f "$STATE/pid" ]] && kill "$(cat "$STATE/pid")" 2>/dev/null
  rm -rf "$TMP"
}
trap cleanup EXIT

export FAKE_STATE="$STATE"
cat > "$TMP/bin/systemctl" <<'EOF'
#!/usr/bin/env bash
# cat <unit>: the unit exists. show <unit> -p X --value: MainPID is the live
# sleep, respawned when the last one is gone; ActiveState is active.
case "${1:-}" in
  cat) exit 0 ;;
  show)
    for a in "$@"; do
      case "$a" in
        MainPID)
          pid="$(cat "$FAKE_STATE/pid" 2>/dev/null)"
          # A zombie is gone: a container whose PID 1 reaps nothing keeps a
          # killed sleep as one, and kill -0 still answers for it.
          if [[ -z "$pid" ]] || ! kill -0 "$pid" 2>/dev/null \
             || [[ "$(awk '{print $3}' "/proc/$pid/stat" 2>/dev/null)" == Z ]]; then
            sleep 300 >/dev/null 2>&1 &
            pid=$!
            disown 2>/dev/null || true
            printf '%s\n' "$pid" > "$FAKE_STATE/pid"
          fi
          echo "$pid"; exit 0 ;;
        ActiveState) echo active; exit 0 ;;
      esac
    done
    exit 0 ;;
  status) echo "aperire-server.service - fake"; exit 0 ;;
  *) exit 0 ;;
esac
EOF
export SWITCH_LOG="$TMP/switch.log"
for prog in sudo runuser; do
  cat > "$TMP/bin/$prog" <<EOF
#!/usr/bin/env bash
who="" flags=""
while [[ \$# -gt 0 ]]; do
  case "\$1" in
    -u) who="\$2"; shift 2 ;;
    -n) flags="\$flags -n"; shift ;;
    -v) exit 0 ;;
    --) shift; break ;;
    -*) shift ;;
    *) break ;;
  esac
done
logcmd="\$*"; [[ "\${1:-}" == env && "\${2:-}" == -i ]] && logcmd="\${*:4}"
printf '%s%s :: %s :: %s\n' "$prog" "\$flags" "\$who" "\$logcmd" >> "\$SWITCH_LOG"
exec "\$@"
EOF
done
chmod +x "$TMP/bin"/*
export PATH="$TMP/bin:$PATH"

dash_unit() { printf '[Service]\nWorkingDirectory=%s/dashboard\nUser=%s\n' "$RIG" "$1" > "$UNITS/aperire-server.service"; }
restart() { : > "$SWITCH_LOG"; bash "$RIG/scripts/restart-dashboard.sh" </dev/null 2>&1; }
# Alive means running: a zombie (see the fake systemctl) counts as gone.
alive() { kill -0 "$1" 2>/dev/null && [[ "$(awk '{print $3}' "/proc/$1/stat" 2>/dev/null)" != Z ]]; }
first_pid() { systemctl show aperire-server.service -p MainPID --value; }

echo "1. a host installed before ADR 0024: the unit names the operator's own login"
dash_unit "$ME"
old="$(first_pid)"
out="$(restart)"; rc=$?
is "exits 0" "$rc" "0"
has "  it says no sudo" "$out" "no sudo"
is "  the old process is gone" "$(alive "$old" && echo alive || echo gone)" "gone"
is "  signalled directly, with no account switch" "$(cat "$SWITCH_LOG")" ""

echo
echo "2. a fresh install: the unit names aperire-dashboard"
dash_unit aperire-dashboard
printf 'TypeError: boom\n' > "$RIG/data/logs/server-err.log"
touch -d '+1 minute' "$RIG/data/logs/server-err.log"
old="$(first_pid)"
out="$(restart)"; rc=$?
is "exits 0" "$rc" "0"
has "  it names the account it signals as" "$out" "as aperire-dashboard"
is "  the old process is gone" "$(alive "$old" && echo alive || echo gone)" "gone"
log="$(cat "$SWITCH_LOG")"
route=sudo; [[ $IS_ROOT -eq 1 ]] && route=runuser
has "  the signal went as aperire-dashboard, through $route" "$log" ":: aperire-dashboard :: kill $old"
has "  the error log was read as aperire-dashboard too" "$log" ":: aperire-dashboard :: tail -n 20 $RIG/data/logs/server-err.log"
has "  and its new lines are shown" "$out" "TypeError: boom"

echo
echo "3. a unit with no User= this can read: refused, nothing signalled"
printf '[Service]\nWorkingDirectory=%s/dashboard\n' "$RIG" > "$UNITS/aperire-server.service"
old="$(first_pid)"
out="$(restart)"; rc=$?
is "exits 1" "$rc" "1"
has "  it says it could not read the account" "$out" "could not read which account the dashboard runs as"
is "  the process is untouched" "$(alive "$old" && echo alive || echo gone)" "alive"

echo
echo "pass=$PASS fail=$FAIL"
if [[ $FAIL -eq 0 ]]; then echo "ALL PASS"; exit 0; fi
echo "FAILED"
exit 1
