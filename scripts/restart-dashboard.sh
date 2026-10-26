#!/usr/bin/env bash
# Restart the Aperire dashboard server so it picks up new on-disk code.
#
# `tsx server.ts` does not hot-reload — after editing server.ts or anything
# it imports, the running process keeps serving the old code until restarted.
# Static assets under public/ (HTML/CSS/JS) DO update on a browser reload, so
# a mismatch shows up as new UI rows reading "—" because the old server never
# sends their fields.
#
# This box co-hosts unrelated projects
# under pm2. This script touches ONLY the Aperire dashboard and never pm2's
# `restart all`. Zero impact on rippled or on the other apps.
#
# No root: the unit runs with `Restart=always`, so signalling its MainPID is
# enough, and systemd respawns it with the new code. The signal is sent as the
# account the unit names in User= (ADR 0024 lane 4). On a host installed
# before ADR 0024 that is your own login, and there is no prompt at all. On a
# fresh install it is aperire-dashboard, and sudo asks for your password once
# to act as it. The error log under data/ is read the same way, because data/
# is that account's.
set -euo pipefail

UNIT="aperire-server.service"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="${REPO}/dashboard"
ERRLOG="${REPO}/data/logs/server-err.log"
# shellcheck source=scripts/dashboard-account-lib.sh
. "${REPO}/scripts/dashboard-account-lib.sh"

say() { printf '\n\033[1m%s\033[0m\n' "$*"; }

# 1) systemd — the installed, expected path. `systemctl cat` is a no-pipe
#    existence check, so it can't trip the pipefail/SIGPIPE footgun that an
#    earlier `list-unit-files | grep -q` version did.
if systemctl cat "${UNIT}" >/dev/null 2>&1; then
  OLD_PID="$(systemctl show "${UNIT}" -p MainPID --value)"
  if [ -z "${OLD_PID}" ] || [ "${OLD_PID}" = "0" ]; then
    # Unit exists but isn't running — starting it needs root (system unit).
    say "${UNIT} is installed but stopped. Start it (needs sudo for a system unit):"
    echo "    sudo systemctl start ${UNIT}"
    exit 1
  fi
  # Restart=always means systemd respawns the moment we kill its MainPID.
  # The signal goes as the unit's own account, which owns the process.
  if ! da_resolve_unit "${DA_UNIT_DIR}/${UNIT}"; then
    say "${DA_WHY}"
    exit 1
  fi
  if da_switch_needed; then
    da_sudo_ready "restarting the dashboard signals its own process" || exit 1
    say "Restarting ${UNIT} via MainPID ${OLD_PID}, as ${DA_ACCOUNT} (systemd will respawn)."
  else
    say "Restarting ${UNIT} via MainPID ${OLD_PID} (no sudo — systemd will respawn)."
  fi
  RESTART_AT="$(date +%s)"
  as_dashboard kill "${OLD_PID}"
  NEW_PID=""
  for _ in $(seq 1 30); do
    sleep 0.5
    NEW_PID="$(systemctl show "${UNIT}" -p MainPID --value)"
    STATE="$(systemctl show "${UNIT}" -p ActiveState --value)"
    [ -n "${NEW_PID}" ] && [ "${NEW_PID}" != "0" ] && [ "${NEW_PID}" != "${OLD_PID}" ] \
      && [ "${STATE}" = "active" ] && break
  done
  if [ -z "${NEW_PID}" ] || [ "${NEW_PID}" = "0" ] || [ "${NEW_PID}" = "${OLD_PID}" ]; then
    say "Did not respawn cleanly (still pid '${NEW_PID:-none}'). Check the unit:"
    echo "    systemctl status ${UNIT}"
    echo "  If Restart= is not 'always', restart it directly: sudo systemctl restart ${UNIT}"
    exit 1
  fi
  say "Respawned: new MainPID ${NEW_PID}, state active."
  systemctl --no-pager --full status "${UNIT}" | head -n 12
  # Only lines written since the restart are this restart's. The file is
  # append-only across every run, so a bare tail printed stack traces from
  # days earlier as if the new process had just thrown them.
  # Read as the unit's account: data/ is its directory.
  ERR_MTIME="$(as_dashboard stat -c %Y "${ERRLOG}" 2>/dev/null || true)"
  if [ -n "${ERR_MTIME}" ] && [ "${ERR_MTIME}" -ge "${RESTART_AT}" ]; then
    say "Errors written since this restart (last 20 lines of server-err.log):"
    as_dashboard tail -n 20 "${ERRLOG}"
  else
    say "No errors written since this restart (server-err.log last changed $( [ -n "${ERR_MTIME}" ] && date -d "@${ERR_MTIME}" '+%Y-%m-%d %H:%M' 2>/dev/null || echo never))."
  fi

# 2) Bare process started by hand — scoped to THIS repo's path so it can never
#    match another project's own src/dashboard/server.ts.
elif pgrep -af "${WORKDIR}.*server\.ts" >/dev/null 2>&1; then
  PID="$(pgrep -f "${WORKDIR}.*server\.ts" | head -n1)"
  say "Found a bare tsx process for this repo (pid ${PID}). Stopping it."
  kill "${PID}"
  say "Stopped. It was not under a supervisor — relaunch it the way you started it:"
  echo "    cd ${WORKDIR} && npm start"
  exit 0

else
  say "Could not find the Aperire dashboard (no ${UNIT}, no bare tsx in ${WORKDIR})."
  echo "  Start it with:  cd ${WORKDIR} && npm start"
  echo "  Or install the service: bash ${REPO}/scripts/install-aperire-service.sh"
  exit 1
fi

say "Done. The server samples NuDB on startup and pushes every 5s —"
echo "  NuDB Peak 24h should populate within ~5 seconds."
echo "  In the browser, hard-refresh (Cmd/Ctrl+Shift+R) to load the new system.html."
