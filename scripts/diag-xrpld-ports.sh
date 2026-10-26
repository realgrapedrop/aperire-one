#!/bin/bash
# diag-xrpld-ports.sh — read-only diagnostic for the relay connection-count
# accuracy gap (peer_conn/http_rpc_conn/ws_public_conn reading 0).
#
# Finds the running node (binary may be renamed: rippled/xrpld/xahaud), prints
# its configured ports, and tallies where its ESTABLISHED connections actually
# live — so we can point the relay at the right port/process. Writes nothing.
#
#   sudo bash scripts/diag-xrpld-ports.sh
#
set -uo pipefail

echo "==================================================================="
echo " 1. Node process (renamed-binary aware)"
echo "==================================================================="
# Match common XRPL daemon names; fall back to whatever owns :51235 / :6006.
PID="$(pgrep -x -f -d' ' 'xrpld|rippled|xahaud' 2>/dev/null | awk '{print $1}')"
[ -z "${PID:-}" ] && PID="$(pgrep -x rippled 2>/dev/null | head -1)"
[ -z "${PID:-}" ] && PID="$(pgrep -x xrpld   2>/dev/null | head -1)"
[ -z "${PID:-}" ] && PID="$(pgrep -x xahaud  2>/dev/null | head -1)"
if [ -z "${PID:-}" ]; then
  echo "  pgrep miss — locating by listening port 6006/51235:"
  PID="$(ss -tlnpH 'sport = :6006' 2>/dev/null | grep -oE 'pid=[0-9]+' | head -1 | cut -d= -f2)"
fi
if [ -z "${PID:-}" ]; then
  echo "  ERROR: could not locate the node process." >&2
else
  CMD="$(tr '\0' ' ' < /proc/"$PID"/cmdline 2>/dev/null)"
  echo "  pid=$PID  comm=$(cat /proc/"$PID"/comm 2>/dev/null)"
  echo "  cmdline: $CMD"
  CFG="$(echo "$CMD" | grep -oE '(--conf|--config)[= ]+[^ ]+' | grep -oE '/[^ ]+' | head -1)"
  echo "  config:  ${CFG:-<not on cmdline; check defaults>}"
fi

echo
echo "==================================================================="
echo " 2. Configured port sections"
echo "==================================================================="
for f in "${CFG:-}" /etc/xrpld/xrpld.cfg "$HOME/rippled/config/rippled.cfg"; do
  if [ -z "$f" ] || [ ! -f "$f" ]; then continue; fi
  echo "--- $f ---"
  awk '/^\[port_/{s=$0} /^\[/{if($0!~/^\[port_/)s=""} s&&/^(port|protocol|ip|admin)[[:space:]]*=/{print s"  "$0}' "$f"
  echo
done

echo "==================================================================="
echo " 3. Where do the node's ESTABLISHED connections actually live?"
echo "    (local-port tally — peer protocol should dominate one port)"
echo "==================================================================="
echo "-- by LOCAL port (top 12):"
ss -tnH state established "src = *:*" 2>/dev/null \
  | awk '{n=split($3,a,":"); print a[n]}' | sort | uniq -c | sort -rn | head -12
echo
echo "-- the node's own sockets (pid=$PID), local-port tally:"
if [ -n "${PID:-}" ]; then
  ss -tnpH state established 2>/dev/null | grep "pid=$PID," \
    | awk '{n=split($3,a,":"); print a[n]}' | sort | uniq -c | sort -rn | head -12
fi
echo
echo "-- ESTABLISHED touching :51235 / :6006 / :5005 / :5006 (either end):"
for p in 51235 6006 5005 5006; do
  printf "   :%-6s  %s\n" "$p" "$(ss -tnH state established 2>/dev/null | grep -c ":$p\b")"
done
echo
echo "done — paste sections 2 and 3 back."
