#!/usr/bin/env bash
# Confirm the host came back correctly after a reboot.
#
# Everything checked here was verified green before the machine went down, so a
# red line is the restart rather than the work — which is the whole point of
# having it: after a reboot the question is never "is the code right", it is
# "did everything come back".
#
# Needs no root and changes nothing. Reads only.
#
#   bash scripts/verify-after-restart.sh
#
# Every run also writes data/verify-report.json, the same result in a form a
# program can read — that is what lets aperire-verify.timer run this on a
# schedule and the dashboard turn the outcome into a metric. The human output
# below is unchanged by it: both come from the same ok/bad calls, so the file
# and the screen cannot disagree. See scripts/verify-report-lib.sh.

set -uo pipefail   # deliberately not -e: a failed check must be reported, not fatal

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONF=/etc/aperire/node-wrapper.conf
# The node installer's own record of the node it put here. The wrapper's file
# only exists where the Advisor was installed, and a node-only host is the
# fleet's stock shape: on one of those this whole section used to skip itself
# in one quiet line, after a reboot, which is the one moment it is run (#437).
# Both files name the same node; the wrapper's wins where both are there
# because it names more of it.
NODE_CONF=/etc/aperire/node.conf
UNIT_DIR=/etc/systemd/system
# Where node_seen() reads a matched process's own cgroup (#087). A constant
# rather than a literal /proc so a test can point it at a fixture tree; the
# real cgroup file for a real pid cannot be faked any other way.
PROC_DIR=/proc
ADVISORD_UNIT=aperire-advisord
# Where an older release's Advisor sudo rule lived, retired by ADR 0025 and
# named by check_advisor_account_evidence below if one is still there. A
# variable rather than a literal /etc/sudoers.d so a test can point it at a
# fixture directory, the same reason PROC_DIR above is one.
SUDOERS_DIR=/etc/sudoers.d
# Where the Advisor's root socket listens (ADR 0025). A variable for the same
# reason: a test points it at a fixture directory.
WRAPPER_RUN_DIR=/run/aperire
# Two more places that name a node's config independently of $CONF and
# $NODE_CONF, read by node_installed_evidence() below (#570 follow-up, F6,
# 2026-09-20). Variables for the same reason as PROC_DIR and SUDOERS_DIR: a
# test points them at a fixture rather than the real host paths.
DASH_ENV_FILE=/etc/aperire/aperire.env
RELAY_CONF=/etc/aperire/relay.conf
# The two paths install-aperire-node.sh --native writes a config to, read by
# the same function. One variable, space-separated, rather than two: a test
# rewrites it in one line and a real host is never going to have a space in
# either path.
NATIVE_CFG_PATHS="/etc/xrpld/xrpld.cfg /etc/opt/ripple/rippled.cfg"
REPORT="${APERIRE_VERIFY_REPORT:-$REPO/data/verify-report.json}"

# The machine-readable half. Optional on purpose: this script is run by hand
# out of any checkout, and a missing library must cost the report, never the
# run. The stubs keep every call site below identical in both cases.
VR_LIB="$(dirname "${BASH_SOURCE[0]}")/verify-report-lib.sh"
if [[ -r "$VR_LIB" ]]; then
  # shellcheck source=scripts/verify-report-lib.sh
  # shellcheck disable=SC1091  # resolved at runtime from beside this script
  source "$VR_LIB"
  vr_begin verify-after-restart
else
  VR_CHECK=""
  chk()       { VR_CHECK="$1"; }
  vr_record() { :; }
  vr_write()  { return 1; }
fi

pass=0; fail=0; warned=0
ok()   { printf '  \033[32mok\033[0m    %s\n' "$*"; pass=$((pass+1)); vr_record "${VR_CHECK:-}" true  "$*"; }
bad()  { printf '  \033[31mFAIL\033[0m  %s\n' "$*"; fail=$((fail+1)); vr_record "${VR_CHECK:-}" false "$*"; }
note() { printf '        %s\n' "$*"; }
# Neither a pass nor a failure: a check this run genuinely could not make,
# said in its own colour rather than folded into note()'s plain, easy-to-miss
# lines (F3, #568 follow-up, 2026-09-20). A skip that only ever prints in the
# same tone as an aside is a skip nobody reads back later; this is the one
# other outcome a reader has to be able to tell apart from ok and FAIL at a
# glance. Not recorded in the JSON report: that schema is ok true/false, and
# a check this run could not make was never asked in the first place, in the
# report's own terms.
warn() { printf '  \033[33m!!\033[0m    %s\n' "$*"; warned=$((warned+1)); }
say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }

# ------------------------------------------------------------------ services

say "Services"
# Which account a service runs as is worth asserting, but only where there is
# one right answer. The relay has one. The Advisor has two healthy ones and the
# dashboard's is whoever installed it, so both of those are read off the host
# instead of written down here.
check_unit() {
  local unit=$1 want=$2 state user
  chk "service:$unit"
  state=$(systemctl is-active "$unit" 2>/dev/null)
  user=$(systemctl show "$unit" -p User --value 2>/dev/null)
  if [[ "$state" != "active" ]]; then
    bad "$unit is $state"
    note "journalctl -u $unit -n 40"
    return
  fi
  if [[ -n "$want" && "$user" != "$want" ]]; then
    bad "$unit is active but running as '${user:-?}', expected '$want'"
    return
  fi
  ok "$unit active${user:+ as $user}"
}

# The Advisor has no single expected account. install-advisor-account.sh moves
# the service onto a dedicated one and leaves a .before-account marker beside
# the unit; until that has run it stays on the account that installed it. Both
# states are healthy, and asserting the second one reported all three hardened
# lab nodes as broken (issue #122).
#
# So the expectation is read from the unit file on disk, and the marker only
# decides which of the two states that is. The two sources are independent: the
# file is what the installer wrote, systemctl reports what systemd actually
# loaded, so a unit edited without a daemon-reload still fails here.

# The account the dashboard runs as, from whichever of its two units this host
# has. Used to keep the line below honest: an account shared with the dashboard
# is not a dedicated one, whatever the marker says.
#
# Systemd only. A pm2-supervised dashboard (#576) is invisible here, and this
# runs at check_advisord() time, before the pm2 probe further down even asks
# the question -- so on a host like the lab aggregator, where the Advisor could in principle
# share pm2's own account, check_advisord()'s "its own account" conclusion is
# read against an empty string and defaults to the honest-sounding but
# unproven "its own account, install-advisor-account.sh has run" branch. Left
# as a known gap rather than fixed here: closing it means asking the pm2
# probe for an account before this function runs, which reorders more of the
# file than the dashboard-unit row #576 is actually about.
dashboard_account() {
  local u acct
  for u in aperire-server aperire-read; do
    acct=$(systemctl show "$u" -p User --value 2>/dev/null)
    if [[ -n "$acct" ]]; then printf '%s' "$acct"; return; fi
  done
}

# Whether this host has an Advisor at all, which is a different question from
# whether it is up. Not installed is the ordinary case: it is optional, the
# installer's closing banner says "not installed, and is not missing", and
# ADR 0016 makes absence a first-class observed state everywhere else in the
# product. Reading it as a fault here failed a correct GA-default install
# twice on every run, on screen and in the report the two-hour alert rule
# reads (issue #144).
#
# Deliberately the same expression the token check has used since #123, and
# used by all three sites, so they cannot disagree. A service check that
# skipped while the token check still resolved an advisor account to test
# would be #122 in mirror image: an assertion about an account nothing on the
# host explains.
advisord_installed() {
  [[ -f "$UNIT_DIR/${ADVISORD_UNIT}.service" ]] \
    || systemctl is-enabled "$ADVISORD_UNIT" >/dev/null 2>&1
}

check_advisord() {
  local unit=$ADVISORD_UNIT file="$UNIT_DIR/${ADVISORD_UNIT}.service"
  local state have want concluded dash
  # Asked before chk, and the whole block guarded rather than the name cleared
  # afterwards. VR_CHECK is only cleared by vr_record, so a chk followed by a
  # note that records nothing leaves the name set for whichever check reports
  # next. Here that is the working-tree line, which would record a false green
  # in the report under the exact name the dashboard keys on, unseen onscreen.
  if ! advisord_installed; then
    note "$unit: the Advisor is not installed on this host"
    note "  monitoring is whole without it; nothing to fix"
    return
  fi
  chk "service:$unit"
  state=$(systemctl is-active "$unit" 2>/dev/null)
  # Its own row and its own remedy (#541 P1-091): `failed` here almost always
  # means a credential this host cannot open, and the fix is never "wait":
  # `systemctl restart` on a unit past its start limit answers "start
  # request repeated too quickly" and does nothing. reset-failed clears that
  # counter; the generic journalctl hint alone left an operator restarting a
  # unit that refused every attempt silently.
  if [[ "$state" == "failed" ]]; then
    bad "$unit is failed"
    note "sudo systemctl reset-failed $unit && sudo systemctl start $unit"
    note "journalctl -u $unit -n 40   (what it failed on before that)"
    return
  fi
  if [[ "$state" != "active" ]]; then
    bad "$unit is $state"
    note "journalctl -u $unit -n 40"
    return
  fi
  have=$(systemctl show "$unit" -p User --value 2>/dev/null)
  # Assigned without a pipeline, the way install-advisor-account.sh reads the
  # same line: a missing unit file, or one with no User=, has to leave this
  # empty and fall through to the honest branch below rather than trip pipefail.
  want=""
  [[ -r "$file" ]] && want=$(awk -F= '/^User=/{print $2; exit}' "$file")
  dash=$(dashboard_account)
  if [[ -f "${file}.before-account" ]]; then
    # The marker says the move happened. It does not say where to, and on a
    # host whose Advisor was adopted onto the account the dashboard already
    # uses, "its own account" would be claiming a separation that is not
    # there. Say what was observed instead, and leave it green: a shared
    # account is how some hosts were installed, not a fault to fix at 3am.
    if [[ -n "$dash" && "$have" == "$dash" ]]; then
      concluded="moved by install-advisor-account.sh, though this is the dashboard's account too, not a separate one"
    else
      concluded="its own account, install-advisor-account.sh has run"
    fi
  else
    concluded="the account that installed it, before the dedicated-account move"
  fi
  # Neither state puts it on root, whatever the unit file says, and an empty
  # User= is systemd running it as root without naming it.
  if [[ -z "$have" || "$have" == "root" ]]; then
    bad "$unit is active as root (User=${have:-unset}); both healthy states run it unprivileged"
    note "curl -fsSL https://get.aperire.one | bash -s -- --update --force   (at a terminal, and answer Y when it offers to move the Advisor)"
    return
  fi
  if [[ -n "$want" && "$have" != "$want" ]]; then
    bad "$unit is active as '$have', but $file says User=$want"
    note "concluded from the .before-account marker: $concluded"
    note "the loaded service and the unit on disk disagree: systemctl daemon-reload, then restart it"
    return
  fi
  if [[ -z "$want" ]]; then
    ok "$unit active as $have (nothing readable at $file, so the account is unasserted)"
    return
  fi
  ok "$unit active as $have: $concluded"
}
check_advisord

# A second, independent read of the same question (#568, reintroduced
# 2026-09-20). check_advisord above concludes "moved" or "not moved" from
# the unit's own User= line and the .before-account marker beside it, the
# two things install-advisord.sh's own re-run bug rewrote together, so a host
# it already damaged reads as perfectly consistent. Nothing in that trio can
# catch its own mistake.
#
# What the bug never touches: the Advisor's root socket (ADR 0025). Its
# service unit names the one uid the broker admits (--allow-uid=), written by
# install-advisor-account.sh and never by install-advisord.sh, so on a
# re-owned host it is the one place still disagreeing with what the unit now
# says. Read from that evidence inward, never re-derived from User=. The unit
# is root's and 0644, so this account can read it without sudo.
#
# Before ADR 0025 this evidence was the Advisor's one sudo rule. That rule is
# retired: one still on disk is named here, amber, with the two commands that
# remove it, and so is an Advisor still on the retired shared account.
advisor_socket_allow_uid() { # the uid the socket's broker admits, from its unit
  local f="$UNIT_DIR/aperire-node-wrapper@.service"
  [[ -r "$f" ]] || return 1
  grep -oE -- '--allow-uid=[0-9]+' "$f" | head -1 | cut -d= -f2
}

check_advisor_account_evidence() {
  advisord_installed || return 0
  local rule have uid acct dash

  # The retired sudo rule. Amber, not red: an update keeps it for an Advisor
  # still running on it and removes it once that process restarts.
  if [[ -d "$SUDOERS_DIR" && -r "$SUDOERS_DIR" && -x "$SUDOERS_DIR" ]]; then
    for rule in "$SUDOERS_DIR"/aperire-advisor "$SUDOERS_DIR"/aperire-advisor-*; do
      [[ -e "$rule" ]] || continue
      chk advisor-sudo-rule
      warn "advisor-sudo-rule: $rule still grants the Advisor a sudo rule, which ADR 0025 retired; the Advisor reaches the node through its root socket"
      note "sudo systemctl restart $ADVISORD_UNIT && curl -fsSL https://get.aperire.one | bash -s -- --update --force"
      chk ""
    done
  fi

  have="$(systemctl show "$ADVISORD_UNIT" -p User --value 2>/dev/null)"
  dash="$(dashboard_account)"
  if [[ -n "$dash" && "$have" == "$dash" ]]; then
    chk advisor-shared-account
    warn "advisor-shared-account: $ADVISORD_UNIT runs as $have, the dashboard's account; that mode is retired, and the Advisor gets its own account on every systemd now"
    note "curl -fsSL https://get.aperire.one | bash -s -- --update --force   (at a terminal, and answer Y when it offers to move the Advisor; it restarts the Advisor and the dashboard)"
    chk ""
  fi

  uid="$(advisor_socket_allow_uid)" || return 0
  [[ -n "$uid" ]] || return 0
  chk advisor-account-move-evidence
  acct="$(getent passwd "$uid" 2>/dev/null | cut -d: -f1)"
  if [[ -z "$acct" ]]; then
    warn "advisor-account-move-evidence: the Advisor's socket admits uid $uid, which no account here has; cannot cross-check the account move"
    chk ""
    return
  fi
  if [[ "$have" == "$acct" ]]; then
    ok "the Advisor's socket and $ADVISORD_UNIT's own User= agree: $acct"
  else
    bad "the Advisor's socket admits $acct (uid $uid), but $ADVISORD_UNIT runs as '${have:-root}' (the account move's own evidence disagrees with the unit)"
    # The update offers the account move only for an Advisor on a shared
    # account: root, the dashboard's, or a login. Any other account is one the
    # update leaves alone and says nothing about, so it is not the remedy.
    shared_acct=0
    if [[ -z "$have" || "$have" == root ]] || [[ -n "$dash" && "$have" == "$dash" ]]; then
      shared_acct=1
    else
      have_shell="$(getent passwd "$have" 2>/dev/null | head -1)"
      case "${have_shell##*:}" in ""|*/nologin|*/false|*/sync) ;; *) shared_acct=1 ;; esac
    fi
    if (( shared_acct )); then
      note "curl -fsSL https://get.aperire.one | bash -s -- --update --force   (at a terminal, and answer Y when it offers to move the Advisor; it puts the unit back on $acct)"
    else
      note "curl -fsSL https://get.aperire.one | bash -s -- --run advisor-account    (puts the unit back on $acct)"
    fi
  fi
}
check_advisor_account_evidence

# The Advisor's route to the node (ADR 0025). A build from this release
# reaches the wrapper only through its root socket: the one --wrapper-socket=
# names, or, on a unit an update has not rewritten, the one it derives from
# the installed wrapper's name behind --sudo-wrapper. A socket that is not
# there is an Advisor that cannot reach its node while its process reads as
# perfectly healthy everywhere else on this page, so it is red. An older build
# still on --sudo-wrapper has its own route and is not judged here. The
# binary is read for the flag, never run.
check_advisor_wrapper_route() {
  advisord_installed || return 0
  local exec bin sock wrapper base
  exec="$(grep -m1 '^ExecStart=' "$UNIT_DIR/${ADVISORD_UNIT}.service" 2>/dev/null)"
  [[ "$exec" == *" --wrapper="* ]] || return 0
  bin="${exec#ExecStart=}"; bin="${bin%% *}"
  sock="$(grep -oE -- '--wrapper-socket=[^ ]+' <<<"$exec" | head -1 | cut -d= -f2-)"
  if [[ -z "$sock" ]]; then
    [[ "$exec" == *" --sudo-wrapper"* ]] || return 0
    grep -qa -- 'wrapper-socket' "$bin" 2>/dev/null || return 0
    wrapper="$(grep -oE -- '--wrapper=[^ ]+' <<<"$exec" | head -1 | cut -d= -f2-)"
    base="${wrapper##*/}"
    case "$base" in
      aperire-node-wrapper|aperire-node-wrapper-*) sock="$WRAPPER_RUN_DIR/node-wrapper${base#aperire-node-wrapper}.sock" ;;
      *) sock="" ;;
    esac
    if [[ -z "$sock" ]]; then
      chk advisor-wrapper-socket
      bad "$ADVISORD_UNIT runs a build with no sudo path, on --sudo-wrapper with $wrapper, which is no installed wrapper: it cannot reach the node"
      note "curl -fsSL https://get.aperire.one | bash -s -- --update --force"
      return
    fi
  fi
  chk advisor-wrapper-socket
  if [[ -S "$sock" && ! -L "$sock" ]]; then
    ok "the Advisor's root socket is listening ($sock)"
  else
    bad "$ADVISORD_UNIT reaches the node only through $sock, and nothing is listening there: it cannot reach the node"
    note "curl -fsSL https://get.aperire.one | bash -s -- --update --force"
  fi
  # A burst past the socket's trigger limit stops it listening until
  # somebody restarts it, and the file can outlive that (#779 review, L4).
  # Said by name, with the one command that brings it back.
  local sunit result
  sunit="aperire-$(basename "$sock" .sock).socket"
  result="$(systemctl show "$sunit" --property=Result --value 2>/dev/null)"
  if [[ "$result" == trigger-limit-hit ]]; then
    chk advisor-wrapper-socket-limit
    bad "$sunit tripped its trigger limit and stopped listening: the Advisor cannot reach the node until it is restarted"
    note "sudo systemctl restart $sunit"
  fi
}
check_advisor_wrapper_route

# Not every dashboard is a systemd unit (#576). The fleet's lab
# aggregator, is deployed from source rather than through the installer and
# supervises its dashboard with pm2 instead, as the process aperire-aggregator
# under its own account -- healthy the whole time, and neither aperire-server
# nor aperire-read is installed there at all. That used to read as "no
# dashboard unit on this host" unconditionally, which is the wrong verdict on
# a host this script never had a systemd-shaped answer for in the first place.
#
# A pm2 process is matched to THIS tree by where it runs (pm2_env.pm_cwd),
# never by its name: an operator can call the pm2 process anything, and
# aperire-aggregator is what the lab's own publishing script happens to pick,
# not a rule every install follows. pm2_env.pm_cwd and pm2_env.status are the
# two fields real consumers already read off a live `pm2 jlist` in this repo
# (scripts/aperire-fleet-broker.sh's reload path, the
# rename-install-dir tool, the lab publish tool); pid, restart_time
# and pm_uptime are documented by pm2 itself but nothing else here reads them
# yet, so what this prints for those three is read straight off a live jlist,
# not invented.
#
# Prints EITHER the jlist JSON (rc 0) OR the one-line reason it could not be
# had (rc 2) -- never a global set from inside, because every call site below
# reads this through $( ), and a command substitution is a subshell: a
# variable written there is thrown away the moment it returns, the same trap
# this file's own comments call out elsewhere (see reload_dashboard() in
# aperire-fleet-broker.sh). The exit status crosses that boundary fine; only
# a second channel of output does not.
dashboard_pm2_jlist() {
  local bin owner me out rc
  bin=$(command -v pm2 2>/dev/null) || return 1
  me=$(id -un)
  owner=""
  [[ -e "$REPO/dashboard/server.ts" ]] && owner=$(stat -c '%U' "$REPO/dashboard/server.ts" 2>/dev/null)
  if [[ -n "$owner" && "$owner" != "$me" ]]; then
    # A bare `pm2 jlist` as the wrong account does not fail -- it silently
    # starts a fresh pm2 daemon under THAT account's own $HOME/.pm2 and
    # answers an empty list, which reads as "nothing running" on a host
    # where the dashboard is very much up. Read-only means never risking
    # that: query as the owner, through passwordless sudo, or say plainly
    # that this account cannot ask.
    if ! sudo -n true 2>/dev/null; then
      printf "the dashboard tree at %s is owned by '%s', not this account ('%s'), and there is no passwordless sudo to become them" \
        "$REPO/dashboard" "$owner" "$me"
      return 2
    fi
    out=$(sudo -n -u "$owner" "$bin" jlist 2>/dev/null); rc=$?
    if [[ $rc -ne 0 ]]; then
      printf "pm2 jlist failed as '%s' (through passwordless sudo)" "$owner"
      return 2
    fi
    printf '%s' "$out"
    return 0
  fi
  out=$("$bin" jlist 2>/dev/null); rc=$?
  if [[ $rc -ne 0 ]]; then
    printf "pm2 jlist failed as this account ('%s')" "$me"
    return 2
  fi
  printf '%s' "$out"
  return 0
}

# The last read-only word before this is reported as genuinely absent: no
# systemd unit, no pm2 (or none naming this tree), but a live process whose
# cwd is $REPO/dashboard and whose argv names server.ts anyway -- the shape an
# ad-hoc `nohup npm start &` or a supervisor this script has never heard of
# leaves behind. /proc/PID/cmdline is NUL-separated on every host this runs on.
dashboard_process_seen() {
  local pid cwd cmdline
  [[ -d "$PROC_DIR" ]] || return 1
  for pid in "$PROC_DIR"/[0-9]*; do
    [[ -d "$pid" ]] || continue
    cwd=$(readlink "$pid/cwd" 2>/dev/null) || continue
    [[ "$cwd" == "$REPO/dashboard" ]] || continue
    cmdline=$(tr '\0' ' ' <"$pid/cmdline" 2>/dev/null) || continue
    [[ "$cmdline" == *server.ts* ]] || continue
    return 0
  done
  return 1
}

check_dashboard_pm2() {
  chk dashboard-unit-installed
  local json rc row p_name p_status p_pid p_restarts p_uptime
  json=$(dashboard_pm2_jlist); rc=$?
  if [[ $rc -eq 2 ]]; then
    warn "dashboard-unit-installed: pm2 is on PATH but cannot be queried for this tree's dashboard: $json"
    note "run it directly, as the account that owns $REPO/dashboard:  pm2 jlist"
    chk ""
    return
  fi
  if [[ $rc -eq 0 ]] && command -v python3 >/dev/null 2>&1; then
    row=$(printf '%s' "$json" | python3 -c '
import json, sys
try:
    procs = json.load(sys.stdin)
except Exception:
    procs = []
for p in procs:
    env = p.get("pm2_env", {})
    if env.get("pm_cwd") == sys.argv[1]:
        print("\t".join([
            p.get("name", ""),
            env.get("status", ""),
            str(p.get("pid", "")),
            str(env.get("restart_time", "")),
            str(env.get("pm_uptime", "")),
        ]))
        break
' "$REPO/dashboard" 2>/dev/null)
    if [[ -n "$row" ]]; then
      IFS=$'\t' read -r p_name p_status p_pid p_restarts p_uptime <<<"$row"
      if [[ "$p_status" == "online" ]]; then
        # pm_uptime is when pm2 started it, epoch milliseconds. Turned into
        # elapsed minutes here rather than printed raw: a millisecond
        # timestamp read out of context is not what "uptime" means to
        # whoever reads this line.
        local up="" now_ms elapsed_min
        if [[ "$p_uptime" =~ ^[0-9]+$ && "$p_uptime" -gt 0 ]]; then
          now_ms=$(date +%s%3N 2>/dev/null) || now_ms=""
          if [[ "$now_ms" =~ ^[0-9]+$ && "$now_ms" -ge "$p_uptime" ]]; then
            elapsed_min=$(((now_ms - p_uptime) / 60000))
            up=", up ${elapsed_min}m"
          fi
        fi
        ok "pm2 process '$p_name' online (pid $p_pid, ${p_restarts:-0} restarts$up) -- supervisor: pm2, not a systemd unit"
        return
      fi
      bad "pm2 process '$p_name' is ${p_status:-unknown}, not online -- supervisor: pm2, not a systemd unit"
      note "pm2 logs $p_name --lines 40 --nostream"
      return
    fi
  fi
  if dashboard_process_seen; then
    ok "a running process matches this tree's dashboard/server.ts, though neither systemd nor pm2 names it -- supervisor: unknown (process table only)"
    return
  fi
  bad "no dashboard unit on this host: neither aperire-server nor aperire-read is installed, and no pm2 process or running process matches $REPO/dashboard"
  note "systemctl list-unit-files 'aperire-*'"
  note "pm2 jlist   (as the account that runs it, if this host uses pm2)"
}

# The dashboard is aperire-server on a full node and aperire-read on a read-API
# peer, and a host installs one or the other. Asserting one name reported the
# read-API nodes as down while they were serving. Every one of the two that is
# installed here gets checked, so a host carrying both cannot pass on the
# strength of whichever happens to be up.
dash_units=0
for _u in aperire-server aperire-read; do
  if [[ -f "$UNIT_DIR/${_u}.service" ]] || systemctl is-enabled "$_u" >/dev/null 2>&1; then
    dash_units=$((dash_units + 1))
    check_unit "$_u" ""
  fi
done
if [[ "$dash_units" -eq 0 ]]; then
  check_dashboard_pm2
fi

# The relay is optional, the same way the Advisor is (#570): it runs on the
# validator host beside a local node, and an aggregator with no node of its
# own never has one. Asserted unconditionally, this reported every aggregator
# as down for a service it was never installed with, every morning: a fleet
# aggregator has no local relay by design, and neither does a split-install
# dashboard host, where the relay runs on the node's box instead.
#
# The same trade-off already accepted for the Advisor comes with it: a
# validator host whose relay unit was removed by hand, rather than through
# the uninstaller, now reads as "not installed" rather than "inactive". A
# relay that failed to install in the first place and one an operator
# deliberately took off the host both read the same way an absent Advisor
# already does, and that is judged the safer silence to have.
if [[ -f "$UNIT_DIR/aperire-relay.service" ]] || systemctl is-enabled aperire-relay >/dev/null 2>&1; then
  check_unit aperire-relay aperire-relay
else
  note "aperire-relay unchecked: not installed on this host"
fi

# --------------------------------------------------------- log rotation

# install-aperire-service.sh renders /etc/logrotate.d/aperire<instance> from a
# template every time it runs, so a stale glob only survives on a host whose
# tree moved (a rename, a reinstall to a new path) without that installer
# ever running again — which is exactly how prod's logs went unrotated from
# 2026-08-17 (#734). Read-only, the same as every other check here: this
# reports the drift, it does not re-render the file.
#
# Where the glob is read from, a variable so a test can point it at a fixture
# directory rather than the real /etc/logrotate.d.
LOGROTATE_DIR="${APERIRE_VERIFY_LOGROTATE_DIR:-/etc/logrotate.d}"

check_logrotate() {
  local f glob dir acct found=0
  for f in "${LOGROTATE_DIR}"/aperire*; do
    [[ -f "$f" ]] || continue
    found=1
    chk "logrotate:$(basename "$f")"
    # The template's first line is always "<glob> {"; the glob itself never
    # has a space, so the first field is exactly it.
    glob=$(awk 'NR==1{print $1; exit}' "$f")
    dir=$(dirname "$glob" 2>/dev/null || true)
    # data/ is the dashboard's own account's, 0700, on a fresh install (ADR
    # 0024), so an operator running this by hand cannot see into it. That is
    # this account's view, not a missing directory: the timer runs as the
    # dashboard's account and checks it.
    if [[ "$dir" == "${REPO}/data/logs" && -d "${REPO}/data" && ! -x "${REPO}/data" ]]; then
      note "$(basename "$f"): ${REPO}/data is not this account's to read; the verifier's own timer checks it"
      continue
    fi
    if [[ -z "$dir" || ! -d "$dir" ]]; then
      bad "$(basename "$f") names a log directory that does not exist: ${glob:-<empty>}"
      note "re-run: curl -fsSL https://get.aperire.one | bash -s -- --update --force"
      continue
    fi
    if [[ "$dir" != "${REPO}/data/logs" ]]; then
      bad "$(basename "$f") rotates ${dir}, not this checkout's ${REPO}/data/logs"
      note "the tree moved since this file was last rendered; re-run install-aperire-service.sh"
      continue
    fi
    acct="$(dashboard_account)"
    if [[ -n "$acct" ]]; then
      local bad_owner=()
      local logf owner
      shopt -s nullglob
      for logf in "$dir"/*.log; do
        owner=$(stat -c '%U' "$logf" 2>/dev/null || true)
        [[ -n "$owner" && "$owner" != "$acct" ]] && bad_owner+=("$(basename "$logf"):$owner")
      done
      shopt -u nullglob
      if [[ ${#bad_owner[@]} -gt 0 ]]; then
        bad "$(basename "$f") runs \`su $acct\`, but not every log there is $acct's: ${bad_owner[*]}"
        note "copytruncate under su fails silently on a file it cannot write; re-run install-aperire-service.sh"
        continue
      fi
    fi
    ok "$(basename "$f") rotates ${dir}, owned by ${acct:-the dashboard account}"
  done
  if [[ $found -eq 0 ]]; then
    note "logrotate unchecked: no ${LOGROTATE_DIR}/aperire* file on this host"
  fi
}

say "Log rotation"
check_logrotate

# The one file whose permissions are invisible until a ceremony fails.
#
# advisord verifies every pushed credential bundle against the aggregator's
# public key in dashboard/config/fleet-trust.yaml. If its account cannot read
# that file the push fails 403 and the operator sees "your passkey is not
# enrolled" at an approval prompt, on a node that is otherwise healthy — which
# is exactly what happened on 2026-08-19. It costs one stat to check, and a
# restart is when a changed unit or a re-created account would have moved it.
#
# Read-only: this reports, it never repairs. A signing-key file is tightened
# deliberately by the installer, not as a side effect of a health check.
say "Fleet trust"
FT_LIB="$REPO/scripts/fleet-trust-perms.sh"
if [[ -r "$FT_LIB" ]]; then
  # shellcheck source=scripts/fleet-trust-perms.sh
  # shellcheck disable=SC1091  # resolved at runtime from $REPO, beside this script
  source "$FT_LIB"
  # $ADVISORD_UNIT named explicitly (#589): left to its own default glob,
  # ft_advisor_account used to match the FIRST file on disk starting with
  # "aperire-advisord", in ASCII order, and
  # aperire-advisord-credcheck.service (its OnFailure= handler, which runs
  # User=root by design) sorts before aperire-advisord.service itself,
  # because '-' sorts before '.'. That read the trust row as "measured: root
  # can read", which is true of every file on the host and proves nothing.
  ft_line=$(ft_check_file "$REPO/dashboard/config/fleet-trust.yaml" "$UNIT_DIR" "$ADVISORD_UNIT")
  ft_state="${ft_line%%$'\t'*}"
  ft_msg="${ft_line#*$'\t'}"
  chk fleet-trust-perms
  case "$ft_state" in
    ok)   ok "fleet-trust.yaml: $ft_msg" ;;
    # Nothing to judge here, so nothing is recorded — and the name is put back
    # so it cannot be picked up by whichever check reports next.
    skip) note "fleet-trust.yaml: $ft_msg"; chk "" ;;
    # The unit exists but its effective User= is root or unset (#589): root
    # can read anything, so testing as root would prove nothing about
    # whichever account the Advisor actually runs as. Amber, not green, and
    # not recorded either, the same "could not judge" treatment as skip.
    warn) warn "fleet-trust.yaml: $ft_msg"; chk "" ;;
    *)    bad "fleet-trust.yaml: $ft_msg"
          note "advisord cannot verify a pushed trust bundle until this is fixed"
          # A unit with no User= to read has nothing to chgrp toward yet.
          [[ "$ft_msg" == *"names no User= under"* ]] \
            || note "fix: chgrp it to a group the advisor account is in, then chmod 640" ;;
  esac
else
  note "scripts/fleet-trust-perms.sh not found, trust-file permissions unchecked"
fi

# ------------------------------------------------------- read-only mount guard

# A unit with ProtectHome=read-only or ProtectSystem=strict (this one
# included, aperire-verify.service) mounts everything outside its own
# ReadWritePaths= read-only for its WHOLE process tree, including a child
# spawned through `sudo -n -u`, so `test -w` against a path in that shadow is
# false for every account regardless of what that path's real owner and mode
# say (#589). This is asked from THIS process's own mount table, never the
# host's real one: the two can disagree, for instance a path newly added to
# ReadWritePaths= on disk but not yet live because the unit has not been
# reinstalled, or this same script run by hand outside the unit at all, and
# it is the namespace actually in force right now that decides what a `test
# -w` failure here can mean.
#
# verify_mount_options <path>: prints that mount's option string (comma
# separated, findmnt's own OPTIONS shape) and returns 0, or returns 1 with
# nothing printed when the mount table could not be read at all. A caller
# that gets 1 has to keep whatever verdict it already had, never guess.
verify_mount_options() {
  local path="$1" opts=""
  if command -v findmnt >/dev/null 2>&1; then
    opts="$(findmnt -no OPTIONS -T "$path" 2>/dev/null)"
  fi
  if [[ -z "$opts" ]]; then
    # No findmnt, or it refused: the same question asked by hand against
    # $PROC_DIR/self/mountinfo (proc(5)). Field 5 is the mount point, field 6
    # is the per-mount option string, and the superblock's own options sit
    # three fields after the "-" separator that always follows whatever
    # optional fields a line carries (zero or more, so the separator's
    # position is never fixed and has to be found, not assumed). Longest
    # matching mount point wins, the same rule `findmnt -T` applies, so a
    # bind mount deeper than its filesystem's own root is not missed.
    [[ -r "${PROC_DIR}/self/mountinfo" ]] || return 1
    opts="$(awk -v target="$path" '
      {
        mp = $5; mountopts = $6; dash = 0
        for (i = 7; i <= NF; i++) { if ($i == "-") { dash = i; break } }
        if (!dash) next
        superopts = $(dash + 3)
        matched = 0
        if (mp == "/") { if (substr(target, 1, 1) == "/") matched = 1 }
        else if (target == mp || index(target, mp "/") == 1) { matched = 1 }
        if (matched && length(mp) > bestlen) { bestlen = length(mp); best = mountopts "," superopts }
      }
      END { print best }
    ' "${PROC_DIR}/self/mountinfo" 2>/dev/null)"
    [[ -n "$opts" ]] || return 1
  fi
  printf '%s' "$opts"
}

# verify_path_is_ro <path>: true (0) only when the mount table could be read
# AND it names "ro" as one of that path's options, in THIS namespace, right
# now. False (1) both for a writable mount and for a mount table that could
# not be read. A caller that needs to tell those two apart calls
# verify_mount_options itself instead.
verify_path_is_ro() {
  local opts o
  opts="$(verify_mount_options "$1")" || return 1
  local IFS=,
  for o in $opts; do
    [[ "$o" == ro ]] && return 0
  done
  return 1
}

# ---------------------------------------------------- advisor state writable

# The account the unit runs as must be able to WRITE its own state, or the
# same silent re-ownership fleet-trust-perms above exists to catch happened
# to advisor/state, advisor/evidence and advisor/knowledge-fleet instead of
# the trust file (#568): a re-run of install-advisord.sh on a host already
# moved onto its own account chowned all five back to the invoking operator,
# and nothing here said so until the next ceremony refused to write its own
# ledger entry.
#
# Read-only in spirit even though the test itself writes: a scratch file
# under a temporary name, created and removed in one command, never a file
# this run did not make. The same skip discipline as the token-closed check
# below: no advisord, no such account, or no passwordless sudo are all
# "cannot test", never "bad": a check that goes red for want of sudo would
# be #570 with a different name.
say "Advisor state directories"
if advisord_installed; then
  adv_state_account=$(systemctl show "$ADVISORD_UNIT" -p User --value 2>/dev/null)
  if [[ -z "$adv_state_account" || "$adv_state_account" == root ]]; then
    note "skipped: $ADVISORD_UNIT names no unprivileged User=, so there is no account to test"
  elif ! id "$adv_state_account" >/dev/null 2>&1; then
    note "skipped: $ADVISORD_UNIT names '$adv_state_account', and no such account exists here"
  elif ! sudo -n true 2>/dev/null; then
    # A real "could not measure", not "nothing to measure" (F3, #568
    # follow-up, 2026-09-20): the account exists and the directories are
    # right here, and the only thing missing is a way to ask the kernel
    # whether that account can write them. Said in its own colour rather
    # than folded into a note nobody reads back, and never green: silence
    # here read the same as "confirmed writable" on a host with no
    # passwordless sudo, which is not what was actually found.
    warn "could not measure whether $adv_state_account can write advisor/state, advisor/evidence, advisor/knowledge-fleet: testing as '$adv_state_account' needs passwordless sudo"
    note "run it directly:  sudo -u $adv_state_account test -w $REPO/advisor/state && echo CAN WRITE"
  else
    for adv_state_dir in state evidence knowledge-fleet; do
      adv_state_path="$REPO/advisor/$adv_state_dir"
      [[ -d "$adv_state_path" ]] || continue
      chk "advisor-state-writable:$adv_state_dir"
      if sudo -n -u "$adv_state_account" test -w "$adv_state_path" 2>/dev/null; then
        ok "advisor/$adv_state_dir is writable by $adv_state_account"
      elif verify_path_is_ro "$adv_state_path"; then
        # Never a permission FAIL (#589): this run's own namespace mounts the
        # path read-only, so `test -w` answered a question about the mount,
        # not about $adv_state_account's real Unix permissions there. Amber,
        # with the one command that asks the real question outside this
        # sandbox, and not recorded, the same "could not judge" treatment
        # skip and the sudo-less row above both get.
        warn "could not confirm advisor/$adv_state_dir is writable by $adv_state_account: this run's own namespace mounts it read-only"
        note "run it directly, outside this unit's sandbox:  sudo -u $adv_state_account test -w $adv_state_path && echo CAN WRITE"
        chk ""
      else
        bad "advisor/$adv_state_dir is NOT writable by $adv_state_account, the account $ADVISORD_UNIT runs as"
        note "sudo chown $adv_state_account advisor/$adv_state_dir"
      fi
    done
  fi
else
  note "advisor state directories unchecked: the Advisor is not installed on this host"
fi

# ------------------------------------------------------------------ the node

say "The node"

# Read, never sourced: these files name what gets inspected and exec'd into,
# so a shell metacharacter in one of them stays data. The wrapper's file is
# asked first and the node installer's answers whatever is left, so a host
# with both reads exactly as it did before and a host with only the second one
# stops skipping its node.
node_fact() { # $1 = key
  local f v
  for f in "$CONF" "$NODE_CONF"; do
    [[ -f "$f" ]] || continue
    v=$(awk -F= -v k="$1" '$1==k{sub(/^[^=]*=/,""); print; exit}' "$f")
    [[ -n "$v" ]] && { printf '%s' "$v"; return 0; }
  done
  return 0
}
SERVICE=$(node_fact SERVICE)
CONFIG_FILE=$(node_fact CONFIG_FILE)

# Recorded as a no-node host, before SERVICE is normalised away below: the
# difference between "this host has told this script it runs no node" and
# "nothing on this host names a node at all" (the truly unrecorded shape
# node_seen() exists to catch). Used only to word the skip notes further
# down; node_seen() itself runs the same way regardless.
IS_NO_NODE_HOST=0
[[ "$SERVICE" == "none" ]] && IS_NO_NODE_HOST=1

# A no-node record says nothing was ever installed, and that is not the same
# claim as nothing running now (#570 follow-up, F6, 2026-09-20). node_seen()
# further down only ever looks for a node that is UP: docker ps with no -a,
# and a process search. A node stopped rather than uninstalled, one adopted
# elsewhere and then left off, or a container simply not started this boot
# all leave that search empty, and normalising the sentinels below would read
# every one of them as the honest aggregator shape they are not. Read only
# when the record actually claims none, since a host with a real record has
# its node checked properly further down regardless of what any of this finds.
#
# Five places, any one of which is enough: a unit file for a stopped native
# node, a container docker ps -a can still see even if it is not running, a
# config at the paths install-aperire-node.sh --native writes to, the node
# installer's own record underneath the wrapper's --no-node sentinel (CONF
# wins in node_fact() above, so NODE_CONF's own CONFIG_FILE is read directly
# here), and the dashboard's or the relay's own config, which each name the
# node's config file independently of both of the above.
# Sets $NODE_INSTALLED_EVIDENCE directly rather than printing it for a
# caller to capture: a source this function could not check (docker present
# but unreachable, or $NODE_CONF unreadable) has to say so with warn(), and
# warn() writes straight to the screen -- inside a `$(...)` capture that
# output would be swallowed into the evidence string instead of shown (F6
# follow-up, 2026-09-20). A plain global assignment, called directly and
# never through a subshell, is what every other check in this file already
# does through ok()/bad()/warn() themselves.
# Rows from docker ps whose Image column (the second field) is a bare image ID
# (a container created from a digest reference, which the Advisor's own
# upgrade makes) get the name the container was created from, read back with
# docker inspect, so the image-name match below still finds the node (#896).
# Only that column is looked at, so a word in a command that looks like an ID
# is left alone; the rest of the row and every separator is left as it was. A
# refused inspect prints docker's reason and returns 1: it is not a container
# that failed to match. A container that is gone by now is skipped. Asked as this account.
resolve_image_ids() { # $1 = docker ps rows
  local line ref rest lead img tail res err out='' nl=$'\n' idre='^(sha256:)?[0-9a-fA-F]{12,64}$'
  local -a dk=(docker)
  while IFS= read -r line; do
    if [[ -n "$line" ]]; then
      ref="${line%%[[:space:]]*}"; rest="${line#"$ref"}"
      lead="${rest%%[![:space:]]*}"; rest="${rest#"$lead"}"
      img="${rest%%[[:space:]]*}"; tail="${rest#"$img"}"
      if [[ -n "$img" && "$img" =~ $idre ]]; then
        res="$("${dk[@]}" inspect --type container "$ref" --format '{{.Config.Image}}' 2>/dev/null)" || res=''
        if [[ -n "$res" ]]; then
          line="${ref}${lead}${res%%@*}${tail}"
        else
          err="$("${dk[@]}" inspect --type container "$ref" --format '{{.Config.Image}}' 2>&1 >/dev/null | head -1 || true)"
          if ! grep -qiE 'no such (object|container)' <<<"$err"; then
            printf '%s' "${err:-no reason given}"; return 1
          fi
        fi
      fi
    fi
    out+="${line}${nl}"
  done <<<"$1"
  printf '%s' "${out%"$nl"}"
}

NODE_INSTALLED_EVIDENCE=""
node_installed_evidence() {
  NODE_INSTALLED_EVIDENCE=""
  local u f p c ps_out
  for u in xrpld rippled xahaud; do
    if [[ -f "$UNIT_DIR/${u}.service" ]]; then
      NODE_INSTALLED_EVIDENCE="a $u.service unit file at $UNIT_DIR/${u}.service"
      return 0
    fi
  done
  if command -v docker >/dev/null 2>&1; then
    if ! docker info >/dev/null 2>&1; then
      warn "docker is present on this host but 'docker info' failed; could not check docker ps -a for a node container"
    else
      if ! ps_out=$(docker ps -a --format '{{.Names}} {{.Image}}' 2>/dev/null); then
        warn "docker info answered but 'docker ps -a' failed; could not check for a node container"
      elif ! ps_out=$(resolve_image_ids "$ps_out"); then
        warn "docker listed the containers but would not say which image one was created from (${ps_out}); could not check for a node container"
      else
        c=$(printf '%s\n' "$ps_out" | grep -aiE 'rippled|xrpld|xahau' | awk 'NR==1{print $1}')
        if [[ -n "$c" ]]; then
          NODE_INSTALLED_EVIDENCE="the container $c (docker ps -a)"
          return 0
        fi
      fi
    fi
  fi
  # shellcheck disable=SC2086  # deliberately unquoted: a space-separated list of two fixed paths, never a value that carries a shell metacharacter
  for p in $NATIVE_CFG_PATHS; do
    if [[ -f "$p" ]]; then
      NODE_INSTALLED_EVIDENCE="a node config at $p"
      return 0
    fi
  done
  if [[ -f "$NODE_CONF" ]]; then
    if [[ ! -r "$NODE_CONF" ]]; then
      warn "$NODE_CONF exists but is not readable by this account; could not check its own CONFIG_FILE"
    else
      f=$(awk -F= '$1=="CONFIG_FILE"{sub(/^[^=]*=/,""); print; exit}' "$NODE_CONF")
      if [[ -n "$f" && "$f" != "/dev/null" && -f "$f" ]]; then
        NODE_INSTALLED_EVIDENCE="$NODE_CONF's own CONFIG_FILE at $f"
        return 0
      fi
    fi
  fi
  if [[ -f "$DASH_ENV_FILE" ]]; then
    f=$(sed -nE 's/^[[:space:]]*RIPPLED_CFG_PATH=//p' "$DASH_ENV_FILE" 2>/dev/null \
        | tail -1 | tr -d "\"' ")
    if [[ -n "$f" && -f "$f" ]]; then
      NODE_INSTALLED_EVIDENCE="the dashboard's RIPPLED_CFG_PATH at $f"
      return 0
    fi
  fi
  if [[ -f "$RELAY_CONF" ]]; then
    f=$(awk -F= '/^[[:space:]]*rippled_cfg_path[[:space:]]*=/{gsub(/["'"'"' ]/,"",$2); print $2; exit}' "$RELAY_CONF")
    if [[ -n "$f" && -f "$f" ]]; then
      NODE_INSTALLED_EVIDENCE="the relay's rippled_cfg_path at $f"
      return 0
    fi
  fi
  return 1
}
if [[ "$IS_NO_NODE_HOST" -eq 1 ]]; then
  node_installed_evidence || true
fi

# The sentinel values install-node-wrapper.sh --no-node writes for a fleet
# aggregator (#570): SERVICE=none and CONFIG_FILE=/dev/null are the record,
# not an absence of one, and the checks below have no branch for them. Left
# as read, SERVICE=none is a non-empty string that sends the node section
# looking for a container literally named "none", and CONFIG_FILE=/dev/null
# is a non-empty path that reads as a validator token sitting open at
# whatever mode /dev/null happens to be. Normalised to empty here, once, so
# every branch below sees exactly what it already knows how to handle: a
# host with no node to check. A node process actually found running despite
# this record (node_seen(), further down) still fails loudly; normalising
# these two variables does not touch that path, only what SERVICE and
# CONFIG_FILE themselves say.
[[ "$SERVICE" == "none" ]] && SERVICE=""
[[ "$CONFIG_FILE" == "/dev/null" ]] && CONFIG_FILE=""

# Is a node running here that nothing on this host has recorded?
#
# Two very different hosts reach the same skip when the record is missing: a
# dashboard-only box, which has no node and nothing to check, and a box whose
# node is up and whose record went with a wipe-clean uninstall. The first is
# fine and quiet. On the second, every node check and the validator-token
# check are skipped, and this script used to print "The host came back
# correctly" over both, which is the kept-versus-observed failure this whole
# file exists to avoid.
#
# So the two are told apart by looking for the node itself. Read-only, no
# root: docker first, and only where the daemon answers, because docker being
# unreachable from this account is not an absence; then the process names the
# three forks use (the vendor's binary names its main thread xrpld-main, so a
# list without it finds nothing on a native host, #463).
#
# Docker goes first because a containerized node's own process is visible in
# the host PID namespace under that same name: /usr/bin/xrpld inside
# `aperire-node` still shows up to this host's pgrep as `xrpld-main`, so a
# process search run first always wins on a container host and calls the
# node "the process xrpld-main" when the host's own docker knows it as the
# container `aperire-node` (#506). Asking docker first, and only trusting the
# process names when docker cannot answer, reports each shape as itself: a
# container host still names its container, and a native host, where docker
# is absent or unreachable, still falls through to naming the process.
NODE_SEEN=""
NODE_SEEN_ASKED=0
# Whether docker itself could be asked, not just whether it found a
# container. A container node is caught by name in the HOST pid namespace
# too (#534), so a process match alone cannot tell "this host's node is
# native" from "docker could not be asked from this account, and the process
# pgrep found is really in a container". Only a docker that actually
# answered and said no rules a container out.
NODE_SEEN_DOCKER_OK=0
# Set only on the shape a name/image match cannot tell apart from a native
# process: a container whose image name docker ps's own substring test does
# not recognise, but whose cgroup still names the runtime that owns it
# (#087). Empty on every other outcome.
NODE_SEEN_UNNAMED_CONTAINER_PID=""
node_seen() {
  if [[ $NODE_SEEN_ASKED -eq 1 ]]; then [[ -n "$NODE_SEEN" ]]; return; fi
  NODE_SEEN_ASKED=1
  local n c pid cgroup cid cname ps_out
  if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    # Docker counts as asked only once an image ID in the list could be read
    # back to a name as well (#896): a refused read is "could not ask", the
    # same as a refused ps, never "no container here".
    ps_out=$(docker ps --format '{{.Names}} {{.Image}}' 2>/dev/null) || ps_out=''
    if ps_out=$(resolve_image_ids "$ps_out"); then
      NODE_SEEN_DOCKER_OK=1
      c=$(printf '%s\n' "$ps_out" | grep -aiE 'rippled|xrpld|xahau' | awk 'NR==1{print $1}')
      if [[ -n "$c" ]]; then
        NODE_SEEN="the container $c"
        return 0
      fi
    fi
  fi
  if command -v pgrep >/dev/null 2>&1; then
    for n in rippled xrpld xahaud xrpld-main rippled-main xahaud-main; do
      pid=$(pgrep -x "$n" 2>/dev/null | head -1)
      if [[ -n "$pid" ]]; then
        # A process match is not proof of a native node. docker ps's own
        # name/image test above is a substring match a foreign or rebuilt
        # image name slips past, and #534 already found that a container's
        # process is visible under this same name in the host's own pid
        # namespace regardless. The cgroup this pid actually sits in is not
        # fooled by either: a container runtime names itself there whatever
        # the image inside it is called, and a bare systemd unit's process
        # never carries one.
        cgroup=""
        [[ -r "$PROC_DIR/$pid/cgroup" ]] && cgroup=$(cat "$PROC_DIR/$pid/cgroup" 2>/dev/null)
        if [[ -n "$cgroup" ]] && grep -qE '(docker|containerd|kubepods)' <<<"$cgroup"; then
          cname=""
          if [[ "$NODE_SEEN_DOCKER_OK" -eq 1 ]]; then
            cid=$(grep -oE '[0-9a-f]{64}' <<<"$cgroup" | head -1)
            [[ -n "$cid" ]] && cname=$(docker inspect --format '{{.Name}}' "$cid" 2>/dev/null | sed 's#^/##')
          fi
          if [[ -n "$cname" ]]; then
            # Named after all: docker can see it, its own name/image test
            # just did not match. Reads exactly like the ordinary container
            # match above, so the same --adopt remedy applies.
            NODE_SEEN="the container $cname"
          else
            NODE_SEEN="the process $n"
            NODE_SEEN_UNNAMED_CONTAINER_PID="$pid"
          fi
          return 0
        fi
        NODE_SEEN="the process $n"
        return 0
      fi
    done
  fi
  return 1
}
# The deployment shape, read the way the wrapper reads it. Absent means
# container: every configuration written before native existed is one, and a
# conf that does not say has to keep reading as what it is.
KIND=$(node_fact KIND)
KIND=${KIND:-container}
NODE_ADMIN_RPC=$(node_fact ADMIN_RPC)
# The fourth sentinel the same --no-node record writes (#570): a port of 0
# answers nothing on any host, and left standing it is the next version of
# this bug the moment something reads NODE_ADMIN_RPC outside the branch
# SERVICE's own normalisation above already keeps this out of.
[[ "$NODE_ADMIN_RPC" == "http://127.0.0.1:0" ]] && NODE_ADMIN_RPC=""

if [[ "$KIND" == native && -n "$SERVICE" ]]; then
  # A node installed from the vendor's package. SERVICE here is a systemd
  # unit, not a container name, and handing it to `docker inspect` is what
  # made this verifier report a running, full node as missing, every night at
  # 03:04, on every native host (#428). The section's three questions all
  # have native answers, and two of them are better ones.
  chk node-unit
  if ! command -v systemctl >/dev/null 2>&1; then
    bad "the configuration names the unit '$SERVICE' but there is no systemctl here to ask about it"
  else
    astate=$(systemctl show "$SERVICE" --property=ActiveState --value 2>/dev/null) || astate=""
    sstate=$(systemctl show "$SERVICE" --property=SubState --value 2>/dev/null) || sstate=""
    case "$astate" in
      active)   ok "unit '$SERVICE' is active (${sstate:-running})" ;;
      "")       bad "systemd would not say what state '$SERVICE' is in" ;;
      *)        bad "unit '$SERVICE' is $astate${sstate:+ ($sstate)}" ;;
    esac
  fi

  # Readable by the account the unit actually runs the node as. This is a
  # stronger reading than the container path's: `docker exec test -r` runs as
  # the image's configured user, which is not always the one the entrypoint
  # drops to, and it has lied about this before.
  node_user=$(systemctl show "$SERVICE" --property=User --value 2>/dev/null) || node_user=""
  node_user=${node_user:-root}
  if [[ -n "$CONFIG_FILE" && -f "$CONFIG_FILE" ]]; then
    chk node-config-readable
    if [[ "$(id -un)" == "$node_user" ]]; then
      # shellcheck disable=SC2015  # ok/bad always return 0, so bad never runs on a pass
      [[ -r "$CONFIG_FILE" ]] && ok "the node can read its config ($CONFIG_FILE)" \
                              || bad "the node CANNOT read its config ($CONFIG_FILE)"
    elif [[ $EUID -eq 0 ]] && command -v runuser >/dev/null 2>&1; then
      if runuser -u "$node_user" -- test -r "$CONFIG_FILE" 2>/dev/null; then
        ok "the node can read its config as $node_user ($CONFIG_FILE)"
      else
        bad "the node CANNOT read its config as $node_user ($CONFIG_FILE)"
        note "it will fail to start next time. fix:"
        note "  curl -fsSL https://get.aperire.one | bash -s -- --run node-config-exposure --apply"
      fi
    else
      # Said, not skipped. A check that quietly does not run is the reason
      # this section was wrong for a day without anyone noticing.
      note "cannot test the config as '$node_user' from this account; re-run as root for that one check"
      chk ""
    fi
  fi

  # Consensus state, over the loopback admin RPC the configuration names.
  # There is no container to exec into here, and this is how the dashboard
  # reads the node anyway.
  if [[ -n "$NODE_ADMIN_RPC" ]] && command -v curl >/dev/null 2>&1; then
    info_json=$(curl -s --max-time 10 -H 'Content-Type: application/json' \
      -d '{"method":"server_info","params":[{}]}' "${NODE_ADMIN_RPC}/" 2>/dev/null) || info_json=""
    if [[ -n "$info_json" ]]; then
      read -r state peers seq < <(printf '%s' "$info_json" | python3 -c "
import json,sys
try:
    d=json.load(sys.stdin)['result']['info']
    print(d.get('server_state','?'), d.get('peers','?'),
          d.get('validated_ledger',{}).get('seq','?'))
except Exception:
    print('? ? ?')
" 2>/dev/null)
      chk node-consensus-state
      if [[ "$state" == "proposing" || "$state" == "full" ]]; then
        ok "node is $state, $peers peers, ledger $seq"
      else
        bad "node is '$state' (expected proposing or full), $peers peers"
      fi
    else
      note "the node did not answer server_info on $NODE_ADMIN_RPC; check by hand"
    fi
  else
    note "neither $CONF nor $NODE_CONF names a loopback admin RPC; skipping the consensus check"
  fi
elif [[ -n "$SERVICE" ]] && command -v docker >/dev/null 2>&1; then
  if ! docker inspect "$SERVICE" >/dev/null 2>&1; then
    # A failed inspect has two very different meanings and one error path. The
    # container may be gone, or this account may simply not be allowed to ask
    # — `docker` is on PATH for everyone, the socket is not. Run by hand from
    # an operator's shell the difference never showed; run from a timer under
    # an account outside the docker group it would report a perfectly healthy
    # node as missing, every day, forever. So the daemon is asked whether it
    # is reachable at all before the absence is believed.
    if ! docker info >/dev/null 2>&1; then
      note "docker is on PATH but not reachable from this account; skipping the node checks"
      note "  add this account to the docker group, or run the verifier as one that is in it"
    else
      chk node-container
      bad "no container named '$SERVICE'"
    fi
  else
    chk node-container
    status=$(docker inspect "$SERVICE" --format '{{.State.Status}}')
    # shellcheck disable=SC2015  # ok/bad are reporters that always return 0, so bad never runs on a pass
    [[ "$status" == "running" ]] && ok "container '$SERVICE' is running" \
                                 || bad "container '$SERVICE' is $status"

    # The check the capability mistake would have failed. `sh -c`, because
    # docker exec runs a binary and `test` is a shell builtin these images do
    # not ship — a bare `docker exec ... test -r` reports failure on a file it
    # can read perfectly well.
    #
    # One destination per line, blanks dropped, sorted, then the first. Since
    # #31 the same host config is mounted at two destinations, and all three
    # parts of that pipeline are load-bearing: without the newline the two
    # paths concatenate into one that exists nowhere and this reports a
    # healthy node as unable to read its own config, after every reboot;
    # without the blank-line filter the empty last line docker leaves sorts
    # first and `head -1` answers nothing, which reads the same way; and
    # without the sort the path this names changes between runs, because
    # docker does not list mounts in a stable order.
    dest=$(docker inspect "$SERVICE" \
      --format "{{range .Mounts}}{{if eq .Source \"$CONFIG_FILE\"}}{{.Destination}}{{\"\\n\"}}{{end}}{{end}}" 2>/dev/null \
      | grep -v '^[[:space:]]*$' | LC_ALL=C sort | head -1)
    if [[ -n "$dest" ]]; then
      chk node-config-readable
      if docker exec "$SERVICE" sh -c "test -r '$dest'" 2>/dev/null; then
        ok "the node can read its config ($dest)"
      else
        bad "the node CANNOT read its config ($dest)"
        note "it will fail to start next time. fix:"
        note "  curl -fsSL https://get.aperire.one | bash -s -- --run node-config-exposure --apply"
      fi
    fi

    # Consensus state, which is the only claim that matters to the operator.
    info_json=$(docker exec "$SERVICE" rippled server_info 2>/dev/null \
                || docker exec "$SERVICE" xrpld server_info 2>/dev/null || true)
    if [[ -n "$info_json" ]]; then
      read -r state peers seq < <(printf '%s' "$info_json" | python3 -c "
import json,sys
try:
    d=json.load(sys.stdin)['result']['info']
    print(d.get('server_state','?'), d.get('peers','?'),
          d.get('validated_ledger',{}).get('seq','?'))
except Exception:
    print('? ? ?')
" 2>/dev/null)
      chk node-consensus-state
      if [[ "$state" == "proposing" || "$state" == "full" ]]; then
        ok "node is $state, $peers peers, ledger $seq"
      else
        bad "node is '$state' (expected proposing or full), $peers peers"
      fi
    else
      note "could not read server_info; check by hand"
    fi
  fi
elif node_seen; then
  # A node is up and nothing here names it, so none of the checks above ran.
  # That is a failure of this run, not a property of the host to pass over:
  # the record is what four readers on this box resolve the node through, and
  # a green verdict printed over checks that never happened is worse than no
  # verdict at all.
  chk node-recorded
  bad "a node is running here ($NODE_SEEN) and nothing on this host names it"
  note "so the container check, the config-readable check and the consensus"
  note "check were not made, and neither was the validator-token check below."
  note "neither $CONF nor $NODE_CONF exists. A wipe-clean uninstall removes"
  note "/etc/aperire whole and leaves the node running, which is where this"
  note "shape comes from. One command records it, and touches nothing else:"
  # The remedy for the shape this host's own record would have named, not the
  # container-only form on every host (#534). node_seen() already told a
  # container from a process; here that is read back rather than re-derived.
  #
  # --native is never printed on process evidence alone (#087). A name/image
  # match against `docker ps` is a substring test a foreign or rebuilt image
  # name slips past, and a containerized node's own process is visible under
  # this same name in the host's pid namespace regardless of what docker
  # ps found, so node_seen() checks the matched process's own cgroup before
  # calling it native. Printing --native there would, on a real host, add a
  # vendor repository and offer to install a second node beside the live one.
  if [[ "$NODE_SEEN" == "the container "* ]]; then
    note "  curl -fsSL https://get.aperire.one | bash -s -- --run node --adopt"
  elif [[ -n "$NODE_SEEN_UNNAMED_CONTAINER_PID" ]]; then
    note "  it is containerized (pid $NODE_SEEN_UNNAMED_CONTAINER_PID's own cgroup names a"
    note "  container runtime), but this account's docker cannot name it, so it cannot be named for --adopt."
    note "  --native would add a second node beside this one on a real host; do not run it."
    note "  Find the container from an account that can see it (its id is in"
    note "  /proc/$NODE_SEEN_UNNAMED_CONTAINER_PID/cgroup), then:"
    note "    curl -fsSL https://get.aperire.one | bash -s -- --run node --adopt --name <that container>"
  elif [[ "$NODE_SEEN_DOCKER_OK" -eq 1 ]]; then
    note "  curl -fsSL https://get.aperire.one | bash -s -- --run node --native"
  else
    note "  docker could not be asked from this account, so which shape this is"
    note "  cannot be told apart here. If the node runs in a container:"
    note "    curl -fsSL https://get.aperire.one | bash -s -- --run node --adopt"
    note "  if it runs natively:"
    note "    curl -fsSL https://get.aperire.one | bash -s -- --run node --native"
  fi
elif [[ "$IS_NO_NODE_HOST" -eq 1 && -n "$NODE_INSTALLED_EVIDENCE" ]]; then
  # A no-node record that is not the whole story: nothing is running (the
  # branch above already ruled that out), but the host still carries
  # $NODE_INSTALLED_EVIDENCE of one having been installed. Stopped is not the
  # same fact as never installed, and the aggregator's own quiet skip below
  # would say the second over evidence of the first (F6, #570 follow-up).
  chk node-recorded-none-but-installed
  bad "this host is recorded as running no node, but $NODE_INSTALLED_EVIDENCE says otherwise"
  note "a stopped or uninstalled-but-not-removed node is not the same as no node;"
  note "the search above only ever looks for one that is running."
  if [[ "$NODE_INSTALLED_EVIDENCE" == "the container "* ]]; then
    note "  curl -fsSL https://get.aperire.one | bash -s -- --run node --adopt"
  else
    note "  curl -fsSL https://get.aperire.one | bash -s -- --run node --native"
  fi
elif [[ "$IS_NO_NODE_HOST" -eq 1 ]]; then
  note "skipped: this host is recorded as running no node (an aggregator);"
  note "nothing here to check, and none is running either."
else
  note "no node named in $CONF or $NODE_CONF, and none running here either;"
  note "nothing on this host to check. That is the right answer on a box that"
  note "watches nodes elsewhere."
fi

# ------------------------------------------------------- config permissions

say "The validator token stays closed"

if [[ -n "$CONFIG_FILE" ]] && ! mode=$(stat -c '%a' "$CONFIG_FILE" 2>/dev/null); then
  # Recorded, but this account could not even stat it (#462 P1-071). `-f`
  # cannot tell "the file is gone" from "a directory above it has no
  # traversal for me", and on a native install closed by this same fix the
  # second is the ordinary case for whichever account runs this script. That
  # used to fall straight through to the "no validator token on this box"
  # note below, a false all-clear on the one host where a token is most
  # likely to be sitting open. A recorded path is never nothing to check.
  chk node-config-mode
  # Distinguished where it safely can be, guessed at nowhere else. Passwordless
  # sudo sees through any permission wall, so it settles the question outright.
  # Failing that, `-d` on the config's own directory needs traversal only on
  # ITS parent, not on the directory itself, so it can succeed even where the
  # directory that actually blocks this account is the config's own (the
  # closer's own 0750, with this account not among its named entries). If it
  # does, and this account also has traversal on that directory, resolving
  # the file inside it needs nothing more, so a stat failure from here on
  # means the file itself is gone rather than a permission wall. Without
  # either signal, the wording stays honestly unsure rather than guessing.
  cfg_dir=$(dirname "$CONFIG_FILE")
  distinguished=""
  if sudo -n true 2>/dev/null; then
    if sudo -n test -e "$CONFIG_FILE" 2>/dev/null; then
      distinguished="a directory above it has no traversal for this account; the file is there (confirmed as root)"
    else
      distinguished="the file itself is gone; there is no traversal problem to blame (confirmed as root)"
    fi
  elif [[ -d "$cfg_dir" ]]; then
    if [[ -x "$cfg_dir" ]]; then
      distinguished="the file itself is gone; this account can reach $cfg_dir and it is not there"
    else
      distinguished="$cfg_dir has no traversal for this account"
    fi
  fi
  if [[ -n "$distinguished" ]]; then
    bad "$CONFIG_FILE is recorded as this node's config, but this account could not stat it: $distinguished"
  else
    bad "$CONFIG_FILE is recorded as this node's config, but this account could not stat it"
    note "that is not the same as no token here: a directory above it may have no"
    note "traversal for this account, or the file may genuinely be gone."
  fi
  note "Confirm as root, or as the account this host installed the node with:"
  note "  sudo stat -c '%a %U:%G' $CONFIG_FILE"
  note "curl -fsSL https://get.aperire.one | bash -s -- --run node-config-exposure"
elif [[ -n "$CONFIG_FILE" ]]; then
  owner=$(stat -c '%U:%G' "$CONFIG_FILE" 2>/dev/null)
  chk node-config-mode
  if [[ "${mode: -1}" =~ [4567] ]]; then
    bad "$CONFIG_FILE is mode $mode, readable by every account on this host"
    note "curl -fsSL https://get.aperire.one | bash -s -- --run node-config-exposure"
  else
    ok "config is $mode $owner, closed to other accounts"
  fi
  # And the account that must not reach it, asked directly rather than derived.
  #
  # Which account that is comes from where close-node-config-exposure.sh takes
  # it, because the two have to be talking about the same identity: an explicit
  # APERIRE_ACCOUNT, else the User= of the installed advisord unit, else that
  # installer's default. The closed state the file is put into is owned by the
  # account that installed the node and shut to the Advisor's account, so the
  # name `aperire` written in here tested the owner, and reported a correctly
  # closed file as an exposure on every fleet host (issue #123).
  adv_account=${APERIRE_ACCOUNT:-}
  adv_from="APERIRE_ACCOUNT in the environment"
  if [[ -z "$adv_account" ]]; then
    if advisord_installed; then
      adv_account=$(systemctl show "$ADVISORD_UNIT" -p User --value 2>/dev/null)
      adv_from="User= of the $ADVISORD_UNIT unit"
      if [[ -z "$adv_account" ]]; then
        adv_account=aperire-advisor
        adv_from="the installer default, since the unit names no User="
      fi
    else
      adv_account=""
      adv_from=""
    fi
  fi
  #
  # Whether the test could run at all is established first. `sudo -n` fails
  # identically when it needs a password and when the file is genuinely
  # unreadable, so without this the check reports a reassuring "cannot read"
  # having tested nothing — the same false negative that once hid a node
  # unable to open its own config.
  if [[ -z "$adv_account" ]]; then
    note "skipped: no $ADVISORD_UNIT on this host, so there is no advisor account to test"
    note "  set APERIRE_ACCOUNT to test a named account here"
  elif ! id "$adv_account" >/dev/null 2>&1; then
    note "skipped: $adv_from names '$adv_account', and no such account exists here"
  elif ! sudo -n true 2>/dev/null; then
    note "skipped: reading as '$adv_account' needs passwordless sudo"
    note "  run it directly:  sudo -u $adv_account test -r $CONFIG_FILE && echo CAN READ"
  elif sudo -n -u "$adv_account" test -r "$CONFIG_FILE" 2>/dev/null; then
    chk node-config-closed-to-advisor
    bad "the advisor account '$adv_account' can read the validator token ($adv_from)"
    note "curl -fsSL https://get.aperire.one | bash -s -- --run node-config-exposure --apply"
  else
    chk node-config-closed-to-advisor
    ok "the advisor account '$adv_account' cannot read the validator token ($adv_from)"
  fi
elif node_seen; then
  # Counted once, above. Two reds for one missing file would read as two
  # problems, and there is one: the record. Said here anyway, because the
  # heading above this line promises a check and no check was made.
  note "not measured: a node is running here ($NODE_SEEN) and no record names"
  note "its config, so there is no file to read the mode of. The record is the"
  note "failure reported under \"The node\" above; put it back and this line"
  note "becomes a check."
elif [[ "$IS_NO_NODE_HOST" -eq 1 && -n "$NODE_INSTALLED_EVIDENCE" ]]; then
  # One red for that record, not two (F6, #570 follow-up): "The node" section
  # above already failed this run over $NODE_INSTALLED_EVIDENCE, and CONFIG_FILE
  # was normalised away with the rest of the --no-node sentinel above, so
  # there is no path here to read a mode from either.
  note "not measured: this host is recorded as running no node, but"
  note "$NODE_INSTALLED_EVIDENCE says otherwise. That disagreement is the"
  note "failure reported under \"The node\" above; put the record back and"
  note "this line becomes a check."
elif [[ "$IS_NO_NODE_HOST" -eq 1 ]]; then
  note "skipped: this host is recorded as running no node (an aggregator);"
  note "there is no validator token on a box like this to close."
else
  note "neither $CONF nor $NODE_CONF names a node config, and no node is"
  note "running here; there is no validator token on this box to close."
fi

# ------------------------------------------------------------------ endpoints

say "Endpoints"

# The dashboard's port is whatever it is listening on, not a number written
# here. A hardcoded port is how this check reports a healthy dashboard as down.
#
# Asked up to ten times, two seconds apart. Run straight after a restart the
# unit is active before the process has bound its port (the DB migration and
# the agreement seed come first), and one look reported a dashboard that was
# up two seconds later as down, twice in one day (2026-09-06, 2026-09-07).
# Twenty seconds is the wait; a dashboard that is not there by then is down.
#
# Whether the route ANSWERED and what it said are two questions, and this
# check used to ask one of them (#439). /healthz is 200 or 503 by design: 503
# means "answering, and here is what is not ok". `curl -sf` exits non-zero on
# any status at or above 400, so a dashboard reporting a node that has not
# validated a ledger yet was reported as no dashboard at all, for the seven or
# eight minutes after a reboot in which this script is the thing an operator
# runs. Same outcome as the hardcoded port above it, by a different route.
#
# So the status is read, not inferred from curl's exit, and the body decides
# what to say about a 503. One loop, no subshell, so the answer comes back
# with the port that gave it.
# Where the dashboard's port is configured, read the way install.sh's
# fleet_dash_port() reads it: the unit's own Environment=PORT, then the
# environment file the unit names, then the instance file in /etc/aperire.
# Prints the port, or nothing. Every read is unprivileged and an unreadable
# file falls through to the next source in silence.
configured_dash_port() {
  local u f p unit_file="" env_file=""
  for u in aperire-server aperire-read; do
    f="$UNIT_DIR/${u}.service"
    if [[ -r "$f" ]]; then unit_file="$f"; break; fi
  done
  if [[ -n "$unit_file" ]]; then
    p=$(awk -F= '/^Environment=PORT=/{print $3; exit}' "$unit_file" 2>/dev/null || true)
    if [[ "$p" =~ ^[0-9]+$ ]]; then printf '%s' "$p"; return 0; fi
    env_file=$(awk -F= '/^EnvironmentFile=/{sub(/^-/,"",$2); print $2; exit}' "$unit_file" 2>/dev/null || true)
  fi
  for f in "$env_file" "$DASH_ENV_FILE"; do
    [[ -n "$f" && -r "$f" ]] || continue
    p=$(awk -F= '$1=="PORT"{sub(/^[^=]*=/,""); gsub(/"/,""); print; exit}' "$f" 2>/dev/null || true)
    if [[ "$p" =~ ^[0-9]+$ ]]; then printf '%s' "$p"; return 0; fi
  done
  return 1
}

# Candidate ports, in the order they are asked. The configured port first.
# Then every loopback listener, with NO process filter: this runs as the
# operator without root, and since ADR 0024 the dashboard runs as its own
# account, so `ss -p` shows no process on its socket and a filter on "node"
# found nothing (#934). The default 7800 is last, for a host whose unit and
# env file both say nothing.
dash_candidates() {
  local cfg
  cfg=$(configured_dash_port) || cfg=""
  [[ -n "$cfg" ]] && printf '%s\n' "$cfg"
  ss -ltn 2>/dev/null | awk '/127.0.0.1:/ {split($4,a,":"); print a[length(a)]}' | sort -u
  printf '7800\n'
}

find_dash() {  # prints "port<TAB>code<TAB>body" for the first loopback answer
  local ports p body code cfg t
  cfg=$(configured_dash_port) || cfg=""
  mapfile -t ports < <(dash_candidates | awk '!seen[$0]++')
  for p in "${ports[@]}"; do
    [[ "$p" == "7810" ]] && continue           # that is advisord
    # The configured port is asked patiently. A scanned listener is only a
    # candidate, and each dead one would otherwise cost five seconds a try.
    t=2; [[ "$p" == "$cfg" ]] && t=5
    body=$(curl -s --max-time "$t" -w '\n%{http_code}' "http://127.0.0.1:$p/healthz" 2>/dev/null) || continue
    code=${body##*$'\n'}
    body=${body%$'\n'*}
    # Any other local service can answer 200 on /healthz. Only the
    # dashboard's own body names the node bridge, and a scanned port is the
    # dashboard only if it says so.
    [[ "$body" == *'"rippled_connected":'* ]] || continue
    case "$code" in
      200|503) printf '%s\t%s\t%s\n' "$p" "$code" "${body//[$'\n\t']/ }"; return 0 ;;
    esac
  done
  return 1
}
DASH_LINE=""
for _ in 1 2 3 4 5 6 7 8 9 10; do
  DASH_LINE=$(find_dash) && break
  sleep 2
done
chk dashboard-healthz
if [[ -n "${DASH_LINE:-}" ]]; then
  IFS=$'\t' read -r DASH_PORT DASH_CODE DASH_BODY <<< "$DASH_LINE"
  if [[ "$DASH_CODE" == 200 ]]; then
    ok "dashboard answers /healthz on 127.0.0.1:$DASH_PORT"
  elif [[ "$DASH_BODY" == *'"ledger_age_ms":null'* && "$DASH_BODY" == *'"rippled_connected":true'* ]]; then
    # The one 503 that is not a fault. The dashboard is up, connected to the
    # node, and the node has not validated a ledger since it restarted with
    # it: about eight minutes on a container node, measured twice on one host.
    # After a reboot that is the expected reading, and it is the line an
    # operator actually wants.
    ok "dashboard answers /healthz on 127.0.0.1:$DASH_PORT (503: connected to the node, which has not validated a ledger yet)"
    note "that is the node syncing after the restart, not the dashboard"
  else
    # Any other 503 is a dashboard saying something is wrong, and it stays a
    # failure. Accepting every 503 would trade this defect for a worse one.
    bad "dashboard answers on 127.0.0.1:$DASH_PORT and reports not ok: $DASH_BODY"
    note "curl -s http://127.0.0.1:$DASH_PORT/healthz    # the whole answer"
  fi
else
  bad "no dashboard /healthz answered on loopback"
  note "ss -ltn | grep 127.0.0.1    # what is actually listening"
fi

# The same fact, asked again rather than carried down from the section above:
# an Advisor that is not installed has no endpoint to be down. Guarded before
# chk for the reason spelled out at check_advisord.
if advisord_installed; then
  chk advisord-endpoint
  if curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:7810/v1/status 2>/dev/null | grep -qE '200|401'; then
    ok "advisord answers on 127.0.0.1:7810"
  else
    bad "advisord did not answer on 127.0.0.1:7810"
  fi
else
  note "127.0.0.1:7810 unchecked: the Advisor is not installed on this host"
fi

# ------------------------------------------------------------------ the tree

say "The working tree"

if [[ -d "$REPO/.git" ]]; then
  changes=$(cd "$REPO" && git status --porcelain 2>/dev/null | grep -v '^?? .project/screenshots/')
  if [[ -z "$changes" ]]; then
    ok "clean, everything committed before the restart"
  else
    note "$(printf '%s\n' "$changes" | wc -l) uncommitted change(s):"
    printf '%s\n' "$changes" | sed 's/^/        /'
  fi
  note "last commit: $(cd "$REPO" && git log --oneline -1)"
fi

# ------------------------------------------------------------------ report

# Written here, at the end, and never from an EXIT trap. A trap would emit a
# report for a run that died at check three, with counts that exclude
# everything it never reached — a file that reads calm because most of the
# work did not happen. A run that dies writes nothing instead, the report on
# disk keeps its old timestamp, and its age is what says so.
say "Report"
# report_as_dashboard: the report lives in data/, which belongs to the
# account the dashboard unit names in User= (ADR 0024). A run by anyone else
# (the operator, by hand, on a host where the dashboard has its own account)
# renders it privately, then hands it to that account to put in place. Only
# ever with sudo -n: this script promises it needs no root and never asks.
report_as_dashboard() {
  local da_lib priv acct
  da_lib="$(dirname "${BASH_SOURCE[0]}")/dashboard-account-lib.sh"
  [[ -r "$da_lib" ]] || return 1
  # shellcheck source=scripts/dashboard-account-lib.sh
  . "$da_lib" || return 1
  DA_NO_PROMPT=1
  da_resolve_repo "$REPO" >/dev/null 2>&1 || [[ -n "$DA_ACCOUNT" ]] || return 1
  da_switch_needed || return 1
  acct="$DA_ACCOUNT"
  priv="$(mktemp -d)" || return 1
  # The single quotes are on purpose: $1 and $$ expand in the account's shell.
  # shellcheck disable=SC2016
  if vr_write "$priv/report.json" \
     && as_dashboard sh -c 'cat > "$1.$$.tmp" && mv -f "$1.$$.tmp" "$1"' _ "$REPORT" < "$priv/report.json" 2>/dev/null; then
    rm -rf "$priv"
    REPORT_WRITTEN_AS="$acct"
    return 0
  fi
  rm -rf "$priv"
  REPORT_NEEDS="$acct"
  return 1
}
REPORT_WRITTEN_AS=""; REPORT_NEEDS=""
if vr_write "$REPORT"; then
  note "written: $REPORT"
elif report_as_dashboard; then
  note "written: $REPORT, as $REPORT_WRITTEN_AS (the dashboard's account, which owns data/)"
else
  note "could not write $REPORT (the run above is unaffected)"
  if [[ -n "$REPORT_NEEDS" ]]; then
    note "  data/ is $REPORT_NEEDS's, and sudo would not act as it without a password here."
    note "  aperire-verify.timer writes it as that account on its next run, or now with:"
    note "    sudo systemctl start aperire-verify.service"
  fi
  note "  the dashboard reads that file for verify_failed_checks; without it there is no metric"
fi

# ------------------------------------------------------------------ verdict

say "Result"
if [[ "$warned" -gt 0 ]]; then
  printf '   \033[33m%s check(s) could not be measured\033[0m, see the !! lines above.\n\n' "$warned"
fi
if [[ "$fail" -eq 0 ]]; then
  printf '   \033[32m%s checks passed. The host came back correctly.\033[0m\n\n' "$pass"
  # What this points at has to be a file the operator has. It named a working
  # document no install writes, and this line prints on every host every
  # morning from aperire-verify.timer (#473).
  printf '   Next: the health checks in the operator guide, "Health checks".\n'
  printf '   docs/OPERATIONAL-GUIDE.md\n\n'
  exit 0
fi
printf '   \033[31m%s failed\033[0m, %s passed.\n\n' "$fail" "$pass"
printf '   Everything here was green before the restart, so start with what the\n'
printf '   failing line suggests rather than with the code.\n\n'
exit 1
