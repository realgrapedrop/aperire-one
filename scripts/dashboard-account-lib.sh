# shellcheck shell=bash
# DA_UNIT, DA_ACCOUNT and DA_WHY are this library's answers, read by callers.
# shellcheck disable=SC2034
# dashboard-account-lib.sh: which account the dashboard runs as, and running a
# command as that account (ADR 0024 lane 4).
#
# The database, its WAL files and the logs under data/ belong to the
# dashboard's account. A command-line tool that opens them as anyone else
# gets it wrong both ways:
#   - as root, it follows any link that account planted at a name in data/,
#     and it leaves root-owned -wal and -shm files the dashboard then cannot
#     open;
#   - as the operator, it cannot open them at all once the dashboard runs as
#     its own account (aperire-dashboard), because data/ is 0700.
# So every such step runs AS the dashboard's account. Whatever that account
# could plant only ever leads it to what it could already write.
#
# The account is read from the dashboard unit's effective User=, through every
# drop-in, by advisor-owner-lib.sh's reader (the one #809 hardened). Never from
# SUDO_USER, the tree's owner or a fixed name: on a host installed before ADR
# 0024 that User= is the operator's own login, on a fresh install it is
# aperire-dashboard, and the unit is the one place that says which.
#
#   . "$REPO/scripts/dashboard-account-lib.sh"
#   da_resolve_unit "$UNIT_DIR/aperire-server.service" || exit
#   as_dashboard_sqlite "$DB" 'PRAGMA integrity_check'
#
# Call da_resolve_* bare, never inside $( ): they hand back DA_ACCOUNT and
# DA_UNIT as globals, and a subshell would drop both.
#
# Pass as_dashboard absolute paths only. When it switches account it runs the
# command from /, because the caller's working directory may be one that
# account cannot enter.

DA_UNIT_DIR=/etc/systemd/system
# The update grant's record of the same account (lane C splits update.conf's
# OPERATOR= into OPERATOR, the tree's owner, and DASH_USER, the unit's
# account). It is a copy of the unit's User=, taken when the grant was last
# installed, and only hosts with that grant have it. So the unit stays the
# answer, the copy is checked against it and a disagreement is said out
# loud, and it is the answer only where no unit serves the checkout.
DA_UPDATE_CONF=/etc/aperire/update.conf

if ! declare -F advisor_owner_effective_property >/dev/null 2>&1; then
  if [[ ! -r "$(dirname "${BASH_SOURCE[0]}")/advisor-owner-lib.sh" ]]; then
    echo "error: $(dirname "${BASH_SOURCE[0]}")/advisor-owner-lib.sh is missing from this checkout. Nothing was changed." >&2
    return 1
  fi
  # shellcheck source=scripts/advisor-owner-lib.sh
  . "$(dirname "${BASH_SOURCE[0]}")/advisor-owner-lib.sh"
fi

DA_ACCOUNT=""
DA_UNIT=""
DA_WHY=""
# Set DA_NO_PROMPT=1 in a caller that must never ask for a password (a
# verifier that promises it needs no root): as_dashboard then only ever uses
# sudo -n, and fails rather than prompts.
DA_NO_PROMPT="${DA_NO_PROMPT:-0}"
# The PATH a command switched to the account runs with, from root.
DA_PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# da_account_of_unit <unit-path>: the account that unit runs as. Prints it and
# returns 0. root when its effective User= is root, 0, or an empty assignment
# (systemd's own reset). Returns 1, printing nothing, when there is no such
# file. Returns 3 when the file is there and no User= can be read out of it:
# the installers always write one, so that is a unit this does not
# understand, and guessing root would put root back in data/.
da_account_of_unit() {
  local unit="$1" eff
  [[ -e "$unit" || -L "$unit" ]] || return 1
  [[ -r "$unit" ]] || return 3
  eff="$(advisor_owner_effective_property "$unit" User)" || return 3
  [[ -n "$eff" && "$eff" != 0 ]] || eff=root
  printf '%s' "$eff"
}

# _da_conf_dash_user: update.conf's DASH_USER, or nothing.
_da_conf_dash_user() {
  [[ -r "$DA_UPDATE_CONF" ]] || return 0
  awk -F= '$1=="DASH_USER"{sub(/^[^=]*=/,""); print; exit}' "$DA_UPDATE_CONF" 2>/dev/null
}

# da_resolve_unit <unit-path>: sets DA_UNIT and DA_ACCOUNT from that unit.
# Same return codes as da_account_of_unit, with DA_WHY holding the sentence
# a caller refuses with.
da_resolve_unit() {
  local unit="$1" acct rc
  DA_UNIT=""; DA_ACCOUNT=""; DA_WHY=""
  acct="$(da_account_of_unit "$unit")"; rc=$?
  case $rc in
    0) DA_UNIT="$unit"; DA_ACCOUNT="$acct"
       local conf_user
       conf_user="$(_da_conf_dash_user)"
       if [[ -n "$conf_user" && "$conf_user" != "$acct" ]]; then
         printf 'note: %s says the dashboard runs as %s, and its unit (%s) says %s. Going by the unit, which is what systemd runs. Re-run install-update-grant.sh to bring the record up to date.\n' \
           "$DA_UPDATE_CONF" "$conf_user" "$unit" "$acct" >&2
       fi
       return 0 ;;
    1) DA_WHY="there is no dashboard unit at $unit"; return 1 ;;
    *) DA_WHY="could not read which account the dashboard runs as from $unit: no User= line under [Service] there or in its drop-ins, or the file cannot be read. Nothing was changed. Check it with: systemctl cat $(basename "$unit" .service)"
       return 3 ;;
  esac
}

# da_resolve_repo <repo-dir>: the dashboard unit whose WorkingDirectory is
# <repo-dir>/dashboard (aperire-server or aperire-read, any instance suffix),
# matched on real paths, the same rule aperire-backup-set.sh's
# bkset_this_instance uses. Then as da_resolve_unit.
#
# No unit at all is return 1. That is a dashboard run by hand or under pm2,
# where the account that owns data/ is the only answer there is, so DA_ACCOUNT
# is set to it and the caller may go on. More than one unit is return 2,
# because a checkout served by two units has no single owner to pick.
da_resolve_repo() {
  local repo="$1" here f wd there matches=() owner
  DA_UNIT=""; DA_ACCOUNT=""; DA_WHY=""
  here="$(cd "$repo" 2>/dev/null && pwd -P)" || { DA_WHY="no such directory: $repo"; return 1; }
  for f in "$DA_UNIT_DIR"/aperire-server.service "$DA_UNIT_DIR"/aperire-server-*.service \
           "$DA_UNIT_DIR"/aperire-read.service "$DA_UNIT_DIR"/aperire-read-*.service; do
    [[ -e "$f" ]] || continue
    wd="$(advisor_owner_effective_property "$f" WorkingDirectory 2>/dev/null)" || continue
    [[ "$(basename "$wd")" == dashboard ]] || continue
    there="$(cd "$(dirname "$wd")" 2>/dev/null && pwd -P)" || continue
    [[ "$there" == "$here" ]] && matches+=("$f")
  done
  if [[ ${#matches[@]} -gt 1 ]]; then
    DA_WHY="more than one dashboard unit serves $here: ${matches[*]}"
    return 2
  fi
  if [[ ${#matches[@]} -eq 1 ]]; then
    da_resolve_unit "${matches[0]}"
    return $?
  fi
  owner="$(_da_conf_dash_user)"
  if [[ -n "$owner" ]] && getent passwd "$owner" >/dev/null 2>&1; then
    DA_ACCOUNT="$owner"
    DA_WHY="no dashboard unit serves $here, so the account $DA_UPDATE_CONF records ($owner) is taken"
    return 1
  fi
  owner="$(stat -c '%U' "$here/data" 2>/dev/null || true)"
  if [[ -n "$owner" && "$owner" != UNKNOWN ]]; then
    DA_ACCOUNT="$owner"
    DA_WHY="no dashboard unit serves $here, so the owner of its data/ ($owner) is taken"
  else
    DA_WHY="no dashboard unit serves $here, and it has no data/ to read an owner from"
  fi
  return 1
}

# This process's uid from id(1) at a fixed path, never one a PATH finds, the
# rule the digest and trusted-path libraries hold to (#1109).
da_uid() { /usr/bin/id -u 2>/dev/null || /bin/id -u 2>/dev/null; }

# da_switch_needed: true when running as DA_ACCOUNT takes an account switch.
# By name, never by uid: two names can share a uid on a test rig, and the
# name is what the unit says.
da_switch_needed() {
  [[ "$(id -un 2>/dev/null)" != "$DA_ACCOUNT" ]]
}

# da_sudo_ready [why]: for a caller that is neither root nor the dashboard's
# account, make sure sudo will let it switch, before the first step needs it.
# On a terminal it says why in one line and asks for the password once (sudo
# keeps it for the rest of the run). Without one it never prompts: sudo -n,
# and a refusal that names the account and the command to run instead.
# Returns 0 when as_dashboard can proceed.
da_sudo_ready() {
  local why="${1:-}"
  [[ -n "$why" ]] || why="this reads and writes the database the dashboard owns"
  [[ -n "$DA_ACCOUNT" ]] || { echo "error: no dashboard account resolved${DA_WHY:+: $DA_WHY}" >&2; return 1; }
  da_switch_needed || return 0
  [[ "$(da_uid)" == 0 ]] && return 0
  if sudo -n -u "$DA_ACCOUNT" -- true >/dev/null 2>&1; then return 0; fi
  if [[ -t 0 && -t 2 ]]; then
    printf 'sudo: acting as %s, the dashboard'"'"'s account, because %s.\n' "$DA_ACCOUNT" "$why" >&2
    sudo -v && return 0
  fi
  printf 'error: this needs to act as %s, the dashboard'"'"'s account, and sudo would not allow it without a password here.\n' "$DA_ACCOUNT" >&2
  printf '       Run it again from a terminal, or with: sudo -u %s %s\n' "$DA_ACCOUNT" "$0" >&2
  return 1
}

# _da_switch_works: can this caller become DA_ACCOUNT right now, without a
# prompt? Asked with `true`, so the answer is about the switch alone and never
# about a command. Root asks runuser (an account that is not there fails);
# anyone else asks sudo -n, which never prompts.
_da_switch_works() {
  if [[ "$(da_uid)" == 0 ]]; then
    ( cd / && runuser -u "$DA_ACCOUNT" -- env -i PATH="$DA_PATH" true ) >/dev/null 2>&1
  else
    ( cd / && sudo -n -u "$DA_ACCOUNT" -- true ) >/dev/null 2>&1
  fi
}

# as_dashboard <command...>: run it as DA_ACCOUNT.
#   - already that account: run it directly;
#   - root: runuser, which never prompts and needs no sudo rule;
#   - anyone else: sudo -u. On a terminal, unless DA_NO_PROMPT=1, sudo may
#     ask once, after a one-line why (see da_sudo_ready); otherwise sudo -n.
#
# The exit status is the command's own, or 125 when the switch itself was
# refused, so nothing ran. That has to be its own code: sudo and runuser
# refuse with 1, the same 1 as grep finding no match or test answering
# false, and a caller reading a refusal as "no" acts on an answer nobody
# gave (#873 review, M1). So the switch is asked first, on its own, and a
# command that exits 1 has the switch asked again: a 1 from a switch that no
# longer works (a sudo timestamp that ran out mid-run) is 125, not "no".
# 125 is also what comes back when no account was resolved. A caller treats
# 125 as a failure to say out loud, never as an answer.
as_dashboard() {
  local rc
  [[ -n "$DA_ACCOUNT" ]] || { echo "as_dashboard: no dashboard account resolved${DA_WHY:+ ($DA_WHY)}" >&2; return 125; }
  if ! da_switch_needed; then
    "$@"
    return
  fi
  if ! _da_switch_works; then
    if [[ "$(da_uid)" != 0 && -t 0 && -t 2 && "$DA_NO_PROMPT" != 1 ]]; then
      da_sudo_ready "" >&2 || true
    fi
    if ! _da_switch_works; then
      printf 'error: could not act as %s, the account the dashboard runs as, so nothing was run as it (%s).\n' \
        "$DA_ACCOUNT" "$( [[ "$(da_uid)" == 0 ]] && echo "runuser refused" || echo "sudo would not allow it without a password here" )" >&2
      return 125
    fi
  fi
  if [[ "$(da_uid)" == 0 ]]; then
    # runuser -u keeps all of root's environment but HOME, SHELL, USER and
    # LOGNAME. The command runs with a fixed PATH and nothing else, the way
    # the sudo branch's env_reset already gives it (#875 review, M1).
    ( cd / && runuser -u "$DA_ACCOUNT" -- env -i PATH="$DA_PATH" "$@" ); rc=$?
  else
    ( cd / && sudo -n -u "$DA_ACCOUNT" -- "$@" ); rc=$?
  fi
  if [[ $rc -eq 1 ]] && ! _da_switch_works; then
    printf 'error: the switch to %s stopped working mid-run, so that step did not run as it.\n' "$DA_ACCOUNT" >&2
    return 125
  fi
  return $rc
}

# as_dashboard_sqlite <sqlite3 args...>: sqlite3 on the dashboard's database,
# as its account, never reading an rc file. The sqlite3 shell reads
# ~/.sqliterc from the passwd home of the account it runs as, whatever HOME
# says, and that file decides what a query prints. On a host installed
# before ADR 0024 that home is the operator's login, which the dashboard
# account can write. `-init /dev/null` reads nothing instead (#875 review,
# M1). Every sqlite3 call made through this lib goes through here, so no
# call site can forget the flag.
#
# What it prints is still the account's to shape (the database is its own),
# so a caller doing arithmetic on it checks ^[0-9]+$ first: bash evaluates
# the operands of -gt and friends as expressions, and an array subscript in
# one runs a command.
as_dashboard_sqlite() {
  as_dashboard sqlite3 -init /dev/null "$@"
}

# da_is_count <value>: true for a plain non-negative integer, the only shape
# a caller may hand to [[ -gt ]] or $(( )).
da_is_count() {
  [[ "${1:-}" =~ ^[0-9]+$ ]]
}
