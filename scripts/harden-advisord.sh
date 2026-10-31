#!/usr/bin/env bash
# Apply the hardened systemd unit to a running aperire-advisord, verify the
# service still works through the tighter sandbox, and put the old unit back
# automatically if it does not.
#
# READ THIS BEFORE RUNNING IT. This is a retrofit, not a step of a normal
# install. install-advisord.sh writes the hardened unit itself now
# (ProtectSystem=strict, an empty capability set and a syscall filter), so on
# any host installed with it there is nothing here to apply. What is left is
# the older case: a unit still on ProtectSystem=full, which leaves /home
# writable, so the service could rewrite the privilege wrapper and the
# credential store that authorises every approval.
#
# It refuses outright once install-advisor-account.sh has run. That installer
# owns the unit from then on: it carries the dedicated account and the
# --wrapper-socket flag (ADR 0025), and the unit written below would take
# both away and leave the Advisor unable to reach the node.
#
# The risk being managed: ProtectSystem=strict makes the whole filesystem
# read-only apart from ReadWritePaths, and the wrapper needs the Docker
# socket. That is exactly why this script tests rather than assumes, and
# reverts rather than leaving you to discover it during an upgrade.
#
#   curl -fsSL https://get.aperire.one | bash -s -- --run harden-advisord
#
# Re-runnable. Changes nothing on the validator itself.

set -euo pipefail

SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# The install: the one APERIRE_INSTALL_TREE names when root runs a copy the
# bootstrap staged out of the release (curl ... | bash -s -- --run
# harden-advisord), else this checkout. What it loads comes from beside it,
# never by the install's path (#955).
REPO="${APERIRE_INSTALL_TREE:-$(cd "$SELF/.." && pwd)}"
UNIT=/etc/systemd/system/aperire-advisord.service
BACKUP="/etc/systemd/system/aperire-advisord.service.before-hardening"
TOKEN="$REPO/advisor/state/approve.token"

[[ -r "$SELF/advisord-restart-lib.sh" ]] \
  || { echo "error: $SELF/advisord-restart-lib.sh is missing beside this program" >&2; exit 1; }
# shellcheck source=scripts/advisord-restart-lib.sh
. "$SELF/advisord-restart-lib.sh"

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
info() { printf '   %s\n' "$*"; }
die()  { printf '\n\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "run with sudo — this rewrites a systemd unit"
[[ -f "$UNIT" ]]  || die "$UNIT not found; run scripts/install-advisord.sh first"
[[ -r "$TOKEN" ]] || die "no approval token at $TOKEN; the checks below need it"

RUN_USER=$(awk -F= '/^User=/{print $2}' "$UNIT" | head -1)
RUN_GROUP=$(awk -F= '/^Group=/{print $2}' "$UNIT" | head -1)
CREDS=$(grep -E '^LoadCredential' "$UNIT" || true)
[[ -n "$RUN_USER" ]] || die "could not read User= from $UNIT"

# Refuse after the dedicated-account move, for the reason in the header. Two
# checks, and they are not equally certain, so they do not share a message.
LOGIN_USER="${SUDO_USER:-$(id -un)}"
HANDS_OFF="install-advisor-account.sh owns this unit, and the one written here
   would strip the account and the wrapper socket, leaving the Advisor unable
   to reach the node. Nothing was changed. To upgrade the
   Advisor, run the update, which rebuilds it and keeps the unit that is here:
     curl -fsSL https://get.aperire.one | bash -s -- --update --force"
# The marker is the definite signal: only install-advisor-account.sh writes it.
if [[ -f "${UNIT}.before-account" ]]; then
  die "the Advisor has already been moved onto its own account ($RUN_USER).
   $HANDS_OFF"
fi
# The User= check is the fallback, and it says what it OBSERVED rather than
# what it concluded. It can fire without the move having happened at all: a
# root shell with no SUDO_USER compares "root" against an operator's login
# account and disagrees. Naming the marker gives the operator the way past it.
if [[ "$RUN_USER" != "$LOGIN_USER" ]]; then
  die "this unit runs as $RUN_USER, and you are $LOGIN_USER.
   If the Advisor was moved onto its own account, $HANDS_OFF
   If it was not, ${UNIT}.before-account does not exist and you are running
   this as the wrong user; re-run it with sudo from that account."
fi

# Reuse the command line and the writable paths the installer worked out, do
# not rebuild them. The rebuilt form used to hardcode --addr=127.0.0.1:7810
# and carried neither --container nor --dash-read-url, so running this on a
# second instance pointed its Advisor at the FIRST instance's dashboard, which
# is the exact failure install-advisord.sh's own comments record from
# 2026-08-14.
EXEC_START=$(grep -E '^ExecStart=' "$UNIT" | head -1 || true)
[[ -n "$EXEC_START" ]] || die "could not read ExecStart= from $UNIT"
RW_PATHS=$(grep -E '^ReadWritePaths=' "$UNIT" | head -1 || true)
[[ -n "$RW_PATHS" ]] || RW_PATHS="ReadWritePaths=$REPO/advisor/state $REPO/advisor/evidence"
# advisor/knowledge-fleet is added if the unit predates it (ADR 0017): an
# accepted knowledge bundle is applied by swapping that directory, and under
# ProtectSystem=strict a unit without it refuses every push with a read-only
# filesystem error that reads as a broken aggregator. Appended rather than
# rebuilt, so everything else the installer worked out is kept. Decided below,
# after the corpus is made, because it is named only when it is there.
# /var/lib/aperire, for the same reason and with the same history. The
# WRAPPER writes there as root, through sudo, as a child of this unit, and a
# namespace applies to children: the record that a container image was
# checked on this host, and any release package kept for a rollback, both
# land there. A unit without it stops an official-image upgrade at the
# verify step with "Read-only file system" (lab node, 2026-09-28). Made
# before it is named, because ReadWritePaths on a missing path takes the
# unit down with 226/NAMESPACE.
WRAPPER_STATE=/var/lib/aperire
if [[ "$RW_PATHS" != *" $WRAPPER_STATE"* ]]; then
  RW_PATHS="$RW_PATHS $WRAPPER_STATE"
fi
if [[ ! -d "$WRAPPER_STATE" ]]; then
  install -d -m 0755 -o root -g root "$WRAPPER_STATE" 2>/dev/null \
    || mkdir -p "$WRAPPER_STATE" 2>/dev/null \
    || printf 'warning: could not create %s; the unit names it writable and will not start without it\n' "$WRAPPER_STATE" >&2
fi
# Created at the same 0750 baseline the two installers that share this corpus
# start from, and only when absent: `install -d` re-modes an existing
# directory, which would take back the group write and the setgid bit that
# let the dashboard promote into it (scripts/fleet-corpus-perms.sh). Created
# by state-file.py with --mode-if-new, which never follows a link at a name and
# never re-modes a directory that is already there (#1048).
for _d in "$REPO/advisor/knowledge-fleet" "$REPO/advisor/knowledge-fleet/base" \
          "$REPO/advisor/knowledge-fleet/local"; do
  python3 -I "$SELF/state-file.py" mkdir "$_d" "" "" 0750 --root "$REPO/advisor" --mode-if-new \
    || echo "   !! $_d was not made or confirmed (named above); it was left as it was" >&2
done
# Named only when it is a real directory now (#1310). The helper above
# refuses a link at the name and leaves it, and ReadWritePaths= on a path
# that is not there fails the unit with 226/NAMESPACE: an Advisor that cannot
# take a knowledge push yet is better than one that does not start. An entry
# the unit already had goes too when the directory is not there.
KF="$REPO/advisor/knowledge-fleet"
if [[ -d "$KF" && ! -L "$KF" ]]; then
  [[ "$RW_PATHS" == *"/advisor/knowledge-fleet"* ]] || RW_PATHS="$RW_PATHS $KF"
else
  read -ra _rw <<<"${RW_PATHS#ReadWritePaths=}"
  _keep=()
  for _e in "${_rw[@]}"; do
    [[ "${_e#-}" == */advisor/knowledge-fleet ]] || _keep+=("$_e")
  done
  RW_PATHS="ReadWritePaths=${_keep[*]}"
  echo "   !! $KF is not a directory, so the unit does not name it; a knowledge push cannot land until it is" >&2
fi
# By descriptor, not `chown -R` by name (#1048): both services write this
# corpus, and chown -R changes a hard link to a file outside it like any other
# entry, so either account could have handed root a second name for a file and
# had it given to RUN_USER. find lists; state-file.py walks each name O_NOFOLLOW
# and refuses, and names, a link or a hard link. --root is advisor/, so the
# corpus itself is never judged as an ancestor. Never fatal, as before.
_run_uid="$(id -u "$RUN_USER" 2>/dev/null || true)"
if [[ "$_run_uid" =~ ^[0-9]+$ ]] && command -v python3 >/dev/null 2>&1; then
  find "$REPO/advisor/knowledge-fleet" -print0 2>/dev/null \
    | python3 -I "$SELF/state-file.py" own-many "$_run_uid" "" "" --root "$REPO/advisor" \
    || echo "   !! some of the fleet corpus was left as it was (named above)" >&2
fi
# The checks at the bottom have to ask the address this unit actually listens
# on. A second instance is on 7910, and a hardcoded 7810 would either time out
# or, worse, answer from the other instance and pass.
ADDR=$(sed -n 's/.*--addr=\([^ ]*\).*/\1/p' <<<"$EXEC_START")
ADDR=${ADDR:-127.0.0.1:7810}

say "Backing up the current unit"
cp -a "$UNIT" "$BACKUP"
info "$BACKUP"

say "Writing the hardened unit"
{
  printf '[Unit]\n'
  printf 'Description=Aperire Advisor (read-only state service)\n'
  printf 'After=network-online.target\nWants=network-online.target\n\n'
  printf '[Service]\n'
  if [[ -n "$CREDS" ]]; then printf '%s\n' "$CREDS"; fi
  printf 'Type=simple\n'
  printf 'User=%s\nGroup=%s\n' "$RUN_USER" "$RUN_GROUP"
  printf 'WorkingDirectory=%s/advisor\n' "$REPO"
  printf '%s\n' "$EXEC_START"
  printf 'Restart=always\nRestartSec=3\n'
  # The service drains on SIGTERM — it finishes the questions already running,
  # up to 60 seconds. This must stay LARGER than that window, or systemd
  # SIGKILLs through the drain and the answer is lost anyway.
  printf 'TimeoutStopSec=75\n\n'
  printf 'NoNewPrivileges=true\n'
  printf 'PrivateTmp=true\n'
  # 0027: files 0640, directories 0750. Without it the service creates
  # world-readable files by default, and what this one creates is the audit
  # ledger, the run transcripts and the credential store. systemd-analyze
  # flags the omission by name.
  printf 'UMask=0027\n'
  printf 'ProtectSystem=strict\n'
  printf 'ProtectHome=read-only\n'
  printf '%s\n' "$RW_PATHS"
  printf 'ProtectKernelTunables=true\n'
  printf 'ProtectKernelModules=true\n'
  printf 'ProtectKernelLogs=true\n'
  printf 'ProtectControlGroups=true\n'
  printf 'ProtectClock=true\n'
  printf 'RestrictSUIDSGID=true\n'
  printf 'RestrictNamespaces=true\n'
  printf 'LockPersonality=true\n'
  printf 'CapabilityBoundingSet=\n'
  printf 'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\n'
  printf 'SystemCallArchitectures=native\n'
  printf 'SystemCallFilter=@system-service\n'
  printf 'SystemCallFilter=~@privileged @resources\n'
  # setrlimit (@resources) is called by the Go runtime before main() to raise
  # RLIMIT_NOFILE; chown (@privileged) sets the group on generated tokens so
  # the dashboard can read them. Both are killed with SIGSYS when denied, so
  # the service dies at startup with nothing in its own log.
  printf 'SystemCallFilter=setrlimit prlimit64 chown fchown fchownat lchown\n\n'
  printf '[Install]\nWantedBy=multi-user.target\n'
} > "$UNIT"
chmod 644 "$UNIT"

revert() {
  printf '\n\033[1;31m== Reverting\033[0m\n'
  cp -a "$BACKUP" "$UNIT"
  systemctl daemon-reload
  advisord_reset_and_restart aperire-advisord || true
  command sleep 3
  if systemctl is-active --quiet aperire-advisord; then
    info "the previous unit is back and the service is running."
  else
    info "the previous unit is back but the service is NOT running — check:"
    info "  journalctl -u aperire-advisord -n 40 --no-pager"
  fi
  die "$1"
}

say "Restarting"
systemctl daemon-reload
advisord_reset_and_restart aperire-advisord
command sleep 4

# ── Verification. Each check answers one question the sandbox could break. ──
# Read through the helper (#703). This script refuses to run as anything but
# root, and $TOKEN lives in a directory the Advisor's own account owns, so a
# plain redirect here is root following that account's link and sending the
# first line of whatever it finds out as a bearer token on the check below.
# The installed helper, a constant: this is root, and a variable set in a root
# shell the login started must not choose the program root runs (#1148).
_ha_tool=/usr/local/sbin/aperire-state-file
[[ -f "$_ha_tool" ]] || _ha_tool="$SELF/state-file.py"
TOK=$(python3 -I "$_ha_tool" read "$TOKEN" | tr -d '\n')
# The token reaches curl on its standard input (-H @-), never on its argv,
# where any account on the host can read it in /proc (#705).
code() { curl -s -o /dev/null -w '%{http_code}' -H @- "$@" <<<"authorization: Bearer $TOK"; }

systemctl is-active --quiet aperire-advisord \
  || revert "the service did not come back up under the hardened unit"
info "service is running"

[[ "$(code "http://$ADDR/v1/status")" == "200" ]] \
  || revert "the service is up but /v1/status did not answer"
info "answers on loopback"

# The important one. /v1/check reads the deployment via `docker inspect`, so a
# 200 with a profile proves the Docker socket is still reachable through
# ProtectSystem=strict — the single most likely thing to break here.
PROFILE=$(curl -s -H @- "http://$ADDR/v1/check" <<<"authorization: Bearer $TOK" \
  | python3 -I -c 'import sys,json;d=json.load(sys.stdin);print((d.get("profile") or {}).get("container",""))' 2>/dev/null || true)
[[ -n "$PROFILE" ]] \
  || revert "the service can no longer read the deployment — the Docker socket is not reachable through the sandbox"
info "can still read the deployment through Docker ($PROFILE)"

# Writes: state/ must stay writable or nothing can be approved or recorded.
[[ "$(curl -s -o /dev/null -w '%{http_code}' -X POST -H @- \
      "http://$ADDR/v1/evidence" <<<"authorization: Bearer $TOK")" == "200" ]] \
  || revert "the service can no longer write its own state directory"
info "can still write advisor/state"

say "Confirming what it can no longer do"
f="$REPO/advisor/state/../persona.md"
if runuser -u "$RUN_USER" -- test -w "$f" 2>/dev/null; then
  info "note: $(basename "$f") is writable by $RUN_USER OUTSIDE the sandbox"
  info "      (that is expected — the unit constrains the service, not the login user)"
fi
# The wrapper is not in that class (ADR 0024). The unit names a root-owned
# copy outside the tree, and nothing the service runs as may be able to write
# it, sandbox or not: install-node-wrapper.sh places it so.
WRAPPER_NAMED="$(grep -o -- '--wrapper=[^ ]*' "$UNIT" | head -1 | cut -d= -f2-)"
if [[ -n "$WRAPPER_NAMED" ]] && runuser -u "$RUN_USER" -- test -w "$WRAPPER_NAMED" 2>/dev/null; then
  info "WARNING: $WRAPPER_NAMED, the wrapper this unit names, is writable by $RUN_USER."
  info "         Place the root-owned copy and point the unit at it:"
  info "           curl -fsSL https://get.aperire.one | bash -s -- --update --force"
fi
info "inside the unit, everything outside state/ and evidence/ is read-only"

say "Done"
info "hardened unit in place; previous one kept at:"
info "  $BACKUP"
info "to undo by hand:"
info "  sudo cp -a $BACKUP $UNIT && sudo systemctl daemon-reload && sudo systemctl restart aperire-advisord"
echo
systemd-analyze security aperire-advisord --no-pager 2>/dev/null | tail -3 || true
