#!/usr/bin/env bash
# Every row hands run() a snippet in single quotes on purpose: it expands in
# the shell that sourced the lib, not here.
# shellcheck disable=SC2016
# What scripts/dashboard-account-lib.sh promises (ADR 0024 lane 4): the account
# is the dashboard unit's effective User=, whatever that names, and
# as_dashboard runs a command as it by the right route.
#
#   bash scripts/test-dashboard-account-lib.sh
#
# Runs as the account already running it, in a temporary directory: no root,
# no real units. sudo, runuser and id are fakes on PATH ahead of the real
# ones. sudo and runuser log who they were asked to switch to and where they
# ran, then run the command as this suite. id answers as root only when a row
# asks it to (FAKE_ROOT=1), so the root branch can be driven without root.
set -uo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIB_SRC="$REPO_DIR/scripts/dashboard-account-lib.sh"
OWNER_LIB_SRC="$REPO_DIR/scripts/advisor-owner-lib.sh"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

PASS=0 FAIL=0
ok()  { printf '  ok    %s\n' "$1"; PASS=$((PASS + 1)); }
bad() { printf '  FAIL  %s\n     %s\n' "$1" "${2:-}"; FAIL=$((FAIL + 1)); }
is()  { if [[ "$2" == "$3" ]]; then ok "$1"; else bad "$1" "got: [$2] | want: [$3]"; fi; }
has() { if [[ "$2" == *"$3"* ]]; then ok "$1"; else bad "$1" "got: $2 | want substring: $3"; fi; }

ME="$(id -un)"
# A CI runner may run this as root. Then the switch to another account is
# runuser, as it is for every root caller, and a sudo-only row is skipped.
IS_ROOT=0; [[ "$(id -u)" == 0 ]] && IS_ROOT=1
UNITS="$TMP/units"
mkdir -p "$UNITS" "$TMP/lib/scripts" "$TMP/bin"

# The lib under test, its unit directory pointed into the fixture. The same
# rewrite every suite that sources it makes; refused loudly if the line moved.
DA_TEST_UPDATE_CONF="$TMP/update.conf"
sed -e "s#^DA_UNIT_DIR=/etc/systemd/system\$#DA_UNIT_DIR=${UNITS}#" -e "s#^DA_UPDATE_CONF=/etc/aperire/update.conf\$#DA_UPDATE_CONF=${DA_TEST_UPDATE_CONF:-/nonexistent/update.conf}#" "$LIB_SRC" > "$TMP/lib/scripts/dashboard-account-lib.sh"
grep -q "^DA_UNIT_DIR=${UNITS}\$" "$TMP/lib/scripts/dashboard-account-lib.sh" \
  || { echo "DA_UNIT_DIR rewrite did not land; the assignment line moved in $LIB_SRC" >&2; exit 1; }
grep -q "^DA_UPDATE_CONF=$TMP/update.conf\$" "$TMP/lib/scripts/dashboard-account-lib.sh" \
  || { echo "DA_UPDATE_CONF rewrite did not land; the assignment line moved in $LIB_SRC" >&2; exit 1; }
cp "$OWNER_LIB_SRC" "$TMP/lib/scripts/advisor-owner-lib.sh"

export SWITCH_LOG="$TMP/switch.log"
for prog in sudo runuser; do
  cat > "$TMP/bin/$prog" <<EOF
#!/usr/bin/env bash
who="" flags=""
while [[ \$# -gt 0 ]]; do
  case "\$1" in
    -u) who="\$2"; shift 2 ;;
    -n) flags="\$flags -n"; shift ;;
    -v) printf '%s -v\n' "$prog" >> "\$SWITCH_LOG"; exit 0 ;;
    --) shift; break ;;
    -*) shift ;;
    *) break ;;
  esac
done
logcmd="\$*"; [[ "\${1:-}" == env && "\${2:-}" == -i ]] && logcmd="\${*:4}"
printf '%s%s :: %s :: cwd=%s :: %s\n' "$prog" "\$flags" "\$who" "\$PWD" "\$logcmd" >> "\$SWITCH_LOG"
# A sudo -n probe before anything runs: refused when the row says sudo would
# want a password.
if [[ "$prog" == sudo && -n "\${FAKE_SUDO_NEEDS_PASSWORD:-}" && "\$flags" == *-n* ]]; then exit 1; fi
exec "\$@"
EOF
  chmod +x "$TMP/bin/$prog"
done
cat > "$TMP/bin/id" <<'EOF'
#!/usr/bin/env bash
if [[ -n "${FAKE_ROOT:-}" && $# -eq 1 ]]; then
  case "$1" in -u) echo 0; exit 0 ;; -un) echo root; exit 0 ;; esac
fi
exec /usr/bin/id "$@"
EOF
chmod +x "$TMP/bin/id"
export PATH="$TMP/bin:$PATH"

unit() {  # <name> <body...>  one line per argument
  local name=$1; shift
  printf '%s\n' "$@" > "$UNITS/$name.service"
}

# Each row runs in its own shell, so a global the lib sets in one row cannot
# leak into the next.
run() {  # <bash snippet>; the lib is sourced first
  : > "$SWITCH_LOG"
  bash -c '. "$1/scripts/dashboard-account-lib.sh"; shift; eval "$1"' _ "$TMP/lib" "$1" </dev/null 2>&1
}

echo "1. the pre-ADR shape: the unit names the operator's own login"
unit aperire-server "[Service]" "WorkingDirectory=$TMP/repo/dashboard" "User=$ME"
out="$(run 'da_resolve_unit "$DA_UNIT_DIR/aperire-server.service"; echo "rc=$? acct=$DA_ACCOUNT"; as_dashboard id -un')"
has "it resolves to the login" "$out" "rc=0 acct=$ME"
has "the command runs" "$out" "$ME"
is "  directly, with no account switch" "$(cat "$SWITCH_LOG")" ""

echo
echo "2. the fresh-install shape: the unit names aperire-dashboard"
unit aperire-server "[Service]" "User=aperire-dashboard"
out="$(run 'da_resolve_unit "$DA_UNIT_DIR/aperire-server.service"; echo "rc=$? acct=$DA_ACCOUNT"; as_dashboard true; echo "cmd-rc=$?"')"
has "it resolves to aperire-dashboard" "$out" "rc=0 acct=aperire-dashboard"
has "  and the command ran" "$out" "cmd-rc=0"
if [[ $IS_ROOT -eq 1 ]]; then
  has "a root caller switches through runuser, to that account" "$(cat "$SWITCH_LOG")" "runuser :: aperire-dashboard :: cwd=/ :: true"
else
  has "an operator caller switches through sudo, to that account" "$(cat "$SWITCH_LOG")" "sudo -n :: aperire-dashboard :: cwd=/ :: true"
fi

echo
echo "3. the same unit, called as root: runuser, never sudo"
# The library asks /usr/bin/id for its uid, a path no fake on PATH can answer
# (#1109), so the root caller is stated by replacing the one function that asks.
out="$(FAKE_ROOT=1 run 'da_uid() { echo 0; }; da_resolve_unit "$DA_UNIT_DIR/aperire-server.service"; as_dashboard true; echo "cmd-rc=$?"')"
has "the command ran" "$out" "cmd-rc=0"
has "through runuser, to aperire-dashboard, from /" "$(cat "$SWITCH_LOG")" "runuser :: aperire-dashboard :: cwd=/ :: true"
if grep -q '^sudo' "$SWITCH_LOG"; then bad "  and sudo was not used" "$(cat "$SWITCH_LOG")"; else ok "  and sudo was not used"; fi

echo
echo "4. a drop-in that changes User= wins over the unit body (#809's reader)"
unit aperire-server "[Service]" "User=$ME"
mkdir -p "$UNITS/aperire-server.service.d"
printf '[Service]\nUser=aperire-dashboard\n' > "$UNITS/aperire-server.service.d/50-account.conf"
out="$(run 'da_resolve_unit "$DA_UNIT_DIR/aperire-server.service"; echo "acct=$DA_ACCOUNT"')"
has "the drop-in's account" "$out" "acct=aperire-dashboard"
rm -rf "$UNITS/aperire-server.service.d"

echo
echo "5. a User= under [Install] is not one systemd applies"
unit aperire-server "[Service]" "ExecStart=/bin/true" "[Install]" "User=$ME"
out="$(run 'da_resolve_unit "$DA_UNIT_DIR/aperire-server.service"; echo "rc=$? acct=[$DA_ACCOUNT]"; as_dashboard echo RAN; echo "cmd-rc=$?"')"
has "refused, rc 3, no account" "$out" "rc=3 acct=[]"
has "  named in words" "$out" "could not read which account the dashboard runs as"
has "as_dashboard runs nothing and says why" "$out" "cmd-rc=125"
if [[ "$out" == *RAN* ]]; then bad "  the command did not run" "$out"; else ok "  the command did not run"; fi

echo
echo "6. an empty User= is systemd's own reset to root, and is read as root"
unit aperire-server "[Service]" "User="
out="$(run 'da_resolve_unit "$DA_UNIT_DIR/aperire-server.service"; echo "rc=$? acct=$DA_ACCOUNT"')"
has "root" "$out" "rc=0 acct=root"

echo
echo "7. no unit file at all"
rm -f "$UNITS/aperire-server.service"
out="$(run 'da_resolve_unit "$DA_UNIT_DIR/aperire-server.service"; echo "rc=$? acct=[$DA_ACCOUNT]"')"
has "rc 1, no account" "$out" "rc=1 acct=[]"

echo
echo "8. by checkout: the unit whose WorkingDirectory is this repo's dashboard"
mkdir -p "$TMP/repo/dashboard" "$TMP/repo/data" "$TMP/other/dashboard"
unit aperire-server "[Service]" "WorkingDirectory=$TMP/other/dashboard" "User=someone-else"
unit aperire-read-node2 "[Service]" "WorkingDirectory=$TMP/repo/dashboard" "User=aperire-dashboard"
out="$(run 'da_resolve_repo "'"$TMP/repo"'"; echo "rc=$? acct=$DA_ACCOUNT unit=$DA_UNIT"')"
has "the matching unit, even an instance of aperire-read" "$out" "rc=0 acct=aperire-dashboard unit=$UNITS/aperire-read-node2.service"
unit aperire-server-b "[Service]" "WorkingDirectory=$TMP/repo/dashboard" "User=aperire-dashboard"
out="$(run 'da_resolve_repo "'"$TMP/repo"'"; echo "rc=$? acct=[$DA_ACCOUNT]"')"
has "two units on one checkout: rc 2, no account picked" "$out" "rc=2 acct=[]"
rm -f "$UNITS"/aperire-*.service
out="$(run 'da_resolve_repo "'"$TMP/repo"'"; echo "rc=$? acct=$DA_ACCOUNT"; echo "why=$DA_WHY"')"
has "no unit (a pm2 or hand-run dashboard): the owner of data/" "$out" "rc=1 acct=$ME"
has "  and it says that is what it did" "$out" "the owner of its data/ ($ME) is taken"

echo
echo "9. the command's own exit status comes back through the switch"
unit aperire-server "[Service]" "User=aperire-dashboard"
out="$(run 'da_resolve_unit "$DA_UNIT_DIR/aperire-server.service"; as_dashboard sh -c "exit 7"; echo "cmd-rc=$?"')"
has "7, not the switch's own" "$out" "cmd-rc=7"

echo
echo "10. da_sudo_ready: no terminal and sudo wants a password is a named refusal, never a prompt"
if [[ $IS_ROOT -eq 1 ]]; then
  echo "  skip  this suite runs as root here, and root never needs sudo"
else
out="$(FAKE_SUDO_NEEDS_PASSWORD=1 run 'da_resolve_unit "$DA_UNIT_DIR/aperire-server.service"; da_sudo_ready "testing"; echo "ready-rc=$?"')"
has "refused" "$out" "ready-rc=1"
has "  naming the account" "$out" "needs to act as aperire-dashboard"
if grep -q 'sudo -v' "$SWITCH_LOG"; then bad "  and sudo -v was never asked" "$(cat "$SWITCH_LOG")"; else ok "  and sudo -v was never asked"; fi
out="$(run 'da_resolve_unit "$DA_UNIT_DIR/aperire-server.service"; da_sudo_ready; echo "ready-rc=$?"')"
has "sudo that needs no password: ready" "$out" "ready-rc=0"
unit aperire-server "[Service]" "User=$ME"
out="$(FAKE_SUDO_NEEDS_PASSWORD=1 run 'da_resolve_unit "$DA_UNIT_DIR/aperire-server.service"; da_sudo_ready; echo "ready-rc=$?"')"
has "already the dashboard's account: ready, with no sudo at all" "$out" "ready-rc=0"
is "  nothing asked of sudo" "$(cat "$SWITCH_LOG")" ""
fi

echo
echo "11. on a terminal: a refused sudo -n asks once through sudo -v, unless DA_NO_PROMPT=1"
if [[ $IS_ROOT -eq 1 ]]; then
  echo "  skip  this suite runs as root here, and root never needs sudo"
elif ! command -v script >/dev/null 2>&1; then
  echo "  skip  no script(1) to give the row a terminal"
else
  unit aperire-server "[Service]" "User=aperire-dashboard"
  : > "$SWITCH_LOG"
  FAKE_SUDO_NEEDS_PASSWORD=1 script -qec "bash -c '. \"$TMP/lib/scripts/dashboard-account-lib.sh\"; DA_NO_PROMPT=1; da_resolve_unit \"\$DA_UNIT_DIR/aperire-server.service\"; as_dashboard true; echo cmd-rc=\$?'" /dev/null > "$TMP/tty.out" 2>&1
  if grep -q 'sudo -v' "$SWITCH_LOG"; then bad "DA_NO_PROMPT=1 on a terminal never asks" "$(cat "$SWITCH_LOG")"; else ok "DA_NO_PROMPT=1 on a terminal never asks"; fi
  has "  and the refusal is 125" "$(cat "$TMP/tty.out")" "cmd-rc=125"
  : > "$SWITCH_LOG"
  FAKE_SUDO_NEEDS_PASSWORD=1 script -qec "bash -c '. \"$TMP/lib/scripts/dashboard-account-lib.sh\"; da_resolve_unit \"\$DA_UNIT_DIR/aperire-server.service\"; as_dashboard true'" /dev/null >/dev/null 2>&1
  has "without it, a terminal gets one sudo -v, never a plain sudo on the command" "$(cat "$SWITCH_LOG")" "sudo -v"
  if grep -E '^sudo :: ' "$SWITCH_LOG" | grep -q .; then bad "  no plain sudo on the command itself" "$(cat "$SWITCH_LOG")"; else ok "  no plain sudo on the command itself"; fi
fi

echo
echo "11b. a refused switch is 125, never the command's own 1 (#873 review, M1)"
if [[ $IS_ROOT -eq 1 ]]; then
  echo "  skip  this suite runs as root here, and root never needs sudo"
else
  unit aperire-server "[Service]" "User=aperire-dashboard"
  printf 'peers: {}\n' > "$TMP/trust.yaml"
  out="$(run 'da_resolve_unit "$DA_UNIT_DIR/aperire-server.service"; as_dashboard grep -q "^private_key:" "'"$TMP/trust.yaml"'"; echo "rc=$?"')"
  has "a switch that works: grep finding nothing is 1, the command's own answer" "$out" "rc=1"
  out="$(FAKE_SUDO_NEEDS_PASSWORD=1 run 'da_resolve_unit "$DA_UNIT_DIR/aperire-server.service"; as_dashboard grep -q "^private_key:" "'"$TMP/trust.yaml"'"; echo "rc=$?"')"
  has "a refusing sudo with no terminal: 125, so no caller reads it as no match" "$out" "rc=125"
  has "  said out loud" "$out" "could not act as aperire-dashboard"
  if grep -q 'grep' "$SWITCH_LOG"; then bad "  and grep never ran" "$(cat "$SWITCH_LOG")"; else ok "  and grep never ran"; fi
  # A switch that stops working between the probe and the command: the
  # command's 1 is then the switch's, and comes back as 125.
  cat > "$TMP/bin/sudo-once" <<'EOF'
#!/usr/bin/env bash
n=$(cat "$ONCE_STATE" 2>/dev/null || echo 0); echo $((n + 1)) > "$ONCE_STATE"
[[ "$n" -ge 1 ]] && exit 1
while [[ $# -gt 0 && "$1" != -- ]]; do shift; done; shift; exec "$@"
EOF
  chmod +x "$TMP/bin/sudo-once"
  mv "$TMP/bin/sudo" "$TMP/bin/sudo.keep"; cp "$TMP/bin/sudo-once" "$TMP/bin/sudo"
  export ONCE_STATE="$TMP/once"; rm -f "$ONCE_STATE"
  out="$(run 'da_resolve_unit "$DA_UNIT_DIR/aperire-server.service"; as_dashboard true; echo "rc=$?"')"
  mv "$TMP/bin/sudo.keep" "$TMP/bin/sudo"; unset ONCE_STATE
  has "a switch that stops mid-run: 125, not the 1 sudo returned" "$out" "rc=125"
  has "  named as such" "$out" "stopped working mid-run"
fi

echo
echo "11c. a planted .sqliterc decides nothing (#875 review, M1)"
if command -v sqlite3 >/dev/null 2>&1; then
  unit aperire-server "[Service]" "User=$ME"
  mkdir -p "$TMP/home"
  sqlite3 "$TMP/rc.db" 'CREATE TABLE t(v); INSERT INTO t VALUES (1);'
  # What an account that can write the home would plant: an rc that prints
  # a non-number where the count goes.
  printf '.print a[$(id)]\n' > "$TMP/home/.sqliterc"
  # The sqlite3 shell reads the rc from the passwd home of the account it
  # runs as, so a suite cannot plant one there; -init names the same file
  # directly, which is what the control needs: that file decides the output.
  plain="$(sqlite3 -init "$TMP/home/.sqliterc" "$TMP/rc.db" 'SELECT COUNT(*) FROM t' 2>/dev/null)"
  has "control: an rc file read by sqlite3 decides what a count prints" "$plain" 'a[$(id)]'
  out="$(run 'da_resolve_unit "$DA_UNIT_DIR/aperire-server.service"; as_dashboard_sqlite "'"$TMP/rc.db"'" "SELECT COUNT(*) FROM t"')"
  is "as_dashboard_sqlite: the count alone" "$out" "1"
  mkdir -p "$TMP/argsql"
  printf '#!/usr/bin/env bash\nprintf "%%s\\n" "$*" > %s/argsql/args\n' "$TMP" > "$TMP/argsql/sqlite3"
  chmod +x "$TMP/argsql/sqlite3"
  PATH="$TMP/argsql:$PATH" run 'da_resolve_unit "$DA_UNIT_DIR/aperire-server.service"; as_dashboard_sqlite "'"$TMP/rc.db"'" "SELECT 1"' >/dev/null
  is "  and it tells sqlite3 to read no rc file, before the database" "$(cut -d' ' -f1-2 "$TMP/argsql/args")" "-init /dev/null"
  out="$(run 'da_is_count "a[\$(id)]" && echo yes || echo no; da_is_count 12 && echo yes || echo no; da_is_count "" && echo yes || echo no')"
  is "da_is_count takes a plain integer and nothing else" "$(tr '\n' ' ' <<<"$out")" "no yes no "
else
  echo "  skip  sqlite3 is not installed"
fi

echo
echo "12. update.conf's DASH_USER (lane C): checked against the unit, the answer only where no unit serves"
unit aperire-server "[Service]" "WorkingDirectory=$TMP/repo/dashboard" "User=aperire-dashboard"
printf 'OPERATOR=%s\nDASH_USER=aperire-dashboard\n' "$ME" > "$TMP/update.conf"
out="$(run 'da_resolve_unit "$DA_UNIT_DIR/aperire-server.service"; echo "acct=$DA_ACCOUNT"')"
has "the two agree: the unit's account" "$out" "acct=aperire-dashboard"
if [[ "$out" == *note:* ]]; then bad "  and nothing is said" "$out"; else ok "  and nothing is said"; fi
printf 'OPERATOR=%s\nDASH_USER=%s\n' "$ME" "$ME" > "$TMP/update.conf"
out="$(run 'da_resolve_unit "$DA_UNIT_DIR/aperire-server.service"; echo "acct=$DA_ACCOUNT"')"
has "they disagree: the unit wins, because systemd runs what it says" "$out" "acct=aperire-dashboard"
has "  and the stale record is named, with its fix" "$out" "Re-run install-update-grant.sh"
rm -f "$UNITS"/aperire-*.service
printf 'OPERATOR=%s\nDASH_USER=%s\n' "$ME" "$ME" > "$TMP/update.conf"
out="$(run 'da_resolve_repo "'"$TMP/repo"'"; echo "rc=$? acct=$DA_ACCOUNT"; echo "why=$DA_WHY"')"
has "no unit: the account update.conf records" "$out" "rc=1 acct=$ME"
has "  and it says where that came from" "$out" "the account $TMP/update.conf records"
printf 'OPERATOR=%s\n' "$ME" > "$TMP/update.conf"
out="$(run 'da_resolve_repo "'"$TMP/repo"'"; echo "why=$DA_WHY"')"
has "an old conf with only OPERATOR: the owner of data/, as before" "$out" "the owner of its data/"
rm -f "$TMP/update.conf"

echo
echo "pass=$PASS fail=$FAIL"
if [[ $FAIL -eq 0 ]]; then echo "ALL PASS"; exit 0; fi
echo "FAILED"
exit 1
