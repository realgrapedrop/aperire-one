#!/usr/bin/env bash
# aperire-auth.sh opens the dashboard's database AS the account the dashboard
# unit names in User=, never as whoever ran it (ADR 0024 lane 4).
#
#   bash scripts/test-aperire-auth-account.sh
#
# A scratch install with a real sqlite database and a fake unit directory.
# sudo and runuser are fakes on PATH that log who they switched to and then
# run the command as this suite, so the database is real and the account
# switch is observed rather than assumed. No authn.yaml, so no node is needed:
# the CLI reads its defaults, which is what it does on a host without one.
set -uo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

PASS=0 FAIL=0
ok()  { printf '  ok    %s\n' "$1"; PASS=$((PASS + 1)); }
bad() { printf '  FAIL  %s\n     %s\n' "$1" "${2:-}"; FAIL=$((FAIL + 1)); }
is()  { if [[ "$2" == "$3" ]]; then ok "$1"; else bad "$1" "got: [$2] | want: [$3]"; fi; }
has() { if [[ "$2" == *"$3"* ]]; then ok "$1"; else bad "$1" "got: $2 | want substring: $3"; fi; }
hasnt() { if [[ "$2" != *"$3"* ]]; then ok "$1"; else bad "$1" "got: $2 | did not want: $3"; fi; }

command -v sqlite3 >/dev/null 2>&1 || { echo "  skip  sqlite3 is not installed"; exit 0; }

ME="$(id -un)"
IS_ROOT=0; [[ "$(id -u)" == 0 ]] && IS_ROOT=1
RIG="$TMP/install"
UNITS="$TMP/units"
mkdir -p "$RIG/scripts" "$RIG/dashboard/config" "$RIG/data" "$UNITS" "$TMP/bin"
cp "$REPO_DIR/scripts/aperire-auth.sh" "$REPO_DIR/scripts/advisor-owner-lib.sh" "$RIG/scripts/"
sed -e "s#^DA_UNIT_DIR=/etc/systemd/system\$#DA_UNIT_DIR=${UNITS}#" -e "s#^DA_UPDATE_CONF=/etc/aperire/update.conf\$#DA_UPDATE_CONF=${DA_TEST_UPDATE_CONF:-/nonexistent/update.conf}#" \
  "$REPO_DIR/scripts/dashboard-account-lib.sh" > "$RIG/scripts/dashboard-account-lib.sh"
grep -q "^DA_UNIT_DIR=${UNITS}\$" "$RIG/scripts/dashboard-account-lib.sh" \
  || { echo "DA_UNIT_DIR rewrite did not land in dashboard-account-lib.sh" >&2; exit 1; }

DB="$RIG/data/aperire.db"
sqlite3 "$DB" "
  CREATE TABLE auth_users (id INTEGER PRIMARY KEY, username TEXT, email TEXT, role TEXT, created_at INT, last_login_at INT);
  CREATE TABLE auth_credentials (id INTEGER PRIMARY KEY, user_id INT, credential_id TEXT, public_key TEXT, sign_count INT, transports TEXT, name TEXT, created_at INT, last_used_at INT);
  CREATE TABLE auth_sessions (id TEXT PRIMARY KEY, user_id INT, created_at INT, last_activity_at INT, expires_at INT, ua TEXT, ip TEXT, credential_id TEXT, revoked_at INT);
  CREATE TABLE auth_magic_links (id INTEGER PRIMARY KEY AUTOINCREMENT, token TEXT NOT NULL UNIQUE, user_id INT NOT NULL, purpose TEXT NOT NULL, created_at INT NOT NULL, expires_at INT NOT NULL, consumed_at INT);
  CREATE TABLE auth_events (id INTEGER PRIMARY KEY, at INT, actor TEXT, actor_role TEXT, event TEXT, target TEXT, detail TEXT);
  INSERT INTO auth_users (id, username, email, role, created_at) VALUES (1, 'op@example.com', 'op@example.com', 'admin', 1);
  INSERT INTO auth_sessions (id, user_id, created_at, last_activity_at, expires_at) VALUES ('sess-abc123', 1, 1, 1, 9999999999);
"

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
printf '%s%s :: %s :: %s\n' "$prog" "\$flags" "\$who" "\$logcmd" >> "\$SWITCH_LOG"
if [[ "$prog" == sudo && -n "\${FAKE_SUDO_NEEDS_PASSWORD:-}" && "\$flags" == *-n* ]]; then exit 1; fi
# The one constant path root runs the trust sync from is mapped to the
# fixture here, and only here: the product has no override for it. Unmapped, a
# root-owned program at its real path is logged and never run, because this
# suite must not call a host's own installed programs.
args=( "\$@" )
for i in "\${!args[@]}"; do
  if [[ "\${args[\$i]}" == /usr/local/sbin/aperire-trust-sync && -n "\${FAKE_SYNC_MAP:-}" ]]; then args[\$i]="\$FAKE_SYNC_MAP"; fi
done
set -- "\${args[@]}"
case " \$* " in *" /usr/local/sbin/"*) exit 0 ;; esac
# What ran after a switch is marked with whom it ran as, inside the env -i the
# real switch is given, so a program can tell (row 8's js-yaml tripwire).
[[ "\${1:-}" == env && "\${2:-}" == -i ]] && set -- env -i "FAKE_AS=\$who" "\${@:3}"
exec "\$@"
EOF
  chmod +x "$TMP/bin/$prog"
done
export PATH="$TMP/bin:$PATH"

dash_unit() {  # <user>
  printf '[Service]\nWorkingDirectory=%s/dashboard\nUser=%s\n' "$RIG" "$1" > "$UNITS/aperire-server.service"
}
auth() { : > "$SWITCH_LOG"; APERIRE_NO_TRUST_PUSH=1 bash "$RIG/scripts/aperire-auth.sh" "$@" </dev/null 2>&1; }

echo "1. a host installed before ADR 0024: the unit names the operator's own login"
dash_unit "$ME"
out="$(auth list)"; rc=$?
is "list exits 0" "$rc" "0"
has "  and lists the operator" "$out" "op@example.com"
is "  with no account switch at all" "$(cat "$SWITCH_LOG")" ""

echo
echo "2. a fresh install: the unit names aperire-dashboard"
dash_unit aperire-dashboard
out="$(auth list)"; rc=$?
is "list exits 0" "$rc" "0"
has "  and lists the operator" "$out" "op@example.com"
log="$(cat "$SWITCH_LOG")"
if [[ $IS_ROOT -eq 1 ]]; then
  has "the read ran as aperire-dashboard, through runuser" "$log" "runuser :: aperire-dashboard :: sqlite3"
else
  has "the read ran as aperire-dashboard, through sudo" "$log" "sudo -n :: aperire-dashboard :: sqlite3"
fi
hasnt "  never as $ME" "$log" ":: $ME ::"

out="$(auth revoke-session sess-abc)"; rc=$?
is "revoke-session, a write, exits 0" "$rc" "0"
has "  the write ran as aperire-dashboard" "$(cat "$SWITCH_LOG")" "aperire-dashboard :: sqlite3 -init /dev/null $DB UPDATE auth_sessions"
is "  and landed" "$(sqlite3 "$DB" "SELECT revoked_at IS NOT NULL FROM auth_sessions WHERE id='sess-abc123'")" "1"

echo
echo "2b. the first step a fresh install prints: aperire-auth add, on the new shape (lanes C and D ship together)"
# The installer's closing summary tells the operator to run exactly this.
# Before lane D it failed on a fresh install: data/ is aperire-dashboard's,
# 0700, and the operator could not open the database at all.
out="$(auth add first@example.com --role admin)"; rc=$?
is "add exits 0" "$rc" "0"
is "  the operator row landed" \
  "$(sqlite3 "$DB" "SELECT role FROM auth_users WHERE email='first@example.com'")" "admin"
has "  and the enrollment link is printed" "$out" "token="
is "  and its magic-link row landed" \
  "$(sqlite3 "$DB" "SELECT COUNT(*) FROM auth_magic_links m JOIN auth_users u ON u.id=m.user_id WHERE u.email='first@example.com'")" "1"
log="$(cat "$SWITCH_LOG")"
has "  every database step ran as aperire-dashboard" "$log" "aperire-dashboard :: sqlite3 -init /dev/null $DB INSERT INTO auth_users"
has "    the link's insert too" "$log" "aperire-dashboard :: sqlite3 -init /dev/null $DB INSERT INTO auth_magic_links"
# Only the switch lines: a multi-line SQL statement continues on lines of its own.
if grep -E '^(sudo|runuser)' "$SWITCH_LOG" | grep -v ':: aperire-dashboard ::' | grep -q .; then
  bad "    and nothing switched to anyone else" "$log"
else
  ok "    and nothing switched to anyone else"
fi

echo
echo "2c. a count that is not a number is refused before any arithmetic (#875 review, M1)"
# A sqlite3 that answers a COUNT with an expression bash would run: what a
# planted rc file could make the real one print. Nothing may evaluate it.
dash_unit "$ME"
mkdir -p "$TMP/badsql"
cat > "$TMP/badsql/sqlite3" <<EOF
#!/usr/bin/env bash
for a in "\$@"; do [[ "\$a" == *COUNT* ]] && { printf '%s\n' 'x[\$(touch $TMP/ran)]'; exit 0; }; done
exec /usr/bin/sqlite3 "\$@"
EOF
chmod +x "$TMP/badsql/sqlite3"
sqlite3 "$DB" "INSERT INTO auth_sessions (id, user_id, created_at, last_activity_at, expires_at) VALUES ('sess-zzz', 1, 1, 1, 9999999999);"
out="$(: > "$SWITCH_LOG"; PATH="$TMP/badsql:$PATH" APERIRE_NO_TRUST_PUSH=1 bash "$RIG/scripts/aperire-auth.sh" revoke-session sess-zzz </dev/null 2>&1)"; rc=$?
is "exits 1" "$rc" "1"
has "  it says the answer is not a count" "$out" "which is not a count"
is "  nothing in it ran" "$([[ -e "$TMP/ran" ]] && echo ran || echo no)" "no"
is "  and the session was not revoked" "$(sqlite3 "$DB" "SELECT revoked_at IS NULL FROM auth_sessions WHERE id='sess-zzz'")" "1"
dash_unit aperire-dashboard

echo
echo "2d. a refused read exits non-zero from every list verb (#885, N2)"
# A sqlite3 that refuses the table read but answers the operator-id lookup, so
# list-credentials and list-sessions reach their listing. A refused read must
# not end as an empty table with status 0.
dash_unit "$ME"
mkdir -p "$TMP/refusesql"
cat > "$TMP/refusesql/sqlite3" <<EOF2
#!/usr/bin/env bash
for a in "\$@"; do [[ "\$a" == *"FROM auth_users u ORDER BY"* || "\$a" == *"FROM auth_credentials WHERE user_id"* || "\$a" == *"FROM auth_sessions WHERE user_id"* ]] && { echo 'Error: attempt to write a readonly database' >&2; exit 8; }; done
exec /usr/bin/sqlite3 "\$@"
EOF2
chmod +x "$TMP/refusesql/sqlite3"
for verb in "list" "list-credentials op@example.com" "list-sessions op@example.com"; do
  # shellcheck disable=SC2086
  out="$(: > "$SWITCH_LOG"; PATH="$TMP/refusesql:$PATH" APERIRE_NO_TRUST_PUSH=1 bash "$RIG/scripts/aperire-auth.sh" $verb </dev/null 2>&1)"; rc=$?
  if [[ "$rc" != 0 ]]; then ok "$verb exits non-zero on a refused read ($rc)"; else bad "$verb exits non-zero on a refused read" "rc=0 out=$out"; fi
  has "  and says the database step did not run" "$out" "a database step did not run"
  hasnt "  and prints no empty table" "$out" "──"
done
dash_unit aperire-dashboard

echo
echo "2e. list-sessions tells an expired session from an active one (#1143)"
# A session past its expiry that nobody revoked used to print as 'active', and
# a lab with many sign-ins listed hundreds of them. Row 2 left sess-abc123
# revoked, so all three states are here. The live row is minted now, because a
# row created more than 7 days ago is over the cap whatever its expires_at says.
sqlite3 "$DB" "INSERT INTO auth_sessions (id, user_id, created_at, last_activity_at, expires_at) VALUES
  ('sess-live-1143', 1, strftime('%s','now'), strftime('%s','now'), strftime('%s','now') + 3600),
  ('sess-expd-1143', 1, strftime('%s','now') - 7200, strftime('%s','now') - 7200, strftime('%s','now') - 3600),
  ('sess-oldc-1143', 1, strftime('%s','now') - 691200, strftime('%s','now'), 9999999999);"
out="$(auth list-sessions op@example.com)"; rc=$?
is "list-sessions exits 0" "$rc" "0"
has "  the state column is headed 'state'" "$out" "last_activity          state"
is "  a session inside its lifetime is active" "$(grep 'sess-live-1143' <<<"$out" | awk '{print $NF}')" "active"
is "  an unrevoked session past expires_at is expired" "$(grep 'sess-expd-1143' <<<"$out" | awk '{print $NF}')" "expired"
is "  one created over 7 days ago is expired, whatever its expires_at" "$(grep 'sess-oldc-1143' <<<"$out" | awk '{print $NF}')" "expired"
is "  a revoked session stays revoked" "$(grep 'sess-abc123' <<<"$out" | awk '{print $NF}')" "revoked"

echo
echo "3. help never opens the database, so it never switches account"
out="$(auth help)"; rc=$?
is "help exits 0" "$rc" "0"
is "  with no account switch" "$(cat "$SWITCH_LOG")" ""

echo
echo "4. no terminal and sudo wants a password: refused by name, never a hidden prompt"
if [[ $IS_ROOT -eq 1 ]]; then
  echo "  skip  this suite runs as root here, and root never needs sudo"
else
  out="$(FAKE_SUDO_NEEDS_PASSWORD=1 auth list)"; rc=$?
  is "exits 1" "$rc" "1"
  has "  it names the account it needs" "$out" "needs to act as aperire-dashboard"
  hasnt "  and lists nothing" "$out" "op@example.com"
  if grep -q 'sudo -v' "$SWITCH_LOG"; then bad "  sudo -v was never asked" "$(cat "$SWITCH_LOG")"; else ok "  sudo -v was never asked"; fi
fi

echo
echo "5. a unit with no User= this can read is refused, never guessed"
printf '[Service]\nWorkingDirectory=%s/dashboard\n' "$RIG" > "$UNITS/aperire-server.service"
out="$(auth list)"; rc=$?
is "exits 1" "$rc" "1"
has "  it says it could not read the account" "$out" "could not read which account the dashboard runs as"
is "  and switched to nobody" "$(cat "$SWITCH_LOG")" ""

echo
echo "6. no unit at all (pm2, or by hand): whoever owns data/ is the account"
rm -f "$UNITS/aperire-server.service"
out="$(auth list)"; rc=$?
is "list exits 0" "$rc" "0"
has "  and lists the operator" "$out" "op@example.com"
is "  as the owner of data/, which is this suite, so no switch" "$(cat "$SWITCH_LOG")" ""

echo
echo "7. advisor-sync: what root runs is the root-owned program, never the checkout's copy (#943)"
# aperire-trust-sync.sh in the checkout is a file the login can change. Under
# sudo (a dashboard with its own account) and as root (sudo aperire-auth
# advisor-sync) the sync is /usr/local/sbin/aperire-trust-sync, the copy the
# grant installer placed after its own checks. The checkout's copy stays for an
# ordinary account acting as itself, which crosses nothing. The checkout's file
# here is a tripwire; the root-owned one is a fixture that records how it was
# called.
printf 'public_url: https://dash.example\nrp_id: dash.example\n' > "$RIG/dashboard/config/authn.yaml"
# authn.yaml is read with the dashboard's own node and js-yaml; a node on PATH
# that answers the two keys keeps this suite from needing either. The key is
# the reader's last argument; 3 is the reader's own "the file does not set it".
cat > "$TMP/bin/node" <<'NODE'
#!/usr/bin/env bash
# A row may answer a key itself: FAKE_AUTHN_DIR/<key> holds the value.
[[ -n "${FAKE_AUTHN_DIR:-}" && -f "$FAKE_AUTHN_DIR/${!#}" ]] && { cat "$FAKE_AUTHN_DIR/${!#}"; exit 0; }
case "${!#}" in
  public_url) printf 'https://dash.example' ;;
  rp_id)      printf 'dash.example' ;;
  *)          exit 3 ;;
esac
NODE
chmod +x "$TMP/bin/node"
mkdir -p "$RIG/advisor/state" "$TMP/sbin"
TRIP7="$TMP/trip7"; CALL7="$TMP/call7"
cat > "$RIG/scripts/aperire-trust-sync.sh" <<EOF
#!/usr/bin/env bash
printf 'tree-copy ran as %s\n' "\$(id -un)" >> "$TRIP7"
exit 0
EOF
cat > "$TMP/sbin/aperire-trust-sync" <<EOF
#!/usr/bin/env bash
printf 'self=%s origin=%s rpid=%s db=%s state=%s\n' "\$0" "\${ORIGIN:-}" "\${RPID:-}" "\${APERIRE_DB_PATH:-}" "\${APERIRE_ADVISOR_STATE:-}" >> "$CALL7"
exit 0
EOF
chmod +x "$RIG/scripts/aperire-trust-sync.sh" "$TMP/sbin/aperire-trust-sync"
sync7() { : > "$SWITCH_LOG"; : > "$TRIP7"; : > "$CALL7"; env FAKE_SYNC_MAP="${SYNC_BIN7-$TMP/sbin/aperire-trust-sync}" ${OLDVARS7:+APERIRE_AUTH_TESTING=1 APERIRE_TRUST_SYNC_PATH="$TMP/sbin/aperire-trust-sync"} "$@" bash "$RIG/scripts/aperire-auth.sh" advisor-sync </dev/null 2>&1; }

if [[ $IS_ROOT -eq 1 ]]; then
  echo "  skip  the sudo leg is not taken when this suite is already root"
else
  dash_unit aperire-dashboard
  out="$(sync7)"; rc=$?
  is "on a dashboard with its own account, advisor-sync exits 0" "$rc" "0"
  has "  and root ran the root-owned program, under sudo" "$(cat "$SWITCH_LOG")" "sudo -n ::  :: env ORIGIN=https://dash.example RPID=dash.example"
  has "    named by its installed path, the constant" "$(cat "$SWITCH_LOG")" "/usr/local/sbin/aperire-trust-sync"
  has "    with the origin and rp_id from authn.yaml" "$(cat "$CALL7")" "origin=https://dash.example rpid=dash.example"
  is "  and the checkout's copy never ran" "$(cat "$TRIP7")" ""
  hasnt "  and no root call names it" "$(cat "$SWITCH_LOG")" "aperire-trust-sync.sh"

  # The program missing (the fake sudo maps the constant to a path with
  # nothing there): the failure env reports is read as "not installed", and
  # the answer names the program and how it gets there. Never a fall back to
  # the file beside this script.
  out="$(SYNC_BIN7="$TMP/sbin/not-here" sync7)"; rc=$?
  is "with the root-owned program missing, advisor-sync exits 1" "$rc" "1"
  has "  it names the program and says the checkout's copy is not run as root" "$out" "will not run the copy in the"
  has "  and how it gets there" "$out" "curl -fsSL https://get.aperire.one/advisor | bash"
  is "  and neither the fixture nor the checkout's copy ran" "$(cat "$CALL7")$(cat "$TRIP7")" ""

  # The login's own environment does not pick what root runs. The variables
  # the earlier review round left as a test switch (APERIRE_AUTH_TESTING with
  # APERIRE_TRUST_SYNC_PATH) are set here, pointing at a good fixture, and
  # change nothing: sudo is handed the constant, and the fixture is never
  # called. The fake sudo is not told to map, so it logs the constant and
  # does not run a host's own installed program.
  out="$(OLDVARS7=1 SYNC_BIN7='' sync7)"; rc=$?
  has "the old test variables set in the login's environment change nothing: sudo is handed the constant path" "$(cat "$SWITCH_LOG")" "env ORIGIN=https://dash.example RPID=dash.example APERIRE_DB_PATH="
  has "  /usr/local/sbin/aperire-trust-sync" "$(cat "$SWITCH_LOG")" "/usr/local/sbin/aperire-trust-sync"
  hasnt "  and never the fixture they name" "$(cat "$SWITCH_LOG")" "$TMP/sbin/aperire-trust-sync"
  is "  which is never called" "$(cat "$CALL7")" ""
fi

# An ordinary account that is the dashboard's own acts as itself: no boundary,
# so the checkout's copy runs, as that account, with no sudo.
dash_unit "$ME"
out="$(sync7)"; rc=$?
is "on a dashboard run by the operator, advisor-sync exits 0" "$rc" "0"
has "  and the checkout's copy ran, as the operator" "$(cat "$TRIP7")" "tree-copy ran as $ME"
is "  with no sudo and no root-owned program involved" "$(cat "$SWITCH_LOG")$(cat "$CALL7")" ""

# Root itself (sudo aperire-auth advisor-sync): the root-owned program at its
# constant path, not the checkout's and not one the environment names. fakeroot
# gives this suite uid 0 without a sudo, and there is no fake sudo in the way,
# so it only runs where the constant is not installed.
if command -v fakeroot >/dev/null 2>&1; then
  dash_unit aperire-dashboard
  if [[ -e /usr/local/sbin/aperire-trust-sync ]]; then
    echo "  skip  this host has /usr/local/sbin/aperire-trust-sync, which root would run for real"
  else
    out="$(OLDVARS7=1 SYNC_BIN7='' sync7 fakeroot)"; rc=$?
    is "run as root with the old test variables set, it ignores them and stops on the constant path" "$rc" "1"
    has "  naming /usr/local/sbin/aperire-trust-sync" "$out" "/usr/local/sbin/aperire-trust-sync is not on this host"
    is "  with the fixture never called and the checkout's copy not run" "$(cat "$CALL7")$(cat "$TRIP7")" ""
  fi
fi
dash_unit aperire-dashboard

echo
echo "7b. the two values the trust store binds to are held to their shape (#993 review)"
# public_url is an origin: https, or http to this machine only (the shipped
# localhost default). rp_id is a host name. Anything else is not used: the
# sync refuses with no origin rather than bind approvals to it.
dash_unit "$ME"
mkdir -p "$TMP/authn9"
printf 'http://dash.example' > "$TMP/authn9/public_url"
out="$(FAKE_AUTHN_DIR="$TMP/authn9" sync7)"; rc=$?
if [[ $rc -ne 0 && "$out" == *"public_url in"*"is not a value this can use"* && "$out" == *"no public_url in authn.yaml"* && ! -s "$TRIP7" ]]; then
  ok "an http public_url that is not this machine is not used, and the sync refuses rather than bind to it"
else
  bad "a plain-http public_url is refused" "rc=$rc :: $out :: ran: $(cat "$TRIP7")"
fi
printf 'http://localhost:7800' > "$TMP/authn9/public_url"
out="$(FAKE_AUTHN_DIR="$TMP/authn9" sync7)"; rc=$?
if [[ $rc -eq 0 && "$(cat "$TRIP7")" == *"tree-copy ran"* ]]; then
  ok "  the control: the shipped http://localhost default is still taken"
else
  bad "  http to localhost is still taken" "rc=$rc :: $out"
fi
rm -f "$TMP/authn9/public_url"; printf 'dash.example/evil' > "$TMP/authn9/rp_id"
out="$(FAKE_AUTHN_DIR="$TMP/authn9" sync7)"; rc=$?
if [[ "$out" == *"rp_id in"*"is not a value this can use"* ]]; then
  ok "an rp_id that is not a host name is not used"
else
  bad "a non-hostname rp_id is refused" "rc=$rc :: $out"
fi
rm -rf "$TMP/authn9"
dash_unit aperire-dashboard

echo
echo "8. root never loads the dashboard's js-yaml: authn.yaml is read as the dashboard's account (#993)"
# Run as root (the Advisor install's trust sync, sudo aperire-auth ...), the
# reader used to start the install owner's node with the dashboard as its
# working directory, so root loaded dashboard/node_modules/js-yaml out of the
# tree. The rig's js-yaml is a tripwire that records the uid it was loaded
# under and the account the fake switch says it ran as, and parses the two
# lines this file holds. fakeroot gives uid 0; a switch through the fake
# runuser drops fakeroot with the rest of the environment (env -i), the way a
# real switch drops root. Needs a real node and fakeroot.
REAL_NODE="$(PATH="${PATH#"$TMP/bin:"}" command -v node 2>/dev/null || true)"
if ! command -v fakeroot >/dev/null 2>&1 || [[ -z "$REAL_NODE" ]]; then
  echo "  skip  needs fakeroot and node"
else
  JSY_LOG="$TMP/jsyaml.log"
  mkdir -p "$RIG/dashboard/node_modules/js-yaml"
  cat > "$RIG/dashboard/node_modules/js-yaml/index.js" <<EOF
require('fs').appendFileSync('$JSY_LOG', 'uid=' + process.getuid() + ' as=' + (process.env.FAKE_AS || '') + '\n');
module.exports = { load: (t) => { const o = {}; let sec = null; for (const l of t.split('\n')) { const m = l.match(/^( *)([a-z_]+):\s*(.*)\$/); if (!m) continue; if (!m[1]) { if (m[3]) { o[m[2]] = m[3]; sec = null; } else { sec = o[m[2]] = {}; } } else if (sec) { sec[m[2]] = m[3]; } } return o; } };
EOF
  # The email send is the dashboard's own code too: a tripwire in its place.
  mkdir -p "$RIG/dashboard/scripts"
  # It also records how node was started and what it was handed. The real
  # script is run by dashboard/test/unit/send-magic-script.test.ts, against a
  # Resend stand-in, with the flags read out of this CLI; this rig proves the
  # CLI starts it that way, through tsx, with the address, subject and link as
  # its three arguments (#1354). tsx itself is a package that does nothing.
  mkdir -p "$RIG/dashboard/node_modules/tsx"
  printf '{"name":"tsx","type":"module","main":"index.mjs"}\n' > "$RIG/dashboard/node_modules/tsx/package.json"
  : > "$RIG/dashboard/node_modules/tsx/index.mjs"
  cat > "$RIG/dashboard/scripts/send-magic.mjs" <<EOF
import { appendFileSync } from 'node:fs';
appendFileSync('$TMP/send.log', 'uid=' + process.getuid() + ' as=' + (process.env.FAKE_AS || '') + '\n');
appendFileSync('$TMP/send-args.log', process.execArgv.join(' ') + ' :: ' + process.argv.slice(2).join(' | ') + '\n');
EOF
  printf 'public_url: https://dash.example\nrp_id: dash.example\nmagic_link:\n  send_via_email: true\n' > "$RIG/dashboard/config/authn.yaml"
  unit8() {  # <user>: the unit names the real node, the one the reader takes first
    printf '[Service]\nWorkingDirectory=%s/dashboard\nUser=%s\nExecStart=%s --import tsx server.ts\n' "$RIG" "$1" "$REAL_NODE" > "$UNITS/aperire-server.service"
  }

  # The control: the tripwire is loaded at all, by an ordinary login acting
  # as itself, with no switch.
  unit8 "$ME"; : > "$JSY_LOG"
  out="$(auth help)"; rc=$?
  is "as the login, help exits 0" "$rc" "0"
  has "  and the reader loaded the rig's js-yaml, as the login" "$(cat "$JSY_LOG")" "uid=$(id -u) as="

  unit8 aperire-dashboard; : > "$JSY_LOG"; : > "$TMP/send.log"; : > "$TMP/send-args.log"
  out="$(: > "$SWITCH_LOG"; fakeroot env APERIRE_NO_TRUST_PUSH=1 bash "$RIG/scripts/aperire-auth.sh" magic-link op@example.com </dev/null 2>&1)"; rc=$?
  is "as root, magic-link exits 0" "$rc" "0"
  has "  and the link is built from authn.yaml's public_url, read through the switch" "$out" "https://dash.example/"
  if [[ -s "$JSY_LOG" ]] && ! grep -q 'uid=0 ' "$JSY_LOG"; then
    ok "  js-yaml was never loaded by root"
  else
    bad "  js-yaml was never loaded by root" "$(cat "$JSY_LOG")"
  fi
  if [[ -s "$JSY_LOG" ]] && ! grep -v ' as=aperire-dashboard$' "$JSY_LOG" | grep -q .; then
    ok "  every load ran as aperire-dashboard"
  else
    bad "  every load ran as aperire-dashboard" "$(cat "$JSY_LOG")"
  fi
  has "  through runuser, with the reader's arguments as words" "$(cat "$SWITCH_LOG")" "runuser :: aperire-dashboard :: $REAL_NODE -e"
  has "  send_via_email, read through the switch, sends the link" "$out" "(emailed enrollment URL to op@example.com)"
  is "  and the send ran as aperire-dashboard, never as root" "$(cat "$TMP/send.log" 2>/dev/null)" "uid=$(id -u) as=aperire-dashboard"
  has "  started through tsx, the way the dashboard's unit starts its code (#1354)" "$(cat "$TMP/send-args.log" 2>/dev/null)" "--import tsx :: op@example.com | "
  hasnt "  and not under Node's own type stripping, which cannot follow email.ts's imports" "$(cat "$TMP/send-args.log" 2>/dev/null)" "strip-types"
  has "  with the enrollment link as its third argument" "$(cat "$TMP/send-args.log" 2>/dev/null)" "https://dash.example/login.html?token="

  # Root with no account but root to switch to reads nothing and says why,
  # before anything runs.
  unit8 root; : > "$JSY_LOG"
  out="$(: > "$SWITCH_LOG"; fakeroot env APERIRE_NO_TRUST_PUSH=1 bash "$RIG/scripts/aperire-auth.sh" help </dev/null 2>&1)"; rc=$?
  is "as root on a dashboard that runs as root, it exits 1" "$rc" "1"
  has "  saying it reads authn.yaml as the dashboard's account, never as root" "$out" "never as root, because reading it runs the dashboard's own code"
  is "  and js-yaml was not loaded at all" "$(cat "$JSY_LOG")" ""

  rm -rf "$RIG/dashboard/node_modules" "$RIG/dashboard/scripts"
  printf 'public_url: https://dash.example\nrp_id: dash.example\n' > "$RIG/dashboard/config/authn.yaml"
  dash_unit aperire-dashboard
fi

echo
echo "pass=$PASS fail=$FAIL"
if [[ $FAIL -eq 0 ]]; then echo "ALL PASS"; exit 0; fi
echo "FAILED"
exit 1
