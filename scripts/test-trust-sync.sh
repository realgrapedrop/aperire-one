#!/usr/bin/env bash
# Exercise scripts/aperire-trust-sync.sh, the one program that writes the
# Advisor's trust store, on both of its paths.
#
# What is being protected. The store decides whose passkey may approve an
# action on the node, and this program is reached from the dashboard's
# process after a browser enrollment (#160) as well as from the CLI. So the
# rows below are about what it will NOT do as much as what it does: it takes
# nothing into the store that is not in the database, it refuses to rebuild
# a store an issuer installed, it refuses a request that moves the relying
# party or widens the origins, and on the socket path its last line is the
# exit code, on every path, because that line is the only status the
# dashboard gets.
#
#   bash scripts/test-trust-sync.sh
#
# Runs entirely in a temporary directory as the current user, so the
# root-only branch (read as the database's owner, write as the state
# directory's) is not exercised here; the socket unit on a real host is what
# covers that, and the fleet install verifies it. Needs sqlite3 and python3,
# which the program itself needs.

set -uo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SUT="$REPO_DIR/scripts/aperire-trust-sync.sh"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

PASS=0 FAIL=0
ok()  { printf '  ok    %s\n' "$1"; PASS=$((PASS + 1)); }
bad() { printf '  FAIL  %s\n     %s\n' "$1" "$2"; FAIL=$((FAIL + 1)); }
is()  { # <description> <got> <wanted>
  if [[ "$2" == "$3" ]]; then ok "$1"; else bad "$1" "got '$2', wanted '$3'"; fi
}
says() { # <description> <haystack> <needle>
  if printf '%s' "$2" | grep -q -- "$3"; then ok "$1"; else bad "$1" "'$3' is not in:
$2"; fi
}
silent() { # <description> <haystack> <needle>
  if printf '%s' "$2" | grep -q -- "$3"; then bad "$1" "'$3' IS in:
$2"; else ok "$1"; fi
}

for tool in sqlite3 python3; do
  command -v "$tool" >/dev/null || { echo "skipping: $tool is not installed"; exit 0; }
done

DB="$TMP/aperire.db"
STATE="$TMP/state"
STORE="$STATE/credentials.json"
mkdir -p "$STATE"

sqlite3 "$DB" <<'SQL'
CREATE TABLE auth_users (id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE, email TEXT,
  role TEXT NOT NULL DEFAULT 'operator', created_at INTEGER NOT NULL, last_login_at INTEGER);
CREATE TABLE auth_credentials (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL,
  credential_id TEXT NOT NULL UNIQUE, public_key TEXT NOT NULL, sign_count INTEGER NOT NULL DEFAULT 0,
  transports TEXT, name TEXT, created_at INTEGER NOT NULL, last_used_at INTEGER);
INSERT INTO auth_users VALUES (1, 'captain', NULL, 'admin', 1, NULL);
INSERT INTO auth_users VALUES (2, 'watcher', NULL, 'operator', 1, NULL);
INSERT INTO auth_credentials (user_id, credential_id, public_key, name, created_at)
  VALUES (1, 'cred-captain-1', 'pub-captain-1', 'laptop', 1);
INSERT INTO auth_credentials (user_id, credential_id, public_key, name, created_at)
  VALUES (2, 'cred-watcher-1', 'pub-watcher-1', 'phone', 1);
SQL

# The program as the CLI runs it: origin and rp_id in the environment.
cli() { # [ORIGIN] [RPID]
  ORIGIN="${1:-https://dash.example.test}" RPID="${2:-}" \
  APERIRE_DB_PATH="$DB" APERIRE_ADVISOR_STATE="$STATE" bash "$SUT" 2>&1
}
# And as the socket unit runs it: two lines on standard input, output is one
# stream, and the exit code is READ OUT of it rather than taken from $?.
sock() { # <origin> <rpid>
  printf '%s\n%s\n' "$1" "$2" | APERIRE_DB_PATH="$DB" APERIRE_ADVISOR_STATE="$STATE" bash "$SUT" --from-socket 2>&1
}
field() { # <name> <stream>
  sed -n "s/^$1=//p" <<<"$2" | tail -n1
}
in_store() { python3 -c "
import json,sys; s=json.load(open('$STORE'))
print(' '.join(sorted(c['credential_id'] for c in s.get('credentials',[]))))
print('rp_id='+str(s.get('rp_id')))
print('origins='+','.join(s.get('origins',[])))
"; }

echo
echo "── the CLI path ──────────────────────────────────────────────────"
out="$(cli)"; rc=$?
is   "a first sync writes the store and exits 0" "$rc" "0"
is   "only the admin's passkey is in it" "$(in_store | sed -n 1p)" "cred-captain-1"
is   "the rp_id is derived from the origin when none is given" "$(in_store | sed -n 2p)" "rp_id=dash.example.test"
is   "the origin is recorded" "$(in_store | sed -n 3p)" "origins=https://dash.example.test"
is   "the store is 0640" "$(stat -c %a "$STORE")" "640"
is   "and carries the state directory's group, so a reader of the directory can read it" \
     "$(stat -c %g "$STORE")" "$(stat -c %g "$STATE")"
silent "the CLI path prints no exit= line" "$out" "^exit="
says "and reports the count in words" "$out" "1 added, 0 replaced, 0 removed, 1 trusted"

echo
echo "── the socket path ───────────────────────────────────────────────"
sqlite3 "$DB" "INSERT INTO auth_credentials (user_id, credential_id, public_key, name, created_at)
  VALUES (1, 'cred-captain-2', 'pub-captain-2', 'yubikey', 2);"
out="$(sock https://dash.example.test dash.example.test)"
is   "the last line is the exit code" "$(tail -n1 <<<"$out")" "exit=0"
is   "the fields say what changed" "$(field added "$out")/$(field trusted "$out")" "1/2"
is   "both admin passkeys are now trusted" "$(in_store | sed -n 1p)" "cred-captain-1 cred-captain-2"
silent "the operator's passkey is still not" "$(in_store)" "cred-watcher-1"

# The socket's two refusals: the relying party and the origins are the
# operator's configuration, not the request's.
out="$(sock https://dash.example.test other.example.test)"
is   "a request that moves the rp_id is refused with exit 3" "$(tail -n1 <<<"$out")" "exit=3"
says "and it says which rp_id the store is bound to" "$out" "bound to rp_id 'dash.example.test'"
is   "and the store was not touched" "$(in_store | sed -n 2p)" "rp_id=dash.example.test"
out="$(sock https://evil.example.test dash.example.test)"
is   "a request that adds an origin is refused with exit 3" "$(tail -n1 <<<"$out")" "exit=3"
is   "and the origins are as they were" "$(in_store | sed -n 3p)" "origins=https://dash.example.test"
# While the CLI, which is the operator, may do both.
out="$(cli https://also.example.test dash.example.test)"; rc=$?
is   "the CLI may add an origin" "$(in_store | sed -n 3p)" "origins=https://also.example.test,https://dash.example.test"

echo
echo "── what the database says goes; nothing else does ────────────────"
sqlite3 "$DB" "UPDATE auth_credentials SET public_key='pub-captain-1-rotated' WHERE credential_id='cred-captain-1';"
out="$(sock https://dash.example.test dash.example.test)"
is   "a changed key is replaced" "$(field replaced "$out")" "1"
sqlite3 "$DB" "UPDATE auth_users SET role='operator' WHERE username='captain';"
out="$(sock https://dash.example.test dash.example.test)"
is   "demoting the last admin empties the store rather than leaving it" "$(field trusted "$out")/$(field removed "$out")" "0/2"
is   "and the file says so" "$(in_store | sed -n 1p)" ""
says "and the words say why" "$out" "no admin has an enrolled passkey"
sqlite3 "$DB" "UPDATE auth_users SET role='admin' WHERE username='captain';"

# A device name is typed by whoever enrolled; a newline in it used to parse
# as a second credential row. JSON carries it inside the field, and the
# label lands in the store with the control characters replaced.
sqlite3 "$DB" "UPDATE auth_credentials SET name='line one
line two	tab' WHERE credential_id='cred-captain-1';"
out="$(sock https://dash.example.test dash.example.test)"
is   "a label with a newline in it does not become a second row" "$(field trusted "$out")" "2"
is   "and is written with the control characters replaced" \
     "$(python3 -c "import json; print([c['label'] for c in json.load(open('$STORE'))['credentials'] if c['credential_id']=='cred-captain-1'][0])")" \
     "line one line two tab"
sqlite3 "$DB" "UPDATE auth_credentials SET credential_id='cred-bad
row' WHERE credential_id='cred-captain-2';"
out="$(sock https://dash.example.test dash.example.test)"
says "a credential id with a control character in it is refused, not sanitised" "$out" "REFUSED a credential"
is   "and the good one is still trusted" "$(field trusted "$out")" "1"
sqlite3 "$DB" "UPDATE auth_credentials SET credential_id='cred-captain-2' WHERE credential_id LIKE 'cred-bad%';"

echo
echo "── a store an issuer installed is not ours to rebuild ────────────"
: > "$STATE/trust-bundle.json"
out="$(sock https://dash.example.test dash.example.test)"
is   "the socket path refuses with exit 1" "$(tail -n1 <<<"$out")" "exit=1"
says "and names the push from the aggregator as the remedy" "$out" "fleet-trust-push --node"
out="$(cli)"; rc=$?
is   "the CLI path refuses the same way" "$rc" "1"
rm -f "$STATE/trust-bundle.json"

echo
echo "── refusing before it can do damage ──────────────────────────────"
out="$(printf 'https://dash.example.test\n' | APERIRE_DB_PATH="$DB" APERIRE_ADVISOR_STATE="$STATE" bash "$SUT" --from-socket 2>&1)"
is   "a payload that ends early is refused, and the exit line is still last" "$(tail -n1 <<<"$out")" "exit=1"
out="$(sock 'https://dash.example.test; rm -rf /' dash.example.test)"
is   "an origin that is not a plain origin is refused" "$(tail -n1 <<<"$out")" "exit=1"
out="$(sock https://dash.example.test 'not a host')"
is   "an rp_id that is not a host name is refused" "$(tail -n1 <<<"$out")" "exit=1"
out="$(ORIGIN=https://x APERIRE_ADVISOR_STATE="$STATE" bash "$SUT" 2>&1)"; rc=$?
is   "no database path is a refusal" "$rc" "1"
says "that names the variable" "$out" "APERIRE_DB_PATH"
out="$(ORIGIN=https://x APERIRE_DB_PATH="$DB" APERIRE_ADVISOR_STATE="$TMP/nowhere" bash "$SUT" 2>&1)"; rc=$?
is   "a state directory that is not there is a refusal, not a mkdir" "$rc" "1"
if [[ ! -d "$TMP/nowhere" ]]; then ok "and nothing was created"; else bad "nothing created" "$TMP/nowhere exists"; fi
out="$(bash "$SUT" --from-socket extra 2>&1 </dev/null)"; rc=$?
is   "an argument on the socket path is refused before anything is read" "$rc" "2"

echo
echo "── the credential read takes no startup file (#885, N1) ──────────"
# sqlite3 runs as the database's owner, so it must not read that account's
# rc file: a fake on PATH records its arguments and passes the call through.
mkdir -p "$TMP/spy"
cat > "$TMP/spy/sqlite3" <<SPY
#!/usr/bin/env bash
printf '%s\n' "\$*" >> "$TMP/spy/args"
exec $(command -v sqlite3) "\$@"
SPY
chmod +x "$TMP/spy/sqlite3"
PATH="$TMP/spy:$PATH" cli >/dev/null
says "the read passes -init /dev/null" "$(cat "$TMP/spy/args" 2>/dev/null)" "-init /dev/null -json"

echo
echo "── an update can tell the installed unit is the old one (#800) ───"
# Until this, an aggregator updated from a release before the fix kept the
# 2026-10-12 unit, CollectMode= at the end of [Service], and every trust sync
# logged "Unknown key name 'CollectMode' in section 'Service'" until someone
# ran --run trust-sync-grant by hand. Nothing in the update said to. The
# installer can now be asked, read only, whether the unit on disk is that one,
# so the update can refresh it (or name the step) without running a root
# install over a unit that is already right.
INST="$REPO_DIR/scripts/install-trust-sync-grant.sh"
UD="$TMP/units"
mkdir -p "$UD"
cat > "$UD/aperire-trust-sync@.service" <<'OLDUNIT'
# Written by scripts/install-trust-sync-grant.sh
[Unit]
Description=Aperire: sync the Advisor's trust store from the dashboard's database (connection %i)
Documentation=file:/usr/local/sbin/aperire-trust-sync

[Service]
ExecStart=/usr/local/sbin/aperire-trust-sync --from-socket
Environment=APERIRE_DB_PATH=/srv/aperire-one/data/aperire.db
StandardInput=socket
StandardOutput=socket
StandardError=socket
RuntimeMaxSec=60
SuccessExitStatus=1 3
CollectMode=inactive-or-failed
OLDUNIT
out="$(APERIRE_UNIT_DIR="$UD" bash "$INST" --stale 2>&1)"; rc=$?
is   "the 2026-10-12 unit (CollectMode= under [Service]) is stale: exit 0" "$rc" "0"
says "and it says so" "$out" "stale=1"

# The unit this tree writes now, taken from the installer's own heredoc.
awk '/^cat > "\$TMPV" <<EOF$/{on=1; next} on && /^EOF$/{exit} on' "$INST" > "$UD/aperire-trust-sync@.service"
out="$(APERIRE_UNIT_DIR="$UD" bash "$INST" --stale 2>&1)"; rc=$?
is   "the unit as it is written now is current: exit 1" "$rc" "1"
says "and says so" "$out" "stale=0"

rm -f "$UD/aperire-trust-sync@.service"
out="$(APERIRE_UNIT_DIR="$UD" bash "$INST" --stale 2>&1)"; rc=$?
is   "a host without the grant is not stale, it is absent: exit 3" "$rc" "3"
says "and says so" "$out" "stale=absent"

# The read-only check changes nothing and needs no root.
cp /dev/null "$TMP/units.before"
( cd "$UD" && ls -la ) > "$TMP/units.before"
APERIRE_UNIT_DIR="$UD" bash "$INST" --stale >/dev/null 2>&1
( cd "$UD" && ls -la ) > "$TMP/units.after"
if cmp -s "$TMP/units.before" "$TMP/units.after"; then ok "--stale writes nothing"; else bad "--stale writes nothing" "$(diff "$TMP/units.before" "$TMP/units.after")"; fi

# One verb at a time: --remove with --if-stale used to remove the grant.
for combo in "--remove --if-stale" "--remove --stale" "--stale --if-stale"; do
  # shellcheck disable=SC2086  # the words are the point
  out="$(APERIRE_UNIT_DIR="$UD" bash "$INST" $combo 2>&1)"; rc=$?
  if [[ $rc -eq 1 ]] && grep -q 'give one of them' <<<"$out"; then ok "$combo is refused before anything is done"
  else bad "$combo is refused" "exit $rc: $out"; fi
done
cat > "$UD/aperire-trust-sync@.service" <<'KEEPUNIT'
[Unit]
Description=x

[Service]
ExecStart=/bin/true
CollectMode=inactive-or-failed
KEEPUNIT
if command -v fakeroot >/dev/null 2>&1; then
  APERIRE_UNIT_DIR="$UD" fakeroot bash "$INST" --remove --if-stale >/dev/null 2>&1
  if [[ -f "$UD/aperire-trust-sync@.service" ]]; then ok "and the unit is still there after --remove --if-stale as root"
  else bad "--remove --if-stale as root removes nothing" "the unit was deleted"; fi
fi
rm -f "$UD/aperire-trust-sync@.service"

# --if-stale, as root: a current unit is left alone and a stale one goes on to
# the install. fakeroot gives the root the install insists on; the install
# itself is not run here (it needs systemd), so "went on" is shown by the
# first thing past the gate, which is the check for systemctl.
if command -v fakeroot >/dev/null 2>&1; then
  awk '/^cat > "\$TMPV" <<EOF$/{on=1; next} on && /^EOF$/{exit} on' "$INST" > "$UD/aperire-trust-sync@.service"
  out="$(APERIRE_UNIT_DIR="$UD" fakeroot bash "$INST" --if-stale 2>&1)"; rc=$?
  if [[ $rc -eq 0 ]] && grep -q 'is current, so nothing was changed' <<<"$out"; then
    ok "--if-stale over a current unit changes nothing and exits 0"
  else
    bad "--if-stale leaves a current unit alone" "exit $rc: $out"
  fi
  rm -f "$UD/aperire-trust-sync@.service"
  out="$(APERIRE_UNIT_DIR="$UD" fakeroot bash "$INST" --if-stale 2>&1)"; rc=$?
  if [[ $rc -eq 0 ]] && grep -q 'not installed here' <<<"$out"; then
    ok "--if-stale on a host without the grant does not install one"
  else
    bad "--if-stale does not install a grant that was never asked for" "exit $rc: $out"
  fi
  cat > "$UD/aperire-trust-sync@.service" <<'OLDUNIT2'
[Unit]
Description=x

[Service]
ExecStart=/bin/true
CollectMode=inactive-or-failed
OLDUNIT2
  mkdir -p "$TMP/emptytree"
  out="$(APERIRE_UNIT_DIR="$UD" APERIRE_INSTALL_TREE="$TMP/emptytree" fakeroot bash "$INST" --if-stale 2>&1)"; rc=$?
  if [[ $rc -ne 0 ]] && grep -q 'is out of date, so it is written again' <<<"$out" && grep -q 'no sync program' <<<"$out"; then
    ok "--if-stale over the old unit goes on to the install (it stops at the first thing it needs, the sync program)"
  else
    bad "--if-stale refreshes an old unit" "exit $rc: $out"
  fi
else
  echo "  skip  --if-stale rows need fakeroot (CI has it)"
fi
echo
printf '  %d passed, %d failed\n' "$PASS" "$FAIL"
[[ $FAIL -eq 0 ]]
