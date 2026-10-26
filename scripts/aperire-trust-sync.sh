#!/usr/bin/env bash
# Write the Advisor's trust store from the dashboard's database.
#
# The Advisor verifies passkey approvals against its OWN copy of the admins'
# public keys, advisor/state/credentials.json. This is the one program that
# writes that copy, and it is reached two ways:
#
#   aperire-auth advisor-sync        the operator, on the host. `add`, `del`,
#                                    `revoke` and `set-role` run it on their way
#                                    out. Origin and rp_id arrive in the
#                                    environment (ORIGIN, RPID), read from
#                                    authn.yaml by the caller.
#
#   --from-socket                    the dashboard, after a passkey was enrolled
#                                    in a browser. systemd hands this program the
#                                    accepted connection as its three streams;
#                                    the origin and rp_id are the two lines on
#                                    standard input, `exit=<code>` is the last
#                                    line out. install-trust-sync-grant.sh puts
#                                    the socket in place.
#
# Both paths do the same thing: read the admins' credentials out of the
# dashboard's database, merge them into the store, write it as the account that
# owns the Advisor's state directory. What crosses from the dashboard is never
# a key: the store is rebuilt from the database on disk, so the dashboard can
# ask for a sync and cannot say what goes in it beyond what it already wrote
# to its own database.
#
# What this refuses, on both paths:
#
#   - a store installed from an issuer's signed bundle (trust-bundle.json is
#     beside it). That store holds the AGGREGATOR's admins; rebuilding it from
#     this host's database would replace them with whatever local accounts
#     this box happens to have, and the first approval from the aggregator
#     would be refused. The remedy is a push from the aggregator, and this
#     says so.
#   - a credential id or key with a control character in it. Nothing in this
#     system produces one; refusing is more honest than sanitising.
#
# And on the socket path only: an rp_id that differs from the one the store
# already holds, or an origin the store does not already list (a store with no
# origins yet takes the first). Which relying party and which origins an
# approval may come from are configuration an operator changes deliberately,
# with the CLI, not something a request may widen.
#
# Environment:
#   APERIRE_DB_PATH        the dashboard's database (required)
#   APERIRE_ADVISOR_STATE  the Advisor's state directory (required)
#   ORIGIN, RPID           CLI path only; the socket path reads them from stdin

set -euo pipefail

MODE=cli
case "${1:-}" in
  "") ;;
  --from-socket) MODE=socket; shift ;;
  -h|--help) awk '/^[^#]/{exit} NR>1{sub(/^# ?/,""); print}' "${BASH_SOURCE[0]}"; exit 0 ;;
  *) echo "unknown argument: $1" >&2; exit 2 ;;
esac
[[ $# -eq 0 ]] || { echo "takes no further arguments" >&2; exit 2; }

DB="${APERIRE_DB_PATH:-}"
ADVISOR_STATE="${APERIRE_ADVISOR_STATE:-}"

# The state helper (#703). This program runs as root out of /usr/local/sbin,
# where its installer puts a copy beside it, and from a checkout when it is
# run from one. Same resolution as the sealer and the credential check: the
# installed name first, which a checkout never carries.
#
# Never taken from the environment (#1148): root runs this file, and a variable
# set in a root shell the login started would choose it. An installed name that
# is not what the installer put there is refused rather than passed over for
# the next one: a regular file, not a link, owned by root, writable by neither
# group nor other. A suite that needs a stand-in runs this program from a
# directory with a state-file.py beside it.
TRUST_STATE_TOOL=""
TRUST_STATE_TOOL_WHY=""
TRUST_STATE_TOOL_INSTALLED=/usr/local/sbin/aperire-state-file
TRUST_FILE_UID=0
installed_file_ok() { # $1 = a path root is about to run
  local meta
  [[ -f "$1" && ! -L "$1" && -r "$1" ]] || return 1
  meta="$(stat -c '%u:%a' -- "$1" 2>/dev/null)" || return 1
  [[ "${meta%%:*}" == "$TRUST_FILE_UID" ]] && (( (8#${meta##*:} & 8#022) == 0 ))
}
# Bash itself, no dirname: this has to resolve with a PATH that holds
# nothing, as a unit with a bare environment can have.
_src_dir="${BASH_SOURCE[0]}"
if [[ "$_src_dir" == */* ]]; then _src_dir="${_src_dir%/*}"; else _src_dir=.; fi
# CDPATH emptied: a relative program path would otherwise be looked up in
# the directories the environment names, and the helper and library are
# found beside whatever directory that finds.
_ts_here="$(CDPATH='' cd -- "$_src_dir" && pwd)"
for _ts_c in "$_ts_here/aperire-state-file" "$TRUST_STATE_TOOL_INSTALLED"; do
  [[ -e "$_ts_c" || -L "$_ts_c" ]] || continue
  if installed_file_ok "$_ts_c"; then
    TRUST_STATE_TOOL="$_ts_c"
  else
    TRUST_STATE_TOOL_WHY="$_ts_c is not a regular file owned by root that no one else can write"
  fi
  break
done
if [[ -z "$TRUST_STATE_TOOL" && -z "$TRUST_STATE_TOOL_WHY" && -f "$_ts_here/state-file.py" ]]; then
  TRUST_STATE_TOOL="$_ts_here/state-file.py"
fi
unset _ts_here _ts_c _src_dir
TAG=aperire-trust-sync

# ---- the last line, on the socket path -----------------------------
#
# An exit code does not cross a socket: when this program ends the connection
# closes carrying nothing about why. So on that path the status is PRINTED, as
# the last line, on every path including every refusal. Installed before
# anything can fail, and `$?` taken on the first line because everything
# below it would overwrite it.
on_exit() {
  local rc=$?
  if [[ "$MODE" == socket ]]; then printf 'exit=%s\n' "$rc"; fi
}
trap on_exit EXIT

# Every socket invocation says what it did in the journal, whatever the
# outcome: a store rewritten at the dashboard's request is the kind of thing
# worth finding later, and a refusal is what an operator watching the tab
# needs the words of. The CLI path speaks to its own terminal.
say() { # $1 = outcome word, rest = detail. Never a key.
  local outcome="$1"; shift
  if [[ "$MODE" == socket ]] && command -v logger >/dev/null 2>&1; then
    logger -t "$TAG" -p authpriv.notice -- "$outcome: $*" || true
  fi
  printf '%s: %s\n' "$outcome" "$*" >&2
}
die() { say "$1" "$2"; exit 1; }

# ---- the inputs ----------------------------------------------------
if [[ "$MODE" == socket ]]; then
  # Read positionally. There is no parser, no names to spoof and no line that
  # can be made to mean a different field by what is in it.
  IFS= read -r ORIGIN || die refused "the payload ended before the origin"
  IFS= read -r RPID   || die refused "the payload ended before the rp_id"
fi
ORIGIN="${ORIGIN:-}"
RPID="${RPID:-}"
[[ -n "$DB" ]]            || die refused "APERIRE_DB_PATH is not set, so there is no database to read"
[[ -n "$ADVISOR_STATE" ]] || die refused "APERIRE_ADVISOR_STATE is not set, so there is no store to write"
[[ -n "$ORIGIN" ]] || die refused "no origin. The Advisor needs to know which origin an approval may come from; guessing defeats the check."
[[ "$ORIGIN" =~ ^https?://[A-Za-z0-9.:_-]+(/[A-Za-z0-9._~/-]*)?$ ]] \
  || die refused "the origin is not a plain http(s) origin"
[[ -n "$RPID" ]] || RPID="$(printf %s "$ORIGIN" | sed -E 's#^https?://##; s#[:/].*$##')"
[[ "$RPID" =~ ^[A-Za-z0-9.-]{1,253}$ ]] || die refused "the rp_id is not a plain host name"

[[ -f "$DB" ]] || die refused "no database at $DB. Start the dashboard once to create it, or set APERIRE_DB_PATH."
[[ -d "$ADVISOR_STATE" ]] \
  || die refused "no Advisor state directory at $ADVISOR_STATE. Install the Advisor first; there is nothing to sync into."
command -v sqlite3 >/dev/null 2>&1 || die refused "sqlite3 is not installed, and the credentials are read with it"
command -v python3 >/dev/null 2>&1 || die refused "python3 is not installed, and the store is written with it"

# ---- a store an issuer installed is not ours to rebuild -------------
if [[ -e "$ADVISOR_STATE/trust-bundle.json" ]]; then
  die refused "this Advisor's trust store was installed from a signed bundle (trust-bundle.json is beside it). Rebuilding it from this host's database would replace the aggregator's admins with this box's own accounts. Push from the aggregator instead: bash scripts/aperire-auth.sh fleet-trust-push --node <this node>. If this host has left its fleet on purpose, remove trust-bundle.json and run the sync again."
fi

# ---- who reads, who writes ------------------------------------------
#
# The database is the dashboard account's file and the state directory is the
# Advisor's, and on a hardened host those are two different accounts with root
# the only thing that can act as both. So a root caller acts as each in turn,
# never as itself: sqlite3 run as root would leave a root-owned -shm beside a
# database the dashboard then cannot open, and a store written by root is one
# the Advisor cannot read. A non-root caller (the operator, on a box where
# they own the checkout) reads as themselves and elevates for the write only
# if the state directory is not theirs.
#
# Seeded with `env`, never empty: bash marks assignment-prefixes at parse
# time, so if the runner expanded to nothing the NAME=value word would become
# the command name.
as_user() { # $1 = account, rest = command
  local who="$1"; shift
  if command -v runuser >/dev/null 2>&1; then runuser -u "$who" -- "$@"
  else sudo -n -u "$who" "$@"; fi
}

db_owner="$(stat -c '%U' "$DB" 2>/dev/null || true)"
state_owner="$(stat -c '%U' "$ADVISOR_STATE" 2>/dev/null || true)"

READER=(env)
WRITER=(env)
if [[ $EUID -eq 0 ]]; then
  if [[ -n "$db_owner" && "$db_owner" != root ]]; then
    READER=(as_user "$db_owner" env)
  fi
  if [[ -n "$state_owner" && "$state_owner" != root ]]; then
    WRITER=(as_user "$state_owner" env)
    # A store left behind root-owned by an earlier run cannot be opened for
    # writing by the account that has to write it now. Handed back rather
    # than refused: the file is the Advisor's, whoever wrote it last.
    # Through the helper, not `chown <name>` (#703). Two name lookups, a
    # `stat` and then a `chown`, in a directory the Advisor's own account
    # owns: that account can put a link at the name between them and have
    # root hand away whatever it points at. `own` does the check and the
    # re-own on one descriptor and refuses anything that is not a
    # single-linked regular file.
    if [[ -e "$ADVISOR_STATE/credentials.json" ]] \
       && [[ "$(stat -c '%U' "$ADVISOR_STATE/credentials.json" 2>/dev/null || true)" != "$state_owner" ]]; then
      _ts_uid="$(id -u "$state_owner" 2>/dev/null || true)"
      if [[ -n "$_ts_uid" && -n "$TRUST_STATE_TOOL" ]] \
         && python3 -I "$TRUST_STATE_TOOL" own "$ADVISOR_STATE/credentials.json" "$_ts_uid" "" ""; then
        echo "  handed the existing trust store back to '$state_owner'" >&2
      else
        echo "  the existing trust store could not be handed back to '$state_owner'${TRUST_STATE_TOOL_WHY:+ ($TRUST_STATE_TOOL_WHY)}" >&2
      fi
    fi
    echo "  writing as '$state_owner', which owns the Advisor's state directory" >&2
  fi
elif [[ ! -w "$ADVISOR_STATE" ]]; then
  [[ -n "$state_owner" ]] || die refused "$ADVISOR_STATE could not be read"
  if sudo -n true 2>/dev/null; then
    WRITER=(sudo -n -u "$state_owner" env)
  elif [[ "$MODE" == cli ]] && sudo -v 2>/dev/null; then
    WRITER=(sudo -u "$state_owner" env)
  else
    die refused "$ADVISOR_STATE is owned by '$state_owner' and this account cannot write it; the Advisor owns its own state. Re-run with sudo available, or directly: sudo -u $state_owner $0"
  fi
  echo "  writing as '$state_owner', which owns the Advisor's state directory" >&2
fi

# ---- the admins' credentials, out of the database --------------------
#
# -json, not -separator. A device name is chosen by whoever enrolled the
# passkey and is only length-capped, so a name containing a newline and tabs
# used to parse as a SECOND row: an attacker-chosen credential_id and
# public_key written straight into the store that authorises approvals. JSON
# cannot be escaped that way: a separator inside a field stays inside it.
rows="$("${READER[@]}" sqlite3 -init /dev/null -json "$DB" \
  "SELECT c.credential_id AS credential_id, c.public_key AS public_key,
          COALESCE(c.name, u.username) AS label, u.username AS user, u.role AS role
     FROM auth_credentials c JOIN auth_users u ON u.id = c.user_id
    WHERE u.role = 'admin';")" \
  || die refused "could not read the credentials out of $DB"

# An empty result is NOT a reason to stop. Demoting the last admin must
# actually remove their trust; bailing out here would leave the demoted
# passkey able to approve, which is precisely the case the demotion was for.
if [[ -z "$rows" ]]; then
  echo "no admin has an enrolled passkey." >&2
  echo "clearing the Advisor's trust store so nothing can approve by passkey." >&2
fi

# ---- the store ------------------------------------------------------
#
# Rows travel by environment, not stdin: on the socket path stdin is the
# connection, and a heredoc already owns it here. The writer prints its
# summary as `name=value` fields on standard output, which is what the
# dashboard reads; everything said to a person goes to standard error.
rc=0
"${WRITER[@]}" ADVISOR_STATE="$ADVISOR_STATE" ORIGIN="$ORIGIN" RPID="$RPID" ROWS="$rows" MODE="$MODE" \
python3 -I - <<'PYEOF' || rc=$?
import json, os, sys, datetime
state = os.environ["ADVISOR_STATE"]
path  = os.path.join(state, "credentials.json")
mode  = os.environ["MODE"]
try:
    store = json.load(open(path))
except FileNotFoundError:
    store = {}
# The socket path may add keys the dashboard's database holds. It may not
# move the relying party or widen where an approval may come from: a store
# bound to one rp_id being rewritten for another, or taught a new origin, is
# a configuration change, and the CLI is where those are made.
if mode == "socket" and store.get("rp_id") and store["rp_id"] != os.environ["RPID"]:
    print(f"refused: the store is bound to rp_id {store['rp_id']!r} and the request "
          f"named {os.environ['RPID']!r}. Change the relying party with "
          f"aperire-auth advisor-sync on the host, not from the dashboard.", file=sys.stderr)
    sys.exit(3)
if mode == "socket" and store.get("origins") and os.environ["ORIGIN"] not in store["origins"]:
    print(f"refused: the store allows approvals from {', '.join(store['origins'])} and the "
          f"request named {os.environ['ORIGIN']!r}. Add an origin with "
          f"aperire-auth advisor-sync on the host, not from the dashboard.", file=sys.stderr)
    sys.exit(3)
store["rp_id"] = os.environ["RPID"]
store["origins"] = sorted(set(store.get("origins") or []) | {os.environ["ORIGIN"]})
old = {c["credential_id"]: c for c in store.get("credentials") or []}
new = {}
added = replaced = 0
rows = json.loads(os.environ.get("ROWS") or "[]")
for row in rows:
    cid   = (row.get("credential_id") or "").strip()
    pub   = (row.get("public_key") or "").strip()
    label = row.get("label") or ""
    # Defence in depth behind the JSON parse. A credential id or key with a
    # control character in it is not something this system ever produces, so
    # the honest response is to refuse the row and say so, not to sanitise it
    # into something that looks fine.
    if not cid or not pub:
        print("  skipped a credential row with an empty id or key", file=sys.stderr)
        continue
    if any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in cid + pub):
        print("  REFUSED a credential whose id or key contains control "
              "characters; this should not be possible; investigate",
              file=sys.stderr)
        continue
    # Replace rather than delete, matching lib/device-label.ts: stripping
    # turns "a\nb" into "ab", which reads as a different label than the one
    # someone typed.
    def clean(v, cap):
        return " ".join("".join(
            ch if ord(ch) >= 0x20 and ord(ch) != 0x7f else " " for ch in (v or "")).split())[:cap]
    label = clean(label, 80)
    # user and role land in a file the ledger quotes from, so a control
    # character in either would be a control character in the audit record.
    user = clean(row.get("user"), 254)
    role = clean(row.get("role"), 32)
    if cid in old:
        if old[cid].get("public_key") != pub:
            replaced += 1
    else:
        added += 1
    entry = {"credential_id": cid, "public_key": pub, "label": label}
    # Omitted when unknown rather than written as "", so the Go side's
    # omitempty and this writer agree on what "absent" looks like.
    if user:
        entry["user"] = user
    if role:
        entry["role"] = role
    entry["enrolled_at"] = (old.get(cid, {}).get("enrolled_at")
        or datetime.datetime.now(datetime.timezone.utc).isoformat())
    new[cid] = entry
removed = len(set(old) - set(new))
store["credentials"] = list(new.values())
store["updated_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
os.makedirs(state, exist_ok=True)
# A temporary file and a rename, so the Advisor, which re-reads this file on
# every use, never sees half a store.
tmp = path + ".tmp"
with open(tmp, "w") as f:
    json.dump(store, f, indent=2); f.write("\n")
os.chmod(tmp, 0o640)
# The group is the state directory's, not the writer's primary group. The
# directory is 0750 and shared with the service group so that the operator
# can READ the Advisor's state (advisor-trust, the audit ledger) without
# being able to write it; a file created by the Advisor's account lands in
# that account's own group by default, and then the operator's read fails
# with a permission error on the very file the guides tell them to inspect.
try:
    os.chown(tmp, -1, os.stat(state).st_gid)
except PermissionError:
    pass  # not a member of that group here; the mode is still 0640
os.replace(tmp, path)
print(f"  {added} added, {replaced} replaced, {removed} removed, {len(new)} trusted", file=sys.stderr)
print(f"  rp_id  {store['rp_id']}", file=sys.stderr)
print(f"  origin {', '.join(store['origins'])}", file=sys.stderr)
print(f"  {path}", file=sys.stderr)
print(f"trusted={len(new)}")
print(f"added={added}")
print(f"replaced={replaced}")
print(f"removed={removed}")
print(f"store={path}")
PYEOF
if (( rc != 0 )); then
  # The writer already said why on standard error; the journal gets one line.
  # Its exit code is kept (3 is a refusal the dashboard tells apart from a
  # failure to write), which is why this is not die.
  say refused "the store was not written"
  exit "$rc"
fi
if [[ "$MODE" == socket ]]; then
  say synced "the Advisor's trust store was rebuilt from $DB at the dashboard's request"
fi
