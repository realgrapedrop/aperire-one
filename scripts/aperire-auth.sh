#!/bin/bash
# Aperire — operator authentication CLI.
#
# Manages auth_users / auth_credentials / auth_sessions / auth_magic_links
# rows in the dashboard's sqlite DB. Run it on the dashboard host as yourself.
# Every read and write of the database runs as the account the dashboard unit
# names in User= (ADR 0024): your own login on a host installed before that,
# aperire-dashboard on a fresh one. When that is not you, it asks for your
# sudo password once and says why.
#
# Configuration lives in dashboard/config/authn.yaml. Edit that file (not
# this script). The CLI re-reads authn.yaml on every invocation, so
# changes take effect immediately for the next CLI command. Dashboard
# server-side reads it at startup; restart aperire-server to pick up
# session policy changes.
#
# Each operator's email IS their identity — there's no separate
# "username" anymore. The email is what they type at the lock-screen
# and what every sub-command below takes as the operator argument.
#
# Sub-commands:
#   add <email> --role <admin|monitor>  create a new operator AND issue their
#                                        enrollment magic link (printed, and
#                                        emailed when an email channel exists).
#                                        --role is required: admin may approve
#                                        Advisor actions, monitor sees the same
#                                        dashboard and approves nothing
#   del <email>                        remove an operator and all their passkeys + sessions
#   list                               list all operators
#   list-credentials <email>           list passkeys for an operator
#   revoke <email | credential-id>     revoke every passkey of an account, or one by id
#   list-sessions <email>              list sessions: active, expired or revoked
#   revoke-session <session-id>        kill a session
#   set-role <email> <role>            admin or monitor. Only an admin may approve
#                                        an Advisor action against the validator.
#                                        Both roles see the same dashboard.
#   advisor-sync                       copy admins' PUBLIC keys into the Advisor's
#                                        trust store. Not a second enrollment —
#                                        operators still enroll once via magic-link.
#                                        del / revoke / set-role re-run this for
#                                        you, and a passkey enrolled in the browser
#                                        asks for it through the dashboard's socket
#                                        (install-trust-sync-grant.sh). Run it
#                                        yourself on a host without that grant.
#   advisor-trust                      show what the Advisor currently trusts
#   magic-link <email> [purpose]       issue a single-use enrollment URL
#                                        purpose = enroll (default) | recover
#                                        If authn.yaml has magic_link.send_via_email: true
#                                        AND the email channel works, the URL is also
#                                        sent via Resend. URL is always printed to
#                                        stdout as a fallback.
#   fleet-trust-push [--node <label>]  aggregator only: push this host's admin
#                                        passkeys to every node in fleet.yaml so
#                                        they accept an approval given here.
#                                        --node limits it to one node
#   help                               this message
#
# Any command that changes who may approve (del, revoke, set-role) pushes the
# new trust set to every fleet node on its way out, and exits nonzero if a node
# did not take it. `add` pushes too, but only ever as a warning — a brand-new
# operator has no passkey yet, so the set cannot have changed, and account
# creation must not report failure because an unrelated node is down.
#
#   --no-push                          do the change, do not push it. For a
#                                        fleet where some nodes run a build
#                                        older than the trust-bundle route;
#                                        push those by hand afterwards.
#                                        (APERIRE_NO_TRUST_PUSH=1 does the same
#                                        for a non-interactive caller.)

set -euo pipefail

# Resolve through the ~/.local/bin symlink (install-aperire-cli.sh) so the repo
# dir is the real checkout, not the symlink's parent.
SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
# The install tree: this program's parent from a checkout (or through the
# ~/.local/bin link), and the tree APERIRE_INSTALL_TREE names when an
# installer runs a copy root staged out of the release (#764).
REPO_DIR="${APERIRE_INSTALL_TREE:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
DASHBOARD_DIR="${REPO_DIR}/dashboard"
AUTHN_YAML="${APERIRE_AUTHN_YAML:-${DASHBOARD_DIR}/config/authn.yaml}"
NOW="$(date +%s)"

# ── Locate node ────────────────────────────────────────────────────
# The documented way to install Node is nvm, which lives in the operator's
# home and is loaded from an interactive shell's profile. This script is run
# over SSH as often as not, where Ubuntu's .bashrc returns before nvm loads —
# so `node` is simply absent from PATH, and every read_authn call below
# silently returns its default. The visible symptom is an enrollment link
# pointing at http://localhost:7800 on a host whose dashboard is published
# somewhere else entirely: a link the operator cannot use, with nothing said
# about why. Resolve it the same way the installer does, and say so plainly
# when it cannot be found.
#
# The tree to look in is the install owner's, not the caller's. The one-line
# Advisor install runs this as root for the trust sync, and root has no nvm:
# $HOME is /root, node is under /home/<owner>/.nvm, and the sync refused with
# its reason swallowed (aperire4, 2026-09-05, #211). The owner's tree is the
# node the dashboard unit itself runs from, so it is the right one whoever
# is asking; the caller's own tree is the fallback, for a checkout nobody
# has installed as a service yet.
#
# Each lookup may find nothing, and finding nothing has to leave NODE_BIN
# empty rather than end the script (#320). `getent passwd` for an account
# with no entry exits 2, and `find` on a home with no .nvm exits 1; under
# `pipefail` that is the pipeline's status, and as the whole of an assignment
# it became the script's status, so `set -e` killed the CLI here, before
# read_authn could say what it could not read, which is the entire point of
# the paragraph above.
# First, the node the dashboard's own unit starts (#873 review, L5): that is
# the one binary the dashboard's account can execute by construction, which
# matters when the trust push re-runs as that account and the operator's
# home, with its nvm, is 0750. The same reading aperire-fleet-pair.sh makes.
#
# The library is loaded once, here. Loading it again further down would reset
# DA_ACCOUNT to nothing, and root's reads of authn.yaml need the account they
# run as before the first of them (#993).
NODE_BIN=""
# shellcheck source=scripts/dashboard-account-lib.sh
. "$SCRIPT_DIR/dashboard-account-lib.sh"
if { da_resolve_repo "$REPO_DIR" 2>/dev/null || true; [[ -n "$DA_UNIT" ]]; }; then
  _unit_node="$(sed -n 's/^ExecStart=//p' "$DA_UNIT" 2>/dev/null | grep -oE '/[^" ]*/node' | head -1 || true)"
  [[ -n "$_unit_node" && -x "$_unit_node" ]] && NODE_BIN="$_unit_node"
fi
[[ -n "$NODE_BIN" ]] || NODE_BIN="$(command -v node 2>/dev/null || true)"
if [[ -z "$NODE_BIN" ]]; then
  OWNER_HOME="$(getent passwd "$(stat -c %U "$REPO_DIR" 2>/dev/null)" 2>/dev/null | cut -d: -f6 || true)"
  for tree in "${OWNER_HOME:-}" "$HOME"; do
    [[ -n "$tree" && -d "$tree/.nvm/versions/node" ]] || continue
    NODE_BIN="$(find "$tree/.nvm/versions/node" -maxdepth 3 -path '*/bin/node' -type f 2>/dev/null | sort -V | tail -1 || true)"
    [[ -n "$NODE_BIN" ]] && break
  done
fi

# A missing node is not a missing key: falling back to the defaults here
# invents configuration the operator did not write. Refuse instead, once, in
# front of every read rather than inside the reader.
#
# It belongs here and not in read_authn because every call site is a command
# substitution: an `exit 1` down there ends the subshell, so the first call
# (the db_path probe, which is an `if` condition and therefore exempt from
# `set -e`) printed the refusal, returned an empty string that is not
# '__unset__', and warned about a db_path key the file does not contain. The
# operator got the same four-line refusal twice with a false warning between
# them, and the script carried on in between (#320).
if [[ -f "$AUTHN_YAML" && ( -z "$NODE_BIN" || ! -x "$NODE_BIN" ) ]]; then
  echo "error: cannot find node, so ${AUTHN_YAML} cannot be read." >&2
  echo "       Every value in it would silently fall back to a default —" >&2
  echo "       including public_url, which decides where enrollment links point." >&2
  echo "       Install Node, or run this from a shell where nvm is loaded." >&2
  exit 1
fi

# ── The dashboard's own code never runs as root (#993) ─────────────
# authn.yaml is read with the dashboard's js-yaml, and the trust push runs
# the dashboard's own JavaScript. Both are files under the install tree, which
# the login that owns it can change, and node itself sits in that login's nvm
# tree. Root runs none of it (ADR 0024). Run as root (the Advisor install's
# trust sync, `sudo aperire-auth ...`), every such step runs as the account
# the dashboard unit names, which already runs this same code as the server,
# and root reads back one value as text, checked for its shape before it is
# used (authn_value_ok).
#
# Not a reader of root's own: Python's standard library has no YAML parser,
# and a hand-written one would read some spelling of public_url or rp_id
# differently from the dashboard. Those two values are what the Advisor's
# trust store binds an approval to, so the one parser is the dashboard's.
#
# Root with no account to switch to (none resolved, or one that is root) runs
# nothing and says so, before the first read.
dash_code() {  # <command...>: as this caller, or as the dashboard's account when root
  if [[ $EUID -ne 0 ]]; then
    "$@"
    return
  fi
  if [[ -z "$DA_ACCOUNT" || "$DA_ACCOUNT" == root || "$(id -u "$DA_ACCOUNT" 2>/dev/null)" == 0 ]]; then
    return 125
  fi
  as_dashboard "$@"
}
if [[ $EUID -eq 0 && -f "$AUTHN_YAML" ]]; then
  if [[ -z "$DA_ACCOUNT" || "$DA_ACCOUNT" == root || "$(id -u "$DA_ACCOUNT" 2>/dev/null)" == 0 ]]; then
    echo "error: run as root, this reads ${AUTHN_YAML} as the account the dashboard runs as," >&2
    echo "       never as root, because reading it runs the dashboard's own code. There is no" >&2
    echo "       such account other than root here${DA_WHY:+ ($DA_WHY)}." >&2
    echo "       Run it as your own login instead (aperire-auth <command>): it asks sudo only" >&2
    echo "       for the steps that need root, and runs root-owned programs for them." >&2
    exit 1
  fi
fi

# ── Read a value from authn.yaml ───────────────────────────────────
# Uses the project's already-installed js-yaml so we don't pull in
# yet another YAML parser. Echoes the value (or the default) to stdout;
# never errors out on missing file or missing key.
#
# The program takes the dashboard directory, the file and the key as
# arguments, never pasted into its text, and finds js-yaml from the dashboard
# directory rather than from the working directory: a switched account runs
# from /. Exit 3 is "no such key".
# shellcheck disable=SC2016  # JavaScript, not shell
AUTHN_JS='
const [dir, file, key] = process.argv.slice(1);
try {
  const y = require("module").createRequire(dir + "/")("js-yaml");
  const c = y.load(require("fs").readFileSync(file, "utf8")) || {};
  let v = c;
  for (const k of key.split(".")) { v = v && typeof v === "object" ? v[k] : undefined; }
  if (v === undefined || v === null) process.exit(3);
  process.stdout.write(String(v));
} catch (err) { process.exit(4); }
'
# The shape each key may have, checked on what comes back before anything uses
# it (#993): from root, the answer is text another account's process printed.
# public_url and rp_id are what the Advisor's trust store binds an approval
# to, so they are held tightest: an origin is https, or http to this machine
# only (the shipped localhost default), and an rp_id is a host name.
AUTHN_HOST_RE='[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*'
authn_value_ok() {  # <key> <value>
  local LC_ALL=C v="$2" u
  [[ "$v" != *[[:cntrl:]]* && ${#v} -le 2048 ]] || return 1
  case "$1" in
    public_url)
      while IFS= read -r u; do
        u="${u#"${u%%[![:space:]]*}"}"; u="${u%"${u##*[![:space:]]}"}"
        [[ -z "$u" ]] && continue
        [[ "$u" =~ ^https://${AUTHN_HOST_RE}(:[0-9]{1,5})?/?$ \
           || "$u" =~ ^http://(localhost|127\.0\.0\.1|\[::1\])(:([0-9]{1,5}))?/?$ ]] || return 1
        # A port, when one is given, is 1 to 65535.
        if [[ "$u" =~ :([0-9]{1,5})/?$ ]]; then
          (( 10#${BASH_REMATCH[1]} >= 1 && 10#${BASH_REMATCH[1]} <= 65535 )) || return 1
        fi
      done < <(printf '%s\n' "$v" | tr ',' '\n') ;;
    rp_id)
      while IFS= read -r u; do
        u="${u#"${u%%[![:space:]]*}"}"; u="${u%"${u##*[![:space:]]}"}"
        [[ -z "$u" || "$u" =~ ^${AUTHN_HOST_RE}$ ]] || return 1
      done < <(printf '%s\n' "$v" | tr ',' '\n') ;;
    magic_link.ttl_minutes) [[ "$v" =~ ^[0-9]{1,6}$ ]] || return 1 ;;
    magic_link.send_via_email) [[ "$v" == true || "$v" == false ]] || return 1 ;;
  esac
  return 0
}
read_authn() {
  local key_path="$1"
  local default_val="$2"
  local out rc=0
  if [[ ! -f "$AUTHN_YAML" ]]; then
    echo "$default_val"
    return
  fi
  # The file is here, so there is a node: the guard above this function
  # refused the run otherwise.
  out="$(dash_code "$NODE_BIN" -e "$AUTHN_JS" -- "$DASHBOARD_DIR" "$AUTHN_YAML" "$key_path" 2>/dev/null)" || rc=$?
  # 3 is a key the file does not set, which is what a default is for. Any
  # other failure is a file that could not be read, said once per key rather
  # than passed off as the default (#320).
  if [[ $rc -ne 0 ]]; then
    if [[ $rc -ne 3 ]]; then
      local as=""
      [[ $EUID -eq 0 ]] && as=" as $DA_ACCOUNT"
      echo "warning: could not read $key_path from ${AUTHN_YAML}${as} (exit $rc), so its default is used." >&2
    fi
    echo "$default_val"
    return
  fi
  if [[ -z "$out" ]]; then
    echo "$default_val"
    return
  fi
  if ! authn_value_ok "$key_path" "$out"; then
    echo "warning: $key_path in ${AUTHN_YAML} is not a value this can use, so its default is used." >&2
    echo "$default_val"
    return
  fi
  printf '%s\n' "$out"
}

# One source of truth for where the database lives: APERIRE_DB_PATH, the same
# variable db.ts reads, with the same default of <repo>/data/aperire.db. The
# service installer writes it into /etc/aperire/aperire.env, so the CLI and the
# dashboard open the same file without either of them being told twice.
#
# A db_path key in authn.yaml is deliberately NOT read. The dashboard does not
# read one either, so honouring it here would move the CLI's database and not
# the server's: `add` would write the operator into a file the dashboard never
# opens, and that operator could never sign in. Say so if the key is present,
# on stderr — magic-link prints a URL to stdout that operators copy, and a
# warning mixed into it breaks the paste.
if [[ -f "$AUTHN_YAML" && "$(read_authn db_path '__unset__')" != '__unset__' ]]; then
  echo "warning: db_path in ${AUTHN_YAML} is ignored." >&2
  echo "         Set APERIRE_DB_PATH (or edit /etc/aperire/aperire.env) instead," >&2
  echo "         then delete the key. The dashboard does not read it." >&2
fi
DB="${APERIRE_DB_PATH:-${APERIRE_DB:-${REPO_DIR}/data/aperire.db}}"

# ── Whose database it is (ADR 0024 lane 4) ──────────────────────────
# The database, its -wal and -shm, sit in data/, which belongs to the
# account the dashboard unit runs as. Every sqlite3 call below goes through
# dbsql, which runs it AS that account: run as root it would leave root-owned
# -wal and -shm files the dashboard cannot open, and run as the operator it
# cannot open the file at all once the dashboard has its own account. The
# library that does it was loaded at the top, with the node lookup.
dbsql(){ as_dashboard_sqlite "$@"; }
# Every value read through dbsql is checked at its own assignment: an exit
# inside dbsql only leaves the $( ) around it, and a refused switch (125) or
# a failed query must never be read as an empty answer ("unknown operator",
# "no admins", "is now admin"). And a count goes into arithmetic only once it
# is a plain integer (#875 review, M1 and L1).
db_fail() {  # <exit status>
  echo "error: a database step did not run (exit $1)$( [[ "$1" == 125 ]] && echo ": could not act as $DA_ACCOUNT, the dashboard's account" ). Nothing after it was done." >&2
  exit 1
}
db_count() {  # <value> <what it counts>; exits unless a plain integer
  da_is_count "$1" && return 0
  echo "error: the database answered '$1' for $2, which is not a count. Nothing was changed." >&2
  exit 1
}
PUBLIC_URL_RAW="${APERIRE_PUBLIC_URL:-$(read_authn public_url 'http://localhost:7800')}"
# public_url may name more than one origin, comma-separated — the shape a
# dashboard reached at both a lab hostname and a production one needs, and the
# shape APERIRE_RP_ORIGIN documents. A link has to point at exactly one of
# them, so the list is split here, once, and everything below uses the first.
# Pasting the whole list into a URL produces "https://a,https://b/login.html"
# — a link that opens nothing, printed at the one moment an operator has no
# way to tell a broken link from a broken install.
#
# The token itself is origin-agnostic: it is redeemed against whichever origin
# the operator lands on, so a link built from the first origin still works if
# they sign in at the second. cmd_magic_link says so when there is more than
# one, rather than leaving the operator to discover it.
PUBLIC_URL_LIST=()
while IFS= read -r origin; do
  origin="${origin#"${origin%%[![:space:]]*}"}"   # trim leading blanks
  origin="${origin%"${origin##*[![:space:]]}"}"   # trim trailing blanks
  [[ -n "$origin" ]] && PUBLIC_URL_LIST+=("$origin")
# printf '%s\n', not '%s': without the trailing newline `read` returns non-zero
# on the final field and the loop drops it, so a two-origin public_url parsed
# as one and the note below never printed — a silent undercount, which is the
# failure mode this whole change exists to remove.
done < <(printf '%s\n' "$PUBLIC_URL_RAW" | tr ',' '\n')
PUBLIC_URL="${PUBLIC_URL_LIST[0]:-http://localhost:7800}"
SEND_VIA_EMAIL="$(read_authn magic_link.send_via_email 'false')"
EMAIL_SUBJECT="$(read_authn magic_link.email_subject 'Aperire — enroll your passkey')"
TTL_MIN="$(read_authn magic_link.ttl_minutes '15')"

if ! command -v sqlite3 >/dev/null 2>&1; then
  echo "error: sqlite3 not installed (apt install sqlite3)" >&2
  exit 1
fi
# help and advisor-trust never open the database, so they never ask for sudo.
_sub=""
for _a in "$@"; do [[ "$_a" == --no-push ]] || { _sub="$_a"; break; }; done
case "${_sub:-help}" in help|-h|--help|advisor-trust) _needs_db=0 ;; *) _needs_db=1 ;; esac
if [[ $_needs_db -eq 1 ]]; then
  # The unit that serves this checkout names the account. A dashboard with no
  # unit (pm2, or started by hand) is run by whoever owns data/, and that is
  # the account taken. Two units on one checkout, or one this cannot read, is
  # a refusal: guessing would write the database as the wrong account.
  _da_rc=0
  da_resolve_repo "$REPO_DIR" || _da_rc=$?
  if [[ $_da_rc -ge 2 ]]; then
    echo "error: $DA_WHY" >&2
    exit 1
  fi
  [[ -n "$DA_ACCOUNT" ]] || DA_ACCOUNT="$(id -un)"
  da_sudo_ready "aperire-auth reads and writes the operators in its database" || exit 1
  # 125 is as_dashboard's own "the switch was refused, nothing ran", which
  # is not "the file is not there" and is never read as it.
  _db_rc=0
  as_dashboard test -f "$DB" || _db_rc=$?
  if [[ $_db_rc -eq 125 ]]; then
    echo "error: could not act as $DA_ACCOUNT to open $DB; nothing was changed" >&2
    exit 1
  fi
  if [[ $_db_rc -ne 0 ]]; then
    echo "error: db not found at $DB (looked for as $DA_ACCOUNT)" >&2
    echo "       set APERIRE_DB_PATH, or start the dashboard once to create it" >&2
    exit 1
  fi
fi

# Wrap a string for safe inclusion in a single-quoted SQL literal.
sqlescape() {
  printf "%s" "$1" | sed "s/'/''/g"
}

cmd_add() {
  # Role is REQUIRED, not defaulted (operator decision, 2026-08-13): the
  # person creating an account decides its rights at creation, out loud —
  # a default would decide silently, and the two candidate defaults are
  # each wrong for somebody (admin over-grants a colleague, monitor
  # under-grants the first install). Missing role fails with the syntax
  # and what the options mean.
  local email="" role=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --role)   role="${2:-}"; shift; shift || true ;;
      --role=*) role="${1#--role=}"; shift ;;
      -*)       echo "error: unknown option: $1" >&2; exit 2 ;;
      *)        if [[ -z "$email" ]]; then email="$1"; else
                  echo "error: unexpected argument: $1" >&2; exit 2
                fi; shift ;;
    esac
  done
  if [[ -z "$email" || -z "$role" ]]; then
    echo "usage: aperire-auth add <email> --role <admin|monitor>" >&2
    echo >&2
    echo "  --role admin     may approve and run Advisor actions against the node" >&2
    echo "  --role monitor   sees the same dashboard, approves nothing" >&2
    echo >&2
    echo "  example: aperire-auth add you@example.com --role admin" >&2
    echo "  (change it later with: aperire-auth set-role <email> <role>)" >&2
    exit 2
  fi
  if [[ "$role" != "admin" && "$role" != "monitor" ]]; then
    echo "error: role must be admin or monitor (got: $role)" >&2
    exit 2
  fi

  # Email format check — must have a local part, an @, and a dotted domain,
  # with no spaces.
  # Loose on purpose; the actual deliverability check happens when
  # Resend tries to send a magic-link.
  if [[ ! "$email" =~ ^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$ ]]; then
    echo "error: email format looks wrong: $email" >&2
    exit 2
  fi

  # Email IS the identity. Hard fail on duplicates — sharing an inbox
  # is fine in real life, but inside the dashboard it would mean two
  # rows that can never be told apart at sign-in.
  local existing
  existing="$(dbsql "$DB" "SELECT id FROM auth_users WHERE username = '$(sqlescape "$email")' OR email = '$(sqlescape "$email")'")" || db_fail $?
  if [[ -n "$existing" ]]; then
    echo "error: '$email' already exists (id $existing)" >&2
    exit 1
  fi

  dbsql "$DB" "INSERT INTO auth_users (username, email, role, created_at) VALUES ('$(sqlescape "$email")', '$(sqlescape "$email")', '$role', $NOW)" || db_fail $?
  local new_id
  new_id="$(dbsql "$DB" "SELECT id FROM auth_users WHERE username = '$(sqlescape "$email")'")" || db_fail $?
  db_count "$new_id" "the new operator's id"
  echo "created operator: id=$new_id  $email"
  # The same row the Settings page writes for the same act, so the audit card
  # reads one history whichever door the operator came through.
  record_auth_event "operator_added" "$email" "{\"role\":\"$role\",\"via\":\"cli\"}"
  if [[ "$role" == "admin" ]]; then
    echo "role: admin — may approve Advisor actions."
    echo "      (After their passkey is enrolled in the browser, run"
    echo "      aperire-auth advisor-sync so the Advisor trusts it.)"
  else
    echo "role: monitor — sees everything, approves nothing."
    echo "      To let them approve Advisor actions: aperire-auth set-role $email admin"
  fi
  # Before the link, not after: the enrollment URL is the last thing on stdout
  # because operators copy it, and push output landing under it breaks the
  # paste.
  #
  # A brand-new operator has no passkey, so this CANNOT change who may approve
  # — it re-asserts the set that is already current. Kept anyway because it
  # costs nothing and heals a node that missed an earlier push, and warning-only
  # for the same reason: creating an account must not report failure because an
  # unrelated node is down. del / revoke / set-role, which really do change the
  # set, exit nonzero instead.
  auto_fleet_trust_push || echo "NOTE: the operator was created; the trust re-assert above did not reach every node." >&2

  echo
  # One step, not two (operator feedback): creating an account is only ever
  # done to enroll a passkey, so the enrollment link is issued right here —
  # printed for copy/paste (email, text, hand it over), and emailed to the
  # operator directly when an email channel is configured. The link is
  # single-use with a short TTL; if it expires before it's redeemed,
  # re-issue with `aperire-auth magic-link <email>` — the account persists.
  cmd_magic_link "$email" enroll
}

cmd_del() {
  local email="${1:-}"
  if [[ -z "$email" ]]; then
    echo "usage: aperire-auth del <email>" >&2
    exit 2
  fi
  local user_id
  user_id="$(dbsql "$DB" "SELECT id FROM auth_users WHERE username = '$(sqlescape "$email")'")" || db_fail $?
  if [[ -z "$user_id" ]]; then
    echo "error: unknown operator: $email" >&2
    exit 1
  fi
  db_count "$user_id" "the operator id"

  # Pre-count for the operator's confirmation summary, and the audit row.
  local cred_count sess_count link_count old_role
  old_role="$(dbsql "$DB" "SELECT role FROM auth_users WHERE id = $user_id")" || db_fail $?
  cred_count="$(dbsql "$DB" "SELECT COUNT(*) FROM auth_credentials WHERE user_id = $user_id")" || db_fail $?
  db_count "$cred_count" "the passkeys"
  sess_count="$(dbsql "$DB" "SELECT COUNT(*) FROM auth_sessions    WHERE user_id = $user_id")" || db_fail $?
  db_count "$sess_count" "the sessions"
  link_count="$(dbsql "$DB" "SELECT COUNT(*) FROM auth_magic_links  WHERE user_id = $user_id")" || db_fail $?
  db_count "$link_count" "the links"

  # Cascade manually — sqlite3 CLI doesn't honor REFERENCES by default
  # (no `PRAGMA foreign_keys = ON` per session). Wrapping in a single
  # transaction so a partial failure doesn't leave dangling rows.
  dbsql "$DB" "
    BEGIN;
    DELETE FROM auth_credentials WHERE user_id = $user_id;
    DELETE FROM auth_sessions    WHERE user_id = $user_id;
    DELETE FROM auth_magic_links WHERE user_id = $user_id;
    DELETE FROM auth_users       WHERE id = $user_id;
    COMMIT;
  " || db_fail $?

  echo "deleted operator '$email' (id $user_id)"
  echo "  $cred_count passkey$([ "$cred_count" = "1" ] || echo 's')"
  echo "  $sess_count session$([ "$sess_count" = "1" ] || echo 's')"
  echo "  $link_count outstanding magic-link$([ "$link_count" = "1" ] || echo 's')"
  # One row for the act, the shape the Settings page writes. The passkeys went
  # with the account; a credential_removed row per key would name a revocation
  # nobody performed.
  record_auth_event "operator_removed" "$email" \
    "{\"role\":\"$(sqlescape "$old_role")\",\"passkeys\":$cred_count,\"sessions\":$sess_count,\"links\":$link_count,\"via\":\"cli\"}"
  auto_advisor_sync
  # Last statement, and its status is this command's. Nothing may run after it:
  # a stray echo would overwrite a failed push with a success.
  local rc=0
  auto_fleet_trust_push || rc=$?
  return "$rc"
}

cmd_list() {
  local rows
  # The role sits beside the email because it is the fact an operator is
  # usually looking for here: who may approve, who only watches. An
  # unassigned legacy value prints as "-" rather than a word the docs do not
  # define.
  rows="$(dbsql -separator $'\t' "$DB" "
    SELECT u.id, u.username,
           CASE WHEN u.role IN ('admin','monitor') THEN u.role ELSE '-' END,
           (SELECT COUNT(*) FROM auth_credentials c WHERE c.user_id = u.id),
           COALESCE(datetime(u.last_login_at, 'unixepoch'), 'never')
    FROM auth_users u ORDER BY u.id ASC
  ")" || db_fail $?
  echo "id  email                                  role     credentials  last_login"
  echo "──  ─────────────────────────────────────  ───────  ───────────  ─────────────────────"
  [[ -z "$rows" ]] || printf '%s\n' "$rows" | awk -F'\t' '{ printf "%-3s %-37s  %-7s  %-12s %s\n", $1, $2, $3, $4, $5 }'
}

# ── The auth audit ───────────────────────────────────────────────────────
#
# Every command here that changes who may do what writes a row to auth_events.
#
# This is the gap that mattered most: `set-role` rewrites the Advisor's trust
# store as a side effect, so one command silently changes the set of passkeys
# that can authorise an upgrade — and until now nothing anywhere recorded that
# it had happened. The Advisor observes its OWN store changing (advisord's
# trust.store_changed); this is the other half, recording the decision rather
# than its downstream effect.
#
# The actor is the shell account. It is not a passkey and the row does not
# pretend otherwise — but shell access outranks the role system anyway (it is
# how roles are assigned at all), so naming the account is naming the
# strongest identity that exists on this path.
record_auth_event() {
  local event="$1" target="${2:-}" detail="${3:-}"
  local actor
  actor="$(id -un 2>/dev/null || echo unknown)"
  # Best effort by design. A CLI command that succeeded must not be reported
  # as failed because its audit row could not be written — but the operator is
  # told, because an unrecorded privilege change is exactly what this exists
  # to prevent.
  if ! dbsql "$DB" "
    INSERT INTO auth_events (at, actor, actor_role, event, target, detail)
    VALUES (strftime('%s','now'), 'cli:$(sqlescape "$actor")', 'shell',
            '$(sqlescape "$event")', '$(sqlescape "$target")', '$(sqlescape "$detail")');
  " 2>/dev/null; then
    echo "WARNING: the change was made but could not be written to the auth audit." >&2
  fi
}

# ── Roles ────────────────────────────────────────────────────────────────
#
# Two roles, and only one of them can approve an Advisor action against the
# validator. Both see the same dashboard: hiding read-only data from a
# colleague is not a security property, and pretending otherwise is how people
# end up sharing the admin login. Approving a change to a validator is a
# different question, and that is the one the role answers.
cmd_set_role() {
  local email="${1:-}" role="${2:-}"
  if [[ -z "$email" || -z "$role" ]]; then
    echo "usage: aperire-auth set-role <email> <admin|monitor>" >&2
    exit 2
  fi
  if [[ "$role" != "admin" && "$role" != "monitor" ]]; then
    echo "error: role must be admin or monitor" >&2
    exit 2
  fi
  # Read the old role BEFORE the update: "was admin, now monitor" is the
  # entry an auditor needs, and after the write it is unrecoverable.
  local was
  was="$(dbsql "$DB" "SELECT role FROM auth_users WHERE username = '$(sqlescape "$email")'")" || db_fail $?
  local n
  n="$(dbsql "$DB" "UPDATE auth_users SET role = '$role' WHERE username = '$(sqlescape "$email")'; SELECT changes();")" || db_fail $?
  db_count "$n" "the rows changed"
  if [[ "$n" == "0" ]]; then
    echo "error: unknown operator: $email" >&2
    exit 1
  fi
  record_auth_event "role_change" "$email" "{\"from\":\"${was:-unknown}\",\"to\":\"$role\"}"
  echo "$email is now $role"
  if [[ "$role" == "monitor" ]]; then
    echo "They keep full read access. They can no longer approve Advisor actions."
    # Warn — don't refuse — when this leaves nobody able to approve. Shell
    # access outranks the role system (it's how roles are assigned at all),
    # so the operator gets the fact and the way back, not a locked door.
    local admins_left
    admins_left="$(dbsql "$DB" "SELECT COUNT(*) FROM auth_users WHERE role = 'admin'")" || db_fail $?
    db_count "$admins_left" "the admins left"
    if [[ "$admins_left" == "0" ]]; then
      echo
      echo "WARNING: that was the last admin. Nobody can approve Advisor actions"
      echo "         now. To restore: aperire-auth set-role <email> admin"
    fi
  else
    echo "They may now approve Advisor actions with their own passkey."
  fi
  auto_advisor_sync
  local rc=0
  auto_fleet_trust_push || rc=$?
  return "$rc"
}

# ── Advisor trust ────────────────────────────────────────────────────────
#
# The Advisor verifies approval signatures against public keys it holds
# itself. Verification is worth nothing if the key can be supplied by whoever
# presents the approval — so the Advisor cannot simply be handed one at verify
# time, and reading this database directly would settle open decision #19 by
# accident.
#
# This is NOT a second enrollment. Operators enroll once, through the magic
# link, exactly as before; this copies the resulting public key across. It is a
# copy, and that has an honest cost: enrolling, demoting or revoking does not
# reach the Advisor until this is re-run. `advisor-trust` shows what it
# currently holds, so the difference is visible rather than silent.
ADVISOR_STATE="${APERIRE_ADVISOR_STATE:-$REPO_DIR/advisor/state}"

# Any command that changes who may hold an approving key leaves the Advisor's
# copy stale until advisor-sync runs, so every CLI mutation rides the sync on
# its way out. A passkey enrolled in a BROWSER is the change the CLI cannot
# see; the dashboard asks for the same sync through the socket
# install-trust-sync-grant.sh puts in place (the store is rebuilt from the
# database either way; nothing the dashboard sends goes into it). On a host
# without that grant, `advisor-trust` shows the difference and the Advisor tab
# names this command.
auto_advisor_sync() {
  if [[ ! -d "$ADVISOR_STATE" ]]; then
    echo "(no Advisor on this host — trust re-sync skipped)"
    return 0
  fi
  echo
  echo "the key set changed — re-syncing the Advisor's trust store:"
  # Recorded on the dashboard side too, not only as the Advisor's observation
  # of its own store. The two are different claims: this says the sync was
  # ASKED FOR by this account, the Advisor's trust.store_changed says what it
  # actually saw change. Either alone can be made to lie; together they cannot
  # both be made to agree on a story that did not happen.
  record_auth_event "trust_synced" "advisor" "{\"trigger\":\"auto after a CLI change\"}"
  ( cmd_advisor_sync ) || {
    # On a managed node the sync is REFUSED on purpose, by
    # scripts/aperire-trust-sync.sh's own guard: rebuilding this store from
    # this host's database would replace the aggregator's admins with this
    # box's local accounts. So "until advisor-sync succeeds" is a remedy that
    # must never run here, and the true sentence is the aggregator's (#489).
    local managed_by mb_rc=0
    managed_by="$(trust_managed_by)" || mb_rc=$?
    if [[ $mb_rc -ne 0 ]]; then
      trust_unreadable_error "the Advisor sync did not run and the managed state of this node is unknown"
      echo "       Every node and this Advisor still enforce the PREVIOUS set of passkeys." >&2
      return 0
    fi
    if [[ -n "$managed_by" ]]; then
      say_managed_note "$managed_by" changed
      return 0
    fi
    echo "NOTE: the change above is saved, but the Advisor still trusts the OLD" >&2
    echo "      key set until advisor-sync succeeds (instructions above)." >&2
  }
}

# ── Who signs the trust bundle on this host ──────────────────────────────
#
# Three shapes, and this tool knew only two of them.
#
#   an aggregator   fleet-trust.yaml holds `private_key:`. It signs bundles and
#                   pushes them to every node in fleet.yaml.
#   no signing key  there is no fleet-trust.yaml at all. Nothing to push with,
#                   and nothing pushes to this host either.
#   MANAGED         fleet-trust.yaml holds a `peers:` map and no private_key:
#                   the aggregator's PUBLIC key, filed under the label it signs
#                   as (scripts/aperire-fleet-pair.sh writes it as
#                   peers.aggregator). This host is a destination, never an
#                   issuer.
#
# The third shape has a READABLE file, so it sailed past the "no signing key"
# guard below and died inside the push with `error: no private_key`, under a
# warning telling the operator to retry a command that cannot run there
# (#489). It was found on revoke, which is the worst place for it: the local
# revoke had worked, and the sentence the operator needed was that the
# aggregator's bundle is what still trusts the key.
#
# ── Whose push it is (#872) ──────────────────────────────────────────────
#
# A push reads three things: the signing key in fleet-trust.yaml (the
# dashboard account's alone, 0600, #868), fleet.yaml, and every node's
# Advisor token (/etc/aperire/fleet-tokens, root on the shared group). Where
# the dashboard runs as its own account (ADR 0024), the operator can read none
# of the first and third, so a push run as the operator used to stop on
# "[[ -r ]]" and print "no signing key" about a key that is there, and a
# fleet.yaml it could not read was taken for "not an aggregator", silently.
#
# So the push runs AS the dashboard's account: the same command, as the same
# account, that the dashboard runs for its own pushes (lib/trust-push-hook.ts).
# Root drops to that account too, so root never runs the tree's node for a
# push. On a host where the dashboard runs as the operator nothing switches.
# The account comes from dashboard-account-lib.sh (ADR 0024 lane 4), the one
# rule every tool uses for it. A failure to switch is a refusal by name and a
# non-zero exit, never a note.
#
# The re-run is told it is one (APERIRE_TRUST_PUSH_AS_DASHBOARD=1) so it
# never tries to switch again, and is handed the database path and nothing
# else: it reads the key, the registry and the tokens itself.
trust_push_account_resolve() {  # sets DA_ACCOUNT; 0, or 1 with the reason said
  if ! declare -F as_dashboard >/dev/null 2>&1; then
    # shellcheck source=scripts/dashboard-account-lib.sh
    . "$SCRIPT_DIR/dashboard-account-lib.sh" || return 1
  fi
  local rc=0
  da_resolve_repo "$REPO_DIR" || rc=$?
  if [[ $rc -ge 2 || -z "$DA_ACCOUNT" ]]; then
    echo "error: could not tell which account runs the dashboard, so the trust push did not run: ${DA_WHY:-no account resolved}" >&2
    return 1
  fi
  return 0
}

# trust_push_switch_needed: true when the push has to run as another account.
trust_push_switch_needed() {
  [[ "${APERIRE_TRUST_PUSH_AS_DASHBOARD:-0}" != 1 ]] || return 1
  trust_push_account_resolve || return 2
  da_switch_needed
}

# trust_read <file> <command...>: a public read of a trust file (a grep -q, a
# label), run here when this process can read it and as the dashboard's
# account when it cannot. Never used to print the key itself.
#
# Returns the command's own status (0, 1, 2 for grep), or 125 when the switch
# itself did not happen. Those two must never meet: a refused `sudo -n` or a
# failed `runuser` also exits 1, which is grep's "no match", and that read as
# "no signing key" and skipped the push with exit 0 (#873 review, M1). So the
# switch is checked before it is used, and the command's status is carried
# back offset by 100, so any other status is the switch failing.
trust_read() {
  local f="$1"; shift
  if [[ -r "$f" ]]; then "$@"; return; fi
  trust_push_account_resolve || return 125
  da_switch_needed || { "$@"; return; }
  if [[ "$(id -u)" != 0 ]] && ! da_sudo_ready "reading $f, which is that account's"; then
    return 125
  fi
  local rc=0
  # shellcheck disable=SC2016  # the inner shell's own "$@" and $r
  as_dashboard bash -c '"$@"; r=$?; [ "$r" -le 2 ] && exit $((r + 100)); exit "$r"' _ "$@" || rc=$?
  if (( rc >= 100 && rc <= 102 )); then return $((rc - 100)); fi
  return 125
}

# One parser for the private key, read by the detector and by the push itself,
# so the two can never disagree about the same file.
trust_private_key() {  # $1 = fleet-trust.yaml
  [[ -r "$1" ]] || return 0
  awk -F': *' '/^private_key:/{print $2; exit}' "$1"
}

# The label this host's trust is managed under, or empty when it is not
# managed. A file with a private key is an ISSUER and is never managed, even
# when it also lists peers: an aggregator holds its own peers map.
trust_managed_by() {
  local f="$DASHBOARD_DIR/config/fleet-trust.yaml" rc=0
  [[ -e "$f" ]] || return 0
  # Returns 125, with nothing printed, when the file could not be read at all
  # (a refused switch, or a read that failed). That is not "no key": a caller
  # says the file could not be read, never that no signing key exists (#873
  # re-review, N1).
  trust_read "$f" grep -q '^private_key:' "$f" || rc=$?
  case $rc in
    0) return 0 ;;   # an issuer is never managed
    1) ;;            # readable, no private_key: carry on
    *) return 125 ;;
  esac
  # The first key under `peers:`, which is the label the bundle is signed as.
  rc=0
  trust_read "$f" awk '
    /^peers:[[:space:]]*$/ { inpeers = 1; next }
    /^[^[:space:]#]/       { inpeers = 0 }
    inpeers && /^[[:space:]]+[A-Za-z0-9_.-]+:[[:space:]]*[^[:space:]]/ {
      sub(/^[[:space:]]+/, ""); sub(/:.*$/, ""); print; exit
    }
  ' "$f" || rc=$?
  [[ $rc -eq 0 ]] || return 125
  return 0
}

# Said by every caller of trust_managed_by that got 125 back.
trust_unreadable_error() {  # $1 = what was not done
  echo >&2
  echo "ERROR: $1: config/fleet-trust.yaml" >&2
  echo "       could not be read, as $(id -un) or as the dashboard's account." >&2
}

# What is true on a managed node, said once and printed by every tail that
# would otherwise offer a remedy for another machine.
#
# Three facts, because all three are the operator's next question: this host
# cannot push, the change it just made is real, and what the Advisor here
# enforces is the aggregator's bundle, which changes on the aggregator's next
# push and not before.
#
# The command is deliberately UNSCOPED. This node's own registry label need not
# be the label the aggregator files it under, so a `--node <label>` built on
# this side can name a row the aggregator does not have; the bare push is
# correct there whatever this node is called.
#
# Said once per run. A revoke on a managed node reaches this from the Advisor
# sync tail and again from the push tail, and one paragraph answers both: no
# bundle is signed here, and the aggregator's is the one that counts.
MANAGED_NOTE_SAID=0
say_managed_note() {  # $1 = the aggregator's label, $2 = "changed" when a local change preceded this
  [[ "$MANAGED_NOTE_SAID" == "1" ]] && return 0
  MANAGED_NOTE_SAID=1
  echo >&2
  echo "NOTE: trust on this node is managed by \"$1\" (config/fleet-trust.yaml holds" >&2
  echo "      that peer's public key and no signing key of this host's own), so no" >&2
  echo "      bundle can be signed or pushed from here." >&2
  if [[ "${2:-}" == "changed" ]]; then
    echo "      The local set DID change: this dashboard's database no longer holds it." >&2
  fi
  echo "      What the Advisor here enforces is the bundle \"$1\" last pushed, so a" >&2
  echo "      passkey revoked here still approves here until the next push." >&2
  echo "      Run this on \"$1\", not on this host:" >&2
  echo "          bash scripts/aperire-auth.sh fleet-trust-push" >&2
}

# The fleet half of the same idea, and the fix for the failure that named it
# (2026-08-19): an admin enrolled at the aggregator could not break glass on
# stock-node2, because the bundle carrying their key had only ever been pushed
# to node1. A trust set that reaches one node out of three is not a fleet trust
# set; it is a trap that springs at the worst moment, in front of a person
# holding a passkey that works everywhere else.
#
# So every command that changes who may approve pushes on its way out. The push
# is loud per node (fleet-trust-push prints one line each, naming the node and
# what the node itself said), and the exit status carries: a caller that saw
# "revoked" must not also see success when two nodes still hold the revoked
# key. Revocation is the case that matters most, and it is the one where a
# silent partial push is worst.
#
# Skipped, with a reason printed, when this host is not an aggregator (no
# fleet.yaml), has no signing key (no fleet-trust.yaml) or has no node with an
# advisor stack to push to. None of those is a failure.
auto_fleet_trust_push() {
  if [[ "$NO_PUSH" == "1" ]]; then
    echo "(--no-push: the trust bundle was NOT pushed; run aperire-auth fleet-trust-push when ready)"
    return 0
  fi
  # By existence, never by readability (#872): dashboard/config is the
  # operator's 0755 directory, so the names are always visible, and a file
  # this account cannot read is the dashboard's, not missing.
  if [[ ! -e "$DASHBOARD_DIR/config/fleet.yaml" ]]; then
    return 0   # not an aggregator — nothing to push to, and nothing to say
  fi
  if [[ ! -e "$DASHBOARD_DIR/config/fleet-trust.yaml" ]]; then
    echo "NOTE: this host has a fleet but no signing key (config/fleet-trust.yaml)," >&2
    echo "      so the change was NOT pushed. Run the fleet trust exchange first." >&2
    return 0
  fi
  # Does it hold a signing key? Asked of the file as whoever can read it.
  local key_rc=0
  trust_read "$DASHBOARD_DIR/config/fleet-trust.yaml" grep -q '^private_key:' "$DASHBOARD_DIR/config/fleet-trust.yaml" || key_rc=$?
  if [[ $key_rc -ge 2 ]]; then
    echo >&2
    echo "ERROR: the change above is saved HERE, but it was NOT pushed: config/fleet-trust.yaml" >&2
    echo "       could not be read, as $(id -un) or as the dashboard's account." >&2
    echo "       Every node still enforces the PREVIOUS set of passkeys." >&2
    echo "       Retry with: aperire-auth fleet-trust-push" >&2
    return 1
  fi
  # A trust file with no signing key in it. Answered BEFORE the push
  # is attempted rather than after it fails, and 0, because the local change
  # succeeded and nothing on this host failed (#489).
  if [[ $key_rc -eq 1 ]]; then
    local managed_by mb_rc=0
    managed_by="$(trust_managed_by)" || mb_rc=$?
    if [[ $mb_rc -ne 0 ]]; then
      echo >&2
      echo "ERROR: the change above is saved HERE, but it was NOT pushed: config/fleet-trust.yaml" >&2
      echo "       could not be read, as $(id -un) or as the dashboard's account." >&2
      echo "       Every node still enforces the PREVIOUS set of passkeys." >&2
      echo "       Retry with: aperire-auth fleet-trust-push" >&2
      return 1
    fi
    if [[ -n "$managed_by" ]]; then
      say_managed_note "$managed_by" changed
    else
      # A trust file that names nobody either. Same fact as no file at all,
      # and the same sentence, rather than the push's `no private_key`.
      echo >&2
      echo "NOTE: this host has a fleet but no signing key in config/fleet-trust.yaml," >&2
      echo "      so the change was NOT pushed. Run the fleet trust exchange first." >&2
    fi
    return 0
  fi
  echo
  echo "pushing the new trust set to the fleet:"
  # A subshell so cmd_fleet_trust_push's own `exit` paths (missing public_url,
  # unreadable key) end the push and not the command that already succeeded.
  local rc=0
  ( cmd_fleet_trust_push ) || rc=$?
  if [[ $rc -eq 3 ]]; then
    # The job builder's "no node has an advisor stack" — a registry of read-only
    # peers is a normal shape, not a failed push.
    echo "(no fleet node has an Advisor to push to)"
    return 0
  fi
  if [[ $rc -eq 5 ]]; then
    echo >&2
    echo "WARNING: the change above is saved HERE, but it was NOT pushed: another trust push" >&2
    echo "         held the push lock past the wait, so this push did not start. Every node" >&2
    echo "         still enforces the PREVIOUS set of passkeys, a revoked key included." >&2
    echo "         Retry once that push is done: aperire-auth fleet-trust-push" >&2
    return 1
  fi
  if [[ $rc -ne 0 ]]; then
    echo >&2
    echo "WARNING: the change above is saved HERE, but at least one node did not take it." >&2
    echo "         Those nodes still enforce the PREVIOUS set of passkeys — a revoked" >&2
    echo "         key still approves there until the push succeeds." >&2
    echo "         Retry with: aperire-auth fleet-trust-push [--node <label>]" >&2
  fi
  return $rc
}

# The program root runs to write the Advisor's trust store has to be the
# root-owned one. Absent, this stops and says how it gets there, rather than
# falling back to the checkout's copy under root.
trust_sync_program_missing() { # $1 = its path
  echo "error: $1 is not on this host. It is the program root runs to write the" >&2
  echo "       Advisor's trust store, and aperire-auth will not run the copy in the" >&2
  echo "       checkout as root instead, because the login that owns the checkout can" >&2
  echo "       change it. It is installed with the Advisor:" >&2
  echo "           curl -fsSL https://get.aperire.one/advisor | bash" >&2
  echo "       or, from the menu, bash ${REPO_DIR}/aperire-one and 3) Advisor." >&2
  exit 1
}

cmd_advisor_sync() {
  local origin rp_id
  # First entry of each: both accept comma-separated lists for a dashboard
  # reachable under two names, and the Advisor's store is bound to one.
  origin="$(read_authn "public_url" "")"
  origin="$(printf %s "${origin%%,*}" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//; s#/+$##')"
  if [[ -z "$origin" ]]; then
    echo "error: no public_url in authn.yaml. The Advisor needs to know which" >&2
    echo "       origin an approval may come from; guessing defeats the check." >&2
    exit 1
  fi
  # rp_id comes from the config rather than being derived, because the config
  # is what WebAuthn credentials were actually bound to. Deriving it from the
  # URL would be right until the day someone sets them differently on purpose.
  rp_id="$(read_authn "rp_id" "")"
  rp_id="$(printf %s "${rp_id%%,*}" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')"

  # One implementation of "read the admins out of the database, write the
  # store as the Advisor's owner": scripts/aperire-trust-sync.sh. The same file
  # sits behind the dashboard's socket (install-trust-sync-grant.sh), so a
  # browser enrollment and this command cannot disagree about what the store
  # holds. It works out for itself which accounts read and write, elevating
  # only where the state directory is not the caller's.
  mkdir -p "$ADVISOR_STATE" 2>/dev/null || true
  # The sync reads the database as the dashboard's account and writes the
  # store as the Advisor's. Run by root it acts as each in turn; run by
  # anyone else it reads as itself. So when this caller is not the
  # dashboard's account (a host where the dashboard has its own, ADR 0024),
  # it runs under your sudo, the same as `sudo aperire-auth advisor-sync`
  # always has. On a host where the dashboard runs as you, nothing changes.
  #
  # Anything root runs is the root-owned copy the grant installer placed under
  # /usr/local/sbin after its own checks (#943), never the file in this
  # checkout: the login that owns the checkout can change that one. Root here
  # is the sudo leg and a caller that already is root; the one leg left on the
  # checkout's file is an ordinary account acting as itself, which crosses
  # nothing.
  # A constant, with no variable and no switch that can name another: what root
  # runs is never chosen by the login's environment (#943 review). The program
  # is run as it stands and its absence is read from how it failed (126 or 127
  # from env or the shell), so the check is made by whoever runs it.
  local sync_bin=/usr/local/sbin/aperire-trust-sync rc=0 root_leg=0
  if [[ $EUID -ne 0 ]] && [[ -n "$DA_ACCOUNT" ]] && da_switch_needed; then
    root_leg=1
    local _sudo=(sudo -n)
    [[ -t 0 ]] && _sudo=(sudo)
    "${_sudo[@]}" env ORIGIN="$origin" RPID="$rp_id" APERIRE_DB_PATH="$DB" APERIRE_ADVISOR_STATE="$ADVISOR_STATE" \
      "$sync_bin" >/dev/null || rc=$?
  elif [[ $EUID -eq 0 ]]; then
    root_leg=1
    ORIGIN="$origin" RPID="$rp_id" APERIRE_DB_PATH="$DB" APERIRE_ADVISOR_STATE="$ADVISOR_STATE" \
      "$sync_bin" >/dev/null || rc=$?
  else
    ORIGIN="$origin" RPID="$rp_id" APERIRE_DB_PATH="$DB" APERIRE_ADVISOR_STATE="$ADVISOR_STATE" \
      bash "$SCRIPT_DIR/aperire-trust-sync.sh" >/dev/null || rc=$?
  fi
  if [[ $root_leg -eq 1 && ( $rc -eq 126 || $rc -eq 127 ) ]]; then
    trust_sync_program_missing "$sync_bin"
  fi
  [[ $rc -eq 0 ]] || exit "$rc"
  echo
  echo "Only admins' passkeys are trusted. Demote someone and re-run to drop theirs."
  echo "Nothing is approved by this - each action still needs its own touch."
}

cmd_advisor_trust_list() {
  local path="$ADVISOR_STATE/credentials.json"
  if [[ ! -f "$path" ]]; then
    echo "nothing trusted — the Advisor cannot approve anything by passkey yet"
    echo "run: aperire-auth advisor-sync"
    return 0
  fi
  python3 -I - "$path" <<'PYEOF'
import json, sys
s = json.load(open(sys.argv[1]))
print(f"rp_id   {s.get('rp_id','(none)')}")
print(f"origins {', '.join(s.get('origins') or []) or '(none)'}")
print(f"updated {s.get('updated_at','')}")
print()
print("label                          credential")
print("-----------------------------  --------------------------")
for c in s.get("credentials") or []:
    print(f"{(c.get('label') or '')[:29]:<29}  {c['credential_id'][:24]}...")
PYEOF
}

cmd_list_credentials() {
  local email="${1:-}"
  if [[ -z "$email" ]]; then
    echo "usage: aperire-auth list-credentials <email>" >&2
    exit 2
  fi
  local user_id rows
  user_id="$(dbsql "$DB" "SELECT id FROM auth_users WHERE username = '$(sqlescape "$email")'")" || db_fail $?
  if [[ -z "$user_id" ]]; then
    echo "error: unknown operator: $email" >&2
    exit 1
  fi
  db_count "$user_id" "the operator id"
  rows="$(dbsql -separator $'\t' "$DB" "
    SELECT id, COALESCE(name, ''), COALESCE(transports, ''),
           datetime(created_at, 'unixepoch'),
           COALESCE(datetime(last_used_at, 'unixepoch'), 'never')
    FROM auth_credentials WHERE user_id = $user_id ORDER BY id ASC
  ")" || db_fail $?
  echo "id  name                  transports          created                last_used"
  echo "──  ────────────────────  ──────────────────  ─────────────────────  ─────────────────────"
  [[ -z "$rows" ]] || printf '%s\n' "$rows" | awk -F'\t' '{ printf "%-3s %-20s  %-18s  %-21s  %s\n", $1, $2, $3, $4, $5 }'
}

cmd_revoke() {
  # Takes an email (unique per operator) and revokes every passkey the
  # account holds — "revoke this person", which is what an operator means
  # (ruling 2026-08-19; the id dance was too much work). A numeric id still
  # works for surgically removing one of several passkeys.
  local who="${1:-}"
  if [[ -z "$who" ]]; then
    echo "usage: aperire-auth revoke <email>        revoke every passkey the account holds" >&2
    echo "       aperire-auth revoke <credential-id> revoke one (id from list-credentials)" >&2
    exit 2
  fi
  local n
  if [[ "$who" =~ ^[0-9]+$ ]]; then
    n="$(dbsql "$DB" "SELECT COUNT(*) FROM auth_credentials WHERE id = $who")" || db_fail $?
    db_count "$n" "the rows changed"
    if [[ "$n" == "0" ]]; then
      echo "error: no credential with id $who" >&2
      exit 1
    fi
    dbsql "$DB" "DELETE FROM auth_credentials WHERE id = $who" || db_fail $?
    echo "revoked credential id $who"
  else
    local user_id
    user_id="$(dbsql "$DB" "SELECT id FROM auth_users WHERE username = '$(sqlescape "$who")'")" || db_fail $?
    if [[ -z "$user_id" ]]; then
      echo "error: no operator $who" >&2
      exit 1
    fi
    db_count "$user_id" "the operator id"
    n="$(dbsql "$DB" "SELECT COUNT(*) FROM auth_credentials WHERE user_id = $user_id")" || db_fail $?
    db_count "$n" "the rows changed"
    if [[ "$n" == "0" ]]; then
      echo "error: $who has no passkeys to revoke" >&2
      exit 1
    fi
    dbsql "$DB" "DELETE FROM auth_credentials WHERE user_id = $user_id" || db_fail $?
    echo "revoked $n passkey(s) for $who (the account remains; del removes it)"
  fi
  auto_advisor_sync
  # Revocation is the one where a partial push is worst: a node that did not
  # take it still accepts the key that was just revoked. The status says so.
  local rc=0
  auto_fleet_trust_push || rc=$?
  return "$rc"
}

cmd_list_sessions() {
  local email="${1:-}"
  if [[ -z "$email" ]]; then
    echo "usage: aperire-auth list-sessions <email>" >&2
    exit 2
  fi
  local user_id rows
  user_id="$(dbsql "$DB" "SELECT id FROM auth_users WHERE username = '$(sqlescape "$email")'")" || db_fail $?
  if [[ -z "$user_id" ]]; then
    echo "error: unknown operator: $email" >&2
    exit 1
  fi
  db_count "$user_id" "the operator id"
  rows="$(dbsql -separator $'\t' "$DB" "
    SELECT substr(id, 1, 24) || '…',
           datetime(created_at, 'unixepoch'),
           datetime(last_activity_at, 'unixepoch'),
           CASE WHEN revoked_at IS NOT NULL THEN 'revoked'
                WHEN expires_at < $NOW OR created_at < $NOW - 604800 THEN 'expired'
                ELSE 'active' END
    FROM auth_sessions WHERE user_id = $user_id ORDER BY created_at DESC
  ")" || db_fail $?
  # 'active' means not revoked and inside the 7-day cap (the two tests the
  # dashboard puts to a cookie first). Idle is the dashboard's call
  # (session.idle_timeout_minutes): it leaves idle sessions out of its count
  # and marks them revoked at the next sign-in. last_activity shows it here.
  echo "id (truncated)              created                last_activity          state"
  echo "──────────────────────────  ─────────────────────  ─────────────────────  ─────────"
  [[ -z "$rows" ]] || printf '%s\n' "$rows" | awk -F'\t' '{ printf "%-26s  %-21s  %-21s  %s\n", $1, $2, $3, $4 }'
}

cmd_revoke_session() {
  local sid="${1:-}"
  if [[ -z "$sid" ]]; then
    echo "usage: aperire-auth revoke-session <session-id>" >&2
    exit 2
  fi
  local match_count
  match_count="$(dbsql "$DB" "SELECT COUNT(*) FROM auth_sessions WHERE id LIKE '$(sqlescape "$sid")%' AND revoked_at IS NULL")" || db_fail $?
  db_count "$match_count" "the matching sessions"
  if [[ "$match_count" == "0" ]]; then
    echo "error: no active session matching prefix $sid" >&2
    exit 1
  fi
  if [[ "$match_count" -gt 1 ]]; then
    echo "error: prefix $sid matches $match_count sessions — use a longer prefix" >&2
    exit 1
  fi
  dbsql "$DB" "UPDATE auth_sessions SET revoked_at = $NOW WHERE id LIKE '$(sqlescape "$sid")%' AND revoked_at IS NULL" || db_fail $?
  echo "revoked session $sid"
}

cmd_magic_link() {
  local email="${1:-}"
  local purpose="${2:-enroll}"
  if [[ -z "$email" ]]; then
    echo "usage: aperire-auth magic-link <email> [enroll|recover]" >&2
    exit 2
  fi
  if [[ "$purpose" != "enroll" && "$purpose" != "recover" ]]; then
    echo "error: purpose must be 'enroll' or 'recover'" >&2
    exit 2
  fi
  local user_row
  user_row="$(dbsql -separator $'\t' "$DB" "SELECT id, COALESCE(email, '') FROM auth_users WHERE username = '$(sqlescape "$email")'")" || db_fail $?
  if [[ -z "$user_row" ]]; then
    echo "error: unknown operator: $email" >&2
    exit 1
  fi
  local user_id="${user_row%%	*}"
  db_count "$user_id" "the operator id"
  local user_email="${user_row#*	}"
  # 256-bit random token, base64url-safe. The raw token rides in the URL
  # below; the DB stores only its SHA-256 (hex) so a DB read can't yield a
  # redeemable link. This must match dashboard/db.ts hashToken(): SHA-256
  # of the base64url *string* (UTF-8), hex-encoded — NOT a hash of the raw
  # 32 bytes. handleMagic in auth.ts hashes the presented token the same
  # way before lookup.
  local token token_hash
  token="$(openssl rand 32 | base64 | tr '+/' '-_' | tr -d '=' | tr -d '\n')"
  token_hash="$(printf '%s' "$token" | openssl dgst -sha256 | awk '{print $NF}')"
  local expires=$(( NOW + TTL_MIN * 60 ))
  dbsql "$DB" "INSERT INTO auth_magic_links (token, user_id, purpose, created_at, expires_at) VALUES ('$(sqlescape "$token_hash")', $user_id, '$purpose', $NOW, $expires)" || db_fail $?
  local url="${PUBLIC_URL%/}/login.html?token=${token}"
  # The audit row is written at the end, once the email outcome is known; it
  # carries the purpose and whether the link was emailed, never the token.
  local emailed=false

  echo "magic-link issued (user=$email, purpose=$purpose, ttl=${TTL_MIN}m, expires $(date -d "@$expires"))"
  echo
  echo "  $url"
  echo
  if (( ${#PUBLIC_URL_LIST[@]} > 1 )); then
    echo "  built from ${PUBLIC_URL} — the first of ${#PUBLIC_URL_LIST[@]} origins in public_url."
    echo "  The token lives in this dashboard's database, not in the hostname, so"
    echo "  it redeems at any origin that reaches this dashboard:"
    printf '    %s\n' "${PUBLIC_URL_LIST[@]}"
    echo
  fi

  # Optional: email the URL to the operator. Falls back to print-only if
  # anything goes wrong (no email channel, no key, send fails).
  if [[ "$SEND_VIA_EMAIL" == "true" ]]; then
    if [[ -z "$user_email" ]]; then
      echo "(send_via_email is true but $email has no email on file — skipping email)"
      record_auth_event "magic_link_issued" "$email" "{\"purpose\":\"$purpose\",\"emailed\":false}"
      return 0
    fi
    if [[ -z "$NODE_BIN" || ! -x "$NODE_BIN" ]]; then
      echo "(node not found — skipping email send)"
      record_auth_event "magic_link_issued" "$email" "{\"purpose\":\"$purpose\",\"emailed\":false}"
      return 0
    fi
    # The send is the dashboard's own code (email.ts), so as root it runs as
    # the dashboard's account, the same as the reads of authn.yaml (#993). It
    # runs through tsx, as the dashboard's unit does: email.ts and lib/ import
    # one another by .js names that tsx maps to .ts and Node's own type
    # stripping does not, so under it the script never got past its imports
    # (#1354). The inner shell loads the environment file for RESEND_API_KEY
    # itself: the key never rides on an argument list and never sits in this
    # shell. The dashboard's account reads that file already; it is its
    # unit's own.
    # shellcheck disable=SC2016  # the inner shell's own variables
    if dash_code bash -c '
         if [[ -r /etc/aperire/aperire.env ]]; then set -a; . /etc/aperire/aperire.env; set +a; fi
         cd "$1" && exec "$2" --import tsx scripts/send-magic.mjs "$3" "$4" "$5"' \
         send "$DASHBOARD_DIR" "$NODE_BIN" "$user_email" "$EMAIL_SUBJECT" "$url" 2>&1; then
      echo "(emailed enrollment URL to $user_email)"
      emailed=true
    else
      echo "(email send failed — operator can still use the URL above)"
    fi
  fi
  record_auth_event "magic_link_issued" "$email" "{\"purpose\":\"$purpose\",\"emailed\":$emailed}"
}

cmd_help() {
  # Print the header comment block: from line 2 to the first non-comment line.
  awk 'NR>=2 { if ($0 !~ /^#/) exit; sub(/^# ?/, ""); print }' "$0"
}


# fleet-trust-push — ADR 0014 decision 4. Build a signed trust bundle from
# THIS host's admin passkeys and push it to each fleet node's advisord, so
# the node can verify a passkey created at this aggregator's origin. Reuses
# advisor-sync's exact admin query (one source of "who may approve"); job
# assembly is dashboard/lib/fleet-trust-job.py, signing + push is
# dashboard/lib/fleet-trust-push.mjs. NEVER a substitute for advisor-sync on
# a fleet node (that wipes its store, ADR-named) — aggregator->nodes only.
cmd_fleet_trust_push() {
  local only_label=""
  if [[ "${1:-}" == "--node" ]]; then only_label="${2:-}"; shift 2 || true; fi

  local rp_id origin
  origin="$(read_authn "public_url" "")"
  [[ -n "$origin" ]] || { echo "error: no public_url in authn.yaml" >&2; exit 1; }
  rp_id="$(read_authn "rp_id" "")"
  rp_id="$(printf %s "${rp_id%%,*}" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')"
  rp_id="${rp_id%%,*}"
  case "$rp_id" in *,*) echo "error: rp_id contains a comma after split" >&2; exit 1;; esac

  # #872: run as the dashboard's account when this one is not it. Before any
  # read: the key, the registry and the node tokens are that account's.
  local sw_rc=0
  trust_push_switch_needed || sw_rc=$?
  if [[ $sw_rc -eq 2 ]]; then
    exit 1
  fi
  if [[ $sw_rc -eq 0 ]]; then
    local -a again=(fleet-trust-push)
    [[ -n "$only_label" ]] && again+=(--node "$only_label")
    if [[ "$(id -u)" != 0 ]] && ! da_sudo_ready "the trust push reads the signing key, the fleet registry and the node tokens, which are that account's"; then
      echo "error: the trust push did not run. Every node still enforces the PREVIOUS set of passkeys." >&2
      exit 1
    fi
    local rc=0
    as_dashboard env APERIRE_TRUST_PUSH_AS_DASHBOARD=1 APERIRE_DB_PATH="$DB" \
      bash "$SCRIPT_DIR/aperire-auth.sh" "${again[@]}" || rc=$?
    return "$rc"
  fi

  local trust_file="$DASHBOARD_DIR/config/fleet-trust.yaml"
  [[ -e "$trust_file" ]] || { echo "error: no $trust_file — generate this aggregator's trust key first" >&2; exit 1; }
  [[ -r "$trust_file" ]] || { echo "error: $trust_file is there but $(id -un) cannot read it ($(stat -c '%U:%G %a' "$trust_file" 2>/dev/null)), so nothing was pushed" >&2; exit 1; }
  local priv
  priv="$(trust_private_key "$trust_file")"
  if [[ -z "$priv" ]]; then
    # Asked for by hand on a node the aggregator manages. Refused, because
    # this host cannot sign a bundle and never will, and refused by NAME:
    # `no private_key` sent an operator looking for a missing key instead of
    # to the machine that holds it (#489).
    local managed_by mb_rc=0
    managed_by="$(trust_managed_by)" || mb_rc=$?
    if [[ $mb_rc -ne 0 ]]; then
      echo "error: $trust_file could not be read, as $(id -un) or as the dashboard's account, so nothing was pushed." >&2
      exit 1
    fi
    if [[ -n "$managed_by" ]]; then
      echo "error: this host does not issue trust bundles." >&2
      say_managed_note "$managed_by"
      exit 1
    fi
    echo "error: no private_key in $trust_file. Generate this aggregator's trust key first" >&2
    exit 1
  fi

  local fleet_file="$DASHBOARD_DIR/config/fleet.yaml"
  [[ -e "$fleet_file" ]] || { echo "error: no $fleet_file (this host is not an aggregator)" >&2; exit 1; }
  [[ -r "$fleet_file" ]] || { echo "error: $fleet_file is there but $(id -un) cannot read it ($(stat -c '%U:%G %a' "$fleet_file" 2>/dev/null)), so nothing was pushed" >&2; exit 1; }

  # One push at a time on this aggregator, from the read of the admin set to
  # the last node's answer (#987 review, L4). Two pushes that interleave can
  # land in the wrong order: an Attach's push reads the list, a revoke and
  # its own push run, and the Attach's older list lands last, so the node
  # trusts the revoked passkey again. With the lock, whichever push reads
  # second also sends second. The node refuses an older bundle as well, but
  # its issued_at is minted when the bundle is signed, to the second, so it
  # cannot order two pushes on its own. The lock sits beside the database,
  # in the directory of the account every push runs as by now.
  local lock_fd="" lock_wait="${APERIRE_TRUST_PUSH_LOCK_WAIT:-50}"
  if command -v flock >/dev/null 2>&1 && exec {lock_fd}>>"$(dirname "$DB")/.fleet-trust-push.lock"; then
    if ! flock -w "$lock_wait" "$lock_fd"; then
      echo "error: another trust push on this host has held its lock for ${lock_wait}s, so this one did not run. Every node keeps the set it holds now. Run it again once that push is done: aperire-auth fleet-trust-push" >&2
      # 5, its own code, so a command that pushed after a change can say the
      # push never started rather than that a node refused it.
      exit 5
    fi
  fi

  # A read that failed is never an empty admin set (#875 review): pushing []
  # would take every passkey off every node. Only a query that succeeded and
  # returned no row is "no admins". dbsql runs as the dashboard's account, so
  # a refused switch (125) is a failed read too, never an empty answer.
  local rows rows_rc=0
  rows="$(dbsql -json "$DB" "SELECT c.credential_id AS credential_id, c.public_key AS public_key, COALESCE(c.name, u.username) AS label, u.username AS user, u.role AS role FROM auth_credentials c JOIN auth_users u ON u.id = c.user_id WHERE u.role = 'admin';")" || rows_rc=$?
  if [[ $rows_rc -ne 0 ]]; then
    echo "error: could not read the admin passkeys from $DB (sqlite3 exit $rows_rc$( [[ $rows_rc == 125 ]] && echo ", could not act as $DA_ACCOUNT, the dashboard's account" )), so nothing was pushed. Every node still enforces the PREVIOUS set." >&2
    exit 1
  fi
  [[ -n "$rows" ]] || rows='[]'

  echo "Pushing trust to fleet nodes (issuer 'aggregator', rp_id $rp_id):"
  local job job_rc=0
  job="$(ORIGIN="$origin" RP_ID="$rp_id" PRIV="$priv" ROWS="$rows" ONLY="$only_label" FLEET_FILE="$fleet_file" python3 -I "$DASHBOARD_DIR/lib/fleet-trust-job.py")" || job_rc=$?
  # 3: no node has an Advisor to push to. 4: at least one node's token could
  # not be read (#872); the job carries the others, and the run fails after
  # pushing them, because that node still enforces the previous set.
  if [[ $job_rc -eq 3 ]]; then
    return 3
  fi
  if [[ $job_rc -ne 0 && $job_rc -ne 4 ]] || [[ -z "$job" ]]; then
    echo "One or more pushes did not succeed (see above)."
    return 1
  fi
  # cwd must be DASHBOARD_DIR so `--import tsx` resolves dashboard/node_modules/tsx;
  # the .mjs imports its siblings by relative path, so that is unaffected.
  # Root never gets here with a switch to make (the push re-ran as the
  # dashboard's account above), and with none to make it runs nothing: the
  # push is the dashboard's own code (#993).
  local rc=0
  # shellcheck disable=SC2016  # $1 and $2 are the inner shell's
  printf '%s' "$job" | dash_code bash -c 'cd "$1" && exec "$2" --import tsx lib/fleet-trust-push.mjs' push "$DASHBOARD_DIR" "$NODE_BIN" || rc=$?
  if [[ $rc -eq 125 && $EUID -eq 0 ]]; then
    echo "error: the push is the dashboard's own code, and root does not run it. Run it as the account the dashboard runs as, or as your own login: aperire-auth fleet-trust-push" >&2
  fi
  [[ $job_rc -eq 4 && $rc -eq 0 ]] && rc=1
  [[ $rc -eq 0 ]] && echo "All pushes succeeded." || echo "One or more pushes did not succeed (see above)."
  return $rc
}

# ── --no-push ────────────────────────────────────────────────────────────
#
# Stripped here, once, rather than taught to four argument parsers. `add` has a
# real option loop and del / revoke / set-role take bare positionals; a flag
# added to each of them is four chances to get it wrong, and the one that got
# it wrong would be the one an operator reached for during an incident.
#
# It exists for a mixed-version fleet: a node running a build older than the
# trust-bundle route has no /v1/trust/bundle to accept a push, and failing every
# credential change on that host until it is upgraded helps nobody.
NO_PUSH=0
[[ "${APERIRE_NO_TRUST_PUSH:-0}" == "1" ]] && NO_PUSH=1
ARGS=()
for arg in "$@"; do
  if [[ "$arg" == "--no-push" ]]; then NO_PUSH=1; else ARGS+=("$arg"); fi
done
set -- ${ARGS+"${ARGS[@]}"}

case "${1:-help}" in
  add)               shift; cmd_add "$@" ;;
  del)               shift; cmd_del "$@" ;;
  list)              shift; cmd_list "$@" ;;
  list-credentials)  shift; cmd_list_credentials "$@" ;;
  set-role)          shift; cmd_set_role "$@" ;;
  advisor-sync)      shift; cmd_advisor_sync "$@" ;;
  advisor-trust)     shift; cmd_advisor_trust_list "$@" ;;
  fleet-trust-push)  shift; cmd_fleet_trust_push "$@" ;;
  revoke)            shift; cmd_revoke "$@" ;;
  list-sessions)     shift; cmd_list_sessions "$@" ;;
  revoke-session)    shift; cmd_revoke_session "$@" ;;
  magic-link)        shift; cmd_magic_link "$@" ;;
  help|-h|--help)    cmd_help ;;
  *)                 echo "error: unknown sub-command: $1" >&2; cmd_help; exit 2 ;;
esac
