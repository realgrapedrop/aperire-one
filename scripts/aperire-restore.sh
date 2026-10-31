#!/usr/bin/env bash
# aperire-restore.sh - the other half of #544: puts a set aperire-backup.sh
# wrote back onto a freshly installed host. Runs LOCALLY, on the host being
# restored, never over ssh.
#
#   curl -fsSL https://get.aperire.one | bash -s -- --restore --from DIR [--instance NAME]
#       [--yes] [--overwrite] [--dry-run] [--db-path ABS] [--replace-trust-pin]
#
# That form runs the release's checked copy of this program as root, never the
# one in your checkout, and the state helper it plants with is that copy's too
# (#941). Put --dir <install> before --restore when the install is not at
# ~/aperire-one.
#
# --overwrite is only ever needed alongside --yes, when this host's own
# database has content the set does not (exit 7 below) and the run is not
# interactive to answer the question asked instead.
#
# --replace-trust-pin is only ever needed when this host already has root's
# pin of a fleet trust key (/etc/aperire/fleet-trust.pub) and the set carries
# a different one: the restore refuses that (exit 9) rather than move the
# key every paired node trusts, unless this says to (#1008).
#
# --db-path is only ever needed when the set's own env file names a database
# path outside this install's own root (exit 8 below): a backup set names
# content, never a destination, so that value is refused rather than trusted,
# and the remedy is to type the destination yourself here.
#
# Order: install fresh from the published one-liner FIRST (this script
# refuses if that has not happened yet, and names the exact command,
# carrying the port the set recorded, #517), then run this.
#
# Before a byte moves, the whole set is validated (a manifest that verifies
# both ways, every member a plain file or directory nobody else can write,
# no path that resolves outside the set) and a safety copy of everything
# about to change is taken to a root-owned directory beside the install,
# printed below and pruned to the last two. A step that fails after that
# stops the restore, says what was and was not touched, and leaves the
# safety copy in place; it never lets a later step run over a step that
# failed, and it never prints PASS for a check that did not run.
#
# The set's own OWNERSHIP file records what an old host's accounts and
# modes were. This script reads it for exactly one thing: which account
# name to translate the Advisor's files onto, and never for a destination
# path or a mode. Every path and every mode below comes from this host's
# own table and its own accounts, so a recorded mode or owner that disagrees
# with the table cannot widen anything (#544 finding 097).
#
# Exit codes, so a script or a runbook can tell one refusal from another:
#
#   0  restored, every closing check passed
#   1  restored, but a closing check FAILed (named, see the output), or a
#      step failed mid-restore (named, see the output; a safety copy of
#      what had already changed is left in place)
#   2  usage error, or the set's OWNERSHIP file is not the six-column shape
#   3  the set itself is the problem: no such directory, no MANIFEST.sha256,
#      it does not verify, it holds something other than a plain file or a
#      directory, a path escapes the set, the set is writable by anyone but
#      root and the operator running this, or the directory it is kept in is
#      writable by anyone and has no sticky bit
#   4  OWNERSHIP names an account this host does not have (create it, or
#      re-run the installer that owns it, then run this again); or the
#      database's destination is a link, sits in a directory that is a
#      link, or is somewhere the dashboard's own account cannot write
#      (#776); nothing was touched
#   5  cannot map the Advisor: the set carries one and this host has none,
#      the reverse, or more than one installed Advisor claims the same state
#      directory
#   6  Aperire is not installed on this host yet; the message names the
#      one-liner, with the port the set recorded
#   7  this host's own database holds content the set does not (and is not
#      merely the empty one a fresh install starts with), --yes was given
#      without --overwrite, and there is no terminal to ask on instead;
#      nothing was touched
#   8  the set's own env file names a database path (APERIRE_DB_PATH) that
#      resolves outside this install's own root; a backup set names content,
#      never a destination, so this is refused rather than trusted. Type the
#      path yourself instead, with --db-path <abs>, which is checked the same
#      way an operator's own input always is (absolute, no unsafe parent, not
#      an existing file that fails to look like a SQLite database); nothing
#      was touched
#   9  the set carries an aggregator's private fleet arm key, and this host
#      already holds a fleet arm key this restore cannot prove is the same
#      one: a different key, a file that is not a plain file, one openssl
#      cannot read, or no openssl to compare with. Every node paired to the
#      key already here would stop trusting this aggregator if it were
#      replaced, so it never is; nothing was touched (#744)
#
# What it never does: touch your node, its data directory or its store. Not
# one line below reads or writes anything under your node's own config
# either. See scripts/aperire-backup-set.sh's node-config row for why, and
# put your rippled.cfg and compose file or unit back yourself, the same way
# you set them aside.
set -uo pipefail

# As root the environment chooses no path or timing (#1206): every APERIRE_*
# variable is dropped except the one a root caller passes on purpose:
#   APERIRE_INSTALL_TREE  get-aperire.sh --restore names the install (#941)
# An account id(1) says is not root keeps them all, which is what every
# suite is. id(1) at a fixed path, never bash's $EUID (#1109).
if ! [[ "$(/usr/bin/id -u 2>/dev/null)" =~ ^[1-9][0-9]*$ ]]; then
  for _v in $(compgen -e); do
    case "$_v" in APERIRE_INSTALL_TREE) ;; APERIRE_*) unset "$_v" ;; esac
  done
fi

# Where this program and its libraries are (SELF_DIR), and the install it puts
# the set back into (REPO_DIR): a directory and its parent from a checkout, two
# when it is a copy root staged out of the release and APERIRE_INSTALL_TREE
# names the install (#941). Code is loaded and run from SELF_DIR only; every
# path that means "the install" (its data, its config, the work and safety
# directories beside it) stays on REPO_DIR.
SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_DIR="$(cd "${APERIRE_INSTALL_TREE:-$SELF_DIR/..}" 2>/dev/null && pwd -P)" \
  || { echo "error: the install at ${APERIRE_INSTALL_TREE:-$SELF_DIR/..} is not a directory this account can enter" >&2; exit 1; }
# shellcheck source=scripts/aperire-backup-set.sh
. "$SELF_DIR/aperire-backup-set.sh"
# shellcheck source=scripts/term-style.sh
[[ -r "$SELF_DIR/term-style.sh" ]] && . "$SELF_DIR/term-style.sh"
# Who the dashboard runs as, and the one way this script acts as it (ADR 0024
# lane 4): the database lives in a directory that account owns, so every
# read and write of it below happens AS that account, never as root by name.
# shellcheck source=scripts/dashboard-account-lib.sh
. "$SELF_DIR/dashboard-account-lib.sh"
# The symlink-safe writer every plant, mkdir and ancestor walk below goes
# through (#776): the copy beside this program, which from the release's stage
# is the checked one, never a file read off the install's own tree (#941).
STATE_FILE_TOOL="$SELF_DIR/state-file.py"

say()  { printf '\n%s== %s%s\n' "${S_BOLD:-}" "$*" "${S_OFF:-}"; }
info() { printf '  %s\n' "$*"; }
refuse() {  # <exit-code> <message...>
  local code=$1; shift
  printf '\n%srefusing:%s %s\n' "${E_RED:-}" "${E_OFF:-}" "$*" >&2
  exit "$code"
}

# Where the closing check below reads the dashboard's own open file
# descriptors (#561). A plain constant, the same as verify-after-restart.sh's
# own PROC_DIR, rather than a literal /proc, so a test can point it at a
# fixture tree instead of the real one.
PROC_DIR=/proc
# Where the relay installer puts the relay program. A constant, so a test can
# point it at a fixture rather than at whatever this machine has installed.
RELAY_BIN_INSTALLED=/usr/local/bin/aperire-relay

# _sql <route-path> <sqlite3 args...> - sqlite3 on a database, as whoever
# owns where it sits. The set's own copy is in this run's private, root-owned
# work directory, and root reads it there. Anything else is the live
# database, in a directory the dashboard's account owns (#776): root never
# opens it by a name that account controls, and a root sqlite3 on a WAL
# database leaves a root-owned -shm the dashboard then cannot open. Set once
# WORKDIR exists; as_dashboard needs DA_ACCOUNT, resolved further down.
_sql() {  # <route-path> <args...>
  local route=$1; shift
  if [[ -n "${WORKDIR:-}" && "$route" == "$WORKDIR"/* ]]; then
    sqlite3 -init /dev/null "$@"
  else
    as_dashboard_sqlite "$@"
  fi
}

# db_total_rows <sqlite-file> -> the sum of row counts across every real
# table (sqlite's own schema tables excluded). 0 for a file that does not
# exist, is not a database, or truly holds nothing yet, which is exactly
# the shape a fresh install's own database has before anything is restored
# into it (#561, #562).
db_total_rows() {  # <path>
  local db=$1 t total=0 c
  [[ -f "$db" ]] || { printf '0\n'; return 0; }
  while IFS= read -r t; do
    [[ -n "$t" ]] || continue
    c="$(_sql "$db" "$db" "SELECT COUNT(*) FROM \"$t\"" 2>/dev/null || echo 0)"
    [[ "$c" =~ ^[0-9]+$ ]] || c=0
    total=$((total + c))
  done < <(_sql "$db" "$db" "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'" 2>/dev/null)
  printf '%s\n' "$total"
}

# db_newest_ts <sqlite-file> -> the newest activity this tooling knows how
# to read out of the dashboard's own schema, as a UTC timestamp, for the
# operator's own judgment when a restore is about to overwrite real content
# (#562). metrics.ts is written continuously (writeMetric stores epoch
# seconds; db.ts: "ts is epoch ms ... we store seconds for compactness"),
# so it is read first as the most representative heartbeat; auth_events.at
# (also epoch seconds, per its own schema comment) is the fallback for a
# database with no metrics history yet. "unknown" when neither table
# exists or both are empty, never a guess.
db_newest_ts() {  # <path>
  local db=$1 ts=""
  [[ -f "$db" ]] || { printf 'unknown\n'; return 0; }
  ts="$(_sql "$db" "$db" "SELECT MAX(ts) FROM metrics" 2>/dev/null || true)"
  if [[ -z "$ts" ]]; then
    ts="$(_sql "$db" "$db" "SELECT MAX(at) FROM auth_events" 2>/dev/null || true)"
  fi
  if [[ "$ts" =~ ^[0-9]+$ ]]; then
    date -u -d "@$ts" +'%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || printf '%s\n' "$ts"
  else
    printf 'unknown\n'
  fi
}

# db_dump_hash <sqlite-file> -> a content hash immune to on-disk layout. A
# raw file hash disagrees on two databases holding identical rows whenever
# one of them went through VACUUM INTO and the other did not, and taking a
# backup always does (#562): comparing bytes would read a database nothing
# has touched since its own backup as "changed" and ask the destructive
# question over nothing. Empty for a file that does not exist or is not a
# database; callers only compare this when at least one side is known to
# exist, so two empties never compare equal by accident.
db_dump_hash() {  # <path>
  local db=$1
  [[ -f "$db" ]] || { printf ''; return 0; }
  _sql "$db" "$db" ".dump" 2>/dev/null | sha256sum | awk '{print $1}'
}

# db_owner_rows <sqlite-file> -> the row count across auth_users and
# auth_credentials, the two tables that actually mark a host as owned: an
# operator enrolled, a passkey registered. "unknown" for a file that exists
# but sqlite3 cannot read as a database at all (corrupt, or a stray file at
# the path) -- never silently 0, which would tell a caller "nothing to
# protect here, replace freely" about a database this tooling could not
# actually examine. 0 for a file that does not exist yet, which is exactly
# a fresh install's own shape before anything is restored into it (#562,
# revised: `rows > 0` across every table asked the destructive question of a
# host that had merely polled for a minute since reinstall; operators and
# passkeys are what a rebuild cannot regenerate on its own, so they are what
# marks a database as somebody's).
db_owner_rows() {  # <path>
  local db=$1 a b
  [[ -f "$db" ]] || { printf '0\n'; return 0; }
  a="$(_sql "$db" "$db" "SELECT COUNT(*) FROM auth_users" 2>/dev/null)" || { printf 'unknown\n'; return 0; }
  [[ "$a" =~ ^[0-9]+$ ]] || { printf 'unknown\n'; return 0; }
  b="$(_sql "$db" "$db" "SELECT COUNT(*) FROM auth_credentials" 2>/dev/null)" || { printf 'unknown\n'; return 0; }
  [[ "$b" =~ ^[0-9]+$ ]] || { printf 'unknown\n'; return 0; }
  printf '%s\n' "$((a + b))"
}

# db_dest_safe_to_replace <path> -> true for a path that does not exist yet,
# is genuinely empty (0 bytes; a previous run's own interrupted write, never
# wedge every future restore because of it), or opens with SQLite's own
# magic header. False for anything else: a real file with real content that
# is not a database, which is the one shape the crafted-set attack actually
# produces (an existing account file, a config file, a secret). Checked
# right before this script ever calls `rm` on a database destination, on the
# main file only -- its -wal/-shm siblings carry different magic bytes (or
# none at all) and are never asked this question, only removed once the
# main file itself has passed it.
db_dest_safe_to_replace() {  # <path>
  local p=$1 sz magic
  [[ -e "$p" ]] || return 0
  [[ -f "$p" ]] || return 1
  sz="$(stat -c '%s' "$p" 2>/dev/null || echo -1)"
  [[ "$sz" == "0" ]] && return 0
  # Read as the dashboard's account, which owns where this sits (#776).
  magic="$(as_dashboard head -c 16 -- "$p" 2>/dev/null | tr -d '\000')"
  [[ "$magic" == "SQLite format 3"* ]] || return 1
  # A SQLite database is not enough: this box can host other projects, and
  # their databases carry the same header. Only a database with the
  # dashboard's own operators table is mine to replace.
  [[ "$(_sql "$p" "file:${p}?mode=ro" \
        "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='auth_users';" \
        2>/dev/null)" == "1" ]]
}

# db_table_row_mismatch <set-db> <live-db> -> prints one line per table whose
# row count does not confirm the restore, and returns non-zero when there is
# at least one. Two different rules, by table:
#
#   - EQUAL, exactly: auth_users, auth_credentials. The operators and
#     passkeys a rebuild cannot regenerate; a restore that landed them
#     anywhere but exactly where the set said is not proven, whichever
#     direction the count is wrong.
#   - AT LEAST the set's own count: alerts_history, auth_events,
#     missed_ledgers. Genuinely append-only (their own schema comments in
#     dashboard/db.ts say so, and nothing in the codebase ever deletes a row
#     from any of the three), so a live host that answered a poll or two
#     during the wait only ever grows them.
#
# Deliberately NOT on either list: metrics, ledgers, agreement, firing_state.
# The first three are pruned by dashboard/db.ts's own prune(), called
# unconditionally the moment the process loads -- restarting the dashboard,
# which this restore does, can shrink them below the set's own count on a
# correct restore of an old backup, the same false-FAIL this rebuild is
# fixing. firing_state has rows removed the moment an alert resolves, so even
# a live host is not one-directional. Both stay unasserted here: the two
# tables above are what a rebuild cannot regenerate, and are enough to prove
# the restore, without also proving something these tables cannot promise.
db_table_row_mismatch() {  # <set-db> <live-db>
  local setdb=$1 livedb=$2 t setc livec mismatches=() is_eq
  local eq_tables=" auth_users auth_credentials "
  local ge_tables=" alerts_history auth_events missed_ledgers "
  while IFS= read -r t; do
    [[ -n "$t" ]] || continue
    is_eq=0
    [[ "$eq_tables" == *" $t "* ]] && is_eq=1
    [[ $is_eq -eq 0 && "$ge_tables" != *" $t "* ]] && continue
    setc="$(sqlite3 "$setdb" "SELECT COUNT(*) FROM \"$t\"" 2>/dev/null || echo 0)"
    [[ "$setc" =~ ^[0-9]+$ ]] || setc=0
    livec="$(_sql "$livedb" "$livedb" "SELECT COUNT(*) FROM \"$t\"" 2>/dev/null || echo -1)"
    [[ "$livec" =~ ^[0-9]+$ ]] || { mismatches+=("$t: could not be read on the running database"); continue; }
    if [[ $is_eq -eq 1 ]]; then
      [[ "$livec" != "$setc" ]] && mismatches+=("$t: set=$setc live=$livec (must match exactly)")
    else
      (( livec < setc )) && mismatches+=("$t: set=$setc live=$livec (must be at least the set's own count)")
    fi
  done < <(sqlite3 "$setdb" "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'" 2>/dev/null)
  if [[ ${#mismatches[@]} -gt 0 ]]; then
    printf '%s\n' "${mismatches[@]}"
    return 1
  fi
  return 0
}

NEEDS_ROOT=1
if [[ $NEEDS_ROOT -eq 1 && $EUID -ne 0 ]]; then
  refuse 2 "run with sudo, this stops services, chowns files and starts them again"
fi

# The operator this restore runs for: the account sudo was invoked as, or
# the account running it directly as root. Used only to decide who is
# allowed to have written the set (#544 finding 097's ownership check),
# never as an owner or a mode applied to anything restored.
OP_USER="${SUDO_USER:-}"
[[ -n "$OP_USER" ]] || OP_USER="$(id -un)"

# A private, root-owned scratch directory for this run's own bookkeeping
# (the manifest cross-check, the verify transcript, and the staged copy of
# the whole set, #563). Beside the install, the same place the safety copy
# lives, never /tmp: a set can be large, staging it doubles that size on
# disk for the run's duration, and /tmp is tmpfs (RAM) on plenty of hosts.
# Root-owned 0700 the same way; removed on every exit path by the trap below.
WORKDIR_ROOT="${REPO_DIR}-restore-work"
install -d -m 0700 "$WORKDIR_ROOT" || refuse 3 "could not create $WORKDIR_ROOT to stage
     this run's own work in; nothing was touched"
chmod 0700 "$WORKDIR_ROOT" 2>/dev/null || true
WORKDIR="$(mktemp -d "$WORKDIR_ROOT/XXXXXXXX")"
chmod 700 "$WORKDIR"
trap 'rm -rf "$WORKDIR"' EXIT

# Real path of the install root, resolved once: both the staging containment
# check below (finding 1) and the closing check's own re-assertion of it use
# this same value, so a symlink component behaves identically in both places.
INSTALL_ROOT_REAL="$(realpath -m -- "$REPO_DIR" 2>/dev/null || printf '%s' "$REPO_DIR")"

# validate_port <value> <source, for the message> - a number from 1 to
# 65535, never trusted uncritically into a curl one-liner an operator is
# about to paste into a root shell, or into a healthz URL this script
# itself calls. Applied to every PORT this run reads, whichever env file it
# came from (finding 1's audit: the set's own env file is content, same as
# APERIRE_DB_PATH, and gets the same "a number, in range, or refused" rule).
validate_port() {  # <value> <source>
  local v=$1 src=$2
  if [[ ! "$v" =~ ^[0-9]+$ ]] || (( v < 1 || v > 65535 )); then
    refuse 2 "the port named in $src (PORT=$v) is not a number from 1 to
         65535; refusing rather than guessing, or printing it into a command
         uncritically. Nothing was touched."
  fi
}

# ── args ──────────────────────────────────────────────────────────────
FROM=""; INSTANCE=""; ASSUME_YES=0; DRY=0; OVERWRITE=0; DB_PATH_OVERRIDE=""; REPLACE_TRUST_PIN=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --from)      FROM=${2:?--from needs a path}; shift 2 ;;
    --instance)  INSTANCE=${2:?--instance needs a name}; shift 2 ;;
    --yes|-y)    ASSUME_YES=1; shift ;;
    --overwrite) OVERWRITE=1; shift ;;
    --dry-run)   DRY=1; shift ;;
    --replace-trust-pin) REPLACE_TRUST_PIN=1; shift ;;
    --db-path)   DB_PATH_OVERRIDE=${2:?--db-path needs an absolute path}; shift 2 ;;
    -h|--help)
      awk '/^[^#]/{exit} NR>1{sub(/^# ?/,""); print}' "$0"
      exit 0 ;;
    *) refuse 2 "unknown argument: $1 (see --help)" ;;
  esac
done
[[ -n "$FROM" ]] || refuse 2 "--from <dir> is required, the set aperire-backup.sh wrote"

# ── validate the whole set before trusting a byte of it (finding 097) ────
# Everything below has to hold before anything is written. A crafted set
# proving each of these wrong, with nothing written and nothing widened, is
# what scripts/test-backup-restore.sh drives.
[[ -d "$FROM" ]] || refuse 3 "no such directory: $FROM"
FROM="$(cd "$FROM" && pwd -P)"

# ── refuse a set kept where another account could swap it out (#563) ────
# aperire-backup.sh already refuses to write --to under a world-writable,
# non-sticky parent, because removing a directory entry only needs write on
# the PARENT, not on the entry itself. --from never had the same check: a
# set sitting under such a directory could be renamed out of the way and
# replaced by another account between this validation and any later read of
# it, and everything below re-reads "$FROM/<name>" by path throughout the
# run rather than only once. This check catches the case where the parent
# itself is unsafe; the staging copy right after validate_set closes the
# window for good, whatever the parent looks like.
_from_parent="$(dirname "$FROM")"
if [[ -d "$_from_parent" ]]; then
  _from_parent="$(cd "$_from_parent" && pwd -P)"
  _from_pperm="$(stat -c '%a' "$_from_parent" 2>/dev/null || echo 000)"
  if (( (8#$_from_pperm & 0002) != 0 && (8#$_from_pperm & 01000) == 0 )); then
    refuse 3 "the parent of --from ($_from_parent) is writable by anyone and
         has no sticky bit; another account there could swap the set out
         from under this run before it finishes reading. Keep the set under
         a directory that is not world-writable, or add the sticky bit to
         it. Nothing was touched."
  fi
fi

validate_set() {  # <root>
  local root=$1 p rel real n owner perm line

  # Every member is a plain file or a directory: no symlink, device, fifo,
  # socket, and no file with more than one hard link (a hardlink can be
  # made to point at a file this restore has no business touching).
  while IFS= read -r -d '' p; do
    if [[ -L "$p" ]]; then
      refuse 3 "the set at $root is not trustworthy: ${p#"$root"/} is a
           symbolic link. Nothing was touched."
    elif [[ -d "$p" ]]; then
      continue
    elif [[ -f "$p" ]]; then
      n="$(stat -c '%h' "$p" 2>/dev/null || echo 1)"
      if [[ "$n" -gt 1 ]]; then
        refuse 3 "the set at $root is not trustworthy: ${p#"$root"/} has more
             than one hard link ($n). Nothing was touched."
      fi
    else
      refuse 3 "the set at $root is not trustworthy: ${p#"$root"/} is not a
           plain file or a directory. Nothing was touched."
    fi
  done < <(find "$root" -mindepth 1 -print0 2>/dev/null)

  # MANIFEST.sha256 exists, names only paths that stay inside the set, and
  # names a file that is actually there for every line.
  [[ -f "$root/MANIFEST.sha256" ]] || \
    refuse 3 "$root holds no MANIFEST.sha256. A set taken before this tool
         cannot be trusted to be whole; take a new one with aperire-backup.sh."
  : > "$WORKDIR/manifest-paths"
  n=0
  while IFS= read -r line; do
    n=$((n + 1))
    [[ -n "$line" ]] || continue
    rel="${line#*  }"
    rel="${rel#./}"
    case "$rel" in
      /*|*..*)
        refuse 3 "MANIFEST.sha256 line $n names an unsafe path: $rel.
             Nothing was touched." ;;
    esac
    real="$(realpath -m -- "$root/$rel" 2>/dev/null || true)"
    case "$real" in
      "$root"/*) : ;;
      *) refuse 3 "MANIFEST.sha256 line $n resolves outside the set: $rel.
             Nothing was touched." ;;
    esac
    [[ -f "$root/$rel" ]] || \
      refuse 3 "MANIFEST.sha256 names $rel, and the set holds no such file.
           Nothing was touched."
    printf '%s\n' "$rel" >> "$WORKDIR/manifest-paths"
  done < "$root/MANIFEST.sha256"

  # The other direction sha256sum -c never checks on its own: every file
  # the set actually holds has to be named in the manifest too, or content
  # could ride along unverified.
  while IFS= read -r -d '' p; do
    rel="${p#"$root"/}"
    grep -qxF -e "$rel" "$WORKDIR/manifest-paths" || \
      refuse 3 "$rel is in the set and is not named in MANIFEST.sha256; a
           set is everything it lists and nothing more. Nothing was touched."
  done < <(find "$root" -mindepth 1 -type f ! -name MANIFEST.sha256 -print0 2>/dev/null)

  # Content matches what the manifest claims.
  if ! ( cd "$root" && sha256sum -c MANIFEST.sha256 ) >"$WORKDIR/verify.out" 2>&1; then
    cat "$WORKDIR/verify.out" >&2
    refuse 3 "$root does not verify against its own MANIFEST.sha256, see the
         failed lines above. Nothing was touched."
  fi

  # A set is as trusted as the place it was kept: the manifest proves it is
  # complete and unchanged since it was written, never who wrote it. Refuse
  # one still writable by an account other than root or the operator.
  while IFS= read -r -d '' p; do
    owner="$(stat -c '%U' "$p" 2>/dev/null || true)"
    perm="$(stat -c '%a' "$p" 2>/dev/null || echo 000)"
    if [[ "$owner" != root && "$owner" != "$OP_USER" ]]; then
      refuse 3 "$p is owned by ${owner:-an unknown account}, neither root nor
           $OP_USER. Nothing was touched."
    fi
    if (( (8#$perm & 0022) != 0 )); then
      refuse 3 "$p is writable by group or other (mode $perm). Nothing was
           touched."
    fi
  done < <(find "$root" -mindepth 0 -print0 2>/dev/null)
}
validate_set "$FROM"

# ── copy the validated set into a private staging area (#563) ───────────
# Validating $FROM proves it is trustworthy at this instant; everything
# after this point re-reads "$FROM/<name>" by path, one file at a time, over
# the whole run, and a set kept somewhere another account can reach could be
# swapped in that window even when its parent looked safe a moment ago
# (a second account racing a rename is not stopped by a parent-directory
# check alone). Copied here into $WORKDIR, already root-owned 0700 and
# already removed on every exit path by the trap at the top of this script,
# re-validated in place, and used for the rest of the run: nothing below
# this point ever reads $FROM again. Messages that name the set for the
# operator use $FROM_DISPLAY, the path they actually gave, not this
# private copy.
FROM_DISPLAY="$FROM"

# Enough room to stage a second copy of the whole set beside the install,
# checked before the copy starts rather than discovered mid-`cp` as a
# truncated, unusable staging tree: a large database doubles into whatever
# filesystem $WORKDIR_ROOT sits on for the run's duration, and that used to
# be /tmp, which is RAM on a host where it is tmpfs.
_set_bytes="$(du -sb -- "$FROM" 2>/dev/null | awk '{print $1}')"
[[ "$_set_bytes" =~ ^[0-9]+$ ]] || _set_bytes=0
_stage_margin_bytes=$((64 * 1024 * 1024))
_stage_avail_bytes="$(df --output=avail -B1 -- "$WORKDIR_ROOT" 2>/dev/null | tail -1 | tr -d ' ')"
[[ "$_stage_avail_bytes" =~ ^[0-9]+$ ]] || _stage_avail_bytes=0
_stage_needed_bytes=$((_set_bytes + _stage_margin_bytes))
if (( _stage_avail_bytes < _stage_needed_bytes )); then
  refuse 3 "not enough free space beside the install to stage a private copy
       of the set safely: $_stage_needed_bytes byte(s) needed ($_set_bytes for
       the set plus a margin), only $_stage_avail_bytes available at
       $WORKDIR_ROOT. Free some space and try again. Nothing was touched."
fi

STAGE_DIR="$WORKDIR/stage"
mkdir -p "$STAGE_DIR" || refuse 3 "could not create a private staging copy of
     the set; nothing was touched."
cp -a "$FROM/." "$STAGE_DIR/" || refuse 3 "could not copy $FROM_DISPLAY into a
     private staging directory; nothing was touched."
validate_set "$STAGE_DIR"
FROM="$STAGE_DIR"

[[ -f "$FROM/OWNERSHIP" ]] || refuse 3 "$FROM_DISPLAY holds no OWNERSHIP; take a new set."

# ── parse OWNERSHIP: mode uid gid owner group path, six columns ──────
# Read for two notes and nothing else: a recorded mode that differs from
# this host's table (report_ownership_drift), and an account or group this
# host does not have (note_foreign_accounts). Never for a destination path,
# an owner or a mode that gets applied, see the file header.
RS_PATHS=(); RS_MODES=(); RS_OWNERS=(); RS_GRPS=()
parse_ownership() {
  local file=$1 line n=0 mode uid gid owner group path
  while IFS= read -r line; do
    n=$((n + 1))
    [[ -n "${line// }" ]] || continue
    read -r mode uid gid owner group path <<<"$line"
    if [[ ! "$uid" =~ ^[0-9]+$ || ! "$gid" =~ ^[0-9]+$ ]]; then
      refuse 2 "$file line $n is not the six-column shape (mode uid gid owner group path): $line"
    fi
    if [[ ! "$mode" =~ ^[0-7]{3,4}$ ]]; then
      refuse 2 "$file line $n has no octal mode: $line"
    fi
    if [[ -z "$path" || "${path:0:1}" != / ]]; then
      refuse 2 "$file line $n names a path that is not absolute: ${path:-(empty)}"
    fi
    # The manifest loop above refuses a ".." the same way (#566): OWNERSHIP
    # is read for exactly one thing today (which account name to translate
    # the Advisor's files onto, never a destination path or a mode), so a
    # ".." here cannot widen anything as the code stands. It is still worth
    # refusing, so the two loops over the two halves of one set agree about
    # what an unsafe path looks like, rather than one of them refusing a
    # shape the other quietly accepts.
    case "$path" in
      *..*) refuse 2 "$file line $n names an unsafe path: $path" ;;
    esac
    RS_PATHS+=("$path"); RS_MODES+=("$mode"); RS_OWNERS+=("$owner"); RS_GRPS+=("$group")
  done < "$file"
}
parse_ownership "$FROM/OWNERSHIP"

# ── which instance, and is Aperire installed on this host yet ────────
if [[ -z "$INSTANCE" ]]; then
  # A plain command substitution, not `mapfile < <(...)`: the latter's `$?`
  # reads mapfile's own exit status, not the piped command's.
  _inst_out="$(bkset_this_instance "$REPO_DIR")"; _inst_rc=$?
  _found=()
  [[ -n "$_inst_out" ]] && mapfile -t _found <<<"$_inst_out"
  if [[ $_inst_rc -eq 2 ]]; then
    refuse 2 "this host runs more than one Aperire instance; name the one to restore: --instance ${_found[0]:-<name>}"
  fi
  [[ $_inst_rc -eq 0 ]] && INSTANCE="${_found[0]:-}"
fi

DASH_UNIT="$(bkset_dash_unit "$INSTANCE" || true)"
if [[ -z "$DASH_UNIT" ]]; then
  SET_PORT="$(bkset_env_key "$FROM/aperire.env" PORT 2>/dev/null || true)"
  [[ -n "$SET_PORT" ]] || SET_PORT=7800
  # This is content out of the set's own env file, printed into a curl
  # one-liner the operator is about to paste into a root shell (#544 finding
  # 097's own audit, extended): the same "a number, in range, or refused"
  # rule that guards the database path below guards this too.
  validate_port "$SET_PORT" "$FROM_DISPLAY/aperire.env"
  SET_ROLE="dashboard-only"
  [[ -f "$FROM/relay.conf" ]] && SET_ROLE="co-located"
  refuse 6 "Aperire is not installed on this host yet. Install it first, then run
       this again:

           curl -fsSL https://get.aperire.one | bash -s -- --port ${SET_PORT}

       (the set at $FROM_DISPLAY was taken from a $SET_ROLE host on port ${SET_PORT})"
fi
# The account the dashboard runs as: its unit's effective User=, drop-ins
# included. The operator's own login on a host installed before ADR 0024,
# aperire-dashboard on a fresh one; the unit says which, never SUDO_USER.
da_resolve_unit "$UNIT_DIR/$DASH_UNIT.service" || refuse 4 "$DA_WHY"
DASH_USER="$DA_ACCOUNT"
# Asked once, here, before anything stops: every read and write of the
# database below goes through as_dashboard, and several of those reads fall
# back to "0" or "unknown" on any failure. A refused switch (as_dashboard's
# 125) must never be one of those quiet answers, so it is a refusal now.
_da_rc=0
as_dashboard true || _da_rc=$?
if [[ $_da_rc -ne 0 ]]; then
  refuse 4 "this restore could not act as $DASH_USER, the account the dashboard
       unit runs as (exit $_da_rc). Every step on the database is made as that
       account, never as root. Check the account exists (id $DASH_USER) and
       run this again. Nothing was touched."
fi

# ── dashboard/config: whose it is, checked before anything stops ─────────
# The config files go back owned by whoever owns dashboard/config, read by
# the dashboard through its group, written by root through state-file.py on a
# descriptor (#875 review, M2): on a host installed before ADR 0024 that
# directory is the dashboard account's own, and a name in it is that
# account's to swap between a root write and a root chown.
#
# On a host where the dashboard has its own account (its unit's User= is not
# the tree's owner), the directory must be the operator's and closed to group
# and other writes; lane C's installer leaves it that way. If it is the
# dashboard account's, or anyone else can write it, that installer has not
# run on this tree, and handing the operator's files out of it would be
# guessing. No fallback owner either: a directory this cannot stat is a
# refusal (#875 review, L2).
CONFIG_DIR="$REPO_DIR/dashboard/config"
SET_HAS_CONFIG=0
for _cf in authn.yaml channels.yaml digest.yaml rules.local.yaml fleet.yaml fleet-trust.yaml fleet-link.json fleet-links.json; do
  [[ -f "$FROM/config/$_cf" ]] && SET_HAS_CONFIG=1
done
if [[ $SET_HAS_CONFIG -eq 1 ]]; then
  if [[ -L "$CONFIG_DIR" || ! -d "$CONFIG_DIR" ]]; then
    refuse 4 "$CONFIG_DIR is not a real directory (it may be a symlink). Nothing was
       touched. Re-run the installer to put it back:
           curl -fsSL https://get.aperire.one | bash -s -- --update --force"
  fi
  CONFIG_OWNER="$(stat -c '%U' "$CONFIG_DIR" 2>/dev/null || true)"
  [[ -n "$CONFIG_OWNER" && "$CONFIG_OWNER" != UNKNOWN ]] \
    || refuse 4 "could not read who owns $CONFIG_DIR. Nothing was touched."
  TREE_OWNER="$(stat -c '%U' "$REPO_DIR" 2>/dev/null || true)"
  if [[ "$DASH_USER" != "$TREE_OWNER" ]]; then
    _cperm="$(stat -c '%a' "$CONFIG_DIR" 2>/dev/null || echo 777)"
    if [[ "$CONFIG_OWNER" == "$DASH_USER" ]] || (( (8#$_cperm & 0022) != 0 )); then
      refuse 4 "$CONFIG_DIR belongs to $CONFIG_OWNER (mode $_cperm), and the dashboard
       runs as its own account here ($DASH_USER). That directory has to be the
       operator's and closed to group and other writes before the operator's
       files go back into it. Re-run the installer, which sets it, then run
       this again. Nothing was touched:
           curl -fsSL https://get.aperire.one | bash -s -- --update --force"
    fi
  fi
  CONFIG_GROUP="$(id -gn "$DASH_USER" 2>/dev/null || true)"
  [[ -n "$CONFIG_GROUP" ]] || refuse 4 "could not read the group of $DASH_USER. Nothing was touched."
  CONFIG_UID="$(id -u "$CONFIG_OWNER" 2>/dev/null || true)"
  CONFIG_GID="$(getent group "$CONFIG_GROUP" 2>/dev/null | cut -d: -f3)"
  DASH_UID="$(id -u "$DASH_USER" 2>/dev/null || true)"
  DASH_GID="$CONFIG_GID"
  for _v in CONFIG_UID CONFIG_GID DASH_UID; do
    [[ "${!_v}" =~ ^[0-9]+$ ]] || refuse 4 "could not resolve a numeric id for the config files' owner or group ($_v). Nothing was touched."
  done
fi

# The env file that will be IN FORCE once this restore finishes: the set's
# own aperire.env when it carries one (this run is about to overwrite the
# live file with it), the live file otherwise. The port a closing check
# tests, and the database this restore writes to, are both decided from
# THIS file, never from whatever the live file said before the set's own
# copy landed (#561): deciding either one from the live file here is how a
# host that moved its database with APERIRE_DB_PATH got the default path
# read back at it while the dashboard opened the real one, and how a host
# moved to a non-default port got its healthz checked on the wrong one.
#
# SET_SUPPLIES_ENV records which side that file came from: the set's own
# copy is CONTENT, the same as anything else aperire-backup.sh wrote, and a
# value it names is never trusted to choose a destination on its own
# (finding 1). This host's own live env file, read only when the set carries
# none at all, is a different thing: an operator's own prior configuration
# of this same host, already in force, not something the set supplied.
RESTORE_ENV_SRC="$FROM/aperire.env"
SET_SUPPLIES_ENV=1
if [[ ! -f "$RESTORE_ENV_SRC" ]]; then
  RESTORE_ENV_SRC="$(bkset_env_file "$INSTANCE" || true)"
  SET_SUPPLIES_ENV=0
fi
PORT=""
[[ -n "$RESTORE_ENV_SRC" ]] && PORT="$(bkset_env_key "$RESTORE_ENV_SRC" PORT)"
[[ -n "$PORT" ]] || PORT=7800
validate_port "$PORT" "${RESTORE_ENV_SRC:-the env file on this host}"
DB_DEST="$(bkset_db_path_from_env "$REPO_DIR" "$INSTANCE" "${RESTORE_ENV_SRC:-}")"
DB_DEST_SOURCE="this install's own default"
# A crafted or corrupted APERIRE_DB_PATH is the one part of this value that
# is not this script's own construction (the suffixed default always is);
# refused here, in words, rather than trusted into rm/install below.
case "$DB_DEST" in
  /*) : ;;
  *) refuse 2 "the database path named in ${RESTORE_ENV_SRC:-the env file on this host}
       (APERIRE_DB_PATH=$DB_DEST) is not absolute; refusing rather than
       guessing where that was meant to go. Nothing was touched." ;;
esac
case "$DB_DEST" in
  *..*) refuse 2 "the database path named in ${RESTORE_ENV_SRC:-the env file on this host}
       (APERIRE_DB_PATH=$DB_DEST) contains \"..\"; refusing rather than
       writing through it. Nothing was touched." ;;
esac

# ── a link where the database goes is refused, before anything stops ────
# The database's directory is the dashboard account's own (data/), so every
# name in it is that account's to replace, a link included. A link at the
# database's name, or a directory there that is itself a link, would have
# root's restore land somewhere else (#776). The write below happens as that
# account anyway, so a link planted after this check only ever leads it to
# what it could write already; this check is what makes a link that is
# already there a named refusal, before anything stops, rather than a
# confusing "outside the install" one further down or a failure mid-restore.
refuse_db_links() {  # <db path> <where it came from>
  local p=$1 src=$2 parent
  parent="$(dirname -- "$p")"
  if [[ -L "$p" ]]; then
    refuse 4 "$p is a symbolic link (it points at $(readlink -- "$p" 2>/dev/null || echo '?')).
       The database's directory belongs to the dashboard's account, and a
       restore never writes through a link there. Remove the link and run
       this again; the restored database is written in its place.
       (the path came from $src.) Nothing was touched."
  fi
  if [[ -e "$p" && ! -f "$p" ]]; then
    refuse 4 "$p exists and is not a plain file. A restore never writes over
       it. Move it aside and run this again. Nothing was touched."
  fi
  if [[ -L "$parent" ]]; then
    refuse 4 "$parent, the directory the database goes in, is a symbolic link
       (it points at $(readlink -- "$parent" 2>/dev/null || echo '?')). A restore never
       writes through a link there. Put a real directory in its place, owned
       by $DASH_USER, and run this again. Nothing was touched."
  fi
}
[[ -n "$DB_PATH_OVERRIDE" ]] || refuse_db_links "$DB_DEST" "${RESTORE_ENV_SRC:-the default for this install}"

# ── the set's own env file never chooses a destination (finding 1) ─────
# A table (this host's own install root) decides every destination; a set
# supplies content only. --db-path is the one way to send this database
# somewhere outside the install, and it is typed by the operator, on THIS
# host's own terminal, at restore time -- never read out of a file the set
# carries. Checked the same way any operator input to a privileged script is:
# absolute, no parent this script would have to invent outside the tree it
# owns, and (below, right before the write) not an existing file that fails
# to look like a SQLite database.
if [[ -n "$DB_PATH_OVERRIDE" ]]; then
  case "$DB_PATH_OVERRIDE" in
    /*) : ;;
    *) refuse 2 "--db-path must be an absolute path: $DB_PATH_OVERRIDE" ;;
  esac
  if [[ -L "$DB_PATH_OVERRIDE" ]]; then
    refuse 2 "--db-path names a symbolic link: $DB_PATH_OVERRIDE; point it at a
         real file, or at a path nothing sits at yet. Nothing was touched."
  fi
  _dbp_parent="$(dirname -- "$DB_PATH_OVERRIDE")"
  if [[ ! -d "$_dbp_parent" ]]; then
    _dbp_parent_real="$(realpath -m -- "$_dbp_parent" 2>/dev/null || printf '%s' "$_dbp_parent")"
    case "$_dbp_parent_real" in
      "$INSTALL_ROOT_REAL"|"$INSTALL_ROOT_REAL"/*) : ;;
      *) refuse 2 "--db-path's parent directory does not exist and is outside
           this install's own root ($REPO_DIR): $_dbp_parent. This script never
           invents a directory outside the tree it owns; create the parent
           yourself first, or choose a path already backed by a real
           directory. Nothing was touched." ;;
    esac
  fi
  # Checked here too, as a usage error, before anything stops or moves --
  # not only later at the rm guard right before the write, which is a
  # mid-restore failure (exit 1, after a safety copy) rather than the plain
  # refusal an operator typo deserves.
  db_dest_safe_to_replace "$DB_PATH_OVERRIDE" || refuse 2 "--db-path names an
       existing file that is not an Aperire database (no \"SQLite format 3\"
       header): $DB_PATH_OVERRIDE. Refusing to replace it. Nothing was
       touched."
  DB_DEST="$DB_PATH_OVERRIDE"
  DB_DEST_SOURCE="--db-path, typed at the terminal"
elif [[ $SET_SUPPLIES_ENV -eq 1 ]]; then
  _db_dest_real="$(realpath -m -- "$DB_DEST" 2>/dev/null || printf '%s' "$DB_DEST")"
  case "$_db_dest_real" in
    "$INSTALL_ROOT_REAL"|"$INSTALL_ROOT_REAL"/*) : ;;
    *)
      refuse 8 "the set at $FROM_DISPLAY names a database path outside this
           install's own root:

               APERIRE_DB_PATH=$DB_DEST
               resolves to    $_db_dest_real
               install root:  $INSTALL_ROOT_REAL

           A backup set names content, never a destination: this script never
           lets a set choose where root writes a file. If you mean to restore
           this database at that path, type it yourself:

               --db-path $_db_dest_real

           Nothing was touched." ;;
  esac
  DB_DEST_SOURCE="the set's own aperire.env (APERIRE_DB_PATH)"
elif [[ "$DB_DEST" != "$REPO_DIR/data/aperire${INSTANCE:+-$INSTANCE}.db" ]]; then
  DB_DEST_SOURCE="this host's own live env file (APERIRE_DB_PATH), already in force"
fi
[[ -z "$DB_PATH_OVERRIDE" ]] || refuse_db_links "$DB_DEST" "--db-path"

# ── the database's place, worked by the dashboard's own account (#776) ──
# One small program, run AS that account through as_dashboard, does every
# step that touches the database's directory: it opens the directory with
# O_NOFOLLOW, never follows a link at a name in it, writes a new file there
# with O_EXCL and renames it over the old one (a rename replaces a link
# rather than writing through it), and removes the old -wal and -shm by name
# within that directory. Root hands it the bytes on stdin and never acts on
# a name in there itself, so nothing that account could plant can turn the
# write into root's write somewhere else.
#
#   probe   <db>          can the account create or replace <db>? prints ok,
#                         or a reason and the path it is about
#   stage   <db>          stdin -> a new 0600 file beside <db>; prints its name
#   commit  <db> <name>   drop <db>-wal and <db>-shm, rename <name> over <db>
#   discard <db> <name>   remove a staged file that is not going to be used
#   read    <db>          <db>'s bytes to stdout, only if it is a plain file
#                         with one link (the safety copy)
DB_PLACE_PY='import errno, os, stat, sys
verb, dest = sys.argv[1], sys.argv[2]
d, b = os.path.split(dest)
def out(*a):
    sys.stdout.write("\t".join(a) + "\n")
def opendir(path):
    return os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
def leaf(dfd, name):
    try:
        return os.lstat(name, dir_fd=dfd)
    except FileNotFoundError:
        return None
if verb == "probe":
    if os.path.lexists(d):
        try:
            dfd = opendir(d)
        except OSError as e:
            out("link" if e.errno in (errno.ELOOP, errno.ENOTDIR) else "unreadable", d); sys.exit(4)
        st = leaf(dfd, b)
        if st is not None and stat.S_ISLNK(st.st_mode):
            out("link", dest); sys.exit(4)
        if st is not None and not stat.S_ISREG(st.st_mode):
            out("notfile", dest); sys.exit(4)
        if not os.access(d, os.W_OK | os.X_OK):
            out("unwritable", d); sys.exit(4)
    else:
        a = d
        while a and not os.path.lexists(a):
            a = os.path.dirname(a)
        if not os.access(a, os.W_OK | os.X_OK):
            out("unwritable", a); sys.exit(4)
    out("ok"); sys.exit(0)
if verb == "stage":
    if not os.path.lexists(d):
        os.makedirs(d, 0o700)
    dfd = opendir(d)
    tmp = ".aperire-restore.%d.db" % os.getpid()
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=dfd)
    os.fchmod(fd, 0o600)
    src = sys.stdin.buffer
    while True:
        chunk = src.read(1 << 20)
        if not chunk:
            break
        os.write(fd, chunk)
    os.fsync(fd)
    os.close(fd)
    out(tmp); sys.exit(0)
if verb in ("commit", "discard"):
    tmp = sys.argv[3]
    if "/" in tmp or not tmp.startswith(".aperire-restore."):
        sys.stderr.write("not a staged name: %s\n" % tmp); sys.exit(2)
    dfd = opendir(d)
    st = leaf(dfd, tmp)
    if st is None or not stat.S_ISREG(st.st_mode):
        sys.stderr.write("the staged file %s is gone or not a plain file\n" % tmp); sys.exit(4)
    # A staged file is a VACUUM INTO copy, in rollback mode, so its checks
    # leave nothing beside it; removed anyway, in case one ever is not.
    for side in (tmp + "-wal", tmp + "-shm", tmp + "-journal"):
        try:
            os.unlink(side, dir_fd=dfd)
        except FileNotFoundError:
            pass
    if verb == "discard":
        os.unlink(tmp, dir_fd=dfd); sys.exit(0)
    for side in (b + "-wal", b + "-shm"):
        try:
            os.unlink(side, dir_fd=dfd)
        except FileNotFoundError:
            pass
    os.rename(tmp, b, src_dir_fd=dfd, dst_dir_fd=dfd)
    os.fsync(dfd)
    sys.exit(0)
if verb == "read":
    try:
        fd = os.open(dest, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOCTTY)
    except FileNotFoundError:
        sys.exit(1)
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
        sys.stderr.write("%s: not a plain file with one link\n" % dest); sys.exit(4)
    o = sys.stdout.buffer
    while True:
        chunk = os.read(fd, 1 << 20)
        if not chunk:
            break
        o.write(chunk)
    o.flush()
    sys.exit(0)
sys.stderr.write("unknown verb %s\n" % verb); sys.exit(2)'
db_place() { as_dashboard python3 -I -c "$DB_PLACE_PY" "$@"; }

# Asked now, before the dry run's own exit and before anything stops: a
# destination the account cannot write would otherwise fail mid-restore,
# with the dashboard already down.
if [[ -f "$FROM/aperire.db" ]]; then
  _probe="$(db_place probe "$DB_DEST" 2>&1)"; _probe_rc=$?
  if [[ $_probe_rc -ne 0 ]]; then
    IFS=$'\t' read -r _why _where <<<"$_probe"
    case "$_why" in
      link) refuse 4 "${_where:-$DB_DEST} is a symbolic link. The database's directory
       belongs to the dashboard's account ($DASH_USER), and a restore never
       writes through a link there. Remove it and run this again. Nothing was
       touched." ;;
      notfile) refuse 4 "${_where:-$DB_DEST} exists and is not a plain file. Move it aside
       and run this again. Nothing was touched." ;;
      unwritable)
        [[ -n "$_where" ]] || _where="$(dirname -- "$DB_DEST")"
        refuse 4 "the dashboard's account ($DASH_USER) cannot write $_where,
       so it could not open the database there once it restarts either. The
       database is written as that account, never by root. Make the directory
       that account's, then run this again:

           sudo install -d -o $DASH_USER -m 0700 $_where

       Nothing was touched." ;;
      *) refuse 4 "could not check $DB_DEST as the dashboard's account ($DASH_USER):
       ${_probe:-no answer}. Nothing was touched." ;;
    esac
  fi
fi

ENV_PATH_LOCAL="$(bkset_env_path "$INSTANCE")"
RELAY_CONF_LOCAL="$(bkset_relay_conf_path "$INSTANCE")"

say "Aperire One restore"
info "install: $REPO_DIR${INSTANCE:+  (instance: $INSTANCE)}"
info "from set: $FROM_DISPLAY"
info "dashboard: $DASH_UNIT, user $DASH_USER, port $PORT"
info "database: $DB_DEST (from $DB_DEST_SOURCE)"

# ── the Advisor, both directions ──────────────────────────────────────
SET_HAS_ADVISOR=0; [[ -d "$FROM/advisor-state" ]] && SET_HAS_ADVISOR=1
ADVISOR_UNIT="$(bkset_advisor_unit "$INSTANCE" || true)"
HOST_HAS_ADVISOR=0; [[ -n "$ADVISOR_UNIT" ]] && HOST_HAS_ADVISOR=1

if [[ $SET_HAS_ADVISOR -eq 1 && $HOST_HAS_ADVISOR -eq 0 ]]; then
  refuse 5 "the set at $FROM_DISPLAY carries an Advisor's state, and this host has none
       installed. Install it, then run this again:

           curl -fsSL https://get.aperire.one/advisor | bash -s -- --yes"
fi
if [[ $SET_HAS_ADVISOR -eq 0 && $HOST_HAS_ADVISOR -eq 1 ]]; then
  refuse 5 "this host runs an Advisor ($ADVISOR_UNIT), and the set at $FROM_DISPLAY carries no
       Advisor state at all. Restoring the rest would leave that Advisor's own
       ledger untouched while everything else moves back to backup time. If
       that is what you want, remove the Advisor first:
           curl -fsSL https://get.aperire.one/uninstall | bash -s -- --role=advisor
       or use a set taken from this host with its Advisor already installed."
fi

# ── the Advisor's account, resolved from this host, never the set's ──────
# The set's OWNERSHIP recorded the old host's account by name; that name is
# only ever used below in a sentence, never as a chown target (#515). Owner
# and group both come from THIS host's own Advisor unit and its own
# account, and from the table's fixed shape: the directory and the two
# tokens on the shared group, everything else on the account's own group,
# never from a recorded mode or a recorded path (#537, #544 finding 097).
ADVISOR_ACCOUNT=""; ADVISOR_GROUP=""; ADVISOR_STATE_LOCAL=""; ADVISOR_SHARED_GROUP=""
if [[ $HOST_HAS_ADVISOR -eq 1 ]]; then
  ADVISOR_ACCOUNT="$(bkset_unit_user "$ADVISOR_UNIT")"
  [[ -n "$ADVISOR_ACCOUNT" ]] || ADVISOR_ACCOUNT=root
  ADVISOR_GROUP="$(id -gn "$ADVISOR_ACCOUNT" 2>/dev/null || true)"
  [[ -n "$ADVISOR_GROUP" ]] || ADVISOR_GROUP="$ADVISOR_ACCOUNT"
  ADVISOR_STATE_LOCAL="$(bkset_advisor_state "$ADVISOR_UNIT")"
  [[ -n "$ADVISOR_STATE_LOCAL" ]] || ADVISOR_STATE_LOCAL="$REPO_DIR/advisor/state"
  # The group actually shared between the dashboard and the Advisor on THIS
  # host, read from what the installer itself recorded rather than assumed:
  # advisor-owner-lib.sh's advisor_owner_shared_group reads the unit's own
  # effective SupplementaryGroups=, the exact line install-advisor-account.sh
  # writes on a split-account install (aperire-svc today, but never hardcoded
  # here either, #568). A --advisor-shared-account install (or any future
  # auto-detected equivalent, e.g. systemd<250) never moves the Advisor off
  # the dashboard's own account, advisor_owner_moved says so, and there is no
  # split to share a group across there: the account's own primary group is
  # the correct and only answer (#755).
  [[ -r "$SELF_DIR/advisor-owner-lib.sh" ]] \
    || refuse 4 "$SELF_DIR/advisor-owner-lib.sh is missing from this checkout. Nothing was changed."
  # shellcheck source=scripts/advisor-owner-lib.sh
  . "$SELF_DIR/advisor-owner-lib.sh"
  # advisor-owner-lib.sh's own functions take a unit PATH, never the bare
  # name bkset_unit_user and friends use (they resolve through $UNIT_DIR
  # themselves); a bare name here would silently read as "no such file",
  # which is indistinguishable from "not moved" and would have picked the
  # wrong branch below on every real host (#755, found running this suite).
  ADVISOR_UNIT_PATH="$UNIT_DIR/$ADVISOR_UNIT.service"
  if advisor_owner_moved "$ADVISOR_UNIT_PATH" "$DASH_USER"; then
    ADVISOR_SHARED_GROUP="$(advisor_owner_shared_group "$ADVISOR_UNIT_PATH" "$DASH_USER")"
    [[ -n "$ADVISOR_SHARED_GROUP" ]] || refuse 4 "the Advisor on this host runs as '$ADVISOR_ACCOUNT', not the
       dashboard's own account '$DASH_USER', and its unit names no shared
       group to put its state and its two dashboard-readable tokens on.
       Nothing was changed. Fix it with:
       curl -fsSL https://get.aperire.one | bash -s -- --dir $REPO_DIR --run advisor-account"
    # The same rule aperire-fleet-broker.sh's own SHARED_GROUP enforces: a
    # group the dashboard is not actually in is a refusal, never a write,
    # because every token this restore places on it would come back
    # unreadable to the dashboard the moment services restart.
    case " $(id -nG "$DASH_USER" 2>/dev/null) " in
      *" $ADVISOR_SHARED_GROUP "*) : ;;
      *) refuse 4 "the dashboard account '$DASH_USER' is not a member of
       '$ADVISOR_SHARED_GROUP', the group this host's Advisor unit names as
       shared with it, so it could not read the Advisor's tokens once
       services restart. Nothing was changed. Fix it with:
       curl -fsSL https://get.aperire.one | bash -s -- --dir $REPO_DIR --run advisor-account" ;;
    esac
  else
    ADVISOR_SHARED_GROUP="$ADVISOR_GROUP"
  fi
  if [[ $SET_HAS_ADVISOR -eq 1 ]]; then
    info "advisor account: $FROM_DISPLAY/advisor-state goes to '$ADVISOR_ACCOUNT' here, this host's own Advisor, not the backup's recorded owner"
  fi
  # A link planted at $ADVISOR_STATE_LOCAL itself (or at anything above it,
  # up to its own root) is refused HERE, before anything stops, the same
  # "before anything stops" rule the two refusals above already follow
  # (#755, review). Without this, the same symlink is only ever discovered
  # once state-file.py's own mkdir/own refuses it deep inside the restore,
  # after services are already down. `ancestors` changes nothing and reads
  # only; --root stops the walk at the directory itself since a fresh
  # install has no such directory yet to walk into.
  #
  # `ancestors` itself only inspects the leaf name when `isdir()` (which
  # follows a link) says it resolves to a directory, so a DANGLING symlink or
  # a plain file sitting at that name would pass this walk unseen; the
  # explicit `-L`/`-e && ! -d` check below is what actually catches those two
  # shapes, before anything stops, the same as the live-directory-symlink
  # case `ancestors` does catch.
  if [[ -L "$ADVISOR_STATE_LOCAL" ]] || { [[ -e "$ADVISOR_STATE_LOCAL" ]] && [[ ! -d "$ADVISOR_STATE_LOCAL" ]]; }; then
    refuse 4 "$ADVISOR_STATE_LOCAL exists and is not a real directory (it may be a
       symlink, dangling or not). Nothing was changed. Remove or rename it
       and run this restore again; a fresh directory is created in its
       place."
  fi
  if [[ -e "$ADVISOR_STATE_LOCAL" ]]; then
    _adv_ancestor_problems="$(python3 -I "$STATE_FILE_TOOL" ancestors "$ADVISOR_STATE_LOCAL" --root "$ADVISOR_STATE_LOCAL" 2>&1)"
    if [[ -n "$_adv_ancestor_problems" ]]; then
      if [[ "$_adv_ancestor_problems" == *unwalkable* ]]; then
        # A link somewhere above the state directory itself, not a mode
        # problem: naming a repair script would be wrong advice.
        refuse 4 "$ADVISOR_STATE_LOCAL could not be walked safely:
       $_adv_ancestor_problems
       Nothing was changed. Remove or rename whichever path that names and
       run this restore again."
      else
        # An ancestor directory writable by an account that is not its
        # owner (the koi #703 shape): the existing repair for this exact
        # rule, never invented here.
        refuse 4 "$ADVISOR_STATE_LOCAL could not be walked safely:
       $_adv_ancestor_problems
       Nothing was changed. Repair it with:
       curl -fsSL https://get.aperire.one | bash -s -- --update --force"
      fi
    fi
  fi
fi

# ── accounts OWNERSHIP names that this host does not have: a note ──────
# Nothing in this restore takes an owner or a group from OWNERSHIP: every
# file lands on this host's own accounts, resolved from its own units above,
# and each of those is refused there if it does not resolve. So a name only
# the set knows is reported, never a reason to stop (#777). This used to
# refuse, with a `useradd`/`groupadd` remedy for an account nothing here
# would ever use: a set taken on a host with its Advisor on its own account
# (aperire-advisor, aperire-svc) refused onto a host still on the retired
# shared account, and any set refused onto a host whose operator login has
# another name. Creating the account was a workaround, not a fix (#755).
note_foreign_accounts() {
  local seen=" " i name kind names=()
  for i in "${!RS_OWNERS[@]}"; do
    for kind in user group; do
      if [[ $kind == user ]]; then name=${RS_OWNERS[$i]}; else name=${RS_GRPS[$i]}; fi
      [[ -n "$name" && "$seen" != *" $kind:$name "* ]] || continue
      seen="$seen$kind:$name "
      if [[ $kind == user ]]; then
        id -u "$name" >/dev/null 2>&1 && continue
      else
        getent group "$name" >/dev/null 2>&1 && continue
      fi
      names+=("$kind $name")
    done
  done
  [[ ${#names[@]} -gt 0 ]] || return 0
  # Names out of the set, on root's terminal: printable ASCII only.
  local listed
  listed="$(printf '%s' "${names[*]}" | LC_ALL=C tr -c '[:print:]' '?')"
  info "note: OWNERSHIP names accounts this host does not have ($listed). The set"
  info "      was taken on a host shaped differently. Nothing takes an owner from"
  info "      OWNERSHIP: every file lands on this host's own accounts, so nothing"
  info "      needs creating."
}
note_foreign_accounts

# What the restore DOES apply is this host's own Advisor account and its two
# groups, so those are the names that have to resolve, and they are checked
# here, before anything stops, rather than met as a failure mid-restore.
if [[ $HOST_HAS_ADVISOR -eq 1 && -d "$FROM/advisor-state" ]]; then
  _own_missing=""
  id -u "$ADVISOR_ACCOUNT" >/dev/null 2>&1 || _own_missing="$_own_missing user $ADVISOR_ACCOUNT"
  for _g in "$ADVISOR_GROUP" "$ADVISOR_SHARED_GROUP"; do
    getent group "$_g" >/dev/null 2>&1 || _own_missing="$_own_missing group $_g"
  done
  [[ -z "$_own_missing" ]] || refuse 4 "this host's own Advisor unit names accounts that do not resolve here:$_own_missing.
       Re-run the Advisor installer, which creates them, then run this again.
       Nothing was changed:
           curl -fsSL https://get.aperire.one | bash -s -- --update --force"
fi

# ── an aggregator's fleet secrets, checked before anything stops (#791, #744)
# Three files an aggregator holds that a rebuild cannot recreate: the hash of
# every node's link credential (fleet-links.json, restored with the fleet
# config below), the tokens it presents to its nodes, and its private fleet
# arm key. Every refusal for them happens HERE, before the dry-run exit and
# before the database question, so nothing has stopped when one fires and a
# --dry-run shows it too.
SET_HAS_FLEET_LINKS=0; [[ -f "$FROM/config/fleet-links.json" ]] && SET_HAS_FLEET_LINKS=1
SET_HAS_FLEET_TOKENS=0; [[ -d "$FROM/fleet-tokens" ]] && SET_HAS_FLEET_TOKENS=1
SET_HAS_ARM_PRIV=0; [[ -f "$FROM/fleet-arm.key" ]] && SET_HAS_ARM_PRIV=1
TOKEN_DIR_LOCAL="$ETC_APERIRE/fleet-tokens"
ARM_PRIV_LOCAL="$ETC_APERIRE/fleet-arm.key"
TOKEN_GROUP=""
ARM_PRIV_ACTION=""   # "place" (none here yet) or "same" (this host's own is the set's)
ARM_PRIV_PUB=""

# The public half, derived the way aperire-fleet-broker.sh derives the one it
# hands a node at pairing: the last 32 bytes of the DER public key, base64.
# `-passin pass:` with no stdin: an encrypted key fails closed as unreadable
# rather than stopping a root restore at a pass-phrase prompt openssl opens
# on the terminal itself, past any redirection.
arm_pub_of() { openssl pkey -passin pass: -in "$1" -pubout -outform DER 2>/dev/null </dev/null | tail -c 32 | base64 -w0; }
is_ed25519_key() { [[ "$(openssl pkey -passin pass: -in "$1" -noout -text 2>/dev/null </dev/null | head -1)" == "ED25519 Private-Key:"* ]]; }

if [[ $SET_HAS_FLEET_TOKENS -eq 1 ]]; then
  # Flat, plain, label-shaped files only: what the broker's own write_token
  # ever leaves in that directory. The manifest checks above already proved
  # nothing in the set is a link; this proves no name in it could become a
  # path anywhere but straight inside the one directory it belongs in.
  while IFS= read -r -d '' _tp; do
    _tn="${_tp#"$FROM/fleet-tokens/"}"
    if [[ ! -f "$_tp" || "$_tn" == */* || ! "$_tn" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
      refuse 3 "the set at $FROM_DISPLAY holds fleet-tokens/$_tn, which is not a
           plain, token-shaped file name. Nothing was touched."
    fi
  done < <(find "$FROM/fleet-tokens" -mindepth 1 -print0 2>/dev/null)
  if [[ -L "$TOKEN_DIR_LOCAL" ]] || { [[ -e "$TOKEN_DIR_LOCAL" ]] && [[ ! -d "$TOKEN_DIR_LOCAL" ]]; }; then
    refuse 4 "$TOKEN_DIR_LOCAL exists and is not a real directory (it may be a
       symlink). Nothing was changed. Remove or rename it and run this
       restore again; a fresh directory is created in its place."
  fi
  TOKEN_GROUP="$(bkset_fleet_token_group "$DASH_USER")"; _tg_rc=$?
  # 3 is "the Advisor's unit is there and says nothing this can read", which
  # is not "no Advisor" and not "share no group": named for what it is.
  [[ $_tg_rc -ne 3 ]] || refuse 4 "$(advisor_owner_unread_msg "$UNIT_DIR/aperire-advisord.service")"
  [[ $_tg_rc -eq 0 ]] || TOKEN_GROUP=""
  [[ -n "$TOKEN_GROUP" ]] || refuse 4 "this host's Advisor and its dashboard account '$DASH_USER'
       share no group, so a fleet token could not be readable by both, the
       same refusal the fleet broker makes before it writes one. Nothing was
       changed. Fix it with:
       curl -fsSL https://get.aperire.one | bash -s -- --dir $REPO_DIR --run advisor-account"
fi

if [[ $SET_HAS_ARM_PRIV -eq 1 ]]; then
  command -v openssl >/dev/null 2>&1 || refuse 9 "the set at $FROM_DISPLAY carries a fleet arm
       key, and this host has no openssl to check it with. Install it
       (apt install openssl) and run this again. Nothing was touched."
  is_ed25519_key "$FROM/fleet-arm.key" || refuse 3 "the set at $FROM_DISPLAY carries a fleet-arm.key that is not
       an Ed25519 private key. Nothing was touched."
  ARM_PRIV_PUB="$(arm_pub_of "$FROM/fleet-arm.key")"
  [[ -n "$ARM_PRIV_PUB" ]] || refuse 3 "the fleet-arm.key in the set at $FROM_DISPLAY has no public
       half openssl can read. Nothing was touched."
  if [[ -L "$ARM_PRIV_LOCAL" ]] || { [[ -e "$ARM_PRIV_LOCAL" ]] && [[ ! -f "$ARM_PRIV_LOCAL" ]]; }; then
    refuse 9 "$ARM_PRIV_LOCAL exists and is not a plain file (it may be a
       symlink). This restore never writes through it or over it. Look at it
       by hand. Nothing was touched."
  elif [[ -f "$ARM_PRIV_LOCAL" ]]; then
    # One name only, checked here, before anything stops: the key is re-owned
    # on its open file further down, and that refuses a file with a second
    # name (#965). The usual second name is a temp the broker, or a restore,
    # placed the key through and was killed before removing (.fleet-arm.key.*).
    _arm_links="$(stat -c %h -- "$ARM_PRIV_LOCAL" 2>/dev/null || echo 0)"
    if [[ "$_arm_links" != 1 ]]; then
      _arm_other="$(find "$ETC_APERIRE" -maxdepth 1 -samefile "$ARM_PRIV_LOCAL" ! -path "$ARM_PRIV_LOCAL" 2>/dev/null \
        | LC_ALL=C tr -c '[:print:]\n' '?' | head -5)"
      if [[ -n "$_arm_other" ]]; then
        _arm_names="" _arm_rm=""
        while IFS= read -r _l; do
          _arm_names+=$'\n'"           $_l"
          _arm_rm+=$'\n'"           sudo rm -- $_l"
        done <<<"$_arm_other"
        refuse 9 "$ARM_PRIV_LOCAL has a second name, left by a placement that was
       stopped before it removed its temporary file:$_arm_names
       Remove it, then run this again. Nothing was touched:$_arm_rm"
      fi
      refuse 9 "$ARM_PRIV_LOCAL has $_arm_links names, and the other is not in
       $ETC_APERIRE. A restore never re-owns a file with a second name. Find
       it with: sudo find / -xdev -samefile $ARM_PRIV_LOCAL
       Nothing was touched."
    fi
    if cmp -s -- "$FROM/fleet-arm.key" "$ARM_PRIV_LOCAL"; then
      ARM_PRIV_ACTION=same
    else
      # Not byte-identical. The same key written out another way is still the
      # same key, and the public half is what every node trusts, so that is
      # what is compared. A key openssl cannot read on this side proves
      # nothing, and is refused the same as a different one.
      _live_pub="$(arm_pub_of "$ARM_PRIV_LOCAL")"
      if [[ -n "$_live_pub" && "$_live_pub" == "$ARM_PRIV_PUB" ]] && is_ed25519_key "$ARM_PRIV_LOCAL"; then
        ARM_PRIV_ACTION=same
      else
        refuse 9 "this host already has a fleet arm key, and it is not the one in the set.

               on this host:  $ARM_PRIV_LOCAL  public half ${_live_pub:-(unreadable)}
               in the set:    fleet-arm.key  public half $ARM_PRIV_PUB

           Every node paired to the key already here trusts it, and would refuse
           every arm from this aggregator if it were replaced, so this restore
           never replaces it. If you are certain the key here is the wrong one
           (the pairing grant installed, or a pairing approved, on this host
           before the restore made a fresh one, say), move it aside yourself,
           then run this again:

               sudo mv $ARM_PRIV_LOCAL /root/fleet-arm.key.replaced

           Nodes paired to that key will need pairing again. Nothing was touched."
      fi
    fi
  else
    ARM_PRIV_ACTION=place
  fi
fi

# ── root's pin of the fleet trust key (#1008) ───────────────────────────
# The set carries root's own pin, and the restore pins from that copy, never
# from the set's fleet-trust.yaml, which is the dashboard account's file. A
# pin already here that differs is the key every node paired to this host
# trusts, so it is replaced only when --replace-trust-pin says so. Checked
# here, before anything stops.
SET_PIN=""
PIN_LOCAL="$ETC_APERIRE/fleet-trust.pub"
# The public half of the key in the set's own fleet-trust.yaml, when it holds
# one, derived the split's way (fts_render). Compared, never pinned from.
SET_YAML_PUB=""
if [[ -f "$FROM/config/fleet-trust.yaml" && -r "$SELF_DIR/fleet-trust-split.sh" ]]; then
  # shellcheck source=scripts/fleet-trust-split.sh
  . "$SELF_DIR/fleet-trust-split.sh"
  SET_YAML_PUB="$(fts_render < "$FROM/config/fleet-trust.yaml" 2>/dev/null | sed -n 's/^public_key: //p'; exit "${PIPESTATUS[0]}")" || SET_YAML_PUB=""
fi
if [[ -f "$FROM/fleet-trust.pub" ]]; then
  SET_PIN="$(head -c 128 -- "$FROM/fleet-trust.pub" 2>/dev/null)" || SET_PIN=""
  [[ "$SET_PIN" =~ ^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$ ]] \
    || refuse 3 "the set at $FROM_DISPLAY carries a fleet-trust.pub that is not one 32-byte
       public key. Nothing was touched."
  if [[ -L "$PIN_LOCAL" ]] || { [[ -e "$PIN_LOCAL" ]] && [[ ! -f "$PIN_LOCAL" ]]; }; then
    refuse 9 "$PIN_LOCAL exists and is not a plain file (it may be a symlink).
       This restore never writes through it or over it. Look at it by hand.
       Nothing was touched."
  elif [[ -f "$PIN_LOCAL" ]]; then
    _pin_here="$(head -c 128 -- "$PIN_LOCAL" 2>/dev/null)" || _pin_here=""
    if [[ "$_pin_here" != "$SET_PIN" && $REPLACE_TRUST_PIN -ne 1 ]]; then
      refuse 9 "this host already pins a fleet trust key, and it is not the one in the set.

               on this host:  $PIN_LOCAL  ${_pin_here:-(unreadable)}
               in the set:    fleet-trust.pub  $SET_PIN

           Every node paired to this host trusts the key pinned here, so this
           restore never replaces it on its own. If the set's key is the one you
           mean this aggregator to use, run this again with --replace-trust-pin.
           Nodes paired to the key here will need pairing again. Nothing was touched."
    fi
  fi
  # The set's own key file was the dashboard account's when the set was
  # taken. A key in it that is not root's pin was planted or changed after
  # the pin, and restoring it would leave a key root refuses to vouch for.
  if [[ -n "$SET_YAML_PUB" && "$SET_YAML_PUB" != "$SET_PIN" ]]; then
    refuse 3 "the set at $FROM_DISPLAY carries a fleet trust key that is not the one
       root pinned when the set was taken.

               root's pin in the set:     $SET_PIN
               key in the set's yaml:     $SET_YAML_PUB

       The dashboard account could write that file, so this restore will not put
       it back. Restore from a set taken while the two agreed. Nothing was touched."
  fi
elif [[ -n "$SET_YAML_PUB" ]]; then
  # A set taken before root pinned the key (#1008) carries no pin. Its key is
  # pinned on first sight, the same reach an update has, and said so here.
  if [[ -e "$PIN_LOCAL" || -L "$PIN_LOCAL" ]]; then
    _pin_here="$(head -c 128 -- "$PIN_LOCAL" 2>/dev/null)" || _pin_here=""
    if [[ "$_pin_here" != "$SET_YAML_PUB" ]]; then
      refuse 9 "this host already pins a fleet trust key, and the set, taken before
       root pinned one, carries a different key and no pin of its own.

               on this host:  $PIN_LOCAL  ${_pin_here:-(unreadable)}
               in the set:    fleet-trust.yaml  $SET_YAML_PUB

           Every node paired to this host trusts the key pinned here. Restore from
           a set taken after this host pinned its key. Nothing was touched."
    fi
  else
    info "note  this set was taken before root pinned the fleet trust key, so it carries no pin."
    info "      Root will pin the key in its fleet-trust.yaml on first sight ($SET_YAML_PUB):"
    info "      compare it with the key a paired node holds before you trust it."
  fi
fi

# ── the numeric groups /etc/aperire's files are planted with (#965) ─────
# state-file.py takes numbers only, and every file below lands through it,
# so the names are turned into numbers here, before anything stops.
DASH_ENV_GROUP=""; DASH_ENV_GID=""
if [[ -f "$FROM/aperire.env" ]]; then
  DASH_ENV_GROUP="$(id -gn "$DASH_USER" 2>/dev/null || true)"
  [[ -n "$DASH_ENV_GROUP" ]] || DASH_ENV_GROUP="$DASH_USER"
  DASH_ENV_GID="$(getent group "$DASH_ENV_GROUP" 2>/dev/null | head -1 | cut -d: -f3)"
  [[ "$DASH_ENV_GID" =~ ^[0-9]+$ ]] || refuse 4 "could not resolve a numeric gid for '$DASH_ENV_GROUP', the group
       aperire.env is read through. Nothing was touched."
fi
# Does this host run a node? Asked the ways the installers ask it: the
# node installer's record, a wrapper configuration naming a node (an
# aggregator's says SERVICE=none), a running rippled, xrpld or xahaud, or a
# container of one. Read only; a stopped node with no record reads as none.
restore_host_has_node() {
  local f n
  [[ -f "$ETC_APERIRE/node.conf" ]] && return 0
  for f in "$ETC_APERIRE"/node-wrapper.conf "$ETC_APERIRE"/node-wrapper-*.conf; do
    [[ -f "$f" ]] || continue
    [[ "$(sed -n 's/^SERVICE=//p' "$f" | head -1)" == none ]] || return 0
  done
  for f in "$PROC_DIR"/[0-9]*/comm; do
    n="$(cat "$f" 2>/dev/null || true)"
    case "$n" in rippled|xrpld|xahaud) return 0 ;; esac
  done
  if command -v docker >/dev/null 2>&1 \
     && timeout 10 docker ps --format '{{.Image}} {{.Names}}' 2>/dev/null | grep -aiqE 'rippled|xrpld|xahaud'; then
    return 0
  fi
  return 1
}

# The relay's group, from this host's own relay unit when it has one, the
# relay's own account name when it does not. Settled here, before anything
# stops (#777: the set's own names used to catch this, by accident).
#
# A host with no such group is one of two hosts (#826). One that runs a node
# should have a relay beside it, so it is refused, with the bootstrap steps
# that build and wire one. One that runs no node has nothing for a relay to
# read: relay.conf is left out, said so, and the restore goes on. The
# dashboard's half of the token pair is in aperire.env and lands as usual.
RELAY_GROUP=""; RELAY_GID=""; RELAY_CONF_SKIPPED=0
if [[ -f "$FROM/relay.conf" ]]; then
  _relay_unit="$(bkset_relay_unit "$INSTANCE" || true)"
  RELAY_ACCOUNT=""
  [[ -n "$_relay_unit" ]] && RELAY_ACCOUNT="$(bkset_unit_user "$_relay_unit")"
  [[ -n "$RELAY_ACCOUNT" ]] || RELAY_ACCOUNT=aperire-relay
  RELAY_GROUP="$(id -gn "$RELAY_ACCOUNT" 2>/dev/null || true)"; [[ -n "$RELAY_GROUP" ]] || RELAY_GROUP="$RELAY_ACCOUNT"
  RELAY_GID="$(getent group "$RELAY_GROUP" 2>/dev/null | head -1 | cut -d: -f3)"
  if [[ ! "$RELAY_GID" =~ ^[0-9]+$ ]]; then
    RELAY_GID=""
    if restore_host_has_node; then
      _relay_bin="$RELAY_BIN_INSTALLED"
      [[ -x "$_relay_bin" ]] || _relay_bin="$REPO_DIR/relay/aperire-relay"
      _relay_build=""
      [[ -x "$_relay_bin" ]] || _relay_build="
           curl -fsSL https://get.aperire.one | bash -s -- --dir $REPO_DIR --run prepare-host --role co-located"
      refuse 4 "the set carries relay.conf, and this host has no '$RELAY_GROUP' group for the
       relay to read it through. This host runs a node, so its relay belongs
       here. Install it beside the dashboard, then run this again:
${_relay_build}
           curl -fsSL https://get.aperire.one | bash -s -- --dir $REPO_DIR --run relay-colocated --unit $DASH_UNIT --port $PORT --binary $_relay_bin

       Nothing was touched."
    fi
    RELAY_CONF_SKIPPED=1
    info "note: the set carries relay.conf, the relay's config from the host it was taken on."
    info "      This host runs no node, so there is no relay here to read it, and it is left out."
  fi
fi
TOKEN_GID=""
if [[ -n "$TOKEN_GROUP" ]]; then
  TOKEN_GID="$(getent group "$TOKEN_GROUP" 2>/dev/null | head -1 | cut -d: -f3)"
  [[ "$TOKEN_GID" =~ ^[0-9]+$ ]] || refuse 4 "could not resolve a numeric gid for '$TOKEN_GROUP', the group the
       node tokens are read through. Nothing was touched."
fi

if [[ $DRY -eq 1 ]]; then
  echo
  [[ $SET_HAS_ARM_PRIV -eq 1 ]] && echo "(fleet arm key: $([[ "$ARM_PRIV_ACTION" == same ]] && echo "this host's own is the set's, left as it is" || echo "none here yet, the set's would be placed"); public half $ARM_PRIV_PUB)"
  echo "(dry run: manifest verifies, accounts resolve, Advisor maps to '$ADVISOR_ACCOUNT'; nothing changed)"
  exit 0
fi

if [[ $ASSUME_YES -ne 1 ]]; then
  if ! IFS= read -r -p $'\nThis stops services and replaces the database, config and tokens on this host. Proceed? [y/N] ' reply; then
    echo; refuse 2 "no terminal to confirm on; pass --yes"
  fi
  case "$reply" in y|Y|yes|YES) ;; *) echo "aborted."; exit 0 ;; esac
fi

# ── is the database restore destructive? (#562) ───────────────────────
# A dashboard writes metrics, ledgers and sessions continuously, so a live
# database differs from a set taken even a minute earlier the moment real
# traffic has touched it, and that is expected, not a reason to ask twice:
# a second, identical restore still says "no files needed to change" below,
# once the write is done. What is worth stopping for is a live database that
# has moved on with content of its own -- an operator enrolled, a passkey
# registered -- and is not simply the set's own content already installed.
# Overwriting that silently is how a second restore rolls a host back
# without saying so; it used to (found in the #544 drill).
#
# Two comparisons, cheapest first. A raw byte hash can only ever prove
# equality correctly (identical bytes are identical content, full stop), so
# it is tried first and, when it matches, nothing more is asked; it is not
# trusted to prove a difference, because VACUUM INTO (how a backup takes the
# database) reformats the file even when the content did not change, and a
# raw hash would read that reformat as drift. When the raw hash does not
# settle it, the only correct next step is the content-level comparison
# below, and that one is not cheap on a large database, so this says so
# before running it rather than leaving the operator watching a silent
# pause.
if [[ -f "$FROM/aperire.db" && -f "$DB_DEST" ]]; then
  _raw_from="$(sha256sum -- "$FROM/aperire.db" 2>/dev/null | awk '{print $1}')"
  _raw_dest="$(as_dashboard sha256sum -- "$DB_DEST" 2>/dev/null | awk '{print $1}')"
  if [[ -n "$_raw_from" && "$_raw_from" == "$_raw_dest" ]]; then
    _content_diverged=0
  else
    info "comparing databases, this can take a minute on a large one"
    if [[ "$(db_dump_hash "$FROM/aperire.db")" != "$(db_dump_hash "$DB_DEST")" ]]; then
      _content_diverged=1
    else
      _content_diverged=0
    fi
  fi
  if [[ $_content_diverged -eq 1 ]]; then
    # What marks a database as somebody's, never "any table has any row":
    # #562 originally asked this over `rows > 0` across every table, which
    # asked the destructive question of a host that had merely polled for a
    # minute since a fresh reinstall -- real rows in a growing metrics table,
    # nobody enrolled yet. "unknown" (sqlite3 could not read the file as a
    # database at all) is treated the same as "owned": a database this
    # tooling cannot examine is never waved through as safe to replace.
    _owned="$(db_owner_rows "$DB_DEST")"
    if [[ "$_owned" == unknown || "$_owned" -gt 0 ]]; then
      _set_rows="$(db_total_rows "$FROM/aperire.db")"
      _live_rows="$(db_total_rows "$DB_DEST")"
      _newest="$(db_newest_ts "$DB_DEST")"
      say "this host's database has moved on since the set at $FROM_DISPLAY"
      if [[ "$_owned" == unknown ]]; then
        info "this host now: could not be read as a database; refusing to assume it is safe to replace"
      else
        info "this host now: $_owned operator/passkey row(s), $_live_rows row(s) total, newest activity: $_newest"
      fi
      info "the set:        $_set_rows row(s) total"
      info "restoring would roll this host's database back to the set's own time."
      info "a safety copy of what is here now is taken first, kept for the last two runs."
      if [[ $ASSUME_YES -eq 1 ]]; then
        if [[ $OVERWRITE -ne 1 ]]; then
          refuse 7 "this host's database has content the set does not, see above. Re-run
               with --overwrite as well as --yes to replace it anyway, or restore
               onto a host whose database has not moved on since the backup.
               Nothing was touched."
        fi
        info "--overwrite given: replacing it anyway."
      else
        if ! IFS= read -r -p $'\nOverwrite the database on this host with the one in the set? [y/N] ' db_reply; then
          echo; refuse 2 "no terminal to confirm on; pass --yes --overwrite"
        fi
        case "$db_reply" in y|Y|yes|YES) ;; *) echo "aborted."; exit 0 ;; esac
      fi
    fi
  fi
fi

CHANGED=0
SERVICES_STOPPED=0

# ── a safety copy of everything about to change, before it changes ───────
# Root-owned, 0700, beside the install, stamped and printed, pruned to the
# last two. A step that fails after this point stops with this copy intact
# (#544 finding 099): this restore only ever adds to what a rebuild can
# recover from, it never bets the only copy on itself succeeding.
# The PID suffix is not for uniqueness across hosts, it is so two restores
# started in the same second (a drill script running one right after
# another) never share a directory and one run's safety copy silently
# folds into another's.
SAFETY_ROOT="${REPO_DIR}-restore-safety"
SAFETY_STAMP="$(date -u +%Y%m%dT%H%M%SZ)-$$"
SAFETY_DIR="$SAFETY_ROOT/$SAFETY_STAMP"

fail_stop() {  # <message...>
  printf '\n%serror mid-restore:%s %s\n' "${E_RED:-}" "${E_OFF:-}" "$*" >&2
  if [[ $SERVICES_STOPPED -eq 1 ]]; then
    echo "  services are left stopped." >&2
  else
    echo "  services were never stopped; nothing before this line changed." >&2
  fi
  echo "  a safety copy of what this restore had already touched is at:" >&2
  echo "    $SAFETY_DIR" >&2
  echo "  nothing after this step ran." >&2
  exit 1
}

# The state-file.py verbs this program needs, wrapped the same way
# install-advisor-account.sh's own state_own_file/state_plant_file are:
# numeric ids in, --root at the caller's own advisor/state so the ancestor
# rule stops there (that tree is the Advisor's own by design), never a plain
# name-based chown/chmod/cp for anything under it (#661, #703, #755).
[[ -r "$STATE_FILE_TOOL" ]] || fail_stop "$STATE_FILE_TOOL is missing from this checkout"
state_mkdir_file() {  # <path> <uid> <gid> <mode> <root>
  python3 -I "$STATE_FILE_TOOL" mkdir "$1" "${2:-}" "${3:-}" "${4:-}" --root "$5"
}
state_plant_file() {  # <path> <uid> <gid> <mode> <root>; content on stdin
  python3 -I "$STATE_FILE_TOOL" plant "$1" "${2:-}" "${3:-}" "${4:-}" --stdin --root "$5"
}
state_own_file() {  # <path> <uid> <gid> <mode> <root>
  python3 -I "$STATE_FILE_TOOL" own "$1" "${2:-}" "${3:-}" "${4:-}" --root "$5"
}

# The files under /etc/aperire this restore writes, with this host's own
# table values, never the set's OWNERSHIP (#544 finding 097). Each one is
# planted by descriptor (#965): a new file beside the name, its owner and
# mode set on that open file, then renamed over the name, which replaces a
# link rather than following it. This was `install`, then chown and chmod
# on the name, as root; a link swapped in after the install took both onto
# whatever it pointed at. Ids are numbers, settled before anything stopped.
fixed_sum() {  # <path> -> sha256 of a plain file read on a descriptor, or of nothing
  python3 -I "$STATE_FILE_TOOL" read "$1" --root "$(dirname -- "$1")" 2>/dev/null | sha256sum | awk '{print $1}'
}
fixed_put() {  # <source> <destination> <uid> <gid> <mode>
  local src=$1 dest=$2 before after
  before="$(fixed_sum "$dest")"
  state_plant_file "$dest" "$3" "$4" "$5" "$(dirname -- "$dest")" < "$src" \
    || fail_stop "could not write $dest safely"
  after="$(fixed_sum "$dest")"
  [[ "$before" != "$after" ]] && CHANGED=$((CHANGED + 1))
  return 0
}

say "safety copy"
install -d -m 0700 "$SAFETY_DIR" || refuse 3 "could not create $SAFETY_DIR; nothing was touched"
info "$SAFETY_DIR"

# DB_DEST, ENV_PATH_LOCAL and RELAY_CONF_LOCAL are decided earlier, before
# the confirmation prompt, from the env file that will be in force once this
# restore lands (#561); nothing here recomputes them from the live host.

# A recorded mode or owner that disagrees with this host's own table is
# never applied (#544 finding 097); it is only ever reported, once, here.
# RS_MODES holds `stat -c '%a'` output (no leading zero, e.g. "640"), so
# the wanted value below is compared the same way.
report_ownership_drift() {  # <path> <table-mode, no leading zero>
  local p=$1 want=$2 i seen=""
  for i in "${!RS_PATHS[@]}"; do
    if [[ "${RS_PATHS[$i]}" == "$p" && "${RS_MODES[$i]}" != "$want" && -z "$seen" ]]; then
      seen=1
      info "note: OWNERSHIP recorded $p as mode ${RS_MODES[$i]}; this host's own table always applies $want, and that is what gets written"
    fi
  done
}
report_ownership_drift "$ENV_PATH_LOCAL" 640
report_ownership_drift "$RELAY_CONF_LOCAL" 640
report_ownership_drift "$ETC_APERIRE/fleet-arm.pub" 644
report_ownership_drift "$ETC_APERIRE/fleet-arm.paired.pub" 644
report_ownership_drift "$DB_DEST" 600
# The dashboard-config and fleet-config rows, asked for the same as the four
# above and not before now (#565): every path a mode is ever asserted onto
# below gets checked here, so a tampered or stale OWNERSHIP cannot widen any
# of them in silence, the same guarantee the four already had. advisor-state
# is the one row still not asked: it applies a different mode per file (the
# directory and two shared tokens on one group, everything else on another),
# which this single-mode-per-path function has no way to express, and adding
# it needs its own mechanism, not a wider table here.
for _cf in authn.yaml channels.yaml digest.yaml rules.local.yaml; do
  report_ownership_drift "$REPO_DIR/dashboard/config/$_cf" 640
done
for _cf in fleet.yaml fleet-link.json fleet-links.json; do
  report_ownership_drift "$REPO_DIR/dashboard/config/$_cf" 600
done
# fleet-trust.yaml is not asked here: its mode is not the table's but the
# split's (#868), 0600 with a private_key and 0640 without, decided from the
# file's own content after it is placed, never from OWNERSHIP.
report_ownership_drift "$ARM_PRIV_LOCAL" 600
if [[ $SET_HAS_FLEET_TOKENS -eq 1 ]]; then
  report_ownership_drift "$TOKEN_DIR_LOCAL" 750
  while IFS= read -r -d '' _tp; do
    report_ownership_drift "$TOKEN_DIR_LOCAL/$(basename "$_tp")" 640
  done < <(find "$FROM/fleet-tokens" -mindepth 1 -maxdepth 1 -type f -print0 2>/dev/null)
fi

safety_save() {  # <label> <path...>
  local label=$1 dir="$SAFETY_DIR/$1" any=0 p
  shift
  for p in "$@"; do
    [[ -e "$p" ]] || continue
    mkdir -p "$dir"
    cp -a "$p" "$dir/" 2>/dev/null && any=1
  done
  [[ $any -eq 1 ]] && info "saved: $label"
}
# The database and its two side files are read AS the dashboard's account,
# one plain file at a time, never followed (#776): they sit in that account's
# own directory. Into root's own 0700 safety copy, which nothing else reads.
_db_saved=0
for _p in "$DB_DEST" "$DB_DEST-wal" "$DB_DEST-shm"; do
  [[ -e "$_p" || -L "$_p" ]] || continue
  mkdir -p "$SAFETY_DIR/database"
  if ( umask 077; db_place read "$_p" > "$SAFETY_DIR/database/$(basename -- "$_p")" ); then
    _db_saved=1
  else
    rm -f -- "$SAFETY_DIR/database/$(basename -- "$_p")"
    refuse 4 "could not take a safety copy of $_p as the dashboard's account
       ($DASH_USER). It is either not a plain file with one link, or that
       account cannot read it. Nothing was stopped and nothing was restored;
       the partial safety copy is at $SAFETY_DIR."
  fi
done
[[ $_db_saved -eq 1 ]] && info "saved: database"
safety_save config "$REPO_DIR"/dashboard/config/{authn,channels,digest,rules.local}.yaml \
                    "$REPO_DIR"/dashboard/config/{fleet.yaml,fleet-trust.yaml,fleet-link.json,fleet-links.json}
safety_save relay-env "$ENV_PATH_LOCAL"
safety_save relay-conf "$RELAY_CONF_LOCAL"
safety_save fleet-arm-key "$ETC_APERIRE/fleet-arm.pub"
safety_save fleet-arm-held-key "$ETC_APERIRE/fleet-arm.paired.pub"
# The fleet arm key is never saved here: this restore only ever places it
# where none exists, or leaves the same key exactly as it is, so there is
# never an earlier one to lose, and a second copy of a private key is one
# more place it can leak from.
[[ $SET_HAS_FLEET_TOKENS -eq 1 ]] && safety_save fleet-tokens "$TOKEN_DIR_LOCAL"
[[ $HOST_HAS_ADVISOR -eq 1 ]] && safety_save advisor-state "$ADVISOR_STATE_LOCAL"

# prune to the last two, oldest first
mapfile -t _old_safety < <(find "$SAFETY_ROOT" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' 2>/dev/null | LC_ALL=C sort)
while [[ ${#_old_safety[@]} -gt 2 ]]; do
  rm -rf "${SAFETY_ROOT:?}/${_old_safety[0]}"
  _old_safety=("${_old_safety[@]:1}")
done

# ── stop what has to stop ─────────────────────────────────────────────
say "stopping services"
systemctl stop "$DASH_UNIT" 2>/dev/null || true
RELAY_UNIT="$(bkset_relay_unit "$INSTANCE" || true)"
[[ -n "$RELAY_UNIT" ]] && systemctl stop "$RELAY_UNIT" 2>/dev/null
[[ $HOST_HAS_ADVISOR -eq 1 ]] && systemctl stop "$ADVISOR_UNIT" 2>/dev/null
SERVICES_STOPPED=1
info "stopped: $DASH_UNIT${RELAY_UNIT:+, $RELAY_UNIT}${ADVISOR_UNIT:+, $ADVISOR_UNIT}"

# ── the database, this instance's own file, only when the set carries one ─
say "restoring the database"
if [[ -f "$FROM/aperire.db" ]]; then
  # Every step on the destination runs as the dashboard's account, in its own
  # directory (#776, ADR 0024 lane 4): root reads the set's copy out of its
  # private work directory and hands the bytes over on stdin, and never
  # removes, writes, chowns or opens anything at the destination by name.
  before=""; [[ -f "$DB_DEST" ]] && before=$(as_dashboard sha256sum -- "$DB_DEST" 2>/dev/null | awk '{print $1}')
  # Never replace a destination this run has not just proven is either absent
  # or a SQLite database: the one guard that would have stopped the
  # crafted-set attack cold even if the containment check above were somehow
  # bypassed or missing on a --db-path an operator typed in error. Checked on
  # the main file only; -wal/-shm are only ever removed once it has passed.
  db_dest_safe_to_replace "$DB_DEST" || fail_stop "$DB_DEST already exists and is not a
       SQLite database (no \"SQLite format 3\" header); refusing to replace it.
       Nothing at that path was touched."
  # Staged beside it first and checked there, so a set whose database does
  # not pass leaves this host's own in place rather than replaced by it.
  # -D's old job, a database directory a fresh install never creates (an
  # operator's own APERIRE_DB_PATH, #561), is the stage step's: it makes the
  # missing directories as the dashboard's account, 0700.
  _staged="$(db_place stage "$DB_DEST" < "$FROM/aperire.db")" \
    || fail_stop "could not write the restored database beside $DB_DEST as $DASH_USER"
  _staged_path="$(dirname -- "$DB_DEST")/$_staged"
  CHECK="$(_sql "$_staged_path" "file:${_staged_path}?mode=ro" "PRAGMA integrity_check" 2>&1 | tr '\n' ' ')"
  CHECK="${CHECK% }"
  if [[ "$CHECK" != "ok" ]]; then
    db_place discard "$DB_DEST" "$_staged" >/dev/null 2>&1 || true
    fail_stop "the database in the set does not pass integrity_check: $CHECK.
         This host's own database at $DB_DEST was left in place."
  fi
  db_place commit "$DB_DEST" "$_staged" \
    || fail_stop "could not put the restored database in place at $DB_DEST as $DASH_USER"
  after=$(as_dashboard sha256sum -- "$DB_DEST" 2>/dev/null | awk '{print $1}')
  [[ "$before" != "$after" ]] && CHANGED=$((CHANGED + 1))
  info "ok    database  (integrity_check: $CHECK, written as $DASH_USER)"
else
  info "skip  database  the set at $FROM_DISPLAY carries none; this host's own database is left exactly as it was"
fi

# ── dashboard config ────────────────────────────────────────────────
# The four operator files: owned by whoever owns dashboard/config, read by
# the dashboard through its group (ADR 0024's target table). The fleet files:
# the dashboard account's, 0600, as before (#866's L2 decides their owner).
# Every write goes through state-file.py's plant, rooted at dashboard/config:
# a descriptor walk with O_NOFOLLOW, a new file beside the name with its
# owner and mode set on the descriptor, then a rename that replaces a link
# rather than following it. Never install and chown by name (#875 review,
# M2). Owners and ids were settled before anything stopped.
say "restoring config"
cfg_sum() {  # <path> -> sha256 of a plain file read on a descriptor, or nothing
  python3 -I "$STATE_FILE_TOOL" read "$1" --root "$CONFIG_DIR" 2>/dev/null | sha256sum | awk '{print $1}'
}
cfg_put() {  # <name> <uid> <gid> <mode>
  local f=$1 dest="$CONFIG_DIR/$1" before after
  before="$(cfg_sum "$dest")"
  state_plant_file "$dest" "$2" "$3" "$4" "$CONFIG_DIR" < "$FROM/config/$f" \
    || fail_stop "could not write $dest safely"
  after="$(cfg_sum "$dest")"
  [[ "$before" != "$after" ]] && CHANGED=$((CHANGED + 1))
  info "ok    $f"
}
for f in authn.yaml channels.yaml digest.yaml rules.local.yaml; do
  [[ -f "$FROM/config/$f" ]] || continue
  cfg_put "$f" "$CONFIG_UID" "$CONFIG_GID" 0640
done

# ── fleet config, named ownership rather than whoever ran this ───────
for f in fleet.yaml fleet-trust.yaml fleet-link.json fleet-links.json; do
  [[ -f "$FROM/config/$f" ]] || continue
  # A node's peers-only fleet-trust.yaml goes back the way pairing makes it,
  # root's on the group the Advisor shares, 0640 (#873 review, M2). Its
  # peers.aggregator is the key the Advisor verifies every push against, and
  # a file the dashboard account owned is one it could repin. Only a file
  # read and found to hold no private_key takes that shape; one with a key,
  # or one this could not read, stays the dashboard account's at 0600.
  # Both shapes are written through cfg_put, by descriptor, never by name.
  _ft_rc=0
  [[ "$f" == fleet-trust.yaml ]] && { grep -q '^private_key:' "$FROM/config/$f" 2>/dev/null || _ft_rc=$?; }
  if [[ "$f" == fleet-trust.yaml && $_ft_rc -eq 1 ]]; then
    _ft_group="${ADVISOR_SHARED_GROUP:-}"
    [[ -n "$_ft_group" ]] || _ft_group="$(id -gn "$DASH_USER" 2>/dev/null || echo "$DASH_USER")"
    _ft_gid="$(getent group "$_ft_group" 2>/dev/null | cut -d: -f3)"
    [[ "$_ft_gid" =~ ^[0-9]+$ ]] || fail_stop "could not resolve a numeric gid for '$_ft_group'"
    cfg_put "$f" 0 "$_ft_gid" 0640
  else
    cfg_put "$f" "$DASH_UID" "$DASH_GID" 0600
  fi
done
if [[ -f "$FROM/config/fleet-link.json" ]]; then
  info "fleet-link.json restored: this node dials the aggregator with the same credential it always had"
fi

# ── the fleet trust file, split by who may read what (#868, #821) ────────
# The loop above leaves a fleet-trust.yaml with a private_key the dashboard
# account's at 0600, which is right for an aggregator's key and wrong for the
# Advisor, which reads public keys out of it. A peers-only file never goes
# through that branch: it is planted root:<group> 0640 already.
# fleet-trust-split.sh settles both: a
# file with a private_key stays 0600 and gets its public half beside it,
# fleet-trust.pub.yaml, on the group the Advisor shares with the dashboard;
# a node's peers-only file goes to that group at 0640, where the Advisor
# reads it. The public file is never in a backup set: it is remade here
# from the file that is.
if [[ -e "$REPO_DIR/dashboard/config/fleet-trust.yaml" ]]; then
  _fts_group="$ADVISOR_SHARED_GROUP"
  [[ -n "$_fts_group" ]] || _fts_group="$(id -gn "$DASH_USER" 2>/dev/null || true)"
  _fts_rc=0
  if [[ -r "$SELF_DIR/fleet-trust-split.sh" ]]; then
    # shellcheck source=scripts/fleet-trust-split.sh
    . "$SELF_DIR/fleet-trust-split.sh"
    # Root's pin of the trust key (#1008): root's own copy from the set,
    # checked above, never a key read out of the set's fleet-trust.yaml. A
    # set made before the pin existed carries none, and the split then pins
    # on first sight or compares with the pin here, as an update does.
    _fts_pin_from="$SET_PIN"
    # The Advisor is stopped above and started on its unit's binary below,
    # so that binary is the one asked whether it reads the public file.
    _fts_out="$(FTS_UNIT_DIR="$UNIT_DIR" FTS_ADVISOR_UNIT="${ADVISOR_UNIT:-aperire-advisord}" FTS_ADVISOR_RESTARTING=1 \
      FTS_PIN_FILE="$ETC_APERIRE/fleet-trust.pub" FTS_PIN_FROM="$_fts_pin_from" \
      fts_converge "$REPO_DIR" "$DASH_USER" "$_fts_group" "$STATE_FILE_TOOL" 2>&1)" || _fts_rc=$?
  else
    _fts_rc=1; _fts_out="scripts/fleet-trust-split.sh is missing from this checkout"
  fi
  while IFS= read -r _l; do [[ -n "$_l" ]] && info "$_l"; done <<<"$_fts_out"
  (( _fts_rc == 0 )) \
    || info "WARNING: fleet-trust.yaml is not split (above), so the Advisor may not verify a pushed bundle. Once fixed: curl -fsSL https://get.aperire.one | bash -s -- --update --force"
fi

# ── the relay token pair, both halves, this instance's own files ─────────
if [[ -f "$FROM/aperire.env" ]]; then
  fixed_put "$FROM/aperire.env" "$ENV_PATH_LOCAL" 0 "$DASH_ENV_GID" 0640
  info "ok    aperire.env -> $ENV_PATH_LOCAL"
fi
if [[ -f "$FROM/relay.conf" && $RELAY_CONF_SKIPPED -eq 1 ]]; then
  info "skip  relay.conf: this host runs no node, so it has no relay (above)"
elif [[ -f "$FROM/relay.conf" ]]; then
  # RELAY_GID was settled before anything stopped, from the same unit.
  fixed_put "$FROM/relay.conf" "$RELAY_CONF_LOCAL" 0 "$RELAY_GID" 0640
  info "ok    relay.conf -> $RELAY_CONF_LOCAL"
fi

# ── the fleet arm key, a public key, root : root ──────────────────────
if [[ -f "$FROM/fleet-arm.pub" ]]; then
  fixed_put "$FROM/fleet-arm.pub" "$ETC_APERIRE/fleet-arm.pub" 0 0 0644
  info "ok    fleet-arm.pub"
fi

# ── the held fleet arm key, kept in step with fleet-arm.pub (#724) ───────
# A pairing before this host had an Advisor holds the key at this second
# name (fleet-arm.paired.pub) until the Advisor install places it as
# fleet-arm.pub; a host paired after already has both, kept equal by
# install-model-key-sealer.sh's own sync_held_arm_key every time the trusted
# key changes. Whichever the set carries wins as content, but when the set
# carries fleet-arm.pub too, THAT content is what lands at both names (#726
# review, M1): a stale held copy of an old pairing is otherwise exactly what
# a later --remove and reinstall of the Advisor would place, silently.
if [[ -f "$FROM/fleet-arm.paired.pub" || -f "$FROM/fleet-arm.pub" ]]; then
  HELD_SRC="$FROM/fleet-arm.paired.pub"
  [[ -f "$FROM/fleet-arm.pub" ]] && HELD_SRC="$FROM/fleet-arm.pub"
  fixed_put "$HELD_SRC" "$ETC_APERIRE/fleet-arm.paired.pub" 0 0 0644
  info "ok    fleet-arm.paired.pub"
fi

# ── the tokens this aggregator presents to its nodes (#791) ─────────────
# root : the group the dashboard and the Advisor share, the same owner, group
# and modes aperire-fleet-broker.sh writes, resolved from this host before
# anything stopped, never read out of the set. The directory and everything
# above it are root's own, so nothing unprivileged can swap a name here
# between the check and the write. A token here already for a label the set
# does not name is left alone: it is a credential, not this restore's to
# delete, and fleet.yaml decides which ones are ever read.
if [[ $SET_HAS_FLEET_TOKENS -eq 1 ]]; then
  _tok_before="$(find "$TOKEN_DIR_LOCAL" -type f -exec sha256sum {} + 2>/dev/null | sort | sha256sum)"
  # Created, or confirmed already a real directory, and set on a descriptor
  # (#965): a link at the name is refused, never followed.
  state_mkdir_file "$TOKEN_DIR_LOCAL" 0 "$TOKEN_GID" 0750 "$ETC_APERIRE" \
    || fail_stop "could not create $TOKEN_DIR_LOCAL safely"
  n=0
  while IFS= read -r -d '' _tp; do
    _tn="$(basename "$_tp")"
    dest="$TOKEN_DIR_LOCAL/$_tn"
    if [[ -L "$dest" ]] || { [[ -e "$dest" ]] && [[ ! -f "$dest" ]]; }; then
      fail_stop "$dest is not a plain file; refusing to write through it"
    fi
    state_plant_file "$dest" 0 "$TOKEN_GID" 0640 "$TOKEN_DIR_LOCAL" < "$_tp" \
      || fail_stop "could not write $dest safely"
    n=$((n + 1))
  done < <(find "$FROM/fleet-tokens" -mindepth 1 -maxdepth 1 -type f -print0 2>/dev/null)
  _tok_after="$(find "$TOKEN_DIR_LOCAL" -type f -exec sha256sum {} + 2>/dev/null | sort | sha256sum)"
  [[ "$_tok_before" != "$_tok_after" ]] && CHANGED=$((CHANGED + 1))
  info "ok    fleet-tokens  -> $TOKEN_DIR_LOCAL ($n files, root : $TOKEN_GROUP)"
fi

# ── the aggregator's private fleet arm key (#744) ──────────────────────
# Placed only where none exists, and then the same way the broker makes one:
# a fresh temp file in the same directory (mktemp: O_EXCL, 0600), its owner
# and mode set on the temp, then hard-linked to the final name with `ln -T`,
# which fails rather than replace anything already there. A key that
# appeared since the check above (a pairing approval, or an operator's own
# aperire-fleet-arm.sh) is never overwritten: it stops the restore here and
# says so. The temp's name is the one the broker's own sweep removes after
# ten minutes, should this be killed between the link and the rm.
if [[ "$ARM_PRIV_ACTION" == place ]]; then
  _ktmp="$(umask 077; mktemp "$ETC_APERIRE/.fleet-arm.key.XXXXXX" 2>/dev/null)" \
    || fail_stop "could not make a temporary file in $ETC_APERIRE for the fleet arm key"
  if ! cat -- "$FROM/fleet-arm.key" > "$_ktmp" || ! chown root:root "$_ktmp" || ! chmod 0600 "$_ktmp"; then
    rm -f -- "$_ktmp"
    fail_stop "could not prepare the fleet arm key for $ARM_PRIV_LOCAL"
  fi
  if ! ln -T -- "$_ktmp" "$ARM_PRIV_LOCAL" 2>/dev/null; then
    rm -f -- "$_ktmp"
    fail_stop "a fleet arm key appeared at $ARM_PRIV_LOCAL while this restore ran
       (a pairing approval, or aperire-fleet-arm.sh), and it was left exactly
       as it is: the set's key was not placed. Compare its public half with
       the set's ($ARM_PRIV_PUB) before deciding which one this fleet trusts."
  fi
  rm -f -- "$_ktmp"
  CHANGED=$((CHANGED + 1))
  info "ok    fleet-arm.key  placed, root : root 0600, public half $ARM_PRIV_PUB"
elif [[ "$ARM_PRIV_ACTION" == same ]]; then
  # Owner and mode set on the open key, never by name (#965). A link or a
  # second name at the key's name since the check above is refused.
  state_own_file "$ARM_PRIV_LOCAL" 0 0 0600 "$ETC_APERIRE" \
    || fail_stop "could not set root : root 0600 on $ARM_PRIV_LOCAL safely"
  info "ok    fleet-arm.key  this host's own is already the set's key (public half $ARM_PRIV_PUB); left as it is"
fi

# ── the Advisor's state, table-driven ownership, never the set's own ─────
if [[ $HOST_HAS_ADVISOR -eq 1 && -d "$FROM/advisor-state" ]]; then
  say "restoring the Advisor's state"
  advisor_before=""
  [[ -d "$ADVISOR_STATE_LOCAL" ]] && \
    advisor_before="$(find "$ADVISOR_STATE_LOCAL" -type f -exec sha256sum {} + 2>/dev/null | sort | sha256sum)"
  # The directory and the two tokens the dashboard reads land on the shared
  # group every install puts them in; everything else the Advisor writes
  # for itself lands on its own account's own group. Neither the mode nor
  # the owner the set's OWNERSHIP recorded is read for this: only this
  # host's own resolved account and this table's fixed shape (#537, #544
  # finding 097). Every path walked below comes from the validated set's
  # own real directory tree, never from a recorded string.
  #
  # advisor/state belongs to the Advisor's own account, and on a shared-
  # account install (this issue, #755) that account is the dashboard's too:
  # every mkdir, chown, chmod and content write below goes through
  # state-file.py, by descriptor, so a name either account has swapped for a
  # symlink between root resolving the path and root acting on it is refused
  # rather than followed (#661, #703). ADR 0024, applied to the one code
  # path this fix makes reachable on a shape it used to abort on first.
  _adv_uid="$(id -u "$ADVISOR_ACCOUNT" 2>/dev/null || true)"
  _adv_gid="$(getent group "$ADVISOR_GROUP" 2>/dev/null | cut -d: -f3)"
  _adv_shared_gid="$(getent group "$ADVISOR_SHARED_GROUP" 2>/dev/null | cut -d: -f3)"
  [[ -n "$_adv_uid" ]] || fail_stop "could not resolve a numeric uid for '$ADVISOR_ACCOUNT'"
  [[ -n "$_adv_gid" ]] || fail_stop "could not resolve a numeric gid for '$ADVISOR_GROUP'"
  [[ -n "$_adv_shared_gid" ]] || fail_stop "could not resolve a numeric gid for '$ADVISOR_SHARED_GROUP'"

  state_mkdir_file "$ADVISOR_STATE_LOCAL" "$_adv_uid" "$_adv_shared_gid" 0750 "$ADVISOR_STATE_LOCAL" \
    || fail_stop "could not create $ADVISOR_STATE_LOCAL safely"
  while IFS= read -r -d '' rel; do
    src="$FROM/advisor-state/$rel"
    dst="$ADVISOR_STATE_LOCAL/$rel"
    if [[ -d "$src" ]]; then
      state_mkdir_file "$dst" "$_adv_uid" "$_adv_gid" 0750 "$ADVISOR_STATE_LOCAL" \
        || fail_stop "could not create $dst safely"
    else
      case "$(basename "$rel")" in
        approve.token|read.token) gid=$_adv_shared_gid ;;
        *) gid=$_adv_gid ;;
      esac
      # A flat file's own parent IS $ADVISOR_STATE_LOCAL, already created and
      # owned with the SHARED group above; re-mkdir'ing it here with the
      # Advisor's own private group on every flat file would overwrite that
      # with whichever file happens to run last (found running this suite:
      # the state directory itself came back on the wrong group when every
      # file in it was flat, which is the common shape in practice).
      dst_parent="$(dirname "$dst")"
      if [[ "$dst_parent" != "$ADVISOR_STATE_LOCAL" ]]; then
        state_mkdir_file "$dst_parent" "$_adv_uid" "$_adv_gid" 0750 "$ADVISOR_STATE_LOCAL" \
          || fail_stop "could not create $dst_parent safely"
      fi
      state_plant_file "$dst" "$_adv_uid" "$gid" 0640 "$ADVISOR_STATE_LOCAL" < "$src" \
        || fail_stop "could not write $dst safely"
    fi
  done < <(cd "$FROM/advisor-state" && find . -mindepth 1 -printf '%P\0')
  advisor_after="$(find "$ADVISOR_STATE_LOCAL" -type f -exec sha256sum {} + 2>/dev/null | sort | sha256sum)"
  [[ "$advisor_before" != "$advisor_after" ]] && CHANGED=$((CHANGED + 1))
  info "ok    advisor state, account '$ADVISOR_ACCOUNT'"
fi

# ── start it back up ────────────────────────────────────────────────
say "starting services"
systemctl start "$DASH_UNIT" || fail_stop "could not start $DASH_UNIT; the restored files are in place"
sleep "${APERIRE_RESTORE_SLEEP:-10}"
if [[ -n "$RELAY_UNIT" ]]; then
  systemctl start "$RELAY_UNIT" || fail_stop "could not start $RELAY_UNIT; the restored files are in place"
fi
if [[ $HOST_HAS_ADVISOR -eq 1 ]]; then
  systemctl start "$ADVISOR_UNIT" || fail_stop "could not start $ADVISOR_UNIT; the restored files are in place"
fi

# ── prove it, one named check at a time ────────────────────────────────
say "checks"
FAIL=0
check() {  # <label> <0=pass 1=fail 2=skip>
  case "$2" in
    0) printf '  PASS  %s\n' "$1" ;;
    2) printf '  SKIP  %s\n' "$1" ;;
    *) printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL + 1)) ;;
  esac
}

_active=0
systemctl is-active "$DASH_UNIT" >/dev/null 2>&1 || _active=1
[[ -n "$RELAY_UNIT" ]] && { systemctl is-active "$RELAY_UNIT" >/dev/null 2>&1 || _active=1; }
[[ $HOST_HAS_ADVISOR -eq 1 ]] && { systemctl is-active "$ADVISOR_UNIT" >/dev/null 2>&1 || _active=1; }
check "units active: $DASH_UNIT${RELAY_UNIT:+, $RELAY_UNIT}${ADVISOR_UNIT:+, $ADVISOR_UNIT}" "$_active"

_health=1
HZ="$(curl -fsS "http://127.0.0.1:${PORT}/healthz" 2>/dev/null || true)"
[[ "$HZ" == *'"ok":true'* ]] && _health=0
check "healthz answers ok" "$_health"

# ── the database the dashboard actually has open, not merely a file that
#    exists at the right path (#561) ────────────────────────────────────
# healthz answering ok proves the process is up, never which database it
# opened: on aperire4 the restored file sat untouched at the moved path
# while the dashboard opened an empty one at the default path, and every
# check above still read PASS. Three independent questions, all three have
# to agree:
#
#   1. Is DB_DEST itself somewhere this restore was ever allowed to write --
#      inside the install root, or the operator's own --db-path? DB_DEST is
#      already vetted before a byte moves (finding 1 above); re-asserted
#      here too, at zero cost, rather than trusted a second time.
#   2. Does the dashboard's own running process have that exact path open on
#      a file descriptor (read off /proc/<pid>/fd, so a misconfigured or
#      stale env file cannot fool it the way asking the env file again
#      would)?
#   3. Does its content confirm the restore -- not "the same number of rows
#      in total", which a poller writing every 2-5s fails on a perfectly
#      correct restore the moment ten seconds pass, but the tables that
#      actually mark a restore as done: see db_table_row_mismatch above.
_dbcheck=2
if [[ -f "$FROM/aperire.db" ]]; then
  _dbcheck=1
  DB_DEST_REAL="$(realpath -m "$DB_DEST" 2>/dev/null || printf '%s' "$DB_DEST")"

  _contained=1
  case "$DB_DEST_REAL" in
    "$INSTALL_ROOT_REAL"|"$INSTALL_ROOT_REAL"/*) _contained=0 ;;
    *)
      if [[ -n "$DB_PATH_OVERRIDE" ]]; then
        _override_real="$(realpath -m -- "$DB_PATH_OVERRIDE" 2>/dev/null || printf '%s' "$DB_PATH_OVERRIDE")"
        [[ "$DB_DEST_REAL" == "$_override_real" ]] && _contained=0
      fi
      ;;
  esac

  _fd_open=1
  DASH_PID="$(systemctl show -p MainPID --value "$DASH_UNIT" 2>/dev/null || true)"
  if [[ -n "$DASH_PID" && "$DASH_PID" != 0 && -d "$PROC_DIR/$DASH_PID/fd" ]]; then
    while IFS= read -r -d '' fdlink; do
      fdtarget="$(readlink -f "$fdlink" 2>/dev/null || true)"
      if [[ "$fdtarget" == "$DB_DEST_REAL" ]]; then
        _fd_open=0
        break
      fi
    done < <(find "$PROC_DIR/$DASH_PID/fd" -mindepth 1 -print0 2>/dev/null)
  fi

  _rows_ok=1
  if _row_mismatch_out="$(db_table_row_mismatch "$FROM/aperire.db" "$DB_DEST")"; then
    _rows_ok=0
  fi

  if [[ $_contained -eq 0 && $_fd_open -eq 0 && $_rows_ok -eq 0 ]]; then
    _dbcheck=0
  else
    [[ $_contained -ne 0 ]] && info "note: $DB_DEST_REAL is outside the install root ($INSTALL_ROOT_REAL) and does not match --db-path"
    [[ $_fd_open -ne 0 ]] && info "note: the dashboard's process (${DASH_PID:-unknown}) does not have $DB_DEST_REAL open"
    if [[ $_rows_ok -ne 0 ]]; then
      info "note: table row counts do not confirm the restore:"
      while IFS= read -r _row_line; do info "  $_row_line"; done <<<"$_row_mismatch_out"
    fi
  fi
fi
check "the running dashboard has the restored database open, with its content confirmed" "$_dbcheck"

# ── a linked node answers a read from this aggregator (#791) ────────────
# healthz, the database and the token files all said PASS on an aggregator
# whose nodes could neither link nor be read: the files that make that work
# were simply not in the set. So an aggregator's restore closes on the thing
# itself. For each node row in the restored fleet.yaml (this host's own row
# left out), its token is read AS THE DASHBOARD'S ACCOUNT, the one that
# reads it for real, and presented to that row's own loopback read origin,
# the port the link from that node binds here. One node answering 200 is
# the proof: its link credential was recognised, so fleet-links.json came
# back, and its token was accepted, so fleet-tokens did. None answering is a
# FAIL with each node's own reason, never a PASS, and an aggregator with no
# node to ask says so as a SKIP.
#
# Asked only of a set that shows this host serves nodes (it carried
# fleet-links.json or fleet-tokens/): a member's fleet.yaml can list peers
# whose tokens were never meant to be on it, and its restore must not FAIL
# over a read it never makes.
#
# Nodes redial on their own backoff, at most a minute apart, and a fresh
# install either had no hub at all (404) or held their dials (503): both are
# transient on the node. So this waits, up to APERIRE_RESTORE_NODE_WAIT
# seconds, for the first one.
if [[ $SET_HAS_FLEET_LINKS -eq 1 || $SET_HAS_FLEET_TOKENS -eq 1 ]]; then
  _node_label="a linked node answers a read from this aggregator"
  _rows_out="$(python3 -I - "$REPO_DIR/dashboard/config/fleet.yaml" "$PORT" <<'PY' 2>/dev/null
import re, sys
path, own = sys.argv[1], int(sys.argv[2])
try:
    import yaml
except ImportError:
    print("ERR\tpython3 has no yaml module to read fleet.yaml with")
    raise SystemExit(0)
try:
    with open(path) as f:
        doc = yaml.safe_load(f.read())
except FileNotFoundError:
    print("ERR\tthere is no fleet.yaml, so this aggregator reads no node")
    raise SystemExit(0)
except Exception:
    print("ERR\tfleet.yaml does not parse")
    raise SystemExit(0)
rows = doc.get("fleet") if isinstance(doc, dict) else None
if not isinstance(rows, list):
    print("ERR\tfleet.yaml has no fleet: list")
    raise SystemExit(0)
for r in rows:
    if not isinstance(r, dict):
        continue
    label = r.get("label")
    origin = r.get("read_origin")
    tok = r.get("token_path")
    if not isinstance(label, str) or not re.fullmatch(r"[a-z0-9-]{1,32}", label):
        print("BAD\t(a row with no usable label)")
        continue
    m = re.fullmatch(r"http://(127\.0\.0\.1|localhost):([0-9]{1,5})", origin) if isinstance(origin, str) else None
    if not m:
        print("BAD\t%s: its read_origin is not a bare loopback origin" % label)
        continue
    if int(m.group(2)) == own:
        continue
    if not isinstance(tok, str) or not tok.startswith("/") or any(c in tok for c in "\t\n\r"):
        print("BAD\t%s: its token_path is not an absolute path" % label)
        continue
    print("ROW\t%s\t%s\t%s" % (label, origin, tok))
print("END")
PY
)"
  # END is the reader's own last line: without it (python3 missing, or the
  # reader dying part way) the list below is not the whole registry, and is
  # never judged as one.
  _node_err=""; _node_rows=(); _node_bad=(); _node_end=0
  while IFS=$'\t' read -r _k _a _b _c; do
    case "$_k" in
      ERR) _node_err="$_a" ;;
      BAD) _node_bad+=("$_a") ;;
      ROW) _node_rows+=("$_a"$'\t'"$_b"$'\t'"$_c") ;;
      END) _node_end=1 ;;
    esac
  done <<<"$_rows_out"
  [[ -n "$_node_err" || $_node_end -eq 1 ]] || _node_err="fleet.yaml could not be read"

  declare -A _node_why=()
  _node_ok=""
  if [[ -z "$_node_err" && ${#_node_rows[@]} -gt 0 ]]; then
    _node_wait="${APERIRE_RESTORE_NODE_WAIT:-90}"
    [[ "$_node_wait" =~ ^[0-9]+$ ]] || _node_wait=90
    _node_deadline=$((SECONDS + _node_wait))
    _node_hdr="$WORKDIR/node-read.hdr"
    [[ "$_node_wait" -gt 0 ]] && info "waiting up to ${_node_wait}s for a linked node to answer a read"
    while :; do
      for _r in "${_node_rows[@]}"; do
        IFS=$'\t' read -r _nl _no _nt <<<"$_r"
        # As the dashboard's account, the one that reads it for real: root
        # proves nothing about whether the dashboard can, and never opens a
        # path the restored registry names on root's own authority.
        # Bounded: a token_path naming a FIFO must not hang the last check.
        _tok="$(timeout 5 runuser -u "$DASH_USER" -- head -c 4096 -- "$_nt" 2>/dev/null </dev/null | head -1 | tr -d ' \r\n\t')"
        if [[ -z "$_tok" || ! "$_tok" =~ ^[A-Za-z0-9._~+/=-]+$ ]]; then
          _node_why[$_nl]="its token at $_nt cannot be read by '$DASH_USER', or is empty"
          continue
        fi
        # The token goes to curl in a header file, root's own 0600 file in
        # this run's private directory, never on its argv.
        ( umask 077; printf 'Authorization: Bearer %s\n' "$_tok" > "$_node_hdr" )
        # -q first, so no ~/.curlrc adds anything; --noproxy, so a proxy
        # sudo picked up from /etc/environment never sees a bearer token
        # meant for a loopback port.
        _code="$(curl -q --noproxy '*' -sS -o /dev/null -w '%{http_code}' -m 5 -H @"$_node_hdr" \
                   "$_no/read/v1/recent?metric=peer_count&limit=1" 2>/dev/null || true)"
        rm -f "$_node_hdr"
        [[ "$_code" =~ ^[0-9]{3}$ ]] || _code=000
        case "$_code" in
          200) _node_ok="$_nl"; break ;;
          401|403) _node_why[$_nl]="answered $_code: it does not accept this aggregator's token for it" ;;
          000) _node_why[$_nl]="nothing answered at $_no: the node is offline, or has not linked to this aggregator yet" ;;
          *) _node_why[$_nl]="answered HTTP $_code at $_no" ;;
        esac
      done
      [[ -n "$_node_ok" ]] && break
      (( SECONDS >= _node_deadline )) && break
      sleep "${APERIRE_RESTORE_NODE_INTERVAL:-5}"
    done
  fi

  if [[ -n "$_node_ok" ]]; then
    check "$_node_label: $_node_ok" 0
    for _r in "${_node_rows[@]}"; do
      IFS=$'\t' read -r _nl _ _ <<<"$_r"
      [[ "$_nl" != "$_node_ok" && -n "${_node_why[$_nl]:-}" ]] && info "note: $_nl ${_node_why[$_nl]}"
    done
  elif [[ -n "$_node_err" ]]; then
    check "$_node_label: none could be checked, $_node_err" 1
  elif [[ ${#_node_rows[@]} -eq 0 && ${#_node_bad[@]} -eq 0 ]]; then
    check "$_node_label: fleet.yaml names no node but this host, so there is none to check" 2
  else
    check "$_node_label: none did" 1
    for _r in "${_node_rows[@]}"; do
      IFS=$'\t' read -r _nl _ _ <<<"$_r"
      info "note: $_nl ${_node_why[$_nl]:-was not asked}"
    done
    for _b in "${_node_bad[@]}"; do info "note: $_b"; done
    info "a node told 401 while this host had no row for it waits up to an hour"
    info "before it asks again; restart that node's dashboard to make it redial now."
  fi
  for _b in ${_node_ok:+"${_node_bad[@]}"}; do info "note: $_b"; done
fi

if [[ $HOST_HAS_ADVISOR -eq 1 ]]; then
  _read=0
  for tok in approve.token read.token; do
    [[ -f "$ADVISOR_STATE_LOCAL/$tok" ]] || continue
    runuser -u "$DASH_USER" -- test -r "$ADVISOR_STATE_LOCAL/$tok" >/dev/null 2>&1 || _read=1
  done
  check "the dashboard's account can read the Advisor's approve.token and read.token" "$_read"

  # Read through the helper, not `cat` (#703). This runs as root in a
  # directory the Advisor's own account owns, and the first line of whatever
  # a link there points at would go straight out as a bearer token on the
  # request below. The helper refuses anything that is not a single-linked
  # regular file. A read that cannot happen leaves TOKEN empty, which is what
  # the `|| true` here always allowed: the check below then reports that the
  # ledger could not be verified, rather than failing the whole restore.
  # The installed helper, a constant: this is root, and a variable set in a
  # root shell the login started must not choose the program root runs (#1148).
  _rs_tool=/usr/local/sbin/aperire-state-file
  [[ -f "$_rs_tool" ]] || _rs_tool="$STATE_FILE_TOOL"
  TOKEN="$(python3 -I "$_rs_tool" read "$ADVISOR_STATE_LOCAL/approve.token" 2>/dev/null || true)"
  ADVISOR_ADDR="$(bkset_advisor_addr "$ADVISOR_UNIT")"
  [[ -n "$ADVISOR_ADDR" ]] || ADVISOR_ADDR="127.0.0.1:7810"
  _ledger=1
  # The approve token in a header file, root's own 0600 file in this run's
  # private directory, never on curl's argv where any account can read it
  # in /proc (#798); and never through a proxy.
  _adv_hdr="$WORKDIR/advisor.hdr"
  ( umask 077; printf 'Authorization: Bearer %s\n' "$TOKEN" > "$_adv_hdr" )
  LEDGER="$(curl -q --noproxy '*' -fsS -H @"$_adv_hdr" "http://${ADVISOR_ADDR}/v1/ledger" 2>/dev/null || true)"
  [[ "$LEDGER" == *'"chain_intact":true'* ]] && _ledger=0
  check "the ledger chain verifies (chain_intact)" "$_ledger"

  STATUS="$(curl -q --noproxy '*' -fsS -H @"$_adv_hdr" "http://${ADVISOR_ADDR}/v1/status" 2>/dev/null || true)"
  rm -f "$_adv_hdr"
  info "model: $STATUS"

  echo
  echo "  Next, to bring the model back with no key pasted anywhere (#539), on the"
  echo "  aggregator, arm both sides and then press"
  echo "  \"Bring up to date\" for this host in Settings under your own passkey:"
  echo
  echo "      sudo aperire-fleet-arm --node <this host's label>"
  echo "      sudo aperire-fleet-arm --self-only"
  echo
  echo "  If aperire-fleet-arm is not found there, that aggregator's fleet broker"
  echo "  grant predates it: update that aggregator first, then run the same commands:"
  echo
  echo "      curl -fsSL https://get.aperire.one | bash -s -- --update --force"
  echo
  echo "  This restore does not run either command."
else
  info "no Advisor on this host: nothing to check or bring back for it"
fi

if [[ $SET_HAS_FLEET_LINKS -eq 1 || $SET_HAS_FLEET_TOKENS -eq 1 ]]; then
  echo
  echo "  This aggregator's own fleet files are back. Root's record of which nodes"
  echo "  a fleet model may be pushed to (/etc/aperire/fleet-nodes.conf) is not in"
  echo "  any set; rebuild it from the restored registry before the next push:"
  echo
  # #825: --refresh-nodes refuses on a host with no grant, and a restore onto
  # a fresh host is exactly that host. The full install comes first there,
  # because it is what puts the socket, the program and the conf in place,
  # and it does not write the node record, so the refresh still follows.
  _broker_prog="${APERIRE_FLEET_BROKER_PATH:-/usr/local/sbin/aperire-fleet-broker}"
  if [[ ! -f "$UNIT_DIR/aperire-fleet-broker.socket" || ! -e "$_broker_prog" \
        || ! -f "$ETC_APERIRE/fleet-broker.conf" ]]; then
    echo "  This host has no fleet broker grant yet, so install it first:"
    echo
    echo "      curl -fsSL https://get.aperire.one | bash -s -- --dir $REPO_DIR --run fleet-broker-grant"
    echo
    echo "  and then:"
    echo
  fi
  echo "      curl -fsSL https://get.aperire.one | bash -s -- --dir $REPO_DIR --run fleet-broker-grant --refresh-nodes"
fi

echo
echo "  This restore never read or wrote your node, its store or its own"
echo "  configuration."

if [[ $CHANGED -eq 0 ]]; then
  echo
  echo "== no files needed to change; this host already matches the set at $FROM_DISPLAY"
else
  echo
  echo "== $CHANGED file group(s) restored from $FROM_DISPLAY"
fi
echo "== safety copy of what changed: $SAFETY_DIR"

[[ $FAIL -gt 0 ]] && exit 1
exit 0
