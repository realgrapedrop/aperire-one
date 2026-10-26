#!/usr/bin/env bash
# aperire-backup.sh - one command in place of the seventy lines an operator
# used to paste out of the guide (#544). Runs LOCALLY, on the host being
# backed up, never over ssh.
#
#   curl -fsSL https://get.aperire.one | bash -s -- --backup [--to DIR] [--instance NAME] [--yes]
#
# That form runs the release's checked copy of this program as root, never the
# one in your checkout (#941).
#
#   --to DIR       write the set here instead of the default
#                  <your home>/aperire-backups/<UTC stamp>/
#   --instance     which dashboard/Advisor pairing on this host to back up
#                  (ADR 0009). Only needed on a host running more than one;
#                  a single-instance host needs nothing.
#   --yes          skip the "about to read /etc/aperire, proceed?" pause.
#                  There is nothing else to ask: this reads, it never writes
#                  anything outside the set it is building.
#   --dry-run      print what was discovered and what would be taken,
#                  touch nothing.
#
# What it discovers and says so: whether this host runs the Advisor, belongs
# to a fleet, and runs its node as a container or natively (read from
# /etc/aperire/node.conf, never from the node's own files).
#
# What it never reads: your node's data directory, or your node's own
# config (rippled.cfg, its compose file, its unit); see the node-config row
# in scripts/aperire-backup-set.sh for why, and the README this writes for
# what to do about it. It never reads /etc/aperire/creds, the sealed model
# credential, either. See the README this writes, and #514.
#
# The set it writes is 0700, owned by you (the account that ran sudo, not
# root), every file inside it closed to group and other. Before it prints
# success it verifies the set AS YOU, not as root: #536 found a set a
# fleet tool wrote that verified clean under sudo and refused for its own
# maker, because the check itself was run as the wrong account.
set -uo pipefail

# Where this program and its libraries are (SELF_DIR), and the install it backs
# up (REPO_DIR): a directory and its parent from a checkout, two when it is a
# copy root staged out of the release and APERIRE_INSTALL_TREE names the
# install (#941). Code is loaded and run from SELF_DIR only.
SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_DIR="$(cd "${APERIRE_INSTALL_TREE:-$SELF_DIR/..}" 2>/dev/null && pwd -P)" \
  || { echo "error: the install at ${APERIRE_INSTALL_TREE:-$SELF_DIR/..} is not a directory this account can enter" >&2; exit 1; }
# shellcheck source=scripts/aperire-backup-set.sh
. "$SELF_DIR/aperire-backup-set.sh"
# Which account the dashboard runs as (ADR 0024 lane 4), read from its unit.
# shellcheck source=scripts/dashboard-account-lib.sh
. "$SELF_DIR/dashboard-account-lib.sh"
# shellcheck source=scripts/term-style.sh
[[ -r "$SELF_DIR/term-style.sh" ]] && . "$SELF_DIR/term-style.sh"

say()  { printf '\n%s== %s%s\n' "${S_BOLD:-}" "$*" "${S_OFF:-}"; }
info() { printf '  %s\n' "$*"; }
warn() { printf '  %s%s%s\n' "${S_AMBER:-}" "$*" "${S_OFF:-}"; }
die()  { printf '\n%serror:%s %s\n' "${E_RED:-}" "${E_OFF:-}" "$*" >&2; exit 1; }

NEEDS_ROOT=1
if [[ $NEEDS_ROOT -eq 1 && $EUID -ne 0 ]]; then
  die "run with sudo, this reads root-only files under /etc/aperire and the Advisor's own state"
fi

# A private scratch directory for this run's own verify transcript, never a
# predictable /tmp/*.$$ name a co-resident account could race to create
# first.
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/aperire-backup.XXXXXXXX")"
chmod 700 "$WORKDIR"
trap 'rm -rf "$WORKDIR"' EXIT

# ── args ──────────────────────────────────────────────────────────────
DEST_ARG=""; INSTANCE=""; ASSUME_YES=0; DRY=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --to)        DEST_ARG=${2:?--to needs a path}; shift 2 ;;
    --instance)  INSTANCE=${2:?--instance needs a name}; shift 2 ;;
    --yes|-y)    ASSUME_YES=1; shift ;;
    --dry-run)   DRY=1; shift ;;
    -h|--help)
      awk '/^[^#]/{exit} NR>1{sub(/^# ?/,""); print}' "$0"
      exit 0 ;;
    *) die "unknown argument: $1 (see --help)" ;;
  esac
done

# ── the operator this set belongs to ─────────────────────────────────
OP_USER="${SUDO_USER:-}"
[[ -n "$OP_USER" ]] || OP_USER="$(id -un)"
OP_HOME="$(getent passwd "$OP_USER" 2>/dev/null | cut -d: -f6)"
[[ -n "$OP_HOME" ]] || OP_HOME="/root"
OP_GROUP="$(id -gn "$OP_USER" 2>/dev/null || echo "$OP_USER")"
# The uid is needed now, not only when the set is placed: the checks of --to
# below name the one account other than root that the directories above the set
# may belong to, and it is this one (#1153). Anyone else who owns one of them
# can rename what is under it before a restore.
OP_UID="$(id -u "$OP_USER" 2>/dev/null || true)"
[[ "$OP_UID" =~ ^[0-9]+$ ]] \
  || die "could not resolve $OP_USER to a uid, so the set could not be handed to the operator. Nothing was written."

# ── which instance ────────────────────────────────────────────────────
if [[ -z "$INSTANCE" ]]; then
  # A plain command substitution, not `mapfile < <(...)`: the latter's `$?`
  # reads mapfile's own exit status, not the piped command's, which is what
  # let a multi-instance host silently fall through as if it were a
  # single-instance one.
  _inst_out="$(bkset_this_instance "$REPO_DIR")"; _inst_rc=$?
  _found=()
  [[ -n "$_inst_out" ]] && mapfile -t _found <<<"$_inst_out"
  if [[ $_inst_rc -eq 2 ]]; then
    die "this host runs more than one Aperire instance; name the one to back up: --instance ${_found[0]:-<name>}
       (found: ${_found[*]:-})"
  fi
  [[ $_inst_rc -eq 0 ]] && INSTANCE="${_found[0]:-}"
fi

say "Aperire One backup"
info "install: $REPO_DIR${INSTANCE:+  (instance: $INSTANCE)}"

# ── discover this host's shape ───────────────────────────────────────
DASH_UNIT="$(bkset_dash_unit "$INSTANCE" || true)"
ENV_FILE="$(bkset_env_file "$INSTANCE" || true)"
PORT=""
[[ -n "$ENV_FILE" ]] && PORT="$(bkset_env_key "$ENV_FILE" PORT)"
[[ -n "$PORT" ]] || PORT=7800

HAS_RELAY_CONF=0
[[ -f "$(bkset_relay_conf_path "$INSTANCE")" ]] && HAS_RELAY_CONF=1

ADVISOR_UNIT="$(bkset_advisor_unit "$INSTANCE" || true)"
HAS_ADVISOR=0
[[ -n "$ADVISOR_UNIT" ]] && HAS_ADVISOR=1

HAS_FLEET_LINK=0
[[ -f "$REPO_DIR/dashboard/config/fleet-link.json" ]] && HAS_FLEET_LINK=1
HAS_FLEET_YAML=0
[[ -f "$REPO_DIR/dashboard/config/fleet.yaml" ]] && HAS_FLEET_YAML=1
# An aggregator's own half of the fleet (#791): the hash of every node's link
# credential, and the tokens it presents to them. Either one alone marks this
# host as one that serves nodes, not only one that reads them.
HAS_FLEET_LINKS=0
[[ -f "$REPO_DIR/dashboard/config/fleet-links.json" ]] && HAS_FLEET_LINKS=1
FLEET_TOKEN_DIR="$ETC_APERIRE/fleet-tokens"
HAS_FLEET_TOKENS=0
[[ -e "$FLEET_TOKEN_DIR" || -L "$FLEET_TOKEN_DIR" ]] && HAS_FLEET_TOKENS=1
FLEET_ARM_PRIV="$ETC_APERIRE/fleet-arm.key"
HAS_FLEET_ARM_PRIV=0
[[ -e "$FLEET_ARM_PRIV" || -L "$FLEET_ARM_PRIV" ]] && HAS_FLEET_ARM_PRIV=1

# node-wrapper.conf first, then node.conf, the same fallback order every
# other reader of this record uses (close-node-config-exposure.sh,
# verify-after-restart.sh, install-aperire-service.sh, detect-rippled-paths.sh):
# the wrapper's file exists only where the Advisor was installed, and a
# node-only host (the fleet's stock shape) only ever has node.conf, which
# this used to skip, printing "not detected" on a host whose node was in
# fact recorded (#564). Both KIND and SERVICE come from whichever one file
# actually answers, never mixed across the two.
NODE_KIND=""; NODE_SERVICE=""
for _ncf in "$ETC_APERIRE/node-wrapper.conf" "$ETC_APERIRE/node.conf"; do
  [[ -r "$_ncf" ]] || continue
  NODE_KIND="$(awk -F= '$1=="KIND"{sub(/^[^=]*=/,""); print; exit}' "$_ncf")"
  NODE_SERVICE="$(awk -F= '$1=="SERVICE"{sub(/^[^=]*=/,""); print; exit}' "$_ncf")"
  [[ -n "$NODE_KIND" ]] && break
done
# SERVICE=none is the wrapper's own way of saying this host runs no node; it
# is not a name worth printing (aperire-compact-check.sh treats it the same
# way).
NODE_DESC="not detected"
if [[ -n "$NODE_KIND" ]]; then
  NODE_DESC="$NODE_KIND"
  [[ -n "$NODE_SERVICE" && "$NODE_SERVICE" != none ]] && NODE_DESC="$NODE_KIND ($NODE_SERVICE)"
fi

info "dashboard: $([[ -n "$DASH_UNIT" ]] && echo "$DASH_UNIT (port $PORT)" || echo "not found on this host")"
info "relay: $([[ $HAS_RELAY_CONF -eq 1 ]] && echo "co-located" || echo "none on this host")"
info "advisor: $([[ $HAS_ADVISOR -eq 1 ]] && echo "$ADVISOR_UNIT" || echo "not installed")"
info "fleet: $([[ $HAS_FLEET_LINK -eq 1 ]] && echo "member, linked" || { [[ $HAS_FLEET_YAML -eq 1 || $HAS_FLEET_LINKS -eq 1 ]] && echo "aggregator"; } || echo "not joined")"
info "node: ${NODE_DESC} (its config is yours to place, see the README this writes)"

if [[ -z "$DASH_UNIT" ]]; then
  die "no aperire-server or aperire-read unit on this host; there is nothing installed to back up"
fi

# ── the plan ──────────────────────────────────────────────────────────
declare -A APPLIES=()
APPLIES[database]=1
APPLIES[dashboard-config]=1
APPLIES[fleet-config]=$(( HAS_FLEET_LINK || HAS_FLEET_YAML || HAS_FLEET_LINKS ? 1 : 0 ))
APPLIES[relay-env]=1
APPLIES[relay-conf]=$HAS_RELAY_CONF
APPLIES[advisor-state]=$HAS_ADVISOR
APPLIES[fleet-arm-key]=0
[[ -f "$ETC_APERIRE/fleet-arm.pub" ]] && APPLIES[fleet-arm-key]=1
APPLIES[fleet-arm-held-key]=0
[[ -f "$ETC_APERIRE/fleet-arm.paired.pub" ]] && APPLIES[fleet-arm-held-key]=1
APPLIES[fleet-tokens]=$HAS_FLEET_TOKENS
APPLIES[fleet-arm-private-key]=$HAS_FLEET_ARM_PRIV

say "plan"
for k in $(bkset_keys); do
  [[ "$k" == node-config ]] && { info "skip  $k  (yours to place; see the README)"; continue; }
  row="$(bkset_row "$k")"
  req="$(bkset_field "$row" 4)"
  if [[ "${APPLIES[$k]:-0}" -eq 1 ]]; then
    info "take  $k  ($(bkset_field "$row" 3))"
  elif [[ "$req" == required ]]; then
    warn "MISSING  $k  is required and was not found: $(bkset_field "$row" 3)"
  else
    info "skip  $k  not present on this host"
  fi
done

if [[ $DRY -eq 1 ]]; then
  echo
  echo "(dry run, nothing written)"
  exit 0
fi

if [[ $ASSUME_YES -ne 1 ]]; then
  if ! IFS= read -r -p $'\nProceed? [y/N] ' reply; then
    echo; die "no terminal to confirm on; pass --yes"
  fi
  case "$reply" in y|Y|yes|YES) ;; *) echo "aborted."; exit 0 ;; esac
fi

# ── the destination, refused rather than reused (#544 finding 100) ───────
if [[ -z "$DEST_ARG" ]]; then
  TS="$(date -u +%Y%m%d-%H%M%S)"
  DEST_ARG="$OP_HOME/aperire-backups/$TS"
fi
# A --to naming an existing tree used to be handed straight to `install -d`
# (a no-op on a directory already there) and then, at the very end, this
# script's own `chown -R`/`chmod -R` ran over WHATEVER was already inside
# it, following any symlink among the entries it walked. Only a directory
# this command creates itself, empty, is safe to lock down that way.
if [[ -L "$DEST_ARG" ]]; then
  die "--to $DEST_ARG is a symlink; name a real path, not a link to one"
fi
if [[ -e "$DEST_ARG" ]]; then
  [[ -d "$DEST_ARG" ]] || die "--to $DEST_ARG exists and is not a directory"
  [[ -z "$(ls -A "$DEST_ARG" 2>/dev/null)" ]] || \
    die "--to $DEST_ARG already exists and is not empty; a backup set owns
         the whole directory it lands in and refuses to inherit one. Name
         an empty or not-yet-existing directory."
fi
# The parent --to will have, resolved without needing it to exist yet: the
# set may be asked for under directories this run creates (mkdir -p below
# makes the whole chain), and `cd && pwd -P` cannot resolve a path that is
# not there. _dexist is the nearest part of it that is. Everything under it is
# made by this run, so it is the first directory the ancestor rule has to judge.
_dparent="$(realpath -m -- "$(dirname -- "$DEST_ARG")")" \
  || die "could not resolve the parent of --to ($DEST_ARG)"
_dexist="$_dparent"
while [[ ! -d "$_dexist" ]]; do _dexist="$(dirname -- "$_dexist")"; done
if [[ "$_dexist" == "$_dparent" ]]; then
  _pperm="$(stat -c '%a' "$_dparent" 2>/dev/null || echo 000)"
  if (( (8#$_pperm & 0002) != 0 && (8#$_pperm & 01000) == 0 )); then
    die "the parent of --to ($_dparent) is writable by anyone and has no
         sticky bit; another account there could swap what --to resolves
         to before this finishes writing. Use a directory whose parent is
         not world-writable, or add the sticky bit to it."
  fi
fi
# The parent and the directories above it are held to the ancestor rule when
# the set is placed for the operator at the end (the same walk, rooted at the
# parent, with the parent judged too: --judge-root, #1153, because the parent is
# the directory root creates the set in on the operator's behalf, not one of
# the Advisor's). Asked now, while nothing has been written, so a path that
# rule refuses stops here and not after the whole set exists. When the parent
# is not there yet, the nearest directory that is gets judged along with
# everything above it. Each refusal line ends with the command that fixes it.
_anc="$(python3 -I "$SELF_DIR/state-file.py" ancestors "$_dexist" --root "$_dparent" --judge-root --owner "$OP_UID" 2>&1)" \
  || die "could not check the directories above --to ($_dexist): $_anc"
if [[ -n "$_anc" ]]; then
  while IFS=$'\t' read -r _k _w _why; do echo "  refused: ${_why:-$_w}" >&2; done <<<"$_anc"
  die "the parent of --to, or a directory above it, can be changed by an account
         other than root and the operator (named above, each with the command
         that fixes it), so root will not hand the set over through it. Run
         those, then this again, or name a path under a directory only they can
         write."
fi
# The set is not built where it will end up (#1154). A directory the operator
# owns is one the operator can rename, and a name there can be made to point
# anywhere between one of root's calls and the next, so every write root made
# into the set by name (the copies, the chmod on the database, the manifest) was
# one it could redirect. The set is built in STAGE instead, a directory under
# this run's own scratch space that only root can enter, and placed at DEST in
# one step at the end, by descriptor, owned by the operator from the moment each
# file holds its content. Only the parent of --to is made here; --to itself is
# made by that last step.
mkdir -p -- "$_dparent"
DEST="$(realpath -m -- "$DEST_ARG")"
STAGE="$WORKDIR/set"
install -d -m 0700 "$STAGE"

# ── reading out of a directory another account owns (#796) ─────────────
# dashboard/config, the database's directory and advisor/state belong to
# the accounts the services run as, and owning a directory means owning
# every name in it: that account can put a symlink (or a hard link, or a
# FIFO) at any of them, and a `cp -p` run as root followed it, so a link at
# fleet-links.json or authn.yaml carried /etc/aperire/fleet-arm.key or the
# sealed model credential into the set, and a restore handed it back to
# the dashboard account. A check before the copy would not close that: the
# account wins the race on its own directory. So every such file is read
# AS THAT ACCOUNT, which can follow a link only to what it could read
# already, and is opened with O_NOFOLLOW and checked on the descriptor
# (a regular file with one link) before a byte is copied from it.
#
# The account is the dashboard unit's effective User=, drop-ins included
# (dashboard-account-lib.sh). It used to fall back to the owner of
# dashboard/config, then to root. Neither is that account once the dashboard
# has its own (ADR 0024: dashboard/config stays the operator's), and root is
# the one reader this exists to avoid, so a unit this cannot read is refused.
da_resolve_unit "$UNIT_DIR/$DASH_UNIT.service" || die "$DA_WHY"
DASH_READER="$DA_ACCOUNT"
READ_NOFOLLOW_PY='import os, stat, sys
p = sys.argv[1]
try:
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOCTTY)
except OSError as e:
    sys.stderr.write("%s: %s\n" % (p, e.strerror))
    sys.exit(3)
st = os.fstat(fd)
if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
    sys.stderr.write("%s: not a plain file with one link\n" % p)
    sys.exit(3)
out = sys.stdout.buffer
while True:
    b = os.read(fd, 65536)
    if not b:
        break
    out.write(b)
out.flush()'
# copy_as <account> <src> <dst>: 0 copied, non-zero refused (dst removed,
# the reason in $WORKDIR/read.err).
copy_as() {
  local rc
  ( umask 077
    timeout 60 runuser -u "$1" -- python3 -I -c "$READ_NOFOLLOW_PY" "$2" > "$3" 2>"$WORKDIR/read.err" )
  rc=$?
  (( rc == 0 )) || rm -f -- "$3"
  return "$rc"
}
read_err() { tr '\n' ' ' < "$WORKDIR/read.err" 2>/dev/null; }

OWNERSHIP_LINES=()
TAKEN=(); SKIPPED=(); FAILED=(); REQUIRED_FAIL=0

record_owner() {  # <path>
  local line
  line="$(bkset_stat_line "$1")" || return 1
  OWNERSHIP_LINES+=("$line")
}

# ── database, through VACUUM INTO ────────────────────────────────────
say "copying into $DEST"
DB_SRC="$(bkset_db_path "$REPO_DIR" "$INSTANCE")"
# The snapshot is taken by the dashboard account itself, into a directory
# only it can write inside this run's own scratch space, then read out the
# same way as every other file it owns (#796). Root never opens the live
# database by a path that account controls.
DB_STAGE="$WORKDIR/as-dashboard"
chmod 711 "$WORKDIR"
install -d -o "$DASH_READER" -m 0700 "$DB_STAGE"
if [[ -L "$DB_SRC" ]]; then
  warn "fail  database  $DB_SRC is a symbolic link; refusing to follow it"
  FAILED+=("database"); REQUIRED_FAIL=$((REQUIRED_FAIL + 1))
elif [[ -f "$DB_SRC" ]]; then
  if command -v sqlite3 >/dev/null 2>&1; then
    if timeout 600 runuser -u "$DASH_READER" -- env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin sqlite3 -init /dev/null "$DB_SRC" "VACUUM INTO '$DB_STAGE/aperire.db'" 2>/dev/null \
       && copy_as "$DASH_READER" "$DB_STAGE/aperire.db" "$STAGE/aperire.db"; then
      chmod 600 "$STAGE/aperire.db"
      # The snapshot in the dashboard account's scratch is not needed any
      # more; a large database would otherwise take that space twice over.
      rm -f -- "$DB_STAGE/aperire.db"
      CHECK="$(sqlite3 "$STAGE/aperire.db" "PRAGMA integrity_check" 2>&1 | tr '\n' ' ')"
      info "ok    database  -> $DEST/aperire.db  (integrity_check: $CHECK)"
      TAKEN+=("database")
      record_owner "$DB_SRC"
    else
      warn "fail  database  VACUUM INTO failed"
      FAILED+=("database"); REQUIRED_FAIL=$((REQUIRED_FAIL + 1))
    fi
  else
    die "sqlite3 is not installed; install it (apt install sqlite3) and try again"
  fi
else
  warn "fail  database  not found at $DB_SRC"
  FAILED+=("database"); REQUIRED_FAIL=$((REQUIRED_FAIL + 1))
fi

# ── dashboard config, the four files ─────────────────────────────────
mkdir -p "$STAGE/config"
_where="$(bkset_field "$(bkset_row dashboard-config)" 3)"
# _cfg is assigned by the eval above, which static analysis cannot see
# through; it is this table's own brace pattern, not operator input, so the
# eval is over a fixed, trusted string.
eval "_cfg=($REPO_DIR/$_where)"
n=0
_cfg_bad=""
# shellcheck disable=SC2154
for f in "${_cfg[@]}"; do
  [[ -e "$f" || -L "$f" ]] || continue
  if ! copy_as "$DASH_READER" "$f" "$STAGE/config/$(basename "$f")"; then
    _cfg_bad="$(read_err)"
    break
  fi
  record_owner "$f"
  n=$((n + 1))
done
if [[ -n "$_cfg_bad" ]]; then
  warn "fail  dashboard-config  refusing to carry it: $_cfg_bad
            Look at that name by hand before backing this host up again."
  FAILED+=("dashboard-config"); REQUIRED_FAIL=$((REQUIRED_FAIL + 1))
elif [[ $n -gt 0 ]]; then
  info "ok    dashboard-config  -> $DEST/config/ ($n files)"
  TAKEN+=("dashboard-config")
else
  warn "fail  dashboard-config  none of the four files were found"
  FAILED+=("dashboard-config"); REQUIRED_FAIL=$((REQUIRED_FAIL + 1))
fi

# ── fleet config, if joined ───────────────────────────────────────────
if [[ "${APPLIES[fleet-config]}" -eq 1 ]]; then
  _where="$(bkset_field "$(bkset_row fleet-config)" 3)"
  eval "_fc=($REPO_DIR/$_where)"
  n=0
  _fc_bad=""
  # shellcheck disable=SC2154  # see the note on _cfg above
  for f in "${_fc[@]}"; do
    [[ -e "$f" || -L "$f" ]] || continue
    if ! copy_as "$DASH_READER" "$f" "$STAGE/config/$(basename "$f")"; then
      _fc_bad="$(read_err)"
      break
    fi
    record_owner "$f"
    n=$((n + 1))
  done
  if [[ -n "$_fc_bad" ]]; then
    warn "fail  fleet-config  refusing to carry it: $_fc_bad
            Look at that name by hand before backing this host up again."
    for f in "${_fc[@]}"; do rm -f -- "$STAGE/config/$(basename "$f")"; done
    FAILED+=("fleet-config")
  else
    info "ok    fleet-config  -> $DEST/config/ ($n files)"
    TAKEN+=("fleet-config")
  fi
else
  info "skip  fleet-config  this host is not fleet-joined"
  SKIPPED+=("fleet-config")
fi

# ── the relay token pair, one row each, this instance's own files ────────
# The canonical, no-fallback path: aperire.env on a single-instance host,
# aperire-node2.env on an instance named node2, never the other instance's
# file (#544 finding 098: a bare $ETC_APERIRE/aperire.env here is how
# --instance node2 used to back up instance one's token).
ENV_PATH="$(bkset_env_path "$INSTANCE")"
if [[ -f "$ENV_PATH" ]]; then
  cp -p "$ENV_PATH" "$STAGE/aperire.env"
  record_owner "$ENV_PATH"
  info "ok    relay-env  -> $DEST/aperire.env (from $ENV_PATH)"
  TAKEN+=("relay-env")
else
  warn "fail  relay-env  $ENV_PATH not found"
  FAILED+=("relay-env"); REQUIRED_FAIL=$((REQUIRED_FAIL + 1))
fi
RELAY_CONF_PATH="$(bkset_relay_conf_path "$INSTANCE")"
if [[ "${APPLIES[relay-conf]}" -eq 1 ]]; then
  cp -p "$RELAY_CONF_PATH" "$STAGE/relay.conf"
  record_owner "$RELAY_CONF_PATH"
  info "ok    relay-conf  -> $DEST/relay.conf (from $RELAY_CONF_PATH)"
  TAKEN+=("relay-conf")
else
  info "skip  relay-conf  this host does not run a relay"
  SKIPPED+=("relay-conf")
fi

# ── the Advisor's whole state directory, if this host runs one ───────
if [[ "${APPLIES[advisor-state]}" -eq 1 ]]; then
  ADVISOR_STATE="$(bkset_advisor_state "$ADVISOR_UNIT")"
  [[ -n "$ADVISOR_STATE" ]] || ADVISOR_STATE="$REPO_DIR/advisor/state"
  ADVISOR_ACCOUNT="$(bkset_unit_user "$ADVISOR_UNIT")"
  if [[ -d "$ADVISOR_STATE" ]]; then
    # File by file, never `cp -a` of a tree a service account writes into:
    # a symlink planted there would ride along as a symlink, becoming an
    # unmanifested member a restore has no business trusting (#544 finding
    # 097c). Anything that is not a plain file or a directory is refused
    # rather than carried; that account has no business owning one either.
    mkdir -p "$STAGE/advisor-state"
    _bad=""
    while IFS= read -r -d '' rel; do
      src="$ADVISOR_STATE/$rel"
      if [[ -d "$src" && ! -L "$src" ]]; then
        mkdir -p "$STAGE/advisor-state/$rel"
      elif [[ -f "$src" && ! -L "$src" ]]; then
        mkdir -p "$STAGE/advisor-state/$(dirname "$rel")"
        # As the Advisor's own account, by descriptor (#796): the check
        # above is only a first answer in a directory that account owns.
        if ! copy_as "${ADVISOR_ACCOUNT:-root}" "$src" "$STAGE/advisor-state/$rel"; then
          _bad="$rel ($(read_err))"
          break
        fi
      else
        _bad="$rel"
        break
      fi
      record_owner "$src"
    done < <(cd "$ADVISOR_STATE" && find . -mindepth 1 -printf '%P\0')
    if [[ -n "$_bad" ]]; then
      warn "fail  advisor-state  $ADVISOR_STATE/$_bad is not a plain file or a
            directory; refusing to carry it. Look at it by hand before
            backing this host up again."
      rm -rf "$STAGE/advisor-state"
      FAILED+=("advisor-state")
    else
      record_owner "$ADVISOR_STATE"
      info "ok    advisor-state  -> $DEST/advisor-state  (account: $ADVISOR_ACCOUNT)"
      TAKEN+=("advisor-state")
    fi
  else
    warn "fail  advisor-state  $ADVISOR_STATE not found"
    FAILED+=("advisor-state")
  fi
else
  info "skip  advisor-state  no Advisor installed on this host"
  SKIPPED+=("advisor-state")
fi

# ── the trusted fleet arm key ──────────────────────────────────────────
if [[ "${APPLIES[fleet-arm-key]}" -eq 1 ]]; then
  cp -p "$ETC_APERIRE/fleet-arm.pub" "$STAGE/fleet-arm.pub"
  record_owner "$ETC_APERIRE/fleet-arm.pub"
  info "ok    fleet-arm-key  -> $DEST/fleet-arm.pub"
  TAKEN+=("fleet-arm-key")
else
  info "skip  fleet-arm-key  not fleet-joined, or no arm key trusted yet"
  SKIPPED+=("fleet-arm-key")
fi

# ── the held fleet arm key, kept for an Advisor not yet installed (#724) ─
if [[ "${APPLIES[fleet-arm-held-key]}" -eq 1 ]]; then
  cp -p "$ETC_APERIRE/fleet-arm.paired.pub" "$STAGE/fleet-arm.paired.pub"
  record_owner "$ETC_APERIRE/fleet-arm.paired.pub"
  info "ok    fleet-arm-held-key  -> $DEST/fleet-arm.paired.pub"
  TAKEN+=("fleet-arm-held-key")
else
  info "skip  fleet-arm-held-key  not fleet-joined, or no key held for a later Advisor"
  SKIPPED+=("fleet-arm-held-key")
fi

# ── the tokens this aggregator presents to its nodes (#791) ─────────────
# Flat, plain files only, the shape aperire-fleet-broker.sh's own write_token
# ever leaves there. The directory is root's and so is every entry, so
# nothing unprivileged could have planted a link; a link or a subdirectory
# found here anyway is refused rather than carried, the same rule the
# Advisor's state follows above, because a restore has no business trusting
# a member nobody here wrote.
if [[ "${APPLIES[fleet-tokens]}" -eq 1 ]]; then
  _bad=""
  if [[ -L "$FLEET_TOKEN_DIR" || ! -d "$FLEET_TOKEN_DIR" ]]; then
    _bad="$FLEET_TOKEN_DIR itself"
  else
    mkdir -p "$STAGE/fleet-tokens"
    n=0
    while IFS= read -r -d '' rel; do
      src="$FLEET_TOKEN_DIR/$rel"
      if [[ -f "$src" && ! -L "$src" && "$(stat -c '%h' "$src" 2>/dev/null)" == 1 ]]; then
        cp -p "$src" "$STAGE/fleet-tokens/$rel"
        record_owner "$src"
        n=$((n + 1))
      else
        _bad="$src"
        break
      fi
    done < <(cd "$FLEET_TOKEN_DIR" && find . -mindepth 1 -printf '%P\0')
  fi
  if [[ -n "$_bad" ]]; then
    warn "fail  fleet-tokens  $_bad is not a plain file (or a real
            directory); refusing to carry it. Look at it by hand before
            backing this host up again."
    rm -rf "$STAGE/fleet-tokens"
    FAILED+=("fleet-tokens")
  else
    record_owner "$FLEET_TOKEN_DIR"
    info "ok    fleet-tokens  -> $DEST/fleet-tokens ($n files)"
    TAKEN+=("fleet-tokens")
  fi
else
  info "skip  fleet-tokens  not an aggregator, or no node paired yet"
  SKIPPED+=("fleet-tokens")
fi

# ── the aggregator's private fleet arm key (#744) ──────────────────────
# A private key, like the trust signing key an aggregator's fleet-trust.yaml
# already carries in fleet-config. aperire-fleet-broker.sh reads it only
# when it is a plain, single-linked file root owns with no group or other
# bits, and so does this: anything else is not the key the broker would use,
# and copying it would hand a restore something no node trusts.
if [[ "${APPLIES[fleet-arm-private-key]}" -eq 1 ]]; then
  if [[ -f "$FLEET_ARM_PRIV" && ! -L "$FLEET_ARM_PRIV" \
        && "$(stat -c '%h' "$FLEET_ARM_PRIV" 2>/dev/null)" == 1 ]]; then
    cp -p "$FLEET_ARM_PRIV" "$STAGE/fleet-arm.key"
    chmod 600 "$STAGE/fleet-arm.key"
    record_owner "$FLEET_ARM_PRIV"
    info "ok    fleet-arm-private-key  -> $DEST/fleet-arm.key  (owner-only; keep this set where only you can reach it)"
    TAKEN+=("fleet-arm-private-key")
  else
    warn "fail  fleet-arm-private-key  $FLEET_ARM_PRIV is not a plain,
            single-linked file; refusing to carry it. Look at it by hand
            before backing this host up again."
    FAILED+=("fleet-arm-private-key")
  fi
else
  info "skip  fleet-arm-private-key  not an aggregator, or no node paired yet"
  SKIPPED+=("fleet-arm-private-key")
fi

# ── the two exclusions, in the operator's own words ───────────────────
CRED_NOTE=""
if [[ -d "$ETC_APERIRE/creds" ]] && compgen -G "$ETC_APERIRE/creds/*" >/dev/null; then
  CRED_NOTE="present, and deliberately NOT copied"
fi

# The aggregator's fleet model store (#711), in whichever form this host
# keeps it. Never read and never copied: named, so a set that left it out on
# purpose does not read like a set that lost it.
FLEET_STORE_NOTE=""
for _fs in "$ETC_APERIRE/fleet-model.cred" "$ETC_APERIRE/fleet-model.cred.plain"; do
  [[ -e "$_fs" ]] && FLEET_STORE_NOTE="$_fs, present, and deliberately NOT copied"
done
unset _fs

# ── OWNERSHIP, README, MANIFEST ────────────────────────────────────────
if [[ ${#OWNERSHIP_LINES[@]} -gt 0 ]]; then
  printf '%s\n' "${OWNERSHIP_LINES[@]}" | LC_ALL=C sort -u > "$STAGE/OWNERSHIP"
else
  : > "$STAGE/OWNERSHIP"
fi

{
  echo "aperire-backup.sh, $(hostname -s 2>/dev/null || hostname), $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo
  echo "install: $REPO_DIR${INSTANCE:+  (instance: $INSTANCE)}"
  echo "dashboard: $DASH_UNIT, port $PORT"
  echo "relay: $([[ "${APPLIES[relay-conf]}" -eq 1 ]] && echo co-located || echo none)"
  echo "advisor: $([[ "${APPLIES[advisor-state]}" -eq 1 ]] && echo "$ADVISOR_UNIT" || echo none)"
  echo "fleet: $([[ $HAS_FLEET_LINK -eq 1 ]] && echo "member, linked" || { [[ $HAS_FLEET_YAML -eq 1 || $HAS_FLEET_LINKS -eq 1 ]] && echo aggregator; } || echo "not joined")"
  echo "node: ${NODE_DESC}"
  echo
  echo "ownership: OWNERSHIP, $(wc -l < "$STAGE/OWNERSHIP" | tr -d ' ') paths"
  echo "  mode uid gid owner group path, one line per path as it was on this host."
  echo "  aperire-restore.sh reads this to put every file back the way it was,"
  echo "  translating the Advisor's own account rather than copying its name"
  echo "  (see the restore guide, and #515)."
  echo
  if [[ "${APPLIES[fleet-arm-private-key]}" -eq 1 || "${APPLIES[fleet-tokens]}" -eq 1 ]]; then
    echo "This set holds this aggregator's fleet secrets:"
    echo
    [[ "${APPLIES[fleet-tokens]}" -eq 1 ]] && \
      echo "  - fleet-tokens/, the tokens it reads its nodes with."
    if [[ "${APPLIES[fleet-arm-private-key]}" -eq 1 ]]; then
      echo "  - fleet-arm.key, its private fleet arm key. Every node paired to this"
      echo "    aggregator trusts its public half, and whoever holds this file can"
      echo "    open an arm window on every one of them. Keep this set where only"
      echo "    you can reach it, the same as the tokens beside it."
    fi
    echo
  fi
  echo "NOT in this set, on purpose:"
  echo
  echo "  - your node's own config. Only you know where it lives; place your"
  echo "    rippled.cfg and its compose file or unit alongside this set by hand."
  echo "    It is never read here, and this set never touches your node's data"
  echo "    directory or its validator token either."
  if [[ -n "$CRED_NOTE" ]]; then
    echo "  - /etc/aperire/creds, the model API key ($CRED_NOTE)."
  else
    echo "  - /etc/aperire/creds, the model API key, when one exists."
  fi
  echo "    On a host with systemd-creds it is sealed against THIS host's own"
  echo "    key in /var/lib/systemd/credential.secret, which no backup can"
  echo "    carry, so a copy of it is bytes that will not open anywhere else,"
  echo "    and on this same host after a wipe it sometimes opens and sometimes"
  echo "    does not. On a host without systemd-creds (Ubuntu 22.04 and its"
  echo "    systemd 249) it is the key itself, readable by root alone, and a"
  echo "    copy would be a working key wherever it landed. Either way it stays"
  echo "    out of this set. A rebuilt host gets its model back through the"
  echo "    fleet push instead, with no key pasted anywhere; see the restore"
  echo "    guide's Advisor section, the last step."
  if [[ -n "$FLEET_STORE_NOTE" ]]; then
    echo "  - the fleet model this aggregator holds ($FLEET_STORE_NOTE)."
    echo "    It is every node's provider key in one file: sealed to this host"
    echo "    where systemd-creds exists, kept in the clear as a root-only file"
    echo "    where it does not. A copy is useless in the first case and a"
    echo "    working key anywhere in the second, so it stays out either way."
    echo "    On a rebuilt aggregator, seal the fleet model again from Settings."
  fi
  echo
  echo "taken:"
  for r in ${TAKEN[@]+"${TAKEN[@]}"}; do echo "  ok    $r"; done
  echo "skipped:"
  for r in ${SKIPPED[@]+"${SKIPPED[@]}"}; do echo "  skip  $r"; done
  echo "failed:"
  for r in ${FAILED[@]+"${FAILED[@]}"}; do echo "  fail  $r"; done
} > "$STAGE/README"

( cd "$STAGE" && find . -type f ! -name MANIFEST.sha256 -print0 \
    | sort -z | xargs -0 sha256sum ) > "$STAGE/MANIFEST.sha256"

# ── place the set, owned by the operator, nobody else ───────────────────
# By descriptor, not `chown -R` by name (#1121) and not a walk over what a find
# returns (#1152, #1154): state-file.py copy-tree makes DEST (or takes an empty
# directory already there) on the parent's descriptor and creates every
# directory and file inside it new, relative to the directory it goes in. Each
# is the operator's from the moment it holds its content, files 0600 and
# anything that can run, and every directory, 0700, which is what `u+rwX,go-rwx`
# made of them. A name that is already in DEST, of any kind, is refused and left
# as it is, and a refusal takes back everything the copy made, so the operator
# cannot turn a link or a second name at one of the set's names into a write
# root makes. If anything it made is still at DEST, or no longer holds what it
# made (the clean-up goes by inode, #1163), it exits 4, not 3, and the run says
# that it is still at DEST. A stop during the placement is waited out by the
# copy and then reported here from the disk (#1164). The root of the walk is the set's
# parent, so the directories above it are held to the ancestor rule, and the
# parent itself with them (--judge-root, the same flag the up-front check
# above passes, so the two cannot disagree); --root / would have switched that
# off, and the mount rule it was mistaken for (state-file.py's
# _no_mount_on_the_way) only limits unlink and remove-tree.
OP_GID="$(getent group "$OP_GROUP" 2>/dev/null | head -1 | cut -d: -f3 || true)"
[[ "$OP_GID" =~ ^[0-9]+$ ]] || OP_GID="$(id -g "$OP_USER" 2>/dev/null || true)"
[[ "$OP_GID" =~ ^[0-9]+$ ]] \
  || die "could not resolve $OP_USER:$OP_GROUP to a uid and gid, so the set could not be handed to the operator. Nothing was written to $DEST."
place_set() { # $1 = the staged set, $2 = where it goes
  python3 -I "$SELF_DIR/state-file.py" copy-tree "$1" "$2" "$OP_UID" "$OP_GID" --root "$(dirname -- "$2")" --judge-root --owner "$OP_UID"
}
# What is at $DEST, read from the disk, for every way the placement can end
# that nothing else here can describe: a status copy-tree does not use, and a
# signal. A kill that cannot be caught, an out-of-memory kill, a stop from the
# service manager or a Ctrl-C can all land with the take-back unfinished, and
# the text that follows must say what is there rather than what a normal exit
# would have meant. It lists names only, as root, and never follows a link.
dest_now() {
  local names owner
  if [[ -L "$DEST" ]]; then
    printf '%s is a link, which this does not follow. Look at where it points before running this again.' "$DEST"
  elif [[ ! -e "$DEST" ]]; then
    printf 'Nothing is at %s. Run this again.' "$DEST"
  elif [[ ! -d "$DEST" ]]; then
    printf '%s is not a directory. Look at it before running this again.' "$DEST"
  else
    owner="$(stat -c '%U:%G, mode %a' -- "$DEST" 2>/dev/null || echo 'owner unknown')"
    # Names only, with anything a terminal would act on shown as "?".
    names="$(find "$DEST" -mindepth 1 -maxdepth 1 -printf '%f\0' 2>/dev/null | LC_ALL=C sort -z | LC_ALL=C tr -c '[:print:]\0' '?' | tr '\0' ' ')"
    if [[ -z "${names// /}" ]]; then
      printf '%s exists and is empty (%s), and a set can be placed in it. Run this again.' "$DEST" "$owner"
    else
      printf '%s holds: %s(%s). This run cannot tell which of that, if any, it put there; if it was cut off while copying, the set'"'"'s files, the private arm key among them, can be there. Look with sudo ls -la %s, remove what the set left, then run this again: a set is never written into a directory that holds something.' \
        "$DEST" "$names" "$owner" "$DEST"
    fi
  fi
}
# A stop that reaches this script during the placement. The child sees the same
# signal and finishes its take-back first; bash runs this when it returns.
# shellcheck disable=SC2317  # run by the traps below
stopped_in_placement() { # $1 = name, $2 = number
  trap '' INT TERM HUP
  printf '\n%serror:%s the backup was stopped by %s while it was placing the set. %s\n' \
    "${E_RED:-}" "${E_OFF:-}" "$1" "$(dest_now)" >&2
  exit $((128 + $2))
}
trap 'stopped_in_placement INT 2' INT
trap 'stopped_in_placement TERM 15' TERM
trap 'stopped_in_placement HUP 1' HUP
place_rc=0
place_set "$STAGE" "$DEST" || place_rc=$?
trap - INT TERM HUP
if [[ $place_rc -eq 4 ]]; then
  # state-file.py exits 4 when it could not clear every name it made or find.
  # What it names is still at DEST: the run must not claim an empty
  # destination, and the next run refuses a destination that holds anything.
  die "the set could not be placed at $DEST, and the take-back could not clear every name: what is named above is still at $DEST, and may include part of what was copied. $DEST is owned by root and closed to everyone else, so look at it and remove what is named as root, then run this again; a set is never written into a directory that holds something."
elif [[ $place_rc -eq 3 ]]; then
  die "the set could not be placed at $DEST: what stopped it is named above, and what was copied there was taken back. Run this again; if the lines above say $DEST still holds a name the copy did not make, that name has to be moved out as root first ($DEST is root's and closed to everyone else), because a set is never written into a directory that holds something."
elif [[ $place_rc -ne 0 ]]; then
  die "the set could not be placed at $DEST (the placement ended with status $place_rc): what stopped it is named above, if it said. $(dest_now)"
fi

# ── verify AS THE OPERATOR, not as root (#536) ────────────────────────
# A set that verifies clean under root and refuses for its own maker is not
# a backup; it only looks like one. runuser drops to the account this set
# now belongs to and re-reads it exactly the way a later restore will.
say "verifying"
if runuser -u "$OP_USER" -- bash -c "cd '$DEST' && sha256sum -c MANIFEST.sha256" >"$WORKDIR/verify.out" 2>&1; then
  info "MANIFEST.sha256 verifies, read back as $OP_USER"
else
  cat "$WORKDIR/verify.out" >&2
  die "the set does not verify as $OP_USER, it would not be readable by the
       operator who is meant to use it. Nothing was left half-written; check
       the output above."
fi

SIZE="$(du -sh "$DEST" 2>/dev/null | cut -f1)"
echo
echo "== done: ${#TAKEN[@]} taken, ${#SKIPPED[@]} skipped, ${#FAILED[@]} failed"
echo "== set:  $DEST  ($SIZE, owned by $OP_USER, mode 700)"
[[ "$REQUIRED_FAIL" -gt 0 ]] && exit 1
exit 0
