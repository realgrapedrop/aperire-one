#!/usr/bin/env bash
# Let the dashboard ask for the Advisor's trust store to be rebuilt, and
# nothing else.
#
#   sudo bash scripts/install-trust-sync-grant.sh          install the grant
#   sudo bash scripts/install-trust-sync-grant.sh --remove take it back off
#   bash scripts/install-trust-sync-grant.sh --stale       read only: is the installed unit out of date?
#   sudo bash scripts/install-trust-sync-grant.sh --if-stale   install again only when it is
#
# What this grants, exactly: the account the dashboard runs as may open one
# private socket. Behind that socket is one program, running as root, which
# takes no arguments, reads an origin and an rp_id on standard input, reads the
# admins' passkeys out of the dashboard's OWN database and writes them into the
# Advisor's trust store as the Advisor's account. Nothing the dashboard sends
# goes into the store; it can only ask for the store to be brought level with
# the database it already owns.
#
# ---- why this exists ------------------------------------------------
#
# The Advisor checks passkey approvals against its own copy of the admins'
# public keys. Every CLI command that changes who is an admin re-syncs that copy
# on its way out. A passkey enrolled in a BROWSER is the one change the CLI
# never sees, and until this grant existed it left the store stale on every
# host, every time, until an operator noticed the banner and ran a command on
# the box. That was the root cause of "Trust store is stale" being the normal
# state of a fresh install. Now the dashboard asks for the same sync the CLI
# runs, the moment an enrollment lands.
#
# ---- why a socket, and not sudo -------------------------------------
#
# Sudo cannot be the boundary. The dashboard's unit sets NoNewPrivileges=true
# and an empty CapabilityBoundingSet, and under those sudo refuses before it
# does anything at all. That hardening is not negotiable; it is most of what
# makes the dashboard a safe thing to run on a validator. So the privileged
# side has to be running already, and the dashboard has to reach it: systemd
# listens on /run/aperire/trust-sync.sock, owned by the dashboard account and
# mode 0600, and starts the sync as root with the connection as its three
# streams. Same shape as install-model-key-sealer.sh, for the same reasons.
#
# ---- why the program is copied out of the tree ----------------------
#
# The dashboard runs as the operator's own account, and the checkout is that
# account's files. A unit naming a script inside the checkout would be a unit
# naming a file the dashboard account can rewrite: root, for anything running
# as that account. So the sync program is installed to /usr/local/sbin, owned
# by root and writable only by root, and the service unit names that copy.
# Re-run this after updating the checkout to refresh it.

set -euo pipefail

# As root the environment chooses no path or program (#1206): every
# APERIRE_* variable is dropped except the ones a root caller passes on
# purpose:
#   APERIRE_INSTALL_TREE  get-aperire.sh names the tree a staged copy serves (#764)
# An account id(1) says is not root keeps them all, which is what every
# suite is. id(1) at a fixed path, never bash's $EUID (#1109).
if ! [[ "$(/usr/bin/id -u 2>/dev/null)" =~ ^[1-9][0-9]*$ ]]; then
  for _v in $(compgen -e); do
    case "$_v" in APERIRE_INSTALL_TREE) ;; APERIRE_*) unset "$_v" ;; esac
  done
fi

# Where this program and its siblings are (GRANT_SELF), and the install tree it acts
# on (REPO): a directory and its parent from a checkout, two when it is a copy
# root staged out of the release and APERIRE_INSTALL_TREE names the tree
# (#764). Code is loaded and run from GRANT_SELF only.
GRANT_SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="${APERIRE_INSTALL_TREE:-$(cd "$GRANT_SELF/.." && pwd)}"
SRC="$REPO/scripts/aperire-trust-sync.sh"
# Every copy into a root location is checked against the release's digests
# and made from the one read that was checked (ADR 0024).
# shellcheck source=scripts/release-digests-lib.sh
. "$GRANT_SELF/release-digests-lib.sh"
DEST="${APERIRE_TRUST_SYNC_PATH:-/usr/local/sbin/aperire-trust-sync}"
SOCK="${APERIRE_TRUST_SYNC_SOCKET:-/run/aperire/trust-sync.sock}"
ETC="${APERIRE_ETC:-/etc/aperire}"
UNIT_DIR="${APERIRE_UNIT_DIR:-/etc/systemd/system}"

SOCKET_UNIT=aperire-trust-sync.socket
SERVICE_UNIT='aperire-trust-sync@.service'

REMOVE=0
STALE_ONLY=0
IF_STALE=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --remove) REMOVE=1; shift ;;
    --stale) STALE_ONLY=1; shift ;;
    --if-stale) IF_STALE=1; shift ;;
    -h|--help) awk '/^[^#]/{exit} NR>1{sub(/^# ?/,""); print}' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

say()  { printf '   %s\n' "$*"; }
die()  { printf 'error: %s\n' "$*" >&2; exit 1; }

# One verb at a time. --if-stale used to be read after --remove had already
# been acted on, so `--remove --if-stale` took the grant off (#1135 review).
if (( REMOVE + STALE_ONLY + IF_STALE > 1 )); then
  die "--remove, --stale and --if-stale each do one thing; give one of them"
fi

# Is the installed service unit one an older release wrote (#800)? A unit
# written before the fix carried CollectMode= under [Service], where systemd
# reads no such key: every trust sync logged "Unknown key name" until someone
# ran this again, and an update did not. Any key systemd reads only under
# [Unit] found under [Service] counts. The unit is 0644 in a directory root
# owns, so this reads it as anyone and changes nothing.
#
#   0 = stale, 1 = current, 3 = no such unit (the grant is not installed here)
unit_is_stale() {
  local f="$UNIT_DIR/$SERVICE_UNIT"
  [[ -f "$f" ]] || return 3
  awk '
    /^\[/ { sec = $0; next }
    sec == "[Service]" && $0 ~ /^(CollectMode|Description|Documentation|After|Before|Requires|Wants|BindsTo|PartOf|Conflicts|OnFailure)[[:space:]]*=/ { found = 1 }
    END { exit found ? 0 : 1 }
  ' "$f"
}

if [[ $STALE_ONLY -eq 1 ]]; then
  rc=0; unit_is_stale || rc=$?
  case "$rc" in
    0) echo "stale=1"; exit 0 ;;
    3) echo "stale=absent"; exit 3 ;;
    *) echo "stale=0"; exit 1 ;;
  esac
fi

[[ $EUID -eq 0 ]] || die "run with sudo: this installs a program as root and two systemd units"

# Install again only when the unit on disk is out of date, and say so either
# way. A grant that is not installed here is not this run's to install.
if [[ $IF_STALE -eq 1 ]]; then
  rc=0; unit_is_stale || rc=$?
  case "$rc" in
    0) say "the installed $SERVICE_UNIT is out of date, so it is written again" ;;
    3) say "the trust sync grant is not installed here, so there is nothing to refresh"; exit 0 ;;
    *) say "the installed $SERVICE_UNIT is current, so nothing was changed"; exit 0 ;;
  esac
fi

if [[ $REMOVE -eq 1 ]]; then
  systemctl disable --now "$SOCKET_UNIT" >/dev/null 2>&1 || true
  rm -f "$UNIT_DIR/$SOCKET_UNIT" "$UNIT_DIR/$SERVICE_UNIT" "$DEST"
  systemctl daemon-reload >/dev/null 2>&1 || true
  say "removed $UNIT_DIR/$SOCKET_UNIT and $UNIT_DIR/$SERVICE_UNIT"
  say "removed $DEST"
  say "the dashboard can no longer ask for a trust sync. The operator still can:"
  say "  bash $REPO/scripts/aperire-auth.sh advisor-sync"
  exit 0
fi

[[ -f "$SRC" ]] || die "no sync program at $SRC; this tree is incomplete"
command -v systemctl >/dev/null || die "systemctl not found, and the grant is a socket unit"

# The account the dashboard runs as, from its own unit. Not $SUDO_USER: on a
# host where one operator installs and the service runs as another, the grant
# has to follow the service.
DASH_USER=""
DASH_ENV_FILE=""
for _u in aperire-server aperire-read; do
  _f="$UNIT_DIR/${_u}.service"
  [[ -f "$_f" ]] || continue
  DASH_USER=$(awk -F= '/^User=/{print $2; exit}' "$_f")
  DASH_ENV_FILE=$(awk -F= '/^EnvironmentFile=/{sub(/^-/,"",$2); print $2; exit}' "$_f")
  [[ -n "$DASH_USER" ]] && break
done
DASH_USER="${DASH_USER:-${SUDO_USER:-}}"
[[ -n "$DASH_USER" ]] \
  || die "could not work out which account the dashboard runs as; no aperire-server unit and no SUDO_USER"
[[ "$DASH_USER" != root ]] \
  || die "the dashboard runs as root on this host, which needs no grant and should not have one"
getent passwd "$DASH_USER" >/dev/null || die "there is no account called '$DASH_USER'"

# The two paths the program needs, resolved the way the services resolve
# them, so the store this writes is the one the Advisor reads and the
# database it reads is the one the dashboard writes. The dashboard's
# environment file names the database; the Advisor's unit names its state.
DB_PATH="${APERIRE_DB_PATH:-}"
if [[ -z "$DB_PATH" ]]; then
  for _e in "$DASH_ENV_FILE" "$ETC/aperire.env"; do
    [[ -n "$_e" && -f "$_e" ]] || continue
    DB_PATH=$(awk -F= '$1=="APERIRE_DB_PATH"{sub(/^[^=]*=/,""); gsub(/"/,""); print; exit}' "$_e")
    [[ -n "$DB_PATH" ]] && break
  done
fi
DB_PATH="${DB_PATH:-$REPO/data/aperire.db}"

STATE_DIR="${APERIRE_ADVISOR_STATE:-}"
if [[ -z "$STATE_DIR" && -f "$UNIT_DIR/aperire-advisord.service" ]]; then
  STATE_DIR=$(grep -oE -- '--state=[^ ]+' "$UNIT_DIR/aperire-advisord.service" | head -1 | cut -d= -f2- || true)
fi
STATE_DIR="${STATE_DIR:-$REPO/advisor/state}"

echo
echo "== The sync program, as root"
# Copied, not linked. A symlink into the tree would put the grantee back in
# charge of what root runs.
rd_place "$REPO" scripts/aperire-trust-sync.sh "$DEST" 0755 \
  || die "the sync program was not installed, so nothing below was written either"
say "an update refreshes this copy; run by hand, it is checked against the release this host is on"

echo
echo "== One socket, one account, one program behind it"
TMPS=$(mktemp)
TMPV=$(mktemp)
trap 'rm -f "$TMPS" "$TMPV"' EXIT

cat > "$TMPS" <<EOF
# Written by scripts/install-trust-sync-grant.sh
#
# The dashboard account may open this socket and nothing else. Behind it is one
# root program that takes no arguments, reads an origin and an rp_id on
# standard input, and rebuilds the Advisor's trust store from the dashboard's
# own database. Nothing sent over this socket goes into the store.
[Unit]
Description=Aperire: the dashboard's way to ask for the Advisor's trust store to be synced
Documentation=file:$DEST

[Socket]
ListenStream=$SOCK
SocketUser=$DASH_USER
SocketGroup=$DASH_USER
SocketMode=0600
# systemd creates the parent directory of a filesystem socket before binding,
# with this mode. Nothing declares /run/aperire as a RuntimeDirectory, so no
# unit stopping takes it away underneath this one.
DirectoryMode=0755
# One connection at a time, each its own instance, each ending when the program
# does. A sync is one question and one answer.
Accept=yes
MaxConnections=1

[Install]
WantedBy=sockets.target
EOF

cat > "$TMPV" <<EOF
# Written by scripts/install-trust-sync-grant.sh
[Unit]
Description=Aperire: sync the Advisor's trust store from the dashboard's database (connection %i)
Documentation=file:$DEST
# A [Unit] key: under [Service] systemd ignores it with an "Unknown key name"
# line on every sync (#800).
CollectMode=inactive-or-failed

[Service]
# Root, because the two files belong to two accounts: the database is the
# dashboard's and the state directory is the Advisor's, and root is the one
# thing that can act as each in turn. The program does exactly that (reads as
# the database's owner, writes as the state directory's owner) and never
# touches either file as root itself.
ExecStart=$DEST --from-socket
Environment=APERIRE_DB_PATH=$DB_PATH
Environment=APERIRE_ADVISOR_STATE=$STATE_DIR
# The accepted connection is this program's three streams. The two lines
# arrive on standard input; the fields and any refusal go back the same way.
# An exit code does not cross a socket, which is why the program prints
# \`exit=\` last. Its journal line is written with logger and is unaffected.
StandardInput=socket
StandardOutput=socket
StandardError=socket
# A bound, so a sync that never returns cannot hold a connection open for
# ever. It reads one table and writes one file.
RuntimeMaxSec=60
# A refusal is an outcome, not a failure. The program exits 1 for "no
# database", "issuer-installed store" and the like, and 3 when the request
# tried to move the relying party or widen the origins; it has already said
# which in the journal and on the socket. Left as failures they would sit in
# \`systemctl --failed\` for ever (CollectMode= alone does not unload an
# Accept=yes instance while the socket holds it). What still counts as a
# failure is the bound above firing.
SuccessExitStatus=1 3
EOF

install -o root -g root -m 0644 "$TMPS" "$UNIT_DIR/$SOCKET_UNIT"
install -o root -g root -m 0644 "$TMPV" "$UNIT_DIR/$SERVICE_UNIT"
say "$UNIT_DIR/$SOCKET_UNIT   ($SOCK, $DASH_USER only, mode 0600)"
say "$UNIT_DIR/$SERVICE_UNIT  (runs $DEST as root, no arguments)"
say "database $DB_PATH"
say "store    $STATE_DIR/credentials.json"

systemctl daemon-reload
# Restarted, not merely enabled: on a re-run the unit text may have changed,
# and an already-listening socket would go on serving the old one.
systemctl enable "$SOCKET_UNIT" >/dev/null
# DirectoryMode= above applies only to a directory systemd creates. The node
# wrapper may have made this one first, under its own umask, and then the
# dashboard cannot traverse it to its own socket (#171). Said here, every run.
install -d -m 0755 -o root -g root "$(dirname "$SOCK")"
systemctl restart "$SOCKET_UNIT"

# The grant has to work for the account it names, not just parse. Without this
# the dashboard discovers it after an enrollment an operator was watching.
systemctl is-active --quiet "$SOCKET_UNIT" \
  || die "$SOCKET_UNIT did not come up. Read: systemctl status $SOCKET_UNIT"
[[ -S "$SOCK" ]] \
  || die "$SOCKET_UNIT is active but there is no socket at $SOCK.
     Read: systemctl status $SOCKET_UNIT"
owner_mode="$(stat -c '%U %a' "$SOCK" 2>/dev/null || true)"
[[ "$owner_mode" == "$DASH_USER 600" ]] \
  || die "$SOCK is '$owner_mode', not '$DASH_USER 600'.
     Either the dashboard cannot open it, or somebody else can."
# As the dashboard account, not as root: root can see a socket in a directory
# the dashboard cannot traverse, and that was exactly the case on aperire1
# (#171). A test -e from that account needs search on every directory above.
runuser -u "$DASH_USER" -- test -e "$SOCK" 2>/dev/null \
  || die "$SOCK exists but $DASH_USER cannot reach it.
     Read: stat -c '%A %U' $(dirname "$SOCK")"
say "checked: $SOCK is listening, owned by $DASH_USER, mode 600, reachable as $DASH_USER"
say "a passkey enrolled in the browser now reaches the Advisor by itself"
