#!/usr/bin/env bash
# Let the dashboard ask this host to move to the release its endpoint
# publishes, and nothing else.
#
#   sudo bash scripts/install-update-grant.sh                 install the grant
#   sudo bash scripts/install-update-grant.sh --program-only  refresh the program
#                                                             and its config, and
#                                                             leave the units alone
#   sudo bash scripts/install-update-grant.sh --remove        take it back off
#
# What this grants, exactly: the account the dashboard runs as may open one
# private socket. Behind that socket is one program, running as root, which
# takes no arguments and reads one line on standard input. That line names a
# verb and, for an apply, the tag, the commit and the checksum the page
# believes is current. It names no source: the endpoint this host fetches
# from is written here, into a root-owned file the dashboard account cannot
# write, and the program fetches release.json and the archive's sum from it
# itself. A payload that disagrees with what the endpoint publishes is
# refused, so the dashboard can narrow what is installed and never widen it.
#
# ---- why a socket, and not sudo -------------------------------------
#
# Sudo cannot be the boundary. The dashboard's unit sets NoNewPrivileges=true
# and an empty CapabilityBoundingSet, and under those sudo refuses before it
# does anything at all. That hardening is not negotiable; it is most of what
# makes the dashboard a safe thing to run on a validator. So the privileged
# side has to be running already, and the dashboard has to reach it: systemd
# listens on /run/aperire/update.sock, owned by the dashboard account and
# mode 0600, and starts the program as root with the connection as its three
# streams. Same shape as install-model-key-sealer.sh and
# install-trust-sync-grant.sh, for the same reasons. This is the third grant.
#
# ---- why the program is copied out of the tree ----------------------
#
# The dashboard runs as the operator's own account, and the checkout is that
# account's files. A unit naming a script inside the checkout would be a unit
# naming a file the dashboard account can rewrite: root, for anything running
# as that account. So the program is installed to /usr/local/sbin, owned by
# root and writable only by root, and the service unit names that copy.
#
# It is copied through a temporary file in the same directory and renamed
# into place, rather than written over. An update runs this installer out of
# the NEW tree while the OLD copy of the program is the process driving that
# update: writing over it in place would hand the running bash new bytes at
# its old offset. A rename gives the running copy its own inode to finish
# reading and the next connection the new one.
#
# ---- what it writes -------------------------------------------------
#
#   /usr/local/sbin/aperire-update      the program, root:root 0755
#   /usr/local/lib/aperire/release-signers
#                                       root:root 0644: the release key the
#                                       program checks every release against
#                                       (docs/RELEASE-SIGNING.md)
#   /usr/local/lib/aperire/release-verify-lib.sh
#                                       root:root 0644: the check itself
#   /etc/aperire/update.conf            root:root 0644: the endpoint, the
#                                       install directory and the account
#                                       that owns it
#   /etc/systemd/system/aperire-update.socket
#   /etc/systemd/system/aperire-update@.service
#
# The endpoint is read from this host's own release stamp when it has one, so
# a host installed from a mirror keeps asking that mirror, and falls back to
# the address the bootstrap in this tree names.

set -euo pipefail

# Where this program and its siblings are (UPD_SELF), and the install tree it acts
# on (REPO): a directory and its parent from a checkout, two when it is a copy
# root staged out of the release and APERIRE_INSTALL_TREE names the tree
# (#764). Code is loaded and run from UPD_SELF only.
UPD_SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="${APERIRE_INSTALL_TREE:-$(cd "$UPD_SELF/.." && pwd)}"
SRC="$REPO/scripts/aperire-update.sh"
# Every copy into a root location is checked against the release's digests
# and made from the one read that was checked (ADR 0024).
# shellcheck source=scripts/release-digests-lib.sh
. "$UPD_SELF/release-digests-lib.sh"
DEST="${APERIRE_UPDATE_PATH:-/usr/local/sbin/aperire-update}"
LIB_DIR="${APERIRE_UPDATE_LIB_DIR:-/usr/local/lib/aperire}"
# The signed release this host last installed, kept by get-aperire.sh before
# install.sh (and so this installer) runs.
RELEASE_STORE="${APERIRE_UPDATE_RELEASE_STORE:-/var/lib/aperire/release}"
SOCK="${APERIRE_UPDATE_SOCKET:-/run/aperire/update.sock}"
ETC="${APERIRE_ETC:-/etc/aperire}"
CONF="${APERIRE_UPDATE_CONF:-$ETC/update.conf}"
UNIT_DIR="${APERIRE_UNIT_DIR:-/etc/systemd/system}"
# Where a host with no stamp and no bootstrap of its own is told to ask.
DEFAULT_ENDPOINT="${APERIRE_UPDATE_ENDPOINT:-https://get.aperire.one}"

SOCKET_UNIT=aperire-update.socket
SERVICE_UNIT='aperire-update@.service'

REMOVE=0
PROGRAM_ONLY=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --remove) REMOVE=1; shift ;;
    --program-only) PROGRAM_ONLY=1; shift ;;
    -h|--help) awk '/^[^#]/{exit} NR>1{sub(/^# ?/,""); print}' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

say()  { printf '   %s\n' "$*"; }
die()  { printf 'error: %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "run with sudo: this installs a program as root and two systemd units"

if [[ $REMOVE -eq 1 ]]; then
  systemctl disable --now "$SOCKET_UNIT" >/dev/null 2>&1 || true
  rm -f "$UNIT_DIR/$SOCKET_UNIT" "$UNIT_DIR/$SERVICE_UNIT" "$DEST" "$CONF"
  systemctl daemon-reload >/dev/null 2>&1 || true
  say "removed $UNIT_DIR/$SOCKET_UNIT and $UNIT_DIR/$SERVICE_UNIT"
  say "removed $DEST and $CONF"
  say "the dashboard can no longer ask this host to update. The operator still can:"
  say "  curl -fsSL ${DEFAULT_ENDPOINT} | bash -s -- --update"
  exit 0
fi

[[ -f "$SRC" ]] || die "no update program at $SRC; this tree is incomplete"
for _f in release-verify-lib.sh release-signers; do
  [[ -f "$REPO/scripts/$_f" ]] || die "no scripts/$_f in $REPO; the update program cannot check a release without it"
done
command -v systemctl >/dev/null || die "systemctl not found, and the grant is a socket unit"

# The account the dashboard runs as, from its own unit. Not $SUDO_USER: on a
# host where one operator installs and the service runs as another, the grant
# has to follow the service. The socket is opened to it.
#
# It is NOT necessarily the account that owns the checkout (ADR 0024): a
# fresh install runs the dashboard as aperire-dashboard and leaves the tree
# with the operator. The two are written to the conf separately below.
DASH_USER=""
for _u in aperire-server aperire-read; do
  _f="$UNIT_DIR/${_u}.service"
  [[ -f "$_f" ]] || continue
  DASH_USER=$(awk -F= '/^User=/{print $2; exit}' "$_f")
  [[ -n "$DASH_USER" ]] && break
done
DASH_USER="${DASH_USER:-${SUDO_USER:-}}"
[[ -n "$DASH_USER" ]] \
  || die "could not work out which account the dashboard runs as; no aperire-server unit and no SUDO_USER"
[[ "$DASH_USER" != root ]] \
  || die "the dashboard runs as root on this host, which needs no grant and should not have one"
getent passwd "$DASH_USER" >/dev/null || die "there is no account called '$DASH_USER'"

# The account that owns the checkout, from the checkout itself. The update
# unpacks, swaps and builds the tree as this account, which on a fresh
# install is the operator and never the dashboard's own account.
TREE_OWNER="$(stat -c '%U' "$REPO" 2>/dev/null || true)"
[[ -n "$TREE_OWNER" && "$TREE_OWNER" != UNKNOWN ]] \
  || die "could not read who owns $REPO"
[[ "$TREE_OWNER" != root ]] \
  || die "$REPO is owned by root; the update builds the tree as its owner, and never as root"
# Nor as a service account (ADR 0024): root runs installers out of the tree
# the update builds, so the tree's owner is never the dashboard's account or
# any account with no login shell.
[[ "$TREE_OWNER" != aperire-dashboard ]] \
  || die "$REPO is owned by aperire-dashboard, the dashboard's own account; the tree belongs to the operator who installed it"
case "$(getent passwd "$TREE_OWNER" | cut -d: -f7)" in
  */nologin|*/false) die "$REPO is owned by $TREE_OWNER, a service account with no login; the update never builds a tree as one" ;;
esac

# Where this host fetches from, in the order that keeps a mirror a mirror.
#
#   1. the stamp the last install wrote, which names the archive it really
#      fetched. It names the ARCHIVE, so the directory above it is the
#      endpoint: .../release.tar.gz -> ...
#   2. the bootstrap in this tree, which is stamped by the publisher
#   3. the address the product publishes from
#
# It says WHICH of the three it took, and that is not decoration. One host
# ended up installing from a lab stand-in on loopback with nothing on the box
# saying how the address got into update.conf (#293), and this file is
# written from inside an update — where the tree, the stamp and the
# bootstrap have all just moved. The answer is printed rather than reasoned
# about afterwards.
#
# Printed as "<source> <url>" on one line because this runs in a command
# substitution: a subshell cannot set a variable for its caller.
resolve_endpoint() {
  local from_stamp from_tree
  if [[ -f "$REPO/.release" ]]; then
    from_stamp="$(sed -n 's/^  "source_url": "\(.*\)",\?$/\1/p' "$REPO/.release" | head -1)"
    from_stamp="${from_stamp%/release.tar.gz}"
    if [[ "$from_stamp" =~ ^https?://[^[:space:]\"]+$ ]]; then
      printf 'stamp %s' "$from_stamp"; return 0
    fi
  fi
  if [[ -f "$REPO/scripts/get-aperire.sh" ]]; then
    from_tree="$(sed -n "s/^DEFAULT_SELF_URL='\(.*\)'\$/\1/p" "$REPO/scripts/get-aperire.sh" | head -1)"
    if [[ "$from_tree" =~ ^https?://[^[:space:]\"]+$ ]]; then
      printf 'tree %s' "$from_tree"; return 0
    fi
  fi
  printf 'default %s' "$DEFAULT_ENDPOINT"
  return 0
}
RESOLVED="$(resolve_endpoint)"
ENDPOINT_SOURCE="${RESOLVED%% *}"
ENDPOINT="${RESOLVED#* }"
case "$ENDPOINT_SOURCE" in
  stamp)   ENDPOINT_SAID="$REPO/.release, the stamp the last install wrote" ;;
  tree)    ENDPOINT_SAID="DEFAULT_SELF_URL in this tree's scripts/get-aperire.sh" ;;
  *)       ENDPOINT_SAID="the built-in default, since neither the stamp nor the tree named one" ;;
esac

echo
echo "== The release key, as root"
# Before the program, never after it: a program in place without the key it
# checks against refuses every update, and the page cannot say why.
#
# And only the bytes the release shipped. This tree is the operator's, and
# by the time an install or an update runs this, npm ci and the builds have
# run in it: a key appended to scripts/release-signers here would be trusted
# by every update after. So both files go through rd_place like every other
# root copy (ADR 0024), into a directory only root can write, checked against
# the release digests; for a signed release that record IS the signed file
# list (get-aperire.sh writes it from release.files, after the signature).
#
# Then the staged signer set is held to three more things before it is
# renamed into place, with the root-owned lib already installed when there is
# one, never code from the tree:
#
#   its shape          one ssh-ed25519 key, two only while rotating
#   the signed set     when the record describes the signed release this host
#                      kept, the set has to be the one its release.json names
#                      (signers_sha256), the value the maintainer's Mac
#                      checked against its own before it signed. The Mac
#                      never sees the tree's copy of this file, so this is
#                      the check that holds those bytes to what was signed
#   one step at most   from the set this host trusts now: the same set, or
#                      one rotation phase from it
#
# A host installed from a clone or a local archive has no signed release to
# hold the tree to, and gets the release digests' answer, said out loud.
install -d -m 0755 -o root -g root "$LIB_DIR"
_stage="$(mktemp -d "$LIB_DIR/.release-trust.XXXXXXXX")"
trap 'rm -rf "$_stage"' EXIT
for _f in release-verify-lib.sh release-signers; do
  _o="$(rd_install "$REPO" "scripts/$_f" "$_stage/$_f" 0644 --kinds)" \
    || die "$(rd_refused_cause "scripts/$_f in $REPO" "$_o"). The release key on this host was left as it was."
done
_lib="$_stage/release-verify-lib.sh"
[[ -s "$LIB_DIR/release-verify-lib.sh" ]] && _lib="$LIB_DIR/release-verify-lib.sh"
# shellcheck source=scripts/release-verify-lib.sh
. "$_lib"
# The staged set has to be one the updater will accept before it goes
# anywhere: a set root installs and the updater then refuses would leave the
# host unable to take any release.
_why="$(release_signers_check "$_stage/release-signers" 2>&1 >/dev/null)" \
  || die "scripts/release-signers in $REPO is not a release key set ($_why). The release key on this host was left as it was."
# The set this host trusts now. Present and not a set this code accepts is a
# refusal, never "nothing installed": the checks below that need it cannot be
# skipped by breaking the file they read.
_trust=""
if [[ -e "$LIB_DIR/release-signers" || -L "$LIB_DIR/release-signers" ]]; then
  if [[ -L "$LIB_DIR/release-signers" ]] || ! _why="$(release_signers_check "$LIB_DIR/release-signers" 2>&1 >/dev/null)"; then
    die "the release key already on this host ($LIB_DIR/release-signers) is not a set this installer accepts (${_why:-a symlink}), so it was left as it was. Uninstall, keeping your data, and install again with the one-liner."
  fi
  _trust="$LIB_DIR/release-signers"
fi
_said="checked against the release digests; not a signed release this host kept"
_cur=""
[[ -r "$RELEASE_STORE/current" ]] && _cur="$(head -1 "$RELEASE_STORE/current")"
_rec_key=""
[[ -r "$RD_DIGESTS" ]] && _rec_key="$(sed -n 's/^# key //p' "$RD_DIGESTS" | head -1)"
if [[ "$_cur" =~ ^[0-9a-f]{64}$ && "$_rec_key" == "$_cur" && -d "$RELEASE_STORE/$_cur" ]]; then
  # The kept release.json is evidence, not trust: its signature is checked
  # again, by the set this host already trusts, or by the staged set on a
  # host that trusts none yet.
  release_verify "$RELEASE_STORE/$_cur/release.json" "$RELEASE_STORE/$_cur/release.json.sig" "${_trust:-$_stage/release-signers}" \
    || die "the signed release this host kept ($RELEASE_STORE/$_cur) does not verify, so the release key on this host was left as it was."
  _set_want="$(release_json_field "$RELEASE_STORE/$_cur/release.json" signers_sha256)" || _set_want=""
  [[ -n "$_set_want" && "$(release_signers_digest "$_stage/release-signers")" == "$_set_want" ]] \
    || die "scripts/release-signers in $REPO is not the key set the signed release names. The release key on this host was left as it was."
  _said="the signed release's key set"
fi
if [[ -n "$_trust" ]] && ! _why="$(release_signers_transition_ok "$_trust" "$_stage/release-signers" 2>&1)"; then
  die "scripts/release-signers in $REPO would move this host's release key by more than one rotation step ($_why). The release key on this host was left as it was."
fi
for _f in release-verify-lib.sh release-signers; do
  mv -fT "$_stage/$_f" "$LIB_DIR/$_f"
  say "$LIB_DIR/$_f  (root:root 0644, $_said)"
done
# shellcheck source=scripts/release-verify-lib.sh
. "$LIB_DIR/release-verify-lib.sh"
if _n="$(release_signers_check "$LIB_DIR/release-signers" 2>/dev/null)"; then
  say "the program checks every release against ${_n} release key(s): $(release_key_fingerprints "$LIB_DIR/release-signers" | tr '\n' ' ')"
else
  say "WARNING: $LIB_DIR/release-signers names no release key, so the program"
  say "refuses every update until a release carrying one is installed by hand."
fi

echo
echo "== The update program, as root"
# Copied, not linked, and renamed rather than written over: this installer is
# run out of the new tree BY an update the old copy of the program is driving.
install -d -m 0755 -o root -g root "$(dirname "$DEST")"
# The two libraries its rollback stages the restored tree's installers with
# (#764), root's own copies beside the release key. First, so a program that
# needs them never lands in front of them.
for _f in release-digests-lib.sh trusted-path-lib.sh; do
  rd_place "$REPO" "scripts/$_f" "$LIB_DIR/$_f" 0644 \
    || die "$LIB_DIR/$_f was not installed, so the update program was not either"
done
rd_place "$REPO" scripts/aperire-update.sh "$DEST" 0755 \
  || die "the update program was not installed, so nothing below was written either"
say "an update refreshes this copy; run by hand, it is checked against the release this host is on"

echo
echo "== Where this host asks, and which tree it updates"
install -d -m 0755 -o root -g root "$ETC"
TMPC=$(mktemp)
cat > "$TMPC" <<EOF
# Written by scripts/install-update-grant.sh
#
# The three facts the update program is allowed to know, and the reason they
# live here rather than in the payload: the dashboard account cannot write
# this file, so a compromised web session cannot point root at a tree or an
# endpoint of its own choosing. It can ask for the release THIS endpoint
# publishes, or nothing.
ENDPOINT=$ENDPOINT
INSTALL_DIR=$REPO
# OPERATOR owns the tree, and the update builds it as that account.
# DASH_USER is the account the dashboard runs as. One account on a host
# installed before ADR 0024; two on a fresh one.
OPERATOR=$TREE_OWNER
DASH_USER=$DASH_USER
EOF
install -o root -g root -m 0644 "$TMPC" "$CONF"
rm -f "$TMPC"
# A fact line, at column 0, in the grammar the update program speaks: this
# installer is run from inside an apply, whose output the page reads as
# `key=value`, so this is where the answer to "how did that address get
# there" ends up on the record.
printf 'source=%s\n' "$ENDPOINT_SOURCE"
say "$CONF  (root:root 0644)"
say "endpoint     $ENDPOINT"
say "  taken from $ENDPOINT_SAID"
say "install dir  $REPO"
say "operator     $TREE_OWNER (owns the tree)"
say "dashboard    $DASH_USER (the socket's account)"

if [[ $PROGRAM_ONLY -eq 1 ]]; then
  echo
  say "--program-only: the socket and the service unit were left as they are."
  say "run this without the flag to write them from this tree."
  exit 0
fi

echo
echo "== One socket, one account, one program behind it"
TMPS=$(mktemp)
TMPV=$(mktemp)
trap 'rm -f "$TMPS" "$TMPV"; rm -rf "$_stage"' EXIT

cat > "$TMPS" <<EOF
# Written by scripts/install-update-grant.sh
#
# The dashboard account may open this socket and nothing else. Behind it is
# one root program that takes no arguments and reads one line: a verb, and for
# an apply the tag, commit and checksum it believes is current. The source is
# not on this socket; it is in $CONF, which that account cannot write.
[Unit]
Description=Aperire: the dashboard's way to ask this host to update itself
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
# One connection at a time, each its own instance, each ending when the
# program does. An update is one question and one long answer: the page tails
# the connection while the release is fetched, swapped and built.
Accept=yes
MaxConnections=1

[Install]
WantedBy=sockets.target
EOF

cat > "$TMPV" <<EOF
# Written by scripts/install-update-grant.sh
[Unit]
Description=Aperire: update this host to the published release (connection %i)
Documentation=file:$DEST
# A [Unit] key: under [Service] systemd 255 logs "Unknown key name" and
# ignores it. With SuccessExitStatus= below, a refusal is not a failure, and
# this lets a finished instance be unloaded rather than sit in
# \`systemctl --failed\` for ever.
CollectMode=inactive-or-failed

[Service]
# Root, because this writes the install tree, the systemd units and
# /usr/local/sbin. It takes no arguments and the socket in front of it is the
# only way to reach it. Deliberately not sandboxed further: it runs the
# release's own installer, which writes unit files and calls systemctl, so
# ProtectSystem= and friends would only break it. What constrains it is that
# it is ONE program, with no arguments, that can name no source.
ExecStart=$DEST
# The accepted connection is this program's three streams. The payload
# arrives on standard input; every line the update prints goes back the same
# way, as it happens, because the page tails this connection. An exit code
# does not cross a socket, which is why the program prints \`exit=\` last.
StandardInput=socket
StandardOutput=socket
StandardError=socket
# An hour, and this is the one place the sealer's shape is wrong to copy.
# A seal restarts one service and is done in seconds; an update runs the
# release's own prepare step, which is \`npm ci\` and two Go builds. On a small
# VPS that is minutes, and the sealer's 180 seconds would kill every real
# apply part way through a build, leaving a swapped tree with no node_modules
# and no binaries.
RuntimeMaxSec=3600
# A refusal is an outcome, not a failure. The program exits 2 for a payload it
# does not speak, 3 when what was asked for is not what the endpoint
# publishes, 4 when a run is already in flight, 5 when the endpoint could not
# be reached, 6 when the install did not finish and 7 when the release is not
# signed by the release key or is older than this host's. It has already said which
# in the journal and on the socket. Left as failures they would sit in
# \`systemctl --failed\` for ever (CollectMode= alone does not unload an
# Accept=yes instance while the socket holds it). What still counts as a
# failure is the bound above firing.
SuccessExitStatus=2 3 4 5 6 7
EOF

# Written only when the text has changed, and this is not an optimisation.
# An update runs this installer out of the new tree, and the process driving
# that update is an instance systemd started from this very socket. Restarting
# the socket underneath it is a question nobody should have to answer, so on
# the common path (a release that did not change these two files) it is never
# asked: nothing is reloaded and nothing is restarted.
UNITS_CHANGED=0
cmp -s "$TMPS" "$UNIT_DIR/$SOCKET_UNIT"  || UNITS_CHANGED=1
cmp -s "$TMPV" "$UNIT_DIR/$SERVICE_UNIT" || UNITS_CHANGED=1

# DirectoryMode= in the socket unit applies only to a directory systemd
# creates. The node wrapper may have made this one first, under its own umask,
# and then the dashboard cannot traverse it to its own socket (#171). Said
# here, every run, whether or not the units moved.
install -d -m 0755 -o root -g root "$(dirname "$SOCK")"

if [[ $UNITS_CHANGED -eq 1 ]]; then
  install -o root -g root -m 0644 "$TMPS" "$UNIT_DIR/$SOCKET_UNIT"
  install -o root -g root -m 0644 "$TMPV" "$UNIT_DIR/$SERVICE_UNIT"
  say "$UNIT_DIR/$SOCKET_UNIT   ($SOCK, $DASH_USER only, mode 0600)"
  say "$UNIT_DIR/$SERVICE_UNIT  (runs $DEST as root, no arguments)"
  systemctl daemon-reload
  # Restarted, not merely enabled: the text just changed, and an
  # already-listening socket would go on serving the old one.
  systemctl enable "$SOCKET_UNIT" >/dev/null
  systemctl restart "$SOCKET_UNIT"
else
  say "$UNIT_DIR/$SOCKET_UNIT   (already this release's text, so nothing was reloaded)"
  say "$UNIT_DIR/$SERVICE_UNIT  (the same)"
  # Enabled and listening is still asserted, because "unchanged" is a claim
  # about a file and not about a socket.
  systemctl enable "$SOCKET_UNIT" >/dev/null
  systemctl is-active --quiet "$SOCKET_UNIT" || systemctl start "$SOCKET_UNIT"
fi

# The grant has to work for the account it names, not just parse. Without this
# the dashboard discovers it when an operator presses Update and watches
# nothing happen.
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
# the dashboard cannot traverse, and that was exactly the case on one host
# (#171). A test -e from that account needs search on every directory above.
runuser -u "$DASH_USER" -- test -e "$SOCK" 2>/dev/null \
  || die "$SOCK exists but $DASH_USER cannot reach it.
     Read: stat -c '%A %U' $(dirname "$SOCK")"
say "checked: $SOCK is listening, owned by $DASH_USER, mode 600, reachable as $DASH_USER"
say "the dashboard can now check for a release, apply it, and ask for a restart"
say "afterwards. It cannot restart anything by applying, and it cannot name a"
say "source: this host fetches from $ENDPOINT and compares what it was asked"
say "for with what it found."
