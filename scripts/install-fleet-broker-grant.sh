#!/usr/bin/env bash
# Let the dashboard register a paired node and hold the fleet's model key,
# and nothing else.
#
#   curl -fsSL https://get.aperire.one | bash -s -- --run fleet-broker-grant          install the grant
#   curl -fsSL https://get.aperire.one | bash -s -- --run fleet-broker-grant --refresh-nodes
#                                                           build root's node record
#                                                           (on a host with the grant;
#                                                           refused on one without)
#   curl -fsSL https://get.aperire.one | bash -s -- --run fleet-broker-grant --remove take it back off
#   curl -fsSL https://get.aperire.one | bash -s -- --run fleet-broker-grant --new-fleet-keys
#                                                           install the grant, and make
#                                                           a fleet key that is missing
#                                                           on a host with paired nodes
#                                                           (#851; see FLEET-KEYS below)
#
# Exit codes:
#
#   0  installed (or removed, or the node record refreshed)
#   1  a check failed or a step could not be done; the message says which
#   2  usage: an unknown argument, or --new-fleet-keys beside --remove or
#      --refresh-nodes
#   3  --refresh-nodes on a host with no grant installed; nothing written
#   4  a fleet key is missing and this host already has paired nodes, so no
#      new key was made and nothing was written (#851). The message names
#      the nodes, the restore command, and --new-fleet-keys
#
# What this grants, exactly: the account the dashboard runs as may open one
# private socket. Behind that socket is one program, running as root, which
# the socket starts with no arguments and which reads one verb on standard
# input. Root's own update also runs it with one argv mode (#828), which
# re-records the install directory's id after the update's tree swap.
#
#   approve           appends one fleet row pinned to a node key, writes that
#                     row's two token files, adds one peer to the Advisor's
#                     own registry, records the node in root's own
#                     fleet-nodes.conf, and sends one SIGHUP
#   revoke            takes the node out everywhere this host holds it: its
#                     fleet.yaml row, its link row, its peer in the Advisor's
#                     registry, its line in fleet-nodes.conf and its two token
#                     files, then sends the same SIGHUP (#854, #859)
#   repin             rewrites one fleet.yaml row's pinned node key for
#                     Accept new key, and never fleet-nodes.conf (#859)
#   attach-advisor    gives ONE link row that already exists an Advisor
#                     address and token path (advisor_origin and
#                     advisor_token_path) on a port from its own pool, adds
#                     that port to the row's link record, writes the token
#                     file the label names and sets the row's advisor flag in
#                     fleet-nodes.conf to 1. It refuses unless the row and
#                     root's own record both pin the node key it is shown
#                     (#641)
#   detach-advisor    takes those two lines back off the row, drops the
#                     link's advisor port, deletes that one token file and
#                     sets the flag back to 0. The node's own Advisor and its
#                     token are not touched (#641)
#   refresh-advisor-token
#                     replaces the content of that token file on a row that
#                     is already attached, and nothing else: no port, no
#                     registry, no flag (#641)
#   model-store-put   seals the fleet's model descriptor, key included, with
#                     systemd-creds under one pinned credential name, or on a
#                     host without it (systemd 249) keeps it as a root 0600
#                     file, fleet-model.cred.plain (#711)
#   model-store-head  reads that descriptor back MINUS the key
#   model-push        sends the descriptor to one node named by
#                     fleet-nodes.conf, which only root writes, and only
#                     while an arming window is open on THIS host
#   arm-key           makes the fleet arm key if there is none and returns
#                     its PUBLIC half, for the signed pairing welcome (#741);
#                     never the private half, and it opens nothing
#   arm-key-check     says whether that key is there (present, missing or
#                     unsafe) and makes nothing; the Settings page's pairing
#                     check asks this, so opening Add a node never makes a key
#                     (both arm verbs refuse no_node first when the broker
#                     has no node to read registries back with, #964)
#
# The installer itself also makes the two keys a node's pairing fingerprint
# covers, the fleet trust key and the fleet arm key, where either is absent,
# and never rewrites one that is there. On a host that already has paired
# nodes it makes neither without --new-fleet-keys, and refuses with exit 4
# instead (#851; see FLEET-KEYS below).
#
# It removes a fleet.yaml row only on revoke, the row the label names (#859).
# It cannot name a path, choose a port, widen a
# token file's mode, open an arm window or mint an arm token.
# There is no verb that returns the model key: it goes in and it goes out to
# a node, and nothing reads it back. And it cannot move the key at a moment
# of its own choosing: a push refuses unless /etc/aperire/model-key.arm is
# here, owned by root, not group or world writable, and younger than 900 s.
# The broker only ever STATS that marker. It never writes one and never
# removes one, so the window stays something an operator opens at this
# keyboard with:
#
#   sudo aperire-fleet-arm --self-only
#
# A push does not spend it, because a catch-up is one arming and many
# pushes. It lapses on its own. Every path it writes is derived from the
# label inside one fixed directory, and the ports come from its own pool.
# `revoke` does remove a LINK row, which is the sentence above; fleet.yaml's
# own owner and mode are set by the placement rather than preserved (P3-060);
# `model-store-head` does read a descriptor back, which is how the page says
# whether a node paired now would inherit a model; and, #620, `approve` with
# `convert_tunnel=1` does change ONE fleet.yaml row in place -- only the row
# already pinned to the presented node key under the label the caller names,
# from a tunnel to a link, never a row of the caller's own choosing.
# `attach-advisor` and `detach-advisor` rewrite those two Advisor lines on ONE
# existing link row and never append or remove a row: every other field on it
# is read back as it went in. A rejoin never raises a row's Advisor state:
# attach-advisor is how an existing link row gets one. A rejoin lowers it
# when the node's hello says it has no Advisor or brings a token other than
# the one held here (#1079), and when root's record marks an Advisor that the
# fleet.yaml row does not have.
#
# Round 4, #648: there is no migration story here. This project has not
# shipped, so there is no installed base whose fleet-tokens ever sat under
# advisor/state to carry forward, and shipping root code that walks an
# unprivileged account's directory to migrate an installed base that does
# not exist is a net loss whatever its own guards look like -- an earlier
# version of that guard was itself the finding a round later. TOKEN_DIR
# sits under $ETC unconditionally now; the broker never reads from or writes
# to advisor/state/fleet-tokens, on any verb, on any host. A fleet whose
# fleet.yaml still names that path is left exactly as it is (the broker's
# write_token already refuses to write anywhere but TOKEN_DIR by name), and
# carrying an existing fleet across is a hand-run, lab-only script, never a
# thing this program does to a connection nobody asked to migrate anything
# on.
#
# ---- where a push may send -------------------------------------------
#
# /etc/aperire/fleet-nodes.conf, root:root 0600, one line per node:
#
#   <label> <pubkey_node> <read_port> <advisor 0|1> [read token path]
#
# Every label, node key, port and token path in it is validated on the way in
# and on the way out: fleet.yaml belongs to the dashboard account, and a label
# carrying a newline would otherwise write rows into the one file that says
# where a provider key may be sent. Rows that do not match are counted and
# named.
#
# The fifth field is there only when the registry names a read token path
# other than the one an approval writes, `/etc/aperire/fleet-tokens/
# <label>.token` (#458). Absent means that path. A fleet joined
# with aperire-fleet-add.sh --token-path keeps its token where the operator
# put it, the dashboard's seal reads that path off the row, and a push that
# derived the path from the label refused a node the seal had reached
# minutes before. Carrying the path here rather than copying the token to
# the convention path is the point: two copies of a bearer token are equal
# only at the moment they are made, and root vouches for this path the same
# way it vouches for the pin and the port.
#
# `approve` appends to it and `revoke` prunes it. A fleet paired before this
# feature has no such file, so `--refresh-nodes` builds it once from
# fleet.yaml plus fleet-links.json, as an explicit root act: root vouching
# for the registry as it stands today, rather than the broker trusting a file
# the dashboard account owns.
#
# ---- why this exists ------------------------------------------------
#
# Phase 1 of ADR 0019 had an operator hand-place a credential hash on the
# aggregator and a credential on the node, on two machines, in two files
# whose parsers both fail the whole thing closed. Phase 3 replaces that with
# a code an admin mints on the page and one command on the node — and the
# files that have to change are the dashboard's own config, which the
# dashboard must not be able to write on its own say-so.
#
# ---- why a socket, and not sudo -------------------------------------
#
# The dashboard's unit sets NoNewPrivileges=true and an empty
# CapabilityBoundingSet, and under those sudo refuses before it does anything
# at all. That hardening is most of what makes the dashboard a safe thing to
# run beside a validator, so the privileged side has to be running already:
# systemd listens on /run/aperire/fleet-broker.sock, owned by the dashboard
# account and mode 0600, and starts the broker as root with the connection as
# its three streams. The same shape as the model-key sealer, the trust sync
# and the updater, for the same reasons.
#
# ---- why the program is copied out of the tree ----------------------
#
# The checkout belongs to the dashboard's own account. A unit naming a script
# inside it would be a unit naming a file that account can rewrite, which is
# root for that account. So the broker is installed to /usr/local/sbin, owned
# by root, and the unit names that copy. Re-run this after updating the
# checkout to refresh it.
#
# "Owned by root" is not the same as "no other account can replace it", and
# this used to claim the second one. /usr/local's own historical Debian
# default is root:staff 2775, group-writable on purpose, and on a host that
# follows that convention any account in that group can rename the installed
# program out of the way. So the install checks it rather than asserting: the
# dashboard account and the advisord account are held against the whole
# ancestor chain of the install directory, by numeric gid, and an install
# into a directory either of them can write through a group refuses and says
# which group.
#
# ---- and the same rule, for the one thing that got past it (#370) ---
#
# The broker reads every registry back before it writes one, with the
# dashboard's own TypeScript parsers, out of that same checkout. Importing a
# module out of a tree that account can rewrite is the rule above with the
# words changed, so that validation does not run as root: it runs as the
# dashboard account itself, through `runuser -u`, with the candidates handed
# to it in a directory it can read and cannot write. What comes back to root
# is one word out of a fixed set.
#
# That account is a fact about this host, so it is settled HERE and pinned in
# the conf as DASH_ACCOUNT, read from the dashboard unit's own `User=`. The
# broker never works it out at run time: a host whose grant predates this key
# refuses an approval by name and says to run this installer again, which is
# the honest answer, where guessing would be the thing this exists to stop.

set -euo pipefail

# Where this program and its siblings are (BROKER_SELF), and the install tree it acts
# on (REPO): a directory and its parent from a checkout, two when it is a copy
# root staged out of the release and APERIRE_INSTALL_TREE names the tree
# (#764). Code is loaded and run from BROKER_SELF only.
BROKER_SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="${APERIRE_INSTALL_TREE:-$(cd "$BROKER_SELF/.." && pwd)}"
SRC="$REPO/scripts/aperire-fleet-broker.sh"
DEST="${APERIRE_FLEET_BROKER_PATH:-/usr/local/sbin/aperire-fleet-broker}"
# #741: the one command a node's operator runs on this aggregator for the
# pairing fingerprint, root-owned at a fixed name on root's PATH. The node's
# prompt, the install summary and the docs name it by that name, so the
# operator never takes a path from the Settings page, which the dashboard
# account serves. Placed beside the broker, by the same primitive, because a
# host that can approve a pairing is exactly a host that has this grant.
ARM_SRC="$REPO/scripts/aperire-fleet-arm.sh"
ARM_DEST="${APERIRE_FLEET_ARM_PATH:-$(dirname -- "$DEST")/aperire-fleet-arm}"
SOCK="${APERIRE_FLEET_BROKER_SOCKET:-/run/aperire/fleet-broker.sock}"
ETC="${APERIRE_ETC:-/etc/aperire}"
UNIT_DIR="${APERIRE_UNIT_DIR:-/etc/systemd/system}"
CONF="$ETC/fleet-broker.conf"

SOCKET_UNIT=aperire-fleet-broker.socket
SERVICE_UNIT='aperire-fleet-broker@.service'

# The pool a new node's two loopback ports come from (ruling, 2026-09-12).
# One contiguous range, lowest free first, overridable here rather than in
# the payload: a caller that could name a port could name a conflict.
PORT_MIN="${APERIRE_FLEET_LINK_PORT_MIN:-7900}"
PORT_MAX="${APERIRE_FLEET_LINK_PORT_MAX:-7999}"

NODES_CONF="$ETC/fleet-nodes.conf"

# ── the directory-safe primitive (#648, round 7, review7-0.json CRITICAL) ──
#
# The IDENTICAL text aperire-fleet-broker.sh carries between its own
# DIRSAFE-PY markers, mirrored here byte for byte rather than sourced --
# this program installs the broker to /usr/local/sbin as ONE file with no
# sibling library, the same reason --refresh-nodes' own snapshot_registry_file
# is a second copy rather than an import. test-fleet-broker.sh and
# test-install-fleet-broker-grant.sh both extract their copy between these
# markers and diff them byte for byte, so the two drifting apart fails CI
# rather than silently, the way this file's OWN snapshot_registry_file once
# could have next to the broker's.
#
# What it is FOR is dirsafe.py's own header, not repeated here; every write
# and read in THIS installer that lands in a directory an unprivileged
# account could own (dashboard/config, for --refresh-nodes) or that this
# round asked to carry the same discipline anyway ($ETC, the unit directory,
# /usr/local/sbin) goes through it now.
GRANT_WORK="$(umask 077; mktemp -d)"
# Root's own scratch (the dirsafe copy, key and registry snapshots), gone on
# every exit. --refresh-nodes lays its own trap and puts this one back.
trap 'rm -rf "$GRANT_WORK"' EXIT
# --- DIRSAFE-PY-BEGIN ---
cat > "$GRANT_WORK/dirsafe.py" <<'DIRSAFE_PY_EOF'
import grp
import os
import pwd
import stat
import sys

# One directory-safe primitive for every root write, rename, read, unlink and
# mkdir this program (and its grant installer) ever makes into a directory an
# unprivileged account could own -- dashboard/config, advisor/state, and, for
# the one discipline everywhere, $ETC and /usr/local/sbin too, which need no
# defence today but must never become a second copy of this file to drift
# from (#648, round 7, review7-0.json CRITICAL).
#
# The bug this closes: every write in this program used to resolve the
# TARGET's directory by ORDINARY PATH LOOKUP (bash's own `dirname`, then
# mktemp/mv/install/cp against that string). Path lookup follows a symlink at
# ANY component silently. An account that owns a directory somewhere on the
# way down -- dashboard/, because the dashboard account manages its own
# tree end to end -- can swap that directory's own entry in ITS OWN PARENT
# for a symlink at any instant, atomically (`mv -T decoy dashboard`), and the
# very next root write that resolves "dashboard/config/fleet.yaml" as a
# string walks straight through it. Nothing this program checked before round
# 7 ever looked at anything but the FINAL component (the target file itself,
# or, in ensure_token_dir, one parent up) -- never the whole chain.
#
# The fix is never to let the OS resolve that path again after the first
# look. Every hop from a trusted ANCHOR down to the directory a write lands
# in is opened by NAME, relative to the file descriptor already open on its
# parent (`os.open(name, O_DIRECTORY | O_NOFOLLOW, dir_fd=parent_fd)`).
# O_NOFOLLOW on a relative open is not a check-then-use race: the kernel
# resolves that one path component and either hands back a descriptor on a
# real directory or fails outright (ELOOP) in the same call. There is no
# window between "looks like a directory" and "opened as one" for a rename
# to land in, at any hop, because no hop is ever re-opened by a path string
# a second time. The final write, rename or unlink all happen relative to
# that same descriptor too (`dir_fd=`), never by joining it back into a path.
#
# What the per-hop OWNER check adds, and does not: it does NOT stop the
# dashboard account from swapping its OWN directory's entry -- nothing can,
# short of moving the directory out from under that account entirely, which
# is not possible for dashboard/config the way it was for TOKEN_DIR (#648,
# round 3), because the dashboard's own code has to find its config where it
# has always lived. The O_NOFOLLOW walk above is what actually closes that
# hole: a swapped entry is a symlink, and a symlink is refused at the instant
# it is opened, full stop, whoever owns the directory it sits in. The owner
# check is the SECOND, independent line of defence the header of
# ensure_token_dir already named for TOKEN_DIR's own parent, and it is held
# to TWO DIFFERENT RULES depending on what kind of anchor a call names,
# because they are not the same fact about this host:
#
#   $ETC, the systemd unit directory, /usr/local/sbin (trust_anchor_owner
#   False, extra-uid always ""): the anchor's own owner must ALREADY be in
#   allowed_uids -- root, or this process's own euid under the test harness
#   -- exactly the rule ensure_token_dir's pre-round-7 body held TOKEN_DIR's
#   parent to. Nothing but root has ever owned any of these on a real host,
#   so this is unchanged, not relaxed: an owner outside that set refuses the
#   whole call, the anchor included.
#
#   INSTALL_DIR (trust_anchor_owner True): the anchor's owner is instead
#   ADDED to allowed_uids once read, so every hop below it -- dashboard/,
#   dashboard/config, advisor/state -- may belong to root, to the anchor's
#   own real owner, or to the one extra account (extra-uid) that specific
#   call names. This is a deliberate DEVIATION from "an attacker-owned
#   component may be traversed only under a trusted parent", checked
#   directly on a live host rather than assumed: `stat` from / down to
#   dashboard/config and to advisor/state, and each service's own
#   `systemctl show -p User` (aperire-server: the operator's own login
#   account; aperire-advisord: a dedicated service account), showed
#   INSTALL_DIR and dashboard/config owned by the SAME account two hops
#   apart, with advisor/state under the SAME INSTALL_DIR owned by a
#   DIFFERENT one. A rule that required INSTALL_DIR's own owner to already
#   be in allowed_uids would refuse that first host outright -- the install
#   this program exists to serve, not an attacker -- so trust here extends
#   DOWN from a fact the root-owned conf already vouched for by naming this
#   path as INSTALL_DIR, never up from a value this call merely asked about.
#
# Neither rule stops the account that legitimately owns a hop from doing
# whatever that ownership already lets it do to entries directly inside it
# -- only the O_NOFOLLOW walk does that, by refusing a symlink outright
# regardless of who planted it. What the owner check catches, on either
# rule, is a THIRD account appearing anywhere in the chain: one the operator
# never granted anything, or a bug that pointed this program at the wrong
# subtree entirely.
#
# CALL SHAPE
#   dirsafe.py <anchor> <relpath> <extra-uid> <write-mask> <op> [op-args...]
#
#   anchor      Absolute path to a directory this host's OWN configuration
#               already names (INSTALL_DIR, $ETC, the systemd unit
#               directory, /usr/local/sbin's parent) -- trusted as a fact
#               about this host the same way $CONF's own INSTALL_DIR always
#               has been, not re-derived here. Its OWN ancestors are not
#               walked: for $ETC, the unit directory and /usr/local/sbin
#               they are root's on any host this ever runs on (see
#               ensure_token_dir's original header). For INSTALL_DIR they
#               are NOT, which round 9 proved with a working attack, so
#               that anchor carries a PIN instead -- see DS_ANCHOR_PIN
#               below and open_chain's own note. The anchor's own entry IS opened
#               O_NOFOLLOW: an anchor that has itself become a symlink is
#               refused rather than trusted from its name alone, the same
#               as every hop below it, and its type and mode are checked the
#               same way too. Its OWNER is checked one of two ways -- see
#               open_chain's own header for exactly which, and why they
#               differ.
#   relpath     "" (the leaf IS the anchor) or a POSIX-relative path
#               ("dashboard/config", "advisor/state", "fleet-tokens") from
#               the anchor down to the directory the operation acts inside.
#               No component may be empty, ".", or "..".
#   extra-uid   "" (only uid 0, or this process's own EUID under the test
#               harness, may own any hop -- and, for an INSTALL_DIR anchor
#               only, the anchor's own real owner too) or one decimal uid
#               additionally allowed to own EVERY hop from the anchor to the
#               leaf inclusive -- DASH_USER under dashboard/, the Advisor's
#               own account under advisor/, never both at once and never a
#               list: each call names the ONE account that subtree
#               legitimately belongs to. Whether a NON-EMPTY value here also
#               extends trust to the anchor's own real owner is exactly what
#               open_chain's trust_anchor_owner flag decides, derived from
#               this same value (never a list) rather than passed
#               separately.
#   write-mask  Octal mode bits that may not be set on ANY hop (root or the
#               extra account). "002" (no OTHER-write) for a subtree an
#               unprivileged account legitimately group-shares with itself;
#               "022" (no GROUP- or OTHER-write) for a subtree nothing but
#               root should ever be able to write into at all ($ETC, the
#               unit directory, /usr/local/sbin).
#   op          put | create | unlink | unlinkfile | read | ensuredir |
#               owner | identity -- see below.
#
# THE "create" OP is put that never replaces anything: the same arguments,
# the same temp file set up on its descriptor, but it lands with link(2),
# which fails when ANY entry already has the name (a file, a directory, a
# symlink, dangling or not) and never follows one. So a key a caller asked
# to make only when absent cannot overwrite one that appeared a moment
# earlier, and a planted link at the name is neither followed nor replaced.
# Exit 3 says the name was taken and nothing was written.
#
# THE "unlinkfile" OP is unlink that removes only a regular file (#854).
# "unlink" removes whatever has the name, which is right for putting back a
# name this program wrote. A revoke deleting a node's credentials is not
# that: a symlink or anything else found there is not what approve wrote,
# so it is refused (exit 2) and left exactly as it is, link and target
# both. The type is read with lstat on the leaf's own descriptor, never by
# path. Exit 3 says nothing had that name, which a caller counts as
# nothing to remove rather than a failure.
#
# THE "identity" OP answers "which directory is this", in the form
# DS_ANCHOR_PIN is compared against: the filesystem's own id (f_fsid,
# derived from its UUID on ext4, xfs and btrfs, so it survives a reboot)
# and the inode, or the device number and the inode where a filesystem
# reports no f_fsid. It prints which of the two rules it used, then the
# value. Nothing is read, written or removed. The grant installer calls
# it to record the pin, and the broker's own --rerecord-install-dir calls it
# with one argument, the <st_dev>:<st_ino> root read before an update's
# rename, to re-record the pin for exactly that directory (#828).
#
# THE "owner" OP IS THE ONE THAT DOES NOT CHECK OWNERSHIP, and that is the
# whole point of it: it exists because two callers have to LEARN which
# account owns dashboard/config on a host whose dashboard has no systemd
# unit (the pm2 case), and a `stat -c '%U'` on that path is ordinary,
# symlink-following path lookup -- the exact step every other op here
# exists to never take again. So it walks the same O_NOFOLLOW chain, with
# the same type and mode rules at every hop, and answers with the LEAF's
# own owner instead of holding it to an owner rule it is being asked to
# discover. Nothing is written, read or removed on this op. Whatever name
# it answers is then held to the caller's own rules (not root, not uid 0),
# and every later call that USES it as extra-uid gets the full owner check
# back.
#
# ONE ENVIRONMENT VARIABLE, AND ONLY ONE
#   DS_ANCHOR_PIN  "" or the "identity" op's own value for the directory the anchor
#               argument must actually BE. Set by the caller for an
#               INSTALL_DIR anchor and nothing else, from a value the
#               root-owned conf carries, because that is the one anchor
#               whose ancestors an unprivileged account can rename. An
#               anchor that opens to a different inode is refused (status
#               2) before a single hop below it is touched. It travels in
#               the environment rather than as a sixth positional argument
#               so every existing call site keeps its shape; the caller
#               decides per call whether the pin applies at all.
#
# EXIT CODES (every op)
#   0  ok
#   1  ordinary failure: absent (read), or an operational fault (a bad
#      owner/group name, a write error) -- never tampering.
#   2  refused: a symlink, wrong type, wrong owner, too-wide mode, or a
#      candidate too large to trust. Named apart from 1 so a caller that
#      wants to tell an operator "something is planted here" can.
#   3  identity only, with an expected <st_dev>:<st_ino>: the directory
#      opened is a different one (#828). create only: something already
#      has that name, and it was left exactly as it was.

MAX_TMP_ATTEMPTS = 64


def fail(code):
    sys.exit(code)


def resolve_id(value, table_lookup):
    try:
        return int(value)
    except ValueError:
        return table_lookup(value)


def uid_of(value):
    return resolve_id(value, lambda name: pwd.getpwnam(name).pw_uid)


def gid_of(value):
    return resolve_id(value, lambda name: grp.getgrnam(name).gr_gid)


def dir_identity(fd):
    # WHICH DIRECTORY an open descriptor is, in a form that survives a
    # reboot (#648, round 9, the lead's ruling). st_ino alone is not
    # enough: inode numbers are only unique within one filesystem. st_dev
    # is not stable, because it is the device NUMBER, and nvme
    # enumeration, LVM/dm minors and btrfs anonymous devices can all hand
    # the same filesystem a different one after a reboot, which would
    # refuse a perfectly good install. f_fsid is derived from the
    # filesystem's own UUID on ext4, xfs and btrfs, so it is the same
    # number tomorrow.
    #
    # Where a filesystem reports no f_fsid at all (it is allowed to
    # report 0), this falls back to st_dev, and BOTH sides fall back
    # together because both ask this same function on the same
    # filesystem. The installer says out loud when it recorded a fallback,
    # because that is the one case a reboot can undo.
    st = os.fstat(fd)
    try:
        fsid = os.fstatvfs(fd).f_fsid
    except OSError:
        fsid = 0
    return "%d:%d" % (fsid or st.st_dev, st.st_ino), ("fsid" if fsid else "dev")


def check_leaf(name):
    # A leaf is ONE name inside the directory this call walked to, never a
    # path (#648, round 9). "" / "." / ".." were already refused; a name
    # carrying "/" was not, and every op below joins it to a directory fd,
    # where the kernel resolves the whole string -- "../../etc/x" from a
    # caller that could name a leaf would step straight back out of the
    # chain this walk exists to hold it inside. No current call site builds
    # a leaf from anything but basename() of a path this program itself
    # spelled; this is the rule that keeps the next one honest.
    if name in ("", ".", "..") or "/" in name:
        fail(2)


def split_components(relpath):
    if not relpath:
        return []
    parts = relpath.split("/")
    for p in parts:
        if p in ("", ".", ".."):
            fail(2)
    return parts


def check_hop(fd, allowed_uids, forbid_mask):
    st = os.fstat(fd)
    if not stat.S_ISDIR(st.st_mode):
        fail(2)
    # allowed_uids is None ONLY on the "owner" op, which is asking who owns
    # the leaf rather than asserting it: see the CALL SHAPE note above. The
    # symlink, type and mode rules still apply at every hop.
    if allowed_uids is not None and st.st_uid not in allowed_uids:
        fail(2)
    if stat.S_IMODE(st.st_mode) & forbid_mask:
        fail(2)


def open_chain(anchor, components, allowed_uids, forbid_mask, trust_anchor_owner):
    # The anchor itself: opened by path ONCE (its own ancestors are the
    # documented trust assumption above), and checked for type and mode
    # exactly like every hop after it. Its OWNER is checked two different
    # ways depending on what kind of anchor this call names:
    #
    # trust_anchor_owner is False for $ETC, the systemd unit directory and
    # /usr/local/sbin: nothing but root has ever owned any of those on a
    # real host, and ensure_token_dir's own pre-round-7 body already refused
    # an owner outside (0, want_uid) for TOKEN_DIR's parent for exactly this
    # reason (round 3 review, CRITICAL). That check is kept, structurally
    # unchanged, for every ETC-rooted write: the anchor's owner must be in
    # allowed_uids (root, or this process's own euid under the test
    # harness) or this call refuses, same as every hop below it.
    #
    # trust_anchor_owner is True ONLY for INSTALL_DIR, because dashboard/
    # and advisor/state sit inside a tree this program did not create and
    # does not own: the root-owned conf merely NAMES it. Checked directly on
    # this host (`stat` down from / to dashboard/config and to
    # advisor/state, and every install script's own chown lines):
    # INSTALL_DIR itself can be the operator's own login account, the same
    # account dashboard/config is owned by two hops down, while
    # advisor/state two hops down the SAME anchor is a dedicated service
    # account's. A rule that required INSTALL_DIR's own owner to already be
    # in allowed_uids (root or the ONE extra account this call names) would
    # refuse that first host outright -- the install this program exists to
    # serve, not an attacker. So here, and only here, the anchor's real
    # owner is ADDED to allowed_uids once read, extending trust down from a
    # fact the root-owned conf already vouched for by naming this path as
    # INSTALL_DIR, never up from a value this call merely asked about.
    if os.path.islink(anchor):
        fail(2)
    try:
        fd = os.open(anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError:
        fail(2)
    anchor_st = os.fstat(fd)
    # THE ANCHOR'S OWN ANCESTORS (#648, round 9). Everything from the anchor
    # DOWN is walked a component at a time with O_NOFOLLOW; the anchor
    # itself is still resolved by ordinary path lookup, once, and that lookup
    # walks its ancestors the ordinary way. The header below used to call
    # those ancestors root's on any host this runs on. For $ETC, the unit
    # directory and /usr/local/sbin that is true. For INSTALL_DIR it is not:
    # an install under /home/<operator>/aperire-one has ancestors the
    # operator's own account owns, and renaming ANY of them (`mv -T
    # projects decoy`) repoints the anchor at a different tree between one
    # dirsafe call and the next, with no symlink anywhere in the chain this
    # walk inspects. Reproduced end to end: root wrote a third account's
    # registry, as that account's own file, and reported success.
    #
    # So the caller that knows which directory the install really is pins
    # it: DS_ANCHOR_PIN carries "<st_dev>:<st_ino>", recorded by the grant
    # installer and read back from the root-owned conf, and the anchor this
    # call actually opened has to BE that directory (see dir_identity for
    # what that value is and why it is not the device number). An inode
    # cannot be renamed into place; a swapped ancestor lands on a
    # different one and refuses here. Empty means no pin was named for this anchor (the
    # $ETC-rooted calls, whose ancestors really are root's), and nothing
    # changes for those.
    pin = os.environ.get("DS_ANCHOR_PIN", "")
    if pin and dir_identity(fd)[0] != pin:
        os.close(fd)
        fail(2)
    if not stat.S_ISDIR(anchor_st.st_mode):
        os.close(fd)
        fail(2)
    if stat.S_IMODE(anchor_st.st_mode) & forbid_mask:
        os.close(fd)
        fail(2)
    if allowed_uids is not None:
        allowed_uids = set(allowed_uids)
        if trust_anchor_owner:
            allowed_uids.add(anchor_st.st_uid)
        elif anchor_st.st_uid not in allowed_uids:
            os.close(fd)
            fail(2)
    for name in components:
        try:
            lst = os.stat(name, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            os.close(fd)
            fail(1)
        except OSError:
            os.close(fd)
            fail(2)
        if stat.S_ISLNK(lst.st_mode):
            os.close(fd)
            fail(2)
        try:
            nfd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
        except OSError:
            os.close(fd)
            fail(2)
        os.close(fd)
        fd = nfd
        check_hop(fd, allowed_uids, forbid_mask)
    return fd


def op_put(leaf_fd, args):
    owner, group, mode, src, leafname = args
    check_leaf(leafname)
    # A target that already exists as something other than a plain file is
    # tampering to name, never a state this silently renames over -- the
    # same refusal place() has always made on the final component, now made
    # relative to the held descriptor rather than by re-resolving a path.
    try:
        lst = os.stat(leafname, dir_fd=leaf_fd, follow_symlinks=False)
        if not stat.S_ISREG(lst.st_mode):
            fail(2)
    except FileNotFoundError:
        pass
    except OSError:
        fail(2)

    if src == "-":
        data = sys.stdin.buffer.read()
    else:
        with open(src, "rb") as f:
            data = f.read()

    try:
        uid = uid_of(owner)
        gid = gid_of(group)
        mode_bits = int(mode, 8)
    except (KeyError, ValueError):
        fail(1)

    tmp_fd = None
    tmp_name = None
    for _ in range(MAX_TMP_ATTEMPTS):
        candidate = ".dirsafe." + os.urandom(9).hex()
        try:
            tmp_fd = os.open(
                candidate,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=leaf_fd,
            )
            tmp_name = candidate
            break
        except FileExistsError:
            continue
        except OSError:
            fail(1)
    if tmp_fd is None:
        fail(1)

    try:
        os.write(tmp_fd, data)
        os.fchown(tmp_fd, uid, gid)
        os.fchmod(tmp_fd, mode_bits)
    except OSError:
        os.close(tmp_fd)
        try:
            os.unlink(tmp_name, dir_fd=leaf_fd)
        except OSError:
            pass
        fail(1)

    # tmp_fd stays OPEN across the rename: the verification just below reads
    # it back by descriptor, which a name-level swap cannot touch.
    try:
        os.rename(tmp_name, leafname, src_dir_fd=leaf_fd, dst_dir_fd=leaf_fd)
    except OSError:
        os.close(tmp_fd)
        try:
            os.unlink(tmp_name, dir_fd=leaf_fd)
        except OSError:
            pass
        fail(1)

    # rename(2) is name-based, like every rename ever is: if the account
    # that owns this directory replaced tmp_name's own directory entry with
    # something else in the window between this process creating it
    # (O_CREAT|O_EXCL|O_NOFOLLOW, so nothing could have been there before
    # that instant) and the rename call just above, that rename moved
    # WHATEVER now sat at tmp_name -- not necessarily the file this process
    # wrote, chowned and chmoded on tmp_fd -- onto leafname. There is no
    # atomic compare-and-rename in POSIX, so this is checked as soon as
    # physically possible AFTER the rename, never before: a pre-rename check
    # here would leave the identical gap between the check and the rename
    # call itself, proving nothing. A mismatched (device, inode) means the
    # account that owns this directory won that race, and root's own rename
    # just placed a name of ITS OWN choosing onto leafname rather than the
    # content this process actually wrote. Refused after the fact, and the
    # name it landed is removed rather than left live: leafname was never
    # going to keep its PRIOR content past this rename either way (rename's
    # own semantics already replaced whatever was there), so an account's
    # own symlink sitting at the live path it already owned the directory of
    # is a worse state for a reader to find than leafname being absent.
    try:
        landed = os.stat(leafname, dir_fd=leaf_fd, follow_symlinks=False)
        mine = os.fstat(tmp_fd)
    except OSError:
        os.close(tmp_fd)
        fail(2)
    if (landed.st_dev, landed.st_ino) != (mine.st_dev, mine.st_ino):
        try:
            os.unlink(leafname, dir_fd=leaf_fd)
        except OSError:
            pass
        os.close(tmp_fd)
        fail(2)
    os.close(tmp_fd)


def op_create(leaf_fd, args):
    owner, group, mode, src, leafname = args
    check_leaf(leafname)
    try:
        os.stat(leafname, dir_fd=leaf_fd, follow_symlinks=False)
        fail(3)
    except FileNotFoundError:
        pass
    except OSError:
        fail(2)

    if src == "-":
        data = sys.stdin.buffer.read()
    else:
        with open(src, "rb") as f:
            data = f.read()

    try:
        uid = uid_of(owner)
        gid = gid_of(group)
        mode_bits = int(mode, 8)
    except (KeyError, ValueError):
        fail(1)

    tmp_fd = None
    tmp_name = None
    for _ in range(MAX_TMP_ATTEMPTS):
        candidate = ".dirsafe." + os.urandom(9).hex()
        try:
            tmp_fd = os.open(
                candidate,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=leaf_fd,
            )
            tmp_name = candidate
            break
        except FileExistsError:
            continue
        except OSError:
            fail(1)
    if tmp_fd is None:
        fail(1)

    def drop_tmp():
        try:
            os.unlink(tmp_name, dir_fd=leaf_fd)
        except OSError:
            pass

    try:
        os.write(tmp_fd, data)
        os.fchown(tmp_fd, uid, gid)
        os.fchmod(tmp_fd, mode_bits)
    except OSError:
        os.close(tmp_fd)
        drop_tmp()
        fail(1)

    # link(2), not rename(2): it refuses an existing name of any kind, a
    # symlink included, and follows neither side. follow_symlinks=False
    # asks for linkat without AT_SYMLINK_FOLLOW, so even the source name is
    # never resolved through a link.
    try:
        os.link(tmp_name, leafname, src_dir_fd=leaf_fd, dst_dir_fd=leaf_fd,
                follow_symlinks=False)
    except FileExistsError:
        os.close(tmp_fd)
        drop_tmp()
        fail(3)
    except OSError:
        os.close(tmp_fd)
        drop_tmp()
        fail(1)

    # The same after-the-fact check put makes, for the same reason: link(2)
    # is name-based on its source, so an account that owns this directory
    # could have swapped tmp_name's entry between the create and the link.
    # If what landed is not the inode set up above, the name this call just
    # made is taken back out, and nothing it did not write is left behind
    # under the caller's name.
    try:
        landed = os.stat(leafname, dir_fd=leaf_fd, follow_symlinks=False)
        mine = os.fstat(tmp_fd)
    except OSError:
        os.close(tmp_fd)
        drop_tmp()
        fail(2)
    drop_tmp()
    if (landed.st_dev, landed.st_ino) != (mine.st_dev, mine.st_ino):
        try:
            os.unlink(leafname, dir_fd=leaf_fd)
        except OSError:
            pass
        os.close(tmp_fd)
        fail(2)
    os.close(tmp_fd)


def op_unlink(leaf_fd, args):
    (leafname,) = args
    check_leaf(leafname)
    try:
        os.unlink(leafname, dir_fd=leaf_fd)
    except FileNotFoundError:
        pass
    except OSError:
        fail(1)


def op_unlinkfile(leaf_fd, args):
    (leafname,) = args
    check_leaf(leafname)
    try:
        st = os.stat(leafname, dir_fd=leaf_fd, follow_symlinks=False)
    except FileNotFoundError:
        fail(3)
    except OSError:
        fail(1)
    if not stat.S_ISREG(st.st_mode):
        fail(2)
    try:
        os.unlink(leafname, dir_fd=leaf_fd)
    except FileNotFoundError:
        fail(3)
    except OSError:
        fail(1)


def op_read(leaf_fd, args):
    leafname, out, max_bytes_s = args
    check_leaf(leafname)
    max_bytes = int(max_bytes_s)
    try:
        fd = os.open(leafname, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=leaf_fd)
    except FileNotFoundError:
        fail(1)
    except OSError:
        fail(2)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            fail(2)
        try:
            data = os.read(fd, max_bytes + 1)
        except OSError:
            fail(2)
        if len(data) > max_bytes:
            fail(2)
    finally:
        os.close(fd)
    # The snapshot is written with the SOURCE's own owner and mode, not
    # whatever this process's umask would otherwise leave it at: backup_of's
    # "self" restore spec reads a file's true owner and mode back off this
    # exact snapshot (NODES_CONF and ADVISOR_TOKEN_PATH both live under a
    # directory only root can write to, so there has never been a race in
    # reading it from the live file, only in how the COPY was made). A
    # snapshot that came out world-readable at 0644 because open()'s own
    # default mode said so would have restore_all() putting a token file
    # back wider than this program has ever written one.
    out_fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(out_fd, data)
        try:
            os.fchown(out_fd, st.st_uid, st.st_gid)
        except OSError:
            # The test harness, and only that: chowning to an owner other
            # than this process's own euid needs privilege this run does not
            # have. A real root run always owns whatever it just read.
            pass
        os.fchmod(out_fd, stat.S_IMODE(st.st_mode))
    finally:
        os.close(out_fd)


def op_ensuredir(leaf_fd, args):
    leafname, owner, group, mode = args
    check_leaf(leafname)
    try:
        uid = uid_of(owner)
        gid = gid_of(group)
        mode_bits = int(mode, 8)
    except (KeyError, ValueError):
        fail(1)

    # mkdir first, exactly as ensure_token_dir's own pre-round-7 body did:
    # FileExistsError covers a directory, a file, OR a symlink already
    # sitting at this name, and every one of those three is told apart by
    # the lstat right after, never by mkdir's own errno.
    created = False
    try:
        os.mkdir(leafname, mode_bits, dir_fd=leaf_fd)
        created = True
    except FileExistsError:
        pass
    except OSError:
        fail(1)

    try:
        lst = os.stat(leafname, dir_fd=leaf_fd, follow_symlinks=False)
    except OSError:
        fail(1)
    if stat.S_ISLNK(lst.st_mode):
        # Planted in the instant between the mkdir attempt and this check,
        # or simply already there: refused, never opened.
        fail(2)

    try:
        fd = os.open(leafname, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=leaf_fd)
    except OSError:
        fail(2)
    try:
        st = os.fstat(fd)
        # Checked against the EXACT owner this call names, on both branches,
        # never against the wider "root, the anchor's own owner, or the
        # subtree's account" set open_chain's own walk uses above this leaf:
        # a directory this call just created belongs to whoever ran this
        # process (mkdir does not take an owner), so a fresh directory owned
        # by anyone OTHER than the uid this call names is refused here
        # exactly as an already-existing one owned by the wrong account
        # would be. This is what lets a single-account test rig prove the
        # ownership check at all: asked to ensure a directory for a uid that
        # is not this process's own, the fresh mkdir above still succeeds
        # (mkdir does not check who a directory is FOR), and this is the
        # line that catches it -- removing what it just made rather than
        # leaving a directory nobody asked for behind, since a directory
        # this call created a moment ago and immediately refused is not a
        # state to leave on disk for the next reader to puzzle over.
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != uid:
            if created:
                try:
                    os.rmdir(leafname, dir_fd=leaf_fd)
                except OSError:
                    pass
            fail(1)
        if created:
            # A real root run (uid == 0) sets the owner and group
            # explicitly; the test-harness run (uid == this process's own
            # euid, the only uid a fresh mkdir could have produced here)
            # needs neither.
            if uid == 0:
                os.fchown(fd, uid, gid)
            os.fchmod(fd, mode_bits)
        elif stat.S_IMODE(st.st_mode) & ~mode_bits:
            # Already existed, and wider than this call has ever set:
            # refused, never silently narrowed. A directory somebody else
            # opened up is a fact for an operator to look at, not one for
            # this call to paper over.
            fail(1)
        else:
            # Already existed, no wider than this call sets it, so it may be
            # NARROWER: reapplied to exactly the mode this call names. That
            # repair is why /run/aperire's own creation could be a plain
            # `install -d` for so long (#171): another unit may make that
            # directory first, under its own umask or its own
            # RuntimeDirectoryMode, and a 0700 /run/aperire is one the
            # dashboard account cannot traverse to reach its own socket.
            # `install -d` reapplied the mode on an existing directory too,
            # so this op has to, or routing that line through here would
            # have traded a symlink-follow for a socket nobody can open.
            # The group is asserted on the same branch, as before, in case
            # this directory predates a group change.
            os.fchmod(fd, mode_bits)
            if uid == 0:
                os.fchown(fd, 0, gid)
    finally:
        os.close(fd)


def op_identity(leaf_fd, args):
    if len(args) > 1:
        fail(2)
    if args:
        # #828: "and is it the directory root read before a rename moved it
        # here?" The expected value is "<st_dev>:<st_ino>", the way
        # `stat -c '%d:%i'` prints it, and it is compared against fstat on
        # THIS descriptor. So the id printed below belongs to the directory
        # that matched, never to a path looked up a second time. A different
        # directory exits 3.
        try:
            want_dev, want_ino = (int(x) for x in args[0].split(":"))
        except ValueError:
            fail(2)
        st = os.fstat(leaf_fd)
        if (st.st_dev, st.st_ino) != (want_dev, want_ino):
            fail(3)
    ident, source = dir_identity(leaf_fd)
    # Two fields: the word says WHICH rule produced the value, so the
    # installer can tell an operator that it fell back. Only the value is
    # ever written into the conf.
    # With the newline: the caller reads this with `read`, which returns
    # non-zero on a last line that has none, however much it assigned.
    sys.stdout.write("%s %s\n" % (source, ident))


def op_owner(leaf_fd, args):
    if args:
        fail(2)
    st = os.fstat(leaf_fd)
    try:
        name = pwd.getpwuid(st.st_uid).pw_name
    except KeyError:
        # A uid with no account behind it is not a name any caller can hand
        # to chown, runuser or id, so it is an ordinary failure to report
        # rather than a number to print and let a caller misread later.
        fail(1)
    sys.stdout.write(name)


def main(argv):
    anchor, relpath, extra_uid, write_mask, op = argv[1:6]
    op_args = argv[6:]

    allowed_uids = {0}
    euid = os.geteuid()
    if euid != 0:
        allowed_uids.add(euid)
    if extra_uid:
        allowed_uids.add(int(extra_uid))
    forbid_mask = int(write_mask, 8)

    if op == "ensuredir":
        # The parent this directory is created under is walked the same way
        # every other op walks its own chain (open_chain trusts the ANCHOR's
        # real owner, root, and extra-uid at every hop -- see open_chain's
        # own header). What ensure_token_dir's pre-round-7 body held to a
        # single exact "(0, want_uid)" is now op_ensuredir's own job: it
        # checks the LEAF it just created or found against the EXACT owner
        # this call names, never the wider set the chain walk uses, and
        # removes a freshly-created directory again rather than leaving a
        # mismatched one behind (see op_ensuredir's own header).
        components = split_components(relpath)
        leaf_fd = open_chain(anchor, components, allowed_uids, forbid_mask, bool(extra_uid))
        try:
            op_ensuredir(leaf_fd, op_args)
        finally:
            os.close(leaf_fd)
        return

    if op == "identity":
        # Asked before any pin exists, so no owner rule and no pin: this
        # is the call that PRODUCES the value every later call is held
        # to. Reads nothing, writes nothing.
        components = split_components(relpath)
        leaf_fd = open_chain(anchor, components, None, forbid_mask, False)
        try:
            op_identity(leaf_fd, op_args)
        finally:
            os.close(leaf_fd)
        return

    if op == "owner":
        # The one op that asks rather than asserts: allowed_uids None means
        # no hop is held to an owner rule, because the answer IS an owner
        # this caller does not know yet (see the CALL SHAPE note). Every
        # other rule -- no symlink at any hop, a real directory at every
        # hop, no hop wider than the mask -- is exactly as it is everywhere
        # else, which is the whole reason this is not a `stat` in the shell.
        components = split_components(relpath)
        leaf_fd = open_chain(anchor, components, None, forbid_mask, False)
        try:
            op_owner(leaf_fd, op_args)
        finally:
            os.close(leaf_fd)
        return

    components = split_components(relpath)
    leaf_fd = open_chain(anchor, components, allowed_uids, forbid_mask, bool(extra_uid))
    try:
        if op == "put":
            op_put(leaf_fd, op_args)
        elif op == "create":
            op_create(leaf_fd, op_args)
        elif op == "unlink":
            op_unlink(leaf_fd, op_args)
        elif op == "unlinkfile":
            op_unlinkfile(leaf_fd, op_args)
        elif op == "read":
            op_read(leaf_fd, op_args)
        else:
            fail(2)
    finally:
        os.close(leaf_fd)


main(sys.argv)
DIRSAFE_PY_EOF
# --- DIRSAFE-PY-END ---
# The same per-call pin the broker carries (#648, round 9): set for an
# INSTALL_DIR anchor and nothing else, by string comparison against the
# variable this program resolved itself, never by asking the filesystem
# what a path means. $INSTALL_DIR_ID is empty until the install directory
# is read below, which is before any INSTALL_DIR-anchored call.
INSTALL_DIR_ID=""
dirsafe() {
  local pin=""
  [[ -n "${INSTALL_DIR:-}" && "${1:-}" == "${INSTALL_DIR:-}" ]] && pin="${INSTALL_DIR_ID:-}"
  DS_ANCHOR_PIN="$pin" python3 -I "$GRANT_WORK/dirsafe.py" "$@"
}

REMOVE=0
REFRESH_NODES=0
# #851: the one way to make a fleet key on a host that already has paired
# nodes. Root's argv only: the broker's socket has no field that does this.
NEW_FLEET_KEYS=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --remove) REMOVE=1; shift ;;
    --refresh-nodes) REFRESH_NODES=1; shift ;;
    --new-fleet-keys) NEW_FLEET_KEYS=1; shift ;;
    -h|--help) awk '/^[^#]/{exit} NR>1{sub(/^# ?/,""); print}' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
if (( NEW_FLEET_KEYS == 1 && ( REMOVE == 1 || REFRESH_NODES == 1 ) )); then
  echo "--new-fleet-keys goes with the full install only, not with --remove or --refresh-nodes" >&2
  exit 2
fi

say()  { printf '   %s\n' "$*"; }
die()  { printf 'error: %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "run with sudo: this installs a program as root and two systemd units"

# --refresh-nodes maintains a grant; it does not install one (#825). On a
# host with no socket unit, no installed program or no conf it used to write
# fleet-nodes.conf and exit 0, so a restore's next step reported success
# and every pairing approval still failed with no socket to reach. Refused
# by name instead, before anything is read or written, naming both commands
# in order: the full install does not write fleet-nodes.conf, so the
# refresh is still a run of its own after it.
grant_missing_parts() {
  local m=()
  [[ -f "$UNIT_DIR/$SOCKET_UNIT" ]] || m+=("$UNIT_DIR/$SOCKET_UNIT")
  [[ -e "$DEST" ]] || m+=("$DEST")
  [[ -f "$CONF" ]] || m+=("$CONF")
  printf '%s\n' "${m[@]}"
}
if (( REFRESH_NODES == 1 && REMOVE == 0 )); then
  GRANT_MISSING="$(grant_missing_parts)"
  if [[ -n "$GRANT_MISSING" ]]; then
    {
      printf 'error: this host has no fleet broker grant installed, so --refresh-nodes has nothing to refresh. Nothing was written.\n'
      printf '  missing:\n'
      while IFS= read -r _m; do printf '    %s\n' "$_m"; done <<<"$GRANT_MISSING"
      printf '  Install the grant, then build root'"'"'s node record:\n'
      printf '    curl -fsSL https://get.aperire.one | bash -s -- --dir %s --run fleet-broker-grant\n' "$REPO"
      printf '    curl -fsSL https://get.aperire.one | bash -s -- --dir %s --run fleet-broker-grant --refresh-nodes\n' "$REPO"
    } >&2
    exit 3
  fi
fi

if [[ $REMOVE -eq 1 ]]; then
  systemctl disable --now "$SOCKET_UNIT" >/dev/null 2>&1 || true
  # dirsafe's own "unlink", not a bare `rm -f` on three paths built by
  # string (#648, round 8). `unlink` never follows a symlink at the final
  # component, so this was never the bug `install -d` was; what it did do
  # was resolve the DIRECTORY those three names sit in by ordinary path
  # lookup, which is the one step this program's own primitive exists to be
  # the only place that happens. Every root write, rename and removal in
  # this file now walks its own chain, with no exception left for a reader
  # to copy.
  dirsafe "$UNIT_DIR" "" "" 022 unlink "$SOCKET_UNIT" \
    || die "could not remove $UNIT_DIR/$SOCKET_UNIT"
  dirsafe "$UNIT_DIR" "" "" 022 unlink "$SERVICE_UNIT" \
    || die "could not remove $UNIT_DIR/$SERVICE_UNIT"
  dirsafe "$(dirname -- "$DEST")" "" "" 002 unlink "$(basename -- "$DEST")" \
    || die "could not remove $DEST"
  dirsafe "$(dirname -- "$ARM_DEST")" "" "" 002 unlink "$(basename -- "$ARM_DEST")" \
    || die "could not remove $ARM_DEST"
  systemctl daemon-reload >/dev/null 2>&1 || true
  say "removed $UNIT_DIR/$SOCKET_UNIT and $UNIT_DIR/$SERVICE_UNIT"
  say "removed $DEST and $ARM_DEST"
  say "left in place: $CONF, and every node already registered."
  # And the fleet model store, named with its form (#711). It is left for the
  # same reason the registry is, but it is every node's provider key, and on a
  # host with no systemd-creds it is that key in the clear, so it is said out
  # loud rather than left to be found.
  for _fm in "$ETC/fleet-model.cred" "$ETC/fleet-model.cred.plain"; do
    [[ -e "$_fm" || -L "$_fm" ]] || continue
    if [[ "$_fm" == *.plain ]]; then
      say "left in place: $_fm, the fleet model with its key in the clear (root only)."
    else
      say "left in place: $_fm, the fleet model, sealed to this machine."
    fi
    say "  if this host is done being an aggregator: sudo rm -f $_fm"
  done
  say "the page can no longer register a node. The operator still can:"
  say "  bash $REPO/scripts/aperire-fleet-add.sh --help"
  exit 0
fi

[[ -f "$SRC" ]] || die "no broker at $SRC; this tree is incomplete"
[[ -f "$ARM_SRC" ]] || die "no aperire-fleet-arm.sh at $ARM_SRC; this tree is incomplete"
command -v systemctl >/dev/null || die "systemctl not found, and the grant is a socket unit"
command -v python3 >/dev/null || die "python3 not found, and the broker reads back every registry it writes with it"
python3 -I -c 'import yaml' 2>/dev/null || die "python3 has no yaml module (apt install python3-yaml), and fleet.yaml is yaml"

# The account the dashboard runs as, from its own unit. Not $SUDO_USER: on a
# host where one operator installs and the service runs as another, the grant
# has to follow the service.
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

# --- ADVISOR-ACCOUNT-BEGIN ---
# advisor_unit_account <unit-dir>: the account the Advisor runs as, read from
# EXACTLY aperire-advisord.service and its own drop-ins, never a glob (#809).
# A glob over "aperire-advisord*.service" also matches
# aperire-advisord-credcheck.service, the Advisor's OnFailure= handler
# (#541), which runs User=root by design and sorts first ('-' before '.'),
# so a first-match reader saw root on every host with an Advisor.
#
# Inlined, never sourced. aperire-fleet-broker.sh is installed to
# /usr/local/sbin as one file and can read nothing beside it, and
# install-fleet-broker-grant.sh has to decide exactly what the broker will.
# So the text between these markers is the same in both files, and
# scripts/test-fleet-trust-perms.sh fails if they drift, then runs the same
# unit files through this and scripts/advisor-owner-lib.sh and wants the
# same answers. It reads the unit the way that library does without
# systemctl: the unit, then each drop-in in name order (a symlinked one
# too), the last User= under [Service] winning, indentation, spaces around
# '=' and one pair of quotes ignored. Three answers: the account; root when
# the unit says root, 0 or an empty User=; nothing when there is no such
# unit. And one refusal, exit 3 with nothing printed: the unit is there but
# names no User= this can read, cannot be read, or reads as root beside the
# .before-account marker install-advisor-account.sh leaves on a moved host.
# Each of those used to print root, which put the token files on the
# dashboard's own group with no word said.
advisor_unit_account() {
  local unit="$1/aperire-advisord.service" f line name value section user="" seen=0
  local -a files=()
  [[ -e "$unit" || -L "$unit" ]] || return 0
  [[ -r "$unit" ]] || return 3
  files=("$unit")
  if [[ -d "$unit.d" ]]; then
    while IFS= read -r -d '' f; do files+=("$f"); done \
      < <(find "$unit.d" -maxdepth 1 -xtype f -name '*.conf' -print0 | sort -z)
  fi
  for f in "${files[@]}"; do
    section=""
    while IFS= read -r line || [[ -n "$line" ]]; do
      line="${line%$'\r'}"
      line="${line#"${line%%[![:space:]]*}"}"
      [[ -n "$line" && "$line" != '#'* && "$line" != ';'* ]] || continue
      if [[ "$line" == '['*']' ]]; then section="$line"; continue; fi
      [[ "$section" == '[Service]' && "$line" == *=* ]] || continue
      name="${line%%=*}"; name="${name%"${name##*[![:space:]]}"}"
      [[ "$name" == User ]] || continue
      value="${line#*=}"
      value="${value#"${value%%[![:space:]]*}"}"
      value="${value%"${value##*[![:space:]]}"}"
      if [[ ${#value} -ge 2 && ( ( "$value" == '"'*'"' ) || ( "$value" == "'"*"'" ) ) ]]; then
        value="${value:1:${#value}-2}"
      fi
      user="$value"; seen=1
    done < "$f"
  done
  (( seen )) || return 3
  [[ -n "$user" && "$user" != 0 ]] || user=root
  [[ "$user" != root || ! -e "$unit.before-account" ]] || return 3
  printf '%s' "$user"
}
# --- ADVISOR-ACCOUNT-END ---

# The advisord account, resolved HERE rather than beside the shared-group
# check at the end: the install-directory guard just below needs it, and
# deriving the same fact twice in one program is how the two derivations
# come apart later. Read exactly the way the broker reads it, from the same
# inlined block, because the shared-group check below exists to predict the
# broker's own answer (#809). An Advisor running as root has no second
# account to share a group with, and is treated the way the broker treats
# it: as no separate account at all.
ADV_USER="$(advisor_unit_account "$UNIT_DIR")" \
  || die "could not read which account the Advisor runs as from $UNIT_DIR/aperire-advisord.service: it names no User= under [Service] (there or in its drop-ins), cannot be read, or reads as root beside the .before-account marker a moved Advisor leaves. The broker refuses the same unit by name (advisor_account_unread), so nothing was installed. Check it with: systemctl cat aperire-advisord"
[[ "$ADV_USER" != root ]] || ADV_USER=""

# The install tree, resolved here and written into the conf, because the
# broker must not take it from a payload.
INSTALL_DIR="${APERIRE_DIR:-$REPO}"
[[ -d "$INSTALL_DIR/dashboard/config" ]] \
  || die "$INSTALL_DIR does not look like an Aperire install (no dashboard/config in it)"
# WHICH DIRECTORY that is, not just what it is called (#648, round 9). The
# broker resolves INSTALL_DIR by path on every connection, and an account
# that can rename any ancestor of it points that path at a tree of its own
# choosing between one write and the next, with no symlink in the part of
# the chain the broker's own walk inspects. An inode cannot be renamed
# into place, so which directory this IS gets recorded here, in the
# root-owned conf, and the broker refuses an anchor that opens to anything
# else. Re-running this installer is what re-records it, which is also the
# answer after a genuine move of the install.
#
# Read through dirsafe's own "identity" op rather than `stat` here, so the
# rule that produces this value and the rule the broker checks it against
# are the same code: the filesystem's own id (from its UUID on ext4, xfs
# and btrfs, so a reboot cannot change it) and the inode. Where a
# filesystem reports no id of its own, both sides fall back to the device
# number together, and this says so, because that is the one case a
# reboot can undo.
ID_SOURCE=""
read -r ID_SOURCE INSTALL_DIR_ID < <(dirsafe "$INSTALL_DIR" "" "" 002 identity) || true
[[ "$INSTALL_DIR_ID" =~ ^[0-9]+:[0-9]+$ && "$ID_SOURCE" =~ ^(fsid|dev)$ ]] \
  || die "could not read which directory $INSTALL_DIR is"
say_install_id_note() {  # source-word -> the caveat, only where there is one
  [[ "$1" != fsid ]] || return 0
  say ""
  say "NOTE: this filesystem reports no id of its own, so which directory the install is"
  say "      has been recorded by device number instead. A reboot that renumbers the disk"
  say "      changes that number, and the broker then refuses every approval until this"
  say "      installer is run again. Nothing is written anywhere else in the meantime."
  say ""
}
say_install_id_note "$ID_SOURCE"
# And the warning that says why the pin is needed at all: an ancestor any
# non-root account can write is an ancestor that account can rename. The
# pin turns that from a silent redirect into a refusal, which is a broker
# that stops working rather than one that writes somewhere else, so the
# operator hears about it here instead.
writable_ancestors() {  # dir -> one line per ancestor a non-root account can write
  local dir="$1" up uid mode
  while :; do
    if read -r uid mode < <(stat -c '%u %a' "$dir" 2>/dev/null); then
      # Owned by someone other than root, or group- or other-writable:
      # each of those is a rename of this directory's own entries by an
      # account that is not root.
      if [[ "$uid" != 0 ]] || (( 8#"$mode" & 8#22 )); then
        printf '%s (uid %s, mode %s)\n' "$dir" "$uid" "$mode"
      fi
    fi
    up="$(dirname -- "$dir")"
    [[ "$up" != "$dir" ]] || break
    dir="$up"
  done
}
INSTALL_ANCESTORS="$(writable_ancestors "$(dirname -- "$INSTALL_DIR")")"
if [[ -n "$INSTALL_ANCESTORS" ]]; then
  say ""
  say "NOTE: these directories above $INSTALL_DIR are writable by an account that is not root:"
  while IFS= read -r _line; do say "  $_line"; done <<<"$INSTALL_ANCESTORS"
  say "Whoever can write one of those can rename the install out from under the broker. The"
  say "broker refuses rather than following it: it compares the directory it opens against the"
  say "one recorded here, so a rename stops every approval until this installer is run again."
  say ""
fi
# The registry --refresh-nodes reads, named once. It was written out in the
# python call below and spelled $FLEET_YAML in the summary, where nothing set
# it: under `set -u` a fleet.yaml with one malformed row killed the run at
# the line that was about to say which rows those were, after the record had
# already been written.
FLEET_YAML="$INSTALL_DIR/dashboard/config/fleet.yaml"
FLEET_LINKS="$INSTALL_DIR/dashboard/config/fleet-links.json"
# The directory an approval writes a node's read token into, spelled the same
# way the broker spells it: $ETC/fleet-tokens, never under advisor/state.
# That directory's own parent belongs to the unprivileged advisord account,
# and root:group 0750 on the directory itself never stopped that account
# renaming or symlink-swapping the directory's OWN entry, which is a
# permission of $ADV_STATE, not of fleet-tokens (round 3 review, CRITICAL).
# This is what makes a row's token_path "the convention one" or "a path of
# its own" (#458), so a record built here and a push resolving it agree on
# which rows need a fifth field at all. There is no migration story (round 4:
# this project has not shipped, so there is no installed base to carry
# forward); this program only ever READS this path to decide that fifth
# field, and never writes to it at all.
TOKEN_DIR="$ETC/fleet-tokens"
# The same bound aperire-fleet-broker.sh's own snapshot_registry_file holds
# every registry read to.
REGISTRY_SNAP_MAX_BYTES=1048576

# ---- --refresh-nodes: root vouches for the registry as it stands ------
#
# A run of its own. The broker maintains fleet-nodes.conf from `approve` and
# `revoke` from now on, so this exists for the fleet that was paired before
# the file did, and for a fleet joined with aperire-fleet-add.sh.
#
# It is deliberately an explicit root act rather than the broker reading
# fleet.yaml when the conf is missing. fleet.yaml belongs to the dashboard
# account, and a broker that fell back to it would be a broker whose push
# destination the dashboard could name, which is the whole thing this file
# exists to prevent.
#
# A row with no expected_pubkey_node is SKIPPED and counted. The seal already
# refuses such a node by name (row_not_pinned), so writing it here would only
# move the refusal to the first push, and a push with nothing to compare is a
# push that must not carry a key.
if [[ $REFRESH_NODES -eq 1 ]]; then
  command -v python3 >/dev/null || die "python3 not found, and fleet.yaml is yaml"
  python3 -I -c 'import yaml' 2>/dev/null || die "python3 has no yaml module (apt install python3-yaml)"
  TMPN="$(mktemp)"
  SNAP_DIR="$(mktemp -d)"
  trap 'rm -f "$TMPN"; rm -rf "$SNAP_DIR" "$GRANT_WORK"' EXIT
  echo
  echo "== Where a push may send"

  # fleet.yaml and fleet-links.json sit in dashboard/config, a directory the
  # DASHBOARD account owns outright -- the same fact that made a plain
  # open() on either one two bugs at once for the broker itself
  # (aperire-fleet-broker.sh's own snapshot_registry_file, #648 round 4): a
  # FIFO planted at either name hangs whatever reads it until a writer
  # connects, and a symlink is followed, this run parsing whatever it points
  # at with root's own privilege. Round 4 gave this its own guard, but only
  # ever checked dashboard/config ITSELF as the one parent -- never whatever
  # sits above it. Round 7 (#648, review7-0.json) routes it through the
  # same dirsafe.py primitive the broker's own snapshot_registry_file now
  # uses, walking the whole chain from INSTALL_DIR: an account that owns
  # dashboard/ could still symlink-swap dashboard/config's own entry in ITS
  # parent, and a parent-only check would open straight through it.
  DASH_USER_UID="$(id -u "$DASH_USER" 2>/dev/null)" || DASH_USER_UID=""
  FLEET_YAML_SNAP=""
  SNAP_RC=0
  dirsafe "$INSTALL_DIR" dashboard/config "$DASH_USER_UID" 002 read "$(basename "$FLEET_YAML")" "$SNAP_DIR/fleet.yaml" "$REGISTRY_SNAP_MAX_BYTES" || SNAP_RC=$?
  case "$SNAP_RC" in
    0) FLEET_YAML_SNAP="$SNAP_DIR/fleet.yaml" ;;
    1) : ;; # genuinely absent: the COUNTS step below already treats this as no rows
    *) die "$FLEET_YAML is not a plain file this program will read, or could not be read without risking this run. Nothing was changed." ;;
  esac

  FLEET_LINKS_SNAP=""
  SNAP_RC=0
  dirsafe "$INSTALL_DIR" dashboard/config "$DASH_USER_UID" 002 read "$(basename "$FLEET_LINKS")" "$SNAP_DIR/fleet-links.json" "$REGISTRY_SNAP_MAX_BYTES" || SNAP_RC=$?
  case "$SNAP_RC" in
    0) FLEET_LINKS_SNAP="$SNAP_DIR/fleet-links.json" ;;
    1) : ;;
    *) die "$FLEET_LINKS is not a plain file this program will read, or could not be read without risking this run. Nothing was changed." ;;
  esac

  COUNTS="$(python3 -I - "$FLEET_YAML_SNAP" "$FLEET_LINKS_SNAP" "$TMPN" "$TOKEN_DIR" "$NODES_CONF" <<'PY'

import json, os, re, sys
from urllib.parse import urlparse
import yaml

fleet_path, links_path, out_path, token_dir, nodes_conf_path = sys.argv[1:6]
rows = []
if os.path.exists(fleet_path):
    with open(fleet_path) as f:
        doc = yaml.safe_load(f.read()) or {}
    rows = doc.get("fleet") or []

# #620 review (121): the pin this rewrites for a label that already has one
# is exactly the fact root_pin_disagrees exists to guard, so the operator
# who is about to bless that change with --refresh-nodes sees it named here
# first, on stderr so it never lands inside the counts this program parses
# back for its own summary.
old_pins = {}
if os.path.exists(nodes_conf_path):
    with open(nodes_conf_path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) >= 2:
                old_pins[parts[0]] = parts[1]

linked = set()
if os.path.exists(links_path):
    with open(links_path) as f:
        doc = json.load(f)
    linked = {r.get("label") for r in (doc.get("links") or []) if isinstance(r, dict)}

# THE SHAPES, because every value below comes out of files the DASHBOARD
# account owns (security review, finding F2). A label carrying a newline
# writes extra rows into root's own record, and root's record is the one
# thing that says where a provider key may be sent. Same two regexes the
# broker itself applies, on both writing and reading.
LABEL_RE = re.compile(r"^[a-z0-9-]{1,32}$")
NODE_KEY_RE = re.compile(r"^n[1-9A-HJ-NP-Za-km-z]{20,60}$")
# And the token path, which the broker applies again on the way out (#458).
# Absolute, no whitespace (the record is whitespace separated, so a path that
# could carry a space could carry a field of its own) and no `..`.
TOKEN_PATH_RE = re.compile(r"^/[A-Za-z0-9._/-]{1,512}$")


def token_field(label, raw):
    """The fifth field for this row, or "" for the convention path.

    None means the row carries no path this record will hold. The dashboard's
    own parser requires token_path, so a row without a usable one is a row
    the seal cannot read either, and root vouching for it would put the two
    readers back where #458 found them.
    """
    want = os.path.join(token_dir, label + ".token")
    if not raw:
        return None
    if raw == want:
        return ""
    if not TOKEN_PATH_RE.fullmatch(raw) or raw.endswith("/") or ".." in raw.split("/"):
        return None
    return raw


written = skipped_unpinned = skipped_self = skipped_bad = 0
lines = [
    "# Written by scripts/install-fleet-broker-grant.sh --refresh-nodes.",
    "# Maintained from here on by the fleet broker's approve and revoke.",
    "#",
    "# <label> <pubkey_node> <read_port> <advisor 0|1>",
]
for r in rows:
    if not isinstance(r, dict):
        continue
    label = str(r.get("label") or "")
    if not label:
        continue
    if not LABEL_RE.fullmatch(label):
        # Counted, not dropped in silence: a row an operator can see in
        # fleet.yaml and cannot find here is a row they will assume is here.
        skipped_bad += 1
        continue
    if r.get("role") == "aggregator":
        # This host. A `self` push goes to the local sealer and needs no row.
        skipped_self += 1
        continue
    pin = str(r.get("expected_pubkey_node") or "")
    port = urlparse(str(r.get("read_origin") or "")).port
    if not pin or not port:
        skipped_unpinned += 1
        continue
    if not NODE_KEY_RE.fullmatch(pin) or not (1 <= port <= 65535):
        skipped_bad += 1
        continue
    advisor = 1 if r.get("advisor_origin") else 0
    token = token_field(label, str(r.get("token_path") or ""))
    if token is None:
        skipped_bad += 1
        continue
    old_pin = old_pins.get(label)
    if old_pin and old_pin != pin:
        sys.stderr.write(f"{label}: pin changing {old_pin} -> {pin}\n")
    lines.append(f"{label} {pin} {port} {advisor}{' ' + token if token else ''}")
    written += 1

with open(out_path, "w") as f:
    f.write("\n".join(lines) + "\n")
print(f"{written} {skipped_unpinned} {skipped_self} {len(linked)} {skipped_bad}")
PY
)" || die "the node record could not be built"
  read -r N_WRITTEN N_UNPINNED N_SELF N_LINKED N_BAD <<<"$COUNTS"
  # dirsafe's own "put", the same discipline the broker's own
  # nodes_conf_write uses (#648 round 7): $ETC is root's own directory here
  # too, so the old "$NODES_CONF.new.$$" -> mktemp+mv shape was never
  # attacker-reachable, but one discipline everywhere is what stops the next
  # reader copying a different shape into a place it would matter.
  dirsafe "$ETC" "" "" 022 put root root 600 "$TMPN" "$(basename "$NODES_CONF")" \
    || die "could not write $NODES_CONF"
  rm -f "$TMPN"
  rm -rf "$SNAP_DIR"
  trap 'rm -rf "$GRANT_WORK"' EXIT
  say "$NODES_CONF  (root:root 0600)"
  say "$N_WRITTEN node(s) a push may send to"
  say "linked rows on this host: $N_LINKED"
  if [[ "$N_UNPINNED" != "0" || "$N_SELF" != "0" || "$N_BAD" != "0" ]]; then
    say "skipped: $N_UNPINNED unpinned, $N_SELF this host's own row, $N_BAD malformed"
  fi
  if [[ "$N_BAD" != "0" ]]; then
    say ""
    say "$N_BAD row(s) carried a label, node key, port or token path this"
    say "program will not write into root's record. Fix them in $FLEET_YAML"
    say "and run this again."
  fi
  say ""
  say "A row with no expected_pubkey_node is not here. Pin it in fleet.yaml and"
  say "run this again; a push compares that pin before it sends anything."

  # And the last word, because this verb is narrow and reads as broad (#443).
  # It writes the destinations file and nothing else. The program behind the
  # socket is the copy in /usr/local/sbin, which only the full install
  # replaces, and on 2026-09-17 this exact command was the morning's "refresh
  # the broker grant" on an aggregator whose installed copy was four days
  # older than its tree. The page sealed the fleet model that afternoon, the
  # broker answered unknown_verb to a verb it had never been built with, and
  # the aggregator's own sealed copy was never written.
  say ""
  if [[ ! -e "$DEST" ]]; then
    say "the broker program is not installed at $DEST, so nothing here can be"
    say "reached from the page yet. Install it:"
    say "  curl -fsSL https://get.aperire.one | bash -s -- --dir $REPO --run fleet-broker-grant"
  elif cmp -s "$SRC" "$DEST"; then
    say "the installed program $DEST is this tree's copy, byte for byte"
  else
    say "$DEST is NOT this tree's copy, and this verb did not replace it: only the"
    say "record above was written. The page will meet the installed program, verbs"
    say "and all. Refresh it with the full install, which is idempotent:"
    say "  curl -fsSL https://get.aperire.one | bash -s -- --dir $REPO --run fleet-broker-grant"
  fi
  exit 0
fi

# --- FLEET-KEYS-BEGIN ---
# ── the two keys a pairing fingerprint covers (pairing v2, lane B) ───────
#
# A node being paired asks for this aggregator's pairing fingerprint, which
# root prints with `sudo aperire-fleet-arm --fingerprint`. It covers two
# keys, and on a fresh aggregator neither existed until something made it:
#
#   the fleet trust key  private_key: in dashboard/config/fleet-trust.yaml.
#                        Before this, only aperire-fleet-add.sh (the manual
#                        path) ever wrote one, so a first aggregator paired
#                        through the page had no fingerprint to print.
#   the fleet arm key    /etc/aperire/fleet-arm.key, root:root 0600.
#
# This grant is what makes a host one that pairs nodes, so it makes both,
# and only when absent. Neither is ever rewritten: a rotated trust key
# breaks every paired node's peers.aggregator, and a rotated arm key breaks
# every node's arming. An update does not run this, so a host whose grant
# predates it is told to run the grant installer again (the Settings page's
# pairing check says so by name).
#
# And on a host that already has paired nodes, a missing key is not made at
# all without --new-fleet-keys (#851, ruled 2026-10-04). Those nodes trust
# the key that is gone, so a new one silently orphans every one of them, and
# the recovery is the backup set, which aperire-restore.sh refuses to place
# over a different key (its exit 9). So the run stops with exit 4 before it
# writes anything, naming the nodes, the restore command and the flag.
# --new-fleet-keys is the deliberate re-key: it makes only the key that is
# missing, never replaces one, and lists the nodes to pair again. "Paired"
# is fleet_paired_records' answer, the same text the broker's arm-key verb
# asks, and a record it cannot read safely counts as paired.
#
# What holds, exactly (#851 review L1). The records are not a floor: the
# dashboard account owns two of them and the socket's `revoke` prunes the
# third. So for the ARM key a second fact decides first: fleet-arm.made,
# which ensure_fleet_arm_key leaves beside every arm key, root's, and which
# nothing but root at a shell removes. A missing arm key beside it is lost,
# whatever the records say. That protects a host whose key was made, or seen,
# by this release; one whose key predates the marker and is already gone
# rests on the records alone. The TRUST key lives in the dashboard account's
# own directory, so for it this guards against mistakes only.
#
# The trust file sits in a directory the DASHBOARD account owns (#795, #796
# class), so root never touches it by a path: it is read with dirsafe's
# "read" (no link followed, no FIFO held open, bounded) and made with
# dirsafe's "create" (a temp set up on its own descriptor, then link(2),
# which fails on any name already there and follows none). Its owner, group
# and mode come from fleet-trust-perms.sh's ft_key_target: the dashboard
# account's own, 0600, so the Advisor's account never reads the key (#868).
# fleet-trust-split.sh then makes the public half the Advisor does read,
# with ft_target's group, and ft_check_file holds both to the same rule.
#
# The arm key is made by the SAME ensure_fleet_arm_key block the broker and
# aperire-fleet-arm carry (#723), taken from the checked copy of
# aperire-fleet-arm.sh this run already staged, so there is no third copy of
# it to drift.
#
# Every refusal about the keys is by name. The ones that need no write (a
# trust file or arm key name this program would refuse, two accounts that
# share no group, a fleet-trust-perms.sh that is not the release's) happen
# before this program writes anything at all. Making a key is itself a
# write, so it comes after every check and before either program is placed
# in /usr/local/sbin: a key that cannot be made leaves no program, no conf
# and no unit behind (#846 review, L2).
FLEET_TRUST_LEAF=fleet-trust.yaml
FLEET_TRUST_STATE=''
FLEET_TRUST_WHY=''
FLEET_TRUST_MADE=0

# classify_fleet_trust_file <install-dir> <dashboard-uid>
# Sets FLEET_TRUST_STATE to absent or kept and returns 0, or sets
# FLEET_TRUST_WHY and returns 1. Reads only.
classify_fleet_trust_file() {
  local dir="$1" uid="$2" snap="$GRANT_WORK/fleet-trust.snap" rc=0 path verdict
  path="$dir/dashboard/config/$FLEET_TRUST_LEAF"
  FLEET_TRUST_STATE='' FLEET_TRUST_WHY=''
  rm -f -- "$snap"
  dirsafe "$dir" dashboard/config "$uid" 002 read "$FLEET_TRUST_LEAF" "$snap" 65536 2>/dev/null || rc=$?
  if (( rc == 1 )) && [[ ! -e "$path" && ! -L "$path" ]]; then
    FLEET_TRUST_STATE=absent
    return 0
  fi
  if (( rc != 0 )); then
    FLEET_TRUST_WHY="$path is not a plain file this program will read (a symlink, a FIFO, a directory, larger than 64 KiB, or under a directory the dashboard account does not own). It was not followed and not touched. Look at it by hand: ls -la $(dirname -- "$path")"
    return 1
  fi
  # The key the way every reader takes it: the first top-level
  # `private_key:` line, trimmed, one quote off each end
  # (lib/trust-bundle.ts readOwnPrivateKey, advisor's OwnPubKey,
  # aperire-fleet-arm.sh). A file with one is kept as it is, byte for byte.
  verdict="$(python3 -I - "$snap" <<'PYCLASS'
import base64, binascii, sys
try:
    text = open(sys.argv[1], "rb").read().decode("utf-8")
except UnicodeDecodeError:
    print("malformed: it is not UTF-8 text"); sys.exit(0)
seed = None
for line in text.split("\n"):
    if line.startswith("private_key:"):
        seed = line[len("private_key:"):].strip()
        if seed[:1] in ("'", '"'):
            seed = seed[1:]
        if seed[-1:] in ("'", '"'):
            seed = seed[:-1]
        break
if seed is None:
    peers = any(l.startswith((" ", "\t")) and ":" in l and not l.strip().startswith("#")
                for l in text.split("\n"))
    print("peers" if peers else "nokey"); sys.exit(0)
try:
    raw = base64.urlsafe_b64decode(seed + "=" * (-len(seed) % 4))
except (binascii.Error, ValueError):
    raw = b""
print("kept" if seed and len(raw) == 32 else "malformed: its private_key is not a 32-byte base64url seed")
PYCLASS
)" || verdict="malformed: it could not be read as text"
  rm -f -- "$snap"
  case "$verdict" in
    kept) FLEET_TRUST_STATE=kept; return 0 ;;
    peers)
      FLEET_TRUST_WHY="$path holds peers but no private_key, which is a node's trust file, not an aggregator's. This program never rewrites it. If this host is meant to be an aggregator, move that file aside by hand and run this again." ;;
    nokey)
      FLEET_TRUST_WHY="$path exists and holds no private_key. This program makes a fleet trust key only where there is no file, and never rewrites one. Move it aside by hand and run this again." ;;
    *)
      FLEET_TRUST_WHY="$path is ${verdict#malformed: }. This program never rewrites a trust file. Fix or move it aside by hand and run this again." ;;
  esac
  return 1
}

# classify_fleet_arm_key <key-path>: refuses a link or a non-file at the
# name before anything is written. Absent and a plain file both pass; the
# plain file's owner and shape are checked once it is the one in use.
classify_fleet_arm_key() {
  local key="$1"
  if [[ -L "$key" ]] || { [[ -e "$key" ]] && [[ ! -f "$key" ]]; }; then
    FLEET_TRUST_WHY="$key exists and is not a plain file (it may be a symlink). A signing key is never made or read through one. Look at it by hand."
    return 1
  fi
  return 0
}

# ensure_fleet_trust_key <install-dir> <dashboard-uid> <owner> <group> <mode>
# Makes the fleet trust key when classify found no file, and only then.
# Prints one line saying which. Returns 1 with FLEET_TRUST_WHY on a refusal.
ensure_fleet_trust_key() {
  local dir="$1" uid="$2" owner="$3" group="$4" mode="$5" pem seed rc=0 path
  path="$dir/dashboard/config/$FLEET_TRUST_LEAF"
  if [[ "$FLEET_TRUST_STATE" == kept ]]; then
    say "$path  (kept: it already holds this aggregator's fleet trust key)"
    return 0
  fi
  [[ "$FLEET_TRUST_STATE" == absent ]] || { FLEET_TRUST_WHY="$path was not checked before this write"; return 1; }
  pem="$GRANT_WORK/fleet-trust-new.pem"
  rm -f -- "$pem"
  if ! (umask 077; openssl genpkey -algorithm ed25519 -out "$pem" 2>/dev/null); then
    FLEET_TRUST_WHY="openssl could not generate an Ed25519 key on this host"; return 1
  fi
  # The seed the way fleet-trust.yaml holds one: the last 32 bytes of the
  # PKCS8 DER, base64url, no padding. It crosses to dirsafe on a pipe from
  # printf, a builtin, so it is never an argument any process carries.
  seed="$(openssl pkey -in "$pem" -outform DER 2>/dev/null | tail -c 32 | base64 -w0 | tr '+/' '-_' | tr -d '=')"
  rm -f -- "$pem"
  if [[ ! "$seed" =~ ^[A-Za-z0-9_-]{43}$ ]]; then
    seed=''; FLEET_TRUST_WHY="the key openssl generated did not come out as a 32-byte seed"; return 1
  fi
  printf 'private_key: %s\npeers: {}\n' "$seed" \
    | dirsafe "$dir" dashboard/config "$uid" 002 create "$owner" "$group" "$mode" - "$FLEET_TRUST_LEAF" 2>/dev/null \
    || rc=$?
  seed=''
  case "$rc" in
    0) FLEET_TRUST_MADE=1; say "$path  (made: this aggregator's fleet trust key, $owner:$group $mode)"; return 0 ;;
    3)
      # Something made one between the check and this write. Whatever it
      # is stands; it is judged the way a file found at the start would be.
      if classify_fleet_trust_file "$dir" "$uid" && [[ "$FLEET_TRUST_STATE" == kept ]]; then
        say "$path  (kept: one appeared while this ran, and it holds a fleet trust key)"
        return 0
      fi
      [[ -n "$FLEET_TRUST_WHY" ]] || FLEET_TRUST_WHY="$path appeared while this ran and holds no fleet trust key. Nothing was written. Look at it by hand."
      return 1 ;;
    2) FLEET_TRUST_WHY="$path could not be made safely (a link or a directory the dashboard account does not own is in the way). Nothing was written." ; return 1 ;;
    *) FLEET_TRUST_WHY="$path could not be written" ; return 1 ;;
  esac
}

# --- FLEET-PAIRED-BEGIN ---
# fleet_paired_records <install-dir> <dashboard-uid> <etc-dir> <snapshot-dir> [label to leave out] [own port]
#
# Does this aggregator already have paired nodes? (#851) One answer for the
# grant installer and the fleet broker. Both carry this same text between
# these markers, and scripts/test-install-fleet-broker-grant.sh fails if the
# two copies differ by a byte: the broker is installed as one file and
# sources nothing, so the copy is the price of the two never disagreeing.
#
# Every record counts: root's own fleet-nodes.conf, the link registry
# fleet-links.json, and every fleet.yaml row (link, manual or tunnel) but
# this host's own: one marked `role: aggregator`, or one whose read_origin is
# loopback on [own port], the rule the dashboard itself finds its own row by
# (fleet-health.ts, resolveFleet). The broker's first approval writes that
# row (#1045), `role: node` on a co-located install, so the port is what
# leaves it out. With no port given, a row for this host without the role is
# counted and named like any other.
#
# fleet-links.json and fleet.yaml sit in a directory the dashboard account
# owns, so all three are read through dirsafe's "read" (no link followed, no
# FIFO held open, a plain file of 1 MiB at most) into <snapshot-dir>, which
# root made, and only those copies are parsed. fleet-nodes.conf is anchored
# one level above <etc-dir>, so a host with no <etc-dir> yet reads as no
# record rather than as one that could not be read. Anything that could not
# be read or parsed that way is never "no nodes": it is named, and counts.
#
# Prints one line per finding, and nothing else:
#   node <label> <file>   a node one record names
#   badrow <file>         a row whose label is not a fleet label
#   unread <file>         a record this could not read or parse safely
# Returns 0 when it printed anything (paired, or cannot tell), 1 when this
# host has no paired node. Reads only, and never writes outside <snapshot-dir>.
fleet_paired_records() {
  local dir="$1" uid="$2" etc="$3" snaps="$4" skip="${5:-}" port="${6:-}" name path rc out i
  local -a recs=()
  for name in fleet-nodes.conf fleet-links.json fleet.yaml; do
    rm -f -- "$snaps/paired.$name"
    rc=0
    if [[ "$name" == fleet-nodes.conf ]]; then
      path="$etc/$name"
      dirsafe "$(dirname -- "$etc")" "$(basename -- "$etc")" "" 022 \
        read "$name" "$snaps/paired.$name" 1048576 2>/dev/null || rc=$?
    else
      path="$dir/dashboard/config/$name"
      dirsafe "$dir" dashboard/config "$uid" 002 \
        read "$name" "$snaps/paired.$name" 1048576 2>/dev/null || rc=$?
    fi
    if (( rc == 0 )); then
      recs+=("$name" "$snaps/paired.$name" "$path")
    elif (( rc == 1 )) && [[ ! -e "$path" && ! -L "$path" ]]; then
      :  # absent, and confirmed absent: dirsafe's 1 is also a crash's
    else
      recs+=(unread - "$path")
    fi
  done
  (( ${#recs[@]} )) || return 1
  rc=0
  out="$(python3 -I - "$skip" "$port" "${recs[@]}" <<'PYPAIRED'
import json, re, sys
from urllib.parse import urlparse
LABEL = re.compile(r"[a-z0-9-]{1,32}")
skip, port, args = sys.argv[1], sys.argv[2], sys.argv[3:]
def on_own_port(origin):
    if not port or not isinstance(origin, str):
        return False
    try:
        u = urlparse(origin)
        return (u.hostname or "").lower() in ("127.0.0.1", "localhost", "::1") and u.port == int(port)
    except ValueError:
        return False
found = []
def note(label, shown):
    # Only a str is ever looked at: a YAML value is never str()'d, because
    # an alias-nested one expands when it is.
    if isinstance(label, str) and LABEL.fullmatch(label):
        if label != skip:
            found.append("node %s %s" % (label, shown))
    else:
        found.append("badrow %s" % shown)
def rows_of(doc, key):
    if doc is None:
        return []
    if not isinstance(doc, dict):
        raise ValueError
    rows = doc.get(key)
    if rows is None:
        return []
    if not isinstance(rows, list):
        raise ValueError
    return rows
for i in range(0, len(args), 3):
    kind, snap, shown = args[i:i + 3]
    if kind == "unread":
        found.append("unread %s" % shown)
        continue
    try:
        text = open(snap, "rb").read().decode("utf-8")
        if kind == "fleet-nodes.conf":
            for line in text.split("\n"):
                f = line.split()
                if f and not f[0].startswith("#"):
                    note(f[0], shown)
        elif kind == "fleet-links.json":
            for r in rows_of(json.loads(text), "links"):
                note(r.get("label") if isinstance(r, dict) else None, shown)
        else:
            import yaml
            for r in rows_of(yaml.safe_load(text), "fleet"):
                if isinstance(r, dict) and isinstance(r.get("role"), str) and r.get("role") == "aggregator":
                    continue
                if isinstance(r, dict) and on_own_port(r.get("read_origin")):
                    continue
                note(r.get("label") if isinstance(r, dict) else None, shown)
    except Exception:
        found.append("unread %s" % shown)
sys.stdout.write("".join(line + "\n" for line in found))
PYPAIRED
)" || rc=$?
  if (( rc != 0 )); then
    # The parser itself failed, so no record it was handed can be called
    # empty. Every one is named.
    out=''
    for (( i = 2; i < ${#recs[@]}; i += 3 )); do out+="unread ${recs[i]}"$'\n'; done
  fi
  [[ -n "$out" ]] || return 1
  printf '%s' "$out"
  return 0
}

# fleet_self_facts <unit-dir> <snapshot-dir>
#
# This host's own dashboard, as root reads it (#1045): the port it listens
# on, the role its install recorded, and its own read token path. Out of the
# dashboard's unit (aperire-server, else aperire-read) in <unit-dir> and the
# env file that unit names, both read through dirsafe's "read" into
# <snapshot-dir> (no link followed, every directory on the way root's and
# not group or world writable), and the env file believed only when the copy
# says it is root's and nobody else may write it. Prints one line each:
#   port <n>        PORT= in the env file, else Environment=PORT= in the
#                   unit, else 7800, the server's own default
#   role <r>        aggregator for a dashboard-role install, node for a
#                   co-located one, nothing when none was recorded
#   token <path>    APERIRE_READ_TOKEN_PATH, when it is a plain path
# or, when the port cannot be known, one line and status 1:
#   unknown <why>
# A port this cannot read is never guessed: a row on the wrong port is the
# held fleet #1045 is about, written down as if it were fixed.
fleet_self_facts() {
  local units="$1" snaps="$2" u rc found='' envfile='' optional=0 st port='' v role='' token=''
  for u in aperire-server aperire-read; do
    rc=0
    rm -f -- "$snaps/self.unit"
    dirsafe "$(dirname -- "$units")" "$(basename -- "$units")" "" 022 \
      read "$u.service" "$snaps/self.unit" 65536 2>/dev/null || rc=$?
    if (( rc == 0 )); then found="$u"; break; fi
    if (( rc != 1 )) || [[ -e "$units/$u.service" || -L "$units/$u.service" ]]; then
      printf 'unknown %s could not be read safely\n' "$units/$u.service"; return 1
    fi
  done
  if [[ -z "$found" ]]; then
    printf 'unknown this host has no aperire-server or aperire-read unit in %s to say which port the dashboard listens on\n' "$units"
    return 1
  fi
  envfile="$(sed -n 's/^EnvironmentFile=//p' "$snaps/self.unit" | head -n 1)"
  [[ "$envfile" == -* ]] && optional=1
  envfile="${envfile#-}"
  rm -f -- "$snaps/self.env"
  if [[ -n "$envfile" ]]; then
    if [[ "$envfile" != /* || "$envfile" == */ ]]; then
      printf 'unknown the dashboard unit names an env file that is not an absolute path\n'; return 1
    fi
    rc=0
    dirsafe "$(dirname -- "$(dirname -- "$envfile")")" "$(basename -- "$(dirname -- "$envfile")")" "" 022 \
      read "$(basename -- "$envfile")" "$snaps/self.env" 65536 2>/dev/null || rc=$?
    if (( rc == 1 )) && (( optional )) && [[ ! -e "$envfile" && ! -L "$envfile" ]]; then
      :  # an optional env file that is not there says nothing
    elif (( rc != 0 )); then
      printf 'unknown %s, the env file the dashboard unit names, could not be read safely (a link, a directory others may write, or not a plain file)\n' "$envfile"
      return 1
    else
      st="$(stat -c '%u %a' -- "$snaps/self.env" 2>/dev/null || true)"
      if [[ "${st%% *}" != "$(/usr/bin/id -u 2>/dev/null)" ]] || (( (8#${st##* } & 8#022) != 0 )); then
        printf 'unknown %s is not root'"'"'s alone (owner and mode %s), so what it says is not believed\n' "$envfile" "${st:-unknown}"
        return 1
      fi
    fi
  fi
  if [[ -s "$snaps/self.env" ]]; then
    port="$(sed -n 's/^[[:space:]]*PORT=//p' "$snaps/self.env" | head -n 1 | tr -d '"'"'"'[:space:]')"
    v="$(sed -n 's/^[[:space:]]*APERIRE_INSTALL_ROLE=//p' "$snaps/self.env" | head -n 1 | tr -d '"'"'"'[:space:]')"
    case "$v" in dashboard) role=aggregator ;; co-located) role=node ;; esac
    v="$(sed -n 's/^[[:space:]]*APERIRE_READ_TOKEN_PATH=//p' "$snaps/self.env" | head -n 1 | tr -d '"'"'"'[:space:]')"
    if [[ "$v" =~ ^/[A-Za-z0-9._/-]{1,255}$ && "$v" != */ && "$v" != *..* ]]; then token="$v"; fi
  fi
  [[ -n "$port" ]] || port="$(sed -n 's/^Environment=PORT=//p' "$snaps/self.unit" | head -n 1 | tr -d '"'"'"'[:space:]')"
  [[ -n "$port" ]] || port=7800
  if ! [[ "$port" =~ ^[0-9]{1,5}$ ]] || (( port < 1 || port > 65535 )); then
    printf 'unknown the dashboard port this host records (%s) is not a port\n' "$port"; return 1
  fi
  printf 'port %s\n' "$port"
  [[ -n "$role" ]] && printf 'role %s\n' "$role"
  [[ -n "$token" ]] && printf 'token %s\n' "$token"
  return 0
}
# --- FLEET-PAIRED-END ---

# fleet_keys_gate <install-dir> <dashboard-uid> <etc-dir> <repo>
# #851, ruled 2026-10-04: on a host that already has paired nodes, no new
# fleet key is ever made without an explicit request. Run after both keys
# are classified and before the first write. Sets FLEET_KEYS_MISSING (one
# line per key that is not there) and FLEET_REPAIR (what fleet_paired_records
# found, for the --new-fleet-keys report). Returns 0 to go on, or prints the
# refusal on stderr and returns 4, with nothing written.
#
# A key that IS there needs no check at all, so a symlinked or unreadable
# registry never stands in the way of an ordinary re-run.
FLEET_KEYS_MISSING=''
FLEET_REPAIR=''
fleet_keys_gate() {
  local dir="$1" uid="$2" etc="$3" repo="$4" recs nodes badrows unread
  FLEET_KEYS_MISSING='' FLEET_REPAIR=''
  if [[ "$FLEET_TRUST_STATE" == absent ]]; then
    FLEET_KEYS_MISSING+="the fleet trust key  $dir/dashboard/config/$FLEET_TRUST_LEAF"$'\n'
  fi
  local marked=0
  if [[ ! -e "$etc/fleet-arm.key" && ! -L "$etc/fleet-arm.key" ]]; then
    FLEET_KEYS_MISSING+="the fleet arm key    $etc/fleet-arm.key"$'\n'
    # Review L1: this host made or held an arm key before, so a missing one
    # was lost, whatever the records say by now.
    [[ -e "$etc/fleet-arm.made" || -L "$etc/fleet-arm.made" ]] && marked=1
  fi
  [[ -n "$FLEET_KEYS_MISSING" ]] || return 0
  recs="$(fleet_paired_records "$dir" "$uid" "$etc" "$GRANT_WORK" "" \
    "$(fleet_self_facts "${UNIT_DIR:-/etc/systemd/system}" "$GRANT_WORK" 2>/dev/null | sed -n 's/^port //p')")" || recs=''
  [[ -n "$recs" ]] || (( marked )) || return 0
  FLEET_REPAIR="$recs"
  (( ${NEW_FLEET_KEYS:-0} == 1 )) && return 0
  nodes="$(sed -n 's/^node \([a-z0-9-]*\) .*/\1/p' <<<"$recs" | sort -u | paste -sd, - | sed 's/,/, /g')"
  badrows="$(sed -n 's/^badrow //p' <<<"$recs" | sort -u)"
  unread="$(sed -n 's/^unread //p' <<<"$recs" | sort -u)"
  {
    if [[ -n "$recs" ]]; then
      printf 'error: this aggregator already has paired nodes, and a fleet key they trust is missing:\n'
    else
      printf 'error: this aggregator has had a fleet arm key before, and it is missing:\n'
    fi
    while IFS= read -r _k; do [[ -n "$_k" ]] && printf '    %s\n' "$_k"; done <<<"$FLEET_KEYS_MISSING"
    printf '  No new key was made, and nothing was written.\n\n'
    (( marked )) && printf '  %s says this host has had a fleet arm key before, so the missing one was lost.\n' "$etc/fleet-arm.made"
    [[ -n "$nodes" ]] && printf '  paired nodes: %s\n' "$nodes"
    while IFS= read -r _f; do
      [[ -n "$_f" ]] && printf '  a row in %s has no usable label; counted as a paired node\n' "$_f"
    done <<<"$badrows"
    while IFS= read -r _f; do
      [[ -n "$_f" ]] && printf '  %s could not be read safely (a symlink, a FIFO, over 1 MiB, or it does not parse); counted as paired\n' "$_f"
    done <<<"$unread"
    printf '\n  Those nodes trust the key that is gone. A new one would cut every one of\n'
    printf '  them off until each is paired again. Put the key back from your backup set,\n'
    printf '  then run this again:\n'
    printf '      curl -fsSL https://get.aperire.one | bash -s -- --dir %s --restore --from <backup set>\n' "$repo"
    printf '  With no backup, make new keys on purpose, then pair each node again from\n'
    printf '  Add a node:\n'
    printf '      curl -fsSL https://get.aperire.one | bash -s -- --dir %s --run fleet-broker-grant --new-fleet-keys\n' "$repo"
    [[ -n "$nodes" ]] && printf '  If a node named above is this host, its fleet.yaml row does not read this\n  dashboard%ss own port: set its read_origin to that port, mark it role: aggregator\n  only if this host runs no node of its own, and run this again.\n' "'"
  } >&2
  return 4
}

# say_new_fleet_keys: after the keys, on a run given --new-fleet-keys. Says
# on stderr what it made (or that it made nothing, because it never replaces
# a key), and which nodes to pair again.
say_new_fleet_keys() {
  local made='' nodes others
  (( ${NEW_FLEET_KEYS:-0} == 1 )) || return 0
  (( FLEET_TRUST_MADE )) && made+="the fleet trust key  $INSTALL_DIR/dashboard/config/$FLEET_TRUST_LEAF"$'\n'
  (( ${FLEET_ARM_KEY_MADE:-0} )) && made+="the fleet arm key    $ETC/fleet-arm.key"$'\n'
  {
    if [[ -z "$made" ]]; then
      printf -- '--new-fleet-keys: no fleet key was missing, so none was made. It never replaces a key that is there.\n'
      return 0
    fi
    printf -- '--new-fleet-keys: made\n'
    while IFS= read -r _k; do [[ -n "$_k" ]] && printf '    %s\n' "$_k"; done <<<"$made"
    nodes="$(sed -n 's/^node \([a-z0-9-]*\) .*/\1/p' <<<"$FLEET_REPAIR" | sort -u | paste -sd, - | sed 's/,/, /g')"
    others="$(sed -n 's/^\(badrow\|unread\) //p' <<<"$FLEET_REPAIR" | sort -u | paste -sd, - | sed 's/,/, /g')"
    if [[ -n "$nodes" || -n "$others" ]]; then
      printf '  Every node paired before this trusts the old key. Pair each again from Add a node,\n'
      printf '  which hands it the new one:\n'
      [[ -n "$nodes" ]] && printf '    %s\n' "$nodes"
      [[ -n "$others" ]] && printf '    and any node named in: %s\n' "$others"
    fi
  } >&2
  # Said, never a status: the installer runs under set -e, and the last test
  # above is false on a fleet with no unreadable record.
  return 0
}

# ensure_grant_arm_key <key-path> <checked copy of aperire-fleet-arm.sh>
ensure_grant_arm_key() {
  local key="$1" armsrc="$2" lib="$GRANT_WORK/ensure-fleet-arm-key.sh"
  classify_fleet_arm_key "$key" || return 1
  sed -n '/^# ---- BEGIN ensure_fleet_arm_key/,/^# ---- END ensure_fleet_arm_key/p' "$armsrc" > "$lib"
  grep -q '^ensure_fleet_arm_key() {' "$lib" \
    || { FLEET_TRUST_WHY="the checked aperire-fleet-arm.sh carries no ensure_fleet_arm_key block"; return 1; }
  # shellcheck source=/dev/null  # the block just extracted from the checked copy
  . "$lib"
  if ! ensure_fleet_arm_key "$key"; then
    FLEET_TRUST_WHY="$FLEET_ARM_KEY_WHY"; return 1
  fi
  # It returns 0 for ANY name already there, a link included, so the one
  # in use is checked here, the way aperire-fleet-arm.sh checks it.
  classify_fleet_arm_key "$key" || return 1
  [[ -O "$key" ]] || { FLEET_TRUST_WHY="$key is not root's, so it is not one this host can sign with"; return 1; }
  if (( FLEET_ARM_KEY_MADE )); then
    say "$key  (made: this aggregator's fleet arm key, root:root 0600)"
  else
    say "$key  (kept: this aggregator already has a fleet arm key)"
  fi
  # #853 review: the marker could not be made. Not a refusal, and not silent.
  if (( ${FLEET_ARM_MARK_FAILED:-0} )); then
    printf 'warning: %s has no fleet-arm.made beside it (%s could not be written), so if this key is ever
         lost, only the fleet'"'"'s records will stop a new one being made in its place.
' "$key" "$(dirname -- "$key")" >&2
  fi
}
# --- FLEET-KEYS-END ---

# ── the pm2 fallback, if this host is one (#310) ─────────────────────────
# An aggregator whose dashboard runs under pm2 has no unit for systemctl to
# reload, and the broker said the row would be picked up on the next restart,
# which nothing was going to do. Detected here rather than in the broker: the
# broker reads facts about this host from its conf, never from its caller.

# Who owns dashboard/config, asked the one way this program is allowed to
# ask anything about a path (#648, round 8): dirsafe's own "owner" op walks
# INSTALL_DIR down to dashboard/config with O_NOFOLLOW at every hop and
# answers with the leaf's own owner. `stat -c '%U'` on that path is
# ordinary path lookup, which follows a symlink at any component, and the
# name it comes back with becomes an identity root later switches to.
config_dir_owner() {  # -> the account that owns INSTALL_DIR/dashboard/config, or ""
  dirsafe "$INSTALL_DIR" dashboard/config "" 002 owner 2>/dev/null || true
}
# One rule for every account name this program writes into the conf, because
# each of them becomes an identity root switches to or runs a program as.
# DASH_ACCOUNT already had it; PM2_ACCOUNT had only the shape check the
# broker makes, which "root" passes (#648, round 8).
usable_account() {  # name -> 0 if it is a real, non-root account
  local name="$1"
  [[ -n "$name" ]] || return 1
  [[ "$name" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || return 1
  [[ "$name" != root ]] || return 1
  local uid
  uid="$(id -u "$name" 2>/dev/null || true)"
  [[ -n "$uid" && "$uid" != 0 ]]
}

PM2_ACCOUNT=""
PM2_HOME_DIR=""
PM2_BIN=""
if [[ ! -f "$UNIT_DIR/aperire-server.service" && ! -f "$UNIT_DIR/aperire-read.service" ]]; then
  # No unit, so the dashboard is supervised some other way. The account that
  # owns the config directory is the one running it, which is the same
  # derivation the broker itself falls back to.
  PM2_ACCOUNT="$(config_dir_owner)"
  # Refused BEFORE runuser, and before it is written into the conf: this is
  # the account root signals pm2 as, and `runuser -u root` is not a drop at
  # all. The broker makes the same refusal again at the point of use.
  if [[ -n "$PM2_ACCOUNT" ]] && ! usable_account "$PM2_ACCOUNT"; then
    die "the account that owns $INSTALL_DIR/dashboard/config is '$PM2_ACCOUNT', and this host has no
     dashboard unit, so that is the account the reload would run pm2 as. It has to be a real,
     non-root account. Fix the ownership of that directory, or add the dashboard unit, then run
     this again."
  fi
  if [[ -n "$PM2_ACCOUNT" ]]; then
    PM2_HOME_DIR="$(getent passwd "$PM2_ACCOUNT" | cut -d: -f6)"
    # Resolved HERE, as the account, through a LOGIN shell, and written to
    # the conf as an absolute path.
    #
    # The broker runs from a systemd socket with systemd's PATH, and
    # `runuser` without --login preserves the environment it was given, so a
    # pm2 under the account's nvm is on neither. Asking PATH from inside the
    # broker would have reported a pm2 failure on a host where pm2 is
    # perfectly fine, which is the trap /etc/profile.d laid for the pinned Go
    # install. A login shell is the one context that has the account's own
    # PATH, and this installer is the one place a login shell is available.
    PM2_BIN="$(runuser -u "$PM2_ACCOUNT" -- bash -lc 'command -v pm2' 2>/dev/null || true)"
    [[ -n "$PM2_BIN" ]] || PM2_BIN="$(command -v pm2 2>/dev/null || true)"
  fi
fi

# ── the node binary (#318, #964) ─────────────────────────────────────────
# The broker reads all three candidate registries back with the dashboard's
# own parsers before it renames any of them into place, so an approval it
# cannot run node for is an approval it refuses. It runs from a systemd
# socket with systemd's PATH, and a node under the dashboard account's nvm is
# on none of it, which is the same trap PM2_BIN above exists for. Its own
# run-time search stays as the fallback, but on a host where that search came
# up empty it used to take the program down under `set -e` before it could
# say so. Resolved here instead.
#
# First, the node the dashboard's own unit starts (#964). On a fresh install
# the dashboard runs as aperire-dashboard (ADR 0024): no home, no shell, no
# nvm. Node lives under the operator's nvm, so the login-shell probe below
# and this shell's PATH both came back empty, the conf said `NODE_BIN=`, and
# every approval refused after the passkey. The unit names the one node that
# account already runs as itself, and install-aperire-service.sh proved it
# can. Root reads the unit, which is root's, and never runs what it names:
# the broker runs it under runuser as that account (#370). The operator's
# login, which owns that nvm, is outside the service set ADR 0024 guards.
# --- READER-NODE-BEGIN ---
unit_node_of() {  # unit-file install-dir -> the node that unit's ExecStart runs, or nothing
  local f="$1" dir="$2" wd here want n
  [[ -n "$f" && -f "$f" ]] || return 0
  # Only a unit that serves THIS tree: another dashboard on the host may
  # run another node, and it is not the one these parsers are read with.
  wd="$(sed -n 's/^WorkingDirectory=//p' "$f" | tail -n 1)"
  if [[ -n "$wd" ]]; then
    want="$(cd "$dir/dashboard" 2>/dev/null && pwd -P)" || return 0
    here="$(cd "$wd" 2>/dev/null && pwd -P)" || return 0
    [[ "$here" == "$want" ]] || return 0
  fi
  # An absolute path whose last part is exactly `node`, ended by a quote, a
  # space or the line. The shipped unit runs `exec "<dir>/node" --import
  # tsx server.ts`, and a `.../dashboard/node_modules/...` later on some
  # other unit's line must never match.
  n="$(sed -n 's/^ExecStart=//p' "$f" | grep -oE "/[^\"' ]*/node([\"' ]|\$)" | head -n 1 | tr -d "\"' " || true)"
  [[ -n "$n" && -f "$n" && -x "$n" ]] && printf '%s' "$n"
  return 0
}
# --- READER-NODE-END ---
NODE_BIN=""
DASH_ACCOUNT=""
DASH_UNIT_FILE=""
for u in aperire-server aperire-read; do
  [[ -f "$UNIT_DIR/${u}.service" ]] || continue
  DASH_ACCOUNT="$(awk -F= '/^User=/{print $2; exit}' "$UNIT_DIR/${u}.service")"
  DASH_UNIT_FILE="$UNIT_DIR/${u}.service"
  break
done
if [[ -z "$DASH_ACCOUNT" || "$DASH_ACCOUNT" == root ]]; then
  # The same fallback the broker itself makes: the account that owns the
  # config directory is the one running the dashboard. Through the same
  # O_NOFOLLOW walk the broker's own fallback uses now, never `stat`.
  DASH_ACCOUNT="$(config_dir_owner)"
fi
NODE_BIN="$(unit_node_of "$DASH_UNIT_FILE" "$INSTALL_DIR")"
if [[ -z "$NODE_BIN" && -n "$DASH_ACCOUNT" ]] && id -u "$DASH_ACCOUNT" >/dev/null 2>&1; then
  NODE_BIN="$(runuser -u "$DASH_ACCOUNT" -- bash -lc 'command -v node' 2>/dev/null || true)"
fi
# The account's own nvm tree, the same place the broker's run-time fallback
# looks, because Ubuntu's stock .bashrc returns before nvm loads in a
# non-interactive shell and the login shell above misses it. Tested before
# find walks it, and `|| true`, so finding nothing stays empty (#318).
if [[ -z "$NODE_BIN" && -n "$DASH_ACCOUNT" ]]; then
  _dash_home="$(getent passwd "$DASH_ACCOUNT" 2>/dev/null | cut -d: -f6 || true)"
  if [[ -n "$_dash_home" && -d "$_dash_home/.nvm/versions/node" ]]; then
    NODE_BIN="$(find "$_dash_home/.nvm/versions/node" -maxdepth 3 -path '*/bin/node' -type f 2>/dev/null | sort -V | tail -1 || true)"
  fi
fi
[[ -n "$NODE_BIN" ]] || NODE_BIN="$(command -v node 2>/dev/null || true)"
# Absolute or nothing. The broker refuses a relative NODE_BIN outright, so
# writing one here would only move the failure to the first approval.
[[ -z "$NODE_BIN" || "$NODE_BIN" == /* ]] || NODE_BIN=""

# The same account, now written into the conf as the identity that read-back
# runs UNDER (#370). $DASH_USER is the one this whole grant is for and it has
# already been checked for existing and for not being root, so it is the
# answer whenever the two derivations above came up empty. A grant that
# cannot name a non-root account here is one that would leave the broker
# refusing every approval, so it stops now and says which.
[[ -n "$DASH_ACCOUNT" ]] || DASH_ACCOUNT="$DASH_USER"
[[ "$DASH_ACCOUNT" != root ]] \
  || die "the dashboard runs as root on this host, and the broker will not read a registry back as root"
id -u "$DASH_ACCOUNT" >/dev/null 2>&1 \
  || die "there is no account called '$DASH_ACCOUNT', and that is the account the broker reads every candidate registry back as"
[[ "$(id -u "$DASH_ACCOUNT")" != 0 ]] \
  || die "'$DASH_ACCOUNT' is uid 0, and the broker will not read a registry back as root"
command -v runuser >/dev/null \
  || die "runuser not found (it is in util-linux), and the broker reads every candidate registry back as $DASH_ACCOUNT rather than as root"

# Both keys are judged here, and the owner, group and mode a new trust file
# would take are settled here, before the first write below (#846 review,
# L2). So a trust file this program would refuse, or two accounts that share
# no group, stop the run with nothing changed: no program in /usr/local/sbin,
# no conf, no unit. The keys themselves are made just before the first
# program is placed, so a key that cannot be made leaves neither program
# behind either.
command -v openssl >/dev/null || die "openssl not found, and the fleet's two pairing keys are made with it"
# The owner, group and mode rule, from a copy checked against the release
# (ADR 0024) rather than sourced out of a tree the dashboard account can
# rewrite: root acts on what it says.
# shellcheck source=scripts/release-digests-lib.sh
. "$BROKER_SELF/release-digests-lib.sh"
FT_STAGED="$(mktemp "$GRANT_WORK/fleet-trust-perms.XXXXXXXX")"
rd_stage "$REPO" scripts/fleet-trust-perms.sh "$FT_STAGED" \
  || die "nothing was written: $(rd_refused_cause "the fleet-trust-perms.sh in this tree")"
# shellcheck source=scripts/fleet-trust-perms.sh
. "$FT_STAGED"
# The split (#868): the key file is the dashboard account's alone, and the
# Advisor reads the public half beside it. The same checked-copy rule, and
# state-file.py with it, which does the writes on a directory descriptor.
FTS_STAGED="$(mktemp "$GRANT_WORK/fleet-trust-split.XXXXXXXX")"
rd_stage "$REPO" scripts/fleet-trust-split.sh "$FTS_STAGED" \
  || die "nothing was written: $(rd_refused_cause "the fleet-trust-split.sh in this tree")"
FTS_TOOL="$GRANT_WORK/state-file.py"
rd_stage "$REPO" scripts/state-file.py "$FTS_TOOL" \
  || die "nothing was written: $(rd_refused_cause "the state-file.py in this tree")"
# shellcheck source=scripts/fleet-trust-split.sh
. "$FTS_STAGED"
classify_fleet_trust_file "$INSTALL_DIR" "$(id -u "$DASH_ACCOUNT")" || die "$FLEET_TRUST_WHY"
classify_fleet_arm_key "$ETC/fleet-arm.key" || die "$FLEET_TRUST_WHY"
if ! FT_PLAN="$(ft_target "$DASH_ACCOUNT" "$ADV_USER")"; then
  die "the dashboard runs as $DASH_ACCOUNT and advisord as $ADV_USER, and they share no group, so no
     fleet-trust.yaml made here could be read by both. Nothing was written. Fix it first:
       curl -fsSL https://get.aperire.one | bash -s -- --dir $REPO --run advisor-account"
fi
read -r _ FT_GROUP _ <<<"$FT_PLAN"
# FT_PLAN is the PUBLIC half's owner, group and mode (the file the Advisor
# reads). A new key file is the dashboard account's own, 0600 (#868).
FK_PLAN="$(ft_key_target "$DASH_ACCOUNT")" \
  || die "the dashboard account $DASH_ACCOUNT has no primary group here, so no fleet-trust.yaml was made. Nothing was written."
read -r FK_OWNER FK_GROUP FK_MODE <<<"$FK_PLAN"
# #851: a key that is missing on a host with paired nodes is not made
# without --new-fleet-keys. Asked here, after both keys are judged and before
# the first write below, so the refusal (exit 4) leaves no program, conf,
# unit or key behind.
fleet_keys_gate "$INSTALL_DIR" "$(id -u "$DASH_ACCOUNT")" "$ETC" "$REPO" || exit $?
# #964: node found, or refused here, after the key checks and before the
# first write below. A grant that wrote an empty NODE_BIN installed a broker
# that refused every approval after the passkey, and said so only in one
# line of its summary.
[[ -n "$NODE_BIN" && -x "$NODE_BIN" ]] \
  || die "nothing was written: there is no node here for the broker to read registries back with. It
     looked at the node ${DASH_UNIT_FILE:-the dashboard unit} starts, $DASH_ACCOUNT's login shell and nvm,
     and this shell's PATH. Install the dashboard first (its unit names the node it runs), then run this again."
[[ -f "$INSTALL_DIR/dashboard/node_modules/tsx/dist/cli.mjs" ]] \
  || die "nothing was written: $INSTALL_DIR/dashboard/node_modules has no tsx, and the broker reads
     registries back with it. Run npm ci in $INSTALL_DIR/dashboard, then run this again."
# Asked as the account that runs it, not judged as root (#970 review, L1):
# the broker runs node only as $DASH_ACCOUNT, so a node root can execute and
# that account cannot reach would pass here and fail every approval.
runuser -u "$DASH_ACCOUNT" -- test -x "$NODE_BIN" 2>/dev/null \
  || die "nothing was written: $DASH_ACCOUNT cannot run $NODE_BIN, though root can, and the broker
     runs it only as $DASH_ACCOUNT. Give that account passage to it (install-aperire-service.sh
     does, for the node the dashboard runs), then run this again."
# Every value the conf below takes from a probe, held to one line (#970
# review, M1). A PATH entry is the login's to name, a directory name can hold
# a newline, and the broker reads this file line by line: a NODE_BIN of
# "a<newline>PM2_BIN=/x/evil" would be read as a second key root obeys. The
# broker now refuses a key seen twice and a control character too; this
# refuses before anything is written. Under LC_ALL=C, [[:cntrl:]] is exactly
# the ASCII controls, newline and carriage return among them.
conf_value_ok() { local LC_ALL=C; [[ "$1" != *[[:cntrl:]]* ]]; }
for _kv in "INSTALL_DIR=$INSTALL_DIR" "INSTALL_DIR_ID=$INSTALL_DIR_ID" \
           "FLEET_LINK_PORT_MIN=$PORT_MIN" "FLEET_LINK_PORT_MAX=$PORT_MAX" \
           "PM2_ACCOUNT=$PM2_ACCOUNT" "PM2_HOME_DIR=$PM2_HOME_DIR" "PM2_BIN=$PM2_BIN" \
           "NODE_BIN=$NODE_BIN" "DASH_ACCOUNT=$DASH_ACCOUNT"; do
  conf_value_ok "${_kv#*=}" \
    || die "nothing was written: the value found for ${_kv%%=*} has a control character in it (a newline
     is one), so in $CONF it would read as more than one line: $(printf '%q' "${_kv#*=}")"
done

echo
echo "== The broker, as root"
# ── the one convention that would undo all of it (#648, round 8) ─────────
#
# The broker is copied to /usr/local/sbin because the checkout belongs to
# the dashboard account and a unit naming a file that account can rewrite is
# root for that account. /usr/local's own historical Debian default is
# root:staff 2775: group-writable on purpose, so members of staff can
# install software without root. dirsafe's own mask for this one write is
# 002 rather than 022 for exactly that reason, so the convention does not
# refuse the install on a host that follows it.
#
# That is fine while no service account is IN that group. It is not fine
# when one is: group-write on /usr/local/sbin lets that account rename the
# installed broker out of the way and put its own file there, and root runs
# whatever is at that name on the next connection. Group-write on any
# ANCESTOR is the same thing one level up (rename sbin itself). So the two
# accounts this grant exists for are checked against the whole chain, by
# numeric gid, at install time, and a host that has put them in a
# group-writable install directory is told exactly which directory and which
# group rather than being handed a root program it cannot trust.
group_writable_for() {  # account dir -> prints the first ancestor that account can write via a group
  local account="$1" dir="$2" gids gid mode up
  gids=" $(id -G "$account" 2>/dev/null || true) "
  [[ "$gids" != "  " ]] || return 0
  while :; do
    if read -r gid mode < <(stat -c '%g %a' "$dir" 2>/dev/null); then
      if (( 8#"$mode" & 8#20 )) && [[ "$gids" == *" $gid "* ]]; then
        printf '%s %s' "$dir" "$gid"
        return 0
      fi
    fi
    # Up one, and stop at the top whether that top is "/" or a name
    # dirname cannot climb past: a relative path would otherwise sit on "."
    # for ever.
    up="$(dirname -- "$dir")"
    [[ "$up" != "$dir" ]] || break
    dir="$up"
  done
  return 0
}
for _acct in "$DASH_USER" "$ADV_USER"; do
  [[ -n "$_acct" ]] || continue
  id -u "$_acct" >/dev/null 2>&1 || continue
  _writable="$(group_writable_for "$_acct" "$(dirname -- "$DEST")")"
  [[ -z "$_writable" ]] \
    || die "$_acct is in a group that can write ${_writable% *} (gid ${_writable#* }), and that is where
     this installs the program root runs. That account could replace it. Take the account out of
     that group, or take the group's write bit off that directory, then run this again."
done
say "checked: no account this grant names can write into $(dirname -- "$DEST") through a group"
# Copied, not linked, and written temp-then-rename: a plain `install` onto
# $DEST truncates in place and keeps the inode, which hands a running copy
# of this program new bytes at its old offset (#62's lesson). Round 7
# (#648, review7-0.json) routes it through dirsafe.py's own "put" rather
# than a bare "mktemp in /tmp, then mv -f onto /usr/local/sbin": that mv was
# never even a same-filesystem rename in general, and one discipline
# everywhere is the standing rule for every root write this program makes,
# not only the ones a review found reachable. The mask is 002 here, not
# $CONF's and the unit directory's 022: /usr/local's own historical Debian
# default is root:staff 2775, group-writable on purpose so members of staff
# can install software without root, and this program has no business
# refusing that convention on /usr/local/sbin specifically. A directory that
# is world-writable is still refused either way.
#
# And what it puts is not the tree file but a checked copy of it (ADR 0024):
# read once into root's own work directory, compared with the release's
# digests, and that copy is the one "put" reads. The tree file is never read
# a second time, so nothing can swap it between the check and the write.
# shellcheck source=scripts/release-digests-lib.sh
. "$BROKER_SELF/release-digests-lib.sh"
BROKER_STAGED="$(mktemp "$GRANT_WORK/broker.XXXXXXXX")"
rd_stage "$REPO" scripts/aperire-fleet-broker.sh "$BROKER_STAGED" \
  || die "$DEST was not written, and nothing below was either: $(rd_refused_cause "the broker in this tree")"
# #741: the pairing fingerprint's command, the same way and the same checks.
[[ "$(dirname -- "$ARM_DEST")" == "$(dirname -- "$DEST")" ]] \
  || die "$ARM_DEST is not beside $DEST, and only that directory was checked above"
# Staged and checked like the broker above (ADR 0024): the tree file is read
# once, compared with the release's digests, and only that copy is put.
ARM_STAGED="$(mktemp "$GRANT_WORK/arm.XXXXXXXX")"
rd_stage "$REPO" scripts/aperire-fleet-arm.sh "$ARM_STAGED" \
  || die "$ARM_DEST was not written: $(rd_refused_cause "the aperire-fleet-arm.sh in this tree")"

# Both programs are checked against the release before anything is placed,
# so a refused one stops the run with nothing written. Then the two pairing
# keys, made only where absent (see FLEET-KEYS above), before either program
# lands: a key that cannot be made leaves no program behind.
echo
echo "== The pairing keys"
# dirsafe's own "ensuredir", not `install -d` (#648, round 8): GNU
# `install -d` follows a pre-existing symlink at the name it is asked to
# create and chowns and chmods whatever it points at. $ETC's own ancestors
# are root's on every host this installs on, so this closes no gap today; it
# is the same one-discipline-everywhere rule the writes just below already
# follow, and the next reader copying this shape into a directory where it
# would matter is the failure this avoids.
dirsafe "$(dirname -- "$ETC")" "" "" 022 ensuredir "$(basename -- "$ETC")" root root 755 \
  || die "could not make $ETC a root-owned 0755 directory"
ensure_fleet_trust_key "$INSTALL_DIR" "$(id -u "$DASH_ACCOUNT")" "$FK_OWNER" "$FK_GROUP" "$FK_MODE" \
  || die "$FLEET_TRUST_WHY"
# Then the public half, made or remade from the key file, and a key file
# kept from before #868 narrowed to its owner. Not fatal: the key is already
# made, and a run that stops after it is a host the line below names red.
FTS_RC=0
FTS_OUT="$(fts_converge "$INSTALL_DIR" "$DASH_ACCOUNT" "$FT_GROUP" "$FTS_TOOL" 2>&1)" || FTS_RC=$?
while IFS= read -r _l; do [[ -n "$_l" ]] && say "  $_l"; done <<<"$FTS_OUT"
(( FTS_RC == 0 )) || say "  WARNING: the fleet trust key is not split (above). Once fixed: curl -fsSL https://get.aperire.one | bash -s -- --update --force"
FT_LINE="$(ft_check_file "$INSTALL_DIR/dashboard/config/$FLEET_TRUST_LEAF" "$UNIT_DIR")" || true
say "  ${FT_LINE%%$'\t'*}: ${FT_LINE#*$'\t'}"
ensure_grant_arm_key "$ETC/fleet-arm.key" "$ARM_STAGED" || die "$FLEET_TRUST_WHY"
say_new_fleet_keys
say "  root prints the pairing fingerprint over both: sudo aperire-fleet-arm --fingerprint"
echo
echo "== The programs, as root"
dirsafe "$(dirname -- "$DEST")" "" "" 002 put root root 755 "$BROKER_STAGED" "$(basename -- "$DEST")" \
  || die "could not write $DEST"
say "$DEST  (root:root 0755, copied from the one read that was checked)"
# The installed-copy drift check (#185): a root program runs from
# /usr/local/sbin and rsync never refreshes it, so the summary says whether
# the two are the same bytes rather than leaving it to be discovered.
if cmp -s "$BROKER_STAGED" "$DEST"; then
  say "checked: $DEST is the same bytes as the release's copy"
else
  die "$DEST does not match the copy just checked after installing it; something else is writing that path"
fi
dirsafe "$(dirname -- "$ARM_DEST")" "" "" 002 put root root 755 "$ARM_STAGED" "$(basename -- "$ARM_DEST")" \
  || die "could not write $ARM_DEST"
cmp -s "$ARM_STAGED" "$ARM_DEST" \
  || die "$ARM_DEST does not match the copy just checked after installing it; something else is writing that path"
say "$ARM_DEST  (root:root 0755, copied from the one read that was checked)"
say "  a node being paired asks for the fingerprint it prints: sudo aperire-fleet-arm --fingerprint"


echo
echo "== What it may write"
TMPC="$(mktemp)"
cat > "$TMPC" <<EOF
# Written by scripts/install-fleet-broker-grant.sh
#
# Read by /usr/local/sbin/aperire-fleet-broker only, as key=value and never
# sourced. Nothing here can come from the dashboard: the install tree and the
# port pool are facts about this host, and a caller that could name them
# could name a path or a conflict.
INSTALL_DIR=$INSTALL_DIR
# WHICH directory that is: the filesystem's own id and the inode, read
# when this installer ran. The broker compares the directory its own
# anchor opens against this and refuses anything else, so renaming an
# ancestor of the install redirects nothing. Re-run this installer if the
# install is moved or copied: that changes what this records, and the
# broker says so by name rather than carrying on.
INSTALL_DIR_ID=$INSTALL_DIR_ID
FLEET_LINK_PORT_MIN=$PORT_MIN
FLEET_LINK_PORT_MAX=$PORT_MAX
# The pm2 fallback for the reload, when this host has no dashboard unit.
# Empty on a systemd host, which is every host that has one. The process
# name is fixed here so a caller can never name a process for root to signal.
PM2_ACCOUNT=$PM2_ACCOUNT
PM2_HOME_DIR=$PM2_HOME_DIR
PM2_PROCESS=aperire-aggregator
PM2_BIN=$PM2_BIN
# The node the broker reads the three candidate registries back with,
# resolved as the dashboard account through a login shell. Empty means the
# broker asks this host at run time instead.
NODE_BIN=$NODE_BIN
# WHO that read-back runs as (#370). The dashboard's own account, off its
# unit's User=, so root never imports a module out of a tree this account can
# rewrite. There is no run-time fallback for this one: the broker refuses an
# approval when this key is missing rather than reading the candidates back
# as root.
DASH_ACCOUNT=$DASH_ACCOUNT
EOF
# dirsafe (#648, round 7), not a bare `install` onto $CONF: $ETC is root's
# own directory, so this was never reachable by either unprivileged account,
# but one discipline everywhere is what stops the next reader copying a
# plain `install` shape into a place it would matter.
dirsafe "$ETC" "" "" 022 put root root 644 "$TMPC" "$(basename -- "$CONF")" \
  || die "could not write $CONF"
rm -f "$TMPC"
say "$CONF  (root:root 0644)"
say "install dir  $INSTALL_DIR"
say "port pool    $PORT_MIN-$PORT_MAX, lowest free first"
say "validates as $DASH_ACCOUNT, never as root (the registries are read back with that account's own parsers)"
say "node         $NODE_BIN (reads the candidate registries back, as $DASH_ACCOUNT)"
if [[ -n "$PM2_ACCOUNT" ]]; then
  if [[ -n "$PM2_BIN" ]]; then
    say "reload       $PM2_BIN sendSignal SIGHUP aperire-aggregator, as $PM2_ACCOUNT (no dashboard unit here)"
  else
    # Said loudly, because the alternative is a broker that reports a pm2
    # failure on every approval and an operator who reloads by hand forever
    # without knowing why.
    say "reload       NOT RESOLVED. This host has no dashboard unit and no pm2 on $PM2_ACCOUNT's PATH,"
    say "             so an approval will register the node and not be able to tell the dashboard."
    say "             Install pm2 for that account, or add the unit, then run this again."
  fi
else
  say "reload       systemctl reload aperire-server or aperire-read"
fi
# --- FLEET-MODEL-LINE-BEGIN ---
# How this aggregator will keep the fleet model the page seals (#711), said
# here, at the aggregator's own install, rather than at the first seal. Never
# a refusal: a host without systemd-creds (Ubuntu 22.04 and its systemd 249)
# keeps it as a root-only file, the same arrangement its Advisor's own key
# has. Measured by the tree's copy of the library the broker mirrors byte for
# byte, so this line and the broker cannot answer differently.
if [[ -r "$BROKER_SELF/model-key-method-lib.sh" ]]; then
  # shellcheck source=scripts/model-key-method-lib.sh
  . "$BROKER_SELF/model-key-method-lib.sh"
  FM_METHOD="$(aperire_key_method)"
  say "fleet model  $(aperire_key_blob_path "$ETC" fleet-model.cred "$FM_METHOD"), $(aperire_key_method_line "$FM_METHOD")"
fi
# --- FLEET-MODEL-LINE-END ---

echo
echo "== One socket, one account, one program behind it"
TMPS=$(mktemp)
TMPV=$(mktemp)

cat > "$TMPS" <<EOF
# Written by scripts/install-fleet-broker-grant.sh
#
# The dashboard account may open this socket and nothing else. Behind it is
# one root program, started with no arguments, that reads one verb on
# standard input. It appends a fleet row and removes one only on revoke; it
# cannot name a path. It changes an existing row only to convert the SAME
# label's own tunnel row to a link, to move one row's pinned key on Accept
# new key, or, with attach-advisor and detach-advisor, to add or take off that
# row's Advisor address and token path, each on an explicit passkey approval.
# refresh-advisor-token replaces the content of an attached row's Advisor
# token file and changes nothing else. Its other verbs: revoke takes
# a node out of the fleet's registries, and the three model verbs seal the
# fleet's model descriptor, read it back minus the key, and push it to one
# node named by a root-owned file. No verb returns the key.
[Unit]
Description=Aperire: the dashboard's way to register a paired node
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
# program does. An approval is one question and one answer.
#
# MaxConnections=1 STAYS at phase 4, and it is doing more work than it looks
# like: it is what stops two model pushes racing fleet-nodes.conf and each
# other. A lock inside the program would be a second mechanism for a property
# the socket already has.
#
# What it costs, stated rather than designed around: a push can run for
# minutes, and while one holds this socket a second connection is accepted
# and dropped at once ("Too many incoming connections (1), dropping
# connection" in the journal; read on a real host, 2026-09-15). The caller
# sees a clean close with no bytes, which is the no-answer state
# lib/fleet-broker.ts must not read as a refusal. The dashboard therefore
# serialises its own broker calls in process and names a busy socket to the
# operator.
Accept=yes
MaxConnections=1

[Install]
WantedBy=sockets.target
EOF

cat > "$TMPV" <<EOF
# Written by scripts/install-fleet-broker-grant.sh
[Unit]
Description=Aperire: register a paired node (connection %i)
Documentation=file:$DEST
# In [Unit], where systemd reads it (#314). It sat in [Service] and every
# invocation logged \`Unknown key name 'CollectMode' in section 'Service',
# ignoring\`, so it never took effect at all. It lets systemd garbage-collect
# this template instance once it is inactive OR failed, rather than only
# inactive, so a run that exits non-zero (now including exit 1, see
# SuccessExitStatus below) does not leave a loaded instance behind. Whether
# an Accept=yes instance is collected promptly while the socket lives is a
# systemd behaviour this installer cannot exercise; it is confirmed on the
# lab, not here.
CollectMode=inactive-or-failed

[Service]
# Root, because the files belong to two accounts: dashboard/config is the
# dashboard's and advisor/state is the Advisor's, and root is the one thing
# that can act as each in turn. The program writes each file as the account
# that owns it and never leaves one owned by root.
ExecStart=$DEST
# The accepted connection is this program's three streams. The payload
# arrives on standard input; the facts and any refusal go back the same way.
# An exit code does not cross a socket, which is why the program prints
# \`exit=\` last.
StandardInput=socket
StandardOutput=socket
StandardError=socket
# A bound, so a run that never returns cannot hold a connection open for
# ever. 300 s, raised from 120 at phase 4 (#168): an approval reads three
# registries, runs one tsx validation and reloads, and is done in seconds,
# but a model push waits on the far node's own sealer, whose worst case is
# about 213 s (a 180 s sealer plus its read-back). A bound below that would
# cut a push that had SEALED and report it as no answer, which is this
# project's kept-versus-observed failure written into a unit file.
RuntimeMaxSec=300
# A memory bound too (#870 review, M1), so a registry file built to blow up
# a parser costs this one connection and not a process the host's own OOM
# killer picks. 1 GiB: the as-dashboard validation's node and tsx, which run
# in this unit's cgroup, need a few hundred MiB, and nothing else here comes
# close. The revoke's own fleet.yaml parse has a tighter cap inside.
MemoryMax=1G
# A refusal is an outcome, not a failure. The program exits 3 for a label
# that is taken, a pin that collides, a pool with nothing free and the like;
# it has already said which on the socket, so 3 is not a failed unit.
#
# 3 ONLY (#313). Exit 1 is the program's own fail(): not root, an unreadable
# conf, a registry that could not be written, a set -e death between the
# reload and the exit line. Those are real failures and must show in
# \`systemctl --failed\`; marking 1 a success logged "Deactivated
# successfully" on a broken run, indistinguishable from a clean one. The
# header agrees, and now the unit does: 0 ok, 3 refused, 1 failed.
SuccessExitStatus=3
EOF

# dirsafe (#648, round 7), not a bare `install` onto the unit directory: one
# discipline everywhere, the same reason $CONF and the broker binary itself
# go through it now.
dirsafe "$UNIT_DIR" "" "" 022 put root root 644 "$TMPS" "$SOCKET_UNIT" \
  || die "could not write $UNIT_DIR/$SOCKET_UNIT"
dirsafe "$UNIT_DIR" "" "" 022 put root root 644 "$TMPV" "$SERVICE_UNIT" \
  || die "could not write $UNIT_DIR/$SERVICE_UNIT"
rm -f "$TMPS" "$TMPV"
say "$UNIT_DIR/$SOCKET_UNIT   ($SOCK, $DASH_USER only, mode 0600)"
say "$UNIT_DIR/$SERVICE_UNIT  (runs $DEST as root, no arguments)"

systemctl daemon-reload
# Restarted, not merely enabled: on a re-run the unit text may have changed,
# and an already-listening socket would go on serving the old one.
systemctl enable "$SOCKET_UNIT" >/dev/null
# DirectoryMode= above applies only to a directory systemd creates. Another
# unit may have made this one first, under its own umask, and then the
# dashboard cannot traverse it to its own socket (#171). dirsafe's own
# "ensuredir" rather than `install -d` (#648, round 8), for the reason $ETC
# just above carries: `install -d` follows a symlink already sitting at that
# name and chowns and chmods its target instead. /run is root's on every
# host this runs on, so nothing unprivileged can plant one there today; the
# discipline is the point. ensuredir reapplies the mode on a directory that
# already exists, which is the whole reason this line is here, and refuses
# outright if another unit left it WIDER than 0755 rather than quietly
# narrowing somebody else's directory.
dirsafe "$(dirname -- "$(dirname -- "$SOCK")")" "" "" 022 \
  ensuredir "$(basename -- "$(dirname -- "$SOCK")")" root root 755 \
  || die "$(dirname -- "$SOCK") is not a root-owned directory at 0755 or narrower, and the
     dashboard has to traverse it to reach $SOCK. Look at it by hand: stat -c '%A %U' $(dirname -- "$SOCK")"
systemctl restart "$SOCKET_UNIT"

# The grant has to work for the account it names, not just parse. Without
# this the dashboard discovers it in the middle of an approval an operator is
# watching.
systemctl is-active --quiet "$SOCKET_UNIT" \
  || die "$SOCKET_UNIT did not come up. Read: systemctl status $SOCKET_UNIT"
[[ -S "$SOCK" ]] \
  || die "$SOCKET_UNIT is active but there is no socket at $SOCK.
     Read: systemctl status $SOCKET_UNIT"
owner_mode="$(stat -c '%U %a' "$SOCK" 2>/dev/null || true)"
[[ "$owner_mode" == "$DASH_USER 600" ]] \
  || die "$SOCK is '$owner_mode', not '$DASH_USER 600'.
     Either the dashboard cannot open it, or somebody else can."
runuser -u "$DASH_USER" -- test -e "$SOCK" 2>/dev/null \
  || die "$SOCK exists but $DASH_USER cannot reach it.
     Read: stat -c '%A %U' $(dirname "$SOCK")"
say "checked: $SOCK is listening, owned by $DASH_USER, mode 600, reachable as $DASH_USER"

# The one refusal that would only show up mid-approval: the token files land
# root:<shared group> 0640 because advisord reads them too, and a group the
# dashboard is not in would 401 every peer read on this aggregator.
if [[ -n "$ADV_USER" ]] && id -u "$ADV_USER" >/dev/null 2>&1; then
  SHARED=""
  _dash=" $(id -nG "$DASH_USER") "
  for _g in $(id -nG "$ADV_USER"); do
    if [[ "$_dash" == *" $_g "* ]]; then SHARED="$_g"; break; fi
  done
  [[ -n "$SHARED" ]] \
    || die "the dashboard runs as $DASH_USER and advisord as $ADV_USER, and they share no group.
     A token file cannot then be readable by both, and the broker refuses rather than
     writing one the dashboard cannot read. Fix it first:
       curl -fsSL https://get.aperire.one | bash -s -- --dir $REPO --run advisor-account"
  say "checked: $DASH_USER and $ADV_USER share group $SHARED, so a token file can be read by both"
else
  say "no advisord on this host, so the token files are the dashboard's alone"
fi

echo
say "the page can now register a node from a one-time code:"
say "  Settings -> Fleet registry list -> Pair a node"
