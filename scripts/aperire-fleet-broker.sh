#!/usr/bin/env bash
# Register a paired node and hold the fleet's model key, as root, ADR 0019
# phases 3 and 4, #176 and #168.
#
# Installed at /usr/local/sbin/aperire-fleet-broker. Reached through its
# socket, and by root's update with argv. The socket is
# /run/aperire/fleet-broker.sock, which systemd owns and the dashboard
# account may open. One verb per connection, the payload on stdin, the answer
# on this stream with `exit=<code>` as its last line because an exit code
# does not cross a socket. The socket unit starts this program with no
# arguments, so nothing that reaches the socket can name the one argv mode
# below (#828).
#
# THE ARGV MODE, #828. An update and a rollback swap the install tree by
# rename, which gives $INSTALL_DIR a new inode, and the conf's
# INSTALL_DIR_ID pin then refuses every verb as install_moved. Root's update
# re-records the pin through this:
#
#   aperire-fleet-broker --rerecord-install-dir --previous <tree> --expect <dev>:<ino>
#
# with stdin closed. It writes ONE line of the conf, INSTALL_DIR_ID, and only
# when every rule holds; otherwise it writes nothing and says which rule:
#
#   0. $INSTALL_DIR already IS the recorded directory: already_current=1.
#   1. <tree> is $INSTALL_DIR's own sibling, named the way an update
#      (.previous-*) or a rollback (.rolled-back-*) names the tree it moved
#      aside.
#   2. <tree> is the recorded directory: only the original has that id, so
#      this proves the update moved the recorded tree aside, and that the pin
#      was valid before it did.
#   3. $INSTALL_DIR, opened through dirsafe.py, is the directory the update
#      moved in: fstat on that descriptor gives the <dev>:<ino> root read
#      before the move. The new id is read from the same descriptor.
#
# A hand swap fails rule 2 or rule 3, so it still refuses as install_moved.
# The answer is rerecorded=1, already_current=1, or refused=<reason>, then
# exit=. The caller believes nothing else.
#
# WHAT THIS PROGRAM CAN DO, which is the whole of the security argument:
#
#   it can APPEND one fleet row pinned to a node key (and, on a first
#   approval into a fleet.yaml with no row on this dashboard's own port, this
#   host's own row beside it, every value of which is root's own fact about
#   this host and none the caller's, #1045), write that row's two
#   token files, add one peer to the Advisor's own registry, send one SIGHUP,
#   keep the fleet's model descriptor at rest (sealed with systemd-creds
#   where this host has it, a root-only 0600 file where it does not, #711),
#   and push that descriptor to one node named by a root-owned file.
#
#   it removes a fleet.yaml row only on `revoke`, and only the row named by
#   the label the caller sends (#859, below); it cannot name a path (every
#   path it writes is derived from the label inside one fixed directory), cannot
#   choose a port (they come from its own pool), cannot restart anything,
#   cannot widen a token file's mode, cannot open an arm window or mint an
#   arm token, and has NO VERB THAT RETURNS THE KEY. (`arm-key-check` only
#   says whether the fleet arm key is there, and the node an approval reads
#   registries back with (#964), and makes nothing.) (#741: `arm-key` returns
#   the PUBLIC half of the fleet arm key, making the key first when there is
#   none and this host never had one and has no paired node; never the
#   private half, and it opens nothing. #851: otherwise it makes nothing and
#   refuses as fleet_arm_key_lost, and `approve` never makes one.) Since the phase-4
#   review it also cannot move the key whenever it likes: a push happens
#   only inside an arming window root opened on this host, and this program
#   reads that marker without ever writing or removing one.
#
#   what it CAN do that an earlier version of this header denied, stated
#   here because a claim that overstates is worse than no claim (P3-060):
#   `revoke` removes a LINK row from fleet-links.json, which is how a live
#   link is closed rather than only the next dial, and deletes that label's
#   two token files (#854), regular files only; since #859 the same press
#   also takes that label's row out of fleet.yaml and its peer out of the
#   Advisor's fleet.json, so a compromised dashboard can remove any node from
#   the fleet (denial of service, the class #854 already accepted) and gains
#   no node, key or destination by it; `repin` (#859) rewrites one fleet.yaml
#   row's expected_pubkey_node from the key the caller says it was to the
#   key it names, and never touches fleet-nodes.conf, so a push still goes
#   only where root's own record says; `place` sets fleet.yaml's
#   owner and mode (the dashboard account, 0644) with none of the mode check
#   the token files get; `model-store-head` reads the sealed descriptor
#   back, minus the key, so the page can say whether a node paired now would
#   inherit a model; and, #620, `approve` with `convert_tunnel=1` changes
#   ONE fleet.yaml row's transport from a tunnel to a link, in place, and
#   only the row already pinned to the presented node key under the SAME
#   label the caller names -- never a row of its choosing, never a rename,
#   and it still cannot APPEND a row pinned to a key that already has one.
#   All of these but the last are not an escalation, for the reason below. The
#   last is narrower than an escalation but is a real change to a node
#   already in the fleet, and it moves three things in root's own record
#   (fleet-nodes.conf), not the port alone: a convert takes a fresh port
#   the same way a first approval does, its token path moves to this
#   program's own convention path (the tunnel row's own token file, wherever
#   it lived, is not the one the converted row reads any more), and the
#   advisor flag in that record is set from what the node's OWN hello says
#   now, which need not be what the tunnel row's file happened to hold. It
#   can never move that node's PIN there: a label root's own record already
#   pins to a key is refused (root_pin_disagrees) unless the presented key
#   agrees with what root already recorded, so rewriting fleet.yaml's pin
#   first and converting under the same label cannot repoint where a push
#   for that label lands.
#
#   #641: `attach-advisor` and `detach-advisor` rewrite two lines,
#   advisor_origin and advisor_token_path, on ONE fleet.yaml row that
#   already exists, pinned to the same key that row already holds under
#   the same label; every other field on that row (read_origin, token_path,
#   dashboard_url, role) is read back exactly what it went in as, checked
#   rather than assumed. Neither verb can APPEND a row, neither can widen a
#   token file's mode, and detach's deletion of the Advisor token file is
#   bounded to the one path this program derives from the label, never a
#   path fleet.yaml itself named. `refresh-advisor-token` replaces that
#   same convention-path file's content on a row already attached; it
#   cannot allocate a port, cannot touch fleet.yaml or fleet-links.json, and
#   cannot flip fleet-nodes.conf's advisor field.
#
#   #648, round 4: there is no migration story here any more, on an
#   operator-level call rather than a code fix. This project has not
#   shipped, the only fleet ever paired under the old advisor/state
#   convention path is the maintainer's own lab aggregator, and a migration
#   function that walks a directory an unprivileged account owns, to carry
#   forward an installed base that does not exist, is a net loss whatever
#   its own guards look like -- round 3's version of that guard was itself
#   the finding two rounds later. TOKEN_DIR sits under $ETC unconditionally
#   now (see its own declaration below); this program never reads from or
#   writes to advisor/state/fleet-tokens or any other legacy path, on any
#   verb, and a fleet.yaml row whose token_path or advisor_token_path still
#   names one is left exactly as it is (write_token already refuses to
#   write outside TOKEN_DIR by name; nothing here ever rewrites a row's
#   path to move it there for you). The one-time move for an existing
#   install some operator's own fleet needs is a hand-run, lab-only script,
#   not a thing this socket does to every connection.
#
# That matters because the passkey gate in front of it lives in the
# dashboard, which is the process an attacker would have. The mitigation is
# therefore the SHAPE OF THE VERB and not the caller: a compromised
# dashboard calling `approve` gets one more node in the fleet, of its
# choosing, and nothing else.
#
# And the honest narrowing of that, which is smaller than it sounds: of the
# five writes, only two are beyond what the dashboard account can already do
# to its own files. fleet.yaml and fleet-links.json are that account's, in a
# config directory it owns, and it can SIGHUP its own process. The two that
# are not are the Advisor's registry (the Advisor account's) and the token
# files (root:<shared group> 0640, so readable by the dashboard and not
# forgeable by it). ADR 0019 decision 4's first row is corrected
# in those words rather than left reading as though this socket enforced the
# ceremony.
#
#   approve          label= pubkey_node= role= advisor= \
#                    credential_sha256= read_token= [dashboard_url=] \
#                    [advisor_token=] [convert_tunnel=] end
#   revoke           label= end
#   repin            label= was_pubkey_node= pubkey_node= end
#   attach-advisor         label= pubkey_node= advisor_token= end
#   detach-advisor         label= end
#   refresh-advisor-token  label= advisor_token= end
#   model-store-put  base_url= shape= model= credential_name= key_hint= \
#                    sealed_by= key= end
#   model-store-head end
#   model-push       label= granted_by= credential_id= end
#                    (refused unless root has a window open here:
#                     /etc/aperire/model-key.arm, 900 s, not spent)
#
#   (argv, root only, never the socket)
#   --rerecord-install-dir --previous <tree> --expect <dev>:<ino>
#
# Values are percent-encoded outside [A-Za-z0-9._:/-] so a token cannot forge
# a line boundary. Codes: 0 ok, 3 refused, 1 failed.
#
# THE KEY'S PATH, phase 4, and it is the checklist item the rest of this file
# is arranged around. The key arrives on stdin, lives in one shell variable,
# and leaves on a pipe: to `systemd-creds encrypt` when it is stored on a
# host that has it, to dirsafe.py's "put" on its stdin when it is stored on
# one that does not (#711), to the local sealer's stdin or to
# `curl --data-binary @-` when it is pushed. Never an argument, never the
# environment, never a staging file: on the plain form the only file it is
# written to is the store itself, created 0600 under $ETC's descriptor and
# renamed onto its name. No verb prints
# it, on success or on any refusal. The node's read token takes the same care
# for the same reason and rides a 0600 `curl --config` file rather than an
# argument, because /proc/<pid>/cmdline is world readable and a push holds
# that process for minutes.
#
# The one journal line per invocation carries the verb, the label and the
# exit code. Nothing decrypted, and both values stripped of anything outside
# the set a verb or a label can hold: the journal is world readable on a
# default host, and a log an attacker can compose is worse than no log.
#
# ALL THREE CANDIDATES OR NONE. loadFleetLinks() empties the link table and
# reconciles on ANY cross-check disagreement, so a SIGHUP observed between
# the fleet.yaml append and the fleet-links.json write tears down every live
# link on the fleet. One approval must never be able to do that, so the three
# files are built as candidates, validated together with the services' own
# parsers, and renamed into place only when all three agree.
#
# AND NOTHING OUT OF THE INSTALL TREE IS RUN BY ROOT (#370). That validation
# imports the dashboard's own TypeScript, out of a checkout that belongs to
# the dashboard's account, through a tsx in that same tree. Root importing a
# module that account can rewrite is root for that account, which is the one
# rule this whole grant is built on: it is why the broker itself is copied to
# /usr/local/sbin. So the validation runs AS the dashboard, through
# `runuser -u`, with the two candidates copied into a directory that account
# can read and cannot write, never the other way round. What crosses back to
# root is one short verdict on stdout, matched against a fixed set of words;
# the sentence an operator reads is root's own, and stderr is captured to a
# file so it cannot reach this socket. A host with no runuser refuses by
# name rather than falling back to running it as root.
#
# Two things this deliberately leaves, because a future reader will ask.
# Root still READS files that account owns (fleet.yaml, fleet-links.json,
# the Advisor's registry) with python3, which is parsing data and not
# executing a module -- but never by path a second time: every one of those
# reads goes through snap_fleet_yaml/snap_fleet_links/snap_adv_fleet first
# (#648, round 4), which take the file by descriptor out of a directory that
# account owns, refuse anything that is not a plain file it could itself have
# left, and never block this connection open on a FIFO planted where a
# registry should be. What python3 parses afterward is root's own snapshot in
# $WORK, not the live file. And NODE_BIN may resolve under that account's
# home, which is now harmless for the same reason as everything else here:
# the binary is run as that account, so swapping it buys the swapper nothing
# it did not already have.
set -euo pipefail
# #854 security review (L5): LABEL_RE's bracket classes are locale-dependent
# in bash -- under a UTF-8 locale with certain collations, [a-z] can widen to
# admit accented letters, which would let a label through that every other
# tool on this host (python3's regex, the dashboard's own LABEL_RE) reads as
# ASCII-only and refuses. Fixed once, here, for the whole program: every
# [[ =~ ]] below runs under the C locale, so [a-z0-9-] means exactly those
# 37 bytes regardless of what systemd or the shell's own environment set.
export LC_ALL=C

ETC="${APERIRE_ETC:-/etc/aperire}"
CONF="$ETC/fleet-broker.conf"
UNIT_DIR="${APERIRE_UNIT_DIR:-/etc/systemd/system}"
ARM_KEY="$ETC/fleet-arm.key"
# #741: the command a node's operator is told to run on this host for the
# pairing fingerprint. `arm-key` refuses while it is not installed, so no
# welcome is sent that asks the operator for a value they cannot get.
# The constant: as root this program never takes the path from its environment
# (#1123, set again below only for an account that is not root).
FLEET_ARM_PROGRAM=/usr/local/sbin/aperire-fleet-arm
# ── phase 4 ──────────────────────────────────────────────────────────────
# Where a push may send, and nowhere else. Root's own record of the fleet:
# one line per node,
#
#   <label> <pubkey_node> <read_port> <advisor 0|1> [read token path]
#
# NOT fleet.yaml, which belongs to the dashboard account: a destination the
# dashboard can rewrite is a destination it can point at itself.
#
# The fifth field is the row's read token, and it is there only when the
# registry names a path other than the one this program writes on approve
# (#458). A node registered through aperire-fleet-add.sh keeps its token
# wherever the operator put it, the dashboard's own seal reads that path out
# of the registry row, and a push that derived the path from the label
# instead refused a node the seal had just reached: two readers of one row,
# two answers. Absent means the convention path, which is what an approval
# writes and what all but a hand-registered fleet has.
#
# Root's record carries it rather than the refresh placing a copy at the
# convention path, because two copies of a bearer token are equal only at
# the moment they are made. One token, one row, and the path enters this
# file the way the pin and the port do: through an explicit root act.
NODES_CONF="$ETC/fleet-nodes.conf"
# How this host keeps a model key at rest, and where each form lives (#711).
#
# The block between the KEY-METHOD-LIB markers is scripts/model-key-method-
# lib.sh's own text, byte for byte, the one decision the Advisor's sealer,
# its credential check, its installer and both preflights make (#708). It is
# copied here rather than sourced because this program is installed to
# /usr/local/sbin as ONE file with no sibling library (the same reason the
# DIRSAFE-PY block below is a copy), and a sibling it depended on would be
# refreshed and removed on the Advisor's schedule, not on this program's: an
# aggregator with no Advisor has no /usr/local/sbin/aperire-model-key-method
# at all. scripts/test-fleet-broker.sh extracts both copies and diffs them,
# so the two drifting apart fails CI rather than silently.
# --- KEY-METHOD-LIB-BEGIN ---
# The suffix, in one place. Named rather than spelled inline anywhere else so
# a change here cannot leave half the tree looking at the other name.
APERIRE_KEY_PLAIN_SUFFIX='.plain'

# aperire_systemd_major. Prints this host's systemd major version, or fails.
#
# The leading run of digits out of the second field, the same rule
# scripts/preflight.sh reads it with: the first line is "systemd 255
# (255.4-1ubuntu8.17)" on one host and carries a distro suffix on another, and
# taking the field whole compares "255" with "249~rc1".
aperire_systemd_major() {
  local line ver
  line="$(systemctl --version 2>/dev/null | head -1)"
  [[ -n "$line" ]] || return 1
  ver="$(printf '%s' "$line" | awk '{print $2}' | grep -oE '^[0-9]+')"
  [[ -n "$ver" ]] || return 1
  printf '%s\n' "$ver"
}

# aperire_key_method. Prints `sealed` or `plain`. Never fails: every host has
# one of the two, and a host this cannot measure gets the method that works
# everywhere.
#
# Both halves are asked, not just the version. A minimal image can carry
# systemd 255 with the systemd-creds binary split into a package that is not
# installed, and a version test alone would send that host down a path whose
# first command is not there.
aperire_key_method() {
  local ver
  command -v systemd-creds >/dev/null 2>&1 || { printf 'plain\n'; return 0; }
  # Only a version this host will actually say, and says is older than 250,
  # sends it down the fallback from here. A version that cannot be read is not
  # evidence of anything, and the binary being on the PATH is the stronger
  # fact: a host whose systemd-creds runs can seal, whatever `systemctl
  # --version` did or did not print.
  ver="$(aperire_systemd_major)" || { printf 'sealed\n'; return 0; }
  if (( ver >= 250 )); then printf 'sealed\n'; else printf 'plain\n'; fi
}

# aperire_key_method_line. One sentence for an operator, said by both
# preflights and by the model setup, so a host tells you up front how it will
# keep the key rather than at the first failure.
aperire_key_method_line() { # $1 = method (optional; measured when absent)
  local method="${1:-}" ver
  [[ -n "$method" ]] || method="$(aperire_key_method)"
  ver="$(aperire_systemd_major || true)"
  if [[ "$method" == sealed ]]; then
    printf 'sealed to this machine with systemd-creds (systemd %s)\n' "${ver:-unknown}"
  elif command -v systemd-creds >/dev/null 2>&1; then
    printf 'a root-only file loaded with LoadCredential= (systemd %s is older than 250, which is where systemd-creds began)\n' "${ver:-unknown}"
  else
    printf 'a root-only file loaded with LoadCredential= (this host has no systemd-creds)\n'
  fi
}

# aperire_key_blob_path $1=creds dir $2=credential name $3=method.
aperire_key_blob_path() {
  case "$3" in
    plain) printf '%s/%s%s\n' "$1" "$2" "$APERIRE_KEY_PLAIN_SUFFIX" ;;
    *)     printf '%s/%s\n' "$1" "$2" ;;
  esac
}

# --- KEY-METHOD-LIB-END ---

# The fleet's model descriptor, kept at rest on this host in ONE of two forms,
# the same two the Advisor's own model key has (#708, #711), told apart by
# the name that is on disk and never by a flag that could disagree with it:
#
#   sealed  $ETC/fleet-model.cred, one systemd-creds blob sealed to this
#           machine. A host with systemd 250 or newer and systemd-creds.
#   plain   $ETC/fleet-model.cred.plain, the same JSON object in the clear.
#           A host without them: Ubuntu 22.04 and its systemd 249.
#
# Root:root 0600 either way, and checked for both before it is read. The
# plaintext inside is one JSON object, the key included, so the plain form is
# a working provider key wherever a copy of it lands: it lives in $ETC and
# NOT in $ETC/creds, because the Advisor's sealer sweeps every *.plain in
# there on each seal and reset, and it is left out of every backup set by
# name for the same reason the creds directory is.
#
# A put writes the form this host measures and then removes the other one,
# so a host that is upgraded from 22.04 converges on its next seal and never
# keeps a plaintext copy beside a sealed one.
STORE="$ETC/fleet-model.cred"
STORE_PLAIN_FILE="$(aperire_key_blob_path "$ETC" fleet-model.cred plain)"
# Pinned on encrypt AND on decrypt. `systemd-creds decrypt` refuses a name
# that does not match, so a blob sealed for something else on this host
# cannot be read here by pointing this path at it.
STORE_CRED_NAME=aperire-fleet-model
# The local sealer, for a `self` push. Root to root, over no socket: this
# program IS root, and the installed copy is root's own.
SEALER=/usr/local/sbin/aperire-seal-model-key
# THIS AGGREGATOR's own arming marker, and the window it means. The same file
# install-model-key-sealer.sh --arm and aperire-fleet-arm.sh --self-only
# write, and the same 900 s the local sealer already reads it with. A push
# moves the key only while root has this window open here (security review,
# finding F1).
ARM_FILE="${APERIRE_ARM_FILE:-$ETC/model-key.arm}"
ARM_WINDOW_SEC="${APERIRE_ARM_WINDOW_SEC:-900}"
# The dashboard's fleet-trust seed, which signs a job for a peer. Read at the
# moment of a push and never kept.
FLEET_TRUST_REL=dashboard/config/fleet-trust.yaml
# The contract's own two constants, re-declared here because bash cannot
# import. scripts/test-fleet-broker.sh holds both against
# dashboard/types/fleet-write-contract.ts, by fixture and not by comment.
FLEET_WRITE_PROTOCOL_VERSION=1
FLEET_WRITE_ISSUER_LABEL=aggregator
# The contract's own bound on a bearer token this program writes into
# TOKEN_DIR, re-declared here because bash cannot import.
# scripts/test-fleet-broker.sh holds this against
# dashboard/types/fleet-link-contract.ts's own FLEET_PAIR_MAX_TOKEN_CHARS.
FLEET_PAIR_MAX_TOKEN_CHARS=512

# `trap '' PIPE` and a tolerant printf: the reader is the dashboard, and a
# reader that goes away must not end this run between two file renames.
trap '' PIPE
out()  { printf '%s\n' "$*" 2>/dev/null || true; }
fact() { printf '%s=%s\n' "$1" "$2" 2>/dev/null || true; }
# Every path ends here, and every path ends with `exit=`. FINISHED is what
# the EXIT trap below reads to tell a completed run from a shell that died
# under `set -e`, which is a thing that happened (#318) and which no caller
# can diagnose: a stream with no `exit=` line is the "no answer" state
# lib/fleet-broker.ts has to call indeterminate.
# Set before the trap is laid: it names both, and under `set -u` a trap that
# reads an unset name fails at the one moment the program is already failing.
# The directory the validation reads its candidates out of, as the dashboard
# account (#370). Named here with the other two, and for the same reason: the
# EXIT trap reads it, `set -u` makes an unset name fatal inside the one
# function whose job is to say what happened, and it is set far below.
VWORK=""
FINISHED=0
# ONE LINE PER INVOCATION, in the journal, naming what this run was and how it
# ended. The header and the design both said this happened and nothing wrote
# it (security review, finding F4): a root program reached through a socket
# that leaves no trace is a program whose history an operator cannot read
# after an incident.
#
# The verb, the label and the exit code, and nothing else. No decrypted field
# and no free text from the payload: the journal is world readable on a
# default host, so anything that could carry a secret or a forged line is not
# put in it. LABEL is set by the verbs that have one and is empty elsewhere.
LABEL_FOR_LOG=""
journal() {  # <exit code>
  local v l
  command -v logger >/dev/null || return 0
  # Both of these come off the payload, and one of them may not have been
  # validated yet when a run ends early. Anything outside the set a label or a
  # verb can hold is dropped rather than escaped: a value that could carry a
  # newline could write a second journal line, and a log an attacker can
  # compose is worse than no log.
  # `${VAR-}` first: a run can end before the payload has been read at all,
  # and `set -u` makes an unset name a fatal error inside the one function
  # whose job is to say what happened.
  v="${VERB-}"; v="${v//[^A-Za-z0-9._:-]/}"
  l="${LABEL_FOR_LOG-}"; l="${l//[^A-Za-z0-9._:-]/}"
  logger -t aperire-fleet-broker -p daemon.info -- \
    "verb=${v:-none} label=${l:-none} exit=$1" 2>/dev/null || true
}
finish() { FINISHED=1; journal "$1"; fact exit "$1"; exit "$1"; }
# The argv mode (#828), decided before anything can refuse, so that every
# refusal on that path, the conf's own included, carries `refused=` as well
# as `error=`. The update believes only rerecorded=, already_current= and
# refused=: an older broker that ignores argv answers with none of them, and
# that is how the update tells "this broker said no" from "this broker does
# not have the mode".
RERECORD=0
[[ "${1:-}" == --rerecord-install-dir ]] && RERECORD=1
if (( RERECORD == 1 )); then VERB=rerecord-install-dir; fi
refuse() { fact error "$1"; (( RERECORD == 0 )) || fact refused "$1"; out "$2"; finish 3; }
fail()   { fact error "$1"; (( RERECORD == 0 )) || fact refused "$1"; out "$2"; finish 1; }

[[ $EUID -eq 0 ]] || fail not_root "this program is root's; it is reached through a systemd socket, and by root's update with argv"
# Whose account this is, from id(1), never from bash's $EUID, which bash imports
# from the environment (#1109). The gate above refuses a root shell whose EUID
# was set to a login's uid; every owner this program then writes is taken from
# here, so none of them can be that uid either.
BROKER_UID="$(/usr/bin/id -u 2>/dev/null)" || fail not_root "this program could not read its own account"
# APERIRE_FLEET_ARM_PROGRAM is a test hook, and a root that honoured it would
# take the word of whoever set its environment about which file is "the
# fingerprint command" (#1123). Only an account that is not root may move it.
[[ "$BROKER_UID" == 0 ]] || FLEET_ARM_PROGRAM="${APERIRE_FLEET_ARM_PROGRAM:-$FLEET_ARM_PROGRAM}"
# The same for the local sealer a `self` push pipes the model key into (#1148):
# a root that honoured APERIRE_SEALER_PATH would hand the key to whatever
# program the environment named.
[[ "$BROKER_UID" == 0 ]] || SEALER="${APERIRE_SEALER_PATH:-$SEALER}"

# The argv mode's own arguments, exactly these and in this order. Anything
# else on the command line is refused rather than ignored: a mode that
# guessed at what it was asked would be a mode that wrote the conf for a
# question nobody asked.
RR_PREVIOUS="" RR_EXPECT=""
if (( RERECORD == 1 )); then
  [[ $# -eq 5 && "$2" == --previous && "$4" == --expect ]] \
    || refuse bad_args "the only command line this program takes is --rerecord-install-dir --previous <tree> --expect <dev>:<ino>. Nothing was written"
  RR_PREVIOUS="$3" RR_EXPECT="$5"
  [[ "$RR_PREVIOUS" == /* ]] \
    || refuse bad_args "--previous is not an absolute path. Nothing was written"
  [[ "$RR_EXPECT" =~ ^[0-9]+:[0-9]+$ ]] \
    || refuse bad_args "--expect is not <dev>:<ino>. Nothing was written"
fi

# ── the conf ─────────────────────────────────────────────────────────────
# Root-owned, 0644, written by the grant installer. Nothing here comes from
# the payload: the install directory, the port pool and the dashboard unit
# are facts about this host, and a caller that could name them could name a
# path.
INSTALL_DIR=""
FLEET_LINK_PORT_MIN=7900
FLEET_LINK_PORT_MAX=7999
# The pm2 fallback's account, its home and the process name (#310). Empty
# means "this host has no pm2 dashboard", which is every host with a unit.
PM2_ACCOUNT=""
PM2_HOME_DIR=""
PM2_PROCESS="aperire-aggregator"
# The pm2 binary, by ABSOLUTE PATH. Not a bare name: this program runs from a
# systemd socket with systemd's PATH, `runuser` without --login preserves
# that environment, and a pm2 installed under the account's nvm is on none of
# it. Asking PATH would have reported a pm2 failure on a host where pm2 is
# fine, which is the same trap the pinned Go install laid on 2026-09-01. The
# grant installer resolves it as the account, through a login shell.
PM2_BIN=""
# The node binary, by ABSOLUTE PATH, for the same reason PM2_BIN is (#318).
# This program runs from a systemd socket with systemd's PATH, `su` to the
# dashboard account is not available to it in every arrangement, and a node
# installed under that account's nvm is on none of it. The candidates are
# read back with the dashboard's own parsers before anything is renamed into
# place, so a node this program cannot find is an approval it must refuse
# outright. The grant installer resolves it as the account, through a login
# shell. Empty means "ask the host at run time", which is the fallback below.
NODE_BIN=""
# The account the DASHBOARD runs as, read by the grant installer from that
# unit's own `User=` and pinned here (#370). The candidates are validated as
# this account and never as root, so this is the identity a module out of the
# install tree gets to run with. Pinned rather than worked out at run time:
# the whole point is that it is a fact about this host, decided by root when
# the grant was installed, and an approval on a host whose grant predates
# this key is refused by name rather than validated as root.
DASH_ACCOUNT=""
# The install directory's own identity, "<st_dev>:<st_ino>", recorded by the
# grant installer when it read that directory (#648, round 9). INSTALL_DIR is
# a PATH, and a path is only ever as trustworthy as every directory above it:
# an install under an operator's home has ancestors that account owns, and
# renaming one of them points this program's own anchor at a different tree
# between one write and the next, with no symlink for the chain walk to
# catch. An inode cannot be renamed into place, so this is what the walk
# compares the directory it actually opened against.
INSTALL_DIR_ID=""
if [[ -r "$CONF" ]]; then
  # Read as key=value, never sourced: a conf file that is `source`d is a
  # shell script root runs.
  #
  # One line per key, and no control character in any value (#970 review,
  # M1). The grant writes values it probed off the host, a PATH entry among
  # them, and a directory name can hold a newline: one value would then read
  # here as two lines, and with the last key winning, the second line would
  # name PM2_ACCOUNT, PM2_BIN, INSTALL_DIR or the port pool for root. So a key
  # seen twice is refused, not resolved, and so is a value with a control
  # character in it (this program runs under LC_ALL=C, so that class is the
  # ASCII controls). The grant refuses to write either.
  declare -A CONF_SEEN=()
  while IFS='=' read -r k v; do
    k="${k%%[[:space:]]*}"
    [[ -z "${CONF_SEEN[$k]:-}" ]] \
      || fail bad_conf "$CONF names $k more than once, so this program cannot tell which one root meant. Re-run install-fleet-broker-grant.sh, which writes each key once"
    CONF_SEEN[$k]=1
    [[ "$v" != *[[:cntrl:]]* ]] \
      || fail bad_conf "$CONF has a control character in the value for $k, so it is not one this program will take. Re-run install-fleet-broker-grant.sh"
    v="${v%\"}"; v="${v#\"}"
    case "$k" in
      INSTALL_DIR) INSTALL_DIR="$v" ;;
      FLEET_LINK_PORT_MIN) FLEET_LINK_PORT_MIN="$v" ;;
      FLEET_LINK_PORT_MAX) FLEET_LINK_PORT_MAX="$v" ;;
      PM2_ACCOUNT) PM2_ACCOUNT="$v" ;;
      PM2_BIN) PM2_BIN="$v" ;;
      NODE_BIN) NODE_BIN="$v" ;;
      DASH_ACCOUNT) DASH_ACCOUNT="$v" ;;
      INSTALL_DIR_ID) INSTALL_DIR_ID="$v" ;;
      PM2_HOME_DIR) PM2_HOME_DIR="$v" ;;
      PM2_PROCESS) PM2_PROCESS="$v" ;;
    esac
    # `[A-Z_]+` would not match PM2_ACCOUNT, because of the digit. That is
    # #293's lesson and it has now cost this project three separate bugs:
    # a key-name pattern is ^[A-Z][A-Z0-9_]*$, the same shape as the
    # lower-case one the payload grammar uses.
  done < <(grep -E '^[A-Z][A-Z0-9_]*=' "$CONF" || true)
fi
[[ -n "$INSTALL_DIR" ]] || fail no_conf "$CONF does not name an INSTALL_DIR, so this program does not know which tree to write. Re-run install-fleet-broker-grant.sh"
[[ -d "$INSTALL_DIR/dashboard" ]] || fail no_install "$INSTALL_DIR does not look like an Aperire install"
# Refused rather than treated as "no pin, carry on": a missing or malformed
# value here is a grant written before this check existed, and running
# without it is exactly the state round 9's attack needs. The fix is one
# command, and the refusal names it. The same command is also the fix after
# a move: the install directory's inode changes when the tree is copied
# somewhere else, and this program cannot tell that apart from the swap it
# is looking for, so it refuses both and lets the operator say which it was.
[[ "$INSTALL_DIR_ID" =~ ^[0-9]+:[0-9]+$ ]] \
  || fail bad_conf "$CONF does not record which directory $INSTALL_DIR is (INSTALL_DIR_ID), so this program cannot tell that tree apart from another one moved into its place. Re-run install-fleet-broker-grant.sh on this host, which is what records it"
[[ "$FLEET_LINK_PORT_MIN" =~ ^[0-9]+$ && "$FLEET_LINK_PORT_MAX" =~ ^[0-9]+$ ]] \
  || fail bad_conf "the port pool in $CONF is not two numbers"
(( FLEET_LINK_PORT_MIN >= 1024 && FLEET_LINK_PORT_MAX <= 65535 && FLEET_LINK_PORT_MIN < FLEET_LINK_PORT_MAX )) \
  || fail bad_conf "the port pool in $CONF is not a usable range"

# Anchored like PM2_BIN, and for the same reason: this becomes a program root
# runs, so a relative path out of a root-owned conf is refused rather than
# resolved against whatever directory the socket happened to start this in.
[[ -z "$NODE_BIN" || "$NODE_BIN" == /* ]] \
  || fail bad_conf "NODE_BIN in $CONF is not an absolute path"

# Anchored here for the same reason, and checked again where it is used: this
# becomes an identity root switches to. A conf this program cannot make sense
# of is a conf it refuses rather than one it interprets generously.
[[ -z "$DASH_ACCOUNT" || "$DASH_ACCOUNT" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] \
  || fail bad_conf "DASH_ACCOUNT in $CONF is not a user name"

# These three become an account root switches to and a process name root
# signals, so they are anchored here even though only root can write the
# file they come from. A conf this program cannot make sense of is a conf it
# refuses rather than one it interprets generously.
if [[ -n "$PM2_ACCOUNT" ]]; then
  [[ "$PM2_ACCOUNT" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] \
    || fail bad_conf "PM2_ACCOUNT in $CONF is not a user name"
  # root, by name and by number, the same pair of refusals DASH_ACCOUNT
  # already gets at its own point of use. The name regex above matches
  # "root" perfectly well, and this is an identity root switches TO: a
  # runuser to root is not a drop at all, it is the program running the
  # account's own pm2 and PATH as root. The grant installer refuses to
  # write this value; this is the same rule at the point of use, because a
  # conf is a file and a check is a check.
  [[ "$PM2_ACCOUNT" != root ]] \
    || fail bad_conf "PM2_ACCOUNT in $CONF is root, and the reload is never run as root"
  [[ "$(id -u "$PM2_ACCOUNT" 2>/dev/null || echo -1)" != 0 ]] \
    || fail bad_conf "the account PM2_ACCOUNT names in $CONF is uid 0, and the reload is never run as root"
  [[ "$PM2_PROCESS" =~ ^[A-Za-z0-9._-]{1,64}$ ]] \
    || fail bad_conf "PM2_PROCESS in $CONF is not a process name"
  [[ -z "$PM2_HOME_DIR" || "$PM2_HOME_DIR" == /* ]] \
    || fail bad_conf "PM2_HOME_DIR in $CONF is not an absolute path"
  [[ -z "$PM2_BIN" || "$PM2_BIN" == /* ]] \
    || fail bad_conf "PM2_BIN in $CONF is not an absolute path"
fi

CONFIG_DIR="$INSTALL_DIR/dashboard/config"
FLEET_YAML="$CONFIG_DIR/fleet.yaml"
FLEET_LINKS="$CONFIG_DIR/fleet-links.json"
ADV_STATE="$INSTALL_DIR/advisor/state"
ADV_FLEET="$ADV_STATE/fleet.json"
# TOKEN_DIR sits under $ETC, never under $ADV_STATE (round 3 review,
# CRITICAL). $ADV_STATE is install-advisord.sh's own working tree for the
# account advisord runs as, unprivileged by design, and owning a directory
# means owning every entry inside it: that account could always rename or
# symlink-swap a "fleet-tokens" entry there, whatever THAT entry's own mode
# said, because renaming an entry is a permission of the PARENT, never of
# the entry itself. $ETC's own ancestors (/etc/aperire, /etc, /) are root's
# on any host this ever runs on, the same as fleet-nodes.conf and
# fleet-model.cred already are, so the rename that account could always
# reach here is a rename it can no longer reach at all, not a faster check
# for the same reachable one (see ensure_token_dir and write_token below).
# There is no LEGACY_TOKEN_DIR any more (#648, round 4): this program never
# reads from or writes to advisor/state/fleet-tokens, on any verb, on any
# host. An existing fleet still naming that path in a row's token_path or
# advisor_token_path is left exactly as it is -- write_token already refuses
# to write anywhere but TOKEN_DIR by name -- and carrying such a fleet across
# is a one-time, hand-run migration kept out of the release, never a thing
# this socket does to a connection nobody asked to migrate anything on.
TOKEN_DIR="$ETC/fleet-tokens"

command -v python3 >/dev/null || fail no_python3 "python3 is not on this host, and this program will not write a registry it cannot read back"

WORK="$(umask 077; mktemp -d)"

# ── the directory-safe primitive (#648, round 7, review7-0.json CRITICAL) ──
#
# Written into $WORK (root's own private mktemp -d, mode 0700) exactly once,
# per connection, and cleaned up for free when $WORK is removed below: never
# a second copy in this program to drift from the one install-fleet-broker-
# grant.sh carries for its own, separately-deployed, root-only writes.
# test-fleet-broker.sh and test-install-fleet-broker-grant.sh both extract
# their copy between the DIRSAFE-PY markers and diff them byte for byte, so
# a change to one that is not made to the other fails CI rather than
# drifting silently the way place()'s own body once could have.
#
# What it is FOR and why every root write below now goes through it is the
# whole of dirsafe.py's own header, not repeated here.
# --- DIRSAFE-PY-BEGIN ---
cat > "$WORK/dirsafe.py" <<'DIRSAFE_PY_EOF'
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

# anchor relpath extra-uid write-mask op [op-args...] -- see dirsafe.py's own
# header for the full contract. Every call site below names its own anchor
# and relpath from the fixed directories this program already declared
# above ($CONFIG_DIR, $ADV_STATE, $ETC, $TOKEN_DIR), compared as PLAIN
# STRINGS against a target this program built itself -- never by asking the
# filesystem to resolve anything, which is exactly the step dirsafe.py's own
# walk exists to be the only place that happens.
# The pin travels for an INSTALL_DIR anchor and for nothing else (#648,
# round 9): $ETC, the unit directory and /usr/local/sbin have root's own
# ancestors, and pinning them would only add a value to keep in step. Which
# anchor this call names is decided by a STRING COMPARISON against the
# variable this program already read from the root-owned conf, never by
# asking the filesystem what any path resolves to, which is the question
# dirsafe.py exists to be the only place that asks.
dirsafe() {
  local pin=""
  [[ -n "${INSTALL_DIR:-}" && "${1:-}" == "${INSTALL_DIR:-}" ]] && pin="${INSTALL_DIR_ID:-}"
  DS_ANCHOR_PIN="$pin" python3 "$WORK/dirsafe.py" "$@"
}

# ── the anchor, asked ONCE, up front (#648 round 9, #701) ───────────────
#
# Without this the pin still holds, and says the wrong thing: the first
# refusal would be whichever write happened to come first, reported as
# "fleet.yaml could not be written", and restore_all would then walk every
# backed-up leg through the same refused anchor and report all of them as
# files it could not put back. Nothing had been touched. An operator who
# moved their install, or whose disk came back with a different device
# number after a reboot, would be told to check four files by hand and
# never told the one thing that fixes it.
#
# So it is asked here, before any verb runs and before anything is backed
# up, with the one op that asks about the ANCHOR ITSELF and nothing else:
# "identity", which opens the anchor, checks it is a directory, checks its
# mode, compares it against the pin, prints which directory it is, and
# reads, writes and removes nothing. Status 0 means the anchor is the
# recorded directory. Status 2 is the anchor being refused, which is this
# refusal's whole subject.
#
# WHY NOT A READ OF A NAME THAT IS NOT THERE (#701). Round 9 asked this with
# `read`, naming an EMPTY extra uid, and in dirsafe.py an empty extra uid is
# two facts at once, not one: only root may own a hop, AND the anchor's own
# owner is not trusted (`trust_anchor_owner = bool(extra_uid)`). Every other
# call that walks from this anchor names the ONE account that subtree belongs
# to, so it gets the round-7 INSTALL_DIR rule and the anchor's own owner is
# trusted. This call names no subtree, so it had nothing to name, and it got
# $ETC's strict rule by accident: root, and nobody else, may own the anchor.
# $INSTALL_DIR belongs to the dashboard account on every install this program
# has ever served (/home/<account>/aperire-one, that account's own uid), never
# to root. So it refused every verb on every aggregator, before any verb body
# ran, and the page reported it as a moved install. The journal line was
# `verb=none label=none exit=1`.
#
# "identity" is the same question with no owner rule to get wrong, which is
# what an anchor-only call wants: for an INSTALL_DIR anchor the owner rule is
# "trust the owner" anyway, so with no hop below the anchor the two are the
# same check. Every OTHER INSTALL_DIR call still names its account, and $ETC,
# the unit directory and /usr/local/sbin keep the strict rule, unchanged. If
# this call ever grows a relative path it needs an extra uid again, because
# then there are hops below the anchor for an owner rule to be about.
# ── the argv mode, #828: re-record the pin for the tree an update swapped in ──
#
# Here, before the anchor check below, because the state this mode exists
# for is exactly the one that check refuses: the update has just renamed a
# new tree into $INSTALL_DIR, and the pin still names the tree it moved
# aside. The rules are in the header. It reads no stdin at all.
#
# There is no EXIT trap yet at this point in the program (it is laid after
# the anchor check), so this one is its own: $WORK goes, and a run that dies
# under `set -e` still ends with `refused=` and `exit=` rather than silence,
# which the update would otherwise have to read as an older broker.
rerecord_install_dir() {
  local rc=0 src="" prev_id="" new_id="" conf_mode tmp
  # shellcheck disable=SC2317,SC2329  # reached by the trap below
  rr_cleanup() {
    rm -rf "$WORK"
    if [[ "$FINISHED" != "1" ]]; then
      fact error internal
      fact refused internal
      out "this program ended before it could say what it did. Nothing was written"
      journal 1
      fact exit 1
    fi
  }
  trap rr_cleanup EXIT

  # Rule 0: the pin is already current. Asked through dirsafe() so the pin
  # travels, which is the whole question. An update whose re-record was
  # refused, followed by a rollback that put the recorded tree back, lands
  # here, and nothing is written.
  if dirsafe "$INSTALL_DIR" "" "" 002 identity >/dev/null 2>&1; then
    fact already_current 1
    out "$INSTALL_DIR is already the directory this host's grant recorded. Nothing was written"
    finish 0
  fi

  # Rule 1: the tree the caller says it moved aside is $INSTALL_DIR's own
  # sibling, named the way an update or a rollback names it, by string. This
  # is also where the caller's own idea of the install directory (its
  # update.conf, or --dir) is held to the conf's: a different spelling of
  # the same path is a different string, and is refused by name.
  local suffix
  case "$RR_PREVIOUS" in
    "$INSTALL_DIR".previous-*|"$INSTALL_DIR".rolled-back-*) suffix="${RR_PREVIOUS#"$INSTALL_DIR".}" ;;
    *) refuse not_a_sibling "$RR_PREVIOUS is not $INSTALL_DIR.previous-* or $INSTALL_DIR.rolled-back-*, the names an update and a rollback give the tree they move aside, so it is not a tree this program re-records from. $CONF names $INSTALL_DIR as the install. Nothing was written" ;;
  esac
  # The only guard on --previous against `/` and `..`: the case glob above
  # matches across `/`, and dirsafe.py resolves its anchor by path. So both
  # are refused by name, and the character class leaves room for neither.
  [[ "$suffix" =~ ^(previous|rolled-back)-[A-Za-z0-9-]+$ && "$suffix" != */* && "$suffix" != *..* ]] \
    || refuse not_a_sibling "$RR_PREVIOUS is not a name an update or a rollback gives the tree it moves aside. Nothing was written"

  # Rule 2: that tree IS the recorded directory. No pin and mask 000: this
  # is a comparison of two values, and the moved-aside tree's own mode is
  # not the question. A symlink there is still refused (open_chain opens the
  # anchor O_NOFOLLOW), and an empty answer is a refusal.
  read -r src prev_id \
    < <(DS_ANCHOR_PIN="" python3 "$WORK/dirsafe.py" "$RR_PREVIOUS" "" "" 000 identity 2>/dev/null || true) || true
  [[ -n "$prev_id" && "$prev_id" == "$INSTALL_DIR_ID" ]] \
    || refuse previous_not_recorded "$RR_PREVIOUS is not the directory this host's grant recorded ($INSTALL_DIR_ID), so this program cannot tell that the pin was valid before the swap, or that the swap moved the recorded tree aside. The pin is left as it is. Re-record it by hand: curl -fsSL https://get.aperire.one | bash -s -- --dir $INSTALL_DIR --run fleet-broker-grant"

  # Rule 3: $INSTALL_DIR is the directory root read before it moved in.
  # dirsafe.py opens it O_NOFOLLOW, compares fstat on that descriptor with
  # --expect (exit 3 on a different directory), and prints the id of that
  # same descriptor. Called directly with DS_ANCHOR_PIN empty, never through
  # dirsafe(): the wrapper would carry the pin rule 0 just found stale, and
  # the anchor would refuse before the comparison that matters was made.
  # ONE call: the check and the id it prints come off one descriptor.
  rc=0
  DS_ANCHOR_PIN="" python3 "$WORK/dirsafe.py" "$INSTALL_DIR" "" "" 002 identity "$RR_EXPECT" \
    > "$WORK/rerecord.id" 2>/dev/null || rc=$?
  case "$rc" in
    0) : ;;
    3) refuse not_the_swapped_tree "$INSTALL_DIR is not the directory the update moved in (the update read $RR_EXPECT before the move). Something replaced it in between. The pin is left as it is. Nothing was written" ;;
    *) refuse install_unsafe "$INSTALL_DIR could not be opened as a directory only its owner can write, so its id is not re-recorded. Look at it with: stat -c '%A %U %G %n' $INSTALL_DIR. Nothing was written" ;;
  esac
  read -r src new_id < "$WORK/rerecord.id" || true
  [[ "$src" =~ ^(fsid|dev)$ && "$new_id" =~ ^[0-9]+:[0-9]+$ ]] \
    || fail no_identity "could not read which directory $INSTALL_DIR is. Nothing was written"

  # The conf, with exactly one line changed. Read through dirsafe.py from
  # $ETC (root's own directory, mask 022), and written back the same way the
  # installer wrote it, with the mode it has now. Exactly one INSTALL_DIR_ID
  # line, or nothing is written: a conf with two would leave the reader's
  # last-one-wins rule to decide which pin holds.
  tmp="$WORK/fleet-broker.conf.new"
  dirsafe "$ETC" "" "" 022 read "$(basename -- "$CONF")" "$WORK/fleet-broker.conf.now" 65536 >/dev/null 2>&1 \
    || fail conf_unreadable "could not read $CONF back to change it. Nothing was written"
  awk -v id="$new_id" '
    /^INSTALL_DIR_ID=/ { print "INSTALL_DIR_ID=" id; n++; next }
    { print }
    END { exit (n == 1 ? 0 : 1) }' "$WORK/fleet-broker.conf.now" > "$tmp" \
    || refuse bad_conf "$CONF does not carry exactly one INSTALL_DIR_ID line, so this program will not choose which one to change. Re-run curl -fsSL https://get.aperire.one | bash -s -- --dir $INSTALL_DIR --run fleet-broker-grant. Nothing was written"
  conf_mode="$(stat -c '%a' -- "$CONF" 2>/dev/null || echo 644)"
  [[ "$conf_mode" =~ ^[0-7]{3,4}$ ]] || conf_mode=644
  local o g
  if (( BROKER_UID == 0 )); then o=root; g=root; else o="$BROKER_UID"; g="$(id -g)"; fi
  dirsafe "$ETC" "" "" 022 put "$o" "$g" "$conf_mode" "$tmp" "$(basename -- "$CONF")" \
    || fail conf_unwritten "could not write $CONF. The pin is left as it was"
  fact rerecorded 1
  fact previous_id "$prev_id"
  fact new_id "$new_id"
  out "$CONF now records $INSTALL_DIR as $new_id, the tree the update moved in. Nothing else in it changed"
  finish 0
}
if (( RERECORD == 1 )); then
  rerecord_install_dir
fi

ANCHOR_RC=0
dirsafe "$INSTALL_DIR" "" "" 002 identity >/dev/null 2>&1 \
  || ANCHOR_RC=$?
if (( ANCHOR_RC != 0 )); then
  # Which causes are possible depends on what the recorded value is made
  # of, so it is asked rather than assumed: on a filesystem with an id of
  # its own a reboot cannot change this, and naming it would send an
  # operator looking at the wrong thing. The pin is bypassed for this one
  # question, which reads a directory and writes nothing.
  #
  # And the pin is only ONE of the reasons dirsafe.py refuses an anchor
  # (#701). A mode that lets any account on this host write into the install
  # directory refuses with the same status 2, on a directory that was never
  # moved and that the recorded value matches exactly, and reporting THAT as
  # a move is what sent me to re-run the installer twice against a conf that
  # was already correct.
  #
  # THE MASK IS 000 ON THIS ONE CALL, and only this one. Every check
  # open_chain makes runs in a fixed order -- symlink, open, pin, directory,
  # mode -- so at mask 002 this question refuses on the very mode it is being
  # asked to detect, comes back empty, and the branch below can never be
  # reached at all. Nothing is read, written or removed on the identity op,
  # and this call does not decide whether the program continues: the pinned
  # call above already refused. It decides which sentence the operator gets.
  #
  # The two shapes that are NOT told apart here are a symlink where the
  # install directory should be, and something that is not a directory at
  # all. Both refuse before there is any value to compare, whatever the mask,
  # so both keep the moved-install sentence -- which is not wrong for either:
  # the path does not lead to the recorded directory any more.
  ID_SOURCE_NOW=""; ID_VALUE_NOW=""
  read -r ID_SOURCE_NOW ID_VALUE_NOW \
    < <(DS_ANCHOR_PIN="" python3 "$WORK/dirsafe.py" "$INSTALL_DIR" "" "" 000 identity 2>/dev/null || true) || true
  if [[ -n "$ID_VALUE_NOW" && "$ID_VALUE_NOW" == "$INSTALL_DIR_ID" ]]; then
    fail install_unsafe "$INSTALL_DIR IS the directory this host's grant recorded, so nothing was moved, and this program still refused to open it. Its mode lets ANY account on this host write into it (the other-write bit), and this program will not write a fleet's registries into a directory anyone can replace them in. Nothing was read or written. Look at it with: stat -c '%A %U %G %n' $INSTALL_DIR"
  fi
  ANCHOR_CAUSES="Either the install was moved or copied, or something renamed a directory above it."
  if [[ "$ID_SOURCE_NOW" == dev ]]; then
    ANCHOR_CAUSES="Either the install was moved or copied, or a reboot renumbered the disk it is on (this filesystem reports no id of its own, so the disk's number is what was recorded), or something renamed a directory above it."
  fi
  fail install_moved "$INSTALL_DIR is not the directory this host's grant recorded. $ANCHOR_CAUSES Nothing was read or written. Re-record it: curl -fsSL https://get.aperire.one | bash -s -- --dir $INSTALL_DIR --run fleet-broker-grant (the full installer, not --refresh-nodes, which does not rewrite the conf)"
fi

# shellcheck disable=SC2317,SC2329  # reached by the trap below, which shellcheck cannot see
cleanup() {
  rm -rf "$WORK"
  [[ -z "${VWORK:-}" ]] || rm -rf "$VWORK"
  # Round 5 through round 6 kept a note here about two candidates (the sealed
  # provider key, a copy of root's node record) written BESIDE their targets
  # rather than under $WORK, so a run that died mid-write would not leave one
  # loose in /etc/aperire under a name nothing reads and nothing cleans
  # (security review, finding F8). Round 7 (#648, review7-0.json) removes
  # that exception: every temp dirsafe.py's own primitive creates now lives
  # UNDER the directory fd it is about to rename into (never beside a target
  # by a path this program joined itself), and a run that dies mid-write
  # leaves that temp exactly where dirsafe.py put it -- inside the same
  # directory the target lives in, under a name nothing but this program's
  # own ".dirsafe." prefix ever uses, which an operator can find and remove
  # by hand the same way a dangling ".place." or ".write_token." name always
  # could. There is no longer a "$STORE.new.$$" or ".nodes-conf.XXXXXX" this
  # trap has to know to remove: dirsafe.py's own temp is never named by this
  # program's PID, and it is not this trap's job to guess dirsafe.py's own
  # naming scheme from outside it.
  # THE CONTRACT, ENFORCED (#318). This program's header promises every path
  # ends with `exit=`, and one path did not: an unguarded command under
  # `set -euo pipefail` took the shell down with no `error=` and no `exit=`,
  # so the answer was an empty stream and the dashboard could only call it
  # indeterminate. A caller that gets nothing cannot tell a refusal from a
  # crash, so if the shell is leaving without finish() having run, it says so
  # in the program's own grammar rather than in silence.
  #
  # Safe in a subshell: bash does not run an inherited EXIT trap when a $( )
  # command substitution ends, so this cannot fire spuriously mid-run.
  if [[ "$FINISHED" != "1" ]]; then
    fact error internal
    out "this program ended before it could say what it did. Nothing was written"
    journal 1
    fact exit 1
  fi
}
trap cleanup EXIT

# ── who the files belong to ──────────────────────────────────────────────
# The dashboard account from its own unit, never $SUDO_USER: reached through
# a socket there is no SUDO_USER, and on a host where one operator installed
# and the service runs as another, everything here has to follow the service.
DASH_USER=""
for u in aperire-server aperire-read; do
  [[ -f "$UNIT_DIR/${u}.service" ]] || continue
  DASH_USER="$(awk -F= '/^User=/{print $2; exit}' "$UNIT_DIR/${u}.service")"
  break
done
if [[ -z "$DASH_USER" || "$DASH_USER" == root ]]; then
  # dirsafe's own "owner" op, not `stat -c '%U' "$CONFIG_DIR"`: that stat
  # resolves dashboard/config by ordinary path lookup, which follows a
  # symlink at ANY component, and the name it came back with becomes this
  # program's DASH_USER, DASH_GROUP and SHARED_GROUP -- the identity the
  # token files are written FOR. On a host with no dashboard unit (the pm2
  # case, the only host that reaches this line at all) an account that owns
  # a hop could point that lookup at a directory belonging to a different
  # unprivileged account and have root write this fleet's token files for
  # it. Same chain walk, same refusals, no path resolved twice.
  DASH_USER="$(dirsafe "$INSTALL_DIR" dashboard/config "" 002 owner 2>/dev/null || true)"
fi
[[ -n "$DASH_USER" ]] || fail no_account "this host does not say which account its dashboard runs as"
id -u "$DASH_USER" >/dev/null 2>&1 || fail no_account "there is no account called '$DASH_USER'"
# root, by name and by number, the same pair of refusals DASH_ACCOUNT and
# PM2_ACCOUNT already get (#648, round 9). The unit branch above already
# skips a `User=root`, but the fallback did not: on a pm2-shaped host whose
# dashboard/config happens to be root-owned, the owner op answered "root"
# and this program went on to write the fleet's token files root:root,
# readable by nothing the dashboard runs as, and to name root as the
# account those registries belong to. A dashboard this program serves is
# never root; that is the premise the whole grant is built on, so an answer
# of root here is a host to stop on, not a value to use.
[[ "$DASH_USER" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] \
  || fail bad_account "the account this host names for its dashboard, \"${DASH_USER:0:32}\", is not a user name"
[[ "$DASH_USER" != root ]] \
  || fail bad_account "the dashboard on this host resolves to root, and this program does not write a fleet's registries or token files for root. Its unit should name a non-root User=, or $CONFIG_DIR should belong to the account it runs as"
[[ "$(id -u "$DASH_USER")" != 0 ]] \
  || fail bad_account "the account '$DASH_USER' this host names for its dashboard is uid 0, and this program does not write a fleet's registries or token files for root"

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

# The group BOTH the dashboard and advisord are in, resolved from the two
# UNITS and never from root's own groups.
#
# This is the one resolution with a fleet-wide downside. The token files are
# root:<group> 0640 because advisord reads them too (ruling, 2026-09-12), and
# if that group does not contain the dashboard account then readTokenFresh
# and its five call sites all fail and every peer read on this aggregator
# 401s. So a group the dashboard is not in is a REFUSAL, never a write.
#
# aperire-fleet-add.sh's resolve_trust_group intersects the advisor account's
# groups with the groups of whoever is RUNNING it, which is the operator
# there and root here. Root is in neither group, so copying it would fall
# through to the dashboard's own primary group — the exact answer that broke
# the trust push on 2026-08-19.
# Exit 3 is the reader saying it could not tell (see the block above), and
# that is a refusal by name, never root: root here means "no second
# account", the dashboard's own group, which is exactly the file a moved
# Advisor cannot read (#809).
ADV_USER="$(advisor_unit_account "$UNIT_DIR")" || refuse advisor_account_unread \
  "could not read which account the Advisor runs as from $UNIT_DIR/aperire-advisord.service: it names no User= under [Service] (there or in its drop-ins), cannot be read, or reads as root beside the .before-account marker a moved Advisor leaves. Nothing was written. Check it with: systemctl cat aperire-advisord"
# An Advisor that runs as root reads every file on the host, so there is no
# second account to share a group with: it takes the path a host with no
# Advisor takes, which is also what a unit with no User= line always got
# here. Before #809 an explicit User=root was refused as "share no group",
# which is not true of root.
ADV_IS_ROOT=0
if [[ "$ADV_USER" == root ]]; then ADV_IS_ROOT=1; ADV_USER=""; fi
# Who the Advisor's fleet.json is placed as (#870 review, M3). Its own
# account where it has one. Root where advisord runs as root: never the
# dashboard account, or that account would choose the token path a root
# advisord reads and the origin it sends that token to. The dashboard's own
# account only on a host with no Advisor unit at all, where nothing reads it.
# The test harness is never root, so there "root" is this process's own uid.
if [[ -n "$ADV_USER" ]]; then
  ADV_FLEET_OWNER="$ADV_USER"
elif (( ADV_IS_ROOT )); then
  if (( BROKER_UID == 0 )); then ADV_FLEET_OWNER=root; else ADV_FLEET_OWNER="$BROKER_UID"; fi
else
  ADV_FLEET_OWNER="$DASH_USER"
fi
SHARED_GROUP=""
if [[ -n "$ADV_USER" ]] && id -u "$ADV_USER" >/dev/null 2>&1; then
  dash_groups=" $(id -nG "$DASH_USER" 2>/dev/null) "
  for cand in $(id -nG "$ADV_USER" 2>/dev/null); do
    if [[ "$dash_groups" == *" $cand "* ]]; then SHARED_GROUP="$cand"; break; fi
  done
  [[ -n "$SHARED_GROUP" ]] || refuse no_shared_group \
    "the dashboard runs as $DASH_USER and advisord as $ADV_USER, and they share no group, so a token file cannot be readable by both. Nothing was written. Fix it with: curl -fsSL https://get.aperire.one | bash -s -- --dir $INSTALL_DIR --run advisor-account"
else
  # No Advisor on this host. The token files are the dashboard's alone, so
  # its own primary group is the honest answer and 0640 is no wider than
  # 0600 would have been to anyone who matters.
  SHARED_GROUP="$(id -gn "$DASH_USER")"
fi
# By construction the dashboard is in it; asserted anyway, because this is
# the check whose failure is a fleet-wide read outage.
case " $(id -nG "$DASH_USER" 2>/dev/null) " in
  *" $SHARED_GROUP "*) : ;;
  *) fail no_shared_group "the dashboard account $DASH_USER is not in group $SHARED_GROUP, so it could not read the token files this would write. Nothing was written" ;;
esac

# ── the one binary that drops this program's privilege ───────────────────
#
# Resolved by PATH first and then by absolute path, the same rule PM2_BIN and
# NODE_BIN follow and for the same reason: this program runs from a systemd
# socket, and runuser lives in /usr/sbin (util-linux 2.37 on Ubuntu 22.04,
# measured). That is on systemd's own PATH, but a miss here is not a degraded
# reload, it is every approval and every push on the host refusing, so the
# fallback is spelled out. Two verbs need it now: `approve` reads its
# candidate registries back as the dashboard account, and `model-push` reads
# a node's read token as that account too (#458). Each states its own
# refusal; this only finds the binary.
RUNUSER_BIN="$(command -v runuser 2>/dev/null || true)"
if [[ -z "$RUNUSER_BIN" ]]; then
  for runuser_cand in /usr/sbin/runuser /sbin/runuser /usr/bin/runuser; do
    [[ -x "$runuser_cand" ]] && { RUNUSER_BIN="$runuser_cand"; break; }
  done
fi

# ── the payload ──────────────────────────────────────────────────────────
# Bounded before it is parsed: 32 lines and 16 KiB, so a caller cannot
# stream at this program forever. Nothing is read after `end`.
VERB="" LINES=0 BYTES=0 value="" WIDE=""
declare -A P=()
# Percent-decoded value on stdout, and NOTHING else: a refusal in here would
# run in the subshell the call site puts it in, so its `error=` line would be
# captured into the variable instead of reaching the socket and the run would
# carry on with a value it had refused. The backslash check therefore lives
# at the call site, in the main shell.
decode() { printf '%b' "${1//%/\\x}"; }
while IFS= read -r line; do
  LINES=$((LINES + 1)); BYTES=$((BYTES + ${#line} + 1))
  (( LINES <= 32 )) || refuse bad_payload "that payload has more lines than any verb here takes"
  (( BYTES <= 16384 )) || refuse bad_payload "that payload is larger than any verb here takes"
  [[ "$line" == "end" ]] && break
  if [[ -z "$VERB" ]]; then VERB="$line"; continue; fi
  [[ "$line" == *=* ]] || refuse bad_payload "every line after the verb is name=value"
  name="${line%%=*}"
  # Digits are part of a field name. `[a-z_]+` matches none of
  # `credential_sha256`, `installed_sha256` or `published_sha256`, and that
  # exact pattern is what dropped three of the updater's own facts on the
  # floor (#293). Same rule as lib/fleet-broker.ts's reader, both ends.
  [[ "$name" =~ ^[a-z][a-z0-9_]*$ ]] || refuse bad_payload "that payload names a field this program does not take"
  value="${line#*=}"
  # A literal backslash cannot appear in an encoded value (the encoder
  # escapes it as %5C), and printf %b would interpret one. Refused here, in
  # the main shell, rather than interpreted.
  case "$value" in
    *\\*) refuse bad_payload "a value in that payload carries a backslash, which an encoded value never does" ;;
  esac
  P["$name"]="$(decode "$value")"
done
[[ -n "$VERB" ]] || refuse bad_payload "that payload names no verb"

LABEL_RE='^[a-z0-9-]{1,32}$'
# The twin of lib/fleet-registry.ts's NODE_KEY_RE and of the contract's
# PAIR_NODE_KEY_RE. Three declarations of one rule, because this one is bash
# and cannot import; scripts/test-fleet-broker.sh drives one near-miss set
# through all three.
NODE_KEY_RE='^n[1-9A-HJ-NP-Za-km-z]{20,60}$'
# The fifth field of a node record row (#458): an absolute path with no
# whitespace in it, because the record is whitespace separated and a path
# that could carry a space could carry a field. No `..` either: a path root
# reads a bearer token out of is a path that says what it is.
TOKEN_PATH_RE='^/[A-Za-z0-9._/-]{1,512}$'
token_path_ok() {  # path -> 0 usable, 1 not
  [[ "$1" =~ $TOKEN_PATH_RE ]] || return 1
  [[ "$1" != */ ]] || return 1
  case "/$1/" in */../*) return 1 ;; esac
  return 0
}
# WHO READS A NODE'S READ TOKEN, said once (#458). The account the conf pins,
# which is the account the dashboard runs as, and the account whose own
# `readTokenFresh` reads the same file on the page. The conf's value first,
# for the same reason the approve path prefers it: it was settled by the
# installer on this host rather than worked out at run time. The unit-derived
# name is the fallback, exactly as the installer itself falls back.
TOKEN_READER="${DASH_ACCOUNT:-$DASH_USER}"
# One file, one reader (#458). Bounded at 4 KiB, because what this reads is a
# bearer token and not a stream: what answers an open on a path out of a
# registry is whatever is at that path. It PRINTS THE TOKEN and nothing else,
# so it must never call refuse: a refusal inside the command substitution its
# caller puts it in would be captured into the variable instead of reaching
# the socket. The caller states both refusals.
read_token_as_dash() {  # path -> token on stdout, 0 read it, 1 could not
  local path="$1" raw=""
  # `timeout`, not because this account is not trusted with its own file (it
  # is, the same file its own dashboard reads directly), but because this
  # program's own socket is one connection at a time (Accept=yes,
  # MaxConnections=1): a fifth-field path (#458) may name anywhere on the
  # host, not only a directory this program otherwise guards, so a FIFO
  # planted at it would otherwise block `head` open for the length of this
  # program's own RuntimeMaxSec rather than fail named and fast (#648, round
  # 4's read audit).
  if (( BROKER_UID == 0 )); then
    raw="$(timeout 5 "$RUNUSER_BIN" -u "$TOKEN_READER" -- head -c 4096 -- "$path" 2>/dev/null)" \
      || return 1
  else
    # The harness case, and only that: on a host this program is root.
    raw="$(timeout 5 head -c 4096 -- "$path" 2>/dev/null)" || return 1
  fi
  printf '%s' "$raw" | tr -d '\r\n'
  return 0
}

# Sets RELOADED (1 or 0) and RELOAD_VIA (how). It PRINTS NOTHING and must
# never be called through $( ): a command substitution is a subshell, and
# both globals would be thrown away while the run carried on believing the
# reload had not happened. That trap has bitten this project before.
#
# systemd first, then pm2 (#310). An aggregator that runs its dashboard under
# pm2 has no unit for systemctl to find, so this returned 0 and the answer
# said the dashboard would pick the row up on its next restart. That is a
# false sentence on that host: nothing restarts it, and the fleet's newest
# node is invisible until somebody notices. The lab aggregator is one of
# these, so without this the phase 3 proof cannot pass.
#
# `reloaded` stays 1-or-0 because lib/fleet-broker.ts reads it as
# `=== '1'`; the mechanism is a SEPARATE fact. A third value there would have
# been read as "did not reload" by a consumer that predates it, which is the
# #268 class of bug: a verdict switch meeting a value it does not know.
RELOAD_VIA=""
RELOADED="0"
reload_dashboard() {  # sets RELOADED and RELOAD_VIA
  local u
  RELOAD_VIA=""
  RELOADED="0"
  for u in aperire-server aperire-read; do
    if systemctl is-active --quiet "$u" 2>/dev/null; then
      if systemctl reload "$u" >/dev/null 2>&1; then
        RELOAD_VIA="systemd:$u"; RELOADED="1"
      else
        RELOAD_VIA="systemd:$u:failed"; RELOADED="0"
      fi
      return 0
    fi
  done
  # pm2, as the dashboard account. Two things make this safe to run from
  # root: the process name is fixed here rather than taken from the payload,
  # and `sendSignal` delivers a SIGHUP to one named process, which is the
  # same signal systemctl reload sends. It is never a restart.
  #
  # HOME has to be set: pm2 keeps its process list under $HOME/.pm2, and
  # root's own HOME would find an empty list and report success for having
  # signalled nothing.
  if [[ -n "$PM2_ACCOUNT" ]] && command -v runuser >/dev/null 2>&1; then
    local home="$PM2_HOME_DIR"
    local bin="$PM2_BIN"
    [[ -n "$home" ]] || home="$(getent passwd "$PM2_ACCOUNT" | cut -d: -f6)"
    # PATH is the last resort, not the first: see PM2_BIN above.
    [[ -n "$bin" && -x "$bin" ]] || bin="$(command -v pm2 2>/dev/null || true)"
    if [[ -z "$bin" || ! -x "$bin" ]]; then
      # Named apart from a failure on purpose. "pm2 refused the signal" and
      # "this host has no pm2 where the conf says" are different problems
      # with different fixes, and one sentence for both would send an
      # operator looking in the wrong place.
      RELOAD_VIA="pm2:not-found"; RELOADED="0"; return 0
    fi
    if [[ -n "$home" ]] \
      && runuser -u "$PM2_ACCOUNT" -- env HOME="$home" "$bin" sendSignal SIGHUP "$PM2_PROCESS" >/dev/null 2>&1; then
      RELOAD_VIA="pm2:$PM2_PROCESS"; RELOADED="1"; return 0
    fi
    RELOAD_VIA="pm2:$PM2_PROCESS:failed"; RELOADED="0"; return 0
  fi
  RELOAD_VIA="none"
  RELOADED="0"
}

# ── root's own record of where a push may send ───────────────────────────
#
# One line per node, written only by `approve` and pruned only by `revoke`;
# `repin` never touches it, and a rejoin must agree with it (#866 review,
# M2). `model-push` resolves a label here and in no other file, which is what
# stops a compromised dashboard choosing a port or a node key for a push:
# fleet.yaml is the dashboard account's and a row in it is a row that account
# can rewrite. It does NOT stop the dashboard reading a push to a LINK row.
# That port is the dashboard's own link hub, and the pin check is an answer
# from that same listener, so until the push is encrypted to the node (#867)
# a compromised dashboard can read the key on its way to a link node (ADR
# 0024, row 18).
#
# Written beside the target and renamed, the same rule place() follows: a
# truncating write over a live path is a state a concurrent reader can see.
nodes_conf_write() {  # candidate-file -> 0 ok, 1 could not, 2 refused
  # $ETC is root's own directory (root:root 0755) on any host this program
  # runs on, so nothing here is reachable the way place()'s own directory
  # always was. Round 7 (#648, review7-0.json) routes it through dirsafe
  # anyway, on the standing rule that one discipline everywhere is what
  # stops the next reader copying the wrong one, never a faster check for a
  # reachable race. No extra account is ever allowed to own $ETC, so
  # extra-uid is empty and the write-mask is the strict 022.
  local o g
  if (( BROKER_UID == 0 )); then o=root; g=root; else o="$BROKER_UID"; g="$(id -g)"; fi
  dirsafe "$ETC" "" "" 022 put "$o" "$g" 600 "$1" "$(basename "$NODES_CONF")"
}

# Every row but this label's, in order. Comments and blank lines survive: an
# operator reading root's own file should find their own notes still in it.
nodes_conf_without() {  # label -> the file's remaining lines on stdout
  local label="$1" line first
  [[ -f "$NODES_CONF" ]] || return 0
  while IFS= read -r line || [[ -n "$line" ]]; do
    case "$line" in
      ''|'#'*) printf '%s\n' "$line"; continue ;;
    esac
    read -r first _ <<<"$line"
    [[ "$first" == "$label" ]] && continue
    printf '%s\n' "$line"
  done < "$NODES_CONF"
}

# ── the arm key, made if absent, then read ───────────────────────────────
# The public half of this aggregator's fleet arm key, for the node to trust.
#
# MADE HERE WHEN IT IS ABSENT (#723, ruled 2026-09-29). It used to be read
# and never made, so a node paired before an operator first ran
# aperire-fleet-arm.sh was handed no key, held none, and could never be armed
# from the page: the only ways on were a re-pair or a root shell on that
# node. The settlement is the one moment a node takes this key from a source
# its operator has just checked by fingerprint, so the key has to exist by
# then.
#
# Making it arms nothing. The private half is root's, 0600, and never leaves
# this host; a window on any node still needs root here to run
# aperire-fleet-arm.sh and sign a token for it. What changes is only that the
# public half is there to hand over. This program still mints no token and
# opens no window (scripts/test-fleet-broker.sh holds that).
#
# NEVER FATAL to `approve`, which reports `-` and says why in the
# fleet_arm_key fact. Since #741 it is `arm-key`, asked a moment before the
# welcome, that decides whether a pairing can go ahead at all: a node refuses
# a welcome with no arm key in it, so that verb refuses by name instead.
#
# AND NEVER ON A FLEET THAT HAD ONE (#851, ruled 2026-10-04). A key missing
# there was lost: the nodes paired to it trust its public half, and a new key
# would orphan every one of them, silently, the moment someone opened Add a
# node. Only `arm-key` makes a key at all, and only when this host has never
# had one (no fleet-arm.made, which ensure_fleet_arm_key leaves beside every
# key and no verb removes) AND fleet_paired_records (below, the same text the
# grant installer carries) finds no node. Otherwise the state is `lost` and
# nothing is made. `approve` never makes one (#851 review L2): it refuses a
# missing key before it writes anything. The way back is the backup set, or
# the grant installer's --new-fleet-keys on root's own argv. The only input
# a socket caller has to this choice is the records, which the dashboard
# account can edit, and that is why the marker exists: the marker alone
# decides once a key has been made here. Only a host whose key predates the
# marker AND is already lost rests on the records alone.
# ---- BEGIN ensure_fleet_arm_key (one rule, two copies: #723) ----------
# Make the fleet arm key at $1 if there is none, and never touch one that is
# there. The same text lives in aperire-fleet-arm.sh and in
# aperire-fleet-broker.sh, and scripts/test-fleet-broker.sh fails if the two
# copies ever differ: the broker runs from a root-installed copy that sources
# nothing out of the tree, so a shared file would be one more program to
# install beside it.
#
# Race-free, because two root programs can now make it (#723): an approval on
# the broker and an operator's first arm. `openssl genpkey -out` on the final
# name truncates whatever is there, so two makers racing could each report a
# public key while the file ended up holding the other's. Here the key is
# generated into a fresh temp file in the same directory (mktemp: O_EXCL,
# 0600), then hard-linked to the final name with `ln -T`, which fails if that
# name exists (a file OR a directory) and never replaces it. The loser discards its own and reads the winner's.
# Whoever reports a public key reads it back from the final file.
#
# Sets FLEET_ARM_KEY_MADE=1 when this call made it, 0 when one was there.
# Returns 1, with FLEET_ARM_KEY_WHY, when it could make none and none exists.
#
# #851 review L1: whenever a plain key file is at the name, this also leaves
# fleet-arm.made beside it, root's, 0600, empty, and never replaced. It says
# this host HAS had a fleet arm key, so a key missing later was lost rather
# than never made, whatever the fleet's records say by then (no socket verb
# removes this file, and the records are ones the dashboard account can
# empty). A host whose key predates the marker gets one the next time this
# runs with the key there. The callers refuse to make a key where it is.
# The reason is read by aperire-fleet-arm.sh, which prints it; the broker
# reports a one-word state instead, because its output is facts.
# shellcheck disable=SC2034
FLEET_ARM_KEY_MADE=0
# shellcheck disable=SC2034
FLEET_ARM_KEY_WHY=''
# shellcheck disable=SC2034
ensure_fleet_arm_key() { # $1 = the key path
  local key="$1" dir tmp stale rc=0
  FLEET_ARM_KEY_MADE=0; FLEET_ARM_KEY_WHY=''
  dir="$(dirname "$key")"
  # A temp a killed maker left behind (#743 review, L3), swept first. It is a
  # root 0600 private key, and if the kill landed between the link and the
  # rm it is a second name for the LIVE key, which would outlive a later
  # rotation by rm. Only ones older than ten minutes: a maker that is still
  # running takes seconds, and its temp is not this call's to take.
  if [[ -d "$dir" ]]; then
    while IFS= read -r -d '' stale; do rm -f -- "$stale"; done \
      < <(find "$dir" -maxdepth 1 -name '.fleet-arm.key.??????' ! -type d -mmin +10 -print0 2>/dev/null)
  fi
  if [[ -e "$key" || -L "$key" ]]; then fleet_arm_mark "$key"; return 0; fi
  # Made only when absent, and its mode stated: a caller running under
  # umask 077 that let mkdir decide would leave /etc/aperire 0700, which the
  # dashboard account cannot traverse to its own env file.
  if [[ ! -d "$dir" ]]; then
    if ! mkdir -p "$dir" || ! chmod 0755 "$dir"; then
      FLEET_ARM_KEY_WHY="$dir could not be made"; return 1
    fi
  fi
  if ! tmp="$(umask 077; mktemp "$dir/.fleet-arm.key.XXXXXX" 2>/dev/null)" || [[ -z "$tmp" ]]; then
    FLEET_ARM_KEY_WHY="no temporary file could be made in $dir"; return 1
  fi
  # Generate and link in a subshell that removes the temp on its way out,
  # however it goes: a TERM from RuntimeMaxSec, an INT, or an ordinary exit.
  # A KILL cannot be trapped, and the sweep above is what answers that.
  #
  # `ln -T` (#743 review, L1): without it a DIRECTORY appearing at the key's
  # name between the check above and this line is linked INTO, ln reports
  # success, and a private key is left inside it while this call says it made
  # the key. With -T the name is the target or nothing.
  ( trap 'rm -f -- "$tmp"' EXIT
    trap 'exit 1' TERM INT HUP
    umask 077
    openssl genpkey -algorithm ed25519 -out "$tmp" 2>/dev/null || exit 2
    chmod 0600 "$tmp" || exit 2
    ln -T -- "$tmp" "$key" 2>/dev/null || exit 3
  ) || rc=$?
  rm -f -- "$tmp"
  if (( rc == 0 )); then
    FLEET_ARM_KEY_MADE=1
    fleet_arm_mark "$key"
    return 0
  fi
  if (( rc == 2 )); then
    FLEET_ARM_KEY_WHY="openssl could not generate an Ed25519 key on this host"; return 1
  fi
  # Somebody else made it between the check above and the link: theirs stands.
  if [[ -e "$key" || -L "$key" ]]; then fleet_arm_mark "$key"; return 0; fi
  FLEET_ARM_KEY_WHY="$key could not be linked into place"
  return 1
}
# fleet_arm_mark <key path>: fleet-arm.made beside a key that is a plain
# file. Created with noclobber (O_EXCL), so a name already there, a link
# included, is neither followed nor replaced. Never a failure of its caller,
# and never silent: FLEET_ARM_MARK_FAILED=1 when the marker should be there
# and could not be made, so each caller says what that leaves (#853 review).
# shellcheck disable=SC2034
FLEET_ARM_MARK_FAILED=0
fleet_arm_mark() {
  local mark
  FLEET_ARM_MARK_FAILED=0
  mark="$(dirname "$1")/fleet-arm.made"
  [[ -f "$1" && ! -L "$1" ]] || return 0
  [[ -e "$mark" || -L "$mark" ]] && return 0
  ( set -C; umask 077; : > "$mark" ) 2>/dev/null || FLEET_ARM_MARK_FAILED=1
  return 0
}
# ---- END ensure_fleet_arm_key -----------------------------------------

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

# arm_key_paired <label to leave out, or ''>: fleet_paired_records for this
# host, said the way this program says things. Sets ARM_KEY_PAIRED (the
# labels, comma-separated) and ARM_KEY_PAIRED_WHY (one sentence naming any
# record counted without a label: a row with none usable, or a file that
# could not be read safely). Returns 0 when this host has a paired node or
# cannot tell, 1 when it has none.
ARM_KEY_PAIRED=""
ARM_KEY_PAIRED_WHY=""
arm_key_paired() {
  local recs others
  ARM_KEY_PAIRED="" ARM_KEY_PAIRED_WHY=""
  recs="$(fleet_paired_records "$INSTALL_DIR" "$(id -u "$DASH_USER")" "$ETC" "$WORK" "$1" \
    "$(fleet_self_facts "$UNIT_DIR" "$WORK" 2>/dev/null | sed -n 's/^port //p')")" || return 1
  ARM_KEY_PAIRED="$(sed -n 's/^node \([a-z0-9-]*\) .*/\1/p' <<<"$recs" | sort -u | paste -sd, -)"
  others="$(sed -n 's/^\(badrow\|unread\) //p' <<<"$recs" | sort -u | paste -sd, - | sed 's/,/, /g')"
  [[ -z "$others" ]] || ARM_KEY_PAIRED_WHY=" ($others could not be read safely or holds a row with no usable label, so it counts as paired)"
  return 0
}

# arm_key_lost: is a MISSING arm key a lost one (#851)? Yes when this host
# has had one (fleet-arm.made, review L1) or has a paired node. Sets
# ARM_KEY_MARKED and, through arm_key_paired, the names. Reads only.
ARM_KEY_MARKED=0
arm_key_lost() {
  ARM_KEY_MARKED=0
  [[ -e "$ETC/fleet-arm.made" || -L "$ETC/fleet-arm.made" ]] && ARM_KEY_MARKED=1
  if arm_key_paired ""; then return 0; fi
  (( ARM_KEY_MARKED ))
}

# The sentence a fleet_arm_key_lost refusal carries, on either verb.
arm_key_lost_sentence() {
  local names="${ARM_KEY_PAIRED//,/, }" had
  if [[ -n "$names$ARM_KEY_PAIRED_WHY" ]]; then
    had="it already has paired nodes (${names:-named in its records}${ARM_KEY_PAIRED_WHY})"
  else
    had="it has had one before ($ETC/fleet-arm.made says so), so every node paired to it trusts that key"
  fi
  local selfrow=''
  [[ -n "$names" ]] && selfrow=" If a node named here is this host, its fleet.yaml row does not read this dashboard's own port: set its read_origin to that port, and mark it role: aggregator only if this host runs no node of its own."
  printf '%s' "this aggregator has no fleet arm key, and $had. They trust the key that is gone, so a new one would cut every one of them off. Nothing was made. Put the key back from your backup set: curl -fsSL https://get.aperire.one | bash -s -- --dir $INSTALL_DIR --restore --from <backup set>. With no backup, make a new one on purpose and pair each node again: curl -fsSL https://get.aperire.one | bash -s -- --dir $INSTALL_DIR --run fleet-broker-grant --new-fleet-keys.$selfrow"
}

# Sets ARM_PUB (the public half, plain base64, or empty) and ARM_KEY_STATE
# (one word). With `make` (only `arm-key`, #741, a moment before the welcome)
# it makes the key when there is none and arm_key_lost says it was never
# had; otherwise the state is `lost`, nothing is made, and ARM_KEY_PAIRED
# names the nodes (#851). With `read` (`approve`, whose settlement hands the
# public half to the node) it makes nothing: a missing key is `missing`.
# PRINTS NOTHING and must never be called through $( ): the globals would be
# thrown away with the subshell.
resolve_fleet_arm_pub() {  # $1 = make | read
  ARM_PUB=""
  ARM_KEY_PAIRED=""
  ARM_KEY_PAIRED_WHY=""
  # One word for the dashboard's audit row, never free text: made, present,
  # lost, or the reason there is none. Printed as a fact rather than
  # journalled, because the journal line is fixed (verb, label, exit) on
  # purpose.
  ARM_KEY_STATE=no_openssl
  if command -v openssl >/dev/null 2>&1; then
    if [[ ! -e "$ARM_KEY" && ! -L "$ARM_KEY" && "$1" != make ]]; then
      ARM_KEY_STATE=missing
    elif [[ ! -e "$ARM_KEY" && ! -L "$ARM_KEY" ]] && arm_key_lost; then
      ARM_KEY_STATE=lost
    elif ! ensure_fleet_arm_key "$ARM_KEY"; then
      ARM_KEY_STATE=make_failed
    elif [[ -L "$ARM_KEY" || ! -f "$ARM_KEY" || ! -O "$ARM_KEY" ]] \
      || (( (8#$(stat -c '%a' "$ARM_KEY" 2>/dev/null || echo 777) & 8#077) != 0 )) \
      || [[ "$(stat -c '%h' "$ARM_KEY" 2>/dev/null)" != 1 ]]; then
      # The file every node's arm trust rests on, read only when it is a plain
      # file this account owns and nobody else may read or write: otherwise the
      # key handed over could be one somebody else chose, or knows.
      ARM_KEY_STATE=unsafe
    else
      ARM_PUB="$(openssl pkey -in "$ARM_KEY" -pubout -outform DER 2>/dev/null | tail -c 32 | base64 -w0 || true)"
      if [[ -z "$ARM_PUB" ]]; then
        ARM_KEY_STATE=unusable
      elif (( FLEET_ARM_KEY_MADE )); then
        # A first key. #743 review L2's made_fleet_had_nodes, a key remade
        # while other nodes trusted the old one, cannot happen any more: on
        # such a fleet nothing is made at all (#851, above).
        ARM_KEY_STATE=made
      else
        ARM_KEY_STATE=present
      fi
    fi
  fi
}

# ── shared candidate-write primitives (#620, #641) ────────────────────────
# Hoisted here, ahead of every verb that writes a registry, so approve and
# the three #641 advisor verbs share one copy rather than four that could
# drift apart. Function DEFINITIONS only: nothing here runs until a verb
# below calls one, and every name a body reads ($TOKEN_DIR, $SHARED_GROUP,
# $DASH_USER, $ARM_KEY and the rest) is already settled by this point in the
# script, the same as it was where this used to live, further down.
DASH_GROUP="$(id -gn "$DASH_USER")"

# ── one place-name lookup for every write, read and unlink below ─────────
#
# Maps a target path this program is about to write, read or unlink to the
# ANCHOR and RELATIVE PATH dirsafe.py should walk from, its WRITE-MASK, and
# the one EXTRA account (besides root) that subtree's own directories may
# legitimately be owned by. A plain STRING match against this program's own
# fixed directories ($CONFIG_DIR, $ADV_STATE, $ETC, $TOKEN_DIR) -- never a
# filesystem call, so nothing on disk can steer which anchor gets used.
# Sets DS_ANCHOR, DS_RELPATH, DS_MASK, DS_EXTRA and DS_LEAF; returns 1 for a
# path this program has no business touching at all, which every caller
# below treats as a hard refusal rather than a fallback to the old,
# path-string way of finding it.
DS_ANCHOR=""; DS_RELPATH=""; DS_MASK=""; DS_EXTRA=""; DS_LEAF=""
dirsafe_locate() {  # target
  local target="$1" dir extra=""
  dir="$(dirname -- "$target")"
  DS_LEAF="$(basename -- "$target")"
  case "$dir" in
    "$CONFIG_DIR")
      # dashboard/config: the dashboard's own account, end to end, is the
      # ONE extra owner this subtree's directories may legitimately carry --
      # see dirsafe.py's own header for why that is a deliberate deviation
      # from "an attacker-owned hop must sit under a trusted parent" rather
      # than an oversight.
      DS_ANCHOR="$INSTALL_DIR"; DS_RELPATH="dashboard/config"; DS_MASK=002
      extra="$(id -u "$DASH_USER" 2>/dev/null)" || extra=""
      ;;
    "$ADV_STATE")
      # advisor/state: the Advisor's own account where this host has one,
      # the dashboard's otherwise -- the same fallback place()'s own callers
      # already use for ADV_FLEET's owner.
      DS_ANCHOR="$INSTALL_DIR"; DS_RELPATH="advisor/state"; DS_MASK=002
      extra="$(id -u "${ADV_USER:-$DASH_USER}" 2>/dev/null || id -u "$DASH_USER" 2>/dev/null || true)"
      ;;
    "$TOKEN_DIR")
      # $ETC/fleet-tokens: root's own, no extra account, ever.
      DS_ANCHOR="$ETC"; DS_RELPATH="fleet-tokens"; DS_MASK=022; extra=""
      ;;
    "$ETC")
      DS_ANCHOR="$ETC"; DS_RELPATH=""; DS_MASK=022; extra=""
      ;;
    *) return 1 ;;
  esac
  DS_EXTRA="$extra"
  return 0
}

backup_of() {  # path -> backup path, or empty
  local src="$1"
  local dst
  dst="$WORK/$(basename -- "$src").restore"
  # This function's own contract, kept exactly the same as before round 7:
  # it ALWAYS prints something (a backup path, or an empty string) and
  # ALWAYS returns 0. Every caller uses it inside a command substitution
  # (`"$(backup_of ...)"`) as part of a plain assignment, and under this
  # program's `set -euo pipefail` a nonzero exit there would abort the whole
  # verb, not just skip a backup -- an absent or unreadable source is an
  # ordinary outcome for this function to report empty, never a failure for
  # it to propagate.
  case "$src" in
    "")
      dst=""
      ;;
    "$WORK"/*)
      # Already root's own private snapshot (snapshot_registry_file's own
      # output, or $WORK/nodes.new and the like): a plain `cp -a` by path is
      # exactly as safe as reading it in the first place, since nothing
      # outside this program has ever been able to write into $WORK.
      if [[ -f "$src" ]]; then cp -a "$src" "$dst"; else dst=""; fi
      ;;
    *)
      # A LIVE path this program does not own the directory of --
      # $NODES_CONF or $ADVISOR_TOKEN_PATH, both under $ETC. Read the same
      # way snapshot_registry_file reads fleet.yaml and fleet-links.json, by
      # a directory-fd walk from a trusted anchor, rather than a `cp -a`
      # that resolves the path in the ordinary way. $ETC has never been
      # reachable by an unprivileged account (its own ancestors are root's),
      # so this closes no gap on its own; it is the "one discipline
      # everywhere" round 7 asked for, so backup_of is never the one
      # remaining place in this program that still finds a directory by
      # string. A refusal here (a symlink, say) is folded into "no backup"
      # the same as "absent" -- this function only ever preserves what it
      # can safely read before a write proceeds; it never blocks the write
      # on its own account.
      # $DS_EXTRA, never a hardcoded "": every live path this reaches today
      # is under $ETC, where dirsafe_locate sets the extra account to ""
      # anyway, so the two agree on every current caller. A future caller
      # that hands this a dashboard/config or advisor/state path would get
      # a refusal from the "" version for a chain that is perfectly
      # legitimate, and "no backup" is how this function reports a refusal
      # -- a silent one, on the leg before a write. One place-name lookup
      # decides the anchor, the relative path, the mask AND the extra
      # account; taking three of the four and overriding the fourth by hand
      # is how the next reader gets a puzzle instead of a rule.
      if ! dirsafe_locate "$src"; then
        dst=""
      elif ! dirsafe "$DS_ANCHOR" "$DS_RELPATH" "$DS_EXTRA" "$DS_MASK" read "$DS_LEAF" "$dst" "$REGISTRY_SNAP_MAX_BYTES"; then
        dst=""
      fi
      ;;
  esac
  printf '%s' "$dst"
  return 0
}
# The clause restore_all's own outcome earns, appended by every caller to
# its own last line. Set on every call, never read before one.
RESTORE_NOTE="; every file was put back"
restore_all() {
  # Round 6 (#648, review6-0.json): this used to be a THIRD copy of the
  # exact bug place() and revoke's own inline write both carried before
  # round 5 closed it for them -- a predictable "$path.restore.$$" temp
  # name, in the SAME dashboard- or advisord-owned directory as the live
  # registry, closed with a bare `mv -f` (no `-T`) and, on that rename
  # failing, a direct `cp -a` straight over the live path as a last resort.
  # The review reproduced this 10/10 at the primitive level, and end to end
  # through one real failure path (approve's token_too_wide, after
  # fleet.yaml and fleet-links.json had already been placed): dashboard/
  # config/fleet.yaml came out a symlink pointing outside that directory.
  # This function is reached from many OTHER failure branches across
  # approve, attach-advisor and detach-advisor too -- a nodes_conf_write
  # failure, an ensure_token_dir failure, or any ordinary operational fault
  # -- and an account that owns dashboard/config or advisor/state outright
  # does not need to cause any of them itself: it can watch, for free, in
  # the background, for this function to run for any reason at all, for as
  # long as the fleet lives.
  #
  # Never a fourth copy: every write below goes through place() itself,
  # unguessable mktemp, O_NOFOLLOW|O_NONBLOCK reopen, write and
  # owner/mode on one fd, `mv -fT`, refusing outright rather than falling
  # back to a direct write when any of that fails. There is no more "the
  # direct write is still better than nothing" branch; a restore that
  # cannot be done safely is a restore this function now leaves undone and
  # SAYS so (below), the same rule place()'s own callers already accept for
  # the write that got them here.
  #
  # The owner and mode restored are not read back off the live path (which
  # is exactly the thing an attacker who owns its directory controls) or off
  # the backup file for fleet.yaml, fleet-links.json and the advisor peer
  # registry (whose backup was copied from root's OWN snapshot in $WORK,
  # never carrying the dashboard or advisord account's ownership). They are
  # the fixed convention this program already writes each of those three
  # paths with everywhere else in this file (place()'s own call sites,
  # below): there has only ever been one correct owner and mode for each of
  # them, so there is nothing to preserve by reading it, only a value to
  # restate. NODES_CONF and ADVISOR_TOKEN_PATH are different: both live
  # under a directory only root can write to, so backup_of's own `cp -a`
  # already reads their true owner and mode off the live file with no race
  # at all, and the caller marks their BACKED entry "self" to say so, since
  # a literal "root" would fail to chown under the test harness, which is
  # never root.
  #
  # Reads the caller's own BACKED array, which every verb that uses this
  # initializes (BACKED=()) before its first backup_of call, as PATH,
  # BACKUP-PATH-OR-EMPTY, "owner:group:mode" (or the literal "self")
  # triples.
  local i path backup spec owner group mode
  local -a incomplete=()
  for (( i = 0; i < ${#BACKED[@]}; i += 3 )); do
    path="${BACKED[i]}"
    backup="${BACKED[i+1]}"
    spec="${BACKED[i+2]}"
    if [[ -z "$backup" ]]; then
      # Nothing existed at this path before this connection touched it, so
      # putting it back means removing whatever this connection wrote.
      # dirsafe's own unlink op is what "rm -f on a name in a hostile-owned
      # directory unlinks whatever is actually there, symlink or not, and
      # never follows it" now means: the DIRECTORY the name sits in is
      # walked from a trusted anchor first, so the name being removed is the
      # one this program actually meant, never one a swapped ancestor
      # redirected the unlink into.
      if dirsafe_locate "$path"; then
        dirsafe "$DS_ANCHOR" "$DS_RELPATH" "$DS_EXTRA" "$DS_MASK" unlink "$DS_LEAF" \
          || incomplete+=("$path")
      else
        incomplete+=("$path")
      fi
      continue
    fi
    if [[ "$spec" == self ]]; then
      if ! read -r owner group mode < <(stat -c '%u %g %a' "$backup" 2>/dev/null); then
        incomplete+=("$path")
        continue
      fi
    else
      IFS=: read -r owner group mode <<<"$spec"
    fi
    # One leg's own refusal (place() declines a hostile or now-unwritable
    # target the same as it always does) must never stop the legs after it:
    # under this program's own `set -euo pipefail`, a bare failing command
    # here would abort the WHOLE function, silently skipping every entry
    # still queued behind the one that failed -- worse than the single file
    # this leg could not put back.
    place "$backup" "$path" "$owner" "$group" "$mode" || incomplete+=("$path")
  done
  # A caller's own message ("every file was put back") is only true when
  # every leg above actually landed. Round 6 named the failure on the
  # answer stream here; round 9 finishes the job, because naming it HERE
  # was not enough: every caller below prints its own refusal AFTER this
  # function returns, and the dashboard shows an operator the LAST line it
  # got (lib/fleet-broker.ts's brokerStoreOutcome takes lines[length - 1]).
  # So the true sentence scrolled past and the fixed, false one was the one
  # on the page. This returns non-zero now, and sets the exact clause each
  # caller appends to its own message, so the last line is the true one
  # whichever way the rollback went.
  RESTORE_NOTE="; every file was put back"
  if (( ${#incomplete[@]} )); then
    fact restore_incomplete "${incomplete[*]}"
    RESTORE_NOTE=", and the rollback could not put every file back: ${incomplete[*]}. Check those by hand before trusting this fleet's registries"
    return 1
  fi
  return 0
}
place() {  # candidate target owner group mode -> 0 ok, 1 could not, 2 refused
  # Round 5 (#648, review5-2.json) closed the temp NAME being guessable
  # (mktemp's own O_CREAT|O_EXCL replaced a predictable "$2.new.$$"). Round 7
  # (#648, review7-0.json CRITICAL) closes the DIRECTORY that name lived in
  # being found by ordinary path lookup at all: `dir="$(dirname "$target")"`
  # then `mktemp "$dir/..."` and `mv -fT` both let the OS resolve
  # "dashboard/config" or "advisor/state" fresh, which follows a symlink an
  # account that owns dashboard/ or advisor/ swapped in at any component
  # along the way -- reproduced end to end in review7-0.json against this
  # exact function. dirsafe.py's own header carries the full account of the
  # bug and the fix; this function is now the thinnest possible caller of
  # it: name which of this program's own directories $target lives in
  # (dirsafe_locate, a string match, never a filesystem call) and hand the
  # rest to the one primitive every write in this program now shares.
  local candidate="$1" target="$2" owner="$3" group="$4" mode="$5"

  # Refused before dirsafe.py is even invoked: a target that is already a
  # symlink, or exists as something other than a plain file, is tampering to
  # name, never a state this function silently rewrites through or replaces
  # by rename. dirsafe.py's own op_put makes the identical check again,
  # relative to the directory fd it actually opened rather than by a path
  # that could have changed since this line ran; this one is cheap, named,
  # and fails fast.
  [[ -L "$target" ]] && return 1
  [[ -e "$target" && ! -f "$target" ]] && return 1

  dirsafe_locate "$target" || return 1
  dirsafe "$DS_ANCHOR" "$DS_RELPATH" "$DS_EXTRA" "$DS_MASK" put "$owner" "$group" "$mode" "$candidate" "$DS_LEAF"
}

# Refused BEFORE anything is written, so a wide file that is about to be
# refused does not first cost the registries a rename to put back.
check_token_mode() {  # path -> 0 ok, 1 too wide (prints the mode), 2 a symlink
  local mode
  # A symlink is its own refusal, named apart from "too wide" rather than
  # left to the accident that `stat` with no -L reports the link's own mode
  # (typically 777) rather than its target's: that accident would have
  # caught most of them anyway, but not a host where a symlink's own mode
  # happens to read 640, and the message an operator reads should say what
  # this actually is.
  [[ -L "$1" ]] && return 2
  [[ -e "$1" ]] || return 0
  mode="$(stat -c '%a' "$1" 2>/dev/null || echo '?')"
  if [[ "$mode" =~ ^[0-7]{3,4}$ ]] && (( (8#$mode & ~8#640) != 0 )); then
    printf '%s' "$mode"
    return 1
  fi
  return 0
}

# The bug this used to leave open, before TOKEN_DIR moved out from under
# $ADV_STATE (see TOKEN_DIR's own declaration above): a directory's
# permissions govern what its CONTENTS may do, never what happens to the
# directory's OWN entry in its PARENT, so a plain `[[ -L "$TOKEN_DIR" ]]`
# followed by a separate `install -d -o root ...` left a race window an
# account that owned the parent could always win, however TOKEN_DIR itself
# was owned or moded (round 3 review, CRITICAL: a background loop with no
# special timing, racing exactly that ownership, turned every version of
# write_token()'s own per-write recheck into a root arbitrary-file-write).
# Structural now, not a faster check for the same reachable rename: TOKEN_DIR
# lives under $ETC, whose own ancestors are root's on any host this ever
# runs on, so the parent this function checks below is checked as a second
# independent line of defence, never as the thing that makes the rename
# unreachable in the first place. Both checks (the parent, and this
# directory) run on a file descriptor opened with O_NOFOLLOW rather than a
# path re-resolved afterwards: a symlink at either name, planted before this
# call or in the instant between the mkdir attempt and the open, makes the
# open itself fail (ELOOP) rather than silently traverse it, so there is no
# separate check-then-use step left to race even where the parent is not
# where this program expects it to be.
ensure_token_dir() {  # dir -> 0 ok, 1 refused (other), 2 refused (symlink)
  # Round 7 (#648, review7-0.json): this used to be this program's OWN
  # one-off implementation of the walk dirsafe.py now generalizes -- a
  # parent check, then a create-or-verify on the directory itself, both by
  # O_NOFOLLOW-opened file descriptor rather than by a path re-resolved
  # afterwards. TOKEN_DIR has exactly one parent ($ETC, root's own on any
  # host this ever runs on) so that walk was already correct for THIS
  # directory; it is routed through dirsafe.py's own "ensuredir" op now so
  # there is one copy of the discipline, not two that could drift the next
  # time either changed.
  local dir="$1" want_owner
  [[ "$dir" == "$TOKEN_DIR" ]] || return 1
  if (( BROKER_UID == 0 )); then want_owner=0; else want_owner="$BROKER_UID"; fi
  dirsafe "$ETC" "" "" 022 ensuredir fleet-tokens "$want_owner" "$SHARED_GROUP" 750
}

write_token() {  # path value -> 0 ok, 1 could not, 2 refused
  local path="$1" value="$2"
  local dir tokname src o g rc

  # This program writes exactly one directory's worth of bearer tokens, and
  # every caller already derives $path from $TOKEN_DIR and a label, never
  # from anything a payload names. Asserted here too, as a standing
  # invariant rather than trusted from those call sites alone: a future
  # caller that constructed a path outside TOKEN_DIR, whatever its reason,
  # is refused before anything is opened rather than allowed to write
  # wherever it named. A plain string compare, not a filesystem call, so it
  # adds no re-resolution of its own for anything to race.
  dir="$(dirname -- "$path")"
  [[ "$dir" == "$TOKEN_DIR" ]] || return 1

  # The bug this replaced (round 4) was a plain shell redirection into
  # "$path.new", a name fully deterministic from the caller's own LABEL. The
  # bug round 7 closes is TOKEN_DIR itself being found by ordinary path
  # lookup -- `dir="$(dirname "$path")"` above is used only to compare
  # against the fixed constant $TOKEN_DIR, a string match, never handed to
  # mktemp or mv. dirsafe.py's own "put" op walks from $ETC by directory
  # descriptor, builds its temp under a random name INSIDE TOKEN_DIR's own
  # fd, and renames onto $path in one atomic rename(2) relative to that same
  # fd -- never a plain shell redirection, never a path re-resolved after
  # the walk, and never a window where $path does not exist at all (a
  # concern here specifically because the Advisor proxy re-reads this file
  # fresh, with no cache, on every proxied request).
  [[ -L "$path" ]] && return 1
  tokname="$(basename -- "$path")"

  # The content is written into $WORK (root's own private mktemp -d, mode
  # 0700) first: dirsafe.py's own put reads its source from an ordinary
  # path, and $WORK is the one directory in this program nothing but root
  # has ever been able to touch, so a plain path read there needs none of
  # the discipline TOKEN_DIR itself gets.
  src="$WORK/write_token.$$"
  ( umask 077; printf '%s\n' "$value" > "$src" ) || { rm -f "$src"; return 1; }
  # root:SHARED_GROUP, because the Advisor reads this token through that
  # group. Under the test harness (never real root) a chown to SHARED_GROUP
  # would fail outright unless this account happens to already be in it, so
  # the harness case chowns to nothing but itself, the same distinction the
  # original body drew.
  if (( BROKER_UID == 0 )); then o=root; g="$SHARED_GROUP"; else o="$BROKER_UID"; g="$(id -g)"; fi
  dirsafe "$ETC" fleet-tokens "" 022 put "$o" "$g" 640 "$src" "$tokname"
  rc=$?
  rm -f "$src"
  return $rc
}

# ── reading a file an unprivileged account owns (#648, round 4) ──────────
#
# fleet.yaml and fleet-links.json sit in a directory the DASHBOARD account
# owns; the Advisor's own registry sits in a directory the ADVISORD account
# owns. Both are "a config directory it owns" in the header's own words, and
# owning a directory means owning every entry inside it: either account can
# replace one of these files with a symlink or a FIFO at will, the same fact
# that made TOKEN_DIR's old location a bug. A plain `cp -a` does not save a
# reader from that, checked directly: it copies a symlink AS a symlink
# (rather than reading through it, so the copy in $WORK becomes the same
# trap one line later) and recreates a FIFO as a FIFO (rather than reading
# it, so the copy in $WORK hangs the first ordinary `open()` that tries to
# read it). Neither failure shows up at the `cp -a` call; both show up one
# step downstream, in whichever python3 heredoc opens the "copy" by path.
#
# snapshot_registry_file takes the file by descriptor instead, relative to a
# parent directory opened with O_NOFOLLOW, with O_NONBLOCK on the file's own
# open so a FIFO refuses at open() rather than blocking this connection for
# the length of its RuntimeMaxSec, and requires the result to be a genuine
# regular file no larger than any registry this program has ever written
# before trusting a byte of it. Every caller passes the SAME snapshot on to
# every later step that needs that file's content in the same verb, rather
# than opening the live path a second time: one read, by descriptor, per
# connection, per file.
REGISTRY_SNAP_MAX_BYTES=1048576
snapshot_registry_file() {  # parent-dir filename out-path [max-bytes] -> 0 written, 1 absent, 2 refused
  # Round 4 gave this its own O_NOFOLLOW-by-descriptor read, but only ever
  # checked ONE parent -- $CONFIG_DIR or $ADV_STATE itself -- never whatever
  # sits ABOVE it. An account that owns dashboard/ or advisor/ could still
  # symlink-swap $CONFIG_DIR or $ADV_STATE's own entry in ITS parent and this
  # function would open straight through it, the identical class of bug
  # review7-0.json found in place(). Round 7 gives it the same whole-chain
  # walk every write now shares, from $INSTALL_DIR down, rather than a
  # second parent-only check that would only have covered the read side.
  local parent="$1" name="$2" out="$3" max="${4:-$REGISTRY_SNAP_MAX_BYTES}"
  local anchor relpath extra mask
  case "$parent" in
    "$CONFIG_DIR")
      anchor="$INSTALL_DIR"; relpath="dashboard/config"; mask=002
      extra="$(id -u "$DASH_USER" 2>/dev/null)" || extra=""
      ;;
    "$ADV_STATE")
      anchor="$INSTALL_DIR"; relpath="advisor/state"; mask=002
      # The dashboard's account is the fallback for a unit naming an
      # account this host no longer has, not "" -- the sentence this
      # already meant to say ("the Advisor's own account where this host
      # has one, the dashboard's otherwise"), which a bare `id -u` on a
      # dead name quietly turned into "root only".
      extra="$(id -u "${ADV_USER:-$DASH_USER}" 2>/dev/null || id -u "$DASH_USER" 2>/dev/null || true)"
      ;;
    *) return 2 ;;
  esac
  dirsafe "$anchor" "$relpath" "$extra" "$mask" read "$name" "$out" "$max"
}

# Three thin wrappers, one per file this program ever reads out of a
# directory it does not own, each setting one global to either the snapshot
# path (present and safe) or "" (absent -- ENOENT, which every caller
# already treats as "start from empty", same as before this round). A
# refusal (status 2: not a plain file, or this program could not read it
# without risking the connection) is named on the socket rather than
# silently folded into "absent" -- an operator fixes a planted symlink by
# hand, and folding it into "start from empty" would let a hostile
# advisord or dashboard account make root act as though a real fleet had
# none of these rows at all.
SNAP_FLEET_YAML=""
snap_fleet_yaml() {  # -> refuses by name, or sets SNAP_FLEET_YAML
  SNAP_FLEET_YAML=""
  local rc=0
  snapshot_registry_file "$CONFIG_DIR" fleet.yaml "$WORK/snap.fleet.yaml" || rc=$?
  case "$rc" in
    0) SNAP_FLEET_YAML="$WORK/snap.fleet.yaml" ;;
    1) : ;;
    *) refuse registry_unreadable "$FLEET_YAML is not a plain file this program will read, or could not be read without risking this connection. Nothing was changed." ;;
  esac
}
SNAP_FLEET_LINKS=""
snap_fleet_links() {  # -> refuses by name, or sets SNAP_FLEET_LINKS
  SNAP_FLEET_LINKS=""
  local rc=0
  snapshot_registry_file "$CONFIG_DIR" fleet-links.json "$WORK/snap.links.json" || rc=$?
  case "$rc" in
    0) SNAP_FLEET_LINKS="$WORK/snap.links.json" ;;
    1) : ;;
    *) refuse registry_unreadable "$FLEET_LINKS is not a plain file this program will read, or could not be read without risking this connection. Nothing was changed." ;;
  esac
}
SNAP_ADV_FLEET=""
snap_adv_fleet() {  # -> refuses by name, or sets SNAP_ADV_FLEET
  SNAP_ADV_FLEET=""
  # Absent outright (this host has no Advisor tree at all) is the ordinary
  # case and not a refusal: every caller already treats "$ADV_STATE" missing
  # the same way it treats "$ADV_FLEET" missing. That question is left to
  # the chain walk below rather than asked here with `[[ -d "$ADV_STATE" ]]`
  # (#648, round 8): `-d` follows symlinks, so a dangling symlink or a plain
  # file planted at advisor/state by the account that owns advisor/ read as
  # "no Advisor installed" and this function returned quietly, which is
  # exactly the "fold tampering into absent" the other three wrappers refuse
  # to do. open_chain answers the same two cases apart on its own: a
  # genuinely missing hop is status 1 (absent), and a symlink or a
  # non-directory at any hop is status 2 (refused, named below).
  local rc=0
  snapshot_registry_file "$ADV_STATE" fleet.json "$WORK/snap.adv.json" || rc=$?
  case "$rc" in
    0) SNAP_ADV_FLEET="$WORK/snap.adv.json" ;;
    1) : ;;
    *) refuse registry_unreadable "$ADV_FLEET is not a plain file this program will read, or could not be read without risking this connection. Nothing was changed." ;;
  esac
}
# The dashboard's fleet-trust seed sits in $CONFIG_DIR too, the same
# unprivileged-owned directory as fleet.yaml and fleet-links.json, so it
# gets the same guard: a `sed` straight against the live path would follow a
# symlink planted there, or hang this connection open on a FIFO, exactly
# the two failures snapshot_registry_file exists to close.
snap_fleet_trust() {  # -> refuses by name, or sets SNAP_FLEET_TRUST
  SNAP_FLEET_TRUST=""
  local rc=0
  snapshot_registry_file "$CONFIG_DIR" fleet-trust.yaml "$WORK/snap.fleet-trust.yaml" || rc=$?
  case "$rc" in
    0) SNAP_FLEET_TRUST="$WORK/snap.fleet-trust.yaml" ;;
    1) : ;;
    *) refuse registry_unreadable "$INSTALL_DIR/$FLEET_TRUST_REL is not a plain file this program will read, or could not be read without risking this connection. Nothing was sent." ;;
  esac
}

# port_free's DEFINITION is hoisted; the port pool it reads ($PLAN, the
# LISTENING scan) stays computed inside whichever verb allocates one, since
# only a verb that needs a fresh port pays for the `ss` call.
port_free() {
  local p="$1"
  python3 -c '
import json, sys
plan, port = sys.argv[1], int(sys.argv[2])
used = set(json.load(open(plan))["used"])
raise SystemExit(0 if port not in used else 1)
' "$PLAN" "$p" || return 1
  case " $LISTENING " in *" $p "*) return 1 ;; esac
  return 0
}

# ── the node the candidates are read back with (#318, #964) ─────────────
# One answer for every verb that needs it: validate_candidates_or_refuse
# below, and `arm-key` and `arm-key-check`, which the page asks before a
# pairing code exists (#964). A fresh aggregator whose grant found no node
# used to pass both of those and then refuse the approval itself, after the
# passkey. Now the first thing the operator hears is that node is missing,
# with the one command that finds it.
#
# Found, never run here: this only names the binary. It runs in exactly one
# place, under runuser as the dashboard account (#370), so a node under the
# operator's nvm is the one the dashboard already runs as itself.
# Sets NODE_BIN, or refuses by name and never returns.
reader_node_or_refuse() {
  local cand home reach
  # The conf's NODE_BIN is the answer when the grant installer resolved one
  # (#318). The run-time search below stays as the fallback, for a host whose
  # grant predates that key.
  if [[ -n "$NODE_BIN" && ! -x "$NODE_BIN" ]]; then
    # Named apart from "this host has no node", the way pm2:not-found is named
    # apart from a pm2 failure: a conf that points at a node which is not there
    # any more (an nvm version pruned after the grant ran) is a different
    # problem, with a different fix, from a host that never had one.
    refuse no_node "$CONF names NODE_BIN=$NODE_BIN, and there is no executable there. Run the grant installer again, which finds the node the dashboard runs now: curl -fsSL https://get.aperire.one | bash -s -- --dir $INSTALL_DIR --run fleet-broker-grant. Nothing was written"
  fi
  if [[ -z "$NODE_BIN" ]]; then
    for cand in "$(command -v node 2>/dev/null || true)" \
                "$(su -s /bin/bash -c 'command -v node' "$DASH_USER" 2>/dev/null || true)"; do
      [[ -n "$cand" && -x "$cand" ]] && { NODE_BIN="$cand"; break; }
    done
  fi
  if [[ -z "$NODE_BIN" ]]; then
    home="$(getent passwd "$DASH_USER" | cut -d: -f6)"
    # The directory is TESTED before find is asked to walk it, and the whole
    # pipeline ends in `|| true` (#318). `find` on a missing directory exits 1;
    # under `pipefail` that is the pipeline's status, and as the last command
    # of an `&&` list it was the script's status, so `set -e` killed this
    # program silently on every host whose dashboard account has no ~/.nvm —
    # before it could reach the honest `no_node` refusal ten lines below. A
    # fallback that cannot find a thing must return empty, never take the
    # program down.
    if [[ -n "$home" && -d "$home/.nvm/versions/node" ]]; then
      NODE_BIN="$(find "$home/.nvm/versions/node" -maxdepth 3 -path '*/bin/node' -type f 2>/dev/null | sort -V | tail -1 || true)"
    fi
  fi
  # A REFUSAL, not a warning. aperire-fleet-add.sh warns and continues here
  # because an operator is watching it; nothing is watching this. Each one
  # carries the grant command whole, because that is what the page offers
  # as the fix (settings-api.ts matches it out of this sentence).
  [[ -n "$NODE_BIN" && -x "$NODE_BIN" ]] \
    || refuse no_node "node is not on this host where this program can find it, so the two candidate registries cannot be read back with the parsers the dashboard runs. Run the grant installer again, which finds the node the dashboard runs: curl -fsSL https://get.aperire.one | bash -s -- --dir $INSTALL_DIR --run fleet-broker-grant. Nothing was written"
  [[ -f "$INSTALL_DIR/dashboard/node_modules/tsx/dist/cli.mjs" ]] \
    || refuse no_node "$INSTALL_DIR/dashboard/node_modules has no tsx, so the candidates cannot be read back with the parsers the dashboard runs. Run npm ci in $INSTALL_DIR/dashboard, then: curl -fsSL https://get.aperire.one | bash -s -- --dir $INSTALL_DIR --run fleet-broker-grant. Nothing was written"
  # The account the read-back drops to, judged here and not only at the
  # approval (#972). This used to skip the reach check below when the conf
  # pinned no account or runuser was missing, so a host with an old conf
  # passed the pairing check and the mint, and the approval then refused
  # no_account_pinned after the passkey. Now every verb that asks for node
  # meets the same refusals the read-back would, before a code exists.
  reader_account_or_refuse

  # And asked as the account that will run it, not judged as root (#970
  # review, L1): root can execute a node the dashboard account cannot reach
  # (passage lost on an nvm directory, a home made 0700), and that node used
  # to pass both pairing checks and then end the approval's read-back with no
  # verdict, after the passkey. `test -x` is asked about a copy of the path,
  # so the line holds no "$NODE_BIN" followed by an argument: node itself
  # still runs from exactly one place.
  #
  # runuser is asked to switch first, with nothing to run but `true`, so a
  # switch that fails is named as one (#972 review, N2) and never read as
  # "that account cannot run node". Both exit 1, and only this tells them
  # apart.
  "$RUNUSER_BIN" -u "$DASH_ACCOUNT" -- true 2>/dev/null \
    || refuse no_runuser "runuser could not switch to $DASH_ACCOUNT here, so the candidates cannot be read back as that account, and they will not be read back as root. Check that the account can be switched to (its shell, PAM's runuser rules), or run the grant installer again: curl -fsSL https://get.aperire.one | bash -s -- --dir $INSTALL_DIR --run fleet-broker-grant. Nothing was written"
  reach="$NODE_BIN"
  "$RUNUSER_BIN" -u "$DASH_ACCOUNT" -- test -x "$reach" 2>/dev/null \
    || refuse no_node "$DASH_ACCOUNT, the account that reads the registries back, cannot run $NODE_BIN, though root can. Give it passage to that node, or run the grant installer again, which checks it as that account: curl -fsSL https://get.aperire.one | bash -s -- --dir $INSTALL_DIR --run fleet-broker-grant. Nothing was written"
  return 0
}

# The account the candidates are read back as, and the program that switches
# to it (#370), checked as one set of refusals. Asked by reader_node_or_refuse
# above, so the approval's read-back, arm-key and arm-key-check all refuse the
# same host the same way, and the last two do it before a code exists (#972).
# Every one is a refusal rather than a fallback. The fallback that would read
# naturally here is "run it as root anyway", and that is the vulnerability.
# Sets VAL_UID and VAL_GROUP, or refuses by name and never returns.
reader_account_or_refuse() {
  [[ -n "$DASH_ACCOUNT" ]] \
    || refuse no_account_pinned "$CONF does not pin the account the dashboard runs as, so this program has nothing to drop to before it reads the candidates back, and it will not read them back as root. Re-run the grant installer on this host: curl -fsSL https://get.aperire.one | bash -s -- --dir $INSTALL_DIR --run fleet-broker-grant. Nothing was written"
  # root, by name or by number. The grant installer already refuses to
  # install on a host whose dashboard runs as root; this is the same rule at
  # the point of use, because a conf saying `DASH_ACCOUNT=root` would put the
  # install tree's own modules back inside a root process.
  [[ "$DASH_ACCOUNT" != root ]] \
    || refuse bad_account_pinned "$CONF pins the validation to root, and reading the candidates back as root is the one thing this program will not do. Nothing was written"
  VAL_UID="$(id -u "$DASH_ACCOUNT" 2>/dev/null || true)"
  [[ -n "$VAL_UID" ]] \
    || refuse bad_account_pinned "$CONF pins the validation to an account called \"$DASH_ACCOUNT\", and there is no such account on this host. Re-run the grant installer: curl -fsSL https://get.aperire.one | bash -s -- --dir $INSTALL_DIR --run fleet-broker-grant. Nothing was written"
  [[ "$VAL_UID" != 0 ]] \
    || refuse bad_account_pinned "the account $CONF pins the validation to is uid 0, and reading the candidates back as root is the one thing this program will not do. Nothing was written"
  VAL_GROUP="$(id -gn "$DASH_ACCOUNT" 2>/dev/null || true)"
  [[ -n "$VAL_GROUP" ]] \
    || refuse bad_account_pinned "\"$DASH_ACCOUNT\" has no primary group, so there is no group this program could hand the candidates to. Nothing was written"
  [[ -n "$RUNUSER_BIN" && -x "$RUNUSER_BIN" ]] \
    || refuse no_runuser "runuser is not on this host, so the candidates cannot be read back as $DASH_ACCOUNT, and they will not be read back as root. Install util-linux. Nothing was written"
  return 0
}

# One candidate fleet.yaml and one candidate fleet-links.json, read back by
# the REAL dashboard parsers as the dashboard account, never as root (#370).
# Approve, attach-advisor, detach-advisor and refresh-advisor-token's
# fleet.yaml-touching path all call this rather than each staging its own
# copy of the identity checks and the node-under-tsx invocation:
# scripts/test-fleet-broker.sh holds this program to exactly one such call
# site, on the reasoning that a second call site is a second, unaudited
# answer to who runs it. Refuses by name and never returns on any failure; a
# caller that
# reaches the line after this call has a candidate pair the shipped parsers
# already accept, so the rename that follows is the only remaining question.
#
# Callers set $LABEL, $WANT_FLEET_ROWS and $WANT_LINK_ROWS before calling,
# and $VALIDATE_EXPECT when the label is not meant to be in both files:
# `absent` for revoke, `fleet_only` for repin (#859). Unset is `present`,
# which is every check this made before #859.
validate_candidates_or_refuse() {  # candidate-fleet-yaml candidate-links-json
  local cand_fleet="$1" cand_links="$2"

  # ── and it runs as the DASHBOARD, not as root (#370) ───────────────────
  # Everything that checks the account is in reader_account_or_refuse, which
  # reader_node_or_refuse asks before its reach check: the pinned account, root by name and by
  # number, a missing account or group, and runuser. Each is a refusal; a
  # caller that reaches the next line has VAL_UID and VAL_GROUP set.
  reader_node_or_refuse

  # The candidates, handed OVER rather than reached for. $WORK is root's own
  # 0700 mktemp and the dashboard account cannot see into it, so the two
  # files it has to read are copied into a directory of their own.
  #
  # THE DIRECTORY IS ROOT'S, the files inside it are the account's, and that
  # asymmetry is the whole of it. Root owns the directory at 0750 with the
  # account's group, so the account can walk in and read, and cannot create,
  # rename or unlink anything there: a directory that account owned would be
  # one where a symlink left in place makes root's own copy land somewhere
  # else. The two files are chowned to the account at 0600 rather than left
  # root:<group> 0640, because fleet-links.json is placed 0600 when it is
  # written for real and staging it group-readable would widen that file for
  # as long as the check runs. What the account can do with a file of its own
  # is edit the copy it is about to have its own parser read, which changes
  # nothing: the bytes that get renamed into place are root's, in $WORK, and
  # the parser was already that account's code.
  VWORK="$(mktemp -d)"
  if ! { chgrp "$VAL_GROUP" "$VWORK" \
         && chmod 0750 "$VWORK" \
         && cp "$cand_fleet" "$VWORK/fleet.yaml" \
         && cp "$cand_links" "$VWORK/links.json" \
         && chown "$DASH_ACCOUNT" "$VWORK/fleet.yaml" "$VWORK/links.json" \
         && chmod 0600 "$VWORK/fleet.yaml" "$VWORK/links.json"; } 2>/dev/null; then
    refuse candidate_refused "the two registries this write would leave could not be handed to $DASH_ACCOUNT to read back, so neither was written"
  fi
  # Asked rather than assumed, because the answer depends on this host: the
  # temp root is whatever TMPDIR says, and a private or root-only one is a
  # directory that account cannot walk into however the files inside it are
  # owned. A validation that cannot read its own candidates would otherwise
  # come back as a parser refusal, which is a sentence about the wrong thing.
  "$RUNUSER_BIN" -u "$DASH_ACCOUNT" -- test -r "$VWORK/fleet.yaml" 2>/dev/null \
    || refuse candidate_refused "$DASH_ACCOUNT cannot read the candidates this program staged for it in $VWORK, so they were not read back and neither registry was written. Check TMPDIR for the broker's own unit, and that $CONF still pins the account the dashboard runs as"

  # The script, in a name of its own so the line that runs it stays one line
  # with the identity it runs under (see scripts/test-fleet-broker.sh, which
  # holds exactly that).
  #
  # It prints ONE WORD to stdout and nothing else: `ok`, or `refused <code>`
  # out of the set the case below knows. The sentence an operator reads is
  # root's, off that code. Nothing else crossing back here is used for
  # anything, because everything else crossing back here is the dashboard
  # account's to compose.
  VALIDATE_JS="$(cat <<'JS'
import { readFileSync } from 'node:fs';
import { loadFleetRegistry } from './lib/fleet-registry.ts';
import { parseLinkRegistry, crossCheckLinkRows } from './lib/fleet-link-hub.ts';
const say = (v) => { process.stdout.write(v + '\n'); process.exit(0); };
const label = process.env.APERIRE_CAND_LABEL;
// #859: what the candidates must say about this label. `present` is every
// write before #859 and the default for any other value, so a caller that
// sets nothing gets exactly the old checks. `absent` is revoke: the label is
// in neither file. `fleet_only` is repin: one fleet.yaml row, and a link row
// is neither required nor forbidden (a tunnel row has none).
const mode = ['absent', 'fleet_only'].includes(process.env.APERIRE_CAND_EXPECT ?? '')
  ? process.env.APERIRE_CAND_EXPECT : 'present';
const fleet = loadFleetRegistry(process.env.APERIRE_CAND_YAML);
if (fleet.error) say('refused fleet_unreadable');
const links = parseLinkRegistry(readFileSync(process.env.APERIRE_CAND_LINKS, 'utf8'));
if (links.error) say('refused links_unreadable');
if (mode === 'absent') {
  if (fleet.nodes.some((n) => n.label === label)) say('refused fleet_row_survived');
  if (links.links.some((l) => l.label === label)) say('refused links_row_survived');
} else {
  if (!fleet.nodes.some((n) => n.label === label)) say('refused fleet_row_missing');
  if (mode === 'present' && !links.links.some((l) => l.label === label)) say('refused links_row_missing');
}
if (crossCheckLinkRows(links.links, fleet.nodes)) say('refused cross_check');
// Plan §3.5 step 5: the previous count plus one, or the same on a rejoin.
// Every check above is about the row being ADDED; these two are the only
// ones that notice a row being LOST, and a lost row empties every link on
// the fleet as soon as the dashboard next reads this file.
const wantFleet = Number(process.env.APERIRE_WANT_FLEET_ROWS);
const wantLinks = Number(process.env.APERIRE_WANT_LINK_ROWS);
if (Number.isInteger(wantFleet) && wantFleet >= 0 && fleet.nodes.length !== wantFleet) say('refused fleet_count');
if (Number.isInteger(wantLinks) && wantLinks >= 0 && links.links.length !== wantLinks) say('refused links_count');
// And exactly one row for this label in each, not two. Revoke has already
// proven there are none; repin wants one fleet.yaml row and at most one link.
if (mode !== 'absent' && fleet.nodes.filter((n) => n.label === label).length !== 1) say('refused fleet_duplicate');
if (mode === 'present' && links.links.filter((l) => l.label === label).length !== 1) say('refused links_duplicate');
if (mode === 'fleet_only' && links.links.filter((l) => l.label === label).length > 1) say('refused links_duplicate');
say('ok');
JS
  )"
  VALIDATE_OUT="$WORK/validate.out"
  # Captured, and never read back. The unit sets StandardError=socket, so an
  # unredirected stderr here would be the dashboard account writing straight
  # onto this program's answer.
  VALIDATE_ERR="$WORK/validate.err"
  VAL_HOME="$(getent passwd "$DASH_ACCOUNT" | cut -d: -f6 || true)"
  [[ -n "$VAL_HOME" ]] || VAL_HOME="$INSTALL_DIR/dashboard"
  # THE DIRECTORY IS THE MODULE RESOLUTION. `./lib/fleet-registry.ts` and the
  # bare `tsx` specifier both resolve against the working directory, so a run
  # in the wrong one is not a wrong answer, it is ERR_MODULE_NOT_FOUND and an
  # approval refused on every host. It is set twice on purpose.
  #
  # Outside: `cd`, which `runuser -u` keeps (measured on util-linux 2.37.2:
  # the working directory survives the switch, and only --login moves it).
  # Inside: env --chdir, so it is the switched process itself that lands
  # there and not a directory it inherited. --chdir arrived in coreutils
  # 8.28, so it is used when this host's env takes it and left out when it
  # does not. The placeholder keeps the array non-empty, because an empty
  # one under `set -u` is a fatal expansion on bash before 4.4.
  VAL_ENV_CHDIR=(-u APERIRE_ENV_PLACEHOLDER)
  if env -C / true 2>/dev/null; then VAL_ENV_CHDIR=(-C "$INSTALL_DIR/dashboard"); fi
  # HOME, stated rather than inherited. `runuser -u` sets it from the
  # account's passwd entry (2.37.2, measured), which is the same value this
  # reads with getent, and stating it means the answer does not depend on
  # which runuser a host has. tsx and node both write caches under it, and
  # root's own home is not a directory this account can read.
  VAL_STATUS=0
  ( cd "$INSTALL_DIR/dashboard" \
    && "$RUNUSER_BIN" -u "$DASH_ACCOUNT" -- env "${VAL_ENV_CHDIR[@]}" HOME="$VAL_HOME" APERIRE_CAND_YAML="$VWORK/fleet.yaml" APERIRE_CAND_LINKS="$VWORK/links.json" APERIRE_CAND_LABEL="$LABEL" APERIRE_CAND_EXPECT="${VALIDATE_EXPECT:-present}" APERIRE_WANT_FLEET_ROWS="$WANT_FLEET_ROWS" APERIRE_WANT_LINK_ROWS="$WANT_LINK_ROWS" "$NODE_BIN" --import tsx --input-type=module -e "$VALIDATE_JS" \
  ) >"$VALIDATE_OUT" 2>"$VALIDATE_ERR" || VAL_STATUS=$?

  # Bounded before it is matched. A module that printed for ever would
  # otherwise be a module that decides how much this program reads.
  VAL_VERDICT="$(head -c 200 "$VALIDATE_OUT" 2>/dev/null | tr -d '\r' | sed '/^[[:space:]]*$/d' | tail -n 1 || true)"
  if (( VAL_STATUS != 0 )); then
    # A run that died says nothing about the candidates, so this program says
    # nothing about them either. It does not repeat what came back: the whole
    # point of the switch is that what came back is the dashboard account's.
    refuse candidate_refused "the two registries this write would leave could not be read back by the parsers the dashboard runs, so neither was written. That check runs as $DASH_ACCOUNT, and it ended without a verdict"
  fi
  case "$VAL_VERDICT" in
    ok) : ;;
    "refused fleet_unreadable")
      refuse candidate_refused "the fleet.yaml this write would leave is not one the dashboard's own parser reads, so neither registry was written" ;;
    "refused links_unreadable")
      refuse candidate_refused "the fleet-links.json this write would leave is not one the dashboard's own parser reads, so neither registry was written" ;;
    "refused fleet_row_survived")
      refuse candidate_refused "the fleet.yaml this write would leave still names \"$LABEL\", so neither registry was written" ;;
    "refused links_row_survived")
      refuse candidate_refused "the fleet-links.json this write would leave still names \"$LABEL\", so neither registry was written" ;;
    "refused fleet_row_missing")
      refuse candidate_refused "the row for \"$LABEL\" is not in the fleet.yaml this write would leave, so neither registry was written" ;;
    "refused links_row_missing")
      refuse candidate_refused "the row for \"$LABEL\" is not in the fleet-links.json this write would leave, so neither registry was written" ;;
    "refused cross_check")
      refuse candidate_refused "the pair of registries this write would leave do not agree with each other, so neither was written" ;;
    "refused fleet_count")
      refuse candidate_refused "the fleet.yaml this write would leave does not hold the $WANT_FLEET_ROWS rows this write should have left, so neither registry was written" ;;
    "refused links_count")
      refuse candidate_refused "the fleet-links.json this write would leave does not hold the $WANT_LINK_ROWS rows this write should have left, so neither registry was written" ;;
    "refused fleet_duplicate")
      refuse candidate_refused "the fleet.yaml this write would leave names \"$LABEL\" more than once, so neither registry was written" ;;
    "refused links_duplicate")
      refuse candidate_refused "the fleet-links.json this write would leave names \"$LABEL\" more than once, so neither registry was written" ;;
    *)
      refuse candidate_refused "the check that reads these two registries back answered in a shape this program does not take, so neither was written" ;;
  esac
}

# ── #641: reading one existing link row, for the three advisor verbs ─────
# attach-advisor, detach-advisor and refresh-advisor-token all act on a row
# fleet.yaml and fleet-links.json ALREADY hold, never a new one, so what
# they need is the row's own current fields, read as raw strings rather
# than re-derived from any of approve's port/convention globals: a
# hand-registered row that does not follow #458's own convention path must
# come back out exactly as it went in.
ROW_PLAN="$WORK/row-plan.json"
read_row_plan_or_refuse() {  # label -> writes $ROW_PLAN
  local label="$1"
  # One guarded read of each registry, reused for every field this verb
  # goes on to check: never the live path a second time (#648, round 4).
  snap_fleet_yaml
  snap_fleet_links
  snap_adv_fleet
  if ! python3 - "$SNAP_FLEET_YAML" "$SNAP_FLEET_LINKS" "$SNAP_ADV_FLEET" "$label" "$ROW_PLAN" <<'PY' 2>"$WORK/row-plan.err"
import json, os, sys
try:
    import yaml
except ImportError:
    sys.stderr.write("python3 has no yaml module, and fleet.yaml is yaml\n")
    raise SystemExit(3)

fleet_path, links_path, adv_path, label, out_path = sys.argv[1:6]
# The row shape emit_link_row (approve's own) ever writes. A row carrying a
# key outside this set was not written by this program, and this program
# will not rewrite it by hand without knowing every field it holds.
known = {"label", "role", "dashboard_url", "read_origin", "token_path",
         "expected_pubkey_node", "transport", "advisor_origin",
         "advisor_token_path"}

def port_of(origin):
    if not isinstance(origin, str):
        return None
    try:
        from urllib.parse import urlparse
        p = urlparse(origin).port
        return int(p) if p else None
    except ValueError:
        return None

rows = []
if os.path.exists(fleet_path):
    with open(fleet_path) as f:
        doc = yaml.safe_load(f.read())
    if doc is None:
        doc = {}
    if not isinstance(doc, dict) or not isinstance(doc.get("fleet", []), list):
        sys.stderr.write("fleet.yaml is not a mapping with a fleet: list\n")
        raise SystemExit(3)
    rows = doc.get("fleet") or []

used = set()
row = None
extra_keys = []
for r in rows:
    if not isinstance(r, dict):
        sys.stderr.write("fleet.yaml has an entry that is not a mapping\n")
        raise SystemExit(3)
    for key in ("read_origin", "advisor_origin"):
        p = port_of(r.get(key))
        if p:
            used.add(p)
    if r.get("label") == label:
        row = {
            "role": r.get("role"),
            "dashboard_url": r.get("dashboard_url"),
            "read_origin": r.get("read_origin"),
            "token_path": r.get("token_path"),
            "pin": r.get("expected_pubkey_node"),
            "transport": r.get("transport"),
            "advisor_origin": r.get("advisor_origin"),
            "advisor_token_path": r.get("advisor_token_path"),
        }
        extra_keys = sorted(set(r.keys()) - known)

link_rows = 0
link_has_label = False
link_advisor_port = None
if os.path.exists(links_path):
    with open(links_path) as f:
        doc = json.load(f)
    linkrows = (doc.get("links") or []) if isinstance(doc, dict) else []
    link_rows = len(linkrows)
    for r in linkrows:
        if not isinstance(r, dict):
            sys.stderr.write("fleet-links.json has an entry that is not an object\n")
            raise SystemExit(3)
        for key in ("read_port", "advisor_port"):
            if isinstance(r.get(key), int):
                used.add(r[key])
        if r.get("label") == label:
            link_has_label = True
            link_advisor_port = r.get("advisor_port")

# The Advisor's own registry names ports too (ruling, 2026-09-12; the same
# read approve's own plan builder makes), or the pool here could hand out a
# port the aggregator's Advisor already reaches another node on.
if os.path.exists(adv_path):
    with open(adv_path) as f:
        doc = json.load(f)
    peers = doc if isinstance(doc, list) else (doc.get("peers") or [])
    for r in peers:
        if isinstance(r, dict):
            p = port_of(r.get("origin"))
            if p:
                used.add(p)

with open(out_path, "w") as f:
    json.dump({
        "found": row is not None,
        "row": row,
        "extra_keys": extra_keys,
        "fleet_rows": len(rows),
        "link_rows": link_rows,
        "link_has_label": link_has_label,
        "link_advisor_port": link_advisor_port,
        "used": sorted(used),
    }, f)
PY
  then
    cat "$WORK/row-plan.err" >&2 || true
    refuse unreadable_registry "one of this host's registries could not be read, so nothing was changed: $(tr -d '\n' < "$WORK/row-plan.err")"
  fi
}

# Re-emits one fleet.yaml row from its OWN already-read fields, never from
# approve's port or convention globals, so attach-advisor and detach-advisor
# touch only the advisor_origin/advisor_token_path lines and leave a row's
# read_origin and token_path exactly as they already were.
#
# Callers set $ROW_LABEL, $ROW_EMIT_ROLE, $ROW_DASH_URL, $ROW_READ_ORIGIN,
# $ROW_TOKEN_PATH, $ROW_PIN and $ROW_EMIT_ADVISOR (1 or 0); when 1, also
# $ROW_ADVISOR_ORIGIN and $ROW_ADVISOR_TOKEN_PATH.
emit_attached_row() {
  printf '  - label: %s\n' "$ROW_LABEL"
  printf '    role: %s\n' "$ROW_EMIT_ROLE"
  if [[ -n "$ROW_DASH_URL" ]]; then printf '    dashboard_url: %s\n' "$ROW_DASH_URL"; fi
  printf '    read_origin: %s\n' "$ROW_READ_ORIGIN"
  printf '    token_path: %s\n' "$ROW_TOKEN_PATH"
  printf '    expected_pubkey_node: %s\n' "$ROW_PIN"
  printf '    transport: link\n'
  if [[ "$ROW_EMIT_ADVISOR" == "1" ]]; then
    printf '    advisor_origin: %s\n' "$ROW_ADVISOR_ORIGIN"
    printf '    advisor_token_path: %s\n' "$ROW_ADVISOR_TOKEN_PATH"
  fi
}

# ── revoke (#854, #859) ──────────────────────────────────────────────────
# One press takes a node out of this fleet, everywhere this host holds it, in
# two phases (#866 review, M3):
#
#   PHASE 1, the credential half. Removing access must not depend on parsing
#   a file the dashboard account can write, so this goes first and is never
#   rolled back by anything after it:
#     - its fleet-links.json row        (closes a live link at the reload)
#     - its line in root's fleet-nodes.conf (no longer a push destination)
#     - its two token files in TOKEN_DIR
#
#   PHASE 2, the registry half. Its fleet.yaml row and its peer in the
#   Advisor's fleet.json, all-or-nothing between the two (backed up, placed,
#   restore_all on any failure). A fleet.yaml this program cannot cut or
#   parse refuses THIS phase only, as registry_left, and the answer says the
#   link is already closed. A fleet.yaml link row with no fleet-links.json row
#   is a safe state at a reload: the cross-check walks from link rows to
#   fleet.yaml, never the other way.
#
# One SIGHUP after phase 1, so the link closes whatever phase 2 does, and a
# second after phase 2 when it placed anything.
#
# The label comes from the payload and nowhere else. Nothing read out of
# fleet.yaml names what gets removed: the files are searched FOR the label.
# The read-back as the dashboard account in phase 2 is a correctness check
# on the candidate, not a security control: that account is the one being
# defended against, and its answer can always be "ok". Root's own cut and
# the yaml.safe_load identity check are the gate.
#
# Phase 1 reads nothing but fleet-links.json, root's own record and the
# label; fleet.yaml is opened only after it, and parsed in a separate,
# capped process (#870 review, M1). This aggregator's own row is refused
# (#866 review, L1) and stops phase 2 only. A tunnel row is cut like a link
# row (#870 review, M4): the account a refusal there would guard against
# owns fleet.yaml and can delete the row itself. So the worst a compromised
# dashboard gets from revoke is a member removed, the denial of service #854
# already accepted.
#
# Idempotent. Each place that no longer holds the label counts as done, and
# the verb refuses no_row only when the label is in none of the five. So a
# revoke that was interrupted, or one an older broker left half done (the
# fleet.yaml row, or the Advisor's peer, still there), finishes on a re-run.
#
# advisor/state/fleet-tokens is never touched (#648, round 4; see the
# header). The Advisor is never signalled: advisord re-reads fleet.json when
# the file changes, and a Go process with no SIGHUP handler dies on one.
#
# Each piece is its own function, so a reader can hold one rule at a time.

# The cut attach-advisor and detach-advisor make (#620): exactly one
# "  - label: <label>" block, out to the next item or the next top-level key.
# Exit 1 when there is not exactly one such block. Shared by revoke and repin.
cut_one_row_block() {  # in label out -> 0 cut, 1 not exactly one block
  python3 - "$1" "$2" "$3" <<'PY'
import re
import sys

path, label, out = sys.argv[1:4]
with open(path) as f:
    lines = f.readlines()
start_re = re.compile(r'^  - label: ' + re.escape(label) + r'\s*$')
starts = [i for i, ln in enumerate(lines) if start_re.match(ln)]
if len(starts) != 1:
    raise SystemExit(1)
start = starts[0]
end = start + 1
while end < len(lines):
    ln = lines[end]
    if ln.strip() == '':
        end += 1
        continue
    if re.match(r'^  - ', ln) or re.match(r'^\S', ln):
        break
    end += 1
with open(out, 'w') as f:
    f.writelines(lines[:start] + lines[end:])
PY
}

# The two plans a revoke reads, in two processes, at two moments (#870
# review, M1). Phase 1 must not depend on parsing fleet.yaml: a small file
# the dashboard account writes can make a YAML parser run out of memory, and
# the process that dies then is the one that would have closed the link. So
# fleet-links.json is judged alone, BEFORE phase 1, by a JSON-only process;
# fleet.yaml and the Advisor's fleet.json are judged AFTER phase 1, by a
# second process under a memory and time cap, and its failure gates phase 2
# only. A file that is there and does not parse is "unreadable", never
# "absent".
REVOKE_LINKS_PLAN="$WORK/revoke-links-plan.json"
REVOKE_PLAN="$WORK/revoke-plan.json"
revoke_links_plan() {  # label -> writes $REVOKE_LINKS_PLAN, never ends the verb
  python3 - "$SNAP_FLEET_LINKS" "$1" "$REVOKE_LINKS_PLAN" <<'PY' 2>/dev/null \
    || printf '{"links_state": "unreadable", "link_rows": 0, "link_count": 0}\n' > "$REVOKE_LINKS_PLAN"
import json, sys
links_path, label, out_path = sys.argv[1:4]
plan = {"links_state": "absent", "link_rows": 0, "link_count": 0}
if links_path:
    try:
        with open(links_path) as f:
            doc = json.load(f)
        rows = doc.get("links") or [] if isinstance(doc, dict) else None
        if not isinstance(rows, list):
            raise ValueError("not an object with a links list")
        plan.update(links_state="ok", link_rows=len(rows),
                    link_count=len([r for r in rows if isinstance(r, dict) and r.get("label") == label]))
    except Exception:
        plan["links_state"] = "unreadable"
with open(out_path, "w") as f:
    json.dump(plan, f)
PY
}

# fleet.yaml and the Advisor's fleet.json, after phase 1. Capped at 512 MiB
# of address space and 20 s: a parser that dies or hangs on a hostile file
# leaves both marked unreadable, which refuses phase 2 and nothing else.
# Anchors and aliases are refused before anything is composed (no writer of
# this file emits them, and they are how a few hundred bytes become
# gigabytes), and role and transport must be strings.
revoke_registry_plan() {  # label -> writes $REVOKE_PLAN, never ends the verb
  local rc=0
  ( ulimit -v 524288 2>/dev/null || true
    exec timeout 20 python3 - "$SNAP_FLEET_YAML" "$SNAP_ADV_FLEET" "$1" "$REVOKE_PLAN" ) <<'PY' >/dev/null 2>&1 || rc=$?
import json, sys
fleet_path, adv_path, label, out_path = sys.argv[1:5]
plan = {"yaml_state": "absent", "yaml_rows": 0, "yaml_count": 0, "yaml_role": "",
        "adv_state": "absent", "adv_count": 0}
if fleet_path:
    try:
        import yaml
        with open(fleet_path) as f:
            text = f.read()
        for ev in yaml.parse(text, Loader=yaml.SafeLoader):
            if isinstance(ev, yaml.AliasEvent) or getattr(ev, "anchor", None):
                raise ValueError("fleet.yaml uses a YAML anchor or alias")
        doc = yaml.safe_load(text)
        if doc is None:
            doc = {}
        rows = doc.get("fleet") or [] if isinstance(doc, dict) else None
        if not isinstance(rows, list):
            raise ValueError("not a mapping with a fleet: list")
        mine = [r for r in rows if isinstance(r, dict) and r.get("label") == label]
        for r in mine:
            for key in ("role", "transport"):
                if key in r and r[key] is not None and not isinstance(r[key], str):
                    raise ValueError("a %s that is not a string" % key)
        plan.update(yaml_state="ok", yaml_rows=len(rows), yaml_count=len(mine))
        if mine:
            plan["yaml_role"] = mine[0].get("role") or ""
    except Exception:
        plan["yaml_state"] = "unreadable"
if adv_path:
    try:
        with open(adv_path) as f:
            doc = json.load(f)
        peers = doc if isinstance(doc, list) else (doc.get("peers") or [] if isinstance(doc, dict) else None)
        if not isinstance(peers, list):
            raise ValueError("no peer list")
        plan.update(adv_state="ok",
                    adv_count=len([p for p in peers if isinstance(p, dict) and p.get("label") == label]))
    except Exception:
        plan["adv_state"] = "unreadable"
with open(out_path, "w") as f:
    json.dump(plan, f)
PY
  if (( rc != 0 )) || [[ ! -s "$REVOKE_PLAN" ]]; then
    printf '{"yaml_state": "unreadable", "yaml_rows": 0, "yaml_count": 0, "yaml_role": "", "adv_state": "unreadable", "adv_count": 0}\n' > "$REVOKE_PLAN"
  fi
}
revoke_plan_get() {  # plan-file key -> the value on stdout
  python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$1" "$2"
}

# fleet.yaml without this label's row, at $WORK/revoke.fleet.yaml, or a
# refusal. The cut, then the #623 cross-check: the original and the candidate
# parsed with yaml.safe_load, and every row but this label's identical.
revoke_fleet_yaml_candidate() {  # label
  local label="$1"
  cut_one_row_block "$SNAP_FLEET_YAML" "$label" "$WORK/revoke.fleet.yaml" \
    || refuse row_missing "the row for \"$label\" could not be found as exactly one block in $FLEET_YAML, so nothing was revoked. Take that row out by hand, then revoke again."
  # The last row takes the bare `fleet:` key with it, exactly as the
  # dashboard's own dropFleetRow did: a key with nothing under it loads as
  # null, which the dashboard's parser refuses, and that fails the whole
  # registry closed.
  if ! python3 - "$WORK/revoke.fleet.yaml" <<'PY'
import re, sys
try:
    import yaml
except ImportError:
    raise SystemExit(1)
path = sys.argv[1]
with open(path) as f:
    text = f.read()
doc = yaml.safe_load(text)
if isinstance(doc, dict) and "fleet" in doc and doc["fleet"] is None:
    lines = text.splitlines(keepends=True)
    for i in range(len(lines) - 1, -1, -1):
        if re.match(r'^fleet:\s*$', lines[i]):
            del lines[i]
            break
    with open(path, "w") as f:
        f.writelines(lines)
PY
  then
    refuse excision_mismatch "the fleet.yaml this revoke would leave could not be read back, so nothing was written."
  fi
  if ! python3 - "$SNAP_FLEET_YAML" "$WORK/revoke.fleet.yaml" "$label" <<'PY'
import sys
try:
    import yaml
except ImportError:
    raise SystemExit(1)
orig_path, new_path, label = sys.argv[1:4]
with open(orig_path) as f:
    orig = yaml.safe_load(f.read()) or {}
with open(new_path) as f:
    new = yaml.safe_load(f.read()) or {}
if not isinstance(orig, dict) or not isinstance(new, dict):
    raise SystemExit(1)
orig_rows = orig.get("fleet")
new_rows = new.get("fleet") if "fleet" in new else []
if not isinstance(orig_rows, list) or not isinstance(new_rows, list):
    raise SystemExit(1)
# Exactly one row named this label went in, and none comes out.
if len([r for r in orig_rows if isinstance(r, dict) and r.get("label") == label]) != 1:
    raise SystemExit(1)
if [r for r in new_rows if isinstance(r, dict) and r.get("label") == label]:
    raise SystemExit(1)
orig_rest = [r for r in orig_rows if not (isinstance(r, dict) and r.get("label") == label)]
if orig_rest != new_rows:
    raise SystemExit(1)
# And nothing outside the list moved either.
o = {k: v for k, v in orig.items() if k != "fleet"}
n = {k: v for k, v in new.items() if k != "fleet"}
if o != n:
    raise SystemExit(1)
PY
  then
    refuse excision_mismatch "revoking \"$label\" would change a row other than its own in $FLEET_YAML, which means the text that was removed did not match its actual boundary. Nothing was written. Take that row out by hand first."
  fi
}

# fleet-links.json without this label's row, at $WORK/revoke.links.json.
# Returns 1 rather than ending the verb: phase 1's caller still clears root's
# record and the token files, and says the link may still be up.
revoke_links_candidate() {  # label
  python3 - "$SNAP_FLEET_LINKS" "$WORK/revoke.links.json" "$1" <<'PY' 2>/dev/null \
    || return 1
import json, sys
src, out, label = sys.argv[1:4]
with open(src) as f:
    doc = json.load(f)
rows = doc.get("links") or []
kept = [r for r in rows if not (isinstance(r, dict) and r.get("label") == label)]
if len(kept) == len(rows):
    raise SystemExit(1)
doc["links"] = kept
with open(out, "w") as f:
    json.dump(doc, f, indent=2)
    f.write("\n")
PY
}

# The Advisor's fleet.json without this label's peer, at $WORK/revoke.adv.json,
# in whatever shape the file already had (a legacy array stays an array). The
# rows that stay are the rows advisord already loaded, byte for byte as data,
# and that is checked rather than assumed: no key set is re-declared here,
# because nothing new is written into a row.
revoke_adv_candidate() {  # label
  python3 - "$SNAP_ADV_FLEET" "$WORK/revoke.adv.json" "$1" <<'PY' \
    || fail candidate_failed "the Advisor's fleet.json this revoke would leave could not be built, so nothing was written"
import json, sys
src, out, label = sys.argv[1:4]
with open(src) as f:
    doc = json.load(f)
with open(src) as f:
    orig = json.load(f)
if isinstance(doc, list):
    peers = doc
elif isinstance(doc, dict) and isinstance(doc.get("peers"), list):
    peers = doc["peers"]
else:
    raise SystemExit(1)
before = len(peers)
peers[:] = [p for p in peers if not (isinstance(p, dict) and p.get("label") == label)]
if len(peers) == before:
    raise SystemExit(1)
# Cross-check against the untouched parse: everything but this label's peer
# is the same, and so is everything outside the peer list (the self block).
if isinstance(orig, list):
    if [p for p in orig if not (isinstance(p, dict) and p.get("label") == label)] != peers:
        raise SystemExit(1)
else:
    if [p for p in orig["peers"] if not (isinstance(p, dict) and p.get("label") == label)] != peers:
        raise SystemExit(1)
    if {k: v for k, v in orig.items() if k != "peers"} != {k: v for k, v in doc.items() if k != "peers"}:
        raise SystemExit(1)
with open(out, "w") as f:
    json.dump(doc, f, indent=2)
    f.write("\n")
PY
}

# Root's own record: this label's line out of fleet-nodes.conf. Sets
# NODES_PRUNED to 1 (pruned), absent (root never held it, or no file), or 0
# (a line was there and the rewrite failed) -- the three answers #704 asked
# for. Only 0 leaves anything for an operator to do.
revoke_nodes_conf() {  # label
  local label="$1" ncline nclabel
  NODES_PRUNED=absent
  NODES_HAD_ROW=0
  if [[ -f "$NODES_CONF" ]]; then
    while IFS= read -r ncline || [[ -n "$ncline" ]]; do
      case "$ncline" in ''|'#'*) continue ;; esac
      read -r nclabel _ <<<"$ncline"
      if [[ "$nclabel" == "$label" ]]; then NODES_HAD_ROW=1; break; fi
    done < "$NODES_CONF"
  fi
  if (( NODES_HAD_ROW )); then
    NODES_PRUNED=0
    if nodes_conf_without "$label" > "$WORK/nodes.new" && nodes_conf_write "$WORK/nodes.new"; then
      NODES_PRUNED=1
    fi
  fi
}

# The node's credentials (#854): the bearer token approve wrote, and the
# Advisor token attach wrote, out of TOKEN_DIR and nowhere else. Removed
# through dirsafe's unlinkfile, which walks to TOKEN_DIR by descriptor the
# way write_token does and removes only a regular file: a symlink or anything
# else at either name is refused, left as it is, and named in tokens_failed.
# A name that is not there is nothing to remove. No TOKEN_DIR is the same.
revoke_token_files() {  # label
  local label="$1" tokname rc
  TOKENS_REMOVED=0
  TOKENS_FAILED=()
  TOKENS_DIR_REFUSED=0
  [[ -e "$TOKEN_DIR" || -L "$TOKEN_DIR" ]] || return 0
  # #854 security review (L1): a walk refused at TOKEN_DIR itself (a symlink
  # there, a too-wide mode, ETC not root's) is the directory's own problem,
  # named apart from a refusal at a leaf. Asked once, read-only, with the
  # same anchor and mask the unlinkfile calls below use.
  if ! dirsafe "$ETC" fleet-tokens "" 022 identity >/dev/null 2>&1; then
    TOKENS_DIR_REFUSED=1
    return 0
  fi
  for tokname in "$label.token" "$label.approve.token"; do
    rc=0
    dirsafe "$ETC" fleet-tokens "" 022 unlinkfile "$tokname" || rc=$?
    case "$rc" in
      0) TOKENS_REMOVED=$((TOKENS_REMOVED + 1)) ;;
      3) ;;
      *) TOKENS_FAILED+=("$tokname") ;;
    esac
  done
}

# A snapshot that may be refused without ending the verb: fleet.yaml and the
# Advisor's fleet.json, whose refusal is phase 2's to report. Sets the named
# global to the snapshot path, or "", and REVOKE_SNAP_RC to dirsafe's answer
# (0 read, 1 absent, 2 refused).
revoke_soft_snap() {  # parent-dir name out-path
  REVOKE_SNAP_RC=0
  snapshot_registry_file "$1" "$2" "$3" || REVOKE_SNAP_RC=$?
}

# Phase 2, run in a subshell by the verb below with its output captured, so
# that every refusal in it (its own, place()'s, the read-back's) ends phase 2
# and never the verb: phase 1 has already happened by then and must stand.
revoke_registry_half() {  # label
  local label="$1"
  [[ "$YAML_STATE" != "unreadable" ]] \
    || refuse registry_unreadable "$FLEET_YAML is not a plain file this program will read or parse, so its row for \"$label\" could not be taken out."
  [[ "$ADVREG_STATE" != "unreadable" ]] \
    || refuse registry_unreadable "$ADV_FLEET is not a plain file this program will read or parse, so its peer for \"$label\" could not be taken out."
  (( YAML_COUNT <= 1 )) \
    || refuse row_missing "$FLEET_YAML names \"$label\" more than once, so it is not one row this program can take out."
  # This aggregator's own row is never cut (#866 review, L1). Read from
  # fleet.yaml, so it stops THIS phase only. A tunnel row IS cut, with the
  # same cut, cross-check and read-back as a link row (#870 review, M4,
  # under the operator's one-press ruling): the account the old
  # label_not_a_link refusal guarded against owns fleet.yaml and can delete
  # the row itself, so the refusal only ever blocked the honest path, and a
  # pinned row left behind was re-vouched by the next --refresh-nodes.
  if (( YAML_COUNT >= 1 )); then
    [[ "$YAML_ROLE" != "aggregator" ]] \
      || refuse bad_role "\"$label\" is this aggregator's own row in $FLEET_YAML, and revoke never touches it."
  fi
  (( YAML_COUNT == 1 )) && revoke_fleet_yaml_candidate "$label"
  (( ADV_COUNT >= 1 )) && revoke_adv_candidate "$label"
  if (( YAML_COUNT == 1 )); then
    # The read-back, against fleet-links.json as phase 1 left it.
    VAL_LINKS="$WORK/revoke.links.json"
    if (( LINK_COUNT == 0 )); then
      VAL_LINKS="$WORK/revoke.links.unchanged.json"
      if [[ -n "$SNAP_FLEET_LINKS" ]]; then cp -a "$SNAP_FLEET_LINKS" "$VAL_LINKS"; else printf '{\n  "links": []\n}\n' > "$VAL_LINKS"; fi
    fi
    LABEL="$label"
    WANT_FLEET_ROWS="$(( YAML_ROWS - 1 ))"
    WANT_LINK_ROWS="$(( LINK_ROWS - LINK_COUNT ))"
    VALIDATE_EXPECT=absent
    validate_candidates_or_refuse "$WORK/revoke.fleet.yaml" "$VAL_LINKS"
  fi
  # Backed up first, and only the files this phase places: restore_all
  # removes a target whose backup is empty, which is right for a file this
  # connection created and wrong for one it never touched.
  BACKED=()
  (( YAML_COUNT == 1 )) && BACKED+=("$FLEET_YAML" "$(backup_of "$SNAP_FLEET_YAML")" "$DASH_USER:$DASH_GROUP:644")
  (( ADV_COUNT >= 1 )) && BACKED+=("$ADV_FLEET" "$(backup_of "$SNAP_ADV_FLEET")" "$ADV_FLEET_OWNER:$SHARED_GROUP:640")
  if (( YAML_COUNT == 1 )); then
    STEP="fleet.yaml"
    place "$WORK/revoke.fleet.yaml" "$FLEET_YAML" "$DASH_USER" "$DASH_GROUP" 644 \
      || { restore_all || true; fail rename_failed "$STEP could not be written back safely$RESTORE_NOTE"; }
  fi
  if (( ADV_COUNT >= 1 )); then
    STEP="advisor/state/fleet.json"
    place "$WORK/revoke.adv.json" "$ADV_FLEET" "$ADV_FLEET_OWNER" "$SHARED_GROUP" 640 \
      || { restore_all || true; fail rename_failed "$STEP could not be written back safely$RESTORE_NOTE"; }
  fi
  if command -v sync >/dev/null 2>&1; then sync "$CONFIG_DIR" 2>/dev/null || true; fi
  return 0
}

if [[ "$VERB" == "revoke" ]]; then
  label="${P[label]:-}"
  [[ "$label" =~ $LABEL_RE ]] || refuse bad_label "that is not a label this fleet could hold"
  LABEL_FOR_LOG="$label"

  # ── phase 1: the credential half, never rolled back ───────────────────
  # From fleet-links.json, root's record and the label, and nothing else:
  # fleet.yaml is not opened until this phase is done (#870 review, M1). A
  # fleet-links.json this program cannot read or write back does not stop
  # the rest of it: root's record and the token files are named by the label
  # alone, and they go regardless. The answer then refuses below, because
  # the link itself may still be up.
  SNAP_FLEET_LINKS="" SNAP_FLEET_YAML="" SNAP_ADV_FLEET="" LINKS_SNAP="" YAML_SNAP="" ADV_SNAP=""
  revoke_soft_snap "$CONFIG_DIR" fleet-links.json "$WORK/snap.links.json"
  LINKS_SNAP="$REVOKE_SNAP_RC"
  [[ "$LINKS_SNAP" == 0 ]] && SNAP_FLEET_LINKS="$WORK/snap.links.json"
  revoke_links_plan "$label"
  LINKS_STATE="$(revoke_plan_get "$REVOKE_LINKS_PLAN" links_state)"
  [[ "$LINKS_SNAP" == 0 || "$LINKS_SNAP" == 1 ]] || LINKS_STATE=unreadable
  LINK_ROWS="$(revoke_plan_get "$REVOKE_LINKS_PLAN" link_rows)"
  LINK_COUNT="$(revoke_plan_get "$REVOKE_LINKS_PLAN" link_count)"

  LINK_LEFT=""
  if [[ "$LINKS_STATE" == unreadable ]]; then
    LINK_LEFT="$FLEET_LINKS is not a plain file this program will read or parse"
    fact link_removed unknown
  elif (( LINK_COUNT >= 1 )); then
    if revoke_links_candidate "$label" \
       && place "$WORK/revoke.links.json" "$FLEET_LINKS" "$DASH_USER" "$DASH_GROUP" 600; then
      fact link_removed 1
    else
      LINK_LEFT="$FLEET_LINKS could not be written back safely"
      fact link_removed unknown
    fi
  else
    fact link_removed 0
  fi
  revoke_nodes_conf "$label"
  fact nodes_pruned "$NODES_PRUNED"
  revoke_token_files "$label"
  fact tokens_removed "$TOKENS_REMOVED"
  if (( TOKENS_DIR_REFUSED )); then
    fact tokens_dir_refused 1
  elif (( ${#TOKENS_FAILED[@]} )); then
    fact tokens_failed "$(IFS=,; printf '%s' "${TOKENS_FAILED[*]}")"
  fi

  # The first SIGHUP: the link closes now, whatever phase 2 does.
  reload_dashboard

  if [[ -n "$LINK_LEFT" ]]; then
    # Not `revoked`: the one fact the dashboard believes a revoke on is said
    # only once the link row is known to be gone.
    fact reloaded "$RELOADED"
    fact reload_via "${RELOAD_VIA:-none}"
    refuse registry_unreadable "$LINK_LEFT, so \"$label\"'s link may still be up. Root's record of it and its token files were cleared regardless. Fix that file by hand, then press Revoke again to finish."
  fi

  # ── only now, fleet.yaml and the Advisor's fleet.json ──────────────────
  revoke_soft_snap "$CONFIG_DIR" fleet.yaml "$WORK/snap.fleet.yaml"
  YAML_SNAP="$REVOKE_SNAP_RC"
  [[ "$YAML_SNAP" == 0 ]] && SNAP_FLEET_YAML="$WORK/snap.fleet.yaml"
  revoke_soft_snap "$ADV_STATE" fleet.json "$WORK/snap.adv.json"
  ADV_SNAP="$REVOKE_SNAP_RC"
  [[ "$ADV_SNAP" == 0 ]] && SNAP_ADV_FLEET="$WORK/snap.adv.json"
  revoke_registry_plan "$label"
  YAML_STATE="$(revoke_plan_get "$REVOKE_PLAN" yaml_state)"
  ADVREG_STATE="$(revoke_plan_get "$REVOKE_PLAN" adv_state)"
  [[ "$YAML_SNAP" == 0 || "$YAML_SNAP" == 1 ]] || YAML_STATE=unreadable
  [[ "$ADV_SNAP" == 0 || "$ADV_SNAP" == 1 ]] || ADVREG_STATE=unreadable
  YAML_ROWS="$(revoke_plan_get "$REVOKE_PLAN" yaml_rows)"
  YAML_COUNT="$(revoke_plan_get "$REVOKE_PLAN" yaml_count)"
  YAML_ROLE="$(revoke_plan_get "$REVOKE_PLAN" yaml_role)"
  ADV_COUNT="$(revoke_plan_get "$REVOKE_PLAN" adv_count)"

  # Nothing anywhere: phase 1 found no link row, no line of root's and no
  # token file, and the two registries hold nothing either. The facts a
  # dashboard needs to tell this program from one older than #859 are said
  # with it: an older broker's no_row meant "there was no link, and
  # fleet.yaml was never looked at", and this one means "nothing anywhere".
  if (( LINK_COUNT == 0 && YAML_COUNT == 0 && ADV_COUNT == 0 && TOKENS_REMOVED == 0 && TOKENS_DIR_REFUSED == 0 )) \
     && (( ${#TOKENS_FAILED[@]} == 0 )) && [[ "$NODES_PRUNED" == absent ]] \
     && [[ "$YAML_STATE" != unreadable && "$ADVREG_STATE" != unreadable ]]; then
    fact fleet_row absent
    fact advisor_peer absent
    refuse no_row "\"$label\" is not in this fleet's registry, its link registry, the Advisor's fleet map, root's record or the fleet token directory, so there was nothing to revoke"
  fi
  # Said only now, at the end of phase 1: the link row, root's record and the
  # token files have all been acted on. The dashboard believes a revoke only
  # on this fact naming its label (#859 security scan).
  fact revoked "$label"

  # ── phase 2: the registry half, all-or-nothing on its own ─────────────
  # In a subshell with its output captured: a refusal or a failure in there
  # ends phase 2 and not this verb. Its finish() is redefined to leave the
  # journal line to this shell, which writes exactly one per invocation.
  PHASE2_RC=0
  PHASE2_OUT="$WORK/revoke-phase2.out"
  if (( YAML_COUNT == 1 || ADV_COUNT >= 1 )) || [[ "$YAML_STATE" == unreadable || "$ADVREG_STATE" == unreadable ]]; then
    # NOT `( ... ) || PHASE2_RC=$?`: bash ignores errexit for the whole left
    # side of a `||`, subshell included, so an unguarded failure in there
    # would fall through to `return 0` and read as success. errexit is off
    # in THIS shell for the one line, and on again inside the subshell.
    # stderr goes to its own file: it can carry a Python traceback about a
    # dashboard-owned file, and nothing from it reaches the answer.
    set +e
    (
      set -e
      finish() { FINISHED=1; fact exit "$1"; exit "$1"; }
      trap '[[ -z "${VWORK:-}" ]] || rm -rf "$VWORK"' EXIT
      revoke_registry_half "$label"
    ) > "$PHASE2_OUT" 2> "$WORK/revoke-phase2.err"
    PHASE2_RC=$?
    set -e
  else
    : > "$PHASE2_OUT"
  fi
  if (( PHASE2_RC == 0 )); then
    if (( YAML_COUNT == 1 )); then fact fleet_row removed; else fact fleet_row absent; fi
    if (( ADV_COUNT >= 1 )); then fact advisor_peer removed; else fact advisor_peer absent; fi
  else
    fact fleet_row left
    fact advisor_peer left
    PHASE2_ERROR="$(sed -n 's/^error=//p' "$PHASE2_OUT" | tail -n 1)"
    PHASE2_SAID="$(grep -vE '^[a-z_]+=' "$PHASE2_OUT" | tail -n 1 || true)"
    fact registry_left_reason "${PHASE2_ERROR:-internal}"
    grep -qE '^restore_incomplete=' "$PHASE2_OUT" && fact restore_incomplete "$(sed -n 's/^restore_incomplete=//p' "$PHASE2_OUT" | tail -n 1)"
  fi

  # The second SIGHUP, after the registry half placed something.
  if (( PHASE2_RC == 0 )) && (( YAML_COUNT == 1 || ADV_COUNT >= 1 )); then reload_dashboard; fi
  fact reloaded "$RELOADED"
  fact reload_via "${RELOAD_VIA:-none}"
  if (( PHASE2_RC != 0 )); then
    refuse registry_left "\"$label\"'s link is closed, root's record and its token files are cleared, and it can no longer reach this fleet. Its registry row or its place in the Advisor's fleet map could not be taken out: ${PHASE2_SAID:-no reason was given}"
  fi
  out "\"$label\" is off this fleet: its link, its registry row, its place in the Advisor's fleet map, root's record and its token files are gone, and the dashboard was told to re-read."
  finish 0
fi

# ── repin (#422, #859) ───────────────────────────────────────────────────
# Accept new key. Rewrites ONE line, expected_pubkey_node, on ONE fleet.yaml
# row, and nothing else anywhere:
#
#   repin  label= was_pubkey_node= pubkey_node= end
#
# was_pubkey_node is the key the operator was shown as pinned. A row pinned
# to anything else by now refuses pin_changed, so an approval taken for one
# change cannot be spent on another.
#
# It never touches fleet-nodes.conf. A pin move only the socket asked for
# would let a compromised dashboard redirect model-push, and this header
# promises that cannot happen. So after a repin a model push to that node is
# refused at root's own pin check until the operator runs the existing root
# step, install-fleet-broker-grant.sh --refresh-nodes, which prints the old
# and the new key before it writes.
#
# It also moves that peer's expected_pubkey_node in the Advisor's fleet.json
# (#866 review, L3), in the same all-or-nothing pair as fleet.yaml, so the
# Advisor's menu never shows the old key as the declared one. No token file
# is touched.

# The Advisor's fleet.json with this peer's pin moved, at $WORK/repin.adv.json.
# Returns 1 when the file has no peer by that label (nothing to move), 2 when
# the file is in a shape this will not rewrite.
repin_adv_candidate() {  # label new
  python3 - "$SNAP_ADV_FLEET" "$WORK/repin.adv.json" "$1" "$2" <<'PY'
import copy, json, sys
src, out, label, key = sys.argv[1:5]
with open(src) as f:
    doc = json.load(f)
orig = copy.deepcopy(doc)
peers = doc if isinstance(doc, list) else (doc.get("peers") if isinstance(doc, dict) else None)
if not isinstance(peers, list):
    raise SystemExit(2)
mine = [p for p in peers if isinstance(p, dict) and p.get("label") == label]
if not mine:
    raise SystemExit(1)
if len(mine) != 1:
    raise SystemExit(2)
mine[0]["expected_pubkey_node"] = key
# Everything but that one field on that one peer is what advisord loaded.
def without(d):
    ps = d if isinstance(d, list) else d.get("peers")
    rest = [({k: v for k, v in p.items() if k != "expected_pubkey_node"}
             if isinstance(p, dict) and p.get("label") == label else p) for p in ps]
    return rest if isinstance(d, list) else dict({k: v for k, v in d.items() if k != "peers"}, peers=rest)
if without(orig) != without(doc):
    raise SystemExit(2)
with open(out, "w") as f:
    json.dump(doc, f, indent=2)
    f.write("\n")
PY
}
repin_fleet_yaml_candidate() {  # label was new
  local label="$1" was="$2" new="$3"
  cut_one_row_block "$SNAP_FLEET_YAML" "$label" "$WORK/repin.cut.yaml" \
    || refuse row_missing "the row for \"$label\" could not be found as exactly one block in $FLEET_YAML, so nothing was re-pinned. Change its pinned key by hand."
  # The block itself, rewritten in place: exactly one expected_pubkey_node
  # line inside it, at the row's own field indentation, holding the key the
  # operator was shown.
  if ! python3 - "$SNAP_FLEET_YAML" "$label" "$was" "$new" "$WORK/repin.fleet.yaml" <<'PY'
import re, sys
path, label, was, new, out = sys.argv[1:6]
with open(path) as f:
    lines = f.readlines()
start_re = re.compile(r'^  - label: ' + re.escape(label) + r'\s*$')
starts = [i for i, ln in enumerate(lines) if start_re.match(ln)]
if len(starts) != 1:
    raise SystemExit(1)
start = starts[0]
end = start + 1
while end < len(lines):
    ln = lines[end]
    if ln.strip() == '':
        end += 1
        continue
    if re.match(r'^  - ', ln) or re.match(r'^\S', ln):
        break
    end += 1
pin_re = re.compile(r'^    expected_pubkey_node:\s*' + re.escape(was) + r'\s*$')
hits = [i for i in range(start + 1, end) if pin_re.match(lines[i])]
if len(hits) != 1:
    raise SystemExit(1)
lines[hits[0]] = '    expected_pubkey_node: ' + new + '\n'
with open(out, 'w') as f:
    f.writelines(lines)
PY
  then
    refuse row_missing "the row for \"$label\" does not carry exactly one expected_pubkey_node line holding the key you were shown, so nothing was re-pinned. Change its pinned key by hand."
  fi
  # The #623 cross-check, for a rewrite rather than a cut: every other row
  # identical, and this row identical but for its pin, which is the new key.
  if ! python3 - "$SNAP_FLEET_YAML" "$WORK/repin.fleet.yaml" "$label" "$new" <<'PY'
import sys
try:
    import yaml
except ImportError:
    raise SystemExit(1)
orig_path, new_path, label, key = sys.argv[1:5]
with open(orig_path) as f:
    orig = yaml.safe_load(f.read()) or {}
with open(new_path) as f:
    cand = yaml.safe_load(f.read()) or {}
if not isinstance(orig, dict) or not isinstance(cand, dict):
    raise SystemExit(1)
o_rows, n_rows = orig.get("fleet"), cand.get("fleet")
if not isinstance(o_rows, list) or not isinstance(n_rows, list) or len(o_rows) != len(n_rows):
    raise SystemExit(1)
if {k: v for k, v in orig.items() if k != "fleet"} != {k: v for k, v in cand.items() if k != "fleet"}:
    raise SystemExit(1)
for a, b in zip(o_rows, n_rows):
    if isinstance(a, dict) and a.get("label") == label:
        if not isinstance(b, dict) or b.get("expected_pubkey_node") != key:
            raise SystemExit(1)
        if {k: v for k, v in a.items() if k != "expected_pubkey_node"} != {k: v for k, v in b.items() if k != "expected_pubkey_node"}:
            raise SystemExit(1)
    elif a != b:
        raise SystemExit(1)
PY
  then
    refuse excision_mismatch "re-pinning \"$label\" would change more than its own pinned key in $FLEET_YAML, so nothing was written. Change its pinned key by hand."
  fi
}

if [[ "$VERB" == "repin" ]]; then
  LABEL="${P[label]:-}"
  WAS_KEY="${P[was_pubkey_node]:-}"
  NEW_KEY="${P[pubkey_node]:-}"
  LABEL_FOR_LOG="$LABEL"
  [[ "$LABEL" =~ $LABEL_RE ]] || refuse bad_label "that is not a label this fleet could hold"
  [[ "$WAS_KEY" =~ $NODE_KEY_RE ]] || refuse bad_pubkey "the key this row was pinned to is not a node key shape"
  [[ "$NEW_KEY" =~ $NODE_KEY_RE ]] || refuse bad_pubkey "that is not a node key shape the fleet can pin"
  [[ "$WAS_KEY" != "$NEW_KEY" ]] || refuse same_key "that is the key \"$LABEL\" is already pinned to, so there is nothing to accept"

  snap_fleet_yaml
  snap_fleet_links
  snap_adv_fleet
  [[ -n "$SNAP_FLEET_YAML" ]] || refuse label_not_found "there is no $FLEET_YAML, so there is no row to re-pin"
  if ! python3 - "$SNAP_FLEET_YAML" "$SNAP_FLEET_LINKS" "$LABEL" "$WAS_KEY" "$NEW_KEY" "$WORK/repin-plan.txt" <<'PY' 2>"$WORK/repin-plan.err"
import json, sys
try:
    import yaml
except ImportError:
    sys.stderr.write("python3 has no yaml module, and fleet.yaml is yaml\n")
    raise SystemExit(3)
fleet_path, links_path, label, was, new, out = sys.argv[1:7]
with open(fleet_path) as f:
    doc = yaml.safe_load(f.read()) or {}
rows = doc.get("fleet") if isinstance(doc, dict) else None
if not isinstance(rows, list):
    sys.stderr.write("fleet.yaml is not a mapping with a fleet: list\n")
    raise SystemExit(3)
mine = [r for r in rows if isinstance(r, dict) and r.get("label") == label]
link_rows = 0
if links_path:
    with open(links_path) as f:
        ld = json.load(f)
    link_rows = len((ld.get("links") or []) if isinstance(ld, dict) else [])
# One word for the verdict, then the counts the validation wants.
if len(mine) != 1:
    verdict = "label_not_found"
elif str(mine[0].get("role") or "") == "aggregator":
    verdict = "bad_role"
elif not mine[0].get("expected_pubkey_node"):
    verdict = "not_pinned"
elif mine[0].get("expected_pubkey_node") != was:
    verdict = "pin_changed"
elif any(isinstance(r, dict) and r.get("label") != label and r.get("expected_pubkey_node") == new for r in rows):
    verdict = "pin_taken"
else:
    verdict = "ok"
with open(out, "w") as f:
    f.write("%s %d %d\n" % (verdict, len(rows), link_rows))
PY
  then
    refuse unreadable_registry "one of this host's registries could not be read, so nothing was re-pinned: $(tr -d '\n' < "$WORK/repin-plan.err")"
  fi
  read -r REPIN_VERDICT WANT_FLEET_ROWS WANT_LINK_ROWS < "$WORK/repin-plan.txt"
  case "$REPIN_VERDICT" in
    ok) : ;;
    label_not_found) refuse label_not_found "$FLEET_YAML has no single row called \"$LABEL\", so there is nothing to re-pin." ;;
    bad_role) refuse bad_role "\"$LABEL\" is this aggregator's own row; repin never touches it." ;;
    not_pinned) refuse not_pinned "\"$LABEL\" pins no node key, so there is nothing to re-pin." ;;
    pin_changed) refuse pin_changed "\"$LABEL\" is no longer pinned to the key you were shown, so this approval does not apply to it. Read the row again." ;;
    pin_taken) refuse pin_taken "another row already pins that node key. Two labels on one node key is a copied install, so nothing was re-pinned." ;;
    *) refuse unreadable_registry "the row for \"$LABEL\" could not be judged, so nothing was re-pinned." ;;
  esac

  repin_fleet_yaml_candidate "$LABEL" "$WAS_KEY" "$NEW_KEY"
  VAL_LINKS="$WORK/repin.links.json"
  if [[ -n "$SNAP_FLEET_LINKS" ]]; then cp -a "$SNAP_FLEET_LINKS" "$VAL_LINKS"; else printf '{\n  "links": []\n}\n' > "$VAL_LINKS"; fi
  VALIDATE_EXPECT=fleet_only
  validate_candidates_or_refuse "$WORK/repin.fleet.yaml" "$VAL_LINKS"
  VALIDATE_EXPECT=""

  REPIN_ADV=0
  if [[ -n "$SNAP_ADV_FLEET" ]]; then
    RA_RC=0; repin_adv_candidate "$LABEL" "$NEW_KEY" || RA_RC=$?
    case "$RA_RC" in
      0) REPIN_ADV=1 ;;
      1) : ;;
      *) refuse candidate_refused "the Advisor's fleet.json names \"$LABEL\" in a shape this program will not rewrite, so nothing was re-pinned. Fix it by hand first." ;;
    esac
  fi

  BACKED=()
  BACKED+=("$FLEET_YAML" "$(backup_of "$SNAP_FLEET_YAML")" "$DASH_USER:$DASH_GROUP:644")
  (( REPIN_ADV )) && BACKED+=("$ADV_FLEET" "$(backup_of "$SNAP_ADV_FLEET")" "$ADV_FLEET_OWNER:$SHARED_GROUP:640")
  STEP="fleet.yaml"
  place "$WORK/repin.fleet.yaml" "$FLEET_YAML" "$DASH_USER" "$DASH_GROUP" 644 \
    || { restore_all || true; fail rename_failed "$STEP could not be written$RESTORE_NOTE"; }
  if (( REPIN_ADV )); then
    STEP="advisor/state/fleet.json"
    place "$WORK/repin.adv.json" "$ADV_FLEET" "$ADV_FLEET_OWNER" "$SHARED_GROUP" 640 \
      || { restore_all || true; fail rename_failed "$STEP could not be written$RESTORE_NOTE"; }
  fi
  if command -v sync >/dev/null 2>&1; then sync "$CONFIG_DIR" 2>/dev/null || true; fi

  reload_dashboard
  fact repinned "$LABEL"
  fact advisor_peer_repinned "$REPIN_ADV"
  fact reloaded "$RELOADED"
  fact reload_via "${RELOAD_VIA:-none}"
  out "\"$LABEL\" is pinned to its new key. Root's record of where a model key may be sent still names the old one: run curl -fsSL https://get.aperire.one | bash -s -- --dir $INSTALL_DIR --run fleet-broker-grant --refresh-nodes, and compare the new key it prints with pubkey_node in that node's own server_info before you confirm."
  finish 0
fi

# ══ #641: attach, detach and refresh an Advisor on an already-paired node ═
#
# Three verbs, and the ONLY writers of a link row's advisor state from here
# on: REJOIN carries the existing state forward (above) rather than acting
# on it, and approve/convert only ever set it on a row this label has never
# had before. All three act on a row fleet.yaml and fleet-links.json
# ALREADY hold; none of the three may create a fleet member, repoint a pin,
# or widen what a row already grants beyond the one field named in its own
# name.
#
#   attach-advisor         label= pubkey_node= advisor_token= end
#   detach-advisor         label= end
#   refresh-advisor-token  label= advisor_token= end

if [[ "$VERB" == "attach-advisor" ]]; then
  LABEL="${P[label]:-}"
  PUBKEY="${P[pubkey_node]:-}"
  ADVISOR_TOKEN="${P[advisor_token]:-}"
  LABEL_FOR_LOG="$LABEL"

  [[ "$LABEL" =~ $LABEL_RE ]] || refuse bad_label "that is not a label this fleet could hold"
  [[ "$PUBKEY" =~ $NODE_KEY_RE ]] || refuse bad_pubkey "that is not a node key shape the fleet can pin"
  [[ -n "$ADVISOR_TOKEN" ]] || refuse no_token "no Advisor token was given, so there is nothing to attach"
  (( ${#ADVISOR_TOKEN} <= FLEET_PAIR_MAX_TOKEN_CHARS )) \
    || refuse bad_token "that Advisor token is longer than any bearer token this fleet writes"

  read_row_plan_or_refuse "$LABEL"
  HAVE_ROW="$(python3 -c 'import json,sys;print("1" if json.load(open(sys.argv[1]))["found"] else "0")' "$ROW_PLAN")"
  [[ "$HAVE_ROW" == "1" ]] \
    || refuse label_not_found "$FLEET_YAML has no row called \"$LABEL\", so there is nothing to attach an Advisor to. Pair that node first."

  ROW_PIN="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["row"].get("pin") or "")' "$ROW_PLAN")"
  ROW_TRANSPORT="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["row"].get("transport") or "")' "$ROW_PLAN")"
  ROW_ROLE="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["row"].get("role") or "")' "$ROW_PLAN")"
  ROW_DASH_URL="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["row"].get("dashboard_url") or "")' "$ROW_PLAN")"
  ROW_READ_ORIGIN="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["row"].get("read_origin") or "")' "$ROW_PLAN")"
  ROW_TOKEN_PATH="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["row"].get("token_path") or "")' "$ROW_PLAN")"
  ROW_ADVISOR_ORIGIN="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["row"].get("advisor_origin") or "")' "$ROW_PLAN")"
  ROW_EXTRA_KEYS="$(python3 -c 'import json,sys;print(",".join(json.load(open(sys.argv[1]))["extra_keys"]))' "$ROW_PLAN")"
  LINK_HAS_LABEL="$(python3 -c 'import json,sys;print("1" if json.load(open(sys.argv[1]))["link_has_label"] else "0")' "$ROW_PLAN")"
  LINK_ADVISOR_PORT="$(python3 -c 'import json,sys;v=json.load(open(sys.argv[1]))["link_advisor_port"];print(v if v is not None else "")' "$ROW_PLAN")"
  WANT_FLEET_ROWS="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["fleet_rows"])' "$ROW_PLAN")"
  WANT_LINK_ROWS="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["link_rows"])' "$ROW_PLAN")"

  [[ -z "$ROW_EXTRA_KEYS" ]] \
    || refuse row_shape "$FLEET_YAML's row for \"$LABEL\" carries a field this program does not know ($ROW_EXTRA_KEYS), so it will not rewrite that row by hand. Fix it by hand first."
  [[ "$ROW_TRANSPORT" == "link" ]] \
    || refuse label_not_a_link "$FLEET_YAML's row for \"$LABEL\" does not say transport: link, so an Advisor cannot be attached to it this way. If that row is over a tunnel and this fleet already watches it, approve it on the Pending row first (#620's convert), then attach."
  [[ "$ROW_ROLE" != "aggregator" ]] \
    || refuse bad_role "\"$LABEL\" is this aggregator's own row; attach-advisor never touches it."
  [[ "$ROW_PIN" == "$PUBKEY" ]] \
    || refuse root_pin_disagrees "$FLEET_YAML pins \"$LABEL\" to a different node key than the one presented here, so attaching is refused."
  [[ -z "$ROW_ADVISOR_ORIGIN" ]] \
    || refuse already_attached "\"$LABEL\" already carries an Advisor. Use refresh-advisor-token to replace its token instead."
  [[ "$LINK_HAS_LABEL" == "1" ]] \
    || refuse no_links_row "$FLEET_LINKS has no row for \"$LABEL\" (it may have been revoked), so nothing was attached."
  # A drift the row check above cannot see: fleet.yaml said no Advisor, but
  # fleet-links.json already names a port for one. Named rather than left
  # to fail candidate_failed further down, which would read as a crash.
  [[ -z "$LINK_ADVISOR_PORT" ]] \
    || refuse links_row_already_attached "$FLEET_LINKS already names an advisor_port for \"$LABEL\" although $FLEET_YAML does not. The two registries disagree; fix that by hand before attaching."

  # Root's own record anchors the pin, the same reasoning #620's convert
  # already uses: no line here at all is refused rather than trusted from
  # fleet.yaml alone, since fleet.yaml is the dashboard account's own file.
  [[ -f "$NODES_CONF" ]] \
    || refuse no_root_record "root's own record has no line for \"$LABEL\" at all, so attaching an Advisor is refused. Run: curl -fsSL https://get.aperire.one | bash -s -- --dir $INSTALL_DIR --run fleet-broker-grant --refresh-nodes, then attach again."
  NODES_LINE=""
  while IFS= read -r ncline || [[ -n "$ncline" ]]; do
    case "$ncline" in ''|'#'*) continue ;; esac
    read -r nclabel _ <<<"$ncline"
    if [[ "$nclabel" == "$LABEL" ]]; then NODES_LINE="$ncline"; break; fi
  done < "$NODES_CONF"
  [[ -n "$NODES_LINE" ]] \
    || refuse no_root_record "root's own record has no line for \"$LABEL\", so attaching an Advisor is refused. Run: curl -fsSL https://get.aperire.one | bash -s -- --dir $INSTALL_DIR --run fleet-broker-grant --refresh-nodes, then attach again."
  read -r NL_LABEL NL_PIN NL_PORT _ NL_REST <<<"$NODES_LINE"
  [[ "$NL_PIN" == "$PUBKEY" ]] \
    || refuse root_pin_disagrees "root's own record already pins \"$LABEL\" to a different node key than the one presented here, so attaching is refused."

  ADVISOR_TOKEN_PATH="$TOKEN_DIR/$LABEL.approve.token"

  # ── the port, from the same pool approve uses ──────────────────────────
  LISTENING=""
  if command -v ss >/dev/null 2>&1; then
    LISTENING="$(ss -ltnH 2>/dev/null | awk '{print $4}' | sed 's/.*://' | tr '\n' ' ' || true)"
  fi
  PLAN="$ROW_PLAN"
  ADVISOR_PORT=""
  for (( p = FLEET_LINK_PORT_MIN; p <= FLEET_LINK_PORT_MAX; p++ )); do
    port_free "$p" || continue
    ADVISOR_PORT="$p"
    break
  done
  [[ -n "$ADVISOR_PORT" ]] \
    || refuse no_port "every port in $FLEET_LINK_PORT_MIN-$FLEET_LINK_PORT_MAX is taken or listening, so there is nowhere to land this Advisor"

  # ── the fleet.yaml candidate: excise, re-emit, cross-check (#620, #623) ─
  # TOKEN_DIR itself is created below, by ensure_token_dir, never here: a
  # bare `mkdir -p` takes this PROCESS's own umask, which on plenty of
  # hosts leaves group- or other-write bits ensure_token_dir would then
  # have to find already wrong and refuse rather than silently tighten
  # (round 3 review's own "never silently tightened" rule, applied to the
  # directory this program creates and not only to the file it writes
  # into it).
  # $SNAP_FLEET_YAML is read_row_plan_or_refuse's own snapshot, already
  # guaranteed non-empty here (HAVE_ROW was checked "1" above, so
  # fleet.yaml had content when it was taken): never the live path again.
  cp -a "$SNAP_FLEET_YAML" "$WORK/fleet.yaml"
  if ! python3 - "$WORK/fleet.yaml" "$LABEL" "$WORK/fleet.yaml.excised" <<'PY'
import re
import sys

path, label, out = sys.argv[1:4]
with open(path) as f:
    lines = f.readlines()
start_re = re.compile(r'^  - label: ' + re.escape(label) + r'\s*$')
starts = [i for i, ln in enumerate(lines) if start_re.match(ln)]
if len(starts) != 1:
    raise SystemExit(1)
start = starts[0]
end = start + 1
while end < len(lines):
    ln = lines[end]
    if ln.strip() == '':
        end += 1
        continue
    if re.match(r'^  - ', ln) or re.match(r'^\S', ln):
        break
    end += 1
with open(out, 'w') as f:
    f.writelines(lines[:start] + lines[end:])
PY
  then
    refuse row_missing "the row for \"$LABEL\" could not be found as exactly one block in $FLEET_YAML, so nothing was attached. Fix that row by hand first."
  fi
  mv -f "$WORK/fleet.yaml.excised" "$WORK/fleet.yaml"

  case "$ROW_ROLE" in
    node|validator|relay) ROW_EMIT_ROLE="$ROW_ROLE" ;;
    *) ROW_EMIT_ROLE="node" ;;
  esac
  if [[ -s "$WORK/fleet.yaml" ]]; then
    [[ "$(tail -c1 "$WORK/fleet.yaml")" == "" ]] || printf '\n' >> "$WORK/fleet.yaml"
  else
    printf 'fleet:\n' > "$WORK/fleet.yaml"
  fi
  ROW_LABEL="$LABEL"
  ROW_PIN="$PUBKEY"
  ROW_EMIT_ADVISOR=1
  ROW_ADVISOR_ORIGIN="http://127.0.0.1:$ADVISOR_PORT"
  ROW_ADVISOR_TOKEN_PATH="$ADVISOR_TOKEN_PATH"
  emit_attached_row >> "$WORK/fleet.yaml"

  # The #623 guard: parse the ORIGINAL file and this candidate, drop the
  # target label's own row from each, and the two lists of everything else
  # must be identical. Anything else means the excision found the wrong
  # boundary (a column-zero comment inside the row, the usual cause).
  if ! python3 - "$SNAP_FLEET_YAML" "$WORK/fleet.yaml" "$LABEL" <<'PY'
import sys
try:
    import yaml
except ImportError:
    raise SystemExit(1)
orig_path, new_path, label = sys.argv[1:4]
with open(orig_path) as f:
    orig = yaml.safe_load(f.read()) or {}
with open(new_path) as f:
    new = yaml.safe_load(f.read()) or {}
orig_rows = orig.get("fleet") if isinstance(orig, dict) else None
new_rows = new.get("fleet") if isinstance(new, dict) else None
if not isinstance(orig_rows, list) or not isinstance(new_rows, list):
    raise SystemExit(1)
orig_rest = [r for r in orig_rows if not (isinstance(r, dict) and r.get("label") == label)]
new_rest = [r for r in new_rows if not (isinstance(r, dict) and r.get("label") == label)]
if orig_rest != new_rest:
    raise SystemExit(1)
# And the target row itself: attach may only ADD advisor_origin and
# advisor_token_path. Every other field (read_origin, token_path,
# dashboard_url, a role a quoting slip could have mangled on the way back
# out) must come back exactly what it went in as.
orig_target = next((r for r in orig_rows if isinstance(r, dict) and r.get("label") == label), None)
new_target = next((r for r in new_rows if isinstance(r, dict) and r.get("label") == label), None)
if orig_target is None or new_target is None:
    raise SystemExit(1)
def sans_advisor(r):
    d = {k: v for k, v in r.items() if k not in ("advisor_origin", "advisor_token_path")}
    d.setdefault("role", "node")
    return d
if sans_advisor(orig_target) != sans_advisor(new_target):
    raise SystemExit(1)
PY
  then
    refuse excision_mismatch "attaching an Advisor to \"$LABEL\" would change a row other than its own in $FLEET_YAML, which means the text that was removed did not match its actual boundary. Nothing was written. Fix that row by hand first."
  fi

  # ── the fleet-links.json candidate: mutate advisor_port, nothing else ──
  if [[ -n "$SNAP_FLEET_LINKS" ]]; then cp -a "$SNAP_FLEET_LINKS" "$WORK/links.json"; else printf '{\n  "links": []\n}\n' > "$WORK/links.json"; fi
  if ! python3 - "$WORK/links.json" "$WORK/links.new.json" "$LABEL" "$ADVISOR_PORT" <<'PY'
import json, sys
src, out, label, port = sys.argv[1:5]
with open(src) as f:
    doc = json.load(f)
if not isinstance(doc, dict) or not isinstance(doc.get("links"), list):
    raise SystemExit(1)
matches = [r for r in doc["links"] if isinstance(r, dict) and r.get("label") == label]
if len(matches) != 1:
    raise SystemExit(1)
row = matches[0]
if "advisor_port" in row:
    raise SystemExit(1)
row["advisor_port"] = int(port)
with open(out, "w") as f:
    json.dump(doc, f, indent=2)
    f.write("\n")
PY
  then
    fail candidate_failed "the fleet-links.json candidate could not be built"
  fi
  if ! python3 - "$SNAP_FLEET_LINKS" "$WORK/links.new.json" "$LABEL" <<'PY'
import json, sys
orig_path, new_path, label = sys.argv[1:4]
with open(orig_path) as f:
    orig = json.load(f)
with open(new_path) as f:
    new = json.load(f)
orig_rows = orig.get("links") if isinstance(orig, dict) else None
new_rows = new.get("links") if isinstance(new, dict) else None
if not isinstance(orig_rows, list) or not isinstance(new_rows, list):
    raise SystemExit(1)
orig_rest = [r for r in orig_rows if not (isinstance(r, dict) and r.get("label") == label)]
new_rest = [r for r in new_rows if not (isinstance(r, dict) and r.get("label") == label)]
if orig_rest != new_rest:
    raise SystemExit(1)
orig_target = next((r for r in orig_rows if isinstance(r, dict) and r.get("label") == label), None)
new_target = next((r for r in new_rows if isinstance(r, dict) and r.get("label") == label), None)
if orig_target is None or new_target is None:
    raise SystemExit(1)
o = {k: v for k, v in orig_target.items() if k != "advisor_port"}
n = {k: v for k, v in new_target.items() if k != "advisor_port"}
if o != n:
    raise SystemExit(1)
PY
  then
    refuse excision_mismatch "attaching an Advisor to \"$LABEL\" would change a row other than its own in $FLEET_LINKS, so nothing was written."
  fi

  validate_candidates_or_refuse "$WORK/fleet.yaml" "$WORK/links.new.json"

  # ── all three, or none ─────────────────────────────────────────────────
  BACKED=()
  BACKED+=("$FLEET_YAML" "$(backup_of "$SNAP_FLEET_YAML")" "$DASH_USER:$DASH_GROUP:644")
  BACKED+=("$FLEET_LINKS" "$(backup_of "$SNAP_FLEET_LINKS")" "$DASH_USER:$DASH_GROUP:600")
  BACKED+=("$NODES_CONF" "$(backup_of "$NODES_CONF")" "self")
  BACKED+=("$ADVISOR_TOKEN_PATH" "$(backup_of "$ADVISOR_TOKEN_PATH")" "self")

  STEP="fleet.yaml"
  place "$WORK/fleet.yaml" "$FLEET_YAML" "$DASH_USER" "$DASH_GROUP" 644 \
    || { restore_all || true; fail rename_failed "$STEP could not be written$RESTORE_NOTE"; }
  STEP="fleet-links.json"
  place "$WORK/links.new.json" "$FLEET_LINKS" "$DASH_USER" "$DASH_GROUP" 600 \
    || { restore_all || true; fail rename_failed "$STEP could not be written$RESTORE_NOTE"; }
  if command -v sync >/dev/null 2>&1; then sync "$CONFIG_DIR" 2>/dev/null || true; fi

  # ensure_token_dir does the symlink check and the create/chown/chmod on
  # ONE file descriptor, opened O_NOFOLLOW: a plain `[[ -L ]]` check
  # followed by a separate `install -d` left a race window (TOKEN_DIR's
  # own parent is owned by an unprivileged account; see the function's own
  # comment) where that account could swap a symlink in between the two
  # lines, and `install -d` follows a symlinked directory argument,
  # chowning and chmoding whatever it points at as root (verified). Doing
  # both on the same fd closes that window rather than narrowing it.
  ETD_RC=0; ensure_token_dir "$TOKEN_DIR" || ETD_RC=$?
  if (( ETD_RC == 2 )); then
    restore_all || true
    fail token_is_symlink "$TOKEN_DIR already exists as a symlink, and this program will not create, own or mode a directory through one. Nothing here follows it. Remove it by hand and try again.$RESTORE_NOTE."
  elif (( ETD_RC != 0 )); then
    restore_all || true
    fail token_failed "$TOKEN_DIR could not be created$RESTORE_NOTE"
  fi
  TOKEN_MODE_RC=0; WIDE="$(check_token_mode "$ADVISOR_TOKEN_PATH")" || TOKEN_MODE_RC=$?
  if (( TOKEN_MODE_RC == 2 )); then
    restore_all || true
    refuse token_is_symlink "$ADVISOR_TOKEN_PATH already exists as a symlink, and a bearer token is never written through one. Nothing here follows it. Remove it by hand and try again.$RESTORE_NOTE."
  elif (( TOKEN_MODE_RC == 1 )); then
    restore_all || true
    refuse token_too_wide "$ADVISOR_TOKEN_PATH already exists with mode $WIDE, wider than 0640. A bearer token at that mode is refused, never silently tightened.$RESTORE_NOTE."
  fi
  write_token "$ADVISOR_TOKEN_PATH" "$ADVISOR_TOKEN" \
    || { restore_all || true; fail token_failed "$ADVISOR_TOKEN_PATH could not be written$RESTORE_NOTE"; }

  # Root's own record: the SAME line, only field 4 flipped, the #458 fifth
  # field (a custom read-token path) carried forward untouched if it was
  # there.
  {
    nodes_conf_without "$LABEL"
    if [[ -n "$NL_REST" ]]; then
      printf '%s %s %s 1 %s\n' "$LABEL" "$PUBKEY" "$NL_PORT" "$NL_REST"
    else
      printf '%s %s %s 1\n' "$LABEL" "$PUBKEY" "$NL_PORT"
    fi
  } > "$WORK/nodes.new"
  nodes_conf_write "$WORK/nodes.new" \
    || { restore_all || true; fail nodes_conf_failed "$NODES_CONF could not be written$RESTORE_NOTE"; }

  reload_dashboard
  fact attached "$LABEL"
  fact advisor_port "$ADVISOR_PORT"
  fact advisor_token_path "$ADVISOR_TOKEN_PATH"
  fact reloaded "$RELOADED"
  fact reload_via "${RELOAD_VIA:-none}"
  out "\"$LABEL\" now has an Advisor attached, reading on 127.0.0.1:$ADVISOR_PORT."
  if [[ "$RELOADED" != "1" ]]; then
    out "the dashboard could not be reloaded here, so the Advisor tab will pick this up on its next restart."
  fi
  finish 0
fi

if [[ "$VERB" == "detach-advisor" ]]; then
  LABEL="${P[label]:-}"
  LABEL_FOR_LOG="$LABEL"
  [[ "$LABEL" =~ $LABEL_RE ]] || refuse bad_label "that is not a label this fleet could hold"

  read_row_plan_or_refuse "$LABEL"
  HAVE_ROW="$(python3 -c 'import json,sys;print("1" if json.load(open(sys.argv[1]))["found"] else "0")' "$ROW_PLAN")"
  [[ "$HAVE_ROW" == "1" ]] \
    || refuse label_not_found "$FLEET_YAML has no row called \"$LABEL\", so there is nothing to detach an Advisor from."

  ROW_PIN="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["row"].get("pin") or "")' "$ROW_PLAN")"
  ROW_TRANSPORT="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["row"].get("transport") or "")' "$ROW_PLAN")"
  ROW_ROLE="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["row"].get("role") or "")' "$ROW_PLAN")"
  ROW_DASH_URL="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["row"].get("dashboard_url") or "")' "$ROW_PLAN")"
  ROW_READ_ORIGIN="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["row"].get("read_origin") or "")' "$ROW_PLAN")"
  ROW_TOKEN_PATH="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["row"].get("token_path") or "")' "$ROW_PLAN")"
  ROW_ADVISOR_ORIGIN="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["row"].get("advisor_origin") or "")' "$ROW_PLAN")"
  ROW_EXTRA_KEYS="$(python3 -c 'import json,sys;print(",".join(json.load(open(sys.argv[1]))["extra_keys"]))' "$ROW_PLAN")"
  LINK_HAS_LABEL="$(python3 -c 'import json,sys;print("1" if json.load(open(sys.argv[1]))["link_has_label"] else "0")' "$ROW_PLAN")"
  WANT_FLEET_ROWS="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["fleet_rows"])' "$ROW_PLAN")"
  WANT_LINK_ROWS="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["link_rows"])' "$ROW_PLAN")"

  [[ -z "$ROW_EXTRA_KEYS" ]] \
    || refuse row_shape "$FLEET_YAML's row for \"$LABEL\" carries a field this program does not know ($ROW_EXTRA_KEYS), so it will not rewrite that row by hand. Fix it by hand first."
  [[ "$ROW_TRANSPORT" == "link" ]] \
    || refuse label_not_a_link "$FLEET_YAML's row for \"$LABEL\" does not say transport: link."
  [[ "$ROW_ROLE" != "aggregator" ]] \
    || refuse bad_role "\"$LABEL\" is this aggregator's own row; detach-advisor never touches it."
  [[ -n "$ROW_ADVISOR_ORIGIN" ]] \
    || refuse not_attached "\"$LABEL\" carries no Advisor, so there is nothing to detach."
  # A revoke leaves exactly this shape: fleet.yaml's row still carries an
  # Advisor, but fleet-links.json's own row for the label is already gone.
  # Falling through from here builds a fleet-links.json candidate that can
  # never find its one required row, which is a bug this program should
  # name rather than let surface as candidate_failed (an unnamed exit 1
  # that reads like a crash, not a refusal an operator can act on).
  [[ "$LINK_HAS_LABEL" == "1" ]] \
    || refuse no_links_row "$FLEET_LINKS has no row for \"$LABEL\" (it may have been revoked), so there is nothing there to detach. $FLEET_YAML's own row still names an Advisor; fix it by hand, or re-pair \"$LABEL\" first."

  ADVISOR_TOKEN_PATH="$TOKEN_DIR/$LABEL.approve.token"

  # detach-advisor writes no token file and creates no directory: this row
  # names ADVISOR_TOKEN_PATH only so restore_all has something to back up
  # and put back if a LATER step in this same transaction fails. It is
  # always this program's own convention path, never whatever the row's
  # OWN advisor_token_path field happens to say (a hand-registered custom
  # path, or a leftover legacy value now that there is no migration to move
  # it: #648, round 4): detach removes only the one file it derives itself,
  # inside TOKEN_DIR, and a row naming a path elsewhere is left untouched by
  # this call, the same as any write here would be.
  #
  # $SNAP_FLEET_YAML is read_row_plan_or_refuse's own snapshot, already
  # guaranteed non-empty (HAVE_ROW was checked "1" above): never the live
  # path again.
  cp -a "$SNAP_FLEET_YAML" "$WORK/fleet.yaml"
  if ! python3 - "$WORK/fleet.yaml" "$LABEL" "$WORK/fleet.yaml.excised" <<'PY'
import re
import sys

path, label, out = sys.argv[1:4]
with open(path) as f:
    lines = f.readlines()
start_re = re.compile(r'^  - label: ' + re.escape(label) + r'\s*$')
starts = [i for i, ln in enumerate(lines) if start_re.match(ln)]
if len(starts) != 1:
    raise SystemExit(1)
start = starts[0]
end = start + 1
while end < len(lines):
    ln = lines[end]
    if ln.strip() == '':
        end += 1
        continue
    if re.match(r'^  - ', ln) or re.match(r'^\S', ln):
        break
    end += 1
with open(out, 'w') as f:
    f.writelines(lines[:start] + lines[end:])
PY
  then
    refuse row_missing "the row for \"$LABEL\" could not be found as exactly one block in $FLEET_YAML, so nothing was detached. Fix that row by hand first."
  fi
  mv -f "$WORK/fleet.yaml.excised" "$WORK/fleet.yaml"

  case "$ROW_ROLE" in
    node|validator|relay) ROW_EMIT_ROLE="$ROW_ROLE" ;;
    *) ROW_EMIT_ROLE="node" ;;
  esac
  if [[ -s "$WORK/fleet.yaml" ]]; then
    [[ "$(tail -c1 "$WORK/fleet.yaml")" == "" ]] || printf '\n' >> "$WORK/fleet.yaml"
  else
    printf 'fleet:\n' > "$WORK/fleet.yaml"
  fi
  ROW_LABEL="$LABEL"
  ROW_EMIT_ADVISOR=0
  emit_attached_row >> "$WORK/fleet.yaml"

  if ! python3 - "$SNAP_FLEET_YAML" "$WORK/fleet.yaml" "$LABEL" <<'PY'
import sys
try:
    import yaml
except ImportError:
    raise SystemExit(1)
orig_path, new_path, label = sys.argv[1:4]
with open(orig_path) as f:
    orig = yaml.safe_load(f.read()) or {}
with open(new_path) as f:
    new = yaml.safe_load(f.read()) or {}
orig_rows = orig.get("fleet") if isinstance(orig, dict) else None
new_rows = new.get("fleet") if isinstance(new, dict) else None
if not isinstance(orig_rows, list) or not isinstance(new_rows, list):
    raise SystemExit(1)
orig_rest = [r for r in orig_rows if not (isinstance(r, dict) and r.get("label") == label)]
new_rest = [r for r in new_rows if not (isinstance(r, dict) and r.get("label") == label)]
if orig_rest != new_rest:
    raise SystemExit(1)
# And the target row itself: detach may only REMOVE advisor_origin and
# advisor_token_path. Every other field must come back exactly what it
# went in as.
orig_target = next((r for r in orig_rows if isinstance(r, dict) and r.get("label") == label), None)
new_target = next((r for r in new_rows if isinstance(r, dict) and r.get("label") == label), None)
if orig_target is None or new_target is None:
    raise SystemExit(1)
def sans_advisor(r):
    d = {k: v for k, v in r.items() if k not in ("advisor_origin", "advisor_token_path")}
    d.setdefault("role", "node")
    return d
if sans_advisor(orig_target) != sans_advisor(new_target):
    raise SystemExit(1)
PY
  then
    refuse excision_mismatch "detaching the Advisor from \"$LABEL\" would change a row other than its own in $FLEET_YAML, which means the text that was removed did not match its actual boundary. Nothing was written. Fix that row by hand first."
  fi

  if [[ -n "$SNAP_FLEET_LINKS" ]]; then cp -a "$SNAP_FLEET_LINKS" "$WORK/links.json"; else printf '{\n  "links": []\n}\n' > "$WORK/links.json"; fi
  if ! python3 - "$WORK/links.json" "$WORK/links.new.json" "$LABEL" <<'PY'
import json, sys
src, out, label = sys.argv[1:4]
with open(src) as f:
    doc = json.load(f)
if not isinstance(doc, dict) or not isinstance(doc.get("links"), list):
    raise SystemExit(1)
matches = [r for r in doc["links"] if isinstance(r, dict) and r.get("label") == label]
if len(matches) != 1:
    raise SystemExit(1)
matches[0].pop("advisor_port", None)
with open(out, "w") as f:
    json.dump(doc, f, indent=2)
    f.write("\n")
PY
  then
    fail candidate_failed "the fleet-links.json candidate could not be built"
  fi
  if ! python3 - "$SNAP_FLEET_LINKS" "$WORK/links.new.json" "$LABEL" <<'PY'
import json, sys
orig_path, new_path, label = sys.argv[1:4]
with open(orig_path) as f:
    orig = json.load(f)
with open(new_path) as f:
    new = json.load(f)
orig_rows = orig.get("links") if isinstance(orig, dict) else None
new_rows = new.get("links") if isinstance(new, dict) else None
if not isinstance(orig_rows, list) or not isinstance(new_rows, list):
    raise SystemExit(1)
orig_rest = [r for r in orig_rows if not (isinstance(r, dict) and r.get("label") == label)]
new_rest = [r for r in new_rows if not (isinstance(r, dict) and r.get("label") == label)]
if orig_rest != new_rest:
    raise SystemExit(1)
orig_target = next((r for r in orig_rows if isinstance(r, dict) and r.get("label") == label), None)
new_target = next((r for r in new_rows if isinstance(r, dict) and r.get("label") == label), None)
if orig_target is None or new_target is None:
    raise SystemExit(1)
o = {k: v for k, v in orig_target.items() if k != "advisor_port"}
n = {k: v for k, v in new_target.items() if k != "advisor_port"}
if o != n:
    raise SystemExit(1)
PY
  then
    refuse excision_mismatch "detaching the Advisor from \"$LABEL\" would change a row other than its own in $FLEET_LINKS, so nothing was written."
  fi

  validate_candidates_or_refuse "$WORK/fleet.yaml" "$WORK/links.new.json"

  BACKED=()
  BACKED+=("$FLEET_YAML" "$(backup_of "$SNAP_FLEET_YAML")" "$DASH_USER:$DASH_GROUP:644")
  BACKED+=("$FLEET_LINKS" "$(backup_of "$SNAP_FLEET_LINKS")" "$DASH_USER:$DASH_GROUP:600")
  BACKED+=("$NODES_CONF" "$(backup_of "$NODES_CONF")" "self")
  BACKED+=("$ADVISOR_TOKEN_PATH" "$(backup_of "$ADVISOR_TOKEN_PATH")" "self")

  STEP="fleet.yaml"
  place "$WORK/fleet.yaml" "$FLEET_YAML" "$DASH_USER" "$DASH_GROUP" 644 \
    || { restore_all || true; fail rename_failed "$STEP could not be written$RESTORE_NOTE"; }
  STEP="fleet-links.json"
  place "$WORK/links.new.json" "$FLEET_LINKS" "$DASH_USER" "$DASH_GROUP" 600 \
    || { restore_all || true; fail rename_failed "$STEP could not be written$RESTORE_NOTE"; }
  if command -v sync >/dev/null 2>&1; then sync "$CONFIG_DIR" 2>/dev/null || true; fi

  # The token file is removed only now, after both registries are safely
  # placed: a failure past this point still has restore_all bring it back,
  # since it was backed up before anything else moved. Routed through
  # dirsafe (#648, round 7) rather than a bare `rm -f` by path: TOKEN_DIR's
  # own chain gets the identical O_NOFOLLOW walk every other write in this
  # program now does, not a fifth place that still finds it by string. A
  # refused unlink (TOKEN_DIR itself gone symlink, say) is reported and
  # rolled back the same as a failed place() above -- the old `rm -f` never
  # refused at all, so a detach that could not actually remove the token
  # must not go on to report success either.
  STEP="the Advisor token"
  if ! dirsafe_locate "$ADVISOR_TOKEN_PATH" \
     || ! dirsafe "$DS_ANCHOR" "$DS_RELPATH" "$DS_EXTRA" "$DS_MASK" unlink "$DS_LEAF"; then
    restore_all || true
    fail token_failed "$STEP could not be removed$RESTORE_NOTE"
  fi

  NODES_LINE=""
  if [[ -f "$NODES_CONF" ]]; then
    while IFS= read -r ncline || [[ -n "$ncline" ]]; do
      case "$ncline" in ''|'#'*) continue ;; esac
      read -r nclabel _ <<<"$ncline"
      if [[ "$nclabel" == "$LABEL" ]]; then NODES_LINE="$ncline"; break; fi
    done < "$NODES_CONF"
  fi
  NODES_UPDATED=0
  if [[ -n "$NODES_LINE" ]]; then
    read -r NL_LABEL NL_PIN NL_PORT _ NL_REST <<<"$NODES_LINE"
    {
      nodes_conf_without "$LABEL"
      if [[ -n "$NL_REST" ]]; then
        printf '%s %s %s 0 %s\n' "$NL_LABEL" "$NL_PIN" "$NL_PORT" "$NL_REST"
      else
        printf '%s %s %s 0\n' "$NL_LABEL" "$NL_PIN" "$NL_PORT"
      fi
    } > "$WORK/nodes.new"
    nodes_conf_write "$WORK/nodes.new" \
      || { restore_all || true; fail nodes_conf_failed "$NODES_CONF could not be written$RESTORE_NOTE"; }
    NODES_UPDATED=1
  fi

  reload_dashboard
  fact detached "$LABEL"
  fact nodes_updated "$NODES_UPDATED"
  fact reloaded "$RELOADED"
  fact reload_via "${RELOAD_VIA:-none}"
  out "the Advisor is detached from \"$LABEL\". This aggregator no longer reaches it there; the node's own Advisor and its token are untouched."
  finish 0
fi

if [[ "$VERB" == "refresh-advisor-token" ]]; then
  LABEL="${P[label]:-}"
  ADVISOR_TOKEN="${P[advisor_token]:-}"
  LABEL_FOR_LOG="$LABEL"
  [[ "$LABEL" =~ $LABEL_RE ]] || refuse bad_label "that is not a label this fleet could hold"
  [[ -n "$ADVISOR_TOKEN" ]] || refuse no_token "no Advisor token was given, so there is nothing to refresh"
  (( ${#ADVISOR_TOKEN} <= FLEET_PAIR_MAX_TOKEN_CHARS )) \
    || refuse bad_token "that Advisor token is longer than any bearer token this fleet writes"

  read_row_plan_or_refuse "$LABEL"
  HAVE_ROW="$(python3 -c 'import json,sys;print("1" if json.load(open(sys.argv[1]))["found"] else "0")' "$ROW_PLAN")"
  [[ "$HAVE_ROW" == "1" ]] \
    || refuse label_not_found "$FLEET_YAML has no row called \"$LABEL\"."
  ROW_ADVISOR_ORIGIN="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["row"].get("advisor_origin") or "")' "$ROW_PLAN")"
  [[ -n "$ROW_ADVISOR_ORIGIN" ]] \
    || refuse not_attached "\"$LABEL\" carries no Advisor, so there is no token to refresh. Use attach-advisor instead."

  # This verb can only ever replace a token for a row that is already fully
  # attached and trusted: it cannot widen ADVISOR, cannot allocate a port,
  # cannot touch fleet.yaml or fleet-links.json, so it needs none of the
  # all-three-or-none machinery the other two verbs do. write_token's own
  # rename is the only write, and it is already atomic on its own.
  #
  # The path it writes is derived from LABEL, never read out of fleet.yaml:
  # a row's own advisor_token_path is checked against that same convention
  # path and refused if it disagrees, so this program is never asked to
  # write a path fleet.yaml (the dashboard account's own file) named.
  ROW_ADVISOR_TOKEN_PATH="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["row"].get("advisor_token_path") or "")' "$ROW_PLAN")"
  ADVISOR_TOKEN_PATH="$TOKEN_DIR/$LABEL.approve.token"
  [[ "$ROW_ADVISOR_TOKEN_PATH" == "$ADVISOR_TOKEN_PATH" ]] \
    || refuse non_convention_path "\"$LABEL\"'s row names an Advisor token path this program did not write ($ROW_ADVISOR_TOKEN_PATH), so refreshing it by the convention path is refused rather than writing beside a path fleet.yaml named."
  # This is the passkey-free verb the round 3 review's CRITICAL finding
  # reached (scripts/aperire-fleet-broker.sh, as it stood before this fix):
  # every other write path calls ensure_token_dir before it calls
  # write_token, and this one called neither, so a first refresh against a
  # row whose token had never yet needed the directory found it re-created
  # by write_token's OWN unguarded assumptions rather than by the one
  # function that opens it with O_NOFOLLOW and checks who owns it and its
  # parent. Called here for the same reason attach-advisor already calls it.
  ETD_RC=0; ensure_token_dir "$TOKEN_DIR" || ETD_RC=$?
  if (( ETD_RC == 2 )); then
    refuse token_is_symlink "$TOKEN_DIR already exists as a symlink, and this program will not create, own or mode a directory through one. Nothing here follows it. Remove it by hand and try again."
  elif (( ETD_RC != 0 )); then
    fail token_failed "$TOKEN_DIR could not be created"
  fi
  TOKEN_MODE_RC=0; WIDE="$(check_token_mode "$ADVISOR_TOKEN_PATH")" || TOKEN_MODE_RC=$?
  if (( TOKEN_MODE_RC == 2 )); then
    refuse token_is_symlink "$ADVISOR_TOKEN_PATH already exists as a symlink, and a bearer token is never written through one. Nothing here follows it. Remove it by hand and try again."
  elif (( TOKEN_MODE_RC == 1 )); then
    refuse token_too_wide "$ADVISOR_TOKEN_PATH already exists with mode $WIDE, wider than 0640. A bearer token at that mode is refused, never silently tightened."
  fi
  write_token "$ADVISOR_TOKEN_PATH" "$ADVISOR_TOKEN" \
    || fail token_failed "$ADVISOR_TOKEN_PATH could not be written"
  # No reload: advisorPreamble's own guarded read (peer-advisor-proxy.ts,
  # the readTokenFresh call right after verifyPeerPin) opens this file with
  # readFileSync on every call it makes (fleet-health.ts's readTokenFresh,
  # "read the token fresh from disk on every fetch, never cache it"), so
  # nothing here is read once and held in memory the way a bound listener
  # would be.
  fact refreshed "$LABEL"
  out "the Advisor token for \"$LABEL\" is refreshed."
  finish 0
fi

# ══ phase 4: the fleet model store ═══════════════════════════════════════
#
# One store in one of two forms (see STORE above), three verbs, and one rule
# that governs all of them: the key arrives on stdin, lives in a shell
# variable, and leaves on a pipe. No verb prints it, and there is no verb
# that asks for it back.

# The field rules, the sealer's own, re-declared here so a descriptor this
# program stores is one the sealer will accept months later. A store that
# holds a value the sealer refuses is a fleet that cannot catch a node up and
# cannot say why.
STORE_BASE_HTTPS_RE='^https://[^[:space:]"\\]+$'
STORE_BASE_LOOPBACK_RE='^http://(127\.0\.0\.1|localhost)(:[0-9]{1,5})?(/[^[:space:]"\\]*)?$'
STORE_MODEL_RE='^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$'
STORE_CRED_RE='^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'
# The descriptor is seven short fields and one key. Anything past this is not
# a descriptor this program wrote, and is not read into a variable whole.
STORE_MAX_BYTES=65536

# Which form is on disk, and so which one a read opens (#711). Sets STORE_FORM
# to sealed, plain or none, and STORE_AT to its path.
#
# By the NAME that is there, never by what this host would write today: a
# host upgraded from 22.04 keeps a plain store at a name that still says
# plain, and handing that file to `systemd-creds decrypt` would call a good
# store unreadable. Both present is a put that wrote one form and died before
# it removed the other; the form this host measures is the one that put just
# wrote, so that is the one read. A name standing there as anything at all,
# a dangling link included, counts as present, so store_guard refuses it by
# name rather than a read reporting "there is none" over it.
store_resolve() {
  local have_sealed=0 have_plain=0
  [[ -e "$STORE" || -L "$STORE" ]] && have_sealed=1
  [[ -e "$STORE_PLAIN_FILE" || -L "$STORE_PLAIN_FILE" ]] && have_plain=1
  STORE_FORM=none; STORE_AT=""; STORE_BOTH=0
  if (( have_sealed && have_plain )); then
    STORE_BOTH=1
    STORE_FORM="$(aperire_key_method)"
  elif (( have_sealed )); then
    STORE_FORM=sealed
  elif (( have_plain )); then
    STORE_FORM=plain
  fi
  case "$STORE_FORM" in
    sealed) STORE_AT="$STORE" ;;
    plain)  STORE_AT="$STORE_PLAIN_FILE" ;;
  esac
  return 0
}

# The pair of stats the sealer already makes on $FLEET_ARM_PUB and $ARM_FILE,
# on a file that is a provider key. This project has met the permissions
# accident twice (#171, #113), so it is checked and not assumed.
#
# `-O` and not "owned by root": on a host this program IS root, and in the
# harness it is whoever runs the tests. The property that matters is the
# same either way, that the account reading the key owns the file it is in.
#
# On whichever form store_resolve found, and the plain form is checked a
# second time on the descriptor it is read through (store_read_plain), which
# is the check that holds; this one is the sentence.
store_guard() {  # -> refuses, or returns 0
  local mode
  [[ -O "$STORE_AT" ]] \
    || refuse store_not_owned "$STORE_AT is not owned by the account this program runs as, so it is not a file this host wrote. Nothing was read."
  [[ ! -L "$STORE_AT" ]] \
    || refuse store_not_owned "$STORE_AT is a symlink, and this program reads a provider key out of a plain file it wrote and out of nothing it points at. Nothing was read."
  mode="$(stat -c '%a' "$STORE_AT" 2>/dev/null || echo '?')"
  [[ "$mode" =~ ^[0-7]{3,4}$ ]] \
    || refuse store_bad_mode "$STORE_AT has no mode this program can read. Nothing was read."
  (( (8#$mode & 8#077) == 0 )) \
    || refuse store_too_wide "$STORE_AT is mode $mode, readable or writable by somebody other than its owner. A provider key at that mode is refused, never silently tightened. Nothing was read."
  return 0
}

# A sealed store needs systemd-creds to open, and a plain one must never be
# handed to it. Only the sealed form asks. A host that holds a sealed store
# and has no systemd-creds any more (the package removed, or the store copied
# from another machine) cannot open it here, and the one thing to do about
# that is to seal the fleet model again, which writes the form this host has.
store_opener_or_fail() {  # -> fails, or returns 0
  [[ "$STORE_FORM" == sealed ]] || return 0
  command -v systemd-creds >/dev/null 2>&1 \
    || fail no_systemd_creds "$STORE is sealed with systemd-creds, and systemd-creds is not on this host, so the fleet model cannot be read here. Seal the fleet model again from Settings: this host keeps it as $(aperire_key_method_line plain)."
  return 0
}

# The plain form's content, through ONE descriptor (#711). O_NOFOLLOW, so a
# link standing at the name is refused at the open rather than followed;
# O_NONBLOCK, so a FIFO planted there cannot hold this connection open; and
# the same three facts store_guard read by name, read again off the
# descriptor that is actually read: a regular file, owned by this account,
# nothing in the group or other bits. Out to stdout, into a variable, never a
# file. The path is on python's argv, which is not a secret; the content never
# is.
store_read_plain() {  # -> the descriptor on stdout, or non-zero
  python3 -c '
import os, stat, sys
path, cap = sys.argv[1], int(sys.argv[2])
try:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
except OSError:
    sys.exit(2)
try:
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or (st.st_mode & 0o077):
        sys.exit(3)
    chunks, got = [], 0
    while got <= cap:
        b = os.read(fd, cap + 1 - got)
        if not b:
            break
        chunks.append(b)
        got += len(b)
    if got > cap:
        sys.exit(4)
finally:
    os.close(fd)
sys.stdout.buffer.write(b"".join(chunks))
' "$STORE_AT" "$STORE_MAX_BYTES"
}

# The descriptor's plaintext, on stdout, for one caller at a time.
#
# Sealed: `--name` is pinned on the way out as it was on the way in, so a
# blob sealed on this host for something else cannot be read by pointing
# this path at it. Plain: the one-descriptor read above.
store_decrypt() {  # -> plaintext on stdout, or non-zero
  case "$STORE_FORM" in
    sealed) systemd-creds decrypt --name="$STORE_CRED_NAME" "$STORE" - 2>/dev/null ;;
    plain)  store_read_plain ;;
    *)      return 1 ;;
  esac
}

# The facts every answer about the store carries, so the page can say which
# form it is and whether this host could do better now (#711). host_method
# differs from method only on a host whose OS moved under a store: a 22.04
# aggregator upgraded in place still holds the plain form until its next put.
store_method_facts() {
  local host
  host="$(aperire_key_method)"
  fact method "$STORE_FORM"
  fact host_method "$host"
  # Both forms at once is a put that died between writing one and removing
  # the other. The answer above is right either way; this says the leftover
  # is there, because on a sealing host it is a plaintext key nobody named.
  if (( STORE_BOTH )); then
    fact other_form present
    # WHICH file is the leftover, by path, so the page can name it and the
    # command that removes it without deriving a path of its own.
    if [[ "$STORE_FORM" == sealed ]]; then fact other_form_at "$STORE_PLAIN_FILE"
    else fact other_form_at "$STORE"; fi
  fi
}

if [[ "$VERB" == "model-store-put" ]]; then
  # The form this host writes, measured by the one rule every program that
  # keeps a model key uses (#708, #711). Never a refusal: a host without
  # systemd-creds keeps the store as a root-only file, the arrangement the
  # operator ruled supported for 22.04. And never a fall-back from one to the
  # other: a host that measures `sealed` and whose seal then fails refuses
  # below, rather than quietly writing the key in the clear.
  PUT_METHOD="$(aperire_key_method)"
  S_BASE="${P[base_url]:-}"
  S_SHAPE="${P[shape]:-}"
  S_MODEL="${P[model]:-}"
  S_CRED="${P[credential_name]:-}"
  S_HINT="${P[key_hint]:-}"
  S_BY="${P[sealed_by]:-}"
  # The same strip the sealer makes, and for the same reason: a key pasted
  # with a trailing newline would seal here and hash differently there, and
  # the operator would be told their key does not match itself.
  S_KEY="${P[key]:-}"
  S_KEY="${S_KEY//[$'\t\r\n ']/}"

  [[ "$S_BASE" =~ $STORE_BASE_HTTPS_RE || "$S_BASE" =~ $STORE_BASE_LOOPBACK_RE ]] \
    || refuse bad_base_url "the provider address must be https, or loopback for a local runner"
  [[ "$S_SHAPE" == openai || "$S_SHAPE" == anthropic ]] \
    || refuse bad_shape "shape is openai or anthropic"
  [[ "$S_MODEL" =~ $STORE_MODEL_RE ]] || refuse bad_model "that does not look like a model identifier"
  [[ "$S_CRED" =~ $STORE_CRED_RE && "$S_CRED" != *".."* ]] \
    || refuse bad_credential_name "the credential name must be a bare name"
  [[ -n "$S_KEY" ]] || refuse no_key "that payload carries no key, and a descriptor with no key is one no node could be sealed from"
  [[ "$S_KEY" =~ ^[[:print:]]+$ ]] \
    || refuse bad_key "that key carries characters a credential file cannot hold"
  # The hint and the operator name are the two free-text fields, and both are
  # rendered on a page. A newline in either would forge a line in the answer
  # this program's own grammar is made of.
  case "$S_HINT$S_BY" in
    *[$'\n\r']*) refuse bad_payload "a value in that payload carries a line break, which no field here takes" ;;
  esac
  (( ${#S_HINT} <= 64 )) || refuse bad_payload "that key hint is longer than any hint this product makes"
  (( ${#S_BY} <= 128 )) || refuse bad_payload "that operator name is longer than an operator name"

  SEALED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  # The JSON, built by python3 reading its fields on STDIN. Not argv: a value
  # on a command line is in /proc/<pid>/cmdline for as long as that process
  # runs, and one of these values is the key. Seven lines in, one object out.
  if ! STORE_PLAIN="$(printf '%s\n' "$S_BASE" "$S_SHAPE" "$S_MODEL" "$S_CRED" "$S_HINT" \
        "$SEALED_AT" "$S_BY" "$S_KEY" | python3 -c '
import json, sys
f = sys.stdin.read().split("\n")
if len(f) < 8:
    raise SystemExit(1)
sys.stdout.write(json.dumps({
    "v": 1, "base_url": f[0], "shape": f[1], "model": f[2],
    "credential_name": f[3], "key_hint": f[4], "sealed_at": f[5],
    "sealed_by": f[6], "key": f[7],
}))
')"; then
    fail store_failed "the fleet model descriptor could not be built on this host"
  fi

  # root:root under a real run; under the test harness (never really root) a
  # chown to root would fail outright, so that case owns it as itself, the
  # same fallback nodes_conf_write and write_token already make.
  if (( BROKER_UID == 0 )); then STORE_OWNER=root; STORE_GROUP=root
  else STORE_OWNER="$BROKER_UID"; STORE_GROUP="$(id -g)"; fi

  if [[ "$PUT_METHOD" == sealed ]]; then
    PUT_TARGET="$STORE"; PUT_OTHER="$STORE_PLAIN_FILE"
    # Sealed to a file in $WORK first (root's own private mktemp -d), never to
    # a name built beside $STORE ("$STORE.new.$$" was the fourth copy of the
    # exact "$2.new.$$" shape review5-2.json closed in place() and review6-0.json
    # closed in restore_all -- round 7, review7-0.json, closes it here by never
    # building it at all). `systemd-creds encrypt ... - -` writes the sealed
    # blob to ITS OWN stdout rather than to a path this program would have had
    # to trust; dirsafe.py's "put" then walks $ETC by directory descriptor and
    # does the create-write-chown-chmod-rename itself, the one primitive every
    # other root write in this program now shares. What sits in $WORK is
    # ciphertext; the plaintext never touches a file on this path.
    STORE_SEAL="$WORK/store.sealed"
    if ! ( umask 077; printf '%s' "$STORE_PLAIN" \
           | systemd-creds encrypt --name="$STORE_CRED_NAME" - - ) > "$STORE_SEAL" 2>/dev/null; then
      STORE_PLAIN=""; unset STORE_PLAIN
      rm -f "$STORE_SEAL"
      # Its own sentence. The usual cause is a host with no
      # /var/lib/systemd/credential.secret, which is a thing to fix rather than
      # a payload to correct.
      refuse seal_failed "systemd-creds could not seal the fleet model on this host. It needs a local credential host secret; nothing was written."
    fi
    STORE_PLAIN=""; unset STORE_PLAIN
    if ! dirsafe "$ETC" "" "" 022 put "$STORE_OWNER" "$STORE_GROUP" 600 "$STORE_SEAL" "$(basename -- "$STORE")"; then
      rm -f "$STORE_SEAL"
      fail store_failed "$STORE could not be written; nothing was changed"
    fi
    rm -f "$STORE_SEAL"
  else
    PUT_TARGET="$STORE_PLAIN_FILE"; PUT_OTHER="$STORE"
    # The plain form (#711). There is nothing on this host to seal with, so
    # the protection is the mode, the owner and $ETC above it, the same
    # reader set a sealed blob has on a host with no TPM, where the host key
    # systemd-creds encrypts with is itself a 0400 root file beside it.
    #
    # The JSON goes to dirsafe.py's "put" on its STDIN ("-" as the source),
    # never through a staging file: $WORK is a fine place for ciphertext and
    # the wrong place for a key in the clear. put creates its candidate under
    # $ETC's own descriptor, O_CREAT|O_EXCL|O_NOFOLLOW at 0600 from the first
    # byte, chowns and chmods it on that descriptor, renames it onto the
    # store, and checks that what landed is the inode it wrote.
    if ! printf '%s' "$STORE_PLAIN" \
         | dirsafe "$ETC" "" "" 022 put "$STORE_OWNER" "$STORE_GROUP" 600 - "$(basename -- "$STORE_PLAIN_FILE")"; then
      STORE_PLAIN=""; unset STORE_PLAIN
      fail store_failed "$STORE_PLAIN_FILE could not be written; nothing was changed"
    fi
    STORE_PLAIN=""; unset STORE_PLAIN
  fi

  # The OTHER form goes, after the new one has landed and never before: a
  # put that dies between the two leaves both, and a read then takes the form
  # this host measures, which is the one just written. This is what makes a
  # host upgraded from 22.04 converge on its next seal, with no plaintext
  # copy left beside the sealed one (the rule #708 set for the Advisor's own
  # key). A plain copy that cannot be removed is a failure, never a success
  # with a footnote: it is a working key on disk that the operator believes
  # is gone.
  PUT_REMOVED=none
  if [[ -e "$PUT_OTHER" || -L "$PUT_OTHER" ]]; then
    if ! dirsafe "$ETC" "" "" 022 unlink "$(basename -- "$PUT_OTHER")"; then
      fail store_stale_left "the fleet model was written to $PUT_TARGET, and the older copy at $PUT_OTHER could not be removed. Remove it by hand: sudo rm -f $PUT_OTHER"
    fi
    PUT_REMOVED="$(basename -- "$PUT_OTHER")"
  fi

  fact stored 1
  fact sealed_at "$SEALED_AT"
  fact method "$PUT_METHOD"
  fact removed "$PUT_REMOVED"
  if [[ "$PUT_METHOD" == sealed ]]; then
    out "the fleet model is sealed on this host. It is sealed to this machine and is not a backup: rebuild the host and it decrypts nowhere."
  else
    out "the fleet model is kept on this host as $(aperire_key_method_line plain), at $STORE_PLAIN_FILE, root only. It is not a backup, and a copy of that file is a working key wherever it lands, so no backup set carries it."
  fi
  finish 0
fi

if [[ "$VERB" == "model-store-head" ]]; then
  # Absent is an ANSWER, not a refusal. "This aggregator holds no sealed
  # fleet key" is what the page needs in order to say that a node paired now
  # would join with no model, and a refusal there would render as a broken
  # broker instead.
  store_resolve
  if [[ "$STORE_FORM" == none ]]; then
    fact stored 0
    out "this aggregator holds no sealed fleet model, so a node paired now would join with no model."
    finish 0
  fi
  store_opener_or_fail
  store_guard
  if ! HEAD_PLAIN="$(store_decrypt)"; then
    # Named apart from absent, and it must stay that way: the page's sentence
    # for absent tells an operator to seal the fleet model again, and saying
    # that about a blob this host simply could not open would be telling them
    # to re-paste a key over one that is fine.
    if [[ "$STORE_FORM" == plain ]]; then
      refuse store_unreadable "the fleet model kept on this host at $STORE_PLAIN_FILE could not be read as a plain file this account owns at mode 0600. Nothing was read."
    fi
    refuse store_unreadable "the sealed fleet model on this host could not be decrypted under the name it was sealed with. If this host was rebuilt, seal the fleet model again from Settings."
  fi
  # The key is dropped HERE, by the only program that ever sees it, and what
  # comes out of this pipe is the descriptor minus the key. There is no flag
  # on this verb that keeps it.
  if ! HEAD_FACTS="$(printf '%s' "$HEAD_PLAIN" | python3 -c '
import json, sys
d = json.load(sys.stdin)
for name in ("base_url", "shape", "model", "credential_name", "key_hint", "sealed_at", "sealed_by"):
    v = d.get(name)
    sys.stdout.write("%s=%s\n" % (name, "" if v is None else str(v)))
')"; then
    HEAD_PLAIN=""; unset HEAD_PLAIN
    refuse store_unreadable "the sealed fleet model on this host decrypted to something this program could not read."
  fi
  HEAD_PLAIN=""; unset HEAD_PLAIN
  fact stored 1
  printf '%s\n' "$HEAD_FACTS"
  store_method_facts
  if (( STORE_BOTH )); then
    out "a copy in the other form is also on this host, left by a seal that did not finish ($STORE and $STORE_PLAIN_FILE are both here). The next seal removes it; so does: sudo rm -f $([[ "$STORE_FORM" == sealed ]] && printf '%s' "$STORE_PLAIN_FILE" || printf '%s' "$STORE")"
  fi
  if [[ "$STORE_FORM" == sealed ]]; then
    out "this aggregator holds a sealed fleet model, and a node paired now inherits it."
  elif [[ "$(aperire_key_method)" == sealed ]]; then
    # The upgraded host (#711). Read, not converted: this verb runs on every
    # page load with no window open, and a read that rewrote the key would be
    # a write nobody asked for. The next put converts it and removes the file.
    out "this aggregator holds the fleet model as a root-only file, and a node paired now inherits it. This host can seal it now: seal the fleet model again from Settings, with the key, and the file is replaced by a sealed copy."
  else
    out "this aggregator holds the fleet model as a root-only file, and a node paired now inherits it."
  fi
  finish 0
fi

# THE WINDOW ON THIS HOST, which is what bounds when the key can move at all.
#
# Without it, a compromised dashboard could push on its own schedule to any
# label in root's record. On a LINK fleet that is worse than it sounds: the
# loopback port in that record is bound by the dashboard process itself, so
# the same process can answer the identity check with the pin it reads out of
# fleet.yaml and take delivery of the key. The pin proves the port is
# answered by the node it names only as far as the node is what holds the
# port (security review, finding F1).
#
# The marker is NOT spent here. The sealer spends it because one arming is
# one seal on one host; a catch-up is one arming and many pushes, and an
# operator arming once per node they are catching up is an operator who stops
# catching up. The window lapses on its own, which is the property that
# matters: root said WHEN, and that is fifteen minutes.
#
# Read exactly as aperire-seal-model-key.sh reads it: owned by this account,
# not group or world writable, and younger than the window. A marker dated in
# the future is a clock that moved, and "I cannot tell how old this is" reads
# as too old.
# The line that opens one, as an operator types it (#812): the installed name
# when the grant put it on root's PATH. When this grant is older than that
# program, the update first (it places the program, wherever the broker is,
# and --force because a host already on the current release is otherwise told
# "nothing was touched" before that step), then a check that the program is
# there now, then the installed name. The check keeps a declined prompt or a
# failed download from running an arm that says "command not found". Never a
# path into the tree: root would run a file the dashboard's own account can
# write. Both end in the bare program, so a caller adds --self-only.
# "Installed" is the same test the dashboard makes (server.ts
# rootProgramInstalled): a regular file, not a link, root's, executable.
arm_program_installed() {
  [[ ! -L "$FLEET_ARM_PROGRAM" && -f "$FLEET_ARM_PROGRAM" && -O "$FLEET_ARM_PROGRAM" && -x "$FLEET_ARM_PROGRAM" ]]
}
arm_self_line() {
  if arm_program_installed; then
    printf 'sudo aperire-fleet-arm --self-only'
  else
    printf 'curl -fsSL https://get.aperire.one | bash -s -- --update --force && test -x /usr/local/sbin/aperire-fleet-arm && sudo aperire-fleet-arm --self-only'
  fi
}
# The clause that says why the line leads with the update, or nothing.
arm_self_lead() {
  arm_program_installed || printf ' (this grant predates the arm program, so the line updates first)'
}
arm_guard() {  # -> refuses, or returns 0
  local mode armed_at age
  [[ -f "$ARM_FILE" ]] \
    || refuse arm_closed "this aggregator has no sealing window open, so it moved no key. Open one on this host$(arm_self_lead) and try again: $(arm_self_line)"
  [[ -O "$ARM_FILE" ]] \
    || refuse arm_closed "$ARM_FILE is not owned by the account this program runs as, so it is not an arming. Nothing was sent."
  mode="$(stat -c '%a' "$ARM_FILE" 2>/dev/null || echo 777)"
  if (( 8#$mode & 8#022 )); then
    refuse arm_closed "$ARM_FILE is mode $mode; a marker group or others may write is not an arming. Nothing was sent."
  fi
  armed_at="$(stat -c '%Y' "$ARM_FILE" 2>/dev/null || echo 0)"
  age=$(( $(date +%s) - armed_at ))
  if (( age < 0 || age > ARM_WINDOW_SEC )); then
    refuse arm_closed "this aggregator's sealing window closed ${age}s after it opened (limit ${ARM_WINDOW_SEC}s), so it moved no key. Open one on this host$(arm_self_lead) and try again: $(arm_self_line)"
  fi
  return 0
}

if [[ "$VERB" == "model-push" ]]; then
  PUSH_LABEL="${P[label]:-}"
  LABEL_FOR_LOG="$PUSH_LABEL"
  [[ "$PUSH_LABEL" == "self" || "$PUSH_LABEL" =~ $LABEL_RE ]] \
    || refuse bad_label "that is not a label this fleet could hold"
  # WHO approved THIS push, from the caller, not from the store.
  #
  # The node's own gate (checkSealJob, gate 4) refuses a job whose granted_by
  # or credential_id is empty, so these are not decoration: a push without
  # them is a push every node answers bad_job. They are the caller's because
  # the store holds who sealed it MONTHS ago, and a catch-up is a fresh
  # approval by a named operator at a passkey. The node's ledger has to name
  # the person who authorised the key reaching it, and that is this one.
  PUSH_BY="${P[granted_by]:-}"
  PUSH_CRED_ID="${P[credential_id]:-}"
  [[ -n "$PUSH_BY" && ${#PUSH_BY} -le 128 ]] \
    || refuse no_grant "a push names the operator who approved it, and this one did not"
  [[ "$PUSH_CRED_ID" =~ ^[A-Za-z0-9_-]{1,255}$ ]] \
    || refuse no_grant "a push names the passkey that approved it, and this one did not"

  # The window first. Before the store, before the record, before a node is
  # dialled: a push nobody armed is refused without this program reading a
  # sealed key at all.
  arm_guard

  # The store, and both its stats, so a push that was never going to
  # carry anything refuses before it touches a node.
  store_resolve
  [[ "$STORE_FORM" != none ]] \
    || refuse no_store "this aggregator holds no sealed fleet model, so there is nothing to push. Seal the fleet model from Settings first."
  store_opener_or_fail
  store_guard

  # The destination, from root's own file and from nowhere else. fleet.yaml
  # belongs to the dashboard account, and a destination that account can
  # rewrite is a destination it can point at itself.
  PUSH_PIN="" PUSH_PORT="" PUSH_ADVISOR="" PUSH_TOKEN_PATH=""
  if [[ "$PUSH_LABEL" != "self" ]]; then
    [[ -f "$NODES_CONF" ]] \
      || refuse no_node_record "this aggregator has no $NODES_CONF, so root has vouched for no node as a place to send a key. Run: install-fleet-broker-grant.sh --refresh-nodes"
    PUSH_ROW_TOKEN=""
    while read -r n_label n_pin n_port n_adv n_token _; do
      case "$n_label" in ''|'#'*) continue ;; esac
      # THE ROW'S OWN SHAPE, on the way in as well as on the way out
      # (security review, finding F2). This file is root's, but it is built
      # from files the dashboard account owns, and a builder that let a label
      # with a newline through would have written rows nobody approved. A row
      # that does not match is not this label, whatever it says its label is.
      [[ "$n_label" =~ $LABEL_RE ]] || continue
      [[ "$n_pin" =~ $NODE_KEY_RE ]] || continue
      [[ "$n_port" =~ ^[0-9]{1,5}$ ]] || continue
      [[ "$n_label" == "$PUSH_LABEL" ]] || continue
      PUSH_PIN="$n_pin"; PUSH_PORT="$n_port"; PUSH_ADVISOR="$n_adv"; PUSH_ROW_TOKEN="$n_token"
      break
    done < "$NODES_CONF"
    [[ -n "$PUSH_PIN" ]] \
      || refuse unknown_node "$NODES_CONF names no node called \"$PUSH_LABEL\", so there is nowhere this key may be sent. Approve that node, or run: install-fleet-broker-grant.sh --refresh-nodes"
    [[ "$PUSH_PIN" =~ $NODE_KEY_RE ]] \
      || refuse bad_node_record "the row for \"$PUSH_LABEL\" in $NODES_CONF does not carry a node key shape, so nothing can be pinned before the key travels"
    if ! [[ "$PUSH_PORT" =~ ^[0-9]{1,5}$ ]] || (( PUSH_PORT < 1 || PUSH_PORT > 65535 )); then
      refuse bad_node_record "the row for \"$PUSH_LABEL\" in $NODES_CONF names no usable read port"
    fi
    [[ "$PUSH_ADVISOR" == "1" ]] \
      || refuse no_advisor_there "\"$PUSH_LABEL\" is registered with no Advisor, so there is nothing on it to seal a model onto"
    # WHERE THAT NODE'S READ TOKEN IS, from the same row (#458). The fifth
    # field when the registry named a path of its own, and the path an
    # approval writes when it did not. Derived from the label alone, this
    # refused every node registered through aperire-fleet-add.sh with a
    # token outside that directory, while the dashboard's own seal read the
    # registry's path and reached the same node in the same minute.
    #
    # A fifth field whose shape is wrong is its own refusal and never a
    # quiet fall back to the convention path: falling back is the two
    # readers again, with root reading a file the seal does not.
    if [[ -n "$PUSH_ROW_TOKEN" ]]; then
      token_path_ok "$PUSH_ROW_TOKEN" \
        || refuse bad_node_record "the row for \"$PUSH_LABEL\" in $NODES_CONF names a read token path this program will not read a bearer token out of, so nothing was sent. Fix that row's token_path in the registry and run: install-fleet-broker-grant.sh --refresh-nodes"
      PUSH_TOKEN_PATH="$PUSH_ROW_TOKEN"
    else
      PUSH_TOKEN_PATH="$TOKEN_DIR/$PUSH_LABEL.token"
    fi
  fi

  # Decrypted into a variable, never a file, not even on tmpfs.
  PUSH_PLAIN=""
  if ! PUSH_PLAIN="$(store_decrypt)"; then
    [[ "$STORE_FORM" != plain ]] \
      || refuse store_unreadable "the fleet model kept on this host at $STORE_PLAIN_FILE could not be read as a plain file this account owns at mode 0600. Nothing was sent."
    refuse store_unreadable "the sealed fleet model on this host could not be decrypted under the name it was sealed with. If this host was rebuilt, seal the fleet model again from Settings."
  fi

  # ── self: the local sealer, root to root ───────────────────────────────
  # Five lines on its stdin, exactly the payload the dashboard's own socket
  # sends. The local arm marker still gates it; that refusal is the sealer's
  # and this program neither opens a window nor writes a marker.
  if [[ "$PUSH_LABEL" == "self" ]]; then
    [[ -x "$SEALER" ]] || { PUSH_PLAIN=""; refuse no_sealer "$SEALER is not on this host, so this aggregator's own Advisor cannot be sealed from here"; }
    SEAL_OUT="$WORK/self-seal.out"
    SEAL_RC=0
    printf '%s' "$PUSH_PLAIN" | python3 -c '
import json, sys
d = json.load(sys.stdin)
sys.stdout.write("\n".join([
    d["base_url"], d["shape"], d["model"], d["credential_name"], d["key"],
]) + "\n")
' | "$SEALER" > "$SEAL_OUT" 2>&1 || SEAL_RC=$?
    PUSH_PLAIN=""; unset PUSH_PLAIN
    # Its own words, read back. `sealed=` is the sealer's success fact; its
    # last prose line is the sentence an operator acts on.
    SEAL_DETAIL="$(grep -v '=' "$SEAL_OUT" 2>/dev/null | grep -v '^$' | tail -n 1 || true)"
    [[ -n "$SEAL_DETAIL" ]] || SEAL_DETAIL="$(tail -n 1 "$SEAL_OUT" 2>/dev/null || true)"
    if (( SEAL_RC == 0 )) && grep -q '^sealed=' "$SEAL_OUT"; then
      fact pushed 1
      fact state sealed
      fact reason sealed
      fact detail "${SEAL_DETAIL:-this host sealed the fleet model onto its own Advisor.}"
      out "this aggregator's own Advisor is on the fleet model."
      finish 0
    fi
    fact pushed 0
    fact state refused
    # The sealer prints `refused: <why>` on stderr; its own word, not one
    # invented here. An unarmed host is the ordinary case and reads as its
    # own refusal rather than as a failure of this program.
    fact reason "$(sed -n 's/^\([a-z_]*\): .*/\1/p' "$SEAL_OUT" | tail -n 1 || true)"
    fact detail "${SEAL_DETAIL:-the sealer on this host refused, and said nothing this program could read.}"
    out "this aggregator's own sealer refused the fleet model."
    finish 0
  fi

  # ── a peer: pin it, sign for it, POST to it ────────────────────────────
  command -v curl >/dev/null || { PUSH_PLAIN=""; fail no_curl "curl is not on this host, and a push is one HTTPS-shaped request to a loopback port"; }
  command -v openssl >/dev/null || { PUSH_PLAIN=""; fail no_openssl "openssl is not on this host, and a job for a node has to be signed"; }
  # Named rather than left to fail as a generic signing error: `-rawin` is
  # OpenSSL 3, and a host on 1.1 needs its openssl updated, which is a
  # different fix from a key that will not load.
  openssl pkeyutl -help 2>&1 | grep -q -- '-rawin' \
    || { PUSH_PLAIN=""; fail no_openssl "this host's openssl has no 'pkeyutl -rawin', which is OpenSSL 3. An Ed25519 job cannot be signed here"; }

  PUSH_ORIGIN="http://127.0.0.1:$PUSH_PORT"
  # THE TOKEN, READ AS THE DASHBOARD ACCOUNT (#458). The seal on the page
  # reads this same file as that account, and this reads it as that account
  # too, so the two readers are one reader and root gets nothing here the
  # dashboard could not already read for itself. It matters now that the
  # path can come out of a registry row: a token under a tree the dashboard
  # account owns is a file that account can replace with a symlink, and a
  # root that opened it would be a root opening whatever the link named. A
  # stat cannot close that (the swap can come after the stat); dropping the
  # privilege closes it at the open.
  if (( BROKER_UID == 0 )); then
    [[ -n "$RUNUSER_BIN" && -x "$RUNUSER_BIN" ]] \
      || { PUSH_PLAIN=""; refuse no_runuser "runuser is not on this host, so \"$PUSH_LABEL\"'s read token cannot be read as $TOKEN_READER, and this program will not read a bearer token as root. Install util-linux. Nothing was sent"; }
    [[ -n "$TOKEN_READER" && "$TOKEN_READER" != root ]] \
      || { PUSH_PLAIN=""; refuse bad_account_pinned "this host says its dashboard runs as root, and a node's read token will not be read as root. Re-run install-fleet-broker-grant.sh on this host. Nothing was sent"; }
  fi
  PUSH_TOKEN=""
  PUSH_TOKEN="$(read_token_as_dash "$PUSH_TOKEN_PATH")" \
    || { PUSH_PLAIN=""; refuse token_unreadable "$TOKEN_READER cannot read the read token for \"$PUSH_LABEL\" at $PUSH_TOKEN_PATH, so this host sent nothing. That is the same file and the same account the dashboard's own seal reads it with"; }
  [[ -n "$PUSH_TOKEN" ]] \
    || { PUSH_PLAIN=""; refuse token_unreadable "the read token file for \"$PUSH_LABEL\" at $PUSH_TOKEN_PATH is empty, so this host sent nothing"; }
  # The bearer goes in a 0600 file under $WORK, never on curl's argv
  # (security review, finding F3, and the same reason P2-057 moved it in
  # aperire-fleet-pair.sh): /proc/<pid>/cmdline is world readable, and a push
  # holds that process for up to 270 s, which is a long time for any local
  # account to be able to read a node's read token off a command line.
  PUSH_CURL_CFG="$WORK/curl.cfg"
  ( umask 077; printf 'header = "Authorization: Bearer %s"\n' "$PUSH_TOKEN" > "$PUSH_CURL_CFG" )
  PUSH_TOKEN=""; unset PUSH_TOKEN

  # THE PIN, before the key is anywhere near the wire. A row whose loopback
  # port now lands on a different host is exactly the case where a key must
  # not travel.
  ID_BODY="$WORK/identity.json"
  # `--no-location` on this one too, though it reads rather than writes: a
  # redirect here is an older node sending this program's bearer token
  # somewhere, and the destination of every request this program makes is
  # 127.0.0.1 on a port out of root's own record.
  # --max-filesize, on both calls: what answers a loopback port is whatever
  # holds that port, and this program must not read an unbounded stream into
  # a file because something on the other end offered one.
  ID_CODE="$(curl -sS --max-time 10 --no-location --max-filesize 65536 --config "$PUSH_CURL_CFG" \
    -o "$ID_BODY" -w '%{http_code}' "$PUSH_ORIGIN/read/v1/identity" 2>/dev/null || true)"
  if [[ "$ID_CODE" != "200" ]]; then
    PUSH_PLAIN=""
    fact pushed 0; fact state unreachable; fact reason "identity_http_${ID_CODE:-none}"
    fact detail "\"$PUSH_LABEL\" did not answer its identity check, so nothing was sent to it."
    out "\"$PUSH_LABEL\" was not reached."
    finish 0
  fi
  OBSERVED_PIN="$(python3 -c '
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception:
    raise SystemExit(0)
v = d.get("pubkey_node")
sys.stdout.write(v if isinstance(v, str) else "")
' "$ID_BODY" || true)"
  if [[ -z "$OBSERVED_PIN" || "$OBSERVED_PIN" != "$PUSH_PIN" ]]; then
    PUSH_PLAIN=""
    fact pushed 0; fact state unreachable; fact reason peer_integrity_mismatch
    fact detail "\"$PUSH_LABEL\" did not prove it is the node root's record is pinned to, so nothing was sent to it."
    out "\"$PUSH_LABEL\" is not the node this row names."
    finish 0
  fi

  snap_fleet_trust
  SEED=""
  if [[ -n "$SNAP_FLEET_TRUST" ]]; then
    SEED="$(sed -n 's/^private_key:[[:space:]]*//p' "$SNAP_FLEET_TRUST" 2>/dev/null \
      | head -n 1 | tr -d '"'\''[:space:]' || true)"
  fi
  [[ -n "$SEED" ]] \
    || { PUSH_PLAIN=""; refuse no_signing_key "this aggregator holds no fleet-trust private key, so it cannot sign a job for any node"; }

  # The job, its signing bytes and the request body, built by one python3
  # reading the descriptor and the seed on STDIN. Two lines in (the seed,
  # then the descriptor), the signing bytes and the job out; the key never
  # touches an argument and never a file.
  #
  # The signing bytes are dashboard/types/fleet-write-contract.ts's
  # sealJobSigningBytes, declared a second time because bash cannot import.
  # scripts/test-fleet-broker.sh holds the two together by fixture.
  JOB_FILE="$WORK/job.json"
  SIGN_FILE="$WORK/signing.bytes"
  # Written with `python3 -c` and not a heredoc: a heredoc IS the process's
  # standard input, and this one has a pipe on its standard input carrying
  # the descriptor. The two cannot both be stdin, and the descriptor is the
  # one that must not become a file.
  if ! printf '%s' "$PUSH_PLAIN" | python3 -c '
import hashlib, json, os, re, sys, time

target, version, issuer, granted_by, credential_id, job_path, sign_path = sys.argv[1:8]
d = json.loads(sys.stdin.read())

job = {
    "v": int(version),
    "kind": "model.seal",
    "issuer_label": issuer,
    "target_pubkey_node": target,
    "nonce": os.urandom(16).hex(),
    "issued_at": int(time.time()),
    "base_url": d["base_url"],
    "shape": d["shape"],
    "model": d["model"],
    "credential_name": d["credential_name"],
    # Over the key AS THE NODE SEALER WILL RECEIVE IT: whitespace stripped
    # first, the same strip sealKeyHash makes and the same one the per-node
    # seal handler makes. Hashed here and hashed differently there would tell
    # an operator their key does not match itself.
    "key_sha256": hashlib.sha256(re.sub(r"\s", "", d["key"]).encode()).hexdigest(),
    # The approving operator and the passkey they used, out of the payload
    # this verb was given. Both are inside the signature and both are what
    # the node writes in its own ledger row.
    "granted_by": granted_by,
    "credential_id": credential_id,
}
fields = ["v", "kind", "issuer_label", "target_pubkey_node", "nonce", "issued_at",
          "base_url", "shape", "model", "credential_name", "key_sha256",
          "granted_by", "credential_id"]
lines = ["%s=%s" % (n, str(job[n]).encode().hex()) for n in fields]
signing = "aperire-fleet-write/%s\n%s" % (version, "\n".join(lines))
with open(sign_path, "w") as f:
    f.write(signing)
with open(job_path, "w") as f:
    json.dump(job, f)
' "$PUSH_PIN" "$FLEET_WRITE_PROTOCOL_VERSION" "$FLEET_WRITE_ISSUER_LABEL" \
  "$PUSH_BY" "$PUSH_CRED_ID" "$JOB_FILE" "$SIGN_FILE"; then
    PUSH_PLAIN=""
    fail job_failed "the seal job for \"$PUSH_LABEL\" could not be built on this host"
  fi

  # The PKCS8 DER for the seed: the fixed Ed25519 prefix and the raw 32
  # bytes, the same construction aperire-fleet-add.sh already uses. The seed
  # crosses on stdin for the same reason the key does.
  SEED_DER="$WORK/seed.der"
  if ! printf '%s' "$SEED" | python3 -c '
import base64, sys
s = sys.stdin.read().strip()
raw = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
if len(raw) != 32:
    raise SystemExit(1)
open(sys.argv[1], "wb").write(bytes.fromhex("302e020100300506032b657004220420") + raw)
' "$SEED_DER"; then
    PUSH_PLAIN=""
    refuse no_signing_key "the fleet-trust private key on this aggregator is not a usable 32-byte signing key"
  fi
  SIGNATURE="$(openssl pkeyutl -sign -rawin -inkey "$SEED_DER" -in "$SIGN_FILE" 2>/dev/null \
    | python3 -c 'import sys,base64; sys.stdout.write(base64.urlsafe_b64encode(sys.stdin.buffer.read()).decode().rstrip("="))' || true)"
  rm -f "$SEED_DER"
  [[ -n "$SIGNATURE" ]] \
    || { PUSH_PLAIN=""; refuse sign_failed "this aggregator could not sign a job with its fleet-trust key"; }

  # The request body, on curl's STDIN. `--data-binary @-` is what keeps the
  # key off the command line; `-o` and `-w` split the body from the status so
  # the node's own refusal can be reported as the node's refusal; and no
  # redirect is followed, because a redirect here is an older node sending a
  # key to its login page.
  PUSH_BODY="$WORK/push-answer.json"
  PUSH_CODE="$(printf '%s\n%s\n%s' "$SIGNATURE" "$(cat "$JOB_FILE")" "$PUSH_PLAIN" | python3 -c '
import json, sys
sig, job, plain = sys.stdin.read().split("\n", 2)
sys.stdout.write(json.dumps({
    "job": json.loads(job), "signature": sig, "key": json.loads(plain)["key"],
}))
' | curl -sS --max-time 270 --no-location --max-filesize 65536 --config "$PUSH_CURL_CFG" \
      -o "$PUSH_BODY" -w '%{http_code}' -H 'content-type: application/json' \
      --data-binary @- "$PUSH_ORIGIN/fleet/v1/model/seal" 2>/dev/null || true)"
  PUSH_PLAIN=""; unset PUSH_PLAIN

  if [[ -z "$PUSH_CODE" || "$PUSH_CODE" == "000" ]]; then
    fact pushed 0; fact state unreachable; fact reason no_answer
    fact detail "\"$PUSH_LABEL\" did not answer in time. Its own sealer may still be finishing; check its Advisor."
    out "\"$PUSH_LABEL\" did not answer."
    finish 0
  fi
  # The node's own answer, read as facts. Refused, unreachable and sealed
  # stay three states here exactly as they are in lib/fleet-seal.ts: the
  # operator's next action differs, and collapsing them into "failed" is what
  # loses that.
  # Three values, three LINES, read one per variable (security review,
  # finding F7). Read off one whitespace-split line, a node answering
  # `{"error": "x 1"}` wrote this program's own `model_configured` field for
  # it: a value from the far side deciding a fact about what happened here.
  # Each line is its own field, and `read -r` on separate lines cannot be
  # made to spill one into the next. Shapes are enforced below, not here,
  # because a node that answers nonsense must still be reported as a node
  # that answered nonsense.
  PUSH_FACTS="$WORK/push-facts"
  python3 - "$PUSH_BODY" "$PUSH_CODE" > "$PUSH_FACTS" <<'PY'
import json, re, sys
path, code = sys.argv[1], sys.argv[2]
SAFE = re.compile(r"[^A-Za-z0-9._:-]")
try:
    b = json.load(open(path))
except Exception:
    b = None
def say(state, reason, configured):
    # Sanitised HERE, once, on the one value that comes off the far side. A
    # reason is a short token in this protocol and anything else is not one.
    sys.stdout.write("%s\n%s\n%s\n" % (state, SAFE.sub("", str(reason))[:48] or "unnamed", configured))
if not isinstance(b, dict):
    # 404 and 302 are what a build older than the fleet write API answers.
    if code in ("404", "302"):
        say("refused", "no_fleet_write_surface", "-")
    else:
        say("unreachable", "bad_answer", "-")
    raise SystemExit(0)
if code == "200" and b.get("ok"):
    mc = b.get("model_configured")
    say("sealed", b.get("reason") or "sealed", "-" if mc is None else ("1" if mc else "0"))
else:
    say("refused", b.get("error") or b.get("reason") or ("http_" + code), "-")
PY
  IFS= read -r PUSH_STATE < "$PUSH_FACTS" || PUSH_STATE=""
  PUSH_REASON="$(sed -n 2p "$PUSH_FACTS")"
  PUSH_CONFIGURED="$(sed -n 3p "$PUSH_FACTS")"
  PUSH_DETAIL="$(python3 -c '
import json, sys
try:
    b = json.load(open(sys.argv[1]))
except Exception:
    b = {}
d = b.get("detail") if isinstance(b, dict) else ""
# Bounded, and on one line. This is the sentence the far side wrote and it is
# rendered on a page: a node answering with a megabyte of prose would put it
# through the answer this program writes, the socket, and a dashboard in
# memory (security review, finding F5).
sys.stdout.write(" ".join(str(d or "").split())[:400])
' "$PUSH_BODY" || true)"
  # Read back as one of the three states this program has, never as whatever
  # the far side wrote. Same discipline as lib/fleet-broker.ts's reader.
  case "$PUSH_STATE" in
    sealed|refused|unreachable) ;;
    *) PUSH_STATE=unreachable ;;
  esac
  case "$PUSH_CONFIGURED" in 0|1|-) ;; *) PUSH_CONFIGURED="-" ;; esac
  fact pushed "$([[ "$PUSH_STATE" == sealed ]] && printf 1 || printf 0)"
  fact state "$PUSH_STATE"
  fact reason "$PUSH_REASON"
  fact model_configured "$PUSH_CONFIGURED"
  fact detail "${PUSH_DETAIL:-that node answered $PUSH_CODE.}"
  if [[ "$PUSH_STATE" == sealed ]]; then
    out "\"$PUSH_LABEL\" is on the fleet model."
  else
    out "\"$PUSH_LABEL\" did not take the fleet model."
  fi
  finish 0
fi

# ── arm-key (#741) ───────────────────────────────────────────────────────
# The PUBLIC half of this aggregator's fleet arm key, made first when there is
# none and this host never had one (no fleet-arm.made) and has no paired
# node. Asked by the dashboard a moment
# before it sends a node the signed welcome: the welcome carries this key,
# and the pairing fingerprint the operator pastes at the node covers it
# together with the fleet trust key.
#
# Where the key was lost it makes nothing and refuses as fleet_arm_key_lost,
# naming the nodes, the restore command and the grant's --new-fleet-keys
# (#851). That flag is on root's argv and nowhere else.
#
# What this hands the dashboard account is a public key it would receive from
# `approve` anyway, one call later. It is not trusted for being here: the
# operator's paste against root's own output (aperire-fleet-arm.sh
# --fingerprint) is what decides whether the key a node takes is this one.
# No payload fields; anything after the verb is ignored rather than read.
if [[ "$VERB" == "arm-key" ]]; then
  if [[ -L "$FLEET_ARM_PROGRAM" || ! -f "$FLEET_ARM_PROGRAM" || ! -O "$FLEET_ARM_PROGRAM" ]]; then
    refuse no_fingerprint_command "$FLEET_ARM_PROGRAM is not installed here, and it is the one command that prints the pairing fingerprint the node will ask for. Install it with the broker grant: curl -fsSL https://get.aperire.one | bash -s -- --run fleet-broker-grant"
  fi
  # #964: the approval this key is for reads its registries back with node.
  # Asked before the key is made, so a host that could never finish a
  # pairing makes nothing, mints no code, and says which command fixes it.
  reader_node_or_refuse
  resolve_fleet_arm_pub make
  fact fleet_arm_pubkey "${ARM_PUB:--}"
  fact fleet_arm_key "$ARM_KEY_STATE"
  # The marker that says this host has had a key could not be made (#853
  # review): a fact, never a refusal. Without it a key lost later is judged
  # by the fleet's records alone.
  if (( FLEET_ARM_MARK_FAILED )); then fact fleet_arm_marker failed; fi
  if [[ "$ARM_KEY_STATE" == lost ]]; then
    [[ -n "$ARM_KEY_PAIRED" ]] && fact fleet_arm_key_paired "$ARM_KEY_PAIRED"
    refuse fleet_arm_key_lost "$(arm_key_lost_sentence)"
  fi
  if [[ -z "$ARM_PUB" ]]; then
    refuse no_fleet_arm_key "this aggregator has no usable fleet arm key ($ARM_KEY_STATE), so a node has nothing to compare its pairing fingerprint against. Run sudo aperire-fleet-arm --fingerprint on this host to see why."
  fi
  out "this aggregator's fleet arm key is ready to hand to a node."
  finish 0
fi

# ── arm-key-check (pairing v2, #846 review L5) ───────────────────────────
# Is this host ready to hand a node its arm key, asked WITHOUT making one.
# The Settings page's pairing check asks this before an operator is sent to
# print the fingerprint. `arm-key` would make a key that is missing, and on
# a fleet whose key was lost (a restore from a set that carried none) that
# silently orphans every paired node the moment someone opens Add a node. So
# this verb only looks: making the key stays with an approval and with the
# grant's installer, where the operator is told what a new key costs.
#
# It answers fleet_arm_key=present|missing|lost|unsafe and nothing else: no
# public key, no file name the caller chose. With a key there and no node to
# read registries back with, it refuses no_node instead of present (#964). `lost` is a missing key on a
# host that had one or has paired nodes (#851), which `arm-key` refuses to
# make, so the
# page says so before anyone walks to a node, with the restore command
# rather than the grant install. install_moved is the anchor check above,
# which every verb meets first. No payload fields.
if [[ "$VERB" == "arm-key-check" ]]; then
  if [[ -L "$FLEET_ARM_PROGRAM" || ! -f "$FLEET_ARM_PROGRAM" || ! -O "$FLEET_ARM_PROGRAM" ]]; then
    refuse no_fingerprint_command "$FLEET_ARM_PROGRAM is not installed here, and it is the one command that prints the pairing fingerprint the node will ask for. Install it with the broker grant: curl -fsSL https://get.aperire.one | bash -s -- --dir $INSTALL_DIR --run fleet-broker-grant"
  fi
  if ! [[ -L "$ARM_KEY" || -e "$ARM_KEY" ]]; then
    if arm_key_lost; then
      fact fleet_arm_key lost
      [[ -n "$ARM_KEY_PAIRED" ]] && fact fleet_arm_key_paired "$ARM_KEY_PAIRED"
      refuse fleet_arm_key_lost "$(arm_key_lost_sentence)"
    fi
    fact fleet_arm_key missing
    refuse no_fleet_arm_key "this aggregator has no fleet arm key, so there is no pairing fingerprint to print. The pairing grant makes it: curl -fsSL https://get.aperire.one | bash -s -- --dir $INSTALL_DIR --run fleet-broker-grant"
  fi
  # The same rule resolve_fleet_arm_pub holds the key to before it hands
  # anything over, without the make that function starts with.
  if [[ -L "$ARM_KEY" || ! -f "$ARM_KEY" || ! -O "$ARM_KEY" ]] \
    || (( (8#$(stat -c '%a' "$ARM_KEY" 2>/dev/null || echo 777) & 8#077) != 0 )) \
    || [[ "$(stat -c '%h' "$ARM_KEY" 2>/dev/null)" != 1 ]] \
    || (( $(openssl pkey -in "$ARM_KEY" -pubout -outform DER 2>/dev/null | wc -c) < 32 )); then
    fact fleet_arm_key unsafe
    refuse no_fleet_arm_key "this aggregator's fleet arm key is not a plain, root-only Ed25519 key, so it is not one a node may be handed. Run sudo aperire-fleet-arm --fingerprint on this host to see why."
  fi
  # #964: the node the approval will need, asked here so Settings says so
  # before anyone walks to a node, rather than after the passkey. After the
  # key checks, so a lost key still leads with the restore (#851).
  reader_node_or_refuse
  fact fleet_arm_key present
  out "this aggregator has a fleet arm key to hand a node."
  finish 0
fi

[[ "$VERB" == "approve" ]] || refuse unknown_verb "this program has no verb called \"${VERB:0:24}\""

# ── approve: what the caller said ────────────────────────────────────────
LABEL="${P[label]:-}"
LABEL_FOR_LOG="$LABEL"
PUBKEY="${P[pubkey_node]:-}"
DASH_URL="${P[dashboard_url]:-}"
ROLE="${P[role]:-}"
ADVISOR="${P[advisor]:-0}"
CRED_SHA="${P[credential_sha256]:-}"
READ_TOKEN="${P[read_token]:-}"
ADVISOR_TOKEN="${P[advisor_token]:-}"
# #620: the dashboard's own passkey approval for a node the fleet already
# watches over a tunnel. Never trusted alone -- it only says which of the two
# refusals below to skip; the row it names is re-derived from fleet.yaml and
# the presented key a few lines down, never taken from this flag or LABEL.
CONVERT_TUNNEL="${P[convert_tunnel]:-0}"

[[ "$LABEL" =~ $LABEL_RE ]] || refuse bad_label "a label is lower-case letters, digits and dashes, up to 32 of them, the same rule fleet.yaml uses"
[[ "$PUBKEY" =~ $NODE_KEY_RE ]] || refuse bad_pubkey "that is not a node key shape the fleet can pin, and a row with no usable pin cannot be sealed"
# Optional (#339). A node whose public_url is still the shipped default
# does not know an address anybody else can open, and says nothing rather
# than deriving one from its own host name: the row is then written with no
# dashboard_url line, which fleet.yaml's parser takes as "not set". A value
# that IS given still has to be a dashboard address, and the two refusals
# below are unchanged for it.
if [[ -n "$DASH_URL" ]]; then
  case "$DASH_URL" in
    https://*|http://*) : ;;
    *) refuse bad_url "a dashboard address is http:// or https://" ;;
  esac
  case "$DASH_URL" in
    *[[:space:]]*|*\"*|*\'*) refuse bad_url "that dashboard address carries characters a registry row cannot hold" ;;
  esac
fi
[[ "$ROLE" == "node" ]] || refuse bad_role "this program registers a node, and nothing else"
[[ "$ADVISOR" == "0" || "$ADVISOR" == "1" ]] || refuse bad_payload "advisor is 0 or 1"
[[ "$CRED_SHA" =~ ^[0-9a-f]{64}$ ]] || refuse bad_credential "a credential hash is 64 lower-case hex characters"
[[ -n "$READ_TOKEN" ]] || refuse no_token "that node sent no read token, so there is nothing for this aggregator to read it with"
if [[ "$ADVISOR" == "1" ]]; then
  [[ -n "$ADVISOR_TOKEN" ]] || refuse no_token "that node says it runs an Advisor and sent no Advisor token"
  (( ${#ADVISOR_TOKEN} <= FLEET_PAIR_MAX_TOKEN_CHARS )) \
    || refuse bad_token "that node's Advisor token is longer than any bearer token this fleet writes"
fi
[[ "$CONVERT_TUNNEL" == "0" || "$CONVERT_TUNNEL" == "1" ]] || refuse bad_payload "convert_tunnel is 0 or 1"

# #741 review, L2: the fleet arm key the signed welcome carried, which the
# operator's pasted fingerprint covered. Compared with the key on disk HERE,
# before anything is read for writing or written: a key that changed since the
# approval (a restore, a rotation by rm) would otherwise be discovered by the
# hub only after this program had appended the row and written the node's
# token file, leaving a registration the node refuses to finish. Read-only:
# nothing is made here. Optional on the wire, so the refusal is a property of
# what the dashboard sends; the dashboard always sends it (settings-api.ts).
EXPECT_ARM="${P[fleet_arm_pubkey]:-}"
if [[ -n "$EXPECT_ARM" ]]; then
  [[ "$EXPECT_ARM" =~ ^[A-Za-z0-9+/]{43}=$ ]] \
    || refuse bad_payload "fleet_arm_pubkey is not the plain base64 of a 32-byte key"
  NOW_ARM=""
  if ! [[ -L "$ARM_KEY" || ! -f "$ARM_KEY" || ! -O "$ARM_KEY" ]] && command -v openssl >/dev/null 2>&1; then
    NOW_ARM="$(openssl pkey -in "$ARM_KEY" -pubout -outform DER 2>/dev/null | tail -c 32 | base64 -w0 || true)"
  fi
  [[ -n "$NOW_ARM" && "$NOW_ARM" == "$EXPECT_ARM" ]] \
    || refuse arm_key_changed "this aggregator's fleet arm key is not the one the node was shown at the approval, so the fingerprint that was pasted does not cover it. Nothing was written. Pair the node again with a fresh code."
fi

# Every path this writes, derived from the LABEL inside one fixed directory.
# Nothing in the payload can name a path.
TOKEN_PATH="$TOKEN_DIR/$LABEL.token"
ADVISOR_TOKEN_PATH="$TOKEN_DIR/$LABEL.approve.token"

# ── what the three registries already say ────────────────────────────────
# One read, three files, and it fails the whole run closed on any of them:
# this program is about to append to files whose parsers fail closed, so a
# file it cannot read is a file it must not touch. Each is taken once here,
# by descriptor (snap_fleet_yaml/snap_fleet_links/snap_adv_fleet, #648 round
# 4), and every later step in this verb -- the convert plan, the duplicate-
# pin check, the three candidate builds, the excision cross-checks -- reads
# that same snapshot rather than the live file a second time.
snap_fleet_yaml
snap_fleet_links
snap_adv_fleet
PLAN="$WORK/plan.json"
if ! python3 - "$SNAP_FLEET_YAML" "$SNAP_FLEET_LINKS" "$SNAP_ADV_FLEET" "$LABEL" "$PUBKEY" "$PLAN" <<'PY' 2>"$WORK/plan.err"
import json, os, sys
try:
    import yaml
except ImportError:
    sys.stderr.write("python3 has no yaml module, and fleet.yaml is yaml\n")
    raise SystemExit(3)

fleet_path, links_path, adv_path, label, pubkey, out_path = sys.argv[1:7]
used = set()
plan = {"rejoin": False, "row": None}

rows = []
if os.path.exists(fleet_path):
    with open(fleet_path) as f:
        doc = yaml.safe_load(f.read())
    if doc is None:
        doc = {}
    if not isinstance(doc, dict) or not isinstance(doc.get("fleet", []), list):
        sys.stderr.write("fleet.yaml is not a mapping with a fleet: list\n")
        raise SystemExit(3)
    rows = doc.get("fleet") or []

def port_of(origin):
    if not isinstance(origin, str):
        return None
    try:
        from urllib.parse import urlparse
        p = urlparse(origin).port
        return int(p) if p else None
    except ValueError:
        return None

for r in rows:
    if not isinstance(r, dict):
        sys.stderr.write("fleet.yaml has an entry that is not a mapping\n")
        raise SystemExit(3)
    for key in ("read_origin", "advisor_origin"):
        p = port_of(r.get(key))
        if p:
            used.add(p)
    if r.get("label") == label:
        plan["row"] = {
            "pin": r.get("expected_pubkey_node"),
            "transport": r.get("transport"),
            "read_port": port_of(r.get("read_origin")),
            "advisor_port": port_of(r.get("advisor_origin")),
            "role": r.get("role"),
            # What a rejoin that lowers the Advisor attachment (#1079) writes
            # the row back from, taken from the snapshot this plan was made
            # from: one read, so what is decided and what is written agree.
            "dashboard_url": r.get("dashboard_url"),
            "read_origin": r.get("read_origin"),
            "token_path": r.get("token_path"),
            "advisor_token_path": r.get("advisor_token_path"),
            "extra_keys": sorted(set(r.keys()) - {
                "label", "role", "dashboard_url", "read_origin", "token_path",
                "expected_pubkey_node", "transport", "advisor_origin",
                "advisor_token_path"}),
        }

# How many rows there are NOW. Plan §3.5 step 5's assertion is "the previous
# count plus one", and without it a candidate that had dropped an unrelated
# row would pass every other check: both parsers would be happy, the new
# label would be present, and the cross-check only compares the rows that
# are there (P3-062).
plan["fleet_rows"] = len(rows)
plan["link_rows"] = 0
# Whether this label ALREADY has a link row: a rejoin replaces it, so the
# count is unchanged, and a first approval adds one.
plan["link_has_label"] = False

if os.path.exists(links_path):
    with open(links_path) as f:
        doc = json.load(f)
    plan["link_rows"] = len(doc.get("links") or [])
    plan["link_has_label"] = any(
        isinstance(r, dict) and r.get("label") == label for r in (doc.get("links") or [])
    )
    for r in (doc.get("links") or []):
        if not isinstance(r, dict):
            sys.stderr.write("fleet-links.json has an entry that is not an object\n")
            raise SystemExit(3)
        for key in ("read_port", "advisor_port"):
            if isinstance(r.get(key), int):
                used.add(r[key])

# The Advisor's own registry names ports too, now that this program writes
# it: three registries, not two, or a pool could hand out a port the
# aggregator's Advisor already reaches another node on.
if os.path.exists(adv_path):
    with open(adv_path) as f:
        doc = json.load(f)
    peers = doc if isinstance(doc, list) else (doc.get("peers") or [])
    for r in peers:
        if isinstance(r, dict):
            p = port_of(r.get("origin"))
            if p:
                used.add(p)

with open(out_path, "w") as f:
    json.dump({"used": sorted(used), **plan}, f)
PY
then
  cat "$WORK/plan.err" >&2 || true
  refuse unreadable_registry "one of this host's registries could not be read, so nothing was appended to any of them: $(tr -d '\n' < "$WORK/plan.err")"
fi

# This host's own dashboard, read once (#1045): the port the dashboard finds
# its own fleet.yaml row by, the role its install recorded and its read
# token path, or why none of that can be known.
SELF_FACT_PORT="" SELF_FACT_ROLE="" SELF_FACT_TOKEN="" SELF_FACT_UNKNOWN=""
SELF_FACTS="$(fleet_self_facts "$UNIT_DIR" "$WORK" 2>/dev/null || true)"
SELF_FACT_PORT="$(sed -n 's/^port //p' <<<"$SELF_FACTS")"
SELF_FACT_ROLE="$(sed -n 's/^role //p' <<<"$SELF_FACTS")"
SELF_FACT_TOKEN="$(sed -n 's/^token //p' <<<"$SELF_FACTS")"
SELF_FACT_UNKNOWN="$(sed -n 's/^unknown //p' <<<"$SELF_FACTS")"
[[ -n "$SELF_FACT_PORT$SELF_FACT_UNKNOWN" ]] || SELF_FACT_UNKNOWN="this host's dashboard unit could not be read"

REJOIN=0
REJOIN_ROOT_PIN="" REJOIN_ROOT_PORT=""
CONVERT=0
EXISTING_PIN="$(python3 -c 'import json,sys;d=json.load(open(sys.argv[1]));r=d["row"];print((r or {}).get("pin") or "")' "$PLAN")"
EXISTING_TRANSPORT="$(python3 -c 'import json,sys;d=json.load(open(sys.argv[1]));r=d["row"];print((r or {}).get("transport") or "")' "$PLAN")"
# The row's own role, so a rejoin rebuilds the Advisor's own registry peer
# with the same role fleet.yaml already carries instead of silently
# flattening a validator or relay row back to node the next time it dials
# in after a convert kept it (#620 review).
EXISTING_ROLE="$(python3 -c 'import json,sys;d=json.load(open(sys.argv[1]));r=d["row"];print((r or {}).get("role") or "")' "$PLAN")"
# Whether the row ALREADY carries an Advisor, read off fleet.yaml itself
# rather than off anything the node just sent: this is the REJOIN fix's own
# fallback, used only when root's own record (below) has no line yet for
# this label.
EXISTING_ADVISOR_PORT="$(python3 -c 'import json,sys;d=json.load(open(sys.argv[1]));r=d["row"];print((r or {}).get("advisor_port") or "")' "$PLAN")"
# Whether fleet-links.json ALSO currently names this label. revoke prunes
# both its own row here and root's own nodes.conf line, but leaves
# fleet.yaml's advisor_origin standing (revoke's own scope; the row itself
# is an operator's decision, untouched). A label the fleet's live-link
# registry no longer recognizes is not a label whose fleet.yaml leftovers
# should be trusted as "still live" by the fallback below.
LINK_HAS_LABEL="$(python3 -c 'import json,sys;print("1" if json.load(open(sys.argv[1]))["link_has_label"] else "0")' "$PLAN")"
HAVE_ROW="$(python3 -c 'import json,sys;d=json.load(open(sys.argv[1]));print("1" if d["row"] else "0")' "$PLAN")"
if [[ "$HAVE_ROW" == "1" ]]; then
  if [[ "$EXISTING_TRANSPORT" == "link" ]]; then
    if [[ "$EXISTING_PIN" != "$PUBKEY" ]]; then
      refuse label_taken "$FLEET_YAML already has a row called \"$LABEL\" pinned to a different node key. Pick another label, or remove that row by hand first."
    fi
    REJOIN=1
    # #866 review, M2: a rejoin is anchored on ROOT'S record, never on
    # fleet.yaml alone, the same rule convert follows below. fleet.yaml is a
    # file the dashboard account can rewrite (and `repin` rewrites its pin
    # on request), so a pin that matched only there would let repin-then-
    # rejoin move where a model key may be sent with no root step at all.
    # Root's line, when there is one, must hold this same key, and its read
    # port is the one this rejoin keeps (checked against fleet.yaml's below).
    REJOIN_ROOT_PIN="" REJOIN_ROOT_PORT=""
    if [[ -f "$NODES_CONF" ]]; then
      while IFS= read -r ncline || [[ -n "$ncline" ]]; do
        case "$ncline" in ''|'#'*) continue ;; esac
        read -r nclabel ncpin ncport _ <<<"$ncline"
        if [[ "$nclabel" == "$LABEL" ]]; then REJOIN_ROOT_PIN="$ncpin"; REJOIN_ROOT_PORT="$ncport"; break; fi
      done < "$NODES_CONF"
    fi
    # No line in root's record is not a rejoin root can anchor. It is what a
    # revoke that answered registry_left leaves (the fleet.yaml link row
    # stayed, root's line went), or a row --refresh-nodes never reached.
    # Neither has a port this program may take from fleet.yaml (#866
    # re-review, note 2), so it is refused with the two ways out, rather than
    # rewriting a row a rejoin never writes.
    if [[ -z "$REJOIN_ROOT_PIN" ]]; then
      # #870 review, L3: --refresh-nodes rebuilds root's record from
      # fleet.yaml, so offering it for a revoked label (no link row left)
      # would re-vouch the node the revoke just removed.
      if [[ "$LINK_HAS_LABEL" == "1" ]]; then
        refuse rejoin_unanchored "$FLEET_YAML has a link row called \"$LABEL\" and so does $FLEET_LINKS, but this host's own record has no line for it, so this cannot be taken as a rejoin. If it is a live member root's record never reached, run curl -fsSL https://get.aperire.one | bash -s -- --dir $INSTALL_DIR --run fleet-broker-grant --refresh-nodes, then pair again. If that node was revoked, press Revoke on its row again instead."
      fi
      refuse rejoin_unanchored "$FLEET_YAML still has a row called \"$LABEL\", and this host's own record and its link registry have none, which is what a revoke that could not take the registry row out leaves. Press Revoke on its row again to finish taking it out, then pair it again."
    fi
    if [[ "$REJOIN_ROOT_PIN" != "$PUBKEY" ]]; then
      refuse root_pin_disagrees "this host's own record pins \"$LABEL\" to $REJOIN_ROOT_PIN, and the node calling in now presented $PUBKEY, so this rejoin is refused. If that node's key genuinely changed, bring root's record up to date first: curl -fsSL https://get.aperire.one | bash -s -- --dir $INSTALL_DIR --run fleet-broker-grant --refresh-nodes, which prints the old and new key for every row it changes before it writes anything. Compare the new one with that node's own server_info pubkey_node, then pair again."
    fi
  elif [[ "$CONVERT_TUNNEL" == "1" ]]; then
    # #620: the row this label names is re-derived here, never taken from
    # LABEL or the flag alone -- exactly one fleet.yaml row may pin PUBKEY,
    # it must be this same label, it must not already say transport: link,
    # and it must not be this aggregator's own row (never converted). A
    # peer row with NO role line at all is the common shape #620 was filed
    # against, and is a node exactly as fleet-registry.ts's own parser and
    # classifyPairKey both already read it; refusing that shape here would
    # be #620's own bug again, one step later. A dashboard that lied about
    # which row this is gets refused below, by what fleet.yaml actually
    # says rather than by what it was told.
    CONVERT_PLAN="$(python3 - "$SNAP_FLEET_YAML" "$PUBKEY" <<'PY'
import sys
try:
    import yaml
except ImportError:
    raise SystemExit(0)
path, pubkey = sys.argv[1:3]
with open(path) as f:
    doc = yaml.safe_load(f.read()) or {}
rows = [r for r in (doc.get("fleet") or [])
        if isinstance(r, dict) and r.get("expected_pubkey_node") == pubkey]
if len(rows) == 1:
    r = rows[0]
    # \x1f (ASCII unit separator), never a tab and never a pipe: IFS made of
    # nothing but whitespace characters squeezes consecutive delimiters and
    # strips them at the ends, which loses exactly the empty TRANSPORT field
    # a tunnel row has (measured); a dashboard_url is a value a NODE'S OWN
    # operator chose by hand and is not this program's to assume never holds
    # the one ASCII character it picked for its own payload encoding either.
    sys.stdout.write('\x1f'.join([
        str(r.get("label") or ""), str(r.get("transport") or ""), str(r.get("role") or ""),
        str(r.get("dashboard_url") or ""),
    ]))
PY
)"
    IFS=$'\x1f' read -r CONVERT_LABEL CONVERT_TRANSPORT CONVERT_ROLE CONVERT_DASH_URL <<<"$CONVERT_PLAN"
    if [[ "$CONVERT_LABEL" == "$LABEL" && "$CONVERT_TRANSPORT" != "link" && "$CONVERT_ROLE" != "aggregator" ]]; then
      # fleet.yaml is the DASHBOARD account's own file: everything above this
      # line trusts it for the ordinary reason this whole program trusts it,
      # that a compromised dashboard calling approve gets one more node of
      # its choosing and nothing else. A convert is different, because the
      # label it names may already be one root itself has vouched for: root's
      # OWN record (fleet-nodes.conf), never the dashboard's, is what anchors
      # that. No row there for this label is the ordinary first-trust case,
      # same as any fresh approval. A row THAT DISAGREES is refused, because
      # a dashboard that first rewrote fleet.yaml's pin and then converted
      # under the same label would otherwise move an EXISTING node's push
      # destination in root's own record by editing a file that account
      # already owns, which is exactly the escalation this record exists to
      # rule out (#620's own security review).
      EXISTING_NODES_PIN=""
      if [[ -f "$NODES_CONF" ]]; then
        while IFS= read -r ncline || [[ -n "$ncline" ]]; do
          case "$ncline" in ''|'#'*) continue ;; esac
          read -r nclabel ncpin _ <<<"$ncline"
          if [[ "$nclabel" == "$LABEL" ]]; then EXISTING_NODES_PIN="$ncpin"; break; fi
        done < "$NODES_CONF"
      fi
      if [[ -n "$EXISTING_NODES_PIN" && "$EXISTING_NODES_PIN" != "$PUBKEY" ]]; then
        refuse root_pin_disagrees "this host's own record already pins \"$LABEL\" to $EXISTING_NODES_PIN, and the node calling in now presented $PUBKEY, so converting it is refused. If that node's key genuinely changed, bring root's record up to date first: curl -fsSL https://get.aperire.one | bash -s -- --dir $INSTALL_DIR --run fleet-broker-grant --refresh-nodes, which prints the old and new key for every row it changes before it writes anything, then pair again."
      fi
      CONVERT=1
    else
      refuse convert_mismatch "the node key this pairing presented is not pinned to exactly one row called \"$LABEL\" that is not already a link row, so converting it is refused. Compare the node key against the row you meant, and pair again."
    fi
  else
    # This host's own row (#1045): by its role, or by the port the dashboard
    # finds itself on. No node pairs under the aggregator's own name.
    # Loopback AND this port, the rule fleet_paired_records and the dashboard
    # use: a hand-written remote row on the same port number is not this host.
    EXISTING_SELF_PORT="$(python3 -I - "$SNAP_FLEET_YAML" "$LABEL" <<'PY' 2>/dev/null || true
import sys
from urllib.parse import urlparse
import yaml
path, label = sys.argv[1:3]
doc = yaml.safe_load(open(path).read()) or {}
for r in doc.get("fleet") or []:
    if isinstance(r, dict) and r.get("label") == label and isinstance(r.get("read_origin"), str):
        u = urlparse(r["read_origin"])
        if (u.hostname or "").lower() in ("127.0.0.1", "localhost", "::1") and u.port:
            print(u.port)
        break
PY
)"
    if [[ "$EXISTING_ROLE" == "aggregator" || ( -n "$SELF_FACT_PORT" && "$EXISTING_SELF_PORT" == "$SELF_FACT_PORT" ) ]]; then
      refuse label_is_this_host "\"$LABEL\" is the name of this aggregator's own row in $FLEET_YAML, so no node may pair under it. Pair that node again under another name."
    fi
    refuse label_not_a_link "$FLEET_YAML already has a row called \"$LABEL\" and it does not say transport: link, so it is reached another way. Converting a tunnel row to a link row is a decision made once, with a passkey, on the Pending row that names it as already in the fleet. It is never an ordinary approval's to make on its own. Approve it there, pick another label, or change that row by hand first."
  fi
fi

# #870 review, M2: a FRESH approval (not a rejoin, not a convert) never
# replaces a line root's own record already holds. fleet.yaml is the
# dashboard account's file, so a row missing there proves nothing: that
# account could delete it and approve the same label under a key and port of
# its choosing, moving where a model key may be sent with no root step. The
# operator revokes the label first (which clears root's line), then pairs.
if [[ "$REJOIN" == "0" && "$CONVERT" == "0" && -f "$NODES_CONF" ]]; then
  while IFS= read -r ncline || [[ -n "$ncline" ]]; do
    case "$ncline" in ''|'#'*) continue ;; esac
    read -r nclabel _ <<<"$ncline"
    if [[ "$nclabel" == "$LABEL" ]]; then
      # #870 re-review, N1: with no fleet.yaml row the page shows no row to
      # press Revoke on. --refresh-nodes rebuilds root's record from
      # fleet.yaml rows only, so it drops this line, and it prints what it
      # changes before it writes. A fresh approve reaches here only with no
      # row (a row is a rejoin, a convert, or refused above), so the second
      # branch is the defensive one.
      if [[ "$HAVE_ROW" == "0" ]]; then
        refuse root_holds_label "this host's own record already holds \"$LABEL\", although $FLEET_YAML has no row for it, so pairing it fresh is refused. Clear root's line with curl -fsSL https://get.aperire.one | bash -s -- --dir $INSTALL_DIR --run fleet-broker-grant --refresh-nodes (it rebuilds that record from $FLEET_YAML, where the row is gone, and prints what it changes), then pair again."
      fi
      refuse root_holds_label "this host's own record already holds \"$LABEL\", so pairing it fresh is refused. Press Revoke on its row first (root's record is cleared there), then pair again."
    fi
  done < "$NODES_CONF"
fi

# What the written row's own role and address are. A fresh approval and a
# rejoin write exactly what the payload said (ROLE is always "node", the
# only role a node ever presents itself as); a convert keeps the EXISTING
# row's role (node, validator or relay -- anything else, including no role
# line at all, is a node, the same reading classifyPairKey and
# fleet-registry.ts's own parser already give it) and its dashboard_url,
# because #620's row conversion is meant to change transport and nothing
# a hand-set fact about the node itself.
if [[ "$CONVERT" == "1" ]]; then
  case "$CONVERT_ROLE" in
    node|validator|relay) EMIT_ROLE="$CONVERT_ROLE" ;;
    *) EMIT_ROLE="node" ;;
  esac
  # The hello's own value wins when the node sent one (#339); otherwise the
  # row's own existing address survives the convert, run through the same
  # two checks an approval's own dashboard_url gets. A row's address that
  # fails them is dropped rather than refusing the whole convert over a
  # value nobody just typed.
  if [[ -n "$DASH_URL" ]]; then
    EMIT_DASH_URL="$DASH_URL"
  else
    EMIT_DASH_URL=""
    case "$CONVERT_DASH_URL" in
      https://*|http://*)
        case "$CONVERT_DASH_URL" in
          *[[:space:]]*|*\"*|*\'*) : ;;
          *) EMIT_DASH_URL="$CONVERT_DASH_URL" ;;
        esac
        ;;
    esac
  fi
elif [[ "$REJOIN" == "1" ]]; then
  # fleet.yaml is untouched on a rejoin, but the Advisor candidate below is
  # rebuilt unconditionally: it has to carry the same role fleet.yaml
  # already does, or a rejoin after a convert kept a validator or relay
  # row would flatten just the Advisor's OWN copy of it back to node,
  # leaving the two registries disagreeing about a role neither wrote.
  case "$EXISTING_ROLE" in
    node|validator|relay) EMIT_ROLE="$EXISTING_ROLE" ;;
    *) EMIT_ROLE="node" ;;
  esac
  EMIT_DASH_URL="$DASH_URL"
else
  EMIT_ROLE="$ROLE"
  EMIT_DASH_URL="$DASH_URL"
fi

# ── the advisor bit this run actually acts on ────────────────────────────
# A rejoin's hello carries the NODE's own "advisor" claim, and before this
# fix that claim went straight into root's own fleet-nodes.conf (the one
# file model-push resolves a label in) and, when it said 1, straight into a
# fresh advisor/state/fleet-tokens/<label>.approve.token as well, both
# regardless of whether fleet.yaml's row (untouched on a rejoin) had ever
# been given an Advisor at all. A node that lied on rejoin could grant
# itself model-push eligibility with no row to show for it. #641's
# attach-advisor and detach-advisor are the only verbs that may RAISE a link
# row's advisor state, and a rejoin carries the EXISTING state forward, the
# same way it already does for role. The one thing a hello may do is LOWER it
# (#1079, below): when it says there is no Advisor, or brings a token other
# than the one this aggregator holds. That is not the harm the carry-forward
# prevents. Lowering only detaches, it is said in the answer and on the
# pairing row, and the operator attaches again under a passkey.
#
# EXISTING state means BOTH registries agree, not either alone: root's own
# record (never fleet.yaml, which the dashboard account owns, and which is
# what a push actually resolves a label in) says 1 AND fleet.yaml's row
# names an advisor_origin. Requiring both, rather than trusting root's
# field alone, is what lets this heal a label the pre-fix bug already
# flipped to 1 with no fleet.yaml row to back it.
#
# Root having NO LINE AT ALL for this label is not the same fact as root
# saying 0, and trusting fleet.yaml alone in that case is exactly the gap a
# security review named: revoke prunes root's own line (and fleet-links.json's
# row) but, by its own documented scope, leaves fleet.yaml's advisor_origin
# standing. Before this correction, an absent root line fell back to
# fleet.yaml alone, which COULD raise the effective value against what root's
# own (absent) line said: attach an Advisor, revoke the node, then let it
# reconnect with an honest hello claiming no Advisor at all -- the absent
# root line resolved to fleet.yaml's stale advisor_origin, field 4 came back
# as 1 with no attach-advisor call and no passkey anywhere in the path. The
# fix asks a second, independent question of that absent-line case: does
# fleet-links.json, the fleet's own live-link registry, ALSO currently name
# this label? revoke prunes that row too, in the same call, so a label
# revoke has touched answers no there, and the fallback now resolves to 0
# rather than to whatever fleet.yaml still says. A label root has simply
# never had a line for yet (a fleet paired before phase 4, or a row
# --refresh-nodes has not reached) still answers yes there, since revoke
# never ran against it, and the fallback carries fleet.yaml's own state
# forward exactly as before. The hello's own claim is consulted nowhere in
# this branch, on any of its paths.
if [[ "$REJOIN" == "1" ]]; then
  ROOT_ROW_ADVISOR=""
  if [[ -f "$NODES_CONF" ]]; then
    while IFS= read -r ncline || [[ -n "$ncline" ]]; do
      case "$ncline" in ''|'#'*) continue ;; esac
      read -r nclabel _ _ ncadv _ <<<"$ncline"
      if [[ "$nclabel" == "$LABEL" ]]; then ROOT_ROW_ADVISOR="$ncadv"; break; fi
    done < "$NODES_CONF"
  fi
  FLEET_YAML_HAS_ADVISOR="$([[ -n "$EXISTING_ADVISOR_PORT" ]] && printf 1 || printf 0)"
  if [[ "$ROOT_ROW_ADVISOR" == "0" || "$ROOT_ROW_ADVISOR" == "1" ]]; then
    if [[ "$ROOT_ROW_ADVISOR" == "1" && "$FLEET_YAML_HAS_ADVISOR" == "1" ]]; then
      EFFECTIVE_ADVISOR=1
    else
      EFFECTIVE_ADVISOR=0
    fi
  elif [[ "$LINK_HAS_LABEL" == "1" ]]; then
    EFFECTIVE_ADVISOR="$FLEET_YAML_HAS_ADVISOR"
  else
    EFFECTIVE_ADVISOR=0
  fi
else
  # A fresh approval or a convert: there is no existing link-row advisor
  # state to protect, so the hello's own claim is what this run acts on,
  # same as before this fix.
  EFFECTIVE_ADVISOR="$ADVISOR"
fi

# ── a rejoin whose hello contradicts the attachment it kept (#1079) ──────
# The carry-forward above is right about never RAISING the state from a
# hello. It is wrong the other way round: a node rebuilt with its identity
# kept rejoins with no Advisor, or with a new one, and the attachment this
# aggregator kept points at an Advisor and credentials that are gone. The
# Advisor the operator then installs generates its own token, this
# aggregator's old one is refused, and the page reads "refused" with Add an
# Advisor offering nothing until someone presses Remove this Advisor and then
# Attach.
#
# So a hello that says NO Advisor, or brings an Advisor token whose hash is
# not the one in the token file this aggregator holds, on a rejoin, LOWERS the
# attachment to what detach-advisor leaves behind: fleet.yaml's row without
# advisor_origin and advisor_token_path, fleet-links.json's row without
# advisor_port, root's record at 0, and the old approve token removed. It can
# only detach. The hello's token is compared and never written: a hello that
# claims an Advisor still carries the existing state forward and no further.
#
# Only on an EXPLICIT claim. The dashboard always sends advisor=0 or
# advisor=1 (lib/fleet-broker.ts); a payload with no such key says nothing
# about the node, and nothing is lowered on silence.
#
# When the row cannot be rewritten safely (a field this program does not
# know, a boundary it cannot find) the old carry-forward stands and the answer
# says so: a rejoin that succeeded before still succeeds.
#
# Runs as root, from this program's own checked copy, and reads nothing the
# login can change: the registries through the descriptor-walked snapshot
# approve took above, the token file through dirsafe.
ADVISOR_NOTE_PREFIX="Advisor attachment: "
LOWER_ADVISOR=0
LOWER_WHY="" LOWER_NOTE="" LOWER_FAIL=""
CARRIED_EFFECTIVE="$EFFECTIVE_ADVISOR" CARRIED_ADVISOR_PORT=""
lower_give_up() {  # reason -> leave the carry-forward standing, and say so
  LOWER_ADVISOR=0
  EFFECTIVE_ADVISOR="$CARRIED_EFFECTIVE"
  [[ -z "$CARRIED_ADVISOR_PORT" ]] || ADVISOR_PORT="$CARRIED_ADVISOR_PORT"
  LOWER_NOTE="${ADVISOR_NOTE_PREFIX}\"$LABEL\" $LOWER_WHY, but $1, so the attachment this aggregator kept is left as it was. Press Remove this Advisor on its row, then Attach once its Advisor is installed."
}
if [[ "$REJOIN" == "1" && -n "${P[advisor]+x}" && -n "$EXISTING_ADVISOR_PORT" ]]; then
  if [[ "$ADVISOR" == "0" ]]; then
    LOWER_ADVISOR=1
    LOWER_WHY="said it has no Advisor"
  elif [[ "$ADVISOR" == "1" && -n "$ADVISOR_TOKEN" ]]; then
    # Compared only with the file this program itself keeps for the node, in
    # its own token directory. A row whose advisor_token_path names somewhere
    # else (a carried-over fleet) is never read at the path fleet.yaml chose,
    # and a hello cannot be judged against a file that is not there: the
    # attachment stays and the answer says why.
    ROW_ATP="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["row"].get("advisor_token_path") or "")' "$PLAN")"
    KEPT_TOK_SHA=""
    if [[ "$ROW_ATP" == "$ADVISOR_TOKEN_PATH" ]]; then
      KEPT_TOK_COPY="$(backup_of "$ADVISOR_TOKEN_PATH")"
      if [[ -n "$KEPT_TOK_COPY" && -f "$KEPT_TOK_COPY" ]]; then
        KEPT_TOK_SHA="$(printf '%s' "$(cat "$KEPT_TOK_COPY")" | sha256sum | cut -d' ' -f1)"
      fi
    fi
    HELLO_TOK_SHA="$(printf '%s' "$ADVISOR_TOKEN" | sha256sum | cut -d' ' -f1)"
    if [[ -z "$KEPT_TOK_SHA" ]]; then
      LOWER_WHY="brought an Advisor token"
      lower_give_up "this aggregator holds no token file for it in its own token directory to compare it with"
    elif [[ "$HELLO_TOK_SHA" != "$KEPT_TOK_SHA" ]]; then
      LOWER_ADVISOR=1
      LOWER_WHY="sent an Advisor token that is not the one this aggregator holds for it"
    fi
  fi
fi
if [[ "$LOWER_ADVISOR" == "1" ]]; then
  LROW_EXTRA="$(python3 -c 'import json,sys;print(",".join(json.load(open(sys.argv[1]))["row"].get("extra_keys") or []))' "$PLAN")"
  if [[ -n "$LROW_EXTRA" ]]; then
    lower_give_up "its fleet.yaml row carries a field this program does not know ($LROW_EXTRA)"
  elif [[ "$EXISTING_ROLE" == "aggregator" ]]; then
    lower_give_up "this is the aggregator's own row"
  else
    EFFECTIVE_ADVISOR=0
  fi
fi

# A pin another row already holds. Two labels on one node key is the
# copied-install hazard the phase-1 review named: one read token, two rows,
# and silently wrong fleet data under the wrong label. Skipped on a convert:
# that path already proved PUBKEY is pinned to exactly this row and no other.
if [[ "$REJOIN" == "0" && "$CONVERT" == "0" ]]; then
  DUP="$(python3 - "$SNAP_FLEET_YAML" "$PUBKEY" <<'PY'
import os, sys
try:
    import yaml
except ImportError:
    raise SystemExit(0)
path, pubkey = sys.argv[1:3]
if not os.path.exists(path):
    raise SystemExit(0)
with open(path) as f:
    doc = yaml.safe_load(f.read()) or {}
for r in (doc.get("fleet") or []):
    if isinstance(r, dict) and r.get("expected_pubkey_node") == pubkey:
        sys.stdout.write(str(r.get("label") or "?"))
        break
PY
)"
  [[ -z "$DUP" ]] || refuse pin_taken \
    "$FLEET_YAML already pins that node key to the row \"$DUP\". Two labels on one node key is a copied install, and it reads as wrong fleet data under the wrong name."
fi

# ── the ports ────────────────────────────────────────────────────────────
# One contiguous pool, lowest free first (ruling, 2026-09-12). Free means:
# named by no registry above, and not listening right now. That third check
# is what turns `bind_failed` into an assignment-time refusal rather than a
# runtime one, and a leftover SSH forward is exactly the case it catches.
LISTENING=""
if command -v ss >/dev/null 2>&1; then
  LISTENING="$(ss -ltnH 2>/dev/null | awk '{print $4}' | sed 's/.*://' | tr '\n' ' ' || true)"
fi
if [[ "$REJOIN" == "1" ]]; then
  # A rejoin keeps its ports. Changing a bound port under a live fleet is
  # not something an approval does.
  READ_PORT="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["row"].get("read_port") or "")' "$PLAN")"
  ADVISOR_PORT="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["row"].get("advisor_port") or "")' "$PLAN")"
  # The port goes with the attachment (#1079): the links row below is built
  # from it, and it is the row the hub binds the Advisor's port from.
  if [[ "$LOWER_ADVISOR" == "1" ]]; then CARRIED_ADVISOR_PORT="$ADVISOR_PORT"; ADVISOR_PORT=""; fi
  [[ -n "$READ_PORT" ]] || refuse no_port "the existing row for \"$LABEL\" names no read port, so this cannot be a rejoin. Fix that row by hand."
  # #866 review, M2: the port is root's when root has a line, and from this
  # program's own pool when it does not. A read port taken from fleet.yaml
  # alone is a port the dashboard account chose, and it lands in root's
  # record and the Advisor's registry from here.
  if [[ -n "$REJOIN_ROOT_PORT" ]]; then
    [[ "$READ_PORT" == "$REJOIN_ROOT_PORT" ]] \
      || refuse root_port_disagrees "this host's own record reads \"$LABEL\" on port $REJOIN_ROOT_PORT and $FLEET_YAML says $READ_PORT, so this rejoin is refused. Bring the two back into line by hand, or run curl -fsSL https://get.aperire.one | bash -s -- --dir $INSTALL_DIR --run fleet-broker-grant --refresh-nodes, then pair again."
    READ_PORT="$REJOIN_ROOT_PORT"
  fi
  if ! [[ "$READ_PORT" =~ ^[0-9]{1,5}$ ]] || (( READ_PORT < FLEET_LINK_PORT_MIN || READ_PORT > FLEET_LINK_PORT_MAX )); then refuse port_out_of_pool "the existing row for \"$LABEL\" reads on port $READ_PORT, which is outside this host's link pool $FLEET_LINK_PORT_MIN-$FLEET_LINK_PORT_MAX, so this rejoin is refused. Fix that row by hand."; fi
else
  READ_PORT="" ADVISOR_PORT=""
  for (( p = FLEET_LINK_PORT_MIN; p <= FLEET_LINK_PORT_MAX; p++ )); do
    port_free "$p" || continue
    if [[ -z "$READ_PORT" ]]; then READ_PORT="$p"; continue; fi
    if [[ "$ADVISOR" == "1" && -z "$ADVISOR_PORT" ]]; then ADVISOR_PORT="$p"; fi
    break
  done
  [[ -n "$READ_PORT" ]] || refuse no_port "every port in $FLEET_LINK_PORT_MIN-$FLEET_LINK_PORT_MAX is taken or listening, so there is nowhere to land that node"
  if [[ "$ADVISOR" == "1" && -z "$ADVISOR_PORT" ]]; then
    refuse no_port "there is one free port left in $FLEET_LINK_PORT_MIN-$FLEET_LINK_PORT_MAX and that node needs two"
  fi
fi

# ── the three candidates ─────────────────────────────────────────────────
# TOKEN_DIR itself is created further down, by ensure_token_dir, never by a
# bare `mkdir -p` here: see attach-advisor's own copy of this note.
#
# Both from the SNAP_* this verb already took above: a fresh install's very
# first approve has no fleet.yaml or fleet-links.json yet, which is exactly
# what an empty SNAP_* means (absent, not refused), so the empty-file
# fallback survives unchanged.
if [[ -n "$SNAP_FLEET_YAML" ]]; then cp -a "$SNAP_FLEET_YAML" "$WORK/fleet.yaml"; else : > "$WORK/fleet.yaml"; fi
if [[ -n "$SNAP_FLEET_LINKS" ]]; then cp -a "$SNAP_FLEET_LINKS" "$WORK/links.json"; else printf '{\n  "links": []\n}\n' > "$WORK/links.json"; fi

# ── this host's own row (#1045) ──────────────────────────────────────────
# The dashboard finds itself in fleet.yaml by one rule (fleet-health.ts,
# resolveFleet): the row whose read_origin is loopback on its OWN port. A
# file with rows and none of them that one is a file it refuses whole, so it
# loads no peers and holds every link. A fresh aggregator's first approval
# used to leave exactly that: the node's row and nothing naming this host,
# and the node registered and never linked.
#
# So a first approval that finds no row on this dashboard's port writes one,
# in the same candidate as the node's row, validated and placed with it.
# Every value in it is root's own fact about this host, never the caller's:
# the port, the install role and the token path out of the dashboard's unit
# and its env file (fleet_self_facts, both read through dirsafe), the name
# out of uname. A row already on that port is this host whatever it says,
# and is left exactly as it is. A port that cannot be read is never guessed:
# no row is written, and the approval says which row to add and why.
#
# The role follows what the install said this host is, because the dashboard
# reads `role: aggregator` on its own row as "no node of its own" and stops
# raising that node's alerts (server.ts, selfIsFleetAggregator). A
# dashboard-role install is that, and gets it; a co-located one runs a node
# beside the dashboard and gets `role: node`; an install that never recorded
# a role gets no role line, which the dashboard reads as no claim.
self_name() {  # -> this host's short name as a fleet label, or nothing
  local n
  n="$(uname -n 2>/dev/null || true)"
  n="${n%%.*}"
  n="$(printf '%s' "$n" | tr '[:upper:]' '[:lower:]')"
  [[ "$n" =~ $LABEL_RE ]] && printf '%s' "$n"
  return 0
}

self_label_taken() {  # label -> 0 when a row or this approval already uses it
  [[ "$1" == "$LABEL" ]] && return 0
  grep -qxF "label $1" <<<"$SELF_SCAN"
}

SELF_ROW_ADDED=0
SELF_ROW_LABEL=""
SELF_ROW_NOTE=""
SELF_ROW_LINE=""
if [[ "$REJOIN" == "0" && "$CONVERT" == "0" ]]; then
  SELF_ROW_PORT="${SELF_FACT_PORT:-0}"
  SELF_ROW_ROLE="$SELF_FACT_ROLE"
  SELF_ROW_TOKEN="${SELF_FACT_TOKEN:-$INSTALL_DIR/advisor/state/read.token}"
  # What the candidate already says about this host, read off root's own
  # copy: one line per row label, and `self <label>` for a row already on
  # this port, `aggrow <label> <port>` for one marked aggregator elsewhere.
  # With the port unknown (0), no row is `self` and every aggregator row is
  # an `aggrow`.
  SELF_SCAN="$(python3 -I - "$WORK/fleet.yaml" "$SELF_ROW_PORT" <<'PY' || printf 'unread\n'
import sys
from urllib.parse import urlparse
path, port = sys.argv[1], int(sys.argv[2])
try:
    import yaml
    with open(path) as f:
        doc = yaml.safe_load(f.read())
except Exception:
    print("unread")
    raise SystemExit(0)
rows = (doc or {}).get("fleet") if isinstance(doc, dict) else None
for r in rows if isinstance(rows, list) else []:
    if not isinstance(r, dict) or not isinstance(r.get("label"), str):
        continue
    label = r["label"]
    print("label %s" % label)
    origin = r.get("read_origin")
    try:
        u = urlparse(origin) if isinstance(origin, str) else None
        host = (u.hostname or "").lower() if u else ""
        p = (u.port or (443 if u.scheme == "https" else 80)) if u else None
    except ValueError:
        host, p = "", None
    if host in ("127.0.0.1", "localhost", "::1") and p == port:
        print("self %s" % label)
    elif r.get("role") == "aggregator":
        print("aggrow %s %s" % (label, p if p else "-"))
PY
)"
  SELF_ROW_WANT="$(self_name)"
  [[ -n "$SELF_ROW_WANT" ]] || SELF_ROW_WANT=aggregator
  if self_label_taken "$SELF_ROW_WANT"; then SELF_ROW_WANT=aggregator; fi
  if grep -q '^unread$' <<<"$SELF_SCAN"; then
    # The candidate is validated below by the dashboard's own parser, which
    # refuses a file this could not read. Nothing to add to that refusal.
    :
  elif grep -q '^self ' <<<"$SELF_SCAN"; then
    :  # this host already has its row
  elif [[ -n "$SELF_FACT_UNKNOWN" ]]; then
    # The port cannot be read. A row marked aggregator is taken as this
    # host's, the way every installer before #1045 left it; otherwise the
    # row is named for the operator to add, never written on a guess.
    if ! grep -q '^aggrow ' <<<"$SELF_SCAN"; then
      SELF_ROW_NOTE="fleet.yaml has no row for this host, and this program could not tell which port this dashboard listens on ($SELF_FACT_UNKNOWN), so it wrote none and the dashboard holds every link. Add this host's own row by hand and reload: label: $SELF_ROW_WANT read_origin: http://127.0.0.1:<the dashboard's PORT> token_path: $SELF_ROW_TOKEN"
    fi
  elif AGGROW="$(sed -n 's/^aggrow //p' <<<"$SELF_SCAN" | head -n 1)" && [[ -n "$AGGROW" ]]; then
    # Somebody wrote this host's row by hand, on another port. It is theirs
    # to fix, and a second row for the same host is not this program's to add.
    SELF_ROW_NOTE="fleet.yaml's row \"${AGGROW%% *}\" is marked role: aggregator but reads port ${AGGROW##* }, not this dashboard's port $SELF_ROW_PORT, so the dashboard does not take it for this host and holds every link. Set its read_origin to http://127.0.0.1:$SELF_ROW_PORT."
  else
    SELF_ROW_LINE="  - label: $SELF_ROW_WANT"$'\n'
    [[ -n "$SELF_ROW_ROLE" ]] && SELF_ROW_LINE+="    role: $SELF_ROW_ROLE"$'\n'
    SELF_ROW_LINE+="    read_origin: http://127.0.0.1:$SELF_ROW_PORT"$'\n'
    SELF_ROW_LINE+="    token_path: $SELF_ROW_TOKEN"$'\n'
    if self_label_taken "$SELF_ROW_WANT"; then
      # Both names are in use. Said with the row to add, never guessed at.
      SELF_ROW_NOTE="fleet.yaml has no row for this host, and the names this program would give it are both in use, so none was written and the dashboard holds every link. Add this host's own row by hand, under a name no other row uses, and reload: $(printf '%s' "$SELF_ROW_LINE" | sed 's/^ *//' | tr '\n' ' ' | sed 's/ $//')"
      SELF_ROW_LINE=""
    else
      SELF_ROW_ADDED=1
      SELF_ROW_LABEL="$SELF_ROW_WANT"
    fi
  fi
fi

# One row, one shape, for the append this label has never had and the
# convert that replaces its tunnel row -- so "shape equals a fresh row" (the
# proof this phase already carries) holds for both by construction rather
# than by two printf blocks staying in agreement by hand.
emit_link_row() {
  printf '  - label: %s\n' "$LABEL"
  printf '    role: %s\n' "$EMIT_ROLE"
  # No line at all when there is no address to carry (#339). An empty
  # `dashboard_url:` would be a present key with an empty value, which
  # fails the whole file closed in fleet-registry.ts, so the absent field
  # and the absent line are the same fact all the way down.
  if [[ -n "$EMIT_DASH_URL" ]]; then printf '    dashboard_url: %s\n' "$EMIT_DASH_URL"; fi
  printf '    read_origin: http://127.0.0.1:%s\n' "$READ_PORT"
  printf '    token_path: %s\n' "$TOKEN_PATH"
  printf '    expected_pubkey_node: %s\n' "$PUBKEY"
  printf '    transport: link\n'
  if [[ "$ADVISOR" == "1" ]]; then
    # Both halves or neither: either one alone fails the whole file closed.
    printf '    advisor_origin: http://127.0.0.1:%s\n' "$ADVISOR_PORT"
    printf '    advisor_token_path: %s\n' "$ADVISOR_TOKEN_PATH"
  fi
}

if [[ "$CONVERT" == "1" ]]; then
  # The tunnel row this label already held comes out as TEXT, the same rule
  # an append follows below: fleet.yaml is never re-parsed and re-dumped,
  # so a hand-written comment anywhere else in the file survives byte for
  # byte. The block is the `- label: LABEL` line through to (not including)
  # the next list item or a line at column zero, blank lines inside it
  # going with it. Anything short of exactly one such block -- the label
  # spelled differently in the raw text than the parse the plan already
  # trusted, or two -- is refused rather than guessed at: this program
  # would rather leave a convert unfinished than remove the wrong lines.
  if ! python3 - "$WORK/fleet.yaml" "$LABEL" "$WORK/fleet.yaml.excised" <<'PY'
import re
import sys

path, label, out = sys.argv[1:4]
with open(path) as f:
    lines = f.readlines()
start_re = re.compile(r'^  - label: ' + re.escape(label) + r'\s*$')
starts = [i for i, ln in enumerate(lines) if start_re.match(ln)]
if len(starts) != 1:
    raise SystemExit(1)
start = starts[0]
end = start + 1
while end < len(lines):
    ln = lines[end]
    if ln.strip() == '':
        end += 1
        continue
    if re.match(r'^  - ', ln) or re.match(r'^\S', ln):
        break
    end += 1
with open(out, 'w') as f:
    f.writelines(lines[:start] + lines[end:])
PY
  then
    refuse convert_row_missing "the row for \"$LABEL\" could not be found as exactly one block in $FLEET_YAML, so nothing was converted. Fix that row by hand, then mint a new code and pair again."
  fi
  mv -f "$WORK/fleet.yaml.excised" "$WORK/fleet.yaml"
fi

if [[ "$REJOIN" == "0" ]]; then
  # APPENDED as text, never regenerated. fleet.yaml.example ships a
  # commented-out expected_pubkey_node and a commented-out transport: link,
  # and a load-then-dump cycle deletes both invisibly. A hand-written row
  # surviving an approval is the second clause of this phase's own proof.
  # On a convert this is the row's own replacement, appended at the end of
  # the file rather than back where the excised block was: fleet.yaml
  # carries no ordering guarantee the dashboard's own parser depends on.
  #
  # The trailing newline first: an append onto a file with no trailing
  # newline fuses onto the last line.
  if [[ -s "$WORK/fleet.yaml" ]]; then
    [[ "$(tail -c1 "$WORK/fleet.yaml")" == "" ]] || printf '\n' >> "$WORK/fleet.yaml"
  else
    printf 'fleet:\n' > "$WORK/fleet.yaml"
  fi
  # This host's own row first, when the file has none (#1045, above).
  (( SELF_ROW_ADDED )) && printf '%s' "$SELF_ROW_LINE" >> "$WORK/fleet.yaml"
  emit_link_row >> "$WORK/fleet.yaml"
fi

# #620 review (119): the excision above finds the block by TEXT, and a
# column-zero comment INSIDE the tunnel row (rare, but legal YAML: a comment
# is ignored by a real parser at any indentation) would end that scan early.
# The row's own later lines -- advisor_origin, expected_pubkey_node, a
# hand-added transport -- would then survive as ORPHANED text, indented as
# if they were still fields, with nothing opening a new list item ahead of
# them. A real YAML parser reads exactly that shape as more keys on the
# PRECEDING row's own mapping: this label's fields would attach themselves
# to some other node's row, silently, and neither this program's own later
# checks nor the dashboard's real parser would refuse it, because every key
# in play is one an ordinary row is allowed to carry. So this is asked
# directly rather than trusted from the text scan: parse the ORIGINAL file
# (still untouched at $FLEET_YAML) and this candidate, drop the target
# label's own row from each, and the two lists of everything else must be
# identical. Anything else means the excision found the wrong boundary.
if [[ "$CONVERT" == "1" ]]; then
  if ! python3 - "$SNAP_FLEET_YAML" "$WORK/fleet.yaml" "$LABEL" <<'PY'
import sys
try:
    import yaml
except ImportError:
    raise SystemExit(1)
orig_path, new_path, label = sys.argv[1:4]
with open(orig_path) as f:
    orig = yaml.safe_load(f.read()) or {}
with open(new_path) as f:
    new = yaml.safe_load(f.read()) or {}
orig_rows = orig.get("fleet") if isinstance(orig, dict) else None
new_rows = new.get("fleet") if isinstance(new, dict) else None
if not isinstance(orig_rows, list) or not isinstance(new_rows, list):
    raise SystemExit(1)
orig_rest = [r for r in orig_rows if not (isinstance(r, dict) and r.get("label") == label)]
new_rest = [r for r in new_rows if not (isinstance(r, dict) and r.get("label") == label)]
if orig_rest != new_rest:
    raise SystemExit(1)
PY
  then
    refuse convert_excision_mismatch "converting \"$LABEL\" would change a row other than its own in $FLEET_YAML, which means the text that was removed did not match its actual boundary (a comment inside that row is the usual cause). Nothing was written. Fix that row by hand, then mint a new code and pair again."
  fi
fi

# The row without its two Advisor lines (#1079). The pieces are
# detach-advisor's and revoke's (cut_one_row_block, emit_attached_row), the row
# comes out of the plan's snapshot, and everything else on it, and every other
# row, has to come back as it went in: checked by parsing both. Returns 1 with
# LOWER_FAIL set when it cannot, and the caller leaves the carry-forward.
lower_fleet_yaml_row() {
  local rc=0
  ROW_LABEL="$LABEL"
  ROW_EMIT_ROLE="$EMIT_ROLE"
  ROW_DASH_URL="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["row"].get("dashboard_url") or "")' "$PLAN")"
  ROW_READ_ORIGIN="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["row"].get("read_origin") or "")' "$PLAN")"
  ROW_TOKEN_PATH="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["row"].get("token_path") or "")' "$PLAN")"
  ROW_PIN="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["row"].get("pin") or "")' "$PLAN")"
  ROW_EMIT_ADVISOR=0
  if ! cut_one_row_block "$WORK/fleet.yaml" "$LABEL" "$WORK/fleet.yaml.lowered"; then
    LOWER_FAIL="its row could not be found as exactly one block in fleet.yaml"
    return 1
  fi
  mv -f "$WORK/fleet.yaml.lowered" "$WORK/fleet.yaml"
  if [[ -s "$WORK/fleet.yaml" ]]; then
    [[ "$(tail -c1 "$WORK/fleet.yaml")" == "" ]] || printf '\n' >> "$WORK/fleet.yaml"
  else
    printf 'fleet:\n' > "$WORK/fleet.yaml"
  fi
  emit_attached_row >> "$WORK/fleet.yaml"
  python3 - "$SNAP_FLEET_YAML" "$WORK/fleet.yaml" "$LABEL" <<'PY' || rc=$?
import sys
try:
    import yaml
except ImportError:
    raise SystemExit(1)
orig_path, new_path, label = sys.argv[1:4]
with open(orig_path) as f:
    orig = yaml.safe_load(f.read()) or {}
with open(new_path) as f:
    new = yaml.safe_load(f.read()) or {}
orig_rows = orig.get("fleet") if isinstance(orig, dict) else None
new_rows = new.get("fleet") if isinstance(new, dict) else None
if not isinstance(orig_rows, list) or not isinstance(new_rows, list):
    raise SystemExit(1)
orig_rest = [r for r in orig_rows if not (isinstance(r, dict) and r.get("label") == label)]
new_rest = [r for r in new_rows if not (isinstance(r, dict) and r.get("label") == label)]
if orig_rest != new_rest:
    raise SystemExit(1)
orig_target = next((r for r in orig_rows if isinstance(r, dict) and r.get("label") == label), None)
new_target = next((r for r in new_rows if isinstance(r, dict) and r.get("label") == label), None)
if orig_target is None or new_target is None:
    raise SystemExit(1)
def sans_advisor(r):
    d = {k: v for k, v in r.items() if k not in ("advisor_origin", "advisor_token_path")}
    d.setdefault("role", "node")
    return d
if sans_advisor(orig_target) != sans_advisor(new_target):
    raise SystemExit(1)
if "advisor_origin" in new_target or "advisor_token_path" in new_target:
    raise SystemExit(1)
PY
  if (( rc != 0 )); then
    LOWER_FAIL="rewriting its row would change more of fleet.yaml than its two Advisor lines"
    return 1
  fi
  return 0
}
if [[ "$LOWER_ADVISOR" == "1" ]]; then
  if ! lower_fleet_yaml_row; then
    cp -a "$SNAP_FLEET_YAML" "$WORK/fleet.yaml"
    lower_give_up "$LOWER_FAIL"
  fi
fi

python3 - "$WORK/links.json" "$WORK/links.new.json" "$LABEL" "$CRED_SHA" "$READ_PORT" "${ADVISOR_PORT:-}" <<'PY' || fail candidate_failed "the fleet-links.json candidate could not be built"
import json, sys
src, out, label, sha, read_port, advisor_port = sys.argv[1:7]
with open(src) as f:
    doc = json.load(f)
if not isinstance(doc, dict):
    raise SystemExit(1)
rows = doc.get("links")
if rows is None:
    rows = []
row = {"label": label, "credential_sha256": sha, "read_port": int(read_port)}
if advisor_port:
    row["advisor_port"] = int(advisor_port)
# A rejoin REPLACES that label's row, which is what re-mints its credential.
rows = [r for r in rows if not (isinstance(r, dict) and r.get("label") == label)]
rows.append(row)
doc["links"] = rows
with open(out, "w") as f:
    json.dump(doc, f, indent=2)
    f.write("\n")
PY

# The Advisor's own registry, as the third candidate (ruling, 2026-09-12).
# Without it a node paired from a code is invisible to the AGGREGATOR's own
# Advisor, which is a regression against the manual path this replaces.
WROTE_ADV=0
# `-d` follows a symlink, and that is safe HERE and nowhere else in this
# program: snap_adv_fleet has already run for this connection, and since
# round 8 it refuses the whole verb when advisor/state is anything but a
# real directory reached through a real chain. So the only two states this
# line can still see are "a genuine directory" and "genuinely absent". A
# swap landing between that refusal and this check does not get through
# either: the write below goes through place(), which walks the chain
# again and refuses rather than following it.
if [[ -d "$ADV_STATE" ]]; then
  WROTE_ADV=1
  # $SNAP_ADV_FLEET is this verb's own snapshot, taken above: never the
  # live file a second time.
  if [[ -n "$SNAP_ADV_FLEET" ]]; then cp -a "$SNAP_ADV_FLEET" "$WORK/adv.json"; else printf '{\n  "peers": []\n}\n' > "$WORK/adv.json"; fi
  python3 - "$WORK/adv.json" "$WORK/adv.new.json" "$LABEL" "http://127.0.0.1:$READ_PORT" "$TOKEN_PATH" "$EMIT_ROLE" "$PUBKEY" <<'PY' || fail candidate_failed "the advisor fleet.json candidate could not be built"
import json, sys
src, out, label, origin, token_path, role, pubkey = sys.argv[1:8]
with open(src) as f:
    doc = json.load(f)
# Whatever shape the file is in, it stays in: this program joins a node, it
# does not migrate a registry. The same rule aperire-fleet-add.sh follows.
if isinstance(doc, list):
    peers = doc
elif isinstance(doc, dict):
    peers = doc.setdefault("peers", [])
    if not isinstance(peers, list):
        raise SystemExit(1)
else:
    raise SystemExit(1)
row = {"label": label, "origin": origin, "token_path": token_path, "transport": "link",
       "role": role, "expected_pubkey_node": pubkey}
peers[:] = [p for p in peers if not (isinstance(p, dict) and p.get("label") == label)]
peers.append(row)
with open(out, "w") as f:
    json.dump(doc, f, indent=2)
    f.write("\n")
PY
fi

# ── validated TOGETHER, with the services' own parsers ───────────────────
# The row counts the candidates must have: one more than before on a first
# approval, the same on a rejoin AND on a convert (that one replaces its
# tunnel row rather than adding to the count). Read off the plan, which
# counted them before anything was built.
WAS_FLEET_ROWS="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("fleet_rows", -1))' "$PLAN")"
WAS_LINK_ROWS="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("link_rows", -1))' "$PLAN")"
HAD_LINK_ROW="$(python3 -c 'import json,sys;print("1" if json.load(open(sys.argv[1])).get("link_has_label") else "0")' "$PLAN")"
if [[ "$REJOIN" == "1" || "$CONVERT" == "1" ]]; then
  WANT_FLEET_ROWS="$WAS_FLEET_ROWS"
else
  # One more, and one more again when this host's own row goes in with it
  # (#1045): that row is counted rather than let through uncounted.
  WANT_FLEET_ROWS="$(( WAS_FLEET_ROWS + 1 + SELF_ROW_ADDED ))"
fi
if [[ "$HAD_LINK_ROW" == "1" ]]; then
  # A rejoin replaces that label's row rather than adding one.
  WANT_LINK_ROWS="$WAS_LINK_ROWS"
else
  WANT_LINK_ROWS="$(( WAS_LINK_ROWS + 1 ))"
fi
# scripts/test-fleet-broker.sh holds this program to exactly one
# node-under-tsx call site (#370); this is it, shared with #641's advisor
# verbs through validate_candidates_or_refuse rather than a second copy.
validate_candidates_or_refuse "$WORK/fleet.yaml" "$WORK/links.new.json"

if (( WROTE_ADV )); then
  # advisord's parser is Go and has no validate entry point, so the key set
  # it accepts is re-declared here, exactly as aperire-fleet-add.sh
  # re-declares it. scripts/test-fleet-broker.sh holds this list against the
  # json tags in advisor/internal/fleet/fleet.go, so the replica cannot
  # drift from the thing it stands in for.
  if ! python3 - "$WORK/adv.new.json" "$LABEL" <<'PY' 2>"$WORK/adv.err"
import json, sys
path, label = sys.argv[1:3]
with open(path) as f:
    d = json.load(f)
peers = d if isinstance(d, list) else d.get("peers", [])
assert isinstance(peers, list), "peers is not a list"
row = next((r for r in peers if isinstance(r, dict) and r.get("label") == label), None)
assert row is not None, "the new row is not in the advisor fleet.json candidate"
allowed = {"label", "origin", "token_path", "transport", "role", "expected_pubkey_node"}
assert set(row.keys()) <= allowed, "the new row carries a key advisord's loader would refuse"
assert {"label", "origin", "token_path"} <= set(row.keys()), "the new row is missing a required key"
PY
  then
    refuse candidate_refused "the advisor registry this approval would write is not one advisord would load, so nothing was written: $(tr -d '\n' < "$WORK/adv.err")"
  fi
fi

# #851 review L2: an approval never makes the arm key. `arm-key`, a moment
# before the welcome, is the one verb that may, under its own rule; a key
# missing by now is refused here, after every other check and before the
# first backup or write, whatever the payload carries. The dashboard sends
# fleet_arm_pubkey on every approval (settings-api.ts, after arm-key), and a
# missing key already refuses as arm_key_changed above, so this is reached
# only by a caller that sent none.
if [[ ! -e "$ARM_KEY" && ! -L "$ARM_KEY" ]]; then
  if arm_key_lost; then
    fact fleet_arm_key lost
    [[ -n "$ARM_KEY_PAIRED" ]] && fact fleet_arm_key_paired "$ARM_KEY_PAIRED"
    refuse fleet_arm_key_lost "$(arm_key_lost_sentence)"
  fi
  fact fleet_arm_key missing
  refuse no_fleet_arm_key "this aggregator has no fleet arm key, and an approval never makes one. Nothing was written. Pair the node again from Add a node, which makes the key first on a fleet that never had one."
fi
# ── all three, or none ───────────────────────────────────────────────────
# Backed up first, restored on any failure below, and the SIGHUP comes after
# the last rename so a reload can never observe half of this. backup_of,
# restore_all and place are the shared primitives hoisted above.
BACKED=()
BACKED+=("$FLEET_YAML" "$(backup_of "$SNAP_FLEET_YAML")" "$DASH_USER:$DASH_GROUP:644")
BACKED+=("$FLEET_LINKS" "$(backup_of "$SNAP_FLEET_LINKS")" "$DASH_USER:$DASH_GROUP:600")
(( WROTE_ADV )) && BACKED+=("$ADV_FLEET" "$(backup_of "$SNAP_ADV_FLEET")" "$ADV_FLEET_OWNER:$SHARED_GROUP:640")
# Root's own node record joins the set that is put back (phase 4). It is
# written after the token files, which is after the three renames, and a
# token refusal there calls restore_all: without this line a refused approval
# would leave a conf naming a node fleet.yaml does not hold, and `model-push`
# would then have a destination for a row that was rolled back.
BACKED+=("$NODES_CONF" "$(backup_of "$NODES_CONF")" "self")
# The old Advisor's token is removed below when the attachment is lowered, so
# it is backed up first like everything else this run replaces (#1079).
[[ "$LOWER_ADVISOR" == "1" ]] && BACKED+=("$ADVISOR_TOKEN_PATH" "$(backup_of "$ADVISOR_TOKEN_PATH")" "self")

STEP=""
if [[ "$REJOIN" == "0" || "$LOWER_ADVISOR" == "1" ]]; then
  STEP="fleet.yaml"
  place "$WORK/fleet.yaml" "$FLEET_YAML" "$DASH_USER" "$DASH_GROUP" 644 || { restore_all || true; fail rename_failed "$STEP could not be written$RESTORE_NOTE"; }
fi
STEP="fleet-links.json"
place "$WORK/links.new.json" "$FLEET_LINKS" "$DASH_USER" "$DASH_GROUP" 600 || { restore_all || true; fail rename_failed "$STEP could not be written$RESTORE_NOTE"; }
if (( WROTE_ADV )); then
  STEP="advisor/state/fleet.json"
  adv_owner="$ADV_FLEET_OWNER"
  place "$WORK/adv.new.json" "$ADV_FLEET" "$adv_owner" "$SHARED_GROUP" 640 \
    || { restore_all || true; fail rename_failed "$STEP could not be written$RESTORE_NOTE"; }
fi
# The directory entries, so a power cut between here and the reload cannot
# leave one of the three renames unrecorded.
if command -v sync >/dev/null 2>&1; then sync "$CONFIG_DIR" 2>/dev/null || true; fi

# ── the token files ──────────────────────────────────────────────────────
# root:<shared group> 0640, because advisord reads them too now that this
# program writes its registry (ruling, 2026-09-12). An existing file wider
# than 0640 is refused, never silently tightened.
# root:<group> when root can set it, and never wider when it cannot: the
# aperire-fleet-add.sh degrade, and the one case that reaches it here is a
# test harness, because this program is only ever root on a host. Checked
# rather than assumed, because every failure from here on is AFTER the three
# renames and has to put them back rather than end the run.
#
# ensure_token_dir does the symlink check and the create/chown/chmod on ONE
# file descriptor, opened O_NOFOLLOW: a plain `[[ -L ]]` check followed by
# a separate `install -d` left a race window (TOKEN_DIR's own parent is
# owned by an unprivileged account; see the function's own comment) where
# that account could swap a symlink in between the two lines, and
# `install -d` follows a symlinked directory argument, chowning and
# chmoding whatever it points at as root (verified). Doing both on the
# same fd closes that window rather than narrowing it.
ETD_RC=0; ensure_token_dir "$TOKEN_DIR" || ETD_RC=$?
if (( ETD_RC == 2 )); then
  restore_all || true
  fail token_is_symlink "$TOKEN_DIR already exists as a symlink, and this program will not create, own or mode a directory through one. Nothing here follows it. Remove it by hand and try again.$RESTORE_NOTE."
elif (( ETD_RC != 0 )); then
  restore_all || true
  fail token_failed "$TOKEN_DIR could not be created$RESTORE_NOTE"
fi

# Refused BEFORE anything is written, so a wide file that is about to be
# refused does not first cost the registries a rename to put back.
# check_token_mode and write_token are the shared primitives hoisted above.
for _t in "$TOKEN_PATH" "$ADVISOR_TOKEN_PATH"; do
  # A token this run is about to remove is not one it is about to write.
  [[ "$LOWER_ADVISOR" == "1" && "$_t" == "$ADVISOR_TOKEN_PATH" ]] && continue
  TOKEN_MODE_RC=0; WIDE="$(check_token_mode "$_t")" || TOKEN_MODE_RC=$?
  if (( TOKEN_MODE_RC == 2 )); then
    restore_all || true
    refuse token_is_symlink "$_t already exists as a symlink, and a bearer token is never written through one. Nothing here follows it. Remove it by hand and try again.$RESTORE_NOTE."
  elif (( TOKEN_MODE_RC == 1 )); then
    restore_all || true
    refuse token_too_wide "$_t already exists with mode $WIDE, wider than 0640. A bearer token at that mode is refused, never silently tightened.$RESTORE_NOTE."
  fi
done
write_token "$TOKEN_PATH" "$READ_TOKEN" \
  || { restore_all || true; fail token_failed "$TOKEN_PATH could not be written$RESTORE_NOTE"; }
# A rejoin never writes this file: #641's attach-advisor, detach-advisor and
# refresh-advisor-token are the only verbs that may change what it holds or
# whether it exists at all, on an already-established row. Writing it here
# from the hello's own claim, on a rejoin, is exactly what let a rejoining
# node plant or silently keep planting a token file fleet.yaml's own row
# never asked for.
if [[ "$REJOIN" == "0" && "$ADVISOR" == "1" ]]; then
  write_token "$ADVISOR_TOKEN_PATH" "$ADVISOR_TOKEN" \
    || { restore_all || true; fail token_failed "$ADVISOR_TOKEN_PATH could not be written$RESTORE_NOTE"; }
fi
if [[ "$LOWER_ADVISOR" == "1" ]]; then
  # Removed on a descriptor, not by name, exactly as detach-advisor removes it:
  # TOKEN_DIR gets the same O_NOFOLLOW walk every other write here does, and a
  # name that is not there is not an error. A refusal rolls everything back.
  STEP="the old Advisor token"
  if ! dirsafe_locate "$ADVISOR_TOKEN_PATH" \
     || ! dirsafe "$DS_ANCHOR" "$DS_RELPATH" "$DS_EXTRA" "$DS_MASK" unlink "$DS_LEAF"; then
    restore_all || true
    fail token_failed "$STEP could not be removed$RESTORE_NOTE"
  fi
fi

# ── root's own node record ───────────────────────────────────────────────
# One line, replacing this label's if it had one, so a rejoin updates its row
# rather than growing a second. This is the ONLY file `model-push` resolves a
# label in, so a node that is not registered here is a node the key cannot
# travel to, whatever any dashboard-owned registry says.
{
  nodes_conf_without "$LABEL"
  printf '%s %s %s %s\n' "$LABEL" "$PUBKEY" "$READ_PORT" "$EFFECTIVE_ADVISOR"
} > "$WORK/nodes.new"
nodes_conf_write "$WORK/nodes.new" \
  || { restore_all || true; fail nodes_conf_failed "$NODES_CONF could not be written$RESTORE_NOTE"; }

# ── the arm key, made if absent, then read ───────────────────────────────
# Read, never made (#851 review L2): `arm-key` made it a moment before the
# welcome, and a missing key was refused above, before anything was written.
# This reads it again so the settlement carries what is on disk NOW, and the
# hub refuses to settle if that is not the key the welcome carried.
resolve_fleet_arm_pub read

# ── one SIGHUP, last ─────────────────────────────────────────────────────
reload_dashboard

fact read_port "$READ_PORT"
fact advisor_port "${ADVISOR_PORT:--}"
fact token_path "$TOKEN_PATH"
[[ "$EFFECTIVE_ADVISOR" == "1" ]] && fact advisor_token_path "$ADVISOR_TOKEN_PATH"
fact advisor_registry "$WROTE_ADV"
fact fleet_arm_pubkey "${ARM_PUB:--}"
fact fleet_arm_key "$ARM_KEY_STATE"
fact rejoined "$REJOIN"
# #1045: this host's own row, when this approval wrote it, and the sentence
# when it could not.
(( SELF_ROW_ADDED )) && fact self_row "$SELF_ROW_LABEL"
[[ -n "$SELF_ROW_NOTE" ]] && fact self_row missing
# #620: named apart from `rejoined`, which a convert is not -- its ports are
# new and its row is a different shape afterward. "tunnel" is the only value
# today; named rather than a bare 0/1 so a later transport this program
# learns to convert from does not have to overload what this fact means.
[[ "$CONVERT" == "1" ]] && fact converted_from tunnel
fact reloaded "$RELOADED"
fact reload_via "${RELOAD_VIA:-none}"
if [[ "$REJOIN" == "1" ]]; then
  out "\"$LABEL\" was already in the fleet on the same node key: its credential is re-minted and its ports are unchanged."
  if [[ "$LOWER_ADVISOR" == "1" ]]; then
    fact advisor_lowered "$LABEL"
    out "${ADVISOR_NOTE_PREFIX}\"$LABEL\" $LOWER_WHY, so the one this aggregator had attached is cleared: its old credentials no longer apply. Add an Advisor offers the node again once its Advisor is installed."
  elif [[ -n "$LOWER_NOTE" ]]; then
    out "$LOWER_NOTE"
  fi
elif [[ "$CONVERT" == "1" ]]; then
  out "\"$LABEL\" was already in the fleet over an SSH tunnel: it now reads over the fleet link on 127.0.0.1:$READ_PORT, keeping its name and history. This aggregator no longer reads through the old token, but the token itself is still a live bearer and the old SSH forward is still up: stop that forward, and the token with it, on your end."
else
  out "\"$LABEL\" is registered, reading on 127.0.0.1:$READ_PORT."
fi
if (( SELF_ROW_ADDED )); then
  out "fleet.yaml had no row for this host, so it has one now, \"$SELF_ROW_LABEL\" on 127.0.0.1:$SELF_ROW_PORT${SELF_ROW_ROLE:+ (role: $SELF_ROW_ROLE)}, and the dashboard can tell itself from the node."
fi
[[ -n "$SELF_ROW_NOTE" ]] && out "$SELF_ROW_NOTE"
if [[ "$RELOADED" != "1" ]]; then
  if [[ "$RELOAD_VIA" == "pm2:not-found" ]]; then
    out "this host has no dashboard unit and no pm2 where $CONF says, so nothing could be told to re-read. Re-run install-fleet-broker-grant.sh, then reload the dashboard by hand."
  else
    out "the dashboard could not be reloaded here, so it will pick this up on its next restart."
  fi
fi
finish 0
