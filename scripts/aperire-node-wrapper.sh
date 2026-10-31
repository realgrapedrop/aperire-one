#!/usr/bin/env bash
# The privilege boundary, ADR 0007, option D1.
#
# The executor performs node operations ONLY by calling this script with one of
# the verbs below. It never runs docker or systemctl directly, never builds a
# command string, and never passes a path. Every path comes from /etc/aperire/
# node-wrapper.conf, root-owned, written once at install from the deployment
# the Advisor discovers, and not writable by the account this script runs as.
#
# What that buys, precisely:
#
#   - The set of possible operations is finite and readable. Anyone auditing
#     what the Advisor can do reads this file, not the Go source.
#   - Arguments are validated against patterns, not escaped. A version that is
#     not digits and dots is rejected rather than quoted.
#   - Every invocation is logged with its arguments before it runs.
#
# How the Advisor reaches it (ADR 0025): never through sudo. The Advisor runs
# as its own account, with no docker group and NoNewPrivileges, and connects
# to one root socket, /run/aperire/node-wrapper<-instance>.sock. Behind it,
# /usr/local/sbin/aperire-wrapper-broker checks the caller's uid, takes one
# verb from a fixed table with arguments of fixed shapes and no paths, and
# runs the root-owned copy of this script, /usr/local/sbin/aperire-node-
# wrapper<-instance>. So on every shape, container or native, this file is
# the whole of what the Advisor can do as root, and a real boundary rather
# than an allow-list.
#
# An operator running this as root from a shell is not the Advisor, and is
# not constrained by the socket's table: every check below still applies.
#
# ── The node's shape: KIND=container|native ────────────────────────────
#
# One declared fact in the configuration says how this node is deployed, and
# every verb that touches the node branches on it:
#
#   container   a compose deployment; docker drives it
#   native      the vendor's package, run by systemd; systemctl and the host's
#               package manager drive it
#
# A configuration with no KIND is a container. That covers every host
# installed before this key existed, and their configurations keep working
# untouched. An unrecognised KIND stops the run instead of falling back: a
# value nobody recognises quietly reading as "container" is how a native host
# would end up being asked for an image digest.
#
# The keys mean different things per kind, and none of them means two things
# at once:
#
#   container   SERVICE is the container name, REPO the image repository,
#               PROJECT and COMPOSE_FILE name the compose deployment.
#   native      SERVICE is the systemd unit (xrpld.service), REPO the package
#               name (xrpld). PROJECT and COMPOSE_FILE are absent, and a
#               native configuration that sets either is refused: a file
#               naming both shapes describes a host nobody measured.
#               NODE_LOG_SOURCE names the one place this node's log is read
#               from, `journal` or an absolute path from the config's
#               [debug_logfile]. It is declared, never searched for.
#
# Native puts two more programs in this root context, and both are held to the
# rule the rest of this file follows, that the arguments are not the caller's:
#
#   systemctl   restart, reset-failed, show, status and cat only, and only on
#               the unit the configuration names. Never enable, never disable,
#               never edit, and never a unit name from a caller.
#               reset-failed is here because a vendor unit's start limiter
#               counts starts, not faults: an upgrade and a rollback spend
#               four between them and the node is then refused its next start
#               and left stopped. Clearing a counter changes nothing else,
#               cannot start or stop anything, and does nothing at all to a
#               unit that is not failed. The alternative was an operator
#               SSHing in to run one command, which is what this file exists
#               to remove. It runs before a native start and says so in the
#               output.
#   the package manager
#               only the package the configuration names, only at a version
#               that is digits and dots, resolved against what this host's own
#               repositories already list. Never a repository URL, a keyring,
#               a sources list or a package name as an argument. Never
#               upgrade, dist-upgrade, full-upgrade or an unversioned install:
#               a node upgrade that patches the whole host is a different
#               blast radius and nobody approved it.
#
# Upgrade integrity is a different guarantee on native, and that is worth
# saying plainly rather than calling the two equivalent. Container: the bytes
# that ran are the bytes I verified, by digest. Native: the package was signed
# by the vendor and the package manager verified that signature before it
# installed, and the version that came up is the version that was installed.
#
# Verbs, both shapes:
#   status                      what the node reports about itself
#   backup-config               dated copy of the node config
#   set-config <key=value>      change ONE allow-listed tuning setting, backed up first
#                               two shapes: a key=value line inside a stanza
#                               (online_delete, advisory_delete) or a stanza whose
#                               value is the line under its header (node_size,
#                               ledger_history). The shape is per key, not guessed
#   restart                     restart the node in place, on what it is running
#
#   restart stops the node, and refuses while the ledger store is mid-rotation.
#   See "Store rotation" below. So does package-install, because a package
#   change restarts the unit from its own maintainer scripts.
#
# Container only. Each of these is an image read or a compose-file edit, and
# on a native host each refuses with that fact rather than with a parse error
# about a configuration key that is not there:
#
#   backup-compose              dated copy of the deployment definition
#   compose-backups             the dated copies, and the tag each names
#   restore-compose <name>      put back a dated copy, named by its file
#                               name (it lives beside the compose file); a
#                               full path is accepted from root's own shell
#   set-image <version>         point the deployment at a REGISTRY tag
#   set-image-local <version>   point the deployment at the locally built
#                               image, localhost/xrpld:<version>, and add
#                               pull_policy: never beside it
#   build-image <version>       build localhost/xrpld:<version> from the XRPL
#                               Foundation's signed package, using the recipe
#                               installed under /usr/local/lib/aperire
#   pull <version>              fetch an image, without touching the node
#   image-version <version>     ask a local image what it is
#   image-digest <version>      what the local image resolves to (no pull)
#   running-digest              what the image the node is running resolves to
#   recreate                    stop and start the node on the current tag
#
# ── Two image origins, one node ───────────────────────────────────────────
#
# A container node's image comes from one of two places, and every image verb
# above handles both:
#
#   the official image    rippleci/xrpld:<version>@sha256:..., pinned to the
#                         digest the tag had when the pull was approved
#   a local build         localhost/xrpld:<version>, built on this box from
#                         the signed DEB package at packages.xrplf.org
#   any other registry    REPO:<version>, a deployment somebody else wrote
#
# The second exists because a release ships as a signed package first, and
# an official image does not always follow the same day. `localhost/`
# is a name no registry can answer for, which is the point: a pull of it
# dials https://localhost/ and fails rather than fetching somebody else's
# image. `set-image-local` writes `pull_policy: never` beside the image line
# for the same reason: a missing local image then fails loudly at once
# instead of turning into a surprise download.
#
# Resolution order for `image-version` and `image-digest` is local first,
# then the registry repository, because that is the order of specificity: a
# locally built image for this version is the one this node was told to use.
#
# Native only. The refusals above take the image path away, and nothing
# installs a package without a replacement; these are it:
#
#   package-available <version> is that exact version installable from this
#                               host's own repositories, changing nothing
#   package-latest              the newest version those same repositories
#                               offer, in package-available's three fields.
#                               The "is there an upgrade" question, which on a
#                               container is a registry tag read
#                               Both answer `retired` instead when the only
#                               source offering the package is the retired
#                               repos.ripple.com (#802), naming the fix
#   package-install <version>   install it, and print what the package manager
#                               resolved and what the package database now says
#   package-install --from <path>
#                               install from an artefact this wrapper kept
#                               (below) instead of asking a repository, for the
#                               version the repository no longer offers. The
#                               path must be one this wrapper's own
#                               package-keep wrote; nothing else is accepted
#   package-keep                copy the package CURRENTLY installed into this
#                               wrapper's own backup directory, beside the
#                               config backups, before an upgrade replaces it.
#                               Records the path, the version and a sha256,
#                               issue #393's second half. Idempotent: kept
#                               once per version, never re-fetched
#   package-kept                the artefacts package-keep is holding, and
#                               whether each still matches the sha256 recorded
#                               when it was kept
#   package-version             what is installed right now, from the package
#                               database; the before-and-after comparison that
#                               replaces running-digest
#
# Read-only inspection. These change nothing; they exist so the Advisor can
# answer a question about this host instead of asking the operator to paste
# something. Each one is a permanent widening of what it can see, so the list
# is short and every entry is here because a real question needed it.
#
#   inspect                     the deployment, for the profile: docker inspect
#                               on a container, systemctl show plus the
#                               installed package version on a native host
#   config-readable             can the node read its own config file
#   show-config                 the node config, with key material REMOVED HERE
#   show-validators             the configured validator list file
#   show-toml                   the domain-verification file this node serves
#   disk                        free space on the node's data path
#   store-size                  how many bytes the ledger store is using, as
#                               root. A native node's state directory is 0750
#                               and owned by the node's own account, so the
#                               account serving the dashboard cannot even
#                               traverse it, and a walk it could not take was
#                               being shown as 0 B. Prints AperireStorePath
#                               and AperireStoreBytes, or the word unknown
#                               with one AperireStoreReason line. A number
#                               crosses, never a listing
#   store-headroom              free space on the filesystem the ledger store
#                               sits on, as root, measured on the store's own
#                               path so a store on its own volume reports its
#                               own mount. Prints AperireHeadroomPath,
#                               AperireHeadroomTotalBytes and
#                               AperireHeadroomAvailBytes, or the word unknown
#                               with one AperireHeadroomReason line
#   node-log <n>                last n lines the node emitted
#   sysctl-relevant             the kernel settings that affect a validator
#   limits                      the node process's actual resource limits
#   unit-status                 systemd state of the Aperire units
#   resources                   memory, swap, load, uptime
#   journal <n>                 last n journal lines for the Aperire units
#   rotation-state [--wait]     is the ledger store mid-rotation right now.
#                               Bare, the log read has a time limit; with
#                               --wait it has none, as the stop guard reads
#   rotation-window             how far the store is from its NEXT rotation:
#                               the last rotated sequence, the configured
#                               online_delete and the node's validated
#                               sequence, so a caller can tell whether a
#                               swap would land inside one. rotation-state
#                               answers about now; this answers about soon.
#                               The last rotation is read over 24 hours by
#                               time, not by a line count, and a read that
#                               could not reach back that far says so.
#                               It also says how many seconds ago that
#                               rotation finished (#833). Every log read
#                               it and rotation-state make has a time
#                               limit (#1043).
#                               Both shapes: a native node reads its unit's
#                               declared log and its admin port (#832)
#   image-headroom              free space where docker keeps its images,
#                               which is not the node's data path and is
#                               where a build writes
#   recipe-state                is the xrpld image recipe installed here,
#                               and would this wrapper build from it. The
#                               same checks build-image makes, taken as a
#                               read so the card can refuse BEFORE an
#                               operator approves anything (#675)
#   can-delete-timer            is the daily rotation window (aperire-can-delete.timer)
#                               installed and enabled on this host, and when it ran
#   artefact-hashes <what>      digests of the node config (both shapes), or of
#                               the deployment definition (container only)
#
# Anything else exits 64 without running.
#
# ── Store rotation ────────────────────────────────────────────────────────
#
# rippled prunes by ROTATING its NuDB store: it copies the current state map
# forward, swaps in a new writable backend and deletes the old one. A node
# stopped inside that window came back with an empty store and rebuilt from
# genesis (issue #79, stock-node1, 2026-08-25), a clean SIGTERM inside the
# stop grace was not enough.
#
# Two mechanisms keep a stop out of that window, and they are deliberately
# independent:
#
#   1. A lock. /run/aperire/node-rotation.lock is held by the scheduled
#      rotation window (aperire-can-delete.service) for as long as it is
#      arming or watching a rotation. restart and recreate take it too, so
#      the two cannot run at once.
#   2. The node's own log. Whatever started a rotation, our timer, a hand
#      call to can_delete, or a node still on advisory_delete=0 that rotates
#      by itself, rippled says "rotating" when it starts and "finished
#      rotation" when it ends. This reads those, and refuses on the first
#      without the second.
#
# The lock alone would trust that nothing else ever rotates. The log alone
# would race the moment between arming and the first log line. Both, and
# neither hole is open.
#
# WHICH log is read is the shape's business. A container has one answer,
# `docker logs`. A native host has two, the journal or the file the node's
# config names, so it is DECLARED in NODE_LOG_SOURCE rather than searched for.
# A search that misses answers "unknown" to every read, the log half of the
# guard goes quiet, and the guard silently becomes the lock alone, which this
# file's own reasoning above says is not enough. So the declared source is
# checked when this configuration is read (a path must exist and be a regular
# file, `journal` needs journalctl on this host and a unit that resolves), and
# the native "unknown" verdict says in its own words that the guard is down to
# the lock alone. That the source ANSWERS is a stronger claim, proven once by
# the installer with a real read, not here.
set -euo pipefail

# 0027: files 0640, directories 0750.
#
# This script runs as root in its own service behind the Advisor's socket
# (it ran through sudo before ADR 0025), and neither carries the calling
# service's UMask across, so the log below was once created world-readable
# even with UMask=0027 on the unit. What it records is every privileged verb
# and its arguments, which is an audit trail and nobody else's business.
umask 0027

# ── Fixed configuration. The executor supplies none of this. ──────────────
#
# The values used to be written into this file, which meant the recommended
# setup could not be installed: every operator's paths differ, so everyone
# would have had to hand-edit a security file to use it, making the *less*
# safe mode the path of least resistance. They now come from a config written
# by `scripts/install-node-wrapper.sh` from the deployment the Advisor already
# knows how to discover.
#
# ONE path, absolute, no fallback and no environment override. A search order
# would let anything that can write the repository, which is what the service
# account can do outside the hardened unit, plant a config this script would
# then honour, and the claim at the top of this file, that every path is fixed
# somewhere the executor cannot write, would quietly stop being true. If the
# file is missing, this script stops. It does not guess: a wrapper that
# invents paths is worse than one that refuses.
CONF=/etc/aperire/node-wrapper.conf
# A second instance on the same host needs its own configuration: the file
# names the node, the compose file and the evidence log, all of which differ
# per instance, sharing one meant the first instance's wrapper logged into
# the second's evidence directory, which its sandbox correctly refused.
#
# The instance's path is derived from THIS SCRIPT'S OWN location, which is
# still not a search order and still not an override: each instance has its
# own root-owned copy of this script, /usr/local/sbin/aperire-node-wrapper-
# <instance> (ADR 0024), and that instance's socket unit pins that exact
# path (ADR 0025). Nothing
# the Advisor account can write decides which configuration is read, and
# /etc/aperire is root-only. The default instance's copy has no slugged file
# and reads CONF above.
_wrapper_self="$(realpath "${BASH_SOURCE[0]}" 2>/dev/null || printf '%s' "${BASH_SOURCE[0]}")"
_wrapper_slug="$(printf '%s' "$_wrapper_self" | sha256sum | cut -c1-12)"
if [[ -r "/etc/aperire/node-wrapper-${_wrapper_slug}.conf" ]]; then
  CONF="/etc/aperire/node-wrapper-${_wrapper_slug}.conf"
fi

VERB=${1:-}

# gawk, by name. Stock Ubuntu and Mint ship mawk as /usr/bin/awk, and mawk
# cannot compile the secret-shape pattern in show-config: it panics, the
# redacted read comes back 3 lines instead of the config, and everything
# downstream treats "empty" as "clean" (found 2026-08-20 on a stock 24.04
# rootfs). The redaction is the security property of this script, so the
# tool that performs it is required by name, never resolved through awk.
command -v gawk >/dev/null 2>&1 || {
  echo "aperire-node-wrapper: gawk is required (mawk cannot run the redaction pattern); apt-get install gawk" >&2
  exit 1
}
ARG=${2:-}
# A third word exists for exactly one shape: `package-install --from <path>`,
# where ARG is the literal flag and this is the kept artefact's path. Every
# other verb takes at most two words, the same rule require_no_arg enforces
# on the second, applied here to the third so a caller cannot smuggle a path
# past a verb that never asked for one.
# … and for the two official-image verbs, which take a version AND the digest
# that version was pinned to at approval time. Resolving a digest at pull
# time is exactly what pinning it at approval exists to prevent, so the
# digest travels with the verb rather than being looked up here.
ARG2=${3:-}

die() { printf 'wrapper: %s\n' "$*" >&2; exit 64; }

# The ACL-carrying helper shared with every other script that rewrites a node
# artefact by temp file and rename (#545): set-config and set-image below,
# enable-advisory-delete.sh, configure-rippled-paths.sh and
# migrate-node-nonroot.sh. One implementation, sourced everywhere it is
# needed, so a second copy of it is never how the fix drifts from the bug it
# exists to close.
#
# Sourced lazily, by the two verbs that actually call into it, rather than
# unconditionally at the top of every invocation. This file is one of a
# handful the Advisor calls by name for every node operation, including the
# read-only ones (status, show-config, backup-config, image-digest, ...), and
# a deploy that updates this wrapper without also shipping its library would
# otherwise take every verb down on the source line above, read-only ones
# included, over a helper only two of them need.
#
# ONE path, root-owned, outside the install tree (ADR 0024). This used to be
# the file beside this script, and root sourced it from a checkout the
# dashboard's account can write, which is root for that account the next
# time the Advisor asked for set-config. scripts/install-node-wrapper.sh
# places it from the tree after checking no service account can write the
# copy it reads, and an update refreshes it on any host where this wrapper is
# configured, including one whose sudo rule still names the tree.
CWL_LIB=/usr/local/lib/aperire/config-write-lib.sh
require_cwl() {
  [[ -r "$CWL_LIB" ]] \
    || die "$VERB needs $CWL_LIB, which is missing (it carries a config's ACL through a rewrite); every other verb still works. Place it with: curl -fsSL https://get.aperire.one | bash -s -- --update --force"
  # shellcheck source=scripts/config-write-lib.sh
  . "$CWL_LIB"
}

# ADR 0024, lane 6a. Root runs the compose file (docker compose up, restart)
# and writes it and the node config (every verb below that edits one), so a
# service account that can change either, or a directory on the way to it,
# can have root do what it likes. These are the same two checks the update
# makes before a root copy (scripts/trusted-path-lib.sh), loaded from the one
# root-owned copy the installer places, never from beside this script.
#
# The tree is what the pre-migration tolerance is judged against: a host whose
# dashboard still runs as the operator's login, which also owns the install
# tree, is let through with the same warning the update prints, and anything
# else that a service account can write is refused. It comes from root's own
# update configuration, then from the dashboard unit's working directory.
# Without either the tolerance cannot apply, so such a host refuses.
#
# Verbs that only read a file as data do not call this, and neither does a
# native restart or package-install, which hand the unit to systemd and never
# read the compose file or the config themselves.
TPL_LIB=/usr/local/lib/aperire/trusted-path-lib.sh
TPL_CONF_DIR=/etc/aperire
TPL_PROC_DIR=/proc
TPL_UPDATE_CONF=/etc/aperire/update.conf

trusted_tree() {
  local t u wd
  t="$(awk -F= '$1=="INSTALL_DIR"{sub(/^[^=]*=/,""); print; exit}' "$TPL_UPDATE_CONF" 2>/dev/null || true)"
  if [[ "$t" == /* && -d "$t" ]]; then printf '%s' "$t"; return 0; fi
  for u in aperire-server aperire-read; do
    wd="$(systemctl show -p WorkingDirectory --value "$u.service" 2>/dev/null || true)"
    wd="${wd#WorkingDirectory=}"
    if [[ "$wd" == */dashboard && -d "$wd" ]]; then printf '%s' "${wd%/dashboard}"; return 0; fi
  done
  return 0
}

# The compose file with its comments taken out, quote-aware: a # starts a
# comment only outside a quoted value and after whitespace or at a line's
# start. A quote opens at any ' or " outside one, which YAML does not do: in
# a plain value (it's, x"y) the quote is just text. One stray quote only
# makes the rest count as quoted, which is the safe direction, but a second
# one flips the awk's phase against YAML's and a real quoted ' #' reads as a
# comment that hides the keys after it. So a comment is dropped only when
# the text it would drop holds no quote character at all; compose can't read
# a key from a tail like that, because it takes a quote to close YAML's own.
# A comment with a quote in it stays, which can only make the check refuse
# more. Inside a double quote a backslash takes the next character with it;
# inside a single quote '' closes and reopens.
_yaml_without_comments() { # $1 = the file
  LC_ALL=C awk -v dq='"' -v sq="'" -v bs="\\\\" '
    { out = ""; n = length($0)
      for (i = 1; i <= n; i++) {
        c = substr($0, i, 1)
        if (q == dq) { out = out c; if (c == bs) { i++; out = out substr($0, i, 1) } else if (c == dq) q = ""; continue }
        if (q == sq) { out = out c; if (c == sq) q = ""; continue }
        if (c == "#" && (i == 1 || substr($0, i - 1, 1) ~ /[ \t]/)) { t = substr($0, i); if (index(t, dq) || index(t, sq)) out = $0; break }
        if (c == dq || c == sq) q = c
        out = out c
      }
      print out
    }' "$1"
}

require_trusted_inputs() { # $@ = the files this verb will make root run, obey or rewrite
  local f tree rc key dash_login acct
  [[ -r "$TPL_LIB" ]] \
    || die "$VERB needs $TPL_LIB, which is missing (it decides whether a service account can change a file root is about to obey); every read-only verb still works. Place it with: curl -fsSL https://get.aperire.one | bash -s -- --update --force"
  # shellcheck source=scripts/trusted-path-lib.sh
  . "$TPL_LIB"
  # Root's own places, whatever the environment says. Read by the library.
  # shellcheck disable=SC2034
  TP_CONF_DIR=$TPL_CONF_DIR
  # shellcheck disable=SC2034
  TP_PROC_DIR=$TPL_PROC_DIR
  tree="$(trusted_tree)"
  trusted_path_hold_accounts "$tree" \
    || die "$VERB refused: $(tp_accounts_refusal 2>/dev/null || printf 'the account check could not run'), so the service accounts are unknown and whether one can change $* cannot be judged"
  # The compose file is not the only file compose obeys. It loads
  # <its directory>/.env on its own (this wrapper passes -f and nothing
  # else), so that file is judged with it when it exists.
  local -a judged=("$@")
  for f in "$@"; do
    if [[ "$f" == "${COMPOSE_FILE:-}" && ( -e "${f%/*}/.env" || -L "${f%/*}/.env" ) ]]; then
      judged+=("${f%/*}/.env")
    fi
  done
  for f in "${judged[@]}"; do
    rc=0
    trusted_path_check "$f" "$tree" || rc=$?
    case "$rc" in
      0|3) ;;
      2) trusted_path_release_accounts
         # The migration moves the dashboard off a login. A dashboard that
         # already has its own account (aperire-dashboard, no shell) gets the
         # fix below instead: the write is what has to go (#920).
         dash_login=0
         if [[ "${TP_REPORT_ROLES:-}" == " dashboard " ]]; then
           dash_login=1
           while IFS= read -r acct; do
             _tp_is_login "${acct% (*}" || dash_login=0
           done <<<"${TP_REPORT_ACCTS//, /$'\n'}"
         fi
         if [[ $dash_login -eq 1 ]]; then
           die "$VERB refused: ${TP_REPORT_ACCTS:-a service account} can change $f or a directory above it (named above), so root will not run or rewrite it; migrate-dashboard-account.sh moves the dashboard off the operator's login"
         fi
         die "$VERB refused: ${TP_REPORT_ACCTS:-a service account} can change $f or a directory above it (named above), so root will not run or rewrite it; give that file and the directories above it to root, or take the write away from the account named, then run this again" ;;
      *) trusted_path_release_accounts
         die "$VERB refused: $f could not be checked (named above)" ;;
    esac
  done
  # What the compose file pulls in is read by compose as root too, and the
  # wrapper can only judge files it can name. Refusing is the simple answer:
  # the shipped template and a hand-built prod file use none of these keys.
  if [[ -n "${COMPOSE_FILE:-}" && -r "$COMPOSE_FILE" ]]; then
    for f in "$@"; do
      [[ "$f" == "$COMPOSE_FILE" ]] || continue
      # A line pattern is a denylist against a YAML parser, so this refuses
      # the YAML features the template never uses rather than chase every
      # way to spell a key: tags, anchors, aliases, `? ` complex keys, an
      # escape (a backslash that is not part of \\ or \"), and a file that is
      # not plain bytes (UTF-16 reads as no lines at all). A file-loading key
      # counts only in key position: at the start of a line (after an
      # optional `- `), or after a { or a comma. A value that merely holds the
      # word (an image named xrpld-build:1, a volume /srv/build:/b) is not one.
      # Comments come out first, but only where the text is outside a quote:
      # a line starting with # inside a quoted value that runs over lines is
      # part of the value, and dropping it would hide a key.
      local keyp tagp
      keyp='(^[[:space:]]*(-[[:space:]]+)?|[{,][[:space:]]*)["'"'"']?(include|extends|env_file|label_file|build)["'"'"']?[[:space:]]*:'
      tagp='(^|[[:space:]{,:[-])([&*][[:alnum:]_.-]|![^[:space:]]|[?]([[:space:]]|$))'
      # A key in key position is named first, since that is what the
      # operator can act on; a tag, an anchor and the rest are named when no
      # key is.
      key="$(_yaml_without_comments "$f" 2>/dev/null \
        | LC_ALL=C sed -e 's/\\\\//g' -e 's/\\"//g' \
        | LC_ALL=C grep -m1 -oE -e "$keyp" \
        | head -n1 || true)"
      if [[ -z "$key" ]]; then
        key="$(_yaml_without_comments "$f" 2>/dev/null \
          | LC_ALL=C sed -e 's/\\\\//g' -e 's/\\"//g' \
          | LC_ALL=C grep -m1 -oE -e "$tagp|\\\\" \
          | head -n1 || true)"
      fi
      [[ $(LC_ALL=C tr -d '\000' < "$f" | wc -c) -eq $(wc -c < "$f") ]] || key=encoding
      if [[ -n "$key" ]]; then
        trusted_path_release_accounts
        case "$key" in
          *:)
            key="${key//[^a-z_]/}"
            die "$VERB refused: $f uses ${key}, which has compose read other paths as root, and the wrapper judges only the files it can name; put what it pulls in into the compose file itself" ;;
          encoding)
            die "$VERB refused: $f is not plain text (it holds a NUL byte, as a UTF-16 file does), so what it names cannot be read line by line, and the wrapper judges only the files it can name; save it as UTF-8" ;;
          *)
            die "$VERB refused: $f uses a YAML tag, anchor, alias, ? key or backslash escape, any of which can spell one of include, extends, env_file, label_file or build, and the wrapper judges only the files it can name; write the keys out plainly" ;;
        esac
      fi
    done
  fi
  trusted_path_release_accounts
}

if [[ -n "$ARG2" ]]; then
  case "$VERB" in
    package-install) [[ "$ARG" == "--from" ]] || die "$VERB takes no third argument" ;;
    pull-official|set-image-official|image-provenance|image-version|image-digest|verify-official-image) ;;
    # restore-compose takes the version the copy must name, so a copy
    # naming another release is refused rather than restored (#682,
    # second review).
    restore-compose) ;;
    *) die "$VERB takes no third argument" ;;
  esac
fi

# Two verbs ask nothing about this host's node: they are about an IMAGE and
# the signed package chain. They must work before a node exists, because a
# fresh install checks an image before it writes the deployment that would
# have produced this configuration. Everything else still refuses without
# it (#682, second review).
case "$VERB" in
  verify-official-image|pull-official)
    [[ -f "$CONF" ]] || CONFLESS=1
    ;;
esac
[[ -n "${CONFLESS:-}" ]] || [[ -f "$CONF" ]] \
  || die "no configuration at $CONF, run: curl -fsSL https://get.aperire.one | bash -s -- --node-wrapper (a node in docker) or curl -fsSL https://get.aperire.one | bash -s -- --node-wrapper-native (a node run by systemd)"
[[ -n "${CONFLESS:-}" ]] || [[ -r "$CONF" ]] || die "$CONF is not readable by $(id -un)"

# Read, do not source. Sourcing would execute whatever the file contains, so a
# configuration file and a shell script would be the same thing, and this
# script exists precisely to keep the set of possible operations finite and
# readable. Every key is expected, every value is checked against a shape, and
# anything else stops the run.
REPO='' SERVICE='' PROJECT='' COMPOSE_FILE='' CONFIG_FILE='' ADMIN_RPC='' LOG=''
# Optional: the inspection verbs use these, the upgrade verbs do not. An older
# configuration without them still drives an upgrade; only the verb that needs
# a missing value refuses, and says which one.
DATA_PATH='' VALIDATORS_PATH='' TOML_URL=''
# The deployment shape, and the one log source a native node's rotation check
# reads. KIND is absent on every configuration written before it existed, and
# those are all containers, so absent means container. NODE_LOG_SOURCE has no
# meaning on a container, where docker is the log.
KIND='' NODE_LOG_SOURCE=''
# A last line with no newline after it is still a line: `read` returns false
# on it with the text already in $line, and dropping it let the wrapper and
# the Advisor's account installer read two different files out of one (#806,
# a SERVICE=none on that line was "none" to the installer and the line before
# it to this parser). And a key set twice is refused, so no reader's choice
# of first or last can matter.
_seen_keys=' '
while IFS= read -r line || [[ -n "$line" ]]; do
  [[ -z "$line" || "$line" == \#* ]] && continue
  key=${line%%=*}
  val=${line#*=}
  [[ "$line" == *=* ]] || die "$CONF: not a key=value line: $line"
  case "$key" in
    REPO|SERVICE|PROJECT|COMPOSE_FILE|CONFIG_FILE|ADMIN_RPC|LOG|DATA_PATH|VALIDATORS_PATH|TOML_URL|KIND|NODE_LOG_SOURCE)
      [[ "$_seen_keys" != *" $key "* ]] || die "$CONF: '$key' is set more than once"
      _seen_keys+="$key "
      printf -v "$key" '%s' "$val" ;;
    *) die "$CONF: unexpected key '$key'" ;;
  esac
done < <(if [[ -n "${CONFLESS:-}" ]]; then :; else cat "$CONF"; fi)

# The shape, before anything is checked against it. Unrecognised stops here
# rather than reading as a container: "KIND=Native" silently becoming a
# container is a compose verb reaching a host that has no compose file.
KIND=${KIND:-container}
case "$KIND" in
  container|native) ;;
  *) die "$CONF: KIND '$KIND' is not container or native" ;;
esac

# A host with no node. An aggregator (a dashboard watching other nodes) still
# wants the Advisor's HOST reads, unit state, the journal, memory, disk, and
# has nothing for the node verbs to act on. `SERVICE=none` says so in the one
# place the wrapper is configured; the node verbs then refuse with that fact
# rather than a config error, and the host verbs work. Found 2026-08-19: the
# lab aggregator's Advisor could not read its own relay's journal because the
# only way to get a wrapper config was an installer that needs a container.
NODELESS=0
[[ "$SERVICE" == "none" ]] && NODELESS=1
require_node() {
  (( NODELESS )) && die "this host runs no node (SERVICE=none in $CONF); '$VERB' needs one"
  return 0
}

# The same pattern, one shape further in. The compose-only verbs are image
# reads and compose-file edits, and a native host has neither, so they refuse
# with that fact. Without this they would die in the parser above, on a
# COMPOSE_FILE that is absent because it is SUPPOSED to be absent, and the
# operator would go looking for a broken configuration instead of reading
# "there is no compose file here".
require_container() {
  [[ "$KIND" == container ]] || die "this node is a native package install (KIND=native in $CONF): there is no compose file and no image, so '$VERB' has nothing to act on"
}

# And its mirror, for the three package verbs.
require_native() {
  [[ "$KIND" == native ]] || die "this node is a container deployment (KIND=container in $CONF): it is driven by images, not by a package, so '$VERB' has nothing to act on"
}

# Shapes, not escaping, the same rule the verbs below follow for arguments.
# A value that is not what it claims to be is rejected here rather than
# reaching docker, systemctl, the package manager or the filesystem in some
# quoted form. Every message names the kind it is checking against, so an
# operator reading a refusal knows which half of the table applies.
#
# What both shapes share: the node's own config, this script's evidence log,
# and the loopback admin endpoint.
# None of this describes a host with no node. The two verbs allowed there
# touch an image and the signed package chain, and every value below is
# about a node that does not exist yet (#682, second review). Skipped as a
# block rather than loosened line by line, so the shapes a real
# configuration must have stay exactly as strict as they were.
if [[ -z "${CONFLESS:-}" ]]; then
[[ "$CONFIG_FILE"  == /* ]] || die "$CONF: CONFIG_FILE must be an absolute path"
[[ "$LOG"          == /* ]] || die "$CONF: LOG must be an absolute path"
[[ "$ADMIN_RPC" =~ ^http://(127\.0\.0\.1|localhost|\[::1\]):[0-9]+$ ]] \
  || die "$CONF: ADMIN_RPC '$ADMIN_RPC' must be loopback"
if [[ "$KIND" == container ]]; then
  [[ "$REPO"      =~ ^[a-z0-9._/-]+$ ]]        || die "$CONF: REPO '$REPO' is not an image repository"
  [[ "$SERVICE"   =~ ^[A-Za-z0-9._-]+$ ]]      || die "$CONF: SERVICE '$SERVICE' is not a container name"
  [[ "$PROJECT"   =~ ^[A-Za-z0-9._-]+$ ]]      || die "$CONF: PROJECT '$PROJECT' is not a compose project"
  [[ "$COMPOSE_FILE" == /* ]]                  || die "$CONF: COMPOSE_FILE must be an absolute path"
else
  # A package name, in the shape both dpkg and rpm accept: lower case, digits,
  # and +-._ inside. Not a path, not a URL, and nothing a shell would read as
  # anything but a word.
  [[ "$REPO" =~ ^[a-z0-9][a-z0-9+._-]*$ ]] \
    || die "$CONF: KIND=native, so REPO '$REPO' must be a package name (xrpld, rippled), not an image repository"
  # A systemd unit, named in full. The suffix is required rather than assumed:
  # "systemctl restart xrpld" would take a unit this file never named if a
  # xrpld.timer or xrpld.socket existed beside it.
  [[ "$SERVICE" =~ ^[A-Za-z0-9:@._-]+\.service$ ]] \
    || die "$CONF: KIND=native, so SERVICE '$SERVICE' must be a systemd unit name ending in .service (xrpld.service)"
  # Absent, not empty-and-ignored. A configuration naming both a unit and a
  # compose deployment describes two shapes, and nobody measured that host.
  [[ -z "$PROJECT" ]] \
    || die "$CONF: KIND=native, so PROJECT must be absent; this host has no compose project, and '$PROJECT' names one"
  [[ -z "$COMPOSE_FILE" ]] \
    || die "$CONF: KIND=native, so COMPOSE_FILE must be absent; this host has no compose file, and '$COMPOSE_FILE' names one"
  # The rotation guard's log half, declared. Refused here, where an operator
  # is reading a message, rather than answered "unknown" at every restart.
  case "$NODE_LOG_SOURCE" in
    journal)
      command -v journalctl >/dev/null 2>&1 \
        || die "$CONF: NODE_LOG_SOURCE=journal, but journalctl is not on this host, so the store-rotation guard could never read a log" ;;
    /*)
      [[ -e "$NODE_LOG_SOURCE" ]] \
        || die "$CONF: NODE_LOG_SOURCE $NODE_LOG_SOURCE does not exist, so the store-rotation guard would answer unknown at every restart"
      [[ -f "$NODE_LOG_SOURCE" ]] \
        || die "$CONF: NODE_LOG_SOURCE $NODE_LOG_SOURCE is not a regular file" ;;
    '')
      die "$CONF: KIND=native needs NODE_LOG_SOURCE: 'journal', or the absolute path from the node config's [debug_logfile]" ;;
    *)
      die "$CONF: NODE_LOG_SOURCE '$NODE_LOG_SOURCE' must be 'journal' or an absolute path" ;;
  esac
fi
fi
# The files this script edits and copies have to exist now, not at the moment
# of an upgrade. Detection wrote these paths; if they have since moved, that is
# a stale profile, and RB-001 should not be the first thing to notice. On a
# node-less host these name nothing (the installer writes /dev/null); the node
# verbs that would use them refuse earlier, at require_node.
if (( ! NODELESS )) && [[ -z "${CONFLESS:-}" ]]; then
  [[ "$KIND" != container || -f "$COMPOSE_FILE" ]] \
    || die "$CONF: COMPOSE_FILE $COMPOSE_FILE does not exist"
  [[ -f "$CONFIG_FILE" ]] || die "$CONF: CONFIG_FILE $CONFIG_FILE does not exist"
fi

# The value a stanza-shaped setting holds right now.
#
# rippled.cfg has two shapes and only one of them is a key=value line. A
# stanza-shaped setting is a header on its own line with its value on the next
# line that carries anything:
#
#   [node_size]
#   huge
#
# Blank and comment lines between the two are skipped; the next section header
# ends the search, because a stanza with no value line of its own is a stanza
# with no value, not one that borrows the next section's. Prints nothing when
# there is no value, which is how the caller tells the two apart.
#
# The resync matrix tool has been doing the same replace by hand with
# `sed '/^\[node_size\]/{n;s/.*/…/}'` since the node-size matrix runs, so this
# is the file's real layout and not an assumption about it. That sed takes the
# very next line whatever it is; this skips blanks and comments first.
stanza_value() { # $1 = file, $2 = stanza name
  awk -v k="$2" '
    BEGIN { inb = 0 }
    $0 ~ "^[[:space:]]*\\[" k "\\][[:space:]]*$" { inb = 1; next }
    inb {
      if ($0 ~ /^[[:space:]]*$/ || $0 ~ /^[[:space:]]*#/) next
      if ($0 ~ /^[[:space:]]*\[/) exit
      sub(/^[[:space:]]+/, ""); sub(/[[:space:]]+$/, "")
      print; exit
    }
  ' "$1"
}

# The audit line, and the two things that go wrong with it.
#
# This wrapper runs as two different accounts on the same host: as root for
# everything that acts (through sudo, which does not drop into the calling
# account), and as the Advisor's own account for everything that only reads.
# Whichever of them gets here FIRST creates the log, with its own ownership
# and the default 0640. On aperire4 that was a root run, and from then on
# every read-only verb died on "Permission denied" writing the one line it
# logs before it does anything: `docker-disk`, `rotation-window`,
# `backup-state` and `compose-state` all failed, and the Operations card
# rendered four of its preconditions off that single error (#679).
#
# So: the log is created group-writable and owned by the directory it lives
# in, which is the Advisor's own evidence directory, and a root run repairs
# a log it finds owned by root inside somebody else's directory. That is the
# cause.
#
# And the guard: a log this run cannot write NEVER stops the verb. It says
# so on stderr, loudly, and carries on. An audit line that cannot be
# appended is worth knowing about; it is not worth turning every read of the
# host into a failure a caller upstream renders as a verdict.
# Root never writes this file. That is the rule, and it is the whole of why
# the code below is shaped the way it is.
#
# The log sits inside a directory the Advisor's own account owns, and that
# account is the one that can make this wrapper run as root whenever it
# likes. So a root run that opened, created or chmod'ed a path in there
# would be root following whatever that account had just put at the name:
# swap the log for a link to /etc/shadow between the check and the write and
# retry until root loses the race. Same class as #657, and a repair is not
# worth a root primitive.
#
# So when this runs as root inside somebody else's directory, every part of
# it happens AS that account, through runuser: the rename, the create and
# the append. A link then reaches only what the account could already reach,
# and the file it makes is its own. Root does not chown, chmod, create or
# append here at all.
#
# The repair used to be a root `chown -h`. `-h` stops root following a
# SYMLINK, and does nothing about a HARD link: that account can hard-link
# any file it can read into its own directory under the log's name, and the
# chown then hands it that file. A rename needs no privilege in a directory
# the account owns, so root has no part to play.
log_owner_of() { stat -c "%$1" "$2" 2>/dev/null || true; }

# The one repair, and its only case: a REGULAR file owned by root, sitting
# in a directory owned by somebody else. That is what an earlier root run of
# this wrapper leaves behind, and what left every read-only verb on aperire4
# failing before it ran (#679). It is moved aside, by the account that owns
# the directory, and the next line starts a fresh log that account owns.
# Moved rather than removed: it is an audit trail, and an audit trail is not
# something this script deletes.
log_hand_back() { # $1 = directory owner
  local logowner
  [[ ! -L "$LOG" && -f "$LOG" ]] || return 0
  logowner=$(log_owner_of U "$LOG")
  [[ "$logowner" == root ]] || return 0
  command -v runuser >/dev/null 2>&1 || return 0
  # shellcheck disable=SC2016  # the inner sh's own $1 and $2, passed after --
  runuser -u "$1" -- /bin/sh -c 'mv -f -- "$1" "$1.root-owned-$2" 2>/dev/null' \
    _ "$LOG" "$(date -u +%Y%m%d-%H%M%S)" 2>/dev/null \
    && printf 'wrapper: note: %s was owned by root inside a directory owned by %s. It was moved aside and a new one started.\n' \
         "$LOG" "$1" >&2
  return 0
}

log_cannot_write() {
  printf 'wrapper: warning: this run could not be written to %s, so it is not in the wrapper log. The verb ran anyway.\n' \
    "$LOG" >&2
}

log() {
  local dir owner line
  # No log path, no logging. The verbs that run before a node exists
  # (verify-official-image, pull-official) have no configuration to name one,
  # and "> ''" is a redirection bash reports on the real stderr before any
  # 2>/dev/null on the command can apply (#1004).
  [[ -n "$LOG" ]] || return 0
  dir=$(dirname "$LOG")
  line="$(date -Is) $VERB ${ARG:-}"
  owner=$(log_owner_of U "$dir")

  # No directory, and root. Root does not create one here: the evidence
  # directory belongs to the Advisor's account, and a root mkdir would put
  # a root-owned directory in a tree that account has to write, which is
  # the same lockout this whole block exists to end. The installer makes
  # it; until then the run says so and carries on.
  if [[ $EUID -eq 0 ]] && { [[ ! -d "$dir" ]] || [[ -z "$owner" ]]; }; then
    printf 'wrapper: warning: %s is not a directory this run can read the owner of, so it was not logged. Root does not create or write one here: it belongs to the account the Advisor runs as.\n' \
      "$dir" >&2
    return 0
  fi
  if [[ $EUID -eq 0 && -n "$owner" && "$owner" != root ]]; then
    log_hand_back "$owner"
    # umask 0007: the next run, whichever account it is, has to be able to
    # append to what this one creates. That is the whole fix for the two
    # accounts locking each other out.
    # As that account, with no_new_privs where this host can set it and no
    # terminal to read from: the drop runs outside any sandbox now that the
    # wrapper is its own root service (#779 review, L6).
    local -a nnp=()
    if command -v setpriv >/dev/null 2>&1 && setpriv --no-new-privs true 2>/dev/null; then
      nnp=(setpriv --no-new-privs)
    fi
    # shellcheck disable=SC2016  # the inner sh's own $1 and $2, passed after --
    if command -v runuser >/dev/null 2>&1 &&
       runuser -u "$owner" -- ${nnp[@]+"${nnp[@]}"} /bin/sh -c 'umask 0007; printf "%s\n" "$1" >> "$2" 2>/dev/null' _ "$line" "$LOG" </dev/null 2>/dev/null; then
      return 0
    fi
    log_cannot_write
    return 0
  fi

  # Running as the account that owns the place, or as root in root's own
  # directory: write it directly, and create it group-writable.
  mkdir -p "$dir" 2>/dev/null || true
  # Asked before it is attempted, not caught afterwards. A redirection bash
  # cannot open prints bash's own "Permission denied" to stderr before any
  # 2>/dev/null on the command can apply to it, and two lines about one
  # fact (one of them naming a line number in this file) is not what a
  # caller should read out of a verb that worked.
  if [[ -L "$LOG" ]]; then
    printf 'wrapper: warning: %s is a symlink, so this run was not logged\n' "$LOG" >&2
    return 0
  fi
  if [[ -w "$LOG" ]]; then
    printf '%s\n' "$line" >> "$LOG" 2>/dev/null || true
    return 0
  fi
  if [[ ! -e "$LOG" && -w "$dir" ]]; then
    ( umask 0007; printf '%s\n' "$line" >> "$LOG" 2>/dev/null ) || true
    return 0
  fi
  log_cannot_write
}

# ── Store rotation ────────────────────────────────────────────────────────
# Constants, not configuration. They are here so that anyone auditing what
# this script refuses reads one file, and because a rotation window that an
# operator can widen from a config file is not a boundary.

# How far back to read the node's log. A rotation that started before this
# has either finished or been abandoned; a day covers both with room.
ROTATION_LOOKBACK=24h
# The same window in seconds, for judging a stamp against it.
ROTATION_LOOKBACK_SECONDS=$(( ${ROTATION_LOOKBACK%h} * 3600 ))
# How many lines from the END of the log that read is allowed to touch.
# --since alone does not bound the read: the json-file driver has no index,
# so docker scans the whole file and filters afterwards, and on validator1
# an unrotated 2.9GB container log made every rotation-state read (and so
# every readiness check behind it) take 35 seconds, measured 2026-08-28.
# --tail seeks from the end, which bounds the I/O; --since still bounds the
# WINDOW. This bound is for rotation-state, which only has to see back past
# ROTATION_STALE_MIN: a "rotating" line older than that is already stale by
# the rule below. It was sized at eight times that horizon's log volume. The
# chattiest node measured since writes about 15,000 lines in 30 minutes
# (2026-10-12), so 200,000 lines reach back about 6.7 hours there, which is
# 1.7 times the horizon rather than eight. Still past it, with less room.
ROTATION_TAIL=200000
# rotation-window needs the last FINISHED rotation in the whole 24 hours, and
# at that rate a day is about 720,000 lines. A fixed line count is the wrong
# bound for that: it reached back 6.7 hours on that node, and a rotation
# eight hours old read as none at all (#1031). So rotation-window reads by
# time. It reads the last lines with --tail, which still seeks from the end,
# and judges how far back the read reached by the oldest stamp it got. When
# that is newer than ROTATION_LOOKBACK and the log has more, it reads again,
# wider. These are the reads, in order. The widest is the ceiling: past it,
# the answer is "not measured, reached back only so far", never "none".
#
# What the reads cost, measured, and why the wider ones have a time limit:
#   docker   433,121 lines of a json-file log (50m x 3, uncompressed) read
#            back in 3.1 seconds (2026-10-12), so a million is about seven.
#            Rotated logs the template compresses cost more, not measured.
#   journald 1,000,000 lines took 121 seconds, and 200,000 about 24
#            (2026-10-12). A busy native node with no finish in its last
#            200,000 lines would spend 145 seconds here.
ROTATION_WINDOW_READS='200000 1000000'
# Every log read the upgrade and rollback check makes runs under a time limit
# of its own (#1043), through timeout(1) with a kill grace, so exit 124 or 137
# is "ran out" and never "unreadable". A read that runs out answers with what
# it can say, "not measured, reached back so far" or "unknown", never an
# error. An error renders as a check that failed to measure, which refuses
# the upgrade or rollback; a slow log is not a reason to refuse.
#
# The Advisor gives one whole check 90 seconds (checkRefreshTimeout), and
# these reads run one after another inside it. Worst case per read, as the
# limit plus the kill grace:
#
#   read                                   limit  worst  measured (2026-10-12)
#   rotation-state, its tail               25s    27s    ~19s journald
#   rotation-window, first 200,000 lines   30s    32s    ~24s journald
#   rotation-window, 1,000,000 lines       20s    22s    121s journald, ~7s docker
#   rotation-window, docker logs --tail 1   5s     7s    instant
#   rotation-window, server_info (curl)     5s     5s    instant
#
# The wider read starts only when the first read's own pace says it can
# finish inside its limit (rotation_last_finish), so it never follows a slow
# first read: it runs only after one that took under 4 seconds. The probe
# runs only on a container with no online_delete, which makes no log read
# after it. So rotation-window's worst is 32 + 5 = 37 seconds, and with
# rotation-state's 27 the reads take at most 64 of the 90. That leaves 26
# for sudo and the check's other wrapper reads (profile, image, backups),
# which are each a second or two.
#
# Only the read-only verbs are held to this. rotation_guard, in front of every
# stop, reads with no limit: a cut read there would drop the guard to the
# lock alone, and a stop can wait for its answer.
ROTATION_STATE_SECONDS=25
ROTATION_FIRST_SECONDS=30
ROTATION_WIDEN_SECONDS=20
ROTATION_PROBE_SECONDS=5
ROTATION_KILL_GRACE=2
# A "rotating" line with no ending after this long is not treated as in
# flight. Without it, one aborted rotation would refuse every restart on this
# node forever, which helps nobody.
#
# Calibrated against two real rotations on 2026-08-27/28: 40.5 minutes on
# stock-node1 (a ~118GB-used VPS disk) and 13.2 minutes on the production
# validator (NVMe). Four hours stands at roughly six times the slowest
# observed, which is the margin it should keep. It has to
# stay ABOVE the longest real rotation on this host, because past it nothing
# blocks a restart: between ROTATION_HOLD (in /etc/aperire/can-delete.conf,
# where the window gives up holding the lock) and this, the log check below is
# the only guard, and past this there is none. Measure the wall time between
# "rotating" and "finished rotation" on this node and raise both if it is
# close.
ROTATION_STALE_MIN=240
# How long to wait for the scheduled window's lock before giving up. The
# window itself is bounded (see aperire-can-delete.sh), so waiting a little
# is better than refusing a restart that could go ahead a moment later.
ROTATION_LOCK_WAIT=45
ROTATION_LOCK=/run/aperire/node-rotation.lock

# Is the node mid-rotation? Prints "<state><TAB><detail>".
#
#   rotating  a rotation started and has not reported finishing
#   stale     it started, never finished, and is older than the bound above
#   idle      the last thing the store said was that it finished, or the log
#             carries no rotation at all in the window
#   unknown   the log could not be read, so this proves nothing
#
# Only "rotating" refuses. The other three print and continue, because a
# check that cannot read its evidence must not be the thing that stops an
# operator recovering a node.
# The lines the store writes about a rotation, other than its finish. One
# pattern, whichever log it is read from, because it is the node writing them
# and not the log driver. The finish is ROTATION_FINISHED_MSG below, anchored.
ROTATION_LINES='rotating[[:space:]]+validatedSeq|online_delete rotation has been unable to make progress|Process starting'

# The line the store writes when a rotation completes, whole, to the end of
# the line. Two shapes, both from the source:
#   up to 3.3.0  "finished rotation <seq>"
#                aperire2's debug.log, 2026-10-04:
#                2026-Oct-04 04:08:25.033209494 UTC SHAMapStore:WRN finished rotation 107418600
#   from 3.4.0   "finished rotation. validatedSeq: <seq>, lastRotated: <seq>.
#                 Complete ledgers: <ranges>" (SHAMapStoreImp.cpp, 3.4.0;
#                both numbers are the same value there, lastRotated is read)
# Anchored at both ends, the start by rotation_finished_re per log source,
# because an unanchored "finished rotation" anywhere in a later line would
# win the last-match read, and both the restart guard and the upgrade's
# rotation check trust that line.
ROTATION_FINISHED_MSG='SHAMapStore:WRN finished rotation( [0-9]+|\. validatedSeq: [0-9]+, lastRotated: [0-9]+\. Complete ledgers: [^[:space:]]*)[[:space:]]*$'
# rippled's own stamp, required. xrpld formats every line the same way for
# the debug log and for stderr, so for docker and journald too (Log.cpp,
# Logs::format, 3.3.0): "<stamp> <Partition>:<SEV> <message>". The store
# writes this line at warn. A finish with no stamp in front of it is not a
# line xrpld wrote, whatever else it says.
#
# What this cannot do: xrpld does not escape a newline inside a message, so
# a logged string carrying one can start a new physical line, and a line
# shaped exactly like this one is text anyone who reaches the log can write.
# The anchoring stops a quoted or truncated imitation; rotation_window_insane
# bounds what a perfect one can move (never past the validated ledger, never
# further than online_delete), and the restart guard's lock half does not
# read the log at all.
ROTATION_NODE_STAMP='[0-9]{4}-[A-Z][a-z]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{9} UTC '

# The whole finish line for the log this host reads, from its first column.
# What comes before rippled's own text is the log driver's:
#   container  docker --timestamps:       "<RFC 3339> "
#   journal    journalctl -o short-iso:   "<ISO 8601> <host> <ident>[<pid>]: "
#   file       the node's debug_logfile:  nothing
rotation_finished_re() {
  local lead='^'
  if [[ "$KIND" == container ]]; then
    lead='^[0-9]{4}-[0-9]{2}-[0-9]{2}T[^ ]+ '
  elif [[ "$NODE_LOG_SOURCE" == journal ]]; then
    lead='^[0-9]{4}-[0-9]{2}-[0-9]{2}T[^ ]+ [^ ]+ [^ ]+\[[0-9]+\]: '
  fi
  printf '%s%s%s' "$lead" "$ROTATION_NODE_STAMP" "$ROTATION_FINISHED_MSG"
}

# The sequence a matched finish line rotated at. Prints nothing for a line
# that is not one.
rotation_finished_seq() { # $1 = a line that matched rotation_finished_re
  if [[ "$1" =~ lastRotated:\ ([0-9]+)\.\ Complete\ ledgers: ]]; then
    printf '%s\n' "${BASH_REMATCH[1]}"
  elif [[ "$1" =~ finished\ rotation\ ([0-9]+)[[:space:]]*$ ]]; then
    printf '%s\n' "${BASH_REMATCH[1]}"
  fi
}

# The timestamp at the front of a matched line, in a form GNU date will parse.
#
# docker --timestamps and journalctl --output=short-iso both put one RFC 3339
# field first. rippled's own stamps are not that shape: it writes them as
# "2026-Aug-13 04:32:01.070821912 UTC", two fields and a month in the middle,
# which GNU date refuses outright (measured here, not assumed). So the file
# case is rearranged into a form date does take, and read as UTC.
#
# What is measured and what is not: the stamp shape above is rippled's, taken
# from a server_info reading this repository keeps as a fixture. That the
# debug.log line PREFIX is the same shape is the reasonable reading and is not
# yet proven on a box; the lab run is where it gets proven, and the installer
# should prove the declared source both answers AND carries a stamp this can
# read. If it cannot, a matched "rotating" line gives an unreadable age, which
# prints "rotating" and refuses a restart until a completed rotation appears
# in the window. That is the safe direction, and it is still a refusal an
# operator would have to understand, so it is worth proving once at install.
rotation_stamp() { # $1 = the matched log line
  local f1 f2
  read -r f1 f2 _ <<< "$1"
  if [[ "$KIND" == native && "$NODE_LOG_SOURCE" != journal ]]; then
    if [[ "$f1" =~ ^([0-9]{4})-([A-Za-z]{3})-([0-9]{1,2})$ ]]; then
      printf '%s %s %s %s UTC\n' "${BASH_REMATCH[3]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[1]}" "$f2"
    else
      printf '%s %s\n' "$f1" "$f2"
    fi
    return 0
  fi
  printf '%s\n' "$f1"
}

# A matched line's time as epoch seconds, or nothing. Only the stamp shapes
# rotation_stamp produces reach date: a line is the node's text, and its first
# fields are whatever the line says.
ROTATION_ISO_STAMP='^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?(Z|[+-][0-9]{2}:?[0-9]{2})$'
ROTATION_FILE_STAMP='^[0-9]{1,2} [A-Z][a-z]{2} [0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})? UTC$'
rotation_epoch() { # $1 = a log line
  local s
  s=$(rotation_stamp "$1")
  if [[ "$s" =~ $ROTATION_ISO_STAMP || "$s" =~ $ROTATION_FILE_STAMP ]]; then
    date -d "$s" +%s 2>/dev/null || true
  fi
  return 0
}

# The last n lines of the node's log, from the end, with no --since. The
# window is judged from the stamps by rotation_last_finish, and a read bounded
# by both cannot say which bound cut it short.
#
# With a time limit in $2 the reader runs under timeout(1), which signals its
# whole process group: exit 124 when it ran out, 137 when it then had to be
# killed. The caller treats those two as "ran out", never as unreadable.
rotation_log_tail() { # $1 = how many lines, $2 = seconds allowed, or empty
  local -a lim=()
  if [[ -n "${2:-}" ]]; then
    lim=(timeout --kill-after="$ROTATION_KILL_GRACE" "$2")
  fi
  if [[ "$KIND" == container ]]; then
    "${lim[@]}" docker logs --timestamps --tail "$1" "$SERVICE" 2>&1
  elif [[ "$NODE_LOG_SOURCE" == journal ]]; then
    "${lim[@]}" journalctl --no-pager --output=short-iso --unit="$SERVICE" --lines="$1" 2>/dev/null
  else
    "${lim[@]}" tail -n "$1" "$NODE_LOG_SOURCE" 2>/dev/null
  fi
}

# "3h05m (since 2026-10-12 10:05 UTC)", for saying how far back a read reached.
rotation_reach() { # $1 = now, $2 = the oldest stamp read, both epoch seconds
  local d=$(( $1 - $2 ))
  (( d >= 0 )) || d=0
  printf '%dh%02dm (since %s)' "$(( d / 3600 ))" "$(( d % 3600 / 60 ))" \
    "$(date -u -d "@$2" '+%Y-%m-%d %H:%M UTC')"
}

# The last finished rotation inside ROTATION_LOOKBACK, read by time (#1031).
# Sets one of:
#   RF_SEQ     the sequence it rotated at: found, inside the window
#   RF_REASON  why there is none: the whole window was read and holds no
#              finish, or the read could not reach back that far and says
#              how far it did. Both are answers. No "not measured:" in
#              front: the Advisor puts that on every reason it renders.
#   RF_ERROR   the log could not be read at all: the guard is blind
# and, beside RF_SEQ, RF_AGE: how many seconds ago that finish was, by its own
# stamp, when the stamp reads. The Advisor adds it to the time left before
# the next rotation to get the quiet stretch a rotation leaves (#833).
# Each read streams through awk, which keeps three things: the line count,
# the first line that carries a stamp, and the candidate finish lines. grep
# then holds the candidates to the anchored finish and awk keeps the last.
# No regex interval in awk, because mawk before 20200717 has none. The
# status is the READER's, as everywhere else here: no match is an answer, an
# unreadable log is not.
RF_SEQ='' RF_REASON='' RF_ERROR='' RF_AGE=''
rotation_last_finish() {
  local fin now cutoff n out rc l count first raw last t where limit
  local first_n=0 first_t='' prev_n=0 prev_ms=0 t0 proj
  local -a reads
  RF_SEQ='' RF_REASON='' RF_ERROR='' RF_AGE=''
  fin=$(rotation_finished_re)
  now=$(date +%s)
  cutoff=$(( now - ROTATION_LOOKBACK_SECONDS ))
  if [[ "$KIND" == container ]]; then
    where='the node log'
  elif [[ "$NODE_LOG_SOURCE" == journal ]]; then
    where="$SERVICE's journal"
  else
    where=$NODE_LOG_SOURCE
  fi
  read -ra reads <<< "$ROTATION_WINDOW_READS"
  t='' n=0
  for n in "${reads[@]}"; do
    # Each read has its own limit (#1043): the first ROTATION_FIRST_SECONDS,
    # the wider ones ROTATION_WIDEN_SECONDS. A wider read is not started at
    # all when the last one's pace says it cannot finish inside its limit:
    # the cost is linear in lines (journald, 200,000 in ~24s and 1,000,000 in
    # 121s), and a read that is bound to run out only spends the budget.
    limit=$ROTATION_FIRST_SECONDS
    if (( first_n > 0 )); then
      limit=$ROTATION_WIDEN_SECONDS
      proj=$(( prev_ms * n / prev_n / 1000 ))
      if (( proj > limit )); then
        if [[ -z "$first_t" ]]; then
          RF_REASON="the last $first_n lines of $where carry no time this could read, and a wider read would take about ${proj}s at this log's pace, past its ${limit}s limit, so whether the store rotated in the last $ROTATION_LOOKBACK is unknown"
        else
          RF_REASON="the last $first_n lines of $where reach back only $(rotation_reach "$now" "$first_t"), short of the $ROTATION_LOOKBACK this reads, and hold no finished rotation; a wider read would take about ${proj}s at this log's pace, past its ${limit}s limit"
        fi
        return 0
      fi
    fi
    t0=$(date +%s%N)
    rc=0
    out=$(
      rotation_log_tail "$n" "$limit" \
        | LC_ALL=C awk '
            NR == 1 { print "R " substr($0, 1, 200) }
            !d && /^[0-9][0-9][0-9][0-9]-/ { print "D " substr($0, 1, 120); d = 1 }
            index($0, "finished rotation") { print "F " $0 }
            END { print "N " NR }' \
        | LC_ALL=C grep -aE "^(F ${fin#^}|[RDN] )" \
        | LC_ALL=C awk '/^F / { f = $0; next } { print } END { if (f != "") print f }'
      exit "${PIPESTATUS[0]}"
    ) || rc=$?
    prev_ms=$(( ($(date +%s%N) - t0) / 1000000 )) prev_n=$n
    count='' first='' raw='' last=''
    while IFS= read -r l; do
      case "$l" in
        'N '*) count=${l#N } ;;
        'D '*) first=${l#D } ;;
        'R '*) raw=${l#R } ;;
        'F '*) last=${l#F } ;;
      esac
    done <<< "$out"
    if (( (rc == 124 || rc == 137) && first_n == 0 )); then
      # The first read ran out of time. What it got is partial and read
      # oldest first, so a finish in it might not be the last one and its
      # oldest stamp is not how far the log reaches: nothing from it is used.
      RF_REASON="reading the last $n lines of $where ran past its ${limit}s limit, so whether the store rotated in the last $ROTATION_LOOKBACK is unknown"
      return 0
    fi
    if (( rc == 124 || rc == 137 )); then
      # A wider read ran out of time. Partial for the same reason, so
      # nothing from it is used either. The answer is the first read's reach.
      if [[ -z "$first_t" ]]; then
        RF_REASON="the last $first_n lines of $where carry no time this could read, and a wider read ran past its ${limit}s limit, so whether the store rotated in the last $ROTATION_LOOKBACK is unknown"
      else
        RF_REASON="the last $first_n lines of $where reach back only $(rotation_reach "$now" "$first_t"), short of the $ROTATION_LOOKBACK this reads, and hold no finished rotation; a wider read ran past its ${limit}s limit"
      fi
      return 0
    fi
    if (( rc != 0 )); then
      if [[ "$KIND" == container ]]; then
        # The engine's own words, so an operator reads the driver's name
        # rather than an exit status.
        RF_ERROR="this node's log could not be read (docker logs exited $rc): $(printf '%s' "$raw" | tr '\n\r\t' '   ')"
      elif [[ "$NODE_LOG_SOURCE" == journal ]]; then
        RF_ERROR="the journal for $SERVICE could not be read (journalctl exited $rc), so when the store last rotated is unknown"
      else
        RF_ERROR="$NODE_LOG_SOURCE could not be read (tail exited $rc), so when the store last rotated is unknown"
      fi
      return 0
    fi
    [[ "$count" =~ ^[0-9]+$ ]] || count=0
    if [[ -n "$last" ]]; then
      # The last finish in the log, since the read is the log's end. Judged
      # by its own stamp: a finish older than the window is not this
      # window's, and summed it would trip the gap check into an error.
      t=$(rotation_epoch "$last")
      if [[ -n "$t" ]] && (( t < cutoff )); then
        RF_REASON="no finished rotation in $where in the last $ROTATION_LOOKBACK"
        return 0
      fi
      RF_SEQ=$(rotation_finished_seq "$last")
      [[ -n "$RF_SEQ" ]] || RF_ERROR="a finished rotation in $where carried no sequence this could read"
      if [[ -n "$t" ]] && (( t <= now )); then
        RF_AGE=$(( now - t ))
      fi
      return 0
    fi
    t=''
    if [[ -n "$first" ]]; then
      t=$(rotation_epoch "$first")
    fi
    if [[ -n "$t" ]] && (( t <= cutoff )); then
      RF_REASON="no finished rotation in $where in the last $ROTATION_LOOKBACK"
      return 0
    fi
    if (( first_n == 0 )); then
      first_n=$n first_t=$t
    fi
    if (( count < n )); then
      # The read took the whole log, and the log starts inside the window:
      # a container recreated, a journal vacuumed, a file rotated. What came
      # before is not here, so this cannot say none.
      if [[ -z "$t" ]]; then
        RF_REASON="$where holds no line with a time this could read, so whether the store rotated in the last $ROTATION_LOOKBACK is unknown"
      else
        RF_REASON="$where reaches back only $(rotation_reach "$now" "$t"), short of the $ROTATION_LOOKBACK this reads, and holds no finished rotation in that time"
      fi
      return 0
    fi
  done
  # The widest read ran out before the window did.
  if [[ -z "$t" ]]; then
    RF_REASON="the last $n lines of $where carry no time this could read, so whether the store rotated in the last $ROTATION_LOOKBACK is unknown"
  else
    RF_REASON="the last $n lines of $where reach back only $(rotation_reach "$now" "$t"), short of the $ROTATION_LOOKBACK this reads, and hold no finished rotation"
  fi
}

# What rotation-window says about a node whose config sets no online_delete,
# or sets it to 0. Not a reading that failed: there is no rotation to wait for.
rotation_not_configured() { # $1 = config file
  printf '%s sets no online_delete in [node_db], or sets it to 0: no rotation is configured, so this node'"'"'s store never rotates' "$1"
}

# What rotation_state keeps out of the stream it reads: the first line that
# carries a stamp (so the verb can say how far back the read reached, #1054)
# and the last line that matches. Lines pass through awk untouched, so the
# reader's own exit status is still the one the caller takes. No regex
# interval in awk, because mawk before 20200717 has none.
ROTATION_FIRST_MARK=$'\001D '
rotation_pick() { # $1 = the egrep pattern for the lines that count
  LC_ALL=C awk -v m="$ROTATION_FIRST_MARK" \
      '!d && /^[0-9][0-9][0-9][0-9]-/ { print m substr($0, 1, 120); d = 1 } { print }' \
    | LC_ALL=C grep -aE "^${ROTATION_FIRST_MARK}|$1" \
    | LC_ALL=C awk -v m="$ROTATION_FIRST_MARK" \
        'index($0, m) == 1 { if (f == "") f = $0; next } { l = $0 } END { if (f != "") print f; if (l != "") print l }'
}

# A read that stops short of the lookback says so (#1054). Slack for the
# edge: a read bounded by --since starts at the first line after the cutoff,
# not on it, and a node that logs every second is a few seconds inside.
ROTATION_REACH_SLACK=900

# $1, when given, is a time limit in seconds for the log read (#1043). The
# rotation-state verb passes ROTATION_STATE_SECONDS, because it sits inside
# the Advisor's 90-second check; rotation_guard passes nothing and waits for
# its answer, because a cut read there would leave the stop with the lock
# alone. A read that runs out is "unknown", and what it read is not used:
# the tail comes back oldest first, so a cut read can end on a "rotating"
# line whose finish it never reached.
rotation_state() {
  local last stamp started now age empty fin lines rc raw first l reach_t what
  local -a lim=()
  fin=$(rotation_finished_re)
  lines="$fin|$ROTATION_LINES"
  if [[ -n "${1:-}" ]]; then
    lim=(timeout --kill-after="$ROTATION_KILL_GRACE" "$1")
  fi
  # The last thing the store said. "Process starting" counts as an ending
  # because the process that was rotating is gone; whatever it left behind is
  # not in flight now.
  #
  # Streamed, not captured. The window is up to 200,000 lines, and holding
  # them in a variable and printing them back into grep cost as much again as
  # reading them (a second on a VPS, measured 2026-09-02: 1.4s to read, 2.5s
  # to read, hold and re-print). grep sees the lines as the log writes them.
  # The pipeline's status is the READER's, not grep's: a log with no rotation
  # in it is an answer, a log that could not be read is not. That distinction
  # is the whole point of this function, so it is kept on all three readers.
  if [[ "$KIND" == container ]]; then
    rc=0
    raw=$(
      "${lim[@]}" docker logs --timestamps --tail "$ROTATION_TAIL" --since "$ROTATION_LOOKBACK" "$SERVICE" 2>&1 \
        | rotation_pick "$lines"
      exit "${PIPESTATUS[0]}"
    ) || rc=$?
    if (( ${#lim[@]} > 0 && (rc == 124 || rc == 137) )); then
      printf 'unknown\tthe last %s lines of the node log did not read back within %ss, so whether a rotation is in flight is not measured\n' "$ROTATION_TAIL" "$1"
      return 0
    elif (( rc != 0 )); then
      printf 'unknown\tthe node log could not be read, so whether a rotation is in flight is unknown\n'
      return 0
    fi
    # Says what the read covered. The tail is a line count, and on a chatty
    # node it reaches back hours, not the whole day (#1031).
    what='the node log'
    empty=$(printf 'no rotation in the node log within the last %s, as far back as its last %s lines reach' \
      "$ROTATION_LOOKBACK" "$ROTATION_TAIL")
  elif [[ "$NODE_LOG_SOURCE" == journal ]]; then
    # A unit journalctl has never heard of is not an empty journal: it exits 0
    # with no output, which would read as "idle" and drop the guard to the lock
    # alone without saying so. Ask systemd whether the unit resolves first.
    local loadstate
    loadstate=$(systemctl show "$SERVICE" --property=LoadState --value 2>/dev/null) || loadstate=''
    if [[ "$loadstate" != loaded ]]; then
      printf 'unknown\tsystemd does not have %s loaded (%s), so its journal proves nothing and the store-rotation guard is down to the lock alone\n' \
        "$SERVICE" "${loadstate:-no answer}"
      return 0
    fi
    # --lines bounds the I/O the same way --tail does on a container, and
    # --since bounds the window. An unbounded scan of a chatty validator's day
    # took 35 seconds on validator1 (2026-08-28), and this read sits in front
    # of every restart.
    rc=0
    raw=$(
      "${lim[@]}" journalctl --no-pager --output=short-iso --unit="$SERVICE" \
                 --lines="$ROTATION_TAIL" --since="-$ROTATION_LOOKBACK" 2>&1 \
        | rotation_pick "$lines"
      exit "${PIPESTATUS[0]}"
    ) || rc=$?
    if (( ${#lim[@]} > 0 && (rc == 124 || rc == 137) )); then
      printf "unknown\tthe last %s lines of %s's journal did not read back within %ss, so whether a rotation is in flight is not measured\n" "$ROTATION_TAIL" "$SERVICE" "$1"
      return 0
    elif (( rc != 0 )); then
      printf 'unknown\tthe journal for %s could not be read, so whether a rotation is in flight is unknown and the store-rotation guard is down to the lock alone\n' "$SERVICE"
      return 0
    fi
    what="$SERVICE's journal"
    empty=$(printf "no rotation in %s's journal within the last %s, as far back as its last %s lines reach" \
      "$SERVICE" "$ROTATION_LOOKBACK" "$ROTATION_TAIL")
  else
    # The file the node's own config names. tail seeks from the end, so the
    # read is bounded on a log that has never been rotated; a whole-file grep
    # is the thing this must never become.
    rc=0
    raw=$(
      "${lim[@]}" tail -n "$ROTATION_TAIL" "$NODE_LOG_SOURCE" 2>/dev/null \
        | rotation_pick "$lines"
      exit "${PIPESTATUS[0]}"
    ) || rc=$?
    if (( ${#lim[@]} > 0 && (rc == 124 || rc == 137) )); then
      printf 'unknown\tthe last %s lines of %s did not read back within %ss, so whether a rotation is in flight is not measured\n' "$ROTATION_TAIL" "$NODE_LOG_SOURCE" "$1"
      return 0
    elif (( rc != 0 )); then
      printf 'unknown\t%s could not be read, so whether a rotation is in flight is unknown and the store-rotation guard is down to the lock alone\n' "$NODE_LOG_SOURCE"
      return 0
    fi
    what=$NODE_LOG_SOURCE
    empty=$(printf 'no rotation in the last %s lines of %s' "$ROTATION_TAIL" "$NODE_LOG_SOURCE")
  fi
  # The read is two things: the first line that carried a stamp, and the last
  # line that matched.
  first='' last=''
  while IFS= read -r l; do
    case "$l" in
      "$ROTATION_FIRST_MARK"*) first=${l#"$ROTATION_FIRST_MARK"} ;;
      *) last=$l ;;
    esac
  done <<< "$raw"
  if [[ -z "$last" ]]; then
    # An empty answer is only as wide as the read was (#1054). The sentence
    # above is the whole lookback; say how far back this read reached when it
    # did not get there, or that this could not be measured.
    now=$(date +%s)
    reach_t=''
    [[ -z "$first" ]] || reach_t=$(rotation_epoch "$first")
    if [[ -z "$reach_t" ]]; then
      empty=$(printf 'no rotation in %s (its last %s lines); how far back that reaches is not measured' \
        "$what" "$ROTATION_TAIL")
    elif (( reach_t <= now && now - reach_t + ROTATION_REACH_SLACK < ROTATION_LOOKBACK_SECONDS )); then
      empty=$(printf 'no rotation in %s in the last %s, as far back as the log reached' \
        "$what" "$(rotation_reach "$now" "$reach_t")")
    fi
    printf 'idle\t%s\n' "$empty"
    return 0
  fi
  if [[ "$last" =~ $fin ]]; then
    printf 'idle\tthe last rotation finished\n'; return 0
  fi
  case "$last" in
    *"unable to make progress"*)
      printf 'idle\tthe last rotation gave up without finishing; the store was not swapped\n'; return 0 ;;
    *"Process starting"*)
      printf 'idle\tthe node has started since the last rotation line\n'; return 0 ;;
  esac
  # A "rotating" line with nothing after it.
  stamp=$(rotation_stamp "$last")
  started=$(date -d "$stamp" +%s 2>/dev/null) || started=0
  now=$(date +%s)
  if (( started == 0 )); then
    printf 'rotating\ta rotation is in flight (its start time could not be read)\n'
    return 0
  fi
  if (( started > now )); then
    # A stamp in the future is a clock or a timezone this script has read
    # wrongly, and an age computed from it would be negative, which would sail
    # past the stale bound as "in flight" or fail it as ancient depending on
    # the sign. Say so, and refuse: the refusing side is the safe one.
    printf 'rotating\ta rotation is in flight (its start time reads as being in the future, so how long it has been running could not be judged)\n'
    return 0
  fi
  age=$(( (now - started) / 60 ))
  if (( age >= ROTATION_STALE_MIN )); then
    printf 'stale\ta rotation started %s minutes ago and never reported finishing, which is past the %s-minute bound, not treating it as in flight\n' \
      "$age" "$ROTATION_STALE_MIN"
    return 0
  fi
  printf 'rotating\ta store rotation started %s minutes ago and has not finished; stopping the node now is what emptied a store on 2026-08-25\n' "$age"
}

# Everything that stops the node calls this first. It holds the lock on fd 9
# for the rest of the script, so the scheduled window cannot start while a
# stop is under way either.
rotation_guard() {
  local st detail
  # /run/aperire is shared with the socket units the dashboard connects to
  # (the model key sealer, the trust sync), and this script runs under
  # umask 0027. A plain mkdir here made the directory 0750 on aperire1, and
  # a socket the dashboard owns inside a directory it cannot traverse is one
  # it cannot open (#171). The mode is said, not inherited.
  install -d -m 0755 "$(dirname "$ROTATION_LOCK")"
  exec 9>"$ROTATION_LOCK"
  if ! flock -w "$ROTATION_LOCK_WAIT" 9; then
    printf 'refusing to %s: the scheduled store-rotation window is running\n' "$VERB"
    die "the scheduled store-rotation window holds $ROTATION_LOCK. It is bounded and releases on its own; try again in a few minutes, or check: systemctl status aperire-can-delete.service"
  fi
  IFS=$'\t' read -r st detail < <(rotation_state)
  case "$st" in
    rotating)
      printf 'refusing to %s: %s\n' "$VERB" "$detail"
      die "$detail, wait for it to finish, then $VERB again"
      ;;
    stale)    printf 'warning: %s\n' "$detail" ;;
    unknown)  printf 'note: %s\n' "$detail" ;;
    *)        printf 'store rotation: %s\n' "$detail" ;;
  esac
}

# online_delete as xrpld itself reads it from the node's config, so the
# wrapper and the node cannot disagree about it. xrpld 3.3.0's own rules
# (Config.cpp parseIniFile, BasicConfig.cpp Section::append):
#   - CR LF and a lone CR are both line breaks, and every line is trimmed
#   - a line starting with # is a comment
#   - a header is a trimmed line that starts with [ and ends with ], and its
#     name is everything between, exactly; "[ node_db ]" is another section
#   - a section named twice is one section, its lines joined in order
#   - in a line, the first # not preceded by a backslash starts a comment
#   - key = value with a key of [a-zA-Z][_a-zA-Z0-9]* and a non-empty value;
#     case matters, and a key set twice takes the LAST value
# Prints "<times set>\t<last value>". The wrapper refuses a key set more than
# once rather than copying last-wins: a config that says two things about the
# one setting the swap's safety rests on has not said which it means. Exits
# non-zero when the file could not be read.
node_db_online_delete() { # $1 = config file
  [[ -r "$1" ]] || return 1
  tr '\r' '\n' < "$1" | awk '
    function trim(s) { sub(/^[[:space:]]+/, "", s); sub(/[[:space:]]+$/, "", s); return s }
    {
      line = trim($0)
      if (line == "" || substr(line, 1, 1) == "#") next
      if (substr(line, 1, 1) == "[" && substr(line, length(line), 1) == "]") {
        sec = substr(line, 2, length(line) - 2); next
      }
      if (sec != "node_db") next
      for (i = 1; i <= length(line); i++)
        if (substr(line, i, 1) == "#" && (i == 1 || substr(line, i - 1, 1) != "\\")) {
          line = trim(substr(line, 1, i - 1)); break
        }
      if (line !~ /^[a-zA-Z][_a-zA-Z0-9]*[[:space:]]*=[[:space:]]*[^[:space:]]/) next
      key = line; sub(/[[:space:]]*=.*$/, "", key)
      if (key != "online_delete") next
      val = line; sub(/^[^=]*=[[:space:]]*/, "", val)
      n++; last = val
    }
    END { printf "%d\t%s\n", n, last }'
}

# The one online_delete reading both rotation-window paths take. Sets
# OD_VALUE to a plain ledger count, or 0 when the node never rotates, and
# OD_ERROR to why it could not be read. Ten digits and 32 bits, like a ledger
# sequence; anything else is an error, never "never rotates".
OD_VALUE='' OD_ERROR=''
online_delete_reading() { # $1 = config file
  local raw count val
  OD_VALUE='' OD_ERROR=''
  if ! raw=$(node_db_online_delete "$1"); then
    OD_ERROR="the node config $1 could not be read, so its online_delete is unknown"
    return 0
  fi
  IFS=$'\t' read -r count val <<< "$raw"
  if [[ "$count" == 0 ]]; then
    OD_VALUE=0
  elif [[ "$count" != 1 ]]; then
    OD_ERROR="online_delete is set $count times in [node_db] of $1; xrpld uses the last one, and a config that says two things about the setting this check rests on is not read on a guess"
  elif [[ ! "$val" =~ ^[0-9]{1,10}$ ]] || (( 10#$val > 4294967295 )); then
    OD_ERROR="online_delete in [node_db] of $1 reads '$(printf '%s' "$val" | cut -c1-40)', which is not a ledger count"
  else
    OD_VALUE=$((10#$val))
  fi
}

# rotation-window's answer when it could not look. Three zeros so a reader
# that only knows the three readings still sees the keys, and the reason on
# its own key so the Advisor renders a guard that could not read its
# evidence as unmeasured, never as a quiet node (#679). One line, bounded.
rotation_window_error() { # $1 = why
  printf 'AperireLastRotatedSeq=0\nAperireOnlineDelete=0\nAperireValidatedSeq=0\n'
  printf 'AperireRotationError=%s\n' "$(printf '%s' "$1" | tr '\n\r\t' '   ' | cut -c1-300)"
}

# How far past online_delete the validated ledger may run beyond the last
# rotation before the three readings stop describing one store. A rotation
# becomes due at last + online_delete, and two things can hold it past that:
# on advisory_delete=1 it waits for the daily window to arm it (up to the 24h
# of ROTATION_LOOKBACK), and a rotation in flight runs up to
# ROTATION_STALE_MIN (4h). 28 hours at 3 seconds a ledger, the fast end of
# the network's 3 to 4, is 33,600 ledgers. A gap wider than that is a last
# rotation from some other store, a restored database, or a line that is not
# this node's, and the caller's sum on it would be a number about nothing.
ROTATION_GAP_SLACK=33600

# The three readings, checked against each other before anyone does sums on
# them. Prints why they do not hang together, or nothing. Ledger sequences
# are 32-bit, so ten digits and 4294967295 bound all three; a longer number
# is not a ledger and would overflow the caller's time arithmetic.
rotation_window_insane() { # $1 = last rotated, $2 = online_delete, $3 = validated
  local v last online validated
  for v in "$1" "$2" "$3"; do
    if [[ ! "$v" =~ ^[0-9]{1,10}$ ]] || (( 10#$v > 4294967295 )); then
      printf 'a rotation reading (%s) is not a ledger sequence, so none of the three was used\n' "$(printf '%s' "$v" | cut -c1-24)"
      return 0
    fi
  done
  last=$((10#$1)) online=$((10#$2)) validated=$((10#$3))
  if (( last == 0 )); then
    printf 'the node log reports a rotation at ledger 0, which no store rotates at\n'
  elif (( last > validated )); then
    printf 'the node log reports a rotation at ledger %s, past the validated ledger %s, so the log and the node are not describing the same store\n' \
      "$last" "$validated"
  elif (( validated - last > online + ROTATION_GAP_SLACK )); then
    printf "the last rotation in the node log is at ledger %s, %s ledgers behind the validated ledger %s, more than online_delete (%s) plus %s could hold it off, so it is not this store's last rotation\n" \
      "$last" "$((validated - last))" "$validated" "$online" "$ROTATION_GAP_SLACK"
  fi
}

# rotation-window on a native node (#832). The same three readings and the
# same keys as the container path, taken from what a package install has:
#
#   online_delete  the [node_db] key in CONFIG_FILE, read first, because a
#                  node without it never rotates and nothing else matters
#   last rotation  the last "finished rotation <seq>" in NODE_LOG_SOURCE,
#                  the journal or the node's own debug log, read by time
#                  through rotation_last_finish, as on a container (#1031)
#   validated seq  server_info on the loopback ADMIN_RPC
#
# What each failure answers, and why it differs from the container path in
# two places:
#
#   no online_delete, or 0   Reason. A fact about the node, and a benign one.
#   config unreadable, or a  Error. Nothing was measured.
#     value that is not a
#     number
#   unit not loaded          Error. journalctl answers an unknown unit with
#                            nothing and exit 0, which would read as "has not
#                            rotated". The same trap rotation_state guards.
#   log unreadable           Error, from the reader's own exit status, never
#                            from whether grep matched.
#   admin RPC unreachable    Error. The container path folds this into the
#                            Reason; on native it is the only way to the
#                            validated sequence, and a guard that could not
#                            take a reading must not render as a pass.
#   no validated ledger      Error, for the same reason. aperire2 drops to
#                            "syncing" inside every rotation (debug.log,
#                            2026-10-04), so a node with no validated ledger
#                            can be one mid-rotation.
#   no finished rotation     Reason, with LastRotatedSeq=0, naming the source.
#     in the window          "none in the last 24h" only when the read reached
#                            back past 24 hours. A log that starts later (a
#                            freshly rotated debug.log, a vacuumed journal)
#                            or one too long for the widest read says "not
#                            measured" and how far back it reached. The
#                            container path answers the same way.
#
# Root reads NODE_LOG_SOURCE here as it already does in rotation_state, and
# only digits leave this function from it.
rotation_window_native() {
  local online last validated body rc loadstate why
  if [[ ! -r "$CONFIG_FILE" ]]; then
    rotation_window_error "the node config $CONFIG_FILE could not be read, so its online_delete is unknown"
    return 0
  fi
  online_delete_reading "$CONFIG_FILE"
  if [[ -n "$OD_ERROR" ]]; then
    rotation_window_error "$OD_ERROR"
    return 0
  fi
  online=$OD_VALUE
  if (( online == 0 )); then
    printf 'AperireLastRotatedSeq=0\nAperireOnlineDelete=0\nAperireValidatedSeq=0\n'
    printf 'AperireRotationReason=%s\n' "$(rotation_not_configured "$CONFIG_FILE")"
    return 0
  fi

  if [[ "$NODE_LOG_SOURCE" == journal ]]; then
    loadstate=$(systemctl show "$SERVICE" --property=LoadState --value 2>/dev/null) || loadstate=''
    if [[ "$loadstate" != loaded ]]; then
      rotation_window_error "systemd does not have $SERVICE loaded (${loadstate:-no answer}), so its journal proves nothing about when the store last rotated"
      return 0
    fi
  fi
  rotation_last_finish
  if [[ -n "$RF_ERROR" ]]; then
    rotation_window_error "$RF_ERROR"
    return 0
  fi
  last=$RF_SEQ

  rc=0
  body=$(curl -sS --max-time 5 --max-filesize 1048576 \
              --data '{"method":"server_info","params":[{}]}' "$ADMIN_RPC" 2>&1) || rc=$?
  if (( rc != 0 )); then
    rotation_window_error "the node's admin RPC at $ADMIN_RPC did not answer server_info (curl exited $rc): $body"
    return 0
  fi
  validated=$(printf '%s' "$body" \
    | grep -oE '"validated_ledger"[^}]*"seq"[[:space:]]*:[[:space:]]*[0-9]+' \
    | grep -oE '[0-9]+$' | tail -1) || validated=''
  if [[ -z "$validated" ]]; then
    rotation_window_error "the node answered server_info with no validated ledger, so how far it is from its next rotation cannot be worked out, and a node in that state can be mid-rotation"
    return 0
  fi

  if [[ -n "$last" ]]; then
    why=$(rotation_window_insane "$last" "$online" "$validated")
    if [[ -n "$why" ]]; then
      rotation_window_error "$why"
      return 0
    fi
  fi
  printf 'AperireLastRotatedSeq=%s\n' "${last:-0}"
  printf 'AperireOnlineDelete=%s\n' "$online"
  printf 'AperireValidatedSeq=%s\n' "$validated"
  if [[ -n "$last" && -n "$RF_AGE" ]]; then
    printf 'AperireLastRotatedAge=%s\n' "$RF_AGE"
  fi
  if [[ -z "$last" ]]; then
    printf 'AperireRotationReason=%s\n' "$RF_REASON"
  fi
}

# A version reaches an image tag, a package version, a docker build argument
# or an apt version pin. Digits and dots only, not escaped, rejected. The
# package verbs hold to the same shape: widening it would widen what an
# approved plan is able to say.
#
# Bounded as well as shaped, since build-image carries this value into a
# build argument and the recipe carries it into an apt pin and a tag. A
# release is four numbers at most and each is small; nothing legitimate comes
# near these limits, and an unbounded "digits and dots" is a megabyte of
# digits that no length check downstream would have caught.
REQUIRE_VERSION_MAXLEN=24
REQUIRE_VERSION_MAXPARTS=4
require_version() {
  [[ -n "$ARG" ]] || die "$VERB needs a version"
  [[ "${#ARG}" -le $REQUIRE_VERSION_MAXLEN ]] \
    || die "refusing version '${ARG:0:$REQUIRE_VERSION_MAXLEN}…': longer than $REQUIRE_VERSION_MAXLEN characters"
  [[ "$ARG" =~ ^[0-9]{1,5}(\.[0-9]{1,5}){0,3}$ ]] \
    || die "refusing version '$ARG': digits and dots only, at most $REQUIRE_VERSION_MAXPARTS parts of 5 digits each"
}

# ── The locally built image, and the recipe that makes it ─────────────────
#
# Constants, not configuration, for the reason the rotation bounds above are:
# a caller that could name the recipe could name any program root then runs.
#
# The recipe is INSTALLED, root-owned, beside the other root programs. It is
# never read out of the checkout: that tree is writable by the account this
# script serves, so building from it would hand that account a root build
# with its own Dockerfile and its own entrypoint. That is the #657 class, and
# it is closed here by refusing anything that is not a root-owned regular
# file in a root-owned directory, symlinks included.
#
# The directory is a variable only so the tests can point it somewhere
# harmless. Nothing on a host should ever pass anything else.
LOCAL_IMAGE_REPO=localhost/xrpld
# The official image, published as part of the XRPL release process
# (announced 2026-09-19, and WietseWind/docker-xrpld#31 retires the old
# xrpllabsofficial repository in its favour). A constant for the same reason
# LOCAL_IMAGE_REPO is one: a caller that could name the repository could
# name any registry this host then pulls root-run code from.
OFFICIAL_IMAGE_REPO=rippleci/xrpld

# On a host with no node configuration, the two image verbs that are allowed
# to run there work against the official repository and nothing else. Set
# here rather than at the guard above, because the constant does not exist
# yet up there.
if [[ -n "${CONFLESS:-}" ]]; then
  REPO="$OFFICIAL_IMAGE_REPO"
fi
IMAGE_RECIPE_DIR=/usr/local/lib/aperire
IMAGE_RECIPE_SCRIPT="build-xrpld-image.sh"
IMAGE_RECIPE_CONTEXT="xrpld-image"
# The one script in the recipe context that fetches a release's .deb through
# the same signed apt chain the Dockerfile uses and prints the SHA-256 of the
# binary inside it. signed-binary-sha256 runs it; nothing else does. Named
# here, beside the Dockerfile and the entrypoint, so require_recipe holds it
# to the same ownership rule.
IMAGE_RECIPE_SIGNED_BINARY="signed-binary-sha256.sh"
# The base that reader runs in, pinned by digest to exactly what the
# recipe's own Dockerfile builds on.
#
# It is the trust root of the one check that binds the bytes a node would
# run to the Foundation's signing key: gpg, apt and sha256sum all run inside
# this image, so a substituted base could print any hash it liked and every
# comparison downstream would agree with it. A moving tag is not a root.
# The recipe suite holds this digest equal to the Dockerfile's.
SIGNED_BINARY_BASE="ubuntu:24.04@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3"
# The uid the recipe must belong to. An assignment rather than a literal for
# the same reason CONF and ROTATION_LOCK are: a test has to be able to point
# this at a fixture it owns, and it can only do that by rewriting a line in
# a copy of this script. That is not a weakening. Anything that can rewrite
# this file is already root.
IMAGE_RECIPE_OWNER=0
# Where the parent-chain walk stops. "/" on a host, which is the whole chain;
# an assignment rather than a literal for the same reason IMAGE_RECIPE_DIR is
# one, so a test can hold a fixture to the same rule inside a directory it
# owns without being refused by /tmp's own world-writable mode.
IMAGE_RECIPE_CHAIN_TOP=/

# Every path the recipe run touches has to be root's, and none of it a
# symlink. The build COPIES the context into a root build, so checking the
# script alone would leave the Dockerfile and the entrypoint open.
# Every directory from the recipe up to /, held to the same rule as the
# recipe itself.
#
# Checking the leaf alone trusts the chain above it. Anything that can write
# /usr/local/lib can replace the whole recipe directory with one of its own
# and every check below would then pass against files it planted. Default
# permissions on those directories are already root-owned and 0755, so this
# normally reads four directories and says nothing; the point is that it is
# CHECKED rather than assumed, because the assumption is what a host with a
# loosened /usr/local (or a mount an operator added) quietly breaks.
require_recipe_chain() { # $1 = the deepest path to walk up from
  local d="$1" owner mode
  while :; do
    [[ ! -L "$d" ]] \
      || die "refusing to build: $d is a symlink, and root does not follow one into a build"
    owner=$(stat -c '%u' "$d" 2>/dev/null) || die "could not read the owner of $d"
    [[ "$owner" == "$IMAGE_RECIPE_OWNER" ]] \
      || die "refusing to build: $d is owned by uid $owner, not uid $IMAGE_RECIPE_OWNER, and it holds the recipe root runs"
    mode=$(stat -c '%a' "$d" 2>/dev/null) || die "could not read the mode of $d"
    (( (8#$mode & 8#022) == 0 )) \
      || die "refusing to build: $d is mode $mode, writable by someone other than root, and it holds the recipe root runs"
    [[ "$d" != "$IMAGE_RECIPE_CHAIN_TOP" && "$d" != "/" ]] || break
    d=$(dirname "$d")
  done
  return 0
}

require_recipe() {
  local dir="$IMAGE_RECIPE_DIR" script="$IMAGE_RECIPE_DIR/$IMAGE_RECIPE_SCRIPT"
  local ctx="$IMAGE_RECIPE_DIR/$IMAGE_RECIPE_CONTEXT" p owner mode
  [[ -e "$dir" ]] \
    || die "no image recipe installed at $dir; install it with: curl -fsSL https://get.aperire.one | bash -s -- --update --force"
  [[ ! -L "$dir" ]] || die "refusing to build: $dir is a symlink, and root does not follow one into a build"
  [[ -d "$dir" ]]   || die "refusing to build: $dir is not a directory"
  for p in "$dir" "$script" "$ctx" "$ctx/Dockerfile" "$ctx/entrypoint.sh"; do
    [[ -e "$p" ]] \
      || die "the image recipe is incomplete: $p is missing. Re-install it with: curl -fsSL https://get.aperire.one | bash -s -- --update --force"
    [[ ! -L "$p" ]] \
      || die "refusing to build: $p is a symlink; the recipe root runs must be root-owned regular files, never a link to somewhere else"
    owner=$(stat -c '%u' "$p" 2>/dev/null) || die "could not read the owner of $p"
    [[ "$owner" == "$IMAGE_RECIPE_OWNER" ]] \
      || die "refusing to build: $p is owned by uid $owner, not uid $IMAGE_RECIPE_OWNER; a recipe the calling account can rewrite is a root build it wrote"
    mode=$(stat -c '%a' "$p" 2>/dev/null) || die "could not read the mode of $p"
    # Group- or world-writable is the same hole by another name.
    (( (8#$mode & 8#022) == 0 )) \
      || die "refusing to build: $p is mode $mode, which is writable by someone other than root"
  done
  [[ -f "$script" ]] || die "refusing to build: $script is not a regular file"
  [[ -f "$ctx/Dockerfile" && -f "$ctx/entrypoint.sh" ]] \
    || die "refusing to build: $ctx must hold a Dockerfile and an entrypoint.sh, both regular files"
  # And the chain above it, which the checks so far took on trust.
  require_recipe_chain "$dir"
  return 0
}

# One more file in the recipe context, held to exactly the rules above.
#
# Separate from require_recipe rather than folded into its loop, because a
# host whose recipe was installed before this file existed must still be able
# to BUILD. Only the verb that runs this script needs it, and only that verb
# is told to re-install.
require_recipe_file() { # $1 = the file's name inside the recipe context
  local p="$IMAGE_RECIPE_DIR/$IMAGE_RECIPE_CONTEXT/$1" owner mode
  require_recipe
  [[ -e "$p" ]] \
    || die "the installed image recipe has no $1; re-install it with: curl -fsSL https://get.aperire.one | bash -s -- --update --force"
  [[ ! -L "$p" ]] \
    || die "refusing to run $1: $p is a symlink, and root does not follow one"
  [[ -f "$p" ]] || die "refusing to run $1: $p is not a regular file"
  owner=$(stat -c '%u' "$p" 2>/dev/null) || die "could not read the owner of $p"
  [[ "$owner" == "$IMAGE_RECIPE_OWNER" ]] \
    || die "refusing to run $1: $p is owned by uid $owner, not uid $IMAGE_RECIPE_OWNER"
  mode=$(stat -c '%a' "$p" 2>/dev/null) || die "could not read the mode of $p"
  (( (8#$mode & 8#022) == 0 )) \
    || die "refusing to run $1: $p is mode $mode, which is writable by someone other than root"
  printf '%s' "$p"
}

# A digest, as an argument. Required rather than resolved, and shaped
# exactly, because this is what the pull is pinned to: anything looser is a
# reference the caller gets to choose at the moment the image lands.
require_digest() {
  [[ -n "$ARG2" ]] || die "$VERB needs the digest the version was pinned to"
  [[ "${#ARG2}" -le 78 ]] || die "refusing digest: longer than 78 characters"
  [[ "$ARG2" =~ ^sha256:[0-9a-f]{64}$ ]] \
    || die "refusing digest '$ARG2': sha256: followed by 64 lowercase hex characters"
}

# uid:gid, for set-runtime-user. Numeric on purpose: a name resolves
# differently inside the container than it does on this host, and the whole
# point of writing the line is that the account the node comes back as is
# the account it went down as.
require_userspec() {
  [[ -n "$ARG" ]] || die "$VERB needs a uid:gid"
  [[ "${#ARG}" -le 21 ]] || die "refusing user '${ARG:0:21}…': longer than 21 characters"
  [[ "$ARG" =~ ^[0-9]{1,10}:[0-9]{1,10}$ ]] \
    || die "refusing user '$ARG': numeric uid:gid only, for instance 997:997"
}

# Run a build with a docker client config directory of its own.
#
# Why this exists (#677). advisord's unit sets ProtectHome=read-only, and
# while the wrapper ran through sudo it stayed in that unit's mount
# namespace, so every root command the Advisor ran through it saw /root
# read-only. Behind the socket (ADR 0025) it no longer does, and the
# separate config directory stays because it costs nothing and keeps a
# build from touching root's own docker config. Where docker has
# the buildx plugin, `docker build` routes through buildx, and buildx writes
# an activity timestamp under /root/.docker/buildx/ BEFORE it builds. On the
# lab validator that ended the upgrade at the build step:
#
#   ERROR: failed to build: failed to update builder last activity time:
#          open /root/.docker/buildx/activity/.tmp-default…: read-only file system
#
# A host without the plugin never hits it, which is why the first lab pass
# went green. Every current Docker CE ships buildx, prod included.
#
# The fix keeps the unit exactly as hardened as it was: the build gets a
# writable config directory instead of the service getting a writable /root.
# It is created fresh per run, 0700, owned by whoever is running this
# (root, on the Advisor's path), and removed afterwards. Fresh and
# unpredictable rather than a fixed path on purpose: docker runs
# $DOCKER_CONFIG/cli-plugins/docker-* and any credential helper the config
# names, so a directory another account could pre-plant would be root
# executing that account's code, the same class of hole the recipe's own
# ownership checks exist to close (#657).
#
# The builder is NOT pinned. Forcing the legacy builder would work today and
# quietly change what gets produced the day the recipe needs anything
# BuildKit-only, so this makes both builders work rather than choosing one.
# The recipe's output, line by line onto fd 3 (the verb's own stdout) as it
# arrives, and its last refusal line printed at the end for the caller to
# name. The recipe's own words only: its "error:" line or its "VERIFY FAILED:"
# line, never a line out of apt or docker. One line, printable, bounded: it
# ends up in the Advisor's chat.
build_relay_reason() {
  local line why=""
  while IFS= read -r line || [[ -n "$line" ]]; do
    printf '%s\n' "$line" >&3
    case "$line" in
      "error: "*) why="${line#error: }" ;;
      "VERIFY FAILED: "*) why="$line" ;;
    esac
  done
  printf '%s' "$why" | LC_ALL=C tr -cd '[:print:]' | head -c 300
}

image_build_env() { # $@ = the command to run
  local cfg rc=0
  cfg=$(mktemp -d -t aperire-docker-XXXXXX) || die "could not create a docker config directory for the build"
  chmod 0700 "$cfg" 2>/dev/null || true
  # Carry over root's own client config when there is one, so a host that
  # configured a proxy or a registry credential keeps behaving as it did.
  # Only a root-owned regular file, never a link: what is copied here is
  # read by root's docker client.
  if [[ -f /root/.docker/config.json && ! -L /root/.docker/config.json ]] \
     && [[ "$(stat -c '%u' /root/.docker/config.json 2>/dev/null)" == 0 ]]; then
    cp -p /root/.docker/config.json "$cfg/config.json" 2>/dev/null || true
  fi
  # A build can take a minute, and the operator's own hand on the terminal
  # (or a systemd stop of whatever drove it) is a signal, not a clean
  # return: without a trap the 0700 directory outlives the run that made
  # it. Set here and cleared below so the rest of the script keeps its own
  # handling.
  # shellcheck disable=SC2064  # $cfg is expanded now on purpose: the trap must name this run's directory
  trap "rm -rf '$cfg'" TERM INT HUP EXIT
  DOCKER_CONFIG="$cfg" BUILDX_CONFIG="$cfg/buildx" "$@" || rc=$?
  trap - TERM INT HUP EXIT
  rm -rf "$cfg"
  return "$rc"
}

# The floor on the stop grace a recreate gives the container it replaces,
# in seconds, and the reason it is 300: the xrpld package's own systemd unit
# sets TimeoutStopSec=5min for the same binary. See the recreate verb for
# what goes wrong without an explicit -t (#665).
RECREATE_STOP_GRACE_FLOOR=300

# The longest stop grace this wrapper will hand a stop, in seconds.
#
# A grace is a ceiling on how long docker waits before SIGKILL, so a very
# large one is not dangerous the way a short one is: docker waits for the
# exit, not for the timer. What it IS is a wait nobody chose. An hour is
# already twelve times what the package's own unit gives xrpld, and a
# deployment naming a day would leave an operator watching a stop that looks
# hung with no way to tell it from one that is. Above this, the floor is
# used and the reason is printed.
COMPOSE_STOP_GRACE_MAX=3600

# What the RUNNING container records as its stop timeout.
#
# Prints the number it read, whether or not that number is usable, and says
# which by its exit status: 0 usable, 2 past the ceiling, 1 nothing to read.
# The caller needs both, one to use and one to report, and a function cannot
# hand back a second value through a global: a command substitution runs in
# a subshell, so the global would never arrive.
#
# This matters as much as the file's own value, because compose COPIES
# stop_grace_period into the container it creates. A file that named
# something absurd once leaves every later stop inheriting it, including
# after the file is fixed.
container_stop_grace() { # $1 = container
  local v
  v=$(docker inspect "$1" --format '{{.Config.StopTimeout}}' 2>/dev/null) || v=''
  [[ "$v" =~ ^[0-9]+$ ]] || return 1
  printf '%s' "$v"
  (( v <= COMPOSE_STOP_GRACE_MAX )) || return 2
  return 0
}

# How a reading reads in the transcript: the number, or why it was not used.
# One helper for both readings, so the line cannot tell two different stories
# about the same kind of fact.
grace_note() { # $1 = the number read (may be empty), $2 = its exit status
  if [[ -z "$1" ]]; then
    printf 'none'
  elif (( $2 == 2 )); then
    printf '%ss, past the %ss ceiling and not used' "$1" "$COMPOSE_STOP_GRACE_MAX"
  else
    printf '%ss' "$1"
  fi
}

# The stop_grace_period a compose file names, in seconds. Prints nothing and
# fails when the file names none, names one in a shape this does not read
# (compose accepts "1m30s"), or names one past the ceiling above; the caller
# then falls back on the floor, which is the safe direction. The first one in
# the file: the deployments this wrapper is configured for carry one service.
compose_stop_grace() { # $1 = file
  local raw n secs
  raw=$(grep -oP '(?<=stop_grace_period:)[^#]*' "$1" | head -1 | tr -d "[:space:]\"'") || true
  [[ -n "$raw" ]] || return 1
  case "$raw" in
    *h) n=${raw%h}; [[ "$n" =~ ^[0-9]{1,5}$ ]] || return 1; secs=$(( n * 3600 )) ;;
    *m) n=${raw%m}; [[ "$n" =~ ^[0-9]{1,5}$ ]] || return 1; secs=$(( n * 60 )) ;;
    *s) n=${raw%s}; [[ "$n" =~ ^[0-9]{1,5}$ ]] || return 1; secs=$n ;;
    *)  [[ "$raw" =~ ^[0-9]{1,5}$ ]] || return 1; secs=$raw ;;
  esac
  printf '%s' "$secs"
  (( secs <= COMPOSE_STOP_GRACE_MAX )) || return 2
  return 0
}

# Which reference holds this version on this host: the local build first,
# then the configured registry repository. Prints the reference, or nothing
# when neither is here. Never pulls.
# Three origins now, in this order: the local build, the official image, and
# whatever registry repository this deployment is configured for. The
# official one is looked up by TAG even though it is pulled by digest,
# because pull-official tags what it pulled: an image with a digest and no
# tag is one docker cannot be asked about by version, and every reader below
# asks by version.
resolve_image_ref() { # $1 = version
  local ref
  for ref in "$LOCAL_IMAGE_REPO:$1" "$OFFICIAL_IMAGE_REPO:$1" "$REPO:$1"; do
    [[ "$ref" == ":"* ]] && continue
    if docker image inspect "$ref" >/dev/null 2>&1; then
      printf '%s' "$ref"
      return 0
    fi
  done
  return 1
}

# The image a verb is about, when the caller may have named a digest.
#
# This is not a convenience. resolve_image_ref looks under the local build
# name FIRST, and every host this project has upgraded already carries
# localhost/xrpld:<version>. Verifying the official image by VERSION on such
# a host reads the locally built image instead: the version matches, the
# package hash matches, the binary hash matches, and every check passes
# against bytes nobody pulled. Prod and the lab node are both in exactly
# that state. So the official path names the digest it pinned, and these
# verbs inspect that reference and no other.
ref_for() { # $1 = version, $2 = digest or empty
  if [[ -n "$2" ]]; then
    printf '%s@%s' "$OFFICIAL_IMAGE_REPO" "$2"
    return 0
  fi
  resolve_image_ref "$1"
}

# What an image resolves to, in one token that two readings of the same image
# can be compared by.
#
# RepoDigests when the store has one, the image ID when it does not. A local
# build has no registry behind it, so on the classic overlay2 store its
# RepoDigests is empty and the old `{{index .RepoDigests 0}}` died on an
# index out of range. The containerd store reports the manifest digest in
# both fields for a local build, and every consumer compares on the sha256
# part alone, so the two forms answer the same question either way.
image_digest_of() { # $1 = image reference
  local d
  d=$(docker image inspect "$1" --format '{{if .RepoDigests}}{{index .RepoDigests 0}}{{else}}{{.Id}}{{end}}' 2>/dev/null) || return 1
  [[ -n "$d" ]] || return 1
  printf '%s' "$d"
}

# The image reference a compose file names for this node, under either
# origin. The pattern is `image: ` with one space then the repository, which
# is the shape both set verbs write and the shape the Go side matches
# character for character; being looser here than the writer would make the
# two disagree about a file.
#
# An official image is named by DIGEST, with its tag in a trailing comment
# (`image: rippleci/xrpld@sha256:e77e…  # 3.4.1`). A digest is what the pull
# was pinned to and a comment is not something compose can act on, so the
# file says exactly what will run and still reads. Both separators are
# matched here; `\S+` stops at the space before the comment, so what comes
# back is the reference alone.
compose_image_ref() { # $1 = file
  local t esc
  esc=${REPO//./\\.}
  t=$(grep -oP '(?<=image: )(?:'"$esc"'|'"${LOCAL_IMAGE_REPO//./\\.}"'|'"${OFFICIAL_IMAGE_REPO//./\\.}"')[:@]\S+' "$1" | head -1) || true
  if [[ -z "$t" ]]; then
    # Neither origin this host is known to use. That is a real state, not a
    # broken file: a rollback writes the registry repository back while the
    # container is still running the locally built image, so for that moment
    # the profile names one repository, the configuration names it too, and
    # the file names neither of the two a READER was given. What identifies
    # the line then is the node's own service block, which is what the file
    # is keyed by in the first place. First image line at or after that key,
    # since a service's own image precedes the next service's.
    t=$(awk -v svc="$SERVICE" '
      $0 ~ "^[[:space:]]*" svc ":[[:space:]]*$" { insvc = 1; next }
      insvc && $0 ~ /^[[:space:]]*image:[[:space:]]*[^[:space:]]/ {
        sub(/^[[:space:]]*image:[[:space:]]*/, ""); sub(/[[:space:]].*$/, "")
        print; exit
      }' "$1")
  fi
  printf '%s' "$t"
}

# The version a compose file names, under either origin and under either
# shape the official image is written in. Promoted out of compose-backups
# (#682, second review) so restore-compose can refuse a copy that names a
# release other than the one the rollback was approved for, reading it the
# same way the listing that chose the copy read it.
compose_tag_of_file() { # $1 = file -> the version on the node's image line, or empty
  local t='' c='' before=''
  t=$(compose_image_ref "$1")
  if [[ "$t" == *@sha256:* ]]; then
    # repo:tag@sha256:... first; the comment beside the line second, which
    # is what set-image-official writes.
    before=${t%@*}
    if [[ "$before" == *:* && "${before##*:}" != */* ]]; then
      printf '%s' "${before##*:}"
      return 0
    fi
    c=$(grep -F -m1 "image: $t" "$1" | sed -n 's/.*#[[:space:]]*\([0-9][0-9.]*\)[[:space:]]*$/\1/p')
    printf '%s' "$c"
    return 0
  fi
  printf '%s' "${t##*:}"
}

# Is that pull_policy line the one this verb manages? Only when it comes
# AFTER the image line with nothing but blank lines and comments between
# them. A policy line somewhere else in the file belongs to another service
# or to an operator, and writing a second key beside it would produce a
# duplicate mapping key rather than an override.
# One dated copy, written safely.
#
# Every backup on this path used to be `cp -a <file> <file>.<stamp>.bak`.
# The name is predictable to the second, and cp FOLLOWS a symlink at the
# destination: an account that can create a file beside the deployment can
# pre-plant that name pointing anywhere and have root write the deployment's
# contents there. #673 covers the class; this closes it on the paths #682
# touches, and on the two backup verbs beside them.
#
# Written to a mktemp name in the same directory, given the source's own
# owner and mode, and moved into place with `mv -T`, which replaces a
# symlink rather than writing through it. A name that already exists is a
# refusal, not an overwrite.
#
# Prints the path it wrote. Returns non-zero and prints nothing on failure.
# Put new bytes in place of a file the node's or the operator's account may
# own the directory of, as root, without following anything (ADR 0025 review,
# L2). The wrapper runs as unsandboxed root behind the Advisor's socket, so
# the mount namespace that used to bound a stray write is gone, and every
# write into the deployment's or the config's directory is held to what
# dated_backup already does (#661): the directory opened once, everything
# else on descriptors relative to it, O_NOFOLLOW at every open.
#
#   commit_rewrite   TARGET NEW     NEW's bytes replace TARGET, carrying
#                                   TARGET's owner, group, mode and ACL
#   restore_backup   BACKUP TARGET  BACKUP's bytes replace TARGET, carrying
#                                   BACKUP's owner, group, mode and ACL (what
#                                   `cp -a` gave)
#
# TARGET must be a regular file with one link, and must still be the same
# file (device and inode) at the moment it is replaced; a link there, or a
# swap between the read and the rename, refuses with TARGET untouched. The
# bytes land in an O_EXCL name in TARGET's directory and are renamed over
# it, so a reader sees the old file or the new one, never half. NEW and
# BACKUP are opened without following a final link.
fd_replace() { # $1 = attrs from (target|content), $2 = content file, $3 = target
  python3 -I - "$1" "$2" "$3" "$FD_REPLACE_ACL_XATTR" <<'FD_REPLACE_PY'
import os, stat, sys

attrs, content, target, ACL_WRITE = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
ACL = "system.posix_acl_access"
MAX = 16 << 20

def fail(msg):
    sys.stderr.write("wrapper: %s\n" % msg)
    sys.exit(1)

d, base = os.path.dirname(target) or ".", os.path.basename(target)
dfd = os.open(d, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    try:
        tfd = os.open(base, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=dfd)
    except OSError as e:
        fail("%s could not be opened without following a link (%s); nothing was written" % (target, e.strerror))
    tst = os.fstat(tfd)
    if not stat.S_ISREG(tst.st_mode) or tst.st_nlink != 1:
        fail("%s is not a regular file with one name; nothing was written" % target)
    try:
        cfd = os.open(content, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as e:
        fail("%s could not be opened without following a link (%s); nothing was written" % (content, e.strerror))
    cst = os.fstat(cfd)
    if not stat.S_ISREG(cst.st_mode):
        fail("%s is not a regular file; nothing was written" % content)
    body = b""
    while True:
        chunk = os.read(cfd, 1 << 20)
        if not chunk:
            break
        body += chunk
        if len(body) > MAX:
            fail("%s is larger than any file this writes; nothing was written" % content)
    src_fd, src_st = (tfd, tst) if attrs == "target" else (cfd, cst)
    try:
        acl = os.getxattr(src_fd, ACL)
    except OSError:
        acl = None

    tmp = ".aperire-write.%d" % os.getpid()
    try:
        os.unlink(tmp, dir_fd=dfd)
    except FileNotFoundError:
        pass
    wfd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=dfd)
    try:
        try:
            os.write(wfd, body)
            try:
                os.fchown(wfd, src_st.st_uid, src_st.st_gid)
            except PermissionError:
                pass
            os.fchmod(wfd, stat.S_IMODE(src_st.st_mode))
            if acl is not None:
                os.setxattr(wfd, ACL_WRITE, acl)
            os.fsync(wfd)
        except OSError as e:
            # Nothing has moved: the target is as it was, and the half-made
            # copy goes.
            try:
                os.unlink(tmp, dir_fd=dfd)
            except OSError:
                pass
            fail("could not write the copy of %s with its owner, group, mode and ACL (%s); nothing was written" % (target, e.strerror))
        mine = os.fstat(wfd)
        now = os.lstat(tmp, dir_fd=dfd)
        cur = os.lstat(base, dir_fd=dfd)
        if (now.st_dev, now.st_ino) != (mine.st_dev, mine.st_ino) \
           or (cur.st_dev, cur.st_ino) != (tst.st_dev, tst.st_ino):
            try:
                os.unlink(tmp, dir_fd=dfd)
            except OSError:
                pass
            fail("%s changed under this write; nothing was written" % target)
        os.rename(tmp, base, src_dir_fd=dfd, dst_dir_fd=dfd)
    finally:
        os.close(wfd)
    os.fsync(dfd)
finally:
    os.close(dfd)
FD_REPLACE_PY
}
# The extended attribute the ACL is written back under. Always the POSIX
# access ACL; a constant, not a literal, so a test can force the ACL carry to
# fail by rewriting this one line in its copy, the way it moves
# IMAGE_RECIPE_OWNER. It is read under the real name either way.
FD_REPLACE_ACL_XATTR=system.posix_acl_access
commit_rewrite() { fd_replace target "$2" "$1"; }   # $1 = target, $2 = new content
restore_backup() { fd_replace content "$1" "$2"; }  # $1 = backup, $2 = target

# A scratch file for a rewrite, root's own, outside the directory being
# rewritten: mktemp makes it O_EXCL, 0600, in /tmp, where the sticky bit
# keeps every other account from swapping it, so writing it by name is safe.
# commit_rewrite then copies it in on descriptors.
rewrite_tmp() { mktemp -t aperire-rewrite.XXXXXX; }

dated_backup() { # $1 = file to copy
  # Every step on FILE DESCRIPTORS, not on names (#661 class, and #682's
  # second review, which proved the previous shape still raceable at
  # 295/300 attempts).
  #
  # What was wrong with names: the temp file was created by mktemp, then
  # written with `cat >`, then chmod/chown --reference, then renamed. Each
  # of those four re-resolved the same path, and the deployment directory
  # belongs to the node's own account. Swap the temp file for a symlink
  # between two of them and root follows it: `cat >` truncates whatever it
  # points at, and chmod/chown re-mode the target rather than the temp.
  #
  # The fix is the one the broker's dirsafe uses: open the directory once,
  # and do everything else relative to THAT descriptor with O_NOFOLLOW.
  # A descriptor cannot be swapped; a name can, at any instant.
  local src=$1 dir base dest
  dir=$(dirname "$src")
  base=$(basename "$src")
  dest="$base.$(date +%Y%m%d-%H%M%S).bak"
  python3 -I - "$dir" "$base" "$dest" <<'DATED_BACKUP_PY' || return 1
import os, sys, stat

d, base, dest = sys.argv[1], sys.argv[2], sys.argv[3]
dfd = os.open(d, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    # The source, opened without following a symlink, and its mode and
    # ownership read off the OPEN FILE rather than looked up again.
    sfd = os.open(base, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=dfd)
    try:
        st = os.fstat(sfd)
        if not stat.S_ISREG(st.st_mode):
            sys.exit(1)
        body = b""
        while True:
            chunk = os.read(sfd, 1 << 20)
            if not chunk:
                break
            body += chunk
            if len(body) > (8 << 20):
                sys.exit(1)
    finally:
        os.close(sfd)

    # A name nobody else can have opened first: O_EXCL, and a fresh name
    # per attempt.
    tmp = ".aperire-backup.%d" % os.getpid()
    try:
        os.unlink(tmp, dir_fd=dfd)
    except FileNotFoundError:
        pass
    tfd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=dfd)
    tfd_ino = tfd
    try:
        os.write(tfd, body)
        # On the descriptor, so a swapped name changes nothing.
        os.fchmod(tfd, stat.S_IMODE(st.st_mode))
        try:
            os.fchown(tfd, st.st_uid, st.st_gid)
        except PermissionError:
            pass
        os.fsync(tfd)
    except Exception:
        os.close(tfd)
        raise

    # A SYMLINK at the destination is refused rather than replaced: it is
    # somebody saying this path means something else. A plain file of the
    # same name is a second copy in the same second, which is ordinary.
    try:
        dst = os.lstat(dest, dir_fd=dfd)
        if stat.S_ISLNK(dst.st_mode):
            os.unlink(tmp, dir_fd=dfd)
            sys.exit(1)
    except FileNotFoundError:
        pass

    # And the NAME being renamed still has to be the file that was written
    # (#682, third review). Everything above happens on the descriptor, but
    # the rename takes a name, and the account that owns this directory can
    # put a symlink at that name between the last write and this line: the
    # racer turned the dated copy into a symlink 7 times in 300. Nothing is
    # written through it, but a dated copy that is a link to somewhere else
    # is not a copy.
    #
    # The check is the file identity, not the file type: fstat on the open
    # descriptor against lstat on the name, both st_dev and st_ino.
    now = os.lstat(tmp, dir_fd=dfd)
    mine = os.fstat(tfd_ino)
    if (now.st_dev, now.st_ino) != (mine.st_dev, mine.st_ino):
        try:
            os.unlink(tmp, dir_fd=dfd)
        except OSError:
            pass
        sys.exit(1)
    os.rename(tmp, dest, src_dir_fd=dfd, dst_dir_fd=dfd)
    os.close(tfd_ino)
    os.fsync(dfd)
finally:
    os.close(dfd)
sys.stdout.write(os.path.join(d, dest))
DATED_BACKUP_PY
}

pull_policy_is_ours() { # $1 = image line number, $2 = pull_policy line number
  local between
  (( $2 > $1 )) || return 1
  # Adjacent, so there is nothing between them to read. Said as its own case
  # because GNU sed reads an inverted range ("5,4p") as the single line 5,
  # which would hand back the policy line itself and refuse every file this
  # project renders.
  (( $2 == $1 + 1 )) && return 0
  between=$(sed -n "$(($1 + 1)),$(($2 - 1))p" "$COMPOSE_FILE" \
            | grep -vE '^[[:space:]]*(#.*)?$' | head -1)
  [[ -z "$between" ]]
}

# Rewrite the deployment's image line, and manage the pull_policy line that
# belongs with it.
#
# One implementation for both set verbs, because everything except the
# reference and that one extra line is identical, and a second copy of the
# backup-then-carry-the-ACL dance is how the fix for #545 would drift from
# the bug it closes.
#
# pull_policy is touched ONLY where it sits directly under the image line
# being rewritten. A pull_policy anywhere else in the file is an operator's
# line, and adding a second key beside it would produce a duplicate mapping
# key rather than an override, so this refuses and says where to look.
# $3, when given, is a trailing comment for the image line. It exists for
# one case: a digest-pinned official image, where the digest is the only
# thing compose may act on and the human-readable version has nowhere else
# to live on that line. It is never read back as data (compose config drops
# comments); the version a reader wants comes from the running node's own
# build_version.
set_compose_image() { # $1 = new image reference, $2 = 1 to write pull_policy: never, $3 = trailing comment
  local newref=$1 want_never=$2 comment=${3:-}
  local current backup was_snap now_snap tmp now ln pp pp_total cur_re
  # No newline, no '#' of its own, nothing that could close the line and
  # open something else. The only caller passes a version that already
  # passed require_version, and this holds it to that anyway.
  [[ -z "$comment" ]] || [[ "$comment" =~ ^[0-9A-Za-z._:-]{1,40}$ ]] \
    || die "refusing image-line comment '$comment'"

  current=$(compose_image_ref "$COMPOSE_FILE")
  [[ -n "$current" ]] \
    || die "no image line naming $REPO or $LOCAL_IMAGE_REPO in $COMPOSE_FILE"

  # The line is found by its key at the start of the line, so a commented
  # `# image:` never matches. A flow mapping has no such line; it is found by
  # the text instead, and the check below refuses it.
  cur_re=$(printf '%s' "$current" | sed 's/[][\\.^$*+?(){}|\/]/\\&/g')
  ln=$(grep -n -m1 -E "^[[:space:]]*image:[[:space:]]*[\"']?$cur_re" "$COMPOSE_FILE" | cut -d: -f1 || true)
  [[ -n "$ln" ]] || ln=$(grep -n -F "image: $current" "$COMPOSE_FILE" | grep -vE '^[0-9]+:[[:space:]]*#' | head -1 | cut -d: -f1 || true)
  [[ "$ln" =~ ^[0-9]+$ ]] || die "could not locate the image line in $COMPOSE_FILE"
  # The rewrite below keeps the indent and replaces everything after
  # `image: `, so it is exact only for a block line: the key on its own line
  # with the reference after it and at most a comment. A flow mapping
  # (`node: {image: x:1.0, init: true}`) would lose the rest of its line and
  # leave a file compose cannot parse (#899). Refuse it, and change nothing.
  sed -n "${ln}p" "$COMPOSE_FILE" | grep -qE '^[[:space:]]*image:[[:space:]]+[^][{},[:space:]#]+[[:space:]]*(#.*)?$' \
    || die "the image line in $COMPOSE_FILE is not a plain 'image: <reference>' line (a flow mapping such as {image: ..., init: true} is one), so this verb cannot rewrite it without cutting the rest of the line; put image: on a line of its own and run it again. Nothing was changed"

  # Which pull_policy line, if any, is the one this verb manages: the first
  # in the file, and only when it sits under the image line with nothing but
  # blank lines and comments in between. The template ships a comment right
  # there, so "the very next line" would refuse every deployment this
  # project renders.
  pp_total=$(grep -cE '^[[:space:]]*pull_policy:' "$COMPOSE_FILE" || true)
  pp=0
  if (( pp_total == 1 )); then
    pp=$(grep -nE '^[[:space:]]*pull_policy:' "$COMPOSE_FILE" | head -1 | cut -d: -f1)
  fi
  if (( pp_total > 1 )) || { (( pp_total == 1 )) && ! pull_policy_is_ours "$ln" "$pp"; }; then
    die "$COMPOSE_FILE carries a pull_policy line that is not the one under its image line; this verb only manages that one, so fix the file by hand and run it again"
  fi

  # Always a dated copy first, by this script, before it writes anything,
  # the same rule set-config holds below (#545 P3-109). The failure message
  # further down used to point at "this run's backup-compose copy", which
  # this verb never took: a caller that invoked set-image without a prior
  # backup-compose (or whose own copy this run's rewrite could not read
  # back afterward) was told to restore from a file that might not exist.
  # Taking the copy here makes the message name a backup this run actually
  # holds, the same way set-config's own message does.
  backup=$(dated_backup "$COMPOSE_FILE") \
    || { rm -f "$tmp"; die "could not take a dated copy of $COMPOSE_FILE beside it; nothing was changed"; }
  cmp -s "$COMPOSE_FILE" "$backup" || die "backup does not match the original"
  cwl_prune_backups "$COMPOSE_FILE" 10

  # `sed -i` used to do this write directly: it rewrites through its own
  # temporary file and rename, which is the same defect #545 found in
  # set-config below, just one layer further from view. Written out by
  # hand here so it goes through the one helper that carries the ACL too.
  was_snap=$(cwl_acl_snapshot "$COMPOSE_FILE")
  tmp=$(rewrite_tmp)
  awk -v new="$newref" -v want="$want_never" -v ln="$ln" -v pp="$pp" -v cmt="$comment" '
    NR == ln {
      i = index($0, "image:")
      indent = substr($0, 1, i - 1)
      print indent "image: " new (cmt == "" ? "" : "  # " cmt)
      # No policy line of ours anywhere: this one goes directly under the
      # image, which is where the next run will look for it.
      if (want && pp == 0) print indent "pull_policy: never"
      next
    }
    pp > 0 && NR == pp {
      if (want) { print indent "pull_policy: never"; next }
      # Leaving a registry tag behind our own "never" would make compose
      # refuse to fetch it. Any other policy belongs to the operator and stays.
      if ($0 ~ /^[[:space:]]*pull_policy:[[:space:]]*never[[:space:]]*$/) next
      print; next
    }
    { print }
  ' "$COMPOSE_FILE" > "$tmp"

  # Read back from the line that was rewritten, not by searching the file
  # again: a commented `# image:` above the real line would be found first.
  now=$(sed -n "${ln}p" "$tmp" | sed -n 's/^[[:space:]]*image:[[:space:]]*\([^[:space:]]*\).*$/\1/p')
  [[ "$now" == "$newref" ]] || { rm -f "$tmp"; die "edit did not take; file says ${now:-nothing}"; }
  if (( want_never )); then
    grep -qE '^[[:space:]]*pull_policy:[[:space:]]*never[[:space:]]*$' "$tmp" \
      || { rm -f "$tmp"; die "the rewrite did not leave a 'pull_policy: never' line beside the image; $COMPOSE_FILE is untouched"; }
  fi

  # Does the rewritten file still describe a deployment? A grep proves the
  # one line changed; it does not prove compose can still read the file.
  # Judged against the ORIGINAL rather than absolutely: a deployment that
  # compose already could not parse (a missing variable in someone's
  # environment, a file it needs that is not there) must not have that
  # blamed on this edit, and only a file that parsed before and does not
  # parse now is this verb's doing.
  if command -v docker >/dev/null 2>&1 \
     && docker compose -p "$PROJECT" --project-directory "$(dirname "$COMPOSE_FILE")" -f "$COMPOSE_FILE" config >/dev/null 2>&1 \
     && ! docker compose -p "$PROJECT" --project-directory "$(dirname "$COMPOSE_FILE")" -f "$tmp" config >/dev/null 2>&1; then
    rm -f "$tmp"
    die "the rewritten deployment file no longer parses, though the current one does; $COMPOSE_FILE is untouched"
  fi

  if ! commit_rewrite "$COMPOSE_FILE" "$tmp"; then
    rm -f "$tmp"
    die "could not put the rewrite in place, carrying $COMPOSE_FILE's owner, group, mode and ACL; $COMPOSE_FILE is untouched"
  fi
  rm -f "$tmp"

  now_snap=$(cwl_acl_snapshot "$COMPOSE_FILE")
  if [[ "$now_snap" != "$was_snap" ]]; then
    if restore_backup "$backup" "$COMPOSE_FILE" && cmp -s "$backup" "$COMPOSE_FILE"; then
      die "the rewrite changed $COMPOSE_FILE's $(cwl_snapshot_describe); restored $backup and left the compose file reading exactly as it did before this ran"
    else
      die "the rewrite changed $COMPOSE_FILE's $(cwl_snapshot_describe), AND restoring $backup failed; the deployment file's permissions are unproven, fix $COMPOSE_FILE by hand from $backup before touching this deployment again"
    fi
  fi

  printf '%s -> %s\n' "$current" "$now"
  (( want_never )) && printf 'pull_policy: never\n'
  printf 'backup: %s\n' "$backup"
  return 0
}

# ── Normalising a deployment somebody else wrote ──────────────────────────
#
# Aperire runs on the compose an operator already has. Three changes make an
# arbitrary shape safe to swap an image under, and each one is its own verb,
# its own approval and its own recreate: never two changes in one step,
# because a node that gains an argument and an image at once has two ways to
# fail and no way to tell them apart.
#
# Every one of them writes through compose_write_tmp below, which is
# set_compose_image's tail lifted out: a dated backup first, the rewritten
# file checked for parse against the original, the owner/group/mode/ACL
# carried, and the whole thing restored if the permissions moved.

# Where this node's service block starts and ends, as "start end" line
# numbers (end is the last line of the block). Read from the raw file, not
# from `docker compose config`: the resolved output is a normalised
# re-emission and nothing written back to it would land in the operator's
# own file.
compose_service_range() { # $1 = file
  awk -v svc="$SERVICE" '
    # The service key: any indent, the name, a bare colon.
    !start && $0 ~ "^([[:space:]]*)" svc ":[[:space:]]*(#.*)?$" {
      match($0, /^[[:space:]]*/); ind = RLENGTH; start = NR; next
    }
    start && !done {
      if ($0 ~ /^[[:space:]]*(#.*)?$/) next          # blank or comment: still inside
      match($0, /^[[:space:]]*/)
      if (RLENGTH <= ind) { print start, NR - 1; done = 1 }
    }
    END { if (start && !done) print start, NR; else if (!start) print 0, 0 }
  ' "$1"
}

# The indent one level inside the service block, taken from the block's own
# first keyed line rather than assumed to be four spaces. Compose files in
# this project use two-space nesting; operators use all sorts.
compose_inner_indent() { # $1 = file, $2 = start, $3 = end
  awk -v s="$2" -v e="$3" '
    NR > s && NR <= e && $0 !~ /^[[:space:]]*(#.*)?$/ {
      match($0, /^[[:space:]]*/); print substr($0, 1, RLENGTH); exit
    }' "$1"
}

# Finish a rewrite: the same backup, parse, permission and restore dance
# set_compose_image does, in one place so the three normalisation verbs
# cannot each get a piece of it slightly wrong.
compose_write_tmp() { # $1 = the rewritten file, $2 = what to say about it
  local tmp=$1 what=$2 backup was_snap now_snap
  was_snap=$(cwl_acl_snapshot "$COMPOSE_FILE")

  backup=$(dated_backup "$COMPOSE_FILE") \
    || { rm -f "$tmp"; die "could not take a dated copy of $COMPOSE_FILE beside it; nothing was changed"; }
  cmp -s "$COMPOSE_FILE" "$backup" || { rm -f "$tmp"; die "backup does not match the original"; }
  cwl_prune_backups "$COMPOSE_FILE" 10

  if command -v docker >/dev/null 2>&1 \
     && docker compose -p "$PROJECT" --project-directory "$(dirname "$COMPOSE_FILE")" -f "$COMPOSE_FILE" config >/dev/null 2>&1 \
     && ! docker compose -p "$PROJECT" --project-directory "$(dirname "$COMPOSE_FILE")" -f "$tmp" config >/dev/null 2>&1; then
    rm -f "$tmp"
    die "the rewritten deployment file no longer parses, though the current one does; $COMPOSE_FILE is untouched"
  fi
  if ! commit_rewrite "$COMPOSE_FILE" "$tmp"; then
    rm -f "$tmp"
    die "could not put the rewrite in place, carrying $COMPOSE_FILE's owner, group, mode and ACL; $COMPOSE_FILE is untouched"
  fi
  rm -f "$tmp"

  now_snap=$(cwl_acl_snapshot "$COMPOSE_FILE")
  if [[ "$now_snap" != "$was_snap" ]]; then
    if restore_backup "$backup" "$COMPOSE_FILE" && cmp -s "$backup" "$COMPOSE_FILE"; then
      die "the rewrite changed $COMPOSE_FILE's $(cwl_snapshot_describe); restored $backup and left the compose file reading exactly as it did before this ran"
    fi
    die "the rewrite changed $COMPOSE_FILE's $(cwl_snapshot_describe), AND restoring $backup failed; fix $COMPOSE_FILE by hand from $backup before touching this deployment again"
  fi
  printf '%s\n' "$what"
  printf 'backup: %s\n' "$backup"
  return 0
}

# Does this deployment put the node's own config where xrpld reads it?
#
# The one question node-args turns on. `entrypoint: ["/usr/bin/xrpld"]`
# bypasses an image's own entrypoint script, and on a /config-only
# deployment that script is the only thing copying the operator's config to
# /etc/xrpld/xrpld.cfg. Write the arguments there and the node comes back on
# the package's stock config: someone else's settings, no validator key, and
# a container reporting healthy. So the order is enforced here, not
# documented somewhere.
compose_config_at_etc() { # $1 = file -> 0 when the config is mounted at /etc/xrpld
  local s e body
  # The RESOLVED deployment when docker can give it: an `.env`, an
  # `extends:` or a profile is already applied there, which is the
  # difference between reading what compose will do and reading what
  # somebody typed. It is also the reading a comment cannot forge.
  # Read as STRUCTURE, not as text (#682, second review). Grepping the
  # rendered file for the path let anything that merely mentions it answer
  # yes: a healthcheck command, an environment value, a label. What this
  # asks is whether the SERVICE MOUNTS something at that path, which is
  # one field in the rendered JSON and cannot be forged by a string
  # somewhere else in the file.
  if command -v docker >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1 \
     && body=$(docker compose -p "$PROJECT" --project-directory "$(dirname "$COMPOSE_FILE")" -f "$1" config --format json 2>/dev/null) \
     && [[ -n "$body" ]]; then
    printf '%s' "$body" | python3 -I -c '
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(2)
svc = (d.get("services") or {}).get(sys.argv[1]) or {}
for v in svc.get("volumes") or []:
    target = v.get("target") if isinstance(v, dict) else None
    if target == "/etc/xrpld/xrpld.cfg":
        sys.exit(0)
sys.exit(1)
' "$SERVICE"
    case $? in
      0) return 0 ;;
      1) return 1 ;;
      # 2 is "that was not JSON this reader understands". Fall through to
      # the text reading below rather than answering a question that was
      # not asked.
    esac
  fi
  # Without docker, the file itself, with comments stripped. A line reading
  # `# mount it at /etc/xrpld/xrpld.cfg one day` used to satisfy this and
  # let set-node-args write an entrypoint that bypasses the only thing
  # putting the operator's config where xrpld reads it (#682, review of
  # 2026-09-27). A comment is not a mount.
  read -r s e < <(compose_service_range "$1")
  (( s > 0 )) || return 1
  sed -n "${s},${e}p" "$1" | sed 's/[[:space:]]#.*$//; s/^[[:space:]]*#.*$//' \
    | grep -qE ':/etc/xrpld/xrpld\.cfg(:[a-z,]+)?[[:space:]]*$'
}

# ── The package manager, on a native host ─────────────────────────────────
#
# Which one this host has. Detected, never configured: a configuration key
# naming a package manager would be a second place to get it wrong, and what
# is installed here is a fact this can read. ADR 0002's rule, applied to a
# tool instead of a symbol name.
#
# Named rather than written inline, the same reason CONF and ROTATION_LOCK
# are: a fixed path a test needs to redirect has to be an assignment a test
# can rewrite, not a literal buried in a verb.
APT_CACHE_DIR=/var/cache/apt/archives
DNF_CACHE_DIR=/var/cache/dnf

# Where package-keep puts the artefact a rollback needs (#429, ruled
# 2026-09-17: under the install's own state, never in /etc). It used to sit
# beside the node config, which on a container host is the deployment
# directory and is right, and on a native host is /etc/xrpld: 38 MB of .deb
# per kept version in /etc, nothing pruning it by design.
#
# Not the Aperire install root either, which reads like the obvious place and
# is the one place these must not be: an update unpacks a fresh tree and moves
# the old one aside, so a rollback artefact kept there is stranded in a
# directory nothing looks in, at exactly the moment it is wanted. Not under
# the node's own store either: the dashboard walks that to size the ledger
# store, and the node's package owns it.
# Where a VERIFIED official image digest is recorded (#682, review of
# 2026-09-27). Root-owned, created by this script with 0755/0644 and never
# under a directory the calling account can rename: a marker an operator's
# own account could plant is a marker that proves nothing. One file per
# digest, named by the digest, holding what was compared and to what.
#
# Why a marker at all: the checks that bind an image to the Foundation's
# signed package are expensive (they fetch the release through apt) and they
# happen in the PREPARE stage, while the write that points a node at that
# image happens in the CUTOVER. Without a record on this side, set-image
# has only the caller's word that anything was checked, and the caller is
# the thing being constrained.
VERIFIED_IMAGE_DIR=/var/lib/aperire/verified-images

# The signed index the Foundation publishes. The same URL the recipe and the
# Advisor read; named here so the verify verb compares an image's claimed
# package hash against the index rather than against anything on this host.
PACKAGES_INDEX_URL=https://packages.xrplf.org/repository/deb-stable/dists/any/main/binary-amd64/Packages

# The signed chain's own reading of one release: the binary's hash, what
# that binary reports, and a file of per-file md5sums out of the .deb apt
# verified. Factored out of the signed-binary-sha256 verb so the verify verb
# can use the same one reading rather than a second implementation of it.
#
# Prints key=value lines and returns non-zero when the chain could not be
# read at all. It is the only thing here that needs a network, and that is
# the point: the chain is fetched, never cached.
#
# $2 is the .deb SHA-256 the image says it was built from, and it is what
# picks the package revision (#1001). One release can be published as more
# than one revision, each with its own binary, and the image carries
# exactly one of them. The script picks the revision whose .deb, in apt's
# signed index, has that hash, and confirms it on the bytes apt fetched.
# Return 3 is that script saying no revision of this release is that
# package, with its reason on stdout as `refused=`; anything else non-zero
# is the chain not being read.
verify_signed_release() { # $1 = version, $2 = the image's .deb SHA-256
  local script out md5 err rc=0
  script=$(require_recipe_file "$IMAGE_RECIPE_SIGNED_BINARY") || return 1
  md5=$(mktemp "${TMPDIR:-/tmp}/aperire-md5sums.XXXXXX") || return 1
  err=$(mktemp "${TMPDIR:-/tmp}/aperire-signed-err.XXXXXX") || { rm -f "$md5"; return 1; }
  out=$(image_build_env docker run --rm \
          --security-opt no-new-privileges \
          -e "XRPLD_VERSION=$1" \
          -e "XRPLD_DEB_SHA256=$2" \
          -v "$script:/signed-binary-sha256.sh:ro" \
          "$SIGNED_BINARY_BASE" /bin/sh /signed-binary-sha256.sh 2>"$err") || rc=$?
  if (( rc != 0 )); then
    # Only the script's own named line, never apt's chatter.
    printf 'refused=%s\n' "$(sed -n 's/^signed-binary-sha256: //p' "$err" | tail -1)"
    rm -f "$md5" "$err"
    return "$rc"
  fi
  rm -f "$err"
  printf '%s\n' "$out" | sed -n 's/^md5sum:[[:space:]]*//p' > "$md5"
  if [[ -s "$md5" ]]; then
    printf '%s\npackage_md5sums=%s\n' "$out" "$md5"
  else
    rm -f "$md5"
    printf '%s\n' "$out"
  fi
}

# One package revision's .deb SHA-256, as the index publishes it. Read
# fresh, never from a file anybody here writes. By the EXACT package version
# (3.4.1-1), the one the signed chain just read (#1001): matched on the
# release alone, it took the first revision listed while the chain read
# another, and the two halves of one check compared different packages.
package_index_sha256() { # $1 = package version, e.g. 3.4.1-1
  local body
  [[ "$1" =~ ^[0-9.]+-[0-9]+$ ]] || return 1
  body=$(curl -fsSL --max-time 30 "$PACKAGES_INDEX_URL" 2>/dev/null) || return 1
  printf '%s\n' "$body" \
    | awk -v v="$1" '
        /^Package: / { pkg=$2 }
        /^Version: / { ver=$2 }
        /^SHA256: /  { if (pkg == "xrpld" && ver == v) { print $2; exit } }'
}

# Everything in the image that decides what the node's process LOADS,
# checked for DRIFT against the image's own package records (#682, second
# and third reviews).
#
# What it catches: an image built FROM the official one with something
# dropped in or edited afterwards. An NSS module planted beside a genuine
# binary ran its own code inside xrpld's pid 1 and passed every check there
# was; appending bytes to libc passed too. Both are refused now, and so is
# a program loader retargeted at a planted ELF.
#
# What it does: exports the container's filesystem as a tar stream (no code
# runs, the container is never started), reads the image's OWN dpkg records
# out of the same stream, and requires every ELF file, plus the loader's
# configuration files, to match what those records say.
#
# THE LIMIT, and it is not a small one: the reference is the image's own
# dpkg database. An attacker who edits a file AND its md5sums line passes
# this, which was proven in review. So this is drift detection over
# everything except the xrpld package itself, whose files ARE bound to the
# XRPL Foundation's signed .deb by the comparison above. Binding the rest
# would mean comparing against a pinned base image and the signed Ubuntu
# archive, which is #707, after GA by the operator's ruling.
image_files_accounted_for() { # $1 = container id, $2 = xrpld package md5sums file
  local cid=$1 pkgmd5=$2
  docker export "$cid" 2>/dev/null | python3 -I -c '
import hashlib, sys, tarfile

pkg_list = sys.argv[1] if len(sys.argv) > 1 else ""
want = {}          # path (no leading /) -> md5 the package recorded
if pkg_list:
    try:
        with open(pkg_list) as fh:
            for line in fh:
                parts = line.split()
                if len(parts) == 2:
                    want[parts[1].lstrip("/")] = parts[0]
    except OSError:
        pass

# Pass one is not possible: the stream is read once. So the dpkg database
# entries and the files they describe are collected together, and the
# comparison happens at the end.
seen = {}          # path -> md5 measured here
# Selected by what a file IS, not by what it is called (#682, second
# review). A name-based rule missed two real load paths: the loader maps a
# soname to a path through /etc/ld.so.cache, and that path need not end in
# ".so", and the interpreter recorded in the binary can be pointed at a
# file with any name at all. Every ELF in the image is compared instead,
# which is every file the loader could be made to map, plus the handful of
# loader configuration files, which are not ELF and decide what gets
# mapped.
LOADER_FILES = ("etc/nsswitch.conf", "etc/ld.so.preload", "etc/ld.so.conf")

def by_name(name):
    return name in LOADER_FILES or name.startswith("etc/ld.so.conf.d/")

try:
    tf = tarfile.open(fileobj=sys.stdin.buffer, mode="r|")
    for m in tf:
        name = m.name.lstrip("./")
        if name == "var/lib/dpkg/status":
            f = tf.extractfile(m)
            if f is None:
                continue
            inconf = False
            for line in f.read().decode("utf-8", "replace").splitlines():
                if line.startswith("Conffiles:"):
                    inconf = True
                    continue
                if inconf and line.startswith(" "):
                    parts = line.split()
                    # " /etc/foo <md5> [obsolete]"
                    if len(parts) >= 2 and len(parts[1]) == 32:
                        want.setdefault(parts[0].lstrip("/"), parts[1])
                    continue
                inconf = False
            continue
        if name.startswith("var/lib/dpkg/info/") and name.endswith(".md5sums"):
            f = tf.extractfile(m)
            if f is None:
                continue
            # Decoded by hand rather than through TextIOWrapper, which
            # asks the underlying object whether it is seekable and a tar
            # read from a PIPE is not. That one call is what made this
            # whole check answer "unreadable" on a real image.
            for line in f.read().decode("utf-8", "replace").splitlines():
                parts = line.split()
                if len(parts) == 2:
                    want.setdefault(parts[1].lstrip("/"), parts[0])
            continue
        if not m.isfile():
            continue
        f = tf.extractfile(m)
        if f is None:
            continue
        first = f.read(1 << 16)
        # ELF, or one of the loader configuration files. Anything else in
        # the image is not something the node process loads, and hashing
        # all of it would answer a question nobody asked.
        if not (first[:4] == b"\x7fELF" or by_name(name)):
            continue
        h = hashlib.md5()
        h.update(first)
        while True:
            chunk = f.read(1 << 20)
            if not chunk:
                break
            h.update(chunk)
        seen[name] = h.hexdigest()
except Exception as e:
    print("unreadable: %s" % e)
    sys.exit(2)

if not want:
    print("no package database in this image, so nothing accounts for its libraries")
    sys.exit(2)

def alt(name):
    # usr-merge: dpkg records "lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"
    # and the filesystem has it under "usr/lib/...". Same file, two names,
    # and a check that did not know that refused every genuine image.
    if name.startswith("usr/"):
        rest = name[4:]
        if rest.split("/", 1)[0] in ("lib", "lib64", "bin", "sbin"):
            return rest
    elif name.split("/", 1)[0] in ("lib", "lib64", "bin", "sbin"):
        return "usr/" + name
    return None

# /etc/nsswitch.conf is not shipped to /etc by any package: libc-bin ships
# a TEMPLATE at /usr/share/libc-bin/nsswitch.conf and its postinst copies
# it. So the file that decides which name-service modules get loaded is in
# no package record at all, which is what made planting one work. It is
# compared against that template instead.
TEMPLATE = {"etc/nsswitch.conf": "usr/share/libc-bin/nsswitch.conf"}

bad = []
for name, got in sorted(seen.items()):
    ref = want.get(name)
    if ref is None:
        a = alt(name)
        if a:
            ref = want.get(a)
    if ref is None and name in TEMPLATE:
        ref = want.get(TEMPLATE[name])
        if ref is not None and ref != got:
            bad.append("/%s is not the file its package ships as the template" % name)
            if len(bad) >= 3:
                break
            continue
    if ref is None:
        bad.append("/%s is in no package this image records" % name)
    elif ref != got:
        bad.append("/%s is not the file its package recorded" % name)
    if len(bad) >= 3:
        break
if bad:
    print("; ".join(bad))
    sys.exit(1)
print("%d executables, libraries and loader files, each matching the package records inside this image (drift check only)" % len(seen))
' "$pkgmd5"
}

# Whichever repository this node is configured with, an image reference
# that names the OFFICIAL one is an image this host must have checked
# before it is run or read (#682, third review).
#
# The earlier guard asked whether REPO was the official repository, which
# is false on every node that builds its own images, and those are exactly
# the nodes where pull-official has just put an official image on the disk.
# A hostile one whose verify had FAILED was then run by image-version.
require_verified_if_official() { # $1 = image reference, $2 = version
  local ref=$1 version=$2 dg
  [[ "$ref" == "$OFFICIAL_IMAGE_REPO"@* || "$ref" == "$OFFICIAL_IMAGE_REPO":* ]] || return 0
  dg=${ref#*@}
  if [[ "$dg" == "$ref" ]]; then
    # Named by tag, so ask the local store what that tag resolves to. An
    # image nobody can resolve is not one to run either.
    dg=$(image_digest_of "$ref") || dg=""
  fi
  verified_marker_ok "$version" "$dg" \
    || die "$ref is an image from $OFFICIAL_IMAGE_REPO that this host has not checked; run: verify-official-image $version ${dg:-<digest>}"
}

# Two host-side readers, so no verb has to run an image to describe it.
#
# Both create a container with an entrypoint that does not exist and never
# start it, stream the file out with docker cp, and read it here. The
# container is removed with its anonymous volumes.
image_file_line() { # $1 = ref, $2 = path -> "ID:VERSION_ID" from an os-release
  local ref=$1 path=$2 cid out
  cid=$(docker create --entrypoint /nonexistent "$ref" 2>/dev/null) || return 1
  out=$(docker cp -L "$cid:$path" - 2>/dev/null | tar -xO 2>/dev/null) || out=""
  docker rm -f -v "$cid" >/dev/null 2>&1 || true
  [[ -n "$out" ]] || return 1
  local id ver
  id=$(printf '%s\n' "$out" | sed -n 's/^ID=//p' | tr -d '"' | head -1)
  ver=$(printf '%s\n' "$out" | sed -n 's/^VERSION_ID=//p' | tr -d '"' | head -1)
  [[ -n "$id" ]] || return 1
  printf '%s:%s' "$id" "$ver"
}

image_binary_sha256() { # $1 = ref -> the sha256 of /usr/bin/xrpld, taken here
  local ref=$1 cid out
  cid=$(docker create --entrypoint /nonexistent "$ref" 2>/dev/null) || return 1
  out=$(docker cp -L "$cid:/usr/bin/xrpld" - 2>/dev/null | tar -xO 2>/dev/null \
        | sha256sum | awk '{print $1}') || out=""
  docker rm -f -v "$cid" >/dev/null 2>&1 || true
  [[ "$out" =~ ^[0-9a-f]{64}$ ]] || return 1
  printf '%s' "$out"
}

# The uid an image's USER runs as, worked out HERE and never by running the
# image (#1329). A numeric USER (or uid:gid) is the uid as it stands. A name
# is looked up in the image's own /etc/passwd, streamed out of a container
# that is never started. Nothing from the image is sourced or evaluated; the
# file is split on ":" and field 3 has to be a plain number.
#
# The runtime reads that file with its own parser, and a difference between
# the two readers is a way past this check. So the file has to be one that
# both read the same: printable ASCII and newlines only (a NUL is dropped by
# a shell variable and kept by the runtime; a CR or a tab is part of a name to
# one and not the other), no line padded with spaces (the runtime trims them),
# and the name on exactly one line (no first-match against any-match).
# Returns 1 when the name cannot be looked up at all (no name, a name the
# file lacks, a file that cannot be read), 2 when the file is not one
# both readers agree on, and 3 for a uid above 2147483647, which Docker
# wraps. The caller treats any of them as a refusal, never a pass.
image_user_uid() { # $1 = container id, $2 = the image's USER -> uid on stdout
  local cid=$1 spec=$2 name members pw bad line n uid hit=0 found=""
  name=${spec%%:*}
  if [[ "$name" =~ ^[0-9]{1,10}$ ]]; then
    # Docker keeps the low 32 bits of a uid it is given (uint32), and moby's
    # own bound is 2147483647: 4294967296 is root to the kernel. Base 10
    # named, so a leading zero is not read as octal.
    (( 10#$name <= 2147483647 )) || return 3
    printf '%s' "$name"
    return 0
  fi
  [[ "$name" =~ ^[A-Za-z_][A-Za-z0-9._-]{0,63}$ ]] || return 1
  members=$(docker cp -L "$cid:/etc/passwd" - 2>/dev/null | tar -tv 2>/dev/null) || return 1
  [[ $(printf '%s\n' "$members" | grep -c .) -eq 1 && "$members" == -* ]] || return 2
  # Counted on the raw stream, before a shell variable can drop a byte.
  bad=$(docker cp -L "$cid:/etc/passwd" - 2>/dev/null | tar -xO 2>/dev/null \
        | head -c 1048577 | LC_ALL=C tr -d '\040-\176\n' | wc -c) || return 1
  [[ "$bad" == 0 ]] || return 2
  pw=$(docker cp -L "$cid:/etc/passwd" - 2>/dev/null | tar -xO 2>/dev/null | head -c 1048577) || return 1
  (( ${#pw} <= 1048576 )) || return 2
  while IFS= read -r line; do
    [[ "$line" != " "* && "$line" != *" " ]] || return 2
    IFS=: read -r n _ uid _ <<<"$line"
    [[ "$n" == "$name" ]] || continue
    hit=$((hit + 1))
    found=$uid
  done <<<"$pw"
  (( hit == 1 )) || { (( hit == 0 )) && return 1; return 2; }
  [[ "$found" =~ ^[0-9]{1,10}$ ]] || return 2
  (( 10#$found <= 2147483647 )) || return 3
  printf '%s' "$found"
}

# The marker a verified digest leaves behind, and the check that reads it.
#
# Root-owned, under a root-owned directory this script creates itself. Never
# under the deployment directory or anything else the calling account can
# rename: a marker that account could plant would prove only that it wanted
# the swap to happen.
write_verified_marker() { # $1 = version, $2 = digest, $3 = binary hash, $4 = signed hash, $5 = index hash, $6 = base layer
  local f tmp
  install -d -m 0755 -o root -g root "$VERIFIED_IMAGE_DIR" 2>/dev/null \
    || mkdir -p "$VERIFIED_IMAGE_DIR" 2>/dev/null || true
  # Said plainly when it cannot be written, with what was found. This used
  # to blame the Advisor unit's ReadWritePaths, because the wrapper ran
  # through sudo inside that unit's mount namespace. It runs in its own root
  # service now (ADR 0025), so a failure here is the directory itself: not
  # root's, not a directory, or a read-only filesystem (#768).
  if [[ ! -d "$VERIFIED_IMAGE_DIR" ]] || ! : > "$VERIFIED_IMAGE_DIR/.probe" 2>/dev/null; then
    printf 'error: root could not write in %s (%s).\n' "$VERIFIED_IMAGE_DIR" \
      "$(stat -c '%U:%G %a' "$VERIFIED_IMAGE_DIR" 2>/dev/null || echo 'missing')" >&2
    printf '       It should be a root:root 0755 directory under /var/lib/aperire.\n' >&2
    printf '       Nothing about this deployment changed.\n' >&2
    return 1
  fi
  rm -f "$VERIFIED_IMAGE_DIR/.probe"
  f="$VERIFIED_IMAGE_DIR/${2//:/_}"
  tmp=$(mktemp "$VERIFIED_IMAGE_DIR/.marker.XXXXXX") || return 1
  {
    printf 'version=%s\n' "$1"
    printf 'digest=%s\n' "$2"
    printf 'binary_sha256=%s\n' "$3"
    printf 'signed_binary_sha256=%s\n' "$4"
    printf 'index_sha256=%s\n' "$5"
    printf 'base_layer=%s\n' "${6:-unknown}"
    printf 'verified_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  } > "$tmp"
  chmod 0644 "$tmp"
  mv -T "$tmp" "$f"
}

base_layer_seen_for() { # $1 = version -> the base layer a previous verify of this release recorded
  local f v b
  [[ -d "$VERIFIED_IMAGE_DIR" ]] || return 1
  for f in "$VERIFIED_IMAGE_DIR"/sha256_*; do
    [[ -f "$f" && ! -L "$f" ]] || continue
    v=$(sed -n 's/^version=//p' "$f" | head -1)
    [[ "$v" == "$1" ]] || continue
    b=$(sed -n 's/^base_layer=//p' "$f" | head -1)
    [[ -n "$b" && "$b" != unknown ]] || continue
    printf '%s' "$b"
    return 0
  done
  return 1
}

verified_marker_ok() { # $1 = version, $2 = digest -> 0 when this digest was verified FOR this version
  local f v owner mode
  f="$VERIFIED_IMAGE_DIR/${2//:/_}"
  [[ -f "$f" && ! -L "$f" ]] || return 1
  # Written by root, and nobody else's to edit (#682, second review; #768).
  # The marker is what set-image-official trusts instead of the caller's
  # word, so a file another account can write is worth exactly as much as
  # the caller's word. Root, by rule, not "whoever is running this": the
  # comparison used to be against the running uid, and on a host where the
  # Advisor ran this wrapper as its own account (the retired shared-account
  # shape) that accepted a marker the Advisor's own account had written.
  # Every call now arrives as root through the socket (ADR 0025). Read off
  # the file itself, not off the directory.
  owner=$(stat -c '%u' "$f" 2>/dev/null) || return 1
  [[ "$owner" == "$VERIFIED_MARKER_OWNER" ]] || return 1
  mode=$(stat -c '%a' "$f" 2>/dev/null) || return 1
  # The last two digits, whatever the mode's width: stat prints four when a
  # setgid or sticky bit is set, and reading fixed positions then read the
  # wrong ones. And [0145], not [0-5]: 2 and 3 carry the write bit, so a
  # 0622 marker passed a check meant to refuse a writable one.
  mode=${mode: -2}
  [[ "${mode:0:1}" =~ ^[0145]$ && "${mode:1:1}" =~ ^[0145]$ ]] || return 1
  v=$(sed -n 's/^version=//p' "$f" | head -1)
  [[ "$v" == "$1" ]]
}

# The one owner a verified-image marker may have. A constant so the tests can
# point it at the account they run as, the same as IMAGE_RECIPE_OWNER.
VERIFIED_MARKER_OWNER=0

PACKAGE_KEEP_DIR=/var/lib/aperire/rollback

# Both directories a kept artefact may be in: the one above, and the one they
# were written to before this moved. A host holding a rollback from then must
# not lose it, so the older location is still listed and still installable
# from, and only new ones are written to the first.
package_keep_dirs() {
  printf '%s\n' "$PACKAGE_KEEP_DIR"
  local legacy
  legacy=$(dirname "$CONFIG_FILE")
  [[ -n "$legacy" && "$legacy" != "$PACKAGE_KEEP_DIR" && "$legacy" != /dev ]] && printf '%s\n' "$legacy"
  return 0
}
#
# Note for whoever reads this next: the deb half is the one the lab proves
# first. The rpm commands are written from the vendor's RHEL instructions and
# are not measured on a box yet.
# It RETURNS a failure rather than dying, because every caller reads it inside
# a command substitution, and a die in a subshell kills the subshell and lets
# the script carry on with an empty answer. That is this project's
# characteristic bug, a reading nobody took rendered as a fact, and it was
# real here: package-version printed the package name and an empty version,
# and exited 0, on a host with no package manager at all.
pkg_tool() {
  if command -v apt-get >/dev/null 2>&1 && command -v apt-cache >/dev/null 2>&1 \
     && command -v dpkg-query >/dev/null 2>&1; then
    printf 'deb\n'
  elif command -v dnf >/dev/null 2>&1 && command -v rpm >/dev/null 2>&1; then
    printf 'rpm\n'
  else
    return 1
  fi
}

# The verbs that cannot work without one say so in the main shell, once, before
# they do anything else.
require_pkg_tool() {
  pkg_tool >/dev/null \
    || die "no package manager this wrapper knows is on this host (apt-get with dpkg-query, or dnf with rpm), so '$VERB' cannot be answered"
}

# What the package database says is installed right now.
#
# Three outcomes, and the caller has to tell them apart: 0 with a version, 1
# for "the database says it is not installed", which is an answer, and 2 for
# "there is nothing here to ask", which is not.
pkg_installed_version() {
  local v tool
  tool=$(pkg_tool) || return 2
  case "$tool" in
    deb)
      # dpkg-query exits 0 for a package it merely KNOWS, including one that
      # was removed and left its configuration behind, so the status is read
      # rather than the exit code.
      v=$(dpkg-query -W -f='${db:Status-Status} ${Version}' "$REPO" 2>/dev/null) || return 1
      [[ "$v" == "installed "* ]] || return 1
      printf '%s\n' "${v#installed }" ;;
    rpm)
      v=$(rpm -q --queryformat '%{VERSION}-%{RELEASE}' "$REPO" 2>/dev/null) || return 1
      [[ -n "$v" ]] || return 1
      printf '%s\n' "$v" ;;
  esac
}

# Every version of the configured package this host's own repositories offer,
# in the order the package manager lists them, which is newest first on both.
# A read: neither command writes anything and neither touches the node.
#
# The STATUS is the package manager's, not awk's, for the same reason
# rotation_state keeps PIPESTATUS: a broken sources list, an unreachable
# repository or a repoquery that errors out would otherwise come back as an
# empty list, and an empty list means "this version is not offered". That is a
# reading nobody took rendered as a fact, and RB-004 asks this question to
# decide whether a rollback has anywhere to go.
#
#   0   the list is what the repositories offer, however short
#   1   the package manager was asked and would not answer
#   2   there is no package manager here to ask
pkg_candidates() {
  local tool
  tool=$(pkg_tool) || return 2
  case "$tool" in
    deb)
      apt-cache madison "$REPO" 2>/dev/null \
        | awk -F'|' '{gsub(/ /, "", $2); if ($2 != "") print $2}'
      return "${PIPESTATUS[0]}" ;;
    rpm)
      dnf --quiet repoquery --queryformat '%{VERSION}-%{RELEASE}' "$REPO" 2>/dev/null ;;
  esac
}

# Is this URL the retired repository? One rule, kept byte for byte the same
# in scripts/install-aperire-node.sh, and the installer's suite holds the two
# copies equal. The host is repos.ripple.com, reached directly (with or
# without a port) or through a caching proxy that carries the host as the
# first path segment, the way apt-cacher-ng does. A name that merely ends in
# it is not it.
aperire_retired_source_url() {
  case "$1" in
    */repos.ripple.com|*/repos.ripple.com/*|*/repos.ripple.com:*) return 0 ;;
  esac
  return 1
}

# Whether the ONLY place this host's package manager offers the package from
# is the retired repos.ripple.com (#802). That repository stopped at 3.3.0
# when releases moved to packages.xrplf.org, so on such a host "the newest
# version the repositories offer" is a true sentence about a dead source,
# and the Advisor read it as "this node is current". After an amendment that
# needs 3.4 activates, that node is blocked while the Advisor says otherwise.
#
# deb: the third column of `apt-cache madison`, the repository each version
# comes from. rpm: `dnf repoquery --location`, the URL each would download
# from. Either way a read, and 0 only when there is at least one source and
# every one of them is repos.ripple.com. Anything it cannot read answers 1:
# this never claims a retired source on evidence nobody took.
pkg_source_retired() {
  local tool raw line url seen=0
  tool=$(pkg_tool) || return 1
  case "$tool" in
    deb)
      raw=$(apt-cache madison "$REPO" 2>/dev/null) || return 1
      while IFS= read -r line; do
        [[ "$line" == *"|"*"|"* ]] || continue
        url=${line#*|}; url=${url#*|}
        read -r url _ <<< "$url"
        [[ -n "$url" ]] || continue
        seen=1
        aperire_retired_source_url "$url" || return 1
      done <<< "$raw" ;;
    rpm)
      raw=$(dnf --quiet repoquery --location "$REPO" 2>/dev/null) || return 1
      while IFS= read -r url; do
        [[ -n "$url" ]] || continue
        seen=1
        aperire_retired_source_url "$url" || return 1
      done <<< "$raw" ;;
  esac
  (( seen ))
}

# The sentence that goes with the retired verdict, and the fix, the same
# words on both verbs. One line, no tabs: it is the third field.
#
# The command is named only for the xrpld package, because that is the only
# package the source move can help: packages.xrplf.org carries xrpld, and a
# host running the older rippled package (adopted as rippled.service) would
# be handed a command that answers "xrpld is not installed here" and changes
# nothing. That host needs a package change, and it is told so instead.
PKG_RETIRED_FIX='curl -fsSL https://get.aperire.one | bash -s -- --update --force'
pkg_retired_sentence() {
  if [[ "$REPO" == xrpld ]]; then
    printf 'the only %s source on this host is repos.ripple.com, which stopped at 3.3.0 when releases moved to packages.xrplf.org, so it cannot say what is newest; move the source (it installs, upgrades and restarts nothing): %s' \
      "$REPO" "$PKG_RETIRED_FIX"
  else
    printf 'the only %s source on this host is repos.ripple.com, which stopped at 3.3.0, so it cannot say what is newest; later releases ship as the xrpld package at packages.xrplf.org, and moving this node to it is a package change, not a source change' \
      "$REPO"
  fi
}

# The exact repository versions a caller's digits-and-dots version names.
#
# A caller cannot pass "3.3.0-1": the version shape here is the one image tags
# use, and widening it would widen what an approved plan is able to say. So
# the package release suffix is RESOLVED from what this host's repositories
# list, and a candidate matches only if it is that version exactly or that
# version followed by a dash. "3.3" can never take "3.3.1".
# It carries pkg_candidates' status out, which a process substitution would
# drop, so the list is captured first. Capturing is right here and would be
# wrong on the rotation read: this is a handful of version strings, not the
# 200,000 lines that read streams.
pkg_match() { # $1 = version -> the matching candidates, in the manager's order
  local c raw rc=0
  raw=$(pkg_candidates) || rc=$?
  (( rc == 0 )) || return "$rc"
  while IFS= read -r c; do
    [[ -n "$c" ]] || continue
    if [[ "$c" == "$1" || "$c" == "$1"-* ]]; then printf '%s\n' "$c"; fi
  done <<< "$raw"
}


# A verb that takes nothing must be given nothing. Silently ignoring a second
# word would make `restart 3.3.0` read to an operator as a restart onto a
# version, which is the one thing this verb must never be.
require_no_arg() {
  [[ -z "$ARG" ]] || die "$VERB takes no argument, and was given '$ARG'"
}

# A count for a log tail. Bounded so a verb cannot be turned into "send me the
# whole journal", an inspection verb should answer a question, not exfiltrate.
require_count() {
  [[ -n "$ARG" ]] || die "$VERB needs a line count"
  [[ "$ARG" =~ ^[1-9][0-9]{0,3}$ ]] || die "refusing count '$ARG': digits only, up to 4, no leading zero"
  (( ARG >= 1 && ARG <= 2000 )) || die "refusing count '$ARG': 1 to 2000"
}

# A configured value the inspection verbs need. The upgrade verbs do not, so a
# configuration written before these existed still works for what it covered.
require_conf() {
  [[ -n "${!1}" ]] || die "$VERB needs $1 in $CONF, re-run: curl -fsSL https://get.aperire.one | bash -s -- --node-wrapper (a node in docker) or curl -fsSL https://get.aperire.one | bash -s -- --node-wrapper-native (a node run by systemd)"
}

# A restore path must be a dated backup of one of the two files we manage, in
# the directory that file lives in. Not a path the caller chose.
require_backup_path() {
  [[ -n "$ARG" ]] || die "$VERB needs a path"
  # The glob below anchors the prefix but not the middle, so a path could walk
  # back out of it: "$COMPOSE_FILE.../../../etc/anything.bak" matches the
  # pattern and names a file nowhere near the deployment. Harmless while the
  # only caller is cancel, which passes a path this script printed, and
  # exactly the wrong thing to leave in place before rollback ships and starts
  # taking a path from a plan. Two checks, because neither is sufficient:
  # the shape, and then the actual name after the shell has done its worst.
  case "$ARG" in
    *..*)  die "refusing path '$ARG': no relative segments" ;;
    */*/*.bak|"$COMPOSE_FILE".*.bak) ;;
    *) die "refusing path '$ARG': only a dated backup of $COMPOSE_FILE" ;;
  esac
  # A dated backup lives beside the file it backs up, is named after it, and
  # ends in .bak. Anything else is not one, whatever it is called.
  local dir base
  dir=$(cd "$(dirname "$ARG")" 2>/dev/null && pwd) || die "no such directory for '$ARG'"
  base=$(basename "$ARG")
  [[ "$dir" == "$(dirname "$COMPOSE_FILE")" ]] \
    || die "refusing path '$ARG': backups live beside $COMPOSE_FILE, not in $dir"
  [[ "$base" == "$(basename "$COMPOSE_FILE")".*.bak ]] \
    || die "refusing path '$ARG': not a dated backup of $(basename "$COMPOSE_FILE")"
  [[ -f "$ARG" && ! -L "$ARG" ]] || die "no such backup, or not a regular file: $ARG"
}

# The path `package-install --from` may act on: one of package-keep's own
# artefacts, never one the caller names. The same two checks
# require_backup_path takes for the same reason, and in the same order: the
# shape first, and then the resolved directory and the basename. The first
# glob (`*"$REPO".kept.*.deb`) is deliberately loose, it anchors the suffix
# but not the start, so it would also match a name that merely ENDS the
# right way ("notxrpld.kept.1.deb"); it exists only to reject a path with no
# relative segments and the wrong shape outright, cheaply, before touching
# the filesystem. The second check, against the resolved basename alone
# (`"$REPO".kept.*.deb`, anchored at both ends because there is no path left
# in front of it to confuse the anchor), is the one that actually decides.
# Loosening that second one to match the first would be the mistake; the
# first is the pre-check, not the guard.
require_kept_path() {
  [[ -n "$ARG2" ]] || die "$VERB --from needs a path"
  case "$ARG2" in
    *..*) die "refusing path '$ARG2': no relative segments" ;;
    *"$REPO".kept.*.deb|*"$REPO".kept.*.rpm) ;;
    *) die "refusing path '$ARG2': not a kept package artefact of $REPO" ;;
  esac
  local dir base d ok_dir=0
  dir=$(cd "$(dirname "$ARG2")" 2>/dev/null && pwd) || die "no such directory for '$ARG2'"
  base=$(basename "$ARG2")
  # Either of the two directories kept artefacts live in, and nothing else.
  # The second is where they were written before #429 moved them, kept
  # installable so a host holding one from then can still roll back with it.
  while IFS= read -r d; do
    [[ "$dir" == "$d" ]] && { ok_dir=1; break; }
  done < <(package_keep_dirs)
  (( ok_dir )) \
    || die "refusing path '$ARG2': kept artefacts live in $(package_keep_dirs | tr '\n' ' '), not in $dir"
  case "$base" in
    "$REPO".kept.*.deb|"$REPO".kept.*.rpm) ;;
    *) die "refusing path '$ARG2': not a kept package artefact of $REPO" ;;
  esac
  [[ -f "$ARG2" && ! -L "$ARG2" ]] || die "no such kept artefact, or not a regular file: $ARG2"
}

log

case "$VERB" in

  status)
    require_node
    curl -s --max-time 5 --data '{"method":"server_info","params":[{}]}' "$ADMIN_RPC"
    ;;

  backup-config)
    require_node
    require_cwl
    dest=$(dated_backup "$CONFIG_FILE") \
      || die "could not take a dated copy of $CONFIG_FILE beside it";
    cmp -s "$CONFIG_FILE" "$dest" || die "backup does not match the original"
    # Keeps the newest ten, silently on stdout: this verb's whole output
    # contract to a caller is the one path it just printed below, and a
    # prune line mixed into that would be read as a second backup.
    cwl_prune_backups "$CONFIG_FILE" 10
    printf '%s\n' "$dest"
    ;;

  backup-compose)
    require_node
    require_container
    require_cwl
    dest=$(dated_backup "$COMPOSE_FILE") \
      || die "could not take a dated copy of $COMPOSE_FILE beside it";
    cmp -s "$COMPOSE_FILE" "$dest" || die "backup does not match the original"
    cwl_prune_backups "$COMPOSE_FILE" 10
    printf '%s\n' "$dest"
    ;;

  pull)
    require_node
    require_container
    require_trusted_inputs "$COMPOSE_FILE"
    require_version
    # A registry fetch, so it needs a registry. A deployment whose repository
    # is the local build name has none by construction, and `docker pull
    # localhost/xrpld:…` dials https://localhost/ and fails with a connection
    # error that says nothing about why. Refuse with the reason instead, and
    # name the verb that does apply.
    [[ "$REPO" != localhost/* ]] \
      || die "this node's images are built on this host ($REPO), so there is no registry to pull from; build it with: build-image $ARG"
    # The official repository is not fetched by tag, ever, and not by this
    # verb (#682, second review). A tag there is a label the publisher can
    # move, and an image pulled by one carries no digest this host has
    # checked anything against. pull-official takes the digest and
    # verify-official-image is what makes it usable.
    [[ "$REPO" != "$OFFICIAL_IMAGE_REPO" ]] \
      || die "$OFFICIAL_IMAGE_REPO is fetched by digest and checked on this host before anything runs it; use: pull-official $ARG <digest>"
    docker pull "$REPO:$ARG" >&2
    image_digest_of "$REPO:$ARG" || die "pulled $REPO:$ARG but it reports no digest"
    printf '\n'
    ;;

  image-digest)
    require_node
    require_container
    # What a LOCAL image resolves to, without pulling. The pull verb also
    # prints a digest, but re-pulling at cutover time would fetch whatever the
    # tag points at then, which is exactly the substitution this guards
    # against. Read-only by construction: inspect touches nothing.
    #
    # Two fields, the reference and the digest, because a version can live
    # under either origin on the same host and the caller's next move differs
    # per origin: a locally built image is swapped in with set-image-local, a
    # registry one with set-image. Printing which one answered means that
    # choice is made from evidence rather than from a configuration key that
    # may already be one swap out of date.
    require_version
    # A digest, when the caller pinned one, names the image exactly. Without
    # it this resolves by version, and on a host that has both the local
    # build wins, which is the wrong image to pin an official swap against.
    [[ -z "$ARG2" ]] || require_digest
    ref=$(ref_for "$ARG" "$ARG2") \
      || { echo "wrapper: no image for $ARG on this host, under $LOCAL_IMAGE_REPO, $OFFICIAL_IMAGE_REPO or $REPO" >&2; exit 1; }
    dg=$(image_digest_of "$ref") || { echo "wrapper: $ref reports no digest" >&2; exit 1; }
    printf '%s %s\n' "$ref" "$dg"
    ;;

  running-digest)
    require_node
    require_container
    # What the image the container is actually running resolves to, so "what
    # came up" can be compared with "what was built or pulled and verified".
    # Two hops on purpose: a container's .Image is its image CONFIG id, which
    # on a registry image is a different hash from the manifest digest that
    # pull reports, and comparing those directly would never match and would
    # look like tampering every time.
    img=$(docker inspect "$SERVICE" --format '{{.Image}}')
    [[ -n "$img" ]] || die "could not read the running image for $SERVICE"
    image_digest_of "$img" || die "the image $SERVICE is running reports no digest"
    printf '\n'
    ;;

  image-version)
    require_node
    require_container
    require_version
    # Never on an unverified official image (#682, second and third
    # reviews). This verb RUNS the image to ask its version, and running an
    # image to decide whether to trust it is the shape the first review
    # threw out. Asked of the reference this verb will actually use, so a
    # node whose own repository is localhost/xrpld is covered too: that is
    # the node pull-official has just put an official image on.
    # Ask the image itself what it holds, because a tag is a label somebody
    # chose and can move.
    #
    # This used to look the version up under the configured REPO only, and
    # to swallow the failure with `|| true`: on a node whose image is built
    # locally the reference did not exist, docker said so on a stderr that
    # went to /dev/null, and the verb printed nothing and exited 0. An empty
    # answer then travelled upward as "could not be confirmed", which reads
    # like an image that would not speak rather than a lookup that named an
    # image nobody had. Both halves are closed here: the reference is
    # resolved the same way image-digest resolves it, and an empty answer is
    # a named refusal rather than a silent pass.
    [[ -z "$ARG2" ]] || require_digest
    ref=$(ref_for "$ARG" "$ARG2") \
      || die "no image for $ARG on this host, under $LOCAL_IMAGE_REPO, $OFFICIAL_IMAGE_REPO or $REPO; build it first (build-image $ARG), pull the official one (pull-official $ARG <digest>) or pull it (pull $ARG)"
    require_verified_if_official "$ref" "$ARG"
    # The image entrypoint is a wrapper script, so reach the binary directly.
    # Either name may be right depending on the release that renamed it.
    # --network none: this runs somebody's image, and a version string needs
    # no network.
    v=$(docker run --rm --network none --entrypoint xrpld "$ref" --version 2>&1) \
      || v=$(docker run --rm --network none --entrypoint rippled "$ref" --version 2>&1) \
      || die "$ref would not report a version: $(printf '%s' "$v" | tr '\n' ' ' | cut -c1-300)"
    [[ -n "${v//[[:space:]]/}" ]] \
      || die "$ref ran and printed nothing, so what it holds is unproven; nothing downstream may treat that as a version"
    printf '%s\n' "$v"
    ;;

  set-image)
    require_node
    require_container
    require_version
    require_cwl
    require_trusted_inputs "$COMPOSE_FILE"
    # A registry tag. A deployment whose repository is the local build name
    # has no registry behind it, and writing "localhost/xrpld:<v>" here would
    # look identical to set-image-local while skipping the check that the
    # image is actually on this host and the pull_policy line that makes a
    # missing one fail loudly. Two verbs, two origins, neither pretending to
    # be the other.
    [[ "$REPO" != localhost/* ]] \
      || die "this node's images are built on this host ($REPO), so a registry tag is not what it runs; use: set-image-local $ARG"
    # And never an unpinned line naming the official repository. That is
    # the one the upgrade path spent a review learning to pin and check;
    # writing it here by tag would be the same deployment reached through
    # a door with no marker behind it (#682, second review).
    [[ "$REPO" != "$OFFICIAL_IMAGE_REPO" ]] \
      || die "$OFFICIAL_IMAGE_REPO is written pinned to a digest this host verified; use: set-image-official $ARG <digest>"
    set_compose_image "$REPO:$ARG" 0
    ;;

  set-image-local)
    require_node
    require_container
    require_version
    require_cwl
    require_trusted_inputs "$COMPOSE_FILE"
    # The image has to be here BEFORE the deployment names it. With
    # pull_policy: never beside it, a missing image stops the recreate at
    # once rather than sending compose to a registry that cannot answer for
    # this name, and refusing here means the node never gets that far.
    ref="$LOCAL_IMAGE_REPO:$ARG"
    docker image inspect "$ref" >/dev/null 2>&1 \
      || die "$ref is not on this host, so pointing the deployment at it would stop the node on an image that does not exist; build it first: build-image $ARG"
    set_compose_image "$ref" 1
    ;;

  compose-config)
    require_node
    require_container
    require_no_arg
    # A read, but root interprets the file to make it: `include:`, `env_file:`
    # and `extends:` have compose open other paths as root and fold what it
    # finds into the output, and a sibling .env is interpolated. Judged like
    # the verbs that run the file: the file and that .env are checked, and a
    # file that names others is refused rather than followed.
    require_trusted_inputs "$COMPOSE_FILE"
    # The resolved deployment: an .env, an extends: or a profile is already
    # applied, so this is what compose WILL do rather than what somebody
    # typed. A read, and the profile's one structured source for the shape
    # of a deployment this project did not write.
    #
    # JSON, so the reader is encoding/json rather than a YAML parser this
    # project would have to take a dependency for.
    #
    # `environment` is stripped HERE, on root's side, before the answer
    # leaves (#682, review of 2026-09-27). A compose file is not where
    # validator key material lives, and it is where plenty of other
    # people's secrets do: an env_file resolved by `config` is inlined into
    # this output, and this verb's caller is a service that holds a model
    # credential and talks to a model. The old note said the caller's
    # profile has no field for it, which is true and is the wrong place for
    # the boundary: a field added later would carry it without anybody
    # noticing. Nothing that is not read cannot leak.
    #
    # The values go; the KEYS stay, as a count, because "this service sets
    # eleven environment variables" is a fact about the shape and none of
    # them is a secret.
    #
    # Bounded like every other read here. A real deployment is a few
    # kilobytes; a megabyte of it is not a deployment.
    out=$(docker compose -p "$PROJECT" -f "$COMPOSE_FILE" config --format json 2>&1) \
      || die "docker compose could not resolve $COMPOSE_FILE: $(printf '%s' "$out" | tr '\n' ' ' | cut -c1-300)"
    out=$(printf '%s' "$out" | python3 -I -c '
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(1)
for svc in (d.get("services") or {}).values():
    env = svc.get("environment")
    if isinstance(env, dict):
        svc["environment"] = {k: None for k in env}
    elif isinstance(env, list):
        svc["environment"] = [str(x).split("=", 1)[0] for x in env]
    svc.pop("env_file", None)
json.dump(d, sys.stdout)
' 2>/dev/null) || die "could not strip the environment out of $COMPOSE_FILE's resolved shape; nothing was read"
    printf '%s' "$out" | head -c 262144
    printf '\n'
    ;;

  pull-official)
    require_node
    require_container
    require_version
    require_digest
    command -v docker >/dev/null 2>&1 || die "docker is not installed on this host"
    # By digest, never by tag. The digest was pinned when the operator
    # approved this, and resolving one here is exactly what pinning at
    # approval exists to prevent: a tag moved in between would install
    # something nobody looked at.
    ref="$OFFICIAL_IMAGE_REPO@$ARG2"
    # Through image_build_env for the same reason the build is (#677):
    # a docker client that wants to write under /root failed inside
    # advisord's namespace while this ran through sudo, and the separate
    # config directory keeps root's own out of it either way.
    image_build_env docker pull "$ref" >&2 \
      || die "could not pull $ref; nothing on this node changed"
    # What the store actually holds now. On a containerd store this is the
    # index digest and it equals what was asked for; that equality is the
    # check, not a formality.
    got=$(image_digest_of "$ref") || die "pulled $ref but it reports no digest"
    [[ "$got" == *"$ARG2" ]] \
      || die "pulled $ARG2 and the store reports $got; those are different images, and nothing will be pointed at either"
    # Tag it locally by version. An image with a digest and no tag is one
    # docker cannot be asked about by version, and every reader downstream
    # (image-version, image-provenance, image-digest) asks by version.
    docker tag "$ref" "$OFFICIAL_IMAGE_REPO:$ARG" \
      || die "pulled $ref but could not tag it $OFFICIAL_IMAGE_REPO:$ARG"
    printf '%s %s\n' "$OFFICIAL_IMAGE_REPO:$ARG" "$got"
    ;;

  image-provenance)
    require_node
    require_container
    require_version
    # What an image says about its own origin, in four facts a caller can
    # compare against the signed index: the .deb SHA-256 its build pinned,
    # its base, the account it runs as, and the SHA-256 of the binary
    # itself. Everything here is read from image metadata or from a
    # throwaway container with no network.
    [[ -z "$ARG2" ]] || require_digest
    ref=$(ref_for "$ARG" "$ARG2") \
      || die "no image for $ARG on this host, under $LOCAL_IMAGE_REPO, $OFFICIAL_IMAGE_REPO or $REPO"
    # An official image this host has not checked is not read by running it
    # either (#682, third review).
    require_verified_if_official "$ref" "$ARG"
    # DEB_SHA256 is a build argument, so it is in the history rather than in
    # the config. Our own recipe also writes it as a label; both are read,
    # and the label wins when it is there because it is the narrower claim.
    deb=$(docker image inspect "$ref" \
            --format '{{index .Config.Labels "xrpld.package.sha256"}}' 2>/dev/null) || deb=""
    if [[ ! "$deb" =~ ^[0-9a-f]{64}$ ]]; then
      deb=$(docker history --no-trunc --format '{{.CreatedBy}}' "$ref" 2>/dev/null \
            | grep -oE 'DEB_SHA256=[0-9a-f]{64}' | head -1 | cut -d= -f2) || deb=""
    fi
    base=$(docker image inspect "$ref" \
             --format '{{index .Config.Labels "org.opencontainers.image.base.name"}}' 2>/dev/null) || base=""
    if [[ -z "$base" ]]; then
      # Read OUT of a container that is never started, not by running the
      # image's own shell (#682, third review). An image asked to describe
      # itself with its own sh describes whatever it likes, and this verb
      # exists to report what an image claims, not to let it claim it by
      # executing.
      base=$(image_file_line "$ref" /etc/os-release) || base=""
    fi
    usr=$(docker image inspect "$ref" --format '{{.Config.User}}' 2>/dev/null) || usr=""
    ep=$(docker image inspect "$ref" --format '{{json .Config.Entrypoint}}' 2>/dev/null) || ep="null"
    cmd=$(docker image inspect "$ref" --format '{{json .Config.Cmd}}' 2>/dev/null) || cmd="null"
    # Hashed HERE, out of a container that is never started. The first
    # review threw out asking the image to hash its own binary; this verb
    # was the place it had been asked, and it kept asking.
    bin=$(image_binary_sha256 "$ref") || bin=""
    [[ "$bin" =~ ^[0-9a-f]{64}$ ]] \
      || die "/usr/bin/xrpld could not be read out of $ref, so what it would run is unproven"
    dg=$(image_digest_of "$ref") || dg=""
    printf 'ref=%s\n' "$ref"
    printf 'digest=%s\n' "${dg:-unknown}"
    printf 'deb_sha256=%s\n' "${deb:-unknown}"
    printf 'base=%s\n' "${base:-unknown}"
    printf 'user=%s\n' "${usr:-unset}"
    printf 'entrypoint=%s\n' "$ep"
    printf 'cmd=%s\n' "$cmd"
    printf 'binary_sha256=%s\n' "$bin"
    ;;

  signed-binary-sha256)
    require_node
    require_container
    require_version
    command -v docker >/dev/null 2>&1 || die "docker is not installed on this host"
    # The one check that binds what will run to the XRPL Foundation's signed
    # chain. The official image's DEB_SHA256 and its --version are claims:
    # its build fetched the .deb off an upload host and compared one hash,
    # not apt's signed metadata. This fetches the same release through the
    # chain the recipe uses (the pinned key fingerprint, the signed
    # InRelease, the Packages entry's SHA-256), unpacks the .deb, and hashes
    # usr/bin/xrpld. No hash is typed into a file anywhere.
    #
    # It names no image, so it has no package hash to pick a revision by
    # (#1001). A release published as one revision answers; one published
    # as several refuses and names them, rather than reading the newest.
    # verify-official-image is the verb that answers for a given image.
    script=$(require_recipe_file "$IMAGE_RECIPE_SIGNED_BINARY")
    # Passed to sh rather than executed, so the recipe's own 0644 mode is
    # not a trap. Read-only, and the container gets nothing of this host.
    # Nothing of this host reaches the container but the script itself,
    # read-only, and the container is gone when it returns. It needs a
    # network (that is the point: the chain is fetched, not cached) and it
    # needs to write apt's own state, so it is a plain throwaway rather than
    # a --read-only one whose tmpfs list would be a second thing to keep in
    # step with apt's layout.
    image_build_env docker run --rm \
      --security-opt no-new-privileges \
      -e "XRPLD_VERSION=$ARG" \
      -v "$script:/signed-binary-sha256.sh:ro" \
      "$SIGNED_BINARY_BASE" /bin/sh /signed-binary-sha256.sh \
      || die "could not read $ARG's binary through the signed package chain; nothing on this node changed"
    ;;

  verify-official-image)
    # No require_node/require_container: this reads an IMAGE and the signed
    # package chain, and nothing about the node. It has to answer on a host
    # that has no node yet, which is exactly when a fresh install asks.
    require_version
    require_digest
    command -v docker >/dev/null 2>&1 || die "docker is not installed on this host"
    # Everything #682 promises about an official image, checked HERE, as
    # root, with nothing of the image's own doing the checking.
    #
    # The review of 2026-09-27 found the previous shape unsound in one
    # sentence: image-provenance ran the image's OWN sha256sum to hash its
    # own binary. An image that wants to pass simply ships a sha256sum that
    # prints the right answer. Every other fact it reported (DEB_SHA256, the
    # base, the runtime user, --version) is a claim in metadata the same
    # publisher writes.
    #
    # So: the container is CREATED and never started, the binary is streamed
    # OUT of it with docker cp, and the hash is taken on this host. No code
    # from that image runs at any point in this verb.
    ref="$OFFICIAL_IMAGE_REPO@$ARG2"
    docker image inspect "$ref" >/dev/null 2>&1 \
      || die "$ref is not on this host; pull it first: pull-official $ARG $ARG2"

    # The package this image says it was built from: a claim in metadata,
    # read here (no code of the image runs) and read FIRST, because it is
    # what picks which revision of the release the signed chain is read at
    # (#1001). An image that names none cannot be bound to any revision, and
    # "the newest of this version" is exactly the guess that refused every
    # genuine 3.4.1 image the day 3.4.1-2 was published.
    deb=$(docker image inspect "$ref" \
            --format '{{index .Config.Labels "xrpld.package.sha256"}}' 2>/dev/null) || deb=""
    if [[ ! "$deb" =~ ^[0-9a-f]{64}$ ]]; then
      deb=$(docker history --no-trunc --format '{{.CreatedBy}}' "$ref" 2>/dev/null \
            | grep -oE 'DEB_SHA256=[0-9a-f]{64}' | head -1 | cut -d= -f2) || deb=""
    fi
    if [[ ! "$deb" =~ ^[0-9a-f]{64}$ ]]; then
      printf 'verified=no\n'
      die "$ref names no package it was built from (no xrpld.package.sha256 label and no DEB_SHA256 in its history), so there is no package revision to check it against; nothing was recorded"
    fi

    # What the signed chain says that package is. If this cannot be read
    # there is nothing to compare against and the verb refuses rather than
    # reporting a comparison it did not make.
    if signed=$(verify_signed_release "$ARG" "$deb"); then
      signed_rc=0
    else
      signed_rc=$?
    fi
    if (( signed_rc == 3 )); then
      # The chain was read, and this image's package is not in it at this
      # release. A finding about the image, said as one.
      printf 'deb_sha256=%s\n' "$deb"
      printf 'verified=no\n'
      die "$ref says it was built from package $deb, and the signed index has no revision of xrpld $ARG that is that package ($(printf '%s\n' "$signed" | sed -n 's/^refused=//p' | head -1)); nothing was recorded"
    elif (( signed_rc != 0 )); then
      die "could not read $ARG through the signed package chain, so nothing about $ref was checked ($(printf '%s\n' "$signed" | sed -n 's/^refused=//p' | head -1))"
    fi
    # The file verify_signed_release made for the per-file hashes stays in the
    # temp dir unless something removes it, and it stayed there on every check
    # (#588). Removed on every way out of this branch, by the one name it was
    # made under: the value came back through a stream, so it is removed only
    # if it still has the shape of what that function creates. Set before any
    # of the refusals below, because each of them is a die.
    # The LAST such line: verify_signed_release appends its own after whatever
    # the container printed, so a line of the container's cannot be the one read.
    signed_md5=$(printf '%s\n' "$signed" | sed -n 's/^package_md5sums=//p' | tail -1)
    md5_scrap() {
      [[ "${signed_md5:-}" == "${TMPDIR:-/tmp}"/aperire-md5sums.?????? && -f "$signed_md5" && ! -L "$signed_md5" ]] \
        && rm -f -- "$signed_md5"
      return 0
    }
    trap md5_scrap EXIT
    signed_pkg=$(printf '%s\n' "$signed" | sed -n 's/^package=xrpld=//p' | head -1)
    signed_deb=$(printf '%s\n' "$signed" | sed -n 's/^deb_sha256=//p' | head -1)
    # One revision, chosen once, by the image's own package hash, and every
    # comparison below is against it. The chain's answer has to say which
    # revision it read and that its .deb is the image's; a reader that
    # answered for any other package (an older recipe that took the newest,
    # say) is refused here rather than compared against.
    [[ "$signed_pkg" == "$ARG"-* && "${signed_pkg#"$ARG"-}" =~ ^[0-9]+$ ]] \
      || die "the signed package chain did not say which revision of $ARG it read (got '${signed_pkg:0:40}'); if the image recipe under $IMAGE_RECIPE_DIR is older than this wrapper, update Aperire. Nothing was recorded"
    [[ "$signed_deb" == "$deb" ]] \
      || die "the signed package chain read xrpld=$signed_pkg as package '${signed_deb:0:64}', and $ref says it was built from $deb; nothing was recorded"
    # The newest signed revision of this release, as the chain listed it.
    # Information only (operator ruling on #1001): an image carrying an
    # older revision still verifies, and the output says which is newest.
    newest_rev=$(printf '%s\n' "$signed" | sed -n 's/^newest_revision=//p' | head -1)
    [[ "$newest_rev" == "$ARG"-* && "${newest_rev#"$ARG"-}" =~ ^[0-9]+$ ]] || newest_rev=unknown
    signed_bin=$(printf '%s\n' "$signed" | sed -n 's/^binary_sha256=//p' | head -1)
    signed_ver=$(printf '%s\n' "$signed" | sed -n 's/^binary_version=//p' | head -1)
    signed_commit=$(printf '%s\n' "$signed" | sed -n 's/^binary_commit=//p' | head -1)
    [[ "$signed_bin" =~ ^[0-9a-f]{64}$ ]] \
      || die "the signed package chain answered with no usable binary hash for $ARG"

    cid=$(docker create --entrypoint /nonexistent "$ref" 2>/dev/null) \
      || die "could not create a container from $ref to read it; nothing was checked"
    # Removed whatever happens next, including a die inside the checks.
    # -v as well as -f: an image with a VOLUME leaves an anonymous volume
    # behind for every container created from it, and this verb creates one
    # per check (#682, second review).
    # shellcheck disable=SC2064
    trap "docker rm -f -v '$cid' >/dev/null 2>&1 || true; md5_scrap" EXIT

    # Exactly ONE member, and a regular file (#682, second review). A
    # DIRECTORY at /usr/bin/xrpld streams its whole tree through `tar -xO`,
    # which hashes to something, takes as long as the image wants it to,
    # and is not a binary. The listing is read first, on its own, so the
    # shape is decided before any of it is concatenated.
    members=$(docker cp -L "$cid:/usr/bin/xrpld" - 2>/dev/null | tar -tv 2>/dev/null) \
      || die "could not read /usr/bin/xrpld out of $ref, so what it would run is unproven"
    [[ $(printf '%s\n' "$members" | grep -c .) -eq 1 ]] \
      || die "/usr/bin/xrpld in $ref is not one file: $(printf '%s' "$members" | head -3 | tr '\n' ' ')"
    [[ "$members" == -* ]] \
      || die "/usr/bin/xrpld in $ref is not a regular file: ${members:0:40}"
    bin=$(docker cp -L "$cid:/usr/bin/xrpld" - 2>/dev/null | tar -xO 2>/dev/null | sha256sum | awk '{print $1}')
    [[ "$bin" =~ ^[0-9a-f]{64}$ ]] \
      || die "could not read /usr/bin/xrpld out of $ref, so what it would run is unproven"

    # The loader's own hooks, which the binary's hash says nothing about.
    # /etc/ld.so.preload names a library loaded into EVERY process in that
    # image before its own code, and LD_PRELOAD / LD_LIBRARY_PATH in the
    # image's environment do the same for the process the deployment starts.
    # A genuine binary beside either of those is not a genuine node.
    preload=absent
    if docker cp -L "$cid:/etc/ld.so.preload" - >/dev/null 2>&1; then
      preload=present
    fi
    ldenv=$(docker image inspect "$ref" --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null \
            | grep -E '^LD_[A-Z_]+=' | cut -d= -f1 | paste -sd, -) || ldenv=""

    # The package's own files, compared against the .deb the signed chain
    # verified. The binary is the one that matters and it is not the only
    # file the package owns: validator-keys sits beside it, and the unit and
    # the stock config are read by the installer. Streamed out the same way,
    # hashed here.
    pkgfiles_ok=unmeasured
    pkgfiles_detail="the signed chain listed no per-file hashes, so only the binary was compared"
    pkgfiles_n=0
    if [[ -n "$signed_md5" && -f "$signed_md5" ]]; then
      pkgfiles_ok=yes
      while IFS=' ' read -r want path; do
        [[ -n "$path" ]] || continue
        # What a node RUNS and READS. Documentation is deliberately out:
        # dpkg compresses man pages and licences at build time and records
        # them under names that differ between builds, so comparing them
        # answers "the doc tree was packed differently", which is not a
        # statement about the node. Binaries, libraries and configuration
        # are the files that decide what runs.
        case "$path" in
          usr/bin/*|usr/sbin/*|usr/lib/*|lib/*|etc/*) ;;
          *) continue ;;
        esac
        got=$(docker cp -L "$cid:/$path" - 2>/dev/null | tar -xO 2>/dev/null | md5sum | awk '{print $1}')
        pkgfiles_n=$((pkgfiles_n + 1))
        if [[ "$got" != "$want" ]]; then
          pkgfiles_ok=no
          pkgfiles_detail="/$path in the image is not the file the signed .deb ships"
          break
        fi
      done < "$signed_md5"
      if [[ "$pkgfiles_ok" == yes ]]; then
        pkgfiles_detail="$pkgfiles_n of the package's own binaries, libraries and configuration files match the signed .deb"
      fi
      if [[ "$pkgfiles_ok" == yes && "$pkgfiles_n" -eq 0 ]]; then
        pkgfiles_ok=unmeasured
        pkgfiles_detail="the signed .deb listed no binaries, libraries or configuration to compare"
      fi
    fi

    # Everything else that gets loaded into the node's process, against the
    # image's own package records (#682, second review).
    # In an `if`, not a bare assignment: this script runs under `set -e`,
    # and an assignment whose command substitution fails takes the whole
    # verb down before it can say anything. It did exactly that on the
    # first live run of this check.
    if loaded_detail=$(image_files_accounted_for "$cid" "$signed_md5"); then
      loaded_rc=0
    else
      loaded_rc=$?
    fi
    case "$loaded_rc" in
      0) loaded_ok=yes ;;
      1) loaded_ok=no ;;
      *) loaded_ok=unmeasured ;;
    esac

    # The base image's own layer, recorded per release so a base that
    # changes under a release is visible rather than assumed.
    baselayer=$(docker image inspect "$ref" \
                  --format '{{index .RootFS.Layers 0}}' 2>/dev/null) || baselayer=""

    # The claims, recorded beside the measurements rather than instead of
    # them. A caller reading this knows which is which. The package claim
    # ($deb) was read above, before the signed chain, because it picks the
    # revision.
    usr=$(docker image inspect "$ref" --format '{{.Config.User}}' 2>/dev/null) || usr=""
    # Who that USER is once the image's own /etc/passwd has had its say
    # (#1329). Read now: the container is removed below. A name is not a
    # uid, and `USER xrpld` beside `xrpld:x:0:0` runs the node as root.
    usr_uid=""
    usr_rc=0
    if [[ -n "$usr" ]]; then
      if usr_uid=$(image_user_uid "$cid" "$usr"); then
        usr_rc=0
      else
        usr_rc=$?
        usr_uid=""
      fi
    fi
    base=$(docker image inspect "$ref" \
             --format '{{index .Config.Labels "org.opencontainers.image.base.name"}}' 2>/dev/null) || base=""
    # The index's entry for the SAME revision the chain read, never for
    # whichever revision of the release the index happens to list first.
    idx=$(package_index_sha256 "$signed_pkg") || idx=""
    # Unmeasured is a failure on this side too (#682, second review). The
    # Go gate refuses an answer with index_sha256=unknown, but the marker
    # was written first, and a marker is the thing set-image-official
    # trusts. Nothing may be recorded as verified on a check that did not
    # run.
    [[ -n "$idx" ]] \
      || die "the signed package index could not be read for $ARG, so the package this image says it was built from was never compared; nothing was recorded"

    docker rm -f -v "$cid" >/dev/null 2>&1 || true
    md5_scrap
    trap - EXIT

    # The verdict. Every check has to be MEASURED and EQUAL; an unmeasured
    # one is never a pass (#679), and the one exception is named as such.
    fail=""
    if [[ "$bin" != "$signed_bin" ]]; then
      fail="the binary in the image is not the binary in the signed package ($bin, expected $signed_bin)"
    elif [[ "$preload" != absent ]]; then
      fail="$ref ships /etc/ld.so.preload, which loads code into the node before its own"
    elif [[ -n "$ldenv" ]]; then
      fail="$ref sets $ldenv in its own environment, which changes what the node loads"
    elif [[ "$pkgfiles_ok" == no ]]; then
      fail="$pkgfiles_detail"
    elif [[ "$pkgfiles_ok" == unmeasured ]]; then
      fail="the package's own files could not be compared: $pkgfiles_detail"
    elif [[ "$loaded_ok" == no ]]; then
      fail="$loaded_detail"
    elif [[ "$loaded_ok" == unmeasured ]]; then
      fail="what this image would load into the node could not be accounted for: $loaded_detail"
    elif [[ -n "$idx" && "$deb" != "$idx" ]]; then
      fail="the image says it was built from package $deb; the signed index publishes $idx"
    elif [[ -z "$usr" ]]; then
      fail="$ref names no account of its own, so it would run as root wherever a deployment names none"
    elif [[ "$usr_rc" == 3 ]]; then
      fail="$ref runs as '$usr', which resolves to an account Docker would run as root (a uid above 2147483647 wraps to 0); nothing was recorded. Use an image whose USER is an unprivileged account, or build the image here from the signed package"
    elif [[ "$usr_rc" == 2 ]]; then
      fail="$ref runs as '$usr', and the image's /etc/passwd is malformed (an odd byte, a line padded with spaces, the name on more than one line, or a uid that is not a number), so what that name means is not proven; nothing was recorded. Build the image here from the signed package instead"
    elif [[ -z "$usr_uid" ]]; then
      fail="$ref runs as '$usr', and that could not be turned into a uid from the image's own /etc/passwd, so it is not proven to run as anyone but root; nothing was recorded. Build the image here from the signed package instead"
    elif [[ "$usr_uid" =~ ^0+$ ]]; then
      fail="$ref runs as '$usr', which is uid 0 (root) inside the container wherever a deployment names no user; nothing was recorded. Use an image whose USER is an unprivileged account, or build the image here from the signed package"
    fi

    printf 'ref=%s\n' "$ref"
    printf 'digest=%s\n' "$ARG2"
    printf 'version=%s\n' "$ARG"
    printf 'binary_sha256=%s\n' "$bin"
    printf 'signed_binary_sha256=%s\n' "$signed_bin"
    printf 'signed_binary_version=%s\n' "${signed_ver:-unknown}"
    printf 'signed_binary_commit=%s\n' "${signed_commit:-unknown}"
    printf 'signed_package=xrpld=%s\n' "$signed_pkg"
    printf 'newest_revision=%s\n' "$newest_rev"
    printf 'deb_sha256=%s\n' "${deb:-unknown}"
    printf 'index_sha256=%s\n' "${idx:-unknown}"
    printf 'loaded_files=%s\n' "${loaded_ok:-unmeasured}"
    printf 'loaded_detail=%s\n' "${loaded_detail:-unmeasured}"
    printf 'base_layer=%s\n' "${baselayer:-unknown}"
    # What that recorded layer is FOR: a second verify of the same release
    # built on a different base is worth an operator's attention. Reported,
    # never refused: a publisher may rebuild a release on a newer base, and
    # which of those it is is a judgement, not a rule.
    if prev_base=$(base_layer_seen_for "$ARG"); then
      if [[ -n "$baselayer" && "$baselayer" != "$prev_base" ]]; then
        printf 'base_layer_drift=yes\n'
        printf 'base_layer_was=%s\n' "$prev_base"
      else
        printf 'base_layer_drift=no\n'
      fi
    else
      printf 'base_layer_drift=first\n'
    fi
    printf 'base=%s\n' "${base:-unknown}"
    printf 'user=%s\n' "${usr:-unset}"
    printf 'ld_preload=%s\n' "$preload"
    printf 'ld_env=%s\n' "${ldenv:-none}"
    printf 'package_files=%s\n' "$pkgfiles_ok"
    printf 'package_files_detail=%s\n' "$pkgfiles_detail"
    if [[ -n "$fail" ]]; then
      printf 'verified=no\n'
      die "$fail"
    fi
    write_verified_marker "$ARG" "$ARG2" "$bin" "$signed_bin" "${idx:-unknown}" "${baselayer:-unknown}" \
      || die "this image checked out, but the result could not be recorded, so nothing was swapped"
    printf 'verified=yes\n'
    ;;

  set-image-official)
    require_node
    require_container
    require_version
    require_digest
    require_cwl
    require_trusted_inputs "$COMPOSE_FILE"
    # The digest has to have been VERIFIED on this host, by the verb above,
    # as root (#682, review of 2026-09-27). Without this, advisord could
    # pull any digest from that repository, a commit-hash dev tag among
    # them, and point a validator at it: the pull verb refuses a reference
    # outside the official repository, and that repository publishes
    # hundreds of things that are not releases.
    verified_marker_ok "$ARG" "$ARG2" \
      || die "$ARG2 has not been verified on this host for $ARG; run verify-official-image $ARG $ARG2 first. Nothing about this deployment changed"
    # The image has to be here, at that digest, BEFORE the deployment names
    # it: pointing a node at an image that is not on the host stops it on a
    # reference nothing can answer for.
    ref="$OFFICIAL_IMAGE_REPO@$ARG2"
    docker image inspect "$ref" >/dev/null 2>&1 \
      || die "$ref is not on this host; pull it first: pull-official $ARG $ARG2"
    # The digest is the reference and the version is a comment. pull_policy:
    # never is a local build's line, and leaving it beside a registry digest
    # would make compose refuse to fetch an image it may legitimately need
    # after a prune.
    set_compose_image "$ref" 0 "$ARG"
    ;;

  set-node-args)
    require_node
    require_container
    require_no_arg
    require_cwl
    require_trusted_inputs "$COMPOSE_FILE"
    # One fixed literal pair, and no argument at all. There is no allowlist
    # to get wrong, and a deployment that needs different arguments is one
    # this verb declines rather than one it tries to express.
    #
    # The refusal first: see compose_config_at_etc above for why writing
    # these two lines on a /config-only deployment would take a validator
    # off the network quietly.
    compose_config_at_etc "$COMPOSE_FILE" \
      || die "this deployment does not mount its config at /etc/xrpld/xrpld.cfg, and writing an entrypoint here would bypass the image's own script that copies it there; the node would come back on the package's stock config with no validator key. Run add-config-mount first"
    read -r s e < <(compose_service_range "$COMPOSE_FILE")
    (( s > 0 )) || die "no service named $SERVICE in $COMPOSE_FILE"
    ind=$(compose_inner_indent "$COMPOSE_FILE" "$s" "$e")
    [[ -n "$ind" ]] || die "could not read $SERVICE's indentation in $COMPOSE_FILE"
    if sed -n "${s},${e}p" "$COMPOSE_FILE" | grep -qE '^[[:space:]]*(entrypoint|command):'; then
      die "$SERVICE already names an entrypoint or a command; this verb writes one fixed pair and will not overwrite what an operator chose"
    fi
    ln=$(grep -n -m1 -E '^[[:space:]]*image:' "$COMPOSE_FILE" | cut -d: -f1) || true
    if ! [[ "$ln" =~ ^[0-9]+$ ]] || (( ln < s || ln > e )); then
      die "could not locate $SERVICE's image line in $COMPOSE_FILE"
    fi
    # After the pull_policy line, not after the image line, WHEN the two are
    # adjacent. `pull_policy` sitting directly under `image` is an invariant
    # the set-image verbs rely on and refuse without: they manage that one
    # line and no other, so a file with something in between is a file they
    # decline to touch. Writing these two in that gap put a normalised
    # deployment in exactly that state, and the next upgrade halted on
    # "carries a pull_policy line that is not the one under its image line"
    # after the pull, with the node still up and the deployment half done.
    # Met on aperire1, 2026-09-27.
    nxt=$(( ln + 1 ))
    if (( nxt <= e )) && sed -n "${nxt}p" "$COMPOSE_FILE" | grep -qE '^[[:space:]]*pull_policy:'; then
      ln=$nxt
    fi
    tmp=$(rewrite_tmp)
    awk -v ln="$ln" -v ind="$ind" '
      { print }
      NR == ln {
        print ind "entrypoint: [\"/usr/bin/xrpld\"]"
        print ind "command: [\"--conf\", \"/etc/xrpld/xrpld.cfg\"]"
      }' "$COMPOSE_FILE" > "$tmp"
    compose_write_tmp "$tmp" 'entrypoint: ["/usr/bin/xrpld"] / command: ["--conf", "/etc/xrpld/xrpld.cfg"]'
    ;;

  add-config-mount)
    require_node
    require_container
    require_no_arg
    require_cwl
    require_trusted_inputs "$COMPOSE_FILE"
    # The two /etc/xrpld read-only binds a legacy /config-only deployment
    # needs before any image that has no entrypoint script can read its
    # config. The /config pair STAYS: a rollback to the current image needs
    # it, and migrate-node-nonroot.sh refuses a compose without it.
    if compose_config_at_etc "$COMPOSE_FILE"; then
      printf 'already mounted: the config is at /etc/xrpld/xrpld.cfg\n'
      exit 0
    fi
    read -r s e < <(compose_service_range "$COMPOSE_FILE")
    (( s > 0 )) || die "no service named $SERVICE in $COMPOSE_FILE"
    # The host paths come from the deployment's own /config mounts, never
    # from a caller and never from a guess: whatever file this node already
    # reads is the file it keeps reading.
    # `|| true` on both: a deployment with no such mount is a real state
    # this verb has a named refusal for, and pipefail would otherwise end the
    # run on the grep with nothing said at all.
    cfg_src=$(sed -n "${s},${e}p" "$COMPOSE_FILE" \
              | grep -oE '^[[:space:]]*-[[:space:]]*[^[:space:]]+:/config/rippled\.cfg(:[a-z,]+)?' \
              | head -1 | sed -E 's#^[[:space:]]*-[[:space:]]*##; s#:/config/rippled\.cfg.*$##') || true
    val_src=$(sed -n "${s},${e}p" "$COMPOSE_FILE" \
              | grep -oE '^[[:space:]]*-[[:space:]]*[^[:space:]]+:/config/validators\.txt(:[a-z,]+)?' \
              | head -1 | sed -E 's#^[[:space:]]*-[[:space:]]*##; s#:/config/validators\.txt.*$##') || true
    [[ -n "$cfg_src" ]] \
      || die "$SERVICE mounts nothing at /config/rippled.cfg, so there is no config on this host for this verb to also mount at /etc/xrpld; fix the deployment by hand"
    [[ "$cfg_src" == /* && "$cfg_src" != *..* ]] \
      || die "refusing config source '$cfg_src': an absolute path with no relative segments, or nothing"
    [[ -z "$val_src" ]] || [[ "$val_src" == /* && "$val_src" != *..* ]] \
      || die "refusing validators source '$val_src': an absolute path with no relative segments, or nothing"
    vl=$(awk -v s="$s" -v e="$e" 'NR>=s && NR<=e && $0 ~ /^[[:space:]]*volumes:[[:space:]]*(#.*)?$/ { print NR; exit }' "$COMPOSE_FILE")
    [[ "$vl" =~ ^[0-9]+$ ]] \
      || die "$SERVICE has no volumes: list this verb can add to (an inline list is not one it will rewrite); fix the deployment by hand"
    # The list's own item indent, from its first item.
    vind=$(awk -v v="$vl" -v e="$e" 'NR>v && NR<=e && $0 ~ /^[[:space:]]*-[[:space:]]/ { match($0,/^[[:space:]]*/); print substr($0,1,RLENGTH); exit }' "$COMPOSE_FILE")
    [[ -n "$vind" ]] || die "$SERVICE's volumes: list has no entries to take an indentation from"
    tmp=$(rewrite_tmp)
    awk -v v="$vl" -v ind="$vind" -v cfg="$cfg_src" -v val="$val_src" '
      { print }
      NR == v {
        print ind "- " cfg ":/etc/xrpld/xrpld.cfg:ro"
        if (val != "") print ind "- " val ":/etc/xrpld/validators.txt:ro"
      }' "$COMPOSE_FILE" > "$tmp"
    compose_config_at_etc "$tmp" \
      || { rm -f "$tmp"; die "the rewrite did not leave a mount at /etc/xrpld/xrpld.cfg; $COMPOSE_FILE is untouched"; }
    compose_write_tmp "$tmp" "mounted $cfg_src at /etc/xrpld/xrpld.cfg (read-only), and the /config pair stays"
    ;;

  set-runtime-user)
    require_node
    require_container
    require_userspec
    require_cwl
    require_trusted_inputs "$COMPOSE_FILE"
    read -r s e < <(compose_service_range "$COMPOSE_FILE")
    (( s > 0 )) || die "no service named $SERVICE in $COMPOSE_FILE"
    # The service's OWN user:, at the service's own indent. A `user:` key
    # nested under anything else in that range (a build block, a develop
    # block, a healthcheck somebody wrote) is a different setting, and
    # rewriting it would leave the runtime account untouched while
    # reporting that it had been set (#682, review of 2026-09-27).
    svc_ind=$(compose_inner_indent "$COMPOSE_FILE" "$s" "$e")
    [[ -n "$svc_ind" ]] || die "could not read $SERVICE's indentation in $COMPOSE_FILE"
    ul=$(awk -v s="$s" -v e="$e" -v want="${#svc_ind}" '
      NR>=s && NR<=e {
        match($0, /^[[:space:]]*/)
        if (RLENGTH == want && substr($0, RLENGTH+1) ~ /^user:[[:space:]]/) { print NR; exit }
      }' "$COMPOSE_FILE")
    tmp=$(rewrite_tmp)
    if [[ "$ul" =~ ^[0-9]+$ ]]; then
      awk -v ln="$ul" -v u="$ARG" '
        NR == ln { match($0, /^[[:space:]]*/); print substr($0,1,RLENGTH) "user: \"" u "\""; next }
        { print }' "$COMPOSE_FILE" > "$tmp"
    else
      ind=$(compose_inner_indent "$COMPOSE_FILE" "$s" "$e")
      [[ -n "$ind" ]] || { rm -f "$tmp"; die "could not read $SERVICE's indentation in $COMPOSE_FILE"; }
      ln=$(grep -n -m1 -E '^[[:space:]]*image:' "$COMPOSE_FILE" | cut -d: -f1) || true
      if ! [[ "$ln" =~ ^[0-9]+$ ]] || (( ln < s || ln > e )); then
        rm -f "$tmp"; die "could not locate $SERVICE's image line in $COMPOSE_FILE"
      fi
      awk -v ln="$ln" -v ind="$ind" -v u="$ARG" '
        { print }
        NR == ln { print ind "user: \"" u "\"" }' "$COMPOSE_FILE" > "$tmp"
    fi
    grep -qE "^[[:space:]]*user:[[:space:]]*\"$ARG\"[[:space:]]*$" "$tmp" \
      || { rm -f "$tmp"; die "the rewrite did not leave a user: line; $COMPOSE_FILE is untouched"; }
    compose_write_tmp "$tmp" "user: \"$ARG\""
    ;;

  build-image)
    require_node
    require_container
    require_trusted_inputs "$COMPOSE_FILE"
    require_version
    require_recipe
    command -v docker >/dev/null 2>&1 || die "docker is not installed on this host"
    # Builds nothing that is running: the node keeps validating throughout,
    # and the tag it would be swapped to is a new name until set-image-local
    # names it. So this verb changes no deployment and interrupts nothing.
    #
    # Never --rebuild. Two builds of one version are different images (the
    # build date is in them), so rebuilding would move the tag off the image
    # a running node was created from and the next recreate would change the
    # node's image with nobody having asked. The recipe verifies an existing
    # tag instead, which is the behaviour this verb wants.
    #
    # --no-deb-sha256 is NOT "skip the check". The recipe consults its own
    # table of announced hashes first and pins whenever it has a row for this
    # version; the flag only says what to do when it has none, and what it
    # does then is fall back on the signed chain apt already verifies:
    # the pinned key fingerprint, the signed InRelease, the Packages entry's
    # SHA-256, and the .deb that hash names. That chain is the authority for
    # a build the Advisor drives, because the alternative is a release that
    # cannot be installed until a person has read an announcement and typed a
    # hash into a file. The hash of the bytes that were actually installed is
    # recorded in the image's own provenance either way, and this verb prints
    # it.
    # The recipe's output goes to this verb's stdout AS IT LANDS, and a copy
    # is kept for the lines below that read it.
    #
    # It used to be captured whole (`out=$(…)`) and printed once at the end,
    # so a build that takes a minute sent the operator nothing for that
    # minute and then 120 lines stamped at the same second (#678). The
    # Operations card's working line is keyed to the recipe's own phases, and
    # a phase cannot advance on output that arrives all at once.
    #
    # Nothing here keeps a copy of the output: the only reader of it is the
    # caller reading this verb's stdout, and the line the executor parses
    # ("built <tag> <id>") is printed below from a fresh docker read.
    #
    # One line is kept, the recipe's own last refusal, and it leads the
    # error this verb ends with (#801). A version the repository does not
    # carry used to end in "the image build failed" alone, with the reason
    # buried hundreds of lines up, and that last line is all the Advisor
    # relays. The build itself stays in this shell, so image_build_env's
    # trap still takes its directory with it on a signal; only the relay
    # runs beside it, and it is waited for before anything else is said.
    # The one line goes in a directory of root's own (mktemp -d, 0700), never
    # at a name in /tmp itself.
    _bi_dir="$(mktemp -d -t aperire-build-why-XXXXXX)" \
      || die "could not create a directory to keep the build's reason in; nothing was built"
    chmod 0700 "$_bi_dir"
    _bi_rc=0
    image_build_env bash "$IMAGE_RECIPE_DIR/$IMAGE_RECIPE_SCRIPT" \
      --version "$ARG" --no-deb-sha256 > >(build_relay_reason 3>&1 > "$_bi_dir/why") 2>&1 || _bi_rc=$?
    wait "$!" 2>/dev/null || true
    _bi_why="$(cat "$_bi_dir/why" 2>/dev/null || true)"
    rm -rf "$_bi_dir"
    (( _bi_rc == 0 )) \
      || die "${_bi_why:+$_bi_why; }the image build failed; nothing on this node was changed"
    id=$(docker image inspect "$LOCAL_IMAGE_REPO:$ARG" --format '{{.Id}}' 2>/dev/null) \
      || die "the build reported success and $LOCAL_IMAGE_REPO:$ARG is not on this host"
    printf 'built %s %s\n' "$LOCAL_IMAGE_REPO:$ARG" "$id"
    ;;

  restore-compose)
    require_node
    require_container
    # A bare file name is a dated copy beside the compose file this
    # configuration names, and that is the only way the Advisor asks for one:
    # the root socket takes no paths (ADR 0025). A full path still works for
    # an operator running this as root, and both go through the same check.
    if [[ -n "$ARG" && "$ARG" != */* ]]; then
      ARG="$(dirname "$COMPOSE_FILE")/$ARG"
    fi
    require_backup_path
    require_trusted_inputs "$COMPOSE_FILE" "$ARG"
    # The copy has to be the one this rollback was approved for. The caller
    # names the version beside the path, and the version inside the file is
    # read here and compared (#682, second review): a plan that named one
    # copy and a run that restored another is how a node ends up two
    # releases back under an approval that said one. No version given is
    # the older callers (cancel restores the copy it just took), and those
    # keep working.
    if [[ -n "$ARG2" ]]; then
      restore_v=$(compose_tag_of_file "$ARG")
      [[ "$restore_v" == "$ARG2" ]] \
        || die "$ARG names ${restore_v:-no version} and this rollback is to $ARG2; nothing was restored"
    fi
    # A copy that pins an OFFICIAL image is a deployment naming a digest,
    # and this host has to have checked that digest (#682, second review).
    # Restoring one was the last door into a deployment naming an official
    # image with no marker behind it: set-image-official refuses that, and
    # a whole-file restore was going around it.
    restore_ref=$(compose_image_ref "$ARG")
    if [[ "$restore_ref" == "$OFFICIAL_IMAGE_REPO"@* || "$restore_ref" == "$OFFICIAL_IMAGE_REPO":*@* ]]; then
      restore_dg=${restore_ref#*@}
      verified_marker_ok "${ARG2:-$(compose_tag_of_file "$ARG")}" "$restore_dg" \
        || die "$ARG names $OFFICIAL_IMAGE_REPO at $restore_dg, which this host has not checked; run verify-official-image first. Nothing was restored"
    fi
    # On descriptors, carrying the copy's own owner, group, mode and ACL as
    # `cp -a` did, and never through a link at either name.
    restore_backup "$ARG" "$COMPOSE_FILE" \
      || die "could not put $ARG back in place of $COMPOSE_FILE; the deployment file is as it was"
    printf 'restored %s\n' "$ARG"
    ;;

  recreate)
    require_node
    require_container
    require_trusted_inputs "$COMPOSE_FILE" "$CONFIG_FILE"
    # Recreate stops the node exactly as restart does, so it carries the same
    # hazard and takes the same guard. The task that added this named only
    # `restart`; leaving recreate open would have left the upgrade cutover,
    # the one operation an operator runs least often and trusts most, as the
    # remaining way to stop a node mid-rotation.
    rotation_guard
    # The stop grace, explicit, printed, and NOT left to the engine (#665).
    #
    # `docker compose up -d` with no -t gives the OLD container's stop the
    # timeout that container was CREATED with (.Config.StopTimeout), not the
    # stop_grace_period the file now names. Measured on aperire3 on
    # 2026-09-26: a container created at 5s, with the file since edited to
    # 20s, was killed 5.016 s after SIGTERM. So raising the grace before an
    # upgrade did nothing for the one stop the upgrade performs, which is
    # exactly backwards from what raising it is for. Precedence is -t, then
    # the old container's recorded value, then the file's, which never
    # applies to this stop.
    #
    # rippled killed mid-write is how a NuDB store gets damaged, and the lab
    # has seen SIGKILL at a 90 s grace on two of four stops. The package's
    # own systemd unit gives the same binary TimeoutStopSec=5min, so that is
    # the floor here. A longer grace costs nothing when the node exits
    # promptly: docker waits for the exit, not for the timer.
    #
    # The asymmetry is worth stating: a ROLLBACK's recreate needs this just
    # as much, because the container it stops is the one the upgrade created,
    # and whatever that one recorded is what the engine would otherwise use.
    stop_grace=$RECREATE_STOP_GRACE_FLOOR
    grace_src="this wrapper's floor"
    # Both readings, both capped. The file's cap is the obvious one; the
    # container's matters just as much, because compose COPIES
    # stop_grace_period into the container it creates, so a file that named
    # something absurd once is a StopTimeout every later stop inherits even
    # after the file is fixed. Capping the file and then using the
    # container's uncapped value is how a run printed "the floor below
    # applies" and then waited on a number four orders of magnitude past it.
    declared_rc=0; declared=$(container_stop_grace "$SERVICE") || declared_rc=$?
    file_rc=0;     file_grace=$(compose_stop_grace "$COMPOSE_FILE") || file_rc=$?
    if (( declared_rc == 0 )) && [[ -n "$declared" ]] && (( declared > stop_grace )); then
      stop_grace=$declared; grace_src="the running container's own StopTimeout"
    fi
    if (( file_rc == 0 )) && [[ -n "$file_grace" ]] && (( file_grace > stop_grace )); then
      stop_grace=$file_grace; grace_src="the deployment's stop_grace_period"
    fi
    # One story: what was used, where it came from, what each reading said,
    # and which of them was past the ceiling. A note above the number saying
    # a value "is not used" while the number below it IS that value is worse
    # than no note.
    printf 'stop grace %ss (%s; the container records %s, the file says %s)\n' \
      "$stop_grace" "$grace_src" \
      "$(grace_note "$declared" "$declared_rc")" "$(grace_note "$file_grace" "$file_rc")"
    # Scoped to the one service, by project and file. Never `down`, which on
    # this project would take the whole compose stack with it.
    docker compose -p "$PROJECT" -f "$COMPOSE_FILE" up -d -t "$stop_grace" "$SERVICE" >&2
    docker inspect "$SERVICE" --format '{{.State.Status}} {{.Config.Image}}'
    ;;

  restart)
    require_node
    require_no_arg
    # Scoped exactly as recreate is: one service, by project and file, never
    # `down`. It differs in bringing the node back on the image it is already
    # running rather than on whatever the file names, the executor's
    # preconditions enforce that those are the same thing, and this verb is
    # the defence in depth behind them.
    #
    # The stop grace is explicit and printed. rippled killed mid-write is how
    # a NuDB store gets damaged, so the transcript records the grace the node
    # actually got rather than leaving it to compose's ten-second default.
    # The deployment's own stop_grace_period surfaces as .Config.StopTimeout,
    # which is unset on most deployments and prints as <nil>; anything that is
    # not a plain integer is treated as absent, and 90s is the floor either
    # way.
    #
    # The stop grace is not what protects the store. A clean SIGTERM inside a
    # 90s grace is exactly what emptied one (issue #79), rippled aborts a
    # rotation at its next health checkpoint and the store does not survive
    # it. The guard below is what keeps the stop out of that window; the
    # grace is still printed, because it is still what the node gets.
    if [[ "$KIND" == container ]]; then
      require_trusted_inputs "$COMPOSE_FILE" "$CONFIG_FILE"
    fi
    rotation_guard
    if [[ "$KIND" == native ]]; then
      # The grace is the UNIT's, read and printed, never chosen here. A
      # container's grace can be floored because compose takes it as an
      # argument; TimeoutStopSec is a property of the unit file, and editing a
      # unit is not something this wrapper does. So it is reported, and a unit
      # whose grace is too short is an operator's line to change, not a
      # silently different number.
      declared=$(systemctl show "$SERVICE" --property=TimeoutStopUSec --value 2>/dev/null) || declared=''
      printf 'stop grace %s (from %s; this wrapper does not change it)\n' \
        "${declared:-not stated by the unit}" "$SERVICE"
      # A failed restart is read before it is reported. systemd's own line on
      # a refused start is "Job for xrpld.service failed. See systemctl
      # status", which names neither the cause nor the way out, and one cause
      # in particular leaves the node STOPPED and keeps it there: the vendor's
      # unit carries StartLimitBurst=5 inside StartLimitIntervalSec=5min, so
      # the sixth start in five minutes is refused and the unit sits failed
      # until somebody clears the counter (#415). That is easy to reach
      # without doing anything wrong: a package upgrade restarts the node from
      # the vendor's maintainer scripts, this verb restarts it again, and a
      # rollback does both once more. Four starts, no mistakes.
      #
      # So the refusal names itself, in this wrapper's words, with the exact
      # command that clears it, and exits 64 like every other named refusal in
      # this file. Either way the run stops here: reporting ActiveState after
      # a restart that did not happen would print "failed" as if it were the
      # outcome of one that did.
      # Clear the unit's failure counter before asking for the start, and say
      # that this happened.
      #
      # The limiter above is not a safety property. It is a crash-loop brake,
      # and what it counts is starts, not faults, so a clean upgrade and a
      # clean rollback trip it without anything having gone wrong. Without
      # this line, the operator's way out of a sequence they were invited to
      # run is an SSH session and a command, which is the thing this wrapper
      # exists to remove.
      #
      # It is a widening of the systemctl grant, and it is a narrow one. One
      # subcommand, on the one unit the root-owned conf names, never a unit
      # from a caller. It changes a counter and nothing else: it cannot start,
      # stop, enable, disable or edit anything, and on a unit that is not
      # failed it does nothing at all. Recorded in the output either way, so
      # the ledger shows that this ran rather than leaving the operator to
      # infer it from a restart that worked when the last one did not.
      reset_rc=0
      systemctl reset-failed "$SERVICE" >/dev/null 2>&1 || reset_rc=$?
      if (( reset_rc == 0 )); then
        printf 'cleared the failure counter on %s (systemctl reset-failed), so a start its limiter had already refused can be asked for again\n' "$SERVICE"
      else
        printf 'could not clear the failure counter on %s (systemctl reset-failed rc=%s); if the start limiter refuses below, that is why\n' \
          "$SERVICE" "$reset_rc"
      fi
      restart_rc=0
      systemctl restart "$SERVICE" >&2 || restart_rc=$?
      if (( restart_rc != 0 )); then
        result=$(systemctl show "$SERVICE" --property=Result --value 2>/dev/null) || result=''
        if [[ "$result" == "start-limit-hit" ]]; then
          die "$SERVICE refused to start: its own start limiter has been hit, so systemd will not try again and the node is stopped. Nothing here can raise that limit, it belongs to the unit file. Clear the counter and start it: systemctl reset-failed $SERVICE && systemctl start $SERVICE"
        fi
        # Any other failed start carries systemd's own status out rather than
        # 64. 64 is this wrapper refusing to act; this is systemd having acted
        # and failed, and the Advisor tells the two apart by the code.
        printf 'wrapper: systemctl restart %s failed (rc=%s%s); the node may be stopped. Read: systemctl status %s, journalctl -xeu %s\n' \
          "$SERVICE" "$restart_rc" "${result:+, Result=$result}" "$SERVICE" "$SERVICE" >&2
        exit "$restart_rc"
      fi
      state=$(systemctl show "$SERVICE" --property=ActiveState --value 2>/dev/null) || state=''
      pkg_rc=0; ver=$(pkg_installed_version) || pkg_rc=$?
      case "$pkg_rc" in
        0) ;;
        2) ver=unknown ;;
        *) ver=not-installed ;;
      esac
      printf '%s %s:%s\n' "${state:-unknown}" "$REPO" "$ver"
    else
      # Same floor a recreate takes, and the same ceiling, for the same
      # reasons: this stops the same binary, the hazard is the store rather
      # than the verb, and the container's recorded StopTimeout is a copy of
      # whatever stop_grace_period the file named when it was created. The
      # floor used to be 90s here, which is the grace two of four lab stops
      # ran out of, and it is below what the package's own systemd unit
      # gives xrpld (TimeoutStopSec=5min). A longer grace costs nothing when
      # the node exits promptly, because docker waits for the exit and not
      # for the timer; a grace past the ceiling is a wait nobody chose.
      declared_rc=0; declared=$(container_stop_grace "$SERVICE") || declared_rc=$?
      if (( declared_rc == 0 )) && [[ -n "$declared" ]] && (( declared >= RECREATE_STOP_GRACE_FLOOR )); then
        stop_grace=$declared
        printf 'stop grace %ss (from the deployment)\n' "$stop_grace"
      elif (( declared_rc == 0 )) && [[ -n "$declared" ]]; then
        stop_grace=$RECREATE_STOP_GRACE_FLOOR
        printf 'stop grace %ss (the deployment names %ss, floored)\n' "$stop_grace" "$declared"
      else
        stop_grace=$RECREATE_STOP_GRACE_FLOOR
        printf 'stop grace %ss (the container records %s)\n' \
          "$stop_grace" "$(grace_note "$declared" "$declared_rc")"
      fi
      docker compose -p "$PROJECT" -f "$COMPOSE_FILE" restart -t "$stop_grace" "$SERVICE" >&2
      docker inspect "$SERVICE" --format '{{.State.Status}} {{.Config.Image}}'
    fi
    ;;

  # ── Read-only inspection ────────────────────────────────────────────────
  # Nothing below changes anything. Each verb answers one question the Advisor
  # would otherwise have to ask the operator to answer by hand.

  inspect)
    require_node
    # The deployment, for the profile. advisord used to run this itself, which
    # meant its account needed the docker group, and docker group membership
    # is root-equivalent, so the account could have bypassed this whole file.
    # Routing it here is what lets the service run with no docker access at all.
    #
    # On a native host the equivalent "describe this deployment" read is the
    # unit plus the installed package, in systemd's own Key=Value shape so one
    # parser handles the lot. The Aperire* keys are this script's, and are
    # named so they cannot collide with a property systemd adds later.
    if [[ "$KIND" == native ]]; then
      systemctl show "$SERVICE"
      pkg_rc=0; ver=$(pkg_installed_version) || pkg_rc=$?
      case "$pkg_rc" in
        0) ;;
        2) ver=unknown ;;
        *) ver=not-installed ;;
      esac
      printf 'AperireKind=native\n'
      printf 'AperireUnit=%s\n' "$SERVICE"
      printf 'AperirePackage=%s\n' "$REPO"
      printf 'AperirePackageVersion=%s\n' "$ver"
      printf 'AperireConfigFile=%s\n' "$CONFIG_FILE"
      printf 'AperireDataPath=%s\n' "$DATA_PATH"
      # The publisher list this node reads, from the conf rather than from a
      # guess about where the vendor puts it: the container path and the
      # native path do not agree, and a profile that carries the wrong one
      # compares two nodes on a file neither of them has (#429).
      printf 'AperireValidatorsPath=%s\n' "$VALIDATORS_PATH"
      printf 'AperireNodeLogSource=%s\n' "$NODE_LOG_SOURCE"
    else
      docker inspect "$SERVICE"
    fi
    ;;

  rotation-state)
    require_node
    # The same reading restart and recreate refuse on, on its own, so the
    # Advisor can answer "why was my restart refused" and "can I restart yet"
    # without attempting one. Reads the node's log and nothing else.
    #
    # Bare, under a time limit (#1043): the check and the card read it inside
    # the Advisor's 90-second budget, and a run-out there is "unknown".
    # With --wait, no limit, as rotation_guard reads: the Advisor's spend
    # guard asks this just before an approval is spent on a stop, and a slow
    # log cut into "unknown" there would let the approval be spent on a stop
    # the wrapper then refuses with exit 64 (PR #1049 review). It waits for
    # the answer, as the stop itself would.
    if [[ "$ARG" == --wait ]]; then
      rotation_state
    else
      require_no_arg
      rotation_state "$ROTATION_STATE_SECONDS"
    fi
    ;;

  can-delete-timer)
    require_no_arg
    # Whether the daily rotation window (issue #79, aperire-can-delete.timer)
    # is installed and enabled on this host, and when it last ran, issue
    # #106. This is an observation, not a recommendation: advisory_delete=0
    # (rippled rotates on its own) and advisory_delete=1 with this window
    # installed are both legitimate, and the operator picks between them.
    # What the Advisor should never do is claim ignorance of a process that is
    # actually running here, which is exactly what happened before this verb
    # existed.
    #
    # Deliberately NOT require_node: this reads systemd state, not the node's
    # container, so a host with SERVICE=none still gets a real answer instead
    # of a configuration refusal.
    #
    # Four states, and "unknown" is a real answer, same rule as
    # config-readable: a host where systemctl would not answer must say so,
    # never fall through to "absent". A timer this host never installed is
    # "absent" and that is a normal, healthy answer too, most of this
    # fleet's advisory_delete=0 hosts have never installed it.
    if ! command -v systemctl >/dev/null 2>&1; then
      printf 'unknown\tsystemctl is not available on this host, so the daily rotation window could not be checked\n'
      exit 0
    fi
    _cd_load=$(systemctl show aperire-can-delete.timer --property=LoadState --value 2>&1) || {
      printf 'unknown\tsystemctl did not answer about aperire-can-delete.timer: %s\n' "$_cd_load"
      exit 0
    }
    case "$_cd_load" in
      not-found)
        printf 'absent\tthe aperire-can-delete.timer unit is not installed on this host\n'
        exit 0 ;;
      loaded) ;;
      *)
        printf 'unknown\tsystemctl reported an unrecognised load state (%s) for aperire-can-delete.timer\n' "$_cd_load"
        exit 0 ;;
    esac
    _cd_enabled=$(systemctl is-enabled aperire-can-delete.timer 2>&1) || true
    _cd_trigger=$(systemctl show aperire-can-delete.timer --property=LastTriggerUSec --value 2>/dev/null)
    if [[ -z "$_cd_trigger" || "$_cd_trigger" == "0" || "$_cd_trigger" == "n/a" ]]; then
      _cd_last='has not run a window yet on this host'
    else
      _cd_last="last ran $_cd_trigger"
    fi
    case "$_cd_enabled" in
      enabled|enabled-runtime)
        printf 'enabled\tthe daily rotation window is installed and enabled; %s\n' "$_cd_last" ;;
      *)
        printf 'disabled\tthe daily rotation window is installed but not enabled (%s); %s. This is the ordinary state for a node still rotating on its own\n' "$_cd_enabled" "$_cd_last" ;;
    esac
    ;;

  compose-backups)
    require_node
    require_container
    require_no_arg
    # What versions this node has a dated deployment copy for, ADR 0019.
    #
    # A rollback's target must be DERIVED, and this is one of the two things
    # it is derived from: `backup-compose` runs before `set-image` in both the
    # upgrade's prepare and the rollback's own stage, so each copy is the
    # deployment as it stood before a version change, and the tag inside it is
    # the version this node was running then.
    #
    # Read-only, and deliberately narrow: path, modification time and the image
    # tag. A compose file can carry environment values, so this prints the one
    # line that answers the question and nothing else.
    #
    # What counts as a backup is the SAME predicate require_backup_path
    # enforces for restore-compose: named after the compose file, ending .bak,
    # beside it, a regular file. A listing that recognised more than the
    # restore verb accepts could name a file the manual fallback then refuses,
    # a refusal after the operator has already approved.
    _cb_dir=$(dirname "$COMPOSE_FILE")
    _cb_base=$(basename "$COMPOSE_FILE")
    # The tag on the image line, under either origin: the configured
    # registry repository, or the local build name a node upgraded through
    # the Advisor's own build is on. A listing that only knew one of them
    # would report "-" for every copy taken on the other side of that swap,
    # and a rollback target derived from it would silently lose those rows.
    #
    # A digest-pinned official image has no tag in the reference at all,
    # and the last colon in it opens the hash rather than a version. For
    # that one shape the version is read from the comment beside it, which
    # is the only thing in the file that carries it and is exactly what
    # set-image-official wrote there.
    # One implementation, at the top of this file: the restore guard reads
    # a copy's version with the same rule that chose it here.
    compose_tag() { compose_tag_of_file "$1"; }
    # Five fields now, not four: the fifth is the whole image reference.
    # #680 is a rollback that cannot rebuild a pruned locally built image
    # because the only reading of "where did this image come from" was
    # whether the image is on the host RIGHT NOW, which is false in exactly
    # the case that needs the rebuild. The reference in the copy taken
    # before the change says where the target came from whether or not the
    # image survived, and it is appended rather than inserted so a reader
    # written against four fields still reads the same four.
    compose_row() { # $1 = file, $2 = origin|backup
      local t r
      t=$(compose_tag "$1")
      r=$(compose_image_ref "$1")
      printf '%s\t%s\t%s\t%s\t%s\n' "$2" "$(stat -c '%Y' "$1" 2>/dev/null || echo 0)" \
        "${t:--}" "$(basename "$1")" "${r:--}"
    }
    compose_row "$COMPOSE_FILE" origin
    while IFS= read -r f; do
      [[ -f "$f" && ! -L "$f" ]] || continue
      # Bounded for the reason artefact-hashes bounds its reads: a
      # multi-megabyte file in a deployment directory is not a compose file.
      (( $(stat -c '%s' "$f" 2>/dev/null || echo 0) < 1048576 )) || continue
      compose_row "$f" backup
    done < <(find "$_cb_dir" -maxdepth 1 -type f -name "$_cb_base.*.bak" -print | sort)
    ;;

  rotation-window)
    require_node
    require_no_arg
    # A native node answers from its unit, its config and its admin port, in
    # the same keys. See rotation_window_native.
    if [[ "$KIND" == native ]]; then
      rotation_window_native
      exit 0
    fi
    require_container
    # How far the store is from its NEXT rotation, in ledgers.
    #
    # rotation-state answers "is one running right now", which the restart
    # guard needs. This answers "would one start during the next few
    # minutes", which is what an upgrade needs: a stop inside a rotation is
    # how a store gets emptied (#79), and a rotation that has not started
    # yet is invisible to a log read.
    #
    # Three readings, each printed as its own key, and the caller does the
    # arithmetic. A missing one is said rather than defaulted: a node with
    # no online_delete never rotates, which is a fact rather than a zero.
    #
    # online_delete first, as on a native node. A node that never rotates
    # has no rotation to wait for, and says so. But CONFIG_FILE is the copy
    # on this host, and a container runs whatever its compose file mounts.
    # So "not configured" is only said when the container's own log reads
    # back. When docker will not read it, nothing on the node's side
    # confirms that file is the one it runs, and a rotating container would
    # pass as quiet: that is the blind guard, on its error key, naming the
    # file that was read.
    online_delete_reading "$CONFIG_FILE"
    if [[ -n "$OD_ERROR" ]]; then
      rotation_window_error "$OD_ERROR"
      exit 0
    fi
    _rw_online=$OD_VALUE
    if (( _rw_online == 0 )); then
      _rw_probe_rc=0
      _rw_probe=$(timeout --kill-after="$ROTATION_KILL_GRACE" "$ROTATION_PROBE_SECONDS" \
        docker logs --tail 1 "$SERVICE" 2>&1) || _rw_probe_rc=$?
      if (( _rw_probe_rc == 124 || _rw_probe_rc == 137 )); then
        # docker did not answer in time. Not the blind guard (nothing said
        # the log is unreadable), and not "never rotates" either: nothing
        # confirmed the file read is the config the container runs.
        printf 'AperireLastRotatedSeq=0\nAperireOnlineDelete=0\nAperireValidatedSeq=0\n'
        printf 'AperireRotationReason=%s\n' "$CONFIG_FILE on this host sets no online_delete, but this container's log did not answer within ${ROTATION_PROBE_SECONDS}s, so whether the config it runs rotates is unknown"
        exit 0
      fi
      if (( _rw_probe_rc != 0 )); then
        rotation_window_error "$CONFIG_FILE on this host sets no online_delete, but this container's log could not be read (docker logs exited $_rw_probe_rc: $(printf '%s' "$_rw_probe" | head -1)), so nothing confirms that file is the config the container runs"
        exit 0
      fi
      printf 'AperireLastRotatedSeq=0\nAperireOnlineDelete=0\nAperireValidatedSeq=0\n'
      printf 'AperireRotationReason=%s\n' "$(rotation_not_configured "$CONFIG_FILE")"
      exit 0
    fi
    # The last finish in the last 24 hours, read by time (#1031). A log the
    # engine refuses to read back is the guard being blind, on its own key,
    # never the same answer as a node that has nothing to report (#679).
    rotation_last_finish
    if [[ -n "$RF_ERROR" ]]; then
      rotation_window_error "$RF_ERROR"
      exit 0
    fi
    _rw_last=$RF_SEQ
    _rw_validated=$(curl -s --max-time 5 --data '{"method":"server_info","params":[{}]}' "$ADMIN_RPC" \
      | grep -oE '"validated_ledger"[^}]*"seq"[[:space:]]*:[[:space:]]*[0-9]+' \
      | grep -oE '[0-9]+$' | tail -1) || _rw_validated=''
    if [[ -n "$_rw_last" && -n "$_rw_validated" ]]; then
      _rw_why=$(rotation_window_insane "$_rw_last" "$_rw_online" "$_rw_validated")
      if [[ -n "$_rw_why" ]]; then
        rotation_window_error "$_rw_why"
        exit 0
      fi
    fi
    printf 'AperireLastRotatedSeq=%s\n' "${_rw_last:-0}"
    printf 'AperireOnlineDelete=%s\n' "$_rw_online"
    printf 'AperireValidatedSeq=%s\n' "${_rw_validated:-0}"
    if [[ -n "$_rw_last" && -n "$RF_AGE" ]]; then
      printf 'AperireLastRotatedAge=%s\n' "$RF_AGE"
    fi
    if [[ -z "$_rw_last" ]]; then
      printf 'AperireRotationReason=%s\n' "$RF_REASON"
    elif [[ -z "$_rw_validated" ]]; then
      printf 'AperireRotationReason=%s\n' \
        "the node did not answer server_info with a validated ledger, so how far it is from its next rotation is unknown"
    fi
    ;;

  image-headroom)
    require_node
    require_container
    require_no_arg
    # Free space where docker keeps its images, which is where a build
    # writes and is not necessarily the filesystem the ledger store is on.
    # docker names its own root; this does not guess at /var/lib/docker.
    _ih_root=$(docker info --format '{{.DockerRootDir}}' 2>/dev/null) || _ih_root=''
    if [[ -z "$_ih_root" || ! -d "$_ih_root" ]]; then
      printf 'AperireImagePath=unknown\n'
      printf 'AperireImageReason=%s\n' "docker did not say where it keeps its images${_ih_root:+ (it named $_ih_root, which is not a directory here)}"
      exit 0
    fi
    _ih_avail=$(df -B1 --output=avail "$_ih_root" 2>/dev/null | tail -1 | tr -d '[:space:]')
    _ih_total=$(df -B1 --output=size "$_ih_root" 2>/dev/null | tail -1 | tr -d '[:space:]')
    if [[ ! "$_ih_avail" =~ ^[0-9]+$ ]]; then
      printf 'AperireImagePath=%s\n' "$_ih_root"
      printf 'AperireImageReason=%s\n' "df would not measure $_ih_root"
      exit 0
    fi
    printf 'AperireImagePath=%s\n' "$_ih_root"
    printf 'AperireImageTotalBytes=%s\n' "${_ih_total:-0}"
    printf 'AperireImageAvailBytes=%s\n' "$_ih_avail"
    ;;

  recipe-state)
    require_node
    require_container
    require_no_arg
    # Would build-image build? Asked as a read, before anything is
    # approved.
    #
    # It exists because an update never placed the recipe (#675), so every
    # container node installed before 17w had a perfectly healthy
    # Operations card that refused halfway through a run the operator had
    # already approved. The precondition behind this verb is the same
    # question the build asks, taken through the same code, so the card and
    # the build cannot disagree about a host.
    #
    # Always exits 0: this is a reading, and a reading that exits non-zero
    # is one a caller turns into an error about the wrapper rather than an
    # answer about the host.
    _rs_why=$( (require_recipe) 2>&1 ) && _rs_ok=1 || _rs_ok=0
    if (( _rs_ok )); then
      printf 'AperireRecipe=present\n'
      printf 'AperireRecipePath=%s\n' "$IMAGE_RECIPE_DIR/$IMAGE_RECIPE_SCRIPT"
    else
      printf 'AperireRecipe=absent\n'
      # One line, always: this is read as key=value, and a reason that
      # wrapped onto a second line would arrive as a key nobody knows.
      printf 'AperireRecipeReason=%s\n' "$(printf '%s' "${_rs_why#wrapper: }" | tr '\n' ' ')"
    fi
    ;;

  config-readable)
    require_node
    require_no_arg
    # Can the node's own container still READ the configuration it will start
    # with? Punch #10, and a real incident: a config the container cannot read
    # makes rippled come up on image defaults, no error, no log line, and the
    # first symptom is a peer count that looks wrong days later.
    #
    # Read-only by construction. It resolves where the config is mounted from
    # `docker inspect`, then runs `test -r` on that path INSIDE the container
    # and throws the byte away. Nothing is written, nothing is copied out, and
    # the path is passed as an argument rather than interpolated into a
    # command string.
    #
    # Three verdicts, not two. "unknown" is a real answer here: an image with
    # no shell, a container that is not running, or a config that reaches the
    # node by some route this cannot see are all cases where the honest report
    # is that it could not be checked. Saying "unreadable" for any of them
    # would refuse a change on evidence that does not exist.
    #
    # What it proves is bounded, and the wording says so. `docker exec` runs
    # as the user the DEPLOYMENT configures, which is the compose file's
    # `user:` when there is one and the image's own otherwise, and neither is
    # necessarily the user the node process ends up as if the entrypoint drops
    # privileges further. So the verdict names which of those two it got: a
    # deployment that says `user: "997:997"` (#31) is running the node as that
    # account and this check opened the file as that account, and a deployment
    # that says nothing leaves the old bounded wording in place, because it is
    # still the honest one.
    #
    # Exit status is 0 for all three verdicts, this is a reading, and the
    # caller decides what it means. Only a configuration problem exits 64.
    #
    # Native takes the better route, and it is worth saying why it is better:
    # `docker exec test -r` runs as the image's configured user, which is not
    # necessarily the user the entrypoint drops to, so the container answer is
    # bounded in a way this one is not. Here the file is opened as the account
    # the unit actually runs the node as. The three verdicts are the same, and
    # "unknown" is still a real answer: root can read almost anything, so a
    # test run as root would say "readable" about a file the node cannot open.
    if [[ "$KIND" == native ]]; then
      nuser=$(systemctl show "$SERVICE" --property=User --value 2>/dev/null) || nuser=''
      if [[ -z "$nuser" && -n "$DATA_PATH" && -e "$DATA_PATH" ]]; then
        # A unit with no User= runs as root, and a node running as root is
        # rare enough that the data directory's owner is the better reading.
        nuser=$(stat -c '%U' "$DATA_PATH" 2>/dev/null || true)
        [[ "$nuser" == "UNKNOWN" ]] && nuser=''
      fi
      if [[ -z "$nuser" ]]; then
        printf 'unknown\t%s\t%s names no service user and the data path does not say who owns it, so which account the node reads its config as is unknown\n' \
          "$CONFIG_FILE" "$SERVICE"
        exit 0
      fi
      if ! id "$nuser" >/dev/null 2>&1; then
        printf 'unknown\t%s\tthe unit names user %s, which does not exist on this host\n' "$CONFIG_FILE" "$nuser"
        exit 0
      fi
      if ! command -v runuser >/dev/null 2>&1; then
        printf 'unknown\t%s\trunuser is not on this host, so the config could not be opened as %s\n' "$CONFIG_FILE" "$nuser"
        exit 0
      fi
      rc=0
      # The inner shell says "unreadable" with a status of its OWN, 3, and not
      # with 1. runuser exits 1 for its own reasons too, "may not be used by
      # non-root users" among them, and reading that as "unreadable" would
      # report a config the node reads perfectly well as one it cannot open,
      # which is a refusal built on a check that never ran. Found driving this
      # verb by hand as an unprivileged user, 2026-09-15.
      #
      # The path is an ARGUMENT to the inner shell, never interpolated into
      # its script, which is why the single quotes are deliberate here.
      # shellcheck disable=SC2016  # $1 is the inner shell's argument, not this one's
      runuser -u "$nuser" -- sh -c 'test -r "$1" && head -c 1 "$1" >/dev/null && exit 0; exit 3' _ "$CONFIG_FILE" >/dev/null 2>&1 || rc=$?
      case "$rc" in
        0)
          printf 'readable\t%s\t%s opened it, and that is the account the unit runs the node as\n' "$CONFIG_FILE" "$nuser" ;;
        3)
          printf 'unreadable\t%s\t%s cannot read it, a node started now would fall back to defaults with no error\n' "$CONFIG_FILE" "$nuser" ;;
        *)
          printf 'unknown\t%s\tthe check itself could not be run as %s (exit %s), so whether the node can read its config is unknown\n' "$CONFIG_FILE" "$nuser" "$rc" ;;
      esac
      exit 0
    fi
    cpath=''
    mounts=$(docker inspect "$SERVICE" --format '{{range .Mounts}}{{.Source}}|{{.Destination}}{{"\n"}}{{end}}' 2>/dev/null) || mounts=''
    if [[ -z "$mounts" ]]; then
      printf 'unknown\t-\tthe node container could not be inspected, so where its config comes from is unknown\n'
      exit 0
    fi
    cfg_dir=$(dirname "$CONFIG_FILE")
    cfg_base=$(basename "$CONFIG_FILE")
    # Since #31 the same host config is mounted twice: at /etc/xrpld/xrpld.cfg,
    # which is the path the node opens, and at /config/rippled.cfg, where the
    # image's entrypoint and this project's path detection look. They are the
    # same file, so the READING is the same either way, but the path this
    # prints must not wobble: docker does not list mounts in a stable order
    # (measured on 28.3.3, three consecutive inspects of one container gave two
    # different orders), so taking whichever came first would make this verb
    # answer a different path run to run. Every exact match is collected and
    # the lexicographically first is named, which is the same answer every
    # time on the same deployment.
    #
    # Nothing breaks out of this loop and nothing is decided inside it. Every
    # candidate is collected by kind, and the kinds are ranked afterwards, so
    # the answer does not depend on the order the mounts arrived in. A loop
    # that stopped at the first directory mount would resolve one way on a
    # deployment that mounts both the file and its directory and the other way
    # on the next call, on the same host.
    exact='' dircand='' parentcand='' parentsrclen=0
    while IFS='|' read -r src dst; do
      [[ -n "$src" && -n "$dst" ]] || continue
      if [[ "$src" == "$CONFIG_FILE" ]]; then
        exact+="$dst"$'\n'
        continue
      fi
      if [[ "$src" == "$cfg_dir" ]]; then
        # More than one mount of the config's own directory is the same
        # wobble one level up, so the same rule settles it.
        if [[ -z "$dircand" || "${dst%/}/$cfg_base" < "$dircand" ]]; then
          dircand="${dst%/}/$cfg_base"
        fi
        continue
      fi
      # A parent directory mounted higher up. Longest match wins, so a
      # deployment mounting both / and the config directory resolves to the
      # closer one; the two cases above have already taken the exact ones.
      if [[ "$CONFIG_FILE" == "$src"/* ]]; then
        if (( ${#src} > parentsrclen )); then
          parentcand="${dst%/}/${CONFIG_FILE#"$src"/}"
          parentsrclen=${#src}
        fi
      fi
    done <<< "$mounts"

    # The ranking, said once: an exact mount of the file beats the file's own
    # directory, which beats a directory further up.
    also=0
    if [[ -n "$exact" ]]; then
      also=$(printf '%s' "$exact" | grep -c .)
      cpath=$(printf '%s' "$exact" | LC_ALL=C sort | head -1)
    elif [[ -n "$dircand" ]]; then
      cpath=$dircand
    elif [[ -n "$parentcand" ]]; then
      cpath=$parentcand
    fi

    if [[ -z "$cpath" ]]; then
      printf 'unknown\t-\tno mount in this deployment carries %s, so the container reads its config by some other route\n' "$CONFIG_FILE"
      exit 0
    fi

    # Who that exec will run as, read from the deployment rather than assumed.
    # Empty means the compose names no user and the image's own applies.
    cuser=$(docker inspect "$SERVICE" --format '{{.Config.User}}' 2>/dev/null) || cuser=''

    rc=0
    docker exec "$SERVICE" sh -c 'test -r "$1" && head -c 1 "$1" >/dev/null' _ "$cpath" >/dev/null 2>&1 || rc=$?
    case "$rc" in
      0)
        _also_note=''
        (( also > 1 )) && _also_note=" (mounted at ${also} paths in this deployment, the same file at each)"
        if [[ -n "$cuser" ]]; then
          printf 'readable\t%s\t%s opened it, and that is the account this deployment runs the node as%s\n' "$cpath" "$cuser" "$_also_note"
        else
          printf 'readable\t%s\tthe container opened it as the user the image configures; an entrypoint that drops to another user is not covered%s\n' "$cpath" "$_also_note"
        fi ;;
      1)
        # What an unreadable config costs depends on the deployment, so the
        # verdict says which one this is. A compose that mounts the config
        # over the image's own default (#31) has nothing left to fall back
        # to, and that is the better failure: loud, at the start, instead of
        # a node quietly running a configuration nobody chose.
        if [[ "$mounts" == *"|/etc/xrpld/xrpld.cfg"* ]]; then
          printf 'unreadable\t%s\tthe container cannot read it, and this deployment mounts it over the image default, so a node started now would refuse to start rather than come up on a config nobody chose\n' "$cpath"
        else
          printf 'unreadable\t%s\tthe container cannot read it, a node started now would fall back to image defaults with no error\n' "$cpath"
        fi ;;
      *)
        printf 'unknown\t%s\tthe check could not run inside the container (exit %s), no shell, not running, or exec refused\n' "$cpath" "$rc" ;;
    esac
    ;;

  show-config)
    require_node
    # The node configuration, WITHOUT the validator's key material.
    #
    # This is the one verb where the redaction is the security property, not a
    # courtesy. rippled.cfg carries [validator_token], the key this validator
    # signs with, and §7 says the Advisor never reads validator key material.
    #
    # The stripping happens HERE, on the privileged side, before a single byte
    # leaves this script. The Advisor is not trusted to ignore a secret it was
    # handed; it never receives one. That is the difference between a boundary
    # and a promise.
    #
    # Fails closed: awk drops every line inside a secret section and only
    # re-enables output at the next section header, so a section this script
    # has never heard of still ends its redaction correctly, and a truncated
    # or malformed file redacts more rather than less.
    #
    # Comment-only and blank lines are dropped. A stock rippled.cfg opens with
    # around a thousand lines of documentation before the first real setting,
    # and the reader on the other side has a fixed byte budget, so the whole
    # of it was spent on the boilerplate header and cut off exactly where the
    # configuration starts. An operator asking for a summary of their config
    # got a description of the generic template. Dropping the commentary is
    # what makes the settings fit; the count is disclosed rather than silent,
    # and redaction below is untouched by it.
    # Name the file and the machine, in the output itself.
    #
    # "your rippled.cfg" is ambiguous the moment an operator runs more than
    # one node, and they do: a validator at home and a test node on a VPS
    # read as the same phrase. Twice, a summary of the node this dashboard
    # watches was compared against a config file on a different machine and
    # reported as the Advisor inventing values. The reading now carries its
    # own provenance, so an answer built from it can say where it came from.
    echo "# configuration read from $CONFIG_FILE on $(hostname) at $(date -u '+%Y-%m-%d %H:%M:%SZ')"
    echo "# this is the node this dashboard monitors, which may not be the only node you run"
    gawk '
      BEGIN { redact = 0; dropped = 0 }
      # Comments are dropped before anything else looks at them, so a comment
      # can never be mistaken for a section header or a setting.
      /^[[:space:]]*#/ { dropped++; next }
      /^[[:space:]]*$/ { dropped++; next }
      /^[[:space:]]*\[/ {
        # A new section always ends the previous one.
        redact = 0
        name = $0
        sub(/^[[:space:]]*\[/, "", name); sub(/\].*$/, "", name)
        if (name ~ /^(validator_token|validation_seed|node_seed|validation_manifest|validator_key|master_seed)$/) {
          redact = 1
          print "[" name "]"
          print "  <redacted by the privilege wrapper, key material never leaves the host>"
          next
        }
        print; next
      }
      redact { next }
      # Belt and braces for a secret written outside a section: anything that
      # looks like a rippled seed or a long opaque blob goes too.
      /(^|[^A-Za-z0-9])s[A-HJ-NP-Za-km-z1-9]{25,}([^A-Za-z0-9]|$)/ {
        print "  <redacted: value matched a secret shape>"; next
      }
      { print }
      END {
        if (dropped > 0)
          print "\n# (" dropped " comment and blank lines omitted so the settings fit; " \
                "every configured value above is verbatim)"
      }
    ' "$CONFIG_FILE"
    ;;

  show-validators)
    require_node
    require_conf VALIDATORS_PATH
    # Which lists this node trusts, not how it voted. No secrets live here.
    [[ -f "$VALIDATORS_PATH" ]] || die "no validators file at $VALIDATORS_PATH"
    cat "$VALIDATORS_PATH"
    ;;

  show-toml)
    require_node
    require_conf TOML_URL
    # The file the operator publishes to prove they own the domain. Public by
    # definition, this fetches it the way anyone else would, so the Advisor
    # sees exactly what the network sees.
    curl -sS --max-time 10 --max-filesize 524288 -L --proto '=https' "$TOML_URL"
    ;;

  disk)
    require_conf DATA_PATH
    df -h "$DATA_PATH"
    ;;

  store-size)
    require_no_arg
    require_conf DATA_PATH
    # How many bytes the ledger store is using, measured as root.
    #
    # On a native host the vendor's unit ships StateDirectory=xrpld with mode
    # 0750, owned by the node's own account, so the account serving the
    # dashboard cannot even traverse it. A walk it could not take came back as
    # a successful reading of zero, and the System tab showed 0 B beside a
    # 42.70 GB peak from the day before, on a store that was 6.7 GB and
    # filling (#427). Root can read it, this already runs as root, and a
    # number is all that crosses. Nothing about the store's contents is
    # exposed and no account gains access to the directory.
    #
    # The shape is fixed, because another program parses it:
    #
    #   AperireStorePath=<the DATA_PATH this conf names>
    #   AperireStoreBytes=<integer>     bytes, or the word unknown
    #   AperireStoreReason=<sentence>   present only when it is unknown
    #
    # Exit 0 either way. "I could not read it" is an answer to the question
    # asked, and a non-zero exit would make the caller report a host problem
    # instead of the fact. Unknown is never 0: the whole of #427 is a reading
    # nobody took rendered as a number.
    printf 'AperireStorePath=%s\n' "$DATA_PATH"
    if [[ ! -e "$DATA_PATH" ]]; then
      printf 'AperireStoreBytes=unknown\n'
      printf 'AperireStoreReason=%s does not exist on this host\n' "$DATA_PATH"
    elif [[ ! -d "$DATA_PATH" ]]; then
      printf 'AperireStoreBytes=unknown\n'
      printf 'AperireStoreReason=%s is not a directory\n' "$DATA_PATH"
    else
      # du's status is kept, not awk's, the same rule pkg_candidates follows:
      # a walk that hit an unreadable subtree still prints a total, and that
      # total is short by however much it could not enter. Reported as
      # unknown with the reason, never as a number that looks complete.
      # `x=$(cmd); rc=$?` never reaches the second statement under set -e:
      # the assignment carries the command's status and the shell is gone
      # before $? is read. The status has to be caught on the assignment
      # itself, which is the same shape that ended a native install at 141
      # with nothing printed (#411).
      store_rc=0
      store_out=$(du -sb "$DATA_PATH" 2>&1) || store_rc=$?
      if (( store_rc == 0 )); then
        store_bytes=${store_out%%[!0-9]*}
        if [[ "$store_bytes" =~ ^[0-9]+$ ]]; then
          printf 'AperireStoreBytes=%s\n' "$store_bytes"
        else
          printf 'AperireStoreBytes=unknown\n'
          printf 'AperireStoreReason=du answered something this cannot read: %s\n' "${store_out//$'\n'/ }"
        fi
      else
        printf 'AperireStoreBytes=unknown\n'
        printf 'AperireStoreReason=%s\n' "${store_out//$'\n'/ }"
      fi
    fi
    ;;

  store-headroom)
    require_no_arg
    require_conf DATA_PATH
    # How much free space the filesystem holding the ledger store has, as
    # root, with the path that was measured beside it.
    #
    # Same wall as store-size, one syscall further in (#465). statfs needs
    # traverse on every component of the path it is given, and on a native
    # host the vendor's unit ships StateDirectory=xrpld at 0750 owned by the
    # node's own account, so the Advisor's account cannot statfs the store at
    # all. Its own reading came back "permission denied", the disk-headroom
    # precondition turned that into a refusal, and every runbook that carries
    # it (upgrade, restart, config change, rollback) was blocked on a box
    # with 82% of its disk free.
    #
    # The path is measured itself rather than an ancestor the Advisor could
    # reach. A store on its own volume is an ordinary validator layout, and an
    # ancestor's numbers would then describe a different filesystem while
    # reading like the store's.
    #
    # The shape is fixed, because another program parses it:
    #
    #   AperireHeadroomPath=<the DATA_PATH this conf names>
    #   AperireHeadroomTotalBytes=<integer>   bytes, or the word unknown
    #   AperireHeadroomAvailBytes=<integer>   bytes, or the word unknown
    #   AperireHeadroomReason=<sentence>      present only when it is unknown
    #
    # Avail is what a non-root account could still write: stat's %a, which is
    # statfs's f_bavail, so the number agrees with the one the Advisor takes
    # for itself on a host where it can. Reserved blocks are not headroom
    # anyone can spend.
    #
    # Exit 0 either way, for the reason store-size does: "I could not read it"
    # is an answer to the question asked, and unknown is never zero.
    printf 'AperireHeadroomPath=%s\n' "$DATA_PATH"
    # No existence test before the measurement. A path whose parent is 0750
    # fails one the same way a path that was never created does, and the first
    # version of this verb reported a store it could not reach as one that
    # "does not exist on this host": the wrong cause, printed with confidence.
    # stat says which of the two it hit, in its own words, so that is the
    # sentence that crosses.
    #
    # The status is caught on the assignment, the shape #411 ended a native
    # install on: `x=$(cmd); rc=$?` never reaches the second statement under
    # set -e.
    hr_rc=0
    hr_out=$(stat -f -c '%S %b %a' "$DATA_PATH" 2>&1) || hr_rc=$?
    hr_frag=''; hr_blocks=''; hr_avail=''
    if (( hr_rc == 0 )); then
      read -r hr_frag hr_blocks hr_avail <<<"$hr_out"
    fi
    if (( hr_rc == 0 )) && [[ "$hr_frag" =~ ^[0-9]+$ && "$hr_blocks" =~ ^[0-9]+$ \
          && "$hr_avail" =~ ^[0-9]+$ ]] && (( hr_frag > 0 && hr_blocks > 0 )); then
      printf 'AperireHeadroomTotalBytes=%s\n' "$(( hr_blocks * hr_frag ))"
      printf 'AperireHeadroomAvailBytes=%s\n' "$(( hr_avail * hr_frag ))"
    else
      printf 'AperireHeadroomTotalBytes=unknown\n'
      printf 'AperireHeadroomAvailBytes=unknown\n'
      if (( hr_rc == 0 )); then
        printf 'AperireHeadroomReason=stat answered something this cannot read: %s\n' "${hr_out//$'\n'/ }"
      else
        printf 'AperireHeadroomReason=%s\n' "${hr_out//$'\n'/ }"
      fi
    fi
    ;;

  node-log)
    require_node
    require_count
    # What the node emitted. On a container that is Docker rather than a reach
    # into the container: the config names a log path, but that path is inside
    # the container and is not mounted here. On a native host it is the one
    # source the configuration declares, the same one the rotation guard reads,
    # so an operator comparing the two is reading the same log.
    if [[ "$KIND" == native ]]; then
      if [[ "$NODE_LOG_SOURCE" == journal ]]; then
        journalctl --no-pager --output=short-iso --unit="$SERVICE" --lines="$ARG" 2>&1
      else
        tail -n "$ARG" "$NODE_LOG_SOURCE" 2>&1
      fi
    else
      docker logs --tail "$ARG" "$SERVICE" 2>&1
    fi
    ;;

  sysctl-relevant)
    # The kernel settings that actually affect a validator, named individually.
    # Not `sysctl -a`: that is thousands of values, most of them irrelevant,
    # and a verb should answer a question rather than hand over everything.
    for k in vm.swappiness vm.dirty_ratio vm.dirty_background_ratio \
             net.core.somaxconn net.core.rmem_max net.core.wmem_max \
             net.ipv4.tcp_rmem net.ipv4.tcp_wmem net.ipv4.tcp_fin_timeout \
             net.ipv4.tcp_max_syn_backlog fs.file-max; do
      printf '%s = %s\n' "$k" "$(sysctl -n "$k" 2>/dev/null || echo '<unset>')"
    done
    ;;

  limits)
    require_node
    # What the node process is actually allowed, which is not always what the
    # unit or the shell says.
    if [[ "$KIND" == native ]]; then
      pid=$(systemctl show "$SERVICE" --property=MainPID --value 2>/dev/null || true)
    else
      pid=$(docker inspect "$SERVICE" --format '{{.State.Pid}}' 2>/dev/null || true)
    fi
    [[ -n "$pid" && "$pid" != "0" ]] || die "could not find the running pid for $SERVICE"
    cat "/proc/$pid/limits"
    ;;

  unit-status)
    # State only, not logs. --no-pager because this is read by a program.
    systemctl status --no-pager --lines=0 \
      aperire-advisord.service aperire-server.service aperire-relay.service 2>&1 || true
    ;;

  resources)
    free -h
    echo
    uptime
    echo
    printf 'load: %s\n' "$(cat /proc/loadavg)"
    ;;

  journal)
    require_count
    # Aperire's own units only. Deliberately not the whole journal: this exists
    # so the Advisor can explain its own behaviour and the relay's, not to read
    # everything else running on this host.
    journalctl --no-pager -n "$ARG" \
      -u aperire-advisord.service -u aperire-server.service -u aperire-relay.service 2>&1 || true
    ;;

  artefact-hashes)
    require_node
    # Digest the node config (or the deployment file) and every candidate
    # backup beside it, so the Advisor can judge whether a rollback exists
    # WITHOUT opening those files itself.
    #
    # This is the last read that kept the Advisor's account needing access to
    # the node's config directory, and that directory holds rippled.cfg, which
    # holds the validator token. With this verb the account can be refused the
    # directory outright, and §7 stops depending on the Advisor's own code
    # choosing not to look.
    #
    # Two digests per file. The plain one answers "is this byte-identical".
    # The normalised one blanks the image tag, which is what lets a pre-change
    # copy still count as a rollback after prepare has edited that one line,
    # without it, the plan's own progress fails the cutover's precondition.
    #
    # Output is one tab-separated row per file. Selection, ordering and the
    # wording of the verdict stay in the caller: this verb reads, it does not
    # decide.
    #
    # The config half works on both shapes. The deployment half has nothing to
    # digest on a native host, where the deployment is a package and a unit
    # rather than a file this script manages, so it refuses with that fact.
    case "$ARG" in
      node-config)            origin=$CONFIG_FILE ;;
      deployment-definition)  require_container; origin=$COMPOSE_FILE ;;
      *) die "artefact-hashes needs node-config or deployment-definition" ;;
    esac
    [[ -f "$origin" ]] || die "no such artefact: $origin"
    dir=$(dirname "$origin")

    emit() {
      local f=$1 kind=$2 sz plain norm
      sz=$(stat -c '%s' "$f" 2>/dev/null || echo 0)
      # Bounded for the same reason the caller bounds it: a multi-gigabyte
      # "backup" in a config directory is not a config.
      if (( sz == 0 || sz >= 1048576 )); then
        printf '%s\t-\t-\t%s\t%s\t%s\n' "$kind" "$(stat -c '%Y' "$f" 2>/dev/null || echo 0)" "$sz" "$(basename "$f")"
        return
      fi
      plain=$(sha256sum < "$f" | cut -d' ' -f1)
      # Blank the image line and drop the pull_policy line, then digest. Must
      # match the caller's normalisation byte for byte.
      #
      # The whole reference is blanked, not just the tag, because an upgrade
      # through a locally built image changes the repository too: the copy
      # taken before it names the registry repository and the file after it
      # names localhost/xrpld, and a normalisation that kept the repository
      # would report the plan's own change as unrelated drift and refuse the
      # cutover. pull_policy goes for the same reason, it is the other half
      # of that one edit.
      # The official repository is named here as well as the other two,
      # and by BOTH separators: an official image line is digest-pinned
      # (image: rippleci/xrpld@sha256:...  # 3.4.1), and the whole line
      # including its comment is blanked, so a copy taken before the swap
      # and the file after it normalise to the same bytes.
      norm=$(awk -v repo="$REPO" -v localrepo="$LOCAL_IMAGE_REPO" \
                 -v officialrepo="$OFFICIAL_IMAGE_REPO" -v svc="$SERVICE" '
        $0 ~ "^[[:space:]]*" svc ":[[:space:]]*$" { insvc = 1 }
        {
          if ($0 ~ /^[[:space:]]*pull_policy:/) next
          i = index($0, "image:")
          if (i > 0 && (index($0, repo ":") > 0 || index($0, localrepo ":") > 0 \
                        || index($0, officialrepo ":") > 0 || index($0, officialrepo "@") > 0 \
                        || (insvc && !seen))) {
            $0 = substr($0, 1, i - 1) "image: @"
            seen = 1
          }
          print
        }' "$f" | head -c 1048576 | sha256sum | cut -d' ' -f1)
      printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$kind" "$plain" "$norm" \
        "$(stat -c '%Y' "$f")" "$sz" "$(basename "$f")"
    }

    emit "$origin" origin
    # Every regular file beside it. Which of them counts as a backup is the
    # caller's rule, not this script's.
    while IFS= read -r f; do
      [[ "$f" == "$origin" ]] && continue
      emit "$f" file
    done < <(find "$dir" -maxdepth 1 -type f -print | sort)
    ;;

  set-config)
    require_node
    require_cwl
    require_trusted_inputs "$CONFIG_FILE"
    # Change ONE tuning setting in the node config. ADR 0007's shape, applied
    # to configuration: the set of possible changes is finite and readable
    # here, not assembled from a caller's string.
    #
    # ARG is "key=value". Both halves are matched against an allow-list and a
    # shape below. There is no verb that writes an arbitrary line, no verb
    # that takes a stanza body, and no verb that names a file, so the secret
    # stanzas are not protected by a check that could be forgotten, they are
    # unreachable because nothing here can address them.
    #
    # The node is NOT restarted. rippled reads its config at startup, so this
    # takes effect on the next restart and that restart is its own approval.
    # Until then the change is reversible by restoring the backup, with the
    # node still running and validating throughout.
    key=${ARG%%=*}
    val=${ARG#*=}
    [[ "$ARG" == *=* && -n "$key" && -n "$val" ]] || die "set-config needs key=value, got '$ARG'"

    # The allow-list. A key absent here is refused, including every key that
    # carries or points at key material. Ranges are the safe operating bands
    # from the field guide, not rippled's full syntax: a value rippled would
    # accept but that would hurt this node is still refused.
    case "$key" in
      online_delete)
        # Below 16384 is the I/O-storm band NuDB rotation misbehaves in.
        [[ "$val" =~ ^[0-9]+$ ]] || die "online_delete must be a whole number, got '$val'"
        (( val >= 16384 && val <= 131072 )) || \
          die "online_delete $val is outside the safe band 16384-131072"
        ;;
      advisory_delete)
        [[ "$val" =~ ^[01]$ ]] || die "advisory_delete must be 0 or 1, got '$val'" ;;
      node_size)
        [[ "$val" =~ ^(tiny|small|medium|large|huge)$ ]] || \
          die "node_size must be tiny|small|medium|large|huge, got '$val'" ;;
      ledger_history)
        [[ "$val" =~ ^([0-9]+|full)$ ]] || \
          die "ledger_history must be a whole number or 'full', got '$val'" ;;
      *)
        die "set-config refuses '$key', allowed: online_delete, advisory_delete, node_size, ledger_history"
        ;;
    esac

    # The shape table. A second per-key fact, kept beside the bands rather than
    # inferred, because inferring it is exactly what went wrong: this verb
    # looked for a `key=` line for every key, and on 2026-08-19 an operator was
    # told node_size "is not a setting that exists in this node's config" while
    # the node was running `[node_size]` / `huge`. rippled has both shapes and
    # nothing in a key's name says which one it takes.
    case "$key" in
      online_delete|advisory_delete) shape=kv ;;
      node_size|ledger_history)      shape=stanza ;;
      *) die "set-config has no shape recorded for '$key'" ;;
    esac

    [[ -f "$CONFIG_FILE" && ! -L "$CONFIG_FILE" ]] || die "no config at $CONFIG_FILE, or it is a link; nothing was changed"
    # Always a dated copy first, by this script, before it writes anything.
    # The caller cannot skip it by not asking. Taken on descriptors
    # (dated_backup): `cp -a` here wrote through a link planted at the
    # dated name, as root.
    backup=$(dated_backup "$CONFIG_FILE") \
      || die "could not take a dated copy of $CONFIG_FILE beside it; nothing was changed"
    cmp -s "$CONFIG_FILE" "$backup" || die "backup does not match the original"
    cwl_prune_backups "$CONFIG_FILE" 10

    # What the file is right now, so the rewrite can be proven not to have
    # moved it. Read BEFORE anything is written. was_snap also carries the
    # ACL, which was_own alone cannot see (#545): stat reports the ACL mask
    # in the group-permission position, so a file that loses every named
    # entry can still print the identical owner:group:mode.
    was_own=$(stat -c '%U:%G:%a' "$CONFIG_FILE" 2>/dev/null || echo '?')
    [[ "$was_own" != '?' ]] || die "could not read the current owner and mode of $CONFIG_FILE"
    was_snap=$(cwl_acl_snapshot "$CONFIG_FILE")

    tmp=$(rewrite_tmp)
    if [[ "$shape" == kv ]]; then
      # Rewrite every assignment of this key, commented or not, and record what
      # was there. A duplicate key is the exact thing this node has, two
      # online_delete lines, so replacing only the first would leave the second
      # to win and the change would appear to do nothing.
      #
      # A key that is not present anywhere is an error rather than an append:
      # knowing which stanza it belongs in is not something this script can
      # decide, and guessing produces a config that parses and means something
      # else.
      found=$(grep -cE "^[[:space:]]*${key}[[:space:]]*=" "$CONFIG_FILE" || true)
      (( found > 0 )) || { rm -f "$tmp"; die "no '$key=' line in $CONFIG_FILE, nothing to change"; }
      before=$(grep -E "^[[:space:]]*${key}[[:space:]]*=" "$CONFIG_FILE" | tr '\n' ' ')
      before=${before% }
      awk -v k="$key" -v v="$val" '
        $0 ~ "^[[:space:]]*" k "[[:space:]]*=" { print k "=" v; next }
        { print }
      ' "$CONFIG_FILE" > "$tmp"

      # The written file must contain the value once per line it replaced, and
      # must differ from the original only in those lines.
      after=$(grep -cE "^${key}=${val}$" "$tmp" || true)
      (( after == found )) || { rm -f "$tmp"; die "rewrite produced $after lines, expected $found"; }
    else
      # The stanza shape: one header, one value line under it. Exactly one
      # line is replaced, and the header is not touched, it names the setting
      # and is not part of the value.
      #
      # Three ways this refuses, and none of them writes: no such stanza (the
      # same rule as the kv shape, for the same reason, this script never
      # adds a setting the file does not already have, because which section
      # it belongs in is not something it can decide); more than one stanza of
      # that name (which one wins is rippled's business, not this script's,
      # and rewriting the first while the last is in force is a change that
      # appears to do nothing); and a header with no value line under it,
      # which is a config to fix by hand rather than a line to replace.
      hdr=$(grep -cE "^[[:space:]]*\[${key}\][[:space:]]*$" "$CONFIG_FILE" || true)
      (( hdr > 0 )) || { rm -f "$tmp"; die "no [$key] stanza in $CONFIG_FILE, nothing to change"; }
      (( hdr == 1 )) || { rm -f "$tmp"; die "$CONFIG_FILE has $hdr [$key] stanzas, which one is in force is not something this script can decide"; }
      was=$(stanza_value "$CONFIG_FILE" "$key")
      [[ -n "$was" ]] || { rm -f "$tmp"; die "the [$key] stanza in $CONFIG_FILE has no value line under it, nothing to change"; }
      found=1
      before="[$key] $was"
      awk -v k="$key" -v v="$val" '
        BEGIN { inb = 0; done = 0 }
        !done && $0 ~ "^[[:space:]]*\\[" k "\\][[:space:]]*$" { inb = 1; print; next }
        inb && !done {
          if ($0 ~ /^[[:space:]]*$/ || $0 ~ /^[[:space:]]*#/) { print; next }
          if ($0 ~ /^[[:space:]]*\[/) { inb = 0; print; next }
          print v; done = 1; inb = 0; next
        }
        { print }
      ' "$CONFIG_FILE" > "$tmp"

      # Read the written file back the same way the value was read out of the
      # original, the rewrite is proven by what the file now says, not by awk
      # having exited zero.
      now=$(stanza_value "$tmp" "$key")
      [[ "$now" == "$val" ]] || \
        { rm -f "$tmp"; die "the rewrite left [$key] reading '$now', not '$val'"; }
    fi
    # At most the key's own lines moved, and they moved in pairs, diff
    # reports one removed and one added line per rewrite. Fewer is legitimate
    # and has to be: a line that already reads exactly key=value is left
    # identical by the rewrite, so setting a key to the value it already holds
    # changes nothing at all. An upper bound rather than an equality, because
    # what this is defending against is a rewrite that touched something else.
    changed=$(diff <(cat "$CONFIG_FILE") <(cat "$tmp") | grep -c '^[<>]' || true)
    (( changed % 2 == 0 && changed <= found * 2 )) || \
      { rm -f "$tmp"; die "rewrite changed $changed lines, more than the $found $key line(s) it was allowed to touch"; }
    # The stanza header is not one of the lines this was allowed to touch, and
    # the bound above would not notice: replacing a header AND a value is two
    # lines, which is what one stanza rewrite is allowed. So it is checked by
    # name, the count says how much moved, this says the header did not.
    if [[ "$shape" == stanza ]]; then
      hdr_after=$(grep -cE "^[[:space:]]*\[${key}\][[:space:]]*$" "$tmp" || true)
      (( hdr_after == hdr )) || \
        { rm -f "$tmp"; die "the rewrite changed the [$key] header itself, refusing to move it"; }
    fi

    # Owner, group, mode AND the ACL are carried across, through the one
    # helper every rewrite in this project shares (#545), and then CHECKED
    # the same way: by reading the ACL back, not by reasoning about stat's
    # nine bits, which cannot see it.
    #
    # A rewrite that lands correct content under a different group is the
    # 2026-08-19 drift: the node runs as its own account inside the
    # container and reads this file through a bind mount, so a group it can
    # no longer read makes rippled start on image defaults, silently, with
    # no error anywhere, and the operator finds out from a peer count. A
    # rewrite that drops the ACL is the same failure one layer further out:
    # the node keeps reading fine, because it owns the file outright, and
    # the accounts that lose their read are the dashboard's and the relay's,
    # which is why #545 stayed invisible on the very host it broke. The copy
    # is written beside the original and moved into place, which is atomic
    # on the same filesystem; carrying every one of owner, group, mode and
    # ACL is what makes the moved file indistinguishable from the one it
    # replaces.
    # Guarded rather than a bare call: under `set -e`, an unguarded call
    # whose setfacl fails would kill this script right here, on bash's own
    # message, and skip every line below that exists to name the failure and
    # clean up after it. Nothing has moved yet at this point, $tmp is beside
    # $CONFIG_FILE, not yet in its place, so a failed carry needs no restore,
    # only its own name and a config left exactly as it was.
    if ! commit_rewrite "$CONFIG_FILE" "$tmp"; then
      rm -f "$tmp"
      die "could not put the rewrite in place, carrying $CONFIG_FILE's owner, group, mode and ACL; $CONFIG_FILE is untouched"
    fi
    rm -f "$tmp"

    # Verified after the move, from the filesystem, not assumed from the
    # helper having exited zero. This is the check that would have caught
    # both the 2026-08-19 drift and #545: cwl_acl_snapshot reads the ACL
    # back as well as stat, so a rewrite that lands under the same
    # owner:group:mode but a smaller ACL is a mismatch here, not a pass.
    now_own=$(stat -c '%U:%G:%a' "$CONFIG_FILE" 2>/dev/null || echo '?')
    now_snap=$(cwl_acl_snapshot "$CONFIG_FILE")
    if [[ "$now_snap" != "$was_snap" ]]; then
      if restore_backup "$backup" "$CONFIG_FILE" && cmp -s "$backup" "$CONFIG_FILE"; then
        die "the rewrite changed $CONFIG_FILE's $(cwl_snapshot_describe); restored $backup and \
left the config reading exactly as it did before this ran, investigate before trying again"
      else
        die "the rewrite changed $CONFIG_FILE's $(cwl_snapshot_describe), AND restoring $backup \
failed; the node is running on a config whose permissions are unproven, fix $CONFIG_FILE by hand \
from $backup before doing anything else"
      fi
    fi

    printf 'set %s=%s in %s\n' "$key" "$val" "$CONFIG_FILE"
    printf 'owner: %s (unchanged)\n' "$now_own"
    printf 'compared: %s\n' "$(cwl_snapshot_describe)"
    printf 'was: %s\n' "$before"
    printf 'lines changed: %s\n' "$found"
    printf 'backup: %s\n' "$backup"
    printf 'not in effect until the node restarts, that is a separate approval\n'
    ;;

  # ── Native only ─────────────────────────────────────────────────────────
  # The image verbs are refused on this shape, and these are what replace
  # them. Every one of them acts on the package the root-owned configuration
  # names, at a version that came through require_version, resolved against
  # what this host's own repositories already carry.

  package-latest)
    require_node
    require_native
    require_no_arg
    require_pkg_tool
    # The same question package-available answers, asked without a version:
    # what is the newest release this host's own repositories offer. A read,
    # and only a read.
    #
    # Same three fields and the same verdicts, because the caller parses one
    # shape for both: yes/no/unknown/retired, then the candidate or "-", then
    # a sentence. retired (#802) is a host whose only source is the retired
    # repos.ripple.com, where the last version listed is not the newest. "unknown" stays a real answer for the reason package-available
    # gives: a package manager that would not answer has not said there is no
    # newer version, and rendering that as "no" is a reading nobody took.
    #
    # pkg_candidates() already computes the list, newest first on both
    # managers, and carries the manager's own status rather than awk's. The
    # first line is the answer; nothing here re-sorts it, because the order is
    # the package manager's and inventing one would be this script deciding
    # which release an install would take.
    pkg_rc=0; pkg_raw=$(pkg_candidates) || pkg_rc=$?
    if (( pkg_rc != 0 )); then
      printf 'unknown\t-\tthe package manager would not say what the repositories offer, so the newest %s available here is unknown\n' "$REPO"
      exit 0
    fi
    mapfile -t pkg_hits < <(printf '%s' "$pkg_raw" | grep -v '^$' || true)
    if (( ${#pkg_hits[@]} == 0 )); then
      printf 'no\t-\tthe repositories this host is configured with offer no %s at all\n' "$REPO"
    elif pkg_source_retired; then
      # Not "yes": what a retired repository lists last is not the newest
      # release, and a caller reading this as current is #802 itself.
      printf 'retired\t-\t%s\n' "$(pkg_retired_sentence)"
    else
      printf 'yes\t%s\t%s is the newest %s these repositories offer, of %s listed\n' \
        "${pkg_hits[0]}" "${pkg_hits[0]}" "$REPO" "${#pkg_hits[@]}"
    fi
    ;;

  package-available)
    require_node
    require_native
    require_pkg_tool
    require_version
    # A read, and only a read: it asks what the repositories offer and changes
    # nothing. RB-004's "the rollback target is installable" precondition is
    # this verb, asked before a cutover instead of discovered during one.
    #
    # Three verdicts, the same rule config-readable and rotation-state follow.
    # "unknown" is a real answer: a package manager that would not answer has
    # not told us the version is missing, and reporting that as "no" would
    # refuse a rollback on evidence nobody has.
    pkg_rc=0; pkg_raw=$(pkg_match "$ARG") || pkg_rc=$?
    if (( pkg_rc != 0 )); then
      printf 'unknown\t-\tthe package manager would not say what the repositories offer, so whether %s %s is installable is unknown\n' \
        "$REPO" "$ARG"
      exit 0
    fi
    mapfile -t pkg_hits < <(printf '%s' "$pkg_raw" | grep -v '^$' || true)
    # A retired source still answers truthfully about the versions it
    # carries, and a rollback to one of them depends on that "yes". What it
    # cannot do is stand for "not offered" when a newer release exists
    # elsewhere, so a miss on a retired source says retired, never no (#802).
    pkg_retired=0
    pkg_source_retired && pkg_retired=1
    pkg_note=''
    (( pkg_retired )) && pkg_note="; note: $(pkg_retired_sentence)"
    if (( ${#pkg_hits[@]} == 0 )); then
      if (( pkg_retired )); then
        printf 'retired\t-\t%s %s is not offered here, and %s\n' "$REPO" "$ARG" "$(pkg_retired_sentence)"
      else
        printf 'no\t-\t%s %s is not offered by the repositories this host is configured with\n' "$REPO" "$ARG"
      fi
    elif (( ${#pkg_hits[@]} == 1 )); then
      printf 'yes\t%s\t%s %s is installable from this host'"'"'s own repositories%s\n' \
        "${pkg_hits[0]}" "$REPO" "${pkg_hits[0]}" "$pkg_note"
    else
      # More than one package release of the same upstream version. Which one
      # is taken is said out loud, and so are the others, rather than picked
      # quietly: the caller passed a version, not a release.
      printf 'yes\t%s\t%s releases match %s (%s); %s is the one an install would take, being the first the package manager listed%s\n' \
        "${pkg_hits[0]}" "${#pkg_hits[@]}" "$ARG" "${pkg_hits[*]}" "${pkg_hits[0]}" "$pkg_note"
    fi
    ;;

  package-install)
    require_node
    require_native
    require_pkg_tool
    if [[ "$ARG" == "--from" ]]; then
      # Installing from an artefact package-keep already put on this host,
      # for the rollback whose repository no longer offers the version it
      # needs, issue #393's second half. Never a path the caller invents:
      # require_kept_path only accepts one of package-keep's own files, in
      # its own directory.
      require_kept_path
      case "$(pkg_tool)" in
        deb) [[ "$ARG2" == *.deb ]] || die "refusing $ARG2: this host installs .deb packages, not this" ;;
        rpm) [[ "$ARG2" == *.rpm ]] || die "refusing $ARG2: this host installs .rpm packages, not this" ;;
      esac
      # The sha256 package-keep recorded when it copied this file, re-read
      # and re-hashed now rather than trusted from the filename. That proves
      # the file has not been truncated or altered since it was kept. It does
      # not prove nobody with root wrote both the file and its sidecar, that
      # guarantee does not exist on this host, and is not claimed here.
      sidecar="$ARG2.sha256"
      [[ -f "$sidecar" ]] \
        || die "no recorded sha256 for $ARG2 ($sidecar is missing); refusing to install an unverified artefact"
      recorded=$(awk '{print $1}' "$sidecar")
      actual=$(sha256sum "$ARG2" | cut -d' ' -f1)
      [[ -n "$recorded" ]] || die "the recorded sha256 for $ARG2 is empty"
      [[ "$recorded" == "$actual" ]] \
        || die "refusing to install $ARG2: its sha256 is $actual, and this wrapper kept it as $recorded; it has changed since it was kept"
      base=$(basename "$ARG2")
      target=${base#"$REPO".kept.}
      target=${target%.deb}
      target=${target%.rpm}
      rotation_guard
      pkg_rc=0; before=$(pkg_installed_version) || pkg_rc=$?
      (( pkg_rc == 0 )) || before='not installed'
      printf 'installed before: %s\n' "$before"
      printf 'installing from the kept artefact: %s (sha256 verified)\n' "$ARG2"
      case "$(pkg_tool)" in
        deb)
          DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
            --allow-downgrades -o Dpkg::Options::=--force-confold "$ARG2" >&2 ;;
        rpm)
          dnf install -y "$ARG2" >&2 ;;
      esac
      pkg_rc=0; after=$(pkg_installed_version) || pkg_rc=$?
      (( pkg_rc == 0 )) \
        || die "the package manager exited 0 and the package database has no installed $REPO; nothing here will report a version it cannot read"
      [[ "$after" == "$target" ]] \
        || die "installed the kept artefact for $target and the package database now says $after, refusing to report an install that did not land where it was aimed"
      printf '%s -> %s\n' "$before" "$after"
    else
      require_version
      # A package change restarts the unit from the vendor's own maintainer
      # scripts, so it stops the node exactly as `restart` does, and it takes
      # the same guard for the same reason. #79 does not care which program
      # stopped the node mid-rotation.
      rotation_guard
      pkg_rc=0; pkg_raw=$(pkg_match "$ARG") || pkg_rc=$?
      (( pkg_rc == 0 )) \
        || die "the package manager would not say what the repositories offer, so $REPO $ARG could not be checked; nothing was installed"
      mapfile -t pkg_hits < <(printf '%s' "$pkg_raw" | grep -v '^$' || true)
      (( ${#pkg_hits[@]} > 0 )) \
        || die "the repositories this host is configured with do not offer $REPO $ARG, so there is nothing to install; ask package-available first"
      target=${pkg_hits[0]}
      if (( ${#pkg_hits[@]} > 1 )); then
        printf 'note: %s releases match %s (%s); installing %s, the first the package manager listed\n' \
          "${#pkg_hits[@]}" "$ARG" "${pkg_hits[*]}" "$target"
      fi
      pkg_rc=0; before=$(pkg_installed_version) || pkg_rc=$?
      (( pkg_rc == 0 )) || before='not installed'
      printf 'installed before: %s\n' "$before"
      case "$(pkg_tool)" in
        deb)
          # Pinned to one exact version, always. --allow-downgrades because a
          # rollback IS a downgrade and apt refuses one under -y without it;
          # --no-install-recommends because a node upgrade should bring the node
          # and not a recommendation tree. Never `upgrade`, never bare install.
          #
          # --force-confold keeps the node's config as it is. Every host this
          # project sets up has an edited xrpld.cfg (the installer hardens the
          # one the package ships), which makes it a modified conffile, and
          # dpkg stops on one of those to ask what to do. DEBIAN_FRONTEND is
          # not enough: it silences debconf, not dpkg's own conffile prompt.
          # Measured on a lab host, 2026-09-17: the prompt went to a closed
          # stdin, dpkg exited "end of file on stdin at conffile prompt", and
          # the package was left unconfigured, so the package database then
          # held no installed node at all. Keeping the operator's file is also
          # the only answer this wrapper is allowed to give: replacing a node
          # config is not one of its verbs.
          DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
            --allow-downgrades -o Dpkg::Options::=--force-confold "$REPO=$target" >&2 ;;
        rpm)
          dnf install -y "$REPO-$target" >&2 ;;
      esac
      # What the package DATABASE says afterwards, not what the command printed
      # and not what was asked for. The version that came up being the version
      # that was installed is the native half of the integrity guarantee, and it
      # is only a guarantee if it is read back.
      pkg_rc=0; after=$(pkg_installed_version) || pkg_rc=$?
      (( pkg_rc == 0 )) \
        || die "the package manager exited 0 and the package database has no installed $REPO; nothing here will report a version it cannot read"
      [[ "$after" == "$target" ]] \
        || die "asked for $REPO $target and the package database now says $after, refusing to report an install that did not land where it was aimed"
      printf '%s -> %s\n' "$before" "$after"
    fi
    ;;

  package-keep)
    require_node
    require_native
    require_pkg_tool
    require_no_arg
    # The artefact a rollback needs when the repository this host trusts no
    # longer offers the version an upgrade is about to replace, issue #393's
    # second half. Beside the config backups for the same reason
    # backup-compose's dated copies sit beside the compose file: one
    # directory this wrapper already knows to look in, not a second place
    # invented for a package.
    #
    # Retention matches backup-config's: nothing here is ever pruned, because
    # a pruned rollback artefact is the exact failure this exists to prevent.
    # The one honest cost is size, a kept package is tens of megabytes where
    # a kept config is a few kilobytes.
    pkg_rc=0; version=$(pkg_installed_version) || pkg_rc=$?
    (( pkg_rc == 0 )) || die "no installed $REPO on this host to keep"
    [[ "$version" =~ ^[A-Za-z0-9.:_+~-]+$ ]] \
      || die "refusing to keep: installed version '$version' has unexpected characters"
    # dpkg reports an epoch as "1:3.3.0-1"; apt's own cache filenames encode
    # the colon as %3a, and this wrapper's kept-artefact names do not encode
    # anything, so the colon would not round-trip back out through
    # require_kept_path's plain basename match. Refused here, before a
    # download, rather than kept under a name package-install --from could
    # never match again. This does not fix comparing an epoch version
    # elsewhere in this tree; it only means this host keeps no artefact for
    # one, and the ordinary package-available/package-install path is
    # unaffected.
    case "$version" in
      *:*) die "refusing to keep $version: an epoch version does not round-trip through this wrapper's file naming; keep it by hand if this host ever needs one" ;;
    esac
    case "$(pkg_tool)" in
      deb) ext=deb ;;
      rpm) ext=rpm ;;
    esac
    dest_dir="$PACKAGE_KEEP_DIR"
    # Created only when it is not there, and with its mode stated rather than
    # inherited: this script runs under umask 0027, and a plain mkdir would
    # leave 0750 behind. An `install -d` over a directory that already exists
    # would re-apply owner and mode to it, which is how a re-run undoes a
    # deliberate change (#441).
    [[ -d "$dest_dir" ]] || install -d -m 0755 "$dest_dir" \
      || die "could not create $dest_dir to keep the artefact in"
    dest="$dest_dir/$REPO.kept.$version.$ext"
    sidecar="$dest.sha256"
    # A version kept in the older location is already kept. Reported from
    # where it is, and not fetched again into the new one.
    legacy_dest="$(dirname "$CONFIG_FILE")/$REPO.kept.$version.$ext"
    if [[ ! -f "$dest" && -f "$legacy_dest" ]]; then
      dest="$legacy_dest"
      sidecar="$dest.sha256"
    fi
    # Idempotent: a version already kept and still intact is reported, not
    # re-fetched. A version kept whose sidecar disagrees with the file is a
    # question for an operator, not something this overwrites quietly.
    if [[ -f "$dest" ]]; then
      if [[ -f "$sidecar" ]]; then
        recorded=$(awk '{print $1}' "$sidecar")
        actual=$(sha256sum "$dest" | cut -d' ' -f1)
        if [[ -n "$recorded" && "$recorded" == "$actual" ]]; then
          printf 'already kept\t%s\t%s\t%s\n' "$dest" "$version" "$actual"
          exit 0
        fi
      fi
      die "a kept artefact for $version already exists at $dest and its recorded sha256 does not match the file (or is missing); remove it by hand and re-run if that is intended"
    fi
    # apt-get download and dnf download both drop the file in the working
    # directory (or --destdir), never in a place they invent, so a scratch
    # directory beside the destination is what makes either safe to run
    # under this umask. install -d states the mode rather than inheriting
    # it, the same reason rotation_guard's own directory does: this script
    # runs under umask 0027, and a plain mkdir would leave 0750 behind.
    tmp_dl="$dest_dir/.$REPO.kept.$version.$$"
    install -d -m 0755 "$tmp_dl"
    raw=''
    case "$(pkg_tool)" in
      deb)
        # The repository first: it verifies the vendor's signature the same
        # way an ordinary install does. The exit code is not trusted, apt's
        # privilege-drop to _apt is noisy and version-dependent, whether a
        # .deb actually landed is what is checked.
        (cd "$tmp_dl" && apt-get download "$REPO=$version") >&2 || true
        raw=$(find "$tmp_dl" -maxdepth 1 -name '*.deb' -print -quit)
        if [[ -z "$raw" ]]; then
          # The repository may no longer carry this version; the fallback is
          # whatever this host cached the day it installed it, which needs no
          # network and no repository at all.
          raw=$(find "$APT_CACHE_DIR" -maxdepth 1 -name "${REPO}_${version}_*.deb" -print -quit 2>/dev/null || true)
        fi
        ;;
      rpm)
        (dnf download --destdir "$tmp_dl" "$REPO-$version") >&2 || true
        raw=$(find "$tmp_dl" -maxdepth 1 -name '*.rpm' -print -quit)
        if [[ -z "$raw" ]]; then
          raw=$(find "$DNF_CACHE_DIR" -maxdepth 4 -name "${REPO}-${version}.*.rpm" -print -quit 2>/dev/null || true)
        fi
        ;;
    esac
    if [[ -z "$raw" ]]; then
      rm -rf "$tmp_dl"
      die "could not obtain the $REPO $version package artefact, from the repository or from this host's own cache; nothing was kept"
    fi
    cp -a "$raw" "$dest"
    rm -rf "$tmp_dl"
    [[ -s "$dest" ]] || die "kept artefact at $dest is empty"
    sum=$(sha256sum "$dest" | cut -d' ' -f1)
    printf '%s  %s\n' "$sum" "$(basename "$dest")" > "$sidecar"
    check=$(sha256sum "$dest" | cut -d' ' -f1)
    [[ "$check" == "$sum" ]] || die "the kept artefact's hash changed while recording it"
    printf 'kept\t%s\t%s\t%s\n' "$dest" "$version" "$sum"
    ;;

  package-kept)
    require_node
    require_native
    require_no_arg
    # What package-keep is holding, read back rather than assumed: a file
    # whose sha256 no longer matches its sidecar is reported as a mismatch,
    # not silently skipped, because a rollback that trusted a corrupt
    # artefact would fail worse than one that found nothing kept at all.
    kept=()
    shopt -s nullglob
    while IFS= read -r kdir; do
      kept+=("$kdir/$REPO".kept.*.deb "$kdir/$REPO".kept.*.rpm)
    done < <(package_keep_dirs)
    shopt -u nullglob
    if (( ${#kept[@]} == 0 )); then
      printf 'no kept package artefacts in %s\n' "$(package_keep_dirs | tr '\n' ' ')"
      exit 0
    fi
    for f in "${kept[@]}"; do
      [[ -f "$f" && ! -L "$f" ]] || continue
      base=$(basename "$f")
      ver=${base#"$REPO".kept.}
      ver=${ver%.deb}
      ver=${ver%.rpm}
      actual=$(sha256sum "$f" | cut -d' ' -f1)
      sidecar="$f.sha256"
      if [[ -f "$sidecar" ]]; then
        recorded=$(awk '{print $1}' "$sidecar")
        if [[ -n "$recorded" && "$recorded" == "$actual" ]]; then
          printf '%s\t%s\t%s\tok\n' "$ver" "$f" "$actual"
        else
          printf '%s\t%s\t%s\tsha mismatch\n' "$ver" "$f" "$actual"
        fi
      else
        printf '%s\t%s\t%s\tno recorded sha256\n' "$ver" "$f" "$actual"
      fi
    done
    ;;

  package-version)
    require_node
    require_native
    require_pkg_tool
    require_no_arg
    # What is installed right now, from the package database. The
    # before-and-after comparison that running-digest performs on a container.
    pkg_rc=0; v=$(pkg_installed_version) || pkg_rc=$?
    (( pkg_rc == 0 )) \
      || die "the package database has no installed $REPO on this host, which is what $CONF says this node is"
    printf '%s\t%s\n' "$REPO" "$v"
    ;;

  *)
    die "unknown verb '${VERB:-}'"
    ;;
esac
