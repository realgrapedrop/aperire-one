#!/usr/bin/env bash
# install-aperire-node.sh - put a hardened XRPL node on this box, from nothing.
#
#   curl -fsSL https://get.aperire.one | bash -s -- --node
#                                   a box with no node: this, then the install
#   curl -fsSL https://get.aperire.one | bash -s -- --run node --adopt
#   curl -fsSL https://get.aperire.one | bash -s -- --run node --native --name <label>
#                                   an installed host: take over the node it has
#
# Root runs it only as a copy the bootstrap checked out of the release (#929).
# Its own arguments, as the bootstrap hands them on: --yes, --name <label>,
# --role stock|validator, --image-tag <tag>, --native, --adopt, --unit <unit>,
# --move-source.
#
# Why it exists (#139): every other installer in this tree assumes a node is
# already running. install.sh's co-located role puts the dashboard and the
# relay BESIDE a node; it does not deploy one. The hardened compose lived only
# in an internal document that never ships, so an operator starting from zero
# had no supported path to a running node and no way to get the hardening
# without copying YAML out of a doc they do not have.
#
# What it does, in order (the container path, which is the default):
#   1. installs the Docker engine and the compose plugin if they are absent
#   2. creates <dir>/{config,data} with the ownership the hardened compose
#      needs, which is not the obvious one (see below)
#   3. copies the stock rippled.cfg and validators.txt from
#      scripts/templates/, and NEVER over an existing config
#   4. renders scripts/templates/aperire-node.compose.yml with this node's
#      name, paths and image tag
#   5. docker compose up -d
#   6. verifies out loud: the container is healthy, 5005 and 6006 are on
#      loopback, server_info answers, and the ledger sequence moved
#   7. closes the config file to every account but its owner and the node,
#      through scripts/close-node-config-exposure.sh (#462). That file carries
#      [validator_token] on a validator, and until this ran here only the
#      Advisor one-liner closed it, so a host with a node and a dashboard and
#      no Advisor kept it world-readable for the life of the install
#
# Idempotent. A second run changes no content: it keeps the config it finds,
# keeps the image tag already in the compose file (a re-run must never quietly
# stage an upgrade - that is the Advisor's runbook, not this script), and
# rewrites the compose only when the rendered bytes actually differ. Step 7 is
# the one thing it re-asserts every time, and it is idempotent in its own
# right: an already-closed file is reported as already closed, and a named ACL
# entry an earlier run or the Advisor one-liner added survives.
#
# Flags:
#   --dir PATH        where the node lives (default /home/<operator>/aperire-node).
#                      Ignored by --native: a package install lives where the
#                      vendor's package puts it, not under an operator's home
#   --name NAME       container AND compose project name (default aperire-node).
#                     This is the label the fleet knows the node by, and the
#                     relay picks its node_label from it, so name it once and
#                     do not rename it later. On --native this is the fleet
#                     label alone: there is no container to also name
#   --image-tag TAG   pin the image. Default: the newest release-shaped tag the
#                     registry lists, the same source and the same filter the
#                     Advisor uses to decide what is installable. Ignored by
#                     --native, which has no image to tag
#   --role stock|validator
#                     validator adds the commented [validator_token] stanza and
#                     says where the token goes. It NEVER generates a validator
#                     key: that is done off the box, by hand, with the
#                     validator-keys tool, and this script must not be able to
#                     mint an identity
#   --net mainnet     mainnet only for now; any other value is refused rather
#                     than silently treated as mainnet
#   --adopt           record a node that is already here. It measures the
#                     running container (its name, the config it mounts, the
#                     admin RPC it publishes, the account it runs as) and
#                     writes /etc/aperire/node.conf from that, then closes
#                     that config the same way an install does (#462).
#                     Nothing is installed, started or stopped, and no file
#                     CONTENT is edited: the config's mode changes, its bytes
#                     do not. This is the repair for a host whose node
#                     outlived a wipe-clean uninstall (#434), and it is a
#                     smaller action than re-running an install over a node
#                     that needs nothing
#   --native          no Docker: adopt a native node if one is already on this
#                     host (by systemd unit), otherwise offer to install the
#                     vendor's own package. See "Native mode" below
#   --vendor-retention
#                     --native only: keep the package's own online_delete
#                     instead of the window this project's container nodes
#                     use. The default is 16384 ledgers on both shapes; the
#                     vendor ships 512, which keeps about a thirtieth of the
#                     history and needs a fraction of the disk
#   --unit NAME       name the systemd unit yourself, for --native's adopt
#                     check. Needed for a fork this script does not guess at
#                     (xahaud's unit is not one of the two names probed by
#                     default)
#   --move-source     a native host only: move this host's xrpld package
#                     source off the retired repos.ripple.com (it stops at
#                     3.3.0) onto packages.xrplf.org, with the same
#                     fingerprint-checked key an install uses. Changes apt or
#                     dnf sources and refreshes that one list, nothing else:
#                     no package is installed or upgraded, the node is not
#                     restarted and its config is not read or written. A
#                     source file this installer did not write is kept and
#                     named. --native's adopt and an update run it for you
#   --yes             unattended: no prompts
#   -h, --help        this header
#
# The ownership, which is the whole permission story (#31). The node does not
# run as root inside its container, and the compose drops ALL capabilities, so
# the process has no CAP_DAC_OVERRIDE and the host file modes on the mounts
# decide everything. Three paths and one account:
#
#   the account   `xrpld`, created here if this host has no such account,
#                 preferring uid 997 gid 997, which is the account and the
#                 numbers the vendor's own image ships. See
#                 scripts/node-user-lib.sh for what happens when 997 is taken
#   data/         owned by that account, 0755. Owned by anyone else, the very
#                 first start crash-loops on "Can not create
#                 /var/lib/xrpld/db", which reads like a broken image and is a
#                 file mode. 0755 rather than 0750 because the dashboard walks
#                 this directory to size the ledger store, and it is public
#                 ledger data with no key material in it
#   config/rippled.cfg, validators.txt
#                 owned by the operator, group `xrpld`, so the node reads them
#                 through the group and nothing has to be world-readable. The
#                 config carries [validator_token] on a validator, which is
#                 why the group is the narrow one and not the operator's
#
# Native mode (#30, no Docker anywhere on the host): two verbs, kept apart.
#
#   Adopt. If a native node is already on this host - xrpld.service,
#   rippled.service, xahaud.service, or the unit named by --unit - nothing is
#   installed from anywhere. Its config is found, its admin RPC is confirmed,
#   and scripts/install-node-wrapper.sh --native points the privilege wrapper
#   at it. xahaud is adopt-only: there is no vendor repository named for it
#   below, so a host running it always takes this path and says so.
#   An xrpld package still sourced from the retired repos.ripple.com has its
#   source moved to packages.xrplf.org on the way (--move-source above):
#   sources only, the package itself is not touched.
#
#   Offer. With no native node found, this installs one, but only on the
#   three combinations the vendor names: Ubuntu 22.04, Ubuntu 24.04 or
#   Debian 12 (x86_64), or RHEL 9 (x86_64). It adds the vendor's own
#   repository and signing key, installs the xrpld package at the newest
#   stable version the repository offers, hardens the config the package
#   shipped (admin ports to loopback, the same publisher list the container
#   path installs, one advisory_delete line), enables the unit, then runs the
#   same verification the container path runs. Anywhere else, this refuses by
#   name and points at the adopt path: install a node yourself, by hand or by
#   the vendor's own instructions, and run this again to adopt it.
#
#   Either way, the run ends with a configured wrapper: install-node-wrapper.sh
#   --native has already run, so there is nothing left to wire by hand.

# -E so the ERR trap below reaches inside functions: the failure this guards
# against happened three frames deep, and a trap that only fires at the top
# level would not have seen it.
set -Eeuo pipefail

# As root the environment chooses no path or program (#1206): every
# APERIRE_* variable is dropped except the ones a root caller passes on
# purpose:
#   APERIRE_INSTALL_TREE  get-aperire.sh names the tree a staged copy serves (#764)
#   APERIRE_INSTANCE      install.sh exports it to every step; checked below
# An account id(1) says is not root keeps them all, which is what every
# suite is. id(1) at a fixed path, never bash's $EUID (#1109).
if ! [[ "$(/usr/bin/id -u 2>/dev/null)" =~ ^[1-9][0-9]*$ ]]; then
  for _v in $(compgen -e); do
    case "$_v" in APERIRE_INSTALL_TREE|APERIRE_INSTANCE) ;; APERIRE_*) unset "$_v" ;; esac
  done
fi
# The instance names a unit file and a drop-in path, so it is held to the
# rule advisor-owner-lib.sh holds it to, under the C locale (under
# en_US.UTF-8, [a-z] matches é), and anything else is refused.
instance_name_ok() { # $1 = a name; [a-z] is held to ASCII, whatever the locale
  local LC_ALL=C
  [[ "$1" =~ ^[a-z0-9][a-z0-9-]{0,30}$ && "$1" != credcheck && "$1" != credcheck-* ]]
}
if [[ -n "${APERIRE_INSTANCE:-}" ]] && ! instance_name_ok "$APERIRE_INSTANCE"; then
  printf 'refused: APERIRE_INSTANCE=%q is not an instance name (a-z, 0-9 and -, at most 31, not credcheck)\n' "$APERIRE_INSTANCE" >&2
  exit 2
fi

# Where this program and its siblings are (SCRIPTS_DIR), and the install tree
# it acts on (REPO_DIR): a directory and its parent from a checkout, two when
# get-aperire.sh runs a copy root staged out of the release and names the
# tree with APERIRE_INSTALL_TREE (#764). Code is loaded from SCRIPTS_DIR only.
SCRIPTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="${APERIRE_INSTALL_TREE:-$(cd "${SCRIPTS_DIR}/.." && pwd)}"
TEMPLATE_DIR="${SCRIPTS_DIR}/templates"

# The palette the install path shares, so "done", "degraded" and "refused"
# look the same wherever they are printed. Every string in it is empty unless
# the stream is a terminal, so a captured or piped run stays byte-plain.
[[ -r "${SCRIPTS_DIR}/term-style.sh" ]] \
  || { echo "error: ${SCRIPTS_DIR}/term-style.sh is missing from this checkout" >&2; exit 1; }
# shellcheck source=scripts/term-style.sh
. "${SCRIPTS_DIR}/term-style.sh"

# The account the node runs as, and the rules for resolving it. Shared with
# scripts/migrate-node-nonroot.sh so a migrated host and a freshly installed
# one land on the same uid by the same reasoning (#31).
[[ -r "${SCRIPTS_DIR}/node-user-lib.sh" ]] \
  || { echo "error: ${SCRIPTS_DIR}/node-user-lib.sh is missing from this checkout" >&2; exit 1; }
# shellcheck source=scripts/node-user-lib.sh
. "${SCRIPTS_DIR}/node-user-lib.sh"

# The one place in this tree that knows how to ask docker what is running, and
# how to tell "nothing is running" from "docker would not answer". --adopt
# decides what to record from that answer, so it must not read a refusal as an
# absence (#140, #142).
[[ -r "${SCRIPTS_DIR}/docker-ask-lib.sh" ]] \
  || { echo "error: ${SCRIPTS_DIR}/docker-ask-lib.sh is missing from this checkout" >&2; exit 1; }
# shellcheck source=scripts/docker-ask-lib.sh
. "${SCRIPTS_DIR}/docker-ask-lib.sh"

# The ACL-carrying helper this script shares with aperire-node-wrapper.sh's
# set-config and set-image, enable-advisory-delete.sh, configure-rippled-
# paths.sh and migrate-node-nonroot.sh (#545). native_harden_cfg below is the
# same mktemp-then-mv shape every one of those already goes through it for.
[[ -r "${SCRIPTS_DIR}/config-write-lib.sh" ]] \
  || { echo "error: ${SCRIPTS_DIR}/config-write-lib.sh is missing from this checkout" >&2; exit 1; }
# shellcheck source=scripts/config-write-lib.sh
. "${SCRIPTS_DIR}/config-write-lib.sh"
# Where an instance's wrapper and its configuration live (ADR 0024), spelled
# in one place for every script that has to find them.
[[ -r "${SCRIPTS_DIR}/trusted-path-lib.sh" ]] \
  || { echo "error: ${SCRIPTS_DIR}/trusted-path-lib.sh is missing from this checkout" >&2; exit 1; }
# shellcheck source=scripts/trusted-path-lib.sh
. "${SCRIPTS_DIR}/trusted-path-lib.sh"

# The image this installs, and the release it pins.
#
# A fresh node takes the OFFICIAL image for the pinned release, pinned to the
# digest that tag has right now (#682). The XRPL release process publishes it
# as part of the release itself, announced 2026-09-19, and
# WietseWind/docker-xrpld#31 retires the old xrpllabsofficial account in its
# favour. The reference written into the deployment carries both: the tag, so
# a person reading the file can see which release it is, and the digest, so
# what actually gets pulled cannot change when somebody moves a tag.
#
# When no official image carries the pinned release, the image is BUILT here
# from the XRPL Foundation's signed DEB package and named
# localhost/xrpld:<release>. A release ships as a signed package first and an
# official image does not always follow the same day, and a release with an
# amendment deadline on it (fixBatchV1_2, 2026-10-09) is not something to
# wait on a registry for.
#
# localhost/ is a name no registry can answer for, which is the point: a pull
# of it fails rather than fetching somebody else's image under a name that
# looks like ours.
#
# The release is pinned here and bumped deliberately, with the announcement
# open, together with the row in scripts/build-xrpld-image.sh's own table of
# announced package hashes. Nothing here resolves "newest" over the network:
# the one place that reads the package index is the Advisor, which is also
# the thing that performs upgrades, and a second reader would be a second
# answer to one question.
DEFAULT_IMAGE_REPO=localhost/xrpld
# The repository the release process publishes to. A constant, never a
# setting: what comes back from a registry is what the node runs.
OFFICIAL_IMAGE_REPO=rippleci/xrpld
PINNED_TAG=3.4.1
# Filled in below when an official image carries the pinned release. Empty
# means this run builds instead.
IMAGE_DIGEST=""
# Resolved below, with the repository, from the deployment this host already
# has when there is one.
IMAGE_REPO="$DEFAULT_IMAGE_REPO"

# Where the root-owned image recipe is installed, and where this script then
# builds from. The same path scripts/install-xrpld-image-recipe.sh writes and
# the privilege wrapper runs, so all three agree by construction. A variable
# only so the tests can point it somewhere harmless.
IMAGE_RECIPE_DIR="${APERIRE_IMAGE_RECIPE_DIR:-/usr/local/lib/aperire}"

NODE_WRAPPER="${APERIRE_NODE_WRAPPER:-}"
if [[ -z "$NODE_WRAPPER" ]]; then
  NODE_WRAPPER="$(trusted_wrapper_path "${APERIRE_INSTANCE:-}")"
  if [[ ! -f "$NODE_WRAPPER" || -L "$NODE_WRAPPER" || "$(stat -c %u -- "$NODE_WRAPPER" 2>/dev/null)" != 0 ]]; then
    NODE_WRAPPER="$SCRIPTS_DIR/aperire-node-wrapper.sh"
  fi
fi

# Where a dashboard on this host keeps its env files, if one is here yet.
ETC_APERIRE=/etc/aperire

# Ports. Two numbers each, and they are not the same number: the host side is
# what an operator and a firewall see, the container side is what the node
# binds. The peer pair is the one that goes wrong quietly.
HOST_PEER_PORT=51235
ADMIN_RPC_PORT=5005
ADMIN_WS_PORT=6006

# How many ledgers a node keeps online, on the native path. The value this
# project's own container config has always used, applied to a native install
# so both shapes of the same product keep the same history (#429, ruled
# 2026-09-17). The vendor's package ships 512. The cost is disk: the lab's
# container node held about 43 GB at this setting, against a few gigabytes at
# the vendor's, and the deployment guide states it. Empty would leave the
# package's own value untouched.
NATIVE_ONLINE_DELETE=16384

# A node opens its admin RPC some way into its start; see the wait loop below.
NODE_WAIT_SECS="${APERIRE_NODE_WAIT_SECS:-150}"

# Stubbed by the test the way ETC_APERIRE is: a fixture os-release file, never
# the real one.
OS_RELEASE_FILE="${APERIRE_OS_RELEASE_FILE:-/etc/os-release}"

# ── The three OS/package combinations the vendor names (#30) ──────────────
# Source: XRPLF/rippled docs/install.md (packages published from 2026-08-19
# on; the legacy repository below is for 3.3.0 and earlier per
# docs/install-legacy.md) and the 3.4.1 announcement at xrpl.org/blog, both
# read 2026-09-30. Named once, here, so a correction from the lab run or a
# new vendor release has exactly one place to land.
#
# repos.ripple.com never carries 3.4.0 or later (#655): packages moved to
# packages.xrplf.org, under an XRPL Foundation key, on 2026-08-19. A node
# whose apt sources still name the old repository resolves an install or an
# update against a repository that will never offer the release an
# activating amendment requires.
NATIVE_PACKAGE=xrpld
NATIVE_DEB_REPO_URL=https://packages.xrplf.org/repository/deb-stable
NATIVE_DEB_KEY_URL=https://packages.xrplf.org/xrplf.asc
# install.md L54-L60: the fingerprint of the key at NATIVE_DEB_KEY_URL /
# NATIVE_RPM_KEY_URL (the two are the same key), checked before either is
# trusted (#655). A key fetched over TLS is a key whatever answered that
# connection chose to hand back; the fingerprint is the one fact that does
# not travel over the same wire.
NATIVE_XRPLF_KEY_FINGERPRINT=B655416741221F780FBCFBC9AA84D41A11D29FA9
# The four paths below are stubbable, the way ETC_APERIRE and OS_RELEASE_FILE
# are: the test drives the real add-repository code against a fixture
# directory rather than the real /etc, which needs root and would otherwise
# make this the one part of the suite that could not run unprivileged.
NATIVE_DEB_KEYRING="${APERIRE_NATIVE_DEB_KEYRING:-/etc/apt/keyrings/xrplf.asc}"
NATIVE_DEB_SOURCES_LIST="${APERIRE_NATIVE_DEB_SOURCES_LIST:-/etc/apt/sources.list.d/xrplf.list}"
NATIVE_RPM_REPO_URL=https://packages.xrplf.org/repository/rpm-stable/\$basearch/
NATIVE_RPM_KEY_URL=https://packages.xrplf.org/xrplf.asc
NATIVE_RPM_REPO_FILE="${APERIRE_NATIVE_RPM_REPO_FILE:-/etc/yum.repos.d/xrplf.repo}"
# The repository and keyring this installer wrote before #655, left on a host
# that installed natively before this fix. Named so the same repo-add step
# can retire them, rather than leaving apt or dnf holding two sources that
# both claim to offer the same package.
NATIVE_LEGACY_DEB_KEYRING="${APERIRE_NATIVE_LEGACY_DEB_KEYRING:-/etc/apt/keyrings/ripple.gpg}"
NATIVE_LEGACY_DEB_SOURCES_LIST="${APERIRE_NATIVE_LEGACY_DEB_SOURCES_LIST:-/etc/apt/sources.list.d/ripple.list}"
NATIVE_LEGACY_RPM_REPO_FILE="${APERIRE_NATIVE_LEGACY_RPM_REPO_FILE:-/etc/yum.repos.d/ripple.repo}"
# What those files named, exactly as every release before #655 wrote them,
# so "is this file ours" is a comparison with what was written rather than a
# guess from one word in it (#802).
NATIVE_LEGACY_DEB_REPO_URL=https://repos.ripple.com/repos/rippled-deb
NATIVE_LEGACY_RPM_REPO_URL=https://repos.ripple.com/repos/rippled-rpm/stable/
NATIVE_LEGACY_RPM_KEY_URL=https://repos.ripple.com/repos/rippled-rpm/stable/repodata/repomd.xml.key
# Where apt reads its sources, beside the legacy file: every .list and
# .sources file there, and the main list one level up. Read only to decide
# whether anything still names the legacy keyring before it is removed.
NATIVE_APT_SOURCES_DIR="$(dirname "$NATIVE_LEGACY_DEB_SOURCES_LIST")"
NATIVE_APT_MAIN_LIST="$(dirname "$NATIVE_APT_SOURCES_DIR")/sources.list"
# Where the node wrapper's package-keep keeps the package a rollback needs,
# and the two caches it falls back to. The source move keeps the installed
# package here, in package-keep's own form, before it retires the only
# repository that still carries that version (#802). Stubbable the way the
# paths above are.
NATIVE_PACKAGE_KEEP_DIR="${APERIRE_PACKAGE_KEEP_DIR:-/var/lib/aperire/rollback}"
NATIVE_APT_CACHE_DIR="${APERIRE_APT_CACHE_DIR:-/var/cache/apt/archives}"
NATIVE_DNF_CACHE_DIR="${APERIRE_DNF_CACHE_DIR:-/var/cache/dnf}"
# The candidate cfg paths a fresh xrpld package install can leave, checked
# in this order. Same discipline as install-node-wrapper.sh's --native
# candidates: read what is there, never assume a single layout.
if [[ -n "${APERIRE_NATIVE_CFG_CANDIDATES:-}" ]]; then
  read -ra NATIVE_CFG_CANDIDATES <<< "$APERIRE_NATIVE_CFG_CANDIDATES"
else
  NATIVE_CFG_CANDIDATES=(/etc/xrpld/xrpld.cfg /etc/opt/ripple/rippled.cfg)
fi

OPERATOR="${SUDO_USER:-$(id -un)}"
DIR=""
NAME=aperire-node
IMAGE_TAG=""
ROLE=stock
NET=mainnet
ASSUME_YES=0
NATIVE=0
NATIVE_KEEP_VENDOR_PEER_PORT=0
MOVE_SOURCE=0
UNIT_OVERRIDE=""
ADOPT=0
# Empty means "find the node yourself". --name fills it, because on a host
# running two containers this run must not pick one.
ADOPT_NAME=""

# ── The last line, on every path ─────────────────────────────────────────
#
# Every refusal in this script goes through die(), which names the problem
# and stops. Nothing else is meant to end a run, and for one release
# something else did: a pipeline came back 141 under `set -o pipefail`,
# `set -e` took the run down with it, and an operator installing a node
# natively got a blank line, no node and no reason (#411). That one line is
# fixed. A script that CAN stop without giving a reason has optional error
# handling, though, so this makes the reason compulsory: if the run ends
# non-zero and nothing has spoken, this speaks, and names the line and the
# command.
#
# The mark is a FILE rather than a variable because die() is reachable from
# inside a command substitution (native_harden_cfg prints its answer and
# refuses on the same path), and a variable set in a subshell never comes
# back to the shell that has to read it.
#
# The file is created empty and kept, never deleted and re-made: mktemp owns
# the name, so nothing else on this host can get between the two and hand a
# root process a symlink to write through. The mark is the content.
SAID_WHY_MARK="$(mktemp -t aperire-install-said.XXXXXX)"
# Every other temp file this run makes is added here and removed by on_exit
# with the mark, so a die between making one and the rm that follows it leaves
# nothing behind (#588): a key that failed its fingerprint check used to stay
# in the temp dir.
SCRAPS=()
# Removes one scrap now and takes it off the list, so on_exit does not try a
# name that is already free. A name freed here can be taken by another account
# in a shared temp dir; on_exit must never be the one to trip over that. A
# removal that fails keeps the entry, and on_exit tries it once more.
scrap_rm() {
  local gone="$1" s keep=()
  rm -f -- "$gone" 2>/dev/null || return 0
  for s in ${SCRAPS[@]+"${SCRAPS[@]}"}; do [[ "$s" == "$gone" ]] || keep+=("$s"); done
  SCRAPS=()
  for s in ${keep[@]+"${keep[@]}"}; do SCRAPS+=("$s"); done
  return 0
}
FAILED_AT=''
trap 'FAILED_AT="line ${LINENO}: ${BASH_COMMAND}"' ERR
# shellcheck disable=SC2329,SC2317  # installed as an EXIT trap below, which shellcheck cannot see as a call (SC2317 is the runner's older name for it)
on_exit() {
  # First line: everything below it would overwrite the status being reported.
  local rc=$?
  local spoke=0
  [[ -s "$SAID_WHY_MARK" ]] && spoke=1
  rm -f "$SAID_WHY_MARK"
  [[ -n "${RENDERED:-}" ]] && rm -f "$RENDERED"
  local scrap
  # errexit is live in an EXIT trap: a removal that fails (a name another
  # account replaced with something root cannot delete) must not change the
  # status being reported or skip the line below.
  for scrap in ${SCRAPS[@]+"${SCRAPS[@]}"}; do rm -rf -- "$scrap" 2>/dev/null || true; done
  if (( rc != 0 )) && (( ! spoke )); then
    local why="status ${rc}"
    (( rc > 128 )) && why="${why}, killed by signal $(( rc - 128 ))"
    echo >&2
    echo "${E_RED}error: this install stopped with ${why} and nothing above it said why.${E_OFF}" >&2
    echo "   at ${FAILED_AT:-a step that did not name itself}" >&2
    echo "   That is a defect in this installer, not something you did. Nothing" >&2
    echo "   after that point ran, so re-running it is safe once it is fixed." >&2
  fi
  exit "$rc"
}
trap on_exit EXIT

die()  { echo said > "$SAID_WHY_MARK"; echo; echo "${E_RED}error: $*${E_OFF}" >&2; exit 1; }

# The node's config, its publisher list and its compose file all start from a
# template in this checkout, and the node, and root through the wrapper, obey
# what they become. So each template is checked against the release's digests
# and read once into a file only root holds, and that copy is what is written
# or rendered (ADR 0024). Prints the checked copy's path.
# shellcheck source=scripts/release-digests-lib.sh
. "${SCRIPTS_DIR}/release-digests-lib.sh"
#
# Called as `x="$(checked_template <file>)" || exit 1`, never inside another
# command's arguments: a refusal has to stop the run, not hand the command
# an empty path. The caller removes the copy once it has used it.
checked_template() { # $1 = file name under scripts/templates
  local f d
  # Checked in a directory of its own, then renamed onto a file only root
  # holds: the trusted-path check never lands a copy straight in a directory
  # every account can write, which /tmp is.
  d="$(mktemp -d)" || die "cannot make a directory to check ${1} in"
  f="$(mktemp)" || { rm -rf "$d"; die "cannot make a file to check ${1} in"; }
  if ! rd_stage "$REPO_DIR" "scripts/templates/$1" "$d/t"; then
    rm -rf "$d" "$f"
    die "$(rd_refused_cause "${TEMPLATE_DIR}/$1"), so nothing was written from it"
  fi
  mv -fT -- "$d/t" "$f" || { rm -rf "$d" "$f"; die "cannot keep the checked copy of ${1}"; }
  rmdir "$d"
  printf '%s' "$f"
}
say()  { echo; echo "${S_BOLD}== $*${S_OFF}"; }
info() { echo "   $*"; }
have() { echo "   ${S_GREEN}already there: $*${S_OFF}"; }
warn() { echo "   ${S_AMBER}$*${S_OFF}"; }

# ── Shared verify vocabulary ─────────────────────────────────────────────
# Used by both the container path's verify section (below) and native_main's.
# Moved up here, once, rather than kept twice: a verdict word or a JSON read
# that drifted between the two would be exactly the kind of gap this pair of
# paths must not have.
V_OK=0
V_FAIL=0
v_ok()     { echo "   ${S_GREEN}ok${S_OFF}      $1"; V_OK=$((V_OK + 1)); }
v_warn()   { echo "   ${S_AMBER}warn${S_OFF}    $1"; }
v_failed() { echo "   ${S_RED}FAILED${S_OFF}  $1"; V_FAIL=$((V_FAIL + 1)); }

# server_info over the published (or, on native, the configured) admin RPC
# port. Reached the way anything else on this host would reach it, so this
# proves the publish/bind as well as the node.
server_info() {
  curl -s --max-time 10 -H 'Content-Type: application/json' \
    -d '{"method":"server_info","params":[{}]}' \
    "http://127.0.0.1:${ADMIN_RPC_PORT}/" 2>/dev/null
}
json_field() {  # $1 = key, reads the body on stdin
  sed -n "s/.*\"$1\"[[:space:]]*:[[:space:]]*\"\\{0,1\\}\\([A-Za-z0-9_.]*\\)\"\\{0,1\\}.*/\\1/p" | head -1
}

# The two admin ports, on loopback, from the host. This is what the dashboard
# will connect to, so it is measured the way the dashboard will reach it and
# not by asking docker (or systemd) what it published.
# Three answers, not two. "listening" is not the check: an admin port bound
# to a wildcard address is reachable from off this host, and anything that
# reaches it can tell this node to stop. That is a worse outcome than a closed
# port and it would otherwise read as ok.
port_state() {  # $1 = port; prints loopback, wildcard or closed
  local lines
  if ! command -v ss >/dev/null 2>&1; then
    # No ss on this image. A connect answers the open/closed half of the
    # question; it cannot answer the loopback half, so it never says loopback.
    if ( exec 3<>"/dev/tcp/127.0.0.1/$1" ) 2>/dev/null; then echo unchecked; else echo closed; fi
    return 0
  fi
  # ss answered, so its answer is the answer. Falling through to a connect
  # after a successful ss is how a port ss says is closed gets reported open
  # by whatever else happens to hold it.
  lines="$(ss -ltn 2>/dev/null | grep -E "[:.]$1[[:space:]]" || true)"
  if [[ -z "$lines" ]]; then echo closed; return 0; fi
  if printf '%s\n' "$lines" | grep -qE "127\.0\.0\.1:$1[[:space:]]"; then echo loopback; return 0; fi
  echo wildcard
}

# Shared by the container and native config-writing sections: placeholders
# and a sentence, never a key. Generating a validator identity is done off
# the box with the validator-keys tool, and a script that could mint one is a
# script that can be made to mint one.
append_validator_token_stanza() {  # $1 = the cfg file to append to
  local cfg="$1"
  cat >> "$cfg" <<'EOF'

# ── validator identity ──────────────────────────────────────────────
# This node is a validator in every respect except its identity, which is not
# here and was not generated for you. Nothing in Aperire creates a validator
# key: the key IS the validator, and it is made once, off this box, with the
# validator-keys tool, and its master key is kept somewhere this host cannot
# reach.
#
#   1. On a machine that is not this one, run validator-keys:
#        validator-keys create_keys
#        validator-keys create_token --keyfile <the key file>
#   2. Paste the four-line token block it prints below, uncommented.
#   3. chmod 0640 this file and keep it out of every backup that leaves the
#      host. Anything holding this token can sign as this validator.
#   4. Restart the node, and confirm with server_info that
#      pubkey_validator is the key you expect.
#
#[validator_token]
#eyJtYW5pZmVzdCI6IkpBQUFBQV...
#...
#...
#...
EOF
  chmod 0640 "$cfg"
  info "added the commented [validator_token] stanza and set the file 0640"
  warn "No validator key was generated, and none will be. Make it off this box"
  warn "with validator-keys, paste the token into ${cfg}, restart the node."
}

# Close the node's config to its owner and the node, on every run (#462).
#
# This installer writes rippled.cfg 0644 in a 0755 directory, and on a
# validator that file carries [validator_token] - the key the node signs
# with. Until now the only thing on the host that closed it was
# close-node-config-exposure.sh, which runs from the Advisor one-liner
# because the Advisor's account is the reader that needs a named entry. A
# host with a node and a dashboard and no Advisor never ran it, so the 0644
# stood for the life of the install and every local account could read the
# token. Seen on a lab node 2026-09-18; the after-reboot check reported it
# for a host nothing was going to fix.
#
# The ACL model is not repeated here, it is called. That script owns it: the
# group the node actually reads the file as, asked of the running node rather
# than assumed; the relay's named read entry when that relay parses the file
# for its ports; the Advisor's refusal on the directory when an Advisor
# account exists; passage through the directory for the accounts that need to
# reach the file through it; and a verify that puts every one of those back if
# the node stops being able to open its own configuration. A second copy of
# that reasoning here is a second copy to get wrong, and the first version of
# it cost a validator its next restart.
#
# Idempotent by construction. It re-reads the file each run, restores from a
# snapshot of what it found rather than from a list of entries it knows how to
# add, and a named entry an earlier run made survives a later one.
#
# Never fatal. It refuses to tighten anything it cannot prove the node still
# reads, and reverts itself if a check fails, so a failure here leaves the
# config exactly as it was and never half-applied. A node that came up is
# worth more than a run that ends red over a step that can be repeated by
# hand.
close_node_config() {  # $1 = the config file this run recorded
  local cfg="$1" closer="${SCRIPTS_DIR}/close-node-config-exposure.sh"
  local dir='' before='' after='' out='' rc=0
  dir="$(dirname "$cfg")"
  say "closing the node config to everyone else"
  if [[ ! -f "$closer" ]]; then
    warn "${closer} is not in this checkout, so the config was left as it is."
    warn "It is readable by every account on this host until that script runs."
    return 0
  fi
  # The directory's mode as well as the file's, because they do not always
  # move together: a config written 0640 by --role validator is already closed
  # as a file while its directory is still 0755, and reading the file alone
  # would report "already closed" about a run that took the directory down to
  # 0750. Two facts, one summary. One `%a` per file, not two: a format string
  # applies to every operand, so `'%a %a'` against two files printed each
  # mode twice, "644 644 755 755" (#462 P3-074).
  before="$(stat -c '%a' "$cfg" "$dir" 2>/dev/null | tr '\n' ' ' || true)"
  # `if`, not `|| true`: a non-zero status in a compound command is the one
  # shape `set -e` does not act on, and this step is deliberately not fatal.
  # The wrapper the closer reads the node back through: root's own copy when
  # there is one, the sibling (the staged copy, under get-aperire.sh) if not.
  local -a closer_env=()
  local cw
  cw="$(trusted_wrapper_path "${APERIRE_INSTANCE:-}")"
  if [[ -f "$cw" && ! -L "$cw" && "$(stat -c %u -- "$cw" 2>/dev/null)" == 0 ]]; then
    closer_env=( "APERIRE_CLOSER_WRAPPER=$cw" )
  fi
  if out="$(env ${closer_env[@]+"${closer_env[@]}"} bash "$closer" --apply 2>&1)"; then rc=0; else rc=$?; fi
  after="$(stat -c '%a' "$cfg" "$dir" 2>/dev/null | tr '\n' ' ' || true)"
  # Its own output, indented, rather than summarised away. It names the group
  # it chose, the accounts it granted and the node read it verified, and every
  # one of those is worth having in the install transcript.
  printf '%s\n' "$out" | sed 's/^/   | /'
  echo
  if [[ "$rc" -ne 0 ]]; then
    if [[ "$rc" -eq 2 ]]; then
      # The closer's own distinct code for "the revert itself did not take"
      # (#462 P2-072): the config may be left mutated, and this is exactly the
      # one case where "nothing was half-applied" would be a lie.
      warn "the config may be left PARTIALLY changed; the reason is in the lines above."
      warn "Check it by hand before trusting this host's permissions again:"
      warn "    sudo getfacl -p ${cfg} ${dir}"
    else
      warn "the config was left exactly as it was; the reason is in the lines above."
      warn "Nothing was half-applied. Once that is resolved:"
      warn "    curl -fsSL https://get.aperire.one | bash -s -- --run node-config-exposure --apply"
    fi
    return 0
  fi
  # What the paths say now, not what the run above claimed. Three answers, and
  # the third one is the one worth printing loudly: a run that reported success
  # over a file still open to everybody.
  local fmode='' ; fmode="$(stat -c '%a' "$cfg" 2>/dev/null || true)"
  if [[ -n "$before" && -n "$after" && "$before" != "$after" ]]; then
    info "${S_GREEN}closed: ${cfg} and its directory, ${before}-> ${after}${S_OFF}"
    info "${S_GREEN}        readable by you and by the node, by nobody else${S_OFF}"
  elif [[ -n "$fmode" && "${fmode: -1}" =~ [4567] ]]; then
    warn "${cfg} is still mode ${fmode}, which is readable by every account on this host."
    warn "    curl -fsSL https://get.aperire.one | bash -s -- --run node-config-exposure"
  else
    info "${S_GREEN}already closed: ${cfg} is mode ${fmode:-unreadable}, not open to other accounts${S_OFF}"
  fi
  return 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dir)         DIR="${2:?--dir needs a path}"; shift 2 ;;
    --dir=*)       DIR="${1#*=}"; shift ;;
    --name)        NAME="${2:?--name needs a name}"; ADOPT_NAME="$NAME"; shift 2 ;;
    --name=*)      NAME="${1#*=}"; ADOPT_NAME="$NAME"; shift ;;
    --adopt)       ADOPT=1; shift ;;
    --image-tag)   IMAGE_TAG="${2:?--image-tag needs a tag}"; shift 2 ;;
    --image-tag=*) IMAGE_TAG="${1#*=}"; shift ;;
    --role)        ROLE="${2:?--role needs stock or validator}"; shift 2 ;;
    --role=*)      ROLE="${1#*=}"; shift ;;
    --net)         NET="${2:?--net needs mainnet}"; shift 2 ;;
    --net=*)       NET="${1#*=}"; shift ;;
    --native)      NATIVE=1; shift ;;
    --move-source) MOVE_SOURCE=1; shift ;;
    --vendor-peer-port) NATIVE_KEEP_VENDOR_PEER_PORT=1; shift ;;
    --vendor-retention) NATIVE_ONLINE_DELETE=""; shift ;;
    --unit)        UNIT_OVERRIDE="${2:?--unit needs a systemd unit name}"; shift 2 ;;
    --unit=*)      UNIT_OVERRIDE="${1#*=}"; shift ;;
    --yes|-y)      ASSUME_YES=1; shift ;;
    -h|--help)     sed -n '2,140p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) die "unknown argument: $1 (try --help)" ;;
  esac
done

if [[ $EUID -ne 0 ]]; then
  if [[ $MOVE_SOURCE -eq 1 ]]; then
    die "run with sudo: it changes this host's package sources"
  fi
  if [[ $NATIVE -eq 1 ]]; then
    die "run with sudo: it adds a package repository, installs a package and configures the node's systemd unit"
  fi
  die "run with sudo: it installs packages, writes under ${DIR:-/home/<operator>/aperire-node} and starts a container"
fi
[[ "$OPERATOR" != "root" ]] \
  || die "run as a normal user with sudo, not as root itself: the node directory belongs to the operator's account"

case "$ROLE" in stock|validator) ;; *) die "--role must be stock or validator (got '$ROLE')" ;; esac
# Refused rather than accepted-and-ignored. A node started on the wrong network
# builds a store that has to be thrown away, and "it said mainnet" is exactly
# the sentence that gets believed.
[[ "$NET" == "mainnet" ]] \
  || die "--net supports mainnet only right now (got '$NET'). Nothing here writes a testnet or devnet config, and pretending otherwise would build a store on the wrong network"

# The name reaches a container name, a compose project name and a directory
# on the container path, and the fleet label alone on --native, and each of
# those has its own opinion about what a name is. This is the intersection.
[[ "$NAME" =~ ^[a-z0-9][a-z0-9._-]*$ ]] \
  || die "--name must start with a lowercase letter or digit and hold only lowercase letters, digits, dot, underscore or dash (got '$NAME')"

# ═════════════════════════════════════════════════════════════════════
# Native mode (#30). Adopt first, offer second - see the header for what
# each verb means. Everything below is only reached with --native.
# ═════════════════════════════════════════════════════════════════════

# The unit already there, by LoadState rather than ActiveState: a node that is
# installed and stopped is a different fact from one that was never here, and
# is-active alone cannot tell the two apart (see the systemd unit
# detection notes). --unit is the escape hatch for a fork whose
# unit name is not one of the three guessed here.
native_unit_loaded() {  # $1 = unit
  local ls
  ls="$(systemctl show -p LoadState --value "$1" 2>/dev/null)" || ls=''
  [[ "$ls" == "loaded" ]]
}

native_probe_unit() {
  local candidates=() u
  if [[ -n "$UNIT_OVERRIDE" ]]; then
    candidates=("$UNIT_OVERRIDE")
  else
    candidates=(xrpld.service rippled.service xahaud.service)
  fi
  for u in "${candidates[@]}"; do
    if native_unit_loaded "$u"; then
      NATIVE_UNIT="$u"
      return 0
    fi
  done
  return 1
}

# Reached only once native_probe_unit above has already said no native unit
# it knows how to adopt is loaded. That is not the same fact as "no node is
# running": a container node's own process is visible in the host's pid
# namespace under these same names, whatever its image is called (the same
# fact verify-after-restart.sh's node_seen() checks, #087, a security review
# 2026-09-18). Without this, --native reaching this far on a host that
# already runs a container node would add a vendor repository and offer to
# install a second, conflicting node beside a live one.
native_conflicting_node() {
  local c n
  if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    c=$(docker ps --format '{{.Names}} {{.Image}}' 2>/dev/null) || true
    # A container created from a digest shows an image ID; read its name back
    # (#896). A refused read is not "no node": this guard exists to stop a
    # second node going in beside a live one, so it says so and refuses.
    if ! c=$(docker_resolve_image_ids "$c"); then
      printf 'a container whose image docker would not name (%s)' "$c"
      return 0
    fi
    c=$(printf '%s\n' "$c" | grep -aiE 'rippled|xrpld|xahau' | awk 'NR==1{print $1}') || true
    if [[ -n "$c" ]]; then
      printf 'the container %s' "$c"
      return 0
    fi
  fi
  if command -v pgrep >/dev/null 2>&1; then
    for n in rippled xrpld xahaud xrpld-main rippled-main xahaud-main; do
      if pgrep -x "$n" >/dev/null 2>&1; then
        printf "the process '%s'" "$n"
        return 0
      fi
    done
  fi
  return 1
}

# What OS this is, read rather than assumed - and stubbable, the way
# ETC_APERIRE already is, so the test fixture never touches the real file.
#
# Read whole, then parsed, the same discipline native_add_repo_deb's candidate
# read follows and for the same reason: a `producer | reader that quits` is a
# 141 under `set -o pipefail` and a run that ends with nothing said (#411).
# An os-release carrying the key twice is all it would take here.
native_os_release() {
  OS_ID="" OS_VERSION_ID=""
  [[ -r "$OS_RELEASE_FILE" ]] || return 1
  local content line
  content="$(cat "$OS_RELEASE_FILE")" || return 1
  while IFS= read -r line; do
    case "$line" in
      ID=*)         [[ -n "$OS_ID" ]]         || OS_ID="${line#ID=}" ;;
      VERSION_ID=*) [[ -n "$OS_VERSION_ID" ]] || OS_VERSION_ID="${line#VERSION_ID=}" ;;
    esac
  done <<< "$content"
  OS_ID="${OS_ID//\"/}"
  OS_VERSION_ID="${OS_VERSION_ID//\"/}"
}

# The three combinations the vendor names, and nothing invented beyond them.
# All three are x86_64 only in the source this was read from, so an arm64 box
# on a supported distro is still refused: a package that does not exist there
# would otherwise fail at apt-get/dnf, with a worse message than this one.
native_offer_target() {
  local arch
  arch="$(uname -m 2>/dev/null || echo unknown)"
  native_os_release
  NATIVE_OS_DESC="${OS_ID:-an unrecognised OS}${OS_VERSION_ID:+ $OS_VERSION_ID} (${arch})"
  [[ "$arch" == "x86_64" ]] || return 1
  case "$OS_ID" in
    ubuntu)
      case "$OS_VERSION_ID" in
        22.04) NATIVE_PKG_KIND=deb ;;
        24.04) NATIVE_PKG_KIND=deb ;;
        *) return 1 ;;
      esac ;;
    debian)
      case "$OS_VERSION_ID" in
        12) NATIVE_PKG_KIND=deb ;;
        *) return 1 ;;
      esac ;;
    rhel)
      case "$OS_VERSION_ID" in
        9|9.*) NATIVE_PKG_KIND=rpm ;;
        *) return 1 ;;
      esac ;;
    *) return 1 ;;
  esac
  return 0
}

# A key=value line inside a named stanza, and a stanza whose value is the
# line under its own header - the two shapes rippled.cfg holds, and the same
# two readers install-node-wrapper.sh --native already proved.
native_cfg_kv() {  # $1=file $2=stanza $3=key
  awk -v s="$2" -v k="$3" '
    $0 ~ "^[[:space:]]*\\[" s "\\][[:space:]]*$" { insec=1; next }
    insec && $0 ~ /^[[:space:]]*\[/ { insec=0 }
    insec && $0 ~ "^[[:space:]]*" k "[[:space:]]*=" {
      sub(/^[^=]*=[[:space:]]*/, ""); sub(/[[:space:]]+$/, ""); print; exit
    }
  ' "$1" 2>/dev/null
}
native_cfg_line() {  # $1=file $2=stanza
  awk -v s="$2" '
    BEGIN { insec = 0 }
    $0 ~ "^[[:space:]]*\\[" s "\\][[:space:]]*$" { insec = 1; next }
    insec {
      if ($0 ~ /^[[:space:]]*$/ || $0 ~ /^[[:space:]]*#/) next
      if ($0 ~ /^[[:space:]]*\[/) exit
      sub(/^[[:space:]]+/, ""); sub(/[[:space:]]+$/, "")
      print; exit
    }
  ' "$1" 2>/dev/null
}

# The first value a key holds in a KEY=value file, or nothing. Used on the
# wrapper configuration this script has just written, and read whole rather
# than through `sed | head -1` for the reason above.
native_conf_value() {  # $1=file $2=key
  local content='' line
  [[ -r "$1" ]] || return 0
  content="$(cat "$1")" || return 0
  while IFS= read -r line; do
    if [[ "$line" == "$2="* ]]; then printf '%s' "${line#"$2"=}"; return 0; fi
  done <<< "$content"
  return 0
}

native_locate_cfg() {
  local p
  for p in "${NATIVE_CFG_CANDIDATES[@]}"; do
    [[ -f "$p" ]] && { printf '%s' "$p"; return 0; }
  done
  return 1
}

# Prerequisites for the apt path: wget to fetch the key, gnupg to dearmor it.
# Refresh every source on this host, and never die of it.
#
# Never the verdict. `apt-get update` returns non-zero when ANY source on
# this host fails, including ones this installer never touched, and a stale
# third-party repository somebody added a year ago is not a reason to refuse
# a node install (#410). What decides is whether the package installs.
#
# It cannot be skipped either, which is the half the first fix left open.
# apt can only resolve a package out of a list it has actually fetched: with
# the host's own lists stale or absent, the vendor install below cannot
# satisfy a single dependency from the host archives and answers "Unable to
# locate package" (measured against a real apt-get, 2026-09-17). The scoped
# refresh in native_add_repo_deb covers the vendor's list and deliberately
# touches nothing else, so this is the only thing that covers the rest.
native_apt_update_host() {
  apt-get update -qq \
    || warn "apt-get update reported a problem on this host. Carrying on: whether the packages install is the real answer."
  return 0
}

native_apt_prereqs() {
  command -v wget >/dev/null 2>&1 && command -v gpg >/dev/null 2>&1 && return 0
  export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l NEEDRESTART_SUSPEND=1
  native_apt_update_host
  apt-get install -y -qq --no-install-recommends apt-transport-https ca-certificates wget gnupg \
    || die "could not install the prerequisites this repository needs (apt-transport-https ca-certificates wget gnupg)"
}

# A key fetched over TLS is a key whatever answered that connection handed
# back — TLS proves the channel, not the content at the far end of it. The
# fingerprint in docs/install.md is the one fact that does not travel over
# the same wire this key did, so it is checked before anything trusts the
# file: a mismatch is refused here, before a sources file or a repo stanza
# ever names it (#655).
#
# CHECKING THE FIRST FINGERPRINT IN THE FILE IS NOT ENOUGH (review finding,
# 2026-09-30). A key file is a sequence of independent OpenPGP packets: one
# holding the real XRPLF key, matching the pin, followed by a second,
# attacker-controlled key, still passes a check that only ever reads the
# first `fpr:` line — and then the WHOLE FILE, both keys, becomes the
# `signed-by=` keyring apt trusts, or the whole file is what `rpm --import`
# adds to the RPM keyring. So this now demands the file hold EXACTLY ONE
# public key (never zero, never two or more, never a file carrying secret
# material), reads that one key's OWN fingerprint (the `fpr:` record that
# immediately follows its `pub:` line, before any `sub:` subkey line can
# reset which key a later `fpr:` belongs to), and only then checks it
# against the pin.
#
# AND THEN IT NEVER TRUSTS THE DOWNLOADED BYTES THEMSELVES. Passing the
# check proves the file CONTAINS the right key; it does not prove the file
# contains NOTHING ELSE gpg's own parser tolerates riding along in a form
# --show-keys happens to summarize the same way. So the pinned key is
# re-exported, by its own verified fingerprint, out of a throwaway
# $GNUPGHOME this run creates and deletes, and THAT export — not the
# original download — is what ever reaches a keyring or `rpm --import`.
#
# $1 the key file to verify (already fetched, or already on disk).
# $2 a label for the error.
# $3 where to write the clean, single-key, armoured re-export. Refused (and
#    nothing written to $3) unless every check above passes.
native_verified_xrplf_key() {
  local keyfile=$1 label=$2 out=$3
  command -v gpg >/dev/null 2>&1 || die "gpg is required to check the ${label} key and was not found"
  local info pubs secret fpr
  info="$(gpg --show-keys --with-colons "$keyfile" 2>/dev/null)" || info=""
  pubs=$(awk -F: '$1=="pub"{n++} END{print n+0}' <<<"$info")
  secret=$(awk -F: '$1=="sec" || $1=="ssb"{n++} END{print n+0}' <<<"$info")
  # The primary key's OWN fpr is the first `fpr:` record after its `pub:`
  # line; `mode` is cleared the instant a `sub:` line appears so a subkey's
  # fpr (which reads identically at field 1) is never mistaken for it, and
  # `f` latches on the first hit so a SECOND pub block's fpr cannot silently
  # overwrite the first one this check is actually judging.
  fpr=$(awk -F: '
    $1=="pub"{mode="pub"; next}
    $1=="sub"{mode="sub"; next}
    $1=="fpr" && mode=="pub" && f==""{f=$10}
    END{print f}
  ' <<<"$info")
  if [[ "$secret" -gt 0 ]]; then
    die "the ${label} key at ${keyfile} carries secret-key material; refusing to trust it"
  fi
  if [[ "$pubs" -ne 1 ]]; then
    die "the ${label} key at ${keyfile} holds ${pubs} public keys, not exactly one.
   A key file with more than one key becomes a keyring trusting all of them, and one with
   none at all is not a key. Nothing was trusted and nothing was written."
  fi
  [[ -n "$fpr" ]] || die "could not read a fingerprint out of the ${label} key at ${keyfile}; refusing to trust it"
  [[ "$fpr" == "$NATIVE_XRPLF_KEY_FINGERPRINT" ]] \
    || die "the ${label} key's fingerprint does not match the one docs/install.md names.
   expected: ${NATIVE_XRPLF_KEY_FINGERPRINT}
   got:      ${fpr}
   Nothing was trusted and nothing was written. Remove ${keyfile} and re-run once this is understood."

  local gnupg_tmp
  gnupg_tmp="$(mktemp -d)"
  chmod 700 "$gnupg_tmp"
  if ! GNUPGHOME="$gnupg_tmp" gpg --batch --quiet --import "$keyfile" >/dev/null 2>&1; then
    rm -rf "$gnupg_tmp"
    die "the ${label} key passed its fingerprint check but could not be imported into a scratch keyring for re-export"
  fi
  GNUPGHOME="$gnupg_tmp" gpg --batch --quiet --armor --export "$NATIVE_XRPLF_KEY_FINGERPRINT" > "$out" 2>/dev/null
  rm -rf "$gnupg_tmp"
  [[ -s "$out" ]] || die "re-exporting the verified ${label} key produced nothing; refusing to trust it"
}

# A host that installed natively before #655 has a repository and a keyring
# this installer wrote pointed at the retired repos.ripple.com, which never
# carries 3.4.0 or later. Left in place they cost nothing on their own (apt
# only resolves what a sources file names), but a host with both the old and
# the new source configured for one package name is a host where "which one
# actually installed" stops being obvious.
#
# Retired only when the content is EXACTLY what this installer wrote (#802).
# The check used to be "the file mentions repos.ripple.com", which is also
# true of a file an operator wrote by hand with a pin, a mirror or a comment
# in it, and that file was deleted on the strength of one substring. Every
# release before #655 wrote one shape: a single line, this keyring, this
# URL, one of the three codenames it mapped, "stable". The vendor's own old
# instructions wrote the same line, so a file that matches is retired
# whoever typed it. Anything else is kept and named.
#
# Prints nothing; answers 0 for "ours", 1 for anything else.
native_legacy_deb_is_ours() {
  [[ -f "$NATIVE_LEGACY_DEB_SOURCES_LIST" && ! -L "$NATIVE_LEGACY_DEB_SOURCES_LIST" ]] || return 1
  local body line n=0 match codename
  body="$(cat "$NATIVE_LEGACY_DEB_SOURCES_LIST" 2>/dev/null)" || return 1
  while IFS= read -r line; do
    [[ -n "${line//[[:space:]]/}" ]] || continue
    n=$((n + 1))
    match=0
    for codename in jammy noble bookworm; do
      [[ "$line" == "deb [signed-by=${NATIVE_LEGACY_DEB_KEYRING}] ${NATIVE_LEGACY_DEB_REPO_URL} ${codename} stable" ]] && match=1
    done
    (( match )) || return 1
  done <<< "$body"
  (( n == 1 ))
}

# Whether any apt source still on this host names the legacy keyring. The
# keyring goes only when nothing does: a source the operator kept (above) may
# be signed by it, and removing its key turns that source into an apt error
# on every update. Both shapes apt reads: one-line .list files and deb822
# .sources files, plus the main sources.list.
native_legacy_keyring_in_use() {
  local f
  for f in "$NATIVE_APT_MAIN_LIST" "$NATIVE_APT_SOURCES_DIR"/*.list "$NATIVE_APT_SOURCES_DIR"/*.sources; do
    [[ -f "$f" ]] || continue
    grep -qF -- "$NATIVE_LEGACY_DEB_KEYRING" "$f" 2>/dev/null && return 0
  done
  return 1
}

# Retires the legacy apt source when it is ours, keeps and names it when it
# is not.
native_retire_legacy_repo_deb() {
  local retired=0
  if [[ -e "$NATIVE_LEGACY_DEB_SOURCES_LIST" ]]; then
    if native_legacy_deb_is_ours; then
      rm -f "$NATIVE_LEGACY_DEB_SOURCES_LIST"
      retired=1
      info "removed the retired ${NATIVE_LEGACY_DEB_SOURCES_LIST} (repos.ripple.com never carries 3.4.0+)"
    else
      warn "kept ${NATIVE_LEGACY_DEB_SOURCES_LIST}: it is not the one line this installer wrote, so it is yours and this run does not remove it."
      if grep -qF 'repos.ripple.com' "$NATIVE_LEGACY_DEB_SOURCES_LIST" 2>/dev/null; then
        warn "It names repos.ripple.com, which stopped at 3.3.0. Once packages.xrplf.org is in place, remove it yourself:"
        warn "    sudo rm ${NATIVE_LEGACY_DEB_SOURCES_LIST}"
      fi
    fi
  fi
  # The keyring only when its own list went in this run, and nothing left on
  # the host still names it. An `if` rather than `&&`, so a false test is
  # never this function's exit status under set -e.
  if (( retired )) && [[ -f "$NATIVE_LEGACY_DEB_KEYRING" ]]; then
    if native_legacy_keyring_in_use; then
      info "kept ${NATIVE_LEGACY_DEB_KEYRING}: another apt source on this host still names it"
    else
      rm -f "$NATIVE_LEGACY_DEB_KEYRING"
      info "removed the retired signing key ${NATIVE_LEGACY_DEB_KEYRING}"
    fi
  fi
  return 0
}

# The signing key for packages.xrplf.org, fingerprint-checked and re-exported
# clean into NATIVE_DEB_KEYRING whether it is already on disk or fetched now.
# Shared by the install and by the source move, so there is one path a key
# takes to being trusted, never two.
native_install_xrplf_key_deb() {
  install -d -m 0755 "$(dirname "$NATIVE_DEB_KEYRING")"
  if [[ -f "$NATIVE_DEB_KEYRING" ]]; then
    # Re-verified and re-exported on every run too, not left alone: a file
    # that reached this path before this check existed, or was ever edited
    # on the host, gets the same "exactly one key, and it is re-exported
    # clean" treatment a fresh fetch gets, rather than being trusted because
    # it is merely present.
    local cleankey; cleankey="$(mktemp)"; SCRAPS+=("$cleankey")
    native_verified_xrplf_key "$NATIVE_DEB_KEYRING" "existing apt" "$cleankey"
    install -m 0644 "$cleankey" "$NATIVE_DEB_KEYRING"
    scrap_rm "$cleankey"
    have "the signing key is already at ${NATIVE_DEB_KEYRING}"
  else
    local tmpkey; tmpkey="$(mktemp)"; SCRAPS+=("$tmpkey")
    wget -qO "$tmpkey" "$NATIVE_DEB_KEY_URL" || { scrap_rm "$tmpkey"; die "could not fetch the signing key from ${NATIVE_DEB_KEY_URL}"; }
    local cleankey; cleankey="$(mktemp)"; SCRAPS+=("$cleankey")
    native_verified_xrplf_key "$tmpkey" "downloaded apt" "$cleankey"
    scrap_rm "$tmpkey"
    # install.md's own apt line takes the armoured key file directly with
    # signed-by=; the re-export above is already armoured and holds exactly
    # the one pinned key, nothing riding along from the download.
    install -m 0644 "$cleankey" "$NATIVE_DEB_KEYRING"
    scrap_rm "$cleankey"
    info "verified and installed the signing key to ${NATIVE_DEB_KEYRING}"
  fi
}

# The one line apt reads packages.xrplf.org from.
native_xrplf_deb_line() {
  printf 'deb [signed-by=%s] %s any main' "$NATIVE_DEB_KEYRING" "$NATIVE_DEB_REPO_URL"
}

native_write_xrplf_list_deb() {
  local line; line="$(native_xrplf_deb_line)"
  if [[ -f "$NATIVE_DEB_SOURCES_LIST" ]] && grep -qF -e "$line" "$NATIVE_DEB_SOURCES_LIST"; then
    have "${NATIVE_DEB_SOURCES_LIST} already names this repository"
  else
    printf '%s\n' "$line" > "$NATIVE_DEB_SOURCES_LIST"
    info "wrote ${NATIVE_DEB_SOURCES_LIST}"
  fi
}

# The refresh of the list this installer writes, and only that one. A bare
# update takes every source on the host as its own precondition, which is
# not this installer's business and is not something it can fix (#410).
native_apt_update_xrplf() {
  local update_rc=0
  apt-get update -qq \
    -o Dir::Etc::sourcelist="$NATIVE_DEB_SOURCES_LIST" \
    -o Dir::Etc::sourceparts=- \
    -o APT::Get::List-Cleanup=0 || update_rc=$?
  (( update_rc == 0 )) \
    || warn "apt-get update returned ${update_rc} for ${NATIVE_DEB_SOURCES_LIST}. Asking apt what it can install anyway."
  return 0
}

# What apt would install for the package now, into NATIVE_APT_CANDIDATE
# (empty for none), with the whole answer kept in APT_POLICY for a refusal.
# Globals rather than printed, so a caller never reads it through $( ) and
# loses the second one. Read to the end, then parsed, with no pipe anywhere:
# an awk that quits on the line it wants leaves apt-cache writing into a
# closed pipe, and under `set -o pipefail` that SIGPIPE ended the whole run
# with status 141 and no message at all, on every deb host (#411).
APT_POLICY=""
NATIVE_APT_CANDIDATE=""
native_apt_candidate() {
  local line
  NATIVE_APT_CANDIDATE=''
  APT_POLICY="$(apt-cache policy "$NATIVE_PACKAGE" 2>/dev/null)" || APT_POLICY=''
  while IFS= read -r line; do
    case "$line" in
      *Candidate:*) NATIVE_APT_CANDIDATE="${line#*Candidate:}"; NATIVE_APT_CANDIDATE="${NATIVE_APT_CANDIDATE//[[:space:]]/}"; break ;;
    esac
  done <<< "$APT_POLICY"
  [[ "$NATIVE_APT_CANDIDATE" == "(none)" ]] && NATIVE_APT_CANDIDATE=''
  return 0
}

# Source: XRPLF/rippled docs/install.md, "With the APT package manager",
# read 2026-09-30.
native_add_repo_deb() {
  say "vendor repository (apt)"
  native_apt_prereqs
  native_retire_legacy_repo_deb
  native_install_xrplf_key_deb
  native_write_xrplf_list_deb
  export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l NEEDRESTART_SUSPEND=1
  # The host's own lists first, and never fatally. native_apt_prereqs runs
  # this too, but it returns early whenever wget and gnupg are already here,
  # which is the common case on a cloud image, so on most hosts nothing had
  # refreshed them at all and the install below was resolving dependencies
  # out of whatever was already on disk. Skipping #410's scoped refresh is
  # not what fixes that; running this as well is.
  native_apt_update_host
  # Then the list this installer just wrote, and only that one.
  native_apt_update_xrplf
  native_apt_candidate
  [[ -n "$NATIVE_APT_CANDIDATE" ]] \
    || die "apt has no installable ${NATIVE_PACKAGE} after adding the repository. Check ${NATIVE_DEB_SOURCES_LIST} and ${NATIVE_DEB_KEYRING}${APT_POLICY:+
   apt-cache policy ${NATIVE_PACKAGE} said:
${APT_POLICY}}"
  info "apt offers ${NATIVE_PACKAGE} ${NATIVE_APT_CANDIDATE}"
}

# A host that installed natively before #655 has a repository file naming
# the retired repos.ripple.com. The same rule the apt half follows (#802):
# retired only when the file is byte for byte the stanza every release
# before #655 wrote, kept and named otherwise.
native_legacy_rpm_stanza() {
  printf '%s\n' \
    '[ripple-stable]' \
    'name=XRP Ledger Packages' \
    'enabled=1' \
    'gpgcheck=0' \
    'repo_gpgcheck=1' \
    "baseurl=${NATIVE_LEGACY_RPM_REPO_URL}" \
    "gpgkey=${NATIVE_LEGACY_RPM_KEY_URL}"
}
native_legacy_rpm_is_ours() {
  [[ -f "$NATIVE_LEGACY_RPM_REPO_FILE" && ! -L "$NATIVE_LEGACY_RPM_REPO_FILE" ]] || return 1
  cmp -s "$NATIVE_LEGACY_RPM_REPO_FILE" <(native_legacy_rpm_stanza)
}
native_retire_legacy_repo_rpm() {
  [[ -e "$NATIVE_LEGACY_RPM_REPO_FILE" ]] || return 0
  if native_legacy_rpm_is_ours; then
    rm -f "$NATIVE_LEGACY_RPM_REPO_FILE"
    info "removed the retired ${NATIVE_LEGACY_RPM_REPO_FILE} (repos.ripple.com never carries 3.4.0+)"
  else
    warn "kept ${NATIVE_LEGACY_RPM_REPO_FILE}: it is not the stanza this installer wrote, so it is yours and this run does not remove it."
    if grep -qF 'repos.ripple.com' "$NATIVE_LEGACY_RPM_REPO_FILE" 2>/dev/null; then
      warn "It names repos.ripple.com, which stopped at 3.3.0. Once packages.xrplf.org is in place, remove it yourself:"
      warn "    sudo rm ${NATIVE_LEGACY_RPM_REPO_FILE}"
    fi
  fi
  return 0
}

# The key and the repo file for packages.xrplf.org on dnf, shared by the
# install and the source move. The key is checked here, ahead of `rpm
# --import` and ahead of gpgcheck ever running against a real package: rpm
# has already trusted it once the repo file names it with gpgcheck=1, and
# #655's own report is that a key fetched from this URL is worth verifying
# independently of whatever fetched it (same reasoning as the apt path).
native_install_xrplf_key_rpm() {
  command -v curl >/dev/null 2>&1 || die "curl is required to fetch the signing key and was not found"
  local tmpkey; tmpkey="$(mktemp)"; SCRAPS+=("$tmpkey")
  curl -fsSL "$NATIVE_RPM_KEY_URL" -o "$tmpkey" || { scrap_rm "$tmpkey"; die "could not fetch the signing key from ${NATIVE_RPM_KEY_URL}"; }
  local cleankey; cleankey="$(mktemp)"; SCRAPS+=("$cleankey")
  native_verified_xrplf_key "$tmpkey" "downloaded dnf" "$cleankey"
  scrap_rm "$tmpkey"
  # rpm --import gets the re-exported, single-key file, never the raw
  # download: the same "prove the file holds nothing else" step the apt
  # path takes, because rpm --import trusts every key a file carries too.
  rpm --import "$cleankey" || { scrap_rm "$cleankey"; die "rpm --import refused the verified key at ${NATIVE_RPM_KEY_URL}"; }
  scrap_rm "$cleankey"
  info "verified and imported the signing key from ${NATIVE_RPM_KEY_URL}"
}
native_write_xrplf_repo_rpm() {
  if [[ -f "$NATIVE_RPM_REPO_FILE" ]] && grep -qF -e "$NATIVE_RPM_REPO_URL" "$NATIVE_RPM_REPO_FILE"; then
    have "${NATIVE_RPM_REPO_FILE} already names this repository"
  else
    cat > "$NATIVE_RPM_REPO_FILE" <<EOF
[xrplf-stable]
name=XRP Ledger Packages
enabled=1
gpgcheck=1
repo_gpgcheck=1
baseurl=${NATIVE_RPM_REPO_URL}
gpgkey=${NATIVE_RPM_KEY_URL}
EOF
    info "wrote ${NATIVE_RPM_REPO_FILE}"
  fi
}

# Source: XRPLF/rippled docs/install.md, "With the DNF package manager",
# read 2026-09-30.
native_add_repo_rpm() {
  say "vendor repository (dnf)"
  native_retire_legacy_repo_rpm
  command -v gpg >/dev/null 2>&1 || dnf install -y gnupg2 \
    || die "could not install gnupg2, needed to check the signing key's fingerprint before it is trusted"
  native_install_xrplf_key_rpm
  native_write_xrplf_repo_rpm
  dnf -y makecache \
    || die "dnf makecache failed after adding ${NATIVE_RPM_REPO_FILE}; check the repository and key it names"
  dnf list available "$NATIVE_PACKAGE" >/dev/null 2>&1 \
    || die "dnf has no installable ${NATIVE_PACKAGE} after adding the repository. Check ${NATIVE_RPM_REPO_FILE}"
  info "dnf offers ${NATIVE_PACKAGE}"
}

# ── Moving an installed host's source (#802) ─────────────────────────────
#
# #655 moved the install onto packages.xrplf.org, and only the install: a
# native host that installed before it kept repos.ripple.com through every
# adopt and every update, so `apt-cache policy xrpld` there stopped at 3.3.0
# and the Advisor, asking this host's own repositories, called 3.3.0 the
# newest release. After fixBatchV1_2 activates that node is amendment
# blocked while the Advisor says it is current.
#
# This is the fix for a host already installed, and it is deliberately
# smaller than an install: the new key (the same fingerprint check), the new
# source, the old one retired when it is ours, one refresh of the new list.
# No package is installed or upgraded, the node is not restarted, its config
# is not read. The upgrade itself stays the operator's to approve.

# Whether the package is installed, by the package database's own status:
# dpkg-query exits 0 for a package it merely KNOWS (removed, config left
# behind), so the status is read rather than the exit code, the way the
# node wrapper reads it.
native_pkg_installed() {
  case "$NATIVE_PKG_KIND" in
    deb)
      local st
      st="$(dpkg-query -W -f='${db:Status-Status} ${Version}' "$NATIVE_PACKAGE" 2>/dev/null)" || return 1
      [[ "$st" == "installed "* ]] || return 1
      NATIVE_INSTALLED_VERSION="${st#installed }" ;;
    rpm)
      NATIVE_INSTALLED_VERSION="$(rpm -q --queryformat '%{VERSION}-%{RELEASE}' "$NATIVE_PACKAGE" 2>/dev/null)" || return 1
      [[ -n "$NATIVE_INSTALLED_VERSION" ]] || return 1 ;;
    *) return 1 ;;
  esac
}

native_move_source_main() {
  say "the package source for ${NATIVE_PACKAGE}"
  if ! native_offer_target; then
    info "no vendor repository is named for ${NATIVE_OS_DESC}, so there is no source here to move"
    return 0
  fi
  if ! native_pkg_installed; then
    info "${NATIVE_PACKAGE} is not installed from a package on this host, so there is no source here to move"
    return 0
  fi
  case "$NATIVE_PKG_KIND" in
    deb) native_move_source_deb ;;
    rpm) native_move_source_rpm ;;
  esac
  info "nothing was installed, upgraded or restarted: ${NATIVE_PACKAGE} stays at ${NATIVE_INSTALLED_VERSION} until you upgrade it"
}

# Is this URL the retired repository? One rule, kept byte for byte the same
# in scripts/aperire-node-wrapper.sh, and the installer's suite holds the two
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

# Where apt says the package comes from now: one repository URL per line,
# the third field of `apt-cache madison`, read whole and then parsed (#411).
# A read; nothing is refreshed to answer it.
native_xrpld_sources_deb() {
  local raw line url
  raw="$(apt-cache madison "$NATIVE_PACKAGE" 2>/dev/null)" || raw=''
  while IFS= read -r line; do
    [[ "$line" == *"|"*"|"* ]] || continue
    url="${line#*|}"; url="${url#*|}"
    read -r url _ <<< "$url"
    [[ -n "$url" ]] && printf '%s\n' "$url"
  done <<< "$raw"
  return 0
}

# Which of four situations this host is in, for the apt half:
#   legacy   the file this installer wrote before #655 (or any file at that
#            path) is here, or every source offering the package is
#            repos.ripple.com: move
#   current  packages.xrplf.org is already this installer's own source
#   other    the package comes from somewhere else the operator chose
#   none     no source offers it at all (a .deb installed by hand)
NATIVE_SOURCE_STATE=""
NATIVE_SOURCE_SEEN=""
native_source_state_deb() {
  NATIVE_SOURCE_SEEN=""
  if native_legacy_deb_is_ours; then NATIVE_SOURCE_STATE=legacy; return 0; fi
  if [[ -f "$NATIVE_DEB_KEYRING" && -f "$NATIVE_DEB_SOURCES_LIST" ]] \
     && grep -qF -e "$(native_xrplf_deb_line)" "$NATIVE_DEB_SOURCES_LIST"; then
    NATIVE_SOURCE_STATE=current; return 0
  fi
  if [[ -e "$NATIVE_LEGACY_DEB_SOURCES_LIST" ]] \
     && grep -qF 'repos.ripple.com' "$NATIVE_LEGACY_DEB_SOURCES_LIST" 2>/dev/null; then
    NATIVE_SOURCE_STATE=legacy; return 0
  fi
  local urls u retired=1
  urls="$(native_xrpld_sources_deb)"
  if [[ -z "$urls" ]]; then NATIVE_SOURCE_STATE=none; return 0; fi
  while IFS= read -r u; do
    aperire_retired_source_url "$u" || retired=0
  done <<< "$urls"
  NATIVE_SOURCE_SEEN="$(sort -u <<< "$urls" | tr '\n' ' ')"
  if (( retired )); then NATIVE_SOURCE_STATE=legacy; else NATIVE_SOURCE_STATE=other; fi
  return 0
}

# Keeps the installed package where the node wrapper's package-keep keeps
# it, in exactly package-keep's form: <dir>/<pkg>.kept.<version>.<deb|rpm>
# beside a "<sha256>  <name>" sidecar, so the wrapper's package-kept lists
# it and its package-install --from accepts it. Run while the old
# repository is still configured, because packages.xrplf.org carries only
# 3.4.0 and later: once repos.ripple.com is gone, a 3.3.0 that was not kept
# here or still in the package cache has nowhere to come back from (#802).
#
# The artefact is read back before it is believed: its own package name and
# version must be the installed ones. Answers 0 when a verified copy is
# kept (now or before), 1 with the reason said when it is not.
native_keep_installed_package() {
  local version="$NATIVE_INSTALLED_VERSION" ext raw='' dest sidecar tmp_dl got sum
  [[ "$version" =~ ^[A-Za-z0-9.:_+~-]+$ ]] || { warn "could not keep ${NATIVE_PACKAGE} '${version}': unexpected characters in the version"; return 1; }
  case "$version" in
    *:*) warn "could not keep ${NATIVE_PACKAGE} ${version}: an epoch version does not round-trip through the wrapper's file naming"; return 1 ;;
  esac
  ext="$NATIVE_PKG_KIND"
  [[ -d "$NATIVE_PACKAGE_KEEP_DIR" ]] || install -d -m 0755 "$NATIVE_PACKAGE_KEEP_DIR" \
    || { warn "could not create ${NATIVE_PACKAGE_KEEP_DIR} to keep the installed package in"; return 1; }
  dest="${NATIVE_PACKAGE_KEEP_DIR}/${NATIVE_PACKAGE}.kept.${version}.${ext}"
  sidecar="${dest}.sha256"
  if [[ -f "$dest" ]]; then
    if [[ -f "$sidecar" && "$(awk '{print $1}' "$sidecar")" == "$(sha256sum "$dest" | cut -d' ' -f1)" ]]; then
      have "${NATIVE_PACKAGE} ${version} is kept at ${dest}"
      return 0
    fi
    warn "${dest} exists and its recorded sha256 does not match it; it was left alone and nothing new was kept"
    return 1
  fi
  tmp_dl="${NATIVE_PACKAGE_KEEP_DIR}/.${NATIVE_PACKAGE}.kept.${version}.$$"
  install -d -m 0755 "$tmp_dl"
  case "$NATIVE_PKG_KIND" in
    deb)
      # The exit code is not trusted, the wrapper's own reasoning: apt's drop
      # to _apt is noisy and version dependent. Whether a .deb landed is.
      (cd "$tmp_dl" && apt-get download "${NATIVE_PACKAGE}=${version}") >/dev/null 2>&1 || true
      raw=$(find "$tmp_dl" -maxdepth 1 -name '*.deb' -print -quit)
      [[ -n "$raw" ]] || raw=$(find "$NATIVE_APT_CACHE_DIR" -maxdepth 1 -name "${NATIVE_PACKAGE}_${version}_*.deb" -print -quit 2>/dev/null || true)
      # shellcheck disable=SC2016  # dpkg-deb's own ${Package} fields, not the shell's
      [[ -n "$raw" ]] && got="$(dpkg-deb --show --showformat='${Package} ${Version}' "$raw" 2>/dev/null || true)" ;;
    rpm)
      (dnf download --destdir "$tmp_dl" "${NATIVE_PACKAGE}-${version}") >/dev/null 2>&1 || true
      raw=$(find "$tmp_dl" -maxdepth 1 -name '*.rpm' -print -quit)
      [[ -n "$raw" ]] || raw=$(find "$NATIVE_DNF_CACHE_DIR" -maxdepth 4 -name "${NATIVE_PACKAGE}-${version}.*.rpm" -print -quit 2>/dev/null || true)
      [[ -n "$raw" ]] && got="$(rpm -qp --queryformat '%{NAME} %{VERSION}-%{RELEASE}' "$raw" 2>/dev/null || true)" ;;
  esac
  if [[ -z "$raw" ]]; then
    rm -rf "$tmp_dl"
    warn "could not get the installed ${NATIVE_PACKAGE} ${version} from the old repository or this host's package cache, so it was not kept"
    return 1
  fi
  if [[ "${got:-}" != "${NATIVE_PACKAGE} ${version}" ]]; then
    rm -rf "$tmp_dl"
    warn "the package fetched to keep says it is '${got:-unreadable}', not ${NATIVE_PACKAGE} ${version}; it was not kept"
    return 1
  fi
  cp -a "$raw" "$dest"
  rm -rf "$tmp_dl"
  [[ -s "$dest" ]] || { rm -f "$dest"; warn "the kept copy at ${dest} is empty; nothing was kept"; return 1; }
  sum=$(sha256sum "$dest" | cut -d' ' -f1)
  printf '%s  %s\n' "$sum" "$(basename "$dest")" > "$sidecar"
  [[ "$(sha256sum "$dest" | cut -d' ' -f1)" == "$sum" ]] || { warn "the kept copy changed while its sha256 was recorded"; return 1; }
  info "kept the installed ${NATIVE_PACKAGE} ${version} at ${dest} (sha256 ${sum:0:12}...), so a rollback to it still has somewhere to come from"
  return 0
}

# What the new repository offers, after its refresh: at least one version
# whose source is packages.xrplf.org. apt's Candidate alone would not do,
# because with the old source still configured it can be 3.3.0 from there.
native_xrplf_offers_deb() {
  local u
  while IFS= read -r u; do
    [[ "$u" == *"://packages.xrplf.org/"* ]] && return 0
  done <<< "$(native_xrpld_sources_deb)"
  return 1
}

native_move_source_deb() {
  native_source_state_deb
  case "$NATIVE_SOURCE_STATE" in
    current)
      # Present is not trusted: the key on disk gets the same exactly-one-key,
      # pinned-fingerprint check and clean re-export a fresh fetch gets.
      native_install_xrplf_key_deb
      have "${NATIVE_DEB_SOURCES_LIST} already names packages.xrplf.org; nothing to move"
      # A kept file is said again, because it is still there and still names
      # a repository that stopped at 3.3.0. Nothing is changed either way.
      [[ -e "$NATIVE_LEGACY_DEB_SOURCES_LIST" ]] && native_retire_legacy_repo_deb
      return 0 ;;
    other)
      info "${NATIVE_PACKAGE} comes from ${NATIVE_SOURCE_SEEN% }, not the retired repos.ripple.com; nothing to move"
      return 0 ;;
    none)
      info "no apt source on this host offers ${NATIVE_PACKAGE}, so there is no source to move; nothing was changed"
      return 0 ;;
  esac
  # Refused by name rather than installed: the move adds no package to this
  # host, prerequisites included.
  if ! command -v wget >/dev/null 2>&1 || ! command -v gpg >/dev/null 2>&1; then
    die "moving the source needs wget and gpg, and this host is missing one of them. Nothing was changed.
   Install them, then run this again:
     sudo apt-get install wget gnupg"
  fi
  # In this order, and each step gates the next:
  #   1. keep the installed package, while the old repository can still
  #      hand it over: packages.xrplf.org never carries 3.3.0
  #   2. the new key (fingerprint checked) and the new source
  #   3. refresh the new source alone, and require that it offers the package
  #   4. only then retire the old source, and only if step 1 kept a copy
  # A failure anywhere leaves the old source in place and says what failed.
  local kept=0
  if native_legacy_deb_is_ours; then
    native_keep_installed_package && kept=1
  fi
  native_install_xrplf_key_deb
  native_write_xrplf_list_deb
  native_apt_update_xrplf
  if ! native_xrplf_offers_deb; then
    die "packages.xrplf.org offered no ${NATIVE_PACKAGE} after its refresh, so the old source was left in place and this host still has one.
   ${NATIVE_DEB_SOURCES_LIST} is written; check this host can reach packages.xrplf.org, then run the update, which moves the source again:
     curl -fsSL https://get.aperire.one | bash -s -- --update --force"
  fi
  if (( kept )); then
    native_retire_legacy_repo_deb
  elif [[ -e "$NATIVE_LEGACY_DEB_SOURCES_LIST" ]] && native_legacy_deb_is_ours; then
    warn "kept ${NATIVE_LEGACY_DEB_SOURCES_LIST}: the installed ${NATIVE_PACKAGE} ${NATIVE_INSTALLED_VERSION} could not be kept (above), and that repository is the only place it can come back from."
    warn "Once a copy is kept (the Advisor's upgrade keeps one, or sudo apt-get download ${NATIVE_PACKAGE}=${NATIVE_INSTALLED_VERSION}), run this again to retire it."
  else
    native_retire_legacy_repo_deb
  fi
  native_apt_candidate
  if [[ -n "$NATIVE_APT_CANDIDATE" ]]; then
    info "apt now offers ${NATIVE_PACKAGE} ${NATIVE_APT_CANDIDATE}"
  else
    warn "apt names no installable ${NATIVE_PACKAGE} after the refresh. Check ${NATIVE_DEB_SOURCES_LIST} and ${NATIVE_DEB_KEYRING}"
  fi
}

# The rpm half of the same read: the download location of every xrpld dnf
# offers, which names the repository it would come from.
native_xrpld_sources_rpm() {
  local raw
  raw="$(dnf --quiet repoquery --location "$NATIVE_PACKAGE" 2>/dev/null)" || raw=''
  printf '%s' "$raw" | grep -v '^$' || true
}

native_source_state_rpm() {
  NATIVE_SOURCE_SEEN=""
  if native_legacy_rpm_is_ours; then NATIVE_SOURCE_STATE=legacy; return 0; fi
  if [[ -f "$NATIVE_RPM_REPO_FILE" ]] && grep -qF -e "$NATIVE_RPM_REPO_URL" "$NATIVE_RPM_REPO_FILE"; then
    NATIVE_SOURCE_STATE=current; return 0
  fi
  if [[ -e "$NATIVE_LEGACY_RPM_REPO_FILE" ]] \
     && grep -qF 'repos.ripple.com' "$NATIVE_LEGACY_RPM_REPO_FILE" 2>/dev/null; then
    NATIVE_SOURCE_STATE=legacy; return 0
  fi
  local urls u rest hosts='' retired=1
  urls="$(native_xrpld_sources_rpm)"
  if [[ -z "$urls" ]]; then NATIVE_SOURCE_STATE=none; return 0; fi
  while IFS= read -r u; do
    aperire_retired_source_url "$u" || retired=0
    # Scheme and host only: a download URL per package says nothing more.
    rest="${u#*://}"
    hosts+="${u%%://*}://${rest%%/*}"$'\n'
  done <<< "$urls"
  NATIVE_SOURCE_SEEN="$(sort -u <<< "$hosts" | grep -v '^$' | tr '\n' ' ')" || NATIVE_SOURCE_SEEN=''
  if (( retired )); then NATIVE_SOURCE_STATE=legacy; else NATIVE_SOURCE_STATE=other; fi
  return 0
}

native_move_source_rpm() {
  native_source_state_rpm
  case "$NATIVE_SOURCE_STATE" in
    current)
      have "${NATIVE_RPM_REPO_FILE} already names packages.xrplf.org; nothing to move"
      [[ -e "$NATIVE_LEGACY_RPM_REPO_FILE" ]] && native_retire_legacy_repo_rpm
      return 0 ;;
    other)
      info "${NATIVE_PACKAGE} comes from ${NATIVE_SOURCE_SEEN% }, not the retired repos.ripple.com; nothing to move"
      return 0 ;;
    none)
      info "no dnf repository on this host offers ${NATIVE_PACKAGE}, so there is no source to move; nothing was changed"
      return 0 ;;
  esac
  if ! command -v curl >/dev/null 2>&1 || ! command -v gpg >/dev/null 2>&1; then
    die "moving the source needs curl and gpg, and this host is missing one of them. Nothing was changed.
   Install them, then run this again:
     sudo dnf install curl gnupg2"
  fi
  # The same order and the same gates as the apt half.
  local kept=0
  if native_legacy_rpm_is_ours; then
    native_keep_installed_package && kept=1
  fi
  native_install_xrplf_key_rpm
  native_write_xrplf_repo_rpm
  # The new repository's metadata and nothing else's, for the reason the apt
  # half scopes its refresh (#410), and it has to offer the package.
  local offered=''
  if dnf -y makecache --disablerepo='*' --enablerepo=xrplf-stable >/dev/null; then
    offered="$(dnf --quiet repoquery --disablerepo='*' --enablerepo=xrplf-stable "$NATIVE_PACKAGE" 2>/dev/null || true)"
  fi
  if [[ -z "${offered//[[:space:]]/}" ]]; then
    die "packages.xrplf.org offered no ${NATIVE_PACKAGE} after its refresh, so the old repository was left in place and this host still has one.
   ${NATIVE_RPM_REPO_FILE} is written; check this host can reach packages.xrplf.org, then run the update, which moves the source again:
     curl -fsSL https://get.aperire.one | bash -s -- --update --force"
  fi
  info "dnf refreshed packages.xrplf.org, which offers ${NATIVE_PACKAGE}"
  if (( kept )); then
    native_retire_legacy_repo_rpm
  elif native_legacy_rpm_is_ours; then
    warn "kept ${NATIVE_LEGACY_RPM_REPO_FILE}: the installed ${NATIVE_PACKAGE} ${NATIVE_INSTALLED_VERSION} could not be kept (above), and that repository is the only place it can come back from."
    warn "Once a copy is kept (the Advisor's upgrade keeps one), run this again to retire it."
  else
    native_retire_legacy_repo_rpm
  fi
}

# The adopt's way to the same move. A child process rather than a call: a
# refusal in it (a key that will not verify, a fetch that fails) ends that
# process with its reason said, and the adopt this run already finished
# stands. `( ... ) || warn` would look the same and is not: errexit is off
# inside anything tested with ||.
native_move_source_after_adopt() {
  local rc=0
  bash "${BASH_SOURCE[0]}" --move-source || rc=$?
  if (( rc != 0 )); then
    warn "the node is adopted, and its package source was not moved; the lines above say why. Once that is settled:"
    warn "    curl -fsSL https://get.aperire.one | bash -s -- --update --force"
  fi
  return 0
}

native_install_package() {
  say "installing ${NATIVE_PACKAGE}"
  case "$NATIVE_PKG_KIND" in
    deb)
      export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l NEEDRESTART_SUSPEND=1
      apt-get install -y -qq "$NATIVE_PACKAGE" || die "apt-get install ${NATIVE_PACKAGE} failed"
      NATIVE_INSTALLED_VERSION="$(dpkg-query -W -f='${Version}' "$NATIVE_PACKAGE" 2>/dev/null)"
      ;;
    rpm)
      dnf install -y "$NATIVE_PACKAGE" || die "dnf install ${NATIVE_PACKAGE} failed"
      NATIVE_INSTALLED_VERSION="$(rpm -q --queryformat '%{VERSION}-%{RELEASE}' "$NATIVE_PACKAGE" 2>/dev/null)"
      ;;
  esac
  # The package's own unit name. Both the deb and the rpm repository ship the
  # current package under this name (the design note's table); a legacy
  # rippled package is never what this branch installs.
  NATIVE_UNIT=xrpld.service
  native_unit_loaded "$NATIVE_UNIT" \
    || die "installed ${NATIVE_PACKAGE} ${NATIVE_INSTALLED_VERSION:-} but systemd has no ${NATIVE_UNIT} loaded; the package layout may have changed since this was written"
  info "installed ${NATIVE_PACKAGE} ${NATIVE_INSTALLED_VERSION}"
}

# Patches the config the package just shipped: forces the two admin stanzas to
# loopback, collapses [node_db] to one advisory_delete line at 0 (#81, in the
# exact shape upstream's own example ships broken), sets online_delete to the
# window this project's own container config uses (#429, ruled 2026-09-17: the
# vendor ships 512, roughly a thirtieth of the history, and two shapes of one
# product keeping different history is a difference an operator discovers from
# a chart rather than from a document), and points
# [validators_file] at the publisher list this installer writes. Everything
# else - the node_db path, node_size, whatever the vendor decided - is left
# exactly as shipped: an edit, never a fresh file, on a config this project did
# not choose the layout of (the design note's own rule: measured, not
# invented). Prints the validators path it resolved, so the caller can install
# the list there and say so.
# The publisher-list path native_harden_cfg would write into
# [validators_file], read-only and with no side effects: the config's own
# existing directive if it has one, this project's own default beside the
# config otherwise. Split out of native_harden_cfg so the caller can name
# this path even on a run that decides not to harden the config at all (an
# existing config is kept exactly as it is, the same rule the container path
# follows for its own config file), without pulling the write in with it.
native_resolve_valpath() {  # $1 = cfg
  local cfg="$1" existing_vf
  existing_vf="$(native_cfg_line "$cfg" validators_file)"
  if [[ -n "$existing_vf" ]]; then
    if [[ "$existing_vf" == /* ]]; then printf '%s' "$existing_vf"; else printf '%s' "$(dirname "$cfg")/$existing_vf"; fi
  else
    printf '%s' "$(dirname "$cfg")/validators.txt"
  fi
}

native_harden_cfg() {  # $1 = cfg, $2 = the peer port to force, or empty
  local cfg="$1" peerport="${2:-}" valpath tmp backup was_snap now_snap
  valpath="$(native_resolve_valpath "$cfg")"

  for stanza in port_rpc_admin_local port_ws_admin_local; do
    grep -qE "^[[:space:]]*\[${stanza}\][[:space:]]*\$" "$cfg" \
      || die "${cfg} has no [${stanza}] stanza. xrpld's own example ships one; check the package version installed"
  done

  # Always a dated copy first, before anything is written, the same rule
  # aperire-node-wrapper.sh's set-config holds (#545 P1-105): a config this
  # function hardens can already carry the dashboard's and the relay's own
  # named ACL grants from a previous run of the same installer or from
  # close-node-config-exposure.sh, and a rewrite that turns out to have
  # dropped them needs something to put back.
  backup="$cfg.$(date +%Y%m%d-%H%M%S).bak"
  cp -a "$cfg" "$backup"
  cmp -s "$cfg" "$backup" || die "backup of $cfg does not match the original; nothing further was changed"
  cwl_prune_backups "$cfg" 10

  was_snap=$(cwl_acl_snapshot "$cfg")
  tmp="$(mktemp "$cfg.XXXXXX")"
  awk -v valpath="$valpath" -v peerport="$peerport" -v online="$NATIVE_ONLINE_DELETE" '
    function flush_stanza() {
      if (stanza == "port_rpc_admin_local" || stanza == "port_ws_admin_local") {
        if (!seen_ip)    print "ip = 127.0.0.1"
        if (!seen_admin) print "admin = 127.0.0.1"
      }
      if (stanza == "node_db" && !seen_advisory) print "advisory_delete = 0"
      if (stanza == "node_db" && !seen_online && online != "") print "online_delete = " online
      if (stanza == "port_peer" && peerport != "" && !seen_peer_port) print "port = " peerport
      if (stanza == "validators_file" && !seen_validators_line) print valpath
    }
    /^[[:space:]]*\[/ {
      flush_stanza()
      stanza = $0
      gsub(/^[[:space:]]*\[|\][[:space:]]*$/, "", stanza)
      seen_ip = 0; seen_admin = 0; seen_advisory = 0; seen_validators_line = 0
      seen_peer_port = 0; seen_online = 0
      print; next
    }
    (stanza == "port_rpc_admin_local" || stanza == "port_ws_admin_local") && /^[[:space:]]*ip[[:space:]]*=/ {
      print "ip = 127.0.0.1"; seen_ip = 1; next
    }
    (stanza == "port_rpc_admin_local" || stanza == "port_ws_admin_local") && /^[[:space:]]*admin[[:space:]]*=/ {
      print "admin = 127.0.0.1"; seen_admin = 1; next
    }
    stanza == "port_peer" && peerport != "" && /^[[:space:]]*port[[:space:]]*=/ {
      if (seen_peer_port) next
      print "port = " peerport; seen_peer_port = 1; next
    }
    stanza == "node_db" && /^[[:space:]]*advisory_delete[[:space:]]*=/ {
      if (seen_advisory) next
      print "advisory_delete = 0"; seen_advisory = 1; next
    }
    stanza == "node_db" && online != "" && /^[[:space:]]*online_delete[[:space:]]*=/ {
      if (seen_online) next
      print "online_delete = " online; seen_online = 1; next
    }
    stanza == "validators_file" {
      if ($0 ~ /^[[:space:]]*(#.*)?$/) { print; next }
      if (seen_validators_line) next
      print valpath; seen_validators_line = 1; next
    }
    { print }
    END { flush_stanza() }
  ' "$cfg" > "$tmp"

  # Owner, group, mode AND the ACL are carried across through the one helper
  # every rewrite in this project shares (#545), not `chown`/`chmod` alone:
  # those carry the classic bits only, and the `mv` right after installs a
  # new inode with no ACL at all, silently dropping any named grant the
  # dashboard's or the relay's account holds on this file.
  if ! cwl_carry_permissions "$cfg" "$tmp"; then
    rm -f "$tmp"
    die "could not carry ${cfg}'s owner, group, mode and ACL onto the hardening rewrite; ${cfg} is untouched"
  fi
  mv "$tmp" "$cfg"

  now_snap=$(cwl_acl_snapshot "$cfg")
  if [[ "$now_snap" != "$was_snap" ]]; then
    if cwl_restore_from_backup "$backup" "$cfg"; then
      die "hardening changed ${cfg}'s $(cwl_snapshot_describe); restored ${backup} and left the config reading exactly as it did before this ran"
    else
      die "hardening changed ${cfg}'s $(cwl_snapshot_describe), AND restoring ${backup} failed; the config's permissions are unproven, fix ${cfg} by hand from ${backup} before starting the node"
    fi
  fi

  grep -qE '^[[:space:]]*\[validators_file\][[:space:]]*$' "$cfg" \
    || printf '\n[validators_file]\n%s\n' "$valpath" >> "$cfg"

  # A vendor config ships [port_peer]. If one ever does not, the stanza is
  # added rather than the port being silently left at whatever the binary
  # defaults to: the whole point of setting it is that a fleet pinned it.
  if [[ -n "$peerport" ]] \
     && ! grep -qE '^[[:space:]]*\[port_peer\][[:space:]]*$' "$cfg"; then
    printf '\n[port_peer]\nport = %s\nip = 0.0.0.0\nprotocol = peer\n' "$peerport" >> "$cfg"
  fi

  install -d -m 0755 "$(dirname "$valpath")"
  # An existing publisher list at this path is the operator's, the same rule
  # the container path holds for VAL_FILE further down: this function is
  # only ever called on a config this run is hardening for the first time
  # (the caller in native_main keeps a config that already existed exactly
  # as it is, validators.txt included), but a stale record naming a path
  # some earlier, unrelated run already populated is still worth respecting
  # rather than overwriting on the strength of that assumption alone.
  if [[ -f "$valpath" ]]; then
    :
  else
    _vout="$(rd_install "$REPO_DIR" scripts/templates/validators.txt "$valpath" 0644 --kinds)" || {
      # The account check not running is not a file that changed (#1111).
      rd_was_accounts "$_vout" \
        && die "${valpath} was not written: $(rd_refused_cause "${TEMPLATE_DIR}/validators.txt" "$_vout")"
      die "${valpath} was not written: ${TEMPLATE_DIR}/validators.txt is not the file this release shipped, a service account can change it, or it could not be written (above)"
    }
  fi
  printf '%s' "$valpath"
}

# Say which peer port this node will answer on, and open it if this host has
# an active firewall.
#
# A fleet pins its peers by address AND port. Every Aperire container node
# answers on 51235, because the compose file maps the host's 51235 to the
# vendor's 2459 inside the container. The vendor's package listens on 2459
# directly, so a host converted from the container shape to native stops
# answering where the fleet is dialling, and every node that pinned it loses
# it without a word. On a peer-private validator that is a consensus
# problem, not a cosmetic one: validator1 sat at peer_count 1 for 45 minutes
# after the lab converted stock-node2 (#430).
#
# ufw is opened, never enabled. Enabling a default-deny firewall over a live
# SSH session locks the operator out, which is exactly why the relay
# installer detects and advises rather than switching it on, and this follows
# that rule. A host with no active ufw gets the line to run, and a host that
# wanted the vendor's own port is told the fleet consequence in one line.
native_peer_port_note() {  # $1 = the peer port forced, or empty for the vendor's
  local port="$1"
  if [[ -z "$port" ]]; then
    warn "keeping the vendor's own peer port (--vendor-peer-port). Any node that pinned this host at ${HOST_PEER_PORT}, which is the port every Aperire node in a fleet answers on, will stop reaching it"
    return 0
  fi
  info "peer port ${port} (the port a fleet pins, and the one this project's container nodes answer on)"
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
    if ufw allow "${port}/tcp" >/dev/null 2>&1; then
      info "ufw is active on this host, so ${port}/tcp is now allowed inbound"
    else
      warn "ufw is active but would not add a rule for ${port}/tcp. Inbound peers cannot reach this node until it is allowed: sudo ufw allow ${port}/tcp"
    fi
  else
    info "no active ufw here, so nothing was opened. If you add one later, this node needs: sudo ufw allow ${port}/tcp"
  fi
}

# A whole stanza, header and all, from a config. Empty when it is not there.
native_cfg_stanza() {  # $1=file $2=stanza
  [[ -r "$1" ]] || return 0
  awk -v s="$2" '
    $0 ~ "^[[:space:]]*\\[" s "\\][[:space:]]*$" { inb = 1; print; next }
    inb && $0 ~ /^[[:space:]]*\[/ { inb = 0 }
    inb { print }
  ' "$1" 2>/dev/null
}

# Carry the node's peer settings from the config it had to the config it has.
#
# The peer PORT (#430's first half) was only half of it. On aperire2 the
# freshly installed native node filled rippled's default 21 peer slots with
# public peers before the validator retried, and the validator's inbound
# connection was refused: the container had had the validator connected
# before it ever filled, and the conversion threw that away. A peer-private
# validator with a fixed peer list then sits with one peer, and nothing on
# either box says why.
#
# So a conversion carries [ips_fixed], [peers_max] and [peer_private] across,
# and says what it carried. A slot reserved by [ips_fixed] is what stops the
# race, and it is a setting the operator already chose once.
#
# The new config wins wherever it already names one of them: this appends
# what is missing and never edits what the package shipped with a value in
# it. Nothing is invented either. A container config with no [ips_fixed]
# converts without one, because "no fixed peers" is a choice too.
native_carry_peer_stanzas() {  # $1 = the config this host had, $2 = the new one
  local from="$1" to="$2" stanza block carried=() present=()
  [[ -n "$from" && -r "$from" && "$from" != "$to" ]] || return 0
  for stanza in ips_fixed peers_max peer_private; do
    block="$(native_cfg_stanza "$from" "$stanza")"
    [[ -n "$block" ]] || continue
    if grep -qE "^[[:space:]]*\[${stanza}\][[:space:]]*\$" "$to"; then
      present+=("$stanza")
      continue
    fi
    printf '\n%s\n' "$block" >> "$to"
    carried+=("$stanza")
  done
  if (( ${#carried[@]} )); then
    info "carried ${carried[*]} across from ${from}, so the peers this node was told to keep are still in its config"
    info "${S_DIM}a fixed peer holds a slot; without one a fresh node can fill every slot with public peers before a validator retries, and the validator is then refused${S_OFF}"
  fi
  (( ${#present[@]} )) && info "${present[*]} already set in ${to}; left as it is"
  (( ${#carried[@]} || ${#present[@]} )) || return 0
  return 0
}

# The same fact on the adopt path, read and said, never changed.
#
# Adopting is also a conversion: this installer's own refusal on an
# unsupported OS tells an operator to install a node by hand and run it again
# to adopt it, and a node installed by hand from the vendor's instructions
# listens on the vendor's port. So the fleet consequence is exactly #430's,
# reached by a different door.
#
# It reads and warns rather than editing. An adopted node is one this
# installer did not put here and whose config it did not choose the layout
# of, and rewriting the peer port of a node that is already running, and
# already reachable somewhere, is a change nobody asked for. The line names
# the port, the port a fleet pins, and the two commands that move it.
native_adopt_peer_port_note() {  # $1 = the adopted node's cfg
  local cfg="$1" port=''
  [[ -n "$cfg" && -f "$cfg" ]] || return 0
  port="$(native_cfg_kv "$cfg" port_peer port)"
  if [[ -z "$port" ]]; then
    info "peer port: ${cfg} names none under [port_peer], so this node is on whatever its binary defaults to"
    return 0
  fi
  if [[ "$port" == "$HOST_PEER_PORT" ]]; then
    info "peer port ${port} (the port a fleet pins; this node already answers there)"
    return 0
  fi
  warn "peer port ${port}, and a fleet pins ${HOST_PEER_PORT}. Every Aperire node in a fleet answers on ${HOST_PEER_PORT}, so any node that pinned this host at that port is not reaching it. Nothing here changed it: set [port_peer] port = ${HOST_PEER_PORT} in ${cfg}, allow it if this host runs a firewall (sudo ufw allow ${HOST_PEER_PORT}/tcp), and restart the node"
}

native_unit_health() {  # $1 = unit
  local state substate
  state="$(systemctl show -p ActiveState --value "$1" 2>/dev/null || true)"
  substate="$(systemctl show -p SubState --value "$1" 2>/dev/null || true)"
  case "$state" in
    active)     v_ok "unit ${1}: active (${substate:-running})" ;;
    activating) v_warn "unit ${1}: activating (${substate:-start})" ;;
    failed)     v_failed "unit ${1}: FAILED (journalctl -u ${1} -n 50)" ;;
    *)          v_failed "unit ${1}: ${state:-not found}" ;;
  esac
}

# The same three proofs the container path runs: server_info answers, the two
# admin ports are on loopback, the publisher list loaded. Shares server_info,
# json_field, port_state and the v_* verdicts with the container path's own
# verify section - one implementation, read by both.
NATIVE_LAST_STATE=""
native_run_verify() {  # $1=unit $2=rpc_port $3=ws_port $4=cfg_file
  local unit="$1" rpc_port="$2" ws_port="$3" cfg="$4"
  local waited=0 si1 srv_state build trusted p
  ADMIN_RPC_PORT="$rpc_port"
  si1="$(server_info || true)"
  while [[ -z "$(printf '%s' "$si1" | json_field server_state)" && $waited -lt $NODE_WAIT_SECS ]]; do
    printf '\r   %swaiting for the node to open its admin RPC on 127.0.0.1:%s  %ss of %ss%s   ' \
      "$S_DIM" "$rpc_port" "$waited" "$NODE_WAIT_SECS" "$S_OFF"
    sleep 5; waited=$((waited + 5))
    si1="$(server_info || true)"
  done
  [[ $waited -gt 0 ]] && printf '\r%*s\r' 78 ''
  native_unit_health "$unit"
  for p in "$rpc_port" "$ws_port"; do
    case "$(port_state "$p")" in
      loopback)  v_ok "127.0.0.1:${p} is listening, on loopback only" ;;
      unchecked) v_ok "127.0.0.1:${p} answers (no ss here, so the bind address was not checked)" ;;
      wildcard)  v_failed "port ${p} is listening on a WILDCARD address, not 127.0.0.1. This is an admin port: anything that reaches it can stop this node. Check [port_rpc_admin_local] / [port_ws_admin_local] in ${cfg}" ;;
      *)         v_failed "127.0.0.1:${p} is not listening (the dashboard reads the node through these two)" ;;
    esac
  done
  srv_state="$(printf '%s' "$si1" | json_field server_state)"
  if [[ -z "$srv_state" ]]; then
    v_failed "server_info did not answer on 127.0.0.1:${rpc_port} within ${NODE_WAIT_SECS}s"
    info "${S_DIM}what came back: ${si1:-nothing at all}${S_OFF}"
  else
    [[ $waited -gt 0 ]] && v_ok "the node opened its admin RPC after ${waited}s"
    build="$(printf '%s' "$si1" | json_field build_version)"
    v_ok "server_info answers: server_state=${srv_state}${build:+, build ${build}}"
  fi
  if [[ -n "$srv_state" ]]; then
    # The answer is captured before it is parsed. A curl that cannot reach the
    # node, which can be restarting under us, would otherwise fail the whole
    # pipeline under `set -o pipefail` and end a verification run that is
    # already reporting problems, with no line saying so.
    local val_body=''
    val_body="$(curl -s --max-time 10 -H 'Content-Type: application/json' \
      -d '{"method":"validators","params":[{}]}' "http://127.0.0.1:${rpc_port}/" 2>/dev/null)" || val_body=''
    trusted="$(printf '%s' "$val_body" \
      | tr -d ' \n' \
      | sed -n 's/.*"trusted_validator_keys":\[\([^]]*\)\].*/\1/p' \
      | { grep -o '"[^"]*"' || true; } | wc -l)"
    if [[ "${trusted:-0}" -gt 0 ]]; then
      v_ok "${trusted} trusted validators, so the publisher list loaded"
    else
      v_warn "no trusted validators yet. Until the publisher list loads, this node can sync and never validate. Re-check in a few minutes: curl -s -d '{\"method\":\"validators\",\"params\":[{}]}' http://127.0.0.1:${rpc_port}/"
    fi
  fi
  NATIVE_LAST_STATE="$srv_state"
}

# ── The registry's own row for this host ─────────────────────────────────
#
# A conversion to the native package writes a FRESH store, and a fresh store
# writes a new node key. The dashboard's registry on this box went on pinning
# the key the host had before it, and nothing said so for a month (#488,
# aperire2): a self row is read locally, so the stale pin costs nothing HERE
# while every other host reading this node through a registry with the same
# pin fails it closed.
#
# So the run that changes the identity repoints the row, and says it out loud.
# What it refuses to do matters as much as what it does:
#
#   never pins an unpinned row      an absent expected_pubkey_node is a
#                                   first-class shape (fleet-registry.ts says
#                                   so). Adding a pin is a decision, not a
#                                   consequence of an install
#   never guesses which row is this a row is this host's when its read_origin
#                                   is loopback on THIS dashboard's port, the
#                                   same rule resolveFleet uses. No port, two
#                                   ports, no match, or more than one: it
#                                   prints what it found and changes nothing
#   never writes on a key it did    no server_info, no pubkey_node, no write.
#   not have                        A conversion whose node has not opened its
#                                   RPC yet leaves the file alone
#   never a load-and-dump           one line is rewritten in place, so the
#                                   comments, the other rows and the file's
#                                   owner and mode all survive
native_self_dash_port() {  # prints this dashboard's port, or nothing when it is not one answer
  local f p
  local -a ports=()
  while IFS= read -r f; do
    [[ -n "$f" ]] || continue
    p="$(awk -F= '/^[[:space:]]*PORT=/{gsub(/[[:space:]]/,"",$2); print $2; exit}' "$f")" || p=''
    [[ "$p" =~ ^[0-9]{1,5}$ ]] && ports+=("$p")
    true
  done < <(find "$ETC_APERIRE" -maxdepth 1 -name 'aperire*.env' -type f 2>/dev/null | sort)
  # Two instances on one host is a supported shape, and it is exactly the
  # shape where guessing which registry row is "this one" would repoint
  # somebody else's. Distinct values, not a count of files: two env files
  # agreeing on a port is one answer, two disagreeing is none.
  local -a seen=()
  for p in ${ports+"${ports[@]}"}; do
    [[ " ${seen[*]-} " == *" $p "* ]] || seen+=("$p")
  done
  [[ ${#seen[@]} -eq 1 ]] && printf '%s' "${seen[0]}"
  # Never the status of the test above: "no single answer" is an ANSWER this
  # function gives, and under `set -e` a bare false here ends the install.
  return 0
}

native_repin_self_row() {
  local fleet_file="${REPO_DIR}/dashboard/config/fleet.yaml"
  [[ -r "$fleet_file" ]] || return 0   # no registry here: the ordinary single-node install
  say "the dashboard's own registry row for this node"
  if ! command -v python3 >/dev/null 2>&1; then
    warn "python3 is not here, and fleet.yaml is yaml, so the registry row was not checked."
    warn "check expected_pubkey_node in ${fleet_file} by hand."
    return 0
  fi
  local port key
  port="$(native_self_dash_port)"
  if [[ -z "$port" ]]; then
    info "no single dashboard port in ${ETC_APERIRE}, so which row is this host is not a question this can answer. ${fleet_file} was not touched"
    return 0
  fi
  # `|| true`, because a node that will not answer is one of the cases this
  # handles rather than a reason to end the install: curl's own status rides
  # out of the pipeline under `pipefail` and would otherwise be fatal.
  key="$(server_info | json_field pubkey_node || true)"
  if [[ -z "$key" ]]; then
    warn "the node did not say what its node key is, so nothing was compared. ${fleet_file} was not touched"
    warn "if this host was just converted, re-run this once the node answers server_info"
    return 0
  fi
  local out rc=0
  out="$(python3 -I "${SCRIPTS_DIR}/fleet-self-pin.py" "$fleet_file" "$port" "$key")" || rc=$?
  case "$rc" in
    0)  # rewritten
      info "$out"
      info "the registry pinned the key this host had BEFORE this run; it now names the one the node answers with"
      # Said, not done. The unit name is a convention on most hosts and not on
      # all of them, and reloading the wrong service is worse than printing a
      # line. The consequence of not reloading is spelled out because it is
      # otherwise a confusing minute: the page goes on reporting the key it
      # read at startup, so it asks for an edit the file has already had.
      info "the dashboard reads this file at startup and on reload, so until you run"
      info "  ${S_CYAN}sudo systemctl reload aperire-server${S_OFF}"
      info "its page keeps naming the OLD key and keeps asking for the edit this run already made"
      ;;
    2)  info "$out" ;;                                   # nothing to do, said plainly
    *)  warn "$out"; warn "${fleet_file} was not touched" ;;
  esac
  return 0
}

native_main() {
  say "checking for a native node already on this host"
  # install-node-wrapper.sh below would print the compact notice itself, in
  # the middle of this run. This run prints it at the end, where the operator
  # is reading, so the child's copy is suppressed rather than duplicated.
  export APERIRE_COMPACT_CHECK=0
  local wconf="${ETC_APERIRE}/node-wrapper.conf"
  if [[ -n "${APERIRE_INSTANCE:-}" ]]; then
    # Keyed to the instance's installed wrapper since ADR 0024, and to the
    # copy in its checkout before that. A host install-node-wrapper.sh has
    # not reached yet still has only the older one.
    wconf="$(trusted_wrapper_conf "$APERIRE_INSTANCE" "${ETC_APERIRE}/node-wrapper.conf")"
    [[ -r "$wconf" ]] \
      || wconf="${ETC_APERIRE}/node-wrapper-$(printf '%s' "${REPO_DIR}/scripts/aperire-node-wrapper.sh" | sha256sum | cut -c1-12).conf"
  fi

  # The config this host had before this run, captured BEFORE anything
  # overwrites the records that name it. On a conversion this is the
  # container node's config, and it holds peer settings the operator chose
  # once and should not have to choose again (#430).
  local prev_cfg=''
  prev_cfg="$(native_conf_value "${ETC_APERIRE}/node.conf" CONFIG_FILE)"
  [[ -n "$prev_cfg" ]] || prev_cfg="$(native_conf_value "$wconf" CONFIG_FILE)"
  [[ -r "$prev_cfg" ]] || prev_cfg=''

  local adopted=0
  if native_probe_unit; then
    info "found ${NATIVE_UNIT}, already loaded by systemd"
    if [[ "$NATIVE_UNIT" == "xahaud.service" ]]; then
      info "xahaud is adopt-only: no repository is named for it here, so this host is always adopted, never offered a package"
    fi
    say "adopting ${NATIVE_UNIT}"
    info "nothing is installed from anywhere: the config and the admin RPC come from what is already running"
    bash "${SCRIPTS_DIR}/install-node-wrapper.sh" --native "$NATIVE_UNIT" \
      || die "could not adopt ${NATIVE_UNIT}. See the message above for the cfg or admin-RPC problem it found"
    adopted=1
    NATIVE_CFG="$(native_conf_value "$wconf" CONFIG_FILE)"
    local admin_rpc; admin_rpc="$(native_conf_value "$wconf" ADMIN_RPC)"
    ADMIN_RPC_PORT="${admin_rpc##*:}"
    ADMIN_WS_PORT="$(native_cfg_kv "$NATIVE_CFG" port_ws_admin_local port)"
    ADMIN_WS_PORT="${ADMIN_WS_PORT:-6006}"
    native_adopt_peer_port_note "$NATIVE_CFG"
    # Adopting installs nothing, and a host installed before #655 still has
    # its source on repos.ripple.com (#802). xahaud has no repository here.
    [[ "$NATIVE_UNIT" == "xahaud.service" ]] || native_move_source_after_adopt
  else
    say "no native node found; checking whether this OS can be offered one"
    local running
    if running="$(native_conflicting_node)"; then
      die "$running is already running on this host, and it is not a native unit this run
   knows how to adopt (xrpld.service, rippled.service, xahaud.service, or an
   explicit --unit). Installing a second node beside a live one is not
   something this script will do without being told to.
   If it runs in a container, adopt it instead:
     curl -fsSL https://get.aperire.one | bash -s -- --run node --adopt
   If this really is meant to be a second, separate native install, name its
   own unit so this run stops guessing which node is which:
     curl -fsSL https://get.aperire.one | bash -s -- --run node --native --unit <its-unit-name>"
    fi
    if ! native_offer_target; then
      die "no vendor package is named for ${NATIVE_OS_DESC}.
   xrpld is offered on Ubuntu 22.04, Ubuntu 24.04, Debian 12 or RHEL 9 (all
   x86_64) only. Anywhere else, install a node yourself - the vendor's own
   instructions, a from-source build, or xahaud - and adopt it instead:
     curl -fsSL https://get.aperire.one | bash -s -- --node-wrapper-native${APERIRE_INSTANCE:+ --instance $APERIRE_INSTANCE}"
    fi
    info "offering ${NATIVE_PACKAGE} for ${NATIVE_OS_DESC}"

    if [[ $ASSUME_YES -ne 1 ]]; then
      if [[ -t 0 ]]; then
        local repo_url
        [[ "$NATIVE_PKG_KIND" == deb ]] && repo_url="$NATIVE_DEB_REPO_URL" || repo_url="$NATIVE_RPM_REPO_URL"
        cat <<EOF

  ${S_BOLD}About to install a native XRPL node on this host${S_OFF}

    package     ${NATIVE_PACKAGE} (${NATIVE_OS_DESC})
    repository  ${repo_url}
    network     ${NET}
    role        ${ROLE}
    label       ${NAME}

EOF
        read -r -p "  Proceed? [Y/n] " reply
        case "$reply" in n|N|no|NO) echo "  stopped, nothing was changed."; exit 0 ;; esac
      else
        die "nothing here to ask, and --yes was not passed. Nothing has been changed"
      fi
    fi

    case "$NATIVE_PKG_KIND" in
      deb) native_add_repo_deb ;;
      rpm) native_add_repo_rpm ;;
    esac

    # Read BEFORE the install below touches anything. A config already
    # sitting at one of the vendor's own paths is this host's own, the same
    # rule the container path holds for CFG_FILE further down ("an existing
    # config is the operator's, always"): a package manager never overwrites
    # a modified conffile, so reaching this branch with one already there
    # means either a genuine re-run or a unit this run's own probe did not
    # recognise, never a package that was not installed before. Hardening it
    # again would run the ACL-losing rewrite #545 exists to fix on a config
    # this run did not create, on top of overwriting validators.txt with the
    # vendor's own list and losing whatever publisher list is really there.
    local pre_existing_cfg=''
    pre_existing_cfg="$(native_locate_cfg 2>/dev/null)" || true

    native_install_package

    say "the shipped config"
    NATIVE_CFG="$(native_locate_cfg)" \
      || die "installed ${NATIVE_PACKAGE} but none of these config paths exist: ${NATIVE_CFG_CANDIDATES[*]}"
    info "found ${NATIVE_CFG}"

    local peerport=''
    if [[ -n "$pre_existing_cfg" && "$pre_existing_cfg" == "$NATIVE_CFG" ]]; then
      have "${NATIVE_CFG} exists; keeping it exactly as it is"
      info "${S_DIM}(nothing here edits a config it did not write, the same rule the container path follows. If this node is not adopting cleanly, check whether its unit is loaded under a name this run recognises: xrpld.service, rippled.service or xahaud.service.)${S_OFF}"
      NATIVE_VALPATH="$(native_resolve_valpath "$NATIVE_CFG")"
    else
      cp -p "$NATIVE_CFG" "${NATIVE_CFG}.prev"
      info "kept the package's own default at ${NATIVE_CFG}.prev"
      (( NATIVE_KEEP_VENDOR_PEER_PORT )) || peerport="$HOST_PEER_PORT"
      NATIVE_VALPATH="$(native_harden_cfg "$NATIVE_CFG" "$peerport")"
      info "hardened ${NATIVE_CFG}: admin ports to loopback, one advisory_delete line, publisher list at ${NATIVE_VALPATH}"
      # Said out loud, with the cost, because it is the one setting here that
      # decides how much disk this node needs and the vendor's default is
      # thirty-two times smaller.
      if [[ -n "$NATIVE_ONLINE_DELETE" ]]; then
        info "online_delete = ${NATIVE_ONLINE_DELETE} ledgers kept online, the same window this project's container nodes use"
        info "${S_DIM}(the lab's container node held about 43 GB of store at this window; the package's own 512 needs a fraction of that. --vendor-retention keeps the package's value.)${S_OFF}"
      else
        info "online_delete: left at whatever the package shipped"
      fi
      native_peer_port_note "$peerport"
      [[ "$ROLE" == "validator" ]] && append_validator_token_stanza "$NATIVE_CFG"
    fi

    if [[ -n "$prev_cfg" ]]; then
      native_carry_peer_stanzas "$prev_cfg" "$NATIVE_CFG"
    else
      # No config to carry from, so this is a fresh node rather than a
      # conversion, and the same trap is waiting on the other side of it: a
      # node that fills its peer slots with public peers before the validator
      # it exists to serve gets a connection in. Said once, here, where the
      # operator is already reading about this node's peers.
      info "${S_DIM}if this node exists to peer with a private validator, put that validator in [ips_fixed] in ${NATIVE_CFG} and restart: a fixed peer holds a slot, and without one this node can fill all of them with public peers before the validator retries${S_OFF}"
    fi

    say "starting ${NATIVE_UNIT}"
    systemctl enable "$NATIVE_UNIT" >/dev/null 2>&1 || true
    systemctl restart "$NATIVE_UNIT" \
      || die "systemctl restart ${NATIVE_UNIT} failed. The config at ${NATIVE_CFG} was written; check systemctl status ${NATIVE_UNIT} and journalctl -u ${NATIVE_UNIT}"

    ADMIN_RPC_PORT="$(native_cfg_kv "$NATIVE_CFG" port_rpc_admin_local port)"; ADMIN_RPC_PORT="${ADMIN_RPC_PORT:-5005}"
    ADMIN_WS_PORT="$(native_cfg_kv "$NATIVE_CFG" port_ws_admin_local port)"; ADMIN_WS_PORT="${ADMIN_WS_PORT:-6006}"
  fi

  say "verifying"
  native_run_verify "$NATIVE_UNIT" "$ADMIN_RPC_PORT" "$ADMIN_WS_PORT" "$NATIVE_CFG"

  # After the verify, because it needs the node to have answered, and on BOTH
  # branches: a conversion usually arrives here through the install half, and
  # aperire2 arrived through the adopt half with a store that had already been
  # replaced. Never fatal: a registry row is not a reason to fail a node that
  # is up (#488).
  native_repin_self_row

  if [[ $adopted -eq 0 ]]; then
    say "pointing the wrapper at ${NATIVE_UNIT}"
    bash "${SCRIPTS_DIR}/install-node-wrapper.sh" --native "$NATIVE_UNIT" \
      || die "the node is up but the wrapper could not be configured. Run: curl -fsSL https://get.aperire.one | bash -s -- --node-wrapper-native ${NATIVE_UNIT}${APERIRE_INSTANCE:+ --instance $APERIRE_INSTANCE}"
  fi

  cat <<EOF

  ${S_BOLD}What a syncing node looks like${S_OFF}

  server_state walks: ${S_CYAN}connected${S_OFF} -> ${S_CYAN}syncing${S_OFF} -> ${S_CYAN}tracking${S_OFF} -> ${S_CYAN}full${S_OFF}
  (a validator with a token then reads ${S_CYAN}proposing${S_OFF}). It does not walk that in
  a straight line, and it can drop back a step while it finds peers.

  Right now it is: ${S_CYAN}${NATIVE_LAST_STATE:-not answering yet}${S_OFF}

  Watch it:
      ${S_CYAN}journalctl -u ${NATIVE_UNIT} -f${S_OFF}
      ${S_CYAN}curl -s -d '{"method":"server_info","params":[{}]}' http://127.0.0.1:${ADMIN_RPC_PORT}/${S_OFF}

EOF

  say "wiring for the dashboard and the relay"
  local node_conf="${ETC_APERIRE}/node.conf"
  mkdir -p "$ETC_APERIRE" 2>/dev/null || true
  if { umask 0022; cat > "$node_conf" <<EOF
# Written by scripts/install-aperire-node.sh --native: the node this
# installer adopted or installed on this host. Read line by line, never
# sourced.
#
# KIND         container or native (#30)
# SERVICE      the systemd unit
# ADMIN_RPC    loopback admin RPC, read out of the node's own config
# CONFIG_FILE  the node's config on this host
# NODE_LABEL   the fleet label the operator chose (--name). There is no
#              container name to fall back on here, so
#              scripts/install-aperire-relay.sh reads this key ahead of the
#              wrapper's SERVICE (a unit name is not a label)
#
# Re-run this installer after anything that moves the node.
KIND=native
SERVICE=${NATIVE_UNIT}
ADMIN_RPC=http://127.0.0.1:${ADMIN_RPC_PORT}
CONFIG_FILE=${NATIVE_CFG}
NODE_LABEL=${NAME}
EOF
     }; then
    chown root:root "$node_conf" 2>/dev/null || true
    chmod 0644 "$node_conf"
    info "${node_conf} names this node (${NAME}), so the relay and the rotation window can find it"
  else
    warn "could not write ${node_conf}; the relay and the rotation window will have to be told the node's name by hand"
  fi

  # After the record, because the closer finds the node through it, and before
  # the V_FAIL block below, so a node that did not come up still gets the
  # sentence saying why its config could not be closed (#462).
  close_node_config "$NATIVE_CFG"

  # A dashboard already on this host is pointed at whatever node was here
  # before. The container path re-detects into every env file for exactly
  # that reason and this one did not, so a host converted from a container
  # kept measuring the container's store: on a lab host the System tab was
  # walking a 26 GB directory the node had stopped writing to, while its real
  # store was 6.7 GB. Same block as the container path, same reason.
  local env_files=() f
  while IFS= read -r f; do
    [[ -n "$f" ]] && env_files+=("$f")
  done < <(find "$ETC_APERIRE" -maxdepth 1 -name 'aperire*.env' -type f 2>/dev/null | sort)
  if [[ ${#env_files[@]} -gt 0 ]]; then
    info "a dashboard is already installed here; re-detecting its node paths"
    for f in "${env_files[@]}"; do
      bash "${SCRIPTS_DIR}/configure-rippled-paths.sh" --env-file "$f" \
        || warn "path detection did not finish for ${f}; run scripts/configure-rippled-paths.sh --env-file ${f} by hand"
    done
  fi

  if [[ $V_FAIL -gt 0 ]]; then
    cat >&2 <<EOF

${E_RED}The node is not working: ${V_FAIL} check(s) FAILED above.${E_OFF}

  Nothing has been rolled back, because a half-started node is worth looking
  at rather than deleting. Start here:

      systemctl status ${NATIVE_UNIT}
      journalctl -u ${NATIVE_UNIT} -n 100

  Then fix and run this again; it is idempotent and adopts what it finds.

EOF
    return 1
  fi

  cat <<EOF

${S_GREEN}${S_BOLD}The node is up.${S_OFF} ${V_OK} check(s) passed.

  ${S_BOLD}Next: install Aperire One beside it${S_OFF}

      ${S_CYAN}curl -fsSL https://get.aperire.one | bash${S_OFF}

  It will find this node by itself. The preflight probes ${ADMIN_WS_PORT}, reads the
  ports out of ${NATIVE_CFG}, and the role comes out co-located.

EOF

  # Last, because it is the one thing on a CONVERSION that the operator has to
  # act on themselves. A host that ran a container node and now runs this unit
  # keeps the operator compact it accepted, that acceptance names the
  # container, and the Advisor's node key is this unit: every privileged class
  # is refused until it is accepted again, and until now nothing said so
  # anywhere an operator would look (#466).
  #
  # It accepts nothing. It prints the exact command with the privilege and the
  # classes that acceptance already named, and a fresh install, which has
  # accepted nothing, sees no line from it at all.
  APERIRE_COMPACT_CHECK=1 APERIRE_ETC="$ETC_APERIRE" \
    bash "${SCRIPTS_DIR}/aperire-compact-check.sh" --node "$NATIVE_UNIT" || true
  return 0
}

# ── The record of the node on this host ─────────────────────────────
#
# One writer for /etc/aperire/node.conf on the container path, shared by the
# install at the end of this script and by --adopt above it. Two writers of
# one file is how two hosts end up describing the same node differently.
#
# The rotation-window installer (scripts/install-can-delete-timer.sh), the
# relay installer and (since #437) the after-reboot check, the baseline check
# and the config closer all read this file. Its own file, not the wrapper's:
# /etc/aperire/node-wrapper.conf is the privilege wrapper's security
# configuration, written whole by install-node-wrapper.sh and restored from a
# .previous copy whenever its own verification fails, so a partial one written
# here would become what that revert restores.
write_container_node_conf() { # provenance service admin_rpc config label [user uid gid]
  local provenance="$1" service="$2" admin_rpc="$3" config="$4" label="$5"
  local nuser="${6:-}" nuid="${7:-}" ngid="${8:-}"
  local target="${ETC_APERIRE}/node.conf"
  mkdir -p "$ETC_APERIRE" 2>/dev/null || true
  {
    umask 0022
    {
      cat <<EOF
# Written by scripts/install-aperire-node.sh: ${provenance} on this host.
# Read line by line, never sourced.
#
# KIND         container or native (#30); this installer only ever writes
#              container here, --native writes native from its own branch
# SERVICE      the container's name, which is also its compose project
# ADMIN_RPC    loopback admin RPC, published by the compose on 127.0.0.1 only
# CONFIG_FILE  the node's config on this host, bind-mounted into the container
# NODE_LABEL   the fleet label the operator chose (--name). On the container
#              path this is the same string as SERVICE; it exists as its own
#              key because a native node has no container name for the relay
#              to fall back on, so scripts/install-aperire-relay.sh reads
#              this key ahead of anything it would otherwise guess
# NODE_USER / NODE_UID / NODE_GID
#              the account the node runs as inside its container and owns its
#              store as on this host (#31). Recorded because the ids are
#              resolved per host: 997 when this host had it free, whatever the
#              system allocated when it did not. Absent where the node still
#              runs as root inside its container
#
# Re-run this installer after anything that moves the node. Read by
# scripts/install-can-delete-timer.sh, which falls back to asking docker.
KIND=container
SERVICE=${service}
ADMIN_RPC=${admin_rpc}
CONFIG_FILE=${config}
NODE_LABEL=${label}
EOF
      if [[ -n "$nuser" && -n "$nuid" && -n "$ngid" ]]; then
        printf 'NODE_USER=%s\nNODE_UID=%s\nNODE_GID=%s\n' "$nuser" "$nuid" "$ngid"
      fi
    } > "$target"
  } || return 1
  chown root:root "$target" 2>/dev/null || true
  chmod 0644 "$target"
  return 0
}

# ── Adopt: record a node this installer did not put here (#434) ─────
#
# A wipe-clean uninstall removes /etc/aperire whole, the node and its data
# survive by design, and nothing on the reinstall path writes node.conf back
# on a host whose node is already running. That leaves a healthy node with no
# record of itself, and every reader without a fallback of its own dead-ends
# on it: the non-root migration refuses outright, and its advice is to re-run
# this installer over a 46 GB node that needs nothing (aperire4, 2026-09-17).
#
# So this is the small verb for that: measure the node that is here and write
# the record. It installs nothing, starts nothing, stops nothing and edits no
# config. Every value comes from the container itself, the way the timer and
# relay installers already ask docker, rather than from what this script would
# have chosen had it done the install.
container_adopt() {
  local want="${1:-}" line names=() n image
  command -v docker >/dev/null 2>&1 \
    || die "--adopt needs docker to ask about the node that is running; there is none on this host"

  say "finding the node on this host"
  local said='' ask=0
  said="$(docker_ask '{{.Names}} {{.Image}}')" || ask=$?
  # A container created from a digest shows an image ID; read its name back,
  # and treat a refused read like a refused ps (#896).
  if [[ $ask -eq 0 ]]; then said="$(docker_resolve_image_ids "$said")" || ask=$?; fi
  case $ask in
    1) die "docker is installed here and no daemon answered, so what is running is not something this run can read: ${said}" ;;
    2) die "docker would not say what is running (${said}). That is not an absence, so nothing has been recorded. Run this again as an account that may ask docker" ;;
  esac

  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    n="${line%% *}"; image="${line#* }"
    if [[ -n "$want" ]]; then
      [[ "$n" == "$want" ]] && names+=("$n")
    else
      case "$image" in *rippled*|*xrpld*|*xahau*) names+=("$n") ;; esac
    fi
  done <<< "$said"

  if [[ ${#names[@]} -eq 0 ]]; then
    if [[ -n "$want" ]]; then
      die "no running container named '${want}' on this host. 'docker ps' lists what is here"
    fi
    die "no running container on this host looks like an XRPL node (no image naming rippled, xrpld or xahau). If this host's node is native, run --native instead; otherwise name it yourself with --name, or install one without --adopt"
  fi
  if [[ ${#names[@]} -gt 1 ]]; then
    die "more than one container here looks like an XRPL node (${names[*]}). Say which with --name"
  fi
  local svc="${names[0]}"
  have "found ${svc}"

  # The config, from the mount rather than from a path this script would
  # guess. Since #31 the same host file is mounted at two destinations, so the
  # answer is sorted and the first taken: docker does not list mounts in a
  # stable order, and an unsorted read names a different path between runs.
  local cfg
  cfg=$(docker inspect "$svc" --format '{{range .Mounts}}{{.Source}} {{.Destination}}{{"\n"}}{{end}}' 2>/dev/null \
        | awk '$2=="/etc/xrpld/xrpld.cfg" || $2=="/config/rippled.cfg" {print $2"\t"$1}' \
        | LC_ALL=C sort | head -1 | cut -f2)
  [[ -n "$cfg" && -f "$cfg" ]] \
    || die "${svc} mounts no node config this run can find on the host (looked for /etc/xrpld/xrpld.cfg and /config/rippled.cfg). Nothing has been recorded"
  have "config ${cfg}"

  # The admin RPC, from what the container publishes rather than from the
  # number this script would have chosen. A node published on another port is
  # a node the readers have to reach on that port.
  local published port
  published=$(docker port "$svc" "${ADMIN_RPC_PORT}/tcp" 2>/dev/null | head -1) || published=''
  port="${published##*:}"
  if [[ -z "$port" || ! "$port" =~ ^[0-9]+$ ]]; then
    die "${svc} publishes nothing on ${ADMIN_RPC_PORT}/tcp, so there is no loopback admin RPC to record. Nothing has been recorded"
  fi
  case "$published" in
    127.0.0.1:*|localhost:*|"[::1]:"*) ;;
    *) warn "${svc} publishes its admin RPC on ${published}, not on loopback. Anything that reaches that address can ask this node to stop" ;;
  esac
  have "admin RPC on 127.0.0.1:${port}"

  # The account, if the deployment names one. A node still running as root
  # inside its container names none, and the record says nothing rather than
  # inventing a pair: scripts/migrate-node-nonroot.sh writes those three keys
  # when it moves the node, and that is the run that knows them.
  local cuser nuser='' nuid='' ngid=''
  cuser=$(docker inspect "$svc" --format '{{.Config.User}}' 2>/dev/null) || cuser=''
  if [[ "$cuser" =~ ^([0-9]+):([0-9]+)$ ]]; then
    nuid="${BASH_REMATCH[1]}"; ngid="${BASH_REMATCH[2]}"
    nuser=$(getent passwd "$nuid" 2>/dev/null | cut -d: -f1)
    nuser="${nuser:-$(node_account_name)}"
    have "runs as ${nuser} (${nuid}:${ngid}) inside its container"
  else
    warn "${svc} names no account, so it runs as root inside its container. scripts/migrate-node-nonroot.sh moves it off, and records the account it lands on"
  fi

  # An existing record for a DIFFERENT node is not something to overwrite.
  # A host that runs two nodes is a host where the wrong record sends the
  # rotation window at the wrong container.
  local existing=''
  if [[ -f "${ETC_APERIRE}/node.conf" ]]; then
    existing=$(awk -F= '$1=="SERVICE"{sub(/^[^=]*=/,""); print; exit}' "${ETC_APERIRE}/node.conf")
    [[ -z "$existing" || "$existing" == "$svc" ]] \
      || die "${ETC_APERIRE}/node.conf already names ${existing}, and this run measured ${svc}. Two different nodes; move that file aside yourself if ${svc} is the one this host should record"
  fi

  say "recording it"
  write_container_node_conf "the node this installer adopted, measured from the running container" \
    "$svc" "http://127.0.0.1:${port}" "$cfg" "$svc" "$nuser" "$nuid" "$ngid" \
    || die "could not write ${ETC_APERIRE}/node.conf"
  info "${ETC_APERIRE}/node.conf names ${svc}"
  info "no image, no compose file and no config CONTENT was touched, and the node was not restarted."
  echo
  info "what reads it: the store-rotation window, the relay's node label, the"
  info "after-reboot check, the baseline check, the config closer and the"
  info "non-root migration."

  # The one thing adopt changes beyond the record (#462). A node this
  # installer did not deploy has the same world-readable config a node it did
  # deploy has, and adopt is the verb a host reaches for after a wipe-clean
  # uninstall left the node behind. Leaving the file open on that host because
  # this verb is the small one is how a validator token stays readable by
  # every local account. The file's MODE changes; its content does not.
  close_node_config "$cfg"
  return 0
}

# ── Native mode splits off here ──────────────────────────────────────
# Nothing below this belongs to it: no --dir (a package lives where the
# vendor's package puts it), no compose template, no image tag. Only the
# publisher list is shared with the container path, so only it is checked
# for here.
# The source move is the smallest native verb there is (#802): sources, one
# refresh, and out. Nothing below it runs, the publisher list included.
if [[ $MOVE_SOURCE -eq 1 ]]; then
  native_move_source_main
  exit 0
fi
if [[ $NATIVE -eq 1 ]]; then
  [[ -r "${TEMPLATE_DIR}/validators.txt" ]] \
    || die "${TEMPLATE_DIR}/validators.txt is missing from this checkout; the node cannot be installed from a partial copy"
  native_main
  exit $?
fi

# Adopting is not installing, so it splits off before docker is installed, a
# tag is resolved or any directory is created. --native adopts by itself
# whenever it finds a unit; a container node needs asking for, because on this
# path "there is a node here already" is also the ordinary re-run.
if [[ $ADOPT -eq 1 ]]; then
  container_adopt "${ADOPT_NAME}"
  exit $?
fi

if [[ -z "$DIR" ]]; then
  OP_HOME="$(getent passwd "$OPERATOR" | cut -d: -f6)"
  [[ -n "$OP_HOME" ]] || die "cannot find a home directory for '${OPERATOR}'; pass --dir explicitly"
  DIR="${OP_HOME}/aperire-node"
fi
[[ "$DIR" == /* ]] || die "--dir must be an absolute path (got '$DIR')"

COMPOSE_FILE="${DIR}/docker-compose.yml"
CFG_FILE="${DIR}/config/rippled.cfg"
VAL_FILE="${DIR}/config/validators.txt"

for t in aperire-node.compose.yml rippled.stock.cfg validators.txt; do
  [[ -r "${TEMPLATE_DIR}/${t}" ]] \
    || die "${TEMPLATE_DIR}/${t} is missing from this checkout; the node cannot be installed from a partial copy"
done

# ── 1. Docker engine + compose plugin ───────────────────────────────
say "Docker engine and the compose plugin"

have_compose() { docker compose version >/dev/null 2>&1; }

if command -v docker >/dev/null 2>&1 && have_compose; then
  have "$(docker --version 2>/dev/null | head -1), $(docker compose version --short 2>/dev/null | head -1)"
else
  info "installing docker.io and docker-compose-v2"
  # needrestart (present on Ubuntu server) can restart services after an apt
  # run, and on some images it does so without asking. On a host that already
  # runs a node that list includes docker, which would restart the container.
  # List-only mode: it may print, it may not act. Same guard prepare-host.sh
  # applies from the first apt call on a box.
  export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l NEEDRESTART_SUSPEND=1
  apt-get update -qq
  # Two packages, then one, because docker-compose-v2 is not in every release
  # this installs on. A missing compose plugin is caught below either way, so
  # the fallback cannot leave a half-installed engine looking finished.
  if ! apt-get install -y -qq --no-install-recommends docker.io docker-compose-v2; then
    warn "docker-compose-v2 is not available from apt here; installing docker.io alone"
    apt-get install -y -qq --no-install-recommends docker.io
  fi
  command -v docker >/dev/null 2>&1 || die "apt finished but there is no docker on PATH"
  have_compose || die "docker is installed but 'docker compose' is not. Install the compose plugin (apt install docker-compose-plugin, or https://docs.docker.com/compose/install/) and run this again"
  info "installed: $(docker --version 2>/dev/null | head -1), $(docker compose version --short 2>/dev/null | head -1)"
fi

# The daemon has to be up before anything below can ask it a question.
systemctl enable --now docker >/dev/null 2>&1 || true
docker info >/dev/null 2>&1 || die "the docker daemon is not answering (systemctl status docker). Nothing has been written yet"

# ── 2. The docker group ─────────────────────────────────────────────
# Said plainly because it is a real grant: the docker group is root without a
# password. Nothing in this script depends on the membership (it runs as root
# and calls docker directly), so a host that would rather not have it can
# remove the account from the group and everything here still works.
say "docker group for ${OPERATOR}"
if id -nG "$OPERATOR" 2>/dev/null | tr ' ' '\n' | grep -qx docker; then
  have "${OPERATOR} is in the docker group"
else
  usermod -aG docker "$OPERATOR"
  info "added ${OPERATOR} to the docker group"
  warn "${OPERATOR} must log out and back in before 'docker ps' works without sudo."
  warn "Membership of the docker group is root-equivalent: anything that account"
  warn "runs can become root through the daemon. Remove it with"
  warn "'sudo gpasswd -d ${OPERATOR} docker' if you would rather use sudo docker."
fi

# ── 3. The image tag ────────────────────────────────────────────────
# Resolution order, and the middle one is the important one: a re-run keeps
# the tag the node is already on. An installer that re-resolved "newest" on
# every run would stage an upgrade behind the operator's back, on a script
# whose whole job is supposed to be idempotent.
say "image tag"

# The WHOLE image reference an existing compose file names, repository and
# tag. Both, because the repository is not a constant any more: a node
# installed before this release names a registry repository, and a node
# upgraded through the Advisor names the local build. A re-run that read the
# tag alone would hand "3.3.0" to a default repository that has no such
# image, and rewrite a working deployment into one that cannot start.
compose_image() {  # the image reference already written into an existing compose file
  [[ -f "$COMPOSE_FILE" ]] || return 1
  sed -n "s#^[[:space:]]*image:[[:space:]]*\\([^[:space:]]*\\).*#\\1#p" "$COMPOSE_FILE" | head -1
}

# repo, tag and digest out of one image reference.
#
# A digest-pinned line is `repo:tag@sha256:...`, and its LAST colon belongs
# to the digest. `${ref##*:}` on one of those answers with 64 hex characters
# and `${ref%:*}` answers with `repo:tag@sha256`, so a re-run over a
# deployment this installer itself wrote would resolve a repository that
# does not exist and a tag that is not a version. The digest is taken off
# the end first, which is the same order the Advisor's own splitImage uses.
split_image_ref() {  # $1 = reference; sets SPLIT_REPO, SPLIT_TAG, SPLIT_DIGEST
  local ref=$1
  SPLIT_REPO="" SPLIT_TAG="" SPLIT_DIGEST=""
  if [[ "$ref" == *@* ]]; then
    SPLIT_DIGEST="${ref##*@}"
    ref="${ref%@*}"
  fi
  # A colon in the last path segment is a tag; a colon before a slash is a
  # registry port, and that reference carries no tag at all.
  if [[ "$ref" == *:* && "${ref##*:}" != */* ]]; then
    SPLIT_TAG="${ref##*:}"
    SPLIT_REPO="${ref%:*}"
  else
    SPLIT_REPO="$ref"
  fi
}

# The digest the official tag points at right now, or nothing at all.
#
# Nothing at all covers every way this can fail and they are deliberately
# one answer: no tag, no network, a registry that would not answer, a reply
# in a shape this does not recognise. All of them mean the same thing here,
# which is that this install builds from the signed package instead. That is
# a path that needs no registry, so a registry outage never blocks an
# install; it only decides which of two good sources this node uses.
official_image_digest() {
  local version=$1 body digest
  [[ "$version" =~ ^[0-9]{1,5}(\.[0-9]{1,5}){0,3}$ ]] || return 1
  command -v curl >/dev/null 2>&1 || return 1
  body=$(curl -fsS --max-time 15 \
    "https://hub.docker.com/v2/repositories/${OFFICIAL_IMAGE_REPO}/tags/${version}" 2>/dev/null) \
    || return 1
  # The tag that came back has to be the tag that was asked for. A registry
  # answering 200 about something else is not an answer to this question.
  printf '%s' "$body" | grep -q "\"name\"[[:space:]]*:[[:space:]]*\"${version}\"" || return 1
  digest=$(printf '%s' "$body" \
    | sed -n 's#.*"digest"[[:space:]]*:[[:space:]]*"\(sha256:[0-9a-f]\{64\}\)".*#\1#p' | head -1)
  [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || return 1
  printf '%s' "$digest"
}

if [[ -n "$IMAGE_TAG" ]]; then
  info "pinned by --image-tag: ${IMAGE_TAG}"
  info "${S_DIM}(the image is built here from the signed package unless this node already runs one from a registry)${S_OFF}"
  if EXISTING_IMAGE="$(compose_image)" && [[ "$EXISTING_IMAGE" == *:* ]]; then
    split_image_ref "$EXISTING_IMAGE"
    IMAGE_REPO="$SPLIT_REPO"
    # A digest pins ONE release. Carrying the old one onto a different tag
    # would write `repo:3.4.2@sha256:<3.4.1's digest>`: the file would say
    # one release, docker would run another, and every reading that trusts
    # the tag (the rollback's own lookup among them) would be wrong about
    # what the node runs. Met in review on 2026-09-27.
    if [[ "$IMAGE_REPO" == "$OFFICIAL_IMAGE_REPO" ]]; then
      if [[ "$SPLIT_TAG" == "$IMAGE_TAG" ]]; then
        IMAGE_DIGEST="$SPLIT_DIGEST"
      else
        # A different release: look up ITS digest, and say so if the
        # registry cannot answer. Falling back to the tag alone would turn
        # a pinned deployment into a mutable one without anybody asking.
        IMAGE_DIGEST="$(official_image_digest "$IMAGE_TAG")" || IMAGE_DIGEST=""
        if [[ -n "$IMAGE_DIGEST" ]]; then
          info "pinning ${IMAGE_TAG} to ${IMAGE_DIGEST}, the digest that tag has now"
        else
          die "this deployment is pinned by digest and no official image could be found for ${IMAGE_TAG}. Nothing was changed: a pinned line is not turned into a mutable one to satisfy a --image-tag"
        fi
      fi
    fi
  fi
elif EXISTING_IMAGE="$(compose_image)" && [[ "$EXISTING_IMAGE" == *:* ]]; then
  split_image_ref "$EXISTING_IMAGE"
  IMAGE_REPO="$SPLIT_REPO"
  IMAGE_TAG="$SPLIT_TAG"
  IMAGE_DIGEST="$SPLIT_DIGEST"
  info "keeping the image this node is already on: ${EXISTING_IMAGE}"
  info "${S_DIM}(upgrades are a runbook, not a re-install; pass --image-tag to move it deliberately)${S_OFF}"
else
  IMAGE_TAG="$PINNED_TAG"
  # One question about one tag, by name. Never a tag list: that repository
  # carries hundreds of tags and most of them are not releases (commit
  # hashes, `develop`, release candidates), and a walk of it is a thing to
  # filter correctly forever. A tag that is not there answers 404, which is
  # a real answer and the build's cue.
  IMAGE_DIGEST="$(official_image_digest "$IMAGE_TAG")" || IMAGE_DIGEST=""
  if [[ -n "$IMAGE_DIGEST" ]]; then
    IMAGE_REPO="$OFFICIAL_IMAGE_REPO"
    info "using the official image for ${IMAGE_TAG}, pinned at ${IMAGE_DIGEST}"
  else
    info "no official image carries ${IMAGE_TAG} yet"
    info "building ${IMAGE_REPO}:${IMAGE_TAG} on this host, from the XRPL Foundation's signed package"
  fi
fi

# Whether this run has to build. A registry repository is pulled by compose
# as it always was; the local name has no registry behind it and the image
# has to exist here before anything points a deployment at it.
BUILD_IMAGE=0
[[ "$IMAGE_REPO" == localhost/* ]] && BUILD_IMAGE=1
PULL_POLICY=missing
(( BUILD_IMAGE )) && PULL_POLICY=never
# What goes into the deployment file. Tag AND digest for an official pull, so
# the file says which release it is and pulls exactly one set of bytes; the
# tag alone everywhere else.
IMAGE_REF="${IMAGE_REPO}:${IMAGE_TAG}"
[[ -n "$IMAGE_DIGEST" ]] && IMAGE_REF="${IMAGE_REPO}:${IMAGE_TAG}@${IMAGE_DIGEST}"

# ── 4. Confirm ──────────────────────────────────────────────────────
cat <<EOF

  ${S_BOLD}About to install an XRPL node on this host${S_OFF}

    name        ${NAME}
    directory   ${DIR}
    image       ${IMAGE_REPO}:${IMAGE_TAG}
    network     ${NET}
    role        ${ROLE}
    ports       ${HOST_PEER_PORT} public (peers), ${ADMIN_RPC_PORT} and ${ADMIN_WS_PORT} on 127.0.0.1 only

EOF
if [[ $ASSUME_YES -ne 1 ]]; then
  if [[ -t 0 ]]; then
    read -r -p "  Proceed? [Y/n] " reply
    case "$reply" in n|N|no|NO) echo "  stopped, nothing was changed."; exit 0 ;; esac
  else
    die "nothing here to ask, and --yes was not passed. Nothing has been changed"
  fi
fi

# ── 5. The account, and the directories ─────────────────────────────
say "the account the node runs as"
NODE_ACCOUNT_LINE="$(node_account_ensure)" \
  || die "could not resolve or create the account the node runs as. Nothing has been changed"
IFS=$'\t' read -r NODE_USER NODE_UID NODE_GID <<< "$NODE_ACCOUNT_LINE"
[[ -n "$NODE_USER" && -n "$NODE_UID" && -n "$NODE_GID" ]] \
  || die "the account the node runs as resolved to an incomplete answer ('${NODE_ACCOUNT_LINE}')"
have "${NODE_USER}, uid ${NODE_UID} gid ${NODE_GID}"

say "directories under ${DIR}"
# Created with an owner and a mode; left alone once they exist. `install -d`
# applies -o and -m to a directory that is already there, and the config
# directory is one close-node-config-exposure.sh deliberately closes to 0750
# on a host that carries a validator token. A re-run would have widened it
# back to 0755 and said nothing, which is a re-run undoing a security change
# by tidying.
for d in "$DIR" "${DIR}/config"; do
  [[ -d "$d" ]] || install -d -o "$OPERATOR" -g "$OPERATOR" -m 0755 "$d"
done

# A node installed before #31 runs as root inside its container, its data/ is
# root-owned, and its config is group-readable by root because that is how
# container-root reads it. Every line below would be correct on that host and
# the run as a whole would not be: rewriting the compose recreates the
# container as a non-root user against a store it cannot write, which is a
# crash loop, and moving the config's group takes the read away from the node
# that is running right now. So this run leaves an older shape exactly as it
# found it and names the one script that moves it, which stops the node first
# and takes the rotation guard. Nothing else here depends on the answer.
LEGACY_ROOT_SHAPE=0
if [[ -d "${DIR}/data" ]]; then
  data_owner="$(stat -c '%U' "${DIR}/data" 2>/dev/null || echo unknown)"
  if [[ "$data_owner" != "$NODE_USER" ]]; then
    LEGACY_ROOT_SHAPE=1
    warn "${DIR}/data is owned by ${data_owner}, not ${NODE_USER}: this node was installed before it ran as a non-root user."
    warn "Leaving its ownership and its compose file alone. To move it:"
    warn "    curl -fsSL https://get.aperire.one | bash -s -- --run migrate-node"
  fi
else
  # Owned by the node's own account, 0755. Dropping ALL capabilities leaves
  # the process bound by these modes whatever uid it is, so a directory the
  # node does not own crash-loops the very first start on "Can not create
  # /var/lib/xrpld/db". 0755 keeps the dashboard's ledger-store sizing walk
  # and any backup working; it is public ledger data.
  install -d -o "$NODE_USER" -g "$NODE_USER" -m 0755 "${DIR}/data"
fi
info "config/ owned by ${OPERATOR}, data/ owned by ${NODE_USER} (the node writes its store and its log there)"

# ── 6. The config ───────────────────────────────────────────────────
say "node config"

# An existing config is the operator's, always. rippled.cfg is where a
# validator token lives; a script that overwrote one would take a validator's
# identity away on a re-run and report success.
if [[ -f "$CFG_FILE" ]]; then
  have "${CFG_FILE} exists; keeping it exactly as it is"
  info "${S_DIM}(nothing here edits a config it did not write. To start from the shipped stock config, move yours aside first.)${S_OFF}"
else
  # Group ${NODE_USER}, so the node can read it through the group once the
  # file is closed to everyone else. The MODE written here is still the open
  # one, 0644, or 0640 on a validator: tightening a config a co-located relay
  # may be parsing for its port list is close-node-config-exposure.sh's job,
  # because that script grants the relay its read first and proves the node
  # still opens the file afterwards. The difference since #462 is that this
  # installer now CALLS that script at the end of the run rather than leaving
  # it to the Advisor one-liner, so the file does not stay at 0644 on a host
  # that never installs an Advisor. The group is what makes the tightening
  # possible at all.
  #
  # On a greenfield host that close grants the relay nothing, because this
  # script runs before the one-liner that creates aperire-relay. The relay
  # installer closes that loop itself: it calls the same script once, when the
  # account it just created cannot read the config its relay.conf names.
  _tpl="$(checked_template rippled.stock.cfg)" || exit 1
  install -o "$OPERATOR" -g "$NODE_USER" -m 0644 "$_tpl" "$CFG_FILE"
  rm -f "$_tpl"
  info "wrote ${CFG_FILE} from the shipped stock config, group ${NODE_USER}"
  [[ "$ROLE" == "validator" ]] && append_validator_token_stanza "$CFG_FILE"
fi

if [[ -f "$VAL_FILE" ]]; then
  have "${VAL_FILE} exists; keeping it"
else
  _tpl="$(checked_template validators.txt)" || exit 1
  install -o "$OPERATOR" -g "$NODE_USER" -m 0644 "$_tpl" "$VAL_FILE"
  rm -f "$_tpl"
  info "wrote ${VAL_FILE} (the mainnet publisher lists, verbatim from upstream)"
fi

# ── 6b. The image, built here ───────────────────────────────────────
# Before the compose file names it, and before anything starts: with
# pull_policy: never, a deployment naming an image that is not here fails at
# once rather than reaching for a registry that cannot serve this name.
#
# The recipe is installed root-owned first, and the build runs from THERE,
# never from this checkout. That is the rule the privilege wrapper holds to
# as well: the tree is writable by the account that serves the dashboard, and
# a root build reading its Dockerfile from there would be that account's
# build.
if [[ $BUILD_IMAGE -eq 1 ]]; then
  say "building ${IMAGE_REPO}:${IMAGE_TAG}"
  if docker image inspect "${IMAGE_REPO}:${IMAGE_TAG}" >/dev/null 2>&1; then
    have "${IMAGE_REPO}:${IMAGE_TAG} is already on this host; not rebuilding"
    info "${S_DIM}(two builds of one release are different images; a rebuild would move the tag off the one a node runs)${S_OFF}"
  else
    bash "${SCRIPTS_DIR}/install-xrpld-image-recipe.sh" >/dev/null \
      || die "the image recipe could not be installed under ${IMAGE_RECIPE_DIR}. Nothing has been started"
    info "this takes about a minute. It checks the signing key's fingerprint, installs one exact"
    info "package version through apt's own signature checking, and proves what it built."
    bash "${IMAGE_RECIPE_DIR}/build-xrpld-image.sh" --version "$IMAGE_TAG" \
      || die "the image build failed. Nothing has been started, and nothing about this host changed"
  fi
  docker image inspect "${IMAGE_REPO}:${IMAGE_TAG}" >/dev/null 2>&1 \
    || die "the build reported success and ${IMAGE_REPO}:${IMAGE_TAG} is not on this host"
elif [[ -n "$IMAGE_DIGEST" ]]; then
  # Pulled by digest before the deployment names it, so a registry that
  # cannot answer is a refusal here, with its own sentence, rather than a
  # container that will not start for a reason nobody reads until later.
  say "pulling ${IMAGE_REF}"
  docker pull "${IMAGE_REPO}@${IMAGE_DIGEST}" >/dev/null \
    || die "the official image for ${IMAGE_TAG} could not be pulled. Nothing has been started, and nothing about this host changed"
  docker image inspect "${IMAGE_REPO}@${IMAGE_DIGEST}" >/dev/null 2>&1 \
    || die "the pull reported success and ${IMAGE_REPO}@${IMAGE_DIGEST} is not on this host"

  # And CHECKED, on this host, before the deployment file names it (#682,
  # second review, and the lead's ruling with it). The upgrade path spent a
  # review learning that an image is not trusted because a registry served
  # it; a fresh install taking the same image on the strength of the tag
  # alone was the same claim through a quieter door, and it is the FIRST
  # image most operators will ever run.
  #
  # Same check the Advisor makes: the binary inside the image against the
  # binary inside the .deb apt just verified, with the container created
  # and never started. It needs the wrapper and its recipe, which this
  # script has just installed.
  IMAGE_VERIFIED=0
  VERIFY_LOG="$(mktemp)"; SCRAPS+=("$VERIFY_LOG")
  # A file, run through bash: the staged copy may sit on a /tmp mounted
  # noexec (#764), and that must not read as "no wrapper", which skips the check.
  if [[ -f "$NODE_WRAPPER" ]]; then
    say "checking that image against the XRPL Foundation's signed package"
    VERIFY_RC=0
    bash "$NODE_WRAPPER" verify-official-image \
      "$IMAGE_TAG" "$IMAGE_DIGEST" >/dev/null 2>"$VERIFY_LOG" || VERIFY_RC=$?
    if (( VERIFY_RC == 0 )); then
      IMAGE_VERIFIED=1
      info "the binary in that image is the binary in the signed package"
    elif (( VERIFY_RC == 64 )); then
      warn "that image did not check out against the signed package:"
      sed 's/^/    /' "$VERIFY_LOG" | tail -5
    else
      # Two different sentences, because they mean different things: an
      # image that failed its check is a finding, and a check that could
      # not run is this host missing something. Saying the first when the
      # second happened is telling an operator their image is bad.
      warn "that image could not be checked on this host:"
      sed 's/^/    /' "$VERIFY_LOG" | tail -5
    fi
  else
    warn "the privilege wrapper is not here, so that image could not be checked on this host"
  fi
  if (( ! IMAGE_VERIFIED )); then
    # Falling back to the build rather than installing something unproven.
    # The build reaches the same release through the chain this does trust,
    # and it says so rather than doing it quietly.
    warn "building ${DEFAULT_IMAGE_REPO}:${IMAGE_TAG} here instead, from that same signed package"
    IMAGE_REPO="$DEFAULT_IMAGE_REPO"
    IMAGE_DIGEST=""
    IMAGE_REF="${IMAGE_REPO}:${IMAGE_TAG}"
    PULL_POLICY=never
    bash "${IMAGE_RECIPE_DIR}/build-xrpld-image.sh" --version "$IMAGE_TAG" \
      || die "the official image could not be verified and the build from the signed package failed too. Nothing has been started, and nothing about this host changed"
    docker image inspect "${IMAGE_REPO}:${IMAGE_TAG}" >/dev/null 2>&1 \
      || die "the build reported success and ${IMAGE_REPO}:${IMAGE_TAG} is not on this host"
  fi
fi

# ── 7. The compose file ─────────────────────────────────────────────
say "hardened compose"

# sed over placeholders, never a heredoc. The healthcheck line carries
# backslash escapes that do not survive being re-emitted through a shell, and
# a healthcheck that never matches is a container that reports unhealthy
# forever while the node underneath it is fine.
# Cleaned up by on_exit, the one EXIT trap this script installs. A second
# trap here would replace that one and take the "say why" guard with it.
RENDERED="$(mktemp)"
_tpl="$(checked_template aperire-node.compose.yml)" || exit 1
sed -e "s#@NAME@#${NAME}#g" \
    -e "s#@DIR@#${DIR}#g" \
    -e "s#@IMAGE@#${IMAGE_REF}#g" \
    -e "s#@PULL_POLICY@#${PULL_POLICY}#g" \
    -e "s#@UID@#${NODE_UID}#g" \
    -e "s#@GID@#${NODE_GID}#g" \
    "$_tpl" > "$RENDERED"
rm -f "$_tpl"

grep -q '@[A-Z]*@' "$RENDERED" \
  && die "the compose template still holds an unsubstituted placeholder after rendering: $(grep -o '@[A-Z]*@' "$RENDERED" | sort -u | tr '\n' ' ')"

# A compose scripts/migrate-node-nonroot.sh patched in place, recognised from
# the file itself and confirmed against the record (#441). The migration adds
# three things this installer's own template also has, so a migrated file and
# a fresh render agree from `name:` down; what they do not agree on is the
# comment block above it, which came from whichever release rendered the file
# first. `cmp` sees that difference and nothing else, and the branch below it
# would take a working, migrated host, overwrite its deployment and start the
# node from the replacement in the same run.
#
# So the shape is read rather than inferred from bytes being equal: a `user:`
# line and the config mounted at the path the node opens. NODE_UID and
# NODE_GID in /etc/aperire/node.conf are the migration's own record of what it
# chose, and they are compared rather than required: a host whose record was
# taken by a wipe-clean uninstall (#434) is still migrated, and the compose is
# still the thing not to overwrite.
COMPOSE_MIGRATED=0
COMPOSE_USER_IDS=''
RECORDED_IDS=''
if [[ -f "$COMPOSE_FILE" ]]; then
  COMPOSE_USER_IDS=$(sed -nE 's/^[[:space:]]*user:[[:space:]]*"([0-9]+:[0-9]+)".*/\1/p' "$COMPOSE_FILE" | head -1)
  if [[ -n "$COMPOSE_USER_IDS" ]] && grep -qF ":/etc/xrpld/xrpld.cfg:ro" "$COMPOSE_FILE"; then
    COMPOSE_MIGRATED=1
  fi
fi
if [[ -f "${ETC_APERIRE}/node.conf" ]]; then
  rec_uid=$(awk -F= '$1=="NODE_UID"{sub(/^[^=]*=/,""); print; exit}' "${ETC_APERIRE}/node.conf")
  rec_gid=$(awk -F= '$1=="NODE_GID"{sub(/^[^=]*=/,""); print; exit}' "${ETC_APERIRE}/node.conf")
  [[ -n "$rec_uid" && -n "$rec_gid" ]] && RECORDED_IDS="${rec_uid}:${rec_gid}"
fi

if [[ $LEGACY_ROOT_SHAPE -eq 1 ]]; then
  # Said again here, where the file would have been written, because this is
  # the line that would have recreated the container.
  warn "not writing ${COMPOSE_FILE}: it would start this node as ${NODE_USER} against a store it does not own."
  warn "scripts/migrate-node-nonroot.sh does both halves in the right order, with the node stopped."
elif [[ -f "$COMPOSE_FILE" ]] && cmp -s "$RENDERED" "$COMPOSE_FILE"; then
  have "${COMPOSE_FILE} is already what this template renders; unchanged"
elif [[ $COMPOSE_MIGRATED -eq 1 ]]; then
  have "${COMPOSE_FILE} was migrated onto a non-root account (user: \"${COMPOSE_USER_IDS}\"); keeping it"
  if [[ -n "$RECORDED_IDS" ]]; then
    info "${ETC_APERIRE}/node.conf records the same account (${RECORDED_IDS})"
  fi
  # Keeping the file is the whole of #441, and it is also the point at which
  # this run can swallow something the operator asked for. The two markers
  # above separate a post-#31 deployment from the pre-#31 root shape; they do
  # not separate a hand-edited deployment from one this template renders
  # identically, because today's template carries both markers too. Only the
  # body answers that: from `name:` down is the deployment, and everything
  # above it is the comment header whichever release rendered the file first
  # left behind (#438). So the body is compared, and if it differs, what this
  # run resolved and did not write is named rather than implied.
  RENDERED_BODY=$(sed -n '/^name:/,$p' "$RENDERED")
  CURRENT_BODY=$(sed -n '/^name:/,$p' "$COMPOSE_FILE")
  if [[ "$RENDERED_BODY" == "$CURRENT_BODY" ]]; then
    info "it is already what this template renders, apart from the comment header above its name: line"
  else
    warn "it differs from what this run would render, and nothing here overwrote it."
    EXISTING_IMAGE=$(compose_image || true)
    if [[ -n "$EXISTING_IMAGE" && "$EXISTING_IMAGE" != "$IMAGE_REF" ]]; then
      warn "the image was NOT applied: this file names ${EXISTING_IMAGE} and this run resolved ${IMAGE_REF}."
      warn "to move it on this deployment, edit its image line and recreate:"
      if (( BUILD_IMAGE )); then
        warn "  sudo aperire-node-wrapper${APERIRE_INSTANCE:+-$APERIRE_INSTANCE} set-image-local ${IMAGE_TAG}   (where the wrapper is configured)"
      elif [[ -n "$IMAGE_DIGEST" ]]; then
        # Verify first, then set: the wrapper refuses a digest this host has
        # not checked, which is the point of the check (#682).
        warn "  sudo aperire-node-wrapper${APERIRE_INSTANCE:+-$APERIRE_INSTANCE} verify-official-image ${IMAGE_TAG} ${IMAGE_DIGEST}   (where the wrapper is configured)"
        warn "  sudo aperire-node-wrapper${APERIRE_INSTANCE:+-$APERIRE_INSTANCE} set-image-official ${IMAGE_TAG} ${IMAGE_DIGEST}"
      else
        warn "  sudo aperire-node-wrapper${APERIRE_INSTANCE:+-$APERIRE_INSTANCE} set-image ${IMAGE_TAG}   (where the wrapper is configured)"
      fi
      warn "  or change 'image: ${EXISTING_IMAGE}' in ${COMPOSE_FILE}, then docker compose -f ${COMPOSE_FILE} up -d"
    fi
  fi
  if [[ "$COMPOSE_USER_IDS" != "${NODE_UID}:${NODE_GID}" ]]; then
    # Not overwritten either way. The file is still the one the running store
    # was chowned for, and the account this run resolved is the one this host
    # has now; which of the two is wrong is not something to decide by
    # rewriting the deployment.
    warn "it names ${COMPOSE_USER_IDS} and the ${NODE_USER} account here is ${NODE_UID}:${NODE_GID}."
    warn "check who owns ${DIR}/data before the next recreate: a node that does not own its store cannot open it."
  fi
  info "${S_DIM}(a migrated deployment is not re-rendered from the template. To start from the shipped one, move yours aside first.)${S_OFF}"
else
  if [[ -f "$COMPOSE_FILE" ]]; then
    cp -p "$COMPOSE_FILE" "${COMPOSE_FILE}.prev"
    warn "the compose file differed from the template; the old one is at ${COMPOSE_FILE}.prev"
  fi
  install -o "$OPERATOR" -g "$OPERATOR" -m 0644 "$RENDERED" "$COMPOSE_FILE"
  info "wrote ${COMPOSE_FILE}"
fi

# ── 8. Start ────────────────────────────────────────────────────────
say "starting ${NAME}"
docker compose -f "$COMPOSE_FILE" up -d \
  || die "docker compose refused to start the node. Nothing above it was undone; fix and run this again"

# ── 9. Verify, out loud ─────────────────────────────────────────────
# The same three verdicts the preflight uses, and only one of them blocks:
#   ok       measured, and it is what a running node looks like
#   warn     measured, and expected on a node this young
#   FAILED   this is not a working node
say "verifying"

# The container. Health first, because "running" is not "answering": the
# healthcheck asks the node for server_state and a container can be up with a
# node inside it that never opened a port. Read AFTER the wait below has had
# its turn, so a node that took a minute to answer reads as what it is now.
container_health() {
state="$(docker inspect -f '{{.State.Status}}' "$NAME" 2>/dev/null || true)"
health="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$NAME" 2>/dev/null || true)"
if [[ "$state" != "running" ]]; then
  v_failed "container ${NAME}: ${state:-not found}"
else
  case "$health" in
    healthy)   v_ok "container ${NAME}: running, healthy" ;;
    starting)  v_warn "container ${NAME}: running, health check still in its start period (120s)" ;;
    unhealthy) v_failed "container ${NAME}: running but UNHEALTHY (docker logs ${NAME})" ;;
    *)         v_warn "container ${NAME}: running, no health status yet" ;;
  esac
fi
}

# Who the node is running as, asked of the process and not of the file that
# was written. `id -u` inside the container with no -u flag on the exec runs
# as the user the deployment configured, so this reads the same account the
# node's own process has. A compose that lost its user: line starts a node as
# root and looks identical from outside.
container_user() {
  local seen
  seen="$(docker exec "$NAME" id -u 2>/dev/null || true)"
  case "$seen" in
    '')      v_warn "could not ask the container what user it runs as (no shell, or it is not running)" ;;
    0)
      # Root, on a host this run deliberately left on its older shape, is not
      # a failure: it is the state the run just explained and declined to
      # change. Calling it FAILED would contradict the instruction printed
      # two steps earlier, and an operator reading a red line does not read
      # the amber one above it.
      if [[ $LEGACY_ROOT_SHAPE -eq 1 ]]; then
        v_warn "the node is still running as root inside its container, which is what this run left alone. scripts/migrate-node-nonroot.sh moves it"
      else
        v_failed "the node is running as ROOT inside its container. The compose file's user: line is missing or was not applied"
      fi ;;
    "$NODE_UID") v_ok "the node runs as uid ${seen} (${NODE_USER}), not root" ;;
    *)       v_warn "the node runs as uid ${seen}, and this install resolved ${NODE_USER} to ${NODE_UID}" ;;
  esac
}

# `|| true` is load-bearing: without it a curl that refused would end the run
# through set -e, at the exact moment the script has something worth saying.
#
# Asked more than once. A node opens its admin RPC some way into its start,
# and the first live run (aperire4, 2026-09-08) asked once, seconds after
# `up`, read nothing, and called a node FAILED that answered thirty seconds
# later. The wait is the container's own start period, which is the time the
# healthcheck gives it too; a node silent past that has something to say.
waited=0
SI1="$(server_info || true)"
while [[ -z "$(printf '%s' "$SI1" | json_field server_state)" && $waited -lt $NODE_WAIT_SECS ]]; do
  printf '\r   %swaiting for the node to open its admin RPC on 127.0.0.1:%s  %ss of %ss%s   ' \
    "$S_DIM" "$ADMIN_RPC_PORT" "$waited" "$NODE_WAIT_SECS" "$S_OFF"
  sleep 5; waited=$((waited + 5))
  SI1="$(server_info || true)"
done
[[ $waited -gt 0 ]] && printf '\r%*s\r' 78 ''
container_health
container_user
for p in "$ADMIN_RPC_PORT" "$ADMIN_WS_PORT"; do
  case "$(port_state "$p")" in
    loopback)  v_ok "127.0.0.1:${p} is listening, on loopback only" ;;
    unchecked) v_ok "127.0.0.1:${p} answers (no ss here, so the bind address was not checked)" ;;
    wildcard)  v_failed "port ${p} is listening on a WILDCARD address, not 127.0.0.1. This is an admin port: anything that reaches it can stop this node. Check the ports: block in ${COMPOSE_FILE}" ;;
    *)         v_failed "127.0.0.1:${p} is not listening (the dashboard reads the node through these two)" ;;
  esac
done
SRV_STATE="$(printf '%s' "$SI1" | json_field server_state)"
if [[ -z "$SRV_STATE" ]]; then
  v_failed "server_info did not answer on 127.0.0.1:${ADMIN_RPC_PORT} within ${NODE_WAIT_SECS}s"
  info "${S_DIM}what came back: ${SI1:-nothing at all}${S_OFF}"
else
  [[ $waited -gt 0 ]] && v_ok "the node opened its admin RPC after ${waited}s"
  BUILD="$(printf '%s' "$SI1" | json_field build_version)"
  v_ok "server_info answers: server_state=${SRV_STATE}${BUILD:+, build ${BUILD}}"
fi

# The ledger sequence, twice. A node that answers but does not move is a node
# with no peers, which looks healthy and is not.
#
# This one WARNS and never fails. A store this young spends its first phase
# connected and empty with no sequence to report at all, and a hard failure
# here would end every honest fresh install in red.
if [[ -n "$SRV_STATE" ]]; then
  SEQ1="$(printf '%s' "$SI1" | json_field seq)"
  sleep 8
  SEQ2="$(server_info 2>/dev/null | json_field seq || true)"
  if [[ "$SEQ1" =~ ^[0-9]+$ && "$SEQ2" =~ ^[0-9]+$ && "$SEQ2" -gt "$SEQ1" ]]; then
    v_ok "ledger sequence advanced: ${SEQ1} -> ${SEQ2}"
  elif [[ -n "$SEQ2" ]]; then
    v_warn "ledger sequence has not moved yet (${SEQ1:-none} -> ${SEQ2}); normal in the first minutes"
  else
    v_warn "no validated ledger to report yet; the node is still acquiring its first one"
  fi
fi

# The trusted validator set. This is the failure the four checks above cannot
# see: a node whose publisher lists never loaded peers, syncs, reaches full and
# answers every one of them, and validates nothing, forever. Nothing else in
# the output would ever mention it.
#
# Warn, never fail: a node this young legitimately has not fetched its lists
# yet. What matters is that it is SAID.
if [[ -n "$SRV_STATE" ]]; then
  TRUSTED="$(curl -s --max-time 10 -H 'Content-Type: application/json' \
      -d '{"method":"validators","params":[{}]}' "http://127.0.0.1:${ADMIN_RPC_PORT}/" 2>/dev/null \
    | tr -d ' \n' \
    | sed -n 's/.*"trusted_validator_keys":\[\([^]]*\)\].*/\1/p' \
    | { grep -o '"[^"]*"' || true; } | wc -l)"
  # The braces and the `|| true` are the point: an EMPTY trusted set is the
  # case this whole check exists for, grep returns 1 when it matches nothing,
  # and under `set -o pipefail` that ends the run at the moment it has
  # something to say. It did, before this line.
  if [[ "${TRUSTED:-0}" -gt 0 ]]; then
    v_ok "${TRUSTED} trusted validators, so the publisher lists in validators.txt loaded"
  else
    v_warn "no trusted validators yet. Until the publisher lists in ${VAL_FILE} load, this node can sync and never validate. Re-check in a few minutes: curl -s -d '{\"method\":\"validators\",\"params\":[{}]}' http://127.0.0.1:${ADMIN_RPC_PORT}/"
  fi
fi

# Memory, said now rather than discovered as an OOM kill in a week. The config
# ships node_size=medium and the compose caps the container at 20g.
MEM_GB="$(awk '/^MemTotal:/ {printf "%d", $2/1048576}' /proc/meminfo 2>/dev/null || echo 0)"
if [[ "${MEM_GB:-0}" -gt 0 && "${MEM_GB}" -lt 8 ]]; then
  v_warn "this host has ${MEM_GB} GB of RAM. A mainnet node wants 16 GB or more; below 8 GB it will struggle to stay synced"
fi

cat <<EOF

  ${S_BOLD}What a syncing node looks like${S_OFF}

  server_state walks: ${S_CYAN}connected${S_OFF} -> ${S_CYAN}syncing${S_OFF} -> ${S_CYAN}tracking${S_OFF} -> ${S_CYAN}full${S_OFF}
  (a validator with a token then reads ${S_CYAN}proposing${S_OFF}). It does not walk that in
  a straight line, and it can drop back a step while it finds peers.

  Right now it is: ${S_CYAN}${SRV_STATE:-not answering yet}${S_OFF}

  A brand new store starts empty and has no ledger to report at all. Reaching
  full is a matter of hours, not minutes, and the store keeps filling behind
  it until it holds the whole online_delete window. During that phase the
  dashboard's health endpoint answers ok:false on ledger_age - that is the
  node syncing, not a broken install.

  Watch it:
      ${S_CYAN}docker logs -f ${NAME}${S_OFF}
      ${S_CYAN}curl -s -d '{"method":"server_info","params":[{}]}' http://127.0.0.1:${ADMIN_RPC_PORT}/${S_OFF}

EOF

# ── 10. What the rest of the install expects ────────────────────────
say "wiring for the dashboard"

# The one thing this script does write: which node it put here.
#
# The rotation-window installer (scripts/install-can-delete-timer.sh) needs the
# container's name, its admin RPC and its config file, and until now it could
# only read them from the Advisor's wrapper configuration. On a co-located box
# with no Advisor there is no such file, so every one of those installs ended
# with "no node container name, set APERIRE_NODE_SERVICE, or install the
# Advisor's wrapper first" and no scheduled rotation window (aperire4,
# 2026-09-09, #270). This script knows all three values: it chose them.
#
# Its own file, not the wrapper's. /etc/aperire/node-wrapper.conf is the
# privilege wrapper's security configuration, written whole by
# install-node-wrapper.sh from detection and restored from a .previous copy
# whenever its own verification fails. A partial one written here would become
# what that revert restores: a wrapper configuration with no REPO, PROJECT,
# COMPOSE_FILE or LOG. Two files, one writer each, and the timer reads both.
NODE_CONF="${ETC_APERIRE}/node.conf"
if write_container_node_conf "the node this installer deployed" \
     "$NAME" "http://127.0.0.1:${ADMIN_RPC_PORT}" "$CFG_FILE" "$NAME" \
     "$NODE_USER" "$NODE_UID" "$NODE_GID"; then
  info "${NODE_CONF} names this node (${NAME}), so the rotation window can find it"
else
  warn "could not write ${NODE_CONF}; the store-rotation window will have to be told the node's name:"
  warn "    curl -fsSL https://get.aperire.one | bash -s -- --run rotation-timer --service ${NAME} --admin-rpc http://127.0.0.1:${ADMIN_RPC_PORT}"
fi

# After the record, because the closer finds the node through it, and before
# the V_FAIL block below, so a node that did not come up still gets the
# sentence saying why its config could not be closed (#462).
close_node_config "$CFG_FILE"

# Nothing else to write here on purpose. scripts/detect-rippled-paths.sh finds a
# containerised node by asking docker what is running and mapping the node's
# in-container paths back through the bind mounts, and the mounts this compose
# writes are exactly the ones it looks for. Writing RIPPLED_CFG_PATH by hand
# would be a second source of truth for a value that is already measured.
# Every env file, not just the default one. An operator running one dashboard
# per node (ADR 0009) has aperire-node2.env beside aperire.env, and a node
# installed next to those would otherwise wire the first and leave the rest
# reading "NuDB Size: not set" with nothing saying why.
ENV_FILES=()
while IFS= read -r f; do
  [[ -n "$f" ]] && ENV_FILES+=("$f")
done < <(find "$ETC_APERIRE" -maxdepth 1 -name 'aperire*.env' -type f 2>/dev/null | sort)

if [[ ${#ENV_FILES[@]} -gt 0 ]]; then
  info "a dashboard is already installed here; re-detecting its node paths"
  for f in "${ENV_FILES[@]}"; do
    bash "${SCRIPTS_DIR}/configure-rippled-paths.sh" --env-file "$f" \
      || warn "path detection did not finish for ${f}; run scripts/configure-rippled-paths.sh --env-file ${f} by hand"
  done
else
  DETECTED="$(bash "${SCRIPTS_DIR}/detect-rippled-paths.sh" 2>/dev/null || true)"
  DET_CFG="$(printf '%s\n' "$DETECTED" | sed -n 's/^RIPPLED_CFG_PATH=//p')"
  if [[ -n "$DET_CFG" ]]; then
    info "${S_GREEN}the node is discoverable: detection already resolves this config as ${DET_CFG}${S_OFF}"
  else
    warn "detection did not resolve this node's config path yet; it usually needs the container to have written its store. It is re-run by the dashboard install."
  fi
  info "no dashboard on this host yet, so there is no env file to write into."
fi

if [[ $V_FAIL -gt 0 ]]; then
  cat >&2 <<EOF

${E_RED}The node was installed and it is not working: ${V_FAIL} check(s) FAILED above.${E_OFF}

  Nothing has been rolled back, because a half-started node is worth looking
  at rather than deleting. Start here:

      docker logs --tail 100 ${NAME}
      docker inspect -f '{{json .State.Health}}' ${NAME}

  Then fix and run this again; it is idempotent and keeps your config.

EOF
  exit 1
fi

cat <<EOF

${S_GREEN}${S_BOLD}The node is up.${S_OFF} ${V_OK} check(s) passed.

  ${S_BOLD}Next: install Aperire One beside it${S_OFF}

      ${S_CYAN}curl -fsSL https://get.aperire.one | bash${S_OFF}

  It will find this node by itself. The preflight probes ${ADMIN_WS_PORT}, reads the
  ports out of ${CFG_FILE}, and the role comes out co-located.

EOF
