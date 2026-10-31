#!/usr/bin/env bash
# get-aperire.sh - the one command that puts Aperire One on a fresh box.
#
#   curl -fsSL https://get.aperire.one | bash
#
# Or, when you would rather read it first (and you should):
#
#   curl -fsSL https://get.aperire.one -o get-aperire.sh
#   less get-aperire.sh
#   bash get-aperire.sh
#
# What it does, and nothing more: work out what this host is, fetch the
# release and check it, and hand over to the two scripts that own the
# install. It
# reimplements neither. scripts/prepare-host.sh owns the toolchain (apt
# packages, Node 22, Go, npm ci, the builds) and install.sh owns the
# services, the order they go in, and the plan it prints before it acts.
# install.sh runs prepare-host.sh itself as its first step, so this script
# calls install.sh and stays out of the ordering: one owner, one place a
# change lands.
#
# Roles (--role, or detected from the host):
#   co-located   a node runs on this box: the dashboard and relay beside it
#   dashboard    no node here; this box watches nodes that live elsewhere
#   relay        the node's box in a split install: the relay only.
#                install.sh, the uninstaller and the guides call this role
#                `validator`, and this script does not rename it for them -
#                it accepts `relay` because that is what the box gets, and
#                passes --role=validator on.
#   cli-only     the operator commands on a workstation, no services
#
# Flags (--flag value and --flag=value both work):
#   --role <r>      one of the four above
#   --dir <path>    where the release lands (default $HOME/aperire-one)
#   --ref <ref>     for a git source, the branch, tag or commit to install
#   --source <url>  where the release comes from: a .tar.gz to fetch and
#                   check, or a git remote to clone
#   --sha256 <hex>  the checksum a .tar.gz source has to match
#   --port <n>      dashboard listen port (default 7800)
#   --node          this box has no node yet: put a hardened mainnet node
#                   on it first (scripts/install-aperire-node.sh), then the
#                   dashboard and relay beside it, co-located. The role
#                   prompt offers the same as answer 5
#   --check         run the prerequisite check and stop. Installs nothing,
#                   changes nothing, and exits 0 when this host is ready:
#                       curl -fsSL <url> | bash -s -- --check
#   --update        move a host that is ALREADY installed to this release:
#                       curl -fsSL <url> | bash -s -- --update
#                   The role is read from the units here and never asked, the
#                   database is copied out of the tree first, your data,
#                   config and Advisor state are carried into the new release,
#                   and nothing is restarted until you say so. A host already
#                   on this release is told so and nothing is fetched
#   --force         with --update, apply this release again even when the
#                   stamp says the host is already on it
#   --no-restart    with --update, do not ask about restarting: print the
#                   command instead. What an unattended caller wants
#   --fleet-aggregator <url>
#                   join this box to a fleet at the end of the install:
#                       curl -fsSL <url> | bash -s -- \
#                         --fleet-aggregator https://<your-aggregator>
#                   The install runs to the end, then asks you for a pairing
#                   code on this terminal. Mint the code on the aggregator
#                   (Settings & Updates -> Fleet registry list -> Pair a node)
#                   when it asks and not before: a code is good for fifteen
#                   minutes. A pairing that does not finish leaves this box
#                   installed, enabled and running, and prints the one line
#                   that pairs it later
#   --fleet-label <label>
#                   the name to propose for this node, [a-z0-9-]{1,32}.
#                   Defaults to this host's short name; the aggregator settles
#                   it and you may rename before approving
#                   There is no --fleet-code here, deliberately. This layer
#                   reaches install.sh through sudo, and sudo writes the
#                   command line to /var/log/auth.log, where a live code would
#                   sit for weeks readable by the adm group. The install asks
#                   for the code on the terminal instead. A box that is
#                   already built can take one on install.sh directly, which
#                   has no sudo in its chain when it is already root
#   --node-wrapper [<container>]
#                   a host that is ALREADY installed: write the privilege
#                   wrapper's configuration (/etc/aperire/node-wrapper.conf)
#                   for a node in a docker container. With no name it finds
#                   the node itself; with one it uses that container:
#                       curl -fsSL <url> | bash -s -- --node-wrapper xrpld
#                   Root runs the release's checked copy of the installer,
#                   never the one in your checkout. Letters, digits, dot,
#                   dash and underscore only, starting with a letter or digit
#   --node-wrapper-rpc <port|url>
#                   with --node-wrapper <container>: the node's admin RPC, as
#                   a port (5005) or a loopback http URL
#                   (http://127.0.0.1:5005). Only for a second node on a host,
#                   where the default port belongs to the first one
#   --node-wrapper-native [<unit>]
#                   the same for a node installed from the vendor's package
#                   and run by systemd. With no unit it tries xrpld.service,
#                   then rippled.service
#   --instance <name>
#                   with a --node-wrapper flag: configure the wrapper of a
#                   named Advisor instance rather than the default one,
#                   [a-z0-9-]{1,31}. APERIRE_INSTANCE says the same. With
#                   --refresh-node-key: the instance whose node to ask. With
#                   --fleet-aggregator and --code: the dashboard instance to
#                   pair (only the flag names it, not APERIRE_INSTANCE). A host
#                   with more than one dashboard refuses a pair that names
#                   none; --instance= with nothing after it is the default one
#   --refresh-node-key [--node-key <key>] [--instance <name>]
#                   a host that is ALREADY installed: ask the node who it is
#                   again and stamp the answer as this host's own node key,
#                   which is what lets it tell whether a fleet arm token is
#                   addressed to it. --node-key states the key when the node
#                   cannot be asked (it is down, or its admin RPC is
#                   somewhere unusual); it is checked for shape before any
#                   root call. Root runs the release's checked copy of the
#                   sealer's installer, never the one in your checkout
#   --backup [--to <dir>] [--instance <name>] [--yes] [--dry-run]
#   --restore --from <set> [--instance <name>] [--yes] [--overwrite]
#             [--dry-run] [--db-path <file>] [--replace-trust-pin]
#                   a host that is ALREADY installed: back it up, or put a
#                   backup set back (the set the backup wrote):
#                       curl -fsSL <url> | bash -s -- --backup
#                       curl -fsSL <url> | bash -s -- --restore --from <set>
#                   Everything after --backup or --restore is that program's
#                   own arguments, so --yes there answers its question and not
#                   this script's. Paths are absolute, with letters, digits
#                   and _ . @ + , : = - only, and no . or .. part, and each is
#                   checked before anything runs as root. --dir <install> goes
#                   before the verb or after it. Root runs the release's
#                   checked copy of the program, and the helper it plants
#                   with, never the ones in your checkout
#   --yes, -y       take every default, ask nothing
#   --help, -h
#
# The same values can arrive as environment variables, which is what the
# tests and any automation use: APERIRE_GET_SOURCE_URL, APERIRE_GET_SOURCE_REF,
# APERIRE_GET_EXPECTED_SHA256, APERIRE_GET_SELF_URL, APERIRE_GET_DIR,
# APERIRE_GET_OS_RELEASE, APERIRE_GET_HEALTH_TRIES, APERIRE_GET_HEALTH_SLEEP,
# APERIRE_GET_ETC, APERIRE_GET_SBIN, APERIRE_GET_UNIT_DIR.
#
# ---- the two guards -------------------------------------------------
#
# `curl | bash` runs code nobody read, from a pipe that can be cut in the
# middle. A half-delivered install script is worse than a failed download,
# because the half that arrived still runs. Two guards, and neither is
# optional:
#
#   1. A piped run re-fetches itself to a temporary FILE, checks that the
#      file ends with the sentinel this script's last line carries, and
#      execs that file. A truncated download has no sentinel and is never
#      run. It happens near the top rather than at the bottom on purpose:
#      a pipe cut in the middle never reaches the bottom, so a guard there
#      could not rescue the one run it exists for. From the top, a cut
#      pipe is fetched again whole and re-run from the file. The re-exec
#      also hands the run a terminal back (stdin under a pipe is the pipe,
#      never a keyboard), so the questions below get answered rather than
#      defaulted.
#   2. Everything below guard 1 is a function, and `main` is called on the
#      last line. A copy cut anywhere above that line defines its
#      functions and does nothing at all, which is what covers the case
#      guard 1 cannot: a cut pipe with no network left to re-fetch from.
#
set -euo pipefail

SENTINEL='# --- end of get-aperire.sh ---'

# Where the release comes from, where this script comes from, and what the
# release has to weigh, and which release that is. Seven values, and the
# first four have to agree: a copy served from one endpoint that fetches its
# release from another is a copy nobody can audit by reading it.
#
# So they are not edited by hand. scripts/build-release-snapshot.sh rewrites
# the first four inside the markers below when it builds a release, from the
# one --source-url it was given, and refuses to build if any of those four
# lines has moved. The publisher writes the last three into the copy it
# stages beside the archive, because a tag, a commit and a date are facts
# about a publish rather than about a build. The script and the archive it
# names are published together or not at all: the checksum below is of the
# archive that was built in the same run.
#
# On integrity: the archive is fetched, its sha256 is compared with the one
# stamped here, and only then is anything unpacked. So what an operator gets
# is what this script says it is, or nothing at all, whatever happened to the
# connection or to the endpoint in between.
#
# On authenticity: every published release is signed with the release key,
# which never touches the machine that builds a release or the server that
# serves it. Before the archive is even fetched, this script fetches the
# signed release.json for exactly the archive it names, checks the signature
# with `ssh-keygen -Y verify` against the signer set built into it (the block
# below the stamp), and refuses a release that is unsigned or signed by
# anybody else. No flag turns that check off for a published release. Two
# sources are not published releases and are not checked, and say so when
# used: --source file://<archive> (your own bytes on this box) and --source
# <git remote> (a clone at a ref you chose). What it cannot do is vouch
# for itself: whoever controls the endpoint controls the copy of this script
# you pipe in, which is why docs/RELEASE-SIGNING.md says how to check
# this file by hand first. What the signature does buy, for certain, is every
# update after that: the Update button checks against the key already on the
# host, not against anything it fetched.
#
# The checksum is empty in a copy that came out of a release tree, because no
# archive can carry the checksum of itself. The published copy, served beside
# the archive, is the one that carries it. The three release-identity values
# are empty for the same reason and one more: a copy taken out of a clone was
# never published, so it has no tag and no date to state. What it writes into
# .release then is what it knows, and nothing else (ADR 0022).
# >>> release stamp >>>
DEFAULT_SOURCE_URL='https://get.aperire.one/release.tar.gz'
DEFAULT_SOURCE_REF='snapshot-2026-09-17cc'
DEFAULT_SELF_URL='https://get.aperire.one'
DEFAULT_EXPECTED_SHA256=''
DEFAULT_RELEASE_TAG=''
DEFAULT_RELEASE_COMMIT=''
DEFAULT_PUBLISHED_AT=''
# <<< release stamp <<<

# The keys a release may be signed with, one allowed_signers line each.
# Empty in the repository, and written in by scripts/build-release-snapshot.sh
# from the ref's scripts/release-signers, which docs/RELEASE-SIGNING.md
# publishes beside it. A copy with no key refuses every published release,
# because there is nothing to check a signature against.
# >>> release signers >>>
RELEASE_SIGNERS='aperire-release-key namespaces="aperire-release" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHIkP5Gqz/T/4taeWVb5repX47RKnpgYkNJPJ69Di9kp aperire-release-key-1'
# <<< release signers <<<

SOURCE_URL="${APERIRE_GET_SOURCE_URL:-$DEFAULT_SOURCE_URL}"
SOURCE_REF="${APERIRE_GET_SOURCE_REF:-$DEFAULT_SOURCE_REF}"
EXPECTED_SHA256="${APERIRE_GET_EXPECTED_SHA256:-$DEFAULT_EXPECTED_SHA256}"
DIR="${APERIRE_GET_DIR:-}"
ROLE=""
# 1 once an update has READ the role off the units rather than been told it.
# An inference is not recorded as the install role (#808): a box with a node of
# its own and no relay unit reads as a dashboard here, and recording that
# would switch its rippled bridge off while /healthz reported ok.
ROLE_INFERRED=0
REF_GIVEN=0
PORT="${APERIRE_GET_PORT:-7800}"
PORT_GIVEN=0
ASSUME_YES=0
# --node, or answer 5 at the prompt: a box that is meant to run a node and
# has none yet. The node installer runs first, out of the fetched release,
# and the role is co-located from then on.
NODE_FIRST=0
CHECK_ONLY=0
# The fleet flags, passed straight through to install.sh, which owns the
# pairing step and every refusal about it. Validated here too, because a bad
# origin found after the whole build is a bad origin found an hour late.
FLEET_AGGREGATOR=""
FLEET_LABEL=""
# The pairing code, for a host that turns out to be ALREADY installed: the
# Settings page's mint step prints one line that carries both this and
# --fleet-aggregator, and a copied line has to run as typed. Kept apart from
# --fleet-code below, which this script still refuses for a different host
# shape and a different reason. FLEET_CODE_GIVEN is separate from the value
# because a code read from stdin is a code that was given, and an empty one
# is still a refusal rather than a silent prompt.
FLEET_CODE=""
FLEET_CODE_GIVEN=0
# The privilege wrapper pass-through (#924): --node-wrapper for a container (or
# none named, which detects), --node-wrapper-native for a systemd unit. The
# name and the RPC are held apart from "was the flag given" because a flag
# given with an empty value is a refusal, never a quiet detect. The instance
# comes from the environment too, the way get-aperire-advisor.sh takes it.
SOURCE_FLAGGED=0
WRAPPER_ASKED=0
WRAPPER_NAME=""
WRAPPER_NAME_GIVEN=0
WRAPPER_NATIVE_ASKED=0
WRAPPER_UNIT=""
WRAPPER_UNIT_GIVEN=0
WRAPPER_RPC=""
WRAPPER_RPC_GIVEN=0
WRAPPER_INSTANCE="${APERIRE_INSTANCE:-}"
WRAPPER_INSTANCE_GIVEN=0
# The node-key pass-through (#935): --refresh-node-key re-reads this host's own
# node key into the sealer's stamp, and --node-key states it when the node
# cannot be asked. Same shape of flags as the wrapper's, for the same reason.
REFRESH_NODE_KEY_ASKED=0
NODE_KEY_VALUE=""
NODE_KEY_GIVEN=0
# The backup and restore pass-through (#941): --backup and --restore take
# everything after them as the program's own arguments (BR_ARGS), held to a
# whitelist before any root call, and what passes is BR_PASS, one word each.
BR_VERB=""
BR_ARGS=()
BR_PASS=()
# Set when the release's own preflight ran, which is what lets install.sh be
# told not to run it a second time. Never assumed: a release that predates
# scripts/preflight.sh would refuse an argument it has never heard of.
PREFLIGHT_RAN=0

# Temporary files this run made, removed however it ends. One list and one
# trap, because a second `trap ... EXIT` anywhere would silently replace the
# first and leave whatever it was cleaning up behind.
CLEANUP_PATHS=()
# The same, for what root made: the held copy of the release and anything
# staged beside it. `sudo -n`, because a run that is ending must not stop to
# ask for a password; a sudo that has lapsed leaves a root-only directory in
# /tmp, which the next boot clears.
ROOT_CLEANUP_PATHS=()
cleanup_temporaries() {
  [[ -n "${APERIRE_GET_SELF_TMP:-}" ]] && rm -f "${APERIRE_GET_SELF_TMP}"
  local p
  for p in ${CLEANUP_PATHS[@]+"${CLEANUP_PATHS[@]}"}; do rm -rf "$p"; done
  for p in ${ROOT_CLEANUP_PATHS[@]+"${ROOT_CLEANUP_PATHS[@]}"}; do
    if [[ $EUID -eq 0 ]]; then rm -rf "$p"; else sudo -n rm -rf "$p" 2>/dev/null || true; fi
  done
  # The root-owned directory a signature was checked in, when the run ended
  # before it was kept. Root's, so root removes it; never waits on a password.
  if [[ -n "${ROOT_CLEANUP:-}" && -d "${ROOT_CLEANUP:-}" ]]; then
    if [[ $EUID -eq 0 ]]; then rm -rf "$ROOT_CLEANUP"; else sudo -n rm -rf "$ROOT_CLEANUP" 2>/dev/null || true; fi
  fi
  return 0
}
ROOT_CLEANUP=""

# How long the closing health check waits. Thirty tries two seconds apart:
# a first start builds nothing but does open a database and read a node,
# and a box that has just finished `npm ci` is not a fast box.
HEALTH_TRIES="${APERIRE_GET_HEALTH_TRIES:-30}"
HEALTH_SLEEP="${APERIRE_GET_HEALTH_SLEEP:-2}"

OS_RELEASE="${APERIRE_GET_OS_RELEASE:-/etc/os-release}"
# Where the installers keep the service environment and the relay's config.
# A variable only so the tests can point it somewhere harmless: an installed
# host is recognised by this directory, and a test that had to create the
# real one would be an install.
ETC_APERIRE="${APERIRE_GET_ETC:-/etc/aperire}"
# Where a verified release's signed files are kept, root-owned, one directory
# per archive sha256. The updater reads the kept release.json to refuse a
# release older than this one. A variable only so the tests can point it
# somewhere harmless; it holds evidence, not trust: every read of it
# re-checks the signature.
RELEASE_STORE="${APERIRE_GET_RELEASE_STORE:-/var/lib/aperire/release}"

# The account everything belongs to. Under `curl | sudo bash` that is the
# operator, not root: the services run as them, the checkout is theirs, and
# the builds run as them. Under `curl | bash` it is simply us.
OP_USER="${SUDO_USER:-$(id -un)}"
# `|| true`: getent exits 2 for an account it has no entry for, and under
# pipefail that ended this script right here, silently, with exit 2.
OP_HOME="$(getent passwd "$OP_USER" 2>/dev/null | cut -d: -f6 || true)"
# $HOME stands in only when this process is the operator. Under sudo it is
# root's, and the checkout would land in root's home. Nothing else stands in:
# the old /tmp put the checkout in a directory anyone can write, with root
# about to run out of it (#616). main refuses an unresolved home by name.
if [[ -z "$OP_HOME" && -z "${SUDO_USER:-}" ]]; then OP_HOME="${HOME:-}"; fi

# >>> aperire palette >>>
# Colour says what happened. It is never decoration, and nothing is said in
# colour alone: bold heads a phase, green marks a thing that was read back as
# done, amber marks degraded-but-continuing, red marks a refusal, dim carries
# the detail under a line, and cyan marks a command or an address meant to be
# typed or opened (the same cyan the operator menu uses for the command it is
# about to run).
#
# Set once per stream, because the two streams need not be the same terminal.
# A run whose stdout is a log file and whose stderr is still the operator's
# window must put no escapes in the file and must not strip them from the
# window, so S_ dresses stdout and E_ dresses stderr. Anything written with
# >&2 uses E_.
#
# Every one of them is the empty string when the stream is not a terminal,
# when NO_COLOR is set to anything (https://no-color.org), or under TERM=dumb.
# So a piped, redirected or logged run is byte-plain and greps exactly the way
# it always did. The values hold real escape bytes rather than backslash text,
# which is what lets a plain `echo "${S_GREEN}...${S_OFF}"` carry them.
_aperire_style() {  # $1 = variable prefix, $2 = the fd it dresses
  local p="$1" fd="$2" on=1 n
  [[ -z "${NO_COLOR:-}" ]] || on=0
  [[ "${TERM:-}" != "dumb" ]] || on=0
  [[ -t "$fd" ]] || on=0
  for n in BOLD GREEN AMBER RED DIM CYAN OFF; do printf -v "${p}${n}" '%s' ''; done
  [[ $on -eq 1 ]] || return 0
  printf -v "${p}BOLD"  '\033[1m'
  printf -v "${p}GREEN" '\033[32m'
  printf -v "${p}AMBER" '\033[33m'
  printf -v "${p}RED"   '\033[31m'
  printf -v "${p}DIM"   '\033[2m'
  printf -v "${p}CYAN"  '\033[36m'
  printf -v "${p}OFF"   '\033[0m'
}
_aperire_style S_ 1
_aperire_style E_ 2
# <<< aperire palette <<<

# The second deliberate copy, and the same argument as the palette above: this
# script runs from a pipe before any checkout exists, so it has nothing to
# source. scripts/fleet-origin.sh owns the rule, install.sh and
# scripts/aperire-fleet-pair.sh source it, and scripts/test-fleet-origin.sh
# compares this block against that file byte for byte.
#
# >>> aperire fleet origin >>>
# BOTH OF THESE ALWAYS RUN, scheme first and shape second, and the safety
# property is the conjunction rather than either half (P3-076).
# `fleet_origin_scheme_ok` on its own accepts
# `http://127.0.0.1:7800@evil.example` and `http://127.0.0.1:7800.evil.example`,
# because everything after the port colon is a glob in a case pattern. What
# refuses those is `fleet_origin_plain_ok`. A caller that runs only the first
# one has a plaintext dial to a stranger, which is P3-059 again by another
# route. There is no single-predicate use of this file and there must not be.
#
# The scheme. https:// anywhere, http:// only to a loopback name, ANCHORED,
# with an explicit optional port and never a prefix glob (P3-059). The node is
# the only party that holds the URL, so the node is the only party that can
# know whether the hop carrying its tokens is encrypted.
fleet_origin_scheme_ok() {
  case "${1:-}" in
    https://*) return 0 ;;
    http://127.0.0.1|http://127.0.0.1:*) return 0 ;;
    http://localhost|http://localhost:*) return 0 ;;
    http://\[::1\]|http://\[::1\]:*) return 0 ;;
  esac
  return 1
}

# The shape: scheme, host, optional port, and nothing else. The origin is
# interpolated into the JSON job the dial helper reads, and a value carrying a
# quote would forge structure there. Same refusal scripts/fleet-link-place.sh
# makes, for the same reason.
#
# THE WHOLE VALUE, and this is the second thing lifting the rule here fixed.
# It used to be `printf | grep -Eq`, and grep matches a LINE: `https://host`
# followed by a newline and anything at all passed on its first line, which is
# the opposite of what the sentence above claims. A bash regex matches the
# string, newlines included, so a value with one in it has no line to hide on.
#
# The host is either a bracketed IPv6 literal or a name, as alternatives. It
# used to be one character class with `:` in it followed by an OPTIONAL
# bracket group, so `[` never had a class to start in and `http://[::1]` was
# refused as "not a plain origin" by a program whose message directly above it
# offers `[::1]` as a supported loopback form.
FLEET_ORIGIN_RE='^https?://(\[[0-9a-fA-F:]+\]|[A-Za-z0-9._~-]+)(:[0-9]{1,5})?$'
fleet_origin_plain_ok() {
  [[ "${1:-}" =~ $FLEET_ORIGIN_RE ]]
}
# <<< aperire fleet origin <<<

# -- Output ----------------------------------------------------------
step() { printf '\n%s%s%s\n' "$S_BOLD" "$*" "$S_OFF"; }
info() { printf '  %s\n' "$*"; }
ok()   { printf '  %sok    %s%s\n' "$S_GREEN" "$*" "$S_OFF"; }
warn() { printf '  %s!!    %s%s\n' "$S_AMBER" "$*" "$S_OFF"; }
die()  { printf '\n%serror: %s%s\n' "$E_RED" "$*" "$E_OFF" >&2; exit 1; }
# The detail under a line: a path, a reading, the command that explains it.
# Same text, one step back, so the line above it is the one that is read.
dim()  { printf '  %s%s%s\n' "$S_DIM" "$*" "$S_OFF"; }

# The header comment is the help text. Under a pipe there is no file to read
# it out of, and awk with no filename would sit waiting on the same exhausted
# stdin, so that case gets the short form instead of a hang.
usage() {
  if [[ -n "${BASH_SOURCE[0]:-}" && -f "${BASH_SOURCE[0]}" ]]; then
    awk '/^[^#]/{exit} NR>1{sub(/^# ?/,""); print}' "${BASH_SOURCE[0]}"
    return 0
  fi
  cat <<'EOF'
get-aperire.sh - installs Aperire One on this host.

  --role <co-located|dashboard|relay|cli-only>   (detected when not given)
  --dir <path>    where the release lands (default $HOME/aperire-one)
  --ref <ref>     for a git source, the branch, tag or commit to install
  --source <url>  a .tar.gz release to fetch and check, or a git remote
  --sha256 <hex>  the checksum a .tar.gz source has to match
  --port <n>      dashboard listen port (default 7800)
  --node          no node here yet: install one first, then co-located
  --check         check this host and stop, installing nothing
  --update        update a host that is already installed, and ask before
                  anything restarts (--force, --no-restart)
  --fleet-aggregator <url>
                  join this box to a fleet at the end of the install. It asks
                  for the pairing code on this terminal when it gets there
  --fleet-label <label>   the name to propose, [a-z0-9-]{1,32}
  --node-wrapper [<container>]   an installed host: write the privilege
                  wrapper's configuration for a docker node (finds it when no
                  name is given). --node-wrapper-rpc <port|url> names its
                  admin RPC
  --node-wrapper-native [<unit>]   the same for a node run by systemd
  --instance <name>   with either, the Advisor instance to configure; with
                  --fleet-aggregator and --code, the dashboard instance to pair
  --refresh-node-key [--node-key <key>] [--instance <name>]   an installed host: ask the node who
                  it is again and stamp that as this host's own node key.
                  --node-key states it when the node cannot be asked
  --backup [--to <dir>] [--instance <name>] [--yes] [--dry-run]
                  an installed host: write a backup set of its operator state
  --restore --from <set> [--instance <name>] [--yes] [--overwrite]
            [--dry-run] [--db-path <file>] [--replace-trust-pin]
                  an installed host: put a backup set back. Everything after
                  --backup or --restore is that program's own arguments
  --run <step> [its arguments]
                  an installed host: one root step of this release, run from
                  the release's checked copy (a grant, the sealer's --arm, the
                  Advisor's account, the node config fix and the menu's root
                  entries). Everything after the step is its own arguments.
                  --run with an unknown step lists them
  --yes, -y       take every default, ask nothing

Download it to a file for the whole story, which is its header comment:
  curl -fsSL <url> -o get-aperire.sh && less get-aperire.sh
EOF
}

# -- Guard 1: never run a half-delivered script ----------------------
running_from_a_pipe() { [[ -z "${BASH_SOURCE[0]:-}" || ! -f "${BASH_SOURCE[0]}" ]]; }

reexec_from_a_file() {
  running_from_a_pipe || return 0
  [[ "${APERIRE_GET_REEXEC:-0}" != "1" ]] || return 0

  local url tmp
  url="${APERIRE_GET_SELF_URL:-$DEFAULT_SELF_URL}"
  tmp="$(mktemp -t get-aperire.XXXXXXXX.sh)"

  if ! curl -fsSL --max-time 60 -o "$tmp" "$url" 2>/dev/null; then
    rm -f "$tmp"
    info "note: this script could not re-fetch itself from"
    info "      $url"
    info "      so it runs from the pipe instead. The end-of-file guard still"
    info "      applies: a copy cut short defines its functions and runs nothing."
    return 0
  fi
  if [[ "$(tail -n 1 "$tmp")" != "$SENTINEL" ]]; then
    rm -f "$tmp"
    info "note: the copy fetched from $url arrived without its last line, so it"
    info "      was not run. Continuing from the pipe, which the end-of-file"
    info "      guard checks in its own right."
    return 0
  fi

  export APERIRE_GET_REEXEC=1 APERIRE_GET_SELF_TMP="$tmp"

  # Read the rest of the pipe and throw it away, here, before the exec.
  #
  # `curl ... | bash` writes this script into a pipe as bash reads it, and the
  # exec below closes the read end while curl is still writing the tail. curl
  # dies of that write and says so:
  #
  #     curl: (23) Failure writing output to destination
  #
  # first line of a run that then works perfectly (aperire4, 2026-09-09, #269).
  # Nothing below wants those bytes: the copy that runs came from the re-fetch,
  # and the run either gets a terminal on stdin or an exhausted pipe by design.
  # So they are consumed rather than abandoned, and the writer ends normally.
  #
  # After the sentinel check, never before it: both refusals above go back to
  # reading the script itself out of this pipe, and a drain up there would eat
  # the run. And not on a terminal, where there is no writer to spare and the
  # drain would sit waiting on a keyboard forever.
  [[ -t 0 ]] || cat >/dev/null 2>/dev/null || true

  # Hand the run a terminal. Under a pipe, stdin IS the pipe: it is empty and
  # it is not a keyboard, so every question below would silently take its
  # default for a reason that has nothing to do with the answer.
  #
  # Opened for real rather than tested with -r: /dev/tty is mode 0666, so -r
  # says yes on a host with no controlling terminal at all (cloud-init, a CI
  # runner) and the redirection then fails, taking the whole run with it.
  if [[ ! -t 0 ]] && ( : < /dev/tty ) 2>/dev/null; then
    exec bash "$tmp" "$@" < /dev/tty
  fi
  exec bash "$tmp" "$@"
}

# Called here, before anything else in this file runs, and that placement is
# the point: a pipe cut further down never reaches a call at the bottom, so
# a guard at the bottom cannot rescue the very run it exists for. From here
# a cut pipe is re-fetched whole and re-run from a file.
reexec_from_a_file "$@"

# -- Privilege -------------------------------------------------------
# Root when we have it, sudo when we do not. Never `sudo` while already
# root: sudo would rewrite SUDO_USER to root, and prepare-host.sh refuses
# that on purpose, because a host whose only account is root has nowhere
# to put the services.
# NO_COLOR crosses the sudo boundary by hand, because sudo does not carry it.
# `Defaults env_reset` keeps TERM and drops NO_COLOR, so without this an
# operator who set it got a plain bootstrap and a coloured installer out of one
# run. Passed through `env` rather than left to sudo's own filtering, which
# would need an env_keep line in sudoers this script has no business asking for.
NO_COLOR_ENV=()
[[ -n "${NO_COLOR:-}" ]] && NO_COLOR_ENV=("NO_COLOR=${NO_COLOR}")

run_root() {
  if [[ $EUID -eq 0 ]]; then "$@"; else sudo -H env "${NO_COLOR_ENV[@]}" "$@"; fi
}

# The mirror image: the checkout and the builds belong to the operator. A
# tree cloned by root is one `npm ci` cannot write into.
as_operator() {
  if [[ $EUID -eq 0 && "$OP_USER" != "root" ]]; then
    sudo -u "$OP_USER" -H env "${NO_COLOR_ENV[@]}" "$@"
  else
    "$@"
  fi
}

# The account the installed dashboard runs as, read from its unit (ADR 0024).
# A fresh install runs it as aperire-dashboard, which owns data/ and nothing
# else; a host installed before that runs it as the operator. Without a unit
# (nothing installed yet, or a pm2 dashboard) it is the operator, which is
# what every step here assumed before the two could differ.
dash_account() {
  local unit_dir="${APERIRE_GET_UNIT_DIR:-/etc/systemd/system}" f u
  for f in "$unit_dir/aperire-server.service" "$unit_dir/aperire-read.service" \
           "$unit_dir"/aperire-server-*.service; do
    [[ -f "$f" ]] || continue
    u="$(awk -F= '/^User=/{print $2; exit}' "$f" 2>/dev/null || true)"
    [[ -n "$u" && "$u" != root ]] && { printf '%s' "$u"; return 0; }
  done
  printf '%s' "$OP_USER"
}

# Run as that account. The operator's own route when the two are the same
# account, so a host installed before ADR 0024 sees exactly what it always did.
as_dashboard_account() {
  local who
  who="$(dash_account)"
  if [[ "$who" == "$OP_USER" ]]; then as_operator "$@"; else run_root runuser -u "$who" -- "$@"; fi
}

# Standard input and standard ERROR, not standard output. Every question in
# this script is asked as `reply="$(ask ...)"`, and a command substitution
# gives the function a pipe for stdout, so a check on -t 1 is false on a
# real terminal every time: the questions printed, took their default, and
# moved on without waiting for anybody. Which is also where `read -p` puts
# its prompt (stderr) and where it takes the answer from (stdin), so these
# are the two the answer actually travels on.
have_tty() { [[ -t 0 && -t 2 ]]; }

ask() { # $1 = prompt, $2 = the answer when there is nobody to ask
  local reply
  if [[ $ASSUME_YES -eq 1 ]] || ! have_tty; then printf '%s' "$2"; return 0; fi
  read -r -p "  $1 " reply || reply=""
  [[ -n "$reply" ]] || reply="$2"
  printf '%s' "$reply"
}

# -- Guards on the host ----------------------------------------------
guard_privilege() {
  if [[ $EUID -eq 0 && "$OP_USER" == "root" ]]; then
    cat >&2 <<EOF

${E_RED}error: run this from your ordinary account, not as root.${E_OFF}

  The checkout, the build cache and the Node the dashboard runs on are the
  installing account's, and the dashboard itself runs as an account of its
  own beside it. A root-only install has nowhere to put any of it, so
  prepare-host.sh refuses it too, further in and after a wait.

  Either of these is right, from your own account:

      curl -fsSL <url> | bash
      curl -fsSL <url> | sudo bash

  The first asks for your sudo password when it reaches the part that
  needs it. The second has it already.
EOF
    exit 1
  fi
}

guard_os() {
  local id="" version_id="" id_like="" pretty="unknown" manual_fetch
  if [[ -r "$OS_RELEASE" ]]; then
    # shellcheck source=/dev/null  # a runtime file, not present at lint time
    . "$OS_RELEASE"
    id="${ID:-}"; version_id="${VERSION_ID:-}"; id_like="${ID_LIKE:-}"
    pretty="${PRETTY_NAME:-unknown}"
  fi

  # The same predicate install.sh uses, deliberately duplicated rather than
  # sourced: install.sh is not on this host yet when this runs. If either of
  # them ever learns a new distribution, the other has to learn it too.
  local supported=0
  if [[ "$id" == "ubuntu" && "$version_id" =~ ^(22\.04|24\.04)$ ]]; then supported=1; fi
  if [[ " $id_like " == *ubuntu* || "$id" == "linuxmint" ]]; then supported=1; fi
  if [[ $supported -eq 1 ]]; then return 0; fi

  # The same source this run was pointed at, in the shape it comes in.
  if source_is_tarball; then
    manual_fetch="curl -fsSL $SOURCE_URL -o aperire-one.tar.gz && tar -xzf aperire-one.tar.gz"
  else
    manual_fetch="git clone $SOURCE_URL aperire-one"
  fi

  cat >&2 <<EOF

${E_RED}error: the one-line install is verified on Ubuntu 24.04 and 22.04 LTS, and
       on Linux Mint 22. This host reports: $pretty${E_OFF}

  That is a statement about what has been tested, not a claim that nothing
  else works, so what it gates is the unattended door. The manual path is
  open and is not gated on the distribution:

      $manual_fetch
      cd aperire-one
      sudo bash install.sh --role=co-located --yes

  install.sh prints a warning on a system it does not recognise and carries
  on. The requirement underneath is systemd 250 or newer, and only for the
  Advisor's own dedicated account, which is off by default. On older systemd
  the Advisor runs under your account and its model key is kept as a
  root-only file instead of sealed to the machine; the checklist says which
  of the two this host will use.
EOF
  exit 1
}

# python3, asked of the same two fixed paths root's trusted-path check runs
# in, never a PATH (#1193). Without it every copy root makes out of the
# release is refused, and the refusal used to blame where the release digests
# sit. So it is named here, before anything is fetched. A --check reports it
# and carries on, since a check runs nothing as root.
PYTHON3_MISSING=0
guard_python3() {
  _tp_python >/dev/null && return 0
  PYTHON3_MISSING=1
  if [[ $CHECK_ONLY -eq 1 ]]; then
    warn "this host has no python3 at /usr/bin or /bin, and the install needs it: the check on every file root copies runs in it. Install it first: sudo apt-get install -y python3"
    return 0
  fi
  die "this install needs python3, and this host has none at /usr/bin or /bin: the check on every file root copies runs in it. Nothing was fetched. Install it, then run this again: sudo apt-get install -y python3"
}

# -- Idempotence: an installed host gets the menu, not a second install --
#
# Installed means a UNIT. Nothing else, and this is a correction: /etc/aperire
# or a checkout used to count too, and after `uninstall.sh --keep` a host has
# both of those and no units at all. The uninstaller says of them "A later
# install picks them up where they are", and then the bootstrap refused to
# install, saying the host was already running (aperire4, 2026-09-07). Keeping
# your data made reinstalling impossible, which is the opposite of what
# keeping it is for.
#
# A unit file is the honest evidence, because it is the thing that would be
# installed over: a service that exists is a service that may be running, and
# nothing this script does may go on top of one. A file left behind is not a
# service. It is yours, and the fetch below carries it into the new release.
installed_units() { systemctl list-unit-files 'aperire-*' 2>/dev/null | grep '\.service' || true; }

already_installed() { [[ -n "$(installed_units)" ]]; }

# What an earlier install left, when it left anything. Read from the two
# places that survive `--keep`, and printed rather than assumed: an operator
# about to reinstall over their own database should see it named first.
#
# A directory at $DIR is treated as an earlier checkout only when it holds an
# install.sh, because every release tree does. Anything else there is somebody
# else's directory and the fetch still refuses it by name.
looks_like_a_checkout() { [[ -f "$1/install.sh" ]]; }

# And whether anything in it is the OPERATOR'S. A tree left by an install that
# died halfway is a checkout with nothing of theirs in it, and telling them
# their files were kept when the only thing there is a half-unpacked release
# would be a claim about data that does not exist. Asked of the same three
# groups the carry moves, so the answer and the promise cannot disagree.
checkout_holds_operator_files() { # $1 = a checkout
  local f
  [[ -d "$1/data" ]] && return 0
  for c in "${CARRY_CONFIG[@]}"; do [[ -f "$1/dashboard/config/$c" ]] && return 0; done
  for c in "${CARRY_ADVISOR[@]}"; do [[ -d "$1/advisor/$c" ]] && return 0; done
  return 1
}

report_kept_artifacts() {
  local config=0 checkout=0 theirs=0
  [[ -d "$ETC_APERIRE" ]] && config=1
  if looks_like_a_checkout "$DIR"; then
    checkout=1
    checkout_holds_operator_files "$DIR" && theirs=1
  fi
  [[ $config -eq 1 || $checkout -eq 1 ]] || return 0

  if already_installed; then
    # Only --check gets here: an install on an installed host opened the
    # menu above and never reached this. Say what is true of THIS host, not
    # what is true after an uninstall that kept its files.
    step "what is installed on this host"
    info "Installed here: $(installed_units | awk '{print $1}' | tr '\n' ' ')"
    info "An install here would open the operator menu, not install over them."
    echo
    [[ -d "$ETC_APERIRE" ]] && ok "config:   ${ETC_APERIRE}"
    [[ -d "$DIR" ]] && ok "checkout: ${DIR}"
    echo
    return 0
  fi
  step "what an earlier install left on this host"
  info "No unit is installed, so nothing is running and there is nothing to"
  if [[ $CHECK_ONLY -eq 1 ]]; then
    # A check installs nothing, so it reports what it found and promises
    # nothing about what would be done with it.
    info "install over. This is what an install here would find."
  elif [[ $config -eq 1 || $theirs -eq 1 ]]; then
    info "install over. These are yours, and this install reuses them."
  else
    # Nothing here belongs to the operator, so nothing is said to. A tree an
    # install died halfway through is a tree, not somebody's data.
    info "install over, and nothing here is yours to keep."
  fi
  echo
  if [[ $config -eq 1 ]]; then
    ok "config:   ${ETC_APERIRE}"
    dim "the relay token, the service environment, any sealed key. Untouched:"
    dim "no new token is minted while the old one is still there."
  fi
  if [[ $checkout -eq 1 ]]; then
    ok "checkout: ${DIR}"
    if [[ $theirs -eq 0 ]]; then
      # Every honest word of it. The tree is replaced, and nothing is claimed
      # to have been carried, because there was nothing to carry.
      dim "nothing of yours is in it: no data/, no config you edited, no"
      dim "Advisor state. So it is replaced rather than carried, and the old"
      dim "tree is kept under a dated name rather than deleted."
    else
      if [[ -f "$DIR/data/aperire.db" ]]; then
        dim "data/aperire.db is here: your operators, passkeys and history."
      elif [[ -d "$DIR/data" && ! -x "$DIR/data" ]]; then
        # data/ belongs to the dashboard's account at 0700 once an install
        # has moved it there (an install refused partway leaves it so). This
        # account cannot look inside, so "not there" would be a guess; the
        # carry reads it as the dashboard's account and finds the file (#1046).
        dim "data/ is here, but it belongs to another account and this one can't look inside it."
        dim "so whether data/aperire.db is in it can't be checked from here. The install reads it as"
        dim "the account that owns it, and carries it if it is there."
      else
        dim "no data/aperire.db in it, so there is no database to carry."
      fi
      dim "the release unpacks beside it, your files move across, and the old"
      dim "tree is kept under a dated name rather than deleted."
    fi
  fi
  echo
  return 0
}

# What the earlier install had beyond the dashboard, read off what a keep
# leaves behind (#1181). `uninstall --keep` removes the relay, the Advisor and
# the pairing grant and keeps their configuration, and this install brings back
# the dashboard and, only where it finds a node, the relay. So an operator who
# does what the product recommends (uninstall, then the one-liner) can come out
# with a host that is less than it was and no line anywhere saying so. These
# three facts are read BEFORE the install, from files that survive a keep and
# that nothing this run writes before then could have made, and the closing
# text sets them against what the install put back.
#
#   relay    /etc/aperire/relay.conf, which names the label it reported under
#   Advisor  its build output in the kept tree, the two config files its
#            installer leaves in /etc/aperire, or the approval token in its
#            state directory
#   grant    the aggregator's fleet broker config, node registry or arm key
#
# Read only, as the operator: /etc/aperire is listable and a missing file reads
# as absent, so a host that hides one says less, never something untrue. Only a
# first install over kept files has anything to compare against.
KEPT_RELAY=0
KEPT_ADVISOR=0
KEPT_GRANT=0
note_kept_components() {
  KEPT_RELAY=0 KEPT_ADVISOR=0 KEPT_GRANT=0
  [[ $UPDATE -eq 0 && $CHECK_ONLY -eq 0 ]] || return 0
  [[ -e "$ETC_APERIRE/relay.conf" ]] && KEPT_RELAY=1
  local f
  for f in "$ETC_APERIRE/node-wrapper.conf" "$ETC_APERIRE/model-key.arm"; do
    [[ -e "$f" ]] && KEPT_ADVISOR=1
  done
  if [[ -d "$DIR/advisor/bin" ]] && [[ -n "$(ls -A "$DIR/advisor/bin" 2>/dev/null)" ]]; then
    KEPT_ADVISOR=1
  fi
  # An aggregator has no node wrapper, and the keep removes its model key and
  # its build output, so advisor/state is all that is left of its Advisor
  # (#1181, walks 1 and 2 on koi). approve.token is the one file there that only
  # the Advisor writes: read.token beside it is the dashboard's, and is on every
  # host. A state directory the operator cannot open reads as absent, which
  # says less and never something untrue.
  [[ -e "$DIR/advisor/state/approve.token" ]] && KEPT_ADVISOR=1
  for f in "$ETC_APERIRE/fleet-broker.conf" "$ETC_APERIRE/fleet-nodes.conf" "$ETC_APERIRE/fleet-arm.key"; do
    [[ -e "$f" ]] && KEPT_GRANT=1
  done
  return 0
}

# Whether a unit file of that name is on this host. The same question
# installed_units asks, asked of one name.
unit_here() { systemctl list-unit-files "$1" 2>/dev/null | grep -q '\.\(service\|socket\)'; }

# The closing comparison: what the earlier install had, against what this one
# put back. Nothing is printed for a host that left none of the three, and
# every line is read from systemctl now, not from what the install meant to do.
# This is a first install, so any such unit on the host is one this run made.
report_components_against_before() {
  [[ $UPDATE -eq 0 ]] || return 0
  [[ "$ROLE" != cli-only ]] || return 0
  [[ $KEPT_RELAY -eq 1 || $KEPT_ADVISOR -eq 1 || $KEPT_GRANT -eq 1 ]] || return 0
  step "what the earlier install had, against what this one put back"
  case "$ROLE" in
    co-located|dashboard) info "The dashboard is back, with your database, passkeys and config." ;;
  esac
  if [[ $KEPT_RELAY -eq 1 ]]; then
    if unit_here 'aperire-relay*'; then
      ok "the relay is back"
    else
      warn "the relay is NOT back. This install put no relay on this host (role: ${ROLE})."
      dim "${ETC_APERIRE}/relay.conf from the earlier install is still here, with its label."
      dim "To put it back, build it and wire it beside the dashboard:"
      dim "  curl -fsSL https://get.aperire.one | bash -s -- --dir ${DIR} --run prepare-host --role co-located"
      dim "  curl -fsSL https://get.aperire.one | bash -s -- --dir ${DIR} --run relay-colocated --unit ${DASH_UNIT_FOUND:-aperire-server} --port ${PORT} --binary ${DIR}/relay/aperire-relay"
    fi
  fi
  if [[ $KEPT_ADVISOR -eq 1 ]]; then
    if unit_here 'aperire-advisord.service'; then
      ok "the Advisor is back"
    else
      warn "the Advisor is NOT back. It is always its own install, and this one did not run it."
      dim "To put it back: curl -fsSL https://get.aperire.one/advisor | bash"
    fi
  fi
  if [[ $KEPT_GRANT -eq 1 ]]; then
    if unit_here 'aperire-fleet-broker.socket'; then
      ok "the pairing grant is back"
    else
      warn "the pairing grant is NOT back, so this host cannot pair nodes yet. Your fleet keys are kept."
      dim "To put it back: curl -fsSL https://get.aperire.one | bash -s -- --dir ${DIR} --run fleet-broker-grant"
    fi
  fi
  echo
}

# Whether the operator can read a directory, asked as the operator (#616).
# Under `curl | sudo bash` this shell is root, which reads everything, so a
# test made here would be a claim about root under a refusal that names the
# operator.
operator_reads_dir() { [[ -d "$1" ]] && as_operator test -r "$1"; }

# The dashboard instances this host runs, read off the units: an empty line
# for the default one (aperire-server or aperire-read), the suffix for each
# named one. Only the dashboard's own units count, not the Advisor's, the
# relay's or the trust sync's, because the pair command talks to a dashboard.
dashboard_instances() {
  local LC_ALL=C u
  while read -r u; do
    [[ "$u" =~ ^aperire-(server|read)(-([a-z0-9][a-z0-9-]*))?\.service$ ]] || continue
    printf '%s\n' "${BASH_REMATCH[3]}"
  done < <(installed_units | awk '{print $1}') | sort -u
}

# The shape of a run that names an instance beside a pair (#1278): --instance
# beside --fleet-aggregator, on a host that is installed, with nothing else in
# the run that wants --instance for itself. Whether it also has its --code is
# the two callers' question below. On a host that is not installed the old
# refusal still stands, so the flag is never dropped.
pair_instance_shape() {
  [[ $WRAPPER_INSTANCE_GIVEN -eq 1 && -n "$FLEET_AGGREGATOR" ]] || return 1
  [[ $WRAPPER_ASKED -eq 0 && $WRAPPER_NATIVE_ASKED -eq 0 && $WRAPPER_RPC_GIVEN -eq 0 \
     && $REFRESH_NODE_KEY_ASKED -eq 0 && $NODE_KEY_GIVEN -eq 0 \
     && $UPDATE -eq 0 && $UPDATE_FORCE -eq 0 && $CHECK_ONLY -eq 0 && $NODE_FIRST -eq 0 \
     && -z "$BR_VERB" && $RS_ASKED -eq 0 ]] || return 1
  already_installed
}
# True when this run is a pair that names its instance (#1278).
pair_names_instance() {
  [[ $FLEET_CODE_GIVEN -eq 1 ]] || return 1
  pair_instance_shape
}
# The same run with no --code (#1358). It was given the wrapper's sentence,
# "--instance goes beside --node-wrapper", which is true and says nothing about
# the pair the operator was writing.
pair_instance_needs_code() {
  [[ $FLEET_CODE_GIVEN -eq 0 ]] || return 1
  pair_instance_shape
}

# The checkout one dashboard instance runs from: the parent of its unit's
# WorkingDirectory (<checkout>/dashboard), as a real path. Empty when there is
# no unit or it names nothing this can read, which is not a mismatch.
instance_checkout() {  # <instance, or empty for the default one>
  local unit_dir="${APERIRE_GET_UNIT_DIR:-/etc/systemd/system}" f wd
  for f in "$unit_dir/aperire-server${1:+-$1}.service" "$unit_dir/aperire-read${1:+-$1}.service"; do
    [[ -f "$f" ]] || continue
    wd="$(awk -F= '$1=="WorkingDirectory"{sub(/^[^=]*=/, ""); print; exit}' "$f" 2>/dev/null || true)"
    [[ "$wd" == */dashboard ]] || continue
    (cd "${wd%/dashboard}" 2>/dev/null && pwd -P) && return 0
  done
  return 0
}

# Which dashboard the pair command talks to, settled before anything is
# dialled or any code is spent (#1278). $1 is the instance the run named, and
# $2 is 1 when it named one (an empty name given on purpose, --instance=, is
# the default instance). A run that names none pairs the default instance, and
# that is only a safe guess on a host that runs nothing else: with a second
# instance beside it the run is refused and the instances are listed, because
# guessing pairs the wrong dashboard and the code is spent on it.
pair_instance_gate() {
  local want="$1" given="$2" i label here there
  local -a all=()
  mapfile -t all < <(dashboard_instances)
  if [[ $given -eq 0 ]]; then
    [[ ${#all[@]} -eq 0 || ( ${#all[@]} -eq 1 && -z "${all[0]}" ) ]] && return 0
    warn "this host runs more than one dashboard, or only a named one, and a run that names none would pair the default instance."
  else
    for i in "${all[@]}"; do
      [[ "$i" == "$want" ]] || continue
      # The pair command takes the instance's port and unit from the name and
      # the tokens and the config it writes from the checkout. A name with the
      # wrong checkout reads one dashboard's token and writes another's link,
      # so the two must be the same instance's.
      here="$(cd "$DIR" 2>/dev/null && pwd -P)" || here="$DIR"
      there="$(instance_checkout "$want")"
      [[ -z "$there" || "$there" == "$here" ]] && return 0
      if [[ -n "$want" ]]; then
        warn "the dashboard of instance '$want' runs from $there, and this run was pointed at $here."
      else
        warn "the default dashboard runs from $there, and this run was pointed at $here."
      fi
      die "add --dir $(printf '%q' "$there") to pair that instance. Nothing was dialled and no code was spent."
    done
    [[ -z "$want" && ${#all[@]} -eq 0 ]] && return 0
    if [[ -n "$want" ]]; then
      warn "there is no dashboard instance '$want' on this host (no aperire-server-$want or aperire-read-$want unit)."
    else
      warn "there is no default dashboard instance on this host (no aperire-server or aperire-read unit)."
    fi
  fi
  info "the dashboards here, and the flag that pairs each:"
  for i in "${all[@]}"; do
    label="${i:-the default one}"
    there="$(instance_checkout "$i")"
    if [[ -z "$i" ]]; then
      info "  ${label}   --instance=   (nothing after the equals sign)${there:+   in $there}"
    else
      info "  ${label}   --instance $i${there:+   in $there}"
    fi
  done
  info "add --dir <that instance's checkout> as well when it is not $DIR."
  die "nothing was dialled and no code was spent. Name the instance and run this again."
}

offer_the_menu() {
  local units menu
  units="$(installed_units | awk '{print $1}' | tr '\n' ' ')"
  menu=""
  # As you, never under sudo (#955): the menu asks sudo for each entry that
  # needs root, and root then runs only the release's checked copies.
  [[ -f "$DIR/aperire-one" ]] && menu="bash $DIR/aperire-one"

  step "Aperire One is already installed on this host."
  [[ -n "$units" ]]     && info "units:    $units"
  [[ -d "$ETC_APERIRE" ]] && info "config:   $ETC_APERIRE"
  if [[ -n "$menu" ]]; then
    info "checkout: $DIR"
  else
    info "checkout: not at $DIR (pass --dir if it lives somewhere else)"
  fi

  # A code AND an aggregator pair this host now, in place of the menu: that
  # is the whole point of the flag, and the Settings page's mint step prints
  # exactly this line for an operator to copy. Refused by name rather than
  # attempted blind (P3-077 again): a checkout this account cannot read, one
  # that is not a checkout at all (no install.sh), or one built before fleet
  # pairing existed (#176), is not a host this can run the ceremony against.
  # The checkout gate below is a named refusal, not validation of $DIR: it
  # does not make an arbitrary --dir safe to run root against, it only
  # refuses the one shape this script can tell apart from a real checkout.
  # The operator who chose --dir is the one handing this run sudo.
  if [[ -n "$FLEET_AGGREGATOR" && $FLEET_CODE_GIVEN -eq 1 ]]; then
    operator_reads_dir "$DIR" \
      || die "the checkout at $DIR is not readable by $OP_USER, so there is nothing here to pair. Pass --dir if it lives somewhere else."
    looks_like_a_checkout "$DIR" \
      || die "$DIR does not look like an Aperire checkout (no install.sh there), so there is no pair command to run here. Pass --dir if it lives somewhere else."
    [[ -f "$DIR/scripts/aperire-fleet-pair.sh" ]] \
      || die "$DIR/scripts/aperire-fleet-pair.sh is missing from this checkout, so there is no pair command to run here. That install predates fleet pairing (#176); update it first, then run this again."
    # Only an explicit --instance names one. A login's own APERIRE_INSTANCE
    # is not read here, and the pair command is always handed the answer, empty
    # included: it keeps the variable it is given, so a stale one would pair
    # that instance by another route (#949 settled the same for the seal).
    local pair_instance="" pair_given=0
    if [[ $WRAPPER_INSTANCE_GIVEN -eq 1 ]]; then
      pair_instance="$WRAPPER_INSTANCE"; pair_given=1
      wrapper_instance_ok "$pair_instance" \
        || die "--instance must match [a-z0-9][a-z0-9-]{0,30}, the rule the Advisor's instance names follow."
    fi
    pair_instance_gate "$pair_instance" "$pair_given"
    echo
    info "pairing this checkout with ${FLEET_AGGREGATOR}${pair_instance:+ as instance $pair_instance}"
    ensure_sudo
    local -a pair_args=( --code - --aggregator "$FLEET_AGGREGATOR" )
    [[ -n "$FLEET_LABEL" ]] && pair_args+=( --label "$FLEET_LABEL" )
    # The code crosses on the child's own stdin, never on sudo's argv: the
    # same reason --fleet-code is refused as a flag on this script applies to
    # any command this layer would otherwise hand root over sudo carrying it.
    # The pair command root runs is the staged copy of this tree's, held to
    # both checks first (#764), and it is told which tree it pairs.
    stage_release_for_root || refuse_unstaged_release
    local rc=0
    printf '%s\n' "$FLEET_CODE" \
      | run_root env APERIRE_INSTALL_TREE="$DIR" APERIRE_INSTANCE="$pair_instance" bash "$RUN_TREE/scripts/aperire-fleet-pair.sh" "${pair_args[@]}" || rc=$?
    collect_installer_refusals
    [[ ${#ROOT_COPY_REFUSED[@]} -eq 0 ]] || report_refused_root_copies
    exit "$rc"
  fi

  cat <<EOF

  So there is nothing for the bootstrap to do, and it will not install over
  a host that is already running. Everything past the first install lives
  behind one command: add a role, add operators, add nodes, the Advisor,
  day-2 maintenance, the verifies.

      ${S_CYAN}${menu:-aperire-one}${S_OFF}

EOF
  # A flag given and not used is named, never dropped quietly (P3-077).
  # install.sh states the principle in its own words: an install given a flag
  # it silently dropped did something other than what it was asked for. This
  # is the one path where the fleet flags are validated and then never reach
  # it, and it is a realistic mistake now that the Settings page prints this
  # line permanently: the operator runs it on a box they already installed.
  if [[ -n "$FLEET_AGGREGATOR" ]]; then
    # A tree that is not the default is named, shell-quoted, so the line
    # pairs the host it was printed on.
    local pair_dir=""
    [[ "$DIR" == "${OP_HOME}/aperire-one" ]] || pair_dir=" --dir $(printf '%q' "$DIR")"
    cat <<EOF
  ${S_AMBER}This run was asked to join ${FLEET_AGGREGATOR}, and it did not.${S_OFF} Nothing was
  dialled and no code was spent: joining a fleet happens as the last step of an
  install, and there is no install to do here.

  One line pairs this host, at a terminal on it, once you have minted a code on
  that aggregator:

      ${S_CYAN}curl -fsSL https://get.aperire.one | bash -s -- --fleet-aggregator ${FLEET_AGGREGATOR}${FLEET_LABEL:+ --fleet-label ${FLEET_LABEL}} --code -${pair_dir}${S_OFF}

EOF
  fi
  if [[ -n "$menu" ]] && have_tty && [[ $ASSUME_YES -ne 1 ]]; then
    local reply
    reply="$(ask 'Open it now? [Y/n]' y)"
    case "$reply" in
      y|Y|yes|YES)
        # As the operator, never as root (#955): the menu asks sudo for each
        # entry that needs it, and root runs only the release's checked
        # copies. Under `curl | sudo bash` it is handed back to the account
        # that ran sudo.
        if [[ $EUID -eq 0 && "$OP_USER" != root ]]; then
          exec sudo -u "$OP_USER" -H bash "$DIR/aperire-one"
        fi
        exec bash "$DIR/aperire-one"
        ;;
    esac
  fi
  exit 0
}

# -- What this host is -----------------------------------------------
# A node RUNNING here is the only honest evidence that this is a node box.
# A config file left behind is not: a decommissioned native install leaves
# one, and it would turn a dashboard-only box into a co-located one that
# waits forever for a node that is never coming back.
#
# The two sources of that evidence are not equally easy to read, and the
# difference put a node box through this script as a dashboard. A process
# needs no privileges to see, so pgrep is asked first and its answer is
# final. Docker's socket belongs to root, and on a hardened host the
# operator account is deliberately not in the docker group, because that
# group is root without a password. `docker ps` there prints nothing and
# fails, which reads exactly like a box with no containers on it: the node
# was invisible, the role came out `dashboard`, no Go and no relay were
# installed, and the closing health check still passed, because a
# dashboard-role box answers /healthz perfectly well.
#
# So the query goes through `sudo -n` when the direct one fails, and the
# three outcomes stay apart. `sudo -n` never prompts for a password, which
# is why it may run here, ahead of the sudo announcement further down.
#
#   0  a node is running here
#   1  nothing is running here, and everything asked answered
#   2  docker is installed and would not answer: the evidence is
#      UNAVAILABLE, which is not the same fact as absent and is never
#      rounded down to it
#
# What was seen, and how it was asked, is left in DETECT_EVIDENCE and
# printed in the plan. One line of any captured log then shows the next
# wrong guess for what it is.
DETECT_EVIDENCE=""

# And WHICH KIND of node was found, when one was: `container` or `process`.
# The two are not interchangeable to anything downstream. The installer's
# record-a-node-that-is-already-here verb is the container one, and the
# native equivalent lives behind a flag that also installs where it finds no
# unit, so the branch below reads this rather than the sentence above it.
DETECT_KIND=""

DOCKER_PS_FORMAT='{{.Names}} {{.Image}} {{.Command}}'

# The complaint docker makes when there is no daemon to talk to. It is the
# one failure that is an answer rather than a silence: no daemon running
# means no container running, for anybody on this machine. Everything else
# is a question that did not get asked.
docker_has_no_daemon() {
  printf '%s' "$1" \
    | grep -qiE 'cannot connect to the docker daemon|is the docker daemon running|docker daemon is not running'
}

# Whether the process half of the evidence could be gathered at all. A host
# with no pgrep on it answers "no node process" to a question nothing asked,
# which is the same rounding this whole change exists to stop: a native node
# would be just as invisible as a container was.
PROC_CHECK_RAN=1

# Nothing was found. That is only an answer when both halves could be asked,
# so the process half decides whether this returns absent or unavailable.
nothing_found() { # $1 = what the docker half found
  if [[ $PROC_CHECK_RAN -eq 0 ]]; then
    DETECT_EVIDENCE="nothing here could look for a node process (no pgrep on this host), and $1"
    return 2
  fi
  DETECT_EVIDENCE="no node process, and $1"
  return 1
}

# Rows from docker ps whose Image column (the second field) is a bare image ID
# (a container created from a digest reference, which the Advisor's own
# upgrade makes) get the name the container was created from, read back with
# docker inspect, so the image-name match below still finds the node (#896).
# Only that column is looked at, so a word in a command that looks like an ID
# is left alone; the rest of the row and every separator is left as it was. A
# refused inspect prints docker's reason and returns 1: it is not a container
# that failed to match. A container that is gone by now is skipped. Asked the way docker ps was.
resolve_image_ids() { # $1 = docker ps rows, $2 = how ps was answered (docker or sudo docker)
  local line ref rest lead img tail res err out='' nl=$'\n' idre='^(sha256:)?[0-9a-fA-F]{12,64}$'
  local -a dk=(docker); [[ "${2:-}" == 'sudo docker' ]] && dk=(sudo -n docker)
  while IFS= read -r line; do
    if [[ -n "$line" ]]; then
      ref="${line%%[[:space:]]*}"; rest="${line#"$ref"}"
      lead="${rest%%[![:space:]]*}"; rest="${rest#"$lead"}"
      img="${rest%%[[:space:]]*}"; tail="${rest#"$img"}"
      if [[ -n "$img" && "$img" =~ $idre ]]; then
        res="$("${dk[@]}" inspect --type container "$ref" --format '{{.Config.Image}}' 2>/dev/null)" || res=''
        if [[ -n "$res" ]]; then
          line="${ref}${lead}${res%%@*}${tail}"
        else
          err="$("${dk[@]}" inspect --type container "$ref" --format '{{.Config.Image}}' 2>&1 >/dev/null | head -1 || true)"
          if ! grep -qiE 'no such (object|container)' <<<"$err"; then
            printf '%s' "${err:-no reason given}"; return 1
          fi
        fi
      fi
    fi
    out+="${line}${nl}"
  done <<<"$1"
  printf '%s' "${out%"$nl"}"
}

detect_node() {
  local n pid
  if ! command -v pgrep >/dev/null 2>&1; then
    PROC_CHECK_RAN=0
  fi
  for n in rippled xrpld xahaud; do
    pid="$(pgrep -x "$n" 2>/dev/null | head -1 || true)"
    if [[ -n "$pid" ]]; then
      DETECT_EVIDENCE="process $n pid $pid"
      DETECT_KIND="process"
      return 0
    fi
  done

  if ! command -v docker >/dev/null 2>&1; then
    nothing_found "docker is not installed here" || return $?
  fi

  # stdout and stderr are kept apart on purpose: merged, a docker warning
  # would be read as a line of the container list. The complaint is read
  # back in a second call, on the failure path only, where it is cheap.
  local out derr='' serr='' rc=0 via='docker'
  out="$(docker ps --format "$DOCKER_PS_FORMAT" 2>/dev/null)" || rc=$?
  if [[ $rc -ne 0 ]]; then
    derr="$(docker ps --format '{{.Names}}' 2>&1 >/dev/null | head -1 || true)"
    if command -v sudo >/dev/null 2>&1; then
      rc=0
      out="$(sudo -n docker ps --format "$DOCKER_PS_FORMAT" 2>/dev/null)" || rc=$?
      if [[ $rc -eq 0 ]]; then
        via='sudo docker'
      else
        serr="$(sudo -n docker ps --format '{{.Names}}' 2>&1 >/dev/null | head -1 || true)"
      fi
    else
      serr='sudo is not installed here'
    fi
  fi

  if [[ $rc -ne 0 ]]; then
    # Both complaints, because they answer different halves of the
    # question, and because either one naming a daemon that is not running
    # settles it: no daemon means no container, for this account and for
    # root alike.
    local why="${derr:-no reason given}"
    [[ -n "$serr" ]] && why="${why}; ${serr}"
    if docker_has_no_daemon "$why"; then
      nothing_found "docker has no daemon running (${why})" || return $?
    fi
    DETECT_EVIDENCE="docker is installed here, and neither this account nor 'sudo -n' could ask it what is running (${why})"
    return 2
  fi

  local c
  # A container created from a digest shows an image ID; read its name back
  # through the same account that answered ps (#896).
  if ! out="$(resolve_image_ids "$out" "$via")"; then
    DETECT_EVIDENCE="docker is installed here, and listed what is running, but would not say which image a container was created from (${out})"
    return 2
  fi
  c="$(printf '%s\n' "$out" | grep -aiE 'rippled|xrpld|xahaud' | head -1 | awk '{print $1}' || true)"
  if [[ -n "$c" ]]; then
    DETECT_EVIDENCE="running container ${c} via ${via}"
    DETECT_KIND="container"
    return 0
  fi
  nothing_found "${via} answered with no node container"
}

# Detection could not see. There is exactly one thing not to do here, and
# it is what turned this from an inconvenience into a bug: pick a role
# anyway. A wrong role installs the wrong half of the product and then
# passes every check that comes after it.
role_when_unknown() {
  cat <<EOF

  ${S_AMBER}I cannot tell what this host is.${S_OFF}

      ${DETECT_EVIDENCE}

  That is not a broken host. Being in the docker group is being root
  without a password, so an operator account that is not in it is correct.
  It does mean nothing running as you can see a node in a container.

  The role is one word, and naming it settles the question:

      co-located   a node runs on this box (dashboard and relay beside it)
      dashboard    no node here; this box watches nodes elsewhere
      relay        this is the node's box in a split install, relay only
      cli-only     the operator commands on a workstation, no services
EOF

  if [[ $ASSUME_YES -ne 1 ]] && have_tty; then
    local reply tries=3
    # Bounded, because stdin can end: an operator who walked away, or a
    # pipe that closed, has to reach the refusal below rather than a loop.
    while (( tries-- > 0 )); do
      reply="$(ask 'Which is this host? (co-located / dashboard / relay / cli-only, or n to stop)' '')"
      case "$reply" in
        n|N|no|NO) echo "  stopped, nothing was changed."; exit 0 ;;
        *)
          if valid_role "$reply"; then
            ROLE="$reply"
            return 0
          fi
          info "that is not one of the four roles, and not n."
          ;;
      esac
    done
  fi

  cat >&2 <<EOF

${E_RED}error: this host could not be identified, and there is nobody here to ask.${E_OFF}

  Guessing is worse than stopping. A wrong role installs the wrong half of
  the product (a node box installed as a dashboard gets no Go, no relay
  build and no relay service), and every check afterwards still passes,
  because a dashboard-role box answers its own health endpoint perfectly
  well. So this run stops here, having changed nothing.

  Two ways on, and either one is enough:

    1. name the role, which is the only thing this run was missing. Add
       it to the same command you just ran:

           --role=co-located

       (or dashboard, or relay, or cli-only)

    2. or run that command under sudo, where docker answers. Detection
       works anywhere 'sudo -n docker ps' does, root included:

           curl -fsSL <url> | sudo bash -s -- --yes
           sudo bash get-aperire.sh --yes

EOF
  exit 1
}

# install.sh's name for the role this script was given. `relay` is the only
# rename, and it happens here at the boundary and nowhere else.
install_role_for() {
  case "$1" in
    relay) printf 'validator' ;;
    *)     printf '%s' "$1" ;;
  esac
}

# `--flag value` needs its value checked here rather than by `shift 2`, which
# under `set -e` would end the run on a bare `shift: count out of range` with
# nothing said about which flag was left short.
flag_value() {
  [[ $# -ge 2 && -n "$2" && "$2" != -* ]] || die "$1 needs a value after it."
  printf '%s' "$2"
}

# The same check as flag_value, except a bare `-` is the one value this flag
# accepts that looks like a flag: it means "read the code from stdin",
# aperire-fleet-pair.sh's own better habit.
code_flag_value() {
  [[ $# -ge 2 && -n "$2" ]] || die "--code needs a value after it (a pairing code, or - to read it from stdin)."
  [[ "$2" == '-' || "$2" != -* ]] \
    || die "--code needs a value after it (a pairing code, or - to read it from stdin)."
  printf '%s' "$2"
}

# A flag whose value is optional: prints the next word when it is a value (not
# empty, not another flag) and nothing otherwise. The caller shifts by whether
# it got one.
optional_value() {
  [[ $# -ge 2 && -n "$2" && "$2" != -* ]] && printf '%s' "$2"
  return 0
}

# The names and the port the wrapper installer is allowed to be handed (#924).
# Whole-string matches with [[ =~ ]], never grep: grep -q is true when ANY line
# matches, so a two-line value would pass (P3-074). Every one starts with a
# letter or digit, which is what keeps `--node-wrapper=--refresh` from being
# an installer flag by another spelling.
# LC_ALL=C in each: a range like [a-z] follows the locale's collation, and under
# a UTF-8 locale it matches letters outside ASCII (é, fullwidth ａ).
wrapper_name_ok() { local LC_ALL=C; [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$ ]]; }
wrapper_unit_ok() { local LC_ALL=C; [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9_.@-]{0,127}$ ]]; }
wrapper_instance_ok() { local LC_ALL=C; [[ -z "$1" || "$1" =~ ^[a-z0-9][a-z0-9-]{0,30}$ ]]; }
# A port, or an http URL to loopback with a port and nothing else, printed as
# the URL the installer takes. No leading zero (08 is not a number to bash
# arithmetic), and 1 to 65535.
wrapper_rpc_url() {
  local host="127.0.0.1" port LC_ALL=C
  if [[ "$1" =~ ^[1-9][0-9]{0,4}$ ]]; then
    port="$1"
  elif [[ "$1" =~ ^http://(127\.0\.0\.1|localhost|\[::1\]):([1-9][0-9]{0,4})$ ]]; then
    host="${BASH_REMATCH[1]}"; port="${BASH_REMATCH[2]}"
  else
    return 1
  fi
  (( 10#$port <= 65535 )) || return 1
  printf 'http://%s:%s' "$host" "$port"
}

# `--code -` resolved once, right after parsing, into the code itself: it is
# read here because neither offer_the_menu's own dial nor install.sh's
# --fleet-code takes "-" as a literal, and this is the one place that would
# otherwise have to know both. Stdin under a pipe is a terminal by the time
# this runs (reexec_from_a_file already handed one back), so this prompts
# the same way aperire-fleet-pair.sh does when it is run by hand.
resolve_fleet_code() {
  [[ $FLEET_CODE_GIVEN -eq 1 && "$FLEET_CODE" == '-' ]] || return 0
  if have_tty; then
    printf '   Paste the pairing code, then Enter: ' >&2
    read -rs FLEET_CODE < /dev/tty || FLEET_CODE=''
    printf '\n' >&2
  else
    read -r FLEET_CODE || FLEET_CODE=''
  fi
  [[ -n "$FLEET_CODE" ]] || die "--code - asked to read a code from stdin, and none arrived."
}

valid_role() {
  case "$1" in co-located|dashboard|relay|validator|cli-only) return 0 ;; *) return 1 ;; esac
}

# -- The plan, and one chance to change it ---------------------------
confirm_plan() {
  local evidence="$1" hostname_now source_line fetch_line
  hostname_now="$(hostname 2>/dev/null || echo this-host)"

  # An archive and a git remote arrive differently and are trusted
  # differently, and the plan says which of the two this run is.
  if source_is_tarball; then
    if [[ -n "$EXPECTED_SHA256" ]]; then
      source_line="$SOURCE_URL
              release ${SOURCE_REF}, sha256 ${EXPECTED_SHA256}"
      fetch_line="fetch the release, check that sha256, and unpack it into $DIR"
    else
      source_line="$SOURCE_URL
              release ${SOURCE_REF}, with no checksum, which only a local file gets"
      fetch_line="fetch the release and unpack it into $DIR"
    fi
  else
    source_line="$SOURCE_URL @ $SOURCE_REF"
    fetch_line="fetch the release into $DIR"
  fi

  cat <<EOF

  ${S_BOLD}----- Aperire One -----${S_OFF}

  Host:       $hostname_now
  Role:       $ROLE
              $evidence
  Source:     $source_line
  Directory:  $DIR

  Will do, in order:
    1. $fetch_line
    2. check what this host has before anything is changed: the OS, sudo,
       disk, memory, the ports, egress, the clock, the tools and the node.
       Anything missing is printed with the command that fixes it, and the
       run stops there having installed nothing
    3. install.sh --role=$(install_role_for "$ROLE") --yes, as root from a
       checked copy of the release, which runs scripts/prepare-host.sh
       first (apt build deps, Node 22 through nvm, Go, npm ci, the relay
       build), prints its own plan, and installs each part as a
       supervised, non-privileged systemd service
EOF
  case "$ROLE" in
    co-located|dashboard)
      info "  4. wait for http://127.0.0.1:${PORT}/healthz to answer, before"
      info "      claiming that any of it worked" ;;
    *)
      info "  4. check what landed, before claiming that any of it worked" ;;
  esac
  echo

  # The role above is `dashboard` because nothing was found, not because
  # anyone said so. "No node here" and "no node here YET" are the same
  # reading, and only one of them wants this install.
  if [[ $ROLE_IS_NODELESS_GUESS -eq 1 ]]; then
    cat <<EOF
  ${S_AMBER}That role is a reading, not a decision.${S_OFF} If this box is supposed to run a
  node and does not have one yet, answer ${S_CYAN}5${S_OFF} below: a hardened mainnet node is
  installed here first, then the dashboard and relay beside it, co-located.
  Unattended, that is ${S_CYAN}--node${S_OFF}. If this box watches nodes that live elsewhere,
  dashboard is right and there is nothing to do.

EOF
  fi

  [[ $ASSUME_YES -eq 1 ]] && return 0
  have_tty || return 0

  local reply
  while true; do
    reply="$(ask "Proceed? [Y/n], or pick another role. 1) co-located 2) dashboard 3) relay 4) cli-only 5) node first, then co-located:" y)"
    # A number is the same answer as its role's name; the menu the rest of
    # the product runs on taught operators numbers, so the prompt takes both.
    case "$reply" in
      1) reply=co-located ;;
      2) reply=dashboard ;;
      3) reply=relay ;;
      4) reply=cli-only ;;
      5|node) NODE_FIRST=1; ROLE=co-located; info "role: co-located, after a node is installed here"; return 0 ;;
    esac
    case "$reply" in
      y|Y|yes|YES) return 0 ;;
      n|N|no|NO)   echo "  aborted, nothing was changed."; exit 0 ;;
      *)
        if valid_role "$reply"; then
          ROLE="$reply"
          info "role: $ROLE"
        else
          info "that is not one of the four roles, not 5, and not yes or no."
        fi
        ;;
    esac
  done
}

# -- Sudo, stated before it is asked for -----------------------------
announce_sudo() {
  cat <<'EOF'

  What needs root here, and what for:

    apt packages     the build toolchain the dashboard and relay compile
                     with (build-essential, git, sqlite3, and a few more)
    /usr/local/go    Go, and only when this host has none new enough
    systemd units    aperire-server / aperire-relay, so they come back
                     after a reboot without anybody logging in
    /etc/aperire     the service environment and the relay's config
    /usr/local/lib/aperire
                     the release's own digests, so that root copies a
                     program out of the checkout only if it is the one the
                     release shipped
EOF
  [[ $NODE_FIRST -eq 1 ]] && cat <<'EOF'
    docker           the engine and compose plugin if this host has none,
                     and the node's container (--node, or answer 5)
EOF
  cat <<'EOF'

  One more, already spent: working out what this host is asked docker
  what containers are running, and asked it through `sudo -n` when this
  account could not. It reads, it changes nothing, and `-n` means it
  never prompted. The role above says which query answered.

  Nothing else, nothing outside that list, and `curl -fsSL https://get.aperire.one/uninstall | bash`
  takes it back off. The checkout and every build stay yours: they run as
  your own account, never as root.
EOF
}

ensure_sudo() {
  [[ $EUID -eq 0 ]] && return 0
  command -v sudo >/dev/null 2>&1 \
    || die "this host has no sudo, and the install needs root for the four things listed above."
  sudo -n true 2>/dev/null && return 0
  if ! have_tty; then
    die "sudo wants a password and there is no terminal to ask on. Run it as: curl -fsSL <url> | sudo bash"
  fi
  sudo -v || die "sudo was refused, so nothing was installed."
}

# -- Root copies, checked against the release (ADR 0024) ------------
#
# Everything root copies out of the tree into a root location (the programs
# behind the four sockets, their helpers, the image recipe) is checked against
# the release's own digests before it is copied, and the copy is made from the
# one read that was checked. The digests are taken from the archive ROOT holds
# a copy of, the moment it has been checked against the sha256 this script
# pins, before anything has run in the tree. What that closes: the tree is the
# operator's account's to write, and an update spends minutes in it (npm ci,
# the builds) before the root steps. Anything that rewrote a root program in
# that window used to be copied into /usr/local/sbin by the next line.
#
# The block below is scripts/release-digests-lib.sh, byte for byte. It is
# carried inline because this script cannot source a library out of the tree
# it is about to check; scripts/test-release-digests-lib.sh fails if the two
# drift.
# >>> trusted path >>>
# The check itself: the account set, the walk and the copy. This block is
# copied byte for byte into scripts/get-aperire.sh, so the bootstrap never
# takes the check out of the tree it is about to judge (#877 review, M1).
# scripts/test-trusted-path-lib.sh fails if the two drift.
# Groups that are root on the host by themselves, and capabilities that
# bypass file permissions. An account holding either can write any path, so
# no path is trusted while one does (#756 review, L1).
TP_ROOT_GROUPS=(docker lxd incus-admin libvirt microk8s disk)
TP_ROOT_CAPS=(cap_dac_override cap_fowner cap_chown cap_setuid cap_setgid cap_sys_admin cap_sys_module cap_sys_rawio)

# The account set, read once and held for one batch of copies (#764). Staging
# a release's scripts for root is a hundred copies in one root shell, and
# reading every unit for each one costs about half a second a file. Always 0
# when this block is loaded, and in the text tp_lib_text hands a root shell,
# so nothing in the environment can switch the read off: only
# trusted_path_hold_accounts sets it, in the one shell making the batch, and
# trusted_path_release_accounts puts it back.
TP_ACCOUNTS_HELD=0

# A login is an account with a passwd entry whose shell lets it log in. One
# with no entry at all is not proven to be anything, so it is not one.
_tp_is_login() { # $1 = a user name or uid
  local entry shell
  entry="$(getent passwd "$1" 2>/dev/null | head -1)"
  [[ -n "$entry" ]] || return 1
  shell="${entry##*:}"
  case "$shell" in
    */nologin|*/false|*/sync) return 1 ;;
  esac
  return 0
}

_tp_gid() { # $1 = a group name or number
  if [[ "$1" =~ ^[0-9]+$ ]]; then printf '%s' "$1"; return 0; fi
  getent group "$1" 2>/dev/null | cut -d: -f3
}

# systemctl, asked again while systemd is busy. A daemon-reload makes systemd
# fail a call for a moment (13 reloads in 46 s through one install, #1089),
# and that is not "no service accounts". Five tries, a second apart, then it
# is a fault and the caller refuses. The wait is a constant: no variable in
# the environment changes it (the suites put a `sleep` that does not wait on
# PATH, as they do for systemctl). The answer is left in _TP_SC, not printed:
# a $( ) here would lose TP_ACCOUNTS_FAILED, the call that gave up, with the
# subshell.
_tp_systemctl() { # $@ = systemctl's arguments
  local n
  for (( n = 1; n <= 5; n++ )); do
    if _TP_SC="$(systemctl "$@" 2>/dev/null)"; then return 0; fi
    if (( n < 5 )); then sleep 1; fi
  done
  TP_ACCOUNTS_FAILED="systemctl $*"
  return 1
}

# The one sentence for a refusal because the account set could not be read.
# It is not a finding about any file, so it is never told as one.
tp_accounts_refusal() {
  printf "the account check could not run: systemd did not answer \`%s\`" "${TP_ACCOUNTS_FAILED:-systemctl}"
}

# role:name:uid:gid,gid,... per service account, and TP_TOLERATE, the uids of
# dashboard accounts that are logins (the one state that only warns).
# Why an account can write any path at all, or nothing. $1 = user,
# $2 = the unit ("" for an account with none), $3 = extra group names,
# $4 = the unit's AmbientCapabilities, already read by trusted_path_accounts
# through _tp_systemctl, so a read that failed is a fault there and never an
# empty set here (#1089).
_tp_root_equivalent() {
  local user="$1" unit="$2" g c caps names
  names=" $(id -nG "$user" 2>/dev/null) $3 "
  for g in "${TP_ROOT_GROUPS[@]}"; do
    case "$names" in *" $g "*) printf 'is in the %s group, which is root on this host' "$g"; return 0 ;; esac
  done
  [[ -n "$unit" ]] || return 1
  caps=" $(printf '%s' "${4:-}" | tr '[:upper:]' '[:lower:]') "
  for c in "${TP_ROOT_CAPS[@]}"; do
    case "$caps" in *" $c "*) printf 'holds %s (AmbientCapabilities= on %s), which bypasses file permissions' "$c" "$unit"; return 0 ;; esac
  done
  return 1
}

_tp_group_name() { # $1 = a group name or number
  if [[ "$1" =~ ^[0-9]+$ ]]; then getent group "$1" 2>/dev/null | cut -d: -f1; else printf '%s' "$1"; fi
}

# $1 = the install tree, "" for none. A dashboard with no unit is found by the
# process running out of <tree>/dashboard, so without a tree there is nothing
# to scope that search to and it is not made (#757).
trusted_path_accounts() {
  [[ "${TP_ACCOUNTS_HELD:-0}" == 1 ]] && return 0
  TP_ACCOUNTS=()
  TP_TOLERATE=()
  TP_PRIV=()
  TP_ACCOUNTS_FAILED=""
  # No systemd to ask is not "no service accounts": it is a set nobody can
  # vouch for, and the callers refuse on it (#877 review, L1).
  if ! command -v systemctl >/dev/null 2>&1; then
    TP_ACCOUNTS_FAILED="systemctl (this host has none)"
    return 1
  fi
  local list unit role user group sup caps uid gids g gid why gnames seen=" " tree="${1:-}" dash_units=0
  # Unfiltered, then matched here: systemctl exits 1 when a pattern matches
  # nothing, which would read the same as a systemd that will not answer.
  _tp_systemctl list-unit-files --type=service --no-legend || return 1
  list="$_TP_SC"
  while read -r unit _; do
    case "$unit" in
      aperire-server.service|aperire-server-*.service|aperire-read.service|aperire-read-*.service) role=dashboard ;;
      aperire-advisord.service|aperire-advisord-*.service) role=advisor ;;
      aperire-relay.service|aperire-relay-*.service) role=relay ;;
      xrpld.service|rippled.service) role=node ;;
      *) continue ;;
    esac
    [[ "$role" == dashboard ]] && dash_units=1
    # A unit it lists and cannot describe is a fault, never a unit skipped.
    _tp_systemctl show "$unit" -p User --value || return 1
    user="$_TP_SC"
    [[ -n "$user" && "$user" != root && "$user" != 0 ]] || continue
    uid="$(id -u "$user" 2>/dev/null)" || continue
    [[ "$uid" =~ ^[0-9]+$ && "$uid" != 0 ]] || continue
    gids="$(id -G "$user" 2>/dev/null | tr ' ' ',')"
    _tp_systemctl show "$unit" -p Group --value || return 1
    group="$_TP_SC"
    _tp_systemctl show "$unit" -p SupplementaryGroups --value || return 1
    sup="$_TP_SC"
    _tp_systemctl show "$unit" -p AmbientCapabilities --value || return 1
    caps="$_TP_SC"
    gnames=""
    for g in $group $sup; do
      gid="$(_tp_gid "$g")"
      [[ -n "$gid" ]] && gids="${gids:+$gids,}$gid"
      gnames="$gnames $(_tp_group_name "$g")"
    done
    case "$seen" in *" $role:$uid "*) continue ;; esac
    seen="$seen$role:$uid "
    TP_ACCOUNTS+=("$role:$user:$uid:$gids")
    if why="$(_tp_root_equivalent "$user" "$unit" "$gnames" "$caps")"; then
      TP_PRIV+=("$uid:$role:$user:$why")
    fi
    if [[ "$role" == dashboard ]] && _tp_is_login "$user"; then
      TP_TOLERATE+=("$uid")
    fi
  done <<<"$list"
  local name
  for name in xrpld rippled; do
    uid="$(id -u "$name" 2>/dev/null)" || continue
    [[ "$uid" =~ ^[0-9]+$ && "$uid" != 0 ]] || continue
    case "$seen" in *" node:$uid "*) continue ;; esac
    seen="${seen}node:$uid "
    TP_ACCOUNTS+=("node:$name:$uid:$(id -G "$name" 2>/dev/null | tr ' ' ',')")
    if why="$(_tp_root_equivalent "$name" "" "")"; then
      TP_PRIV+=("$uid:node:$name:$why")
    fi
  done
  # A container node's uid. It is in the compose file's `user:` line and
  # nowhere a unit names it, and it may have no account on this host at all
  # (migrate-node-nonroot.sh writes 997:997 whether or not 997 is taken).
  # A `user:` that holds a variable names no uid this can know, so it is a
  # finding on every path, not a node left out of the set.
  local cu cg
  while read -r cu cg; do
    if [[ "$cu" == unknown ]]; then
      TP_PRIV+=("-1:node:container-user:the compose file's user: line holds a variable, so which host account runs the node cannot be known")
      continue
    fi
    if [[ "$cu" == unreadable ]]; then
      TP_PRIV+=("-1:node:container-user:the compose file writes user: in a form this check cannot read (a flow mapping, JSON, a quoted key, a tag, an anchor or an alias), so which host account runs the node cannot be known; write it as user: \"uid:gid\"")
      continue
    fi
    [[ "$cu" =~ ^[0-9]+$ && "$cu" != 0 ]] || continue
    case "$seen" in *" node:$cu "*) continue ;; esac
    seen="${seen}node:$cu "
    name="$(getent passwd "$cu" 2>/dev/null | cut -d: -f1)"
    gids="$(id -G "${name:-$cu}" 2>/dev/null | tr ' ' ',')"
    [[ -n "$gids" ]] || gids="$cg"
    TP_ACCOUNTS+=("node:${name:-uid$cu}:$cu:$gids")
    if [[ -n "$name" ]] && why="$(_tp_root_equivalent "$name" "" "")"; then
      TP_PRIV+=("$cu:node:$name:$why")
    fi
  done < <(_tp_container_uids)
  # A dashboard with no unit (pm2, or started by hand): the account running
  # <tree>/dashboard is the dashboard's account all the same. Only when no
  # dashboard unit exists, because with one its User= is the answer, and
  # only on a process seen running out of this tree. Never the tree's owner
  # by default: that is the account an installer suite's destination belongs
  # to too, and it turned every one of them red (#757).
  if (( ! dash_units )) && [[ -n "$tree" ]]; then
    local pu pg
    while read -r pu pg; do
      [[ "$pu" =~ ^[0-9]+$ && "$pu" != 0 ]] || continue
      case "$seen" in *" dashboard:$pu "*) continue ;; esac
      seen="${seen}dashboard:$pu "
      name="$(getent passwd "$pu" 2>/dev/null | cut -d: -f1)"
      gids="$(id -G "${name:-$pu}" 2>/dev/null | tr ' ' ',')"
      [[ -n "$gids" ]] || gids="$pg"
      TP_ACCOUNTS+=("dashboard:${name:-uid$pu}:$pu:$gids")
      if [[ -n "$name" ]] && why="$(_tp_root_equivalent "$name" "" "")"; then
        TP_PRIV+=("$pu:dashboard:$name:$why")
      fi
      if _tp_is_login "$pu"; then
        TP_TOLERATE+=("$pu")
      fi
    done < <(_tp_dashboard_procs "$tree")
  fi
  return 0
}

# "uid gid" for every container user a node's compose file names, numeric
# ones only: a name in `user:` is a name inside the container, and says
# nothing about a host uid. The files are the wrapper's own configurations
# (root-owned, written by the installer) and the node installer's record.
# The compose file itself is read as data, for digits, and nothing else.
_tp_container_uids() {
  local dir="${TP_CONF_DIR:-/etc/aperire}" cf c u g
  local q='["'"'"']?' var='^[[:space:]]*user:[[:space:]]*["'"'"']?[^#]*[$]'
  for cf in "$dir"/node-wrapper.conf "$dir"/node-wrapper-*.conf; do
    [[ -r "$cf" ]] || continue
    c="$(awk -F= '$1=="COMPOSE_FILE"{sub(/^[^=]*=/,""); print; exit}' "$cf" 2>/dev/null)"
    [[ "$c" == /* && -r "$c" ]] || continue
    sed -nE "s/^[[:space:]]*user:[[:space:]]*${q}([0-9]+)(:([0-9]+))?${q}[[:space:]]*(#.*)?\$/\\1 \\3/p" "$c" 2>/dev/null
    grep -qE -e "$var" "$c" 2>/dev/null && printf 'unknown 0\n'
    # uid:groupname names the uid all the same
    sed -nE "s/^[[:space:]]*user:[[:space:]]*${q}([0-9]+):[A-Za-z_][A-Za-z0-9_.-]*${q}[[:space:]]*(#.*)?\$/\\1 /p" "$c" 2>/dev/null
    # Every `user` key this can see must be one the strict parse above read.
    # A line pattern cannot follow a flow mapping wrapped after a comma, a
    # JSON file, a quoted or spaced key, a value on the next line, a block
    # scalar, a tag, an anchor or an alias, so it counts instead: a key it
    # cannot account for refuses, as a variable does. Whole-line comments are
    # dropped here; trailing ones are not.
    local tok='([0-9]+|[A-Za-z_][A-Za-z0-9_.-]*)' body loose strict
    body="$(grep -vE '^[[:space:]]*#' "$c" 2>/dev/null)"
    loose="$(grep -cE "(^|[[:space:]{,])${q}user${q}[[:space:]]*:" <<<"$body")"
    strict="$(grep -cE "^[[:space:]]*user:[[:space:]]*${q}${tok}(:${tok})?${q}[[:space:]]*(#.*)?\$" <<<"$body")"
    [[ "$loose" == "$strict" ]] || printf 'unreadable 0\n'
    # a comment-looking line that closes a quote and then holds a user key
    grep -qE "^[[:space:]]*#.*[\"'].*[{,][[:space:]]*${q}user${q}[[:space:]]*:" "$c" 2>/dev/null && printf 'unreadable 0\n'
    # tags, anchors, aliases, ? keys, an unpaired backslash, a NUL byte
    LC_ALL=C sed -e 's/\\\\//g' -e 's/\\"//g' "$c" 2>/dev/null \
      | LC_ALL=C grep -qE '(^|[[:space:]{,:[-])([&*][[:alnum:]_.-]|![^[:space:]]|[?]([[:space:]]|$))|[\\]' && printf 'unreadable 0\n'
    [[ $(LC_ALL=C tr -d '\000' < "$c" | wc -c) -eq $(wc -c < "$c") ]] || printf 'unreadable 0\n'
  done
  if [[ -r "$dir/node.conf" ]]; then
    u="$(awk -F= '$1=="NODE_UID"{print $2; exit}' "$dir/node.conf" 2>/dev/null)"
    g="$(awk -F= '$1=="NODE_GID"{print $2; exit}' "$dir/node.conf" 2>/dev/null)"
    [[ "$u" =~ ^[0-9]+$ ]] && printf '%s %s\n' "$u" "$g"
  fi
  return 0
}

# "uid gid" for each process running the dashboard out of <tree>/dashboard.
# The positive signal, the same one verify-after-restart.sh reads for a
# dashboard it finds without a unit: the process's working directory is the
# tree's dashboard directory (pm2 sets it to its pm_cwd) and an argument of
# its command line is server.ts. Neither alone: a shell in that directory is
# not the dashboard, and a server.ts elsewhere is not this tree's.
_tp_dashboard_procs() { # $1 = install tree
  local proc="${TP_PROC_DIR:-/proc}" dash p u g
  dash="$(realpath -e -- "$1/dashboard" 2>/dev/null)" || return 0
  for p in "$proc"/[0-9]*; do
    [[ -d "$p" ]] || continue
    [[ "$(readlink "$p/cwd" 2>/dev/null)" == "$dash" ]] || continue
    tr '\0' '\n' <"$p/cmdline" 2>/dev/null | grep -qxE '(.*/)?server\.ts' || continue
    u="$(awk '/^Uid:/{print $2; exit}' "$p/status" 2>/dev/null)"
    g="$(awk '/^Gid:/{print $2; exit}' "$p/status" 2>/dev/null)"
    [[ "$u" =~ ^[0-9]+$ ]] && printf '%s %s\n' "$u" "$g"
  done | sort -u
  return 0
}

# ---- the walk and the copy (Python, so a descriptor can be held) ---------
_TP_PY="$(cat <<'TP_PY_EOF'
import errno, hashlib, os, stat, struct, sys

ACL_USER, ACL_GROUP_OBJ, ACL_GROUP, ACL_MASK, ACL_OTHER = 0x02, 0x04, 0x08, 0x10, 0x20
WRITE = 2
MAX_HOPS = 40
MAX_BYTES = 16 << 20


class Fault(Exception):
    pass


def acl_of(fd):
    try:
        raw = os.getxattr("/proc/self/fd/%d" % fd, "system.posix_acl_access")
    except OSError as e:
        if e.errno in (errno.ENODATA, errno.EOPNOTSUPP):
            return None
        raise Fault("cannot read the ACL (%s)" % e.strerror)
    if len(raw) < 4 or (len(raw) - 4) % 8 or struct.unpack_from("<I", raw, 0)[0] != 2:
        raise Fault("an ACL this does not understand")
    return [struct.unpack_from("<HHI", raw, 4 + 8 * i) for i in range((len(raw) - 4) // 8)]


def how_writable(st, acl, uid, gids):
    """Why this account can change the inode, or None. POSIX.1e order."""
    if st.st_uid == uid:
        return "owns it"
    if acl is None:
        if st.st_gid in gids:
            return "group write" if st.st_mode & 0o020 else None
        return "write for everyone" if st.st_mode & 0o002 else None
    mask = next((p for t, p, _ in acl if t == ACL_MASK), 7)
    for t, p, i in acl:
        if t == ACL_USER and i == uid:
            return "an ACL entry names it" if p & mask & WRITE else None
    matched = False
    for t, p, i in acl:
        if t == ACL_GROUP_OBJ and st.st_gid in gids:
            matched = True
            if p & mask & WRITE:
                return "group write"
        elif t == ACL_GROUP and i in gids:
            matched = True
            if p & mask & WRITE:
                return "an ACL entry names its group"
    if matched:
        return None
    for t, p, _ in acl:
        if t == ACL_OTHER and p & WRITE:
            return "write for everyone"
    return None


class Walk:
    def __init__(self, accts, strict=False):
        self.accts = accts
        self.findings = []
        # Strict: a symlink anywhere on the way is a refusal, not a turn to
        # follow. The release-digests copy resolves its tree once up front,
        # so the path it hands in has none, and one that turns up is a swap.
        self.strict = strict

    def judge(self, fd, st, disp, sticky_ok):
        acl = None if stat.S_ISLNK(st.st_mode) else acl_of(fd)
        for role, name, uid, gids in self.accts:
            if stat.S_ISLNK(st.st_mode):
                how = "owns it" if st.st_uid == uid else None
            else:
                how = how_writable(st, acl, uid, gids)
            if how is None:
                continue
            if how != "owns it" and sticky_ok and stat.S_ISDIR(st.st_mode) and st.st_mode & stat.S_ISVTX:
                continue
            f = (role, name, uid, how, disp)
            if f not in self.findings:
                self.findings.append(f)

    def reopen(self, fd, st, flags):
        rfd = os.open("/proc/self/fd/%d" % fd, flags)
        rst = os.fstat(rfd)
        if (rst.st_dev, rst.st_ino) != (st.st_dev, st.st_ino):
            os.close(rfd)
            raise Fault("changed while it was being read")
        return rfd

    def walk(self, path, want):
        """Descriptor on the file (want='file') or directory (want='dir')."""
        if not path.startswith("/"):
            raise Fault("%s is not an absolute path" % path)
        root = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
        self.judge(root, os.fstat(root), "/", True)
        chain = [(root, "/")]
        todo = [c for c in path.split("/") if c]
        hops = 0
        try:
            while todo:
                name = todo.pop(0)
                if name == ".":
                    continue
                if name == "..":
                    if len(chain) > 1:
                        os.close(chain.pop()[0])
                    continue
                pfd, pdisp = chain[-1]
                disp = (pdisp if pdisp != "/" else "") + "/" + name
                try:
                    fd = os.open(name, os.O_PATH | os.O_NOFOLLOW, dir_fd=pfd)
                except FileNotFoundError:
                    raise Fault("%s does not exist" % disp)
                except NotADirectoryError:
                    raise Fault("%s is not a directory" % pdisp)
                try:
                    st = os.fstat(fd)
                    if stat.S_ISLNK(st.st_mode):
                        if self.strict:
                            raise Fault("%s is a symlink, or sits under one, so it is not the file its path names" % disp)
                        hops += 1
                        if hops > MAX_HOPS:
                            raise Fault("too many symlinks under %s" % path)
                        self.judge(fd, st, disp + " (symlink)", False)
                        target = os.readlink("", dir_fd=fd)
                        if target.startswith("/"):
                            while len(chain) > 1:
                                os.close(chain.pop()[0])
                        todo = [c for c in target.split("/") if c] + todo
                        continue
                    # A directory is judged here as one on the way. The one
                    # the walk ends in is judged again below, strictly, once
                    # the path is resolved: deciding "the last one" here from
                    # what was left to walk read "<sticky dir>/." as a
                    # directory with more below it, and waved a destination
                    # through on the sticky rule (#756 review, L2).
                    if stat.S_ISDIR(st.st_mode):
                        dfd = self.reopen(fd, st, os.O_RDONLY | os.O_DIRECTORY)
                        self.judge(dfd, st, disp, True)
                        chain.append((dfd, disp))
                        continue
                    if stat.S_ISREG(st.st_mode) and not todo and want == "file":
                        rfd = self.reopen(fd, st, os.O_RDONLY | os.O_NONBLOCK | os.O_NOCTTY)
                        self.judge(rfd, st, disp, False)
                        return rfd, disp
                    raise Fault("%s is not a %s" % (disp, "regular file" if want == "file" else "directory"))
                finally:
                    os.close(fd)
            if want == "dir":
                # The directory a write lands in, judged once more with no
                # sticky exemption, after the path is fully resolved: the
                # exemption is about entries under a sticky directory, and
                # this one is where the new entry goes.
                fd, disp = chain.pop()
                self.judge(fd, os.fstat(fd), disp, False)
                return fd, disp
            raise Fault("%s is a directory" % path)
        finally:
            for fd, _ in chain:
                os.close(fd)


def verdict(findings, tolerated_uid):
    if not findings:
        return "clean"
    if tolerated_uid is not None and all(f[2] == tolerated_uid for f in findings):
        return "tolerated"
    return "refused"


def report(findings, kind):
    for role, name, uid, how, disp in findings:
        print("finding\t%s\t%s\t%s\t%s\t%s" % (kind, role, name, how, disp))


def main(argv):
    accts, tolerate, tree, priv, want, strict = [], set(), None, [], None, False
    while argv and argv[0].startswith("--"):
        flag = argv.pop(0)
        if flag == "--priv":
            uid, role, name, why = argv.pop(0).split(":", 3)
            priv.append((role, name, int(uid), why, "(every path)"))
        elif flag == "--acct":
            role, name, uid, gids = argv.pop(0).split(":", 3)
            accts.append((role, name, int(uid), {int(g) for g in gids.split(",") if g}))
        elif flag == "--tolerate":
            tolerate.add(int(argv.pop(0)))
        elif flag == "--tree":
            tree = argv.pop(0)
        elif flag == "--want":
            want = argv.pop(0)
            if want != "none" and (len(want) != 64 or any(c not in "0123456789abcdef" for c in want)):
                raise Fault("--want takes a sha256 or none, not %r" % want)
        elif flag == "--strict":
            strict = True
        else:
            raise Fault("unknown flag %s" % flag)
    op = argv.pop(0)
    # A copy states the digest its bytes must have, or "none" where the host
    # has no release record to hold them to. Never left out: a copy with no
    # digest is not one this does.
    if op == "copy" and want is None:
        raise Fault("a copy needs --want: the release's sha256 for the file, or none")
    src = Walk(accts, strict)
    sfd, sdisp = src.walk(argv[0], "file")
    # An account that can bypass file permissions outright makes every path
    # writable to it, so it is a finding on every check, not on one inode.
    src.findings[:0] = priv
    try:
        tolerated_uid = None
        if tree is not None and tolerate:
            tfd, _ = Walk(accts).walk(tree, "dir")
            owner = os.fstat(tfd).st_uid
            os.close(tfd)
            if owner in tolerate:
                tolerated_uid = owner
        report(src.findings, "source")
        v = verdict(src.findings, tolerated_uid)
        if op == "check":
            print("verdict\t%s" % v)
            return {"clean": 0, "tolerated": 3, "refused": 2}[v]
        if op != "copy":
            raise Fault("unknown op %s" % op)
        destdir, name, mode = argv[1], argv[2], int(argv[3], 8)
        if not name or "/" in name or name in (".", ".."):
            raise Fault("bad destination name %r" % name)
        dst = Walk(accts)
        dfd, ddisp = dst.walk(destdir, "dir")
        try:
            report(dst.findings, "destination")
            if dst.findings:
                v = "refused"
            print("verdict\t%s" % v)
            if v == "refused":
                return 2
            downer = os.fstat(dfd).st_uid
            if downer not in (0, os.geteuid()):
                raise Fault("%s belongs to uid %d, not root" % (ddisp, downer))
            data = b""
            while True:
                chunk = os.read(sfd, 1 << 16)
                if not chunk:
                    break
                data += chunk
                if len(data) > MAX_BYTES:
                    raise Fault("%s is larger than any program this copies" % sdisp)
            digest = hashlib.sha256(data).hexdigest()
            # The second check, on the same bytes the first one judged: the
            # descriptor the walk opened is the only thing read, and what was
            # read is what is compared and what is written. Before "same", so
            # a tampered file is never let through because the destination
            # already holds the same tampered bytes.
            if want != "none" and digest != want:
                print("mismatch\t%s\t%s" % (digest, sdisp))
                return 4
            owner = (0, 0) if os.geteuid() == 0 else (os.geteuid(), os.getegid())
            try:
                efd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dfd)
            except OSError:
                efd = None
            if efd is not None:
                try:
                    est = os.fstat(efd)
                    same = (stat.S_ISREG(est.st_mode) and stat.S_IMODE(est.st_mode) == mode
                            and (est.st_uid, est.st_gid) == owner and est.st_size == len(data)
                            and os.read(efd, len(data) + 1) == data)
                finally:
                    os.close(efd)
                if same:
                    print("same\t%s\t%s/%s" % (digest, ddisp, name))
                    return 0 if v == "clean" else 3
            tmp = ".%s.new-%d" % (name, os.getpid())
            try:
                tfd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=dfd)
            except OSError as e:
                print("fault\tcannot write into %s (%s)" % (ddisp, e.strerror))
                return 5
            try:
                view = memoryview(data)
                while view:
                    view = view[os.write(tfd, view):]
                if os.geteuid() == 0:
                    os.fchown(tfd, 0, 0)
                os.fchmod(tfd, mode)
                os.fsync(tfd)
                os.close(tfd)
                tfd = None
                os.rename(tmp, name, src_dir_fd=dfd, dst_dir_fd=dfd)
            except BaseException as e:
                if tfd is not None:
                    os.close(tfd)
                try:
                    os.unlink(tmp, dir_fd=dfd)
                except OSError:
                    pass
                if isinstance(e, OSError):
                    print("fault\t%s/%s could not be written (%s)" % (ddisp, name, e.strerror))
                    return 5
                raise
            os.fsync(dfd)
            print("copied\t%s\t%s/%s" % (digest, ddisp, name))
            return 0 if v == "clean" else 3
        finally:
            os.close(dfd)
    finally:
        os.close(sfd)


try:
    sys.exit(main(sys.argv[1:]))
except Fault as e:
    print("fault\t%s" % e)
    sys.exit(1)
except (OSError, ValueError, IndexError) as e:
    print("fault\t%s" % e)
    sys.exit(1)
TP_PY_EOF
)"

_tp_run() { # $@ = op and arguments; the account set and tolerance come from trusted_path_accounts
  local -a args=()
  local a u
  for a in "${TP_ACCOUNTS[@]}"; do args+=(--acct "$a"); done
  for u in "${TP_TOLERATE[@]}"; do args+=(--tolerate "$u"); done
  for a in "${TP_PRIV[@]}"; do args+=(--priv "$a"); done
  # Root's own interpreter at a fixed path, never one a caller's PATH
  # finds (#877 review, L2). None there is a fault, which refuses.
  local py
  py="$(_tp_python)" || { printf 'fault\tno python3 at /usr/bin or /bin, and the check runs in it (sudo apt-get install -y python3)\n'; return 1; }
  "$py" -I -c "$_TP_PY" "${args[@]}" "$@"
}

# Human lines from the program's own, on stderr. Sets TP_REPORT_WHO to the
# account a tolerated finding belongs to, for the warning, TP_REPORT_ACCTS to
# every account found ("name (role), ..."), and TP_REPORT_ROLES to the roles
# among them, each between spaces, so a caller can say which fix fits.
_tp_say() { # $1 = the program's output
  local kind side role name how path
  TP_REPORT_WHO="" TP_REPORT_ACCTS="" TP_REPORT_ROLES=" "
  while IFS=$'\t' read -r kind side role name how path; do
    case "$kind" in
      finding)
        printf '   %s: %s is writable by %s (%s account): %s\n' "$side" "$path" "$name" "$role" "$how" >&2
        TP_REPORT_WHO="$name"
        case ", $TP_REPORT_ACCTS, " in *", $name ($role), "*) ;; *) TP_REPORT_ACCTS="${TP_REPORT_ACCTS:+$TP_REPORT_ACCTS, }$name ($role)" ;; esac
        case "$TP_REPORT_ROLES" in *" $role "*) ;; *) TP_REPORT_ROLES="$TP_REPORT_ROLES$role " ;; esac ;;
      fault)
        printf '   %s\n' "$side${role:+ $role}${name:+ $name}" >&2 ;;
    esac
  done <<<"$1"
}

_tp_warn_tolerated() { # $1 = what was let through
  printf '   warning: %s is writable by %s, the login the dashboard runs as, which\n' "$1" "$TP_REPORT_WHO" >&2
  printf '   also owns this install. It was used anyway so this can go ahead. Moving\n' >&2
  printf '   the dashboard onto its own account (migrate-dashboard-account.sh, ADR 0024)\n' >&2
  printf '   closes it, and a later release refuses instead of warning.\n' >&2
}

# --strict refuses any symlink on the way, as the copy does, so a clean
# answer with it is the answer the copy's source walk would give.
trusted_path_check() { # $1 = path, $2 = install tree ("" for none), $3 = --strict or ""
  local out rc=0
  if ! trusted_path_accounts "${2:-}"; then
    printf '   refused: %s, so the service accounts are unknown\n' "$(tp_accounts_refusal)" >&2
    return 1
  fi
  out="$(_tp_run ${2:+--tree "$2"} ${3:+"$3"} check "$1")" || rc=$?
  _tp_say "$out"
  [[ $rc -eq 3 ]] && _tp_warn_tolerated "$1"
  return "$rc"
}

# The one copy root makes out of a tree, with both of ADR 0024's checks on
# one read. The walk judges the source and the destination directory; the
# bytes are read once, from the descriptor the walk judged; their sha256 is
# compared with WANT; and only then are they written beside the destination
# and renamed in. There is no second lookup of the source by name, so a file
# swapped in after the check is never the one read, and the bytes compared
# are the bytes written.
#
# WANT is the release's sha256 for the file, or "none" when the host has no
# release record (a git checkout); release-digests-lib.sh's rd_stage is the
# one caller that decides which, and nothing else should call this.
# --strict refuses a symlink anywhere on the source's way, rather than
# following it; rd_stage resolves its tree once first, so it has none.
#
# Quiet on stdout. Findings and faults go to stderr. Sets TP_COPY (copied or
# same), TP_COPY_DIGEST (the sha256 of what was read) and TP_REPORT_WHO (the
# account a tolerated finding belongs to).
#   0  copied or already the same, nothing on the way can be changed
#   3  the same, but only the pre-migration login can change the source;
#      the caller says so
#   2  refused: a service account can change the source or the destination
#   4  refused: the bytes read are not WANT
#   1  refused: it could not be checked (missing, not a regular file, a
#      symlink under --strict)
#   5  checked, and could not be written
#   6  refused: the account check could not run (systemd did not answer;
#      TP_ACCOUNTS_FAILED names the call). Nothing was judged about the file,
#      so a caller must not tell it as a file that changed.
# Nothing is written on 1, 2, 4 or 6, and what was at the destination stays.
trusted_path_copy() { # $1 = source, $2 = destination dir, $3 = name, $4 = octal mode, $5 = install tree, $6 = sha256 or none, $7 = --strict or ""
  local out rc=0 kind a
  # Read by the caller (rd_stage), not here.
  # shellcheck disable=SC2034
  TP_COPY="" TP_COPY_DIGEST="" TP_REPORT_WHO=""
  if [[ $# -lt 6 || -z "$6" ]]; then
    printf '   refused: %s: a copy needs the digest it must match\n' "$1" >&2
    return 1
  fi
  if ! _tp_python >/dev/null; then
    printf '   refused: %s: the trusted-path check runs in python3, and this host has none at /usr/bin or /bin (sudo apt-get install -y python3)\n' "$1" >&2
    return 1
  fi
  if ! trusted_path_accounts "$5"; then
    printf '   refused: %s, so the service accounts are unknown\n' "$(tp_accounts_refusal)" >&2
    return 6
  fi
  out="$(_tp_run --tree "$5" --want "$6" ${7:+"$7"} copy "$1" "$2" "$3" "$4")" || rc=$?
  # shellcheck disable=SC2034  # TP_COPY and TP_COPY_DIGEST are the caller's
  while IFS=$'\t' read -r kind a _; do
    case "$kind" in
      copied) TP_COPY=copied TP_COPY_DIGEST="$a" ;;
      same) TP_COPY=same TP_COPY_DIGEST="$a" ;;
      mismatch) TP_COPY_DIGEST="$a" ;;
    esac
  done <<<"$out"
  # Every finding is named on a refusal. A tolerated copy has one owner to
  # name, and the caller says it in one line, not one per directory.
  if [[ $rc -eq 3 ]]; then
    TP_REPORT_WHO="$(awk -F'\t' '$1=="finding"{print $4; exit}' <<<"$out")"
  else
    _tp_say "$out"
  fi
  return "$rc"
}

# The interpreter the service names: root's own, at a fixed path. Never one
# found on a PATH.
_tp_python() {
  local p
  for p in /usr/bin/python3 /bin/python3; do
    if [[ -x "$p" ]]; then printf '%s' "$p"; return 0; fi
  done
  return 1
}

# Read the account set now and keep it for the copies that follow in this
# shell, until trusted_path_release_accounts. For a batch made in one root
# shell that writes no unit and adds no account while it runs (the staging of
# a release's scripts); never across an installer, which can do both.
trusted_path_hold_accounts() { # $1 = the install tree the batch copies out of
  TP_ACCOUNTS_HELD=0
  trusted_path_accounts "${1:-}" || return 1
  TP_ACCOUNTS_HELD=1
}
trusted_path_release_accounts() { TP_ACCOUNTS_HELD=0; }

# This whole block, as text a root shell can define: the account set, the
# walk and the copy. rd_lib_text appends it when this
# library is loaded, so a root shell that gets the release-digests functions
# as text gets both checks with them, and never sources a tree file for it.
tp_lib_text() {
  # Plain assignments, never `declare`: text a caller evals inside a
  # function would otherwise make these local to it.
  printf 'TP_ROOT_GROUPS=(%s)\nTP_ROOT_CAPS=(%s)\nTP_ACCOUNTS_HELD=0\n_TP_PY=%q\n' \
    "$(printf '%q ' "${TP_ROOT_GROUPS[@]}")" "$(printf '%q ' "${TP_ROOT_CAPS[@]}")" "$_TP_PY"
  declare -f _tp_python _tp_is_login _tp_gid _tp_root_equivalent _tp_group_name _tp_systemctl tp_accounts_refusal trusted_path_accounts \
    _tp_container_uids _tp_dashboard_procs \
    trusted_path_hold_accounts trusted_path_release_accounts \
    _tp_run _tp_say _tp_warn_tolerated trusted_path_check trusted_path_copy tp_lib_text
}
# <<< trusted path <<<

# >>> release digests >>>
# Where the record lives. One constant, and root never reads anything else:
# under EUID 0 the environment is ignored outright, so no caller, sudo rule
# or unit can point root at a record of its choosing, or at none. An
# unprivileged fixture may point it at a file of its own; a fixture that runs
# as root (fakeroot) rewrites this one line in its copy instead.
RD_DIGESTS_DEFAULT=/usr/local/lib/aperire/release.sha256
# Whose account this process is, asked of id(1) at a fixed path and never of
# bash's $EUID. bash takes EUID from its environment (env EUID=1000 bash -c
# 'echo $EUID' prints 1000, and so does a root shell under fakeroot), so a
# root shell started with one would read a login's uid as its own and accept
# that login's files as root's (#1109). Prints the uid; fails when it cannot be
# read, and every caller below reads that as "not provably this account".
rd_euid() {
  local p u
  for p in /usr/bin/id /bin/id; do
    [[ -x "$p" ]] || continue
    u="$("$p" -u 2>/dev/null)" || continue
    [[ "$u" =~ ^[0-9]+$ ]] || continue
    printf '%s' "$u"
    return 0
  done
  return 1
}
# Root, on positive evidence only.
rd_is_root() { [[ "$(rd_euid)" == 0 ]]; }
# Not root, on positive evidence only: an unreadable answer is neither, so the
# environment is not trusted and a fixture's shortcut is not taken on it.
rd_unprivileged() {
  local u
  u="$(rd_euid)" || return 1
  [[ "$u" != 0 ]]
}
rd_resolve_path() {
  if rd_unprivileged; then
    RD_DIGESTS="${APERIRE_RELEASE_DIGESTS:-$RD_DIGESTS_DEFAULT}"
  else
    RD_DIGESTS="$RD_DIGESTS_DEFAULT"
  fi
  # Beside the record: a host that has ever had one says so here, root-owned,
  # and from then on a missing record is a refusal, never the fallback.
  RD_REQUIRED="$(dirname -- "$RD_DIGESTS")/digests-required"
}
rd_resolve_path
# Larger than any file the release carries by two orders of magnitude, and
# small enough that a tree file swapped for /dev/zero cannot fill a disk.
RD_MAX_BYTES=16777216
# A tree file swapped for a FIFO blocks its open until a writer shows up.
# Bounded, so that is a refusal after a minute rather than a hung update.
RD_READ_TIMEOUT=60
RD_STATE=""
RD_BODY=""
RD_ANCHOR=""
# Set to 1, by the one caller that means it, for a single staging of a file
# root needs in order to see or repair a tree a service account can write.
# Never from the environment: every load of this block and every root shell
# rd_lib_text builds starts it at 0.
RD_PINNED=0
# Why the last refusal was not about the file: "accounts" when the account
# check could not run (systemd did not answer), empty for every other cause.
# rd_stage sets it and rd_note_refused tags the refusal file's line with it,
# so a closing block that reads the file can tell the two apart (#1089).
RD_REFUSED_WHY=""

rd_say_refused() { # $1 = path in the release, rest = why
  local rel="$1"; shift
  printf 'refused: %s %s\n' "$rel" "$*" >&2
}

# Load the record once per process. 0 = loaded, 3 = there is none on this
# host, 1 = there is one and it cannot be trusted, or the check that judges
# where it sits could not run (RD_STATE=fault). Said on stderr.
rd_manifest_load() {
  case "$RD_STATE" in
    ok) return 0 ;;
    none) return 3 ;;
    bad|fault) return 1 ;;
  esac
  local f="$RD_DIGESTS" meta want_uid line
  # The owner a real run needs is root. A fixture that runs unprivileged
  # writes its record as itself, and holding it to uid 0 there would be a
  # claim about a host nobody is on.
  want_uid=0
  rd_is_root || want_uid="$(rd_euid)" || want_uid=""
  if [[ ! -e "$f" && ! -L "$f" ]]; then
    # No record. The fallback, unless this host has had one: then something
    # took it away, and taking it away must not be how the check is turned off.
    if [[ -e "$RD_REQUIRED" || -L "$RD_REQUIRED" ]]; then
      RD_STATE=bad
      printf 'refused: this host has had release digests (%s) and %s is gone, so nothing is copied as root until a release puts it back: curl -fsSL https://get.aperire.one | bash -s -- --update --force\n' "$RD_REQUIRED" "$f" >&2
      return 1
    fi
    RD_STATE=none
    return 3
  fi
  RD_STATE=bad
  if [[ -L "$f" ]]; then
    printf 'refused: the release digests at %s are a symlink, so nothing is copied as root until that is put right.\n' "$f" >&2
    return 1
  fi
  meta="$(stat -c '%F:%u:%a' -- "$f" 2>/dev/null)" || meta=""
  if [[ "${meta%%:*}" != "regular file" ]]; then
    printf 'refused: the release digests at %s are not a regular file (%s).\n' "$f" "${meta%%:*}" >&2
    return 1
  fi
  local uid mode
  uid="${meta#*:}"; uid="${uid%%:*}"
  mode="${meta##*:}"
  if [[ "$uid" != "$want_uid" ]] || (( (8#$mode & 8#022) != 0 )); then
    printf 'refused: the release digests at %s are owned by uid %s, mode %s. They have to be root'"'"'s and writable by nobody else.\n' "$f" "$uid" "$mode" >&2
    return 1
  fi
  # And the directories above it, judged the way a copy's destination is,
  # with no tolerance and no symlink: an account that can write one of them
  # could rename an older record into place, or take the record away
  # (#877 review, L3). Only where the trusted-path check is loaded; without
  # it nothing is copied anyway.
  if declare -F _tp_run >/dev/null 2>&1; then
    local walk wrc=0
    if ! trusted_path_accounts; then
      printf 'refused: the release digests at %s could not be judged: %s.\n' "$f" "$(tp_accounts_refusal)" >&2
      # Not a verdict on the record, so it is not remembered as one: the next
      # copy asks again. rd_stage reads the reason to tell it as what it is.
      RD_STATE=""
      RD_REFUSED_WHY=accounts
      return 1
    fi
    # Judged as a place root writes to is, by the walk alone: an account
    # that can write any path at all (the docker group) is the source
    # check's finding, and the pre-migration login is one, so counting it
    # here would refuse every copy on every host before the account move.
    local -a TP_PRIV=()
    walk="$(_tp_run --strict check "$f")" || wrc=$?
    if [[ $wrc -ne 0 ]]; then
      _tp_say "$walk"
      # 2 is a finding. Anything else is a walk that never ran (no python3,
      # #1193): nothing was judged about where the record sits, so it is not
      # told as a finding about that.
      if [[ $wrc -ne 2 ]]; then
        RD_STATE=fault
        printf 'refused: the release digests at %s could not be judged: the check of the directories above them did not run (above), so nothing is copied as root.\n' "$f" >&2
        return 1
      fi
      printf 'refused: the release digests at %s sit where a service account can change them (above), so nothing is copied as root until that is put right.\n' "$f" >&2
      return 1
    fi
  fi
  RD_BODY=""
  RD_ANCHOR=""
  local n=0
  while IFS= read -r line || [[ -n "$line" ]]; do
    case "$line" in
      '# anchor '*) RD_ANCHOR="${line#\# anchor }" ;;
      '# refuse '*)
        # A record that stands for "no record this host trusts" (a rollback
        # to a tree whose digests were not kept): every copy refuses, and the
        # line says why and what puts it right.
        printf 'refused: %s\n' "${line#\# refuse }" >&2
        RD_BODY=""
        return 1 ;;
      '#'*|'') ;;
      *)
        if [[ ! "$line" =~ ^[0-9a-f]{64}\ \ [^[:cntrl:]]+$ ]]; then
          printf 'refused: the release digests at %s carry a line that is not a digest and a path.\n' "$f" >&2
          RD_BODY=""
          return 1
        fi
        RD_BODY+="$line"$'\n'
        n=$((n + 1)) ;;
    esac
  done < "$f"
  if [[ $n -eq 0 ]]; then
    printf 'refused: the release digests at %s name no file at all.\n' "$f" >&2
    return 1
  fi
  RD_STATE=ok
  return 0
}

# The digest the release records for one path, or nothing.
rd_digest_for() { # $1 = path in the release
  # Reads to the end rather than exiting on the match: an early exit closes the
  # pipe while printf is still writing a body bigger than a pipe buffer, printf
  # dies of SIGPIPE, and pipefail turns that into exit 141 (#973).
  printf '%s' "$RD_BODY" | awk -v k="$1" '!found && substr($0, 67) == k { print substr($0, 1, 64); found = 1 }'
}

# A path inside the release, spelled one way only: no leading slash, no
# empty, "." or ".." component, nothing but the characters release paths use.
rd_rel_ok() { # $1 = path in the release
  local rel="$1" part
  [[ "$rel" =~ ^[A-Za-z0-9._+-]+(/[A-Za-z0-9._+-]+)*$ ]] || return 1
  local IFS=/
  for part in $rel; do
    [[ "$part" != "." && "$part" != ".." ]] || return 1
  done
  return 0
}

# Why a copy refused on its digest: both digests, the record, the way back.
rd_say_mismatch() { # $1 = the release's digest, $2 = what was read
  printf '  release  %s\n  tree     %s\n  record   %s%s\n' "$1" "$2" "$RD_DIGESTS" "${RD_ANCHOR:+ ($RD_ANCHOR)}" >&2
  printf '  To put the release back as it shipped: curl -fsSL https://get.aperire.one | bash -s -- --update --force, which fetches it again.\n' >&2
  printf '  Code that is not a published release goes in from its git source (--update --source <repo> --ref <ref>),\n  which records no digests and names every copy unchecked.\n' >&2
}

# Read <tree>/<rel> once into <out>, which the caller made and root owns, and
# check what was read. 0 = the bytes are the release's (or there is no record
# and that was said), 1 = refused (said on stderr).
#
# Two checks, on one read (ADR 0024, "How root copies"; #765). With
# trusted-path-lib.sh loaded, trusted_path_copy walks the tree file's path
# from / one descriptor at a time, refuses a component a service account can
# change (and any symlink), reads the bytes from the descriptor it judged,
# and compares their sha256 with the release's before it writes <out>. The
# bytes judged, the bytes hashed and the bytes staged are one read.
#
# Without that check loaded, nothing is copied.
#
# Pinned (RD_PINNED=1): held to its release digest alone, read once through
# one descriptor, and never to its path. Only for a file root needs in order
# to see or repair a tree a service account can write (the state-ancestors
# narrowing, the wrapper step's library, the account move), where a path
# finding must not be what stops the repair of that finding. Only with a
# record: on a host with none there is no digest to pin, so a pinned staging
# takes both checks like any other (#877 review, M1, M2).
rd_stage() { # $1 = tree, $2 = path in the release, $3 = the file to fill
  local rel="$2" out="$3" tree want got rc size
  RD_REFUSED_WHY=""
  if ! rd_rel_ok "$rel"; then
    rd_say_refused "$rel" "is not a path inside a release."
    return 1
  fi
  tree="$(realpath -e -- "$1" 2>/dev/null)" || {
    rd_say_refused "$rel" "has no tree to come from: $1 does not resolve."
    return 1
  }
  rc=0
  rd_manifest_load || rc=$?
  if [[ $rc -eq 1 ]]; then
    if [[ "${RD_REFUSED_WHY:-}" == accounts ]]; then
      rd_say_refused "$rel" "was not copied: $(tp_accounts_refusal). Nothing about the file was judged."
    elif [[ "$RD_STATE" == fault ]]; then
      rd_say_refused "$rel" "was not copied: the check it is held to could not run (above). Nothing about the file was judged."
    else
      rd_say_refused "$rel" "was not copied, because the record it would be checked against cannot be trusted."
    fi
    return 1
  fi
  # What the bytes must be: the release's digest, or none at all on a host
  # with no record (the one fallback, said below every time).
  if [[ $rc -eq 3 ]]; then
    want=none
  else
    want="$(rd_digest_for "$rel")"
    if [[ -z "$want" ]]; then
      rd_say_refused "$rel" "is not a file this release shipped: the release digests have no entry for it."
      return 1
    fi
  fi

  local src="$tree/$rel" crc=0
  if [[ "$RD_PINNED" == 1 && "$want" != none ]]; then
    :
  elif declare -F trusted_path_copy >/dev/null 2>&1; then
    trusted_path_copy "$src" "$(dirname -- "$out")" "$(basename -- "$out")" 0600 "$tree" "$want" --strict || crc=$?
    case $crc in
      0) ;;
      3) printf '  warning: %s can be changed by %s, the login the dashboard runs as; used anyway (ADR 0024)\n' \
           "$rel" "${TP_REPORT_WHO:-that login}" >&2 ;;
      2) rd_say_refused "$rel" "can be changed by a service account (above), so root does not copy it."; return 1 ;;
      4) rd_say_refused "$rel" "is not the file this release shipped."
         rd_say_mismatch "$want" "$TP_COPY_DIGEST"
         return 1 ;;
      5) rd_say_refused "$rel" "was checked, and could not be staged (above)."; return 1 ;;
      6) rd_say_refused "$rel" "was not copied: $(tp_accounts_refusal). Nothing about the file was judged."
         RD_REFUSED_WHY=accounts
         return 1 ;;
      *) rd_say_refused "$rel" "could not be checked (above), so it was not copied."; return 1 ;;
    esac
    if [[ "$want" == none ]]; then
      printf '  unchecked: %s (no release digests on this host, so it was copied from one read and checked against nothing but its path)\n' "$rel" >&2
    fi
    return 0
  else
    rd_say_refused "$rel" "was not copied: the trusted-path check is not loaded here, and root copies only after both checks."
    return 1
  fi

  # Pinned: one open, and everything else through it. The descriptor
  # has to be the file the path names as it stands resolved, which refuses a
  # symlink at any component and a file renamed in from elsewhere; it has to
  # be a regular file; and the copy is read from that same descriptor, so the
  # bytes hashed below are the bytes that were checked for type and place.
  # shellcheck disable=SC2016  # the inner script's own positional parameters
  timeout "$RD_READ_TIMEOUT" bash -c '
    exec 3<"$1" || exit 3
    [ "$(readlink /proc/self/fd/3)" = "$1" ] || exit 5
    [ "$(stat -L -c %F /dev/fd/3)" = "regular file" ] || exit 4
    head -c "$2" <&3 > "$3" || exit 6
  ' rd-read "$src" "$((RD_MAX_BYTES + 1))" "$out" 2>/dev/null || crc=$?
  case $crc in
    0) ;;
    3) rd_say_refused "$rel" "is not in the tree at $tree."; return 1 ;;
    4) rd_say_refused "$rel" "is not a regular file."; return 1 ;;
    5) rd_say_refused "$rel" "is a symlink, or sits under one, so it is not the file its path names."; return 1 ;;
    124) rd_say_refused "$rel" "could not be read within ${RD_READ_TIMEOUT}s."; return 1 ;;
    *) rd_say_refused "$rel" "could not be read."; return 1 ;;
  esac
  size="$(stat -c %s -- "$out" 2>/dev/null)" || size=""
  if [[ -z "$size" ]] || (( size > RD_MAX_BYTES )); then
    rd_say_refused "$rel" "is larger than any file a release carries."
    return 1
  fi
  got="$(sha256sum < "$out" | cut -c1-64)"
  if [[ "$want" != "$got" ]]; then
    rd_say_refused "$rel" "is not the file this release shipped."
    rd_say_mismatch "$want" "$got"
    return 1
  fi
  return 0
}

# Place <tree>/<rel> at <dest>, root-owned, <mode>, only if its bytes are the
# release's. Prints "placed" or "same" on stdout and nothing else there.
# 0 = placed or already the same bytes, 1 = refused (the destination is left
# exactly as it was), 2 = could not be written. With $5 = --kinds, a refusal
# because the account check could not run also prints "refused:accounts" on
# stdout, the one word that crosses the sudo a caller reads only rc and
# stdout through (get-aperire.sh's root_place); no other caller passes it.
rd_install() { # $1 = tree, $2 = path in the release, $3 = destination, $4 = mode, $5 = --kinds or ""
  local tree="$1" rel="$2" dest="$3" mode="$4" dir base stg meta want_uid dmeta duid dgid dmode why
  RD_REFUSED_WHY=""
  dir="$(dirname -- "$dest")"
  base="$(basename -- "$dest")"
  if [[ ! -d "$dir" || -L "$dir" ]]; then
    printf 'error: %s is not a directory, so %s cannot be placed in it.\n' "$dir" "$base" >&2
    return 2
  fi
  # The directory has to be root's and writable by nobody else, or whoever
  # can write it can swap the staging file or the result under root. Group
  # write is allowed for gid 0 alone, whose members are root already. (The
  # directory's own ancestors are the trusted-path check's, lane 1.)
  want_uid=0
  rd_is_root || want_uid="$(rd_euid)" || want_uid=""
  dmeta="$(stat -c '%u:%g:%a' -- "$dir" 2>/dev/null)" || dmeta=""
  duid="${dmeta%%:*}"; dgid="${dmeta#*:}"; dgid="${dgid%%:*}"; dmode="${dmeta##*:}"
  if [[ -z "$dmeta" || "$duid" != "$want_uid" ]] || (( (8#$dmode & 8#002) != 0 )) \
     || { (( (8#$dmode & 8#020) != 0 )) && [[ "$dgid" != 0 ]]; }; then
    printf 'refused: %s is owned by uid %s, gid %s, mode %s, so %s was not placed there. Root writes only into a directory root owns and nobody else can write.\n' \
      "$dir" "${duid:-?}" "${dgid:-?}" "${dmode:-?}" "$base" >&2
    rd_note_refused "$dest" "$rel"
    return 1
  fi
  # Beside the destination, so the last step is a rename on one filesystem,
  # and in root's directory, so nothing else can touch it in between. mktemp
  # creates it O_EXCL under a random name, so nothing planted there first is
  # opened or followed.
  stg="$(mktemp "$dir/.$base.XXXXXXXXXX")" || {
    printf 'error: cannot make a staging file in %s.\n' "$dir" >&2
    return 2
  }
  if ! rd_stage "$tree" "$rel" "$stg"; then
    why="${RD_REFUSED_WHY:-}"
    rm -f -- "$stg"
    printf '  %s was left exactly as it was.\n' "$dest" >&2
    rd_note_refused "$dest" "$rel"
    if [[ "${5:-}" == --kinds && "$why" == accounts ]]; then printf 'refused:accounts\n'; fi
    return 1
  fi
  if [[ -f "$dest" && ! -L "$dest" ]] && cmp -s -- "$stg" "$dest"; then
    meta="$(stat -c '%u:%a' -- "$dest" 2>/dev/null)" || meta=""
    # Same bytes and already root's with this mode. A fixture that runs
    # unprivileged cannot own anything as root, so there it is the bytes.
    if rd_unprivileged || [[ "$meta" == "0:${mode#0}" ]]; then
      rm -f -- "$stg"
      printf 'same\n'
      return 0
    fi
  fi
  # Owner and mode are set on the staging file itself, it is flushed, and it
  # is renamed over the destination, never written into it: a running copy of
  # the program keeps its own inode, and a symlink planted at that name is
  # replaced rather than written through. Then the directory is flushed, so
  # the rename survives a crash.
  if { rd_unprivileged || chown 0:0 -- "$stg"; } \
     && chmod "$mode" -- "$stg" && sync -- "$stg" \
     && mv -fT -- "$stg" "$dest"; then
    sync -- "$dir" 2>/dev/null || true
    printf 'placed\n'
    return 0
  fi
  rm -f -- "$stg"
  printf 'error: %s could not be written.\n' "$dest" >&2
  return 2
}

# rd_install for an installer's own run: says what happened in the installer's
# voice and returns non-zero on anything but a placed or current copy, so a
# caller can `rd_place ... || die ...` and never go on to write a unit that
# names a program that is not there.
rd_place() { # $1 = tree, $2 = path in the release, $3 = destination, $4 = mode
  local out rc=0
  out="$(rd_install "$@" --kinds)" || rc=$?
  case $rc in
    0) if [[ "$out" == same ]]; then
         printf '   %s  (already matches the release)\n' "$3"
       else
         printf '   %s  (root:root %s, copied from the one read that was checked, renamed into place)\n' "$3" "$4"
       fi ;;
    1) if [[ "$out" == refused:accounts ]]; then
         printf 'error: %s was not written: the account check could not run (above), so %s was not judged.\n' "$3" "$2" >&2
       else
         printf 'error: %s was not written: %s in the tree is not the file this release shipped, or a service account can change it (above).\n' "$3" "$2" >&2
       fi ;;
    *) printf 'error: %s could not be written.\n' "$3" >&2 ;;
  esac
  return $rc
}

# The clause an installer's own error line puts after "nothing was written:",
# for a rd_stage that just failed in this shell. A refusal because the account
# check could not run is never told as a file that changed (#1111): $1 is what
# was being staged ("the broker in this tree"). Reads RD_REFUSED_WHY, so it is
# called in the same shell, straight after the failed rd_stage.
rd_was_accounts() { # $1 = the output of an rd_install --kinds that refused, when that is what failed
  [[ "${RD_REFUSED_WHY:-}" == accounts || "${1:-}" == refused:accounts ]]
}
rd_refused_cause() { # $1 = what was staged, $2 = as rd_was_accounts
  if rd_was_accounts "${2:-}"; then
    printf 'the account check could not run (above), so %s was not judged' "$1"
  else
    printf '%s is not the file this release shipped, or a service account can change it (above)' "$1"
  fi
}

# A refused copy is a failed run, not an amber line (#764). An installer run
# under install.sh, or under the update, has its refusals written to the file
# RD_REFUSED_LOG names, and the run that made that file lists them at its end
# and exits non-zero. Written only to a regular file this process owns, never
# through a symlink, and nothing else happens when the variable is unset.
#
# A line is "<destination> (from <path>)". When the refusal was not about the
# file but about the account check not running (RD_REFUSED_WHY=accounts), a
# tab and the word follow, so a closing block can tell a copy that was judged
# and refused from one that was never judged. A line with no tab is the first
# kind, as every line was before.
rd_note_refused() { # $1 = destination, $2 = path in the release
  local f="${RD_REFUSED_LOG:-}" why="${RD_REFUSED_WHY:-}"
  RD_REFUSED_WHY=""
  [[ -n "$f" && -f "$f" && ! -L "$f" && -O "$f" ]] || return 0
  printf '%s (from %s)%s\n' "$1" "$2" "${why:+$'\t'$why}" >> "$f" 2>/dev/null || true
}

# The files root runs out of a release: the top-level installers and every
# file under scripts/. With a record, the record's own entries, so a file the
# release did not ship is not one root runs because it turned up in the tree.
# With none (a git checkout), what the tree holds there, regular files only.
rd_stage_list() { # $1 = tree (resolved); RD_STATE is loaded
  if [[ "$RD_STATE" == ok ]]; then
    printf '%s' "$RD_BODY" | awk '{ p = substr($0, 67) } p == "install.sh" || p == "uninstall.sh" || p == "aperire-one" || p ~ /^scripts\// { print p }'
    return 0
  fi
  local f
  for f in install.sh uninstall.sh aperire-one; do
    [[ -f "$1/$f" && ! -L "$1/$f" ]] && printf '%s\n' "$f"
  done
  [[ -d "$1/scripts" && ! -L "$1/scripts" ]] || return 0
  (cd -- "$1" && find scripts -type f -print) | LC_ALL=C sort
}

# Stage what root runs out of a release, once per run (#764): install.sh,
# uninstall.sh, the menu and every file under scripts/, each through rd_stage
# (both checks, one read) into <out>/<the same path>, so an installer finds
# its siblings where it expects them and root never runs the tree's own
# bytes. <out> is an empty directory this process made and nobody else can
# write. All or nothing: 0 every file staged, 1 refused (each one named on
# stderr, in full) and nothing in <out> may be run.
#
# The account set is read once for the batch: nothing here writes a unit or
# adds an account. The warnings a tolerated tree earns, and the "unchecked"
# lines of a host with no record, are one line each for the whole set, not a
# hundred; a refusal is always said in full.
rd_stage_tree() { # $1 = tree, $2 = out
  local out="$2" tree rel f err rc n=0 tolerated=0 unchecked=0 who="" acct_n=0
  local -a refused_rels=()
  tree="$(realpath -e -- "$1" 2>/dev/null)" || {
    printf 'refused: %s does not resolve, so there is no release to stage for root.\n' "$1" >&2
    return 1
  }
  if [[ ! -d "$out" || -L "$out" || ! -O "$out" ]] || [[ -n "$(ls -A -- "$out" 2>/dev/null)" ]]; then
    printf 'refused: %s is not an empty directory of this account'"'"'s, so nothing was staged in it.\n' "$out" >&2
    return 1
  fi
  rc=0
  RD_REFUSED_WHY=""
  # python3, asked once and before anything is staged (#1355). Every file this
  # copies goes through a check that runs in it, at /usr/bin or /bin and never
  # off a PATH, so a host without it refused each file on its own and named
  # python3 once per file (198 lines for this tree). Said once, with the
  # reason the callers read (RD_REFUSED_WHY=python3), so none of them blames a
  # file for it. Where the trusted-path block is not loaded the next check
  # says so.
  if declare -F _tp_python >/dev/null 2>&1 && ! _tp_python >/dev/null; then
    printf 'refused: this host has no python3 at /usr/bin or /bin, and the check on every file root runs out of %s runs in it, so nothing was staged. Install it, then run this again: sudo apt-get install -y python3\n' "$tree" >&2
    RD_REFUSED_WHY=python3
    return 1
  fi
  rd_manifest_load || rc=$?
  if [[ $rc -eq 1 ]]; then
    if [[ "${RD_REFUSED_WHY:-}" == accounts ]]; then
      printf 'refused: the scripts in %s were not staged: %s.\n' "$tree" "$(tp_accounts_refusal)" >&2
    elif [[ "$RD_STATE" == fault ]]; then
      printf 'refused: the scripts in %s were not staged: the check they are held to could not run (above), so none of them was judged.\n' "$tree" >&2
    else
      printf 'refused: the scripts in %s were not staged, because the record they would be checked against cannot be trusted.\n' "$tree" >&2
    fi
    return 1
  fi
  if ! declare -F trusted_path_copy >/dev/null 2>&1; then
    printf 'refused: the trusted-path check is not loaded, so nothing in %s was staged for root.\n' "$tree" >&2
    return 1
  fi
  if ! trusted_path_hold_accounts "$tree"; then
    printf 'refused: %s, so the service accounts are unknown and nothing was staged.\n' "$(tp_accounts_refusal)" >&2
    RD_REFUSED_WHY=accounts
    return 1
  fi
  while IFS= read -r rel; do
    [[ -n "$rel" ]] || continue
    n=$((n + 1))
    f="$out/$rel"
    if ! (umask 022 && mkdir -p -- "$(dirname -- "$f")") || ! : > "$f" || ! chmod 0600 -- "$f"; then
      printf 'error: %s could not be made, so nothing was staged.\n' "$f" >&2
      refused_rels+=("$rel")
      break
    fi
    rc=0
    err="$(rd_stage "$tree" "$rel" "$f" 2>&1)" || rc=$?
    if [[ $rc -ne 0 ]]; then
      printf '%s\n' "$err" >&2
      refused_rels+=("$rel")
      # Counted, so a batch that was refused only because the account check
      # could not run says so to its caller (RD_REFUSED_WHY, #1111).
      case "$err" in *"the account check could not run"*) acct_n=$((acct_n + 1)) ;; esac
      continue
    fi
    case "$err" in
      *"the login the dashboard runs as"*)
        tolerated=$((tolerated + 1))
        [[ -n "$who" ]] || who="$(sed -n 's/.* can be changed by \(.*\), the login the dashboard runs as.*/\1/p' <<<"$err" | head -1)" ;;
    esac
    case "$err" in *"unchecked: "*) unchecked=$((unchecked + 1)) ;; esac
    case "$rel" in
      *.sh|*.py|aperire-one|scripts/xrpld-image/*) chmod 0755 -- "$f" ;;
      *) chmod 0644 -- "$f" ;;
    esac
  done < <(rd_stage_list "$tree")
  trusted_path_release_accounts
  if [[ ${#refused_rels[@]} -gt 0 ]]; then
    printf 'refused: %d of the %d files root runs out of %s did not pass both checks, so none of them is run as root:\n' "${#refused_rels[@]}" "$n" "$tree" >&2
    printf '  %s\n' "${refused_rels[@]}" >&2
    if [[ $acct_n -gt 0 && $acct_n -eq ${#refused_rels[@]} ]]; then RD_REFUSED_WHY=accounts; fi
    return 1
  fi
  if [[ $n -eq 0 || ! -f "$out/install.sh" ]]; then
    printf 'refused: %s holds no install.sh this release shipped, so there is nothing for root to run.\n' "$tree" >&2
    return 1
  fi
  if [[ $tolerated -gt 0 ]]; then
    printf '  warning: %d of the %d files root runs can be changed by %s, the login the dashboard runs as; used anyway (ADR 0024)\n' \
      "$tolerated" "$n" "${who:-that login}" >&2
  fi
  if [[ $unchecked -gt 0 ]]; then
    printf '  unchecked: %d files (no release digests on this host, so each was copied from one read and checked against nothing but its path)\n' "$unchecked" >&2
  fi
  return 0
}

# Everything above, as text a root shell can define. Used to run one of these
# functions as root from a shell that is not, without sourcing the tree again.
#
# The record's path is NOT carried across. The root side resolves it again
# (rd_resolve_path), and as root it takes the constant and ignores the
# environment: a caller that exported APERIRE_RELEASE_DIGESTS=/nonexistent
# must not thereby hand root the no-record fallback and every copy unchecked.
rd_lib_text() {
  printf 'RD_DIGESTS_DEFAULT=%q\nRD_MAX_BYTES=%q\nRD_READ_TIMEOUT=%q\nRD_STATE=\nRD_BODY=\nRD_ANCHOR=\nRD_PINNED=0\nRD_REFUSED_WHY=\n' \
    "$RD_DIGESTS_DEFAULT" "$RD_MAX_BYTES" "$RD_READ_TIMEOUT"
  declare -f rd_euid rd_is_root rd_unprivileged rd_resolve_path rd_say_refused rd_say_mismatch rd_manifest_load rd_digest_for rd_rel_ok rd_stage rd_install rd_place \
    rd_was_accounts rd_refused_cause rd_note_refused rd_stage_list rd_stage_tree rd_lib_text rd_priv
  # The trusted-path check travels with them when this shell has it, so the
  # root side makes the same two checks this shell would.
  if declare -F tp_lib_text >/dev/null 2>&1; then tp_lib_text; fi
  printf 'rd_resolve_path\n'
}

# Run one of these functions as root: directly when this shell already is,
# through sudo when it is not. The functions travel as text, so the root side
# runs exactly the code this shell has, never a second read of a tree file.
rd_priv() { # $1 = function, rest = its arguments
  if rd_is_root; then
    "$@"
    return
  fi
  local code
  code="$(rd_lib_text)"
  sudo -H bash -c "$code"$'\n''"$@"' rd-priv "$@"
}
# <<< release digests <<<

# A directory only root can write, for the archive root checked and anything
# staged out of the tree for root to source. Made once, on first use, and
# removed however the run ends. Called on its own, never inside $( ): the
# path and its cleanup have to land in this shell, not a subshell's.
RELEASE_HELD=""
release_held_dir() {
  if [[ -z "$RELEASE_HELD" ]]; then
    RELEASE_HELD="$(run_root mktemp -d -t aperire-held.XXXXXXXX)" \
      || die "cannot make a directory only root can write, so nothing can be checked as root."
    ROOT_CLEANUP_PATHS+=("$RELEASE_HELD")
    # Readable, never writable, by the account this script also runs as: a
    # library staged here is sourced by that account's shell too.
    run_root chmod 0755 "$RELEASE_HELD"
  fi
}

# Every root copy this run refused, named again at the end where an operator
# is reading, and the reason the run ends non-zero.
ROOT_COPY_REFUSED=()

# On a host whose dashboard still runs as the login that owns the tree, every
# root copy below is let through with a one-line warning. Said here once, in
# full, so those lines need not each repeat why.
say_tolerated_tree() {
  local rc=0
  trusted_path_check "$DIR/scripts/trusted-path-lib.sh" "$DIR" >/dev/null 2>&1 || rc=$?
  [[ $rc -eq 3 ]] || return 0
  warn "the dashboard runs as the login that owns $DIR, so that login can change what root copies out of it."
  dim "Each file is still held to the release's digests where this host has them, and copied with a one-line warning."
  dim "Moving the dashboard onto its own account closes this, and then a changed path is refused instead (ADR 0024)."
}

# Place one file as root, checked. $1 = path in the release, $2 = destination,
# $3 = mode. Leaves "placed" or "same" in ROOT_PLACED and returns
# rd_install's own status, except 6: a refusal because the account check could
# not run (systemd did not answer), which nothing about the file caused and
# which the closing list tells apart from a file that was judged (#1089).
# Called on its own, never inside $( ): a refusal has to reach
# ROOT_COPY_REFUSED in this shell.
ROOT_PLACED=""
# The one way an entry reaches ROOT_COPY_REFUSED from a staging call. $1 is the
# call's status: 6 is the account check that could not run (systemd did not
# answer), which says nothing about the file, so its entry carries the tag the
# closing list tells apart. Any other status is a file that was judged (#1111).
refused_root_copy() { # $1 = status, $2 = what was refused
  if [[ "$1" -eq 6 ]]; then ROOT_COPY_REFUSED+=("$2"$'\t'accounts); else ROOT_COPY_REFUSED+=("$2"); fi
}
root_place() {
  local rc=0
  ROOT_PLACED="$(rd_priv rd_install "$DIR" "$1" "$2" "$3" --kinds)" || rc=$?
  if [[ $rc -eq 1 && "$ROOT_PLACED" == refused:accounts ]]; then
    ROOT_PLACED=""
    ROOT_COPY_REFUSED+=("$2 (from $1)"$'\t'accounts)
    return 6
  fi
  [[ $rc -eq 1 ]] && ROOT_COPY_REFUSED+=("$2 (from $1)")
  return $rc
}

# A library out of the tree that root is about to source, staged first: read
# once, checked, and copied into the held directory, and that copy is what is
# sourced. Prints the staged path. Both checks, from this script's own copy
# of the trusted-path block, never one out of the tree (#877 review, M1).
stage_for_root() { # $1 = path in the release; release_held_dir has run
  _stage_for_root 0 "$1"
}
# The same, pinned: held to the release digest alone, for a library root
# needs in order to repair a tree a service account can write (the
# state-ancestors narrowing, the wrapper step). A host with no record has no
# digest to pin, and there it takes both checks (rd_stage, RD_PINNED).
stage_for_root_pinned() { # $1 = path in the release; release_held_dir has run
  _stage_for_root 1 "$1"
}
_stage_for_root() { # $1 = 1 to pin, $2 = path in the release
  local held="$RELEASE_HELD"
  [[ -n "$held" && ( "$1" == 0 || "$1" == 1 ) ]] || return 2
  # shellcheck disable=SC2016  # the root shell's own positional parameters
  run_root bash -c "$(rd_lib_text)"'
    RD_PINNED="$4"
    f="$(mktemp "$1/stage-XXXXXXXX")" || exit 2
    if rd_stage "$2" "$3" "$f"; then chmod 0644 "$f" && printf "%s\n" "$f"; else rm -f "$f"; [[ "${RD_REFUSED_WHY:-}" == accounts ]] && exit 6; exit 1; fi
  ' rd-stage "$held" "$DIR" "$2" "$1"
}

# A program root is about to RUN out of the tree, staged with the files it
# loads from beside itself: each read once and checked, into one directory
# only root can write, under its own name, so the program finds its siblings
# where it expects them and root never runs the tree's bytes. Prints the
# directory; release_held_dir has run.
stage_program_for_root() { # $1 = a name for the set, rest = paths in the release
  _stage_program_for_root 0 "$@"
}
# The same, pinned (see stage_for_root_pinned): the account move, which is
# how a host whose tree the Advisor's account can write gets off that shape.
stage_program_for_root_pinned() { # $1 = a name for the set, rest = paths in the release
  _stage_program_for_root 1 "$@"
}
_stage_program_for_root() { # $1 = 1 to pin, $2 = a name for the set, rest = paths in the release
  local pin="$1" held="$RELEASE_HELD" set="$2"; shift 2
  [[ -n "$held" && "$set" =~ ^[a-z0-9-]+$ && ( "$pin" == 0 || "$pin" == 1 ) ]] || return 2
  # shellcheck disable=SC2016  # the root shell's own positional parameters
  run_root bash -c "$(rd_lib_text)"'
    held="$1"; tree="$2"; set="$3"; RD_PINNED="$4"; shift 4
    d="$held/$set"
    rm -rf "$d"; mkdir -m 0755 "$d" || exit 2
    for rel in "$@"; do
      f="$d/${rel##*/}"
      : > "$f" && chmod 0600 "$f" || exit 2
      rd_stage "$tree" "$rel" "$f" || { [[ "${RD_REFUSED_WHY:-}" == accounts ]] && exit 6; exit 1; }
      chmod 0644 "$f"
    done
    printf "%s\n" "$d"
  ' rd-stage-set "$held" "$DIR" "$set" "$pin" "$@"
}

# What root RUNS out of this release, staged once per run (#764): install.sh,
# uninstall.sh, the menu and every file under scripts/, each read once and
# held to both checks (rd_stage_tree), into one directory only root can write.
# Every installer root runs from here on is the staged copy, handed the tree
# it acts on as APERIRE_INSTALL_TREE, so a file rewritten in the tree after
# the release was unpacked is never what root executes. Called on its own,
# never inside $( ): RUN_TREE and a refusal have to land in this shell.
#
# Staged from the unpacked release BEFORE it is swapped in when there is a
# swap ($1 = the unpacked tree, $2 = the record root wrote from its archive,
# in the held directory): a refusal then leaves the host exactly as it was,
# the previous tree and its record in place. Staged after the swap, a refusal
# would leave a new tree nobody built under the running services, and the
# next restart would start the dashboard from it. Called with no arguments
# it stages $DIR against the live record.
RUN_TREE=""
STAGED_BEFORE_SWAP=0
# What the refusal below says was not done, for the runs that stage a release
# for something other than an install ("backed up", "restored").
STAGE_REFUSED_DID=""
STAGE_REFUSED_ACCOUNTS=0
stage_release_for_root() { # [$1 = tree, $2 = record in the held directory]
  [[ -n "$RUN_TREE" ]] && return 0
  release_held_dir
  local tree="${1:-$DIR}" record="${2:-}" rc=0
  if [[ -n "$record" && "$record" != "$RELEASE_HELD/"* ]]; then
    printf 'refused: %s is not a record root holds, so nothing was staged against it.\n' "$record" >&2
    return 1
  fi
  # shellcheck disable=SC2016  # the root shell's own positional parameters
  run_root bash -c "$(rd_lib_text)"'
    out="$1/run"
    # The record this release'"'"'s archive gave, in root'"'"'s own held
    # directory, when the stage comes before the record is put in place.
    if [[ -n "$3" ]]; then RD_DIGESTS="$3"; RD_STATE=""; fi
    rm -rf -- "$out" && mkdir -m 0755 -- "$out" || exit 2
    rd_stage_tree "$2" "$out" || { why="${RD_REFUSED_WHY:-}"; rm -rf -- "$out"; [[ "$why" == accounts ]] && exit 6; exit 1; }
  ' rd-stage-tree "$RELEASE_HELD" "$tree" "$record" || rc=$?
  if [[ $rc -ne 0 ]]; then
    refused_root_copy "$rc" "the installers root runs (install.sh and scripts/ in the release)"
    STAGE_REFUSED_ACCOUNTS=0
    [[ $rc -ne 6 ]] || STAGE_REFUSED_ACCOUNTS=1
    return 1
  fi
  RUN_TREE="$RELEASE_HELD/run"
  # The file every root copy the installers refuse is written to, so a
  # refusal fails this run rather than reading as one more amber line.
  # shellcheck disable=SC2016  # the root shell's own positional parameters
  run_root bash -c 'umask 022; : > "$1"' rd-refused "$RELEASE_HELD/refused.log" \
    && RD_REFUSED_FILE="$RELEASE_HELD/refused.log"
  return 0
}
RD_REFUSED_FILE=""
STAGE_TREE_SAID=""

# The refusal above, where it stops the run: nothing of the new release has
# been run as root. On an update the new tree is already in place (the swap
# came first, and its record with it), so that is said too.
refuse_unstaged_release() {
  printf '\n%serror: root would not run the installers in %s, so nothing was %s from it.%s\n' "$E_RED" "${STAGE_TREE_SAID:-$DIR}" "${STAGE_REFUSED_DID:-installed}" "$E_OFF" >&2
  if [[ $STAGE_REFUSED_ACCOUNTS -eq 1 ]]; then
    cat >&2 <<EOF

  Each file root runs out of a release is read once and held to the
  release's digests and to the trusted-path check before it is run. The
  account check could not run (systemd did not answer), so no file was
  judged, and nothing says the tree changed. Running the update again
  retries it.
EOF
  else
    cat >&2 <<EOF

  Each file root runs out of a release is read once and held to the
  release's digests and to the trusted-path check before it is run. The
  refusals above name each file that failed, and why.
EOF
  fi
  if [[ $STAGED_BEFORE_SWAP -eq 1 ]]; then
    cat >&2 <<EOF

  This was checked before the release was moved into place, so nothing on
  this host changed: $DIR is still the release it was, with its record,
  and nothing was restarted.
EOF
  elif [[ $UPDATE -eq 1 ]]; then
    cat >&2 <<EOF

  The new release is at $DIR, and nothing was installed from it: it is not
  built. Do not restart the services or reboot until this is put right,
  because they would start from it. No release stamp was written.
EOF
  fi
  cat >&2 <<EOF

  Put the release back as it shipped, which fetches it again:

      curl -fsSL ${APERIRE_GET_SELF_URL:-$DEFAULT_SELF_URL} | bash -s -- --update --force

EOF
  exit 1
}

# The refusals an installer run as root wrote to the run's refusal file,
# folded into this run's own list (said again at the end, and the run ends
# non-zero there).
collect_installer_refusals() {
  [[ -n "$RD_REFUSED_FILE" ]] || return 0
  local line
  while IFS= read -r line; do
    [[ -n "$line" ]] && ROOT_COPY_REFUSED+=("$line")
  done < <(run_root cat -- "$RD_REFUSED_FILE" 2>/dev/null || true)
  # Read once: a second installer run in this process starts from empty.
  # shellcheck disable=SC2016  # the root shell's own positional parameters
  run_root bash -c ': > "$1"' rd-refused "$RD_REFUSED_FILE" 2>/dev/null || true
  return 0
}

# THE one function that vouches for the release digests.
#
# Given the archive root holds, it proves the archive is the release, and only
# then writes the per-file digests of what is inside it. The proof is the
# sha256 pinned in this script, and for a published release that sum is the
# one the signed release.json names: fetch_signed_release checked the
# signature and the per-file list it names before the archive was fetched,
# in a directory only root can write. So for a signed release the record's
# body IS the signed list, and the archive has to agree with it entry for
# entry, or nothing is unpacked. Nothing that reads the record changes: it
# is root's, and every root copy out of the tree is checked against it.
#
# The digests are read out of the archive by tar itself (--to-command hands
# each regular file to sha256sum on a pipe), so nothing is unpacked as root
# and nothing touches a disk. A name with a newline in it could forge a
# second line, and fails the whole record instead.
release_manifest_verified() { # $1 = the archive root holds, $2 = where root writes the digests
  local held="$1" out="$2" got anchor
  if [[ -n "$EXPECTED_SHA256" ]]; then
    got="$(run_root sha256sum -- "$held" | cut -c1-64)"
    if [[ "$got" != "$EXPECTED_SHA256" ]]; then
      die "the archive that arrived is not the one this script names, so nothing was unpacked.

  from      $SOURCE_URL
  expected  $EXPECTED_SHA256
  arrived   $got

  A cut download reads exactly like this, and so does an archive that
  changed underneath the script. Run it again; if it says the same thing
  twice, do not install from that address."
    fi
    ok "sha256 $got, which is the archive this script names"
    anchor="sha256 $got, pinned in the bootstrap that fetched it"
  else
    anchor="none: a local file with no checksum, named by whoever ran this"
  fi
  local signed_list=""
  if [[ -n "$SIGNED_DIR" && -n "${ROOT_CLEANUP:-}" ]] && run_root test -s "$SIGNED_DIR/release.files"; then
    signed_list="$SIGNED_DIR/release.files"
    anchor="signed release.json for sha256 ${EXPECTED_SHA256}, release key $(release_key_fingerprints "$SIGNED_DIR/release-signers" | tr '\n' ' ' | sed 's/ $//')"
  fi
  # shellcheck disable=SC2016  # the root shell's own positional parameters
  run_root env RD_ANCHOR="$anchor" RD_SOURCE="$SOURCE_URL" \
      bash -c "$(declare -f rd_record_digests)"$'\n''rd_record_digests "$@"' rd-record "$held" "$out" \
    || die "the release digests could not be read out of the archive, so nothing was unpacked."
  if [[ -n "$signed_list" ]]; then
    # shellcheck disable=SC2016  # the root shell's own positional parameters
    run_root env RD_ANCHOR="$anchor" RD_SOURCE="$SOURCE_URL" \
        bash -c "$(declare -f rd_record_from_signed)"$'\n''rd_record_from_signed "$@"' rd-signed "$out" "$signed_list" \
      || die "the archive is not the tree its signed file list names, so nothing was unpacked.

  The archive's sum matched, so this is not a cut download: the signed list
  and the archive disagree about what is inside it. Do not install from that
  address."
    ok "release digests taken from the signed file list, and the archive agrees with every entry"
  fi
}

# The signed half of the above, as root. The record the archive gave is held
# against the signed list as two sets of "<sha256>  <path>" lines, and only
# when they are the same set is the record rewritten with the signed list as
# its body. Both files are root's: the record in the held directory, the list
# in the directory the signature was checked in.
rd_record_from_signed() { # $1 = the record rd_record_digests wrote, $2 = the signed release.files
  set -euo pipefail
  umask 022
  local rec="$1" list="$2" tmp
  # The signed list has the same shape as the record body, or it is not used.
  if grep -qvE '^[0-9a-f]{64}  [^/[:cntrl:]][^[:cntrl:]]*$' "$list"; then return 1; fi
  if ! cmp -s <(grep -E '^[0-9a-f]{64}  ' "$rec" | LC_ALL=C sort) <(LC_ALL=C sort "$list"); then
    return 1
  fi
  tmp="$(mktemp "$rec.XXXXXXXX")"
  {
    grep -E '^# ' "$rec" | grep -v '^# anchor '
    printf '# anchor %s\n' "$RD_ANCHOR"
    printf '# body: the signed release.files, which the archive matched entry for entry\n'
    cat -- "$list"
  } > "$tmp"
  mv -fT -- "$tmp" "$rec"
}

# The root half of the above, sent to the root shell as text. It runs in the
# held directory, and the per-file hook it hands tar lives there too: tar
# runs it once per regular file with the file on stdin and its name in
# TAR_FILENAME, and writes nothing to disk itself.
rd_record_digests() { # $1 = the archive root holds, $2 = where to write
  set -euo pipefail
  umask 022
  local dir hook
  dir="$(dirname -- "$1")"
  hook="$dir/rd-entry.sh"
  cat > "$hook" <<'HOOK'
n="${TAR_FILENAME#./}"
case "$n" in
  */*) ;;
  *) echo BAD; cat >/dev/null; exit 0 ;;
esac
rel="${n#*/}"
case "$rel" in
  *"
"*|*'\'*|../*|*/../*|*/..|..) echo BAD; cat >/dev/null; exit 0 ;;
esac
printf '%s  %s\n' "$(sha256sum | cut -c1-64)" "$rel"
HOOK
  {
    printf '# Aperire One release digests: the sha256 of every regular file in the release.\n'
    printf '# Written by root from the archive it held, before anything ran in the tree.\n'
    printf '# anchor %s\n' "$RD_ANCHOR"
    printf '# source %s\n' "$RD_SOURCE"
    printf '# key %s\n' "$(sha256sum < "$1" | cut -c1-64)"
    (cd "$dir" && tar -xzf "$1" --to-command="sh '$hook'")
  } > "$2"
  if grep -qx BAD "$2"; then return 1; fi
  # A name that appears twice is an archive whose tree and whose digests
  # could disagree (tar keeps the last, a lookup finds the first), so the
  # whole record fails.
  if grep -E '^[0-9a-f]{64}  ' "$2" | cut -c67- | sort | uniq -d | grep -q .; then return 1; fi
  grep -qE '^[0-9a-f]{64}  ' "$2"
}

# The record follows the tree. The one this run replaces is KEPT, under its
# own key (the sha256 of the archive it was read out of), in
# release.sha256.kept/, and that is what a rollback puts back: the kept tree's
# .release stamp names the same sha, so the tree and its record are matched
# by what they are, not by which one happened to be written last. The newest
# eight are kept.
#
# Writing a record also writes digests-required beside it. From then on this
# host has no way to reach "no record": a missing one refuses every copy.
persist_release_digests() { # $1 = the digests root wrote
  local src="$1" rc=0 prev_id=""
  # This process may already have loaded (and cached) a record: the next
  # load has to read the one written here.
  RD_STATE=""; RD_BODY=""; RD_ANCHOR=""
  # The tree the swap moved aside, by what root reads of it now (#782): the
  # record being replaced is that tree's, and a rollback finds it by this.
  if [[ -n "${KEPT_PREVIOUS:-}" ]]; then
    prev_id="$(run_root stat -c '%d:%i' -- "$KEPT_PREVIOUS" 2>/dev/null)" || prev_id=""
  fi
  run_root bash -c "$(rd_lib_text)"$'\n'"$(declare -f rd_persist_record)"$'\n''rd_persist_record "$@"' rd-persist "$src" "$prev_id" \
    || rc=$?
  if [[ $rc -ne 0 ]]; then
    die "the release digests could not be written to $RD_DIGESTS, so nothing out of this tree can be checked as root. Nothing was installed."
  fi
  ok "release digests recorded at $RD_DIGESTS: root copies out of this tree are checked against them"
  return 0
}

# The root half of the above, sent as text. rd_resolve_path (in the text
# before it) has already set RD_DIGESTS and RD_REQUIRED from root's own
# constant, never from anything this account passed.
rd_persist_record() { # $1 = the new record, $2 = <dev>:<ino> of the tree the swap moved aside, or ""
  set -euo pipefail
  umask 022
  local cur="$RD_DIGESTS" kept="$RD_DIGESTS.kept" prev="$RD_DIGESTS.previous" key="" tmp f
  [[ -f "$1" && -s "$1" ]] || { echo "no record to write" >&2; return 1; }
  mkdir -p "$(dirname "$cur")"
  if [[ -L "$cur" ]]; then
    rm -f "$cur"
  elif [[ -f "$cur" ]]; then
    key="$(sed -n 's/^# key //p' "$cur" | head -1)"
    if [[ "$key" =~ ^([0-9a-f]{64}|git-[0-9a-f]{40})$ ]]; then
      [[ -d "$kept" && ! -L "$kept" ]] || { rm -rf "$kept"; mkdir -m 0755 "$kept"; }
      mv -fT "$cur" "$kept/$key"
    else
      key=""
    fi
  fi
  # Which kept record belongs to the tree the swap moved aside (#782), in a
  # file only root writes, beside the record and not inside kept/ (which is
  # pruned by count). A rollback reads the key here, never out of the tree's
  # own stamp, which the tree's account can rewrite. No previous tree, or no
  # record that went with it: no pointer, and a rollback refuses.
  rm -f "$prev"
  if [[ -n "$key" && "${2:-}" =~ ^[0-9]+:[0-9]+$ ]]; then
    tmp="$(mktemp "$prev.XXXXXXXXXX")"
    printf '%s %s\n' "$2" "$key" > "$tmp"
    chmod 0644 "$tmp"
    rd_unprivileged || chown 0:0 "$tmp"
    mv -fT "$tmp" "$prev"
  fi
  tmp="$(mktemp "$cur.XXXXXXXXXX")"
  cat -- "$1" > "$tmp"
  chmod 0644 "$tmp"
  rd_unprivileged || chown 0:0 "$tmp"
  sync -- "$tmp"
  mv -fT "$tmp" "$cur"
  if [[ ! -f "$RD_REQUIRED" || -L "$RD_REQUIRED" ]]; then
    rm -f "$RD_REQUIRED"
    printf 'This host checks every root copy against its release digests. Written by get-aperire.sh; a missing record here is a refusal.\n' > "$RD_REQUIRED"
    chmod 0644 "$RD_REQUIRED"
  fi
  sync -- "$(dirname "$cur")" 2>/dev/null || true
  if [[ -d "$kept" ]]; then
    # shellcheck disable=SC2012  # the names are keys this function wrote
    ls -1t "$kept" | tail -n +9 | while IFS= read -r f; do rm -f "$kept/$f"; done
  fi
  return 0
}

# -- Fetch -----------------------------------------------------------
#
# Two shapes of source, told apart by the URL and nothing else. A .tar.gz is
# a published release: one archive, one checksum, fetched and checked before
# a byte of it is unpacked. Anything else is a git remote, which is what a
# fork, a rehearsal and `--source` against a working repository are.
#
# Both land the same tree in the same place, owned by the same account. The
# difference stops at this section: everything after it reads $DIR and cannot
# tell which door the release came through.
source_is_tarball() { [[ "$SOURCE_URL" == *.tar.gz ]]; }

ensure_git() {
  command -v git >/dev/null 2>&1 && return 0
  # This one apt call belongs here rather than in prepare-host.sh, which
  # installs git too: prepare-host.sh lives inside the checkout, and there
  # is no checkout until git exists.
  info "git is not on this host yet, installing it"
  run_root env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l apt-get update -qq
  run_root env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l \
    apt-get install -y -qq --no-install-recommends git
  command -v git >/dev/null 2>&1 || die "git still is not here after apt-get install git."
}

# The archive path, and the two guards that make it safe to run at all.
#
#   1. The checksum is checked BEFORE anything is unpacked. A truncated
#      download, a proxy's error page, an archive swapped underneath the
#      script: all of them fail the sum, and the file is deleted unread.
#   2. It unpacks into a temporary directory BESIDE $DIR and is renamed into
#      place in one step. Same filesystem, so the rename is atomic: $DIR
#      either does not exist or is the whole release. Never half of one, not
#      even for the moment an unpack takes.
#
# Everything here runs as the operator, the way `git clone` does on the other
# path, so the tree that lands is theirs to build in. A tree unpacked by root
# is one `npm ci` cannot write into.
# ---- carrying an earlier install's files into the new release -------
#
# What moves across, and nothing else. Three groups, and each one is here
# because it is the operator's rather than the release's:
#
#   data/                 the database (operators, passkeys, alert history)
#                         and the logs beside it
#   dashboard/config/     the files an operator edits. rules.local.yaml is
#                         among them and rules.yaml is NOT (ADR 0020): the
#                         shipped rule set is the release's and this update
#                         is how a corrected rule reaches this host, while
#                         the overrides beside it are the operator's and
#                         cross untouched
#   advisor/<state>       every gitignored directory the Advisor writes into.
#                         state/ holds read.token, and the other three hold
#                         fleet knowledge, bundles and the run evidence, none
#                         of which any release carries
#
# Everything else in the old tree is source, node_modules and built binaries,
# which the new release brings and the prepare step rebuilds.
# fleet-link.json is the credential pairing wrote: the ONLY copy of it is this
# file, and a node that loses it stops dialling its aggregator on its first
# update, with a re-pair as the only way back. mv keeps its 0600.
# fleet-links.json is the aggregator's half: the hash of every paired node's
# link credential. Lose it and every node fails to link until it is re-paired.
# mv is a rename inside one directory, so it keeps the 0600 and the owner, and
# needs no read of the file. scripts/test-get-aperire.sh holds this list equal
# to the backup set's dashboard/config rows.
CARRY_CONFIG=(rules.local.yaml channels.yaml fleet.yaml fleet-trust.yaml fleet-trust.pub.yaml fleet-link.json fleet-links.json authn.yaml digest.yaml metric-alerts.yaml)
# bin/ too: the advisord unit names the install path, and an update that
# left the binary in the previous tree left the unit exec'ing nothing,
# 203/EXEC in a loop, on every host with the Advisor (#350). Carried as it
# is; whether it is then rebuilt from the new tree is the drift note's job.
CARRY_ADVISOR=(state evidence knowledge-fleet knowledge-bundles bin)

# The old tree, kept. Set by swap_kept_checkout and named in the closing text:
# nothing here ever deletes it, because a bootstrap that removes the only copy
# of somebody's previous install is a bootstrap nobody can undo.
KEPT_PREVIOUS=""
# Which directory moved in, as root read it just before the rename (#828):
# "<st_dev>:<st_ino>", the way `stat -c '%d:%i'` prints it. A rename keeps
# both, so the fleet broker's re-record can prove that the directory now at
# $DIR is the one this run verified and moved there, and not one swapped in
# after it. Empty when this run swapped nothing.
SWAPPED_IN_ID=""

# The order below is the whole safety argument, and it is not the obvious one.
#
# Carrying the files across FIRST and swapping afterwards would put the only
# copy of the database inside a staging directory that the exit trap removes:
# a run that dies in between takes the data with it. So the old tree is
# RENAMED first, which loses nothing and cannot be half-done, the new tree
# takes its place, and only then are the files moved out of the renamed one.
# At every instant the database exists in exactly one place, and that place is
# never deleted by anything here.
#
# Moved rather than copied, deliberately: a copy of a multi-gigabyte database
# is slow, can fill the disk, and would need root to keep its ownership. A
# rename keeps owner, group, mode and timestamps exactly as they were.
# A name in the tree that root removes when the operator's own delete could
# not (#1064). Never `rm` as root by name: rm resolves the path again, and
# follows a parent swapped for a link. The release's state helper does it on
# descriptors instead, from the checked copy staged for root before the swap
# ($RUN_TREE, never the tree's own bytes), in root's own interpreter: walked
# from / without following a link, a link or a non-directory at the name
# refused, nothing on another filesystem entered. With no staged copy there
# is no root delete at all: the name is left, and said. Returns non-zero when
# the name is still there.
root_remove_in_tree() { # $1 = remove-tree or unlink, $2 = a path inside $DIR
  local verb="$1" path="$2" tool="" py uid
  [[ -n "$RUN_TREE" ]] && tool="$RUN_TREE/scripts/state-file.py"
  if [[ -z "$tool" ]] || ! run_root test -f "$tool"; then
    warn "${path#"$DIR"/} could not be removed as $OP_USER, and root deletes nothing in the tree by name, so it was left."
    return 1
  fi
  py="$(_tp_python)" || { warn "${path#"$DIR"/} was left: there is no python3 at /usr/bin or /bin to remove it with."; return 1; }
  uid="$(id -u "$OP_USER" 2>/dev/null)" || uid=""
  run_root "$py" -I "$tool" "$verb" "$path" --root "$DIR" ${uid:+--owner "$uid"}
}

# Kept trees beside the checkout: the newest KEPT_TREES_MAX stay, older ones go
# (#958). Root keeps release digest records for the newest 8 updates and no
# more (persist_release_digests prunes by count), so a tree older than that
# has no record root could check an installer against, and a rollback goes only
# to the tree the last update moved aside. Before this the trees stayed for
# ever (38 and 39 of them on two lab boxes, each a full tree) and nothing told
# the operator the older ones could not be used.
KEPT_TREES_MAX=8
KEPT_TREES_PRUNED=0
KEPT_TREES_HELD=0
KEPT_TREES_KEPT=0

# Only the operator's own rm runs. The kept trees sit in the login's home and
# the login picks their names, so root has no record that a name is a tree an
# update moved aside (its only record is the one rollback pointer). A real
# directory the login renames to an old stamp could hold files a service
# account owns and the login cannot delete (advisor/state), and a root
# remove-tree on that name would delete them. So there is no root fallback
# (#958 review): what the operator's rm cannot remove is left and named, with
# the one command for it. Never touched: the newest KEPT_TREES_MAX, the tree
# root's pointer names (the one a rollback returns to, whatever its age), a
# link, and a tree that still holds anything the carry should have moved out
# (a database that did not move is the operator's, and is named instead). A
# failure is said and never fatal: the update is done.
prune_kept_trees() {
  KEPT_TREES_PRUNED=0 KEPT_TREES_HELD=0 KEPT_TREES_KEPT=0
  [[ -n "$KEPT_PREVIOUS" ]] || return 0
  local parent base t i=0 ptr_id="" held_why
  parent="$(dirname -- "$DIR")"; base="$(basename -- "$DIR")"
  [[ -f "${RD_DIGESTS}.previous" && ! -L "${RD_DIGESTS}.previous" ]] \
    && ptr_id="$(head -1 -- "${RD_DIGESTS}.previous" 2>/dev/null | cut -d' ' -f1)"
  local -a trees=()
  # Newest first. The stamp is UTC to the second and a clash adds -N, so the
  # names sort by age; type d leaves a link out of the list altogether.
  mapfile -t trees < <(find "$parent" -maxdepth 1 -type d -name "${base}.previous-*" -printf '%f\n' 2>/dev/null | LC_ALL=C sort -r)
  local name
  for name in "${trees[@]}"; do
    # Only the names an update gives (a UTC stamp, then -N on a clash). The
    # login chooses what else sits beside the checkout, and a name outside
    # this shape is not ours to prune or to print into a command line.
    [[ "$name" == "$base".previous-* \
       && "${name#"$base".previous-}" =~ ^[0-9]{8}T[0-9]{6}Z(-[0-9]+)?$ ]] || continue
    i=$((i + 1))
    t="$parent/$name"
    if [[ $i -le $KEPT_TREES_MAX ]]; then
      KEPT_TREES_KEPT=$((KEPT_TREES_KEPT + 1)); continue
    fi
    held_why=""
    if [[ -n "$ptr_id" && "$(stat -c '%d:%i' -- "$t" 2>/dev/null)" == "$ptr_id" ]]; then
      held_why="it is the tree a rollback returns to"
    elif checkout_holds_operator_files "$t"; then
      held_why="it still holds files that were meant to move out of it (data/ or config), which are yours"
    fi
    if [[ -n "$held_why" ]]; then
      KEPT_TREES_HELD=$((KEPT_TREES_HELD + 1)); KEPT_TREES_KEPT=$((KEPT_TREES_KEPT + 1))
      warn "kept $t: $held_why. Nothing here removes it."
      continue
    fi
    if as_operator rm -rf -- "$t" 2>/dev/null && [[ ! -e "$t" ]]; then
      KEPT_TREES_PRUNED=$((KEPT_TREES_PRUNED + 1)); continue
    fi
    KEPT_TREES_KEPT=$((KEPT_TREES_KEPT + 1))
    warn "could not remove $t as $OP_USER (something in it belongs to another account), so it was left."
    dim "if you know it is an old kept tree, remove it yourself:  sudo rm -rf -- $(printf '%q' "$t")"
  done
  if [[ $KEPT_TREES_PRUNED -gt 0 ]]; then
    step "older kept trees"
    info "removed $KEPT_TREES_PRUNED kept tree(s) older than the newest $KEPT_TREES_MAX beside $DIR: root holds release digests for no more than that, so nothing could check an installer run out of the older ones."
    info "$KEPT_TREES_KEPT kept tree(s) remain."
  fi
  return 0
}

swap_kept_checkout() { # $1 = the new tree, unpacked beside $DIR
  local new="$1" previous stamp f n=0
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  previous="${DIR}.previous-${stamp}"
  # A name nothing is using. `mv a b` where b is an existing DIRECTORY does
  # not refuse, it moves a INSIDE b, so a second reinstall in the same second
  # would bury the first one's tree inside it and the closing text would name
  # a path that no longer holds what it says. Two runs a second apart is not a
  # thing an operator does by hand, and it is a thing a script does.
  while [[ -e "$previous" ]]; do
    n=$((n + 1))
    previous="${DIR}.previous-${stamp}-${n}"
  done

  as_operator mv "$DIR" "$previous" \
    || die "could not move the earlier checkout aside to $previous, so nothing was replaced."
  KEPT_PREVIOUS="$previous"
  SWAPPED_IN_ID="$(run_root stat -c '%d:%i' -- "$new" 2>/dev/null)" || SWAPPED_IN_ID=""
  as_operator mv "$new" "$DIR" \
    || die "the earlier checkout is at $previous and the new release did not move into $DIR. Nothing was deleted; move it back or unpack again."

  # The heading is printed by the first thing that moves, never before it. A
  # tree an install died halfway through has nothing of the operator's in it,
  # and "carrying your files" over an empty list is a claim about data that
  # does not exist.
  local said=0
  carrying() { [[ $said -eq 1 ]] && return 0; said=1; step "carrying your files into the new release"; }

  if [[ -d "$previous/data" ]]; then
    carrying
    # As root, like the Advisor's directories below (ADR 0024). data/ is the
    # dashboard's account's on a fresh install, and moving a directory to a
    # new parent needs write on that directory itself, to update its '..'.
    # The operator owns both parents and not data/, so the old as_operator mv
    # was refused there. Both parents are the operator's, so the dashboard's
    # account cannot swap either name under root, and a rename keeps the
    # owner. -T: never move it INTO something already standing at the name.
    # Cleared first, and when the operator cannot, root clears it on
    # descriptors (#1064), never by name; if neither can, nothing is moved.
    if ! { as_operator rm -rf "$DIR/data" 2>/dev/null || root_remove_in_tree remove-tree "$DIR/data"; }; then
      warn "data/ was not moved across: $DIR/data could not be cleared for it. It is still at $previous/data"
    elif run_root mv -T "$previous/data" "$DIR/data"; then
      ok "data/    the database, the passkeys and the logs"
    else
      warn "data/ could not be moved across. It is still at $previous/data"
    fi
  fi
  # The release stamp, moved without a word about it. It is not the
  # operator's file and it is not the release's either: it is what the last
  # finished install wrote about itself, and this run overwrites it with its
  # own. It comes across so that a run that dies between the swap above and
  # the stamp below leaves a host that still says what it is, instead of one
  # that says nothing at all. What it says then can be stale and can never be
  # newer than the code on disk, which is the safe direction of that race.
  # Copied, not moved: the kept tree keeps its own stamp, whose sha256 is
  # the key a rollback uses to find the release digests that tree came with.
  if [[ -f "$previous/.release" ]]; then
    as_operator cp -p "$previous/.release" "$DIR/.release" 2>/dev/null || true
  fi
  for c in "${CARRY_CONFIG[@]}"; do
    [[ -f "$previous/dashboard/config/$c" ]] || continue
    carrying
    if as_operator mv -f "$previous/dashboard/config/$c" "$DIR/dashboard/config/$c"; then
      ok "dashboard/config/$c"
    else
      warn "dashboard/config/$c could not be moved across. It is still at $previous/dashboard/config/$c"
    fi
  done
  for c in "${CARRY_ADVISOR[@]}"; do
    [[ -d "$previous/advisor/$c" ]] || continue
    carrying
    # As root, not as the operator. These directories are the Advisor's
    # account's (advisord writes its state, evidence and knowledge as
    # aperire-advisor, mode 700), and a directory can only be renamed into
    # another parent by someone who may write it, to update its own '..'.
    # The operator owns both parents and still got "Permission denied" on
    # the first live reinstall (aperire4, 2026-09-07). A rename keeps the
    # owner, so the Advisor finds its files as it left them. Cleared the
    # same way as data/ above (#1064).
    if ! { as_operator rm -rf "$DIR/advisor/$c" 2>/dev/null || root_remove_in_tree remove-tree "$DIR/advisor/$c"; }; then
      warn "advisor/$c/ was not moved across: $DIR/advisor/$c could not be cleared for it. It is still at $previous/advisor/$c"
    elif run_root mv "$previous/advisor/$c" "$DIR/advisor/$c"; then
      ok "advisor/$c/"
    else
      warn "advisor/$c/ could not be moved across. It is still at $previous/advisor/$c"
    fi
  done
  if [[ $said -eq 0 ]]; then
    step "the earlier checkout held nothing to carry"
    info "no data/, no config you had edited, no Advisor state. Nothing was"
    info "moved, and nothing was deleted."
  fi
  info "the earlier checkout is kept at"
  dim "$previous"
  return 0
}

# ---- rebuilding the Advisor across an update -------------------------
#
# install.sh's own build step only rebuilds advisor/bin with --with-advisor,
# and an update never passes that: the flag means "put the Advisor on this
# host", which is not a question an update gets to answer on its own. So the
# binary CARRY_ADVISOR just moved across above is the one this host would run
# forever, on every release after the one that built it, unless something
# here compares the new tree's advisor/ against the old one and rebuilds when
# they differ. #383, the drift left over once #350 carried the binary but
# nothing ever rebuilt it.
#
# Gated the way the fleet update tool gates its own advisord swap:
# has the Go source changed, or does the carried binary's own stamp already
# disagree with the commit this run is about to write into .release.
# Checksums, not mtimes: a tree this run just extracted whole gives every
# file the same mtime, which is exactly what makes prepare-host.sh's own
# newest-than check useless on a tree that landed a second ago. A binary too
# old to answer -version is read as stale here, the opposite of
# prepare-host.sh's own stamp_stale(): there a source diff already catches a
# real change and forcing on "cannot say" would rebuild the relay on every
# unstamped dev run, but here the stamp is the only signal an update with an
# unchanged source tree has left, and "cannot say" left alone is exactly the
# drift this closes.
#
# Not routed through prepare-host.sh's own WITH_ADVISOR build: that path also
# downloads a Go toolchain when none is found, and an update that never asked
# for the Advisor must never decide to install one either. A host with no Go
# anywhere this looks keeps the carried binary and is told so by name.
#
# Looked for in the same order install-advisord.sh's own find_go() uses
# (~L198-231): /usr/local/go/bin/go first, because that is exactly where
# prepare-host.sh puts the pinned toolchain and where install-advisord.sh
# already finds it under sudo, whose PATH has none of /etc/profile.d's
# additions. Only then `command -v go` on this run's own PATH, then the
# operator's login shell, for a Go apt or the operator installed by hand.
# Disagreeing with install-advisord.sh about whether a host has Go is worse
# than checking one place too many: a host missed here carries a stale build
# it did not have to (#633).
#
# advisor/go.mod's own minimum, the same figure prepare-host.sh pins as
# GO_MIN, and the same comparison it uses (`sort -V`, since Go's version
# numbers are not zero-padded and a plain string compare puts 1.9 after
# 1.23). A candidate below it is skipped, not trusted: it would answer
# `version` and win the slot, and the build a line further down would fail
# on syntax this project's own module already requires, on a host that may
# have a perfectly good Go one candidate further down the list.
#
# Asked through advisor_ask, so from / (#1203). Go refuses to run from a
# directory its user cannot search, and sudo hands the operator the caller's
# directory: started from /root (`sudo -i`, then --update), every candidate
# read as no Go and a changed Advisor was carried stale.
ADVISOR_GO_MIN="1.23"
advisor_go_ok() { # $1 = go binary; prints its version, as the build itself would see it, if it meets ADVISOR_GO_MIN
  local v
  v="$(advisor_ask "$1" version | sed -n 's/.*go\([0-9]*\.[0-9]*\).*/\1/p')"
  [[ -n "$v" ]] || return 1
  [[ "$(printf '%s\n%s\n' "$ADVISOR_GO_MIN" "$v" | sort -V | head -1)" == "$ADVISOR_GO_MIN" ]] && echo "$v"
}
advisor_go_bin() {
  local cand
  for cand in /usr/local/go/bin/go "$(command -v go 2>/dev/null || true)" \
              "$(as_operator bash -lc 'command -v go' 2>/dev/null || true)"; do
    [[ -n "$cand" && -x "$cand" ]] || continue
    # Run as the operator, not as this run's own EUID: under `curl | sudo
    # bash` that is root, and the account whose PATH and permissions
    # actually decide whether a build works is the one the build itself
    # runs as, a few lines down. Candidate 3 already comes from that
    # account's own login shell; this makes candidates 1 and 2 answer for
    # it too, rather than for a root this run happens to be running as.
    advisor_go_ok "$cand" >/dev/null || continue
    printf '%s' "$cand"
    return 0
  done
  return 1
}

# One line per Go source file the daemon and the executor are built from,
# name and content both, so a rename and an edit are each read as a
# difference. Read as the operator: advisor/bin crossed as root above (the
# Advisor's account owns it), and a checksum that cannot read a file is not
# evidence that the file agrees with anything.
advisor_source_manifest() { # $1 = an advisor/ directory
  local f
  as_operator find "$1" -type f \( -name '*.go' -o -name 'go.mod' -o -name 'go.sum' \) 2>/dev/null \
    | sort \
    | while read -r f; do
        printf '%s %s\n' "$(as_operator sha256sum "$f" 2>/dev/null | cut -d' ' -f1)" "${f#"$1"/}"
      done
}

advisor_sources_changed() { # $1 = previous tree root, $2 = new tree root
  ! diff -q <(advisor_source_manifest "$1/advisor") <(advisor_source_manifest "$2/advisor") >/dev/null 2>&1
}

# Ask an Advisor binary something, as the operator and from /. Go's version
# is asked the same way (advisor_go_ok above, #1203). advisor/bin is
# the operator's directory (the Advisor's account owns what it writes there),
# so the program in it is one the login can replace, and the page update runs
# this whole bootstrap as root (#1201, ADR 0024: root never runs what the login
# can change). The stat tests that come before an ask are not an ask: they run
# nothing. From /, the way install-advisord.sh probes Go (#1162): sudo keeps
# the caller's directory, and a root shell in /root hands the login one it
# cannot search.
advisor_ask() { # $1 = a binary under advisor/bin, or a Go to probe; rest = its arguments; prints what it said
  ( cd / && as_operator "$@" ) 2>/dev/null
}

# Empty and unequal both read as stale: see the block comment above for why
# this is the opposite reading from prepare-host.sh's own stamp_stale().
advisor_stamp_stale() { # $1 = binary, $2 = the commit this run is stamping
  local have
  [[ -x "$1" ]] || return 0
  have="$(advisor_ask "$1" -version || true)"
  [[ -n "$have" && "$have" == "$2" ]] && return 1
  return 0
}

# The binaries an Advisor build produces, built to scratch names in
# advisor/bin, then renamed into place (#787). knowledge-lint is the third
# (#1131): the knowledge push that Promote runs lints the corpus with it, and
# a host that never built it answers every Promote with the missing-linter
# refusal until something builds it. One list for the build, the rename and
# the clean-up, so the three cannot drift.
ADVISOR_BINARIES=(aperire-advisord aperire-executor knowledge-lint)

# The scratch names start with a dot and are removed on any failure, so
# nothing that lists advisor/bin meets a half-written build, and no binary is
# swapped unless all of them built: a rebuild that fails leaves the previous
# release's set exactly as it was, which is what the warning then says. Built
# and renamed as the operator, the account the rebuild has always run as;
# advisor/bin is the operator's directory.
advisor_build_and_swap() { # $1 = Go's directory, $2 = commit, $3 = the one binary to build (default: all)
  local name ok=1 sfx=".new.$$" only="${3:-}"
  for name in "${ADVISOR_BINARIES[@]}"; do
    [[ -z "$only" || "$name" == "$only" ]] || continue
    as_operator env PATH="${1}:${PATH}" GOFLAGS=-trimpath CGO_ENABLED=0 bash -c \
      "cd '$DIR/advisor' && go build -ldflags '-s -w -X main.version=${2}' -o 'bin/.${name}${sfx}' ./cmd/${name}" \
      || { ok=0; break; }
  done
  if [[ $ok -eq 1 ]]; then
    for name in "${ADVISOR_BINARIES[@]}"; do
      [[ -z "$only" || "$name" == "$only" ]] || continue
      as_operator mv -fT "$DIR/advisor/bin/.${name}${sfx}" "$DIR/advisor/bin/${name}" || { ok=0; break; }
    done
  fi
  for name in "${ADVISOR_BINARIES[@]}"; do
    [[ -z "$only" || "$name" == "$only" ]] || continue
    as_operator rm -f "$DIR/advisor/bin/.${name}${sfx}" 2>/dev/null || true
  done
  [[ $ok -eq 1 ]]
}

# Asked, not assumed: the word "stamped" is printed only for a binary that
# answers with the commit it was built for. -X main.version is silently
# ignored by `go build` for a package without that symbol, which is how the
# executor once shipped unstamped (#695). The daemon and the linter answer
# -version, the executor answers the subcommand version. Run as the operator,
# the account that built them. Prints the names that did not answer it.
advisor_unstamped() { # $1 = the commit, rest = the binaries to ask
  local commit="$1" name got
  shift
  for name in "$@"; do
    case "$name" in
      aperire-executor) got="$(advisor_ask "$DIR/advisor/bin/$name" version || true)" ;;
      *)                got="$(advisor_ask "$DIR/advisor/bin/$name" -version || true)" ;;
    esac
    [[ "$got" == "$commit" ]] || printf '%s\n' "$name"
  done
}

rebuild_advisor_if_installed() {
  local bin="$DIR/advisor/bin/aperire-advisord"
  local unit_present=0
  installed_units | awk '{print $1}' | grep -qx 'aperire-advisord.service' && unit_present=1
  if [[ $unit_present -eq 0 && ! -x "$bin" ]]; then
    return 0   # the Advisor is not on this host, so there is nothing to rebuild
  fi

  local commit
  commit="$(installed_commit)"
  [[ "$commit" =~ ^[0-9a-f]{7,40}$ ]] || commit=dev

  local stale=0
  if [[ -n "$KEPT_PREVIOUS" && -d "$KEPT_PREVIOUS/advisor" ]]; then
    advisor_sources_changed "$KEPT_PREVIOUS" "$DIR" && stale=1
  fi
  # A git checkout updated in place (fetch_clone's git-fetch-and-checkout
  # branch) never renames the old tree aside, so there is no previous tree
  # above to diff against ($KEPT_PREVIOUS stays empty) and this is always
  # reached: the stamp is then the only signal an unchanged checkout has
  # left, in place of a source diff it cannot run.
  if [[ $stale -eq 0 ]]; then
    advisor_stamp_stale "$bin" "$commit" && stale=1
  fi
  # The corpus linter is part of the build (#1131), and a host that was
  # installed or updated before it joined the build has the daemon current and
  # no linter. Judging the daemon alone said "carried, not rebuilt" for ever.
  # When that is all that is missing, only the linter is built: the daemon and
  # the executor are current, and rebuilding them swaps in binaries that are no
  # different for a host that then has no reason to restart them.
  local lint_only=0
  if [[ ! -x "$DIR/advisor/bin/knowledge-lint" ]]; then
    [[ $stale -eq 1 ]] || lint_only=1
    stale=1
  fi
  if [[ $stale -eq 0 ]]; then
    ok "advisor/bin/aperire-advisord is unchanged and already stamped $commit; carried, not rebuilt"
    return 0
  fi

  local go_bin
  if ! go_bin="$(advisor_go_bin)"; then
    if [[ $lint_only -eq 1 ]]; then
      warn "advisor/bin/knowledge-lint is missing, and this host has no Go toolchain anywhere this looks to build it."
      info "Promote on the dashboard cannot lint a note until it is built. The Advisor itself is current."
    else
      warn "the Advisor changed in this release and this host has no Go toolchain anywhere this looks."
      info "advisor/bin/aperire-advisord is still the previous release's build, carried across."
    fi
    # Not the Advisor's own installer: it honors a carried binary as a
    # prebuilt one, meant for a fleet operator copying advisor/bin/* between
    # boxes of the same platform, and re-registers this exact stale build
    # rather than rebuilding it. Putting Go where prepare-host.sh already
    # knows how, then running the update again, is what actually clears
    # this: the update's own rebuild above runs as the operator and stamps
    # with the release, which is the one thing this host is short of.
    # --force is not optional in the second command: by the time this line
    # prints, this run has already written its own stamp, so a bare
    # --update would find the host already on this release and touch
    # nothing.
    info "put Go on this host, then run the update again; it will find it and rebuild,"
    info "stamped with this release, as you:"
    dim "  curl -fsSL https://get.aperire.one | bash -s -- --dir $DIR --run prepare-host --with-advisor"
    dim "  curl -fsSL ${APERIRE_GET_SELF_URL:-$DEFAULT_SELF_URL} | bash -s -- --update --force"
    ADVISOR_CARRIED_REASON="no Go toolchain found on this host"
    ADVISOR_CARRIED_KEY="no-go"
    if [[ $lint_only -eq 1 ]]; then
      ADVISOR_CARRIED_REASON="no corpus linter, and no Go toolchain to build it"
      ADVISOR_CARRIED_KEY="no-linter"
    fi
    return 0
  fi

  # Never stopped, on any path (#787). Each binary is built to a scratch name
  # beside it in advisor/bin and renamed over the old one. rename(2) swaps
  # the directory entry; a running Advisor keeps the inode it was started
  # from, so it carries on, on the old build, until whatever restarts it
  # next. The stop that used to come first left an unattended run
  # (--yes --no-restart, the dashboard's own Update button) with no Advisor at
  # all, while its closing text said it was still running.
  local built=1 unstamped
  if [[ $lint_only -eq 1 ]]; then
    info "building advisor/bin/knowledge-lint as $OP_USER; the Advisor itself is current and is not rebuilt"
    advisor_build_and_swap "$(dirname "$go_bin")" "$commit" knowledge-lint || built=0
  else
    info "rebuilding advisor/bin/aperire-advisord, advisor/bin/aperire-executor and advisor/bin/knowledge-lint as $OP_USER"
    advisor_build_and_swap "$(dirname "$go_bin")" "$commit" || built=0
  fi

  if [[ $built -eq 1 ]]; then
    if [[ $lint_only -eq 1 ]]; then
      unstamped="$(advisor_unstamped "$commit" knowledge-lint)"
    else
      unstamped="$(advisor_unstamped "$commit" "${ADVISOR_BINARIES[@]}")"
    fi
    if [[ -n "$unstamped" ]]; then
      warn "built, but ${unstamped//$'\n'/, } did not answer $commit when asked, so that build is not stamped with this release."
      info "Running the update again does not change that: the program's own package does not record the"
      info "commit it was built from. It is a defect in the build, and worth reporting."
    elif [[ $lint_only -eq 1 ]]; then
      ok "advisor/bin/knowledge-lint built, stamped $commit; the Advisor itself is unchanged"
    else
      ok "advisor/bin/aperire-advisord, advisor/bin/aperire-executor, advisor/bin/knowledge-lint rebuilt, stamped $commit"
    fi
  else
    warn "the Advisor rebuild failed; advisor/bin/aperire-advisord is still the previous release's build."
    info "the build's own error is in the output just above. Once it is fixed, run the update"
    info "again to retry the rebuild:"
    dim "  curl -fsSL ${APERIRE_GET_SELF_URL:-$DEFAULT_SELF_URL} | bash -s -- --update --force"
    ADVISOR_CARRIED_REASON="the rebuild failed"
    ADVISOR_CARRIED_KEY="build-failed"
  fi
  # Nothing here stopped it, so a running Advisor is still running, on the
  # previous build. offer_the_restart, further down, names it and restarts
  # it if this run is allowed to.
  return 0
}

# ---- delivering the reachable start limit and its recovery hook (#541) --
#
# 17f fixed a unit that crash-loops forever on an unopenable model credential
# (RestartSec * (Burst - 1) < StartLimitIntervalSec, so the limit is actually
# reachable) and gave that failure a recovery hook,
# OnFailure=aperire-advisord-credcheck.service. Neither half reached an
# existing host through --update: this function never ran before rebuild_advisor
# rebuilt the binary and nothing rewrote the unit, and refresh_root_programs
# below only refreshes a root program that is ALREADY at its destination,
# which credcheck never was on a host installed before 17f.
#
# So this does two things, and only when this host has the Advisor's unit at
# all:
#
#   1. installs or refreshes the credcheck program and its own recovery unit
#      (write_advisord_credcheck_unit, the one place that does either, so this
#      cannot drift from what install-advisord.sh itself would write)
#   2. rewrites ONLY the three [Unit] lines this project owns in
#      aperire-advisord's own unit -- StartLimitIntervalSec=,
#      StartLimitBurst=, and an OnFailure= naming the recovery unit --
#      leaving everything else byte for byte: User=, Group=,
#      SupplementaryGroups=, ExecStart= with every flag it carries
#      (--container, --dash-read-url, --state, --wrapper, --sudo-wrapper),
#      and any LoadCredential* line. An update's own promise is that it
#      changes the account and the deployment for nobody, and a hand edit to
#      any other line survives next to these three untouched.
#
# Does nothing on a host with no Advisor unit at all: neither the program nor
# the unit is installed where nothing would ever reference either.
refresh_advisord_recovery() {
  local advisord_unit="aperire-advisord"
  local unit_dir="${APERIRE_GET_UNIT_DIR:-/etc/systemd/system}"
  local unit="${unit_dir}/${advisord_unit}.service"
  local credcheck_unit="aperire-advisord-credcheck"

  run_root test -f "$unit" || return 0

  step "the Advisor's failure-recovery path (#541)"

  if [[ ! -r "$DIR/scripts/advisord-credcheck-lib.sh" ]]; then
    warn "scripts/advisord-credcheck-lib.sh is missing from the new release; the recovery path was not refreshed"
    return 0
  fi
  # advisord-credcheck-lib.sh reads where the program goes from
  # APERIRE_CREDCHECK_SBIN at the moment it is SOURCED (CREDCHECK_SBIN is a
  # plain top-level assignment in that file, not re-read per call), so this
  # has to be set before the `.` below, not merely before calling the
  # function. SBIN_DIR is the same directory the four programs above already
  # refresh into: one override, not a second one this program alone answers to.
  # Unset again right after the read that needs it: exported, this would
  # otherwise persist through everything the rest of run_update still calls
  # (write_release_stamp, offer_the_restart, verify_and_report) and every
  # child process any of them spawn, an override with no reason to outlive
  # this one function.
  #
  # As root the library ignores that variable (#1148) and uses its constant,
  # /usr/local/sbin, which is SBIN_DIR on any real host; the export matters for
  # a run as the login, and for the suites, which are the login.
  #
  # Sourced from the checked copy, never the tree's: this function runs in
  # this script's own shell, which is root under `curl | sudo bash`. The
  # copies it makes go through rd_install, which this script already defines,
  # so the library never reaches for a second one out of the tree.
  local credlib srcrc=0
  release_held_dir
  credlib="$(stage_for_root scripts/advisord-credcheck-lib.sh)" || srcrc=$?
  if [[ $srcrc -ne 0 || -z "$credlib" ]]; then
    refused_root_copy "$srcrc" "the recovery path (from scripts/advisord-credcheck-lib.sh)"
    if [[ $srcrc -eq 6 ]]; then
      warn "the recovery path was not refreshed: the account check could not run (above), so its library was not judged."
    else
      warn "the recovery path was not refreshed: its library in the tree is not the file this release shipped, or a service account can change it."
    fi
    return 0
  fi
  export APERIRE_CREDCHECK_SBIN="${SBIN_DIR}/${credcheck_unit}"
  # shellcheck source=/dev/null
  . "$credlib"
  unset APERIRE_CREDCHECK_SBIN
  if write_advisord_credcheck_unit "$DIR" "$unit_dir" "$credcheck_unit" ""; then srcrc=0; else srcrc=$?; fi
  if [[ $srcrc -ne 0 ]]; then
    refused_root_copy "$srcrc" "the recovery program or one of its helpers (see above)"
    warn "the recovery path was not refreshed, and the Advisor's unit was left as it was."
    return 0
  fi

  local onfailure_line="OnFailure=${credcheck_unit}.service"

  # What systemd actually loaded, never the file on disk: a drop-in with its
  # own [Unit] section overrides both, and reading the FILE back said "needed
  # no change" on a unit an operator's own override was still winning
  # underneath (P1-091 follow-up, 2026-09-20). StartLimitIntervalSec has no
  # `systemctl show` property of its own -- it answers back as
  # StartLimitIntervalUSec, rendered "30s" rather than the bare integer this
  # unit is written with (measured against systemd 255.4-1ubuntu8.17,
  # 2026-09-20) -- so that is what this compares.
  advisord_recovery_effective_ok() {
    local burst interval onfail
    burst="$(systemctl show "$advisord_unit" -p StartLimitBurst --value 2>/dev/null)"
    interval="$(systemctl show "$advisord_unit" -p StartLimitIntervalUSec --value 2>/dev/null)"
    onfail="$(systemctl show "$advisord_unit" -p OnFailure --value 2>/dev/null)"
    [[ "$burst" == "5" && "$interval" == "30s" ]] || return 1
    case " $onfail " in *" ${credcheck_unit}.service "*) return 0 ;; *) return 1 ;; esac
  }

  # Which drop-in, if any, is the reason the effective value still disagrees
  # after the unit body has been rewritten -- named rather than left to a
  # generic "something overrides this", since the file that is winning is
  # exactly what an operator needs to go and look at.
  advisord_recovery_overriding_dropin() {
    local dropin_dir="${unit}.d" f last=""
    run_root test -d "$dropin_dir" || { printf ''; return 0; }
    while IFS= read -r f; do
      if run_root grep -qE '^(StartLimitBurst=|StartLimitIntervalSec=|OnFailure=)' "$f" 2>/dev/null; then
        last="$f"
      fi
    done < <(run_root find "$dropin_dir" -maxdepth 1 -type f -name '*.conf' 2>/dev/null | sort)
    printf '%s' "$last"
  }

  if advisord_recovery_effective_ok; then
    ok "$unit already carries the reachable start limit and the recovery hook"
    unset -f advisord_recovery_effective_ok advisord_recovery_overriding_dropin
    return 0
  fi

  local before after
  before="$(mktemp)"; after="$(mktemp)"
  if ! run_root cat "$unit" > "$before"; then
    warn "could not read $unit; the reachable start limit was not applied"
    rm -f "$before" "$after"
    unset -f advisord_recovery_effective_ok advisord_recovery_overriding_dropin
    return 0
  fi

  local have_onfailure=0
  grep -qxF -e "$onfailure_line" "$before" && have_onfailure=1

  if grep -qx '\[Unit\]' "$before"; then
    # Inserted once, right after [Unit], never touching any other line.
    # Order inside [Unit] carries no meaning to systemd, so this is a safe
    # place for all three regardless of what else is already there. Any
    # OnFailure= line already present, ours or an operator's own naming
    # something else, passes through untouched -- OnFailure= is a
    # dependency-type setting and accumulates across multiple lines rather
    # than being overwritten by a second one, so nothing here needs to
    # choose between two.
    awk -v onf="$onfailure_line" -v have_onf="$have_onfailure" '
      BEGIN { in_unit = 0; inserted = 0 }
      /^\[Unit\]/ { print; in_unit = 1; next }
      /^\[/ {
        if (in_unit && !inserted) {
          print "StartLimitIntervalSec=30"
          print "StartLimitBurst=5"
          if (have_onf == 0) print onf
          inserted = 1
        }
        in_unit = 0
        print
        next
      }
      /^StartLimitIntervalSec=/ { next }
      /^StartLimitBurst=/ { next }
      { print }
      END {
        if (in_unit && !inserted) {
          print "StartLimitIntervalSec=30"
          print "StartLimitBurst=5"
          if (have_onf == 0) print onf
        }
      }
    ' "$before" > "$after"
  else
    # No [Unit] section at all: the awk pass above has nothing to attach to,
    # so a unit written before this project ever had one left this byte for
    # byte alone while the run went on to claim "needed no change" -- three
    # lines the fix exists to add, silently never added.
    {
      printf '[Unit]\n'
      printf 'StartLimitIntervalSec=30\n'
      printf 'StartLimitBurst=5\n'
      [[ $have_onfailure -eq 0 ]] && printf '%s\n' "$onfailure_line"
      cat "$before"
    } > "$after"
  fi
  rm -f "$before"

  if run_root cmp -s "$after" "$unit"; then
    rm -f "$after"
  else
    local staged="${unit}.new-$$"
    if run_root install -o root -g root -m 0644 "$after" "$staged" \
       && run_root mv -f "$staged" "$unit"; then
      dim "  $unit: rewritten with the reachable start limit (30s / 5) and the recovery hook"
      dim "  User=, Group=, SupplementaryGroups=, ExecStart= and any LoadCredential* line are unchanged"
      run_root systemctl daemon-reload
    else
      run_root rm -f "$staged" 2>/dev/null || true
      warn "$unit could not be updated with the reachable start limit; the previous unit is unchanged"
      rm -f "$after"
      unset -f advisord_recovery_effective_ok advisord_recovery_overriding_dropin
      return 0
    fi
    rm -f "$after"
  fi

  # The claim is about what systemd loaded after that reload, not about the
  # bytes just written -- an operator's own drop-in with a [Unit] section of
  # its own wins over anything the unit body says, and that has to be named
  # rather than papered over with a success line.
  if advisord_recovery_effective_ok; then
    ok "$unit: reachable start limit (30s / 5) and the recovery hook are in place"
    dim "  applies at the unit's next start; nothing was restarted"
  else
    local winner
    winner="$(advisord_recovery_overriding_dropin)"
    if [[ -n "$winner" ]]; then
      warn "$unit was rewritten, but $winner still overrides the start limit or the recovery hook; the effective values on this host are unchanged"
    else
      warn "$unit was rewritten, but systemd still reports the previous start limit or hook on this host; something here overrides it"
    fi
  fi
  unset -f advisord_recovery_effective_ok advisord_recovery_overriding_dropin
}

# ---- the Advisor's writable grants, the same set a fresh install has (#699)
#
# An Advisor installed before #682 has no /var/lib/aperire on its unit's
# ReadWritePaths=, and its first official-image upgrade stops at the verify
# step on "Read-only file system": the wrapper writes the verified-image
# marker there as root, but inside this unit's namespace. Both installers
# name the path now, and neither is something an update may run (#641:
# install.sh goes without --with-advisor on purpose).
#
# So the one narrow program does it, the same one an operator or the fleet
# deploy runs by hand: scripts/advisord-unit-grants.sh. Its header carries
# the whole argument. In short, it adds a constant from the release this run
# verified, to the unit refresh_advisord_recovery above already edits, and
# refuses to name a directory root does not own outright. It restarts
# nothing, and the unit is in the restart list offer_the_restart reads when
# it was running.
#
# Gated on the unit being here, like the recovery path: a host with no
# Advisor gets no directory and no write.
WRAPPER_STATE_DIR="${APERIRE_GET_WRAPPER_STATE:-/var/lib/aperire}"
refresh_advisord_grants() {
  local unit_dir="${APERIRE_GET_UNIT_DIR:-/etc/systemd/system}"
  local prog="$DIR/scripts/advisord-unit-grants.sh"
  run_root test -f "$unit_dir/aperire-advisord.service" || return 0
  step "the Advisor's writable paths, the same set a fresh install has (#699)"
  if [[ ! -f "$prog" ]]; then
    warn "scripts/advisord-unit-grants.sh is missing from the new release; the Advisor's grants were not checked"
    return 0
  fi
  # Root runs the checked copies, never the tree's (ADR 0024): the program
  # and the library it loads from beside itself, staged together.
  local rc=0 staged srcrc=0
  release_held_dir
  staged="$(stage_program_for_root unit-grants scripts/advisord-unit-grants.sh scripts/advisord-unit-grants-lib.sh)" || srcrc=$?
  if [[ $srcrc -ne 0 || -z "$staged" ]]; then
    refused_root_copy "$srcrc" "the Advisor's unit grants (from scripts/advisord-unit-grants.sh and its library)"
    if [[ $srcrc -eq 6 ]]; then
      warn "the Advisor's grants were not checked: the account check could not run (above), so the program and its library were not judged."
    else
      warn "the Advisor's grants were not checked: the program or its library in the tree is not the release's, or a service account can change it."
    fi
    return 0
  fi
  # The wrapper's configuration too (#767): the node's own directories are
  # read from it, and it is this run's own override, the one
  # refresh_image_recipe reads, not a second one.
  run_root env APERIRE_UNIT_DIR="$unit_dir" APERIRE_WRAPPER_STATE_DIR="$WRAPPER_STATE_DIR" \
    APERIRE_NODE_WRAPPER_CONF="$NODE_WRAPPER_CONF" bash "$staged/advisord-unit-grants.sh" || rc=$?
  case $rc in
    0) ;;
    4) warn "the Advisor's unit names every grant, but systemd does not load one of them; the line above says which file wins" ;;
    *) warn "the Advisor's unit was left as it was, so an official-image upgrade may stop at its verify step."
       dim "the reason is above. Once it is fixed, the update runs this step again from a checked copy:"
       dim "  curl -fsSL ${APERIRE_GET_SELF_URL:-$DEFAULT_SELF_URL} | bash -s -- --update --force" ;;
  esac
  return 0
}

fetch_tarball() {
  local tmp staging root parent got kept=0
  local -a entries

  if [[ -e "$DIR" ]]; then
    if looks_like_a_checkout "$DIR"; then
      kept=1
    else
      die "$DIR already exists, and the release unpacks into a new directory. Move it, or pass --dir <somewhere else>."
    fi
  fi

  guard_checksum
  # A published release is checked against its signature before a byte of it
  # is fetched. A file:// archive is the developer's own bytes, the one
  # source that goes without a checksum above, and it goes without this too.
  case "$SOURCE_URL" in
    file://*) warn "a local file is not a published release, so no signature is checked." ;;
    *)        fetch_signed_release ;;
  esac

  parent="$(dirname "$DIR")"
  as_operator mkdir -p "$parent" \
    || die "cannot create $parent as $OP_USER, which is who the release has to belong to."

  # Made as the operator, in the operator's name, and registered for removal
  # before either is written to: a run that dies between here and the rename
  # leaves nothing behind but the directory it started with.
  tmp="$(as_operator mktemp -t aperire-release.XXXXXXXX.tar.gz)" \
    || die "cannot make a temporary file as $OP_USER."
  CLEANUP_PATHS+=("$tmp")
  staging="$(as_operator mktemp -d -p "$parent" .aperire-release.XXXXXXXX)" \
    || die "cannot unpack beside $DIR as $OP_USER. Is $parent writable by them?"
  CLEANUP_PATHS+=("$staging")

  info "fetching $SOURCE_URL"
  as_operator curl -fsSL --max-time 900 -o "$tmp" "$SOURCE_URL" \
    || die "could not fetch the release from $SOURCE_URL"

  if [[ $CHECK_ONLY -eq 1 ]]; then
    # A check installs nothing and runs nothing as root, so it neither asks
    # for sudo nor records anything: the operator's own copy is checked and
    # unpacked, the way every run did before root held one.
    if [[ -n "$EXPECTED_SHA256" ]]; then
      got="$(sha256sum "$tmp" | cut -d' ' -f1)"
      [[ "$got" == "$EXPECTED_SHA256" ]] \
        || die "the archive that arrived is not the one this script names, so nothing was unpacked.

  from      $SOURCE_URL
  expected  $EXPECTED_SHA256
  arrived   $got"
      ok "sha256 $got, which is the archive this script names"
    fi
    as_operator tar -xzf "$tmp" -C "$staging" \
      || die "the archive fetched from $SOURCE_URL did not unpack. Nothing was moved into $DIR."
  else
    # Root takes its own copy of what arrived, in one read, and everything
    # after this comes from that copy: the checksum, the digests, and the
    # tree the operator unpacks. The file curl wrote is the operator's, and
    # a copy checked there and unpacked from there a moment later could be
    # two different files.
    local held
    release_held_dir
    held="$RELEASE_HELD"
    # shellcheck disable=SC2016  # the root shell's own positional parameters
    run_root bash -c 'umask 077; cat -- "$1" > "$2"' rd-hold "$tmp" "$held/release.tar.gz" \
      || die "root could not take a copy of the archive that arrived, so nothing was unpacked."
    release_manifest_verified "$held/release.tar.gz" "$held/release.sha256"
    run_root cat -- "$held/release.tar.gz" | as_operator tar -xzf - -C "$staging" \
      || die "the archive fetched from $SOURCE_URL did not unpack. Nothing was moved into $DIR."
  fi

  # One directory, and the tree is inside it. Asserted rather than assumed:
  # an archive that unpacks its contents into the current directory would
  # otherwise scatter a release across $parent.
  mapfile -t entries < <(find "$staging" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort)
  if [[ "${#entries[@]}" -ne 1 || ! -d "$staging/${entries[0]}" ]]; then
    die "the release archive should hold exactly one directory and it holds ${#entries[@]} entries (${entries[*]:-none}), so it is not an Aperire One release."
  fi
  root="$staging/${entries[0]}"

  # Every file the signed manifest names, with the sum it names, and nothing
  # else. The archive's own sum already covers this; checking it here too is
  # what makes the manifest trustworthy for the root copies that read it
  # later (ADR 0024), long after this archive is gone.
  if [[ -n "$SIGNED_DIR" && -s "$SIGNED_DIR/release.files" ]]; then
    local why
    if ! why="$(release_tree_check "$SIGNED_DIR/release.files" "$root" 2>&1)"; then
      die "the unpacked release is not the tree its signed manifest names, so nothing was moved into $DIR.

  $why"
    fi
    ok "every file matches the signed manifest"
  fi

  # What root will RUN out of this release, staged and checked against the
  # record it has just written from the archive, before anything moves
  # (#764): a refusal here leaves the host as it was.
  if [[ $CHECK_ONLY -eq 0 ]]; then
    STAGED_BEFORE_SWAP=1
    STAGE_TREE_SAID="the release unpacked beside $DIR"
    stage_release_for_root "$root" "$RELEASE_HELD/release.sha256" || refuse_unstaged_release
  fi

  # The one step that is not reversible, and it is a rename on one
  # filesystem because the unpack happened beside its destination.
  if [[ $kept -eq 1 ]]; then
    swap_kept_checkout "$root"
  else
    as_operator mv "$root" "$DIR" \
      || die "could not move the unpacked release into $DIR."
  fi
  rm -rf "$staging" "$tmp"
  # The record lands with the tree it describes, and not before: a run that
  # died above left the previous tree in place, and the previous record with it.
  [[ $CHECK_ONLY -eq 1 ]] || persist_release_digests "$RELEASE_HELD/release.sha256"
}

# No checksum is allowed for a local file and for nothing else. Written as
# a list of what may pass rather than a list of what may not: "refuse it
# when it is https" would wave http:// straight through.
guard_checksum() {
  [[ -z "$EXPECTED_SHA256" ]] || return 0
  case "$SOURCE_URL" in
    file://*)
      warn "no checksum for a local file, so nothing is checked against anything. That is allowed here and nowhere else."
      return 0 ;;
  esac
  die "this copy of the script names an archive but no checksum for it, so there is nothing to check what arrives against.

  source  $SOURCE_URL

  A published bootstrap carries the checksum of the archive beside it,
  written in when that release was built. A copy taken out of a release
  tree carries none, because no archive can hold the checksum of itself.

  So either run the copy the endpoint serves, or name the checksum here:

      bash get-aperire.sh --sha256 <64 hex characters>

  A file:// source is the one that may go without."
}

# ---- the release signature -------------------------------------------
#
# The functions between the two "shared" lines are a byte-for-byte copy
# of the ones in scripts/release-verify-lib.sh: this script arrives on a host
# alone, before there is a tree to source anything from.
# scripts/test-release-verify.sh fails when the two copies differ.
#
# The principal and the namespace are fixed here, never read from anywhere.
RELEASE_SIGNER_PRINCIPAL='aperire-release-key'
RELEASE_SIG_NAMESPACE='aperire-release'

# ---- shared: the inline copy in get-aperire.sh must match these ----

# Is this a signer set this code will hand to ssh-keygen? Prints the number
# of keys on stdout. Refuses, with the line number, on anything that is not
# exactly the one shape above, and on a file that names no key at all.
release_signers_check() { # $1 = allowed_signers file
  local file="$1" line trimmed principal opts type key rest n=0 ln=0 seen=""
  if [[ ! -f "$file" || ! -r "$file" ]]; then
    printf 'there is no readable release signer set at %s\n' "$file" >&2
    return 1
  fi
  while IFS= read -r line || [[ -n "$line" ]]; do
    ln=$((ln + 1))
    trimmed="${line#"${line%%[![:space:]]*}"}"
    [[ -z "$trimmed" || "$trimmed" == \#* ]] && continue
    if [[ "$trimmed" != "$line" ]]; then
      printf 'line %s of %s starts with whitespace, and a signer line may not\n' "$ln" "$file" >&2
      return 1
    fi
    principal="" opts="" type="" key="" rest=""
    read -r principal opts type key rest <<<"$line"
    if [[ "$principal" != "$RELEASE_SIGNER_PRINCIPAL" ]]; then
      printf 'line %s of %s names the signer %s, and the only one accepted is %s\n' \
        "$ln" "$file" "${principal:-nothing}" "$RELEASE_SIGNER_PRINCIPAL" >&2
      return 1
    fi
    if [[ "$opts" != "namespaces=\"$RELEASE_SIG_NAMESPACE\"" ]]; then
      printf 'line %s of %s carries the options %s, and the only one accepted is namespaces="%s"\n' \
        "$ln" "$file" "${opts:-none}" "$RELEASE_SIG_NAMESPACE" >&2
      return 1
    fi
    if [[ "$type" != ssh-ed25519 ]]; then
      printf 'line %s of %s names the key type %s, and a release is signed with ssh-ed25519 only\n' \
        "$ln" "$file" "${type:-nothing}" >&2
      return 1
    fi
    if [[ ! "$key" =~ ^[A-Za-z0-9+/]{40,}={0,2}$ ]]; then
      printf 'line %s of %s does not carry a key after its type\n' "$ln" "$file" >&2
      return 1
    fi
    if [[ -n "$rest" && ! "$rest" =~ ^[A-Za-z0-9._@:+\ -]+$ ]]; then
      printf 'line %s of %s ends in a comment with characters a signer line does not need\n' "$ln" "$file" >&2
      return 1
    fi
    case " $seen " in
      *" $key "*)
        printf 'line %s of %s names a key an earlier line already names\n' "$ln" "$file" >&2
        return 1 ;;
    esac
    seen+=" $key"
    n=$((n + 1))
  done < "$file"
  if [[ $n -eq 0 ]]; then
    printf 'the release signer set at %s names no key, so no release can be checked against it\n' "$file" >&2
    return 1
  fi
  if [[ $n -gt 2 ]]; then
    printf 'the release signer set at %s names %s keys. It holds one, and two only while the key is rotated\n' "$file" "$n" >&2
    return 1
  fi
  printf '%s\n' "$n"
  return 0
}

# Did a key in the signer set sign this file? Exit status only: 0 when
# ssh-keygen says so, 1 otherwise with the reason on stderr. The message is
# fed on stdin from the file itself, never from a pipe, and nothing it prints
# on success is read.
#
# Call it as a statement (`if ! release_verify ...`), never inside $( ): a
# refusal in a command substitution under set -e is swallowed.
release_verify() { # $1 = the signed file, $2 = its .sig, $3 = allowed_signers
  local msg="$1" sig="$2" signers="$3" out
  release_signers_check "$signers" >/dev/null || return 1
  if ! command -v ssh-keygen >/dev/null 2>&1; then
    printf 'this host has no ssh-keygen, so a release signature cannot be checked. It is in the openssh-client package: sudo apt-get install openssh-client\n' >&2
    return 1
  fi
  if [[ ! -f "$msg" ]]; then
    printf 'there is no %s to check\n' "$msg" >&2
    return 1
  fi
  if [[ ! -s "$sig" ]]; then
    printf 'there is no signature for %s, and an unsigned release is not installed\n' "$(basename "$msg")" >&2
    return 1
  fi
  if out="$(ssh-keygen -Y verify -f "$signers" -I "$RELEASE_SIGNER_PRINCIPAL" \
              -n "$RELEASE_SIG_NAMESPACE" -s "$sig" < "$msg" 2>&1)"; then
    return 0
  fi
  # Old enough not to know -Y at all is a different sentence from a bad
  # signature, and an operator needs to know which one they are looking at.
  if grep -qiE 'illegal option|unknown option|invalid option' <<<"$out"; then
    printf 'this host'"'"'s ssh-keygen is too old to check a release signature (it needs OpenSSH 8.2 or newer)\n' >&2
    return 1
  fi
  printf 'the signature on %s does not verify against the release key: %s\n' \
    "$(basename "$msg")" "$(tr '\n' ' ' <<<"$out" | sed 's/[[:space:]]*$//')" >&2
  return 1
}

# One flat string field out of a release.json, in the exact shape the
# publisher writes it ("  \"key\": \"value\"" on its own line). Prints it
# only when exactly one line carries that key, so a file with a second
# "sha256" somewhere cannot be read two ways.
release_json_field() { # $1 = release.json, $2 = key
  local hits
  hits="$(grep -cE "^  \"$2\": \"[^\"]*\",?\$" "$1" 2>/dev/null || true)"
  [[ "$hits" == "1" ]] || return 1
  sed -n "s/^  \"$2\": \"\([^\"]*\)\",\{0,1\}\$/\1/p" "$1"
  return 0
}

# The per-file manifest, held against a tree. Exactly the files it names,
# each with the sum it names, and no file it does not name. Used on a fresh
# unpack, before anything in the tree has run.
release_tree_check() { # $1 = release.files, $2 = the tree root
  local files="$1" root="$2" named present bad
  [[ -s "$files" && -d "$root" ]] || { printf 'no manifest or no tree to check\n' >&2; return 1; }
  # Regular files and directories only, checked first: sha256sum follows a
  # symlink, so a link named like a manifest file would pass on the bytes of
  # whatever it points at, and root would later copy through it.
  bad="$(cd "$root" && find . ! -type f ! -type d -print -quit)"
  if [[ -n "$bad" ]]; then
    printf 'the tree holds %s, which is not a regular file or a directory, and a release holds nothing else\n' "${bad#./}" >&2
    return 1
  fi
  if ! bad="$(cd "$root" && sha256sum --check --strict --quiet "$files" 2>&1)"; then
    printf 'the tree does not match the signed manifest: %s\n' "$(head -3 <<<"$bad" | tr '\n' ' ')" >&2
    return 1
  fi
  named="$(grep -c . "$files")"
  present="$(cd "$root" && find . -type f | wc -l)"
  if [[ "$named" != "$present" ]]; then
    printf 'the tree holds %s files and the signed manifest names %s\n' "$present" "$named" >&2
    return 1
  fi
  return 0
}

# Every key a signer file names, as "<type> <base64>", one per line, read the
# way ssh-keygen reads an allowed_signers line: principals first, then an
# options field only when the next field is not already a key type. So a
# three-field line (no options) is counted here exactly as ssh-keygen would
# count it, and nothing that ssh-keygen accepts as a key is missed by the
# digest or the rotation rule.
release_signers_keys() { # $1 = allowed_signers file
  awk '/^[[:space:]]*(#|$)/ { next }
       { if ($2 ~ /^(ssh-|ecdsa-|sk-)/) print $2 " " $3; else if (NF >= 4) print $3 " " $4; else print "unparsed " NR }' "$1"
}

# The signer set, reduced to what decides trust: one "<key type> <base64>"
# line per key, sorted bytewise, hashed. Comments, order and the principal
# column (which release_signers_check pins) do not change it. release.json
# carries this as signers_sha256; the Mac computes the same value from its
# own .pub files (fields 1 and 2 there, 3 and 4 here) and will not sign a
# release whose value differs from its own.
release_signers_digest() { # $1 = allowed_signers file
  release_signers_keys "$1" | LC_ALL=C sort | sha256sum | cut -d' ' -f1
}

# The keys of a signer set as OpenSSH prints them (`ssh-keygen -l`): one
# "SHA256:<base64>" per key, in file order. This is the value Settings &
# Updates shows and the guide prints, so an operator compares like with like.
release_key_fingerprints() { # $1 = allowed_signers file
  release_signers_keys "$1" | while IFS= read -r k; do
    printf '%s\n' "$k" | ssh-keygen -lf - 2>/dev/null | awk '{ print $2 }'
  done
}

# May a host that trusts the set in $1 move to the set in $2? Only to the
# same set, or by one of the two rotation phases: a single key gains exactly
# one more (phase 1), or a pair drops to one of its own two (phase 2). Says
# why not on stderr. Both files have passed release_signers_check.
release_signers_transition_ok() { # $1 = the set this host trusts, $2 = the set on offer
  local old new no nn
  old="$(release_signers_keys "$1" | LC_ALL=C sort)"
  new="$(release_signers_keys "$2" | LC_ALL=C sort)"
  [[ "$old" == "$new" ]] && return 0
  no="$(grep -c . <<<"$old")"; nn="$(grep -c . <<<"$new")"
  if [[ "$no" == 1 && "$nn" == 2 ]] && grep -qxF -- "$old" <<<"$new"; then
    return 0
  fi
  if [[ "$no" == 2 && "$nn" == 1 ]] && grep -qxF -- "$new" <<<"$old"; then
    return 0
  fi
  printf 'the release key set on offer is not this host'"'"'s set or one rotation step from it (one key gains a second, or a pair drops to one of its two)\n' >&2
  return 1
}

# ---- end of shared ----

# The one package the check needs, installed the way git is above when it is
# missing: from the distribution's own signed archive. It is in every
# supported Ubuntu's server and cloud images already, so this is for a
# container or a stripped-down box.
ensure_ssh_keygen() {
  command -v ssh-keygen >/dev/null 2>&1 && return 0
  info "ssh-keygen is not on this host yet, installing openssh-client to check the release signature"
  run_root env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l apt-get update -qq
  run_root env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l \
    apt-get install -y -qq --no-install-recommends openssh-client
  command -v ssh-keygen >/dev/null 2>&1 \
    || die "ssh-keygen still is not here after apt-get install openssh-client, so the release signature cannot be checked and nothing was fetched."
}

# What the signature vouched for, once it has. A directory ROOT made before
# anything was verified, so nothing but root can change a file in it between
# the check and the reads after it: the unpack check, the refresh of the
# release key, and keep_signed_release, which renames it into the store.
# Only a --check run, which hands nothing to root, checks in a directory of
# its own.
SIGNED_DIR=""

# Make the directory the signed files are checked in. Downloads land in the
# operator's own temporary directory first (the fetch runs as them), and are
# copied from there into this one; nothing is read from the download again.
signed_dir_make() {
  if [[ ${CHECK_ONLY:-0} -eq 1 ]]; then
    SIGNED_DIR="$(as_operator mktemp -d -t aperire-signed.XXXXXXXX)" \
      || die "cannot make a temporary directory as $OP_USER to check the release signature in."
    CLEANUP_PATHS+=("$SIGNED_DIR")
    return 0
  fi
  { run_root mkdir -p "$RELEASE_STORE" && run_root chmod 0755 "$RELEASE_STORE"; } \
    || die "cannot make $RELEASE_STORE, where the signed release is checked and kept."
  SIGNED_DIR="$(run_root mktemp -d "$RELEASE_STORE/.incoming.XXXXXXXX")" \
    || die "cannot make a directory under $RELEASE_STORE to check the release signature in."
  ROOT_CLEANUP="$SIGNED_DIR"
  run_root chmod 0755 "$SIGNED_DIR" \
    || die "cannot set the mode of $SIGNED_DIR."
}
# Fetch one signed file straight into SIGNED_DIR. On a real run root fetches
# it itself, into the directory root just made: no file the operator's
# account can touch (a symlink to a root file, a FIFO, /dev/zero) is ever
# opened by root on the way in. Capped, because nothing honest in this set
# is anywhere near it, and a file over the cap is refused and removed rather
# than read. A --check run hands nothing to root, so it fetches as the
# operator into the operator's own directory.
SIGNED_MAX_BYTES=8388608
signed_fetch() { # $1 = url, $2 = its name in SIGNED_DIR
  local dest="$SIGNED_DIR/$2" size
  if [[ ${CHECK_ONLY:-0} -eq 1 ]]; then
    as_operator curl -fsSL --max-time 60 --max-filesize "$SIGNED_MAX_BYTES" -o "$dest" "$1" || return 1
    size="$(stat -c %s -- "$dest" 2>/dev/null)" || return 1
  else
    run_root curl -fsSL --max-time 60 --max-filesize "$SIGNED_MAX_BYTES" -o "$dest" "$1" || { run_root rm -f -- "$dest"; return 1; }
    size="$(run_root stat -c %s -- "$dest" 2>/dev/null)" || return 1
    run_root chmod 0644 "$dest" || return 1
  fi
  if [[ ! "$size" =~ ^[0-9]+$ ]] || (( size > SIGNED_MAX_BYTES )); then
    if [[ ${CHECK_ONLY:-0} -eq 1 ]]; then rm -f -- "$dest"; else run_root rm -f -- "$dest"; fi
    return 1
  fi
  return 0
}

# The signer set this host already trusts, when it has one: an install or an
# update before this one put it there, root-owned. Empty on a fresh box.
installed_signers() {
  local f="$RELEASE_LIB_DIR/release-signers" why
  run_root test -e "$f" 2>/dev/null || run_root test -L "$f" 2>/dev/null || return 0
  # Present and not a signer set this code accepts is NOT "no set": reading
  # it as none would skip every check that needs the installed set, and a
  # broken file must never be how those checks are switched off.
  if run_root test -L "$f" || ! why="$(release_signers_check "$f" 2>&1 >/dev/null)"; then
    die "this host's release key at $f is there but is not a release key set this script accepts, so nothing was fetched.

  ${why:-it is a symlink}

  A host in this state has to be put right by hand: uninstall it, keeping
  your data, and install again with the one-liner."
  fi
  printf '%s' "$f"
  return 0
}

# The signed release.json for exactly the archive this script names, its
# signature, and the per-file manifest it names, fetched from beside the
# archive under the names that never change, and checked before the archive
# itself is fetched. Every refusal leaves nothing behind but a message.
#
# Why the immutable names and not release.json: two files cannot be renamed
# into place at once, and the origin lets a cache keep a file for five
# minutes. A fresh release.json beside a stale signature would read as a bad
# signature, which is the one message an operator must never learn to shrug
# at. release-<sha256>.json is written once and never changes.
fetch_signed_release() {
  local base json sig files signers named files_want files_got at want_signers installed
  base="${SOURCE_URL%/*}"

  if [[ -z "$RELEASE_SIGNERS" ]]; then
    die "this copy of the script carries no release key, so it has nothing to check a signature against and installs no published release.

  A copy taken out of the repository or out of a release tree is like this;
  the one the endpoint serves carries the key. Run that one, or check a
  release by hand first: docs/RELEASE-SIGNING.md."
  fi
  ensure_ssh_keygen

  # Checked where only root can write, and fetched there by root itself:
  # nothing in this set passes through a directory the operator's account
  # owns (L2 of #759's review).
  signed_dir_make
  info "fetching the signature for release ${EXPECTED_SHA256:0:12}"
  signed_fetch "$base/release-${EXPECTED_SHA256}.json" release.json \
    || die "$base serves no signed release.json for the archive this script names, so nothing was fetched. An unsigned release is not installed.

  wanted  $base/release-${EXPECTED_SHA256}.json"
  signed_fetch "$base/release-${EXPECTED_SHA256}.json.sig" release.json.sig \
    || die "$base serves no signature for release ${EXPECTED_SHA256:0:12}, so nothing was fetched. An unsigned release is not installed."
  signed_fetch "$base/release-${EXPECTED_SHA256}.files" release.files \
    || die "$base serves no per-file manifest for release ${EXPECTED_SHA256:0:12}, so nothing was fetched."
  json="$SIGNED_DIR/release.json"
  sig="$SIGNED_DIR/release.json.sig"
  files="$SIGNED_DIR/release.files"
  signers="$SIGNED_DIR/release-signers"
  if [[ ${CHECK_ONLY:-0} -eq 1 ]]; then
    printf '%s\n' "$RELEASE_SIGNERS" | as_operator tee "$signers" >/dev/null
  else
    printf '%s\n' "$RELEASE_SIGNERS" | run_root tee "$signers" >/dev/null
  fi || die "cannot write the release key to $signers."

  local why
  if ! why="$(release_verify "$json" "$sig" "$signers" 2>&1)"; then
    die "the release at $base is not signed by the release key, so nothing was fetched.

  $why

  If this happened once, run it again. If it says the same thing twice, do
  not install from that address, and check the release by hand first:
  docs/RELEASE-SIGNING.md."
  fi

  # A host that already trusts a key set believes a release only when a key
  # in THAT set signed it. A new set arrives signed by the old one, or not at
  # all: the key built into this script is not enough to change who this
  # host trusts.
  installed="$(installed_signers)" || exit 1
  if [[ -n "$installed" ]] && ! why="$(release_verify "$json" "$sig" "$installed" 2>&1)"; then
    die "this release is not signed by a key this host already trusts ($installed), so nothing was fetched.

  $why

  A release that changes the release key has to be signed by the key it
  replaces. A host that trusts a lab key refuses every public release, by
  design: reinstall it with the one-liner after uninstalling."
  fi

  # Verified first, then read, from the same root-owned file.
  named="$(release_json_field "$json" sha256)" || named=""
  if [[ "$named" != "$EXPECTED_SHA256" ]]; then
    die "the signed release.json names the archive ${named:-nothing}, and this script names $EXPECTED_SHA256. Nothing was fetched."
  fi
  at="$(release_json_field "$json" published_at)" || at=""
  [[ "$at" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] \
    || die "the signed release.json states no publish date, so it cannot be told apart from an older release. Nothing was fetched."
  # The key set this release makes hosts trust is part of what was signed,
  # and the one built into this script has to be it.
  want_signers="$(release_json_field "$json" signers_sha256)" || want_signers=""
  [[ "$want_signers" =~ ^[0-9a-f]{64}$ ]] \
    || die "the signed release.json names no release key set, so it cannot say which keys hosts should trust. Nothing was fetched."
  [[ "$(release_signers_digest "$signers")" == "$want_signers" ]] \
    || die "the release key built into this script is not the key set the signed release names. Nothing was fetched."
  # And a host that already trusts a set moves only by the two rotation
  # phases: one key gains a second (signed by the old), or a pair drops to
  # one of its own two. A release that would swap the whole set at once is
  # refused, whoever signed it.
  if [[ -n "$installed" ]] && ! why="$(release_signers_transition_ok "$installed" "$signers" 2>&1)"; then
    die "this release would change the release key this host trusts by more than one rotation step, so nothing was fetched.

  $why

  trusted now  $(release_key_fingerprints "$installed" | tr '\n' ' ')
  on offer     $(release_key_fingerprints "$signers" | tr '\n' ' ')"
  fi
  refuse_an_older_release "$json" "$at"

  files_want="$(release_json_field "$json" files_sha256)" || files_want=""
  [[ "$files_want" =~ ^[0-9a-f]{64}$ ]] \
    || die "the signed release.json names no per-file manifest, so the tree it describes could not be checked. Nothing was fetched."
  files_got="$(sha256sum "$files" | cut -d' ' -f1)"
  [[ "$files_got" == "$files_want" ]] \
    || die "the per-file manifest $base serves is not the one the signed release names, so nothing was fetched."
  ok "signed by the release key: ${named:0:12}, $(grep -c . "$files") files named"
  dim "release key $(release_key_fingerprints "${installed:-$signers}" | tr '\n' ' ')"
}

# An update never moves a host to a release published BEFORE the one it is
# on. A replayed older release is still a validly signed one, so the date is
# the only thing that tells them apart, and the date it is compared with is
# read from this host's own kept copy (root-owned, read in place), believed
# only when a key this host trusts signed it.
refuse_an_older_release() {
  [[ ${UPDATE:-0} -eq 1 ]] || return 0
  local cur dir new_at="$2" old_at="" trust hw
  cur="$(run_root cat "$RELEASE_STORE/current" 2>/dev/null || true)"
  [[ "$cur" != "$EXPECTED_SHA256" ]] || return 0
  trust="$(installed_signers)" || exit 1; [[ -n "$trust" ]] || trust="$SIGNED_DIR/release-signers"
  if [[ "$cur" =~ ^[0-9a-f]{64}$ ]]; then
    dir="$RELEASE_STORE/$cur"
    if release_verify "$dir/release.json" "$dir/release.json.sig" "$trust" 2>/dev/null; then
      old_at="$(release_json_field "$dir/release.json" published_at)" || old_at=""
    fi
  fi
  [[ "$old_at" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] || old_at=""
  # And the high-water mark: the newest publish date this host has installed,
  # root-owned, kept apart from the store so that a kept release that went
  # missing does not switch this check off.
  hw="$(high_water_at)"
  if [[ -z "$old_at" || ( -n "$hw" && "$hw" > "$old_at" ) ]]; then old_at="$hw"; fi
  [[ -n "$old_at" ]] || return 0
  if [[ ! "$new_at" > "$old_at" ]]; then
    die "the release on offer was published $new_at, no later than the newest this host has installed ($old_at). An update never goes backwards, so nothing was fetched.

  A replayed older release looks exactly like this. To go back on purpose,
  the kept previous tree is the way: see the rollback steps in the guide."
  fi
}

# The newest publish date this host has ever installed, or nothing. Believed
# only from a regular, root-owned file nobody else can write.
high_water_at() {
  local f="$RELEASE_STORE/high-water" meta want_uid at
  run_root test -f "$f" 2>/dev/null && ! run_root test -L "$f" 2>/dev/null || return 0
  want_uid=0; [[ $EUID -eq 0 ]] || want_uid="$(run_root id -u 2>/dev/null || echo 0)"
  meta="$(run_root stat -c '%u:%a' -- "$f" 2>/dev/null)" || return 0
  [[ "${meta%%:*}" == "$want_uid" ]] && (( (8#${meta#*:} & 8#022) == 0 )) || return 0
  at="$(run_root head -c 64 "$f" 2>/dev/null | head -1)"
  [[ "$at" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] && printf '%s' "$at"
  return 0
}

# The signed files, kept root-owned, once the release they describe is in
# place: the directory they were checked in is renamed into the store, so
# what is kept is exactly what was verified. One directory per archive, so a
# rollback to the previous tree still finds the set that describes it, and
# `current` naming the one this host is on now. release-signers beside them
# is the set this script checked them with.
keep_signed_release() {
  [[ -n "$SIGNED_DIR" && -n "$ROOT_CLEANUP" ]] || return 0
  local dest="$RELEASE_STORE/$EXPECTED_SHA256"
  if run_root test -e "$dest"; then
    run_root rm -rf "$dest" \
      || { warn "could not replace the kept copy at $dest; the next update checks the key all the same."; return 0; }
  fi
  if ! run_root mv "$SIGNED_DIR" "$dest"; then
    warn "could not keep the signed release under $RELEASE_STORE; the next update checks the key all the same."
    return 0
  fi
  SIGNED_DIR="$dest"
  ROOT_CLEANUP=""
  if ! printf '%s\n' "$EXPECTED_SHA256" | run_root tee "$RELEASE_STORE/current.new" >/dev/null \
     || ! run_root mv -f "$RELEASE_STORE/current.new" "$RELEASE_STORE/current"; then
    warn "could not record which signed release this host is on."
    return 0
  fi
  # The high-water mark only ever moves forward. Written as a new root file
  # renamed into place, so a symlink planted at the name is replaced, never
  # written through.
  local at hw
  at="$(release_json_field "$SIGNED_DIR/release.json" published_at 2>/dev/null)" || at=""
  hw="$(high_water_at)"
  if [[ "$at" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] && [[ -z "$hw" || "$at" > "$hw" ]]; then
    if ! printf '%s\n' "$at" | run_root tee "$RELEASE_STORE/high-water.new" >/dev/null \
       || ! run_root chmod 0644 "$RELEASE_STORE/high-water.new" \
       || ! run_root mv -fT "$RELEASE_STORE/high-water.new" "$RELEASE_STORE/high-water"; then
      warn "could not record the newest release date this host has installed."
    fi
  fi
  dim "the signed release is kept under $dest"
}

fetch_clone() {
  # A git checkout is updated in place, which is what it is for: the fetch and
  # the checkout below leave data/, dashboard/config/ and advisor/state/ where
  # they are, because git does not touch what it does not track.
  #
  # A kept checkout with no .git in it is a release tree, and there is nothing
  # to fetch INTO. It gets the same treatment the archive path gives it: clone
  # beside it, swap, carry across.
  if [[ -e "$DIR" && ! -d "$DIR/.git" ]]; then
    if looks_like_a_checkout "$DIR"; then
      clone_beside_and_swap
      return 0
    fi
    die "$DIR already exists and is not a git checkout. Move it, or pass --dir <somewhere else>."
  fi

  if [[ -d "$DIR/.git" ]]; then
    info "a checkout is already at $DIR, moving it to $SOURCE_REF"
    as_operator git -C "$DIR" fetch --depth 1 origin "$SOURCE_REF"
    as_operator git -C "$DIR" checkout --detach FETCH_HEAD
  elif [[ "$SOURCE_REF" =~ ^[0-9a-f]{7,40}$ ]]; then
    # A commit, which no clone can be pointed at directly.
    as_operator git clone --depth 1 "$SOURCE_URL" "$DIR"
    as_operator git -C "$DIR" fetch --depth 1 origin "$SOURCE_REF"
    as_operator git -C "$DIR" checkout --detach FETCH_HEAD
  else
    as_operator git clone --depth 1 --branch "$SOURCE_REF" "$SOURCE_URL" "$DIR"
  fi

  # A pinned ref leaves a detached HEAD, which is correct (it is pinned) and is
  # also why the operator's next pull in there would fail. Say so now rather
  # than let them meet it later.
  if ! as_operator git -C "$DIR" symbolic-ref -q HEAD >/dev/null 2>&1; then
    info "pinned to ${SOURCE_REF}, so this checkout sits on a detached HEAD."
    info "to follow a branch again later: git -C $DIR checkout main"
  fi
}

# The clone half of the kept path. Into a directory beside $DIR, on the same
# filesystem, so the swap that follows is a rename and not a copy.
clone_beside_and_swap() {
  local parent staging new
  parent="$(dirname "$DIR")"
  staging="$(as_operator mktemp -d -p "$parent" .aperire-release.XXXXXXXX)" \
    || die "cannot clone beside $DIR as $OP_USER. Is $parent writable by them?"
  CLEANUP_PATHS+=("$staging")
  new="$staging/aperire-one"

  if [[ "$SOURCE_REF" =~ ^[0-9a-f]{7,40}$ ]]; then
    as_operator git clone --depth 1 "$SOURCE_URL" "$new"
    as_operator git -C "$new" fetch --depth 1 origin "$SOURCE_REF"
    as_operator git -C "$new" checkout --detach FETCH_HEAD
  else
    as_operator git clone --depth 1 --branch "$SOURCE_REF" "$SOURCE_URL" "$new"
  fi

  # Staged before the swap, as the archive path does (#764). A git source
  # has no record, so this is the path check alone, said once.
  if [[ $CHECK_ONLY -eq 0 ]]; then
    STAGED_BEFORE_SWAP=1
    STAGE_TREE_SAID="the clone beside $DIR"
    stage_release_for_root "$new" || refuse_unstaged_release
  fi
  swap_kept_checkout "$new"
  rm -rf "$staging"
}

# What the release is called afterwards. A clone knows its own commit; an
# archive is one release and the label it was published under is what says
# which, so that is what gets printed rather than a commit nothing here can
# read back.
release_label() {
  if source_is_tarball; then
    printf '%s' "${SOURCE_REF:-an unnamed release}"
  else
    git -C "$DIR" rev-parse --short HEAD 2>/dev/null || printf '%s' 'unknown commit'
  fi
}

# -- What this install is, written down -------------------------------
#
# <install dir>/.release, one JSON object, written at the end of a successful
# install or reinstall and owned by the operator. It is the only place a host
# records which release it is running: dashboard/package.json has not moved
# in any release, and a version nobody bumps is not an identity (ADR 0022).
#
#   tag, commit, sha256, published_at   what the publisher stamped into this
#                                       copy of the script
#   source_url                          where this run actually fetched from
#   installed_at                        when this run finished
#
# Two rules, and they are the same rule twice. A copy with no stamp writes
# empty strings rather than a guess: no tag, no date, and a commit only when
# it can read one back (a clone can, an archive cannot). And a run that was
# pointed somewhere else with --source or --sha256 installed something this
# copy's stamp does not name, so the stamp is not evidence about it and none
# of it is used.
#
# Nothing in here may end the run. It happens after install.sh has finished
# and the services are up, so a stamp that could not be written is a warning
# about a file, never a failed install.
release_stamp_is_ours() {
  [[ -n "${DEFAULT_RELEASE_TAG}${DEFAULT_RELEASE_COMMIT}${DEFAULT_PUBLISHED_AT}" ]] || return 1
  [[ "$SOURCE_URL" == "$DEFAULT_SOURCE_URL" ]] || return 1
  [[ "$EXPECTED_SHA256" == "$DEFAULT_EXPECTED_SHA256" ]] || return 1
  return 0
}

# The commit this host is on, or nothing. A clone knows its own, and it is
# read as the operator because git refuses a repository owned by somebody
# else and root reading it here would come back empty for a reason no line
# would name.
installed_commit() {
  if source_is_tarball; then
    if release_stamp_is_ours; then printf '%s' "$DEFAULT_RELEASE_COMMIT"; fi
  else
    as_operator git -C "$DIR" rev-parse --short HEAD 2>/dev/null || printf ''
  fi
  return 0
}

# Values go through here rather than straight into the object. None of these
# should ever hold a quote or a backslash, and a --ref an operator typed is
# still a value this script did not choose.
json_string() { # $1 = the value
  local v="${1//\\/\\\\}"
  v="${v//\"/\\\"}"
  printf '"%s"' "$v"
}

write_release_stamp() {
  local file="$DIR/.release" tag="" published="" commit="" now=""
  now="$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || true)"
  if release_stamp_is_ours; then
    tag="$DEFAULT_RELEASE_TAG"
    published="$DEFAULT_PUBLISHED_AT"
  fi
  commit="$(installed_commit)"

  if ! printf '{\n  "tag": %s,\n  "commit": %s,\n  "sha256": %s,\n  "published_at": %s,\n  "source_url": %s,\n  "installed_at": %s\n}\n' \
        "$(json_string "$tag")" "$(json_string "$commit")" \
        "$(json_string "$EXPECTED_SHA256")" "$(json_string "$published")" \
        "$(json_string "$SOURCE_URL")" "$(json_string "$now")" \
      | as_operator tee "$file" >/dev/null; then
    warn "could not write $file, so this host cannot say which release it is on."
    dim "everything else about the install is done and unaffected."
    return 0
  fi
  as_operator chmod 0644 "$file" 2>/dev/null || true

  if [[ -n "$tag" || -n "$commit" ]]; then
    ok "this host now says what it is: ${tag:-no tag}${commit:+, commit $commit}"
  else
    ok "this host now has a .release, and it names no release: this copy of"
    info "the script carries no stamp, so there is no tag and no date to state."
  fi
  dim "$file"

  # One file claims identity, not two. A host the fleet update has been on
  # carries a .deploy-ref naming a commit that is no longer installed here,
  # and two files answering the same question is how a page ends up reading
  # the wrong one. The stamp wins: it is the one whatever wrote it still
  # stands behind. Removed only after the stamp landed, never before.
  # Root's fallback is the helper's unlink on a descriptor (#1064).
  if [[ -e "$DIR/.deploy-ref" || -L "$DIR/.deploy-ref" ]]; then
    if as_operator rm -f "$DIR/.deploy-ref" 2>/dev/null || root_remove_in_tree unlink "$DIR/.deploy-ref"; then
      dim "the earlier .deploy-ref is gone: .release is what names this install now"
    fi
  fi
  return 0
}

fetch_release() {
  if source_is_tarball; then
    fetch_tarball
  else
    # A git source has no archive and so no digests. On a host that has, or
    # has ever had, release digests it is refused before anything moves:
    # replacing them with nothing is the one thing that would turn the check
    # off, so it is not something an install does on its way past.
    if [[ $CHECK_ONLY -eq 0 ]] && { run_root test -e "$RD_DIGESTS" || run_root test -e "$RD_REQUIRED"; }; then
      die "this host checks every root copy against its release digests, and a git source has none, so nothing was fetched.

  Install a published release instead (the plain one-line command), or, to
  run unreleased code here on purpose, take the check off by hand first:

      sudo rm $RD_REQUIRED $RD_DIGESTS

  and every root copy after that is made unchecked, and says so."
    fi
    fetch_clone
  fi

  # What arrived has to be the thing, checked before anything is run out of it.
  local f
  # RELEASE-CHECK-LIST. scripts/test-release-snapshot.sh reads the names out of
  # the loop directly under this marker, so a fourth name added here is asserted
  # against the snapshot without editing the gate. It finds the loop by this
  # marker, never by position: other "for f in" loops come earlier in the file.
  for f in install.sh scripts/prepare-host.sh aperire-one; do
    [[ -f "$DIR/$f" ]] \
      || die "$DIR/$f is missing, so what was fetched from $SOURCE_URL is not an Aperire One release."
  done
  ok "release at $DIR ($(release_label))"
}

# -- The checklist, before anything is installed ---------------------
#
# It runs from the release that was just unpacked, and it cannot run before
# that: the checklist lives in the checkout, and this script arrives on the
# host alone. So the order is fetch, check, install, and the plan above says
# so in those words.
#
# The answer the node question can end with travels in a file. install.sh
# reads it and exports APERIRE_RIPPLED_URL, which is what puts RIPPLED_URL
# into /etc/aperire/aperire.env. A file rather than an exported variable
# because preflight is a child process, and a child cannot export into its
# parent.
#
# Run as the account that invoked this, not through sudo. It reads only, and
# the one thing root would buy it (naming the process behind a busy port)
# already has an honest third answer of its own when it cannot be named.
PREFLIGHT_ANSWER=""
# The directory the install will really live in, which is not always the one
# the release was unpacked into: --check unpacks into a temporary directory
# that goes with the run, and measuring the free space on THAT filesystem
# would report /tmp. Empty means they are the same.
PREFLIGHT_DIR=""
run_preflight() {
  # The staged copy when there is one: under `curl | sudo bash` this shell is
  # root, and root runs only what was staged (#764). A --check stages nothing
  # (it asks for no sudo), so it reads the unpack it made itself.
  local pf="${RUN_TREE:-$DIR}/scripts/preflight.sh" rc=0
  local -a args
  if [[ ! -f "$pf" ]]; then
    warn "this release carries no scripts/preflight.sh, so nothing was checked up front."
    dim "the installers' own guards still apply, further in."
    return 0
  fi

  step "checking this host"
  PREFLIGHT_ANSWER="$(mktemp -t aperire-preflight.XXXXXXXX)"
  CLEANUP_PATHS+=("$PREFLIGHT_ANSWER")

  args=( "--role=$(install_role_for "$ROLE")" "--dir=${PREFLIGHT_DIR:-$DIR}" "--answer-file=$PREFLIGHT_ANSWER" )
  [[ $PORT_GIVEN -eq 1 ]]  && args+=( "--port=$PORT" )
  [[ $ASSUME_YES -eq 1 ]]  && args+=( --yes )
  [[ $CHECK_ONLY -eq 1 ]]  && args+=( --check )
  [[ $ROLE_IS_NODELESS_GUESS -eq 1 ]] && args+=( --role-guessed )
  bash "$pf" "${args[@]}" || rc=$?
  PREFLIGHT_RAN=1
  return $rc
}

# What the answer becomes on its way to install.sh. Empty unless the node
# question was answered with a port, which is the only case anything here
# knows better than the dashboard's own loopback default.
preflight_rippled_url() {
  [[ -s "${PREFLIGHT_ANSWER:-}" ]] || return 0
  sed -n 's/^RIPPLED_URL=//p' "$PREFLIGHT_ANSWER" | tail -1
}

# -- Install ---------------------------------------------------------
run_install() {
  local -a args
  # Root runs the staged copy and names the tree it installs (#764). cli-only
  # is the one role install.sh runs as the operator, from the tree itself.
  if [[ "$ROLE" == "cli-only" ]]; then
    args=( "$DIR/install.sh" "--role=$(install_role_for "$ROLE")" --yes )
  else
    [[ -n "$RUN_TREE" ]] || stage_release_for_root || refuse_unstaged_release
    args=( "$RUN_TREE/install.sh" "--role=$(install_role_for "$ROLE")" --yes )
  fi
  [[ $PORT_GIVEN -eq 1 ]] && args+=( "--port=$PORT" )
  # The fleet flags, handed on unchanged. install.sh owns the step, the
  # prompt, the refusals and what the closing text may claim about them.
  #
  # The --yes above is this script's own, and it stops here. install.sh never
  # passes it to the pair command: `--yes` on an installer means "take the
  # plan as printed", and on the pair command it means "I have already
  # compared the aggregator's fingerprint by hand". An installer may not
  # answer that for anybody.
  [[ -n "$FLEET_AGGREGATOR" ]] && args+=( "--fleet-aggregator=$FLEET_AGGREGATOR" )
  [[ -n "$FLEET_LABEL" ]] && args+=( "--fleet-label=$FLEET_LABEL" )
  # Run once, by one owner. install.sh runs the same preflight as its own
  # step zero when it is run by hand, and running it twice here would ask the
  # node question twice and keep only the second answer.
  [[ $PREFLIGHT_RAN -eq 1 ]] && args+=( --no-preflight )

  # An update adds two, and neither is an optimisation.
  #
  # --no-restart, because the swap has just put new code under running
  # processes and restarting them here would be the silent restart the
  # operator ruled out. They are named and asked about afterwards.
  #
  # --no-preflight, because the checklist's node question ends in
  # APERIRE_RIPPLED_URL, which is what puts RIPPLED_URL into
  # /etc/aperire/aperire.env. On a host that has been running for months that
  # value is settled and probably hand-edited, and a probe's answer must not
  # overwrite it. The checks it makes are about a host that has nothing on it
  # yet; this one is already running the thing.
  #
  # --quiet-existing, because install.sh and its sub-installers otherwise print
  # the whole first-install banner at a host that has been running for months:
  # "authn.yaml still names localhost" to a host with enrolled passkeys, "create
  # the first operator" to a host with operators, both firewall advisories and
  # the PATH warning for a shell that ended long ago (#269). It silences
  # guidance, never a read-back.
  if [[ $UPDATE -eq 1 ]]; then
    args+=( --no-restart --no-preflight --quiet-existing )
  fi

  # The node the checklist found, or the port the operator named. Passed as
  # an environment variable rather than a flag because every sub-installer
  # reads it that way, and a value that only arrived through install.sh would
  # be a second way to configure one thing.
  local -a node_env=()
  local url
  url="$(preflight_rippled_url)"
  [[ -n "$url" ]] && node_env=( "APERIRE_RIPPLED_URL=$url" )

  # The commit this install is about to put on disk (#266), read the same way
  # .release's own commit field will be: installed_commit() is the one
  # function this script already trusts for that answer, for a tarball
  # release and for a git checkout alike. prepare-host.sh stamps the relay
  # and advisord binaries with it, so a component's own build ref and the
  # release the host ends up claiming can never disagree about which commit
  # was meant, they are read from the same place. Empty falls back to "dev"
  # on the far side, which is the honest answer for a run this script did
  # not carry a stamp for.
  node_env+=( "APERIRE_BUILD_COMMIT=$(installed_commit)" )
  # Only a role somebody NAMED, or a fresh install's detection, is written into
  # aperire.env as the install role (#808). One inferred from the units is not.
  [[ $ROLE_INFERRED -eq 1 ]] && node_env+=( "APERIRE_RECORD_ROLE=0" )

  # cli-only is the one role install.sh refuses to run as root: it puts two
  # symlinks in one account's ~/.local/bin, and root's is the wrong one.
  if [[ "$ROLE" == "cli-only" ]]; then
    as_operator env ${node_env[@]+"${node_env[@]}"} bash "${args[@]}"
    return
  fi
  node_env+=( "APERIRE_INSTALL_TREE=$DIR" )
  [[ -n "$RD_REFUSED_FILE" ]] && node_env+=( "RD_REFUSED_LOG=$RD_REFUSED_FILE" )
  # 4 is install.sh's own answer for "installed, and root refused to copy
  # one or more files out of the tree" (#764). The run goes on to say what it
  # installed and then ends non-zero with that list, rather than stopping
  # here as if nothing had happened.
  local rc=0
  run_root env "${node_env[@]}" bash "${args[@]}" || rc=$?
  collect_installer_refusals
  if [[ $rc -eq 4 ]]; then
    [[ ${#ROOT_COPY_REFUSED[@]} -gt 0 ]] || ROOT_COPY_REFUSED+=("a copy install.sh made (its own lines above name it)")
    return 0
  fi
  if [[ $rc -ne 0 ]]; then
    # A step install.sh does not carry on past, with a refusal in it: the
    # list is said here, where it is read, before the run ends.
    [[ ${#ROOT_COPY_REFUSED[@]} -eq 0 ]] || report_refused_root_copies
    exit "$rc"
  fi
}

# -- Verify, before anything is claimed ------------------------------

# Where the dashboard on this host listens, read where the server reads it.
#
# The server takes its port from PORT in its environment and nowhere else
# (dashboard/server.ts), and the role does not choose it: a co-located host
# and a dashboard-only host take the same default, 7800, and keep whatever an
# earlier install wrote. That line goes into the unit's EnvironmentFile
# (aperire.env) once and is never overwritten, so a host first installed with
# --port=7900 listens on 7900 for every later run, and a run that carries no
# --port asking 7800 is asking the wrong question (#1175).
#
# Same order install.sh's fleet_dash_port and verify-after-restart.sh use: the
# unit's own Environment=PORT, then the environment file the unit names, then
# aperire.env. The unit is world-readable; the env file is 0640 root:<group>
# and is read through root, because a failed read is otherwise
# indistinguishable from a file with no PORT line in it.
#
# Sets CONFIGURED_PORT, CONFIGURED_PORT_FROM and DASH_UNIT_FOUND (the unit's
# name, for the lines that tell the operator what to read). Not a command
# substitution, so those survive the call. Returns 1, and leaves the three
# empty, when nothing on this host names a port.
CONFIGURED_PORT=""
CONFIGURED_PORT_FROM=""
DASH_UNIT_FOUND=""
configured_dash_port() {
  local unit_dir="${APERIRE_GET_UNIT_DIR:-/etc/systemd/system}" u f p
  local unit_file="" env_file=""
  CONFIGURED_PORT=""; CONFIGURED_PORT_FROM=""; DASH_UNIT_FOUND=""
  for u in aperire-server aperire-read; do
    f="$unit_dir/${u}.service"
    if [[ -f "$f" ]]; then unit_file="$f"; DASH_UNIT_FOUND="$u"; break; fi
  done
  if [[ -n "$unit_file" ]]; then
    p="$(awk -F= '/^Environment=PORT=/{print $3; exit}' "$unit_file" 2>/dev/null | tr -d "\"' " || true)"
    if [[ "$p" =~ ^[0-9]+$ ]]; then
      CONFIGURED_PORT="$p"; CONFIGURED_PORT_FROM="$unit_file"; return 0
    fi
    env_file="$(awk -F= '/^EnvironmentFile=/{sub(/^-/,"",$2); print $2; exit}' "$unit_file" 2>/dev/null || true)"
  fi
  for f in "$env_file" "${ETC_APERIRE}/aperire.env"; do
    [[ -n "$f" ]] || continue
    # `|| true`: under pipefail a failing `cat` (no such file) would take the
    # whole run out on an assignment.
    p="$(run_root cat "$f" 2>/dev/null | sed -n 's/^PORT=//p' | tail -1 | tr -d "\"' " || true)"
    if [[ "$p" =~ ^[0-9]+$ ]]; then
      CONFIGURED_PORT="$p"; CONFIGURED_PORT_FROM="$f"; return 0
    fi
  done
  return 1
}

# Before the closing check: the port it asks is the one this host is
# configured with, whatever this run's PORT started as. On a first install
# the file was just written from --port (or the default), so the two agree
# and this says nothing. On a reinstall the file is older than this run and
# wins, and the run says so.
settle_dash_port() {
  configured_dash_port || return 0
  [[ "$CONFIGURED_PORT" == "$PORT" ]] && return 0
  if [[ $PORT_GIVEN -eq 1 ]]; then
    info "--port ${PORT} was given, but this host's service environment already says PORT=${CONFIGURED_PORT}"
    info "(${CONFIGURED_PORT_FROM}), which is what the dashboard listens on. Asking ${CONFIGURED_PORT}."
  else
    info "this dashboard listens on ${CONFIGURED_PORT}, read from ${CONFIGURED_PORT_FROM}"
  fi
  PORT="$CONFIGURED_PORT"
  return 0
}

# What the closing check heard from the dashboard on its LAST ask: healthz_heard
# clears all three first, so nothing an earlier ask heard outlives it. When the
# dashboard itself answered, HEALTHZ_CODE is its HTTP status (200 or 503) and
# HEALTHZ_BODY what it said. HEALTHZ_STRAY is the status of an answer on that
# port that was not the dashboard's, kept so the failure can say something
# answered and what, instead of "nothing did".
HEALTHZ_CODE="" HEALTHZ_BODY="" HEALTHZ_STRAY=""

# Ask /healthz once. Returns 0 only for an answer the dashboard itself gives.
#
# Not `curl -f` (#1177). The handler answers 503, with a JSON body, until the
# node it reads has closed a ledger in the last 30 seconds (the verdict is in
# dashboard/lib/healthz-verdict.ts), and a node installed minutes ago is still
# catching up. -f turns that into a curl failure, and the check then said "the
# dashboard did not answer" about a dashboard that had, and exited 1 on a
# correct install. So the status is read rather than inferred from curl's exit.
#
# "Answering" is the dashboard's own two answers, not any HTTP status: a 200,
# or a 503 whose body is the handler's ({"ok":false,"role":...}). A 404, a 502
# or a 503 error page is some other program holding the port, or a dashboard
# that is failing, and passing either off as an installed dashboard would trade
# this defect for a worse one.
healthz_heard() {
  local out code body
  HEALTHZ_CODE="" HEALTHZ_BODY="" HEALTHZ_STRAY=""
  out="$(curl -sS --max-time 3 -w $'\n%{http_code}' "http://127.0.0.1:${PORT}/healthz" 2>/dev/null || true)"
  code="${out##*$'\n'}"
  [[ "$code" =~ ^[0-9]{3}$ && "$code" != 000 ]] || return 1
  body="${out%$'\n'*}"
  case "$code" in
    200) ;;
    503) if ! { grep -Eq '"ok"[[:space:]]*:[[:space:]]*false' <<<"$body" && grep -q '"role"' <<<"$body"; }; then
           HEALTHZ_STRAY="$code"; return 1
         fi ;;
    *)   HEALTHZ_STRAY="$code"; return 1 ;;
  esac
  HEALTHZ_CODE="$code"; HEALTHZ_BODY="$body"
  return 0
}

# A 200 ends the wait at once. A 503 does not: a node that is already synced
# answers 503 for the first seconds after the dashboard starts, and ending on
# it would call a host that is a few seconds from ready "not ready". So the
# wait runs its full window, and what the last ask heard decides: a dashboard
# whose last answer is a 503 is up, and one that said 503 and then went quiet,
# or answered something else, is not.
healthz_answers() {
  local i said=0
  for (( i = 1; i <= HEALTH_TRIES; i++ )); do
    if healthz_heard; then
      [[ "$HEALTHZ_CODE" == 200 ]] && return 0
      if [[ $said -eq 0 ]]; then
        said=1
        dim "it answered 503: the dashboard is up and its node is not ready. Waiting out the window in case that is only the first seconds."
      fi
    fi
    sleep "$HEALTH_SLEEP"
  done
  [[ -n "$HEALTHZ_CODE" ]]
}

health_failed() {
  if [[ -n "$HEALTHZ_STRAY" ]]; then
    warn "something answered on http://127.0.0.1:${PORT}/healthz with HTTP ${HEALTHZ_STRAY}, and it was not the dashboard's own /healthz answer."
  else
    warn "the dashboard did not answer on http://127.0.0.1:${PORT}/healthz."
  fi
  cat <<EOF

  This is the check, not the install: everything install.sh did is still in
  place and still enabled. What to read, in this order:

      systemctl status ${DASH_UNIT_FOUND:-aperire-server} --no-pager
      sudo journalctl -u ${DASH_UNIT_FOUND:-aperire-server} -n 50 --no-pager

  Then ask it yourself. -i prints the status line, which is what tells a
  dashboard that is not there from one that is up and not ready:

      curl -sS -i http://127.0.0.1:${PORT}/healthz
EOF
  # A failed health check exits here, before verify_and_report's own trailing
  # call to this. A stale Advisor is no less true for the dashboard also
  # being unreachable right now, and an operator chasing this failure needs
  # that fact and its remedy exactly as much as one reading a clean run.
  mention_previous_tree
  exit 1
}

# Loopback unless the operator bound it somewhere else. Read from the file the
# service itself reads, and read it through root: that file is 0640
# root:<operator>, so a plain read here fails and is then indistinguishable
# from "no HOST line", which is the answer that means loopback. A fallback
# that looks like a reading is the bug class this project keeps meeting.
bound_to_loopback() {
  local env_file="${ETC_APERIRE}/aperire.env" host
  host="$(run_root cat "$env_file" 2>/dev/null | sed -n 's/^HOST=//p' | tail -1 | tr -d "\"' ")"
  [[ -z "$host" || "$host" == "127.0.0.1" || "$host" == "localhost" ]]
}

# What the answer was, in the words of the answer. A 200 is a healthy dashboard.
# A 503 is a dashboard that is up and whose node is not ready. That is the
# normal state of a node started minutes ago and is said as exactly that, not as
# a failure: the install is whole, and the next step does not wait on it. What
# the body does not say, why the node is not ready, is not said either.
healthz_report() {
  if [[ "$HEALTHZ_CODE" == 200 ]]; then
    ok "http://127.0.0.1:${PORT}/healthz answered"
    return 0
  fi
  warn "http://127.0.0.1:${PORT}/healthz answered 503: the dashboard is up, and the node it reads is not ready"
  if grep -Eq '"rippled_connected"[[:space:]]*:[[:space:]]*true' <<<"$HEALTHZ_BODY"; then
    info "It is connected to the node, and no ledger has closed there in the last 30 seconds."
  else
    info "It is not connected to the node."
  fi
  info "A 503 is the dashboard's own answer, not a failed install. /healthz stays 503"
  info "until the node has closed a ledger in the last 30 seconds. That is expected on a"
  info "node started minutes ago, which is still catching up. On a node that has been"
  info "running, it is not. Ask again whenever you like:"
  dim "curl -sS http://127.0.0.1:${PORT}/healthz     # \"ok\":true once the node is current"
  info "If it stays 503 after the node reports synced, read the dashboard's journal:"
  dim "sudo journalctl -u ${DASH_UNIT_FOUND:-aperire-server} -n 50 --no-pager"
}

banner_dashboard() {
  local hostname_now
  hostname_now="$(hostname 2>/dev/null || echo this-host)"
  step "----- Aperire One is installed, and answering -----"
  healthz_report
  cat <<EOF

  The dashboard can be accessed on   ${S_CYAN}http://127.0.0.1:${PORT}${S_OFF}
EOF
  if bound_to_loopback; then
    cat <<EOF
  and on loopback only, so no part of it faces the network. If you want to
  access the dashboard from your local machine, forward the port over SSH
  and open that same address there:

      ${S_CYAN}ssh -L ${PORT}:127.0.0.1:${PORT} ${OP_USER}@${hostname_now}${S_OFF}

EOF
  else
    info "on the address this host was bound to. Keep it off the internet:"
    info "a LAN address or a Cloudflare tunnel, never an open port."
    echo
  fi
  # Everything below this line is true of a FIRST install and of nothing else.
  # An update has operators already, has whatever Advisor this host has, and
  # its relay was wired months ago; saying "the Advisor is not installed" to a
  # host that has been running one all along is a false sentence, and a banner
  # is not exempt from this script's own rule about claims.
  if [[ $UPDATE -eq 1 ]]; then
    info "This host moved from ${UPDATE_TAG_FROM:-a release it did not record}"
    info "to ${DEFAULT_RELEASE_TAG:-the release this script names}."
    info "Everything else on this host is as it was: your operators, your"
    info "passkeys, your history, your config, and the Advisor if you run one."
    return 0
  fi
  cat <<EOF
  You can set up your first operator admin from the browser: open the
  address above, and the dashboard walks you through creating the account
  and enrolling its passkey. Or use one command here instead. It creates
  your first operator and prints the single-use enrollment link, and it is
  the same command for everything after that:

      ${S_CYAN}bash $DIR/aperire-one${S_OFF}

EOF
  if [[ "$ROLE" == "co-located" ]]; then
    info "The relay on this host was installed, wired and read back by the"
    info "installer above, enabled, running and pushing or exactly what was"
    info "missing. One owner for that claim, and it is the one that read it."
    echo
  fi
  # An earlier install that had an Advisor is not told the Advisor "is not
  # missing": the comparison below names it, and says how to put it back.
  if [[ $KEPT_ADVISOR -eq 0 ]]; then
    info "The Advisor is not installed, and is not missing: monitoring is whole"
    info "without it. Add it later from that menu, with nothing to reconfigure."
  fi
}

banner_relay() {
  step "----- the relay is installed on this host -----"
  # Read, not assumed. This banner used to say "not started and not enabled",
  # which was true of the installer it was written against and stopped being
  # true when the split path started enabling the unit. Either sentence is a
  # claim about a service, so both go through systemctl.
  local enabled active
  enabled="$(run_root systemctl is-enabled aperire-relay 2>/dev/null || true)"
  active="$(run_root systemctl is-active aperire-relay 2>/dev/null || true)"
  if [[ "$enabled" != "enabled" || "$active" != "active" ]]; then
    warn "the aperire-relay unit is on this host and did not come up."
    dim "systemctl is-enabled  ->  ${enabled:-<no answer>}"
    dim "systemctl is-active   ->  ${active:-<no answer>}"
    dim "read: sudo journalctl -u aperire-relay -n 50 --no-pager"
    exit 1
  fi
  ok "aperire-relay is enabled and running, and standing by"
  # The paragraph below describes a relay that has never been wired, which is
  # what a first install leaves. On an update this host's relay has been
  # pushing to a dashboard for as long as it has been installed, and the run
  # that just finished went out of its way not to touch its config.
  if [[ $UPDATE -eq 1 ]]; then
    info "Its config in ${ETC_APERIRE} was not touched, so it dials the same"
    info "dashboard with the same token it did before this update."
    return 0
  fi
  cat <<EOF

  Standing by is the whole state: /etc/aperire/relay.conf names no dashboard
  yet, because only you know which one collects from this host. So the relay
  dials nothing, pushes nothing, and says exactly that once in its journal.
  It is enabled, so a reboot brings it back the same way.

  Two edits and one command finish it. A restart, not \`enable --now\`: the
  unit is already enabled and already running, so \`--now\` does nothing and
  the process keeps the config it started with.

      ${S_CYAN}sudo nano /etc/aperire/relay.conf${S_OFF}     # dashboard_url, auth_token
      ${S_CYAN}sudo systemctl restart aperire-relay${S_OFF}
      ${S_CYAN}systemctl status aperire-relay${S_OFF}

  auth_token has to match RELAY_TOKENS in /etc/aperire/aperire.env on the
  dashboard host, and that dashboard has to be restarted after you add it,
  or the relay's first push is a 401. The full reference is
  docs/RELAY-REFERENCE.md in $DIR.
EOF
}

banner_cli() {
  step "----- the operator commands are installed -----"
  ok "aperire-auth and aperire-one are in ${OP_HOME}/.local/bin"
  cat <<EOF

  No services were installed on this host, which is what cli-only means.
  Open a new shell if ~/.local/bin was not already on your PATH, then:

      ${S_CYAN}aperire-auth list${S_OFF}

EOF
}

# The one thing this run left behind on purpose, named at the end where an
# operator is reading rather than waiting. Never removed here: a bootstrap
# that deletes the only copy of somebody's previous install is one nobody can
# undo, so the removal is a command they run when they are ready.
mention_previous_tree() {
  # Said once more here, plainly, because the mid-run warn inside
  # rebuild_advisor_if_installed scrolled past a fetch and an install step
  # ago and an operator reading only the end of an update never saw it
  # (#633: aperire4 carried a stale Advisor across three updates on exactly
  # this account). Only on an update: a first install never rebuilds and
  # ADVISOR_CARRIED_REASON stays empty. The remedy named per reason is the
  # one that actually clears it, not a command that merely sounds like the
  # Advisor's own installer: that one honors a carried binary as prebuilt,
  # meant for copying advisor/bin/* between boxes of the same platform, and
  # would re-register this exact stale build rather than rebuild it.
  if [[ $UPDATE -eq 1 && -n "$ADVISOR_CARRIED_REASON" ]]; then
    if [[ "$ADVISOR_CARRIED_KEY" == no-linter ]]; then
      warn "advisor/bin/knowledge-lint is missing, so Promote cannot lint a note (${ADVISOR_CARRIED_REASON})."
    else
      warn "the Advisor is still on its previous build (${ADVISOR_CARRIED_REASON})."
    fi
    case "$ADVISOR_CARRIED_KEY" in
      no-linter)
        info "put Go on this host, then run the update again; it will find it and build the linter:"
        dim "  curl -fsSL https://get.aperire.one | bash -s -- --dir $DIR --run prepare-host --with-advisor"
        dim "  curl -fsSL ${APERIRE_GET_SELF_URL:-$DEFAULT_SELF_URL} | bash -s -- --update --force"
        ;;
      no-go)
        info "put Go on this host, then run the update again; it will find it and rebuild,"
        info "stamped with this release, as you:"
        dim "  curl -fsSL https://get.aperire.one | bash -s -- --dir $DIR --run prepare-host --with-advisor"
        dim "  curl -fsSL ${APERIRE_GET_SELF_URL:-$DEFAULT_SELF_URL} | bash -s -- --update --force"
        ;;
      build-failed)
        info "its own error is in the output above. Once it is fixed, run the update again:"
        dim "  curl -fsSL ${APERIRE_GET_SELF_URL:-$DEFAULT_SELF_URL} | bash -s -- --update --force"
        ;;
    esac
  fi
  if [[ $TRUST_SYNC_PENDING -eq 1 ]]; then
    warn "the trust sync unit was not brought up to date by this update."
    info "An older trust-sync unit logs 'Unknown key name' on every passkey enrollment until it is written again."
    info "Write it again with:"
    dim "  curl -fsSL https://get.aperire.one | bash -s -- --dir $DIR --run trust-sync-grant"
  fi
  if [[ -n "$KEPT_PREVIOUS" ]]; then
    echo
    info "Your earlier checkout is still on this host, untouched:"
    dim "$KEPT_PREVIOUS"
    info "Your database, config and Advisor state moved out of it into the new"
    info "release, so what is left there is the old code. It is the tree a rollback"
    info "returns to. An update keeps the newest ${KEPT_TREES_MAX} such trees, the ones root"
    info "still holds release digests for, and removes older ones; it never removes this"
    info "one. When the dashboard above is working, you can remove it yourself:"
    [[ ${KEPT_TREES_KEPT:-0} -le 1 ]] || info "(${KEPT_TREES_KEPT} kept trees are beside ${DIR} in all; only the first, above, is a rollback target.)"
    echo
    info "    ${S_CYAN}rm -rf ${KEPT_PREVIOUS}${S_OFF}"
    echo
  fi
  # The other half of a rollback by hand, and the reason the snapshot is
  # taken beside the tree rather than inside data/: the tree above holds the
  # old code, this file holds the data as it was before the swap, and the two
  # together are the state this host was in an hour ago.
  [[ -n "$DB_SNAPSHOT" ]] || return 0
  info "The database as it was before this update:"
  dim "$DB_SNAPSHOT"
  info "A copy, not the live one: your database itself moved into the new"
  info "release with everything else. Keep it until you are happy."
  echo
  return 0
}

verify_and_report() {
  case "$ROLE" in
    co-located|dashboard)
      step "checking that it answers"
      settle_dash_port
      info "asking http://127.0.0.1:${PORT}/healthz, up to ${HEALTH_TRIES} times"
      healthz_answers || health_failed
      banner_dashboard
      ;;
    relay|validator)
      if [[ -z "$(systemctl list-unit-files 'aperire-relay*' 2>/dev/null | grep '\.service' || true)" ]]; then
        warn "the aperire-relay unit is not on this host after the install."
        dim "read: sudo journalctl -u aperire-relay -n 50 --no-pager"
        exit 1
      fi
      banner_relay
      ;;
    cli-only)
      [[ -x "${OP_HOME}/.local/bin/aperire-auth" ]] \
        || die "aperire-auth is not in ${OP_HOME}/.local/bin after the install."
      banner_cli
      ;;
  esac
  report_components_against_before
  mention_previous_tree
  report_refused_root_copies
}

# A root copy the release did not vouch for is the one thing this run will
# not paper over with a banner. The previous copy is still in place, the
# host is running, and the run ends non-zero with the list where it is read.
report_refused_root_copies() {
  if ! run_root test -e "$RD_DIGESTS" 2>/dev/null; then
    printf '\n%s!!    this host has no release digests.%s\n' "$E_RED" "$E_OFF" >&2
    cat >&2 <<EOF
        Every program root copied out of $DIR on this run was copied
        unchecked: nothing says it is the file a release shipped. Installing
        a published release records them, and from then on each copy is
        checked and a changed file is refused.
EOF
  fi
  [[ ${#ROOT_COPY_REFUSED[@]} -gt 0 ]] || return 0
  # An entry the account check could not run for carries a tab and the word
  # "accounts" (rd_note_refused, root_place). It was never judged, so it is
  # not told as a file that changed (#1089).
  local r judged=0 unjudged=0 lead
  for r in "${ROOT_COPY_REFUSED[@]}"; do
    if [[ "$r" == *$'\t'accounts ]]; then unjudged=$((unjudged + 1)); else judged=$((judged + 1)); fi
  done
  printf '\n%s!!    root refused to copy %d file(s) out of %s:%s\n' "$E_RED" "${#ROOT_COPY_REFUSED[@]}" "$DIR" "$E_OFF" >&2
  for r in "${ROOT_COPY_REFUSED[@]}"; do
    printf '        %s\n' "${r%%$'\t'*}" >&2
  done
  if [[ $judged -gt 0 ]]; then
    lead="The lines above each refusal say which of two things it was"
    [[ $unjudged -eq 0 ]] || lead="For the $judged that were judged, the lines above each refusal say which of two things it was"
    cat >&2 <<EOF

  Root kept the copy it already had of each one. $lead:

    a file that is not the one this release shipped (both digests are
    named): something changed the tree after the release was unpacked.
    Find out what changed it first.

    a path a service account can change (the account and the directory
    are named): make that directory or file writable by its owner only.

  Then put the release back as it shipped, which fetches it again and
  swaps the tree:

      curl -fsSL ${APERIRE_GET_SELF_URL:-$DEFAULT_SELF_URL} | bash -s -- --update --force

  Installing out of the same tree again refuses the same way.
EOF
  fi
  if [[ $unjudged -gt 0 ]]; then
    lead="The account check could not run: systemd did not answer (the line at each refusal names the call)."
    [[ $judged -eq 0 ]] || lead="The account check could not run for $unjudged of them: systemd did not answer (the line at each of those names the call)."
    cat >&2 <<EOF

  $lead
  Those files were never compared with the release, so nothing here says the
  tree changed. Root kept the copy it already had. Run the update again to
  retry the check:

      curl -fsSL ${APERIRE_GET_SELF_URL:-$DEFAULT_SELF_URL} | bash -s -- --update --force
EOF
  fi
  # This exit comes before the node wrapper's own, so its worst case is
  # said here too rather than lost behind the list.
  if [[ ${NODE_WRAPPER_REFUSED:-0} -eq 1 ]]; then
    printf '\n%s!!    the Advisor'"'"'s old sudo rule still grants a file in the install tree that a service account can write.%s\n' "$E_RED" "$E_OFF" >&2
    printf '        The REFUSED line under the node wrapper above names it. Make that path writable by its owner only, then\n        put the release back as it shipped, which runs the wrapper step again from a checked copy:\n            curl -fsSL %s | bash -s -- --update --force\n' "${APERIRE_GET_SELF_URL:-$DEFAULT_SELF_URL}" >&2
  fi
  if [[ ${NODE_WRAPPER_STRANDED:-0} -eq 1 ]]; then
    printf '\n%s!!    the Advisor reaches the node only through its root socket, and that socket is not working.%s\n' "$E_RED" "$E_OFF" >&2
    printf '        The lines under the node wrapper above say why. Put that right, then run the wrapper step again from a checked copy:\n            curl -fsSL %s | bash -s -- --update --force\n' "${APERIRE_GET_SELF_URL:-$DEFAULT_SELF_URL}" >&2
  fi
  exit 1
}

# -- Updating a host that is already running -------------------------
#
# The one-line install refuses an installed host and opens the operator menu
# instead, which is right: nothing may be installed on top of a running
# service. It left no way to move that host to a newer release, so the
# dashboard's Updates card named a command that told the operator their host
# was already installed and stopped (found live, 2026-09-09).
#
#   curl -fsSL https://get.aperire.one | bash -s -- --update
#
# It is the same swap a reinstall does, and deliberately so: rename the old
# tree aside, move the new one in, carry data/, the operator's config and the
# Advisor's directories across (swap_kept_checkout), prepare and install from
# the new tree. One implementation, proven on two Ubuntu releases, rather than
# a second copy of the ordering that is the whole safety argument (ADR 0022).
#
# What it adds on top of a reinstall, and each one is here because an update
# is not a first install:
#
#   the stamp gate     a host already on this release is told so and nothing
#                      is fetched, so the command is safe to run twice
#   the role           read from this host's own units, never asked. An
#                      operator updating is not choosing what their box is
#   the db snapshot    taken before anything moves, out of the tree, so it is
#                      still findable after the swap renamed the tree it
#                      came from
#   no restart         install.sh is run with --no-restart and the processes
#                      are named and asked about afterwards
UPDATE=0
# The release this host was on when the update started, read from its stamp
# before the new one is written over it.
UPDATE_TAG_FROM=""
UPDATE_FORCE=0
# Whether the restart question is asked at all. --no-restart skips it and
# prints the command instead, which is what an unattended caller wants.
RESTART_ASK=1
# The database snapshot this run took, named in the closing text. Empty when
# there was no database to take one of.
DB_SNAPSHOT=""
# Set by rebuild_advisor_if_installed when a stale Advisor build could not be
# corrected this run (no Go toolchain anywhere it looks, or the rebuild
# itself failed), so the closing summary can say so once more where an
# operator is actually reading, rather than only in the mid-run warn that
# has already scrolled past by the time the run finishes.
ADVISOR_CARRIED_REASON=""
# The same verdict as a key (no-go, no-linter, build-failed), which is what the
# closing summary matches on. The sentence above is for the reader; a check
# that finds a verdict by its wording breaks when someone rewords it (#838).
ADVISOR_CARRIED_KEY=""

# The four fields of this host's stamp, read one at a time. Every value the
# stamp holds is a JSON string on its own line, which is what write_release_stamp
# writes, so no JSON parser is needed on a box that may not have one.
release_field() { # $1 = key
  [[ -f "$DIR/.release" ]] || return 0
  sed -n "s/^  \"$1\": \"\(.*\)\",\?\$/\1/p" "$DIR/.release" | head -1
  return 0
}

update_needs_an_install() {
  cat >&2 <<EOF

${E_RED}error: there is nothing installed on this host to update.${E_OFF}

  --update moves an installed host to a newer release. It reads the role off
  the units that are here, carries this host's database and config into the
  new tree, and asks before it restarts anything. None of that has a meaning
  on a box with no Aperire One unit on it.

  This is the install, and it is the same address:

      ${E_CYAN}curl -fsSL ${APERIRE_GET_SELF_URL:-$DEFAULT_SELF_URL} | bash${E_OFF}

  It works out what this host is, checks it, and installs. To see what it
  would find without installing anything, add ${E_CYAN}--check${E_OFF}.

EOF
  exit 1
}

# The role, read from the host. Never asked, because an operator updating is
# not choosing what their box is, and never guessed either: a set of units
# nothing here recognises stops the run and names --role, the same way
# detection does when it cannot see (role_when_unknown).
#
# Read from the units rather than from /etc/aperire, because a unit is what
# "installed" means here and because /etc/aperire holds no role: it is a
# service environment and a relay config, and both survive an uninstall that
# kept them. The dashboard's unit is `aperire-server` on most hosts and
# `aperire-read` on one of mine, and an instance suffixes both, so the match
# is on the prefix.
update_resolve_role() {
  local units dash=0 relay=0
  units="$(installed_units | awk '{print $1}' | tr '\n' ' ')"
  if [[ -n "$ROLE" ]]; then
    ROLE_EVIDENCE="(you named it; the units here are $units)"
    return 0
  fi
  # An instance host is refused rather than updated. `--instance=NAME` suffixes
  # the unit names, the env file, the config and the database (ADR 0009), and
  # this run passes no --instance to install.sh: it would install a SECOND,
  # unnamed set of units beside the named ones and mint a new relay token in a
  # new /etc/aperire/aperire.env. Guessing is worse than stopping, and the
  # instance is not a thing this run can read off a unit name reliably enough
  # to act on.
  if grep -qE '(^| )aperire-(server|read)-[^ ]+\.service' <<<" $units "; then
    die "this host runs a named instance ($units), and an update cannot name it back: --instance suffixes the units, the config and the database, and this run would install an unnamed set beside them. Update it from its own checkout instead: cd <checkout> && sudo bash install.sh --role=<role> --instance=<name> --no-restart"
  fi
  grep -qE '(^| )aperire-(server|read)\.service' <<<" $units " && dash=1
  grep -qE '(^| )aperire-relay\.service' <<<" $units " && relay=1
  if   [[ $dash -eq 1 && $relay -eq 1 ]]; then ROLE="co-located"
  elif [[ $dash -eq 1 ]];                 then ROLE="dashboard"
  elif [[ $relay -eq 1 ]];                then ROLE="relay"
  else
    die "the units on this host are '$units', and none of them is a dashboard or a relay, so this run cannot tell what to install. Name it: --role=co-located (or dashboard, or relay)."
  fi
  ROLE_EVIDENCE="(read from this host's units: $units)"
  ROLE_INFERRED=1
  return 0
}

# Already on it, and nothing is fetched to find out.
#
# The comparison is between the checksum THIS copy of the script names and the
# one in the stamp the last install wrote. Both are facts about an archive, so
# they answer the question exactly, and the copy an operator just piped from
# the endpoint is the published one for the release the endpoint is serving.
# A copy with no checksum in it (one taken out of a clone) has nothing to
# compare, and says so rather than claiming either answer.
# The port this host's dashboard actually listens on.
#
# Everything after the install reads PORT: the health check, the address in the
# banner. Left at the default, a host installed with --port=7900 would be
# updated correctly and then declared broken, because 7800 answers nothing.
# Read the way bound_to_loopback reads HOST, through root, because that file is
# 0640 root:<operator> and a failed read is otherwise indistinguishable from a
# file with no PORT line in it.
update_read_port() {
  [[ $PORT_GIVEN -eq 0 ]] || return 0
  configured_dash_port || return 0
  [[ "$CONFIGURED_PORT" == "$PORT" ]] && return 0
  PORT="$CONFIGURED_PORT"
  info "this dashboard listens on ${PORT}, read from ${CONFIGURED_PORT_FROM}"
  return 0
}

update_stamp_gate() {
  local have want tag
  want="$EXPECTED_SHA256"
  have="$(release_field sha256)"
  if [[ $UPDATE_FORCE -eq 1 ]]; then
    info "--force: this release is applied again whatever the stamp says."
    return 0
  fi
  if [[ -z "$want" ]]; then
    info "this copy of the script names no checksum, so there is nothing to"
    info "compare this host's stamp against. Applying what it fetches."
    return 0
  fi
  [[ "$want" == "$have" ]] || return 0

  tag="${DEFAULT_RELEASE_TAG:-$(release_field tag)}"
  step "this host is already on ${tag:-this release}."
  info "installed  ${tag:-no tag}${have:+, sha256 $have}"
  info "published  ${tag:-no tag}${want:+, sha256 $want}"
  echo
  info "The same archive, so there is nothing to fetch and nothing to swap."
  info "Nothing on this host was touched."
  echo
  info "To apply it again anyway, which is a reinstall of the same release:"
  dim "  --update --force"
  echo
  exit 0
}

# The database, copied out of the tree before anything moves.
#
# Beside the checkout rather than inside data/, and that is the difference
# from the snapshot fleet-update.sh takes: the swap renames $DIR aside and
# carries data/ into the new tree, so a snapshot inside it travels with the
# database it is a copy of. A rollback by hand needs a file that stayed where
# the operator can find it whatever the swap did, which is what
# `<dir>.db-<stamp>` is.
#
# VACUUM INTO is the copy: one read transaction, one pass, a consistent file,
# and it finishes while the dashboard keeps writing. sqlite3's .backup is
# NOT that on a live database. The shell's .backup copies in steps and starts
# over whenever another connection writes to the source between steps, and
# a dashboard writes metrics every few seconds, so on a database of a
# gigabyte the copy restarted forever: 43 minutes on stock-node1 with the
# file's size never moving and its mtime cycling, while a VACUUM INTO of the
# same database takes seconds. .backup stays as the fallback for a sqlite3
# too old for VACUUM INTO (before 3.27, 2019). Without sqlite3 at all the
# last fallback copies the WAL and the SHM beside the file, because a bare
# copy of the .db with a hot WAL is a torn snapshot that reads as a database
# and is missing the newest writes.
#
# The newest two are kept and the prune says what it removed (#127: snapshots
# filled a disk, 91 files and 56G on one busy day).
snapshot_database() {
  local db="$DIR/data/aperire.db" stamp out who
  step "snapshotting the database, before anything moves"
  # Read as the dashboard's account, never as root: data/ is 0700 for that
  # account on a fresh install (ADR 0024), so the operator cannot even see
  # the file is there, and a root sqlite3 could create a -shm the dashboard
  # then cannot open. On a host installed before ADR 0024 that account is
  # the operator, and this is exactly the route it always took.
  who="$(dash_account)"
  if ! as_dashboard_account test -f "$db" 2>/dev/null; then
    info "there is no $db on this host, so there is nothing to copy."
    return 0
  fi
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  out="${DIR}.db-${stamp}"
  if [[ "$who" == "$OP_USER" ]]; then
    snapshot_as_operator "$db" "$out"
  else
    snapshot_through_data "$db" "$out" "$who" "$stamp"
  fi
  if [[ -z "$DB_SNAPSHOT" ]]; then
    # Never fatal, and never silent. An operator who cannot take a snapshot
    # may still want the update; what they may not have is a run that told
    # them it took one.
    warn "the database could not be copied to ${out}, so this update has no snapshot."
    dim "the swap keeps your data/ either way: it is moved into the new tree, not replaced."
    return 0
  fi
  ok "database snapshot: $DB_SNAPSHOT"
  prune_db_snapshots
  return 0
}

# The operator owns the database and the directory beside the tree.
snapshot_as_operator() { # $1 = db, $2 = out
  local db="$1" out="$2" s ok=1
  if command -v sqlite3 >/dev/null 2>&1; then
    # VACUUM INTO first, .backup only where sqlite3 does not know the verb.
    # A VACUUM INTO that refuses leaves no file behind; a partial .backup
    # would, so it is removed before the next attempt.
    if as_operator sqlite3 "$db" "VACUUM INTO '$out'" 2>/dev/null; then
      DB_SNAPSHOT="$out"; return 0
    fi
    as_operator rm -f "$out" 2>/dev/null || true
    if as_operator sqlite3 "$db" ".backup '$out'" 2>/dev/null; then
      DB_SNAPSHOT="$out"; return 0
    fi
    as_operator rm -f "$out" 2>/dev/null || true
  fi
  # No sqlite3, or it refused. The sidecars come too: without them this is
  # a copy that is missing whatever had not been checkpointed yet.
  as_operator cp -p "$db" "$out" || ok=0
  for s in -wal -shm; do
    [[ -f "${db}${s}" ]] || continue
    as_operator cp -p "${db}${s}" "${out}${s}" || ok=0
  done
  if [[ $ok -eq 1 ]]; then
    DB_SNAPSHOT="$out"
    warn "sqlite3 did not take this copy, so it is a file copy with the WAL and SHM beside it."
  fi
}

# The dashboard has its own account (ADR 0024), which may read the database
# and may write nothing outside data/. sqlite3 writes a journal beside the
# file it fills, so a copy straight into the operator's directory fails even
# into a file made for it (measured: VACUUM INTO and .backup both refuse with
# "attempt to write a readonly database"). So the copy is made inside data/,
# 0600, as that account, and root then renames it out beside the tree. The
# rename never follows a link; what arrives is then checked to be a plain
# file, and anything else that account swapped in is removed, not kept.
snapshot_through_data() { # $1 = db, $2 = out, $3 = account, $4 = stamp
  local db="$1" out="$2" who="$3" tmp="$DIR/data/.update-snapshot-$4.db"
  command -v sqlite3 >/dev/null 2>&1 || return 0
  as_dashboard_account rm -rf "$tmp" 2>/dev/null || true
  # shellcheck disable=SC2016  # $1 and $2 are the inner shell's, on purpose
  if ! as_dashboard_account sh -c 'umask 077 && exec sqlite3 "$1" "$2"' sh "$db" "VACUUM INTO '$tmp'" 2>/dev/null; then
    as_dashboard_account rm -f "$tmp" 2>/dev/null || true
    # shellcheck disable=SC2016  # as above
    as_dashboard_account sh -c 'umask 077 && exec sqlite3 "$1" "$2"' sh "$db" ".backup '$tmp'" 2>/dev/null \
      || { as_dashboard_account rm -f "$tmp" 2>/dev/null || true; return 0; }
  fi
  if ! run_root mv -T "$tmp" "$out"; then
    as_dashboard_account rm -rf "$tmp" 2>/dev/null || true
    warn "the snapshot ${who} made inside data/ could not be moved out beside the tree."
    return 0
  fi
  # What arrived is judged before it is kept. Not a plain file (a link, a
  # directory, anything else the account put at the name): removed, rm -rf
  # follows no link. A plain file is then handed to the operator on its
  # descriptor, which also refuses a file with more than one link (a hard
  # link to the live database would otherwise pass as a copy and stay the
  # account's). After that the snapshot is the operator's, like the tree
  # beside it, and an uninstall that removes the account leaves no file on a
  # freed uid.
  if run_root test -L "$out" || ! run_root test -f "$out"; then
    run_root rm -rf -- "$out" 2>/dev/null || true
    warn "the snapshot ${who} made was not a plain file when it was moved out, so it was removed."
    return 0
  fi
  # Inline and isolated (-I), never a program from the tree: root acts on a
  # descriptor opened O_NOFOLLOW in the operator's own directory, checks it
  # is a regular file with one link, then re-owns and re-modes that same
  # descriptor.
  # shellcheck disable=SC2016  # Python source, not shell
  if ! run_root python3 -I -c '
import os, stat, sys
d, n, uid, gid = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
dfd = os.open(d, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
fd = os.open(n, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dfd)
st = os.fstat(fd)
if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
    sys.exit("not a single-link regular file")
os.fchown(fd, uid, gid)
os.fchmod(fd, 0o600)
' "$(dirname "$out")" "$(basename "$out")" "$(id -u "$OP_USER")" "$(id -g "$OP_USER")"; then
    run_root rm -rf -- "$out" 2>/dev/null || true
    warn "the snapshot ${who} made could not be handed to ${OP_USER} (a second link to it, or it changed), so it was removed."
    return 0
  fi
  DB_SNAPSHOT="$out"
}

prune_db_snapshots() {
  local parent base n=0 f
  parent="$(dirname "$DIR")"
  base="$(basename "$DIR")"
  local -a snaps
  # Newest first: the names carry a UTC stamp in a form that sorts the way it
  # runs, so a reverse sort is chronological with no stat call.
  mapfile -t snaps < <(find "$parent" -maxdepth 1 -name "${base}.db-*" -printf '%f\n' 2>/dev/null \
                       | grep -v -- '-wal$' | grep -v -- '-shm$' | sort -r)
  for f in ${snaps[@]+"${snaps[@]}"}; do
    n=$((n + 1))
    [[ $n -le 2 ]] && continue
    as_operator rm -f "$parent/$f" "$parent/$f-wal" "$parent/$f-shm" 2>/dev/null || true
    dim "removed the older snapshot $parent/$f"
  done
  return 0
}

# What is running right now, captured BEFORE anything moves.
#
# Discovered, never hardcoded. The dashboard's unit is `aperire-server` on
# most hosts and `aperire-read` on one of mine, an instance suffixes both,
# and `aperire-advisord` is only there when the Advisor is. A fixed list of
# three names would offer to restart a unit that is not here and would miss
# one that is.
#
# Captured before the swap because that is when the answer is true: after
# install.sh has run, a unit that was down and got enabled looks the same as
# one that was carrying the operator's traffic a minute ago. These are the
# processes that were serving when the code under them changed.
UPDATE_RUNNING_UNITS=()
capture_running_units() {
  local u
  while read -r u; do
    [[ -n "$u" ]] || continue
    [[ "$(systemctl is-active "$u" 2>/dev/null)" == "active" ]] || continue
    # A timer-driven oneshot that happens to be running at this instant is a
    # job, not a process serving anybody: the verifier and the store-rotation
    # window are both Type=oneshot, and offering to restart one would be
    # offering to run it again. Asked of systemd rather than matched against
    # a list of names, so a oneshot added later is excluded by being one.
    [[ "$(systemctl show -p Type --value "$u" 2>/dev/null)" == "oneshot" ]] && continue
    UPDATE_RUNNING_UNITS+=("$u")
  done < <(installed_units | awk '{print $1}')
  return 0
}

# The one question this whole path exists to ask.
#
# The swap has landed and install.sh was run with --no-restart, so every
# process named here is running code from the release that was on this host
# when the run started. That is a real state and it has a real consequence
# the operator meets immediately: dashboard/public/ is served from the tree,
# so a browser reload gets the new frontend against the old server, and rows
# the old server never sends read as em dashes.
#
# Three ways it is answered, and none of them is a silent restart:
#   --no-restart   print the command and stop
#   --yes          yes
#   a terminal     the question, defaulting to yes
# No terminal and no --yes is the fourth, and it prints the command rather
# than taking a default: an unattended run that restarted the dashboard
# because nobody was there to say otherwise is exactly the restart the
# operator ruled out.
offer_the_restart() {
  local cmd reply u
  step "what is still running the old code"
  # Installed, enabled, and not running now or when this run started (#803).
  # An Advisor that was already down before the update was never in the list
  # below, so nothing named it, and the run ended on a banner the operator
  # read as "everything is up". Read here, one unit at a time, the way the
  # running list is: a unit file that is enabled, not a template, and not a
  # oneshot (a job, not a service), whose own is-active answer is not active.
  local -a idle=()
  local name state
  while read -r name state _; do
    [[ "$name" == *.service && "$name" != *@.service && "$state" == enabled ]] || continue
    [[ " ${UPDATE_RUNNING_UNITS[*]} " == *" $name "* ]] && continue
    [[ "$(systemctl is-active "$name" 2>/dev/null)" == "active" ]] && continue
    [[ "$(systemctl show -p Type --value "$name" 2>/dev/null)" == "oneshot" ]] && continue
    idle+=("$name")
  done < <(installed_units)
  if [[ ${#UPDATE_RUNNING_UNITS[@]} -eq 0 ]]; then
    info "nothing of Aperire One was running when this started, so there is"
    info "nothing to restart."
    _offer_the_start "${idle[@]}"
    return 0
  fi
  # Read again, one at a time, before a word is said about them (#787). The
  # list was true when the run started; "still running the old code" is a
  # claim about now, and a unit that went down since then is not running
  # anything. It is named as down, with the command that brings it back,
  # and never started here: this run does not know why it stopped.
  local -a still=() down=()
  for u in "${UPDATE_RUNNING_UNITS[@]}"; do
    if [[ "$(systemctl is-active "$u" 2>/dev/null)" == "active" ]]; then
      still+=("$u")
    else
      down+=("$u")
    fi
  done
  if [[ ${#down[@]} -gt 0 ]]; then
    warn "These were running when this update started and are NOT running now:"
    for u in "${down[@]}"; do warn "  $u ($(systemctl is-active "$u" 2>/dev/null || true))"; done
    info "Read why, then start them:"
    for u in "${down[@]}"; do dim "sudo journalctl -u $u -n 50 --no-pager"; done
    dim "sudo systemctl start ${down[*]}"
    echo
  fi
  if [[ ${#still[@]} -eq 0 ]]; then
    info "Nothing of Aperire One is running the old code now, so there is nothing to restart."
    _offer_the_start "${idle[@]}"
    return 0
  fi
  info "The new code is on disk. These processes are still running, on the old code:"
  echo
  for u in "${still[@]}"; do info "  $u"; done
  echo
  info "The dashboard is served out of the tree, so a browser reload already"
  info "gets the new page against the old server. Restarting settles it."
  info "None of this touches the node: it is a different service, and it was"
  info "not stopped, restarted or reconfigured by any of the above."
  echo
  cmd="sudo systemctl restart ${still[*]}"

  if [[ $RESTART_ASK -eq 0 ]]; then
    info "--no-restart, so nothing here restarted anything. When you are ready:"
    dim "$cmd"
    _offer_the_start "${idle[@]}"
    return 0
  fi
  if [[ $ASSUME_YES -ne 1 ]] && ! have_tty; then
    info "There is no terminal here to ask on, and this run will not restart a"
    info "service nobody answered for. When you are ready:"
    dim "$cmd"
    _offer_the_start "${idle[@]}"
    return 0
  fi
  reply="$(ask 'Restart them now? [Y/n]' y)"
  case "$reply" in
    y|Y|yes|YES) ;;
    *) info "not restarted. When you are ready:"; dim "$cmd"; _offer_the_start "${idle[@]}"; return 0 ;;
  esac

  run_root systemctl restart "${still[@]}" || true
  # Read back, one at a time, because "restarted them" is a claim about
  # services and this script's own rule is that a claim about a service goes
  # through systemctl.
  local failed=0
  for u in "${still[@]}"; do
    state="$(systemctl is-active "$u" 2>/dev/null || true)"
    if [[ "$state" == "active" ]]; then
      ok "$u is running the new code"
    else
      warn "$u is ${state:-<no answer>} after the restart"
      dim "read: sudo journalctl -u $u -n 50 --no-pager"
      failed=1
    fi
  done
  [[ $failed -eq 0 ]] || warn "the release is installed; what did not come back is named above."
  _offer_the_start "${idle[@]}"
  return 0
}

# The units offer_the_restart found installed, enabled and not running, both
# before this run and now (#803). Named, with the command that starts them,
# and offered at a terminal only, answer no unless someone types yes: a unit
# that was down before the update may be down on purpose, so --yes, which
# answers this run's own questions, is not an answer to this one.
_offer_the_start() { # $@ = the units
  [[ $# -gt 0 ]] || return 0
  local u state reply failed=0
  echo
  warn "Installed and enabled, and NOT running (they were not running when this update started either):"
  for u in "$@"; do warn "  $u ($(systemctl is-active "$u" 2>/dev/null || true))"; done
  info "This update did not stop them, and it does not start them on its own: one"
  info "may be stopped on purpose. Read why, then start them:"
  for u in "$@"; do dim "sudo journalctl -u $u -n 50 --no-pager"; done
  dim "sudo systemctl start $*"
  if [[ $RESTART_ASK -eq 0 || $ASSUME_YES -eq 1 ]] || ! have_tty; then
    return 0
  fi
  reply="$(ask 'Start them now? [y/N]' n)"
  case "$reply" in
    y|Y|yes|YES) ;;
    *) info "not started."; return 0 ;;
  esac
  run_root systemctl start "$@" || true
  for u in "$@"; do
    state="$(systemctl is-active "$u" 2>/dev/null || true)"
    if [[ "$state" == "active" ]]; then
      ok "$u is running"
    else
      warn "$u is ${state:-<no answer>} after the start"
      dim "read: sudo journalctl -u $u -n 50 --no-pager"
      failed=1
    fi
  done
  [[ $failed -eq 0 ]] || warn "what did not start is named above."
  return 0
}

# The root programs, refreshed from the new tree.
#
# Four programs run as root out of /usr/local/sbin: the model-key sealer, the
# trust sync, this host's own updater, and on an aggregator the fleet broker.
# They are copied there rather than named inside the checkout on purpose
# (install-model-key-sealer.sh says why: a unit naming a file the
# dashboard's account can rewrite is root for anything running as that
# account). The consequence is that swapping the tree does not touch them,
# and the host then runs a program from the release before this one. That is
# #185, and it has been met live twice: an arm token refused by a sealer
# whose source was current and whose installed copy was not, and then #443,
# where the fleet broker on an aggregator was four days behind the tree, the
# page's seal called a verb it did not have, and the aggregator's own sealed
# copy of the fleet model was never written while every node reported sealed.
#
# Refreshed the way fleet-update.sh refreshes it, compare and install, and
# only where a copy is ALREADY there. An absent one is a host that never had
# that grant, and installing it would be widening what root will do on a run
# nobody asked that of.
#
# The Advisor's model-credential recovery program is deliberately NOT on this
# list (#541). The other four are operator-facing grants an installer put
# there on purpose; credcheck is the recovery half of a reference
# refresh_advisord_recovery is about to write into aperire-advisord's own
# unit (OnFailure=), and a unit naming a recovery service with no program or
# unit behind it is a dangling reference systemd silently ignores. The line
# and the program have to move together, gated on "this host has the
# Advisor's unit", not on "a copy is already at this destination" -- which is
# exactly the gate that left credcheck undelivered to every host that had not
# already been through install-advisor-stack.sh or install-advisor-account.sh
# since 17e. write_advisord_credcheck_unit (below, in refresh_advisord_recovery)
# is the one place that copies the program and writes its unit, the same
# function install-advisord.sh and install-advisor-account.sh call, so this
# cannot drift from what either installer would produce.
#
# The directory is a variable only so the tests can point it somewhere
# harmless. Nothing here should ever pass anything else.
SBIN_DIR="${APERIRE_GET_SBIN:-/usr/local/sbin}"
# Where the updater finds the release key and the function that checks it.
# A variable only so the tests can point it somewhere harmless, the same as
# the two above.
RELEASE_LIB_DIR="${APERIRE_GET_RELEASE_LIB_DIR:-/usr/local/lib/aperire}"

# The updater's two dependencies, placed BEFORE the updater itself: a new
# aperire-update that arrived without the key it checks against would refuse
# every update from then on, and the page would have no way to say why.
#
# Gated on the updater being installed, the way the state helper is gated on
# the programs that use it. Each file goes through root_place like every other
# root copy (ADR 0024): read once, checked against the release digests (for a
# signed release, the signed file list), into a directory only root can
# write. The signer set is then checked once more on that staged copy, before
# it is renamed into place: it has to be the set the signed release.json
# names (signers_sha256, which the maintainer's Mac checked against its own
# before it signed) and one rotation step at most from the set this host
# trusts now. The Mac never sees the tree's copy of the file, so this check
# is the one that holds the tree's bytes to what was signed.
refresh_release_trust() {
  run_root test -e "${SBIN_DIR}/aperire-update" || return 0
  local rel name stage rc want why trust_kind=""
  { run_root mkdir -p "$RELEASE_LIB_DIR" && run_root chmod 0755 "$RELEASE_LIB_DIR"; } \
    || { warn "could not make $RELEASE_LIB_DIR, so the updater keeps the release key it had."; return 0; }
  stage="$(run_root mktemp -d "$RELEASE_LIB_DIR/.release-trust.XXXXXXXX")" \
    || { warn "could not stage the release key under $RELEASE_LIB_DIR, so the updater keeps the one it had."; return 0; }
  ROOT_CLEANUP_PATHS+=("$stage")
  run_root chmod 0755 "$stage"
  for rel in scripts/release-verify-lib.sh scripts/release-signers; do
    [[ -f "$DIR/$rel" ]] || { warn "this release carries no $rel, so the updater keeps the release key it had."; return 0; }
    name="${rel#scripts/}"
    rc=0
    root_place "$rel" "$stage/$name" 0644 || rc=$?
    if [[ $rc -eq 6 ]]; then
      warn "$RELEASE_LIB_DIR/$name was NOT refreshed: the account check could not run (above), so $rel was not judged."
      dim "the updater still checks against the release key it had."
      return 0
    elif [[ $rc -ne 0 ]]; then
      warn "$RELEASE_LIB_DIR/$name was NOT refreshed: $rel in the tree is not the file this release shipped, or a service account can change it (above)."
      dim "the updater still checks against the release key it had."
      return 0
    fi
  done
  if ! why="$(release_signers_check "$stage/release-signers" 2>&1 >/dev/null)"; then
    warn "$RELEASE_LIB_DIR/release-signers was NOT refreshed: $why"
    return 0
  fi
  if [[ -n "$SIGNED_DIR" ]] && run_root test -s "$SIGNED_DIR/release.json"; then
    want="$(release_json_field "$SIGNED_DIR/release.json" signers_sha256)" || want=""
    if [[ -z "$want" || "$(release_signers_digest "$stage/release-signers")" != "$want" ]]; then
      warn "$DIR/scripts/release-signers is not the key set the signed release names, so it was not copied to $RELEASE_LIB_DIR."
      return 0
    fi
    trust_kind="the signed release's key set"
  else
    trust_kind="not a signed release, so held only to the release digests"
  fi
  if run_root test -e "$RELEASE_LIB_DIR/release-signers" || run_root test -L "$RELEASE_LIB_DIR/release-signers"; then
    # A set that is there and not one this code accepts is a refusal, never
    # "nothing installed": the transition rule cannot be skipped by breaking
    # the file it reads.
    if run_root test -L "$RELEASE_LIB_DIR/release-signers" \
       || ! why="$(release_signers_check "$RELEASE_LIB_DIR/release-signers" 2>&1 >/dev/null)"; then
      warn "$RELEASE_LIB_DIR/release-signers was NOT refreshed: the set installed there is not one this release accepts (${why:-a symlink})."
      dim "put this host right by uninstalling it, keeping your data, and installing again with the one-liner."
      return 0
    fi
    if ! why="$(release_signers_transition_ok "$RELEASE_LIB_DIR/release-signers" "$stage/release-signers" 2>&1)"; then
      warn "$RELEASE_LIB_DIR/release-signers was NOT refreshed: $why"
      return 0
    fi
  fi
  if run_root mv -fT "$stage/release-verify-lib.sh" "$RELEASE_LIB_DIR/release-verify-lib.sh" \
     && run_root mv -fT "$stage/release-signers" "$RELEASE_LIB_DIR/release-signers"; then
    ok "$RELEASE_LIB_DIR/release-verify-lib.sh and release-signers are this release's (${trust_kind})"
    dim "release key $(release_key_fingerprints "$RELEASE_LIB_DIR/release-signers" | tr '\n' ' ')"
  else
    warn "$RELEASE_LIB_DIR could not be refreshed, so the updater still checks against the previous copy."
  fi
  return 0
}

# The fleet broker's record of which directory the install is (#828).
#
# The broker grant pins $DIR by identity (INSTALL_DIR_ID, the filesystem id
# and the inode), so a renamed or swapped tree cannot stand in for the real
# one. The swap above is a rename, which gives $DIR a new inode, and before
# this every update left the broker refusing every pairing approval as
# install_moved until root re-ran the grant installer by hand.
#
# So the INSTALLED broker re-records it, through a root-only argv mode, for
# the tree this run moved in and nothing else: the tree moved aside has to
# carry the recorded id, and $DIR has to be the directory root read before
# the rename (SWAPPED_IN_ID). Run after refresh_root_programs, so the first
# fixed update installs the broker that has the mode before it asks for it.
#
# stdin is closed and the call is bounded. A broker from before this mode
# ignores argv and reads its verb from stdin, and on a page-driven update
# stdin is the update's own socket, so an open stdin would wait on it.
# Only an exact rerecorded=1, already_current=1 or refused= line is
# believed; anything else is an older broker, named as one. Never fatal:
# the release is installed either way, and the line says what is left.
#
# broker_grant=<state> is a machine line, a fact in the apply stream that
# aperire-update streams from this script's output (#842 will show it on the
# page). It is printed on an update whose output is piped and nowhere else
# (#938): not on an install, where it showed a fresh host with no broker a
# bare "broker_grant=absent" in the closing text, and not on a terminal,
# where an operator running --update by hand reads the sentences beside it.
# A state that needs the operator is said in words either way.
grant_fact() { # $1 = absent, rerecorded, already_current, stale or too_old
  [[ $UPDATE -eq 1 && ! -t 1 ]] || return 0
  printf 'broker_grant=%s\n' "$1"
}
rerecord_broker_grant() {
  local broker="${SBIN_DIR}/aperire-fleet-broker" conf="$ETC_APERIRE/fleet-broker.conf" out reason
  if ! run_root test -e "$broker" || ! run_root test -e "$conf"; then
    grant_fact absent
    return 0
  fi
  # A run that swapped nothing (a git checkout updated in place) kept the
  # same directory, so there is nothing to re-record.
  [[ -n "$KEPT_PREVIOUS" ]] || return 0
  if [[ -z "$SWAPPED_IN_ID" ]]; then
    out="refused=no_swap_id"
  else
    out="$(run_root env APERIRE_ETC="$ETC_APERIRE" timeout -k 5 60 "$broker" \
             --rerecord-install-dir --previous "$KEPT_PREVIOUS" --expect "$SWAPPED_IN_ID" \
             </dev/null 2>&1)" || true
  fi
  if grep -qx 'rerecorded=1' <<<"$out"; then
    grant_fact rerecorded
    ok "the fleet broker's grant now records the new tree, so pairing approvals keep working"
  elif grep -qx 'already_current=1' <<<"$out"; then
    grant_fact already_current
    ok "the fleet broker's grant already records this tree"
  elif reason="$(sed -n 's/^refused=\([a-z_]*\)$/\1/p' <<<"$out" | head -1)" && [[ -n "$reason" ]]; then
    grant_fact stale
    warn "the fleet broker's grant still records the tree before this one ($reason), so it refuses pairing approvals as install_moved."
    dim "the update itself is fine. Re-record the grant with the full installer:"
    dim "  curl -fsSL https://get.aperire.one | bash -s -- --dir $DIR --run fleet-broker-grant"
  else
    grant_fact too_old
    warn "the installed fleet broker is older than this release and cannot re-record which tree the install is, so it refuses pairing approvals as install_moved."
    dim "the update itself is fine. Install the grant from this release:"
    dim "  curl -fsSL https://get.aperire.one | bash -s -- --dir $DIR --run fleet-broker-grant"
  fi
  return 0
}

# ---- the trust sync unit, brought up to date by the update (#800, #1133) ----
#
# A passkey enrolled in the browser asks one root service to rebuild the
# Advisor's trust store (install-trust-sync-grant.sh). Until #800 that service
# unit carried a [Unit] key under [Service], and systemd logged "Unknown key
# name" on every enrollment. Fixing the installer did not reach a host that
# already had the old unit: nothing wrote it again.
#
# So when the unit is installed, the update runs the grant installer's
# --if-stale. It reads the installed unit and writes the grant again only if
# it is out of date, and says either way. Root runs the release's checked
# copy out of the staged tree, never the checkout's; a host that never had the
# grant is left alone, since the installer says "not installed here" and
# stops. Never fatal: the release is installed either way. When the step could
# not run, the closing text names the one command that does (TRUST_SYNC_PENDING).
TRUST_SYNC_PENDING=0
refresh_trust_sync_unit() {
  local rc=0
  installed_units | awk '{print $1}' | grep -qx 'aperire-trust-sync@.service' || return 0
  step "the trust sync unit (#800)"
  if [[ ! -f "$DIR/scripts/install-trust-sync-grant.sh" ]]; then
    warn "scripts/install-trust-sync-grant.sh is missing from the new release; the trust sync unit was not checked"
    TRUST_SYNC_PENDING=1
    return 0
  fi
  if [[ -z "$RUN_TREE" ]]; then
    warn "root has no checked copy of the release to run the trust sync check from; it was not run"
    TRUST_SYNC_PENDING=1
    return 0
  fi
  local -a renv=()
  [[ -n "$RD_REFUSED_FILE" ]] && renv+=( "RD_REFUSED_LOG=$RD_REFUSED_FILE" )
  # Told the install and nothing else: no directory comes from this shell's
  # environment, so the unit it reads and rewrites is where systemd keeps it.
  run_root env APERIRE_INSTALL_TREE="$DIR" ${renv[@]+"${renv[@]}"} \
    bash "$RUN_TREE/scripts/install-trust-sync-grant.sh" --if-stale < /dev/null || rc=$?
  collect_installer_refusals
  if [[ $rc -ne 0 ]]; then
    warn "the trust sync check exited $rc, so the trust sync unit may still be the old one. The lines above say why."
    TRUST_SYNC_PENDING=1
  fi
  return 0
}

# The two libraries the updater's rollback stages a restored tree's
# installers with (#764), beside the release key, wherever the updater is.
# Before the updater itself below, so a new updater never lands without them.
refresh_rollback_libs() {
  run_root test -e "${SBIN_DIR}/aperire-update" || return 0
  local f rc
  for f in release-digests-lib.sh trusted-path-lib.sh; do
    rc=0
    root_place "scripts/$f" "$RELEASE_LIB_DIR/$f" 0644 || rc=$?
    case $rc in
      0) [[ "$ROOT_PLACED" == same ]] || ok "$RELEASE_LIB_DIR/$f refreshed from the new tree (the updater's rollback checks with it)" ;;
      1) warn "$RELEASE_LIB_DIR/$f was NOT refreshed: scripts/$f in the tree is not the file this release shipped, or a service account can change it." ;;
      6) warn "$RELEASE_LIB_DIR/$f was NOT refreshed: the account check could not run (above), so scripts/$f was not judged." ;;
      *) warn "$RELEASE_LIB_DIR/$f could not be refreshed." ;;
    esac
  done
  return 0
}

refresh_root_programs() {
  local pair rel dest out rc said=0
  refresh_release_trust
  refresh_rollback_libs
  local -a programs=(
    "scripts/aperire-seal-model-key.sh:aperire-seal-model-key"
    "scripts/aperire-trust-sync.sh:aperire-trust-sync"
    "scripts/aperire-update.sh:aperire-update"
    "scripts/aperire-fleet-broker.sh:aperire-fleet-broker"
    "scripts/aperire-fleet-arm.sh:aperire-fleet-arm"
  )
  for pair in "${programs[@]}"; do
    rel="${pair%%:*}"
    dest="${SBIN_DIR}/${pair##*:}"
    [[ -f "$DIR/$rel" ]] || continue
    if [[ "$dest" == */aperire-fleet-arm ]]; then
      # #741: the command a node's operator runs for the pairing fingerprint,
      # by its fixed name. Wherever the fleet broker is (every host that can
      # approve a pairing), including one whose grant predates it, so the
      # name the node's prompt gives is on this host after this update.
      run_root test -e "${SBIN_DIR}/aperire-fleet-broker" || continue
    else
      run_root test -e "$dest" || continue
    fi
    if [[ $said -eq 0 ]]; then
      step "refreshing the root programs from the new release"
      said=1
    fi
    # Checked against the release and copied from the one read that was
    # checked, then renamed over the old copy, never written into it. The
    # third program on this list is aperire-update, and on an update driven
    # from the dashboard THAT is the process running this script: a rename
    # leaves the running copy its own inode to finish.
    rc=0
    root_place "$rel" "$dest" 0755 || rc=$?
    out="$ROOT_PLACED"
    case $rc in
      0)
        if [[ "$out" == same ]]; then
          ok "$dest already matches this release"
          continue
        fi
        ok "$dest refreshed from the new tree"
        # The broker is more than its program: it also has a socket unit, a
        # service unit and a conf, and those are the grant installer's to
        # write. They are NOT written here, because an update's own promise
        # is that it restarts nothing, and that installer restarts the
        # socket. So the verbs are current after this and the unit text may
        # not be, and the operator is told which command closes the rest.
        if [[ "$dest" == */aperire-fleet-broker ]]; then
          dim "its units and its conf belong to the grant installer and were not touched."
          dim "if this release changed them:  curl -fsSL https://get.aperire.one | bash -s -- --dir $DIR --run fleet-broker-grant"
        fi
        ;;
      1)
        # Not "re-run it on its own": a re-run out of this same tree meets
        # the same bytes and refuses the same way.
        warn "$dest was NOT refreshed: $rel in the tree is not the file this release shipped, or a service account can change it."
        dim "the previous release's copy is still in place. What changed the tree is the question."
        ;;
      6)
        warn "$dest was NOT refreshed: the account check could not run (above), so $rel was not judged."
        dim "the previous release's copy is still in place. Nothing about the file was judged."
        dim "run it again from a checked copy: curl -fsSL ${APERIRE_GET_SELF_URL:-$DEFAULT_SELF_URL} | bash -s -- --update --force"
        ;;
      *)
        warn "$dest could not be refreshed, so it is still the previous release's copy."
        dim "re-run it from a checked copy: curl -fsSL ${APERIRE_GET_SELF_URL:-$DEFAULT_SELF_URL} | bash -s -- --update --force"
        ;;
    esac
  done
  refresh_state_tool
  split_fleet_trust
  refresh_image_recipe
  refresh_node_wrapper
  return 0
}

# The node wrapper, the two libraries it loads, and how the Advisor reaches it
# (ADR 0024, ADR 0025).
#
# An update converges the host to what a fresh install leaves (#756 review,
# M1), not only the copies: every instance's wrapper is placed in
# /usr/local/sbin from this release after the check that no service account
# can write it, and the Advisor's unit is pointed at that copy. An Advisor on
# its own account gets its root socket and the full sandbox, and the sudo rule
# an older release wrote goes. Nothing restarts here. An Advisor already
# running on its sudo rule keeps the rule until it restarts, and the restart
# is offered below with the others; once it has happened this runs again and
# the rule goes (finish_node_wrapper).
#
# An Advisor on a shared account (the retired --advisor-shared-account shape,
# every 22.04 host before ADR 0025) cannot be converted in place. Moving it
# restarts the Advisor and the dashboard and plants a reveal window, so it is
# offered to an operator at a terminal after the restart, and never done by a
# run nobody is at (#641): offer_the_advisor_move.
#
# A refusal is not a warning when the rule still grants the tree's file and a
# service account can write that file: that is root for the account, the
# thing this exists to end, so the update finishes what it was doing and then
# exits non-zero, naming it.
NODE_WRAPPER_PENDING=0
NODE_WRAPPER_REFUSED=0
# An Advisor whose new build reaches the node only through its root socket,
# with that socket not working (ADR 0025): cut off at its next start. Like a
# refusal, the update finishes and then ends non-zero, naming it.
NODE_WRAPPER_STRANDED=0
ADVISOR_MOVE_NEEDED=0
# Named instances whose Advisor is on a shared account (#946). The staged move
# acts on the default instance only, so these are named to the operator and
# never moved from here.
ADVISOR_MOVE_INSTANCED=()
SUDOERS_DIR_GET="${APERIRE_GET_SUDOERS_DIR:-/etc/sudoers.d}"
_node_wrapper_run() { # prints the lib's own lines; returns its code. release_held_dir has run
  # Root sources the library from a checked copy, never from the tree: read
  # once, matched against the release's digests, staged where only root can
  # write (ADR 0024 lane 2). And it gets this script's own release-digests
  # functions as text, so the broker it places is checked the same way.
  local said lib rc=0
  said="$(stage_for_root_pinned scripts/trusted-path-lib.sh 2>&1)" || rc=$?
  lib="$(tail -n 1 <<<"$said")"
  if [[ $rc -ne 0 || "$lib" != /* ]]; then
    if [[ $rc -eq 6 ]]; then
      printf '%s\n   refused: the account check could not run (above), so scripts/trusted-path-lib.sh was not judged and root sourced nothing\n' "$said"
    else
      printf '%s\n   refused: scripts/trusted-path-lib.sh could not be staged as the release shipped it, so root sourced nothing\n' "$said"
    fi
    return 1
  fi
  # What the staging said besides the path (an "unchecked" line on a host
  # with no release digests), kept with the rest of this step's lines.
  [[ "$said" == "$lib" ]] || printf '%s\n' "$(sed '$d' <<<"$said")"
  # The state helper is the release's staged copy (RUN_TREE), the one the
  # converge makes the Advisor's fleet corpus with (#1345).
  # shellcheck disable=SC2016  # $1 to $4 are the inner shell's own arguments
  run_root env APERIRE_SBIN_DIR="$SBIN_DIR" APERIRE_LIB_DIR="$IMAGE_RECIPE_DEST" APERIRE_MOVE_MARKERS=1 \
    APERIRE_SUDOERS_DIR="$SUDOERS_DIR_GET" APERIRE_UNIT_DIR="${APERIRE_GET_UNIT_DIR:-/etc/systemd/system}" \
    APERIRE_PROC_DIR="${APERIRE_GET_PROC_DIR:-/proc}" APERIRE_RUN_DIR="${APERIRE_GET_RUN_DIR:-/run/aperire}" \
    bash -c "$(rd_lib_text)"'
    . "$3"
    TP_STATE_TOOL="$4"
    trusted_update_node_wrapper "$1" "$2"' _ "$DIR" "$NODE_WRAPPER_CONF" "$lib" "${RUN_TREE:+$RUN_TREE/scripts/state-file.py}" 2>&1
}
refresh_node_wrapper() {
  [[ -r "$DIR/scripts/trusted-path-lib.sh" && -f "$DIR/scripts/aperire-node-wrapper.sh" ]] || return 0
  local out rc=0
  release_held_dir
  out="$(_node_wrapper_run)" || rc=$?
  [[ -n "$out" ]] || return 0
  # The lines naming which instance needs the account move (#946) are for this
  # script, not the operator.
  local marks inst_m
  marks="$(grep -E '^@move-needed:' <<<"$out" || true)"
  out="$(grep -vE '^@move-needed:' <<<"$out" || true)"
  step "the node wrapper: the root-owned copy, and how the Advisor reaches it"
  printf '%s\n' "$out"
  case "$rc" in
    0) ;;
    5) NODE_WRAPPER_PENDING=1
       dim "the running Advisor has not restarted since its route changed (its sudo rule is kept, or already removed); the restart offered below finishes this." ;;
    6) NODE_WRAPPER_REFUSED=1 ;;
    7) while IFS= read -r inst_m; do
         [[ -n "$inst_m" ]] || continue
         inst_m="${inst_m#@move-needed:}"
         if [[ -z "$inst_m" ]]; then ADVISOR_MOVE_NEEDED=1; else ADVISOR_MOVE_INSTANCED+=("$inst_m"); fi
       done <<<"$marks"
       if [[ $ADVISOR_MOVE_NEEDED -eq 1 ]]; then
         dim "the move to its own account is offered below, after the restart."
       elif [[ -z "$marks" ]]; then
         # A staged library older than the marker names no instance, so the
         # move is not offered; the operator is told the command instead.
         warn "an Advisor is on a shared account, but this release's check did not say which, so the move is not offered here."
         dim "to move it: curl -fsSL ${APERIRE_GET_SELF_URL:-$DEFAULT_SELF_URL} | bash -s -- --update --force"
       fi ;;
    8) NODE_WRAPPER_STRANDED=1 ;;
    *) warn "not converged, so the Advisor may still name the previous copy."
       dim "run it again from a checked copy: curl -fsSL ${APERIRE_GET_SELF_URL:-$DEFAULT_SELF_URL} | bash -s -- --update --force" ;;
  esac
  return 0
}
finish_node_wrapper() {
  [[ $NODE_WRAPPER_PENDING -eq 1 ]] || return 0
  local out rc=0
  release_held_dir
  out="$(_node_wrapper_run)" || rc=$?
  out="$(grep -vE '^@move-needed:' <<<"$out" || true)"
  step "the node wrapper: removing the Advisor's old sudo rule"
  [[ -n "$out" ]] && printf '%s\n' "$out"
  if [[ $rc -eq 0 ]]; then
    ok "the Advisor holds no sudo rule; it reaches the wrapper through its root socket"
  elif [[ $rc -eq 7 ]]; then
    :
  elif [[ $rc -eq 8 ]]; then
    NODE_WRAPPER_STRANDED=1
  else
    warn "THE RUNNING ADVISOR HAS NOT RESTARTED, so it still runs on its old sudo route (kept, or removed above)."
    warn "Until it restarts it may not reach the node. Restart it, then finish:"
    dim "sudo systemctl restart aperire-advisord, then: curl -fsSL ${APERIRE_GET_SELF_URL:-$DEFAULT_SELF_URL} | bash -s -- --update --force"
  fi
  return 0
}

# The Advisor off a shared account and onto its own (ADR 0025). Only for an
# operator at a terminal who agrees, because install-advisor-account.sh
# restarts the Advisor and the dashboard and plants a reveal window, and #641
# says a run nobody is at (the dashboard's own update socket runs this with
# --yes --no-restart and no terminal) never does that. Everyone else is told
# the one command.
offer_the_advisor_move() {
  [[ $ADVISOR_MOVE_NEEDED -eq 1 || ${#ADVISOR_MOVE_INSTANCED[@]} -gt 0 ]] || return 0
  local cmd reply rc=0 named
  # The move below acts on the default instance: its unit, its account, its
  # state. A named instance's Advisor on a shared account is not that one, so
  # it is named here and left alone (#946).
  if [[ ${#ADVISOR_MOVE_INSTANCED[@]} -gt 0 ]]; then
    named="${ADVISOR_MOVE_INSTANCED[*]}"
    step "the Advisor's own account, named instances"
    info "The Advisor of instance ${named// /, } runs on a shared account, and this update"
    info "does not move a named instance's Advisor. It was left as it is. The lines under"
    info "the node wrapper step above name the command that moves it."
  fi
  [[ $ADVISOR_MOVE_NEEDED -eq 1 ]] || return 0
  cmd="curl -fsSL ${APERIRE_GET_SELF_URL:-$DEFAULT_SELF_URL} | bash -s -- --update --force"
  step "the Advisor's own account"
  info "The Advisor here runs on a shared account. That mode is retired: the"
  info "Advisor now always runs on its own account, reaching the node only"
  info "through a root socket, with no sudo and NoNewPrivileges, on Ubuntu"
  info "22.04 as on 24.04. Moving it restarts the Advisor and the dashboard."
  if [[ $RESTART_ASK -eq 0 ]] || ! have_tty; then
    info "Nobody is here to agree to that restart, so it was not moved. When you are ready:"
    dim "$cmd"
    return 0
  fi
  reply="$(ask 'Move it now? [Y/n]' y)"
  case "$reply" in
    y|Y|yes|YES) ;;
    *) info "not moved. When you are ready:"; dim "$cmd"; return 0 ;;
  esac
  # A checked copy of the installer and of everything it loads or runs, each
  # read once and matched against the release's digests into a directory
  # only root can write, never the tree's own bytes (#779 review, L1). It
  # acts on this tree, named to it.
  local staged srcrc=0
  release_held_dir
  staged="$(stage_program_for_root_pinned account-move \
        scripts/install-advisor-account.sh scripts/fleet-corpus-perms.sh \
        scripts/advisord-credcheck-lib.sh scripts/advisord-restart-lib.sh \
        scripts/trusted-path-lib.sh scripts/release-digests-lib.sh \
        scripts/state-ancestors-lib.sh scripts/state-file.py \
        scripts/close-node-config-exposure.sh scripts/fleet-trust-split.sh)" || srcrc=$?
  if [[ $srcrc -ne 0 || -z "$staged" ]]; then
    refused_root_copy "$srcrc" "the Advisor's account move (from scripts/install-advisor-account.sh and the files it loads)"
    if [[ $srcrc -eq 6 ]]; then
      warn "the move did not run: the account check could not run (above), so the installer and the files it loads were not judged."
      dim "nothing says the tree changed. Run the update again to retry the check:"
    else
      warn "the move did not run: the installer or a file it loads is not the one this release shipped, or a service account can change it."
      dim "running it out of this tree would run those same bytes as root. Find what changed the tree, then put the release back as it shipped:"
    fi
    dim "curl -fsSL ${APERIRE_GET_SELF_URL:-$DEFAULT_SELF_URL} | bash -s -- --update --force"
    return 0
  fi
  run_root env APERIRE_INSTALL_TREE="$DIR" bash "$staged/install-advisor-account.sh" < /dev/null || rc=$?
  if [[ $rc -eq 0 ]]; then
    ok "the Advisor runs on its own account now, and reaches the node through its socket"
  else
    warn "the move did not finish, and it put the previous arrangement back; what it said is above."
    dim "to try again: $cmd"
  fi
  return 0
}

# The fleet trust key, the dashboard's alone (#868, ADR 0024 row 19), on
# every update rather than only on the Advisor's account move. On a host
# whose fleet-trust.yaml holds a private_key, the key file goes to the
# dashboard account at 0600 and the Advisor reads fleet-trust.pub.yaml
# beside it; a node's peers-only file stays readable where it is. Before
# this, the account move left the key 0640 to the group the Advisor shares,
# and nothing narrowed it after.
#
# Root runs the release's checked copies of the split, the rule it shares
# with verify-after-restart.sh, and the helper that walks the unit, never
# the tree's. Quiet when nothing moved.
# The key is narrowed only once the Advisor runs a build that reads the
# public file (fleet-trust-split.sh says why). An update restarts nothing
# until the operator agrees to it, so this runs twice: here, which writes the
# public file and narrows the key if the Advisor already reads it, and again
# after the restart offer ("after"), which narrows it once the restart has
# put the new build in place, and stays quiet when nothing moved.
split_fleet_trust() {
  [[ -e "$DIR/dashboard/config/fleet-trust.yaml" ]] || return 0
  [[ -r "$DIR/scripts/fleet-trust-split.sh" ]] || return 0
  local when="${1:-}" staged out rc=0 srcrc=0
  release_held_dir
  staged="$(stage_program_for_root fleet-trust-split \
        scripts/fleet-trust-split.sh scripts/fleet-trust-perms.sh \
        scripts/advisor-owner-lib.sh scripts/dashboard-account-lib.sh scripts/state-file.py)" || srcrc=$?
  if [[ $srcrc -ne 0 || -z "$staged" ]]; then
    refused_root_copy "$srcrc" "the fleet trust key split (from scripts/fleet-trust-split.sh and the files it loads)"
    if [[ $srcrc -eq 6 ]]; then
      warn "the fleet trust key was not checked: the account check could not run (above), so its program was not judged."
    else
      warn "the fleet trust key was not checked: its program in the tree is not the release's."
    fi
    return 0
  fi
  out="$(run_root bash "$staged/fleet-trust-split.sh" --repo "$DIR" < /dev/null 2>&1)" || rc=$?
  if [[ $rc -eq 0 ]]; then
    # After the restart offer, only news: the key narrowed now. A key still
    # waiting was said once already, above.
    if { [[ "$when" != after ]] && grep -q -e '->' -e 'not yet narrowed' <<<"$out"; } \
       || { [[ "$when" == after ]] && grep -q -- '->' <<<"$out" && ! grep -q 'not yet narrowed' <<<"$out"; }; then
      step "the fleet trust key"
      printf '%s\n' "$out"
    fi
  else
    step "the fleet trust key"
    [[ -n "$out" ]] && printf '%s\n' "$out"
    warn "the fleet trust key is not in its target shape; what it said is above."
    dim "to try again: curl -fsSL https://get.aperire.one | bash -s -- --update --force"
  fi
  return 0
}

# The install tree above advisor/state (#703), on every update rather than
# only on a fresh install. This is the half that reaches a host nobody is
# going to re-install: an aggregator whose tree was 0775 owner:owner with the
# Advisor's account in the owner's group refuses every seal until it is
# narrowed, and the operator has no reason to connect that refusal to an
# install they did months ago.
#
# Runs on any host with an advisor/state, whether or not the Advisor is
# installed: the directory is what root writes through, and a tree that is
# going to refuse should be repaired before the seal that meets it.
narrow_state_ancestors() {
  [[ -r "$DIR/scripts/state-ancestors-lib.sh" ]] || return 0
  [[ -d "$DIR/advisor/state" ]] || return 0
  # Root sources this library and runs the helper it drives, so root uses
  # checked copies of both, never the tree's. Pinned to their release digests
  # (#877 review, M2): this is the repair of a tree the Advisor's account can
  # write, so a path finding on that tree must not be what stops it.
  local staged srcrc=0
  release_held_dir
  staged="$(stage_program_for_root_pinned state-ancestors \
        scripts/state-ancestors-lib.sh scripts/state-file.py)" || srcrc=$?
  if [[ $srcrc -ne 0 || -z "$staged" ]]; then
    refused_root_copy "$srcrc" "the state-ancestors check (from scripts/state-ancestors-lib.sh)"
    if [[ $srcrc -eq 6 ]]; then
      warn "the install tree above advisor/state was not checked: the account check could not run (above), so its library was not judged."
    else
      warn "the install tree above advisor/state was not checked: its library in the tree is not the release's, or a service account can change it."
    fi
    # Not the tree's own fix script: it sits beside the library that was just
    # refused, and running it would run those bytes as root (#764).
    dim "put the release back as it shipped, then run this again: curl -fsSL ${APERIRE_GET_SELF_URL:-$DEFAULT_SELF_URL} | bash -s -- --update --force"
    return 0
  fi
  local out rc=0
  # shellcheck disable=SC2016  # $1 and $2 are the inner shell's own arguments, not this one's
  out="$(run_root env STATE_ANCESTORS_TOOL="$staged/state-file.py" bash -c '
    . "$2/state-ancestors-lib.sh"
    state_ancestors_narrow "$1" "$1/advisor/state"' _ "$DIR" "$staged" 2>&1)" || rc=$?
  if [[ $rc -eq 0 ]]; then
    # Only worth a line when something moved. A tree that was already right
    # is not news on an update that prints thirty other things.
    if grep -q '\->' <<<"$out"; then
      step "the install tree above advisor/state"
      printf '%s\n' "$out"
    fi
  else
    warn "the install tree above advisor/state is writable by an account that is not"
    dim "its owner, so the Advisor's seals will refuse on this host. What is left:"
    printf '%s\n' "$out" >&2
    dim "put the release back as it shipped, which narrows it again:  curl -fsSL https://get.aperire.one | bash -s -- --update --force"
  fi
  return 0
}

# The state helper (#703), which is not one of the grants above but a
# dependency of two of the programs that ARE: the model-key sealer and the
# Advisor's credential check both write advisor/state through it and resolve
# it from /usr/local/sbin.
#
# Gated on THEM, not on itself, and that is the difference from the loop
# above. "Only refresh what is already there" is right for a grant, because
# installing one nobody asked for widens what root will do. It is wrong for a
# dependency: a host that has the sealer from an older release has no helper
# yet, and leaving it that way is a sealer that refuses every seal after this
# update. So the helper is placed when either program is here, and left alone
# when neither is.
# Not read from APERIRE_STATE_TOOL_DEST (#1127): root places the helper at the
# path this names, and a variable the login set would choose that place.
STATE_TOOL_DEST="${SBIN_DIR}/aperire-state-file"
# The second dependency of the same two programs (#708): the one place that
# says how this host keeps a model key and writes the directive that loads it.
# Placed on the same rule and refreshed in the same pass, because a sealer or
# a credential check that cannot find it refuses rather than guesses.
METHOD_LIB_DEST="${APERIRE_KEY_METHOD_LIB_DEST:-${SBIN_DIR}/aperire-model-key-method}"
refresh_root_helper() { # $1 = path in the release, $2 = destination, $3 = mode
  local rel="$1" dest="$2" mode="$3" out rc=0
  [[ -f "$DIR/$rel" ]] || return 0
  # Checked, then renamed over the old copy rather than written into it, for
  # the reason the loop above gives: one of the programs that resolves this
  # helper may be running from it at the moment an update lands.
  root_place "$rel" "$dest" "$mode" || rc=$?
  out="$ROOT_PLACED"
  case $rc in
    0)
      if [[ "$out" == same ]]; then
        ok "$dest already matches this release"
      else
        ok "$dest refreshed from the new tree"
      fi ;;
    1)
      warn "$dest was NOT refreshed: $rel in the tree is not the file this release shipped, or a service account can change it."
      dim "the previous release's copy is still in place." ;;
    6)
      warn "$dest was NOT refreshed: the account check could not run (above), so $rel was not judged."
      dim "the previous release's copy is still in place." ;;
    *)
      warn "$dest could not be refreshed, so sealing and the credential check"
      dim "may refuse until it is: curl -fsSL https://get.aperire.one | bash -s -- --update --force" ;;
  esac
  return 0
}
refresh_state_tool() {
  local user
  user=0
  if run_root test -e "${SBIN_DIR}/aperire-seal-model-key"; then user=1; fi
  if run_root test -e "${SBIN_DIR}/aperire-advisord-credcheck"; then user=1; fi
  [[ $user -eq 1 ]] || return 0
  refresh_root_helper scripts/state-file.py "$STATE_TOOL_DEST" 0755
  refresh_root_helper scripts/model-key-method-lib.sh "$METHOD_LIB_DEST" 0644
  return 0
}

# Where the node wrapper's configuration lives, and the recipe's destination.
# Both are variables only so the tests can point them somewhere harmless.
NODE_WRAPPER_CONF="${APERIRE_GET_WRAPPER_CONF:-$ETC_APERIRE/node-wrapper.conf}"
IMAGE_RECIPE_DEST="${APERIRE_IMAGE_RECIPE_DIR:-/usr/local/lib/aperire}"

# What shape of node this host's wrapper is configured for: container,
# native, or nothing at all. A configuration with no KIND is a container,
# which is the wrapper's own rule and covers every host installed before
# that key existed.
wrapper_node_kind() {
  run_root test -r "$NODE_WRAPPER_CONF" 2>/dev/null || return 1
  local kind
  # shellcheck disable=SC2016  # awk's own $1, not the shell's
  kind="$(run_root awk -F= '$1=="KIND"{sub(/^[^=]*=/,""); print; exit}' "$NODE_WRAPPER_CONF" 2>/dev/null || true)"
  printf '%s' "${kind:-container}"
}

# The xrpld image recipe: four root-owned files a container node's upgrade
# builds its image from, each placed here through the same checked copy as
# the programs above.
#
# This used to run the recipe installer out of the tree, and before that in
# --refresh-only always. That mode exits 0 without writing when nothing is
# installed, so an update placed the recipe on exactly the hosts that already
# had it, and on every container node installed before it shipped the
# Advisor's upgrade refused at the build step, after the operator had
# approved (#675). Prod is one of those hosts. It is not run out of the tree
# any more either: root would be running a script the tree's account can
# rewrite, to copy files that account can rewrite. This script places them
# itself, each checked against the release and copied from the read that was
# checked (ADR 0024).
#
# So: on a host whose wrapper is configured for a CONTAINER node, this
# installs and says so. The "no widening" rule is not in play there. That
# rule is about adding a root grant nobody asked for, and this host has
# already granted the wrapper root for this account; the recipe exists so
# that root builds from a root-owned copy instead of from the account's
# checkout. Anywhere else, native or no wrapper at all, a copy that is here
# is refreshed and nothing is added.
#
# The same list install-xrpld-image-recipe.sh places, path in the release
# and path under the recipe directory.
RECIPE_FILES=(
  "scripts/build-xrpld-image.sh:build-xrpld-image.sh"
  "scripts/xrpld-image/Dockerfile:xrpld-image/Dockerfile"
  "scripts/xrpld-image/entrypoint.sh:xrpld-image/entrypoint.sh"
  "scripts/xrpld-image/signed-binary-sha256.sh:xrpld-image/signed-binary-sha256.sh"
)
refresh_image_recipe() {
  [[ -f "$DIR/scripts/build-xrpld-image.sh" ]] || return 0
  local kind container=0
  kind="$(wrapper_node_kind || true)"
  [[ "$kind" == container ]] && container=1
  if [[ $container -eq 0 ]] && ! run_root test -e "$IMAGE_RECIPE_DEST/build-xrpld-image.sh"; then
    # Native, or a host with no node wrapper, and no copy here: add nothing.
    return 0
  fi

  [[ $container -eq 1 ]] && step "the xrpld image recipe (this node's upgrade builds its image from it)"
  # root:root 0755 on both, every run: `install -d` also puts right a
  # directory that exists with the wrong owner or mode, which mkdir -p would
  # leave as it found it and the wrapper would refuse at the build step.
  if ! run_root install -d -m 0755 -o root -g root "$IMAGE_RECIPE_DEST" "$IMAGE_RECIPE_DEST/xrpld-image"; then
    warn "$IMAGE_RECIPE_DEST/xrpld-image could not be made, so the recipe was not placed."
    return 0
  fi
  local entry rel dest out rc placed=0 same=0 refused=0 failed=0 missing=0
  for entry in "${RECIPE_FILES[@]}"; do
    rel="${entry%%:*}"
    dest="$IMAGE_RECIPE_DEST/${entry#*:}"
    if [[ ! -f "$DIR/$rel" ]]; then
      missing=$((missing + 1))
      warn "$rel is missing from this release, so $dest was not placed."
      continue
    fi
    rc=0
    root_place "$rel" "$dest" 0644 || rc=$?
    out="$ROOT_PLACED"
    case $rc in
      0) if [[ "$out" == same ]]; then same=$((same + 1)); else placed=$((placed + 1)); fi ;;
      1) refused=$((refused + 1))
         warn "$dest was NOT placed: $rel in the tree is not the file this release shipped, or a service account can change it." ;;
      6) refused=$((refused + 1))
         warn "$dest was NOT placed: the account check could not run (above), so $rel was not judged." ;;
      *) failed=$((failed + 1))
         warn "$dest could not be written." ;;
    esac
  done
  if (( refused + failed + missing > 0 )); then
    if [[ $container -eq 1 ]]; then
      warn "the xrpld image recipe is not this release's, so the Advisor's upgrade would build from the previous copy or refuse at the build step."
    fi
    return 0
  fi
  # The wrapper's own rule for what it will build from, checked here so a
  # bad installation is found by the update rather than by the first upgrade
  # (#675: every precondition green, then refused at the build step). Only
  # on a root side that really is root: a fixture's files are its own.
  local wrong
  # shellcheck disable=SC2016  # the root shell's own positional parameters
  wrong="$(run_root bash -c '
    [ "$(id -u)" -eq 0 ] || exit 0
    d="$1"
    for p in "$d" "$d/build-xrpld-image.sh" "$d/xrpld-image" "$d/xrpld-image/Dockerfile" \
             "$d/xrpld-image/entrypoint.sh" "$d/xrpld-image/signed-binary-sha256.sh"; do
      if [ -L "$p" ]; then echo "$p is a symlink"; continue; fi
      o="$(stat -c %u "$p" 2>/dev/null)"; m="$(stat -c %a "$p" 2>/dev/null)"
      [ "$o" = 0 ] || echo "$p is owned by uid ${o:-?}, not root"
      [ -n "$m" ] && [ $(( 0$m & 022 )) -eq 0 ] || echo "$p is mode ${m:-?}, writable by someone other than root"
    done' rd-recipe "$IMAGE_RECIPE_DEST" 2>&1)" || true
  if [[ -n "$wrong" ]]; then
    warn "the xrpld image recipe is in place, and the wrapper will refuse to build from it:"
    printf '        %s\n' "$wrong" >&2
    return 0
  fi
  if [[ $container -eq 1 ]]; then
    if ! run_root test -e "$RD_DIGESTS"; then
      ok "installed under $IMAGE_RECIPE_DEST, copied from one read each (this tree has no release digests to check them against)"
    else
      ok "installed under $IMAGE_RECIPE_DEST: all four files match the release as it arrived, checked before anything ran in the tree"
    fi
  fi
  return 0
}

update_plan() {
  local hostname_now tag_now tag_new
  hostname_now="$(hostname 2>/dev/null || echo this-host)"
  tag_now="$(release_field tag)"
  tag_new="${DEFAULT_RELEASE_TAG:-}"
  # Kept for the closing banner, which prints after write_release_stamp has
  # replaced the file this was read from: by then nothing on the host still
  # says which release it came off.
  UPDATE_TAG_FROM="$tag_now"

  cat <<EOF

  ${S_BOLD}----- Aperire One, update -----${S_OFF}

  Host:       $hostname_now
  Role:       $ROLE
              $ROLE_EVIDENCE
  Installed:  ${tag_now:-no release stamp on this host}
  Applying:   ${tag_new:-the release this script names}
              $SOURCE_URL
              ${EXPECTED_SHA256:+sha256 $EXPECTED_SHA256}
  Directory:  $DIR

  Will do, in order:
    1. copy the database out of the tree, beside it
    2. fetch the release and check that sha256. A mismatch stops here and
       nothing on this host has moved
    3. move the current tree aside under a dated name, put the new one in
       its place, and carry your data/, your config and the Advisor's own
       directories across
    4. build and install from the new tree, and restart nothing
    5. name what is still running the old code, and ask

EOF
  [[ $ASSUME_YES -eq 1 ]] && return 0
  have_tty || return 0
  local reply
  reply="$(ask 'Update this host? [Y/n]' y)"
  case "$reply" in
    y|Y|yes|YES) return 0 ;;
    *) echo "  stopped, nothing was changed."; exit 0 ;;
  esac
}

run_update() {
  already_installed || update_needs_an_install
  looks_like_a_checkout "$DIR" \
    || die "there is no Aperire One checkout at $DIR to update, and an update swaps a tree in place rather than making a new one. If the checkout lives somewhere else, name it: --dir <path>."

  update_resolve_role
  update_read_port
  update_stamp_gate
  update_plan
  announce_sudo
  ensure_sudo

  # Before anything moves: what is serving right now.
  capture_running_units
  snapshot_database

  step "fetching the release"
  source_is_tarball || ensure_git
  fetch_release
  keep_signed_release
  rebuild_advisor_if_installed

  # Once, in this shell, before the first root copy or run out of the new
  # tree: from here every copy makes both checks, in this shell and in every
  # root shell it hands the functions to (#765), and everything root runs out
  # of the release is the staged copy (#764).
  # The narrowing first: on the #703 shape (the tree group-writable, the
  # Advisor in its owner's group) every copy after it, the stage included,
  # would be refused for exactly what it repairs (#877 review, M2).
  release_held_dir
  narrow_state_ancestors
  say_tolerated_tree
  stage_release_for_root || refuse_unstaged_release

  # The node's record, on a host that has a node and nothing naming it.
  # After the fetch, because the verb that writes it ships with the release
  # this run has just put in place, and before the install, because the
  # checks that read the file arrive with that run.
  update_adopt_node
  update_native_source

  step "installing"
  run_install
  # Again after the install, before the first root copy out of the tree:
  # anything the install's own steps (npm ci, the builds) left group-writable
  # is narrowed before refresh_root_programs judges it. Quiet when nothing
  # moved.
  narrow_state_ancestors
  refresh_root_programs
  rerecord_broker_grant
  refresh_trust_sync_unit
  refresh_advisord_recovery
  refresh_advisord_grants

  write_release_stamp
  prune_kept_trees
  offer_the_restart
  split_fleet_trust after
  finish_node_wrapper
  offer_the_advisor_move
  verify_and_report
  if [[ $NODE_WRAPPER_STRANDED -eq 1 ]]; then
    die "the release is installed, but the Advisor's new build reaches the node only through its root socket, and that socket is not working (the lines under 'the node wrapper' above say why). After its next restart it cannot reach the node. Put that right, then run the wrapper step again from a checked copy of the release: curl -fsSL ${APERIRE_GET_SELF_URL:-$DEFAULT_SELF_URL} | bash -s -- --update --force"
  fi
  if [[ $NODE_WRAPPER_REFUSED -eq 1 ]]; then
    die "the release is installed, but the Advisor's old sudo rule still grants a file in the install tree that a service account can write, and the root-owned copy was refused. The refusal above names the file and the account. Make the tree writable by its owner only, then put the release back as it shipped, which runs the wrapper step again from a checked copy: curl -fsSL ${APERIRE_GET_SELF_URL:-$DEFAULT_SELF_URL} | bash -s -- --update --force"
  fi
}

# -- Which host is this ----------------------------------------------
# Detection speaks only when it was not told. An explicit --role always wins:
# this box may be a node host that is getting the relay alone, and no probe
# here can tell that from a co-located one.
#
# This is not the same question the checklist's node probe answers, and the
# two are deliberately separate. This one runs before any checkout exists, on
# a host that has this script and nothing else, so it can only look at
# processes and containers. The checklist runs out of the unpacked release
# and reads the config file and the ports as well. One picks the role; the
# other measures the node the role implies.
ROLE_EVIDENCE=""
# Set when the role came out `dashboard` because the probe found no node, as
# opposed to the operator naming it. The two look identical in the plan and
# they are not the same situation: one of them has a third way on (#139).
ROLE_IS_NODELESS_GUESS=0
resolve_role() {
  local state=0
  if [[ -n "$ROLE" ]]; then
    ROLE_EVIDENCE="(you named it)"
    return 0
  fi
  detect_node || state=$?
  case $state in
    0) ROLE="co-located"
       ROLE_EVIDENCE="(detected: a node is running here - ${DETECT_EVIDENCE})" ;;
    1) ROLE="dashboard"
       ROLE_IS_NODELESS_GUESS=1
       ROLE_EVIDENCE="(detected: no node is running here, so this box watches others - ${DETECT_EVIDENCE})" ;;
    *) # Docker is here and would not answer. Never a default: this is
       # the branch a silent `dashboard` came out of on a node box.
       role_when_unknown
       ROLE_EVIDENCE="(you named it, after the node check could not be completed)" ;;
  esac
}

# --check: fetch, check, say, and leave. Into a temporary directory that goes
# with the run, because a check that leaves a checkout behind has installed
# something after all.
check_only_run() {
  local parent rc=0
  parent="$(as_operator mktemp -d -t aperire-check.XXXXXXXX)" \
    || die "cannot make a temporary directory as $OP_USER to check against."
  CLEANUP_PATHS+=("$parent")
  # Where an install WOULD go, kept before the unpack path takes the variable
  # over. The disk check measures the filesystem the install would land on,
  # and /tmp is frequently neither that filesystem nor even on a disk.
  PREFLIGHT_DIR="$DIR"
  DIR="$parent/aperire-one"

  step "fetching the release to check this host against"
  source_is_tarball || ensure_git
  fetch_release
  run_preflight || rc=$?
  # Said up front by guard_python3, and the install would refuse on it.
  [[ $PYTHON3_MISSING -eq 0 || $rc -ne 0 ]] || rc=1
  exit $rc
}

# -- A node first, when the box has none yet -------------------------
# --node, or answer 5. Runs the node installer out of the release that was
# just fetched, as root, and then lets the preflight find the node it put
# there: the role is co-located because a node is now running here, not
# because this flag said so. A node that does not come up stops the install
# with the installer's own report; nothing of the dashboard is touched yet.
install_node_first() {
  [[ $NODE_FIRST -eq 1 ]] || return 0
  local args=()
  [[ -f "$DIR/scripts/install-aperire-node.sh" ]] || die "the release at $DIR carries no scripts/install-aperire-node.sh"
  stage_release_for_root || refuse_unstaged_release
  step "installing a node on this host first"
  [[ $ASSUME_YES -eq 1 ]] && args+=( --yes )
  run_root env APERIRE_INSTALL_TREE="$DIR" bash "$RUN_TREE/scripts/install-aperire-node.sh" ${args[@]+"${args[@]}"} \
    || die "the node installer did not finish; the dashboard was not installed. Its report above says why."
  ROLE=co-located
  ROLE_IS_NODELESS_GUESS=0
  ROLE_EVIDENCE="(a node was just installed here)"
}

# -- A node that is already here, with no record of itself (#434) ----
#
# A wipe-clean uninstall removes /etc/aperire whole and leaves the node
# running, which is the point of it. What goes with the directory is
# /etc/aperire/node.conf, the one file that says which node this host runs,
# and nothing on this path ever wrote it back: install_node_first fires only
# where the host has NO node, and this is the opposite case. So a rebuilt
# host came back with a healthy node and nothing on the box naming it, and
# every reader without a fallback of its own dead-ended there. The rotation
# window and the relay installer ask docker when the file is missing; the
# non-root migration, the after-reboot check, the baseline check and the
# config closer do not, and all four read it now.
#
# The installer's own `--adopt` measures the running container and writes the
# record. It installs nothing, starts nothing, stops nothing and edits no
# config, which is what makes it safe to run here without being asked for.
#
# Three things this is deliberately not.
#
#   * Not an install. A host with no node reaches install_node_first or
#     nothing at all; nothing here can run the installer's install path.
#   * Not for a native node. `--adopt` is the container verb. The native
#     equivalent lives behind `--native`, which also adds a repository and
#     installs a package where it finds no unit, and that is far more than a
#     missing text file is worth doing unasked. A native host with no record
#     is told the command and left alone.
#   * Not fatal. `--adopt` refuses on everything it cannot be sure of: two
#     node-shaped containers, no published admin RPC, a record naming a
#     different node, a docker that would not answer. Each of those is a
#     reason to say so and carry on installing the dashboard, never a reason
#     to stop an install that has nothing to do with it.
adopt_node_with_no_record() {
  [[ "$ROLE" == "co-located" ]] || return 0
  [[ $NODE_FIRST -eq 0 ]]       || return 0
  if [[ -f "${ETC_APERIRE}/node.conf" ]]; then return 0; fi

  # The checklist's answer first, this run's own probe second.
  #
  # The probe at the top of this script runs only when the role was DETECTED:
  # `--role=co-located` short-circuits it, which is the way out of a box where
  # docker cannot be asked, and the suite holds that naming the role asks
  # docker nothing. A first install driven that way therefore ended with the
  # node unrecorded on a host whose node predated the dashboard (aperire4,
  # 2026-09-17), while the run's own checklist had found that node and written
  # its config paths into the service environment. So the checklist's answer
  # is read rather than a second question asked: it runs on every install
  # path, named role included, and it has already measured the shape and the
  # container's name.
  local shape="$DETECT_KIND" seen="$DETECT_EVIDENCE"
  if [[ -s "${PREFLIGHT_ANSWER:-}" ]]; then
    local pf_shape pf_name
    pf_shape="$(sed -n 's/^NODE_SHAPE=//p' "$PREFLIGHT_ANSWER" | tail -1)"
    pf_name="$(sed -n 's/^NODE_CONTAINER=//p' "$PREFLIGHT_ANSWER" | tail -1)"
    if [[ -n "$pf_shape" ]]; then
      shape="$pf_shape"
      seen="${pf_name:+container ${pf_name}}"
      seen="${seen:-a ${pf_shape} node, found by the checklist}"
    fi
  fi
  # Nothing found a node. Not a refusal: a co-located role named on a box
  # whose node is not up yet is the operator's business, not this run's.
  [[ -n "$shape" ]] || return 0

  local script="$DIR/scripts/install-aperire-node.sh"
  if [[ ! -f "$script" ]]; then
    warn "the release at $DIR carries no scripts/install-aperire-node.sh, so the node running here was not recorded"
    return 0
  fi

  step "recording the node that is already here"
  info "a node is running on this host (${seen}) and nothing names it:"
  info "${ETC_APERIRE}/node.conf is not there. A wipe-clean uninstall takes"
  info "that file and leaves the node, so this is the run that puts it back."

  # Only a container is recorded from here. `--adopt` is the container verb;
  # the native equivalent lives behind `--native`, which also adds a
  # repository and installs a package where it finds no unit. A shape that was
  # not measured (a process with no unit and no container behind it) is the
  # same answer: not something to act on from here.
  if [[ "$shape" != container ]]; then
    info "It is not in a container, so recording it goes through the"
    info "installer's native mode, which also installs where it finds no unit."
    info "That is more than this run will do unasked, so it is left to you and"
    info "it is one command:"
    info "    curl -fsSL https://get.aperire.one | bash -s -- --dir $DIR --run node --native"
    return 0
  fi

  info "The node itself is not touched: no image, no compose file, no config,"
  info "and it is not restarted."
  local rc=0
  stage_release_for_root || refuse_unstaged_release
  run_root env APERIRE_INSTALL_TREE="$DIR" bash "$RUN_TREE/scripts/install-aperire-node.sh" --adopt || rc=$?
  if [[ $rc -ne 0 ]]; then
    warn "the node here was not recorded and the install carries on. The lines above say why; when it is settled, one command puts the record back:"
    warn "    curl -fsSL https://get.aperire.one | bash -s -- --dir $DIR --run node --adopt"
  fi
  return 0
}

# The update's way to the same record, and the reason it needs one (#480).
#
# `--update` branches out of main() before resolve_role, and it runs
# install.sh with --no-preflight, so neither of the two things that measure
# a node on an install happens on this path. The record was therefore never
# written on a host that was updated rather than installed, and since the
# verify became honest about a node it cannot name, that host goes red at
# its nightly check until somebody runs the verb by hand. Three of mine were
# in exactly that state the night this was filed.
#
# So the probe is asked here, once, and only where the answer can change
# anything: a co-located host with no record. A host that already has the
# record is not asked at all, which is what keeps an ordinary update as
# quiet as it was.
#
# Asking docker here and not on a named-role install is deliberate, and the
# suite holds both. An install has the checklist, which measures the node
# out of the unpacked release and leaves the shape and the container's name
# in its answer file; `--role=co-located` is the way out of a box where
# docker cannot be asked, so the install path reads that answer rather than
# asking a second time. An update has no checklist to read, so this probe is
# the only source there is.
#
# Everything after the probe is adopt_node_with_no_record's, unchanged: a
# container is recorded, a native node is named and left alone, and a refusal
# is said out loud and never stops the run.
update_adopt_node() {
  [[ "$ROLE" == "co-located" ]] || return 0
  if [[ -f "${ETC_APERIRE}/node.conf" ]]; then return 0; fi
  # Both non-zero answers mean leave it alone, and neither is read here:
  # adopt_node_with_no_record reads DETECT_KIND, and an empty kind is what
  # makes it return quietly. 1 is "nothing is running here", 2 is "docker
  # would not answer", and an update is no place to start that argument.
  detect_node || true
  adopt_node_with_no_record
}

# The node's package source, on a native host (#802).
#
# #655 moved the native install onto packages.xrplf.org, and only the
# install: a host installed before it kept the retired repos.ripple.com
# through every update, so its package manager stopped at 3.3.0 and the
# Advisor, asking that package manager, called 3.3.0 the newest release.
# After fixBatchV1_2 activates, that node is amendment blocked while the
# Advisor says it is current.
#
# So an update on a native host runs the installer's source move, the same
# way update_adopt_node runs its --adopt: out of the release this run has
# just fetched, as root. The verb changes package sources and refreshes that
# one list. It installs nothing, upgrades nothing, restarts nothing and
# never reads the node's config, and it keeps any source file it did not
# write. The upgrade itself stays with the operator.
#
# Native is read from either record: node.conf's KIND, which the installer
# writes on every native host, or the wrapper configuration's, which is
# there on a host with the Advisor. Not fatal: a refusal is said, with the
# command that finishes it, and the update carries on.
host_node_is_native() {
  local kind=''
  if [[ -r "${ETC_APERIRE}/node.conf" ]]; then
    # shellcheck disable=SC2016  # awk's own $1, not the shell's
    kind="$(awk -F= '$1=="KIND"{sub(/^[^=]*=/,""); print; exit}' "${ETC_APERIRE}/node.conf" 2>/dev/null || true)"
  fi
  [[ "$kind" == native ]] && return 0
  [[ "$(wrapper_node_kind 2>/dev/null || true)" == native ]]
}
update_native_source() {
  host_node_is_native || return 0
  local script="$DIR/scripts/install-aperire-node.sh"
  if [[ ! -f "$script" ]]; then
    warn "the release at $DIR carries no scripts/install-aperire-node.sh, so this node's package source was not checked"
    return 0
  fi
  step "the node's package source"
  info "a native node takes its upgrades from its package source, so this checks that"
  info "the source is not the retired repos.ripple.com. Sources only: the node is"
  info "not upgraded, not restarted, and its config is not touched."
  local rc=0
  stage_release_for_root || refuse_unstaged_release
  run_root env APERIRE_INSTALL_TREE="$DIR" bash "$RUN_TREE/scripts/install-aperire-node.sh" --move-source || rc=$?
  if [[ $rc -ne 0 ]]; then
    warn "the node's package source was not moved, and the update carries on. The lines above say why; when it is settled:"
    warn "    curl -fsSL ${APERIRE_GET_SELF_URL:-$DEFAULT_SELF_URL} | bash -s -- --update --force"
  fi
  return 0
}

# -- The wrapper installer, one argument at a time (#924) -------------
# install-node-wrapper.sh takes an operator argument its detection refusals
# ask for: a container name, a systemd unit, an admin RPC port. Root may not
# run it out of the tree (the login owns the tree), and a hint that says
# `sudo bash <tree>/scripts/install-node-wrapper.sh <name>` is the same act
# typed by hand (#812). So the bootstrap takes the argument, holds it to a
# whitelist, stages the release for root and runs the checked copy, the way
# the pair command goes.
validate_node_wrapper_flags() {
  [[ $WRAPPER_ASKED -eq 0 || $WRAPPER_NATIVE_ASKED -eq 0 ]] \
    || die "--node-wrapper is for a node in a docker container and --node-wrapper-native for one run by systemd. Pick the one that matches this host."
  [[ $WRAPPER_ASKED -eq 1 || $WRAPPER_NATIVE_ASKED -eq 1 ]] \
    || die "--node-wrapper-rpc and --instance go beside --node-wrapper or --node-wrapper-native. Alone they say nothing about what to configure."
  [[ $UPDATE -eq 0 && $UPDATE_FORCE -eq 0 && $RESTART_ASK -eq 1 ]] \
    || die "--node-wrapper configures the wrapper on an installed host and --update moves it to a new release. Run them one at a time."
  [[ $CHECK_ONLY -eq 0 && $NODE_FIRST -eq 0 ]] \
    || die "--node-wrapper configures the wrapper on an installed host, so it does not go with --check or --node. Run them one at a time."
  [[ -z "$FLEET_AGGREGATOR" && -z "$FLEET_LABEL" && $FLEET_CODE_GIVEN -eq 0 ]] \
    || die "--node-wrapper does not join a fleet. Pair on its own: curl -fsSL https://get.aperire.one | bash -s -- --fleet-aggregator <url> --code -"
  [[ -z "$ROLE" && $PORT_GIVEN -eq 0 && $REF_GIVEN -eq 0 && $ASSUME_YES -eq 0 ]] \
    || die "--node-wrapper takes no --role, --port, --ref or --yes: it installs nothing and asks nothing. Only --dir (where the release lives) goes beside it."
  [[ $SOURCE_FLAGGED -eq 0 ]] \
    || die "--node-wrapper fetches nothing, so --source and --sha256 have nothing to act on."
  wrapper_instance_ok "$WRAPPER_INSTANCE" \
    || die "--instance must match [a-z0-9][a-z0-9-]{0,30}, the rule the Advisor's instance names follow."
  if [[ $WRAPPER_ASKED -eq 1 && $WRAPPER_NAME_GIVEN -eq 1 ]]; then
    wrapper_name_ok "$WRAPPER_NAME" \
      || die "--node-wrapper takes a container name: letters, digits, dot, dash and underscore, starting with a letter or digit. It was not given a name like that."
  fi
  if [[ $WRAPPER_NATIVE_ASKED -eq 1 && $WRAPPER_UNIT_GIVEN -eq 1 ]]; then
    wrapper_unit_ok "$WRAPPER_UNIT" \
      || die "--node-wrapper-native takes a systemd unit name: letters, digits, dot, dash, underscore and @, starting with a letter or digit. It was not given a name like that."
  fi
  if [[ $WRAPPER_RPC_GIVEN -eq 1 ]]; then
    [[ $WRAPPER_ASKED -eq 1 && $WRAPPER_NAME_GIVEN -eq 1 ]] \
      || die "--node-wrapper-rpc names a docker node's admin RPC, so it needs --node-wrapper <container> beside it. A native node's comes from its own config."
    WRAPPER_RPC="$(wrapper_rpc_url "$WRAPPER_RPC")" \
      || die "--node-wrapper-rpc takes a port from 1 to 65535, or an http URL to 127.0.0.1, localhost or [::1] with a port and nothing else."
  fi
}

run_node_wrapper_installer() {
  local what rc=0
  local -a wargs=()
  if [[ $WRAPPER_NATIVE_ASKED -eq 1 ]]; then
    wargs=( --native )
    [[ $WRAPPER_UNIT_GIVEN -eq 1 ]] && wargs+=( "$WRAPPER_UNIT" )
    what="the native node${WRAPPER_UNIT:+ $WRAPPER_UNIT}"
  elif [[ $WRAPPER_NAME_GIVEN -eq 1 ]]; then
    wargs=( "$WRAPPER_NAME" )
    [[ $WRAPPER_RPC_GIVEN -eq 1 ]] && wargs+=( "$WRAPPER_RPC" )
    what="the container $WRAPPER_NAME"
  else
    what="the node this host runs"
  fi

  step "configuring the privilege wrapper for ${what}"
  already_installed \
    || die "Aperire One is not installed on this host, so there is no wrapper to configure. Install it first: curl -fsSL https://get.aperire.one | bash"
  [[ -d "$DIR" && -r "$DIR" ]] \
    || die "the checkout at $DIR is not readable by $OP_USER, so there is nothing to configure the wrapper from. Pass --dir if it lives somewhere else."
  looks_like_a_checkout "$DIR" \
    || die "$DIR does not look like an Aperire checkout (no install.sh there). Pass --dir if it lives somewhere else."
  [[ -f "$DIR/scripts/install-node-wrapper.sh" ]] \
    || die "$DIR/scripts/install-node-wrapper.sh is missing from this checkout, so this install predates the wrapper. Update it first: curl -fsSL https://get.aperire.one | bash -s -- --update"
  # An instance is a second Advisor on this host, and its unit is how this tells
  # one that exists from a name nobody installed: configuring a wrapper for the
  # second would write a configuration nothing reads and report success.
  local units
  units="$(installed_units | awk '{print $1}')"
  if [[ -n "$WRAPPER_INSTANCE" ]] \
     && ! grep -qxF "aperire-advisord-${WRAPPER_INSTANCE}.service" <<<"$units"; then
    die "there is no Advisor instance '$WRAPPER_INSTANCE' on this host (no aperire-advisord-${WRAPPER_INSTANCE}.service), so there is no wrapper of that name to configure. Leave --instance off for the default one."
  fi
  ensure_sudo
  info "root runs the release's checked copy of the installer, not the one in $DIR"
  stage_release_for_root || refuse_unstaged_release
  # The refusal file the staged installers write to, so a root copy the
  # installer refuses fails this run rather than reading as one more line.
  local -a renv=()
  [[ -n "$RD_REFUSED_FILE" ]] && renv+=( "RD_REFUSED_LOG=$RD_REFUSED_FILE" )
  run_root env APERIRE_INSTALL_TREE="$DIR" APERIRE_INSTANCE="$WRAPPER_INSTANCE" ${renv[@]+"${renv[@]}"} \
    bash "$RUN_TREE/scripts/install-node-wrapper.sh" ${wargs[@]+"${wargs[@]}"} < /dev/null || rc=$?
  collect_installer_refusals
  [[ ${#ROOT_COPY_REFUSED[@]} -eq 0 ]] || report_refused_root_copies
  if [[ $rc -eq 0 ]]; then
    ok "the wrapper is configured for ${what}${WRAPPER_INSTANCE:+ (instance $WRAPPER_INSTANCE)}"
  else
    warn "the wrapper installer exited $rc, so the wrapper may still be unconfigured. The lines above say why."
  fi
  exit "$rc"
}

# -- --refresh-node-key: this host's own node key, through the bootstrap (#935)
#
# The sealer's installer takes a flag and, with --node-key, an operator-typed
# value, and root may not run it out of the tree: `sudo bash <tree>/scripts/
# install-model-key-sealer.sh --refresh-node-key` is the same act as the
# wrapper hint above (#812, #929). So the bootstrap holds the value to the
# key's own shape before any root call, stages the release, and runs the
# checked copy.
node_key_ok() { local LC_ALL=C; [[ "$1" =~ ^n[1-9A-HJ-NP-Za-km-z]{20,60}$ ]]; }

validate_refresh_node_key_flags() {
  [[ $REFRESH_NODE_KEY_ASKED -eq 1 ]] \
    || die "--node-key states the key --refresh-node-key stamps, so it goes beside it. Alone it says nothing about what to do."
  [[ $WRAPPER_ASKED -eq 0 && $WRAPPER_NATIVE_ASKED -eq 0 && $WRAPPER_RPC_GIVEN -eq 0 ]] \
    || die "--refresh-node-key and the --node-wrapper flags are two different jobs. Run them one at a time."
  # --instance names the node to ask on a host that runs one as a named
  # instance (#949), held to the rule the wrapper's --instance is. Only the
  # flag counts here: an APERIRE_INSTANCE the login still exports is not this
  # run's answer, so it is neither checked nor used.
  if [[ $WRAPPER_INSTANCE_GIVEN -eq 1 ]]; then
    wrapper_instance_ok "$WRAPPER_INSTANCE" \
      || die "--instance must match [a-z0-9][a-z0-9-]{0,30}, the rule the Advisor's instance names follow."
  fi
  [[ $UPDATE -eq 0 && $UPDATE_FORCE -eq 0 && $RESTART_ASK -eq 1 ]] \
    || die "--refresh-node-key stamps the node's key on an installed host and --update moves it to a new release. Run them one at a time."
  [[ $CHECK_ONLY -eq 0 && $NODE_FIRST -eq 0 ]] \
    || die "--refresh-node-key works on an installed host, so it does not go with --check or --node. Run them one at a time."
  [[ -z "$FLEET_AGGREGATOR" && -z "$FLEET_LABEL" && $FLEET_CODE_GIVEN -eq 0 ]] \
    || die "--refresh-node-key does not join a fleet. Pair on its own: curl -fsSL https://get.aperire.one | bash -s -- --fleet-aggregator <url> --code -"
  [[ -z "$ROLE" && $PORT_GIVEN -eq 0 && $REF_GIVEN -eq 0 && $ASSUME_YES -eq 0 ]] \
    || die "--refresh-node-key takes no --role, --port, --ref or --yes: it installs nothing and asks nothing. Only --dir (where the release lives) goes beside it."
  [[ $SOURCE_FLAGGED -eq 0 ]] \
    || die "--refresh-node-key fetches nothing, so --source and --sha256 have nothing to act on."
  if [[ $NODE_KEY_GIVEN -eq 1 ]]; then
    node_key_ok "$NODE_KEY_VALUE" \
      || die "--node-key takes this node's pubkey_node as its own server_info reports it: base58, starting with n, 21 to 61 characters. It was not given a key like that."
  fi
}

run_node_key_refresh() {
  local rc=0
  local -a kargs=( --refresh-node-key )
  [[ $NODE_KEY_GIVEN -eq 1 ]] && kargs+=( --node-key "$NODE_KEY_VALUE" )

  step "stamping this host's own node key"
  already_installed \
    || die "Aperire One is not installed on this host, so there is no sealer to stamp a key for. Install it first: curl -fsSL https://get.aperire.one | bash"
  [[ -d "$DIR" && -r "$DIR" ]] \
    || die "the checkout at $DIR is not readable by $OP_USER, so there is nothing to stamp the key from. Pass --dir if it lives somewhere else."
  looks_like_a_checkout "$DIR" \
    || die "$DIR does not look like an Aperire checkout (no install.sh there). Pass --dir if it lives somewhere else."
  [[ -f "$DIR/scripts/install-model-key-sealer.sh" ]] \
    || die "$DIR/scripts/install-model-key-sealer.sh is missing from this checkout, so this install predates the sealer. Update it first: curl -fsSL https://get.aperire.one | bash -s -- --update"
  ensure_sudo
  info "root runs the release's checked copy of the sealer's installer, not the one in $DIR"
  stage_release_for_root || refuse_unstaged_release
  local -a renv=()
  [[ -n "$RD_REFUSED_FILE" ]] && renv+=( "RD_REFUSED_LOG=$RD_REFUSED_FILE" )
  # The instance only from an explicit --instance, and always passed, empty
  # when there was none (#949). Never from the environment: curl | bash keeps
  # the login's exports, so a stale APERIRE_INSTANCE would pick that
  # instance's node to stamp, and sudo's env reset would drop a real one.
  local stamp_instance=""
  [[ $WRAPPER_INSTANCE_GIVEN -eq 1 ]] && stamp_instance="$WRAPPER_INSTANCE"
  run_root env APERIRE_INSTALL_TREE="$DIR" APERIRE_INSTANCE="$stamp_instance" ${renv[@]+"${renv[@]}"} \
    bash "$RUN_TREE/scripts/install-model-key-sealer.sh" "${kargs[@]}" < /dev/null || rc=$?
  collect_installer_refusals
  [[ ${#ROOT_COPY_REFUSED[@]} -eq 0 ]] || report_refused_root_copies
  if [[ $rc -eq 0 ]]; then
    ok "this host's own node key is stamped"
  else
    warn "the sealer's installer exited $rc, so the node key may not be stamped. The lines above say why."
  fi
  exit "$rc"
}

# -- --backup and --restore: the host's operator state, through the bootstrap (#941)
#
# aperire-backup.sh and aperire-restore.sh read and write /etc/aperire, the
# Advisor's state and the dashboard's database, so they run as root, and
# `sudo bash <tree>/scripts/aperire-restore.sh` has root run a checkout the
# login can change, together with the state helper it plants every file with.
# So the bootstrap takes the program's arguments, holds each one to a whitelist
# before any root call, stages the release (every file under scripts/ read once
# and checked against root's record) and runs the checked copy. That copy loads
# its libraries and its state helper from beside itself and acts on the install
# it is told about with APERIRE_INSTALL_TREE.
#
# A path is absolute and spelled from a short set of characters, with no . or
# .. part: it is handed on as one word and the programs quote it, but they also
# build a shell command with it (the backup's read-back as the operator), and a
# quote or a space is how that one would go wrong. LC_ALL=C, because a range
# like [a-z] follows the locale and under UTF-8 matches letters outside ASCII.
br_path_ok() { # $1 = a path argument
  local LC_ALL=C v="$1" part
  local -a parts=()
  [[ "$v" =~ ^/[A-Za-z0-9_.@+,:=/-]+$ ]] || return 1
  v="${v%/}"
  IFS=/ read -r -a parts <<<"${v#/}"
  for part in "${parts[@]}"; do
    [[ -n "$part" && "$part" != . && "$part" != .. ]] || return 1
  done
  return 0
}
# Never credcheck: aperire-advisord-credcheck is the recovery unit's own name,
# the rule advisor-owner-lib.sh holds an instance to (#1206 review).
br_instance_ok() { local LC_ALL=C; [[ "$1" =~ ^[a-z0-9][a-z0-9-]{0,30}$ && "$1" != credcheck && "$1" != credcheck-* ]]; }

validate_backup_restore_flags() {
  local verb="$BR_VERB" arg name val inline i=0 key
  local -A seen=()
  local -a a=()
  [[ ${#BR_ARGS[@]} -eq 0 ]] || a=( "${BR_ARGS[@]}" )

  [[ $UPDATE -eq 0 && $UPDATE_FORCE -eq 0 && $RESTART_ASK -eq 1 ]] \
    || die "--$verb works on an installed host and --update moves it to a new release. Run them one at a time."
  [[ $CHECK_ONLY -eq 0 && $NODE_FIRST -eq 0 ]] \
    || die "--$verb works on an installed host, so it does not go with --check or --node. Run them one at a time."
  [[ -z "$FLEET_AGGREGATOR" && -z "$FLEET_LABEL" && $FLEET_CODE_GIVEN -eq 0 ]] \
    || die "--$verb does not join a fleet. Pair on its own: curl -fsSL https://get.aperire.one | bash -s -- --fleet-aggregator <url> --code -"
  [[ $WRAPPER_ASKED -eq 0 && $WRAPPER_NATIVE_ASKED -eq 0 && $WRAPPER_RPC_GIVEN -eq 0 && $WRAPPER_INSTANCE_GIVEN -eq 0 \
     && $REFRESH_NODE_KEY_ASKED -eq 0 && $NODE_KEY_GIVEN -eq 0 ]] \
    || die "--$verb and the --node-wrapper or --refresh-node-key flags are different jobs. Run them one at a time."
  [[ -z "$ROLE" && $PORT_GIVEN -eq 0 && $REF_GIVEN -eq 0 && $ASSUME_YES -eq 0 ]] \
    || die "--$verb takes no --role, --port or --ref, and a --yes before it is not the one it asks for: put --yes after --$verb. Only --dir (where the release lives) goes before it."
  [[ $SOURCE_FLAGGED -eq 0 ]] \
    || die "--$verb fetches nothing, so --source and --sha256 have nothing to act on."

  BR_PASS=()
  while [[ $i -lt ${#a[@]} ]]; do
    arg="${a[$i]}"; i=$((i + 1))
    name="$arg"; val=""; inline=0
    if [[ "$arg" == --*=* ]]; then name="${arg%%=*}"; val="${arg#*=}"; inline=1; fi
    case "$name" in
      --to|--from|--db-path|--instance|--dir)
        if [[ $inline -eq 0 ]]; then
          [[ $i -lt ${#a[@]} ]] || die "$name needs a value after it."
          val="${a[$i]}"; i=$((i + 1))
        fi ;;
      --yes|-y|--overwrite|--dry-run|--replace-trust-pin)
        [[ $inline -eq 0 ]] || die "$name takes no value."
        ;;
      *) die "unknown argument after --$verb: $arg. $(br_flags_for "$verb")" ;;
    esac
    key="$name"; [[ "$key" == -y ]] && key=--yes
    case "$verb:$key" in
      backup:--to|backup:--instance|backup:--yes|backup:--dry-run) ;;
      restore:--from|restore:--instance|restore:--yes|restore:--overwrite|restore:--dry-run|restore:--db-path|restore:--replace-trust-pin) ;;
      *:--dir) ;;
      *) die "$name is not an argument of --$verb. $(br_flags_for "$verb")" ;;
    esac
    [[ -z "${seen[$key]:-}" ]] || die "$key was given twice."
    seen[$key]=1
    case "$key" in
      --to|--from|--db-path|--dir)
        br_path_ok "$val" \
          || die "$name takes an absolute path of letters, digits and _ . @ + , : = - with no . or .. part, and no space or quote. It was not given one like that." ;;
      --instance)
        br_instance_ok "$val" \
          || die "--instance must match [a-z0-9][a-z0-9-]{0,30}, the rule the Advisor's instance names follow." ;;
    esac
    case "$key" in
      --dir) DIR="$val" ;;
      --yes|--overwrite|--dry-run|--replace-trust-pin) BR_PASS+=( "$key" ) ;;
      *) BR_PASS+=( "$key" "$val" ) ;;
    esac
  done
  if [[ "$verb" == restore ]]; then
    [[ -n "${seen[--from]:-}" ]] \
      || die "--restore needs --from <set>, the directory a backup wrote."
  fi
  # --dir before the verb was taken without a look in the main loop. It is
  # judged here for the same reason the rest are: it reaches root as a path.
  br_path_ok "$DIR" \
    || die "the install's directory ($DIR) is not an absolute path of letters, digits and _ . @ + , : = - with no . or .. part. Pass --dir with one that is."
}

br_flags_for() { # $1 = backup or restore
  if [[ "$1" == backup ]]; then
    printf 'It takes --to <dir>, --instance <name>, --yes and --dry-run.'
  else
    printf 'It takes --from <set>, --instance <name>, --yes, --overwrite, --dry-run, --db-path <file> and --replace-trust-pin.'
  fi
}

run_backup_restore() {
  local verb="$BR_VERB" prog rc=0 did
  case "$verb" in
    backup)  prog=aperire-backup.sh;  did="backed up"; step "backing up this host" ;;
    restore) prog=aperire-restore.sh; did="restored";  step "restoring this host from the set" ;;
  esac
  already_installed \
    || die "Aperire One is not installed on this host, so there is nothing to $verb. Install it first: curl -fsSL https://get.aperire.one | bash"
  [[ -d "$DIR" && -r "$DIR" ]] \
    || die "the checkout at $DIR is not readable by $OP_USER, so there is nothing to $verb from. Pass --dir if it lives somewhere else."
  looks_like_a_checkout "$DIR" \
    || die "$DIR does not look like an Aperire checkout (no install.sh there). Pass --dir if it lives somewhere else."
  [[ -f "$DIR/scripts/$prog" ]] \
    || die "$DIR/scripts/$prog is missing from this checkout, so this install predates it. Update it first: curl -fsSL https://get.aperire.one | bash -s -- --update"
  # A program from before staged runs works out its install from where it
  # sits, so the copy root stages would take the staging directory for the
  # install: a backup of nothing, or a restore that refuses with the wrong
  # reason. The checkout's file is only read here, for the name it carries.
  grep -q 'APERIRE_INSTALL_TREE' "$DIR/scripts/$prog" 2>/dev/null \
    || die "$DIR/scripts/$prog predates staged runs: it finds its install from where it sits, so a copy root checked and ran from elsewhere would take that place for the install. Update the install first, which brings it up to date: curl -fsSL https://get.aperire.one | bash -s -- --update"
  ensure_sudo
  info "root runs the release's checked copy of $prog, not the one in $DIR"
  STAGE_REFUSED_DID="$did"
  stage_release_for_root || refuse_unstaged_release
  # The check above read the checkout's file; root runs the staged one, a
  # separate read. A file swapped between the two puts an older program in the
  # stage, one that takes the stage for the install, so the staged copy is the
  # one judged (#941 review, L1).
  grep -q 'APERIRE_INSTALL_TREE' "$RUN_TREE/scripts/$prog" 2>/dev/null \
    || die "the $prog root staged out of $DIR predates staged runs (it is older than the one that was read first), so it was not run. Nothing was ${did}. Update the install first, which brings it up to date: curl -fsSL https://get.aperire.one | bash -s -- --update"
  # Its questions (the backup's "Proceed?", the restore's overwrite prompt)
  # are asked on this terminal when there is one. With none, stdin is closed
  # so the program says "pass --yes" rather than waiting on a pipe this run's
  # own script may still be arriving on.
  if [[ -t 0 ]]; then
    run_root env APERIRE_INSTALL_TREE="$DIR" \
      bash "$RUN_TREE/scripts/$prog" ${BR_PASS[@]+"${BR_PASS[@]}"} || rc=$?
  else
    run_root env APERIRE_INSTALL_TREE="$DIR" \
      bash "$RUN_TREE/scripts/$prog" ${BR_PASS[@]+"${BR_PASS[@]}"} < /dev/null || rc=$?
  fi
  if [[ $rc -ne 0 ]]; then
    warn "$prog exited $rc. The lines above say why."
  fi
  exit "$rc"
}

# -- --run: one root step of the release, with its arguments (#929, #955)
#
# Every root step an operator is told to type outside an install or an update
# (a grant, the sealer's --arm, the account move, the node config fix, the
# menu's root entries) used to be `sudo bash <tree>/scripts/<program> ...`,
# which has root run a file the login that owns the tree can change (ADR 0024,
# #812). This is the one form for all of them, the way --node-wrapper, --backup
# and --restore already go: the bootstrap takes the step's name and its
# arguments, holds each to a whitelist before any root call, stages the
# release (every file under scripts/ read once and checked against root's
# record) and runs the checked copy with the install named to it.
#
#   curl -fsSL https://get.aperire.one | bash -s -- --run <step> [its arguments]
#
# Each step is "program|tree|arguments". tree is 1 when the program finds the
# install from APERIRE_INSTALL_TREE, which a staged copy has to: one from
# before that would take the staging directory for the install, so its copy
# is refused rather than run. An argument is NAME:TYPE, passed on as itself;
# NAME:TYPE>VAR reaches the program as that environment variable instead
# (sudo's env reset drops one the operator set, so here it is a flag); and
# NAME:TYPE@ is handed on as a bare value, in the order the arguments are
# listed. The names are the steps' own, without .sh, so no text that offers one
# names a file in the tree.
root_step_spec() { # $1 = a step
  case "$1" in
    fleet-broker-grant)   echo 'install-fleet-broker-grant.sh|1|--refresh-nodes:flag --new-fleet-keys:flag --remove:flag' ;;
    model-key-sealer)     echo 'install-model-key-sealer.sh|1|--arm:flag --remove:flag --trust-arm-key:armkey --node-key:nodekey' ;;
    advisor-account)      echo 'install-advisor-account.sh|1|--instance:instance>APERIRE_INSTANCE --account:account>APERIRE_ACCOUNT --hand-trees-back:flag' ;;
    trust-sync-grant)     echo 'install-trust-sync-grant.sh|1|--remove:flag --if-stale:flag' ;;
    fleet-trust-split)    echo 'fleet-trust-split.sh|1|--dry-run:flag' ;;
    update-grant)         echo 'install-update-grant.sh|1|--remove:flag --program-only:flag' ;;
    advisor-stack)        echo 'install-advisor-stack.sh|1|--port:port --instance:instance --report:path --yes:flag --shared-account:flag --grants-only:flag' ;;
    dashboard-service)    echo 'install-aperire-service.sh|1|--instance:instance>APERIRE_INSTANCE' ;;
    relay)                echo 'install-aperire-relay.sh|1|--instance:instance>APERIRE_INSTANCE --binary:path@' ;;
    prepare-host)         echo 'prepare-host.sh|1|--with-advisor:flag>APERIRE_WITH_ADVISOR --role:role>APERIRE_ROLE' ;;
    node)                 echo 'install-aperire-node.sh|1|--adopt:flag --native:flag --move-source:flag --name:name --unit:unit --role:noderole --image-tag:imagetag --yes:flag' ;;
    harden-advisord)      echo 'harden-advisord.sh|1|' ;;
    reseal-model-key)     echo 'reseal-model-key.sh|1|--instance:instance>APERIRE_INSTANCE' ;;
    node-config-exposure) echo 'close-node-config-exposure.sh|0|--apply:flag --account:account>APERIRE_ACCOUNT --instance:instance>APERIRE_INSTANCE' ;;
    migrate-node)         echo 'migrate-node-nonroot.sh|0|--apply:flag --hand-store-back:flag --rotation-checked-by-hand:flag' ;;
    advisory-delete)      echo 'enable-advisory-delete.sh|0|--config:path@' ;;
    rotation-timer)       echo 'install-can-delete-timer.sh|1|--service:name>APERIRE_NODE_SERVICE --admin-rpc:rpcurl>APERIRE_NODE_ADMIN_RPC --config:path>APERIRE_NODE_CONFIG --kind:nodekind>APERIRE_NODE_KIND' ;;
    tunnel)               echo 'setup-aperire-tunnel.sh|0|' ;;
    relay-colocated)      echo 'enable-relay-colocated.sh|0|--unit:dashunit@ --port:port@ --binary:path@' ;;
    peer-token)           echo 'place-peer-token.sh|1|--label:peerlabel' ;;
    *) return 1 ;;
  esac
}
root_step_names() {
  printf '%s' 'fleet-broker-grant, model-key-sealer, advisor-account, trust-sync-grant, fleet-trust-split, update-grant, advisor-stack, dashboard-service, relay, prepare-host, node, harden-advisord, reseal-model-key, node-config-exposure, migrate-node, advisory-delete, rotation-timer, tunnel, relay-colocated, peer-token'
}

# One value against its type. LC_ALL=C, because a range like [a-z] follows the
# locale and under UTF-8 matches letters outside ASCII.
root_step_value_ok() { # $1 = type, $2 = value
  local LC_ALL=C v="$2"
  case "$1" in
    instance) br_instance_ok "$v" ;;
    account)  [[ "$v" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] ;;
    unit)     wrapper_unit_ok "$v" ;;
    dashunit) [[ "$v" =~ ^aperire-(server|read)(-[a-z0-9][a-z0-9-]{0,30})?$ ]] ;;
    name)     wrapper_name_ok "$v" ;;
    path)     br_path_ok "$v" ;;
    port)     [[ "$v" =~ ^[0-9]{1,5}$ ]] && (( 10#$v >= 1 && 10#$v <= 65535 )) ;;
    armkey)   [[ "$v" =~ ^[A-Za-z0-9+/]{40,120}={0,2}$ ]] || br_path_ok "$v" ;;
    nodekey)  node_key_ok "$v" ;;
    role)     [[ "$v" =~ ^(co-located|dashboard|validator|relay|cli-only)$ ]] ;;
    noderole) [[ "$v" =~ ^(stock|validator)$ ]] ;;
    imagetag) [[ "$v" =~ ^[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}([-+][A-Za-z0-9.]{1,32})?$ ]] ;;
    rpcurl)   [[ "$v" =~ ^http://127\.0\.0\.1:([0-9]{1,5})$ ]] && (( 10#${BASH_REMATCH[1]} >= 1 && 10#${BASH_REMATCH[1]} <= 65535 )) ;;
    nodekind) [[ "$v" =~ ^(container|native)$ ]] ;;
    peerlabel) [[ "$v" =~ ^[a-z0-9][a-z0-9-]{0,31}$ ]] ;;
    *) return 1 ;;
  esac
}
root_step_type_says() { # $1 = type
  case "$1" in
    instance) printf 'an instance name matching [a-z0-9][a-z0-9-]{0,30}, not credcheck' ;;
    account)  printf 'an account name matching [a-z_][a-z0-9_-]{0,31}' ;;
    unit)     printf 'a systemd unit name: letters, digits, dot, dash, underscore and @' ;;
    dashunit) printf 'a dashboard unit: aperire-server or aperire-read, with an instance suffix or none' ;;
    name)     printf 'a name of letters, digits, dot, dash and underscore, starting with a letter or digit' ;;
    path)     printf 'an absolute path of letters, digits and _ . @ + , : = - with no . or .. part, and no space or quote' ;;
    port)     printf 'a port from 1 to 65535' ;;
    armkey)   printf 'the base64 public key, or an absolute path to a PEM public key' ;;
    nodekey)  printf "this node's pubkey_node: base58, starting with n" ;;
    role)     printf 'one of co-located, dashboard, validator, relay, cli-only' ;;
    noderole) printf 'stock or validator' ;;
    imagetag) printf 'a release version like 3.3.0, with an optional -suffix' ;;
    rpcurl)   printf 'a loopback URL like http://127.0.0.1:5005' ;;
    nodekind) printf 'container or native' ;;
    peerlabel) printf 'a node label: up to 32 of a-z, 0-9 and -, starting with a letter or digit' ;;
  esac
}

RS_ASKED=0
RS_STEP=""
RS_ARGS=()
RS_PASS=()
RS_POS=()
RS_ENV=()
validate_root_step_flags() {
  local step="$RS_STEP" spec args arg name val inline i=0 entry ename etype evar epos found
  local -A seen=()
  local -a a=() specs=()
  [[ ${#RS_ARGS[@]} -eq 0 ]] || a=( "${RS_ARGS[@]}" )

  [[ -n "$step" ]] || die "--run takes the name of a step. The steps are: $(root_step_names)."
  spec="$(root_step_spec "$step")" \
    || die "--run does not know a step called '$step'. The steps are: $(root_step_names)."
  [[ $UPDATE -eq 0 && $UPDATE_FORCE -eq 0 && $RESTART_ASK -eq 1 ]] \
    || die "--run takes one step on an installed host and --update moves it to a new release. Run them one at a time."
  [[ $CHECK_ONLY -eq 0 && $NODE_FIRST -eq 0 ]] \
    || die "--run works on an installed host, so it does not go with --check or --node. Run them one at a time."
  [[ -z "$FLEET_AGGREGATOR" && -z "$FLEET_LABEL" && $FLEET_CODE_GIVEN -eq 0 ]] \
    || die "--run does not join a fleet. Pair on its own: curl -fsSL https://get.aperire.one | bash -s -- --fleet-aggregator <url> --code -"
  [[ $WRAPPER_ASKED -eq 0 && $WRAPPER_NATIVE_ASKED -eq 0 && $WRAPPER_RPC_GIVEN -eq 0 && $WRAPPER_INSTANCE_GIVEN -eq 0 \
     && $REFRESH_NODE_KEY_ASKED -eq 0 && $NODE_KEY_GIVEN -eq 0 && -z "$BR_VERB" ]] \
    || die "--run and the --node-wrapper, --refresh-node-key, --backup or --restore flags are different jobs. Run them one at a time."
  [[ -z "$ROLE" && $PORT_GIVEN -eq 0 && $REF_GIVEN -eq 0 && $ASSUME_YES -eq 0 ]] \
    || die "--run takes no --role, --port, --ref or --yes before it: everything after the step's name is that step's own. Only --dir (where the install lives) goes before it."
  [[ $SOURCE_FLAGGED -eq 0 ]] \
    || die "--run fetches nothing, so --source and --sha256 have nothing to act on."

  args="${spec#*|}"; args="${args#*|}"
  [[ -z "$args" ]] || read -r -a specs <<<"$args"
  RS_PASS=(); RS_POS=(); RS_ENV=()
  while [[ $i -lt ${#a[@]} ]]; do
    arg="${a[$i]}"; i=$((i + 1))
    name="$arg"; val=""; inline=0
    if [[ "$arg" == --*=* ]]; then name="${arg%%=*}"; val="${arg#*=}"; inline=1; fi
    if [[ "$name" == --dir ]]; then
      if [[ $inline -eq 0 ]]; then
        [[ $i -lt ${#a[@]} ]] || die "--dir needs a value after it."
        val="${a[$i]}"; i=$((i + 1))
      fi
      [[ -z "${seen[--dir]:-}" ]] || die "--dir was given twice."
      seen[--dir]=1
      br_path_ok "$val" || die "--dir takes $(root_step_type_says path). It was not given one like that."
      DIR="$val"
      continue
    fi
    found=""
    for entry in ${specs[@]+"${specs[@]}"}; do
      [[ "${entry%%:*}" == "$name" ]] && { found="$entry"; break; }
    done
    [[ -n "$found" ]] || die "$arg is not an argument of --run $step. $(root_step_args_say "$step")"
    [[ -z "${seen[$name]:-}" ]] || die "$name was given twice."
    seen[$name]=1
    ename="${found%%:*}"; etype="${found#*:}"; evar=""; epos=0
    if [[ "$etype" == *'>'* ]]; then evar="${etype#*>}"; etype="${etype%%>*}"; fi
    if [[ "$etype" == *@ ]]; then epos=1; etype="${etype%@}"; fi
    if [[ "$etype" == flag ]]; then
      [[ $inline -eq 0 ]] || die "$name takes no value."
      if [[ -n "$evar" ]]; then RS_ENV+=( "$evar=1" ); else RS_PASS+=( "$ename" ); fi
      continue
    fi
    if [[ $inline -eq 0 ]]; then
      [[ $i -lt ${#a[@]} ]] || die "$name needs a value after it."
      val="${a[$i]}"; i=$((i + 1))
    fi
    root_step_value_ok "$etype" "$val" \
      || die "$name takes $(root_step_type_says "$etype"). It was not given one like that."
    if [[ -n "$evar" ]]; then RS_ENV+=( "$evar=$val" )
    elif [[ $epos -eq 1 ]]; then :
    else RS_PASS+=( "$ename" "$val" ); fi
  done
  # Bare values go on in the order the step lists them, so a program that
  # takes positions gets them in its own order whatever order they came in.
  local -a want=()
  for entry in ${specs[@]+"${specs[@]}"}; do
    [[ "$entry" == *@ ]] || continue
    ename="${entry%%:*}"
    [[ -n "${seen[$ename]:-}" ]] || { want+=( "$ename" ); continue; }
    for ((i = 0; i < ${#a[@]}; i++)); do
      if [[ "${a[$i]}" == "$ename" ]]; then RS_POS+=( "${a[$((i + 1))]}" ); break; fi
      if [[ "${a[$i]}" == "$ename="* ]]; then RS_POS+=( "${a[$i]#*=}" ); break; fi
    done
  done
  if [[ "$step" == relay-colocated && ${#want[@]} -gt 0 ]]; then
    die "--run relay-colocated needs ${want[*]}: the dashboard unit, its port and the relay program. Nothing is guessed."
  fi
  if [[ "$step" == peer-token ]]; then
    [[ -n "${seen[--label]:-}" ]] || die "--run peer-token needs --label, the node whose token this is."
    [[ ! -t 0 ]] || die "--run peer-token reads the peer's token on its standard input, and this is a terminal. aperire-fleet-add.sh --place-token hands it over."
  fi
  br_path_ok "$DIR" \
    || die "the install's directory ($DIR) is not an absolute path of letters, digits and _ . @ + , : = - with no . or .. part. Pass --dir with one that is."
}
root_step_args_say() { # $1 = a step
  local spec args
  spec="$(root_step_spec "$1")" || return 0
  args="${spec#*|}"; args="${args#*|}"
  if [[ -z "$args" ]]; then
    printf 'It takes no arguments, only --dir.'
  else
    printf 'It takes %s, and --dir.' "$(sed -E 's/:[a-z]+(>[A-Z_]+)?@?//g; s/ /, /g' <<<"$args")"
  fi
}

run_root_step() {
  local spec prog tree rc=0
  spec="$(root_step_spec "$RS_STEP")"
  prog="${spec%%|*}"; tree="${spec#*|}"; tree="${tree%%|*}"
  # peer-token is the one step that is handed something on standard input: the
  # peer's token, opened by the caller, never an argument (#1144). Set it aside
  # on descriptor 3 now, so nothing between here and the root call can read
  # it, and give it back to the program alone.
  if [[ "$RS_STEP" == peer-token ]]; then
    exec 3<&0 0< /dev/null
  fi
  step "running the release's checked copy of $prog"
  # The steps that are pieces of an install run on a host that has none yet,
  # the way the menu's install entries always did: host preparation (step
  # zero, and the line install.sh prints when it fails), the dashboard
  # service, the relay, the Advisor stack and the tunnel. Every other step
  # acts on something an install put here.
  case "$RS_STEP" in
    prepare-host|dashboard-service|relay|advisor-stack|tunnel) ;;
    *) already_installed \
         || die "Aperire One is not installed on this host, so there is no install for $prog to act on. Install it first: curl -fsSL https://get.aperire.one | bash" ;;
  esac
  [[ -d "$DIR" && -r "$DIR" ]] \
    || die "the checkout at $DIR is not readable by $OP_USER, so there is nothing to run $prog from. Pass --dir if it lives somewhere else."
  looks_like_a_checkout "$DIR" \
    || die "$DIR does not look like an Aperire checkout (no install.sh there). Pass --dir if it lives somewhere else."
  [[ -f "$DIR/scripts/$prog" ]] \
    || die "$DIR/scripts/$prog is missing from this checkout, so this install predates it. Update it first: curl -fsSL https://get.aperire.one | bash -s -- --update"
  ensure_sudo
  info "root runs the release's checked copy of $prog, not the one in $DIR"
  STAGE_REFUSED_DID="run"
  stage_release_for_root || refuse_unstaged_release
  # A program that finds the install from where it sits, and not from
  # APERIRE_INSTALL_TREE, would take the staging directory for the install.
  # The staged copy is the one judged: it is the one root runs.
  if [[ "$tree" == 1 ]] && ! grep -q 'APERIRE_INSTALL_TREE' "$RUN_TREE/scripts/$prog" 2>/dev/null; then
    die "the $prog root staged out of $DIR predates staged runs: it finds its install from where it sits, so a copy root checked and ran from elsewhere would take that place for the install. Nothing was run. Update the install first, which brings it up to date: curl -fsSL https://get.aperire.one | bash -s -- --update"
  fi
  local -a renv=( "APERIRE_INSTALL_TREE=$DIR" )
  [[ -n "$RD_REFUSED_FILE" ]] && renv+=( "RD_REFUSED_LOG=$RD_REFUSED_FILE" )
  [[ ${#RS_ENV[@]} -eq 0 ]] || renv+=( "${RS_ENV[@]}" )
  # Host preparation builds the relay and the Advisor, and stamps what it
  # builds with APERIRE_BUILD_COMMIT (#266). An install or an update passes the
  # release it is putting down. A --run puts nothing down, so the stamp is the
  # commit of the release already on this host, read off its own record
  # ($DIR/.release, what the last install or update wrote), not off this
  # script's baked-in release, which can be newer than the tree on disk, and
  # not off the caller's environment, which sudo would drop anyway. With none
  # sent, prepare-host.sh stamps "dev" and leaves a stamped binary alone
  # (#1142). Not the checkout's own HEAD on a clone install: the dashboard's
  # component_drift compares a binary's stamp with this same record, so a stamp
  # off a tree that moved since the last install would read as drifted.
  # The value goes into a go build line, so it is held to the shape
  # of a commit here too; anything else sends nothing.
  if [[ "$RS_STEP" == prepare-host ]]; then
    local rel_commit
    rel_commit="$(release_field commit)"
    [[ "$rel_commit" =~ ^[0-9a-f]{7,40}$ ]] && renv+=( "APERIRE_BUILD_COMMIT=$rel_commit" )
  fi
  local -a pos=()
  [[ ${#RS_POS[@]} -eq 0 ]] || pos=( "${RS_POS[@]}" )
  # The co-located relay's enabler runs the relay installer it is handed: the
  # staged one, never the tree's.
  [[ "$RS_STEP" == relay-colocated ]] && pos+=( "$RUN_TREE/scripts/install-aperire-relay.sh" )
  # Its questions are asked on this terminal when there is one. With none,
  # stdin is closed so the program says what it needs rather than waiting on
  # a pipe this run's own script may still be arriving on.
  if [[ "$RS_STEP" == peer-token ]]; then
    run_root env "${renv[@]}" bash "$RUN_TREE/scripts/$prog" ${RS_PASS[@]+"${RS_PASS[@]}"} <&3 || rc=$?
  elif [[ -t 0 ]]; then
    run_root env "${renv[@]}" bash "$RUN_TREE/scripts/$prog" ${RS_PASS[@]+"${RS_PASS[@]}"} ${pos[@]+"${pos[@]}"} || rc=$?
  else
    run_root env "${renv[@]}" bash "$RUN_TREE/scripts/$prog" ${RS_PASS[@]+"${RS_PASS[@]}"} ${pos[@]+"${pos[@]}"} < /dev/null || rc=$?
  fi
  collect_installer_refusals
  [[ ${#ROOT_COPY_REFUSED[@]} -eq 0 ]] || report_refused_root_copies
  if [[ $rc -ne 0 ]]; then
    warn "$prog exited $rc. The lines above say why."
  fi
  exit "$rc"
}

# -- main ------------------------------------------------------------
main() {
  local wrapper_val=""
  # Everything temporary this run makes, removed on the way out however the
  # run ends: the copy guard 1 exec'd into, and the archive and unpack
  # directory the fetch works in.
  trap cleanup_temporaries EXIT

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --role)      ROLE="$(flag_value "$@")"; shift 2 ;;
      --role=*)    ROLE="${1#*=}"; shift ;;
      --dir)       DIR="$(flag_value "$@")"; shift 2 ;;
      --dir=*)     DIR="${1#*=}"; shift ;;
      --ref)       SOURCE_REF="$(flag_value "$@")"; REF_GIVEN=1; shift 2 ;;
      --ref=*)     SOURCE_REF="${1#*=}"; REF_GIVEN=1; shift ;;
      --source)    SOURCE_URL="$(flag_value "$@")"; SOURCE_FLAGGED=1; shift 2 ;;
      --source=*)  SOURCE_URL="${1#*=}"; SOURCE_FLAGGED=1; shift ;;
      --sha256)    EXPECTED_SHA256="$(flag_value "$@")"; SOURCE_FLAGGED=1; shift 2 ;;
      --sha256=*)  EXPECTED_SHA256="${1#*=}"; SOURCE_FLAGGED=1; shift ;;
      --port)      PORT="$(flag_value "$@")"; PORT_GIVEN=1; shift 2 ;;
      --port=*)    PORT="${1#*=}"; PORT_GIVEN=1; shift ;;
      --check)     CHECK_ONLY=1; shift ;;
      --update)    UPDATE=1; shift ;;
      --force)     UPDATE_FORCE=1; shift ;;
      --no-restart) RESTART_ASK=0; shift ;;
      --node)      NODE_FIRST=1; shift ;;
      --fleet-aggregator)   FLEET_AGGREGATOR="$(flag_value "$@")"; shift 2 ;;
      --fleet-aggregator=*) FLEET_AGGREGATOR="${1#*=}"; shift ;;
      # --code, not --fleet-code below: this one is for a host that turns out
      # to be ALREADY installed, where offer_the_menu pairs it directly and
      # carries the code to aperire-fleet-pair.sh over its stdin, never on
      # sudo's own argv, so it never reaches /var/log/auth.log. A NOT-yet-
      # installed host still refuses it, further down, for the reason
      # --fleet-code states below: this same process's own sudo, wrapping
      # install.sh, would put it on that argv.
      --code)      FLEET_CODE="$(code_flag_value "$@")"; FLEET_CODE_GIVEN=1; shift 2 ;;
      --code=*)    FLEET_CODE="${1#*=}"; FLEET_CODE_GIVEN=1; shift ;;
      # Refused here, in the arm, and the value is never read (P3-072). This
      # layer reaches install.sh through `sudo`, and sudo writes the whole
      # command line to /var/log/auth.log, which is 0640 syslog:adm and keeps
      # it for weeks. /proc is a window of seconds; that is one of weeks, on a
      # code that is live for fifteen minutes. The flag survives on install.sh,
      # where the operator is already root and there is no sudo in the chain.
      #
      # In the ARM rather than in the validation block below, because the
      # two-word form would otherwise fall through to "unknown argument:
      # APR-..." and print the live code back in the refusal.
      --fleet-code|--fleet-code=*)
        die "--fleet-code is not a flag on this command, and that is deliberate: it reaches the installer through sudo, and sudo writes the whole command line to /var/log/auth.log, where a live code would sit for weeks readable by the adm group. Leave it out and the install asks for the code on this terminal when it gets there, which is the way the docs and the Settings page teach anyway. A box that is ALREADY built pairs on its own: curl -fsSL https://get.aperire.one | bash -s -- --fleet-aggregator <url> --code -"
        ;;
      --fleet-label)        FLEET_LABEL="$(flag_value "$@")"; shift 2 ;;
      --fleet-label=*)      FLEET_LABEL="${1#*=}"; shift ;;
      # The wrapper pass-through (#924). The two-word forms read their value
      # only when the next word is one, so a bare `--node-wrapper` detects the
      # node; the = forms always carry one, and an empty one is refused below.
      --node-wrapper)
        WRAPPER_ASKED=1
        wrapper_val="$(optional_value "$@")"
        if [[ -n "$wrapper_val" ]]; then WRAPPER_NAME="$wrapper_val"; WRAPPER_NAME_GIVEN=1; shift 2; else shift; fi ;;
      --node-wrapper=*)  WRAPPER_ASKED=1; WRAPPER_NAME="${1#*=}"; WRAPPER_NAME_GIVEN=1; shift ;;
      --node-wrapper-native)
        WRAPPER_NATIVE_ASKED=1
        wrapper_val="$(optional_value "$@")"
        if [[ -n "$wrapper_val" ]]; then WRAPPER_UNIT="$wrapper_val"; WRAPPER_UNIT_GIVEN=1; shift 2; else shift; fi ;;
      --node-wrapper-native=*) WRAPPER_NATIVE_ASKED=1; WRAPPER_UNIT="${1#*=}"; WRAPPER_UNIT_GIVEN=1; shift ;;
      --node-wrapper-rpc)      WRAPPER_RPC="$(flag_value "$@")"; WRAPPER_RPC_GIVEN=1; shift 2 ;;
      --node-wrapper-rpc=*)    WRAPPER_RPC="${1#*=}"; WRAPPER_RPC_GIVEN=1; shift ;;
      --refresh-node-key)      REFRESH_NODE_KEY_ASKED=1; shift ;;
      --node-key)              NODE_KEY_VALUE="$(flag_value "$@")"; NODE_KEY_GIVEN=1; shift 2 ;;
      --node-key=*)            NODE_KEY_VALUE="${1#*=}"; NODE_KEY_GIVEN=1; shift ;;
      --instance)              WRAPPER_INSTANCE="$(flag_value "$@")"; WRAPPER_INSTANCE_GIVEN=1; shift 2 ;;
      --instance=*)            WRAPPER_INSTANCE="${1#*=}"; WRAPPER_INSTANCE_GIVEN=1; shift ;;
      # The backup and restore pass-through (#941). Everything after the verb
      # belongs to that program and is judged by its own whitelist below, which
      # is why --yes and --instance after it are not this script's.
      --backup)    BR_VERB=backup;  BR_ARGS=( "${@:2}" ); shift $#; break ;;
      --restore)   BR_VERB=restore; BR_ARGS=( "${@:2}" ); shift $#; break ;;
      # One root step of the release (#929, #955): the step's name, then its
      # own arguments, judged by the step's whitelist below.
      --run)       RS_ASKED=1; RS_STEP="${2:-}"; RS_ARGS=( "${@:3}" ); shift $#; break ;;
      --run=*)     RS_ASKED=1; RS_STEP="${1#*=}"; RS_ARGS=( "${@:2}" ); shift $#; break ;;
      --yes|-y)    ASSUME_YES=1; shift ;;
      -h|--help)   usage; exit 0 ;;
      *)           die "unknown argument: $1 (run with --help)" ;;
    esac
  done

  # After the flags, so --help still answers. The default checkout and the
  # operator commands both live under this home, so a run that cannot name it
  # has nowhere to put either (#616).
  [[ "$OP_HOME" == /* ]] \
    || die "the home directory of ${OP_USER:-this account} could not be found: getent passwd has no entry for it${SUDO_USER:+, and under sudo \$HOME belongs to root}. There is nowhere to put the checkout, so nothing was fetched. Run this from an account with a home directory."
  [[ -n "$DIR" ]] || DIR="${OP_HOME}/aperire-one"

  if [[ -n "$ROLE" ]] && ! valid_role "$ROLE"; then
    die "invalid role '$ROLE'. One of: co-located, dashboard, relay, cli-only."
  fi
  # A port that is not a number would be passed to install.sh and then asked
  # for in a URL, and the health check would fail for a reason nothing names.
  [[ "$PORT" =~ ^[0-9]+$ && $PORT -ge 1 && $PORT -le 65535 ]] \
    || die "--port takes a number from 1 to 65535, not '$PORT'."

  # A checksum that is not a sha256 can never match one, and the refusal it
  # would produce further down would blame the download. Say it here, where
  # the mistake is.
  EXPECTED_SHA256="${EXPECTED_SHA256,,}"
  [[ -z "$EXPECTED_SHA256" || "$EXPECTED_SHA256" =~ ^[0-9a-f]{64}$ ]] \
    || die "a sha256 is 64 hex characters, and this is '$EXPECTED_SHA256'."
  if [[ -n "$EXPECTED_SHA256" ]] && ! source_is_tarball; then
    die "--sha256 has nothing to check: $SOURCE_URL is a git remote, and a clone is pinned with --ref, not with a checksum."
  fi
  if [[ -n "$EXPECTED_SHA256" ]] && ! command -v sha256sum >/dev/null 2>&1; then
    die "this host has no sha256sum, so the release could not be checked. Install coreutils, or fetch and check it by hand."
  fi
  # --ref selects a commit out of a repository. An archive is one release
  # already, so the flag labels this run and chooses nothing, which is worth
  # one line rather than a silent acceptance.
  if source_is_tarball && [[ $REF_GIVEN -eq 1 ]]; then
    info "--ref labels this run only: an archive is one release, and its checksum is what decides which one arrived."
  fi

  # ── The fleet flags ───────────────────────────────────────────────
  # Checked here, before the fetch and before anything is built. install.sh
  # makes the same refusals when it is run by hand, and this is the layer that
  # catches them an hour earlier.
  if [[ -n "$FLEET_AGGREGATOR" || -n "$FLEET_LABEL" || $FLEET_CODE_GIVEN -eq 1 ]]; then
    [[ $UPDATE -eq 0 ]] \
      || die "--update moves an installed host to this release, and a host that is already installed has already decided its fleet. Pair it on its own, on that host: curl -fsSL https://get.aperire.one | bash -s -- --fleet-aggregator <url> --code -"
    [[ $CHECK_ONLY -eq 0 ]] \
      || die "--check reports on this host and installs nothing, so there is nothing to join a fleet. Run the check, then run the install with --fleet-aggregator."
    [[ -n "$FLEET_AGGREGATOR" ]] \
      || die "--fleet-label and --code both need --fleet-aggregator. They say what to call this node and what code to spend; nothing says where to dial."
    # The role is usually detected rather than given, so this is not refused
    # here by role: install.sh refuses `validator` and `cli-only` by name, and
    # resolve_role has not run yet.
    FLEET_AGGREGATOR="${FLEET_AGGREGATOR%/}"
    fleet_origin_scheme_ok "$FLEET_AGGREGATOR" \
      || die "--fleet-aggregator must be https://, because this node's read token and its Advisor token cross on that dial. http:// is accepted only to loopback: 127.0.0.1, localhost or [::1], with an optional port and nothing else. Given: $FLEET_AGGREGATOR"
    fleet_origin_plain_ok "$FLEET_AGGREGATOR" \
      || die "--fleet-aggregator is not a plain origin (scheme, host, optional port, no path). Give https://<host>. Given: $FLEET_AGGREGATOR"
    # The whole value, not its first line (P3-074). `grep -q` exits 0 when ANY
    # line matches, so a two-line label passed here and then forged a second
    # line in the command the closing text tells the operator to copy.
    if [[ -n "$FLEET_LABEL" ]]; then
      [[ "$FLEET_LABEL" =~ ^[a-z0-9-]{1,32}$ ]] \
        || die "--fleet-label must match [a-z0-9-]{1,32}, the same rule fleet.yaml uses."
    fi
    if [[ $FLEET_CODE_GIVEN -eq 1 ]]; then
      [[ -n "$FLEET_CODE" ]] \
        || die "--code was given and carries no code. Leave the flag out and this either asks for one at the end of a fresh install, or prints the pair command for an installed host to run by hand."
      resolve_fleet_code
    fi
  fi

  # The two flags that only mean something beside --update. Refused here
  # rather than ignored: a run that was given --force and installed a fresh
  # host anyway did something other than what it was asked for.
  if [[ $UPDATE -eq 0 ]]; then
    [[ $UPDATE_FORCE -eq 0 ]] \
      || die "--force only means something with --update, which applies a release over an installed host."
    [[ $RESTART_ASK -eq 1 ]] \
      || die "--no-restart only means something with --update. A first install starts the services it installs."
  fi
  if [[ $UPDATE -eq 1 ]]; then
    # A check reports and an update changes the host, so asking for both is
    # asking for two different runs.
    [[ $CHECK_ONLY -eq 0 ]] \
      || die "--check and --update are two different runs: one reports and changes nothing, the other applies a release. Run them one at a time."
    [[ $NODE_FIRST -eq 0 ]] \
      || die "--node installs a node on a box that has none, and --update moves an installed box to a newer release. Run them one at a time."
  fi

  # ── The wrapper pass-through flags (#924) ─────────────────────────
  # Held to a whitelist here, before guard_privilege and before any sudo: a bad
  # value makes no root call at all. What passes is handed to the wrapper
  # installer as one word each, never through a shell.
  if [[ -n "$BR_VERB" ]]; then
    validate_backup_restore_flags
  fi
  if [[ $RS_ASKED -eq 1 ]]; then
    validate_root_step_flags
  fi
  if [[ $REFRESH_NODE_KEY_ASKED -eq 1 || $NODE_KEY_GIVEN -eq 1 ]]; then
    validate_refresh_node_key_flags
  fi
  # --instance beside a pair (--fleet-aggregator and --code, on an installed
  # host) names the instance to pair, not a wrapper to configure (#1278).
  # Every other use of it is still the wrapper's.
  if pair_names_instance; then
    :
  elif pair_instance_needs_code; then
    # The name is held to its rule before it is printed into a command to copy,
    # and the aggregator is not printed at all: neither has been checked yet.
    wrapper_instance_ok "$WRAPPER_INSTANCE" \
      || die "--instance must match [a-z0-9][a-z0-9-]{0,30}, the rule the Advisor's instance names follow."
    die "--instance names the dashboard to pair, and this pair has no --code. Add --code - and it asks for the code on this terminal: curl -fsSL https://get.aperire.one | bash -s -- --fleet-aggregator <url> --code -${WRAPPER_INSTANCE:+ --instance $WRAPPER_INSTANCE}"
  elif [[ $WRAPPER_ASKED -eq 1 || $WRAPPER_NATIVE_ASKED -eq 1 || $WRAPPER_RPC_GIVEN -eq 1 ]] \
     || [[ $WRAPPER_INSTANCE_GIVEN -eq 1 && $REFRESH_NODE_KEY_ASKED -eq 0 ]]; then
    validate_node_wrapper_flags
  fi

  guard_privilege
  # The distribution gate is about what the one-line install has been
  # verified on. A root step (--run) acts on the host that is already here,
  # which may have been installed by the manual path on another distribution,
  # and the operator menu reaches its root entries through it, so it is not
  # gated on the distribution (#955).
  [[ $RS_ASKED -eq 1 ]] || guard_os
  # Every branch below stages something for root, which runs in python3.
  guard_python3

  # The wrapper pass-through never returns: it configures the wrapper on an
  # installed host and exits with the installer's own status.
  if [[ $WRAPPER_ASKED -eq 1 || $WRAPPER_NATIVE_ASKED -eq 1 ]]; then
    run_node_wrapper_installer
  fi

  # The node-key pass-through (#935) never returns either.
  if [[ $REFRESH_NODE_KEY_ASKED -eq 1 ]]; then
    run_node_key_refresh
  fi

  # Nor does backup or restore (#941).
  if [[ -n "$BR_VERB" ]]; then
    run_backup_restore
  fi

  # Nor does one root step (#929, #955).
  if [[ $RS_ASKED -eq 1 ]]; then
    run_root_step
  fi

  # An update reaches neither the menu short-circuit below (it is FOR an
  # installed host) nor detection (the role is read off the units, never
  # guessed), so it branches here and never returns.
  if [[ $UPDATE -eq 1 ]]; then
    run_update
    exit 0
  fi

  # --check is a report, and it runs BEFORE the short-circuit that opens the
  # operator menu on an installed host. A check that opens a menu is not a
  # check, and an installed host is exactly where somebody asks what is
  # missing.
  if [[ $CHECK_ONLY -eq 0 ]]; then
    already_installed && offer_the_menu
  fi

  # Past this line the host is NOT installed, so --code has nothing to pair
  # yet. Named rather than dropped (P3-077): install.sh's own --fleet-code is
  # refused above for the same reason this script refuses it as a top-level
  # flag, and forwarding the value here through run_install's sudo would be
  # that same exposure by another route. The install still ends by asking for
  # a code on this terminal, same as it always has, so nothing is lost -- it
  # is asked again rather than carried.
  if [[ $FLEET_CODE_GIVEN -eq 1 ]]; then
    warn "--code pairs a host that is already installed; this one is not, so it is not used here."
    info "the install still asks for a pairing code on this terminal, at the end, the way it always has."
  fi

  resolve_role
  if [[ $NODE_FIRST -eq 1 ]]; then
    ROLE=co-located; ROLE_IS_NODELESS_GUESS=0
    ROLE_EVIDENCE="(--node: a node is installed here first, then this beside it)"
  fi
  # Read before --check takes $DIR over with a temporary one, so a check on a
  # host with a kept checkout reports that checkout rather than an empty
  # directory under /tmp.
  report_kept_artifacts
  note_kept_components
  if [[ $CHECK_ONLY -eq 1 ]]; then
    check_only_run
  fi

  confirm_plan "$ROLE_EVIDENCE"
  announce_sudo
  ensure_sudo

  step "fetching the release"
  source_is_tarball || ensure_git
  fetch_release
  keep_signed_release
  # Everything root runs out of the release from here on is a staged copy,
  # held to both checks first (#764).
  release_held_dir
  say_tolerated_tree
  stage_release_for_root || refuse_unstaged_release

  install_node_first

  if ! run_preflight; then
    cat >&2 <<EOF

${E_RED}error: this host is missing something the install needs, so nothing was installed.${E_OFF}

  The list above says what, and the command that fixes each one. The release
  is unpacked at ${DIR} and nothing else was touched; when the list is clear,
  run the check again and then the install:

      bash ${DIR}/scripts/preflight.sh --role=$(install_role_for "$ROLE")
      sudo bash ${DIR}/install.sh --role=$(install_role_for "$ROLE") --yes

EOF
    exit 1
  fi

  # After the checklist, because that is what measured the node on a run whose
  # role was named rather than detected, and before the install, because the
  # readers #437 added want the record to be there when they arrive.
  adopt_node_with_no_record

  step "installing"
  run_install
  # A reinstall over a kept tree swaps it too, and the broker's pin with it
  # (#828). No root programs are refreshed on this path, so on an aggregator
  # this usually meets the broker the last update placed.
  rerecord_broker_grant
  refresh_trust_sync_unit

  # After the install finished and before anything is claimed about it: what
  # this host is now running, in a file the dashboard can read.
  write_release_stamp
  prune_kept_trees

  verify_and_report
}

main "$@"
# --- end of get-aperire.sh ---
