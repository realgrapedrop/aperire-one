#!/usr/bin/env bash
# get-aperire-uninstall.sh - the one command that takes Aperire One off a host.
#
#   curl -fsSL https://get.aperire.one/uninstall | bash
#
# Or, when you would rather read it first (and for this one you should):
#
#   curl -fsSL https://get.aperire.one/uninstall -o get-aperire-uninstall.sh
#   less get-aperire-uninstall.sh
#   bash get-aperire-uninstall.sh
#
# It downloads nothing but the signed release.json, which says whether the
# release on offer is newer than this install, and, when it is, that
# release's uninstall.sh. There is no release to fetch here: the uninstaller
# is part of the install that is already on the box, and this script's job is
# to find that install and hand over to it. On a host with no install it says
# so and stops, rather than fetching one in order to remove it.
#
# Root never runs the checkout's own copy (#943). The uninstaller is staged
# first, with the rest of the install's scripts: each file read once and held
# to the release's digests and the trusted-path check, into a directory only
# root can write, and that copy is what runs, told which install it removes.
# That needs root's own copy of the checking libraries under
# /usr/local/lib/aperire, which every install and update puts there; a host
# without them is told to update first.
#
# The newest uninstaller runs when it is newer (#1027). A removal a later
# release added is in that release's uninstall.sh, not in the one this host
# installed, so a wipe with the host's own copy leaves it behind. Root reads
# the signed release.json the endpoint names and compares its publish date
# with the newest release this host has installed (the kept signed release
# and the high-water mark the install and update write, the same floor an
# update refuses an older release by). Strictly newer: that release's
# uninstall.sh is fetched, checked, and runs beside the install's staged
# scripts. The same, older, or no record on this host: the install's own copy
# runs. An endpoint that does not answer leaves the install's own copy too,
# with a warning; one that answers with something that does not verify is a
# refusal, and nothing is removed.
#
# An install made before the keep/wipe question carries an uninstall.sh that
# requires --role and refuses --keep and --wipe outright, so handing it those
# flags ends the run with "unknown argument". An uninstall.sh from before
# staged runs would take the staging directory for the install. When either
# is what is here, the current uninstall.sh is fetched, because the host's own
# cannot run, and a fetch that fails is a refusal. So is a release older than
# one this host has a verified record of installing. Root fetches the copy
# itself, over https (or a lab gate's loopback stand-in), from the address
# stamped below, into a directory
# only root can write; it is checked whole, announced on screen and run from
# there, leaving the checkout's file alone.
#
# It runs only once the release key vouches for it (#762). Root fetches the
# release the endpoint names, release-<sha256>.json and its signature, checks
# them against the release key this host already trusts (root's own copy in
# /usr/local/lib/aperire, never the checkout's), and runs the fetched
# uninstall.sh only when its sha256 is the uninstaller_sha256 that signed
# release names. An older install with no release key is told to update
# first, because there is nothing to check the download against.
#
# The uninstaller asks one question and it has no default:
#
#   1) keep artifacts   the database (operators, passkeys, alert history),
#                       /etc/aperire and the checkout stay
#   2) wipe clean       they go too
#
# --keep and --wipe answer it without a terminal. --yes does not: it skips
# the "proceed?" confirmation, which is a different question.
#
# Flags (--flag value and --flag=value both work). Everything except --dir is
# passed straight through to the uninstaller:
#   --dir <path>    the install to remove. Found from the installed dashboard
#                   unit when not given.
#   --no-upgrade    download nothing: run the install's own uninstall.sh even
#                   when a newer release has one. An install whose own cannot
#                   be staged (one older than the keep/wipe question, or than
#                   staged runs) is then refused by name, because the only
#                   other way to run it is as root out of the checkout
#   --keep          keep the database, /etc/aperire and the checkout
#   --wipe          remove those as well
#   --toolchain     with --wipe, also remove Go and nvm
#   --role <role>   remove one half only: dashboard, validator, co-located
#                   or cli-only
#   --yes, -y       skip the confirmation (not an answer to the question)
#   --help, -h
#
# The unattended form is both flags together:
#
#   curl -fsSL https://get.aperire.one/uninstall | bash -s -- --wipe --yes
#
# Two of the values can arrive as environment variables, which is what the
# tests use: APERIRE_UNINSTALL_GET_DIR and APERIRE_UNINSTALL_GET_SELF_URL. The
# address of uninstall.sh and its signed release cannot: root fetches those,
# and only from the address stamped below.
#
# ---- the two guards -------------------------------------------------
#
# The same two the other bootstraps carry, for the same reason: `curl | bash`
# runs code nobody read, from a pipe that can be cut in the middle, and the
# half that arrived still runs. On a script whose job is removal that matters
# more, not less.
#
#   1. A piped run re-fetches itself to a temporary FILE, checks that the file
#      ends with the sentinel this script's last line carries, and execs that
#      file. It happens near the top, because a pipe cut in the middle never
#      reaches the bottom.
#   2. Everything below guard 1 is a function, and `main` is called on the
#      last line. A copy cut anywhere above that line defines its functions
#      and does nothing at all.
#
set -euo pipefail

SENTINEL='# --- end of get-aperire-uninstall.sh ---'

# Where this script comes from, so a piped run can fetch itself whole. One
# value, not four: this script installs nothing, so there is no archive to
# name and no checksum to state. The one thing it fetches is itself, and the
# sentinel is what says that arrived whole.
#
# Not edited by hand. scripts/build-release-snapshot.sh rewrites the line
# below when it builds a release, and refuses to build if the line has moved.
# >>> release stamp >>>
DEFAULT_SELF_URL='https://get.aperire.one/uninstall'
DEFAULT_UNINSTALL_URL='https://get.aperire.one/uninstall.sh'
# <<< release stamp <<<

# The second address is the uninstaller itself, published beside this script
# under its own name. Stamped rather than derived from the line above it,
# because the two do not sit in the same place in every layout: on the release
# endpoint they are siblings in one flat directory, and in a clone this script
# is under scripts/ while the uninstaller is at the root.

DIR="${APERIRE_UNINSTALL_GET_DIR:-}"
DIR_GIVEN=0
# How the install below was arrived at, printed in the plan. Set on every path
# out of find_install, because "which install is this about to remove" is the
# one question worth answering out loud before anything is removed.
DIR_EVIDENCE="(you named it)"

# Everything that is not --dir goes on to the uninstaller untouched. This
# script decides nothing about the removal itself: one place owns that
# question, and it is the file that does the removing.
PASS_ARGS=()

# What root runs (#943): a copy staged out of the install, or the current one
# fetched for an install whose own is too old to stage. Set by
# prepare_uninstaller, and root's directory is removed however the run ends.
UNINSTALL_RUN=""
ROOT_CLEANUP_PATHS=()
# Root's own copy of the checking libraries, placed by every install and
# update. A constant, with no variable and no switch that can name another
# directory: the bootstrap runs as the login, so anything it reads from its own
# environment could pick what root sources (#943 review). A test maps this path
# to a fixture in its fake sudo.
ROOT_LIB_DIR=/usr/local/lib/aperire
# Where the install and every update keep the signed release this host is on
# and the high-water mark (#1027): the floor a release on offer has to be
# newer than before its uninstall.sh runs. A constant for the same reason as
# the line above, mapped the same way in the test's fake sudo.
RELEASE_STORE=/var/lib/aperire/release

# Whether the copy on this host understands the keep/wipe question, decided by
# reading it rather than by asking it: running an unknown script to find out
# what it accepts is a worse first move than grepping it.
NEEDS_CURRENT_UNINSTALLER=0
UPGRADE_WHY=""
# What root's check of the release on offer found (#1027): newer, same,
# older, or unknown (this host keeps no record to compare with), with the
# release it names and the two dates. Set by check_served_release.
SERVED_VERDICT=""
SERVED_ID=""
SERVED_AT=""
SERVED_FLOOR=""
ALLOW_UPGRADE=1
UNINSTALL_SENTINEL='# --- end of uninstall.sh ---'

# The operator this install belongs to. Under sudo that is the account that
# invoked it, never root: the checkout, the database and the CLI links are
# that account's files.
# `|| true` on both lookups, and it is load-bearing: getent exits 2 for a name
# it does not know, pipefail carries that out of the pipeline, and set -e
# would then end the run with no output at all, before it had said anything.
if [[ -n "${SUDO_USER:-}" ]]; then
  OP_USER="$SUDO_USER"
  OP_HOME="$(getent passwd "$OP_USER" 2>/dev/null | cut -d: -f6 || true)"
else
  OP_USER="$(id -un)"
  OP_HOME="${HOME:-}"
fi
[[ -n "$OP_HOME" ]] || OP_HOME="$(getent passwd "$OP_USER" 2>/dev/null | cut -d: -f6 || true)"
[[ -n "$OP_HOME" ]] || OP_HOME="/nonexistent"

# Temporary files this run made, removed however it ends. One list and one
# trap, because a second `trap ... EXIT` anywhere would silently replace the
# first and leave whatever it was cleaning up behind.
CLEANUP_PATHS=()
cleanup_temporaries() {
  [[ -n "${APERIRE_UNINSTALL_GET_SELF_TMP:-}" ]] && rm -f "${APERIRE_UNINSTALL_GET_SELF_TMP}"
  local p
  for p in ${CLEANUP_PATHS[@]+"${CLEANUP_PATHS[@]}"}; do rm -rf "$p"; done
  # Root's, so root removes it, and never waits on a password: a sudo that has
  # lapsed leaves a root-only directory in /tmp, which the next boot clears.
  for p in ${ROOT_CLEANUP_PATHS[@]+"${ROOT_CLEANUP_PATHS[@]}"}; do
    if [[ $EUID -eq 0 ]]; then rm -rf "$p"; else sudo -n rm -rf "$p" 2>/dev/null || true; fi
  done
  return 0
}

# >>> aperire palette >>>
# The same palette the rest of the install path uses, kept identical on
# purpose: one run that crosses from this script into uninstall.sh should not
# change colour halfway.
#
# Empty when the stream is not a terminal, when NO_COLOR is set to anything
# (https://no-color.org), or under TERM=dumb. So a piped, redirected or logged
# run is byte-plain and greps exactly the way it always did.
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

# -- Output ----------------------------------------------------------
step() { printf '\n%s%s%s\n' "$S_BOLD" "$*" "$S_OFF"; }
info() { printf '  %s\n' "$*"; }
ok()   { printf '  %sok    %s%s\n' "$S_GREEN" "$*" "$S_OFF"; }
die()  { printf '\n%serror: %s%s\n' "$E_RED" "$*" "$E_OFF" >&2; exit 1; }
dim()  { printf '  %s%s%s\n' "$S_DIM" "$*" "$S_OFF"; }
warn() { printf '  %s!!    %s%s\n' "$S_AMBER" "$*" "$S_OFF"; }

# The header comment is the help text. Under a pipe there is no file to read
# it out of, and awk with no filename would sit waiting on the same exhausted
# stdin, so that case gets the short form instead of a hang.
usage() {
  if [[ -n "${BASH_SOURCE[0]:-}" && -f "${BASH_SOURCE[0]}" ]]; then
    awk '/^[^#]/{exit} NR>1{sub(/^# ?/,""); print}' "${BASH_SOURCE[0]}"
    return 0
  fi
  cat <<'EOF'
get-aperire-uninstall.sh - takes Aperire One off a host that has it.

  --dir <path>    the install to remove (found from the dashboard unit)
  --keep          keep the database, /etc/aperire and the checkout
  --wipe          remove those as well
  --toolchain     with --wipe, also remove Go and nvm
  --role <role>   remove one half only
  --yes, -y       skip the confirmation (not an answer to the question)

Download it to a file for the whole story, which is its header comment:
  curl -fsSL <url> -o get-aperire-uninstall.sh && less get-aperire-uninstall.sh
EOF
}

# -- Guard 1: never run a half-delivered script ----------------------
running_from_a_pipe() { [[ -z "${BASH_SOURCE[0]:-}" || ! -f "${BASH_SOURCE[0]}" ]]; }

reexec_from_a_file() {
  running_from_a_pipe || return 0
  [[ "${APERIRE_UNINSTALL_GET_REEXEC:-0}" != "1" ]] || return 0

  local url tmp
  url="${APERIRE_UNINSTALL_GET_SELF_URL:-$DEFAULT_SELF_URL}"
  tmp="$(mktemp -t get-aperire-uninstall.XXXXXXXX.sh)"

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

  export APERIRE_UNINSTALL_GET_REEXEC=1 APERIRE_UNINSTALL_GET_SELF_TMP="$tmp"
  # Hand the run a terminal. Under a pipe, stdin IS the pipe: it is empty and
  # it is not a keyboard, so the keep-or-wipe question below would have nobody
  # to ask and the whole run would refuse for a reason that has nothing to do
  # with the host.
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
# the point: a pipe cut further down never reaches a call at the bottom.
reexec_from_a_file "$@"

# -- Privilege -------------------------------------------------------
# NO_COLOR crosses the sudo boundary by hand, because sudo does not carry it:
# `Defaults env_reset` keeps TERM and drops NO_COLOR, so without this an
# operator who set it would get a plain bootstrap and a coloured uninstaller
# out of one run.
NO_COLOR_ENV=()
[[ -n "${NO_COLOR:-}" ]] && NO_COLOR_ENV=("NO_COLOR=${NO_COLOR}")

run_root() {
  if [[ $EUID -eq 0 ]]; then "$@"; else sudo -H env "${NO_COLOR_ENV[@]}" "$@"; fi
}

have_tty() { [[ -t 0 && -t 2 ]]; }

# -- Finding the install ---------------------------------------------
#
# The dashboard's own unit is the answer, and it is the only one that cannot
# be wrong: it is what the running service reads from. WorkingDirectory is
# <install>/dashboard, so the install is its parent.
#
# --dir overrides it, because a host can legitimately carry a second install
# and only the operator knows which one is being removed.
installed_dir_from_unit() {
  local wd
  wd="$(systemctl show -p WorkingDirectory --value "aperire-server${APERIRE_INSTANCE:+-$APERIRE_INSTANCE}.service" 2>/dev/null || true)"
  # systemd answers with the property empty rather than failing when the unit
  # is unknown, and older versions answer `WorkingDirectory=` even with
  # --value. Both come back as nothing useful, which is the same answer.
  wd="${wd#WorkingDirectory=}"
  [[ -n "$wd" && "$wd" != "/" ]] || return 1
  [[ "$(basename "$wd")" == "dashboard" ]] || return 1
  printf '%s' "$(dirname "$wd")"
}

# What makes a directory an Aperire One install, rather than a directory with
# a familiar name. Both, because either alone is something else: a bare
# uninstall.sh is a copy someone saved, and a bare scripts/ directory is any
# repository at all.
looks_like_an_install() { # $1 = directory
  [[ -f "$1/uninstall.sh" && -d "$1/scripts" ]]
}

find_install() {
  local candidate
  if [[ $DIR_GIVEN -eq 1 ]]; then
    looks_like_an_install "$DIR" \
      || die "$DIR is not an Aperire One install: it has no uninstall.sh and no scripts/ directory."
    DIR_EVIDENCE="(you named it)"
    return 0
  fi
  if candidate="$(installed_dir_from_unit)" && looks_like_an_install "$candidate"; then
    DIR="$candidate"
    DIR_EVIDENCE="(from the installed dashboard unit)"
    return 0
  fi
  # The default location, for a host whose dashboard unit is already gone but
  # whose checkout is not. Named as a guess, because that is what it is.
  if looks_like_an_install "${OP_HOME}/aperire-one"; then
    DIR="${OP_HOME}/aperire-one"
    DIR_EVIDENCE="(found at the default location; no dashboard unit named one)"
    return 0
  fi
  refuse_no_install
}

# Whether anything of ours is on this host at all, used only to make the
# refusal below say the right thing. A host with units but no checkout is a
# different problem from a host with nothing on it, and telling an operator
# with leftovers that they have none would be the worse of two mistakes.
units_are_here() {
  local n
  n="$(systemctl list-unit-files 'aperire-*' --no-legend 2>/dev/null | grep -c . || true)"
  [[ "${n:-0}" -gt 0 ]]
}

# The refusal this script exists to make well. There is no honest way to
# uninstall on a box with nothing on it, and fetching a release here would
# download the thing the operator is trying to be rid of.
refuse_no_install() {
  cat >&2 <<EOF

${E_RED}error: there is no Aperire One install on this host.${E_OFF}

  This script removes an install; it does not download one. There is no
  uninstall.sh here to run and nothing was fetched to make one.
EOF
  if units_are_here; then
    cat >&2 <<EOF

  Something IS here though: this host still has units whose names begin with
  aperire. That is a checkout that was deleted before it was uninstalled from.

  Unpack the release again and run the uninstaller from it:

      ${E_CYAN}curl -fsSL https://get.aperire.one | bash${E_OFF}
      ${E_CYAN}curl -fsSL https://get.aperire.one/uninstall | bash -s -- --wipe${E_OFF}

  Or read what is left first, from any copy of the release:

      ${E_CYAN}bash scripts/aperire-leftovers.sh${E_OFF}
EOF
  else
    cat >&2 <<EOF

  If the install IS here and lives somewhere unusual, name it:

      ${E_CYAN}curl -fsSL <url> | bash -s -- --dir /path/to/aperire-one${E_OFF}
EOF
  fi
  exit 1
}

# -- Privilege, once there is something to remove --------------------
#
# The install is an ordinary account's files: the checkout, the database, the
# CLI links under its home. A root-only login has none of them, and an
# uninstall run there would take the units off and leave that account's
# commands on its PATH pointing at nothing.
# The test for it is the account this run BELONGS to, not the effective uid.
# `curl | sudo bash` is a root run that belongs to an operator, and it is the
# documented way to do this; what has nobody behind it is a root login shell,
# where SUDO_USER is unset and the account works out to root itself.
guard_privilege() {
  if [[ "$OP_USER" == "root" ]]; then
    cat >&2 <<EOF

${E_RED}error: run this from the account that owns the install, not as root.${E_OFF}

  ${DIR} belongs to an ordinary account, and so do the aperire commands on
  that account's PATH. A run started from a root-only login cannot see whose
  they are, so it would remove the units and leave the commands behind.

  Either of these is right, from the account that owns the install:

      ${E_CYAN}curl -fsSL <url> | bash${E_OFF}
      ${E_CYAN}curl -fsSL <url> | sudo bash${E_OFF}

  The first asks for your sudo password when it reaches the part that needs
  it. The second has it already.
EOF
    exit 1
  fi
}

ensure_sudo() {
  [[ $EUID -eq 0 ]] && return 0
  command -v sudo >/dev/null 2>&1 \
    || die "this host has no sudo, and removing systemd units, accounts and files under /etc needs root."
  sudo -n true 2>/dev/null && return 0
  if ! have_tty; then
    die "sudo wants a password and there is no terminal to ask on. Run it as: curl -fsSL <url> | sudo bash"
  fi
  sudo -v || die "sudo was refused, so nothing was removed."
}

# -- Is the uninstaller on this box the current one? -----------------
#
# Two things make an install's own uninstall.sh unusable here, and both are
# read off the file rather than asked of it.
#
#   - An install made before the keep/wipe question carries an uninstall.sh
#     that requires --role and refuses --keep and --wipe as unknown arguments,
#     so the one-line uninstall ends with "unknown argument: --wipe" and exit
#     2 on every host installed from a release older than that change.
#     Reported live from aperire4 on 2026-09-07.
#   - One from before staged runs (#943) works out the install it removes from
#     its own location, so root running a staged copy of it would take the
#     staging directory for the install.
#
# The test is one grep for each, against the file. Asking the script what it
# accepts would mean running it, and running an unknown script to find out
# what it does is the wrong first move here.
probe_installed_uninstaller() {
  NEEDS_CURRENT_UNINSTALLER=0
  UPGRADE_WHY=""
  if ! grep -q -- '--wipe' "$DIR/uninstall.sh" 2>/dev/null; then
    NEEDS_CURRENT_UNINSTALLER=1
    UPGRADE_WHY="predates the keep/wipe question"
  elif ! grep -q 'APERIRE_INSTALL_TREE' "$DIR/uninstall.sh" 2>/dev/null; then
    NEEDS_CURRENT_UNINSTALLER=1
    UPGRADE_WHY="predates staged runs"
  fi
  return 0
}

# --no-upgrade has one honest answer on an install like that: the only other
# way to run its uninstall.sh is as root out of the checkout, which is what
# this script no longer does.
refuse_no_upgrade() {
  die "this install's uninstall.sh ${UPGRADE_WHY}, so it cannot be staged for root, and --no-upgrade rules out the current one. Leave --no-upgrade off, or update the install first: curl -fsSL https://get.aperire.one | bash -s -- --update"
}

# A directory only root can write, for whatever root is about to run. Leaves
# the path in ROOT_HELD. Called on its own, never inside $( ): its cleanup has
# to land in this shell, not a subshell's.
ROOT_HELD=""
root_held_dir() { # $1 = a name for it
  ROOT_HELD="$(run_root mktemp -d -t "aperire-uninstall-$1.XXXXXXXX")" \
    || die "cannot make a directory only root can write, so nothing can be run as root. Nothing was removed."
  ROOT_CLEANUP_PATHS+=("$ROOT_HELD")
  run_root chmod 0755 "$ROOT_HELD" || die "cannot set up the directory root runs the uninstaller from. Nothing was removed."
}

# The current uninstall.sh, fetched and checked by root, into a directory only
# root can write (check_served_release), then put where root can run it
# without the checkout's say (prepare_uninstaller). It is not written into the
# checkout: uninstall.sh is told which install it removes (APERIRE_INSTALL_TREE),
# so it no longer needs to sit in it, and a root write into a directory the
# install's accounts can change follows whatever link one of them left there.
#
# The address is the one stamped into this script (DEFAULT_UNINSTALL_URL), never
# one from the environment: the login's environment does not pick what root
# fetches (#1027 review). The test reaches it through its fake curl on PATH.
#
# Returns 1, after the same warning as the first look, only on a current
# install whose endpoint stopped answering after it said "newer": that install
# still has its own copy to run.
FETCHED_UNINSTALLER=""
fetch_current_uninstaller() {
  local url="$DEFAULT_UNINSTALL_URL" copy
  step "this install's uninstall.sh ${UPGRADE_WHY}"
  info "using the current one from ${url}"
  root_held_dir fetched
  copy="$ROOT_HELD/uninstall.sh"
  check_served_release "$url" "$copy" || return 1
  # An install whose own uninstall.sh cannot run, beside a verified record that
  # this host has installed a release NEWER than the one on offer, is a
  # contradiction: that record's release took the question. Running the older
  # copy would be a replayed release choosing what root removes.
  if [[ $NEEDS_CURRENT_UNINSTALLER -eq 1 && "$SERVED_VERDICT" == older ]]; then
    die "the release on offer was published ${SERVED_AT}, before the newest this host has installed (${SERVED_FLOOR}), so its uninstall.sh was not run. Nothing was removed.

  A replayed older release looks exactly like this. And a host that installed
  ${SERVED_FLOOR} should not carry an uninstall.sh that predates the keep/wipe
  question, so check what changed ${DIR}/uninstall.sh, then put the release back
  as it shipped: curl -fsSL https://get.aperire.one | bash -s -- --update --force"
  fi
  # And that what arrived is actually newer, rather than another copy of the
  # one already here. Without this a stale endpoint would hand an old script
  # flags it does not know, which is the failure this whole path exists to end.
  grep -q -- '--wipe' "$copy" \
    || die "the copy fetched from ${url} does not understand --keep or --wipe either, so it was not installed. The endpoint is serving an old uninstall.sh."
  grep -q 'APERIRE_INSTALL_TREE' "$copy" \
    || die "the copy fetched from ${url} does not take the install it removes from APERIRE_INSTALL_TREE, so root cannot run it from outside the checkout. The endpoint is serving an old uninstall.sh."
  FETCHED_UNINSTALLER="$copy"
}

# The release on offer, held to the release signature (#762), the way the
# updater holds the bootstrap (scripts/aperire-update.sh, verify_published):
# release.json only says WHICH release, and everything else is read from the
# signed release-<sha256>.json once it verifies. One root call does it all, in
# a directory root made for it, against root's own copy of the verifier and
# the key set. Nothing is forked: the functions are the ones in
# scripts/release-verify-lib.sh, sourced from where every install and update
# puts them, after the same owner and mode checks the staging call makes.
#
# With a destination ($2), the same call then fetches uninstall.sh itself,
# straight into root's directory, and holds it to its last line and to the
# signed uninstaller_sha256: no file the login wrote is ever a source for root
# (#1027 review). Without one, only the release is read, to say whether it is
# newer.
#
# Newer is judged in the same call, once the signature verifies (#1027): the
# signed publish date against this host's floor, the later of the kept signed
# release (believed only when root's key set verifies it) and the root-owned
# high-water mark. That is the floor get-aperire.sh --update and
# aperire-update.sh refuse an older release by, read the same way. The answer
# is newer, same, older, or unknown (no floor on this host).
#
# Returns 1, with a warning, only on a current install, and only when nothing
# was served to refuse: this host has no release key, or the endpoint did not
# answer (for release.json, or for uninstall.sh after the record said newer).
# Its own copy can still run. Anything served that does not verify ends the
# run.
check_served_release() { # $1 = the url uninstall.sh comes from, $2 = where root puts it, or ""
  local url="$1" copy="$2" base out rc=0 hint=""
  base="${url%/*}"
  if [[ -n "$copy" ]]; then
    info "root fetches it and checks it against this host's release key"
  else
    info "checking the release ${base} serves against this host's release key"
  fi
  # A current install has its own uninstall.sh to fall back on, and the way to
  # choose it without any of this is named in every refusal.
  [[ $NEEDS_CURRENT_UNINSTALLER -eq 1 ]] || hint="

  To remove with this install's own uninstall.sh and download nothing, run it again with --no-upgrade."
  # The scheme root's curl may use, and may be redirected to, comes from the
  # stamped address (part of this script, not of the login's environment).
  # Every release is https. The lab gate stamps its loopback stand-in, which
  # is plain http on this host, so that one shape is allowed http and nothing
  # else; any other http address is refused before root fetches anything. The
  # signature is what vouches for the bytes either way.
  local scheme
  if [[ "$url" == https://* ]]; then
    scheme="=https"
  elif [[ "$url" =~ ^http://(127\.0\.0\.1|localhost):[0-9]+/ ]]; then
    scheme="=http"
  else
    die "this script's uninstaller address (${url}) is not https, and not the loopback stand-in a lab gate serves, so root fetches nothing from it. Nothing was removed.${hint}"
  fi
  # shellcheck disable=SC2016  # the root shell's own positional parameters
  out="$(run_root bash -c '
    d="$1"; held="$2"; url="$3"; copy="$4"; store="$5"; sentinel="$6"; scheme="$7"; base="${url%/*}"
    re_at="^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"
    [[ -d "$d" && ! -L "$d" && -O "$d" ]] || exit 3
    (( (8#$(stat -c %a -- "$d") & 8#022) == 0 )) || exit 3
    for f in release-verify-lib.sh release-signers; do
      p="$d/$f"
      [[ -f "$p" && ! -L "$p" && -O "$p" ]] || exit 3
      (( (8#$(stat -c %a -- "$p") & 8#022) == 0 )) || exit 3
    done
    . "$d/release-verify-lib.sh" || exit 3
    s="$held/signed"
    mkdir -m 0755 -- "$s" || exit 2
    get() { curl -fsSL --proto "$scheme" --proto-redir "$scheme" --max-time 60 --max-filesize 8388608 -o "$2" "$1"; }
    get "$base/release.json" "$s/pointer.json" || exit 4
    sha="$(release_json_field "$s/pointer.json" sha256)" || sha=""
    [[ "$sha" =~ ^[0-9a-f]{64}$ ]] || exit 5
    get "$base/release-$sha.json" "$s/release.json" || exit 6
    get "$base/release-$sha.json.sig" "$s/release.json.sig" || exit 6
    if ! release_verify "$s/release.json" "$s/release.json.sig" "$d/release-signers"; then exit 7; fi
    named="$(release_json_field "$s/release.json" sha256)" || named=""
    [[ "$named" == "$sha" ]] || { echo "the signed release.json names the archive ${named:-nothing}, and release.json names $sha" >&2; exit 7; }
    at="$(release_json_field "$s/release.json" published_at)" || at=""
    [[ "$at" =~ $re_at ]] || exit 10
    floor=""
    cur="$(head -c 64 -- "$store/current" 2>/dev/null)" || cur=""
    if [[ "$cur" =~ ^[0-9a-f]{64}$ ]] \
       && release_verify "$store/$cur/release.json" "$store/$cur/release.json.sig" "$d/release-signers" >/dev/null 2>&1; then
      floor="$(release_json_field "$store/$cur/release.json" published_at)" || floor=""
      [[ "$floor" =~ $re_at ]] || floor=""
    fi
    hw="$store/high-water"
    if [[ -f "$hw" && ! -L "$hw" && -O "$hw" ]] && (( (8#$(stat -c %a -- "$hw") & 8#022) == 0 )); then
      hw="$(head -c 64 -- "$hw" | head -1)"
      [[ "$hw" =~ $re_at ]] && { [[ -z "$floor" || "$hw" > "$floor" ]] && floor="$hw"; }
    fi
    if [[ -z "$floor" ]]; then v=unknown
    elif [[ "$at" > "$floor" ]]; then v=newer
    elif [[ "$at" == "$floor" ]]; then v=same
    else v=older; fi
    if [[ -n "$copy" ]]; then
      want="$(release_json_field "$s/release.json" uninstaller_sha256)" || want=""
      [[ "$want" =~ ^[0-9a-f]{64}$ ]] || exit 8
      ( umask 022; get "$url" "$copy" ) || exit 11
      [[ "$(tail -n 1 -- "$copy")" == "$sentinel" ]] || exit 12
      got="$(sha256sum -- "$copy" | cut -d" " -f1)"
      [[ "$got" == "$want" ]] || { echo "fetched $got, signed $want" >&2; exit 9; }
      chmod 0755 -- "$copy" || exit 2
    fi
    echo "${sha:0:12} $v $at ${floor:--}"' rd-verify-uninstaller "$ROOT_LIB_DIR" "$ROOT_HELD" "$url" "$copy" "$RELEASE_STORE" "$UNINSTALL_SENTINEL" "$scheme" 2>&1)" || rc=$?
  if [[ $rc -eq 0 ]]; then
    read -r SERVED_ID SERVED_VERDICT SERVED_AT SERVED_FLOOR <<<"${out##*$'\n'}"
    if [[ -n "$copy" ]]; then
      ok "signed by the release key: release ${SERVED_ID}, and its uninstall.sh is the one fetched"
    else
      ok "signed by the release key: release ${SERVED_ID}, published ${SERVED_AT}"
    fi
    return 0
  fi
  if [[ $NEEDS_CURRENT_UNINSTALLER -eq 0 ]] && [[ $rc -eq 3 || $rc -eq 4 || $rc -eq 11 ]]; then
    case "$rc" in
      3)  warn "this host has no release key root can check a newer uninstall.sh against (in $ROOT_LIB_DIR), so this install's own runs." ;;
      4)  warn "could not fetch release.json from ${base}, so nothing says whether a newer release has a newer uninstall.sh. This install's own runs." ;;
      11) warn "could not fetch ${url} after the release said it is newer, so this install's own runs." ;;
    esac
    warn "If a newer release removes something this one does not know about, it stays. Update first and run this again to have it removed: curl -fsSL https://get.aperire.one | bash -s -- --update"
    return 1
  fi
  case "$rc" in
    3) die "this host has no release key root can check the current uninstall.sh against (release-verify-lib.sh and release-signers, root-owned, in $ROOT_LIB_DIR), so it was not run. Nothing was removed. Update the install first, which puts the key there and the current uninstall.sh with it: curl -fsSL https://get.aperire.one | bash -s -- --update" ;;
    4) die "could not fetch release.json from ${base}, which names the release the uninstall.sh beside it belongs to, so nothing was run and nothing was removed. Update the install (curl -fsSL https://get.aperire.one | bash) and run this again." ;;
    5) die "release.json at ${base} names no archive, so there is no signed release to check the uninstall.sh against, and it was not run. Nothing was removed.${hint}" ;;
    6) die "${base} serves no signed release.json for the release it names, so the uninstall.sh beside it cannot be checked and was not run. Nothing was removed. An unsigned uninstaller is never run as root.${hint}" ;;
    7) die "the release at ${base} is not signed by a key this host trusts, so the uninstall.sh beside it was not run. Nothing was removed.

  ${out}

  If it says the same thing twice, do not run anything from that address.${hint}" ;;
    8) die "the signed release.json at ${base} names no uninstaller, so the uninstall.sh beside it cannot be checked and was not run. Nothing was removed.${hint}" ;;
    9) die "the uninstall.sh fetched from ${url} is not the one the signed release names, so it was not run. Nothing was removed.

  ${out}${hint}" ;;
    10) die "the signed release.json at ${base} states no publish date, so it cannot be told apart from an older release, and the uninstall.sh beside it was not run. Nothing was removed.${hint}" ;;
    11) die "could not fetch ${url}. Nothing was changed and nothing was removed. Update the install (curl -fsSL https://get.aperire.one | bash) and run this again." ;;
    12) die "the copy fetched from ${url} did not arrive whole (its last line is not the one uninstall.sh ends with), so it was not installed and nothing was run.${hint}" ;;
    *) die "root could not check the release at ${base} against the release key (exit ${rc}), so its uninstall.sh was not run. Nothing was removed.${out:+

  ${out}}${hint}" ;;
  esac
}

# The install's own scripts, staged for root (#943): uninstall.sh and
# everything it loads, each file read once and held to the release's digests
# and the trusted-path check, into a directory only root can write. The check
# comes from root's own copies of its two libraries, never from the checkout
# it is judging. Returns 1 with the reason when $1 is "soft" (a fetched
# uninstall.sh can still run alone), and ends the run otherwise.
stage_install_for_root() {
  local soft="${1:-}" rc=0 held
  root_held_dir run
  held="$ROOT_HELD"
  # One root call checks the two libraries and sources them: a regular file
  # that is not a link, owned by the account running it, and not writable by
  # group or other, in a directory that is the same. Checked by root on the
  # path root then sources, so there is no gap for the login to swap a
  # directory in (#943 review, L2).
  # shellcheck disable=SC2016  # the root shell's own positional parameters
  run_root bash -c '
    d="$1"
    [[ -d "$d" && ! -L "$d" && -O "$d" ]] || exit 3
    (( (8#$(stat -c %a -- "$d") & 8#022) == 0 )) || exit 3
    for f in release-digests-lib.sh trusted-path-lib.sh; do
      p="$d/$f"
      [[ -f "$p" && ! -L "$p" && -O "$p" ]] || exit 3
      (( (8#$(stat -c %a -- "$p") & 8#022) == 0 )) || exit 3
    done
    . "$d/release-digests-lib.sh" || exit 2
    mkdir -m 0755 -- "$2/run" || exit 2
    rd_stage_tree "$3" "$2/run" || { [[ "${RD_REFUSED_WHY:-}" == accounts ]] && exit 6; [[ "${RD_REFUSED_WHY:-}" == python3 ]] && exit 7; exit 1; }' rd-stage-tree "$ROOT_LIB_DIR" "$held" "$DIR" || rc=$?
  if [[ $rc -eq 3 ]]; then
    if [[ "$soft" == soft ]]; then
      warn "this host has no root-owned copy of the checking libraries in $ROOT_LIB_DIR, so root cannot check the scripts in $DIR."
      return 1
    fi
    die "this host has no root-owned copy of the checking libraries in $ROOT_LIB_DIR (release-digests-lib.sh and trusted-path-lib.sh), so root cannot check the uninstaller it would run out of $DIR, and runs none of it. Nothing was removed. Put the release back as it shipped, which places them even on a host already on the published release: curl -fsSL https://get.aperire.one | bash -s -- --update --force"
  fi
  if [[ $rc -eq 7 ]]; then
    # No python3 for the check to run in (#1355): no file was judged, and the
    # line above says so once. Not a file that changed.
    if [[ "$soft" == soft ]]; then
      warn "root would not run the scripts in $DIR: this host has no python3 at /usr/bin or /bin, and the check on every file runs in it, so no file there was judged."
      return 1
    fi
    die "root would not run the uninstaller in $DIR: this host has no python3 at /usr/bin or /bin, and the check on every file runs in it, so no file there was judged. Nothing was removed. Install it, then run this again: sudo apt-get install -y python3"
  fi
  if [[ $rc -eq 6 ]]; then
    # The account check could not run: no file was judged (#1111).
    if [[ "$soft" == soft ]]; then
      warn "root would not run the scripts in $DIR: the account check could not run (systemd did not answer), so no file there was judged."
      return 1
    fi
    die "root would not run the uninstaller in $DIR: the account check could not run (systemd did not answer), so no file there was judged, and nothing says the install changed. Nothing was removed. Run it again to retry the check: curl -fsSL https://get.aperire.one | bash -s -- --update --force"
  fi
  if [[ $rc -ne 0 ]]; then
    if [[ "$soft" == soft ]]; then
      warn "root would not run the scripts in $DIR: a file there is not the one its release shipped, or a service account can change it (each is named above)."
      return 1
    fi
    die "root would not run the uninstaller in $DIR: a file there is not the one its release shipped, or a service account can change it (each is named above). Nothing was removed. Find what changed the install, then put the release back as it shipped: curl -fsSL https://get.aperire.one | bash -s -- --update --force"
  fi
  UNINSTALL_RUN="$held/run/uninstall.sh"
  # The probe read the checkout's file; root runs this one, a separate read.
  # A file swapped between the two would put an older program here that takes
  # the stage for the install, so the staged copy is what is judged now.
  if [[ "$soft" != soft ]]; then
    if ! grep -q -- '--wipe' "$UNINSTALL_RUN" 2>/dev/null || ! grep -q 'APERIRE_INSTALL_TREE' "$UNINSTALL_RUN" 2>/dev/null; then
      die "the uninstall.sh root staged out of $DIR is older than the one that was read first (it does not take its install from APERIRE_INSTALL_TREE), so it was not run. Nothing was removed. Update the install: curl -fsSL https://get.aperire.one | bash -s -- --update"
    fi
  fi
}

# What root runs. A current install's own uninstall.sh is staged with the rest
# of its scripts. For one too old to stage, the fetched current copy goes
# where the staged one would sit, so the helper the dashboard hand-back plants
# with is the staged, checked one beside it. When the install cannot be staged
# at all (no root-owned libraries on an old host, or a refused file) the fetched
# copy runs alone: it runs no code from the install, and the uninstaller says
# so itself if the dashboard's files could not be handed back.
#
# A current install's own copy is replaced the same way when the release on
# offer is newer than the one this host is on (#1027), because a removal that
# release added is only in its uninstall.sh. The verdict that counts is the one
# from the call that checked the fetched bytes, not the first look.
prepare_uninstaller() {
  if [[ $NEEDS_CURRENT_UNINSTALLER -eq 0 ]]; then
    stage_install_for_root
    [[ $ALLOW_UPGRADE -eq 1 ]] || return 0
    step "is there a newer uninstall.sh?"
    root_held_dir release
    check_served_release "$DEFAULT_UNINSTALL_URL" "" || return 0
    case "$SERVED_VERDICT" in
      newer) ;;
      same|older)
        ok "no: it is not newer than the newest release this host has installed (${SERVED_FLOOR}), so this install's own uninstall.sh runs"
        return 0 ;;
      *)
        ok "this host keeps no signed record of the release it is on, so nothing says the one on offer is newer. This install's own uninstall.sh runs"
        return 0 ;;
    esac
    UPGRADE_WHY="is older than the release on offer (${SERVED_AT}; this host's newest is ${SERVED_FLOOR})"
    fetch_current_uninstaller || return 0
    if [[ "$SERVED_VERDICT" != newer ]]; then
      ok "on the second read the release on offer is not newer after all, so this install's own uninstall.sh runs"
      return 0
    fi
    run_root install -m 0755 "$FETCHED_UNINSTALLER" "$UNINSTALL_RUN" \
      || die "could not put the newer uninstall.sh where root can run it. Nothing was removed."
    ok "the newer uninstall.sh is ready, beside the install's checked scripts; ${DIR}/uninstall.sh is left as it is"
    return 0
  fi
  fetch_current_uninstaller
  if stage_install_for_root soft; then
    run_root install -m 0755 "$FETCHED_UNINSTALLER" "$UNINSTALL_RUN" \
      || die "could not put the current uninstall.sh where root can run it. Nothing was removed."
    ok "the current uninstall.sh is ready, beside the install's checked scripts; ${DIR}/uninstall.sh is left as it is"
    return 0
  fi
  UNINSTALL_RUN="$FETCHED_UNINSTALLER"
  warn "so the current uninstall.sh runs on its own, with none of the install's scripts. If the dashboard has an account of its own, the uninstaller says if it could not hand that account's files back."
  ok "the current uninstall.sh is ready; ${DIR}/uninstall.sh is left as it is"
}

# -- What is about to happen -----------------------------------------
#
# Short on purpose. The uninstaller prints the plan, the question and the
# ending; repeating any of that here would be a second opinion about a
# removal, and two of those is one too many.
announce() {
  step "the uninstall"
  info "install    ${DIR}  ${DIR_EVIDENCE}"
  if [[ $NEEDS_CURRENT_UNINSTALLER -eq 1 ]]; then
    info "running    the current uninstall.sh, as root, from a directory only root can write"
    info "downloads  the current uninstall.sh, because the one here ${UPGRADE_WHY}"
    info "           and cannot be staged for root, and the signed release.json"
    info "           that says which uninstall.sh is genuine. Nothing else."
  elif [[ $ALLOW_UPGRADE -eq 1 ]]; then
    info "running    a checked copy of ${DIR}/uninstall.sh, which is part of that install,"
    info "           or the current one if the release on offer is newer than this install"
    info "downloads  the signed release.json, to see whether it is newer, and only then the"
    info "           current uninstall.sh. Nothing else. --no-upgrade downloads nothing."
  else
    info "running    a checked copy of ${DIR}/uninstall.sh, which is part of that install"
    info "downloads  nothing. This script fetched only itself."
  fi
  echo
  dim "It prints what it found on this host, then asks whether to keep your"
  dim "database and /etc/aperire or wipe them. There is no default."
  dim "Your node, docker, Go and nvm are not touched."
}

hand_over() {
  step "handing over to the uninstaller"
  local rc=0
  # stdin is deliberately NOT redirected: the question below has to reach a
  # keyboard, and guard 1 above is what put a terminal there under a pipe.
  # The install is named to it, because root runs a copy from somewhere else.
  run_root env "${NO_COLOR_ENV[@]}" APERIRE_INSTALL_TREE="$DIR" \
    bash "$UNINSTALL_RUN" ${PASS_ARGS[@]+"${PASS_ARGS[@]}"} || rc=$?
  return "$rc"
}

# -- main ------------------------------------------------------------
main() {
  trap cleanup_temporaries EXIT

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --dir)      DIR="${2:?--dir needs a path}"; DIR_GIVEN=1; shift 2 ;;
      --dir=*)    DIR="${1#*=}"; DIR_GIVEN=1; shift ;;
      --role)     PASS_ARGS+=("--role=${2:?--role needs a value}"); shift 2 ;;
      --role=*)   PASS_ARGS+=("$1"); shift ;;
      --keep|--wipe|--toolchain|--yes|-y|--purge-config|--purge-data|--purge-all)
                  PASS_ARGS+=("$1"); shift ;;
      --no-upgrade) ALLOW_UPGRADE=0; shift ;;
      -h|--help)  usage; exit 0 ;;
      *)          die "unknown argument: $1 (run with --help)" ;;
    esac
  done

  find_install
  guard_privilege
  probe_installed_uninstaller
  if [[ $NEEDS_CURRENT_UNINSTALLER -eq 1 && $ALLOW_UPGRADE -eq 0 ]]; then
    refuse_no_upgrade
  fi
  announce
  ensure_sudo
  prepare_uninstaller
  hand_over
}

main "$@"
# --- end of get-aperire-uninstall.sh ---
