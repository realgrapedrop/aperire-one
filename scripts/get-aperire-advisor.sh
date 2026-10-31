#!/usr/bin/env bash
# get-aperire-advisor.sh - the one command that adds the Advisor to a host
# that already runs Aperire One.
#
#   curl -fsSL https://get.aperire.one/advisor | bash
#
# Or, when you would rather read it first (and you should):
#
#   curl -fsSL https://get.aperire.one/advisor -o get-aperire-advisor.sh
#   less get-aperire-advisor.sh
#   bash get-aperire-advisor.sh
#
# The Advisor is an add-on, not a product of its own. It reads the dashboard's
# own store through a versioned API and it watches the node this box runs, so
# it needs an Aperire One install to attach to. On a box with none this script
# says so and stops, rather than fetching a release nobody asked for.
#
# What it does, and nothing more: find the install that is already here, build
# what a host without --with-advisor never built, then hand over to
# scripts/install-advisor-stack.sh, which owns the sequence. It reimplements
# none of it. That same script is what `install.sh --with-advisor` runs, and
# that is the point: one command and one flag have to leave the same host
# behind, and for a while they did not.
#
# It does NOT set up a language model. That step needs a provider, a key and a
# choice of model, and it belongs where the operator already is.
#
# Flags (--flag value and --flag=value both work):
#   --dir <path>    the Aperire One install to add the Advisor to.
#                   Found from the installed dashboard unit when not given.
#   --port <n>      the port advisord listens on (default 7810)
#   --yes, -y       take every default, ask nothing
#   --help, -h
#
# The same values can arrive as environment variables, which is what the tests
# and any automation use: APERIRE_ADVISOR_GET_DIR, APERIRE_ADVISOR_GET_SELF_URL,
# APERIRE_ADVISOR_GET_PORT, APERIRE_ADVISOR_GET_TRIES, APERIRE_ADVISOR_GET_SLEEP.
#
# ---- the two guards -------------------------------------------------
#
# The same two the main bootstrap carries, for the same reason: `curl | bash`
# runs code nobody read, from a pipe that can be cut in the middle, and the
# half that arrived still runs.
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

SENTINEL='# --- end of get-aperire-advisor.sh ---'

# Where this script comes from, so a piped run can fetch itself whole.
#
# One value, not four: this script installs nothing it downloads. It attaches
# to the release that is already on the box, so there is no archive to name
# and no checksum to state. The one thing it does fetch is itself, and the
# sentinel is what says that arrived whole.
#
# Not edited by hand. scripts/build-release-snapshot.sh rewrites the line
# below when it builds a release, and refuses to build if the line has moved.
# >>> release stamp >>>
DEFAULT_SELF_URL='https://get.aperire.one/advisor'
# <<< release stamp <<<

DIR="${APERIRE_ADVISOR_GET_DIR:-}"
DIR_GIVEN=0
# How the install below was arrived at, printed in the plan. Set on every path
# out of find_install, because "which install is this attaching to" is the one
# question a second pairing on one host makes worth answering out loud.
DIR_EVIDENCE="(you named it)"
PORT="${APERIRE_ADVISOR_GET_PORT:-${APERIRE_ADVISOR_PORT:-7810}}"
ASSUME_YES=0
HEALTH_TRIES="${APERIRE_ADVISOR_GET_TRIES:-10}"
HEALTH_SLEEP="${APERIRE_ADVISOR_GET_SLEEP:-1}"

# The operator this install belongs to. Under sudo that is the account that
# invoked it, never root: the checkout, the build cache and the Advisor's
# state are that account's files.
# Under sudo, $HOME belongs to root (or to whatever sudo preserved), so the
# operator's home has to be looked up. Without sudo the reverse holds: $HOME is
# the operator's own, and it outranks the passwd database, which can name a
# different directory in a container or under a test harness.
if [[ -n "${SUDO_USER:-}" ]]; then
  OP_USER="$SUDO_USER"
  OP_HOME="$(getent passwd "$OP_USER" 2>/dev/null | cut -d: -f6)"
else
  OP_USER="$(id -un)"
  OP_HOME="${HOME:-}"
fi
[[ -n "$OP_HOME" ]] || OP_HOME="$(getent passwd "$OP_USER" 2>/dev/null | cut -d: -f6)"
[[ -n "$OP_HOME" ]] || OP_HOME="/nonexistent"

# Temporary files this run made, removed however it ends. One list and one
# trap, because a second `trap ... EXIT` anywhere would silently replace the
# first and leave whatever it was cleaning up behind.
CLEANUP_PATHS=()
cleanup_temporaries() {
  [[ -n "${APERIRE_ADVISOR_GET_SELF_TMP:-}" ]] && rm -f "${APERIRE_ADVISOR_GET_SELF_TMP}"
  local p
  for p in ${CLEANUP_PATHS[@]+"${CLEANUP_PATHS[@]}"}; do rm -rf "$p"; done
  # What root staged (#764): root's, so root removes it, and a run that is
  # ending never waits on a password for it.
  for p in ${ROOT_CLEANUP_PATHS[@]+"${ROOT_CLEANUP_PATHS[@]}"}; do
    if [[ $EUID -eq 0 ]]; then rm -rf "$p"; else sudo -n rm -rf "$p" 2>/dev/null || true; fi
  done
  return 0
}

# >>> aperire palette >>>
# The same palette the rest of the install path uses, kept identical on
# purpose: one run that crosses from this script into install-advisord.sh
# should not change colour halfway. Bold heads a phase, green is a reading
# taken and passed, amber is a degradation carried on from, red is a refusal,
# dim is the detail under a line, and cyan marks a command or an address meant
# to be typed or opened.
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
warn() { printf '  %s!!    %s%s\n' "$S_AMBER" "$*" "$S_OFF"; }
die()  { printf '\n%serror: %s%s\n' "$E_RED" "$*" "$E_OFF" >&2; exit 1; }
dim()  { printf '  %s%s%s\n' "$S_DIM" "$*" "$S_OFF"; }

# The header comment is the help text. Under a pipe there is no file to read it
# out of, and awk with no filename would sit waiting on the same exhausted
# stdin, so that case gets the short form instead of a hang.
usage() {
  if [[ -n "${BASH_SOURCE[0]:-}" && -f "${BASH_SOURCE[0]}" ]]; then
    awk '/^[^#]/{exit} NR>1{sub(/^# ?/,""); print}' "${BASH_SOURCE[0]}"
    return 0
  fi
  cat <<'EOF'
get-aperire-advisor.sh - adds the Advisor to a host that already runs Aperire One.

  --dir <path>    the install to add it to (found from the dashboard unit)
  --port <n>      the port advisord listens on (default 7810)
  --yes, -y       take every default, ask nothing

Download it to a file for the whole story, which is its header comment:
  curl -fsSL <url> -o get-aperire-advisor.sh && less get-aperire-advisor.sh
EOF
}

# -- Guard 1: never run a half-delivered script ----------------------
running_from_a_pipe() { [[ -z "${BASH_SOURCE[0]:-}" || ! -f "${BASH_SOURCE[0]}" ]]; }

reexec_from_a_file() {
  running_from_a_pipe || return 0
  [[ "${APERIRE_ADVISOR_GET_REEXEC:-0}" != "1" ]] || return 0

  local url tmp
  url="${APERIRE_ADVISOR_GET_SELF_URL:-$DEFAULT_SELF_URL}"
  tmp="$(mktemp -t get-aperire-advisor.XXXXXXXX.sh)"

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

  export APERIRE_ADVISOR_GET_REEXEC=1 APERIRE_ADVISOR_GET_SELF_TMP="$tmp"
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
# the point: a pipe cut further down never reaches a call at the bottom.
reexec_from_a_file "$@"

# -- Privilege -------------------------------------------------------
# NO_COLOR crosses the sudo boundary by hand, because sudo does not carry it:
# `Defaults env_reset` keeps TERM and drops NO_COLOR, so without this an
# operator who set it would get a plain bootstrap and a coloured installer out
# of one run.
NO_COLOR_ENV=()
[[ -n "${NO_COLOR:-}" ]] && NO_COLOR_ENV=("NO_COLOR=${NO_COLOR}")

run_root() {
  if [[ $EUID -eq 0 ]]; then "$@"; else sudo -H env "${NO_COLOR_ENV[@]}" "$@"; fi
}

# What root runs out of the install, staged first (#764). The install's
# prepare step, the Advisor stack and the state tool are run by root, and
# root runs them only from a copy it staged out of the tree into a directory
# only it can write, each file read once and held to the release's digests
# and the trusted-path check. The check comes from root's own installed
# copies of its two libraries (placed by the update grant and every update),
# never from the tree it is judging. The directory is a constant as root;
# only an unprivileged test run may point it elsewhere.
ROOT_LIB_DIR=/usr/local/lib/aperire
# Honoured on positive evidence of an unprivileged account only, from id(1)
# and not bash's $EUID, which bash imports from the environment (#1109).
_g_uid="$(/usr/bin/id -u 2>/dev/null || true)"
if [[ "$_g_uid" =~ ^[0-9]+$ && "$_g_uid" != 0 ]]; then
  ROOT_LIB_DIR="${APERIRE_ADVISOR_GET_ROOT_LIB_DIR:-$ROOT_LIB_DIR}"
fi
unset _g_uid
RUN_TREE=""
ROOT_CLEANUP_PATHS=()
# One caller has to survive a refusal: the wrapper repair is a courtesy on a
# host that is otherwise done, so with STAGE_SOFT=1 a refusal prints its
# reason on stderr and returns 1 instead of ending the run.
STAGE_SOFT=0
stage_refuse() {
  if [[ $STAGE_SOFT -eq 1 ]]; then printf '\n%serror: %s%s\n' "$E_RED" "$*" "$E_OFF" >&2; return 0; fi
  die "$@"
}
stage_install_for_root() {
  [[ -n "$RUN_TREE" ]] && return 0
  local f meta want_uid out rc=0
  want_uid=0
  [[ $EUID -eq 0 ]] || want_uid="$(run_root id -u 2>/dev/null || echo 0)"
  for f in release-digests-lib.sh trusted-path-lib.sh; do
    meta="$(run_root stat -c '%F:%u:%a' -- "$ROOT_LIB_DIR/$f" 2>/dev/null)" || meta=""
    if [[ "${meta%%:*}" != "regular file" ]] || [[ "$(cut -d: -f2 <<<"$meta")" != "$want_uid" ]] \
       || (( (8#${meta##*:} & 8#022) != 0 )); then
      stage_refuse "this host has no root-owned copy of $ROOT_LIB_DIR/$f, so root cannot check the installers it would run out of $DIR, and runs none of them. Put the release back as it shipped, which places it even on a host already on the published release: curl -fsSL https://get.aperire.one | bash -s -- --update --force"
      return 1
    fi
  done
  out="$(run_root mktemp -d -t aperire-advisor-run.XXXXXXXX)" \
    || { stage_refuse "cannot make a directory only root can write, so nothing can be staged for root."; return 1; }
  ROOT_CLEANUP_PATHS+=("$out")
  run_root chmod 0755 "$out"
  # shellcheck disable=SC2016  # the root shell's own positional parameters
  run_root bash -c '. "$1/release-digests-lib.sh" || exit 2
    mkdir -m 0755 -- "$2/run" || exit 2
    rd_stage_tree "$3" "$2/run" || { [[ "${RD_REFUSED_WHY:-}" == accounts ]] && exit 6; [[ "${RD_REFUSED_WHY:-}" == python3 ]] && exit 7; exit 1; }' rd-stage-tree "$ROOT_LIB_DIR" "$out" "$DIR" || rc=$?
  if [[ $rc -eq 7 ]]; then
    # No python3 for the check to run in (#1355): no file was judged, and the
    # line above says so once. Not a file that changed.
    stage_refuse "root would not run the installers in $DIR: this host has no python3 at /usr/bin or /bin, and the check on every file runs in it, so no file there was judged. Nothing was installed. Install it, then run this again: sudo apt-get install -y python3"
    return 1
  elif [[ $rc -eq 6 ]]; then
    # The account check could not run (systemd did not answer): no file was
    # judged, and nothing says the install changed (#1111).
    stage_refuse "root would not run the installers in $DIR: the account check could not run (systemd did not answer), so no file there was judged, and nothing says the install changed. Nothing was installed. Run it again to retry the check: curl -fsSL https://get.aperire.one | bash -s -- --update --force"
    return 1
  elif [[ $rc -ne 0 ]]; then
    stage_refuse "root would not run the installers in $DIR: a file there is not the one its release shipped, or a service account can change it (each is named above). Nothing was installed. Find what changed the install, then put the release back as it shipped: curl -fsSL https://get.aperire.one | bash -s -- --update --force"
    return 1
  fi
  RUN_TREE="$out/run"
}

# The copy of an install file this shell may load or run itself: the staged
# one when this shell is root (`curl ... | sudo bash`), the install's own
# when it is the operator, whose own files grant the operator nothing new.
# Call own_code_ready in this shell first, never inside $( ): the stage and
# its cleanup have to land here, not in a subshell.
own_code_ready() { [[ $EUID -ne 0 ]] || stage_install_for_root; }
own_code() { # $1 = path in the install; own_code_ready has run
  if [[ $EUID -eq 0 ]]; then
    printf '%s/%s' "$RUN_TREE" "$1"
  else
    printf '%s/%s' "$DIR" "$1"
  fi
}

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

  The Advisor attaches to an Aperire One install, and that install is an
  ordinary account's files: the checkout, the build cache, the database. A
  root-only login has none of them, so there is nothing here to attach to.

  Either of these is right, from the account that owns the install:

      curl -fsSL <url> | bash
      curl -fsSL <url> | sudo bash

  The first asks for your sudo password when it reaches the part that needs
  it. The second has it already.
EOF
    exit 1
  fi
}

# -- Finding the install ---------------------------------------------
#
# The dashboard's own unit is the answer, and it is the only one that cannot
# be wrong: it is what the running service reads from. WorkingDirectory is
# <install>/dashboard, so the install is its parent.
#
# --dir overrides it, because a host can legitimately carry a second pairing
# and only the operator knows which one this Advisor is for.
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
# a familiar name. Both files, because either alone is something else: a bare
# aperire-one script is a copy someone saved, and a bare scripts/ directory is
# any repository at all.
looks_like_an_install() { # $1 = directory
  [[ -f "$1/aperire-one" && -f "$1/scripts/install-advisord.sh" ]]
}

find_install() {
  local candidate
  if [[ $DIR_GIVEN -eq 1 ]]; then
    looks_like_an_install "$DIR" || die "$DIR is not an Aperire One install: it has no aperire-one and no scripts/install-advisord.sh."
    DIR_EVIDENCE="(you named it)"
    return 0
  fi
  if candidate="$(installed_dir_from_unit)" && looks_like_an_install "$candidate"; then
    DIR="$candidate"
    DIR_EVIDENCE="(from the installed dashboard unit)"
    return 0
  fi
  # The default location, for a host where the dashboard is not installed as a
  # service yet but the release is unpacked. Named as a guess, because that is
  # what it is.
  if looks_like_an_install "${OP_HOME}/aperire-one"; then
    DIR="${OP_HOME}/aperire-one"
    DIR_EVIDENCE="(found at the default location; no dashboard unit named one)"
    return 0
  fi
  refuse_no_install
}

# The refusal this script exists to make well. The Advisor is an add-on: there
# is no honest way to install it on a box with nothing to add it to, and
# fetching a release here would install the thing the operator did not ask for.
refuse_no_install() {
  cat >&2 <<EOF

${E_RED}error: there is no Aperire One install on this host.${E_OFF}

  The Advisor is an add-on. It reads the dashboard's own store and watches the
  node this box runs, so it needs an install to attach to, and this script
  will not create one: that is a different command, and a bigger decision than
  the one you just made.

  Install Aperire One first:

      ${E_CYAN}curl -fsSL https://get.aperire.one | bash${E_OFF}

  Then run this again. If the install IS here and lives somewhere unusual,
  name it:

      ${E_CYAN}curl -fsSL <url> | bash -s -- --dir /path/to/aperire-one${E_OFF}
EOF
  exit 1
}

# -- What is here already --------------------------------------------
advisor_unit() { printf 'aperire-advisord%s' "${APERIRE_INSTANCE:+-$APERIRE_INSTANCE}"; }

advisor_unit_installed() {
  [[ -n "$(systemctl list-unit-files "$(advisor_unit).service" 2>/dev/null | grep '\.service' || true)" ]]
}

# The token every /v1 endpoint requires, reads included. Without it the check
# below gets a 401 and reports a working service as broken.
# Read as this account first, then through a NON-INTERACTIVE sudo. Never
# `sudo` plainly: this runs before the sudo announcement, and a password
# prompt appearing there, with no line saying what it is for, is exactly the
# thing announce_sudo exists to prevent. A read that cannot happen yet is
# reported as "not answering", which is what the caller does with it anyway.
# Every read goes through state-file.py, which opens the name without
# following a link and from a walk of its parents (#703 item 5). A plain
# `cat` of a name in a directory the Advisor's own account owns, run by root
# (`curl ... | sudo bash`), follows a link there and sends the target's
# lines out as a bearer token to whoever holds the Advisor's port. As root
# the tool is the staged copy, never the tree's own; as the operator it is
# the install's own, which grants the operator nothing new, and a read it
# cannot make falls back to a NON-INTERACTIVE sudo, through the root-held copy.
advisor_token() {
  local tok="$DIR/advisor/state/approve.token" tool
  if [[ $EUID -eq 0 ]]; then
    tool="$(own_code scripts/state-file.py)"
    [[ -r "$tool" ]] || return 0
    python3 -I "$tool" read "$tok" 2>/dev/null | tr -d '\n'
    return 0
  fi
  tool="$DIR/scripts/state-file.py"
  if [[ ! -r "$tool" ]]; then
    # A checkout older than the helper. This account reads its own
    # group-shared file, which holds no privilege to redirect, as it always
    # did; the sudo leg below needs the helper and is not tried.
    python3 -I -c 'import sys;sys.stdout.write(open(sys.argv[1]).read())' "$tok" 2>/dev/null | tr -d '\n'
    return 0
  fi
  # The sudo leg runs the root-held copy of the helper, never the tree's:
  # sudo -n on a file in a folder the Advisor's account can write is root
  # running whatever it left there (#886). A host with no root-held copy has
  # no sudo leg, and the read above is all there is.
  # A constant, never read from the environment (#1127), and checked before
  # the sudo: a regular file, not a link, owned by root, writable by neither
  # group nor other.
  local root_tool=/usr/local/sbin/aperire-state-file root_uid=0 meta
  {
    python3 -I "$tool" read "$tok" 2>/dev/null \
      || { [[ -f "$root_tool" && ! -L "$root_tool" && -r "$root_tool" ]] \
           && meta="$(stat -c '%u:%a' -- "$root_tool" 2>/dev/null)" \
           && [[ "${meta%%:*}" == "$root_uid" ]] && (( (8#${meta##*:} & 8#022) == 0 )) \
           && sudo -n python3 -I "$root_tool" read "$tok" 2>/dev/null; }
  } | tr -d '\n'
}

ADVISOR_STATUS=""
advisor_answers() {
  local token
  # In this shell, never inside the $( ) below: as root the stage has to land
  # here so its cleanup runs.
  own_code_ready
  token="$(advisor_token)"
  [[ -n "$token" ]] || return 1
  # On curl's standard input, never its argv: /proc/<pid>/cmdline is world
  # readable (#705).
  ADVISOR_STATUS="$(curl -fsS --max-time 3 -H @- \
    "http://127.0.0.1:${PORT}/v1/status" 2>/dev/null <<<"authorization: Bearer $token")" || return 1
  [[ -n "$ADVISOR_STATUS" ]]
}

# Whether the Advisor it just answered has a model. Read from the answer rather
# than from a file, because the service reporting on itself is the fact and
# model.json is only the intent. A status this cannot read is not evidence of
# a model: absent is not "configured".
advisor_has_model() {
  case "$ADVISOR_STATUS" in
    *'"configured":true'*|*'"configured": true'*) return 0 ;;
    *) return 1 ;;
  esac
}

# -- The reveal window, on a host that is already answering (#644) ---
#
# advisor/state/reveal.window is root's own mark that a human with real sudo
# stood at THIS box recently. It gates an aggregator attaching this node's
# Advisor to an already-paired link, and it lapses after 900 seconds on
# purpose. The Add an Advisor card's "the window has closed" copy box hands the
# operator this very one-liner to open another.
#
# It used to not do that. Both branches below return before
# install-advisor-stack.sh's step 1 (install-advisord.sh) is ever reached, and
# that plant is one of only two in the tree, so the documented recovery command
# was a no-op on exactly the host it is written for: one whose Advisor is
# already installed and answering.
#
# The plant lives HERE, in the bootstrap, rather than behind a new flag on
# install-advisor-stack.sh, and the reason is version skew. The one-liner
# fetches THIS file fresh from the URL every time, but run_stack invokes
# "$DIR/scripts/install-advisor-stack.sh", the copy already on disk. A new flag
# there would meet `die "unknown argument"` on every host installed before this
# change, which is the entire population that needs the recovery. Three lines
# in the file that is always current beats a flag in the file that is not.
#
# Root-owned, deliberately, exactly as install-advisord.sh plants it: a window
# the dashboard's own account could open at will is the same as no window. The
# group is read from the Advisor's own unit when this host has moved onto a
# dedicated account, so the dashboard keeps its group read; the invoking
# account's group is the fallback on a host that has not moved, which is what
# install-advisord.sh falls back to as well.
#
# A fresh root-owned inode, not a truncate: a plain `: >` keeps whatever owner
# the file drifted to, and on a moved host that is the Advisor's own account.
reveal_window_group() {
  local unit grp=""
  unit="/etc/systemd/system/$(advisor_unit).service"
  if [[ -r "$DIR/scripts/advisor-owner-lib.sh" ]]; then
    local owner_lib
    own_code_ready
    owner_lib="$(own_code scripts/advisor-owner-lib.sh)"
    # shellcheck source=scripts/advisor-owner-lib.sh
    . "$owner_lib"
    grp="$(advisor_owner_shared_group "$unit" "$OP_USER" 2>/dev/null || true)"
  fi
  printf '%s' "${grp:-$(id -gn "$OP_USER" 2>/dev/null || id -gn)}"
}

# Planted through scripts/state-file.py, not `install` (#661). GNU install
# finishes with fchmodat on the PATH and no nofollow flag, so the account that
# owns advisor/state can unlink the file install just created, put a symlink at
# the same name, and have root chmod that link's target to 0640. Measured on
# Ubuntu 24.04 with coreutils 9.4, by the racer in
# scripts/test-install-advisor-account.sh: 39 to 150 wins out of 150 across
# runs, on two machines. The
# helper creates the file relative to a descriptor on the directory and never
# resolves a name after that.
#
# It also needs `sudo` to reach the helper, which is why the helper is a
# program and not a shell function: run_root execs, and a function does not
# survive an exec.
#
# THE TRADE, and it is the one thing about this function worth arguing with.
# This file is fetched fresh from the URL on every run, but the helper comes
# from "$DIR/scripts", the copy already on disk, and that copy is whatever
# version the host last installed. A host old enough to predate the helper
# gets a refusal naming the update command rather than a window. That is
# deliberate: the alternative is falling back to `install` on exactly the hosts
# the recovery exists for, which would be reopening #661 where it is most
# likely to be exercised. An operator who updates gets both.
#
# Asked BEFORE the sudo prompt by the branch whose only reason to ask is this
# plant. A password typed for a file that was never going to be written is the
# worst version of this trade.
replant_is_possible() { [[ -r "$DIR/scripts/state-file.py" ]]; }
say_replant_impossible() {
  warn "this install predates the safe state-file plant, so no window was opened."
  dim "Update this install first, then run this command again:"
  dim "    bash ${DIR}/aperire-one   then Install & upgrade, entry 6."
}

replant_reveal_window() {
  local marker="$DIR/advisor/state/reveal.window" grp gid tool
  # Staged here, in this shell, before the group is read inside $( ) below.
  own_code_ready
  grp="$(reveal_window_group)"
  gid="$(getent group "$grp" 2>/dev/null | cut -d: -f3)"
  if ! replant_is_possible; then
    say_replant_impossible
    return 1
  fi
  # Root runs the staged copy of the state tool, never the tree's (#764).
  stage_install_for_root
  tool="$RUN_TREE/scripts/state-file.py"
  if [[ -z "$gid" ]]; then
    warn "the group ${grp} has no gid on this host, so the window has no group to be read through."
    return 1
  fi
  if run_root python3 -I "$tool" plant "$marker" 0 "$gid" 0640; then
    ok "a fresh 15 minute window is open: root:${grp} 0640 at advisor/state/reveal.window"
    return 0
  fi
  warn "the reveal window could not be replanted at $marker."
  dim "The dashboard's Add an Advisor card will still say the window has closed."
  return 1
}

# The wrapper's configuration, and the program that reads it. A host whose
# Advisor is installed but whose wrapper was never configured (#915 left
# some that way) refuses every gated verb with rc 64, and re-running this
# command used to refresh the sockets and leave it so (#917).
#
# Both paths are constants as root, and an instance's are derived the way the
# installer and the wrapper derive them. Only an unprivileged test run may
# point the default pair elsewhere.
WRAPPER_PATHS_SET=0
wrapper_paths() {
  [[ $WRAPPER_PATHS_SET -eq 1 ]] && return 0
  WRAPPER_CONF=/etc/aperire/node-wrapper.conf
  WRAPPER_BIN=/usr/local/sbin/aperire-node-wrapper
  # On positive evidence of an unprivileged account only, from id(1) and not
  # bash's $EUID, which bash imports from the environment (#1109).
  local _wp_uid
  _wp_uid="$(/usr/bin/id -u 2>/dev/null || true)"
  if [[ "$_wp_uid" =~ ^[0-9]+$ && "$_wp_uid" != 0 ]]; then
    WRAPPER_CONF="${APERIRE_ADVISOR_GET_WRAPPER_CONF:-$WRAPPER_CONF}"
    WRAPPER_BIN="${APERIRE_ADVISOR_GET_WRAPPER_BIN:-$WRAPPER_BIN}"
  fi
  if [[ -n "${APERIRE_INSTANCE:-}" ]]; then
    local lib def="$WRAPPER_CONF" bin conf
    STAGE_SOFT=1
    own_code_ready || { STAGE_SOFT=0; return 1; }
    STAGE_SOFT=0
    lib="$(own_code scripts/trusted-path-lib.sh)"
    [[ -r "$lib" ]] || return 1
    # A subshell, so the library's variables stay out of this script, and as
    # root its environment overrides are dropped first.
    # shellcheck disable=SC2016  # the subshell's own positional parameters
    bin="$(bash -c 'u=$(/usr/bin/id -u 2>/dev/null); [[ "$u" =~ ^[0-9]+$ && "$u" != 0 ]] || unset APERIRE_SBIN_DIR APERIRE_CONF_DIR
      . "$1" && trusted_valid_instance "$2" && trusted_wrapper_path "$2"' x "$lib" "$APERIRE_INSTANCE")" || return 1
    # shellcheck disable=SC2016
    conf="$(bash -c 'u=$(/usr/bin/id -u 2>/dev/null); [[ "$u" =~ ^[0-9]+$ && "$u" != 0 ]] || unset APERIRE_SBIN_DIR APERIRE_CONF_DIR
      . "$1" && trusted_wrapper_conf "$2" "$3"' x "$lib" "$APERIRE_INSTANCE" "$def")" || return 1
    [[ -n "$bin" && -n "$conf" ]] || return 1
    WRAPPER_BIN="$bin"
    WRAPPER_CONF="$conf"
  fi
  WRAPPER_PATHS_SET=1
}

# The file is root-owned 0644 in a 0755 directory, so this needs no sudo. A
# host whose paths cannot be worked out is not called missing: nothing is
# known, so nothing is repaired.
wrapper_conf_missing() { wrapper_paths && [[ ! -e "$WRAPPER_CONF" ]]; }

# Root runs the installed wrapper only when it is a regular file of root's that
# no group or other can write, the same test the checking libraries get.
wrapper_bin_trusted() {
  local meta want_uid=0
  [[ $EUID -eq 0 ]] || want_uid="$(run_root id -u 2>/dev/null || echo 0)"
  meta="$(run_root stat -c '%F:%u:%a' -- "$WRAPPER_BIN" 2>/dev/null)" || return 1
  [[ "${meta%%:*}" == "regular file" ]] && [[ "$(cut -d: -f2 <<<"$meta")" == "$want_uid" ]] \
    && (( (8#${meta##*:} & 8#022) == 0 ))
}

# Does the installed wrapper work with its configuration? `resources` is read
# only and needs no node, so it answers the same on a container, a native
# package, an aggregator (SERVICE=none) and a host whose node is stopped.
# `status` asks the node, which refuses on an aggregator and fails on a
# stopped one, and neither is a broken wrapper.
wrapper_answers() { wrapper_bin_trusted && run_root "$WRAPPER_BIN" resources >/dev/null 2>&1; }

# Does this host run a node? Yes unless it can be shown that it does not, so a
# host the Advisor cannot read is repaired as it always was (#1129). The signs,
# in the order the node installers leave them:
#
#   /etc/aperire/node.conf          written by the node installer
#   a native unit                   xrpld, rippled or xahaud, loaded
#   a running container             an image named for rippled, xrpld or
#                                   xahaud, or one docker shows only as an id
#                                   (created from a digest), which may be it
#
# The container list is read by root, as the wrapper installer reads it, and
# it is a fixed read-only question: `docker ps` with a format. Docker present
# and unwilling to answer is "cannot tell", which is not "none".
host_runs_a_node() {
  local nconf=/etc/aperire/node.conf u rows rc=0
  [[ $EUID -eq 0 ]] || nconf="${APERIRE_ADVISOR_GET_NODE_CONF:-$nconf}"
  [[ -e "$nconf" ]] && return 0
  for u in xrpld rippled xahaud; do
    [[ "$(systemctl show -p LoadState --value "$u.service" 2>/dev/null)" == loaded ]] && return 0
  done
  command -v docker >/dev/null 2>&1 || return 1
  rows="$(run_root docker ps --format $'{{.Names}}\t{{.Image}}' 2>/dev/null)" || rc=$?
  (( rc == 0 )) || return 0
  grep -Eiq '(rippled|xrpld|xahaud)' <<<"$rows" && return 0
  grep -Eq $'\t(sha256:)?[0-9a-fA-F]{12,64}$' <<<"$rows" && return 0
  return 1
}

# Set when the repair ran the installer, so the closing line stays true.
WRAPPER_REPAIRED=0

# Configure the wrapper the way a fresh install does: the installer root runs
# is the staged, checked copy, never the one in the operator's tree (ADR 0024).
# Root is already held by the caller. Configured and working is left alone;
# missing, or one that does not answer, is repaired. A repair that does not
# take is said plainly and is not fatal, as in install-advisord.sh: the Advisor
# still reads and explains.
repair_wrapper_if_unconfigured() {
  wrapper_paths || { warn "the wrapper's paths for instance '${APERIRE_INSTANCE:-}' could not be worked out, so it was not checked."; return 0; }
  if ! wrapper_conf_missing && wrapper_answers; then
    return 0
  fi
  # A host that runs no node has nothing for a wrapper to act on, so a missing
  # configuration there is not a fault and the installer would only end in
  # "could not find a running node container" (#1129). Said once, quietly.
  if wrapper_conf_missing && ! host_runs_a_node; then
    info "this host runs no node, so the Advisor here acts on none."
    return 0
  fi
  step "configuring the privilege wrapper"
  if wrapper_conf_missing; then
    info "$WRAPPER_CONF is missing, so every action the Advisor proposes would be refused."
  else
    info "$WRAPPER_BIN did not answer a read-only check with $WRAPPER_CONF, so it is configured again."
  fi
  info "running the checked copy of install-node-wrapper.sh, as a fresh install does"
  STAGE_SOFT=1
  if ! stage_install_for_root; then
    STAGE_SOFT=0
    warn "the checked copy could not be staged, so the wrapper was not configured (the reason is above)."
    return 0
  fi
  STAGE_SOFT=0
  WRAPPER_REPAIRED=1
  local rc=0
  run_root env "${NO_COLOR_ENV[@]}" APERIRE_INSTALL_TREE="$DIR" APERIRE_INSTANCE="${APERIRE_INSTANCE:-}" \
    bash "$RUN_TREE/scripts/install-node-wrapper.sh" < /dev/null || rc=$?
  if [[ $rc -eq 0 ]]; then
    ok "the wrapper is configured"
  else
    warn "install-node-wrapper.sh exited $rc, so the wrapper may still be unconfigured."
    info "everything else works. Run this again once the lines above are dealt with."
  fi
}

# Already installed and answering is not a failure and not a reason to
# reinstall. Say what is here, replant the window the recovery copy promises,
# and point at the one remaining step.
already_have_advisor() {
  step "----- the Advisor is already installed here -----"
  ok "$(advisor_unit) is running, and answered on http://127.0.0.1:${PORT}/v1/status"

  if advisor_has_model; then
    # Nothing is installed, built or moved here. One thing IS done, and it is
    # the only reason a complete host would be running this command at all:
    # the reveal window is replanted, so an aggregator can attach this node's
    # Advisor. That needs root, which is why this branch asks for sudo where
    # it used to claim nothing was changed and exit.
    if replant_is_possible; then
      cat <<EOF

  It has a language model, so nothing needs installing, building or moving.
  Opening a fresh window, so this node's Advisor can be attached from a
  dashboard that already knows this box.

EOF
      announce_sudo_window_only
      ensure_sudo
      local planted=0
      replant_reveal_window && planted=1
      repair_wrapper_if_unconfigured
      if [[ $planted -eq 1 ]]; then
        if [[ $WRAPPER_REPAIRED -eq 1 ]]; then
          printf '\n  That, and the wrapper'"'"'s configuration, is all that changed.\n'
        else
          printf '\n  That is all that changed.\n'
        fi
      fi
    else
      # Neither the promise nor the sudo prompt. Root was wanted for one file,
      # this host has no way to write that file safely, so there is nothing to
      # announce and nothing to ask for.
      cat <<EOF

  It has a language model, so nothing needs installing, building or moving.

EOF
      say_replant_impossible
      # Root is asked for only when the wrapper is missing; a host whose
      # wrapper is in place has nothing here that needs it.
      if wrapper_conf_missing; then
        announce_sudo_wrapper_only
        ensure_sudo
        repair_wrapper_if_unconfigured
      fi
    fi
    cat <<EOF

  To change the model, or to move the Advisor onto its own account if it is
  still on yours:

      ${S_CYAN}bash ${DIR}/aperire-one${S_OFF}

  and choose ${S_BOLD}3) Advisor${S_OFF}.

EOF
    exit 0
  fi

  # Keyless. This is the host that most needs the one command to do something,
  # and the something is a window: the browser model step is a fifteen minute
  # arming that only root can open, so an operator whose window lapsed has to
  # be able to open another without learning a second command.
  cat <<EOF

  It has ${S_BOLD}no language model${S_OFF} yet, so it cannot answer questions. Opening a
  window so the dashboard can set one up.

EOF
  announce_sudo_sealer_only
  ensure_sudo
  # The wrapper first (#935). The sealer in the next step asks the node who it
  # is and finds the node's admin address in the wrapper's configuration, so a
  # host whose configuration is missing used to be told "not stamped" by a
  # sealer that was about to have its answer written one step later. A fresh
  # install configures the wrapper in step 1 of the stack, before the sealer;
  # this is the same order for the host that is already here.
  repair_wrapper_if_unconfigured
  # The grants and the trust store, and nothing else. Rebuilding a service that
  # is answering, or moving an account that is already moved, to open a window
  # would be work nobody asked for on the host that asked for the least.
  run_stack --grants-only || true
  # --grants-only runs steps 2, 3 and 5 of the stack, and step 1
  # (install-advisord.sh) is the only one of them that plants the reveal
  # window, so this path never replanted it either (#644). Here rather than
  # inside the stack, for the version-skew reason in replant_reveal_window's
  # own header.
  replant_reveal_window || true
  banner_model_step
  exit 0
}

# The narrowest announcement of the three. This host is complete: nothing is
# built, no account is created, no grant is installed. One root-owned marker
# with a fresh timestamp is the entire change, and naming the sealer and the
# trust socket here would name work that is not about to happen.
announce_sudo_window_only() {
  cat <<'EOF'
  What needs root here, and what for:

    advisor/state/reveal.window    one empty root-owned file, replanted so its
                       timestamp is now. It is how a dashboard knows a human
                       stood at this box in the last fifteen minutes, which is
                       half of what attaching this node's Advisor requires.
                       It holds no content and it is never read, only dated.

  Nothing else. It lapses by itself after fifteen minutes.
EOF
}

# For a complete host whose only gap is the wrapper's configuration.
announce_sudo_wrapper_only() {
  cat <<'EOF'
  What needs root here, and what for:

    /etc/aperire/node-wrapper.conf   the privilege wrapper's configuration,
                       root-owned. It is missing, so every action the Advisor
                       proposes is refused. It is written from the deployment
                       on this host, by a checked copy of the installer.

  Nothing else.
EOF
}

# The short form, for the already-installed path. Nothing is being built or
# moved there, so listing the toolchain and the account would name work that
# is not about to happen.
announce_sudo_sealer_only() {
  cat <<'EOF'
  What needs root here, and what for:

    two private sockets the dashboard may reach ONE root program through each.
                       Behind one is the model-key sealer, which takes no
                       arguments, reads a key on standard input and seals once
                       per arming. Behind the other is the trust sync, which
                       rebuilds the Advisor's copy of your passkeys from the
                       dashboard's own database, so a passkey enrolled in the
                       browser reaches the Advisor without a command here.
                       Both sockets are the dashboard account's alone (0600).
    /etc/aperire       the arming marker, root-owned, which lapses on its own

  Nothing else. Removing them again is two commands:
    curl -fsSL https://get.aperire.one | bash -s -- --run model-key-sealer --remove
    curl -fsSL https://get.aperire.one | bash -s -- --run trust-sync-grant --remove
EOF
}

# -- The plan, before anything is done -------------------------------
confirm_plan() {
  local reply
  step "the plan"
  info "install    the Advisor, on this host"
  info "for        ${DIR}  ${DIR_EVIDENCE}"
  info "listening  127.0.0.1:${PORT}, loopback only; the binary refuses any other address"
  info "as         its own account, reaching the node through one root socket (no sudo)"
  info "first      a build. The Advisor is Go, and a dashboard installed without"
  info "           it has no Advisor binaries, so they are compiled here. Under a"
  info "           minute on most boxes, and skipped when they are already current."
  echo
  dim "It reads. Every action it can take on your node comes back to you for a"
  dim "passkey first, and the list of those actions is one reviewable script."
  echo
  if [[ $ASSUME_YES -eq 1 ]] || ! have_tty; then
    return 0
  fi
  reply="$(ask "Go ahead? [Y/n]" y)"
  case "$reply" in
    y|Y|yes|YES|"") ;;
    *) echo; info "nothing was installed."; exit 0 ;;
  esac
}

# -- Sudo, stated before it is asked for -----------------------------
announce_sudo() {
  cat <<'EOF'

  What needs root here, and what for:

    systemd unit     aperire-advisord, so it comes back after a reboot
    a service account  the Advisor gets its own, so its files are not yours
    one root socket    the only way that account reaches root, and no sudo
                       rule at all: root checks the caller's uid, takes one
                       verb from a fixed list, and runs the privilege
                       wrapper, the entire list of things the Advisor can do
                       to your node, reviewable in one file.
    the toolchain    Go, and only when this host has none new enough. Pinned
                       version, checked against a recorded sha256, into
                       /usr/local/go. The build itself runs as your own account.
    /etc/aperire     the wrapper's configuration, root-owned
    a private socket  so the model step can happen in your browser: the
                       dashboard may reach ONE root program through it, the
                       model-key sealer, which takes no arguments and seals
                       once per arming. It cannot arm itself, and the socket is
                       the dashboard account's alone (0600). Sealing needs root
                       whichever way this host keeps the key, and there is no
                       way to delegate that.
    a second socket   so a passkey enrolled in your browser reaches the
                       Advisor by itself: one root program behind it rebuilds
                       the Advisor's copy of your passkeys from the dashboard's
                       own database. Nothing the dashboard sends goes into that
                       copy. Same shape, same 0600, same one program.

  Nothing else, and nothing outside that list. The checkout and the build stay
  yours: they run as your own account, never as root.
EOF
  say_model_key_method
}

# How this host will keep the model API key, said before anything is
# installed (#708). Two ways, and which one a host uses is a fact about its
# systemd, not a choice. A 22.04 box used to install cleanly and then refuse
# every key with a sentence about systemd-creds, which is the wrong place to
# learn it.
say_model_key_method() {
  local lib
  [[ -r "$DIR/scripts/model-key-method-lib.sh" ]] || return 0
  own_code_ready
  lib="$(own_code scripts/model-key-method-lib.sh)"
  # shellcheck source=scripts/model-key-method-lib.sh
  . "$lib"
  printf '\n  The model key on this host: %s\n' "$(aperire_key_method_line "$(aperire_key_method)")"
}

ensure_sudo() {
  [[ $EUID -eq 0 ]] && return 0
  command -v sudo >/dev/null 2>&1 \
    || die "this host has no sudo, and the Advisor needs root for the things listed above."
  sudo -n true 2>/dev/null && return 0
  if ! have_tty; then
    die "sudo wants a password and there is no terminal to ask on. Run it as: curl -fsSL <url> | sudo bash"
  fi
  sudo -v || die "sudo was refused, so nothing was installed."
}

# -- Build -----------------------------------------------------------
#
# scripts/prepare-host.sh owns the toolchain and the builds, for every
# component, and this is where the Advisor's turn comes. It is not optional and
# it is not a duplicate of install.sh's call: a host installed WITHOUT
# --with-advisor has no Advisor binaries and no reason to have had them, so
# adding the Advisor later has to build them now. The first live ceremony hit
# exactly that, and then hit it a second way, because install-advisord.sh could
# not see the Go this project itself had installed.
#
# Idempotent and quick when there is nothing to do: prepare-host compares the
# binaries against their sources and says so rather than rebuilding.

# The role prepare-host is told, worked out from what this host actually has.
#
# Not from a config file: nothing records a role. /etc/aperire/aperire.env
# holds the relay token and the port and has never held a role, so reading one
# out of it would be a lookup that always misses and a comment that lies. The
# units are the record, the same way the dashboard's own unit is the record of
# where this install lives.
#
# It decides one thing here: whether prepare-host also tends the relay's
# toolchain and binary. Go comes from APERIRE_WITH_ADVISOR=1 either way.
install_role() {
  # A relay unit on this box means a node runs here and something reports it.
  if systemctl list-unit-files 'aperire-relay*' 2>/dev/null | grep -q '\.service'; then
    printf 'co-located'
    return 0
  fi
  # No relay: this box watches nodes that live elsewhere. Saying co-located
  # here would have prepare-host build a relay nothing on this host runs.
  printf 'dashboard'
}

run_build() {
  local role
  role="$(install_role)"
  step "building the Advisor"
  info "running ${DIR}/scripts/prepare-host.sh as role '${role}', with the Advisor"
  dim "role from this host's own units: $([[ "$role" == co-located ]] && echo 'a relay runs here' || echo 'no relay here, so this box watches others')"
  dim "it owns the toolchain and the builds; it is quick when nothing has changed"
  stage_install_for_root
  run_root env "${NO_COLOR_ENV[@]}" APERIRE_ROLE="$role" APERIRE_WITH_ADVISOR=1 APERIRE_INSTALL_TREE="$DIR" \
    bash "$RUN_TREE/scripts/prepare-host.sh" < /dev/null \
    || die "prepare-host.sh did not finish, so there is nothing to install. Read what it printed above."
}

# -- Install ---------------------------------------------------------
#
# One script, and this one owns none of it. scripts/install-advisor-stack.sh
# runs the service installer, both root grants, the account move, the trust
# sync and the read-back, in that order, and says for itself what each one did
# or could not do. `sudo bash install.sh --with-advisor` runs the same script
# with the same flags, which is what makes the two ways in one host: before it
# existed the flag path installed neither grant, so that host had no browser
# model step and a passkey enrolled in the browser never reached its Advisor.
#
# What stays here is what only this path has: the sentinel, the re-exec, the
# search for the install, the refusal when there is none, the sudo
# announcement, the build, and the closing text once the read-back has passed.
#
# The tries and the sleep are passed rather than exported. sudo's env_reset
# drops anything not on its allow-list, so a value that reached the stack in a
# test through a fake sudo would be silently dropped by the real one, and a
# host would quietly take the defaults.
STACK_REPORT=""
run_stack() { # any extra flags are appended
  stage_install_for_root
  run_root env "${NO_COLOR_ENV[@]}" APERIRE_INSTALL_TREE="$DIR" \
    bash "$RUN_TREE/scripts/install-advisor-stack.sh" \
      --dir "$DIR" --port "$PORT" --instance "${APERIRE_INSTANCE:-}" \
      --tries "$HEALTH_TRIES" --sleep "$HEALTH_SLEEP" \
      --report "$STACK_REPORT" --yes "$@" < /dev/null
}

# What the stack reported, for the closing text that is this script's to print.
# Fail-closed: a run that died before writing the file, or a key that is not in
# it, answers 0. A missing measurement is never a passing one, so the banner
# below claims nothing the stack did not report having done.
stack_said() { # $1 = key
  local v
  [[ -n "$STACK_REPORT" && -r "$STACK_REPORT" ]] || { printf '0'; return 0; }
  v="$(sed -n "s/^$1=//p" "$STACK_REPORT" 2>/dev/null | head -1)"
  printf '%s' "${v:-0}"
}

banner() {
  step "----- the Advisor is installed, and answering -----"
  if [[ "$(stack_said account_moved)" == "1" ]]; then
    ok "on its own account, reaching the node through its root socket"
  fi
  cat <<EOF

  It listens on ${S_CYAN}127.0.0.1:${PORT}${S_OFF} and nowhere else. The dashboard reaches it
  behind your session, and an Advisor tab is now on the dashboard: it reports
  what this node is doing, and it refuses to act until you approve with a
  passkey.

EOF
  banner_model_step
}

# The one step left, and where it happens. The text is the stack's, printed
# from the one file both install paths share: `install.sh --with-advisor` ends
# with these same four steps, and two copies of an instruction is how they stop
# being the same instruction. Which of the two branches it takes is decided by
# whether the sealer armed, which the stack reported; a host whose browser
# cannot seal is given the terminal instead.
#
# Run as this account, not through run_root: it prints, and printing needs
# nothing. It also says nothing about itself, because the banner is not the
# place to name an internal script.
banner_model_step() {
  local stack
  own_code_ready
  stack="$(own_code scripts/install-advisor-stack.sh)"
  APERIRE_INSTALL_TREE="$DIR" bash "$stack" \
    --model-steps --dir "$DIR" --report "$STACK_REPORT"
}

# -- main ------------------------------------------------------------
main() {
  trap cleanup_temporaries EXIT

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --dir)      DIR="${2:?--dir needs a path}"; DIR_GIVEN=1; shift 2 ;;
      --dir=*)    DIR="${1#*=}"; DIR_GIVEN=1; shift ;;
      --port)     PORT="${2:?--port needs a number}"; shift 2 ;;
      --port=*)   PORT="${1#*=}"; shift ;;
      --yes|-y)   ASSUME_YES=1; shift ;;
      -h|--help)  usage; exit 0 ;;
      *)          die "unknown argument: $1 (run with --help)" ;;
    esac
  done

  # A port that is not a number would be asked for in a URL, and the check
  # would fail for a reason nothing names.
  [[ "$PORT" =~ ^[0-9]+$ && $PORT -ge 1 && $PORT -le 65535 ]] \
    || die "--port takes a number from 1 to 65535, not '$PORT'."

  guard_privilege
  find_install

  # Where the stack reports what it did, for the closing text below. A private
  # directory of this account's, and the stack creates the file INSIDE it.
  # Not a file minted here: root writing into a file another account owns in
  # /tmp is refused on Ubuntu (fs.protected_regular), and that is exactly what
  # happened on the first live run (aperire4, 2026-09-07: "Permission denied"
  # at the stack's first write, after the build). A new file in a directory
  # this account owns, mode 700, is allowed, root-owned, world-readable by
  # default umask, and the directory is removed however this run ends.
  STACK_REPORT_DIR="$(mktemp -d -t aperire-advisor-stack.XXXXXXXX)"
  STACK_REPORT="$STACK_REPORT_DIR/report"
  CLEANUP_PATHS+=("$STACK_REPORT_DIR")

  # Installed and answering already: nothing to do, and saying so is the whole
  # answer. An installed unit that is NOT answering is a repair, and running
  # the installers again is what repairs it, so that case falls through.
  if advisor_unit_installed && advisor_answers; then
    already_have_advisor
  fi

  confirm_plan
  announce_sudo
  ensure_sudo

  run_build
  # The banner is printed only when this returns 0, and it returns 0 only after
  # the service was read back as enabled, running and answering. A stack that
  # refused said why; there is nothing to add to it here. Its own code goes
  # out with it: 3 is an Advisor that answers but stayed on the dashboard's
  # account (#806), and the stack's closing block already named the step.
  local stack_rc=0
  run_stack || stack_rc=$?
  (( stack_rc == 0 )) || exit "$stack_rc"
  banner
}

main "$@"
# --- end of get-aperire-advisor.sh ---
