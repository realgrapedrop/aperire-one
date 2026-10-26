#!/usr/bin/env bash
# preflight.sh - what this host is missing, said before anything is installed.
#
#   bash scripts/preflight.sh --role co-located
#   bash scripts/preflight.sh --role dashboard --json
#   curl -fsSL https://get.aperire.one | bash -s -- --check
#
# Why it exists: every refusal in this tree used to arrive minutes into a
# build. No sqlite3, a port already held, a clock nobody had synchronised, a
# node the dashboard would never find - all of them true before the first apt
# call, all of them said after `npm ci` and two Go builds had already run. So
# the whole list is measured up front, printed as one checklist, and anything
# that would stop the install stops it here, where nothing has been changed
# yet and the fix is one command.
#
# Three verdicts, and only one of them blocks:
#
#   ok       measured, and it is what the install needs
#   warn     measured, degraded, and the install still works. Never blocks
#   MISSING  the install cannot succeed until this is fixed. Blocks, and
#            --yes does not skip it: an unattended run that installs half a
#            product is worse than one that refuses
#
# Every line carries the value that was MEASURED, not the fact that a check
# ran. "ok  disk: 41 GB free on /home" can be read back by hand; "ok  disk"
# cannot, and the difference is the whole point of printing it.
#
# Flags:
#   --role <r>          co-located | dashboard | validator | relay | cli-only
#                       (relay is the bootstrap's name for validator)
#   --instance <name>   the ADR 0009 instance, so its ports are the ones checked
#   --port <n>          dashboard port to check (default 7800)
#   --advisor-port <n>  Advisor port to check (default 7810)
#   --with-advisor      the Advisor is wanted, so docker and its port count
#   --dir <path>        where the install will live, for the disk check
#   --answer-file <p>   where to write what the node question was answered with
#   --yes               take defaults, ask nothing. Never skips a MISSING
#   --check             report only: never prompt, never write an answer file
#   --json              the same results as a JSON array, and no prompts
#   -h, --help
#
# Exit status: 0 when nothing is MISSING, 1 when something is.
#
# ---- how the node answer reaches the install ------------------------
#
# The node probe can end with an operator typing a port number. That answer
# has to survive four hops or it was never asked for:
#
#   preflight.sh --answer-file <path>      writes RIPPLED_URL=ws://host:port,
#                                          and NODE_SHAPE / NODE_CONTAINER for
#                                          the node it found
#   get-aperire.sh / install.sh            read that file
#   install.sh                             exports APERIRE_RIPPLED_URL
#   install-aperire-service.sh             writes RIPPLED_URL= into
#                                          /etc/aperire/aperire.env, once
#
# A FILE rather than an environment variable, because preflight runs as a
# child process and a child cannot export into its parent. The file is the
# caller's to make and to delete; this script only writes into it.
#
# Sourced or executed. Nothing here sets a shell option, because a sourced
# file that turns on errexit changes the caller, and because a preflight
# whose probes may not fail is a preflight that dies on the first host it was
# written for. Every probe here is allowed to fail; failing is the answer.

# ---- where we are --------------------------------------------------
# SCRIPT_DIR, spelled the way every other installer in scripts/ spells it, and
# deliberately: scripts/check-script-refs.sh reads that spelling to know this
# file depends on term-style.sh, docker-ask-lib.sh and detect-rippled-paths.sh,
# and a release built without one of them is a release whose checklist refuses
# to start.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ -r "${SCRIPT_DIR}/term-style.sh" ]]; then
  # shellcheck source=scripts/term-style.sh
  . "${SCRIPT_DIR}/term-style.sh"
else
  echo "error: ${SCRIPT_DIR}/term-style.sh is missing from this checkout" >&2
  exit 1
fi

# ---- what the run was asked to do ----------------------------------
PF_ROLE=""
PF_INSTANCE=""
PF_PORT="${APERIRE_PORT:-7800}"
PF_ADVISOR_PORT="${APERIRE_ADVISOR_PORT:-7810}"
PF_WITH_ADVISOR=0
PF_DIR=""
PF_ANSWER_FILE=""
PF_YES=0
PF_JSON=0
PF_CHECK_ONLY=0
# Set by the bootstrap when the role came out `dashboard` because its probe
# found no node, not because the operator said so. A box with no node YET
# is the same reading, and that one wants the node installer, not a fleet.
PF_ROLE_GUESSED=0

# Overridable so the tests can point every path somewhere harmless. A test
# that had to create /etc/aperire would be an install.
PF_ETC="${APERIRE_PREFLIGHT_ETC:-/etc/aperire}"
PF_OS_RELEASE="${APERIRE_PREFLIGHT_OS_RELEASE:-/etc/os-release}"
PF_PROBE_HOST="${APERIRE_PREFLIGHT_HOST:-127.0.0.1}"
# The bundle ca-certificates installs. It ships no command of its own, so the
# file IS the measurement.
PF_CA_BUNDLE="${APERIRE_PREFLIGHT_CA_BUNDLE:-/etc/ssl/certs/ca-certificates.crt}"
# The hosts the install downloads from, checked in this order. nvm's installer
# comes from raw.githubusercontent.com, the Node tarballs from nodejs.org, the
# Go tarball from go.dev, and the release itself from get.aperire.one
# (scripts/prepare-host.sh and the release stamp in scripts/get-aperire.sh).
PF_EGRESS_HOSTS="${APERIRE_PREFLIGHT_EGRESS:-https://github.com https://raw.githubusercontent.com https://go.dev/dl/ https://nodejs.org https://get.aperire.one}"
# The ports v3 tried, in v3's order, and the config files this tree has always
# looked in. Overridable for one reason only: the tests stand a real node up on
# a port the kernel gave them, and a fixed list could only be tested by binding
# 6006 on the machine running the suite. The defaults ARE the product.
PF_WS_PORTS="${APERIRE_PREFLIGHT_WS_PORTS:-6006 6005}"
PF_RPC_PORTS="${APERIRE_PREFLIGHT_RPC_PORTS:-5005 5006 51234}"
PF_PEER_PORT="${APERIRE_PREFLIGHT_PEER_PORT:-51235}"
PF_CFG_PATHS="${APERIRE_PREFLIGHT_CFG_PATHS:-/etc/xrpld/xrpld.cfg /etc/opt/ripple/rippled.cfg /opt/ripple/etc/rippled.cfg /etc/ripple/rippled.cfg}"
# The one place in this tree that resolves a node's config file, container
# bind mounts included. Asked rather than reimplemented, and named in a
# variable only so the tests can point it at a stub: on a developer's own
# machine the real one finds the real node, and a suite that reads the host it
# runs on is a suite that passes for the wrong reason.
PF_DETECT="${APERIRE_PREFLIGHT_DETECT:-${SCRIPT_DIR}/detect-rippled-paths.sh}"

# ---- results -------------------------------------------------------
# Four parallel arrays rather than one string per row, because a measured
# value holds spaces, quotes and the odd backslash, and a row split back out
# of a joined string is a row that lost half of itself.
PF_NAME=()
PF_VERDICT=()
PF_VALUE=()
PF_REMEDY=()
PF_MISSING_COUNT=0

# The node facts, measured once and read by two checks (docker and node).
PF_NODE_STATE="unknown"     # found | absent | unavailable
PF_NODE_DESC=""
PF_NODE_WS=""
PF_NODE_RPC=""
PF_NODE_HOW=""
PF_NODE_NAME=""
PF_NODE_PEER=""
PF_NODE_IN_CONTAINER=0
PF_NODE_CFG=""
# The shape the node was found in, said in the checklist's own words: empty
# until something is found, then "container" or "native". Read by the docker
# check (a native host needs no docker at all) and by the report line.
PF_NODE_SHAPE=""
PF_NODE_CONTAINER_NAME=""
# xrpld.service or rippled.service, when systemd has one loaded, and what
# ActiveState answered for it. Set whether or not the unit is running: an
# installed-but-stopped unit is the third state ADR 0016 asks for, and it is
# a different answer from absent.
PF_NODE_UNIT=""
PF_NODE_UNIT_STATE=""
# Why the node question could not be asked, when it could not. Never empty on
# the unavailable branch, because "I could not look" said without saying what
# stopped it is the same unusable answer as "nothing is here".
PF_NODE_UNASKED=""
PF_DOCKER_ASK=-1            # -1 not asked, else docker_ask's 0/1/2
PF_DOCKER_SAID=""

pf_usage() {
  if [[ -n "${BASH_SOURCE[0]:-}" && -f "${BASH_SOURCE[0]}" ]]; then
    awk '/^[^#]/{exit} NR>1{sub(/^# ?/,""); print}' "${BASH_SOURCE[0]}"
  fi
}

# ---- recording and printing ----------------------------------------
# One escaping helper, used at every JSON site. The values here are real
# distro strings and real process names: PRETTY_NAME arrives quoted, a
# process name can hold a backslash, and a hand-rolled quote at each site is
# how one of them ends up producing JSON nothing can parse.
pf_json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\t'/\\t}"
  s="${s//$'\n'/\\n}"
  s="${s//$'\r'/\\r}"
  printf '%s' "$s"
}

pf_record() { # $1 name, $2 verdict, $3 value, $4 remedy
  PF_NAME+=("$1")
  PF_VERDICT+=("$2")
  PF_VALUE+=("$3")
  PF_REMEDY+=("${4:-}")
  [[ "$2" == "MISSING" ]] && PF_MISSING_COUNT=$((PF_MISSING_COUNT + 1))
  [[ $PF_JSON -eq 1 ]] && return 0
  case "$2" in
    ok)      printf '  %sok       %s: %s%s\n' "$S_GREEN" "$1" "$3" "$S_OFF" ;;
    # A warning carries its fix on the line under it, because nothing else
    # will: the block at the bottom reads out the refusals, and a warning an
    # operator cannot act on is a warning they learn to scroll past.
    warn)    printf '  %swarn     %s: %s%s\n' "$S_AMBER" "$1" "$3" "$S_OFF"
             [[ -n "${4:-}" ]] && printf '           %s%s%s\n' "$S_DIM" "$4" "$S_OFF" ;;
    MISSING) printf '  %sMISSING  %s: %s%s\n' "$S_RED"   "$1" "$3" "$S_OFF" ;;
  esac
  return 0
}

pf_ok()      { pf_record "$1" ok      "$2" ""; }
pf_warn()    { pf_record "$1" warn    "$2" "${3:-}"; }
pf_missing() { pf_record "$1" MISSING "$2" "${3:-}"; }

# A note that belongs under the line above it, in the same dim the installers
# use for detail. Never a verdict of its own.
pf_note() { [[ $PF_JSON -eq 1 ]] || printf '           %s%s%s\n' "$S_DIM" "$*" "$S_OFF"; }

pf_print_json() {
  local i first=1
  printf '[\n'
  for i in "${!PF_NAME[@]}"; do
    [[ $first -eq 1 ]] || printf ',\n'
    first=0
    printf '  {"check": "%s", "verdict": "%s", "value": "%s", "remedy": "%s"}' \
      "$(pf_json_escape "${PF_NAME[$i]}")" \
      "$(pf_json_escape "${PF_VERDICT[$i]}")" \
      "$(pf_json_escape "${PF_VALUE[$i]}")" \
      "$(pf_json_escape "${PF_REMEDY[$i]}")"
  done
  printf '\n]\n'
}

# The block that turns a refusal into a next step. Every MISSING row carries
# the command or the config line that fixes it, and this is where they are
# read out. A refusal with no remedy is a refusal an operator cannot act on.
pf_print_remedies() {
  local i
  [[ $PF_MISSING_COUNT -gt 0 ]] || return 0
  printf '\n%sBefore Aperire can install, fix these:%s\n\n' "$S_BOLD" "$S_OFF"
  for i in "${!PF_NAME[@]}"; do
    [[ "${PF_VERDICT[$i]}" == "MISSING" ]] || continue
    printf '  %s%s%s  %s\n' "$S_RED" "${PF_NAME[$i]}" "$S_OFF" "${PF_VALUE[$i]}"
    if [[ -n "${PF_REMEDY[$i]}" ]]; then
      printf '      %s%s%s\n' "$S_CYAN" "${PF_REMEDY[$i]}" "$S_OFF"
    fi
    printf '\n'
  done
}

# ---- asking -------------------------------------------------------
# Standard input and standard ERROR, the same two the bootstrap asks on: a
# prompt written to stdout disappears into whatever is capturing the
# checklist, and the answer never arrives.
pf_have_tty() { [[ -t 0 && -t 2 ]]; }

pf_ask() { # $1 prompt, $2 the answer when there is nobody to ask
  local reply
  if [[ $PF_YES -eq 1 || $PF_JSON -eq 1 || $PF_CHECK_ONLY -eq 1 ]] || ! pf_have_tty; then
    printf '%s' "$2"; return 0
  fi
  read -r -p "  $1 " reply || reply=""
  [[ -n "$reply" ]] || reply="$2"
  printf '%s' "$reply"
}

# ---- roles ---------------------------------------------------------
# `relay` is the bootstrap's name for the role install.sh calls `validator`.
# Renamed here at the boundary, the same way get-aperire.sh does it, so every
# gate below reads one word.
pf_normalise_role() {
  case "$1" in relay) printf 'validator' ;; *) printf '%s' "$1" ;; esac
}

pf_role_is() { # $@ = roles this check applies to
  local r
  for r in "$@"; do [[ "$PF_ROLE" == "$r" ]] && return 0; done
  return 1
}

# The roles that want a node reachable FROM THIS BOX. A dashboard-only host
# watching a fleet has no node here and that is the whole point of the role,
# so the node question is a warning there and a refusal on the other two.
pf_role_needs_node() { pf_role_is co-located validator; }

# ---- the checks ----------------------------------------------------

pf_check_os() {
  local id="" version_id="" id_like="" pretty="unknown"
  if [[ -r "$PF_OS_RELEASE" ]]; then
    # shellcheck source=/dev/null  # a runtime file, not present at lint time
    . "$PF_OS_RELEASE"
    id="${ID:-}"; version_id="${VERSION_ID:-}"; id_like="${ID_LIKE:-}"
    pretty="${PRETTY_NAME:-unknown}"
  fi
  # The same predicate install.sh and get-aperire.sh use. Verified is not the
  # same claim as required, so an unknown distribution warns here: the gate
  # that refuses one is the bootstrap's, and it is about the unattended door.
  if [[ "$id" == "ubuntu" && "$version_id" =~ ^(22\.04|24\.04)$ ]] \
     || [[ " $id_like " == *ubuntu* ]] || [[ "$id" == "linuxmint" ]]; then
    pf_ok "OS" "$pretty"
  else
    pf_warn "OS" "$pretty, which nobody has verified this on" \
      "Install from a clone instead of the one-line door: install.sh warns on an unknown system and carries on."
  fi
}

pf_check_systemd() {
  local line ver
  line="$(systemctl --version 2>/dev/null | head -1)"
  if [[ -z "$line" ]]; then
    pf_missing "systemd" "no systemd on this host" \
      "Aperire installs supervised systemd units. There is nothing here to install them into."
    return 0
  fi
  # The leading run of digits out of the second field, because the first line
  # is "systemd 255 (255.4-1ubuntu8.17)" on one host and carries a distro
  # suffix on another. Taking the field whole compares "255" with "249~rc1".
  ver="$(printf '%s' "$line" | awk '{print $2}' | grep -oE '^[0-9]+')"
  if [[ -z "$ver" ]]; then
    pf_warn "systemd" "$line, and no version number could be read out of it" \
      "Check it by hand: systemctl --version"
    return 0
  fi
  # Every supported systemd, 249 (Ubuntu 22.04) included. The Advisor's own
  # account used to need 250, because it reached the node through sudo and
  # 249's sandbox forces no_new_privs; it reaches the node through a root
  # socket now (ADR 0025). The one thing 249 still does differently is where
  # the model key is kept, and the check below says that on its own line.
  pf_ok "systemd" "$ver"
}

# Which of the two ways this host will keep the Advisor's model API key (#708).
# Said here, before anything is installed, because the alternative is finding
# out at the first seal: a 22.04 host used to install, pair and then refuse
# every key with a sentence about systemd-creds, and nothing up front said so.
#
# Never a refusal, on any host. Both methods work, and the operator ruling is
# that 22.04 is supported.
pf_check_model_key() {
  local lib="${APERIRE_KEY_METHOD_LIB:-$SCRIPT_DIR/model-key-method-lib.sh}" method
  if [[ ! -r "$lib" ]]; then
    pf_warn "model key" "this release carries no model-key method library, so how the key would be kept could not be read" \
      "Check the release is complete: scripts/model-key-method-lib.sh"
    return 0
  fi
  # shellcheck source=scripts/model-key-method-lib.sh
  . "$lib"
  method="$(aperire_key_method)"
  if [[ "$method" == sealed ]]; then
    pf_ok "model key" "$(aperire_key_method_line "$method")"
  else
    # An `ok`, not a warning. It is the supported arrangement on this host,
    # not a shortfall: without a TPM, systemd-creds encrypts with a root-only
    # file sitting beside the blob, so on a VPS the two methods have the same
    # reader set and differ only in whether the file travels.
    pf_ok "model key" "$(aperire_key_method_line "$method")"
  fi
}

pf_check_account() {
  local who
  who="${SUDO_USER:-$(id -un 2>/dev/null)}"
  # cli-only is the mirror image: it puts two symlinks in one account's
  # ~/.local/bin, and root's is the wrong one. install.sh refuses it as root.
  if [[ "$PF_ROLE" == "cli-only" ]]; then
    if [[ $EUID -eq 0 ]]; then
      pf_missing "account" "running as root, and cli-only installs into one account's ~/.local/bin" \
        "Drop the sudo: bash install.sh --role=cli-only"
    else
      pf_ok "account" "$who, no root needed for this role"
    fi
    return 0
  fi
  if [[ $EUID -eq 0 && "$who" == "root" ]]; then
    pf_missing "account" "root, with no ordinary account behind it" \
      "Run it from your own account with sudo in front. The services, the checkout and the database all belong to that account, and root has nowhere to put them."
    return 0
  fi
  if [[ $EUID -eq 0 ]]; then
    pf_ok "account" "$who, through sudo"
    return 0
  fi
  if ! command -v sudo >/dev/null 2>&1; then
    pf_missing "account" "$who, and there is no sudo on this host" \
      "sudo apt-get install -y sudo   (from a root shell), then add $who to the sudo group"
    return 0
  fi
  pf_ok "account" "$who, with sudo available"
}

pf_check_arch() {
  local m a
  m="$(uname -m 2>/dev/null)"
  case "$m" in
    x86_64|amd64) a="amd64" ;;
    aarch64|arm64) a="arm64" ;;
    *) a="" ;;
  esac
  if [[ -n "$a" ]]; then
    pf_ok "arch" "$m ($a)"
  else
    pf_missing "arch" "$m, and the Go toolchain is pinned to amd64 and arm64" \
      "Install Go for this architecture yourself, then run install.sh with --no-prepare."
  fi
}

# The nearest ancestor of a path that exists. The install directory has not
# been created yet on a fresh host, and df on a path that is not there fails
# with nothing said about which filesystem was meant.
pf_nearest_existing() {
  local p="$1"
  while [[ -n "$p" && "$p" != "/" && ! -d "$p" ]]; do p="$(dirname "$p")"; done
  [[ -n "$p" ]] || p="/"
  printf '%s' "$p"
}

pf_check_disk() {
  local target avail_kb gb mount line
  target="$(pf_nearest_existing "$PF_DIR")"
  line="$(df -Pk "$target" 2>/dev/null | awk 'NR==2')"
  if [[ -z "$line" ]]; then
    pf_warn "disk" "nothing here could measure the free space on $target" \
      "Check it by hand: df -h $target"
    return 0
  fi
  avail_kb="$(printf '%s' "$line" | awk '{print $4}')"
  mount="$(printf '%s' "$line" | awk '{print $6}')"
  [[ "$avail_kb" =~ ^[0-9]+$ ]] || avail_kb=0
  gb=$((avail_kb / 1024 / 1024))
  if [[ $gb -lt 5 ]]; then
    pf_missing "disk" "${gb} GB free on ${mount} (${target}), and the build needs 5" \
      "Free some space on ${mount}, or install into another filesystem with --dir <path>."
  elif [[ $gb -lt 10 ]]; then
    pf_warn "disk" "${gb} GB free on ${mount} (${target}), which is enough to install and little to grow into" \
      "The database and the node store both grow. 10 GB is the comfortable floor."
  else
    pf_ok "disk" "${gb} GB free on ${mount} (${target})"
  fi
}

pf_check_memory() {
  local kb mb
  kb="$(free -k 2>/dev/null | awk '/^Mem:/{print $7}')"
  [[ "$kb" =~ ^[0-9]+$ ]] || kb="$(awk '/^MemAvailable:/{print $2}' /proc/meminfo 2>/dev/null)"
  if [[ ! "$kb" =~ ^[0-9]+$ ]]; then
    pf_warn "memory" "nothing here could read the available memory" \
      "Check it by hand: free -h"
    return 0
  fi
  mb=$((kb / 1024))
  if [[ $mb -lt 1024 ]]; then
    pf_warn "memory" "${mb} MB available, and the build wants about 1 GB" \
      "npm ci and the Go builds are the peak. Add swap, or build elsewhere and install with --no-prepare."
  else
    pf_ok "memory" "${mb} MB available"
  fi
}

# What is listening, and who owns it. Three outcomes, not two: unprivileged
# `ss` sees another account's socket but not the process behind it, so "held
# by something I cannot name" is its own answer and never rounds down to
# either free or held-by-X.
#
#   0  free
#   1  held; PF_PORT_HOLDER names the process, PF_PORT_PID its pid
#   2  held by a process this account cannot see
PF_PORT_HOLDER=""
PF_PORT_PID=""
pf_port_state() { # $1 = port
  local row users
  PF_PORT_HOLDER=""; PF_PORT_PID=""
  row="$(ss -ltnp 2>/dev/null | awk -v p=":$1\$" 'NR>1 && $4 ~ p {print; exit}')"
  [[ -n "$row" ]] || return 0
  users="$(printf '%s' "$row" | grep -oE 'users:\(\("[^"]+",pid=[0-9]+' | head -1)"
  if [[ -z "$users" ]]; then return 2; fi
  PF_PORT_HOLDER="$(printf '%s' "$users" | sed -E 's/.*\(\("([^"]+)".*/\1/')"
  PF_PORT_PID="$(printf '%s' "$users" | sed -E 's/.*pid=([0-9]+).*/\1/')"
  return 1
}

# The unit a pid belongs to, when it is one of ours. systemd knows this and
# nothing else on the box does; the cgroup file is the fallback for a host
# where `systemctl status <pid>` is not allowed to answer.
pf_unit_for_pid() { # $1 = pid
  local u
  u="$(systemctl status "$1" 2>/dev/null | head -1 | grep -oE 'aperire[A-Za-z0-9@._-]*\.service' | head -1)"
  [[ -n "$u" ]] || u="$(grep -ao 'aperire[A-Za-z0-9@._-]*\.service' "/proc/$1/cgroup" 2>/dev/null | head -1)"
  printf '%s' "$u"
}

pf_check_one_port() { # $1 = label, $2 = port
  local state=0 unit
  if ! command -v ss >/dev/null 2>&1; then
    pf_warn "port $2" "nothing here could look at the listening sockets (no ss on this host)" \
      "sudo apt-get install -y iproute2"
    return 0
  fi
  pf_port_state "$2" || state=$?
  case $state in
    0) pf_ok "port $2" "free, for the $1" ;;
    1)
      unit="$(pf_unit_for_pid "$PF_PORT_PID")"
      if [[ -n "$unit" ]]; then
        # Our own service holding our own port is an existing install, not a
        # collision. Saying "in use" here would refuse every upgrade.
        pf_ok "port $2" "held by ${unit} (pid ${PF_PORT_PID}), which is this host's own install"
      else
        pf_missing "port $2" "held by ${PF_PORT_HOLDER} (pid ${PF_PORT_PID}), and the $1 needs it" \
          "Stop that process, or give Aperire another port: --port=<n> (and --advisor-port=<n> for the Advisor)."
      fi
      ;;
    *)
      pf_warn "port $2" "something is listening and this account cannot see what" \
        "Name it before you install: sudo ss -ltnp | grep :$2"
      ;;
  esac
}

pf_check_ports() {
  local which="${PF_INSTANCE:+instance ${PF_INSTANCE} }"
  pf_role_is dashboard co-located || return 0
  pf_check_one_port "${which}dashboard" "$PF_PORT"
  [[ $PF_WITH_ADVISOR -eq 1 ]] && pf_check_one_port "${which}Advisor" "$PF_ADVISOR_PORT"
  return 0
}

# Reachable means the name resolved, the connection opened and something
# answered. NOT that it answered 200: go.dev and a CDN in front of a release
# are both entitled to refuse a HEAD, and a 403 still proves every hop this
# check is about.
pf_host_answers() { # $1 = url
  local code
  code="$(curl -sS --max-time 5 -o /dev/null -w '%{http_code}' -I "$1" 2>/dev/null)"
  [[ -n "$code" && "$code" != "000" ]] && return 0
  code="$(curl -sS --max-time 5 -o /dev/null -w '%{http_code}' -r 0-0 "$1" 2>/dev/null)"
  [[ -n "$code" && "$code" != "000" ]]
}

pf_check_egress() {
  local url host reached=0 total=0 unreachable="" names=""
  if ! command -v curl >/dev/null 2>&1; then
    pf_missing "egress" "no curl on this host, so nothing can be downloaded" \
      "sudo apt-get install -y curl ca-certificates"
    return 0
  fi
  # The one check here that takes real time, so it says what it is waiting on
  # before it waits. A pause with nothing on the screen is the one thing no
  # surface in this product is allowed to be.
  for url in $PF_EGRESS_HOSTS; do
    host="${url#*://}"; host="${host%%/*}"
    names="${names:+$names, }${host}"
  done
  pf_note "asking ${names}"
  for url in $PF_EGRESS_HOSTS; do
    total=$((total + 1))
    host="${url#*://}"; host="${host%%/*}"
    if pf_host_answers "$url"; then
      reached=$((reached + 1))
    else
      unreachable="${unreachable:+$unreachable, }${host}"
    fi
  done
  if [[ $reached -eq 0 ]]; then
    pf_missing "egress" "none of the ${total} download hosts answered" \
      "The install fetches Node, Go and the release over HTTPS. Open outbound 443, or set a proxy in the environment, or build elsewhere and install with --no-prepare."
  elif [[ -n "$unreachable" ]]; then
    pf_warn "egress" "${reached}/${total} download hosts answered; no answer from ${unreachable}" \
      "Whatever the install needs from there will fail. Check a proxy or a firewall rule before you start."
  else
    pf_ok "egress" "${reached}/${total} download hosts answered"
  fi
}

pf_check_clock() {
  local shown
  shown="$(timedatectl show -p NTPSynchronized 2>/dev/null | sed -n 's/^NTPSynchronized=//p')"
  if [[ "$shown" == "yes" ]]; then
    pf_ok "clock" "synchronised (timedatectl NTPSynchronized=yes)"
    return 0
  fi
  if command -v chronyc >/dev/null 2>&1 && chronyc tracking >/dev/null 2>&1; then
    pf_ok "clock" "synchronised (chronyc tracking answers)"
    return 0
  fi
  if command -v ntpstat >/dev/null 2>&1 && ntpstat >/dev/null 2>&1; then
    pf_ok "clock" "synchronised (ntpstat)"
    return 0
  fi
  # Not a refusal, and it is close to one. A skewed clock does not break the
  # install; it breaks the first sign-in afterwards, which is a much worse
  # place to find out.
  pf_warn "clock" "not synchronised${shown:+ (NTPSynchronized=$shown)}" \
    "sudo timedatectl set-ntp true   # passkey enrollment and TLS both fail on a clock that has drifted"
}

pf_check_tools() {
  local t missing="" have_apt=0
  command -v apt-get >/dev/null 2>&1 && have_apt=1
  for t in git curl sqlite3; do
    command -v "$t" >/dev/null 2>&1 || missing="${missing:+$missing }${t}"
  done
  # ca-certificates ships no command of its own; the bundle it installs is
  # the thing every https fetch here reads.
  [[ -r "$PF_CA_BUNDLE" ]] || missing="${missing:+$missing }ca-certificates"
  if [[ -z "$missing" ]]; then
    pf_ok "tools" "git, curl, ca-certificates and sqlite3 are all here"
    return 0
  fi
  if [[ $have_apt -eq 1 ]]; then
    pf_warn "tools" "not here yet: ${missing}" \
      "The prepare step installs them: sudo apt-get install -y ${missing}"
  else
    pf_missing "tools" "not here: ${missing}, and there is no apt-get to install them with" \
      "Install ${missing} with this system's package manager, then run install.sh --no-prepare."
  fi
}

pf_check_docker() {
  # A native node needs no docker at all, whether or not the Advisor is
  # wanted: its own runbook is systemd and the package manager, and a
  # warning that is never actionable trains people to ignore the list.
  [[ "$PF_NODE_SHAPE" == "native" ]] && return 0
  # Only when it matters. The Advisor drives a containerised node through
  # docker, and a node that IS in a container was found through it.
  [[ $PF_WITH_ADVISOR -eq 1 || $PF_NODE_IN_CONTAINER -eq 1 ]] || return 0
  case $PF_DOCKER_ASK in
    0) pf_ok "docker" "answering" ;;
    1) if [[ $PF_WITH_ADVISOR -eq 1 ]]; then
         pf_warn "docker" "$PF_DOCKER_SAID" \
           "The Advisor manages a containerised node through docker. Without one it still answers questions and still refuses actions it cannot take."
       else
         pf_ok "docker" "$PF_DOCKER_SAID"
       fi ;;
    2) # The bug this whole library exists for: a refused answer is not an
       # absence, and rounding it down is what installed a node box as a
       # dashboard once already.
       pf_warn "docker" "installed here and would not answer (${PF_DOCKER_SAID})" \
         "Ask it as root before you install: sudo docker ps" ;;
    *) : ;;
  esac
  return 0
}

pf_check_existing_install() {
  local units
  units="$(systemctl list-unit-files 'aperire-*' 2>/dev/null | grep '\.service' | awk '{print $1}' | tr '\n' ' ')"
  units="${units% }"
  if [[ -n "$units" ]]; then
    pf_warn "install" "already installed here: ${units}" \
      "Everything past the first install lives behind one command: bash aperire-one"
  elif [[ -d "$PF_ETC" ]]; then
    pf_warn "install" "${PF_ETC} exists, so something of Aperire has been here" \
      "Everything past the first install lives behind one command: bash aperire-one"
  else
    pf_ok "install" "nothing of Aperire is on this host yet"
  fi
}

# ---- the node ------------------------------------------------------
#
# v3's rule, which is the one the operator asked for again: find the node by
# looking for it, and when it cannot be found, say which of the three things
# it might be and let them name the port.
#
# Three sources, in this order, because they are not equally trustworthy:
#
#   a. a process or a container. Evidence that a node is RUNNING
#   b. the config file, which names the ports it was told to open. Evidence
#      of what was configured, which a decommissioned install also leaves
#   c. the standard ports, probed on loopback
#
# and then one confirmation, which is what separates "something is listening
# there" from "that is a node": server_info over the RPC port, and a real
# WebSocket handshake with a server_info frame over the admin WS port.

pf_ask_docker_once() {
  [[ $PF_DOCKER_ASK -eq -1 ]] || return 0
  if [[ -r "${SCRIPT_DIR}/docker-ask-lib.sh" ]]; then
    # shellcheck source=scripts/docker-ask-lib.sh
    . "${SCRIPT_DIR}/docker-ask-lib.sh"
    PF_DOCKER_ASK=0
    PF_DOCKER_SAID="$(docker_ask '{{.Names}} {{.Image}} {{.Command}}')" || PF_DOCKER_ASK=$?
    # A container created from a digest shows an image ID; read its name back,
    # and treat a refused read like a refused ps (#896).
    if [[ $PF_DOCKER_ASK -eq 0 ]]; then
      PF_DOCKER_SAID="$(docker_resolve_image_ids "$PF_DOCKER_SAID")" || PF_DOCKER_ASK=$?
    fi
  else
    PF_DOCKER_ASK=1
    PF_DOCKER_SAID="docker-ask-lib.sh is not in this checkout, so nothing asked docker"
  fi
  return 0
}

# The [port_ws_admin_local] style stanza's `port` line. Empty when the stanza
# is not there, which is a different fact from a port of 0 and is kept apart.
pf_cfg_port() { # $1 = cfg file, $2 = stanza name without brackets
  awk -v want="[$2]" '
    /^[[:space:]]*\[/ { s = $0; gsub(/[[:space:]]/, "", s); inb = (s == want); next }
    inb && /^[[:space:]]*port[[:space:]]*=/ {
      sub(/^[^=]*=[[:space:]]*/, ""); gsub(/[[:space:]]/, ""); print; exit
    }
  ' "$1" 2>/dev/null
}

# A plain TCP connect. Says a socket is open and nothing more, which is
# exactly what it is used for below.
pf_tcp_open() { # $1 = host, $2 = port
  ( exec 3<>"/dev/tcp/$1/$2" ) 2>/dev/null
}

# server_info over HTTP, which is how the RPC port answers. Prints
# "<build_version> <server_state>" and returns non-zero when the thing on
# that port is not a node.
PF_RPC_BUILD=""
PF_RPC_STATE=""
pf_rpc_server_info() { # $1 = host, $2 = port
  local body
  PF_RPC_BUILD=""; PF_RPC_STATE=""
  command -v curl >/dev/null 2>&1 || return 1
  body="$(curl -sS --max-time 4 -H 'Content-Type: application/json' \
    -d '{"method":"server_info","params":[{}]}' \
    "http://$1:$2/" 2>/dev/null)"
  [[ -n "$body" ]] || return 1
  PF_RPC_BUILD="$(printf '%s' "$body" | grep -oE '"build_version"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | sed -E 's/.*"([^"]*)"$/\1/')"
  PF_RPC_STATE="$(printf '%s' "$body" | grep -oE '"server_state"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | sed -E 's/.*"([^"]*)"$/\1/')"
  [[ -n "$PF_RPC_BUILD" || -n "$PF_RPC_STATE" ]]
}

# server_info over the admin WebSocket. A TCP connect proves a socket; the
# handshake and one frame prove a node. python3 is what does the framing, and
# when there is none the honest report is "listening, not confirmed" rather
# than a claim either way.
PF_WS_BUILD=""
PF_WS_STATE=""
pf_ws_server_info() { # $1 = host, $2 = port
  local out
  PF_WS_BUILD=""; PF_WS_STATE=""
  command -v python3 >/dev/null 2>&1 || return 2
  out="$(python3 -I - "$1" "$2" <<'PY' 2>/dev/null
import base64, json, os, socket, struct, sys

host, port = sys.argv[1], int(sys.argv[2])

def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise IOError("short read")
        buf += chunk
    return buf

try:
    s = socket.create_connection((host, port), 3)
    s.settimeout(3)
    key = base64.b64encode(os.urandom(16)).decode()
    s.sendall((
        "GET / HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: %s\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n" % (host, port, key)
    ).encode())
    head = b""
    while b"\r\n\r\n" not in head:
        chunk = s.recv(4096)
        if not chunk:
            sys.exit(1)
        head += chunk
        if len(head) > 65536:
            sys.exit(1)
    if b" 101" not in head.split(b"\r\n")[0]:
        sys.exit(1)
    payload = b'{"command":"server_info"}'
    # Masked, as a client frame must be. An all-zero mask is legal and keeps
    # the payload readable in a packet capture.
    s.sendall(b"\x81" + bytes([0x80 | len(payload)]) + b"\x00\x00\x00\x00" + payload)
    b0 = recv_exact(s, 2)
    length = b0[1] & 0x7F
    if length == 126:
        length = struct.unpack("!H", recv_exact(s, 2))[0]
    elif length == 127:
        length = struct.unpack("!Q", recv_exact(s, 8))[0]
    if b0[1] & 0x80:
        recv_exact(s, 4)
    data = recv_exact(s, length) if length else b""
    info = json.loads(data.decode("utf-8", "replace")).get("result", {}).get("info", {})
    print("%s\t%s" % (info.get("build_version", ""), info.get("server_state", "")))
except Exception:
    sys.exit(1)
PY
)" || return 1
  PF_WS_BUILD="${out%%$'\t'*}"
  PF_WS_STATE="${out##*$'\t'}"
  [[ -n "$PF_WS_BUILD" || -n "$PF_WS_STATE" ]]
}

# Does this port hold a node? Sets PF_NODE_WS / PF_NODE_RPC as it confirms
# them, and returns 0 the moment either one answers server_info.
pf_confirm_ws() { # $1 = port
  local rc=0
  pf_tcp_open "$PF_PROBE_HOST" "$1" || return 1
  pf_ws_server_info "$PF_PROBE_HOST" "$1" || rc=$?
  case $rc in
    0) PF_NODE_WS="${PF_PROBE_HOST}:$1"
       [[ -n "$PF_WS_BUILD$PF_WS_STATE" ]] && PF_NODE_DESC="${PF_WS_BUILD:-a node}${PF_WS_STATE:+ ($PF_WS_STATE)}"
       return 0 ;;
    2) PF_NODE_WS="${PF_PROBE_HOST}:$1 (listening, not confirmed: no python3 here to speak WebSocket)"
       return 0 ;;
    *) return 1 ;;
  esac
}

pf_confirm_rpc() { # $1 = port
  pf_tcp_open "$PF_PROBE_HOST" "$1" || return 1
  if pf_rpc_server_info "$PF_PROBE_HOST" "$1"; then
    PF_NODE_RPC="${PF_PROBE_HOST}:$1"
    [[ -z "$PF_NODE_DESC" ]] && PF_NODE_DESC="${PF_RPC_BUILD:-a node}${PF_RPC_STATE:+ ($PF_RPC_STATE)}"
    return 0
  fi
  return 1
}

# The unit fact: xrpld.service or rippled.service, asked by LoadState first
# and ActiveState only once one is actually there. is-active alone cannot
# tell a stopped unit from one that was never defined - it answers
# "inactive" for both - so LoadState is what says the unit exists, and it is
# asked with `systemctl show`, not `list-unit-files`, because a fixed conf
# key or fixture that lists every unit on the box (as the existing-install
# check does) is not this question and must not answer it by accident.
pf_unit_prop() { # $1 = property, $2 = unit
  systemctl show -p "$1" --value "$2" 2>/dev/null
}

pf_native_unit_probe() {
  local name load
  for name in xrpld.service rippled.service; do
    load="$(pf_unit_prop LoadState "$name")"
    [[ "$load" == "loaded" ]] || continue
    PF_NODE_UNIT="$name"
    PF_NODE_UNIT_STATE="$(pf_unit_prop ActiveState "$name")"
    [[ -n "$PF_NODE_UNIT_STATE" ]] || PF_NODE_UNIT_STATE="inactive"
    return 0
  done
  return 1
}

# The silent half of the node question. Runs before anything is printed
# because the docker check reads its answer too.
pf_node_probe() {
  local n pid cfg p proc_asked=1

  # The unit, asked first and independent of everything below: it is the
  # "installed but down" reading ADR 0016 wants, and it holds whether or not
  # a process or a container can also be seen. An active unit is treated the
  # same way a matched container is below - found on that evidence alone -
  # so a native admin port that answers on an address this probe never
  # tries is not read back as "no node here".
  if pf_native_unit_probe; then
    PF_NODE_SHAPE="native"
    if [[ "$PF_NODE_UNIT_STATE" == "active" ]]; then
      PF_NODE_STATE="found"
      PF_NODE_HOW="unit active"
    fi
  fi

  # (a) a process. No privileges needed to see one, so it is asked first and
  # its answer is final. A host with no pgrep on it answers "no node process"
  # to a question nothing asked, which is the rounding this whole section
  # exists to stop, so whether it could be asked is kept.
  if ! command -v pgrep >/dev/null 2>&1; then
    proc_asked=0
  else
    for n in rippled xrpld xahaud; do
      pid="$(pgrep -x "$n" 2>/dev/null | head -1)"
      if [[ -n "$pid" ]]; then
        PF_NODE_HOW="process $n pid $pid"
        PF_NODE_NAME="$n"
        PF_NODE_STATE="found"
        break
      fi
    done
  fi

  # (a, continued) a container, asked through the one library that tells a
  # refused answer from an absence.
  if [[ "$PF_NODE_STATE" != "found" ]]; then
    pf_ask_docker_once
    if [[ $PF_DOCKER_ASK -eq 0 ]]; then
      n="$(printf '%s\n' "$PF_DOCKER_SAID" | grep -aiE 'rippled|xrpld|xahaud' | head -1)"
      if [[ -n "$n" ]]; then
        # The fork's own name, out of the row docker printed, so the line
        # says rippled or xrpld rather than whichever one was guessed.
        PF_NODE_NAME="$(printf '%s' "$n" | grep -aoiE 'rippled|xrpld|xahaud' | head -1 | tr '[:upper:]' '[:lower:]')"
        PF_NODE_CONTAINER_NAME="$(printf '%s' "$n" | awk '{print $1}')"
        PF_NODE_HOW="container ${PF_NODE_CONTAINER_NAME}"
        PF_NODE_STATE="found"
        PF_NODE_IN_CONTAINER=1
        PF_NODE_SHAPE="container"
      fi
    fi
  else
    pf_ask_docker_once
  fi

  # (b) the config file. detect-rippled-paths.sh is the one place in this
  # tree that resolves it, container bind mounts included, so it is asked
  # rather than reimplemented. Its stderr is not swallowed: the one thing it
  # writes there is a docker that refused, and hiding that is #142.
  cfg="$(bash "$PF_DETECT" 2>/dev/null | sed -n 's/^RIPPLED_CFG_PATH=//p')"
  if [[ -z "$cfg" ]]; then
    for p in $PF_CFG_PATHS; do
      [[ -f "$p" ]] && { cfg="$p"; break; }
    done
  fi
  PF_NODE_CFG="$cfg"

  # (c) the ports. The config's own stanzas first, because a node told to
  # listen somewhere unusual is exactly the case a fixed list would miss,
  # then the standard ports in the order v3 tried them.
  local ws_cfg="" rpc_cfg=""
  if [[ -n "$cfg" && -r "$cfg" ]]; then
    ws_cfg="$(pf_cfg_port "$cfg" port_ws_admin_local)"
    rpc_cfg="$(pf_cfg_port "$cfg" port_rpc_admin_local)"
  fi

  for p in $ws_cfg $PF_WS_PORTS; do
    [[ "$p" =~ ^[0-9]+$ ]] || continue
    [[ -n "$PF_NODE_WS" ]] && break
    pf_confirm_ws "$p" && break
  done
  for p in $rpc_cfg $PF_RPC_PORTS; do
    [[ "$p" =~ ^[0-9]+$ ]] || continue
    [[ -n "$PF_NODE_RPC" ]] && break
    pf_confirm_rpc "$p" && break
  done
  # The peer port carries no admin surface and the dashboard never dials it.
  # Read anyway, and reported as detail only: an open peer port beside a
  # silent admin port is reason 1 on the list below, said in one measurement.
  if pf_tcp_open "$PF_PROBE_HOST" "$PF_PEER_PORT"; then
    PF_NODE_PEER="${PF_PROBE_HOST}:${PF_PEER_PORT}"
  fi

  if [[ -n "$PF_NODE_WS" || -n "$PF_NODE_RPC" ]]; then
    PF_NODE_STATE="found"
    [[ -n "$PF_NODE_HOW" ]] || PF_NODE_HOW="answering on loopback"
    return 0
  fi
  [[ "$PF_NODE_STATE" == "found" ]] && return 0

  # Nothing was found, and that is only an ANSWER when every half of the
  # question could be asked. On a hardened host the operator is deliberately
  # not in the docker group, and `sudo -n` is refused: a node in a container
  # is then invisible to everything running here, and reading that silence as
  # "there is no node" is the bug (#140, #142) that installed a node box as a
  # dashboard. So it is kept apart, and it warns rather than refusing.
  if [[ $PF_DOCKER_ASK -eq 2 ]]; then
    PF_NODE_STATE="unavailable"
    PF_NODE_UNASKED="docker is installed here, and neither this account nor 'sudo -n' could ask it what is running (${PF_DOCKER_SAID})"
  elif [[ $proc_asked -eq 0 ]]; then
    PF_NODE_STATE="unavailable"
    PF_NODE_UNASKED="nothing here could look for a node process (no pgrep on this host)"
  elif [[ "$PF_NODE_SHAPE" == "native" ]]; then
    # A loaded unit that is not active: the early return above already
    # claimed "found" for an active one, so reaching here on a native shape
    # means installed and stopped, not absent.
    PF_NODE_STATE="native-stopped"
  else
    PF_NODE_STATE="absent"
  fi
  return 0
}

# The three reasons, in the operator's own words. Printed whenever the probe
# came back with nothing, before anything is asked and before anything is
# refused, because they are what turns "not found" into something to go and
# look at.
pf_node_three_reasons() {
  [[ $PF_JSON -eq 1 ]] && return 0
  cat <<EOF

  ${S_AMBER}No node answered on this host.${S_OFF} Three things it can be:

    1. the port is not exposed
       (a container with no published port, or a node bound to an address
        that is not ${PF_PROBE_HOST}; ss -ltnp says which)
    2. there is no node on this host
       (then this box is a dashboard, and --role=dashboard is the install)${PF_NODE_PEER:+
       - though ${PF_NODE_PEER} IS open, so something node-shaped is here}
    3. the node listens on a non-standard port
       (name it below, or set port_ws_admin_local in rippled.cfg)

  If this box has no node YET, that is a third way on rather than a refusal:
  install one here, then run this again. From the one-liner that is --node
  (or answer 5 at its role prompt):

      curl -fsSL https://get.aperire.one | bash -s -- --node

EOF
}

pf_check_node() {
  local answered where

  # A node not on this box is what the dashboard role MEANS, so the probe is
  # reported there and never refuses. cli-only reads no node at all.
  if [[ "$PF_ROLE" == "cli-only" ]]; then return 0; fi

  if [[ "$PF_NODE_STATE" == "found" ]]; then
    where="${PF_NODE_NAME:+${PF_NODE_NAME} }${PF_NODE_DESC:-a node}"
    # The shape, said in the checklist's own words: it is what decides which
    # install path is offered next, so it is printed whether or not the
    # admin port went on to confirm it.
    case "$PF_NODE_SHAPE" in
      native)    where="${where}, native, ${PF_NODE_UNIT}" ;;
      container) where="${where}, container, ${PF_NODE_CONTAINER_NAME}" ;;
    esac
    [[ -n "$PF_NODE_WS" ]]  && where="${where}, admin WS ${PF_NODE_WS}"
    [[ -n "$PF_NODE_RPC" ]] && where="${where}, RPC ${PF_NODE_RPC}"
    [[ -n "$PF_NODE_HOW" && -z "$PF_NODE_WS$PF_NODE_RPC" ]] && where="${where}, found by ${PF_NODE_HOW}"
    pf_ok "node" "$where"
    [[ -n "$PF_NODE_CFG" ]]  && pf_note "config: ${PF_NODE_CFG}"
    [[ -n "$PF_NODE_PEER" ]] && pf_note "peer port ${PF_NODE_PEER} is open"
    [[ -n "$PF_NODE_WS" ]] && pf_write_answer "ws://${PF_NODE_WS%% *}"
    return 0
  fi

  # Installed and stopped: a fact of its own, not a rounding-down to absent
  # (ADR 0016). It never blocks - starting the service is the operator's own
  # next step, not something this checklist can do for them.
  if [[ "$PF_NODE_STATE" == "native-stopped" ]]; then
    pf_warn "node" "installed as ${PF_NODE_UNIT} (${PF_NODE_UNIT_STATE:-inactive}), not running" \
      "Start it, then run this again: sudo systemctl start ${PF_NODE_UNIT}"
    [[ -n "$PF_NODE_CFG" ]] && pf_note "config: ${PF_NODE_CFG}"
    return 0
  fi

  # Not found is one thing; could not look is another, and the second one is
  # never refused on. Everything the install does still works on a host whose
  # node this account cannot see, and the operator can name the port.
  if [[ "$PF_NODE_STATE" == "unavailable" ]]; then
    pf_warn "node" "not confirmed: ${PF_NODE_UNASKED}" \
      "Ask as root before you install: sudo docker ps, and ss -ltnp. If the node is here on a port of its own, set RIPPLED_URL=ws://${PF_PROBE_HOST}:<port> in /etc/aperire/aperire.env."
    return 0
  fi

  if ! pf_role_needs_node; then
    if [[ $PF_ROLE_GUESSED -eq 1 ]]; then
      # Nobody named the role; the probe found no node and read 'dashboard'
      # into that. "No node here" and "no node here YET" look the same to a
      # probe, and only the operator knows which this is (#139).
      pf_warn "node" "none on this host, so this reads as role '${PF_ROLE}': a box that watches nodes elsewhere" \
        "If this box is meant to run a node and has none yet, run the install with --node (or answer 5 at its role prompt): a hardened mainnet node goes in first, then the dashboard beside it."
      pf_note "If it watches nodes that live elsewhere, 'dashboard' is right; add them afterwards: bash aperire-one, then the fleet helper."
    else
      pf_warn "node" "none on this host, which is what role '${PF_ROLE}' means" \
        "Add the nodes this dashboard watches afterwards: bash aperire-one, then the fleet helper."
    fi
    return 0
  fi

  # From here down the role says a node belongs on this box and none was
  # found. The reasons come first, then the question.
  pf_node_three_reasons

  if [[ $PF_YES -eq 1 || $PF_JSON -eq 1 || $PF_CHECK_ONLY -eq 1 ]] || ! pf_have_tty; then
    pf_missing "node" "none found, and there is nobody here to ask which port it is on" \
      "Name it and run this again: RIPPLED_URL=ws://${PF_PROBE_HOST}:<port> in /etc/aperire/aperire.env, or install with --role=dashboard if this box has no node."
    return 0
  fi

  answered="$(pf_ask 'Admin WebSocket port to use (Enter to continue without a node, and the dashboard will wait for one):' '')"
  if [[ -z "$answered" ]]; then
    pf_warn "node" "none found, and none named. The dashboard will start and wait for one" \
      "Set RIPPLED_URL=ws://${PF_PROBE_HOST}:<port> in /etc/aperire/aperire.env later, then: sudo systemctl restart aperire-server"
    return 0
  fi
  if [[ ! "$answered" =~ ^[0-9]+$ ]] || [[ $answered -lt 1 || $answered -gt 65535 ]]; then
    pf_missing "node" "'${answered}' is not a port number" \
      "Run the preflight again and give a number from 1 to 65535: bash scripts/preflight.sh --role ${PF_ROLE}"
    return 0
  fi
  if pf_confirm_ws "$answered"; then
    pf_ok "node" "${PF_NODE_NAME:+${PF_NODE_NAME} }${PF_NODE_DESC:-a node}, admin WS ${PF_NODE_WS}"
    pf_write_answer "ws://${PF_NODE_WS%% *}"
    return 0
  fi
  # Taken anyway, and said out loud. The operator knows their host better
  # than a probe does, and a node that is down right now is still the node
  # this dashboard is for.
  pf_warn "node" "nothing answered on ${PF_PROBE_HOST}:${answered}, and the install will use it anyway" \
    "If it stays quiet: systemctl status rippled, and ss -ltnp | grep ${answered}"  # grep-lint: skip
  pf_write_answer "ws://${PF_PROBE_HOST}:${answered}"
  return 0
}

# The answer, on its way to /etc/aperire/aperire.env. See the header: a file,
# because a child process cannot export into its parent.
pf_write_answer() { # $1 = the RIPPLED_URL value
  [[ -n "$PF_ANSWER_FILE" ]] || return 0
  [[ $PF_CHECK_ONLY -eq 1 || $PF_JSON -eq 1 ]] && return 0
  printf 'RIPPLED_URL=%s\n' "$1" > "$PF_ANSWER_FILE" 2>/dev/null
  return 0
}

# What the node probe measured, for the caller that has to act on it.
#
# scripts/get-aperire.sh records a node this host is running when nothing on
# the host names it (#434), and that is the container verb, so it has to know
# the shape and the container's name. Its own probe runs before the release is
# fetched and only when the role was DETECTED: a named role short-circuits it,
# and a first install driven with --role=co-located therefore left the node
# unrecorded on a host whose node predated the dashboard (aperire4,
# 2026-09-17). This probe ran on that host and found the node. So the answer
# travels rather than being asked for twice.
#
# APPENDED, and last: pf_write_answer truncates, so a fact written before it
# would be the one that disappears. Same two exclusions as the URL: a --check
# reports and acts on nothing, and --json is a different reader entirely.
pf_write_node_facts() {
  [[ -n "$PF_ANSWER_FILE" ]] || return 0
  [[ $PF_CHECK_ONLY -eq 1 || $PF_JSON -eq 1 ]] && return 0
  [[ "$PF_NODE_STATE" == found ]] || return 0
  {
    printf 'NODE_SHAPE=%s\n' "${PF_NODE_SHAPE:-unknown}"
    [[ -n "$PF_NODE_CONTAINER_NAME" ]] && printf 'NODE_CONTAINER=%s\n' "$PF_NODE_CONTAINER_NAME"
  } >> "$PF_ANSWER_FILE" 2>/dev/null
  return 0
}

# ---- main ----------------------------------------------------------
pf_parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --role)           PF_ROLE="${2:-}"; shift 2 ;;
      --role=*)         PF_ROLE="${1#*=}"; shift ;;
      --instance)       PF_INSTANCE="${2:-}"; shift 2 ;;
      --instance=*)     PF_INSTANCE="${1#*=}"; shift ;;
      --port)           PF_PORT="${2:-}"; shift 2 ;;
      --port=*)         PF_PORT="${1#*=}"; shift ;;
      --advisor-port)   PF_ADVISOR_PORT="${2:-}"; shift 2 ;;
      --advisor-port=*) PF_ADVISOR_PORT="${1#*=}"; shift ;;
      --with-advisor)   PF_WITH_ADVISOR=1; shift ;;
      --dir)            PF_DIR="${2:-}"; shift 2 ;;
      --dir=*)          PF_DIR="${1#*=}"; shift ;;
      --answer-file)    PF_ANSWER_FILE="${2:-}"; shift 2 ;;
      --answer-file=*)  PF_ANSWER_FILE="${1#*=}"; shift ;;
      --yes|-y)         PF_YES=1; shift ;;
      --check)          PF_CHECK_ONLY=1; shift ;;
      --role-guessed)   PF_ROLE_GUESSED=1; shift ;;
      --json)           PF_JSON=1; shift ;;
      -h|--help)        pf_usage; return 2 ;;
      *) echo "${E_RED}error: unknown argument: $1${E_OFF}" >&2; return 3 ;;
    esac
  done
  return 0
}

pf_main() {
  local rc=0
  pf_parse_args "$@" || rc=$?
  case $rc in 0) ;; 2) return 0 ;; *) return 2 ;; esac

  PF_ROLE="$(pf_normalise_role "$PF_ROLE")"
  case "$PF_ROLE" in
    dashboard|validator|co-located|cli-only) ;;
    "") echo "${E_RED}error: --role is required (co-located, dashboard, relay, validator or cli-only)${E_OFF}" >&2; return 2 ;;
    *)  echo "${E_RED}error: invalid role '$PF_ROLE'${E_OFF}" >&2; return 2 ;;
  esac
  [[ "$PF_PORT" =~ ^[0-9]+$ ]] || PF_PORT=7800
  [[ "$PF_ADVISOR_PORT" =~ ^[0-9]+$ ]] || PF_ADVISOR_PORT=7810
  [[ -n "$PF_DIR" ]] || PF_DIR="$(pwd)"

  if [[ $PF_JSON -ne 1 ]]; then
    printf '\n%s----- what this host has, before anything is installed -----%s\n\n' "$S_BOLD" "$S_OFF"
  fi

  # Measured before the first line is printed, because the docker check reads
  # what the node probe found and the two are one question asked once.
  pf_node_probe

  pf_check_os
  pf_check_systemd
  pf_check_model_key
  pf_check_account
  [[ "$PF_ROLE" == "cli-only" ]] || pf_check_arch
  pf_check_disk
  [[ "$PF_ROLE" == "cli-only" ]] || pf_check_memory
  pf_check_ports
  pf_check_egress
  pf_check_clock
  pf_check_tools
  pf_check_docker
  pf_check_existing_install
  pf_check_node
  # After every check, because the node answer can end in a question the
  # operator is asked, and pf_write_answer truncates the file this appends to.
  pf_write_node_facts

  if [[ $PF_JSON -eq 1 ]]; then
    pf_print_json
  else
    pf_print_remedies
    if [[ $PF_MISSING_COUNT -eq 0 ]]; then
      printf '\n  %sNothing is missing. %s%s\n\n' "$S_GREEN" \
        "$([[ $PF_CHECK_ONLY -eq 1 ]] && printf 'This host can install Aperire One.' || printf 'Carrying on.')" "$S_OFF"
    else
      printf '  %s%d thing%s above has to be fixed first, so nothing was installed.%s\n\n' \
        "$S_RED" "$PF_MISSING_COUNT" "$([[ $PF_MISSING_COUNT -eq 1 ]] || printf 's')" "$S_OFF"
    fi
  fi

  [[ $PF_MISSING_COUNT -eq 0 ]] && return 0
  return 1
}

# Executed, not sourced: run it. Sourced, the caller has the functions and
# calls pf_main itself. The guard is the last line rather than an early
# return at the top, because a `return` above a function definition makes
# every definition under it unreachable to shellcheck (SC2317).
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  pf_main "$@"
  exit $?
fi
