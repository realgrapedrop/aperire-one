#!/usr/bin/env bash
# Write the privilege wrapper's configuration from the deployment on this host,
# then prove the wrapper still works with it.
#
# Why this exists: the wrapper is the boundary between the Advisor and your
# node — it names the only paths that can be touched and the only operations
# that can run. Those paths used to be typed into the script itself, which
# meant every operator had to hand-edit a security file before the recommended
# setup would work at all. That makes the *less* safe path the easy one, and
# security you have to hand-assemble is security most people skip.
#
# So the paths are detected instead, by the same code the Advisor already uses
# to describe your deployment, and written to a root-owned file the service
# account cannot rewrite.
#
#   install-node-wrapper.sh
#   install-node-wrapper.sh --no-node          # an aggregator: host reads only
#   install-node-wrapper.sh --native [unit]    # a vendor package, run by systemd
#   install-node-wrapper.sh --refresh          # the root-owned copies only (an update)
#
# Root runs the release's checked copy of this program, never the one in the
# login-owned install tree (ADR 0024). An operator reaches it through the
# bootstrap, which holds each argument to a whitelist first:
#
#   curl -fsSL https://get.aperire.one | bash -s -- --node-wrapper [<container> [--node-wrapper-rpc <port>]]
#   curl -fsSL https://get.aperire.one | bash -s -- --node-wrapper-native [<unit>]
#   curl -fsSL https://get.aperire.one | bash -s -- --update --force      (--refresh)
#
# Re-runnable. Changes nothing about the node itself: detection is reads only
# (a `docker inspect`, or a `systemctl show` and a package-database query on
# --native), and the checks afterwards only read too. With --no-node it writes
# a configuration that names no node (SERVICE=none): the Advisor's host reads
# (unit state, journal, memory, disk) work, every node verb refuses.
#
# --native adopts whatever is already on this host: it detects the unit
# (xrpld.service, then rippled.service, or the one named on the command line),
# reads its config for the admin RPC and the data path, works out which
# package owns the binary it runs and asks the package database what version
# is installed, and writes KIND=native into the configuration. It refuses
# rather than writes when the admin RPC or the store-rotation guard's log
# source cannot be proven to work, because a wrapper configured on a guess
# would find that out at the first restart instead of here.

set -euo pipefail

# Where this program and its siblings are (NW_SELF), and the install tree it acts
# on (REPO_DIR): a directory and its parent from a checkout, two when it is a copy
# root staged out of the release and APERIRE_INSTALL_TREE names the tree
# (#764). Code is loaded and run from NW_SELF only.
NW_SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="${APERIRE_INSTALL_TREE:-$(cd "$NW_SELF/.." && pwd)}"
CONF=/etc/aperire/node-wrapper.conf

# Where root runs the wrapper from (ADR 0024): a root-owned copy in
# /usr/local/sbin, placed by this script from the tree only after the check
# that no service account can write the copy it reads, with the library the
# wrapper sources beside it in /usr/local/lib/aperire. The Advisor's root
# socket runs that copy (ADR 0025), never the one in the tree. trusted-path-lib.sh is the check, the
# copy, and the one place both installed names are spelled.
[[ -r "$NW_SELF/trusted-path-lib.sh" ]] \
  || { echo "error: $NW_SELF/trusted-path-lib.sh is missing from this checkout" >&2; exit 1; }
# shellcheck source=scripts/trusted-path-lib.sh
. "$NW_SELF/trusted-path-lib.sh"
# The broker behind the Advisor's socket is placed through the release's own
# digests (ADR 0024 lane 2, ADR 0025), so the check that does that is loaded
# here, the way every grant installer loads it.
[[ -r "$NW_SELF/release-digests-lib.sh" ]] \
  || { echo "error: $NW_SELF/release-digests-lib.sh is missing from this checkout" >&2; exit 1; }
# shellcheck source=scripts/release-digests-lib.sh
. "$NW_SELF/release-digests-lib.sh"
INSTANCE="${APERIRE_INSTANCE:-}"
# The name lands in /usr/local/sbin and /etc/aperire paths, so it is held to
# the rule install-advisord.sh holds it to.
trusted_valid_instance "$INSTANCE" \
  || { echo "error: instance name must be lowercase letters, digits and dashes" >&2; exit 2; }
DEFAULT_CONF="$CONF"

# With an instance named, write the configuration the way that instance's
# wrapper will look for it: keyed to that instance's installed copy. The
# default instance keeps the original path exactly, so an existing host and
# everything that reads it — the verify script, the config closer, advisord's
# own status check — are untouched.
#
# Before ADR 0024 an instance's configuration was keyed to the copy in its
# checkout. That one is carried to the new name byte for byte, once, and left
# where it was: the scripts that still run the tree's copy as root (the
# config closer, the rotation scripts) keep finding it.
LEGACY_CONF=""
if [[ -n "$INSTANCE" ]]; then
  _w="$REPO_DIR/scripts/aperire-node-wrapper.sh"
  LEGACY_CONF="$(dirname "$CONF")/node-wrapper-$(printf '%s' "$_w" | sha256sum | cut -c1-12).conf"
  CONF="$(trusted_wrapper_conf "$INSTANCE" "$CONF")"
fi
TREE_WRAPPER="$REPO_DIR/scripts/aperire-node-wrapper.sh"
WRAPPER="$(trusted_wrapper_path "$INSTANCE")"

carry_legacy_conf() {
  [[ -n "$LEGACY_CONF" && ! -e "$CONF" && -f "$LEGACY_CONF" ]] || return 0
  conf_copy "$LEGACY_CONF" "$CONF" || die "could not carry $LEGACY_CONF to $CONF"
  info "carried $LEGACY_CONF to $CONF, unchanged"
}

place_wrapper() {
  say "Placing the wrapper where the Advisor's socket runs it"
  command -v python3 >/dev/null || die "missing: python3 (the check that no service account can write the wrapper needs it)"
  [[ -f "$TREE_WRAPPER" ]] || die "no wrapper at $TREE_WRAPPER"
  carry_legacy_conf
  trusted_place_node_wrapper "$REPO_DIR" "$INSTANCE" \
    || die "the wrapper was not placed, so nothing else was changed. The lines above
   name the file and the account that can write it. Root will not run a copy
   a service account can change: make it writable by its owner only, then
   run this again."
}

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
info() { printf '   %s\n' "$*"; }
die()  { printf '\n\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

# The configuration is read by the wrapper's root socket at any moment, so it
# is never rewritten in place: a reader that lands mid-write sees a truncated
# file and refuses (#925). Each write goes to a temp file beside the target,
# gets its final owner and mode, is synced, then renamed over it. A failure
# at any step leaves the old file untouched and removes the temp file.
# conf_put reads stdin from a here-string, not a pipe, so it runs in this shell
# and the trap below can see the temp name.
#
# mv -fT so a directory at the destination is an error and not a place to
# drop the temp file into, a symlink is refused as a source so the target
# never becomes a link, and an interrupt between mktemp and mv removes the
# temp file through the EXIT trap.
_CONF_TMP=""
trap 'rm -f "${_CONF_TMP:-}"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
conf_put() { # $1 = destination, stdin = content
  local dest="$1"
  _CONF_TMP="$(mktemp "$(dirname "$dest")/.$(basename "$dest").XXXXXX")" || return 1
  if cat > "$_CONF_TMP" && chown root:root "$_CONF_TMP" && chmod 0644 "$_CONF_TMP" \
     && { sync "$_CONF_TMP" 2>/dev/null || true; } && mv -fT "$_CONF_TMP" "$dest"; then
    _CONF_TMP=""
    return 0
  fi
  rm -f "$_CONF_TMP"; _CONF_TMP=""
  return 1
}
conf_copy() { # $1 = source, $2 = destination; keeps owner, mode and times
  local src="$1" dest="$2"
  [[ -L "$src" ]] && return 1
  _CONF_TMP="$(mktemp "$(dirname "$dest")/.$(basename "$dest").XXXXXX")" || return 1
  if cp -a "$src" "$_CONF_TMP" && { sync "$_CONF_TMP" 2>/dev/null || true; } && mv -fT "$_CONF_TMP" "$dest"; then
    _CONF_TMP=""
    return 0
  fi
  rm -f "$_CONF_TMP"; _CONF_TMP=""
  return 1
}

# The one way anything here asks docker what is running, and the one place
# that tells a refused answer from an absence (#142).
[[ -r "$NW_SELF/docker-ask-lib.sh" ]] \
  || die "$NW_SELF/docker-ask-lib.sh is missing from this checkout"
# shellcheck source=scripts/docker-ask-lib.sh
. "$NW_SELF/docker-ask-lib.sh"

[[ $EUID -eq 0 ]] || die "run with sudo — $CONF must be owned by root, or the service could rewrite its own limits"

# An update's refresh: the root-owned copies only, from this tree, where the
# wrapper is in use. Detects nothing and writes no configuration. This is
# what get-aperire.sh --update and the lab's fleet update both run, so the two
# ways a release reaches a host place the same bytes the same way.
#
# It converges, not only copies (#756 review, M1; ADR 0025): every instance's
# copy is placed, its unit's --wrapper= is pointed at the copy, an Advisor on
# its own account gets its root socket and the full sandbox, and the sudo rule
# an older release wrote goes: the same state a fresh install leaves. Exit 5
# means one step is left: an Advisor still running on that rule keeps it
# until it restarts, and running this again after that removes it. Exit 7
# is an Advisor on a shared account, which install-advisor-account.sh moves.
# Exit 6 and exit 8 must stop an update. 6: a copy was refused while an old
# rule still grants a file in the tree that a service account can write. 8:
# an Advisor whose build reaches the node only through its socket, with the
# socket not working, so it is cut off at its next start.
if [[ "${1:-}" == --refresh ]]; then
  say "Bringing the wrapper, the Advisor's unit and its socket to what a fresh install has"
  command -v python3 >/dev/null || die "missing: python3"
  carry_legacy_conf
  rc=0
  trusted_update_node_wrapper "$REPO_DIR" "$DEFAULT_CONF" || rc=$?
  case "$rc" in
    0) info "every instance on this host runs the root-owned copy, and no Advisor holds a sudo rule" ;;
    5) info "left: restart the Advisor, then run this again:"
       info "  sudo systemctl restart aperire-advisord && curl -fsSL https://get.aperire.one | bash -s -- --update --force" ;;
    7) info "left: an Advisor on a shared account; the line above names the one command that moves it" ;;
    6) printf '\n\033[1;31mREFUSED:\033[0m the Advisor may still run, as root, a file a service account can\n' >&2
       printf '   write. Nothing was copied. Put the release back as it shipped, then\n' >&2
       printf '   run this again:  curl -fsSL https://get.aperire.one | bash -s -- --update --force\n' >&2 ;;
    8) printf '\n\033[1;31mSTRANDED:\033[0m an Advisor here reaches the node only through its root socket,\n' >&2
       printf '   and the socket is not working. The lines above say why. Put that right,\n' >&2
       printf '   then run this again:  curl -fsSL https://get.aperire.one | bash -s -- --update --force\n' >&2 ;;
    *) printf '\n\033[1;31merror:\033[0m not converged; the lines above say which step and why\n' >&2 ;;
  esac
  exit "$rc"
fi

# Which host this is, decided before the dependency gate rather than after it.
# --no-node writes a fixed configuration and runs no detection: no
# `docker inspect`, no profile for python3 to parse, no RPC for curl to reach.
# Demanding Docker there refused an aggregator the one mode built for
# aggregators (fresh-install run, 2026-08-20). --native is the third shape,
# and it never touches docker either: everything it reads comes from systemd
# and the host's own package database.
NO_NODE=0
NATIVE=0
AUTO_UNIT=""
case "${1:-}" in
  --no-node) NO_NODE=1 ;;
  --native)  NATIVE=1 ;;
  '')
    # No flag at all: a re-run, not a first install. install-advisord.sh and
    # the fleet menu (scripts/aperire.sh) both call this bare, and used to
    # fall into the container branch below no matter what shape the host
    # actually is, which demanded a docker binary that a native host never
    # had (#528). This host's own already-written configuration is the one
    # record that cannot disagree with itself, so it is read here rather than
    # assumed: KIND=native carries the shape forward, and SERVICE=none (the
    # --no-node marker, which never gets a KIND= line) carries that one
    # forward too. No configuration yet (a true first run) leaves both flags
    # at 0, which is the container path this always defaulted to.
    if [[ -f "$CONF" ]]; then
      _PRIOR_KIND="$(awk -F= '$1=="KIND"{sub(/^[^=]*=/,""); print; exit}' "$CONF")"
      _PRIOR_SERVICE="$(awk -F= '$1=="SERVICE"{sub(/^[^=]*=/,""); print; exit}' "$CONF")"
      if [[ "$_PRIOR_KIND" == native ]]; then
        NATIVE=1
        AUTO_UNIT="$_PRIOR_SERVICE"
      elif [[ -z "$_PRIOR_KIND" && "$_PRIOR_SERVICE" == none ]]; then
        NO_NODE=1
      fi
    fi
    ;;
esac

# Checked before anything is written. python3 parses the detected profile and
# awk reads it back; a missing one halfway through leaves a partial config that
# the wrapper would then refuse, with a confusing message.
TOOLS=(awk install python3)
DOCKER_NOTE=""
if [[ $NO_NODE -eq 0 && $NATIVE -eq 0 ]]; then
  TOOLS+=(docker python3 curl)
  DOCKER_NOTE=$'\n   Docker must already be installed and running.'
elif [[ $NATIVE -eq 1 ]]; then
  TOOLS+=(systemctl python3 curl)
fi
for t in "${TOOLS[@]}"; do
  command -v "$t" >/dev/null || die "missing: $t
   On Debian or Ubuntu:  sudo apt-get install -y python3 gawk curl coreutils${DOCKER_NOTE}"
done

# Placed before any branch writes a configuration, so a refusal changes
# nothing, and every check below runs the copy the Advisor's socket will run.
place_wrapper

# ── No node here (an aggregator) ─────────────────────────────────────
# Same file, same owner, same shapes; the values just say "none" where a node
# would be named. The wrapper's own parser understands SERVICE=none and turns
# every node verb into a refusal that says why, so nothing below in this
# script (detection, the compose-vs-container check, the status probe) applies.
if [[ $NO_NODE -eq 1 ]]; then
  say "Writing $CONF for a host that runs no node"
  [[ -f "$CONF" ]] && { conf_copy "$CONF" "$CONF.previous" || die "could not keep $CONF as $CONF.previous"; info "previous configuration kept at $CONF.previous"; }
  install -d -m 0755 -o root -g root "$(dirname "$CONF")"
  CONTENT=$(
    printf '# Written by scripts/install-node-wrapper.sh --no-node: this host runs no\n'
    printf '# node (an aggregator). The Advisor may read the host (unit state, journal,\n'
    printf '# memory, disk); every node verb refuses. Root-owned on purpose.\n'
    printf 'REPO=none\n'
    printf 'SERVICE=none\n'
    printf 'PROJECT=none\n'
    printf 'COMPOSE_FILE=/dev/null\n'
    printf 'CONFIG_FILE=/dev/null\n'
    printf 'ADMIN_RPC=http://127.0.0.1:0\n'
    printf 'LOG=%s\n' "$REPO_DIR/advisor/evidence/wrapper.log"
  ) || die "could not build the configuration, nothing was changed"
  conf_put "$CONF" <<<"$CONTENT" || die "could not write $CONF, the old one is untouched"
  say "Checking the wrapper against what was just written"
  bash "$WRAPPER" resources >/dev/null 2>&1 || die "the wrapper refused 'resources' with the new configuration"
  info "resources    ok"
  bash "$WRAPPER" unit-status >/dev/null 2>&1 || die "the wrapper refused 'unit-status' with the new configuration"
  info "unit-status  ok"
  if out=$(bash "$WRAPPER" inspect 2>&1); then die "the wrapper ran a node verb on a node-less host: $out"; fi
  info "inspect      refused, as it must: $(printf '%s' "$out" | tail -1)"
  # No chown of the wrapper log here, and that is deliberate.
  #
  # This used to hand the log to whoever owns advisor/evidence, because the
  # checks above run the wrapper as root and could leave a root-owned log
  # the Advisor's account then cannot append to. The chown followed a link:
  # that directory belongs to the Advisor's account, so that account could
  # point wrapper.log at any file it can read and have root hand it over.
  # The wrapper itself now creates the log as the directory's owner and
  # moves a root-owned one aside, so there is nothing left for root to
  # repair from out here.
  # Host reads include the journal, which is root or the systemd-journal group.
  # A node-less host has no socket for the Advisor (nothing to escalate for),
  # so read-only journal membership is the whole grant. Takes effect on the
  # service's next start.
  ADV_USER=$(systemctl show aperire-advisord -p User --value 2>/dev/null || true)
  if [[ -n "$ADV_USER" && "$ADV_USER" != "root" ]] && id "$ADV_USER" >/dev/null 2>&1; then
    if ! id -nG "$ADV_USER" | tr ' ' '\n' | grep -qx systemd-journal; then
      usermod -aG systemd-journal "$ADV_USER" && info "added $ADV_USER to systemd-journal (read-only journal); restart aperire-advisord to apply"
    else
      info "$ADV_USER already reads the journal (systemd-journal group)"
    fi
  fi
  say "Done"
  info "$CONF written. The Advisor's host reads work on this host; node verbs refuse."
  exit 0
fi

# ── A native node (the vendor's package, run by systemd) ────────────────
# No advisord here and no docker: everything below comes from systemd and the
# host's own package database, read the same way the wrapper itself reads
# them once this configuration exists. Detect, write, then prove with reads,
# the same discipline the container path follows, in the other shape.
if [[ $NATIVE -eq 1 ]]; then
  # A key=value line inside a named stanza, up to the next stanza header.
  # rippled.cfg's admin-port and node-db stanzas are this shape; a comment or
  # a blank line between two such lines is skipped, never taken as the value.
  cfg_kv() { # $1=file $2=stanza $3=key
    awk -v s="$2" -v k="$3" '
      $0 ~ "^[[:space:]]*\\[" s "\\][[:space:]]*$" { insec=1; next }
      insec && $0 ~ /^[[:space:]]*\[/ { insec=0 }
      insec && $0 ~ "^[[:space:]]*" k "[[:space:]]*=" {
        sub(/^[^=]*=[[:space:]]*/, ""); sub(/[[:space:]]+$/, ""); print; exit
      }
    ' "$1" 2>/dev/null
  }
  # A stanza whose value is the line under its own header, rather than a
  # key=value pair. [debug_logfile] and [validators_file] are this shape.
  # Blanks and comments between the header and the value are skipped.
  cfg_line() { # $1=file $2=stanza
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

  say "Detecting a native install"
  # $2 is an explicit --native <unit> call; AUTO_UNIT is this host's own
  # previously-recorded SERVICE when NATIVE came from reading $CONF above
  # (a bare re-run) rather than from the command line. Either beats the
  # candidate loop below, which exists for the case neither is known yet.
  UNIT=${2:-$AUTO_UNIT}
  if [[ -z "$UNIT" ]]; then
    for cand in xrpld.service rippled.service; do
      ls=$(systemctl show "$cand" --property=LoadState --value 2>/dev/null) || ls=''
      if [[ "$ls" == loaded ]]; then UNIT=$cand; break; fi
    done
    [[ -n "$UNIT" ]] || die "neither xrpld.service nor rippled.service is loaded on this host.
   Name the unit yourself:  curl -fsSL https://get.aperire.one | bash -s -- --node-wrapper-native <unit>${INSTANCE:+ --instance $INSTANCE}"
    info "detected unit: $UNIT"
  else
    ls=$(systemctl show "$UNIT" --property=LoadState --value 2>/dev/null) || ls=''
    [[ "$ls" == loaded ]] || die "systemd does not have $UNIT loaded (${ls:-no answer})"
    info "unit: $UNIT"
  fi

  # The binary this unit starts, and the --conf argument it starts it with,
  # both read from systemd rather than assumed. An operator's own unit file
  # can point anywhere.
  EXECSTART=$(systemctl show "$UNIT" --property=ExecStart --value 2>/dev/null)
  BIN=$(printf '%s' "$EXECSTART" | grep -oE 'path=[^ ;]+' | head -1)
  BIN=${BIN#path=}
  [[ -n "$BIN" ]] || die "could not read the binary $UNIT starts; its ExecStart did not parse: $EXECSTART"
  EXECCONF=$(printf '%s' "$EXECSTART" | grep -oE -- '--conf[= ][^ ;]+' | head -1)
  EXECCONF=${EXECCONF#--conf}
  EXECCONF=${EXECCONF# }
  EXECCONF=${EXECCONF#=}

  P_CONFIG=""
  for cand in "$EXECCONF" /etc/xrpld/xrpld.cfg /etc/opt/ripple/rippled.cfg; do
    [[ -n "$cand" && -f "$cand" ]] && { P_CONFIG=$cand; break; }
  done
  [[ -n "$P_CONFIG" ]] || die "could not find $UNIT's config file.
   Checked its own --conf argument, /etc/xrpld/xrpld.cfg and
   /etc/opt/ripple/rippled.cfg. None of those exist on this host."
  info "config file: $P_CONFIG"

  # The package name and the version installed, from whichever package
  # manager owns this binary, never guessed from the unit's name, so a
  # renamed package or a from-source binary is told apart from a real one.
  P_REPO="" P_VERSION=""
  if command -v dpkg >/dev/null 2>&1 && command -v dpkg-query >/dev/null 2>&1; then
    # Read to the end of what dpkg prints. A consumer that exits on the first
    # line closes the pipe under a writer that is still writing, the writer
    # takes SIGPIPE, and under pipefail this assignment fails with 141 and no
    # message (#411's shape; it turned every PR red on the hosted runner).
    P_REPO=$(dpkg -S "$BIN" 2>/dev/null | awk -F: 'NR==1{print $1}')
    [[ -n "$P_REPO" ]] && P_VERSION=$(dpkg-query -W -f='${Version}' "$P_REPO" 2>/dev/null)
  elif command -v rpm >/dev/null 2>&1; then
    P_REPO=$(rpm -qf --queryformat '%{NAME}\n' "$BIN" 2>/dev/null)
    [[ -n "$P_REPO" ]] && P_VERSION=$(rpm -qf --queryformat '%{VERSION}-%{RELEASE}\n' "$BIN" 2>/dev/null)
  fi
  [[ -n "$P_REPO" ]] || die "no installed package owns $BIN (checked dpkg -S / rpm -qf).
   The wrapper's native mode drives a package the host's own package manager
   knows about, so it can ask that database for a version before an upgrade
   and resolve a rollback target from it after one. A from-source build or an
   unpackaged binary is not a fit for this mode; run it under the container
   path instead, or package it first."
  info "package: $P_REPO $P_VERSION"

  # The admin RPC. Absent or non-loopback is refused here, by name, rather
  # than written into a configuration the wrapper would refuse at every call.
  RPC_PORT=$(cfg_kv "$P_CONFIG" port_rpc_admin_local port)
  RPC_IP=$(cfg_kv "$P_CONFIG" port_rpc_admin_local ip)
  [[ -n "$RPC_IP" ]] || RPC_IP=$(cfg_kv "$P_CONFIG" port_rpc_admin_local admin)
  [[ -n "$RPC_PORT" ]] || die "$P_CONFIG has no [port_rpc_admin_local] port.
   There is no admin RPC in this config for the wrapper to reach. Add a
   [port_rpc_admin_local] stanza with a loopback ip and a port, and run this
   again."
  case "$RPC_IP" in
    127.0.0.1|localhost|::1|'') ADMIN_RPC="http://127.0.0.1:${RPC_PORT}" ;;
    *) die "$P_CONFIG's [port_rpc_admin_local] answers on $RPC_IP, not loopback.
   The wrapper only drives a node whose admin RPC is on loopback." ;;
  esac
  info "admin RPC (from the config): $ADMIN_RPC"

  # The data path, read the same key the wrapper's own inspection verbs read.
  P_DATA=$(cfg_kv "$P_CONFIG" node_db path)
  P_VALIDATORS=$(cfg_line "$P_CONFIG" validators_file)
  if [[ -n "$P_VALIDATORS" && "$P_VALIDATORS" != /* ]]; then
    P_VALIDATORS="$(dirname "$P_CONFIG")/$P_VALIDATORS"
  fi

  # The rotation guard's log source: the file [debug_logfile] names, or the
  # journal when the config names none, which is what a unit with no
  # StandardOutput= override leaves stdout going to.
  P_DEBUG_LOGFILE=$(cfg_line "$P_CONFIG" debug_logfile)
  if [[ -n "$P_DEBUG_LOGFILE" ]]; then
    [[ "$P_DEBUG_LOGFILE" == /* ]] || P_DEBUG_LOGFILE="$(dirname "$P_CONFIG")/$P_DEBUG_LOGFILE"
    NODE_LOG_SOURCE="$P_DEBUG_LOGFILE"
    info "log source (from [debug_logfile]): $NODE_LOG_SOURCE"
  else
    NODE_LOG_SOURCE="journal"
    info "log source: journal ($P_CONFIG names no [debug_logfile])"
  fi

  # The domain this validator claims, if it claims one, the same read the
  # container path takes, once the admin RPC answers.
  P_DOMAIN=$(curl -s --max-time 5 --data '{"method":"server_info","params":[{}]}' "$ADMIN_RPC" 2>/dev/null \
    | python3 -I -c 'import sys,json
try:
    i=json.load(sys.stdin)["result"]["info"]
    print(i.get("validator_domain") or i.get("domain") or "")
except Exception:
    print("")' 2>/dev/null || true)
  TOML_URL=""
  [[ -n "$P_DOMAIN" ]] && TOML_URL="https://$P_DOMAIN/.well-known/xrp-ledger.toml"

  say "Writing $CONF"
  PREVIOUS=""
  if [[ -f "$CONF" ]]; then
    PREVIOUS="$CONF.previous"
    conf_copy "$CONF" "$PREVIOUS" || die "could not keep $CONF as $PREVIOUS"
    info "previous configuration kept at $PREVIOUS"
  fi

  install -d -m 0755 -o root -g root "$(dirname "$CONF")"
  CONTENT=$(
    printf '# Written by scripts/install-node-wrapper.sh --native from the unit running\n'
    printf '# on this host. Read by scripts/aperire-node-wrapper.sh, which is the only\n'
    printf '# thing that touches the node. Root-owned on purpose.\n'
    printf '#\n'
    printf '# Re-run the installer after anything that moves the node, a package\n'
    printf '# reinstall onto a different unit, a config relocation, a fresh install.\n'
    printf 'KIND=native\n'
    printf 'REPO=%s\n'         "$P_REPO"
    printf 'SERVICE=%s\n'      "$UNIT"
    printf 'CONFIG_FILE=%s\n'  "$P_CONFIG"
    printf 'ADMIN_RPC=%s\n'    "$ADMIN_RPC"
    printf 'LOG=%s\n'          "$REPO_DIR/advisor/evidence/wrapper.log"
    printf 'NODE_LOG_SOURCE=%s\n' "$NODE_LOG_SOURCE"
    printf '#\n'
    printf '# Used only by the read-only inspection verbs. Missing values make the\n'
    printf '# verb that needs one refuse and say so; the upgrade path is unaffected.\n'
    printf 'DATA_PATH=%s\n'       "$P_DATA"
    printf 'VALIDATORS_PATH=%s\n' "$P_VALIDATORS"
    printf 'TOML_URL=%s\n'        "$TOML_URL"
  ) || die "could not build the configuration, nothing was changed"
  conf_put "$CONF" <<<"$CONTENT" || die "could not write $CONF, the old one is untouched"
  info "written, root-owned, mode 0644"

  revert() {
    printf '\n\033[1;31m== Reverting\033[0m\n'
    if [[ -n "$PREVIOUS" ]]; then
      conf_copy "$PREVIOUS" "$CONF" || die "could not restore $PREVIOUS to $CONF"
      info "the previous configuration is back in place."
    else
      rm -f "$CONF"
      info "removed $CONF, there was no previous one to restore."
    fi
    die "$1"
  }

  say "Checking the wrapper against what was just written"

  systemctl show "$UNIT" --property=LoadState --value 2>/dev/null | grep -qx loaded \
    || revert "systemd no longer has $UNIT loaded"
  info "the unit resolves"

  STATE=$(bash "$WRAPPER" status 2>/dev/null \
    | python3 -I -c 'import sys,json;print(json.load(sys.stdin)["result"]["info"]["server_state"])' 2>/dev/null || true)
  [[ -n "$STATE" ]] || revert "the node did not answer on $ADMIN_RPC, check the [port_rpc_admin_local] stanza in $P_CONFIG"
  info "the node answers on its admin RPC (state: $STATE)"

  # Same rule: the wrapper writes its inspect answer line by line, so the
  # consumer keeps reading after the line it wanted rather than exiting on it.
  INSPECT_VER=$(bash "$WRAPPER" inspect 2>/dev/null | awk -F= '!f && /^AperirePackageVersion=/{print $2; f=1}')
  [[ "$INSPECT_VER" == "$P_VERSION" ]] \
    || revert "the wrapper reads the package version as '$INSPECT_VER', not '$P_VERSION', check REPO"
  info "the package version resolves ($P_VERSION)"

  # The rotation guard's log half: the declared source must answer, and the
  # timestamp at the front of what it returns must be one the guard's own
  # rotation_stamp() can read. Answering is not enough: a source that
  # answers with a stamp the guard cannot parse would still make every
  # restart refuse, since an unreadable stamp is treated as "in flight" and
  # the safe direction is to refuse rather than guess. Both are proven here,
  # once, rather than found at the first restart.
  if [[ "$NODE_LOG_SOURCE" == journal ]]; then
    LASTLINE=$(journalctl --no-pager --output=short-iso --unit="$UNIT" --lines=1 2>/dev/null) || LASTLINE=''
  else
    LASTLINE=$(tail -n 1 "$NODE_LOG_SOURCE" 2>/dev/null) || LASTLINE=''
  fi
  [[ -n "$LASTLINE" ]] || revert "the declared log source ($NODE_LOG_SOURCE) is silent, no line could be read from it.
   The store-rotation guard reads this source before every restart. A source
   that answers nothing would drop the guard to the lock alone with no line
   saying so (the failure behind #79). Start the
   node so it writes at least one line, or point NODE_LOG_SOURCE somewhere
   else, and run this again."
  info "the log source answers"

  # The wrapper's own rotation_stamp(), extracted rather than reimplemented,
  # so this proof and the guard it proves agree by construction.
  ROTATION_STAMP_FN=$(sed -n '/^rotation_stamp() {/,/^}/p' "$WRAPPER")
  [[ -n "$ROTATION_STAMP_FN" ]] || revert "rotation_stamp() has moved in $WRAPPER; this installer can no longer prove the log source parses"
  eval "$ROTATION_STAMP_FN"
  # rotation_stamp() reads KIND and NODE_LOG_SOURCE as globals; NODE_LOG_SOURCE
  # is already set above, and KIND is set only for this call since nothing
  # else in this script needs the wrapper's own shape variable.
  # shellcheck disable=SC2034
  KIND=native
  STAMP=$(rotation_stamp "$LASTLINE")
  date -d "$STAMP" >/dev/null 2>&1 \
    || revert "the timestamp at the front of $NODE_LOG_SOURCE's last line does not parse ('$STAMP' read from: $LASTLINE).
   The store-rotation guard times a rotation from this, and a stamp it cannot
   read is treated as a rotation still in flight, which would refuse every
   restart. Check the log's own format, or declare a different
   NODE_LOG_SOURCE, and run this again."
  info "its timestamp parses"

  say "Done"
  info "the wrapper is configured and answering. Nothing about the node changed."
  if [[ -n "$PREVIOUS" ]]; then info "previous configuration still at $PREVIOUS"; fi

  cat <<EOF

   Optional, and the stronger setup:

   There is no docker group on a native host, so an account with no group
   memberships at all and one root socket is a real boundary here, not an
   allow-list plus an audit trail.

   To make it that account, run the update at a terminal and answer Y when it
   offers to move the Advisor:

     curl -fsSL https://get.aperire.one | bash -s -- --update --force

   That does the whole move: creates the account, hands it the state
   it owns, gives it its root socket (no sudo), and verifies the service
   still works before it keeps the change.
EOF

  # The one thing an adopt can leave behind: an operator compact accepted
  # against the node this host used to run (#466). Pointing the wrapper at a
  # different node is exactly when that becomes true, and nothing else on the
  # host says so until someone asks the Advisor for a restart and is told the
  # class is not permitted.
  #
  # Read-only, silent when there is nothing to say, and never accepts
  # anything. Suppressed when a parent installer is going to print it at the
  # end of its own run, so the notice appears once, at the end, rather than
  # in the middle of a longer install.
  if [[ "${APERIRE_COMPACT_CHECK:-1}" != "0" ]]; then
    bash "$(dirname "${BASH_SOURCE[0]}")/aperire-compact-check.sh" --node "$UNIT" || true
  fi
  exit 0
fi

# Which container to describe.
#
# Detected rather than defaulted. The old default was this project's own
# container name, which is right on exactly one machine and silently wrong
# everywhere else — it would describe nothing, or worse, describe some other
# container that happened to share the name. The node is found by its image
# instead, which is the thing that actually identifies it.
# The admin RPC this container actually answers on. Defaulted, it is the
# first node's port — and on a host running two nodes that means the wrapper
# for the second one talks to the first. The published port mapping is
# resolved from the container below, once it is known; this is only the
# fallback for a node that publishes nothing (native installs, host
# networking).
ADMIN_RPC=${2:-}
CONTAINER=${1:-}

# The image a container was created from, as it was written (Config.Image),
# for a container docker ps shows only by image ID. Asked the way docker_ask
# asks: as this account, then through sudo. On failure prints docker's own
# complaint and returns 1.
container_config_image() { # $1 = container name
  local out err
  if out="$(docker inspect "$1" --format '{{.Config.Image}}' 2>/dev/null)" && [[ -n "$out" ]]; then
    printf '%s' "$out"; return 0
  fi
  if command -v sudo >/dev/null 2>&1 \
     && out="$(sudo -n docker inspect "$1" --format '{{.Config.Image}}' 2>/dev/null)" && [[ -n "$out" ]]; then
    printf '%s' "$out"; return 0
  fi
  err="$(docker inspect "$1" --format '{{.Config.Image}}' 2>&1 >/dev/null | head -1 || true)"
  printf '%s' "${err:-no reason given}"
  return 1
}
if [[ -z "$CONTAINER" ]]; then
  # A refused query is not an empty host. Read as one it reaches the die
  # below, which names the wrong cause and sends the operator looking for a
  # node that is running the whole time (#142).
  # On a non-zero return DOCKER_SAID is docker's complaint, not the list.
  DOCKER_SAID=''; DOCKER_ASK=0
  DOCKER_SAID="$(docker_ask '{{.Names}}\t{{.Image}}')" || DOCKER_ASK=$?
  if [[ $DOCKER_ASK -eq 2 ]]; then
    die "docker is installed here and would not say what is running.
   It said: ${DOCKER_SAID}
   That is not the same as no node running here, so this stops rather than
   report an empty host. Run it as an account that can reach docker, or name
   the container yourself:  curl -fsSL https://get.aperire.one | bash -s -- --node-wrapper <container-name>${INSTANCE:+ --instance $INSTANCE}"
  fi
  # A container created from a digest reference (rippleci/xrpld@sha256:...,
  # which the Advisor's own upgrade makes) has no name to show: docker ps
  # prints the short image ID in the Image column. For those rows the name
  # the container was created from is read back with docker inspect, so the
  # node is still found by its image (#894).
  #
  # A row that cannot be resolved is remembered, not fatal: a container that
  # exits between the ps and the inspect, or one docker will not describe, is
  # not the node when the node was already found by name. Only an empty FOUND
  # with an unresolved row stops the run, because then that row may be the
  # node and the host is not known to be empty (#898 review).
  FOUND=()
  UNRESOLVED=()
  UNRESOLVED_SAID=""
  while IFS=$'\t' read -r cname cimage; do
    [[ -n "$cname" ]] || continue
    if [[ "$cimage" =~ ^(sha256:)?[0-9a-fA-F]{12,64}$ ]]; then
      if ! resolved="$(container_config_image "$cname")"; then
        # A container docker says no longer exists exited between ps and
        # inspect: it is not running, so it is not the node. Any other reason
        # leaves the row possibly being the node (#898 review, N5).
        if [[ "$resolved" =~ [Nn]o\ such\ (object|container) ]]; then continue; fi
        UNRESOLVED+=("$cname")
        [[ -n "$UNRESOLVED_SAID" ]] || UNRESOLVED_SAID="$resolved"
        continue
      fi
      cimage="$resolved"
    fi
    cimage="${cimage%%@*}"
    shopt -s nocasematch
    if [[ "$cimage" =~ (rippled|xrpld|xahaud) ]]; then FOUND+=("$cname"); fi
    shopt -u nocasematch
  done <<<"$DOCKER_SAID"
  if [[ ${#FOUND[@]} -eq 0 && ${#UNRESOLVED[@]} -gt 0 ]]; then
    die "docker is installed here and would not say which image these containers were created from: ${UNRESOLVED[*]}
   It said: ${UNRESOLVED_SAID}
   That is not the same as no node running here, so this stops rather than
   report an empty host. Run it as an account that can reach docker, or name
   the container yourself:  curl -fsSL https://get.aperire.one | bash -s -- --node-wrapper <container-name>${INSTANCE:+ --instance $INSTANCE}"
  fi
  # One match and one row docker would not describe, for a reason other than
  # the container being gone: the unread row may be the node and the match its
  # exporter, so the match is not taken in silence. Failing closed costs the
  # operator one command (#898 review, N5).
  if [[ ${#FOUND[@]} -eq 1 && ${#UNRESOLVED[@]} -gt 0 ]]; then
    die "found one candidate node container, ${FOUND[0]}, but docker would not say which image these containers were created from: ${UNRESOLVED[*]}
   It said: ${UNRESOLVED_SAID}
   One of them may be the node, so ${FOUND[0]} is not taken on its own.
   Name the one you mean:  curl -fsSL https://get.aperire.one | bash -s -- --node-wrapper <container-name>${INSTANCE:+ --instance $INSTANCE}"
  fi
  case ${#FOUND[@]} in
    1) CONTAINER=${FOUND[0]}
       info "detected node container: $CONTAINER" ;;
    0) die "could not find a running node container.
   Nothing running here has an image named for rippled, xrpld or xahaud.
   Name it explicitly:  curl -fsSL https://get.aperire.one | bash -s -- --node-wrapper <container-name>${INSTANCE:+ --instance $INSTANCE}" ;;
    *) die "found more than one candidate node container: ${FOUND[*]}
   Name the one you mean:  curl -fsSL https://get.aperire.one | bash -s -- --node-wrapper <container-name>${INSTANCE:+ --instance $INSTANCE}" ;;
  esac
fi

say "Reading the deployment"
info "container: $CONTAINER"
# Resolve the host port this container publishes its admin RPC on, so a
# second node on the same host is described by its own node and not by
# whichever one happens to own the default port.
if [[ -z "$ADMIN_RPC" ]]; then
  RPC_HOST_PORT=$(docker inspect "$CONTAINER" \
    --format '{{range $p, $conf := .NetworkSettings.Ports}}{{if eq $p "5005/tcp"}}{{(index $conf 0).HostPort}}{{end}}{{end}}' 2>/dev/null || true)
  if [[ -n "$RPC_HOST_PORT" ]]; then
    ADMIN_RPC="http://127.0.0.1:${RPC_HOST_PORT}"
    info "admin RPC resolved from the container's published port: $ADMIN_RPC"
  else
    ADMIN_RPC="http://127.0.0.1:5005"
    info "container publishes no admin port; assuming $ADMIN_RPC"
  fi
fi

# The deployment, read by root from root's own `docker inspect` (#764). This
# used to run the tree's advisor/bin/aperire-advisord --print-profile as root,
# a binary built on this host that no digest covers, so anything that could
# write it got root code at the next install. Root runs no tree binary now.
# The python below reads the same inspect answer the same way the Go
# parseContainerInspect does (advisor/internal/host/profile.go): one
# container, the compose labels for project, service and file, the image
# split into repository and tag, and the mounts for the node's config, data
# and validators file. Keep the two in step. Every value is a bounded string
# with no control character, because it is written into the configuration the
# wrapper reads one line at a time.
INSPECT_RAW="$(docker inspect "$CONTAINER" 2>/dev/null | head -c 1048577 || true)"
(( ${#INSPECT_RAW} <= 1048576 )) || die "docker inspect $CONTAINER answered with more than 1 MiB; that is not one container"
PROFILE=$(printf '%s' "$INSPECT_RAW" | python3 -I -c '
import json, re, sys
container, admin_rpc = sys.argv[1], sys.argv[2]
def refuse(why):
    sys.stderr.write(why + "\n"); sys.exit(1)
try:
    all_ = json.loads(sys.stdin.read())
except Exception:
    refuse("inspect %r: decode: not JSON" % container)
if not isinstance(all_, list) or len(all_) != 1 or not isinstance(all_[0], dict):
    refuse("inspect %r: expected 1 container" % container)
d = all_[0]
cfg = d.get("Config") if isinstance(d.get("Config"), dict) else {}
labels = cfg.get("Labels") if isinstance(cfg.get("Labels"), dict) else {}
image = cfg.get("Image") if isinstance(cfg.get("Image"), str) else ""
ref = image.rsplit("@", 1)[0] if "@" in image else image
i = ref.rfind(":")
repo, tag = (ref, "") if i < 0 or "/" in ref[i + 1:] else (ref[:i], ref[i + 1:])
if "@" in repo: refuse("inspect %r: the image reference has more than one @" % container)
# The digest a pinned reference names, shaped exactly as the wrapper shapes one
# (sha256: and 64 lowercase hex). Anything else is not carried (#915).
digest = image.rsplit("@", 1)[1] if "@" in image else ""
if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest): digest = ""
def lab(k):
    v = labels.get(k)
    return v if isinstance(v, str) else ""
name = d.get("Name") if isinstance(d.get("Name"), str) else ""
out = {
    "image_repo": repo, "image_tag": tag, "image_digest": digest,
    "compose_project": lab("com.docker.compose.project"),
    "compose_file": lab("com.docker.compose.project.config_files"),
    "service": lab("com.docker.compose.service"),
    "container": name[1:] if name.startswith("/") else name,
    "admin_rpc": admin_rpc, "config_path": "", "data_path": "", "validators_path": "",
}
for m in d.get("Mounts") or []:
    if not isinstance(m, dict): continue
    dest, src = m.get("Destination"), m.get("Source")
    if not isinstance(dest, str) or not isinstance(src, str): continue
    if dest.endswith("rippled.cfg") or dest.endswith("xrpld.cfg"): out["config_path"] = src
    elif dest.endswith("validators.txt"): out["validators_path"] = src
    elif dest in ("/var/lib/rippled", "/var/lib/xrpld"): out["data_path"] = src
if not out["compose_project"] or not out["service"]:
    refuse("container %r carries no compose labels; it was not started by compose" % container)
if not out["config_path"]:
    refuse("container %r exposes no node config mount" % container)
if not out["data_path"]:
    refuse("container %r exposes no data mount" % container)
for k, v in out.items():
    if len(v) > 4096 or re.search(r"[\x00-\x1f\x7f]", v):
        refuse("the %s value is too long or holds a control character, so it is not written into the wrapper configuration" % k)
json.dump(out, sys.stdout)
' "$CONTAINER" "$ADMIN_RPC") \
  || die "could not read the deployment. Is $CONTAINER running, and was it started by docker compose?"

field() { printf '%s' "$PROFILE" | python3 -I -c "import sys,json;print(json.load(sys.stdin).get('$1',''))"; }
P_REPO=$(field image_repo)
P_SERVICE=$(field service)
P_PROJECT=$(field compose_project)
P_COMPOSE=$(field compose_file)
P_CONFIG=$(field config_path)
P_RPC=$(field admin_rpc)
P_TAG=$(field image_tag)
P_DIGEST=$(field image_digest)
P_CONTAINER=$(field container)
P_DATA=$(field data_path)
P_VALIDATORS=$(field validators_path)

# The domain this validator claims, if it claims one. Only used to fetch the
# public .well-known file, which is exactly what anyone else on the network
# can read — so an empty value costs one verb, not correctness.
P_DOMAIN=$(curl -s --max-time 5 --data '{"method":"server_info","params":[{}]}' "$P_RPC" 2>/dev/null \
  | python3 -I -c 'import sys,json
try:
    i=json.load(sys.stdin)["result"]["info"]
    print(i.get("validator_domain") or i.get("domain") or "")
except Exception:
    print("")' 2>/dev/null || true)
TOML_URL=""
if [[ -n "$P_DOMAIN" ]]; then TOML_URL="https://$P_DOMAIN/.well-known/xrp-ledger.toml"; fi

for pair in "image repository:$P_REPO" "service:$P_SERVICE" "compose project:$P_PROJECT" \
            "compose file:$P_COMPOSE" "node config:$P_CONFIG" "admin RPC:$P_RPC"; do
  [[ -n "${pair#*:}" ]] || die "detection returned no ${pair%%:*}; this host is not a compose deployment the wrapper can drive"
  printf '   %-18s %s\n' "${pair%%:*}" "${pair#*:}"
done
if [[ -n "$P_DIGEST" ]]; then
  info "running image      $P_REPO@$P_DIGEST${P_TAG:+ (tag $P_TAG)}"
else
  info "running tag        $P_TAG"
fi
printf '   %-18s %s\n' "data path" "${P_DATA:-<not detected>}"
printf '   %-18s %s\n' "validators file" "${P_VALIDATORS:-<not detected>}"
printf '   %-18s %s\n' "domain TOML" "${TOML_URL:-<no domain claimed>}"

# `recreate` addresses the service by container name, and every other verb that
# names a container uses SERVICE too. On a compose deployment where the
# container is not named after the service, one of those is wrong — better to
# stop here than to discover it during a cutover.
if [[ "$P_SERVICE" != "$P_CONTAINER" ]]; then
  die "the compose service is '$P_SERVICE' but the container is named '$P_CONTAINER'.
   The wrapper addresses the node by one name for both. Rename the container to
   match the service, or the upgrade path will act on the wrong target."
fi

say "Writing $CONF"
PREVIOUS=""
if [[ -f "$CONF" ]]; then
  PREVIOUS="$CONF.previous"
  conf_copy "$CONF" "$PREVIOUS" || die "could not keep $CONF as $PREVIOUS"
  info "previous configuration kept at $PREVIOUS"
fi

install -d -m 0755 -o root -g root "$(dirname "$CONF")"
CONTENT=$(
  printf '# Written by scripts/install-node-wrapper.sh from the running deployment.\n'
  printf '# Read by scripts/aperire-node-wrapper.sh, which is the only thing that\n'
  printf '# touches the node. Root-owned on purpose: the account the Advisor runs\n'
  printf '# as must not be able to widen its own reach by editing this.\n'
  printf '#\n'
  printf '# Re-run the installer after anything that moves the node — a compose\n'
  printf '# file relocation, a rename, a fresh deployment.\n'
  printf 'REPO=%s\n'         "$P_REPO"
  printf 'SERVICE=%s\n'      "$P_SERVICE"
  printf 'PROJECT=%s\n'      "$P_PROJECT"
  printf 'COMPOSE_FILE=%s\n' "$P_COMPOSE"
  printf 'CONFIG_FILE=%s\n'  "$P_CONFIG"
  printf 'ADMIN_RPC=%s\n'    "$P_RPC"
  printf 'LOG=%s\n'          "$REPO_DIR/advisor/evidence/wrapper.log"
  printf '#\n'
  printf '# Used only by the read-only inspection verbs. Missing values make the\n'
  printf '# verb that needs one refuse and say so; the upgrade path is unaffected.\n'
  printf 'DATA_PATH=%s\n'       "$P_DATA"
  printf 'VALIDATORS_PATH=%s\n' "$P_VALIDATORS"
  printf 'TOML_URL=%s\n'        "$TOML_URL"
) || die "could not build the configuration, nothing was changed"
conf_put "$CONF" <<<"$CONTENT" || die "could not write $CONF, the old one is untouched"
# conf_put leaves it readable by anyone, writable only by root. The wrapper may
# run as the service account or through sudo, and both must be able to read it.
info "written, root-owned, mode 0644"

revert() {
  printf '\n\033[1;31m== Reverting\033[0m\n'
  if [[ -n "$PREVIOUS" ]]; then
    conf_copy "$PREVIOUS" "$CONF" || die "could not restore $PREVIOUS to $CONF"
    info "the previous configuration is back in place."
  else
    rm -f "$CONF"
    info "removed $CONF — there was no previous one to restore."
  fi
  die "$1"
}

# ── Verification. Each verb exercises one detected value, and each is a read.
# Writing the file is not the same as it working: a wrong value here fails in
# the middle of an upgrade, which is the worst possible moment to find out.
say "Checking the wrapper against what was just written"

# SERVICE and PROJECT are only exercised by verbs that act, so the closest
# read-only proof is that docker resolves the name at all.
docker inspect "$P_SERVICE" >/dev/null 2>&1 \
  || revert "docker does not know a container named '$P_SERVICE'"
info "the service name resolves"

# ADMIN_RPC — the node answering for itself.
STATE=$(bash "$WRAPPER" status 2>/dev/null \
  | python3 -I -c 'import sys,json;print(json.load(sys.stdin)["result"]["info"]["server_state"])' 2>/dev/null || true)
[[ -n "$STATE" ]] || revert "the node did not answer on $P_RPC — check ADMIN_RPC"

# Answering is not the same as being the right node. On a host with two
# nodes the default port belongs to the first one, so this check passed
# while the wrapper was pointed at a node it does not manage — a wrapper
# that would then read one node's configuration and act on another's
# container. Ask both sides who they are and refuse if they disagree.
RPC_KEY=$(bash "$WRAPPER" status 2>/dev/null \
  | python3 -I -c 'import sys,json;print(json.load(sys.stdin)["result"]["info"].get("pubkey_node",""))' 2>/dev/null || true)
OWN_KEY=$(docker exec "$P_SERVICE" sh -c \
  'xrpld --conf /etc/xrpld/xrpld.cfg -q server_info 2>/dev/null || rippled -q server_info 2>/dev/null' 2>/dev/null \
  | python3 -I -c 'import sys,json;print(json.load(sys.stdin)["result"]["info"].get("pubkey_node",""))' 2>/dev/null || true)
if [[ -n "$RPC_KEY" && -n "$OWN_KEY" && "$RPC_KEY" != "$OWN_KEY" ]]; then
  revert "ADMIN_RPC $P_RPC answers as a DIFFERENT node than container '$P_SERVICE'.
   that endpoint reports node key $RPC_KEY
   the container reports        $OWN_KEY
   On a host running more than one node, pass this node's own admin port:
     curl -fsSL https://get.aperire.one | bash -s -- --node-wrapper $P_SERVICE --node-wrapper-rpc <port>${INSTANCE:+ --instance $INSTANCE}"
fi
if [[ -n "$RPC_KEY" && "$RPC_KEY" == "$OWN_KEY" ]]; then
  info "the node answers on its admin RPC, and it is this container (state: $STATE)"
else
  info "the node answers on its admin RPC (state: $STATE)"
fi

# REPO, resolving the running tag through the image origin it came from.
#
# image-digest prints two fields since #664, the reference that answered and
# what it resolves to, because a version can live under the configured
# repository or under the local build name (localhost/xrpld) on the same
# host. The digest itself is the last field, and it is a repo digest
# (repo@sha256:…) where the image store has one and an image ID (sha256:…)
# where it does not, which is the ordinary case for an image built here on
# the classic overlay2 store. Both are compared on the part after the @,
# which a bare ID leaves untouched.
#
# A container created from a digest reference (repo@sha256:…, which the
# Advisor's own official-image upgrade makes) has no tag to look up, and the
# verb needs a version. The digest it names is the thing to resolve, so it is
# taken from the reference docker recorded for the container, and the check
# below compares it with what docker reports the container running (#915).
if [[ -n "$P_DIGEST" ]]; then
  P_WANT="$P_REPO@$P_DIGEST"
  # Nothing here resolves a tag, so the reference itself is asked of the image
  # store. A digest reference is content-addressed: when the store holds it,
  # its image ID has to be the one the container was created from, and when it
  # does not, the repository in the profile is not the one the node came from.
  WANT_ID=$(docker image inspect "$P_WANT" --format '{{.Id}}' 2>/dev/null || true)
  [[ "$WANT_ID" == sha256:* ]] \
    || revert "could not resolve $P_WANT in the local image store, check REPO"
  CONT_ID=$(docker inspect "$CONTAINER" --format '{{.Image}}' 2>/dev/null || true)
  [[ "$CONT_ID" == "$WANT_ID" ]] \
    || revert "$P_WANT is not the image $CONTAINER was created from (${WANT_ID:0:19} against ${CONT_ID:0:19}), check REPO"
  DIGEST_LINE="$P_WANT $P_WANT"
  DIGEST_CMP="$P_DIGEST"
else
  DIGEST_LINE=$(bash "$WRAPPER" image-digest "$P_TAG" 2>/dev/null || true)
  P_WANT="$P_REPO:$P_TAG"
fi
DIGEST=${DIGEST_LINE##* }
[[ "$DIGEST" == *sha256:* ]] \
  || revert "could not resolve $P_WANT to a digest, check REPO"
DIGEST_CMP=${DIGEST_CMP:-${DIGEST#*@}}
info "the image ${DIGEST_LINE%% *} resolves ($DIGEST_CMP)"

# The two together: what the node is running, which is what the upgrade path
# compares against to detect a substituted image.
RUNNING=$(bash "$WRAPPER" running-digest 2>/dev/null || true)
[[ "$RUNNING" == *sha256:* ]] \
  || revert "could not read the digest the node is running — check SERVICE"
if [[ "${RUNNING#*@}" != "$DIGEST_CMP" ]]; then
  info "note: the node is running ${RUNNING#*@}"
  if [[ -n "$P_DIGEST" ]]; then
    info "      but the reference it was created from names $DIGEST_CMP."
    info "      The image store holds more than one digest for it. Not an"
    info "      installation problem, but the upgrade path compares these, so"
    info "      it is worth knowing now."
  else
    info "      but $P_REPO:$P_TAG now resolves to $DIGEST_CMP."
    info "      That means the tag was republished since the node started. Not an"
    info "      installation problem — but it is exactly what the upgrade path"
    info "      refuses to restart on, so it is worth knowing now."
  fi
else
  if [[ -n "$P_DIGEST" ]]; then
    info "the node is running the image its digest names"
  else
    info "the node is running the image its tag resolves to"
  fi
fi

# The image recipe, so root can build this node's image from the signed
# package. It is the other half of the wrapper's build-image verb: the verb
# refuses outright unless the recipe is installed here, root-owned, because
# the checkout it would otherwise run from is writable by the account this
# wrapper serves (#657's class).
if [[ -f "$NW_SELF/install-xrpld-image-recipe.sh" ]]; then
  say "the xrpld image recipe"
  if bash "$NW_SELF/install-xrpld-image-recipe.sh" >/dev/null 2>&1; then
    info "installed under /usr/local/lib/aperire, root-owned"
    info "the Advisor builds with it:  $WRAPPER build-image <version>"
  else
    # Not fatal. The wrapper is configured and every other verb works; the
    # one that does not says so itself, with the command that fixes it.
    info "could not be installed; build-image will refuse until it is."
    info "the update retries it and shows why:  curl -fsSL https://get.aperire.one | bash -s -- --update --force"
  fi
fi

say "Done"
info "the wrapper is configured and answering. Nothing about the node changed."
if [[ -n "$PREVIOUS" ]]; then info "previous configuration still at $PREVIOUS"; fi

cat <<EOF

   Optional, and the stronger setup:

   The account the Advisor runs as is in the docker group, and docker group
   membership is root-equivalent — that account can mount the host filesystem
   into a container and reach everything this wrapper is trying to constrain.
   On such a host the wrapper is an allow-list and an audit trail, not a
   sandbox, and the Advisor says so rather than implying otherwise.

   To make it a real boundary, give the Advisor its own account with no docker
   group, reaching this one script only through a root socket, run the update
   at a terminal and answer Y when it offers to move the Advisor:

     curl -fsSL https://get.aperire.one | bash -s -- --update --force

   That does the whole move: it creates the account, hands it the state it
   owns, gives it its root socket (no sudo), and verifies the service still
   works before it keeps the change. It changes how the service runs, so it is a
   separate deliberate step rather than something done here.
EOF
