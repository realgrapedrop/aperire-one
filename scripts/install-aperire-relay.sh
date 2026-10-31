#!/bin/bash
# Aperire — install the relay (aperire-relay) on the validator host.
#
# Idempotent, safe to re-run after upgrades. Walks the same steps the
# Deployment Guide documents under "Wiring each shape"
# (docs/DEPLOYMENT-GUIDE.md), but as a script: install binary,
# create system user, drop config + systemd unit, daemon-reload. Named by
# heading, not by step number: the numbers moved once already and left
# this pointing at steps that no longer existed.
#
# Both branches end with the unit ENABLED and STARTED. What differs is what
# the config says.
#
# Co-located install: everything the relay needs is on this box, so the
# script wires it. dashboard_url is loopback on the port the dashboard was
# installed with, auth_token is the one already in the dashboard's env (or a
# fresh one, minted here and added to that env's RELAY_TOKENS list), and
# node_label names the node. Nothing is left for the operator to do.
#
# Split install (dashboard on another host): neither the URL nor the token is
# knowable here, so the config is written with an EMPTY dashboard_url, which
# the relay reads as "installed, not registered yet". It starts, logs one line
# saying it is standing by, and pushes nothing. It is never pointed at a
# placeholder hostname: that dials a name that does not exist in a retry loop
# forever and looks like a working service.
#
# An operator config that is already wired is never rewritten. Only a missing
# file, or one still holding the shipped example values, is generated.
#
# One thing beyond this host's own files gets touched, and only on the shape
# that needs it (#462). The relay reads the node's config to auto-detect the
# node's four ports, the node installer closes that config before this account
# exists, and a native node therefore arrives here closed to a reader that
# could open it the day before. Where the account this run just created cannot
# read the config its relay.conf names, and has no ACL entry on it either,
# scripts/close-node-config-exposure.sh is called once for the one named entry
# it needs. That script owns the ACL model and reverts itself if the node
# stops being able to open its own config; nothing here reopens anything, and
# a host where the grant would change nothing calls nothing.
#
# Environment. install.sh sets these; they are not meant to be set by hand:
#   APERIRE_COLOCATED=1     dashboard is here: wire the conf from this box
#   APERIRE_INSTANCE=<name> second pairing on one host. Names the config
#                           (relay-<name>.conf), the unit (aperire-relay-<name>)
#                           and the dashboard env file the token comes from
#   APERIRE_PORT=<port>     the co-located dashboard's port. Unset, it is read from
#                           the dashboard unit and its environment file (default 7800)
#   APERIRE_DASH_UNIT=<u>   the co-located dashboard unit to restart when a
#                           token is minted (default aperire-server[-instance])
#   APERIRE_NODE_LABEL=<n>  the name this node is stored under. Set it only
#                           when this script cannot read it: it wins over
#                           everything below, and a name that disagrees with
#                           the one the dashboard already holds starts a
#                           second series for one box
#
# Usage:
#   sudo bash install-aperire-relay.sh /path/to/aperire-relay-binary
#
# If no path is given, the script tries:
#   1. <repo>/relay/aperire-relay               (in-tree build)
#   2. ./aperire-relay                          (current directory)
#
# Build the binary first if you haven't:
#   cd relay && go build -ldflags "-s -w" -o aperire-relay .
# prepare-host.sh's own build stamps this with the commit being installed
# (-X main.version=<commit>, #266); a binary built here by hand carries no
# stamp and reports "dev", which the dashboard reads as not measured rather
# than as drift.

set -euo pipefail

# The instance names units and paths, so it is held to the rule
# advisor-owner-lib.sh holds it to, and anything else is refused (#1206).
instance_name_ok() { # $1 = a name; [a-z] is held to ASCII, whatever the locale
  local LC_ALL=C
  [[ "$1" =~ ^[a-z0-9][a-z0-9-]{0,30}$ && "$1" != credcheck && "$1" != credcheck-* ]]
}
if [[ -n "${APERIRE_INSTANCE:-}" ]] && ! instance_name_ok "$APERIRE_INSTANCE"; then
  printf 'refused: APERIRE_INSTANCE=%q is not an instance name (a-z, 0-9 and -, at most 31, not credcheck)\n' "$APERIRE_INSTANCE" >&2
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# The install tree: this program's parent from a checkout, and the tree
# APERIRE_INSTALL_TREE names when install.sh runs a copy root staged out of
# the release (#764). Code is loaded and run from SCRIPT_DIR only.
REPO_DIR="${APERIRE_INSTALL_TREE:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

# The palette the install path shares, so "done", "degraded" and "refused"
# look the same wherever they are printed. Every string in it is empty unless
# the stream is a terminal, so a captured or piped run stays byte-plain.
[[ -r "${SCRIPT_DIR}/term-style.sh" ]] \
  || { echo "error: ${SCRIPT_DIR}/term-style.sh is missing from this checkout" >&2; exit 1; }
# shellcheck source=scripts/term-style.sh
. "${SCRIPT_DIR}/term-style.sh"

# The one way anything here asks docker what is running, and the one place
# that tells a refused answer from an absence (#142).
[[ -r "${SCRIPT_DIR}/docker-ask-lib.sh" ]] \
  || { echo "error: ${SCRIPT_DIR}/docker-ask-lib.sh is missing from this checkout" >&2; exit 1; }
# shellcheck source=scripts/docker-ask-lib.sh
. "${SCRIPT_DIR}/docker-ask-lib.sh"

if [[ $EUID -ne 0 ]]; then
  echo "${E_RED}error: must run as root (sudo bash $0 ...)${E_OFF}" >&2
  exit 1
fi

# The three absolute paths this script writes to, named once. Everything
# below goes through them.
ETC_APERIRE=/etc/aperire
SYSTEMD_DIR=/etc/systemd/system
RELAY_BIN_PATH=/usr/local/bin/aperire-relay

# One relay per node, feeding one dashboard (ADR 0009). The instance name
# selects the unit and the config file together so a second pairing on the
# same host collides with nothing; empty is the single-instance layout.
INSTANCE="${APERIRE_INSTANCE:-}"
if [[ -n "$INSTANCE" && ! "$INSTANCE" =~ ^[a-z0-9][a-z0-9-]{0,30}$ ]]; then
  echo "${E_RED}error: instance name must be lowercase letters, digits and dashes${E_OFF}" >&2
  exit 2
fi
SUFFIX="${INSTANCE:+-$INSTANCE}"
RELAY_UNIT_NAME="aperire-relay${SUFFIX}"
UNIT_PATH="${SYSTEMD_DIR}/${RELAY_UNIT_NAME}.service"

# Everything the co-located branch reads from this host, resolved once.
RELAY_CONF="${ETC_APERIRE}/relay${SUFFIX}.conf"
ENV_FILE="${ETC_APERIRE}/aperire${SUFFIX}.env"
DASH_UNIT="${APERIRE_DASH_UNIT:-aperire-server${SUFFIX}}"

# The port the co-located dashboard answers on, which is what the config this
# writes dials and what the closing summary tells the operator to ask.
#
# Not `${APERIRE_PORT:-7800}`. install.sh sets APERIRE_PORT only when this run
# was given --port, and the installer is meant to be re-run: on a host built
# with --port=7900 the next run carries none, the constant said 7800, and the
# relay's config then dialled a port nothing listens on (#1176). So when
# nothing told this run, the host is read, the way install.sh and
# aperire-fleet-pair.sh read it and in the same order: the dashboard unit's own
# Environment=PORT, then the environment file that unit names, then this
# instance's file in /etc/aperire, then the default. A value read from those
# files that is not a port number is skipped, so nothing but digits from them
# lands in a URL. An APERIRE_PORT is install.sh's own argument and is used as
# given.
dash_port() {
  local f unit="" envf="" p
  if [[ -n "${APERIRE_PORT:-}" ]]; then printf '%s' "$APERIRE_PORT"; return 0; fi
  for f in "${SYSTEMD_DIR}/${DASH_UNIT}.service" "${SYSTEMD_DIR}/aperire-read${SUFFIX}.service"; do
    if [[ -f "$f" ]]; then unit="$f"; break; fi
  done
  if [[ -n "$unit" ]]; then
    p="$(awk -F= '/^Environment=PORT=/{print $3; exit}' "$unit" 2>/dev/null || true)"
    if [[ "$p" =~ ^[0-9]+$ ]]; then printf '%s' "$p"; return 0; fi
    envf="$(awk -F= '/^EnvironmentFile=/{sub(/^-/,"",$2); print $2; exit}' "$unit" 2>/dev/null || true)"
  fi
  for f in "$envf" "$ENV_FILE"; do
    [[ -n "$f" && -f "$f" ]] || continue
    p="$(awk -F= '$1=="PORT"{sub(/^[^=]*=/,""); gsub(/"/,""); print; exit}' "$f" 2>/dev/null || true)"
    if [[ "$p" =~ ^[0-9]+$ ]]; then printf '%s' "$p"; return 0; fi
  done
  printf '7800'
}
DASH_PORT="$(dash_port)"

# ── 1. Locate the binary ─────────────────────────────────────────────
BINARY="${1:-}"
if [[ -z "$BINARY" ]]; then
  # Auto-detect typical build locations.
  for guess in \
      "${REPO_DIR}/relay/aperire-relay" \
      "$(pwd)/relay/aperire-relay" \
      "$(pwd)/aperire-relay"; do
    if [[ -n "$guess" && -x "$guess" ]]; then
      BINARY="$guess"
      break
    fi
  done
fi
if [[ -z "$BINARY" || ! -x "$BINARY" ]]; then
  cat >&2 <<EOF
error: relay binary not found.

  Pass the path explicitly:
      sudo bash $0 /path/to/aperire-relay

  Or build it from this repo (pin to a reviewed commit, not floating main):
      git checkout <reviewed-commit>          # then: git rev-parse HEAD
      cd relay && go build -ldflags "-s -w" -o aperire-relay .
      sudo bash $0
EOF
  exit 1
fi
echo "${S_GREEN}→ using binary: $BINARY${S_OFF}"

# ── 2. Install the binary ────────────────────────────────────────────
# The binary handed in can BE the installed one. That is what a re-run looks
# like on a host where the relay is already installed: the operator passes
# /usr/local/bin/aperire-relay, because that is the binary this host has.
# `install` refuses a copy whose source and destination are one file, and
# under `set -euo pipefail` that ended the run right here, before the token,
# the pairing, the dashboard restart and the unit (#494). Nothing downstream
# ran and nothing above was undone, so the host was left half wired by a line
# an operator reads as a note.
#
# The test is identity, not content: same device and inode, the comparison
# coreutils itself makes before it refuses. It answers a plain repeat of the
# path, a symlink pointing at the destination and a relative path naming it,
# all of them one file with nothing to copy. A byte-identical copy somewhere
# else is a different file and is installed, because content was never what
# failed. The mode and owner are asserted on the skip, since `install -m 755`
# was the only thing asserting them: "already in place" must not also mean
# "and no longer executable".
#
# Any other binary is copied through the trusted-path check (ADR 0024, GA
# position 1; #764). It is built on this host, so a release has no digest to
# hold it to, and it is trusted the way the tree it was built in is: no
# service account may be able to change it or any directory on its way, and
# the bytes root installs are the one read that was judged. Not a plain
# `install`, which reads a path a service account might have swapped.
if [[ -e "$RELAY_BIN_PATH" && "$BINARY" -ef "$RELAY_BIN_PATH" ]]; then
  chown root:root "$RELAY_BIN_PATH"
  chmod 755 "$RELAY_BIN_PATH"
  echo "${S_GREEN}→ already in place: ${RELAY_BIN_PATH}  (the binary handed in is the installed one, nothing to copy)${S_OFF}"
else
  [[ -r "${SCRIPT_DIR}/release-digests-lib.sh" ]] \
    || { echo "${E_RED}error: ${SCRIPT_DIR}/release-digests-lib.sh is missing from this checkout${E_OFF}" >&2; exit 1; }
  # shellcheck source=scripts/release-digests-lib.sh
  . "${SCRIPT_DIR}/release-digests-lib.sh"
  RELAY_PLACED_RC=0
  RELAY_PLACED="$(rd_install_built "$BINARY" "$RELAY_BIN_PATH" 0755 "$REPO_DIR")" || RELAY_PLACED_RC=$?
  case "$RELAY_PLACED_RC" in
    0) if [[ "$RELAY_PLACED" == same ]]; then
         echo "${S_GREEN}→ installed: ${RELAY_BIN_PATH}  (it already held the same bytes as ${BINARY}, so there was nothing to rewrite)${S_OFF}"
       else
         echo "${S_GREEN}→ installed: ${RELAY_BIN_PATH}  ($(file -b "$RELAY_BIN_PATH" | head -c 60))${S_OFF}"
         echo "${S_DIM}  built on this host, so it was checked by its path (no service account can change it), not by a release digest${S_OFF}"
       fi ;;
    1) echo "${E_RED}error: ${RELAY_BIN_PATH} was not installed: root refused the copy, and the lines above say why. The relay already there, if any, was left as it was.${E_OFF}" >&2
       exit 1 ;;
    *) echo "${E_RED}error: ${RELAY_BIN_PATH} could not be written (above).${E_OFF}" >&2
       exit 1 ;;
  esac
fi

# ── 3. Create the unprivileged system user ──────────────────────────
# Why the relay has an account of its own, and does not share one (#813).
# An account exists here only where a trust boundary does. The relay sits on
# one the other accounts cannot stand in for:
#   - it may read the node's config, and on a validator that file holds
#     [validator_token], the key the node signs with. Section 5b below has
#     close-node-config-exposure.sh grant it read by ACL when it needs the
#     node's ports from there. Whatever account holds that read can sign as
#     the validator.
#   - the dashboard's account faces the internet. Sharing it would hand the
#     signing key to the most exposed process on the box.
#   - the Advisor's account acts on model output, and is optional: a split
#     validator host has neither it nor the dashboard's.
#   - the operator's login has sudo, so a network daemon running as it would
#     be one step from root.
# So the relay runs as aperire-relay: no shell, no home, no sudo, no
# capabilities, holding the config read and its own relay.conf token and
# nothing else.
if id aperire-relay >/dev/null 2>&1; then
  echo "${S_GREEN}→ user aperire-relay already exists${S_OFF}"
else
  useradd --system --no-create-home --shell /usr/sbin/nologin aperire-relay
  echo "${S_GREEN}→ created system user: aperire-relay${S_OFF}"
fi

# ── 4. Create the config directory ───────────────────────────────────
# 755 root:root — traversable by all, contents protected by their own modes.
# Critically, on a CO-LOCATED host /etc/aperire also holds aperire.env
# (root:<dashboard user>, read by aperire-server as that user). Chowning this dir to
# aperire-relay:aperire-relay 750 (as an earlier version did) silently breaks
# that read on the next dashboard restart. Per-file ownership — relay.conf is
# root:aperire-relay 640 below — gives the relay its access without locking
# anyone else out of the shared directory.
install -d -m 755 -o root -g root "$ETC_APERIRE"
echo "${S_GREEN}→ ${ETC_APERIRE} (mode 755, root:root; per-file perms protect contents)${S_OFF}"

# ── 5. Write the relay config ─────────────────────────
# One writer for both branches. What it writes differs; that it writes a
# config the relay can actually load does not.
#
# The shipped relay.conf.example used to be copied in here as a starter, and
# on a real box that is what shipped: node_label validator-fra-01, dashboard
# wss://aperire.example.com/ingest, a relay dialling a documentation hostname
# in a retry loop with nothing in the journal that reads as broken. A
# placeholder is not configuration. The example file stays in relay/ as
# documentation and is no longer installed.

# Read one quoted value out of the config. Empty if the key is absent, and
# empty rather than fatal when there is no config yet: sed on a file that does
# not exist exits 2, and under `set -o pipefail` that ends the run on the first
# question anyone asks about a fresh host.
conf_value() {  # $1 = key
  [[ -f "$RELAY_CONF" ]] || return 0
  sed -nE "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*\"([^\"]*)\".*/\1/p" "$RELAY_CONF" 2>/dev/null | head -1
}

# The starter values, recognised so they are never mistaken for settings.
# Both halves matter: a token of REPLACE_WITH_... satisfies any naive
# non-empty test, and a dashboard_url on example.com is a hostname that does
# not resolve anywhere.
has_placeholder_url() {
  grep -qE '^[[:space:]]*dashboard_url[[:space:]]*=[[:space:]]*"[^"]*\.example\.com' "$RELAY_CONF" 2>/dev/null
}
placeholder_token() {  # $1 = token value
  [[ -z "$1" || "$1" =~ ^(REPLACE_WITH[A-Z_]*|CHANGE_ME[A-Z_]*)$ ]]
}
# A shape, checked before a token is written to either file. RELAY_TOKENS is a
# comma-separated list, so a value carrying a comma or whitespace would be read
# back as two tokens and neither would match. It is also the one string here
# that comes from a file a person edits, and it ends up inside a line this
# script builds, so a shape is the honest guard rather than escaping at each
# use. `openssl rand -hex 32` satisfies it, and so does anything an operator
# would sensibly paste.
usable_token() {  # $1 = token value
  [[ "$1" =~ ^[A-Za-z0-9._~+/=-]{8,512}$ ]]
}
# The token already in the config, or empty when there is not a usable one.
conf_token() {
  local t; t="$(conf_value auth_token)"
  placeholder_token "$t" && return 0
  usable_token "$t" || return 0
  printf '%s' "$t"
}
# A config that points somewhere real. Not "the file exists", and not "a
# value is present": either of those is true of the shipped example.
conf_is_wired() {
  [[ -f "$RELAY_CONF" ]] || return 1
  has_placeholder_url && return 1
  [[ -n "$(conf_value dashboard_url)" && -n "$(conf_token)" ]]
}
# A config this script wrote that says it awaits a dashboard. The shipped
# example does not qualify: it names a host.
conf_is_awaiting() {
  [[ -f "$RELAY_CONF" ]] || return 1
  has_placeholder_url && return 1
  [[ -z "$(conf_value dashboard_url)" ]]
}

# node_label names this host in the dashboard's store, and the fleet's name
# for a node is its container/compose name, not the machine's hostname: a
# rented box arrives carrying the provider's name for it, and the node on
# it has the name you gave the container.
# Order: APERIRE_NODE_LABEL if the operator set one, then node.conf's own
# NODE_LABEL (scripts/install-aperire-node.sh writes this - the operator's
# --name, chosen once, whichever shape the node is), then the node wrapper's
# configured SERVICE (root-owned, already resolved, needs no docker), then the
# running node container, then the hostname as the last resort. Only ever
# chosen when writing a FRESH config. node_label is the key host metrics are
# stored under, so rewriting it on an existing install forks the series into
# two nodes that are one box.
#
# NODE_LABEL outranks the wrapper's SERVICE on purpose (#30): on a native
# install SERVICE is a systemd unit name (xrpld.service), not a label, and
# every native host would otherwise register in the fleet table under the
# same string. A unit name must never win over a name the operator chose.
#
# The hostname is the last resort only when docker ANSWERED and named no node,
# or when there is no docker to ask. A docker that refused is not an absence,
# and taking the hostname there is how a node quietly acquires a second name
# (#142): the box is called srv12345 and the node everyone else calls
# stock-node1. Returns 2 without printing in that case, and the caller stops.
detect_node_label() {
  local wconf="${ETC_APERIRE}/node-wrapper.conf" nconf="${ETC_APERIRE}/node.conf" label=""
  if [[ -n "${APERIRE_NODE_LABEL:-}" ]]; then
    label="$APERIRE_NODE_LABEL"
  elif [[ -r "$nconf" ]] && label="$(awk -F= '$1=="NODE_LABEL"{sub(/^[^=]*=/,""); print; exit}' "$nconf" 2>/dev/null)" && [[ -n "$label" ]]; then
    :
  elif [[ -r "$wconf" ]]; then
    label="$(awk -F= '$1=="SERVICE"{sub(/^[^=]*=/,""); print; exit}' "$wconf" 2>/dev/null || true)"
    [[ "$label" == "none" ]] && label=""
  fi
  if [[ -z "$label" ]]; then
    # On a non-zero return $said is docker's complaint rather than the list.
    local said ask=0
    said="$(docker_ask '{{.Names}} {{.Image}}')" || ask=$?
    # A container created from a digest shows an image ID here; read its name
    # back, and treat a refused read like a refused ps (#896).
    if [[ $ask -eq 0 ]]; then said="$(docker_resolve_image_ids "$said")" || ask=$?; fi
    case $ask in
      0) label="$(printf '%s\n' "$said" | awk '/rippled|xrpld|xahaud/ {print $1; exit}' || true)" ;;
      1) : ;;   # no docker, or no daemon: nothing is running in one, so the
                # hostname below is the honest answer rather than a guess
      2) echo "${E_RED}error: docker is installed here and would not say what is running (${said}).${E_OFF}" >&2
         echo "       That is not the same as no node running here, and the name this" >&2
         echo "       relay writes is the key every host metric is stored under, so" >&2
         echo "       this stops rather than name the node after the box." >&2
         echo "       Give it the name and run again:" >&2
         echo "         sudo APERIRE_NODE_LABEL=<node-name> bash $0" >&2
         return 2 ;;
    esac
  fi
  # Shape, not escaping. Anything else and the hostname is the safer answer.
  [[ "$label" =~ ^[A-Za-z0-9._-]+$ ]] || label="$(hostname 2>/dev/null || echo aperire-node)"
  printf '%s%s' "$label" "$SUFFIX"
}

# Where rippled.cfg is on the host, so connection counts come from the node's
# real ports instead of the well-known defaults.
#
# One rule, shared with close-node-config-exposure.sh (#462 P3-076): the
# wrapper's node-wrapper.conf first, then the node installer's own node.conf,
# and only once both are silent does this fall to aperire.env's
# RIPPLED_CFG_PATH, which configure-rippled-paths.sh writes and the closer
# does not consult at all. The two used to diverge here: this function
# stopped at node-wrapper.conf and fell straight to the env file, so a host
# whose env file still named a stale path (moved node, restored backup)
# would have the relay ask the closer for a read on one file while the closer
# itself was acting on the record's own CONFIG_FILE from node.conf. Same
# order, same file, or the grant and the close are for two different paths.
detect_rippled_cfg() {
  local wconf="${ETC_APERIRE}/node-wrapper.conf" nconf="${ETC_APERIRE}/node.conf" p=""
  for f in "$wconf" "$nconf"; do
    [[ -z "$p" && -r "$f" ]] || continue
    p="$(awk -F= '$1=="CONFIG_FILE"{sub(/^[^=]*=/,""); print; exit}' "$f" 2>/dev/null || true)"
  done
  if [[ -z "$p" && -r "$ENV_FILE" ]]; then
    p="$(sed -nE 's/^[[:space:]]*RIPPLED_CFG_PATH=//p' "$ENV_FILE" 2>/dev/null | tail -1 | tr -d "\"' ")"
  fi
  [[ -n "$p" && -f "$p" ]] || return 1
  printf '%s' "$p"
}

# $1 = dashboard_url (empty means awaiting registration), $2 = auth_token.
write_relay_conf() {
  local url="$1" token="$2" label cfg
  # A refusal is fatal here, and deliberately: this function's next act is to
  # WRITE the name into the config, and there is no later point at which a
  # wrong one gets corrected.
  label="$(detect_node_label)" || exit 1
  cfg="$(detect_rippled_cfg || true)"
  # Scoped: the config is 640 root:aperire-relay and nothing between here and
  # the chmod below should be able to leave a wider file behind, but a umask
  # set for the rest of the script would then apply to the unit file too.
  (
  umask 077
  {
    if [[ -n "$url" ]]; then
      printf '# Aperire relay config. Written by install-aperire-relay.sh, co-located.\n'
      printf '# The dashboard is on this host, so both values below were read from it.\n'
    else
      printf '# Aperire relay config. Written by install-aperire-relay.sh, split install.\n'
      printf '#\n'
      printf '# THIS RELAY IS INSTALLED AND AWAITING REGISTRATION. The empty\n'
      printf '# dashboard_url is deliberate and valid: the service is enabled and\n'
      printf '# running, it says so once in its journal, and it pushes nothing. Only\n'
      printf '# you know which dashboard collects from this host.\n'
      printf '#\n'
      printf '# Fill both values in, then:  systemctl restart %s\n' "$RELAY_UNIT_NAME"
      printf '#\n'
      printf '#   dashboard_url  keep the hop off the open network. Either tunnel it\n'
      printf '#                  (WireGuard/SSH) and use ws://127.0.0.1:7800/ingest,\n'
      printf '#                  or terminate TLS and use wss://<dashboard>/ingest.\n'
      printf '#                  A plain ws URL to another host sends the token in\n'
      printf '#                  the clear, and a dashboard bound off loopback\n'
      printf '#                  refuses it with 403.\n'
      printf '#   auth_token     must match RELAY_TOKENS in /etc/aperire/aperire.env\n'
      printf '#                  on the dashboard host.\n'
    fi
    printf 'dashboard_url        = "%s"\n' "$url"
    printf 'auth_token           = "%s"\n' "$token"
    printf 'node_label           = "%s"\n' "$label"
    printf 'interface            = "auto"\n'
    printf 'data_mount           = "/"\n'
    printf 'interval_seconds     = 5\n'
    printf 'monthly_budget_bytes = 5000000000000\n'
    if [[ -n "$cfg" ]]; then
      printf 'rippled_cfg_path     = "%s"\n' "$cfg"
    else
      printf '# rippled_cfg_path   = "/etc/opt/ripple/rippled.cfg"\n'
    fi
    printf '# The relay reads the node ports from rippled_cfg_path. When that file\n'
    printf '# sits outside the relay user reach, the installer pins them in a\n'
    printf '# marked block below and every update refreshes it. To pin a port\n'
    printf '# yourself, set it outside that block. See docs/RELAY-REFERENCE.md\n'
    printf '# (Port connection monitoring):\n'
    printf '#   http_rpc_port  = 5005\n'
    printf '#   admin_ws_port  = 6006\n'
    printf '#   ws_public_port = 6005\n'
    printf '#   peer_port      = 51235\n'
  } > "$RELAY_CONF"
  )
  chown root:aperire-relay "$RELAY_CONF"; chmod 640 "$RELAY_CONF"
  RELAY_LABEL="$label"
}

# ── The dashboard's side of the pair, co-located only ──────────
# The token has to be in two files at once or the relay's first push is a
# 401. This script owns both writes, because a token written to one of them
# is not configuration, it is a mismatch. scripts/enable-relay-colocated.sh
# used to mint its own for the retrofit case; it now calls this and there is
# one place a relay token comes from.
env_tokens() {
  # No env file means no tokens known, which is a fact, not an error. Same
  # pipefail trap as conf_value.
  [[ -r "$ENV_FILE" ]] || return 0
  sed -nE 's/^[[:space:]]*RELAY_TOKENS=//p' "$ENV_FILE" 2>/dev/null \
    | tail -1 | tr -d "\"'" | tr -d '\r'
}
env_has_token() {  # $1 = token
  local want="$1" t toks=()
  [[ -n "$want" ]] || return 1
  IFS=, read -r -a toks <<< "$(env_tokens)"
  for t in ${toks[@]+"${toks[@]}"}; do
    [[ "$(printf '%s' "$t" | tr -d '[:space:]')" == "$want" ]] && return 0
  done
  return 1
}
# Append, never replace. The list is the dashboard's allow-list and an
# operator may have their own entries in it (a second relay, a rotation part
# way through); overwriting it revokes those silently.
#
# The ownership dance is not decoration. This file is root:<dashboard user>
# 0640, `sed -i` writes a new inode, and the replacement lands root:root. The
# dashboard then cannot read its own environment on the next restart, which
# presents as a service that will not come up for no visible reason.
env_append_token() {  # $1 = token
  local token="$1" cur new own mode tmp line
  usable_token "$token" || { echo "${E_RED}error: refusing to write a token of that shape${E_OFF}" >&2; return 1; }
  touch "$ENV_FILE"
  own="$(stat -c '%U:%G' "$ENV_FILE" 2>/dev/null || echo root:root)"
  mode="$(stat -c '%a' "$ENV_FILE" 2>/dev/null || echo 640)"
  cur="$(env_tokens)"
  new="${cur:+${cur},}${token}"
  # Built line by line rather than with `sed -i`, for two reasons. The line is
  # assembled from values that came out of a file, and `&` and the delimiter
  # are live inside a sed replacement. And the result is written back THROUGH
  # the existing file, which keeps the inode and therefore the ownership and
  # mode, instead of `sed -i`'s new file landing root:root.
  tmp="$(mktemp "${ENV_FILE}.XXXXXX")"
  if grep -qE '^[[:space:]]*RELAY_TOKENS=' "$ENV_FILE"; then
    while IFS= read -r line || [[ -n "$line" ]]; do
      if [[ "$line" =~ ^[[:space:]]*RELAY_TOKENS= ]]; then
        printf 'RELAY_TOKENS=%s\n' "$new"
      else
        printf '%s\n' "$line"
      fi
    done < "$ENV_FILE" > "$tmp"
  else
    cat "$ENV_FILE" > "$tmp"
    printf 'RELAY_TOKENS=%s\n' "$new" >> "$tmp"
  fi
  cat "$tmp" > "$ENV_FILE"
  rm -f "$tmp"
  chown "$own" "$ENV_FILE" 2>/dev/null || true
  chmod "$mode" "$ENV_FILE" 2>/dev/null || true
}

# wired | awaiting | preserved. The closing summary reads it so it reports
# what happened rather than the shape it assumed.
RELAY_STATE=""
RELAY_LABEL=""

# The config that points at a dashboard on THIS host, which is the only kind
# whose token belongs in this host's allow-list. An operator who pointed a
# co-located box's relay at some other dashboard gets left alone: adding their
# remote dashboard's token to this one's RELAY_TOKENS would widen this
# dashboard's allow-list with a secret it has no business accepting.
conf_points_here() {
  local u; u="$(conf_value dashboard_url)"
  [[ "$u" == ws://127.0.0.1:* || "$u" == ws://localhost:* || "$u" == "ws://[::1]:"* ]]
}

if [[ "${APERIRE_COLOCATED:-0}" == "1" ]]; then
  ENV_CHANGED=0
  if conf_is_wired; then
    # Somebody's working configuration, whether this script wrote it or a
    # person did. Left alone on every re-run: this is where a hand-tuned
    # node_label or a pinned port lives.
    RELAY_STATE=preserved
    RELAY_LABEL="$(conf_value node_label)"
    TOKEN="$(conf_token)"
    echo "${S_GREEN}→ $RELAY_CONF already points at $(conf_value dashboard_url), leaving as is${S_OFF}"
  else
    # Reuse before minting. A token that is already paired is the same token on
    # a re-run, so re-running the installer does not rotate the dashboard's
    # allow-list under a relay that is working.
    TOKEN="$(conf_token)"
    if [[ -z "$TOKEN" ]]; then
      TOKEN="$(env_tokens | cut -d, -f1 | tr -d '[:space:]')"
      if usable_token "$TOKEN"; then
        echo "${S_GREEN}→ co-located: reusing the relay token already in $ENV_FILE${S_OFF}"
      else
        TOKEN=""
      fi
    fi
    if [[ -z "$TOKEN" ]]; then
      TOKEN="$(openssl rand -hex 32)"
      echo "${S_GREEN}→ co-located: minted a relay token${S_OFF}"
    fi
    write_relay_conf "ws://127.0.0.1:${DASH_PORT}/ingest" "$TOKEN"
    RELAY_STATE=wired
    echo "${S_GREEN}→ co-located: wrote $RELAY_CONF (dashboard :$DASH_PORT, node_label=$RELAY_LABEL)${S_OFF}"
  fi

  # Pairing is checked on BOTH shapes, not only the one this run wrote. A
  # config carrying a real token that is not in RELAY_TOKENS is a relay that
  # 401s forever, and it reaches here whenever an earlier attempt wrote the
  # config and something stopped before the token reached the dashboard. The
  # installer is holding both files; leaving them disagreeing is a choice.
  if [[ -n "$TOKEN" ]] && conf_points_here && ! env_has_token "$TOKEN"; then
    env_append_token "$TOKEN"
    ENV_CHANGED=1
    echo "${S_GREEN}→ co-located: paired the token into RELAY_TOKENS in $ENV_FILE${S_OFF}"
  fi

  # The dashboard has to be carrying the token before the relay dials, or the
  # first push is a 401 and the operator reads a rejection that was only a
  # matter of ordering. Restarted only when the env actually changed: a re-run
  # that reused a paired token must not bounce a working dashboard.
  if [[ $ENV_CHANGED -eq 1 ]]; then
    if [[ "${APERIRE_NO_RESTART:-0}" == "1" ]]; then
      echo "${E_AMBER}warning: RELAY_TOKENS changed and $DASH_UNIT was NOT restarted, so it is${E_OFF}" >&2
      echo "${E_AMBER}         still running without the new token. Restart it before the relay${E_OFF}" >&2
      echo "${E_AMBER}         dials, or its first push is a 401.${E_OFF}" >&2
    elif systemctl list-unit-files "${DASH_UNIT}.service" 2>/dev/null | grep -q -e "${DASH_UNIT}.service"; then
      systemctl restart "$DASH_UNIT"
      echo "${S_GREEN}→ co-located: restarted $DASH_UNIT so /ingest accepts the token${S_OFF}"
    else
      echo "${E_AMBER}warning: $DASH_UNIT is not a unit on this host, so the dashboard was not${E_OFF}" >&2
      echo "${E_AMBER}         restarted. It must be restarted to read the new RELAY_TOKENS.${E_OFF}" >&2
    fi
  fi
elif conf_is_wired; then
  RELAY_STATE=preserved
  RELAY_LABEL="$(conf_value node_label)"
  echo "${S_GREEN}→ $RELAY_CONF already points at $(conf_value dashboard_url), leaving as is${S_OFF}"
else
  # Split install. Everything about this host is knowable; the dashboard is
  # not. Write the awaiting-registration config rather than a placeholder and
  # let the unit come up standing by.
  if conf_is_awaiting; then
    RELAY_LABEL="$(conf_value node_label)"
    echo "${S_GREEN}→ $RELAY_CONF already awaits registration, leaving as is${S_OFF}"
  else
    write_relay_conf "" ""
    echo "${S_GREEN}→ split install: wrote $RELAY_CONF awaiting registration (node_label=$RELAY_LABEL)${S_OFF}"
  fi
  RELAY_STATE=awaiting
fi

# A kept relay.conf is given back to the relay's group (#824). The paths
# above that leave a config "as is" never chowned it, and an uninstall --keep
# hands it to root's group before userdel takes aperire-relay with the
# account, so the relay this run makes again could not read it. A host kept
# before that fix has it on the old, dead gid instead, which the new group
# only gets back by luck. Either way the relay's own group is the answer.
# By name, as write_relay_conf does: /etc/aperire is root's, and no service
# account can write in it.
if [[ -f "$RELAY_CONF" && ! -L "$RELAY_CONF" ]] && [[ "$(stat -c '%G' "$RELAY_CONF" 2>/dev/null)" != aperire-relay ]]; then
  chown root:aperire-relay "$RELAY_CONF"; chmod 640 "$RELAY_CONF"
  echo "${S_GREEN}→ $RELAY_CONF is the relay's to read again (root:aperire-relay 0640)${S_OFF}"
fi

# ── 5b. The node config the relay parses for its ports ───────────────
#
# The relay auto-detects the node's four ports by reading the node's own
# config. Since #462 the node installer closes that file to its owner and the
# node's group on every run, and the ordering on a fresh host puts that close
# BEFORE this account exists: install-aperire-node.sh runs first, the
# get.aperire.one one-liner runs second and creates aperire-relay right above
# here. A close cannot grant an account that is not there yet, so on a native
# node, whose config sits in world-traversable /etc rather than under an
# operator's home, the relay arrives able to see the directory and not the
# file. It falls back to the well-known ports, the connection counts on the
# Network tab are wrong, and nothing anywhere says so.
#
# The grant is not made here. close-node-config-exposure.sh owns the ACL
# model: the node's own group, the relay's named read, passage through the
# directory, and a verify that puts all of it back if the node stops being
# able to open its own config. A second copy of that reasoning in this script
# is a second copy to get wrong. Its work gate counts "the relay needs this
# file and has no entry on it" as work in its own right, so calling it on an
# already-closed host adds that one entry and changes nothing else.
#
# Two gates, and the second one is why a container host is a no-op. The read
# is the question that matters, but a container node keeps its config under
# the operator's home, which Ubuntu creates 0750, so the relay cannot traverse
# to the file whatever entry it holds on it. Gating on the read alone would
# call the closer on every run of that shape forever. Gating on the read AND
# on the entry being absent means one pass there, and silence after it.
#
# A relay that still cannot read the file gets the ports pinned instead
# (#1266, section 5c below). This script runs as root, so the relay's own
# --print-effective-config, asked from here, does read the node config and
# says which ports it found there. Those go into relay.conf inside a marked
# block that every run rewrites. The relay gets no new passage: nothing here
# touches a directory above the config, and /var/lib/xrpld least of all.
relay_reads_cfg() {  # $1 = the config file
  id aperire-relay >/dev/null 2>&1 || return 1
  runuser -u aperire-relay -- test -r "$1" 2>/dev/null
}
relay_granted_cfg() {  # $1 = the config file; is the named entry already on it
  getfacl -p "$1" 2>/dev/null | grep -qE '^user:aperire-relay:r'
}
relay_answer_value() {  # $1 = key, $2 = the printed key=value text
  awk -F= -v k="$1" '$1==k {sub(/^[^=]*=/,""); print; exit}' <<<"$2"
}

# The installer's own pins, between these two lines and nowhere else. A port
# outside them is the operator's, and no run touches it.
RELAY_PINS_BEGIN='# >>> node ports pinned by install-aperire-relay.sh >>>'
RELAY_PINS_END='# <<< node ports pinned by install-aperire-relay.sh <<<'
# relay.conf with that block taken out. Only a whole block, both marker lines
# in order: a file with a begin line and no end line is left as it is, so a
# hand edit that broke the block can never take the operator's lines with it.
relay_conf_without_pins() {
  awk -v b="$RELAY_PINS_BEGIN" -v e="$RELAY_PINS_END" '
    { line[NR] = $0 }
    !s && $0 == b { s = NR }
    s && !t && $0 == e { t = NR }
    END { for (i = 1; i <= NR; i++) if (!t || i < s || i > t) print line[i] }' "$RELAY_CONF"
}
# The block for every port the relay found in the node config, from an answer
# about relay.conf without the old block. A port the operator pinned answers
# "override" and is skipped, so the block never repeats a key (the relay
# refuses a duplicate key, and Restart=always would make that a start loop).
# A port the file does not name answers "default" and is skipped too: it was
# not read from anywhere. Prints nothing when there is nothing to pin.
relay_pins_block() {  # $1 = the node config, $2 = the relay's answer
  local k v lines=''
  for k in http_rpc_port admin_ws_port ws_public_port peer_port; do
    [[ "$(relay_answer_value "${k}_source" "$2" || true)" == auto-detected ]] || continue
    v="$(relay_answer_value "$k" "$2" || true)"
    [[ "$v" =~ ^[1-9][0-9]{0,4}$ ]] || continue
    lines+="$(printf '%-14s = %s' "$k" "$v")"$'\n'
  done
  [[ -n "$lines" ]] || return 0
  printf '%s\n' "$RELAY_PINS_BEGIN" \
    "# Read from $1, a file aperire-relay cannot reach" \
    "# from where it runs. Every install and update rewrites this block from" \
    "# that file. To pin a port yourself, set it outside the block."
  printf '%s' "$lines"
  printf '%s\n' "$RELAY_PINS_END"
}

# Asked of the binary this step just installed at $RELAY_BIN_PATH, about the
# config this step just wrote at $RELAY_CONF — both already known here, so
# there is no unit to read yet and none is needed. This used to answer from
# a shell reparse of $RELAY_CONF (grep for `key = "value"`, count `key = N`
# lines against four), which cannot tell a single-quoted TOML string from
# unset, a key inside an unrelated `[table]` from the top-level one, or an
# explicit `= 0` from a pinned port (a security review, 2026-09-18); the
# relay's own parser has none of those blind spots, so this step asks it
# directly instead of guessing on its behalf.
#
# close-node-config-exposure.sh's own standalone re-runs ask the same
# question a different way, reading the installed unit's ExecStart to find
# the binary and config (there is no unit here yet for THIS run to read).
# When this step calls that script below, it hands over the binary and
# config it already resolved (APERIRE_RELAY_BIN / APERIRE_RELAY_CONF) so the
# two never disagree about which relay they mean.
#
# Asked about relay.conf WITHOUT this installer's own pins, handed over on
# stdin so no copy of the token lands on disk. The question is what the
# operator's config needs, and the pins a past run wrote would answer it for
# them: four of them read as "every port is already pinned", and a re-run
# would never refresh them again.
RELAY_CANNOT_ASK_NOTE=''
RELAY_READS_FLAG=''
RELAY_NODE_CFG=''
RELAY_ALL_PINNED=0
RELAY_CONF_NOW="$(cat "$RELAY_CONF")"
RELAY_CONF_BARE="$(relay_conf_without_pins)"
RELAY_HAD_PINS=0
[[ "$RELAY_CONF_BARE" != "$RELAY_CONF_NOW" ]] && RELAY_HAD_PINS=1
# What section 5c does with the block once the branch below has decided: pin
# (rewrite it from the node config), drop (take it out), or nothing.
RELAY_PINS_ACTION=''

if RELAY_ANSWER="$(printf '%s\n' "$RELAY_CONF_BARE" \
    | timeout 10 "$RELAY_BIN_PATH" --print-effective-config --config /dev/stdin 2>/dev/null)"; then
  RELAY_ASK_RC=0
else
  RELAY_ASK_RC=$?
fi
if [[ "$RELAY_ASK_RC" -ne 0 ]]; then
  RELAY_CANNOT_ASK_NOTE="$RELAY_BIN_PATH --print-effective-config exited $RELAY_ASK_RC (an older build predating that flag answers this way too)"
else
  RELAY_READS_FLAG="$(relay_answer_value reads_node_config "$RELAY_ANSWER" || true)"
  if [[ "$RELAY_READS_FLAG" != "true" && "$RELAY_READS_FLAG" != "false" ]]; then
    RELAY_CANNOT_ASK_NOTE="$RELAY_BIN_PATH printed something this install could not parse"
  else
    RELAY_NODE_CFG="$(relay_answer_value node_config_path "$RELAY_ANSWER" || true)"
    # Distinct from reads_node_config=false: that is also true whenever
    # auto-detection is needed but nothing is there to auto-detect FROM. One
    # is a satisfied configuration ("every port is pinned, nothing to do
    # here"); the other is port auto-detection quietly not working. Read
    # straight off the four *_source fields the relay prints beside its own
    # resolved numbers, the same fact close-node-config-exposure.sh's own
    # relay_ask() reads.
    RELAY_ALL_PINNED=1
    for relay_port_key in http_rpc_port admin_ws_port ws_public_port peer_port; do
      [[ "$(relay_answer_value "${relay_port_key}_source" "$RELAY_ANSWER" || true)" == "override" ]] \
        || { RELAY_ALL_PINNED=0; break; }
    done
    unset relay_port_key
  fi
fi

# The wrapper the closer reads the node back through: root's own copy in
# /usr/local/sbin when this host has one (ADR 0024), the sibling otherwise,
# which is the copy root staged when install.sh runs this (#764).
CLOSER_ENV=()
CLOSER_WRAPPER="/usr/local/sbin/aperire-node-wrapper${INSTANCE:+-$INSTANCE}"
if [[ -f "$CLOSER_WRAPPER" && ! -L "$CLOSER_WRAPPER" && "$(stat -c %u -- "$CLOSER_WRAPPER" 2>/dev/null)" == 0 ]]; then
  CLOSER_ENV=( "APERIRE_CLOSER_WRAPPER=$CLOSER_WRAPPER" )
fi
if [[ -n "$RELAY_CANNOT_ASK_NOTE" && ! -f "${SCRIPT_DIR}/close-node-config-exposure.sh" ]]; then
  echo "${E_AMBER}warning: $RELAY_CANNOT_ASK_NOTE, so this install cannot ask its own relay${E_OFF}" >&2
  echo "${E_AMBER}         whether it needs the node config, and${E_OFF}" >&2
  echo "${E_AMBER}         ${SCRIPT_DIR}/close-node-config-exposure.sh is not in this checkout${E_OFF}" >&2
  echo "${E_AMBER}         either, so the safe-default read was not granted. Port auto-detection${E_OFF}" >&2
  echo "${E_AMBER}         is off until it is resolved.${E_OFF}" >&2
elif [[ -n "$RELAY_CANNOT_ASK_NOTE" ]]; then
  echo "${E_AMBER}warning: $RELAY_CANNOT_ASK_NOTE, so this install cannot ask its own${E_OFF}" >&2
  echo "${E_AMBER}         relay whether it needs the node config. Falling back to the safe${E_OFF}" >&2
  echo "${E_AMBER}         default: asking close-node-config-exposure.sh, which grants or keeps${E_OFF}" >&2
  echo "${E_AMBER}         a read when it cannot be asked either, rather than guessing one away.${E_OFF}" >&2
  echo "  asking close-node-config-exposure.sh:"
  # `if`, not `|| true`: see the same reasoning below, where this script's own
  # call to the closer is made a second time for the shape it can name.
  if RELAY_CLOSE_OUT="$(APERIRE_RELAY_BIN="$RELAY_BIN_PATH" APERIRE_RELAY_CONF="$RELAY_CONF" \
      env ${CLOSER_ENV[@]+"${CLOSER_ENV[@]}"} bash "${SCRIPT_DIR}/close-node-config-exposure.sh" --apply 2>&1)"; then
    :
  fi
  printf '%s\n' "$RELAY_CLOSE_OUT" | sed 's/^/     | /'
elif [[ "$RELAY_ALL_PINNED" -eq 1 ]]; then
  echo "${S_GREEN}→ aperire-relay does not need a node config: every port is already pinned in $RELAY_CONF${S_OFF}"
  RELAY_PINS_ACTION=drop
elif [[ "$RELAY_READS_FLAG" != "true" || -z "$RELAY_NODE_CFG" ]]; then
  echo "${S_GREEN}→ no node config recorded in $RELAY_CONF, and none of the well-known paths exist${S_OFF}"
  echo "${S_GREEN}  on this host either, so the relay uses the well-known ports; there is nothing${S_OFF}"
  echo "${S_GREEN}  to grant${S_OFF}"
  RELAY_PINS_ACTION=drop
elif [[ "$RELAY_HAD_PINS" -eq 1 ]]; then
  # An earlier run pinned these because the relay could not read the file.
  # Refreshed from it, and nothing else asked: the closer would only be asked
  # for a read the pins already make unneeded.
  RELAY_PINS_ACTION=pin
elif relay_reads_cfg "$RELAY_NODE_CFG"; then
  echo "${S_GREEN}→ aperire-relay reads $RELAY_NODE_CFG, so the connection counts come from your node's own ports${S_OFF}"
elif relay_granted_cfg "$RELAY_NODE_CFG"; then
  # The entry is on the file and the account still cannot open it, so a
  # directory above does not let it through. An operator's home is the usual
  # reason. Pinned in 5c, never granted any further than this.
  RELAY_PINS_ACTION=pin
elif [[ ! -f "${SCRIPT_DIR}/close-node-config-exposure.sh" ]]; then
  echo "${E_AMBER}warning: aperire-relay cannot read $RELAY_NODE_CFG and${E_OFF}" >&2
  echo "${E_AMBER}         ${SCRIPT_DIR}/close-node-config-exposure.sh is not in this checkout, so the${E_OFF}" >&2
  echo "${E_AMBER}         read it needs was not granted. Port auto-detection is off until it runs.${E_OFF}" >&2
else
  echo "${S_GREEN}→ aperire-relay cannot read $RELAY_NODE_CFG yet (the node config was closed before this account existed)${S_OFF}"
  echo "  asking close-node-config-exposure.sh for the one named entry it needs:"
  # `if`, not `|| true`: a non-zero status in a compound command is the shape
  # `set -e` does not act on, and a relay install must not die over a file
  # mode. That script reverts itself and never half-applies except where its
  # own exit code says the revert itself did not take (#462 P2-072).
  #
  # APERIRE_RELAY_BIN / APERIRE_RELAY_CONF hand over the binary and config
  # this step already resolved, so the closer does not have to find a unit
  # that does not exist yet (step 6, below, is what writes it).
  if RELAY_CLOSE_OUT="$(APERIRE_RELAY_BIN="$RELAY_BIN_PATH" APERIRE_RELAY_CONF="$RELAY_CONF" \
      env ${CLOSER_ENV[@]+"${CLOSER_ENV[@]}"} bash "${SCRIPT_DIR}/close-node-config-exposure.sh" --apply 2>&1)"; then
    RELAY_CLOSE_RC=0
  else
    RELAY_CLOSE_RC=$?
  fi
  printf '%s\n' "$RELAY_CLOSE_OUT" | sed 's/^/     | /'
  # Read off the account's own read, not off that script's exit status. It
  # can finish happily having granted an entry a directory above still
  # refuses to let the account past.
  #
  # A relay that still cannot read it has its ports pinned in 5c, whatever
  # the closer answered: with an entry a directory above refuses to honour,
  # or with none because the closer would not grant one.
  if relay_reads_cfg "$RELAY_NODE_CFG"; then
    echo "${S_GREEN}→ granted: aperire-relay reads $RELAY_NODE_CFG, so the connection counts come from your node's own ports${S_OFF}"
  else
    RELAY_PINS_ACTION=pin
    if [[ "$RELAY_CLOSE_RC" -eq 2 ]]; then
      echo "${E_AMBER}warning: the closer's own revert did not take; the config may be left${E_OFF}" >&2
      echo "${E_AMBER}         partially changed. Check it by hand before trusting this host's${E_OFF}" >&2
      echo "${E_AMBER}         permissions again: sudo getfacl -p $RELAY_NODE_CFG${E_OFF}" >&2
    elif [[ "$RELAY_CLOSE_RC" -ne 0 ]]; then
      echo "${E_AMBER}warning: the read was not granted; the reason is in the lines above. Nothing was${E_OFF}" >&2
      echo "${E_AMBER}         half-applied.${E_OFF}" >&2
    fi
  fi
fi

# ── 5c. The ports a relay that cannot read the node config is told (#1266) ──
#
# A node config under an operator's home, which Ubuntu creates 0750, is out of
# the relay's reach whatever entry it holds on the file, and widening that
# reach is exactly what this does not do. The relay's own answer above was
# given to root, which does read the file, so it already carries the ports
# the relay would have found there. They go into relay.conf between the two
# marker lines, written through the existing inode so its owner, group, mode
# and ACL stay as they are (#824). The relay reads them at its restart in 7c,
# or, under --no-restart, at the restart the update offers.
#
# Read back by the relay's own parser before a word is said about them. A
# block it refuses, or that does not resolve to the ports written, is taken
# straight out again: under Restart=always a config the relay will not load
# is a start loop, which is worse than the well-known ports.
if [[ -n "$RELAY_PINS_ACTION" ]]; then
  RELAY_PINS=''
  [[ "$RELAY_PINS_ACTION" == pin ]] && RELAY_PINS="$(relay_pins_block "$RELAY_NODE_CFG" "$RELAY_ANSWER")"
  RELAY_CONF_NEW="$RELAY_CONF_BARE"
  if [[ -n "$RELAY_PINS" ]]; then
    # Above the first [table], if an operator added one: a key below it
    # belongs to that table and the relay would never see it as a port.
    RELAY_CONF_NEW="$(printf '%s\n' "$RELAY_CONF_BARE" | PINS="$RELAY_PINS" awk '
      !done && /^[[:space:]]*\[/ { print ENVIRON["PINS"]; done = 1 }
      { print }
      END { if (!done) print ENVIRON["PINS"] }')"
  fi
  RELAY_PINS_SAID="$(sed -nE 's/^([a-z_]+_port) += ([0-9]+)$/\1=\2/p' <<<"$RELAY_PINS" | tr '\n' ' ')"
  RELAY_PINS_SAID="${RELAY_PINS_SAID% }"
  if [[ "$RELAY_CONF_NEW" != "$RELAY_CONF_NOW" ]]; then
    printf '%s\n' "$RELAY_CONF_NEW" > "$RELAY_CONF"
    RELAY_PINS_OK=0
    if RELAY_READBACK="$(timeout 10 "$RELAY_BIN_PATH" --print-effective-config --config "$RELAY_CONF" 2>/dev/null </dev/null)"; then
      RELAY_PINS_OK=1
      for relay_pin in $RELAY_PINS_SAID; do
        [[ "$(relay_answer_value "${relay_pin%%=*}" "$RELAY_READBACK" || true)" == "${relay_pin#*=}" \
           && "$(relay_answer_value "${relay_pin%%=*}_source" "$RELAY_READBACK" || true)" == override ]] \
          || RELAY_PINS_OK=0
      done
      unset relay_pin
    fi
    if [[ "$RELAY_PINS_OK" -ne 1 ]]; then
      printf '%s\n' "$RELAY_CONF_NOW" > "$RELAY_CONF"
      echo "${E_AMBER}warning: aperire-relay would not load $RELAY_CONF with this change in it, so the file${E_OFF}" >&2
      echo "${E_AMBER}         is back as it was. Check it with: $RELAY_BIN_PATH --print-effective-config --config $RELAY_CONF${E_OFF}" >&2
      RELAY_PINS_SAID=''
      RELAY_PINS_ACTION=''
    fi
  fi
  if [[ "$RELAY_PINS_ACTION" == pin && -n "$RELAY_PINS_SAID" ]]; then
    echo "${S_GREEN}→ pinned $RELAY_PINS_SAID in $RELAY_CONF, read from $RELAY_NODE_CFG,${S_OFF}"
    echo "${S_GREEN}  because aperire-relay cannot reach that file itself; every update reads them again${S_OFF}"
  elif [[ "$RELAY_PINS_ACTION" == pin ]]; then
    echo "${S_GREEN}→ aperire-relay cannot reach $RELAY_NODE_CFG, and nothing in it changes the ports the${S_OFF}"
    echo "${S_GREEN}  relay already uses, so there is nothing to pin${S_OFF}"
  elif [[ "$RELAY_PINS_ACTION" == drop && "$RELAY_HAD_PINS" -eq 1 ]]; then
    echo "${S_GREEN}→ took the ports this installer had pinned out of $RELAY_CONF: none of them applies any more${S_OFF}"
  fi
fi

# ── 6. Install the systemd unit ──────────────────────────────────────
cat > "$UNIT_PATH" <<'EOF'
[Unit]
Description=Aperire validator relay (host and network metrics from /proc)
After=network-online.target
Wants=network-online.target
# A telemetry forwarder should never voluntarily exit; never stop restarting it
# (the default start-limiter would otherwise give up after a few fast crashes).
StartLimitIntervalSec=0

[Service]
Type=simple
User=aperire-relay
Group=aperire-relay
ExecStart=@RELAY_BIN@ --config @RELAY_CONF@
# Restart=always (not on-failure): if the relay ever exits cleanly we still
# want it back. Combined with the reboot persistence below (WantedBy=
# multi-user.target), this guarantees the relay returns after a crash or a
# host reboot without operator intervention.
Restart=always
RestartSec=5

# ── Hardening ────────────────────────────────────────────────────────
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
ProtectKernelLogs=true
PrivateTmp=true
# 0027: files 0640, directories 0750. The relay writes nothing, so this
# changes nothing today; it is here so a future version that does write
# cannot leave a world-readable file behind. systemd-analyze flags the
# omission either way.
UMask=0027
PrivateDevices=true
RestrictRealtime=true
RestrictSUIDSGID=true
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources
# The Go runtime raises RLIMIT_NOFILE to the hard limit before main() runs,
# and setrlimit lives in @resources — so the deny above kills this service
# at startup with SIGSYS, before a line of relay code executes. It only
# happens where the soft limit is below the hard one, which is the stock
# Ubuntu systemd default (1024 / 1048576) and is why a host configured with
# them equal never showed it.
SystemCallFilter=setrlimit prlimit64

# ProtectSystem=strict already makes the whole filesystem read-only (with no
# ReadWritePaths, the relay can write nowhere). It reads only /proc/net/* and
# statfs() on data_mount — both still readable. We intentionally do NOT pin a
# rippled data path here: it varies by install (/var/lib/rippled, ~/rippled,
# /etc/xrpld, containerized) and a non-existent ReadOnlyPaths entry makes the
# unit fail to start on modern systemd. The relay never reads the NuDB anyway.

# Outbound-only; no listening sockets.
RestrictAddressFamilies=AF_INET AF_INET6

# Capability bound — none needed for /proc reads.
CapabilityBoundingSet=
AmbientCapabilities=

[Install]
WantedBy=multi-user.target
EOF
sed -i -e "s#@RELAY_BIN@#${RELAY_BIN_PATH}#" -e "s#@RELAY_CONF@#${RELAY_CONF}#" "$UNIT_PATH"
chmod 644 "$UNIT_PATH"
echo "${S_GREEN}→ installed unit: $UNIT_PATH${S_OFF}"

# ── 7. daemon-reload ─────────────────────────────────────────────────
systemctl daemon-reload
echo "${S_GREEN}→ systemd reloaded${S_OFF}"

# ── 7c. Enable and start, on both branches ───────────────────
# The validator branch used to install the unit and stop, while install.sh,
# the guided setup and the deployment guide all said it was "installed,
# enabled and stopped". An operator who believed that and ran `systemctl
# start` had a relay that worked until the next reboot and was then silently
# gone, with the dashboard showing host metrics stopping and nothing naming
# the cause (#138). Enabling it was blocked by one thing: a relay with nowhere
# to push used to crash-loop or dial a placeholder. It stands by now, so both
# branches can end the same way, running and reboot-persistent.
#
# enable, then restart, not `enable --now`. On a re-run the unit is already
# active, `--now` is a no-op, and the process keeps whatever config it started
# with: a relay went on dialling the placeholder host for as long as it was
# left running, with a correct config on disk the whole time. The relay writes
# nothing and holds no state, so a restart costs a single missed push.
systemctl enable "${RELAY_UNIT_NAME}" >/dev/null 2>&1 || true
if [[ "${APERIRE_NO_RESTART:-0}" == "1" ]]; then
  echo "${S_AMBER}→ not restarted: ${RELAY_UNIT_NAME} keeps the code it started with${S_OFF}"
else
  systemctl restart "${RELAY_UNIT_NAME}" || true
fi

# Asserted, not assumed. Everything downstream of this script (install.sh's
# closing text, the bootstrap's banner) reports the relay as running, and the
# whole point of this change is that those sentences are readings. If the unit
# did not come up, this exits non-zero and says what to read; install.sh
# catches that and prints it rather than a congratulation.
UNIT_ENABLED="$(systemctl is-enabled "${RELAY_UNIT_NAME}" 2>/dev/null || true)"
UNIT_ACTIVE="$(systemctl is-active "${RELAY_UNIT_NAME}" 2>/dev/null || true)"
# Under APERIRE_NO_RESTART nothing here tried to start it, so "did not come
# up" would be a claim about a start that never happened. The unit still has
# to be ENABLED, which this run did do; whether it is running is the restart
# question's business, and the line below says which of the two this is.
if [[ "${APERIRE_NO_RESTART:-0}" == "1" ]]; then
  if [[ "$UNIT_ENABLED" != "enabled" ]]; then
    echo "${E_RED}error: ${RELAY_UNIT_NAME} is not enabled, so a reboot would not bring it back.${E_OFF}" >&2
    echo "${E_DIM}  systemctl is-enabled -> ${UNIT_ENABLED:-<no answer>}${E_OFF}" >&2
    exit 1
  fi
  echo "${S_GREEN}→ ${RELAY_UNIT_NAME} is enabled; it was not restarted, so this is the${S_OFF}"
  echo "${S_GREEN}  process that was already running (is-active: ${UNIT_ACTIVE:-<no answer>})${S_OFF}"
elif [[ "$UNIT_ENABLED" != "enabled" || "$UNIT_ACTIVE" != "active" ]]; then
  cat >&2 <<EOF

${E_RED}error: ${RELAY_UNIT_NAME} did not come up.${E_OFF}

  ${E_DIM}systemctl is-enabled -> ${UNIT_ENABLED:-<no answer>}${E_OFF}
  ${E_DIM}systemctl is-active  -> ${UNIT_ACTIVE:-<no answer>}${E_OFF}

  Everything else is installed: the binary, ${RELAY_CONF} and ${UNIT_PATH}.
  Read why, then start it again:

      systemctl status ${RELAY_UNIT_NAME} --no-pager
      journalctl -u ${RELAY_UNIT_NAME} -n 50 --no-pager
      systemctl enable --now ${RELAY_UNIT_NAME}
EOF
  exit 1
else
  echo "${S_GREEN}→ ${RELAY_UNIT_NAME} is enabled and active (survives reboot)${S_OFF}"
fi

# ── 7a. Plaintext link check (non-fatal) ─────────────────────────────
# MED-07. A relay dialling ws:// on another machine sends its auth_token and
# every telemetry frame across the network readable. Anyone who can see that
# traffic can replay the token and push forged telemetry, which is worse than
# losing the metrics: a real incident can be papered over with healthy numbers.
#
# A dashboard bound off-loopback refuses this by default, so the operator would
# otherwise learn about it as a bare 403 in this host's journal with the
# explanation sitting in a journal on the other machine. Say it here, where the
# config is, at the moment it is written.
#
# Read from the file rather than from a variable so a re-run over a hand-edited
# config gets checked too, not only the config this run generated. Classified
# on the URL literal: no DNS, for the same reason the relay itself does not
# resolve at startup.
DASHBOARD_URL="$(sed -nE 's/^[[:space:]]*dashboard_url[[:space:]]*=[[:space:]]*"([^"]*)".*/\1/p' "$RELAY_CONF" 2>/dev/null | head -1)"
if has_placeholder_url; then
  # A hand-installed config still holding the shipped example. This script no
  # longer writes one, and saying "your link is TLS" about a host that does
  # not exist would be a reassuring line about nothing.
  echo "${S_AMBER}→ dashboard_url is still the shipped placeholder, which points at nothing:${S_OFF}"
  echo "  ${S_CYAN}edit $RELAY_CONF, then: systemctl restart ${RELAY_UNIT_NAME}${S_OFF}"
  DASHBOARD_URL=""
fi
case "$DASHBOARD_URL" in
  "")
    : ;;                                        # awaiting registration; the summary says so already
  wss://*|WSS://*|https://*|HTTPS://*)
    echo "${S_GREEN}→ dashboard link is TLS ($DASHBOARD_URL)${S_OFF}" ;;
  ws://127.*|ws://localhost*|ws://\[::1\]*|http://127.*|http://localhost*|http://\[::1\]*)
    echo "${S_GREEN}→ dashboard link stays on this host ($DASHBOARD_URL)${S_OFF}" ;;
  ws://*|http://*)
    cat >&2 <<EOF

  ${E_AMBER}WARNING: $RELAY_CONF points at a remote dashboard over plain ws.${E_OFF}

      dashboard_url = "$DASHBOARD_URL"

  The auth_token and every telemetry frame cross the network readable, and
  anyone who can see them can push forged telemetry. A dashboard bound
  off-loopback REFUSES this by default and the relay's dial fails with 403.

  Two sanctioned fixes:
    1. Tunnel the hop (WireGuard or SSH) so both ends stay loopback, then set
         dashboard_url = "ws://127.0.0.1:7800/ingest"
    2. Terminate TLS in front of the dashboard, then set
         dashboard_url = "wss://your-dashboard.example/ingest"

  Accepting the cleartext hop on a trusted L2 is a last resort, and it is the
  dashboard operator who opts in, with APERIRE_INGEST_ALLOW_PLAINTEXT=1.

  See docs/RELAY-REFERENCE.md, "Securing a remote relay link".

EOF
    ;;
  *)
    echo "${E_AMBER}warning: could not read the transport of dashboard_url=\"$DASHBOARD_URL\" in $RELAY_CONF.${E_OFF}" >&2
    echo "${E_AMBER}         Expected ws:// or wss:// with a host.${E_OFF}" >&2 ;;
esac

# ── 7d. Path check (non-fatal) ───────────────────────────────────────
# #586. A relay on another network that never shows up leaves the operator one
# fact, "no frame arrived". The relay can try its own dashboard_url once,
# with its own handshake and its own root store, and say which of these it
# is: the name does not resolve, the connection is refused or times out, the
# TLS handshake fails, the token is refused, or it was accepted. That is
# `aperire-relay --check-dashboard`; this runs it here and prints the answer.
#
# Never fatal. A path that is not open yet is the operator's next step, not a
# failed install, and the relay keeps retrying on its own whatever this says.
#
# The URL is read by the relay from $RELAY_CONF, never built from anything
# here, and the token is not printed by either side.
#
# Not run when the dashboard is on this host (a co-located install has
# nothing between the two, and the dashboard may still be coming up), nor
# when there is no dashboard_url to try.
RELAY_CHECK_CMD="sudo aperire-relay --check-dashboard${INSTANCE:+ --config ${RELAY_CONF}}"
if [[ -n "$DASHBOARD_URL" && "${APERIRE_COLOCATED:-0}" != "1" && -x "$RELAY_BIN_PATH" ]]; then
  CHECK_RC=0
  CHECK_OUT="$(timeout 20 "$RELAY_BIN_PATH" --check-dashboard --config "$RELAY_CONF" 2>&1 </dev/null)" || CHECK_RC=$?
  CHECK_SAYS="$(printf '%s\n' "$CHECK_OUT" | sed -n 2p)"
  case "$CHECK_RC" in
    0)
      echo "${S_GREEN}→ dashboard check: ${CHECK_SAYS}${S_OFF}" ;;
    2)
      # An unknown flag. A relay binary from before this check, which the
      # "already in place" path can leave here. Not a verdict on the link.
      echo "${S_AMBER}→ dashboard check skipped: ${RELAY_BIN_PATH} predates --check-dashboard${S_OFF}" ;;
    124)
      echo "${E_AMBER}warning: the dashboard check did not finish in 20 seconds. Run it again: ${RELAY_CHECK_CMD}${E_OFF}" >&2 ;;
    *)
      echo "${E_AMBER}warning: the relay cannot reach its dashboard yet.${E_OFF}" >&2
      echo "${E_AMBER}         ${CHECK_SAYS:-$CHECK_OUT}${E_OFF}" >&2
      echo "${E_AMBER}         After the fix, test the same path again: ${RELAY_CHECK_CMD}${E_OFF}" >&2 ;;
  esac
fi

# ── 7b. Firewall check (non-fatal) ───────────────────────────────────
# The validator host's inbound surface (rippled peer :51235, admin :6006)
# must be filtered. A fresh Ubuntu host ships UFW inactive. We do NOT
# auto-enable it — a default-deny firewall applied over a live SSH session
# can lock the operator out. Detect and warn with the exact rules instead.
# See docs/HARDENING-GUIDE.md (Firewall).
# An advisory is given once, on the install. A relay that has been pushing for
# months does not need the whole block again under an update (#269).
if [[ "${APERIRE_UPDATE:-0}" == "1" ]]; then
  :
elif command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
  echo "${S_GREEN}→ firewall: ufw is active${S_OFF}"
else
  cat >&2 <<'EOF'

  ============================================================
  NOTE: no active host firewall (ufw) detected on this VAL host.
  ============================================================

  Advisory, not an error. rippled's admin WS (:6006) must be
  reachable only from the dashboard host, and the peer port
  (:51235) is intentionally public. Harden to fit your setup:

  - Behind a perimeter / hardware firewall (UniFi, pfSense, …)
    that drops unsolicited inbound? It is reasonable to accept
    skipping a host firewall — but it does NOT stop LAN-lateral
    attacks: keep :6006 reachable only from the dashboard host
    (segment the LAN / use admin_ip in rippled.cfg) and SSH
    key-only.

  - No perimeter firewall? Apply a default-deny host firewall:
      sudo ufw default deny incoming
      sudo ufw allow OpenSSH
      sudo ufw allow 51235/tcp
      sudo ufw allow from <DASH-ip> to any port 6006 proto tcp
      sudo ufw enable
    Run it from a console or a second SSH session you can recover
    from — a wrong SSH rule can lock you out.

  - rippled in Docker? Plain ufw can be bypassed by Docker's own
    iptables rules — use the DOCKER-USER chain (or ufw-docker) so
    the published peer/admin ports are actually filtered.
  ============================================================

EOF
fi

# ── 8. Final instructions ────────────────────────────────
cat <<EOF

  ${S_BOLD}───── ${RELAY_UNIT_NAME} installed ─────${S_OFF}

  Binary:   ${RELAY_BIN_PATH}
  Config:   ${RELAY_CONF}  (mode 640, root:aperire-relay)
  Unit:     ${UNIT_PATH}   (enabled, active)
  Node:     ${RELAY_LABEL:-<not read>}
EOF

# On a host that is already set up, the block above IS the summary: it is read
# from what this run wrote. What follows it is either an introduction to a
# working relay or the wiring instructions for one that was never wired, and
# both were said at install time (#269).
if [[ "${APERIRE_UPDATE:-0}" == "1" ]]; then
  echo
  case "$RELAY_STATE" in
    wired|preserved)
      # Read from the file a moment ago, not from the role: this line is the
      # one thing an update wants to know about the hop, and a templated
      # version of it would be a claim.
      echo "  It pushes to ${DASHBOARD_URL:-<no dashboard_url in the config>}, and the token in"
      echo "  ${RELAY_CONF} is the one the dashboard already trusts." ;;
    *)
      echo "  ${RELAY_CONF} names no dashboard, which is how this host was before"
      echo "  this run: nothing here changed it. See docs/RELAY-REFERENCE.md." ;;
  esac
else
# Left at its original indentation on purpose: every line below is inside a
# heredoc, and indenting the block would move the operator's screen with it.
case "$RELAY_STATE" in
  wired|preserved)
    cat <<EOF

  The dashboard this relay pushes to is configured, and the unit is enabled
  and running. Nothing left to do.

  Verify:
    systemctl status ${RELAY_UNIT_NAME}
    journalctl -u ${RELAY_UNIT_NAME} -n 30 --no-pager
    curl -sS http://127.0.0.1:${DASH_PORT}/healthz   (relay_last_push_ms should be small)

  See docs/RELAY-REFERENCE.md for full reference.
EOF
    ;;
  *)
    cat <<EOF

  The unit is enabled and running, and standing by: ${RELAY_CONF} names no
  dashboard yet, so the relay pushes nothing and says so in its journal. It
  dials nothing at all, which is the point. Two edits and one command:

    1. Fill in the two values only you know:
         sudo editor ${RELAY_CONF}

         dashboard_url   Keep this hop off the open LAN. Either tunnel it
                         (WireGuard/SSH) and use ws://127.0.0.1:7800/ingest,
                         or terminate TLS and use
                         wss://your-dashboard.example/ingest. A plain ws URL
                         to another host sends the token in the clear and a
                         dashboard bound off loopback refuses it (403).
                         See docs/RELAY-REFERENCE.md,
                         "Securing a remote relay link".
         auth_token      Must match RELAY_TOKENS in
                         /etc/aperire/aperire${SUFFIX}.env on the dashboard
                         host. Add it there and restart that dashboard.

    2. Pick the new config up. Restart, not \`enable --now\`: the unit is
       already enabled and already running, so \`--now\` does nothing and the
       process keeps the config it started with.
         sudo systemctl restart ${RELAY_UNIT_NAME}

    3. Verify. The first line tries the dashboard once and names what is in
       the way if it is not reachable: the name, a firewall, TLS, or the token.
         ${RELAY_CHECK_CMD}
         systemctl status ${RELAY_UNIT_NAME}
         journalctl -u ${RELAY_UNIT_NAME} -n 30 --no-pager
         curl -sS http://127.0.0.1:7800/healthz   (run on the dashboard host;
                                                   relay_last_push_ms
                                                   should be small)

  See docs/RELAY-REFERENCE.md for full reference.
EOF
    ;;
esac
fi
