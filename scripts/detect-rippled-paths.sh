#!/bin/bash
# Detect rippled's config file and NuDB data directory on the host, for either
# a native install or a Dockerized rippled, and print two lines:
#
#   RIPPLED_CFG_PATH=<host path, or empty>
#   RIPPLED_DATA_PATH=<host path, or empty>
#
# These feed the dashboard's System tab — RIPPLED_DATA_PATH drives NuDB size /
# growth / mount-free-days (the dashboard walks it), and RIPPLED_CFG_PATH
# surfaces the online_delete retention setting. Empty values are printed when a
# path can't be determined, so the caller can write a commented placeholder
# instead of a wrong guess.
#
# The dashboard reads these from the HOST filesystem, so for Docker we resolve
# the in-container paths back to their host bind-mount sources. We prefer the
# rippled that is actually RUNNING (a live Docker container, then a native
# install) so a stale/decommissioned install on the same host doesn't win, and
# we only emit a data path that exists on the host.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# The one way anything here asks docker what is running, and the one place
# that tells a refused answer from an absence (#142).
if [[ ! -r "$SCRIPT_DIR/docker-ask-lib.sh" ]]; then
  echo "detect-rippled-paths: $SCRIPT_DIR/docker-ask-lib.sh is missing from this checkout" >&2
  exit 1
fi
# shellcheck source=scripts/docker-ask-lib.sh
. "$SCRIPT_DIR/docker-ask-lib.sh"

cfg=""
data=""

# Pull the [node_db] path out of a rippled.cfg on disk.
node_db_path() {  # $1 = cfg file
  awk '
    /^[[:space:]]*\[node_db\]/ { innode=1; next }
    /^[[:space:]]*\[/          { innode=0 }
    innode && /^[[:space:]]*path[[:space:]]*=/ {
      sub(/^[^=]*=[[:space:]]*/, ""); gsub(/[[:space:]]+$/, ""); print; exit
    }
  ' "$1" 2>/dev/null
}

# Map an in-container path to its host path via the longest bind-mount
# destination that is a path-prefix of it. $1=container id, $2=container path.
map_container_path() {
  docker inspect "$1" \
    --format '{{range .Mounts}}{{println .Source "\t" .Destination}}{{end}}' 2>/dev/null \
  | awk -F'\t' -v t="$2" '
      { gsub(/^[[:space:]]+|[[:space:]]+$/,"",$1); gsub(/^[[:space:]]+|[[:space:]]+$/,"",$2) }
      $2 != "" && index(t,$2)==1 {
        rest = substr(t, length($2)+1)
        if (rest == "" || substr(rest,1,1) == "/") {
          if (length($2) > best) { best=length($2); src=$1; dst=$2 }
        }
      }
      END { if (src != "") { sub("^"dst, src, t); print t } }
    '
}

# ── Priority 1: live Dockerized rippled ──
# The gate used to be `docker ps` succeeding, so a query docker refused fell
# through to the native search below and this host was reported as a native
# install on no evidence (#142). A refusal is now said out loud, on stderr,
# and the native search still runs: it is not made wrong by an unanswered
# question, it is just no longer the whole answer.
# On a non-zero return DOCKER_SAID is docker's complaint, not the list.
DOCKER_SAID=''
DOCKER_ASK=0
DOCKER_SAID="$(docker_ask '{{.ID}} {{.Image}} {{.Command}}' --no-trunc)" || DOCKER_ASK=$?
# A container created from a digest shows an image ID in the Image column;
# read its name back, and treat a refused read like a refused ps (#896).
if [[ $DOCKER_ASK -eq 0 ]]; then
  DOCKER_SAID="$(docker_resolve_image_ids "$DOCKER_SAID")" || DOCKER_ASK=$?
fi
if [[ $DOCKER_ASK -eq 2 ]]; then
  echo "detect-rippled-paths: docker is installed here and would not say what is" >&2
  echo "  running (${DOCKER_SAID}). A node in a container cannot be seen from" >&2
  echo "  here, so what follows describes this host's native install only." >&2
fi
if [[ $DOCKER_ASK -eq 0 ]]; then
  cid="$(printf '%s\n' "$DOCKER_SAID" | awk '/rippled|xrpld/ {print $1; exit}')"
  if [[ -n "$cid" ]]; then
    # cfg the container actually runs with (--conf arg), else the known
    # conventions in order. The fork renames paths the way it renames
    # binaries: xrpl-labs images take config as a /config bind mount (the
    # entrypoint copies it to /etc/xrpld/, which is not a mount and cannot
    # map back to the host), and native rippled uses /opt/ripple. A single
    # assumed default is how a running, healthy node detected as nothing.
    ccfg="$(docker inspect "$cid" \
      --format '{{join .Config.Entrypoint " "}} {{join .Config.Cmd " "}}' 2>/dev/null \
      | grep -oE -- '--conf[ =][^ ]+' | head -1 | sed -E 's/^--conf[ =]//')"
    for cand in "$ccfg" /config/xrpld.cfg /config/rippled.cfg /opt/ripple/etc/rippled.cfg; do
      [[ -z "$cand" ]] && continue
      m="$(map_container_path "$cid" "$cand")"
      if [[ -n "$m" && -f "$m" ]]; then cfg="$m"; break; fi
    done
    ndb=""
    [[ -n "$cfg" && -f "$cfg" ]] && ndb="$(node_db_path "$cfg")"
    # ndb is the CONTAINER path from the config; map it, then fall back to
    # both data-dir conventions (3.2.x xrpld uses /var/lib/xrpld, rippled
    # and older images /var/lib/rippled).
    for dcand in "$ndb" /var/lib/xrpld /var/lib/rippled; do
      [[ -z "$dcand" ]] && continue
      m="$(map_container_path "$cid" "$dcand")"
      if [[ -n "$m" && -d "$m" ]]; then data="$m"; break; fi
    done
  fi
fi

# ── Priority 2: native rippled (only if Docker didn't resolve a data dir) ──
#
# The candidates start with the config a program on this host already
# MEASURED and wrote down, before any guessed path: /etc/aperire/
# node-wrapper.conf is written by install-node-wrapper.sh from the unit that
# is running, and node.conf by install-aperire-node.sh for the node it
# installed. A guess list can only hold the layouts that existed when it was
# written, and on a lab host it held none of them: the current vendor
# package puts its config at /etc/xrpld/xrpld.cfg, all three guesses below
# are the older `rippled` package's, and this script answered with two empty
# values on a perfectly ordinary native host. The System tab then had no
# store to measure and said nothing about why.
native_candidates=()
for conf in /etc/aperire/node-wrapper.conf /etc/aperire/node.conf; do
  [[ -r "$conf" ]] || continue
  declared="$(awk -F= '$1=="CONFIG_FILE"{sub(/^[^=]*=/,""); print; exit}' "$conf" 2>/dev/null)"
  [[ -n "$declared" ]] && native_candidates+=("$declared")
done
native_candidates+=(/etc/xrpld/xrpld.cfg /etc/opt/ripple/rippled.cfg /opt/ripple/etc/rippled.cfg /etc/ripple/rippled.cfg)

if [[ -z "$data" ]]; then
  for p in "${native_candidates[@]}"; do
    [[ -f "$p" ]] || continue
    ndata="$(node_db_path "$p")"
    # Accept only when the parsed data dir actually exists on the host — this
    # rejects a stale cfg whose data lives somewhere that no longer exists.
    if [[ -n "$ndata" && -d "$ndata" ]]; then cfg="$p"; data="$ndata"; break; fi
  done
fi

# Final guard: never emit a path that isn't really there.
[[ -n "$data" && ! -d "$data" ]] && data=""
[[ -n "$cfg"  && ! -f "$cfg"  ]] && cfg=""

echo "RIPPLED_CFG_PATH=${cfg}"
echo "RIPPLED_DATA_PATH=${data}"
