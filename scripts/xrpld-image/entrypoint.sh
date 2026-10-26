#!/bin/bash
# Entrypoint for an xrpld image built from the signed DEB package.
#
# Why it exists at all: it keeps the contract of the previous image,
# xrpllabsofficial/xrpld (up to 3.3.0), whose deployments mount their config
# at /config and rely on the entrypoint to copy it where xrpld reads it. A
# deployment that mounts only /config/rippled.cfg needs this file; without it
# xrpld would start on the package's default config. The contract:
#
#   /config/xrpld.cfg, else /config/rippled.cfg   copied to /etc/xrpld/xrpld.cfg
#   /config/validators.txt                        copied to /etc/xrpld/validators.txt
#   then: exec /usr/bin/xrpld --conf /etc/xrpld/xrpld.cfg <args> $ENV_ARGS
#
# Three differences from the previous entrypoint, all deliberate:
#
#   - No environment dump. The old one ran `printenv` at every start, which
#     puts whatever a deployment passes in the environment into the log.
#   - A copy onto a file that already holds the same bytes is skipped. A
#     non-root node with its config mounted read-only at both paths used to
#     print one "Read-only file system" line per file at every start.
#   - The exec line quotes what it passes on. The old one ended
#     `--conf /etc/xrpld/xrpld.cfg $@$ENV_ARGS`: unquoted, so every argument
#     was word-split and glob-expanded on the way through, and with nothing
#     between $@ and $ENV_ARGS the last argument and the first word of
#     ENV_ARGS were glued into one token. Here each argument arrives whole,
#     and ENV_ARGS follows it as its own words, which is what a deployment
#     setting ENV_ARGS="--net --silent" is asking for.
#
# A copy that is needed and fails STOPS the node. The old entrypoint carried
# on, and that is the failure worth refusing: this image defaults to uid 997
# and /etc/xrpld is root-owned, so a deployment that mounts its config only at
# /config would have xrpld come up on the package's default config. A node on
# someone else's settings, with no validator key, reporting healthy. The
# message says what to do: mount the file where xrpld reads it, which needs
# no write access at all. It does not say "run as root", because that is only
# sometimes true. Under `--read-only` the write is refused whatever the uid
# is, and this image's own verify runs use that flag.
set -u

CFG=/etc/xrpld/xrpld.cfg
VALIDATORS=/etc/xrpld/validators.txt

copy_in() {
  local src=$1 dst=$2
  if cmp -s "$src" "$dst"; then
    echo "entrypoint: $dst already matches $src"
    return 0
  fi
  if cat "$src" > "$dst"; then
    echo "entrypoint: copied $src to $dst"
    return 0
  fi
  echo "entrypoint: could not copy $src to $dst, and will not start xrpld on whatever the package left at $dst instead." >&2
  echo "entrypoint: mount the file at $dst as well, read-only. That needs no write access here at all, and it is what the copy would have produced." >&2
  echo "entrypoint: writing it instead needs $dst writable by uid $(id -u), which a read-only root filesystem refuses whatever the uid is." >&2
  exit 1
}

if [ -s /config/xrpld.cfg ]; then
  copy_in /config/xrpld.cfg "$CFG"
elif [ -s /config/rippled.cfg ]; then
  copy_in /config/rippled.cfg "$CFG"
fi

if [ -s /config/validators.txt ]; then
  copy_in /config/validators.txt "$VALIDATORS"
fi

# ENV_ARGS is split into words on purpose, as the image this replaces did.
# shellcheck disable=SC2086
exec /usr/bin/xrpld --conf "$CFG" "$@" ${ENV_ARGS:-}
