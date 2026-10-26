#!/bin/bash
# Enable a co-located aperire-relay on a node whose dashboard was installed
# without RELAY_TOKENS (the read-API dashboard, aperire-read). Idempotent.
#
# One thing is done here and nowhere else: wiring that dashboard's unit to
# read its own /etc/aperire environment file at all, with a drop-in. On a host
# carrying a second pairing that file is aperire-<instance>.env, and the
# instance is read off the unit handed in. Everything after that
# (mint or reuse the token, pair it into RELAY_TOKENS, restart the dashboard
# so /ingest accepts it, write relay.conf, enable and start the relay) belongs
# to install-aperire-relay.sh's co-located path and is called, not copied. A
# relay token that two scripts can mint is a token that ends up in one file
# and not the other, which presents as a 401 nobody wrote down.
#
# Idempotent means idempotent on the host this is naturally re-run on: one
# whose relay is already installed, where the binary to hand in is the
# installed one at /usr/local/bin/aperire-relay. A second run over a host
# that is fully wired writes nothing, mints nothing, restarts no dashboard,
# and says so at each step rather than reporting work it did not do.
#
# Usage (run ON the node, as root):
#   sudo bash enable-relay-colocated.sh <dashboard-unit> <dash-port> <relay-binary> <install-script>
# e.g.
#   sudo bash enable-relay-colocated.sh aperire-read 7900 /tmp/aperire-relay /tmp/install-aperire-relay.sh
#   sudo bash enable-relay-colocated.sh aperire-server 7800 /usr/local/bin/aperire-relay \
#        /home/<user>/aperire-one/scripts/install-aperire-relay.sh
# A host carrying a second pairing names its instance in that unit, and every
# file this touches follows from it:
#   sudo bash enable-relay-colocated.sh aperire-server-node2 7900 /usr/local/bin/aperire-relay \
#        /home/<user>/aperire-one/scripts/install-aperire-relay.sh
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "error: must run as root" >&2
  exit 1
fi

DASH_UNIT="${1:?dashboard systemd unit, e.g. aperire-read}"
DASH_PORT="${2:?dashboard port, e.g. 7900}"
RELAY_BIN="${3:?path to the aperire-relay binary}"
INSTALL_SH="${4:?path to install-aperire-relay.sh}"

[[ -x "$RELAY_BIN"   ]] || { echo "error: relay binary not executable: $RELAY_BIN" >&2; exit 2; }
[[ -f "$INSTALL_SH"  ]] || { echo "error: install script not found: $INSTALL_SH" >&2; exit 2; }

# The two absolute paths this script writes under, named once. Everything
# below goes through them, which is also what lets the wiring suite run this
# script against a temporary directory rather than reading it and guessing.
ETC_APERIRE=/etc/aperire
SYSTEMD_DIR=/etc/systemd/system

# One relay per node, feeding one dashboard (ADR 0009). A host carrying a
# second pairing names its unit, its relay config and the dashboard's own
# environment file with an instance suffix, and the single job of this script
# is the drop-in that points a dashboard unit at that environment file. Naming
# the unsuffixed one on an instance host wires the dashboard to a file the
# installer never writes the token into, and the drop-in's leading "-" turns
# that into a 401 nobody wrote down rather than a unit that refuses to start
# (#498).
#
# The instance is read off the dashboard unit handed in. That unit is the one
# being wired, and it is the only carrier that survives the `sudo` in front of
# this script: env_reset drops APERIRE_INSTANCE out of an operator's own
# environment, and the menu entry that calls this passes the unit and no
# environment at all. Set explicitly, APERIRE_INSTANCE still names the layout,
# and a name that disagrees with the unit is refused rather than resolved.
UNIT_INSTANCE=""
UNIT_IS_READABLE=0   # 1 when the unit name is one a suffix can be read off
case "$DASH_UNIT" in
  aperire-server|aperire-read)  UNIT_IS_READABLE=1 ;;
  aperire-server-*)             UNIT_IS_READABLE=1; UNIT_INSTANCE="${DASH_UNIT#aperire-server-}" ;;
  aperire-read-*)               UNIT_IS_READABLE=1; UNIT_INSTANCE="${DASH_UNIT#aperire-read-}" ;;
esac

# A name read off the unit gets the same shape check the installer makes of a
# name handed to it. Without it, a typo in the unit is refused downstream by
# the installer, after this script has already written the drop-in, and a
# misspelling leaves a part-wired host behind.
if [[ -n "$UNIT_INSTANCE" && ! "$UNIT_INSTANCE" =~ ^[a-z0-9][a-z0-9-]{0,30}$ ]]; then
  cat >&2 <<EOF
error: $DASH_UNIT names the instance '$UNIT_INSTANCE', which is not a shape an
instance name takes: lowercase letters, digits and dashes. Nothing was written
and nothing was run.

  Name the unit this host actually has. systemctl list-unit-files 'aperire-*'
  prints them.
EOF
  exit 2
fi

INSTANCE="${APERIRE_INSTANCE:-}"
if [[ -n "$INSTANCE" && ! "$INSTANCE" =~ ^[a-z0-9][a-z0-9-]{0,30}$ ]]; then
  echo "error: instance name must be lowercase letters, digits and dashes" >&2
  exit 2
fi
if [[ -n "$INSTANCE" && $UNIT_IS_READABLE -eq 1 && "$INSTANCE" != "$UNIT_INSTANCE" ]]; then
  if [[ -n "$UNIT_INSTANCE" ]]; then
    UNIT_SAYS="instance '$UNIT_INSTANCE', whose file is ${ETC_APERIRE}/aperire-${UNIT_INSTANCE}.env"
  else
    UNIT_SAYS="the single-instance layout, whose file is ${ETC_APERIRE}/aperire.env"
  fi
  cat >&2 <<EOF
error: the instance named and the dashboard unit handed in disagree. Nothing
was written and nothing was run.

  APERIRE_INSTANCE=$INSTANCE names ${ETC_APERIRE}/aperire-${INSTANCE}.env.
  $DASH_UNIT is the unit of $UNIT_SAYS.

  Resolving that would point one file at the unit and mint the token into the
  other, which is a relay whose every push is rejected. Name the unit and the
  instance for the same pairing, or drop APERIRE_INSTANCE and let the unit say.
EOF
  exit 2
fi
[[ -n "$INSTANCE" ]] || INSTANCE="$UNIT_INSTANCE"
SUFFIX="${INSTANCE:+-$INSTANCE}"

# The same line, character for character, as the one install-aperire-relay.sh
# resolves its own ENV_FILE with, and the same rule the menu uses to read this
# dashboard's port. The wiring suite asserts the two lines are one, because
# the whole of #498 was the two files drifting apart by one suffix.
ENV_FILE="${ETC_APERIRE}/aperire${SUFFIX}.env"
# The installer's names for the other two halves of the same pairing, so the
# repair text and the verify block below name what this host actually has.
RELAY_CONF="${ETC_APERIRE}/relay${SUFFIX}.conf"
RELAY_UNIT_NAME="aperire-relay${SUFFIX}"
if [[ -n "$INSTANCE" ]]; then
  echo "→ instance '$INSTANCE', read off $DASH_UNIT: env $ENV_FILE, relay unit $RELAY_UNIT_NAME"
fi

# The env file is root-owned and readable by the group the dashboard runs in.
# That group is read off the unit handed in, the way install-aperire-service.sh
# picks it for the file it writes: the account in the unit (systemd's answer
# first, so a User= in a drop-in counts, then the unit file for one it has not
# loaded yet), then the group called after that account when there is one, its
# primary group otherwise. A fresh install runs the dashboard as
# aperire-dashboard; a host that predates that runs it as the login. A unit
# with no User= runs as root. This was the literal group `aperire`, which
# stopped the script on a host that has no such group (#1221) and, on one that
# has it, handed the file to a group the dashboard is not in.
#
# Resolved before anything is written, so a unit or an account the host does
# not have stops the run with the host as it was. The unit is checked first
# because systemd answers `show` for a unit it has never heard of with no error
# and an empty User=, which would read as a dashboard that runs as root and
# hand the live env file to root (install-aperire-service.sh asks for
# LoadState=loaded for the same reason).
if [[ "$(systemctl show -p LoadState --value "${DASH_UNIT}.service" 2>/dev/null || true)" != loaded \
      && ! -f "${SYSTEMD_DIR}/${DASH_UNIT}.service" ]]; then
  cat >&2 <<EOF
error: $DASH_UNIT is not a unit on this host, so there is no account to read the
env file's group from. Nothing was written and nothing was run.

  Name the unit this host actually has. systemctl list-unit-files 'aperire-*'
  prints them.
EOF
  exit 2
fi
DASH_USER="$(systemctl show -p User --value "${DASH_UNIT}.service" 2>/dev/null || true)"
if [[ -z "$DASH_USER" && -f "${SYSTEMD_DIR}/${DASH_UNIT}.service" ]]; then
  DASH_USER="$(awk '/^\[/{svc=($0=="[Service]"); next} svc && /^[[:space:]]*User[[:space:]]*=/{sub(/^[^=]*=[[:space:]]*/,""); sub(/[[:space:]]+$/,""); u=$0} END{print u}' \
    "${SYSTEMD_DIR}/${DASH_UNIT}.service" 2>/dev/null || true)"
fi
ENV_GROUP=root
if [[ -n "$DASH_USER" && "$DASH_USER" != root ]]; then
  if getent group -- "$DASH_USER" >/dev/null 2>&1; then
    ENV_GROUP="$DASH_USER"
  else
    ENV_GROUP="$(id -gn -- "$DASH_USER" 2>/dev/null || true)"
  fi
  if [[ -z "$ENV_GROUP" ]]; then
    cat >&2 <<EOF
error: $DASH_UNIT runs as '$DASH_USER', and this host has no such account, so
the env file has no group to be given. Nothing was written and nothing was run.

  Look at the unit: systemctl cat $DASH_UNIT
EOF
    exit 2
  fi
fi

mkdir -p "$ETC_APERIRE"
touch "$ENV_FILE"
# The installer preserves whatever ownership it finds here, so set it before
# calling it.
chown "root:${ENV_GROUP}" "$ENV_FILE"; chmod 640 "$ENV_FILE"
echo "→ $ENV_FILE is root:${ENV_GROUP} 0640, the group $DASH_UNIT runs in (as ${DASH_USER:-root})"

# ── 1. Wire the dashboard to read the env file (additive drop-in) ─────
# EnvironmentFile is additive: the unit's inline Environment= lines (PORT,
# HOST, RIPPLED_URL, …) are untouched; this only adds RELAY_TOKENS. Written
# BEFORE the installer runs, because the installer's restart of this unit is
# what makes the token take effect, and a unit that does not read the file
# would restart into the same tokenless state.
#
# The leading "-" makes a missing file a skipped read rather than a failed
# start, and it belongs here for one reason: this drop-in adds RELAY_TOKENS to
# a unit that carries its own PORT, HOST and RIPPLED_URL inline, so a host
# without the file has a dashboard that serves and a relay whose pushes are
# rejected (healthz reports that as relay_last_push_ms), not a dashboard that
# refuses to start. The unit whose whole environment does come from this file
# is the installer's own, and that one declares the file hard in the unit
# itself, where a drop-in cannot relax it.
#
# Written only when it is not already what it should be. A host that has been
# through this once is a host this step has nothing to do on, and saying
# "written" over a file nobody wrote is the small dishonesty that makes an
# operator doubt the rest of the run. The content is compared, not the file's
# existence, so a drop-in naming some other env file is still rewritten.
DROPDIR="${SYSTEMD_DIR}/${DASH_UNIT}.service.d"
DROPIN="$DROPDIR/relay-env.conf"
DESIRED_DROPIN="$(cat <<EOF
[Service]
EnvironmentFile=-$ENV_FILE
EOF
)"
if [[ -f "$DROPIN" && "$(cat "$DROPIN")" == "$DESIRED_DROPIN" ]]; then
  echo "→ drop-in already in place: $DROPIN"
else
  mkdir -p "$DROPDIR"
  printf '%s\n' "$DESIRED_DROPIN" > "$DROPIN"
  systemctl daemon-reload
  echo "→ drop-in written: $DROPIN"
fi

# ── 2. Token, pairing, config, enable, start ──────────────────────────
# Say which binary is being handed over, before handing it over. On a host
# where the relay is already installed the natural thing to pass is the
# installed path, and the installer answers that with "already in place"
# rather than a copy. Its line says which of the two happened; this one says
# what it was given, resolved, so the two read together.
RELAY_BIN_REAL="$(readlink -f -- "$RELAY_BIN" 2>/dev/null || true)"
if [[ -n "$RELAY_BIN_REAL" && "$RELAY_BIN_REAL" != "$RELAY_BIN" ]]; then
  echo "→ handing the installer the binary at $RELAY_BIN (resolves to $RELAY_BIN_REAL)"
else
  echo "→ handing the installer the binary at $RELAY_BIN"
fi

# Run it without dying on it. Under `set -e` a failure here ends the script
# where it stands, and an operator is left with the installer's last line and
# nothing about the state of the host: the drop-in above IS written, on
# purpose, and step 2 owns everything that makes it useful. So the failure is
# caught and named. The steps this script cannot speak for are pointed back
# at the installer's own output rather than declared undone, because the
# installer can fail anywhere in its run and a fixed list of what did not
# happen would be a claim nothing here measured.
#
# The instance is handed over on the command that runs it rather than left to
# survive whatever environment this script was started in. That is what makes
# the file named above and the file the installer writes the token into the
# same file, on a host where they are not the only candidate.
RELAY_RC=0
APERIRE_COLOCATED=1 APERIRE_PORT="$DASH_PORT" APERIRE_DASH_UNIT="$DASH_UNIT" \
  APERIRE_INSTANCE="$INSTANCE" \
  bash "$INSTALL_SH" "$RELAY_BIN" || RELAY_RC=$?
if [[ $RELAY_RC -ne 0 ]]; then
  cat >&2 <<EOF

error: the relay installer exited $RELAY_RC. This host is part wired.

  Done here, before it ran, and left in place:
    $DROPIN
      It adds nothing but RELAY_TOKENS, and names the file with a leading "-",
      so $DASH_UNIT starts and serves whether or not the rest of this ran.

  Owned by the installer, whose output above says how far it got:
    the relay token, its pairing into RELAY_TOKENS in $ENV_FILE, the
    $DASH_UNIT restart that makes that token take effect,
    $RELAY_CONF, and $RELAY_UNIT_NAME enabled and started.

  Fix what it reported and run this same command again. Nothing it already
  got right is redone: the token is reused rather than reminted, and the
  dashboard is restarted only when the token it holds changed.
EOF
  exit $RELAY_RC
fi

# ── 3. Verify — positive evidence on both sides of the hop ───────────
echo "===================== VERIFY ====================="
echo "--- relay active? ---"
systemctl is-active "$RELAY_UNIT_NAME" || true
echo "--- relay journal (want: a successful push, not just 'started') ---"
journalctl -u "$RELAY_UNIT_NAME" -n 20 --no-pager || true
echo "--- dashboard journal (want: accepted /ingest upgrade, NOT a 401 reject) ---"
journalctl -u "$DASH_UNIT" -n 20 --no-pager || true
# Both halves of the wiring name one file, or they do not. The drop-in above
# points $DASH_UNIT at $ENV_FILE and the installer pairs the token into the
# file it resolved for itself; if those were ever two files the relay would
# start, push, and be rejected, with nothing in either journal saying why.
# Read rather than assumed, and printed either way.
echo "--- the file both halves name ---"
echo "    drop-in points $DASH_UNIT at: $ENV_FILE"
if grep -qE '^[[:space:]]*RELAY_TOKENS=..*' "$ENV_FILE" 2>/dev/null; then
  echo "    and that file carries RELAY_TOKENS, so the dashboard reads the token the installer paired"
else
  echo "    and that file holds no RELAY_TOKENS. Two readings fit that, and the installer's"
  echo "    own lines above say which. It paired into a different file, so the two halves"
  echo "    disagree about this host's instance and every push will be rejected. Or it left"
  echo "    a config pointing at a dashboard on another host, where this file is not the one"
  echo "    in use and nothing here is wrong."
fi
echo "=================================================="
