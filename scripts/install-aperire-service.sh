#!/bin/bash
# Install Aperire Dashboard as a systemd service.
#
# Idempotent — safe to re-run after upgrades. Creates /etc/aperire/aperire.env
# with a fresh relay token on first run; preserves the existing token on
# subsequent runs (so the relay config does not need to be rotated every
# time the service file changes).
#
# Run with: sudo bash install-aperire-service.sh
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

# Where this program and its siblings are, and the install tree it acts on:
# one directory and its parent from a checkout, two when install.sh runs a
# copy root staged out of the release and names the tree (#764). Code is
# only ever loaded from SCRIPT_DIR.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="${APERIRE_INSTALL_TREE:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

# The palette the install path shares, so "done", "degraded" and "refused"
# look the same wherever they are printed. Every string in it is empty unless
# the stream is a terminal, so a captured or piped run stays byte-plain.
[[ -r "${SCRIPT_DIR}/term-style.sh" ]] \
  || { echo "error: ${SCRIPT_DIR}/term-style.sh is missing from this checkout" >&2; exit 1; }
# shellcheck source=scripts/term-style.sh
. "${SCRIPT_DIR}/term-style.sh"
# The one rule about who may write advisor/knowledge-fleet, and the repair for
# a host that has it wrong. Its own file because two installers and a check
# all need the same answer (#245).
[[ -r "${SCRIPT_DIR}/fleet-corpus-perms.sh" ]] \
  || { echo "error: ${SCRIPT_DIR}/fleet-corpus-perms.sh is missing from this checkout" >&2; exit 1; }
# shellcheck source=scripts/fleet-corpus-perms.sh
. "${SCRIPT_DIR}/fleet-corpus-perms.sh"
# The account the service runs as is decided below the root check, because
# a fresh install creates it (ADR 0024). RUN_USER is that account.
DATA_DIR="${REPO_DIR}/data"
LOG_DIR="${DATA_DIR}/logs"
# The dashboard opens its sqlite DB under data/ (outside the source tree, so
# the unit's ReadWritePaths can exclude dashboard/), i.e. data/aperire.db.
# APERIRE_DB_PATH, if set in the env file, overrides; honour it so the chmod
# hits the right file.
# ── Instance ────────────────────────────────────────────────────────
# One dashboard monitors one node (ADR 0009), so an operator with two nodes
# runs two dashboards. Everything that would collide between them is named
# from this one value: the unit, the env file, the logrotate config and the
# database. Empty — the default — reproduces the single-instance layout
# exactly, so an existing host sees no change at all.
#
# The name is used in file paths and a unit name, so it is restricted to
# what is safe in both rather than sanitised into something surprising.
INSTANCE="${APERIRE_INSTANCE:-}"
if [[ -n "$INSTANCE" && ! "$INSTANCE" =~ ^[a-z0-9][a-z0-9-]{0,30}$ ]]; then
  echo "${E_RED}error: instance name must be lowercase letters, digits and dashes${E_OFF}" >&2
  exit 2
fi
SUFFIX="${INSTANCE:+-$INSTANCE}"

DB_FILE="${APERIRE_DB_PATH:-${DATA_DIR}/aperire${SUFFIX}.db}"
ENV_DIR="/etc/aperire"
ENV_FILE="${ENV_DIR}/aperire${SUFFIX}.env"
SERVICE_NAME="aperire-server${SUFFIX}"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
LOGROTATE_FILE="/etc/logrotate.d/aperire${SUFFIX}"

if [[ $EUID -ne 0 ]]; then
  echo "${E_RED}error: must run as root (sudo)${E_OFF}" >&2
  exit 1
fi

# ── Which account the dashboard runs as (ADR 0024) ───────────────────
#
# Its own system account, aperire-dashboard: no login shell, no home, and
# none of the groups that are root on this host by themselves. It owns data/
# and nothing else in the tree. The tree stays the operator's.
#
# Why not the operator's own login, which is what this used to name: that
# login is in docker on most hosts, and often in sudo. A web process running
# as it could open /run/docker.sock and be root with the validator in reach,
# and anything else running as that login could rewrite the code root runs.
# The unit's sandbox was the only thing in between, and a sandbox is one
# file, not an account boundary.
#
# The one exception is a host that already runs the dashboard as somebody
# else's account (every host installed before this, prod among them). That
# account is kept, with a warning, and everything below comes out exactly as
# it did before. Moving an existing host restarts the dashboard and hands
# its files over, and an install or an update promises neither. That move is
# its own step, after GA (#864).
DASH_ACCOUNT=aperire-dashboard
# Groups that are root on a host by themselves.
ROOT_GROUPS="docker sudo admin wheel libvirt lxd incus-admin microk8s adm disk root"
# The tree's owner, from the tree itself. Not $SUDO_USER: this script is
# also run from the update's root socket, where there is no SUDO_USER.
TREE_OWNER="$(stat -c '%U' "${REPO_DIR}" 2>/dev/null || true)"
[[ -n "${TREE_OWNER}" && "${TREE_OWNER}" != "UNKNOWN" ]] || TREE_OWNER="${SUDO_USER:-root}"
# Every dashboard unit on the host, not only this instance's: instances share
# data/, so a second instance on a kept host must not take the new shape and
# hand the first one's database to an account that one does not run as.
# What a unit runs as: systemd's own answer first, so a User= set in a
# drop-in counts, then the file itself (a unit not loaded yet), the last
# User= under [Service] winning, spaces around the = allowed.
unit_user() { # $1 = unit file
  local name v
  name="$(basename "$1")"
  v=""
  if [[ "$(systemctl show -p LoadState --value "$name" 2>/dev/null || true)" == loaded ]]; then
    v="$(systemctl show -p User --value "$name" 2>/dev/null || true)"
  fi
  if [[ -z "$v" ]]; then
    v="$(awk '/^\[/{svc=($0=="[Service]"); next} svc && /^[[:space:]]*User[[:space:]]*=/{sub(/^[^=]*=[[:space:]]*/,""); sub(/[[:space:]]+$/,""); u=$0} END{print u}' "$1" 2>/dev/null || true)"
  fi
  printf '%s' "$v"
}
EXISTING_USER=""
if [[ -f "${SERVICE_FILE}" ]]; then
  EXISTING_USER="$(unit_user "${SERVICE_FILE}")"
fi
if [[ -z "${EXISTING_USER}" || "${EXISTING_USER}" == "${DASH_ACCOUNT}" ]]; then
  for _u in "$(dirname "${SERVICE_FILE}")"/aperire-server*.service "$(dirname "${SERVICE_FILE}")"/aperire-read*.service; do
    [[ -f "$_u" ]] || continue
    _who="$(unit_user "$_u")"
    if [[ -n "$_who" && "$_who" != "${DASH_ACCOUNT}" ]]; then EXISTING_USER="$_who"; break; fi
  done
fi
LEGACY_ACCOUNT=0
if [[ -n "${EXISTING_USER}" && "${EXISTING_USER}" != "${DASH_ACCOUNT}" ]]; then
  LEGACY_ACCOUNT=1
  RUN_USER="${EXISTING_USER}"
  echo "${S_AMBER}The dashboard on this host runs as '${RUN_USER}', not as its own account (${DASH_ACCOUNT}).${S_OFF}"
  echo "${S_DIM}  Kept as it is: this run changes no account and restarts nothing for it.${S_OFF}"
  echo "${S_DIM}  A dashboard on a person's login can reach whatever that login can (docker,${S_OFF}"
  echo "${S_DIM}  sudo, the code root runs). Moving it to ${DASH_ACCOUNT} is a separate step${S_OFF}"
  echo "${S_DIM}  that comes in a later release.${S_OFF}"
else
  RUN_USER="${DASH_ACCOUNT}"
  # The tree must not be the dashboard's. If it were, this account would own
  # the code root runs, which is the whole thing this account exists to stop.
  if [[ "${TREE_OWNER}" == "${DASH_ACCOUNT}" ]]; then
    echo "${E_RED}error: ${REPO_DIR} is owned by ${DASH_ACCOUNT}, the dashboard's own account.${E_OFF}" >&2
    echo "${E_RED}       The install tree belongs to the operator who installed it. Give it back:${E_OFF}" >&2
    echo "${E_RED}         sudo chown -R <your-login>: ${REPO_DIR}${E_OFF}" >&2
    exit 1
  fi
  if id -u "${DASH_ACCOUNT}" >/dev/null 2>&1; then
    _shell="$(getent passwd "${DASH_ACCOUNT}" 2>/dev/null | cut -d: -f7 || true)"
    case "${_shell}" in
      /usr/sbin/nologin|/sbin/nologin|/bin/false|/usr/bin/false) ;;
      *)
        echo "${E_RED}error: an account called ${DASH_ACCOUNT} already exists, and it can log in (shell: ${_shell:-none}).${E_OFF}" >&2
        echo "${E_RED}       That is somebody's account, not one this installer made. Nothing was changed.${E_OFF}" >&2
        exit 1 ;;
    esac
  else
    _nologin=""
    for _c in /usr/sbin/nologin /sbin/nologin /bin/false /usr/bin/false; do
      [[ -x "$_c" ]] && { _nologin="$_c"; break; }
    done
    [[ -n "${_nologin}" ]] \
      || { echo "${E_RED}error: no nologin shell on this host, so an account that cannot log in cannot be made${E_OFF}" >&2; exit 1; }
    useradd --system --user-group --no-create-home --home-dir /nonexistent \
            --shell "${_nologin}" "${DASH_ACCOUNT}"
    echo "${S_GREEN}Created ${DASH_ACCOUNT}: a system account, no login, no home.${S_OFF}"
  fi
  # Asserted after creation, not assumed from it, and on every run, because
  # a later change by hand would undo the point quietly.
  #
  # Its identity first. Every check below asks by name, and a name is only
  # as good as the uid behind it: uid 0, or a uid another account shares
  # (stat would then name that account as the tree's owner, and the check
  # above would pass), would make this account somebody else.
  _uid="$(id -u "${DASH_ACCOUNT}" 2>/dev/null || true)"
  _sys_min="$(awk '$1=="SYS_UID_MIN"{print $2}' /etc/login.defs 2>/dev/null || true)"
  _sys_max="$(awk '$1=="SYS_UID_MAX"{print $2}' /etc/login.defs 2>/dev/null || true)"
  [[ "${_sys_min}" =~ ^[0-9]+$ ]] || _sys_min=100
  [[ "${_sys_max}" =~ ^[0-9]+$ ]] || _sys_max=999
  _back="$(getent passwd "${_uid:-x}" 2>/dev/null | cut -d: -f1 || true)"
  if [[ ! "${_uid}" =~ ^[0-9]+$ || "${_uid}" -eq 0 || "${_uid}" -lt "${_sys_min}" || "${_uid}" -gt "${_sys_max}" \
        || "${_back}" != "${DASH_ACCOUNT}" ]]; then
    echo "${E_RED}error: ${DASH_ACCOUNT} has uid ${_uid:-none}, which is not a system uid of its own${E_OFF}" >&2
    echo "${E_RED}       (system range ${_sys_min}-${_sys_max}; that uid names '${_back:-nobody}').${E_OFF}" >&2
    echo "${E_RED}       This installer makes that account itself. Nothing was changed.${E_OFF}" >&2
    exit 1
  fi
  _members="$(getent group "${DASH_ACCOUNT}" 2>/dev/null | cut -d: -f4 || true)"
  if [[ -n "${_members}" ]]; then
    echo "${E_RED}error: the ${DASH_ACCOUNT} group has other members (${_members}), so they could read what the dashboard keeps.${E_OFF}" >&2
    echo "${E_RED}       Take them out, then run this again:  sudo gpasswd -d <member> ${DASH_ACCOUNT}${E_OFF}" >&2
    exit 1
  fi
  # Each of these is root on this host by itself, and the account is only
  # worth having without them. The unit's own SupplementaryGroups= are checked
  # again once the unit is loaded, below, because systemd adds those at start
  # whatever /etc/group says.
  _groups=" $(id -nG "${DASH_ACCOUNT}" 2>/dev/null || true) "
  for _g in ${ROOT_GROUPS}; do
    if [[ "${_groups}" == *" ${_g} "* ]]; then
      echo "${E_RED}error: ${DASH_ACCOUNT} is in the '${_g}' group, which reaches root on this host by itself.${E_OFF}" >&2
      echo "${E_RED}       Take it out, then run this again:  sudo gpasswd -d ${DASH_ACCOUNT} ${_g}${E_OFF}" >&2
      exit 1
    fi
  done
  echo "${S_GREEN}The dashboard runs as ${DASH_ACCOUNT}; the install tree stays ${TREE_OWNER}'s.${S_OFF}"
fi
# Who owns the files this script puts in the TREE (the read token, the
# seeded configs): the tree's owner, read through the dashboard's group. On
# a kept host that is the account it always was, so nothing moves.
if (( LEGACY_ACCOUNT )); then FILE_OWNER="${RUN_USER}"; else FILE_OWNER="${TREE_OWNER}"; fi
# The dashboard's group, by number. The group called after the account when
# there is one (what the old lines named), its primary group otherwise.
RUN_UID="$(id -u "${RUN_USER}" 2>/dev/null || true)"
RUN_GID="$(getent group "${RUN_USER}" 2>/dev/null | cut -d: -f3 || true)"
if [[ -n "${RUN_GID}" ]]; then
  RUN_GROUP="${RUN_USER}"
else
  RUN_GID="$(id -g "${RUN_USER}" 2>/dev/null || true)"
  RUN_GROUP="$(id -gn "${RUN_USER}" 2>/dev/null || echo "${RUN_USER}")"
fi

# 1. Ensure data + log dirs exist, owned by the service user, and
#    locked to the owner. Not world-readable, which keeps a co-located user
#    or second service from listing/reading the DB and rotated logs. The DB
#    itself is squeezed to 0600 in step 6 once it exists.
#
#    data/ is the one directory in the tree that belongs to the dashboard's
#    account, so everything root does INSIDE it goes through state-file.py,
#    on a descriptor, never by name: the account can put a link at any name
#    in there, and `install -d`, `chown` and `chmod` all follow one. data/
#    itself sits in a directory the operator owns, so the account cannot swap
#    it, and naming it is safe.
#
#    0700 for the dashboard's own account (ADR 0024). A kept host keeps the
#    0750 it always had.
if (( LEGACY_ACCOUNT )); then DATA_MODE=0750; else DATA_MODE=0700; fi
install -d -o "${RUN_USER}" -g "${RUN_GROUP}" -m "${DATA_MODE}" "${DATA_DIR}"
python3 -I "${SCRIPT_DIR}/state-file.py" mkdir "${LOG_DIR}" "${RUN_UID}" "${RUN_GID}" 0750 --root "${DATA_DIR}"
# A data/ that came from somewhere else (an install over files an earlier
# uninstall kept, which were handed back to the operator then) is handed to
# the dashboard's account here, entry by entry. Only what is not already its
# own, and never through a link: own-many refuses a link and names it.
if (( ! LEGACY_ACCOUNT )) && [[ -n "${RUN_UID}" ]]; then
  DATA_OWN_RC=0
  find "${DATA_DIR}" -mindepth 1 ! -uid "${RUN_UID}" \( -type f -o -type d \) -print0 2>/dev/null \
    | python3 -I "${SCRIPT_DIR}/state-file.py" own-many "${RUN_UID}" "${RUN_GID}" "" --root "${DATA_DIR}" \
    || DATA_OWN_RC=$?
  if [[ "${DATA_OWN_RC}" -eq 3 ]]; then
    echo "${S_AMBER}Some entries in ${DATA_DIR} were not plain files or directories and were left as they are (above).${S_OFF}"
  elif [[ "${DATA_OWN_RC}" -ne 0 ]]; then
    echo "${E_AMBER}warning: ${DATA_DIR} could not be fully handed to ${RUN_USER} (above).${E_OFF}" >&2
  fi
fi

# 1b. The aggregator's curation surface (ADR 0017 phase 2). Only on a host
#     that has a fleet registry: the Advisor tab's Proposals inbox writes
#     promoted notes into knowledge-fleet/ and builds the signed bundle
#     under knowledge-bundles/, and both are in the unit's ReadWritePaths.
#
#     If the fleet corpus is already owned by a hardened Advisor ACCOUNT
#     (install-advisor-account.sh hands it over at 0750), the dashboard user
#     can read it and not write it — so the promote button would fail with a
#     permission error at the moment of the click. On a host where both
#     services curate the same corpus the directory is group-writable and
#     setgid, so whichever account writes a file, the other can still read
#     and replace it.
#
#     fc_apply is what puts it in that shape, including on a host that is in
#     neither arrangement: stock-node2 and validator1 were set up by hand and
#     ended up advisord:advisord with the dashboard's account in no group that
#     could write, which this script warned about for a month and did not fix
#     (#245). Warnings are kept for what it cannot repair; scripts/fleet-corpus-perms.sh
#     has the whole decision table.
if [[ -f "${REPO_DIR}/dashboard/config/fleet.yaml" ]]; then
  KNOW_FLEET="${REPO_DIR}/advisor/knowledge-fleet"
  KNOW_BUNDLES="${REPO_DIR}/advisor/knowledge-bundles"
  install -d -o "${RUN_USER}" -g "${RUN_USER}" -m 0750 "${KNOW_BUNDLES}"
  # `install -d` hands over the directory, never what is in it. An uninstall
  # --keep gives every file the dashboard's account owned back to the tree's
  # owner before it removes the account, so after the reinstall the push
  # counter (seq.json), the delivery record and the archived bundles were the
  # login's, 0640, and every Promote stopped at "seq.json is unreadable"
  # (#1237). They are handed back here the way data/ is: entry by entry, only
  # what is not already the account's, on descriptors, never through a link.
  # The directory is the account's, so it can put a link at any name in it.
  if (( ! LEGACY_ACCOUNT )) && [[ -n "${RUN_UID}" ]]; then
    KB_OWN_RC=0
    find "${KNOW_BUNDLES}" -mindepth 1 ! -uid "${RUN_UID}" \( -type f -o -type d \) -print0 2>/dev/null \
      | python3 -I "${SCRIPT_DIR}/state-file.py" own-many "${RUN_UID}" "${RUN_GID}" "" --root "${KNOW_BUNDLES}" \
      || KB_OWN_RC=$?
    if [[ "${KB_OWN_RC}" -eq 3 ]]; then
      echo "${S_AMBER}Some entries in ${KNOW_BUNDLES} were not plain files or directories and were left as they are (above).${S_OFF}"
    elif [[ "${KB_OWN_RC}" -ne 0 ]]; then
      echo "${E_AMBER}warning: ${KNOW_BUNDLES} could not be fully handed to ${RUN_USER} (above). Promote stops until it is.${E_OFF}" >&2
    fi
  fi
  # Created only when missing, and owned by the dashboard's account when it
  # is: `install -d` applies -o/-g/-m to a directory that already exists, so
  # naming an owner here unconditionally would take the corpus away from the
  # Advisor account that renames it, and naming a mode would strip the setgid
  # bit and the group write this same script granted on its last run.
  for d in "${KNOW_FLEET}" "${KNOW_FLEET}/base" "${KNOW_FLEET}/local"; do
    [[ -d "$d" ]] || install -d -o "${RUN_USER}" -g "${RUN_USER}" -m 0750 "$d"
  done
  # Every failure inside fc_apply prints what it could not do, including a
  # repair that started and stopped halfway, so a non-zero here is already on
  # the operator's screen. The install carries on: a corpus the dashboard
  # cannot write costs the Promote button, not the dashboard.
  #
  # The group the corpus is shared through is the one install-advisor-account.sh
  # named on this host, read from what it wrote (#794), never the Advisor's
  # own primary group: that is the group its root socket is opened to.
  FC_SHARED_GROUP=""
  if [[ -r "${SCRIPT_DIR}/advisor-owner-lib.sh" ]]; then
    # shellcheck source=scripts/advisor-owner-lib.sh
    . "${SCRIPT_DIR}/advisor-owner-lib.sh"
    FC_SHARED_GROUP="$(advisor_owner_shared_group "/etc/systemd/system/aperire-advisord${SUFFIX}.service" "${RUN_USER}" 2>/dev/null || true)"
  fi
  FC_SHARED_GROUP="$(fc_resolve_shared "$FC_SHARED_GROUP" "${REPO_DIR}/advisor/state" "${RUN_USER}")"
  fc_apply "${KNOW_FLEET}" "${RUN_USER}" || true
fi

# 2. Stop a bare tsx process left by a pre-systemd install. Only one that
#    systemd does NOT own: the same pattern matches the dashboard the unit is
#    running, and this line was killing it on every re-run of this installer,
#    with systemd starting it again a moment later. The manual update's own
#    restart question hid that; the socket apply's gate, which asserts the
#    main PID is untouched, did not (aperire4, 2026-09-10).
if systemctl is-active --quiet "${SERVICE_NAME}" 2>/dev/null; then
  : # the unit owns the dashboard; nothing here stops it
else
  pkill -f "tsx server.ts" 2>/dev/null || true
  sleep 1
fi

# 3. Env file with RELAY_TOKENS — generate a fresh token on first run only.
#    Root-owned 0640 so the service user can read it; nobody else can.
install -d -o root -g root -m 0755 "${ENV_DIR}"
if [[ ! -f "${ENV_FILE}" ]]; then
  TOKEN="$(openssl rand -hex 32)"
  umask 077
  cat > "${ENV_FILE}" <<EOF
# Aperire dashboard environment file.
# RELAY_TOKENS — comma-separated bearer tokens the /ingest endpoint accepts.
# Paste the same value into the relay's relay.conf \`auth_token\` field.
RELAY_TOKENS=${TOKEN}
EOF
  chown "root:${RUN_GROUP}" "${ENV_FILE}"
  chmod 0640 "${ENV_FILE}"
  echo ""
  echo "${S_AMBER}NEW relay token generated. Copy this into relay.conf auth_token:${S_OFF}"
  echo "  ${S_CYAN}${TOKEN}${S_OFF}"
  echo ""
else
  echo "${S_GREEN}Existing ${ENV_FILE} preserved (token unchanged).${S_OFF}"
fi

# 3a. The values that make this instance distinct from any other on the host.
# Written once, never overwritten — an operator who edits a port keeps it.
# Without these two an instance would listen on the same port as the first
# one (so the second service dies on bind) and open the same database (so two
# processes would write one node's history into one file).
ENV_KV=( "PORT=${APERIRE_PORT:-7800}" "APERIRE_DB_PATH=${DB_FILE}" \
         "ADVISOR_URL=http://127.0.0.1:${APERIRE_ADVISOR_PORT:-7810}" \
         "ADVISOR_TOKEN_PATH=${REPO_DIR}/advisor/state/approve.token" \
         "APERIRE_READ_TOKEN_PATH=${REPO_DIR}/advisor/state/read.token" \
         "APERIRE_ADVISOR_UNIT_PATH=/etc/systemd/system/aperire-advisord${SUFFIX}.service" )
# The node this dashboard reads, when something upstream measured it. The
# preflight (scripts/preflight.sh) finds the admin WebSocket port or asks for
# it, and install.sh hands the answer down in APERIRE_RIPPLED_URL. Written
# once like everything else in this list, so an operator who moved the port
# keeps their line. Nothing set means the loopback default in the dashboard
# itself, which is ws://127.0.0.1:6006 and is right on most hosts.
[[ -n "${APERIRE_RIPPLED_URL:-}" ]] && ENV_KV+=( "RIPPLED_URL=${APERIRE_RIPPLED_URL}" )
for kv in "${ENV_KV[@]}"; do
  key="${kv%%=*}"
  grep -qE "^[[:space:]]*${key}=" "${ENV_FILE}" || echo "${kv}" >> "${ENV_FILE}"
done
# 3a-bis. The role the installer was told (#808). Unlike the lines above this
# one is REPLACED when it differs, not kept: it is a fact about the install,
# not an operator's tuning, and a host re-installed under a new role must not
# keep answering to the old one. The server reads it to know a dashboard-role
# host has no node to wait for. Absent (a host installed before this existed,
# or this script run by hand) means no claim, and the server falls back to
# the evidence it always used.
if [[ -n "${APERIRE_INSTALL_ROLE:-}" ]]; then
  if [[ ! "${APERIRE_INSTALL_ROLE}" =~ ^[a-z-]+$ ]]; then
    echo "${E_RED}error: APERIRE_INSTALL_ROLE '${APERIRE_INSTALL_ROLE}' is not a role name${E_OFF}" >&2
    exit 2
  fi
  if grep -qE "^[[:space:]]*APERIRE_INSTALL_ROLE=" "${ENV_FILE}"; then
    sed -i -E "s|^[[:space:]]*APERIRE_INSTALL_ROLE=.*|APERIRE_INSTALL_ROLE=${APERIRE_INSTALL_ROLE}|" "${ENV_FILE}"
  else
    echo "APERIRE_INSTALL_ROLE=${APERIRE_INSTALL_ROLE}" >> "${ENV_FILE}"
  fi
fi
chown "root:${RUN_GROUP}" "${ENV_FILE}"; chmod 0640 "${ENV_FILE}"
if [[ -n "${INSTANCE}" ]]; then
  echo "instance '${INSTANCE}': unit ${SERVICE_NAME}, port ${APERIRE_PORT:-7800}, db ${DB_FILE}"
fi

# 3a-ter. Mint the read-surface token (ADR 0008).
#
# The dashboard's read API is the surface a fleet aggregator reads a peer
# through, and it authenticates every request against this file. No file, or a
# file too short to be a secret, and the surface is disabled — never open, which
# is the right default but only half a story: the line above writes the PATH,
# and until now nothing on this host wrote the FILE. The Advisor did, as a side
# effect of its own startup, so a host without the optional Advisor had a read
# surface that could not be switched on and could not join a fleet. The peer is
# supposed to be a normal install; this is what makes that true.
#
# Written once and never overwritten. The Advisor adopts an existing token
# rather than replacing it (ensureReadToken checks for a file of at least 32
# characters and returns early), so whichever of the two is installed first
# mints it and the other one uses it.
#
# 0640, owner-and-group, matching the token beside it: when the Advisor later
# moves onto its own account, install-advisor-account.sh hands this directory
# to that account with the shared service group, and the dashboard keeps
# reading through the group. Mode survives that handover untouched, and
# advisord's own start-up tightening leaves a 0640 file alone.
#
# One thing to know if you write a fleet registry by hand: advisord narrows
# every token_path named in fleet.yaml to 0600. Pointing a row at this host's
# own read.token would therefore close it to the dashboard, and the read
# surface would go quiet with the token still sitting right there. A row's
# token is the token of the peer it names — never this file.
#
# Every `|| true` below is load-bearing: this script runs under `set -e` and
# `pipefail`, so a grep that finds nothing or a file that is not there would
# otherwise end the install at the last moment, having done everything right.
# ── the install tree above advisor/state (#703) ──────────────────────
#
# Before anything below plants or re-owns a file in there, because every one
# of those runs through scripts/state-file.py and the helper refuses a chain
# whose directories an account other than root or the owner can write. A host
# in that state gets the refusal at the FIRST seal otherwise, which is hours
# later and three hops from the cause.
#
# Found on an aggregator: the install tree was 0775 owner:owner and the
# owner's group held the Advisor's own account, so the Advisor could rename
# a directory root walks through. Neither half is an installer's doing (the
# mode is umask 002, the membership was made by hand), so this repairs rather
# than assumes. Idempotent, and never fatal: it says what is left and the
# refusal names the same script.
if [[ -r "${SCRIPT_DIR}/state-ancestors-lib.sh" ]]; then
  # shellcheck source=scripts/state-ancestors-lib.sh
  . "${SCRIPT_DIR}/state-ancestors-lib.sh"
  # The helper root runs is the one beside this script, which is the checked
  # copy root staged when it is root, never the tree's (#952).
  STATE_ANCESTORS_TOOL="${SCRIPT_DIR}/state-file.py"
  echo "== The install tree above ${REPO_DIR}/advisor/state"
  state_ancestors_narrow "${REPO_DIR}" "${REPO_DIR}/advisor/state" || true
fi

READ_TOKEN_PATH="$(grep -E '^[[:space:]]*APERIRE_READ_TOKEN_PATH=' "${ENV_FILE}" | tail -1 | sed -E 's/^[^=]*=//' | tr -d '[:space:]' || true)"
READ_TOKEN_PATH="${READ_TOKEN_PATH:-${REPO_DIR}/advisor/state/read.token}"
READ_TOKEN_LEN=0
if [[ -f "${READ_TOKEN_PATH}" ]]; then
  # Through the helper (#703). This installer runs as root and the token sits
  # in a directory the Advisor's own account owns on a moved host: a redirect
  # there is root reading whatever that account pointed the name at, and the
  # LENGTH of that decides whether this run mints a fresh token over it.
  READ_TOKEN_LEN=$(python3 -I "$SCRIPT_DIR/state-file.py" read "${READ_TOKEN_PATH}" 2>/dev/null \
                   | tr -d '[:space:]' | wc -c || true)
fi
if (( READ_TOKEN_LEN >= 32 )); then
  echo "${S_GREEN}Read-surface token already present at ${READ_TOKEN_PATH} — left as is.${S_OFF}"
else
  # Only create the directory if it is not already there. Re-running this after
  # the Advisor has moved onto its own account must not take state/ back off
  # that account, which is what an unconditional chown would do.
  READ_TOKEN_DIR="$(dirname "${READ_TOKEN_PATH}")"
  # The tree's owner, not the dashboard's account: advisor/ is the tree, and
  # a directory the dashboard owned there is row 10 of ADR 0024 again. The
  # dashboard reads the token through its group.
  [[ -d "${READ_TOKEN_DIR}" ]] || install -d -o "${FILE_OWNER}" -g "${RUN_GROUP}" -m 0750 "${READ_TOKEN_DIR}"
  # Same generator the relay token above uses: 64 hex characters, comfortably
  # past the 32 both readers insist on, and no alphabet that a config file,
  # a URL or a shell will treat as punctuation.
  # Planted through scripts/state-file.py, not written by name (#703). This
  # is root minting a shared secret inside a directory the Advisor's own
  # account owns on a moved host: a redirect, a chown and a chmod each
  # re-resolve the name, and that account can put a link there between any
  # two of them. The helper does all three on one descriptor.
  #
  # Found by the sweep in scripts/test-state-file-shape.sh rather than by
  # reading, which is the point of widening it past the three installers.
  # The group the old line named was the one CALLED $RUN_USER, not whatever
  # happens to be that account's primary; kept, with the primary as the
  # fallback for a host where no such group exists.
  # An account that does not resolve leaves both halves alone, which is what
  # the `chown ... || true` this replaced did: the file still lands, at 0640,
  # owned by whoever wrote it, and the run does not die over an ownership it
  # could not have applied either way.
  READ_TOKEN_UID="$(id -u "${FILE_OWNER}" 2>/dev/null || true)"
  READ_TOKEN_GID="${RUN_GID}"
  [[ -n "$READ_TOKEN_UID" ]] || READ_TOKEN_GID=""
  openssl rand -hex 32 \
    | python3 -I "$SCRIPT_DIR/state-file.py" plant "${READ_TOKEN_PATH}" \
        "${READ_TOKEN_UID}" "${READ_TOKEN_GID}" 0640 --stdin
  echo "${S_GREEN}Minted read-surface token: ${READ_TOKEN_PATH} (0640 ${FILE_OWNER}:${RUN_GROUP}).${S_OFF}"
  echo "  The read API now answers on loopback with it — this host can join a fleet."
fi

# 3a-bis. Seed the operator-edited configs from their templates.
#
# authn.yaml and channels.yaml are not tracked in git: they name the host
# operators reach this dashboard at and the addresses alerts go to, which
# belong to whoever installed it. Without this the dashboard falls back to
# localhost defaults and says so only in a log line — and the first symptom
# is an enrollment link pointing at localhost on a host published elsewhere.
#
# rules.local.yaml is here for a different reason (ADR 0020). It is the file
# alert-rule changes go in, because rules.yaml is the set the product ships
# and every update replaces it. Seeded as comments only: an empty override
# file and no override file mean the same thing to the loader, and the
# comments are where an operator reads the shape without opening the docs.
# Seeded ONLY when absent, and never written again by anything.
for cfg in authn channels rules.local; do
  live="${REPO_DIR}/dashboard/config/${cfg}.yaml"
  tmpl="${live}.example"
  if [[ ! -f "$live" && -f "$tmpl" ]]; then
    install -o "${FILE_OWNER}" -g "${RUN_GROUP}" -m 0640 "$tmpl" "$live"
    if [[ "$cfg" == "rules.local" ]]; then
      echo "${S_GREEN}seeded ${live}. Alert-rule changes go there, not in rules.yaml.${S_OFF}"
    elif [[ "$cfg" == "authn" ]]; then
      # The template says localhost:7800 because that is the default port.
      # Copying it verbatim onto an install made with --port 7900 produced a
      # config claiming a port nothing was listening on, and WebAuthn compares
      # the browser's origin against exactly this value: expectedOrigin
      # mismatched and every enrollment failed, with nothing on the page
      # naming a port. Seed the port this install actually uses.
      #
      # Only the shipped localhost default is rewritten. Anything else in the
      # template is an operator's own choice and is left alone.
      sed -i "s|^public_url: http://localhost:7800\s*$|public_url: http://localhost:${APERIRE_PORT:-7800}|" "$live"
      echo "${S_AMBER}seeded ${live} from its template — edit it before enrolling operators:${S_OFF}"
      echo "  public_url and rp_id must name the host operators actually reach."
      echo "  public_url currently says http://localhost:${APERIRE_PORT:-7800} (this install's port)."
    else
      echo "${S_GREEN}seeded ${live} from its template.${S_OFF}"
    fi
  fi
done

# 3a-quater. dashboard/config stays the operator's directory (ADR 0024,
# amended 2026-10-05). The dashboard reads what is in it and writes nothing
# there; root's fleet broker writes its files through a pinned descriptor.
# So the dashboard's account must not be able to create, rename or remove an
# entry in it: owning it, or a group or other write bit, would let that
# account swap a file root then reads or writes. Repaired here on every run,
# on the new shape only; a kept host keeps what it had.
#
# The directory sits in dashboard/, which is the operator's, so naming it is
# safe: the account cannot replace the entry.
CONFIG_DIR_PATH="${REPO_DIR}/dashboard/config"
if (( ! LEGACY_ACCOUNT )) && [[ -d "${CONFIG_DIR_PATH}" && ! -L "${CONFIG_DIR_PATH}" ]]; then
  if [[ "$(stat -c '%U' "${CONFIG_DIR_PATH}" 2>/dev/null)" == "${RUN_USER}" ]]; then
    chown "${FILE_OWNER}" "${CONFIG_DIR_PATH}"
    echo "${S_AMBER}${CONFIG_DIR_PATH} was ${RUN_USER}'s; it is ${FILE_OWNER}'s again.${S_OFF}"
  fi
  _cfg_mode="$(stat -c '%a' "${CONFIG_DIR_PATH}" 2>/dev/null || echo 0)"
  if (( (8#${_cfg_mode} & 8#022) != 0 )); then
    chmod go-w "${CONFIG_DIR_PATH}"
    echo "${S_AMBER}${CONFIG_DIR_PATH} was ${_cfg_mode}; group and other write are off.${S_OFF}"
  fi
fi

# 3a-ter. digest.yaml, unlike the three files just seeded, is tracked in git
# rather than seeded from a `.example` template, so nothing above has ever
# put a mode on it. `git archive` (what a release build unpacks) reproduces
# the CHECKED-OUT working tree's own mode bits rather than a fixed 0644, so
# the mode a fresh install lands with has always depended on the umask of
# whatever machine built that release, not on anything this repository
# declares; on the box that builds releases today that is 0664, group-
# readable, world-readable, holding the digest cadence and the recipient
# addresses (#565). An update carries the previous install's copy across by
# `mv`, which preserves whatever mode it already had, so a host that got it
# wrong once keeps getting it wrong forever without this. Asserted on every
# run, fresh install or update, so neither path can leave it wider than its
# three neighbours.
DIGEST_CFG="${REPO_DIR}/dashboard/config/digest.yaml"
if [[ -f "$DIGEST_CFG" ]]; then
  chown "${FILE_OWNER}:${RUN_GROUP}" "$DIGEST_CFG" 2>/dev/null || true
  # Tighten, never loosen: an operator who deliberately locked this down
  # tighter than 0640 (0600, say) keeps that choice. Only a mode carrying a
  # bit outside 0640 (0664, 0644, world- or group-write, ...) gets corrected.
  # On the new shape (ADR 0024) the operator owns it and the dashboard reads
  # it through its group, so group read is the one bit added: 0600 there
  # would be a digest config the dashboard cannot open.
  _digest_mode="$(stat -c '%a' "$DIGEST_CFG" 2>/dev/null || echo 0)"
  if (( (8#$_digest_mode & ~8#0640 & 8#0777) != 0 )); then
    chmod 0640 "$DIGEST_CFG"
  fi
  (( LEGACY_ACCOUNT )) || chmod g+r "$DIGEST_CFG"
fi

# 3a-quinquies. Files the dashboard reads in the operator's directories, put
# back in the shape a fresh install leaves (ADR 0024, amended 2026-10-05), on
# every run on the new shape.
#
# The case this is for: an uninstall that keeps the tree hands everything the
# dashboard's account owned back to the operator, because the account itself
# is removed. The next install makes the account again, and every file
# below has come back as the operator's own, which the new account cannot
# read: the seeding above skips a file that exists, and the read token above
# is "left as is". Without this, a reinstall over kept files serves
# localhost for its public URL and drops its fleet link.
#
#   operator configs  the tree owner's, group the dashboard's, readable by it
#   fleet files       the dashboard's, as root's broker and pairing leave them
#                     (fleet-trust.yaml keeps group aperire-svc where the
#                     Advisor reads it through that group; a node's, which
#                     holds no private_key, is root's, as pairing leaves it)
#   read token        group the dashboard's, while no Advisor owns its state
#
# dashboard/config is the operator's directory, so these names cannot be
# swapped by the dashboard's account; -h and the link test are for a link the
# operator made, which this leaves alone rather than re-owning its target.
if (( ! LEGACY_ACCOUNT )); then
  for _cfg in authn channels rules.local metric-alerts; do
    _f="${REPO_DIR}/dashboard/config/${_cfg}.yaml"
    [[ -f "$_f" && ! -L "$_f" ]] || continue
    chown -h "${FILE_OWNER}:${RUN_GROUP}" "$_f" 2>/dev/null || true
    chmod g+r,g-wx,o-rwx "$_f" 2>/dev/null || true
  done
  for _cfg in fleet.yaml fleet-links.json fleet-trust.yaml fleet-link.json; do
    _f="${REPO_DIR}/dashboard/config/${_cfg}"
    [[ -f "$_f" && ! -L "$_f" ]] || continue
    # fleet-trust.yaml is only the account's while it holds the private_key
    # (an aggregator's, 0600). A node's peers-only file is root's, on the
    # group the Advisor shares, so the dashboard account cannot repin
    # peers.aggregator (#868). A file that root already owns is left as it is.
    #
    # A peers-only file some other account owns is made root's here, in the
    # shape pairing leaves it (#1187). An uninstall --keep hands it to the
    # tree's owner, and with no Advisor in this install nothing else runs the
    # split that would put it back: the dashboard account, in none of that
    # group, could not read the pin it dials the aggregator by. The group is
    # aperire-svc where the file is still on it and the dashboard is in it,
    # and the dashboard's own otherwise; the Advisor's account step regroups
    # it when one comes back.
    #
    # dashboard/config is the operator's directory, so any name in it can be
    # renamed over between one look and the next. The owner, the group, the
    # device and inode, and whether a private_key line is there are all read in
    # one no-follow open, and the re-own is held to that inode: a file renamed
    # onto the name after the look is refused and left as it is, where a
    # re-own by name would have given it to root. The key never reaches a
    # shell variable; awk sees it on the pipe and keeps a flag.
    if [[ "$_cfg" == fleet-trust.yaml ]]; then
      _tm="$(python3 -I "${SCRIPT_DIR}/state-file.py" read "$_f" --meta-ino --root "${REPO_DIR}/dashboard" \
             | awk 'NR == 1 { m = $0; next } /^private_key:/ { k = 1 } /^[^ \t#]/ { p = ($0 ~ /^peers:/) } p && /^[ \t]+aggregator:/ && a == "" { a = $2 } END { print m, k + 0, a }')" || _tm=""
      read -r _tu _tg _tmode _tdev _tino _tkey _tagg <<<"$_tm" || true
      if ! [[ "${_tu:-}" =~ ^[0-9]+$ && "${_tg:-}" =~ ^[0-9]+$ && "${_tdev:-}" =~ ^[0-9]+$ \
              && "${_tino:-}" =~ ^[0-9]+$ && "${_tkey:-}" =~ ^[01]$ ]]; then
        echo "${S_AMBER}${_f} was left as it was: it could not be read safely (the reason is above, if the helper gave one). Remove what it names, then run this again.${S_OFF}" >&2
        continue
      fi
      [[ "$_tu" == 0 ]] && continue
      if [[ "$_tkey" == 0 ]]; then
        _tgrp="${RUN_GROUP}"; _tgid="${RUN_GID}"
        _svc_gid="$(getent group aperire-svc 2>/dev/null | cut -d: -f3 || true)"
        _dgroups="$(id -nG "${RUN_USER}" 2>/dev/null | tr ' ' '\n' || true)"
        if [[ -n "${_svc_gid}" && "${_tg}" == "${_svc_gid}" && $'\n'"${_dgroups}"$'\n' == *$'\naperire-svc\n'* ]]; then
          _tgrp=aperire-svc; _tgid="${_svc_gid}"
        fi
        [[ "${_tagg:-}" =~ ^[A-Za-z0-9_-]{20,128}$ ]] || _tagg="(not readable as a key)"
        if [[ "${_tgid}" =~ ^[0-9]+$ ]] \
           && python3 -I "${SCRIPT_DIR}/state-file.py" own "$_f" 0 "${_tgid}" 0640 --root "${REPO_DIR}/dashboard" --expect "${_tdev}:${_tino}"; then
          echo "${S_GREEN}${_f} is root:${_tgrp} 0640 again, the pin a node dials its aggregator by. It pins ${_tagg}; check it against the aggregator's fleet key.${S_OFF}"
        else
          echo "${S_AMBER}${_f} was left as it was (the reason is above): it is not root's, and the dashboard account may not be able to read it. Remove what the reason names, then run this again.${S_OFF}" >&2
        fi
        continue
      fi
    fi
    _grp="${RUN_GROUP}"
    if [[ "$_cfg" == fleet-trust.yaml && "$(stat -c '%G' "$_f" 2>/dev/null)" == aperire-svc ]]; then _grp=aperire-svc; fi
    if [[ "$(stat -c '%U:%G' "$_f" 2>/dev/null)" != "${RUN_USER}:${_grp}" ]]; then
      chown -h "${RUN_USER}:${_grp}" "$_f" 2>/dev/null || true
      echo "${S_GREEN}${_f} is ${RUN_USER}:${_grp} again${S_OFF}"
    fi
  done
  # The read token, only while it is the tree owner's: once an Advisor has
  # its own account, that account owns advisor/state and its installer sets
  # the group (aperire-svc), and this leaves it alone.
  _tok_dir="$(dirname "${READ_TOKEN_PATH}")"
  if [[ -d "${_tok_dir}" && "$(stat -c '%U' "${_tok_dir}" 2>/dev/null)" == "${FILE_OWNER}" \
        && "$(stat -c '%G' "${_tok_dir}" 2>/dev/null)" != aperire-svc && -n "${RUN_GID}" ]]; then
    python3 -I "${SCRIPT_DIR}/state-file.py" own "${_tok_dir}" "" "${RUN_GID}" "" 2>/dev/null || true
    if [[ -f "${READ_TOKEN_PATH}" ]]; then
      python3 -I "${SCRIPT_DIR}/state-file.py" own "${READ_TOKEN_PATH}" "" "${RUN_GID}" 0640 2>/dev/null || true
    fi
  fi
  # An aggregator's fleet tokens, kept by an uninstall --keep (#824).
  #
  # Where aperire-svc is still here, the keep left them on it, and kept the
  # group so its id could not pass to anyone else. The dashboard this run made
  # again is not in it yet (the Advisor's installer adds it, and the Advisor
  # may never come back), so it joins it here, before its unit starts, and
  # reads them through it as it did before. Nothing else about the group or
  # the files changes.
  #
  # With no aperire-svc, the broker writes them root:<the dashboard's group>,
  # and the keep gives that group's kept files to root's group before it
  # deletes the group, so the dashboard made again could read none of them and
  # every peer read would fail. A host kept before that fix has them on the
  # old, dead gid instead. Either way they go back to the group the broker
  # would write them with now, owner and mode untouched, on descriptors: the
  # directory and the files directly in it.
  _ft="${ENV_DIR}/fleet-tokens"
  _svc="$(getent group aperire-svc 2>/dev/null || true)"
  if [[ -d "${_ft}" && ! -L "${_ft}" && -n "${_svc}" ]]; then
    _svc_gid="$(cut -d: -f3 <<<"${_svc}")"
    _svc_members=",$(cut -d: -f4 <<<"${_svc}"),"
    if [[ "$(stat -c '%g' "${_ft}" 2>/dev/null)" == "${_svc_gid}" && "${_svc_members}" != *",${RUN_USER},"* ]]; then
      # Adopted only when everyone already in it is an account an Aperire
      # unit here runs as (#1023 review, M1): every member reads what is on
      # it, and a login a dashboard ran as before ADR 0024 is not one.
      _allowed=" ${RUN_USER} "
      for _f in /etc/systemd/system/aperire-server*.service /etc/systemd/system/aperire-read*.service \
                /etc/systemd/system/aperire-advisord.service /etc/systemd/system/aperire-advisord-*.service; do
        [[ "${_f}" == *credcheck* ]] && continue   # the recovery unit runs as root
        [[ -f "${_f}" ]] || continue
        _u="$(awk -F= '/^[[:space:]]*User[[:space:]]*=/{v=$2; gsub(/[[:space:]]/,"",v)} END{print v}' "${_f}" 2>/dev/null || true)"
        [[ -n "${_u}" ]] && _allowed+="${_u} "
      done
      # The listed members, and every account whose PRIMARY group it is, which
      # the member list does not show: trusted-path-lib.sh's _tp_group_others,
      # loaded in a subshell (it only defines). Without the library nothing is
      # adopted.
      if [[ -r "${SCRIPT_DIR}/trusted-path-lib.sh" ]]; then
        # shellcheck source=scripts/trusted-path-lib.sh
        _primary="$( . "${SCRIPT_DIR}/trusted-path-lib.sh" && _tp_group_others "" "${_svc_gid}" )"
      else
        _primary="(could-not-read-${SCRIPT_DIR}/trusted-path-lib.sh)"
      fi
      _strangers=()
      for _m in $(tr ',' ' ' <<<"${_svc_members}") ${_primary}; do
        [[ "${_allowed}" == *" ${_m} "* || " ${_strangers[*]} " == *" ${_m} "* ]] || _strangers+=("${_m}")
      done
      if (( ${#_strangers[@]} )); then
        echo "${E_RED}error: ${_ft} is on aperire-svc, and that group lists ${_strangers[*]}, which no Aperire${E_OFF}" >&2
        echo "${E_RED}       install puts there. Every member reads the fleet's tokens, so ${RUN_USER} does not join it.${E_OFF}" >&2
        echo "${E_RED}       Take each one out, then run this again:${E_OFF}" >&2
        for _m in "${_strangers[@]}"; do echo "${E_RED}         sudo gpasswd -d ${_m} aperire-svc${E_OFF}" >&2; done
        exit 1
      fi
      if usermod -aG aperire-svc "${RUN_USER}"; then
        echo "${S_GREEN}${_ft} is on aperire-svc, kept by an uninstall: ${RUN_USER} joins it, so the dashboard reads the fleet's tokens${S_OFF}"
      else
        echo "${E_AMBER}warning: could not add ${RUN_USER} to aperire-svc; the dashboard cannot read the fleet's tokens in ${_ft}${E_OFF}" >&2
      fi
    fi
  elif [[ -d "${_ft}" && ! -L "${_ft}" && -n "${RUN_GID}" ]]; then
    _ftl=()
    mapfile -d '' _ftl < <(find "${_ft}" -maxdepth 1 \( -type d -o -type f \) ! -gid "${RUN_GID}" -print0 2>/dev/null)
    if (( ${#_ftl[@]} )); then
      if printf '%s\0' "${_ftl[@]}" | python3 -I "${SCRIPT_DIR}/state-file.py" own-many "" "${RUN_GID}" "" --root "${ENV_DIR}"; then
        echo "${S_GREEN}${_ft}: ${#_ftl[@]} kept entr$( (( ${#_ftl[@]} == 1 )) && echo y || echo ies) back on ${RUN_GROUP}, so the dashboard reads the fleet's tokens${S_OFF}"
      else
        echo "${E_AMBER}warning: some of ${_ft} could not be given back to ${RUN_GROUP} (named above); the dashboard cannot read those tokens${E_OFF}" >&2
      fi
    fi
  fi
fi

# 3b. Auto-detect rippled's config + NuDB data dir so the System tab's NuDB
#     size / growth / mount-free-days and online_delete rows populate. The
#     detection and the write live in scripts/configure-rippled-paths.sh, the
#     same program an operator runs by hand on a dashboard installed without
#     this step (a hand-made unit never had the paths, and the System tab
#     showed the store as dashes with nothing naming why). Only adds keys the
#     operator hasn't already set; runs before the restart so they take effect.
bash "${SCRIPT_DIR}/configure-rippled-paths.sh" --env-file "${ENV_FILE}" --quiet

# 4. Install unit file + logrotate config.
#
# These are templates, not files to copy. They used to be copied verbatim with
# this maintainer's user, repository path and Node location baked in, so on any
# other host the unit named a directory that does not exist and the service
# would not start — the operator's first experience of the dashboard being a
# unit file to hand-edit.
#
# Every placeholder is filled from something already known here: the account
# running the install, the repository this script sits in, and the Node that
# will actually run the server.
# The node is the one the operator installed: on a kept host that is the
# unit's own account, and on a fresh one it is whoever ran this install
# (SUDO_USER, or the tree's owner when there is none). aperire-dashboard has
# no shell and no home to look in; it is granted passage to that node below
# and proven able to run it. The
# documented dependency path is nvm, which lives under the user's home and is
# invisible to root's PATH — a fresh host that followed the docs to the letter
# failed exactly here. Resolution order: the user's own shell (covers nvm
# sourced from a profile), then the nvm install tree directly (Ubuntu's
# default .bashrc returns before nvm loads in non-interactive shells, so the
# first probe legitimately misses), then root's PATH as the last resort.
#
# Each probe may come back empty, and an empty answer must fall through to the
# next one rather than end the install (#320). `getent passwd` for an account
# with no entry exits 2, `find` on a home with no .nvm exits 1, and under
# `pipefail` that is the pipeline's status, and as the whole of an assignment it
# became the script's status, so `set -e` ended the install at the second
# probe, ten lines above the refusal that names what is missing. A host that
# followed the docs and installed Node as the operator, then ran this with
# sudo from a shell where nvm was not loaded, got no unit and no sentence.
if (( LEGACY_ACCOUNT )); then NODE_ACCOUNT="${RUN_USER}"; else NODE_ACCOUNT="${SUDO_USER:-${TREE_OWNER}}"; fi
NODE_PATH_USER="$(sudo -u "${NODE_ACCOUNT}" bash -lc 'command -v node' 2>/dev/null || true)"
if [[ -z "${NODE_PATH_USER}" ]]; then
  RUN_HOME="$(getent passwd "${NODE_ACCOUNT}" 2>/dev/null | cut -d: -f6 || true)"
  if [[ -n "${RUN_HOME}" && -d "${RUN_HOME}/.nvm/versions/node" ]]; then
    NODE_PATH_USER="$(find "${RUN_HOME}/.nvm/versions/node" -maxdepth 3 -path '*/bin/node' -type f 2>/dev/null | sort -V | tail -1 || true)"
  fi
fi
if [[ -n "${NODE_PATH_USER}" && -x "${NODE_PATH_USER}" ]]; then
  NODE_BIN="$(dirname "${NODE_PATH_USER}")"
else
  NODE_BIN="$(dirname "$(command -v node || true)")"
fi
if [[ -z "${NODE_BIN}" || ! -x "${NODE_BIN}/node" ]]; then
  echo "${E_RED}error: cannot find node for ${NODE_ACCOUNT} (looked in the user's shell,${E_OFF}" >&2
  echo "${E_RED}       ~/.nvm/versions/node/, and PATH); the unit needs its absolute location${E_OFF}" >&2
  exit 1
fi
if [[ ! -x "${REPO_DIR}/dashboard/node_modules/tsx/dist/cli.mjs" && \
      ! -f "${REPO_DIR}/dashboard/node_modules/tsx/dist/cli.mjs" ]]; then
  echo "${E_RED}error: ${REPO_DIR}/dashboard/node_modules/tsx not found — run npm install first${E_OFF}" >&2
  exit 1
fi
echo "Unit will run as ${RUN_USER}, from ${REPO_DIR}, using ${NODE_BIN}/node"

# Passage for the dashboard's account, and only passage. The tree sits under
# a home directory that is 0750 on a current Ubuntu, and so does the node nvm
# put there, so a separate account cannot reach either. Adding it to the
# operator's group would be the wrong fix: that reads everything in the home,
# the node config and its validator token among it. An ACL entry of `--x` on
# each directory it cannot already pass through is permission to walk past,
# not to list. The same shape the Advisor's account is given.
#
# Then read back as that account, because an ACL that was applied and a
# service that can start are two different facts: a tree unpacked under a
# umask of 077 passes every directory and still cannot be read.
if (( ! LEGACY_ACCOUNT )); then
  grant_passage() { # $1 = a directory the account must be able to reach
    local d="$1" chain=() i
    while [[ -n "$d" && "$d" != "/" ]]; do chain=("$d" "${chain[@]}"); d="$(dirname "$d")"; done
    for i in "${chain[@]}"; do
      runuser -u "${RUN_USER}" -- test -x "$i" 2>/dev/null && continue
      # -n: never recompute the mask. A recomputed mask is the union of every
      # named entry and the group, so adding ours could hand back a write some
      # other entry had masked off. With -n a mask that hides our --x leaves
      # the entry inert, which the read-back right after catches.
      if ! setfacl -n -m "u:${RUN_USER}:--x" "$i"; then
        echo "${E_RED}error: could not give ${RUN_USER} passage through ${i} (setfacl, from the acl package)${E_OFF}" >&2
        exit 1
      fi
      # Recorded for the uninstaller, which takes back exactly these.
      grep -qxF -- "$i" "${PASSAGE_RECORD}" 2>/dev/null || printf '%s\n' "$i" >> "${PASSAGE_RECORD}"
      if ! runuser -u "${RUN_USER}" -- test -x "$i" 2>/dev/null; then
        echo "${E_RED}error: ${RUN_USER} still cannot pass through ${i}: its access mask hides the entry.${E_OFF}" >&2
        echo "${E_RED}       Read it with:  getfacl -p ${i}   (the 'mask::' line needs x)${E_OFF}" >&2
        exit 1
      fi
      echo "${S_GREEN}${i}: ${RUN_USER} may pass through, and may not list it${S_OFF}"
    done
  }
  # Root's own record, beside the env file: not in the tree, which the
  # operator owns, and not readable as instructions by anything else.
  PASSAGE_RECORD="${ENV_DIR}/dashboard-passage"
  touch "${PASSAGE_RECORD}" && chmod 0644 "${PASSAGE_RECORD}"
  grant_passage "${REPO_DIR}"
  grant_passage "${NODE_BIN}"
  for _probe in "-x ${NODE_BIN}/node" "-r ${REPO_DIR}/dashboard/server.ts" \
                "-r ${REPO_DIR}/dashboard/node_modules/tsx/dist/cli.mjs"; do
    # shellcheck disable=SC2086  # "-x path": the test and its operand, split on purpose
    if ! runuser -u "${RUN_USER}" -- test ${_probe} 2>/dev/null; then
      case "${_probe%% *}" in -x) _verb="run" ;; *) _verb="read" ;; esac
      echo "${E_RED}error: ${RUN_USER} cannot ${_verb} ${_probe#* }, so the dashboard could not start.${E_OFF}" >&2
      echo "${E_RED}       The tree and the node must be readable by others (0755 directories,${E_OFF}" >&2
      echo "${E_RED}       0644 files), which is what an unpack under the usual umask leaves.${E_OFF}" >&2
      exit 1
    fi
  done
  echo "${S_GREEN}${RUN_USER} can reach the tree and run ${NODE_BIN}/node.${S_OFF}"
fi

fill() {
  sed -e "s#@REPO@#${REPO_DIR}#g" \
      -e "s#@RUN_USER@#${RUN_USER}#g" \
      -e "s#@ENV_FILE@#${ENV_FILE}#g" \
      -e "s#@NODE_BIN@#${NODE_BIN}#g" "$1"
}
# Refuse to install a unit that still has a placeholder in it: a systemd file
# with an unsubstituted token fails at start with an error that says nothing
# about why.
#
# The template is checked against the release's digests first and filled
# from the one read that was checked (ADR 0024): a unit's User= and ExecStart
# are root's to obey, so a template rewritten in the tree is refused rather
# than rendered.
# shellcheck source=scripts/release-digests-lib.sh
. "${SCRIPT_DIR}/release-digests-lib.sh"
install_filled() {
  local src=$1 dest=$2 tmp staged
  # Staged in a directory of its own, never straight into /tmp: the copy is
  # renamed into the directory it lands in, and a directory every account can
  # write is one the trusted-path check refuses to land anything in.
  staged=$(mktemp -d)
  if ! rd_stage "${REPO_DIR}" "scripts/$(basename "${src}")" "${staged}/t"; then
    rm -rf "${staged}"
    echo "${E_RED}error: ${dest} was not written: $(rd_refused_cause "${src}")${E_OFF}" >&2
    rd_note_refused "${dest}" "scripts/$(basename "${src}")"
    exit 1
  fi
  tmp=$(mktemp)
  fill "${staged}/t" > "${tmp}"
  rm -rf "${staged}"
  if grep -q '@[A-Z_]*@' "${tmp}"; then
    echo "${E_RED}error: ${src} still has unfilled placeholders:${E_OFF}" >&2
    grep -o '@[A-Z_]*@' "${tmp}" | sort -u >&2
    rm -f "${tmp}"
    exit 1
  fi
  install -o root -g root -m 0644 "${tmp}" "${dest}"
  rm -f "${tmp}"
}
# The logrotate config's `su ${RUN_USER} ${RUN_USER}` line only helps if every
# file it names is actually readable and writable by that account. A log file
# systemd itself created (StandardError=append: before this install ever ran,
# or a unit that briefly ran as root) is root-owned, and `copytruncate` run as
# an unprivileged user against a root-owned file fails silently under cron —
# logrotate logs the error to its own state file, not to this install's
# output, so a host can go months believing it rotates (#734). Re-own every
# log this instance already has on every run, the same "re-tighten on every
# re-run" rule the DB lock below follows, rather than only at first creation.
#
# NEVER `find -exec chown {} +` here (review finding, 2026-09-30): LOG_DIR is
# writable by ${RUN_USER}, find's `-exec` on a matched symlink follows it, and
# chown on a followed symlink retargets its OWNER — an account with write
# access to this directory could plant `x.log -> /etc/shadow` (or any
# root-owned file) between install runs and have this root-run chown that
# target to itself, the exact ADR 0024 escalation class. Routed through
# scripts/state-file.py's own-many (#703's tool for precisely this: adopting
# a directory's own files back to their account), which opens each entry
# O_NOFOLLOW on a directory descriptor, refuses anything that is not a plain
# regular file (a symlink, a device) without touching it, and refuses a file
# with more than one hard link rather than re-owning another name for the
# same inode. Only ever touches ${LOG_DIR} itself (maxdepth 1, matching the
# find call it replaces): the directory named --root is trusted the same way
# advisor/state is trusted by every other own-many call in this tree, because
# it is this run's own install directory, created by this installer at 0750
# ${RUN_USER}:${RUN_USER} above.
# --also-owner is that same account (#1174): ${DATA_DIR} above ${LOG_DIR} is the
# service account's own and sits inside the login's checkout, which the
# ancestor rule read as two unrelated accounts and refused every log for. The
# pair is named here, by the caller that built the layout, and only that one.
if [[ -d "${LOG_DIR}" ]]; then
  LOG_DIR_OWNER="$(stat -c '%U' "${LOG_DIR}" 2>/dev/null || true)"
  if [[ "${LOG_DIR_OWNER}" != "${RUN_USER}" && "${LOG_DIR_OWNER}" != "root" ]]; then
    echo "${S_AMBER}${LOG_DIR} is owned by '${LOG_DIR_OWNER}', neither ${RUN_USER} nor root — leaving its logs' ownership alone.${S_OFF}"
  else
    LOG_UID="$(id -u "${RUN_USER}" 2>/dev/null || true)"
    LOG_GID="$(getent group "${RUN_USER}" 2>/dev/null | cut -d: -f3 || true)"
    [[ -n "${LOG_GID}" ]] || LOG_GID="$(id -g "${RUN_USER}" 2>/dev/null || true)"
    if [[ -n "${LOG_UID}" ]]; then
      LOG_OWN_RC=0
      find "${LOG_DIR}" -maxdepth 1 -name '*.log*' -print0 2>/dev/null \
        | python3 -I "${SCRIPT_DIR}/state-file.py" own-many "${LOG_UID}" "${LOG_GID}" "" --root "${LOG_DIR}" --also-owner "${LOG_UID}" \
        || LOG_OWN_RC=$?
      if [[ "${LOG_OWN_RC}" -eq 3 ]]; then
        echo "${S_AMBER}One or more entries in ${LOG_DIR} were not a plain, single-link log file and were left untouched, or the path to it was refused as a whole. The state-file lines above say which.${S_OFF}"
      fi
    fi
  fi
fi

# 4c. The unit's shell opens both logs as the dashboard's account (see the
#     ExecStart comment in aperire-server.service). systemd used to open
#     them as root, so a log root had created (#734's server-err.log) was no
#     obstacle; now it is one, and the unit would not start. The re-own
#     above fixes that on every run; this proves it, as the account, before
#     the new unit is written, and stops here if it did not take, so a
#     refusal leaves the unit that was there.
for _log in "${LOG_DIR}/server-out.log" "${LOG_DIR}/server-err.log"; do
  if [[ -e "$_log" ]]; then _probe=(-w "$_log"); else _probe=(-w "${LOG_DIR}"); fi
  if ! runuser -u "${RUN_USER}" -- test "${_probe[@]}" 2>/dev/null; then
    echo "${E_RED}error: ${RUN_USER} cannot write ${_probe[1]}, so ${SERVICE_NAME} could not open its log and would not start.${E_OFF}" >&2
    echo "${E_RED}       The unit was not rewritten and nothing was restarted. Fix the owner, then run this again:${E_OFF}" >&2
    echo "${E_RED}         sudo stat -c '%U:%G %a' ${_probe[1]}${E_OFF}" >&2
    exit 1
  fi
done

install_filled "${SCRIPT_DIR}/aperire-server.service" "${SERVICE_FILE}"
install_filled "${SCRIPT_DIR}/aperire-logrotate.conf" "${LOGROTATE_FILE}"

# 4a. The host verifier, on a timer.
#
# scripts/verify-after-restart.sh is the check an operator runs after a reboot.
# Run only by hand it answers one question a year, and a host that quietly
# broke between reboots was never asked at all. On the timer it runs 30
# minutes after that timer starts, which is 30 minutes after every boot and 30
# minutes after this install, then once a day. Each run leaves
# data/verify-report.json, which the dashboard reads into verify_failed_checks
# and verify_report_age_s; a host that has this timer and no report at all
# reads as verify_report_missing. The three shipped rules in
# dashboard/config/rules.yaml turn those into an alert.
#
# One verifier per host, so these two are NOT instance-suffixed: a second
# dashboard instance re-installs the same pair of files rather than adding a
# second timer that checks the same box.
#
# Unprivileged. The unit runs as ${RUN_USER}, the account this install is for,
# because everything the verifier does is a read that account can already do.
VERIFY_TIMER=aperire-verify.timer
install_filled "${SCRIPT_DIR}/aperire-verify.service" /etc/systemd/system/aperire-verify.service
install_filled "${SCRIPT_DIR}/aperire-verify.timer"   /etc/systemd/system/${VERIFY_TIMER}

# 4b. Relocate a legacy in-source DB before the service starts. The DB used to
#     live at dashboard/aperire.db; it now lives in the data dir so the unit's
#     ReadWritePaths can exclude dashboard/. The service itself can no longer
#     move it (dashboard/ is read-only under ProtectSystem=strict), so do it
#     here with root while the service is stopped. Only when no DB already
#     exists at the new location and the operator hasn't set APERIRE_DB_PATH.
LEGACY_DB="${REPO_DIR}/dashboard/aperire.db"
if [[ -z "${APERIRE_DB_PATH:-}" && ! -f "${DB_FILE}" && -f "${LEGACY_DB}" ]]; then
  # Under APERIRE_NO_RESTART this is the one thing that still touches the
  # running service, because the alternative is worse: skip the move and the
  # next start opens an empty database at the new path while the operator's
  # history sits at the old one. So it stops, moves, and says plainly that
  # the dashboard is down until the restart question is answered.
  [[ "${APERIRE_NO_RESTART:-0}" == "1" ]] && \
    echo "${S_AMBER}Moving a legacy database needs the service stopped, so ${SERVICE_NAME} is stopped now.${S_OFF}"
  systemctl stop "${SERVICE_NAME}" 2>/dev/null || true
  for suffix in "" "-wal" "-shm"; do
    # -T: a name in data/ that is a link to a directory must be replaced, not
    # moved into. The owner and mode are set by step 6, on a descriptor.
    [[ -f "${LEGACY_DB}${suffix}" ]] && mv -T "${LEGACY_DB}${suffix}" "${DB_FILE}${suffix}"
  done
  echo "${S_GREEN}Relocated legacy ${LEGACY_DB} → ${DB_FILE} (history preserved).${S_OFF}"
fi

# 5. Reload, enable, restart
#
# The restart is the one step APERIRE_NO_RESTART suppresses, and it is the
# only one: the unit file is written and daemon-reload has run, so the new
# text is on disk and takes effect the moment somebody starts it. An update
# runs this way because a swap that restarted the dashboard by itself would
# be the silent restart the operator ruled out; the bootstrap asks, with the
# unit names in front of them, and restarts what they answer for.
systemctl daemon-reload
# The unit as systemd will start it, drop-ins included: a Group= or
# SupplementaryGroups= that names a root-equivalent group hands the account
# that group at start, whatever /etc/group says.
if (( ! LEGACY_ACCOUNT )); then
  _unit_groups=" $(systemctl show -p Group --value "${SERVICE_NAME}" 2>/dev/null || true) $(systemctl show -p SupplementaryGroups --value "${SERVICE_NAME}" 2>/dev/null || true) "
  for _g in ${ROOT_GROUPS}; do
    if [[ "${_unit_groups}" == *" ${_g} "* ]]; then
      echo "${E_RED}error: ${SERVICE_NAME} gives its account the '${_g}' group (a drop-in?), which reaches root by itself.${E_OFF}" >&2
      echo "${E_RED}       Read it with:  systemctl cat ${SERVICE_NAME}. Nothing was started.${E_OFF}" >&2
      exit 1
    fi
  done
fi
systemctl enable "${SERVICE_NAME}" >/dev/null
if [[ "${APERIRE_NO_RESTART:-0}" == "1" ]]; then
  echo "${S_AMBER}Not restarted: ${SERVICE_NAME} is still running the code it started with.${S_OFF}"
  echo "${S_DIM}  The unit is written and reloaded. Nothing below restarted it, so what${S_OFF}"
  echo "${S_DIM}  systemctl reports about it is the process that was already there.${S_OFF}"
else
  systemctl restart "${SERVICE_NAME}"
fi

# 5b. The node config this dashboard reads directly for four display values
#     (online_delete, advisory_delete, node_size and ledger_history on the
#     System tab; #462 P3-078). Nothing in this install path called the
#     closer at all: on the greenfield native order the node installer runs
#     first and closes the config before this unit exists, so its own call
#     finds no dashboard loaded and grants nothing for it, and the grant
#     only ever arrived afterwards as a side effect of the relay installer's
#     own later call. A host where the relay is declined, already holds its
#     entry, or already has all four ports pinned never got that side
#     effect, and the dashboard kept reading a file it had just failed to
#     be granted.
#
# Called here instead, once this unit is loaded (the closer resolves the
# dashboard account off LoadState=loaded, which daemon-reload plus enable
# above already gave it), the same non-fatal way install-aperire-relay.sh
# calls it, and reported through the same three exit codes: 0 closed or
# already closed, 1 refused or reverted cleanly (nothing half-applied), 2
# the revert itself did not take (may be left partially changed).
NODE_CONF_CANDIDATE=""
for f in "${ENV_DIR}/node-wrapper.conf" "${ENV_DIR}/node.conf"; do
  [[ -f "$f" ]] && { NODE_CONF_CANDIDATE="$f"; break; }
done
if [[ -z "$NODE_CONF_CANDIDATE" ]]; then
  echo "${S_GREEN}→ no node config recorded on this host yet; nothing here for the dashboard to be granted a read on${S_OFF}"
elif [[ ! -f "${SCRIPT_DIR}/close-node-config-exposure.sh" ]]; then
  echo "${E_AMBER}warning: ${SCRIPT_DIR}/close-node-config-exposure.sh is not in this checkout, so${E_OFF}" >&2
  echo "${E_AMBER}         the dashboard's own read of the node config was not granted.${E_OFF}" >&2
else
  echo "${S_DIM}  asking close-node-config-exposure.sh for the dashboard's named entry:${S_OFF}"
  # `if`, not `|| true`: a non-zero status in a compound command is the shape
  # `set -e` does not act on, and a dashboard install must not die over a
  # file mode. APERIRE_INSTANCE is passed through so the closer resolves
  # THIS unit (aperire-server${SUFFIX}) rather than the unsuffixed default.
  # The closer reads the node back through the wrapper. Root's own copy when
  # this host has one (ADR 0024), the sibling otherwise, which is the copy
  # root staged when install.sh runs this (#764).
  CLOSER_ENV=( "APERIRE_INSTANCE=${INSTANCE}" )
  CLOSER_WRAPPER="$(trusted_wrapper_path "${INSTANCE}")"
  if [[ -f "$CLOSER_WRAPPER" && ! -L "$CLOSER_WRAPPER" && "$(stat -c %u -- "$CLOSER_WRAPPER" 2>/dev/null)" == 0 ]]; then
    CLOSER_ENV+=( "APERIRE_CLOSER_WRAPPER=${CLOSER_WRAPPER}" )
  fi
  if DASH_CLOSE_OUT="$(env "${CLOSER_ENV[@]}" bash "${SCRIPT_DIR}/close-node-config-exposure.sh" --apply 2>&1)"; then
    DASH_CLOSE_RC=0
  else
    DASH_CLOSE_RC=$?
  fi
  printf '%s\n' "$DASH_CLOSE_OUT" | sed 's/^/     | /'
  case "$DASH_CLOSE_RC" in
    0) echo "${S_GREEN}→ node config closed; the dashboard's own account is granted where it needs to be${S_OFF}" ;;
    2) echo "${E_AMBER}warning: the closer's own revert did not take; the config may be left partially${E_OFF}" >&2
       echo "${E_AMBER}         changed. Check it by hand:  sudo getfacl -p \"\$(awk -F= '\$1==\"CONFIG_FILE\"{print \$2}' ${NODE_CONF_CANDIDATE})\"${E_OFF}" >&2 ;;
    *) echo "${E_AMBER}warning: the read was not granted; the reason is in the lines above. Nothing was${E_OFF}" >&2
       echo "${E_AMBER}         half-applied. Once resolved:  curl -fsSL https://get.aperire.one | bash -s -- --update --force${E_OFF}" >&2 ;;
  esac
fi

# 5c. What the dashboard reads outside the tree, read back as its own account
#     (ADR 0024). As the operator's login it could read whatever that login
#     could; as aperire-dashboard it reads what it was granted. The node
#     config is granted by the closer above. The node's store is measured
#     for the System tab. A miss here costs those values, not the dashboard,
#     so it warns with the path and the fix rather than failing the install.
if (( ! LEGACY_ACCOUNT )); then
  _cfg_path="$(grep -E '^[[:space:]]*RIPPLED_CFG_PATH=' "${ENV_FILE}" 2>/dev/null | tail -1 | sed -E 's/^[^=]*=//' | tr -d '"'"'"'[:space:]' || true)"
  _data_path="$(grep -E '^[[:space:]]*RIPPLED_DATA_PATH=' "${ENV_FILE}" 2>/dev/null | tail -1 | sed -E 's/^[^=]*=//' | tr -d '"'"'"'[:space:]' || true)"
  if [[ -n "${_cfg_path}" ]] && ! runuser -u "${RUN_USER}" -- test -r "${_cfg_path}" 2>/dev/null; then
    echo "${E_AMBER}warning: ${RUN_USER} cannot read ${_cfg_path}, so the System tab shows no online_delete,${E_OFF}" >&2
    echo "${E_AMBER}         advisory_delete, node_size or ledger_history. Grant it the read:${E_OFF}" >&2
    echo "${E_AMBER}           curl -fsSL https://get.aperire.one | bash -s -- --dir ${REPO_DIR} --run node-config-exposure --apply${E_OFF}" >&2
  fi
  # The store is measured by walking it (lib/store-size.ts), so it needs
  # read as well as passage. It holds ledger data, which is public.
  if [[ -n "${_data_path}" ]] && ! { runuser -u "${RUN_USER}" -- test -r "${_data_path}" 2>/dev/null \
                                     && runuser -u "${RUN_USER}" -- test -x "${_data_path}" 2>/dev/null; }; then
    echo "${E_AMBER}warning: ${RUN_USER} cannot list ${_data_path}, so the System tab shows no store size or growth.${E_OFF}" >&2
    echo "${E_AMBER}         To measure it, let it read the store (ledger data, no keys):${E_OFF}" >&2
    echo "${E_AMBER}           sudo setfacl -R -m u:${RUN_USER}:rX -m d:u:${RUN_USER}:rX ${_data_path}${E_OFF}" >&2
    echo "${E_AMBER}         and --x on each directory above it that ${RUN_USER} cannot pass through.${E_OFF}" >&2
  fi
fi

# 5a. The verifier timer is enabled AND started.
#
# It used to be enabled only, because the timer was OnBootSec= and starting it
# on a box that booted hours ago fires the verifier immediately, in the middle
# of an install, against a dashboard two seconds old. Sound, with an unsound
# consequence: the daily cadence only arms after a first run, and an absent
# report writes no metric, so a box that never rebooted stayed unverified
# forever and nothing said so (#143).
#
# The timer carries OnActiveSec=30min now, measured from its own start, so
# `--now` gives that first honest run half an hour from here, warm-up
# respected, with no reboot needed. The three-line explanation that used to
# live here lives in the unit beside the directive it explains.
#
# `|| true`, and this is the one line in this script that has it. Everything
# else here is the dashboard: if that will not start, the install has failed
# and should say so. The verifier is monitoring, it starts after the service
# is already up, and `--now` can fail in ways `enable` alone could not (a
# masked unit, a triggered unit that will not load). A box that has a working
# dashboard and a timer that would not start is not a failed install, it is an
# install with something to report, and the read-back below is what reports
# it. Without this the amber branch is unreachable: set -e would have taken
# the script out first.
systemctl enable --now "${VERIFY_TIMER}" >/dev/null || true
# Read back rather than claimed. This whole item exists because a timer that
# was never going to run looked exactly like one that was, so the install
# reports the moment systemd itself decided on, and says so when there is no
# moment to report.
# NextElapseUSecMonotonic is the moment systemd has scheduled, and it reads
# "infinity" on a timer that is not going to run: enabled but never started,
# masked, or a unit systemd does not know. Anything else is a real next run.
VERIFY_LEFT="$(systemctl show "${VERIFY_TIMER}" -p NextElapseUSecMonotonic --value 2>/dev/null || true)"
if [[ -n "${VERIFY_LEFT}" && "${VERIFY_LEFT}" != "infinity" && "${VERIFY_LEFT}" != "0" ]]; then
  echo "${S_GREEN}Host verifier: ${VERIFY_TIMER} enabled and started (first run ~30 min from now, then daily).${S_OFF}"
else
  echo "${S_AMBER}Host verifier: ${VERIFY_TIMER} is enabled but systemd reports no next run.${S_OFF}"
  echo "${S_DIM}  Check it:  systemctl list-timers --all ${VERIFY_TIMER}${S_OFF}"
fi
echo "${S_DIM}  Run it now, without waiting:  bash ${REPO_DIR}/scripts/verify-after-restart.sh${S_OFF}"

# The status dump is for somebody meeting this service for the first time, and
# the sleep exists only to let it settle before that read. On a host that is
# already running it, the unit's state was reported line by line above and the
# operator has `systemctl status` (#269).
#
# `|| true` because this is a dump, not a decision: `systemctl status` exits 3
# for a unit that is not running, which is the ordinary state after an install
# that was asked not to restart anything. Unguarded it ended the install right
# here, under `set -e`, so the database was never locked to 0600 and the
# firewall advisory was never printed, on the one path that prints neither a
# reason nor a failure (#320).
if [[ "${APERIRE_UPDATE:-0}" != "1" ]]; then
  sleep 2
  systemctl status "${SERVICE_NAME}" --no-pager --lines=5 || true
fi

# 6. Lock the sqlite DB to the service user (0600). The server also does
#    this on every open (db.ts), but enforce it here so the file is tight
#    even before the first start completes, and re-tighten on every
#    re-run. The DB now stores only hashes of session ids + magic-link
#    tokens, but a world-readable DB is needless exposure regardless.
#    Include the WAL/SHM sidecars when present.
#    Through state-file.py, on a descriptor: the database sits in data/,
#    which is the dashboard account's, and a chown or chmod by name there
#    follows whatever link that account put at the name.
DB_LOCK_RC=0
printf '%s\0' "${DB_FILE}" "${DB_FILE}-wal" "${DB_FILE}-shm" \
  | python3 -I "${SCRIPT_DIR}/state-file.py" own-many "${RUN_UID}" "${RUN_GID}" 0600 --root "$(dirname "${DB_FILE}")" \
  || DB_LOCK_RC=$?
if [[ "${DB_LOCK_RC}" -eq 0 ]]; then
  echo "${S_GREEN}Locked ${DB_FILE} (+ WAL/SHM) to 0600 ${RUN_USER}:${RUN_GROUP}.${S_OFF}"
else
  echo "${E_AMBER}warning: ${DB_FILE} was not locked to 0600 (above). The server tightens it on its next open.${E_OFF}" >&2
fi

# 7. Firewall check (non-fatal). A fresh Ubuntu host ships UFW inactive, which
#    would leave the dashboard host's inbound surface unfiltered. We do NOT
#    auto-enable ufw here — enabling a default-deny firewall over a live SSH
#    session can lock the operator out. Instead we detect and warn loudly with
#    the exact rules to apply. See docs/HARDENING-GUIDE.md (Firewall).
#    An advisory, and an advisory is given once. A host that has been serving
#    for months made its firewall decision on the install; re-printing thirty
#    lines of it under an update buries what the run actually changed (#269).
if [[ "${APERIRE_UPDATE:-0}" == "1" ]]; then
  :
elif command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
  echo "${S_GREEN}Firewall: ufw is active.${S_OFF}"
else
  cat >&2 <<'EOF'

  ============================================================
  NOTE: no active host firewall (ufw) detected on this host.
  ============================================================

  Advisory, not an error — the install has completed. The
  dashboard binds to loopback (127.0.0.1), so it is not network-
  exposed; the usual inbound surface here is SSH (and, on Shape B,
  the split, the relay's :7800). Harden to fit your environment:

  - Already behind a perimeter / hardware firewall (a UniFi
    gateway, pfSense, etc.) that drops unsolicited inbound? A host
    firewall is then defense-in-depth, and skipping it is a
    reasonable accepted risk. Caveat: a perimeter firewall does
    NOT stop LAN-lateral attacks — put this host on its own
    VLAN/segment and keep SSH key-only.

  - No perimeter firewall? Enable a default-deny host firewall:
      sudo ufw default deny incoming
      sudo ufw allow OpenSSH
      # Shape B only (relay pushes from a separate host):
      sudo ufw allow from <VAL-ip> to any port 7800 proto tcp
      sudo ufw enable
    Run it from a console or a second SSH session you can recover
    from — a wrong SSH rule can lock you out.

  - rippled in Docker on this host? Plain ufw can be bypassed by
    Docker's own iptables rules — use the DOCKER-USER chain (or
    ufw-docker) so published container ports are actually filtered.
  ============================================================

EOF
fi
