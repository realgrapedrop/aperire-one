#!/bin/bash
# Write rippled's config and NuDB paths into the dashboard's env file, so the
# System tab measures the node store (NuDB size, growth, mount free days) and
# reads online_delete from rippled.cfg.
#
#   sudo bash scripts/configure-rippled-paths.sh                 # /etc/aperire/aperire.env
#   sudo bash scripts/configure-rippled-paths.sh --env-file /etc/aperire/aperire-node2.env
#
# Idempotent. The installer runs this on every install; it is also the repair
# for a dashboard whose unit was made by hand and never had the paths, which
# the System tab reports as "NuDB Size: not set" (the lab aggregator, 2026-09-05: two
# nodes had no store samples at all, and nothing named why).
#
# The two keys are written between markers and the block is replaced in
# place on a re-run. A key an operator set by hand outside the block is
# kept, and this script then touches nothing. Detection that finds nothing
# leaves commented placeholders (no fake values are shown by the page), and a
# comment does not satisfy the guard, so a later run detects again.
#
# After a change the dashboard needs a restart to read the env file; the
# unit that reads this file is printed at the end.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[[ -r "${SCRIPT_DIR}/term-style.sh" ]] \
  || { echo "error: ${SCRIPT_DIR}/term-style.sh is missing from this checkout" >&2; exit 1; }
# shellcheck source=scripts/term-style.sh
. "${SCRIPT_DIR}/term-style.sh"
# The ACL-carrying helper this script shares with aperire-node-wrapper.sh's
# set-config, enable-advisory-delete.sh and migrate-node-nonroot.sh (#545).
[[ -r "${SCRIPT_DIR}/config-write-lib.sh" ]] \
  || { echo "error: ${SCRIPT_DIR}/config-write-lib.sh is missing from this checkout" >&2; exit 1; }
# shellcheck source=scripts/config-write-lib.sh
. "${SCRIPT_DIR}/config-write-lib.sh"

ENV_FILE="/etc/aperire/aperire.env"
QUIET=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --env-file) ENV_FILE="${2:?--env-file needs a path}"; shift 2 ;;
    --quiet)    QUIET=1; shift ;;
    -h|--help)  sed -n '2,20p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "${E_RED}error: unknown argument: $1${E_OFF}" >&2; exit 2 ;;
  esac
done

if [[ $EUID -ne 0 ]]; then
  echo "${E_RED}error: must run as root (sudo)${E_OFF}" >&2
  exit 1
fi
if [[ ! -f "${ENV_FILE}" ]]; then
  # The env file is what the unit reads. A new file nothing references would
  # configure nothing, so this is the installer's job, not a repair.
  echo "${E_RED}error: ${ENV_FILE} does not exist; run scripts/install-aperire-service.sh first${E_OFF}" >&2
  exit 1
fi

say() { [[ ${QUIET} -eq 1 ]] || echo "$@"; }

RIPPLED_BLOCK_BEGIN="# >>> aperire: rippled paths (rewritten by the installer) >>>"
RIPPLED_BLOCK_END="# <<< aperire: rippled paths <<<"

# The guard: a value already set is the operator's, wherever it sits, with one
# exception. The block below says "rewritten by the installer" in its own first
# line, and a value inside it was written by this script from what detection
# measured, so it is this script's to measure again.
#
# Without that exception a host whose node MOVED kept pointing at the node that
# was there before, for as long as it lived. Measured on a lab host during
# the #30 native lab: after a container node was replaced by the vendor's
# package, the System tab went on walking the container's old 26 GB directory
# while the node's real store was 6.7 GB somewhere else, and nothing anywhere
# said the number belonged to a store nothing was writing to.
#
# Detection answering nothing never blanks a value that is there: the existing
# in-block value is kept and said out loud. A docker that refused to answer is
# not evidence that a path is wrong (#142).
OLD_CFG="" OLD_DATA=""
if grep -qE '^RIPPLED_(CFG|DATA)_PATH=' "${ENV_FILE}"; then
  OUTSIDE="$(awk -v b="${RIPPLED_BLOCK_BEGIN}" -v e="${RIPPLED_BLOCK_END}" '
    $0 == b { inb = 1; next }
    inb && $0 == e { inb = 0; next }
    !inb && /^RIPPLED_(CFG|DATA)_PATH=/ { print }
  ' "${ENV_FILE}")"
  if [[ -n "${OUTSIDE}" ]]; then
    say "${S_GREEN}rippled paths already set in ${ENV_FILE}:${S_OFF}"
    grep -E '^RIPPLED_(CFG|DATA)_PATH=' "${ENV_FILE}" | sed 's/^/  /'
    say "${S_DIM}Edit the file to change them; this script does not overwrite a set value.${S_OFF}"
    exit 0
  fi
  OLD_CFG="$(sed -n 's/^RIPPLED_CFG_PATH=//p' "${ENV_FILE}" | head -1)"
  OLD_DATA="$(sed -n 's/^RIPPLED_DATA_PATH=//p' "${ENV_FILE}" | head -1)"
  say "${S_DIM}the paths in this file were written by this script; measuring again.${S_OFF}"
fi

# stderr is deliberately NOT discarded. The one thing detection writes there
# is a docker that refused to answer, and swallowing it here is how a host
# came to be described as a native install because nothing could ask (#142).
DETECT="$(bash "${SCRIPT_DIR}/detect-rippled-paths.sh" || true)"
DET_CFG="$(printf '%s\n' "${DETECT}"  | sed -n 's/^RIPPLED_CFG_PATH=//p')"
DET_DATA="$(printf '%s\n' "${DETECT}" | sed -n 's/^RIPPLED_DATA_PATH=//p')"

# Nothing measured does not mean nothing is there. Keep what this script wrote
# last time rather than replacing a working path with a placeholder.
if [[ -z "${DET_CFG}" && -n "${OLD_CFG}" ]]; then
  DET_CFG="${OLD_CFG}"
  say "${S_AMBER}detection did not resolve a config path; keeping ${OLD_CFG}${S_OFF}"
fi
if [[ -z "${DET_DATA}" && -n "${OLD_DATA}" ]]; then
  DET_DATA="${OLD_DATA}"
  say "${S_AMBER}detection did not resolve a data path; keeping ${OLD_DATA}${S_OFF}"
fi

ENV_WAS_SNAP="$(cwl_acl_snapshot "${ENV_FILE}")"
ENV_TMP="$(mktemp "${ENV_FILE}.XXXXXX")"
# Both markers, or neither: half a block is a hand-edited file, and dropping
# everything from an opening marker to the end of a file the service reads
# its token from is not a repair.
STRIP_BLOCK=0
if grep -qF -- "${RIPPLED_BLOCK_BEGIN}" "${ENV_FILE}" \
   && grep -qF -- "${RIPPLED_BLOCK_END}" "${ENV_FILE}"; then
  STRIP_BLOCK=1
fi
awk -v b="${RIPPLED_BLOCK_BEGIN}" -v e="${RIPPLED_BLOCK_END}" -v strip="${STRIP_BLOCK}" '
  strip && $0 == b { skip = 1; next }
  skip && $0 == e { skip = 0; next }
  skip { next }
  # Trailing blank lines are held back and only printed once something
  # follows them, so the separator below is not re-added on every run.
  /^[[:space:]]*$/ { blanks++; next }
  { for (; blanks > 0; blanks--) print ""; print }
' "${ENV_FILE}" > "${ENV_TMP}"
{
  echo ""
  echo "${RIPPLED_BLOCK_BEGIN}"
  echo "# rippled paths for the System tab (NuDB size/growth, online_delete)."
  echo "# Auto-detected by scripts/configure-rippled-paths.sh. Edit if rippled"
  echo "# moves or a value is wrong; leave commented to skip those metrics."
  [[ -n "${DET_CFG}"  ]] && echo "RIPPLED_CFG_PATH=${DET_CFG}"   || echo "# RIPPLED_CFG_PATH=/path/to/rippled.cfg"
  [[ -n "${DET_DATA}" ]] && echo "RIPPLED_DATA_PATH=${DET_DATA}" || echo "# RIPPLED_DATA_PATH=/path/to/rippled/db/nudb"
  echo "${RIPPLED_BLOCK_END}"
} >> "${ENV_TMP}"
# The env file keeps its owner, group, mode AND its ACL if it has one:
# mktemp made the temp file 0600 root:root, and the service account reads
# this file through its group (or, on a host with an ACL grant on it, a
# named entry a chown/chmod-only carry would silently drop, #545).
if ! cwl_carry_permissions "${ENV_FILE}" "${ENV_TMP}"; then
  rm -f "${ENV_TMP}"
  echo "${E_RED}error: could not carry ${ENV_FILE}'s owner, group, mode and ACL onto the rewrite; ${ENV_FILE} is untouched${E_OFF}" >&2
  exit 1
fi
mv -f "${ENV_TMP}" "${ENV_FILE}"

ENV_NOW_SNAP="$(cwl_acl_snapshot "${ENV_FILE}")"
if [[ "${ENV_NOW_SNAP}" != "${ENV_WAS_SNAP}" ]]; then
  echo "${E_RED}error: the rewrite changed ${ENV_FILE}'s $(cwl_snapshot_describe); the paths above were written, but its permissions moved. Check it by hand before restarting anything that reads it.${E_OFF}" >&2
  exit 1
fi

if [[ -n "${DET_DATA}" || -n "${DET_CFG}" ]]; then
  echo "${S_GREEN}Detected rippled paths, written to ${ENV_FILE}:${S_OFF}"
  [[ -n "${DET_CFG}"  ]] && echo "  RIPPLED_CFG_PATH=${DET_CFG}"
  [[ -n "${DET_DATA}" ]] && echo "  RIPPLED_DATA_PATH=${DET_DATA}"
else
  echo "${S_AMBER}Could not auto-detect rippled paths; left commented placeholders in ${ENV_FILE}.${S_OFF}"
  echo "${S_DIM}Fill them in by hand (the [node_db] path in rippled.cfg is the data path).${S_OFF}"
fi

# The unit (or drop-in) that reads this env file is the one to restart. Named
# from systemd's own files rather than guessed from the instance name, because
# a hand-made unit can read the file under any name.
if [[ ${QUIET} -eq 0 ]]; then
  UNITS="$(grep -lsE "^EnvironmentFile=-?${ENV_FILE}\$" /etc/systemd/system/*.service /etc/systemd/system/*.d/*.conf 2>/dev/null \
    | sed -E 's#^/etc/systemd/system/##; s#\.service(\.d/.*)?$##' | sort -u || true)"
  if [[ -n "${UNITS}" ]]; then
    for u in ${UNITS}; do
      echo "Restart to apply: ${S_CYAN}sudo systemctl restart ${u}${S_OFF}"
    done
  else
    echo "${S_AMBER}No systemd unit names ${ENV_FILE} in an EnvironmentFile= line; restart the dashboard that reads it.${S_OFF}"
  fi
fi
