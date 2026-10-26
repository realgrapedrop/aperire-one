#!/bin/bash
# Aperire — install the operator CLI to your user's local bin.
#
# Two symlinks, after which both work from any directory on this host
# without typing a full path. No root required:
#
#   aperire-auth   operator management (add / list / magic-link / revoke …)
#   aperire-one    the interactive menu that wraps every script in scripts/
#
# Usage:
#   bash scripts/install-aperire-cli.sh
#
# Idempotent — safe to re-run after `git pull` to refresh the symlinks.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# The palette the install path shares, so "done", "degraded" and "refused"
# look the same wherever they are printed. Every string in it is empty unless
# the stream is a terminal, so a captured or piped run stays byte-plain.
[[ -r "${SCRIPT_DIR}/term-style.sh" ]] \
  || { echo "error: ${SCRIPT_DIR}/term-style.sh is missing from this checkout" >&2; exit 1; }
# shellcheck source=scripts/term-style.sh
. "${SCRIPT_DIR}/term-style.sh"

SOURCE="${SCRIPT_DIR}/aperire-auth.sh"
BIN_DIR="${HOME}/.local/bin"
TARGET="${BIN_DIR}/aperire-auth"

if [[ ! -x "$SOURCE" ]]; then
  echo "${E_RED}error: source script missing or not executable: $SOURCE${E_OFF}" >&2
  exit 1
fi

mkdir -p "$BIN_DIR"
ln -sf "$SOURCE" "$TARGET"

echo "${S_GREEN}installed: $TARGET${S_OFF}"
echo "${S_DIM}         → $SOURCE${S_OFF}"

# The one operator entry point rides along: after this, the whole menu is
# just `aperire`, from any directory on this host.
# aperire-one, not a bare `aperire`: other software in the world already
# answers to aperire, and a front door must never shadow or be shadowed on
# PATH (operator ruling, 2026-08-20). One name, collision-proof.
ln -sf "${SCRIPT_DIR}/aperire.sh" "${BIN_DIR}/aperire-one"
# A previous install may have linked the bare name; retire it if it is ours.
if [[ -L "${BIN_DIR}/aperire" && "$(readlink "${BIN_DIR}/aperire")" == "${SCRIPT_DIR}/aperire.sh" ]]; then
  rm -f "${BIN_DIR}/aperire"
fi
echo "${S_GREEN}installed: ${BIN_DIR}/aperire-one${S_OFF}"
echo "${S_DIM}         → ${SCRIPT_DIR}/aperire.sh${S_OFF}"

# Most modern Ubuntu / macOS shells include ~/.local/bin in PATH via
# /etc/profile or ~/.profile. Warn if it's not there in the current
# shell so the operator knows to fix it before calling the command.
#
# Not on a host that already has the CLI. Everything below the first branch is
# guidance given at install time: the warning is about a shell that ended
# months ago (this one is sudo's), and "try: aperire-auth list" introduces a
# command the operator has been running since. The two `installed:` lines
# above are the read-back, and they are what an update needs to see. (#269)
if [[ "${APERIRE_UPDATE:-0}" == "1" ]]; then
  echo "${S_DIM}both links now point into this release; your PATH is untouched.${S_OFF}"
elif [[ ":$PATH:" != *":${BIN_DIR}:"* ]]; then
  echo
  echo "${S_AMBER}WARNING: ${BIN_DIR} is not in your current shell's PATH.${S_OFF}"
  echo
  echo "  Add this line to ~/.bashrc (or ~/.zshrc on macOS):"
  echo
  echo "      ${S_CYAN}export PATH=\"\$HOME/.local/bin:\$PATH\"${S_OFF}"
  echo
  echo "  Then reload your shell:  source ~/.bashrc"
  echo
  echo "  (Most modern Ubuntu setups already do this from /etc/profile."
  echo "   If it works in a NEW shell session but not this one, that's fine."
  echo "   Or just keep using the full path: $SOURCE)"
else
  echo
  if command -v aperire-auth >/dev/null 2>&1; then
    echo "${S_GREEN}verified: 'aperire-auth' is on PATH and resolves to $(command -v aperire-auth)${S_OFF}"
    echo
    echo "try:  ${S_CYAN}aperire-auth list${S_OFF}"
  else
    echo "${S_AMBER}note: ${BIN_DIR} is on PATH but the command is not yet visible in this shell.${S_OFF}"
    echo "${S_DIM}open a new terminal, or run: hash -r${S_OFF}"
  fi
fi
