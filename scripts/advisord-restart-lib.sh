#!/usr/bin/env bash
# advisord-restart-lib.sh, one place for the two lines every intentional
# aperire-advisord restart needs (#541 P1-091). Sourced, never executed, by
# install-advisord.sh, install-advisor-account.sh and harden-advisord.sh.
#
#   . "$REPO/scripts/advisord-restart-lib.sh"
#   advisord_reset_and_restart "$UNIT_NAME"
#
# ---- why this exists --------------------------------------------------
#
# StartLimitIntervalSec=/StartLimitBurst= count every start attempt the unit
# has made, including ones a script asked for on purpose: the install +
# account-move + seal sequence alone can restart this unit several times in
# a normal run. Past the burst, `systemctl restart` answers "start request
# repeated too quickly and rate-limited" and starts nothing. A unit that
# was fine gets left in `failed` by a script that thinks it just restarted
# it, and the very next thing that script prints is a claim read back from a
# service that never came up. `systemctl reset-failed` before the restart
# clears that counter unconditionally; it is a no-op on a unit that was
# never near the limit, so calling it every time costs nothing on the
# common path and fixes the rare one.
#
# Two scripts that run FROM the tree source this (docker-ask-lib.sh's own
# sourcing pattern). aperire-seal-model-key.sh cannot: it is copied to
# /usr/local/sbin and runs with no tree beside it (install-model-key-sealer.sh
# says why), so it carries the same two lines as a local function of its
# own rather than sourcing this file: one helper, restated once where
# sourcing is not available, not six inline copies scattered through every
# script that has ever needed to restart this unit.

# advisord_reset_and_restart $1=unit name. Returns systemctl restart's own
# exit status, so a caller checking `if ! advisord_reset_and_restart ...`
# reads exactly what it read before this existed.
advisord_reset_and_restart() {
  local unit="$1"
  systemctl reset-failed "$unit" 2>/dev/null || true
  systemctl restart "$unit"
}

# advisord_unit_running $1=unit name. True when systemd reports it active. A
# unit that is activating, failed or unknown is not running, which is what
# the callers that ask want: only a service that is up is somebody's working
# install.
advisord_unit_running() {
  systemctl is-active --quiet "$1" 2>/dev/null
}
