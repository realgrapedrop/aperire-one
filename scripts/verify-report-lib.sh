#!/usr/bin/env bash
# The machine-readable half of a verifier run. Sourced, never executed.
#
# A verifier prints for a human. Once it runs on a timer nobody is reading
# the output, so the same run has to leave something a program can read,
# and the two must not be able to disagree. That is the whole design rule
# here: the reporters that print a line are the reporters that record it,
# one call, so a check cannot pass on screen and fail in the file.
#
# Usage, from a script whose ok/bad helpers already count pass/fail:
#
#   source "$(dirname "${BASH_SOURCE[0]}")/verify-report-lib.sh"
#   vr_begin "verify-after-restart"
#   chk service:aperire-relay        # names the NEXT ok/bad
#   ok "aperire-relay active"        # -> vr_record from inside ok()
#   vr_write "$REPO/data/verify-report.json"
#
# The file it writes:
#
#   { "ts": <epoch seconds>, "generated": "<ISO-8601 UTC>", "host": "...",
#     "script": "...", "passed": N, "failed": N,
#     "checks": [ { "name": "...", "ok": true|false, "detail": "..." } ] }
#
# `ts` is the run's own stamp and is what freshness is measured from, never
# the file's mtime, which a copy, a backup or a restore rewrites without any
# verifier having run.
#
# Written atomically: a temp file beside the destination, then rename. A
# reader either sees the previous report or the new one, never half of one.

# VR_CHECK below is read and written by the script that sources this file, so
# from in here it looks unused. File-wide, and placed before the first command
# so shellcheck reads it as one: the same assignment happens in two functions.
# shellcheck disable=SC2034

# Records, parallel arrays. Bash 4.2 has no arrays-of-struct and this needs
# no more than three columns.
_VR_NAME=()
_VR_OK=()
_VR_DETAIL=()
_VR_SCRIPT=""
# The name the next ok/bad will be recorded under. Cleared as it is consumed,
# so a check whose name was never set records as "unnamed", visible in the
# file and caught by the tests, rather than silently inheriting the name of
# the check before it.
VR_CHECK=""

# Start a run. Clears anything a previous run in the same shell recorded.
vr_begin() {
  _VR_SCRIPT="${1:-verify}"
  _VR_NAME=(); _VR_OK=(); _VR_DETAIL=()
  VR_CHECK=""
}

# Name the next check. Terse, stable, and not the message: the message carries
# observed values (accounts, ports, ledger numbers) and changes run to run,
# while the name is what a reader keys on.
chk() { VR_CHECK="$1"; }

# Record one check. ok is the string true or false.
vr_record() {
  local name=$1 okness=$2 detail=$3
  _VR_NAME+=("${name:-unnamed}")
  _VR_OK+=("$okness")
  _VR_DETAIL+=("$detail")
  VR_CHECK=""
}

# JSON string escaping, without a JSON tool. python3 is not a dependency of
# the verifier (it is used opportunistically, for one optional read), and a
# report that only exists on hosts with python3 is not a report.
_vr_esc() {
  local s=$1
  s=${s//\\/\\\\}
  s=${s//\"/\\\"}
  s=${s//$'\t'/\\t}
  s=${s//$'\r'/\\r}
  s=${s//$'\n'/\\n}
  # Anything else in the C0 range would be a raw control character inside a
  # JSON string, which is invalid. Dropped rather than escaped: nothing here
  # produces them on purpose, so their presence is noise, not content.
  s=${s//[[:cntrl:]]/}
  printf '%s' "$s"
}

# Write the report. Returns non-zero (and prints nothing) if it cannot, so the
# caller decides what to say. A verifier must not fail its own run because a
# side output could not be written.
vr_write() {
  local dest=$1 dir base tmp i pass=0 fail=0
  dir=$(dirname "$dest"); base=$(basename "$dest")
  [[ -d "$dir" && -w "$dir" ]] || return 1

  for i in "${!_VR_OK[@]}"; do
    if [[ "${_VR_OK[$i]}" == true ]]; then pass=$((pass + 1)); else fail=$((fail + 1)); fi
  done

  # Beside the destination, never in /tmp: rename is only atomic within one
  # filesystem, and a temp file elsewhere turns this into a copy a reader can
  # catch half-written.
  tmp="$dir/.$base.$$.tmp"
  {
    printf '{\n'
    printf '  "ts": %s,\n'          "$(date +%s)"
    printf '  "generated": "%s",\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf '  "host": "%s",\n'      "$(_vr_esc "$(hostname 2>/dev/null)")"
    printf '  "script": "%s",\n'    "$(_vr_esc "$_VR_SCRIPT")"
    printf '  "passed": %d,\n'      "$pass"
    printf '  "failed": %d,\n'      "$fail"
    printf '  "checks": ['
    for i in "${!_VR_NAME[@]}"; do
      [[ $i -eq 0 ]] && printf '\n' || printf ',\n'
      printf '    { "name": "%s", "ok": %s, "detail": "%s" }' \
        "$(_vr_esc "${_VR_NAME[$i]}")" "${_VR_OK[$i]}" "$(_vr_esc "${_VR_DETAIL[$i]}")"
    done
    [[ ${#_VR_NAME[@]} -gt 0 ]] && printf '\n  '
    printf ']\n}\n'
  } > "$tmp" 2>/dev/null || { rm -f "$tmp"; return 1; }

  # 0644 deliberately. It holds no secrets (service states, modes, account
  # names, everything in it is readable from systemctl by any local account)
  # and the dashboard that reads it does not always run as the account the
  # timer does. A mode that hides the report from the reader would look
  # exactly like a verifier that never ran, which is the failure this whole
  # file exists to make impossible.
  chmod 0644 "$tmp" 2>/dev/null || true
  mv -f "$tmp" "$dest" 2>/dev/null || { rm -f "$tmp"; return 1; }
  return 0
}
