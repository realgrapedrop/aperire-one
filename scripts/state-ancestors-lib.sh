#!/usr/bin/env bash
# The install tree above advisor/state belongs to root and to one account, and
# nobody else may write it. Sourced, never executed; scripts/fix-state-ancestors.sh
# is the standalone runner every refusal names.
#
# ---- what this is for (#703, found on koi) ---------------------------
#
# scripts/state-file.py walks to advisor/state one O_NOFOLLOW component at a
# time and refuses a component above it that root or the install owner is not
# the only writer of. One host failed that, and it was right to. The shape:
#
#   <install>                 <operator>:<operator>  0775
#   <install>/advisor         <operator>:<operator>  0775
#   <install>/advisor/state   aperire-advisor:<operator>  2750
#   and the operator's own group held the member aperire-advisor
#
# So the Advisor's own account could rename anything in the dashboard's tree,
# including advisor/ itself, which is a directory root walks through on its way
# to plant a token. The refusal is the rule working. This file is the repair.
#
# Two facts made that shape, and neither is an installer's doing. The 0775 is
# umask 002, which is what a default Ubuntu account gets and what a plain
# `git clone` or `mkdir` then leaves behind. The membership is not made
# anywhere in this tree: the only groups this tree ever puts the Advisor's
# account into are aperire-svc (install-advisor-account.sh, for the service
# token) and systemd-journal (install-node-wrapper.sh, read-only). That one
# was made by hand, or by a flow predating the dedicated account. Either way a
# host can be in this state, so the installers have to handle it.
#
# ---- what it changes, and what it deliberately does not --------------
#
# ONLY the group-write bit, and only on directories that are ancestors of the
# state directory AND at or below the install root. That is `<install>` and
# `<install>/advisor` on a normal tree: two chmods.
#
#   * advisor/state itself is never touched. It is the Advisor's own, setgid,
#     and the rule stops above it on purpose.
#   * advisor/knowledge-fleet is never touched. The corpus is group-writable
#     ON PURPOSE (scripts/fleet-corpus-perms.sh) so the dashboard can promote
#     into what the Advisor applies bundles to. It is not an ancestor of
#     advisor/state, so it is not on the path this walks.
#   * dashboard/config/fleet-trust.yaml is never touched. The Advisor reads it
#     (or, on an aggregator, fleet-trust.pub.yaml beside it, #868) through the
#     group on the FILE, which a directory's write bit has nothing to do with.
#   * anything ABOVE the install root is reported and left alone. The
#     operator's home is the host's, not this install's, and an installer that
#     started chmodding it would be worse than the problem it fixes.
#
# WHAT THIS COSTS: nothing any account still needs. The Advisor reaches its
# own directories by TRAVERSING these two, which needs the execute bit and not
# the write bit, and install-advisor-account.sh already grants that traverse
# by ACL on the home above rather than by group. The dashboard's account owns
# these directories and writes them as the owner.
#
# THE RULE ITSELF IS NOT COPIED HERE. `state-file.py ancestors` reports it and
# this acts on the report. An installer with its own idea of "is this group
# private" would sooner or later repair a shape the helper still refuses, and
# that drift is invisible until a seal fails on a host the installer has just
# called fixed.

# state_ancestors_tool: where the helper is.
#
# A caller names it in STATE_ANCESTORS_TOOL: the state-file.py beside the
# script it runs from (a copy root staged out of the release), or root's own
# /usr/local/sbin/aperire-state-file. Only a caller that is not root may fall
# back to the checkout's copy, because that is the operator running their own
# file. Root with nothing named gets a refusal, never the tree's helper: the
# login can change that file, and root would run it (#952, ADR 0024).
state_ancestors_tool() { # $1 = repo root
  if [[ -n "${STATE_ANCESTORS_TOOL:-}" ]]; then printf '%s' "$STATE_ANCESTORS_TOOL"; return 0; fi
  # Root unless id(1) says plainly otherwise: bash's $EUID comes from the
  # environment, and a root shell started with one must not fall through to
  # the tree's own copy (#1109).
  local u
  u="$(/usr/bin/id -u 2>/dev/null || true)"
  if ! [[ "$u" =~ ^[0-9]+$ && "$u" != 0 ]]; then
    echo "   not checked: running as root with no STATE_ANCESTORS_TOOL, and root does not run the" >&2
    echo "   state-file.py in the install tree. Run: curl -fsSL https://get.aperire.one | bash -s -- --update --force" >&2
    return 1
  fi
  printf '%s' "$1/scripts/state-file.py"
}

# state_ancestors_report <repo> <state-dir>
#
# Prints the helper's own lines, unchanged. Empty output means the layout
# passes. Never writes. Returns non-zero only when the helper cannot be run at
# all, which the caller reports rather than treating as "the layout is fine".
state_ancestors_report() {
  local repo="$1" state="$2" tool
  tool="$(state_ancestors_tool "$repo")" || return 1
  [[ -r "$tool" ]] || return 1
  command -v python3 >/dev/null 2>&1 || return 1
  python3 -I "$tool" ancestors "$state" --root "$state" 2>/dev/null
}

# state_ancestors_narrow <repo> <state-dir> [--dry-run]
#
# Takes group write off every offending ancestor at or below <repo>, reports
# anything it will not touch, and says what it did either way. Idempotent: a
# tree already narrow prints one line and changes nothing.
#
# Returns 0 when the layout passes afterwards, 1 when something is left that
# this cannot fix. Never fatal to the caller on its own: an installer that
# died here would leave a host worse off than the refusal it is preventing,
# and the refusal already names this script.
state_ancestors_narrow() {
  local repo="$1" state="$2" dry="${3:-}"
  # No running tally of what was left: the verdict below is MEASURED by
  # asking the helper again, so a chmod that silently did not happen
  # cannot be reported as work done.
  local kind path why modes tool changed=0 report

  # The refusal for root with no helper named says its own reason on stderr.
  tool="$(state_ancestors_tool "$repo")" || return 1
  if ! report="$(state_ancestors_report "$repo" "$state")"; then
    echo "   could not check the install tree's directory modes (no python3, or no" >&2
    echo "   state-file.py beside this script). Nothing was changed." >&2
    return 1
  fi
  if [[ -z "$report" ]]; then
    echo "   install tree above $state: only root and its owner can write it"
    return 0
  fi

  while IFS=$'\t' read -r kind path why; do
    [[ -n "$kind" ]] || continue
    # Ours to fix, or the host's to be told about. The test is on the PATH, so
    # a directory above the install root is never chmodded by an installer.
    if [[ "$path" != "$repo" && "$path" != "$repo"/* ]]; then
      echo "   !! $why" >&2
      echo "      That directory is above this install, so nothing here changes it." >&2
      continue
    fi
    case "$kind" in
      group-write|world-write)
        if [[ -n "$dry" ]]; then
          echo "   would take group and other write off $path"
          changed=1
          continue
        fi
        # Through the helper's `narrow`, not `chmod go-w "$path"`. That was
        # root resolving a name in a directory this very report has just
        # called renamable by an account which is not its owner, which is the
        # shape all of #703 exists to remove. `narrow` walks there one
        # O_NOFOLLOW component at a time and fchmods the descriptor. It
        # prints "<was> <now>" in octal, which is also what the row below
        # says, so the mode is reported from the call that changed it rather
        # than from a second lookup by name.
        if modes="$(python3 -I "$tool" narrow "$path" 2>&1)"; then
          echo "   $path  ${modes% *} -> ${modes#* }  (group and other write removed)"
          changed=1
        else
          echo "   !! could not change the mode of $path; run this as root" >&2
          echo "      $modes" >&2
        fi ;;
      *)
        # An owner split or an unwalkable component. A mode change does not
        # answer either, and guessing at one would be worse than saying so.
        echo "   !! $why" >&2 ;;
    esac
  done <<< "$report"

  if [[ -n "$dry" ]]; then
    (( changed )) && return 1
    return 0
  fi

  # Measured again, not assumed. A chmod that could not happen would otherwise
  # be reported as work done and the next seal would refuse anyway.
  report="$(state_ancestors_report "$repo" "$state")" || return 1
  if [[ -z "$report" ]]; then
    (( changed )) && echo "   the install tree is now writable only by root and its owner"
    return 0
  fi
  echo "   !! the install tree above $state is still writable by an account that is" >&2
  echo "      not its owner, so the Advisor's seals and its credential check will" >&2
  echo "      refuse on this host:" >&2
  while IFS=$'\t' read -r kind path why; do
    [[ -n "$why" ]] && echo "      $why" >&2
  done <<< "$report"
  return 1
}
