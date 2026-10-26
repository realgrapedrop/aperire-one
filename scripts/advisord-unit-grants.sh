#!/usr/bin/env bash
# Bring an existing Advisor's unit to the writable grants a fresh install
# gives it, and nothing else (#699).
#
#   sudo bash scripts/advisord-unit-grants.sh            converge, then say what it found
#   sudo bash scripts/advisord-unit-grants.sh --check    say what is missing, change nothing
#   sudo bash scripts/advisord-unit-grants.sh --instance node2
#                                                        aperire-advisord-node2 instead
#   bash scripts/advisord-unit-grants.sh --list          the grants it ensures, one per line
#
# ---- why this exists ------------------------------------------------
#
# The node wrapper records a verified container image, and keeps a release
# package for a rollback, under /var/lib/aperire. It writes there as root,
# through sudo, as a CHILD of aperire-advisord, and that unit carries
# ProtectSystem=strict. A mount namespace applies to children, root included,
# so on a unit that does not name the path the first official-image upgrade
# stops at the verify step on "Read-only file system". Both installers name it
# now. Nothing reached a host installed before they did: `--update` runs
# install.sh without --with-advisor, on purpose, and harden-advisord.sh
# refuses on a host whose Advisor has its own account, which is every host.
#
# ---- why an update may run it (#641) --------------------------------
#
# The update is reachable from a signed, aggregator-triggered job, and #641
# is the rule that such a path never reaches install-advisor-stack.sh or
# anything else that plants a reveal window. This is not that:
#
#   - it never runs an installer, and never touches the account, the sudo
#     rule, ExecStart=, or any secret
#   - what it adds is a constant in this file, from the release the update
#     already verified. Nothing on the update socket's payload names a path,
#     and nothing here reads one from it
#   - the update already edits this same unit (#541's start limit and
#     recovery hook, refresh_advisord_recovery in get-aperire.sh)
#   - it restarts nothing. The grant applies at the unit's next start
#
# ---- what "safe to name" means --------------------------------------
#
# The wrapper trusts a marker in /var/lib/aperire because root owns it and
# nobody else can write the directory it sits in. So the path is named only
# when it is a real directory, owned by the account running this (root, in
# production), and not writable by group or other, and so is every
# directory above it up to / (a sticky one like /tmp excepted). A symlink,
# another owner, or a group-writable mode anywhere on that chain is refused
# with the unit left as it was:
# naming a directory somebody else controls would make every marker in it
# worth exactly what that somebody wants.
#
# Absent, it is created root:root 0755 first, because ReadWritePaths= on a
# path that does not exist takes the unit down with 226/NAMESPACE.
#
# ---- how the unit is written ----------------------------------------
#
# In root's own shell, never through a file an unprivileged account made:
# the new text is staged by mktemp INSIDE the unit directory, which only
# root can write, and renamed over the unit. One line changes: the first
# ReadWritePaths= in [Service] gains the path at its end, or, when [Service]
# has none, one line naming it goes in right after the heading. Every other
# byte is kept, hand edits included, and so are the unit's mode and owner.
# A first ReadWritePaths= continued with a backslash is refused, not guessed.
#
# Success is read from what systemd loaded after a daemon-reload, never from
# the bytes on disk. A drop-in with an empty `ReadWritePaths=` resets the
# list, and that drop-in is named rather than papered over.
#
# Exit status: 0 converged (or no Advisor here), 3 refused (the directory is
# not safe to name, or the unit has no [Service]), 4 written but systemd
# still does not load it, 2 usage. --check exits 1 when something is missing.

# The table and the predicates live in the library beside this file, so
# the installer and update suites can hold a fresh unit to the same answer
# without running this program.
_grants_lib="$(dirname "${BASH_SOURCE[0]}")/advisord-unit-grants-lib.sh"
[[ -r "$_grants_lib" ]] \
  || { printf 'error: %s is missing; this program and it ship together\n' "$_grants_lib" >&2; exit 2; }
# shellcheck source=scripts/advisord-unit-grants-lib.sh
. "$_grants_lib"

set -euo pipefail

UNIT_DIR="${APERIRE_UNIT_DIR:-/etc/systemd/system}"
UNIT_NAME=aperire-advisord
UNIT="$UNIT_DIR/${UNIT_NAME}.service"
MODE=converge
QUIET_ABSENT=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --check) MODE=check; shift ;;
    --list)  MODE=list; shift ;;
    --quiet-absent) QUIET_ABSENT=1; shift ;;
    --instance)
      # A named instance's unit (ADR 0009). An update never reaches one, it
      # refuses instance hosts, so this is the only way theirs converge.
      # Never the recovery unit: aperire-advisord-credcheck<-instance> runs
      # as root on demand and has no business writing the wrapper's state.
      [[ $# -ge 2 && "$2" =~ ^[a-z0-9][a-z0-9-]{0,31}$ && "$2" != credcheck* ]] \
        || { printf 'error: --instance takes an instance name (lowercase letters, digits and dashes)\n' >&2; exit 2; }
      UNIT_NAME="aperire-advisord-$2"; UNIT="$UNIT_DIR/${UNIT_NAME}.service"; shift 2 ;;
    -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
    *) printf 'error: unknown argument %s\n' "$1" >&2; exit 2 ;;
  esac
done

# The wrapper's configuration, for the node's own directories (#767). The
# default instance reads the fixed path; a named one reads the file its own
# wrapper copy is keyed to, which is how install-node-wrapper.sh names it
# (node-wrapper-<first 12 of the sha256 of the wrapper's path>.conf), the
# wrapper taken from the unit's own ExecStart.
node_wrapper_conf() {
  if [[ -n "${APERIRE_NODE_WRAPPER_CONF:-}" ]]; then
    printf '%s' "$APERIRE_NODE_WRAPPER_CONF"; return 0
  fi
  if [[ "$UNIT_NAME" == aperire-advisord ]]; then
    printf '/etc/aperire/node-wrapper.conf'; return 0
  fi
  local w
  w="$(sed -n 's/^ExecStart=.*--wrapper=\([^ ]*\).*/\1/p' "$UNIT" 2>/dev/null | head -1)"
  [[ -n "$w" ]] || return 0
  printf '/etc/aperire/node-wrapper-%s.conf' "$(printf '%s' "$w" | sha256sum | cut -c1-12)"
}

if [[ "$MODE" == list ]]; then
  printf '%s\n' "${ADVISORD_RW_GRANTS[@]}"
  exit 0
fi

say()  { printf '   %s\n' "$*"; }
warn() { printf '   ! %s\n' "$*" >&2; }

if [[ ! -f "$UNIT" ]]; then
  [[ $QUIET_ABSENT -eq 1 ]] || say "no $UNIT here, so there is no Advisor to grant anything to"
  exit 0
fi

# An Advisor that reaches the wrapper through its root socket (ADR 0025)
# needs none of these. The grants exist because the wrapper used to run
# through sudo as a child of this unit, inside its mount namespace; behind the
# socket it runs in its own root service, and this unit keeps only its own
# three directories. Naming the wrapper's paths here again would widen it for
# nothing, so a socket unit is left as it is.
if grep -qE -- '--wrapper-socket=[^ ]+' "$UNIT"; then
  say "$UNIT reaches the wrapper through its root socket, so it needs no grant for the wrapper's paths"
  exit 0
fi

# The node's own directories, from a configuration root can trust: owned by
# the account running this (root) and writable by nobody else, the same bar
# as the grant directory. One that fails it is read by nothing here, said,
# and the fixed grant above still converges.
DEPLOY_GRANTS=()
NWCONF="$(node_wrapper_conf)"
if [[ -n "$NWCONF" && -f "$NWCONF" ]]; then
  _o="$(stat -c '%u' "$NWCONF")"; _m="$(stat -c '%a' "$NWCONF")"; _m="${_m: -2}"
  if [[ -L "$NWCONF" || "$_o" != "$(id -u)" || ! "${_m:0:1}" =~ ^[0145]$ || ! "${_m:1:1}" =~ ^[0145]$ ]]; then
    warn "$NWCONF is not root's alone, so the node's directories were not read from it"
  else
    mapfile -t DEPLOY_GRANTS < <(advisord_deploy_dirs "$NWCONF")
  fi
fi
ALL_GRANTS=("${ADVISORD_RW_GRANTS[@]}" "${DEPLOY_GRANTS[@]}")

# What systemd has loaded for the unit, as one space-separated string.
effective_rw() {
  systemctl show "$UNIT_NAME" -p ReadWritePaths --value 2>/dev/null || true
}

# The last drop-in that resets the list with an empty ReadWritePaths=. Named
# when the effective value still disagrees after the unit body is right.
resetting_dropin() {
  local d="${UNIT}.d" f last=""
  [[ -d "$d" ]] || return 0
  while IFS= read -r f; do
    grep -qE '^[[:space:]]*ReadWritePaths=[[:space:]]*$' "$f" 2>/dev/null && last="$f"
  done < <(find "$d" -maxdepth 1 -type f -name '*.conf' 2>/dev/null | sort)
  printf '%s' "$last"
}

# The ReadWritePaths entries written in the unit body itself, [Service] only.
file_rw() {
  awk '
    /^\[/ { in_svc = ($0 == "[Service]"); next }
    in_svc && /^ReadWritePaths=/ { sub(/^ReadWritePaths=/, ""); printf "%s ", $0 }
  ' "$UNIT"
}

# Refuse a directory that is not safe to name, per the header. Creates it
# when absent. Reads the answer off lstat, so a symlink is never followed.
# Every directory above the grant, up to /, has to be one nobody but root (or
# the account running this, which is root on a host) can rename things in: a
# writable ancestor lets another account swap the grant directory itself
# between this check and the wrapper's next write, which is the same
# substitution the leaf checks refuse. A sticky world-writable directory
# (/tmp) is safe for this purpose: only an entry's owner may rename it.
ancestors_safe() { # $1 = path
  local d="$1" owner mode me
  me="$(id -u)"
  while d="$(dirname "$d")"; do
    if [[ -L "$d" ]]; then
      warn "$d, above the grant, is a symlink, so the path the unit names is not the one checked here; it is not named"
      return 3
    fi
    owner="$(stat -c '%u' "$d")" || return 3
    mode="$(stat -c '%a' "$d")" || return 3
    if [[ "$owner" != 0 && "$owner" != "$me" ]]; then
      warn "$d, above the grant, is owned by uid $owner, who could swap the grant directory; it is not named"
      return 3
    fi
    # Four digits when a special bit is set; the first of four carries sticky.
    local sticky=0
    [[ ${#mode} -eq 4 && $(( ${mode:0:1} & 1 )) -eq 1 ]] && sticky=1
    mode="${mode: -2}"
    if [[ $sticky -eq 0 && ( ! "${mode:0:1}" =~ ^[0145]$ || ! "${mode:1:1}" =~ ^[0145]$ ) ]]; then
      warn "$d, above the grant, is writable by group or other, which could swap the grant directory; it is not named"
      return 3
    fi
    [[ "$d" == / ]] && break
  done
  return 0
}

ensure_grant_dir() { # $1 = path
  local p="$1" owner mode me
  me="$(id -u)"
  [[ "$p" == /* ]] || { warn "$p is not an absolute path; it is not named"; return 3; }
  ancestors_safe "$p" || return 3
  if [[ -L "$p" ]]; then
    warn "$p is a symlink. A marker behind it would be worth what its target's owner wants, so it is not named"
    return 3
  fi
  if [[ ! -e "$p" ]]; then
    if [[ "$MODE" == check ]]; then return 0; fi
    # mkdir, not install -d: one syscall that creates the directory with its
    # mode, and fails rather than following anything already at the name.
    if ! mkdir -m 0755 -- "$p" 2>/dev/null; then
      warn "could not create $p, and a unit naming a missing path will not start (226/NAMESPACE)"
      return 3
    fi
    # Read back the same way as a directory that was already here.
    [[ ! -L "$p" ]] || { warn "$p became a symlink while it was being created"; return 3; }
    say "created $p (root-owned, 0755)"
  fi
  [[ -d "$p" ]] || { warn "$p exists and is not a directory"; return 3; }
  owner="$(stat -c '%u' "$p")"
  mode="$(stat -c '%a' "$p")"
  if [[ "$owner" != "$me" ]]; then
    warn "$p is owned by uid $owner, not $me. The wrapper trusts what is in it because root owns it, so it is not named"
    return 3
  fi
  mode="${mode: -2}"
  if [[ ! "${mode:0:1}" =~ ^[0145]$ || ! "${mode:1:1}" =~ ^[0145]$ ]]; then
    warn "$p is writable by group or other (mode $(stat -c '%a' "$p")), so a marker in it proves nothing; it is not named"
    return 3
  fi
  return 0
}

# One line changes, per the header. Staged in the unit directory and renamed.
add_to_unit() { # $1 = path
  local p="$1" staged
  # A first ReadWritePaths= line continued onto the next with a trailing
  # backslash would have the path appended after the backslash, which joins
  # it to whatever the next line says. Not a shape any installer writes, so
  # it is refused rather than guessed at.
  if awk '/^\[/ { in_svc = ($0 == "[Service]"); next } in_svc && /^ReadWritePaths=/ && !seen { seen = 1; cont = /\\[[:space:]]*$/ } END { exit !cont }' "$UNIT"; then
    warn "$UNIT continues its ReadWritePaths= line with a backslash; add $p to it by hand, then re-run this"
    return 3
  fi
  if ! grep -qx '\[Service\]' "$UNIT"; then
    warn "$UNIT has no [Service] section to add ReadWritePaths= to; it is not a unit an installer wrote"
    return 3
  fi
  local has_rw=0
  if awk '/^\[/ { in_svc = ($0 == "[Service]"); next } in_svc && /^ReadWritePaths=/ { found = 1 } END { exit !found }' "$UNIT"; then
    has_rw=1
  fi
  staged="$(mktemp "${UNIT}.new-XXXXXX")"
  # has_rw: append to the first ReadWritePaths= in [Service]. Otherwise one
  # new line straight after the [Service] heading, where a reader looks.
  if ! awk -v add="$p" -v has_rw="$has_rw" '
      BEGIN { done = 0; in_svc = 0 }
      /^\[/ {
        in_svc = ($0 == "[Service]")
        print
        if (in_svc && !done && has_rw == 0) { print "ReadWritePaths=" add; done = 1 }
        next
      }
      in_svc && !done && /^ReadWritePaths=/ {
        sub(/[[:space:]]+$/, "")
        print $0 " " add
        done = 1
        next
      }
      { print }
    ' "$UNIT" > "$staged"; then
    rm -f "$staged"
    warn "could not stage the new $UNIT; it is unchanged"
    return 3
  fi
  # The unit's own mode and owner, whatever they were, not a mode this
  # program picks: an operator who tightened the file keeps it tight.
  chmod --reference="$UNIT" "$staged"
  chown --reference="$UNIT" "$staged" 2>/dev/null || true
  mv -f "$staged" "$UNIT"
  return 0
}

if [[ "$MODE" == check ]]; then
  missing=0
  eff="$(effective_rw)"
  for g in "${ALL_GRANTS[@]}"; do
    if advisord_rw_names "$eff" "$g"; then
      say "$UNIT_NAME can write $g"
    else
      say "$UNIT_NAME does NOT name $g in ReadWritePaths="
      missing=1
    fi
  done
  exit "$missing"
fi

rc=0
changed=0
for g in "${ALL_GRANTS[@]}"; do
  # The fixed grants are root's own directories and held to that. The
  # node's are the node's or the operator's, named exactly as a fresh
  # install names them: they exist, and that is the whole test.
  case " ${ADVISORD_RW_GRANTS[*]} " in
    *" $g "*) if ! ensure_grant_dir "$g"; then rc=3; continue; fi ;;
  esac
  if advisord_rw_names "$(file_rw)" "$g"; then
    continue
  fi
  if add_to_unit "$g"; then
    changed=1
    say "$UNIT: ReadWritePaths= now names $g"
  else
    rc=3
  fi
done

# Reload when the body changed, and also when the body was already right and
# systemd has not caught up with it, which is a unit edited by hand and never
# reloaded. Harmless when there is nothing new to read.
eff="$(effective_rw)"
need_reload=$changed
for g in "${ALL_GRANTS[@]}"; do
  advisord_rw_names "$eff" "$g" || need_reload=1
done
if [[ $need_reload -eq 1 ]]; then
  systemctl daemon-reload || warn "systemctl daemon-reload failed; systemd has not read the new unit yet"
  eff="$(effective_rw)"
fi

for g in "${ALL_GRANTS[@]}"; do
  if advisord_rw_names "$eff" "$g"; then
    if [[ $changed -eq 1 ]]; then
      say "$UNIT_NAME can write $g, as a fresh install can. Applies at its next start; nothing was restarted"
    else
      say "$UNIT_NAME already names $g, as a fresh install does"
    fi
  elif [[ $rc -eq 0 ]]; then
    winner="$(resetting_dropin)"
    if [[ -n "$winner" ]]; then
      warn "$UNIT names $g, but $winner resets ReadWritePaths= and wins, so systemd still does not load it"
    else
      warn "$UNIT names $g, but systemd still does not load it; something on this host overrides the unit"
    fi
    rc=4
  fi
done
exit "$rc"
