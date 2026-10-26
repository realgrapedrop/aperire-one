#!/usr/bin/env bash
# Root never runs, sources or copies a file a service account can write
# (ADR 0024). Sourced, never executed.
#
# ---- the rule ------------------------------------------------------------
#
# A file is trusted when no service account can change what root reads at
# its path. That covers the file itself and every directory on the way to
# it, because a directory an account can write is one where it can rename
# the next entry away and put its own in the gap. "Can change" means any of:
#
#   * it owns the component (an owner can always chmod it back open)
#   * the group bits, through its primary group, a unit's Group= or
#     SupplementaryGroups=, or a group it is a member of
#   * a POSIX ACL entry, for the account or one of its groups, under the mask
#   * the bits for everyone else
#
# One exception, and it is the kernel's own: a directory with the sticky bit
# (/tmp) lets an account add its own entries but not move anybody else's. The
# owner rule on the next component already catches an entry the account put
# there itself.
#
# The service accounts are read from the installed units, never from names:
# the User=, Group= and SupplementaryGroups= of aperire-server*, aperire-read*,
# aperire-advisord*, aperire-relay*, and the native node unit, plus an xrpld or
# rippled account if the host has one, a container node's uid from its compose
# file, and the account running a dashboard that has no unit. Prod's Advisor is `aperire`, a peer's
# dashboard is aperire-read, and a constant would miss both. The operator's
# own login is not in the set unless a unit runs as it.
#
# ---- why it is descriptor-based -------------------------------------------
#
# The walk opens every component by name relative to the descriptor already
# open on its parent, O_NOFOLLOW, the same discipline as dirsafe.py and
# state-file.py. A symlink met on the way is followed by hand: its own owner
# is judged, then its target is walked the same way, so every directory that
# decides where the path lands has been judged. A copy reads the bytes from
# the descriptor that was judged, and writes them beside the destination
# through a descriptor on the destination directory, then renames. Nothing is
# ever looked up by its path string a second time, so there is no window
# between "trusted" and "read" for a rename to land in. The release's sha256
# is checked on those same bytes, before anything is written (#765): the
# two checks are one read, not two reads of one path.
#
# ---- before a host has moved the dashboard off the login -----------------
#
# On prod and every lab box today the dashboard runs as the operator's login,
# which also owns the install tree. Every file in the tree fails the rule for
# that account. Refusing there would block the very update that brings the
# migration, so exactly that one state is let through with a warning: every
# finding belongs to one account, that account runs the dashboard, it has a
# login shell, and it owns the install tree. Anything else, the Advisor's
# account in the owner's group, a nologin dashboard account, a relay or node
# account, still refuses. ADR 0024 lane 6b (#864) turns the warning into a
# refusal once prod has moved.
#
# "Runs the dashboard" is one of two things. The User= of a dashboard unit
# (aperire-server*, aperire-read*). Or, on a host with no dashboard unit at
# all (a pm2 install, or one started by hand), a process of that account
# whose working directory is <tree>/dashboard and whose command line names
# server.ts. No known host is in this state today (the lab aggregator runs
# aperire-server.service), but a dashboard that were judged by the unit rule
# alone would flip every root copy on such a host from a warning to a
# refusal. The tree's owner is never taken for the dashboard's
# account just because no unit exists: a process has to be seen.
#
# ---- an account that can write anything ---------------------------------
#
# A service account in a group that is root on the host by itself (docker,
# lxd, incus-admin, libvirt, microk8s, disk), or whose unit hands it a capability that bypasses file
# permissions (AmbientCapabilities= with cap_dac_override, cap_fowner,
# cap_chown and the like), can write every path whatever its mode says. For
# such an account no path is trusted, so every check refuses with that as its
# finding. The pre-migration login is the one exception, as above, and only
# until lane 6.
#
# ---- what it does not cover yet -----------------------------------------
#
# A container node's uid comes from the compose file's `user:` line (found
# through the wrapper's own configuration), and a dashboard with no unit is
# found by the process running it. Both are in the set. What still is not:
# a container user named rather than numbered (a name inside the container is
# not a host uid), a unitless dashboard that is not running when the check
# is made (nothing positively shows whose it is), nor ACL models other than
# POSIX.1e (an NFSv4 ACL is not read), or file capabilities on a program a
# service account can run. The destination's chain is held to the same rule
# as the source, never to the tolerance above.
#
# ---- interface ------------------------------------------------------------
#
#   trusted_path_accounts [TREE]     fill TP_ACCOUNTS from the units, the
#                                    compose file's user: and, given the
#                                    tree, a unitless dashboard's process;
#                                    1 if systemd will not answer (after
#                                    five tries), and TP_ACCOUNTS_FAILED
#                                    names the call that gave up
#   trusted_path_check PATH [TREE]   judge one file; prints findings;
#                                    0 clean, 3 tolerated, 2 refused, 1 fault
#   trusted_path_copy SRC DESTDIR NAME MODE TREE WANT [--strict]
#                                    judge SRC and DESTDIR, read SRC once,
#                                    compare its sha256 with WANT, copy
#                                    root-owned; 0 clean, 3 tolerated, 2
#                                    refused, 4 not the release's bytes, 1
#                                    could not check, 5 could not write, 6
#                                    the account check could not run.
#                                    Called by rd_stage only: every root copy
#                                    goes through rd_install or rd_stage
#   trusted_place_node_wrapper TREE INSTANCE
#                                    the wrapper and the two libraries it
#                                    loads, into the root-owned locations,
#                                    each through rd_install
#   tp_lib_text                      the copy and what it needs, as text for
#                                    a root shell (rd_lib_text carries it)
#   trusted_update_node_wrapper TREE CONF
#                                    what an update and --refresh run: every
#                                    instance placed, its unit pointed at the
#                                    copy and the socket, and the sudo rule an
#                                    older release wrote removed (ADR 0025)
#   trusted_write_socket_units INSTANCE ACCOUNT
#                                    the Advisor's root socket and its broker
#                                    service, bound to that one account
#   trusted_convert_advisor_unit INSTANCE
#                                    an existing Advisor unit, onto the socket
#                                    and the full sandbox, in place
#
# The directories are variables only so the tests can point them somewhere
# harmless: APERIRE_SBIN_DIR, APERIRE_LIB_DIR, APERIRE_SUDOERS_DIR,
# APERIRE_UNIT_DIR, APERIRE_PROC_DIR, APERIRE_CONF_DIR and APERIRE_RUN_DIR.

TP_SBIN_DIR="${APERIRE_SBIN_DIR:-/usr/local/sbin}"
TP_LIB_DIR="${APERIRE_LIB_DIR:-/usr/local/lib/aperire}"
TP_SUDOERS_DIR="${APERIRE_SUDOERS_DIR:-/etc/sudoers.d}"
TP_UNIT_DIR="${APERIRE_UNIT_DIR:-/etc/systemd/system}"
TP_PROC_DIR="${APERIRE_PROC_DIR:-/proc}"
# Where root's own configuration lives. Read for a container node's compose
# file; the functions that read it default to /etc/aperire, so the text a
# root shell is handed takes no override from the environment.
TP_CONF_DIR="${APERIRE_CONF_DIR:-/etc/aperire}"

# An instance name, the same rule install-advisord.sh holds it to. It ends up
# in a path under /usr/local/sbin, /etc/sudoers.d and /etc/systemd/system.
trusted_valid_instance() { # $1 = instance ("" is the default and valid)
  local LC_ALL=C   # [a-z] follows the locale: under UTF-8 it matches é
  [[ -z "$1" || "$1" =~ ^[a-z0-9][a-z0-9-]{0,30}$ ]]
}

# The installed name of an instance's wrapper. The wrapper keys its own
# per-instance configuration on this path, so everything that needs to find
# that configuration asks here rather than spelling the name again.
trusted_wrapper_path() { # $1 = instance ("" for the default)
  printf '%s/aperire-node-wrapper%s' "$TP_SBIN_DIR" "${1:+-$1}"
}

# The configuration an instance's wrapper reads: the default path for the
# default instance, and one keyed to the wrapper's own resolved path for any
# other. The same derivation the wrapper makes at its top.
trusted_wrapper_conf() { # $1 = instance, $2 = the default conf path
  if [[ -z "$1" ]]; then printf '%s' "$2"; return 0; fi
  local w
  w="$(realpath -m "$(trusted_wrapper_path "$1")")"
  printf '%s/node-wrapper-%s.conf' "$(dirname "$2")" "$(printf '%s' "$w" | sha256sum | cut -c1-12)"
}

# >>> trusted path >>>
# The check itself: the account set, the walk and the copy. This block is
# copied byte for byte into scripts/get-aperire.sh, so the bootstrap never
# takes the check out of the tree it is about to judge (#877 review, M1).
# scripts/test-trusted-path-lib.sh fails if the two drift.
# Groups that are root on the host by themselves, and capabilities that
# bypass file permissions. An account holding either can write any path, so
# no path is trusted while one does (#756 review, L1).
TP_ROOT_GROUPS=(docker lxd incus-admin libvirt microk8s disk)
TP_ROOT_CAPS=(cap_dac_override cap_fowner cap_chown cap_setuid cap_setgid cap_sys_admin cap_sys_module cap_sys_rawio)

# The account set, read once and held for one batch of copies (#764). Staging
# a release's scripts for root is a hundred copies in one root shell, and
# reading every unit for each one costs about half a second a file. Always 0
# when this block is loaded, and in the text tp_lib_text hands a root shell,
# so nothing in the environment can switch the read off: only
# trusted_path_hold_accounts sets it, in the one shell making the batch, and
# trusted_path_release_accounts puts it back.
TP_ACCOUNTS_HELD=0

# A login is an account with a passwd entry whose shell lets it log in. One
# with no entry at all is not proven to be anything, so it is not one.
_tp_is_login() { # $1 = a user name or uid
  local entry shell
  entry="$(getent passwd "$1" 2>/dev/null | head -1)"
  [[ -n "$entry" ]] || return 1
  shell="${entry##*:}"
  case "$shell" in
    */nologin|*/false|*/sync) return 1 ;;
  esac
  return 0
}

_tp_gid() { # $1 = a group name or number
  if [[ "$1" =~ ^[0-9]+$ ]]; then printf '%s' "$1"; return 0; fi
  getent group "$1" 2>/dev/null | cut -d: -f3
}

# systemctl, asked again while systemd is busy. A daemon-reload makes systemd
# fail a call for a moment (13 reloads in 46 s through one install, #1089),
# and that is not "no service accounts". Five tries, a second apart, then it
# is a fault and the caller refuses. The wait is a constant: no variable in
# the environment changes it (the suites put a `sleep` that does not wait on
# PATH, as they do for systemctl). The answer is left in _TP_SC, not printed:
# a $( ) here would lose TP_ACCOUNTS_FAILED, the call that gave up, with the
# subshell.
_tp_systemctl() { # $@ = systemctl's arguments
  local n
  for (( n = 1; n <= 5; n++ )); do
    if _TP_SC="$(systemctl "$@" 2>/dev/null)"; then return 0; fi
    if (( n < 5 )); then sleep 1; fi
  done
  TP_ACCOUNTS_FAILED="systemctl $*"
  return 1
}

# The one sentence for a refusal because the account set could not be read.
# It is not a finding about any file, so it is never told as one.
tp_accounts_refusal() {
  printf "the account check could not run: systemd did not answer \`%s\`" "${TP_ACCOUNTS_FAILED:-systemctl}"
}

# role:name:uid:gid,gid,... per service account, and TP_TOLERATE, the uids of
# dashboard accounts that are logins (the one state that only warns).
# Why an account can write any path at all, or nothing. $1 = user,
# $2 = the unit ("" for an account with none), $3 = extra group names,
# $4 = the unit's AmbientCapabilities, already read by trusted_path_accounts
# through _tp_systemctl, so a read that failed is a fault there and never an
# empty set here (#1089).
_tp_root_equivalent() {
  local user="$1" unit="$2" g c caps names
  names=" $(id -nG "$user" 2>/dev/null) $3 "
  for g in "${TP_ROOT_GROUPS[@]}"; do
    case "$names" in *" $g "*) printf 'is in the %s group, which is root on this host' "$g"; return 0 ;; esac
  done
  [[ -n "$unit" ]] || return 1
  caps=" $(printf '%s' "${4:-}" | tr '[:upper:]' '[:lower:]') "
  for c in "${TP_ROOT_CAPS[@]}"; do
    case "$caps" in *" $c "*) printf 'holds %s (AmbientCapabilities= on %s), which bypasses file permissions' "$c" "$unit"; return 0 ;; esac
  done
  return 1
}

_tp_group_name() { # $1 = a group name or number
  if [[ "$1" =~ ^[0-9]+$ ]]; then getent group "$1" 2>/dev/null | cut -d: -f1; else printf '%s' "$1"; fi
}

# $1 = the install tree, "" for none. A dashboard with no unit is found by the
# process running out of <tree>/dashboard, so without a tree there is nothing
# to scope that search to and it is not made (#757).
trusted_path_accounts() {
  [[ "${TP_ACCOUNTS_HELD:-0}" == 1 ]] && return 0
  TP_ACCOUNTS=()
  TP_TOLERATE=()
  TP_PRIV=()
  TP_ACCOUNTS_FAILED=""
  # No systemd to ask is not "no service accounts": it is a set nobody can
  # vouch for, and the callers refuse on it (#877 review, L1).
  if ! command -v systemctl >/dev/null 2>&1; then
    TP_ACCOUNTS_FAILED="systemctl (this host has none)"
    return 1
  fi
  local list unit role user group sup caps uid gids g gid why gnames seen=" " tree="${1:-}" dash_units=0
  # Unfiltered, then matched here: systemctl exits 1 when a pattern matches
  # nothing, which would read the same as a systemd that will not answer.
  _tp_systemctl list-unit-files --type=service --no-legend || return 1
  list="$_TP_SC"
  while read -r unit _; do
    case "$unit" in
      aperire-server.service|aperire-server-*.service|aperire-read.service|aperire-read-*.service) role=dashboard ;;
      aperire-advisord.service|aperire-advisord-*.service) role=advisor ;;
      aperire-relay.service|aperire-relay-*.service) role=relay ;;
      xrpld.service|rippled.service) role=node ;;
      *) continue ;;
    esac
    [[ "$role" == dashboard ]] && dash_units=1
    # A unit it lists and cannot describe is a fault, never a unit skipped.
    _tp_systemctl show "$unit" -p User --value || return 1
    user="$_TP_SC"
    [[ -n "$user" && "$user" != root && "$user" != 0 ]] || continue
    uid="$(id -u "$user" 2>/dev/null)" || continue
    [[ "$uid" =~ ^[0-9]+$ && "$uid" != 0 ]] || continue
    gids="$(id -G "$user" 2>/dev/null | tr ' ' ',')"
    _tp_systemctl show "$unit" -p Group --value || return 1
    group="$_TP_SC"
    _tp_systemctl show "$unit" -p SupplementaryGroups --value || return 1
    sup="$_TP_SC"
    _tp_systemctl show "$unit" -p AmbientCapabilities --value || return 1
    caps="$_TP_SC"
    gnames=""
    for g in $group $sup; do
      gid="$(_tp_gid "$g")"
      [[ -n "$gid" ]] && gids="${gids:+$gids,}$gid"
      gnames="$gnames $(_tp_group_name "$g")"
    done
    case "$seen" in *" $role:$uid "*) continue ;; esac
    seen="$seen$role:$uid "
    TP_ACCOUNTS+=("$role:$user:$uid:$gids")
    if why="$(_tp_root_equivalent "$user" "$unit" "$gnames" "$caps")"; then
      TP_PRIV+=("$uid:$role:$user:$why")
    fi
    if [[ "$role" == dashboard ]] && _tp_is_login "$user"; then
      TP_TOLERATE+=("$uid")
    fi
  done <<<"$list"
  local name
  for name in xrpld rippled; do
    uid="$(id -u "$name" 2>/dev/null)" || continue
    [[ "$uid" =~ ^[0-9]+$ && "$uid" != 0 ]] || continue
    case "$seen" in *" node:$uid "*) continue ;; esac
    seen="${seen}node:$uid "
    TP_ACCOUNTS+=("node:$name:$uid:$(id -G "$name" 2>/dev/null | tr ' ' ',')")
    if why="$(_tp_root_equivalent "$name" "" "")"; then
      TP_PRIV+=("$uid:node:$name:$why")
    fi
  done
  # A container node's uid. It is in the compose file's `user:` line and
  # nowhere a unit names it, and it may have no account on this host at all
  # (migrate-node-nonroot.sh writes 997:997 whether or not 997 is taken).
  # A `user:` that holds a variable names no uid this can know, so it is a
  # finding on every path, not a node left out of the set.
  local cu cg
  while read -r cu cg; do
    if [[ "$cu" == unknown ]]; then
      TP_PRIV+=("-1:node:container-user:the compose file's user: line holds a variable, so which host account runs the node cannot be known")
      continue
    fi
    if [[ "$cu" == unreadable ]]; then
      TP_PRIV+=("-1:node:container-user:the compose file writes user: in a form this check cannot read (a flow mapping, JSON, a quoted key, a tag, an anchor or an alias), so which host account runs the node cannot be known; write it as user: \"uid:gid\"")
      continue
    fi
    [[ "$cu" =~ ^[0-9]+$ && "$cu" != 0 ]] || continue
    case "$seen" in *" node:$cu "*) continue ;; esac
    seen="${seen}node:$cu "
    name="$(getent passwd "$cu" 2>/dev/null | cut -d: -f1)"
    gids="$(id -G "${name:-$cu}" 2>/dev/null | tr ' ' ',')"
    [[ -n "$gids" ]] || gids="$cg"
    TP_ACCOUNTS+=("node:${name:-uid$cu}:$cu:$gids")
    if [[ -n "$name" ]] && why="$(_tp_root_equivalent "$name" "" "")"; then
      TP_PRIV+=("$cu:node:$name:$why")
    fi
  done < <(_tp_container_uids)
  # A dashboard with no unit (pm2, or started by hand): the account running
  # <tree>/dashboard is the dashboard's account all the same. Only when no
  # dashboard unit exists, because with one its User= is the answer, and
  # only on a process seen running out of this tree. Never the tree's owner
  # by default: that is the account an installer suite's destination belongs
  # to too, and it turned every one of them red (#757).
  if (( ! dash_units )) && [[ -n "$tree" ]]; then
    local pu pg
    while read -r pu pg; do
      [[ "$pu" =~ ^[0-9]+$ && "$pu" != 0 ]] || continue
      case "$seen" in *" dashboard:$pu "*) continue ;; esac
      seen="${seen}dashboard:$pu "
      name="$(getent passwd "$pu" 2>/dev/null | cut -d: -f1)"
      gids="$(id -G "${name:-$pu}" 2>/dev/null | tr ' ' ',')"
      [[ -n "$gids" ]] || gids="$pg"
      TP_ACCOUNTS+=("dashboard:${name:-uid$pu}:$pu:$gids")
      if [[ -n "$name" ]] && why="$(_tp_root_equivalent "$name" "" "")"; then
        TP_PRIV+=("$pu:dashboard:$name:$why")
      fi
      if _tp_is_login "$pu"; then
        TP_TOLERATE+=("$pu")
      fi
    done < <(_tp_dashboard_procs "$tree")
  fi
  return 0
}

# "uid gid" for every container user a node's compose file names, numeric
# ones only: a name in `user:` is a name inside the container, and says
# nothing about a host uid. The files are the wrapper's own configurations
# (root-owned, written by the installer) and the node installer's record.
# The compose file itself is read as data, for digits, and nothing else.
_tp_container_uids() {
  local dir="${TP_CONF_DIR:-/etc/aperire}" cf c u g
  local q='["'"'"']?' var='^[[:space:]]*user:[[:space:]]*["'"'"']?[^#]*[$]'
  for cf in "$dir"/node-wrapper.conf "$dir"/node-wrapper-*.conf; do
    [[ -r "$cf" ]] || continue
    c="$(awk -F= '$1=="COMPOSE_FILE"{sub(/^[^=]*=/,""); print; exit}' "$cf" 2>/dev/null)"
    [[ "$c" == /* && -r "$c" ]] || continue
    sed -nE "s/^[[:space:]]*user:[[:space:]]*${q}([0-9]+)(:([0-9]+))?${q}[[:space:]]*(#.*)?\$/\\1 \\3/p" "$c" 2>/dev/null
    grep -qE -e "$var" "$c" 2>/dev/null && printf 'unknown 0\n'
    # uid:groupname names the uid all the same
    sed -nE "s/^[[:space:]]*user:[[:space:]]*${q}([0-9]+):[A-Za-z_][A-Za-z0-9_.-]*${q}[[:space:]]*(#.*)?\$/\\1 /p" "$c" 2>/dev/null
    # Every `user` key this can see must be one the strict parse above read.
    # A line pattern cannot follow a flow mapping wrapped after a comma, a
    # JSON file, a quoted or spaced key, a value on the next line, a block
    # scalar, a tag, an anchor or an alias, so it counts instead: a key it
    # cannot account for refuses, as a variable does. Whole-line comments are
    # dropped here; trailing ones are not.
    local tok='([0-9]+|[A-Za-z_][A-Za-z0-9_.-]*)' body loose strict
    body="$(grep -vE '^[[:space:]]*#' "$c" 2>/dev/null)"
    loose="$(grep -cE "(^|[[:space:]{,])${q}user${q}[[:space:]]*:" <<<"$body")"
    strict="$(grep -cE "^[[:space:]]*user:[[:space:]]*${q}${tok}(:${tok})?${q}[[:space:]]*(#.*)?\$" <<<"$body")"
    [[ "$loose" == "$strict" ]] || printf 'unreadable 0\n'
    # a comment-looking line that closes a quote and then holds a user key
    grep -qE "^[[:space:]]*#.*[\"'].*[{,][[:space:]]*${q}user${q}[[:space:]]*:" "$c" 2>/dev/null && printf 'unreadable 0\n'
    # tags, anchors, aliases, ? keys, an unpaired backslash, a NUL byte
    LC_ALL=C sed -e 's/\\\\//g' -e 's/\\"//g' "$c" 2>/dev/null \
      | LC_ALL=C grep -qE '(^|[[:space:]{,:[-])([&*][[:alnum:]_.-]|![^[:space:]]|[?]([[:space:]]|$))|[\\]' && printf 'unreadable 0\n'
    [[ $(LC_ALL=C tr -d '\000' < "$c" | wc -c) -eq $(wc -c < "$c") ]] || printf 'unreadable 0\n'
  done
  if [[ -r "$dir/node.conf" ]]; then
    u="$(awk -F= '$1=="NODE_UID"{print $2; exit}' "$dir/node.conf" 2>/dev/null)"
    g="$(awk -F= '$1=="NODE_GID"{print $2; exit}' "$dir/node.conf" 2>/dev/null)"
    [[ "$u" =~ ^[0-9]+$ ]] && printf '%s %s\n' "$u" "$g"
  fi
  return 0
}

# "uid gid" for each process running the dashboard out of <tree>/dashboard.
# The positive signal, the same one verify-after-restart.sh reads for a
# dashboard it finds without a unit: the process's working directory is the
# tree's dashboard directory (pm2 sets it to its pm_cwd) and an argument of
# its command line is server.ts. Neither alone: a shell in that directory is
# not the dashboard, and a server.ts elsewhere is not this tree's.
_tp_dashboard_procs() { # $1 = install tree
  local proc="${TP_PROC_DIR:-/proc}" dash p u g
  dash="$(realpath -e -- "$1/dashboard" 2>/dev/null)" || return 0
  for p in "$proc"/[0-9]*; do
    [[ -d "$p" ]] || continue
    [[ "$(readlink "$p/cwd" 2>/dev/null)" == "$dash" ]] || continue
    tr '\0' '\n' <"$p/cmdline" 2>/dev/null | grep -qxE '(.*/)?server\.ts' || continue
    u="$(awk '/^Uid:/{print $2; exit}' "$p/status" 2>/dev/null)"
    g="$(awk '/^Gid:/{print $2; exit}' "$p/status" 2>/dev/null)"
    [[ "$u" =~ ^[0-9]+$ ]] && printf '%s %s\n' "$u" "$g"
  done | sort -u
  return 0
}

# ---- the walk and the copy (Python, so a descriptor can be held) ---------
_TP_PY="$(cat <<'TP_PY_EOF'
import errno, hashlib, os, stat, struct, sys

ACL_USER, ACL_GROUP_OBJ, ACL_GROUP, ACL_MASK, ACL_OTHER = 0x02, 0x04, 0x08, 0x10, 0x20
WRITE = 2
MAX_HOPS = 40
MAX_BYTES = 16 << 20


class Fault(Exception):
    pass


def acl_of(fd):
    try:
        raw = os.getxattr("/proc/self/fd/%d" % fd, "system.posix_acl_access")
    except OSError as e:
        if e.errno in (errno.ENODATA, errno.EOPNOTSUPP):
            return None
        raise Fault("cannot read the ACL (%s)" % e.strerror)
    if len(raw) < 4 or (len(raw) - 4) % 8 or struct.unpack_from("<I", raw, 0)[0] != 2:
        raise Fault("an ACL this does not understand")
    return [struct.unpack_from("<HHI", raw, 4 + 8 * i) for i in range((len(raw) - 4) // 8)]


def how_writable(st, acl, uid, gids):
    """Why this account can change the inode, or None. POSIX.1e order."""
    if st.st_uid == uid:
        return "owns it"
    if acl is None:
        if st.st_gid in gids:
            return "group write" if st.st_mode & 0o020 else None
        return "write for everyone" if st.st_mode & 0o002 else None
    mask = next((p for t, p, _ in acl if t == ACL_MASK), 7)
    for t, p, i in acl:
        if t == ACL_USER and i == uid:
            return "an ACL entry names it" if p & mask & WRITE else None
    matched = False
    for t, p, i in acl:
        if t == ACL_GROUP_OBJ and st.st_gid in gids:
            matched = True
            if p & mask & WRITE:
                return "group write"
        elif t == ACL_GROUP and i in gids:
            matched = True
            if p & mask & WRITE:
                return "an ACL entry names its group"
    if matched:
        return None
    for t, p, _ in acl:
        if t == ACL_OTHER and p & WRITE:
            return "write for everyone"
    return None


class Walk:
    def __init__(self, accts, strict=False):
        self.accts = accts
        self.findings = []
        # Strict: a symlink anywhere on the way is a refusal, not a turn to
        # follow. The release-digests copy resolves its tree once up front,
        # so the path it hands in has none, and one that turns up is a swap.
        self.strict = strict

    def judge(self, fd, st, disp, sticky_ok):
        acl = None if stat.S_ISLNK(st.st_mode) else acl_of(fd)
        for role, name, uid, gids in self.accts:
            if stat.S_ISLNK(st.st_mode):
                how = "owns it" if st.st_uid == uid else None
            else:
                how = how_writable(st, acl, uid, gids)
            if how is None:
                continue
            if how != "owns it" and sticky_ok and stat.S_ISDIR(st.st_mode) and st.st_mode & stat.S_ISVTX:
                continue
            f = (role, name, uid, how, disp)
            if f not in self.findings:
                self.findings.append(f)

    def reopen(self, fd, st, flags):
        rfd = os.open("/proc/self/fd/%d" % fd, flags)
        rst = os.fstat(rfd)
        if (rst.st_dev, rst.st_ino) != (st.st_dev, st.st_ino):
            os.close(rfd)
            raise Fault("changed while it was being read")
        return rfd

    def walk(self, path, want):
        """Descriptor on the file (want='file') or directory (want='dir')."""
        if not path.startswith("/"):
            raise Fault("%s is not an absolute path" % path)
        root = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
        self.judge(root, os.fstat(root), "/", True)
        chain = [(root, "/")]
        todo = [c for c in path.split("/") if c]
        hops = 0
        try:
            while todo:
                name = todo.pop(0)
                if name == ".":
                    continue
                if name == "..":
                    if len(chain) > 1:
                        os.close(chain.pop()[0])
                    continue
                pfd, pdisp = chain[-1]
                disp = (pdisp if pdisp != "/" else "") + "/" + name
                try:
                    fd = os.open(name, os.O_PATH | os.O_NOFOLLOW, dir_fd=pfd)
                except FileNotFoundError:
                    raise Fault("%s does not exist" % disp)
                except NotADirectoryError:
                    raise Fault("%s is not a directory" % pdisp)
                try:
                    st = os.fstat(fd)
                    if stat.S_ISLNK(st.st_mode):
                        if self.strict:
                            raise Fault("%s is a symlink, or sits under one, so it is not the file its path names" % disp)
                        hops += 1
                        if hops > MAX_HOPS:
                            raise Fault("too many symlinks under %s" % path)
                        self.judge(fd, st, disp + " (symlink)", False)
                        target = os.readlink("", dir_fd=fd)
                        if target.startswith("/"):
                            while len(chain) > 1:
                                os.close(chain.pop()[0])
                        todo = [c for c in target.split("/") if c] + todo
                        continue
                    # A directory is judged here as one on the way. The one
                    # the walk ends in is judged again below, strictly, once
                    # the path is resolved: deciding "the last one" here from
                    # what was left to walk read "<sticky dir>/." as a
                    # directory with more below it, and waved a destination
                    # through on the sticky rule (#756 review, L2).
                    if stat.S_ISDIR(st.st_mode):
                        dfd = self.reopen(fd, st, os.O_RDONLY | os.O_DIRECTORY)
                        self.judge(dfd, st, disp, True)
                        chain.append((dfd, disp))
                        continue
                    if stat.S_ISREG(st.st_mode) and not todo and want == "file":
                        rfd = self.reopen(fd, st, os.O_RDONLY | os.O_NONBLOCK | os.O_NOCTTY)
                        self.judge(rfd, st, disp, False)
                        return rfd, disp
                    raise Fault("%s is not a %s" % (disp, "regular file" if want == "file" else "directory"))
                finally:
                    os.close(fd)
            if want == "dir":
                # The directory a write lands in, judged once more with no
                # sticky exemption, after the path is fully resolved: the
                # exemption is about entries under a sticky directory, and
                # this one is where the new entry goes.
                fd, disp = chain.pop()
                self.judge(fd, os.fstat(fd), disp, False)
                return fd, disp
            raise Fault("%s is a directory" % path)
        finally:
            for fd, _ in chain:
                os.close(fd)


def verdict(findings, tolerated_uid):
    if not findings:
        return "clean"
    if tolerated_uid is not None and all(f[2] == tolerated_uid for f in findings):
        return "tolerated"
    return "refused"


def report(findings, kind):
    for role, name, uid, how, disp in findings:
        print("finding\t%s\t%s\t%s\t%s\t%s" % (kind, role, name, how, disp))


def main(argv):
    accts, tolerate, tree, priv, want, strict = [], set(), None, [], None, False
    while argv and argv[0].startswith("--"):
        flag = argv.pop(0)
        if flag == "--priv":
            uid, role, name, why = argv.pop(0).split(":", 3)
            priv.append((role, name, int(uid), why, "(every path)"))
        elif flag == "--acct":
            role, name, uid, gids = argv.pop(0).split(":", 3)
            accts.append((role, name, int(uid), {int(g) for g in gids.split(",") if g}))
        elif flag == "--tolerate":
            tolerate.add(int(argv.pop(0)))
        elif flag == "--tree":
            tree = argv.pop(0)
        elif flag == "--want":
            want = argv.pop(0)
            if want != "none" and (len(want) != 64 or any(c not in "0123456789abcdef" for c in want)):
                raise Fault("--want takes a sha256 or none, not %r" % want)
        elif flag == "--strict":
            strict = True
        else:
            raise Fault("unknown flag %s" % flag)
    op = argv.pop(0)
    # A copy states the digest its bytes must have, or "none" where the host
    # has no release record to hold them to. Never left out: a copy with no
    # digest is not one this does.
    if op == "copy" and want is None:
        raise Fault("a copy needs --want: the release's sha256 for the file, or none")
    src = Walk(accts, strict)
    sfd, sdisp = src.walk(argv[0], "file")
    # An account that can bypass file permissions outright makes every path
    # writable to it, so it is a finding on every check, not on one inode.
    src.findings[:0] = priv
    try:
        tolerated_uid = None
        if tree is not None and tolerate:
            tfd, _ = Walk(accts).walk(tree, "dir")
            owner = os.fstat(tfd).st_uid
            os.close(tfd)
            if owner in tolerate:
                tolerated_uid = owner
        report(src.findings, "source")
        v = verdict(src.findings, tolerated_uid)
        if op == "check":
            print("verdict\t%s" % v)
            return {"clean": 0, "tolerated": 3, "refused": 2}[v]
        if op != "copy":
            raise Fault("unknown op %s" % op)
        destdir, name, mode = argv[1], argv[2], int(argv[3], 8)
        if not name or "/" in name or name in (".", ".."):
            raise Fault("bad destination name %r" % name)
        dst = Walk(accts)
        dfd, ddisp = dst.walk(destdir, "dir")
        try:
            report(dst.findings, "destination")
            if dst.findings:
                v = "refused"
            print("verdict\t%s" % v)
            if v == "refused":
                return 2
            downer = os.fstat(dfd).st_uid
            if downer not in (0, os.geteuid()):
                raise Fault("%s belongs to uid %d, not root" % (ddisp, downer))
            data = b""
            while True:
                chunk = os.read(sfd, 1 << 16)
                if not chunk:
                    break
                data += chunk
                if len(data) > MAX_BYTES:
                    raise Fault("%s is larger than any program this copies" % sdisp)
            digest = hashlib.sha256(data).hexdigest()
            # The second check, on the same bytes the first one judged: the
            # descriptor the walk opened is the only thing read, and what was
            # read is what is compared and what is written. Before "same", so
            # a tampered file is never let through because the destination
            # already holds the same tampered bytes.
            if want != "none" and digest != want:
                print("mismatch\t%s\t%s" % (digest, sdisp))
                return 4
            owner = (0, 0) if os.geteuid() == 0 else (os.geteuid(), os.getegid())
            try:
                efd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dfd)
            except OSError:
                efd = None
            if efd is not None:
                try:
                    est = os.fstat(efd)
                    same = (stat.S_ISREG(est.st_mode) and stat.S_IMODE(est.st_mode) == mode
                            and (est.st_uid, est.st_gid) == owner and est.st_size == len(data)
                            and os.read(efd, len(data) + 1) == data)
                finally:
                    os.close(efd)
                if same:
                    print("same\t%s\t%s/%s" % (digest, ddisp, name))
                    return 0 if v == "clean" else 3
            tmp = ".%s.new-%d" % (name, os.getpid())
            try:
                tfd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=dfd)
            except OSError as e:
                print("fault\tcannot write into %s (%s)" % (ddisp, e.strerror))
                return 5
            try:
                view = memoryview(data)
                while view:
                    view = view[os.write(tfd, view):]
                if os.geteuid() == 0:
                    os.fchown(tfd, 0, 0)
                os.fchmod(tfd, mode)
                os.fsync(tfd)
                os.close(tfd)
                tfd = None
                os.rename(tmp, name, src_dir_fd=dfd, dst_dir_fd=dfd)
            except BaseException as e:
                if tfd is not None:
                    os.close(tfd)
                try:
                    os.unlink(tmp, dir_fd=dfd)
                except OSError:
                    pass
                if isinstance(e, OSError):
                    print("fault\t%s/%s could not be written (%s)" % (ddisp, name, e.strerror))
                    return 5
                raise
            os.fsync(dfd)
            print("copied\t%s\t%s/%s" % (digest, ddisp, name))
            return 0 if v == "clean" else 3
        finally:
            os.close(dfd)
    finally:
        os.close(sfd)


try:
    sys.exit(main(sys.argv[1:]))
except Fault as e:
    print("fault\t%s" % e)
    sys.exit(1)
except (OSError, ValueError, IndexError) as e:
    print("fault\t%s" % e)
    sys.exit(1)
TP_PY_EOF
)"

_tp_run() { # $@ = op and arguments; the account set and tolerance come from trusted_path_accounts
  local -a args=()
  local a u
  for a in "${TP_ACCOUNTS[@]}"; do args+=(--acct "$a"); done
  for u in "${TP_TOLERATE[@]}"; do args+=(--tolerate "$u"); done
  for a in "${TP_PRIV[@]}"; do args+=(--priv "$a"); done
  # Root's own interpreter at a fixed path, never one a caller's PATH
  # finds (#877 review, L2). None there is a fault, which refuses.
  local py
  py="$(_tp_python)" || { printf 'fault\tno python3 at /usr/bin or /bin, and the check runs in it\n'; return 1; }
  "$py" -I -c "$_TP_PY" "${args[@]}" "$@"
}

# Human lines from the program's own, on stderr. Sets TP_REPORT_WHO to the
# account a tolerated finding belongs to, for the warning, TP_REPORT_ACCTS to
# every account found ("name (role), ..."), and TP_REPORT_ROLES to the roles
# among them, each between spaces, so a caller can say which fix fits.
_tp_say() { # $1 = the program's output
  local kind side role name how path
  TP_REPORT_WHO="" TP_REPORT_ACCTS="" TP_REPORT_ROLES=" "
  while IFS=$'\t' read -r kind side role name how path; do
    case "$kind" in
      finding)
        printf '   %s: %s is writable by %s (%s account): %s\n' "$side" "$path" "$name" "$role" "$how" >&2
        TP_REPORT_WHO="$name"
        case ", $TP_REPORT_ACCTS, " in *", $name ($role), "*) ;; *) TP_REPORT_ACCTS="${TP_REPORT_ACCTS:+$TP_REPORT_ACCTS, }$name ($role)" ;; esac
        case "$TP_REPORT_ROLES" in *" $role "*) ;; *) TP_REPORT_ROLES="$TP_REPORT_ROLES$role " ;; esac ;;
      fault)
        printf '   %s\n' "$side${role:+ $role}${name:+ $name}" >&2 ;;
    esac
  done <<<"$1"
}

_tp_warn_tolerated() { # $1 = what was let through
  printf '   warning: %s is writable by %s, the login the dashboard runs as, which\n' "$1" "$TP_REPORT_WHO" >&2
  printf '   also owns this install. It was used anyway so this can go ahead. Moving\n' >&2
  printf '   the dashboard onto its own account (migrate-dashboard-account.sh, ADR 0024)\n' >&2
  printf '   closes it, and a later release refuses instead of warning.\n' >&2
}

# --strict refuses any symlink on the way, as the copy does, so a clean
# answer with it is the answer the copy's source walk would give.
trusted_path_check() { # $1 = path, $2 = install tree ("" for none), $3 = --strict or ""
  local out rc=0
  if ! trusted_path_accounts "${2:-}"; then
    printf '   refused: %s, so the service accounts are unknown\n' "$(tp_accounts_refusal)" >&2
    return 1
  fi
  out="$(_tp_run ${2:+--tree "$2"} ${3:+"$3"} check "$1")" || rc=$?
  _tp_say "$out"
  [[ $rc -eq 3 ]] && _tp_warn_tolerated "$1"
  return "$rc"
}

# The one copy root makes out of a tree, with both of ADR 0024's checks on
# one read. The walk judges the source and the destination directory; the
# bytes are read once, from the descriptor the walk judged; their sha256 is
# compared with WANT; and only then are they written beside the destination
# and renamed in. There is no second lookup of the source by name, so a file
# swapped in after the check is never the one read, and the bytes compared
# are the bytes written.
#
# WANT is the release's sha256 for the file, or "none" when the host has no
# release record (a git checkout); release-digests-lib.sh's rd_stage is the
# one caller that decides which, and nothing else should call this.
# --strict refuses a symlink anywhere on the source's way, rather than
# following it; rd_stage resolves its tree once first, so it has none.
#
# Quiet on stdout. Findings and faults go to stderr. Sets TP_COPY (copied or
# same), TP_COPY_DIGEST (the sha256 of what was read) and TP_REPORT_WHO (the
# account a tolerated finding belongs to).
#   0  copied or already the same, nothing on the way can be changed
#   3  the same, but only the pre-migration login can change the source;
#      the caller says so
#   2  refused: a service account can change the source or the destination
#   4  refused: the bytes read are not WANT
#   1  refused: it could not be checked (missing, not a regular file, a
#      symlink under --strict)
#   5  checked, and could not be written
#   6  refused: the account check could not run (systemd did not answer;
#      TP_ACCOUNTS_FAILED names the call). Nothing was judged about the file,
#      so a caller must not tell it as a file that changed.
# Nothing is written on 1, 2, 4 or 6, and what was at the destination stays.
trusted_path_copy() { # $1 = source, $2 = destination dir, $3 = name, $4 = octal mode, $5 = install tree, $6 = sha256 or none, $7 = --strict or ""
  local out rc=0 kind a
  # Read by the caller (rd_stage), not here.
  # shellcheck disable=SC2034
  TP_COPY="" TP_COPY_DIGEST="" TP_REPORT_WHO=""
  if [[ $# -lt 6 || -z "$6" ]]; then
    printf '   refused: %s: a copy needs the digest it must match\n' "$1" >&2
    return 1
  fi
  if ! _tp_python >/dev/null; then
    printf '   refused: %s: the trusted-path check runs in python3, and this host has none at /usr/bin or /bin (sudo apt-get install -y python3)\n' "$1" >&2
    return 1
  fi
  if ! trusted_path_accounts "$5"; then
    printf '   refused: %s, so the service accounts are unknown\n' "$(tp_accounts_refusal)" >&2
    return 6
  fi
  out="$(_tp_run --tree "$5" --want "$6" ${7:+"$7"} copy "$1" "$2" "$3" "$4")" || rc=$?
  # shellcheck disable=SC2034  # TP_COPY and TP_COPY_DIGEST are the caller's
  while IFS=$'\t' read -r kind a _; do
    case "$kind" in
      copied) TP_COPY=copied TP_COPY_DIGEST="$a" ;;
      same) TP_COPY=same TP_COPY_DIGEST="$a" ;;
      mismatch) TP_COPY_DIGEST="$a" ;;
    esac
  done <<<"$out"
  # Every finding is named on a refusal. A tolerated copy has one owner to
  # name, and the caller says it in one line, not one per directory.
  if [[ $rc -eq 3 ]]; then
    TP_REPORT_WHO="$(awk -F'\t' '$1=="finding"{print $4; exit}' <<<"$out")"
  else
    _tp_say "$out"
  fi
  return "$rc"
}

# The interpreter the service names: root's own, at a fixed path. Never one
# found on a PATH.
_tp_python() {
  local p
  for p in /usr/bin/python3 /bin/python3; do
    if [[ -x "$p" ]]; then printf '%s' "$p"; return 0; fi
  done
  return 1
}

# Read the account set now and keep it for the copies that follow in this
# shell, until trusted_path_release_accounts. For a batch made in one root
# shell that writes no unit and adds no account while it runs (the staging of
# a release's scripts); never across an installer, which can do both.
trusted_path_hold_accounts() { # $1 = the install tree the batch copies out of
  TP_ACCOUNTS_HELD=0
  trusted_path_accounts "${1:-}" || return 1
  TP_ACCOUNTS_HELD=1
}
trusted_path_release_accounts() { TP_ACCOUNTS_HELD=0; }

# This whole block, as text a root shell can define: the account set, the
# walk and the copy. rd_lib_text appends it when this
# library is loaded, so a root shell that gets the release-digests functions
# as text gets both checks with them, and never sources a tree file for it.
tp_lib_text() {
  # Plain assignments, never `declare`: text a caller evals inside a
  # function would otherwise make these local to it.
  printf 'TP_ROOT_GROUPS=(%s)\nTP_ROOT_CAPS=(%s)\nTP_ACCOUNTS_HELD=0\n_TP_PY=%q\n' \
    "$(printf '%q ' "${TP_ROOT_GROUPS[@]}")" "$(printf '%q ' "${TP_ROOT_CAPS[@]}")" "$_TP_PY"
  declare -f _tp_python _tp_is_login _tp_gid _tp_root_equivalent _tp_group_name _tp_systemctl tp_accounts_refusal trusted_path_accounts \
    _tp_container_uids _tp_dashboard_procs \
    trusted_path_hold_accounts trusted_path_release_accounts \
    _tp_run _tp_say _tp_warn_tolerated trusted_path_check trusted_path_copy tp_lib_text
}
# <<< trusted path <<<

# /usr/local/lib/aperire, made root's if it is not there yet. The copy below
# holds it to the same rule as any destination either way.
# This process's uid from id(1) at a fixed path, never from bash's $EUID,
# which bash imports from the environment (#1109): a root shell started with
# EUID=<a login's uid> would otherwise take that login's files for root's.
# Prints nothing and fails when it cannot be read.
_tp_euid() {
  local p u
  for p in /usr/bin/id /bin/id; do
    [[ -x "$p" ]] || continue
    u="$("$p" -u 2>/dev/null)" || continue
    [[ "$u" =~ ^[0-9]+$ ]] || continue
    printf '%s' "$u"
    return 0
  done
  return 1
}

_tp_root_only() { # $1 = path; root's (the invoking user's, when this is not run as root) and writable by nobody else
  local want=0 meta me
  me="$(_tp_euid)" || me=""
  [[ "$me" == 0 ]] || want=$me
  [[ ! -L "$1" ]] || return 1
  meta="$(stat -c '%u:%a' -- "$1" 2>/dev/null)" || return 1
  [[ "${meta%%:*}" == "$want" ]] && (( (8#${meta##*:} & 8#022) == 0 ))
}

_tp_libdir() {
  # A directory that is already there is held to the same rule as one made
  # here: a record read from a directory another account can write is no fact
  # (#780 review).
  if [[ -d "$TP_LIB_DIR" ]]; then _tp_root_only "$TP_LIB_DIR"; return; fi
  if [[ "$(_tp_euid)" == 0 ]]; then install -d -m 0755 -o root -g root "$TP_LIB_DIR"
  else install -d -m 0755 "$TP_LIB_DIR"; fi
}

# The wrapper, and the two libraries it loads, into the root-owned places the
# socket's broker and the wrapper itself name. Each goes through rd_install
# (release-digests-lib.sh), so each is the release's own bytes and passed
# the trusted-path check, both on the one read. The libraries go first, so a
# wrapper never lands in front of an older copy of what it sources. With the
# release-digests check not loaded nothing is placed, rather than a copy
# nobody held to the release. 0 when all three are in place, 2 when one was
# refused, 1 when one could not be written; nothing after that one is.
trusted_place_node_wrapper() { # $1 = install tree, $2 = instance
  local tree="$1" inst="$2" rc out
  if ! declare -F rd_install >/dev/null 2>&1; then
    printf '   refused: the release-digests check is not loaded here, so the wrapper was not placed\n' >&2
    return 1
  fi
  _tp_libdir || return 1
  _tp_place_one() { # $1 = path in the release, $2 = destination, $3 = mode
    rc=0
    out="$(rd_install "$tree" "$1" "$2" "$3")" || rc=$?
    case "$rc" in
      0) if [[ "$out" == same ]]; then printf '   %s already matches the release\n' "$2"
         else printf '   %s placed: checked against the release, renamed into place\n' "$2"; fi
         return 0 ;;
      1) printf '   refused: %s was not placed; the lines above say why\n' "$2" >&2; return 2 ;;
      *) printf '   %s could not be written\n' "$2" >&2; return 1 ;;
    esac
  }
  _tp_place_one scripts/config-write-lib.sh "$TP_LIB_DIR/config-write-lib.sh" 0644 || return
  _tp_place_one scripts/trusted-path-lib.sh "$TP_LIB_DIR/trusted-path-lib.sh" 0644 || return
  _tp_place_one scripts/aperire-node-wrapper.sh "$(trusted_wrapper_path "$inst")" 0755 || return
  return 0
}

# ---- the Advisor's root socket (ADR 0025) --------------------------------
#
# The Advisor reaches the wrapper through one socket per instance and never
# through sudo. systemd listens on /run/aperire/node-wrapper<-instance>.sock,
# root:<the Advisor account's own group> 0660, and each connection starts
# aperire-wrapper-broker as root, which checks the caller's uid, takes one
# verb from a fixed table and runs the installed wrapper copy. The socket's
# owner is root on purpose: an account that owns a socket inode can chmod it
# wider. The broker's SO_PEERCRED check against the one uid named in its
# unit is the second lock.
#
# What used to be here was the one writer of the Advisor's sudo rule. There
# is no writer now. What is left is the reader the update needs to find a
# rule an older release wrote, and the one place that removes it once the
# Advisor no longer runs on it.

TP_RUN_DIR="${APERIRE_RUN_DIR:-/run/aperire}"

trusted_broker_path() { printf '%s/aperire-wrapper-broker' "$TP_SBIN_DIR"; }
trusted_socket_path() { printf '%s/node-wrapper%s.sock' "$TP_RUN_DIR" "${1:+-$1}"; }
trusted_socket_unit() { printf 'aperire-node-wrapper%s.socket' "${1:+-$1}"; }
trusted_socket_service() { printf 'aperire-node-wrapper%s@.service' "${1:+-$1}"; }

# The broker, from the tree, through the release-digests check (ADR 0024
# lane 2, release-digests-lib.sh): read once through one descriptor, its
# sha256 compared with the release's own record, and renamed into a root
# directory. The caller loads that library first: the installers source it,
# and the update hands its own copy to the root shell that runs this. With it
# missing nothing is placed, rather than falling back to a copy nobody
# checked against the release. 0 placed or already the same, 1 refused (said
# above), 2 not written.
trusted_place_broker() { # $1 = install tree
  local out rc=0 dest
  dest="$(trusted_broker_path)"
  if ! declare -F rd_install >/dev/null 2>&1; then
    printf '   refused: the release-digests check is not loaded here, so %s was not placed\n' "$dest" >&2
    return 1
  fi
  out="$(rd_install "$1" scripts/aperire-wrapper-broker.py "$dest" 0755)" || rc=$?
  case "$rc" in
    0) if [[ "$out" == same ]]; then printf '   %s already matches the release\n' "$dest"
       else printf '   %s placed: checked against the release, renamed into place\n' "$dest"; fi ;;
    1) printf '   refused: %s was not placed; the release-digests check above says why\n' "$dest" >&2 ;;
    *) printf '   %s could not be written\n' "$dest" >&2 ;;
  esac
  return "$rc"
}

# A root file in a root-only directory (the unit directory): staged, then
# installed root:root 0644 by the same call every installer here uses for a
# unit, so the test suites' one stand-in for it covers this too.
_tp_put_root_file() { # $1 = destination, stdin = content
  local dest="$1" tmp rc=0
  tmp="$(mktemp)" || return 1
  cat > "$tmp" && install -o root -g root -m 0644 "$tmp" "$dest" || rc=1
  rm -f "$tmp"
  return "$rc"
}

trusted_socket_unit_text() { # $1 = instance, $2 = the account's gid
  local inst="$1" gid="$2"
  cat <<EOF
# Written by Aperire One (install-advisor-account.sh, or an update). ADR 0025.
#
# The Advisor's one way to the node wrapper as root, in place of the sudo rule
# it used to hold. The socket is root's, with the Advisor account's own group,
# so only that account can connect; the broker behind it checks the caller's
# uid too, takes one verb from a fixed table, and runs the root-owned wrapper.
[Unit]
Description=Aperire: the Advisor's socket to the node wrapper${inst:+ ($inst)}
Documentation=file:$(trusted_broker_path)

[Socket]
ListenStream=$(trusted_socket_path "$inst")
SocketUser=root
SocketGroup=$gid
SocketMode=0660
DirectoryMode=0755
# One process per call. The Advisor calls often and at once, so this is not
# the one-at-a-time of the other root sockets. At the limit systemd closes a
# new connection unanswered, and the Advisor tries it again.
Accept=yes
MaxConnections=16
# Explicit. The Accept=yes default (2s, 200) can trip on a burst of reads,
# and a tripped socket stops listening until someone restarts it.
TriggerLimitIntervalSec=10s
TriggerLimitBurst=1000

[Install]
WantedBy=sockets.target
EOF
}

trusted_socket_service_text() { # $1 = instance, $2 = the account's uid, $3 = python
  local inst="$1" uid="$2" py="$3"
  cat <<EOF
# Written by Aperire One (install-advisor-account.sh, or an update). ADR 0025.
[Unit]
Description=Aperire: one Advisor call to the node wrapper${inst:+ ($inst)} (connection %i)
Documentation=file:$(trusted_broker_path)
# A [Unit] key. Under [Service] systemd logs "Unknown key name" on every call
# and ignores it, so finished instances were never collected (#800).
CollectMode=inactive-or-failed

[Service]
# Root, because the wrapper is the whole of what the Advisor may do as root.
# No sandbox: a native package install writes under /usr and /var/lib/dpkg,
# and a sandbox wide enough for that constrains nothing. The boundary is the
# broker's table and the wrapper's own checks.
ExecStart=$py -I -S $(trusted_broker_path) --wrapper=$(trusted_wrapper_path "$inst") --allow-uid=$uid${inst:+ --instance=$inst}
StandardInput=socket
StandardOutput=socket
# The broker's own ledger line, one per call, at notice.
StandardError=journal
SyslogIdentifier=aperire-wrapper-broker
# Keeps systemd's own start and stop line for every connection out of the
# journal; the ledger line is notice and passes.
LogLevelMax=notice
# Anything the broker writes without a priority of its own (a Python
# traceback) is an error, so it passes LogLevelMax too rather than vanishing.
SyslogLevel=err
# The backstop behind the broker's own bounds (600 s a read, 7200 s an act).
RuntimeMaxSec=7500
EOF
}

# The two units for one instance, bound to one account, and the socket
# (re)started so a changed unit is the one listening. 0 written and
# listening as expected, 1 not.
trusted_write_socket_units() { # $1 = instance, $2 = the Advisor's account
  local inst="$1" acct="$2" uid gid py sock
  uid="$(id -u "$acct" 2>/dev/null)"
  gid="$(getent passwd "$acct" 2>/dev/null | cut -d: -f4)"
  if [[ ! "$uid" =~ ^[1-9][0-9]*$ || ! "$gid" =~ ^[1-9][0-9]*$ ]]; then
    printf '   %s has no uid and gid of its own here (uid %s, gid %s); no socket was written\n' "$acct" "${uid:-none}" "${gid:-none}" >&2
    return 1
  fi
  py="$(_tp_python)" || { printf '   no python3 at /usr/bin or /bin; the broker cannot run, so no socket was written\n' >&2; return 1; }
  # The socket's mode is 0660 to this group, so the group has to be this
  # account's alone, or 0660 lets in whoever else holds it.
  local others
  others="$(_tp_group_others "$acct" "$gid")"
  if [[ -n "$others" ]]; then
    printf '   %s'"'"'s primary group (gid %s) is also held by: %s. The socket would admit them too, so it was not written\n' \
      "$acct" "$gid" "$others" >&2
    # Named one by one, with what takes each one out. Nothing here removes
    # them: an account this did not put there may need the group (#794).
    local o gname
    gname="$(_tp_group_name "$gid")"
    for o in $others; do
      if _tp_listed_member "$o" "$gname"; then
        printf '     %s is a member of %s. If nothing it runs needs that group:  sudo gpasswd -d %s %s\n' "$o" "$gname" "$o" "$gname" >&2
      else
        printf '     %s has %s as its own primary group. No one command is safe for that: give %s a\n' "$o" "$gname" "$o" >&2
        printf '     group of its own (usermod -g), or give the Advisor an account of its own\n' >&2
      fi
    done
    return 1
  fi
  trusted_socket_unit_text "$inst" "$gid" | _tp_put_root_file "$TP_UNIT_DIR/$(trusted_socket_unit "$inst")" || return 1
  trusted_socket_service_text "$inst" "$uid" "$py" | _tp_put_root_file "$TP_UNIT_DIR/$(trusted_socket_service "$inst")" || return 1
  systemctl daemon-reload 2>/dev/null || true
  systemctl enable "$(trusted_socket_unit "$inst")" >/dev/null 2>&1 || true
  # DirectoryMode= applies only to a directory systemd creates (#171).
  install -d -m 0755 -o root -g root "$TP_RUN_DIR" 2>/dev/null || true
  systemctl restart "$(trusted_socket_unit "$inst")" 2>/dev/null || true
  sock="$(trusted_socket_path "$inst")"
  printf '   %s and %s: only %s (uid %s) may connect, at %s\n' \
    "$(trusted_socket_unit "$inst")" "$(trusted_socket_service "$inst")" "$acct" "$uid" "$sock"
  trusted_socket_ready "$inst" "$gid"
}

# Every other account that holds a gid, as a primary group or as a member,
# space-separated. Empty when it is the one account's alone.
_tp_group_others() { # $1 = account, $2 = gid
  local acct="$1" gid="$2" members m
  members="$(getent group "$gid" 2>/dev/null | head -1 | cut -d: -f4 | tr ',' ' ')"
  {
    for m in $members; do [[ "$m" == "$acct" ]] || printf '%s\n' "$m"; done
    getent passwd 2>/dev/null | awk -F: -v g="$gid" -v a="$acct" '$4 == g && $1 != a { print $1 }'
  } | sort -u | tr '\n' ' ' | sed 's/ $//'
}

# ---- the dashboard in the Advisor's own group (#794) ------------------------
#
# The socket above is 0660 to the Advisor's primary group, so it is written
# only while that group is the Advisor's alone. The #245 corpus repair broke
# that on every host it touched: to let the dashboard write a fleet corpus
# owned by the Advisor's group, it put the dashboard's account IN that group
# (`usermod -aG advisord aperire`), and the update then refused the socket and
# ended STRANDED on an otherwise healthy box (aperire2, aperire3, 2026-10-02).
#
# Repaired here, before the socket is written, and only in that one shape: the
# dashboard's account is the one other holder of the group, as a listed
# member. In order, stopping at the first thing that does not hold:
#   1. the shared group is named, the way install-advisor-account.sh named it,
#      and both accounts hold it
#   2. every fleet corpus the unit names has whatever was in the Advisor's
#      group moved to the shared group, g+w and setgid on directories, by
#      descriptor (the Advisor's account can write in there)
#   3. nothing left in a corpus still needs the Advisor's group
#   4. `gpasswd -d <dashboard> <advisor group>`, and the group read back
# Any other holder, and nothing is changed: the socket writer's refusal names
# every one, with the command. Nobody but the dashboard's account is ever
# removed from anything.

# Is <account> listed as a member of <group name>? Primary groups are not
# listed, and this does not count them.
_tp_listed_member() { # $1 = account, $2 = group name
  local m
  for m in $(getent group "$2" 2>/dev/null | head -1 | cut -d: -f4 | tr ',' ' '); do
    [[ "$m" == "$1" ]] && return 0
  done
  return 1
}

# Does <account> hold <group name>, as its primary group or a listed member?
_tp_holds_group() { # $1 = account, $2 = group name
  local gid pg
  gid="$(getent group "$2" 2>/dev/null | head -1 | cut -d: -f3)"
  pg="$(getent passwd "$1" 2>/dev/null | head -1 | cut -d: -f4)"
  [[ -n "$gid" && "$pg" == "$gid" ]] && return 0
  _tp_listed_member "$1" "$2"
}

# The unit's ReadWritePaths entries ending in <suffix>, one per line. The
# writable set is the Advisor's own three directories (ADR 0025), so this is
# where its state and its fleet corpus are named.
_tp_unit_rw() { # $1 = unit file, $2 = suffix such as /advisor/knowledge-fleet
  local line tok
  while IFS= read -r line; do
    for tok in ${line#ReadWritePaths=}; do
      tok="${tok#-}"
      [[ "$tok" == *"$2" ]] && printf '%s\n' "$tok"
    done
  done < <(grep '^ReadWritePaths=' "$1" 2>/dev/null)
}

# The group the Advisor shares with the dashboard, read from what
# install-advisor-account.sh wrote, never a constant: the unit's
# SupplementaryGroups= first, then the group it handed advisor/state to.
# Printed only when it is a real share: not root, not the Advisor's primary
# group, nobody's primary group, and held by both accounts (for the Advisor,
# naming it in SupplementaryGroups= is holding it).
_tp_shared_group() { # $1 = instance, $2 = unit file, $3 = Advisor account, $4 = dashboard account
  local g="" from_unit=0 st gid
  g="$(systemctl show "aperire-advisord${1:+-$1}.service" -p SupplementaryGroups --value 2>/dev/null || true)"
  g="${g%% *}"
  if [[ -n "$g" ]]; then
    from_unit=1
  else
    st="$(_tp_unit_rw "$2" /advisor/state | head -1)"
    [[ -n "$st" && -d "$st" && ! -L "$st" ]] && g="$(stat -c %g "$st" 2>/dev/null || true)"
  fi
  g="$(_tp_group_name "$g")"
  [[ -n "$g" && "$g" != root && "$g" != UNKNOWN ]] || return 1
  gid="$(_tp_gid "$g")"
  [[ "$gid" =~ ^[0-9]+$ && "$gid" != 0 ]] || return 1
  # Nobody's primary group, the Advisor's included: that is the group the
  # socket is opened to, and the shape this repair exists to undo.
  getent passwd 2>/dev/null | awk -F: -v g="$gid" '$4 == g { f = 1 } END { exit !f }' && return 1
  _tp_holds_group "$4" "$g" || return 1
  [[ $from_unit -eq 1 ]] || _tp_holds_group "$3" "$g" || return 1
  printf '%s' "$g"
}

# Moves one corpus off a group, by descriptor. Root walks a tree the Advisor's
# account can write, so no name is ever resolved twice: each entry is opened
# O_NOFOLLOW relative to its parent's descriptor, checked on that descriptor,
# and changed through it. A link is never followed and never changed. Only an
# entry still in the old group, owned by the Advisor or the dashboard, and
# (a file) with one link, moves; anything else in the old group is printed as
# left, and the caller stops. Bounded: a corpus past the cap is refused, not
# walked.
_TP_REGROUP_PY="$(cat <<'TP_REGROUP_EOF'
import os, stat, sys
root, old_gid, new_gid, uids = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), {int(u) for u in sys.argv[4].split(",") if u}
for _s in (sys.stdout, sys.stderr):
    _s.reconfigure(errors="backslashreplace")

def esc(p):
    # A name the Advisor's account chose, printed on root's terminal (#795):
    # printable ASCII as itself, every other byte and the backslash as \xNN.
    return "".join(chr(c) if 0x20 <= c < 0x7f and c != 0x5c else "\\x%02x" % c for c in os.fsencode(p))
CAP = 200000
moved, left, seen = [0], [], [0]
NF = os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NOCTTY | os.O_NONBLOCK

APPLY = [False]

def fix(fd, st, path):
    if st.st_gid != old_gid:
        return
    is_dir = stat.S_ISDIR(st.st_mode)
    if st.st_uid not in uids or not (is_dir or (stat.S_ISREG(st.st_mode) and st.st_nlink == 1)):
        left.append(path)
        return
    if not APPLY[0]:
        return
    os.fchown(fd, -1, new_gid)
    mode = stat.S_IMODE(os.fstat(fd).st_mode) | stat.S_IWGRP | (stat.S_ISGID if is_dir else 0)
    os.fchmod(fd, mode)
    moved[0] += 1

def walk(dfd, dev, path):
    for name in sorted(os.listdir(dfd)):
        seen[0] += 1
        if seen[0] > CAP:
            raise SystemExit("   %s holds more than %d entries; it was not walked" % (esc(root), CAP))
        sub = path + "/" + name
        try:
            lst = os.stat(name, dir_fd=dfd, follow_symlinks=False)
        except FileNotFoundError:
            continue
        if not (stat.S_ISDIR(lst.st_mode) or stat.S_ISREG(lst.st_mode)):
            # a link (never followed), a socket, a FIFO: nothing the group gives
            if not stat.S_ISLNK(lst.st_mode) and lst.st_gid == old_gid:
                left.append(sub)
            continue
        try:
            fd = os.open(name, os.O_RDONLY | NF | (os.O_DIRECTORY if stat.S_ISDIR(lst.st_mode) else 0), dir_fd=dfd)
        except OSError:
            if lst.st_gid == old_gid:
                left.append(sub)
            continue
        try:
            st = os.fstat(fd)
            if (st.st_ino, st.st_dev) != (lst.st_ino, lst.st_dev) or st.st_dev != dev:
                if st.st_gid == old_gid:
                    left.append(sub)
                continue
            fix(fd, st, sub)
            if stat.S_ISDIR(st.st_mode):
                walk(fd, dev, sub)
        finally:
            os.close(fd)

parent, base = os.path.split(root.rstrip("/"))
pfd = os.open(parent or "/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
try:
    try:
        rfd = os.open(base, os.O_RDONLY | os.O_DIRECTORY | NF, dir_fd=pfd)
    except OSError as e:
        raise SystemExit("   %s could not be opened as a directory, without following a link: %s" % (esc(root), e.strerror))
finally:
    os.close(pfd)
try:
    # Twice: a pass that only looks, then, if nothing would be left behind,
    # the pass that changes. A corpus that cannot be moved whole is not
    # moved at all.
    for APPLY[0] in (False, True):
        seen[0] = 0
        st = os.fstat(rfd)
        fix(rfd, st, root)
        try:
            walk(rfd, st.st_dev, root)
        except RecursionError:
            raise SystemExit("   %s is nested too deep to walk; it was not moved" % esc(root))
        if left:
            break
finally:
    os.close(rfd)
print("moved %d" % moved[0])
for p in left[:10]:
    print("left %s" % esc(p))
if len(left) > 10:
    print("left ... and %d more" % (len(left) - 10))
sys.exit(3 if left else 0)
TP_REGROUP_EOF
)"

# The corpus walk the share and the hand-over make, by descriptor (#795,
# #978). Root walks a tree the Advisor's account can write, so this is the
# regroup walk's discipline: each entry is opened O_NOFOLLOW relative to its
# parent's descriptor, checked on that descriptor (same inode as the name had,
# same filesystem, a file with one link) and changed through it. A link is
# never followed and never changed. What is not a directory or a plain file of
# the corpus's own (a link, a hard link, a socket, a FIFO, an entry swapped
# while it was walked) is skipped and printed, and the walk carries on: those
# were never the corpus's to change. A corpus that cannot be opened as a
# directory without following a link is refused with nothing changed. A walk
# stopped part way (too deep, too big, a change the kernel refused) says how
# much it changed before it stopped. Every name printed is escaped: it is a
# name the Advisor's account chose, on root's terminal. Each walk below is
# this, plus what it does to one entry.
_TP_CORPUS_WALK_PY="$(cat <<'TP_WALK_EOF'
import errno, os, stat, sys
for _s in (sys.stdout, sys.stderr):
    _s.reconfigure(errors="backslashreplace")
CAP = 200000
NF = os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NOCTTY | os.O_NONBLOCK
SWAPPED = (errno.ELOOP, errno.ENOTDIR, errno.ENXIO, errno.EISDIR)
changed, skipped, seen = [0], [], [0]

def esc(p):
    # Printable ASCII as itself, every other byte (and the backslash) as \xNN:
    # no escape code, no newline, nothing a terminal or a locale acts on.
    if not isinstance(p, (str, bytes)):
        p = str(p)
    return "".join(chr(c) if 0x20 <= c < 0x7f and c != 0x5c else "\\x%02x" % c for c in os.fsencode(p))

class Stop(Exception):
    pass

def walk(dfd, dev, path, visit):
    try:
        names = sorted(os.listdir(dfd))
    except OSError as e:
        raise Stop("%s could not be read: %s" % (esc(path), e.strerror))
    for name in names:
        seen[0] += 1
        if seen[0] > CAP:
            raise Stop("it holds more than %d entries" % CAP)
        sub = path + "/" + name
        try:
            lst = os.stat(name, dir_fd=dfd, follow_symlinks=False)
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(lst.st_mode):
            skipped.append((sub, "a symbolic link, never followed"))
            continue
        is_dir = stat.S_ISDIR(lst.st_mode)
        if not (is_dir or stat.S_ISREG(lst.st_mode)):
            skipped.append((sub, "not a file or a directory"))
            continue
        if not is_dir and lst.st_nlink != 1:
            skipped.append((sub, "a hard link: the same file has another name"))
            continue
        try:
            fd = os.open(name, os.O_RDONLY | NF | (os.O_DIRECTORY if is_dir else 0), dir_fd=dfd)
        except FileNotFoundError:
            continue
        except OSError as e:
            if e.errno in SWAPPED:
                skipped.append((sub, "changed while it was walked"))
                continue
            raise Stop("%s could not be opened: %s" % (esc(sub), e.strerror))
        try:
            st = os.fstat(fd)
            if (st.st_ino, st.st_dev) != (lst.st_ino, lst.st_dev) or st.st_dev != dev \
               or stat.S_ISDIR(st.st_mode) != is_dir:
                skipped.append((sub, "changed while it was walked"))
                continue
            if not is_dir and st.st_nlink != 1:
                skipped.append((sub, "a hard link: the same file has another name"))
                continue
            visit(fd, st, sub, False)
            if is_dir:
                walk(fd, dev, sub, visit)
        finally:
            os.close(fd)

def run(root, visit, done, word):
    parent, base = os.path.split(root.rstrip("/"))
    try:
        pfd = os.open(parent or "/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            rfd = os.open(base, os.O_RDONLY | os.O_DIRECTORY | NF, dir_fd=pfd)
        finally:
            os.close(pfd)
    except OSError as e:
        raise SystemExit("   %s could not be opened as a directory, without following a link: %s; nothing was changed"
                         % (esc(root), e.strerror))
    why = None
    try:
        st = os.fstat(rfd)
        visit(rfd, st, root, True)
        walk(rfd, st.st_dev, root, visit)
    except RecursionError:
        why = "it is nested too deep to walk"
    except Stop as e:
        why = str(e)
    finally:
        os.close(rfd)
    if why:
        if changed[0]:
            raise SystemExit("   %s: %s; it is partly %s: %d entries were changed before it stopped"
                             % (esc(root), why, done, changed[0]))
        raise SystemExit("   %s: %s; nothing was changed" % (esc(root), why))
    print("%s %d" % (word, changed[0]))
    print("skips %d" % len(skipped))
    for p, w in skipped[:10]:
        print("skipped %s: %s" % (esc(p), w))
    if len(skipped) > 10:
        print("skipped ... and %d more" % (len(skipped) - 10))

def setmode(fd, path, want):
    try:
        os.fchmod(fd, want)
    except OSError as e:
        raise Stop("%s: its mode could not be set: %s" % (esc(path), e.strerror))
TP_WALK_EOF
)"

# The share (#795): group write on every directory and regular file, setgid
# on every directory. A mode already right is not written again.
_TP_SHARE_PY="$_TP_CORPUS_WALK_PY"$'\n'"$(cat <<'TP_SHARE_EOF'
def share(fd, st, path, top):
    mode = stat.S_IMODE(st.st_mode)
    want = mode | stat.S_IWGRP | (stat.S_ISGID if stat.S_ISDIR(st.st_mode) else 0)
    if want != mode:
        setmode(fd, path, want)
        changed[0] += 1

run(sys.argv[1], share, "shared", "shared")
TP_SHARE_EOF
)"

# The hand-over (#978): every directory and regular file to <uid>:<gid> with
# fchown, the world bits cleared, and the corpus itself 0750 (its setuid and
# setgid bits kept, as GNU chmod keeps them on a directory for an octal mode).
# It only takes bits away and only gives entries of the corpus's own to the
# account. -1 for <gid> leaves the group as it is.
#
# An optional fifth argument, "<uid>:<dev>:<ino>", is the corpus a plan judged
# (#989). The corpus opened here is checked against it before anything is
# changed, and a different directory (a sibling renamed into the name after
# the plan, say) is refused with nothing changed.
_TP_HANDOVER_PY="$_TP_CORPUS_WALK_PY"$'\n'"$(cat <<'TP_HANDOVER_EOF'
uid, gid, clear_other = int(sys.argv[2]), int(sys.argv[3]), sys.argv[4] == "1"
planned = None
if len(sys.argv) > 5 and sys.argv[5]:
    try:
        planned = tuple(int(x) for x in sys.argv[5].split(":"))
    except ValueError:
        planned = ()
    if len(planned) != 3:
        raise SystemExit("   the planned corpus is not <uid>:<dev>:<ino>: %s; nothing was changed" % esc(sys.argv[5]))

def hand(fd, st, path, top):
    if top and planned is not None:
        if (st.st_dev, st.st_ino) != planned[1:]:
            raise Stop("it is not the directory that was planned (a different directory is at that name now)")
        if st.st_uid != planned[0]:
            raise Stop("its owner is uid %d, not uid %d as planned" % (st.st_uid, planned[0]))
    did = False
    if st.st_uid != uid or (gid != -1 and st.st_gid != gid):
        try:
            os.fchown(fd, uid, gid)
        except OSError as e:
            raise Stop("%s: its owner could not be set: %s" % (esc(path), e.strerror))
        st = os.fstat(fd)
        did = True
    mode = stat.S_IMODE(st.st_mode)
    if top:
        want = 0o750 | (mode & (stat.S_ISUID | stat.S_ISGID))
    elif clear_other:
        want = mode & ~0o007
    else:
        want = mode
    if want != mode:
        setmode(fd, path, want)
        did = True
    if did:
        changed[0] += 1

run(sys.argv[1], hand, "handed over", "handed")
TP_HANDOVER_EOF
)"

# The two tokens the dashboard reads out of the Advisor's state directory,
# moved off the Advisor's group by descriptor, group only: a token keeps its
# mode. approve.token is the one that needs it. Before #799, advisord
# regenerated it with its own primary group when it was missing (ensureToken
# had no chown, unlike ensureReadToken), so on a host where that happened the
# dashboard reads it only through the membership this repair removes. A
# regeneration now takes the state directory's group, but one from before still
# needs this. Same rules as the corpus walk: the state
# directory opened without following a link, each token O_NOFOLLOW against it,
# and only a regular file of the Advisor's own, with one link, moves.
_TP_TOKEN_REGROUP_PY="$(cat <<'TP_TOKEN_EOF'
import os, stat, sys
state, old_gid, new_gid, uid = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
NF = os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NOCTTY | os.O_NONBLOCK
parent, base = os.path.split(state.rstrip("/"))
pfd = os.open(parent or "/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
try:
    try:
        dfd = os.open(base, os.O_RDONLY | os.O_DIRECTORY | NF, dir_fd=pfd)
    except FileNotFoundError:
        sys.exit(0)
    except OSError as e:
        raise SystemExit("   %s could not be opened as a directory, without following a link: %s" % (state, e.strerror))
finally:
    os.close(pfd)
left, plan = [], []
try:
    for name in ("approve.token", "read.token"):
        try:
            lst = os.stat(name, dir_fd=dfd, follow_symlinks=False)
        except FileNotFoundError:
            continue
        if lst.st_gid != old_gid:
            continue
        if not stat.S_ISREG(lst.st_mode) or lst.st_uid != uid or lst.st_nlink != 1:
            left.append(name)
            continue
        plan.append(name)
    if not left:
        for name in plan:
            fd = os.open(name, os.O_RDONLY | NF, dir_fd=dfd)
            try:
                st = os.fstat(fd)
                if not stat.S_ISREG(st.st_mode) or st.st_uid != uid or st.st_nlink != 1:
                    left.append(name)
                    continue
                if st.st_gid == old_gid:
                    os.fchown(fd, -1, new_gid)
                    print("moved %s" % name)
            finally:
                os.close(fd)
finally:
    os.close(dfd)
for name in left:
    print("left %s/%s" % (state, name))
sys.exit(3 if left else 0)
TP_TOKEN_EOF
)"

_tp_repair_advisor_group() { # $1 = install tree, $2 = instance, $3 = Advisor account, $4 = unit file
  local tree="$1" inst="$2" acct="$3" unit="$4"
  local gid gname dash others o shared sgid auid duid corpus out rc dunit pid
  local -a corpora=()
  gid="$(getent passwd "$acct" 2>/dev/null | head -1 | cut -d: -f4)"
  [[ "$gid" =~ ^[1-9][0-9]*$ ]] || return 0
  others="$(_tp_group_others "$acct" "$gid")"
  [[ -n "$others" ]] || return 0
  dash="$(_tp_dash_user "$inst")"
  # Only the one shape #245 made. Anything else is the socket writer's
  # refusal, which names every holder and changes nothing.
  [[ -n "$dash" && "$dash" != root && "$dash" != "$acct" && "$others" == "$dash" ]] || return 0
  gname="$(_tp_group_name "$gid")"
  [[ -n "$gname" ]] && _tp_listed_member "$dash" "$gname" || return 0

  printf '   %s, the dashboard'"'"'s account, is a member of %s, the Advisor'"'"'s own group.\n' "$dash" "$gname"
  printf '   The Advisor'"'"'s socket is opened to that group, so the dashboard comes out of it first.\n'
  if ! shared="$(_tp_shared_group "$inst" "$unit" "$acct" "$dash")"; then
    printf '   No group shared by %s and %s is named on this host, so nothing was changed.\n' "$acct" "$dash" >&2
    printf '   install-advisor-account.sh names one (aperire-svc on a standard install). Run:\n' >&2
    printf '     curl -fsSL https://get.aperire.one | bash -s -- --update --force\n' >&2
    return 1
  fi
  sgid="$(_tp_gid "$shared")"
  auid="$(id -u "$acct" 2>/dev/null)"
  duid="$(id -u "$dash" 2>/dev/null)"
  [[ "$auid" =~ ^[0-9]+$ && "$duid" =~ ^[0-9]+$ ]] || { printf '   %s or %s has no uid here; nothing was changed\n' "$acct" "$dash" >&2; return 1; }

  mapfile -t corpora < <(_tp_unit_rw "$unit" /advisor/knowledge-fleet)
  [[ ${#corpora[@]} -gt 0 ]] || corpora=("$tree/advisor/knowledge-fleet")
  for corpus in "${corpora[@]}"; do
    [[ -e "$corpus" || -L "$corpus" ]] || continue
    rc=0
    out="$(python3 -I -c "$_TP_REGROUP_PY" "$corpus" "$gid" "$sgid" "$auid,$duid" 2>&1)" || rc=$?
    if [[ $rc -ne 0 ]]; then
      printf '%s\n' "$out" | sed -n 's/^left /     still in '"$gname"': /p; /^   /p' >&2
      printf '   The fleet corpus %s still needs %s, so %s stays in it and nothing\n' "$corpus" "$gname" "$dash" >&2
      printf '   else was changed. Move what is named above to %s (or remove it), then:\n' "$shared" >&2
      printf '     curl -fsSL https://get.aperire.one | bash -s -- --update --force\n' >&2
      return 1
    fi
    o="$(sed -n 's/^moved //p' <<<"$out")"
    if [[ "${o:-0}" != 0 ]]; then
      printf '   moved the fleet corpus %s from %s to %s: %s entries, group-writable, setgid on directories\n' "$corpus" "$gname" "$shared" "$o"
    fi
  done

  local state t
  state="$(_tp_unit_rw "$unit" /advisor/state | head -1)"
  [[ -n "$state" ]] || state="$tree/advisor/state"
  rc=0
  out="$(python3 -I -c "$_TP_TOKEN_REGROUP_PY" "$state" "$gid" "$sgid" "$auid" 2>&1)" || rc=$?
  if [[ $rc -ne 0 ]]; then
    printf '%s\n' "$out" | sed -n 's/^left /     still in '"$gname"': /p; /^   /p' >&2
    printf '   The dashboard reads that token only through %s, so %s stays in it.\n' "$gname" "$dash" >&2
    printf '   Put it in %s (chgrp %s <file>, as root), then:\n' "$shared" "$shared" >&2
    printf '     curl -fsSL https://get.aperire.one | bash -s -- --update --force\n' >&2
    return 1
  fi
  while IFS= read -r t; do
    [[ -n "$t" ]] && printf '   moved %s/%s from %s to %s, mode unchanged: the dashboard reads it through %s\n' "$state" "$t" "$gname" "$shared" "$shared"
  done < <(sed -n 's/^moved //p' <<<"$out")

  gpasswd -d "$dash" "$gname" >/dev/null 2>&1 \
    || { printf '   gpasswd -d %s %s failed; %s is still in %s\n' "$dash" "$gname" "$dash" "$gname" >&2; return 1; }
  others="$(_tp_group_others "$acct" "$gid")"
  if [[ -n "$others" ]]; then
    printf '   %s still lists: %s, after gpasswd -d %s %s\n' "$gname" "$others" "$dash" "$gname" >&2
    return 1
  fi
  printf '   removed %s from %s (gpasswd -d %s %s). It keeps %s, which is how it shares\n' "$dash" "$gname" "$dash" "$gname" "$shared"
  printf '   the Advisor'"'"'s tokens and the fleet corpus. No other account was changed.\n'

  # Group membership is fixed when a process starts. A dashboard started
  # before the line above still holds the group until it restarts, and so
  # does every other process of that account (an operator's open shells, if
  # it is a login). Until then the socket's mode lets such a process connect,
  # and the broker refuses it on its uid (SO_PEERCRED) before it reads a
  # byte: one check holds instead of two. Said here, from /proc, not assumed.
  for dunit in "aperire-server${inst:+-$inst}" "aperire-read${inst:+-$inst}"; do
    [[ -f "$TP_UNIT_DIR/$dunit.service" ]] || continue
    pid="$(systemctl show "$dunit.service" -p MainPID --value 2>/dev/null)"
    [[ "$pid" =~ ^[1-9][0-9]*$ ]] || continue
    if awk '/^Groups:/ { for (i = 2; i <= NF; i++) if ($i == g) f = 1 } END { exit !f }' g="$gid" "$TP_PROC_DIR/$pid/status" 2>/dev/null; then
      printf '   %s (pid %s) started before this and still holds %s until it restarts:\n' "$dunit" "$pid" "$gname"
      printf '     sudo systemctl restart %s\n' "$dunit"
      printf '   Until then it can open the Advisor'"'"'s socket, and the socket refuses it: the broker\n'
      printf '   admits only %s'"'"'s uid (%s). So do any open sessions of %s from before now.\n' "$acct" "$auid" "$dash"
    fi
  done
  return 0
}

# Is the socket there, and shaped as written? Read back, never assumed: not a
# link, a socket, root's, with the account's group, 0660.
trusted_socket_ready() { # $1 = instance, $2 = the gid it must carry
  local sock got
  sock="$(trusted_socket_path "$1")"
  if [[ -L "$sock" || ! -S "$sock" ]]; then
    printf '   %s is not listening at %s. Read: systemctl status %s\n' "$(trusted_socket_unit "$1")" "$sock" "$(trusted_socket_unit "$1")" >&2
    return 1
  fi
  got="$(stat -c '%u %g %a' "$sock" 2>/dev/null)"
  if [[ "$got" != "0 $2 660" ]]; then
    printf '   %s is uid/gid/mode %s, not 0 %s 660; either the Advisor cannot connect or somebody else can\n' "$sock" "${got:-unknown}" "$2" >&2
    return 1
  fi
  return 0
}

# One read through the socket as the Advisor's own account, with the
# Advisor's own client (--wrapper-call) and under no_new_privs where this
# host can set it: the route the Advisor takes, not a second client that
# could agree with the broker while the Advisor's did not. Listening is not
# answering: a broker that cannot start (no interpreter, a refused copy, a
# unit typo) leaves a socket that accepts and closes. The client runs as the
# account, never as root. The verb is `resources`, which the wrapper answers
# on every host shape: a node verb is refused by the wrapper itself on a host
# with SERVICE=none, so asking one there read every aggregator's working
# socket as broken (#806).
_tp_socket_probe() { # $1 = account, $2 = the Advisor's binary, $3 = wrapper, $4 = socket
  local -a nnp=()
  local out
  if command -v setpriv >/dev/null 2>&1 && setpriv --no-new-privs true 2>/dev/null; then
    nnp=(setpriv --no-new-privs)
  fi
  # Its own session, no terminal and no input (#779 review, L6): nothing
  # this tree's binary does while it runs as the account can reach the
  # operator's terminal.
  if out="$(timeout 120 setsid -w runuser -u "$1" -- ${nnp[@]+"${nnp[@]}"} "$2" --wrapper="$3" --wrapper-socket="$4" --wrapper-call resources 2>&1 >/dev/null </dev/null)"; then
    return 0
  fi
  printf '   %s did not answer %s through its own client: %s\n' "$4" "$1" "$(tail -3 <<<"${out:-no output}" | tr '\n' ' ')" >&2
  return 1
}

# The Advisor unit's own route, read off the unit: its account, its binary,
# the wrapper and the socket it names. One line, tab-separated, or nothing.
_tp_unit_route() { # $1 = unit file
  local user exec bin wrapper sock
  user="$(awk -F= '/^User=/{print $2; exit}' "$1" 2>/dev/null)"
  exec="$(grep -m1 '^ExecStart=' "$1" 2>/dev/null)"
  bin="${exec#ExecStart=}"; bin="${bin%% *}"
  wrapper="$(grep -oE -- '--wrapper=[^ ]+' <<<"$exec" | head -1 | cut -d= -f2-)"
  sock="$(grep -oE -- '--wrapper-socket=[^ ]+' <<<"$exec" | head -1 | cut -d= -f2-)"
  printf '%s\t%s\t%s\t%s\n' "$user" "$bin" "$wrapper" "$sock"
}

trusted_remove_socket_units() { # $1 = instance
  local inst="$1"
  systemctl disable --now "$(trusted_socket_unit "$inst")" >/dev/null 2>&1 || true
  rm -f "$TP_UNIT_DIR/$(trusted_socket_unit "$inst")" "$TP_UNIT_DIR/$(trusted_socket_service "$inst")"
  systemctl daemon-reload 2>/dev/null || true
}

# The Advisor unit an update finds, brought to the socket shape in place:
# --sudo-wrapper becomes --wrapper-socket=, NoNewPrivileges and
# RestrictSUIDSGID become true, the empty capability set and the syscall
# filter install-advisord.sh already runs on systemd 249 go in where they are
# missing, and ReadWritePaths= keeps only the Advisor's own three directories:
# the wrapper no longer runs inside this unit's mount namespace, so the
# node's directories and /var/lib/aperire are nothing it needs. Every other
# line is kept. 0 converted or already so, 1 not written.
_TP_CONVERT_PY="$(cat <<'TP_CONVERT_EOF'
import re, sys
path, sock = sys.argv[1], sys.argv[2]
src = open(path).read()
lines = src.split("\n")
out, in_svc, saw_cap, saw_scf, changed = [], False, False, False, []
saw_rw = False
# The tree this unit runs from, off its own binary: <tree>/advisor/bin/aperire-advisord.
# The writable set is exactly that tree's three directories, by prefix, never
# any path that merely ends the same way (#779 review, L5).
repo = None
for ln in lines:
    if ln.startswith("ExecStart="):
        b = ln[len("ExecStart="):].split()[0] if ln[len("ExecStart="):].split() else ""
        b = b.lstrip("-@:+!")
        if b.endswith("/advisor/bin/aperire-advisord"):
            repo = b[: -len("/advisor/bin/aperire-advisord")]
        break
if not repo:
    sys.stderr.write("   %s does not start <tree>/advisor/bin/aperire-advisord, so its writable paths cannot be named; it is left as it is\n" % path)
    sys.exit(1)
own_rw = [repo + "/advisor/state", repo + "/advisor/evidence", repo + "/advisor/knowledge-fleet"]
stale_comments = (
    "# NoNewPrivileges must stay false",
    "# wrapper is now the ONLY way this service reaches the node at all.",
    "# RestrictSUIDSGID must stay false for the same reason",
)
for ln in lines:
    if ln.startswith("["):
        if in_svc and ln.strip() != "[Service]":
            if not saw_rw:
                out.append("ReadWritePaths=" + " ".join(own_rw)); changed.append("ReadWritePaths= (only this tree's own three directories)")
                saw_rw = True
            if not saw_cap:
                out.append("CapabilityBoundingSet="); changed.append("CapabilityBoundingSet= (empty)")
            if not saw_scf:
                out += ["SystemCallFilter=@system-service", "SystemCallFilter=~@privileged @resources",
                        "SystemCallFilter=setrlimit prlimit64 chown fchown fchownat lchown"]
                changed.append("the syscall filter")
        in_svc = ln.strip() == "[Service]"
    if in_svc and ln.startswith(stale_comments):
        changed.append("a comment about sudo"); continue
    if in_svc and ln.startswith("ExecStart="):
        new = re.sub(r" --sudo-wrapper(?= |$)", "", ln)
        new = re.sub(r" --wrapper-socket=\S+", "", new)
        if re.search(r" --wrapper=\S+", new):
            new += " --wrapper-socket=" + sock
        if new != ln:
            changed.append("ExecStart= (--wrapper-socket=%s)" % sock)
        ln = new
    elif in_svc and re.match(r"^\s*NoNewPrivileges\s*=", ln):
        # Whatever spelling it had (false, no, 0, off), it is true now.
        if ln != "NoNewPrivileges=true":
            changed.append("NoNewPrivileges=true")
        ln = "NoNewPrivileges=true"
    elif in_svc and re.match(r"^\s*RestrictSUIDSGID\s*=", ln):
        if ln != "RestrictSUIDSGID=true":
            changed.append("RestrictSUIDSGID=true")
        ln = "RestrictSUIDSGID=true"
    elif in_svc and re.match(r"^\s*ReadWritePaths\s*=", ln):
        if ln.rstrip().endswith("\\"):
            sys.stderr.write("   ReadWritePaths= continues onto another line in %s; it is left as it is\n" % path)
            sys.exit(1)
        # One line, naming the tree's three directories and nothing else;
        # any further ReadWritePaths= lines go.
        if saw_rw:
            changed.append("a second ReadWritePaths= line")
            continue
        saw_rw = True
        new = "ReadWritePaths=" + " ".join(own_rw)
        if ln != new:
            changed.append("ReadWritePaths= (only this tree's own three directories)")
        ln = new
    elif in_svc and re.match(r"^\s*CapabilityBoundingSet\s*=", ln):
        # Empty, whatever it named, and said once: the Advisor needs no
        # capability at all.
        if saw_cap:
            changed.append("a second CapabilityBoundingSet= line")
            continue
        saw_cap = True
        if ln != "CapabilityBoundingSet=":
            changed.append("CapabilityBoundingSet= (empty)")
        ln = "CapabilityBoundingSet="
    elif in_svc and ln.startswith("SystemCallFilter="):
        saw_scf = True
    out.append(ln)
if in_svc:
    if not saw_rw:
        out.append("ReadWritePaths=" + " ".join(own_rw)); changed.append("ReadWritePaths= (only this tree's own three directories)")
    if not saw_cap:
        out.append("CapabilityBoundingSet="); changed.append("CapabilityBoundingSet= (empty)")
    if not saw_scf:
        out += ["SystemCallFilter=@system-service", "SystemCallFilter=~@privileged @resources",
                "SystemCallFilter=setrlimit prlimit64 chown fchown fchownat lchown"]
        changed.append("the syscall filter")
res = "\n".join(out)
if res != src:
    sys.stdout.write(res)
    for c in changed:
        sys.stderr.write("CHANGED\t%s\n" % c)
    sys.exit(10)
sys.exit(0)
TP_CONVERT_EOF
)"

trusted_convert_advisor_unit() { # $1 = instance
  local inst="$1" unit tmp rc=0 notes
  unit="$TP_UNIT_DIR/aperire-advisord${inst:+-$inst}.service"
  [[ -f "$unit" ]] || return 0
  tmp="$(mktemp)" || return 1
  notes="$(python3 -I -c "$_TP_CONVERT_PY" "$unit" "$(trusted_socket_path "$inst")" 2>&1 >"$tmp")" || rc=$?
  if [[ $rc -eq 0 ]]; then rm -f "$tmp"; return 0; fi
  if [[ $rc -ne 10 ]]; then rm -f "$tmp"; printf '%s\n' "$notes" >&2; return 1; fi
  # The Advisor running now was started on the old route. Which start of the
  # unit that was is written down before the unit changes, in a root-owned
  # file, because that id is the one fact the Advisor cannot rewrite (#780).
  _tp_note_old_start "$inst" "$unit" || { rm -f "$tmp"; return 1; }
  _tp_put_root_file "$unit" < "$tmp" || { rm -f "$tmp"; return 1; }
  rm -f "$tmp"
  systemctl daemon-reload 2>/dev/null || true
  printf '   %s now reaches the wrapper through its socket, with no sudo:\n' "$unit"
  sed -n 's/^CHANGED\t/     /p' <<<"$notes"
  return 0
}

# Which start of the Advisor's unit predates the unit's conversion. systemd
# gives every start of a unit its own InvocationID; the Advisor cannot change
# it, and an exec keeps it. The file is root's, in the library directory.
_tp_old_start_file() { printf '%s/advisord-sudo-invocation%s' "$TP_LIB_DIR" "${1:+-$1}"; }

_tp_invocation() { # $1 = instance; the running unit's id, or nothing
  systemctl show "aperire-advisord${1:+-$1}.service" -p InvocationID --value 2>/dev/null | head -1
}

_tp_note_old_start() { # $1 = instance, $2 = the unit file, still the old one
  local inst="$1" unit="$2" id file
  file="$(_tp_old_start_file "$inst")"
  # A unit already on its socket has no old route to note, and a record from
  # the conversion that did is kept: it is still the start that needs the
  # restart.
  grep -q -- '--sudo-wrapper' "$unit" && ! grep -q -- '--wrapper-socket=' "$unit" || return 0
  [[ "$(systemctl is-active "aperire-advisord${inst:+-$inst}.service" 2>/dev/null)" == active ]] || { rm -f -- "$file"; return 0; }
  id="$(_tp_invocation "$inst")"
  [[ "$id" =~ ^[A-Za-z0-9-]+$ ]] || { rm -f -- "$file"; return 0; }
  _tp_libdir && printf '%s\n' "$id" | _tp_put_root_file "$file"
}

# When the process started, in epoch seconds, from the kernel's own record:
# btime plus the start time in /proc/<pid>/stat, which the process cannot
# change. The command name there is the process's to set and may hold a ")",
# so the fields are counted from the last one.
_tp_start_epoch() { # $1 = pid
  local line rest ticks btime tck
  line="$(cat "$TP_PROC_DIR/$1/stat" 2>/dev/null)" || return 1
  rest="${line##*) }"
  ticks="$(awk '{print $20}' <<<"$rest")"
  btime="$(awk '$1=="btime"{print $2; exit}' "$TP_PROC_DIR/stat" 2>/dev/null)"
  tck="$(getconf CLK_TCK 2>/dev/null)"
  [[ "$tck" =~ ^[1-9][0-9]*$ ]] || tck=100
  [[ "$ticks" =~ ^[0-9]+$ && "$btime" =~ ^[0-9]+$ ]] || return 1
  printf '%s' $(( btime + ticks / tck ))
}

# Is this instance's Advisor running, and is it the start that predates the
# conversion? Read from systemd and the kernel, never from what the process
# says about itself: its command line is its own to rewrite, and a compromised
# Advisor could read as old for good and keep a grant (#780). "old" is the
# start recorded when the unit was converted; a restart, a crash or anything
# else gives a new id. With no record we can trust (a host the previous
# release converted, or a record in a directory others can write), the start
# time is held against the unit file's own time: a process that started
# before its unit last changed is still on what the unit used to say.
_tp_advisord_state() { # $1 = instance; prints "stopped", "socket" or "old"
  local unit file was now pid start mtime
  unit="aperire-advisord${1:+-$1}.service"
  [[ "$(systemctl is-active "$unit" 2>/dev/null)" == active ]] || { echo stopped; return 0; }
  file="$(_tp_old_start_file "$1")"
  if [[ -f "$file" ]] && _tp_root_only "$file" && _tp_root_only "$TP_LIB_DIR"; then
    was="$(head -1 -- "$file" 2>/dev/null)"
    now="$(_tp_invocation "$1")"
    if [[ -n "$was" && "$was" == "$now" ]]; then echo old; else echo socket; fi
    return 0
  fi
  # The start-time reading is only for a host that still has a rule to keep or
  # take away. Without one, a unit rewritten after the Advisor started (a
  # sandbox change, a --wrapper= repoint, a hand edit) is no sign the Advisor
  # is on a route that is gone (#780 re-review).
  [[ -e "$TP_SUDOERS_DIR/aperire-advisor${1:+-$1}" || -L "$TP_SUDOERS_DIR/aperire-advisor${1:+-$1}" ]] || { echo socket; return 0; }
  pid="$(systemctl show "$unit" -p MainPID --value 2>/dev/null)"
  [[ "$pid" =~ ^[1-9][0-9]*$ ]] || { echo socket; return 0; }
  start="$(_tp_start_epoch "$pid")" || { echo socket; return 0; }
  mtime="$(stat -c %Y -- "$TP_UNIT_DIR/$unit" 2>/dev/null)"
  [[ "$mtime" =~ ^[0-9]+$ ]] || { echo socket; return 0; }
  if (( start < mtime )); then
    # Written down now, from the id this start has, so the rule's removal
    # leaves the record the later runs read.
    now="$(_tp_invocation "$1")"
    if [[ "$now" =~ ^[A-Za-z0-9-]+$ ]] && _tp_libdir; then
      printf '%s\n' "$now" | _tp_put_root_file "$file" || true
    fi
    echo old
  else
    echo socket
  fi
}

# What a rule this library is about to remove held, so a line that was the
# operator's own can be moved to a file of their own.
_tp_say_rule_lines() { # $1 = rule file
  local line n=0
  [[ -f "$1" && ! -L "$1" ]] || return 0
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" =~ ^[[:space:]]*(#.*)?$ ]] && continue
    (( n++ )) || printf '   it held these lines; move any that are yours to a file of your own:\n'
    printf '     %s\n' "$line"
  done < "$1"
}

# Is every line of an older release's sudo rule one this library vouches for?
# The shape its own writer left and nothing else: comments, one grant of one
# program to one account, and that account's !requiretty and secure_path. The
# program is the root-owned copy, or the tree's wrapper when the walk to it is
# clean. A rule is read as text and any line it does not know is a no, so a
# second grant, a Defaults line, an #include, a continuation or a comma list
# cannot ride along. Says why not, on stderr (#780). $1 = rule file,
# $2 = instance, $3 = install tree ("" for none).
_tp_rule_vouch() {
  local rule="$1" inst="$2" tree="$3" line acct="" prog="" want crc d dn dv comp sp_ok uuser bad=""
  local -a defs=()
  local grant_re='^([A-Za-z_][A-Za-z0-9_.-]*)[[:space:]]+ALL=\(root\)[[:space:]]+NOPASSWD:[[:space:]]+(/[A-Za-z0-9_./-]+)[[:space:]]*$'
  local def_re='^Defaults:([A-Za-z_][A-Za-z0-9_.-]*)[[:space:]]+(.+)$'
  [[ -e "$rule" || -L "$rule" ]] || return 0
  if [[ -L "$rule" || ! -f "$rule" ]]; then
    printf '   REFUSED: the sudo rule %s is not a plain file\n' "$rule" >&2
    return 1
  fi
  want="$(trusted_wrapper_path "$inst")"
  while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ "$line" == *\\ ]]; then
      bad="a line continued with a backslash"
    elif [[ "$line" =~ ^[[:space:]]*$ ]] || [[ "$line" =~ ^[[:space:]]*#([[:space:]].*)?$ ]]; then
      continue
    elif [[ "$line" =~ $grant_re ]]; then
      if [[ -n "$acct" ]]; then bad="a second grant"; else acct="${BASH_REMATCH[1]}"; prog="${BASH_REMATCH[2]}"; fi
    elif [[ "$line" =~ $def_re ]]; then
      defs+=("${BASH_REMATCH[1]} ${BASH_REMATCH[2]}")
    else
      bad="a line this release did not write"
    fi
    [[ -z "$bad" ]] || break
  done < "$rule"
  if [[ -z "$bad" ]]; then
    if [[ -z "$acct" ]]; then
      [[ ${#defs[@]} -eq 0 ]] || bad="settings with no grant"
    elif [[ "$acct" == ALL ]]; then
      bad="a grant to every account"
    fi
  fi
  if [[ -z "$bad" && -n "$acct" ]]; then
    # The account the rule names is the account the Advisor's unit runs as,
    # literally: not another login, and not an alias defined in some other
    # file.
    uuser="$(awk -F= '/^User=/{print $2; exit}' "$TP_UNIT_DIR/aperire-advisord${inst:+-$inst}.service" 2>/dev/null)"
    [[ -n "$uuser" && "$acct" == "$uuser" ]] || bad="a grant to $acct, which is not the account the Advisor's unit runs as"
  fi
  if [[ -z "$bad" ]]; then
    for d in "${defs[@]}"; do
      dn="${d%% *}"; dv="${d#* }"
      if [[ "$dn" != "$acct" ]]; then bad="settings for another account"; break; fi
      case "$dv" in
        '!requiretty') ;;
        secure_path=*)
          sp_ok=1
          while IFS= read -r comp; do
            case "$comp" in /usr/local/sbin|/usr/local/bin|/usr/sbin|/usr/bin|/sbin|/bin|/snap/bin) ;; *) sp_ok=0 ;; esac
          done < <(tr ':' '\n' <<<"${dv#secure_path=}")
          [[ $sp_ok -eq 1 ]] || bad="a secure_path outside the system directories"
          ;;
        *) bad="a setting this release did not write (Defaults:$dn $dv)" ;;
      esac
      [[ -z "$bad" ]] || break
    done
  fi
  if [[ -z "$bad" && -n "$prog" && "$prog" != "$want" ]]; then
    if [[ "$prog" != */scripts/aperire-node-wrapper.sh || "$prog" == *//* || "$prog" == */./* || "$prog" == */../* ]]; then
      bad="a program that is neither the root-owned copy nor a tree's wrapper ($prog)"
    else
      crc=0
      trusted_path_check "$prog" "$tree" >/dev/null 2>&1 || crc=$?
      # Clean or the pre-migration login only: the rule is what it was, and
      # the check's own warning says so. Anything else, including a path that
      # cannot even be walked, is a grant nobody can vouch for.
      if [[ $crc -ne 0 && $crc -ne 3 ]]; then
        printf '   REFUSED: the sudo rule %s still grants %s as root,\n' "$rule" "$prog" >&2
        printf '   and it is not a file only root and the install owner can change.\n' >&2
        return 1
      fi
    fi
  fi
  if [[ -n "$bad" ]]; then
    printf '   REFUSED: the sudo rule %s holds %s,\n' "$rule" "$bad" >&2
    printf '   which is not the one-program grant this release writes.\n' >&2
    return 1
  fi
  return 0
}

# The sudo rule, gone, once nothing running depends on it. A running Advisor
# started before its unit was converted still reaches the node through that
# rule, and taking the rule first would cut it off mid-operation, so it stays
# until that process restarts (#756's reading). Only a rule this library
# vouches for is kept (_tp_rule_vouch); any other is removed, and the process
# that was still on it is told to restart. That start is remembered until the
# unit gets a new one, so a run after the rule is gone still says so. 0 gone
# or never here and nothing running on it, 5 kept for a running process that
# has not restarted yet, or removed under one that has not, 1 not removable,
# 6 refused (an unconverted unit still needs a rule that is not the
# one-program grant).
trusted_drop_sudo_rule() { # $1 = instance, $2 = the install tree ("" when the caller has none)
  local inst="$1" tree="${2:-}" rule unit route user bin wrapper sock why why_line lines
  rule="$TP_SUDOERS_DIR/aperire-advisor${inst:+-$inst}"
  unit="$TP_UNIT_DIR/aperire-advisord${inst:+-$inst}.service"
  if [[ ! -e "$rule" && ! -L "$rule" ]]; then
    if [[ -f "$unit" ]] && grep -q -- '--wrapper-socket=' "$unit" && [[ "$(_tp_advisord_state "$inst")" == old ]]; then
      printf '   aperire-advisord%s started before this change and may still reach the node through\n' "${inst:+-$inst}"
      printf '   a sudo rule that is gone; restart it to reach the node through its socket\n'
      return 5
    fi
    rm -f -- "$(_tp_old_start_file "$inst")"
    return 0
  fi
  # An Advisor that reaches a wrapper at all has to be on its socket, and the
  # socket has to answer it, before the rule goes. Otherwise the rule is the
  # only route a running Advisor may still have, and this keeps it.
  if [[ -f "$unit" ]] && grep -q -- '--wrapper=' "$unit"; then
    if ! grep -q -- '--wrapper-socket=' "$unit"; then
      # Nothing replaces this rule yet, so it cannot be dropped, but it is
      # not kept on trust either.
      _tp_rule_vouch "$rule" "$inst" "$tree" || return 6
      printf '   %s stays: aperire-advisord%s is not on its root socket yet\n' "$rule" "${inst:+-$inst}" >&2
      return 1
    fi
    if [[ "$(_tp_advisord_state "$inst")" == old ]]; then
      if ! why="$(_tp_rule_vouch "$rule" "$inst" "$tree" 2>&1)"; then
        # The unit is on its socket already, so the rule is not the Advisor's
        # only route. Keeping a grant nobody vouches for is worse than a
        # restart the Advisor needs anyway, and 5 makes the caller say so.
        lines="$(_tp_say_rule_lines "$rule")"
        rm -f -- "$rule" || return 1
        printf '   removed %s: it was not kept for the running Advisor.\n' "$rule"
        while IFS= read -r why_line; do printf '%s\n' "${why_line/#   REFUSED: /   }"; done <<<"$why"
        [[ -z "$lines" ]] || printf '%s\n' "$lines"
        printf '   aperire-advisord%s still runs on its old start and has lost that route;\n' "${inst:+-$inst}"
        printf '   restart it to reach the node through its socket\n'
        return 5
      fi
      printf '   %s stays for now: the running Advisor was started on it, before this\n' "$rule"
      printf '   change, and still uses it. It goes the next time this runs after\n'
      printf '   aperire-advisord%s restarts.\n' "${inst:+-$inst}"
      return 5
    fi
    route="$(_tp_unit_route "$unit")"
    IFS=$'\t' read -r user bin wrapper sock <<<"$route"
    if ! _tp_socket_probe "$user" "$bin" "$wrapper" "$sock"; then
      printf '   %s stays: the socket did not answer the Advisor, so nothing is taken away until it does\n' "$rule" >&2
      return 1
    fi
  fi
  why=""
  _tp_rule_vouch "$rule" "$inst" "$tree" >/dev/null 2>&1 || why="$(_tp_say_rule_lines "$rule")"
  rm -f -- "$rule" "$(_tp_old_start_file "$inst")" || return 1
  printf '   removed %s: the Advisor holds no sudo rule (ADR 0025)\n' "$rule"
  [[ -z "$why" ]] || printf '%s\n' "$why"
  return 0
}

# The account the dashboard of this instance runs as, "" when there is none.
_tp_dash_user() { # $1 = instance
  local u f user
  for u in "aperire-server${1:+-$1}" "aperire-read${1:+-$1}"; do
    f="$TP_UNIT_DIR/$u.service"
    [[ -r "$f" ]] || continue
    user="$(awk -F= '/^User=/{print $2; exit}' "$f")"
    [[ -n "$user" ]] && { printf '%s' "$user"; return 0; }
  done
  return 0
}

# Why this Advisor is on a shared account, or nothing when it has its own.
# Shared: no User= at all, the dashboard's account, a login, or an account in
# a group that is root on the host by itself. Each of those makes the socket
# pointless, since that account can already do anything the wrapper can.
_tp_shared_reason() { # $1 = instance, $2 = the unit's User=
  local user="$2" dash why
  [[ -n "$user" && "$user" != root && "$user" != 0 ]] || { printf 'it runs with no account of its own'; return 0; }
  dash="$(_tp_dash_user "$1")"
  [[ -n "$dash" && "$user" == "$dash" ]] && { printf 'it runs as %s, the dashboard'"'"'s account' "$user"; return 0; }
  _tp_is_login "$user" && { printf 'it runs as %s, a login' "$user"; return 0; }
  why="$(_tp_root_equivalent "$user" "" "")" && { printf 'it runs as %s, which %s' "$user" "$why"; return 0; }
  return 1
}

# One instance's Advisor, brought to what a fresh install leaves: the unit's
# --wrapper= names the placed copy; on its own account it reaches that copy
# through the socket, with the full sandbox, and holds no sudo rule. An
# Advisor on a shared account cannot be converted in place: moving it is
# install-advisor-account.sh, which restarts services and plants a reveal
# window, so it is never run from here (#641); this names it and returns 7.
# 0 converged, 5 converged but a running process has not restarted (its rule
# is kept, or was removed under it), 6 a rule that is not the one-program grant
# on a unit that still needs it, 7 the
# account move is needed, 1 something failed while the Advisor still has a
# route, 8 something failed after its binary lost every route but the socket
# (it is stranded at its next start, and the caller says so loudly).
trusted_converge_advisor() { # $1 = install tree, $2 = instance, $3 = 1 when this instance has a wrapper
  local tree="$1" inst="$2" has_wrapper="$3" suffix new unit tmp user why rc=0 bin
  suffix="${inst:+-$inst}"
  new="$(trusted_wrapper_path "$inst")"
  unit="$TP_UNIT_DIR/aperire-advisord$suffix.service"
  # No Advisor unit, so nothing running could still depend on a rule an
  # older release left for this instance.
  [[ -f "$unit" ]] || { trusted_drop_sudo_rule "$inst" "$tree"; return; }
  if [[ -x "$new" ]] && grep -q -- '--wrapper=' "$unit" && ! grep -qE -- "--wrapper=$new( |$)" "$unit"; then
    sed -E "s#--wrapper=[^ ]+#--wrapper=$new#" "$unit" | _tp_put_root_file "$unit" || return 1
    systemctl daemon-reload 2>/dev/null || true
    printf '   %s now starts the Advisor on %s\n' "$unit" "$new"
  fi
  user="$(awk -F= '/^User=/{print $2; exit}' "$unit")"
  if why="$(_tp_shared_reason "$inst" "$user")"; then
    printf '   aperire-advisord%s is on a shared account: %s.\n' "$suffix" "$why"
    printf '   The shared-account mode is retired (ADR 0025). Moving it to its own\n'
    printf '   account restarts the Advisor and the dashboard, so it is not done here:\n'
    if [[ -n "$inst" ]]; then
      printf '     curl -fsSL https://get.aperire.one | bash -s -- --dir %s --run advisor-account --instance %s\n' "$tree" "$inst"
    else
      printf '     curl -fsSL https://get.aperire.one | bash -s -- --update --force\n'
      printf '     (at a terminal; answer Y when it offers to move the Advisor)\n'
    fi
    # A shared unit that names --sudo-wrapper (a native host) and a build
    # that reads it as the socket's name: no socket exists for a shared
    # account, so that Advisor cannot reach its node from its next start.
    # Stranded, not merely pending a move (#779 review).
    bin="$(grep -m1 '^ExecStart=' "$unit" | sed 's/^ExecStart=//; s/ .*//')"
    if grep -q -- '--sudo-wrapper' "$unit" && grep -qa -- 'wrapper-socket' "$bin" 2>/dev/null; then
      printf '   STRANDED: aperire-advisord%s runs a build that reaches the node only\n' "$suffix" >&2
      printf '   through a root socket, and an Advisor on a shared account has none.\n' >&2
      printf '   Until the move above runs, it cannot reach the node after a restart.\n' >&2
      return 8
    fi
    # For a caller that offers the move (get-aperire.sh), which sees only the
    # worst code across instances: which instance needs it, on a line of its
    # own. An empty name is the default instance. Off unless asked for, so
    # --refresh prints what it always did (#946).
    [[ "${APERIRE_MOVE_MARKERS:-}" != 1 ]] || printf '@move-needed:%s\n' "$inst"
    return 7
  fi
  if [[ "$has_wrapper" == 1 ]] && grep -q -- '--wrapper=' "$unit"; then
    # The binary this unit starts has to know the flag before the unit names
    # it, or the next restart is a crash loop. Read, never run as root: this
    # is a file in the tree (ADR 0024). The probe below runs it, as the
    # Advisor's own account.
    bin="$(grep -m1 '^ExecStart=' "$unit" | sed 's/^ExecStart=//; s/ .*//')"
    if ! grep -qa -- 'wrapper-socket' "$bin" 2>/dev/null; then
      printf '   %s predates the wrapper socket, so aperire-advisord%s was\n' "$bin" "$suffix" >&2
      printf '   left on its sudo rule; rebuild it and run this again\n' >&2
      return 1
    fi
    # From here on that binary has no route to the node but the socket: it
    # reads --sudo-wrapper as the socket's name (ADR 0025). A socket that is
    # not working is the Advisor cut off at its next start, not a warning.
    rc=0
    trusted_place_broker "$tree" || rc=$?
    if [[ $rc -eq 0 ]]; then _tp_repair_advisor_group "$tree" "$inst" "$user" "$unit" || rc=$?; fi
    if [[ $rc -eq 0 ]]; then trusted_write_socket_units "$inst" "$user" || rc=$?; fi
    if [[ $rc -eq 0 ]]; then _tp_socket_probe "$user" "$bin" "$new" "$(trusted_socket_path "$inst")" || rc=$?; fi
    if [[ $rc -eq 0 ]]; then trusted_convert_advisor_unit "$inst" || rc=$?; fi
    if [[ $rc -ne 0 ]]; then
      printf '   STRANDED: aperire-advisord%s runs a build that reaches the node only\n' "$suffix" >&2
      printf '   through its root socket, and that socket is not working (above). After\n' >&2
      printf '   its next restart it cannot reach the node. Put right what is named\n' >&2
      printf '   above, then:  curl -fsSL https://get.aperire.one | bash -s -- --update --force\n' >&2
      return 8
    fi
  fi
  trusted_drop_sudo_rule "$inst" "$tree"
}

# The ACL an older account move could leave on /dev itself (#806 review).
# On a host with no node its wrapper configuration names CONFIG_FILE=/dev/null,
# and the move read that as a node config in /dev: it refused the Advisor's
# account the whole directory (u:<account>:---), and a run that then failed
# took the named entry back and left the mask behind, or kept the entry on a
# re-run. An entry there cuts the account off from /dev/null and every device
# it opens.
#
# Only /dev, never anything under it, and never recursively. A named user
# entry for one of the given accounts goes; then, when what is left is a mask
# with no named user or group entry and no default entry, the extended ACL is
# removed, which is the state /dev has on a host nothing ever touched. Says
# what it did. Best effort: a failure is printed and the caller carries on,
# since nothing it does is needed for what the caller is doing.
trusted_repair_dev_acl() { # $@ = account names
  _tp_repair_acl_on /dev "$@"
}
# The same, on one named directory: /dev on a host, a scratch directory in
# the tests, which need the real setfacl's mask behaviour and cannot use
# /dev for it. Every removal is `setfacl -n -x`: without -n, setfacl
# recomputes the mask from what is left, and a named entry the mask was
# holding to r-x gets its write back (lane C reproduced r-x becoming rwx).
_tp_repair_acl_on() { # $1 = directory, rest = account names
  local d="$1" acl a uid did=0
  shift
  command -v getfacl >/dev/null 2>&1 && command -v setfacl >/dev/null 2>&1 || return 0
  acl="$(getfacl -p --omit-header "$d" 2>/dev/null)" || return 0
  for a in "$@"; do
    [[ -n "$a" && "$a" != root ]] || continue
    uid="$(id -u "$a" 2>/dev/null || true)"
    if grep -qE "^user:(${a//./\\.}${uid:+|$uid}):" <<<"$acl"; then
      if setfacl -n -x "u:${uid:-$a}" "$d" 2>/dev/null || setfacl -n -x "u:$a" "$d" 2>/dev/null; then
        printf '   removed an ACL entry for %s from %s, left by an older account move\n' "$a" "$d"
        did=1
      else
        printf '   %s carries an ACL entry for %s that could not be removed; remove it with: sudo setfacl -n -x u:%s %s\n' "$d" "$a" "$a" "$d" >&2
      fi
    fi
  done
  (( did )) && { acl="$(getfacl -p --omit-header "$d" 2>/dev/null)" || return 0; }
  if grep -q '^mask::' <<<"$acl" && ! grep -qE '^(user|group):[^:]+:|^default:' <<<"$acl"; then
    if setfacl -b "$d" 2>/dev/null; then
      printf '   removed a leftover ACL mask from %s, which names nobody\n' "$d"
    else
      printf '   %s carries a leftover ACL mask that could not be removed; remove it with: sudo setfacl -b %s\n' "$d" "$d" >&2
    fi
  fi
  return 0
}

# Every instance this host has a wrapper, a rule or a copy for.
_tp_instances() {
  local f n
  printf '\n'
  for f in "$TP_SBIN_DIR"/aperire-node-wrapper-* "$TP_SUDOERS_DIR"/aperire-advisor-* \
           "$TP_UNIT_DIR"/aperire-advisord-*.service; do
    [[ -e "$f" ]] || continue
    n="${f##*/}"; n="${n#aperire-node-wrapper-}"; n="${n#aperire-advisor-}"
    n="${n#aperire-advisord-}"; n="${n%.service}"
    case "$n" in credcheck|credcheck-*) continue ;; esac
    case "$n" in *.new-*|.*) continue ;; esac
    trusted_valid_instance "$n" && printf '%s\n' "$n"
  done | sort -u
}

# What an update does, and what --refresh does: bring every instance on this
# host to the state a fresh install leaves (#756 review, M1; ADR 0025). The
# copy and its libraries placed from this tree after the check; the Advisor's
# unit pointed at the copy and, on its own account, at the socket, with the
# full sandbox; the sudo rule an older release wrote removed once nothing
# running uses it. A host with no wrapper configuration, no rule, no copy and
# no Advisor gets nothing.
#
# 0: converged. 5: converged except a rule kept for a running Advisor (see
# trusted_drop_sudo_rule). 7: an Advisor on a shared account, which only
# install-advisor-account.sh moves. 6: a copy was refused while a rule still
# grants a file in a tree that a service account can write, which is exactly
# what ADR 0024 exists to end, so the caller fails loudly rather than warns.
# 8: an Advisor whose build has no route but the socket, and the socket is
# not working, so it is cut off at its next start; also loud. 1: something
# else failed. 8 over 6 over 1 over 7 over 5 over 0.
_tp_worse() { # $1 = so far, $2 = this one; prints the worse
  local rank_a rank_b
  case "$1" in 8) rank_a=5 ;; 6) rank_a=4 ;; 1) rank_a=3 ;; 7) rank_a=2 ;; 5) rank_a=1 ;; *) rank_a=0 ;; esac
  case "$2" in 8) rank_b=5 ;; 6) rank_b=4 ;; 1) rank_b=3 ;; 7) rank_b=2 ;; 5) rank_b=1 ;; *) rank_b=0 ;; esac
  if (( rank_b > rank_a )); then printf '%s' "$2"; else printf '%s' "$1"; fi
}

trusted_update_node_wrapper() { # $1 = install tree, $2 = the default instance's wrapper configuration
  local tree="$1" conf="$2" inst rc worst=0 prc has_wrapper
  # Once per update, before anything else: the Advisor's dedicated accounts,
  # the default name and whatever a unit here runs as that is not root and
  # not its dashboard's account.
  local -a advisor_accounts=(aperire-advisor)
  local u inst_u
  while IFS= read -r inst_u; do
    u="$(awk -F= '/^User=/{print $2; exit}' "$TP_UNIT_DIR/aperire-advisord${inst_u:+-$inst_u}.service" 2>/dev/null)"
    [[ -n "$u" && "$u" != root && "$u" != "$(_tp_dash_user "$inst_u")" ]] && advisor_accounts+=("$u")
  done < <(_tp_instances)
  trusted_repair_dev_acl "${advisor_accounts[@]}"
  while IFS= read -r inst; do
    has_wrapper=1
    if [[ -z "$inst" ]]; then
      [[ -r "$conf" || -e "$(trusted_wrapper_path "")" || -f "$TP_SUDOERS_DIR/aperire-advisor" ]] || has_wrapper=0
      [[ $has_wrapper -eq 1 || -f "$TP_UNIT_DIR/aperire-advisord.service" ]] || continue
    elif [[ ! -e "$(trusted_wrapper_path "$inst")" && ! -f "$TP_SUDOERS_DIR/aperire-advisor-$inst" ]]; then
      has_wrapper=0
    fi
    if [[ $has_wrapper -eq 1 ]]; then
      prc=0
      trusted_place_node_wrapper "$tree" "$inst" || prc=$?
      if [[ $prc -ne 0 ]]; then
        rc=1
        # The copy was refused, so the rule is what an older release left. It
        # is held to the same reading as a kept rule: a grant nobody can vouch
        # for is a refusal, not a pass (#780).
        _tp_rule_vouch "$TP_SUDOERS_DIR/aperire-advisor${inst:+-$inst}" "$inst" "$tree" || rc=6
        worst="$(_tp_worse "$worst" "$rc")"
        continue
      fi
    fi
    rc=0
    trusted_converge_advisor "$tree" "$inst" "$has_wrapper" || rc=$?
    worst="$(_tp_worse "$worst" "$rc")"
  done < <(_tp_instances)
  return "$worst"
}
