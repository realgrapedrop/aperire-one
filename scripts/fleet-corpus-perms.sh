#!/usr/bin/env bash
# One rule about advisor/knowledge-fleet, in one place.
#
# The rule: on an aggregator, TWO accounts write that directory. advisord
# applies a signature-verified bundle by renaming the directory whole (ADR
# 0017), and the dashboard's Proposals inbox promotes a note into it when an
# operator clicks Promote. If only one of them can write, the other fails at
# the moment of the click, with a permission error three hops from its cause.
#
# The correct arrangement, which install-advisor-account.sh creates: the
# corpus is owned by the Advisor's account, its group is the shared service
# group (aperire-svc today), the dashboard's account is in that group, and the
# directory is group-writable and setgid so a file either account writes stays
# readable and replaceable by the other.
#
# What this file exists for is the arrangement that is NOT that. stock-node2
# and validator1 were set up by hand in August 2026: knowledge-fleet ended up
# advisord:advisord, the dashboard's account was in no group that could write
# it, and promoting a proposal from those nodes' Advisor tabs was refused
# (#245). install-aperire-service.sh had noticed and printed a warning for a
# month. A warning is the right answer for a state an installer cannot fix
# safely; this one it can.
#
# Use it two ways:
#
#   source scripts/fleet-corpus-perms.sh   the functions, for the installer
#   bash   scripts/fleet-corpus-perms.sh <dir> [user]   report the plan, change nothing
#
# fc_plan decides and touches nothing. fc_apply and fc_hand_over are the parts
# that write: fc_apply is what install-aperire-service.sh calls and needs root
# for the `join` verdict (it edits group membership), fc_hand_over is what
# install-advisor-account.sh calls when it moves the corpus onto the Advisor's
# own account. Both end in the same shape, whichever ran first.

# ── the pure part ────────────────────────────────────────────────────────

# The shared group, never the Advisor's own (#794). The corpus is shared
# through the group install-advisor-account.sh names for the two accounts
# (aperire-svc today), read by the caller from what that installer wrote, never
# from a constant here. Putting the dashboard's account in the Advisor's
# PRIMARY group instead (what `join` did until #794) also put it in the group
# the Advisor's root socket is opened to (ADR 0025), so the socket was refused
# on every host this repair had touched, and the update stranded there.
#
# The caller sets FC_SHARED_GROUP before fc_apply. Empty means "not known
# here", and a repair that needs it refuses rather than guess.
FC_SHARED_GROUP="${FC_SHARED_GROUP:-}"
# Where this file sits, for the root walks it shares with the Advisor's
# socket repair (trusted-path-lib.sh, beside it in the same tree).
FC_SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# The walks root runs, read from that file and from nowhere else (#795
# review, L3). Cleared here, so a variable of the same name inherited from
# whoever started the installer can never stand in for one.
unset _FC_REGROUP_PY _FC_SHARE_PY _FC_HANDOVER_PY
# How many entries the last fc_share left alone (a link, a hard link), so the
# caller's account of what it did is true.
FC_SHARE_SKIPPED=0

# fc_plan <owner> <group> <user> <user_groups_csv> <user_primary_group> <shared> <foreign_primary>
#
# Prints "<verdict>\t<group>\t<message>". The group column is the group the
# corpus should end up in, empty where the verdict does not set one.
# <shared> is the shared group (may be empty). <foreign_primary> is 1 when the
# corpus's group is the primary group of an account other than <user>: some
# account's own group, which the dashboard's account is never put in or
# shared through.
#
#   owned    the dashboard's account owns it. A fresh install; nothing to do.
#   share    the dashboard's account is already in the corpus's group, and
#            that group is nobody else's own. Make the corpus group-writable
#            and setgid. This is the correct arrangement being completed.
#   adopt    root owns it. Nothing needs root to own this, and a root-owned
#            corpus is writable by neither service, so hand it to the
#            dashboard's account: what a fresh install would have created.
#   join     another service account owns it, and the dashboard's account
#            either cannot write it or could only through that account's own
#            group. Move the two accounts' own entries to the shared group
#            by descriptor, then share as above. Both accounts must already
#            hold the shared group: nothing here adds anyone to a group. The
#            same arrangement install-advisor-account.sh makes.
#   refuse   nothing above applies, or no shared group is known. Warn,
#            change nothing.
fc_plan() {
  local owner="$1" group="$2" user="$3" groups_csv="$4" primary="$5"
  local shared="${6:-}" foreign="${7:-0}"

  if [[ -z "$owner" || -z "$group" || -z "$user" ]]; then
    printf 'refuse\t\t%s\n' "could not read the corpus owner, group or the dashboard account"
    return 0
  fi
  if [[ "$owner" == "$user" ]]; then
    printf 'owned\t%s\t%s\n' "$group" "$user owns the corpus already"
    return 0
  fi

  local g
  if [[ "$foreign" != 1 ]]; then
    while IFS= read -r g; do
      if [[ -n "$g" && "$g" == "$group" ]]; then
        printf 'share\t%s\t%s\n' "$group" "$user is already in $group"
        return 0
      fi
    done < <(printf '%s\n' "${groups_csv//,/$'\n'}")
  fi

  # root as owner is not an arrangement anyone chose. It is what
  # `install -d` leaves behind when it creates the directory under sudo
  # without being told an owner, and it locks out both services.
  if [[ "$owner" == "root" ]]; then
    if [[ -n "$primary" && "$primary" != "root" ]]; then
      printf 'adopt\t%s\t%s\n' "$primary" "root owns the corpus; no service needs that"
      return 0
    fi
    printf 'refuse\t\t%s\n' "root owns the corpus and $user has no group of its own to hand it to"
    return 0
  fi

  # Joining the dashboard's account to `root` would be a privilege grant, not
  # a repair, and no installer here may make one.
  if [[ "$group" == "root" ]]; then
    printf 'refuse\t\t%s\n' "the corpus is $owner:root, and $user may not be put in root"
    return 0
  fi

  if [[ -z "$shared" || "$shared" == root ]]; then
    printf 'refuse\t\t%s\n' "$owner owns the corpus, and no group shared by $owner and $user is named on this host (install-advisor-account.sh names it)"
    return 0
  fi
  if [[ "$foreign" == 1 ]]; then
    printf 'join\t%s\t%s\n' "$shared" "the corpus's group $group is an account's own group, and $user is never shared through it"
    return 0
  fi
  printf 'join\t%s\t%s\n' "$shared" "$owner owns the corpus and $user is in no group that can write it"
}

# fc_foreign_primary <group> <user>: 1 when <group> is the primary group of
# any account other than <user>, else 0. Read from the account database, the
# same reading the root socket's own check makes.
fc_foreign_primary() {
  local gid
  gid="$(getent group "$1" 2>/dev/null | head -1 | cut -d: -f3)"
  [[ "$gid" =~ ^[0-9]+$ ]] || { echo 0; return 0; }
  if getent passwd 2>/dev/null | awk -F: -v g="$gid" -v u="$2" '$4 == g && $1 != u { f = 1 } END { exit !f }'; then
    echo 1
  else
    echo 0
  fi
}

# fc_resolve_shared <unit_supplementary_group> <state_dir> <user>
#
# The shared group, from what install-advisor-account.sh wrote on this host:
# the Advisor unit's SupplementaryGroups= first (the caller reads it, through
# advisor-owner-lib.sh), and failing that the group the installer handed the
# Advisor's state directory to. A group that is some account's own, root, or
# the dashboard account's own primary group is never the answer: those are
# the shapes this exists to keep the corpus out of, and neither is a group
# the dashboard's account does not already hold. Prints nothing when no
# group qualifies.
fc_resolve_shared() {
  local g="${1:-}" state="${2:-}" user="${3:-}"
  local n
  if [[ -z "$g" && -n "$state" && -d "$state" && ! -L "$state" ]]; then
    n="$(stat -c %g "$state" 2>/dev/null || true)"
    [[ "$n" =~ ^[0-9]+$ ]] && g="$(getent group "$n" 2>/dev/null | head -1 | cut -d: -f1)"
    [[ -n "$g" ]] || g="$(stat -c %G "$state" 2>/dev/null || true)"
  fi
  [[ -n "$g" && "$g" != root && "$g" != UNKNOWN ]] || return 0
  [[ "$g" != "$(id -gn "$user" 2>/dev/null)" ]] || return 0
  [[ "$(fc_foreign_primary "$g" "$user")" == 0 ]] || return 0
  # The dashboard must already hold it. A group read off advisor/state is
  # the Advisor's own say-so (it can chgrp its own directory), so the
  # resolver never names a group the dashboard is not already in, and no
  # verdict adds it to one (#797 review, L2). install-advisor-account.sh is
  # what puts both accounts in the shared group.
  fc_in_group "$user" "$g" || return 0
  printf '%s' "$g"
}

# fc_in_group <account> <group>: the account holds the group, primary or member.
fc_in_group() {
  local g
  for g in $(id -nG "$1" 2>/dev/null); do [[ "$g" == "$2" ]] && return 0; done
  return 1
}

# ── the host part ────────────────────────────────────────────────────────

# fc_apply <dir> <user> [dry]
#
# Reads the live state of <dir>, plans, and applies. Prints what it changed,
# in operator words, or the warning when it cannot. Returns 0 unless it
# refused, so the caller can decide whether a refusal is fatal (it is not:
# the dashboard still runs, the Promote button is what stops working).
fc_apply() {
  local dir="$1" user="$2" dry="${3:-}"
  local owner group groups primary line verdict target msg out rc

  # By number, named through the account database (getent), the same reading
  # every other check here makes. stat's own names are the fallback.
  #
  # One stat for the owner, the group and the directory's identity, so the
  # plan judges one directory (#989). The walk that acts on the plan is handed
  # the same owner and inode, and refuses a corpus that is not that directory:
  # anyone who can write advisor/ could rename a sibling into this name
  # between the two.
  local n ouid="" ogid="" odev="" oino=""
  owner="" group=""
  read -r ouid ogid odev oino < <(stat -c '%u %g %d %i' -- "$dir" 2>/dev/null) || true
  [[ "$ouid" =~ ^[0-9]+$ ]] && owner="$(getent passwd "$ouid" 2>/dev/null | head -1 | cut -d: -f1)"
  [[ -n "$owner" ]] || owner="$(stat -c %U "$dir" 2>/dev/null || true)"
  [[ "$ogid" =~ ^[0-9]+$ ]] && group="$(getent group "$ogid" 2>/dev/null | head -1 | cut -d: -f1)"
  [[ -n "$group" ]] || group="$(stat -c %G "$dir" 2>/dev/null || true)"
  groups="$(id -nG "$user" 2>/dev/null | tr ' ' ',' || true)"
  primary="$(id -gn "$user" 2>/dev/null || true)"

  local shared="${FC_SHARED_GROUP:-}" foreign
  foreign="$(fc_foreign_primary "$group" "$user")"
  line="$(fc_plan "$owner" "$group" "$user" "$groups" "$primary" "$shared" "$foreign")"
  verdict="${line%%$'\t'*}"
  target="$(printf '%s' "$line" | cut -f2)"
  msg="$(printf '%s' "$line" | cut -f3)"

  if [[ -n "$dry" ]]; then
    printf '%s\t%s\t%s\n' "$verdict" "$target" "$msg"
    return 0
  fi

  case "$verdict" in
    owned)
      return 0 ;;
    share)
      fc_share "$dir" || { fc_incomplete "$dir" "$user" "could not set group write and setgid"; return 1; }
      if [[ "$FC_SHARE_SKIPPED" == 0 ]]; then
        echo "Fleet corpus ${dir} is owned by ${owner}; made it group-writable for ${group}"
      else
        echo "Fleet corpus ${dir} is owned by ${owner}; made it group-writable for ${group},"
        echo "except the ${FC_SHARE_SKIPPED} entries named above, which were left as they were,"
      fi
      echo "so the dashboard can promote into the same corpus the Advisor applies bundles to."
      return 0 ;;
    adopt)
      # By descriptor, like every other root change to this tree (#978): a
      # service account may own what is under a root-owned corpus. Only the
      # directory this plan judged is adopted (#989): without its identity
      # there is nothing to hold the walk to, so nothing moves.
      if [[ ! "$ouid" =~ ^[0-9]+$ || ! "$odev" =~ ^[0-9]+$ || ! "$oino" =~ ^[0-9]+$ ]]; then
        fc_incomplete "$dir" "$user" "could not read which directory the corpus is, so it was not handed over"
        return 1
      fi
      fc_handover_walk "$dir" "$user" "$target" 0 "$ouid:$odev:$oino" \
        || { fc_incomplete "$dir" "$user" "could not hand the corpus to ${user}"; return 1; }
      # What it says is what it did. An Advisor on this host gets its share back
      # from its own installer, which is the only thing that knows its account.
      echo "Repaired ${dir}: root owned it, and a service that does not run as root cannot write it."
      echo "  owner  root:${group} -> ${user}:${target}   (every directory and file of its own, by descriptor)"
      echo "  mode   0750 on the corpus itself"
      return 0 ;;
    join)
      # Nobody is added to any group here (#797 review, L2): both accounts
      # must already hold the shared group, which install-advisor-account.sh
      # arranges. The Advisor reads and replaces what the dashboard writes
      # through it; the dashboard writes through it.
      if ! fc_in_group "$owner" "$target" || ! fc_in_group "$user" "$target"; then
        echo "${E_AMBER:-}WARNING: ${dir}: ${owner} and ${user} do not both hold ${target}; nothing was changed.${E_OFF:-}" >&2
        echo "${E_AMBER:-}         install-advisor-account.sh puts both accounts in ${target}. Run it, then this again.${E_OFF:-}" >&2
        echo "${E_AMBER:-}         Promoting a proposal from the Advisor tab will be refused until ${user} can write there.${E_OFF:-}" >&2
        return 1
      fi
      # The move is the same descriptor walk the Advisor's socket repair
      # makes (#797 review, L1), never a root chown -R: only an entry in the
      # old group, owned by one of the two accounts and (a file) with one
      # link, moves, a link is never followed, and if anything would be left
      # behind nothing moves at all.
      if [[ "$group" != "$target" ]]; then
        rc=0
        out="$(fc_regroup "$dir" "$group" "$target" "$owner" "$user" 2>&1)" || rc=$?
        if [[ $rc -ne 0 ]]; then
          echo "${E_AMBER:-}WARNING: ${dir} was not moved from ${group} to ${target}; nothing was changed:${E_OFF:-}" >&2
          printf '%s\n' "$out" | sed -n 's/^left /           still in '"$group"': /p; /^   /p' >&2
          echo "${E_AMBER:-}         Only ${owner}'s and ${user}'s own entries move. Move or remove what is named, then run this again.${E_OFF:-}" >&2
          echo "${E_AMBER:-}         Promoting a proposal from the Advisor tab will be refused until ${user} can write there.${E_OFF:-}" >&2
          return 1
        fi
      fi
      fc_share "$dir" \
        || { fc_incomplete "$dir" "$user" "the corpus is in ${target} now, but the share did not finish"; return 1; }
      echo "Repaired ${dir}: ${msg}."
      if [[ "$group" != "$target" ]]; then
        echo "  group  ${group} -> ${target} on ${owner}'s and ${user}'s own entries   ($(sed -n 's/^moved //p' <<<"$out") moved, by descriptor)"
      fi
      if [[ "$FC_SHARE_SKIPPED" == 0 ]]; then
        echo "  mode   g+w on every file, setgid on every directory"
      else
        echo "  mode   g+w on every file, setgid on every directory, except the ${FC_SHARE_SKIPPED} named above"
      fi
      echo "  owner  ${owner}, unchanged: the Advisor still writes it as the owner."
      return 0 ;;
    *)
      echo "${E_AMBER:-}WARNING: ${dir} is owned by ${owner}:${group} and ${user} is not in ${group}.${E_OFF:-}" >&2
      echo "${E_AMBER:-}         ${msg}.${E_OFF:-}" >&2
      echo "${E_AMBER:-}         Promoting a proposal from the Advisor tab will be refused until it can write there.${E_OFF:-}" >&2
      return 1 ;;
  esac
}

# The root walks over the corpus live in trusted-path-lib.sh, beside this
# file, with the Advisor's socket repair that shares the regroup walk. Read
# once, the first time one is needed, into this file's own names. The library
# is sourced in a subshell with its names cleared first, so nothing it sets
# reaches the caller and nothing the caller inherited reaches the walks.
fc_walks() {
  local lib="$FC_SELF_DIR/trusted-path-lib.sh"
  local -a w=()
  [[ -n "${_FC_REGROUP_PY:-}" && -n "${_FC_SHARE_PY:-}" && -n "${_FC_HANDOVER_PY:-}" ]] && return 0
  [[ -r "$lib" ]] || { echo "   $lib is missing, so the corpus walk is not here"; return 1; }
  mapfile -d '' -t w < <(
    unset _TP_REGROUP_PY _TP_SHARE_PY _TP_HANDOVER_PY _TP_CORPUS_WALK_PY
    # shellcheck source=scripts/trusted-path-lib.sh
    . "$lib" >/dev/null 2>&1
    printf '%s\0' "${_TP_REGROUP_PY:-}" "${_TP_SHARE_PY:-}" "${_TP_HANDOVER_PY:-}"
  )
  if [[ ${#w[@]} -ne 3 || -z "${w[0]}" || -z "${w[1]}" || -z "${w[2]}" ]]; then
    echo "   the corpus walk did not load; $lib may be older than this file"
    return 1
  fi
  _FC_REGROUP_PY="${w[0]}" _FC_SHARE_PY="${w[1]}" _FC_HANDOVER_PY="${w[2]}"
}

# What a walk printed, read the same way for every walk. Its count line is
# its last word; without one nothing ran. Every name in it is already escaped
# by the walk; the output is filtered to printable ASCII once more anyway,
# since it lands on root's terminal. A failure prints the walk's own lines; a
# skip prints "not <what>: <name>: <why>".
# fc_walk_said <rc> <output> <count word> <what a skipped entry was not>
fc_walk_said() {
  local rc="$1" out
  out="$(LC_ALL=C tr -c '[:print:]\n' '?' <<<"$2")"
  if [[ $rc -eq 0 ]] && ! grep -qE "^$3 [0-9]+\$" <<<"$out"; then
    rc=1; out="   the corpus walk did not run; $FC_SELF_DIR/trusted-path-lib.sh may be older than this file"
  fi
  if [[ $rc -ne 0 ]]; then
    if grep -q '^   ' <<<"$out"; then
      LC_ALL=C sed -n '/^   /p' <<<"$out" >&2
    else
      printf '   the corpus walk stopped: %s\n' "$(tail -n 1 <<<"$out")" >&2
    fi
    return 1
  fi
  LC_ALL=C sed -n "s/^skipped \(.*\)\$/   not $4: \1/p" <<<"$out" >&2
}

# fc_regroup <dir> <old group> <new group> <owner> <user>
#
# The corpus off <old group> and onto <new group>, by descriptor, through the
# walk trusted-path-lib.sh holds (_TP_REGROUP_PY): one control for both root
# paths that move it. Prints the walk's own lines; 0 moved, non-zero refused
# with nothing changed.
fc_regroup() {
  local dir="$1" og ng ou uu
  fc_walks || return 1
  og="$(getent group "$2" 2>/dev/null | head -1 | cut -d: -f3)"
  ng="$(getent group "$3" 2>/dev/null | head -1 | cut -d: -f3)"
  ou="$(id -u "$4" 2>/dev/null)"
  uu="$(id -u "$5" 2>/dev/null)"
  if [[ ! "$og" =~ ^[0-9]+$ || ! "$ng" =~ ^[0-9]+$ || ! "$ou" =~ ^[0-9]+$ || ! "$uu" =~ ^[0-9]+$ ]]; then
    echo "   could not resolve $2, $3, $4 or $5 to a number"
    return 1
  fi
  python3 -I -c "$_FC_REGROUP_PY" "$dir" "$og" "$ng" "$ou,$uu"
}

# A repair that started and did not finish is the one state worse than the one
# it was in, because the installer carries on either way. It says so.
fc_incomplete() {
  echo "${E_AMBER:-}WARNING: the repair of $1 did not finish: $3.${E_OFF:-}" >&2
  echo "${E_AMBER:-}         Promoting a proposal from the Advisor tab will be refused until $2 can write there.${E_OFF:-}" >&2
}

# The two-account share: group write on everything that is there, and setgid
# on every directory so what either account writes next keeps the group.
#
# Root runs this over a tree the Advisor's account writes, so it never hands
# a name to chmod (#795). `chmod -R` and `find -exec chmod` both resolve each
# path again at the moment they change it and follow a link in its last
# component: the Advisor's account could swap a directory it owns for a link
# between the two, and `chmod g+s` would land on the link's target as root.
# GNU coreutils fixed the same race inside `chmod -R` only in 9.5; 22.04 ships
# 8.32 and 24.04 9.4. So the share is the descriptor walk in
# trusted-path-lib.sh (_TP_SHARE_PY), which opens every entry without
# following a link and changes it through that descriptor.
#
# A link, a hard link or anything not a file or a directory is skipped and
# named, and the share still counts as done: it was never the corpus's to
# share. Returns non-zero only when the corpus could not be walked or a mode
# could not be set, which is what fc_incomplete reports.
fc_share() {
  local dir="$1" out rc=0
  FC_SHARE_SKIPPED=0
  fc_walks >&2 || return 1
  out="$(python3 -I -c "$_FC_SHARE_PY" "$dir" 2>&1)" || rc=$?
  fc_walk_said "$rc" "$out" shared shared || return 1
  FC_SHARE_SKIPPED="$(sed -n 's/^skips \([0-9][0-9]*\)$/\1/p' <<<"$out")"
  FC_SHARE_SKIPPED="${FC_SHARE_SKIPPED:-0}"
  return 0
}

# fc_handover_walk <dir> <account> <group> <clear-other: 1|0> [<uid>:<dev>:<ino>]
#
# The corpus to <account>:<group>, by the same descriptor walk (#978): every
# directory and file of the corpus's own fchown-ed, the world bits cleared
# when asked, and the corpus itself 0750. `chown -R` follows no link, but it
# changes a hard-linked file outside the corpus like any other, and `chmod -R
# o=` follows a directory swapped for a link while it runs: on coreutils 9.4 a
# swap timed to its traversal took the world bits off the link's target. A
# link, a hard link or a swapped entry is skipped and named, as the share does.
#
# The fifth argument is the corpus a plan judged (#989): its owner, device and
# inode. Given, the walk refuses at the top, with nothing changed, when the
# directory it opened is not that one.
fc_handover_walk() {
  local dir="$1" uid gid out rc=0
  fc_walks >&2 || return 1
  uid="$(id -u "$2" 2>/dev/null)"
  gid="$(getent group "$3" 2>/dev/null | head -1 | cut -d: -f3)"
  if [[ ! "$uid" =~ ^[0-9]+$ || ! "$gid" =~ ^[0-9]+$ ]]; then
    echo "   could not resolve $2 or $3 to a number" >&2
    return 1
  fi
  out="$(python3 -I -c "$_FC_HANDOVER_PY" "$dir" "$uid" "$gid" "$4" "${5:-}" 2>&1)" || rc=$?
  fc_walk_said "$rc" "$out" handed "handed over"
}

# fc_hand_over <dir> <account> <group> <dashboard-account>
#
# The other installer's half of the same rule. install-advisor-account.sh
# moves the corpus onto the Advisor's own account, and it used to end that
# move with a plain `chmod 0750` — which took back the group write fc_share
# had granted on an earlier install-aperire-service.sh run. install.sh runs
# the service step first, so that was the shipped order: a host both
# installers had just run refused the first Promote (#248).
#
# It left 2750, measured on coreutils 9.4, not 0750: GNU chmod preserves a
# directory's setgid bit for an octal mode, leading zero and all. So the
# corpus kept the bit that makes it LOOK shared and lost the one that makes
# it writable, which is why this went a month without anyone reading it off
# a host.
#
# Two things have to be true for the orders to agree, and neither is free:
#
#   the corpus ends shared, not 0750 — so the move finishes by asking the
#   same fc_plan the other installer asks, and the answer on a host this
#   script has just chowned is `share`: the correct arrangement completed,
#   never a repair.
#
#   the modes underneath start from the same place. `install -d -m 0750` and
#   a bare `mkdir -p` under root's umask leave 0750 and 0755, and fc_share
#   only ADDS bits — so without a baseline the two orders ended at 2770 and
#   2775, the second one world-readable. Nothing in the corpus is for anyone
#   outside these two accounts, whoever created it, so the world bits go.
#
# Returns non-zero if any part did not land. The caller decides what that
# costs; in both installers it is the Promote button, not the install.
fc_hand_over() {
  local dir="$1" account="$2" group="$3" user="${4:-}"

  # The move itself, by descriptor (#978): owner and group on every directory
  # and file of the corpus's own, world bits cleared, the corpus itself 0750.
  fc_handover_walk "$dir" "$account" "$group" 1 || return 1

  # No second writer, nothing to share. A dashboard running as root is left
  # out on purpose: it can already write this, and putting root in a service
  # group would be a privilege grant made for no gain.
  if [[ -z "$user" || "$user" == "$account" || "$user" == "root" ]]; then
    return 0
  fi
  FC_SHARED_GROUP="$group" fc_apply "$dir" "$user"
}

# Run directly, or be sourced. ${BASH_SOURCE[0]} != $0 when sourced.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  set -uo pipefail
  _repo="${APERIRE_INSTALL_TREE:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
  _dir="${1:-$_repo/advisor/knowledge-fleet}"
  _user="${2:-${SUDO_USER:-$(id -un)}}"
  if [[ ! -d "$_dir" ]]; then
    echo "no fleet corpus at $_dir"
    exit 0
  fi
  # The same shared group an installer would read (#794), so the plan printed
  # here is the plan an install would carry out.
  _sup=""
  if [[ -r "$FC_SELF_DIR/advisor-owner-lib.sh" ]]; then
    # shellcheck source=scripts/advisor-owner-lib.sh
    . "$FC_SELF_DIR/advisor-owner-lib.sh"
    _sup="$(advisor_owner_shared_group "/etc/systemd/system/aperire-advisord${APERIRE_INSTANCE:+-$APERIRE_INSTANCE}.service" "$_user" 2>/dev/null || true)"
  fi
  FC_SHARED_GROUP="$(fc_resolve_shared "$_sup" "$_repo/advisor/state" "$_user")"
  _line="$(fc_apply "$_dir" "$_user" dry)"
  printf 'would %s: %s\n' "${_line%%$'\t'*}" "$(printf '%s' "$_line" | cut -f3)"
  exit 0
fi
