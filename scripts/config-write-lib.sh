#!/usr/bin/env bash
# Shared by every script that rewrites a node artefact (a config file, a
# compose deployment, an env file) by temp file and rename, so exactly one
# place carries a file's owner, group, mode AND its POSIX ACL across that
# rewrite, and exactly one place proves it landed.
#
# Issue #545: `chown --reference` and `chmod --reference` carry owner, group
# and mode. Nothing else. The `mv` that follows installs a new inode with no
# ACL at all, so every named grant on the file it replaced is gone. This went
# unnoticed for a reason worth stating plainly: `stat` reports the ACL MASK
# in the group-permission position, so a file that just lost every named
# entry can still show the identical owner:group:mode it had before. A guard
# built on `stat` alone cannot see this class of regression, by construction.
#
# What this library does instead: carries the ACL alongside owner/group/mode,
# and verifies the result by reading the ACL back (`getfacl -p`), not by
# reasoning about the classic nine bits.
#
# Callers: scripts/aperire-node-wrapper.sh (set-config, set-image),
# scripts/enable-advisory-delete.sh, scripts/configure-rippled-paths.sh,
# scripts/migrate-node-nonroot.sh, scripts/install-aperire-node.sh
# (native_harden_cfg). That is every site in this tree that rewrites a node
# config, a compose file or an env file by temp-file-and-rename; a sweep
# done for #545 found two more sites that touch a node config directly
# (scripts/install-aperire-relay.sh's relay-token append,
# scripts/dedup-nodedb.sh) and neither needs this library, because neither
# renames a new inode over the old one: both write through the EXISTING
# inode (`cat "$tmp" > "$file"`, never `mv`), so owner, group, mode and ACL
# all ride along for free and there is nothing here to carry. A future
# rewrite of either one into a temp-and-rename shape would need to start
# using this library, not keep assuming the inode never moves.
#
# Out of scope: SELinux contexts and other xattrs. This carries and verifies
# POSIX ACLs (getfacl/setfacl) and the classic owner/group/mode bits, and
# says so rather than silently doing less than a caller might assume.
#
# Sourced, not executed: this file defines functions only and has no side
# effects of its own.

# True when this host has both halves of the ACL toolchain. A host with
# neither cannot carry a POSIX ACL beyond the classic bits in the first
# place, so its absence is "nothing here to lose", not a failure: every
# function below treats it that way rather than refusing to run.
_cwl_have_acl_tools() {
  command -v getfacl >/dev/null 2>&1 && command -v setfacl >/dev/null 2>&1
}

# A single comparable snapshot of everything a rewrite of $1 must not move:
# owner, group and mode (stat, which also carries the setuid/setgid/sticky
# bits) and, when this host has the tools, the file's full ACL text (every
# named entry and the mask). Two calls against the same path compare equal
# exactly when nothing in that surface changed, never when owner:group:mode
# merely look the same, because stat cannot see an ACL at all, named or
# default.
cwl_acl_snapshot() {
  local f=$1
  local st
  st=$(stat -c '%U:%G:%a' "$f" 2>/dev/null || printf '?')
  printf 'stat:%s\n' "$st"
  if _cwl_have_acl_tools; then
    printf 'acl:\n%s\n' "$(getfacl -p "$f" 2>/dev/null)"
  else
    printf 'acl: not checked, no getfacl/setfacl on this host\n'
  fi
}

# The ACL text alone, with getfacl's own "# file: <path>" header left out
# (getfacl -c). cwl_acl_snapshot keeps that header because every caller of
# it compares the SAME path against itself, before and after a rewrite, and
# the header is identical either way. This one exists for the single place
# this library compares two DIFFERENT paths against each other: a restore
# checks the backup's own permissions against whatever landed at the target,
# and the header would differ by filename alone even when every entry and
# the mask match.
_cwl_acl_body() {
  local f=$1
  _cwl_have_acl_tools || return 0
  getfacl -pc "$f" 2>/dev/null
}

# One phrase, fit for a run log line, naming what cwl_acl_snapshot actually
# compared, so a caller's "(unchanged)" claim says something a reader could
# go check, instead of asserting a surface it never looked at.
cwl_snapshot_describe() {
  if _cwl_have_acl_tools; then
    printf 'owner, group, mode and ACL (named entries and mask)'
  else
    printf 'owner, group and mode only, no getfacl/setfacl on this host to read an ACL with'
  fi
}

# Copy owner, group, mode AND the full ACL of $1 onto $2. $2 must already be
# a regular file sitting beside $1, a caller's `mktemp "$1.XXXXXX"` in the
# same directory as $1, never a path on another filesystem: an ACL carried
# across a filesystem boundary is not the same ACL, and neither is a `mv`
# that stops being atomic once it crosses one.
#
# chown first, then chmod: chown clears the setuid/setgid bits, so the other
# order can quietly drop a bit chmod --reference had just set. setfacl runs
# LAST and takes the whole ACL from one read of $1, entries and mask
# together, so the mask on $2 is never assembled from two different ideas
# of what it should be.
#
# Every step's exit status is checked on purpose, not left to whichever
# command happens to run last. A caller invokes this as `if ! cwl_carry_
# permissions ...; then`, and bash suspends `set -e` for the whole body of a
# function called that way: a chown that fails here does not stop the
# function, it just falls through to chmod and then to setfacl, and without
# an explicit check the function's return value is only the last command
# run, so the chown failure is invisible.
#
# setfacl failing is not automatically a failure of this function. A
# filesystem with no ACL support fails setfacl with ENOTSUP even when there
# is nothing to lose, and that looks, from here, exactly like the source
# having no named entries in the first place: getfacl's own base three
# lines (user::, group::, other::) round-trip through chown/chmod already,
# with no ACL step needed at all. Only a source that HAS a named entry
# (user:NAME: or group:NAME:) and still fails to carry it is refused: that
# is #545's own failure mode, and the one this function exists to catch.
cwl_carry_permissions() {
  local src=$1
  local dst=$2

  chown --reference="$src" "$dst" || return 1
  chmod --reference="$src" "$dst" || return 1

  _cwl_have_acl_tools || return 0

  local src_acl
  src_acl=$(getfacl -p "$src" 2>/dev/null) || return 1

  if printf '%s\n' "$src_acl" | setfacl --set-file=- "$dst" 2>/dev/null; then
    return 0
  fi

  if printf '%s\n' "$src_acl" | grep -qE '^(user|group):[^:]+:'; then
    return 1
  fi

  printf 'note: %s carries no POSIX ACL beyond the base owner/group/other bits, or this filesystem does not support one; owner, group and mode were carried, the ACL step was a no-op\n' "$dst" >&2
  return 0
}

# Put $1 (a dated backup) back as $2, atomically, carrying the BACKUP's own
# owner, group, mode and ACL rather than whatever $2 currently holds, since
# $2 is the write already in question. Goes through cwl_carry_permissions
# like every other rewrite in this library, so a rollback cannot drop the
# ACL either. mktemp-and-rename in $2's own directory, so whatever reads $2
# never observes it missing or unreadable, not even for the instant this
# takes.
#
# Returns non-zero and leaves $2 untouched when the restore never starts (no
# such backup, or the copy/carry/rename step itself fails). Past that point
# the mv having exited zero is not treated as proof: what actually landed at
# $2 is re-read from the filesystem, content and permissions both, and
# compared against a snapshot of $1 taken before any of this ran. Only a
# restore that reads back byte-for-byte and permission-for-permission
# identical to its own backup returns success. A caller printing "restored
# and left the config reading exactly as it did before this ran" is
# therefore printing something this function actually checked, not
# something it assumed from a command's exit status. A failure past this
# point leaves $2 holding whatever the rename installed, unverified; a
# caller's own message is expected to say that plainly, naming $1 as the
# backup to restore from by hand.
cwl_restore_from_backup() {
  local backup=$1
  local target=$2
  local rtmp
  local backup_own backup_acl

  [[ -f "$backup" ]] || return 1

  backup_own=$(stat -c '%U:%G:%a' "$backup" 2>/dev/null || printf '?')
  backup_acl=$(_cwl_acl_body "$backup")

  rtmp=$(mktemp "${target}.XXXXXX") || return 1
  cp "$backup" "$rtmp" || { rm -f "$rtmp"; return 1; }
  cwl_carry_permissions "$backup" "$rtmp" || { rm -f "$rtmp"; return 1; }
  mv "$rtmp" "$target" || { rm -f "$rtmp"; return 1; }

  if ! cmp -s "$backup" "$target"; then
    printf 'cwl_restore_from_backup: %s does not read back the same as %s; content differs after the restore\n' "$target" "$backup" >&2
    return 1
  fi

  local target_own target_acl
  target_own=$(stat -c '%U:%G:%a' "$target" 2>/dev/null || printf '?')
  target_acl=$(_cwl_acl_body "$target")
  if [[ "$target_own" != "$backup_own" || "$target_acl" != "$backup_acl" ]]; then
    printf 'cwl_restore_from_backup: %s does not carry the same owner, group, mode and ACL as %s after the restore\n' "$target" "$backup" >&2
    return 1
  fi
}

# Keep the newest $2 (default 10) dated backups this library's callers make
# of $1, delete the rest. Ten is enough to hold the last ten deliberate,
# approved config changes on a node without reaching for anything off-host,
# while still bounding growth on a validator that keeps running for years:
# #545 itself was filed against a host already carrying a dozen of these
# with nothing pruning any of them.
#
# The match is exact: "$1.<8 digits>-<6 digits>.bak", which is the one shape
# every caller in this project names a backup with (date +%Y%m%d-%H%M%S).
# Never a bare "$1.*.bak" glob: that also matches a file an operator happened
# to name that way for their own reasons, and a prune that cannot tell the
# two apart is a prune that deletes someone's file without asking.
cwl_prune_backups() {
  local target=$1
  local keep=${2:-10}
  local dir base
  dir=$(dirname "$target")
  base=$(basename "$target")
  [[ -d "$dir" ]] || return 0

  local -a matches=()
  local f
  while IFS= read -r f; do
    matches+=("$f")
  done < <(find "$dir" -maxdepth 1 -type f \
             -name "${base}.[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9][0-9][0-9].bak" \
             -print 2>/dev/null | sort)

  local total=${#matches[@]}
  (( total > keep )) || return 0

  local excess=$(( total - keep ))
  local i
  for (( i = 0; i < excess; i++ )); do
    rm -f -- "${matches[$i]}"
  done
}
