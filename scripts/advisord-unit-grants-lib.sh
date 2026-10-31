#!/usr/bin/env bash
# The writable grants an Advisor unit gets on a fresh install, and the
# questions asked of a unit about them (#699). Sourced, never run.
#
#   scripts/advisord-unit-grants.sh           converges a host's unit to this table
#   scripts/test-install-advisord-sudo-wrapper.sh,
#   scripts/test-install-advisor-account.sh   hold each installer's fresh unit to it
#   scripts/test-get-aperire.sh               holds an UPDATED unit to the same
#                                             advisord_can_record_verified_image
#
# Sets no shell options: the suites that source it keep their own.

# ---- the table -------------------------------------------------------
#
# The writable grants a fresh install names that do not depend on the
# install directory or the deployment. The update ensures every one of them.
# A path added to either installer's ReadWritePaths= has to land here or in
# ADVISORD_RW_NOT_ENSURED below, with a reason: the installer suites render
# a fresh unit and fail on any entry neither list covers.
#
# The variable is overridable so the suites can point it at a temporary
# directory. It does reach root on a host: get-aperire.sh passes it through
# `run_root env` from its own APERIRE_GET_WRAPPER_STATE, and that run is
# either the operator's own sudo or aperire-update.sh's clean systemd
# environment, never the update payload. So the program does not trust the
# value for its name alone: it must be absolute, the directory and every
# ancestor up to / must be root's and not writable by anyone else
# (advisord-unit-grants.sh, ensure_grant_dir and ancestors_safe).
ADVISORD_WRAPPER_STATE="${APERIRE_WRAPPER_STATE_DIR:-/var/lib/aperire}"
ADVISORD_RW_GRANTS=("$ADVISORD_WRAPPER_STATE")

# What a fresh install names that this does NOT ensure, and why. Each is a
# path relative to the install directory.
#
#   advisor/state, advisor/evidence   in every unit any installer has ever
#                                     written, harden-advisord.sh's fallback
#                                     line included
#
# The node's own config and compose directories are the fourth kind, and
# the update DOES ensure them (#767): read from the wrapper's configuration
# (/etc/aperire/node-wrapper.conf), the same file both installers read, so
# they follow the deployment rather than the release. A first install used
# to write its unit before that file existed and name none of them, so an
# existing host converges here or nowhere. advisord_deploy_dirs is the one
# reading of it, for the program and the suites alike.
ADVISORD_RW_NOT_ENSURED=(advisor/state advisor/evidence)

# The Advisor's fleet corpus, relative to the tree the unit runs from (#746).
# The update ensures it in two steps: the node wrapper step makes it, owned by
# the unit's User= (_tp_ensure_corpus in trusted-path-lib.sh), and then the
# unit names it, the converter for a socket unit and advisord-unit-grants.sh
# for any other. Named only when it is a real directory (#1310), never a link,
# because ReadWritePaths= on a missing path fails the unit with 226/NAMESPACE.
ADVISORD_RW_TREE_GRANTS=(advisor/knowledge-fleet)

# The fleet corpus of the tree a unit runs from, read off its ExecStart=
# (<tree>/advisor/bin/aperire-advisord), the same reading the converter
# makes. Nothing when the unit does not start the Advisor from a tree.
advisord_unit_corpus() { # $1 = unit file
  local bin
  bin="$(grep -m1 '^ExecStart=' "$1" 2>/dev/null | sed 's/^ExecStart=//; s/^[-@:+!]*//; s/ .*//')"
  [[ "$bin" == /*/advisor/bin/aperire-advisord ]] || return 0
  printf '%s/%s\n' "${bin%/advisor/bin/aperire-advisord}" "${ADVISORD_RW_TREE_GRANTS[0]}"
}

# Is $2 one of the entries in the ReadWritePaths string $1? Whole words only:
# /var/lib/aperire-old is not /var/lib/aperire. systemd renders an optional
# entry with a leading "-", and that names the same path.
advisord_rw_names() { # $1 = space-separated entries, $2 = path
  local e
  for e in $1; do
    e="${e#-}"; e="${e#+}"
    [[ "${e%/}" == "${2%/}" ]] && return 0
  done
  return 1
}

# The one question the verify step asks of a unit: can the wrapper, running
# as root inside this unit's namespace, write where a verified image is
# recorded? Used by this script on what systemd loaded, and by the installer
# and update suites on the text they render, so a fresh install and an
# updated host are held to the same assertion.
advisord_can_record_verified_image() { # $1 = space-separated ReadWritePaths entries
  advisord_rw_names "$1" "$ADVISORD_WRAPPER_STATE"
}

# Is one entry of a freshly rendered unit's ReadWritePaths= accounted for,
# either ensured by this script or on the list above with its reason?
advisord_rw_entry_covered() { # $1 = entry, $2 = install dir, $3 = node-wrapper.conf (may be absent)
  local entry="${1#-}" dir="${2%/}" conf="${3:-}" g rel k f
  entry="${entry%/}"
  for g in "${ADVISORD_RW_GRANTS[@]}"; do
    [[ "$entry" == "${g%/}" ]] && return 0
  done
  for rel in "${ADVISORD_RW_NOT_ENSURED[@]}" "${ADVISORD_RW_TREE_GRANTS[@]}"; do
    [[ "$entry" == "$dir/$rel" ]] && return 0
  done
  while IFS= read -r f; do
    [[ -n "$f" && "$entry" == "$f" ]] && return 0
  done < <(advisord_deploy_dirs "$conf")
  return 1
}

# The directories the wrapper writes into when it acts on the node, one per
# line: the directory of CONFIG_FILE and of COMPOSE_FILE, each only when it
# is an absolute path to a directory that exists, each once. The same rule
# install-advisord.sh and install-advisor-account.sh apply when they write a
# fresh unit.
advisord_deploy_dirs() { # $1 = node-wrapper.conf (may be absent)
  local conf="${1:-}" k f d seen=" "
  [[ -n "$conf" && -r "$conf" ]] || return 0
  for k in CONFIG_FILE COMPOSE_FILE; do
    # shellcheck disable=SC2016  # awk's own $1
    f=$(awk -F= -v key="$k" '$1==key{sub(/^[^=]*=/,""); print; exit}' "$conf")
    [[ "$f" == /* ]] || continue
    d=$(dirname "$f")
    [[ -d "$d" ]] || continue
    [[ "$seen" == *" $d "* ]] && continue
    seen="$seen$d "
    printf '%s\n' "$d"
  done
  return 0
}
