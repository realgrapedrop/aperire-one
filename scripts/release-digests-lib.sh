#!/usr/bin/env bash
# release-digests-lib.sh - root copies only the bytes the release shipped.
#
# ADR 0024, lane 2. Every place root copies a program, a unit or a library
# out of an install tree into a root location goes through rd_install. It
# reads the tree file ONCE, through one open descriptor, into a root-owned
# staging file beside the destination, hashes that staging file, and compares
# the digest with the release's own record. What is hashed is what is
# installed: there is no second read of the tree between the check and the
# copy, so a rename-swap in the tree cannot land bytes the check never saw.
# The same read is the trusted-path check's (lane 1, trusted-path-lib.sh):
# the path is walked one descriptor at a time and refused if a service
# account can change any part of it, and the descriptor it judged is the one
# read. Both of ADR 0024's checks, on one read (#765).
#
# The record is /usr/local/lib/aperire/release.sha256, root 0644. get-aperire.sh
# writes it when a release lands, from the archive ROOT holds a copy of and
# has checked against the sha256 pinned in the bootstrap, before anything ran
# in the tree (release_manifest_verified there is the one function that
# vouches for it, and #736's release signature slots in at that point).
# fleet-update.sh writes it from the committed ref it deploys.
#
# Three answers, and only one of them copies without a check:
#
#   the bytes match          copied
#   the bytes differ         refused, named with both digests; the root copy
#                            that was there stays exactly as it was
#   no entry for the file    refused: a file the release did not ship is not
#                            one root copies because it turned up in the tree
#   no record on this host   copied from the one read, and each file is named
#                            as unchecked. A git checkout has no archive to
#                            record, and neither does a host installed before
#                            this existed. That is the one fallback, and it
#                            says so every time
#
# A record that is there and cannot be trusted (not a regular file, not
# root's, writable by anyone else, a line that is not a digest) refuses every
# copy. It never falls back to "no record": an account that could break the
# record must not thereby switch the check off.
#
# What this does NOT prove: that the code calling this was trustworthy. A
# grant installer run out of the tree verifies its copies with this library,
# and an installer somebody rewrote can skip that. Running root's installers
# from verified copies (#764) closes that; this closes the copies.
#
# The block between the markers is copied byte for byte into
# scripts/get-aperire.sh, which cannot source anything from a tree it is
# about to verify. scripts/test-release-digests-lib.sh fails if the two drift.
#
#   . scripts/release-digests-lib.sh
#   rd_install <tree> <path in the release> <destination> <mode>   (as root)
#   rd_priv rd_install ...                        (from a non-root shell)

# >>> release digests >>>
# Where the record lives. One constant, and root never reads anything else:
# under EUID 0 the environment is ignored outright, so no caller, sudo rule
# or unit can point root at a record of its choosing, or at none. An
# unprivileged fixture may point it at a file of its own; a fixture that runs
# as root (fakeroot) rewrites this one line in its copy instead.
RD_DIGESTS_DEFAULT=/usr/local/lib/aperire/release.sha256
# Whose account this process is, asked of id(1) at a fixed path and never of
# bash's $EUID. bash takes EUID from its environment (env EUID=1000 bash -c
# 'echo $EUID' prints 1000, and so does a root shell under fakeroot), so a
# root shell started with one would read a login's uid as its own and accept
# that login's files as root's (#1109). Prints the uid; fails when it cannot be
# read, and every caller below reads that as "not provably this account".
rd_euid() {
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
# Root, on positive evidence only.
rd_is_root() { [[ "$(rd_euid)" == 0 ]]; }
# Not root, on positive evidence only: an unreadable answer is neither, so the
# environment is not trusted and a fixture's shortcut is not taken on it.
rd_unprivileged() {
  local u
  u="$(rd_euid)" || return 1
  [[ "$u" != 0 ]]
}
rd_resolve_path() {
  if rd_unprivileged; then
    RD_DIGESTS="${APERIRE_RELEASE_DIGESTS:-$RD_DIGESTS_DEFAULT}"
  else
    RD_DIGESTS="$RD_DIGESTS_DEFAULT"
  fi
  # Beside the record: a host that has ever had one says so here, root-owned,
  # and from then on a missing record is a refusal, never the fallback.
  RD_REQUIRED="$(dirname -- "$RD_DIGESTS")/digests-required"
}
rd_resolve_path
# Larger than any file the release carries by two orders of magnitude, and
# small enough that a tree file swapped for /dev/zero cannot fill a disk.
RD_MAX_BYTES=16777216
# A tree file swapped for a FIFO blocks its open until a writer shows up.
# Bounded, so that is a refusal after a minute rather than a hung update.
RD_READ_TIMEOUT=60
RD_STATE=""
RD_BODY=""
RD_ANCHOR=""
# Set to 1, by the one caller that means it, for a single staging of a file
# root needs in order to see or repair a tree a service account can write.
# Never from the environment: every load of this block and every root shell
# rd_lib_text builds starts it at 0.
RD_PINNED=0
# Why the last refusal was not about the file: "accounts" when the account
# check could not run (systemd did not answer), empty for every other cause.
# rd_stage sets it and rd_note_refused tags the refusal file's line with it,
# so a closing block that reads the file can tell the two apart (#1089).
RD_REFUSED_WHY=""

rd_say_refused() { # $1 = path in the release, rest = why
  local rel="$1"; shift
  printf 'refused: %s %s\n' "$rel" "$*" >&2
}

# Load the record once per process. 0 = loaded, 3 = there is none on this
# host, 1 = there is one and it cannot be trusted, or the check that judges
# where it sits could not run (RD_STATE=fault). Said on stderr.
rd_manifest_load() {
  case "$RD_STATE" in
    ok) return 0 ;;
    none) return 3 ;;
    bad|fault) return 1 ;;
  esac
  local f="$RD_DIGESTS" meta want_uid line
  # The owner a real run needs is root. A fixture that runs unprivileged
  # writes its record as itself, and holding it to uid 0 there would be a
  # claim about a host nobody is on.
  want_uid=0
  rd_is_root || want_uid="$(rd_euid)" || want_uid=""
  if [[ ! -e "$f" && ! -L "$f" ]]; then
    # No record. The fallback, unless this host has had one: then something
    # took it away, and taking it away must not be how the check is turned off.
    if [[ -e "$RD_REQUIRED" || -L "$RD_REQUIRED" ]]; then
      RD_STATE=bad
      printf 'refused: this host has had release digests (%s) and %s is gone, so nothing is copied as root until a release puts it back: curl -fsSL https://get.aperire.one | bash -s -- --update --force\n' "$RD_REQUIRED" "$f" >&2
      return 1
    fi
    RD_STATE=none
    return 3
  fi
  RD_STATE=bad
  if [[ -L "$f" ]]; then
    printf 'refused: the release digests at %s are a symlink, so nothing is copied as root until that is put right.\n' "$f" >&2
    return 1
  fi
  meta="$(stat -c '%F:%u:%a' -- "$f" 2>/dev/null)" || meta=""
  if [[ "${meta%%:*}" != "regular file" ]]; then
    printf 'refused: the release digests at %s are not a regular file (%s).\n' "$f" "${meta%%:*}" >&2
    return 1
  fi
  local uid mode
  uid="${meta#*:}"; uid="${uid%%:*}"
  mode="${meta##*:}"
  if [[ "$uid" != "$want_uid" ]] || (( (8#$mode & 8#022) != 0 )); then
    printf 'refused: the release digests at %s are owned by uid %s, mode %s. They have to be root'"'"'s and writable by nobody else.\n' "$f" "$uid" "$mode" >&2
    return 1
  fi
  # And the directories above it, judged the way a copy's destination is,
  # with no tolerance and no symlink: an account that can write one of them
  # could rename an older record into place, or take the record away
  # (#877 review, L3). Only where the trusted-path check is loaded; without
  # it nothing is copied anyway.
  if declare -F _tp_run >/dev/null 2>&1; then
    local walk wrc=0
    if ! trusted_path_accounts; then
      printf 'refused: the release digests at %s could not be judged: %s.\n' "$f" "$(tp_accounts_refusal)" >&2
      # Not a verdict on the record, so it is not remembered as one: the next
      # copy asks again. rd_stage reads the reason to tell it as what it is.
      RD_STATE=""
      RD_REFUSED_WHY=accounts
      return 1
    fi
    # Judged as a place root writes to is, by the walk alone: an account
    # that can write any path at all (the docker group) is the source
    # check's finding, and the pre-migration login is one, so counting it
    # here would refuse every copy on every host before the account move.
    local -a TP_PRIV=()
    walk="$(_tp_run --strict check "$f")" || wrc=$?
    if [[ $wrc -ne 0 ]]; then
      _tp_say "$walk"
      # 2 is a finding. Anything else is a walk that never ran (no python3,
      # #1193): nothing was judged about where the record sits, so it is not
      # told as a finding about that.
      if [[ $wrc -ne 2 ]]; then
        RD_STATE=fault
        printf 'refused: the release digests at %s could not be judged: the check of the directories above them did not run (above), so nothing is copied as root.\n' "$f" >&2
        return 1
      fi
      printf 'refused: the release digests at %s sit where a service account can change them (above), so nothing is copied as root until that is put right.\n' "$f" >&2
      return 1
    fi
  fi
  RD_BODY=""
  RD_ANCHOR=""
  local n=0
  while IFS= read -r line || [[ -n "$line" ]]; do
    case "$line" in
      '# anchor '*) RD_ANCHOR="${line#\# anchor }" ;;
      '# refuse '*)
        # A record that stands for "no record this host trusts" (a rollback
        # to a tree whose digests were not kept): every copy refuses, and the
        # line says why and what puts it right.
        printf 'refused: %s\n' "${line#\# refuse }" >&2
        RD_BODY=""
        return 1 ;;
      '#'*|'') ;;
      *)
        if [[ ! "$line" =~ ^[0-9a-f]{64}\ \ [^[:cntrl:]]+$ ]]; then
          printf 'refused: the release digests at %s carry a line that is not a digest and a path.\n' "$f" >&2
          RD_BODY=""
          return 1
        fi
        RD_BODY+="$line"$'\n'
        n=$((n + 1)) ;;
    esac
  done < "$f"
  if [[ $n -eq 0 ]]; then
    printf 'refused: the release digests at %s name no file at all.\n' "$f" >&2
    return 1
  fi
  RD_STATE=ok
  return 0
}

# The digest the release records for one path, or nothing.
rd_digest_for() { # $1 = path in the release
  # Reads to the end rather than exiting on the match: an early exit closes the
  # pipe while printf is still writing a body bigger than a pipe buffer, printf
  # dies of SIGPIPE, and pipefail turns that into exit 141 (#973).
  printf '%s' "$RD_BODY" | awk -v k="$1" '!found && substr($0, 67) == k { print substr($0, 1, 64); found = 1 }'
}

# A path inside the release, spelled one way only: no leading slash, no
# empty, "." or ".." component, nothing but the characters release paths use.
rd_rel_ok() { # $1 = path in the release
  local rel="$1" part
  [[ "$rel" =~ ^[A-Za-z0-9._+-]+(/[A-Za-z0-9._+-]+)*$ ]] || return 1
  local IFS=/
  for part in $rel; do
    [[ "$part" != "." && "$part" != ".." ]] || return 1
  done
  return 0
}

# Why a copy refused on its digest: both digests, the record, the way back.
rd_say_mismatch() { # $1 = the release's digest, $2 = what was read
  printf '  release  %s\n  tree     %s\n  record   %s%s\n' "$1" "$2" "$RD_DIGESTS" "${RD_ANCHOR:+ ($RD_ANCHOR)}" >&2
  printf '  To put the release back as it shipped: curl -fsSL https://get.aperire.one | bash -s -- --update --force, which fetches it again.\n' >&2
  printf '  Code that is not a published release goes in from its git source (--update --source <repo> --ref <ref>),\n  which records no digests and names every copy unchecked.\n' >&2
}

# Read <tree>/<rel> once into <out>, which the caller made and root owns, and
# check what was read. 0 = the bytes are the release's (or there is no record
# and that was said), 1 = refused (said on stderr).
#
# Two checks, on one read (ADR 0024, "How root copies"; #765). With
# trusted-path-lib.sh loaded, trusted_path_copy walks the tree file's path
# from / one descriptor at a time, refuses a component a service account can
# change (and any symlink), reads the bytes from the descriptor it judged,
# and compares their sha256 with the release's before it writes <out>. The
# bytes judged, the bytes hashed and the bytes staged are one read.
#
# Without that check loaded, nothing is copied.
#
# Pinned (RD_PINNED=1): held to its release digest alone, read once through
# one descriptor, and never to its path. Only for a file root needs in order
# to see or repair a tree a service account can write (the state-ancestors
# narrowing, the wrapper step's library, the account move), where a path
# finding must not be what stops the repair of that finding. Only with a
# record: on a host with none there is no digest to pin, so a pinned staging
# takes both checks like any other (#877 review, M1, M2).
rd_stage() { # $1 = tree, $2 = path in the release, $3 = the file to fill
  local rel="$2" out="$3" tree want got rc size
  RD_REFUSED_WHY=""
  if ! rd_rel_ok "$rel"; then
    rd_say_refused "$rel" "is not a path inside a release."
    return 1
  fi
  tree="$(realpath -e -- "$1" 2>/dev/null)" || {
    rd_say_refused "$rel" "has no tree to come from: $1 does not resolve."
    return 1
  }
  rc=0
  rd_manifest_load || rc=$?
  if [[ $rc -eq 1 ]]; then
    if [[ "${RD_REFUSED_WHY:-}" == accounts ]]; then
      rd_say_refused "$rel" "was not copied: $(tp_accounts_refusal). Nothing about the file was judged."
    elif [[ "$RD_STATE" == fault ]]; then
      rd_say_refused "$rel" "was not copied: the check it is held to could not run (above). Nothing about the file was judged."
    else
      rd_say_refused "$rel" "was not copied, because the record it would be checked against cannot be trusted."
    fi
    return 1
  fi
  # What the bytes must be: the release's digest, or none at all on a host
  # with no record (the one fallback, said below every time).
  if [[ $rc -eq 3 ]]; then
    want=none
  else
    want="$(rd_digest_for "$rel")"
    if [[ -z "$want" ]]; then
      rd_say_refused "$rel" "is not a file this release shipped: the release digests have no entry for it."
      return 1
    fi
  fi

  local src="$tree/$rel" crc=0
  if [[ "$RD_PINNED" == 1 && "$want" != none ]]; then
    :
  elif declare -F trusted_path_copy >/dev/null 2>&1; then
    trusted_path_copy "$src" "$(dirname -- "$out")" "$(basename -- "$out")" 0600 "$tree" "$want" --strict || crc=$?
    case $crc in
      0) ;;
      3) printf '  warning: %s can be changed by %s, the login the dashboard runs as; used anyway (ADR 0024)\n' \
           "$rel" "${TP_REPORT_WHO:-that login}" >&2 ;;
      2) rd_say_refused "$rel" "can be changed by a service account (above), so root does not copy it."; return 1 ;;
      4) rd_say_refused "$rel" "is not the file this release shipped."
         rd_say_mismatch "$want" "$TP_COPY_DIGEST"
         return 1 ;;
      5) rd_say_refused "$rel" "was checked, and could not be staged (above)."; return 1 ;;
      6) rd_say_refused "$rel" "was not copied: $(tp_accounts_refusal). Nothing about the file was judged."
         RD_REFUSED_WHY=accounts
         return 1 ;;
      *) rd_say_refused "$rel" "could not be checked (above), so it was not copied."; return 1 ;;
    esac
    if [[ "$want" == none ]]; then
      printf '  unchecked: %s (no release digests on this host, so it was copied from one read and checked against nothing but its path)\n' "$rel" >&2
    fi
    return 0
  else
    rd_say_refused "$rel" "was not copied: the trusted-path check is not loaded here, and root copies only after both checks."
    return 1
  fi

  # Pinned: one open, and everything else through it. The descriptor
  # has to be the file the path names as it stands resolved, which refuses a
  # symlink at any component and a file renamed in from elsewhere; it has to
  # be a regular file; and the copy is read from that same descriptor, so the
  # bytes hashed below are the bytes that were checked for type and place.
  # shellcheck disable=SC2016  # the inner script's own positional parameters
  timeout "$RD_READ_TIMEOUT" bash -c '
    exec 3<"$1" || exit 3
    [ "$(readlink /proc/self/fd/3)" = "$1" ] || exit 5
    [ "$(stat -L -c %F /dev/fd/3)" = "regular file" ] || exit 4
    head -c "$2" <&3 > "$3" || exit 6
  ' rd-read "$src" "$((RD_MAX_BYTES + 1))" "$out" 2>/dev/null || crc=$?
  case $crc in
    0) ;;
    3) rd_say_refused "$rel" "is not in the tree at $tree."; return 1 ;;
    4) rd_say_refused "$rel" "is not a regular file."; return 1 ;;
    5) rd_say_refused "$rel" "is a symlink, or sits under one, so it is not the file its path names."; return 1 ;;
    124) rd_say_refused "$rel" "could not be read within ${RD_READ_TIMEOUT}s."; return 1 ;;
    *) rd_say_refused "$rel" "could not be read."; return 1 ;;
  esac
  size="$(stat -c %s -- "$out" 2>/dev/null)" || size=""
  if [[ -z "$size" ]] || (( size > RD_MAX_BYTES )); then
    rd_say_refused "$rel" "is larger than any file a release carries."
    return 1
  fi
  got="$(sha256sum < "$out" | cut -c1-64)"
  if [[ "$want" != "$got" ]]; then
    rd_say_refused "$rel" "is not the file this release shipped."
    rd_say_mismatch "$want" "$got"
    return 1
  fi
  return 0
}

# Place <tree>/<rel> at <dest>, root-owned, <mode>, only if its bytes are the
# release's. Prints "placed" or "same" on stdout and nothing else there.
# 0 = placed or already the same bytes, 1 = refused (the destination is left
# exactly as it was), 2 = could not be written. With $5 = --kinds, a refusal
# because the account check could not run also prints "refused:accounts" on
# stdout, the one word that crosses the sudo a caller reads only rc and
# stdout through (get-aperire.sh's root_place); no other caller passes it.
rd_install() { # $1 = tree, $2 = path in the release, $3 = destination, $4 = mode, $5 = --kinds or ""
  local tree="$1" rel="$2" dest="$3" mode="$4" dir base stg meta want_uid dmeta duid dgid dmode why
  RD_REFUSED_WHY=""
  dir="$(dirname -- "$dest")"
  base="$(basename -- "$dest")"
  if [[ ! -d "$dir" || -L "$dir" ]]; then
    printf 'error: %s is not a directory, so %s cannot be placed in it.\n' "$dir" "$base" >&2
    return 2
  fi
  # The directory has to be root's and writable by nobody else, or whoever
  # can write it can swap the staging file or the result under root. Group
  # write is allowed for gid 0 alone, whose members are root already. (The
  # directory's own ancestors are the trusted-path check's, lane 1.)
  want_uid=0
  rd_is_root || want_uid="$(rd_euid)" || want_uid=""
  dmeta="$(stat -c '%u:%g:%a' -- "$dir" 2>/dev/null)" || dmeta=""
  duid="${dmeta%%:*}"; dgid="${dmeta#*:}"; dgid="${dgid%%:*}"; dmode="${dmeta##*:}"
  if [[ -z "$dmeta" || "$duid" != "$want_uid" ]] || (( (8#$dmode & 8#002) != 0 )) \
     || { (( (8#$dmode & 8#020) != 0 )) && [[ "$dgid" != 0 ]]; }; then
    printf 'refused: %s is owned by uid %s, gid %s, mode %s, so %s was not placed there. Root writes only into a directory root owns and nobody else can write.\n' \
      "$dir" "${duid:-?}" "${dgid:-?}" "${dmode:-?}" "$base" >&2
    rd_note_refused "$dest" "$rel"
    return 1
  fi
  # Beside the destination, so the last step is a rename on one filesystem,
  # and in root's directory, so nothing else can touch it in between. mktemp
  # creates it O_EXCL under a random name, so nothing planted there first is
  # opened or followed.
  stg="$(mktemp "$dir/.$base.XXXXXXXXXX")" || {
    printf 'error: cannot make a staging file in %s.\n' "$dir" >&2
    return 2
  }
  if ! rd_stage "$tree" "$rel" "$stg"; then
    why="${RD_REFUSED_WHY:-}"
    rm -f -- "$stg"
    printf '  %s was left exactly as it was.\n' "$dest" >&2
    rd_note_refused "$dest" "$rel"
    if [[ "${5:-}" == --kinds && "$why" == accounts ]]; then printf 'refused:accounts\n'; fi
    return 1
  fi
  if [[ -f "$dest" && ! -L "$dest" ]] && cmp -s -- "$stg" "$dest"; then
    meta="$(stat -c '%u:%a' -- "$dest" 2>/dev/null)" || meta=""
    # Same bytes and already root's with this mode. A fixture that runs
    # unprivileged cannot own anything as root, so there it is the bytes.
    if rd_unprivileged || [[ "$meta" == "0:${mode#0}" ]]; then
      rm -f -- "$stg"
      printf 'same\n'
      return 0
    fi
  fi
  # Owner and mode are set on the staging file itself, it is flushed, and it
  # is renamed over the destination, never written into it: a running copy of
  # the program keeps its own inode, and a symlink planted at that name is
  # replaced rather than written through. Then the directory is flushed, so
  # the rename survives a crash.
  if { rd_unprivileged || chown 0:0 -- "$stg"; } \
     && chmod "$mode" -- "$stg" && sync -- "$stg" \
     && mv -fT -- "$stg" "$dest"; then
    sync -- "$dir" 2>/dev/null || true
    printf 'placed\n'
    return 0
  fi
  rm -f -- "$stg"
  printf 'error: %s could not be written.\n' "$dest" >&2
  return 2
}

# rd_install for an installer's own run: says what happened in the installer's
# voice and returns non-zero on anything but a placed or current copy, so a
# caller can `rd_place ... || die ...` and never go on to write a unit that
# names a program that is not there.
rd_place() { # $1 = tree, $2 = path in the release, $3 = destination, $4 = mode
  local out rc=0
  out="$(rd_install "$@" --kinds)" || rc=$?
  case $rc in
    0) if [[ "$out" == same ]]; then
         printf '   %s  (already matches the release)\n' "$3"
       else
         printf '   %s  (root:root %s, copied from the one read that was checked, renamed into place)\n' "$3" "$4"
       fi ;;
    1) if [[ "$out" == refused:accounts ]]; then
         printf 'error: %s was not written: the account check could not run (above), so %s was not judged.\n' "$3" "$2" >&2
       else
         printf 'error: %s was not written: %s in the tree is not the file this release shipped, or a service account can change it (above).\n' "$3" "$2" >&2
       fi ;;
    *) printf 'error: %s could not be written.\n' "$3" >&2 ;;
  esac
  return $rc
}

# The clause an installer's own error line puts after "nothing was written:",
# for a rd_stage that just failed in this shell. A refusal because the account
# check could not run is never told as a file that changed (#1111): $1 is what
# was being staged ("the broker in this tree"). Reads RD_REFUSED_WHY, so it is
# called in the same shell, straight after the failed rd_stage.
rd_was_accounts() { # $1 = the output of an rd_install --kinds that refused, when that is what failed
  [[ "${RD_REFUSED_WHY:-}" == accounts || "${1:-}" == refused:accounts ]]
}
rd_refused_cause() { # $1 = what was staged, $2 = as rd_was_accounts
  if rd_was_accounts "${2:-}"; then
    printf 'the account check could not run (above), so %s was not judged' "$1"
  else
    printf '%s is not the file this release shipped, or a service account can change it (above)' "$1"
  fi
}

# A refused copy is a failed run, not an amber line (#764). An installer run
# under install.sh, or under the update, has its refusals written to the file
# RD_REFUSED_LOG names, and the run that made that file lists them at its end
# and exits non-zero. Written only to a regular file this process owns, never
# through a symlink, and nothing else happens when the variable is unset.
#
# A line is "<destination> (from <path>)". When the refusal was not about the
# file but about the account check not running (RD_REFUSED_WHY=accounts), a
# tab and the word follow, so a closing block can tell a copy that was judged
# and refused from one that was never judged. A line with no tab is the first
# kind, as every line was before.
rd_note_refused() { # $1 = destination, $2 = path in the release
  local f="${RD_REFUSED_LOG:-}" why="${RD_REFUSED_WHY:-}"
  RD_REFUSED_WHY=""
  [[ -n "$f" && -f "$f" && ! -L "$f" && -O "$f" ]] || return 0
  printf '%s (from %s)%s\n' "$1" "$2" "${why:+$'\t'$why}" >> "$f" 2>/dev/null || true
}

# The files root runs out of a release: the top-level installers and every
# file under scripts/. With a record, the record's own entries, so a file the
# release did not ship is not one root runs because it turned up in the tree.
# With none (a git checkout), what the tree holds there, regular files only.
rd_stage_list() { # $1 = tree (resolved); RD_STATE is loaded
  if [[ "$RD_STATE" == ok ]]; then
    printf '%s' "$RD_BODY" | awk '{ p = substr($0, 67) } p == "install.sh" || p == "uninstall.sh" || p == "aperire-one" || p ~ /^scripts\// { print p }'
    return 0
  fi
  local f
  for f in install.sh uninstall.sh aperire-one; do
    [[ -f "$1/$f" && ! -L "$1/$f" ]] && printf '%s\n' "$f"
  done
  [[ -d "$1/scripts" && ! -L "$1/scripts" ]] || return 0
  (cd -- "$1" && find scripts -type f -print) | LC_ALL=C sort
}

# Stage what root runs out of a release, once per run (#764): install.sh,
# uninstall.sh, the menu and every file under scripts/, each through rd_stage
# (both checks, one read) into <out>/<the same path>, so an installer finds
# its siblings where it expects them and root never runs the tree's own
# bytes. <out> is an empty directory this process made and nobody else can
# write. All or nothing: 0 every file staged, 1 refused (each one named on
# stderr, in full) and nothing in <out> may be run.
#
# The account set is read once for the batch: nothing here writes a unit or
# adds an account. The warnings a tolerated tree earns, and the "unchecked"
# lines of a host with no record, are one line each for the whole set, not a
# hundred; a refusal is always said in full.
rd_stage_tree() { # $1 = tree, $2 = out
  local out="$2" tree rel f err rc n=0 tolerated=0 unchecked=0 who="" acct_n=0
  local -a refused_rels=()
  tree="$(realpath -e -- "$1" 2>/dev/null)" || {
    printf 'refused: %s does not resolve, so there is no release to stage for root.\n' "$1" >&2
    return 1
  }
  if [[ ! -d "$out" || -L "$out" || ! -O "$out" ]] || [[ -n "$(ls -A -- "$out" 2>/dev/null)" ]]; then
    printf 'refused: %s is not an empty directory of this account'"'"'s, so nothing was staged in it.\n' "$out" >&2
    return 1
  fi
  rc=0
  RD_REFUSED_WHY=""
  # python3, asked once and before anything is staged (#1355). Every file this
  # copies goes through a check that runs in it, at /usr/bin or /bin and never
  # off a PATH, so a host without it refused each file on its own and named
  # python3 once per file (198 lines for this tree). Said once, with the
  # reason the callers read (RD_REFUSED_WHY=python3), so none of them blames a
  # file for it. Where the trusted-path block is not loaded the next check
  # says so.
  if declare -F _tp_python >/dev/null 2>&1 && ! _tp_python >/dev/null; then
    printf 'refused: this host has no python3 at /usr/bin or /bin, and the check on every file root runs out of %s runs in it, so nothing was staged. Install it, then run this again: sudo apt-get install -y python3\n' "$tree" >&2
    RD_REFUSED_WHY=python3
    return 1
  fi
  rd_manifest_load || rc=$?
  if [[ $rc -eq 1 ]]; then
    if [[ "${RD_REFUSED_WHY:-}" == accounts ]]; then
      printf 'refused: the scripts in %s were not staged: %s.\n' "$tree" "$(tp_accounts_refusal)" >&2
    elif [[ "$RD_STATE" == fault ]]; then
      printf 'refused: the scripts in %s were not staged: the check they are held to could not run (above), so none of them was judged.\n' "$tree" >&2
    else
      printf 'refused: the scripts in %s were not staged, because the record they would be checked against cannot be trusted.\n' "$tree" >&2
    fi
    return 1
  fi
  if ! declare -F trusted_path_copy >/dev/null 2>&1; then
    printf 'refused: the trusted-path check is not loaded, so nothing in %s was staged for root.\n' "$tree" >&2
    return 1
  fi
  if ! trusted_path_hold_accounts "$tree"; then
    printf 'refused: %s, so the service accounts are unknown and nothing was staged.\n' "$(tp_accounts_refusal)" >&2
    RD_REFUSED_WHY=accounts
    return 1
  fi
  while IFS= read -r rel; do
    [[ -n "$rel" ]] || continue
    n=$((n + 1))
    f="$out/$rel"
    if ! (umask 022 && mkdir -p -- "$(dirname -- "$f")") || ! : > "$f" || ! chmod 0600 -- "$f"; then
      printf 'error: %s could not be made, so nothing was staged.\n' "$f" >&2
      refused_rels+=("$rel")
      break
    fi
    rc=0
    err="$(rd_stage "$tree" "$rel" "$f" 2>&1)" || rc=$?
    if [[ $rc -ne 0 ]]; then
      printf '%s\n' "$err" >&2
      refused_rels+=("$rel")
      # Counted, so a batch that was refused only because the account check
      # could not run says so to its caller (RD_REFUSED_WHY, #1111).
      case "$err" in *"the account check could not run"*) acct_n=$((acct_n + 1)) ;; esac
      continue
    fi
    case "$err" in
      *"the login the dashboard runs as"*)
        tolerated=$((tolerated + 1))
        [[ -n "$who" ]] || who="$(sed -n 's/.* can be changed by \(.*\), the login the dashboard runs as.*/\1/p' <<<"$err" | head -1)" ;;
    esac
    case "$err" in *"unchecked: "*) unchecked=$((unchecked + 1)) ;; esac
    case "$rel" in
      *.sh|*.py|aperire-one|scripts/xrpld-image/*) chmod 0755 -- "$f" ;;
      *) chmod 0644 -- "$f" ;;
    esac
  done < <(rd_stage_list "$tree")
  trusted_path_release_accounts
  if [[ ${#refused_rels[@]} -gt 0 ]]; then
    printf 'refused: %d of the %d files root runs out of %s did not pass both checks, so none of them is run as root:\n' "${#refused_rels[@]}" "$n" "$tree" >&2
    printf '  %s\n' "${refused_rels[@]}" >&2
    if [[ $acct_n -gt 0 && $acct_n -eq ${#refused_rels[@]} ]]; then RD_REFUSED_WHY=accounts; fi
    return 1
  fi
  if [[ $n -eq 0 || ! -f "$out/install.sh" ]]; then
    printf 'refused: %s holds no install.sh this release shipped, so there is nothing for root to run.\n' "$tree" >&2
    return 1
  fi
  if [[ $tolerated -gt 0 ]]; then
    printf '  warning: %d of the %d files root runs can be changed by %s, the login the dashboard runs as; used anyway (ADR 0024)\n' \
      "$tolerated" "$n" "${who:-that login}" >&2
  fi
  if [[ $unchecked -gt 0 ]]; then
    printf '  unchecked: %d files (no release digests on this host, so each was copied from one read and checked against nothing but its path)\n' "$unchecked" >&2
  fi
  return 0
}

# Everything above, as text a root shell can define. Used to run one of these
# functions as root from a shell that is not, without sourcing the tree again.
#
# The record's path is NOT carried across. The root side resolves it again
# (rd_resolve_path), and as root it takes the constant and ignores the
# environment: a caller that exported APERIRE_RELEASE_DIGESTS=/nonexistent
# must not thereby hand root the no-record fallback and every copy unchecked.
rd_lib_text() {
  printf 'RD_DIGESTS_DEFAULT=%q\nRD_MAX_BYTES=%q\nRD_READ_TIMEOUT=%q\nRD_STATE=\nRD_BODY=\nRD_ANCHOR=\nRD_PINNED=0\nRD_REFUSED_WHY=\n' \
    "$RD_DIGESTS_DEFAULT" "$RD_MAX_BYTES" "$RD_READ_TIMEOUT"
  declare -f rd_euid rd_is_root rd_unprivileged rd_resolve_path rd_say_refused rd_say_mismatch rd_manifest_load rd_digest_for rd_rel_ok rd_stage rd_install rd_place \
    rd_was_accounts rd_refused_cause rd_note_refused rd_stage_list rd_stage_tree rd_lib_text rd_priv
  # The trusted-path check travels with them when this shell has it, so the
  # root side makes the same two checks this shell would.
  if declare -F tp_lib_text >/dev/null 2>&1; then tp_lib_text; fi
  printf 'rd_resolve_path\n'
}

# Run one of these functions as root: directly when this shell already is,
# through sudo when it is not. The functions travel as text, so the root side
# runs exactly the code this shell has, never a second read of a tree file.
rd_priv() { # $1 = function, rest = its arguments
  if rd_is_root; then
    "$@"
    return
  fi
  local code
  code="$(rd_lib_text)"
  sudo -H bash -c "$code"$'\n''"$@"' rd-priv "$@"
}
# <<< release digests <<<

# A program built on this host, placed at <dest> as root: the relay, which
# install.sh compiles out of the tree before it installs it (#764). A release
# has no bytes to compare a build with, so the build is trusted the way the
# tree it was built in is trusted (ADR 0024, GA position 1): the trusted-path
# check alone, on the one read that is copied. No service account may be able
# to change the file or any directory on its way to it, and a symlink on that
# way is refused. Shipped binaries with release digests come after GA.
#
# Not part of the block get-aperire.sh carries: only an installer that sources
# this library places a built program. Same answers as rd_install: stdout only
# "placed" or "same"; 0 placed or same, 1 refused (the destination is left
# exactly as it was), 2 could not be written.
rd_install_built() { # $1 = the built file, $2 = destination, $3 = mode, $4 = install tree ("" for none)
  local dest="$2" mode="$3" tree="$4" src dir base stg dmeta duid dgid dmode want_uid crc=0
  RD_REFUSED_WHY=""
  dir="$(dirname -- "$dest")"
  base="$(basename -- "$dest")"
  src="$(realpath -e -- "$1" 2>/dev/null)" || {
    printf 'refused: %s does not resolve, so %s was not placed.\n' "$1" "$dest" >&2
    rd_note_refused "$dest" "$1"
    return 1
  }
  if ! declare -F trusted_path_copy >/dev/null 2>&1; then
    printf 'refused: the trusted-path check is not loaded here, so %s was not placed from %s.\n' "$dest" "$src" >&2
    rd_note_refused "$dest" "$src"
    return 1
  fi
  if [[ ! -d "$dir" || -L "$dir" ]]; then
    printf 'error: %s is not a directory, so %s cannot be placed in it.\n' "$dir" "$base" >&2
    return 2
  fi
  want_uid=0
  rd_is_root || want_uid="$(rd_euid)" || want_uid=""
  dmeta="$(stat -c '%u:%g:%a' -- "$dir" 2>/dev/null)" || dmeta=""
  duid="${dmeta%%:*}"; dgid="${dmeta#*:}"; dgid="${dgid%%:*}"; dmode="${dmeta##*:}"
  if [[ -z "$dmeta" || "$duid" != "$want_uid" ]] || (( (8#$dmode & 8#002) != 0 )) \
     || { (( (8#$dmode & 8#020) != 0 )) && [[ "$dgid" != 0 ]]; }; then
    printf 'refused: %s is owned by uid %s, gid %s, mode %s, so %s was not placed there.\n' \
      "$dir" "${duid:-?}" "${dgid:-?}" "${dmode:-?}" "$base" >&2
    rd_note_refused "$dest" "$src"
    return 1
  fi
  stg="$(mktemp "$dir/.$base.XXXXXXXXXX")" || {
    printf 'error: cannot make a staging file in %s.\n' "$dir" >&2
    return 2
  }
  trusted_path_copy "$src" "$dir" "$(basename -- "$stg")" 0600 "$tree" none --strict || crc=$?
  case $crc in
    0) ;;
    3) printf '  warning: %s can be changed by %s, the login the dashboard runs as; used anyway (ADR 0024)\n' \
         "$src" "${TP_REPORT_WHO:-that login}" >&2 ;;
    2) printf 'refused: %s can be changed by a service account (above), so root does not install it.\n' "$src" >&2 ;;
    5) printf 'refused: %s was checked, and could not be staged (above).\n' "$src" >&2 ;;
    6) printf 'refused: %s was not installed: %s. Nothing about the file was judged.\n' "$src" "$(tp_accounts_refusal)" >&2
       RD_REFUSED_WHY=accounts ;;
    *) printf 'refused: %s could not be checked (above), so it was not installed.\n' "$src" >&2 ;;
  esac
  if [[ $crc -ne 0 && $crc -ne 3 ]]; then
    rm -f -- "$stg"
    printf '  %s was left exactly as it was.\n' "$dest" >&2
    rd_note_refused "$dest" "$src"
    return 1
  fi
  if [[ -f "$dest" && ! -L "$dest" ]] && cmp -s -- "$stg" "$dest"; then
    if rd_unprivileged || [[ "$(stat -c '%u:%a' -- "$dest" 2>/dev/null)" == "0:${mode#0}" ]]; then
      rm -f -- "$stg"
      printf 'same\n'
      return 0
    fi
  fi
  if { rd_unprivileged || chown 0:0 -- "$stg"; } \
     && chmod "$mode" -- "$stg" && sync -- "$stg" \
     && mv -fT -- "$stg" "$dest"; then
    sync -- "$dir" 2>/dev/null || true
    printf 'placed\n'
    return 0
  fi
  rm -f -- "$stg"
  printf 'error: %s could not be written.\n' "$dest" >&2
  return 2
}

# The trusted-path check, from beside this file, unless the caller already
# has it. rd_stage copies nothing without it, so a script that sources this
# library gets both of ADR 0024's checks on every copy without naming the
# second one. get-aperire.sh, which carries the block above inline, loads
# its own from a staged copy instead (load_trusted_path_check there).
if ! declare -F trusted_path_copy >/dev/null 2>&1 \
   && [[ -r "$(dirname -- "${BASH_SOURCE[0]}")/trusted-path-lib.sh" ]]; then
  # shellcheck source=scripts/trusted-path-lib.sh
  . "$(dirname -- "${BASH_SOURCE[0]}")/trusted-path-lib.sh"
fi
