#!/usr/bin/env bash
# advisor-owner-lib.sh, the one place that decides which account owns the
# Advisor's state on THIS host (#568).
#
# Why this has to be one function. install-advisord.sh re-run on a host whose
# Advisor had already been moved onto its own account by
# install-advisor-account.sh re-owned the fleet trust file's group and five
# state directories to the invoking operator, because every chown and chgrp
# site in that script decided the target from SUDO_USER instead of asking
# what account the unit actually names. Every fleet trust push then failed
# with a 403 the operator only ever meets three hops away, at a refused
# passkey on a node that looks healthy (2026-08-19, reintroduced 2026-09-20).
#
# The 2026-09-20 reintroduction is what changed the fact this reads. The
# first fix trusted a marker, ${UNIT}.before-account, over the unit's own
# User= line. A host moved before that marker existed, or one whose unit
# directory was tidied since (the marker removed along with old install
# backups, the unit itself left alone), still runs as the dedicated account
# and carries no marker at all -- and a marker-only test read that host as
# never moved, so the very re-owning this file exists to prevent happened
# again, silently, on a host this file was already installed on.
#
# So the two facts this reads are no longer asked in a fixed order:
#
#   1. What does the unit's own User= say RIGHT NOW -- not cached, and not
#      only the unit's own [Service] block, but the EFFECTIVE value once
#      every drop-in that could override it has been applied, in the order
#      systemd itself loads them. See advisor_owner_effective_property below.
#      A host with no User= line anywhere the walk looks is systemd running
#      it as root, which the fallback account never is, so that alone means
#      moved -- unless nobody called with a fallback to compare against, in
#      which case there is nothing to disagree with (see next).
#
#   2. ${UNIT}.before-account, the marker install-advisor-account.sh alone
#      writes. This is now a TIEBREAKER, for exactly the shape User= cannot
#      answer: a caller with no fallback account to compare against, or a
#      unit with no User= line at all anywhere the walk looked. It is never
#      consulted when the caller supplies a fallback and the walk found a
#      User= to compare it to -- that comparison is the fact, and it does not
#      need the marker's agreement to be trusted.
#
# What this deliberately does NOT do: invent a group. install-advisor-account.sh
# writes Group=<the account's own primary group> in [Service] and puts the
# group two accounts actually share, aperire-svc today, in
# SupplementaryGroups= instead, so a resolver that read Group= (or asked
# `id -gn <account>`) and used that to chgrp the trust file or the state
# directories would hand them to the account's own primary group, which the
# dashboard is not a member of. That is the same failure with a different
# group name. So a caller that wants to CHANGE a group on a moved host does
# not get one handed to it here; advisor_owner_moved is the signal to skip
# the change entirely, which is what the done-when on #568 blesses, and
# advisor_owner_shared_group exists only for the one caller (orphan adoption)
# that has no choice but to put something on a file with no valid group left
# at all.
#
#   . "$REPO/scripts/advisor-owner-lib.sh"
#   OWNER_USER=$(advisor_owner_user "$UNIT" "$RUN_USER")
#   if ! advisor_owner_moved "$UNIT" "$RUN_USER"; then chgrp "$RUN_GROUP" "$FILE"; fi

# advisor_owner_unit_name <unit-path>: the name systemctl needs to be asked
# about a unit -- "aperire-advisord", never the path on disk -- from a path.
# The fallback reader further down still reads the path itself; only
# `systemctl cat` cares about the manager's own name for it.
advisor_owner_unit_name() {
  local base
  base="$(basename "$1")"
  printf '%s' "${base%.service}"
}

# advisor_owner_read_unit_files <unit-path>: the unit body, then every
# drop-in beside it in the lexicographic order systemd.unit(5) documents
# (a drop-in that is a symlink to a file included, as systemd follows it),
# each section headed by its own "# /path" line -- the shape `systemctl cat`
# prints, and the one aperire-advisord-credcheck.sh's own
# read_unit_files_in_load_order builds by hand when systemctl cannot answer.
# Restated here rather than sourced from there: that program is copied out of
# this tree to /usr/local/sbin on purpose (P1-090, see
# advisord-credcheck-lib.sh) and cannot read a checkout it no longer sits
# inside of, so the two copies are deliberately independent.
advisor_owner_read_unit_files() {
  local unit="$1" dropin_dir="${1}.d" f
  if [[ -f "$unit" ]]; then
    printf '# %s\n' "$unit"
    cat "$unit"
  fi
  if [[ -d "$dropin_dir" ]]; then
    while IFS= read -r -d '' f; do
      printf '# %s\n' "$f"
      cat "$f"
    done < <(find "$dropin_dir" -maxdepth 1 -xtype f -name '*.conf' -print0 | sort -z)
  fi
}

# advisor_owner_effective_property <unit-path> <key>: <key>'s effective value
# right now, from the unit body and every drop-in that can override it,
# systemd's own load order. Prints the value and returns 0 when the key was
# assigned anywhere the walk looked, even when the value it prints is empty
# -- an empty `User=` is systemd's own way of resetting an inherited value
# back to root (systemd.exec(5)), and that is a fact about this unit, not the
# absence of one. Returns 1, printing nothing, only when the key was never
# assigned anywhere at all.
#
# Read the way systemd reads it, not the way a grep would (#809): only lines
# inside a [Service] section count (a User= under [Install] or [Unit] is not
# one systemd applies), leading indentation and the whitespace either side
# of '=' are ignored, '#' and ';' lines are comments, and a value wrapped in
# one pair of quotes is the value inside them. Each of those used to read as
# "never assigned", which the account reader below turned into root.
#
# `User=` is scalar, not list-type like aperire-advisord-credcheck.sh's own
# LoadCredentialEncrypted=: systemd.unit(5) has a later assignment replace an
# earlier one outright, so the walk below only ever keeps the LAST match,
# never resets-and-rebuilds a list.
#
# systemctl cat is tried first, the one command that reflects the drop-in
# order systemd actually loaded rather than just the files on disk; a host
# with no systemctl, or one that cannot cat this unit, falls back to reading
# the unit and its drop-ins by hand in the same order.
#
# systemctl is asked by NAME, not by path -- it has no other way to be asked
# -- so its answer is trusted only when the section header it prints back
# names this exact path. Two units can share a basename: this project's own
# dev host runs a real aperire-advisord.service in /etc/systemd/system while
# a test fixture of the same name sits under a temporary directory, and
# without this guard the fixture's own test would silently read the live
# host's real unit instead of the file it just wrote. A mismatch is treated
# the same as systemctl having nothing to say, and the walk falls back to
# reading the path it was actually given.
advisor_owner_effective_property() {
  local unit="$1" key="$2" text="" cat_rc=1 unit_name first_header
  if command -v systemctl >/dev/null 2>&1; then
    unit_name="$(advisor_owner_unit_name "$unit")"
    text="$(systemctl cat "$unit_name" 2>/dev/null)"
    cat_rc=$?
    if [[ $cat_rc -eq 0 ]]; then
      first_header="$(printf '%s\n' "$text" | awk '/^# \// {print; exit}')"
      first_header="${first_header#\# }"
      [[ "$first_header" == "$unit" ]] || cat_rc=1
    fi
  fi
  if [[ $cat_rc -ne 0 ]]; then
    text="$(advisor_owner_read_unit_files "$unit")"
  fi
  [[ -n "$text" ]] || return 1

  local line hdr name value section="" found=1 result=""
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%$'\r'}"
    # Each file's own "# /path" header starts it afresh: a drop-in that
    # names no section of its own is not inside the last file's [Service].
    # Only a header that names this unit or a drop-in file that exists: an
    # ordinary comment that happens to start with a path is just a comment.
    if [[ "$line" == '# /'* ]]; then
      hdr="${line#\# }"
      if [[ "$hdr" == "$unit" || ( "$hdr" == *.d/*.conf && -f "$hdr" ) ]]; then
        section=""; continue
      fi
    fi
    line="${line#"${line%%[![:space:]]*}"}"
    [[ -n "$line" && "$line" != '#'* && "$line" != ';'* ]] || continue
    if [[ "$line" == '['*']' ]]; then section="$line"; continue; fi
    [[ "$section" == '[Service]' && "$line" == *=* ]] || continue
    name="${line%%=*}"
    name="${name%"${name##*[![:space:]]}"}"
    [[ "$name" == "$key" ]] || continue
    value="${line#*=}"
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    if [[ ${#value} -ge 2 && ( ( "$value" == '"'*'"' ) || ( "$value" == "'"*"'" ) ) ]]; then
      value="${value:1:${#value}-2}"
    fi
    result="$value"
    found=0
  done <<<"$text"
  [[ $found -eq 0 ]] || return 1
  printf '%s' "$result"
  return 0
}

# advisor_owner_unit_account <unit-path>: the account that one exact unit
# runs as. Three answers, and a caller has to keep them apart:
#
#   the account   its effective User=, through every drop-in
#   root          the unit says so: its effective User= is root, 0, or an
#                 empty assignment (systemd's own reset to root)
#   nothing       there is no such unit on this host
#
# And one refusal, exit 3 with nothing printed: the unit is there but no
# User= could be read out of it, or it cannot be read at all, or it reads
# as root while ${unit}.before-account says install-advisor-account.sh moved
# this Advisor onto its own account. install-advisord.sh always writes a
# User= line, so a unit with none is one this reader does not understand,
# not a host running as root. Before #809's review all of these printed
# "root", every caller took that as "no second account", and the token
# files landed on the dashboard's own group: the #809 symptom again, with
# no word said. advisor_owner_unread_msg says it in words.
advisor_owner_unit_account() {
  local unit="$1" eff
  [[ -e "$unit" || -L "$unit" ]] || return 0
  [[ -r "$unit" ]] || return 3
  eff="$(advisor_owner_effective_property "$unit" User)" || return 3
  [[ -n "$eff" && "$eff" != 0 ]] || eff=root
  if [[ "$eff" == root && -e "${unit}.before-account" ]]; then
    return 3
  fi
  printf '%s' "$eff"
}

# advisor_owner_unread_msg <unit-path>: the sentence a caller refuses with
# when advisor_owner_unit_account (or advisor_owner_account) returns 3.
advisor_owner_unread_msg() {
  local unit="$1" name eff
  name="$(advisor_owner_unit_name "$unit")"
  if [[ -r "$unit" && -e "${unit}.before-account" ]] \
     && eff="$(advisor_owner_effective_property "$unit" User)"; then
    printf '%s reads as running as root (User=%s), but %s.before-account says this Advisor was moved onto its own account. Nothing was changed. Check the User= line with: systemctl cat %s' "$unit" \
      "$eff" "$unit" "$name"
    return 0
  fi
  printf 'could not read which account the Advisor runs as from %s: no User= line under [Service] there or in its drop-ins, or the file cannot be read. Nothing was changed. Check it with: systemctl cat %s' "$unit" \
    "$name"
}

# advisor_owner_account [unit-dir] [instance]: the account the Advisor runs
# as, read from EXACTLY aperire-advisord.service, or
# aperire-advisord-<instance>.service when the caller has an instance, and
# never from a glob. A glob over "aperire-advisord*.service" also matches
# aperire-advisord-credcheck.service, the OnFailure= handler
# install-advisor-account.sh writes beside the real unit (#541). It runs
# User=root by design, and '-' sorts before '.' in ASCII, so a first-match
# reader got root on every host with an Advisor: #589 on the trust-file
# check, #809 on the fleet token group, which refused every restore and
# every approval on an aggregator that runs the Advisor.
#
# Prints one of advisor_owner_unit_account's three answers, or returns 3
# for its refusal (advisor_owner_unread_msg names it). An instance
# that is not an instance name (the credcheck unit's own suffix included)
# prints nothing and returns 2: that is a caller's mistake, not a host with
# no Advisor.
advisor_owner_account() {
  local dir="${1:-/etc/systemd/system}" inst="${2:-}"
  if [[ -n "$inst" ]]; then
    [[ "$inst" =~ ^[a-z0-9][a-z0-9-]{0,30}$ && "$inst" != credcheck && "$inst" != credcheck-* ]] \
      || return 2
  fi
  advisor_owner_unit_account "$dir/aperire-advisord${inst:+-$inst}.service"
}

# advisor_owner_moved <unit-path> [fallback]: true (0) when this host's
# Advisor account is not the one that would otherwise own it.
#
# With a fallback supplied, User= IS the fact: the unit's effective value
# (an explicit empty assignment reads as "root", never as "not moved") is
# compared to it directly, marker or no marker. A unit that does not exist at
# all is a fresh install, a third shape distinct from "unit with no User=",
# and reads as not moved without asking the marker anything -- there is no
# account yet to disagree with the fallback about.
#
# With no fallback, or when the walk found no User= anywhere to compare
# (a unit that predates the line, kept across an upgrade), the marker is the
# only fact left, and this degrades to exactly what it always answered: did
# install-advisor-account.sh's own marker get left behind here.
advisor_owner_moved() {
  local unit="$1" fallback="${2:-}" eff
  [[ -f "$unit" ]] || return 1
  if [[ -n "$fallback" ]]; then
    if eff="$(advisor_owner_effective_property "$unit" User)"; then
      [[ -n "$eff" ]] || eff="root"
      [[ "$eff" != "$fallback" ]]
      return
    fi
  fi
  [[ -f "${unit}.before-account" ]]
}

# advisor_owner_user <unit-path> <fallback>: the account whose files under
# advisor/ and the fleet trust file this run should write as. On a moved
# host that is whatever the unit's own User= line effectively says right
# now; everywhere else it is the fallback the caller already resolved for a
# host that has not moved (normally the invoking operator, which is also the
# dashboard's own account before the move).
#
# An empty effective value is never handed back here, even on a moved host:
# advisor_owner_moved reads that as "root" to decide the yes/no question, but
# chown-ing state to literally root is not what any caller of THIS function
# wants, so it falls back exactly as it would if nothing had moved at all.
advisor_owner_user() {
  local unit="$1" fallback="$2" eff
  if advisor_owner_moved "$unit" "$fallback"; then
    eff="$(advisor_owner_effective_property "$unit" User)"
    [[ -n "$eff" ]] && { printf '%s' "$eff"; return 0; }
  fi
  printf '%s' "$fallback"
}

# advisor_owner_shared_group <unit-path> [fallback]: the group a moved
# Advisor shares with the dashboard (install-advisor-account.sh's own
# $SHARED, "aperire-svc" today), read from the unit's effective
# SupplementaryGroups= line rather than hardcoded: the installer could rename
# it, and at least one node in this fleet was set up by hand under a
# different one. Empty when the unit is not on a moved host, or names no
# supplementary group at all: the caller's cue to fall back to something else
# rather than invent a name.
#
# This exists for exactly one caller: a file whose group no longer resolves
# to any account at all (adopt_orphaned_files) has no "leave it alone"
# option, and putting it back on the operator's group would be the same
# mistake in miniature. Everything else that wants to CHANGE a group on a
# moved host should call advisor_owner_moved and skip instead.
advisor_owner_shared_group() {
  local unit="$1" fallback="${2:-}" g
  advisor_owner_moved "$unit" "$fallback" || { printf ''; return 0; }
  g="$(advisor_owner_effective_property "$unit" SupplementaryGroups)" || { printf ''; return 0; }
  # First token only: today's arrangement names exactly one, and a caller
  # asking for "the" shared group has nothing to do with a second.
  printf '%s' "${g%% *}"
}
