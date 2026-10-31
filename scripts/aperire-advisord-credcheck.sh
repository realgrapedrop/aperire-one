#!/usr/bin/env bash
# Runs exactly once per failure, and only because it is named on
# aperire-advisord's own OnFailure= (systemd.unit(5): "activated when this
# unit enters the failed state"). Never started by hand, never enabled, never
# on a timer. Its whole job is to tell one failure apart from every other:
# a model credential that is on this host and will not decrypt on it.
#
# Installed by scripts/advisord-credcheck-lib.sh to /usr/local/sbin, never
# run from the checkout it started in (P1-090): a unit naming this file
# inside the tree would be root, on demand, for whichever account owns that
# checkout, which on a dashboard-installed host is the unprivileged account
# the dashboard itself runs as, and the Advisor's own account can force the
# trigger just by crashing itself. Every other root program in this project
# is copied out of reach the same way; install-model-key-sealer.sh says why
# at more length.
#
#   sudo bash scripts/aperire-advisord-credcheck.sh
#
# ---- why this exists (#541) ------------------------------------------
#
# The credential and the directive that loads it come and go together
# (aperire-seal-model-key.sh's own rule): LoadCredentialEncrypted=, in a
# drop-in of its own, naming a file under /etc/aperire/creds. Sealing now
# checks that the file it just wrote reads back before the drop-in is ever
# written, which closes the deterministic half of this: a key sealed here
# always opens here.
#
# What that check cannot see is a blob that was FINE when the drop-in was
# written and is not fine now. This is the exact shape of a backup restored
# onto the wrong host, or the wrong backup restored onto this one (#514).
# systemd refuses to start a unit that declares a credential it cannot
# decrypt (243/CREDENTIALS) before the program ever runs, and Restart=always
# tries again three seconds later, forever, unless the unit's own start
# limit can actually be reached, which install-advisord.sh and
# install-advisor-account.sh now set it to be, and which is what turns this
# script's trigger into a single, dependable moment rather than a race with
# a start already in flight.
#
# ---- what it does, and does not, decide -------------------------------
#
# No declared credential, or a named credential that decrypts fine: this
# program does nothing and prints why. The unit stays in `failed`, which is
# where `systemctl --failed` and every ordinary check will find it, because a
# failure with nothing to do with a credential is a real failure and quietly
# clearing it would hide one.
#
# The declaration is looked for wherever it may be, not only in the drop-in
# this program itself writes over on a quarantine (#541). A host upgraded
# before the drop-in convention existed still carries LoadCredentialEncrypted=
# in the unit's own [Service] block
# (install-advisor-account.sh:751 carries that line forward on a re-run
# rather than migrating it), and reading only $DROPIN there found nothing to
# check on a unit that had everything to check. See
# read_load_credential_encrypted below for how the two are reconciled.
#
# systemd-creds decrypt failing is not, by itself, "this blob cannot be
# opened on this host" (P2-092). A missing binary, a TPM this shell cannot
# reach, or a host key that could not be read for a moment are all real
# failures that say nothing about the CREDENTIAL, and this program is root
# taking a key away from the Advisor: an unknown failure has to be read as
# "could not check" rather than guessed at as "checked and it failed".
#
# So the decision is an allowlist, not a denylist. Quarantine happens ONLY
# when systemd-creds' own stderr matches one of the small, named, observed
# set of strings that mean "this host actually looked at the bytes and they
# are wrong" (see DETERMINISTIC_CRED_ERRORS below). Every other non-zero
# result, whether it is one of the known transients documented here or
# something never seen before, leaves the credential and its drop-in exactly
# as found, names the exit code and the first line of stderr, and exits
# non-zero itself so the unit that ran it is not mistaken for a clean pass.
# See "reading the failure apart" below for what was actually observed and
# what could not be.
#
# A named credential whose stderr matches DETERMINISTIC_CRED_ERRORS below,
# meaning this host DID check and got a definite no: the file is moved
# aside, never deleted (an operator who restored the wrong
# backup gets the evidence, not a silent loss), the credential list the unit
# declares is reset to empty in a drop-in of its own (never by rewriting the
# unit body, which belongs to the two installers, not to this program),
# systemd is reloaded, and the unit is given one clean restart. It comes back
# with no model, reports `credential_present: false`
# through the path that already exists for that (#516), and the Advisor's
# own next start records the credential's disappearance on its ledger from
# what it observes (recordCredentialTransition, P2-081). That entry says
# only "no longer present" on its own; this program leaves a note beside
# the model configuration (the same shape aperire-seal-model-key.sh's
# write_change_file leaves) so the entry can add why: the credential could
# not be opened on this host, discovered by the credential check.
#
# Nothing here ever prints or logs the credential's contents. It is decrypted
# once, to /dev/null, purely to learn whether decryption succeeds.
#
# ---- reading the failure apart (P2-092) --------------------------------
#
# Hand-tested against the real systemd-creds (255.4, this project's own dev
# host, 2026-09-19), as a non-root user with no readable host key and no
# usable TPM device node, which is the shape of a transient this program
# has to leave alone rather than act on:
#
#   binary missing            command -v fails; caught before decrypt ever
#                              runs, never reaches systemd-creds' own text
#   no TPM reachable           "Failed to open specified TCTI device file
#                              /dev/tpmrm0: Permission denied" / "Failed to
#                              create TPM2 context: State not recoverable"
#   no readable host secret    "Failed to determine local credential host
#                              secret: Permission denied"
#
# These are documented and kept as test cases, but they decide nothing: this
# host could not ANSWER the question, and under the allowlist below that
# reads the same as a message nobody has ever seen. What could not be
# produced by hand in that same non-root shell is a real blob sealed to a
# DIFFERENT host, or one actually truncated on disk (the #514 case this
# program exists for): making either needs root and a real credential store
# to check at all.
#
# Those were produced separately: as root, against a real sealed credential,
# on a lab host running systemd 255 (255.4-1ubuntu8.17), 2026-09-19, exit
# code 1 in every case:
#
#   sealed on another host    "Decryption failed (incorrect key?):
#                              error:00000000:lib(0)::reason(0)"
#   truncated blob            "Failed to read encrypted credential data:
#                              Broken pipe" (also seen by hand: "Failed to
#                              read encrypted credential data: ..." and
#                              "Encrypted file too short.")
#
# DETERMINISTIC_CRED_ERRORS matches on the stable prefixes those carry
# ("Decryption failed", "Failed to read encrypted credential data",
# "Encrypted file too short."), never the full line: the parenthetical after
# "Decryption failed" is OpenSSL's own error stack and is not guaranteed to
# repeat verbatim. Jammy ships systemd 249; its wording for these same
# failures is unverified against this list, and an unrecognised message
# there is, by design, left alone rather than guessed at. The operator's way
# back is a re-seal, and verify-after-restart.sh already shows the failed
# unit in red.

set -uo pipefail

[[ $EUID -eq 0 ]] || { echo "refused: must run as root; reading a sealed credential and reloading systemd are root-only" >&2; exit 1; }

# As root the environment chooses no path or program (#1206): every
# APERIRE_* variable is dropped except the ones a root caller passes on
# purpose:
#   APERIRE_INSTANCE       this program's own unit sets it (advisord-credcheck-lib.sh);
#                          checked below
#   APERIRE_ADVISOR_STATE  the same unit sets it, to the instance's advisor/state;
#                          every write there is by descriptor (state-file.py)
# An account id(1) says is not root keeps them all, which is what every
# suite is. id(1) at a fixed path, never bash's $EUID (#1109).
if ! [[ "$(/usr/bin/id -u 2>/dev/null)" =~ ^[1-9][0-9]*$ ]]; then
  for _v in $(compgen -e); do
    case "$_v" in APERIRE_INSTANCE|APERIRE_ADVISOR_STATE) ;; APERIRE_*) unset "$_v" ;; esac
  done
fi
# The instance names a unit file and a drop-in path, so it is held to the
# rule advisor-owner-lib.sh holds it to, under the C locale (under
# en_US.UTF-8, [a-z] matches é), and anything else is refused.
instance_name_ok() { # $1 = a name; [a-z] is held to ASCII, whatever the locale
  local LC_ALL=C
  [[ "$1" =~ ^[a-z0-9][a-z0-9-]{0,30}$ && "$1" != credcheck && "$1" != credcheck-* ]]
}
if [[ -n "${APERIRE_INSTANCE:-}" ]] && ! instance_name_ok "$APERIRE_INSTANCE"; then
  printf 'refused: APERIRE_INSTANCE=%q is not an instance name (a-z, 0-9 and -, at most 31, not credcheck)\n' "$APERIRE_INSTANCE" >&2
  exit 2
fi

UNIT_DIR="${APERIRE_UNIT_DIR:-/etc/systemd/system}"
ADVISORD_UNIT="aperire-advisord${APERIRE_INSTANCE:+-$APERIRE_INSTANCE}"
UNIT="$UNIT_DIR/${ADVISORD_UNIT}.service"
DROPIN_DIR="$UNIT.d"
DROPIN="$DROPIN_DIR/model-credential.conf"
# Where this instance's model.json lives, so a quarantine can leave the
# attribution note beside it, set by advisord-credcheck-lib.sh, which is
# the only thing that writes the unit this program runs under. Empty on a
# host where that line was never written (an older unit kept across an
# upgrade): the note is then skipped, said explicitly, never guessed at.
ADVISOR_STATE="${APERIRE_ADVISOR_STATE:-}"
# Every file this program writes under advisor/state goes through the state
# helper (#703), which does the create and the ownership on a descriptor it
# opened relative to a descriptor on the directory, rather than on a name the
# Advisor's own account can swap. Resolved from /usr/local/sbin, where
# advisord-credcheck-lib.sh puts a root-owned copy beside this program on
# every install and every refresh, and only from a checkout when this program
# is itself being run out of one. Never from a checkout otherwise: this runs
# as root, and the tree belongs to an unprivileged account.
#
# Never taken from the environment (#1148). This program is root, and the file
# STATE_TOOL names is run by it: a drop-in or a root shell the login started
# would otherwise choose that file. Where this program sits decides, in this
# order, and an installed name that is not what the installer put there is
# refused rather than passed over for the next one: a regular file, not a link,
# owned by root, writable by neither group nor other. A suite that needs a
# stand-in puts a state-file.py beside its own copy of this program.
STATE_TOOL=""
STATE_TOOL_WHY=""
STATE_TOOL_INSTALLED=/usr/local/sbin/aperire-state-file
STATE_FILE_UID=0
installed_file_ok() { # $1 = a path root is about to run or source
  local meta
  [[ -f "$1" && ! -L "$1" && -r "$1" ]] || return 1
  meta="$(stat -c '%u:%a' -- "$1" 2>/dev/null)" || return 1
  [[ "${meta%%:*}" == "$STATE_FILE_UID" ]] && (( (8#${meta##*:} & 8#022) == 0 ))
}
# Bash itself, no dirname: this has to resolve with a PATH that holds
# nothing, as a unit with a bare environment can have.
_src_dir="${BASH_SOURCE[0]}"
if [[ "$_src_dir" == */* ]]; then _src_dir="${_src_dir%/*}"; else _src_dir=.; fi
# CDPATH emptied: a relative program path would otherwise be looked up in
# the directories the environment names, and the helper and library are
# found beside whatever directory that finds.
_sf_here="$(CDPATH='' cd -- "$_src_dir" && pwd)"
# Beside this program first, wherever this program is, because that is exactly
# how the installer places it. `aperire-state-file` is the installed name and
# never the checkout's. Then the default destination, for a program that was
# moved without its helper. Then a checkout copy, which is only reachable when
# this program is itself being run out of a checkout.
for _sf_c in "$_sf_here/aperire-state-file" "$STATE_TOOL_INSTALLED"; do
  [[ -e "$_sf_c" || -L "$_sf_c" ]] || continue
  if installed_file_ok "$_sf_c"; then
    STATE_TOOL="$_sf_c"
  else
    STATE_TOOL_WHY="$_sf_c is not a regular file owned by root that no one else can write"
  fi
  break
done
if [[ -z "$STATE_TOOL" && -z "$STATE_TOOL_WHY" && -f "$_sf_here/state-file.py" ]]; then
  STATE_TOOL="$_sf_here/state-file.py"
fi
unset _sf_c
# How this host keeps a model key (#708). Resolved exactly the way STATE_TOOL
# above is, and installed beside this program by advisord-credcheck-lib.sh for
# the same reason: this runs as root out of /usr/local/sbin with no tree
# beside it. A host without it is refused rather than guessed at, the same
# stance this program already takes when systemd-creds itself is missing: the
# unit stays failed and the journal names the command that repairs the host.
METHOD_LIB=""
METHOD_LIB_WHY=""
METHOD_LIB_INSTALLED=/usr/local/sbin/aperire-model-key-method
# Sourced, so it is held to the same check as the helper above and for a
# stronger reason: whatever it holds runs in this shell. Not taken from the
# environment either (#1148).
for _ml_c in "$_sf_here/aperire-model-key-method" "$METHOD_LIB_INSTALLED"; do
  [[ -e "$_ml_c" || -L "$_ml_c" ]] || continue
  if installed_file_ok "$_ml_c"; then
    METHOD_LIB="$_ml_c"
  else
    METHOD_LIB_WHY="$_ml_c is not a regular file owned by root that no one else can write"
  fi
  break
done
if [[ -z "$METHOD_LIB" && -z "$METHOD_LIB_WHY" && -f "$_sf_here/model-key-method-lib.sh" ]]; then
  METHOD_LIB="$_sf_here/model-key-method-lib.sh"
fi
unset _sf_here _ml_c _src_dir
# shellcheck source=scripts/model-key-method-lib.sh
if [[ -n "$METHOD_LIB" && -f "$METHOD_LIB" ]]; then . "$METHOD_LIB"; fi

TAG=aperire-advisord-credcheck
# The one directory this program will ever move a file inside of (F5,
# #541 follow-up, 2026-09-20). It runs as root on OnFailure=, moving
# whatever path the unit's own effective declaration names; a unit is
# ordinarily this project's own, but the declaration is read off whatever
# is on disk, drop-ins included, and this program has no business acting on
# an absolute path outside the one directory every credential this project
# seals ever lands in, whatever a hand-edited or malformed drop-in names.
CREDS_DIR="${APERIRE_CREDS_DIR:-/etc/aperire/creds}"

# The allowlist (P2-092): quarantine happens ONLY when systemd-creds' own
# stderr starts with one of these. Observed as root, against a real sealed
# credential, on a lab host running systemd 255 (255.4-1ubuntu8.17),
# 2026-09-19; see "reading the failure apart" above for how each one was
# produced. Jammy ships systemd 249, whose wording for these same failures
# is unverified against this list; extend it from evidence, not guesswork,
# when that host is checked.
DETERMINISTIC_CRED_ERRORS=(
  'Decryption failed'                          # sealed on a different host
  'Failed to read encrypted credential data'   # corrupt / unreadable blob
  'Encrypted file too short.'                  # truncated blob
)

say() { # $1 = outcome word, rest = detail. Never a credential's contents.
  local outcome="$1"; shift
  if command -v logger >/dev/null 2>&1; then
    logger -t "$TAG" -p authpriv.notice -- "$outcome: $*" || true
  fi
  printf '%s: %s\n' "$outcome" "$*" >&2
}

# write_credential_note $1=via $2=credential name. Same shape as
# aperire-seal-model-key.sh's write_change_file (at/via/credential_name; no
# by, no issuer, because nothing here was an operator's instruction),
# restated rather than sourced: this program runs from /usr/local/sbin with
# no tree beside it.
#
# A failure to write is said out loud, never swallowed (root_cause_not_workaround):
# a departure entry with no attribution is the behaviour this fix started
# from, not the mark of something worth hiding. Still non-fatal: the
# credential is already quarantined and the unit already given its clean
# restart by the time this runs, and a missing note must not undo either.
write_credential_note() {
  local via="$1" cred="$2" err
  if [[ -z "$ADVISOR_STATE" ]]; then
    say refused "no APERIRE_ADVISOR_STATE set on this unit; no attribution note left for $cred"
    return 0
  fi
  if [[ ! -d "$ADVISOR_STATE" ]]; then
    say refused "$ADVISOR_STATE does not exist; no attribution note left for $cred"
    return 0
  fi
  if [[ -z "$STATE_TOOL" || ! -f "$STATE_TOOL" ]]; then
    say refused "no state-file helper beside this program${STATE_TOOL_WHY:+ ($STATE_TOOL_WHY)}; no attribution note left for $cred"
    return 0
  fi
  # Owner and group taken from the state directory itself, which is what the
  # `chown --reference` this replaced was asking for, and taken by the helper
  # from the descriptor it already holds on that directory rather than from a
  # second lookup by name.
  if ! err="$({
    printf '{\n'
    printf '  "at": "%s",\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf '  "via": "%s",\n' "$via"
    printf '  "credential_name": "%s"\n' "$cred"
    printf '}\n'
  } | python3 -I "$STATE_TOOL" plant "$ADVISOR_STATE/model-change.json" dir dir 0640 --stdin 2>&1)"; then
    say refused "could not write an attribution note under $ADVISOR_STATE for $cred: $err"
    return 0
  fi
}

# read_load_credential_encrypted: every credential this unit's
# LoadCredentialEncrypted= effectively declares right now, wherever the
# lines that produce it live, one "name<TAB>path<TAB>file" line per entry.
#
# `systemctl show -p LoadCredentialEncrypted --value` was tried here first
# and is removed now (2026-09-20): hand-measured against a lab host running
# systemd 255.4-1ubuntu8.17, a unit that declares this credential in its own
# [Service] block,
#
#   $ systemctl show aperire-advisord -p LoadCredentialEncrypted --value
#   LoadCredentialEncrypted=[unprintable]
#   $ systemctl show aperire-advisord -p LoadCredentialEncrypted
#   LoadCredentialEncrypted=[unprintable]
#
# systemd redacts this property's answer to the fixed string "[unprintable]"
# and keeps the "Name=" prefix regardless of --value. That string never
# contains a colon, so there is no name:path pair in it to parse, ever; it is
# simply out of this decision from here on.
#
# `systemctl cat` is the one command that answers the question this program
# actually has: the unit body and every drop-in beside it, printed in the
# order systemd loads them, each section headed by its own "# /absolute/path"
# comment line (systemd.unit(5), "Overriding Vendor Configuration"). Same
# host, same day:
#
#   $ systemctl cat aperire-advisord | grep -n 'LoadCredential\|^# /'
#   1:# /etc/systemd/system/aperire-advisord.service
#   8:LoadCredentialEncrypted=model-api-key-anthropic:/etc/aperire/creds/model-api-key-anthropic
#   42:# /etc/systemd/system/aperire-advisord.service.d/10-knowledge-fleet.conf
#
# LoadCredentialEncrypted= is a list-type setting (systemd.exec(5): "This
# option may be used multiple times, each time defining an additional
# credential"), and systemd.unit(5) documents the one way a drop-in removes
# an entry from a list setting: "one needs to first clear the list before
# re-adding all entries except the one that is to be removed". The walk below
# applies exactly that, in the order the lines were actually loaded: an empty
# LoadCredentialEncrypted= line resets the whole accumulated set, wherever
# its entries came from; a non-empty one adds a name, or, for a name already
# present, replaces that name's path and file in place
# (aperire-seal-model-key.sh's own comment: "a unit and a drop-in naming the
# same credential id do not refuse each other, and the drop-in is the one the
# service receives", hand-tested there against the same systemd). What
# survives to the end of the walk is the effective set.
#
# Worth stating rather than assuming: an empty assignment in a drop-in only
# ever cancels a body-declared credential because drop-ins are always parsed
# after the unit body (same systemd.unit(5) section). This program's own
# reset drop-in ($DROPIN, written below) relies on exactly that, and
# test-advisord-credcheck.sh's fixture systemctl cat text is built from this
# host's own real drop-in layout, 10-knowledge-fleet.conf included, which
# sorts before $DROPIN's own filename and so is never what stands between a
# reset and it taking effect.
#
# A section header is trusted only when the line reads "# " followed by a
# path with no embedded whitespace, ending in ".service" or ".conf": a
# credential's own path can start with "/" too (the sealer's drop-in carries
# one inside a hand-written comment, "...so this line and\n#
# /etc/aperire/creds/model-api-key-anthropic come and go together."), and a
# looser test would misread that comment line as a new section and
# misattribute the real directive that follows two lines later to it.
#
# If `systemctl cat` fails or systemctl is not on this host's PATH, the same
# walk runs over text built by hand from $UNIT and $DROPIN_DIR/*.conf: the
# unit body first, if present, then every drop-in in the lexicographic order
# systemd itself applies them (systemd.unit(5) again), each given the same
# "# /path" header so the walk cannot tell the difference.
#
# Two shapes this walk used to be blind to (F5, #541 follow-up, 2026-09-20):
#
#   LoadCredentialEncrypted=NAME, with no ":PATH" at all -- systemd's own
#   documented ID-only shorthand (systemd.exec(5)): the credential is looked
#   up by that name from systemd's own credential stores, not from a path
#   this unit or this program names anywhere. The old walk required both a
#   name AND a path before recording anything, so a bare id was dropped
#   silently during parsing and this program went on to report "no
#   LoadCredentialEncrypted= found", which is not true -- one was found, it
#   is just not one this program has a path to open or a place to move.
#   Recorded now with kind=bare, reported once, and never touched.
#
#   LoadCredential=NAME:PATH, unencrypted -- a different setting entirely
#   (no "Encrypted" in it), with its own independent list and its own
#   independent reset semantics (systemd.unit(5) treats every list-type
#   setting as its own list; an empty LoadCredentialEncrypted= does not
#   touch LoadCredential='s accumulated set, or the other way around). Not
#   a candidate for anything this program does -- it is never sealed by
#   this project and systemd-creds decrypt has nothing to say about it --
#   but its presence is worth a caller knowing about rather than a walk
#   that cannot see it at all.
#
# Both kinds share one stdout stream, each line led by "enc" or "plain": the
# caller reads this back through a command substitution, `resolved="$(...)"`,
# which runs this function in a subshell, so a second output through a
# "global" array set inside the function would be a subshell's own copy and
# vanish the moment the substitution finishes. Only stdout crosses that
# boundary, so both kinds travel on it.
read_load_credential_encrypted() {
  local text="" cat_rc=1
  if command -v systemctl >/dev/null 2>&1; then
    text="$(systemctl cat "$ADVISORD_UNIT" 2>/dev/null)"
    cat_rc=$?
  fi
  if [[ $cat_rc -ne 0 ]]; then
    text="$(read_unit_files_in_load_order)"
  fi
  [[ -n "$text" ]] || return 1

  local current_file="" line candidate value name path
  local names=() kinds=() paths=() files=() i found
  local plain_names=() plain_paths=() plain_files=()

  while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ "$line" == "# /"* ]]; then
      candidate="${line#\# }"
      if [[ "$candidate" != *[[:space:]]* ]] \
         && { [[ "$candidate" == *.service ]] || [[ "$candidate" == *.conf ]]; }; then
        current_file="$candidate"
      fi
      continue
    fi

    # LoadCredential= (unencrypted): its own independent list, tracked only
    # to be reported -- never opened, never moved, never mixed with the
    # encrypted list's own reset below.
    if [[ "$line" == "LoadCredential="* ]]; then
      value="${line#LoadCredential=}"
      value="${value#"${value%%[![:space:]]*}"}"
      value="${value%"${value##*[![:space:]]}"}"
      if [[ -z "$value" ]]; then
        plain_names=(); plain_paths=(); plain_files=()
        continue
      fi
      if [[ "$value" == *:* ]]; then
        name="${value%%:*}"
        path="${value#*:}"
      else
        name="$value"
        path=""
      fi
      [[ -n "$name" ]] || continue
      # The path travels with the name now (#708). A key kept as a root-only
      # file is declared here, not in the encrypted list, so this is the only
      # line that says where it is, and a walk that recorded only the name
      # left this program unable to judge the one form 22.04 hosts use. Same
      # reset-and-override rule as the encrypted list, in its own list: a
      # later line naming the same id replaces that id's path in place.
      found=-1
      for ((i = 0; i < ${#plain_names[@]}; i++)); do
        if [[ "${plain_names[i]}" == "$name" ]]; then found=$i; break; fi
      done
      if [[ $found -ge 0 ]]; then
        plain_paths[found]="$path"
        plain_files[found]="$current_file"
      else
        plain_names+=("$name")
        plain_paths+=("$path")
        plain_files+=("$current_file")
      fi
      continue
    fi

    [[ "$line" == "LoadCredentialEncrypted="* ]] || continue
    value="${line#LoadCredentialEncrypted=}"
    # Trimmed (systemd's own whitespace class, which covers a stray \r from
    # a CRLF-authored drop-in too): an empty-looking assignment that fails
    # this test by one trailing space would never reset the list it looks
    # like it resets, and this program would re-quarantine the same
    # credential forever instead of once.
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    if [[ -z "$value" ]]; then
      names=(); kinds=(); paths=(); files=()
      continue
    fi
    if [[ "$value" == *:* ]]; then
      name="${value%%:*}"
      path="${value#*:}"
      [[ -n "$name" && -n "$path" ]] || continue
    else
      # The bare ID-only shorthand: the id is both the name and, as far as
      # this program is concerned, a path it does not have. Recorded so the
      # walk's own reset-and-override semantics still see it -- a later
      # drop-in naming the same id WITH a path still replaces it in place,
      # and an empty assignment still clears it -- but never given a $path
      # to act on.
      name="$value"
      path=""
    fi
    found=-1
    for ((i = 0; i < ${#names[@]}; i++)); do
      if [[ "${names[i]}" == "$name" ]]; then
        found=$i
        break
      fi
    done
    if [[ $found -ge 0 ]]; then
      kinds[found]="$([[ -n "$path" ]] && echo path || echo bare)"
      paths[found]="$path"
      files[found]="$current_file"
    else
      names+=("$name")
      kinds+=("$([[ -n "$path" ]] && echo path || echo bare)")
      paths+=("$path")
      files+=("$current_file")
    fi
  done <<<"$text"

  for ((i = 0; i < ${#plain_names[@]}; i++)); do
    printf 'plain\t%s\t%s\t%s\t%s\n' "${plain_names[i]}" \
      "$([[ -n "${plain_paths[i]}" ]] && echo path || echo bare)" \
      "${plain_paths[i]}" "${plain_files[i]}"
  done
  [[ ${#names[@]} -gt 0 ]] || { [[ ${#plain_names[@]} -gt 0 ]] && return 0 || return 1; }
  for ((i = 0; i < ${#names[@]}; i++)); do
    printf 'enc\t%s\t%s\t%s\t%s\n' "${names[i]}" "${kinds[i]}" "${paths[i]}" "${files[i]}"
  done
}

# read_unit_files_in_load_order: the fallback when systemctl cat cannot
# answer, built to look exactly like it would have: the unit body first (if
# on this host), then every drop-in under $DROPIN_DIR in the lexicographic
# order systemd.unit(5) documents for them, each headed by the same
# "# /path" line read_load_credential_encrypted's walk looks for.
read_unit_files_in_load_order() {
  local f
  if [[ -f "$UNIT" ]]; then
    printf '# %s\n' "$UNIT"
    cat "$UNIT"
  fi
  if [[ -d "$DROPIN_DIR" ]]; then
    while IFS= read -r -d '' f; do
      printf '# %s\n' "$f"
      cat "$f"
    done < <(find "$DROPIN_DIR" -maxdepth 1 -type f -name '*.conf' -print0 | sort -z)
  fi
}

if ! resolved="$(read_load_credential_encrypted)"; then
  say clean "no model credential declaration found for $ADVISORD_UNIT (checked systemctl cat, $UNIT, and $DROPIN_DIR); failed for a reason that has nothing to do with a model credential"
  exit 0
fi

# The method library decides whether a blob sealed to this machine can be
# opened here at all, and this program will not guess when it is missing
# (#708). Same stance as a missing systemd-creds below: the unit stays failed
# and the journal names the command that repairs the host.
if ! declare -f aperire_key_method >/dev/null 2>&1; then
  say refused "no model-key method library beside this program (looked at ${METHOD_LIB:-$METHOD_LIB_INSTALLED}${METHOD_LIB_WHY:+; $METHOD_LIB_WHY}); cannot judge a credential, leaving $ADVISORD_UNIT failed. Run: curl -fsSL https://get.aperire.one | bash -s -- --run model-key-sealer"
  exit 0
fi
HOST_METHOD="$(aperire_key_method)"

# One line per effective credential: a host that somehow ends up declaring
# more than one distinct name gets every one of them judged on its own, not
# just the first one found. This project's own installers only ever wire
# one, so in every shape this program has actually been run against, the
# loop below runs exactly once.
#
# Both kinds are judged now (#708). A key kept as a root-only file is declared
# with LoadCredential=, and this program used to name that line and walk away,
# which left every 22.04 host with no recovery at all. The two lists are still
# kept apart everywhere it matters: what each one is judged ON differs, and the
# reset at the end clears only the list a credential actually came off.
overall_rc=0
quarantined_names=()
quarantined_enc=0
quarantined_plain=0
found_any=0
while IFS=$'\t' read -r cred_kind_tag cred_name cred_kind cred_path cred_file; do
  [[ "$cred_kind_tag" == enc || "$cred_kind_tag" == plain ]] || continue
  [[ -n "$cred_name" ]] || continue
  found_any=1
  directive=LoadCredentialEncrypted
  [[ "$cred_kind_tag" == plain ]] && directive=LoadCredential

  if [[ "$cred_kind" == bare ]]; then
    say clean "$cred_name is declared with no path ($directive=$cred_name, declared in $cred_file); systemd resolves that from its own credential stores, not from anything this program can open or move"
    continue
  fi

  if [[ -z "$cred_path" ]]; then
    say clean "a declared credential named $cred_name does not parse as name:path; leaving $ADVISORD_UNIT failed"
    continue
  fi

  # F5 (#541 follow-up, 2026-09-20): this program moves a file, as root, to
  # wherever the unit's own effective declaration names. Contained to the one
  # directory every credential this project seals actually lives in --
  # resolved with realpath -m so a symlink or a "../" cannot walk the check
  # itself out of $CREDS_DIR while still landing somewhere else at mv time --
  # so a hand-edited or malformed drop-in naming a path elsewhere on the host
  # is reported and left exactly as it is, never acted on.
  resolved_path="$(realpath -m -- "$cred_path" 2>/dev/null || printf '%s' "$cred_path")"
  case "$resolved_path" in
    "$CREDS_DIR"/*) ;;
    *)
      say refused "$cred_name is declared at $cred_path, which resolves outside $CREDS_DIR (declared in $cred_file); not touching it, whatever systemd-creds would say about it"
      continue
      ;;
  esac
  cred_path="$resolved_path"

  if [[ ! -f "$cred_path" ]]; then
    say clean "$cred_path is not on this host; leaving $ADVISORD_UNIT failed"
    continue
  fi

  # ---- the plain form ------------------------------------------------
  #
  # A key kept as a root-only file has no decryption to fail, so what is
  # judged is whether the file is one root alone can read and whether there is
  # anything in it. Both failures are ones an operator can actually arrive at:
  # an empty file is what a truncated restore leaves, and a widened mode is a
  # key that has already left root's hands. Neither is a file this program
  # will leave wired into a service.
  if [[ "$cred_kind_tag" == plain ]]; then
    plain_bad=""
    plain_st="$(stat -c '%u %a' "$cred_path" 2>/dev/null || true)"
    if [[ -z "$plain_st" ]]; then
      plain_bad="could not be read"
    elif [[ ! -s "$cred_path" ]]; then
      plain_bad="is empty"
    elif [[ "${plain_st%% *}" != "$(/usr/bin/id -u 2>/dev/null)" ]]; then
      # Compared with this program's own account, which is root: it refuses
      # to run as anything else. Asked as a number so a suite can answer it.
      plain_bad="is owned by uid ${plain_st%% *} and not by root"
    elif (( 8#${plain_st##* } & 8#077 )); then
      plain_bad="is mode ${plain_st##* }, which is readable by an account that is not root"
    fi
    if [[ -z "$plain_bad" ]]; then
      say clean "$cred_name at $cred_path is a root-only key file (declared in $cred_file); $ADVISORD_UNIT failed for some other reason"
      continue
    fi
    QUARANTINE="${cred_path}.unopenable-$(date +%s)-$$"
    if ! mv -f "$cred_path" "$QUARANTINE"; then
      say refused "$cred_path $plain_bad and could not be moved aside; leaving $ADVISORD_UNIT failed"
      continue
    fi
    quarantined_names+=("$cred_name")
    quarantined_plain=1
    say quarantined "$cred_name at $cred_path (declared in $cred_file) $plain_bad; moved to $QUARANTINE"
    continue
  fi

  # ---- the sealed form -----------------------------------------------
  #
  # A host with no systemd-creds can never open a blob sealed to a machine,
  # and that is not a transient (#708): it is a 24.04 backup restored onto a
  # 22.04 host, or an image whose systemd-creds was never installed. The
  # answer is the same as a blob sealed to a different host, because it is the
  # same fact from the file's point of view. This used to exit here and leave
  # the unit failed for ever with nothing that would ever judge it.
  if [[ "$HOST_METHOD" != sealed ]]; then
    QUARANTINE="${cred_path}.unopenable-$(date +%s)-$$"
    if ! mv -f "$cred_path" "$QUARANTINE"; then
      say refused "$cred_path is sealed to a machine and this host has no systemd-creds, and it could not be moved aside; leaving $ADVISORD_UNIT failed"
      continue
    fi
    quarantined_names+=("$cred_name")
    quarantined_enc=1
    say quarantined "$cred_name at $cred_path (declared in $cred_file) is sealed to a machine and this host has no systemd-creds to open it with; moved to $QUARANTINE. Seal a key again on this host and it will be kept as a root-only file instead"
    continue
  fi

  # Stderr captured, never discarded: it is the only thing that tells a
  # transient apart from a real no (P2-092). Redirection order matters here:
  # stderr is duplicated onto the command substitution's pipe FIRST, then
  # stdout (nothing meaningful; the plaintext target is /dev/null) is sent
  # away, so only the error text is captured.
  decrypt_err="$(systemd-creds decrypt --name="$cred_name" "$cred_path" /dev/null 2>&1 >/dev/null)"
  decrypt_rc=$?

  if [[ $decrypt_rc -eq 0 ]]; then
    say clean "$cred_name decrypts fine on this host (declared in $cred_file); $ADVISORD_UNIT failed for some other reason"
    continue
  fi

  # The allowlist: quarantine only when the stderr this host actually got
  # starts with one of the confirmed deterministic strings. Anything else,
  # whether it is one of the named transients above or something never seen
  # before, is left alone (root_cause_not_workaround: guessing which unknown
  # errors are safe to act on is exactly the workaround this fix removes).
  is_deterministic=0
  for pattern in "${DETERMINISTIC_CRED_ERRORS[@]}"; do
    if [[ "$decrypt_err" == "$pattern"* ]]; then
      is_deterministic=1
      break
    fi
  done

  if [[ $is_deterministic -ne 1 ]]; then
    first_line="${decrypt_err%%$'\n'*}"
    [[ -n "$first_line" ]] || first_line="(no stderr)"
    say refused "systemd-creds did not confirm $cred_name is unopenable on this host (exit $decrypt_rc: $first_line); leaving $ADVISORD_UNIT failed rather than guessing"
    overall_rc=1
    continue
  fi

  # The stderr matched the allowlist: systemd-creds actually looked at the
  # bytes and said no. Moved aside rather than removed: a unique suffix
  # (timestamp AND pid, P3-095) is what tells an operator this was found
  # broken, and when, without a second quarantine in the same second silently
  # overwriting the first one's evidence.
  QUARANTINE="${cred_path}.unopenable-$(date +%s)-$$"
  if ! mv -f "$cred_path" "$QUARANTINE"; then
    say refused "$cred_path would not decrypt ($decrypt_err) and could not be moved aside; leaving $ADVISORD_UNIT failed"
    continue
  fi
  quarantined_names+=("$cred_name")
  quarantined_enc=1
  say quarantined "$cred_name at $cred_path (declared in $cred_file) would not decrypt on this host ($decrypt_err); moved to $QUARANTINE"
done <<<"$resolved"

if (( ! found_any )); then
  say clean "no model credential declaration found for $ADVISORD_UNIT (checked systemctl cat, $UNIT, and $DROPIN_DIR); failed for a reason that has nothing to do with a model credential"
  exit 0
fi

if [[ ${#quarantined_names[@]} -eq 0 ]]; then
  exit "$overall_rc"
fi

# The declaration is reset here, not removed, and reset the same way
# regardless of where it was found (#541). Whether it lived in $DROPIN, in
# the unit's own body, or in both, a plain `rm -f "$DROPIN"` only ever
# cleared the drop-in half: a body-declared line survives that untouched, and
# the unit refuses to start on the very blob this program just moved aside
# (243/CREDENTIALS again, on the next restart three lines below).
# LoadCredentialEncrypted= is a list-type setting, and systemd.unit(5)'s
# "Overriding Vendor Configuration" section documents that an empty
# assignment in a drop-in resets a list directive's WHOLE accumulated value,
# body included, because drop-ins are parsed after the main unit file. So a
# fresh drop-in naming an empty list is written here, never the unit body
# itself: this program is not the thing that owns that file, and rewriting it
# by hand is exactly the risk a documented reset avoids.
#
# This leaves a real file on the host until an operator seals a new key,
# unlike the old rm -f, so it matters that a re-seal cannot read the reset
# line as "leave it alone". It cannot: both aperire-seal-model-key.sh
# (its own comment: "written whole every time") and install-advisord.sh's
# wire_model_credential write $DROPIN with an unconditional truncating
# write (`cat >` / `sudo tee`, never appended to and never gated on an
# "already declared" check that a bare `LoadCredentialEncrypted=` with no
# name could satisfy), so any credential sealed after this quarantine
# replaces this file whole rather than adding beside it or skipping it.
CRED_RESET_TMP="$(mktemp)"
{
  printf '# Written by aperire-advisord-credcheck (#541).\n'
  printf '#\n'
  printf '# %s could not be used on this host, so the credential list this\n' "${quarantined_names[*]}"
  printf '# unit declares is reset to empty here, whether the line that named it\n'
  printf '# lived in this drop-in, in the unit body, or in both: an empty\n'
  printf '# assignment in a drop-in resets that whole accumulated list\n'
  printf '# (systemd.unit(5), "Overriding Vendor Configuration"), and removing\n'
  printf '# only this file would leave a body-declared line in effect.\n'
  printf '#\n'
  printf '# Removed by:  sudo aperire-seal-model-key --reset, or the next successful seal\n'
  printf '[Service]\n'
  # The list a credential actually came off, and only that one (#708).
  # LoadCredential= and LoadCredentialEncrypted= are two independent
  # list-type settings, and an empty assignment to one says nothing about
  # the other. An empty LoadCredentialEncrypted= on systemd 249 is also an
  # assignment that systemd knows nothing about, so it is not written on a
  # host that never had one.
  if (( quarantined_enc ));   then printf 'LoadCredentialEncrypted=\n'; fi
  if (( quarantined_plain )); then printf 'LoadCredential=\n'; fi
} > "$CRED_RESET_TMP"
mkdir -p "$DROPIN_DIR"
if mv -f "$CRED_RESET_TMP" "$DROPIN"; then
  chown root:root "$DROPIN" 2>/dev/null || true
  chmod 0644 "$DROPIN"
else
  say refused "${quarantined_names[*]} was quarantined, but the reset drop-in at $DROPIN could not be written; the unit may still refuse to start on the missing file"
  rm -f "$CRED_RESET_TMP"
fi
systemctl daemon-reload 2>/dev/null || true
for cred_name in "${quarantined_names[@]}"; do
  write_credential_note credcheck "$cred_name"
done

systemctl reset-failed "$ADVISORD_UNIT" 2>/dev/null || true
if systemctl restart "$ADVISORD_UNIT" 2>/dev/null; then
  say restarted "$ADVISORD_UNIT is running again, with no model credential"
else
  say refused "$ADVISORD_UNIT did not come back after the credential was cleared; it needs a look"
fi

exit 0
