#!/usr/bin/env bash
# release-verify-lib.sh - was this release signed by the release key?
#
# Sourced, never run. Two callers:
#
#   scripts/aperire-update.sh   the root program behind the dashboard's Update
#                               button. It sources the root-owned copy at
#                               /usr/local/lib/aperire/release-verify-lib.sh
#                               and verifies against the root-owned signer set
#                               beside it, never against anything it fetched.
#   scripts/get-aperire.sh      the bootstrap. It arrives alone, so it carries
#                               an inline copy of the functions marked
#                               "shared" below. scripts/test-release-verify.sh
#                               fails when the two copies differ by a byte.
#
# Root copies out of the tree (ADR 0024) are checked against the release
# digests record (scripts/release-digests-lib.sh). For a signed release that
# record is written from the signed per-file list, so it is this signature
# that vouches for every root copy.
#
# ---- what is signed ------------------------------------------------
#
# One file per release: release.json. It names the archive's sha256 and the
# sha256 of every other file the endpoint serves that anything executes (the
# three bootstraps and the uninstaller), plus the sha256 of release.files,
# the per-file list of the tree inside the archive. So one signature covers
# everything, through hashes, and one signing command on the maintainer's
# Mac signs a release.
#
# The signature is OpenSSH's own format (`ssh-keygen -Y sign`, PROTOCOL.sshsig
# in the OpenSSH source), checked with `ssh-keygen -Y verify`. That is in
# openssh-client on every supported Ubuntu (8.9 on 22.04, 9.6 on 24.04), so a
# host needs no extra package to check a release.
#
# ---- the signer set ------------------------------------------------
#
# An OpenSSH allowed_signers file, every line the same shape:
#
#   aperire-release-key namespaces="aperire-release" ssh-ed25519 <base64> [comment]
#
# One key, normally. Two only while the key is being rotated, and then only
# as the two phases below allow. A plain ssh-ed25519 key is the only type:
# the private half is a passphrase-encrypted file the maintainer keeps, and
# nothing here depends on where it lives.
#
# The shape is checked here before ssh-keygen ever reads the file, and the
# check is strict on purpose. The principal field in that format is a
# PATTERN list, so a line reading `*` would accept any principal; an option
# such as cert-authority would widen what counts as the key. Neither can get
# through this check. The principal and the namespace are fixed in this file
# and never read from anywhere else.
#
# ---- rotation, in two signed phases --------------------------------
#
#   phase 1  the old key signs a release whose set is {old, new}
#   phase 2  the new key signs a release whose set is {new}
#
# A host only ever believes a release signed by a key it already trusts, so
# a host that skipped phase 1 still trusts {old} alone and refuses phase 2.
# release_signers_transition_ok holds every change of set to exactly these
# two steps: a single release can never swap {old} for {other}.

RELEASE_SIGNER_PRINCIPAL='aperire-release-key'
RELEASE_SIG_NAMESPACE='aperire-release'

# ---- shared: the inline copy in get-aperire.sh must match these ----

# Is this a signer set this code will hand to ssh-keygen? Prints the number
# of keys on stdout. Refuses, with the line number, on anything that is not
# exactly the one shape above, and on a file that names no key at all.
release_signers_check() { # $1 = allowed_signers file
  local file="$1" line trimmed principal opts type key rest n=0 ln=0 seen=""
  if [[ ! -f "$file" || ! -r "$file" ]]; then
    printf 'there is no readable release signer set at %s\n' "$file" >&2
    return 1
  fi
  while IFS= read -r line || [[ -n "$line" ]]; do
    ln=$((ln + 1))
    trimmed="${line#"${line%%[![:space:]]*}"}"
    [[ -z "$trimmed" || "$trimmed" == \#* ]] && continue
    if [[ "$trimmed" != "$line" ]]; then
      printf 'line %s of %s starts with whitespace, and a signer line may not\n' "$ln" "$file" >&2
      return 1
    fi
    principal="" opts="" type="" key="" rest=""
    read -r principal opts type key rest <<<"$line"
    if [[ "$principal" != "$RELEASE_SIGNER_PRINCIPAL" ]]; then
      printf 'line %s of %s names the signer %s, and the only one accepted is %s\n' \
        "$ln" "$file" "${principal:-nothing}" "$RELEASE_SIGNER_PRINCIPAL" >&2
      return 1
    fi
    if [[ "$opts" != "namespaces=\"$RELEASE_SIG_NAMESPACE\"" ]]; then
      printf 'line %s of %s carries the options %s, and the only one accepted is namespaces="%s"\n' \
        "$ln" "$file" "${opts:-none}" "$RELEASE_SIG_NAMESPACE" >&2
      return 1
    fi
    if [[ "$type" != ssh-ed25519 ]]; then
      printf 'line %s of %s names the key type %s, and a release is signed with ssh-ed25519 only\n' \
        "$ln" "$file" "${type:-nothing}" >&2
      return 1
    fi
    if [[ ! "$key" =~ ^[A-Za-z0-9+/]{40,}={0,2}$ ]]; then
      printf 'line %s of %s does not carry a key after its type\n' "$ln" "$file" >&2
      return 1
    fi
    if [[ -n "$rest" && ! "$rest" =~ ^[A-Za-z0-9._@:+\ -]+$ ]]; then
      printf 'line %s of %s ends in a comment with characters a signer line does not need\n' "$ln" "$file" >&2
      return 1
    fi
    case " $seen " in
      *" $key "*)
        printf 'line %s of %s names a key an earlier line already names\n' "$ln" "$file" >&2
        return 1 ;;
    esac
    seen+=" $key"
    n=$((n + 1))
  done < "$file"
  if [[ $n -eq 0 ]]; then
    printf 'the release signer set at %s names no key, so no release can be checked against it\n' "$file" >&2
    return 1
  fi
  if [[ $n -gt 2 ]]; then
    printf 'the release signer set at %s names %s keys. It holds one, and two only while the key is rotated\n' "$file" "$n" >&2
    return 1
  fi
  printf '%s\n' "$n"
  return 0
}

# Did a key in the signer set sign this file? Exit status only: 0 when
# ssh-keygen says so, 1 otherwise with the reason on stderr. The message is
# fed on stdin from the file itself, never from a pipe, and nothing it prints
# on success is read.
#
# Call it as a statement (`if ! release_verify ...`), never inside $( ): a
# refusal in a command substitution under set -e is swallowed.
release_verify() { # $1 = the signed file, $2 = its .sig, $3 = allowed_signers
  local msg="$1" sig="$2" signers="$3" out
  release_signers_check "$signers" >/dev/null || return 1
  if ! command -v ssh-keygen >/dev/null 2>&1; then
    printf 'this host has no ssh-keygen, so a release signature cannot be checked. It is in the openssh-client package: sudo apt-get install openssh-client\n' >&2
    return 1
  fi
  if [[ ! -f "$msg" ]]; then
    printf 'there is no %s to check\n' "$msg" >&2
    return 1
  fi
  if [[ ! -s "$sig" ]]; then
    printf 'there is no signature for %s, and an unsigned release is not installed\n' "$(basename "$msg")" >&2
    return 1
  fi
  if out="$(ssh-keygen -Y verify -f "$signers" -I "$RELEASE_SIGNER_PRINCIPAL" \
              -n "$RELEASE_SIG_NAMESPACE" -s "$sig" < "$msg" 2>&1)"; then
    return 0
  fi
  # Old enough not to know -Y at all is a different sentence from a bad
  # signature, and an operator needs to know which one they are looking at.
  if grep -qiE 'illegal option|unknown option|invalid option' <<<"$out"; then
    printf 'this host'"'"'s ssh-keygen is too old to check a release signature (it needs OpenSSH 8.2 or newer)\n' >&2
    return 1
  fi
  printf 'the signature on %s does not verify against the release key: %s\n' \
    "$(basename "$msg")" "$(tr '\n' ' ' <<<"$out" | sed 's/[[:space:]]*$//')" >&2
  return 1
}

# One flat string field out of a release.json, in the exact shape the
# publisher writes it ("  \"key\": \"value\"" on its own line). Prints it
# only when exactly one line carries that key, so a file with a second
# "sha256" somewhere cannot be read two ways.
release_json_field() { # $1 = release.json, $2 = key
  local hits
  hits="$(grep -cE "^  \"$2\": \"[^\"]*\",?\$" "$1" 2>/dev/null || true)"
  [[ "$hits" == "1" ]] || return 1
  sed -n "s/^  \"$2\": \"\([^\"]*\)\",\{0,1\}\$/\1/p" "$1"
  return 0
}

# The per-file manifest, held against a tree. Exactly the files it names,
# each with the sum it names, and no file it does not name. Used on a fresh
# unpack, before anything in the tree has run.
release_tree_check() { # $1 = release.files, $2 = the tree root
  local files="$1" root="$2" named present bad
  [[ -s "$files" && -d "$root" ]] || { printf 'no manifest or no tree to check\n' >&2; return 1; }
  # Regular files and directories only, checked first: sha256sum follows a
  # symlink, so a link named like a manifest file would pass on the bytes of
  # whatever it points at, and root would later copy through it.
  bad="$(cd "$root" && find . ! -type f ! -type d -print -quit)"
  if [[ -n "$bad" ]]; then
    printf 'the tree holds %s, which is not a regular file or a directory, and a release holds nothing else\n' "${bad#./}" >&2
    return 1
  fi
  if ! bad="$(cd "$root" && sha256sum --check --strict --quiet "$files" 2>&1)"; then
    printf 'the tree does not match the signed manifest: %s\n' "$(head -3 <<<"$bad" | tr '\n' ' ')" >&2
    return 1
  fi
  named="$(grep -c . "$files")"
  present="$(cd "$root" && find . -type f | wc -l)"
  if [[ "$named" != "$present" ]]; then
    printf 'the tree holds %s files and the signed manifest names %s\n' "$present" "$named" >&2
    return 1
  fi
  return 0
}

# Every key a signer file names, as "<type> <base64>", one per line, read the
# way ssh-keygen reads an allowed_signers line: principals first, then an
# options field only when the next field is not already a key type. So a
# three-field line (no options) is counted here exactly as ssh-keygen would
# count it, and nothing that ssh-keygen accepts as a key is missed by the
# digest or the rotation rule.
release_signers_keys() { # $1 = allowed_signers file
  awk '/^[[:space:]]*(#|$)/ { next }
       { if ($2 ~ /^(ssh-|ecdsa-|sk-)/) print $2 " " $3; else if (NF >= 4) print $3 " " $4; else print "unparsed " NR }' "$1"
}

# The signer set, reduced to what decides trust: one "<key type> <base64>"
# line per key, sorted bytewise, hashed. Comments, order and the principal
# column (which release_signers_check pins) do not change it. release.json
# carries this as signers_sha256; the Mac computes the same value from its
# own .pub files (fields 1 and 2 there, 3 and 4 here) and will not sign a
# release whose value differs from its own.
release_signers_digest() { # $1 = allowed_signers file
  release_signers_keys "$1" | LC_ALL=C sort | sha256sum | cut -d' ' -f1
}

# The keys of a signer set as OpenSSH prints them (`ssh-keygen -l`): one
# "SHA256:<base64>" per key, in file order. This is the value Settings &
# Updates shows and the guide prints, so an operator compares like with like.
release_key_fingerprints() { # $1 = allowed_signers file
  release_signers_keys "$1" | while IFS= read -r k; do
    printf '%s\n' "$k" | ssh-keygen -lf - 2>/dev/null | awk '{ print $2 }'
  done
}

# May a host that trusts the set in $1 move to the set in $2? Only to the
# same set, or by one of the two rotation phases: a single key gains exactly
# one more (phase 1), or a pair drops to one of its own two (phase 2). Says
# why not on stderr. Both files have passed release_signers_check.
release_signers_transition_ok() { # $1 = the set this host trusts, $2 = the set on offer
  local old new no nn
  old="$(release_signers_keys "$1" | LC_ALL=C sort)"
  new="$(release_signers_keys "$2" | LC_ALL=C sort)"
  [[ "$old" == "$new" ]] && return 0
  no="$(grep -c . <<<"$old")"; nn="$(grep -c . <<<"$new")"
  if [[ "$no" == 1 && "$nn" == 2 ]] && grep -qxF -- "$old" <<<"$new"; then
    return 0
  fi
  if [[ "$no" == 2 && "$nn" == 1 ]] && grep -qxF -- "$new" <<<"$old"; then
    return 0
  fi
  printf 'the release key set on offer is not this host'"'"'s set or one rotation step from it (one key gains a second, or a pair drops to one of its two)\n' >&2
  return 1
}

# ---- end of shared ----
