#!/usr/bin/env bash
# The one reader of a value in dashboard/config/authn.yaml for the shell
# scripts that have no YAML parser to hand (#1358).
#
# Sourced, never run:
#     . "${SCRIPTS_DIR}/authn-value.sh"
#
#   authn_file_value  <file> <key>   the value as one line, or empty
#   authn_public_url  <file>         the one public_url entry to speak of
#   authn_public_url_is_local <file> 0 when there is none, or it names only this machine
#
# WHY THIS IS ITS OWN FILE. install.sh, scripts/aperire-setup.sh and
# scripts/aperire-fleet-pair.sh each read public_url with a copy of the same
# few lines. The dashboard started accepting a public_url written as a YAML
# list (#1231), and the pair command's copy learned to read one (#1275) while
# the other two kept a `sed` that reads a list as unset. A host whose
# public_url was a list then got the unset path in the installer and in the
# guided setup: "still localhost", and no enrollment link. There is one copy
# now, and all three source it.
#
# This file is a map of scalars with the odd list, not a YAML document. A
# scalar stays one string, so a value that is not a list reads as it always did.
# A list, in either spelling, is read as the comma-joined line the dashboard
# and aperire-auth read it as:
#
#     public_url:                          public_url: [https://a, https://b]
#       - https://a
#       - https://b
#
# Quotes come off every entry. A flow list that runs onto a second line is left
# as it is, and a caller that wants a plain origin refuses it as not one.
#
# The first occurrence of the key wins, at column 0.

authn_file_value() {  # <file> <key> -> the value as one line, or empty
  [[ -f "${1:-}" ]] || return 0
  awk -v key="$2" '
    function strip(v) { gsub(/["\047]/, "", v); return v }
    function trim(v) { sub(/^[ \t]+/, "", v); sub(/[ \t\r]+$/, "", v); return v }
    !found && index($0, key ":") == 1 {
      found = 1
      v = trim(substr($0, length(key) + 2))
      if (v != "" && v !~ /^#/) {
        if (v ~ /^\[.*\]$/) { v = substr(v, 2, length(v) - 2) }
        print strip(v); exit
      }
      next
    }
    found {
      if ($0 ~ /^[ \t]*-([ \t]|$)/) {
        e = trim(strip(substr($0, index($0, "-") + 1)))
        if (e != "") out = out (out == "" ? "" : ",") e
        next
      }
      if ($0 ~ /^[ \t]*(#.*)?$/) next
      exit
    }
    END { if (found && out != "") print out }
  ' "$1" | head -1
}

# The rules for a host, in the words of dashboard/types/fleet-link-contract.ts
# (isLocalOnlyHost, and the host `new URL()` leaves as written). The pair
# command uses the same four, so scripts/test-fleet-pair.sh cuts this block out
# of this file and runs it beside the dashboard's own rules (#1275).
# >>> host rules >>>
# The host out of a plain origin, lower-cased, brackets off an IPv6 literal.
# Only ever called on a value fleet_origin_plain_ok has already accepted, so
# there is no path, no userinfo and no query left to strip. That is why it is
# asked first.
origin_host() {  # <origin> -> the host
  local rest="${1#*://}" host
  if [[ "$rest" == \[* ]]; then
    host="${rest%%]*}"; host="${host#\[}"
  else
    host="${rest%%:*}"
  fi
  printf '%s' "$host" | tr '[:upper:]' '[:lower:]'
}

# An address only this machine can open. The HOST, anchored, never a prefix
# glob: `https://localhost.evil.example` is not a loopback name and
# `https://127.0.0.1.evil.example` is not a loopback address, and a glob says
# both are. That is P3-059's mistake one layer down.
#
# This is isLocalOnlyHost() in dashboard/types/fleet-link-contract.ts, step
# for step and in its order, for a host as it is written. The dashboard asks
# it of a host `new URL()` has already rewritten, which host_is_carryable
# below makes up for.
#
# `.localhost` is in the set because it is what #339 was: RFC 6761 reserves
# that whole tree for loopback, so no name under it reaches another machine.
# Two spellings are undone first (#1233), because each names the same
# machine: a trailing dot (`localhost.` is the root of the DNS tree, and it
# resolves as `localhost` does) and an IPv4-mapped IPv6 address
# (`[::ffff:127.0.0.1]` is 127.0.0.1, and `new URL()` writes it back as
# `[::ffff:7f00:1]`).
host_is_local_only() {  # <host> -> 0 when only this machine can reach it
  local LC_ALL=C h="${1,,}" hi lo
  h="${h#\[}"; h="${h%\]}"
  while [[ "$h" == *. ]]; do h="${h%.}"; done
  if [[ "$h" =~ ^(::|(0{1,4}:){5})ffff:(([0-9]{1,3}(\.[0-9]{1,3}){3})|([0-9a-f]{1,4}):([0-9a-f]{1,4}))$ ]]; then
    if [[ -n "${BASH_REMATCH[4]}" ]]; then
      h="${BASH_REMATCH[4]}"
    else
      hi=$((16#${BASH_REMATCH[6]})); lo=$((16#${BASH_REMATCH[7]}))
      h="$((hi >> 8)).$((hi & 255)).$((lo >> 8)).$((lo & 255))"
    fi
  fi
  case "$h" in
    localhost|*.localhost|::1|::|0.0.0.0) return 0 ;;
  esac
  # All of 127/8, not 127.0.0.1 alone: a dashboard bound to 127.0.0.2 is
  # just as unreachable from the aggregator.
  [[ "$h" =~ ^127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]
}

# A host in the one spelling `new URL()` gives it back, so that the host this
# command tests is the host the dashboard tests. The dashboard sees
# `https://127.1`, `https://2130706433`, `https://0x7f000001` and
# `https://[0:0:0:0:0:0:0:1]` as 127.0.0.1 and ::1 and drops them. This tests
# the text as written and would call each of them a real address. A host that
# `new URL()` would rewrite is not a usable public_url for pairing anyway, so
# it is refused here and the entry is passed over, as firstUsableUrl() passes
# over a bad one. What is carried is a DNS name, a canonical dotted-quad IPv4
# (four decimal numbers, no leading zeros, no trailing dot), or an IPv6 literal
# written the compressed way `new URL()` writes it.
ipv6_is_canonical() {  # <lower-case host without brackets> -> 0 when new URL() would keep it as written
  local LC_ALL=C h="$1" left right out='' best=-1 blen=0 start=-1 run=0 i n
  local -a L=() R=() G=()
  [[ "$h" =~ ^[0-9a-f:]+$ && "$h" != *:::* ]] || return 1
  if [[ "$h" == *::* ]]; then
    left="${h%%::*}"; right="${h#*::}"
    [[ "$right" != *::* ]] || return 1
    IFS=: read -ra L <<<"$left"; IFS=: read -ra R <<<"$right"
    n=$((8 - ${#L[@]} - ${#R[@]}))
    (( n >= 1 )) || return 1
    G=( "${L[@]}" ); for ((i = 0; i < n; i++)); do G+=( 0 ); done; G+=( "${R[@]}" )
  else
    IFS=: read -ra G <<<"$h"
  fi
  (( ${#G[@]} == 8 )) || return 1
  for i in "${!G[@]}"; do
    [[ "${G[i]}" =~ ^[0-9a-f]{1,4}$ ]] || return 1
    G[i]="$(printf '%x' "$((16#${G[i]}))")"
  done
  for i in "${!G[@]}"; do   # the first longest run of two or more zero groups
    if [[ "${G[i]}" == 0 ]]; then
      (( run == 0 )) && start=$i
      run=$((run + 1))
      (( run > blen )) && { blen=$run; best=$start; }
    else
      run=0
    fi
  done
  if (( blen >= 2 )); then
    for ((i = 0; i < best; i++)); do out+="${G[i]}:"; done
    out+=":"
    for ((i = best + blen; i < 8; i++)); do out+=":${G[i]}"; done
    out="${out/:::/::}"
    [[ "$out" == ":" ]] && out="::"
  else
    out="$(IFS=:; printf '%s' "${G[*]}")"
  fi
  [[ "$out" == "$h" ]]
}
host_is_carryable() {  # <host from origin_host> -> 0 when new URL() leaves it as written
  local LC_ALL=C h="$1" last o
  if [[ "$h" == *:* ]]; then ipv6_is_canonical "$h"; return; fi
  last="${h%.}"; last="${last##*.}"
  # A last label of digits, or of 0x and hex digits, makes new URL() read the
  # whole host as an IPv4 address, whatever the other labels look like.
  if [[ "$last" =~ ^[0-9]+$ || "$last" =~ ^0x[0-9a-f]*$ ]]; then
    [[ "$h" =~ ^(0|[1-9][0-9]{0,2})(\.(0|[1-9][0-9]{0,2})){3}$ ]] || return 1
    for o in ${h//./ }; do (( o <= 255 )) || return 1; done
    return 0
  fi
  return 0
}
# <<< host rules <<<

# The host out of a public_url entry as written, or nothing when the entry is
# not one the dashboard would take (isPairUrl): http or https, no space, quote
# or control character, no user name. A path, query or fragment after the host
# is not part of it, and the entry may carry one.
authn_entry_host() {  # <entry> -> the host, lower-cased, or empty
  local LC_ALL=C e="$1" rest scheme
  [[ "$e" != *[[:space:]\"\'[:cntrl:]]* ]] || return 0
  scheme="${e%%://*}"; scheme="${scheme,,}"
  [[ "$scheme" == http || "$scheme" == https ]] || return 0
  [[ "$e" == *://* ]] || return 0
  rest="${e#*://}"; rest="${rest%%[/?#]*}"
  [[ -n "$rest" && "$rest" != *@* ]] || return 0
  origin_host "http://${rest}"
}

# public_url may name several origins, comma-separated or as a list. The one a
# script speaks of is the one the dashboard does, firstUsableUrl() in
# dashboard/lib/authn-fields.ts: the first entry another machine can open, and
# the first entry when none can, so a default install keeps showing the
# localhost it ships with. An entry is trimmed and loses its trailing slashes.
# "Can open" is the dashboard's question of the host: a name or an address that
# `new URL()` leaves as written, and not one only this machine reaches
# (localhost, a name under .localhost, 127/8, ::1, 0.0.0.0, and the spellings of
# those the dashboard undoes first).
authn_public_url() {  # <file> -> one entry, or empty
  local all rest entry first="" h
  all="$(authn_file_value "${1:-}" public_url)"
  rest="$all,"
  while [[ -n "$rest" ]]; do
    entry="${rest%%,*}"; rest="${rest#*,}"
    entry="${entry#"${entry%%[![:space:]]*}"}"; entry="${entry%"${entry##*[![:space:]]}"}"
    while [[ "$entry" == */ ]]; do entry="${entry%/}"; done
    [[ -n "$entry" ]] || continue
    [[ -n "$first" ]] || first="$entry"
    h="$(authn_entry_host "$entry")"
    if [[ -n "$h" ]] && host_is_carryable "$h" && ! host_is_local_only "$h"; then
      printf '%s\n' "$entry"
      return 0
    fi
  done
  [[ -z "$first" ]] || printf '%s\n' "$first"
}

# Whether this host still has the localhost default: no public_url, or the one
# a script speaks of names only this machine. An entry that is not a URL at all
# is read as the installer always read it, localhost or 127.0.0.1 anywhere in
# the text, so a value that was never the shipped default is not taken for it.
authn_public_url_is_local() {  # <file> -> 0 when unset or local-only
  local u h
  u="$(authn_public_url "${1:-}")"
  [[ -n "$u" ]] || return 0
  h="$(authn_entry_host "$u")"
  if [[ -n "$h" ]]; then host_is_local_only "$h"; return; fi
  [[ "$u" == *localhost* || "$u" == *127.0.0.1* ]]
}
