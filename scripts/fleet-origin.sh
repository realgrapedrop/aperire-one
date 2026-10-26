#!/usr/bin/env bash
# The one rule for an aggregator origin a node may carry its tokens to.
#
# Sourced, never run:
#     . "${SCRIPTS_DIR}/fleet-origin.sh"
#
# Two predicates, because the two refusals say different things and each
# sentence was earned separately:
#
#   fleet_origin_scheme_ok <url>   https://, or http:// to loopback only
#   fleet_origin_plain_ok  <url>   scheme, host, optional port, nothing else
#
# Both return 0 for yes and non-zero for no, and neither prints anything. The
# caller owns the sentence, because install.sh refuses a flag and
# aperire-fleet-pair.sh refuses a dial.
#
# WHY THIS IS ITS OWN FILE. The scheme rule used to be a prefix glob inside
# aperire-fleet-pair.sh. `http://127.0.0.1*` matched
# `http://127.0.0.1.evil.example` and `http://localhost*` matched
# `http://localhost.evil.example`, so a node carried its read token and its
# Advisor token in plaintext to a stranger (P3-059). It is anchored now. A
# second hand-written copy in install.sh would be a second chance to get that
# wrong, so there is one copy and both callers source it.
#
# scripts/get-aperire.sh carries the block below inline, because it runs from
# a pipe before any checkout exists and has nothing to source. That copy is
# deliberate and scripts/test-fleet-origin.sh compares the two byte for byte.

# >>> aperire fleet origin >>>
# BOTH OF THESE ALWAYS RUN, scheme first and shape second, and the safety
# property is the conjunction rather than either half (P3-076).
# `fleet_origin_scheme_ok` on its own accepts
# `http://127.0.0.1:7800@evil.example` and `http://127.0.0.1:7800.evil.example`,
# because everything after the port colon is a glob in a case pattern. What
# refuses those is `fleet_origin_plain_ok`. A caller that runs only the first
# one has a plaintext dial to a stranger, which is P3-059 again by another
# route. There is no single-predicate use of this file and there must not be.
#
# The scheme. https:// anywhere, http:// only to a loopback name, ANCHORED,
# with an explicit optional port and never a prefix glob (P3-059). The node is
# the only party that holds the URL, so the node is the only party that can
# know whether the hop carrying its tokens is encrypted.
fleet_origin_scheme_ok() {
  case "${1:-}" in
    https://*) return 0 ;;
    http://127.0.0.1|http://127.0.0.1:*) return 0 ;;
    http://localhost|http://localhost:*) return 0 ;;
    http://\[::1\]|http://\[::1\]:*) return 0 ;;
  esac
  return 1
}

# The shape: scheme, host, optional port, and nothing else. The origin is
# interpolated into the JSON job the dial helper reads, and a value carrying a
# quote would forge structure there. Same refusal scripts/fleet-link-place.sh
# makes, for the same reason.
#
# THE WHOLE VALUE, and this is the second thing lifting the rule here fixed.
# It used to be `printf | grep -Eq`, and grep matches a LINE: `https://host`
# followed by a newline and anything at all passed on its first line, which is
# the opposite of what the sentence above claims. A bash regex matches the
# string, newlines included, so a value with one in it has no line to hide on.
#
# The host is either a bracketed IPv6 literal or a name, as alternatives. It
# used to be one character class with `:` in it followed by an OPTIONAL
# bracket group, so `[` never had a class to start in and `http://[::1]` was
# refused as "not a plain origin" by a program whose message directly above it
# offers `[::1]` as a supported loopback form.
FLEET_ORIGIN_RE='^https?://(\[[0-9a-fA-F:]+\]|[A-Za-z0-9._~-]+)(:[0-9]{1,5})?$'
fleet_origin_plain_ok() {
  [[ "${1:-}" =~ $FLEET_ORIGIN_RE ]]
}
# <<< aperire fleet origin <<<
