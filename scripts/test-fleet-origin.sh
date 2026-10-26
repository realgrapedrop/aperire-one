#!/usr/bin/env bash
# scripts/fleet-origin.sh, and the copies of it that have to agree.
#
# This is P3-059 as a test. The scheme rule used to be a prefix glob inside
# aperire-fleet-pair.sh: `http://127.0.0.1*` matched
# `http://127.0.0.1.evil.example` and `http://localhost*` matched
# `http://localhost.evil.example`, both of which also pass the shape pattern
# because it allows dots. A node then carried its read token and its Advisor
# token in PLAINTEXT to a stranger.
#
# Three things are checked:
#
#   1. the rule itself, both verdicts, over the corpus that mistake produced
#   2. scripts/get-aperire.sh's inline copy is byte-identical to the shared
#      file. It runs from a pipe before any checkout exists, so it cannot
#      source anything, and one deliberate copy is a decision while two that
#      have drifted apart is the bug that decision invites
#   3. install.sh's pairing-code shape check agrees with
#      aperire-fleet-pair.sh's normalise_code, which owns the real
#      normalisation. install.sh refuses a mistyped code an hour before the
#      pair command would see it, and a refusal the two disagree about is
#      worse than no refusal at all
#
#   bash scripts/test-fleet-origin.sh
#
# Reads only. Touches no host, needs no root, installs nothing.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SHARED="$REPO/scripts/fleet-origin.sh"

PASS=0 FAIL=0
ok()  { printf '  ok    %s\n' "$1"; PASS=$((PASS + 1)); }
bad() { printf '  FAIL  %s\n     %s\n' "$1" "$2"; FAIL=$((FAIL + 1)); }

[[ -f "$SHARED" ]] || { echo "no fleet-origin.sh at $SHARED"; exit 1; }
# shellcheck source=scripts/fleet-origin.sh
. "$SHARED"

echo
echo "fleet-origin.sh, the one rule for an aggregator origin"
echo

# ── 1. the rule, both ways ──────────────────────────────────────────
#
# Every accepted value has a refused twin that differs by as little as
# possible, because a rule that accepts everything also accepts every value in
# the first list.
echo "── what a node may carry its tokens to ────────────────────────────"
for u in \
    'https://aggregator.example' \
    'https://aggregator.example:443' \
    'https://agg-1.example.co.uk' \
    'http://127.0.0.1' \
    'http://127.0.0.1:7800' \
    'http://localhost' \
    'http://localhost:7800' \
    'http://[::1]' \
    'http://[::1]:7800'; do
  if fleet_origin_scheme_ok "$u" && fleet_origin_plain_ok "$u"; then
    ok "accepted: $u"
  else
    bad "accepted: $u" "the rule refused an origin it must accept"
  fi
done

echo
echo "── and what it must not ───────────────────────────────────────────"
# The first two are P3-059 itself. Everything after is a value that would
# forge structure in the JSON job the dial helper reads, or send a token in
# the clear.
for u in \
    'http://127.0.0.1.evil.example' \
    'http://localhost.evil.example' \
    'http://127.0.0.1.evil.example:7800' \
    'http://aggregator.example' \
    'http://aggregator.example:7800' \
    'https://host/fleet/v1/link' \
    'https://host/' \
    'https://host"x' \
    'https://host x' \
    'https://host
x' \
    'wss://host' \
    'ftp://host' \
    'aggregator.example' \
    ''; do
  if fleet_origin_scheme_ok "$u" && fleet_origin_plain_ok "$u"; then
    bad "refused: ${u@Q}" "the rule accepted an origin it must refuse"
  else
    ok "refused: ${u@Q}"
  fi
done

# ── 2. the one deliberate copy ──────────────────────────────────────
echo
echo "── the copy scripts/get-aperire.sh carries inline ─────────────────"
block_of() { sed -n '/^# >>> aperire fleet origin >>>$/,/^# <<< aperire fleet origin <<<$/p' "$1"; }
INLINE="$(block_of "$REPO/scripts/get-aperire.sh")"
CANON="$(block_of "$SHARED")"
if [[ -n "$CANON" && -n "$INLINE" && "$INLINE" == "$CANON" ]]; then
  ok "the inline copy is byte-identical to scripts/fleet-origin.sh"
else
  bad "the inline copy is byte-identical to scripts/fleet-origin.sh" \
      "$(diff <(printf '%s\n' "$CANON") <(printf '%s\n' "$INLINE") | head -12)"
fi

# And the two programs that source it really do, rather than carrying a third
# copy that nothing compares.
for f in install.sh scripts/aperire-fleet-pair.sh; do
  if grep -q 'fleet-origin\.sh"$' "$REPO/$f"; then
    ok "$f sources the shared rule"
  else
    bad "$f sources the shared rule" 'it carries no source line for fleet-origin.sh'
  fi
done

# ── 2b. the label rule, in the same two copies ──────────────────────
#
# P3-074. The label check was `printf | grep -Eq`, which exits 0 when ANY line
# matches, so `node-two` with a second line after it was accepted, in the same
# change whose ADR note records removing exactly that defect from the origin
# rule one function away. The consequence is two lines down: the label goes
# into the plan note and into `fleet_deferred_line`, which builds the command
# the closing text tells the operator to copy, so a second line in the label is
# a second line in that command block.
#
# This file is already "the rule and the copies that must not drift", so the
# label rule lives here too. Both copies are lifted out of their files rather
# than restated, for the reason the code readers below are.
echo
echo "── the label rule, in install.sh and in the one-liner ─────────────"
label_line_of() { grep -n 'FLEET_LABEL.*\[a-z0-9-\]{1,32}' "$1" | head -1; }
for f in install.sh scripts/get-aperire.sh; do
  line="$(label_line_of "$REPO/$f")"
  if [[ -n "$line" && "$line" != *'grep -Eq'* && "$line" == *'=~'* ]]; then
    ok "$f matches the whole label, not its first line"
  else
    bad "$f matches the whole label" "the rule reads: ${line:-<not found>}"
  fi
done

# And driven, rather than only read. The two-line label the review reproduced,
# through the predicate each file now uses.
TWO_LINE=$'node-two\nsudo rm -rf /'
if printf '%s' "$TWO_LINE" | grep -Eq '^[a-z0-9-]{1,32}$'; then
  ok "  the control holds: grep -Eq DOES accept a two-line label, which is the defect"
else
  bad "grep -Eq accepts a two-line label" "the control no longer reproduces; this row proves nothing"
fi
if [[ "$TWO_LINE" =~ ^[a-z0-9-]{1,32}$ ]]; then
  bad "the anchored rule refuses a two-line label" "it accepted $(printf '%q' "$TWO_LINE")"
else
  ok "  and the anchored rule both files now use refuses it"
fi
ONE_LINE='node-two'
if [[ "$ONE_LINE" =~ ^[a-z0-9-]{1,32}$ ]]; then
  ok "  while an ordinary label still goes through"
else
  bad "an ordinary label is accepted" "$ONE_LINE was refused"
fi

# ── 2c. the rule as one grammar, in every language that holds it ────
#
# P3-075. The Settings page builds two command lines an operator pastes into a
# ROOT shell on another machine, and its origin check was /^https?:\/\/\S+$/,
# which accepts a quote, a `;` and a `$(...)`. It holds the shell rule's own
# string now. Compared here because this file is where the copies are counted;
# the TypeScript side is driven by dashboard/test/unit/settings-pair-command.test.ts.
echo
echo "── and the copy dashboard/settings-api.ts holds ───────────────────"
TS_RE="$(sed -nE 's/^const FLEET_ORIGIN_RE = \/(.*)\/;$/\1/p' "$REPO/dashboard/settings-api.ts" | head -1)"
SH_RE="$(sed -nE "s/^FLEET_ORIGIN_RE='(.*)'$/\1/p" "$SHARED" | head -1)"
# One difference is real and is not drift: a JavaScript literal escapes the
# slashes in the scheme, and a shell single-quoted string does not.
TS_NORM="${TS_RE//\\\//\/}"
if [[ -n "$TS_RE" && -n "$SH_RE" && "$TS_NORM" == "$SH_RE" ]]; then
  ok "the TypeScript copy is the shell rule's own pattern, slash escaping aside"
else
  bad "the TypeScript copy matches the shared rule" "shell: ${SH_RE:-<not found>}; ts: ${TS_NORM:-<not found>}"
fi

# ── 3. the pairing-code shape, in two programs ──────────────────────
echo
echo "── install.sh and the pair command read a code the same way ───────"
# Both functions lifted out of their files and run side by side. Lifted rather
# than reimplemented: a third copy in this test would prove the test agrees
# with itself.
fn_of() { awk -v n="$2" '$0 ~ "^" n "\\(\\) \\{" {p=1} p {print} p && /^\}$/ {exit}' "$1"; }
one_liner_of() { grep -m1 "^$2() {" "$1"; }

INSTALL_FNS="$(one_liner_of "$REPO/install.sh" fleet_fold_code)
$(fn_of "$REPO/install.sh" fleet_code_shape_ok)"
PAIR_FNS="$(one_liner_of "$REPO/scripts/aperire-fleet-pair.sh" fold_code)
$(fn_of "$REPO/scripts/aperire-fleet-pair.sh" normalise_code)"

if [[ "$INSTALL_FNS" == *fleet_code_shape_ok* && "$PAIR_FNS" == *normalise_code* ]]; then
  ok "both readers were found in their files"
else
  bad "both readers were found in their files" \
      "install.sh: $(printf '%s' "$INSTALL_FNS" | head -1); pair: $(printf '%s' "$PAIR_FNS" | head -1)"
fi

verdicts_agree() { # $1 = a candidate code
  local a b
  a=$(bash -c "$INSTALL_FNS
fleet_code_shape_ok \"\$1\"" _ "$1"; echo $?)
  b=$(bash -c "$PAIR_FNS
normalise_code \"\$1\" >/dev/null" _ "$1"; echo $?)
  [[ "$a" == "$b" ]]
}

for c in \
    'APR-00000-00000-00000-00000' \
    'apr-00000 00000-00000-00000' \
    '00000000000000000000' \
    'APR-0OIL0-00000-00000-0000' \
    'not-a-code' \
    'APR-00000-00000-00000-0000' \
    'APR-00000-00000-00000-000000' \
    ''; do
  if verdicts_agree "$c"; then
    ok "same verdict on ${c@Q}"
  else
    bad "same verdict on ${c@Q}" "install.sh and aperire-fleet-pair.sh disagree about this code"
  fi
done

echo
printf '%s passed, %s failed\n' "$PASS" "$FAIL"
[[ $FAIL -eq 0 ]]
