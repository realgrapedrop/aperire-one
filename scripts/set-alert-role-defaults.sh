#!/usr/bin/env bash
# Set the alert thresholds whose right value can depend on what this box is.
#
# One threshold uses this today: the swap_used_pct warn rule. It shipped at
# 5% once, strict on the theory that any swap on a box running the node risks
# a missed validation. It fired for days on a healthy co-located validator
# host, 92 GB of RAM at 30% used, 30% of swap sitting in old pages nobody was
# paging, vmstat 1 reading si=0 so=0 throughout: a resident amount that had
# not moved in a long time, not a problem. The shipped rule is 40% now, on
# every role, with the 50% critical unchanged. Nothing in this script needs
# to relax a role's default anymore, because there is no stricter number
# shipping to relax it from.
#
# What this script is still for: an operator who wants a DIFFERENT number
# than the shipped one, on this box specifically. --swap-warn=N sets it and
# is the one input this script takes from you rather than infers.
#
# The role signal is the one the operator already picked at install time, and
# the guided setup states it in the same words this script uses:
#
#   co-located   "the node, the dashboard and the relay, all on this box"
#   dashboard    "the dashboard only; your node lives on another box"
#
# WHERE IT WRITES (ADR 0020). Never dashboard/config/rules.yaml. That file is
# the set the product ships and every update replaces it, so a threshold
# written there would be reverted by the next update, months later and
# silently. The value goes in dashboard/config/rules.local.yaml, the file
# nothing else writes, as an override of the shipped rule.
#
# Defaults are for a fresh install. The question "is this host's swap warn
# still the shipped one, or did somebody choose it" is answered by whether
# rules.local.yaml already has an entry for that rule. While it has none this
# script may add one; once it has one, the number is somebody's and this
# script writes nothing, on every later upgrade and every re-run.
#
# Both roles now default to the shipped value, so a fresh install on either
# one writes no override at all: there is nothing to relax or tighten from
# the shipped rule until you ask for a specific number with --swap-warn.
#
#   bash scripts/set-alert-role-defaults.sh --role=co-located
#   bash scripts/set-alert-role-defaults.sh --role=dashboard
#   bash scripts/set-alert-role-defaults.sh --role=co-located --swap-warn=15
#
# Idempotent. Needs no root: it writes a file in the repository, owned by the
# account that checked it out.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

ROLE=""
RULES="${REPO_DIR}/dashboard/config/rules.yaml"
LOCAL=""
SWAP_WARN=""

# The two values, named once. Anything reading this script should be able to
# see the whole policy without following the code. Both roles read the
# shipped default today; kept as two names, not one, because a role's
# default is still the right place to change if one role's number should
# ever move again on its own.
SWAP_WARN_WITH_NODE=40
SWAP_WARN_NO_NODE=40

for arg in "$@"; do
  case "$arg" in
    --role=*)      ROLE="${arg#*=}" ;;
    --rules=*)     RULES="${arg#*=}" ;;
    --local=*)     LOCAL="${arg#*=}" ;;
    --swap-warn=*) SWAP_WARN="${arg#*=}" ;;
    -h|--help)
      awk '/^[^#]/{exit} NR>1{sub(/^# ?/,""); print}' "$0"
      exit 0
      ;;
    *)
      echo "error: unknown argument: $arg" >&2
      exit 2
      ;;
  esac
done

# The local file sits beside the shipped one, so --rules moves both and a test
# can run this anywhere. Named explicitly with --local when they are apart.
[[ -n "$LOCAL" ]] || LOCAL="$(dirname "$RULES")/rules.local.yaml"

case "$ROLE" in
  co-located|dashboard) ;;
  validator|cli-only)
    # Neither installs a dashboard, so neither has a rules file to tune. Not
    # an error: install.sh should be able to call this for any role.
    echo "role '${ROLE}' runs no dashboard, so it has no alert rules to set."
    exit 0
    ;;
  "")
    echo "error: --role=<co-located|dashboard> is required" >&2
    exit 2
    ;;
  *)
    echo "error: unknown role '${ROLE}'" >&2
    exit 2
    ;;
esac

if [[ -n "$SWAP_WARN" && ! "$SWAP_WARN" =~ ^[0-9]+$ ]]; then
  echo "error: --swap-warn must be a whole number of percent" >&2
  exit 2
fi

if [[ ! -f "$RULES" ]]; then
  echo "error: no rules file at ${RULES}" >&2
  exit 1
fi

# The swap_used_pct warn threshold as a file holds it. Anchored on the rule's
# own two lines rather than on a line number or a comment: the entry this
# writes and the entry the product ships have the same shape, and the critical
# at 50% sits a few lines from the warn in the shipped file, so an edit that
# found the wrong `threshold:` would hit that instead and nothing would notice.
swap_warn_of() {
  [[ -f "$1" ]] || return 0
  awk '
    /^[[:space:]]*#/ { next }
    /^[[:space:]]*-[[:space:]]*metric:[[:space:]]*swap_used_pct[[:space:]]*$/ { inblk = 1; sev = 0; next }
    /^[[:space:]]*-[[:space:]]*metric:/ { inblk = 0; sev = 0 }
    inblk && /^[[:space:]]*severity:[[:space:]]*warn[[:space:]]*$/ { sev = 1; next }
    inblk && sev && /^[[:space:]]*threshold:/ {
      if (match($0, /value:[[:space:]]*[0-9]+(\.[0-9]+)?/)) {
        v = substr($0, RSTART, RLENGTH)
        sub(/value:[[:space:]]*/, "", v)
        print v
      }
      exit
    }
  ' "$1"
}

SHIPPED_WARN="$(swap_warn_of "$RULES")"
if [[ -z "$SHIPPED_WARN" ]]; then
  # No swap warn rule in the shipped file at all. Either an older release or a
  # file somebody replaced. Nothing to override; say so rather than adding an
  # entry that overrides nothing.
  echo "no swap_used_pct warn rule in ${RULES}, leaving the alert rules untouched."
  exit 0
fi

CURRENT_LOCAL="$(swap_warn_of "$LOCAL")"

# An entry already exists. That is somebody's number, and only an explicit
# --swap-warn (the operator saying it out loud) moves it.
if [[ -n "$CURRENT_LOCAL" && -z "$SWAP_WARN" ]]; then
  echo "swap warn already set to ${CURRENT_LOCAL}% in ${LOCAL}, left as it is."
  echo "  (edit that file, or run with --swap-warn=N)"
  exit 0
fi

if [[ -z "$SWAP_WARN" ]]; then
  if [[ "$ROLE" == "co-located" ]]; then
    SWAP_WARN="$SWAP_WARN_WITH_NODE"
  else
    SWAP_WARN="$SWAP_WARN_NO_NODE"
  fi
  # A role default that matches what ships is not worth writing down. Pinning a
  # copy of the shipped value into the operator's file would hold this host on
  # today's number for good, including through a correction it should get.
  if [[ "$SWAP_WARN" == "$SHIPPED_WARN" ]]; then
    echo "the shipped swap warn (${SHIPPED_WARN}%) is already right for role '${ROLE}': nothing to override."
    exit 0
  fi
fi

# Reached only once SWAP_WARN and SHIPPED_WARN differ, which today means an
# explicit --swap-warn: both roles default to the shipped value, so nothing
# gets here from a plain install anymore.
WHY="a number chosen for this box, in place of the shipped default"

TMP="$(mktemp "${LOCAL}.role-default.XXXXXX")"
# The file carries thresholds an operator depends on, so a failure anywhere
# below leaves the original in place and takes the half-written copy with it.
trap 'rm -f "$TMP"' EXIT

if [[ -n "$CURRENT_LOCAL" ]]; then
  # Move the value inside the entry that is already there.
  awk -v val="$SWAP_WARN" '
    /^[[:space:]]*-[[:space:]]*metric:[[:space:]]*swap_used_pct[[:space:]]*$/ { inblk = 1; sev = 0; print; next }
    /^[[:space:]]*-[[:space:]]*metric:/ { inblk = 0; sev = 0 }
    inblk && /^[[:space:]]*severity:[[:space:]]*warn[[:space:]]*$/ { sev = 1; print; next }
    inblk && sev && !done && /^[[:space:]]*threshold:/ {
      sub(/value:[[:space:]]*[0-9]+(\.[0-9]+)?/, "value: " val)
      done = 1
    }
    { print }
  ' "$LOCAL" > "$TMP"
else
  # Add the entry. A file of comments (what the installer seeds) has no
  # `rules:` key yet, so it gets one.
  if [[ -f "$LOCAL" ]]; then
    cat "$LOCAL" > "$TMP"
    grep -qE '^rules:' "$LOCAL" || printf '\nrules:\n' >> "$TMP"
  else
    cat >> "$TMP" <<'HEADER'
# Aperire alert rules, yours.
#
# This file overrides dashboard/config/rules.yaml by metric + severity.
# Nothing but you writes it: no install, no update, no fleet deploy.
HEADER
    printf '\nrules:\n' >> "$TMP"
  fi
  cat >> "$TMP" <<ENTRY

  # Swap warn, for role '${ROLE}':
  # ${WHY}.
  # The shipped rule says ${SHIPPED_WARN}%. Change the number here, not there.
  - metric: swap_used_pct
    severity: warn
    threshold: { op: ">=", value: ${SWAP_WARN} }
ENTRY
fi

# Guard, not a hope. A write that did not land where it was meant to is
# exactly the silent no-op this design exists to avoid, so the file is read
# back before it replaces anything.
WROTE_VALUE="$(swap_warn_of "$TMP")"
if [[ "$WROTE_VALUE" != "$SWAP_WARN" ]]; then
  echo "error: could not set the swap warn threshold in ${LOCAL}" >&2
  echo "       expected ${SWAP_WARN}, read back ${WROTE_VALUE:-none}." >&2
  echo "       Nothing was changed. Set it by hand: a swap_used_pct warn entry" >&2
  echo "       in that file, overriding the shipped rule." >&2
  exit 1
fi

# The dashboard's own parser, when this host has it. The read-back above says
# the number is on the line it meant to write; only the loader can say the
# file it is now part of still merges. A checkout with no npm install has no
# tsx, and that is not a reason to refuse to set a threshold.
TSX_MARK="${REPO_DIR}/dashboard/node_modules/tsx/dist/cli.mjs"
MERGE_LIB="${REPO_DIR}/dashboard/lib/rules-merge.ts"
if [[ -f "$TSX_MARK" && -f "$MERGE_LIB" ]] && command -v node >/dev/null 2>&1; then
  if ! ( cd "${REPO_DIR}/dashboard" && APERIRE_SHIPPED="$RULES" APERIRE_LOCAL="$TMP" APERIRE_WANT="$SWAP_WARN" \
      node --import tsx --input-type=module -e '
        import { readFileSync } from "node:fs";
        const { mergeRuleFiles } = await import(process.cwd() + "/lib/rules-merge.ts");
        const m = mergeRuleFiles(readFileSync(process.env.APERIRE_SHIPPED, "utf8"),
                                 readFileSync(process.env.APERIRE_LOCAL, "utf8"));
        if (m.localError) { console.error(m.localError); process.exit(1); }
        const r = m.rules.find(x => x.metric === "swap_used_pct" && String(x.severity) === "warn");
        if (!r || Number(r.threshold.value) !== Number(process.env.APERIRE_WANT)) {
          console.error("the merged rule set does not carry the value that was written");
          process.exit(1);
        }
      ' ); then
    echo "error: ${LOCAL} would not merge with the shipped rules. Nothing was changed." >&2
    exit 1
  fi
fi

# Keep whatever the file's own ownership was, or the checkout's if it is new:
# this can run under sudo from install.sh, and a rules file that ends up
# root-owned is one the operator cannot edit afterwards.
if [[ -f "$LOCAL" ]]; then
  chmod --reference="$LOCAL" "$TMP"
  chown --reference="$LOCAL" "$TMP" 2>/dev/null || true
else
  chmod 0640 "$TMP"
  chown --reference="$RULES" "$TMP" 2>/dev/null || true
fi
mv "$TMP" "$LOCAL"
trap - EXIT

echo "alert rules tuned for role '${ROLE}': swap_used_pct warn = ${SWAP_WARN}%."
echo "  Written as an override in ${LOCAL} (the shipped rules.yaml is untouched)."
if [[ "$ROLE" == "dashboard" ]]; then
  echo "  This box has no node of its own, so the dashboard reads its own swap."
  echo "  If a node's relay feeds this dashboard (split deployment) the number"
  echo "  describes the NODE, not this box."
fi
echo "  Edit ${LOCAL} and reload to change it: sudo systemctl reload aperire-server"
