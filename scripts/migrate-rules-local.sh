#!/usr/bin/env bash
# Move this host's tuned alert rules into rules.local.yaml, once (ADR 0020).
#
# Until now dashboard/config/rules.yaml was two things: the rule set the
# product ships and the file an operator tunes. It is the product's now, and
# every install and update replaces it, so anything this host changed has to
# move to dashboard/config/rules.local.yaml first, which nothing but the
# operator ever writes. Run this on each existing host, before the update that
# replaces its rules.yaml.
#
# WHAT IT COMPARES, AND WHY IT MATTERS. Three files, not two: this host's
# rules.yaml, the shipped rules.yaml THIS HOST'S FILE DESCENDS FROM, and
# (afterwards) the release's current one. The baseline must be that old
# shipped file. Compared against a newer one, every rule the product has
# added since would look like a rule the operator deleted, and would be
# written back as `enabled: false`: the #143 verify alert, the peer-latency
# rule, the filled peer-count ladder, all disabled by the tool meant to
# preserve this host's tuning.
#
# The right baseline is NOT the shipped file at .deploy-ref. Fleet updates
# skipped rules.yaml, so a host's file is the shipped version from whenever it
# was last written, older than its latest deploy (the lab aggregator, 2026-09-07: deploy ref
# d17a923, file from 2026-08-24, five rules short). The baseline is the newest
# shipped version that has no rule the host lacks; the
# rules-baseline tool finds it from the repository and copies it to the host.
# The .deploy-ref default below is right only for a host whose rules.yaml
# was written by that very deploy (a fresh install).
#
# AND WHAT THE RELEASE ALREADY SHIPS IS DROPPED. The baseline is old, so a
# difference against it is a difference the host MADE, not necessarily one it
# still needs. On stock-node1 three of five overrides are the #128 action
# text, pasted onto the box by hand on 2026-08-31 and shipped in the release
# since (630faa5), and two of its "added" rules ship now as well. Written down
# unpruned, each one pins today's wording or today's threshold on that host
# for good and stops the next correction reaching it: the drift ADR 0020
# exists to end, recreated by the tool meant to end it. So --current takes the
# rules.yaml of the release being deployed, and every field whose value that
# file already carries is dropped, with a line saying so. A disable is never
# dropped: it is the host's own statement, and no release can make it.
#
#   bash scripts/migrate-rules-local.sh                       # dry run, says what it would do
#   bash scripts/migrate-rules-local.sh --write               # do it
#   bash scripts/migrate-rules-local.sh --shipped=FILE        # name the baseline yourself
#   bash scripts/migrate-rules-local.sh --shipped-ref=SHA     # take it from git, here
#   bash scripts/migrate-rules-local.sh --current=FILE        # drop what the release ships
#   bash scripts/migrate-rules-local.sh --prune --current=FILE  # the same, on a file already written
#
# The rules-baseline tool copies both files to the host and prints
# the command with both flags filled in. Without --current the run still works
# and says out loud what it may have pinned, and --prune takes it back out
# later; a host migrated before --current existed (the lab aggregator, 2026-09-07) is exactly
# that case.
#
# With no --shipped and no --shipped-ref it reads .deploy-ref at the install
# root, which the fleet deploy stamps, and asks git for that ref. A host has no
# .git, so on a deployed box produce the baseline where the repository is:
#
#   git show <ref>:dashboard/config/rules.yaml > shipped-<ref>.yaml
#   scp shipped-<ref>.yaml <host>:/tmp/
#   bash scripts/migrate-rules-local.sh --shipped /tmp/shipped-<ref>.yaml --write
#
# Idempotent: a host with nothing to migrate is told so and nothing is
# written, on the first run and on every one after it. --write backs up both
# files with a timestamp, and refuses to write over a rules.local.yaml that
# already has entries. Nothing is replaced until the pair has been shown to
# reproduce the rule set this host is running right now.
#
# Needs no root: it writes two files in the checkout, owned by the account
# that runs the dashboard.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
SHIPPED_FILE=""
SHIPPED_REF=""
CURRENT_FILE=""
WRITE=0
PRUNE_ONLY=0

for arg in "$@"; do
  case "$arg" in
    --dir=*)         DIR="${arg#*=}" ;;
    --shipped=*)     SHIPPED_FILE="${arg#*=}" ;;
    --shipped-ref=*) SHIPPED_REF="${arg#*=}" ;;
    --current=*)     CURRENT_FILE="${arg#*=}" ;;
    --prune)         PRUNE_ONLY=1 ;;
    --write)         WRITE=1 ;;
    --dry-run)       WRITE=0 ;;
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

DIR="$(cd "$DIR" && pwd)"
RULES="${DIR}/dashboard/config/rules.yaml"
LOCAL="${DIR}/dashboard/config/rules.local.yaml"
RUNNER="${DIR}/dashboard/lib/rules-migrate.mjs"
TSX_MARK="${DIR}/dashboard/node_modules/tsx/dist/cli.mjs"

[[ -f "$RULES" ]]    || { echo "error: no alert rules at ${RULES}" >&2; exit 1; }
[[ -f "$RUNNER" ]]   || { echo "error: no ${RUNNER}; is this an Aperire install directory?" >&2; exit 1; }
[[ -f "$TSX_MARK" ]] || { echo "error: no dashboard/node_modules here. Run npm ci in ${DIR}/dashboard first." >&2; exit 1; }
# Node the way aperire-auth.sh finds it (#211): on PATH, else the newest in
# the install owner's nvm tree, else the caller's. A non-interactive ssh on a
# node box has no nvm on PATH, and that is where this runs.
#
# Every lookup below may find nothing, and finding nothing must leave the
# variable empty rather than take the script down (#320). `getent passwd` on
# an account with no entry exits 2 and `find` on a home with no .nvm exits 1;
# under `pipefail` that is the pipeline's status, and as the whole of an
# assignment it was this script's status, so `set -e` killed it here, before
# the refusal below, which is the only sentence that tells the operator what
# is missing.
NODE_BIN="$(command -v node 2>/dev/null || true)"
if [[ -z "$NODE_BIN" ]]; then
  OWNER_HOME="$(getent passwd "$(stat -c %U "$DIR" 2>/dev/null)" 2>/dev/null | cut -d: -f6 || true)"
  for tree in "${OWNER_HOME:-}" "$HOME"; do
    [[ -n "$tree" && -d "$tree/.nvm/versions/node" ]] || continue
    NODE_BIN="$(find "$tree/.nvm/versions/node" -maxdepth 3 -path '*/bin/node' -type f 2>/dev/null | sort -V | tail -1 || true)"
    [[ -n "$NODE_BIN" ]] && break
  done
fi
[[ -n "$NODE_BIN" ]] || { echo "error: no node on PATH and none under an nvm tree for $(stat -c %U "$DIR" 2>/dev/null || echo this) or $(id -un)" >&2; exit 1; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

run() { ( cd "${DIR}/dashboard" && "$NODE_BIN" --import tsx lib/rules-migrate.mjs "$@" ); }

if [[ -n "$CURRENT_FILE" && ! -f "$CURRENT_FILE" ]]; then
  echo "error: no current shipped rules at ${CURRENT_FILE}" >&2
  exit 1
fi

# ── --prune: the same pruning, on a file already written ────────────
#
# For a host migrated before --current existed. It needs no baseline: the
# question is only what this file still says that the release does not.
if [[ $PRUNE_ONLY -eq 1 ]]; then
  [[ -n "$CURRENT_FILE" ]] || {
    echo "error: --prune needs --current=FILE, the rules.yaml of the release being deployed." >&2
    echo "       Pruning against anything else would drop overrides this host still needs." >&2
    exit 2
  }
  [[ -f "$LOCAL" ]] || { echo "no ${LOCAL} on this host: nothing to prune."; exit 0; }
  echo "== pruning your overrides against the rules the release ships"
  echo "   your file:  ${LOCAL}"
  echo "   release:    ${CURRENT_FILE}"
  echo
  PRUNED="${TMP}/rules.local.yaml"
  set +e
  run --prune --local "$LOCAL" --current "$CURRENT_FILE" --out "$PRUNED"
  PRUNE_RC=$?
  set -e
  if [[ $PRUNE_RC -eq 3 ]]; then
    echo
    echo "Nothing to prune: every entry in your file still says something the release does not."
    exit 0
  fi
  [[ $PRUNE_RC -eq 0 ]] || exit "$PRUNE_RC"

  echo
  echo "-- rules.local.yaml as it would be written:"
  sed 's/^/   /' "$PRUNED"

  # Pruning may only remove what the release itself says, so the test is what
  # this host RUNS on that release, before and after.
  run --verify-prune --current "$CURRENT_FILE" --before "$LOCAL" --after "$PRUNED"

  # And rules.yaml has to BE that release, or the pruning takes something away
  # rather than moving it. A host migrated before --current existed sits on the
  # old baseline: drop the action text out of its local file while rules.yaml
  # is still the baseline and the text is simply gone from its alerts until
  # the update lands. So the shipped file is replaced by the release's own,
  # which is the file the update would put there anyway. Where it already is
  # that file, this copies it onto itself.
  REPLACE_SHIPPED=0
  cmp -s "$RULES" "$CURRENT_FILE" || REPLACE_SHIPPED=1

  if [[ $WRITE -eq 0 ]]; then
    echo
    echo "Dry run. Nothing was written. Run it again with --write and it will:"
    echo "  write   ${LOCAL}"
    echo "          (the entries above, and nothing else)"
    if [[ $REPLACE_SHIPPED -eq 1 ]]; then
      echo "  replace ${RULES}"
      echo "          with the release's own rules (${CURRENT_FILE}), because what"
      echo "          was pruned out of your file has to come back from that one"
    fi
    echo "  backed up first, with a timestamp"
    exit 0
  fi
  TS="$(date -u +%Y%m%dT%H%M%SZ)"
  cp -p "$LOCAL" "${LOCAL}.bak-${TS}"
  cp "$PRUNED" "$LOCAL"
  chmod --reference="${LOCAL}.bak-${TS}" "$LOCAL" 2>/dev/null || chmod 0640 "$LOCAL"
  chown --reference="${LOCAL}.bak-${TS}" "$LOCAL" 2>/dev/null || true
  if [[ $REPLACE_SHIPPED -eq 1 ]]; then
    cp -p "$RULES" "${RULES}.bak-${TS}"
    cp "$CURRENT_FILE" "$RULES"
  fi
  # Read back from disk: the pair on this host now, against the pair before it.
  run --verify-prune --current "$RULES" --before "${LOCAL}.bak-${TS}" --after "$LOCAL"
  run --summarise --shipped "$RULES" --local "$LOCAL"
  echo
  echo "Done. Backup: ${LOCAL}.bak-${TS}"
  if [[ $REPLACE_SHIPPED -eq 1 ]]; then echo "          and ${RULES}.bak-${TS}"; fi
  echo "Reload to apply: sudo systemctl reload aperire-server"
  exit 0
fi

# ── the baseline ────────────────────────────────────────────────────
#
# Never guessed. A wrong baseline writes a file that disables rules, and it
# does it quietly, so the only answers accepted here are one somebody named
# and one git can produce from a ref this host recorded.
BASELINE=""
if [[ -n "$SHIPPED_FILE" ]]; then
  [[ -f "$SHIPPED_FILE" ]] || { echo "error: no baseline file at ${SHIPPED_FILE}" >&2; exit 1; }
  BASELINE="$SHIPPED_FILE"
  BASELINE_SAID="the file you named: ${SHIPPED_FILE}"
else
  REF="$SHIPPED_REF"
  REF_FROM="--shipped-ref"
  if [[ -z "$REF" && -f "${DIR}/.deploy-ref" ]]; then
    REF="$(head -1 "${DIR}/.deploy-ref" | tr -d '[:space:]')"
    REF_FROM=".deploy-ref"
  fi
  if [[ -z "$REF" ]]; then
    echo "error: nothing says which shipped rules this host was tuned from." >&2
    echo "       There is no .deploy-ref here, so name the baseline:" >&2
    echo "         --shipped-ref <sha>   take it from git in this directory" >&2
    echo "         --shipped <file>      a copy of the shipped rules.yaml at that ref" >&2
    echo "       Comparing against the CURRENT shipped file would read every rule" >&2
    echo "       added since as one you deleted, and switch it off." >&2
    exit 2
  fi
  if ! git -C "$DIR" rev-parse --git-dir >/dev/null 2>&1; then
    echo "error: this install has no git repository, so the shipped rules at ${REF}" >&2
    echo "       cannot be read here. Produce the file where the repository is:" >&2
    echo "         git show ${REF}:dashboard/config/rules.yaml > shipped-${REF:0:10}.yaml" >&2
    echo "       copy it here, and pass it with --shipped." >&2
    exit 2
  fi
  BASELINE="${TMP}/baseline.yaml"
  if ! git -C "$DIR" show "${REF}:dashboard/config/rules.yaml" > "$BASELINE" 2>/dev/null; then
    echo "error: git here has no dashboard/config/rules.yaml at ${REF}" >&2
    exit 1
  fi
  BASELINE_SAID="the shipped rules at ${REF} (from ${REF_FROM})"
fi

echo "== alert rules on this host"
echo "   host file:  ${RULES}"
echo "   baseline:   ${BASELINE_SAID}"
echo

# ── what differs, and what of it the release already ships ──────────
#
# Two files out of the diff, not one. UNPRUNED is every difference against the
# baseline and is what the first guard below is measured against: it is the
# proof the diff read this host correctly. PROPOSED is what gets written, and
# with --current it is the unpruned set minus everything the release itself
# carries.
UNPRUNED="${TMP}/rules.local.unpruned.yaml"
PROPOSED="${TMP}/rules.local.yaml"
DIFF_ARGS=(--diff --host "$RULES" --baseline "$BASELINE" --out "$PROPOSED" --out-unpruned "$UNPRUNED")
[[ -n "$CURRENT_FILE" ]] && DIFF_ARGS+=(--current "$CURRENT_FILE")
set +e
run "${DIFF_ARGS[@]}"
DIFF_RC=$?
set -e
if [[ $DIFF_RC -eq 3 ]]; then
  echo
  echo "Nothing to migrate: this host runs the shipped rules unchanged."
  if [[ -f "$LOCAL" ]]; then echo "  (${LOCAL} is left exactly as it is)"; fi
  exit 0   # nothing was written, on this run or any run after it
fi
if [[ $DIFF_RC -eq 4 ]]; then
  echo
  echo "Nothing to keep: every difference this host has is what the release now ships."
  echo "  It needs no rules.local.yaml. Update it, and rules.yaml alone gives it"
  echo "  the rules it is running today."
  if [[ -f "$LOCAL" ]]; then echo "  (${LOCAL} is left exactly as it is)"; fi
  exit 0
fi
[[ $DIFF_RC -eq 0 ]] || exit "$DIFF_RC"

echo
echo "-- rules.local.yaml as it would be written:"
sed 's/^/   /' "$PROPOSED"

# ── the guards ──────────────────────────────────────────────────────
#
# Two, because the two files answer different questions. The unpruned set has
# to reproduce this host exactly (the diff read it right); the pruned set has
# to run the same as the unpruned one once this host is on the release the
# pruning was measured against (the pruning removed nothing of the host's).
run --verify --host "$RULES" --baseline "$BASELINE" --local "$UNPRUNED"
if [[ -n "$CURRENT_FILE" ]]; then
  run --verify-prune --current "$CURRENT_FILE" --before "$UNPRUNED" --after "$PROPOSED"
else
  echo
  echo "NOTE: no --current given, so nothing was compared with the release you are"
  echo "      about to deploy. The file above may pin values that release already"
  echo "      ships (action text, or a rule it has since added), and a pinned value"
  echo "      stops every later correction to it. Take them back out afterwards with:"
  echo "        bash ${SCRIPT_DIR}/migrate-rules-local.sh --prune --current=FILE"
fi

if [[ $WRITE -eq 0 ]]; then
  echo
  echo "Dry run. Nothing was written. Run it again with --write and it will:"
  echo "  write   ${LOCAL}"
  echo "          (the differences above, and nothing else)"
  echo "  replace ${RULES}"
  if [[ -n "$CURRENT_FILE" ]]; then
    echo "          with the release's own rules (${CURRENT_FILE}),"
    echo "          which is what the update would put there anyway"
  else
    echo "          with the shipped rules it was compared against"
  fi
  echo "  both files are backed up first, with a timestamp"
  exit 0
fi

# An operator who already has overrides is not somebody this should write
# over. Their file plus these differences is a merge, and a merge is theirs
# to make: the proposed file is on screen above.
if [[ -f "$LOCAL" ]]; then
  # A file that does not load is still theirs, and is a thing to fix rather
  # than a thing to replace. Backed up or not, this must not be how somebody
  # finds out their overrides had a typo in them.
  if ! WHY="$(run --summarise --shipped "$RULES" --local "$LOCAL" 2>&1)"; then
    echo
    echo "error: ${LOCAL} is there and does not load:" >&2
    echo "       ${WHY}" >&2
    echo "       Fix it (or move it aside) and run this again." >&2
    exit 1
  fi
  if grep -qE '^[[:space:]]*-[[:space:]]*metric:' "$LOCAL"; then
    echo
    echo "error: ${LOCAL} already has entries." >&2
    echo "       Add what is above to it by hand, then replace rules.yaml with the" >&2
    echo "       shipped file. This will not write over overrides you already have." >&2
    exit 1
  fi
fi

TS="$(date -u +%Y%m%dT%H%M%SZ)"
cp -p "$RULES" "${RULES}.bak-${TS}"
HAD_LOCAL=0
if [[ -f "$LOCAL" ]]; then
  cp -p "$LOCAL" "${LOCAL}.bak-${TS}"
  HAD_LOCAL=1
fi

# The local file first: a run that dies between the two leaves a host with its
# own rules.yaml and an extra file, which is the state it started in plus
# something to read. The other order leaves it with the shipped rules and no
# overrides, which is the outage.
#
# The file being replaced here has no entries in it (the check above refused
# the case where it does), so it is the seeded comments and nothing of the
# operator's is lost. The backup above holds it either way.
cp "$PROPOSED" "$LOCAL"
if [[ $HAD_LOCAL -eq 1 ]]; then
  chmod --reference="${LOCAL}.bak-${TS}" "$LOCAL" 2>/dev/null || chmod 0640 "$LOCAL"
  chown --reference="${LOCAL}.bak-${TS}" "$LOCAL" 2>/dev/null || true
else
  chmod --reference="$RULES" "$LOCAL" 2>/dev/null || chmod 0640 "$LOCAL"
  chown --reference="$RULES" "$LOCAL" 2>/dev/null || true
fi
# Which shipped file this host is left on.
#
# Without --current it is the baseline, and the pair reproduces this host
# exactly. With --current it is the release's own file, because the pruned
# overrides are measured against THAT one: left on the baseline, a host would
# briefly lose the fields that were dropped as "the release ships them" and
# the rules that were dropped as "the release ships them now", until the
# update arrived. The file being written is the one the update would put here
# anyway, so this only brings it forward.
if [[ -n "$CURRENT_FILE" ]]; then
  cp "$CURRENT_FILE" "$RULES"
else
  cp "$BASELINE" "$RULES"
fi

# Read back what is now on disk, not what was proposed.
if [[ -n "$CURRENT_FILE" ]]; then
  run --verify-prune --current "$RULES" --before "$UNPRUNED" --after "$LOCAL"
else
  run --verify --host "${RULES}.bak-${TS}" --baseline "$RULES" --local "$LOCAL"
fi
run --summarise --shipped "$RULES" --local "$LOCAL"

echo
echo "Done. Backups: ${RULES}.bak-${TS}"
if [[ $HAD_LOCAL -eq 1 ]]; then echo "           and ${LOCAL}.bak-${TS}"; fi
echo
if [[ -n "$CURRENT_FILE" ]]; then
  echo "This host now runs the release's rules plus your overrides, which is what"
  echo "it will still be running after the update. Next:"
  echo "  1. read ${LOCAL} and drop anything you no longer want"
  echo "  2. sudo systemctl reload aperire-server"
  echo "  3. update this host; rules.yaml is the release's from now on"
else
  echo "This host now runs the shipped rules plus your overrides. Next:"
  echo "  1. read ${LOCAL} and drop anything you no longer want"
  echo "  2. sudo systemctl reload aperire-server"
  echo "  3. update this host; rules.yaml is the release's from now on"
fi
