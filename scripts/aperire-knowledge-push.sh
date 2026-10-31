#!/bin/bash
# Aperire — push the fleet knowledge bundle (ADR 0017 decision 3).
#
# Run on the AGGREGATOR, as the account that owns dashboard/config. It lints
# the local advisor/knowledge-fleet/, packs it into a tar.gz with a manifest
# of file hashes, signs the manifest with the aggregator's Ed25519 key (the
# same key the trust bundle uses), and POSTs it to every node registered in
# dashboard/config/fleet.yaml. Each node verifies the signature, verifies
# every hash, refuses a sequence it has already applied, and swaps the corpus
# in atomically.
#
#   aperire-knowledge-push [--node <label>] [--dry-run] [--replace-fleet-corpus]
#                          [--withdraw-all]
#
#   --node <label>          push to one node instead of every registered one
#   --dry-run               lint, build and archive the bundle; push nothing
#   --replace-fleet-corpus  push even though it would delete notes this host has
#                           no record of (see below)
#   --withdraw-all          push an EMPTY corpus, which removes every fleet note
#                           from every node that applies it (see below)
#
# The sequence number is reserved BEFORE the push, not after. A number that
# reached one node and was then reused for different content would be refused
# by that node forever, so a bundle that was built spends its number whether
# the push succeeded, failed, or died halfway.
#
# If this host lost its counter (a wipe, a restore or a move to a new host), the
# first number is 1 and every node that applied a higher one refuses it. The
# refusal names that sequence, so the counter is moved past it and the bundle is
# built once more under the next number, in the same run (#1218).
#
# A bundle is the whole corpus: a node removes every file the bundle does not
# carry. So before it sends anything this asks each node which bundle it last
# applied, and checks the new corpus against the record this host keeps of what
# it delivered to that node (delivered.json beside the archived bundles). A push
# that would delete notes under local/, or one for a node whose bundle this host
# never delivered (a restore, a move to a new host, a wipe lost the record), is
# refused with nothing sent, exit 5, naming the node and the way back (#1236).
# --replace-fleet-corpus is the operator saying the replacement is meant. A node
# whose status cannot be read is not pushed to; the rest are.
#
# An empty corpus is pushed only with --withdraw-all (#1219). It is how a fleet
# takes back the last note it promoted, and it is also exactly what a host that
# lost its corpus looks like, so the two are told apart by the operator saying
# so and by nothing else: without the flag an empty corpus is refused before a
# sequence is spent, and with it a corpus that still has files is refused too,
# so the flag is never a general override. --withdraw-all confirms the drops
# this host's delivery record accounts for, and only those: a node it has no
# record of delivering to, or a record it cannot read (a restore leaves both,
# with an empty corpus), still refuses, exit 5, unless --replace-fleet-corpus
# is given too. That one alone does not push an empty corpus. A node on a
# release from before this one refuses an empty bundle and keeps its notes
# until its Advisor is updated.
#
# It is a separate command from aperire-auth on purpose. That one is about who
# may approve — accounts, passkeys, roles — and this one changes nothing about
# authority at all. Knowledge shapes advice and grants nothing: no bundle can
# widen a read, alter a precondition, or touch a ceremony.
set -euo pipefail

# Resolve through the ~/.local/bin symlink (install-aperire-cli.sh) so the repo
# dir is the real checkout, not the symlink's parent.
SELF="$(readlink -f "${BASH_SOURCE[0]}")"
SCRIPT_DIR="$(cd "$(dirname "$SELF")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
DASHBOARD_DIR="${REPO_DIR}/dashboard"
ADVISOR_DIR="${REPO_DIR}/advisor"
KNOW_DIR="${APERIRE_KNOWLEDGE_FLEET:-${ADVISOR_DIR}/knowledge-fleet}"
BUNDLE_DIR="${APERIRE_KNOWLEDGE_BUNDLES:-${ADVISOR_DIR}/knowledge-bundles}"

ONLY=""
DRY=0
REPLACE=0
WITHDRAW=0
# Kept whole, for the line that tells an operator how to run this same push
# as another account.
ORIG_ARGS=("$@")
while [[ $# -gt 0 ]]; do
  case "$1" in
    # A missing label is refused, and so is an empty one (#1225). `shift 2`
    # with one argument left consumed nothing, so the loop read --node again
    # forever; and an empty label reads as no filter at all, so a variable that
    # expanded to nothing turned a push to one node into a push to every node.
    --node)
      [[ $# -ge 2 && -n "$2" ]] || { echo "error: --node needs a node label" >&2; exit 2; }
      ONLY="$2"; shift 2 ;;
    --dry-run) DRY=1; shift ;;
    --replace-fleet-corpus) REPLACE=1; shift ;;
    --withdraw-all) WITHDRAW=1; shift ;;
    -h|--help) awk 'NR>=2 { if ($0 !~ /^#/) exit; sub(/^# ?/, ""); print }' "$0"; exit 0 ;;
    *) echo "error: unknown argument: $1" >&2; exit 2 ;;
  esac
done

# ── Locate node ────────────────────────────────────────────────────────────
# Same reasoning as aperire-auth.sh: over SSH, .bashrc often returns before
# nvm loads, so `node` is simply absent from PATH.
#
# The tree is tested before find walks it, and the pipeline ends in `|| true`
# (#320). `find` on a home with no .nvm exits 1, `pipefail` makes that the
# pipeline's status, and as the whole of the assignment it became this
# script's status, so `set -e` killed it here, before the refusal three
# lines below, which is the sentence the operator needs. A fallback that
# finds nothing must return empty, never take the program down.
NODE_BIN="$(command -v node 2>/dev/null || true)"
if [[ -z "$NODE_BIN" && -d "$HOME/.nvm/versions/node" ]]; then
  NODE_BIN="$(find "$HOME/.nvm/versions/node" -maxdepth 3 -path '*/bin/node' -type f 2>/dev/null | sort -V | tail -1 || true)"
fi
[[ -n "$NODE_BIN" && -x "$NODE_BIN" ]] || {
  echo "error: cannot find node; the bundle is signed with it." >&2
  exit 1
}

[[ -d "$KNOW_DIR" ]] || {
  echo "error: no $KNOW_DIR — there is no fleet knowledge on this host to push." >&2
  echo "       Create advisor/knowledge-fleet/local/ and put a note in it first." >&2
  exit 1
}

TRUST_FILE="${DASHBOARD_DIR}/config/fleet-trust.yaml"
# There, and not readable by whoever ran this (#878). Since #868 the key is
# the dashboard account's alone, 0600, on purpose: the dashboard is the one
# process that signs with it. So the answer is never a wider mode. It is the
# account to run the push as, when the key's owner IS the dashboard's account,
# or else the step that puts the key back where the release keeps it.
#
# Which account the dashboard runs as is read from its unit, the one whose
# WorkingDirectory is this tree's dashboard/, never taken from the file's
# owner: a key that some third account owns is not a reason to run the push
# as that account.
dashboard_unit_user() {
  local u wd here
  here="$(cd "$DASHBOARD_DIR" 2>/dev/null && pwd -P)" || return 1
  while read -r u _; do
    [[ "$u" == *.service ]] || continue
    wd="$(systemctl show -p WorkingDirectory --value "$u" 2>/dev/null || true)"
    [[ -n "$wd" && "$(cd "$wd" 2>/dev/null && pwd -P)" == "$here" ]] || continue
    systemctl show -p User --value "$u" 2>/dev/null || true
    return 0
  done < <(systemctl list-unit-files --no-legend 'aperire-server*.service' 'aperire-read*.service' 2>/dev/null || true)
  return 1
}
# Three different facts used to share one sentence (#881, #878): the key is
# there but unreadable, its directory cannot be opened, or it is not there.
if [[ ! -r "$TRUST_FILE" ]]; then
  if [[ -e "$TRUST_FILE" ]]; then
    key_owner="$(stat -c %U "$TRUST_FILE" 2>/dev/null || echo unknown)"
    key_mode="$(stat -c %a "$TRUST_FILE" 2>/dev/null || echo unknown)"
    key_meta="$(stat -c '%U:%G %a' "$TRUST_FILE" 2>/dev/null || echo 'owner unknown')"
    me="$(id -un)"
    dash_user="$(dashboard_unit_user || true)"
    echo "error: the trust key exists at $TRUST_FILE but $me can't read it ($key_meta), so nothing was pushed." >&2
    echo "       It holds this aggregator's signing key. Leave its mode as it is: it is meant" >&2
    echo "       to be readable by the dashboard's account alone." >&2
    if [[ "$key_owner" == "$me" ]]; then
      # The caller owns it, so who may read it is not the question: the file's
      # own mode is what blocks the read. The release's own step puts it back.
      echo "       $me owns it, but its mode ($key_mode) blocks reading." >&2
      echo "       Put it back where the release keeps it, then run this as the dashboard's account:" >&2
      echo "         curl -fsSL https://get.aperire.one | bash -s -- --dir $REPO_DIR --run fleet-trust-split" >&2
    elif [[ -n "$dash_user" && "$key_owner" == "$dash_user" && "$key_owner" != root ]]; then
      echo "       Run the push as $key_owner, the account the dashboard runs as:" >&2
      printf '         sudo -u %s env PATH=%q %q' "$key_owner" "$(dirname "$NODE_BIN"):/usr/local/bin:/usr/bin:/bin" \
        "${SCRIPT_DIR}/aperire-knowledge-push.sh" >&2
      [[ ${#ORIG_ARGS[@]} -eq 0 ]] || printf ' %q' "${ORIG_ARGS[@]}" >&2
      printf '\n' >&2
    else
      echo "       It belongs to $key_owner, and the dashboard here runs as ${dash_user:-an account its unit did not name}." >&2
      echo "       Put it back where the release keeps it, then run this as the dashboard's account:" >&2
      echo "         curl -fsSL https://get.aperire.one | bash -s -- --dir $REPO_DIR --run fleet-trust-split" >&2
    fi
  elif [[ -d "${TRUST_FILE%/*}" && ! -x "${TRUST_FILE%/*}" ]]; then
    echo "error: ${TRUST_FILE%/*} exists but $(id -un) can't open it, so the trust key at $TRUST_FILE can't be checked." >&2
    echo "       Run this as the account that owns the dashboard." >&2
  else
    echo "error: no $TRUST_FILE: generate this aggregator's trust key first" >&2
  fi
  exit 1
fi
PRIV="$(awk -F': *' '/^private_key:/{print $2; exit}' "$TRUST_FILE")"
[[ -n "$PRIV" ]] || { echo "error: no private_key in $TRUST_FILE" >&2; exit 1; }

FLEET_FILE="${DASHBOARD_DIR}/config/fleet.yaml"
[[ -r "$FLEET_FILE" ]] || {
  echo "error: no $FLEET_FILE (this host is not an aggregator)" >&2
  exit 1
}

# ── Lint ───────────────────────────────────────────────────────────────────
# The gate is not optional. A corpus pushed to every Advisor in the fleet
# unchecked is exactly what the lint exists for, so a host with no way to run
# it does not get to push instead — it gets told how to build the binary.
LINT=""
if [[ -x "${ADVISOR_DIR}/bin/knowledge-lint" ]]; then
  LINT="${ADVISOR_DIR}/bin/knowledge-lint"
fi
# The shipped binary is taken first (a release install builds it beside the
# Advisor's, #1131). Failing that, Go: on PATH, or where prepare-host.sh puts
# it, since a host that was given its toolchain that way has it off every
# PATH an operator's shell sets.
GO_CMD=""
if command -v go >/dev/null 2>&1; then GO_CMD="$(command -v go)"
elif [[ -x "${APERIRE_GO_FALLBACK:-/usr/local/go/bin/go}" ]]; then GO_CMD="${APERIRE_GO_FALLBACK:-/usr/local/go/bin/go}"; fi
if [[ -z "$LINT" && -n "$GO_CMD" ]]; then
  echo "Building knowledge-lint..."
  ( cd "$ADVISOR_DIR" && "$GO_CMD" build -o bin/knowledge-lint ./cmd/knowledge-lint )
  LINT="${ADVISOR_DIR}/bin/knowledge-lint"
fi
[[ -n "$LINT" ]] || {
  echo "error: no knowledge-lint on this host and no Go toolchain to build one." >&2
  echo "       The Advisor's host preparation builds it, and puts Go on the host if it is missing:" >&2
  echo "         curl -fsSL https://get.aperire.one | bash -s -- --dir ${REPO_DIR} --run prepare-host --role dashboard --with-advisor" >&2
  echo "       Or build it where Go is installed and copy it in:" >&2
  echo "         cd advisor && go build -o bin/knowledge-lint ./cmd/knowledge-lint" >&2
  exit 1
}
echo "Linting $KNOW_DIR:"
"$LINT" -fleet "$KNOW_DIR"

# ── An empty corpus is said out loud (#1219) ───────────────────────────────
# Counted by the same walk that builds the bundle, so what counts as a file is
# decided in one place, and counted before the reservation below, so a refusal
# here spends no sequence.
# The second line says whether this host's delivery record names every node
# the push would reach. Without it this host cannot tell a withdrawal from a
# restore (which leaves the corpus and the record both empty), so the copy-back
# leads and --withdraw-all is not offered.
COUNTED="$(KNOW_DIR="$KNOW_DIR" COUNT_ONLY=1 RECORD_DIR="$BUNDLE_DIR" FLEET_FILE="$FLEET_FILE" ONLY="$ONLY" \
  python3 -I "${DASHBOARD_DIR}/lib/knowledge-bundle-job.py")" || exit 3
NFILES="$(sed -n 1p <<<"$COUNTED")"
ON_RECORD="$(sed -n 2p <<<"$COUNTED")"
[[ "$NFILES" =~ ^[0-9]+$ ]] || { echo "error: the corpus could not be counted" >&2; exit 3; }
if [[ "$NFILES" -eq 0 && $WITHDRAW -eq 0 ]]; then
  {
    echo "Not pushing: there is no markdown under $KNOW_DIR/base or $KNOW_DIR/local. Nothing was built"
    echo "and no sequence was spent. Every node keeps the notes it holds, the ones removed here included, until"
    echo "a push reaches it."
    echo "A push replaces each node's whole corpus, so pushing this would remove every fleet note from every node."
    if [[ "$ON_RECORD" == recorded ]]; then
      echo "If you removed the last promoted note on purpose, withdraw them all with:"
      printf '  aperire-knowledge-push'
      [[ ${#ORIG_ARGS[@]} -eq 0 ]] || printf ' %q' "${ORIG_ARGS[@]}"
      printf ' --withdraw-all\n'
      echo "If this host lost its corpus (a restore, a move, a wipe), copy it back from a node that has it first."
    else
      echo "This host has no record of delivering to every node, which is what a restore, a move or a wipe leaves."
      echo "If it lost its corpus, copy it back from a node that has it first. Promote writes there as the dashboard's"
      echo "account, so run the copy as that account:"
      echo "  sudo -u <dashboard account> rsync -rt <node>:<install dir>/advisor/knowledge-fleet/ <this install dir>/advisor/knowledge-fleet/"
      echo "Then push again. Withdrawing every note from nodes this host has no record of needs both confirmations:"
      printf '  aperire-knowledge-push'
      [[ ${#ORIG_ARGS[@]} -eq 0 ]] || printf ' %q' "${ORIG_ARGS[@]}"
      printf ' --withdraw-all --replace-fleet-corpus\n'
    fi
  } >&2
  exit 3
fi
if [[ "$NFILES" -gt 0 && $WITHDRAW -eq 1 ]]; then
  echo "error: --withdraw-all pushes an empty corpus, and $KNOW_DIR holds $NFILES file(s). Nothing was built." >&2
  echo "       Remove them first, or push without --withdraw-all." >&2
  exit 2
fi

# ── Reserve the sequence ───────────────────────────────────────────────────
# In lib/knowledge-push.ts, not in awk here: the previous number is read out
# of a JSON file, and a hand-rolled parse of one is a thing nobody can test
# and everybody has to trust. The reservation happens before anything is
# built, so a number is spent whether the push then works or not.
SEQ="$(cd "$DASHBOARD_DIR" && "$NODE_BIN" --import tsx lib/knowledge-push.mjs \
  --reserve-seq "$BUNDLE_DIR" "${SUDO_USER:-${USER:-unknown}}")" || exit 3
[[ "$SEQ" =~ ^[0-9]+$ ]] || { echo "error: no sequence number was reserved" >&2; exit 3; }

OUT_TAR="${BUNDLE_DIR}/knowledge-${SEQ}.tar.gz"
OUT_MANIFEST="${BUNDLE_DIR}/manifest-${SEQ}.json"

# ── Build the archive and the manifest, in one pass ────────────────────────
echo "Building bundle ${SEQ}..."
JOB="$(KNOW_DIR="$KNOW_DIR" OUT_TAR="$OUT_TAR" SEQ="$SEQ" ISSUER="aggregator" \
  PUSHED_BY="${SUDO_USER:-${USER:-unknown}}" ONLY="$ONLY" FLEET_FILE="$FLEET_FILE" WITHDRAW_ALL="$WITHDRAW" \
  python3 -I "${DASHBOARD_DIR}/lib/knowledge-bundle-job.py")" || exit 3

# The manifest is archived beside the archive it describes: together they are
# the aggregator's copy of what every node was asked to apply (ADR 0017
# decision 6 — no git on the boxes, so this is the history).
JOB="$JOB" "$NODE_BIN" -e '
  process.stdout.write(JSON.stringify(JSON.parse(process.env.JOB).manifest, null, 2) + "\n");
' > "$OUT_MANIFEST"
chmod 640 "$OUT_MANIFEST" 2>/dev/null || true
echo "  archive:  $OUT_TAR ($(wc -c < "$OUT_TAR") bytes)"
echo "  manifest: $OUT_MANIFEST"

if [[ $DRY -eq 1 ]]; then
  echo "(--dry-run: nothing was pushed; sequence $SEQ is spent and the next build will be $((SEQ + 1)))"
  exit 0
fi

# ── Sign and push ──────────────────────────────────────────────────────────
echo "Pushing to fleet nodes (issuer 'aggregator', sequence ${SEQ}):"
# cwd must be DASHBOARD_DIR so `--import tsx` resolves dashboard/node_modules/tsx;
# the .mjs imports its siblings by relative path, so that is unaffected.
# The key reaches the job on stdin and travels to the pusher on stdin: never
# argv (a command line is readable by every account on the box), never a file,
# and not the environment either (/proc/<pid>/environ is readable by the same
# account for as long as the process lives). The pusher signs with it and
# forwards only the signature.
rc=0
printf '%s' "$PRIV" | JOB="$JOB" REPLACE="$REPLACE" WITHDRAW="$WITHDRAW" "$NODE_BIN" -e '
  let k = ""; process.stdin.setEncoding("utf8");
  process.stdin.on("data", (c) => (k += c));
  process.stdin.on("end", () => {
    const j = JSON.parse(process.env.JOB);
    j.private_key = k.trim();
    j.replace_fleet_corpus = process.env.REPLACE === "1";
    j.withdraw_all = process.env.WITHDRAW === "1";
    process.stdout.write(JSON.stringify(j));
  });
' | ( cd "$DASHBOARD_DIR" && "$NODE_BIN" --import tsx lib/knowledge-push.mjs ) || rc=$?

# 5 is the runner refusing before it sent anything (#1236): the push could delete
# notes this host cannot account for, and the text it printed says which. Not the
# failure of a push, so not the closing lines below. The confirming command is
# printed here, from the arguments this run was given, because the runner cannot
# know them: a refusal under --node X must not be answered by a command that
# turns the check off for every node.
if [[ $rc -eq 5 ]]; then
  {
    echo
    printf 'Nothing was pushed. Sequence %s is spent. To go ahead anyway, run the same push with the confirmation:\n' "$SEQ"
    printf '  aperire-knowledge-push'
    [[ ${#ORIG_ARGS[@]} -eq 0 ]] || printf ' %q' "${ORIG_ARGS[@]}"
    printf ' --replace-fleet-corpus\n'
  } >&2
  exit 5
fi

# 4 is the runner saying a node had already applied a higher sequence than this
# aggregator's counter, and that the counter has been moved past it (#1218).
# The bundle just built carries a number the fleet has used, so it is built
# again under the next one, once. That run writes APERIRE_PUSH_RESULT again when
# it pushes; if it stops before then, the file still describes this attempt and
# the output says why. A second 4 means the fleet moved under this run, and is
# the failure it looks like.
if [[ $rc -eq 4 ]]; then
  if [[ -z "${APERIRE_PUSH_RERUN:-}" ]]; then
    echo
    echo "Building the bundle again under the next sequence."
    APERIRE_PUSH_RERUN=1 exec bash "$SELF" ${ORIG_ARGS[@]+"${ORIG_ARGS[@]}"}
  fi
  rc=1
fi

if [[ $rc -eq 0 ]]; then
  echo "All pushes succeeded."
else
  echo "One or more pushes did not succeed (see above). The bundle is archived as $OUT_TAR;" >&2
  echo "re-run to build the next sequence, or push one node with --node <label>." >&2
fi
exit $rc
