#!/usr/bin/env bash
# Regenerate advisord's peer table from the dashboard's fleet.yaml.
#
#   dashboard/config/fleet.yaml   authored by the operator — the source of truth
#   advisor/state/fleet.json      derived from it by this script
#
# WHY THIS EXISTS. Two files held the same fleet, and only one of them was
# ever edited. A node's advisor registry went on naming a peer for six days
# after that peer's host had been removed — and its loopback port had by
# then become the node's OWN dashboard, so the single thing standing between
# the operator and a wrong-node reading was an unreadable token file. Every
# topology fact this script writes comes from the file the operator actually
# maintains.
#
# WHAT IS GENERATED, AND WHAT IS YOURS:
#
#   generated   label, origin, role, expected_pubkey_node
#   preserved   token_path, transport — host-local facts fleet.yaml cannot
#               know (which token file THIS host can read, which tunnel is
#               load-bearing), carried through from the existing fleet.json.
#               The "self" block is preserved the same way: name the row once
#               with --self-label, and a later run without it keeps it.
#
# A peer with no token_path already recorded here is REPORTED AND SKIPPED,
# never guessed: use scripts/aperire-fleet-add.sh to join a peer for the
# first time, which reads the peer's identity and records its token path.
#
# Prints the plan and writes nothing unless --write is given.
#
#   scripts/aperire-advisor-fleet-sync.sh --self-label aggregator
#   scripts/aperire-advisor-fleet-sync.sh --self-label aggregator --write

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# The root-held copy of the state helper (get-aperire.sh places it, root-owned).
# A read that needs sudo goes through it, never through scripts/state-file.py in
# the tree: that folder is one the dashboard's account can write, and sudo would
# run what is in it as root (#886).
#
# A literal path, and never read from the environment: the login that runs this
# sets its own environment, and what it names here is what root runs (ADR 0024,
# #1127). A suite that needs a stand-in rewrites these two lines in its own copy
# of this file. Before every sudo the file is checked (root_tool_ok below): a
# regular file, not a link, owned by ROOT_TOOL_UID, writable by neither group
# nor other.
ROOT_STATE_TOOL=/usr/local/sbin/aperire-state-file
ROOT_TOOL_UID=0
root_tool_ok() {
  local meta
  [[ -f "$ROOT_STATE_TOOL" && ! -L "$ROOT_STATE_TOOL" && -r "$ROOT_STATE_TOOL" ]] || return 1
  meta="$(stat -c '%u:%a' -- "$ROOT_STATE_TOOL" 2>/dev/null)" || return 1
  [[ "${meta%%:*}" == "$ROOT_TOOL_UID" ]] && (( (8#${meta##*:} & 8#022) == 0 ))
}
DASH_FLEET="$REPO/dashboard/config/fleet.yaml"
ADV_FLEET="$REPO/advisor/state/fleet.json"
TSX="$REPO/dashboard/node_modules/.bin/tsx"

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
info() { printf '   %s\n' "$*"; }
die()  { printf '\n\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'USAGE'
usage: aperire-advisor-fleet-sync.sh [--self-label <label>] [--write]

  --self-label  optional. Which fleet.yaml row is THIS host. Writes the
                registry's "self" block, so the Advisor knows what kind of
                host it is on and stops describing itself as a node it does
                not have. Omit it and the self block already in fleet.json is
                kept as it stands; with none there, none is written — never
                inferred, because a dashboard with no node looks exactly as
                much like an aggregator as it does like a broken node.
  --write       actually write advisor/state/fleet.json. Without it, the
                plan is printed and nothing is touched.

Restart advisord after writing — the registry is read once at start:
  sudo systemctl restart aperire-advisord
USAGE
}

SELF_LABEL="" DO_WRITE=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --self-label) [[ $# -ge 2 ]] || die "--self-label needs a value"; SELF_LABEL=$2; shift 2 ;;
    --write)      DO_WRITE=1; shift ;;
    -h|--help)    usage; exit 0 ;;
    *) die "unknown argument '$1' — see --help" ;;
  esac
done

[[ -f "$DASH_FLEET" ]] || die "no $DASH_FLEET — this host has no fleet to generate from"
[[ -x "$TSX" ]] || die "no tsx at $TSX — the generator runs the dashboard's own parser, so the dashboard must be installed here"
[[ -d "$REPO/advisor/state" ]] || die "no $REPO/advisor/state — install the Advisor first (scripts/install-advisord.sh)"

# The existing registry, read the same three-outcome way aperire-fleet-add.sh
# reads it: absent is fine, unreadable is not, and neither is a shape nobody
# can append to.
EXISTING=""
if [[ -e "$ADV_FLEET" ]]; then
  if [[ -r "$ADV_FLEET" ]]; then
    EXISTING="$(cat "$ADV_FLEET")"
  elif root_tool_ok && command -v sudo >/dev/null 2>&1; then
    EXISTING="$(sudo python3 -I "$ROOT_STATE_TOOL" read "$ADV_FLEET")" \
      || die "$ADV_FLEET exists but could not be read even with sudo — refusing to guess at its contents"
  else
    die "$ADV_FLEET exists and is not readable by $(id -un), and this host has no root-held state helper ($ROOT_STATE_TOOL) to read it with through sudo, or no sudo. If the Advisor is installed here, curl -fsSL https://get.aperire.one | bash -s -- --update --force places it; run this again after"
  fi
fi

WORKDIR="$(mktemp -d)"
# invoked indirectly by the EXIT trap on the next line; shellcheck 0.9.x calls
# the body unreachable (SC2317), 0.10.x calls the function uninvoked (SC2329)
# shellcheck disable=SC2317,SC2329
cleanup() { rm -rf -- "$WORKDIR" 2>/dev/null; return 0; }
trap cleanup EXIT

EXISTING_FILE="$WORKDIR/existing.json"
OUT_FILE="$WORKDIR/fleet.json"
REPORT_FILE="$WORKDIR/report.txt"
# The label of the self block the generator actually produced — which is not
# the same question as "was --self-label given", now that an existing block is
# preserved through a run without the flag. The warning below keys off this
# file, so a preserved host is never told it is unnamed.
SELF_FILE="$WORKDIR/self.txt"
printf '%s' "$EXISTING" > "$EXISTING_FILE"

say "Reading $DASH_FLEET"
# The generator is the dashboard's own module, running under the dashboard's
# own YAML parser — the same code path the server uses to read this file, so
# a row this script accepts is a row the dashboard accepts.
(
  cd "$REPO/dashboard" && "$TSX" -e "
    import { readFileSync, writeFileSync, existsSync } from 'node:fs';
    import { generateAdvisorRegistry, renderAdvisorRegistry } from './lib/advisor-registry-gen.js';
    const g = generateAdvisorRegistry({
      fleetYaml: readFileSync(${DASH_FLEET@Q}, 'utf8'),
      existingJson: readFileSync(${EXISTING_FILE@Q}, 'utf8'),
      selfLabel: ${SELF_LABEL@Q} || undefined,
    });
    const lines = [];
    if (g.error) { console.error(g.error); process.exit(1); }
    for (const n of g.notes) lines.push('note    ' + n);
    for (const s of g.skipped) lines.push('SKIPPED ' + s.label + ' — ' + s.reason);
    const reg = g.registry;
    lines.push('self    ' + (reg.self ? JSON.stringify(reg.self) : '(none — pass --self-label)'));
    for (const p of reg.peers) {
      lines.push('peer    ' + p.label + '  ' + p.origin +
        '  role=' + (p.role ?? '(unspecified)') +
        '  pin=' + (p.expected_pubkey_node ? 'yes' : 'no'));
      // token_path is carried through from the existing registry, never
      // derived from fleet.yaml, so it can go stale on its own: an install
      // dir renamed under it, a token file moved. advisord loads the row
      // fine and fails on the first read. Say so here, where the operator
      // is looking, rather than in a log nobody reads until break glass.
      if (p.token_path && !existsSync(p.token_path)) {
        lines.push('WARNING ' + p.label + ' — token_path does not exist: ' + p.token_path +
          ' (advisord will fail to read this peer; fix the path in fleet.json or re-run aperire-fleet-add.sh)');
      }
    }
    writeFileSync(${REPORT_FILE@Q}, lines.join('\n') + '\n');
    writeFileSync(${SELF_FILE@Q}, reg.self?.label ?? '');
    writeFileSync(${OUT_FILE@Q}, renderAdvisorRegistry(reg));
  "
) || die "the generator refused — nothing was written"

sed 's/^/   /' "$REPORT_FILE"

# Said every run in which the registry ends up with no self block at all —
# not merely every run without the flag, since a block already on disk is
# preserved. Without one the registry describes the fleet but not the host
# reading it, and an Advisor that cannot name its own host is the
# self-blindness this whole change is about: a quiet degrade here would be
# indistinguishable from success.
SELF_RESOLVED=""
[[ -f "$SELF_FILE" ]] && SELF_RESOLVED="$(cat "$SELF_FILE")"
if [[ -z "$SELF_RESOLVED" ]]; then
  say "This host is not named"
  info "no --self-label was given, so no \"self\" block is written and the Advisor will not"
  info "know which host it is on. Pick the fleet.yaml row that IS this host and re-run:"
  info "  $0 --self-label <label> --write"
  info "Nothing is inferred here on purpose: a dashboard with no node looks exactly as"
  info "much like an aggregator as it does like a broken node."
fi

if (( ! DO_WRITE )); then
  say "Plan only"
  info "nothing was written. Re-run with --write to apply, then restart advisord."
  exit 0
fi

# Owner, group and mode are PRESERVED from whatever is already there — this
# file is read by the advisor service account, and a sync that silently
# re-owned it would take the fleet away on the next restart.
resolve_owner_group() {
  local ref="$1" out
  if out="$(stat -c '%U %G' "$ref" 2>/dev/null)"; then printf '%s' "$out"; return 0; fi
  if command -v sudo >/dev/null 2>&1 && out="$(sudo stat -c '%U %G' "$ref" 2>/dev/null)"; then
    printf '%s' "$out"; return 0
  fi
  die "could not determine the owner of $ref to preserve it — refusing to guess an account name"
}

# The same two facts numerically, for the plant below, which hands the file
# away on a descriptor and takes ids rather than names (#703).
resolve_uid_gid() {
  local ref="$1" out
  if out="$(stat -c '%u %g' "$ref" 2>/dev/null)"; then printf '%s' "$out"; return 0; fi
  if command -v sudo >/dev/null 2>&1 && out="$(sudo stat -c '%u %g' "$ref" 2>/dev/null)"; then
    printf '%s' "$out"; return 0
  fi
  die "could not determine the numeric owner of $ref to preserve it"
}

if [[ -e "$ADV_FLEET" ]]; then
  read -r OWNER GROUP <<<"$(resolve_owner_group "$ADV_FLEET")"
  read -r ADV_UID ADV_GID <<<"$(resolve_uid_gid "$ADV_FLEET")"
  MODE="$(stat -c '%a' "$ADV_FLEET" 2>/dev/null || sudo stat -c '%a' "$ADV_FLEET")"
  BACKUP="$WORKDIR/fleet.json.bak"
  printf '%s' "$EXISTING" > "$BACKUP"
else
  read -r OWNER GROUP <<<"$(resolve_owner_group "$REPO/advisor/state")"
  read -r ADV_UID ADV_GID <<<"$(resolve_uid_gid "$REPO/advisor/state")"
  MODE="600"
  BACKUP=""
fi

# The one place this script writes into advisor/state, and it is root doing it
# in a directory the Advisor's own account owns (#703). `install` sets the
# mode through the PATH after making the inode, so a link swapped into that
# gap takes root's chmod; the helper does create, ownership, mode and the
# move onto the name on one descriptor.
SUDO_CMD=()
if [[ -e "$ADV_FLEET" ]]; then
  [[ -w "$ADV_FLEET" ]] || SUDO_CMD=(sudo)
else
  [[ -w "$(dirname "$ADV_FLEET")" ]] || SUDO_CMD=(sudo)
fi
# The tree's copy when this account can write the directory itself (it is that
# account's own code). When the write needs sudo, the root-held copy: sudo on
# a file in the tree is root running what the dashboard's or the Advisor's
# account left there (#886).
ADV_STATE_TOOL="$REPO/scripts/state-file.py"
if (( ${#SUDO_CMD[@]} )); then
  root_tool_ok \
    || die "writing $ADV_FLEET needs sudo, and this host has no root-held state helper ($ROOT_STATE_TOOL) that root will run (a regular file owned by root and writable by no one else) to do it with. Nothing was written. If the Advisor is installed here, curl -fsSL https://get.aperire.one | bash -s -- --update --force places it; run this again after"
  ADV_STATE_TOOL="$ROOT_STATE_TOOL"
fi
[[ -r "$ADV_STATE_TOOL" ]] \
  || die "$ADV_STATE_TOOL is missing from this checkout; it and this script ship together"

say "Writing $ADV_FLEET"
"${SUDO_CMD[@]}" python3 -I "$ADV_STATE_TOOL" plant "$ADV_FLEET" \
  "$ADV_UID" "$ADV_GID" "$MODE" --stdin < "$OUT_FILE"

# Read back what actually landed, and put the previous contents back if it
# is not the shape advisord's loader accepts. A sync that can silently empty
# a fleet is worse than no sync.
READBACK="$WORKDIR/readback.json"
if [[ -r "$ADV_FLEET" ]]; then
  cat "$ADV_FLEET" > "$READBACK"
elif root_tool_ok && command -v sudo >/dev/null 2>&1; then
  # READBACK is a user-owned temp in WORKDIR; only the read of the
  # advisord-owned registry needs root, not the redirect — SC2024 is a false
  # positive here.
  # shellcheck disable=SC2024
  sudo python3 -I "$ROOT_STATE_TOOL" read "$ADV_FLEET" > "$READBACK"
else
  : > "$READBACK"
fi
if ! python3 -I - "$READBACK" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
assert isinstance(d, dict), "not the registry object form"
peers = d.get("peers", [])
assert isinstance(peers, list), "peers is not a list"
allowed = {"label", "origin", "token_path", "transport", "role", "expected_pubkey_node"}
self_label = (d.get("self") or {}).get("label", "")
for r in peers:
    assert set(r.keys()) <= allowed, "a row carries a key advisord's loader would refuse: %s" % sorted(r.keys())
    assert {"label", "origin", "token_path"} <= set(r.keys()), "a row is missing a required key"
    assert r["label"] != self_label, "a row names this host itself"
PY
then
  if [[ -n "$BACKUP" ]]; then
    "${SUDO_CMD[@]}" python3 -I "$ADV_STATE_TOOL" plant "$ADV_FLEET" \
      "$ADV_UID" "$ADV_GID" "$MODE" --stdin < "$BACKUP"
    die "what landed did not verify — restored the previous $ADV_FLEET"
  fi
  # Through the helper, on a descriptor, never `rm -f` by name as root
  # (#897). A root-held helper from before the verb cannot, and nothing falls
  # back to rm.
  "${SUDO_CMD[@]}" python3 -I "$ADV_STATE_TOOL" unlink "$ADV_FLEET" --root "$REPO/advisor/state" \
    || die "what landed did not verify, and the file this run created could not be removed from $ADV_FLEET (above). Bring the helper up to date, then run this again, which rewrites it: curl -fsSL https://get.aperire.one | bash -s -- --update --force"
  die "what landed did not verify — removed the file this run created"
fi
info "wrote and verified ($OWNER:$GROUP, mode $MODE)"

say "Next"
info "the registry is read once at start, so advisord needs a restart to see this:"
info "  sudo systemctl restart aperire-advisord"
info "an advisor restart re-seals the model key and closes any open break-glass window,"
info "which is your call, not this script's."
