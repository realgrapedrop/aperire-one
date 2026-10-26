#!/usr/bin/env bash
# What scripts/aperire-compact-check.sh says, and when it says nothing.
#
# The silence matters as much as the notice. A fresh install has accepted
# nothing, and an install that ends by telling that operator to accept a
# compact again is worse than one that says nothing at all: it sends them to
# re-do a thing they have not done once.
#
#   bash scripts/test-compact-check.sh
#
# Writes only inside its own temp directory and needs no root.
set -uo pipefail

SUT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/aperire-compact-check.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
PASS=0; FAIL=0
ok()  { printf '  ok    %s\n' "$1"; PASS=$((PASS + 1)); }
bad() { printf '  FAIL  %s\n     %s\n' "$1" "${2:-}"; FAIL=$((FAIL + 1)); }

mkdir -p "$TMP/etc" "$TMP/advisor/state"
export APERIRE_ETC="$TMP/etc"
export APERIRE_ADVISOR_STATE="$TMP/advisor/state"

node_conf() { # $1 = SERVICE value
  cat > "$TMP/etc/node.conf" <<EOF
KIND=native
SERVICE=$1
ADMIN_RPC=http://127.0.0.1:5005
CONFIG_FILE=$TMP/node/xrpld.cfg
NODE_LABEL=aperire-node2
EOF
}

# The shape the executor writes: MarshalIndent, one key per line, one class
# per line. Parsed rather than assumed, so this fixture is the real shape.
compact_for() { # $1 = node, $2.. = classes
  local node="$1"; shift
  {
    printf '{\n  "terms_version": "v2",\n'
    printf '  "terms_hash": "6b0c1d2e3f405162",\n'
    printf '  "accepted_by": "aperire-advisor",\n'
    printf '  "accepted_at": "2026-08-20T00:51:29Z",\n'
    printf '  "node": "%s",\n' "$node"
    printf '  "privilege": "D1",\n'
    printf '  "classes": [\n'
    local first=1 c
    for c in "$@"; do
      (( first )) || printf ',\n'
      printf '    "%s"' "$c"
      first=0
    done
    printf '\n  ]\n}\n'
  } > "$TMP/advisor/state/compact.json"
}

echo
echo "A host whose node no longer matches its acceptance is told, with the command:"
node_conf "xrpld.service"
compact_for "aperire-node2" upgrade investigate restart config
out=$(bash "$SUT" 2>&1); rc=$?
if [[ $rc -eq 0 && "$out" == *"aperire-node2"* && "$out" == *"xrpld.service"* ]]; then
  ok "it names the node the compact was accepted for and the one this host runs"
else
  bad "the notice names both nodes" "rc=$rc: $out"
fi
if [[ "$out" == *"--accept --container=xrpld.service --privilege=D1 --classes=upgrade,investigate,restart,config"* ]]; then
  ok "and the command carries this host's node, the accepted privilege and the accepted classes"
else
  bad "the command carries the previous privilege and classes" "$out"
fi
if [[ "$out" == *"aperire-executor compact \\"* ]]; then
  ok "and the line continuation is intact, so the whole command pastes"
else
  bad "the command pastes as one command" "$out"
fi
# The one thing this must never do.
if [[ ! -s "$TMP/advisor/state/ledger.jsonl" ]] \
   && grep -q '"node": "aperire-node2"' "$TMP/advisor/state/compact.json"; then
  ok "and it accepted nothing: the acceptance on disk is untouched"
else
  bad "the check changed state" "$(cat "$TMP/advisor/state/compact.json")"
fi

echo
echo "And it says nothing at all when there is nothing to say:"
compact_for "xrpld.service" upgrade restart
out=$(bash "$SUT" 2>&1); rc=$?
if [[ $rc -eq 0 && -z "$out" ]]; then
  ok "a compact that names this host's node prints nothing"
else
  bad "silence on a matching compact" "rc=$rc: $out"
fi

rm -f "$TMP/advisor/state/compact.json"
out=$(bash "$SUT" 2>&1); rc=$?
if [[ $rc -eq 0 && -z "$out" ]]; then
  ok "a host that has accepted nothing is not told to accept again"
else
  bad "silence on a fresh install" "rc=$rc: $out"
fi

compact_for "aperire-node2" upgrade
node_conf "none"
out=$(bash "$SUT" 2>&1); rc=$?
if [[ $rc -eq 0 && -z "$out" ]]; then
  ok "a host that runs no node compares nothing against 'none'"
else
  bad "silence on a nodeless host" "rc=$rc: $out"
fi

node_conf "xrpld.service"
out=$(bash "$SUT" --node aperire-node2 2>&1); rc=$?
if [[ $rc -eq 0 && -z "$out" ]]; then
  ok "--node is taken over the record, so a caller that knows can say so"
else
  bad "--node overrides the record" "rc=$rc: $out"
fi

echo
echo "A class list it could not read is said, rather than guessed:"
cat > "$TMP/advisor/state/compact.json" <<'EOF'
{
  "node": "aperire-node2"
}
EOF
out=$(bash "$SUT" 2>&1); rc=$?
if [[ $rc -eq 0 && "$out" == *"could not read"* && "$out" != *"--classes="* ]]; then
  ok "no privilege and no classes means no invented ones"
else
  bad "an unreadable class list is named" "rc=$rc: $out"
fi

echo
echo "The Advisor's state is read off its own unit by exact name, never a glob (#809):"
# No state handed in, so the script has to find it in the unit. The credcheck
# unit (#541) sits beside the real one, as on every host with an Advisor, and
# sorts first; here it even carries a --state of its own, so a first-match
# reader would land on the wrong directory and say nothing.
unset APERIRE_ADVISOR_STATE
mkdir -p "$TMP/units" "$TMP/adv-real/state" "$TMP/adv-decoy/state" "$TMP/adv-two/state"
export APERIRE_UNIT_DIR="$TMP/units"
printf '[Service]\nUser=root\nExecStart=/usr/local/sbin/aperire-advisord-credcheck --state=%s\n' \
  "$TMP/adv-decoy/state" > "$TMP/units/aperire-advisord-credcheck.service"
printf '[Service]\nUser=aperire-advisor\nExecStart=/opt/advisord --addr=127.0.0.1:7810 --state=%s\n' \
  "$TMP/adv-real/state" > "$TMP/units/aperire-advisord.service"
node_conf "xrpld.service"
compact_for "aperire-node2" restart
cp "$TMP/advisor/state/compact.json" "$TMP/adv-real/state/compact.json"
out=$(bash "$SUT" 2>&1); rc=$?
if [[ $rc -eq 0 && "$out" == *"aperire-node2"* && "$out" == *"xrpld.service"* ]]; then
  ok "it reads --state from aperire-advisord.service, not from the credcheck unit that sorts before it"
else
  bad "the state comes from the Advisor's own unit" "rc=$rc: $out"
fi
# A named instance reads its own unit, by name, from the installer's own
# APERIRE_INSTANCE.
printf '[Service]\nUser=aperire-advisor\nExecStart=/opt/advisord --state=%s\n' \
  "$TMP/adv-two/state" > "$TMP/units/aperire-advisord-two.service"
compact_for "aperire-node-two" restart
cp "$TMP/advisor/state/compact.json" "$TMP/adv-two/state/compact.json"
out=$(APERIRE_INSTANCE=two bash "$SUT" 2>&1); rc=$?
if [[ $rc -eq 0 && "$out" == *"aperire-node-two"* ]]; then
  ok "  and a named instance reads aperire-advisord-<instance>.service, by name"
else
  bad "a named instance's state comes from its own unit" "rc=$rc: $out"
fi
unset APERIRE_UNIT_DIR

echo
printf '%d passed, %d failed\n' "$PASS" "$FAIL"
[[ $FAIL -eq 0 ]]
