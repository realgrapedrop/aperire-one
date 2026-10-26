#!/usr/bin/env bash
# Exercise scripts/install-advisor-stack.sh, the sequence both Advisor install
# paths run.
#
# What is being protected: there are two ways to add the Advisor to a host, and
# for a while they left two different hosts behind. The one-line install ran
# the service installer, both root grants, the account move and the trust sync.
# `sudo bash install.sh --with-advisor` ran the service installer and the
# account move, and nothing else, so that host had no sealer socket (the
# browser's model panel had nothing to seal through) and no trust-sync grant (a
# passkey enrolled in the browser never reached its Advisor). Both were silent,
# and the documentation said the two paths were the same.
#
# So the sequence lives in one script and both paths call it. Four promises
# here, each of which fails quietly if it breaks:
#
#   1. The order is the order. The account move settles who owns the state
#      directory, so the trust sync follows it; the read-back is last because
#      everything before it is what it reads back.
#   2. Both entry points reach it. Asserted for the shared script directly and
#      for install.sh --with-advisor --yes, against the same stubs, with the
#      same expected sequence.
#   3. A second run does the same thing. Every step is idempotent on its own;
#      what is asserted here is that this script neither skips nor doubles one.
#   4. --shared-account is retired (ADR 0025): accepted, said, and the
#      account move runs anyway, on both entry points.
#
#   bash scripts/test-install-advisor-stack.sh
#
# Runs entirely in a temporary directory against fake curl, systemctl and
# sub-installers that record what they were called with. Touches no host and
# installs nothing.
#
# The steps it drives are root's, and install.sh refuses a non-root run of the
# roles that have an Advisor, so the rows need something that says EUID 0.
# Nothing here is actually privileged (every program it reaches is a stub in a
# temporary directory), so fakeroot is enough and is tried first; a runner with
# passwordless sudo is the fallback; already being root is the third. With none
# of the three this exits non-zero rather than passing quietly, because a row
# that silently does not run is the hole this file exists to close.

set -uo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SUT="$REPO_DIR/scripts/install-advisor-stack.sh"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

PASS=0 FAIL=0
ok()  { printf '  ok    %s\n' "$1"; PASS=$((PASS + 1)); }
bad() { printf '  FAIL  %s\n     %s\n' "$1" "$2"; FAIL=$((FAIL + 1)); }

[[ -f "$SUT" ]] || { echo "no install-advisor-stack.sh at $SUT"; exit 1; }

mkdir -p "$TMP/bin" "$TMP/state" "$TMP/op"
TREE="$TMP/op/aperire-one"

# ── How a row gets EUID 0 ───────────────────────────────────────────
ROOT_HOW=""
if [[ $EUID -eq 0 ]]; then
  ROOT_HOW=direct
elif command -v fakeroot >/dev/null 2>&1; then
  ROOT_HOW=fakeroot
elif sudo -n true 2>/dev/null; then
  ROOT_HOW=sudo
else
  cat >&2 <<EOF
error: this suite drives install.sh, which refuses a role that installs
       services unless EUID is 0. Nothing it runs is privileged — every
       program it reaches is a stub in a temporary directory — so any of
       these is enough:

         apt-get install -y fakeroot     (what CI uses)
         run this as root
         a host where 'sudo -n true' succeeds
EOF
  exit 1
fi

# env -i, so a row says only what it sets and this machine's environment
# reaches nothing. The fakes come first on PATH.
as_root() { # $@ = command and arguments
  local -a env_args=(
    PATH="$TMP/bin:/usr/bin:/bin" HOME="$TMP/op" TERM=dumb
  )
  case "$ROOT_HOW" in
    direct)   ( cd "$TMP" && env -i "${env_args[@]}" "$@" 2>&1 ) ;;
    fakeroot) ( cd "$TMP" && env -i "${env_args[@]}" fakeroot "$@" 2>&1 ) ;;
    sudo)     ( cd "$TMP" && sudo -n env -i "${env_args[@]}" "$@" 2>&1 ) ;;
  esac
}

# ── The install tree ────────────────────────────────────────────────
# Real: install.sh, the stack, the palette. Stubbed: everything either of them
# runs, each recording its own name into one ordered record.
make_tree() {
  rm -rf "$TREE"
  mkdir -p "$TREE/scripts" "$TREE/advisor/state" "$TREE/advisor/bin" \
           "$TREE/dashboard/config" "$TREE/dashboard/node_modules/tsx/dist"
  cp "$REPO_DIR/install.sh" "$TREE/install.sh"
  cp "$REPO_DIR/scripts/install-advisor-stack.sh" "$TREE/scripts/"
  cp "$REPO_DIR/scripts/term-style.sh" "$TREE/scripts/"
  # install.sh also sources the aggregator-origin rule, and refuses a tree
  # without it by name, so it sits beside term-style.sh here as it does there.
  cp "$REPO_DIR/scripts/fleet-origin.sh" "$TREE/scripts/"
  # Run as root from its own checkout, install.sh stages every script before
  # it runs one (#955), with these two. The record is pointed at nothing, the
  # way a fakeroot fixture has to: as root the library takes no variable.
  cp "$REPO_DIR/scripts/trusted-path-lib.sh" "$TREE/scripts/"
  sed "s#^RD_DIGESTS_DEFAULT=.*#RD_DIGESTS_DEFAULT=$TMP/no-record/release.sha256#" \
    "$REPO_DIR/scripts/release-digests-lib.sh" > "$TREE/scripts/release-digests-lib.sh"
  printf '#!/usr/bin/env bash\necho menu\n' > "$TREE/aperire-one"
  # What install.sh's prepare step has to have produced before it will go on.
  : > "$TREE/dashboard/node_modules/tsx/dist/cli.mjs"
  : > "$TREE/advisor/bin/aperire-advisord"; chmod +x "$TREE/advisor/bin/aperire-advisord"

  # One recorder for every stub, so the order is one file and not five.
  local name
  for name in install-advisord install-model-key-sealer install-trust-sync-grant \
              install-advisor-account prepare-host install-aperire-service \
              set-alert-role-defaults install-aperire-cli; do
    cat > "$TREE/scripts/$name.sh" <<EOF
#!/usr/bin/env bash
printf '%s\n' "$name \$*" >> "$TMP/state/calls"
printf '%s TTY=%s PORT=%s\n' "$name" "\$( [[ -t 0 ]] && echo yes || echo no )" \
  "\${APERIRE_ADVISOR_PORT:-unset}" >> "$TMP/state/env"
printf '%s NEXT=%s\n' "$name" "\${APERIRE_ADVISOR_ACCOUNT_NEXT:-unset}" >> "$TMP/state/env"
printf '%s INSTANCE=%s\n' "$name" "\${APERIRE_INSTANCE-unset}" >> "$TMP/state/env"
[[ -f "$TMP/state/$name-fails" ]] && { echo "  $name refused"; exit 1; }
exit 0
EOF
    chmod +x "$TREE/scripts/$name.sh"
  done

  cat > "$TREE/scripts/aperire-auth.sh" <<EOF
#!/usr/bin/env bash
printf '%s\n' "auth \$*" >> "$TMP/state/calls"
n="\$(cat "$TMP/state/sync-count" 2>/dev/null || echo 2)"
printf '  %s added, 0 replaced, 0 removed, %s trusted\n' "\$n" "\$n"
exit 0
EOF
  chmod +x "$TREE/scripts/aperire-auth.sh" "$TREE/aperire-one"
  printf 'tok-abc\n' > "$TREE/advisor/state/approve.token"
}

# ── Fakes on PATH ───────────────────────────────────────────────────
# curl: the read-back, and the same ordered record. install.sh's closing
# summary also curls /healthz, which is not part of the sequence and is told
# apart by its URL.
cat > "$TMP/bin/curl" <<EOF
#!/usr/bin/env bash
url=""
for a in "\$@"; do case "\$a" in http*) url="\$a" ;; esac; done
case "\$url" in
  *v1/status)
    printf '%s\n' "status \$url" >> "$TMP/state/calls"
    [[ "\$(cat "$TMP/state/status" 2>/dev/null)" == up ]] || exit 22
    echo '{"model":{"configured":false}}' ;;
  *) echo '{}' ;;
esac
EOF

cat > "$TMP/bin/systemctl" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >> "$TMP/state/systemctl-calls"
case "\$*" in
  *is-enabled*) [[ -f "$TMP/state/enabled" ]] && exit 0 || exit 1 ;;
  *is-active*)  [[ -f "$TMP/state/active"  ]] && exit 0 || exit 1 ;;
esac
exit 0
EOF
chmod +x "$TMP/bin/"*

healthy() {
  rm -f "$TMP/state/"*
  make_tree
  : > "$TMP/state/enabled"
  : > "$TMP/state/active"
  printf 'up\n' > "$TMP/state/status"
}

# The ordered record, one word per call, with install.sh's own steps dropped:
# what is being compared is the Advisor sequence, which is the same on both
# paths, and the steps around it are not.
sequence() {
  sed -E 's/ .*//' "$TMP/state/calls" 2>/dev/null \
    | grep -vxE 'prepare-host|install-aperire-service|set-alert-role-defaults|install-aperire-cli' \
    | tr '\n' ' '
}

EXPECTED='install-advisord install-model-key-sealer install-trust-sync-grant install-advisor-account auth status '

echo
echo "── the sequence, and why it is that sequence ──────────────────────"

healthy
out="$(as_root bash "$TREE/scripts/install-advisor-stack.sh" --dir "$TREE" --tries 2 --sleep 0)"
rc=$?
if [[ $rc -eq 0 ]]; then ok "the stack runs to the end on a host where every step works"
else bad "a healthy host runs to the end" "exit $rc: $(tail -5 <<<"$out")"; fi
if [[ "$(sequence)" == "$EXPECTED" ]]
then ok "service, sealer, trust grant, account, sync, read-back — in that order"
else bad "the whole sequence, in order" "got: $(sequence)"; fi

# The two orderings that are load-bearing, asserted as themselves so a
# reordering fails here with the reason attached rather than as one long string.
line_of() { grep -n "^$1" "$TMP/state/calls" | head -1 | cut -d: -f1; }
if [[ "$(line_of install-advisor-account)" -lt "$(line_of auth)" ]]
then ok "the sync follows the account move, which settles who owns the state directory"
else bad "the sync follows the account move" "$(cat "$TMP/state/calls")"; fi
if [[ "$(line_of auth)" -lt "$(line_of status)" ]]
then ok "and the read-back is last, because everything before it is what it reads back"
else bad "the read-back is last" "$(cat "$TMP/state/calls")"; fi

# The model ceremony install-advisord offers is CLI-only and needs a provider,
# a key and a choice. It must not open in the middle of a run nobody is
# watching, on either path.
if grep -q 'install-advisord TTY=no' "$TMP/state/env" 2>/dev/null
then ok "no sub-installer is given a terminal, so no CLI ceremony opens mid-run"
else bad "the sub-installers get no terminal" "$(cat "$TMP/state/env" 2>/dev/null)"; fi

# #893: the move onto the Advisor's own account comes right after the service
# install, so the service installer is told to write its unit naming that
# account and leave the start to the move. A unit naming the operator's login
# in between made root refuse every checked copy on a host whose login is in
# the docker group. Only the service installer is told.
if grep -q 'install-advisord NEXT=1' "$TMP/state/env" 2>/dev/null \
   && ! grep -E '^install-(model-key-sealer|trust-sync-grant|advisor-account) NEXT=1' "$TMP/state/env" >/dev/null
then ok "the service installer is told the account move follows, and nothing else is"
else bad "the service installer is told the account move follows" "$(grep NEXT "$TMP/state/env" 2>/dev/null)"; fi

# #949: the sealer is told which instance it is installing for. It reads that
# instance's wrapper configuration to stamp the node key, and without the
# name it read the default node's. A host with no instance says so too.
if grep -qx 'install-model-key-sealer INSTANCE=' "$TMP/state/env" 2>/dev/null
then ok "on the default layout the sealer is told there is no instance"
else bad "the sealer is told the (empty) instance" "$(grep INSTANCE "$TMP/state/env" 2>/dev/null)"; fi
healthy
: > "$TMP/state/env"
as_root bash "$TREE/scripts/install-advisor-stack.sh" --dir "$TREE" --instance node2 --tries 2 --sleep 0 >/dev/null 2>&1
if grep -qx 'install-model-key-sealer INSTANCE=node2' "$TMP/state/env" 2>/dev/null
then ok "and with --instance node2 the sealer is told node2, so it stamps that instance's node"
else bad "the sealer is told the instance (#949)" "$(grep INSTANCE "$TMP/state/env" 2>/dev/null)"; fi

# A move that did not finish on a host whose Advisor was never started says
# so, rather than claiming it is still running as the operator.
healthy
rm -f "$TMP/state/active"
: > "$TMP/state/install-advisor-account-fails"
out="$(as_root bash "$TREE/scripts/install-advisor-stack.sh" --dir "$TREE" --tries 2 --sleep 0)"
if grep -q 'installed but not started' <<<"$out" && ! grep -q 'still running as' <<<"$out"
then ok "a refused move on an Advisor that never started says it is not started, not that it still runs as the operator"
else bad "a never-started Advisor is not reported as running" "$(grep -E 'running|started' <<<"$out")"; fi
healthy

echo
echo "── a second run does the same thing, once ─────────────────────────"

# Idempotence of the STEPS is each installer's own promise, held by their own
# suites (test-seal-model-key.sh, test-trust-sync.sh). What is asserted here is
# this script's part of it: on a host where everything is already installed it
# neither skips a step nor runs one twice.
healthy
as_root bash "$TREE/scripts/install-advisor-stack.sh" --dir "$TREE" --tries 2 --sleep 0 >/dev/null
first="$(sequence)"
: > "$TMP/state/calls"
as_root bash "$TREE/scripts/install-advisor-stack.sh" --dir "$TREE" --tries 2 --sleep 0 >/dev/null
if [[ "$(sequence)" == "$first" ]]
then ok "a second run over the same host runs the same steps in the same order"
else bad "a second run is the same run" "first: $first  second: $(sequence)"; fi
if [[ "$(grep -c '^install-model-key-sealer' "$TMP/state/calls")" -eq 1 \
   && "$(grep -c '^install-advisor-account' "$TMP/state/calls")" -eq 1 ]]
then ok "and each installer is called exactly once, so nothing is armed or moved twice"
else bad "one call per installer per run" "$(cat "$TMP/state/calls")"; fi

# The one thing a second run must NOT do: re-sync a trust store that already
# holds keys. On a fleet node those came from an issuer's signed bundle.
healthy
printf '{"credentials":[{"credential_id":"abc"}]}\n' > "$TREE/advisor/state/credentials.json"
out="$(as_root bash "$TREE/scripts/install-advisor-stack.sh" --dir "$TREE" --tries 2 --sleep 0)"
if ! grep -q '^auth ' "$TMP/state/calls" && grep -q 'already trusts 1 passkey' <<<"$out"
then ok "a trust store that already holds keys is left exactly alone, and named"
else bad "an existing trust store is not rebuilt" "$(cat "$TMP/state/calls")"; fi

echo
echo "── --shared-account is retired, and the move runs anyway (ADR 0025) ──"

healthy
out="$(as_root bash "$TREE/scripts/install-advisor-stack.sh" --dir "$TREE" --shared-account --tries 2 --sleep 0)"
if [[ "$(sequence)" == "$EXPECTED" ]]
then ok "--shared-account no longer skips the account move: every step runs"
else bad "--shared-account is retired" "got: $(sequence)"; fi
if grep -q -- '--shared-account is retired' <<<"$out"
then ok "and it says the flag was retired, rather than ignoring it silently"
else bad "the retired flag is named" "$(tail -6 <<<"$out")"; fi

echo
echo "── what a failed step costs, and what it does not ─────────────────"

# The grants are degradations: an Advisor with no browser grant still reads,
# plans and answers. A refused account move does not stop the run either, the
# sync and the read-back still happen, but the run ends 3, not 0: an Advisor
# left on the dashboard's account is the retired arrangement on every host
# shape, an aggregator included (#806).
healthy
: > "$TMP/state/install-model-key-sealer-fails"
out="$(as_root bash "$TREE/scripts/install-advisor-stack.sh" --dir "$TREE" --tries 2 --sleep 0)"
rc=$?
if [[ $rc -eq 0 ]] && grep -q '^auth ' "$TMP/state/calls"
then ok "a refused grant does not stop the run, and the run still ends 0"
else bad "a refused grant is a degradation" "exit $rc: $(cat "$TMP/state/calls")"; fi

healthy
: > "$TMP/state/install-model-key-sealer-fails"
: > "$TMP/state/install-advisor-account-fails"
out="$(as_root bash "$TREE/scripts/install-advisor-stack.sh" --dir "$TREE" --report "$TMP/state/report" --tries 2 --sleep 0)"
rc=$?
if [[ $rc -eq 3 ]] && grep -q '^auth ' "$TMP/state/calls" && grep -q '^status' "$TMP/state/calls"
then ok "a refused account move still runs the sync and the read-back, and ends 3, never 0"
else bad "a refused account move ends 3 after the read-back" "exit $rc: $(cat "$TMP/state/calls")"; fi
# The closing block is the last thing printed, so it is not buried under the
# sync and the status lines, and it names the step that fixes it.
if tail -9 <<<"$out" | grep -q 'NOT on its own account' && tail -9 <<<"$out" | grep -q 'get.aperire.one | bash -s -- --update --force'
then ok "and it closes on an amber block naming the update that offers the move"
else bad "the refused move closes the run, named" "$(tail -8 <<<"$out")"; fi
if grep -q 'the browser model step is not available' <<<"$out" \
   && grep -q 'still running as' <<<"$out"
then ok "and both are named where they happened"
else bad "the degradations are named" "$(tail -12 <<<"$out")"; fi
if grep -qx 'sealer_ready=0' "$TMP/state/report" && grep -qx 'account_moved=0' "$TMP/state/report"
then ok "and the report says so, which is what the closing text reads"
else bad "the report records what failed" "$(cat "$TMP/state/report" 2>/dev/null)"; fi
# Root writes this file, and all three callers read it back as the OPERATOR to
# print their closing text. A host whose root umask is 077 would leave it
# unreadable there, the readback would fail closed, and a host whose browser
# could seal perfectly would be sent to the terminal instead. Nothing secret is
# in it: three outcomes, a path and a port.
if [[ "$(stat -c %a "$TMP/state/report" 2>/dev/null)" == 644 ]]
then ok "and the operator's account can read it back, whatever root's umask is"
else bad "the report is readable by the account that prints from it" \
         "mode $(stat -c %a "$TMP/state/report" 2>/dev/null)"; fi

# The service is not a degradation: there is no Advisor without it, and
# nothing after it can work.
healthy
: > "$TMP/state/install-advisord-fails"
out="$(as_root bash "$TREE/scripts/install-advisor-stack.sh" --dir "$TREE" --tries 2 --sleep 0)"; rc=$?
if [[ $rc -ne 0 ]] && [[ "$(sequence)" == 'install-advisord ' ]]
then ok "the service installer failing stops the run before anything else is tried"
else bad "a failed service install is fatal" "exit $rc: $(sequence)"; fi

# Nor is the read-back. Everything is installed; what is refused is the claim.
healthy
printf 'down\n' > "$TMP/state/status"
out="$(as_root bash "$TREE/scripts/install-advisor-stack.sh" --dir "$TREE" --report "$TMP/state/report" --tries 2 --sleep 0)"; rc=$?
if [[ $rc -ne 0 ]] && grep -q 'did not answer on' <<<"$out"
then ok "a service that never answers is refused, with the journal to read"
else bad "a silent service is refused" "exit $rc: $(tail -4 <<<"$out")"; fi
if grep -qx 'answering=0' "$TMP/state/report"
then ok "and nothing downstream can read that host as answering"
else bad "the report records the silence" "$(cat "$TMP/state/report" 2>/dev/null)"; fi

echo
echo "── --grants-only, for a window that lapsed ────────────────────────"

# The one-line install re-run on a host whose Advisor is answering but has no
# model. It must open a fresh window without rebuilding a service that works
# or moving an account that is already moved.
healthy
out="$(as_root bash "$TREE/scripts/install-advisor-stack.sh" --dir "$TREE" --grants-only)"; rc=$?
if [[ $rc -eq 0 ]] && [[ "$(sequence)" == 'install-model-key-sealer install-trust-sync-grant auth ' ]]
then ok "both grants and the sync, and nothing built, moved or read back"
else bad "--grants-only is the two grants and the sync" "exit $rc: $(sequence)"; fi
if grep -q 'install-model-key-sealer --arm' "$TMP/state/calls"
then ok "and the sealer is armed, which is the point of running it again"
else bad "the sealer is armed" "$(cat "$TMP/state/calls")"; fi

echo
echo "── the closing text, printed from one place ───────────────────────"

# Fail-closed. A report that is missing, or one whose sealer never armed, must
# not send an operator to a browser panel that cannot seal for them.
healthy
printf 'sealer_ready=1\n' > "$TMP/state/report"
out="$(as_root bash "$TREE/scripts/install-advisor-stack.sh" --model-steps --dir "$TREE" --report "$TMP/state/report")"
if grep -q 'Set one up in your browser' <<<"$out" && grep -q 'Advisor AI model' <<<"$out"
then ok "an armed sealer prints the four browser steps"
else bad "the browser steps print when armed" "$out"; fi
out="$(as_root bash "$TREE/scripts/install-advisor-stack.sh" --model-steps --dir "$TREE" --report "$TMP/state/nothing-here")"
if ! grep -q 'Set one up in your browser' <<<"$out" && grep -q " bash $TREE/aperire-one" <<<"$out" && ! grep -q "sudo bash $TREE/aperire-one" <<<"$out"
then ok "a report that is not there reads as not armed, and names the terminal instead"
else bad "a missing report fails closed" "$out"; fi

echo
echo "── an argument that is not one is named ───────────────────────────"

# Both reach a place where the value is used and not read: the port goes into
# a URL, the sleep goes into `sleep` inside the read-back loop. A refusal that
# names the flag is the difference between a fixable mistake and a run that
# ends on a complaint about a word nothing on screen explains.
healthy
out="$(as_root bash "$TREE/scripts/install-advisor-stack.sh" --dir "$TREE" --port 99999)"; rc=$?
if [[ $rc -ne 0 ]] && grep -q 'takes a number from 1 to 65535' <<<"$out"
then ok "a port outside the range is refused before anything is installed"
else bad "a bad port is refused" "exit $rc: $out"; fi
out="$(as_root bash "$TREE/scripts/install-advisor-stack.sh" --dir "$TREE" --sleep soon)"; rc=$?
if [[ $rc -ne 0 ]] && grep -q "\-\-sleep takes a number of seconds" <<<"$out"
then ok "and a sleep that is not a number is named where the mistake is"
else bad "a bad --sleep is refused" "exit $rc: $out"; fi
if [[ -z "$(sequence)" ]]
then ok "neither of those installs anything on the way to refusing"
else bad "a refused argument installs nothing" "$(sequence)"; fi

echo
# install.sh runs the host checklist as step zero (scripts/preflight.sh) and
# this suite hands it a tree of fakes on a host it must not measure, so
# every drive below passes --no-preflight; the checklist has its own suite.
echo "── install.sh --with-advisor reaches the same script ──────────────"

# The defect, from the other end. This is the path that ran two of the five
# steps and said nothing about the three it had not.
healthy
out="$(as_root bash "$TREE/install.sh" --role=dashboard --no-preflight --with-advisor --yes)"; rc=$?
if [[ "$(sequence)" == "$EXPECTED" ]]
then ok "install.sh --with-advisor runs the same sequence as the one-line install"
else bad "install.sh reaches the stack" "exit $rc: $(sequence)"; fi
if grep -q 'install-advisor-stack.sh' <<<"$out"
then ok "and its plan names the script it is about to run"
else bad "the plan names the stack" "$(sed -n '/Will run/,/^$/p' <<<"$out")"; fi
if grep -q 'Set one up in your browser' <<<"$out" \
   && grep -q 'Open .*Advisor AI model' <<<"$out"
then ok "and its closing text ends where the one-line install ends: the four browser steps"
else bad "install.sh prints the four browser steps" "$(tail -20 <<<"$out")"; fi
if grep -q 'create your operator and enroll the passkey first' <<<"$out"
then ok "with the one thing only this path has to say: the model comes after enrolling"
else bad "the ordering against enrollment is named" "$(tail -20 <<<"$out")"; fi

# --advisor-shared-account, all the way through: retired, so the Advisor
# still gets its own account, and the plan says the flag did nothing.
healthy
out="$(as_root bash "$TREE/install.sh" --role=dashboard --no-preflight --with-advisor --advisor-shared-account --yes)"
if [[ "$(sequence)" == "$EXPECTED" ]] && grep -q 'retired and was ignored' <<<"$out"
then ok "--advisor-shared-account is accepted, named as retired, and the account move still runs"
else bad "the retired install.sh flag" "got: $(sequence)"; fi

# The negative control that gives every row above its meaning: without
# --with-advisor, nothing in the sequence runs at all.
healthy
as_root bash "$TREE/install.sh" --role=dashboard --no-preflight --yes >/dev/null
if [[ -z "$(sequence)" ]]
then ok "and without the flag none of it runs, which is what makes the Advisor optional"
else bad "no advisor step without the flag" "got: $(sequence)"; fi

# A host where the Advisor step fails must not reach a closing text that sends
# the operator to a browser panel it never installed.
healthy
: > "$TMP/state/install-advisord-fails"
out="$(as_root bash "$TREE/install.sh" --role=dashboard --no-preflight --with-advisor --yes)"; rc=$?
if [[ $rc -eq 0 ]]; then ok "an Advisor step that fails does not take the whole install with it"
else bad "the Advisor step is tolerated" "exit $rc: $(tail -6 <<<"$out")"; fi
if grep -q 'the Advisor did not finish' <<<"$out" && ! grep -q 'Set one up in your browser' <<<"$out"
then ok "and the closing text says so instead of naming a step that cannot work"
else bad "a failed Advisor step is named, not papered over" "$(tail -20 <<<"$out")"; fi

echo
printf '  %d passed, %d failed  (root via %s)\n\n' "$PASS" "$FAIL" "$ROOT_HOW"
[[ $FAIL -eq 0 ]]
