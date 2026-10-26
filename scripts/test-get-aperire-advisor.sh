#!/usr/bin/env bash
# Exercise scripts/get-aperire-advisor.sh, the bootstrap behind the one-line
# Advisor install.
#
# What is being protected: this is the script an operator runs by pasting a URL
# into a root-capable shell on a box that already matters. Four of its promises
# fail silently if they break.
#
#   1. A half-delivered copy must not run. `curl | bash` executes what has
#      arrived as it arrives, so a connection cut mid-download runs the top
#      half of an installer and stops. Every check here has its opposite
#      beside it, because "nothing happened" is also what a test proves when
#      the script never ran at all.
#   2. The refusal must be a refusal. The Advisor is an add-on: on a box with
#      no Aperire One install this script has to stop and say so, and it must
#      not fetch a release to make itself installable. Asserted both ways: a
#      bare box refuses and installs nothing, and a box with a checkout runs
#      the installers.
#   3. It must find the install the RUNNING dashboard uses, not a directory
#      with a familiar name. The unit's WorkingDirectory is the only answer
#      that cannot be wrong, and a second checkout beside it is the case that
#      tells the two apart.
#   4. The closing banner must mean something. It prints after the service was
#      read back as enabled, running and answering, never instead of it, so
#      each of those three is asserted in both directions.
#
#   bash scripts/test-get-aperire-advisor.sh
#
# Runs entirely in a temporary directory against fake curl, sudo and systemctl
# on PATH, and a fake install tree whose installers record what they were
# called with. Touches no host, needs no root, and installs nothing.

set -uo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SUT="$REPO_DIR/scripts/get-aperire-advisor.sh"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

PASS=0 FAIL=0
ok()  { printf '  ok    %s\n' "$1"; PASS=$((PASS + 1)); }
bad() { printf '  FAIL  %s\n     %s\n' "$1" "$2"; FAIL=$((FAIL + 1)); }

[[ -f "$SUT" ]] || { echo "no get-aperire-advisor.sh at $SUT"; exit 1; }

# The operator's home in this fixture is "op", not "home": the docs gate in CI
# greps every shipped script for a literal /home/<name>/ path, and a fake one
# in a test would fail it exactly like a real one.
mkdir -p "$TMP/bin" "$TMP/state" "$TMP/op"
# Root's own copies of the two checking libraries (#764): the bootstrap
# stages what root runs out of the install with them, never with the tree's.
mkdir -p "$TMP/rootlib"
cp "$REPO_DIR/scripts/release-digests-lib.sh" "$REPO_DIR/scripts/trusted-path-lib.sh" "$TMP/rootlib/"
chmod 0755 "$TMP/rootlib"; chmod 0644 "$TMP/rootlib/"*

# ── The fake install ────────────────────────────────────────────────
# A directory that satisfies looks_like_an_install, whose two installers record
# their arguments and do the one thing the verification later reads: they
# register the unit and write the approval token the status check presents.
make_install() { # $1 = directory
  local d="$1"
  mkdir -p "$d/scripts" "$d/advisor/state"
  # The real one, not a fake: the replant's whole point (#661) is that the
  # window is planted on a descriptor, and a stub would assert nothing about
  # the owner, group and mode the rows below read back.
  cp "$REPO_DIR/scripts/state-file.py" "$d/scripts/"
  printf '#!/usr/bin/env bash\necho menu\n' > "$d/aperire-one"
  # Every real install has one, and root stages the install only when it does.
  printf '#!/usr/bin/env bash\necho install\n' > "$d/install.sh"
  cat > "$d/scripts/install-advisord.sh" <<EOF
#!/usr/bin/env bash
printf '%s\n' "advisord \$*" >> "$TMP/state/install-args"
printf 'binaries=%s\n' "\$( [[ -x "$d/advisor/bin/aperire-advisord" ]] && echo yes || echo no )" \
  >> "$TMP/state/advisord-env"
printf 'PORT=%s TTY=%s\n' "\${APERIRE_ADVISOR_PORT:-unset}" "\$( [[ -t 0 ]] && echo yes || echo no )" \
  >> "$TMP/state/advisord-env"
[[ -f "$TMP/state/advisord-fails" ]] && exit 1
printf 'aperire-advisord.service enabled\n' >> "$TMP/state/units"
printf 'tok-abc\n' > "$d/advisor/state/approve.token"
echo "  advisord installed"
exit 0
EOF
  cat > "$d/scripts/prepare-host.sh" <<EOF
#!/usr/bin/env bash
printf '%s\n' "prepare role=\${APERIRE_ROLE:-unset} advisor=\${APERIRE_WITH_ADVISOR:-unset}" >> "$TMP/state/install-args"
[[ -f "$TMP/state/prepare-fails" ]] && { echo "no toolchain" >&2; exit 1; }
mkdir -p "$d/advisor/bin"
if [[ -x "$d/advisor/bin/aperire-advisord" ]]; then
  echo "  advisor/bin/* are newer than their sources"
else
  : > "$d/advisor/bin/aperire-advisord"; chmod +x "$d/advisor/bin/aperire-advisord"
  : > "$d/advisor/bin/aperire-executor";  chmod +x "$d/advisor/bin/aperire-executor"
  echo "  built: advisor/bin/aperire-advisord, advisor/bin/aperire-executor"
fi
exit 0
EOF
  # Records whether the wrapper's configuration was on disk when it ran: the
  # real sealer reads the node's admin address out of that file (#935). When a
  # row asks (state/real-nodekey-block), it also runs the real sealer's own
  # node-key code, cut out of the shipped script, so what it prints is what the
  # operator would read and not a restatement of it.
  cat > "$d/scripts/install-model-key-sealer.sh" <<EOF
#!/usr/bin/env bash
printf '%s\n' "sealer \$*" >> "$TMP/state/install-args"
[[ -f "$TMP/state/sealer-fails" ]] && { echo "no dashboard unit" >&2; exit 1; }
printf 'conf=%s\n' "\$( [[ -e "$TMP/wrapper/node-wrapper.conf" ]] && echo yes || echo no )" >> "$TMP/state/sealer-saw"
if [[ -f "$TMP/state/real-nodekey-block" ]]; then
  say() { printf '   %s\n' "\$*"; }
  curl() { [[ -f "$TMP/state/node-answers" ]] && cat "$TMP/state/node-answers"; }
  stamp_node_key() { mkdir -p "\$(dirname "\$NODE_KEY_FILE")"; printf '%s\n' "\$1" > "\$NODE_KEY_FILE"; }
  NODE_KEY="" WCONF="$TMP/wrapper/node-wrapper.conf" NODE_KEY_FILE="$TMP/etcnk/node-key" REPO="$d" FLEET_ARM_PUB="$TMP/etcnk/fleet-arm.pub" FLEET_ARM_HELD="$TMP/etcnk/fleet-arm.paired.pub"
  . "$TMP/nodekey-block.sh"
fi
echo "  the dashboard may seal one key"
exit 0
EOF
  cat > "$d/scripts/install-trust-sync-grant.sh" <<EOF
#!/usr/bin/env bash
printf '%s\n' "trust-grant \$*" >> "$TMP/state/install-args"
[[ -f "$TMP/state/grant-fails" ]] && { echo "no dashboard unit" >&2; exit 1; }
echo "  a passkey enrolled in the browser now reaches the Advisor by itself"
exit 0
EOF
  # The trust sync, as the bootstrap calls it. It reports its own count, and
  # the rows below read the count out of the bootstrap's output rather than
  # recounting anything: two answers to "who may approve" is one too many.
  cat > "$d/scripts/aperire-auth.sh" <<EOF
#!/usr/bin/env bash
printf '%s\n' "auth \$*" >> "$TMP/state/install-args"
[[ -f "$TMP/state/sync-fails" ]] && { echo "no public_url in authn.yaml" >&2; exit 1; }
n="\$(cat "$TMP/state/sync-count" 2>/dev/null || echo 1)"
printf '  %s added, 0 replaced, 0 removed, %s trusted\n' "\$n" "\$n"
exit 0
EOF
  # The wrapper installer, as the bootstrap's repair runs it (#917). It
  # records what it was given and the tree it was told, and writes the
  # configuration the fixture's wrapper reads.
  cat > "$d/scripts/install-node-wrapper.sh" <<EOF
#!/usr/bin/env bash
printf '%s\n' "wrapper \$* tree=\${APERIRE_INSTALL_TREE:-unset} instance=\${APERIRE_INSTANCE:-} self=\$(dirname "\$0")" >> "$TMP/state/install-args"
[[ -f "$TMP/state/wrapper-install-fails" ]] && { echo "no docker" >&2; exit 1; }
printf 'KIND=container\nADMIN_RPC=http://127.0.0.1:5005\n' > "$TMP/wrapper/node-wrapper.conf"
echo "  wrapper configured"
exit 0
EOF
  cat > "$d/scripts/install-advisor-account.sh" <<EOF
#!/usr/bin/env bash
printf '%s\n' "account \$*" >> "$TMP/state/install-args"
[[ -f "$TMP/state/account-fails" ]] && { echo "no wrapper configuration" >&2; exit 1; }
echo "  moved onto its own account"
exit 0
EOF
  chmod +x "$d/aperire-one" "$d/scripts/install-advisord.sh" "$d/scripts/prepare-host.sh" \
           "$d/scripts/install-advisor-account.sh" "$d/scripts/install-model-key-sealer.sh" \
           "$d/scripts/install-node-wrapper.sh" \
           "$d/scripts/install-trust-sync-grant.sh" "$d/scripts/aperire-auth.sh"
  # The one script that is NOT a stub. The bootstrap does not run the five
  # installers above itself any more: it runs the stack, and the stack runs
  # them. Stubbing the stack would leave every row below asserting a fixture.
  cp "$REPO_DIR/scripts/install-advisor-stack.sh" "$d/scripts/install-advisor-stack.sh"
  cp "$REPO_DIR/scripts/term-style.sh" "$d/scripts/term-style.sh"
  # What an instance's wrapper paths are derived from (#917).
  cp "$REPO_DIR/scripts/trusted-path-lib.sh" "$d/scripts/trusted-path-lib.sh"
}
# The wrapper the bootstrap reads and asks for its status. Configured and
# answering unless a row says otherwise, so every older row meets a host with
# nothing to repair; reset_state puts that back.
mkdir -p "$TMP/wrapper"
cat > "$TMP/wrapper/aperire-node-wrapper" <<EOF
#!/usr/bin/env bash
[[ -f "$TMP/state/wrapper-status-fails" ]] && exit 1
exit 0
EOF
chmod 0755 "$TMP/wrapper/aperire-node-wrapper"
make_install "$TMP/op/aperire-one"

# A second checkout, complete and plausible, that the running dashboard is NOT
# using. Row 3's whole point: a directory with the right shape is not evidence.
make_install "$TMP/op/other-checkout"

# ── Fakes on PATH ───────────────────────────────────────────────────
# curl: two callers, told apart by -o. With -o it is the script fetching
# itself (state/self decides what arrives); without, it is the /v1/status
# check (state/status decides whether it answers).
cat > "$TMP/bin/curl" <<EOF
#!/usr/bin/env bash
out=""; url=""
while [[ \$# -gt 0 ]]; do
  case "\$1" in
    -o) out="\$2"; shift 2 ;;
    http*) url="\$1"; shift ;;
    *) shift ;;
  esac
done
if [[ -n "\$out" ]]; then
  printf '%s\n' "self-fetch \$url" >> "$TMP/state/curl-calls"
  [[ -f "$TMP/state/self" ]] || exit 22
  cp "$TMP/state/self" "\$out"; exit 0
fi
printf '%s\n' "\$url" >> "$TMP/state/curl-calls"
# The read-back, in the same ordered record as the installers, for the one
# section that asserts where in the sequence it falls. Off by default: rows
# that assert "no installer ran at all" read that record for emptiness.
[[ -f "$TMP/state/log-status" ]] && printf '%s\n' "status \$url" >> "$TMP/state/install-args"
[[ "\$(cat "$TMP/state/status" 2>/dev/null)" == up ]] || exit 22
if [[ -f "$TMP/state/has-model" ]]; then
  echo '{"model":{"configured":true,"model":"grok-4"}}'
else
  echo '{"model":{"configured":false}}'
fi
EOF

# sudo: drop its own flags and run the rest here, so what the bootstrap asks
# root to do is observable. Real sudo resets the environment (`Defaults
# env_reset` keeps TERM and drops NO_COLOR), so this one does too: a fake that
# passed NO_COLOR through would say the bootstrap carries it across the
# boundary when nothing is carrying it at all.
cat > "$TMP/bin/sudo" <<EOF
#!/usr/bin/env bash
while [[ \$# -gt 0 ]]; do
  case "\$1" in
    -H|-E) shift ;;
    -n) shift
        if [[ -f "$TMP/state/sudo-n-denied" ]]; then
          echo "sudo: a password is required" >&2
          exit 1
        fi
        [[ "\${1:-}" == "true" ]] && exit 0
        ;;
    -v) exit 0 ;;
    -u) shift 2 ;;
    *) break ;;
  esac
done
[[ \$# -eq 0 ]] && exit 0
printf '%s\n' "\$*" >> "$TMP/state/sudo-exec"
# env_reset, as the real one does it: only an allow-list crosses. HOME and
# TERM and PATH are what sudo keeps; the two APERIRE_ names are what the
# fixture's root side reads (the release record and the staged libraries'
# home), listed here so nothing else can leak across by accident.
exec env -i PATH="\$PATH" HOME="\${HOME:-}" TERM="\${TERM:-dumb}" \
  \${APERIRE_RELEASE_DIGESTS:+APERIRE_RELEASE_DIGESTS="\$APERIRE_RELEASE_DIGESTS"} \
  "\$@"
EOF

# systemctl: every reading the bootstrap takes comes from a state file, so a
# row can put the host in any of the states this script has to tell apart.
#   state/workdir      what the dashboard unit reports as WorkingDirectory
#   state/units        which unit files exist
#   state/enabled      is-enabled answers yes
#   state/active       is-active answers yes
cat > "$TMP/bin/systemctl" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >> "$TMP/state/systemctl-calls"
case "\$*" in
  *"show -p WorkingDirectory"*)
    cat "$TMP/state/workdir" 2>/dev/null; exit 0 ;;
  *list-unit-files*)
    pat="\${*: -1}"; pat="\${pat%.service}"; pat="\${pat%\\*}"
    grep -F -e "\$pat" "$TMP/state/units" 2>/dev/null; exit 0 ;;
  *is-enabled*)
    [[ -f "$TMP/state/enabled" ]] && exit 0 || exit 1 ;;
  *is-active*)
    [[ -f "$TMP/state/active" ]] && exit 0 || exit 1 ;;
  --version)
    printf 'systemd %s (%s)\n' "\$(cat "$TMP/state/systemd-version" 2>/dev/null || echo 255)" "fake"; exit 0 ;;
esac
exit 0
EOF

# docker: what `docker ps` lists comes from a state file, so a row can say
# what runs on the host without this machine's own docker being asked
# (#1129). An absent file is a host running nothing; state/docker-fails is a
# docker that is installed and will not answer.
cat > "$TMP/bin/docker" <<EOF
#!/usr/bin/env bash
[[ -f "$TMP/state/docker-fails" ]] && { echo "Cannot connect to the Docker daemon" >&2; exit 1; }
[[ "\$1" == ps ]] && cat "$TMP/state/docker-ps" 2>/dev/null
exit 0
EOF

chmod +x "$TMP/bin/"*

# ── The run harness ─────────────────────────────────────────────────
# One place that decides the environment, so a row says only what it changes.
# HOME and the operator's home are the fixture's, never this machine's.
# The home a row runs with. Overridable, because "this host has no install
# anywhere" needs a home with nothing in it, and env -i means a prefix
# assignment on the caller would be dropped rather than take effect.
RUN_HOME="$TMP/op"

run_sut() { # remaining args are passed to the script
  ( cd "$TMP" && env -i \
      PATH="$TMP/bin:/usr/bin:/bin" \
      HOME="$RUN_HOME" \
      TERM=dumb \
      APERIRE_ADVISOR_GET_SELF_URL="https://example.invalid/advisor" \
      APERIRE_ADVISOR_GET_TRIES=2 \
      APERIRE_ADVISOR_GET_SLEEP=0 \
      APERIRE_ADVISOR_GET_ROOT_LIB_DIR="$TMP/rootlib" \
      APERIRE_ADVISOR_GET_WRAPPER_CONF="$TMP/wrapper/node-wrapper.conf" \
      APERIRE_ADVISOR_GET_WRAPPER_BIN="$TMP/wrapper/aperire-node-wrapper" \
      APERIRE_ADVISOR_GET_NODE_CONF="$TMP/etc-node.conf" \
      APERIRE_RELEASE_DIGESTS="$TMP/no-release-record" \
      ${APERIRE_ADVISOR_GET_DIR:+APERIRE_ADVISOR_GET_DIR="$APERIRE_ADVISOR_GET_DIR"} \
      bash "$SUT" "$@" 2>&1 )
}

reset_state() {
  RUN_HOME="$TMP/op"
  rm -f "$TMP/state/"*
  printf 'KIND=container\n' > "$TMP/wrapper/node-wrapper.conf"
  # This host runs a node, as every row before #1129 assumed.
  printf 'SERVICE=aperire-node\n' > "$TMP/etc-node.conf"
  # A build from an earlier row would make the next one look already-built.
  rm -rf "$TMP/op/aperire-one/advisor/bin" "$TMP/op/other-checkout/advisor/bin"
  : > "$TMP/state/units"
  printf '%s\n' "$TMP/op/aperire-one/dashboard" > "$TMP/state/workdir"
}

# A healthy install: the two installers ran, the unit is enabled and active,
# and /v1/status answers. Rows that want a failure switch one of these off.
healthy() {
  reset_state
  : > "$TMP/state/enabled"
  : > "$TMP/state/active"
  printf 'up\n' > "$TMP/state/status"
}

echo
echo "── the refusal: the Advisor is an add-on ──────────────────────────"

# A box with no install at all. Both directions: it must refuse, AND it must
# not have run an installer or fetched anything on the way to refusing.
reset_state
: > "$TMP/state/workdir"
RUN_HOME="$TMP/nobody"
out="$(run_sut --yes)"; rc=$?
if [[ $rc -ne 0 ]]; then ok "a box with no Aperire One install refuses"
else bad "a box with no Aperire One install refuses" "exit $rc"; fi
if grep -q 'no Aperire One install on this host' <<<"$out"
then ok "the refusal names what is missing, not what failed"
else bad "the refusal names what is missing" "$(tail -3 <<<"$out")"; fi
if grep -q 'get.aperire.one | bash' <<<"$out"
then ok "and names the command that fixes it"
else bad "names the command that fixes it" "$(tail -5 <<<"$out")"; fi
# The negative control for row 2 of the header. A refusal that had already
# installed something would still print the same words.
if [[ ! -f "$TMP/state/install-args" ]]
then ok "and it ran no installer on the way to refusing"
else bad "ran no installer while refusing" "$(cat "$TMP/state/install-args")"; fi

# The opposite: the same script, the same flags, on a box that HAS one.
healthy
out="$(run_sut --yes)"; rc=$?
if [[ $rc -eq 0 ]]; then ok "a box with an install proceeds (the refusal is not unconditional)"
else bad "a box with an install proceeds" "exit $rc: $(tail -3 <<<"$out")"; fi

# --dir naming a directory that is not one. The check is two files, because
# either alone is something else: a saved copy of the menu, or any repository.
healthy
mkdir -p "$TMP/op/not-an-install"
out="$(run_sut --yes --dir "$TMP/op/not-an-install")"; rc=$?
if [[ $rc -ne 0 ]] && grep -q 'is not an Aperire One install' <<<"$out"
then ok "--dir at a directory that is not an install is refused by name"
else bad "--dir at a non-install is refused" "exit $rc: $(tail -2 <<<"$out")"; fi

echo
echo "── finding the install the RUNNING dashboard uses ─────────────────"

healthy
out="$(run_sut --yes)"
if grep -q "for        $TMP/op/aperire-one " <<<"$out"
then ok "the install comes from the dashboard unit's WorkingDirectory"
else bad "the install comes from the unit" "$(grep -F 'for  ' <<<"$out")"; fi
if grep -q 'from the installed dashboard unit' <<<"$out"
then ok "and the plan says that is where it came from"
else bad "the plan names the evidence" "$(tail -5 <<<"$out")"; fi

# The unit points at the OTHER checkout. A script that guessed from $HOME
# would attach the Advisor to a tree the running dashboard does not use, and
# both directories exist and both look right, so only the unit tells them apart.
healthy
printf '%s\n' "$TMP/op/other-checkout/dashboard" > "$TMP/state/workdir"
out="$(run_sut --yes)"
if grep -q "for        $TMP/op/other-checkout " <<<"$out"
then ok "a second plausible checkout does not win over the running unit"
else bad "the running unit wins over a lookalike" "$(grep -F 'for  ' <<<"$out")"; fi

# No unit at all, but the release is unpacked at the default location. A
# guess, and it says so.
healthy
: > "$TMP/state/workdir"
out="$(run_sut --yes)"
if grep -q 'no dashboard unit named one' <<<"$out"
then ok "with no dashboard unit the default location is named as a guess"
else bad "the default location is named as a guess" "$(tail -5 <<<"$out")"; fi

echo
echo "── what it hands to the installers ────────────────────────────────"

healthy
out="$(run_sut --yes --port 7899)"
if grep -q '^advisord ' "$TMP/state/install-args" 2>/dev/null \
   && grep -q '^account ' "$TMP/state/install-args" 2>/dev/null
then ok "both installers run, which is the fleet baseline in one command"
else bad "both installers run" "$(cat "$TMP/state/install-args" 2>/dev/null)"; fi
if [[ "$(grep -n '^advisord ' "$TMP/state/install-args" | cut -d: -f1)" -lt \
      "$(grep -n '^account ' "$TMP/state/install-args" | cut -d: -f1)" ]]
then ok "advisord before the account move (the build is ahead of both now)"
else bad "advisord runs before the account move" "$(cat "$TMP/state/install-args")"; fi
if grep -q 'PORT=7899' "$TMP/state/advisord-env" 2>/dev/null
then ok "the port it was given is the port the installer is told about"
else bad "the port reaches the installer" "$(cat "$TMP/state/advisord-env" 2>/dev/null)"; fi
# The model ceremony is CLI-only today and belongs where the operator answers
# a provider, a key and a model. install-advisord.sh offers it when it has a
# terminal, so this run must not give it one.
if grep -q 'TTY=no' "$TMP/state/advisord-env" 2>/dev/null
then ok "the installer gets no terminal, so its CLI model ceremony is skipped"
else bad "no terminal reaches the installer" "$(cat "$TMP/state/advisord-env" 2>/dev/null)"; fi

echo
echo "── one sequence, through the one script both paths run ────────────"

# The defect this section exists for. There were two ways to add the Advisor
# and they left two different hosts: the one-line install ran the service
# installer, both root grants, the account move and the trust sync, and
# `install.sh --with-advisor` ran the service installer and the account move
# and nothing else. So that host had no sealer socket (no browser model step)
# and no trust-sync grant (a passkey enrolled in the browser never reached its
# Advisor), while the documentation said the two were the same.
#
# The sequence lives in scripts/install-advisor-stack.sh now, and this
# bootstrap runs it rather than carrying its own copy. What is asserted here is
# the order, end to end, with the read-back in the same record: it is the last
# thing, because everything before it is what it is reading back.
healthy
: > "$TMP/state/log-status"
run_sut --yes >/dev/null 2>&1
SEQ="$(sed -E 's/ .*//' "$TMP/state/install-args" | grep -vx prepare | tr '\n' ' ')"
if [[ "$SEQ" == "advisord sealer trust-grant account auth status " ]]
then ok "the stack runs the service, both grants, the account, the sync, then the read-back"
else bad "the whole sequence, in order" "got: $SEQ"; fi

# The knobs have to cross the sudo boundary as arguments. sudo's env_reset
# drops anything not on its allow-list, so a value exported here would reach
# the stack under this test's fake sudo and be silently dropped by the real
# one — a host would take the ten-try default and nothing would say so.
healthy
out="$(run_sut --yes --port 7899)"
if grep -q 'asking http://127.0.0.1:7899/v1/status, up to 2 times' <<<"$out"
then ok "the port and the retry budget reach the read-back inside the stack"
else bad "the read-back gets the port and the tries" "$(grep -F 'asking http' <<<"$out")"; fi

# The report file. The stack writes it as root; this bootstrap runs as the
# operator. A file minted here and handed to root is refused on Ubuntu
# (fs.protected_regular: root may not write a file another account owns in
# /tmp), which is how the first live run ended, after the build, with
# "Permission denied". So the path the stack gets is a file INSIDE a directory
# this account made, not a file this account made. Asserted on the argument
# line that crossed sudo, and on the directory being gone afterwards.
healthy
: > "$TMP/state/sudo-exec"
run_sut --yes >/dev/null 2>&1
REPORT_ARG="$(grep -o -- '--report [^ ]*' "$TMP/state/sudo-exec" | head -1 | cut -d' ' -f2)"
REPORT_DIR="$(dirname "$REPORT_ARG")"
if [[ "$(basename "$REPORT_ARG")" == "report" && "$(basename "$REPORT_DIR")" == aperire-advisor-stack.* ]]
then ok "the stack's report is a file inside a directory the bootstrap made, never a file it made"
else bad "the report path crosses sudo as <private dir>/report" "got: ${REPORT_ARG:-nothing}"; fi
if [[ ! -e "$REPORT_DIR" ]]
then ok "and that directory is removed when the run ends"
else bad "the report directory is cleaned up" "still here: $REPORT_DIR"; fi

# The negative control that makes the rows above mean what they say: with the
# shared script gone, this bootstrap has no sequence of its own to fall back
# on, so nothing is installed. A copy kept here would pass every row above.
healthy
mv "$TMP/op/aperire-one/scripts/install-advisor-stack.sh" "$TMP/state/stack.hidden"
out="$(run_sut --yes)"; rc=$?
if [[ $rc -ne 0 ]] && ! grep -qE '^(advisord|sealer|account) ' "$TMP/state/install-args" 2>/dev/null
then ok "without the shared script the bootstrap installs nothing: it has no second copy"
else bad "the bootstrap has no copy of the sequence" "exit $rc: $(cat "$TMP/state/install-args" 2>/dev/null)"; fi
mv "$TMP/state/stack.hidden" "$TMP/op/aperire-one/scripts/install-advisor-stack.sh"

echo
echo "── the trust store, so the first approval works ───────────────────"

# The Advisor checks approvals against its own copy of the operators' public
# keys, and enrolling in a browser does not reach it: the web side never writes
# that store, on purpose. An operator who enrolled before installing the
# Advisor met "checking approvals against 0 passkeys" the first time they tried
# to approve, which is the worst moment to find out.
STORE="$TMP/op/aperire-one/advisor/state/credentials.json"

healthy
rm -f "$STORE"
out="$(run_sut --yes)"
if grep -qx 'auth advisor-sync' "$TMP/state/install-args" 2>/dev/null
then ok "the Advisor is handed the enrolled passkeys, without being asked for"
else bad "the trust sync runs" "$(cat "$TMP/state/install-args" 2>/dev/null)"; fi
if [[ "$(grep -n '^advisord ' "$TMP/state/install-args" | cut -d: -f1)" -lt \
      "$(grep -n '^auth ' "$TMP/state/install-args" | cut -d: -f1)" ]]
then ok "and after it is installed and answering, never before"
else bad "the sync comes after the install" "$(cat "$TMP/state/install-args")"; fi
if grep -q 'trust store synced: 1 passkey' <<<"$out"
then ok "and the count comes from the sync itself, not from a second opinion"
else bad "it says what it synced" "$(tail -8 <<<"$out")"; fi

# Nobody enrolled yet. Enrolling later does NOT sync by itself, so saying it
# would is the one sentence that leaves an operator waiting for something that
# is never going to happen.
healthy
rm -f "$STORE"
printf '0\n' > "$TMP/state/sync-count"
out="$(run_sut --yes)"
if grep -q 'no operator has enrolled a passkey yet' <<<"$out" \
   && grep -q 'handed the key as you do' <<<"$out"
then ok "with nobody enrolled it says enrolling comes first, and that enrolling is enough"
else bad "the empty case names the next step" "$(tail -10 <<<"$out")"; fi
# Without the grant, enrolling is NOT enough, and the command for afterwards
# is named instead of implied.
healthy
rm -f "$STORE"
printf '0\n' > "$TMP/state/sync-count"
: > "$TMP/state/grant-fails"
out="$(run_sut --yes)"
if grep -q 'no operator has enrolled a passkey yet' <<<"$out" \
   && grep -q 'aperire-auth.sh advisor-sync' <<<"$out"
then ok "and on a host without the grant it names the command for after"
else bad "the empty case without the grant names the command" "$(tail -10 <<<"$out")"; fi
rm -f "$TMP/state/grant-fails"

# A store with keys in it came from somewhere. On a fleet node that somewhere
# is an issuer's signed bundle, and a local sync would replace the fleet's idea
# of who may approve with this box's.
healthy
printf '{"credentials":[{"credential_id":"abc","public_key":"k"}]}\n' > "$STORE"
out="$(run_sut --yes)"
if ! grep -q '^auth ' "$TMP/state/install-args" 2>/dev/null
then ok "a store that already holds keys is never overwritten"
else bad "an existing trust store is left alone" "$(cat "$TMP/state/install-args")"; fi
if grep -q 'already trusts 1 passkey' <<<"$out"
then ok "and it says what it left there"
else bad "it names what it found" "$(tail -8 <<<"$out")"; fi
rm -f "$STORE"

# The Advisor is installed and answering by this point. A sync that cannot run
# is a thing to go and do, not a reason to fail an install that worked.
healthy
rm -f "$STORE"
: > "$TMP/state/sync-fails"
out="$(run_sut --yes)"; rc=$?
if [[ $rc -eq 0 ]] && grep -q 'the trust store was not synced' <<<"$out"
then ok "a sync that fails is named, and does not fail the install behind it"
else bad "a failed sync is not fatal" "exit $rc: $(tail -8 <<<"$out")"; fi
# The sync's own reason reaches the operator. A refusal whose reason was kept
# back was a warning nobody could act on: root had no node, and the install
# said only "not synced" (aperire4, 2026-09-05, #211).
if grep -q 'no public_url in authn.yaml' <<<"$out"
then ok "and the sync's own reason is printed under it"
else bad "the sync's reason is printed" "$(tail -12 <<<"$out")"; fi
if grep -q 'the Advisor is installed, and answering' <<<"$out"
then ok "and the banner still reports what is true, which is that it is running"
else bad "the banner still prints" "$(tail -8 <<<"$out")"; fi

# The account move failing leaves an Advisor that answers, on the dashboard's
# account: the retired arrangement, on every host shape, an aggregator
# included. The run goes on to the read-back, then ends non-zero with the
# step named, never 0 (#806, the lab aggregator ended 0 this way).
healthy
: > "$TMP/state/account-fails"
out="$(run_sut --yes)"; rc=$?
if [[ $rc -eq 3 ]]; then ok "a refused account move ends the install 3, not 0"
else bad "a refused account move ends non-zero" "exit $rc"; fi
if ! grep -q 'the Advisor is installed, and answering' <<<"$out"
then ok "and the green banner is not printed over it"
else bad "no success banner over a refused move" "$(tail -8 <<<"$out")"; fi
if grep -q 'still running as' <<<"$out"
then ok "and says so rather than claiming the baseline"
else bad "it names the degradation" "$(tail -5 <<<"$out")"; fi
if ! grep -q 'on its own account, reaching the node through its root socket' <<<"$out"
then ok "the banner does not claim the account it did not get"
else bad "no false claim of the account" "$(tail -8 <<<"$out")"; fi
# A failed move is not a supported end state on any systemd now (ADR 0025):
# the note sends the operator to the account installer's own reason and the
# one command, and never calls the shared account fine.
# Matched on the closing block, not the whole run: the stack's progress line
# ("running .../install-advisor-account.sh") names the installer too and said
# nothing about the remedy. And the remedy is the update: the Advisor one-liner
# on an Advisor that now answers reports it is already here and moves nothing.
closing="$(sed -n '/NOT on its own account/,$p' <<<"$out")"
if [[ -n "$closing" ]] && grep -q -- '--update --force' <<<"$closing" \
   && ! grep -q 'get.aperire.one/advisor' <<<"$closing" && ! grep -q 'nothing to fix' <<<"$out"
then ok "the closing block names the update that offers the move, and does not call this fine"
else bad "the failed-move closing block names the update" "$closing"; fi

# The same failure on Ubuntu 22.04. Its systemd 249 used to be the reason the
# Advisor stayed on the shared account, and the note said so and called it the
# supported shape. The root socket removed that reason, so 249 gets the same
# note as everyone, with no version excuse in it.
healthy
: > "$TMP/state/account-fails"
echo 249 > "$TMP/state/systemd-version"
out="$(run_sut --yes)"; rc=$?
rm -f "$TMP/state/systemd-version"
if [[ $rc -eq 3 && "$out" != *"nothing to fix"* && "$out" != *"needs 250"* \
      && "$(sed -n '/NOT on its own account/,$p' <<<"$out")" == *"--update --force"* ]]
then ok "on systemd 249 the note is the same: no version excuse, and the update to run again"
else bad "the systemd 249 note has no excuse in it" "rc=$rc $(tail -8 <<<"$out")"; fi
if ! grep -q 'configure the wrapper and run it again' <<<"$out"
then ok "and does not send the operator to configure a wrapper that cannot help there"
else bad "no wrapper advice on 249" "$(tail -8 <<<"$out")"; fi

# The opposite, so the row above is not passing on an absent string.
healthy
out="$(run_sut --yes)"
if grep -q 'on its own account, reaching the node through its root socket' <<<"$out"
then ok "and it does claim it when the move succeeded"
else bad "the banner claims the account when earned" "$(tail -8 <<<"$out")"; fi

# advisord itself failing IS fatal, and stops before the account move.
healthy
: > "$TMP/state/advisord-fails"
out="$(run_sut --yes)"; rc=$?
if [[ $rc -ne 0 ]]; then ok "advisord failing to install stops the run"
else bad "advisord failing stops the run" "exit $rc"; fi
if ! grep -q '^account ' "$TMP/state/install-args" 2>/dev/null
then ok "and nothing after it is attempted"
else bad "nothing runs after a failed advisord install" "$(cat "$TMP/state/install-args")"; fi

echo
echo "── the banner means something ─────────────────────────────────────"

# Three readings, each asserted in both directions. The banner is the claim;
# every row here is the reading it rests on.
healthy
out="$(run_sut --yes)"
if grep -q 'the Advisor is installed, and answering' <<<"$out"
then ok "enabled + running + answering prints the banner"
else bad "the banner prints when all three pass" "$(tail -6 <<<"$out")"; fi

healthy
rm -f "$TMP/state/enabled"
out="$(run_sut --yes)"; rc=$?
if [[ $rc -ne 0 ]] && grep -q 'would not come back after a reboot' <<<"$out"
then ok "a unit that is not enabled is refused, and named as a reboot problem"
else bad "not-enabled is refused" "exit $rc: $(tail -3 <<<"$out")"; fi
if ! grep -q 'the Advisor is installed, and answering' <<<"$out"
then ok "and no banner is printed"
else bad "no banner when not enabled" "$(tail -6 <<<"$out")"; fi

healthy
rm -f "$TMP/state/active"
out="$(run_sut --yes)"; rc=$?
if [[ $rc -ne 0 ]] && grep -q 'enabled but not running' <<<"$out"
then ok "a unit that is enabled but dead is refused, and told apart from the above"
else bad "not-active is refused" "exit $rc: $(tail -3 <<<"$out")"; fi

healthy
printf 'down\n' > "$TMP/state/status"
out="$(run_sut --yes)"; rc=$?
if [[ $rc -ne 0 ]] && grep -q 'did not answer on' <<<"$out"
then ok "a running but silent service is refused, with the journal to read"
else bad "silent service is refused" "exit $rc: $(tail -3 <<<"$out")"; fi
if ! grep -q 'the Advisor is installed, and answering' <<<"$out"
then ok "and no banner is printed for it either"
else bad "no banner when silent" "$(tail -6 <<<"$out")"; fi

echo
echo "── already installed, and the model step ──────────────────────────"

# Installed and answering: nothing to do. Not a failure, and not a reinstall.
healthy
printf 'aperire-advisord.service enabled\n' > "$TMP/state/units"
: > "$TMP/state/has-model"
out="$(run_sut --yes)"; rc=$?
if [[ $rc -eq 0 ]] && grep -q 'already installed here' <<<"$out"
then ok "an Advisor that is already answering is left alone"
else bad "already-installed is left alone" "exit $rc: $(tail -3 <<<"$out")"; fi
if [[ ! -f "$TMP/state/install-args" ]]
then ok "and no installer runs"
else bad "no installer runs when already answering" "$(cat "$TMP/state/install-args")"; fi

# Installed but NOT answering is a repair, and running the installers again is
# what repairs it. Without this the one command would be useless on the box
# that needs it most.
healthy
printf 'aperire-advisord.service enabled\n' > "$TMP/state/units"
printf 'down\n' > "$TMP/state/status"
run_sut --yes >/dev/null 2>&1
if grep -q '^advisord ' "$TMP/state/install-args" 2>/dev/null
then ok "an installed but silent Advisor is repaired, not skipped"
else bad "installed-but-down runs the installer" "$(cat "$TMP/state/install-args" 2>/dev/null)"; fi

# The closing banner names the model step, and when it names the menu it names
# the menu, never an internal script. Driven down the fallback branch on
# purpose: the browser branch has its own rows above, and this one is about the
# shape of the instruction rather than which of the two is given.
healthy
: > "$TMP/state/sealer-fails"
out="$(run_sut --yes)"
if grep -q " bash $TMP/op/aperire-one/aperire-one" <<<"$out" && ! grep -q "sudo bash $TMP/op/aperire-one/aperire-one" <<<"$out"
then ok "the model step is named as the menu, at this install's real path"
else bad "the model step names the menu at a real path" "$(tail -8 <<<"$out")"; fi
banner_only="$(sed -n '/is installed, and answering/,$p' <<<"$out")"
if ! grep -qE 'setup-advisor-model\.sh|install-advisord\.sh|install-advisor-account\.sh' <<<"$banner_only"
then ok "and no internal script is named as the way in"
else bad "no internal script named as the way in" "$(grep -oE '[a-z-]+\.sh' <<<"$banner_only" | sort -u | tr '\n' ' ')"; fi
if grep -q 'has no language model yet' <<<"$out"
then ok "and it says plainly that the model is still missing"
else bad "the missing model is stated" "$(tail -8 <<<"$out")"; fi

echo
echo "── the build, which a host without --with-advisor has never done ──"

# The failure this section exists for, from the first live ceremony: a
# co-located install made WITHOUT --with-advisor has no Advisor binaries and
# no reason to have had them. The bootstrap went straight to install-advisord,
# which found nothing to install and no Go it could see.
healthy
run_sut --yes >/dev/null 2>&1
if grep -q '^prepare role=.* advisor=1$' "$TMP/state/install-args" 2>/dev/null
then ok "prepare-host runs, and is told the Advisor is wanted"
else bad "prepare-host is invoked with the advisor env" "$(cat "$TMP/state/install-args" 2>/dev/null)"; fi
if [[ "$(head -1 "$TMP/state/install-args")" == prepare* ]]
then ok "and it runs BEFORE the installer that needs what it builds"
else bad "the build comes first" "$(cat "$TMP/state/install-args")"; fi
if grep -q 'binaries=yes' "$TMP/state/advisord-env" 2>/dev/null
then ok "so install-advisord finds binaries where it found none before"
else bad "the installer sees built binaries" "$(cat "$TMP/state/advisord-env" 2>/dev/null)"; fi

# The role is worked out from what this host has, not guessed and not read
# from a file that has never held one.
healthy
run_sut --yes >/dev/null 2>&1
if grep -q '^prepare role=dashboard ' "$TMP/state/install-args" 2>/dev/null
then ok "a box with no relay is prepared as a dashboard, not as co-located"
else bad "no relay means dashboard" "$(grep '^prepare' "$TMP/state/install-args")"; fi

healthy
printf 'aperire-relay.service enabled\n' >> "$TMP/state/units"
run_sut --yes >/dev/null 2>&1
if grep -q '^prepare role=co-located ' "$TMP/state/install-args" 2>/dev/null
then ok "and a box whose relay unit is here is prepared as co-located"
else bad "a relay means co-located" "$(grep '^prepare' "$TMP/state/install-args")"; fi

# Already built is not a rebuild. prepare-host compares the binaries against
# their sources and says so, which is what makes putting it on this path free.
healthy
run_sut --yes >/dev/null 2>&1   # first run builds
# The binaries stay; everything that would make the second run take the
# already-installed shortcut goes, because what is being measured is the build
# step meeting work it has already done.
rm -f "$TMP/state/install-args" "$TMP/state/advisord-env"
: > "$TMP/state/units"
out="$(run_sut --yes)"
if grep -q 'newer than their sources' <<<"$out"
then ok "a second run says the binaries are already current rather than rebuilding"
else bad "the build step is idempotent" "$(grep -i 'built\|newer' <<<"$out" | head -2)"; fi
if grep -q 'binaries=yes' "$TMP/state/advisord-env" 2>/dev/null
then ok "and the installer still finds them"
else bad "binaries survive a second run" "$(cat "$TMP/state/advisord-env" 2>/dev/null)"; fi

# A build that cannot happen stops the run. Going on to install a service
# whose binary does not exist is the failure this whole section is about.
healthy
: > "$TMP/state/prepare-fails"
out="$(run_sut --yes)"; rc=$?
if [[ $rc -ne 0 ]]; then ok "a build that fails stops the run"
else bad "a failed build is fatal" "exit $rc"; fi
if ! grep -q '^advisord ' "$TMP/state/install-args" 2>/dev/null
then ok "and nothing is installed on top of binaries that were never built"
else bad "no install after a failed build" "$(cat "$TMP/state/install-args")"; fi

# The operator is told a compile is coming, before it starts.
healthy
out="$(run_sut --yes)"
if grep -q 'The Advisor is Go' <<<"$out"
then ok "the plan says a build is part of this, so a compile is not a surprise"
else bad "the plan mentions the build" "$(sed -n '/the plan/,/^$/p' <<<"$out")"; fi

echo
echo "── the browser model step, and its window ─────────────────────────"

# The grant that makes the browser model step possible is installed on every
# host, and armed. Separately from the account move and before it, because the
# account move legitimately cannot run on a box with no node, while an Advisor
# that watches other nodes still answers questions and still needs a model.
healthy
run_sut --yes >/dev/null 2>&1
if grep -q '^sealer --arm$' "$TMP/state/install-args" 2>/dev/null
then ok "the sealer grant is installed and armed in the same run"
else bad "the grant is installed and armed" "$(cat "$TMP/state/install-args" 2>/dev/null)"; fi
if [[ "$(grep -n '^sealer' "$TMP/state/install-args" | cut -d: -f1)" -lt       "$(grep -n '^account' "$TMP/state/install-args" | cut -d: -f1)" ]]
then ok "and before the account move, which a host with no node cannot run"
else bad "the grant comes before the account move" "$(cat "$TMP/state/install-args")"; fi

healthy
out="$(run_sut --yes)"
if grep -q 'Set one up in your browser' <<<"$out" && grep -q 'choose .*Settings' <<<"$out" \
   && grep -q 'Open .*Advisor AI model' <<<"$out"
then ok "with the grant in place the banner sends you to the browser: refresh, menu, Settings, Advisor AI model"
else bad "the banner names the browser steps" "$(tail -16 <<<"$out")"; fi
if grep -q 'open for .*fifteen minutes' <<<"$out"
then ok "and names the window, and how to open another"
else bad "the banner names the window" "$(tail -12 <<<"$out")"; fi

# The negative control, and the one that matters: a host whose browser cannot
# seal must not be sent to a browser.
healthy
: > "$TMP/state/sealer-fails"
out="$(run_sut --yes)"; rc=$?
if [[ $rc -eq 0 ]]; then ok "a host that cannot take the grant still finishes"
else bad "the grant failing is not fatal" "exit $rc"; fi
if ! grep -q 'Set one up in your browser' <<<"$out"
then ok "and is NOT sent to a browser that could not seal for it"
else bad "no browser instruction without the grant" "$(tail -12 <<<"$out")"; fi
if grep -q " bash $TMP/op/aperire-one/aperire-one" <<<"$out" && ! grep -q "sudo bash $TMP/op/aperire-one/aperire-one" <<<"$out"
then ok "but is given the menu instead, so the model step is still reachable"
else bad "the menu is offered as the fallback" "$(tail -12 <<<"$out")"; fi

# The second grant, so a passkey enrolled in the browser reaches the Advisor
# without a command on the host. Same run, same place, and losing it is a
# named warning rather than a failed install: the CLI sync still works.
healthy
run_sut --yes >/dev/null 2>&1
if grep -qx 'trust-grant ' "$TMP/state/install-args" 2>/dev/null
then ok "the trust-sync grant is installed in the same run"
else bad "the trust-sync grant is installed" "$(cat "$TMP/state/install-args" 2>/dev/null)"; fi
healthy
: > "$TMP/state/grant-fails"
out="$(run_sut --yes)"; rc=$?
if [[ $rc -eq 0 ]] && grep -q 'will not reach the Advisor by itself' <<<"$out" \
   && grep -q '^account ' "$TMP/state/install-args"
then ok "a host that cannot take the grant is told, and the install goes on"
else bad "a failed grant is a warning, not a failed install" "exit $rc: $(grep -n 'reach the Advisor' <<<"$out")"; fi
rm -f "$TMP/state/grant-fails"

echo
echo "── an Advisor that is already here, and its wrapper (#917) ────────"

# Installed, answering, with a model, and no wrapper configuration: the host
# #915 left behind. Re-running the one-liner has to configure it, from the
# staged copy and not from the operator's tree.
healthy
printf 'aperire-advisord.service enabled\n' > "$TMP/state/units"
: > "$TMP/state/has-model"
rm -f "$TMP/wrapper/node-wrapper.conf"
out="$(run_sut --yes)"; rc=$?
if [[ $rc -eq 0 ]] && [[ -f "$TMP/wrapper/node-wrapper.conf" ]]
then ok "an installed Advisor with no wrapper configuration gets it configured"
else bad "the missing wrapper configuration is written" "exit $rc: $(tail -6 <<<"$out")"; fi
if grep -q "^wrapper  *tree=$TMP/op/aperire-one instance= self=" "$TMP/state/install-args" 2>/dev/null \
   && ! grep -q "self=$TMP/op/aperire-one/scripts" "$TMP/state/install-args"
then ok "by the staged copy of the installer, told which tree it acts on"
else bad "the wrapper installer runs from the staged copy" "$(cat "$TMP/state/install-args" 2>/dev/null)"; fi
if grep -q 'node-wrapper.conf is missing' <<<"$out" || grep -q 'is missing, so every action' <<<"$out"
then ok "and the run says so"
else bad "the repair is announced" "$(tail -10 <<<"$out")"; fi

# The keyless branch too.
healthy
printf 'aperire-advisord.service enabled\n' > "$TMP/state/units"
rm -f "$TMP/wrapper/node-wrapper.conf"
out="$(run_sut --yes)"; rc=$?
if [[ $rc -eq 0 ]] && grep -q '^wrapper ' "$TMP/state/install-args" 2>/dev/null
then ok "a keyless Advisor gets its missing wrapper configured too"
else bad "the keyless path repairs the wrapper" "exit $rc: $(cat "$TMP/state/install-args" 2>/dev/null)"; fi

# #1129: a host that runs no node has nothing for a wrapper to act on, so a
# missing configuration there is not repaired and not complained about. The
# live case was the lab aggregator: the re-run ended "install-node-wrapper.sh
# exited 1 ... Run this again" and a --node-wrapper hint that could never
# apply.
healthy
printf 'aperire-advisord.service enabled\n' > "$TMP/state/units"
: > "$TMP/state/has-model"
rm -f "$TMP/wrapper/node-wrapper.conf" "$TMP/etc-node.conf"
printf 'pm2-app\tnode:20\n' > "$TMP/state/docker-ps"
out="$(run_sut --yes)"; rc=$?
if [[ $rc -eq 0 ]] && ! grep -q '^wrapper ' "$TMP/state/install-args" 2>/dev/null
then ok "a host with no node (no node.conf, no node container) is not given a wrapper repair"
else bad "no node, no repair" "exit $rc: $(cat "$TMP/state/install-args" 2>/dev/null)"; fi
if grep -q 'this host runs no node, so the Advisor here acts on none' <<<"$out" \
   && ! grep -q 'install-node-wrapper.sh exited\|Run this again\|--node-wrapper <container' <<<"$out" \
   && ! grep -q '!!.*\(wrapper\|node\)' <<<"$out"
then ok "and says so in one quiet line, with no red line and no instruction to run it again"
else bad "the no-node line, and nothing alarming" "$(tail -12 <<<"$out")"; fi
# The same host on the keyless branch, where the wrapper is repaired first.
rm -f "$TMP/state/has-model" "$TMP/state/install-args"
out="$(run_sut --yes)"; rc=$?
if [[ $rc -eq 0 ]] && ! grep -q '^wrapper ' "$TMP/state/install-args" 2>/dev/null \
   && grep -q 'this host runs no node' <<<"$out"
then ok "a keyless Advisor on a node-less host is not given a wrapper repair either"
else bad "the keyless path asks whether a node runs here" "exit $rc: $(cat "$TMP/state/install-args" 2>/dev/null)"; fi

# The negative controls: no node.conf is not the same as no node. An
# operator's own container, a lost wrapper configuration, is exactly what the
# repair is for (#917).
healthy
printf 'aperire-advisord.service enabled\n' > "$TMP/state/units"
: > "$TMP/state/has-model"
rm -f "$TMP/wrapper/node-wrapper.conf" "$TMP/etc-node.conf" "$TMP/state/install-args"
printf 'my-validator\trippleci/xrpld:3.2.1\n' > "$TMP/state/docker-ps"
out="$(run_sut --yes)"; rc=$?
if [[ $rc -eq 0 ]] && grep -q '^wrapper ' "$TMP/state/install-args" 2>/dev/null && [[ -f "$TMP/wrapper/node-wrapper.conf" ]]
then ok "no node.conf but a node container running: the wrapper is still repaired"
else bad "an operator's own container is still repaired" "exit $rc: $(cat "$TMP/state/install-args" 2>/dev/null) $(tail -6 <<<"$out")"; fi

healthy
printf 'aperire-advisord.service enabled\n' > "$TMP/state/units"
: > "$TMP/state/has-model"
rm -f "$TMP/wrapper/node-wrapper.conf" "$TMP/etc-node.conf" "$TMP/state/install-args"
printf 'a1b2c3d4e5f6\tsha256:0123456789abcdef0123456789abcdef\n' > "$TMP/state/docker-ps"
out="$(run_sut --yes)"; rc=$?
if [[ $rc -eq 0 ]] && grep -q '^wrapper ' "$TMP/state/install-args" 2>/dev/null
then ok "a container docker shows only as an image id may be the node, so the wrapper is still repaired"
else bad "an unresolvable container is not 'no node'" "exit $rc: $(cat "$TMP/state/install-args" 2>/dev/null)"; fi

healthy
printf 'aperire-advisord.service enabled\n' > "$TMP/state/units"
: > "$TMP/state/has-model"
rm -f "$TMP/wrapper/node-wrapper.conf" "$TMP/etc-node.conf" "$TMP/state/install-args"
: > "$TMP/state/docker-fails"
out="$(run_sut --yes)"; rc=$?
if [[ $rc -eq 0 ]] && grep -q '^wrapper ' "$TMP/state/install-args" 2>/dev/null
then ok "docker that will not answer is 'cannot tell', not 'no node': the wrapper is still repaired"
else bad "a silent docker is not 'no node'" "exit $rc: $(cat "$TMP/state/install-args" 2>/dev/null)"; fi
rm -f "$TMP/state/docker-fails" "$TMP/state/docker-ps"

# The order (#935). The sealer asks the node who it is, and finds where to
# ask in the wrapper's configuration, so the configuration has to be written
# first. The stub sealer records whether the file was there when it ran.
healthy
printf 'aperire-advisord.service enabled\n' > "$TMP/state/units"
rm -f "$TMP/wrapper/node-wrapper.conf"
out="$(run_sut --yes)"; rc=$?
if [[ $rc -eq 0 ]] && grep -qx 'conf=yes' "$TMP/state/sealer-saw" 2>/dev/null \
   && ! grep -qx 'conf=no' "$TMP/state/sealer-saw"
then ok "a keyless Advisor with no wrapper configuration has it written before the sealer runs (#935)"
else bad "the wrapper is configured before the sealer reads it" "exit $rc: saw=$(cat "$TMP/state/sealer-saw" 2>/dev/null) args=$(cat "$TMP/state/install-args" 2>/dev/null)"; fi
wline="$(grep -n '^wrapper ' "$TMP/state/install-args" | head -1 | cut -d: -f1)"
sline="$(grep -n '^sealer ' "$TMP/state/install-args" | head -1 | cut -d: -f1)"
if [[ -n "$wline" && -n "$sline" && "$wline" -lt "$sline" ]]
then ok "  and the call log has the wrapper installer first"
else bad "the wrapper installer is called before the sealer" "wrapper at ${wline:-none}, sealer at ${sline:-none}"; fi

# What the operator reads. The real sealer's node-key block, cut out of the
# shipped script and run where the stub sealer runs, against a node that
# answers or does not. Three hosts, one wording each (#935).
nk_src="$REPO_DIR/scripts/install-model-key-sealer.sh"
{
  grep -E '^NODE_KEY_RE=' "$nk_src"
  printf 'NODE_KEY_WHY=""\nNODE_KEY_NONODE=0\n'
  sed -n '/^resolve_node_key() {/,/^}/p' "$nk_src"
  sed -n '/^stamped_node_key() {/,/^}/p' "$nk_src"
  sed -n '/^refresh_node_key_line() {/,/^}/p' "$nk_src"
  sed -n '/^sealer_would_trust() {/,/^}/p' "$nk_src"
  sed -n '/^say_node_key_changed() {/,/^}/p' "$nk_src"
  sed -n '/^echo "== This host.s own node key"$/,/^fi$/p' "$nk_src"
} > "$TMP/nodekey-block.sh"
if grep -q '^resolve_node_key()' "$TMP/nodekey-block.sh" && grep -q '^stamped_node_key()' "$TMP/nodekey-block.sh" \
   && grep -q '^refresh_node_key_line()' "$TMP/nodekey-block.sh" && grep -q '^sealer_would_trust()' "$TMP/nodekey-block.sh" \
   && grep -q '^say_node_key_changed()' "$TMP/nodekey-block.sh" && grep -q 'This host.s own node key' "$TMP/nodekey-block.sh" \
   && [[ "$(tail -1 "$TMP/nodekey-block.sh")" == "fi" ]]
then ok "the sealer's own node-key code was cut out of the shipped script for the rows below"
else bad "the node-key block was found in the sealer" "$(wc -l < "$TMP/nodekey-block.sh") lines"; fi
NK_OLD=nAbCdEfGhJkLmNpQrStUvWxYz12345
NK_NEW=nZyXwVuTsRqPoNmLkJhGfEdCbA98765
nk_host() { # $1 = old stamp or "", $2 = "up" or "down"
  healthy
  printf 'aperire-advisord.service enabled\n' > "$TMP/state/units"
  rm -f "$TMP/wrapper/node-wrapper.conf"
  rm -rf "$TMP/etcnk"; mkdir -p "$TMP/etcnk"
  [[ -z "$1" ]] || printf '%s\n' "$1" > "$TMP/etcnk/node-key"
  : > "$TMP/state/real-nodekey-block"
  rm -f "$TMP/state/node-answers"
  [[ "$2" != up ]] || printf '{"result":{"info":{"pubkey_node":"%s"}}}\n' "$NK_NEW" > "$TMP/state/node-answers"
  out="$(run_sut --yes)"; rc=$?
}
nk_host "$NK_OLD" up
if [[ $rc -eq 0 ]] && ! grep -q 'not stamped' <<<"$out" && ! grep -q 'no admin RPC address' <<<"$out" \
   && grep -qF -e "$NK_NEW" <<<"$out" && [[ "$(cat "$TMP/etcnk/node-key")" == "$NK_NEW" ]] \
   && grep -qF "it was $NK_OLD" <<<"$out" && grep -q 'expected_pubkey_node' <<<"$out"
then ok "an installed Advisor with a stamp and no wrapper configuration asks the node and stamps its answer, and says the old key's tokens stop working"
else bad "the stamp reads the repaired configuration" "exit $rc: $(grep -A6 "own node key" <<<"$out")"; fi
nk_host "$NK_OLD" down
if [[ $rc -eq 0 ]] && ! grep -q 'not stamped' <<<"$out" && ! grep -q 'tokens are refused until' <<<"$out" \
   && grep -q 'kept:' <<<"$out" && grep -qF -e "$NK_OLD" <<<"$out" && [[ "$(cat "$TMP/etcnk/node-key")" == "$NK_OLD" ]] \
   && ! grep -q 'honoured' <<<"$out" && grep -q 'refused until it is paired' <<<"$out"
then ok "  and with the node down the old stamp is said to be kept, with its key, and is left as it was"
else bad "a kept stamp is not reported as missing" "exit $rc: $(grep -A8 "own node key" <<<"$out")"; fi
blk="$(sed -n '/own node key/,/may seal one key/p' <<<"$out")"
if grep -q 'bash -s -- --refresh-node-key' <<<"$blk" && ! grep -q 'sudo bash' <<<"$blk"
then ok "  with the bootstrap's flag as the way to stamp again, never sudo on a script in the tree"
else bad "the hint is a root-owned form" "$(grep -A8 "own node key" <<<"$out")"; fi
nk_host "" down
if [[ $rc -eq 0 ]] && grep -q 'not stamped: the node did not answer' <<<"$out" && ! grep -q 'kept:' <<<"$out" \
   && grep -q 'bash -s -- --refresh-node-key' <<<"$out" && ! sed -n '/own node key/,/may seal one key/p' <<<"$out" | grep -q 'sudo bash'
then ok "a host with no stamp and no answer from its node still says not stamped"
else bad "no stamp still reads as not stamped" "exit $rc: $(grep -A8 "own node key" <<<"$out")"; fi
rm -f "$TMP/state/real-nodekey-block"

# A configuration that is there but a wrapper that does not answer.
healthy
printf 'aperire-advisord.service enabled\n' > "$TMP/state/units"
: > "$TMP/state/has-model"
: > "$TMP/state/wrapper-status-fails"
out="$(run_sut --yes)"; rc=$?
if [[ $rc -eq 0 ]] && grep -q '^wrapper ' "$TMP/state/install-args" 2>/dev/null
then ok "a wrapper whose status fails is configured again"
else bad "a failing status is repaired" "exit $rc: $(cat "$TMP/state/install-args" 2>/dev/null)"; fi

# Negative control: a configured, answering wrapper is left alone.
healthy
printf 'aperire-advisord.service enabled\n' > "$TMP/state/units"
: > "$TMP/state/has-model"
out="$(run_sut --yes)"; rc=$?
if ! grep -q '^wrapper ' "$TMP/state/install-args" 2>/dev/null
then ok "a wrapper that is configured and answering is left alone"
else bad "a good wrapper is not touched" "$(cat "$TMP/state/install-args")"; fi

# A repair that fails is said plainly and does not fail the run.
healthy
printf 'aperire-advisord.service enabled\n' > "$TMP/state/units"
: > "$TMP/state/has-model"
rm -f "$TMP/wrapper/node-wrapper.conf"
: > "$TMP/state/wrapper-install-fails"
out="$(run_sut --yes)"; rc=$?
if [[ $rc -eq 0 ]] && grep -q 'install-node-wrapper.sh exited 1' <<<"$out"
then ok "a wrapper installer that fails is named, and the run still ends cleanly"
else bad "a failed repair is named" "exit $rc: $(tail -8 <<<"$out")"; fi

# M1: an aggregator (SERVICE=none) in front of the REAL wrapper script. Its
# `status` refuses, because it needs a node, and that is a working wrapper, so
# the re-run must not repair it. The real script, redirected to a fixture
# configuration the way test-node-wrapper-conf.sh does it, not the stub.
RW="$TMP/realwrap"; rm -rf "$RW"; mkdir -p "$RW/lib"
cp "$REPO_DIR/scripts/config-write-lib.sh" "$REPO_DIR/scripts/trusted-path-lib.sh" "$RW/lib/" 2>/dev/null
sed -e "s#^CONF=/etc/aperire/node-wrapper.conf#CONF=$RW/node-wrapper.conf#" \
    -e "s#^CWL_LIB=/usr/local/lib/aperire/config-write-lib.sh#CWL_LIB=$RW/lib/config-write-lib.sh#" \
    -e "s#^TPL_LIB=/usr/local/lib/aperire/trusted-path-lib.sh#TPL_LIB=$RW/lib/trusted-path-lib.sh#" \
    "$REPO_DIR/scripts/aperire-node-wrapper.sh" > "$RW/aperire-node-wrapper"
chmod 0755 "$RW/aperire-node-wrapper"
{ printf 'REPO=none\nSERVICE=none\nPROJECT=none\nCOMPOSE_FILE=/dev/null\nCONFIG_FILE=/dev/null\n'
  printf 'ADMIN_RPC=http://127.0.0.1:0\nLOG=%s\n' "$RW/wrapper.log"; } > "$RW/node-wrapper.conf"
if "$RW/aperire-node-wrapper" resources >/dev/null 2>&1 && ! "$RW/aperire-node-wrapper" status >/dev/null 2>&1
then ok "fixture check: the real wrapper on an aggregator answers resources and refuses status"
else bad "fixture check: real wrapper, SERVICE=none" "$("$RW/aperire-node-wrapper" resources 2>&1 | tail -2)"; fi
healthy
printf 'aperire-advisord.service enabled\n' > "$TMP/state/units"
: > "$TMP/state/has-model"
out="$( cd "$TMP" && env -i PATH="$TMP/bin:/usr/bin:/bin" HOME="$TMP/op" TERM=dumb \
   APERIRE_ADVISOR_GET_SELF_URL="https://example.invalid/advisor" APERIRE_ADVISOR_GET_TRIES=2 APERIRE_ADVISOR_GET_SLEEP=0 \
   APERIRE_ADVISOR_GET_ROOT_LIB_DIR="$TMP/rootlib" APERIRE_RELEASE_DIGESTS="$TMP/no-release-record" \
   APERIRE_ADVISOR_GET_WRAPPER_CONF="$RW/node-wrapper.conf" APERIRE_ADVISOR_GET_WRAPPER_BIN="$RW/aperire-node-wrapper" \
   bash "$SUT" --yes 2>&1 )"; rc=$?
if [[ $rc -eq 0 ]] && ! grep -q '^wrapper ' "$TMP/state/install-args" 2>/dev/null \
   && grep -qx 'SERVICE=none' "$RW/node-wrapper.conf" && ! [[ -e "$RW/node-wrapper.conf.previous" ]]
then ok "a working wrapper on an aggregator is left alone (no false repair)"
else bad "an aggregator's wrapper is not repaired" "exit $rc: $(cat "$TMP/state/install-args" 2>/dev/null) $(tail -4 <<<"$out")"; fi

# L1: a stopped node fails `status` and is not a broken wrapper. The stub's
# status verb is not asked at all, so a stub that fails only `status` stays
# quiet here: the probe is the node-free read.
healthy
printf 'aperire-advisord.service enabled\n' > "$TMP/state/units"
: > "$TMP/state/has-model"
out="$(run_sut --yes)"
if ! grep -q 'did not answer a read-only check' <<<"$out"
then ok "the probe is a read that needs no node"
else bad "the probe needs no node" "$(tail -6 <<<"$out")"; fi

# L3: a wrapper program root would run that a group or other can write is
# not run to probe, and the configuration is made again.
healthy
printf 'aperire-advisord.service enabled\n' > "$TMP/state/units"
: > "$TMP/state/has-model"
chmod 0775 "$TMP/wrapper/aperire-node-wrapper"
out="$(run_sut --yes)"; rc=$?
chmod 0755 "$TMP/wrapper/aperire-node-wrapper"
if [[ $rc -eq 0 ]] && grep -q '^wrapper ' "$TMP/state/install-args" 2>/dev/null
then ok "a group-writable wrapper is never probed as root; it is reconfigured instead"
else bad "an untrusted wrapper program is not run" "exit $rc: $(tail -6 <<<"$out")"; fi

# L2: a named instance. Its paths come from the library, and the installer is
# told the instance, because sudo's env_reset would drop it otherwise.
healthy
printf 'aperire-advisord-alt.service enabled\n' > "$TMP/state/units"
: > "$TMP/state/has-model"
mkdir -p "$TMP/sbin"
rm -f "$TMP/sbin/"*
# shellcheck disable=SC2016  # the inner shell's own positional parameters
inst_conf="$(env -i APERIRE_SBIN_DIR="$TMP/sbin" bash -c '. "$1"; trusted_wrapper_conf alt "$2"' x "$REPO_DIR/scripts/trusted-path-lib.sh" "$TMP/wrapper/node-wrapper.conf")"
inst_conf_dir="$(dirname "$inst_conf")"
out="$( cd "$TMP" && env -i PATH="$TMP/bin:/usr/bin:/bin" HOME="$TMP/op" TERM=dumb \
   APERIRE_INSTANCE=alt APERIRE_SBIN_DIR="$TMP/sbin" \
   APERIRE_ADVISOR_GET_SELF_URL="https://example.invalid/advisor" APERIRE_ADVISOR_GET_TRIES=2 APERIRE_ADVISOR_GET_SLEEP=0 \
   APERIRE_ADVISOR_GET_ROOT_LIB_DIR="$TMP/rootlib" APERIRE_RELEASE_DIGESTS="$TMP/no-release-record" \
   APERIRE_ADVISOR_GET_WRAPPER_CONF="$TMP/wrapper/node-wrapper.conf" \
   APERIRE_ADVISOR_GET_NODE_CONF="$TMP/etc-node.conf" \
   bash "$SUT" --yes 2>&1 )"; rc=$?
if [[ $rc -eq 0 ]] && grep -q "^wrapper .*instance=alt" "$TMP/state/install-args" 2>/dev/null \
   && grep -q -e "$inst_conf_dir/node-wrapper-.*\.conf is missing" <<<"$out"
then ok "a named instance is checked at its own configuration and the installer is told its name"
else bad "instance paths and name" "exit $rc: $(cat "$TMP/state/install-args" 2>/dev/null) :: $(tail -14 <<<"$out")"; fi

# L4: the stage refused inside the repair is a warning, not a dead run.
healthy
printf 'aperire-advisord.service enabled\n' > "$TMP/state/units"
: > "$TMP/state/has-model"
rm -f "$TMP/wrapper/node-wrapper.conf"
mv "$TMP/rootlib/trusted-path-lib.sh" "$TMP/rootlib/away"
mv "$TMP/op/aperire-one/scripts/state-file.py" "$TMP/state-file.away"
out="$(run_sut --yes)"; rc=$?
mv "$TMP/rootlib/away" "$TMP/rootlib/trusted-path-lib.sh"
mv "$TMP/state-file.away" "$TMP/op/aperire-one/scripts/state-file.py"
if [[ $rc -eq 0 ]] && grep -q 'could not be staged' <<<"$out" && grep -q 'no root-owned copy' <<<"$out" \
   && grep -qF -- 'bash -s -- --update --force' <<<"$out"
then ok "a refused stage inside the wrapper repair is named, and the run still ends cleanly"
else bad "a refused stage is not fatal here" "exit $rc: $(tail -6 <<<"$out")"; fi

# L4, the branch with no replant: a model, no state-file.py, no wrapper
# configuration. It still exits 0 and still repairs.
healthy
printf 'aperire-advisord.service enabled\n' > "$TMP/state/units"
: > "$TMP/state/has-model"
rm -f "$TMP/wrapper/node-wrapper.conf"
mv "$TMP/op/aperire-one/scripts/state-file.py" "$TMP/state-file.away"
out="$(run_sut --yes)"; rc=$?
mv "$TMP/state-file.away" "$TMP/op/aperire-one/scripts/state-file.py"
if [[ $rc -eq 0 ]] && grep -q '^wrapper ' "$TMP/state/install-args" 2>/dev/null
then ok "a complete host that cannot replant still has its wrapper configured"
else bad "no-replant branch repairs the wrapper" "exit $rc: $(cat "$TMP/state/install-args" 2>/dev/null) $(tail -6 <<<"$out")"; fi

# L5: the closing line comes after the repair. The fixture cannot plant a
# root-owned window, so this reads the order from the script itself.
repair_ln="$(grep -n '^      repair_wrapper_if_unconfigured$' "$SUT" | head -1 | cut -d: -f1)"
close_ln="$(grep -n "is all that changed" "$SUT" | head -1 | cut -d: -f1)"
if [[ -n "$repair_ln" && -n "$close_ln" && "$repair_ln" -lt "$close_ln" ]]
then ok "the closing line comes after the repair, and names it when it ran"
else bad "the closing line is after the repair" "repair line $repair_ln, closing line $close_ln"; fi

# L6: the test-only overrides are honoured by an unprivileged run and ignored
# by root. Run on their own, as root (fakeroot), from the script's own text.
if command -v fakeroot >/dev/null 2>&1; then
  { sed -n '/^wrapper_paths() {/,/^}/p' "$SUT"; } > "$TMP/wp.sh"
  # shellcheck disable=SC2016
  rp="$( cd "$TMP" && env -i PATH=/usr/bin:/bin APERIRE_ADVISOR_GET_WRAPPER_CONF=/tmp/x.conf APERIRE_ADVISOR_GET_WRAPPER_BIN=/tmp/x-bin \
         fakeroot bash -c 'WRAPPER_PATHS_SET=0; . "$1"; wrapper_paths; echo "$WRAPPER_CONF $WRAPPER_BIN"' x "$TMP/wp.sh" 2>/dev/null )"
  # shellcheck disable=SC2016
  up="$( cd "$TMP" && env -i PATH=/usr/bin:/bin APERIRE_ADVISOR_GET_WRAPPER_CONF=/tmp/x.conf APERIRE_ADVISOR_GET_WRAPPER_BIN=/tmp/x-bin \
         bash -c 'WRAPPER_PATHS_SET=0; . "$1"; wrapper_paths; echo "$WRAPPER_CONF $WRAPPER_BIN"' x "$TMP/wp.sh" 2>/dev/null )"
  if [[ "$rp" == "/etc/aperire/node-wrapper.conf /usr/local/sbin/aperire-node-wrapper" && "$up" == "/tmp/x.conf /tmp/x-bin" ]]
  then ok "as root the wrapper paths are constants; unprivileged, the test overrides apply"
  else bad "root ignores the wrapper path overrides" "root='$rp' user='$up'"; fi
else
  bad "fakeroot is needed to run wrapper_paths as root" "install fakeroot (CI has it)"
fi

echo
echo "── an Advisor that is already here, with and without a model ──────"

# Keyless is not "nothing to do". This is the host that most needs the one
# command to do something, and the something is a fresh window: an operator
# whose fifteen minutes lapsed must not have to learn a second command.
healthy
printf 'aperire-advisord.service enabled\n' > "$TMP/state/units"
out="$(run_sut --yes)"; rc=$?
if [[ $rc -eq 0 ]] && grep -q '^sealer --arm$' "$TMP/state/install-args" 2>/dev/null
then ok "an installed but keyless Advisor gets a fresh window from the same command"
else bad "a keyless Advisor is re-armed" "exit $rc: $(cat "$TMP/state/install-args" 2>/dev/null)"; fi
if ! grep -qE '^(advisord|account) ' "$TMP/state/install-args" 2>/dev/null
then ok "and nothing is rebuilt or moved to do it"
else bad "re-arming rebuilds nothing" "$(cat "$TMP/state/install-args")"; fi
if grep -qx 'trust-grant ' "$TMP/state/install-args" 2>/dev/null
then ok "and the trust-sync grant is refreshed, so an older install picks it up"
else bad "the already-installed path refreshes the trust-sync grant" "$(cat "$TMP/state/install-args")"; fi
if grep -q 'no .*language model.* yet' <<<"$out"
then ok "and it says why it did that"
else bad "the keyless state is named" "$(tail -10 <<<"$out")"; fi

# With a model, nothing needs installing. One thing still has to happen, and
# it is the only reason a complete host would run this command at all (#644).
#
# This branch used to print "Nothing was changed" and exit before any of the
# installers, which made the Add an Advisor card's "the window has closed"
# copy box a no-op on exactly the host it is written for. The window is
# planted by install-advisord.sh, and neither this branch nor the keyless
# one's --grants-only reaches that script, so the bootstrap plants it itself.
#
# Asserted on the argv that crossed sudo, which is this fixture's own way of
# watching what the bootstrap asks root to do. Whether the plant then succeeds
# depends on whether the suite is running as root, and that is not the promise
# being measured here: install-advisord.sh's and install-advisor-account.sh's
# own suites already prove the resulting file under fakeroot, from a real stat.
#
# The argv is the helper's, not `install`'s: the plant goes through
# scripts/state-file.py now, because GNU install chmods the path after
# creating the file and the account that owns advisor/state can redirect that
# last call (#661).
healthy
printf 'aperire-advisord.service enabled\n' > "$TMP/state/units"
: > "$TMP/state/has-model"
: > "$TMP/state/sudo-exec"
out="$(run_sut --yes)"; rc=$?
if [[ $rc -eq 0 ]] && grep -q 'nothing needs installing' <<<"$out"
then ok "an Advisor that already has a model installs, builds and moves nothing"
else bad "a complete Advisor installs nothing" "exit $rc: $(tail -6 <<<"$out")"; fi
if [[ ! -f "$TMP/state/install-args" ]]
then ok "and no installer runs, not even the arming"
else bad "a complete Advisor arms nothing" "$(cat "$TMP/state/install-args")"; fi
if grep -qE 'python3 .*state-file\.py plant .*advisor/state/reveal\.window 0 [0-9]+ 0640' "$TMP/state/sudo-exec" 2>/dev/null
then ok "but the reveal window IS replanted, root-owned 0640, through root"
else bad "the complete host replants the reveal window" "$(cat "$TMP/state/sudo-exec" 2>/dev/null)"; fi
if grep -q 'Opening a fresh window' <<<"$out"
then ok "and the run says that is what it is doing, before asking for sudo"
else bad "the replant is announced" "$(tail -12 <<<"$out")"; fi
if grep -q 'reveal.window' <<<"$out"
then ok "the sudo announcement names the one file root is needed for"
else bad "sudo is announced by name" "$(tail -12 <<<"$out")"; fi

# The keyless branch has the same gap for the same reason: --grants-only runs
# steps 2, 3 and 5, and step 1 is the only planter.
healthy
printf 'aperire-advisord.service enabled\n' > "$TMP/state/units"
: > "$TMP/state/sudo-exec"
out="$(run_sut --yes)"; rc=$?
if [[ $rc -eq 0 ]] && grep -qE 'python3 .*state-file\.py plant .*advisor/state/reveal\.window 0 [0-9]+ 0640' "$TMP/state/sudo-exec" 2>/dev/null
then ok "a keyless Advisor gets the window replanted too, not just the arming"
else bad "the keyless path replants the window" "exit $rc: $(cat "$TMP/state/sudo-exec" 2>/dev/null)"; fi

# The plant is never quietly skipped. This runs as an ordinary account in CI,
# so the real helper behind the fake sudo genuinely cannot give the file to
# root, and that is a free look at the failure path: the run still finishes,
# and it says the window is not open rather than leaving the operator to find
# out from a card that keeps refusing.
if [[ $EUID -ne 0 ]]; then
  if grep -q 'reveal window could not be replanted' <<<"$out" \
     || grep -q 'a fresh 15 minute window is open' <<<"$out"
  then ok "and the outcome is stated either way, never silently swallowed"
  else bad "the replant reports itself" "$(tail -12 <<<"$out")"; fi
fi

# A checkout older than scripts/state-file.py, which is the trade #661 chose:
# this file is fetched fresh every run, the helper comes from the install on
# disk, and a host that predates it is refused rather than dropped back onto
# `install`. The refusal must name the update, and it must come BEFORE sudo is
# asked for: the only thing root was wanted for here is a file this host has
# no safe way to write.
healthy
printf 'aperire-advisord.service enabled\n' > "$TMP/state/units"
: > "$TMP/state/has-model"
: > "$TMP/state/sudo-exec"
mv "$TMP/op/aperire-one/scripts/state-file.py" "$TMP/state/state-file.py.away"
out="$(run_sut --yes)"; rc=$?
mv "$TMP/state/state-file.py.away" "$TMP/op/aperire-one/scripts/state-file.py"
if [[ $rc -eq 0 ]] && grep -q 'predates the safe state-file plant' <<<"$out"
then ok "a checkout older than the plant is told so, and told what to update"
else bad "an old checkout hears why no window opened" "exit $rc: $(tail -8 <<<"$out")"; fi
# The announcement is the observable, not the fake sudo's log: `sudo -n true`
# succeeds in this fixture, so ensure_sudo returns before it records anything
# and a row watching that file would pass with the check removed. It was
# written that way first and proved nothing, checked by ablation.
if ! grep -q 'What needs root here' <<<"$out" && ! grep -q 'Opening a fresh window' <<<"$out"
then ok "and root is neither announced nor asked for, for a file that was never going to be written"
else bad "no sudo is announced when the plant cannot run" "$(tail -14 <<<"$out")"; fi

echo
echo "── the two guards ─────────────────────────────────────────────────"

# Guard 2, from the outside: a copy cut anywhere above the last line defines
# its functions and runs nothing. Cut at 70% so the cut lands inside the body.
healthy
total=$(wc -l < "$SUT")
head -n $(( total * 7 / 10 )) "$SUT" > "$TMP/cut.sh"
out="$( cd "$TMP" && env -i APERIRE_ADVISOR_GET_ROOT_LIB_DIR="$TMP/rootlib" APERIRE_RELEASE_DIGESTS="$TMP/no-release-record" PATH="$TMP/bin:/usr/bin:/bin" HOME="$TMP/op" TERM=dumb \
        APERIRE_ADVISOR_GET_REEXEC=1 bash "$TMP/cut.sh" --yes 2>&1 )"; rc=$?
# The exit code is not the promise and must not be asserted: a cut that lands
# inside a heredoc is a parse error (exit 2) and a cut that lands between
# functions runs to the missing `main` call (exit 0). Both run nothing, which
# is the whole guarantee.
if [[ ! -f "$TMP/state/install-args" ]]
then ok "a copy cut in the middle installs nothing (exit $rc, either way)"
else bad "a cut copy installs nothing" "exit $rc, args: $(cat "$TMP/state/install-args" 2>/dev/null)"; fi

# Guard 1: a piped run re-fetches itself and checks the sentinel. A whole copy
# is exec'd; a truncated one is not, and the run continues from the pipe.
healthy
cp "$SUT" "$TMP/state/self"
out="$( cd "$TMP" && env -i APERIRE_ADVISOR_GET_ROOT_LIB_DIR="$TMP/rootlib" APERIRE_RELEASE_DIGESTS="$TMP/no-release-record" PATH="$TMP/bin:/usr/bin:/bin" HOME="$TMP/op" TERM=dumb \
        APERIRE_ADVISOR_GET_SELF_URL="https://example.invalid/advisor" \
        APERIRE_ADVISOR_GET_TRIES=2 APERIRE_ADVISOR_GET_SLEEP=0 \
        bash -c "cat '$SUT' | bash -s -- --yes" 2>&1 )"
if grep -q 'self-fetch' "$TMP/state/curl-calls" 2>/dev/null
then ok "a piped run fetches itself to a file before running"
else bad "a piped run re-fetches itself" "$(cat "$TMP/state/curl-calls" 2>/dev/null)"; fi
if grep -q 'the Advisor is installed, and answering' <<<"$out"
then ok "and a whole copy runs through to the banner"
else bad "a whole re-fetched copy runs" "$(tail -4 <<<"$out")"; fi

healthy
head -n 40 "$SUT" > "$TMP/state/self"
out="$( cd "$TMP" && env -i APERIRE_ADVISOR_GET_ROOT_LIB_DIR="$TMP/rootlib" APERIRE_RELEASE_DIGESTS="$TMP/no-release-record" PATH="$TMP/bin:/usr/bin:/bin" HOME="$TMP/op" TERM=dumb \
        APERIRE_ADVISOR_GET_SELF_URL="https://example.invalid/advisor" \
        APERIRE_ADVISOR_GET_TRIES=2 APERIRE_ADVISOR_GET_SLEEP=0 \
        bash -c "cat '$SUT' | bash -s -- --yes" 2>&1 )"
if grep -q 'arrived without its last line' <<<"$out"
then ok "a truncated re-fetch is refused by the sentinel, and says so"
else bad "a truncated re-fetch is refused" "$(head -4 <<<"$out")"; fi

# The sentinel is only a guard while it is the last line.
if [[ "$(tail -n 1 "$SUT")" == '# --- end of get-aperire-advisor.sh ---' ]]
then ok "the script still ends with the sentinel a piped run checks for"
else bad "the sentinel is the last line" "$(tail -n 1 "$SUT")"; fi

echo
echo "── refusing before it can do damage ───────────────────────────────"

# A root-only login has no operator account, so there is no install to attach
# to and nothing that could own the Advisor's state.
# HOME is not an identity here. With the dashboard unit naming an install, a
# run whose HOME is root's attaches to the unit's install and not to /root: the
# home directory is a fallback for a host with no unit, never an answer that
# outranks one.
healthy
out="$( cd "$TMP" && env -i APERIRE_ADVISOR_GET_ROOT_LIB_DIR="$TMP/rootlib" APERIRE_RELEASE_DIGESTS="$TMP/no-release-record" PATH="$TMP/bin:/usr/bin:/bin" HOME=/root TERM=dumb \
        APERIRE_ADVISOR_GET_TRIES=2 APERIRE_ADVISOR_GET_SLEEP=0 \
        APERIRE_ADVISOR_GET_REEXEC=1 bash "$SUT" --yes 2>&1 )"; rc=$?
if [[ $rc -eq 0 ]] && grep -q "for        $TMP/op/aperire-one " <<<"$out"
then ok "a root HOME does not outrank the dashboard unit"
else bad "the unit outranks HOME" "exit $rc: $(grep -F 'for  ' <<<"$out")"; fi

# And with no unit at all, a root HOME has nowhere to look, so it refuses.
reset_state
: > "$TMP/state/workdir"
out="$( cd "$TMP" && env -i APERIRE_ADVISOR_GET_ROOT_LIB_DIR="$TMP/rootlib" APERIRE_RELEASE_DIGESTS="$TMP/no-release-record" PATH="$TMP/bin:/usr/bin:/bin" HOME=/root TERM=dumb \
        APERIRE_ADVISOR_GET_REEXEC=1 bash "$SUT" --yes 2>&1 )"; rc=$?
if [[ $rc -ne 0 ]] && grep -q 'no Aperire One install on this host' <<<"$out"
then ok "with no unit and a root HOME there is nothing to attach to, and it says so"
else bad "no unit and root HOME refuses" "exit $rc"; fi

# A port that is not a port would be asked for in a URL, and the check would
# fail for a reason nothing names.
out="$(run_sut --yes --port 99999)"; rc=$?
if [[ $rc -ne 0 ]] && grep -q 'takes a number from 1 to 65535' <<<"$out"
then ok "a port outside the range is named where the mistake is"
else bad "a bad port is refused" "exit $rc"; fi

out="$(run_sut --yes --nonsense)"; rc=$?
if [[ $rc -ne 0 ]] && grep -q 'unknown argument' <<<"$out"
then ok "an unknown flag stops the run rather than being ignored"
else bad "an unknown flag is refused" "exit $rc"; fi

# ── what root runs out of the install is a staged copy (#764) ─────
echo
echo "── what root runs is a staged copy of the install's own (#764) ──"
healthy
out="$(run_sut --yes)"; rc=$?
STACK_RAN="$(grep -oE '[^ ]*/install-advisor-stack\.sh' "$TMP/state/sudo-exec" 2>/dev/null | head -1)"
PREP_RAN="$(grep -oE '[^ ]*/prepare-host\.sh' "$TMP/state/sudo-exec" 2>/dev/null | head -1)"
if [[ $rc -eq 0 && "$STACK_RAN" == */run/scripts/install-advisor-stack.sh && "$PREP_RAN" == */run/scripts/prepare-host.sh \
      && "$STACK_RAN" != "$TMP/op/"* ]] && grep -q "APERIRE_INSTALL_TREE=$TMP/op/aperire-one" "$TMP/state/sudo-exec"; then
  ok "root runs a staged copy of prepare-host.sh and the stack, never the install's own, and names the install"
else
  bad "root runs the staged copies" "rc=$rc stack=$STACK_RAN prep=$PREP_RAN"
fi
# Without root's own copy of the checking libraries, root runs nothing out of
# the install, and says what puts them in place. That is --update --force
# (#982): a plain --update on a host already on the published release changes
# nothing, which is where an Advisor-only uninstall used to leave this host.
healthy
mv "$TMP/rootlib/trusted-path-lib.sh" "$TMP/rootlib/away"
out="$(run_sut --yes)"; rc=$?
mv "$TMP/rootlib/away" "$TMP/rootlib/trusted-path-lib.sh"
if [[ $rc -ne 0 && ! -f "$TMP/state/install-args" ]] && grep -q 'no root-owned copy of' <<<"$out" \
   && grep -qF -- 'bash -s -- --update --force' <<<"$out"; then
  ok "with no root-owned checking library, nothing out of the install is run as root, and the update named is one that puts it back"
else
  bad "the stage needs root's own libraries" "rc=$rc args=$(cat "$TMP/state/install-args" 2>/dev/null) $(tail -3 <<<"$out")"
fi
# A file in the install changed after its release was recorded: refused,
# named, and nothing runs.
healthy
{ printf '# anchor a fixture\n'
  (cd "$TMP/op/aperire-one" && for f in install.sh aperire-one scripts/*; do
     [[ -f "$f" ]] && printf '%s  %s\n' "$(sha256sum < "$f" | cut -c1-64)" "$f"; done)
} > "$TMP/record"
chmod 0644 "$TMP/record"
printf '#!/usr/bin/env bash\necho TREE RAN >> "%s/state/TREE-RAN"\n' "$TMP" > "$TMP/op/aperire-one/scripts/prepare-host.sh"
out="$( cd "$TMP" && env -i APERIRE_ADVISOR_GET_ROOT_LIB_DIR="$TMP/rootlib" APERIRE_RELEASE_DIGESTS="$TMP/record" \
        PATH="$TMP/bin:/usr/bin:/bin" HOME="$TMP/op" TERM=dumb \
        APERIRE_ADVISOR_GET_SELF_URL="https://example.invalid/advisor" APERIRE_ADVISOR_GET_TRIES=2 APERIRE_ADVISOR_GET_SLEEP=0 \
        bash "$SUT" --yes 2>&1 )"; rc=$?
if [[ $rc -ne 0 && ! -f "$TMP/state/TREE-RAN" && ! -f "$TMP/state/install-args" ]] \
   && grep -q 'refused: scripts/prepare-host.sh is not the file this release shipped' <<<"$out"; then
  ok "a prepare-host.sh changed after the release was recorded is never run by root"
else
  bad "a changed installer is never run by root" "rc=$rc ran=$(cat "$TMP/state/TREE-RAN" 2>/dev/null) $(tail -4 <<<"$out")"
fi
make_install "$TMP/op/aperire-one"

# ── advisor_token, as root, follows no link (#764) ──────────────────
# Under `curl ... | sudo bash` the token read is root's, in a directory the
# Advisor's own account owns. A plain cat of a link there sent the target's
# lines out as a bearer token. The function is run on its own, as root
# (fakeroot), with the staged tool standing in for RUN_TREE's.
if command -v fakeroot >/dev/null 2>&1; then
  TOKT="$TMP/tokrow"; rm -rf "$TOKT"; mkdir -p "$TOKT/inst/advisor/state" "$TOKT/stage/scripts"
  cp "$REPO_DIR/scripts/state-file.py" "$TOKT/stage/scripts/"
  { sed -n '/^own_code() {/,/^}/p' "$SUT"; sed -n '/^advisor_token() {/,/^}/p' "$SUT"; } > "$TOKT/fn.sh"
  printf 'ROOT-ONLY-SECRET\n' > "$TOKT/secret"; chmod 600 "$TOKT/secret"
  tok_as_root() {  # prints what advisor_token yields as root
    # shellcheck disable=SC2016  # the inner shell's own positional parameter
    ( cd "$TOKT" && env -i PATH=/usr/bin:/bin DIR="$TOKT/inst" RUN_TREE="$TOKT/stage" \
        fakeroot bash -c '. "$1"; advisor_token' x "$TOKT/fn.sh" 2>/dev/null )
  }
  printf 'real-token\n' > "$TOKT/inst/advisor/state/approve.token"
  got="$(tok_as_root)"
  if [[ "$got" == real-token ]]; then ok "as root, the token is read from a plain file through the staged tool"
  else bad "root reads a plain approve.token" "got '$got'"; fi
  rm -f "$TOKT/inst/advisor/state/approve.token"; ln -s "$TOKT/secret" "$TOKT/inst/advisor/state/approve.token"
  got="$(tok_as_root)"
  if [[ -z "$got" ]]; then ok "as root, a link at approve.token yields no token, and none of its target goes out as one"
  else bad "root reads approve.token without following a link" "got '$got'"; fi
else
  bad "fakeroot is needed to run advisor_token as root" "install fakeroot (CI has it)"
fi

echo
printf '  %d passed, %d failed\n\n' "$PASS" "$FAIL"
[[ $FAIL -eq 0 ]]
