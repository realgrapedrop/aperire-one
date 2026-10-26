#!/usr/bin/env bash
# install-advisor-stack.sh - everything an Advisor host gets, in one place.
#
#   sudo bash scripts/install-advisor-stack.sh
#
# There are two ways to add the Advisor to a host, and until this script
# existed they produced two different hosts. The one-line install
# (`curl -fsSL https://get.aperire.one/advisor | bash`) installed the service,
# both root grants, the account and the trust store. `install.sh --with-advisor`
# installed the service and the account, and nothing else: no sealer socket, so
# the browser had no model step to offer, and no trust-sync grant, so a passkey
# enrolled in the browser never reached the Advisor at all. Same flag, same
# documentation, different host.
#
# So the sequence lives here, once, and both paths call it. What it runs, in
# this order, and it owns none of them:
#
#   1. scripts/install-advisord.sh          the build, the unit, the privilege
#                                           wrapper and the first start
#   2. scripts/install-model-key-sealer.sh  the socket behind which one root
#                                           program seals a model key, armed
#   3. scripts/install-trust-sync-grant.sh  the socket behind which one root
#                                           program hands a browser-enrolled
#                                           passkey to the Advisor
#   4. scripts/install-advisor-account.sh   the move onto a dedicated account
#                                           that reaches the node through a
#                                           root socket, never sudo
#   5. scripts/aperire-auth.sh advisor-sync the Advisor's own copy of who may
#                                           approve, for a passkey enrolled
#                                           before it was installed
#   6. the read-back                        enabled, running, and answering on
#                                           /v1/status, before anything is
#                                           claimed
#
# Steps 2, 3 and 5 are degradations when they fail, not failures: an Advisor
# without the browser grants still reads, plans and answers. Each one says
# what was lost and what to run instead. Steps 1 and 6 are fatal, because
# there is no Advisor at all without them.
#
# Step 4 sits between the two. A refused move puts the previous arrangement
# back, so the rest still runs and the read-back still happens, but an
# Advisor left on the dashboard's account is the mode ADR 0025 retired, on
# every host shape, an aggregator included. So the run ends with exit 3 and a
# closing block that names the step to run again, never with 0 (#806).
#
# On a host with no Advisor unit yet there is no previous arrangement to put
# back: step 1 writes the unit naming the Advisor's own account and leaves it
# stopped, so that no unit names the operator's login while root copies files
# (#893), and step 4 is what starts it. A refused move there leaves an Advisor
# that is installed and not running, and the read-back ends the run with 1.
#
# Exit codes: 0 everything, 1 a fatal step or the read-back, 3 installed and
# answering, but still on the dashboard's account.
#
# Flags (--flag value and --flag=value both work):
#   --dir <path>       the Aperire One install to work in. Defaults to the
#                      checkout this script is in, which is what both callers
#                      want; it is a flag because the bootstrap resolves the
#                      install from the running dashboard's own unit and hands
#                      the answer down rather than resolving it twice.
#   --port <n>         the port advisord listens on (default 7810, or
#                      APERIRE_ADVISOR_PORT)
#   --instance <name>  the pairing this Advisor belongs to (ADR 0009), default
#                      APERIRE_INSTANCE. Empty is the single-node layout.
#   --shared-account   retired (ADR 0025): accepted, says so, and step 4 runs
#                      anyway. The Advisor always gets its own account, on
#                      Ubuntu 22.04 as on 24.04, and reaches the node only
#                      through a root socket.
#   --grants-only      steps 2, 3 and 5 only. For a host whose Advisor is
#                      already installed and answering and whose fifteen minute
#                      model window has lapsed: nothing is rebuilt, nothing is
#                      moved, and a fresh window is opened.
#   --tries <n>        how many times the read-back asks /v1/status (default 10)
#   --sleep <n>        seconds between those tries (default 1)
#   --report <path>    write what happened to this file, for a caller that has
#                      a closing summary to print. See below.
#   --model-steps      print the operator's next steps and do nothing else.
#   --yes, -y          accepted and always true: this script asks nothing. Every
#                      sub-installer is given /dev/null for a stdin so a CLI
#                      ceremony cannot open in the middle of a run nobody is
#                      watching.
#   --help, -h
#
# ---- the report ------------------------------------------------------
#
# Both callers print their own closing text, and what that text may say
# depends on what happened here: a host whose sealer could not be armed must
# not be sent to a browser. So --report names a file this script writes
# key=value lines into, rewritten after every step, and the caller reads it.
#
# It is read fail-closed on purpose. A run that died before writing leaves the
# file missing or half-written, and every flag in it is then false, so the
# caller names the terminal fallback rather than a browser step that cannot
# work. A missing measurement is never a passing one.
#
# Nothing secret goes in it: three outcomes, a path and a port.

set -euo pipefail

STACK_SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="${APERIRE_INSTALL_TREE:-$(cd "$STACK_SELF/.." && pwd)}"
[[ -r "$STACK_SELF/term-style.sh" ]] \
  || { echo "error: $STACK_SELF/term-style.sh is missing from this checkout" >&2; exit 1; }
# shellcheck source=scripts/term-style.sh
. "$STACK_SELF/term-style.sh"

DIR="$REPO"
PORT="${APERIRE_ADVISOR_PORT:-7810}"
INSTANCE="${APERIRE_INSTANCE:-}"
GRANTS_ONLY=0
MODEL_STEPS_ONLY=0
HEALTH_TRIES=10
HEALTH_SLEEP=1
REPORT=""

# What the caller is told, and what the closing text is allowed to claim.
SEALER_READY=0
TRUST_GRANT_READY=0
ACCOUNT_MOVED=0
ANSWERING=0

step() { printf '\n%s%s%s\n' "$S_BOLD" "$*" "$S_OFF"; }
info() { printf '  %s\n' "$*"; }
ok()   { printf '  %sok    %s%s\n' "$S_GREEN" "$*" "$S_OFF"; }
warn() { printf '  %s!!    %s%s\n' "$S_AMBER" "$*" "$S_OFF"; }
dim()  { printf '  %s%s%s\n' "$S_DIM" "$*" "$S_OFF"; }
die()  { printf '\n%serror: %s%s\n' "$E_RED" "$*" "$E_OFF" >&2; exit 1; }

usage() {
  awk '/^[^#]/{exit} NR>1{sub(/^# ?/,""); print}' "${BASH_SOURCE[0]}"
}

advisor_unit() { printf 'aperire-advisord%s' "${INSTANCE:+-$INSTANCE}"; }

# The operator this install belongs to, named in the one message that has to
# name an account: "it is still running as <someone>". Under sudo that is the
# invoking account; run straight from install.sh as root there is no such
# account, so the install's own owner is the answer, which is who it would
# have been either way.
op_user() {
  if [[ -n "${SUDO_USER:-}" ]]; then printf '%s' "$SUDO_USER"; return 0; fi
  local owner; owner="$(stat -c %U "$DIR" 2>/dev/null || true)"
  printf '%s' "${owner:-$(id -un)}"
}

write_report() {
  [[ -n "$REPORT" ]] || return 0
  cat > "$REPORT" <<EOF
dir=$DIR
port=$PORT
sealer_ready=$SEALER_READY
trust_grant_ready=$TRUST_GRANT_READY
account_moved=$ACCOUNT_MOVED
answering=$ANSWERING
EOF
  # Root writes this file and the operator's own account reads it back, in all
  # three callers: the closing text is printed as the operator, from what the
  # privileged half reported. Root's umask decides the mode this file is
  # created with, and a host that sets it to 077 would leave every readback
  # unreadable, which reads as fail-closed and names the terminal on a host
  # whose browser could seal perfectly. Set the mode rather than inherit it.
  # Nothing secret is in here: three outcomes, a path and a port.
  chmod 0644 "$REPORT" 2>/dev/null || true
}

# One key out of a report written by an earlier run of this script. Absent
# file, absent key and unreadable file all answer 0, which is what fail-closed
# means here: --model-steps then names the terminal, never the browser.
report_value() { # $1 = key
  [[ -n "$REPORT" && -r "$REPORT" ]] || { printf '0'; return 0; }
  local v
  v="$(sed -n "s/^$1=//p" "$REPORT" 2>/dev/null | head -1)"
  printf '%s' "${v:-0}"
}

# -- The steps -------------------------------------------------------
#
# Every sub-installer gets /dev/null for a stdin. install-advisord.sh offers
# the CLI model ceremony when it has a terminal, and that ceremony does not
# belong in the middle of an install: it needs a provider, a key and a choice
# of model, and the closing text below names where those are answered.
run_advisord_install() {
  step "installing the Advisor"
  info "running ${DIR}/scripts/install-advisord.sh"
  # APERIRE_ADVISOR_ACCOUNT_NEXT: this run moves the Advisor onto its own
  # account in step 4, so on a host with no Advisor running yet the unit is
  # written naming that account and left for step 4 to start. A unit naming
  # the operator's login in between makes root refuse every checked copy
  # (#893).
  APERIRE_ADVISOR_PORT="$PORT" APERIRE_INSTANCE="$INSTANCE" APERIRE_ADVISOR_ACCOUNT_NEXT=1 \
    bash "$CODE/install-advisord.sh" < /dev/null \
    || die "install-advisord.sh did not finish. Nothing further was attempted; read what it printed above."
}

# Installed on every host, and armed, because an Advisor that watches other
# nodes still answers questions and answering needs a model. Before the
# account move, which a host with no node legitimately cannot run.
run_sealer_install() {
  step "letting the model step happen in your browser"
  info "running ${DIR}/scripts/install-model-key-sealer.sh"
  # The instance goes with it (#949): the sealer reads that instance's own
  # wrapper configuration to ask its node who it is, and checks that
  # instance's Advisor unit for a stale credential drop-in.
  if APERIRE_INSTANCE="$INSTANCE" bash "$CODE/install-model-key-sealer.sh" --arm < /dev/null; then
    SEALER_READY=1
    write_report
    return 0
  fi
  SEALER_READY=0
  write_report
  echo
  warn "the browser model step is not available on this host."
  dim "Everything else is installed. The model can still be set up here:"
  dim "  bash ${DIR}/aperire-one   ->  3) Advisor  ->  model setup"
}

# Without this the CLI mutations sync the trust store and the one change the
# CLI cannot see, a passkey enrolled in the browser, leaves it stale until an
# operator runs a command on the box.
run_trust_grant_install() {
  step "letting a browser enrollment reach the Advisor"
  info "running ${DIR}/scripts/install-trust-sync-grant.sh"
  if bash "$CODE/install-trust-sync-grant.sh" < /dev/null; then
    TRUST_GRANT_READY=1
    write_report
    return 0
  fi
  TRUST_GRANT_READY=0
  write_report
  echo
  warn "a passkey enrolled in the browser will not reach the Advisor by itself on this host."
  dim "Everything else is installed. After enrolling, hand it over yourself:"
  dim "  bash ${DIR}/scripts/aperire-auth.sh advisor-sync"
}

run_account_install() {
  step "moving it onto its own account"
  info "running ${DIR}/scripts/install-advisor-account.sh"
  if APERIRE_ADVISOR_PORT="$PORT" APERIRE_INSTANCE="$INSTANCE" \
       bash "$CODE/install-advisor-account.sh" < /dev/null; then
    ACCOUNT_MOVED=1
    write_report
    return 0
  fi
  ACCOUNT_MOVED=0
  write_report
  echo
  if systemctl is-active --quiet "$(advisor_unit)" 2>/dev/null; then
    warn "the Advisor is still running as $(op_user), not on its own account."
  else
    warn "the Advisor is installed but not started: the account it starts as was not set up."
  fi
  # Not a supported end state any more, on any systemd (ADR 0025): the move
  # works on 22.04 now, and on a host with no node as well. What it printed
  # above is the reason; it put the previous arrangement back itself.
  dim "The account installer's own lines above say why, and it put back what was"
  dim "there. Once that is fixed, run it again:"
  if [[ -n "$INSTANCE" ]]; then
    dim "  curl -fsSL https://get.aperire.one | bash -s -- --dir ${DIR} --run advisor-account --instance $INSTANCE"
  else
    dim "  curl -fsSL https://get.aperire.one | bash -s -- --update --force"
    dim "  (at a terminal, and answer Y when it offers to move the Advisor)"
  fi
}

# -- The trust store, so the first approval works ---------------------
#
# The Advisor checks passkey approvals against its OWN copy of the operators'
# public keys. A browser enrollment asks for that copy to be rebuilt through
# the grant above, but an operator who enrolled BEFORE the Advisor was
# installed has a passkey the Advisor has never heard of, and would meet
# "trust store is stale: checking approvals against 0 passkeys" the first time
# they try to approve anything. That is what this closes.
#
# It runs on the one occasion where nothing can be lost by running it: a store
# that is not there yet, or one holding no keys. A store WITH keys is left
# exactly alone, because on a fleet node those came from an issuer's signed
# bundle and a local sync would replace them with this box's own idea of who
# may approve.
#
# After the account step, and that ordering is the load-bearing one: the sync
# writes into the state directory the Advisor owns, and which account owns it
# is settled by the move. It does not wait on the read-back, because a service
# that never answers is a repair, and a trust store that was synced on the way
# there is one less thing to redo.
#
# Run exactly as this script was started, which is as root. The sync works out
# for itself which account may write the state directory and elevates to it;
# demoting to the operator here would be worse, because that account's sudo
# credentials are not cached inside a root shell with no terminal. It finds the
# install owner's node for itself when root has no nvm (#211).
run_trust_sync() {
  local store="$DIR/advisor/state/credentials.json" out held
  step "handing your passkeys to the Advisor"

  if [[ ! -d "$DIR/advisor/state" ]]; then
    info "the Advisor has no state directory here, so there is nothing to sync into."
    return 0
  fi

  if [[ -e "$store" ]]; then
    if [[ ! -r "$store" ]]; then
      info "this account cannot read the Advisor's trust store, so it is left alone."
      dim "  bash ${DIR}/scripts/aperire-auth.sh advisor-sync   (when you need to update it)"
      return 0
    fi
    held="$(grep -c '"credential_id"' "$store" 2>/dev/null || true)"
    if [[ "${held:-0}" -gt 0 ]]; then
      ok "the Advisor already trusts ${held} passkey(s); left as it is"
      return 0
    fi
  fi

  if ! out="$(bash "$CODE/aperire-auth.sh" advisor-sync 2>&1)"; then
    warn "the trust store was not synced, so approvals would be refused."
    # The sync's own words, not a summary of them: a refusal with its reason
    # kept back was a warning nobody could act on (#211).
    if [[ -n "$out" ]]; then
      dim "It said:"
      while IFS= read -r line; do dim "  $line"; done <<<"$out"
    fi
    dim "Run it yourself once that is put right:"
    dim "  bash ${DIR}/scripts/aperire-auth.sh advisor-sync"
    return 0
  fi

  # The sync's own count, taken from its own output. Nothing here recounts the
  # database: two answers to "who may approve" is one too many.
  local trusted
  trusted="$(sed -n 's/.*[^0-9]\([0-9][0-9]*\) trusted.*/\1/p' <<<"$out" | tail -n1)"
  if [[ "${trusted:-0}" -gt 0 ]]; then
    ok "trust store synced: ${trusted} passkey(s) may approve on this host"
    return 0
  fi

  info "no operator has enrolled a passkey yet, so the Advisor trusts none."
  if [[ $TRUST_GRANT_READY -eq 1 ]]; then
    dim "Enroll in the dashboard; the Advisor is handed the key as you do."
  else
    dim "Enroll in the dashboard first, then hand it your key from here:"
    dim "  bash ${DIR}/scripts/aperire-auth.sh advisor-sync"
  fi
}

# -- Verify, before anything is claimed ------------------------------
#
# The token every /v1 endpoint requires, reads included. Without it the check
# gets a 401 and reports a working service as broken.
advisor_token() {
  tr -d '\n' < "$DIR/advisor/state/approve.token" 2>/dev/null || true
}

advisor_answers() {
  local token
  token="$(advisor_token)"
  [[ -n "$token" ]] || return 1
  # On curl's standard input, never its argv: /proc/<pid>/cmdline is world
  # readable (#705).
  curl -fsS --max-time 3 -H @- \
    "http://127.0.0.1:${PORT}/v1/status" >/dev/null 2>&1 <<<"authorization: Bearer $token"
}

verify_failed() {
  warn "the Advisor did not answer on http://127.0.0.1:${PORT}/v1/status."
  cat <<EOF

  This is the check, not the install: everything the installers did is still
  in place and still enabled. What to read, in this order:

      systemctl status $(advisor_unit) --no-pager
      sudo journalctl -u $(advisor_unit) -n 50 --no-pager

  Then ask it yourself, which is exactly what failed above:

      curl -fsS -H @- http://127.0.0.1:${PORT}/v1/status \\
        <<<"authorization: Bearer \$(tr -d '[:space:]' < ${DIR}/advisor/state/approve.token)"
EOF
  exit 1
}

# Three readings, in the order that makes a failure legible: a unit that is not
# enabled comes back differently after a reboot, a unit that is enabled but not
# active never started, and one that is active but silent is the only case
# where the log is the next thing to read.
verify_service() {
  local i
  step "checking that it answers"

  systemctl is-enabled --quiet "$(advisor_unit)" 2>/dev/null \
    || die "$(advisor_unit) is installed but not enabled, so it would not come back after a reboot. Read: systemctl status $(advisor_unit)"
  ok "enabled, so it comes back after a reboot"

  systemctl is-active --quiet "$(advisor_unit)" 2>/dev/null \
    || die "$(advisor_unit) is enabled but not running. Read: sudo journalctl -u $(advisor_unit) -n 50"
  ok "running"

  info "asking http://127.0.0.1:${PORT}/v1/status, up to ${HEALTH_TRIES} times"
  for (( i = 1; i <= HEALTH_TRIES; i++ )); do
    if advisor_answers; then
      ANSWERING=1
      write_report
      ok "/v1/status answered"
      return 0
    fi
    sleep "$HEALTH_SLEEP"
  done
  ANSWERING=0
  write_report
  verify_failed
}

# Last, after the read-back, so it is the final thing on the screen rather
# than a line buried under the trust sync and the status checks. The Advisor
# is installed and answering; what is wrong is the account it answers from.
account_not_moved_closing() {
  [[ $ACCOUNT_MOVED -eq 1 ]] && return 0
  echo
  printf '  %s───── the Advisor is NOT on its own account ─────%s
' "$S_AMBER" "$S_OFF"
  echo
  warn "it runs as $(op_user), the dashboard's account, which is a retired arrangement."
  dim "The account move refused and put the previous unit back; its own lines"
  dim "above say why. Once that is put right, finish the move:"
  if [[ -n "$INSTANCE" ]]; then
    dim "  curl -fsSL https://get.aperire.one | bash -s -- --dir ${DIR} --run advisor-account --instance $INSTANCE"
  else
    dim "  curl -fsSL https://get.aperire.one | bash -s -- --update --force"
    dim "  (at a terminal, and answer Y when it offers to move the Advisor)"
  fi
  echo
  exit 3
}

# -- The one step left, and where it happens -------------------------
#
# Printed by whichever caller has a closing summary, so the two paths cannot
# drift into two different instructions. Which of the two branches is taken is
# decided by whether the sealer armed, not by which one reads better: a host
# whose browser cannot seal must not be sent to a browser.
print_model_steps() {
  if [[ "$(report_value sealer_ready)" == "1" ]]; then
    cat <<EOF
  ${S_BOLD}One step left: it has no language model yet.${S_OFF} Without one it still reads,
  still plans and still keeps its ledger; what it cannot do is answer a
  question in your words.

  ${S_BOLD}Set one up in your browser, within fifteen minutes:${S_OFF}

      1. Refresh the dashboard.
      2. Open the menu (top right) and choose ${S_BOLD}Settings${S_OFF}.
      3. Open ${S_BOLD}Advisor AI model${S_OFF}, the last panel. It is there now
         that an Advisor is.
      4. Choose a provider, paste your key, press Test, pick a model, and
         seal it with your passkey.

  Once it is sealed, the Advisor tab answers.

  That window is open for ${S_BOLD}fifteen minutes${S_OFF}. If it lapses before you get to
  it, nothing is lost: run this same command again to open another.

      ${S_CYAN}curl -fsSL https://get.aperire.one/advisor | bash${S_OFF}

EOF
  else
    cat <<EOF
  ${S_BOLD}One step left: it has no language model yet.${S_OFF} Without one it still reads,
  still plans and still keeps its ledger; what it cannot do is answer a
  question in your words. Setting one up needs a provider, a key and a choice
  of model:

      ${S_CYAN}bash ${DIR}/aperire-one${S_OFF}

  and choose ${S_BOLD}3) Advisor${S_OFF}, then ${S_BOLD}6) Set up / change the model${S_OFF}.

EOF
  fi
}

main() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --dir)            DIR="${2:?--dir needs a path}"; shift 2 ;;
      --dir=*)          DIR="${1#*=}"; shift ;;
      --port)           PORT="${2:?--port needs a number}"; shift 2 ;;
      --port=*)         PORT="${1#*=}"; shift ;;
      --instance)       INSTANCE="${2-}"; shift 2 ;;
      --instance=*)     INSTANCE="${1#*=}"; shift ;;
      --tries)          HEALTH_TRIES="${2:?--tries needs a number}"; shift 2 ;;
      --tries=*)        HEALTH_TRIES="${1#*=}"; shift ;;
      --sleep)          HEALTH_SLEEP="${2:?--sleep needs a number}"; shift 2 ;;
      --sleep=*)        HEALTH_SLEEP="${1#*=}"; shift ;;
      --report)         REPORT="${2-}"; shift 2 ;;
      --report=*)       REPORT="${1#*=}"; shift ;;
      --shared-account)
        # Retired (ADR 0025). Said once, then ignored, so a scripted install
        # that still passes it gets the stronger shape rather than a failure.
        info "--shared-account is retired: the Advisor always gets its own account now."
        shift ;;
      --grants-only)    GRANTS_ONLY=1; shift ;;
      --model-steps)    MODEL_STEPS_ONLY=1; shift ;;
      --yes|-y)         shift ;;
      -h|--help)        usage; exit 0 ;;
      *)                die "unknown argument: $1 (run with --help)" ;;
    esac
  done

  [[ "$PORT" =~ ^[0-9]+$ && $PORT -ge 1 && $PORT -le 65535 ]] \
    || die "--port takes a number from 1 to 65535, not '$PORT'."
  [[ "$HEALTH_TRIES" =~ ^[0-9]+$ && $HEALTH_TRIES -ge 1 ]] \
    || die "--tries takes a number of 1 or more, not '$HEALTH_TRIES'."
  # Checked here, where the flag is named. It reaches `sleep` inside the
  # read-back loop, and a value sleep cannot parse would end that loop with
  # sleep's own complaint about a word nothing on screen connects to a flag.
  [[ "$HEALTH_SLEEP" =~ ^[0-9]+([.][0-9]+)?$ ]] \
    || die "--sleep takes a number of seconds, not '$HEALTH_SLEEP'."
  # A report path that is a symlink would have this script write through it as
  # root. The callers make their own with mktemp; anything else is a mistake
  # worth refusing rather than following.
  [[ -z "$REPORT" || ! -L "$REPORT" ]] || die "--report must not be a symlink: $REPORT"

  # Printing is not installing, so it is answered before the checks that only
  # an install needs. It reads a report and a directory and touches nothing.
  if [[ $MODEL_STEPS_ONLY -eq 1 ]]; then
    print_model_steps
    exit 0
  fi

  [[ -f "$DIR/scripts/install-advisord.sh" ]] \
    || die "$DIR is not an Aperire One install: it has no scripts/install-advisord.sh."
  # The installers this runs. Under install.sh run from a copy root staged
  # out of the release (APERIRE_INSTALL_TREE set), its own staged siblings,
  # acting on --dir; root never runs the tree's bytes then (#764). Run by
  # hand against a --dir, that install's own scripts, as before.
  if [[ -n "${APERIRE_INSTALL_TREE:-}" ]]; then
    CODE="$STACK_SELF"
    APERIRE_INSTALL_TREE="$(cd "$DIR" && pwd)"
    export APERIRE_INSTALL_TREE
  else
    CODE="$DIR/scripts"
  fi

  # No root check here, deliberately. This script installs nothing itself; it
  # runs four installers that each refuse by name without root, and both
  # callers have already made sure of it (install.sh refuses a non-root role,
  # the bootstrap announces sudo and gets it before this is reached). A fifth
  # copy of the rule would be a fifth place to keep true.

  write_report

  if [[ $GRANTS_ONLY -eq 1 ]]; then
    run_sealer_install
    run_trust_grant_install
    run_trust_sync
    exit 0
  fi

  run_advisord_install
  run_sealer_install
  run_trust_grant_install
  run_account_install
  run_trust_sync
  verify_service
  account_not_moved_closing
}

main "$@"
