#!/bin/bash
# aperire — THE operator entry point. Install, configure, operate, verify:
# one script the operator runs; everything else under scripts/ is plumbing
# this menu invokes and nothing an operator needs to type again (operator
# ruling, 2026-08-14: "one script runs all — fewer things to worry about";
# the v3 dashboard proved the pattern). Install the CLI shortcut from the
# Install menu and the command becomes just `aperire-one`, from anywhere.
#
# A THIN wrapper, deliberately: every entry prints
# the real command before running it, so the menu teaches the scripts
# rather than hiding them, and the scripts stay the single source of
# truth. Nothing here duplicates logic; if an entry needs more than
# "run the script", the script is where that belongs.
#
# Run from anywhere: the repo root is derived from this file's own
# location, which is the fix for "bash scripts/... : No such file".
#
# readlink -f, because the CLI installer puts a symlink at ~/.local/bin/aperire
# and BASH_SOURCE is then the symlink, not the script. Without it the menu
# invoked as `aperire-one` resolved REPO to ~/.local and every entry died on a
# path that does not exist — the one way it is meant to be run.
set -u

REPO="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/.." && pwd)"
S="$REPO/scripts"

# The one palette, the same one the install path is dressed in. Every S_ below
# is the empty string unless stdout is a terminal, NO_COLOR is unset and TERM
# is not dumb, so `aperire-one` piped, redirected or logged is byte-plain. This
# menu had the escapes written in by hand and unconditionally, which made it
# the one surface that ignored NO_COLOR while the install path honoured it.
# The cyan-for-a-command here is the precedent the shared palette was built
# against, so it means exactly what it always did.
# shellcheck source=scripts/term-style.sh
. "$S/term-style.sh"

# The screen clear is cursor control, not colour, so it does NOT follow
# NO_COLOR: no-color.org is about colour and has nothing to say about where
# the cursor goes. It does follow the rest of the check, because a clear
# written into a log file is junk in the file and a dumb terminal cannot act
# on it either. Defined here rather than in term-style.sh: that file's palette
# block is byte-compared against the inline copy in get-aperire.sh by
# scripts/test-get-aperire.sh, and a line added to one and not the other fails
# that test for no reason.
S_CLEAR=''
if [[ -t 1 && "${TERM:-}" != "dumb" ]]; then S_CLEAR=$'\033[H\033[2J'; fi

# The Advisor's unit, port and token, derived ONCE and used by every Advisor
# entry below. The unit name matches setup-advisor-model.sh and
# install-advisord.sh exactly, instance suffix included: a second dashboard on
# one host installs "aperire-advisord-node2", and a menu that says
# "aperire-advisord" restarts the wrong service or none at all. That was a
# real bug here, in the maintenance entry, before this.
ADVISORD_UNIT="aperire-advisord${APERIRE_INSTANCE:+-$APERIRE_INSTANCE}"
ADVISOR_PORT="${APERIRE_ADVISOR_PORT:-7810}"
# Overridable like the port beside it, and for the same reason: it is what
# lets the absent branch be exercised on a host that HAS an Advisor, without
# going anywhere near the real token.
ADVISOR_TOKEN="${APERIRE_ADVISOR_TOKEN:-$REPO/advisor/state/approve.token}"

# What the co-located relay item (Maintenance 4) reads this host off, derived
# here with everything else rather than inside the entry. The dashboard's own
# environment file is where the service installer writes this instance's port
# and never overwrites it, so that file is what a :7900 node host says about
# itself; the relay program lives at the installed path on a host that has one
# and in this checkout's build directory on a host that has just built one.
#
# All three overridable, like ADVISOR_TOKEN above and for the same reason: a
# box that HAS a relay binary cannot otherwise exercise the branch that
# refuses when there is none.
ETC_APERIRE="${APERIRE_ETC_DIR:-/etc/aperire}"
RELAY_BIN_INSTALLED="${APERIRE_RELAY_BIN:-/usr/local/bin/aperire-relay}"
RELAY_BIN_BUILT="${APERIRE_RELAY_BUILD:-$REPO/relay/aperire-relay}"
# The instance suffix ADVISORD_UNIT carries, for the dashboard's own names: a
# second dashboard on one host is aperire-server-node2 with aperire-node2.env
# beside it, and a menu that names the unsuffixed pair wires the wrong one.
DASH_SUFFIX="${APERIRE_INSTANCE:+-$APERIRE_INSTANCE}"

# ── A terminal, or nothing ──────────────────────────────────────────
# The menu is a list you pick from, and `read` at EOF returns nothing. Nothing
# matches no entry, the loop paints the menu again, and a piped run spun
# forever repainting a screen with nobody in front of it. Checked here rather
# than in the loop, because everything below this line assumes a reader:
# guided setup is dispatched on a bare host before the menu is ever drawn.
# Same wording as scripts/aperire-setup.sh, and the same exit code.
# APERIRE_MENU_LIB=1 loads this file for its functions and stops before the
# TTY gate, the guided-setup dispatch and the menu loop. That is what lets the
# presence derivation below be called directly by a test: a menu cannot be
# driven by a pipe (see the gate immediately after), so logic that is only
# reachable through the menu is logic nothing can check.
if [[ "${APERIRE_MENU_LIB:-0}" != "1" ]] && [[ ! -t 0 || ! -t 1 ]]; then
  cat >&2 <<'EOF'
The operator menu needs a terminal — it is a list you choose from, and piped
input chooses nothing.

  Interactive:      bash aperire-one
  Non-interactive:  curl -fsSL https://get.aperire.one | bash -s -- --role=co-located --yes
                    (the installer takes every answer as a flag; run it with
                     --help for the full list)
EOF
  exit 2
fi

say()  { printf '\n%s%s%s\n' "$S_BOLD" "$1" "$S_OFF"; }
# Every menu change starts from a clean screen (operator request, 2026-08-20:
# stacked menus read as one long confusing scroll). The host line is repainted
# with it, every time: two identical-looking terminals on two near-identical
# boxes cost the operator the same mistake twice in one night. What machine
# you are about to change is the first fact on every screen.
paint() {
  printf '%s' "$S_CLEAR"
  printf '%sAPERIRE ONE%s   ·   host: %s   ·   %s\n' "$S_BOLD" "$S_OFF" "$(hostname)" "$REPO"
}
item() { printf '  %s) %s\n' "$1" "$2"; }
gone() { printf '  %s%s) %s (not present on this host)%s\n' "$S_DIM" "$1" "$2" "$S_OFF"; }

# Print the real command, then run it. Root is stated, never assumed: entries
# that need it say so in their label, and what the menu does is exactly what
# the operator reads.
#
# No entry runs a file in this checkout as root (#955). The checkout belongs to
# the login that installed it, and ADR 0024's rule is that root runs only a
# copy it checked. So an entry that needs root goes through the bootstrap in
# this checkout, run as you: it holds the step's arguments to a whitelist,
# asks sudo for the one root call, and has root run the release's checked copy
# (`get-aperire.sh --run <step>`, `--backup`, `--restore`). Started as root
# (`sudo bash aperire-one`), the menu is root running this checkout, which is
# the choice the operator made by typing it; the entries below still hand
# root's work to the checked copy rather than to the file beside them.
GA="$S/get-aperire.sh"
root_step() { # $1 = the step, rest = its arguments
  local step="$1"; shift
  run bash "$GA" --dir "$REPO" --run "$step" "$@"
}
run() {
  printf '\n%s$ %s%s\n\n' "$S_CYAN" "$*" "$S_OFF"
  "$@"
  local rc=$?
  printf '\n%s(exit %d — Enter to return to the menu)%s' "$S_DIM" "$rc" "$S_OFF"
  read -r
}

# A pipeline, printed and then run. `run` above takes a command and its
# arguments, which cannot express `curl | bash`, and the one-line install is a
# pipeline in every place it is written down. Same contract as `run`: the real
# command first, in the same cyan, so the menu teaches it rather than hiding it.
# The same pause `run` ends with, for an entry that refused before it ran
# anything. Without the exit status: nothing ran, and printing "exit 0" beside
# "nothing was enabled" is the small dishonesty this menu is written against.
menu_pause() {
  printf '\n%s(Enter to return to the menu)%s' "$S_DIM" "$S_OFF"
  read -r
}

run_pipeline() { # $1 = the command line
  printf '\n%s$ %s%s\n\n' "$S_CYAN" "$1" "$S_OFF"
  bash -c "$1"
  local rc=$?
  printf '\n%s(exit %d — Enter to return to the menu)%s' "$S_DIM" "$rc" "$S_OFF"
  read -r
}

# Where this host's releases come from.
#
# The .release stamp the bootstrap writes names the ARCHIVE it fetched, and
# the bootstrap is served from the directory above it, so the stamp is read
# and the last element dropped: piping release.tar.gz into bash would be a
# funny way to update. A host with no stamp, or one naming something that is
# not an https archive, gets the published endpoint, which is where an
# ordinary install came from anyway.
#
# The stamp file is an argument so this can be exercised: a menu cannot be
# driven by a pipe, and logic only reachable through the menu is logic nothing
# can check.
# shellcheck disable=SC2120  # the test passes a stamp; the menu passes none
update_endpoint() { # $1 = the release stamp, default this checkout's
  local stamp="${1:-$REPO/.release}" url=""
  [[ -r "$stamp" ]] && url="$(sed -n 's/^[[:space:]]*"source_url": "\(.*\)",\?$/\1/p' "$stamp" | head -1)"
  case "$url" in
    http://*/release.tar.gz|https://*/release.tar.gz) printf '%s' "${url%/release.tar.gz}" ;;
    *) printf '%s' 'https://get.aperire.one' ;;
  esac
}

# The one command that moves this host to the latest release. It is the
# published bootstrap, run against the endpoint this install came from, and
# it is the same script the first install ran: it reads the role off this
# host's units, copies the database out of the tree, carries data, config and
# Advisor state into the new release, and asks before anything restarts.
menu_update_release() {
  # shellcheck disable=SC2119
  run_pipeline "curl -fsSL $(update_endpoint) | bash -s -- --update"
}

have() { [[ -e "$S/$1" ]]; }
# The prompt goes to stderr: this function's stdout IS the returned
# selection (command substitution), and a prompt on stdout would ride
# along inside it — every choice would mysteriously match nothing.
pick() { local c; printf '\n> ' >&2; read -r c; echo "$c"; }

menu_install() {
  while true; do
    paint
    say "INSTALL & UPGRADE"
    item 1 "Dashboard service (systemd unit)          [sudo]"
    item 2 "Relay — co-located on this node's box     [sudo]"
    item 3 "Advisor service, grants and account       [sudo]"
    item 4 "CLI shortcuts (aperire + aperire-auth on your PATH)"
    # Item 3 already writes the hardened unit, so 5 is a retrofit for a host
    # installed before it did, and refuses once the account move has run. Kept
    # off the top of the list rather than removed: it is still the only way to
    # harden an old unit in place, with a revert if the sandbox breaks the
    # service.
    item 5 "Harden an older Advisor unit (retrofit)   [sudo]"
    # Last, and not first: every item above installs what this checkout
    # already holds, and this one is the only one that fetches a newer
    # release. Numbering it 6 also leaves 1-5 where operators (and the rows
    # in scripts/test-aperire-menu.sh) already know them.
    item 6 "Update to the latest release              [asks for sudo]"
    item b "back"
    case "$(pick)" in
      1) root_step dashboard-service ${APERIRE_INSTANCE:+--instance "$APERIRE_INSTANCE"} ;;
      2) root_step relay ${APERIRE_INSTANCE:+--instance "$APERIRE_INSTANCE"} ;;
      3) advisor_stack_install ;;
      4) run bash "$S/install-aperire-cli.sh" ;;
      5) root_step harden-advisord ;;
      6) menu_update_release ;;
      b|q) return ;;
    esac
  done
}

menu_operators() {
  # The full account lifecycle, in the order it happens to an account:
  # exists, changes, recovers, loses access, is removed. Trust distribution
  # sits last because it is about the fleet, not any one operator.
  while true; do
    paint
    say "OPERATORS & ACCESS  (aperire-auth — email is the identity)"
    item 1 "List operators"
    item 2 "Add an operator (prints the enrollment link; role required)"
    item 3 "Change a role (admin approves, monitor observes)"
    item 4 "Re-issue a magic link (enroll a new passkey, or recover)"
    item 5 "List an operator's passkeys"
    item 6 "Revoke EVERY passkey an operator holds"
    item 7 "List an operator's live sessions"
    item 8 "Revoke one session by its id"
    item 9 "Remove an operator (passkeys, sessions and links go too)"
    item 10 "Sync the Advisor's trust store               [asks for sudo]"
    item 11 "Show what the Advisor currently trusts"
    item 12 "Push admin trust to the fleet's nodes (aggregator only)"
    item b "back"
    local c; c="$(pick)"
    case "$c" in
      1) run bash "$S/aperire-auth.sh" list ;;
      2) printf 'email: '; read -r em; printf 'role (admin|monitor): '; read -r ro
         run bash "$S/aperire-auth.sh" add "$em" --role "$ro" ;;
      3) printf 'email: '; read -r em; printf 'role (admin|monitor): '; read -r ro
         run bash "$S/aperire-auth.sh" set-role "$em" "$ro" ;;
      4) printf 'email: '; read -r em
         printf 'purpose (enroll|recover, Enter = enroll): '; read -r pu
         run bash "$S/aperire-auth.sh" magic-link "$em" ${pu:+"$pu"} ;;
      5) printf 'email: '; read -r em
         run bash "$S/aperire-auth.sh" list-credentials "$em" ;;
      6) printf 'email: '; read -r em
         printf 'revoke every passkey %s holds? they sign in again by magic link (y/N): ' "$em"
         read -r ok; [[ "$ok" == y || "$ok" == Y ]] && run bash "$S/aperire-auth.sh" revoke "$em" ;;
      7) printf 'email: '; read -r em
         run bash "$S/aperire-auth.sh" list-sessions "$em" ;;
      8) printf 'session id (from the list above): '; read -r sid
         run bash "$S/aperire-auth.sh" revoke-session "$sid" ;;
      # del cascades with no prompt of its own (it is also called by scripts),
      # so the confirmation lives here, where a human is typing.
      9) printf 'email: '; read -r em
         printf 'remove %s and everything they hold? (y/N): ' "$em"
         read -r ok; [[ "$ok" == y || "$ok" == Y ]] && run bash "$S/aperire-auth.sh" del "$em" ;;
      # No sudo in front: aperire-auth asks for it itself, for the one root
      # step, and that step is the root-owned /usr/local/sbin/aperire-trust-sync,
      # never this checkout's copy (#943, #955).
      10) run bash "$S/aperire-auth.sh" advisor-sync ;;
      11) run bash "$S/aperire-auth.sh" advisor-trust ;;
      12) run bash "$S/aperire-auth.sh" fleet-trust-push ;;
      b|q) return ;;
    esac
  done
}

# ── The Advisor's lifecycle ─────────────────────────────────────────
#
# Operator ruling, 2026-08-30: this menu owns the WHOLE Advisor lifecycle, so
# nobody has to know a unit name or a script path to manage it. The entries
# below are the same thin-wrapper shape as everything else here, and the
# scripts stay the single source of truth.

# What the dashboard observes about the Advisor on THIS host: absent, present,
# or installed-but-down (ADR 0016's three states).
#
# Derived locally rather than read from the dashboard's /api/advisor-presence,
# because that route is session-gated like everything under /api/ and a menu
# has no browser session to present. So this reproduces the same rule the
# dashboard applies, in the same ORDER, which is the part that matters: the
# token is checked first and an unreadable token means absent WITHOUT the
# service ever being contacted.
#
# --max-time, unlike the identical probe in install-advisord.sh. That one runs
# immediately after a start and a hang there is a failed install; this one is
# a menu item, and a menu that sits silently on a wedged socket is the #116
# lesson happening somewhere new.
advisor_present() {
  local tok="${ADVISOR_TOKEN}" port="${ADVISOR_PORT}" t
  if [[ ! -r "$tok" ]]; then
    echo absent; return 0
  fi
  t="$(tr -d '\n' < "$tok" 2>/dev/null || true)"
  # The same "at least 32 characters" test advisorApproveToken() applies. A
  # short file is not a token, and a host with one has not installed anything.
  if (( ${#t} < 32 )); then
    echo absent; return 0
  fi
  # The token reaches curl on its standard input (-H @-), never on its argv,
  # where any account on the host can read it in /proc (#705).
  if curl -sf --max-time 3 -H @- \
       "http://127.0.0.1:${port}/v1/status" >/dev/null 2>&1 <<<"authorization: Bearer $t"; then
    echo present; return 0
  fi
  echo installed-but-down
}

# One restart, called from the Advisor section AND from Maintenance. Shared so
# the two can never drift on the unit name or on saying what they are doing.
#
# The wait line is #116's: a stop waits for any question or node operation
# still in flight, which is usually a second and is occasionally most of a
# minute. Silence for that long reads as a hang, and an operator who breaks
# out of it does not know whether the restart happened.
advisor_restart() {
  printf '\n%s$ sudo systemctl restart %s%s\n\n' "$S_CYAN" "$ADVISORD_UNIT" "$S_OFF"
  printf '   waiting for in-flight work to finish (up to a minute)...\n'
  sudo systemctl restart "$ADVISORD_UNIT"
  local rc=$?
  if [[ $rc -eq 0 ]] && systemctl is-active --quiet "$ADVISORD_UNIT"; then
    printf '   restarted, and %s is active\n' "$ADVISORD_UNIT"
  else
    printf '   %s did not come back. See: journalctl -u %s -n 30\n' "$ADVISORD_UNIT" "$ADVISORD_UNIT" >&2
  fi
  printf '\n%s(exit %d — Enter to return to the menu)%s' "$S_DIM" "$rc" "$S_OFF"
  read -r
}

# One Advisor install, called from the Install section, from the absent
# Advisor's only way in, and from the repair on a host that already has one.
#
# It runs scripts/install-advisor-stack.sh, which is the whole sequence: the
# service, the model-key sealer socket, the trust-sync grant, the dedicated
# account, the trust store and the read-back. This menu used to run
# install-advisord.sh on its own and offer the account move as a second item,
# so a host installed from here had no sealer socket (the browser had no model
# step to offer) and no trust-sync grant (a passkey enrolled in the browser
# never reached the Advisor). The one-line install and `install.sh
# --with-advisor` both call the stack; this makes three, and one host (#243).
#
# The port and the instance are passed rather than exported: sudo's env_reset
# drops anything not on its allow-list, so an exported APERIRE_ADVISOR_PORT
# would reach the stack in a test through a fake sudo and be dropped by the
# real one, and a second instance would quietly take the defaults.
#
# The report is a file INSIDE a directory this account owns, never a bare
# mktemp file. The stack runs under sudo and writes the report as root, and
# Ubuntu refuses root writing into a file another account owns in a sticky
# directory (fs.protected_regular). That refusal cost a live run already.
advisor_stack_install() {
  local rep_dir rc
  local -a cmd
  rep_dir="$(mktemp -d -t aperire-advisor-stack.XXXXXXXX)" || {
    # Nothing was installed. Said plainly, because "the report" sounds like a
    # detail that failed after the work, and the operator would go looking for
    # an Advisor that is not there.
    printf '\n  Nothing was installed: this needs a temporary directory to hold\n'
    printf '  what the install reports, and one could not be made.\n\n'
    printf '  Run it directly once there is room:\n'
    printf '    curl -fsSL https://get.aperire.one/advisor | bash\n'
    printf '\n%s(Enter to return to the menu)%s' "$S_DIM" "$S_OFF"
    read -r
    return 1
  }
  cmd=(bash "$GA" --dir "$REPO" --run advisor-stack
       --port "$ADVISOR_PORT" ${APERIRE_INSTANCE:+--instance "$APERIRE_INSTANCE"}
       --report "$rep_dir/report" --yes)
  printf '\n%s$ %s%s\n\n' "$S_CYAN" "${cmd[*]}" "$S_OFF"
  "${cmd[@]}"
  rc=$?
  # The one step left, printed from the same file both other install paths
  # print it from, so the three cannot drift into three different
  # instructions. Which branch it prints is decided by what the run reported,
  # not by what reads better: a host whose sealer could not be armed is given
  # the terminal instead of a browser it cannot seal from, and a missing
  # report reads as not armed. Only after a run that finished, because "one
  # step left" is a lie on a host where the install itself stopped.
  if [[ $rc -eq 0 ]]; then
    echo
    bash "$S/install-advisor-stack.sh" --model-steps --dir "$REPO" --report "$rep_dir/report"
  fi
  rm -rf "$rep_dir"
  printf '\n%s(exit %d — Enter to return to the menu)%s' "$S_DIM" "$rc" "$S_OFF"
  read -r
}

menu_advisor() {
  while true; do
    paint
    say "ADVISOR"
    local st; st="$(advisor_present)"
    # The state the dashboard itself would show, named on the section it
    # belongs to, so "what does the dashboard see" is not a separate errand.
    case "$st" in
      present)
        printf '  %sthis host: the Advisor is installed and answering%s\n\n' "$S_DIM" "$S_OFF" ;;
      installed-but-down)
        printf '  %sthis host: the Advisor is installed but not answering on :%s%s\n\n' "$S_DIM" "$ADVISOR_PORT" "$S_OFF" ;;
      *)
        printf '  %sthis host: no Advisor is installed (the dashboard shows no Advisor tab)%s\n\n' "$S_DIM" "$S_OFF" ;;
    esac

    if [[ "$st" == absent ]]; then
      # Nothing that assumes a service. One way in, and the two reads that
      # work without one.
      item 1 "Install the Advisor on this host             [sudo]"
      item 2 "Test an API key against its provider (touches nothing on this host)"
      gone 3 "Restart / start / stop, status, update, model"
      item b "back"
      case "$(pick)" in
        1) advisor_stack_install ;;
        2) run bash "$S/verify-model-key.sh" ;;
        b|q) return ;;
      esac
      continue
    fi

    item 1 "Restart the Advisor service                  [sudo]"
    item 2 "Start the Advisor service                    [sudo]"
    item 3 "Stop the Advisor service                     [sudo]"
    item 4 "Status + the last 20 journal lines"
    item 5 "Update the Advisor binary from this tree     [sudo for the restart]"
    item 6 "Set up / change the model — seals the key to THIS host + restarts"
    item 7 "Is THIS host done? (checks seal, unit, service, live model)"
    item 8 "Show the model configuration (never the key)"
    item 9 "Test an API key against its provider (touches nothing on this host)"
    item 10 "Re-seal the model key after a restart        [sudo]"
    # The repair, on a host that has an Advisor: it re-runs the whole install,
    # which re-arms the sealer's fifteen minute window, re-installs both root
    # grants and moves the service onto its own account if that step was
    # skipped or could not finish the first time. Every step is idempotent, so
    # a second run neither skips nor doubles one.
    item 11 "Re-run the install (grants, account, model window)  [sudo]"
    item b "back"
    case "$(pick)" in
      1) advisor_restart ;;
      2) run sudo systemctl start "$ADVISORD_UNIT" ;;
      3) run sudo systemctl stop "$ADVISORD_UNIT" ;;
      # Two commands, both printed. --no-pager or systemctl opens a pager
      # inside the menu and the operator is left in less with no way back
      # that the menu told them about.
      4) run bash -c "systemctl status --no-pager --lines=0 '$ADVISORD_UNIT'; echo; journalctl -u '$ADVISORD_UNIT' -n 20 --no-pager" ;;
      # Not sudo in front: the build and the binary swap run as the tree
      # owner, and the script asks for the password on its own line for the
      # one privileged step, the restart. Running the whole thing as root
      # would leave the new binaries owned by root.
      5) run bash "$S/roll-prod-advisord.sh" ;;
      6) run bash "$S/setup-advisor-model.sh" ;;
      7) run bash "$S/setup-advisor-model.sh" --doctor ;;
      8) run bash "$S/setup-advisor-model.sh" --show ;;
      9) run bash "$S/verify-model-key.sh" ;;
      10) root_step reseal-model-key ${APERIRE_INSTANCE:+--instance "$APERIRE_INSTANCE"} ;;
      11) advisor_stack_install ;;
      b|q) return ;;
    esac
  done
}

menu_fleet() {
  while true; do
    paint
    say "FLEET"
    item 1 "Join a node to this dashboard's fleet (guided; --dry-run first)"
    item 2 "Join a node — DRY RUN (prints every change, writes nothing)"
    item 3 "Install the node wrapper (lets the Advisor run upgrades here)  [sudo]"
    item 4 "Show what the Advisor's peer table would become from fleet.yaml"
    item 5 "Regenerate the Advisor's peer table from fleet.yaml (writes)"
    item b "back"
    case "$(pick)" in
      1) run bash "$S/aperire-fleet-add.sh" ;;
      2) run bash "$S/aperire-fleet-add.sh" --dry-run ;;
      # Through the bootstrap's pass-through, not `sudo bash` on the installer in
      # this tree: get-aperire.sh runs as this account and itself asks sudo for
      # the one step, which runs the release's checked copy of the installer. (If
      # this menu was started as root, root runs this tree's get-aperire.sh, as it
      # already runs the menu.) The instance is named because sudo's env reset
      # would drop it (#924).
      3) run bash "$S/get-aperire.sh" --node-wrapper --dir "$REPO" ${APERIRE_INSTANCE:+--instance "$APERIRE_INSTANCE"} ;;
      4) run bash "$S/aperire-advisor-fleet-sync.sh" ;;
      5) run bash "$S/aperire-advisor-fleet-sync.sh" --write ;;
      b|q) return ;;
    esac
  done
}

# The relay on this same box (Maintenance 4).
#
# scripts/enable-relay-colocated.sh takes four arguments and refuses to run
# without them, and this entry passed none, so choosing it printed bash's own
# required-parameter message (a line number in a file the operator had not
# opened) and did nothing at all (#497). It is the only shipped surface that
# offers this, so "pass four arguments" is not the fix on its own: three of
# the four are facts about this host and the fourth sits beside this file.
#
# Read, not asked. And said out loud before the enabler runs, because the
# port in particular decides which dashboard the relay ends up pushing to,
# and a wrong one presents as a relay that starts and is never accepted.
#
# The unit comes from `systemctl list-unit-files`, the same question
# host_installed() below already asks: one question asked one way cannot
# disagree with itself about what is installed here. The port comes from the
# dashboard's own environment file, this instance's first, which is the
# resolution install-advisord.sh and install-advisor-account.sh both use.
#
# Nothing here duplicates the enabler. It still owns every decision about
# what gets written; this answers only which dashboard, which port, which
# binary and which installer, which is the one thing it cannot know.
menu_enable_relay() {
  local unit="" units u
  local port="" port_from="" env_file
  local bin="" bin_from=""
  local installer="$S/install-aperire-relay.sh"
  local -a env_files

  units="$(systemctl list-unit-files 'aperire-*' 2>/dev/null || true)"
  for u in "aperire-server${DASH_SUFFIX}" "aperire-read${DASH_SUFFIX}"; do
    if grep -q "^${u}\.service" <<<"$units"; then unit="$u"; break; fi
  done
  if [[ -z "$unit" ]]; then
    printf '\n  Nothing was enabled: no dashboard unit is installed on this\n'
    printf '  host, and this entry wires a relay to the dashboard beside it.\n'
    printf '  systemctl knows neither aperire-server%s nor aperire-read%s.\n\n' \
           "$DASH_SUFFIX" "$DASH_SUFFIX"
    printf '  Install the dashboard first (Install & upgrade, entry 1). If\n'
    printf '  this box only runs a node, the relay installs on its own:\n'
    printf '  Install & upgrade, entry 2.\n'
    menu_pause
    return 1
  fi

  env_files=("$ETC_APERIRE/aperire${DASH_SUFFIX}.env")
  [[ -n "$DASH_SUFFIX" ]] && env_files+=("$ETC_APERIRE/aperire.env")
  for env_file in "${env_files[@]}"; do
    [[ -r "$env_file" ]] || continue
    port="$(awk -F= '$1=="PORT"{sub(/^[^=]*=/,""); gsub(/"/,""); print; exit}' "$env_file")"
    if [[ -n "$port" ]]; then port_from="$env_file"; break; fi
  done
  # A port always has an answer, so this one is named as the default rather
  # than refused: 7800 is what the dashboard installer writes when nobody
  # says otherwise, and #461 is what calling a default a measurement costs.
  if [[ -z "$port" ]]; then
    port=7800
    port_from="the default, nothing here names a port"
  fi

  if [[ -x "$RELAY_BIN_INSTALLED" ]]; then
    bin="$RELAY_BIN_INSTALLED"; bin_from="installed on this host"
  elif [[ -x "$RELAY_BIN_BUILT" ]]; then
    bin="$RELAY_BIN_BUILT"; bin_from="built in this checkout"
  else
    printf '\n  Nothing was enabled: no relay program on this box, at either\n'
    printf '  place one lives.\n\n'
    printf '    %s\n' "$RELAY_BIN_INSTALLED"
    printf '    %s\n\n' "$RELAY_BIN_BUILT"
    printf '  Build it, then choose this entry again:\n'
    printf '    cd %s/relay && go build -ldflags "-s -w" -o aperire-relay .\n' "$REPO"
    menu_pause
    return 1
  fi

  if [[ ! -f "$installer" ]]; then
    printf '\n  Nothing was enabled: %s\n' "$installer"
    printf '  is missing from this checkout, and it is the half of this work\n'
    printf '  that this entry hands over rather than doing itself.\n'
    menu_pause
    return 1
  fi

  printf '\n  Read off this host, so there is nothing to answer:\n'
  printf '    dashboard unit:  %s\n' "$unit"
  printf '    dashboard port:  %s (%s)\n' "$port" "$port_from"
  printf '    relay binary:    %s (%s)\n' "$bin" "$bin_from"
  printf '    relay installer: %s, the copy the release checked\n' "${installer##*/}"
  root_step relay-colocated --unit "$unit" --port "$port" --binary "$bin"
}

# The one thing a restore needs that a menu cannot default: which set to
# read. Asked here, in cyan like a command, so the operator sees exactly
# what they typed before it runs; the script itself still refuses with the
# same named exit codes on anything the answer gets wrong.
menu_restore() {
  local from
  printf '\n%sWhich backup set? (the directory aperire-backup.sh wrote)%s\n' "$S_CYAN" "$S_OFF"
  printf '> '
  read -r from
  if [[ -z "$from" ]]; then
    printf '\n  Nothing entered; back to the menu.\n'
    menu_pause
    return 1
  fi
  # The bootstrap takes an absolute path only, so a set named from where the
  # operator stands is made absolute here, where that place is known.
  [[ "$from" == /* ]] || from="$PWD/$from"
  run bash "$GA" --dir "$REPO" --restore --from "$from"
}

menu_maintenance() {
  while true; do
    paint
    say "MAINTENANCE"
    item 1 "Restart the dashboard service            [asks for sudo]"
    # Cross-listed, not moved: this is the generic services section and the
    # dashboard restart lives here too. Both entries call the one function, so
    # the wait line and the unit name cannot drift apart.
    item 2 "Restart the Advisor service              [sudo]"
    item 3 "Set up a Cloudflare tunnel               [sudo]"
    item 4 "Enable the relay co-located on this node [sudo]"
    item 5 "Detect rippled paths (config + data dirs)"
    item 6 "Diagnose xrpld ports"
    item 7 "Back up this host's operator state           [sudo]"
    item 8 "Restore this host from a backup               [sudo]"
    item b "back"
    case "$(pick)" in
      # No sudo in front: the restart signals the dashboard's own process as
      # the dashboard's own account, and asks sudo for that switch itself.
      1) run bash "$S/restart-dashboard.sh" ;;
      2) advisor_restart ;;
      3) root_step tunnel ;;
      4) menu_enable_relay ;;
      5) run bash "$S/detect-rippled-paths.sh" ;;
      6) run bash "$S/diag-xrpld-ports.sh" ;;
      7) run bash "$GA" --dir "$REPO" --backup ;;
      8) menu_restore ;;
      b|q) return ;;
    esac
  done
}

menu_verify() {
  while true; do
    paint
    say "VERIFY"
    item 1 "Everything after a restart/reboot (reads only, no root)"
    item 2 "Dashboard health endpoint"
    item b "back"
    case "$(pick)" in
      1) run bash "$S/verify-after-restart.sh" ;;
      # No -f (#1204): a syncing node's 503 is the answer, and -f hid it.
      2) run bash -c 'curl -sS -w "\nHTTP %{http_code}\n" http://127.0.0.1:${PORT:-7800}/healthz | head -c 600; echo' ;;
      b|q) return ;;
    esac
  done
}

# ── Is any of Aperire on this host? ─────────────────────────────────
# What decides whether this opens a menu of things or a walkthrough. Three
# probes, because the answer differs by role: a validator host has a relay
# unit and no dashboard, an aggregator may run under pm2 instead of systemd,
# and any host that reached any installer has /etc/aperire.
#
# The pm2 probe asks the OPERATOR's account, never the shell we happen to be
# in: under `sudo bash aperire-one` a bare `pm2 jlist` reads root's own empty
# daemon and would call a fully installed aggregator a fresh host — dropping
# the operator of a live box into first-run setup.
pm2_has_aperire() {
  local probe='command -v pm2 >/dev/null 2>&1 && pm2 jlist 2>/dev/null'
  local out
  if [[ $EUID -eq 0 && -n "${SUDO_USER:-}" ]]; then
    out="$(sudo -u "$SUDO_USER" -H bash -lc "$probe" 2>/dev/null)"
  else
    out="$(bash -lc "$probe" 2>/dev/null)"
  fi
  grep -q 'aperire' <<<"$out"
}

host_installed() {
  # A glob covers the instance suffix (aperire-server-node2) and the read-only
  # unit name a node may carry. Grep the body, not the exit status.
  systemctl list-unit-files 'aperire-*' 2>/dev/null | grep -q '\.service' && return 0
  [[ -d /etc/aperire ]] && return 0
  pm2_has_aperire
}

# Everything above this line is definitions; everything below ACTS. Sourcing
# the file for its functions (APERIRE_MENU_LIB=1) skips the whole of it, so a
# test can call advisor_present without also getting the guided setup and the
# menu loop. Written as one `if` around the acting half rather than an early
# return, because an early return here is unreachable code in an executed
# script and shellcheck is right to say so.
if [[ "${APERIRE_MENU_LIB:-0}" != "1" ]]; then

# Started as root on a host that is already installed (`sudo bash aperire-one`
# out of habit), the menu hands itself back to the account that ran sudo
# (#955). As root it would be root running this checkout, and every entry
# that needs root already asks sudo for itself and runs the release's checked
# copy. The instance and the Advisor's port are named across sudo's reset. A
# bare host keeps root: that run is the guided first install.
if [[ $EUID -eq 0 && -n "${SUDO_USER:-}" && "$SUDO_USER" != root ]] && host_installed; then
  printf '%s\n' "Opening the menu as $SUDO_USER: it asks for sudo on each step that needs it." >&2
  exec sudo -u "$SUDO_USER" -H env ${APERIRE_INSTANCE:+APERIRE_INSTANCE="$APERIRE_INSTANCE"} \
    ${APERIRE_ADVISOR_PORT:+APERIRE_ADVISOR_PORT="$APERIRE_ADVISOR_PORT"} bash "$REPO/aperire-one" "$@"
fi

# First paint on a bare host: the walkthrough, not a menu. A menu is a list of
# things you may do in any order, which is the wrong shape for an install that
# has one order and four steps.
if [[ "${APERIRE_NO_GUIDED:-0}" != "1" ]] && ! host_installed; then
  say "Nothing of Aperire One is installed on this host yet — opening guided setup."
  printf '  %s(the ordinary menu is behind it, and APERIRE_NO_GUIDED=1 skips this)%s\n' "$S_DIM" "$S_OFF"
  # A guided setup that stopped said why, and dropping straight into a menu of
  # install entries would scroll that off the screen with a list that reads
  # like a second opinion. Say it stopped, and let the operator ask for the
  # menu rather than land in it.
  if ! bash "$S/aperire-setup.sh"; then
    printf '\n  %sGuided setup stopped — fix what it reported and run this again.\n' "$S_DIM"
    printf '  Enter for the operator menu anyway, Ctrl-C to leave.%s ' "$S_OFF"
    read -r
  fi
fi

while true; do
  paint
  say "OPERATOR MENU"
  item 1 "Install & upgrade"
  item 2 "Operators & access"
  item 3 "Advisor"
  item 4 "Fleet"
  item 5 "Maintenance"
  item 6 "Verify"
  item g "Guided setup — the stepped first run, from install to signed in"
  item q "quit"
  case "$(pick)" in
    1) menu_install ;;
    2) menu_operators ;;
    3) menu_advisor ;;
    4) menu_fleet ;;
    5) menu_maintenance ;;
    6) menu_verify ;;
    g) run bash "$S/aperire-setup.sh" ;;
    q) exit 0 ;;
  esac
done

fi
