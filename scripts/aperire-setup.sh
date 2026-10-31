#!/bin/bash
# aperire-setup.sh — the guided first run.
#
# What `aperire-one` opens on a host that has nothing installed yet, and what the
# menu's "Guided setup" entry opens on one that has. Five numbered steps from a
# fresh clone to a dashboard you are signed into.
#
# It owns no logic. Every step prints the real command and then runs it —
# install.sh, aperire-auth.sh, the verify scripts — so the operator finishes
# knowing what was done rather than only that it worked. Doing it by hand
# afterwards is the same commands in the same order.
#
# Re-entrant: a step that has already been done detects it, says so, and
# offers to skip. install.sh is idempotent, so a repeat is always safe.
#
#   bash scripts/aperire-setup.sh          (or: sudo bash aperire-one)
#
# Not for automation. It needs a terminal and refuses without one; the
# non-interactive path is install.sh with flags.

set -u

# readlink -f, because the CLI installer puts a symlink at ~/.local/bin/aperire
# and the checkout is what this needs to find — not the symlink's parent.
REPO="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/.." && pwd)"
S="$REPO/scripts"

# The same palette the install path and the operator menu use. Empty strings
# unless stdout is a terminal with NO_COLOR unset and TERM not dumb, so a
# guided run captured to a file is byte-plain.
# shellcheck source=scripts/term-style.sh
. "$S/term-style.sh"
# The one reader of authn.yaml's values, shared with install.sh and the pair
# command, so a public_url written as a list is read the same way (#1358).
# shellcheck source=scripts/authn-value.sh
. "$S/authn-value.sh"

# ── Voice ───────────────────────────────────────────────────────────
bold()  { printf '%s%s%s\n' "$S_BOLD" "$1" "$S_OFF"; }
step()  { printf '\n%s═══ STEP %s — %s%s\n' "$S_BOLD" "$1" "$2" "$S_OFF"; }
why()   { printf '  %s\n' "$1"; }
note()  { printf '  %s%s%s\n' "$S_DIM" "$1" "$S_OFF"; }
ok()    { printf '  %sok%s    %s\n' "$S_GREEN" "$S_OFF" "$1"; }
bad()   { printf '  %sFAIL%s  %s\n' "$S_RED" "$S_OFF" "$1"; }
rule()  { printf '  %s────────────────────────────────────────────────────────────%s\n' "$S_DIM" "$S_OFF"; }

# Print the real command, then run it, and return ITS status. The menu's
# run() swallows the status into a printed "(exit N)" and waits for Enter,
# which is right for a menu and wrong here: a step that failed must be able to
# stop the flow instead of letting the next one claim work that never happened.
run() {
  printf '\n%s$ %s%s\n\n' "$S_CYAN" "$*" "$S_OFF"
  "$@"
}

# ── A terminal, or nothing ──────────────────────────────────────────
# Piped input is how this fails silently: `read -p` writes its prompt only to
# a terminal, so a piped run answers questions the operator never saw. The
# installer met exactly that on the 2026-08-20 fresh-host run.
if [[ ! -t 0 || ! -t 1 ]]; then
  cat >&2 <<'EOF'
Guided setup needs a terminal — it asks questions, and piped input answers
them without showing them.

  Interactive:      sudo bash aperire-one
  Non-interactive:  curl -fsSL https://get.aperire.one | bash -s -- --role=co-located --yes
                    (the installer takes every answer as a flag; run it with
                     --help for the full list)
EOF
  exit 2
fi

# ── Who owns the files ──────────────────────────────────────────────
# Started with sudo, this runs as root — but the database, ~/.local/bin and
# the operator's nvm Node all belong to the operator. A root-owned -wal file
# beside the database is a dashboard that cannot write its own history, so
# anything touching those runs as the account that called sudo.
OPERATOR="${SUDO_USER:-${USER:-$(id -un)}}"
as_operator() {
  if [[ $EUID -eq 0 && -n "${SUDO_USER:-}" ]]; then
    sudo -u "$SUDO_USER" -H "$@"
  else
    "$@"
  fi
}

# Root is stated, never assumed. Already root, the sudo would be theatre and
# the printed command would not be the one that ran.
ROOTCMD=()
[[ $EUID -ne 0 ]] && ROOTCMD=(sudo)

# ── Asking ──────────────────────────────────────────────────────────
ask() {   # ask "prompt" -> the answer on stdout, prompt on stderr
  local reply
  printf '\n  %s ' "$1" >&2
  read -r reply || reply=''
  printf '%s' "$reply"
}

confirm() {   # confirm "question" [Y|N]  -> exit status
  local q="$1" def="${2:-Y}" reply hint='[Y/n]'
  [[ "$def" == N ]] && hint='[y/N]'
  printf '\n  %s %s ' "$q" "$hint"
  read -r reply || reply=''
  reply="${reply:-$def}"
  [[ "$reply" =~ ^[Yy] ]]
}

# ── What is already here ────────────────────────────────────────────
DB="$REPO/data/aperire.db"
if [[ -r /etc/aperire/aperire.env ]]; then
  env_db="$(awk -F= '$1=="APERIRE_DB_PATH"{sub(/^[^=]*=/,""); gsub(/"/,""); print; exit}' \
            /etc/aperire/aperire.env 2>/dev/null)"
  [[ -n "${env_db:-}" ]] && DB="$env_db"
fi
[[ -n "${APERIRE_DB_PATH:-}" ]] && DB="$APERIRE_DB_PATH"

AUTHN="$REPO/dashboard/config/authn.yaml"

unit_exists() { systemctl list-unit-files "$1" 2>/dev/null | grep -q '\.service'; }
unit_active() { [[ "$(systemctl is-active "$1" 2>/dev/null)" == "active" ]]; }

# The dashboard's unit name, as this host actually spells it. Ordinarily
# aperire-server.service; a second node installed with --instance=NAME carries
# the suffix, and asserting the plain name there reports a FAIL against a
# service that is running perfectly well. The guided flow is the single-node
# path, so this only has to name what is there rather than choose between two.
DASH_UNIT="aperire-server.service"
resolve_dash_unit() {
  local found
  found="$(systemctl list-unit-files 'aperire-server*.service' 2>/dev/null \
           | awk '/\.service/{print $1; exit}')"
  [[ -n "${found:-}" ]] && DASH_UNIT="$found"
  resolve_dash_port
}

# The port the dashboard listens on, which is not the port in public_url
# (#1277). public_url is the address a browser uses: behind a proxy it is 443
# with no port written, or the proxy's own 8443, and nothing answers /healthz
# there on loopback. Every step here that asks the dashboard something asks
# this port.
#
# Read the way install.sh's fleet_dash_port reads it, in the same order: the
# unit's own Environment=PORT, then the environment file the unit names, then
# this instance's file in /etc/aperire, then 7800. A value that is not digits
# is not a reading, so nothing but a number lands in a URL.
# Run again with the unit name, because the unit only exists once the install
# step has made it (resolve_dash_unit is called after it for the same reason).
DASH_PORT=7800
DASH_PORT_UNREAD=""   # an env file that may name the port and this account could not open
resolve_dash_port() {
  local dir="${APERIRE_UNIT_DIR:-/etc/systemd/system}" etc="${APERIRE_ETC:-/etc/aperire}"
  local suffix="${DASH_UNIT#aperire-server}" unit_file="" env_file="" f p
  suffix="${suffix%.service}"   # "" for the default instance, "-NAME" for a named one
  DASH_PORT=7800 DASH_PORT_UNREAD=""
  for f in "$DASH_UNIT" "aperire-read${suffix}.service"; do
    if [[ -f "$dir/$f" ]]; then unit_file="$dir/$f"; break; fi
  done
  if [[ -n "$unit_file" ]]; then
    p="$(awk -F= '/^Environment=PORT=/{print $3; exit}' "$unit_file" 2>/dev/null | tr -d "\"' " || true)"
    if [[ "$p" =~ ^[0-9]+$ ]]; then DASH_PORT="$p"; return 0; fi
    env_file="$(awk -F= '/^EnvironmentFile=/{sub(/^-/,"",$2); print $2; exit}' "$unit_file" 2>/dev/null || true)"
  fi
  for f in "$env_file" "$etc/aperire${suffix}.env"; do
    [[ -n "$f" && -e "$f" ]] || continue
    # A --port install records the port here, and the file is 0640 root:<the
    # dashboard's group>, so an operator who is not in that group cannot open
    # it. An unreadable file is not an empty one, and this step never asks root
    # to open it: the file also holds the ingest tokens. So the port stays a
    # guess, the failure path says so, and prints the command that reads it.
    # Only the PORT line is read, never the whole file.
    if [[ ! -r "$f" ]]; then DASH_PORT_UNREAD="$f"; continue; fi
    p="$(grep -m1 '^PORT=' -- "$f" 2>/dev/null | sed 's/^PORT=//' | tr -d "\"' " || true)"
    if [[ "$p" =~ ^[0-9]+$ ]]; then DASH_PORT="$p"; DASH_PORT_UNREAD=""; return 0; fi
  done
  return 0
}

# The count, or "unknown" — never a confident zero from a database that is
# not there or a sqlite3 that is not installed. An invented zero here would
# offer to create a first operator on a host that already has three.
#
# Read as the account the dashboard unit names in User= (ADR 0024 lane 4):
# the operator on a host installed before it, aperire-dashboard on a fresh
# one, whose data/ the operator cannot open. This script runs as root, so
# that is runuser, with no prompt. A unit this cannot read is "unknown".
operator_count() {
  [[ -f "$DB" ]] || { echo 0; return; }
  command -v sqlite3 >/dev/null 2>&1 || { echo unknown; return; }
  [[ -r "$S/dashboard-account-lib.sh" ]] || { echo unknown; return; }
  (
    # shellcheck source=scripts/dashboard-account-lib.sh
    . "$S/dashboard-account-lib.sh"
    DA_NO_PROMPT=1
    da_resolve_repo "$REPO" >/dev/null 2>&1 || [[ -n "$DA_ACCOUNT" ]] || { echo unknown; exit 0; }
    as_dashboard_sqlite "$DB" 'SELECT COUNT(*) FROM auth_users' 2>/dev/null || echo unknown
  )
}

authn_value() {   # authn_value <key> -> the value, or empty
  authn_file_value "$AUTHN" "$1"
}

# The starter config points at localhost. That is right for a laptop and
# wrong for every other host, and it is not a detail: the enrollment link is
# built from public_url, and WebAuthn binds the passkey to rp_id. Enroll
# against the wrong one and the passkey has to be thrown away.
authn_is_localhost() { authn_public_url_is_local "$AUTHN"; }

# The port the dashboard listens on, as far as this host says before the
# install step has run; resolve_dash_unit reads it again after.
resolve_dash_unit

# ── State ───────────────────────────────────────────────────────────
ROLE=""
WITH_ADVISOR=0
WITH_TUNNEL=0
MAGIC_LINK=""

# ════════════════════════════════════════════════════════════════════
# STEP 0 — what this host is
# ════════════════════════════════════════════════════════════════════
step0_role() {
  step 0 "what this host is"
  why "Aperire One installs by role: the same clone becomes a different set of"
  why "services depending on what the box is for. Pick the one that describes"
  why "this machine."
  echo
  printf "    1) co-located   the node, the dashboard and the relay, all on this box\n"
  printf "    2) dashboard    the dashboard only; your node lives on another box\n"
  printf "    3) validator    the node's box in a split: the relay only, no dashboard\n"
  printf "    4) cli-only     the operator commands on a workstation, no services\n"

  while [[ -z "$ROLE" ]]; do
    case "$(ask 'which one? [1-4]')" in
      1) ROLE=co-located ;;
      2) ROLE=dashboard ;;
      3) ROLE=validator ;;
      4) ROLE=cli-only ;;
      *) printf '  %spick 1, 2, 3 or 4.%s\n' "$S_RED" "$S_OFF" ;;
    esac
  done
  echo
  ok "role: $ROLE"

  [[ "$ROLE" == "validator" || "$ROLE" == "cli-only" ]] && return 0

  # The Advisor, with the consequence stated beside the question rather than
  # discovered at the last step of the install.
  echo
  why "The Advisor is optional. It answers questions about this node and can"
  why "run an upgrade you approve with your passkey. Monitoring works fully"
  why "without it, and it can be added later."
  local sysd; sysd="$(systemctl --version 2>/dev/null | awk 'NR==1{print $2}')"
  if [[ -n "${sysd:-}" && "$sysd" =~ ^[0-9]+$ && "$sysd" -lt 250 ]]; then
    note "this host runs systemd $sysd. The Advisor's own account needs 250+,"
    note "so here it would run under your account instead (weaker: that account"
    note "is in the docker group). Ubuntu 24.04 and Mint 22 are clear."
  fi
  confirm "Install the Advisor too?" N && WITH_ADVISOR=1

  echo
  why "A Cloudflare tunnel publishes the dashboard on the internet with no"
  why "inbound port open. It needs a Cloudflare account and a domain already"
  why "set up. LAN or SSH access needs nothing."
  confirm "Set up the Cloudflare tunnel?" N && WITH_TUNNEL=1
}

# ════════════════════════════════════════════════════════════════════
# STEP 1 — install
# ════════════════════════════════════════════════════════════════════
step1_install() {
  step 1 "install what this role needs"
  why "One command. It puts the toolchain in place (build tools, Node 22, Go),"
  why "builds the binaries, and installs each part as an enabled,"
  why "non-privileged systemd service that survives a reboot. It prints its"
  why "own plan and asks once before it touches anything."
  why "First it checks what this host has, one line per item, and stops on"
  why "anything missing rather than failing minutes into the build."
  note "Roughly 1 to 5 minutes, most of it the build."

  resolve_dash_unit
  local want_unit=""
  case "$ROLE" in
    co-located|dashboard) want_unit="$DASH_UNIT" ;;
    validator)            want_unit="aperire-relay.service" ;;
  esac
  if [[ -n "$want_unit" ]] && unit_exists "$want_unit"; then
    echo
    ok "$want_unit is already installed on this host"
    confirm "Run the installer again anyway? (safe, it is idempotent)" N || return 0
  fi

  local -a cmd=("${ROOTCMD[@]}" bash "$REPO/install.sh" "--role=$ROLE")
  [[ $WITH_ADVISOR -eq 1 ]] && cmd+=(--with-advisor)
  [[ $WITH_TUNNEL  -eq 1 ]] && cmd+=(--with-tunnel)
  # cli-only installs into the operator's own ~/.local/bin and refuses root
  # outright — so under sudo it is the one step that drops back to the account
  # that called sudo, rather than failing on the privilege it was given.
  if [[ "$ROLE" == "cli-only" ]]; then
    if [[ $EUID -eq 0 && -n "${SUDO_USER:-}" ]]; then
      cmd=(sudo -u "$SUDO_USER" -H bash "$REPO/install.sh" --role=cli-only)
    elif [[ $EUID -eq 0 ]]; then
      echo
      bad "cli-only installs for one account and this shell is root with no SUDO_USER"
      why "Run it as yourself instead:  bash install.sh --role=cli-only"
      return 1
    else
      cmd=(bash "$REPO/install.sh" --role=cli-only)
    fi
  fi

  local install_rc=0
  run "${cmd[@]}" || install_rc=$?
  if [[ $install_rc -eq 3 ]]; then
    # install.sh's own code for a finished install whose Advisor stayed on
    # the dashboard's account (#806). Everything else is in place, so the
    # checks below still run; the step left is named, not hidden.
    echo
    bad "the Advisor is installed, but still on the dashboard's account"
    why "Its account move refused; the installer's lines above say why. Once that"
    why "is put right:  curl -fsSL https://get.aperire.one | bash -s -- --update --force"
    why "(at a terminal; answer Y when it offers to move the Advisor)"
  elif [[ $install_rc -ne 0 ]]; then
    echo
    bad "the installer did not finish"
    why "Read the error above: it names the step that stopped. Nothing after"
    why "this point can be trusted, so guided setup stops here. Fix it and run"
    why "  sudo bash aperire-one"
    why "again — everything that did install stays installed."
    return 1
  fi

  echo
  resolve_dash_unit
  case "$ROLE" in
    co-located|dashboard)
      if unit_active "$DASH_UNIT"; then
        ok "$DASH_UNIT is running"
      else
        bad "$DASH_UNIT is not running (journalctl -u $DASH_UNIT -n 40)"
      fi
      ;;
    validator)
      if unit_exists aperire-relay.service; then
        ok "aperire-relay is installed (STEP 3 starts it)"
      else
        bad "aperire-relay was not installed"
      fi
      ;;
    cli-only)
      ok "the operator commands are in ~/.local/bin"
      ;;
  esac
  return 0
}

# ════════════════════════════════════════════════════════════════════
# STEP 2 — your first operator
# ════════════════════════════════════════════════════════════════════
step2_operator() {
  step 2 "your first operator"
  why "Aperire One has no passwords. You create an operator, and they enroll a"
  why "passkey in a browser through a single-use link. The first account"
  why "should be admin: admin approves Advisor actions, monitor sees the same"
  why "dashboard and approves nothing."

  # ── 2a. Where operators reach this host ───────────────────────────
  # Before the link, not after. The link is built from public_url and the
  # passkey binds to rp_id, so getting this wrong does not produce a warning
  # — it produces an enrollment that has to be thrown away and redone.
  echo
  bold "  First: where do operators reach this dashboard?"
  local pub rp
  pub="$(authn_public_url "$AUTHN")"; rp="$(authn_value rp_id)"
  note "config: $AUTHN"
  note "public_url: ${pub:-<unset>}      rp_id: ${rp:-<unset>}"
  why "The enrollment link is built from public_url, and the passkey is bound"
  why "to rp_id. Change either one later and every passkey must be enrolled"
  why "again."

  if authn_is_localhost; then
    if ! confirm "Will you open the dashboard on THIS machine (a browser here, or an SSH tunnel)?" Y; then
      echo
      bad "then the two values above are wrong for this host"
      why "Edit $AUTHN and set:"
      why "  public_url: https://<the address operators type>"
      why "  rp_id:      <that same host name, no scheme, no port>"
      echo
      if confirm "Open it in an editor now?" Y; then
        as_operator "${EDITOR:-nano}" "$AUTHN"
        pub="$(authn_public_url "$AUTHN")"; rp="$(authn_value rp_id)"
        note "public_url: ${pub:-<unset>}      rp_id: ${rp:-<unset>}"
      fi
      if authn_is_localhost; then
        echo
        bad "still localhost — not issuing an enrollment link against it"
        why "A link nobody can open, and a passkey bound to the wrong host, is"
        why "worse than no account. Edit the file, restart the dashboard"
        why "  ${ROOTCMD[*]:+${ROOTCMD[*]} }systemctl restart $DASH_UNIT"
        why "and run 'sudo bash aperire-one' again — this step is where you land."
        return 1
      fi
    fi
  fi
  ok "operators reach this dashboard at ${pub:-http://localhost:$DASH_PORT}"

  # ── 2b. The account ───────────────────────────────────────────────
  local count; count="$(operator_count)"
  if [[ "$count" != "0" && "$count" != "unknown" ]]; then
    echo
    ok "$count operator(s) already exist on this host"
    note "list them: $S/aperire-auth.sh list"
    confirm "Add another operator?" N || return 0
  fi

  local email=""
  while [[ -z "$email" ]]; do
    email="$(ask 'operator email (this is the identity — no usernames):')"
    if [[ ! "$email" =~ ^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$ ]]; then
      printf '  %sthat does not look like an email address.%s\n' "$S_RED" "$S_OFF"
      email=""
    fi
  done

  echo
  why "One command creates the account and issues the enrollment link."
  note "once ~/.local/bin is on your PATH this is just: aperire-auth add $email --role admin"

  local out rc
  local -a addcmd=(bash "$S/aperire-auth.sh" add "$email" --role admin)
  if [[ $EUID -eq 0 && -n "${SUDO_USER:-}" ]]; then
    addcmd=(sudo -u "$SUDO_USER" -H "${addcmd[@]}")
  fi
  printf '\n%s$ %s%s\n\n' "$S_CYAN" "${addcmd[*]}" "$S_OFF"
  out="$("${addcmd[@]}" 2>&1 | tee /dev/tty)"
  rc="${PIPESTATUS[0]}"
  if [[ "$rc" -ne 0 ]]; then
    echo
    bad "the operator was not created"
    return 1
  fi

  MAGIC_LINK="$(grep -oE 'https?://[^[:space:]]+token=[^[:space:]]+' <<<"$out" | tail -1)"
  return 0
}

# The link on its own, because it is the one thing on screen that has to be
# acted on, and anything printed under it breaks the copy. Shown twice on
# purpose: once the moment it is issued, so it can be opened in another window
# while the rest of the flow runs, and once at the very end, because by then
# the first one has scrolled away.
LINK_SHOWN=0
show_link() {
  [[ -n "$MAGIC_LINK" ]] || return 0
  echo
  rule
  if [[ $LINK_SHOWN -eq 0 ]]; then
    bold "   OPEN THIS LINK IN A BROWSER — single use, expires in 15 minutes"
  else
    bold "   THE ENROLLMENT LINK AGAIN — single use, expires in 15 minutes"
  fi
  LINK_SHOWN=1
  echo
  printf '     %s%s%s%s\n' "$S_BOLD" "$S_GREEN" "$MAGIC_LINK" "$S_OFF"
  echo
  why "  On that page choose Register and approve the biometric prompt"
  why "  (Touch ID, Face ID, Windows Hello, a hardware key). That prompt IS"
  why "  the enrollment: the passkey is created on your device and never"
  why "  leaves it. Nothing else signs you in."
  note "  Expired before you got to it? aperire-auth magic-link <email>"
  note "  re-issues one; the account stays."
  rule
}

# ════════════════════════════════════════════════════════════════════
# STEP 3 — what this role still needs
# ════════════════════════════════════════════════════════════════════
step3_role() {
  case "$ROLE" in
    co-located)
      step 3 "the relay"
      why "Nothing to do. On this role the installer wired the relay to the"
      why "dashboard on this box — URL and token both local — and started it."
      echo
      if unit_active aperire-relay; then
        ok "aperire-relay is running and pushing host metrics"
      else
        bad "aperire-relay is installed but not active"
        note "${ROOTCMD[*]:+${ROOTCMD[*]} }systemctl status aperire-relay"
      fi
      ;;
    dashboard)
      step 3 "point this dashboard at your nodes"
      why "This box has no node of its own. Each node you want on it is joined"
      why "once, from here: the helper writes both ends of the registry, sets"
      why "up the tunnel to that node, and pins its identity so a tunnel"
      why "re-pointed at the wrong host is refused rather than believed."
      echo
      # Said here as well as in the installer's own output, because on this
      # path that output has scrolled past by now and this is the step where
      # the operator is thinking about where their node actually is.
      note "swap warns at 40% on this box, same as every role: steady swap is"
      note "normal on a long-running host. If a node's relay pushes host metrics"
      note "to THIS dashboard, the number describes the NODE, not this box, and"
      note "you can set a different warn for it:"
      note "  bash $S/set-alert-role-defaults.sh --role=dashboard --swap-warn=N"
      echo
      note "dry run first — prints every change, writes nothing:"
      note "  bash $S/aperire-fleet-add.sh --dry-run"
      if confirm "Join a node now?" N; then
        run bash "$S/aperire-fleet-add.sh" --dry-run
        confirm "Run it for real?" N && run bash "$S/aperire-fleet-add.sh"
      else
        why "Later: 'aperire-one' → Fleet → 1. The full walkthrough is in the"
        why "fleet guide (docs/FLEET-GUIDE.md)."
      fi
      ;;
    validator)
      step 3 "tell the relay where the dashboard is"
      why "The relay is installed, enabled and running, and standing by. Only"
      why "you know the dashboard's URL and token, so it does not guess: it"
      why "dials nothing until you fill those two values in."
      echo
      note "file:  /etc/aperire/relay.conf"
      note "keys:  dashboard_url = \"wss://<dashboard host>/ingest\""
      note "       auth_token    = \"<must match RELAY_TOKENS on the dashboard host>\""
      local state; state="$(relay_conf_state)"
      case "$state" in
        filled)
          ok "relay.conf already carries a dashboard URL and a real token"
          ;;
        unreadable)
          # Not "it needs filling in". The file is root-owned, and a shell that
          # cannot read it knows nothing about what is in it — reporting that
          # as an empty config is how a guided flow talks somebody into
          # overwriting a working one.
          bad "this shell cannot read /etc/aperire/relay.conf, so what is in it is unknown"
          # The one root step it needs, by name: sudoedit is root's own
          # program and edits a copy as you, so the menu is not run as root
          # to read one file (#955).
          note "open it to check or fill in those two values: sudoedit /etc/aperire/relay.conf"
          ;;
        missing)
          bad "/etc/aperire/relay.conf is not there — STEP 1 is what creates it"
          ;;
        placeholder)
          if confirm "Open relay.conf in an editor now?" Y; then
            run "${ROOTCMD[@]}" "${EDITOR:-nano}" /etc/aperire/relay.conf
            state="$(relay_conf_state)"
          fi
          ;;
      esac
      # Restart, never `enable --now`. The unit is already enabled and already
      # running, so `--now` is a no-op and the process keeps the config it
      # started with, which is the one that named no dashboard.
      if [[ "$state" == "filled" ]] && confirm "Pick up the new config now?" Y; then
        run "${ROOTCMD[@]}" systemctl restart aperire-relay
      fi
      ;;
    cli-only)
      step 3 "nothing runs on this box"
      why "cli-only installs the operator commands and no services. Point them"
      why "at a dashboard host over SSH and use them there."
      note "try: aperire-auth list"
      ;;
  esac
}

# filled | placeholder | unreadable | missing. Four answers rather than a
# yes/no, because "I could not read it" and "it still holds the shipped
# placeholder" are different facts and only one of them is about the config.
# The filled test is the installer's own, so both agree on what counts.
relay_conf_state() {
  local conf=/etc/aperire/relay.conf
  [[ -e "$conf" ]] || { echo missing; return; }
  [[ -r "$conf" ]] || { echo unreadable; return; }
  # An empty dashboard_url is what the split install writes and what the relay
  # reads as "awaiting registration". It is not filled in, so it groups with
  # placeholder here: both mean the two values are still the operator's to add.
  if grep -qE '^[[:space:]]*auth_token[[:space:]]*=[[:space:]]*"[^"]+"' "$conf" \
     && ! grep -qE '^[[:space:]]*auth_token[[:space:]]*=[[:space:]]*"(REPLACE_WITH[A-Z_]*|CHANGE_ME[A-Z_]*)"' "$conf" \
     && ! grep -qE '^[[:space:]]*dashboard_url[[:space:]]*=[[:space:]]*"[^"]*\.example\.com' "$conf"; then
    echo filled
  else
    echo placeholder
  fi
}

# ════════════════════════════════════════════════════════════════════
# STEP 4 — verify
# ════════════════════════════════════════════════════════════════════
# Ask the dashboard's /healthz and say which answer it gave (#1204). Not
# `curl -f`: the handler answers 503, with a JSON body, until the node it reads
# has closed a ledger in the last 30 seconds, and -f swapped that body for
# curl's own "error: 503" on every node still syncing. -w adds the status on
# a line of its own under the body, so the command shown is the one that ran,
# and what is said is read off the answer: the dashboard's own 503 carries
# "ok":false and a role, and anything else on the port does not.
show_healthz() {
  local url="http://127.0.0.1:${DASH_PORT}/healthz" fmt='\nHTTP %{http_code}\n' out code body age next
  printf '\n%s$ curl -sS -w %s %s%s\n\n' "$S_CYAN" "'$fmt'" "$url" "$S_OFF"
  out="$(curl -sS -w "$fmt" "$url" 2>&1)"
  printf '%s\n\n' "$out"
  code="$(sed -n 's/^HTTP \([1-9][0-9][0-9]\)$/\1/p' <<<"$out" | tail -1)"
  body="$(sed '/^HTTP [0-9][0-9][0-9]$/d' <<<"$out")"
  if [[ "$code" == 200 ]]; then
    # A dashboard-role host answers 200 with no node at all, so "current" is
    # said only of a node's answer.
    if grep -Eq '"role"[[:space:]]*:[[:space:]]*"node"' <<<"$body"; then
      ok "the dashboard answered, and the node it reads is current"
    else
      ok "the dashboard answered"
    fi
    next="$(sed -nE 's/.*"next_step"[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/p' <<<"$body")"
    [[ -n "$next" ]] && note "$next"
    return 0
  fi
  if [[ "$code" == 503 ]] && grep -Eq '"ok"[[:space:]]*:[[:space:]]*false' <<<"$body" \
     && grep -q '"role"' <<<"$body"; then
    note "503 is the dashboard's own answer: it is up, and the node it reads is not ready."
    if grep -Eq '"rippled_connected"[[:space:]]*:[[:space:]]*true' <<<"$body"; then
      age="$(sed -nE 's/.*"ledger_age_ms"[[:space:]]*:[[:space:]]*([0-9]+).*/\1/p' <<<"$body")"
      if [[ -n "$age" ]]; then
        note "It is connected to the node, and the last ledger it saw closed $(( age / 1000 ))s ago: the node is syncing."
      else
        note "It is connected to the node, and no ledger has closed there yet: the node is syncing."
      fi
    else
      note "It is not connected to the node yet."
    fi
    note "That is expected right after an install: a new node syncs for hours, not"
    note "minutes. /healthz answers 200 with \"ok\":true once it is current. Ask again any time."
    return 0
  fi
  if [[ -n "$code" ]]; then
    bad "something answered on $url with HTTP $code, and it was not the dashboard's own answer"
  else
    bad "the dashboard did not answer on $url"
  fi
  if [[ -n "${DASH_PORT_UNREAD:-}" ]]; then
    note "This account cannot read $DASH_PORT_UNREAD, where the dashboard's port is recorded, so 7800 was a guess."
    note "Read it with: sudo grep '^PORT=' $DASH_PORT_UNREAD"
  fi
  note "read: systemctl status $DASH_UNIT --no-pager"
  return 1
}

step4_verify() {
  step 4 "prove it works"
  why "Reads only, changes nothing, and needs no root."

  case "$ROLE" in
    co-located|dashboard)
      # Two plain commands rather than one `bash -c "..."`: the quoting that
      # makes a compound command work is exactly what a printed command line
      # loses, and a command an operator cannot copy teaches nothing.
      resolve_dash_unit
      run systemctl is-active "$DASH_UNIT"
      # The keys are explained only where there was JSON to read them in.
      if show_healthz; then
        echo
        why "In that JSON: 'ok' is the whole host's verdict, 'rippled_connected'"
        why "says whether the node answered, and a small 'relay_last_push_ms'"
        why "means the relay is feeding. A node that has no ledgers yet reports"
        why "ok:false honestly — that is the node syncing, not a broken install."
      fi
      ;;
    validator)
      run "${ROOTCMD[@]}" systemctl status --no-pager aperire-relay
      note "the dashboard host is where the result shows up: its System and"
      note "Network tabs fill in within a minute of the relay starting."
      ;;
    cli-only)
      run bash "$S/aperire-auth.sh" list
      ;;
  esac

  # The reboot check asserts all three services and the node, so it only reads
  # true on a host that has all three. Offered where that holds, named
  # everywhere else — a check that reports FAIL for something deliberately not
  # installed teaches operators to ignore it.
  if unit_exists aperire-advisord.service && [[ "$ROLE" == "co-located" ]]; then
    echo
    if confirm "Also run the full after-a-reboot check (services, node, config, both endpoints)?" Y; then
      run bash "$S/verify-after-restart.sh"
    fi
  else
    note "after any reboot: bash $S/verify-after-restart.sh"
  fi
}

# ════════════════════════════════════════════════════════════════════
# Closing
# ════════════════════════════════════════════════════════════════════
closing() {
  echo
  rule
  bold "  Setup complete — what next"
  rule
  case "$ROLE" in
    co-located|dashboard)
      why "1. Sign in at ${pub_final:-http://localhost:$DASH_PORT} with the passkey you enrolled."
      why "2. The tabs: Overview (is anything on fire), Consensus, Network,"
      why "   System, Governance, Insights (alerts and digests)."
      why "3. Alerts reach you by email, push or webhook once you configure a"
      why "   channel on the Insights tab."
      if unit_exists aperire-advisord.service; then
        why "4. The Advisor tab answers questions about this node. After your"
        why "   passkey is enrolled, let it trust you:"
        why "     aperire-auth advisor-sync"
      fi
      ;;
    validator)
      why "1. Open the dashboard host and watch the System and Network tabs"
      why "   fill in for this node."
      why "2. Nothing else runs here. This box stays the node and the relay."
      ;;
    cli-only)
      why "1. These commands act on whichever host you run them on."
      why "2. 'aperire' opens the menu; 'aperire-auth' manages operators."
      ;;
  esac
  echo
  why "The menu is 'aperire-one' from any directory on this host, and this"
  why "walkthrough is under it as 'Guided setup'."
  echo
  note "Guides:  docs/DEPLOYMENT-GUIDE.md  this walkthrough, in writing,"
  note "                                   and the detail behind every step"
  note "         docs/OPERATIONAL-GUIDE.md running it day to day"
  echo
}

# ════════════════════════════════════════════════════════════════════
main() {
  printf '\n'
  bold "  ═══ APERIRE — GUIDED SETUP ═══"
  printf '  host: %s   ·   operator: %s\n  %s\n' "$(hostname)" "$OPERATOR" "$REPO"
  echo
  why "Five steps, about 15 minutes, most of it the build in STEP 1. At the"
  why "end you have the services running and a browser signed into the"
  why "dashboard with your passkey."
  why "Every step prints the command it runs before it runs it, so doing this"
  why "by hand next time is the same commands in the same order."
  note "Ctrl-C at a prompt is safe — nothing has been started yet. Mid-step,"
  note "let it finish: every installer here is idempotent, so a re-run heals a"
  note "partial one, but a re-run is what heals it."

  step0_role
  step1_install || return 1

  if [[ "$ROLE" == "co-located" || "$ROLE" == "dashboard" ]]; then
    step2_operator || return 1
    show_link
  else
    step 2 "your first operator"
    why "Not on this role — operators live on the dashboard host. Create the"
    why "first one there with: aperire-auth add you@example.com --role admin"
  fi

  step3_role
  step4_verify

  pub_final="$(authn_public_url "$AUTHN")"
  show_link
  closing
}

pub_final=""
main "$@"
