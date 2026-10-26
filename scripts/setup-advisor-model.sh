#!/usr/bin/env bash
# Point the Advisor at a language model.
#
# Writes advisor/state/model.json and seals the API key as a systemd
# credential. The config file never contains the key: see the Configuration
# section of docs/ADVISOR-GUIDE.md for why that separation is the
# point.
#
# The Advisor works without this. Readiness, plans and the ledger are
# deterministic and need no account anywhere. A model adds one thing: the
# ability to answer questions in the drawer.
#
# To undo:  ./scripts/setup-advisor-model.sh --disable

set -euo pipefail

# Where this program and its siblings are (MODEL_SELF), and the install tree it acts
# on (REPO): a directory and its parent from a checkout, two when it is a copy
# root staged out of the release and APERIRE_INSTALL_TREE names the tree
# (#764). Code is loaded and run from MODEL_SELF only.
MODEL_SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="${APERIRE_INSTALL_TREE:-$(cd "$MODEL_SELF/.." && pwd)}"
CFG="$REPO/advisor/state/model.json"
CRED_DIR=/etc/aperire/creds
# Named per provider so keys coexist. A single shared name meant configuring a
# second provider silently overwrote the first, and discovering that means
# going back to the vendor for a key you already had.
CRED_NAME=model-api-key
# How this host keeps a key, measured once and said in two places below (#708).
# The same library the sealer reads, so what this prints and what the seal does
# cannot disagree.
KEY_METHOD=sealed
KEY_METHOD_LINE="sealed to this machine with systemd-creds"
if [[ -r "$MODEL_SELF/model-key-method-lib.sh" ]]; then
  # shellcheck source=scripts/model-key-method-lib.sh
  . "$MODEL_SELF/model-key-method-lib.sh"
  KEY_METHOD="$(aperire_key_method)"
  KEY_METHOD_LINE="$(aperire_key_method_line "$KEY_METHOD")"
fi

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
info() { printf '   %s\n' "$*"; }

usage() {
  cat <<'USAGE'
Point the Advisor at a language model.

  setup-advisor-model.sh            interactive setup (provider, key, model)
  setup-advisor-model.sh --show     what is configured now (never the key)
  setup-advisor-model.sh --disable  turn the model off; config kept
  setup-advisor-model.sh --help     this text

The config file never contains the API key — it is sealed as a systemd
credential on this host. See docs/ADVISOR-GUIDE.md, "Configuration".
USAGE
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  usage
  exit 0
fi
# An unrecognised flag prints help and stops. It used to fall through into
# the interactive setup — someone asking --help found themselves in a
# prompt that changes the model config, with no exit on offer.
if [[ -n "${1:-}" && "${1:-}" != "--show" && "${1:-}" != "--disable" && "${1:-}" != "--doctor" ]]; then
  echo "unrecognised option: ${1}" >&2
  usage >&2
  exit 2
fi

if [[ "${1:-}" == "--doctor" ]]; then
  # THIS host's model setup, end to end, each link checked in order — the
  # answer to "is this box actually done?". Born 2026-08-14: an operator
  # verified a PASTED key three times believing it verified the box, while
  # the box had nothing sealed. Every FAIL names the next command.
  echo "model setup on THIS host: $(hostname)"
  ok=1
  if [[ -f "$CFG" ]]; then
    echo "  [ok]   config exists          $CFG"
    CRED_NAME_D=$(python3 -I -c "import json;print(json.load(open('$CFG')).get('credential_name',''))" 2>/dev/null || echo "")
  else
    echo "  [FAIL] no model config on this host"; ok=0; CRED_NAME_D=""
  fi
  # Two forms, because a host that cannot seal keeps the key as a root-only
  # file at <name>.plain instead (#708). Either one present is a key on this
  # host, and the doctor says which it found.
  if [[ -n "$CRED_NAME_D" ]] && sudo -n test -f "$CRED_DIR/$CRED_NAME_D" 2>/dev/null; then
    echo "  [ok]   key sealed here        $CRED_DIR/$CRED_NAME_D"
  elif [[ -n "$CRED_NAME_D" ]] && sudo -n test -f "$CRED_DIR/$CRED_NAME_D.plain" 2>/dev/null; then
    echo "  [ok]   key kept here          $CRED_DIR/$CRED_NAME_D.plain (root-only file; this host has no systemd-creds)"
  elif [[ -n "$CRED_NAME_D" ]] && ! sudo -n true 2>/dev/null; then
    echo "  [??]   seal not checkable without sudo — the live check below decides"
  else
    echo "  [FAIL] no key sealed on this host"; ok=0
  fi
  ADV_UNIT_D="/etc/systemd/system/aperire-advisord${APERIRE_INSTANCE:+-$APERIRE_INSTANCE}.service"
  # Two places, because the directive moved (#451). A key sealed from the
  # browser, or by the sealer on this host, declares itself in a drop-in of
  # its own; a host sealed before that carries the line in the unit, and is
  # migrated by its next seal or reset. Reading only the unit printed a
  # failure on every drop-in host, about an Advisor holding its key
  # perfectly well, which is the one thing this check must never do.
  ADV_DROPIN_D="$ADV_UNIT_D.d/model-credential.conf"
  LOADS_KEY=""
  if [[ -n "$CRED_NAME_D" ]]; then
    for f in "$ADV_DROPIN_D" "$ADV_UNIT_D"; do
      [[ -f "$f" ]] || continue
      # Either spelling (#708): LoadCredentialEncrypted= for a key sealed to
      # this machine, LoadCredential= for one kept as a root-only file.
      grep -qE "^LoadCredential(Encrypted)?=$CRED_NAME_D:" "$f" || continue
      LOADS_KEY="$f"
      break
    done
  fi
  if [[ -n "$LOADS_KEY" ]]; then
    echo "  [ok]   unit loads the key     $LOADS_KEY"
  else
    echo "  [FAIL] the service unit does not load the key"; ok=0
  fi
  if systemctl is-active --quiet "aperire-advisord${APERIRE_INSTANCE:+-$APERIRE_INSTANCE}"; then
    echo "  [ok]   advisord running"
  else
    echo "  [FAIL] advisord is not running"; ok=0
  fi
  # The unprivileged leg is this account reading its own group-shared file and
  # holds no privilege to redirect. The sudo FALLBACK is root, so it goes
  # through the helper (#703): a link at that name would have root read the
  # target and send its first line out as a bearer token below.
  # The root-held copy of the helper, not $MODEL_SELF's: run from the tree as
  # the operator, $MODEL_SELF is a folder the Advisor's account can write (#886).
  # A constant, never read from the environment: what it names here is what
  # root runs under the sudo below (#1127). Checked before that sudo: a regular
  # file, not a link, owned by ROOT_TOOL_UID, writable by neither group nor
  # other. A suite that needs a stand-in rewrites these two lines in its own copy.
  ROOT_STATE_TOOL=/usr/local/sbin/aperire-state-file
  ROOT_TOOL_UID=0
  root_tool_ok() { local m; [[ -f "$ROOT_STATE_TOOL" && ! -L "$ROOT_STATE_TOOL" && -r "$ROOT_STATE_TOOL" ]] && m="$(stat -c '%u:%a' -- "$ROOT_STATE_TOOL" 2>/dev/null)" && [[ "${m%%:*}" == "$ROOT_TOOL_UID" ]] && (( (8#${m##*:} & 8#022) == 0 )); }
  TOK_D="$REPO/advisor/state/approve.token"
  # The token reaches curl on its standard input (-H @-), never on its argv,
  # where any account on the host can read it in /proc (#705).
  # No token readable is an empty one, as before: the check below says
  # "err" rather than set -e ending the run here.
  MODEL_TOK="$( { cat "$TOK_D" 2>/dev/null || { root_tool_ok && sudo -n python3 -I "$ROOT_STATE_TOOL" read "$TOK_D" 2>/dev/null; }; } | tr -d '[:space:]')" || MODEL_TOK=""
  MODEL_UP=$( { curl -sf -m 4 -H @- "http://127.0.0.1:${APERIRE_ADVISOR_PORT:-7810}/v1/status" <<<"authorization: Bearer $MODEL_TOK" | python3 -I -c "import json,sys;print(bool((json.load(sys.stdin).get('model') or {}).get('configured')))"; } 2>/dev/null || echo err)
  unset MODEL_TOK
  if [[ "$MODEL_UP" == "True" ]]; then
    # The live answer outranks every file check above: a running advisord
    # holding a working model IS the end state, however the pieces looked.
    echo "  [ok]   advisord reports the model CONFIGURED — this box is DONE"
    ok=1
  else
    echo "  [FAIL] advisord does not report a configured model (got: $MODEL_UP)"; ok=0
  fi
  if [[ "$ok" == 0 ]]; then
    echo
    echo "  not done. The one command that completes everything above:"
    echo "    bash $REPO/scripts/setup-advisor-model.sh     (option 1 in the menu)"
    exit 1
  fi
  exit 0
fi

if [[ "${1:-}" == "--show" ]]; then
  # What the Advisor is using right now. The key itself is sealed as a
  # systemd credential and is deliberately not printable from here — this
  # shows that a key EXISTS, never what it is. The tab shows none of this:
  # which model answers is host configuration, and host configuration is
  # read and changed on the host.
  if [[ ! -f "$CFG" ]]; then
    echo "no model configured — run ./scripts/setup-advisor-model.sh"
    exit 0
  fi
  python3 -I - "$CFG" <<'PY'
import json,sys
c=json.load(open(sys.argv[1]))
print(f"enabled     {str(c.get('enabled')).lower()}")
print(f"model       {c.get('model')}")
print(f"shape       {c.get('shape')}")
print(f"base_url    {c.get('base_url')}")
print(f"max_tokens  {c.get('max_tokens')}")
print(f"timeout     {c.get('timeout_sec')}s")
print(f"credential  {c.get('credential_name')}")
PY
  CRED="$(python3 -I -c "import json;print(json.load(open('$CFG')).get('credential_name',''))")"
  if [[ -n "$CRED" && -f "$CRED_DIR/$CRED.plain" ]]; then
    echo "api key     kept at $CRED_DIR/$CRED.plain, readable by root alone (contents not printable)"
  elif [[ -n "$CRED" && ( -f "$CRED_DIR/$CRED" || -f "$CRED_DIR/$CRED.cred" ) ]]; then
    echo "api key     sealed at $CRED_DIR/$CRED (contents not printable)"
  else
    echo "api key     NOT FOUND — the drawer will say so; re-run this script to fix"
  fi
  exit 0
fi

if [[ "${1:-}" == "--disable" ]]; then
  if [[ -f "$CFG" ]]; then
    python3 -I - "$CFG" <<'PY'
import json,sys
p=sys.argv[1]; c=json.load(open(p)); c['enabled']=False
json.dump(c, open(p,'w'), indent=2); open(p,'a').write('\n')
PY
    echo "disabled — $CFG kept, enabled set to false"
  else
    echo "nothing to disable"
  fi
  echo "restart the service: sudo systemctl restart aperire-advisord"
  exit 0
fi

say "Provider"
cat <<'MENU'
   1) xAI            https://api.x.ai/v1              shape: openai
   2) OpenAI         https://api.openai.com/v1        shape: openai
   3) Anthropic      https://api.anthropic.com        shape: anthropic
   4) Local/Ollama   http://127.0.0.1:11434/v1        shape: openai
   5) Other
MENU
read -r -p "   choose [1-5, q to quit]: " choice

case "$choice" in
  q|Q) echo "nothing changed"; exit 0 ;;
  1) BASE=https://api.x.ai/v1;         SHAPE=openai;    CRED_NAME=model-api-key-xai ;;
  2) BASE=https://api.openai.com/v1;   SHAPE=openai;    CRED_NAME=model-api-key-openai ;;
  3) BASE=https://api.anthropic.com;   SHAPE=anthropic; CRED_NAME=model-api-key-anthropic ;;
  4) BASE=http://127.0.0.1:11434/v1;   SHAPE=openai;    CRED_NAME=model-api-key-local ;;
  5) read -r -p "   base_url: " BASE
     read -r -p "   shape [openai|anthropic]: " SHAPE
     read -r -p "   credential name [model-api-key-other]: " CRED_NAME
     CRED_NAME="${CRED_NAME:-model-api-key-other}" ;;
  *) echo "unrecognised choice" >&2; exit 1 ;;
esac

# The key comes before the model, so the model can be CHOSEN from what this
# key actually reaches rather than typed from memory. A name that does not
# exist and a key that does not work surface identically later, in the drawer,
# and separating them there is slower than never conflating them here.
KEY=""
if [[ "$BASE" == http://127.0.0.1* || "$BASE" == http://localhost* ]]; then
  say "Local runner"
  info "No key needed. Set key_file in the config later if your runner wants one."
else
  say "API key"
  info "The key comes before the model on purpose: with a working key, the"
  info "model list is fetched from the provider and you choose from what the"
  info "key actually reaches, instead of typing a model name from memory."
  echo
  info "Kept where only root can read it, and handed to the service as a systemd"
  info "credential: a file on a per-service ramfs at 0400. It never enters the"
  info "process environment, so /proc/<pid>/environ, child processes and"
  info "environment dumps are all closed at once."
  info "On this host: $KEY_METHOD_LINE"
  echo
  read -r -s -p "   paste the key (hidden): " KEY
  echo
  KEY="${KEY//[$'\t\r\n ']/}"
  [[ -n "$KEY" ]] || { echo "key cannot be empty" >&2; exit 1; }
  info "$(printf '%s…%s (%d chars)' "${KEY:0:8}" "${KEY: -4}" "${#KEY}")"
fi

say "Model"
MODELS=()
if [[ -n "$KEY" ]]; then
  info "asking $BASE which models this key can reach…"
  RESP="$(mktemp)"
  # Different auth header and a different path — asking Anthropic the OpenAI
  # question gets a 404 and no list, which reads as "your key is bad".
  # The key on curl's standard input (-H @-), never on its argv (#705).
  if [[ "$SHAPE" == "anthropic" ]]; then
    CODE=$(curl -sS -o "$RESP" -w '%{http_code}' \
      -H @- -H 'anthropic-version: 2023-06-01' \
      "$BASE/v1/models" <<<"x-api-key: $KEY" || echo 000)
  else
    CODE=$(curl -sS -o "$RESP" -w '%{http_code}' -H @- "$BASE/models" <<<"Authorization: Bearer $KEY" || echo 000)
  fi
  if [[ "$CODE" == "200" ]]; then
    mapfile -t MODELS < <(python3 -I -c '
import json,sys
d=json.load(open(sys.argv[1]))
for m in sorted(x.get("id","") for x in d.get("data",[])):
    if m: print(m)
' "$RESP" 2>/dev/null || true)
  else
    warn_line="the provider answered $CODE, so the list could not be fetched"
    info "$warn_line"
    head -c 200 "$RESP"; echo
    if [[ "$CODE" == "401" || "$CODE" == "403" ]]; then
      echo
      echo "That key was rejected. Nothing has been written." >&2
      rm -f "$RESP"; exit 1
    fi
  fi
  rm -f "$RESP"
fi

if [[ ${#MODELS[@]} -gt 0 ]]; then
  echo
  # Text models only: an image or video model in this list is a wrong turn
  # waiting to happen, and the Advisor cannot use one.
  PICKS=()
  for m in "${MODELS[@]}"; do
    case "$m" in
      *imagine*|*image*|*video*|*embed*|*whisper*|*tts*|*audio*) continue ;;
      *) PICKS+=("$m") ;;
    esac
  done
  [[ ${#PICKS[@]} -gt 0 ]] || PICKS=("${MODELS[@]}")

  # Suggest the newest-looking general model rather than a dated snapshot or a
  # specialised build. Only a default — the operator picks.
  DEFAULT=1
  for i in "${!PICKS[@]}"; do
    case "${PICKS[$i]}" in
      *build*|*multi-agent*|*non-reasoning*|*-0[0-9][0-9][0-9]*) ;;
      *) DEFAULT=$((i+1)) ;;
    esac
  done

  for i in "${!PICKS[@]}"; do
    mark=" "
    [[ $((i+1)) -eq $DEFAULT ]] && mark="*"
    printf '   %s%2d) %s\n' "$mark" "$((i+1))" "${PICKS[$i]}"
  done
  MANUAL=$(( ${#PICKS[@]} + 1 ))
  HIDDEN=$(( ${#MODELS[@]} - ${#PICKS[@]} ))
  printf '    %2d) type a name myself\n' "$MANUAL"
  echo
  info "* recommended: a general model rather than a dated snapshot or a coding build."
  info "  The Advisor explains a node's state; it does not write code."
  if (( HIDDEN > 0 )); then
    info "$HIDDEN image/video/audio model(s) hidden — the Advisor cannot use one."
  fi
  info "Option $MANUAL is there because a provider can ship a model before its"
  info "/models list catches up, and the list should not become the ceiling."
  read -r -p "   choose [1-$MANUAL, default $DEFAULT]: " pick
  pick="${pick:-$DEFAULT}"
  if ! [[ "$pick" =~ ^[0-9]+$ ]] || (( pick < 1 || pick > MANUAL )); then
    echo "not one of the choices" >&2; exit 1
  fi
  if (( pick == MANUAL )); then
    info "Passed through untouched. If the provider does not know it, its own"
    info "error is what you will see — which is the useful version of being wrong."
    read -r -p "   model: " MODEL
    [[ -n "$MODEL" ]] || { echo "model cannot be empty" >&2; exit 1; }
    # Say so rather than letting it fail later in the drawer.
    if ! printf '%s\n' "${MODELS[@]}" | grep -qx -- "$MODEL"; then
      info "note: $MODEL was not in the provider's list. That may be fine for a"
      info "      brand-new model, and it is also what a typo looks like."
    fi
  else
    MODEL="${PICKS[$((pick-1))]}"
  fi
  info "chose $MODEL"
else
  info "No list available, so this one has to be typed."
  info "It is passed through untouched — if it is wrong, the provider says so verbatim."
  read -r -p "   model: " MODEL
  [[ -n "$MODEL" ]] || { echo "model cannot be empty" >&2; exit 1; }
fi

say "Config"
# Written as the account that owns the Advisor's state. Once the Advisor has
# its own account — the arrangement the privilege model recommends — that
# directory is the Advisor's alone, and the operator running this script is
# granted read access and nothing more. It also holds the approvals and the
# audit ledger, so making it group-writable to let this script through would
# trade a real boundary for a convenience. Before this, the script asked for
# a provider, a key and a model, then failed on the last line with a bare
# "Permission denied".
STATE_DIR="$(dirname "$CFG")"
CFG_OWNER="$(stat -c '%U' "$STATE_DIR" 2>/dev/null || true)"
WRITE_AS=()
if [[ -d "$STATE_DIR" && ! -w "$STATE_DIR" ]]; then
  if [[ -z "$CFG_OWNER" ]]; then
    echo "error: $STATE_DIR is not writable and its owner cannot be read" >&2
    exit 1
  fi
  if sudo -n true 2>/dev/null || sudo -v 2>/dev/null; then
    WRITE_AS=(sudo -u "$CFG_OWNER")
    info "writing as '$CFG_OWNER', which owns the Advisor's state directory"
  else
    echo "error: $STATE_DIR belongs to '$CFG_OWNER' and this account cannot write it." >&2
    echo "       Re-run where sudo is available, or run it directly:" >&2
    echo "         sudo -u $CFG_OWNER $0" >&2
    exit 1
  fi
fi
mkdir -p "$STATE_DIR" 2>/dev/null || true
CFG_JSON="$(cat <<JSON
{
  "enabled": true,
  "shape": "$SHAPE",
  "base_url": "$BASE",
  "model": "$MODEL",
  "credential_name": "$CRED_NAME",
  "max_tokens": 16000,
  "timeout_sec": 300
}
JSON
)"
# Two ways to land the same file, and which one is used depends on who is
# running (#703). As the account that owns the state directory there is no
# root primitive to redirect, so a tee is fine. As ROOT, which this script is
# documented never to need but which nothing stops an operator from doing,
# writing by name in a directory the Advisor's own account owns is the whole
# of #703: that account can swap the name between the tee and the chmod. So a
# root run goes through the helper, which does both on one descriptor.
if [[ $EUID -eq 0 ]]; then
  printf '%s\n' "$CFG_JSON" \
    | python3 -I "$MODEL_SELF/state-file.py" plant "$CFG" dir dir 0640 --stdin
else
  printf '%s\n' "$CFG_JSON" | "${WRITE_AS[@]}" tee "$CFG" >/dev/null
  "${WRITE_AS[@]}" chmod 640 "$CFG"
fi
info "$CFG"
info "no key in this file, by design"

if [[ "$BASE" == http://127.0.0.1* || "$BASE" == http://localhost* ]]; then
  say "Local runner — no key needed"
  info "Set key_file in $CFG if your runner does want one."
  echo
  echo "Restart the service:  sudo systemctl restart aperire-advisord"
  exit 0
fi

say "Sealing the key"
info "on THIS machine: $(hostname). $KEY_METHOD_LINE"
if [[ "$KEY_METHOD" == sealed ]]; then
  info "A sealed key never works anywhere else."
else
  info "It is readable by root on this host alone, and a copy of that file would"
  info "work elsewhere, so treat the file as the key it is."
fi
info "If this is not the node you meant, Ctrl-C now; nothing is written yet."

# One sealing implementation, and this is not it. scripts/aperire-seal-model-key.sh
# holds the whole privileged step: the systemd-creds call, the credential's
# permissions, the LoadCredentialEncrypted= line and the restart that makes the
# key arrive. It exists because the browser needed a boundary to cross, and the
# moment there were two ways to seal a key there was a second one to keep
# correct. So this ceremony calls it too, and there is one file to read.
#
# The window it enforces is not a restriction on an operator: arming needs
# root, and an operator running this already has root, so this arms it and
# spends it in the same breath. What the window stops is the DASHBOARD sealing
# twice, or later, and the dashboard cannot arm.
# Root runs the sealer, so it is root's own installed copy when this host has
# one (placed from the release, both checks), and this program's sibling
# otherwise, which is the copy root staged when an installer runs this
# (#764). Never the tree's file.
SEALER=/usr/local/sbin/aperire-seal-model-key
if [[ ! -f "$SEALER" || -L "$SEALER" || "$(stat -c %u -- "$SEALER" 2>/dev/null)" != 0 ]]; then
  SEALER="$MODEL_SELF/aperire-seal-model-key.sh"
fi
[[ -f "$SEALER" ]] || { echo "error: $SEALER is missing; this tree is incomplete" >&2; exit 1; }
ADVISORD_UNIT="aperire-advisord${APERIRE_INSTANCE:+-$APERIRE_INSTANCE}"
ARM_FILE=/etc/aperire/model-key.arm

# A restart during a run would kill the executor mid-stage, and the restart is
# now part of sealing rather than a question afterwards: a key sealed but not
# picked up is a half-done state, and there is no longer a way to end in it.
# The transcript is the record of what is happening now, so ask it.
RUNS_DIR="$(dirname "$CFG")/runs"
IN_FLIGHT=""
if [[ -d "$RUNS_DIR" ]]; then
  while IFS= read -r f; do
    [[ -n "$f" ]] || continue
    last=$("${WRITE_AS[@]}" tail -n1 "$f" 2>/dev/null || true)
    case "$last" in
      *'"kind":"done"'*|*'"kind":"halt"'*) continue ;;
    esac
    IN_FLIGHT="$(basename "$f" .ndjson)"
    break
  done < <("${WRITE_AS[@]}" find "$RUNS_DIR" -name '*.ndjson' -mmin -3 2>/dev/null || true)
fi
if [[ -n "$IN_FLIGHT" ]]; then
  echo
  echo "   WARNING: a run looks like it is still going ($IN_FLIGHT)."
  echo "   Sealing restarts the Advisor, which would end it mid-stage."
  printf '   seal anyway? [y/N]: '
  read -r ANSWER </dev/tty || ANSWER=""
  case "${ANSWER:-n}" in
    [Yy]|[Yy][Ee][Ss]) ;;
    *) echo "   nothing was sealed. $CFG is written; run this again when the run has finished."; exit 0 ;;
  esac
fi

if ! systemctl list-unit-files "${ADVISORD_UNIT}.service" >/dev/null 2>&1 \
   || [[ ! -f "/etc/systemd/system/${ADVISORD_UNIT}.service" ]]; then
  echo
  echo "   No Advisor service on THIS host ($(hostname)) yet, so there is nothing"
  echo "   for a sealed key to be loaded by. $CFG is written and is picked up"
  echo "   when you install:"
  echo "     bash $REPO/aperire-one     ->  3) Advisor  ->  install"
  echo "   If you meant a DIFFERENT node, run this setup again on that node's own"
  echo "   host. A sealed key never travels between machines."
  exit 0
fi

info "sealing, wiring the unit and restarting $ADVISORD_UNIT. The restart waits"
info "for any question already running to finish, so this can take a minute."

# Arming is a root-only act, and an operator running this already has root, so
# the window is opened and spent in the same breath rather than left standing.
sudo mkdir -p /etc/aperire
sudo install -o root -g root -m 0600 /dev/null "$ARM_FILE"

# The payload is five lines on stdin and nothing on the command line, because
# arguments are world-readable in /proc for as long as a process runs.
if ! printf '%s\n%s\n%s\n%s\n%s\n' "$BASE" "$SHAPE" "$MODEL" "$CRED_NAME" "$KEY" \
     | sudo env APERIRE_INSTANCE="${APERIRE_INSTANCE:-}" bash "$SEALER"; then
  unset KEY
  sudo rm -f "$ARM_FILE"
  echo
  echo "   The seal did not finish cleanly. $CFG is written. If the lines above show" >&2
  echo "   sealed=, the key IS sealed and the Advisor did not answer afterwards (service=" >&2
  echo "   not-answering); otherwise nothing else on this host changed unless the message" >&2
  echo "   above says so. Read the journal for the detail:" >&2
  echo "     journalctl -t aperire-seal-model-key -n 20 --no-pager" >&2
  exit 1
fi
unset KEY

echo
info "sealed, and the Advisor restarted with it."
echo
echo "Ask the Advisor something in the drawer. If the key or model is wrong,"
echo "the provider's own message is what you will see."
