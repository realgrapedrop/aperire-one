#!/usr/bin/env bash
# Re-seal the model API key this host is already configured for.
#
# For when the key itself changed: the provider rotated it, or it was revoked,
# or the one sealed here was never right. Everything else about the model stays
# as it is, because this reads the provider, the shape, the model and the
# credential name out of the configuration rather than asking again.
#
#   curl -fsSL https://get.aperire.one | bash -s -- --run reseal-model-key
#
# To change the model or the provider, this is the wrong command: use
#   bash scripts/setup-advisor-model.sh
set -euo pipefail

SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# The install: the one APERIRE_INSTALL_TREE names when root runs a copy the
# bootstrap staged out of the release (curl ... | bash -s -- --run
# reseal-model-key), else this checkout. The sealer root runs is the one
# beside this program, never the install's copy (#955).
REPO="${APERIRE_INSTALL_TREE:-$(cd "$SELF/.." && pwd)}"
CFG="$REPO/advisor/state/model.json"
SEALER="$SELF/aperire-seal-model-key.sh"
ARM_FILE=/etc/aperire/model-key.arm

# The root-held copy of the state helper, a constant: nothing in the
# environment picks the program root reads the Advisor's state with (#1127). A
# suite that needs a stand-in rewrites these two lines in its own copy of this
# file, the way scripts/test-root-runs-staged.sh does. Before every sudo the
# file is checked (root_tool_ok below): owned by ROOT_TOOL_UID, a regular file
# and not a link, writable by neither group nor other.
ROOT_STATE_TOOL=/usr/local/sbin/aperire-state-file
ROOT_TOOL_UID=0
# Whose account this is comes from id(1), not from bash's $EUID, which bash
# imports from the environment (#1109).
ME_UID="$(/usr/bin/id -u 2>/dev/null || true)"
root_tool_ok() {
  local meta
  [[ -f "$ROOT_STATE_TOOL" && ! -L "$ROOT_STATE_TOOL" && -r "$ROOT_STATE_TOOL" ]] || return 1
  meta="$(stat -c '%u:%a' -- "$ROOT_STATE_TOOL" 2>/dev/null)" || return 1
  [[ "${meta%%:*}" == "$ROOT_TOOL_UID" ]] && (( (8#${meta##*:} & 8#022) == 0 ))
}

# advisor/state belongs to the Advisor's account, so a name in it can be a
# link that account planted. Root reads it only through the root-held helper,
# which refuses a link at the name, judges the directories above
# advisor/state (none may be writable by an account other than its owner),
# and reads on a descriptor with a size cap (#1066). Anyone else reads it as themselves, which crosses
# nothing; a caller that cannot falls back to that same helper under sudo.
state_read() { # $1 = path, $2 = byte cap; prints the bytes, or fails
  local meta
  if [[ "$ME_UID" == 0 ]]; then
    meta="$(stat -c '%u:%a' -- "$ROOT_STATE_TOOL" 2>/dev/null)" || return 1
    [[ "${meta%%:*}" == 0 ]] && (( (8#${meta##*:} & 8#022) == 0 )) || return 1
    python3 -I "$ROOT_STATE_TOOL" read "$1" --max "$2" 2>/dev/null
    return
  fi
  head -c "$2" -- "$1" 2>/dev/null \
    || { root_tool_ok && sudo -n python3 -I "$ROOT_STATE_TOOL" read "$1" --max "$2" 2>/dev/null; }
}
# The approval token: its first line, and only when it is the shape the
# installer mints (48 random bytes, base64: 64 characters). Anything else is
# not sent anywhere.
approve_token() { # $1 = path; prints the token, or fails
  local t
  t="$(state_read "$1" 4096)" || return 1
  t="${t%%$'\n'*}"
  [[ "$t" =~ ^[A-Za-z0-9+/]{64}$ ]] || return 1
  printf '%s' "$t"
}
# The four values a re-seal reuses, each held to a shape before it is used.
model_fields() { # $1 = path to model.json; prints "base shape model credential"
  local json
  json="$(state_read "$1" 65536)" || return 1
  printf '%s' "$json" | python3 -I -c '
import json, re, sys
c = json.load(sys.stdin)
v = [c.get(k, "") for k in ("base_url", "shape", "model", "credential_name")]
ok = (isinstance(v[0], str) and re.fullmatch(r"https?://[^\s]{1,500}", v[0])
      and all(isinstance(x, str) and re.fullmatch(r"[A-Za-z0-9._:/@+-]{1,200}", x) for x in v[1:]))
if not ok:
    sys.exit(3)
print(*v)
'
}

[[ -f "$SEALER" ]] || { echo "error: $SEALER is missing; this tree is incomplete" >&2; exit 1; }
[[ -f "$CFG" ]] || {
  echo "no model is configured on this host, so there is nothing to re-seal." >&2
  echo "set one up first:  bash $REPO/scripts/setup-advisor-model.sh" >&2
  exit 1
}

# The four values that are not the key. Read from the file the Advisor itself
# reads, so a re-seal cannot quietly point at a different credential than the
# unit loads. This used to hard-code `model-api-key`, which stopped being the
# name when keys became per-provider, and a re-seal then wrote a credential
# nothing was looking for.
FIELDS="$(model_fields "$CFG")" \
  || { echo "error: $CFG could not be read as a plain file of the Advisor's (no link), or does not name a provider, shape, model and credential this can use" >&2; exit 1; }
read -r BASE SHAPE MODEL CRED_NAME <<<"$FIELDS"

echo "re-sealing for the model this host is configured with:"
echo "   provider    $BASE"
echo "   model       $MODEL"
echo "   credential  $CRED_NAME"
echo

# Read with -s so it never appears on screen, and never written anywhere by
# this script. The failure this catches: a key pasted with a trailing line, a
# wrapped line, or a smart quote from a document. The sealer checks it too;
# checking here as well names the problem while it is still in front of you.
read -r -s -p "paste the API key (hidden): " KEY
echo
KEY="${KEY//[$'\t\r\n ']/}"
[[ -n "$KEY" ]] || { echo "empty" >&2; exit 1; }
if [[ ! "$KEY" =~ ^[[:print:]]+$ ]]; then
  echo "the key contains a character that cannot go in an HTTP header." >&2
  echo "retype it rather than pasting, or paste into a plain editor first." >&2
  exit 1
fi
printf 'sealing %s...%s (%d chars, no whitespace)\n' "${KEY:0:8}" "${KEY: -4}" "${#KEY}"

# One sealing implementation, and it is not this file. scripts/aperire-seal-model-key.sh
# holds the whole privileged step, including the restart that makes a sealed
# key arrive. Arming needs root and an operator running this has it, so the
# window is opened and spent in the same breath.
sudo mkdir -p /etc/aperire
sudo install -o root -g root -m 0600 /dev/null "$ARM_FILE"

if ! printf '%s\n%s\n%s\n%s\n%s\n' "$BASE" "$SHAPE" "$MODEL" "$CRED_NAME" "$KEY" \
     | sudo env APERIRE_INSTANCE="${APERIRE_INSTANCE:-}" bash "$SEALER"; then
  unset KEY
  sudo rm -f "$ARM_FILE"
  echo
  echo "the seal did not finish cleanly. If the lines above show sealed=, the key IS sealed and the" >&2
  echo "Advisor did not answer afterwards (service=not-answering); otherwise nothing was sealed. Read the journal for the detail:" >&2
  echo "  journalctl -t aperire-seal-model-key -n 20 --no-pager" >&2
  exit 1
fi
unset KEY

echo
echo "asking the Advisor a question to prove it works..."
# The token goes in a header to the Advisor's own listener, so it is read the
# one safe way (approve_token, #1066), and a token that is not one stops the
# check here rather than sending whatever the name led to.
if ! TOKEN="$(approve_token "$REPO/advisor/state/approve.token")"; then
  echo "  the approval token could not be read as a plain file of the Advisor's, or is not one;"
  echo "  the key is sealed, and the check was not made. Ask the Advisor tab a question to see it work."
  exit 0
fi
# The sealer restarts the Advisor and counts the unit up as soon as systemd
# has forked it, which is tens of milliseconds before the listener is. A
# question sent that fast meets a refused connection (#1083), so the ask is
# repeated while the connection is refused, for up to PROOF_SECONDS, five
# times a second. Only a refused connect (curl exit 7, which loopback returns
# at once, so the budget is the real bound) is repeated: any other failure may
# have reached the Advisor, and the question costs a model call. A listener
# that accepts and then stalls is given ASK_SECONDS (90) to answer, no more.
# The key is sealed by now, so nothing below ends this run with an error.
PROOF_SECONDS="${APERIRE_RESEAL_PROOF_SECONDS:-20}"
[[ "$PROOF_SECONDS" =~ ^[0-9]{1,3}$ ]] || PROOF_SECONDS=20
PROOF_TRIES=$(( 10#$PROOF_SECONDS * 5 ))
ASK_SECONDS="${APERIRE_RESEAL_ASK_SECONDS:-90}"
[[ "$ASK_SECONDS" =~ ^[0-9]{1,3}$ ]] && (( 10#$ASK_SECONDS > 0 )) || ASK_SECONDS=90
reply="" answered=0 rc=0 tries=0
while :; do
  rc=0
  # The token goes on curl's standard input (-H @-), never its argv:
  # /proc/<pid>/cmdline is world readable (#705).
  reply="$(curl -s --connect-timeout 3 --max-time "$((10#$ASK_SECONDS))" -X POST -H 'content-type: application/json' \
    -H @- \
    -d '{"question":"Reply with just: ok"}' \
    "http://127.0.0.1:${APERIRE_ADVISOR_PORT:-7810}/v1/ask" <<<"authorization: Bearer $TOKEN")" || rc=$?
  if (( rc == 0 )); then answered=1; break; fi
  (( rc == 7 )) || break
  tries=$(( tries + 1 ))
  (( tries <= PROOF_TRIES )) || break
  sleep 0.2
done
if (( ! answered )); then
  if (( rc == 7 )); then
    echo "  the Advisor did not answer in ${PROOF_SECONDS} s. The key is sealed;"
  elif (( rc == 28 )); then
    echo "  the question did not finish in $((10#$ASK_SECONDS)) s. The key is sealed;"
  else
    echo "  the question did not go through (curl exit ${rc}). The key is sealed;"
  fi
  echo "  ask the Advisor tab a question to see it work."
  exit 0
fi
printf '%s' "$reply" | python3 -I -c '
import json, sys
try:
    d = json.load(sys.stdin)
    msg = str(d.get("reply") or d.get("error", "?"))
except Exception:
    msg = "the Advisor answered, but not with a reply this can read"
print("  " + msg)'
exit 0
