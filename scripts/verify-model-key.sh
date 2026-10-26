#!/usr/bin/env bash
# Check an API key works, and list the models it can actually reach.
#
# Worth doing before setup-advisor-model.sh rather than after: a wrong key or a
# model name that does not exist both surface as a failure in the drawer, and
# telling them apart there is slower than settling it here.
#
# The key is read with -s so it never appears on screen, and it is never
# written anywhere by this script. Nothing is stored — this only asks the
# provider what it knows.
#
#   ./scripts/verify-model-key.sh                 # xAI
#   ./scripts/verify-model-key.sh https://api.openai.com/v1
#
# For an already-installed key, read it back and re-check it. Which of the two
# commands applies depends on how this host keeps the key (#708): a blob sealed
# to the machine, or a root-only file on a host with no systemd-creds.
#   sudo systemd-creds decrypt /etc/aperire/creds/model-api-key - | ./scripts/verify-model-key.sh -
#   sudo cat /etc/aperire/creds/model-api-key.plain | ./scripts/verify-model-key.sh -

set -euo pipefail

# Provider resolution, in honesty order (2026-08-14 — an Anthropic key was
# recognised as Anthropic and then asked about at xAI, whose "incorrect API
# key" reads exactly like a bad paste):
#   1. an explicit argument wins;
#   2. else THIS host's configured model (advisor/state/model.json);
#   3. else the key's own prefix decides, once it is read below;
#   4. else the historical xAI default, said out loud.
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE="${1:-}"
BASE_FROM=""
if [[ -n "$BASE" ]]; then
  BASE_FROM="argument"
else
  # Same rule as everywhere else (#703): the unprivileged leg is this account
  # reading its own file, the sudo fallback is root and goes through the
  # helper. The base_url read here decides which address a key is verified
  # against, so a link that redirected it would send the key somewhere else.
  # The root-held copy, never the tree's (#886): sudo on a file in a folder the
  # Advisor's account can write is root running what it left there.
  # A constant, never read from the environment: what it names here is what
  # root runs under the sudo below (#1127). Checked before that sudo: a regular
  # file, not a link, owned by ROOT_TOOL_UID, writable by neither group nor
  # other. A suite that needs a stand-in rewrites these two lines in its own copy.
  ROOT_STATE_TOOL=/usr/local/sbin/aperire-state-file
  ROOT_TOOL_UID=0
  root_tool_ok() { local m; [[ -f "$ROOT_STATE_TOOL" && ! -L "$ROOT_STATE_TOOL" && -r "$ROOT_STATE_TOOL" ]] && m="$(stat -c '%u:%a' -- "$ROOT_STATE_TOOL" 2>/dev/null)" && [[ "${m%%:*}" == "$ROOT_TOOL_UID" ]] && (( (8#${m##*:} & 8#022) == 0 )); }
  CFG_BASE="$( { cat "$REPO/advisor/state/model.json" 2>/dev/null \
                 || { root_tool_ok && sudo -n python3 -I "$ROOT_STATE_TOOL" read "$REPO/advisor/state/model.json" 2>/dev/null; }; } \
               | python3 -I -c "import json,sys;print(json.load(sys.stdin).get('base_url',''))" 2>/dev/null || true)"
  if [[ -n "$CFG_BASE" ]]; then BASE="$CFG_BASE"; BASE_FROM="this host's model.json"; fi
fi

if [[ "$BASE" == "-" ]]; then
  BASE=https://api.x.ai/v1
  read -r KEY
elif [[ ! -t 0 ]]; then
  read -r KEY
else
  read -r -s -p "paste the API key (hidden): " KEY
  echo
fi
KEY="${KEY//[$'\t\r\n ']/}"

if [[ -z "$KEY" ]]; then
  echo "no key given" >&2
  exit 2
fi

# Shape check first — a truncated paste is the most common failure and it is
# free to catch. Not a validation of the key, just of the paste.
printf 'key looks like: %s…%s  (%d chars)\n' "${KEY:0:8}" "${KEY: -4}" "${#KEY}"
case "$KEY" in
  xai-*)      echo "  prefix xai- — an xAI key" ;;
  sk-ant-*)   echo "  prefix sk-ant- — an Anthropic key" ;;
  sk-*)       echo "  prefix sk- — an OpenAI-style key" ;;
  *)     echo "  no recognised prefix; that may be fine for a self-hosted provider" ;;
esac
if [[ -z "$BASE" ]]; then
  case "$KEY" in
    sk-ant-*) BASE=https://api.anthropic.com;  BASE_FROM="the key's prefix" ;;
    xai-*)    BASE=https://api.x.ai/v1;        BASE_FROM="the key's prefix" ;;
    sk-*)     BASE=https://api.openai.com/v1;  BASE_FROM="the key's prefix" ;;
    *)        BASE=https://api.x.ai/v1;        BASE_FROM="the historical default — pass a base URL if this is wrong" ;;
  esac
fi
echo

echo "asking $BASE (chosen from $BASE_FROM) what it knows…"
# Anthropic uses x-api-key and /v1/models; asking it the OpenAI question gets a
# 404 that reads exactly like a rejected key.
# The key reaches curl on its standard input (-H @-), never on its argv,
# where any account on the host can read it in /proc (#705).
if [[ "$BASE" == *anthropic* ]]; then
  code=$(curl -sS -o /tmp/aperire-models.$$ -w '%{http_code}' \
    -H @- -H 'anthropic-version: 2023-06-01' \
    "$BASE/v1/models" <<<"x-api-key: $KEY" || echo 000)
else
  code=$(curl -sS -o /tmp/aperire-models.$$ -w '%{http_code}' \
    -H @- "$BASE/models" <<<"Authorization: Bearer $KEY" || echo 000)
fi

case "$code" in
  200)
    echo "key works. models available to it:"
    echo
    python3 -I -c '
import json,sys
d=json.load(open(sys.argv[1]))
ids=sorted(m.get("id","?") for m in d.get("data",[]))
for i in ids: print("   "+i)
print()
print(f"   {len(ids)} model(s)")
' /tmp/aperire-models.$$ 2>/dev/null || cat /tmp/aperire-models.$$
    echo
    echo "Use one of those names verbatim in setup-advisor-model.sh."
    ;;
  401|403)
    echo "the provider rejected the key ($code). it is wrong, revoked, or for another account." >&2
    head -c 300 /tmp/aperire-models.$$ >&2; echo >&2
    ;;
  000)
    echo "could not reach $BASE at all. check the host's outbound access." >&2
    ;;
  *)
    echo "unexpected response $code:" >&2
    head -c 300 /tmp/aperire-models.$$ >&2; echo >&2
    ;;
esac

rm -f /tmp/aperire-models.$$
[[ "$code" == "200" ]]
