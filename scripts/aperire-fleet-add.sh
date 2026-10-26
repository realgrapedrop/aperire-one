#!/usr/bin/env bash
# Fleet join helper — one command adds a node to THIS host's fleet.
#
# Writes this dashboard's registry (decisions.md D5/D6, the pubkey-pinning
# slice), and the Advisor's too when the Advisor is installed here:
#   dashboard/config/fleet.yaml     — this dashboard's own peer table
#   advisor/state/fleet.json        — advisord's read-only peer table
#
# and, when a hostname/tunnel pair is given, provisions (or prints) the DNS
# record that hostname needs.
#
# No hand-written YAML/JSON: every value this script writes is either typed
# on argv or read from the peer itself (its own reported node key, TOFU —
# see "Trust on first use" in docs/FLEET-GUIDE.md).
#
# Both registries fail an ENTIRE file closed on one bad row (fleet-registry.ts,
# advisor/internal/fleet/fleet.go), so this script backs up whichever file it
# is about to touch, appends, re-reads what it just wrote with the SAME parser
# the real service uses, and restores the backup if that re-read does not
# confirm the new row landed cleanly. A helper that can silently empty a
# fleet is worse than no helper.
#
# Refuses everything it can before touching anything: argument shape, the
# peer's own identity, and both registries' duplicate/parse state are all
# checked before DNS is provisioned or a byte is written.
#
#   scripts/aperire-fleet-add.sh \
#     --read-origin http://127.0.0.1:7901 \
#     --token-path "$HOME/core-two.token" \
#     [--dashboard-url https://core-two.example.internal/overview.html] \
#     [--label core-two] \
#     [--role node] \
#     [--hostname core-two.example.internal --tunnel my-fleet-tunnel] \
#     [--place-token] \
#     [--dry-run]
#
# The example is the usual case, a peer on another machine: --token-path is
# your own copy of the peer's read token, brought here first (see "The peer's
# read token" in docs/FLEET-GUIDE.md). A peer on this machine is the
# one case that points it at the peer's own file.

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DASH_FLEET="$REPO/dashboard/config/fleet.yaml"
UNIT_DIR="${APERIRE_UNIT_DIR:-/etc/systemd/system}"
# The root-held copy of the state helper (get-aperire.sh places it, root-owned,
# with the programs that use it). A read that needs sudo goes through this copy,
# never through scripts/state-file.py in the tree: that file sits in a folder
# the dashboard's account can write, and sudo would run it as root (#886).
#
# A literal path, and never read from the environment: the login that runs
# this sets its own environment, and what it names here is what root runs
# (ADR 0024). A suite that needs a stand-in rewrites these two lines in its own
# copy of this file, the way scripts/test-root-runs-staged.sh does. Before
# every sudo the file is checked (root_tool_ok below): the owner named on the
# next line, and writable by no group or other.
ROOT_STATE_TOOL=/usr/local/sbin/aperire-state-file
ROOT_TOOL_UID=0
ADV_FLEET="$REPO/advisor/state/fleet.json"
TSX="$REPO/dashboard/node_modules/.bin/tsx"

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
info() { printf '   %s\n' "$*"; }
die()  { printf '\n\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

# Is the root-held state helper one root may run? Readable, a regular file and
# not a link, owned by ROOT_TOOL_UID, and writable by neither group nor other.
# On a refusal ROOT_TOOL_WHY says which, and the callers print it: a helper
# somebody else could have changed is root running their code. Checked
# immediately before each sudo that uses it, not once at the top.
ROOT_TOOL_WHY=""
root_tool_ok() {
  local meta uid mode
  ROOT_TOOL_WHY=""
  if [[ ! -e "$ROOT_STATE_TOOL" ]]; then ROOT_TOOL_WHY="$ROOT_STATE_TOOL is not there"; return 1; fi
  if [[ -L "$ROOT_STATE_TOOL" || ! -f "$ROOT_STATE_TOOL" ]]; then ROOT_TOOL_WHY="$ROOT_STATE_TOOL is a link or not a regular file"; return 1; fi
  if [[ ! -r "$ROOT_STATE_TOOL" ]]; then ROOT_TOOL_WHY="$ROOT_STATE_TOOL is not readable by $(id -un)"; return 1; fi
  meta="$(stat -c '%u %a' -- "$ROOT_STATE_TOOL" 2>/dev/null)" || { ROOT_TOOL_WHY="could not stat $ROOT_STATE_TOOL"; return 1; }
  uid="${meta%% *}"; mode="${meta##* }"
  if [[ "$uid" != "$ROOT_TOOL_UID" ]]; then
    ROOT_TOOL_WHY="$ROOT_STATE_TOOL is owned by uid $uid, not uid $ROOT_TOOL_UID, so root will not run it"; return 1
  fi
  if (( (8#$mode & 8#022) != 0 )); then
    ROOT_TOOL_WHY="$ROOT_STATE_TOOL is mode $mode, writable by its group or by others, so root will not run it"; return 1
  fi
  return 0
}

# The one reader of the Advisor's account (#809), from this same checkout.
[[ -r "$REPO/scripts/advisor-owner-lib.sh" ]] \
  || die "$REPO/scripts/advisor-owner-lib.sh is missing from this checkout, and it is what reads which account this host's Advisor runs as"
# shellcheck source=scripts/advisor-owner-lib.sh
. "$REPO/scripts/advisor-owner-lib.sh"

usage() {
  cat <<'USAGE'
usage: aperire-fleet-add.sh --read-origin <url> --token-path <path> \
         [--dashboard-url <https-url>] [--label <label>] [--role <role>] \
         [--hostname <host> --tunnel <name>] \
         [--place-token] [--dry-run]
       aperire-fleet-add.sh --replace-token --label <label> --token-path <path>

  --read-origin   required. The peer's read-API origin. Must be a bare
                  loopback origin (http://127.0.0.1:<port> or
                  http://localhost:<port>) — the read API's own rule.
  --token-path    required. Path to the PEER's own read.token, readable
                  by the account running this. A copy you made with scp into
                  your own home is the ordinary case (see --place-token).
                  The Advisor's own state folder is not: on a host where the
                  Advisor has its own account that folder is closed to you,
                  and a token is not read from it.
  --place-token   optional. --token-path is YOUR copy of the peer's token.
                  Root places a copy of it at
                  <install>/advisor/state/peer-tokens/<label>.token, owned
                  by root, in the group the dashboard and the Advisor already
                  read this host's own read.token through, mode 0640, and the
                  registries record that path. Your copy is removed once the
                  join has been verified. Needs the Advisor's state folder
                  here and the root-held state helper, and asks sudo once.
  --replace-token a node already joined with --place-token has had its token
                  rotated. Places your new copy over the old one the same way
                  and changes nothing else. Takes only --label and
                  --token-path.
  --dashboard-url optional. A record of where this node's own dashboard
                  answers, for an operator reading the registry. Nothing
                  renders it as a link and nothing dials it: picking a node
                  from the fleet chip redraws THIS dashboard against that
                  node, it never sends the browser to the node's own.
                  Omitted writes no dashboard_url line at all — the same row
                  a paired node produces when it does not know an address
                  anybody else could open (#339), so a node whose dashboard
                  address nobody knows yet still joins. A value that IS
                  given must be https: the fleet's own origin rule
                  (scripts/fleet-origin.sh) allows plain http only to a
                  loopback name, and a loopback name is exactly what
                  fleet-registry.ts drops from a row, so a plain-http
                  address is either one this product does not accept or one
                  no row would keep.
  --label         optional. a-z, 0-9, -, 1 to 32 characters. Proposed from
                  the peer's own node key when omitted.
  --hostname      optional, paired with --tunnel. Provisions DNS for THIS
                  hostname via cloudflared when it and an origin cert are
                  available; otherwise prints the record to create by hand.
                  Its own argument, never read out of --dashboard-url, so a
                  join with no dashboard address can still route a name.
                  Never fails the join either way.
  --tunnel        optional, paired with --hostname. The Cloudflare tunnel
                  name to route.
  --role          optional. What the peer IS: aggregator, node, validator,
                  or relay. Recorded in both registries, and told to the
                  Advisor so it can name the right host for a command and
                  stop offering a node's remedy to a host with no node.
                  Omitted means unspecified — never guessed, because a
                  dashboard with no node looks exactly as much like an
                  aggregator as it does like a broken node.
  --dry-run       print every change; write nothing, run nothing that
                  mutates DNS, either registry, or either trust file.

Pairwise trust key exchange (security-review-enrollment-grant.md, 2026-08-10):
this join also ensures this node has its own Ed25519 trust key
(dashboard/config/fleet-trust.yaml) and places this node's PUBLIC key into
the peer's own trust file when the peer is a local checkout, so the peer can
later accept an enrollment grant issued from here. Directional only, this
node -> the peer — the reverse direction (also trusting grants FROM the
peer) is deliberately not offered by this script; it would need to read the
peer's own private key to derive its public half, and that is not a
private-key handling path this slice takes on. Nothing about the XRPL node
itself, and nothing reads this file yet.
USAGE
}

# One scratch directory for every temp file this run creates, rather than
# tracking paths in an array: mk_tmp is called as `x="$(mk_tmp)"` throughout
# this script, and command substitution always forks a subshell — an array
# append inside that subshell is invisible to the parent shell, so a
# TMP_FILES array filled this way is silently empty at cleanup time no
# matter how many temp files were actually made. A shared directory has no
# such scoping problem: nothing needs to be recorded anywhere.
WORKDIR="$(mktemp -d)"
# The peer's token, placed under the Advisor's state folder by root (#1075).
# Declared before the trap that reads them: PLACED_TOKEN is the file this run
# put there and JOIN_DONE is set once both registries name it, so a run that
# fails in between takes its own file back out.
STATE_DIR="$REPO/advisor/state"
PEER_TOKEN_DIR="$STATE_DIR/peer-tokens"
PLACED_TOKEN="" JOIN_DONE=0
ROOT_RUN=()
(( EUID == 0 )) || ROOT_RUN=(sudo)
# invoked indirectly by the EXIT trap on the next line; shellcheck 0.9.x calls
# the body unreachable (SC2317), 0.10.x calls the function uninvoked (SC2329)
# shellcheck disable=SC2317,SC2329
cleanup() {
  rm -rf -- "$WORKDIR" 2>/dev/null
  # Through the root-held helper, on a descriptor, never `rm` by name as root
  # (#897). A run that placed the token and then did not finish leaves no
  # orphan of it behind; one that cannot say so and names the file.
  if [[ -n "$PLACED_TOKEN" ]] && (( ! JOIN_DONE )); then
    if root_tool_ok && "${ROOT_RUN[@]}" python3 -I "$ROOT_STATE_TOOL" unlink "$PLACED_TOKEN" --root "$STATE_DIR" >/dev/null 2>&1; then
      info "the join did not finish, so the token this run placed at $PLACED_TOKEN was taken out again"
    else
      info "the join did not finish, and the token this run placed at $PLACED_TOKEN could not be removed. It is root's: remove it with sudo rm, or run this again, which replaces it"
    fi
  fi
  return 0
}
trap cleanup EXIT
mk_tmp() { mktemp -p "$WORKDIR"; }

# ── Arguments ────────────────────────────────────────────────────────────
READ_ORIGIN="" TOKEN_PATH="" LABEL="" DASHBOARD_URL="" HOSTNAME_ARG="" TUNNEL="" DRY_RUN=0
ROLE=""
PLACE_TOKEN=0 REPLACE_TOKEN=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --read-origin)   [[ $# -ge 2 ]] || die "--read-origin needs a value"; READ_ORIGIN=$2; shift 2 ;;
    --token-path)    [[ $# -ge 2 ]] || die "--token-path needs a value"; TOKEN_PATH=$2; shift 2 ;;
    --label)         [[ $# -ge 2 ]] || die "--label needs a value"; LABEL=$2; shift 2 ;;
    --dashboard-url) [[ $# -ge 2 ]] || die "--dashboard-url needs a value"; DASHBOARD_URL=$2; shift 2 ;;
    --hostname)      [[ $# -ge 2 ]] || die "--hostname needs a value"; HOSTNAME_ARG=$2; shift 2 ;;
    --tunnel)        [[ $# -ge 2 ]] || die "--tunnel needs a value"; TUNNEL=$2; shift 2 ;;
    --this-label)    die "--this-label is gone: the peer always holds this node's key as peers.aggregator, because every signer (trust push, knowledge push, fleet seal, fleet arm) signs as that fixed label (#177)" ;;
    --role)          [[ $# -ge 2 ]] || die "--role needs a value"; ROLE=$2; shift 2 ;;
    --dry-run)       DRY_RUN=1; shift ;;
    --place-token)   PLACE_TOKEN=1; shift ;;
    --replace-token) REPLACE_TOKEN=1; shift ;;
    -h|--help)       usage; exit 0 ;;
    *) die "unknown argument '$1' — see --help" ;;
  esac
done

if (( REPLACE_TOKEN )); then
  (( ! PLACE_TOKEN )) || die "--replace-token and --place-token are two different jobs: one re-places the token of a node already joined, the other joins a new one"
  [[ -z "$READ_ORIGIN$DASHBOARD_URL$HOSTNAME_ARG$TUNNEL$ROLE" ]] \
    || die "--replace-token takes only --label and --token-path: the node is already registered, and nothing but its token is replaced"
  [[ -n "$LABEL" ]]       || { usage; die "--replace-token needs --label, the node whose token this is"; }
else
  [[ -n "$READ_ORIGIN" ]] || { usage; die "--read-origin is required"; }
fi
[[ -n "$TOKEN_PATH" ]]    || { usage; die "--token-path is required"; }
# No check for --dashboard-url: it is optional (#339). What happens to a
# value that IS given is with the other argument validation below.
if [[ -n "$HOSTNAME_ARG" || -n "$TUNNEL" ]]; then
  [[ -n "$HOSTNAME_ARG" && -n "$TUNNEL" ]] || die "--hostname and --tunnel must be given together"
fi

LABEL_RE='^[a-z0-9-]{1,32}$'
NODE_KEY_RE='^n[1-9A-HJ-NP-Za-km-z]{20,}$'

validate_label() {
  [[ "$1" =~ $LABEL_RE ]] || die "label '$1' must match [a-z0-9-]{1,32} — the registry's own charset"
}

# The closed role set, declared identically in three places that do not
# import from one another: fleet-registry.ts (ROLES), internal/fleet's
# knownRoles, and here. A value outside it fails BOTH registries' parsers
# closed, so it is refused before anything is written rather than after.
case "$ROLE" in
  ""|aggregator|node|validator|relay) ;;
  *) die "--role '$ROLE' is not one of: aggregator, node, validator, relay" ;;
esac

# A bare loopback origin — mirrors fleet-registry.ts's isLoopbackOrigin
# exactly (protocol, no path/query/fragment/credentials, host in the
# loopback set). This is the read API's own rule (docs/FLEET-GUIDE.md,
# "A request from any address other than loopback is refused even WITH the
# token"), not a preference of this script.
check_loopback_origin() {
  python3 -I - "$1" <<'PY'
import sys
from urllib.parse import urlparse
u = urlparse(sys.argv[1])
ok = (
    u.scheme in ("http", "https")
    and u.path in ("", "/")
    and not u.query and not u.fragment
    and not u.username and not u.password
    and u.hostname is not None
    and u.hostname.lower() in ("127.0.0.1", "localhost", "::1")
)
sys.exit(0 if ok else 1)
PY
}

check_https_url() {
  python3 -I - "$1" <<'PY'
import sys
from urllib.parse import urlparse
u = urlparse(sys.argv[1])
sys.exit(0 if (u.scheme == "https" and u.netloc) else 1)
PY
}

# ── Pairwise trust key exchange ─────────────────────────────────────────
# security-review-enrollment-grant.md (2026-08-10), item 7 / condition
# P1-013. Its own file — dashboard/config/fleet-trust.yaml — never a field
# in fleet.yaml: loadFleetRegistry refuses any key outside its own
# ALLOWED_KEY_SET and drops the whole file, so writing a trust field there
# before the loader learns it would empty the fleet. Directional ONLY: a
# node holds the public key only of a peer it accepts grants FROM, and this
# join places THIS node's public key into the peer's file (the peer will
# accept grants from here) — never the reverse in this slice. Recording
# trust the other way round would mean reading the PEER's private key to
# derive its public half, which is not a private-key handling path this
# script takes on; left as a follow-up (see the fleet build punch list).
# Nothing reads this file yet — the grant redemption code does not exist —
# so a problem here is reported and the run continues, with exactly one
# hard exception: an EXISTING file
# already on disk that is too loosely permissioned or does not parse is
# refused outright, never silently repaired.

# The group this file is installed with decides whether advisord can open it
# at all, and advisord is the only thing that ever needs to: it verifies every
# pushed trust bundle against peers.<issuer> in here. The dashboard user needs
# it too on an aggregator (the private key signs the bundle), so the right
# answer is a group BOTH are in — which is exactly what
# install-advisor-account.sh creates and puts in the unit's
# SupplementaryGroups.
#
# Found the hard way on 2026-08-19: this used to return the dashboard unit's
# Group=, which on a host where advisord runs as its own account is a group
# advisord is not in. Every push to that node then failed 403 and the operator
# met it as "your passkey is not enrolled", three hops from the cause.
#
# So: the first group the advisor account and the account running this script
# have in common. Falls back to the old answer when there is no advisord here,
# which is the correct answer for a read-only peer, or when the Advisor runs
# as root, which reads every file and has no group of its own to share.
#
# The advisor account comes from aperire-advisord.service by that exact name.
# A glob over aperire-advisord*.service found the credcheck unit (#541,
# User=root by design) first, so this compared root's groups with this
# account's and never confirmed the group advisord actually reads (#809).
#
# Sets TRUST_GROUP_CONFIRMED (P3-096) rather than only printing the group:
# called directly, never through $( ), because a command substitution is a
# subshell and cannot hand a second value back to the caller (the same rule
# install-model-key-sealer.sh's resolve_node_key follows). CONFIRMED=1 means
# this account and the local advisord account genuinely share the printed
# group: the group is what advisord actually reads through. CONFIRMED=0
# means there was no local advisord to check against, or none of its groups
# matched, and the printed value is only the dashboard unit's declared
# group, or this account's own primary group as a last resort: neither is a
# claim that advisord can read anything through it.
TRUST_GROUP_FOUND=""
TRUST_GROUP_CONFIRMED=0
resolve_trust_group() {
  local unit="$UNIT_DIR/aperire-server.service" g="" adv="" mine="" cand
  TRUST_GROUP_FOUND=""; TRUST_GROUP_CONFIRMED=0
  adv="$(advisor_owner_account "$UNIT_DIR")" \
    || die "$(advisor_owner_unread_msg "$UNIT_DIR/aperire-advisord.service")"
  if [[ -n "$adv" && "$adv" != root ]] && id -u "$adv" >/dev/null 2>&1; then
    mine=" $(id -nG) "
    for cand in $(id -nG "$adv" 2>/dev/null); do
      if [[ "$mine" == *" $cand "* ]]; then
        TRUST_GROUP_FOUND="$cand"; TRUST_GROUP_CONFIRMED=1
        return
      fi
    done
  fi
  [[ -r "$unit" ]] && g="$(awk -F= '/^Group=/{print $2; exit}' "$unit")"
  [[ -n "$g" ]] || g="$(id -gn)"
  TRUST_GROUP_FOUND="$g"
}

trust_file_mode() {  # path -> mode string ("644"), "" if absent, "?" if unreadable
  local ref="$1" m
  [[ -e "$ref" ]] || { printf ''; return; }
  if m="$(stat -c '%a' "$ref" 2>/dev/null)"; then printf '%s' "$m"; return; fi
  if command -v sudo >/dev/null 2>&1 && m="$(sudo stat -c '%a' "$ref" 2>/dev/null)"; then printf '%s' "$m"; return; fi
  printf '?'
}

mode_wider_than_640() {
  local m="$1"
  [[ "$m" =~ ^[0-7]{3,4}$ ]] || return 1
  (( (8#$m & ~8#640) != 0 ))
}

# Fails the WHOLE run — before any mutation — on a trust file already on
# disk that is too loosely permissioned, or does not parse as this file's
# own shape ({private_key?, peers?}). Silent (no output) when the path is
# absent, or exists and is fine; a later step handles absent-vs-create.
check_trust_file_or_die() {
  local path="$1" m raw raw_file
  [[ -e "$path" ]] || return 0
  m="$(trust_file_mode "$path")"
  if [[ -n "$m" && "$m" != "?" ]] && mode_wider_than_640 "$m"; then
    die "$path exists with mode $m, wider than 0640 — a signing-key file this loose is refused, never silently tightened. Fix it deliberately (chmod 0640, confirm the owner) and re-run."
  fi
  if [[ -r "$path" ]]; then raw="$(cat "$path")"
  elif command -v sudo >/dev/null 2>&1; then raw="$(sudo cat "$path" 2>/dev/null)" || die "$path exists but could not be read even with sudo"
  else die "$path exists and is not readable by $(id -un), and sudo is not available here"
  fi
  raw_file="$(mk_tmp)"
  printf '%s' "$raw" > "$raw_file"
  python3 -I - "$raw_file" <<'PY' || die "$path exists but is not shaped like a trust file ({private_key?, peers?}) — refusing to touch a broken file"
import yaml, sys
with open(sys.argv[1]) as f:
    text = f.read()
if not text.strip():
    sys.exit(0)
try:
    data = yaml.safe_load(text)
except yaml.YAMLError:
    sys.exit(1)
if data is None:
    sys.exit(0)
if not isinstance(data, dict):
    sys.exit(1)
if set(data.keys()) - {"private_key", "peers"}:
    sys.exit(1)
pk = data.get("private_key")
if pk is not None and not isinstance(pk, str):
    sys.exit(1)
peers = data.get("peers")
if peers is not None and not isinstance(peers, dict):
    sys.exit(1)
PY
}

# root:<service group> for a fresh file; a plain-user degrade (0600, owned
# by whoever is running this) when privilege isn't available — never wider
# than what root:group 0640 would have been, and never blocking the join.
install_owned() {
  local tmp="$1" target="$2" owner="$3" group="$4" mode="$5"
  local cmd=()
  if [[ "$owner" == "root" ]]; then
    # A root-owned file needs sudo regardless of who can write the
    # directory — dashboard/config/ is normally operator-writable, which
    # would otherwise make this branch look "already writable" and skip
    # sudo, silently downgrading every install to the fallback below and
    # never actually reaching root:group 0640 on an ordinary host.
    (( EUID == 0 )) || cmd=(sudo)
  else
    local writable=0
    if [[ -e "$target" ]]; then [[ -w "$target" ]] && writable=1
    else [[ -w "$(dirname "$target")" ]] && writable=1
    fi
    (( writable )) || cmd=(sudo)
  fi
  "${cmd[@]}" install -o "$owner" -g "$group" -m "$mode" "$tmp" "$target.new" 2>/dev/null || return 1
  "${cmd[@]}" mv -f "$target.new" "$target" 2>/dev/null || return 1
  return 0
}

gen_ed25519_b64_pair() {   # prints "PRIV_B64URL PUB_B64URL"
  local pem priv pub
  pem="$(mk_tmp)"
  openssl genpkey -algorithm ed25519 -out "$pem" >/dev/null 2>&1 || return 1
  priv="$(openssl pkey -in "$pem" -outform DER 2>/dev/null | tail -c 32 \
    | python3 -I -c 'import sys,base64; sys.stdout.write(base64.urlsafe_b64encode(sys.stdin.buffer.read()).decode().rstrip("="))')"
  pub="$(openssl pkey -in "$pem" -pubout -outform DER 2>/dev/null | tail -c 32 \
    | python3 -I -c 'import sys,base64; sys.stdout.write(base64.urlsafe_b64encode(sys.stdin.buffer.read()).decode().rstrip("="))')"
  [[ -n "$priv" && -n "$pub" ]] || return 1
  printf '%s %s\n' "$priv" "$pub"
}

# The fixed PKCS8 DER prefix for an Ed25519 private key, followed by the raw
# 32-byte seed, is a complete, standard PrivateKeyInfo — verified by
# round-tripping it through `openssl pkey -pubout` against a genuine
# genpkey-produced key and diffing the public output byte for byte.
#
# The seed travels over stdin, never as an argv/-c string: a value passed on
# a command line sits in that process's argv for as long as it runs, visible
# to any local account via /proc/<pid>/cmdline. A private key deserves
# better than that even when it is this node's own.
pubkey_from_priv_b64() {   # $1 = private key seed, b64url -> public key, b64url
  local der_tmp
  der_tmp="$(mk_tmp)"
  printf '%s' "$1" | python3 -I -c "
import sys, base64
def unpad(s): return s + '=' * (-len(s) % 4)
seed = base64.urlsafe_b64decode(unpad(sys.stdin.read()))
if len(seed) != 32:
    sys.exit(1)
open('$der_tmp', 'wb').write(bytes.fromhex('302e020100300506032b657004220420') + seed)
" || return 1
  openssl pkey -inform DER -in "$der_tmp" -pubout -outform DER 2>/dev/null | tail -c 32 \
    | python3 -I -c 'import sys,base64; sys.stdout.write(base64.urlsafe_b64encode(sys.stdin.buffer.read()).decode().rstrip("="))'
}

# Adds/updates peers[label] = pub in a trust file, preserving everything
# else. existing_file may be empty (absent file) — that is a fresh
# {peers: {label: pub}} with no private_key, which is a legitimate
# audience-only state; generating another node's private key from here
# would be inventing structure the review does not ask for.
merge_trust_peer_pub() {
  local existing_file="$1" out_file="$2" label="$3" pub="$4"
  python3 -I - "$existing_file" "$out_file" "$label" "$pub" <<'PY'
import yaml, sys
existing_path, out_path, label, pub = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
with open(existing_path) as f:
    text = f.read()
data = yaml.safe_load(text) if text.strip() else {}
if data is None:
    data = {}
peers = data.get("peers") or {}
peers[label] = pub
data["peers"] = peers
with open(out_path, "w") as f:
    yaml.safe_dump(data, f, default_flow_style=False, sort_keys=False)
PY
}

read_trust_file_raw() {  # path -> prints contents ("" if absent/unreadable)
  local path="$1"
  [[ -e "$path" ]] || return 0
  if [[ -r "$path" ]]; then cat "$path"; return; fi
  command -v sudo >/dev/null 2>&1 && sudo cat "$path" 2>/dev/null
  return 0
}

# fleet_add_paired: the nodes this host's records already name, one per
# line, or "unreadable <path>" for a record that is not a plain file or does
# not parse, which counts the same (#851 review L3). The same three records
# the grant installer counts: root's fleet-nodes.conf, fleet-links.json, and
# every fleet.yaml row but the one marked role: aggregator. Read by path, as
# this script reads and writes fleet.yaml everywhere else; a link or a FIFO
# at a name is refused here rather than opened.
fleet_add_paired() {
  python3 -I - "${APERIRE_ETC:-/etc/aperire}/fleet-nodes.conf" "$REPO/dashboard/config/fleet-links.json" "$DASH_FLEET" <<'PY'
import json, os, re, stat, sys
import yaml
LABEL = re.compile(r"[a-z0-9-]{1,32}")
out = []
def note(label, path):
    out.append(label if isinstance(label, str) and LABEL.fullmatch(label) else "unreadable %s" % path)
for kind, path in zip(("nodes", "links", "yaml"), sys.argv[1:4]):
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        continue
    except OSError:
        out.append("unreadable %s" % path); continue
    if not stat.S_ISREG(st.st_mode) or st.st_size > 1048576:
        out.append("unreadable %s" % path); continue
    try:
        text = open(path, encoding="utf-8").read()
    except PermissionError:
        # Root's own record, 0600, and this script runs as the account: it
        # still counts, failing closed, and says why it was not read.
        why = "root's record, which this account cannot read; run this as root to check it" if kind == "nodes" \
            else "this account cannot read it"
        out.append("unreadable %s (%s)" % (path, why))
        continue
    except Exception:
        out.append("unreadable %s" % path); continue
    try:
        if kind == "nodes":
            for line in text.split("\n"):
                f = line.split()
                if f and not f[0].startswith("#"):
                    note(f[0], path)
            continue
        doc = json.loads(text) if kind == "links" else yaml.safe_load(text)
        if doc is None:
            continue
        if not isinstance(doc, dict):
            raise ValueError
        rows = doc.get("links" if kind == "links" else "fleet") or []
        if not isinstance(rows, list):
            raise ValueError
        for r in rows:
            if kind == "yaml" and isinstance(r, dict) and isinstance(r.get("role"), str) and r.get("role") == "aggregator":
                continue
            note(r.get("label") if isinstance(r, dict) else None, path)
    except Exception:
        out.append("unreadable %s" % path)
sys.stdout.write("".join(sorted(set(l + "\n" for l in out))))
PY
}

# Ensures $HOME_TRUST carries a usable private_key (generating one if
# needed, preserving any existing peers: map), and sets HOME_PRIV/HOME_PUB.
# Returns 1 on any problem — the trust step is a bonus on top of the join,
# and check_trust_file_or_die already refused the one case (an existing
# broken file) that this function must not paper over. It dies on one: a
# key missing on a host whose records already name a paired node (#851
# review L3), before this script has written anything.
ensure_own_trust_key() {
  local existing existing_file current_priv
  existing="$(read_trust_file_raw "$HOME_TRUST")"
  existing_file="$(mk_tmp)"
  printf '%s' "$existing" > "$existing_file"

  current_priv="$(python3 -I - "$existing_file" <<'PY'
import yaml, sys
with open(sys.argv[1]) as f:
    text = f.read()
if not text.strip():
    sys.exit(0)
data = yaml.safe_load(text)
if isinstance(data, dict) and isinstance(data.get("private_key"), str) and data["private_key"]:
    sys.stdout.write(data["private_key"])
PY
)"
  if [[ -n "$current_priv" ]]; then
    HOME_PRIV="$current_priv"
    HOME_PUB="$(pubkey_from_priv_b64 "$HOME_PRIV")"
    [[ -n "$HOME_PUB" ]] || { info "could not derive this node's trust public key from its stored private key — skipping the trust-key step"; return 1; }
    return 0
  fi

  # #851 review L3: no key here, and this host already has a fleet. Those
  # nodes trust the key that is gone; a new one would cut them all off. The
  # same refusal the grant installer makes, before anything is written.
  local paired
  paired="$(fleet_add_paired)" || paired="unreadable (the records could not be checked)"
  if [[ -n "$paired" ]]; then
    die "$HOME_TRUST holds no fleet trust key, and this host already has a fleet:
       ${paired//$'\n'/$'\n'       }
     Every node paired to the old key still trusts it, so this makes no new one, and nothing was written.
     Put it back from your backup set:
       curl -fsSL https://get.aperire.one | bash -s -- --dir $REPO --restore --from <backup set>
     Or make a new one on purpose and pair each node again:
       curl -fsSL https://get.aperire.one | bash -s -- --dir $REPO --run fleet-broker-grant --new-fleet-keys
     If a node named above is this host, mark its fleet.yaml row role: aggregator."
  fi

  local pair priv pub out_file
  pair="$(gen_ed25519_b64_pair)" \
    || { info "could not generate a trust keypair (openssl) — skipping the trust-key step this run"; return 1; }
  priv="${pair%% *}"; pub="${pair##* }"
  out_file="$(mk_tmp)"
  python3 -I - "$existing_file" "$out_file" "$priv" <<'PY'
import yaml, sys
existing_path, out_path, priv = sys.argv[1], sys.argv[2], sys.argv[3]
with open(existing_path) as f:
    text = f.read()
data = yaml.safe_load(text) if text.strip() else {}
if data is None:
    data = {}
data["private_key"] = priv
data.setdefault("peers", data.get("peers") or {})
with open(out_path, "w") as f:
    yaml.safe_dump(data, f, default_flow_style=False, sort_keys=False)
PY

  # Three tiers, in the order install-advisor-account.sh's own rule and a
  # guaranteed write both have to hold (#538). root:$TRUST_GROUP 640 is the
  # rule everywhere else in the fleet; without root, $TRUST_GROUP is still
  # the group resolve_trust_group found THIS account sharing with advisord
  # (or with the dashboard, on a host with none), so a self-owned file at
  # 640 through that group is not a downgrade, it is the same file
  # advisord reads, one chown short of the full rule. Only when even that
  # group is not one this account belongs to (a host where the group
  # resolved from a unit this account never joined) does this fall back to
  # 0600, and it says plainly that the fallback is what happened, because a
  # file this narrow is the exact shape #538 found stuck on the lab aggregator for a month.
  if install_owned "$out_file" "$HOME_TRUST" root "$TRUST_GROUP" 640; then
    info "generated this node's trust key: $HOME_TRUST (root:$TRUST_GROUP, mode 640)"
  elif install_owned "$out_file" "$HOME_TRUST" "$(id -un)" "$TRUST_GROUP" 640; then
    info "generated this node's trust key: $HOME_TRUST ($(id -un):$TRUST_GROUP, mode 640)"
    if [[ "${TRUST_GROUP_CONFIRMED:-0}" -eq 1 ]]; then
      info "(could not set root ownership, group $TRUST_GROUP is confirmed shared with the local advisord account)"
    else
      # P3-096: $TRUST_GROUP here is a fallback (the dashboard unit's declared
      # group, or this account's own primary group), never checked against a
      # local advisord account: there was none to check, or none of its
      # groups matched. Saying "advisord reads it through" here would be a
      # claim this run never verified, on the exact file #538 was found
      # stuck unreadable on for a month.
      info "(could not set root ownership, and could not confirm a local advisord shares group"
      info " $TRUST_GROUP. It came from the dashboard's own unit or this account's default group."
      info " Verify by hand once advisord is installed: id -nG <the advisord account> | grep -w $TRUST_GROUP)"  # grep-lint: skip
    fi
  elif install_owned "$out_file" "$HOME_TRUST" "$(id -un)" "$(id -gn)" 600; then
    info "generated this node's trust key: $HOME_TRUST"
    info "(could not set root ownership or the $TRUST_GROUP group, owned by $(id -un) instead,"
    info " mode 600, which advisord cannot read. Fix it by hand: chown $(id -un):$TRUST_GROUP"
    info " $HOME_TRUST && chmod 0640 $HOME_TRUST, or re-run this join once that group is reachable)"
  else
    info "could not write $HOME_TRUST at all, skipping the trust-key step this run"
    return 1
  fi
  HOME_PRIV="$priv"; HOME_PUB="$pub"
  return 0
}

print_trust_exchange_instructions() {
  info "This peer isn't a local checkout (a remote host, or --token-path doesn't end in"
  info "advisor/state/read.token) — exchange the trust key by hand:"
  info "  1. On the PEER, add this to dashboard/config/fleet-trust.yaml (create it if absent,"
  info "     with a top-level 'peers:' mapping; leave any existing 'private_key' untouched):"
  info "       peers:"
  info "         $THIS_LABEL: $HOME_PUB"
  info "  2. Its owner/mode should be root:<service group> 0640, matching this node's own copy."
  info "  3. Eyeball this fingerprint against what you just pasted there: $HOME_PUB"
}

# ── The peer's token (#1075, #1076) ──────────────────────────────────────
#
# The token is read by this account at join time, and afterwards by the
# dashboard's account and the Advisor's, through a group. Those are three
# readers and one folder cannot suit them all: on a host where the Advisor has
# its own account, advisor/state is that account's, 0750, shared with the
# group the dashboard is in, and the operator running this is in neither.
#
# So the hand copy is the operator's own file, in the operator's own home, and
# --place-token has root put a second copy where the other two read it: root
# owned, in the group this host's own read.token is already read through, 0640.
# Root-owned on purpose. The Advisor narrows every peer token it OWNS to 0600
# on each start (tightenFleet), which would lock the dashboard out of a copy
# it owned, and leaves a file it does not own alone.
#
# Root's part is the root-held copy of scripts/state-file.py, the helper this
# script already writes advisor/state/fleet.json through: the token crosses on
# its standard input (never argv, never a path root opens in a folder the
# operator controls), and the folder, the owner, the group and the mode are
# set on one descriptor. `sudo cp`/`install` would resolve the name twice
# (state-file.py's header has the trace).

# Who owns what this account could not get through, for the refusal: the first
# thing on the way up that can be stat'ed is the closed folder itself, or the
# file when the file is what is closed.
unreadable_why() {  # $1 = the path
  local p="$1" d="$1" out="" what="" grp
  while [[ "$d" != "/" && "$d" != "." && -n "$d" ]]; do
    if out="$(stat -c '%U:%G %a' -- "$d" 2>/dev/null)"; then break; fi
    d="$(dirname -- "$d")"
  done
  [[ -n "$out" ]] || return 0
  if [[ "$d" == "$p" ]]; then what="the file $d"; else what="the folder $d"; fi
  grp="${out%% *}"; grp="${grp#*:}"
  printf '%s is %s, mode %s' "$what" "${out%% *}" "${out##* }"
  if [[ " $(id -nG) " != *" $grp "* ]]; then printf ', and %s is not in the group %s' "$(id -un)" "$grp"; fi
}

# Is the path missing, or only out of reach because a folder on the way is
# closed to this account? `-e` says no to both.
token_path_blocked() {
  local d
  d="$(dirname -- "$TOKEN_PATH")"
  while [[ ! -d "$d" && "$d" != "/" && "$d" != "." ]]; do d="$(dirname -- "$d")"; done
  [[ -d "$d" && ! -x "$d" ]]
}

refuse_unreadable_token() {
  local why note=""
  why="$(unreadable_why "$TOKEN_PATH")"
  case "$TOKEN_PATH" in
    */advisor/state/*) note="A token is not read out of the Advisor's state folder. " ;;
  esac
  die "--token-path '$TOKEN_PATH' is not readable by $(id -un)${why:+: $why}. ${note}Bring the peer's token to a file of your own (step 2 of Add a node in Settings: a sudo read on the peer into its home, then an scp from there into yours), then run this with --token-path set to that copy and --place-token: root then puts the copy where the dashboard and the Advisor read it"
}

# The numeric group this host's own read.token is read through. stat first, and
# sudo only when the folder it sits in is closed to this account.
read_token_gid() {
  local ref="$STATE_DIR/read.token" g=""
  if g="$(stat -c '%g' -- "$ref" 2>/dev/null)" && [[ "$g" =~ ^[0-9]+$ ]]; then printf '%s' "$g"; return 0; fi
  if (( EUID != 0 )) && command -v sudo >/dev/null 2>&1 \
     && g="$(sudo stat -c '%g' -- "$ref" 2>/dev/null)" && [[ "$g" =~ ^[0-9]+$ ]]; then printf '%s' "$g"; return 0; fi
  return 1
}

# Everything placing the token needs, asked before anything is written.
# Sets TOKEN_GID, the group the copy is placed in.
TOKEN_GID=""
check_place_token() {
  [[ -d "$STATE_DIR" ]] || die "--place-token puts the token in $STATE_DIR, and the Advisor's state folder is not on this host. A host with no Advisor has no use for the Advisor's copy: point --token-path at your own copy and leave --place-token off"
  root_tool_ok \
    || die "placing the token needs the root-held state helper, and it cannot be used: $ROOT_TOOL_WHY. curl -fsSL https://get.aperire.one | bash -s -- --update --force places it; run this again after"
  TOKEN_GID="$(read_token_gid)" \
    || die "could not read which group $STATE_DIR/read.token is read through, and the token is placed in that group so the dashboard and the Advisor can read it. Is the Advisor installed here?"
}

# Puts $1 (the operator's copy) at $PEER_TOKEN_DIR/$LABEL.token. Sets
# PLACED_TOKEN once it has.
place_peer_token() {
  local src="$1" dest="$PEER_TOKEN_DIR/$LABEL.token" gid
  check_place_token
  gid="$TOKEN_GID"
  info "root is needed once, to put the token where the dashboard and the Advisor read it:"
  info "  $dest, owned by root, group id $gid, mode 0640"
  info "Nothing else here runs as root."
  if (( EUID != 0 )) && ! sudo -n true 2>/dev/null; then
    sudo -v || die "sudo did not give this account root, so the token was not placed and nothing was written"
  fi
  "${ROOT_RUN[@]}" python3 -I "$ROOT_STATE_TOOL" mkdir "$PEER_TOKEN_DIR" 0 "$gid" 750 --root "$STATE_DIR" \
    || die "could not make $PEER_TOKEN_DIR (the helper's reason is above). Nothing was written"
  "${ROOT_RUN[@]}" python3 -I "$ROOT_STATE_TOOL" plant "$dest" 0 "$gid" 640 --root "$STATE_DIR" --stdin < "$src" \
    || die "could not place the token at $dest (the helper's reason is above). Nothing else was written"
  PLACED_TOKEN="$dest"
  info "placed $dest"
}

# Your copy was only ever the way in. Gone once the join has been verified, so
# a second credential does not sit in a home folder for as long as someone
# forgets it.
remove_operator_copy() {
  [[ -n "$1" && -f "$1" ]] || return 0
  if rm -f -- "$1" 2>/dev/null; then
    info "removed your copy of the token, $1"
  else
    info "could not remove your copy of the token, $1. Delete it: it is a second credential for the peer"
  fi
}

# ── --replace-token: a rotated token, for a node already joined ──────────
if (( REPLACE_TOKEN )); then
  say "Replacing the token of $LABEL"
  validate_label "$LABEL"
  [[ -e "$TOKEN_PATH" ]] || token_path_blocked || die "--token-path '$TOKEN_PATH' does not exist"
  [[ -r "$TOKEN_PATH" ]] || refuse_unreadable_token
  [[ -s "$TOKEN_PATH" ]] || die "$TOKEN_PATH is empty, so there is nothing to place"
  [[ -f "$DASH_FLEET" ]] || die "$DASH_FLEET does not exist, so no node has joined this host yet. Join it first, with --place-token"
  # The row's own token_path, from the shape this script writes: a list item
  # starting at "- label:" and the keys beneath it. Only a node joined with
  # --place-token has a placed copy to replace.
  RECORDED="$(awk -v want="$LABEL" '
    /^[[:space:]]*-[[:space:]]*label:/ {
      v = $0; sub(/^[[:space:]]*-[[:space:]]*label:[[:space:]]*/, "", v); sub(/[[:space:]]*#.*$/, "", v); gsub(/"/, "", v)
      inrow = (v == want); next }
    inrow && /^[[:space:]]*token_path:/ {
      t = $0; sub(/^[[:space:]]*token_path:[[:space:]]*/, "", t); sub(/[[:space:]]*#.*$/, "", t); gsub(/"/, "", t)
      print t; exit }' "$DASH_FLEET")"
  [[ -n "$RECORDED" ]] || die "$DASH_FLEET has no node labelled '$LABEL'. Join it first, with --place-token"
  [[ "$RECORDED" == "$PEER_TOKEN_DIR/$LABEL.token" ]] \
    || die "$LABEL was joined with its token at $RECORDED, not at $PEER_TOKEN_DIR/$LABEL.token, so there is no placed copy to replace. Replace the file at $RECORDED yourself, or join it again with --place-token"
  if (( DRY_RUN )); then
    info "(dry run) would place your copy at $PEER_TOKEN_DIR/$LABEL.token and change nothing else"
    exit 0
  fi
  place_peer_token "$TOKEN_PATH"
  PLACED_TOKEN=""   # a replacement is never taken back: the old file is already gone
  remove_operator_copy "$TOKEN_PATH"
  info "$LABEL's token is replaced. The dashboard and the Advisor read the file fresh; nothing is restarted."
  exit 0
fi

say "Validating arguments"

check_loopback_origin "$READ_ORIGIN" \
  || die "--read-origin '$READ_ORIGIN' must be a bare loopback origin (http://127.0.0.1:<port> or http://localhost:<port>, no path) — the read API refuses any other address even with a valid token"
info "read-origin: $READ_ORIGIN (loopback, ok)"

# `-e` is false for a file that is not there AND for one under a folder this
# account cannot search, and those are different faults with different fixes
# (#1076): the second is a closed folder, and it is named as one.
[[ -e "$TOKEN_PATH" ]] || token_path_blocked || die "--token-path '$TOKEN_PATH' does not exist"
[[ -r "$TOKEN_PATH" ]] || refuse_unreadable_token
info "token-path: $TOKEN_PATH (readable, ok)"
# What the registries record: the file the dashboard and the Advisor read. It
# is the same path as --token-path unless the copy is placed for them.
REG_TOKEN_PATH="$TOKEN_PATH"
if (( PLACE_TOKEN )); then
  case "$TOKEN_PATH" in
    */advisor/state/read.token)
      die "--place-token is for your own copy of a remote node's token. --token-path '$TOKEN_PATH' is a node's own read.token on a checkout, which a same-host join reads in place: leave --place-token off" ;;
  esac
  [[ -s "$TOKEN_PATH" ]] || die "$TOKEN_PATH is empty, so there is nothing to place"
fi

# Optional since #339. This field is a record of the node's own address,
# kept for an operator reading the registry: nothing on this dashboard
# renders it as a link and nothing dials it, so not knowing one is an
# ordinary state and never a reason to refuse a join. A value that IS given
# still has to be one a row could keep.
if [[ -n "$DASHBOARD_URL" ]]; then
  check_https_url "$DASHBOARD_URL" \
    || die "--dashboard-url '$DASHBOARD_URL' must be https — the fleet's own origin rule (scripts/fleet-origin.sh) allows plain http only to a loopback name, and fleet-registry.ts drops a loopback name from a row, so a plain-http address is either one this product does not accept or one no row would keep"
  info "dashboard-url: $DASHBOARD_URL (https, ok)"
else
  info "dashboard-url: (none given — the row carries no dashboard address, the same shape a paired node writes)"
fi

if [[ -n "$LABEL" ]]; then
  validate_label "$LABEL"
  info "label: $LABEL (given, charset ok)"
fi

# The Advisor is optional (decisions.md D5), so a host without it is a
# supported fleet member and its join must finish, not half-finish. Resolved
# HERE, with the other arguments, because it decides how much of the run there
# is to do — asking at step 5 instead means answering "no" with the dashboard
# registry already written and the reload not yet run.
HAVE_ADVISOR=0
if [[ -d "$REPO/advisor/state" ]]; then
  HAVE_ADVISOR=1
  info "advisor: installed here — $ADV_FLEET gets a row too"
else
  info "advisor: not installed here — $ADV_FLEET is skipped, dashboard row only"
fi
if (( PLACE_TOKEN )); then
  # Refused here, with the other arguments, so the run stops before it has
  # written or provisioned anything.
  (( HAVE_ADVISOR )) || die "--place-token puts the token in the Advisor's state folder, and there is no $STATE_DIR on this host. A host with no Advisor has no use for the Advisor's copy: point --token-path at your own copy and leave --place-token off"
  check_place_token
fi

# The label the PEER files this node's trust key under is not a choice. Every
# signer on this side (the trust bundle push, the knowledge push, the fleet
# seal job, the fleet arm token) signs as issuer "aggregator", and the peer's
# advisord and dashboard look up peers.aggregator and nothing else. A node
# joined under any other label held a key no push was ever signed with, and
# met it as "no key for aggregator" three hops from the cause (#177).
THIS_LABEL="aggregator"

# Same-host detection for the trust exchange, from the token-path convention
# the fleet guide documents (docs/FLEET-GUIDE.md, "Peers on the same
# machine"): a same-host token_path is <peer-repo>/advisor/state/read.token.
# Anything else — a copied fleet-tokens/<label>.token, or a path that just
# doesn't look like a real checkout — is treated as remote.
PEER_REPO=""
case "$TOKEN_PATH" in
  */advisor/state/read.token) PEER_REPO="${TOKEN_PATH%/advisor/state/read.token}" ;;
esac
if [[ -n "$PEER_REPO" ]]; then
  if [[ "$PEER_REPO" == "$REPO" ]] \
    || [[ ! -d "$PEER_REPO/dashboard/config" ]] || [[ ! -d "$PEER_REPO/advisor/state" ]]; then
    PEER_REPO=""
  fi
fi
HOME_TRUST="$REPO/dashboard/config/fleet-trust.yaml"
PEER_TRUST=""
[[ -n "$PEER_REPO" ]] && PEER_TRUST="$PEER_REPO/dashboard/config/fleet-trust.yaml"
resolve_trust_group
TRUST_GROUP="$TRUST_GROUP_FOUND"

# Refusals — before any mutation, same as every other refusal in this
# script: a trust file already on disk that is too loose or does not parse
# stops the whole join, never a silent repair.
check_trust_file_or_die "$HOME_TRUST"
[[ -n "$PEER_TRUST" ]] && check_trust_file_or_die "$PEER_TRUST"

# ── Step 1: identify the peer ───────────────────────────────────────────
say "Reading the peer's identity"
TOKEN="$(cat "$TOKEN_PATH")"
TOKEN="${TOKEN//$'\n'/}"
[[ -n "$TOKEN" ]] || die "$TOKEN_PATH is empty — nothing to authenticate with"

IDTMP="$(mk_tmp)"
# The token reaches curl on its standard input (-H @-), never on its argv,
# where any account on the host can read it in /proc (#705).
HTTP_CODE="$(curl -sS --max-time 8 -o "$IDTMP" -w '%{http_code}' \
  -H @- "$READ_ORIGIN/read/v1/identity" 2>/dev/null <<<"authorization: Bearer $TOKEN")" || HTTP_CODE="000"
unset TOKEN
[[ "$HTTP_CODE" == "200" ]] \
  || die "could not reach $READ_ORIGIN/read/v1/identity (http $HTTP_CODE) — a node you cannot identify is not a node you register"

PUBKEY="$(python3 -I - "$IDTMP" <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception:
    sys.exit(1)
pk = d.get("pubkey_node")
sys.stdout.write(pk if isinstance(pk, str) else "")
PY
)" || die "the identity response from $READ_ORIGIN was not valid JSON"
[[ -n "$PUBKEY" ]] \
  || die "the peer answered but has not reported a node key yet (pubkey_node is null) — nothing to pin. Wait for it to finish starting and retry."
[[ "$PUBKEY" =~ $NODE_KEY_RE ]] \
  || die "the peer's pubkey_node ('$PUBKEY') is not shaped like a real node key (base58, starting with 'n') — refusing to pin something malformed"

say "Peer identity"
info "pubkey_node: $PUBKEY"
info "Compare this against the node's OWN report (its Overview identity card, or"
info "server_info run on that node) before trusting it. This read is trust-on-first-use:"
info "it is the peer's first answer, by definition unverified until you eyeball it."

# Set by ensure_own_trust_key at step 2b, below every refusal; declared here
# because the plan and the trust-exchange step both read them either way.
HOME_PRIV="" HOME_PUB=""

# ── Step 2: resolve the label, and every duplicate/parse refusal ───────
say "Resolving the label"
if [[ -z "$LABEL" ]]; then
  FRAG="$(printf '%s' "$PUBKEY" | cut -c2-7 | tr '[:upper:]' '[:lower:]')"
  LABEL="node-$FRAG"
  validate_label "$LABEL"
  info "proposed label: $LABEL (from the peer's own node key)"
else
  info "label: $LABEL"
fi

# A simple field-value reader for our own fleet.yaml convention (one
# "key: value" per line, 2/4-space indent, no flow-style mappings — the
# shape this script and fleet.yaml.example both write). Not a YAML parser;
# duplicate detection only. The real parse-and-verify after writing uses
# fleet-registry.ts itself, further down.
yaml_field_has_value() {
  local file="$1" field="$2" want="$3" line v
  [[ -f "$file" ]] || return 1
  while IFS= read -r line; do
    v="${line#*:}"
    v="${v%%#*}"
    v="${v%"${v##*[![:space:]]}"}"
    v="${v#"${v%%[![:space:]]*}"}"
    v="${v%\"}"; v="${v#\"}"
    [[ "$v" == "$want" ]] && return 0
  done < <(grep -E "^[[:space:]]*${field}:[[:space:]]*" "$file" 2>/dev/null || true)
  return 1
}

if yaml_field_has_value "$DASH_FLEET" "label" "$LABEL"; then
  die "label '$LABEL' is already used in $DASH_FLEET — pick another with --label"
fi
if yaml_field_has_value "$DASH_FLEET" "read_origin" "$READ_ORIGIN"; then
  die "$DASH_FLEET already has a row with read_origin '$READ_ORIGIN' — that peer is already registered"
fi

# advisor/state/fleet.json — read (absent / unreadable / invalid JSON are
# three different outcomes, and only the first is fine to proceed past).
ADV_RAW="[]"
ADV_EXISTS=0
if [[ -e "$ADV_FLEET" ]]; then
  ADV_EXISTS=1
  if [[ -r "$ADV_FLEET" ]]; then
    ADV_RAW="$(cat "$ADV_FLEET")"
  elif root_tool_ok && command -v sudo >/dev/null 2>&1; then
    ADV_RAW="$(sudo python3 -I "$ROOT_STATE_TOOL" read "$ADV_FLEET")" \
      || die "$ADV_FLEET exists but could not be read even with sudo — refusing to guess at its contents"
  else
    die "$ADV_FLEET exists and is not readable by $(id -un), and this host has no root-held state helper it can use to read it through sudo${ROOT_TOOL_WHY:+ ($ROOT_TOOL_WHY)}, or no sudo. If the Advisor is installed here, curl -fsSL https://get.aperire.one | bash -s -- --update --force places it; run this again after"
  fi
  # Two accepted shapes, the same two advisord's own version-tolerant Load
  # takes: the legacy peer ARRAY, and the object form carrying a "self"
  # block beside "peers". A host part-way through the topology upgrade has
  # the second; refusing it here would make this script the thing that
  # breaks on an upgraded host.
  printf '%s' "$ADV_RAW" | python3 -I -c '
import json, sys
d = json.load(sys.stdin)
assert isinstance(d, list) or (isinstance(d, dict) and isinstance(d.get("peers", []), list))
' \
    || die "$ADV_FLEET exists but is neither a JSON peer array nor a registry object with a peers list — refusing to append to a broken file rather than guess at what it should contain"
fi

# NOTE: python3 -, given a heredoc, reads the heredoc as the PROGRAM (that is
# what "-" means), so it cannot ALSO read piped data from the same stdin —
# the data has to come from a real file. mk_tmp gives one.
ADV_RAW_FILE="$(mk_tmp)"
printf '%s' "$ADV_RAW" > "$ADV_RAW_FILE"
if python3 -I - "$ADV_RAW_FILE" "$LABEL" <<'PY'
import json, sys
path, label = sys.argv[1], sys.argv[2]
with open(path) as f:
    d = json.load(f)
peers = d if isinstance(d, list) else d.get("peers", [])
self_label = "" if isinstance(d, list) else (d.get("self") or {}).get("label", "")
# A label already used by a peer, OR the label this host calls ITSELF — a
# registry that names this host as its own peer is the wrong-node read
# advisord's loader refuses outright, so it must never be written here.
clash = any(isinstance(r, dict) and r.get("label") == label for r in peers) or label == self_label
sys.exit(1 if clash else 0)
PY
then
  :
else
  die "label '$LABEL' is already used in $ADV_FLEET — pick another with --label"
fi
if (( HAVE_ADVISOR )); then
  info "no duplicate label or read_origin in either registry"
else
  info "no duplicate label or read_origin in the dashboard registry"
fi

# ── Step 2b: this node's own trust key ──────────────────────────────────
# Deliberately AFTER every refusal above, and before the plan that prints its
# fingerprint. This is the first step that can write a file, and the claim the
# fleet guide makes — every duplicate check runs before anything is written —
# is only true if it stays here. It is also the last thing that could refuse:
# an existing trust file too loose or unparseable already stopped the run, up
# with the other argument checks.
if (( DRY_RUN )); then
  info "(dry run — this node's own trust key would be generated/read here; skipped)"
elif ensure_own_trust_key; then
  info "this node's trust public key ($THIS_LABEL): $HOME_PUB"
  info "A SEPARATE key from the peer's node key above — it lets this dashboard vouch for a"
  info "future enrollment grant to a peer, nothing about the XRPL node itself. Eyeball it too."
fi

# ── Report before any registry is written ───────────────────────────────
PORT="${READ_ORIGIN##*:}"
if [[ -n "$TUNNEL" ]]; then
  TRANSPORT="tunnel — see aperire-fleet-add ($TUNNEL -> $HOSTNAME_ARG)"
else
  TRANSPORT="same host, loopback :$PORT"
fi

say "Plan"
info "label:            $LABEL"
if [[ -n "$DASHBOARD_URL" ]]; then
  info "dashboard_url:    $DASHBOARD_URL"
else
  info "dashboard_url:    (not set — no line is written; nothing renders or dials this field)"
fi
info "read_origin:      $READ_ORIGIN"
if (( PLACE_TOKEN )); then
  REG_TOKEN_PATH="$PEER_TOKEN_DIR/$LABEL.token"
  info "token_path:       $REG_TOKEN_PATH  (root places a copy of $TOKEN_PATH there; your copy is removed after the join is verified)"
else
  info "token_path:       $REG_TOKEN_PATH"
fi
info "expected_pubkey:  $PUBKEY  (TOFU — see the eyeball line above)"
info "advisor transport note: $TRANSPORT"
if [[ -n "$ROLE" ]]; then
  info "role:             $ROLE"
else
  info "role:             (unspecified — pass --role so the Advisor can say what this peer is)"
fi
if [[ -n "$HOME_PUB" ]]; then
  info "this-node trust key: $HOME_PUB  (the peer files it as peers.aggregator; see the eyeball line above)"
fi
if [[ -n "$PEER_TRUST" ]]; then
  info "trust exchange: will place this node's public key into $PEER_TRUST"
else
  info "trust exchange: peer is not a local checkout — manual exchange instructions will print below"
fi
if (( HAVE_ADVISOR )); then
  info "registries:       $DASH_FLEET and $ADV_FLEET"
else
  info "registries:       $DASH_FLEET only (no Advisor on this host)"
fi
if (( DRY_RUN )); then
  info "(dry run — nothing below this line writes or provisions anything)"
fi

# ── Step 3: DNS ──────────────────────────────────────────────────────────
# `cloudflared tunnel route dns <name> <hostname>` does NOT reliably fail on
# a tunnel name it doesn't recognise — observed live: with a default
# ~/.cloudflared/config.yml present (`tunnel: <some other tunnel>`), calling
# route dns with an unrelated, non-existent name silently created a route
# against THAT default tunnel instead of failing. Trusting the command's own
# exit code is therefore not enough. This script instead resolves --tunnel
# against `cloudflared tunnel list` FIRST and calls route dns with the
# resolved UUID, never the bare name — if the name isn't found, this is
# treated exactly like cloudflared being absent: manual instructions, never
# a guess at which tunnel gets the route.
resolve_tunnel_uuid() {
  command -v cloudflared >/dev/null 2>&1 || return 1
  local tunnel_list_file
  tunnel_list_file="$(mk_tmp)"
  cloudflared tunnel list -o json >"$tunnel_list_file" 2>/dev/null || return 1
  python3 -I - "$tunnel_list_file" "$TUNNEL" <<'PY'
import json, sys
path, name = sys.argv[1], sys.argv[2]
try:
    with open(path) as f:
        rows = json.load(f)
except Exception:
    sys.exit(1)
for r in rows:
    if isinstance(r, dict) and r.get("name") == name:
        uid = r.get("id") or ""
        if uid:
            sys.stdout.write(uid)
            sys.exit(0)
sys.exit(1)
PY
}

print_manual_dns_instructions() {
  local uuid="${1:-}"
  if [[ -n "$uuid" ]]; then
    info "create a CNAME record: $HOSTNAME_ARG -> ${uuid}.cfargotunnel.com"
  else
    info "create a CNAME record: $HOSTNAME_ARG -> <tunnel-UUID>.cfargotunnel.com"
    info "find the UUID with: cloudflared tunnel list  (or the Cloudflare dashboard)"
  fi
}

if [[ -n "$HOSTNAME_ARG" ]]; then
  say "DNS for $HOSTNAME_ARG"
  CERT="$HOME/.cloudflared/cert.pem"
  if (( DRY_RUN )); then
    info "[dry-run] would resolve tunnel '$TUNNEL' via cloudflared tunnel list, then run:"
    info "[dry-run]   cloudflared tunnel route dns <resolved-uuid> $HOSTNAME_ARG"
    info "[dry-run] (or print the manual record, if cloudflared, its cert, or the named tunnel is unavailable)"
  elif [[ -f "$CERT" ]] && TUNNEL_UUID="$(resolve_tunnel_uuid)"; then
    if cloudflared tunnel route dns "$TUNNEL_UUID" "$HOSTNAME_ARG"; then
      info "DNS route created: $HOSTNAME_ARG -> tunnel $TUNNEL ($TUNNEL_UUID)"
    else
      info "cloudflared could not create the route automatically — create it by hand:"
      print_manual_dns_instructions "$TUNNEL_UUID"
    fi
  else
    info "cloudflared, its origin certificate ($CERT), or a tunnel named '$TUNNEL' is not available here"
    info "— create the record by hand:"
    print_manual_dns_instructions ""
  fi
fi

if (( DRY_RUN )); then
  say "Dry run complete — no files were written, no service was reloaded, no DNS was changed"
  if (( PLACE_TOKEN )); then
    info "would place:     $REG_TOKEN_PATH (root:group $TOKEN_GID, mode 0640), from your copy $TOKEN_PATH"
  fi
  info "would append to: $DASH_FLEET"
  if (( HAVE_ADVISOR )); then
    info "would append to: $ADV_FLEET"
  else
    info "would skip:      $ADV_FLEET (no Advisor installed on this host)"
  fi
  exit 0
fi

# ── Step 3b: the token, where the dashboard and the Advisor read it ──────
# After every refusal and before the first registry write, so a run that was
# going to be refused has placed nothing, and one that fails after this takes
# its own file back out (the EXIT trap).
if (( PLACE_TOKEN )); then
  say "Placing the peer's token"
  place_peer_token "$TOKEN_PATH"
fi

# ── Step 4: dashboard/config/fleet.yaml ─────────────────────────────────
say "Writing $DASH_FLEET"
mkdir -p "$(dirname "$DASH_FLEET")"
DASH_BACKUP=""
if [[ -f "$DASH_FLEET" ]]; then
  DASH_BACKUP="$(mk_tmp)"
  cp -a "$DASH_FLEET" "$DASH_BACKUP"
else
  printf 'fleet:\n' > "$DASH_FLEET"
fi

# A trailing newline before appending — an append onto a file with none
# fuses the new row onto the last existing line.
if [[ -s "$DASH_FLEET" ]] && [[ -n "$(tail -c1 "$DASH_FLEET")" ]]; then
  printf '\n' >> "$DASH_FLEET"
fi
{
  printf '  - label: %s\n' "$LABEL"
  # No line at all when none was given (#339) — the same row
  # scripts/aperire-fleet-broker.sh writes for a paired node. An empty
  # `dashboard_url:` would be a present key with an empty value, which fails
  # the WHOLE file closed in fleet-registry.ts, so the absent field and the
  # absent line have to be the same fact all the way down.
  if [[ -n "$DASHBOARD_URL" ]]; then printf '    dashboard_url: %s\n' "$DASHBOARD_URL"; fi
  printf '    read_origin: %s\n' "$READ_ORIGIN"
  printf '    token_path: %s\n' "$REG_TOKEN_PATH"
  printf '    expected_pubkey_node: %s\n' "$PUBKEY"
  if [[ -n "$ROLE" ]]; then printf '    role: %s\n' "$ROLE"; fi
} >> "$DASH_FLEET"

# Verify with the real parser — the same module the dashboard's own server
# loads at startup and on SIGHUP. Restore the backup (or remove the file we
# just created) on anything but a clean parse naming our new label.
dash_verify_failed=0
if [[ -x "$TSX" ]]; then
  ( cd "$REPO/dashboard" && "$TSX" -e "
    import { loadFleetRegistry } from './lib/fleet-registry.js';
    const r = loadFleetRegistry(${DASH_FLEET@Q});
    if (r.error) { console.error(r.error); process.exit(1); }
    if (!r.nodes.some(n => n.label === ${LABEL@Q})) {
      console.error('label not present after write'); process.exit(1);
    }
    console.log('fleet.yaml parses; ' + r.nodes.length + ' node(s)');
  " ) || dash_verify_failed=1
else
  info "no tsx binary at $TSX — skipping the live-parser verification (unusual; is the dashboard installed here?)"
fi
if (( dash_verify_failed )); then
  if [[ -n "$DASH_BACKUP" ]]; then
    mv -f "$DASH_BACKUP" "$DASH_FLEET"
  else
    rm -f "$DASH_FLEET"
  fi
  die "the appended row did not parse cleanly against fleet-registry.ts — restored $DASH_FLEET to its previous state"
fi
info "wrote and verified the dashboard row"

# ── Step 5: advisor/state/fleet.json ──────────────────────────────────────
# Only when the Advisor is installed here — HAVE_ADVISOR was resolved with the
# other arguments, before a byte was written, so a dashboard-only host never
# reaches this point half-joined.
if (( HAVE_ADVISOR )); then
  say "Writing $ADV_FLEET"
  ADV_WRITABLE=0
  if [[ -e "$ADV_FLEET" ]]; then
    [[ -w "$ADV_FLEET" ]] && ADV_WRITABLE=1
  else
    [[ -w "$(dirname "$ADV_FLEET")" ]] && ADV_WRITABLE=1
  fi
  SUDO_CMD=()
  (( ADV_WRITABLE )) || SUDO_CMD=(sudo)

  resolve_owner_group() {
    local ref="$1" out
    if out="$(stat -c '%U %G' "$ref" 2>/dev/null)"; then
      printf '%s' "$out"; return 0
    fi
    if command -v sudo >/dev/null 2>&1 && out="$(sudo stat -c '%U %G' "$ref" 2>/dev/null)"; then
      printf '%s' "$out"; return 0
    fi
    die "could not determine the owner of $ref to preserve it — refusing to guess an account name"
  }
  resolve_mode() {
    local ref="$1" out
    if out="$(stat -c '%a' "$ref" 2>/dev/null)"; then
      printf '%s' "$out"; return 0
    fi
    if command -v sudo >/dev/null 2>&1 && out="$(sudo stat -c '%a' "$ref" 2>/dev/null)"; then
      printf '%s' "$out"; return 0
    fi
    die "could not determine the mode of $ref to preserve it"
  }

  # The same two facts, numerically. The plant below hands the file away on a
  # descriptor and takes ids, not names, so nothing has to be looked up a
  # second time inside a program running as root (#703).
  resolve_uid_gid() {
    local ref="$1" out
    if out="$(stat -c '%u %g' "$ref" 2>/dev/null)"; then
      printf '%s' "$out"; return 0
    fi
    if command -v sudo >/dev/null 2>&1 && out="$(sudo stat -c '%u %g' "$ref" 2>/dev/null)"; then
      printf '%s' "$out"; return 0
    fi
    die "could not determine the numeric owner of $ref to preserve it"
  }

  if (( ADV_EXISTS )); then
    read -r ADV_OWNER ADV_GROUP <<<"$(resolve_owner_group "$ADV_FLEET")"
    read -r ADV_UID ADV_GID <<<"$(resolve_uid_gid "$ADV_FLEET")"
    ADV_MODE="$(resolve_mode "$ADV_FLEET")"
  else
    # Fresh file: owned by whoever owns advisor/state (the service account),
    # never a hardcoded name. 0600 — tighter than its siblings, since only
    # advisord itself ever needs to read this one.
    read -r ADV_OWNER ADV_GROUP <<<"$(resolve_owner_group "$REPO/advisor/state")"
    read -r ADV_UID ADV_GID <<<"$(resolve_uid_gid "$REPO/advisor/state")"
    ADV_MODE="600"
  fi

  # The one place this script writes into advisor/state, and it is root doing
  # it in a directory the Advisor's own account owns (#703). `install` there
  # sets the mode through the PATH after it has made the inode, so a symlink
  # swapped into that gap gets root's chmod; the helper does the create, the
  # ownership, the mode and the move onto the name on one descriptor.
  # The tree's copy when this runs as an account that can write the directory
  # itself (it is that account's own code). When the write needs sudo, the
  # root-held copy: sudo on a file in the tree is root running what the
  # dashboard's or the Advisor's account left there (#886).
  ADV_STATE_TOOL="$REPO/scripts/state-file.py"
  if (( ${#SUDO_CMD[@]} )); then
    root_tool_ok \
      || die "writing $ADV_FLEET needs sudo, and the root-held state helper cannot be used: $ROOT_TOOL_WHY. The Advisor's registry was not touched ($DASH_FLEET was already written). If the Advisor is installed here, curl -fsSL https://get.aperire.one | bash -s -- --update --force places it; run this again after"
    ADV_STATE_TOOL="$ROOT_STATE_TOOL"
  fi
  [[ -r "$ADV_STATE_TOOL" ]] \
    || die "$ADV_STATE_TOOL is missing from this checkout; it and this script ship together"

  EXISTING_JSON="$(mk_tmp)"
  printf '%s' "$ADV_RAW" > "$EXISTING_JSON"
  NEW_JSON="$(mk_tmp)"
  python3 -I - "$EXISTING_JSON" "$NEW_JSON" "$LABEL" "$READ_ORIGIN" "$REG_TOKEN_PATH" "$TRANSPORT" "$ROLE" "$PUBKEY" <<'PY'
import json, sys
existing_path, out_path, label, origin, token_path, transport, role, pubkey = sys.argv[1:9]
with open(existing_path) as f:
    data = json.load(f)

# Whatever shape the file is in, it stays in — this script joins a node, it
# does not migrate a registry. scripts/aperire-advisor-fleet-sync.sh is the
# one that changes shape, and it does it from fleet.yaml.
if isinstance(data, list):
    peers = data
elif isinstance(data, dict):
    peers = data.setdefault("peers", [])
    if not isinstance(peers, list):
        sys.exit(1)
else:
    sys.exit(1)

row = {"label": label, "origin": origin, "token_path": token_path, "transport": transport}
# role is the operator's word for what this peer IS, and is written only
# when they gave one — an absent role means UNSPECIFIED, never a guess. The
# pin is the key this join already read from the peer and printed for the
# operator to eyeball, so recording it costs nothing and closes the case
# where a row quietly starts pointing at a different node.
if role:
    row["role"] = role
if pubkey:
    row["expected_pubkey_node"] = pubkey
assert set(row.keys()) <= {"label", "origin", "token_path", "transport", "role", "expected_pubkey_node"}
peers.append(row)

with open(out_path, "w") as f:
    json.dump(data, f, indent=2)
    f.write("\n")
PY

  "${SUDO_CMD[@]}" python3 -I "$ADV_STATE_TOOL" plant "$ADV_FLEET" \
    "$ADV_UID" "$ADV_GID" "$ADV_MODE" --stdin < "$NEW_JSON"

  # Re-read what actually landed, the same way advisord's own DisallowUnknownFields
  # loader would refuse it: exactly four keys per row, our label present.
  adv_verify_failed=0
  if [[ -r "$ADV_FLEET" ]]; then
    READBACK="$(cat "$ADV_FLEET")"
  elif root_tool_ok && command -v sudo >/dev/null 2>&1; then
    READBACK="$(sudo python3 -I "$ROOT_STATE_TOOL" read "$ADV_FLEET")" || READBACK=""
  else
    READBACK=""
  fi
  if [[ -n "$READBACK" ]]; then
    READBACK_FILE="$(mk_tmp)"
    printf '%s' "$READBACK" > "$READBACK_FILE"
    python3 -I - "$READBACK_FILE" "$LABEL" <<'PY' || adv_verify_failed=1
import json, sys
path, label = sys.argv[1], sys.argv[2]
with open(path) as f:
    d = json.load(f)
assert isinstance(d, list) or isinstance(d, dict), "neither accepted shape"
peers = d if isinstance(d, list) else d.get("peers", [])
assert isinstance(peers, list), "peers is not a list"
row = next((r for r in peers if isinstance(r, dict) and r.get("label") == label), None)
assert row is not None, "label missing after write"
# The same closed key set advisord's DisallowUnknownFields loader accepts:
# the four this row has always had, plus the two descriptive topology
# fields. Anything else here fails advisord's WHOLE registry closed, so it
# must fail this write instead — while the previous contents can still be
# put back.
assert set(row.keys()) <= {"label", "origin", "token_path", "transport", "role", "expected_pubkey_node"}, "unexpected key set"
assert {"label", "origin", "token_path"} <= set(row.keys()), "a required key is missing"
PY
  else
    adv_verify_failed=1
  fi
  if (( adv_verify_failed )); then
    if (( ADV_EXISTS )); then
      RESTORE="$(mk_tmp)"
      printf '%s' "$ADV_RAW" > "$RESTORE"
      "${SUDO_CMD[@]}" python3 -I "$ADV_STATE_TOOL" plant "$ADV_FLEET" \
        "$ADV_UID" "$ADV_GID" "$ADV_MODE" --stdin < "$RESTORE"
      die "the appended row did not verify against $ADV_FLEET — restored its previous contents"
    else
      # Through the helper, on a descriptor, never `rm -f` by name as root
      # (#897): a parent swapped for a link would take a by-name delete
      # elsewhere. A root-held helper from before the verb cannot do it, and
      # nothing falls back to rm.
      "${SUDO_CMD[@]}" python3 -I "$ADV_STATE_TOOL" unlink "$ADV_FLEET" --root "$REPO/advisor/state" \
        || die "the appended row did not verify against $ADV_FLEET, and the file this run created could not be removed (above). Bring the helper up to date, then run this again, which rewrites it: curl -fsSL https://get.aperire.one | bash -s -- --update --force"
      die "the appended row did not verify against $ADV_FLEET — removed the file this run created"
    fi
  fi
  info "wrote and verified the advisor row ($ADV_OWNER:$ADV_GROUP, mode $ADV_MODE)"
else
  # The Advisor is optional (decisions.md D5), so a dashboard-only host is a
  # supported fleet member and its join is finished, not half-done. Said
  # here, and again in the summary — a skipped registry an operator never
  # heard about is the same as a missing one.
  say "Skipping $ADV_FLEET"
  info "no $REPO/advisor/state directory — the Advisor is not installed on this host,"
  info "so there is no advisord registry to write a row to. The dashboard row above is"
  info "written and verified, and the fleet chip, NODES panel and health polling all"
  info "work without the Advisor."
  info "If you install it later (scripts/install-advisord.sh), generate its registry from"
  info "the file you already have:"
  info "  scripts/aperire-advisor-fleet-sync.sh --self-label <this-host> --write"
fi

# Both registries name the file now and the re-read confirmed them. The
# placed token stays, and your own copy of it goes.
JOIN_DONE=1
if (( PLACE_TOKEN )); then
  remove_operator_copy "$TOKEN_PATH"
fi

# ── Step 5b: pairwise trust key exchange ────────────────────────────────
# A bonus on top of the join, never a blocker for it. HOME_PUB is empty
# here only if ensure_own_trust_key already reported and skipped it above
# (DRY_RUN never reaches this branch at all — dry-run already exited).
say "Trust key exchange"
if [[ -z "$HOME_PUB" ]]; then
  info "skipped (see above) — the registries above are unaffected"
elif [[ -n "$PEER_TRUST" ]]; then
  PEER_EXISTING_FILE="$(mk_tmp)"
  read_trust_file_raw "$PEER_TRUST" > "$PEER_EXISTING_FILE"
  PEER_TRUST_OUT="$(mk_tmp)"
  merge_trust_peer_pub "$PEER_EXISTING_FILE" "$PEER_TRUST_OUT" "$THIS_LABEL" "$HOME_PUB"
  # Same three tiers as HOME_TRUST above (#538): root:$TRUST_GROUP 640 first,
  # self:$TRUST_GROUP 640 without root, and only self:own-group 0600, with
  # advisord unable to read it, as the last resort that still guarantees a
  # write.
  if install_owned "$PEER_TRUST_OUT" "$PEER_TRUST" root "$TRUST_GROUP" 640; then
    info "placed this node's public key into $PEER_TRUST (peers.$THIS_LABEL, root:$TRUST_GROUP 640)"
  elif install_owned "$PEER_TRUST_OUT" "$PEER_TRUST" "$(id -un)" "$TRUST_GROUP" 640; then
    info "placed this node's public key into $PEER_TRUST (peers.$THIS_LABEL, $(id -un):$TRUST_GROUP 640)"
  elif install_owned "$PEER_TRUST_OUT" "$PEER_TRUST" "$(id -un)" "$(id -gn)" 600; then
    info "placed this node's public key into $PEER_TRUST (peers.$THIS_LABEL)"
    info "(could not set root ownership or the $TRUST_GROUP group, mode 600, which its own"
    info " advisord cannot read. Fix it by hand: chown $(id -un):$TRUST_GROUP $PEER_TRUST"
    info " && chmod 0640 $PEER_TRUST)"
  else
    info "could not write $PEER_TRUST, exchange it by hand instead:"
    print_trust_exchange_instructions
  fi
else
  print_trust_exchange_instructions
fi

# ── Step 5c: the public half (#868) ─────────────────────────────────────
# The writes above leave a file that holds a private_key at 0640 through
# the group the Advisor reads with, which is how this script has always
# made it. The Advisor must not hold that key: fleet-trust-split.sh narrows
# such a file to the dashboard account, 0600, and remakes the public half
# the Advisor reads beside it, with the peers just written. A node's
# peers-only file it leaves in the shape it always had. Run for each tree
# this join wrote a trust file in.
#
# Root runs the release's checked copy of the split, never the one in either
# tree (#897): through this checkout's bootstrap, run as you, which asks sudo
# for the one root call and stages the tree it is pointed at against this
# host's record. A tree that is not the release that record holds (a second
# install on another release) is refused by name, and the command that
# finishes it is printed.
fleet_add_split() {  # $1 = install dir
  local repo="$1" out="" rc=0
  [[ -e "$repo/dashboard/config/fleet-trust.yaml" ]] || return 0
  # The bootstrap asks sudo only on a terminal, and here its output is
  # captured to be indented, so a password is asked for first, on the
  # terminal, the way `sudo bash` used to ask it. sudo -v runs nothing.
  if (( EUID != 0 )) && ! sudo -n true 2>/dev/null; then
    sudo -v || rc=$?
  fi
  (( rc == 0 )) && { out="$(bash "$REPO/scripts/get-aperire.sh" --dir "$repo" --run fleet-trust-split < /dev/null 2>&1)" || rc=$?; }
  while IFS= read -r _l; do [[ -n "$_l" ]] && info "$_l"; done <<<"$out"
  if (( rc != 0 )); then
    info "the fleet trust key in $repo/dashboard/config is not split yet, so the Advisor's account may still read it. Finish it with:"
    info "  curl -fsSL https://get.aperire.one | bash -s -- --dir $repo --run fleet-trust-split"
  fi
}
if [[ -n "$HOME_PUB" ]]; then
  fleet_add_split "$REPO"
  [[ -n "${PEER_REPO:-}" && -n "${PEER_TRUST:-}" ]] && fleet_add_split "$PEER_REPO"
fi

# ── Step 6: reload ───────────────────────────────────────────────────────
say "Reload"
# Both registries are already written and verified above — a reload failure
# here (no sudo access, no password on this TTY, ...) must not undo that or
# abort with the join otherwise complete. Told, not silently swallowed.
if systemctl is-active --quiet aperire-server 2>/dev/null; then
  if sudo systemctl reload aperire-server; then
    info "reloaded aperire-server (SIGHUP) — fleet.yaml re-read in place"
  else
    info "could not reload aperire-server (see above) — the registries are written; reload or restart it yourself:"
    info "  sudo systemctl reload aperire-server"
  fi
else
  info "aperire-server is not an active systemd unit here — restart your dashboard process to pick up fleet.yaml"
fi
if (( HAVE_ADVISOR )); then
  info "advisord is NOT being restarted automatically: an advisor restart re-seals the model key"
  info "and closes any open break-glass window, which is your call, not this script's."
  info "when ready:  sudo systemctl restart aperire-advisord"
else
  info "no advisord on this host, so nothing to restart for it."
fi

# ── Step 7: peer enrollment ──────────────────────────────────────────────
say "Enrollment on the peer"
info "Sign-in is per-node (decisions.md D5) — there is no fleet-wide session."
info "On the PEER host, from ITS OWN checkout, run (replace the placeholders):"
info "  <peer-repo>/scripts/aperire-auth.sh magic-link <operator-email>"
info "A navigate-and-redeem grant will replace this manual step once it lands."

say "Done"
if (( HAVE_ADVISOR )); then
  info "label $LABEL is registered in both $DASH_FLEET and $ADV_FLEET."
else
  info "label $LABEL is registered in $DASH_FLEET. There is no Advisor on this host, so"
  info "$ADV_FLEET was skipped."
fi
if [[ -n "$HOME_PUB" ]]; then
  info "this node's trust key: $HOME_TRUST — nothing reads it yet (the grant redemption code is not built)."
fi
# Explicit, not just "falls off the end": the script's true last command
# above is a conditional that is FALSE whenever HOME_PUB is empty (a
# degraded trust-key run) — without this, that false becomes the whole
# script's exit status even though every registry above was written and
# verified. Same shape as the cleanup-trap bug this file already guards
# against; caught the same way, by testing the degraded path for real.
exit 0
