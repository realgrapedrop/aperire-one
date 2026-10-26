#!/usr/bin/env bash
# Place a fleet link credential, phase 1 — ADR 0019.
#
# The link needs one secret on two hosts: the VALUE on the node, its SHA-256
# on the aggregator. Until pairing lands (phase 3) an operator places both by
# hand, and hand-editing JSON on two machines is how a fleet ends up with a
# file that fails closed and a node that will not link.
#
# Three verbs, each on one machine:
#
#   mint                    print a fresh credential, once. Nothing is stored.
#   node        --aggregator wss://<host>/fleet/v1/link --label <label>
#                           writes dashboard/config/fleet-link.json, 0600
#   aggregator  --label <label> --read-port <n> [--advisor-port <n>]
#                           adds one row to dashboard/config/fleet-links.json
#
# The credential is read from STDIN, never from argv: an argument is
# world-readable in /proc for as long as the process lives, and this one is a
# bearer credential for a node's whole read surface.
#
# Both writers are idempotent and fail-safe: the file is backed up, rewritten
# temp-then-rename, and re-read before the backup is dropped. Both parsers
# fail an ENTIRE file closed on one bad row, so a helper that can silently
# empty a fleet's link table is worse than no helper.
set -euo pipefail

die() { printf 'error: %s\n' "$*" >&2; exit 1; }
say() { printf '%s\n' "$*"; }

INSTALL_DIR="${APERIRE_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
CONFIG_DIR="$INSTALL_DIR/dashboard/config"

usage() {
  sed -n '3,26p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  exit "${1:-1}"
}

read_credential() {
  local cred
  if [ -t 0 ]; then
    # -s, so the secret is not printed to the terminal and does not survive
    # in scrollback, a tmux buffer or a session recording. The newline is
    # ours to print because -s ate the operator's.
    printf 'Paste the credential (64 hex characters), then Enter: ' >&2
    read -rs cred
    printf '\n' >&2
  else
    read -r cred || true
  fi
  cred="$(printf '%s' "$cred" | tr -d '[:space:]')"
  [ -n "$cred" ] || die "no credential was given on stdin"
  printf '%s' "$cred" | grep -Eq '^[0-9a-f]{64}$' \
    || die "that is not a credential this helper mints (64 lower-case hex characters)"
  printf '%s' "$cred"
}

require_label() {
  printf '%s' "$1" | grep -Eq '^[a-z0-9-]{1,32}$' \
    || die "label \"$1\" must match [a-z0-9-]{1,32}, the same rule fleet.yaml uses"
}

require_port() {
  case "$1" in
    ''|*[!0-9]*) die "port \"$1\" is not a number" ;;
  esac
  if [ "$1" -lt 1024 ] || [ "$1" -gt 65535 ]; then
    die "port $1 must be between 1024 and 65535"
  fi
}

# Match the config directory's owner, which is the dashboard account on every
# install shape. A no-op when this is not running as root, because a non-root
# caller cannot chown and its own files already land as the right user.
chown_to_config_owner() {
  [ "$(id -u)" -eq 0 ] || return 0
  local owner
  owner="$(stat -c '%u:%g' "$CONFIG_DIR" 2>/dev/null || true)"
  [ -n "$owner" ] || return 0
  chown "$owner" "$1" 2>/dev/null || true
  CHOWNED_TO="$(stat -c '%U:%G' "$CONFIG_DIR" 2>/dev/null || echo "$owner")"
}
CHOWNED_TO=''

# node.js is what parses these files in production. Using it here means the
# check below is the SAME parser the service runs, not a second opinion.
node_bin() {
  command -v node >/dev/null 2>&1 || die "node is not on PATH, and this helper re-reads what it writes with it"
  command -v node
}

verb_mint() {
  command -v openssl >/dev/null 2>&1 || die "openssl is not on PATH"
  openssl rand -hex 32
  say "" >&2
  say "That is the whole secret and it is printed once. Put the VALUE on the node" >&2
  say "and its hash on the aggregator; this helper does both, one machine at a time." >&2
}

verb_node() {
  local aggregator='' label=''
  while [ $# -gt 0 ]; do
    case "$1" in
      --aggregator) aggregator="${2:-}"; shift 2 ;;
      --label) label="${2:-}"; shift 2 ;;
      -h|--help) usage 0 ;;
      *) die "unknown option $1" ;;
    esac
  done
  [ -n "$aggregator" ] || die "--aggregator is required (wss://<host>/fleet/v1/link)"
  [ -n "$label" ] || die "--label is required"
  require_label "$label"
  case "$aggregator" in
    wss://*) : ;;
    ws://127.0.0.1*|ws://localhost*) : ;;
    *) die "--aggregator must be wss:// (the credential crosses on this dial). ws:// is accepted only to loopback" ;;
  esac
  # The whole value, not just its prefix, and this is a security check rather
  # than tidiness. It is the one argument interpolated into the JSON heredoc
  # below, and a value carrying a double quote forges JSON structure: because
  # JSON.parse keeps the LAST duplicate key, an --aggregator of the shape
  # `wss://host", "credential": "<other>` would write a credential the
  # operator never typed, and the re-read would accept it. This character
  # class has no quote, no backslash and no whitespace, so nothing in it can
  # leave the string it is written into.
  printf '%s' "$aggregator" | grep -Eq '^wss?://[A-Za-z0-9._~-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]*)?$' \
    || die "--aggregator is not a plain WebSocket URL (scheme, host, optional port, optional path)"

  [ -d "$CONFIG_DIR" ] || die "$CONFIG_DIR does not exist: is this an Aperire install?"

  local cred; cred="$(read_credential)"
  local target="$CONFIG_DIR/fleet-link.json"
  local tmp="$target.tmp.$$"
  local backup=''
  if [ -f "$target" ]; then
    backup="$target.bak.$(date -u +%Y%m%dT%H%M%SZ)"
    cp -p "$target" "$backup"
  fi
  umask 077
  cat > "$tmp" <<JSON
{
  "aggregator_url": "$aggregator",
  "credential": "$cred",
  "label": "$label"
}
JSON
  chmod 600 "$tmp"
  # The template promises "owned by the dashboard account" and mode was the
  # only half enforced. Run under sudo this left the file root:root 0600,
  # which the dashboard cannot read, so the link never came up and the reason
  # was a permissions error nobody was looking for. The config directory's
  # own owner IS the dashboard account on every install shape.
  chown_to_config_owner "$tmp"
  mv "$tmp" "$target"

  # Re-read with the shipped parser. A file this node's own agent refuses is
  # a file that must not be left in place looking finished.
  #
  # The parser's complaint is captured into a VARIABLE and /tmp is never
  # touched. It used to go to /tmp/fleet-link-check.$$, and $$ is a PID in a
  # world-writable directory: any local account could pre-plant that path as
  # a symlink and the redirection would truncate a file of its choosing with
  # the privileges of whoever ran this, which the usage text tells them is
  # root. On a node that is a unit file, an authorized_keys, or a config the
  # dashboard reads at boot.
  #
  # Run from dashboard/, where tsx and the modules live: `node --import tsx`
  # resolves tsx from the working directory, not from the script's.
  local complaint=''
  local rc=0
  complaint="$( (cd "$INSTALL_DIR/dashboard" && APERIRE_LINK_TARGET="$target" \
    "$(node_bin)" --import tsx --input-type=module -e "
    import { loadLinkConfig } from './lib/fleet-link-agent.ts';
    const r = loadLinkConfig(process.env.APERIRE_LINK_TARGET);
    if (!r.ok) { console.error(r.reason); process.exit(1); }
  ") 2>&1 1>/dev/null )" || rc=$?
  if [ "$rc" -ne 0 ]; then
    say "the file this helper wrote is not one the agent accepts:" >&2
    say "$complaint" >&2
    if [ -n "$backup" ]; then
      mv "$backup" "$target"
      say "the previous file was put back" >&2
    else
      rm -f "$target"
    fi
    exit 1
  fi
  if [ -n "$backup" ]; then rm -f "$backup"; fi
  # A signed revocation names the credential it revoked (#688). This one is
  # new, so any tombstone here is about a relationship that has just been
  # replaced: it is inert already (its hash no longer matches), and removed so
  # nothing on this node can be read as still revoked.
  rm -f "$INSTALL_DIR/data/fleet-link.tombstone.json"

  say "Wrote $target (0600)${CHOWNED_TO:+, owned by $CHOWNED_TO}."
  say ""
  say "Two more things this node needs before the link comes up:"
  say "  1. the aggregator's fleet trust public key, under the literal label"
  say "     \`aggregator\` in the peers: block of $CONFIG_DIR/fleet-trust.yaml"
  say "  2. a restart:  sudo systemctl restart aperire-server"
}

verb_aggregator() {
  local label='' read_port='' advisor_port=''
  while [ $# -gt 0 ]; do
    case "$1" in
      --label) label="${2:-}"; shift 2 ;;
      --read-port) read_port="${2:-}"; shift 2 ;;
      --advisor-port) advisor_port="${2:-}"; shift 2 ;;
      -h|--help) usage 0 ;;
      *) die "unknown option $1" ;;
    esac
  done
  [ -n "$label" ] || die "--label is required"
  [ -n "$read_port" ] || die "--read-port is required (the 780x/790x this node's fleet.yaml row already names)"
  require_label "$label"
  require_port "$read_port"
  if [ -n "$advisor_port" ]; then require_port "$advisor_port"; fi
  [ -d "$CONFIG_DIR" ] || die "$CONFIG_DIR does not exist: is this an Aperire install?"

  local cred; cred="$(read_credential)"
  local hash; hash="$(printf '%s' "$cred" | sha256sum | cut -d' ' -f1)"
  local target="$CONFIG_DIR/fleet-links.json"
  local backup=''
  if [ -f "$target" ]; then
    backup="$target.bak.$(date -u +%Y%m%dT%H%M%SZ)"
    cp -p "$target" "$backup"
  fi

  # The merge is done by the SAME module that parses it, so a row this helper
  # adds is a row the hub will read, or the helper fails here rather than in
  # the journal an hour later.
  umask 077
  if ! ( cd "$INSTALL_DIR/dashboard" \
    && APERIRE_LINK_HASH="$hash" APERIRE_LINK_LABEL="$label" \
       APERIRE_LINK_TARGET="$target" \
       APERIRE_LINK_READ_PORT="$read_port" APERIRE_LINK_ADVISOR_PORT="${advisor_port:-}" \
       "$(node_bin)" --import tsx --input-type=module -e "
    import { readFileSync, writeFileSync, renameSync } from 'node:fs';
    import { parseLinkRegistry } from './lib/fleet-link-hub.ts';
    const path = process.env.APERIRE_LINK_TARGET;
    let rows = [];
    try {
      const parsed = parseLinkRegistry(readFileSync(path, 'utf8'));
      if (parsed.error) { console.error(parsed.error); process.exit(1); }
      rows = parsed.links;
    } catch (err) { if (err.code !== 'ENOENT') { console.error(String(err)); process.exit(1); } }
    const label = process.env.APERIRE_LINK_LABEL;
    const row = {
      label,
      credential_sha256: process.env.APERIRE_LINK_HASH,
      read_port: Number(process.env.APERIRE_LINK_READ_PORT),
      ...(process.env.APERIRE_LINK_ADVISOR_PORT ? { advisor_port: Number(process.env.APERIRE_LINK_ADVISOR_PORT) } : {}),
    };
    const next = rows.filter((r) => r.label !== label).concat([row]);
    const text = JSON.stringify({ links: next }, null, 2) + '\n';
    const check = parseLinkRegistry(text);
    if (check.error) { console.error(check.error); process.exit(1); }
    writeFileSync(path + '.tmp', text, { mode: 0o600 });
    renameSync(path + '.tmp', path);
  " >/dev/null ); then
    say "the row was not added" >&2
    if [ -n "$backup" ]; then
      mv "$backup" "$target"
      say "the previous file was put back" >&2
    fi
    exit 1
  fi
  if [ -n "$backup" ]; then rm -f "$backup"; fi

  chmod 600 "$target"
  chown_to_config_owner "$target"
  say "Wrote $target (0600). The credential itself is NOT in it; only its hash."
  say ""
  say "Then reload, and this aggregator will accept $label's link:"
  say "  sudo systemctl reload aperire-server     # or: pm2 restart <the aggregator process>"
}

case "${1:-}" in
  mint) shift; verb_mint "$@" ;;
  node) shift; verb_node "$@" ;;
  aggregator) shift; verb_aggregator "$@" ;;
  -h|--help|'') usage 0 ;;
  *) die "unknown verb \"$1\". Try: mint | node | aggregator" ;;
esac
