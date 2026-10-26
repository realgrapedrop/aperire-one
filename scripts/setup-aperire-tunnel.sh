#!/usr/bin/env bash
# Aperire Cloudflare Tunnel — systemd setup.
#
#   sudo bash scripts/setup-aperire-tunnel.sh
#
# The unit runs as the operator who invoked this, reading the tunnel config
# from that account's home. Both are resolved here rather than written into the
# file: systemd does not expand $HOME in ExecStart, so a unit containing one
# would point at a directory literally named "$HOME" — and a unit naming one
# machine's user is a unit that only works on that machine.
#
# This script writes the UNIT only. The tunnel config has to exist first; it
# refuses to run without one, because a unit pointing at a file nobody wrote
# fails at start with an error that explains nothing.
#
# Two overrides, and they travel together:
#
#   APERIRE_TUNNEL_USER    account the unit runs as (default: the sudo caller)
#   APERIRE_TUNNEL_CONFIG  path to the tunnel config (default: that account's
#                          ~/.cloudflared/config-aperire.yml)
#
# A dedicated non-login tunnel account has no home, so the default config path
# resolves to nothing and the guard below stops. Pass both, pointing the config
# at somewhere that account can read (/etc/cloudflared is the usual choice):
#
#   sudo APERIRE_TUNNEL_USER=cloudflared \
#        APERIRE_TUNNEL_CONFIG=/etc/cloudflared/config-aperire.yml \
#        bash scripts/setup-aperire-tunnel.sh
#
# The unit is rewritten in full on every run, so hand edits to User= or
# --config do not survive the next one. Pass the variables instead.

set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "run with sudo — this writes a systemd unit" >&2; exit 1; }

RUN_USER="${APERIRE_TUNNEL_USER:-${SUDO_USER:-$(id -un)}}"
id "$RUN_USER" >/dev/null 2>&1 || { echo "no such account: $RUN_USER" >&2; exit 1; }
RUN_HOME="$(getent passwd "$RUN_USER" | cut -d: -f6)"
CONFIG="${APERIRE_TUNNEL_CONFIG:-$RUN_HOME/.cloudflared/config-aperire.yml}"
CLOUDFLARED="$(command -v cloudflared || true)"

[[ -n "$RUN_HOME" ]]    || { echo "could not resolve a home directory for $RUN_USER" >&2; exit 1; }
[[ -n "$CLOUDFLARED" ]] || { echo "cloudflared is not on PATH; install it first" >&2; exit 1; }
[[ -f "$CONFIG" ]] || {
  echo "no tunnel config at $CONFIG" >&2
  echo "this script writes the systemd unit; you write the config first" >&2
  echo "(deployment guide, 'Set up the Cloudflare tunnel', step 3)" >&2
  echo "or point at an existing one:  sudo APERIRE_TUNNEL_CONFIG=/path bash $0" >&2
  exit 1
}

echo "user:   $RUN_USER"
echo "config: $CONFIG"
echo "binary: $CLOUDFLARED"

# Unquoted heredoc: these values are meant to be substituted now, not left for
# systemd to expand — it will not. Written through a temporary file so a
# half-written unit is never installed.
TMP=$(mktemp)
cat > "$TMP" <<EOF
[Unit]
Description=Cloudflare Tunnel (aperire)
After=network-online.target
Wants=network-online.target

[Service]
User=$RUN_USER
Group=$RUN_USER
ExecStart=$CLOUDFLARED tunnel --config $CONFIG run
Restart=always
RestartSec=3
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

# A unit carrying an unexpanded variable fails at start with an error that says
# nothing about why, so it is caught here instead.
if grep -q '\$[A-Za-z_]' "$TMP"; then
  echo "refusing to install: the unit still contains an unexpanded variable" >&2
  grep -n '\$[A-Za-z_]' "$TMP" >&2
  rm -f "$TMP"
  exit 1
fi

install -o root -g root -m 0644 "$TMP" /etc/systemd/system/cloudflared-aperire.service
rm -f "$TMP"

systemctl daemon-reload
systemctl enable cloudflared-aperire
systemctl restart cloudflared-aperire
systemctl status cloudflared-aperire --no-pager
