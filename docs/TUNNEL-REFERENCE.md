# Aperire One Tunnel Reference

How the dashboard reaches the internet through a Cloudflare tunnel, from a host with zero inbound ports open. For operators who already ran the tunnel install and want the day-2 reference: the fields, the files, the commands, and the security posture.

The Deployment Guide's [Reaching it from the internet, with a Cloudflare tunnel](DEPLOYMENT-GUIDE.md#reaching-it-from-the-internet-with-a-cloudflare-tunnel) gets the tunnel running, in every shape. This is what you keep open afterwards.

Replace placeholders in `<angle brackets>` (`<your-dashboard-host>`, `<TUNNEL_UUID>`, `<operator-user>`) with your real values. Examples use `aperire.example.com`, the IANA-reserved example domain, so a copy-paste slip won't route to a real host.

---

## Architecture

```
Browser → https://aperire.example.com
           ↓
       Cloudflare Edge (TLS termination, DDoS, CDN)
           ↓
       cloudflared daemon (outbound-only on port 7844)
           ↓
       localhost:7800 (Node.js / Express)
```

No inbound ports open. The `cloudflared` daemon dials an outbound QUIC connection to Cloudflare's edge. All traffic flows back through that outbound tunnel.

## Tunnel fields

| Field | Value |
|---|---|
| Tunnel name | `aperire` |
| Tunnel ID | `<TUNNEL_UUID>` (from `cloudflared tunnel create aperire`) |
| Hostname | `<your-dashboard-host>` (e.g. `aperire.example.com`) |
| Origin | `http://localhost:7800` |
| Protocol | QUIC |

## Files

| File | Purpose |
|---|---|
| `~/.cloudflared/config-aperire.yml` | Tunnel config (ingress rules) |
| `~/.cloudflared/<TUNNEL_UUID>.json` | Tunnel credentials (keep secret) |
| `~/.cloudflared/cert.pem` | Origin certificate for your Cloudflare zone |
| `/etc/systemd/system/cloudflared-aperire.service` | Systemd service unit |

Paths assume the default layout, where the tunnel runs as the operator account and reads config from that home. If you run it under a dedicated `cloudflared` user instead, config and credentials live in `/etc/cloudflared/`. See the dedicated-user section in the [Deployment Guide](DEPLOYMENT-GUIDE.md).

## Config and unit

You write the config; the script writes the unit.

The config at `~/.cloudflared/config-aperire.yml` is yours, created along with the tunnel itself in the [Deployment Guide](DEPLOYMENT-GUIDE.md#reaching-it-from-the-internet-with-a-cloudflare-tunnel). `scripts/setup-aperire-tunnel.sh` then writes `/etc/systemd/system/cloudflared-aperire.service` and starts it. It refuses to run if the config is missing, rather than installing a unit that points at nothing. Read the script for the exact unit contents. It's the source of truth, and copies here would drift from it.

The unit is enabled on boot and auto-restarts on crash after 3 seconds.

Two environment variables change what it writes, and they travel together:

| Variable | Default | Effect |
|---|---|---|
| `APERIRE_TUNNEL_USER` | the account that ran `sudo` | `User=` / `Group=` in the unit |
| `APERIRE_TUNNEL_CONFIG` | that account's `~/.cloudflared/config-aperire.yml` | the `--config` path in `ExecStart` |

A dedicated non-login tunnel account has no home, so the default config path resolves to nothing and the script stops. Pass both, with the config somewhere that account can read:

```bash
sudo APERIRE_TUNNEL_USER=cloudflared \
     APERIRE_TUNNEL_CONFIG=/etc/cloudflared/config-aperire.yml \
     bash scripts/setup-aperire-tunnel.sh
```

The unit is rewritten in full on every run. Hand edits to `User=` or `--config` do not survive the next one, so pass the variables instead.

## DNS

Cloudflare CNAME record:

```
<your-dashboard-host> → <TUNNEL_UUID>.cfargotunnel.com
```

Created via `cloudflared tunnel route dns aperire <your-dashboard-host>`.

## Day-2 commands

```bash
# Service status
systemctl status cloudflared-aperire

# Restart tunnel
sudo systemctl restart cloudflared-aperire

# View logs
journalctl -u cloudflared-aperire -f

# Tunnel info
cloudflared tunnel info aperire

# List all tunnels on this machine
cloudflared tunnel list
```

## Security notes

- No Cloudflare Access policies configured. The application layer handles authentication: passwordless WebAuthn / passkeys with sqlite-backed sessions, fully self-contained on the dashboard host. See [AUTH-GUIDE.md](AUTH-GUIDE.md).
- The credentials file (`<TUNNEL_UUID>.json`) is read-restricted to the operator user. Deleting it revokes the tunnel.
- In the tunnelled / Shape A layout (co-located, one box: see [Pick your shape](DEPLOYMENT-GUIDE.md#pick-your-shape)) the origin server binds to localhost only, so `:7800` needs no inbound firewall rule. In Shape B, the split, the dashboard binds `:7800` to the LAN for the relay, so that case needs the scoped UFW rule in the [Firewall](HARDENING-GUIDE.md#firewall) section.
- This tunnel carries browsers, not relays. A relay on a separate host is its own hop, and a plain `ws://` one puts the relay's bearer token on the LAN readable. The dashboard refuses that by default. See [Securing a remote relay link](RELAY-REFERENCE.md#securing-a-remote-relay-link).
- WebSocket upgrades work transparently through the tunnel (Cloudflare handles the HTTP/1.1 upgrade).

## Where to next

- **[Deployment Guide](DEPLOYMENT-GUIDE.md)**: the tunnel install steps, the dedicated-user layout, and full deployment for each shape.
- **[Auth Guide](AUTH-GUIDE.md)**: passkey enrollment and operator management.
- **[Hardening Guide](HARDENING-GUIDE.md)**: firewall rules and host hardening.
