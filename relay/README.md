# aperire-relay

Validator-side agent that reads a short list of `/proc` files and pushes the results to the Aperire dashboard over an outbound WebSocket. The dashboard derives every network- and host-level row on its System and Network tabs from what this relay sends.

Single-purpose, zero runtime dependencies, outbound-only on the network — runs unprivileged under a dedicated system user, matches the operational shape of `node_exporter` and `cloudflared`.

## Architecture

Design notes, the metrics catalog and the operator guide ship in this repository:

- [`docs/RELAY-REFERENCE.md`](../docs/RELAY-REFERENCE.md) — install, systemd unit, config, security model
- [`docs/METRICS-CATALOG.md`](../docs/METRICS-CATALOG.md) — every system and network row, and where it comes from

The on-wire JSON contract is the integration point. It lives at `dashboard/types/relay-contract.ts` and the Go structs in `contract.go` here mirror it exactly, `protocol_version` included.

## Build

```sh
go build -o aperire-relay .
```

Produces a static binary around 8 MB. Strip symbols for a smaller artifact:

```sh
go build -ldflags "-s -w -X main.version=$(git describe --tags --always)" -o aperire-relay .
```

## Run

Copy `relay.conf.example` to `/etc/aperire/relay.conf` and fill in the token, `node_label`, and `dashboard_url`. Then:

```sh
./aperire-relay --config /etc/aperire/relay.conf
```

Or run as a systemd service using the unit provided in `docs/system-metrics-collection.md` of the dashboard repo. Standard commands:

```sh
sudo systemctl start aperire-relay     # start
sudo systemctl stop aperire-relay      # stop
sudo systemctl restart aperire-relay   # pick up config changes
sudo systemctl status aperire-relay    # health
sudo journalctl -u aperire-relay -f    # tail logs
```

## Development

The repo ships with `relay.conf.dev` (gitignored) that points at `ws://127.0.0.1:7800/ingest` with a dev token — useful when running the dashboard from the same host. After building:

```sh
./aperire-relay --config ./relay.conf.dev
```

The dashboard side reads the allow-list from the `RELAY_TOKENS` environment variable (comma-separated).

## License

To be decided before the first tagged release.
