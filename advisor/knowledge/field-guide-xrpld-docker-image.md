---
title: xrpld in Docker, built from the signed package
tags: [upgrade, docker, container, image, xrpld, package, packages.xrplf.org, signing key, localhost/xrpld, stop timeout, entrypoint, amendment blocked]
last_reviewed: 2026-09-27
source: The Rippled Field Guide, companion "xrpld in Docker: Build Your Own Image from the Signed Package" (github.com/realgrapedrop/rippled-field-guide), plus two lab swaps and one production swap on 2026-09-26
---

# Field Guide: xrpld in Docker, built from the signed package

Distilled from the operator's companion to The Rippled Field Guide. Treat as
Documented. Written from real swaps, 3.3.0 to 3.4.1, on 2026-09-26.

## Where releases come from

- Since 3.4.0, official xrpld binaries ship only as signed DEB and RPM
  packages at `packages.xrplf.org`, signed by the XRPL Foundation key. The
  official install guide has no Docker section.
- **There is an official image, and it is published as part of the release
  itself.** `rippleci/xrpld`, announced by Mayukha Vadari (Ripple) on
  2026-09-19 (<https://x.com/msvadari/status/2101364629037576276>) as
  produced automatically by the release process. WietseWind/docker-xrpld#31
  (2026-09-21) retires `xrpllabsofficial/xrpld` in its favour; that
  repository stopped at 3.3.0, a day after 3.4.1 shipped with an amendment
  deadline on it. Earlier versions of this note called `rippleci` an
  undocumented CI account. Those two sources are why it no longer does.
- **So the official image is the first source, and it is taken by digest.**
  The tag is asked about by name, one question about one release, and the
  digest that tag points at is what gets pulled: a tag moved between the
  approval and the swap cannot change what is installed.
- **A build from the signed DEB is the second source**, on the node's own
  box, tagged `localhost/xrpld:<version>`. It is what happens when no
  official image carries the release yet, and what happens when the operator
  asks for a build. The `localhost/` name can never resolve to a registry, so
  a pull of it fails instead of fetching someone else's image.
- **What the official image claims is checked against what the signed chain
  says**, before any swap: the release and commit it reports, the package
  hash recorded in its build history against the signed index's, and the
  SHA-256 of its `/usr/bin/xrpld` against the binary in the `.deb` apt just
  verified. They matched byte for byte for 3.4.1
  (`fb8430dfdbee9d8016818dab22881e48a125598beebf9b5b8c90ca7fdba1faaa`). Any
  mismatch stops and offers the build instead. This matters because that
  image's own build fetched the `.deb` from an upload host and checked one
  hash, rather than going through apt's signature chain.
- **This Advisor builds that image itself, as part of an upgrade.** A
  container upgrade is back up, build, ask the image what it is, record what
  it resolves to, point the deployment at it, recreate, then read the
  container's own first lines back. The build runs from a root-owned copy of
  the recipe under `/usr/local/lib/aperire`, never from the checkout, and
  the tag it produces is pinned by digest before the operator approves the
  restart and compared again immediately before it. "Is there a newer
  release" comes from the signed package index, not from a registry.
- **Two things about a container deployment are read before the stop**, and
  each refuses the upgrade rather than being found after it: a container
  that names no user has been running as root, and the built image's own
  account is uid 997, so the deployment has to say `user: "0:0"` first; and
  a deployment that mounts the config only at `/config` needs either root or
  a second read-only mount at `/etc/xrpld/xrpld.cfg`, as its own change.
- **The steps below are still the way to do it by hand**, and they are what
  the Advisor's own plan performs. Use them on a host with no Advisor, or
  when you want to see each step yourself.

## Verify before you build

1. Read the release announcement (`https://xrpl.org/blog/<year>/xrpld-<version>`).
   Write down the DEB SHA-256 and the commit hash.
2. The `SHA256` for `xrpld` in
   `https://packages.xrplf.org/repository/deb-stable/dists/any/main/binary-amd64/Packages`
   must match the announcement.
3. `curl -fsSL https://packages.xrplf.org/xrplf.asc | gpg --show-keys` must
   show exactly one key, fingerprint `B655416741221F780FBCFBC9AA84D41A11D29FA9`,
   the value the install guide and xrpl.org both publish. Anything else: stop.
4. After the build, `xrpld --version` inside the image must report the
   announced commit hash.

## The four things that go wrong on a swap

| Trap | What happens | Do this |
|---|---|---|
| Runtime user changes | The old image ran as **root** (empty `.Config.User`); the new one defaults to uid 997, which on some hosts is another service's account | Read `docker inspect <c> --format '{{.Config.User}}'`. Empty means keep `user: "0:0"` for the swap. Move data ownership to a service account later, as its own change |
| Config mounted only at `/config` | The entrypoint must copy `/config/rippled.cfg` and `/config/validators.txt` into `/etc/xrpld/`, which is root-owned. As uid 997 the copy fails | Root for the swap, or mount both files read-only at `/etc/xrpld/` as well. An older entrypoint warned and started xrpld on the package's stock config: no validator token, a new identity, and a healthcheck that still passed on `full`. The reviewed recipe stops instead |
| Stop grace | `docker compose up` gives the **old** container the stop timeout it was created with (often 90 s), never the file's new `stop_grace_period`. Two of four lab stock-node stops were SIGKILLed at 90 s | Pass `--timeout 300` (or `-t 300`) on the `up` that swaps, and set `stop_grace_period: 5m` for later stops. The package's own systemd unit allows 5 minutes |
| Store rotation | A stop mid online-delete rotation once left a lab node with an empty store | Swap only after `finished rotation`, with the next rotation further off than the swap plus sync time |

Test the new image before the swap with the real mounts and the same
`--user`, `--network none`, and no data volume. You want `copied` for both
files. **Never** run it beside the live node with the real config and
network: two instances signing with one validator key.

**Never print the config.** A stanza header and its value sit on separate
lines, so `grep -A1 '^\[validation_seed\]'` prints the secret. Read one key
(`grep -n '^online_delete'`) or a known line range.

## The swap

The official image, pinned:

```yaml
    image: rippleci/xrpld:<version>@sha256:<digest>
    entrypoint: ["/usr/bin/xrpld"]
    command: ["--conf", "/etc/xrpld/xrpld.cfg"]
    user: "0:0"            # only if the old container ran as root
    stop_grace_period: 5m
```

Or the image built here:

```yaml
    image: localhost/xrpld:<version>
    pull_policy: never
    user: "0:0"            # only if the old container ran as root
    stop_grace_period: 5m
```

**Write the arguments down.** The official image carries no entrypoint script
and its default command is `--net --silent --conf /etc/xrpld/xrpld.cfg`.
`--silent` blanks `docker logs`, which is the stream the store-rotation guard
and the can-delete timer read, so a node that took that default silently
would refuse every restart afterwards. With `entrypoint:` and `command:`
written out, both images start the node exactly the same way and the swap
really is one line. Do it as its own change, before the swap, never in the
same recreate. And on a deployment whose config is mounted only at `/config`,
write the arguments only AFTER the `/etc/xrpld` mounts exist: the entrypoint
being bypassed is the one thing putting the config where xrpld reads it.

```bash
docker compose -p <project> -f <compose file> up -d --timeout 300 <service>
```

Never `down`, which stops every service in the project. Keep the old image
and a dated 0700 backup of the compose file, config and `validators.txt` on
the same box. The data volume carries over, and with it the node identity
(`wallet.db`).

## Verify after

- The first log lines: `entrypoint: copied ...` (or `already matches`), then
  `Validator identity: <key>`. No `Validator identity` line on a validator
  means it is running the wrong config. Roll back.
- `server_info`: `build_version` is the new version, `server_state` reaches
  `proposing` (validator) or `full`, `pubkey_validator` and `pubkey_node`
  unchanged, no `amendment_blocked`, `validation_quorum` back to its old
  value (it can read one higher for a few seconds until the Negative UNL
  reapplies).
- `feature`: the new amendment reads `supported: true`. `count`, `threshold`
  and `validations` are absent until the node passes a flag ledger (about 22
  minutes on one lab validator), so their absence right after is normal.
- `proposing` only means validations are being sent. Confirm they arrive:
  the validator's key should appear about once per ledger on a public
  server's `validations` stream.

## Measured

| Node | Old container stop | RPC down | Start to `proposing`/`full` |
|---|---|---|---|
| Production validator, 20 days up | 27.5 s, clean | 28 s | 3 min 15 s (`proposing`) |
| Lab validator, 19 days up | 48.5 s, clean (`-t 300`) | 50.8 s | 5 min 59 s (`proposing`) |
| Lab stock node, four swaps | 43 s to 95 s; 2 of 4 SIGKILLed at 90 s | 43.5 s to 100 s | 7 min 20 s to 11 min 23 s (`full`) |

The build itself takes 20 to 60 seconds and touches nothing running.

## Rollback

Put the saved compose file back and run the same `up -d --timeout 300`.
**The rollback expires**: once the new release's amendment enables on the
network, the old version is amendment blocked. After that, roll back only
to an image that supports the amendment, so keep the previous
`localhost/xrpld` tag.
