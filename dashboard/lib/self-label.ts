/**
 * What this dashboard calls ITSELF.
 *
 * A fresh install has no `config/fleet.yaml` (the file is deliberately absent
 * until a second node exists, see fleet.yaml.example's header), so there is no
 * registry row to take a label from, and every surface that renders a self
 * label had to fall back to something. What they fell back to was the
 * browser's address, and on the ordinary ways of reaching a new dashboard,
 * `http://localhost:7800` or a tunnel, that address is `localhost`. The
 * operator's first look at their own node named the loopback (#145).
 *
 * The browser's address is never an identity. It is a fact about the route
 * the operator took, not about the machine, and the same box answers to a
 * different one down every tunnel. `authn.yaml`'s `public_url` is the same
 * mistake one step removed: it is where operators reach this dashboard, which
 * is again a route.
 *
 * So the order is: the fleet registry's own row for this host, because an
 * operator who wrote a label in `fleet.yaml` has already answered the
 * question and a join must keep overriding this exactly as it does today;
 * then the machine's own name, `os.hostname()`, the same expression the
 * System tab's HOSTNAME row and the Overview NODE card's HOST row render, so
 * one page cannot give two answers about one box.
 *
 * Kept here, pure and away from the server, so the derivation is testable
 * without a fleet registry, a socket or a hostname.
 */

/**
 * The display form of a machine name: the first label, with any domain
 * dropped. `srv12345` is unchanged; `node1.example.internal` becomes
 * `node1`.
 *
 * Short because this is a NAME, rendered in a compact fleet row beside a role
 * badge and four status badges. A 40 character FQDN there is ellipsised into
 * uselessness, and the row's tip carries the full one. The HOST row on the
 * NODE card is a different field with a different promise (its tooltip says
 * "exactly as the host reports it"), and it keeps the whole string: nothing
 * here is applied to it.
 *
 * An address is not a name. Cutting `192.168.1.5` at its first dot gives
 * `192`, which is worse than showing the whole address, so anything shaped
 * like an IPv4 literal comes back as it went in. IPv6 literals have no dots
 * to cut and are unaffected.
 */
export function shortHostName(raw: string | null | undefined): string {
  const name = String(raw ?? '').trim();
  if (!name) return '';
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(name)) return name;
  const first = name.split('.')[0];
  return first || name;
}

/**
 * The self label, from the two sources that can supply one.
 *
 * `fleetLabel` is this host's own row in the fleet registry, or null when
 * there is no registry, the file is empty, or it could not identify this host
 * (all three of which the registry parser already treats as the same state).
 * `hostName` is `os.hostname()` on this machine.
 *
 * Returns '' when neither is available. Callers render their own kind of
 * absent for that rather than being handed an invented name: an unobserved
 * identity is not a reason to reach for the browser's address, which is the
 * rule every other field in the NODE card already follows.
 */
export function deriveSelfLabel(
  fleetLabel: string | null | undefined,
  hostName: string | null | undefined,
): string {
  const label = String(fleetLabel ?? '').trim();
  if (label) return label;
  return shortHostName(hostName);
}
