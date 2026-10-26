// The validator-list publishers a node is configured to follow, and how
// healthy each of those lists is right now.
//
// One definition, shared by the local Governance page (server.ts's
// sampleGovernance) and the `governance` read route, for the same reason
// lib/amendments.ts holds the ballot row builder: a peer's browser session
// needs the identical computation run against the PEER's own
// `snapshot.validator_list_sites`, and a second hand-copied loop in the read
// surface is exactly how the ballot's two definitions drifted apart.
//
// This is genuinely per-node data, not a network-wide fact to blank on a
// peer: which publishers a node trusts is that operator's own configuration,
// and a stale or rejected list on one node while its neighbours are fine is
// precisely the failure worth being able to see per node.

/** rippled timestamps arrive as ISO-8601 strings, unix seconds, or
 *  ripple-epoch seconds (since 2000-01-01), depending on build and field.
 *  Tries all three. Moved here from server.ts so the route and the local
 *  page parse them the same way. */
const RIPPLE_EPOCH_OFFSET_MS = 946_684_800_000;    // 2000-01-01 UTC

export function parseRippledTs(v: unknown): number | null {
  if (v == null) return null;
  if (typeof v === 'string') {
    const t = Date.parse(v);
    return Number.isFinite(t) ? t : null;
  }
  const n = Number(v);
  if (!Number.isFinite(n) || n <= 0) return null;
  // Heuristic: values under ~2 billion are ripple-epoch seconds
  // (ripple-epoch 2B ≈ year 2063). Bigger → unix seconds. Huge → ms.
  if (n < 2_000_000_000) return n * 1000 + RIPPLE_EPOCH_OFFSET_MS;
  if (n < 10_000_000_000) return n * 1000;
  return n;
}

/** The subset of one `validator_list_sites` entry this summary reads. Every
 *  field is optional on purpose — the lab fleet's rippled reports only
 *  `uri`, `last_refresh_status`, `last_refresh_time` and
 *  `refresh_interval_min`, so list/cert expiry and sequence are genuinely
 *  absent there and must stay null rather than becoming a confident zero. */
export interface ValidatorListSiteEntry {
  uri?: unknown;
  site?: unknown;
  url?: unknown;
  last_refresh_status?: unknown;
  last_refresh_time?: unknown;
  list_expiration?: unknown;
  cert_expiration?: unknown;
  cert_expiry?: unknown;
  seq?: unknown;
  sequence?: unknown;
}

export interface PublisherSiteRow {
  site: string;
  status: string;
  refresh_age_s: number | null;
  list_expiry_days: number | null;
  cert_expiry_days: number | null;
  sequence: number | null;
}

export interface PublisherSummary {
  site_count: number;
  /** The worst status across every site — what the card's single pill shows. */
  refresh_status: string;
  refresh_age_s: number | null;
  list_expiry_days: number | null;
  cert_expiry_days: number | null;
  sites: PublisherSiteRow[];
}

function isHealthy(status: string | undefined): boolean {
  return !status || status === 'accepted' || status === 'same_sequence';
}

function seqOrNull(v: unknown): number | null {
  if (v === undefined || v === null) return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

/** The publisher card's aggregates and the publishers table's rows, from one
 *  `validator_list_sites` response. Aggregates report the WORST case across
 *  sites — the oldest refresh, the nearest expiry — because one stale
 *  publisher is the fact an operator needs, not the average of two. */
export function buildPublisherSummary(
  sites: ValidatorListSiteEntry[],
  nowMs: number,
): PublisherSummary {
  const rows: PublisherSiteRow[] = [];
  let worstStatus = 'ok';
  let oldestRefreshAgeS: number | null = null;
  let nearestListExpiryDays: number | null = null;
  let nearestCertExpiryDays: number | null = null;

  for (const s of sites) {
    const status = typeof s.last_refresh_status === 'string' ? s.last_refresh_status : undefined;

    const refreshMs    = parseRippledTs(s.last_refresh_time);
    const ageS         = refreshMs !== null ? Math.max(0, Math.floor((nowMs - refreshMs) / 1000)) : null;
    const expiryMs     = parseRippledTs(s.list_expiration);
    const listExpDays  = expiryMs !== null ? Math.floor((expiryMs - nowMs) / 86_400_000) : null;
    const certExpiryMs = parseRippledTs(s.cert_expiration ?? s.cert_expiry);
    const certExpDays  = certExpiryMs !== null ? Math.floor((certExpiryMs - nowMs) / 86_400_000) : null;

    if (!isHealthy(status)) worstStatus = status ?? 'unknown';

    if (ageS !== null && (oldestRefreshAgeS === null || ageS > oldestRefreshAgeS)) {
      oldestRefreshAgeS = ageS;
    }
    if (listExpDays !== null && (nearestListExpiryDays === null || listExpDays < nearestListExpiryDays)) {
      nearestListExpiryDays = listExpDays;
    }
    if (certExpDays !== null && (nearestCertExpiryDays === null || certExpDays < nearestCertExpiryDays)) {
      nearestCertExpiryDays = certExpDays;
    }

    const site = s.uri ?? s.site ?? s.url ?? '?';
    rows.push({
      site: String(site),
      status: status ?? 'unknown',
      refresh_age_s: ageS,
      list_expiry_days: listExpDays,
      cert_expiry_days: certExpDays,
      sequence: seqOrNull(s.seq ?? s.sequence),
    });
  }

  return {
    site_count: sites.length,
    refresh_status: worstStatus,
    refresh_age_s: oldestRefreshAgeS,
    list_expiry_days: nearestListExpiryDays,
    cert_expiry_days: nearestCertExpiryDays,
    sites: rows,
  };
}
