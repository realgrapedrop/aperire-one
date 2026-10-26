// What the last-resort 500 looks like, decided by the path it is answering.
//
// The outer handler in server.ts catches everything a route did not catch
// itself. It used to answer `Internal error` as text on every one of them,
// including on /api/* and /auth/*, whose callers in public/ do
// `fetch(...).then(function (r) { return r.json(); })` with nothing between.
// A text body there throws inside the client's own then-chain, so the page
// reported a parse error rather than the failure the server actually had, and
// on some pages the failure vanished into an empty `.catch(function () {})`.
//
// The decision is made on the RAW request URL, not on a parsed one: this runs
// inside a catch, and `new URL()` and `decodeURIComponent()` both throw. A
// path this cannot read falls back to the text body, which is the safe
// direction — an unparseable path is not one of the two JSON prefixes.
//
// The body says `internal_error` and nothing else on purpose. The thrown
// error is logged on the server, where the operator can read it; putting its
// message on the wire is how a stack trace or a file path ends up in a
// browser (server.ts had one route doing exactly that).

/** A complete response, so the caller writes it and decides nothing. */
export interface ErrorResponse {
  status: number;
  headers: Record<string, string>;
  body: string;
}

/** The two prefixes whose clients parse the body as JSON. Both keep their
 *  trailing slash: `/apidocs` is not an API route, and a prefix test without
 *  the slash would answer it JSON. */
const JSON_PREFIXES = ['/api/', '/auth/'];

/** True when this request's client parses what it gets back. */
export function wantsJsonError(rawUrl: string | undefined | null): boolean {
  const url = String(rawUrl ?? '');
  // Cut the query and the fragment; `/api/x?y=1` is still an API path, and a
  // `?` cannot appear before the prefix.
  const q = url.search(/[?#]/);
  const path = q === -1 ? url : url.slice(0, q);
  return JSON_PREFIXES.some((p) => path.startsWith(p));
}

/** The last-resort 500 for one request. no-store because a cached 500 is a
 *  failure that outlives itself, which is the same bug class as a stale
 *  reading rendered as current. */
export function internalErrorResponse(rawUrl: string | undefined | null): ErrorResponse {
  if (wantsJsonError(rawUrl)) {
    return {
      status: 500,
      headers: { 'content-type': 'application/json', 'cache-control': 'no-store' },
      body: JSON.stringify({ error: 'internal_error' }),
    };
  }
  return {
    status: 500,
    headers: { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' },
    body: 'Internal error',
  };
}
