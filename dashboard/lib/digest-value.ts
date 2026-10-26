// #379. The digest email's fallback word for a value it has nothing to
// report: no agreement data for the window, an alert with no recorded
// value, a peer count the poller never filled in. buildDigestHtml used a
// bare `','` for all three, left over from a template-string edit that
// meant to leave an empty placeholder and typed the wrong character. The
// result mailed a lone comma into an operator's inbox where a number
// belonged.
//
// `n/a` is the word the rest of the dashboard already uses for an absent
// field on its own host (see, e.g., public/overview.html's `.na` span and
// public/debug-mem.js's heap/fcp fallbacks). "n/a for a peer" is a
// different case, a field that cannot exist when reading a remote peer,
// and doesn't apply to a digest, which only ever reports on itself.

export const DIGEST_NA = 'n/a';

/** Render a digest value as a string, or DIGEST_NA when it is absent. */
export function digestValue(v: string | number | null | undefined): string {
  return v == null ? DIGEST_NA : String(v);
}
