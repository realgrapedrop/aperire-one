// Peer-read fetch helper — D8 slice 3 backend retrofit
// (advisor-enhancement/security-review-peer-read-proxy.md,
// advisor-enhancement/d8-frontend-tab-audit.md). Shared across every tab
// that reads a read-contract route (history, recent, ledgers,
// missed-ledgers, agreement, alerts, firing, digests, bandwidth) so each
// tab's own retrofit is a one-line call-site swap rather than a repeated
// hash-parsing block. Loaded eagerly, WITHOUT `defer` (see the <script> tag
// in each page's <head>) — every other shared script on these pages
// (fleet-chip.js, mobile-nav.js) is deferred to the bottom of body, but
// several tabs call into this helper from their OWN top-level boot code,
// which runs synchronously during parsing, well before a deferred script at
// the bottom of the document would have executed.
//
// A route-NAME API, not a path rewrite: overview.html's/consensus.html's
// existing peer-view modules (D8 slices 3/4) each duplicate the same
// `window.top.location.hash` reader this file also implements — this is
// deliberately the SAME regex and the SAME window.top-with-fallback
// pattern, not a third independent one, so all three can never disagree
// about which node is active. A caller names a read-contract ROUTE
// (`'history'`, `'ledgers'`, `'missed-ledgers'`, ...), never a path — a
// naive `/history` → `/api/node/<label>/read/history` string rewrite breaks
// on the first call site whose local path doesn't share the route's name
// (`/recent-ledgers` serves the `ledgers` route; `/missed-ledgers` matches
// by coincidence, not by rule).
(function () {
  'use strict';

  var PEER_LABEL_HASH_RE = /[?&#]node=([a-z0-9-]{1,32})/;

  /** The active fleet peer's label, or null when viewing the local node —
   *  read from window.top's hash (falling back to this window's own hash
   *  when window.top is inaccessible, e.g. a cross-origin embed), exactly
   *  the channel fleet-chip.js writes and overview.html/consensus.html's
   *  own peer-view modules already read. */
  function activePeerLabel() {
    var h;
    try { h = window.top.location.hash || ''; } catch { h = location.hash || ''; }
    var m = PEER_LABEL_HASH_RE.exec(h);
    return m ? m[1] : null;
  }

  function isPeerActive() {
    return !!activePeerLabel();
  }

  // The LOCAL path each read-contract route is served through today. Not a
  // 1:1 string match with the route name — `ledgers` predates the
  // /read/v1/<route> naming on the browser side and is served locally at
  // `/recent-ledgers`; `history`/`recent`/`missed-ledgers` happen to share
  // their route's own name. Deliberately does NOT list `alerts`/`firing`/
  // `digests`: Insights' local endpoints (`/api/insights/history|state|
  // digest_log`) return a DIFFERENT shape than the read-contract routes of
  // the same underlying data (different keys, different param names — see
  // insights.html's own peer-view module), so routing them through this
  // one-shape-fits-both map would silently paint the wrong fields. Insights
  // calls readFetch() only on the peer branch, for those three, and keeps
  // its own local fetches direct.
  var LOCAL_PATH = {
    history: '/history',
    recent: '/recent',
    ledgers: '/recent-ledgers',
    'missed-ledgers': '/missed-ledgers',
  };

  // The exact key set lib/peer-read-proxy.ts forwards (P2-037) — sending a
  // narrower set here is cosmetic (the server enforces its own allowlist
  // regardless of what this file sends), but it keeps the constructed URL
  // honest about what will actually reach a peer, and keeps a stray local
  // param (anything read straight off `location.search`, say) from ever
  // being forwarded by accident.
  var PARAM_ALLOWLIST = ['metric', 'limit', 'range', 'agg', 'since_ms', 'around', 'span'];

  function buildQuery(params) {
    var out = [];
    PARAM_ALLOWLIST.forEach(function (k) {
      if (params && params[k] !== undefined && params[k] !== null && params[k] !== '') {
        out.push(encodeURIComponent(k) + '=' + encodeURIComponent(params[k]));
      }
    });
    return out.join('&');
  }

  /**
   * readFetch(routeName, params, explicitLabel) — Promise<Response>, same
   * calling convention as `fetch()` itself. When a peer is active, targets
   * `/api/node/<label>/read/<routeName>?<allowlisted params>`; otherwise
   * targets this node's own local route. Callers keep their existing
   * `.ok`/`.status`/`.json()` handling — including the peer proxy's own
   * status codes (404 unknown peer, 409 integrity mismatch, 424
   * unreachable/timeout, with the reason in the body's `error`: the edge in
   * front of an aggregator replaces a 502 or 504, #1134), which mirror the
   * shapes overview.html's/consensus.html's existing `/api/node/:label/overview` handlers already
   * branch on.
   *
   * `explicitLabel` is OPTIONAL and defaults to the hash — every caller
   * that omits it behaves exactly as before, and the hash stays the one
   * channel deciding which node a peer-aware TAB is showing. It exists for
   * one case the hash cannot express: a component that reads a named node
   * on a page the shell does not make peer-aware, and that labels every
   * number it draws with the node it came from. advisor.html's metric strip
   * on an aggregator host is that case and today the only one — a caller
   * passing a label here and NOT naming the node on screen would be
   * rendering another node's data as this one's, which is the exact
   * dishonesty PEER_AWARE_TABS' allowlist exists to prevent. Pass `null`
   * for "this host's own store, regardless of the hash".
   */
  function readFetch(routeName, params, explicitLabel) {
    var label = explicitLabel !== undefined ? explicitLabel : activePeerLabel();
    var qs = buildQuery(params);
    if (label) {
      var url = '/api/node/' + encodeURIComponent(label) + '/read/' + encodeURIComponent(routeName) + (qs ? '?' + qs : '');
      return fetch(url, { credentials: 'same-origin' });
    }
    var localPath = LOCAL_PATH[routeName];
    if (!localPath) return Promise.reject(new Error('peer-fetch: no local path registered for route "' + routeName + '"'));
    return fetch(localPath + (qs ? '?' + qs : ''));
  }

  window.aperirePeerFetch = {
    readFetch: readFetch,
    isPeerActive: isPeerActive,
    activePeerLabel: activePeerLabel,
  };
})();
