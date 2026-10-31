// Fleet node picker — shared across the shell and all seven tab pages
// (decisions.md D5, task step C; VIEWING superseded by D8 slice 3). Fetches
// /api/fleet once and polls it, renders the header chip + dropdown, and
// dispatches a DOM event so the Overview NODES panel (task step D) reads
// from the SAME payload — the chip and the panel cannot disagree, because
// neither one keeps its own copy of the fleet state; both read this file's
// last fetch.
//
// D8 slice 3: picking a peer no longer navigates to that node's own
// dashboard/origin. It writes the active-node label into
// window.top.location.hash (the same channel overview.html's peer-view
// module reads — see that file's own comment on why `window.top` is the one
// channel that is both "shell-level state" and "survives reload"), which
// only Overview currently renders; picking one elsewhere in the shell jumps
// to Overview first (same origin, never a peer origin). Only the row naming
// whichever node is ACTUALLY on screen renders as the non-interactive
// aria-current span — that can now be a peer, not only self.
//
// Second pass: "jumps to Overview first" above is no longer true inside
// the shell at all — see goToNodeView's own comment. Every tab the shell
// lists is peer-aware (index.html's PEER_AWARE_TABS holds the same eight
// names as its TABS), so picking a peer stays exactly where it is and just
// swaps the active node. The bounce survives only for a standalone tab
// page opened outside the shell, which still navigates to this host's own
// Overview — never to the peer's dashboard.
//
// Markup contract: `#fleetChipWrap` (hidden by default — the single-node
// regression guarantee lives here: an empty `nodes` array from the server
// leaves it hidden and nothing else about the page changes), `#fleetChip`
// (the trigger button), `#fleetDD` (the dropdown, hidden by default),
// `#fleetDDSummary`, `#fleetDDList`, and the chip's own inner spans
// (`#fleetChipDot`/`#fleetChipName`/`#fleetChipSep`/`#fleetChipRoll`). Any
// page missing `#fleetChipWrap` just skips this file's work — same
// convention as mobile-nav.js.
(function () {
  'use strict';

  // What an operator does about a refused node (#268), in one place. The
  // wire carries the verdict and the status; this sentence carries the fix,
  // and it is composed here rather than sent per row because it is a fixed
  // template around a label the browser already has. Every surface that
  // shows a refusal — this dropdown, the Overview FLEET row, the centre
  // card's STATE — reads it from here, so the three cannot drift.
  //
  // Defined before the markup guard below: a page without the chip still
  // renders fleet rows, and would otherwise get an undefined helper.
  function refusedTip(label) {
    var n = String(label == null ? 'This node' : label);
    return n + ' rejected this dashboard\u2019s read token. Its install was wiped or re-keyed; ' +
      'bring its new read token over the way docs/FLEET-GUIDE.md shows (\u201cThe peer\u2019s read token\u201d) ' +
      'into this dashboard\u2019s secrets (the token_path in fleet.yaml), and reload the registry (SIGHUP, or restart).';
  }
  window.__fleetRefusedTip = refusedTip;

  // The same arrangement for the OTHER verdict a peer can answer with and
  // still not be readable (#273): it answered, it named a node key, and the
  // key is not the one this fleet pinned. Composed here for the same reason
  // the refusal is — the wire carries the verdict and the two keys, the
  // browser carries the sentence, and the four surfaces that print it (this
  // dropdown, the Overview FLEET row's badges, the centre card, the Settings
  // updates table) cannot drift apart.
  //
  // Six characters and an ellipsis. Two node keys are 52 characters that
  // differ in the middle, and a sentence carrying both in full is unreadable
  // at a glance; the full pair goes on its own line underneath, where an
  // operator can compare them against fleet.yaml.
  function shortKey(k) {
    var s = String(k == null ? '' : k);
    return s.length > 7 ? s.slice(0, 6) + '\u2026' : s;
  }
  function pinTip(label, expected, reported) {
    var n = String(label == null ? 'This node' : label);
    return n + '\u2019s node key is not the one pinned in this fleet ' +
      '(expected ' + shortKey(expected) + ', it reports ' + shortKey(reported) + '). ' +
      'Its node was rebuilt or re-keyed. If that was you, update expected_pubkey_node ' +
      'in fleet.yaml and reload the registry; if not, treat the node as untrusted.';
  }
  /** The full pair, for the second line. Two strings rather than one, so each
   *  surface breaks them the way its own box wants. */
  function pinKeyLines(expected, reported) {
    return ['expected ' + String(expected), 'it reports ' + String(reported)];
  }
  /** Does this row carry a READ identity failure? The two keys are the
   *  discriminator on every surface, never `verdict === 'critical'`: a node
   *  with a firing critical alert is critical too, and its identity is fine.
   *
   *  NEVER the self row (#488). It carries the same two keys for a different
   *  fact: this dashboard reads its own node directly, nothing it reported
   *  was refused, and what disagrees with it is the registry file on this
   *  host's own disk. Every sentence below this function says an impostor
   *  answered, and on this host that would be a lie. Use pinStale for that
   *  row.
   */
  function pinFailed(node) {
    return !!(node && !node.self && node.pin_expected && node.pin_reported);
  }
  /** The self row's version: this dashboard's OWN registry pins a key its own
   *  node does not answer with. */
  function pinStale(node) {
    return !!(node && node.self && node.pin_state === 'changed' &&
      node.pin_expected && node.pin_reported);
  }
  /** What that costs, and where the fix is. Two things separate it from the
   *  peer sentence above: nothing on this page is refused (the reading came
   *  from this node, not through the registry), and the file to edit is on
   *  this host, which is also why no ceremony is involved. An operator with
   *  a shell on the box they are looking at edits their own file; there is
   *  nothing for a passkey to authorise, unlike accepting a key for a node
   *  on another machine. */
  function pinStaleTip(label, expected, reported) {
    var n = String(label == null ? 'this node' : label);
    return 'This dashboard’s own registry pins a node key ' + n + ' does not have ' +
      '(pinned ' + shortKey(expected) + ', it reports ' + shortKey(reported) + '). ' +
      'Nothing on this page is refused: these readings come from this node itself. ' +
      'What is refused is every OTHER host that reads this node through a registry ' +
      'carrying the same pin. A node key changes when its store is wiped and resynced, ' +
      'when a host is rebuilt, or when a conversion left its identity file behind.';
  }
  window.__fleetPinTip = pinTip;
  window.__fleetPinKeyLines = pinKeyLines;
  window.__fleetPinFailed = pinFailed;
  window.__fleetPinStale = pinStale;
  window.__fleetPinStaleTip = pinStaleTip;
  window.__fleetShortKey = shortKey;

  var wrap = document.getElementById('fleetChipWrap');
  var chip = document.getElementById('fleetChip');
  var dd = document.getElementById('fleetDD');
  if (!wrap || !chip || !dd) return;

  var dotEl = document.getElementById('fleetChipDot');
  var nameEl = document.getElementById('fleetChipName');
  var sepEl = document.getElementById('fleetChipSep');
  var rollEl = document.getElementById('fleetChipRoll');
  var summaryEl = document.getElementById('fleetDDSummary');
  var listEl = document.getElementById('fleetDDList');

  var POLL_MS = 20000;
  var open = false;
  var lastNodes = null;
  // The node this dashboard last had on screen — the operator's own choice,
  // remembered so the automatic landing choice below can restore THAT rather
  // than re-deciding from scratch. Seeded from the hash on every render, so a
  // pick made anywhere (this chip, another tab page's copy, a reload of a
  // bookmarked link) is the one that comes back.
  var lastPicked = null;

  // Each peer's role, for the N/V letter on its row (#1256). The fleet poll
  // does not carry it, so it is asked the way Overview's FLEET panel asks
  // (fetchFleetMeta in overview.html): the peer's own node-status read,
  // `is_validator`. The same read and the same rule, so the picker and the
  // panel cannot name a node differently. Unknown is no letter, never a
  // guess.
  //
  // Asked when the dropdown opens, never on load. On load these reads took
  // browser connections from the tab's own first reads, and the tab painted
  // a hop later (peer-panel-settle-walk's #164 control caught it). The
  // letters are only seen with the dropdown open, so that is when they are
  // asked for. Every open asks again, because the shell can stay up for
  // days and a node's role can change under it; a poll while open asks only
  // the peers still unknown, which is the retry after a failed read. A peer
  // the fleet already reports unreachable or refused, or whose node key is
  // not the pinned one, is not asked: its read would fail, on every open.
  //
  // A letter that lands is patched into its slot (paintRole), never by
  // rebuilding the list: the first open's answers arrive while the operator
  // is reaching for a row, and a rebuild under their finger drops the press
  // and the focus.
  var roleByLabel = Object.create(null);
  var roleInFlight = Object.create(null);
  function roleLetter(role) { return role === 'validator' ? 'V' : role === 'node' ? 'N' : ''; }

  // Every tab page ships its OWN copy of this file inside its OWN
  // #fleetChipWrap — the shell hides that copy's <header> with injected CSS,
  // but the element is still structurally present and (once render() below
  // unhid it) was reachable by a real tap: the "picking a node jumps to
  // Overview" defect. `window.self !== window.top` is the one reliable,
  // synchronous signal for "this document is sitting inside the shell's
  // iframe" — deliberately NOT `?embed=1` (a standalone page opened with
  // that query string by hand is still `self === top` and must still get a
  // working chip) and NOT "is a tab page" (the same file runs unmodified in
  // the shell's own header, where it must stay fully interactive). A
  // cross-origin `window.top` throws on access; that can only happen if this
  // document is itself embedded somewhere unexpected, so treat the throw the
  // same as "embedded" rather than assume standalone.
  var embedded = true;
  try { embedded = window.self !== window.top; } catch { embedded = true; }

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  // Formatted at RENDER time from a raw timestamp, never sent pre-formatted
  // by the server — a server-formatted "4m ago" string would freeze between
  // 20s broadcasts, the same kept-vs-observed shape this project keeps
  // re-finding (HANDOFF, "peers survive an outage the way state used to").
  function fmtAgo(ms) {
    if (ms == null) return 'unknown';
    var mins = Math.max(0, Math.round((Date.now() - ms) / 60000));
    return mins < 1 ? 'just now' : mins + 'm ago';
  }

  // The active-node channel (D8 slice 3). Reads window.top so this works
  // identically whether this script's own document is the shell, a
  // standalone tab page, or (invisibly, header hidden) an embedded
  // Overview — top === self in the standalone/shell case, the shell's own
  // window in the embedded case. Kept in sync with the identical parser in
  // overview.html's peer-view module; not factored into a shared file (no
  // new script tag, no new CSP surface) — the project already tolerates
  // this scale of hand-duplication between its desktop/mobile lists.
  function readActiveNodeLabel() {
    var h;
    try { h = window.top.location.hash || ''; } catch { h = location.hash || ''; }
    var m = /[?&#]node=([a-z0-9-]{1,32})/.exec(h);
    return m ? m[1] : null;
  }
  function setActiveNodeLabel(label) {
    var topWin;
    try { topWin = window.top; } catch { topWin = window; }
    var h = (topWin.location.hash || '').replace(/^#/, '');
    // Strip any existing node= param — whatever precedes it: '?', '&', or
    // nothing at all when it's the very FIRST thing after '#' (a standalone
    // page's bare "#node=x" deep link, which readActiveNodeLabel above
    // accepts but a [?&]-only strip would silently fail to clear).
    h = h.replace(/(^|[?&])node=[a-z0-9-]{1,32}/, function (m, sep) { return sep === '&' ? '&' : ''; });
    h = h.replace(/[?&]$/, '');
    if (label) h += (h.indexOf('?') >= 0 ? '&' : '?') + 'node=' + encodeURIComponent(label);
    topWin.location.hash = h;
  }
  // Picking a peer must stay on whichever tab is already on screen when
  // that tab can render one (the operator's own hard requirement — viewing
  // Consensus and picking a peer must still be Consensus, showing that
  // peer, not a bounce to Overview). Inside the shell that is now every
  // tab: index.html's PEER_AWARE_TABS lists the same eight names as its
  // TABS, so the fall-back-to-Overview branch below no longer fires there
  // for any tab. It is kept because it is still the answer when the hooks
  // are missing — and because it is what a standalone page outside the
  // shell does, one paragraph down.
  //
  // In the shell (window.__shellLoadTab exists): ask the shell which tab
  // is current and whether IT considers that tab peer-aware — via the
  // hooks index.html exposes next to loadTab's own PEER_AWARE_TABS, not a
  // second hand-copied list here that could silently drift from it. A
  // peer-aware current tab just gets the hash write below; its own
  // embedded page reacts to that hashchange in place (overview.html's and
  // consensus.html's own peer-view modules each listen on window.top for
  // exactly this). A non-peer-aware current tab (or an unknown one, if
  // these hooks are ever missing) keeps the original behaviour: switch to
  // Overview first, then write the hash.
  //
  // Outside the shell (a standalone tab page, header visible, no
  // window.__shellLoadTab): unchanged from before this fix — Overview
  // itself sets the hash in place, everything else still navigates there.
  // fleet-peer-consensus-walk.mjs's own comment documents this remaining
  // gap; it wasn't part of the operator's ask, which was scoped to the
  // shell.
  function goToNodeView(label) {
    if (window.__shellLoadTab) {
      var cur = window.__shellCurrentTab ? window.__shellCurrentTab() : 'overview';
      var peerAware = window.__shellPeerAwareTab ? window.__shellPeerAwareTab(cur) : (cur === 'overview');
      if (peerAware) {
        setActiveNodeLabel(label);
        return;
      }
      window.__shellLoadTab('overview');
      setActiveNodeLabel(label);
      return;
    }
    if (/\/overview\.html$/.test(location.pathname) || location.pathname === '/' || location.pathname === '') {
      setActiveNodeLabel(label);
      return;
    }
    location.href = '/overview.html#node=' + encodeURIComponent(label);
  }

  function stateWord(node) {
    // Critical (a pin mismatch — fleet-health.ts's checkIdentityPin) carries
    // its own fixed, full-sentence detail and must be shown VERBATIM, not
    // uppercased like a short warn reason — it reads as a sentence, not a
    // status word, and shouting it would bury "re-pin it (see the fleet
    // guide)" in noise.
    // The identity failure, named. Ahead of the generic critical branch
    // below, and keyed on the keys rather than on the verdict (#273): this
    // is the one critical an operator fixes in fleet.yaml, and it used to
    // read as the same undifferentiated red sentence as everything else.
    if (pinFailed(node)) return 'NOT VERIFIED \u00b7 node key is not the pinned one';
    if (node.verdict === 'critical') return node.detail || 'integrity failure';
    // Answered, and said no. Never UNREACHABLE: the box is up and the
    // network path is fine (#268). The word is short and the fix is in the
    // row's own tip, which is where there is room for a sentence.
    if (node.verdict === 'refused') return 'REFUSED \u00b7 read token rejected';
    // This dashboard could not read its own token for the node (#1305): nothing
    // was asked of it, so UNREACHABLE would be untrue. Keyed on the row's flag,
    // never on the detail's words.
    if (node.token_unreadable === true) return 'TOKEN UNREADABLE · last known ' + fmtAgo(node.last_seen_ms);
    if (node.verdict === 'unreachable') return 'UNREACHABLE · last known ' + fmtAgo(node.last_seen_ms);
    if (node.verdict === 'warn') return (node.detail || 'degraded').toUpperCase();
    return node.self ? 'this node' : 'healthy';
  }

  // Reuses the existing investigate deep-link pattern (Overview ledger
  // strip → advisor.html#investigate=…): a distinct top-level hash key
  // dispatched by advisor.html's own init, opening the drawer and asking a
  // question composed from context rather than a raw label.
  function askHref(node) {
    return '/advisor.html#fleet=' + encodeURIComponent(node.label) +
      '&state=' + encodeURIComponent(node.verdict) +
      '&detail=' + encodeURIComponent(node.detail || '') +
      '&at=' + encodeURIComponent(Date.now());
  }

  // The name a row is printed under. This host's own row carries
  // display_name, the one name every page gives it (its pairing label on a
  // paired node, #1284); `label` stays the key every link and match uses.
  function shownName(node) {
    return (node && node.self && node.display_name) || (node && node.label) || '';
  }

  function rowHTML(node, activeLabel) {
    // 'refused' takes the same red band 'critical' does: it still needs
    // attention. Only the WORD differs, because only the work differs.
    var isCrit = node.verdict === 'critical' || node.verdict === 'refused';
    var rowClass = isCrit ? ' crit' : node.verdict === 'warn' ? ' warn' : node.verdict === 'unreachable' ? ' unreach' : '';
    var dotClass = node.verdict === 'ok' ? ' ok' : node.verdict === 'warn' ? ' warn' : isCrit ? ' crit' : '';
    var stateClass = isCrit ? ' crit' : node.verdict === 'warn' ? ' warn' : node.verdict === 'unreachable' ? ' unreach' : '';
    var nameHTML = esc(shownName(node)) + (node.self ? '<span class="ndd-cur-tag">this dashboard</span>' : '');
    // A peer's slot is always rendered, empty while its role is unknown, so
    // the peers' names line up. This node's own row never gets a letter (nor
    // does it on the FLEET panel), so it has no slot, and its name and "this
    // dashboard" tag keep the width.
    var role = roleByLabel[node.label];
    var roleHTML = node.self ? '' : '<span class="ndd-role' + (role ? ' ' + role : '') +
      '" data-role-label="' + esc(node.label) + '" aria-hidden="true">' + roleLetter(role) + '</span>';
    var body = '<span class="ndd-dot' + dotClass + '" aria-hidden="true"></span>' + roleHTML +
      '<span class="ndd-body"><span class="ndd-name">' + nameHTML + '</span>' +
      '<span class="ndd-state' + stateClass + '">' + esc(stateWord(node)) + '</span></span>';
    // D8 slice 3 supersedes D5's navigate model for VIEWING: whichever row
    // names the node ACTUALLY on screen — which can now be a peer, not
    // only self — is the non-interactive <span aria-current>. Every other
    // row, self included once a peer is active, is a real <button> that
    // swaps this dashboard's data in place; `data-fleet-label=""` on the
    // self button means "return to local" (the delegated click handler
    // below treats an empty attribute as null).
    var isActive = node.self ? !activeLabel : node.label === activeLabel;
    var linkClass = 'ndd-link' + (node.self ? ' ndd-self' : '');
    var link = isActive
      ? '<span class="' + linkClass + '" aria-current="page">' + body + '</span>'
      : '<button type="button" class="' + linkClass + '" data-fleet-label="' + esc(node.self ? '' : node.label) + '">' + body + '</button>';
    // ADR 0016. This link was rendered for ANY non-self, non-ok peer with no
    // presence check at all, so on a fleet where nobody runs an Advisor every
    // unhealthy row offered to ask one. Keyed on THAT PEER's own declared
    // state now, never on this host's: the two are different questions with
    // different answers, and answering one with the other is the ADR 0014
    // mislabel. A dropdown link is a convenience, not a concern, so it is
    // not rendered rather than disabled; the row and its verdict, which are
    // the news, are untouched either way.
    var ap = window.__advisorPresence;
    var peerHasAdvisor = !!ap && ap.nodeState(node.label) === 'present';
    var ask = (!node.self && node.verdict !== 'ok' && peerHasAdvisor)
      ? '<a class="ndd-ask" href="' + esc(askHref(node)) + '">Ask Advisor</a>'
      : '';
    return '<li class="ndd-row' + rowClass + '">' + link + ask + '</li>';
  }

  function counts(nodes) {
    var ok = 0, warn = 0, unreach = 0, crit = 0;
    nodes.forEach(function (n) {
      if (n.verdict === 'ok') ok++;
      else if (n.verdict === 'warn') warn++;
      // A refused node is PRESENT and locked, never absent. Counting it in
      // the bare unreachable stat would say a box is off when it is up
      // (#268); it goes with the other red one.
      else if (n.verdict === 'critical' || n.verdict === 'refused') crit++;
      else unreach++;
    });
    return { ok: ok, warn: warn, unreach: unreach, crit: crit };
  }

  function summaryHTML(nodes) {
    var c = counts(nodes);
    // The crit stat only appears when it's non-zero — every other stat here
    // always shows, but a pin-mismatch integrity failure is rare enough that
    // an always-visible 0 would read as "this fleet supports a 4th ailment
    // class", inviting a question the dropdown can't answer today.
    var critHTML = c.crit
      ? '<span class="hs-stat"><span class="hs-dot crit" aria-hidden="true"></span>' + c.crit +
        '<span class="sr-only"> critical</span></span>'
      : '';
    return '<span class="total"><span class="lbl">Total:</span>&nbsp;' + nodes.length + '</span>' +
      '<span class="hs-div" aria-hidden="true">|</span>' +
      critHTML +
      '<span class="hs-stat"><span class="hs-dot ok" aria-hidden="true"></span>' + c.ok + '</span>' +
      '<span class="hs-stat"><span class="hs-dot warn" aria-hidden="true"></span>' + c.warn + '</span>' +
      '<span class="hs-stat"><span class="hs-dot" aria-hidden="true"></span>' + c.unreach +
      '<span class="sr-only"> unreachable</span></span>';
  }

  // Sort order fixed by the mock: critical, warning, unreachable, healthy.
  // 'critical' is the pin-mismatch integrity failure (fleet-health.ts) — the
  // slot this ranking always reserved ahead of warn is now occupied, not
  // merely reserved. Ties keep registry (server) order, never alphabetical:
  // re-ordering by name would separate a node from the neighbours its
  // operator listed it beside.
  var VERDICT_RANK = { critical: -2, refused: -1, warn: 0, unreachable: 1, ok: 2 };
  function sortForDisplay(nodes) {
    return nodes.map(function (n, i) { return { n: n, i: i }; })
      .sort(function (a, b) { return (VERDICT_RANK[a.n.verdict] - VERDICT_RANK[b.n.verdict]) || (a.i - b.i); })
      .map(function (x) { return x.n; });
  }

  // Aggregator mode: this dashboard hosts no local node of its own — its self
  // row is unreachable (no local rippled) while it federates real peer nodes.
  // The aggregator is the vantage point, not a monitored node, so it is dropped
  // from the roster, the count and the chip. Heuristic (verdict-based) is exact
  // for the aggregator deployment; a normal single-node dashboard keeps its self
  // (reachable → not aggregator; or unreachable-with-no-peers → still shown so a
  // downed local node is visible).
  function isAggregatorSelf(self, peers) {
    return !!self && self.verdict === 'unreachable' && peers.length >= 1;
  }

  function render(nodes) {
    if (!nodes || !nodes.length) {
      if (!embedded) { wrap.hidden = true; closeDropdown(); }
      return;
    }
    var self = nodes.filter(function (n) { return n.self; })[0] || null;
    var peers = nodes.filter(function (n) { return !n.self; });
    var aggregatorMode = isAggregatorSelf(self, peers);
    // What we DISPLAY + count. In aggregator mode the self (dashboard host) is
    // excluded entirely; otherwise the roster is every node, self included.
    var roster = aggregatorMode ? peers : nodes;

    var activeLabel = readActiveNodeLabel();
    if (activeLabel) lastPicked = activeLabel;
    // In aggregator mode there is no meaningful self/local view — the host
    // runs no node of its own — so a hash naming no node has to land on a real
    // one, or the operator is looking at an empty dashboard.
    //
    // Two rules this landing choice did not used to follow, both of which the
    // operator felt as the dashboard "flipping to different things":
    //
    // Restore the node the operator last had, never `roster[0]`. That first
    // row is health-sorted, so it renames itself as verdicts move — the node
    // you came back to was whichever one happened to be unhealthiest at that
    // moment, not the one you were looking at. Falling back to roster[0] is
    // still right for a first-ever landing, when there is nothing to restore.
    //
    // Only a chip that is NOT embedded may write. Every tab page ships its own
    // copy of this file inside the shell's iframe, already inert for its own
    // DOM and its own clicks — but it was still writing the shared active-node
    // channel, and it starts each page load with no memory of what the
    // operator picked. So switching tabs handed the choice to a brand-new copy
    // that had none, and the node changed underneath a pick that was only ever
    // meant to change the tab. State is the shell's to write, same as the
    // pixels are the shell's to draw.
    //
    // Suppressed while the tab on screen has no peer view of its own:
    // re-adding a node there would have the chip claim a peer is being viewed
    // on a tab that renders fleet-wide state — the dishonesty PEER_AWARE_TABS
    // exists to prevent. The node comes back on its own the moment a
    // peer-aware tab is picked again, because lastPicked outlives the round
    // trip. The Advisor USED to be the tab this described; it is peer-aware
    // now (its metric cards read, and name, the selected node), so this
    // branch no longer fires there — see PEER_AWARE_TABS' own comment in
    // index.html for why that changed and what on that tab is still local.
    var tabTakesANode = true;
    if (window.__shellPeerAwareTab && window.__shellCurrentTab) {
      tabTakesANode = !!window.__shellPeerAwareTab(window.__shellCurrentTab());
    }
    if (aggregatorMode && !activeLabel && !embedded && tabTakesANode && roster.length) {
      var restore = null;
      for (var ri = 0; ri < roster.length; ri++) {
        if (roster[ri].label === lastPicked) { restore = lastPicked; break; }
      }
      if (!restore) restore = roster[0].label;
      setActiveNodeLabel(restore);
      activeLabel = restore;
      lastPicked = restore;
    }

    // The embedded copy of this file is never shown and never interactive —
    // the shell's own instance (self === top) is the sole rendered chip. The
    // read-only work above this line still ran (which node is active, what
    // this poll returned) because it is shared state other in-page consumers
    // need — Overview's own NODES panel (overview.html) renders from this SAME
    // script's poll() via the aperire:fleet event and
    // window.__fleetChip.getNodes(), whether or not the chip itself is on
    // screen; stopping that would blank Overview's fleet rows every time it
    // is viewed through the shell, which is the normal way it's viewed. The
    // one thing an embedded copy no longer does is WRITE (see the landing
    // choice above): reading shared state is what those consumers need,
    // writing it was never part of the bargain.
    if (embedded) return;

    wrap.hidden = false;
    var c = counts(roster);
    // The chip names the node ACTUALLY on screen, so an operator always knows
    // which node they are viewing — never the dashboard host.
    // When the hash names no node at all (the Advisor tab, which takes none),
    // fall back to the one last on screen rather than to the health-sorted
    // first row — otherwise the chip renames itself as verdicts move, with the
    // operator having touched nothing.
    var fallbackLabel = aggregatorMode ? (lastPicked || (roster[0] && roster[0].label)) : null;
    var activeNode = (activeLabel && roster.filter(function (n) { return n.label === activeLabel; })[0])
      || (fallbackLabel && roster.filter(function (n) { return n.label === fallbackLabel; })[0])
      || (aggregatorMode ? roster[0] : self) || roster[0];
    // The same three verdicts the picker's rows colour, and the same red for
    // 'refused' as for 'critical' (rowHTML above). Only unreachable or an
    // unread node stays the base grey: a critical node drew grey here once
    // and read as unknown, which is the wrong way to be wrong (#1283).
    dotEl.className = 'chip-dot' + (!activeNode ? ''
      : activeNode.verdict === 'ok' ? ' ok'
      : activeNode.verdict === 'warn' ? ' warn'
      : (activeNode.verdict === 'critical' || activeNode.verdict === 'refused') ? ' crit' : '');
    nameEl.textContent = activeNode ? shownName(activeNode) : '—';
    // The crit clause only appears when it's non-zero, so a fleet with no
    // integrity failures keeps the exact three-part label this already had.
    rollEl.setAttribute('aria-label', 'Fleet: ' + c.ok + ' healthy, ' + c.warn + ' warning, ' + c.unreach + ' unreachable' +
      (c.crit ? ', ' + c.crit + ' critical' : ''));
    // All three counts, always, zeros included: the same three the panel's
    // Total line shows. A roll that dropped its zeros read "3" for a fleet of
    // three healthy nodes and "2 1" for two healthy and one amber, and the
    // operator had to open the panel to learn which was which (the lab aggregator,
    // 2026-09-03). Crit stays non-zero-only, for the panel's reason.
    var rollHTML = '';
    if (c.crit) rollHTML += '<span class="hs-dot crit" aria-hidden="true"></span><span>' + c.crit + '</span>';
    rollHTML += '<span class="hs-dot ok" aria-hidden="true"></span><span>' + c.ok + '</span>';
    rollHTML += '<span class="hs-dot warn" aria-hidden="true"></span><span>' + c.warn + '</span>';
    rollHTML += '<span class="hs-dot" aria-hidden="true"></span><span>' + c.unreach + '</span>';
    rollEl.innerHTML = rollHTML;
    if (sepEl) sepEl.hidden = false;

    summaryEl.innerHTML = summaryHTML(roster);
    listEl.innerHTML = sortForDisplay(roster).map(function (n) { return rowHTML(n, activeLabel); }).join('');
  }

  function openDropdown() {
    if (open) return;
    open = true;
    chip.setAttribute('aria-expanded', 'true');
    dd.hidden = false;
    if (lastNodes) fetchRoles(lastNodes, true);
    document.addEventListener('click', onDocClick, true);
    document.addEventListener('keydown', onKeydown, true);
    // The tab content is a same-origin IFRAME, so a click inside it never
    // reaches this document's outside-click handler — the dropdown would stay
    // open (feedback #19). Clicking the iframe blurs the shell window, so close
    // on blur too, which also dismisses the menu when the operator tabs away.
    window.addEventListener('blur', closeDropdown);
  }
  function closeDropdown() {
    if (!open) return;
    open = false;
    chip.setAttribute('aria-expanded', 'false');
    dd.hidden = true;
    document.removeEventListener('click', onDocClick, true);
    document.removeEventListener('keydown', onKeydown, true);
    window.removeEventListener('blur', closeDropdown);
  }
  function onDocClick(e) {
    if (wrap.contains(e.target)) return;
    closeDropdown();
  }
  function onKeydown(e) {
    if (e.key === 'Escape') { closeDropdown(); chip.focus(); }
  }
  // The embedded copy binds NEITHER of these — it is never shown (render()
  // above returns before ever clearing `wrap.hidden`), so a click can never
  // legitimately land on its chip or its dropdown rows. Not binding the
  // handlers at all, rather than binding-then-early-returning inside them,
  // is the actual fix for the "hard nav to Overview" defect: it was this
  // delegated row handler's own goToNodeView() falling to `location.href`
  // (no window.__shellLoadTab in the iframe's realm) that caused it.
  if (!embedded) {
    chip.addEventListener('click', function () { if (open) closeDropdown(); else openDropdown(); });

    // D8 slice 3 — one delegated handler for every row button (self-return
    // and peer-pick alike), rather than per-row listeners rebuilt on every
    // innerHTML rebuild. Closes the dropdown and returns focus to the chip on
    // either path — same affordance a real navigation would have given for
    // free by unloading the page.
    listEl.addEventListener('click', function (e) {
      var btn = e.target.closest && e.target.closest('button[data-fleet-label]');
      if (!btn) return;
      var label = btn.getAttribute('data-fleet-label') || null;
      closeDropdown();
      chip.focus();
      if (label) goToNodeView(label); else setActiveNodeLabel(null);
    });
  }

  // `all` on open: every reachable peer, known or not. Otherwise (a poll
  // while open) only the peers with no role yet.
  function fetchRoles(nodes, all) {
    nodes.forEach(function (n) {
      if (n.self || n.verdict === 'unreachable' || n.verdict === 'refused' || pinFailed(n)) return;
      if (roleInFlight[n.label] || (!all && roleByLabel[n.label])) return;
      roleInFlight[n.label] = true;
      fetch('/api/node/' + encodeURIComponent(n.label) + '/read/node-status', { credentials: 'same-origin' })
        .then(function (r) { return r.ok ? r.json() : null; })
        .then(function (ns) {
          if (!ns) return;
          roleByLabel[n.label] = ns.is_validator === true ? 'validator' : 'node';
          paintRole(n.label);
        })
        .catch(function () { /* the slot keeps what it had; a poll while open asks an empty one again */ })
        .finally(function () { roleInFlight[n.label] = false; });
    });
  }
  function paintRole(label) {
    var role = roleByLabel[label];
    Array.prototype.forEach.call(listEl.querySelectorAll('.ndd-role'), function (el) {
      if (el.getAttribute('data-role-label') !== label) return;
      el.className = 'ndd-role' + (role ? ' ' + role : '');
      el.textContent = roleLetter(role);
    });
  }

  function poll() {
    fetch('/api/fleet', { credentials: 'same-origin' })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (data) {
        var nodes = (data && data.nodes) || [];
        lastNodes = nodes;
        render(nodes);
        if (open) fetchRoles(nodes, false);
        window.dispatchEvent(new CustomEvent('aperire:fleet', { detail: nodes }));
      })
      .catch(function () { /* keep the last-known chip rather than blank it on one failed poll */ });
  }

  poll();
  setInterval(poll, POLL_MS);

  // ADR 0016. Re-render from the already-fetched nodes (never a second
  // request) when the Advisor fact changes, so a peer's Ask link appears the
  // moment that peer gets an Advisor and goes when it loses one.
  window.addEventListener('aperire:advisor', function () { if (lastNodes) render(lastNodes); });

  // D8 slice 3 — re-render (from the already-fetched `lastNodes`, never a
  // second request) whenever the active-node hash changes, so the dropdown
  // keeps naming the right row as aria-current even between fleet polls —
  // e.g. the OTHER fleet-chip.js instance in this same page pair (the
  // shell's vs. an embedded Overview's) writing the same channel. A
  // listener registered on window.top from inside a child iframe survives
  // a tab-switch-away-and-back unless removed on pagehide.
  function onTopHashChange() { if (lastNodes) render(lastNodes); }
  var topWinForHash;
  try { topWinForHash = window.top; } catch { topWinForHash = window; }
  topWinForHash.addEventListener('hashchange', onTopHashChange);
  window.addEventListener('pagehide', function () {
    try { topWinForHash.removeEventListener('hashchange', onTopHashChange); } catch { /* already gone */ }
  });

  // Exposed for the walk, and for the NODES panel (task step D) so it can
  // render from whatever this file already fetched this page-load instead
  // of opening a second, independent request — the two must never disagree,
  // and the surest way is for there to be only one fetch.
  // lastPicked is exposed READ-ONLY, for the one consumer that has to answer
  // the same question this chip answers on a tab that takes no node: "which
  // node is the operator looking at?" On the Advisor tab the hash names none
  // by design, and the chip's header still names the node last on screen (see
  // the fallbackLabel comment in render()) — so anything else on that tab
  // deriving its own answer from the health-sorted roster would name a
  // DIFFERENT node than the header, with the operator having touched nothing.
  // That is the same instability fallbackLabel exists to avoid, reintroduced
  // one component over. A getter, never a setter: the pick is still made here
  // and only here.
  window.__fleetChip = {
    getNodes: function () { return lastNodes; },
    lastPicked: function () { return lastPicked; },
    refresh: poll,
  };
})();
