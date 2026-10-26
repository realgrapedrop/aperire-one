// Does an Advisor exist? ADR 0016, the browser half.
//
// One published fact, fetched from /api/advisor-presence and polled on
// fleet-chip.js's cadence, so that no surface has to decide for itself
// whether an Advisor is here. Six affordances drifted apart precisely
// because each one answered that question its own way.
//
// The shape is fleet-chip.js's, deliberately: fetch on load, poll every 20s,
// KEEP THE LAST-KNOWN ANSWER on a failed poll rather than blanking it,
// expose it on a documented global, and dispatch a CustomEvent so a page
// repaints when the fact changes. One more instance of a pattern already on
// every page rather than a new one.
//
// Two things it does NOT copy from fleet-chip.js:
//
//   - No markup contract, so no early return. fleet-chip.js bails when
//     #fleetChipWrap is missing; this file has nothing to render and must run
//     on every page unconditionally, because its consumers are elsewhere.
//   - No `embedded` suppression. The shell and the embedded iframe each hold
//     their own instance and each poll for themselves, which is what
//     fleet-chip.js already does across that pair.
//
// The three fields are not interchangeable, and a surface wired to the wrong
// one reproduces the ADR 0014 mislabel:
//
//   self   this host's own Advisor. The break-glass chip, the local half of
//          the nav entry. /api/advisor/status is local by construction.
//   nodes  one row per subject node, from the fleet registry's declaration.
//          Per-row Ask pills, the fleet dropdown's Ask links.
//   any    the roll-up, and what NAVIGATION keys on. On an aggregator the
//          Advisor tab routes to the SUBJECT node's advisord, so an
//          aggregator with no local advisord and one node that has one is a
//          working tab; keying the nav entry on `self` would hide it and
//          take the only route to that node's Advisor with it.
//
// Named __apAdvisorPresence, not __apPeerAdvisorState. That other global
// already exists and keeps its own job (the subject node's capability); two
// similar names for two different questions is how the mislabel happens.
(function () {
  'use strict';

  var POLL_MS = 20000;

  // No fact yet. Not "absent" — absent is an OBSERVATION, and claiming one
  // before the first fetch lands would be the same kept-vs-observed bug this
  // whole record removes, in the browser instead of the server.
  //
  // Consumers must treat null as "do not render the gated thing yet", which
  // per decision 4 is also what they do under absent. Default-hidden,
  // revealed on the fact, never shown-then-hidden: six Ask Advisor pills
  // that flash before being taken away are the nag the design forbids.
  //
  // A logged-out page gets a 401 here, which also lands as null, and null is
  // the right answer there too.
  var fact = null;

  var waiters = [];
  var settled = false;

  // Which node the page is showing, from window.top's hash. Duplicated from
  // overview.html's readActiveNodeFromTopHash rather than imported, because
  // this file has no module system and must run standalone on eight pages —
  // but it reads the SAME channel, never a second store. A cross-origin
  // window.top throws; treat that as "no peer selected", which is what an
  // unexpectedly embedded document should assume.
  // Byte-identical to overview.html:6515 and consensus.html:3702's
  // PEER_LABEL_HASH_RE, applied to the RAW hash exactly as they apply it.
  // The two agree on every realistic input either way, but "the same channel"
  // is a claim worth making unfalsifiable rather than merely true today: one
  // character class drifting apart is a page and its Ask pills disagreeing
  // about which node they mean.
  var PEER_LABEL_HASH_RE = /[?&#]node=([a-z0-9-]{1,32})/;
  function activeNodeLabel() {
    var h;
    try { h = window.top.location.hash || ''; } catch { h = location.hash || ''; }
    var m = PEER_LABEL_HASH_RE.exec(h);
    return m ? m[1] : null;
  }

  function publish(next) {
    fact = next;
    window.__apAdvisorPresence = next;
    // Fired on every successful poll, not only on a change. A consumer that
    // wants to skip identical repaints can compare; a consumer that wants to
    // know the fact is still true cannot recover an event that never fired.
    window.dispatchEvent(new CustomEvent('aperire:advisor', { detail: next }));
    if (!settled) {
      settled = true;
      var pending = waiters;
      waiters = [];
      for (var i = 0; i < pending.length; i++) {
        try { pending[i](next); } catch { /* one bad consumer is not the others' problem */ }
      }
    }
  }

  function poll() {
    fetch('/api/advisor-presence', { credentials: 'same-origin' })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (data) {
        // The contract, not merely "an object". A proxy's error JSON, a
        // captive-portal body, or an older server that does not serve this
        // route at all can all parse as an object, and treating one as a
        // settled fact would publish any=undefined — read downstream as "no
        // Advisor anywhere" and enough to hide the nav entry on a host that
        // has one. An unrecognised body is NO fact, which is a state this
        // module already handles honestly.
        if (!data || typeof data !== 'object' || data.protocol !== 1 || !data.self) {
          // A 401, a 404 on an older server, or a body that is not the
          // contract. Settle the waiters so a consumer gating on ready()
          // is never left hanging, but do not invent a fact.
          if (!settled) publishNoFact();
          return;
        }
        publish(data);
      })
      .catch(function () {
        // Keep the last-known answer rather than blanking it. One failed poll
        // is not evidence that an Advisor was uninstalled — and if none has
        // landed yet, "no fact" is what the waiters get.
        if (!settled) publishNoFact();
      });
  }

  function publishNoFact() {
    settled = true;
    // The event fires here too, carrying null.
    //
    // This file is deferred AFTER mobile-nav.js on all eight pages, so its
    // consumers cannot see the global at their own execution time and reach
    // the fact through this event instead. An event that fires only on
    // success would leave such a consumer waiting forever on a logged-out
    // page, and "waits forever" is indistinguishable from "decided no" right
    // up until the moment it isn't. So the event is the complete channel:
    // exactly one fires on first settle, with the fact or with null.
    window.dispatchEvent(new CustomEvent('aperire:advisor', { detail: null }));
    var pending = waiters;
    waiters = [];
    for (var i = 0; i < pending.length; i++) {
      try { pending[i](null); } catch { /* as above */ }
    }
  }

  poll();
  setInterval(poll, POLL_MS);

  window.__apAdvisorPresence = fact;

  window.__advisorPresence = {
    /** The last fact, or null if none has landed. Synchronous, and null is
     *  a real answer meaning "not observed yet", never "absent". */
    get: function () { return fact; },

    /**
     * Resolves with the FIRST fact (or null if the first read could not
     * produce one), immediately if it has already landed.
     *
     * This exists so a consumer is not gated on script order. Both this file
     * and mobile-nav.js are `defer`, so execution follows document order
     * across eight separate files, and "presence must short-circuit before
     * the session read" would otherwise be a contract enforced by the
     * position of two <script> lines in each of them. It is not.
     */
    ready: function (cb) {
      if (settled) { cb(fact); return; }
      waiters.push(cb);
    },

    /** `any` — the field NAVIGATION keys on. Null-safe and deliberately
     *  false under no-fact, so a gated affordance stays hidden until the
     *  fact says otherwise. */
    anyAdvisor: function () { return !!(fact && fact.any); },

    /** THIS host's state, or null if not observed yet. The break-glass chip
     *  and nothing about a peer. */
    selfState: function () { return (fact && fact.self && fact.self.state) || null; },

    /** Why this host's Advisor is in the state it is in, or '' when there is
     *  nothing to explain. ADR 0016 says the state's reason reaches the
     *  operator ("the revert is never silent"), and until #113 the string was
     *  published and read by nothing: the tab printed whatever the proxy call
     *  failed with, which for an unreadable token is "no advisor token
     *  readable on this host" and no cause at all. That is the sentence the
     *  0600 incident produced in the first place. */
    selfDetail: function () { return (fact && fact.self && fact.self.detail) || ''; },

    /** True only when this host has been OBSERVED to have no Advisor. Null
     *  (not yet observed) is not absent, and the two must not collapse:
     *  a consumer that treats "don't know" as "absent" would hide a real
     *  Advisor for the length of one failed poll. */
    selfAbsent: function () { return this.selfState() === 'absent'; },

    /** A named subject node's declared state, or null if this dashboard
     *  cannot route to it. Peers get two states, never three (decision 7). */
    nodeState: function (label) {
      if (!fact || !fact.nodes) return null;
      for (var i = 0; i < fact.nodes.length; i++) {
        if (fact.nodes[i].label === label) return fact.nodes[i].state;
      }
      return null;
    },

    /**
     * The state of the node a tab is SHOWING, which is what every Ask
     * affordance is keyed on. Read from the shell's own hash channel, the
     * same one fleet-chip.js writes and overview.html reads, so a page and
     * its Ask pills can never disagree about which node they mean.
     *
     * Null when no fact has landed, and null is not absence.
     */
    subjectState: function () {
      if (!fact) return null;
      var label = activeNodeLabel();
      return label ? this.nodeState(label) : this.selfState();
    },

    /** Render an Ask affordance normally. */
    askLive: function () { return this.subjectState() === 'present'; },

    /** Render it, but disabled. Only where the affordance marks a REAL
     *  CONCERN: hiding a firing alert's Ask because the optional Advisor is
     *  down would make installing it a prerequisite for seeing that
     *  something is wrong. A mere convenience link is not rendered instead. */
    askDisabled: function () { return this.subjectState() === 'installed-but-down'; },

    /** Render it at all, live or disabled. */
    askShown: function () {
      var s = this.subjectState();
      return s === 'present' || s === 'installed-but-down';
    },

    /** Exposed for the walk, and so a consumer can force a re-read without
     *  waiting out the poll. */
    refresh: poll,
  };
})();
