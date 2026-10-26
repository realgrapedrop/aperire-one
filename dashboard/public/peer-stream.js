// Peer-stream client — ADR 0013, decisions 2 and 7.
//
// The "Validations received / quorum" bar is not a gauge. Its entire meaning
// is its RHYTHM: it fills as UNL validations land inside a consensus round of
// roughly four seconds, and it snaps back to zero on ledger close. An
// operator reads the shape, not the number. On a node's own dashboard that
// rhythm rides the local WebSocket at 1Hz; on the fleet aggregator a peer has
// no WebSocket to this browser, and two samples per round (PEER_POLL_MS)
// cannot express fill-and-reset — what the operator sees is a smear where
// there should be a pulse. This module is the transport that fixes it.
//
// A SIBLING of peer-fetch.js, not a call into it: readFetch returns
// Promise<Response> for one-shot JSON and has no meaning for an event
// stream. EventSource sends the session cookie same-origin and needs no
// token — the token stays server-side on the aggregator, as it does for
// every other peer read.
//
// ONE copy, shared by overview.html and consensus.html. Both tabs draw the
// same bar from the same route already, and renderQuorumBar's own comment
// says it: "Twinned in consensus.html — change both or the tabs disagree."
// A reconnect-plus-missed-tick state machine written twice is that comment's
// warning with more moving parts.
//
// Loaded eagerly, WITHOUT `defer`, for the same reason peer-fetch.js is:
// each page's own top-level boot code calls into it while parsing.
(function () {
  'use strict';

  // The one channel (ADR 0013, decision 8) — underscore, matching the WS
  // event name the local page already switches on. The JSON route keeps its
  // hyphen. Two transports of one object, each keeping the naming its own
  // side already uses.
  var CHANNEL = 'validations_tick';

  // Three missed one-second ticks. Past this the stream is treated as down
  // REGARDLESS of whether the socket reported anything — a socket that stops
  // delivering while it stays open is invisible to the server, so this
  // deadline is the whole of the defence and it lives here. The failure it
  // exists to prevent is the one this project keeps re-finding: a perfectly
  // plausible bar sitting frozen on screen while nothing behind it is true.
  var TICK_DEADLINE_MS = 3500;

  // A client that does not see `hello` first treats the connection as
  // failed. This needs its own deadline rather than riding `onopen`, which
  // fires on the 200 headers — before a single event has arrived.
  var HELLO_DEADLINE_MS = 5000;

  var WATCHDOG_MS = 500;

  // EventSource reconnects ITSELF only when a connection it had established
  // drops. An HTTP error response — the aggregator answering 424 for a peer
  // that is momentarily unreachable, or 404 for a peer that has not been
  // upgraded yet — is a FATAL failure by the specification: readyState goes
  // to CLOSED and the browser never tries again. Without this timer a single
  // transient upstream failure would silently downgrade the bar to polling
  // for the rest of the session, which is the "worse and also true" fallback
  // quietly becoming permanent. So a fatal error is retried here, on our own
  // clock, until the operator leaves the peer.
  var FATAL_RETRY_MS = 3000;

  var current = null; // one session object; see open()

  function notifyStatus(sess, connected) {
    if (sess.connected === connected) return;
    sess.connected = connected;
    if (sess.onStatus) {
      try { sess.onStatus(connected); } catch { /* a render error must not kill the stream */ }
    }
  }

  function stop() {
    if (!current) return;
    var sess = current;
    current = null;
    if (sess.watchdog) { clearInterval(sess.watchdog); sess.watchdog = null; }
    if (sess.retryTimer) { clearTimeout(sess.retryTimer); sess.retryTimer = null; }
    if (sess.es) {
      // Order matters: drop the handlers BEFORE close(), so a queued error
      // event from the socket we are abandoning cannot report a status for
      // the peer the operator has already left.
      sess.es.onerror = null;
      sess.es.onopen = null;
      try { sess.es.close(); } catch { /* already closed */ }
      sess.es = null;
    }
    if (sess.connected && sess.onStatus) {
      sess.connected = false;
      try { sess.onStatus(false); } catch { /* ignore */ }
    }
  }

  /**
   * open(label, { onTick, onStatus }) — subscribe to one peer's quorum
   * stream. Closes any stream already open first: a peer flip must never
   * blend two peers' ticks into one bar, which is the same wrong-node
   * rendering the peer view's fetchSeq guard exists to prevent for polls.
   *
   * onTick(body)  — one tick, the FLAT contract shape
   *                 (ValidationsTickResponse minus protocol_version), the
   *                 same object /read/v1/validations-tick serves. Never
   *                 synthesized here: this module relays what the peer
   *                 emitted, does not interpolate a missing tick, and does
   *                 not smooth. If nothing arrives, nothing is painted.
   * onStatus(bool) — "is THIS peer's stream currently connected". False the
   *                 moment the missed-tick deadline passes, so the caller
   *                 can fall visibly back to its 2s poll.
   * onUnsupported(): this peer's transport carries no stream at all (the
   *                 fleet link, #831). Called once; the session stops asking
   *                 and the caller says the view is polled.
   */
  function open(label, handlers) {
    stop();
    if (!label || typeof window.EventSource !== 'function') return false;
    var now = Date.now();
    var sess = {
      label: label,
      es: null,
      watchdog: null,
      retryTimer: null,
      openedAtMs: now,
      lastTickMs: 0,
      sawHello: false,
      connected: false,
      onTick: handlers && handlers.onTick,
      onStatus: handlers && handlers.onStatus,
      onUnsupported: handlers && handlers.onUnsupported,
      unsupported: false,
      probing: false,
      probed: false,
    };
    current = sess;
    if (!connect(sess)) { current = null; return false; }

    sess.watchdog = setInterval(function () {
      if (current !== sess || sess.unsupported) return;
      var t = Date.now();
      if (sess.lastTickMs === 0) {
        if (t - sess.openedAtMs > HELLO_DEADLINE_MS) notifyStatus(sess, false);
        return;
      }
      if (t - sess.lastTickMs > TICK_DEADLINE_MS) notifyStatus(sess, false);
    }, WATCHDOG_MS);

    return true;
  }

  /** Opens (or re-opens) the socket for a session that is already current.
   *  Every handler checks `current !== sess` first: a late event from a
   *  socket belonging to a peer the operator has already left must never
   *  report a status or paint a tick. */
  function connect(sess) {
    var url = streamUrl(sess.label);
    try {
      sess.es = new EventSource(url);
    } catch {
      return false;
    }
    sess.sawHello = false;

    sess.es.addEventListener('hello', function () {
      if (current !== sess) return;
      sess.sawHello = true;
    });

    sess.es.addEventListener(CHANNEL, function (ev) {
      if (current !== sess) return;
      var body;
      try { body = JSON.parse(ev.data); } catch { return; }
      if (!body || typeof body !== 'object') return;
      // A tick that arrives before `hello` is a stream that did not follow
      // the framing; treat the connection as failed rather than trusting a
      // payload from something that isn't the read API.
      if (!sess.sawHello) return;
      sess.lastTickMs = Date.now();
      notifyStatus(sess, true);
      if (sess.onTick) {
        try { sess.onTick(body); } catch { /* a render error must not kill the stream */ }
      }
    });

    // EventSource reconnects on its own schedule; an error is not the end of
    // the subscription, only of this attempt. Report "not connected" and let
    // the caller step back to its poll — the reconnect, when it lands,
    // re-runs the aggregator's pin check and starts ticking again.
    sess.es.onerror = function () {
      if (current !== sess) return;
      sess.sawHello = false;
      notifyStatus(sess, false);
      // CLOSED means the browser has given up on this one for good (an HTTP
      // error response rather than a dropped connection). Re-open on our own
      // clock so a transient upstream failure is a gap, not a permanent
      // downgrade to polling.
      if (sess.es && sess.es.readyState === 2 && !sess.retryTimer) {
        try { sess.es.close(); } catch { /* already closed */ }
        sess.es = null;
        // #831. An EventSource never sees the status it was refused with, so
        // one plain request asks. A node reached over the fleet link answers
        // 501 stream_not_supported by design, and that is a capability, not
        // an outage: retrying it every three seconds for as long as the view
        // is open cost a pin check over the link each time and changed
        // nothing. Stop, and say the view is polled. Anything else is
        // retried exactly as before.
        // Once per session: a refusal that was not the capability the first
        // time is retried on the timer alone, so a peer that keeps failing
        // costs one request per three seconds, as it always has, not two.
        var probe = sess.probed ? Promise.resolve(false) : probeRefusal(sess);
        sess.probed = true;
        sess.probing = true;
        probe.then(function (unsupported) {
          sess.probing = false;
          if (current !== sess) return;
          if (unsupported) {
            sess.unsupported = true;
            if (sess.onUnsupported) {
              try { sess.onUnsupported(); } catch { /* a render error must not kill the session */ }
            }
            return;
          }
          sess.retryTimer = setTimeout(function () {
            sess.retryTimer = null;
            if (current !== sess) return;
            sess.openedAtMs = Date.now();
            sess.lastTickMs = 0;
            connect(sess);
          }, FATAL_RETRY_MS);
        });
      }
    };

    return true;
  }

  /** Was this session's refusal the transport saying it carries no stream?
   *  Resolves true only on the aggregator's own 501 stream_not_supported;
   *  any other answer, or none, is the ordinary retry. The body of a 200
   *  (the stream came back between the error and this probe) is cancelled
   *  at once rather than read. */
  function probeRefusal(sess) {
    if (typeof window.fetch !== 'function') return Promise.resolve(false);
    var ctl = typeof AbortController === 'function' ? new AbortController() : null;
    return window.fetch(streamUrl(sess.label), { credentials: 'same-origin', signal: ctl ? ctl.signal : undefined })
      .then(function (r) {
        if (r.status !== 501) { if (ctl) ctl.abort(); return false; }
        return r.json().then(function (b) { return !!b && b.error === 'stream_not_supported'; },
          function () { return false; });
      }, function () { return false; });
  }

  function streamUrl(label) {
    return '/api/node/' + encodeURIComponent(label) + '/stream?channels=' + encodeURIComponent(CHANNEL);
  }

  function isUnsupported() {
    return !!(current && current.unsupported);
  }

  function isConnected() {
    return !!(current && current.connected);
  }

  function activeLabel() {
    return current ? current.label : null;
  }

  // A closed tab should release the peer's connection slot immediately
  // rather than at the node's lifetime cap.
  window.addEventListener('pagehide', stop);

  window.aperirePeerStream = {
    open: open,
    close: stop,
    isConnected: isConnected,
    isUnsupported: isUnsupported,
    activeLabel: activeLabel,
    CHANNEL: CHANNEL,
    TICK_DEADLINE_MS: TICK_DEADLINE_MS,
  };
})();
