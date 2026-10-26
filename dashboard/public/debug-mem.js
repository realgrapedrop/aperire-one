/* A readout for the one question none of us can answer from here: what does a
 * long session on the operator's iPad actually retain, and how long does the
 * page take to come back after iOS discards the tab?
 *
 * There is no way to take a heap snapshot on an iPad, so this puts the few
 * numbers that would settle it on the glass instead. It is off unless asked
 * for, and when it is off this file installs nothing at all — it reads one
 * URL and one storage key and returns.
 *
 * Turn it on:   https://<dashboard>/?debug=mem      (on for 12h, then it lapses)
 * Turn it off:  https://<dashboard>/?debug=off      (or just wait it out)
 *
 * The flag is kept in localStorage rather than the URL because the tabs are
 * iframes and the shell does not pass its query string down to them. Setting
 * it on the shell turns it on for whichever tab is inside.
 *
 * What it reports, and what each number is for:
 *   nodes     every element in this document. The growth to watch: it should
 *             settle, not climb, over a session of asking questions.
 *   drawer    children of #apDrawer on the Advisor tab. Trimmed to the same
 *             number the conversation keeps, so this should sit at its cap.
 *   listen    event listeners bound since this loaded, less those explicitly
 *             removed. Read it WITH nodes, never on its own: these cards
 *             re-render by rewriting their HTML, which drops the old elements
 *             and their listeners without anyone calling removeEventListener,
 *             so this climbs on a page that is leaking nothing. Measured on
 *             2026-08-25 at about nine per refresh, and a forced collection
 *             showed 663 of 680 of those elements already gone. A climbing
 *             listen with a FLAT nodes and heap is re-render churn; the three
 *             climbing together is the leak.
 *   timers    live intervals and pending timeouts.
 *   heap      used JS heap. Chrome on a desktop only. iOS is WebKit whatever
 *             the browser is called, and WebKit does not expose it, so this
 *             reads n/a there rather than showing a number it invented.
 *   fcp       first contentful paint, from the page's own paint timing. This
 *             is the number that says whether a slow return was a white page
 *             or a painted one waiting on its reads.
 *   reads     requests since this file loaded: total, in flight, failed.
 *   cycle     the Advisor tab's own last refresh timings (window.__apTimings)
 *             — status, checks, total, and the note when a cycle gave up.
 *
 * Tap the badge for the detail: the boot requests in the order they were made,
 * with the slowest first.
 */
(function () {
  'use strict';

  var KEY = 'aperire.debug';
  // A debug session is bounded, not permanent. Turning it on stores an expiry
  // rather than a sticky flag, so it lapses on its own instead of following the
  // origin around for weeks — which is how it turned up unasked-for on prod.
  // Default is off: a fresh load with no live window, and any legacy or expired
  // value, reads as off and is cleared. Re-arm it any time from the URL.
  var TTL_MS = 12 * 3600 * 1000;
  var want = /[?&#]debug=(mem|off)\b/.exec(location.href);
  var store;
  try { store = window.localStorage; } catch { store = null; }

  if (want && store) {
    try {
      if (want[1] === 'off') store.removeItem(KEY);
      else store.setItem(KEY, String(Date.now() + TTL_MS));
    } catch { /* private mode; the URL still governs this one load */ }
  }
  var on = (want && want[1] === 'mem');
  // The host can turn it on for every page it serves (APERIRE_CLIENT_DEBUG=mem
  // stamps this tag into the head): the device then has nothing to type.
  var meta = document.querySelector('meta[name="aperire-debug"]');
  if (meta && meta.getAttribute('content') === 'mem') on = true;
  if (!on && store) {
    try {
      var exp = parseInt(store.getItem(KEY) || '', 10);
      on = Number.isFinite(exp) && exp > Date.now();
      // Drop an expired window, or a legacy 'mem' value from before this was
      // time-boxed, so neither can hold the readout on past its welcome.
      if (!on && store.getItem(KEY) !== null) store.removeItem(KEY);
    } catch { on = false; }
  }
  if (!on) return;                       // nothing wrapped, nothing rendered

  // ── counters ────────────────────────────────────────────────────────────
  // Everything below only exists in debug mode. The wrappers delegate and
  // never swallow: a readout that changed the behaviour it is measuring would
  // be worse than no readout.
  var live = { intervals: 0, timeouts: 0, listeners: 0 };
  var reads = { total: 0, inflight: 0, failed: 0, firstOkMs: null };

  var setI = window.setInterval, clrI = window.clearInterval;
  var setT = window.setTimeout, clrT = window.clearTimeout;
  var known = Object.create(null);
  window.setInterval = function () {
    var id = setI.apply(window, arguments);
    if (!known['i' + id]) { known['i' + id] = 1; live.intervals++; }
    return id;
  };
  window.clearInterval = function (id) {
    if (known['i' + id]) { delete known['i' + id]; live.intervals--; }
    return clrI.apply(window, arguments);
  };
  window.setTimeout = function () {
    var args = Array.prototype.slice.call(arguments);
    var fn = args[0];
    var id;
    if (typeof fn === 'function') {
      args[0] = function () {
        if (known['t' + id]) { delete known['t' + id]; live.timeouts--; }
        return fn.apply(this, arguments);
      };
    }
    id = setT.apply(window, args);
    if (typeof fn === 'function') { known['t' + id] = 1; live.timeouts++; }
    return id;
  };
  window.clearTimeout = function (id) {
    if (known['t' + id]) { delete known['t' + id]; live.timeouts--; }
    return clrT.apply(window, arguments);
  };

  var addL = EventTarget.prototype.addEventListener;
  var remL = EventTarget.prototype.removeEventListener;
  EventTarget.prototype.addEventListener = function () {
    live.listeners++;
    return addL.apply(this, arguments);
  };
  EventTarget.prototype.removeEventListener = function () {
    live.listeners--;
    return remL.apply(this, arguments);
  };

  // This file is deferred, so the page's own boot requests were already made
  // by the time it runs. Those come from resource timing below; this counts
  // everything from here on, which is the part that matters for a long
  // session and for the recovery reads after a tab returns.
  var rawFetch = window.fetch;
  if (typeof rawFetch === 'function') {
    window.fetch = function () {
      reads.total++; reads.inflight++;
      return rawFetch.apply(window, arguments).then(function (r) {
        reads.inflight--;
        if (r && r.ok && reads.firstOkMs === null) reads.firstOkMs = Math.round(performance.now());
        else if (r && !r.ok) reads.failed++;
        return r;
      }, function (e) {
        reads.inflight--; reads.failed++;
        throw e;
      });
    };
  }

  // ── what the page itself already records ────────────────────────────────
  function paintMs() {
    try {
      var p = performance.getEntriesByType('paint');
      for (var i = 0; i < p.length; i++) {
        if (p[i].name === 'first-contentful-paint') return Math.round(p[i].startTime);
      }
    } catch { /* not every engine has paint timing */ }
    return null;
  }
  function heapMB() {
    var m = performance.memory;
    if (!m || typeof m.usedJSHeapSize !== 'number') return null;
    return Math.round(m.usedJSHeapSize / 1048576);
  }
  function bootRequests() {
    var out = [];
    try {
      var rs = performance.getEntriesByType('resource');
      for (var i = 0; i < rs.length; i++) {
        var r = rs[i];
        if (r.initiatorType !== 'fetch' && r.initiatorType !== 'xmlhttprequest') continue;
        out.push({
          name: String(r.name).replace(/^https?:\/\/[^/]+/, ''),
          at: Math.round(r.startTime),
          ms: Math.round(r.duration),
          status: (typeof r.responseStatus === 'number') ? r.responseStatus : null,
        });
      }
    } catch { /* no resource timing, no boot list */ }
    out.sort(function (a, b) { return b.ms - a.ms; });
    return out;
  }
  function lastCycle() {
    var t = window.__apTimings;
    if (!t || !t.length) return null;
    return t[t.length - 1];
  }

  // ── the badge ───────────────────────────────────────────────────────────
  var where = (location.pathname.replace(/^\/|\.html$/g, '') || 'shell');

  // ── The page reporting on itself (#259) ──────────────────────────────
  // An iPad came back to a blank Advisor tab with its spinner turning, and
  // the aggregator's page log showed no reload had been asked for: whatever happened,
  // happened inside a document that was never re-fetched. A readout on the
  // glass cannot say anything about a blank page, so while this flag is on
  // the page also sends one small beat to its own dashboard on every
  // lifecycle event (hidden, shown, pageshow with its persisted bit, pagehide,
  // freeze, resume), on every uncaught error, and every 5s while visible,
  // carrying the numbers above. Read them beside the [page] lines in the
  // dashboard's log. sendBeacon so a beat leaves even as the page goes.
  function beat(ev, detail) {
    var d = detail || '';
    try {
      d += (d ? ' ' : '') + 'nodes=' + document.getElementsByTagName('*').length +
        ' listeners=' + live.listeners + ' intervals=' + live.intervals + ' timeouts=' + live.timeouts +
        ' inflight=' + reads.inflight + ' failed=' + reads.failed + ' hidden=' + (document.hidden ? 1 : 0) +
        ' vis=' + document.visibilityState + ' w=' + window.innerWidth + 'x' + window.innerHeight;
    } catch { /* the numbers are a courtesy */ }
    var body = JSON.stringify({ page: where, ev: ev, detail: d });
    try {
      if (navigator.sendBeacon) {
        var blob = new Blob([body], { type: 'application/json' });
        if (navigator.sendBeacon('/api/client-beat', blob)) return;
      }
    } catch { /* fall through to fetch */ }
    try {
      rawFetch.call(window, '/api/client-beat', { method: 'POST', credentials: 'include', keepalive: true,
        headers: { 'content-type': 'application/json' }, body: body });
    } catch { /* nothing more to try */ }
  }
  beat('load', 'href=' + location.href.slice(0, 120));
  document.addEventListener('visibilitychange', function () { beat(document.hidden ? 'hidden' : 'shown'); });
  window.addEventListener('pageshow', function (e) { beat('pageshow', 'persisted=' + (e && e.persisted ? 1 : 0)); });
  window.addEventListener('pagehide', function (e) { beat('pagehide', 'persisted=' + (e && e.persisted ? 1 : 0)); });
  document.addEventListener('freeze', function () { beat('freeze'); });
  document.addEventListener('resume', function () { beat('resume'); });
  window.addEventListener('error', function (e) { beat('error', String(e && e.message || e).slice(0, 100)); });
  window.addEventListener('unhandledrejection', function (e) { beat('rejection', String(e && e.reason || '').slice(0, 100)); });
  setInterval(function () { if (!document.hidden) beat('alive'); }, 5000);
  var el = document.createElement('div');
  el.id = 'apDebugMem';
  el.setAttribute('role', 'status');
  el.style.cssText = [
    'position:fixed', 'left:6px', 'bottom:6px', 'z-index:2147483647',
    'max-width:min(92vw,520px)', 'max-height:60vh', 'overflow:auto',
    'font:11px/1.45 ui-monospace,SFMono-Regular,Menlo,monospace',
    'background:rgba(8,12,20,.92)', 'color:#cfe4ff',
    'border:1px solid rgba(120,170,255,.45)', 'border-radius:6px',
    'padding:5px 7px', 'white-space:pre-wrap', 'cursor:pointer',
    '-webkit-user-select:text', 'user-select:text',
  ].join(';');
  var expanded = false;
  el.addEventListener('click', function () { expanded = !expanded; paint(); });

  function line() {
    var h = heapMB();
    var drawer = document.getElementById('apDrawer');
    var c = lastCycle();
    var bits = [
      where,
      'nodes ' + document.getElementsByTagName('*').length,
      drawer ? 'drawer ' + drawer.children.length : null,
      'listen ' + live.listeners,
      'timers ' + (live.intervals + live.timeouts),
      'heap ' + (h === null ? 'n/a' : h + 'MB'),
      'fcp ' + (paintMs() === null ? 'n/a' : paintMs() + 'ms'),
      'reads ' + reads.total + '/' + reads.inflight + 'f' + reads.failed,
      c ? 'cycle ' + (c.total == null ? (c.status == null ? '…' : c.status + 'ms?') : c.total + 'ms') : null,
    ];
    var s = [];
    for (var i = 0; i < bits.length; i++) if (bits[i]) s.push(bits[i]);
    return s.join('  ');
  }

  function detail() {
    var out = ['', '── slowest requests (all, since load) ──'];
    var b = bootRequests();
    if (!b.length) out.push('(no resource timing for fetches)');
    for (var i = 0; i < b.length && i < 8; i++) {
      out.push(String(b[i].ms).padStart(6) + 'ms  @' + String(b[i].at).padStart(6) + 'ms  ' +
        (b[i].status === null ? '' : b[i].status + ' ') + b[i].name);
    }
    out.push('', '── first ok read ' +
      (reads.firstOkMs === null ? 'not yet (since this readout loaded)' : reads.firstOkMs + 'ms') + ' ──');
    var t = window.__apTimings;
    if (t && t.length) {
      out.push('', '── last ' + Math.min(6, t.length) + ' refresh cycles ──');
      for (var k = Math.max(0, t.length - 6); k < t.length; k++) {
        var m = t[k];
        out.push((m.at || '').slice(11, 19) + '  status ' + (m.status == null ? '-' : m.status) +
          '  checks ' + (m.checks == null ? '-' : m.checks) +
          '  total ' + (m.total == null ? '-' : m.total) +
          (m.note ? '  ' + m.note : ''));
      }
    }
    out.push('', 'listen climbs on every re-render even when nothing leaks —',
      'the retainer is nodes and heap climbing WITH it.',
      '', 'tap to collapse · /?debug=off to switch this off');
    return out.join('\n');
  }

  function paint() { el.textContent = line() + (expanded ? '\n' + detail() : ''); }

  function mount() {
    if (document.body && !el.parentNode) document.body.appendChild(el);
    paint();
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', mount);
  } else { mount(); }
  // A deferred script runs before the browser has painted, so the first
  // reading has no first-contentful-paint to report and would say n/a about a
  // page that painted a moment later. One early repaint gets the number that
  // matters most here right, well before the two-second cycle would.
  setT(paint, 1200);
  // Two seconds, not one: this is a readout, not a clock, and it must not be
  // the thing that makes the page it is measuring look busy.
  setI(function () { if (!document.hidden) paint(); }, 2000);

  // For a walk or a console, the same numbers without reading the badge.
  window.__apDebugMem = function () {
    return {
      where: where,
      nodes: document.getElementsByTagName('*').length,
      drawer: (document.getElementById('apDrawer') || { children: [] }).children.length,
      listeners: live.listeners,
      intervals: live.intervals,
      timeouts: live.timeouts,
      heapMB: heapMB(),
      fcpMs: paintMs(),
      reads: { total: reads.total, inflight: reads.inflight, failed: reads.failed, firstOkMs: reads.firstOkMs },
      requests: bootRequests(),
      cycle: lastCycle(),
    };
  };
})();
