// Add a node, inside Settings & Updates (#585, restepped by #607).
//
// This is setup.html's steps 2 to 5, carried over rather than rewritten: the
// same three choice cards, the same relay commands, the same "what this box
// reports" verdicts, the same watch for the relay's first frame, the same
// Advisor step. setup.html walked those behind a Continue button because a
// box with no operator had nothing else to show; here they sit inside one
// <details>, one step open at a time, each step opening only from the one
// above it (the operator's ruling, 2026-09-22, on the add-a-node mockup).
//
// What a step being "done" means, and it differs by what the page can
// actually know:
//   Step 1 (where)   -- known the instant a card is clicked.
//   Step 2 (the line) -- the page cannot know whether the line was run on
//     the other box, only that it handed the line over. So "done" here is
//     an honest affordance ("I have this") rather than a claim of
//     execution, except on the fleet path, where the question IS something
//     the operator can answer outright: is Aperire on that box already?
//   Step 3 (the proof) -- for local/remote, the watch's own "first frame
//     seen" is a fact the page observed, so THAT is what unlocks step 4.
//     For the fleet path it is the aggregator's pairing fingerprint: one
//     readiness question to this host as the step opens, a command for root
//     to run here, and an honest "I have it" (the page cannot know the line
//     ran, and it never shows the value itself).
//   Step 4 -- the Advisor, optional, for local/remote. For the fleet path it
//     is Pair it, the last step: minting, the code, the countdown and the
//     approval all live here now, and nowhere else. Every path is four steps.
//
// The fleet path does not re-implement pairing. Fleet registry list, below
// this section, still owns the mint route, the ceremony and the poll
// (settings.html: pairMint/pairApprove/pairRefuse/renderPending); this file
// only shows the SAME controls, moved into step 3, and settings.html paints
// step 3's own copy of the pending rows and the waiting countdown
// (renderStepPending/renderMintWait) off the same OV.pending this file is
// handed on every poll.
//
// Loaded by settings.html (defer), after model-form.js (loaded eagerly,
// settings.html:23) and before the page's own inline script runs its gate.
// window.ApAddNode.init(ov) is called once that gate says admin, and again
// on every ten-second poll: ov is the SAME object settings.html's own
// load()/refresh() already read from /api/settings/overview, never a second
// fetch of this file's own. "One read builds the page" is a real assertion
// in tools/settings-walk.mjs, and duplicating that read here would break it
// for a reason that would look unrelated to whoever broke it next.
// openAndScroll(ov) is what the #add-node deep link and the closed-window
// setup.html redirect both land on.
(function () {
  'use strict';

  var $ = function (id) { return document.getElementById(id); };

  function esc(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  function postJson(url, body) {
    return fetch(url, {
      method: 'POST', credentials: 'same-origin', cache: 'no-store',
      headers: { 'content-type': 'application/json', 'x-aperire-csrf': '1' },
      body: JSON.stringify(body || {}),
    }).then(function (r) {
      return r.json().then(
        function (b) { return { status: r.status, ok: r.ok, body: b }; },
        function () { return { status: r.status, ok: r.ok, body: null }; });
    });
  }

  function getJson(url) {
    return fetch(url, { credentials: 'same-origin', cache: 'no-store' }).then(function (r) {
      return r.json().then(
        function (b) { return { status: r.status, ok: r.ok, body: b }; },
        function () { return { status: r.status, ok: r.ok, body: null }; });
    });
  }

  // model-form.js is loaded synchronously before this file (settings.html:23),
  // never lazily like setup.html had to (that page is served before sign-in,
  // and the file sits behind the auth gate). So this always has the shared
  // command block, with the copy button the rest of the product uses.
  function cmdInto(el, text) {
    if (!el) return;
    if (window.ApModelForm && window.ApModelForm.cmdHtml) {
      el.innerHTML = window.ApModelForm.cmdHtml(text);
      if (window.ApModelForm.wireCopyButtons) window.ApModelForm.wireCopyButtons();
      return;
    }
    el.innerHTML = '<pre class="ap-cmd"><code>' + esc(text) + '</code></pre>';
  }

  // Verdict rows, setup.html's pattern: every wait names the step it is on,
  // never a bare spinner. Classes are an- prefixed because this page already
  // owns .verdict as a one-line status pill (Pair a node, Push trust, the
  // model seal) and a plain .verdict here would have quietly relayouted all
  // four of those.
  function verdicts(el) {
    if (!el) return { set: function () {}, add: function () {}, clear: function () {} };
    function row(kind, text, why) {
      var mark = kind === 'ok' ? '✓' : kind === 'warn' ? '▲' : kind === 'bad' ? '✕' : '·';
      return '<div class="an-verdict an-v-' + kind + '"><span class="an-dot">' + mark + '</span><span>'
        + esc(text) + (why ? '<span class="an-why"> (' + esc(why) + ')</span>' : '') + '</span></div>';
    }
    return {
      clear: function () { el.innerHTML = ''; },
      set: function (kind, text, why) { el.innerHTML = row(kind, text, why); },
      add: function (kind, text, why) { el.insertAdjacentHTML('beforeend', row(kind, text, why)); },
    };
  }

  // ── What this box actually reports ───────────────────────────────
  //
  // The relay's own verdict is read fresh, every time: /healthz is the one
  // honest test of whether a frame arrived, and a stale answer here is
  // exactly the "kept versus observed" bug this product watches for
  // everywhere else.
  //
  // this_dashboard's other facts (the install dir, the ingest URL, the
  // Advisor's presence, the fleet-aggregator install line) are NOT re-fetched
  // here. settings.html already reads /api/settings/overview once to build
  // the whole page and polls it every ten seconds; a second independent read
  // from this file would be the same route hit twice for one page view,
  // which is the thing "one read builds the page" (settings-walk.mjs) exists
  // to catch. setSharedOverview() below is how settings.html hands this file
  // the same object its own render functions already use, on load and on
  // every poll.
  var RELAY_FRESH_MS = 60000;   // rules.yaml calls relay_feed_age_s >= 60 critical
  var OVERVIEW = null;
  function setSharedOverview(ov) {
    OVERVIEW = ov || null;
    // Nothing is painted from this on its own: a poll landing while the
    // operator has not chosen a card yet has nothing to repaint. But if
    // they have, what this file draws from OVERVIEW stays live across the
    // ten-second poll rather than freezing at whatever it read on the click.
    if (WHERE) {
      paintAdvisor();
      if (WHERE === 'remote') paintMed07();
      if (WHERE === 'fleet') { paintFleetInstallLine(); paintFleetReach(); paintFpHost(); }
    }
  }

  function readHealth() {
    return getJson('/healthz').then(function (r) {
      var h = r.body;
      if (!h || typeof h !== 'object') return null;
      var age = typeof h.relay_last_push_ms === 'number' ? h.relay_last_push_ms : null;
      var at = typeof h.relay_last_push_at === 'number' ? h.relay_last_push_at : null;
      var label = typeof h.relay_label === 'string' ? h.relay_label : null;
      return {
        raw: h,
        relayAgeMs: age,
        relayAt: at,
        relayLabel: label,
        relayLive: age !== null && age >= 0 && age < RELAY_FRESH_MS,
        nodeConnected: h.rippled_connected === true,
        role: typeof h.role === 'string' ? h.role : null,
      };
    }, function () { return null; });
  }

  function ago(ms) {
    if (typeof ms !== 'number' || ms < 0) return 'a moment ago';
    if (ms < 1000) return 'just now';
    if (ms < 60000) return Math.round(ms / 1000) + 's ago';
    var mins = Math.round(ms / 60000);
    if (ms < 3600000) return mins + (mins === 1 ? ' minute ago' : ' minutes ago');
    var hours = Math.round(ms / 3600000);
    return hours + (hours === 1 ? ' hour ago' : ' hours ago');
  }

  function installDir() {
    var t = OVERVIEW && OVERVIEW.this_dashboard;
    return (t && typeof t.install_dir === 'string' && t.install_dir) || '<install-dir>';
  }

  // ── Step 1's done row: the traffic diagram for the chosen path (#621) ──
  //
  // Every port and direction here was read off the code, not the mockup's
  // own drawing, and the mockup's own picture of local/remote turned out to
  // be missing a whole hop: this dashboard's own bridge (server.ts's
  // RIPPLED_URL, ws://127.0.0.1:6006 by default) dials the node's admin
  // WebSocket DIRECTLY, for the ledger/consensus data the relay cannot read
  // (the relay reads /proc, never rippled itself -- relay/collectors.go's
  // "connections on 6006" is a LOCAL /proc/net/tcp count on the node's own
  // host, never a dial out to it). docs/DEPLOYMENT-GUIDE.md's
  // "Wiring each shape" confirms both defaults (co-located: 127.0.0.1:6006)
  // and the split shape's own three edits (the validator opens 6006 to the
  // dashboard host's address ALONE, and the dashboard's RIPPLED_URL is
  // pointed at it) -- so on the remote path this dashboard genuinely does
  // reach into the node's host, on a port scoped to this dashboard's own
  // address, and the diagram says so rather than the mockup's "nothing
  // reaches into the node's host." The relay's own hop, pushing to this
  // dashboard over a WebSocket (relay/pusher.go dials cfg.DashboardURL,
  // wss:// remote / ws://127.0.0.1:7800 co-located), is unaffected and
  // still reads its own scheme off relay_ingest_url rather than a fixed
  // "HTTPS" label. The fleet link's own shape (wss, node dials out) comes
  // straight off dashboard/types/fleet-link-contract.ts's own comment; its
  // port is this aggregator's own, the same one the checklist below reads.
  //
  // 6006 and 7800 above are the DEFAULTS, not facts this page has about the
  // real host: a node on 6005, or a second instance on a non-default
  // dashboard port, would make a hard-coded number in the diagram wrong,
  // and nothing in OVERVIEW or /healthz carries either port today. So the
  // local/remote diagrams print neutral labels ("this dashboard's port",
  // "the node's admin WS") rather than a guessed digit; only the fleet
  // diagram's port is a real read (fleetAggregatorPort(), below), because
  // that one field actually exists.
  function remoteScheme() {
    var t = OVERVIEW && OVERVIEW.this_dashboard;
    var url = (t && typeof t.relay_ingest_url === 'string' && t.relay_ingest_url) || '';
    return /^ws:\/\//i.test(url) ? 'ws' : 'wss';
  }

  // ── This aggregator's own URL and port, off install_join_command ──
  //
  // Read off install_join_command, which settings-api.ts already built off
  // this host's own validated public_url (aggregatorOrigin(), the same rule
  // the mint command uses) -- never location.origin, which is the tunnel or
  // loopback address THIS browser happens to be using, not the address the
  // node's box would dial. Shared by the fleet diagram's port and the
  // fleet checklist's reach line, so the two can never disagree.
  function fleetAggregatorUrl() {
    var line = OVERVIEW && OVERVIEW.this_dashboard && OVERVIEW.this_dashboard.install_join_command;
    var m = typeof line === 'string' ? line.match(/--fleet-aggregator\s+(\S+)/) : null;
    return m ? m[1] : null;
  }

  function fleetAggregatorPort() {
    var url = fleetAggregatorUrl();
    if (!url || url === '<this-aggregator-url>') return '443';
    try {
      var u = new URL(url);
      return u.port || (u.protocol === 'http:' ? '80' : '443');
    } catch { return '443'; }
  }

  // Whether the remote diagram's second line (and the matching checklist
  // item) should show at all. server.ts holds exactly ONE admin bridge
  // (RIPPLED_URL, server.ts:4763): a dashboard that already reads a node
  // of its own through it never redirects that single connection to a
  // node freshly added by relay, so telling the operator to open THIS
  // node's admin port to this dashboard would be advice for a hop that
  // never happens -- an unneeded exposure, not a useful one. null (not
  // read yet) reads as "don't show it" until readHealth() says otherwise,
  // the safe default: never advise opening a port before the page actually
  // knows the hop would be used.
  var REMOTE_HAS_OWN_NODE = null;

  function paintShape(which) {
    var el = $('anStep1Shape');
    if (!el) return;
    if (which === 'local') {
      el.innerHTML =
        '<span class="an-dim">this machine</span>\n'
        + '[ Aperire ]  <span class="an-arrow">&lt;-- loopback, this dashboard’s port --</span>  [ relay ]\n'
        + '[ Aperire ]  <span class="an-arrow">-- loopback, the node’s admin WS --&gt;</span>  [ node ]\n'
        + '<span class="an-dim">             everything stays on loopback; no port opens to the network</span>';
    } else if (which === 'remote') {
      var showAdmin = REMOTE_HAS_OWN_NODE === false;
      var header = '<span class="an-dim">this dashboard                                 the node’s host</span>\n';
      var pushLine = '[ Aperire ]  <span class="an-arrow">&lt;===  ' + esc(remoteScheme())
        + ' push to this URL, with a token  ===</span>  [ relay ]\n';
      var adminLine = showAdmin
        ? '[ Aperire ]  <span class="an-arrow">===  admin WS, opened to this dashboard alone  ===&gt;</span>  [ node ]\n'
        : '';
      var note = showAdmin
        ? 'the relay pushes out; the admin link reaches in, scoped to this dashboard’s address'
        : 'the relay pushes out; nothing reaches into the node’s host';
      el.innerHTML = header + pushLine + adminLine + '<span class="an-dim">             ' + esc(note) + '</span>';
    } else {
      el.innerHTML =
        '<span class="an-dim">this dashboard (aggregator)                    the node’s box</span>\n'
        + '[ Aperire ]  <span class="an-arrow">&lt;=====  wss, port ' + esc(fleetAggregatorPort())
        + ', node dials out  =====</span>  [ Aperire + node ]\n'
        + '<span class="an-dim">             the link carries readings and signed jobs; nothing dials into the node’s box</span>';
    }
  }

  function paintFleetReach() {
    var el = $('anFleetReachItem');
    if (!el) return;
    var url = fleetAggregatorUrl();
    var port = fleetAggregatorPort();
    if (!url || url === '<this-aggregator-url>') {
      el.innerHTML = 'That box can reach <b>this dashboard’s public URL</b> on port <b>' + esc(port) + '</b> (outbound only).';
      return;
    }
    el.innerHTML = 'That box can reach <b>' + esc(url) + '</b> on port <b>' + esc(port) + '</b> (outbound only).';
  }

  // ── The stepped fold (#607) ─────────────────────────────────────────
  //
  // One step open at a time. paintStep(n, state, opts) is the one place
  // that touches a step's chrome: which of Done/Body it shows, whether its
  // body's own content is laid out, and the two words beside its number
  // (the eyebrow's "Step n of N" and the state word under it -- "done" for a
  // folded step, the path itself while a step is open, "not yet" while it
  // is locked, "optional" for step 4 always).
  var WHERE = null;      // 'local' | 'remote' | 'fleet'
  var STEP2_DONE = false;
  var STEP3_DONE = false;
  // The fleet path's step 4 (Pair it) folds once a node has registered.
  var STEP4_DONE = false;
  var CHOICES = { local: $('anChLocal'), remote: $('anChRemote'), fleet: $('anChFleet') };

  function paintStep(n, state, opts) {
    opts = opts || {};
    var row = $('anStep' + n + 'Row');
    if (!row) return;
    row.classList.remove('an-now', 'an-done', 'an-later');
    row.classList.add('an-' + state);
    var doneEl = $('anStep' + n + 'Done');
    var bodyEl = $('anStep' + n + 'Body');
    var contentEl = $('anStep' + n + 'Content');
    var stateEl = $('anStep' + n + 'State');
    if (state === 'done') {
      if (doneEl) doneEl.hidden = false;
      if (bodyEl) bodyEl.hidden = true;
      if (opts.picked != null && $('anStep' + n + 'Picked')) $('anStep' + n + 'Picked').textContent = opts.picked;
    } else {
      if (doneEl) doneEl.hidden = true;
      if (bodyEl) bodyEl.hidden = false;
      if (contentEl) contentEl.hidden = state !== 'now';
    }
    if (stateEl && opts.word !== undefined) stateEl.textContent = opts.word;
  }

  // Four on every path: the fleet path's own steps 3 and 4 are the
  // fingerprint and Pair it.
  function totalSteps() { return 4; }

  function paintTotals() {
    var t = String(totalSteps());
    ['anStep1Total', 'anStep2Total', 'anStep3Total', 'anStep4Total'].forEach(function (id) {
      if ($(id)) $(id).textContent = t;
    });
  }

  function pickedLabelFor(which) {
    return which === 'local' ? 'On this box'
      : which === 'remote' ? 'On another box'
      : 'It already runs Aperire';
  }

  // ── Step 1: where the node runs ──────────────────────────────────

  // #629/#630 review: settings.html's own pairing-step state (which "done"
  // row, if any, is this step's own; the plaintext command and verdict its
  // last mint printed) has to be forgotten the moment a fresh pick starts
  // here, or a row still lingering server side from an EARLIER pairing on
  // this same card could be matched again and fold step 3 under a node
  // nobody has paired yet, and that earlier node's own command or "Paired"
  // line could still be sitting in the DOM under it. That state lives in a
  // different file's closure, so it is forgotten through the one hook it
  // exports rather than reached into directly.
  function forgetPairMint() {
    if (window.ApSettingsPair && window.ApSettingsPair.forgetPairStep) {
      window.ApSettingsPair.forgetPairStep();
    }
  }

  function choose(which) {
    WHERE = which;
    STEP2_DONE = false;
    STEP3_DONE = false;
    STEP4_DONE = false;
    stopWatching();
    forgetPairMint();
    resetFleetFold();
    resetFp();
    Object.keys(CHOICES).forEach(function (k) {
      if (CHOICES[k]) CHOICES[k].setAttribute('aria-pressed', String(k === which));
    });
    $('anWhereMsg').textContent = '';

    paintTotals();
    paintStep(1, 'done', { picked: pickedLabelFor(which), word: 'done' });
    paintShape(which);

    // Step 2: painted for the path just picked, opened.
    $('anPaneLocal').hidden = which !== 'local';
    $('anPaneRemote').hidden = which !== 'remote';
    $('anPaneFleet').hidden = which !== 'fleet';
    $('anFleetInstallLine').hidden = true;
    $('anStep2Title').textContent = which === 'fleet' ? 'Is Aperire installed on that box?' : 'The command to run.';
    // Local and remote both end on the same "I have this" affordance; the
    // fleet path's own Yes/No buttons complete step 2 instead, so that row
    // stays hidden there.
    $('anStep2DoneRow').hidden = which === 'fleet';
    // #686. Step 2's state slot used to carry the CHOICE, where steps 1, 3
    // and 4 all carry a state word. The fleet path read "it already runs
    // aperire", wrapped onto two lines and repeated the folded step 1 line
    // one row above it, which is what was reported. The other two had the
    // same shape in miniature: pickedLabelFor() folds step 1 to "On this
    // box" and "On another box", so "on this box" underneath it was the
    // same repetition, just short enough not to be noticed. All three read
    // `now`, which is what the approved #607 mockup shows in that slot.
    paintStep(2, 'now', { word: 'now' });

    // Steps 3 and 4: which pane each holds is decided now, so it is correct
    // the moment the step opens.
    $('anStep3Title').textContent = which === 'fleet'
      ? 'Get this aggregator\u2019s pairing fingerprint.' : 'Test the link.';
    $('anPaneWatch').hidden = which === 'fleet';
    $('anPaneFp').hidden = which !== 'fleet';
    $('anWatchVerdicts').innerHTML = '';
    $('anWatchBtn').disabled = false;
    $('anWatchBtn').textContent = 'Test the link';
    paintStep(3, 'later', { word: 'not yet' });
    if ($('anStep3Change')) $('anStep3Change').hidden = false;

    $('anStep4Title').textContent = which === 'fleet' ? 'Pair it.' : 'The Advisor is optional.';
    $('anAdvisorPane').hidden = which === 'fleet';
    $('anPanePair').hidden = which !== 'fleet';
    paintStep(4, 'later', { word: which === 'fleet' ? 'not yet' : 'optional' });

    if (which === 'local') paintLocal();
    if (which === 'remote') { paintRemote(); paintMed07(); }
    if (which === 'fleet') { paintFleetInstallLine(); paintFleetReach(); }
  }
  Object.keys(CHOICES).forEach(function (k) {
    if (!CHOICES[k]) return;
    CHOICES[k].addEventListener('click', function () { choose(k); });
  });

  // "change" on a done step reopens it and locks everything below it again
  // (the operator's ruling): the step above decides the ones after it, so
  // reopening step 1 clears the whole path, and reopening step 2 only
  // re-locks step 3 (and 4, off the fleet path).
  function reopenStep1() {
    WHERE = null;
    STEP2_DONE = false;
    STEP3_DONE = false;
    STEP4_DONE = false;
    stopWatching();
    forgetPairMint();
    resetFp();
    Object.keys(CHOICES).forEach(function (k) {
      if (CHOICES[k]) CHOICES[k].setAttribute('aria-pressed', 'false');
    });
    paintTotals();
    paintStep(1, 'now', { word: 'now' });
    // Locked titles fall back to their defaults: with WHERE cleared, a path
    // chosen before "change" was clicked must not leave its own wording
    // sitting on a step nothing has picked any more.
    $('anStep2Title').textContent = 'The command to run.';
    $('anStep3Title').textContent = 'Test the link.';
    $('anStep4Title').textContent = 'The Advisor is optional.';
    paintStep(2, 'later', { word: 'not yet' });
    paintStep(3, 'later', { word: 'not yet' });
    paintStep(4, 'later', { word: 'optional' });
    if ($('anStep3Change')) $('anStep3Change').hidden = false;
    // #630 review: a fold this step reopens past is gone, and so is
    // whatever it said -- a fleet pairing's own row note (arm-closed,
    // a failed trust push) must not still be sitting under whichever
    // path is picked next.
    resetFleetFold();
  }

  // Step 4's folded Paired card, emptied: its note, its optional next step
  // and its actions. A fold this card moves past, or a fresh pick on it,
  // must not leave an earlier pairing's words under a path that never
  // wrote them.
  function resetFleetFold() {
    if ($('anStep4PairedNote')) $('anStep4PairedNote').textContent = '';
    if ($('anStep4PairedActions')) $('anStep4PairedActions').hidden = true;
    clearPairedNext();
  }

  // #635: the Paired card's own optional next step (today, only arm-closed)
  // has to go dark everywhere the plain note above it already does -- a
  // fold this step reopens past, or a fresh pick on the same card, must not
  // leave an earlier pairing's command sitting in the copy box under a path
  // that never wrote one.
  function clearPairedNext() {
    var nextBox = $('anStep4PairedNext');
    if (nextBox) nextBox.hidden = true;
    if ($('anStep4PairedNextSentence')) $('anStep4PairedNextSentence').textContent = '';
    if ($('anStep4PairedNextCmd')) $('anStep4PairedNextCmd').innerHTML = '';
  }
  if ($('anStep1Change')) $('anStep1Change').addEventListener('click', reopenStep1);

  function reopenStep2() {
    STEP2_DONE = false;
    STEP3_DONE = false;
    STEP4_DONE = false;
    stopWatching();
    forgetPairMint();
    resetFleetFold();
    resetFp();
    paintStep(2, 'now', { word: 'now' });
    paintStep(3, 'later', { word: 'not yet' });
    if ($('anStep3Change')) $('anStep3Change').hidden = false;
    paintStep(4, 'later', { word: WHERE === 'fleet' ? 'not yet' : 'optional' });
  }
  if ($('anStep2Change')) $('anStep2Change').addEventListener('click', reopenStep2);

  // Local/remote reopen the watch. The fleet path reopens the fingerprint
  // step, and asks this host its readiness question again, because
  // opening the step is what asks it. Once a node has paired there is
  // nothing to reopen into: the code is spent.
  function reopenStep3() {
    if (!STEP3_DONE || STEP4_DONE) return;
    STEP3_DONE = false;
    if (WHERE === 'fleet') {
      forgetPairMint();
      paintStep(3, 'now', { word: 'fingerprint' });
      paintStep(4, 'later', { word: 'not yet' });
      paintFpHost();
      fpEnter();
      return;
    }
    paintStep(3, 'now', { word: 'test' });
    paintStep(4, 'later', { word: 'optional' });
  }
  if ($('anStep3Change')) $('anStep3Change').addEventListener('click', reopenStep3);

  // ── Step 2: the path's own content ───────────────────────────────

  function paintLocal() {
    var v = verdicts($('anLocalVerdicts'));
    v.set('wait', 'Reading what this box reports...');
    readHealth().then(function (h) {
      if (!h) {
        v.set('bad', 'This dashboard did not answer its own health check',
          'so nothing here can be said about the relay yet');
        $('anLocalFix').hidden = true;
        return;
      }
      if (h.relayLive) {
        v.set('ok', 'A relay on this box is pushing', 'last frame ' + ago(h.relayAgeMs));
        if (h.nodeConnected) {
          v.add('ok', 'The node on this box is connected and reporting', 'nothing to register');
        } else if (h.role === 'aggregator' || h.role === 'dashboard') {
          v.add('warn', 'This box has no node of its own', 'it reads other nodes, so register one below');
        } else {
          v.add('warn', 'The node on this box is not answering yet', 'the relay is up, the node is not');
        }
        $('anLocalFix').hidden = true;
        return;
      }
      v.set('warn', 'Nothing has pushed to this dashboard yet',
        h.relayAgeMs === null ? 'no relay has ever reported here' : 'the last frame was ' + ago(h.relayAgeMs));
      $('anLocalFix').hidden = false;
      cmdInto($('anLocalCmd'), 'curl -fsSL https://get.aperire.one | bash -s -- --dir ' + installDir() + ' --run relay');
    });
  }

  function paintRemote() {
    cmdInto($('anRemoteCmd'), 'curl -fsSL https://get.aperire.one | bash -s -- --role relay');
    var t = OVERVIEW && OVERVIEW.this_dashboard;
    var url = (t && typeof t.relay_ingest_url === 'string' && t.relay_ingest_url) || '<dashboard-url>/ingest';
    cmdInto($('anRemoteConf'),
      'dashboard_url = "' + url + '"\n'
      + 'auth_token    = "<a token this dashboard accepts>"\n'
      + 'node_label    = "<the name this node goes under>"');

    // Whether this dashboard already spends its one admin bridge on a node
    // of its own (readHealth's nodeConnected, the same fact paintLocal()
    // already reads for its own verdicts). Read fresh every time this pane
    // opens, never cached: a node that came up or went down since the last
    // visit changes the real answer.
    readHealth().then(function (h) {
      REMOTE_HAS_OWN_NODE = !!(h && h.nodeConnected === true);
      var item = $('anRemoteAdminItem');
      if (item) item.hidden = REMOTE_HAS_OWN_NODE;
      // #628: the wiring a dashboard with no node of its own needs, shown on
      // the same fact as the checklist item above and the diagram's admin hop.
      var wiring = $('anRemoteWiring');
      if (wiring) wiring.hidden = REMOTE_HAS_OWN_NODE;
      if (WHERE === 'remote') paintShape('remote');
    });
    // Placeholders, not digits: this page can read neither the node's admin
    // stanza nor this dashboard's environment (see paintShape's comment).
    cmdInto($('anRemoteAdminCfg'),
      '# rippled.cfg, on the node\u2019s host\n'
      + '[port_ws_admin_local]\n'
      + 'port = <admin-port>\n'
      + 'ip = <an address this dashboard can reach>\n'
      + 'admin = <this dashboard\u2019s address, as the node\u2019s host sees it>\n'
      + 'protocol = ws');
    cmdInto($('anRemoteEnvCmd'), 'RIPPLED_URL=ws://<the node\u2019s address>:<admin-port>');
    cmdInto($('anRemoteRestartCmd'), 'sudo systemctl restart aperire-server');
    var cv = $('anRemoteCheckVerdicts');
    if (cv) cv.innerHTML = '';
  }

  // #628's check line. /healthz carries rippled_connected, the one fact this
  // page can read about the admin hop. It cannot say which node the
  // connection is to, and the verdicts say so rather than imply it.
  function checkRemoteNodeLink() {
    var btn = $('anRemoteCheckBtn');
    var v = verdicts($('anRemoteCheckVerdicts'));
    if (btn) btn.disabled = true;
    v.set('wait', 'Asking this dashboard whether it is connected to a node...');
    readHealth().then(function (h) {
      if (btn) btn.disabled = false;
      if (!h) {
        v.set('bad', 'This dashboard did not answer its own health check', 'nothing can be concluded from that');
      } else if (h.nodeConnected) {
        v.set('ok', 'This dashboard is connected to a node', 'rippled_connected is true, so the Consensus and Governance tabs have something to read');
      } else {
        v.set('warn', 'This dashboard is not connected to a node yet', 'rippled_connected is false');
        v.add('warn', 'RIPPLED_URL does not point at that node yet, or the dashboard was not restarted after the edit');
        v.add('warn', 'The node is not listening for this dashboard', 'its admin stanza is wrong, the node was not restarted, or a firewall is in the way');
      }
    });
  }
  if ($('anRemoteCheckBtn')) $('anRemoteCheckBtn').addEventListener('click', checkRemoteNodeLink);

  // MED-07, in the policy module's own words rather than a second wording of
  // the same rule. Shown only when this dashboard would actually refuse the
  // push, which is a fact about how it is bound, not a guess about the
  // operator's network.
  function paintMed07() {
    var box = $('anMed07');
    var ing = OVERVIEW && OVERVIEW.this_dashboard && OVERVIEW.this_dashboard.ingest;
    if (!ing || ing.remote_relay_allowed !== false || WHERE !== 'remote') { box.hidden = true; return; }
    box.hidden = false;
    box.innerHTML = '<b>A relay on another box cannot push to this dashboard as it is bound now.</b> '
      + esc(ing.detail || '')
      + '<span style="display:block;margin-top:6px">The short version: keep both ends on loopback with an '
      + 'SSH or WireGuard tunnel, or put TLS in front of this dashboard and point the relay at '
      + '<code>wss://</code>.</span>';
  }

  // The fleet path's own step 2: whether that box already has Aperire on it.
  // "Not yet" reveals the install line without completing the step (nothing
  // below unlocks); "It is installed" completes it, whichever was clicked
  // last -- the operator can answer either way, in either order, and only
  // the most recent answer is the one that stands.
  function paintFleetInstallLine() {
    var line = OVERVIEW && OVERVIEW.this_dashboard && OVERVIEW.this_dashboard.install_join_command;
    if (line) cmdInto($('anFleetInstallCmd'), line);
  }
  if ($('anFleetNo')) $('anFleetNo').addEventListener('click', function () {
    $('anFleetInstallLine').hidden = false;
    paintFleetInstallLine();
  });
  if ($('anFleetYes')) $('anFleetYes').addEventListener('click', function () {
    completeStep2('Aperire is installed on that box');
  });
  if ($('anStep2DoneBtn')) $('anStep2DoneBtn').addEventListener('click', function () {
    completeStep2('I have the line');
  });

  // `quiet` is the reload path (restorePairedDone): repainting a finished
  // pairing is not an operator entering step 3, so it asks this host nothing.
  function completeStep2(pickedText, quiet) {
    if (STEP2_DONE) return;
    STEP2_DONE = true;
    paintStep(2, 'done', { picked: pickedText, word: 'done' });
    paintStep(3, 'now', { word: WHERE === 'fleet' ? 'fingerprint' : 'test' });
    if (WHERE === 'fleet' && !quiet) { paintFpHost(); fpEnter(); }
  }

  // ── Step 3, fleet path: this aggregator's pairing fingerprint ──────
  //
  // The page names a command and never a value. It asks this host one
  // question as the step opens, whether root here can print a fingerprint,
  // and nothing else: root's broker takes one connection at a time, so this
  // is never on a timer, never in the ten-second poll, and never behind
  // setSharedOverview. It runs from three places only: step 3 opening
  // (completeStep2, reopenStep3) and the explicit "Check again" button.
  var FP_BUSY = false;

  function paintFpHost() {
    var s = OVERVIEW && OVERVIEW.self;
    var t = OVERVIEW && OVERVIEW.this_dashboard;
    var host = (s && s.host_name) || (t && t.host_name) || 'this aggregator';
    if ($('anFpHost')) $('anFpHost').textContent = host;
    var url = fleetAggregatorUrl();
    var shown = '';
    if (url && url !== '<this-aggregator-url>') {
      try { shown = new URL(url).host; } catch { shown = ''; }
    }
    if ($('anFpUrl')) $('anFpUrl').textContent = shown ? ' (' + shown + ')' : '';
  }

  function fpCommand() {
    var how = OVERVIEW && OVERVIEW.pairing_fingerprint;
    return (how && how.command) || 'sudo aperire-fleet-arm --fingerprint';
  }

  // The broker's sentence names the command it wants run, at its end
  // ("... install the grant first: sudo bash ...") or in the middle
  // ("Re-record it: sudo bash ... (the full installer, ...)"). The command
  // gets its own copy box, so the sentence points at the box instead of
  // printing it twice.
  // settings.html owns how a server sentence opens a line (window.ApRefusal,
  // #1195). That script runs before this deferred one; the fallback is only
  // for a page that does not carry it.
  function asLine(text) {
    var R = window.ApRefusal;
    return R && typeof R.capFirst === 'function' ? R.capFirst(text) : String(text || '');
  }

  function sentenceOnly(detail, command) {
    var d = String(detail || '');
    var c = command ? String(command) : '';
    if (!c || d.indexOf(c) < 0) return d;
    if (d.slice(-c.length) === c) return d.slice(0, d.length - c.length).replace(/[\s:]+$/, '') + ':';
    return d.split(c).join('the command below');
  }

  function resetFp() {
    if (!$('anFpReady')) return;
    $('anFpReady').hidden = true;
    $('anFpFix').hidden = true;
    $('anFpRetryRow').hidden = true;
    $('anFpCmd').innerHTML = '';
    $('anFpFixCmd').innerHTML = '';
    $('anFpSentence').textContent = '';
    $('anFpVerdicts').innerHTML = '';
  }

  function fpNotReady(sentence, command) {
    $('anFpReady').hidden = true;
    // The command goes with the readiness: a host that cannot print the
    // fingerprint has no line to run, only a sentence and its fix.
    $('anFpCmd').innerHTML = '';
    $('anFpVerdicts').innerHTML = '';
    $('anFpFix').hidden = false;
    $('anFpSentence').textContent = sentence;
    if (command) cmdInto($('anFpFixCmd'), command); else $('anFpFixCmd').innerHTML = '';
    $('anFpRetryRow').hidden = false;
  }

  function fpEnter() {
    if (WHERE !== 'fleet' || !$('anFpReady')) return;
    var v = verdicts($('anFpVerdicts'));
    $('anFpReady').hidden = true;
    $('anFpFix').hidden = true;
    $('anFpRetryRow').hidden = true;
    $('anFpCmd').innerHTML = '';
    v.set('wait', 'Asking this host, once, whether root can print a pairing fingerprint...');
    // One question in flight at a time. A second entry while one is out
    // adopts that answer when it lands rather than asking root again.
    if (FP_BUSY) return;
    FP_BUSY = true;
    postJson('/api/settings/pair/ready', {}).then(function (r) {
      FP_BUSY = false;
      if (WHERE !== 'fleet') return;
      var b = r.body;
      if (r.status === 200 && b && b.ok === true) {
        $('anFpVerdicts').innerHTML = '';
        verdicts($('anFpVerdicts')).set('ok', 'This host can print the pairing fingerprint',
          'its fleet keys and the command are in place');
        cmdInto($('anFpCmd'), fpCommand());
        $('anFpReady').hidden = false;
        return;
      }
      if (r.status === 200 && b && b.ok === false && typeof b.detail === 'string') {
        // The broker's clause can open the line ("the fleet broker is busy
        // ..."): capitalised by the page's one composer (#1195).
        fpNotReady(asLine(sentenceOnly(b.detail, b.command)), typeof b.command === 'string' ? b.command : null);
        return;
      }
      var why = b && typeof b.error === 'string' ? b.error : 'it answered ' + r.status;
      fpNotReady('This dashboard could not answer the readiness check (' + why + '). Nothing was changed.', null);
    }, function (e) {
      FP_BUSY = false;
      if (WHERE !== 'fleet') return;
      fpNotReady('This dashboard could not be reached for the readiness check (' + ((e && e.message) || e)
        + '). Nothing was changed.', null);
    });
  }

  if ($('anFpRetryBtn')) $('anFpRetryBtn').addEventListener('click', fpEnter);
  if ($('anFpHaveBtn')) $('anFpHaveBtn').addEventListener('click', function () {
    if (WHERE !== 'fleet' || !STEP2_DONE || STEP3_DONE) return;
    STEP3_DONE = true;
    paintStep(3, 'done', { picked: 'I have the fingerprint', word: 'done' });
    if ($('anStep3Change')) $('anStep3Change').hidden = false;
    paintStep(4, 'now', { word: 'pair' });
  });

  // ── Step 3: the link (local/remote) ──────────────────────────────
  //
  // Local and remote alike: the honest test is the relay's own first push,
  // never a claim this dashboard cannot back with a reading. Seeing it is
  // the one fact in this whole flow the page can verify on its own, so it
  // is what unlocks step 4 rather than another click standing in for it.

  var watchTimer = null;
  function stopWatching() { if (watchTimer) { clearInterval(watchTimer); watchTimer = null; } }

  // Step 3 folds to done the same way steps 1 and 2 do (the operator's
  // ruling is unconditional on this: "a DONE step folds to one line").
  function completeStep3() {
    if (STEP3_DONE || WHERE === 'fleet') return;
    STEP3_DONE = true;
    paintStep(3, 'done', { picked: 'First frame seen', word: 'done' });
    // "change" is the way back into a folded step 3.
    if ($('anStep3Change')) $('anStep3Change').hidden = false;
    paintStep(4, 'now', { word: 'optional' });
    paintAdvisor();
  }

  // The fleet path's own step 4 finish (#629, reported after a real pair on
  // the operator's own box left the step sitting open with no way to tell
  // it had worked). Same fold as every other "done" step -- paintStep is
  // the one place that logic lives -- but this path has no step 4 to hand
  // the operator to next, so what usually happens there happens here: a
  // clear finish, a Done that starts the next node at step 1, and a link to
  // where the node actually landed.
  // `note` is this row's own, live: the follow-on that pushes trust and the
  // fleet's Advisor model to the node can still be running the moment this
  // first fires, or have something to report (a trust push that failed). It
  // is this row's `note` field: the one plain sentence every outcome gets
  // ("Registered, linked, ..."), never a command run into the middle of it.
  // "Paired as <label>" is never the whole story on its own, so
  // settings.html calls this again on every poll the row is still known by,
  // and the note below the fold keeps pace with what the row itself says --
  // the fold, driven by STEP3_DONE, happens once; the note does not stop
  // there. `next` (#635) is the row's own `note_next`: the ONE optional step
  // an outcome can carry (today, only arm-closed) -- a sentence and the real
  // command, kept apart from `note` so the command lands in its own copy
  // box, exactly the mockup's "Optional: give it the fleet's Advisor model"
  // block, never folded into running prose.
  // #632: the fold's headline follows how the row finished. "Paired as" is
  // the node's own word that it wrote its credential; the row is registered
  // in every other case too, and the headline says what is missing.
  function pairedHeadline(label, settled) {
    if (settled === 'ok') return 'Paired as ' + label;
    if (settled === 'no_credential' || settled === 'link_closed') return 'Registered as ' + label + ', but the node did not finish';
    if (settled === 'unconfirmed') return 'Registered as ' + label + ', not confirmed by the node';
    return 'Registered as ' + label + ', the node is finishing';
  }

  function completeStep4Fleet(label, note, next, settled, reason) {
    if (WHERE !== 'fleet') return;
    // The STEP2_DONE and STEP3_DONE guards are belt and braces alongside
    // forgetPairMint() above: step 4 cannot be the open step, let alone a
    // folded one, before the two steps above it are done, so a call that
    // lands here anyway (a stale id that slipped past the reset somewhere)
    // still cannot fold a step the operator has not reached yet.
    if (!STEP2_DONE || !STEP3_DONE) return;
    var headline = pairedHeadline(label, settled || 'waiting');
    if (STEP4_DONE && $('anStep4Picked')) $('anStep4Picked').textContent = headline;
    if (!STEP4_DONE) {
      STEP4_DONE = true;
      paintStep(4, 'done', { picked: headline, word: 'done' });
      // Nothing left to reopen into: the code this step held is spent the
      // moment a node presents it, whatever becomes of the row after, so
      // "change" on the fingerprint step above would open a step with no
      // code and no pending row of its own to show.
      if ($('anStep3Change')) $('anStep3Change').hidden = true;
      var actions = $('anStep4PairedActions');
      if (actions) actions.hidden = false;
      var link = $('anStep4PairedLink');
      if (link) link.dataset.label = label;
    }
    // #632: a node that did not finish says why first, whatever the
    // follow-on has written into the note since.
    var said = note || '';
    if ((settled === 'no_credential' || settled === 'link_closed' || settled === 'unconfirmed')
        && reason && said.indexOf(reason) < 0) {
      said = 'The node did not finish: ' + reason + '. ' + said;
    }
    if ($('anStep4PairedNote')) $('anStep4PairedNote').textContent = said;
    if (next && next.sentence && next.command) {
      if ($('anStep4PairedNext')) $('anStep4PairedNext').hidden = false;
      if ($('anStep4PairedNextSentence')) $('anStep4PairedNextSentence').textContent = next.sentence;
      cmdInto($('anStep4PairedNextCmd'), next.command);
    } else {
      clearPairedNext();
    }
  }
  if ($('anStep4DoneBtn')) {
    $('anStep4DoneBtn').addEventListener('click', function () {
      // #685. Pressing Done is the operator saying they have read the fold,
      // and it has to outlive the ten-second poll: without this the restore
      // below would paint the same fold again on the very next read, for as
      // long as the server keeps returning that record.
      DISMISSED_DONE = LAST_DONE_ID;
      reopenStep1();
    });
  }

  // ── #685: the done fold survives a reload ────────────────────────
  //
  // Step 3's fold used to be reachable only through the mint this page
  // session performed: settings.html watched the row that spent ITS code
  // and called pairedDone when it reached `done`. Reload, and both the
  // expiry and the id it matched on are gone, so the fold was never
  // painted again even though /api/settings/overview still returned the
  // whole record, stage and all. What went with it was the one command the
  // operator still had to run, which is the precondition for that node ever
  // getting the fleet's model, and the card offered no way back to it.
  //
  // So a done record repaints the fold from the SERVER's copy. Three rules
  // keep it from fighting anybody:
  //
  //   1. Only when this card is at rest. An operator part-way through
  //      adding another node is not interrupted.
  //   2. Once per record. Pressing Done dismisses that id for this page
  //      session, and the poll does not bring it back.
  //   3. Nothing is invented. The label, the note and the next step are the
  //      row's own fields; a record the server stops returning stops being
  //      painted, which is exactly how long the issue asks it to last.
  var DISMISSED_DONE = null;
  var LAST_DONE_ID = null;

  /** Put the card back into the fleet path's finished state, from a pending
   *  row the server still returns. Called by settings.html on every read,
   *  and a no-op on all but the first one that finds a fresh record. */
  function restorePairedDone(row) {
    if (!row || row.stage !== 'done' || !row.label) return;
    if (row.id && row.id === DISMISSED_DONE) return;
    LAST_DONE_ID = row.id || null;
    // Rule 1: at rest means nothing picked, or already sitting on this
    // exact fold. A half-finished choice is the operator's, not ours.
    if (WHERE !== null && !(WHERE === 'fleet' && STEP4_DONE)) return;
    if (WHERE === null) {
      // Walk the same three steps a live pairing walked, so step 4's fold
      // sits under a step 1, 2 and 3 that read done rather than under
      // rows that never happened. Quiet: a reload asks this host nothing.
      choose('fleet');
      completeStep2('Aperire is installed on that box', true);
      STEP3_DONE = true;
      paintStep(3, 'done', { picked: 'I have the fingerprint', word: 'done' });
    }
    // #632: an older hub sends no value, read as not yet finished.
    var st = row.settled === 'ok' || row.settled === 'no_credential' || row.settled === 'link_closed'
      || row.settled === 'unconfirmed' ? row.settled : 'waiting';
    completeStep4Fleet(row.label, row.note, row.note_next, st, row.settled_reason || null);
  }

  function startWatching() {
    var v = verdicts($('anWatchVerdicts'));
    stopWatching();
    var started = Date.now();
    var attempts = 0;
    // What the watch is for: the NEW node's frame. On a box whose own relay
    // never stops pushing, a fresh age is true every second and a push
    // timestamp lands after the watch began every five (#601, twice): neither
    // tells the new relay from the one already here. The label does. The
    // watch reads which label is pushing when it begins, and only a frame
    // under another label is the one it waited for. And since this dashboard
    // accepts one relay label (ADR 0009), a box already fed by its own relay
    // cannot take a second host's: On another box says so up front, rather
    // than watching for a frame that would be refused.
    var labelAtStart = null;
    $('anWatchBtn').disabled = true;
    $('anWatchBtn').textContent = 'Watching...';

    function tick() {
      attempts++;
      v.set('wait', WHERE === 'local'
        ? 'Watching this box for the relay\'s next frame...'
        : 'Watching for the first authenticated frame from that host...',
        'asked ' + attempts + (attempts === 1 ? ' time' : ' times'));
      readHealth().then(function (h) {
        if (!h) {
          v.set('bad', 'This dashboard did not answer its own health check', 'nothing can be concluded from that');
          return;
        }
        if (attempts === 1) labelAtStart = h.relayLive ? h.relayLabel : null;
        if (WHERE === 'remote' && labelAtStart) {
          // A relay was already pushing here when the watch began, and this
          // dashboard takes exactly one label: the other host's relay will be
          // refused, whatever happens next. Say so now.
          stopWatching();
          $('anWatchBtn').disabled = false;
          $('anWatchBtn').textContent = 'Test again';
          v.set('bad', 'This dashboard already has a relay',
            'it reports as ' + labelAtStart + ' and is pushing; a dashboard accepts one relay, so the one on that host will be refused until this one stops');
          v.add('note', 'To watch a node on another box from here, run that box\'s own dashboard and join it to this fleet: choose "It already runs Aperire"');
          return;
        }
        var sinceStart = h.relayAt !== null ? h.relayAt >= started - 1000 : null;
        var newLabel = h.relayLive && h.relayLabel && h.relayLabel !== labelAtStart;
        var seen = WHERE === 'local'
          ? (sinceStart === null ? h.relayLive : sinceStart)
          : newLabel;
        if (seen) {
          stopWatching();
          $('anWatchBtn').disabled = false;
          $('anWatchBtn').textContent = 'Test again';
          v.set('ok', 'First frame seen',
            (h.relayLabel ? 'a relay reporting as ' + h.relayLabel + ' pushed ' : 'a relay pushed ') + ago(h.relayAgeMs)
            + (WHERE === 'local' && sinceStart === null ? ' (this dashboard is too old to say whether that was after the watch began)' : '')
            + ', and this dashboard accepted it');
          if (h.nodeConnected) v.add('ok', 'The node behind it is connected', 'the tabs have something to draw');
          else v.add('warn', 'The node behind it has not answered yet',
            WHERE === 'remote' && REMOTE_HAS_OWN_NODE === false
              ? 'the host is reporting, but this dashboard is not connected to a node: step 2 ends with the two edits that fix that'
              : 'the host is reporting, the node is not');
          completeStep3();
          return;
        }
        var waited = Math.round((Date.now() - started) / 1000);
        v.set('wait', 'Nothing has pushed since this watch began', 'watching for ' + waited + 's');
        if (h.relayLive) {
          v.add('warn', 'A relay is pushing here, but it was already pushing before the watch began',
            (h.relayLabel ? 'it reports as ' + h.relayLabel + '; ' : '') + 'this dashboard accepts one relay label, so a second host\'s relay is refused until this one stops');
        } else if (h.relayAgeMs !== null) {
          v.add('warn', 'A relay reported here before', 'the last frame was ' + ago(h.relayAgeMs) + ', so it has stopped');
        }
        // On another box the wait is shorter and the answer is longer. The
        // relay dials OUT, so a minute of nothing means something between the
        // two is in the way, and the relay itself can say which (#586).
        if (WHERE === 'remote' && waited >= 60) {
          stopWatching();
          $('anWatchBtn').disabled = false;
          $('anWatchBtn').textContent = 'Watch again';
          v.add('bad', 'Nothing arrived in a minute', 'the relay on that host dials out to this dashboard, so one of these is in the way');
          v.add('warn', 'That host cannot find this dashboard by name', 'the name in dashboard_url does not resolve there');
          v.add('warn', 'The connection is refused or times out', 'a firewall is in the way, or the port in dashboard_url is wrong');
          v.add('warn', 'The TLS handshake fails', 'the certificate does not match the name, has expired, or is not trusted by that host');
          v.add('warn', 'This dashboard refuses the token (401)', 'the auth_token in relay.conf is not in this dashboard\u2019s RELAY_TOKENS');
          v.add('warn', 'This dashboard refuses a plain ws:// push from another host (403)', 'use a tunnel to ws://127.0.0.1, or wss://');
          v.add('warn', 'The relay is not running there, or is standing by with an empty dashboard_url');
          v.add('note', 'On that host, one command tries this dashboard once and says which of these it is');
          $('anWatchVerdicts').insertAdjacentHTML('beforeend', '<div id="anWatchPathCmd" style="min-width:0"></div>');
          cmdInto($('anWatchPathCmd'), 'sudo aperire-relay --check-dashboard');
        } else if (waited > 90) {
          stopWatching();
          $('anWatchBtn').disabled = false;
          $('anWatchBtn').textContent = 'Watch again';
          v.add('bad', 'Nothing arrived in 90 seconds', 'the three usual reasons are below');
          v.add('warn', 'The relay is not running on that host, or it is standing by with no dashboard_url');
          v.add('warn', 'The token in relay.conf is not one this dashboard accepts', 'the relay logs that refusal by name');
          v.add('warn', 'Nothing on that host can reach this address', 'a tunnel is the usual fix');
        }
      });
    }
    tick();
    watchTimer = setInterval(tick, 5000);
  }
  if ($('anWatchBtn')) $('anWatchBtn').addEventListener('click', startWatching);

  // ── Step 4: the Advisor, optional, same for whichever path was picked ──

  function paintAdvisor() {
    cmdInto($('anAdvCmd'), 'curl -fsSL https://get.aperire.one/advisor | bash');
    var v = verdicts($('anAdvVerdicts'));
    var presence = OVERVIEW && OVERVIEW.self && OVERVIEW.self.advisor && OVERVIEW.self.advisor.presence;
    if (!presence) { v.set('warn', 'This dashboard could not say whether an Advisor is installed', 'so nothing is claimed either way'); return; }
    if (presence === 'present') v.set('ok', 'An Advisor is already answering on this box', 'the command below is for any other box you want one on');
    else if (presence === 'absent') v.set('warn', 'No Advisor on this box', 'which is an ordinary state, not a fault');
    else v.set('warn', 'An Advisor is installed here and not answering', 'check it on the host before installing another');
  }

  // A closed fold stops polling for a frame nobody is watching for.
  var fold = $('setAddNode');
  if (fold) {
    fold.addEventListener('toggle', function () {
      if (!fold.open) stopWatching();
    });
  }

  // ── Boot ─────────────────────────────────────────────────────────
  //
  // No fetch of its own here: settings.html hands this file the same
  // overview object its own load() and refresh() already read, so opening
  // this section never costs the page a second /api/settings/overview hit.

  function init(ov) { setSharedOverview(ov); }

  function openAndScroll(ov) {
    if (ov) setSharedOverview(ov);
    var d = $('setAddNode');
    if (d) {
      d.open = true;
      d.scrollIntoView({ block: 'start' });
    }
  }

  window.ApAddNode = {
    init: init, openAndScroll: openAndScroll, setOverview: setSharedOverview,
    // Called by settings.html the moment the row this step's own code
    // produced reaches "done" (#629): this file owns step 3's fold, and
    // settings.html owns the pending row's poll, so the fold is driven from
    // there rather than duplicating the row-watching this file already
    // hands off to it.
    pairedDone: completeStep4Fleet,
    // #685: repaint the finished fold from a pending record the server
    // still returns, on a page that did not mint the code itself.
    restorePairedDone: restorePairedDone,
  };
})();
