// Add an Advisor, inside Settings & Updates (#638).
//
// A home for the curl command that used to live only in a chat bubble on the
// Advisor tab: pick a node with no Advisor, run one command on it, watch it
// arrive, then hand off to giving it the fleet's model. Modelled on
// add-node.js's own stepped fold (#607) -- numbered steps, one open at a
// time, a done step folds to one line -- because this is the same shape of
// job: a command to run elsewhere, and a live fact this page can (sometimes)
// confirm on its own.
//
// Loaded by settings.html (defer), after model-form.js and add-node.js and
// before the page's own inline script runs its gate. window.ApAddAdvisor.init(ov)
// is called once that gate says admin, and again on every ten-second poll:
// ov is the SAME object settings.html's own load()/refresh() already read
// from /api/settings/overview, never a second fetch of this file's own --
// "one read builds the page" (settings-walk.mjs) would break otherwise.
//
// The node picker's source of truth is `n.advisor.presence`, the exact field
// the Fleet registry list's own Advisor column reads (settings.html's
// presenceOf()) and the same one Advisor AI model's table keys `hasAdvisor`
// on. Duplicated here in miniature rather than imported -- this file and
// settings.html's inline script are two closures with no shared module system
// -- but it is the SAME field read the SAME way, never a second probe: no
// fetch happens because this section exists.
//
// The watch is honest about what it can and cannot see. This host's OWN
// Advisor (self) is observed live (advisor-presence.ts's token+probe cycle,
// ADR 0016), so self's step 2 really folds once the command finishes. A
// PEER's advisor_origin is declared, not probed (ADR 0016 decision 7): it is
// written once, when the node joins the fleet, and nothing re-writes it
// afterwards. So a peer's step 2 says that plainly instead of promising a
// fold nothing here can deliver.
//
// The fold is not disabled for a peer, only unpromised: paintWatch's
// presence check runs for every node, so a peer whose presence does turn
// present (a re-registration, a newer build that probes) completes step 2
// and opens step 3 the same way self does. What this page lacks is anything
// that makes that happen on its own.
(function () {
  'use strict';

  var $ = function (id) { return document.getElementById(id); };

  function esc(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  // model-form.js is loaded synchronously before this file (settings.html:23),
  // so this always has the shared command block, with the copy button the
  // rest of the product uses.
  function cmdInto(el, text) {
    if (!el) return;
    if (window.ApModelForm && window.ApModelForm.cmdHtml) {
      el.innerHTML = window.ApModelForm.cmdHtml(text);
      if (window.ApModelForm.wireCopyButtons) window.ApModelForm.wireCopyButtons();
      return;
    }
    el.innerHTML = '<pre class="ap-cmd"><code>' + esc(text) + '</code></pre>';
  }

  // A constant, and it stays one. The model command elsewhere in the product
  // carries --dir because get-aperire.sh only ever guesses the checkout from
  // $HOME. This one does not need it: get-aperire-advisor.sh reads
  // WorkingDirectory off the installed aperire-server unit and takes its
  // parent, so it finds an install wherever it lives, including one this
  // dashboard has no way to name (a peer's).
  var ADVISOR_INSTALL_CMD = 'curl -fsSL https://get.aperire.one/advisor | bash';

  // ── The overview, handed in rather than fetched ──────────────────────
  var OVERVIEW = null;
  // When this page read that overview. The sealing window is a clock on
  // another host, and a line that says how long is left has to say as of when.
  var OVERVIEW_AT = 0;
  function setSharedOverview(ov) {
    OVERVIEW = ov || null;
    OVERVIEW_AT = Date.now();
    render();
  }

  function nodes() {
    if (!OVERVIEW) return [];
    var list = [];
    if (OVERVIEW.self) list.push(OVERVIEW.self);
    (OVERVIEW.peers || []).forEach(function (p) { list.push(p); });
    return list;
  }
  function targetOf(n) { return n.is_self ? 'self' : n.label; }
  function byTarget(t) {
    var all = nodes();
    for (var i = 0; i < all.length; i++) if (targetOf(all[i]) === t) return all[i];
    return null;
  }
  // The exact field the Fleet registry list's own Advisor column reads
  // (settings.html's presenceOf()), read the same way: a build too old to
  // carry the three-state field falls back to two, and "did not answer" is
  // the honest one of them -- never "absent", which would list a node that
  // merely blipped as one with no Advisor at all.
  function presenceOf(n) {
    var a = (n && n.advisor) || {};
    if (a.presence) return a.presence;
    return a.present ? 'present' : 'unread';
  }
  function noAdvisor(n) { return presenceOf(n) === 'absent'; }
  // #859: never offer an Advisor for a node a revoke is taking off the
  // fleet (settings.html keeps that set in window.ApRevoking).
  function leaving(n) { return !n.is_self && Boolean(window.ApRevoking && window.ApRevoking[n.label]); }
  function candidates() { return nodes().filter(function (n) { return noAdvisor(n) && !leaving(n); }); }
  function displayLabel(n) { return n.is_self ? (n.label || 'this dashboard') : n.label; }

  // ── Step state ─────────────────────────────────────────────────────
  var PICKED = null;      // target id ('self' or a peer label), or null
  var STEP2_DONE = false;
  // The label a deep link or a fresh pick most recently named, applied once
  // OVERVIEW carries that node -- a link that arrives before the first
  // /api/settings/overview read has landed has nothing to pick yet.
  var WANT_LABEL = null;

  function paintStep(n, state, opts) {
    opts = opts || {};
    var row = $('aaStep' + n + 'Row');
    if (!row) return;
    row.classList.remove('an-now', 'an-done', 'an-later');
    row.classList.add('an-' + state);
    var doneEl = $('aaStep' + n + 'Done');
    var bodyEl = $('aaStep' + n + 'Body');
    var contentEl = $('aaStep' + n + 'Content');
    var stateEl = $('aaStep' + n + 'State');
    if (state === 'done') {
      if (doneEl) doneEl.hidden = false;
      if (bodyEl) bodyEl.hidden = true;
      if (opts.picked != null && $('aaStep' + n + 'Picked')) $('aaStep' + n + 'Picked').textContent = opts.picked;
    } else {
      if (doneEl) doneEl.hidden = true;
      if (bodyEl) bodyEl.hidden = false;
      if (contentEl) contentEl.hidden = state !== 'now';
    }
    if (stateEl && opts.word !== undefined) stateEl.textContent = opts.word;
  }

  function pick(target) {
    var n = byTarget(target);
    if (!n) return;
    PICKED = target;
    STEP2_DONE = false;
    // Whatever the last pick was watching stops here, before the new node's
    // own watch starts in paintStep2 below: an answer about the old node
    // landing after this point would paint the wrong row's verdict.
    stopWatch();
    HELD_REFUSAL = false;
    said(null);
    rearm(false);
    if ($('aaAttachRow')) $('aaAttachRow').hidden = true;
    if ($('aaVerdict')) { $('aaVerdict').hidden = true; $('aaVerdict').textContent = ''; }
    paintStep(1, 'done', { picked: displayLabel(n), word: 'done' });
    paintStep(2, 'now', { word: 'run it' });
    paintStep(3, 'later', { word: 'not yet' });
    paintStep2(n);
  }

  function reopenStep1() {
    PICKED = null;
    STEP2_DONE = false;
    stopWatch();
    HELD_REFUSAL = false;
    said(null);
    rearm(false);
    if ($('aaAttachRow')) $('aaAttachRow').hidden = true;
    if ($('aaVerdict')) { $('aaVerdict').hidden = true; $('aaVerdict').textContent = ''; }
    paintStep(1, 'now', { word: 'now' });
    paintStep(2, 'later', { word: 'not yet' });
    paintStep(3, 'later', { word: 'not yet' });
  }
  if ($('aaStep1Change')) $('aaStep1Change').addEventListener('click', reopenStep1);
  if ($('aaLaterBtn')) $('aaLaterBtn').addEventListener('click', reopenStep1);

  function renderPickCards() {
    var wrap = $('aaPickCards');
    if (!wrap) return;
    var cand = candidates();
    wrap.innerHTML = cand.map(function (n) {
      var t = targetOf(n);
      return '<button type="button" class="an-choice" data-aa-pick="' + esc(t) + '" aria-pressed="' + (PICKED === t) + '">'
        + '<b>' + esc(displayLabel(n)) + '</b>'
        + (n.is_self ? '<small>This dashboard.</small>' : '<small>A node on this fleet.</small>')
        + '</button>';
    }).join('');
  }
  document.addEventListener('click', function (e) {
    var b = e.target.closest && e.target.closest('[data-aa-pick]');
    if (!b) return;
    pick(b.getAttribute('data-aa-pick'));
  });

  // ── Step 2: the command, and the watch ────────────────────────────

  function paintStep2(n) {
    var label = displayLabel(n);
    $('aaStep2Title').textContent = 'Run this on ' + label + '.';
    var who = $('aaWho');
    if (who) {
      who.innerHTML = 'On <b>' + esc(label) + (n.is_self ? '&rsquo;s own box' : '&rsquo;s box') + '</b>, as the account '
        + 'that installed Aperire there, for example <code>aperire</code>. It asks for sudo itself.'
        + '<span class="info-icon an-tip-wide" tabindex="0" role="button" aria-label="Why that account">'
        + '<span class="info-tip"><span class="info-title">Why that account.</span>'
        + 'Aperire&rsquo;s services run as the account that installed them, so that account owns the checkout '
        + 'and the build cache the Advisor needs too. <strong>Not root:</strong> the installer refuses a root '
        + 'login and asks for sudo itself.</span></span>';
    }
    cmdInto($('aaCmd'), ADVISOR_INSTALL_CMD);
    paintWatch(n);
  }

  function watchVerdict(kind, text) {
    var el = $('aaWatch');
    if (!el) return;
    var mark = kind === 'ok' ? '✓' : kind === 'wait' ? '·' : '▲';
    el.innerHTML = '<div class="an-verdict an-v-' + kind + '"><span class="an-dot">' + mark + '</span><span>'
      + text + '</span></div>';
  }

  // ── The watch (#641) ──────────────────────────────────────────────
  //
  // Until #641 this said, honestly, that it could not see a peer's Advisor
  // arrive: a peer's advisor_origin is written once at pairing and nothing
  // re-wrote it, so nothing on this page ever moved. It can see one now,
  // because the node's OWN dashboard answers for itself over a route that
  // is live the moment any node pairs.
  //
  // SCOPED, and every one of these bounds is deliberate. The poll asks about
  // ONE node, the one that is picked, and only while every one of these
  // holds: a node is picked, step 2 is the open step, the card is open, and
  // the tab is on screen. It stops the moment any of them stops. A page-wide
  // fan-out over the fleet, forever, to answer a question almost nobody is
  // asking at any moment is what this is instead of.
  //
  // FIVE READINGS, decided on the server (lib/fleet-advisor-attach.ts) and
  // rendered here. Nothing about the verdict is composed on this page: the
  // sentence is the server's `detail`, the node's own words are its `said`,
  // and whether Attach may be pressed at all is its `can_attach`. A page
  // that re-derived any of the three could disagree with the route that
  // enforces them.
  var WATCH_TIMER = null;
  var WATCH_INFLIGHT = false;
  // A refusal the operator still has to act on, held against the poll that
  // resumes underneath it. Found by the walk: the re-arm box went up, the
  // next reading four seconds later painted "Advisor found, ready to
  // attach" over it, and the one command the operator needed was gone from
  // a row that looked fine. A reading may still enable or disable Attach
  // while this is set (that is a fact about the node, and it is what makes
  // a second press possible); it may not overwrite the words.
  var HELD_REFUSAL = false;
  var WATCH_FOR = null;    // the label this poll is about, or null
  var WATCH_MS = 4000;

  function stopWatch() {
    if (WATCH_TIMER) { clearInterval(WATCH_TIMER); WATCH_TIMER = null; }
    WATCH_FOR = null;
    WATCH_INFLIGHT = false;
  }

  /** Every condition that has to hold for this page to be asking about a
   *  node at all. One function, so starting and continuing cannot drift. */
  function watchWanted() {
    if (STEP2_DONE || !PICKED) return false;
    var n = byTarget(PICKED);
    if (!n || n.is_self) return false;   // this host's own is observed live already
    var card = $('setAddAdvisor');
    if (card && !card.open) return false;
    var row = $('aaStep2Row');
    if (row && !/\ban-now\b/.test(row.className)) return false;
    if (document.hidden) return false;
    return true;
  }

  function startWatch(label) {
    if (WATCH_FOR === label && WATCH_TIMER) return;
    stopWatch();
    WATCH_FOR = label;
    readWatch();
    WATCH_TIMER = setInterval(readWatch, WATCH_MS);
  }

  function readWatch() {
    if (!watchWanted()) { stopWatch(); return; }
    // One request at a time. A slow node must not queue a second ask behind
    // the first and then answer them out of order.
    if (WATCH_INFLIGHT) return;
    var label = WATCH_FOR;
    WATCH_INFLIGHT = true;
    fetch('/api/settings/advisor-watch?node=' + encodeURIComponent(label), { credentials: 'same-origin' })
      .then(function (r) { return r.json().then(function (b) { return { ok: r.ok, body: b }; }); })
      .then(function (r) {
        WATCH_INFLIGHT = false;
        // The answer to a question this page has stopped asking is dropped,
        // never painted: an operator who picked another node between the
        // ask and the answer must not see the old node's verdict.
        if (WATCH_FOR !== label || !watchWanted()) return;
        if (!r.ok || !r.body) {
          watchVerdict('warn', 'This page could not read that node just now, so it has seen nothing '
            + 'either way.');
          setAttach(false);
          return;
        }
        paintWatchBody(r.body);
      })
      .catch(function () {
        WATCH_INFLIGHT = false;
        if (WATCH_FOR !== label) return;
        watchVerdict('warn', 'This page could not read that node just now, so it has seen nothing '
          + 'either way.');
        setAttach(false);
      });
  }

  /** The three visual tones, from the five readings. `ready` is the only one
   *  that offers the button, and `can_attach` is what actually decides it. */
  var WATCH_TONE = {
    ready: 'ok', waiting: 'wait', down: 'warn', old_build: 'warn', unreachable: 'warn',
  };

  function paintWatchBody(b) {
    // Attach follows the node either way: a held refusal is about what
    // happened last time, not about whether that node is answering now.
    setAttach(b.can_attach === true);
    if (HELD_REFUSAL) return;
    watchVerdict(WATCH_TONE[b.watch] || 'wait', esc(b.detail || ''));
    said(b.said);
    // The re-arm box belongs to a refused attach, not to a reading.
    rearm(false);
  }

  /** That node's own sentence, under the verdict and captioned as a
   *  quotation. Hidden when the node said nothing, which is every timeout
   *  and every answer whose body means nothing. */
  function said(text, label) {
    var el = $('aaSaid');
    if (!el) return;
    if (!text) { el.hidden = true; el.textContent = ''; return; }
    // The caption is which node said it, and it is taken from the node this
    // row is about rather than from the poll's own state: the refusal path
    // stops the watch before it paints, so reading WATCH_FOR there left an
    // uncaptioned quotation with no name on it. `PICKED` is the row.
    var who = label || WATCH_FOR || (byTarget(PICKED) || {}).label || '';
    el.hidden = false;
    el.textContent = (who ? who + ' said: ' : '') + text;
  }

  function setAttach(on) {
    var row = $('aaAttachRow');
    var btn = $('aaAttachBtn');
    if (row) row.hidden = false;
    if (btn) btn.disabled = !on;
  }

  function rearm(on, command) {
    var box = $('aaRearm');
    if (!box) return;
    box.hidden = !on;
    if (on) cmdInto($('aaRearmCmd'), command || ADVISOR_INSTALL_CMD);
  }

  if ($('aaAttachBtn')) {
    $('aaAttachBtn').addEventListener('click', function () {
      if (!PICKED || !window.ApSettingsNode || !window.ApSettingsNode.attach) return;
      var n = byTarget(PICKED);
      if (!n || n.is_self) return;
      var label = n.label;
      $('aaAttachBtn').disabled = true;
      // A fresh press clears whatever the last one left on the row.
      HELD_REFUSAL = false;
      rearm(false);
      // The ceremony's own line lands here, in this card, where the node
      // name and the key prefix an operator is approving can be read.
      if ($('aaVerdict')) $('aaVerdict').hidden = false;
      // The watch is stopped for the length of the ceremony: a poll landing
      // mid-attach would repaint the row underneath a passkey prompt.
      stopWatch();
      window.ApSettingsNode.attach(label, function (err, body) {
        if (!err && body) {
          completeStep2(label, body.advisord_version || null);
          return;
        }
        // A refused attach goes back to watching. The one refusal with a way
        // out on the page gets the copy box, with the SAME command step 1
        // printed: re-running the installer replants the window on that box
        // and leaves an existing token exactly as it is.
        var eb = (err && err.body) || {};
        // Held against the resumed poll: this is the operator's to clear,
        // by pressing Attach again or by picking another node.
        HELD_REFUSAL = true;
        if (eb.error === 'advisor_reveal_window_closed') {
          watchVerdict('warn', esc(eb.detail || ''));
          said(eb.said, label);
          rearm(true, eb.rearm_command || ADVISOR_INSTALL_CMD);
        } else {
          watchVerdict('warn', esc((err && err.message) || 'Nothing was changed.'));
          said(eb.said, label);
          rearm(false);
        }
        setAttach(false);
        startWatch(label);
      });
    });
  }

  // The tab going away stops the asking, and coming back resumes it. Bound
  // once: this file is loaded once and its listeners live as long as the
  // page does.
  document.addEventListener('visibilitychange', function () {
    if (document.hidden) { stopWatch(); return; }
    if (watchWanted()) startWatch(byTarget(PICKED).label);
  });

  // Called on every render (every ten-second poll). Its job is now to decide
  // whether the scoped watch should be running at all, and to paint the two
  // readings that need no network call: this host's own, which is observed
  // live already, and a peer whose registry row has moved on underneath.
  function paintWatch(n) {
    if (STEP2_DONE) return;
    var target = targetOf(n);
    // The node this watch is FOR may have moved on since the render that
    // called us -- re-read it fresh off the current OVERVIEW rather than
    // trusting the argument across a poll boundary.
    var fresh = byTarget(target) || n;
    if (fresh.is_self) {
      stopWatch();
      if (presenceOf(fresh) === 'present') {
        completeStep2(fresh.label, (fresh.advisor && fresh.advisor.version) || null);
        return;
      }
      setAttach(false);
      if ($('aaAttachRow')) $('aaAttachRow').hidden = true;
      said(null);
      watchVerdict('wait', 'Watching this dashboard for its own Advisor. This page moves on by itself '
        + 'once it answers (checked every ten seconds).');
      return;
    }
    // A peer whose row already carries an Advisor is attached: nothing left
    // for this card to do with it.
    if (fresh.advisor_attached) {
      completeStep2(fresh.label, (fresh.advisor && fresh.advisor.version) || null);
      return;
    }
    if (watchWanted()) startWatch(fresh.label);
    else stopWatch();
  }

  /** Step 2 folds, with the build stamp the node actually reported.
   *
   *  `version` is passed in rather than read off the overview row, and that
   *  is the fix for a stamp that was usually missing: a peer's Advisor is
   *  DECLARED on this side, so `n.advisor.version` is null on the very node
   *  this card is about until a later poll has read it. The attach's own 200
   *  carries what that node answered, and the watch carries it before that,
   *  so the stamp is on the row the moment it folds. */
  function completeStep2(label, version) {
    if (STEP2_DONE) return;
    STEP2_DONE = true;
    stopWatch();
    var n = byTarget(PICKED) || byTarget(label) || { label: label };
    var stamp = version ? ' · build ' + esc(version) : '';
    paintStep(2, 'done', { picked: 'Advisor installed on ' + esc(displayLabel(n)) + stamp, word: 'done' });
    paintStep(3, 'now', { word: 'now' });
    paintStep3(n);
  }

  // ── Step 3: hand off to Advisor AI model ──────────────────────────

  function paintStep3(n) {
    var label = displayLabel(n);
    var lead = $('aaStep3Lead');
    if (lead) {
      lead.textContent = label + '’s Advisor is running but can’t answer questions until it has the '
        + 'fleet’s model. This opens Advisor AI model with ' + label + ' highlighted.';
    }
    var btn = $('aaModelBtn');
    if (btn) btn.textContent = 'Give ' + label + ' the fleet’s model';
    paintWindow(n);
  }

  // ── The sealing window on THIS aggregator (#1182) ──────────────────
  //
  // Bringing a node up to date moves the fleet's key, and the aggregator
  // does that only while root has a window open on it. The overview already
  // says whether one is open (self.arm, the same read the server's own
  // refusal makes) and the command that opens one (arm_self_command, built
  // by the function that builds the refusal's sentence), so the walk does not
  // end in a refusal about a step it never numbered. It is read here, never
  // asked for: no request goes out because this is painted.
  //
  // It is a different window from the one on the node. Opening the node's
  // does not open this one, and an operator who just did the first read the
  // refusal as a window that had lapsed.
  var WINDOW_KEY = null;

  function readClock(ms) {
    var d = new Date(ms);
    var pad = function (x) { return (x < 10 ? '0' : '') + x; };
    return pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds());
  }

  function paintWindow(n) {
    var box = $('aaStep3Window');
    if (!box) return;
    var ov = OVERVIEW || {};
    var cmd = typeof ov.arm_self_command === 'string' && ov.arm_self_command ? ov.arm_self_command : null;
    // No fleet broker here: the catch-up refuses for that first, with its
    // own sentence, and a window line would promise a road that is shut.
    if (!cmd) { box.hidden = true; box.textContent = ''; WINDOW_KEY = null; return; }
    var arm = ov.self && ov.self.arm;
    var host = (ov.self && ov.self.label) || 'this aggregator';
    var other = n.is_self ? ''
      : ' This is a different window from the one on ' + displayLabel(n) + ', and that one does not stand in for it.';
    var key, html, readHtml;
    readHtml = '<span class="dim aa-winread">Read at <span id="aaWinRead">' + esc(readClock(OVERVIEW_AT)) + '</span>.</span>';
    if (!arm || typeof arm.armed !== 'boolean') {
      key = 'unread';
      html = '<div class="an-verdict an-v-warn"><span class="an-dot">▲</span><span>This page could not read '
        + 'whether ' + esc(host) + ' has a sealing window open. Bringing ' + esc(displayLabel(n))
        + ' up to date needs one, and the button will say if there is none.' + other + ' ' + readHtml + '</span></div>';
    } else if (arm.armed) {
      var left = Number(arm.remaining_s) || 0;
      var m = Math.floor(left / 60);
      key = 'open:' + (m >= 1 ? m + 'm' : 'under');
      html = '<div class="an-verdict an-v-ok"><span class="an-dot">✓</span><span>A sealing window is open on '
        + esc(host) + ', ' + (m >= 1 ? 'about ' + m + ' min left' : 'under a minute left')
        + '. Bringing ' + esc(displayLabel(n)) + ' up to date needs it.' + other
        + ' ' + readHtml + '</span></div>';
    } else {
      var mins = Math.round((Number(arm.window_s) || 900) / 60);
      key = 'closed:' + cmd + ':' + mins;
      html = '<div class="an-verdict an-v-warn"><span class="an-dot">▲</span><span>Before you press it: '
        + 'bringing ' + esc(displayLabel(n)) + ' up to date needs a sealing window open on ' + esc(host)
        + ', and there is none. Only root can open one, at the console or over ssh on ' + esc(host)
        + ', never from this page. It stays open ' + mins + ' minutes.' + other + ' ' + readHtml + '</span></div>'
        + '<div id="aaWinCmd"></div>';
    }
    box.hidden = false;
    // The ten-second poll calls this again. Rewriting identical markup would
    // drop the focus on the copy button, so only the read time moves while
    // the state under it has not.
    key += ':' + n.label;
    if (key !== WINDOW_KEY) {
      WINDOW_KEY = key;
      box.innerHTML = html;
      if (key.indexOf('closed:') === 0) cmdInto($('aaWinCmd'), cmd);
    } else {
      var at = $('aaWinRead');
      if (at) at.textContent = readClock(OVERVIEW_AT);
    }
  }
  if ($('aaModelBtn')) {
    $('aaModelBtn').addEventListener('click', function () {
      if (!PICKED) return;
      if (window.ApSettingsModel && window.ApSettingsModel.openForNode) {
        window.ApSettingsModel.openForNode(PICKED);
      }
    });
  }

  // ── The header summary, and step 3 unlocking as a node's own presence
  //    flips underneath a step that is not the OPEN one (a node picked
  //    earlier this session, watched, then left while another tab was
  //    open) ──────────────────────────────────────────────────────────

  function render() {
    var card = $('setAddAdvisor');
    if (!card) return;
    var cand = candidates();
    var sub = $('aaSub');
    if (sub) {
      // Observed, never asserted. presenceOf() reads one field, and for a
      // peer that field is the fleet registry's own declaration (ADR 0016
      // decision 7), not a probe of that box -- so "has no Advisor" is a
      // claim this page cannot make. It can say what it has seen, which
      // stays true after the operator installs one and nothing here moves.
      // Self is probed live and this wording is still correct for it, so the
      // mixed list keeps one phrasing rather than two.
      sub.textContent = cand.length === 0
        ? 'This page sees an Advisor on every node.'
        : 'No Advisor seen on ' + cand.length + (cand.length === 1 ? ' node: ' : ' nodes: ')
          + cand.map(displayLabel).join(', ') + '.';
    }
    var empty = $('aaEmpty');
    var flow = $('aaFlow');
    if (cand.length === 0 && !PICKED) {
      if (empty) empty.hidden = false;
      if (flow) flow.hidden = true;
      return;
    }
    if (empty) empty.hidden = true;
    if (flow) flow.hidden = false;

    // A deep link (or a fresh pick) names a node this page has not yet had
    // OVERVIEW for. Apply it once OVERVIEW says it exists, then forget it --
    // re-applying on every later poll would fight an operator's own "change".
    if (WANT_LABEL !== null) {
      var target = WANT_LABEL;
      WANT_LABEL = null;
      var found = byTarget(target);
      if (found && noAdvisor(found) && !leaving(found)) { pick(target); return; }
    }

    renderPickCards();
    if (PICKED) {
      var picked = byTarget(PICKED);
      // #859: a node picked here and then revoked is not one to install on.
      if (picked && leaving(picked)) { reopenStep1(); return; }
      if (picked && !STEP2_DONE) paintWatch(picked);
      else if (picked && STEP2_DONE) paintStep3(picked);
    }
  }

  // ── Boot ─────────────────────────────────────────────────────────
  //
  // No fetch of its own: settings.html hands this file the same overview
  // object its own load() and refresh() already read.

  function init(ov) { setSharedOverview(ov); }

  // node is the self label or a peer's fleet label, from the deep link
  // (#add-advisor&node=<label>) or the Advisor tab's own hash. A label this
  // dashboard does not know, or one that already has an Advisor, opens the
  // section without preselecting anything, rather than guessing.
  function openAndScroll(ov, node) {
    if (ov) OVERVIEW = ov;
    if (node) {
      var self = OVERVIEW && OVERVIEW.self;
      WANT_LABEL = (self && self.label === node) || node === 'self' ? 'self' : node;
    }
    render();
    var d = $('setAddAdvisor');
    if (d) {
      d.open = true;
      d.scrollIntoView({ block: 'start' });
    }
  }

  window.ApAddAdvisor = {
    init: init, openAndScroll: openAndScroll, setOverview: setSharedOverview,
    // #641 review: where settings.html's shared node ceremony writes its
    // working line and its confirmation when it is driven from this card.
    verdictSlot: 'aaVerdict',
  };
})();
