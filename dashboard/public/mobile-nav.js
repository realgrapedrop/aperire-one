// Mobile nav — hamburger mechanics + the cross-tab break-glass chip.
// Loaded by every page (the shell and all seven tabs) so the interaction is
// written once. Markup contract (see the mobile-nav
// mockup and its notes): `#hamburgerBtn`, `#mobMenu`, `#scrim`, a list
// of `a.mtab` inside `#mobMenu`, and — optional, most pages have it, the
// Advisor page deliberately does not (it already carries its own live
// break-glass indicator on the drawer's FAB) — `#navBg`/`#navBgDot`/
// `#navBgText`. Any page missing the hamburger trio just skips this file's
// work; nothing here assumes every page ships every piece.
//
// What this file deliberately does NOT do: it doesn't know about tab
// routing. Standalone pages use plain `<a href="/x.html">` inside the
// dropdown and get ordinary navigation for free. The shell (index.html)
// intercepts those same clicks itself, in its own inline script, to keep the
// iframe swap in place — this file just closes the menu either way.
(function () {
  'use strict';

  var body = document.body;
  // The scroll lock below targets both html and body — on the shell
  // (index.html) html/body are already overflow:hidden unconditionally, so
  // this is a no-op there, but on the seven standalone pages the document
  // element, not the body, is what actually scrolls. A body-only class
  // left the page sliding under an open dropdown on those pages.
  var htmlEl = document.documentElement;
  var hamburger = document.getElementById('hamburgerBtn');
  var mobMenu = document.getElementById('mobMenu');
  var scrim = document.getElementById('scrim');

  // The menu's secondary rows (a.madd: ADR 0016's "Add the Advisor" pointer
  // and the Settings row injected below) are styled here, once, because this
  // file is what puts the Settings row on every page. The rules used to be
  // copied into each page's stylesheet, and the one page that never carried
  // the pointer row (the Advisor tab) had no copy, so its Settings row came
  // out as one underlined run of text (the lab aggregator, 2026-09-02). A page that
  // marks the row current (settings.html) adds to these; it does not repeat
  // them.
  if (mobMenu && !document.getElementById('maddStyle')) {
    var maddStyle = document.createElement('style');
    maddStyle.id = 'maddStyle';
    maddStyle.textContent = [
      // The same measures as a tab row (.mtab / .mtab-title / .mtab-sub in
      // each page's stylesheet), and the same 6px inset the tab list's
      // padding gives its rows, so the title, its line and its separator sit
      // flush with the rows above. The row used to be set smaller, as a
      // secondary entry, and read as an afterthought under the tabs it sits
      // with (operator, the lab aggregator, 2026-09-04).
      // The same shape as a tab row (.mtab in index.html): the two lines
      // stacked in a body, and the check mark at the right edge that the
      // current row shows. It lacked the check (operator, 2026-09-08: "there
      // is no blue checkmark. But at least highlighted").
      // The "Add the Advisor" pointer rows on the tab pages are plain .madd
      // (title over sub); .madd-row is this row's shape, body plus check.
      '.madd { display: flex; flex-direction: column; gap: 1px; margin: 0 6px;',
      '  padding: 11px 16px 11px 14px; min-height: 44px; justify-content: center;',
      '  border-top: 1px solid var(--border); text-decoration: none; }',
      '.madd.madd-row { flex-direction: row; align-items: center; gap: 10px; justify-content: flex-start; }',
      '.madd:hover, .madd:focus-visible { background: var(--surface); }',
      '.madd-body { display: flex; flex-direction: column; gap: 1px; min-width: 0; }',
      '.madd-title { font-size: 14.5px; font-weight: 600; color: var(--text); }',
      '.madd-sub { font-size: 11.5px; color: var(--text-muted); }',
      '.madd-check { margin-left: auto; flex: 0 0 auto; width: 16px; height: 16px; color: var(--accent); visibility: hidden; }',
      '.madd[aria-current="page"] .madd-check { visibility: visible; }',
      // Current, the way .mtab.active is: the accent bar and the tint. The
      // shell marks the Settings row current on its own hash, and it had no
      // rule for that mark; only settings.html opened on its own did.
      '.madd[aria-current="page"] { position: relative; background: rgba(var(--blue-rgb), 0.08); }',
      '.madd[aria-current="page"]::before { content: ""; position: absolute; left: 0; top: 6px; bottom: 6px;',
      '  width: 3px; border-radius: 0 3px 3px 0; background: var(--accent); }'
    ].join('\n');
    document.head.appendChild(maddStyle);
  }

  function focusableInMenu() {
    // a.madd is ADR 0016's "Add the Advisor" pointer row. It is a real link
    // inside this menu, so it has to be in the trap: everything listed here
    // is given tabindex="-1" while the menu is closed, and a link left out
    // stays keyboard-focusable inside an invisible menu — the exact gap the
    // aria-hidden comment in closeMenu says was closed once already.
    return Array.prototype.slice.call(mobMenu.querySelectorAll('a.mtab, a.madd, .mma-logout'));
  }

  var menuOpen = false;

  function openMenu() {
    if (menuOpen || !hamburger) return;
    menuOpen = true;
    hamburger.setAttribute('aria-expanded', 'true');
    hamburger.setAttribute('aria-label', 'Close navigation menu');
    mobMenu.classList.add('on');
    mobMenu.removeAttribute('aria-hidden');
    focusableInMenu().forEach(function (el) { el.removeAttribute('tabindex'); });
    if (scrim) scrim.classList.add('on');
    body.classList.add('menu-open');
    htmlEl.classList.add('menu-open');
    var items = focusableInMenu();
    if (items.length) items[0].focus();
  }

  // `opts.focusTarget` — an element to focus once the menu is closed. Falls
  // back to the hamburger itself (the Escape/scrim-tap path), matching the
  // mock exactly. Selecting a row passes `#content-frame` when it exists —
  // only the shell has one, so on every standalone page this call passes an
  // element that isn't there, `document.getElementById` returns null, and
  // the fallback (hamburger) takes over — which is fine, because a standalone
  // page is about to unload anyway.
  function closeMenu(opts) {
    opts = opts || {};
    if (!menuOpen || !hamburger) return;
    menuOpen = false;
    hamburger.setAttribute('aria-expanded', 'false');
    hamburger.setAttribute('aria-label', 'Open navigation menu');
    mobMenu.classList.remove('on');
    // Hidden with opacity + pointer-events (so the exit transition can play),
    // not display:none — which would otherwise leave its links keyboard-
    // focusable while invisible. aria-hidden + tabindex="-1" close that gap
    // explicitly rather than relying on the transition alone.
    mobMenu.setAttribute('aria-hidden', 'true');
    focusableInMenu().forEach(function (el) { el.setAttribute('tabindex', '-1'); });
    if (scrim) scrim.classList.remove('on');
    body.classList.remove('menu-open');
    htmlEl.classList.remove('menu-open');
    if (opts.focusTarget) opts.focusTarget.focus();
    else if (opts.returnFocus !== false) hamburger.focus();
  }

  if (hamburger && mobMenu) {
    hamburger.addEventListener('click', function () { if (menuOpen) closeMenu(); else openMenu(); });
    if (scrim) scrim.addEventListener('click', function () { closeMenu(); });

    document.addEventListener('keydown', function (e) {
      if (!menuOpen) return;
      if (e.key === 'Escape') { e.preventDefault(); closeMenu(); return; }
      if (e.key === 'Tab') {
        var items = focusableInMenu();
        if (!items.length) return;
        var first = items[0], last = items[items.length - 1];
        if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
        else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
      }
    });

    // Selecting a row always closes the menu. It does NOT preventDefault —
    // that's the shell's own job (index.html swaps the iframe instead of
    // navigating); every other page just lets the link go where it points.
    focusableInMenu().forEach(function (el) {
      el.addEventListener('click', function () {
        if (menuOpen) closeMenu({ focusTarget: document.getElementById('content-frame') || null });
      });
    });

    // Start closed, accessibly, without running the close transition.
    mobMenu.setAttribute('aria-hidden', 'true');
    focusableInMenu().forEach(function (el) { el.setAttribute('tabindex', '-1'); });
  }

  // Exposed for the shell (auto-close when a shell-side tab click swaps the
  // iframe without going through the dropdown) and for the walk script —
  // driven the same way an operator would trigger it, not by reaching past
  // the UI into private state.
  window.__mobileNav = { openMenu: openMenu, closeMenu: closeMenu, isOpen: function () { return menuOpen; } };

  // Identity + Log out, in the menu, on every page. The standalone tab pages
  // carry no auth pill of their own, and the shell's pill used to sign you
  // out on the first click — too easy to fire by accident. So who is signed
  // in is shown here, and signing out is a deliberate button rather than a
  // mis-tap. Built from the real /auth/session read, appended above the hint
  // foot; absent entirely when there is no session (the login screen).
  if (mobMenu) {
    fetch('/auth/session', { credentials: 'same-origin' })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (sess) {
        if (!sess || !sess.authed) return;
        // ── Settings, for an administrator, on every page's menu ──────
        //
        // Injected here rather than written into eight files, for the reason
        // the account row below is: one place decides, and a monitor never
        // gets the row at all. Monitors are refused by the page's own gate
        // and by its API too, so this is the affordance and not the guard.
        //
        // Placed after the tab list and before the account row, in the .madd
        // shape ADR 0016 already gave this menu a secondary row in. It is a
        // real link, so focusableInMenu() already lists a.madd and the focus
        // trap picks it up; the tabindex below matches the menu's current
        // open state, exactly as the Log out button does.
        if (sess.role === 'admin') {
          // Current on the page itself, and on the shell when its hash names
          // the route; the shell's own setActive keeps the latter true after
          // this row exists.
          var here = /\/settings\.html$/.test(location.pathname) || /^#\/settings(\?|$)/.test(location.hash);
          var set = document.createElement('a');
          set.className = 'madd madd-row';
          set.id = 'mobSettings';
          // Into the shell, like the tab rows: the shell's header carries the
          // operator pill and the audio toggle, and a page opened on its own
          // has neither.
          set.href = '/#/settings';
          if (here) set.setAttribute('aria-current', 'page');
          // The title carries the second half of what the page does: asking
          // what release is published moved off this menu and into that page
          // (operator, 2026-09-08), and a menu row that still said Settings
          // would hide it.
          //
          // The sub-line is a category, not an inventory (operator,
          // 2026-09-08: "shorten the list of things to be more general").
          // It reads like every other row's — "Health at a glance", "Peers &
          // connections" — and it names no panel, so it follows nothing and
          // cannot go stale when the page gains one.
          set.innerHTML = '<span class="madd-body"><span class="madd-title">Settings &amp; Updates</span>'
            + '<span class="madd-sub">Fleet, operators, releases</span></span>'
            + '<svg class="madd-check" width="16" height="16" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">'
            + '<path d="M13.7 3.7 6 11.4 2.3 7.7 3.7 6.3 6 8.6l6.3-6.3z"/></svg>';
          // After the tab list, under Advisor. It went to the top of the
          // menu for an hour on 2026-09-08 and came back: the operator's
          // "move it to the top" meant the Updates card inside the page,
          // not this row.
          var list = mobMenu.querySelector('ul');
          if (list && list.nextSibling) mobMenu.insertBefore(set, list.nextSibling);
          else if (list) mobMenu.appendChild(set);
          if (!menuOpen) set.setAttribute('tabindex', '-1');
          set.addEventListener('click', function () {
            if (menuOpen) closeMenu({ focusTarget: document.getElementById('content-frame') || null });
          });

          // A "Set up" row used to sit here (#135), reopening the wizard past
          // the passkey step to add a node. #585 (operator's ruling
          // 2026-09-21) folded that into Settings & Updates itself, as an
          // "Add a node" section on that page, not a second menu row
          // pointing at it, so the menu carries one settings row now, not two.
        }
        var wrap = document.createElement('div');
        wrap.className = 'mobmenu-account';
        wrap.style.cssText = 'display:flex;align-items:center;justify-content:flex-end;gap:12px;padding:11px 14px;border-top:1px solid var(--border)';
        // #4 — the "Signed in as <email>" line was removed from this menu. Who
        // is signed in is already shown in the top bar (truncated, full email
        // on hover), so the menu carries only the deliberate Log out action.
        var out = document.createElement('button');
        out.type = 'button';
        out.className = 'mma-logout';
        out.textContent = 'Log out';
        out.style.cssText = 'flex:0 0 auto;font-family:var(--mono);font-size:11px;letter-spacing:.06em;text-transform:uppercase;color:var(--red);background:transparent;border:1px solid var(--red);border-radius:6px;padding:6px 12px;cursor:pointer';
        out.addEventListener('click', function () {
          // Clear the Advisor conversations this session owns before the
          // session ends — see the shell's original lock note: a signed-out
          // dashboard must not leave questions one localStorage read away
          // from whoever sits down next.
          try {
            var s = window.localStorage;
            for (var i = s.length - 1; i >= 0; i--) {
              var k = s.key(i);
              if (k && k.indexOf('aperire.advisor.') === 0) s.removeItem(k);
            }
          } catch { /* no storage, nothing to clear */ }
          var next = encodeURIComponent(location.pathname + location.search + location.hash);
          fetch('/auth/lock', { method: 'POST', headers: { 'content-type': 'application/json', 'x-aperire-csrf': '1' }, credentials: 'include', body: '{}' })
            .finally(function () { location.href = '/login.html?next=' + next; });
        });
        wrap.appendChild(out);
        var foot = mobMenu.querySelector('.mobmenu-foot');
        if (foot) mobMenu.insertBefore(wrap, foot); else mobMenu.appendChild(wrap);
        // The new button joins the focus trap; refresh tabindex to match the
        // menu's current open/closed state.
        var ti = menuOpen ? null : '-1';
        if (ti) out.setAttribute('tabindex', ti);
      })
      .catch(function () { /* no session read — no account row, same as logged out */ });
  }

  // ── Advisor nav entry, ADR 0016 decisions 4-6 ─────────────────────────
  //
  // Both the entry and the pointer row that replaces it ship hidden and are
  // revealed on the fact. Hiding after the fetch lands would flash an Advisor
  // tab on every page load of an install that declined the Advisor, which is
  // the nag the record forbids, and it is the same race the shell already
  // documents for embedded headers.
  //
  // Keyed on `any`, NOT on `self`. This is the one place where the design
  // applied literally would remove a working feature: on an aggregator the
  // Advisor tab routes to the SUBJECT node's advisord, so an aggregator with
  // no local advisord and one node that has one is a fully working Advisor
  // tab today. Keying the entry on `self` would hide it and take the only
  // route to that node's Advisor with it.
  //
  // Hidden, never removed. The shell captures its `.tab[data-tab]` NodeList
  // once at load and writes classes to those nodes on every tab change; a
  // detached element would go on receiving them, silently, forever.
  //
  // No fact is treated as "not yet", exactly as the chip does: both stay
  // hidden and neither is claimed. The pointer row in particular must not
  // appear on a host that has an Advisor merely because one poll dropped.
  onAdvisorPresence(function (fact) {
    var navEls = document.querySelectorAll('[data-advisor-nav]');
    var ptrEls = document.querySelectorAll('[data-advisor-pointer]');
    var i;
    if (!fact) return; // no fact, no claim, and no reveal either way
    var any = !!fact.any;
    for (i = 0; i < navEls.length; i++) navEls[i].hidden = !any;
    for (i = 0; i < ptrEls.length; i++) ptrEls[i].hidden = any;
  });

  // ── Break-glass chip — ui-design.md §4.6 ──────────────────────────────
  // "Zero overhead in the ordinary (closed) case": one /auth/session read to
  // learn the role (a monitor never sees the chip — fleet-curation-ui.md
  // §1, mobile-nav-notes.md §6), then one /api/advisor/status read. Polling
  // starts ONLY if that first read finds a window already open, and stops
  // the moment it closes — never a client countdown (the real window has no
  // "tier" field yet, so unlike the design mock this chip has one visual
  // state, not four; the dot never goes ring-shaped and the border never
  // dashes, because there is nothing in the real data to tell them apart).
  var chip = document.getElementById('navBg');
  if (chip) {
    var textEl = document.getElementById('navBgText');
    var POLL_MS = 5000;
    var lastGoodPollAt = 0;
    var timer = null;

    function fmtLeft(win) {
      var msLeft = Math.max(0, new Date(win.expires_at).getTime() - Date.now());
      return Math.max(1, Math.ceil(msLeft / 60000));
    }

    function render(win) {
      if (!win || !win.open) { chip.hidden = true; chip.classList.remove('warn', 'stale'); return; }
      var stale = lastGoodPollAt > 0 && (Date.now() - lastGoodPollAt) > (2 * POLL_MS);
      chip.hidden = false;
      chip.classList.remove('warn', 'stale');
      if (stale) {
        chip.classList.add('stale');
        if (textEl) textEl.textContent = 'not answering';
        chip.setAttribute('aria-label',
          'Break glass open — the Advisor is not answering; this window may already be closed. Tap to open Advisor.');
        return;
      }
      var mins = fmtLeft(win);
      var msLeft = new Date(win.expires_at).getTime() - Date.now();
      var warn = msLeft > 0 && msLeft < 120000;
      chip.classList.toggle('warn', warn);
      if (textEl) textEl.textContent = mins + 'm';
      chip.setAttribute('aria-label',
        'Break glass open — ' + mins + ' minute' + (mins === 1 ? '' : 's') +
        ' remaining. Tap to open Advisor.');
    }

    function poll() {
      fetch('/api/advisor/status', { credentials: 'same-origin' })
        .then(function (r) { return r.ok ? r.json() : null; })
        .then(function (body) {
          var win = body && body.breakglass;
          if (win) lastGoodPollAt = Date.now();
          render(win);
          if (win && win.open) schedule();
          else stop();
        })
        .catch(function () { render(null); stop(); });
    }
    function schedule() { stop(); timer = setTimeout(poll, POLL_MS); }
    function stop() { if (timer) { clearTimeout(timer); timer = null; } }

    chip.addEventListener('click', function () {
      if (window.__mobileNav && window.__mobileNav.isOpen()) window.__mobileNav.closeMenu({ returnFocus: false });
      if (typeof window.__shellLoadTab === 'function') window.__shellLoadTab('advisor');
      else location.href = '/advisor.html';
    });

    // ── Presence first, ADR 0016 ──────────────────────────────────────
    //
    // This read used to be unconditional, which made it the clearest
    // violation of the record's central promise: a host where nobody ever
    // installed an Advisor still asked it for a break-glass window every
    // five seconds, on every page of every session, and got a 503 back. The
    // install that declined the AI made an AI-shaped request forever.
    //
    // So the fact is consulted BEFORE the session read, not after. Ordering
    // it the other way would still hide the chip, but it would spend a
    // session read to decide something already decided, and it would leave
    // the status poll one edit away from running again.
    //
    // No fact is treated exactly like absent here. Decision 4 is
    // default-hidden and revealed on the fact, never shown-then-hidden, and
    // a chip that appears and is taken away is the flash the design forbids.
    // A logged-out page 401s the presence endpoint and lands here too, which
    // is the right answer there as well.
    //
    // installed-but-down deliberately does NOT short-circuit. An Advisor
    // whose service is stopped still has windows that may be open, and the
    // chip's own `stale` rendering already says the Advisor is not
    // answering. Hiding it would be the kept-vs-observed bug wearing the
    // other face.
    // Three answers, not two, and the middle one is why this is a listener
    // rather than a one-shot decision. See onAdvisorPresence below.
    var chipArmed = false;
    onAdvisorPresence(function (fact) {
      var observed = !!(fact && fact.self);

      // OBSERVED absent. Tear down if this page had already armed, which is
      // the Advisor-removed-mid-session case: stop asking, and hide.
      // chipArmed is released so that installing one again re-arms without a
      // reload, the same progressive property the fact itself has.
      if (observed && fact.self.state === 'absent') {
        if (chipArmed) { chipArmed = false; stop(); render(null); }
        return;
      }

      // NO FACT. Decide nothing and wait for the next poll. This is not
      // absence: it is a presence read that did not land, and treating it as
      // absence would take the chip away from a host that has an Advisor
      // because one request hiccupped. An open break-glass window is exactly
      // the news this record says must not be lost.
      if (!observed) return;

      // present, or installed-but-down. Arm once.
      if (chipArmed) return;
      chipArmed = true;
      fetch('/auth/session', { credentials: 'same-origin' })
        .then(function (r) { return r.json(); })
        .then(function (sess) {
          if (sess && sess.role === 'monitor') return; // chip disappears outright, not greyed
          poll(); // one status read; schedule() only fires again if it found a window open
        })
        .catch(function () { /* no session read, no chip — same as a closed window */ });
    });
  }

  /**
   * Hand `cb` EVERY published Advisor-presence fact, including null when a
   * read could not produce one. Order-independent, and deliberately not a
   * one-shot.
   *
   * Order-independent because both this file and advisor-presence.js are
   * `defer`, so they execute in document order, and today that order puts
   * this file FIRST: the global does not exist yet when the caller above
   * runs. Depending on that order would make a correctness property of eight
   * separate HTML files a matter of which script line someone moved. So both
   * routes are here, the module's own ready() if it has already executed and
   * its first-settle event if it has not, and the module fires that event
   * exactly once on first settle whatever it found, so this cannot hang.
   *
   * Not a one-shot because deciding on the first answer is wrong twice over,
   * and both were measured rather than imagined:
   *
   *   - One failed presence poll on a host that HAS an Advisor used to
   *     suppress the break-glass chip for the life of the page. The first
   *     read settled as no-fact, the consumer decided, and the successful
   *     poll 20 seconds later had nobody left listening. That is an open
   *     break-glass window not shown because a request hiccupped, which is
   *     the ADR's own trade-off inverted.
   *   - Installing the Advisor on a running host is supposed to bring its
   *     surfaces back with no reinstall and no reload. A consumer that
   *     decided on the first absent answer would never notice.
   *
   * If advisor-presence.js is missing altogether, `cb` is never called and
   * the chip never appears. That is deliberate. Falling back to the old
   * unconditional behaviour would quietly restore the exact defect on
   * precisely the install that is hardest to notice it on.
   */
  function onAdvisorPresence(cb) {
    // Registered first, so a fact published between these two lines is not
    // dropped. The caller is idempotent, which is what lets both fire.
    window.addEventListener('aperire:advisor', function (e) { cb(e.detail); });
    if (window.__advisorPresence) window.__advisorPresence.ready(cb);
  }
})();
