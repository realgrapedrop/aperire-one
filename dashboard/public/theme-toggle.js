// The light/dark switch, and the one place that knows how a theme is stored.
//
// Loaded by every page including login, which has no header and no
// mobile-nav.js, so this file finds its own mount rather than assuming one.
//
// The attribute is NOT set here. It is set by a tiny inline script in each
// page's <head>, before the parser reaches the stylesheet, because anything
// deferred to a file would land after the first paint and the operator would
// see a frame of the wrong theme on every load. This file only draws the
// button, reflects the current state, and writes the change. Read
// theme-boot.js's comment for the other half.
(function () {
  'use strict';

  var KEY = 'aperire-theme';
  var root = document.documentElement;
  // The attribute that gives a header control its hover help. See the
  // popover block below.
  var TIP = 'data-hdr-tip';

  // The attribute always names the theme. It is never removed for dark:
  // "absent or dark" would be an ambiguity the boot script, this file and
  // every test would have to keep agreeing about, and seven pages already
  // shipped a hardcoded data-theme="dark" that nothing read.
  function current() {
    return root.getAttribute('data-theme') === 'light' ? 'light' : 'dark';
  }

  // localStorage throws rather than returns null in a few real situations:
  // Safari's private mode historically, and any embed a browser decides is
  // third-party storage. A theme is a convenience, so every access is
  // wrapped and a failure costs the operator persistence, never the page.
  function store(theme) {
    try { localStorage.setItem(KEY, theme); } catch { /* not fatal */ }
  }

  function apply(theme, persist) {
    root.setAttribute('data-theme', theme === 'light' ? 'light' : 'dark');
    if (persist) store(theme);
    reflect();
    // The shell (index.html) renders each tab in a same-origin iframe. Its
    // document has its own <html> and read the stored value at ITS load, so
    // a toggle after that point has to reach in. Without this the shell
    // flips and the tab under it stays as it was, which is the mixed-theme
    // render this whole feature has to not produce.
    propagateToFrames(theme);
    try {
      window.dispatchEvent(new CustomEvent('aperire:themechange', { detail: { theme: theme } }));
    } catch { /* CustomEvent is everywhere we run; belt only */ }
  }

  function propagateToFrames(theme) {
    var frames = document.querySelectorAll('iframe');
    for (var i = 0; i < frames.length; i++) {
      try {
        var d = frames[i].contentDocument;
        if (!d || !d.documentElement) continue;      // not loaded, or cross-origin
        d.documentElement.setAttribute('data-theme', theme === 'light' ? 'light' : 'dark');
      } catch { /* cross-origin: not ours to theme */ }
    }
  }

  function reflect() {
    var light = current() === 'light';
    var btns = document.querySelectorAll('.theme-toggle');
    for (var i = 0; i < btns.length; i++) {
      var b = btns[i];
      // The button offers the OTHER theme, so that is what it must be
      // labelled with. Labelling it with the current one reads as a status
      // light and an operator clicks expecting nothing to happen.
      b.setAttribute('aria-pressed', light ? 'true' : 'false');
      // Hover help is the header popover below, never a native title=.
      b.setAttribute(TIP, light ? 'Switch to dark' : 'Switch to light');
      b.setAttribute('aria-label', light ? 'Switch to dark theme' : 'Switch to light theme');
      var sun = b.querySelector('.theme-icon-sun');
      var moon = b.querySelector('.theme-icon-moon');
      if (sun)  sun.style.display  = light ? 'none' : '';
      if (moon) moon.style.display = light ? '' : 'none';
    }
  }

  function button() {
    var b = document.createElement('button');
    b.type = 'button';
    b.className = 'theme-toggle';
    b.id = 'themeToggle';
    b.innerHTML =
      '<svg class="theme-icon-sun" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">' +
        '<path d="M8 11a3 3 0 1 1 0-6 3 3 0 0 1 0 6zm0-1a2 2 0 1 0 0-4 2 2 0 0 0 0 4z"/>' +
        '<path d="M8 0a.5.5 0 0 1 .5.5v1.5a.5.5 0 0 1-1 0V.5A.5.5 0 0 1 8 0zm0 13a.5.5 0 0 1 .5.5v1.5a.5.5 0 0 1-1 0v-1.5A.5.5 0 0 1 8 13zM16 8a.5.5 0 0 1-.5.5H14a.5.5 0 0 1 0-1h1.5A.5.5 0 0 1 16 8zM3 8a.5.5 0 0 1-.5.5H1a.5.5 0 0 1 0-1h1.5A.5.5 0 0 1 3 8zm10.657-5.657a.5.5 0 0 1 0 .707l-1.06 1.06a.5.5 0 1 1-.708-.706l1.061-1.061a.5.5 0 0 1 .707 0zM4.111 11.889a.5.5 0 0 1 0 .707L3.05 13.657a.5.5 0 0 1-.707-.707l1.06-1.061a.5.5 0 0 1 .708 0zm9.546 1.768a.5.5 0 0 1-.707 0l-1.06-1.06a.5.5 0 0 1 .706-.708l1.061 1.061a.5.5 0 0 1 0 .707zM4.111 4.111a.5.5 0 0 1-.707 0L2.343 3.05a.5.5 0 1 1 .707-.707l1.061 1.06a.5.5 0 0 1 0 .708z"/>' +
      '</svg>' +
      '<svg class="theme-icon-moon" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true" style="display:none">' +
        '<path d="M6.25 1.5a6.5 6.5 0 1 0 8.25 8.25A5.5 5.5 0 0 1 6.25 1.5zm-.72 1.53a4.5 4.5 0 1 0 7.44 7.44A6.5 6.5 0 0 1 5.53 3.03z"/>' +
      '</svg>';
    b.addEventListener('click', function () {
      apply(current() === 'light' ? 'dark' : 'light', true);
    });
    return b;
  }


  // ── Does APERIRE ONE fit? ────────────────────────────────────────────
  //
  // It used to be answered by a breakpoint: below 420px the word ONE was
  // dropped. That number was calibrated to the longest username anyone
  // had, so every operator with a shorter one lost the brand's name to
  // make room for space that was never used. Reported as a wide empty gap
  // between APERIRE and this button.
  //
  // So it is measured instead. The brand is clipped to its own box (the
  // CSS backstop that makes an overlap impossible), which means
  // scrollWidth exceeding clientWidth is the browser telling us, exactly,
  // that the wordmark did not fit the space the row gave it. ONE drops
  // only then, and only as a whole word: never an ellipsized APERIRE O.
  //
  // Every call re-measures from the full lockup, so this recovers as well
  // as it degrades. Rotate the phone, sign in as someone with a shorter
  // name, close a break-glass window, and ONE comes back.
  //
  // This lives here rather than in a page because theme-toggle.js is
  // already on all nine, already runs at the end of parse, and already
  // inserts a control into this exact row. One file that touches the
  // header is better than eight copies of a measurement.
  function fitBrand() {
    var brand = document.querySelector('nav.tabs .brand');
    if (!brand) return;
    // Measured on .brand-text, NOT on .brand. .brand also contains
    // .brand-tip, the hover explainer, which is position:absolute and
    // 340px wide, and an absolutely positioned child still counts toward
    // its scroll container's scrollWidth. Measuring the parent asked "is
    // the tooltip wider than the header", which is always yes, so ONE was
    // dropped at every width on every page. Same phantom-extent trap as
    // the 320px page overflow in #133. .brand-text holds the two words
    // and nothing else.
    var text = brand.querySelector('.brand-text');
    if (!text || !text.querySelector('.brand-one')) return;
    // Always ask the question about the FULL wordmark. Measuring while
    // ONE is already hidden would answer a different question and the
    // answer would latch: it would never come back.
    brand.removeAttribute('data-fit');
    // Reading scrollWidth forces the layout, so the measurement below is
    // of the line above, not of whatever was there before it.
    var overflows = text.scrollWidth > text.clientWidth + 0.5;
    if (overflows) brand.setAttribute('data-fit', 'short');
    // No paint can happen between those two writes: they are one task.
  }

  // The row's width changes after the page has painted, and not because
  // of the viewport. #authPillName ships as an em dash and is filled once
  // /auth/session answers, which on the shell turns roughly one character
  // into about 134px, the widest thing in the header. A measurement taken
  // only at load would be a measurement of a header that does not exist
  // yet. So the boxes that take room away from the wordmark are watched,
  // and so is the row itself for rotation and resize.
  //
  // #fleetChipWrap is the one that made this a bug rather than a nicety.
  // It ships `hidden` and fleet-chip.js unhides it when /api/fleet
  // answers, and on every tab page it sits in the SAME grid row as the
  // brand (`grid-column: 2`). Measured at 390px: the chip goes 0 to
  // 144.8px, the brand's cell 148.4 to 115.2, and .brand-text's
  // clientWidth 117 to 84 while its scrollWidth stays 117. Neither nav
  // (378x28) nor .right-group (106x28) changes by a pixel when that
  // happens, so the two boxes watched before this could not see it: the
  // header simply kept the ONE it had decided on and clipped it to
  // "APERIRE ON" for the rest of the session. Whether it happened at all
  // was a race between that fetch and this file's first measurement,
  // which is why #207 failed on a different set of pages every run.
  //
  // Deliberately NOT observing .brand, .brand-text or .tabs-spacer. The
  // first two are what fitBrand changes (clientWidth 84 with ONE shown,
  // 75 without), and the spacer is the flexible filler that absorbs
  // whatever the brand gives up, so it mirrors them one hop removed. Any
  // of the three would turn this into a feedback loop that re-measures
  // every frame. Every box below is independent of the wordmark.
  function watchBrandFit() {
    if (typeof ResizeObserver !== 'function') return;   // ancient browser: the clip still holds
    var nav = document.querySelector('nav.tabs');
    if (!nav) return;
    var pending = false;
    var ro = new ResizeObserver(function () {
      // Coalesce: a resize fires per observed box and per frame, and
      // fitBrand writes to the DOM. One measurement per frame is enough.
      if (pending) return;
      pending = true;
      requestAnimationFrame(function () { pending = false; fitBrand(); });
    });
    ro.observe(nav);
    // A display:none target reports 0x0 at first and fires when it gets a
    // box, which is exactly the transition the fleet chip makes.
    ['.right-group', '#fleetChipWrap', '#navBg'].forEach(function (sel) {
      var e = nav.querySelector(sel);
      if (e) ro.observe(e);
    });
  }

  // ── Header hover help ────────────────────────────────────────────────
  //
  // The header's icon controls need a name on hover, and the project's rule
  // is the popover, never a native title=: a title waits about two seconds,
  // does nothing on a phone, and is not styled. Any element carrying
  // data-hdr-tip gets one, so a control (or idle-tracker.js, which turns the
  // account pill into "Session idle, tap to stay signed in") only sets an
  // attribute.
  //
  // One shared element, not one per control. It is appended to <body> and
  // placed with position:fixed from the control's rect, so no header
  // overflow can clip it, it adds no scroll extent when hidden (the #133
  // trap that centred resting tips fall into on the right edge), and the
  // markup of eleven pages does not change. It is text only and keeps
  // pointer-events:none, so a pointer can never land on it instead of the
  // button underneath.
  //
  // How it opens:
  //   mouse     hover (pointerover/out; touch's own pointer events are
  //             ignored, because a phone fires pointerover on a tap and the
  //             tip would stay up with nothing to dismiss it)
  //   keyboard  focus-visible only, so a mouse click's focus does not matter
  //   touch     a tap. WebKit does not focus a button on tap, so :focus
  //             cannot be the trigger. It closes after a moment, on a tap
  //             elsewhere, on scroll or on Escape.
  // A control whose tap already does something else the operator is reading
  // the result of (the account pill opens its menu, or keeps the session
  // signed in) carries data-hdr-tip-notap: it still opens on hover and
  // focus, and a tap just does its job.
  //
  // When the header is hidden (a tab embedded in the shell) its controls
  // cannot be hovered, focused or tapped, so nothing here ever runs.
  var TIP_ID = 'hdrTip';
  var TIP_TOUCH_MS = 2600;
  var tipEl = null, tipAnchor = null, tipTimer = 0, tipObs = null, lastPointer = '';

  function tipOwner(el) {
    return el && el.closest ? el.closest('[' + TIP + ']') : null;
  }

  function tipNode() {
    if (tipEl) return tipEl;
    tipEl = document.createElement('div');
    tipEl.id = TIP_ID;
    tipEl.className = 'hdr-tip';
    tipEl.setAttribute('role', 'tooltip');
    document.body.appendChild(tipEl);
    return tipEl;
  }

  // Right edge of the tip on the right edge of the control (every header
  // control sits at the right or near it), pulled inside the viewport, below
  // the control, or above it when there is no room below.
  function tipPlace() {
    if (!tipEl || !tipAnchor) return;
    var r = tipAnchor.getBoundingClientRect();
    var vw = document.documentElement.clientWidth;
    var vh = window.innerHeight;
    var gap = 8, margin = 8;
    var w = tipEl.offsetWidth, h = tipEl.offsetHeight;
    var left = Math.min(r.right - w, vw - w - margin);
    if (left < margin) left = margin;
    var top = r.bottom + gap;
    if (top + h > vh - margin && r.top - gap - h >= margin) top = r.top - gap - h;
    tipEl.style.left = Math.round(left) + 'px';
    tipEl.style.top = Math.round(top) + 'px';
  }

  function tipClose() {
    clearTimeout(tipTimer);
    tipTimer = 0;
    if (tipObs) { tipObs.disconnect(); tipObs = null; }
    if (tipAnchor) tipAnchor.removeAttribute('aria-describedby');
    tipAnchor = null;
    if (tipEl) tipEl.classList.remove('is-open');
  }

  function tipOpen(a, autoClose) {
    var text = a.getAttribute(TIP);
    if (!text) { tipClose(); return; }
    if (tipAnchor && tipAnchor !== a) tipClose();
    clearTimeout(tipTimer);
    tipTimer = 0;
    var el = tipNode();
    el.textContent = text;
    tipAnchor = a;
    a.setAttribute('aria-describedby', TIP_ID);
    tipPlace();
    el.classList.add('is-open');
    // The text changes under an open tip: the theme button flips its label on
    // the click that opened it, and the account pill swaps in the idle
    // warning. Follow the attribute rather than make each caller poke us.
    if (tipObs) tipObs.disconnect();
    if (typeof MutationObserver === 'function') {
      tipObs = new MutationObserver(function () {
        var t = a.getAttribute(TIP);
        if (!t) { tipClose(); return; }
        tipEl.textContent = t;
        tipPlace();
      });
      tipObs.observe(a, { attributes: true, attributeFilter: [TIP] });
    }
    if (autoClose) tipTimer = setTimeout(tipClose, TIP_TOUCH_MS);
  }

  function bindTips() {
    var opts = true;   // capture: runs before a control's own handlers can stop the event
    document.addEventListener('pointerdown', function (e) {
      lastPointer = e.pointerType || '';
      if (tipAnchor && !tipAnchor.contains(e.target)) tipClose();
    }, opts);
    document.addEventListener('pointerover', function (e) {
      if (e.pointerType === 'touch') return;
      var a = tipOwner(e.target);
      if (a) tipOpen(a, false);
    }, opts);
    document.addEventListener('pointerout', function (e) {
      if (e.pointerType === 'touch' || !tipAnchor) return;
      if (tipAnchor.contains(e.relatedTarget)) return;
      if (tipAnchor.contains(e.target)) tipClose();
    }, opts);
    document.addEventListener('focusin', function (e) {
      var a = tipOwner(e.target);
      if (!a) return;
      var visible = false;
      try { visible = a.matches(':focus-visible'); } catch { /* old engine: no tip on focus */ }
      if (visible) tipOpen(a, false);
    }, opts);
    document.addEventListener('focusout', function (e) {
      if (tipAnchor && tipAnchor.contains(e.target)) tipClose();
    }, opts);
    document.addEventListener('click', function (e) {
      var kind = e.pointerType !== undefined ? e.pointerType : lastPointer;
      if (kind !== 'touch') return;
      var a = tipOwner(e.target);
      if (!a || a.hasAttribute('data-hdr-tip-notap')) return;
      tipOpen(a, true);
    }, opts);
    document.addEventListener('keydown', function (e) {
      lastPointer = '';
      if (e.key === 'Escape') tipClose();
    }, opts);
    window.addEventListener('scroll', tipClose, opts);
    window.addEventListener('resize', tipClose);
    window.addEventListener('blur', tipClose);
  }


  function mount() {
    if (document.getElementById('themeToggle')) return;
    var b = button();
    // Left of the music toggle, sized to it, which is what the operator
    // asked for and what the header's own CSS gives it for free by matching
    // .audio-toggle's box.
    var audio = document.getElementById('audio-toggle');
    if (audio && audio.parentNode) {
      audio.parentNode.insertBefore(b, audio);
      return;
    }
    // Login has neither a header nor a music toggle. It gets its own corner
    // rather than nothing: the operator meets this page before any other,
    // and a sign-in that cannot follow the theme they chose is the first
    // thing they would notice.
    var solo = document.getElementById('themeToggleMount');
    if (solo) { solo.appendChild(b); return; }
    var group = document.querySelector('.right-group');
    if (group) group.insertBefore(b, group.firstChild);
  }

  function start() {
    mount();
    reflect();
    bindTips();
    // Same task as the mount, so the row is measured in the shape it will
    // paint in: this button is inserted by the line above, and measuring
    // before it existed would answer for a narrower row than the operator
    // ever sees.
    fitBrand();
    watchBrandFit();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', start);
  } else {
    start();
  }

  // A tab opened in a second window is the same operator. Following the
  // change there costs one listener and stops the two disagreeing.
  window.addEventListener('storage', function (e) {
    if (e.key !== KEY) return;
    apply(e.newValue === 'light' ? 'light' : 'dark', false);
  });

  // The shell swaps tabs by pointing one iframe at a new document, which
  // loads with whatever the stored value says and needs no help. This covers
  // the other order: a frame that finishes loading while the operator has
  // already toggled, where the stored value and the live attribute agree but
  // the new document has not been told.
  window.addEventListener('load', function () { propagateToFrames(current()); });

  window.aperireTheme = { current: current, apply: apply, KEY: KEY, fitBrand: fitBrand };
})();
