// Aperire — operator idle-tracking + auto-lock (Phase A3).
//
// Loaded by the shell (index.html) AND every iframe tab page. Behavior
// branches on whether we're in the top window:
//
// Both branches also honour a page's idle HOLD (see `holding` below): a tab
// that is showing live work refreshes the session while that work lasts, so
// watching a run is not the same as having walked away.
//
//   - Iframe tabs (window !== window.top):
//       Listen for real input events (mousemove / keydown / scroll /
//       click). Debounced to once per 30 s, POST /auth/touch with the
//       X-Aperire-CSRF header so the server bumps last_activity_at.
//       That's it — no polling, no notice. Each tab page just signals
//       "operator is here."
//
//   - Shell (window === window.top):
//       Same touch behavior PLUS a 15-second poll of /auth/session that
//       drives the idle warning and the lock-on-expiry redirect.
//
//       The warning folds into the account chip in the header: on
//       idle_warning the chip turns amber and reads "Stay signed in · Ns";
//       a tap extends the session. That keeps the header uncluttered and
//       never overlaps the brand or the menu on a phone — the old centered
//       toast used to land right on top of them. A directly-opened tab page
//       (top window, but no shell chip) falls back to a bottom-anchored
//       notice so that case still gets a heads-up rather than a silent lock.
//
// Background-tab note: when document.hidden is true we stop polling
// (saves CPU + network) and reset on visibilitychange so the operator
// gets a fresh check the moment they come back to the tab.

(function () {
  'use strict';

  var TOUCH_DEBOUNCE_MS = 30 * 1000;
  var POLL_INTERVAL_MS  = 15 * 1000;
  var lastTouch = 0;
  var isShell = (window === window.top);

  // Single fire-and-forget POST to /auth/touch. The CSRF header is
  // required server-side; without it the request 403s.
  function postTouch() {
    var now = Date.now();
    if (now - lastTouch < TOUCH_DEBOUNCE_MS) return;
    lastTouch = now;
    fetch('/auth/touch', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-aperire-csrf': '1' },
      credentials: 'include',
      body: '{}',
    }).catch(function () { /* network blip — ignore */ });
  }

  // Real operator input events. Anything passive enough not to fire
  // on background renders. wheel + touchstart cover mobile + trackpad
  // gestures that don't always emit mousemove.
  var INPUT_EVENTS = ['mousemove', 'keydown', 'scroll', 'click', 'wheel', 'touchstart'];
  INPUT_EVENTS.forEach(function (ev) {
    document.addEventListener(ev, postTouch, { passive: true, capture: true });
  });

  // ── holds: present, but not typing ───────────────────────────────────
  //
  // Idle is measured from the last INPUT, which is right for an operator who
  // walked away and wrong for one watching a twenty-minute resync play out.
  // Watching counts as being here, and the operator it locked out was
  // mid-ceremony.
  //
  // A page says so by defining window.__aperireIdleHold — advisor.html does,
  // for a live run, an open break-glass window, or a question in flight, each
  // of them bounded so a hold cannot outlive the thing holding it. Everything
  // else on the dashboard defines nothing and behaves exactly as before.
  //
  // The expiry itself is the server's (last_activity_at on the session), so a
  // hold cannot defer the lock honestly — it refreshes the session, the same
  // thing a keystroke would have done, on the same terms. Nothing here can
  // switch the lock off: an idle page with nothing held still locks.
  var HOLD_TICK_MS  = 10 * 1000;   // how often the hold is re-read
  var HOLD_TOUCH_MS = 60 * 1000;   // how often a hold refreshes the session
  var lastHoldTouch = 0;

  function holding() {
    // A page that throws here must not take input-tracking down with it —
    // this file loads on all eight tabs and only one of them defines a hold.
    try {
      return typeof window.__aperireIdleHold === 'function' &&
        window.__aperireIdleHold() === true;
    } catch { return false; }
  }

  setInterval(function () {
    if (!holding()) return;
    var now = Date.now();
    if (now - lastHoldTouch < HOLD_TOUCH_MS) return;
    lastHoldTouch = now;
    // A hold is not input, and the input debounce must not swallow it: a
    // ceremony that began with a click would otherwise have its first hold
    // tick discarded for being too soon after that click.
    lastTouch = 0;
    postTouch();
  }, HOLD_TICK_MS);

  if (!isShell) return;

  // ── Shell-only beyond this point ─────────────────────────────────

  // A single amber warning glyph, reused by both the chip and the fallback.
  var WARN_SVG = '<svg viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">' +
    '<path d="M8 1.6 15 14H1L8 1.6zm0 4.1a.82.82 0 0 0-.82.82v3.05a.82.82 0 0 0 1.64 0V6.52A.82.82 0 0 0 8 5.7zm0 5.7a.98.98 0 1 0 0 1.96.98.98 0 0 0 0-1.96z"/></svg>';

  // Extend the session and clear the warning. Shared by the chip tap and the
  // fallback button. Forces the next postTouch to actually fire (the debounce
  // would otherwise swallow it), then re-polls so the cleared state shows at
  // once rather than up to 15 s later.
  function staySignedIn() {
    lastTouch = 0;
    postTouch();
    hideWarn();
    setTimeout(poll, 250);
  }

  // One <style> for both presentations, injected once, on tokens so it
  // tracks the dashboard's palette instead of the hard-coded amber the old
  // toast carried.
  var styleInjected = false;
  function injectStyle() {
    if (styleInjected) return;
    styleInjected = true;
    var st = document.createElement('style');
    st.textContent =
      '.auth-pill.is-idle-warn{border-color:var(--amber);background:var(--amber-soft);color:var(--amber);' +
        'animation:aperireIdlePulse 1.7s ease-in-out infinite;}' +
      '.auth-pill.is-idle-warn:hover{color:var(--amber);border-color:var(--amber);background:var(--amber-soft);}' +
      '.auth-pill.is-idle-warn>svg{display:none;}' +
      '.auth-pill.is-idle-warn .name{display:none;}' +
      '.auth-pill-idle{display:inline-flex;align-items:center;gap:6px;white-space:nowrap;}' +
      '.auth-pill-idle svg{width:12px;height:12px;flex-shrink:0;}' +
      '.auth-pill-idle b{font-variant-numeric:tabular-nums;font-weight:700;}' +
      '#aperire-idle-toast{position:fixed;bottom:calc(env(safe-area-inset-bottom,0px) + 16px);left:50%;' +
        'transform:translateX(-50%);z-index:9999;max-width:calc(100vw - 24px);' +
        'background:var(--surface,#161b22);color:var(--text,#e6edf3);' +
        'border:1px solid var(--amber,#d29922);border-radius:999px;padding:9px 10px 9px 15px;' +
        'font-family:var(--mono,ui-monospace,monospace);font-size:12.5px;line-height:1.3;' +
        'box-shadow:0 10px 30px rgba(0,0,0,0.5);display:flex;align-items:center;gap:10px;' +
        'pointer-events:auto;animation:aperireToastIn 200ms ease-out;}' +
      '#aperire-idle-toast .it-lead{display:inline-flex;align-items:center;gap:7px;color:var(--amber,#d29922);}' +
      '#aperire-idle-toast .it-lead svg{width:13px;height:13px;flex-shrink:0;}' +
      '#aperire-idle-toast b{font-variant-numeric:tabular-nums;}' +
      '#aperire-idle-stay{background:var(--amber,#d29922);color:#1a1207;border:0;padding:5px 13px;' +
        'border-radius:999px;font-size:12px;font-weight:600;cursor:pointer;font-family:inherit;flex-shrink:0;}' +
      '@keyframes aperireIdlePulse{0%,100%{opacity:1}50%{opacity:.6}}' +
      '@keyframes aperireToastIn{from{opacity:0;transform:translate(-50%,12px);}to{opacity:1;transform:translate(-50%,0);}}' +
      '@media (prefers-reduced-motion:reduce){.auth-pill.is-idle-warn{animation:none}#aperire-idle-toast{animation:none}}';
    document.head.appendChild(st);
  }

  // ── Presentation 1: the account chip (the shell, the normal case) ──
  var chip = null, chipIdle = null, chipSecs = null, chipBound = false;
  function ensureChip() {
    if (chip) return chip;
    chip = document.getElementById('auth-pill');
    if (!chip) return null;
    injectStyle();
    chipIdle = document.createElement('span');
    chipIdle.className = 'auth-pill-idle';
    chipIdle.hidden = true;
    chipIdle.innerHTML = WARN_SVG +
      '<span>Stay signed in &middot; <b id="aperire-idle-secs">--</b>s</span>';
    chip.appendChild(chipIdle);
    chipSecs = chipIdle.querySelector('#aperire-idle-secs');
    if (!chipBound) {
      chipBound = true;
      // Capture phase, so this runs before the shell's own bubble handler
      // (which opens the mobile menu). While the warning is up, a tap on the
      // chip means "stay signed in", not "open the menu"; stopImmediate
      // keeps that bubble handler from also firing.
      chip.addEventListener('click', function (ev) {
        if (!chip.classList.contains('is-idle-warn')) return;
        ev.preventDefault();
        ev.stopImmediatePropagation();
        staySignedIn();
      }, true);
    }
    return chip;
  }

  // ── Presentation 2: bottom-anchored fallback (a page with no chip) ──
  var toastEl = null, toastSecsEl = null;
  function ensureToast() {
    if (toastEl) return toastEl;
    injectStyle();
    toastEl = document.createElement('div');
    toastEl.id = 'aperire-idle-toast';
    toastEl.innerHTML =
      '<span class="it-lead">' + WARN_SVG + '<span>Session idle</span></span>' +
      '<span>Locking in <b id="aperire-idle-secs-t">--</b>s</span>' +
      '<button id="aperire-idle-stay" type="button">Stay signed in</button>';
    document.body.appendChild(toastEl);
    toastSecsEl = document.getElementById('aperire-idle-secs-t');
    document.getElementById('aperire-idle-stay')
      .addEventListener('click', staySignedIn);
    return toastEl;
  }

  // Chip when the shell has one; otherwise the fallback notice.
  function showWarn(secsRemaining) {
    var secs = String(secsRemaining);
    if (ensureChip()) {
      if (chipSecs) chipSecs.textContent = secs;
      chip.classList.add('is-idle-warn');
      chipIdle.hidden = false;
      chip.setAttribute('title', 'Session idle — tap to stay signed in');
    } else {
      ensureToast();
      if (toastSecsEl) toastSecsEl.textContent = secs;
      toastEl.style.display = 'flex';
    }
  }
  function hideWarn() {
    if (chip) {
      chip.classList.remove('is-idle-warn');
      if (chipIdle) chipIdle.hidden = true;
    }
    if (toastEl) toastEl.style.display = 'none';
  }

  function redirectToLock() {
    var path = window.location.pathname + window.location.search + window.location.hash;
    var next = encodeURIComponent(path || '/');
    window.location.href = '/login.html?next=' + next;
  }

  function poll() {
    fetch('/auth/session', { credentials: 'include' })
      .then(function (r) { return r.json().catch(function () { return null; }); })
      .then(function (j) {
        if (!j) return;
        if (!j.authed) { redirectToLock(); return; }
        if (j.idle_warning) {
          showWarn(j.secs_remaining || 0);
        } else {
          hideWarn();
        }
      })
      .catch(function () { /* network blip — ignore; next tick will retry */ });
  }

  // Pause polling when the tab is hidden — the dashboard does no useful
  // foreground work in the background, and we don't want to keep
  // bumping the API. On return, immediately re-poll so the operator
  // sees the current state.
  var pollHandle = null;
  function startPolling() {
    if (pollHandle) return;
    pollHandle = setInterval(poll, POLL_INTERVAL_MS);
    poll();
  }
  function stopPolling() {
    if (!pollHandle) return;
    clearInterval(pollHandle);
    pollHandle = null;
  }
  document.addEventListener('visibilitychange', function () {
    if (document.hidden) stopPolling();
    else startPolling();
  });
  startPolling();
})();
