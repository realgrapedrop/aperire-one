// Ambient audio toggle, one copy for the shell and every tab page (#166).
//
// The button is a preference, not a transport control. A click on a button
// that shows ON turns the audio OFF, whatever the stream is doing at that
// moment. The handler this replaces branched on whether the element had
// reached `playing`: a click while the stream was still buffering, or after
// a stall, issued play() again instead, so the button would not go off until
// the stream had come up, and every click inside that window re-armed it.
//
// The preference lives in localStorage, which every tab of this site shares.
// A tab that did not receive the click stops when it sees the key go off.
// It never starts on another tab's say-so: audio starts only where the
// operator clicked.
//
// Configured by data attributes on the script tag:
//   data-key       localStorage key (required)
//   data-default   'on' | 'off' when the key is unset (default 'off')
//   data-frame     id of an iframe whose clicks also count as the first gesture
(function () {
  // Embedded in the shell: the header is hidden, the button with it, and the
  // shell's own player is the one the operator hears. No player here.
  if (document.documentElement.hasAttribute('data-embedded')) return;
  var script = document.currentScript;
  var audioToggle = document.getElementById('audio-toggle');
  if (!script || !audioToggle) return;
  var KEY = script.getAttribute('data-key');
  if (!KEY) return;
  var DEFAULT_ON = script.getAttribute('data-default') === 'on';
  var frameId = script.getAttribute('data-frame');
  var frame = frameId ? document.getElementById(frameId) : null;

  var STREAM_URL = 'https://stream.nightride.fm/chillsynth.mp3';
  var FALLBACK_URL = 'lofi-dreams.mp3';

  function readPref() {
    var v = null;
    try { v = localStorage.getItem(KEY); } catch { /* storage blocked: the default stands */ }
    return v === 'on' ? true : v === 'off' ? false : DEFAULT_ON;
  }
  function writePref(on) {
    try { localStorage.setItem(KEY, on ? 'on' : 'off'); } catch { /* storage blocked: this tab alone */ }
  }

  var bgAudio = new Audio(STREAM_URL);
  bgAudio.volume = 0.3;
  bgAudio.preload = 'none';
  var audioEnabled = readPref();
  var isPlaying = false;
  var isUnmuted = false;

  // Stall recovery. Browsers pause live streams on buffer underrun without
  // firing `error`, so the element just stops. Watch `stalled` / `waiting`;
  // if playback has not resumed in 5s, reload the stream (a fresh HTTP
  // connection), and after three failed recoveries fall back to the local
  // loop so the music keeps going while upstream is unreachable. `playing`
  // clears the counter, so a healthy stream costs nothing.
  var stallTimer = null;
  var stallRetries = 0;
  function clearStallTimer() {
    if (stallTimer) { clearTimeout(stallTimer); stallTimer = null; }
  }
  function onStream() { return bgAudio.src.indexOf('nightride') !== -1; }
  function useFallback() {
    bgAudio.src = FALLBACK_URL;
    bgAudio.loop = true;
    bgAudio.load();
    if (isUnmuted && audioEnabled) bgAudio.play().catch(function () {});
  }
  function onStall() {
    if (stallTimer || !audioEnabled) return;
    stallTimer = setTimeout(function () {
      stallTimer = null;
      if (isPlaying || !audioEnabled) return;
      if (stallRetries < 3 && onStream()) {
        stallRetries++;
        try { bgAudio.load(); if (isUnmuted) bgAudio.play().catch(function () {}); } catch { /* no source to reload */ }
      } else if (bgAudio.src.indexOf('lofi-dreams') === -1) {
        useFallback();
      }
    }, 5000);
  }
  bgAudio.addEventListener('stalled', onStall);
  bgAudio.addEventListener('waiting', onStall);
  bgAudio.addEventListener('error', function () { if (onStream()) useFallback(); });
  bgAudio.addEventListener('playing', function () { isPlaying = true; clearStallTimer(); stallRetries = 0; });
  bgAudio.addEventListener('pause', function () { isPlaying = false; });

  function updateAudioUI() {
    audioToggle.classList.toggle('playing', audioEnabled);
    audioToggle.querySelector('.audio-icon-off').style.display = audioEnabled ? 'none' : 'block';
    audioToggle.querySelector('.audio-icon-on').style.display = audioEnabled ? 'block' : 'none';
  }

  function start() {
    if (!bgAudio.getAttribute('src')) {
      // Restore the stream after a release.
      bgAudio.src = STREAM_URL;
      bgAudio.loop = false;
      try { bgAudio.load(); } catch { /* nothing to load */ }
    }
    bgAudio.muted = false; isUnmuted = true;
    bgAudio.play().catch(function () {});
  }
  // Stop, and release the source so the browser's media service drops the
  // streaming buffer: a long-running tab with audio paused still holds it
  // while src stays assigned.
  function stop() {
    clearStallTimer();
    bgAudio.pause();
    bgAudio.removeAttribute('src');
    try { bgAudio.load(); } catch { /* nothing to load */ }
  }
  function setEnabled(on) {
    audioEnabled = on;
    if (on) start(); else stop();
    updateAudioUI();
  }

  updateAudioUI();
  if (audioEnabled) {
    // Autoplay muted (which browsers allow), unmute on the first gesture.
    bgAudio.muted = true;
    bgAudio.play().catch(function () {});
  }

  // First-gesture unmute. A click inside the framed page counts too: user
  // activation propagates through same-origin frames.
  function onFirstGesture(e) {
    if (e && audioToggle.contains(e.target)) return;
    if (!audioEnabled || isUnmuted) return;
    isUnmuted = true;
    bgAudio.muted = false;
    if (!isPlaying) bgAudio.play().catch(function () {});
    cleanupGestureListeners();
  }
  var GESTURE_EVENTS = ['mousedown', 'pointerdown', 'keydown', 'touchstart'];
  function attachGestureListeners(target) {
    if (!target) return;
    GESTURE_EVENTS.forEach(function (evt) { target.addEventListener(evt, onFirstGesture, true); });
  }
  function cleanupGestureListeners() {
    GESTURE_EVENTS.forEach(function (evt) { document.removeEventListener(evt, onFirstGesture, true); });
    try {
      if (frame && frame.contentDocument) {
        GESTURE_EVENTS.forEach(function (evt) { frame.contentDocument.removeEventListener(evt, onFirstGesture, true); });
      }
    } catch { /* the frame is cross-origin or gone */ }
  }
  attachGestureListeners(document);
  if (frame) {
    frame.addEventListener('load', function () {
      if (isUnmuted) return;
      try { attachGestureListeners(frame.contentDocument); } catch { /* not ours to listen in */ }
    });
  }

  // The click follows the button, never the stream (#166).
  audioToggle.addEventListener('click', function () {
    var on = !audioEnabled;
    writePref(on);
    setEnabled(on);
  });

  // Another tab turned it off: stop here too. (#166)
  window.addEventListener('storage', function (e) {
    if (e.key !== KEY || readPref() || !audioEnabled) return;
    setEnabled(false);
  });
})();
