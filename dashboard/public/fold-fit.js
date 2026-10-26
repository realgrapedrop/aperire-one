// ═══════════════════════════════════════════════════════════════════
// fold-fit — publish the height everything-that-is-not-a-chart occupies
// ═══════════════════════════════════════════════════════════════════
//
// The problem this solves. Every tab is a stack of fixed-height strips (metric
// cards, a quorum bar, a bar chart, a diagnostics row) with one flexible band
// at the bottom — the history charts, or a scrolling table. Sizing that band
// as a fixed slice of the viewport (`Ndvh`) cannot make the page end at the
// fold, because it scales the one part of the page that was never the problem:
// raise the coefficient and the last row is sliced harder, lower it and the
// page ends short of the bottom with dead space. What the band actually wants
// is the RESIDUAL — viewport height minus every strip above it — which is a
// number only the rendered page knows.
//
// So each page declares the residual in CSS:
//
//   .hist-svg { height: clamp(72px, calc((100dvh - var(--hist-strip, 790px)) / 2), 220px); }
//
// with a measured constant as the no-JS default, and this script keeps
// --hist-strip honest as the strips move. They do move, on their own schedule:
// Consensus draws 10px of close-timing bar per second of close time, so a
// single slow ledger shifts the strip by ~100px; a peer view swaps a live
// panel for a one-line note; a card grid rewraps on resize. A constant tuned
// for the worst of those wastes ~90px of viewport the rest of the time.
//
// Two properties make this safe to run on a live page:
//
//   * It is invariant of the thing it feeds. The flexible band's own height is
//     subtracted back out, so the answer is the same before and after the band
//     resizes — it reaches a fixed point on the first pass and cannot
//     oscillate. The 3px deadband below absorbs sub-pixel rounding.
//   * It reads the whole document, main's own offset included, so it is
//     correct both embedded in the fleet shell — where 100dvh is the frame and
//     the page header is hidden — and standalone, where 100dvh is the window
//     and that header sits in flow above main.
//
// Usage — one tag per page, after the markup it measures:
//
//   <script src="/fold-fit.js" defer
//           data-target=".hist-svg" data-rows="2" data-var="--hist-strip"
//           data-min-width="1101"></script>
//
//   data-target     selector for one instance of the flexible element; every
//                   instance is assumed to share a height, which is true of a
//                   grid whose rows are the same shape
//   data-rows       how many of them stack VERTICALLY (grid rows, not cells)
//   data-var        custom property to publish on <html>
//   data-min-width  only measure at or above this width; below it the grid
//                   usually has a different row count, and those bands scroll
//                   regardless, so the CSS default is left to stand
(function () {
  var script = document.currentScript;
  if (!script) return;

  var targetSel = script.getAttribute('data-target') || '.hist-svg';
  var rows = parseInt(script.getAttribute('data-rows'), 10) || 1;
  var varName = script.getAttribute('data-var') || '--fold-strip';
  var minWidth = parseInt(script.getAttribute('data-min-width'), 10) || 0;

  var mq = minWidth ? window.matchMedia('(min-width: ' + minWidth + 'px)') : null;
  var last = 0;
  var queued = false;
  var ro = null;

  function measure() {
    queued = false;
    var main = document.querySelector('main');
    var target = document.querySelector(targetSel);
    if (!main || !target) return;

    if (mq && !mq.matches) {
      document.documentElement.style.removeProperty(varName);
      last = 0;
      return;
    }

    // A footer that is display:none on tablet widths must not be counted.
    var foot = document.querySelector('footer');
    var footH = foot && getComputedStyle(foot).display !== 'none' ? foot.offsetHeight : 0;
    var contentH = main.offsetTop + main.offsetHeight + footH;

    var strip = Math.ceil(contentH - rows * target.getBoundingClientRect().height) + 2;
    if (!isFinite(strip) || strip <= 0) return;
    if (Math.abs(strip - last) < 3) return;   // rounding drift, not a real move
    last = strip;
    document.documentElement.style.setProperty(varName, strip + 'px');
  }

  function schedule() {
    if (queued) return;
    queued = true;
    // Deferred out of the ResizeObserver callback: writing a style from inside
    // one is what produces the "loop completed with undelivered notifications"
    // console noise, and there is nothing urgent about a repaint here.
    requestAnimationFrame(measure);
  }

  function start() {
    schedule();
    window.addEventListener('resize', schedule);
    if (mq && typeof mq.addEventListener === 'function') mq.addEventListener('change', schedule);
    // The strips resize on their own — bars redraw every ledger, a list fills
    // in, a peer view swaps a panel for a note. Watching main catches all of
    // them without a hook in each renderer.
    if (window.ResizeObserver) {
      var mainEl = document.querySelector('main');
      if (mainEl) {
        ro = new ResizeObserver(schedule);
        ro.observe(mainEl);
      }
    }
  }

  window.addEventListener('pagehide', function () {
    try { if (ro) ro.disconnect(); } catch { /* already gone */ }
    window.removeEventListener('resize', schedule);
  });

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', start);
  } else {
    start();
  }
})();
