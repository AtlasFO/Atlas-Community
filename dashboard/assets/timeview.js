/* The window of the run the Process chart shows: the whole run, or a view
   zoomed and slid within it. Pure functions over [fromMs, toMs] pairs, so
   the chart's wheel handling is checked under node
   (tests/dashboard/timeview_harness.js). */
(function (root) {
  'use strict';
  // Note: a fixed five-second floor; make it a setting if a case needs finer.
  const MIN_SPAN_MS = 5000;

  // A view stays inside the run. One at least as wide as the run is the
  // run itself, reported as null.
  function fit(view, run) {
    const span = view[1] - view[0];
    if (!(span > 0) || span >= run[1] - run[0]) return null;
    const a = Math.max(run[0], Math.min(view[0], run[1] - span));
    return [a, a + span];
  }

  // Scale the view's span by `factor`, keeping the moment at fraction
  // `frac` of its width where it is.
  function zoom(view, run, frac, factor) {
    const cur = view || run;
    const span = cur[1] - cur[0];
    const next = Math.max(MIN_SPAN_MS, span * factor);
    const anchor = cur[0] + frac * span;
    return fit([anchor - frac * next, anchor + (1 - frac) * next], run);
  }

  // Slide the view by a fraction of its own width; positive is later.
  function pan(view, run, dFrac) {
    if (!view) return null;
    const d = dFrac * (view[1] - view[0]);
    return fit([view[0] + d, view[1] + d], run);
  }

  // A view whose right edge sat at the run's end rides along as the run
  // grows; any other view just stays inside the run.
  function follow(view, prevEnd, run) {
    if (!view) return null;
    if (view[1] < prevEnd - 1000 || run[1] <= prevEnd) return fit(view, run);
    const d = run[1] - view[1];
    return fit([view[0] + d, view[1] + d], run);
  }

  const api = { fit, zoom, pan, follow, MIN_SPAN_MS };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  root.TimeView = api;
})(typeof window !== 'undefined' ? window : globalThis);
