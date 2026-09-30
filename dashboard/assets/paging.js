/* Paging arithmetic for a long list shown a page at a time. Pure functions,
   so the page a row lands on is checked under node
   (tests/dashboard/paging_harness.js); the page draws the rows and the
   pager itself. */
(function (root) {
  'use strict';

  // Where page `page` of `size` rows falls in a list kept in groups holding
  // `counts` rows each, in order. Returns the page clamped to the pages that
  // exist, the page count, the rows [from, to) of the whole list, and per
  // group the range [a, b) of its own rows on the page, or null for a group
  // the page does not reach.
  function slice(counts, page, size) {
    const total = counts.reduce((n, c) => n + c, 0);
    const pages = Math.max(1, Math.ceil(total / size));
    const p = Math.min(Math.max(Math.floor(page) || 0, 0), pages - 1);
    const from = p * size;
    const to = Math.min(total, from + size);
    let offset = 0;
    const ranges = counts.map((c) => {
      const a = Math.max(from, offset) - offset;
      const b = Math.min(to, offset + c) - offset;
      offset += c;
      return a < b ? [a, b] : null;
    });
    return { page: p, pages, from, to, total, ranges };
  }

  // The page numbers a pager offers: the first, the last, and the current
  // page with its neighbours; null marks skipped numbers. A gap of a single
  // page shows that page, since the marker would take the same room.
  function pageList(current, count) {
    const out = [];
    let last = -1;
    for (let i = 0; i < count; i++) {
      if (i !== 0 && i !== count - 1 && Math.abs(i - current) > 1) continue;
      if (i - last === 2) out.push(last + 1);
      else if (i - last > 2) out.push(null);
      out.push(i);
      last = i;
    }
    return out;
  }

  // The page that keeps the first row on screen in view after the page
  // size changes from `oldSize` to `newSize`.
  function resized(page, oldSize, newSize) {
    return Math.floor((page * oldSize) / newSize);
  }

  const api = { slice, pageList, resized };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  root.AtlasPaging = api;
})(typeof window !== 'undefined' ? window : globalThis);
