// Checks the paging arithmetic (dashboard/assets/paging.js) under node: the
// rows a page takes from each group, clamping, the offered page numbers and
// the page kept after a size change. Run by test_paging_js.py.
'use strict';
const assert = require('assert');
const P = require(require('path').resolve(process.argv[2]));

// Two periods of 30 and 9 runs at 25 a page: the first page is the first
// 25 of the first period, the second the rest of it and all of the next.
let s = P.slice([30, 9], 0, 25);
assert.deepStrictEqual([s.page, s.pages, s.from, s.to, s.total], [0, 2, 0, 25, 39]);
assert.deepStrictEqual(s.ranges, [[0, 25], null]);
s = P.slice([30, 9], 1, 25);
assert.deepStrictEqual([s.from, s.to], [25, 39]);
assert.deepStrictEqual(s.ranges, [[25, 30], [0, 9]]);
// A page past the end is the last page, one before the start the first.
assert.strictEqual(P.slice([30, 9], 7, 25).page, 1);
assert.strictEqual(P.slice([30, 9], -3, 25).page, 0);
// A page that is not a number is the first page.
assert.strictEqual(P.slice([5], NaN, 10).page, 0);
assert.strictEqual(P.slice([5], undefined, 10).page, 0);
// An empty group and an empty list.
assert.deepStrictEqual(P.slice([0, 5, 0], 0, 10).ranges, [null, [0, 5], null]);
s = P.slice([], 3, 10);
assert.deepStrictEqual([s.page, s.pages, s.from, s.to, s.total], [0, 1, 0, 0, 0]);
// Exactly one full page.
assert.deepStrictEqual([P.slice([25], 0, 25).pages, P.slice([25], 1, 25).page], [1, 0]);

const show = (c, n) => P.pageList(c, n).map(i => (i === null ? '...' : i + 1)).join(' ');
assert.strictEqual(show(0, 1), '1');
assert.strictEqual(show(0, 4), '1 2 3 4');
assert.strictEqual(show(3, 4), '1 2 3 4');          // one skipped page is shown, not marked
assert.strictEqual(show(0, 8), '1 2 ... 8');
assert.strictEqual(show(7, 8), '1 ... 7 8');
assert.strictEqual(show(5, 20), '1 ... 5 6 7 ... 20');

// From page 2 at 25 a page (rows 26-39) to 10 a page: page 3, rows 21-30,
// which still holds row 26.
assert.strictEqual(P.resized(1, 25, 10), 2);
assert.strictEqual(P.resized(2, 10, 100), 0);
console.log('paging harness: ok');
