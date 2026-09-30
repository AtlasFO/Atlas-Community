// Checks the Process chart's view arithmetic (dashboard/assets/timeview.js)
// under node: zoom about the pointer, the floor, panning, clamping at the
// run's ends, and a view at the run's end riding along as the run grows.
// Run by test_timeview_js.py.
'use strict';
const assert = require('assert');
const TimeView = require(require('path').resolve(process.argv[2]));

const run = [0, 3600e3];                                             // an hour
assert.strictEqual(TimeView.zoom(null, run, 0.5, 1.5), null);       // out past the run is the run
let v = TimeView.zoom(null, run, 0.5, 0.5);                          // halve about the middle
assert.deepStrictEqual(v, [900e3, 2700e3]);
v = TimeView.zoom(v, run, 0, 0.5);                                   // halve about the left edge
assert.deepStrictEqual(v, [900e3, 1800e3]);
assert.deepStrictEqual(TimeView.pan(v, run, 1), [1800e3, 2700e3]);  // one width later
assert.deepStrictEqual(TimeView.pan(v, run, -10), [0, 900e3]);      // clamped at the start
assert.deepStrictEqual(TimeView.pan(v, run, 10), [2700e3, 3600e3]); // clamped at the end
assert.strictEqual(TimeView.pan(null, run, 1), null);               // the whole run has nowhere to go
assert.deepStrictEqual(TimeView.zoom(v, run, 0.5, 1e-9),
  [1350e3 - TimeView.MIN_SPAN_MS / 2, 1350e3 + TimeView.MIN_SPAN_MS / 2]);   // the floor
assert.deepStrictEqual(TimeView.follow([3000e3, 3600e3], 3600e3, [0, 4000e3]), [3400e3, 4000e3]); // rides the tail
assert.deepStrictEqual(TimeView.follow([1000e3, 2000e3], 3600e3, [0, 4000e3]), [1000e3, 2000e3]); // stays put
assert.deepStrictEqual(TimeView.follow([3000e3, 3600e3], 3600e3, [0, 3600e3]), [3000e3, 3600e3]); // nothing grew
assert.strictEqual(TimeView.fit([0, 5000e3], run), null);           // wider than the run
assert.strictEqual(TimeView.fit([10, 10], run), null);              // an empty view
console.log('timeview harness: ok');
