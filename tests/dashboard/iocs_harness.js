// Runs the IoCs page's own script under node with a stub shell and DOM and
// feeds it the case/iocs answer the read model built (argv[3]). Checks the
// headline: the indicator count is the catalog's total (the typed rows the
// report and the export count), and the rows listed beside it (own assets,
// review before use, named but not seen) are named, not counted. Run by
// test_ioc_counts.py.
'use strict';
const fs = require('fs');
const assert = require('assert');

const html = fs.readFileSync(process.argv[2], 'utf8');
const catalog = JSON.parse(fs.readFileSync(process.argv[3], 'utf8'));
const src = html.slice(html.lastIndexOf('<script>') + '<script>'.length,
                       html.lastIndexOf('</script>'));

class El {
  constructor() { this.innerHTML = ''; this.textContent = ''; this.dataset = {}; this.style = {};
    this.classList = { add() {}, remove() {}, toggle() {}, contains: () => false }; }
  addEventListener() {}
  querySelector() { return null; }
  querySelectorAll() { return []; }
  setAttribute() {}
  removeAttribute() {}
}
const els = {};
globalThis.document = { getElementById: (id) => (els[id] ||= new El()), querySelector: () => null,
  querySelectorAll: () => [], addEventListener() {}, body: new El() };
globalThis.window = globalThis;
globalThis.localStorage = { getItem: () => null, setItem() {} };
let firstRound = null;
globalThis.AtlasShell = {
  esc: (s) => String(s ?? ''),
  roleAtLeast: () => true,
  activeCase: () => 'CASE-A',
  isTransient: () => false,
  api: async () => JSON.parse(JSON.stringify(catalog)),
  apiPost: async () => ({ success: true }),
  poll: (fn) => { firstRound = fn(); return () => {}; },
  init: (opts) => opts.onCase(),
};
new Function(src)();

firstRound.then(() => {
  const page = els.app.innerHTML;
  const headline = page.match(/<div class="f-v">(\d+)<\/div><div class="f-l">Indicators<\/div>/);
  assert.ok(headline, 'the band shows an Indicators figure');
  assert.strictEqual(Number(headline[1]), catalog.total, 'the headline is the catalog total');
  assert.match(page, /also listed: [^<]*Review before use 1/, 'the review rows are named beside it');
  const types = page.match(/<div class="f-v">(\d+)<\/div><div class="f-l">Types<\/div>/);
  assert.strictEqual(Number(types[1]), catalog.groups.filter((g) => g.counted).length,
    'only the typed groups are types');
  console.log('iocs harness: ok');
  process.exit(0);
}).catch((e) => { console.error((e && e.stack) || e); process.exit(1); });
