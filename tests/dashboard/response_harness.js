// Runs the Response page's own script under node with a stub shell and DOM
// and feeds it a catalog the read model built (argv[3]). The payload carries
// every row twice, once in the ordered list and once in its phase group, so
// the page has to pair the copies by id: identity between two separately
// parsed JSON objects never holds. Checks the rows that reach the page:
// every open row by default, every row once "Show done and dismissed" is
// on, the open rows again once it is off. Run by test_response.py.
'use strict';
const fs = require('fs');
const assert = require('assert');

const html = fs.readFileSync(process.argv[2], 'utf8');
const catalog = JSON.parse(fs.readFileSync(process.argv[3], 'utf8'));
const src = html.slice(html.lastIndexOf('<script>') + '<script>'.length,
                       html.lastIndexOf('</script>'));

class El {
  constructor() { this.innerHTML = ''; this.textContent = ''; this.dataset = {}; this.listeners = {}; }
  addEventListener(ev, fn) { (this.listeners[ev] ||= []).push(fn); }
  querySelectorAll() { return []; }
}
const els = {};
globalThis.document = { getElementById: (id) => (els[id] ||= new El()) };
let firstRound = null;
globalThis.AtlasShell = {
  esc: (s) => String(s ?? ''),
  roleAtLeast: () => true,
  activeCase: () => 'CASE',
  isTransient: () => false,
  // Each answer is parsed afresh, as the browser parses each fetch.
  api: async () => JSON.parse(JSON.stringify(catalog)),
  apiPost: async () => ({ success: true }),
  poll: (fn) => { firstRound = fn(); return () => {}; },
  init: (opts) => opts.onCase(),
};

new Function(src)();

const app = els.app;
const rows = () => (app.innerHTML.match(/<details class="rs-row /g) || []).length;
const doneRows = () => (app.innerHTML.match(/<details class="rs-row done"/g) || []).length;
const toggle = () => els['rs-toggle-done'].listeners.click.at(-1)();

async function main() {
  await firstRound;
  assert.strictEqual(rows(), catalog.open, 'every open row is on the page, whatever its urgency');
  assert.strictEqual(doneRows(), 0, 'done rows stay hidden until asked for');
  toggle();
  assert.strictEqual(rows(), catalog.total, 'showing done and dismissed shows every row once');
  assert.strictEqual(doneRows(), catalog.done, 'the done rows are the ones marked done');
  toggle();
  assert.strictEqual(rows(), catalog.open, 'hiding them again leaves the open rows');
  console.log('response harness: ok');
}
main().then(() => process.exit(0), (e) => { console.error((e && e.stack) || e); process.exit(1); });
