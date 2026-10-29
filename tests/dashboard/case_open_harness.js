// Loads dashboard/assets/shell.js under node with a stub DOM and a scripted
// case list, and checks which case a page opens on: a ?case= the list does
// not hold opens no case (never the stored or the only one), keeps the link
// and the stored case, and says so escaped; a list that did not load names
// no case unknown and is asked again. Run by test_case_open_js.py.
'use strict';
const fs = require('fs');
const assert = require('assert');

const src = fs.readFileSync(process.argv[2], 'utf8');
const realSetTimeout = setTimeout;

class El {
  constructor() {
    this.textContent = ''; this.innerHTML = ''; this.hidden = false; this.style = {}; this.dataset = {};
    this.value = '';
    const cls = new Set();
    this.classList = { add: (c) => cls.add(c), remove: (c) => cls.delete(c),
      toggle: (c, on) => (on ? cls.add(c) : cls.delete(c)), contains: (c) => cls.has(c) };
  }
  querySelector() { return null; }
  querySelectorAll() { return []; }
  addEventListener() {}
  appendChild() {}
  prepend() {}
  append() {}
  setAttribute() {}
  getAttribute() { return null; }
}

async function open({ urlCase, stored, cases, failLists = 0 }) {
  const els = {};
  globalThis.document = {
    hidden: false, documentElement: { dataset: {} }, body: new El(),
    getElementById: (id) => (els[id] ||= new El()), querySelector: () => null, querySelectorAll: () => [],
    createElement: () => new El(), addEventListener() {}, removeEventListener() {},
  };
  globalThis.window = globalThis;
  globalThis.addEventListener = () => {};
  const store = stored ? { 'atlas.activeCase': stored } : {};
  globalThis.localStorage = { getItem: (k) => (k in store ? store[k] : null),
    setItem: (k, v) => { store[k] = String(v); }, removeItem: (k) => { delete store[k]; } };
  globalThis.sessionStorage = { getItem: () => null, setItem() {}, removeItem() {} };
  const search = urlCase === undefined ? '' : `?case=${encodeURIComponent(urlCase)}`;
  globalThis.location = { pathname: '/_dashboard/overview.html', search, hash: '',
    href: `http://127.0.0.1/_dashboard/overview.html${search}` };
  const urls = [];
  globalThis.history = { replaceState: (_s, _t, u) => urls.push(u) };
  globalThis.AtlasI18n = { t: (k, v) => (v ? `${k} ${Object.values(v).join(' ')}` : k), getLang: () => 'en',
    setLang() {}, getTheme: () => 'dark', setTheme() {} };
  globalThis.EventSource = class { addEventListener() {} close() {} };
  // The list retry, made quick.
  globalThis.setTimeout = (fn, ms, ...a) => realSetTimeout(fn, ms === 3000 ? 5 : ms, ...a);
  let lists = 0;
  globalThis.fetch = (url) => {
    const u = String(url);
    if (u.includes('/api/cases')) {
      lists += 1;
      if (lists <= failLists) return Promise.reject(new TypeError('Failed to fetch'));
    }
    const body = u.includes('/api/cases') ? { cases: cases.map((c) => ({ case_dir: c, case_id: c })) }
      : u.includes('whoami') ? { authenticated: true, user: { role: 'admin', username: 'jane.doe', email: 'jane.doe@example.com' } }
        : {};
    return Promise.resolve({ ok: true, status: 200, redirected: false, url: u, json: async () => body });
  };
  const shell = new Function(`${src}\nreturn AtlasShell;`)();
  const seen = [];
  const initial = await shell.init({ page: 'overview', requiresCase: true, onCase: (c) => seen.push(c) });
  return { shell, initial, store, urls, notice: els['atlas-case-notice'] || new El(), seen,
           wait: () => new Promise((r) => realSetTimeout(r, 60)) };
}

(async () => {
  const two = ['CASE-A', 'CASE-B'];
  // a path form and an unknown name: no case, link and stored case kept, said so
  for (const asked of ['/srv/cases/CASE-B', 'CASE-NOPE']) {
    const p = await open({ urlCase: asked, stored: 'CASE-A', cases: two });
    assert.strictEqual(p.initial, null, asked);
    assert.strictEqual(p.shell.activeCase(), null, asked);
    assert.deepStrictEqual(p.seen, [null], asked);
    assert.strictEqual(p.store['atlas.activeCase'], 'CASE-A', asked);
    assert.ok(p.urls.every((u) => !/case=CASE-A/.test(u)) && p.urls.length === 0, `url rewritten: ${p.urls}`);
    assert.ok(!p.notice.hidden && p.notice.innerHTML.startsWith('shell.caseNotFound '), p.notice.innerHTML);
  }
  // the only case is no stand-in for an unknown one either
  const only = await open({ urlCase: 'CASE-NOPE', cases: ['CASE-A'] });
  assert.strictEqual(only.initial, null);
  // markup in the asked value is shown escaped
  const mark = await open({ urlCase: '<img src=x onerror=alert(1)>', stored: 'CASE-A', cases: two });
  assert.ok(mark.notice.innerHTML.includes('&lt;img src=x onerror=alert(1)&gt;'), mark.notice.innerHTML);
  assert.ok(!mark.notice.innerHTML.includes('<img'), mark.notice.innerHTML);
  // a known ?case= wins; with none, the stored case, then the only case
  assert.strictEqual((await open({ urlCase: 'CASE-B', stored: 'CASE-A', cases: two })).initial, 'CASE-B');
  assert.strictEqual((await open({ stored: 'CASE-A', cases: two })).initial, 'CASE-A');
  assert.strictEqual((await open({ cases: ['CASE-B'] })).initial, 'CASE-B');
  // a case list that did not load: no verdict, no stand-in, asked again
  const down = await open({ urlCase: 'CASE-B', stored: 'CASE-A', cases: two, failLists: 1 });
  assert.strictEqual(down.initial, null);
  assert.ok(down.notice.innerHTML.startsWith('shell.casesUnavailable '), down.notice.innerHTML);
  assert.strictEqual(down.store['atlas.activeCase'], 'CASE-A');
  assert.strictEqual(down.urls.length, 0);
  await down.wait();
  assert.strictEqual(down.shell.activeCase(), 'CASE-B');
  assert.ok(down.notice.hidden);
  // with no ?case=, a failed list keeps the stored case for when it answers
  const quiet = await open({ stored: 'CASE-A', cases: two, failLists: 1 });
  assert.strictEqual(quiet.initial, null);
  assert.strictEqual(quiet.store['atlas.activeCase'], 'CASE-A');
  await quiet.wait();
  assert.strictEqual(quiet.shell.activeCase(), 'CASE-A');
  console.log('case harness: ok');
  process.exit(0);
})().catch((e) => { console.log(`case harness: FAIL ${e && e.stack}`); process.exit(1); });
