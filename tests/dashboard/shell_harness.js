// Loads dashboard/assets/shell.js under node with a stub DOM and a scripted
// fetch, and checks the network policy every page relies on: the request
// timeout, the offline threshold, visibility-aware polling and the
// expired-session redirect. Run by test_shell_js.py.
'use strict';
const fs = require('fs');
const assert = require('assert');

const src = fs.readFileSync(process.argv[2], 'utf8');

class El {
  constructor() {
    this.cls = new Set(); this.textContent = ''; this.innerHTML = '';
    this.hidden = false; this.style = {}; this.dataset = {};
    this.classList = {
      add: (c) => this.cls.add(c), remove: (c) => this.cls.delete(c),
      toggle: (c, on) => (on ? this.cls.add(c) : this.cls.delete(c)),
      contains: (c) => this.cls.has(c),
    };
  }
  querySelector() { return null; }
  querySelectorAll() { return []; }
  addEventListener() {}
  appendChild() {}
}
const els = {};
const docListeners = {};
globalThis.document = {
  hidden: false,
  documentElement: { dataset: {} },
  body: new El(),
  getElementById: (id) => (els[id] ||= new El()),
  querySelector: () => null,
  querySelectorAll: () => [],
  createElement: () => new El(),
  addEventListener: (ev, fn) => (docListeners[ev] ||= []).push(fn),
  removeEventListener: (ev, fn) => {
    docListeners[ev] = (docListeners[ev] || []).filter((f) => f !== fn);
  },
};
globalThis.window = globalThis;
globalThis.addEventListener = () => {};
globalThis.localStorage = { getItem: () => null, setItem() {}, removeItem() {} };
globalThis.sessionStorage = globalThis.localStorage;
globalThis.location = {
  pathname: '/_dashboard/overview.html', search: '?case=x', hash: '#runs', href: '',
};
globalThis.history = { replaceState() {} };
globalThis.AtlasI18n = {
  t: (k) => k, getLang: () => 'en', setLang() {}, getTheme: () => 'dark', setTheme() {},
};
// The shell asks for its real timeout; shorten it so the harness stays fast.
const realTimeout = AbortSignal.timeout.bind(AbortSignal);
AbortSignal.timeout = () => realTimeout(30);
// A fake clock, so "the server has been silent for 10s" is a number the
// test moves rather than a wait.
let clock = 1_000_000_000_000;
Date.now = () => clock;

// Scripted fetch. Each queued step is one of: 'ok' | 'fail' | 'hang' |
// 'redirect' | an HTTP status number.
const steps = [];
globalThis.fetch = (url, init) => {
  const step = steps.length ? steps.shift() : 'ok';
  if (step === 'fail') return Promise.reject(new TypeError('Failed to fetch'));
  if (step === 'hang') {
    return new Promise((_resolve, reject) => {
      init.signal.addEventListener('abort', () => reject(init.signal.reason));
    });
  }
  const status = typeof step === 'number' ? step : 200;
  return Promise.resolve({
    ok: status < 400, status,
    redirected: step === 'redirect',
    url: step === 'redirect' ? '/_dashboard/login.html?next=x' : url,
    json: async () => ({}),
  });
};

// Stub EventSource: the shell opens one; the test drives it.
class FakeEventSource {
  constructor(url) { this.url = url; this.listeners = {}; FakeEventSource.last = this; }
  addEventListener(type, fn) { (this.listeners[type] ||= []).push(fn); }
  emit(type, data) { (this.listeners[type] || []).forEach((fn) => fn({ data })); }
}
globalThis.EventSource = FakeEventSource;

const AtlasShell = new Function(`${src}\nreturn AtlasShell;`)();
const chip = document.getElementById('atlas-activity');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function main() {
  // 1. A request nobody answers is abandoned, and counts as a miss.
  steps.push('hang');
  await assert.rejects(AtlasShell.api('x'),
    (e) => e.network === true && /15s/.test(e.message));

  // 2. Offline needs the server silent for 10s, however many requests miss
  //    inside that window; one answer clears it. (The hang above opened the
  //    silent window.)
  steps.push('fail', 'fail', 'fail');
  for (let i = 0; i < 3; i++) {
    await assert.rejects(AtlasShell.api('x'), (e) => AtlasShell.isTransient(e));
  }
  assert.ok(!chip.classList.contains('offline'), 'a burst of misses must not show offline yet');
  clock += 10_000;
  steps.push('fail');
  await assert.rejects(AtlasShell.api('x'), (e) => !AtlasShell.isTransient(e));
  assert.ok(chip.classList.contains('offline'), 'silent for 10s shows offline');
  steps.push('ok');
  await AtlasShell.api('x');
  assert.ok(!chip.classList.contains('offline'), 'one answer clears offline');

  // 3. An answer we don't like is an error, never "offline".
  steps.push(500);
  await assert.rejects(AtlasShell.api('x'), (e) => e.status === 500 && !e.network);
  assert.ok(!chip.classList.contains('offline'));

  // 4. poll(): runs at once, skips while hidden, catches up on visibility,
  //    never overlaps, stops cleanly.
  let runs = 0, inFlight = 0, overlap = false;
  const stop = AtlasShell.poll(async () => {
    inFlight += 1; if (inFlight > 1) overlap = true;
    runs += 1; await sleep(15); inFlight -= 1;
  }, 5);
  await sleep(2);
  assert.strictEqual(runs, 1, 'first round runs immediately');
  await sleep(60);
  assert.ok(runs >= 2, 'keeps polling while visible');
  assert.ok(!overlap, 'a slow round never overlaps the next');
  document.hidden = true;
  await sleep(25);
  const atHide = runs;
  await sleep(60);
  assert.strictEqual(runs, atHide, 'no work while hidden');
  document.hidden = false;
  docListeners.visibilitychange.forEach((f) => f());
  await sleep(2);
  assert.strictEqual(runs, atHide + 1, 'visible again -> immediate round');
  stop();
  const atStop = runs;
  await sleep(40);
  assert.strictEqual(runs, atStop, 'stopped');
  assert.strictEqual((docListeners.visibilitychange || []).length, 0, 'listener removed');

  // 5. The change stream: a connected stream runs a poll at once on a
  //    change (hidden tab included) and backs its timer off; a dropped
  //    stream puts the timer back on the fast cadence.
  let liveRuns = 0;
  const stopLive = AtlasShell.poll(async () => { liveRuns += 1; }, 5, { everyCase: true });
  await sleep(2);
  AtlasShell.live.connect();
  const es = FakeEventSource.last;
  assert.ok(es && /\/api\/events$/.test(es.url), 'one EventSource on the events endpoint');
  es.onopen();
  const atOpen = liveRuns;
  await sleep(60);
  assert.ok(liveRuns - atOpen <= 1, 'timer backs off while the stream is live');
  document.hidden = true;
  es.emit('change', JSON.stringify({ case: 'x' }));
  await sleep(2);
  assert.strictEqual(liveRuns, atOpen + 1, 'a change runs the poll even in a hidden tab');
  document.hidden = false;
  es.onerror();
  const atDrop = liveRuns;
  await sleep(60);
  assert.ok(liveRuns > atDrop + 3, 'a dropped stream returns to the fast timer');
  stopLive();

  // 6. An expired session goes to the login page, once, with a return path
  // that keeps the page's fragment.
  steps.push(401);
  await Promise.race([AtlasShell.api('x'), sleep(10)]);
  assert.strictEqual(location.href,
    'login.html?next=%2F_dashboard%2Foverview.html%3Fcase%3Dx%23runs');
  location.href = '';
  steps.push('redirect');
  await Promise.race([AtlasShell.fetchJson('/case/analysis/x_trace.json'), sleep(10)]);
  assert.strictEqual(location.href, '', 'a second redirect is not re-fired');

  console.log('shell harness: ok');
}
// Node unrefs the timer behind AbortSignal.timeout, so without a ref'd
// timer the process would exit silently mid-test. This also caps a hung run.
setTimeout(() => { console.error('shell harness: timed out'); process.exit(2); }, 20000);
main().then(() => process.exit(0), (e) => { console.error((e && e.stack) || e); process.exit(1); });
