// Runs the Brief page's own script under node with a stub shell and DOM and
// checks what it does with the brief's version: every save sends the
// version the editor started from; a 409 puts the server's text in the
// editor, keeps the user's text beside it and makes the next save send the
// server's version; "Use mine instead" puts the user's text back. A later
// poll that sees a new version reloads a clean editor and leaves an editor
// with unsaved edits as it is, with a notice. Run by test_brief_js.py.
'use strict';
const fs = require('fs');
const assert = require('assert');

const html = fs.readFileSync(process.argv[2], 'utf8');
const src = html.slice(html.lastIndexOf('<script>') + '<script>'.length,
                       html.lastIndexOf('</script>'));

function load() {
  const els = {};
  class El {
    constructor(id) { this._id = id; this.value = ''; this.textContent = ''; this.className = '';
      this.dataset = {}; this.listeners = {}; this._html = ''; if (id) els[id] = this; }
    set id(v) { this._id = v; els[v] = this; }
    get id() { return this._id; }
    set innerHTML(h) {
      this._html = h;
      for (const m of h.matchAll(/id="([^"]+)"/g)) new El(m[1]);
      for (const m of h.matchAll(/<textarea id="([^"]+)"[^>]*>([\s\S]*?)<\/textarea>/g)) els[m[1]].value = m[2];
    }
    get innerHTML() { return this._html; }
    addEventListener(ev, fn) { (this.listeners[ev] ||= []).push(fn); }
    fire(ev, arg) { (this.listeners[ev] || []).forEach(fn => fn(arg || {})); }
    after() {}
    remove() { delete els[this._id]; }
    select() {}
    querySelectorAll() { return []; }
  }
  new El('app');
  globalThis.document = {
    getElementById: (id) => els[id] || null,
    createElement: () => new El(),
    execCommand: () => true,
  };
  globalThis.window = globalThis;
  Object.defineProperty(globalThis, 'navigator', { value: {}, configurable: true });
  const S = { gets: [], posts: [], postAnswers: [], polls: [] };
  globalThis.AtlasShell = {
    esc: (s) => String(s ?? ''),
    roleAtLeast: () => true,
    activeCase: () => 'CASE-A',
    api: async () => S.gets.shift(),
    apiPost: async (route, body) => {
      S.posts.push({ route, body: JSON.parse(JSON.stringify(body)) });
      const a = S.postAnswers.shift();
      if (a && a.reject) { const e = new Error(a.reject.error); e.status = a.reject.status; e.data = a.reject; throw e; }
      return a;
    },
    poll: (fn) => { S.polls.push(fn); return () => {}; },
    init: (opts) => opts.onCase(),
  };
  new Function(src)();
  return { els, S, round: () => S.polls.at(-1)() };
}

const ctrlS = { ctrlKey: true, key: 's', preventDefault() {} };
// The key handler starts the save without waiting for it.
const flush = () => new Promise((r) => setImmediate(r));
const pressSave = async (els) => { els['md-editor'].listeners.keydown[0](ctrlS); await flush(); };
const C1 = '**Case ID:** CASE-A\n- What ran on CORP-WS01?\n';
const C2 = C1 + '- Who used jane.doe?\n';

async function conflictFlow() {
  const { els, S, round } = load();
  S.gets.push({ exists: true, content: C1, version: 'v1' });
  await round();
  assert.strictEqual(els['md-editor'].value, C1);
  const mine = C1 + '- from this tab\n';
  els['md-editor'].value = mine;
  S.postAnswers.push({ reject: { status: 409, conflict: true, error: 'saved elsewhere', content: C2, version: 'v2' } });
  await pressSave(els);
  assert.strictEqual(S.posts[0].body.version, 'v1', 'the save sends the version the editor started from');
  assert.strictEqual(els['md-editor'].value, C2, 'the editor takes the text that is on the server');
  assert.ok(els['md-conflict'], 'the conflict panel is shown');
  assert.strictEqual(els['md-mine'].value, mine, "the user's unsaved text is kept beside it");
  els['md-mine-use'].fire('click');
  assert.strictEqual(els['md-editor'].value, mine, '"Use mine instead" puts it back');
  assert.ok(!els['md-conflict'], 'and closes the panel');
  S.postAnswers.push({ success: true, version: 'v3' });
  await pressSave(els);
  assert.strictEqual(S.posts[1].body.version, 'v2', 'the next save is based on the server version');
  assert.strictEqual(els['md-msg'].textContent, 'Saved.');
}

async function pollFlow() {
  let { els, S, round } = load();
  S.gets.push({ exists: true, content: C1, version: 'v1' });
  await round();
  S.gets.push({ exists: true, content: C2, version: 'v2' });
  await round();
  assert.strictEqual(els['md-editor'].value, C2, 'a clean editor takes the newer brief');
  assert.match(els['md-msg'].textContent, /Reloaded/);

  ({ els, S, round } = load());
  S.gets.push({ exists: true, content: C1, version: 'v1' });
  await round();
  els['md-editor'].value = C1 + '- typing\n';
  S.gets.push({ exists: true, content: C2, version: 'v2' });
  await round();
  assert.strictEqual(els['md-editor'].value, C1 + '- typing\n', 'unsaved edits are never replaced');
  assert.match(els['md-msg'].textContent, /changed on the server/);
}

conflictFlow().then(pollFlow).then(() => { console.log('brief harness: ok'); process.exit(0); },
  (e) => { console.error((e && e.stack) || e); process.exit(1); });
