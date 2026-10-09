// Runs the Process page's script (dashboard/trace_viewer.html) under node with
// a stub DOM and shell, against invented traces: a sane one; ones with markup
// in one field of every entry, field by field; ones with markup in every id or
// every reference; one with ids written as strings; ones where every field,
// a list's elements, the case id or the entry list itself holds some other
// JSON type. A trace is case content, so every run must list every entry,
// throw nothing, and write only the tags and attribute names the sane run
// writes: no on* attribute, and nothing from the trace in a class or a style.
// With --sink-only the page's normalising of entries is taken out and only the
// markup traces run: the escaping where values are written must hold alone.
// Run by test_trace_viewer_js.py.
'use strict';
const fs = require('fs');
const assert = require('assert');

const [htmlPath, timeviewPath, mode] = process.argv.slice(2);
const SINK_ONLY = mode === '--sink-only';
const html = fs.readFileSync(htmlPath, 'utf8');
const begin = html.indexOf('<script>', html.indexOf('assets/timeview.js'));
let src = html.slice(begin + '<script>'.length, html.indexOf('</script>', begin))
  + '\n;globalThis.__page = { load, renderChart, markClicked, State };';
if (SINK_ONLY) { assert.ok(src.includes('.map(normalizeEntry)')); src = src.replace('.map(normalizeEntry)', ''); }
const filters = [...html.matchAll(/class="type-filter" value="([a-z_]+)"( checked)?/g)]
  .map(m => ({ value: m[1], checked: !!m[2] }));
const TimeView = require(require('path').resolve(timeviewPath));

// ── the trace ────────────────────────────────────────────────────────────────
const TS = (n) => `2031-03-04T10:${String(n).padStart(2, '0')}:00+00:00`;
function golden() {
  return { case_id: 'CASE-A', entries: [
    { call_id: 1, type: 'dair_call', ts: TS(1), dair_phase: 'DETECT', dair_depth: 1,
      current_phase: 'DETECT', next_phase: 'ANALYZE', transition_recommended: true,
      stack_action: 'push', verification_satisfied: true, investigation_focus: 'logons on CORP-DC01',
      phase_rationale: 'why', transition_rationale: 'next', recommended_actions: ['look at 4624'],
      inputs: { tool_results_summary: 'sum', phase_stack: ['DETECT'], case_context: 'ctx' },
      verification_challenges: [
        { claim: 'c1', challenge_method: 'm', verified: true, notes: 'n', confidence_impact: 'none' },
        { claim: 'c2', challenge_method: 'm', verified: false },
        { claim: 'c3', challenge_method: 'm' }],
      directives: { priority_tools: ['fls'] } },
    { call_id: 2, type: 'tool_call', ts: TS(2), dair_phase: 'DETECT', cmd: '/usr/bin/fls -r CORP-DC01.E01',
      success: true, exit_code: 0, elapsed_seconds: 1.5, retries: 1, truncated: true,
      stdout_excerpt: 'out', stderr: 'err', args: { image: 'evidence/CORP-DC01.E01', recursive: true },
      evidence_refs: ['ev-1'] },
    { call_id: 3, type: 'tool_call', ts: TS(3), dair_phase: 'DETECT', cmd: 'icat CORP-DC01.E01 5',
      success: false, timed_out: true, exit_code: null, elapsed_seconds: 30, retries: 0,
      protocol_violation: 'no_evidence_cited' },
    { call_id: 4, type: 'reason_call', ts: TS(4), dair_phase: 'ANALYZE', tool: 'reason.verify',
      conclusion: 'VERDICT: SUPPORTED', success: true, input_tokens: 10, output_tokens: 5,
      hypothesis_id: 'H-1', inputs: { user_message: 'u', system_prompt_kind: 'k' },
      directives: { priority_tools: ['x'] }, evidence_audit: [{ call_id: 2 }] },
    { call_id: 5, type: 'reason_call', ts: TS(5), dair_phase: 'ANALYZE', tool: 'reason.challenge',
      conclusion: 'VERDICT: CHALLENGED', success: false },
    { call_id: 6, type: 'finding', ts: TS(6), dair_phase: 'ANALYZE', confidence: 'CONFIRMED',
      description: 'jane.doe logged on to CORP-DC01 from 203.0.113.9', linked_call_id: 2,
      source: 'fls', tested_hypothesis_id: 'H-1',
      validated_techniques: [{ technique_id: 'T1078', tactic: 'Initial Access' }],
      gate_metadata: { gates: ['evidence'], passed: true } },
    { call_id: 7, type: 'finding', ts: TS(7), dair_phase: 'ANALYZE', confidence: 'likely',
      description: 'second' },
    { call_id: 8, type: 'self_correction', ts: TS(8), dair_phase: 'ANALYZE', trigger: 'new log',
      linked_call_id: 3, prior_belief: 'p', new_belief: 'q', evidence: 'e' },
    { call_id: 9, type: 'curiosity_probe', ts: TS(9), dair_phase: 'ANALYZE', input_call_ids: [2, 3],
      seeded_by: 'absence', probe_rationale: 'r' },
    { call_id: 10, type: 'investigation_narration', ts: TS(10), dair_phase: 'ANALYZE',
      input_call_ids: [2, 3, 4, 5, 6, 7, 8], content: 'note' },
    { call_id: 11, type: 'call_initiated', ts: TS(11), tool: 'fls', backend: 'local', inputs: { a: 1 } },
    { call_id: 12, type: 'call_abandoned', ts: TS(12), tool: 'icat', reason: 'stopped', backend: 'local' },
    { call_id: 13, type: 'deferred_intent', ts: TS(13), status: 'pending', tool: 'mftecmd',
      args_summary: '$MFT', blocked_reason: 'no mount', block_count: 2,
      prescribed_by_dair_cid: 1, parent_dair_cid: 1 },
    { call_id: 14, type: 'deferred_intent', ts: TS(14), status: 'resolved', priority_tool: 'evtx' },
    { call_id: 15, type: 'trace_opened', ts: TS(15), detail: 'opened' },
    { call_id: 16, type: 'system_error', ts: TS(16), category: 'io', detail: 'disk' },
    { call_id: 17, type: 'mystery', ts: TS(17) },
  ] };
}
const IDS = new Set(['call_id', 'linked_call_id', 'input_call_ids', 'prescribed_by_dair_cid', 'parent_dair_cid']);
const MARK = (f) => `x" onmouseover="pwn_${f}()" data-q='<img src=x onerror=pwn_${f}()>');background:url(/pwn_${f})`;

// Every path to a leaf of an entry, outside the ids.
function leaves(obj, prefix = []) {
  const out = [];
  for (const [k, v] of Object.entries(obj)) {
    if (!prefix.length && IDS.has(k)) continue;
    const path = [...prefix, k];
    if (v && typeof v === 'object') out.push(...leaves(v, path));
    else out.push(path);
  }
  return out;
}
function setPath(obj, path, value) {
  let o = obj;
  for (const k of path.slice(0, -1)) o = o[k];
  o[path[path.length - 1]] = value;
}

// ── the stub page ────────────────────────────────────────────────────────────
function cssEscape(value) {             // the CSSOM algorithm
  const s = String(value); let out = '';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === 0) { out += '�'; continue; }
    if ((c >= 1 && c <= 31) || c === 127 || (i === 0 && c >= 48 && c <= 57)
        || (i === 1 && c >= 48 && c <= 57 && s.charCodeAt(0) === 45)) { out += `\\${c.toString(16)} `; continue; }
    if (i === 0 && s.length === 1 && c === 45) { out += `\\${s[i]}`; continue; }
    if (c >= 128 || c === 45 || c === 95 || (c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122)) { out += s[i]; continue; }
    out += `\\${s[i]}`;
  }
  return out;
}
// A browser throws on a selector whose attribute value is not a closed string.
function checkSelector(sel) {
  const attr = /\[[A-Za-z-]+="(?:[^"\\\n]|\\[\s\S])*"\]/g;
  if (/["\\\n]/.test(sel.replace(attr, '[]'))) throw new SyntaxError(`'${sel}' is not a valid selector`);
}

async function runPage(trace) {
  const writes = [], errors = [];
  const registry = {};
  class El {
    constructor(name) {
      this._name = name; this._html = ''; this.textContent = ''; this.dataset = {}; this.style = {};
      this.value = ''; this.checked = false; this.defaultChecked = false; this.open = true;
      this.hidden = false; this.disabled = false; this.scrollTop = 0; this.listeners = {};
      const cls = new Set();
      this.classList = { add: (c) => cls.add(c), remove: (c) => cls.delete(c), contains: (c) => cls.has(c) };
    }
    get parentElement() { return (this._parent ||= new El(`${this._name}^`)); }
    get innerHTML() { return this._html; }
    set innerHTML(v) { this._html = String(v); writes.push({ sink: this._name, html: this._html }); }
    addEventListener(ev, fn) { (this.listeners[ev] ||= []).push(fn); }
    dispatchEvent(ev) { for (const fn of this.listeners[ev.type] || []) fn(ev); return true; }
    appendChild(c) { return c; }
    remove() {}
    scrollIntoView() {}
    getBoundingClientRect() { return { left: 0, top: 0, width: 1000, height: 100 }; }
    setPointerCapture() {}
    closest() { return null; }
    querySelector(sel) { return el(sel); }
    querySelectorAll() { return []; }
  }
  const el = (sel) => (registry[sel] ||= new El(sel));
  const chips = filters.map(f => Object.assign(new El('.type-filter'),
    { value: f.value, checked: f.checked, defaultChecked: f.checked }));
  globalThis.document = {
    hidden: false, documentElement: { dataset: {} }, body: new El('body'),
    getElementById: (id) => el(`#${id}`),
    querySelector: (sel) => {
      if (sel.startsWith('.entry[')) { checkSelector(sel); return null; }
      if (sel.startsWith('.type-filter[')) { checkSelector(sel); return chips.find(c => sel.includes(`"${c.value}"`)) || null; }
      return el(sel);
    },
    querySelectorAll: (sel) => sel === '.type-filter' ? chips
      : sel === '.type-filter:checked' ? chips.filter(c => c.checked) : [],
    createElement: () => new El('created'),
    addEventListener: () => {},
  };
  globalThis.window = globalThis;
  globalThis.addEventListener = () => {};
  globalThis.localStorage = { getItem: () => null, setItem() {} };
  globalThis.location = { search: '?trace=/case-a/analysis/CASE-A_trace.json',
                          href: 'http://127.0.0.1/_dashboard/dashboard.html' };
  globalThis.history = { replaceState() {} };
  globalThis.ResizeObserver = class { observe() {} };
  globalThis.matchMedia = () => ({ matches: true });
  const frames = [];
  globalThis.requestAnimationFrame = (fn) => { frames.push(fn); return frames.length; };
  globalThis.setInterval = () => 0;
  globalThis.setTimeout = () => 0;
  globalThis.CSS = { escape: cssEscape };
  globalThis.TimeView = TimeView;
  globalThis.AtlasShell = {
    fetchJson: async (url) => (/_trace\.json$/.test(url) ? JSON.parse(JSON.stringify(trace)) : { total_tokens: 0 }),
    isTransient: () => false, activeCase: () => 'case-a', esc: (s) => String(s ?? ''),
    cases: () => [{ case_dir: 'case-a', traces: [{ path: '/case-a/analysis/CASE-A_trace.json', name: 'CASE-A_trace.json' }] }],
    poll: () => () => {}, init: (opts) => opts.onCase('case-a'),
  };
  const step = (name, fn) => { try { fn(); } catch (e) { errors.push(`${name}: ${e.message}`); } };
  step('script', () => new Function(src)());
  const page = globalThis.__page;
  try { await page.load(); } catch (e) { errors.push(`load: ${e.message}`); }
  await new Promise(r => setImmediate(r));
  if (/^error/.test(el('#live-text').textContent)) errors.push(`live: ${el('#live-text').textContent}`);
  const list = el('#entries-list').innerHTML;
  while (frames.length) step('frame', frames.shift());
  // Open every entry the way a reader does, through the list's own listeners.
  const clicks = el('#entries-list').listeners.click || [];
  for (const e of Array.isArray(trace.entries) ? trace.entries : []) {
    const id = e && e.call_id;
    const cid = id !== null && typeof id === 'object' ? JSON.stringify(id) : String(id);
    step(`open #${cid}`, () => clicks.forEach(fn => fn({
      target: { closest: (s) => (s === '.entry' ? { dataset: { cid } } : null) },
      stopPropagation() {} })));
    step(`mark #${cid}`, () => page.markClicked({ dataset: { cid } }));
  }
  step('fold', () => { const f = el('#fold-batches'); f.checked = true; f.dispatchEvent({ type: 'change', target: f }); });
  step('chart', () => page.renderChart());
  return { writes, errors, rows: (list.match(/<div class="entry[ "]/g) || []).length,
           entries: page.State.entries };
}

// ── what the page may write ──────────────────────────────────────────────────
const TAG = /<([a-zA-Z][a-zA-Z0-9]*)([^>]*)>/g;
const ATTR = /([^\s=/]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+)))?/g;
function markup(writes) {
  const tags = new Set(), attrs = new Set(), values = [];
  for (const w of writes) for (const [, tag, rest] of w.html.matchAll(TAG)) {
    tags.add(tag.toLowerCase());
    for (const [, name, dq, sq, bare] of rest.matchAll(ATTR)) {
      attrs.add(name.toLowerCase());
      values.push([name.toLowerCase(), dq ?? sq ?? bare ?? '', tag]);
    }
  }
  return { tags, attrs, values };
}
function listed(trace) {
  const entries = Array.isArray(trace.entries) ? trace.entries : [];
  const off = new Set(filters.filter(f => !f.checked).map(f => f.value));
  return entries.filter(e => e && typeof e === 'object' && !Array.isArray(e))
    .filter(e => !off.has(e.type)).length;
}

async function main() {
  const sane = await runPage(golden());
  assert.deepStrictEqual(sane.errors, [], 'the sane trace renders without an error');
  assert.strictEqual(sane.rows, listed(golden()), 'the sane trace lists every entry');
  // A field the page does not read keeps the shape its writer gave it.
  const loaded = new Map(sane.entries.map(e => [e.call_id, e]));
  for (const e of golden().entries) {
    for (const k of ['args', 'evidence_refs', 'validated_techniques', 'gate_metadata']) {
      if (k in e) assert.deepStrictEqual(loaded.get(e.call_id)[k], e[k], `#${e.call_id} ${k} keeps its shape`);
    }
  }
  const allowed = markup(sane.writes);
  let runs = 0;
  const check = async (label, trace, { ids = true } = {}) => {
    const r = await runPage(trace);
    runs += 1;
    if (!SINK_ONLY) assert.deepStrictEqual(r.errors, [], `${label}: the page throws nothing`);
    if (ids && !SINK_ONLY) assert.strictEqual(r.rows, listed(trace), `${label}: every entry is listed`);
    const m = markup(r.writes);
    for (const t of m.tags) assert.ok(allowed.tags.has(t), `${label}: a <${t}> from the trace`);
    for (const a of m.attrs) assert.ok(allowed.attrs.has(a) && !a.startsWith('on'), `${label}: attribute ${a} from the trace`);
    for (const [name, value, tag] of m.values) {
      if (name === 'class' || name === 'style') assert.ok(!/pwn|url\(/.test(value), `${label}: <${tag} ${name}="${value}">`);
    }
  };
  // Markup in one field of every entry, field by field.
  const base = golden();
  const width = Math.max(...base.entries.map(e => leaves(e).length));
  for (let k = 0; k < width; k++) {
    const t = golden();
    t.entries.forEach((e, i) => { const p = leaves(base.entries[i])[k]; if (p) setPath(e, p, MARK(p.join('.'))); });
    await check(`field #${k}`, t);
  }
  // Markup in every id and every reference to one.
  const hostileIds = golden();
  for (const e of hostileIds.entries) for (const k of IDS) {
    if (k in e) e[k] = Array.isArray(e[k]) ? e[k].map(() => MARK(k)) : MARK(k);
  }
  await check('ids', hostileIds);
  // Markup in every reference to another entry, the entries' own ids intact,
  // so the detail pane opens on each of them.
  const hostileRefs = golden();
  for (const e of hostileRefs.entries) for (const k of IDS) {
    if (k !== 'call_id' && k in e) e[k] = Array.isArray(e[k]) ? e[k].map(() => MARK(k)) : MARK(k);
  }
  await check('references', hostileRefs);
  // Ids written as strings.
  const stringIds = golden();
  for (const e of stringIds.entries) for (const k of IDS) {
    if (k in e) e[k] = Array.isArray(e[k]) ? e[k].map(String) : String(e[k]);
  }
  await check('string ids', stringIds);
  if (SINK_ONLY) { console.log('trace viewer harness: ok (sink only)'); return; }
  // Every field of every entry holding another JSON type.
  for (const [kind, value] of [['object', { a: 1 }], ['array', [1, 'b']], ['number', 7], ['null', null],
                               ['bool', true], ['toString', { toString: 1, valueOf: 1 }]]) {
    const t = golden();
    for (const e of t.entries) for (const k of Object.keys(e)) e[k] = JSON.parse(JSON.stringify(value));
    await check(`every field ${kind}`, t);
    // The same with ids, links and types intact, so the linked paths run.
    const linked = golden();
    for (const e of linked.entries) {
      for (const k of Object.keys(e)) if (!IDS.has(k) && k !== 'type') e[k] = JSON.parse(JSON.stringify(value));
    }
    await check(`every other field ${kind}`, linked);
  }
  // List fields holding odd elements, and the case id holding markup or an object.
  const oddLists = golden();
  for (const e of oddLists.entries) {
    for (const k of ['input_call_ids', 'recommended_actions', 'verification_challenges', 'evidence_audit']) {
      if (k in e) e[k] = [null, { toString: 1, valueOf: 1 }, MARK(k), ...e[k]];
    }
  }
  await check('odd list elements', oddLists);
  await check('case id markup', { ...golden(), case_id: MARK('case_id') });
  await check('case id object', { ...golden(), case_id: { toString: 1, valueOf: 1 } });
  // The entry list itself holding something else.
  for (const [kind, entries] of [['object', { a: 1 }], ['string', 'x'], ['mixed', [null, 5, 'x', [], golden().entries[1]]]]) {
    await check(`entries ${kind}`, { case_id: 'CASE-A', entries });
  }
  console.log(`trace viewer harness: ok (${runs} hostile traces)`);
}
main().then(() => process.exit(0), (e) => { console.error((e && e.stack) || e); process.exit(1); });
