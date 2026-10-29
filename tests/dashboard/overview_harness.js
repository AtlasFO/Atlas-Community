// Runs the Overview's own script under node with a stub shell and DOM.
// Run options dialog: after the page has shown two cases, one Start sends
// one start, for the case on screen; reopening the dialog and dismissing it
// (Esc leaves returnValue as it was) starts nothing. Run strip: how a run
// this dashboard started is said to have ended (finished, stopped by a
// user, stopping while the report is written, the documented exit codes in
// words, any other code as a number), with the user name escaped.
// Run by test_overview_js.py.
'use strict';
const fs = require('fs');
const assert = require('assert');

const html = fs.readFileSync(process.argv[2], 'utf8');
const src = html.slice(html.lastIndexOf('<script>') + '<script>'.length,
                       html.lastIndexOf('</script>'));

class El {
  constructor() { this.innerHTML = ''; this.textContent = ''; this.dataset = {}; this.style = {};
    this.value = ''; this.options = []; this.listeners = {}; this.returnValue = ''; this.open = false;
    this.classList = { add() {}, remove() {}, toggle() {}, contains: () => false }; }
  addEventListener(ev, fn) { (this.listeners[ev] ||= []).push(fn); }
  fire(ev) { (this.listeners[ev] || []).forEach((fn) => fn({})); }
  showModal() { this.open = true; }
  querySelector() { return null; }
  querySelectorAll() { return []; }
  setAttribute() {}
}
const els = {};
globalThis.document = { getElementById: (id) => (els[id] ||= new El()), querySelector: () => null,
  querySelectorAll: () => [], addEventListener() {}, body: new El(), hidden: false };
globalThis.window = globalThis;
globalThis.setInterval = () => 0;
globalThis.alert = () => {};
globalThis.prompt = () => null;
const starts = [];
globalThis.AtlasShell = {
  esc: (s) => String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;'),
  roleAtLeast: () => true,
  activeCase: () => null,
  isTransient: () => false,
  timeAgo: () => 'now',
  api: async (route) => (route === 'case/run/options' ? { options: [], modes: [] } : {}),
  apiPost: async (route, body) => { if (route === 'case/run/start') starts.push(body.case); return {}; },
  poll: () => () => {},
  init: () => {},
};
// The page's functions live in its script's scope; the harness reads them
// through one line appended to that script.
new Function(src + '\n;globalThis.__overview = { ensureRunOptionsHost, wireRunControls, runStripHtml, stopLineHtml };')();
const { ensureRunOptionsHost, wireRunControls, runStripHtml, stopLineHtml } = globalThis.__overview;
const flush = () => new Promise((r) => setImmediate(r));

async function dialog() {
  const host = els['run-options-panel-host'];
  ensureRunOptionsHost('CASE-A', 'run');
  ensureRunOptionsHost('CASE-B', 'run');      // an in-page case switch
  wireRunControls('CASE-B');
  assert.strictEqual((host.listeners.close || []).length, 1, 'the static dialog has one close handler, whatever the cases shown');
  const open = () => els['run-options-toggle'].listeners.click.at(-1)();
  open();
  host.returnValue = 'start';                 // the Start button closes the form with "start"
  host.fire('close');
  await flush();
  assert.deepStrictEqual(starts, ['CASE-B'], 'one Start, one start request, for the case on screen');
  open();
  host.fire('close');                         // Esc: no new returnValue
  await flush();
  assert.deepStrictEqual(starts, ['CASE-B'], 'dismissing the reopened dialog starts nothing');
}

function strip() {
  const label = (st) => runStripHtml({ dashboard_tracked: true, ...st }, {}).html
    .match(/<span class="rb-state"><span class="rb-dot"><\/span>([^<]*)<\/span>/)[1];
  assert.strictEqual(label({ running: false, returncode: -15, stop_requested_by: 'jane.doe',
    stop_requested_at: '2031-03-01T10:00:00Z' }), 'Run stopped by jane.doe');
  assert.strictEqual(label({ running: false, returncode: 0, finished_itself: true, stopped_reason: 'finished',
    stop_requested_by: 'jane.doe', stop_requested_at: '2031-03-01T10:00:00Z' }), 'Run finished',
    'a run that reached an ending stays finished');
  // A requested stop also writes a finish_status ("interrupted"): that is no
  // ending, and the server's flag says so.
  assert.strictEqual(label({ running: false, returncode: 130, finished_itself: false,
    stopped_reason: 'stop_requested', finish_status: 'interrupted',
    stop_requested_by: 'jane.doe', stop_requested_at: '2031-03-01T10:00:00Z' }), 'Run stopped by jane.doe');
  assert.strictEqual(label({ running: false, returncode: 1, finished_itself: false,
    stopped_reason: 'crashed', finish_status: 'error' }), 'Run stopped — unexpected error');
  // The loop's own ending word with content classes undecided: the server's
  // flags say a stop, and the strip names it, whatever the loop's reason.
  for (const stopped_reason of ['finished', 'closed_out', 'quiet', 'finish_deferred']) {
    assert.strictEqual(label({ running: false, returncode: 2, finished_itself: false, undecided_end: true,
      stopped_reason, finish_status: 'stopped_undecided' }),
      'Run stopped — content classes have neither a read nor a reason', stopped_reason);
  }
  assert.strictEqual(label({ running: false, returncode: 2, finished_itself: false, undecided_end: false,
    stopped_reason: 'finish_deferred', finish_status: 'incomplete_coverage' }),
    'Run stopped — the finish was held back and nothing followed');
  assert.strictEqual(label({ running: true, stop_requested_by: 'jane.doe',
    stop_requested_at: '2031-03-01T10:00:00Z' }), 'Stopping: the run writes its report');
  assert.strictEqual(label({ running: false, returncode: 0 }), 'Run finished');
  assert.strictEqual(label({ running: false, returncode: 1 }), 'Run ended: model or configuration error');
  assert.strictEqual(label({ running: false, returncode: 2 }), 'Run stopped before it finished');
  assert.strictEqual(label({ running: false, returncode: 4, finished_itself: true }),
    'Run finished, coverage incomplete');
  assert.strictEqual(label({ running: false, returncode: 2, stopped_reason: 'stop_requested' }),
    'Run stopped on request');
  assert.strictEqual(label({ running: false, returncode: 9 }), 'Run ended (exit code 9)');
  assert.strictEqual(label({ running: false, returncode: -15, stop_requested_by: '<b>x</b>',
    stop_requested_at: '2031-03-01T10:00:00Z' }), 'Run stopped by &lt;b&gt;x&lt;/b&gt;');
  // The same record with no session (a dashboard restart): the strip is idle
  // and the activity panel says the stop, not in the error colour.
  assert.strictEqual(runStripHtml({ running: false, dashboard_tracked: false }, {}).html
    .match(/<span class="rb-state"><span class="rb-dot"><\/span>([^<]*)<\/span>/)[1], 'Idle');
  const line = stopLineHtml({ last_stop: { reason: 'stop_requested', finish_status: 'interrupted', error: '' } });
  assert.match(line, /Run stopped on request/);
  assert.ok(!/var\(--bad\)/.test(line), 'a requested stop is not an error');
  assert.match(stopLineHtml({ last_stop: { reason: 'llm_error', error: 'context length exceeded' } }), /var\(--bad\)/);
  assert.strictEqual(stopLineHtml({ last_stop: null }), '');
  // The run's activity is free text of any length: it is its own fact, which
  // may fold within itself on a phone, while the numeric facts stay whole.
  const live = runStripHtml({ running: true, dashboard_tracked: true, turns: 12, duration_seconds: 90,
    input_tokens: 1000, output_tokens: 200,
    activity: 'Intake: fingerprinting evidence 4/9 under /cases/CASE-A/evidence/<b>' }, {}).html;
  assert.match(live, /<span class="rb-activity"><b>Intake: fingerprinting evidence 4\/9 under \/cases\/CASE-A\/evidence\/&lt;b&gt;<\/b><\/span>/,
    'the activity is its own folding fact, escaped');
  assert.match(live, /<span>turn <b>12<\/b><\/span>/, 'a numeric fact keeps the plain, unbreakable item');
  assert.strictEqual((live.match(/class="rb-activity"/g) || []).length, 1);
  assert.match(stopLineHtml({ last_stop: { reason: 'undecided_evidence', finish_status: 'stopped_undecided',
    error: '3 content class(es) with neither a read nor a reason: CORP-WS01 3.' } }),
    /var\(--bad\)[\s\S]*neither a read nor a reason[\s\S]*CORP-WS01 3/);
}

dialog().then(strip).then(() => { console.log('overview harness: ok'); process.exit(0); },
  (e) => { console.error((e && e.stack) || e); process.exit(1); });
