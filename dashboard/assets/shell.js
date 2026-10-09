/* ═══════════════════════════════════════════════════════════════════════
   Atlas dashboard shell — the ONE place that owns:

     • the active-case session (localStorage + URL sync)
     • the application header + navigation
     • the case picker (single implementation for every page)
     • the case-bound chat slide-over
     • small shared helpers (escaping, formatting, JSON fetch, polling)

   Session model
   ─────────────
   The active case is application state, persisted as localStorage
   'atlas.activeCase' so it survives reloads and page navigation. The URL
   stays a shareable deep link: on load, an explicit ?case= URL parameter
   wins over the stored value; afterwards the store wins and the URL is
   rewritten in place (history.replaceState). Security-sensitive state
   (the approval secret) deliberately stays in sessionStorage, scoped to
   the tab — never in localStorage.

   Pages call:
     AtlasShell.init({page:'overview', requiresCase:true, onCase:fn})
   and react to case changes via the onCase callback. Pages must not
   implement their own case pickers.
   ═══════════════════════════════════════════════════════════════════════ */
'use strict';

const AtlasShell = (() => {
  const LS_CASE = 'atlas.activeCase';
  const API = '/_dashboard/api/';
  // Theme + language live in assets/i18n.js, loaded from every page's
  // <head> before this script — see that file's docstring for why it's
  // separate (pre-auth pages need it without the rest of AtlasShell).
  const t = AtlasI18n.t;

  /* Inline SVG icon set. Deliberately not glyph characters: a pictograph
     depends on the platform's emoji font, renders at a size the type scale
     does not control, and reads as decoration in a tool analysts use for
     casework. These inherit colour via currentColor and scale with the
     surrounding font-size, so one definition works in both themes. */
  const ICON = {
    sun: '<svg viewBox="0 0 24 24" width="1em" height="1em" fill="none" '
       + 'stroke="currentColor" stroke-width="2" stroke-linecap="round" '
       + 'aria-hidden="true"><circle cx="12" cy="12" r="4.2"/>'
       + '<path d="M12 2.2v2.1M12 19.7v2.1M4.6 4.6l1.5 1.5M17.9 17.9l1.5 1.5'
       + 'M2.2 12h2.1M19.7 12h2.1M4.6 19.4l1.5-1.5M17.9 6.1l1.5-1.5"/></svg>',
    moon: '<svg viewBox="0 0 24 24" width="1em" height="1em" fill="none" '
        + 'stroke="currentColor" stroke-width="2" stroke-linecap="round" '
        + 'stroke-linejoin="round" aria-hidden="true">'
        + '<path d="M20.8 13.1A8.6 8.6 0 1 1 10.9 3.2a6.7 6.7 0 0 0 9.9 9.9z"/></svg>',
    chat: '<svg viewBox="0 0 24 24" width="1em" height="1em" fill="none" '
        + 'stroke="currentColor" stroke-width="2" stroke-linecap="round" '
        + 'stroke-linejoin="round" aria-hidden="true">'
        + '<path d="M20.5 11.8a8 8 0 0 1-8.6 8 8.6 8.6 0 0 1-3.1-.6L3.5 21l'
        + '1.6-4.7a7.8 7.8 0 0 1-.7-3.3 8 8 0 0 1 8.1-8 8 8 0 0 1 8 7.9z"/></svg>',
    close: '<svg viewBox="0 0 24 24" width="1em" height="1em" fill="none" '
         + 'stroke="currentColor" stroke-width="2" stroke-linecap="round" '
         + 'aria-hidden="true"><path d="M6 6l12 12M18 6L6 18"/></svg>',
  };

  // Case-scoped views (tabs) and global views. `file` is the physical page.
  // `requiresPlugin: 'timeline'` → tab is hidden unless capabilities say so.
  const CASE_NAV = [
    { id: 'overview',  label: 'Overview',  file: 'overview.html' },
    { id: 'questions', label: 'Questions', file: 'questions.html' },
    { id: 'claims',    label: 'Case Findings', file: 'claim_view.html' },
    { id: 'iocs',      label: 'IoCs',      file: 'iocs.html' },
    { id: 'response',  label: 'Response',  file: 'recommendations.html' },
    { id: 'process',   label: 'Process',   file: 'dashboard.html' },
    { id: 'report',    label: 'Report',    file: 'report.html' },
    { id: 'casemd',    label: 'Brief',     file: 'case_md.html' },
    { id: 'timeline',  label: 'Timeline',  file: 'timeline.html',
      requiresPlugin: 'timeline' },
  ];
  const GLOBAL_NAV = [
    { id: 'brain', label: 'Brain', file: 'brain.html', requiresRole: 'analyst' },
  ];

  const S = {
    page: '',
    requiresCase: true,
    cases: [],            // [{case_id, case_dir, traces:[...]}]
    activeCase: null,     // case_dir
    caseListeners: [],
    stopBusy: null,       // cancel function of the activity poll
    pollers: new Set(),   // every live poll() tick, so the change stream can run them
    live: false,          // the change stream is connected
    silentSince: 0,       // when the server stopped answering (0 while healthy)
    offlineShown: false,  // the chip currently says offline because of that
    leaving: false,       // set once we redirect to login, so nothing re-fires it
    working: false,
    runningCases: null, // [{case_dir, case_id, activity}] — every live run; null until fetched

    timelinePlugin: false,
    user: null,            // {id, username, email, role}
    viewerChatEnabled: false,
  };

  const ROLE_RANK = { viewer: 0, analyst: 1, admin: 2 };
  function roleAtLeast(role, minimum) {
    return (ROLE_RANK[role] ?? -1) >= (ROLE_RANK[minimum] ?? 99);
  }
  function canChat() {
    if (!S.user) return false;
    return roleAtLeast(S.user.role, 'analyst') || S.viewerChatEnabled;
  }

  /* ── helpers ─────────────────────────────────────────────────────────── */

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
    }[c]));
  }

  function fmtBytes(n) {
    n = Number(n) || 0;
    if (n < 1024) return `${n} B`;
    const units = ['KB', 'MB', 'GB', 'TB'];
    let u = -1;
    do { n /= 1024; u++; } while (n >= 1024 && u < units.length - 1);
    return `${n < 10 ? n.toFixed(1) : Math.round(n)} ${units[u]}`;
  }

  function timeAgo(tsOrEpoch) {
    if (!tsOrEpoch) return '';
    const t = typeof tsOrEpoch === 'number'
      ? tsOrEpoch * (tsOrEpoch < 1e12 ? 1000 : 1)
      : Date.parse(tsOrEpoch);
    if (!Number.isFinite(t)) return '';
    const s = Math.max(0, (Date.now() - t) / 1000);
    if (s < 60) return 'just now';
    if (s < 3600) return `${Math.floor(s / 60)}m ago`;
    if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
    return `${Math.floor(s / 86400)}d ago`;
  }

  /* One network policy for every request the shell or a page makes:
       - a request with no answer within FETCH_TIMEOUT_MS is abandoned, so a
         half-open connection (laptop sleep, server restart) can never hang a
         poll loop for good;
       - the activity chip flips to offline only once the server has stayed
         silent for OFFLINE_AFTER_MS — a dropped request or two during a
         page load is not an outage and must not flash red (a poll round
         fires several requests at once, so counting requests would not do);
       - a session that expired while the tab was open (the API answers 401,
         a raw case file redirects to login.html) sends the tab to the login
         page instead of leaving it silently frozen. */
  const FETCH_TIMEOUT_MS = 15000;
  const OFFLINE_AFTER_MS = 10000;

  // The return path keeps the fragment: a page's section lives there, and
  // a script navigation, unlike a redirect, carries none over.
  function toLogin() {
    if (S.leaving) return;
    S.leaving = true;
    const next = encodeURIComponent(location.pathname + location.search + location.hash);
    location.href = `login.html?next=${next}`;
  }

  async function fetchJson(url, init) {
    const started = Date.now();
    let resp;
    try {
      resp = await fetch(url, { signal: AbortSignal.timeout(FETCH_TIMEOUT_MS), ...(init || {}) });
    } catch (e) {
      if (e && e.name === 'AbortError') {
        // The page gave the request up itself; the server is not silent.
        const err = new Error('cancelled');
        err.cancelled = true;
        throw err;
      }
      if (!S.silentSince) S.silentSince = started;
      if (Date.now() - S.silentSince >= OFFLINE_AFTER_MS && !S.offlineShown) {
        S.offlineShown = true;
        setOffline();
      }
      const err = new Error(e && e.name === 'TimeoutError'
        ? `no answer within ${FETCH_TIMEOUT_MS / 1000}s` : 'server unreachable');
      err.network = true;
      throw err;
    }
    if (S.silentSince) {
      S.silentSince = 0;
      if (S.offlineShown) { S.offlineShown = false; setWorking(S.working); }
    }
    if (resp.status === 401 || (resp.redirected && /login\.html/.test(resp.url))) {
      toLogin();
      return new Promise(() => {});   // the browser is navigating away
    }
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) {
      const err = new Error(data.error || `HTTP ${resp.status}`);
      err.status = resp.status;
      err.data = data;
      throw err;
    }
    return data;
  }

  /** True while a failure is still inside the tolerated window: nothing came
   * back, but the server has not been silent long enough to call it an
   * outage. Pages keep what is on screen for these and let the next poll
   * retry. */
  function isTransient(err) {
    return !!(err && err.network) && !!S.silentSince
      && Date.now() - S.silentSince < OFFLINE_AFTER_MS;
  }

  function api(endpoint, params) {
    const q = new URLSearchParams(params || {});
    return fetchJson(API + endpoint + (q.toString() ? `?${q}` : ''), { cache: 'no-store' });
  }

  /** POST JSON. A request that waits on work with no bound of its own — a
   * model answering — passes its own `signal` (an AbortController the page
   * can cancel from) in `opts` and is then not abandoned after
   * FETCH_TIMEOUT_MS. */
  function apiPost(endpoint, body, opts) {
    return fetchJson(API + endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body || {}),
      ...(opts && opts.signal ? { signal: opts.signal } : {}),
    });
  }

  const Auth = {
    /** Resolves the current session, or redirects to login.html and never
     * resolves (the caller's await just hangs while the browser navigates
     * away — this is intentional, matching a page that has nothing to
     * render without a session). */
    async require() {
      let data;
      try {
        data = await api('whoami');
      } catch (_e) {
        data = { authenticated: false };
      }
      if (!data.authenticated) {
        toLogin();
        return new Promise(() => {});
      }
      S.user = data.user;
      S.viewerChatEnabled = !!data.viewer_chat_enabled;
      return data.user;
    },
    async logout() {
      try { await apiPost('logout'); } catch (_e) { /* best effort */ }
      location.href = 'login.html';
    },
  };

  /** Managed polling. `fn` runs at once, then every `ms` while the tab is
   * visible. A hidden tab skips the timer work (the browser throttles the
   * timer to about once a minute anyway), and the moment it is visible again
   * the next round runs immediately instead of waiting out whatever delay
   * the throttling left behind. One round at a time: a slow answer never
   * stacks a second request behind it.
   *
   * While the change stream is connected the timer backs off to
   * LIVE_POLL_MS and the stream runs the round the moment the case changes
   * — hidden tab included, so it is already current when it comes back.
   * `opts.everyCase` marks a round that must run for a change in any case
   * (the shell's activity chip), not only the one on screen.
   * Returns a cancel function. */
  function poll(fn, ms, opts) {
    let timer = null;
    let stopped = false;
    let running = false;
    const tick = async (force) => {
      if (stopped || running) return;
      clearTimeout(timer);
      if (force === true || !document.hidden) {
        running = true;
        try { await fn(); } catch (_e) { /* pages render their own errors */ }
        running = false;
      }
      if (!stopped) timer = setTimeout(tick, S.live ? Math.max(ms, LIVE_POLL_MS) : ms);
    };
    tick.everyCase = !!(opts && opts.everyCase);
    const onVisible = () => { if (!document.hidden) tick(); };
    document.addEventListener('visibilitychange', onVisible);
    S.pollers.add(tick);
    tick();
    return () => {
      stopped = true;
      clearTimeout(timer);
      S.pollers.delete(tick);
      document.removeEventListener('visibilitychange', onVisible);
    };
  }

  /* Server push. One EventSource per tab tells the shell *that* a case
     changed on disk; the registered polls then run at once instead of
     waiting for their timer. The stream is the primary trigger and the
     timer the safety net. EventSource reconnects on its own — nothing here
     re-implements that — and every (re)connect runs every poll once, since
     anything may have changed while the stream was down. */
  const LIVE_POLL_MS = 30000;

  function kick(want) {
    S.pollers.forEach((tick) => { if (want(tick)) tick(true); });
  }

  const Live = {
    source: null,
    connect() {
      if (this.source || typeof EventSource === 'undefined') return;
      const es = new EventSource(API + 'events');
      es.onopen = () => { S.live = true; kick(() => true); };
      es.onerror = () => {
        if (!S.live) return;         // still reconnecting; one kick per drop
        S.live = false;
        kick(() => true);            // back on the fast timer from now on
      };
      es.addEventListener('change', (ev) => {
        let changed;
        try { changed = JSON.parse(ev.data).case; } catch (_e) { return; }
        kick((tick) => tick.everyCase || changed === S.activeCase);
      });
      this.source = es;
    },
  };

  /* Minimal Markdown → HTML (headings, bold, code, links, lists, tables).
     Escapes first; good enough for reports + chat, no raw-HTML passthrough. */
  function renderMarkdown(md) {
    const lines = String(md || '').split('\n');
    const out = [];
    let inCode = false, inList = false, inTable = false;
    const inline = (s) => esc(s)
      .replace(/`([^`]+)`/g, '<code>$1</code>')
      .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
      .replace(/(?<!\*)\*([^*\s][^*]*)\*(?!\*)/g, '<em>$1</em>')
      .replace(/\[([^\]]+)\]\((https?:[^)\s]+)\)/g,
               '<a href="$2" target="_blank" rel="noopener">$1</a>')
      // In-page links: the report's table of contents is written as
      // [4. Detailed Findings](#4-detailed-findings) and every finding is
      // reachable as (#f-001). Left unhandled these rendered as plain text,
      // so a long report had no navigation at all.
      .replace(/\[([^\]]+)\]\(#([a-z0-9._-]+)\)/gi,
               '<a href="#$2" class="md-jump">$1</a>');
    const closeAll = () => {
      if (inList) { out.push('</ul>'); inList = false; }
      if (inTable) { out.push('</table>'); inTable = false; }
    };
    for (const raw of lines) {
      if (/^\s*```/.test(raw)) {
        closeAll();
        out.push(inCode ? '</pre>' : '<pre>');
        inCode = !inCode;
        continue;
      }
      if (inCode) { out.push(esc(raw)); continue; }
      // The assembler marks each finding with its own anchor so the table of
      // contents can reach it. Everything here is escaped, so the tag itself
      // was printed into the report as text. Emit the anchor instead — the
      // id pattern is narrow and generated by us, never user prose.
      const anchor = raw.match(/^\s*<a id="([a-z0-9._-]+)"><\/a>\s*$/i);
      if (anchor) { out.push(`<a id="${anchor[1]}"></a>`); continue; }
      const h = raw.match(/^(#{1,4})\s+(.*)$/);
      if (h) { closeAll(); const n = h[1].length + 1;
        out.push(`<h${n}>${inline(h[2])}</h${n}>`); continue; }
      if (/^\s*\|/.test(raw)) {
        if (/^\s*\|[\s:|-]+\|\s*$/.test(raw)) continue; // separator row
        if (!inTable) { closeAll(); out.push('<table class="md-table">'); inTable = true; }
        const cells = raw.trim().replace(/^\||\|$/g, '').split('|');
        out.push('<tr>' + cells.map(c => `<td>${inline(c.trim())}</td>`).join('') + '</tr>');
        continue;
      }
      const li = raw.match(/^\s*[-*+]\s+(.*)$/);
      if (li) {
        if (inTable) { out.push('</table>'); inTable = false; }
        if (!inList) { out.push('<ul>'); inList = true; }
        out.push(`<li>${inline(li[1])}</li>`);
        continue;
      }
      closeAll();
      if (raw.trim() === '') { out.push(''); continue; }
      out.push(`<p>${inline(raw)}</p>`);
    }
    if (inCode) out.push('</pre>');
    closeAll();
    return out.join('\n');
  }

  /* ── session (active case) ───────────────────────────────────────────── */

  function activeCase() { return S.activeCase; }

  function caseInfo() {
    return S.cases.find(c => c.case_dir === S.activeCase) || null;
  }

  function setActiveCase(caseDir, opts) {
    caseDir = caseDir || null;
    const changed = caseDir !== S.activeCase;
    S.activeCase = caseDir;
    try {
      if (caseDir) localStorage.setItem(LS_CASE, caseDir);
      else localStorage.removeItem(LS_CASE);
    } catch (_e) { /* storage may be unavailable; session still works */ }
    // Keep the URL a shareable deep link for the current view.
    const u = new URL(window.location.href);
    if (caseDir) u.searchParams.set('case', caseDir);
    else u.searchParams.delete('case');
    history.replaceState(null, '', u.toString());
    syncHeader();
    if (changed) renderBusy();
    if (changed || (opts && opts.force)) {
      Chat.onCaseChanged();
      for (const cb of S.caseListeners) {
        try { cb(caseDir); } catch (_e) { /* page callback error */ }
      }
    }
  }

  function onCaseChange(cb) { S.caseListeners.push(cb); }

  function resolveInitialCase() {
    const urlCase = new URLSearchParams(window.location.search).get('case');
    let stored = null;
    try { stored = localStorage.getItem(LS_CASE); } catch (_e) { /* n/a */ }
    const known = new Set(S.cases.map(c => c.case_dir));
    if (urlCase && known.has(urlCase)) return urlCase;   // deep link wins
    if (stored && known.has(stored)) return stored;      // session survives
    if (S.cases.length === 1) return S.cases[0].case_dir;
    return null;
  }

  /* ── header / nav rendering ──────────────────────────────────────────── */

  function href(file) {
    return S.activeCase
      ? `${file}?case=${encodeURIComponent(S.activeCase)}` : file;
  }

  function pluginVisible(view) {
    if (!view.requiresPlugin) return true;
    if (view.requiresPlugin === 'timeline') return !!S.timelinePlugin;
    return false;
  }

  function roleVisible(view) {
    if (!view.requiresRole) return true;
    return !!S.user && roleAtLeast(S.user.role, view.requiresRole);
  }

  function renderHeader() {
    const el = document.createElement('div');
    el.className = 'atlas-shell';
    const caseTabs = CASE_NAV.map(v =>
      `<a href="${href(v.file)}" data-nav="${v.id}"
          data-requires-plugin="${v.requiresPlugin || ''}"
          class="${v.id === S.page ? 'active' : ''}"
          ${pluginVisible(v) ? '' : 'hidden'}>${t(`nav.${v.id}`, v.label)}</a>`).join('');
    const globalTabs = GLOBAL_NAV.filter(roleVisible).map(v =>
      `<a href="${v.file}" data-nav="${v.id}"
          class="global ${v.id === S.page ? 'active' : ''}">${t(`nav.${v.id}`, v.label)}<span
          class="nav-badge" data-badge="${v.id}" hidden></span></a>`).join('');
    const isAdmin = S.user && roleAtLeast(S.user.role, 'admin');
    const canManageCases = S.user && roleAtLeast(S.user.role, 'analyst');
    // Account identity and Log out are one object (see .shell-account), so
    // "who am I" and "stop being them" sit together instead of as two loose
    // spans at the end of a button row.
    const userMenu = S.user ? `
        <div class="shell-account" title="${esc(S.user.email)}">
          <span class="acct-id">
            <span class="acct-name">${esc(S.user.username)}</span>
            <span class="acct-role">${esc(S.user.role)}</span>
          </span>
          <button class="shell-btn" id="atlas-logout">${t('shell.logout')}</button>
        </div>` : '';
    const configLink = (S.user && isAdmin)
      ? `<a class="shell-btn" href="config.html">${t('shell.config')}</a>` : '';
    const theme = AtlasI18n.getTheme();
    const nextThemeLabel = theme === 'dark' ? t('theme.toggle.toLight') : t('theme.toggle.toDark');
    const themeTitle = t('theme.toggle.title', { mode: nextThemeLabel });
    // Icon, not a word: the toggle is shaped differently from every other
    // control in the row because it restyles the whole application rather
    // than navigating anywhere. The label survives as the accessible name.
    const themeIcon = theme === 'dark' ? ICON.sun : ICON.moon;
    const lang = AtlasI18n.getLang();
    el.innerHTML = `
      <div class="shell-row">
        <a class="brand" href="overview.html">Atlas</a>
        <div class="case-picker">
          <label for="atlas-case-select">${t('shell.case')}</label>
          <select id="atlas-case-select" class="case-select"
                  title="${t('shell.caseSelectTitle')}">
            <option value="">${t('shell.caseSelectPlaceholder')}</option>
          </select>
          ${canManageCases ? `<a class="shell-btn" href="new_case.html">${t('shell.newCase')}</a>` : ''}
        </div>
        <span class="shell-activity" id="atlas-activity" tabindex="0">
          <span class="dot"></span><span id="atlas-activity-text">${t('shell.idle')}</span>
          <span class="activity-pop" id="atlas-activity-pop" role="tooltip"></span>
        </span>
        <span class="shell-spacer"></span>
        <div class="shell-tools">
          <button class="theme-toggle" id="atlas-theme-toggle"
                  title="${esc(themeTitle)}" aria-label="${esc(nextThemeLabel)}"
          >${themeIcon}</button>
          <select class="shell-btn" id="atlas-lang-select" title="${t('lang.toggle.title')}">
            <option value="en" ${lang === 'en' ? 'selected' : ''}>EN</option>
            <option value="de" ${lang === 'de' ? 'selected' : ''}>DE</option>
          </select>
          ${configLink ? '<span class="tools-sep"></span>' : ''}
          ${configLink}
          ${userMenu}
        </div>
      </div>
      <nav class="shell-nav">
        ${caseTabs}
        <span class="nav-gap"></span>
        ${globalTabs}
      </nav>`;
    document.body.prepend(el);
    document.getElementById('atlas-case-select')
      .addEventListener('change', (ev) => setActiveCase(ev.target.value || null));
    document.getElementById('atlas-theme-toggle')
      .addEventListener('click', (ev) => {
        const next = AtlasI18n.getTheme() === 'dark' ? 'light' : 'dark';
        AtlasI18n.setTheme(next);
        // Theme is pure CSS (the data-theme attribute already flips every
        // token) — only the toggle button's own label/title need updating
        // in place. Rebuilding the whole header here would tear down and
        // recreate #atlas-chat-toggle, orphaning Chat.build()'s listener
        // on it (attached once, at init time) — a real regression, not a
        // hypothetical one.
        const btn = ev.currentTarget;
        const nextLabel = next === 'dark' ? t('theme.toggle.toLight') : t('theme.toggle.toDark');
        btn.innerHTML = next === 'dark' ? ICON.sun : ICON.moon;
        btn.title = t('theme.toggle.title', { mode: nextLabel });
        btn.setAttribute('aria-label', nextLabel);
      });
    document.getElementById('atlas-lang-select')
      .addEventListener('change', (ev) => {
        AtlasI18n.setLang(ev.target.value);
        // Every t()-driven string on the page needs to re-render, and this
        // codebase renders via one-shot innerHTML template calls, not a
        // reactive framework — a full reload is the simplest correct way
        // to apply a language change everywhere at once.
        location.reload();
      });
    const logout = document.getElementById('atlas-logout');
    if (logout) logout.addEventListener('click', () => Auth.logout());
  }

  function syncHeader() {
    const sel = document.getElementById('atlas-case-select');
    if (sel) {
      const opts = [`<option value="">${t('shell.caseSelectPlaceholder')}</option>`];
      for (const c of S.cases) {
        const label = c.case_id === c.case_dir
          ? c.case_id : `${c.case_id} (${c.case_dir})`;
        opts.push(`<option value="${esc(c.case_dir)}">${esc(label)}</option>`);
      }
      sel.innerHTML = opts.join('');
      sel.value = S.activeCase || '';
    }
    document.querySelectorAll('.atlas-shell nav a[data-nav]').forEach(a => {
      const id = a.dataset.nav;
      const view = CASE_NAV.find(v => v.id === id);
      if (view) {
        a.href = href(view.file);
        a.hidden = !pluginVisible(view);
      }
    });
  }

  async function loadCapabilities() {
    try {
      const d = await api('capabilities');
      S.timelinePlugin = !!d.timeline_plugin_active;
    } catch (_e) {
      S.timelinePlugin = false;
    }
    syncHeader();
  }

  function setWorking(working, text) {
    S.working = !!working;
    const el = document.getElementById('atlas-activity');
    const textEl = document.getElementById('atlas-activity-text');
    if (!el || !textEl) return;
    el.classList.toggle('working', !!working);
    el.classList.remove('offline');
    textEl.textContent = text || (working ? t('shell.working') : t('shell.idle'));
  }

  function setOffline(text) {
    const el = document.getElementById('atlas-activity');
    const textEl = document.getElementById('atlas-activity-text');
    if (!el || !textEl) return;
    el.classList.remove('working');
    el.classList.add('offline');
    textEl.textContent = text || t('shell.offline');
  }

  /** Fill the activity chip's hover card from the running-case list. */
  function renderRunningPopover(running) {
    const pop = document.getElementById('atlas-activity-pop');
    if (!pop) return;
    if (!running.length) {
      pop.innerHTML = `<div class="ap-empty">${esc(t('shell.noRuns'))}</div>`;
      return;
    }
    const rows = running.map(r => {
      // The card's job is to say which OTHER cases are busy, so mark the one
      // already on screen instead of letting it read like an unrelated case.
      const here = r.case_dir === S.activeCase
        ? `<span class="ap-here">${esc(t('shell.thisCase'))}</span>` : '';
      const what = r.activity ? `<span class="ap-what">${esc(r.activity)}</span>` : '';
      return `<a class="ap-row" href="overview.html?case=${encodeURIComponent(r.case_dir)}">
                <span class="ap-dot"></span>
                <span class="ap-body">
                  <span class="ap-name">${esc(r.case_id || r.case_dir)}${here}</span>
                  ${what}
                </span>
              </a>`;
    }).join('');
    pop.innerHTML =
      `<div class="ap-head">${esc(running.length === 1 ? t('shell.runningOne') : t('shell.runningMany', { n: running.length }))}</div>${rows}`;
  }

  /** The run pill and its hover card, from the cached run list and the case
   *  on screen. Both inputs change: the list on every poll, the case when the
   *  analyst picks another one, so both re-render it. Nothing is drawn before
   *  the first list arrives. */
  function renderBusy() {
    const running = S.runningCases;
    if (!running) return;
    const el = document.getElementById('atlas-activity');
    if (el) el.classList.toggle('has-runs', running.length > 0);
    if (!running.length) {
      setWorking(false, S.activeCase ? t('shell.idle') : t('shell.noCase'));
    } else if (running.length === 1) {
      const only = running[0];
      // Name the case when the run is somewhere the analyst is not looking;
      // a bare "Atlas working" would imply it is this case.
      setWorking(true, only.case_dir === S.activeCase
        ? t('shell.working')
        : t('shell.workingElsewhere', { case: only.case_id || only.case_dir }));
    } else {
      setWorking(true, t('shell.workingN', { n: running.length }));
    }
    renderRunningPopover(running);
  }

  async function refreshBusy() {
    // Case-wide, not scoped to the selected case: a run in any case has to
    // light this indicator up, including before a case has been picked at
    // all. This used to ask the per-case questions projection for
    // S.activeCase only, so a run elsewhere left the header reading "idle".
    try {
      const d = await api('runs/active');
      S.runningCases = Array.isArray(d.running) ? d.running : [];
      renderBusy();
    } catch (_e) { /* fetchJson tracks the outage; the chip flips after OFFLINE_AFTER_MS */ }
  }

  /* ── shared chat slide-over (case-bound) ─────────────────────────────── */

  const Chat = {
    cursor: 0,
    busy: false,
    pollTimer: null,
    _inflight: false,

    root() { return document.getElementById('atlas-chat'); },
    hidden() { const p = this.root(); return !p || !p.classList.contains('open'); },

    build() {
      const el = document.createElement('div');
      el.className = 'atlas-chat';
      el.id = 'atlas-chat';
      el.innerHTML = `
        <div class="chat-head">
          <span class="chat-title">${t('chat.title')}</span>
          <span class="chat-case" id="atlas-chat-case"></span>
          <button class="chat-close" id="atlas-chat-close" title="${t('chat.close')}">${ICON.close}</button>
        </div>
        <div class="chat-messages" id="atlas-chat-messages"></div>
        <div class="chat-activity" id="atlas-chat-activity"></div>
        <div class="chat-input-row">
          <textarea id="atlas-chat-input" rows="2"
            placeholder="${t('chat.placeholder')}"></textarea>
          <button id="atlas-chat-send" class="chat-send">${t('chat.send')}</button>
        </div>`;
      document.body.appendChild(el);
      document.getElementById('atlas-chat-close')
        .addEventListener('click', () => this.close());
      document.getElementById('atlas-chat-send')
        .addEventListener('click', () => this.send());
      document.getElementById('atlas-chat-input')
        .addEventListener('keydown', (e) => {
          if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); this.send(); }
        });
      const fab = document.createElement('button');
      fab.className = 'chat-fab';
      fab.id = 'atlas-chat-toggle';
      fab.title = t('shell.chatTitle');
      fab.innerHTML = `<span class="fab-icon">${ICON.chat}</span>`
        + `<span>${esc(t('shell.chat'))}</span>`;
      fab.hidden = !canChat();
      document.body.appendChild(fab);
      fab.addEventListener('click', () => this.toggle());
      this.renderStatus();
    },

    renderMd(text) {
      let s = esc(text);
      s = s.replace(/`([^`]+)`/g, '<code>$1</code>');
      s = s.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
      return s;
    },

    setActivity(text) {
      const a = document.getElementById('atlas-chat-activity');
      if (a) a.textContent = text || '';
    },

    setBusy(b) {
      this.busy = b;
      const send = document.getElementById('atlas-chat-send');
      if (send) send.disabled = b || !activeCase();
    },

    renderStatus() {
      const cd = activeCase();
      const caseEl = document.getElementById('atlas-chat-case');
      if (caseEl) caseEl.textContent = cd || t('chat.noCaseSelected');
      const send = document.getElementById('atlas-chat-send');
      const input = document.getElementById('atlas-chat-input');
      if (send) send.disabled = !cd || this.busy;
      if (input) input.disabled = !cd;
      if (!cd) this.setActivity(t('chat.selectCaseToChat'));
    },

    appendEvent(ev) {
      const host = document.getElementById('atlas-chat-messages');
      if (!host) return;
      const empty = host.querySelector('.chat-empty');
      if (empty) empty.remove();
      const el = document.createElement('div');
      if (ev.type === 'user') {
        el.className = 'chat-msg user'; el.textContent = ev.text || '';
      } else if (ev.type === 'assistant') {
        el.className = 'chat-msg assistant'; el.innerHTML = this.renderMd(ev.text || '');
      } else if (ev.type === 'tool_call') {
        el.className = 'chat-tool';
        const args = String(ev.args_preview || '').slice(0, 80);
        el.innerHTML = `<span class="tool-dot" aria-hidden="true"></span>`
          + `<span class="tname">${esc(ev.name || '')}</span> `
          + `<span style="opacity:.7">${esc(args)}</span>`;
      } else if (ev.type === 'error') {
        el.className = 'chat-err'; el.textContent = ev.message || 'error';
      } else { return; }
      host.appendChild(el);
      host.scrollTop = host.scrollHeight;
    },

    async poll() {
      if (this._inflight) {
        clearTimeout(this.pollTimer);
        this.pollTimer = setTimeout(() => this.poll(), 300);
        return;
      }
      const cd = activeCase();
      if (!cd || this.hidden()) return;
      this._inflight = true;
      let data;
      try {
        const r = await fetch(
          `${API}chat/poll?case=${encodeURIComponent(cd)}&since=${this.cursor}`,
          { cache: 'no-store', signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
        data = await r.json();
      } catch (_e) {
        this._inflight = false;
        this.setActivity('connection lost — retrying…');
        this.pollTimer = setTimeout(() => this.poll(), 2000);
        return;
      }
      this._inflight = false;
      // The case may have switched while the request was in flight —
      // never render another case's events (cross-case leakage guard).
      if (activeCase() !== cd) return;
      (data.events || []).forEach(ev => this.appendEvent(ev));
      if (typeof data.total === 'number') this.cursor = data.total;
      if (data.busy) {
        this.setBusy(true);
        this.setActivity('working…');
        clearTimeout(this.pollTimer);
        this.pollTimer = setTimeout(() => this.poll(), 1000);
      } else {
        this.setBusy(false);
        this.setActivity('');
        this.renderStatus();
      }
    },

    async send() {
      const cd = activeCase();
      if (!cd || this.busy) return;
      const input = document.getElementById('atlas-chat-input');
      const text = (input.value || '').trim();
      if (!text) return;
      input.value = '';
      this.setBusy(true);
      this.setActivity('sending…');
      try {
        const r = await fetch(`${API}chat/send`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ case: cd, message: text }),
        });
        const d = await r.json().catch(() => ({}));
        if (!r.ok || d.ok === false) {
          this.setBusy(false); this.setActivity('');
          this.appendEvent({ type: 'error',
            message: d.error || `send failed (HTTP ${r.status})` });
          return;
        }
      } catch (e) {
        this.setBusy(false); this.setActivity('');
        this.appendEvent({ type: 'error', message: `send failed: ${e.message}` });
        return;
      }
      this.setActivity('working…');
      this.poll();
    },

    onCaseChanged() {
      // Hard reset: cursor + transcript belong to exactly one case.
      clearTimeout(this.pollTimer);
      this.cursor = 0;
      this.setBusy(false);
      const host = document.getElementById('atlas-chat-messages');
      if (host) {
        const cd = activeCase();
        host.innerHTML = cd
          ? '<div class="chat-empty">Ask about this case — Atlas runs its forensic tools as needed.</div>'
          : '<div class="chat-empty">Select a case to ask Atlas about it.</div>';
      }
      this.renderStatus();
      if (!this.hidden() && activeCase()) this.poll();
    },

    setFabTucked(tucked) {
      const fab = document.getElementById('atlas-chat-toggle');
      if (fab) fab.classList.toggle('tucked', !!tucked);
    },
    open() {
      const p = this.root(); if (!p) return;
      p.classList.add('open');
      this.setFabTucked(true);
      this.renderStatus();
      if (activeCase()) {
        this.poll();
        const i = document.getElementById('atlas-chat-input');
        if (i) i.focus();
      }
    },
    close() {
      const p = this.root(); if (p) p.classList.remove('open');
      this.setFabTucked(false);
      clearTimeout(this.pollTimer);
    },
    toggle() { this.hidden() ? this.open() : this.close(); },
  };

  /* ── boot ────────────────────────────────────────────────────────────── */

  async function loadCases() {
    try {
      const data = await api('cases');
      S.cases = data.cases || [];
    } catch (_e) {
      S.cases = [];
    }
  }

  /**
   * init({page, requiresCase, onCase}) — pages call this once.
   * `onCase(caseDir)` fires with the initial case (possibly null) and on
   * every later change. Returns a promise resolved after first dispatch.
   */
  async function init(opts) {
    S.page = (opts && opts.page) || '';
    S.requiresCase = !opts || opts.requiresCase !== false;
    // The server already gates the page load itself (a session-less request
    // never reaches here) — this fetches the role/user data the nav needs to
    // render, and is a second check in case a long-lived tab's session
    // expired since the page was first loaded.
    await Auth.require();
    renderHeader();
    Chat.build();
    await Promise.all([loadCases(), loadCapabilities()]);
    if (opts && opts.onCase) onCaseChange(opts.onCase);
    const initial = resolveInitialCase();
    // force:true → listeners always get the initial dispatch, even for null.
    setActiveCase(initial, { force: true });
    // Shell-level "Atlas working" indicator. Runs on every page, global ones
    // included: the whole point of the case-wide check is that it reports a
    // live run regardless of which case — or no case — is on screen.
    S.stopBusy = poll(refreshBusy, 8000, { everyCase: true });
    Live.connect();
    // Brain review badge (pending candidates) — best effort, all pages.
    // brain/* is analyst+ only (viewers can't reach it at all), so skip the
    // call rather than draw a guaranteed 403 every page load.
    if (S.user && roleAtLeast(S.user.role, 'analyst')) {
      try {
        const d = await api('brain/candidates');
        const n = (d.candidates || []).length;
        const badge = document.querySelector('[data-badge="brain"]');
        if (badge && n > 0) { badge.textContent = n; badge.hidden = false; }
      } catch (_e) { /* brain optional */ }
    }
    return initial;
  }

  return {
    init, api, apiPost, fetchJson, isTransient, poll, esc, fmtBytes, timeAgo,
    renderMarkdown, live: Live,
    activeCase, setActiveCase, onCaseChange, caseInfo,
    setWorking, setOffline,
    cases: () => S.cases,
    timelinePluginActive: () => !!S.timelinePlugin,
    chat: Chat,
    auth: Auth,
    currentUser: () => S.user,
    canChat,
    roleAtLeast: (minimum) => !!S.user && roleAtLeast(S.user.role, minimum),
    // Theme + language — thin re-export of assets/i18n.js (loaded before
    // this file); pages should call these, not AtlasI18n directly, so
    // there's one documented entry point for both.
    t,
    lang: () => AtlasI18n.getLang(),
    theme: () => AtlasI18n.getTheme(),
  };
})();
