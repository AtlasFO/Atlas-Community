/* ═══════════════════════════════════════════════════════════════════════
   Atlas dashboard — theme + language, shared by every page.

   Deliberately a separate, tiny, non-AtlasShell script: shell.js owns the
   case-bound chrome (header/nav/chat) that only makes sense once a user is
   signed in, but the pre-auth pages (login.html, reset_password.html) need
   theme + language too, and shouldn't have to load all of shell.js's
   case/auth machinery to get it.

   Load this BEFORE atlas.css's stylesheet finishes applying — i.e. as
   early as possible in <head> — so the stored theme lands on <html> before
   first paint. A page that loads it after body content (the old shell.js
   pattern) gets a brief flash of the default theme first; every page in
   this codebase now loads it from <head> to avoid that.

   AtlasShell (shell.js) re-exposes t()/getLang()/setLang()/getTheme()/
   setTheme() from this module — pages already using AtlasShell should call
   those, not this module directly. Pages without shell.js (login,
   reset_password, brain_globe) call AtlasI18n.* directly.
   ═══════════════════════════════════════════════════════════════════════ */
'use strict';

const AtlasI18n = (() => {
  const LS_THEME = 'atlas.theme';
  const LS_LANG = 'atlas.lang';

  function getTheme() {
    try { return localStorage.getItem(LS_THEME) || 'dark'; }
    catch (_e) { return 'dark'; }
  }
  function setTheme(theme) {
    try { localStorage.setItem(LS_THEME, theme); } catch (_e) { /* n/a */ }
    document.documentElement.dataset.theme = theme;
  }
  function getLang() {
    try { return localStorage.getItem(LS_LANG) || 'en'; }
    catch (_e) { return 'en'; }
  }
  function setLang(lang) {
    try { localStorage.setItem(LS_LANG, lang); } catch (_e) { /* n/a */ }
  }

  // Every string this codebase has externalized so far. Namespaced by
  // page/area (nav.*, shell.*, auth.*) — add a key here, then reference it
  // with t('key') from any page's own script. Not every page's strings are
  // in here yet; an
  // unknown key falls back to English, then to the key itself, so a page
  // using t() for a not-yet-translated string never renders empty.
  const STRINGS = {
    en: {
      'theme.toggle.toDark': 'Dark',
      'theme.toggle.toLight': 'Light',
      'theme.toggle.title': 'Switch to {mode} mode',
      'lang.toggle.title': 'Switch language',

      'nav.overview': 'Overview',
      'nav.questions': 'Questions',
      'nav.claims': 'Case Findings',
      'nav.iocs': 'IoCs',
      'nav.response': 'Response',
      'nav.process': 'Process',
      'nav.report': 'Report',
      'nav.casemd': 'Brief',
      'nav.timeline': 'Timeline',
      'nav.brain': 'Brain',

      'shell.case': 'Case',
      'shell.caseSelectTitle': 'Active case — applies to every view',
      'shell.caseSelectPlaceholder': '— select case —',
      'shell.newCase': '+ New case',
      'shell.chat': 'Ask Atlas',
      'shell.chatTitle': 'Ask Atlas about the active case',
      'shell.config': 'Settings',
      'shell.logout': 'Log out',
      'shell.idle': 'idle',
      'shell.offline': 'offline',
      'shell.working': 'Atlas working',
      'shell.noCase': 'no case',
      'shell.workingElsewhere': 'Atlas working \u00b7 {case}',
      'shell.workingN': 'Atlas working \u00b7 {n} cases',
      'shell.runningOne': 'Run in progress',
      'shell.runningMany': '{n} runs in progress',
      'shell.noRuns': 'No run in progress.',
      'shell.thisCase': 'this case',

      'chat.title': 'Ask Atlas',
      'chat.close': 'Close',
      'chat.noCaseSelected': 'no case selected',
      'chat.selectCaseToChat': 'select a case to ask about',
      'chat.placeholder': 'Ask about this case…  (Enter to send · Shift+Enter for newline)',
      'chat.send': 'Send',

      'auth.brand': 'Atlas',
      'auth.signInSub': 'Sign in to continue.',
      'auth.bootstrapSub': 'No accounts exist yet — create the first admin account.',
      'auth.email': 'Email',
      'auth.username': 'Username',
      'auth.password': 'Password',
      'auth.signIn': 'Sign in',
      'auth.createAdmin': 'Create admin account',
      'auth.forgotPassword': 'Forgot your password?',
      'auth.resetSub': "Enter your account email and we'll send a reset link.",
      'auth.resetSubToken': 'Choose a new password.',
      'auth.sendResetLink': 'Send reset link',
      'auth.newPassword': 'New password',
      'auth.confirmNewPassword': 'Confirm new password',
      'auth.setNewPassword': 'Set new password',
      'auth.backToSignIn': 'Back to sign in',
      'auth.passwordsDontMatch': 'passwords do not match',
      'auth.resetSent': 'If that email is registered, a reset link has been sent.',
      'auth.resetDone': 'Password updated. Redirecting to sign in…',

      'globe.search': 'Search',
      'globe.searchPlaceholder': 'Title, path, tag…',
      'globe.style': 'Style',
      'globe.layout': 'Layout',
      'globe.layoutRings': 'Rings',
      'globe.layoutForce': 'Forces',
      'globe.layoutCluster': 'Cluster',
      'globe.level': 'Level',
      'globe.levelAll': 'all',
      'globe.levelAccepted': 'accepted only',
      'globe.decisions': 'Decisions',
      'globe.decisionsAll': 'all',
      'globe.decisionsKept': 'hide rejected',
      'globe.alwaysLabels': 'Always show labels',
      'globe.resetFilters': 'Reset filters',
      'globe.close': 'Close',
      'globe.filterCluster': 'Filter to this cluster',
      'globe.playGrowth': 'Play growth',
      'globe.play': 'Play',
      'globe.pause': 'Pause',
      'globe.hint': 'zoom in to see names · click a cluster to filter',
      'globe.noData': 'No Brain Earth data ({error}). Generate it first: {cmd}',
      'globe.legendFoot': 'memory_candidate = from brain/inbox,{br}decided — not open',
      'globe.nodesOne': '{n} node',
      'globe.nodesMany': '{n} nodes',
      'globe.edgesOne': '{n} edge',
      'globe.edgesMany': '{n} edges',
      'globe.clustersOne': '{n} cluster',
      'globe.clustersMany': '{n} clusters',
      'globe.duplicatesOne': '{n} duplicate ID skipped',
      'globe.duplicatesMany': '{n} duplicate IDs skipped',
      'globe.matchesOne': '{n} match',
      'globe.matchesMany': '{n} matches',
      'globe.open': '{n} open',
      'globe.active': '{n} active',
      'globe.processed': '{n} processed',
      'globe.archived': '{n} archived',
      'globe.rejected': '{n} rejected',
      'globe.confidential': '{n} excluded as confidential',
      'globe.visible': 'visible: {n}',
      'globe.clickToFilter': 'click to filter',
      'globe.openLoop': 'open loop',
      'globe.degree': 'degree {n}',
      'globe.created': 'created {date}',
      'globe.updated': 'updated {date}',
    },
    de: {
      'theme.toggle.toDark': 'Dunkel',
      'theme.toggle.toLight': 'Hell',
      'theme.toggle.title': 'Zu {mode}modus wechseln',
      'lang.toggle.title': 'Sprache wechseln',

      'nav.overview': 'Übersicht',
      'nav.questions': 'Fragen',
      'nav.claims': 'Fallbefunde',
      'nav.iocs': 'IoCs',
      'nav.response': 'Maßnahmen',
      'nav.process': 'Ablauf',
      'nav.report': 'Bericht',
      'nav.casemd': 'Auftrag',
      'nav.timeline': 'Zeitleiste',
      'nav.brain': 'Wissen',

      'shell.case': 'Fall',
      'shell.caseSelectTitle': 'Aktiver Fall — gilt für jede Ansicht',
      'shell.caseSelectPlaceholder': '— Fall wählen —',
      'shell.newCase': '+ Neuer Fall',
      'shell.chat': 'Atlas fragen',
      'shell.chatTitle': 'Atlas zum aktiven Fall befragen',
      'shell.config': 'Einstellungen',
      'shell.logout': 'Abmelden',
      'shell.idle': 'inaktiv',
      'shell.offline': 'offline',
      'shell.working': 'Atlas arbeitet',
      'shell.noCase': 'kein Fall',
      'shell.workingElsewhere': 'Atlas arbeitet \u00b7 {case}',
      'shell.workingN': 'Atlas arbeitet \u00b7 {n} F\u00e4lle',
      'shell.runningOne': 'Laufender Durchlauf',
      'shell.runningMany': '{n} laufende Durchl\u00e4ufe',
      'shell.noRuns': 'Kein Durchlauf aktiv.',
      'shell.thisCase': 'dieser Fall',

      'chat.title': 'Atlas fragen',
      'chat.close': 'Schließen',
      'chat.noCaseSelected': 'kein Fall ausgewählt',
      'chat.selectCaseToChat': 'Fall auswählen, um Atlas zu fragen',
      'chat.placeholder': 'Frage zu diesem Fall…  (Eingabe zum Senden · Umschalt+Eingabe für neue Zeile)',
      'chat.send': 'Senden',

      'auth.brand': 'Atlas',
      'auth.signInSub': 'Bitte anmelden, um fortzufahren.',
      'auth.bootstrapSub': 'Es existieren noch keine Konten — ersten Admin-Account anlegen.',
      'auth.email': 'E-Mail',
      'auth.username': 'Benutzername',
      'auth.password': 'Passwort',
      'auth.signIn': 'Anmelden',
      'auth.createAdmin': 'Admin-Konto erstellen',
      'auth.forgotPassword': 'Passwort vergessen?',
      'auth.resetSub': 'E-Mail-Adresse eingeben — wir senden einen Link zum Zurücksetzen.',
      'auth.resetSubToken': 'Neues Passwort wählen.',
      'auth.sendResetLink': 'Link senden',
      'auth.newPassword': 'Neues Passwort',
      'auth.confirmNewPassword': 'Neues Passwort bestätigen',
      'auth.setNewPassword': 'Neues Passwort setzen',
      'auth.backToSignIn': 'Zurück zur Anmeldung',
      'auth.passwordsDontMatch': 'Passwörter stimmen nicht überein',
      'auth.resetSent': 'Falls diese E-Mail registriert ist, wurde ein Link zum Zurücksetzen gesendet.',
      'auth.resetDone': 'Passwort aktualisiert. Weiterleitung zur Anmeldung…',

      'globe.search': 'Suche',
      'globe.searchPlaceholder': 'Titel, Pfad, Tag …',
      'globe.style': 'Stil',
      'globe.layout': 'Layout',
      'globe.layoutRings': 'Ringe',
      'globe.layoutForce': 'Kräfte',
      'globe.layoutCluster': 'Cluster',
      'globe.level': 'Ebene',
      'globe.levelAll': 'alles',
      'globe.levelAccepted': 'nur Wissen',
      'globe.decisions': 'Entscheidungen',
      'globe.decisionsAll': 'alle',
      'globe.decisionsKept': 'ohne abgelehnte',
      'globe.alwaysLabels': 'Beschriftung immer',
      'globe.resetFilters': 'Filter zurücksetzen',
      'globe.close': 'Schließen',
      'globe.filterCluster': 'Auf diesen Cluster filtern',
      'globe.playGrowth': 'Wachstum abspielen',
      'globe.play': 'Play',
      'globe.pause': 'Pause',
      'globe.hint': 'hineinzoomen zeigt Namen · Klick auf einen Cluster filtert',
      'globe.noData': 'Keine Brain-Earth-Daten ({error}). Erst erzeugen: {cmd}',
      'globe.legendFoot': 'memory_candidate = aus brain/inbox,{br}beschieden — nicht offen',
      'globe.nodesOne': '{n} Knoten',
      'globe.nodesMany': '{n} Knoten',
      'globe.edgesOne': '{n} Kante',
      'globe.edgesMany': '{n} Kanten',
      'globe.clustersOne': '{n} Cluster',
      'globe.clustersMany': '{n} Cluster',
      'globe.duplicatesOne': '{n} doppelte ID übersprungen',
      'globe.duplicatesMany': '{n} doppelte IDs übersprungen',
      'globe.matchesOne': '{n} Treffer',
      'globe.matchesMany': '{n} Treffer',
      'globe.open': '{n} offen',
      'globe.active': '{n} aktiv',
      'globe.processed': '{n} verarbeitet',
      'globe.archived': '{n} archiviert',
      'globe.rejected': '{n} abgelehnt',
      'globe.confidential': '{n} vertraulich ausgeschlossen',
      'globe.visible': 'sichtbar: {n}',
      'globe.clickToFilter': 'Klick filtert',
      'globe.openLoop': 'offener Punkt',
      'globe.degree': 'Grad {n}',
      'globe.created': 'angelegt {date}',
      'globe.updated': 'geändert {date}',
    },
  };

  function t(key, vars) {
    const lang = getLang();
    const table = STRINGS[lang] || STRINGS.en;
    let s = table[key] ?? STRINGS.en[key] ?? key;
    if (vars) {
      for (const [k, v] of Object.entries(vars)) {
        // A function, so `$&` or `$$` in a value is inserted as written.
        s = s.replace(`{${k}}`, () => String(v));
      }
    }
    return s;
  }

  // Applied immediately at script-load time (this file is loaded from
  // <head>, before body renders) so there's no flash of the wrong theme.
  document.documentElement.dataset.theme = getTheme();

  return { t, getTheme, setTheme, getLang, setLang, STRINGS };
})();
