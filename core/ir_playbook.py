"""First-hour precautions from what the analyst already knows.

An investigator who writes "we think it is ransomware" under *What you
already know* has, at that moment, no finding — and a set of things that
must happen before the first tool runs. This module turns the intake prose
into those precautions, deterministically: a small table keyed by threat
class, matched on words the analyst used, in the case's report language.
Nothing here is an LLM call and nothing here is a finding. Every item is
recorded with ``source="prior_knowledge"`` and no basis, and is shown and
reported with exactly that label, because acting early is the point of
incident response and disguising suspicion as evidence would be worse than
naming it.

The class vocabulary is a seed, not a lexicon: it names behaviours, not
products, and a case that matches nothing still gets the two precautions
every incident shares — even one with no intake section at all. Intake
prose states a suspicion ("stolen passwords"), so a class word alone
names the class there. A finding names artefacts, and a password-recovery
tool, an encrypted volume or a domain controller in its wording is not an
incident: ``asserted=True`` matches only the forms in which the finding
asserts the behaviour (the class noun near an act, or a word that is the
behaviour itself). A graded
case still earns them too: unlike the pivot seeding, a precaution is not an
answer-key shortcut, so this module reads the intake regardless of grading.
"""
from __future__ import annotations

import os
import re
from typing import Any

# (phase, scope, urgency, {lang: action})
_STEP = tuple[str, str, str, dict[str, str]]

UNIVERSAL: list[_STEP] = [
    ("contain", "estate", "now", {
        "en": "Preserve volatile state and logs before any remediation: memory, event logs, shadow copies, firewall and proxy logs",
        "de": "Flüchtige Daten und Logs vor jeder Bereinigung sichern: Arbeitsspeicher, Ereignisprotokolle, Schattenkopien, Firewall- und Proxy-Logs",
    }),
    ("escalate", "estate", "soon", {
        "en": "Keep a timestamped record of every response action taken from now on",
        "de": "Ab jetzt jede Reaktionsmaßnahme mit Zeitstempel dokumentieren",
    }),
]

# What a running device seized from the person under investigation needs
# in its first hour: acquisition, not remediation. The universal steps
# apply to it too (memory before power-off; a record of every action).
SEIZURE: list[_STEP] = [
    ("contain", "host", "now", {
        "en": "Isolate the seized device from every network without powering it off, to prevent a remote wipe, and preserve its memory before power-off",
        "de": "Das sichergestellte Gerät ohne Ausschalten von allen Netzen trennen, um eine Fernlöschung zu verhindern, und den Arbeitsspeicher vor dem Ausschalten sichern",
    }),
]

# ── negation, clause-scoped ─────────────────────────────────────────────
#
# A class word inside a negated clause asserts nothing: "no ransomware was
# found" is not a ransomware case, "credentials were not dumped" is not a
# credential compromise. The scope is the clause, not the sentence: "Mimikatz
# dumped the credentials, but no lateral movement was found" still asserts
# the dump. A clause ends at a sentence end, a semicolon or colon followed
# by a space, a line break, or a contrast word; a bare comma ends nothing.
# "yet" and "though" end a clause only after a comma: "has not yet
# exfiltrated" keeps its negator.
_CLAUSE_END_RE = re.compile(
    r"[.!?](?=\s|$)|[;:](?=\s)|\n|,?\s+\b(?:but|however|although|whereas|"
    r"aber|jedoch|doch|allerdings|obwohl)\b|,\s+\b(?:yet|though)\b")
_WORD_RE = re.compile(r"[a-zäöüß]+(?:'[a-z]+)?")
_NEGATORS = frozenset({
    "no", "not", "never", "without", "none", "neither", "nor", "nothing", "nobody",
    "nowhere",
    "kein", "keine", "keinen", "keinem", "keiner", "keines", "nicht", "nie",
    "niemals", "ohne", "weder", "nichts", "niemand", "nirgends",
})
# Between a negator and the plan word it negates: "not yet planned".
_NEGATOR_BRIDGE = frozenset({"yet", "ever", "even"})
# "no indication of", "kein Hinweis auf": what follows is denied.
_SCOPE_RE = re.compile(
    r"\b(?:no (?:indication|evidence|signs?|traces?)(?: of| that)?|absence of|lack of|"
    r"rules? out|shows? no|kein(?:e|en)? (?:hinweise?|spuren?|anzeichen|belege?))\b")
# A negator reaching an absence verb covers everything between them.
_SPAN_RE = re.compile(
    r"\b(?:no|none|never|not|\w+n't|nicht|kein\w*|nie)\b(?:\s+\S+){0,6}?\s*"
    r"(?:found|present|observed|identified|detected|recorded|seen|exist(?:s|ed)?|"
    r"gefunden|vorhanden|beobachtet|festgestellt|aufgezeichnet)\b")
# A passive negation right after the match: "to Mega was not observed".
_POST_RE = re.compile(
    r"\s*(?:[\w.-]+\s+){0,2}?(?:was|were|is|are|has|have|had|could|can|did|does|wurde|"
    r"wurden|ist|sind|war|waren|konnte|konnten|hat|haben)\s+(?:\S+\s+)?"
    r"(?:not|never|nicht|nie|kein\w*)\b")


def _clause_bounds(text: str, pos: int) -> tuple[int, int]:
    lo = max([m.end() for m in _CLAUSE_END_RE.finditer(text, 0, pos)] or [0])
    nxt = _CLAUSE_END_RE.search(text, pos)
    return lo, (nxt.start() if nxt else len(text))


def _is_negator(words: list[str], i: int) -> bool:
    w = words[i]
    if w in ("not", "nicht") and i + 1 < len(words) and words[i + 1] in ("only", "nur"):
        return False
    return w in _NEGATORS or w.endswith("n't")


def negated(text: str, start: int, end: int) -> bool:
    """Whether the match at ``text[start:end]`` (lower-cased text) stands in
    a negated clause: a negator in the three words before it or inside it,
    a passive negation at most two words after it, a scope phrase before
    it, or a negator-to-absence-verb span covering it."""
    lo, hi = _clause_bounds(text, start)
    before = _WORD_RE.findall(text[lo:start])
    if any(_is_negator(before, i) for i in range(max(0, len(before) - 3), len(before))):
        return True
    inside = _WORD_RE.findall(text[start:end])
    if any(_is_negator(inside, i) for i in range(len(inside))):
        return True
    wend = start + len(re.match(r"[\w']*", text[start:]).group(0))
    wend = max(wend, end + len(re.match(r"[\w']*", text[end:]).group(0)))
    if _POST_RE.match(text[wend:hi]):
        return True
    clause = text[lo:hi]
    if any(m.start() + lo <= start for m in _SCOPE_RE.finditer(clause)):
        return True
    return any(m.start() + lo <= start < m.end() + lo for m in _SPAN_RE.finditer(clause))


# ── planned violence: a plan word beside a violence word ─────────────────
#
# English matches exact words; German matches word-initial stems, because
# its compounds and inflections ("Anschlagspläne", "geplanten") are the
# ordinary forms. A violence word directly after an IT modifier is a
# computing term (logic bomb, push bombing), not violence.
_PLAN_WORDS = frozenset(
    "plan plans planned planning intend intends intended intending prepare prepares "
    "prepared preparing manifesto manifestos threaten threatens threatened threatening".split())
_VIOLENCE_WORDS = frozenset(
    "violent violence shooting shootings shoot bombing bombings bomb bombs explosive "
    "explosives firearm firearms weapon weapons murder murders massacre massacres terror "
    "terrorist terrorists terrorism assassinate assassination assassinations".split())
_PLAN_STEMS_DE = ("plan", "pläne", "geplant", "vorbereit", "droh", "angedroht")
_NOT_PLAN_DE = ("plane", "planet")
_VIOLENCE_STEMS_DE = ("gewalt", "anschlag", "anschläg", "amok", "sprengs", "waffe",
                      "schusswaffe", "töte", "getötet", "ermord", "mord", "attentat", "bombe")
_IT_MODIFIERS = frozenset(
    "logic fork zip mail email e-mail mfa push prompt notification subscription sms "
    "decompression xml cyber".split())
_PAIR_WINDOW = 6


def _plan_word(w: str) -> bool:
    return w in _PLAN_WORDS or (w.startswith(_PLAN_STEMS_DE) and not w.startswith(_NOT_PLAN_DE))


def _violence_word(w: str, prev: str) -> bool:
    if prev in _IT_MODIFIERS:
        return False
    return w in _VIOLENCE_WORDS or w.startswith(_VIOLENCE_STEMS_DE)


def _plan_negated(toks: list[tuple[str, int, int]], i: int) -> bool:
    """A plan word negated by the word directly before it, or by a negator
    one bridge word earlier ("not yet planned")."""
    def neg(w: str) -> bool:
        return w in _NEGATORS or w.endswith("n't")
    if i > 0 and neg(toks[i - 1][0]):
        return True
    return i > 1 and toks[i - 1][0] in _NEGATOR_BRIDGE and neg(toks[i - 2][0])


def violence_spans(low: str) -> list[tuple[int, int]]:
    """Spans where the text asserts planned violence: a violence word and a
    plan word within six words of each other in one clause, neither negated
    (the plan word only by a negator directly before it), or one German
    compound carrying both."""
    toks = [(m.group(0), m.start(), m.end()) for m in _WORD_RE.finditer(low)]
    out: list[tuple[int, int]] = []
    for j, (w, a, b) in enumerate(toks):
        prev = toks[j - 1][0] if j else ""
        if not _violence_word(w, prev) or negated(low, a, b):
            continue
        if w.startswith(_VIOLENCE_STEMS_DE) and any(k in w[3:] for k in ("plan", "plän")):
            out.append((a, b))
            continue
        lo, hi = _clause_bounds(low, a)
        for i, (pw, pa, pb) in enumerate(toks):
            if abs(i - j) > _PAIR_WINDOW or not (lo <= pa < hi):
                continue
            plan = _plan_word(pw) or (pw == "threats" and i + 1 < len(toks) and toks[i + 1][0] == "to")
            if not plan:
                continue
            if _plan_negated(toks, i):
                continue
            out.append((min(pa, a), max(pb, b)))
            break
    return out


# The nouns and acts an asserted class is built from: a class noun within a
# few words of an act names the behaviour; either alone only mentions it.
_OBJECT = r"(?:files?|dateien|data|daten|volumes?|shares?|documents?|dokumente|backups?|archives?|archiv)"
_CREDENTIAL = r"(?:credential|password|passw|kennw|zugangsdaten|hash(?:es)?|ntds|lsass|\bsam\b)"
_CREDENTIAL_ACT = (r"(?:dump|spray|steal|stolen|harvest|crack|compromis|phish|leak|exfil|brute|theft|"
                   r"mimikatz|secretsdump|reuse|abuse|misuse|entwend|gestohlen|abgegriffen|ausgelesen|"
                   r"geknackt|kompromitt)")
_DOMAIN = r"(?:domain controller|\bdc\d*\b|domain admin|dom[aä]nencontroller|dom[aä]nenadmin)"
_DOMAIN_ACT = r"(?:compromis|kompromitt|access|zugriff|logon|login|anmeld|lateral|dumped|exfil|psexec)"

CLASSES: dict[str, dict[str, Any]] = {
    "ransomware": {
        "words": r"ransom|ransomware|encrypt|decrypt|\.lock|extort|erpress|verschl[uü]ssel|l[oö]segeld",
        "asserted": (r"ransom|extort|erpress|l[oö]segeld|\.lock\b"
                     + r"|" + _OBJECT + r"\W+(?:\S+\s+){0,4}(?:encrypt|verschl[uü]ssel)"
                     + r"|(?:encrypt|verschl[uü]ssel)\w*\W+(?:\S+\s+){0,4}" + _OBJECT),
        "steps": [
            ("contain", "estate", "now", {
                "en": "Isolate affected systems from the network without powering them off",
                "de": "Betroffene Systeme vom Netz trennen, ohne sie auszuschalten",
            }),
            ("escalate", "estate", "now", {
                "en": "Do not pay or contact the extortionists before legal counsel and management are involved",
                "de": "Nicht zahlen und keinen Kontakt zu den Erpressern aufnehmen, bevor Rechtsabteilung und Management einbezogen sind",
            }),
            ("recover", "estate", "soon", {
                "en": "Verify backup integrity offline before any restore",
                "de": "Backups offline auf Integrität prüfen, bevor etwas wiederhergestellt wird",
            }),
            ("escalate", "estate", "now", {
                "en": "Notify management, legal and, where personal data may be affected, the data protection officer",
                "de": "Management, Rechtsabteilung und bei möglicher Betroffenheit personenbezogener Daten den Datenschutzbeauftragten informieren",
            }),
        ],
    },
    "credential_compromise": {
        # "account(s) ... compromised" in either order, within four
        # whitespace-separated words — "compromised" alone would also match
        # a compromised host. A word is anything between blanks, so an
        # address or a DOMAIN\user name in between counts as one word.
        "words": (r"credential|password|passw|phish|stolen accounts?|leaked|\bmfa\b|zugangsdaten"
                  r"|(?:accounts?|konto|konten)\W+(?:\S+\s+){0,4}(?:compromis|kompromitt)"
                  r"|(?:compromis|kompromitt)\w*\W+(?:\S+\s+){0,4}(?:accounts?|konto|konten)"),
        "asserted": (r"phish|stolen accounts?"
                     + r"|" + _CREDENTIAL + r"\w*\W+(?:\S+\s+){0,4}" + _CREDENTIAL_ACT
                     + r"|" + _CREDENTIAL_ACT + r"\w*\W+(?:\S+\s+){0,4}" + _CREDENTIAL
                     + r"|(?:accounts?|konto|konten)\W+(?:\S+\s+){0,4}(?:compromis|kompromitt)"
                     + r"|(?:compromis|kompromitt)\w*\W+(?:\S+\s+){0,4}(?:accounts?|konto|konten)"),
        "steps": [
            ("eradicate", "estate", "now", {
                "en": "Reset the affected credentials and revoke their active sessions and tokens",
                "de": "Betroffene Zugangsdaten zurücksetzen und aktive Sitzungen und Tokens widerrufen",
            }),
            ("harden", "estate", "soon", {
                "en": "Enforce multi-factor authentication on the affected accounts and on privileged access",
                "de": "Mehrfaktor-Authentifizierung für betroffene Konten und privilegierte Zugänge erzwingen",
            }),
            ("contain", "estate", "now", {
                "en": "Review recent sign-ins of the affected accounts for unfamiliar locations, devices and times",
                "de": "Aktuelle Anmeldungen der betroffenen Konten auf fremde Orte, Geräte und Zeiten prüfen",
            }),
        ],
    },
    "exfiltration": {
        "words": r"exfil|data theft|data leak|stolen data|leak|abfluss|datendiebstahl|abgeflossen",
        "asserted": (r"exfil|data (?:theft|leak)|stolen data|datendiebstahl|datenabfluss|abgeflossen"
                     + r"|" + _OBJECT + r"\W+(?:\S+\s+){0,4}(?:leak|upload|hochgeladen|transferr|übertrag|staged)"
                     + r"|(?:leak|upload|hochgeladen|transferr|übertrag)\w*\W+(?:\S+\s+){0,4}" + _OBJECT),
        "steps": [
            ("contain", "network", "now", {
                "en": "Block the identified egress destinations at the perimeter and review outbound traffic",
                "de": "Erkannte Zielsysteme am Perimeter sperren und ausgehenden Verkehr prüfen",
            }),
            ("escalate", "estate", "now", {
                "en": "Assess legal and notification duties for the data believed to be taken",
                "de": "Rechtliche Pflichten und Meldepflichten für die mutmaßlich abgeflossenen Daten prüfen",
            }),
            ("contain", "network", "now", {
                "en": "Preserve proxy, firewall and DNS logs covering the suspected window",
                "de": "Proxy-, Firewall- und DNS-Logs für den vermuteten Zeitraum sichern",
            }),
        ],
    },
    "malware": {
        "words": r"malware|trojan|backdoor|web ?shell|beacon|\bc2\b|command and control|schadsoftware|schadcode",
        "steps": [
            ("contain", "host", "now", {
                "en": "Isolate the affected host and preserve its memory before any shutdown",
                "de": "Betroffenen Host isolieren und den Arbeitsspeicher vor jedem Herunterfahren sichern",
            }),
            ("contain", "network", "now", {
                "en": "Block the known command-and-control destinations",
                "de": "Bekannte Command-and-Control-Ziele sperren",
            }),
            ("eradicate", "host", "soon", {
                "en": "Rebuild affected systems from a known-good image rather than cleaning them in place",
                "de": "Betroffene Systeme aus einem bekannt sauberen Abbild neu aufsetzen statt sie zu bereinigen",
            }),
        ],
    },
    "domain_compromise": {
        "words": r"domain controller|\bdc\b|lateral|psexec|golden ticket|krbtgt|domain admin|dom[aä]nen",
        "asserted": (r"golden ticket|krbtgt|dcsync|ntds\.dit|psexec|lateral movement|laterale bewegung"
                     + r"|" + _DOMAIN + r"\W+(?:\S+\s+){0,4}" + _DOMAIN_ACT
                     + r"|" + _DOMAIN_ACT + r"\w*\W+(?:\S+\s+){0,4}" + _DOMAIN),
        "steps": [
            ("eradicate", "estate", "soon", {
                "en": "Plan a domain-wide credential reset including a double krbtgt reset once containment holds",
                "de": "Domänenweiten Zurücksetzen der Zugangsdaten einschließlich doppeltem krbtgt-Reset planen, sobald die Eindämmung greift",
            }),
            ("contain", "estate", "now", {
                "en": "Restrict privileged accounts to hardened administration hosts",
                "de": "Privilegierte Konten auf gehärtete Administrationssysteme beschränken",
            }),
        ],
    },
    "insider": {
        "words": r"insider|employee|former employee|contractor|mitarbeiter|innent[aä]ter",
        "asserted": (r"insider|innent[aä]ter"
                     r"|(?:former|ex-|ehemalig)\w*\s+(?:employee|contractor|mitarbeiter)"
                     r"|(?:employee|contractor|mitarbeiter|angestellte)\w*\W+(?:\S+\s+){0,5}"
                     r"(?:copied|kopiert|exfil|stole|stolen|entwendet|deleted|gelöscht|leaked|uploaded|hochgeladen|downloaded|heruntergeladen)"),
        "steps": [
            ("contain", "estate", "now", {
                "en": "Suspend the person's access and preserve their activity logs",
                "de": "Zugänge der Person sperren und ihre Aktivitätsprotokolle sichern",
            }),
            ("escalate", "estate", "now", {
                "en": "Involve HR and legal before the person is confronted",
                "de": "Personalabteilung und Rechtsabteilung einbeziehen, bevor die Person konfrontiert wird",
            }),
        ],
    },
    # Mandatory escalations: harm to people outranks every engagement rule.
    # These classes are read with negation in both the intake and a
    # finding, recorded whatever the owner and the engagement, never
    # dismissed, and ordered first. ``subject_steps`` apply in the subject
    # frame (the device of the person under investigation) in place of
    # ``steps``.
    "violence": {
        "mandatory": True,
        "match": violence_spans,
        "steps": [
            ("escalate", "estate", "now", {
                "en": "Escalate the indications of planned violence to law enforcement now",
                "de": "Die Hinweise auf geplante Gewalt jetzt an die Strafverfolgungsbehörden eskalieren",
            }),
            ("escalate", "estate", "now", {
                "en": "Identify the intended target(s) named in the material and pass them to law enforcement",
                "de": "Die im Material genannten Ziele identifizieren und an die Strafverfolgungsbehörden weitergeben",
            }),
        ],
    },
    "csam": {
        "mandatory": True,
        "words": (r"child sexual (?:abuse|exploitation) material|\bcsam\b|\bcsem\b|\bcsai\b|\biioc\b|"
                  r"indecent images? of (?:a )?child(?:ren)?|child abuse (?:images?|imagery|material)|"
                  r"child pornograph\w*|kinderpornogra\w*|jugendpornogra\w*|missbrauchsdarstellung\w*"),
        "steps": [
            ("escalate", "estate", "now", {
                "en": "Stop reviewing the material, escalate to law enforcement now and follow the legal handling rules for it (no copying, no distribution)",
                "de": "Die Sichtung des Materials einstellen, jetzt an die Strafverfolgungsbehörden eskalieren und die rechtlichen Umgangsregeln einhalten (kein Kopieren, keine Weitergabe)",
            }),
        ],
    },
    "extortion": {
        "mandatory": True,
        "words": r"sextortion|blackmail\w*|extort\w*|erpress\w*",
        "steps": [
            ("escalate", "estate", "now", {
                "en": "Decide with legal counsel now whether and when to notify law enforcement of the extortion",
                "de": "Jetzt mit der Rechtsabteilung entscheiden, ob und wann die Strafverfolgungsbehörden über die Erpressung informiert werden",
            }),
        ],
        "subject_steps": [
            ("escalate", "estate", "now", {
                "en": "Escalate the extortion to law enforcement now",
                "de": "Die Erpressung jetzt an die Strafverfolgungsbehörden eskalieren",
            }),
            ("escalate", "estate", "now", {
                "en": "Identify the person(s) being extorted and pass them to law enforcement (or counsel) for notification",
                "de": "Die erpresste(n) Person(en) identifizieren und zur Benachrichtigung an die Strafverfolgungsbehörden (oder die Rechtsabteilung) übergeben",
            }),
        ],
    },
}

# The objects a step names, by class and step index: which typed rows of
# the basis claim fill the action (the selectors live in
# core.recommendations). A step not listed is a decision row, which has
# no object by nature and is never marked "to be scoped".
STEP_OBJECTS: dict[tuple[str, int], str] = {
    ("ransomware", 0): "hosts",
    ("credential_compromise", 0): "credentials",
    ("credential_compromise", 1): "credentials",
    ("credential_compromise", 2): "credentials",
    ("exfiltration", 0): "block",
    ("exfiltration", 2): "preserve",
    ("malware", 0): "hosts",
    ("malware", 1): "block",
    ("domain_compromise", 1): "credentials",
    ("insider", 0): "subject",
    ("universal", 0): "estate_hosts",
}

MANDATORY_CLASSES = tuple(n for n, spec in CLASSES.items() if spec.get("mandatory"))
MANDATORY_RATIONALE_PREFIX = "mandatory escalation"


def _class_spans(spec: dict[str, Any], low: str, asserted: bool) -> list[tuple[int, int]]:
    """Where the text asserts the class: its matches, less the negated ones
    ("no ransomware was found" names none, in a brief as in a finding)."""
    matcher = spec.get("match")
    if matcher is not None:
        return matcher(low)
    pattern = (spec.get("asserted") or spec["words"]) if asserted else spec["words"]
    spans = [(m.start(), m.end()) for m in re.finditer(pattern, low)]
    return [sp for sp in spans if not negated(low, *sp)]


def classify(text: str, *, asserted: bool = False) -> list[str]:
    """Threat classes the text names, in table order. ``asserted`` reads
    the text as a finding: the class must be asserted, not mentioned, and
    a match in a negated clause asserts nothing. A class fires when at
    least one of its matches stands."""
    low = (text or "").lower()
    return [name for name, spec in CLASSES.items() if _class_spans(spec, low, asserted)]


def baseline_steps(text: str, language: str = "en", *,
                   asserted: bool = False, subject: bool = False) -> list[dict[str, Any]]:
    """The precautions the text warrants, in the case's language. A
    mandatory class's step carries ``mandatory: True``; with ``subject``
    (the device of the person under investigation) such a class takes its
    ``subject_steps`` where it has them."""
    lang = language if language in ("en", "de") else "en"
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for name in classify(text, asserted=asserted):
        spec = CLASSES[name]
        own_steps = not (subject and spec.get("subject_steps"))
        steps = spec["steps"] if own_steps else spec["subject_steps"]
        for i, (phase, scope, urgency, actions) in enumerate(steps):
            action = actions.get(lang) or actions["en"]
            if action in seen:
                continue
            seen.add(action)
            out.append({"class": name, "phase": phase, "scope": scope,
                        "urgency": urgency, "action": action,
                        "mandatory": bool(spec.get("mandatory")),
                        "objects": STEP_OBJECTS.get((name, i)) if own_steps else None})
    for i, (phase, scope, urgency, actions) in enumerate(UNIVERSAL):
        action = actions.get(lang) or actions["en"]
        if action not in seen:
            out.append({"class": "universal", "phase": phase, "scope": scope,
                        "urgency": urgency, "action": action,
                        "objects": STEP_OBJECTS.get(("universal", i))})
    return out


# The rationale every playbook precaution is recorded with, whichever
# path recorded it; the prefix is how such a row is told from a
# recommendation the investigation or the analyst recorded.
PRECAUTION_RATIONALE_PREFIXES = ("precaution for a suspected", "precaution every incident shares",
                                 "precaution for a seized")


def dismiss_first_hour_rows(case_dir: str | os.PathLike) -> list[str]:
    """Dismiss the open remediation rows Atlas itself derived (the intake's
    prior-knowledge precautions, the playbook rows derived from findings
    and the ATT&CK mitigations) on a case whose evidence is the device of
    the person under investigation, examined after the fact. Returns the
    ids dismissed."""
    from core.claim_graph import load_graph, set_recommendation_state
    out: list[str] = []
    for nid, n in (load_graph(case_dir).get("nodes") or {}).items():
        if not isinstance(n, dict) or n.get("kind") != "recommendation":
            continue
        if n.get("status") in ("superseded", "withdrawn") or n.get("response_state") != "open":
            continue
        rationale = str(n.get("reasoning") or "")
        # A mandatory escalation is owed whoever owns the device.
        if n.get("mandatory") or rationale.startswith(MANDATORY_RATIONALE_PREFIX):
            continue
        # The playbook's precautions and the ATT&CK mitigations derived
        # from findings are remediation for an owner; on the suspect's
        # device there is none to advise. Rows the analyst recorded stay:
        # they may be investigative steps, which the prompt asks for.
        if (n.get("source") == "prior_knowledge"
                or rationale.startswith(PRECAUTION_RATIONALE_PREFIXES)
                or (n.get("source") == "derived"
                    and rationale.startswith("MITRE ATT&CK mitigation"))):
            r = set_recommendation_state(case_dir, nid, "dismissed",
                                         actor="system owner: suspect")
            if r.get("success"):
                out.append(nid)
    return out


def seed_from_intake(case_dir: str | os.PathLike) -> dict[str, Any]:
    """Record the intake's precautions as prior_knowledge recommendations.

    Idempotent: a restatement folds into the existing node, so running at
    every start adds nothing twice. Class-specific precautions are earned by
    what the analyst wrote; the two precautions every incident shares are
    recorded regardless — an absent or empty intake section still gets
    them, and so does a graded case: ``core.case_knowledge`` withholds
    *indicator* seeding there to keep scoring honest, but a canned IR
    precaution is not an investigative shortcut, so this reads the intake
    text either way.
    """
    from core.case_config import get_report_language, get_system_owner, is_examination
    from core.case_knowledge import read
    from core.claim_graph import add_recommendation

    info = read(case_dir)
    text = info.get("text") or ""
    language = get_report_language(case_dir)
    seeded: list[str] = []
    classes = classify(text)
    suspect = get_system_owner(case_dir) == "suspect"
    # A mandatory escalation the brief warrants is recorded first, whatever
    # the owner and the engagement: harm to people is not a first-hour
    # precaution that a seized device can waive. The whole brief is read
    # for it (the case question, the metadata and scenario rows, the
    # requests), not only the prior-knowledge section.
    try:
        from core.investigation_tasks import read_case_markdown
        whole = read_case_markdown(case_dir) or ""
    except Exception:  # noqa: BLE001
        whole = text
    # A class whose material must not be handled, asserted by the brief
    # (not merely mentioned: a handling instruction asserts nothing), puts
    # the case under a handling stop before the first tool runs.
    try:
        from core.handling_stop import STOP_CLASSES, assert_stop
        for cls in classify(whole, asserted=True):
            if cls in STOP_CLASSES:
                assert_stop(case_dir, cls, "intake")
    except Exception:  # noqa: BLE001
        pass
    for step in baseline_steps(whole, language, subject=suspect):
        if not step.get("mandatory"):
            continue
        r = add_recommendation(
            case_dir, action=step["action"], phase=step["phase"],
            scope=step["scope"], urgency=step["urgency"],
            source="prior_knowledge", mandatory=True,
            rationale=f"{MANDATORY_RATIONALE_PREFIX}: {step['class']}, from the case intake",
        )
        if r.get("success") and not r.get("duplicate"):
            seeded.append(r["node_id"])
    # The device of the person under investigation, examined after the
    # fact, can take no first-hour step: the precautions would be recorded
    # for an owner who is not advised. Ones recorded before the brief said
    # so (the graph outlives a run) are dismissed, so the report and the
    # Response tab stop showing them. A victim's system keeps every step:
    # its owner's live estate and logs are what the precautions protect.
    if suspect and is_examination(case_dir):
        return {"present": bool(info.get("present")), "classes": classes,
                "seeded": seeded, "dismissed": dismiss_first_hour_rows(case_dir),
                "skipped": "suspect's device examined after the fact: "
                "no first-hour precautions"}
    try:
        from core.indicators import frame_for
        frame = frame_for(case_dir)
    except Exception:  # noqa: BLE001
        frame = "incident"
    if suspect:
        # Seized running: acquisition steps only, no class precaution. The
        # seizure step applies to a device that arrived live (a live
        # evidence entry), never to an image.
        steps = ([{"class": "seizure", "phase": phase, "scope": scope,
                   "urgency": urgency, "action": actions.get(language) or actions["en"]}
                  for phase, scope, urgency, actions in SEIZURE] if _arrived_live(case_dir) else [])
        steps += [st for st in baseline_steps("", language) if st["class"] == "universal"]
    else:
        steps = [st for st in baseline_steps(text, language) if not st.get("mandatory")]
    hosts = _system_hosts(case_dir) if any(st.get("objects") == "estate_hosts" for st in steps) else []
    for step in steps:
        objects: list[str] = []
        if step.get("objects") == "estate_hosts":
            # The owner's systems are still running only in the incident
            # frame; there the precaution names them.
            if frame != "incident":
                continue
            objects = hosts
        if step["class"] == "seizure":
            rationale = "precaution for a seized running device"
        elif step["class"] != "universal":
            rationale = (f"precaution for a suspected {step['class'].replace('_', ' ')} "
                         "incident, from the case intake")
        elif text:
            rationale = "precaution every incident shares, from the case intake"
        else:
            rationale = "precaution every incident shares"
        from core.recommendations import action_text
        # The estate's systems are recomputed at every start: the row's
        # objects follow what the case knows now (a baseline that arrived
        # later replaces the stand-in claim hosts).
        r = add_recommendation(
            case_dir, action=action_text(step["action"], objects, language), phase=step["phase"],
            scope=step["scope"], urgency=step["urgency"],
            source="prior_knowledge", rationale=rationale,
            indicators=objects, fingerprint_action=step["action"],
            replace_objects=step.get("objects") == "estate_hosts", language=language,
        )
        if r.get("success") and not r.get("duplicate"):
            seeded.append(r["node_id"])
    return {"present": bool(info.get("present")), "classes": classes,
            "seeded": seeded, "skipped": ""}


def _system_hosts(case_dir: str | os.PathLike) -> list[str]:
    """The estate's systems, which are what volatile state and logs live
    on: the baseline's installations and the hosts with memory or live
    evidence. Only when the case has neither do the claim hosts stand in,
    and then only those that match a disk evidence entry; a removable
    medium the findings name under its label is no system."""
    values: dict[str, Any] = {}
    try:
        from core.own_assets import own_assets
        values = own_assets(case_dir).get("values") or {}
    except Exception:  # noqa: BLE001
        pass
    entries: list[dict[str, Any]] = []
    try:
        from core.evidence_links import load_evidence_links
        entries = [e for e in (load_evidence_links(case_dir).get("entries") or []) if isinstance(e, dict)]
    except Exception:  # noqa: BLE001
        pass

    def labels(kinds: tuple[str, ...]) -> list[str]:
        out = []
        for e in entries:
            if str(e.get("kind") or "") in kinds:
                for label in (str(e.get("label") or "").strip(), str(e.get("host") or "").strip()):
                    if label and re.search(r"[A-Za-z]", label) and len(label) <= 64:
                        out.append(label)
        return out

    hosts = [e["value"] for e in values.values() if e.get("type") == "host" and "baseline" in (e.get("sources") or [])]
    hosts += labels(("memory", "live"))
    if not hosts:
        disks = {label.casefold() for label in labels(("disk",))}
        hosts = [e["value"] for e in values.values()
                 if e.get("type") == "host" and "claim_hosts" in (e.get("sources") or [])
                 and e["value"].casefold() in disks]
    seen: set[str] = set()
    return [h for h in hosts if not (h.casefold() in seen or seen.add(h.casefold()))]


def _arrived_live(case_dir: str | os.PathLike) -> bool:
    """Whether the evidence links carry a live entry: the device was
    seized running, not imaged."""
    try:
        from core.evidence_links import load_evidence_links
        return any(str(e.get("kind") or "") == "live"
                   for e in (load_evidence_links(case_dir).get("entries") or []) if isinstance(e, dict))
    except Exception:  # noqa: BLE001
        return False
