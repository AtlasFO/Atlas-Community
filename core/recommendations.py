"""The response plan — what the case tells the responder to do, in order.

Same stance as the IOC catalog: a projection over recorded beliefs, computed
on request, never authored separately. A recommendation is a node in the
claim graph (``core.claim_graph.add_recommendation``) that names the claims
or conclusions it rests on, so this module never invents advice — it orders
and groups what the run recorded and says, for every line, what it stands
on. A precaution taken on prior knowledge alone is shown as exactly that.

Ordering is one rule, used by the Overview, the Response tab and the
report alike: what is still open first; among those the mandatory
escalations (harm to people); then urgency; then how strong the basis is;
then how far the scope reaches; then the newest.
"""
from __future__ import annotations

import datetime as _dt
import os
from typing import Any

from core.claim_graph import (RECOMMENDATION_PHASES, RECOMMENDATION_SCOPES, action_text,  # noqa: F401
                              RECOMMENDATION_URGENCIES, load_graph)

SCHEMA_VERSION = "1.0"
PRIOR = "PRIOR"   # the basis label of a prior_knowledge precaution

_BASIS_RANK = {"CONFIRMED": 4, "LIKELY": 3, "SUSPECTED": 2, "UNCONFIRMED": 1, PRIOR: 0}
_STATE_RANK = {"open": 0, "done": 1, "dismissed": 2}
_URGENCY_RANK = {u: i for i, u in enumerate(RECOMMENDATION_URGENCIES)}
_SCOPE_RANK = {"estate": 0, "network": 1, "host": 2}
# The lifecycle order of the phases, by frame: an intrusion is contained
# first and examined next; an examination of a person's conduct is
# examined first and its decisions handed on next.
_PHASE_ORDER = {
    "incident": ("contain", "investigate", "eradicate", "recover", "harden", "escalate"),
    "subject": ("investigate", "escalate", "contain", "eradicate", "recover", "harden"),
    # A device examined after the fact has no first hour to act in: the
    # follow-ups its findings open come first, lessons for the owner last,
    # whatever the frame.
    "examination": ("investigate", "escalate", "recover", "harden", "eradicate", "contain"),
}
_PHASE_RANK = {f: {p: i for i, p in enumerate(order)} for f, order in _PHASE_ORDER.items()}


def _order_name(frame: str | None, engagement: str | None) -> str:
    if engagement == "examination":
        return "examination"
    return frame if frame in _PHASE_ORDER else "incident"


def _utcnow() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")


def order_key(row: dict[str, Any], frame: str = "incident", engagement: str = "") -> tuple:
    head = (
        _STATE_RANK.get(row.get("state"), 9),
        0 if row.get("mandatory") else 1,
        _URGENCY_RANK.get(row.get("urgency"), 9),
    )
    strength = (
        -_BASIS_RANK.get(str(row.get("basis_confidence") or ""), 0),
        _SCOPE_RANK.get(row.get("scope"), 9),
    )
    phase = _PHASE_RANK[_order_name(frame, engagement)].get(row.get("phase"), 9)
    # newest first among equals; ISO timestamps sort as text
    newest = "".join(chr(0x10FFFF - ord(c)) for c in str(row.get("created_at") or ""))
    # On an examination the phase outranks the basis: a follow-up resting
    # on a LIKELY finding comes before a lesson resting on a CONFIRMED one.
    if engagement == "examination":
        return (*head, phase, *strength, newest)
    return (*head, *strength, phase, newest)


def _row(nid: str, node: dict[str, Any], nodes: dict[str, Any]) -> dict[str, Any]:
    from core.claim_graph import is_current_belief
    basis = []
    for bid in node.get("basis_ids") or []:
        b = nodes.get(bid)
        if not isinstance(b, dict):
            continue
        basis.append({
            "id": bid,
            "finding_id": b.get("finding_id") or "",
            "statement": str(b.get("statement") or "")[:400],
            "confidence": str(b.get("confidence") or "").upper(),
            "host": b.get("host") or "",
            "status": b.get("status") or "",
            "current": is_current_belief(b),
            "reason": str(b.get("withdraw_reason") or b.get("supersede_reason") or "")[:300],
        })
    source = str(node.get("source") or "recorded")
    # Only what the run still asserts carries a step's tier; a basis that was
    # withdrawn stays listed for audit.
    current = [b for b in basis if b["current"]]
    if source == "prior_knowledge" or not basis:
        basis_confidence = PRIOR if source == "prior_knowledge" else "UNCONFIRMED"
    elif not current:
        basis_confidence = "UNCONFIRMED"
    else:
        basis_confidence = max((b["confidence"] for b in current),
                               key=lambda c: _BASIS_RANK.get(c, 0))
    return {
        "id": nid,
        "action": str(node.get("statement") or ""),
        "phase": node.get("phase") or "",
        "urgency": node.get("urgency") or "",
        "scope": node.get("response_scope") or ("estate" if node.get("scope") == "estate" else "host"),
        "source": source,
        "state": node.get("response_state") or "open",
        "state_changed_at": node.get("state_changed_at"),
        "state_changed_by": node.get("state_changed_by") or "",
        "state_note": str(node.get("state_note") or ""),
        "rationale": str(node.get("reasoning") or ""),
        "hosts": list(node.get("hosts") or ([node["host"]] if node.get("host") else [])),
        "indicators": list(node.get("indicators") or []),
        "mandatory": bool(node.get("mandatory")),
        "objects": list(node.get("indicators") or []),
        "basis": basis,
        "basis_confidence": basis_confidence,
        # Every basis withdrawn or superseded without a successor: the step
        # is held back for review, never in "Do now".
        "basis_lost": source in ("recorded", "derived") and bool(basis) and not current,
        "belief_status": node.get("status") or "",
        "created_at": node.get("created_at") or "",
        "updated_at": node.get("updated_at") or "",
    }


def build_catalog(case_dir: str | os.PathLike) -> dict[str, Any]:
    """Every current recommendation, ordered, with what it rests on."""
    try:
        graph = load_graph(case_dir)
    except Exception:  # noqa: BLE001 — a missing graph is an empty plan
        graph = {}
    nodes = graph.get("nodes") or {}
    rows = [
        _row(nid, n, nodes) for nid, n in nodes.items()
        if isinstance(n, dict) and n.get("kind") == "recommendation"
        and n.get("status") not in ("superseded", "withdrawn")
    ]
    try:
        from core.indicators import frame_for
        frame = frame_for(case_dir)
    except Exception:  # noqa: BLE001
        frame = "incident"
    try:
        from core.case_config import get_engagement, get_system_owner
        engagement = get_engagement(case_dir)
        system_owner = get_system_owner(case_dir)
    except Exception:  # noqa: BLE001 - an unreadable brief is an incident
        engagement = "incident-response"
        system_owner = "unknown"
    rows.sort(key=lambda r: order_key(r, frame, engagement))
    by_urgency = {u: 0 for u in RECOMMENDATION_URGENCIES}
    by_source: dict[str, int] = {}
    by_state = {"open": 0, "done": 0, "dismissed": 0}
    for r in rows:
        by_state[r["state"]] = by_state.get(r["state"], 0) + 1
        if r["state"] == "open":
            by_urgency[r["urgency"]] = by_urgency.get(r["urgency"], 0) + 1
        by_source[r["source"]] = by_source.get(r["source"], 0) + 1
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": _utcnow(),
        "case_id": graph.get("case_id") or "",
        "engagement": engagement,
        "system_owner": system_owner,
        "frame": frame,
        "total": len(rows),
        "open": by_state["open"],
        "done": by_state["done"],
        "dismissed": by_state["dismissed"],
        "open_now": by_urgency.get("now", 0),
        "by_urgency": by_urgency,
        "by_source": by_source,
        "evidence_backed": sum(1 for r in rows if r["basis_confidence"] != PRIOR),
        "recommendations": rows,
    }


def do_now(catalog: dict[str, Any]) -> list[dict[str, Any]]:
    """What is open and urgent — the Overview's first question."""
    return [r for r in catalog.get("recommendations") or []
            if r.get("state") == "open" and r.get("urgency") == "now" and not r.get("basis_lost")]


def grouped(catalog: dict[str, Any]) -> list[tuple[str, list[dict[str, Any]]]]:
    """Rows by phase in the lifecycle order of the frame (of the
    engagement, on an examination), empty phases left out."""
    order = _PHASE_ORDER[_order_name(catalog.get("frame"), catalog.get("engagement"))]
    buckets: dict[str, list[dict[str, Any]]] = {p: [] for p in order}
    for r in catalog.get("recommendations") or []:
        buckets.setdefault(r.get("phase") or "", []).append(r)
    return [(p, buckets[p]) for p in order if buckets.get(p)]


def render_markdown(catalog: dict[str, Any], language: str = "en", *,
                    host: str = "", report_scope: str = "case") -> list[str]:
    """The report's Recommendations section as lines — a projection, not
    prose. A host report shows what applies to that host and points at the
    estate report for the rest; every line names its basis and its source.
    """
    from core.report_i18n import t
    rows = list(catalog.get("recommendations") or [])
    lines: list[str] = []
    if report_scope == "host" and host:
        h = host.strip().lower()
        rows = [r for r in rows
                if r.get("scope") == "host"
                and (not r.get("hosts") or h in (x.lower() for x in r["hosts"]))]
    rows = [r for r in rows if r.get("state") != "dismissed"]
    owner = catalog.get("system_owner") or "unknown"
    if owner == "suspect":
        # Why the section holds no remediation: the device belongs to the
        # person under investigation.
        lines.append(f"*{t('response_suspect_note', language)}*")
        lines.append("")
    else:
        if catalog.get("engagement") == "examination":
            # Examined after the fact, the owner's duties remain: the note
            # says each step applies to systems still in service.
            lines.append(f"*{t('response_examination_note', language)}*")
            lines.append("")
        if owner == "unknown":
            lines.append(f"*{t('response_owner_assumption', language)}*")
            lines.append("")
    if not rows:
        lines.append(t("response_none", language))
        lines.append("")
        if report_scope == "host":
            lines.append(t("response_see_estate", language))
            lines.append("")
        return lines

    def line(r: dict[str, Any]) -> str:
        basis = ", ".join(
            f"{b.get('finding_id') or b['id']} [{b.get('confidence') or '?'}]"
            for b in r.get("basis") or [])
        src = t(f"response_source_{r.get('source')}", language)
        parts = [f"**{r['action']}**",
                 f"({t('response_scope_' + r['scope'], language)}, "
                 f"{t('response_urgency_' + r['urgency'], language)})"]
        if r.get("state") == "done":
            parts.append(f"— {t('response_state_done', language)}"
                         + (f": {r['state_note'][:200]}" if r.get("state_note") else ""))
        tail = f" — {src}" + (f": {basis}" if basis else "")
        out = "- " + " ".join(parts) + tail
        if r.get("rationale"):
            out += f"\n  - {r['rationale'][:400]}"
        return out

    lost = [r for r in rows if r.get("basis_lost") and r.get("state") == "open"]
    rows = [r for r in rows if r not in lost]
    now = [r for r in rows if r.get("state") == "open" and r.get("urgency") == "now"]
    if now:
        lines.append(f"### {t('response_do_now', language)}")
        lines.append("")
        lines.extend(line(r) for r in now)
        lines.append("")
    for phase, prow in grouped({"recommendations": rows, "frame": catalog.get("frame"),
                                "engagement": catalog.get("engagement")}):
        prow = [r for r in prow if r not in now]
        if not prow:
            continue
        lines.append(f"### {t('response_phase_' + phase, language)}")
        lines.append("")
        lines.extend(line(r) for r in prow)
        lines.append("")
    if lost:
        lines.append(f"### {t('response_basis_lost', language)}")
        lines.append("")
        for r in lost:
            why = "; ".join(f"{b.get('finding_id') or b['id']} {b.get('status')}"
                            + (f": {b['reason']}" if b.get("reason") else "")
                            for b in r.get("basis") or [])
            lines.append(line(r) + (f"\n  - {why}" if why else ""))
        lines.append("")
    if any(r.get("source") == "prior_knowledge" for r in rows):
        lines.append(f"*{t('response_prior_note', language)}*")
        lines.append("")
    if report_scope == "host":
        lines.append(t("response_see_estate", language))
        lines.append("")
    return lines


def report_readiness_advisories(case_dir: str | os.PathLike | None,
                                substantiated_hosts: list[str],
                                substantiated_findings: int) -> list[str]:
    """What the pre-report check says about the plan — advisory only.

    A case with substantiated findings and no recorded recommendation will
    report a plan built from nothing; findings on several hosts with only
    host-scoped measures will report a plan that stops at the host.
    """
    if not substantiated_findings:
        return []
    try:
        catalog = build_catalog(case_dir) if case_dir else {"recommendations": []}
    except Exception:  # noqa: BLE001
        return []
    # The device of the person under investigation has no owner to advise;
    # a report with no recommendation is complete there.
    if catalog.get("system_owner") == "suspect":
        return []
    open_rows = [r for r in catalog.get("recommendations") or [] if r.get("state") == "open"]
    evidence_backed = [r for r in open_rows if r.get("source") != "prior_knowledge"]
    if not evidence_backed:
        return [
            f"{substantiated_findings} substantiated finding(s) and no recommendation "
            "rests on any of them. Record what the responder must do about each "
            "with claim.record_recommendation (action, phase, scope, urgency, "
            "basis_ids = the claim ids); the report's Recommendations section is "
            "a projection of these and is otherwise empty."
        ]
    if len(substantiated_hosts) >= 2 and not any(
            r.get("scope") in ("estate", "network") for r in evidence_backed):
        return [
            f"Findings span {len(substantiated_hosts)} hosts but every recorded "
            "recommendation is host-scoped. Record the estate-level decisions the "
            "IR team faces (containment, credential hygiene, backup verification, "
            "escalation) with scope=estate, citing beliefs on more than one host."
        ]
    return []


# ── derived from ATT&CK mitigations ──────────────────────────────────────────
#
# A finding that names a technique names, through MITRE's own mitigation
# relationships, what counters it. The mapping below only decides which IR
# phase a mitigation belongs to and how urgent it is; the mitigation itself,
# its name and its wording are MITRE's (share/.common/mitre_mitigations.json).

import re as _re

_TID_RE = _re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_MITIGATION_PHASES: list[tuple[str, str, str, str, str]] = [
    # (name pattern, phase, urgency, scope override or "", object selector or "")
    (r"backup", "recover", "soon", "", ""),
    (r"segmentation|isolat|filter network|network intrusion|traffic|proxy|sandbox", "contain", "now", "network", "hosts"),
    (r"multi-factor|password|credential|privileged account|user account management|account use", "eradicate", "now", "", "credentials"),
    (r"update|patch|vulnerab|exploit protection|disable|restrict|limit|permission|code signing|"
     r"execution prevention|application isolation|antivirus|behavior prevention|boot|encrypt|"
     r"software configuration|operating system configuration|ssl|audit|active directory", "harden", "soon", "", "hosts"),
    (r"training|awareness|threat intelligence", "harden", "later", "", ""),
]
_SKIP_MITIGATIONS = frozenset({"M1055", "M1056"})   # "Do Not Mitigate", "Pre-compromise"
MAX_DERIVED_PER_CLAIM = 3


def _phase_for(name: str) -> tuple[str, str, str, str]:
    low = (name or "").lower()
    for pattern, phase, urgency, scope, selector in _MITIGATION_PHASES:
        if _re.search(pattern, low):
            return phase, urgency, scope, selector
    return "harden", "later", "", ""


# ── objects: what a step names, from the basis claim's typed rows ────────
#
# A step's objects come only from the typed rows the presence check
# verified at record time, never from prose. Block and hunt objects never
# include an own asset; only contain and preserve steps name victim hosts.
_SELECTORS: dict[str, dict[str, Any]] = {
    "block": {"uses": ("block",)},
    "hunt": {"uses": ("hunt",)},
    "hosts": {"types": ("host",), "sides": ("victim",), "claim_host": True},
    "credentials": {"types": ("account",), "sides": ("victim", "attacker")},
    "subject": {"types": ("account", "email", "host"), "sides": ("subject",)},
    "persistence": {"types": ("registry", "service", "task", "path", "file"), "sides": ("attacker",)},
    "preserve": {"claim_host": True},
}
_SELECTOR_NOUNS = {
    "block": "addresses, domains, URLs or mail addresses on the attacker side",
    "hunt": "hashes, files or paths on the attacker side",
    "hosts": "victim hosts",
    "credentials": "accounts",
    "subject": "subject accounts, mailboxes or hosts",
    "persistence": "registry keys, services, tasks or paths on the attacker side",
    "preserve": "host",
}
_HARDEN_NOUNS = {"hosts": {"en": "systems", "de": "Systeme"}, "credentials": {"en": "accounts", "de": "Konten"}}
MAX_NEXT_STEPS = 10

_T = {
    "harden": {"en": "Harden the {noun} the finding names against {tid}",
               "de": "Die im Befund genannten {noun} gegen {tid} härten"},
    "preserve": {"en": "Have law enforcement or counsel request preservation from {provider}",
                 "de": "Strafverfolgungsbehörden oder Rechtsabteilung eine Beweissicherung {bei} {provider} anfordern lassen"},
    "legal_hold": {"en": "Place the owner's own mailboxes and accounts under legal hold",
                   "de": "Die eigenen Postfächer und Konten unter Legal Hold stellen"},
    "victim": {"en": "Identify the person(s) behind these identifiers and pass them to law enforcement (or counsel) for notification",
               "de": "Die Personen hinter diesen Kennungen identifizieren und zur Benachrichtigung an die Strafverfolgungsbehörden (oder die Rechtsabteilung) übergeben"},
    "open_parts": {"en": "Answer the open parts of the request '{request}'",
                   "de": "Die offenen Teile der Anfrage '{request}' beantworten"},
    "examine": {"en": "Examine {unit}", "de": "{unit} auswerten"},
    "mail_provider": {"en": "the mail provider of {domain} (identify it from its MX records)",
                      "de": "Mailanbieter von {domain} (über die MX-Einträge ermitteln)"},
    "provider_of": {"en": "the provider of {value}", "de": "Anbieter von {value}"},
    "hardening_refs": {"en": "Hardening references (ATT&CK mitigations, for lookup)",
                       "de": "Härtungsreferenzen (ATT&CK-Mitigationen, zum Nachschlagen)"},
}


def _tx(key: str, language: str, **kw: Any) -> str:
    lang = language if language in ("en", "de") else "en"
    return _T[key][lang].format(**kw)


def _frame_and_assets(case_dir: str | os.PathLike) -> tuple[str, dict[str, Any] | None]:
    try:
        from core.indicators import frame_for
        frame = frame_for(case_dir)
    except Exception:  # noqa: BLE001
        frame = "incident"
    try:
        from core.own_assets import own_assets
        assets = own_assets(case_dir)
    except Exception:  # noqa: BLE001
        assets = None
    return frame, assets


def _is_own(assets: dict[str, Any] | None, value: str, kind: str) -> bool:
    if not assets:
        return False
    try:
        from core.own_assets import lookup
        return lookup(assets, value, kind) is not None
    except Exception:  # noqa: BLE001
        return False


def objects_for(selector: str | None, claim: dict[str, Any], *, frame: str,
                assets: dict[str, Any] | None = None, claim_host: bool = True) -> list[str]:
    """The objects a selector finds on the claim: typed rows by use (the
    use table of the frame) or by type and side, and, for a step that acts
    on the claim's host (contain, preserve), that host; a hardening row
    takes typed rows only."""
    spec = _SELECTORS.get(selector or "")
    if not spec:
        return []
    from core.indicators import rows_of, use_for
    out: list[str] = []
    if claim_host and spec.get("claim_host") and claim.get("host"):
        out.append(str(claim["host"]))
    for row in rows_of(claim):
        kind, side, value = str(row.get("type") or ""), str(row.get("side") or ""), str(row.get("value") or "")
        if not value:
            continue
        if "uses" in spec:
            if not set(use_for(frame, side, kind, value)) & set(spec["uses"]):
                continue
            if _is_own(assets, value, kind):
                continue
        elif kind not in spec.get("types", ()) or side not in spec.get("sides", ()):
            continue
        if value not in out:
            out.append(value)
    return out


def techniques_in(text: str) -> list[str]:
    return sorted(set(_TID_RE.findall(text or "")))


def derive_from_claim(case_dir: str | os.PathLike, claim_id: str, *,
                      mitigations_path: str | None = None) -> dict[str, Any]:
    """Record the ATT&CK mitigations for the techniques a claim names.

    No model turn: the claim's technique ids meet MITRE's mitigation table,
    each mitigation becomes a recommendation resting on that claim, at most
    a few per claim (most widely applicable first), folded against what is
    already recorded. Wording stays MITRE's, in English, whatever the case
    language — a mitigation is a reference, not prose.
    """
    from core.claim_graph import add_recommendation, get_node
    try:
        from tools.mitre import mitigations_for
    except Exception:  # noqa: BLE001 — no table, no derivation
        return {"claim_id": claim_id, "techniques": [], "recorded": [], "folded": []}
    graph = load_graph(case_dir)
    claim = get_node(graph, claim_id)
    if not claim or claim.get("kind") not in ("claim", "conclusion"):
        return {"claim_id": claim_id, "techniques": [], "recorded": [], "folded": [],
                "error": "not a claim"}
    tids = techniques_in(" ".join(str(claim.get(k) or "") for k in ("statement", "reasoning")))
    if not tids:
        return {"claim_id": claim_id, "techniques": [], "recorded": [], "folded": []}
    # The device of the person under investigation has no owner to advise:
    # no mitigation is recorded for it. On a victim's system examined
    # after the fact a mitigation is a lesson for the owner, never an
    # immediate step: there is no first hour to act in.
    from core.case_config import get_report_language, is_suspect_device
    if is_suspect_device(case_dir):
        return {"claim_id": claim_id, "techniques": tids, "recorded": [], "folded": [],
                "skipped": "suspect's device: no remediation to its owner"}
    frame, assets = _frame_and_assets(case_dir)
    if frame != "incident":
        return {"claim_id": claim_id, "techniques": tids, "recorded": [], "folded": [],
                "skipped": "subject frame: no hardening row"}
    language = get_report_language(case_dir)
    recorded, folded = [], []
    # One row per technique, and only with objects the finding names: the
    # mitigation's own text is the rationale. A mitigation with nothing to
    # act on is a reference, listed once in the report's hardening
    # paragraph (hardening_references), never a row.
    for tid in tids:
        for mit in mitigations_for([tid], mitigations_path):
            if mit["id"] in _SKIP_MITIGATIONS:
                continue
            _phase, _urgency, _scope, selector = _phase_for(mit["name"])
            objects = objects_for(selector, claim, frame=frame, assets=assets, claim_host=False) if selector else []
            if not objects:
                continue
            noun = _HARDEN_NOUNS[selector][language if language in ("en", "de") else "en"]
            verb = _tx("harden", language, noun=noun, tid=tid)
            summary = (mit.get("description") or "").split(". ")[0].strip().rstrip(".")
            r = add_recommendation(
                case_dir, action=(action_text(verb, objects, language) + f" ({mit['id']} {mit['name']})")[:300],
                phase="harden", scope="estate" if claim.get("scope") == "estate" else "host",
                urgency="later", basis_ids=[claim_id], source="derived",
                rationale=((summary + ". ") if summary else "") + (
                    f"MITRE ATT&CK mitigation {mit['id']} for {tid}, established by {claim_id}"),
                hosts=[claim["host"]] if claim.get("host") else None,
                indicators=objects, fingerprint_action=verb,
            )
            if r.get("success"):
                (folded if r.get("duplicate") else recorded).append(r["node_id"])
            break
    return {"claim_id": claim_id, "techniques": tids, "recorded": recorded, "folded": folded}


def hardening_references(case_dir: str | os.PathLike, language: str = "en") -> list[str]:
    """The report's hardening paragraph: every technique the current
    beliefs name, once, with its mitigation ids and names, as references
    to look up. Empty outside the incident frame."""
    try:
        from tools.mitre import mitigations_for
    except Exception:  # noqa: BLE001
        return []
    try:
        from core.indicators import frame_for
        if frame_for(case_dir) != "incident":
            return []
        graph = load_graph(case_dir)
    except Exception:  # noqa: BLE001
        return []
    tids: set[str] = set()
    for n in (graph.get("nodes") or {}).values():
        if isinstance(n, dict) and n.get("kind") in ("claim", "conclusion") \
                and n.get("status") not in ("superseded", "withdrawn"):
            tids |= set(techniques_in(" ".join(str(n.get(k) or "") for k in ("statement", "reasoning"))))
    if not tids:
        return []
    items = []
    for tid in sorted(tids):
        mits = [m for m in mitigations_for([tid]) if m["id"] not in _SKIP_MITIGATIONS]
        if mits:
            items.append(f"{tid}: " + ", ".join(f"{m['id']} {m['name']}" for m in mits[:6]))
    if not items:
        return []
    return [f"*{_tx('hardening_refs', language)}:* " + "; ".join(items) + ".", ""]


def derive_from_finding_text(case_dir: str | os.PathLike, claim_id: str, statement: str,
                             *, host: str = "", language: str = "en") -> dict[str, Any]:
    """Record the canned first-hour precautions a finding's own wording
    warrants — the same table ``core.ir_playbook`` uses for the case
    intake, now matched against what Atlas actually found.

    No model turn: the finding's words meet the threat-class vocabulary in
    its asserted forms (a password-recovery tool in a listing is not a
    credential compromise; dumped credentials are), each matching class's
    steps becomes a recommendation resting on that claim, folded against
    what is already recorded. An intake-table step
    scoped to the whole estate is recorded at host scope here unless the
    claim itself already reaches the estate — a single finding cannot earn
    a wider scope on its own. The universal precautions are not re-derived
    per finding; they are seeded once, from the intake.
    """
    from core.case_config import is_suspect_device
    from core.claim_graph import add_recommendation, get_node
    from core.ir_playbook import MANDATORY_RATIONALE_PREFIX, baseline_steps, classify

    classes = classify(statement or "", asserted=True)
    if not classes:
        return {"claim_id": claim_id, "classes": [], "recorded": [], "folded": []}
    graph = load_graph(case_dir)
    claim = get_node(graph, claim_id)
    if not claim or claim.get("kind") not in ("claim", "conclusion"):
        return {"claim_id": claim_id, "classes": [], "recorded": [], "folded": [],
                "error": "not a claim"}
    suspect = is_suspect_device(case_dir)
    # A finding that asserts a class whose material must not be handled
    # puts the case under a handling stop (the affected device is the
    # finding's host in the incident frame).
    try:
        from core.handling_stop import STOP_CLASSES, assert_stop
        for cls in classes:
            if cls in STOP_CLASSES:
                assert_stop(case_dir, cls, claim_id, device=str(host or claim.get("host") or ""))
    except Exception:  # noqa: BLE001
        pass
    hosts = [host] if host else ([claim["host"]] if claim.get("host") else None)
    estate = claim.get("scope") == "estate"
    steps = [s for s in baseline_steps(statement or "", language, asserted=True, subject=suspect)
             if s["class"] != "universal"]
    recorded, folded = [], []
    # A mandatory escalation rests on the finding whatever the owner: it
    # is recorded before the owner rule below, at the claim's own scope,
    # and is never dismissed.
    for step in [s for s in steps if s.get("mandatory")]:
        r = add_recommendation(
            case_dir, action=step["action"], phase=step["phase"],
            scope=step["scope"] if (step["scope"] != "estate" or estate) else "host",
            urgency=step["urgency"],
            basis_ids=[claim_id], source="derived", mandatory=True,
            rationale=f"{MANDATORY_RATIONALE_PREFIX}: {step['class']}, indicated by {claim_id}",
            hosts=hosts,
        )
        if r.get("success"):
            (folded if r.get("duplicate") else recorded).append(r["node_id"])
    # The device of the person under investigation has no owner to advise:
    # the steps the finding's wording warrants are not recorded. A victim's
    # system keeps them whether the evidence is live or examined after the
    # fact, because the owner's duties do not expire with the image.
    if suspect:
        return {"claim_id": claim_id, "classes": classes, "recorded": recorded, "folded": folded,
                "skipped": "suspect's device: no remediation to its owner"}
    class_steps = [s for s in steps if not s.get("mandatory")]
    frame, assets = _frame_and_assets(case_dir)
    for step in class_steps[:MAX_DERIVED_PER_CLAIM]:
        scope = step["scope"] if (step["scope"] != "estate" or estate) else "host"
        selector = step.get("objects")
        objects = objects_for(selector, claim, frame=frame, assets=assets) if selector else []
        urgency = step["urgency"]
        rationale = (f"precaution for a suspected {step['class'].replace('_', ' ')} "
                     f"incident, indicated by {claim_id}")
        if selector and not objects:
            # A step with nothing to act on is not "do now": it waits to be
            # scoped, and is extended in place once the finding gains rows.
            urgency = "soon" if urgency == "now" else urgency
            rationale += f"; to be scoped: the finding names no typed {_SELECTOR_NOUNS[selector]}"
        r = add_recommendation(
            case_dir, action=action_text(step["action"], objects, language), phase=step["phase"],
            scope=scope, urgency=urgency,
            basis_ids=[claim_id], source="derived", rationale=rationale,
            hosts=hosts, indicators=objects, fingerprint_action=step["action"],
        )
        if not r.get("success"):
            continue
        (folded if r.get("duplicate") else recorded).append(r["node_id"])
    return {"claim_id": claim_id, "classes": classes, "recorded": recorded, "folded": folded}


# ── rows from the typed rows themselves: preservation requests, victims ──

_MAIL_PROVIDERS = {
    ("gmail.com", "googlemail.com"): "Google",
    ("outlook.com", "hotmail.com", "live.com", "msn.com", "outlook.de", "hotmail.de"): "Microsoft",
    ("yahoo.com", "ymail.com", "yahoo.de", "yahoo.co.uk"): "Yahoo",
    ("icloud.com", "me.com", "mac.com"): "Apple",
    ("protonmail.com", "proton.me", "pm.me"): "Proton",
    ("gmx.de", "gmx.net", "gmx.com", "gmx.at", "gmx.ch"): "GMX",
    ("web.de",): "WEB.DE",
    ("aol.com",): "AOL",
    ("mail.ru",): "Mail.ru",
    ("yandex.com", "yandex.ru"): "Yandex",
    ("t-online.de",): "T-Online",
    ("posteo.de",): "Posteo",
}


def _provider(value: str, kind: str, language: str = "en") -> tuple[str, bool]:
    """``(who holds the value, named)``: a well-known consumer mail provider
    by name, otherwise the mail provider of the domain (to be identified
    from its MX records), or the provider of a cloud resource or
    credential."""
    low = (value or "").strip().lower()
    if kind == "email" or (kind == "account" and "@" in low):
        domain = low.rsplit("@", 1)[-1].strip(".")
        for domains, name in _MAIL_PROVIDERS.items():
            if domain in domains:
                return name, True
        return _tx("mail_provider", language, domain=domain), False
    return _tx("provider_of", language, value=value), False


def provider_of(value: str, kind: str, language: str = "en") -> str:
    return _provider(value, kind, language)[0]


def _preserve_verb(provider: str, named: bool, language: str) -> str:
    # German: "bei Google", "beim Mailanbieter von ..."
    return _tx("preserve", language, provider=provider, bei=("bei" if named else "beim"))


def _mail_domain_is_own(assets: dict[str, Any] | None, value: str, kind: str) -> bool:
    low = (value or "").strip().lower()
    if not assets or "@" not in low or kind not in ("email", "account"):
        return False
    return _is_own(assets, low.rsplit("@", 1)[-1].strip("."), "domain")


def derive_from_typed_rows(case_dir: str | os.PathLike, claim_id: str,
                           language: str = "en") -> dict[str, Any]:
    """The rows a claim's typed indicators warrant on their own: a
    preservation request for every value a provider holds (use request,
    in either frame), and, in the subject frame, the identification of
    the victims the rows name, passed on for notification."""
    from core.claim_graph import add_recommendation, get_node
    from core.indicators import rows_of, use_for
    graph = load_graph(case_dir)
    claim = get_node(graph, claim_id)
    if not claim or claim.get("kind") not in ("claim", "conclusion"):
        return {"claim_id": claim_id, "recorded": [], "folded": []}
    frame, assets = _frame_and_assets(case_dir)
    recorded, folded = [], []
    by_provider: dict[tuple[str, bool], list[str]] = {}
    own_held: list[str] = []
    victims: list[str] = []
    for row in rows_of(claim):
        kind, side, value = str(row.get("type") or ""), str(row.get("side") or ""), str(row.get("value") or "")
        if not value:
            continue
        if "request" in use_for(frame, side, kind, value):
            if _is_own(assets, value, kind) or _mail_domain_is_own(assets, value, kind):
                # The owner holds its own mailboxes: an internal step, not
                # legal process against itself.
                own_held.append(value)
            else:
                by_provider.setdefault(_provider(value, kind, language), []).append(value)
        if frame == "subject" and side == "victim" and value not in victims:
            victims.append(value)
    hosts = [claim["host"]] if claim.get("host") else None
    for (provider, named), values in by_provider.items():
        verb = _preserve_verb(provider, named, language)
        # An exact fold: a request to another provider is another row.
        r = add_recommendation(
            case_dir, action=action_text(verb, values, language), phase="investigate", scope="host",
            urgency="now", basis_ids=[claim_id], source="derived",
            rationale=f"a value a provider holds, named by {claim_id}; retention is the clock",
            hosts=hosts, indicators=values, fingerprint_action=verb, fold_exact=True, language=language)
        if r.get("success"):
            (folded if r.get("duplicate") else recorded).append(r["node_id"])
    if own_held:
        verb = _tx("legal_hold", language)
        r = add_recommendation(
            case_dir, action=action_text(verb, own_held, language), phase="investigate", scope="host",
            urgency="now", basis_ids=[claim_id], source="derived",
            rationale=f"a mailbox or account the owner holds itself, named by {claim_id}",
            hosts=hosts, indicators=own_held, fingerprint_action=verb, language=language)
        if r.get("success"):
            (folded if r.get("duplicate") else recorded).append(r["node_id"])
    if victims:
        verb = _tx("victim", language)
        r = add_recommendation(
            case_dir, action=action_text(verb, victims, language), phase="escalate", scope="host",
            urgency="now", basis_ids=[claim_id], source="derived",
            rationale=f"victims or named targets on the typed rows of {claim_id}; notification is a decision for law enforcement or counsel",
            hosts=hosts, indicators=victims, fingerprint_action=verb, language=language)
        if r.get("success"):
            (folded if r.get("duplicate") else recorded).append(r["node_id"])
    return {"claim_id": claim_id, "recorded": recorded, "folded": folded}


# ── next investigative steps, from what is still open ────────────────────

_GAP_TASK_RE = _re.compile(r"request (task-\d+) has open parts")
_GAP_UNIT_RE = _re.compile(r"^unit (.+) is unexamined")


def derive_next_steps(case_dir: str | os.PathLike, language: str = "en") -> dict[str, Any]:
    """Record the next investigative steps at report time, from sources
    that carry a state: the request parts still open (one row per request,
    the parts as its objects) and the ledger's unexamined units of value
    (one row per unit), at most a few in all, in either frame. A step
    whose source has since closed is marked done."""
    from core.claim_graph import add_recommendation, set_recommendation_state
    recorded, folded, closed = [], [], []
    try:
        from core.investigation_tasks import load_tasks
        from core.request_parts import open_parts
        every = [t for t in ((load_tasks(case_dir) or {}).get("tasks") or []) if isinstance(t, dict)]
        tasks = [t for t in every if t.get("status") != "dropped"]
    except Exception:  # noqa: BLE001
        every, tasks = [], []
    # A dropped request has no open parts: its row closes like an answered one.
    open_by_task = {str(t.get("id")): (open_parts(t) if t.get("status") != "dropped" else []) for t in every}
    try:
        from core.coverage_ledger import _is_high_value_name, open_units
        from pathlib import Path as _P
        units = [str(u.get("path")) for u in open_units(case_dir, limit=1_000_000)
                 if _is_high_value_name(_P(str(u.get("path"))).name)]
    except Exception:  # noqa: BLE001
        units = []
    # Rows whose source closed since they were recorded are done.
    try:
        graph = load_graph(case_dir)
        for nid, n in (graph.get("nodes") or {}).items():
            if not isinstance(n, dict) or n.get("kind") != "recommendation" or n.get("source") != "gap":
                continue
            if n.get("response_state") != "open":
                continue
            rationale = str(n.get("reasoning") or "")
            m = _GAP_TASK_RE.search(rationale)
            if m and m.group(1) in open_by_task and not open_by_task[m.group(1)]:
                set_recommendation_state(case_dir, nid, "done", actor="atlas", note="the request's parts were answered afterwards")
                closed.append(nid)
                continue
            m = _GAP_UNIT_RE.search(rationale)
            if m and m.group(1) not in units:
                set_recommendation_state(case_dir, nid, "done", actor="atlas", note="the unit was examined afterwards")
                closed.append(nid)
    except Exception:  # noqa: BLE001
        pass
    budget = MAX_NEXT_STEPS
    for t in tasks:
        parts = open_by_task.get(str(t.get("id"))) or []
        if not parts or budget <= 0:
            continue
        verb = _tx("open_parts", language, request=" ".join(str(t.get("text") or "").split())[:60])
        objects = [" ".join(str(p.get("text") or "").split())[:80] for p in parts]
        # An exact fold on the request; the objects are rebuilt from the
        # parts still open, so an answered part leaves the row.
        r = add_recommendation(
            case_dir, action=action_text(verb, objects, language), phase="investigate", scope="estate",
            urgency="soon", source="gap", rationale=f"request {t.get('id')} has open parts at report time",
            indicators=objects, fingerprint_action=verb, fold_exact=True, replace_objects=True, language=language)
        if r.get("success"):
            (folded if r.get("duplicate") else recorded).append(r["node_id"])
            budget -= 1
    for unit in units:
        if budget <= 0:
            break
        verb = _tx("examine", language, unit=unit)
        r = add_recommendation(
            case_dir, action=verb, phase="investigate", scope="host", urgency="soon", source="gap",
            rationale=f"unit {unit} is unexamined at report time", fingerprint_action=verb, fold_exact=True)
        if r.get("success"):
            (folded if r.get("duplicate") else recorded).append(r["node_id"])
            budget -= 1
    return {"recorded": recorded, "folded": folded, "closed": closed}


# ── coverage: findings that should have a response step ──────────────────

def coverage_warning(case_dir: str | os.PathLike | None) -> str:
    """The pre-report advisory: every CONFIRMED or LIKELY current belief
    whose techniques or wording describe initial access, persistence,
    credential access, command and control or exfiltration needs a
    recommendation resting on it (open or done); the ones without are
    listed with what to do, which is never to invent objects."""
    if not case_dir:
        return ""
    try:
        from core.indicators import _INDICATOR_CLASSES, _INDICATOR_TACTICS, _tactics_of
        from core.ir_playbook import classify
        graph = load_graph(case_dir)
    except Exception:  # noqa: BLE001
        return ""
    nodes = graph.get("nodes") or {}
    covered: set[str] = set()
    for n in nodes.values():
        if isinstance(n, dict) and n.get("kind") == "recommendation" \
                and n.get("status") not in ("superseded", "withdrawn") \
                and n.get("response_state") in ("open", "done"):
            covered |= set(n.get("basis_ids") or [])
    missing: list[str] = []
    for nid, n in nodes.items():
        if not isinstance(n, dict) or n.get("kind") not in ("claim", "conclusion"):
            continue
        if n.get("status") in ("superseded", "withdrawn") or str(n.get("confidence") or "").upper() not in ("CONFIRMED", "LIKELY"):
            continue
        text = " ".join(str(n.get(k) or "") for k in ("statement", "reasoning"))
        tactics = _tactics_of(techniques_in(text))
        if not (tactics & _INDICATOR_TACTICS or set(classify(str(n.get("statement") or ""), asserted=True)) & _INDICATOR_CLASSES):
            continue
        if nid not in covered:
            missing.append(nid)
    if not missing:
        return ""
    return (f"Findings without a response step resting on them: {', '.join(missing[:12])}"
            + (f" and {len(missing) - 12} more" if len(missing) > 12 else "")
            + ". Type the indicators the claim's cited output shows (claim.add_indicators), or record "
            "the step without objects with claim.record_recommendation; it is then marked to be scoped.")



# ── examinations: the follow-ups the findings open ────────────────────────
#
# Typed rows that name something a third party holds records of: a mail
# provider, a registrar or site operator, an internet or hosting provider,
# the service an account lives on, the maker or seller of a device, a cloud
# provider. From prose only what extraction reads unambiguously: mail
# addresses, URLs and public addresses.
_IDENTITY_TYPES = frozenset({"email", "domain", "url", "ip", "account", "serial", "cloud_resource"})
MAX_FOLLOWUPS_NAMED = 5


def _names_identity(node: dict[str, Any]) -> bool:
    from core.entities import extract
    from core.indicators import is_private_ip, rows_of
    for row in rows_of(node):
        kind, value = str(row.get("type") or ""), str(row.get("value") or "")
        if value and kind in _IDENTITY_TYPES and not (kind == "ip" and is_private_ip(value)):
            return True
    return any(e.startswith(("email:", "url:")) or (e.startswith("ip:") and not is_private_ip(e[3:]))
               for e in extract(str(node.get("statement") or "")))


def followup_warning(case_dir: str | os.PathLike | None) -> str:
    """The pre-report advisory on an examination: when no investigative or
    escalation step rests on a current CONFIRMED or LIKELY belief, the
    beliefs that name an identity a third party holds records of are
    listed, and the model is asked for the follow-ups they open. A
    hardening lesson is no answer to it."""
    try:
        from core.case_config import is_examination
        if not is_examination(case_dir):
            return ""
        nodes = load_graph(case_dir).get("nodes") or {}
    except Exception:  # noqa: BLE001 — advisory only
        return ""
    current = {
        nid: n for nid, n in nodes.items()
        if isinstance(n, dict) and n.get("kind") in ("claim", "conclusion")
        and n.get("status") not in ("superseded", "withdrawn")
        and str(n.get("confidence") or "").upper() in ("CONFIRMED", "LIKELY")
    }
    for n in nodes.values():
        if isinstance(n, dict) and n.get("kind") == "recommendation" \
                and n.get("status") not in ("superseded", "withdrawn") \
                and n.get("response_state") in ("open", "done") \
                and n.get("phase") in ("investigate", "escalate") \
                and set(n.get("basis_ids") or []) & current.keys():
            return ""
    named = [nid for nid, n in sorted(current.items(),
                                      key=lambda kv: str(kv[1].get("confidence")).upper() != "CONFIRMED")
             if _names_identity(n)]
    if not named:
        return ""
    return (f"This examination's findings name accounts, addresses or devices a third party holds "
            f"records of ({', '.join(named[:MAX_FOLLOWUPS_NAMED])}"
            + (f" and {len(named) - MAX_FOLLOWUPS_NAMED} more" if len(named) > MAX_FOLLOWUPS_NAMED else "")
            + "), and no investigative follow-up rests on any finding. Record the follow-ups they "
            "open with claim.record_recommendation (phase investigate or escalate, basis_ids = the "
            "claim id): whom to identify, which provider or operator to ask for records, what to "
            "preserve. Hardening lessons come after them.")


def basis_lost_warning(case_dir: str | os.PathLike | None) -> str:
    """The pre-report advisory for open steps whose every basis was
    withdrawn or superseded without a successor: each is named with the way
    out. Never a blocker."""
    if not case_dir:
        return ""
    try:
        rows = [r for r in build_catalog(case_dir).get("recommendations") or []
                if r.get("basis_lost") and r.get("state") == "open"]
    except Exception:  # noqa: BLE001
        return ""
    if not rows:
        return ""
    return (f"{len(rows)} open recommendation(s) rest only on withdrawn findings: "
            + ", ".join(r["id"] for r in rows[:8])
            + ". Dismiss each that no longer applies with claim.update_recommendation "
            "(state dismissed, with a note), or record it again on a current belief; the "
            "report lists them apart, under a review-before-acting heading.")
