"""Analyst-provided investigation context (interpretation, not evidence).

Persists in ``.atlas/investigation_memory.json`` under ``analyst_context[]``.
Evidence fingerprints are never modified by this module.
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.rerun_brief import load_memory, memory_path

SCHEMA_VERSION = "1.0"

_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
_IPV6_RE = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b")
_QUOTED_RE = re.compile(r"[\"']([^\"']{2,80})[\"']")
# User/account tokens after common keywords or DOMAIN\user / user@domain
_USER_KW_RE = re.compile(
    r"(?i)\b(?:user(?:name)?|account|principal|admin(?:istrator)?)\s+"
    r"([A-Za-z0-9._\-\\$]{2,64})\b"
)
_DOMAIN_USER_RE = re.compile(
    r"\b([A-Za-z0-9._\-]{1,32}\\[A-Za-z0-9._\-$]{2,64})\b"
)
_EMAIL_RE = re.compile(
    r"\b([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})\b"
)
_HOST_KW_RE = re.compile(
    r"(?i)\b(?:host(?:name)?|workstation|server|jump\s*host)\s+"
    r"([A-Za-z0-9][A-Za-z0-9.\-_]{1,63})\b"
)
_FQDN_RE = re.compile(
    r"\b([A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)+)\b"
)

MATCH_KINDS = frozenset({
    "claim", "observation", "hypothesis", "conclusion", "conflict",
})


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def extract_entities(text: str) -> list[str]:
    """Lightweight tokens for claim-graph matching (IPs, users, hosts, quotes)."""
    if not text:
        return []
    found: list[str] = []
    for rx in (_IPV4_RE, _IPV6_RE, _DOMAIN_USER_RE, _EMAIL_RE, _QUOTED_RE,
               _USER_KW_RE, _HOST_KW_RE, _FQDN_RE):
        for m in rx.finditer(text):
            tok = (m.group(1) if m.lastindex else m.group(0)).strip()
            if len(tok) < 2:
                continue
            # Drop common false positives from FQDN regex
            if tok.lower() in {
                "is", "a", "the", "and", "or", "not", "our", "an", "to",
                "for", "of", "in", "on", "as", "be", "by",
            }:
                continue
            if tok not in found:
                found.append(tok)
    return found


def list_context(case_dir: str | os.PathLike, *, active_only: bool = False) -> list[dict[str, Any]]:
    mem = load_memory(case_dir)
    entries = list(mem.get("analyst_context") or [])
    if active_only:
        return [e for e in entries if e.get("status") == "active"]
    return entries


def _next_id(entries: list[dict[str, Any]]) -> str:
    n = 1
    for e in entries:
        eid = e.get("id") or ""
        if eid.startswith("ac-"):
            try:
                n = max(n, int(eid.split("-", 1)[1]) + 1)
            except ValueError:
                pass
    return f"ac-{n:04d}"


def save_context_entries(
    case_dir: str | os.PathLike,
    entries: list[dict[str, Any]],
) -> dict[str, Any]:
    """Write analyst_context into investigation_memory without wiping other fields."""
    path = memory_path(case_dir)
    mem = load_memory(case_dir)
    mem["schema_version"] = mem.get("schema_version") or SCHEMA_VERSION
    mem["analyst_context"] = entries
    mem["updated_at"] = _utcnow()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(mem, indent=2, ensure_ascii=False) + "\n",
                    encoding="utf-8")
    return mem


def _new_entry(
    entries: list[dict[str, Any]],
    text: str,
    *,
    run_id: str = "",
    supersedes: str | None = None,
    origin: str = "",
) -> dict[str, Any]:
    from core.investigation_tasks import fingerprint_text

    return {
        "id": _next_id(entries),
        "text": text,
        "status": "active",
        "entities": extract_entities(text),
        "created_at": _utcnow(),
        "created_run_id": run_id or "",
        "supersedes": supersedes,
        "withdrawn_at": None,
        "withdrawn_run_id": None,
        # Where the entry came from: the brief's prior-knowledge section
        # (core.case_knowledge.ORIGIN) or, when empty, a direct write.
        "origin": origin,
        # Exact-text identity, the way a task is matched to its request.
        "fingerprint": fingerprint_text(text),
    }


def add_context(
    case_dir: str | os.PathLike,
    text: str,
    *,
    run_id: str = "",
    supersedes: str | None = None,
    origin: str = "",
) -> dict[str, Any]:
    """Append an active analyst_context entry. Returns the new entry."""
    text = (text or "").strip()
    if not text:
        raise ValueError("analyst context text is empty")
    entries = list_context(case_dir)
    entry = _new_entry(entries, text, run_id=run_id, supersedes=supersedes,
                       origin=origin)
    entries.append(entry)
    save_context_entries(case_dir, entries)
    return entry


def entry_by_id(case_dir: str | os.PathLike, context_id: str) -> dict[str, Any]:
    for e in list_context(case_dir):
        if e.get("id") == context_id:
            return e
    raise KeyError(f"analyst context id not found: {context_id}")


def link_supersedes(
    case_dir: str | os.PathLike, new_id: str, old_id: str,
) -> dict[str, Any]:
    """Record that ``new_id`` replaces ``old_id``; returns the new entry."""
    entries = list_context(case_dir)
    for e in entries:
        if e.get("id") == new_id:
            e["supersedes"] = old_id
            save_context_entries(case_dir, entries)
            return e
    raise KeyError(f"analyst context id not found: {new_id}")


def _entry_fingerprint(entry: dict[str, Any]) -> str:
    from core.investigation_tasks import fingerprint_text
    return str(entry.get("fingerprint") or fingerprint_text(entry.get("text") or ""))


def reconcile_case_knowledge(
    case_dir: str | os.PathLike,
    *,
    persist: bool = True,
    run_id: str = "",
) -> dict[str, Any]:
    """The brief's prior-knowledge bullets, reconciled into the entries by
    exact normalised text, the way requests are reconciled into tasks: a
    bullet not yet held is added, a held bullet no longer written is
    withdrawn, a withdrawn bullet written again comes back under its id.
    Entries that did not come from the brief are left alone. Writes only
    when something changed."""
    from core.case_knowledge import ORIGIN, facts
    from core.investigation_tasks import fingerprint_text

    entries = list_context(case_dir)
    active: dict[str, dict[str, Any]] = {}
    withdrawn_by_fp: dict[str, dict[str, Any]] = {}
    for e in entries:
        if e.get("origin") != ORIGIN:
            continue
        fp = _entry_fingerprint(e)
        if e.get("status") == "active":
            active.setdefault(fp, e)
        else:
            withdrawn_by_fp.setdefault(fp, e)

    now = _utcnow()
    seen: set[str] = set()
    added: list[dict[str, Any]] = []
    reactivated: list[dict[str, Any]] = []
    matched: list[str] = []
    for fact in facts(case_dir):
        fp = fingerprint_text(fact)
        if not fp or fp in seen:
            continue
        seen.add(fp)
        if fp in active:
            matched.append(active[fp]["id"])
            continue
        old = withdrawn_by_fp.get(fp)
        if old is not None:
            old.update({"status": "active", "withdrawn_at": None,
                        "withdrawn_run_id": None})
            active[fp] = old
            reactivated.append(old)
            continue
        entry = _new_entry(entries, fact, run_id=run_id, origin=ORIGIN)
        entries.append(entry)
        active[fp] = entry
        added.append(entry)

    withdrawn: list[dict[str, Any]] = []
    for fp, e in list(active.items()):
        if fp in seen:
            continue
        e.update({"status": "withdrawn", "withdrawn_at": now,
                  "withdrawn_run_id": run_id or ""})
        withdrawn.append(e)

    changed = bool(added or reactivated or withdrawn)
    if persist and changed:
        save_context_entries(case_dir, entries)
    return {
        "added": added,
        "reactivated": reactivated,
        "withdrawn": withdrawn,
        "matched": matched,
        "changed": changed,
    }


def withdraw_context(
    case_dir: str | os.PathLike,
    context_id: str,
    *,
    run_id: str = "",
) -> dict[str, Any]:
    """Mark an entry withdrawn. Raises KeyError if missing."""
    entries = list_context(case_dir)
    for e in entries:
        if e.get("id") == context_id:
            if e.get("status") == "withdrawn":
                return e
            e["status"] = "withdrawn"
            e["withdrawn_at"] = _utcnow()
            e["withdrawn_run_id"] = run_id or ""
            save_context_entries(case_dir, entries)
            return e
    raise KeyError(f"analyst context id not found: {context_id}")


def correct_context(
    case_dir: str | os.PathLike,
    context_id: str,
    new_text: str,
    *,
    run_id: str = "",
) -> dict[str, Any]:
    """Withdraw old entry and add a superseding active entry."""
    withdraw_context(case_dir, context_id, run_id=run_id)
    return add_context(case_dir, new_text, run_id=run_id, supersedes=context_id)


def find_matching_node_ids(
    case_dir: str | os.PathLike,
    *,
    entities: list[str] | None = None,
    texts: list[str] | None = None,
) -> list[str]:
    """Return claim-graph node ids whose statement/host mention any entity."""
    from core.claim_graph import CURRENT_BELIEF_STATUSES, load_graph

    tokens: list[str] = []
    for e in entities or []:
        if e and e not in tokens:
            tokens.append(e)
    for t in texts or []:
        for e in extract_entities(t):
            if e not in tokens:
                tokens.append(e)
    if not tokens:
        return []

    graph = load_graph(case_dir)
    hit: set[str] = set()
    lower_tokens = [(tok, tok.lower()) for tok in tokens]
    for nid, node in (graph.get("nodes") or {}).items():
        kind = node.get("kind")
        if kind not in MATCH_KINDS:
            continue
        st = node.get("status")
        if kind == "conflict":
            if st != "conflict":
                continue
        elif st not in CURRENT_BELIEF_STATUSES | {"needs_review"}:
            continue
        hay = f"{node.get('statement') or ''} {node.get('host') or ''}".lower()
        for _tok, low in lower_tokens:
            if low and low in hay:
                hit.add(nid)
                break
    return sorted(hit)


_RT = {
    "en": {
        "title": "Analyst's prior knowledge",
        "lead": ("the analyst's statements from CASE.md ('What you already know'), "
                 "not evidence. For each, the findings that name an address, "
                 "account or host it names:"),
        "named": "named in {fids}",
        "none": "named in no finding",
        "nothing": "names no address, account or host",
        "more": "... and {n} more statement(s)",
    },
    "de": {
        "title": "Vorwissen",
        "lead": ("Aussagen aus CASE.md ('What you already know'), keine Belege. "
                 "Je Aussage die Befunde, die eine darin genannte Adresse, ein "
                 "Konto oder einen Host nennen:"),
        "named": "genannt in {fids}",
        "none": "in keinem Befund genannt",
        "nothing": "nennt keine Adresse, kein Konto und keinen Host",
        "more": "... und {n} weitere Aussage(n)",
    },
}
_REPORT_MAX = 20


def report_lines(case_dir: str | os.PathLike, findings: list[dict[str, Any]] | None = None,
                 language: str = "en") -> list[str]:
    """The Scope and Evidence block on the analyst's prior knowledge: each
    standing statement with the report's findings that name what it names,
    by the matcher that re-opens findings when a statement changes. A
    statement that names no address, account or host says so; no match is
    no verdict on it."""
    active = list_context(case_dir, active_only=True)
    if not active:
        return []
    tx = _RT["de" if language == "de" else "en"]
    shown = {str(f.get("id")): str(f.get("finding_id") or f.get("id"))
             for f in findings or [] if f.get("id")}
    lines = [f"**{tx['title']}:** {tx['lead']}", ""]
    for e in active[:_REPORT_MAX]:
        text = " ".join(str(e.get("text") or "").split())
        tokens = list(e.get("entities") or extract_entities(text))
        if not tokens:
            tail = tx["nothing"]
        else:
            fids = list(dict.fromkeys(shown[n] for n in find_matching_node_ids(
                case_dir, entities=tokens) if n in shown))
            tail = tx["named"].format(fids=", ".join(fids)) if fids else tx["none"]
        shown_text = text if len(text) <= 300 else text[:299].rstrip() + "…"
        lines.append(f"- `{e.get('id')}`: {shown_text} — {tail}")
    if len(active) > _REPORT_MAX:
        lines.append(tx["more"].format(n=len(active) - _REPORT_MAX))
    return lines


def apply_feedback(
    case_dir: str | os.PathLike,
    *,
    text: str | None = None,
    withdraw_id: str | None = None,
    correct_id: str | None = None,
    run_id: str = "",
    dry_run: bool = False,
) -> dict[str, Any]:
    """Apply add/withdraw/correct mutations. Returns mutation summary.

    When ``dry_run`` is True, compute entities/matches without writing memory.
    """
    text = (text or "").strip() or None
    new_entry: dict[str, Any] | None = None
    withdrawn: dict[str, Any] | None = None
    journal_hints: list[dict[str, Any]] = []

    if dry_run:
        entities: list[str] = []
        texts: list[str] = []
        active = list_context(case_dir, active_only=True)
        if text:
            entities = extract_entities(text)
            texts = [text]
        elif withdraw_id:
            for e in active:
                if e.get("id") == withdraw_id:
                    entities = list(e.get("entities") or extract_entities(e.get("text") or ""))
                    texts = [e.get("text") or ""]
                    break
        matched = find_matching_node_ids(case_dir, entities=entities, texts=texts)
        return {
            "dry_run": True,
            "new_entry": {"text": text, "entities": entities} if text else None,
            "withdrawn_id": withdraw_id,
            "correct_id": correct_id,
            "matched_node_ids": matched,
            "journal_hints": [],
            "active_context": active,
        }

    if correct_id:
        if not text:
            raise ValueError("--correct-context requires -q / --question with new text")
        new_entry = correct_context(case_dir, correct_id, text, run_id=run_id)
        journal_hints.append({
            "reason": "analyst_context_corrected",
            "summary": f"Analyst context corrected: {correct_id} → {new_entry['id']}",
            "related_ids": [correct_id, new_entry["id"]],
            "details": {"old_id": correct_id, "new_id": new_entry["id"],
                        "text": text[:300]},
        })
    elif withdraw_id:
        withdrawn = withdraw_context(case_dir, withdraw_id, run_id=run_id)
        journal_hints.append({
            "reason": "analyst_context_withdrawn",
            "summary": f"Analyst context withdrawn: {withdraw_id}",
            "related_ids": [withdraw_id],
            "details": {"text": (withdrawn.get("text") or "")[:300]},
        })
    elif text:
        new_entry = add_context(case_dir, text, run_id=run_id)
        journal_hints.append({
            "reason": "analyst_context_added",
            "summary": f"Analyst context added: {new_entry['id']}",
            "related_ids": [new_entry["id"]],
            "details": {"text": text[:300], "entities": new_entry.get("entities")},
        })

    entities = []
    texts = []
    if new_entry:
        entities.extend(new_entry.get("entities") or [])
        texts.append(new_entry.get("text") or "")
    if withdrawn:
        entities.extend(withdrawn.get("entities") or [])
        texts.append(withdrawn.get("text") or "")
    for e in list_context(case_dir, active_only=True):
        entities.extend(e.get("entities") or [])
        texts.append(e.get("text") or "")

    matched = find_matching_node_ids(case_dir, entities=entities, texts=texts)
    return {
        "dry_run": False,
        "new_entry": new_entry,
        "withdrawn": withdrawn,
        "matched_node_ids": matched,
        "journal_hints": journal_hints,
        "active_context": list_context(case_dir, active_only=True),
    }
