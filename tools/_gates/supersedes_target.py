"""Gate: a record naming the finding it replaces (``supersedes=``) names a
standing finding of this run, on the same host.

The trace cannot be edited, so a finding changes its tier or gains ATT&CK
techniques by being recorded again. Named, the new record replaces the
finding (its claim is superseded by the new one) instead of standing beside
it as a second finding. The name is a claim id ("C0012") or the finding's
call id ("123", "#123"). The resolved trace entry is left on the context
(``supersedes_entry``) for record_finding; a name that resolves to no
standing finding, or to one on another host, is refused with the standing
findings named."""
from __future__ import annotations


def _norm(value) -> str:
    return " ".join(str(value or "").split()).lower()


def _standing(log) -> list[dict]:
    from core.claim_graph import asserted_finding_entries
    case_dir = log.case_dir() if hasattr(log, "case_dir") else None
    return asserted_finding_entries(
        [e for e in (getattr(log, "_entries", None) or []) if e.get("type") == "finding"], case_dir)


def resolve(name: str, log) -> dict | None:
    """The standing finding entry ``name`` names, or None."""
    raw = str(name or "").strip().lstrip("#").strip()
    if not raw:
        return None
    entries = _standing(log)
    if raw.isdigit():
        return next((e for e in entries if int(e.get("call_id") or 0) == int(raw)), None)
    try:
        from core.claim_graph import load_graph
        case_dir = log.case_dir() if hasattr(log, "case_dir") else None
        nodes = (load_graph(case_dir).get("nodes") or {}) if case_dir else {}
    except Exception:  # noqa: BLE001 - no graph, no claim id to resolve
        return None
    node = next((n for n in nodes.values() if isinstance(n, dict)
                 and str(n.get("id") or "").casefold() == raw.casefold()), None)
    if not node or node.get("kind") != "claim":
        return None
    ids = {node.get("source_finding_call_id"), *(node.get("merged_finding_call_ids") or [])}
    return next((e for e in entries if e.get("call_id") in ids), None)


def _standing_line(log) -> str:
    entries = _standing(log)[-8:]
    if not entries:
        return "this run has no standing finding"
    return "standing findings: " + "; ".join(
        f"#{e.get('call_id')} '{' '.join(str(e.get('description') or '').split())[:60]}'"
        for e in entries)


def _refuse(ctx, error: str) -> dict:
    return {"success": False, "gate": "supersedes_target", "error": error,
            "description": ctx.description, "confidence": ctx.confidence}


def check(ctx) -> dict | None:
    name = str(getattr(ctx, "supersedes", "") or "").strip()
    if not name:
        return None
    entry = resolve(name, ctx.log)
    if entry is None:
        return _refuse(ctx, (
            f"supersedes={name!r} names no standing finding of this run. Pass the claim id "
            f"(C0012) or the call id record_finding returned for the finding this record "
            f"replaces; {_standing_line(ctx.log)}"))
    mine, theirs = _norm(getattr(ctx, "host", "")), _norm(entry.get("host"))
    if mine and theirs and mine != theirs:
        return _refuse(ctx, (
            f"supersedes={name!r} names a finding on host {entry.get('host')}, and this record "
            f"is on {getattr(ctx, 'host', '')}: a finding on another host is another finding. "
            "Record this one without supersedes="))
    ctx.supersedes_entry = entry
    return None
