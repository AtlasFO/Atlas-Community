"""Investigation Claim Graph — epistemic state for a case.

Separate from the execution trace (process/lineage audit). The LLM remains the
investigator; this module stores Observations / Claims / Hypotheses / Conflicts /
Conclusions for explainability, auditability, and incremental updates.

Storage: ``<case>/.atlas/claim_graph.json``

Schema + load/save + fail-open mirror from ``misc.record_finding``.
Later phases add promotion APIs, conflicts, gates, and report grounding.
"""
from __future__ import annotations

import json
import os
import re
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

SCHEMA_VERSION = "1.0"

NODE_KINDS = frozenset({
    "evidence",
    "observation",
    "claim",
    "hypothesis",
    "conflict",
    "conclusion",
    "recommendation",
})

# A recommendation is what the case tells the responder to do. It is a node
# like a conclusion so that it is versioned, superseded, snapshotted and
# projected with everything else — and, like an IOC, it is only as strong as
# the beliefs it rests on, which it must name.
# investigate: a next examination step, a preservation or legal-process
# request; escalate: a decision handed to someone else, and the mandatory
# escalations. gap: a step that rests on what is still open (a request
# part, an unexamined unit), not on a belief.
RECOMMENDATION_PHASES = ("contain", "eradicate", "recover", "harden", "investigate", "escalate")
RECOMMENDATION_URGENCIES = ("now", "soon", "later")
RECOMMENDATION_SCOPES = ("host", "network", "estate")
RECOMMENDATION_SOURCES = ("prior_knowledge", "derived", "recorded", "analyst", "gap")
_URGENCY_ORDER = {u: i for i, u in enumerate(RECOMMENDATION_URGENCIES)}
MAX_OBJECTS_SHOWN = 8
_AND_MORE = {"en": "and {n} more", "de": "und {n} weitere"}


def action_text(verb: str, objects: list[str], language: str = "en") -> str:
    """The verb phrase followed by its objects as the typed rows print
    them, at most a few with "and N more"."""
    if not objects:
        return verb
    shown = ", ".join(objects[:MAX_OBJECTS_SHOWN])
    extra = len(objects) - MAX_OBJECTS_SHOWN
    more = (" " + _AND_MORE.get(language if language in _AND_MORE else "en").format(n=extra)) if extra > 0 else ""
    return f"{verb}: {shown}{more}"
RECOMMENDATION_STATES = ("open", "done", "dismissed")

EDGE_TYPES = frozenset({
    "supports",
    "derived_from",
    "tests",
    "contradicts",
    "supersedes",
    "resolves",
    # claim to claim: a lower-tier finding that adds to a stronger one's
    # event (derived_from also links a claim to a recommendation)
    "refines",
})

# Epistemic lifecycle states (dashboard + incremental engine).
# Legacy aliases on load: active→unchanged, resolved→unchanged (non-conflict).
NODE_STATUSES = frozenset({
    "new",
    "unchanged",
    "updated",
    "needs_review",
    "conflict",
    "superseded",
    "withdrawn",
})
# Beliefs safe to cite as current conclusions/claims.
CURRENT_BELIEF_STATUSES = frozenset({"new", "unchanged", "updated"})
_STATUS_ALIASES = {
    "active": "unchanged",
    "resolved": "unchanged",
}
SCOPES = frozenset({"host", "estate"})
CONFIDENCE_TIERS = frozenset({
    "CONFIRMED", "LIKELY", "SUSPECTED", "UNCONFIRMED",
})

_LOCK = threading.RLock()
_ID_PREFIX = {
    "evidence": "E",
    "observation": "O",
    "claim": "C",
    "hypothesis": "H",
    "conflict": "X",
    "conclusion": "N",
    "recommendation": "R",
}


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _norm_text(s: str) -> str:
    return " ".join((s or "").split()).lower()


def claim_graph_path(case_dir: str | os.PathLike) -> Path:
    return Path(case_dir).resolve() / ".atlas" / "claim_graph.json"


def empty_graph(case_id: str = "") -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "case_id": case_id or "",
        "updated_at": _utcnow(),
        "nodes": {},
        "edges": [],
        "meta": {"next_seq": 1},
    }


def normalize_status(status: str | None, *, kind: str = "") -> str:
    """Map legacy/unknown statuses onto the Phase-6 vocabulary."""
    s = (status or "").strip().lower()
    if s in _STATUS_ALIASES:
        s = _STATUS_ALIASES[s]
    if kind == "conflict" and s in ("unchanged", "new", "updated", "active"):
        return "conflict"
    if s in NODE_STATUSES:
        return s
    return "unchanged"


def _quarantine_corrupt(path: Path) -> None:
    """Move an unreadable claim_graph.json aside instead of leaving it in
    place to be silently overwritten by the next save_graph() — losing
    every belief in the case with no trace anything went wrong."""
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    try:
        path.rename(path.with_name(f"{path.name}.corrupt-{stamp}"))
    except OSError:
        pass


def _normalize_graph(graph: Any) -> dict[str, Any]:
    """Drop what cannot be a node. A graph file with a corrupted entry — a
    null, a string, a dict with no id — used to raise deep inside the first
    reader that touched it and end the run there. The entries that are
    nodes are kept; the count of what was dropped is recorded on the graph."""
    if not isinstance(graph, dict):
        return empty_graph()
    nodes = graph.get("nodes")
    if not isinstance(nodes, dict):
        graph["nodes"] = {}
        return graph
    dropped = 0
    clean: dict[str, Any] = {}
    for nid, node in nodes.items():
        if not isinstance(node, dict) or not str(node.get("id") or nid):
            dropped += 1
            continue
        node.setdefault("id", str(nid))
        node.setdefault("kind", "claim")
        node.setdefault("status", "new")
        if not isinstance(node.get("statement"), str):
            node["statement"] = str(node.get("statement") or "")
        if str(node.get("confidence") or "").upper() not in CONFIDENCE_TIERS:
            node["confidence"] = "UNCONFIRMED"
        clean[str(nid)] = node
    graph["nodes"] = clean
    if dropped:
        graph.setdefault("meta", {})["dropped_malformed_nodes"] = dropped
    return graph


def load_graph(case_dir: str | os.PathLike) -> dict[str, Any]:
    path = claim_graph_path(case_dir)
    if not path.is_file():
        return empty_graph()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        _quarantine_corrupt(path)
        return empty_graph()
    if not isinstance(data, dict):
        _quarantine_corrupt(path)
        return empty_graph()
    data.setdefault("schema_version", SCHEMA_VERSION)
    data.setdefault("case_id", "")
    data.setdefault("nodes", {})
    data.setdefault("edges", [])
    data.setdefault("meta", {})
    data["meta"].setdefault("next_seq", 1)
    # Lazy migrate legacy statuses
    for n in data["nodes"].values():
        if isinstance(n, dict):
            n["status"] = normalize_status(n.get("status"), kind=n.get("kind", ""))
    return _normalize_graph(data)


def save_graph(case_dir: str | os.PathLike, graph: dict[str, Any]) -> Path:
    """Atomic write of the claim graph. Creates ``.atlas/`` as needed."""
    path = claim_graph_path(case_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    graph = _normalize_graph(dict(graph))
    graph["updated_at"] = _utcnow()
    graph["schema_version"] = SCHEMA_VERSION
    payload = json.dumps(graph, indent=2, ensure_ascii=False) + "\n"
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(payload, encoding="utf-8")
    os.replace(tmp, path)
    try:
        from core.investigation_orchestrator import mark_state_dirty
        mark_state_dirty(case_dir, reason="claim_graph_save")
    except Exception:
        pass
    return path


def _next_id(graph: dict[str, Any], kind: str) -> str:
    if kind not in NODE_KINDS:
        raise ValueError(f"unknown node kind: {kind}")
    seq = int(graph.setdefault("meta", {}).get("next_seq", 1))
    graph["meta"]["next_seq"] = seq + 1
    return f"{_ID_PREFIX[kind]}{seq:04d}"


def get_node(graph: dict[str, Any], node_id: str) -> Optional[dict[str, Any]]:
    return graph.get("nodes", {}).get(node_id)


def list_nodes(
    graph: dict[str, Any],
    *,
    kind: str | None = None,
    status: str | None = None,
) -> list[dict[str, Any]]:
    nodes = list(graph.get("nodes", {}).values())
    if kind:
        nodes = [n for n in nodes if n.get("kind") == kind]
    if status:
        nodes = [n for n in nodes if n.get("status") == status]
    return nodes


def find_claim_by_finding_call_id(
    graph: dict[str, Any], call_id: int
) -> Optional[dict[str, Any]]:
    for n in graph.get("nodes", {}).values():
        if n.get("kind") == "claim" and n.get("source_finding_call_id") == call_id:
            return n
    return None


def find_claim_by_statement(
    graph: dict[str, Any], statement: str, host: str = ""
) -> Optional[dict[str, Any]]:
    target = _norm_text(statement)
    host_n = _norm_text(host)
    for n in graph.get("nodes", {}).values():
        if n.get("kind") != "claim":
            continue
        # A retired claim is not the one being restated: saying its words
        # again is a new assertion, which gets a node of its own.
        if n.get("status") in ("superseded", "withdrawn"):
            continue
        if _norm_text(n.get("statement", "")) != target:
            continue
        if _norm_text(n.get("host", "")) != host_n:
            continue
        return n
    return None


def is_current_belief(node: dict[str, Any] | None) -> bool:
    """Whether a graph node is something the run still asserts.

    The report projection renders exactly these statuses; a claim that was
    superseded or withdrawn is kept for audit but no longer said.
    """
    if not isinstance(node, dict):
        return True
    return node.get("status") in CURRENT_BELIEF_STATUSES | {"needs_review"}


def asserted_finding_entries(
    finding_entries: list[dict],
    case_dir: str | os.PathLike | None,
) -> list[dict]:
    """The trace's finding entries as the run currently asserts them.

    The execution trace is append-only: it records that a finding was made,
    not whether the run still stands by it. Supersession and withdrawal live
    on the claim graph, so any gate, count or export that reasons about what
    the report will say has to read the trace through the graph:

    * a finding whose claim mirror is superseded or withdrawn is left out
      (the trace entry stays where it is, for audit);
    * a finding whose claim now carries a different tier - the report gate
      lowered it, or a twin was merged into it - is returned with that tier,
      because that is the tier the report renders;
    * a finding without a mirror (the mirror failed, or a trace written
      before the graph existed) is asserted as recorded.

    Entries are copies where they differ from the trace and the trace's own
    dicts where they do not, so callers may still match them by identity or
    by ``call_id``. Without a case directory nothing can be looked up and the
    trace is returned as it is.
    """
    if not finding_entries:
        return []
    graph: dict[str, Any] | None = None
    if case_dir:
        try:
            graph = load_graph(case_dir)
        except Exception:  # noqa: BLE001
            graph = None
    nodes = (graph or {}).get("nodes") or {}
    by_call: dict[int, dict] = {}
    gone_statements: list[str] = []
    for node in nodes.values():
        if not isinstance(node, dict) or node.get("kind") != "claim":
            continue
        ids = [node.get("source_finding_call_id")]
        ids += list(node.get("merged_finding_call_ids") or [])
        for cid in ids:
            try:
                by_call.setdefault(int(cid), node)
            except (TypeError, ValueError):
                continue
        if not is_current_belief(node):
            stmt = _norm_text(node.get("statement") or "")
            if stmt:
                gone_statements.append(stmt[:160])

    def _mirror(f: dict) -> dict | None:
        cid = f.get("claim_id")
        if cid and isinstance(nodes.get(str(cid)), dict):
            return nodes[str(cid)]
        try:
            return by_call.get(int(f.get("call_id") or 0))
        except (TypeError, ValueError):
            return None

    def _withdrawn_by_statement(desc: str) -> bool:
        # Traces written before findings carried claim ids: the graph's
        # superseded statements are matched on their opening text.
        d = _norm_text(desc)[:120]
        return bool(d) and any(
            d == g[:120] or d.startswith(g[:80]) or g.startswith(d[:80])
            for g in gone_statements)

    out: list[dict] = []
    for f in finding_entries:
        if (f.get("claim_status") or "").lower() in ("superseded", "withdrawn"):
            continue
        node = _mirror(f)
        if node is not None:
            if not is_current_belief(node):
                continue
            tier = str(node.get("confidence") or "").upper()
            own = str(f.get("confidence") or "").upper()
            if tier in CONFIDENCE_TIERS and tier != own:
                # A merge never raises a finding whose statement the claim
                # does not carry: its tier belongs to its own text.
                raised_by_merge = (
                    node.get("merged_finding_call_ids")
                    and _TIER_RANK.get(tier, -1) > _TIER_RANK.get(own, -1)
                    and _norm_text(f.get("description") or "") != _norm_text(node.get("statement") or ""))
                if not raised_by_merge:
                    f = {**f, "confidence": tier, "trace_confidence": f.get("confidence")}
        elif gone_statements and _withdrawn_by_statement(f.get("description") or ""):
            continue
        out.append(f)
    return out


def _evidence_from_finding(
    source: str,
    supporting_evidence: str,
    linked_call_id: int,
    input_call_ids: list[int] | None,
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    cid0 = int(linked_call_id) if linked_call_id else None

    def _add_artifact(path: str, locator: str = "") -> None:
        p = (path or "").strip()
        if not p:
            return
        if any(
            isinstance(i, dict) and i.get("artifact") == p
            for i in items
        ):
            return
        items.append({
            "artifact": p[:256],
            "locator": (locator or "")[:2000],
            "call_id": cid0,
        })

    # I5: persist resolvable case paths (split compounds; mine prose).
    try:
        from core.evidence_resolver import (
            extract_case_paths_from_text,
            split_artifact_names,
        )
    except Exception:
        extract_case_paths_from_text = None  # type: ignore
        split_artifact_names = None  # type: ignore

    if source:
        parts: list[str] = []
        if split_artifact_names is not None:
            parts = split_artifact_names(str(source))
        if not parts:
            parts = [str(source)[:256]]
        for part in parts:
            _add_artifact(part)

    se = (supporting_evidence or "").strip()
    if se:
        if extract_case_paths_from_text is not None:
            for path in extract_case_paths_from_text(se):
                _add_artifact(path, locator=se[:500])
        items.append({
            "artifact": "supporting_evidence",
            "locator": se[:2000],
            "call_id": cid0,
        })
    refused = _refused_call_ids(input_call_ids)
    for cid in input_call_ids or []:
        try:
            c = int(cid)
        except (TypeError, ValueError):
            continue
        # A call that was refused or errored is evidence of nothing but the
        # refusal. One report cited a coverage-ledger refusal as support for
        # a claim about log clearing, because every id the model listed was
        # copied in unexamined.
        if c in refused or c <= 0:
            continue
        if not any(i.get("call_id") == c for i in items):
            items.append({
                "artifact": "trace_call",
                "locator": f"call_id={c}",
                "call_id": c,
            })
    return items


def _refused_call_ids(call_ids: list[int] | None) -> set[int]:
    """Of the given ids, those the trace records as failed or refused."""
    wanted: set[int] = set()
    for cid in call_ids or []:
        try:
            wanted.add(int(cid))
        except (TypeError, ValueError):
            continue
    if not wanted:
        return set()
    try:
        from core.execution_log import log
        return {
            int(e.get("call_id"))
            for e in log._entries
            if e.get("call_id") in wanted
            and e.get("type") == "tool_call"
            and not e.get("success")
        }
    except Exception:  # noqa: BLE001
        return set()


# Ordered — CONFIDENCE_TIERS itself is a set. An unknown tier ranks below
# every tier (readers default to 0 or -1).
_TIER_RANK = {"UNCONFIRMED": 1, "SUSPECTED": 2, "LIKELY": 3, "CONFIRMED": 4}

# Hard identifiers a statement rests on, by kind. Timestamps to the second,
# SIDs, hashes and GUIDs were the whole vocabulary, so a finding written the
# way an analyst writes one — "Feb 4 12:05", 10.0.0.7, DOMAIN\user — yielded
# no anchor at all, and one event recorded twice reached the report twice.
# Addresses, principals and minute-precision times are identifiers too; they
# are weaker alone, which is what ``anchors_agree`` is for.
_ANCHOR_SPECS = (
    ("time_s", re.compile(r"\b\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}")),
    ("time_m", re.compile(r"\b\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}\b")),
    ("time_m", re.compile(
        r"(?i)\b(?:jan|feb|mar|apr|may|jun|jul|aug|sep|sept|oct|nov|dec)"
        r"[a-z]*\.?\s+\d{1,2},?\s+(?:at\s+)?\d{1,2}:\d{2}\b")),
    ("sid", re.compile(r"\bS-1-5-21(?:-\d+){3,4}\b")),
    ("digest", re.compile(
        r"\b[0-9a-f]{32}\b|\b[0-9a-f]{40}\b|\b[0-9a-f]{64}\b", re.I)),
    ("guid", re.compile(
        r"\{[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\}", re.I)),
    ("addr", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    # DOMAIN\\account, but not a path fragment: "C:\\Users\\bob\\x.exe" holds
    # "Users\\bob" and "\\\\SRV\\share" holds "SRV\\share", and two different
    # facts about one user's files would then share an identifier.
    ("principal", re.compile(
        r"(?<![\\/:.\w])[A-Za-z][A-Za-z0-9._-]+\\+[A-Za-z0-9._$-]{2,}(?![\\/])")),
)
# The four kinds that were the whole set before: two of those alone still
# mean one event written twice, so every merge the old rule made is still made.
_STRICT_ANCHOR_KINDS = frozenset({"time_s", "sid", "digest", "guid"})
_ANCHOR_RES = tuple(rx for _kind, rx in _ANCHOR_SPECS)


def statement_anchor_kinds(statement: str) -> set[tuple[str, str]]:
    """``{(kind, value)}`` — the hard identifiers a statement rests on."""
    text = str(statement or "")
    out: set[tuple[str, str]] = set()
    for kind, rx in _ANCHOR_SPECS:
        for m in rx.finditer(text):
            value = m.group(0).lower()
            if kind == "principal":
                # A statement quoted out of JSON carries doubled separators.
                value = re.sub(r"\\+", "\\\\", value)
                if re.search(r"\.[a-z0-9]{1,4}$", value.rsplit("\\", 1)[-1]):
                    continue  # …\\payload.exe is a file, not a principal
            out.add((kind, value))
    # A second-precision timestamp also matches the minute pattern; the
    # prefix is not a second identifier of the same event.
    seconds = {v for k, v in out if k == "time_s"}
    return {
        (k, v) for k, v in out
        if not (k == "time_m" and any(s.startswith(v) for s in seconds))
    }


def statement_anchors(statement: str) -> set[str]:
    """The hard identifiers a statement rests on — timestamps, SIDs, hashes,
    GUIDs, addresses, principals. Two claims on one host that share two of
    these are one finding written twice (see ``anchors_agree``)."""
    return {value for _kind, value in statement_anchor_kinds(statement)}


def anchors_agree(a: set[tuple[str, str]], b: set[tuple[str, str]]) -> bool:
    """True when two statements identify the same thing.

    Two shared identifiers, spanning two different kinds — an address plus a
    time, a principal plus a time. Two of one kind is not enough: two claims
    about different traffic between the same pair of hosts share two
    addresses and are not one finding. The four original kinds are exempt:
    two exact timestamps, or a SID and a hash, were always sufficient.
    """
    shared = a & b
    if len(shared) < 2:
        return False
    kinds = {kind for kind, _v in shared}
    return len(kinds) >= 2 or kinds <= _STRICT_ANCHOR_KINDS


def find_claim_by_anchors(
    graph: dict[str, Any], statement: str, host: str = "",
) -> Optional[dict[str, Any]]:
    """An active claim on the same host sharing at least two hard anchors.

    ``find_claim_by_statement`` is exact-match, so a finding re-recorded
    with one more sentence would become a second node and the report
    would render one event twice. Anchors are identifiers, not words, so
    a paraphrase does not fool this and two different events do not
    collide on it.
    """
    mine = statement_anchor_kinds(statement)
    if len(mine) < 2:
        return None
    host_n = _norm_text(host)
    for n in graph.get("nodes", {}).values():
        if n.get("kind") != "claim" or n.get("status") in ("superseded", "withdrawn"):
            continue
        if host_n and _norm_text(n.get("host", "")) not in ("", host_n):
            continue
        if anchors_agree(mine, statement_anchor_kinds(n.get("statement", ""))):
            return n
    return None


def infer_host_from_text(case_dir: str | os.PathLike | None, text: str) -> tuple[str, list[str]]:
    """``(host, all_mentioned)`` for a statement, against the case's own hosts.

    A claim recorded with ``host: ""`` although its statement names a
    case host leaves the report's Host column empty and per-host grouping
    dead. The evidence table in
    CASE.md already says which hosts exist; a statement that names exactly
    one of them is about it, one that names several is an estate claim.
    """
    if not case_dir or not text:
        return "", []
    try:
        from core.forensic_citation import known_case_hosts
        hosts = known_case_hosts(case_dir)
    except Exception:  # noqa: BLE001
        return "", []
    from core.forensic_citation import host_mentioned
    hits = [label for label in hosts if host_mentioned(label, text)]
    return (hits[0] if len(hits) == 1 else ""), hits


def merge_indicator_rows(node: dict[str, Any], rows: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    """Add typed indicator rows to a claim node, one per (type, value);
    a later row for the same value replaces the earlier one's fields."""
    current = [r for r in (node.get("indicators") or []) if isinstance(r, dict)]
    by_key = {(r.get("type"), str(r.get("value") or "").lower()): r for r in current}
    for r in rows or []:
        if not isinstance(r, dict) or not r.get("type") or not r.get("value"):
            continue
        key = (r["type"], str(r["value"]).lower())
        prev = by_key.get(key)
        new = dict(r)
        if prev and prev.get("side") and new.get("side") and prev["side"] != new["side"] \
                and not new.get("compromised"):
            # the first side stands; the disagreement is kept on the row
            new["side"] = prev["side"]
            new["note"] = (f"side stated as {r['side']} later; kept {prev['side']}"
                           + (f"; {prev['note']}" if prev.get("note") else ""))
        by_key[key] = new
    node["indicators"] = list(by_key.values())
    _resolve_dropped(node)
    return node["indicators"]


def _resolve_dropped(node: dict[str, Any]) -> None:
    """Forget a refused row once the node carries the value it stood for:
    the same value or the digest it was suggested to be a slip of, under any
    type, since the usual repair of a refused row re-types it (a hash
    stated as a file name, a path as a file)."""
    drops = [d for d in (node.get("indicators_dropped") or []) if isinstance(d, dict)]
    if not drops:
        return
    have = {str(r.get("value") or "").lower()
            for r in (node.get("indicators") or []) if isinstance(r, dict) and r.get("value")}
    left = [d for d in drops
            if str(d.get("value") or "").lower() not in have
            and not (d.get("suggested") and str(d["suggested"]).lower() in have)]
    if left:
        node["indicators_dropped"] = left
    else:
        node.pop("indicators_dropped", None)


def merge_dropped_rows(node: dict[str, Any], dropped: list[dict[str, Any]] | None) -> None:
    """Keep the typed rows refused at record time on the claim node, one per
    (type, value), so the indicator file can list what was not exported and
    why; a later row for the same value replaces the earlier one."""
    current = [d for d in (node.get("indicators_dropped") or []) if isinstance(d, dict)]
    by_key = {(d.get("type"), str(d.get("value") or "").lower()): d for d in current}
    for d in dropped or []:
        if isinstance(d, dict) and d.get("value"):
            by_key[(d.get("type"), str(d["value"]).lower())] = dict(d)
    if by_key:
        node["indicators_dropped"] = list(by_key.values())
    _resolve_dropped(node)


def set_claim_indicators(case_dir: str | os.PathLike, claim_id: str,
                         rows: list[dict[str, Any]],
                         dropped: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Attach validated typed rows to a current claim or conclusion, and the
    rows refused on the way (``dropped``)."""
    with _LOCK:
        graph = load_graph(case_dir)
        node = get_node(graph, claim_id)
        if not node or node.get("kind") not in ("claim", "conclusion"):
            return {"success": False, "error": f"not a claim or conclusion: {claim_id}"}
        if node.get("status") in ("superseded", "withdrawn"):
            return {"success": False, "error": f"{claim_id} is {node['status']}; attach to the current belief"}
        merged = merge_indicator_rows(node, rows)
        merge_dropped_rows(node, dropped)
        node["updated_at"] = _utcnow()
        save_graph(case_dir, graph)
    return {"success": True, "claim_id": claim_id, "indicators": merged}


def _names_more(statement: str, other: str) -> bool:
    """``statement`` names an entity or an anchor that ``other`` does not."""
    try:
        from core import entities as _ent
        if _ent.discriminative(_ent.extract(statement)) - _ent.discriminative(_ent.extract(other)):
            return True
    except Exception:  # noqa: BLE001 - the anchors below still decide
        pass
    return bool(statement_anchor_kinds(statement) - statement_anchor_kinds(other))


def upsert_claim_from_finding(
    case_dir: str | os.PathLike,
    *,
    statement: str,
    confidence: str,
    source: str = "",
    host: str = "",
    finding_call_id: int = 0,
    linked_call_id: int = 0,
    input_call_ids: list[int] | None = None,
    supporting_evidence: str = "",
    case_id: str = "",
    scope: str = "host",
    fresh: bool = False,
    indicators: list[dict[str, Any]] | None = None,
    indicators_dropped: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Create or update a ``claim`` node mirrored from a trace finding.

    With ``fresh`` the finding always gets a node of its own, whatever
    current claim says the same thing: a re-record that repairs a
    citation must leave the earlier claim behind to be superseded, not fold
    into it, or the report gate keeps reading the earlier finding's calls.

    Returns ``{success, claim_id, created|updated, path}``.
    """
    tier = (confidence or "").upper()
    if tier not in CONFIDENCE_TIERS:
        tier = "UNCONFIRMED"
    scope_v = scope if scope in SCOPES else "host"
    if not host:
        inferred, mentioned = infer_host_from_text(case_dir, statement)
        if inferred:
            host = inferred
        elif len(mentioned) > 1 and scope_v == "host":
            scope_v = "estate"

    with _LOCK:
        graph = load_graph(case_dir)
        if case_id and not graph.get("case_id"):
            graph["case_id"] = case_id

        existing = None
        if finding_call_id:
            existing = find_claim_by_finding_call_id(graph, finding_call_id)
        if existing is None and not fresh:
            existing = find_claim_by_statement(graph, statement, host)
        merged_twin = False
        if existing is None and not fresh:
            existing = find_claim_by_anchors(graph, statement, host)
            merged_twin = existing is not None
        # A statement and its tier travel together. A weaker twin that names
        # something the claim does not is a refinement, not the same
        # finding: it gets a claim of its own at its own tier, linked to the
        # stronger one, so it is reported and gated as what it is.
        refines_id = ""
        if merged_twin and _TIER_RANK.get(tier, -1) < _TIER_RANK.get(existing.get("confidence"), -1) \
                and _names_more(statement, str(existing.get("statement") or "")):
            refines_id = str(existing["id"])
            existing, merged_twin = None, False

        now = _utcnow()
        evidence = _evidence_from_finding(
            source, supporting_evidence, linked_call_id, input_call_ids
        )

        if existing:
            cid = existing["id"]
            if merged_twin:
                _rank = _TIER_RANK
                old_stmt = str(existing.get("statement") or "")
                old_tier = existing.get("confidence")
                if _rank.get(tier, -1) < _rank.get(old_tier, -1):
                    # a weaker restatement: the claim keeps its own text and tier
                    statement, tier = old_stmt, old_tier
                elif _rank.get(tier, -1) == _rank.get(old_tier, -1) and len(statement) < len(old_stmt):
                    statement = old_stmt
                # a stronger twin brings its own statement with its tier
                prior = [e for e in (existing.get("evidence") or [])
                         if isinstance(e, dict)]
                evidence = prior + [e for e in evidence if e not in prior]
                twins = list(existing.get("merged_finding_call_ids") or [])
                if finding_call_id and finding_call_id not in twins:
                    twins.append(int(finding_call_id))
                existing["merged_finding_call_ids"] = twins
            existing["statement"] = statement
            existing["confidence"] = tier
            existing["host"] = str(host or "")[:128]
            existing["scope"] = scope_v
            existing["evidence"] = evidence
            existing["updated_at"] = now
            try:
                from core.evidence_noise import (
                    claim_report_role,
                    looks_like_evidence_gap_statement,
                )
                existing["report_role"] = claim_report_role(statement)
                if looks_like_evidence_gap_statement(statement):
                    gaps = list(existing.get("gaps") or [])
                    seed = str(statement).strip()[:500]
                    if seed and seed not in gaps:
                        gaps.append(seed)
                    existing["gaps"] = gaps
            except Exception:
                pass
            if finding_call_id and not merged_twin:
                existing["source_finding_call_id"] = int(finding_call_id)
            if input_call_ids:
                prior_ids = list(existing.get("input_call_ids") or []) if merged_twin else []
                existing["input_call_ids"] = prior_ids + [
                    int(c) for c in input_call_ids if c and int(c) not in prior_ids
                ]
            if indicators:
                merge_indicator_rows(existing, indicators)
            if indicators_dropped:
                merge_dropped_rows(existing, indicators_dropped)
            graph["nodes"][cid] = existing
            path = save_graph(case_dir, graph)
            finding_id = None
            try:
                from core.finding_index import f_id_for, sync_after_graph_write
                sync_after_graph_write(case_dir)
                finding_id = f_id_for(case_dir, cid)
            except Exception:
                finding_id = None
            out = {
                "success": True,
                "claim_id": cid,
                "updated": True,
                "created": False,
                "path": str(path),
            }
            if finding_id:
                out["finding_id"] = finding_id
            return out

        cid = _next_id(graph, "claim")
        gap_list: list[str] = []
        report_role = "evidence"
        try:
            from core.evidence_noise import (
                claim_report_role,
                looks_like_evidence_gap_statement,
            )
            report_role = claim_report_role(statement)
            if looks_like_evidence_gap_statement(statement):
                # Seed structured gaps so Gaps projection is deterministic.
                gap_list.append(str(statement).strip()[:500])
        except Exception:
            pass
        node = {
            "id": cid,
            "kind": "claim",
            "status": "new",
            "statement": statement,
            "confidence": tier,
            "scope": scope_v,
            "host": str(host or "")[:128],
            "report_role": report_role,
            "evidence": evidence,
            "reasoning": "",
            "gaps": gap_list,
            "temporal_qualifier": None,
            "source_finding_call_id": int(finding_call_id) if finding_call_id else None,
            "input_call_ids": [int(c) for c in (input_call_ids or []) if c],
            "created_at": now,
            "updated_at": now,
        }
        if indicators:
            merge_indicator_rows(node, indicators)
        if indicators_dropped:
            merge_dropped_rows(node, indicators_dropped)
        if refines_id:
            node["refines"] = refines_id
            graph.setdefault("edges", []).append(
                {"from": cid, "to": refines_id, "type": "refines", "created_at": now})
        graph["nodes"][cid] = node
        path = save_graph(case_dir, graph)
        finding_id = None
        try:
            from core.finding_index import f_id_for, sync_after_graph_write
            sync_after_graph_write(case_dir)
            finding_id = f_id_for(case_dir, cid)
        except Exception:
            finding_id = None
        out = {
            "success": True,
            "claim_id": cid,
            "created": True,
            "updated": False,
            "path": str(path),
        }
        if finding_id:
            out["finding_id"] = finding_id
        return out


def mirror_finding_fail_open(
    *,
    statement: str,
    confidence: str,
    source: str = "",
    host: str = "",
    finding_call_id: int = 0,
    linked_call_id: int = 0,
    input_call_ids: list[int] | None = None,
    supporting_evidence: str = "",
    case_dir: str | None = None,
    case_id: str = "",
    fresh: bool = False,
    indicators: list[dict[str, Any]] | None = None,
    indicators_dropped: list[dict[str, Any]] | None = None,
) -> Optional[dict[str, Any]]:
    """Best-effort claim mirror. Never raises.

    Returns None only for the expected/benign no-op (no active case — a
    finding recorded outside any case has nothing to mirror into). Any
    OTHER failure — the claim graph write itself raising — is reported as
    ``{"skipped": True, "reason": ...}`` instead of also going through
    plain None, so the caller (tools.misc.record_finding) can surface it in
    the tool result rather than the trace having a finding the dashboard's
    claim-graph beliefs silently never got.
    """
    try:
        if not case_dir:
            from core.execution_log import log
            case_dir = log.case_dir()
        if not case_dir:
            return None
        if not case_id:
            try:
                from core.execution_log import log
                case_id = getattr(log, "_case_id", None) or ""
            except Exception:
                case_id = ""
        return upsert_claim_from_finding(
            case_dir,
            statement=statement,
            confidence=confidence,
            source=source,
            host=host,
            finding_call_id=finding_call_id,
            linked_call_id=linked_call_id,
            input_call_ids=input_call_ids,
            supporting_evidence=supporting_evidence,
            case_id=case_id or "",
            fresh=fresh,
            indicators=indicators,
            indicators_dropped=indicators_dropped,
        )
    except Exception as e:
        return {"skipped": True, "reason": f"{type(e).__name__}: {e}"[:200]}


def active_conclusions_and_conflicts(
    case_dir: str | os.PathLike,
) -> dict[str, list[dict[str, Any]]]:
    """Snapshot helpers for later report grounding (Phase 3)."""
    graph = load_graph(case_dir)
    return {
        "conclusions": [n for n in list_nodes(graph, kind="conclusion")
                        if n.get("status") in CURRENT_BELIEF_STATUSES],
        "claims": [n for n in list_nodes(graph, kind="claim")
                   if n.get("status") in CURRENT_BELIEF_STATUSES],
        "conflicts": [n for n in list_nodes(graph, kind="conflict")
                      if n.get("status") == "conflict"],
        "hypotheses": [n for n in list_nodes(graph, kind="hypothesis")
                       if n.get("status") in CURRENT_BELIEF_STATUSES | {"needs_review"}],
    }


def graph_snapshot_for_report(case_dir: str | os.PathLike) -> dict[str, Any]:
    """Compact snapshot for LLM report writers + grounding lint.

    Returns facts only — the LLM still writes the prose.
    """
    graph = load_graph(case_dir)
    snap = active_conclusions_and_conflicts(case_dir)
    superseded = [
        n for n in graph.get("nodes", {}).values()
        if n.get("status") == "superseded"
    ]
    withdrawn = [
        n for n in graph.get("nodes", {}).values()
        if n.get("status") == "withdrawn"
    ]
    return {
        "case_id": graph.get("case_id", ""),
        "updated_at": graph.get("updated_at", ""),
        "schema_version": graph.get("schema_version", SCHEMA_VERSION),
        "active_conclusions": snap["conclusions"],
        "active_claims": snap["claims"],
        "open_conflicts": snap["conflicts"],
        "active_hypotheses": snap["hypotheses"],
        "superseded": superseded,
        "withdrawn": withdrawn,
        # a run has beliefs once it holds a claim or a conclusion: a
        # baseline observation or a seeded precaution is not one
        "has_graph": any(isinstance(n, dict) and n.get("kind") in ("claim", "conclusion")
                         for n in (graph.get("nodes") or {}).values()),
    }


_NEGATIVE_COMPROMISE_RE = re.compile(
    r"\b(?:was|were|is|are)\s+not\s+compromised\b"
    r"|\bnot\s+compromised\b(?!\s+within\s+the\s+available)",
    re.IGNORECASE,
)
_PREFERRED_NEGATIVE_HINT = (
    "No evidence of compromise was identified within the available evidence"
)
_ESTATE_REC_RE = re.compile(
    r"\b(?:domain-wide|krbtgt|estate-wide|all\s+hosts|backup\s+integrity|"
    r"data-leak\s+impact|management\s+escalation|containment\s+and\s+isolation)\b",
    re.IGNORECASE,
)


def lint_report_against_graph(
    content: str,
    case_dir: str | os.PathLike | None,
    *,
    output_path: str = "",
) -> list[str]:
    """Advisory grounding checks against Current Investigation State.

    Empty list when no graph / no case_dir. Still advisory (Phase 7b/7c) —
    one revision cycle via write_final_report; never a deadlock.
    """
    if not case_dir:
        return []
    try:
        snap = graph_snapshot_for_report(case_dir)
        graph = load_graph(case_dir)
    except Exception:
        return []
    if not snap.get("has_graph"):
        return []

    warnings: list[str] = []
    text = content or ""
    text_l = text.lower()
    scope_info = infer_report_scope(output_path, case_dir=case_dir) if output_path else {
        "scope": "case", "host": "",
    }
    report_scope = scope_info.get("scope") or "case"
    report_host = (scope_info.get("host") or "").strip().lower()

    # Negative compromise wording (also Phase 5; cheap to enforce early)
    if _NEGATIVE_COMPROMISE_RE.search(text):
        warnings.append(
            "negative_compromise_wording: do not state the host 'was not "
            "compromised'. Prefer: "
            f"'{_PREFERRED_NEGATIVE_HINT}' — and name investigated evidence, "
            "coverage, gaps, and confidence."
        )

    open_conflicts = snap.get("open_conflicts") or []
    if open_conflicts:
        missing = []
        for c in open_conflicts:
            cid = c.get("id", "")
            stmt = (c.get("statement") or "")[:80]
            if cid and cid in text:
                continue
            fragment = stmt[:40].strip()
            if fragment and fragment.lower() in text_l:
                continue
            missing.append(cid or stmt[:40])
        if missing:
            warnings.append(
                "open_conflicts_unmentioned: open Conflict Findings must appear "
                "in the main report body (not an appendix). Missing: "
                + ", ".join(missing[:8])
                + ". Call misc.current_investigation_state (or claim.snapshot) "
                "and include a Conflicts section."
            )

    # Grounding: active conclusions should be reflected (by id or statement)
    conclusions = snap.get("active_conclusions") or []
    if conclusions:
        ungrounded = []
        for n in conclusions:
            if not node_in_report_scope(n, report_scope, report_host):
                continue
            if _node_reflected_in_text(n, text, text_l):
                continue
            ungrounded.append(n.get("id") or (n.get("statement") or "")[:40])
        if ungrounded:
            warnings.append(
                "conclusion_grounding: active Conclusions should be cited by "
                "node id (e.g. N0001) or reflected in finding prose. Uncited: "
                + ", ".join(ungrounded[:8])
                + ". Call misc.current_investigation_state before writing."
            )

    # CONFIRMED/LIKELY claims also need grounding when present
    claims = snap.get("active_claims") or []
    strong_claims = [
        n for n in claims
        if (n.get("confidence") or "").upper() in ("CONFIRMED", "LIKELY")
        and node_in_report_scope(n, report_scope, report_host)
    ]
    if strong_claims:
        ungrounded_c = []
        for n in strong_claims:
            if _node_reflected_in_text(n, text, text_l):
                continue
            ungrounded_c.append(n.get("id") or (n.get("statement") or "")[:40])
        if ungrounded_c:
            warnings.append(
                "claim_grounding: CONFIRMED/LIKELY claims should appear in the "
                "report (by id or statement). Uncited: "
                + ", ".join(ungrounded_c[:8])
                + ". Prefer misc.write_projected_final_report when has_beliefs."
            )

    # needs_review nodes → mention in gaps / limitations
    needs = [
        n for n in (graph.get("nodes") or {}).values()
        if n.get("status") == "needs_review"
        and node_in_report_scope(n, report_scope, report_host)
    ]
    if needs:
        mentioned = 0
        for n in needs:
            if _node_reflected_in_text(n, text, text_l):
                mentioned += 1
        if "needs_review" not in text_l and "needs review" not in text_l:
            if mentioned < min(len(needs), 1):
                warnings.append(
                    "needs_review_unmentioned: "
                    f"{len(needs)} claim-graph node(s) are needs_review — "
                    "note them under Evidence Gaps / limitations or re-validate "
                    "before promoting conclusions. Ids: "
                    + ", ".join(n.get("id", "") for n in needs[:8])
                )

    # host report must not lean on estate-scoped beliefs in recs
    if report_scope == "host":
        estate_nodes = [
            n for n in (conclusions + claims)
            if (n.get("scope") or "host") == "estate"
        ]
        if estate_nodes and _ESTATE_REC_RE.search(text):
            # Soft: estate beliefs + estate-language in a host report
            warnings.append(
                "host_vs_estate_projection: this looks like a per-host report "
                "but contains estate-scoped recommendation language. Keep "
                "host-scoped recommendations here; put estate-wide items in "
                "the Estate Report. Estate belief ids: "
                + ", ".join(
                    (n.get("id") or "") for n in estate_nodes[:6] if n.get("id")
                )
            )

    return warnings


def _known_host_forms(case_dir) -> set[str]:
    """Lower-cased names (and their log-side short forms) of the case's hosts."""
    try:
        from core.paths import active_case_dir
        cd = case_dir or active_case_dir()
        if not cd:
            return set()
        from core.forensic_citation import host_name_forms, known_case_hosts
        forms: set[str] = set()
        for h in known_case_hosts(cd):
            forms.add(str(h).lower())
            forms.update(host_name_forms(h))
        return forms
    except Exception:  # noqa: BLE001
        return set()


def infer_report_scope(output_path: str,
                       case_dir: str | os.PathLike | None = None) -> dict[str, str]:
    """Infer host vs estate vs case deliverable from the report filename.

    Accepts both modern names (``estate_report.md``, ``host_<HOST>_report.md``)
    and legacy ``<CASE>_estate_report.md`` / ``<CASE>_<HOST>_report.md``.

    The host token must name a host the case knows. Otherwise
    ``CASE_final_report.md`` reads as a host report for a host called
    "final": the narrative narrows to one source, most findings drop out as
    out of scope and the answers cite a claim id instead of a finding.
    With a case directory known — it always is during a run — only a real host
    name selects host scope; without one the filename is trusted as before.
    """
    base = os.path.basename(output_path or "")
    if base in ("estate_report.md", "estate_report.html") or base.endswith(
        "_estate_report.md"
    ):
        return {"scope": "estate", "host": ""}
    known = _known_host_forms(case_dir)

    def _is_host(token: str) -> bool:
        return not known or token.lower().split(".", 1)[0] in known

    # Modern: host_<HOST>_report.md
    m_host = re.match(r"^host_(.+)_report\.(md|html)$", base, re.I)
    if m_host and _is_host(m_host.group(1)):
        return {"scope": "host", "host": m_host.group(1)}
    # Legacy: reports/<CASE>_<host>_report.md — not the generic investigation report
    m = re.search(r"^(.+)_(.+)_report\.md$", base)
    if m and not base.endswith("_investigation_report.md"):
        host_part = m.group(2)
        if host_part and host_part.lower() not in (
            "investigation", "estate", "trace", "run", "final", "case", "draft",
        ) and _is_host(host_part):
            return {"scope": "host", "host": host_part}
    return {"scope": "case", "host": ""}


def _node_reflected_in_text(node: dict, text: str, text_l: str) -> bool:
    nid = node.get("id") or ""
    if nid and nid in text:
        return True
    stmt = (node.get("statement") or "").strip()
    key = stmt[:48] if len(stmt) >= 32 else stmt
    if key and key.lower() in text_l:
        return True
    return False


def _is_address(host: str) -> bool:
    """Whether a recorded host is an IP address rather than a name."""
    import ipaddress
    try:
        ipaddress.ip_address((host or "").strip())
        return True
    except ValueError:
        return False


def _host_key(host: str) -> str:
    h = (host or "").strip().lower()
    return h if _is_address(h) else h.split(".", 1)[0]


def same_host(a: str, b: str) -> bool:
    """Two recorded host names for one machine.

    The graph carries the name as it was written at the time — the case
    label, its FQDN, or the abbreviated form a log uses (``sql-02`` for
    ``PROD-SQL-02``). A shared suffix alone is not the same machine.
    """
    from core.forensic_citation import host_name_forms

    ka, kb = _host_key(a), _host_key(b)
    if not ka or not kb:
        return False
    if ka == kb:
        return True
    # An address is only ever itself. Treating it like a name would drop
    # everything after the first dot, and two machines on one network would
    # become one host.
    if _is_address(a) or _is_address(b):
        return False
    # The abbreviated forms a log uses are already defined once, with a
    # length floor that keeps a two-character fragment from matching half
    # the estate; a second implementation here would drift from it.
    return bool(set(host_name_forms(a)) & set(host_name_forms(b)))


def node_in_report_scope(
    node: dict, report_scope: str, report_host: str,
) -> bool:
    """Whether a belief belongs in this deliverable.

    Decided by the host and scope the belief was recorded with — never by
    what its statement says. A belief with no host recorded cannot be kept
    out of a host report on a guess, so it stays in.
    """
    if (report_scope or "case").lower() != "host":
        return True
    if (node.get("scope") or "host").lower() == "estate":
        return False
    node_host = (node.get("host") or "").strip()
    if report_host and node_host and not same_host(node_host, report_host):
        return False
    return True


def _looks_like_case_root(path: "os.PathLike | str") -> bool:
    """A case root has a .atlas/ store or the canonical evidence/analysis pair."""
    try:
        p = Path(path)
        if (p / ".atlas").is_dir():
            return True
        return (p / "evidence").is_dir() or (p / "analysis").is_dir()
    except Exception:
        return False


def resolve_case_dir(case_dir: str | None = None) -> Optional[str]:
    """Resolve a tool-supplied case_dir to a real case root.

    LLM tool calls routinely pass the case *name* instead of a
    path. Trusting that string blindly resolved it against the process cwd
    (~/Atlas) into a nonexistent directory, and every loader downstream
    fail-opened to empty state: every task update failed and the final
    report came out empty. Policy:

      1. No case_dir given → active execution-log case_dir.
      2. case_dir resolves to an existing case root → use it.
      3. case_dir matches the active case's basename (the "name not path"
         call pattern) → active case_dir.
      4. Anything else *unrecognized* → refuse (None). A typo'd or stale
         case name must never silently redirect into the active case and
         write there under a false "success" — that is the same fail-open
         this function exists to close, just one level up. Only the exact-name match in step 3 is safe to alias.
    """
    active: Optional[str] = None
    try:
        from core.execution_log import log
        active = log.case_dir() or None
    except Exception:
        active = None

    raw = (str(case_dir).strip() if case_dir else "")
    if not raw:
        return active
    try:
        candidate = Path(raw).expanduser()
        if candidate.is_dir() and _looks_like_case_root(candidate):
            return str(candidate.resolve())
        if active:
            active_p = Path(active)
            # "CASE-001" for the active ~/cases/CASE-001 — same case.
            if raw.rstrip("/").split("/")[-1] == active_p.name:
                return str(active_p)
            # Unknown/nonexistent string that doesn't name the active case:
            # refuse rather than silently write into it (a typo or stale
            # case name must fail loudly, not redirect).
            return None
        # No active case: accept an existing plain directory as last resort
        # (unit tests point at bare tmp dirs), refuse nonexistent strings.
        if candidate.is_dir():
            return str(candidate.resolve())
    except Exception:
        pass
    return None


def _normalize_evidence(evidence: list[dict] | None) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for item in evidence or []:
        if not isinstance(item, dict):
            continue
        out.append({
            "artifact": str(item.get("artifact", ""))[:256],
            "locator": str(item.get("locator", ""))[:2000],
            "call_id": item.get("call_id"),
        })
    return out


def _normalize_gaps(gaps: list[str] | None) -> list[str]:
    return [str(g)[:500] for g in (gaps or []) if str(g).strip()]


def add_node(
    case_dir: str | os.PathLike,
    *,
    kind: str,
    statement: str,
    confidence: str = "SUSPECTED",
    host: str = "",
    scope: str = "host",
    evidence: list[dict] | None = None,
    reasoning: str = "",
    gaps: list[str] | None = None,
    temporal_qualifier: str | None = None,
    parent_ids: list[str] | None = None,
    edge_type: str = "derived_from",
    extra: dict[str, Any] | None = None,
    case_id: str = "",
) -> dict[str, Any]:
    """Add an epistemic node. Optional parent_ids create edges from parents → new."""
    if kind not in NODE_KINDS:
        return {"success": False, "error": f"unknown kind: {kind}"}
    if edge_type not in EDGE_TYPES:
        return {"success": False, "error": f"unknown edge_type: {edge_type}"}
    tier = (confidence or "").upper()
    if tier not in CONFIDENCE_TIERS:
        return {"success": False, "error": f"invalid confidence: {confidence}"}
    scope_v = scope if scope in SCOPES else "host"
    statement = (statement or "").strip()
    if not statement:
        return {"success": False, "error": "statement required"}

    with _LOCK:
        graph = load_graph(case_dir)
        if case_id and not graph.get("case_id"):
            graph["case_id"] = case_id
        for pid in parent_ids or []:
            if pid not in graph.get("nodes", {}):
                return {"success": False, "error": f"unknown parent_id: {pid}"}

        now = _utcnow()
        nid = _next_id(graph, kind)
        initial_status = "conflict" if kind == "conflict" else "new"
        node: dict[str, Any] = {
            "id": nid,
            "kind": kind,
            "status": initial_status,
            "statement": statement,
            "confidence": tier,
            "scope": scope_v,
            "host": str(host or "")[:128],
            "evidence": _normalize_evidence(evidence),
            "reasoning": (reasoning or "")[:4000],
            "gaps": _normalize_gaps(gaps),
            "temporal_qualifier": temporal_qualifier,
            "source_finding_call_id": None,
            "input_call_ids": [],
            "created_at": now,
            "updated_at": now,
        }
        if extra:
            for k, v in extra.items():
                if k not in node and v is not None:
                    node[k] = v
        graph["nodes"][nid] = node
        for pid in parent_ids or []:
            graph["edges"].append({
                "from": pid,
                "to": nid,
                "type": edge_type,
                "meta": {},
            })
        path = save_graph(case_dir, graph)
        return {
            "success": True,
            "node_id": nid,
            "kind": kind,
            "path": str(path),
        }


def add_observation(
    case_dir: str | os.PathLike,
    statement: str,
    *,
    confidence: str = "CONFIRMED",
    evidence: list[dict] | None = None,
    host: str = "",
    reasoning: str = "",
    case_id: str = "",
    attrs: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Single-source observation (low interpretation).

    Optional ``attrs`` carries structured fields (e.g. auth event_class,
    source_endpoint) for machine consumers — not a second belief plane.
    """
    extra = {"attrs": attrs} if attrs else None
    return add_node(
        case_dir,
        kind="observation",
        statement=statement,
        confidence=confidence,
        host=host,
        evidence=evidence,
        reasoning=reasoning,
        case_id=case_id,
        extra=extra,
    )


def add_claim(
    case_dir: str | os.PathLike,
    statement: str,
    *,
    confidence: str = "LIKELY",
    observation_ids: list[str] | None = None,
    evidence: list[dict] | None = None,
    host: str = "",
    scope: str = "host",
    reasoning: str = "",
    gaps: list[str] | None = None,
    temporal_qualifier: str | None = None,
    case_id: str = "",
    enforce_validation: bool = True,
) -> dict[str, Any]:
    if enforce_validation:
        errs = validate_claim_statement(
            statement,
            scope=scope,
            temporal_qualifier=temporal_qualifier,
            kind="claim",
        )
        if errs:
            return {"success": False, "gate": "claim_validation", "errors": errs}
    result = add_node(
        case_dir,
        kind="claim",
        statement=statement,
        confidence=confidence,
        host=host,
        scope=scope,
        evidence=evidence,
        reasoning=reasoning,
        gaps=gaps,
        temporal_qualifier=temporal_qualifier,
        parent_ids=observation_ids,
        edge_type="derived_from",
        case_id=case_id,
    )
    if result.get("success"):
        # Soft contradiction scan (does not auto-create unless asked)
        try:
            det = detect_hard_contradictions(case_dir, auto_create=False)
            related = [
                p for p in det.get("pairs", [])
                if result["node_id"] in (p.get("claim_a"), p.get("claim_b"))
            ]
            if related:
                result["contradiction_warnings"] = related
                result["note"] = (
                    "Hard contradiction(s) detected with existing claims. "
                    "Call claim.add_conflict or claim.detect_contradictions "
                    "(auto_create=true) — never silently overwrite."
                )
        except Exception:
            pass
    return result


def add_hypothesis(
    case_dir: str | os.PathLike,
    statement: str,
    *,
    claim_ids: list[str] | None = None,
    confidence: str = "SUSPECTED",
    host: str = "",
    reasoning: str = "",
    gaps: list[str] | None = None,
    case_id: str = "",
) -> dict[str, Any]:
    return add_node(
        case_dir,
        kind="hypothesis",
        statement=statement,
        confidence=confidence,
        host=host,
        evidence=None,
        reasoning=reasoning,
        gaps=gaps,
        parent_ids=claim_ids,
        edge_type="tests",
        case_id=case_id,
    )


def add_conflict(
    case_dir: str | os.PathLike,
    statement: str,
    *,
    claim_ids: list[str],
    possible_explanations: list[str] | None = None,
    evidence_still_required: list[str] | None = None,
    confidence: str = "SUSPECTED",
    host: str = "",
    reasoning: str = "",
    reconciliation_status: str = "open",
    case_id: str = "",
) -> dict[str, Any]:
    """Record disagreement between claims. Does not supersede either side."""
    if not claim_ids or len(claim_ids) < 2:
        return {
            "success": False,
            "error": "conflict requires at least two claim_ids",
        }
    extra = {
        "conflicting_claim_ids": list(claim_ids),
        "possible_explanations": [
            str(x)[:500] for x in (possible_explanations or [])
        ],
        "evidence_still_required": [
            str(x)[:500] for x in (evidence_still_required or [])
        ],
        "reconciliation_status": reconciliation_status or "open",
    }
    result = add_node(
        case_dir,
        kind="conflict",
        statement=statement,
        confidence=confidence,
        host=host,
        reasoning=reasoning,
        gaps=evidence_still_required,
        parent_ids=claim_ids,
        edge_type="contradicts",
        extra=extra,
        case_id=case_id,
    )
    return result


def promote_conclusion(
    case_dir: str | os.PathLike,
    claim_id: str,
    *,
    statement: str | None = None,
    confidence: str | None = None,
    reasoning: str = "",
    gaps: list[str] | None = None,
    case_id: str = "",
) -> dict[str, Any]:
    """Promote an active claim to a conclusion (derived_from edge)."""
    with _LOCK:
        graph = load_graph(case_dir)
        claim = get_node(graph, claim_id)
        if not claim or claim.get("kind") != "claim":
            return {"success": False, "error": f"not an active claim: {claim_id}"}
        if claim.get("status") not in CURRENT_BELIEF_STATUSES | {"needs_review"}:
            return {
                "success": False,
                "error": f"claim {claim_id} status is {claim.get('status')}",
            }
        # Release lock before add_node (it re-acquires)
    return add_node(
        case_dir,
        kind="conclusion",
        statement=statement or claim["statement"],
        confidence=confidence or claim.get("confidence", "LIKELY"),
        host=claim.get("host", ""),
        scope=claim.get("scope", "host"),
        evidence=claim.get("evidence"),
        reasoning=reasoning or claim.get("reasoning", ""),
        gaps=gaps if gaps is not None else claim.get("gaps"),
        temporal_qualifier=claim.get("temporal_qualifier"),
        parent_ids=[claim_id],
        edge_type="derived_from",
        extra={"promoted_from_claim_id": claim_id},
        case_id=case_id,
    )


_ACTION_WORD_RE = re.compile(r"[a-z0-9]+")


def recommendation_fingerprint(phase: str, scope: str, action: str) -> str:
    """Two recommendations that say the same thing in different words are one.

    Order-free content words, so "Isolate FILESRV01 from the network" and
    "Network-isolate the host FILESRV01" fold, while "isolate" and
    "re-image" stay apart. A response plan with forty variations of "monitor
    the network" is the flood an IOC list is also built to refuse.
    """
    words = sorted({w for w in _ACTION_WORD_RE.findall((action or "").lower())
                    if len(w) > 2 and w not in ("the", "and", "for", "from",
                                                "with", "all", "any")})
    return f"{phase}|{scope}|{' '.join(words)}"


def _scopeless(fp: str) -> str:
    """A fingerprint with its scope blanked, for rows that fold across scopes."""
    parts = fp.split("|", 2)
    return f"{parts[0]}|*|{parts[2]}" if len(parts) == 3 else fp


def _same_recommendation(fp_a: str, fp_b: str, *, threshold: float = 0.75) -> bool:
    """Same phase and scope, and content words that mostly overlap — judged
    on the words, so "isolate FILESRV01" and "isolate the host FILESRV01" fold,
    while "isolate" and "re-image" stay apart."""
    try:
        pa, sa, wa = fp_a.split("|", 2)
        pb, sb, wb = fp_b.split("|", 2)
    except ValueError:
        return fp_a == fp_b
    if (pa, sa) != (pb, sb):
        return False
    a, b = set(wa.split()), set(wb.split())
    if not a or not b:
        return a == b
    return len(a & b) / len(a | b) >= threshold


def add_recommendation(
    case_dir: str | os.PathLike,
    *,
    action: str,
    phase: str,
    scope: str = "host",
    urgency: str = "soon",
    basis_ids: list[str] | None = None,
    source: str = "recorded",
    rationale: str = "",
    hosts: list[str] | None = None,
    indicators: list[str] | None = None,
    case_id: str = "",
    mandatory: bool = False,
    fingerprint_action: str = "",
    fold_exact: bool = False,
    replace_objects: bool = False,
    language: str = "en",
) -> dict[str, Any]:
    """Record what the responder should do, resting on named beliefs.

    ``indicators`` are the row's objects, the typed values the action names;
    ``fingerprint_action`` is the verb phrase the row folds on when the
    action text carries objects (a second finding that names more objects
    extends the open row, its text rebuilt from the verb and the union of
    the objects). ``fold_exact`` folds on the whole fingerprint only (a
    provider, a unit or a request in the verb keeps rows apart);
    ``replace_objects`` rebuilds an open row's objects from this call
    instead of adding to them. A closed row (done or dismissed) is never
    extended: the same indication folds into it, while a basis or an
    object that arrives after closure is new evidence and opens a new row,
    a mandatory one for a mandatory step.

    The refusal stance is the finding's: a recommendation names the claims
    or conclusions it derives from, and an estate-wide one must rest on
    evidence that reaches beyond one host — the same rule the report lint
    applied after the fact, now applied when the recommendation is written.
    The one exception is ``source="prior_knowledge"``: a precaution taken on
    what the analyst told Atlas before any evidence was read. It carries no
    basis and says so, because acting in the first hour is the point of
    incident response and pretending the basis is evidence would be worse
    than naming it as suspicion.
    """
    phase = (phase or "").strip().lower()
    scope = (scope or "host").strip().lower()
    urgency = (urgency or "soon").strip().lower()
    source = (source or "recorded").strip().lower()
    action = " ".join((action or "").split())[:300]
    if not action:
        return {"success": False, "error": "action required"}
    for value, allowed, name in ((phase, RECOMMENDATION_PHASES, "phase"),
                                 (scope, RECOMMENDATION_SCOPES, "scope"),
                                 (urgency, RECOMMENDATION_URGENCIES, "urgency"),
                                 (source, RECOMMENDATION_SOURCES, "source")):
        if value not in allowed:
            return {"success": False,
                    "error": f"invalid {name}: {value!r} (one of {', '.join(allowed)})"}
    basis_ids = [str(b).strip() for b in (basis_ids or []) if str(b).strip()]

    with _LOCK:
        graph = load_graph(case_dir)
        nodes = graph.get("nodes") or {}
        bases: list[dict[str, Any]] = []
        if source not in ("prior_knowledge", "gap"):
            if not basis_ids:
                return {"success": False,
                        "error": "basis_ids required: name the claim or conclusion "
                                 "ids this recommendation derives from (a "
                                 "prior_knowledge precaution and a gap step are "
                                 "the only kinds that rest on none)"}
            for bid in basis_ids:
                n = nodes.get(bid)
                if not isinstance(n, dict) or n.get("kind") not in ("claim", "conclusion"):
                    return {"success": False,
                            "error": f"basis {bid} is not a claim or conclusion"}
                if n.get("status") not in CURRENT_BELIEF_STATUSES | {"needs_review"}:
                    return {"success": False,
                            "error": f"basis {bid} is {n.get('status')} — cite a current belief"}
                bases.append(n)
            if scope == "estate":
                base_hosts = {str(b.get("host") or "").strip().lower()
                              for b in bases} - {""}
                reaches = any(b.get("scope") == "estate" for b in bases) or len(base_hosts) >= 2
                if not reaches:
                    return {"success": False,
                            "error": "an estate-scoped recommendation must rest on "
                                     "evidence beyond one host: cite an estate-scoped "
                                     "belief or beliefs on at least two hosts, or "
                                     "record it with scope=host"}
        verb = fingerprint_action or action
        fingerprint = recommendation_fingerprint(phase, scope, verb)
        objects = sorted(set(str(i).strip() for i in (indicators or []) if str(i).strip()))
        for nid, n in nodes.items():
            if n.get("kind") != "recommendation" or n.get("status") in ("superseded", "withdrawn"):
                continue
            fp_old = n.get("fingerprint") or ""
            if fold_exact:
                same = fp_old == fingerprint
            else:
                same = _same_recommendation(fp_old, fingerprint)
                # A mandatory escalation folds on its wording whatever the
                # scope: the existing row becomes mandatory with the new
                # basis added.
                if not same and (mandatory or n.get("mandatory")):
                    same = _same_recommendation(_scopeless(fp_old), _scopeless(fingerprint))
            if not same:
                continue
            state = n.get("response_state")
            have = set(n.get("indicators") or [])
            fresh = [o for o in objects if o not in have]
            new_basis = [b for b in basis_ids if b not in (n.get("basis_ids") or [])]
            if state == "dismissed" and not mandatory:
                continue   # a dismissed row does not block a restatement
            if state == "done":
                # The done row's note records what was done. The same
                # indication folds into it; a basis with nothing already on
                # the row, or a new object, is new evidence after closure
                # and opens a new row (a mandatory one for a mandatory step).
                if fresh or (new_basis and not (objects and not fresh)):
                    continue
            changed = False
            if mandatory and not n.get("mandatory"):
                n["mandatory"] = True
                changed = True
            for bid in new_basis:
                n.setdefault("basis_ids", []).append(bid)
                graph["edges"].append({"from": bid, "to": nid, "type": "derived_from", "meta": {}})
                changed = True
            extended = False
            if state == "open" and (fresh or (replace_objects and set(objects) != have)):
                # An open row follows the fuller derivation: its objects (the
                # union, or this call's when it rebuilds them), its text from
                # the verb and every object, and, when the new step is more
                # urgent, its urgency; the change is recorded in the rationale.
                merged = objects if replace_objects else sorted(have | set(fresh))
                n["indicators"] = merged
                n["verb"] = n.get("verb") or verb
                n["statement"] = action_text(n["verb"], merged, language)
                if _URGENCY_ORDER.get(urgency, 9) < _URGENCY_ORDER.get(str(n.get("urgency")), 9):
                    n["urgency"] = urgency
                n["reasoning"] = (rationale or str(n.get("reasoning") or ""))[:800] + (
                    f" (extended with {', '.join(fresh[:8])}"
                    + (f" and {len(fresh) - 8} more" if len(fresh) > 8 else "")
                    + (f" from {', '.join(basis_ids)}" if basis_ids else "") + ")" if fresh else "")
                extended = changed = True
            if changed:
                n["updated_at"] = _utcnow()
                save_graph(case_dir, graph)
            return {"success": True, "duplicate": True, "node_id": nid, "extended": extended,
                    "note": f"{'extended' if extended else 'already recommended as'} {nid}"}

    if bases:
        confidence = max((str(b.get("confidence") or "UNCONFIRMED").upper() for b in bases),
                         key=lambda tier: _TIER_RANK.get(tier, 0))
        host_set = {str(b.get("host") or "").strip() for b in bases} - {""}
    else:
        confidence = "SUSPECTED"
        host_set = set()
    host_list = sorted(set(str(h).strip() for h in (hosts or []) if str(h).strip()) | host_set)
    return add_node(
        case_dir,
        kind="recommendation",
        statement=action,
        confidence=confidence,
        host=host_list[0] if len(host_list) == 1 else "",
        scope="estate" if scope == "estate" else "host",
        reasoning=rationale,
        parent_ids=basis_ids,
        edge_type="derived_from",
        extra={
            "phase": phase,
            "urgency": urgency,
            "response_scope": scope,
            "source": source,
            "basis_ids": basis_ids,
            "hosts": host_list,
            "indicators": objects,
            "verb": verb,
            "response_state": "open",
            "state_changed_at": None,
            "state_changed_by": "",
            "fingerprint": fingerprint,
            # An escalation owed whoever owns the device: never dismissed
            # by the owner rules, ordered before every other open row.
            "mandatory": True if mandatory else None,
        },
        case_id=case_id,
    )


# A mandatory escalation closed as done needs to say what was done: the
# note is what the report shows in the row's place.
MIN_STATE_NOTE = 10


def set_recommendation_state(
    case_dir: str | os.PathLike,
    node_id: str,
    state: str,
    *,
    actor: str = "",
    note: str = "",
) -> dict[str, Any]:
    """Mark a recommendation open, done or dismissed — the responder's
    bookkeeping, separate from the belief status the graph keeps. A
    mandatory escalation is never dismissed; it is closed as done with a
    note, which the report shows."""
    state = (state or "").strip().lower()
    note = " ".join(str(note or "").split())[:400]
    if state not in RECOMMENDATION_STATES:
        return {"success": False,
                "error": f"invalid state: {state!r} (one of {', '.join(RECOMMENDATION_STATES)})"}
    with _LOCK:
        graph = load_graph(case_dir)
        node = get_node(graph, node_id)
        if not node or node.get("kind") != "recommendation":
            return {"success": False, "error": f"not a recommendation: {node_id}"}
        if node.get("mandatory"):
            if state == "dismissed":
                return {"success": False, "gate": "mandatory_escalation",
                        "error": "a mandatory escalation cannot be dismissed; close it as "
                                 "done with a note saying what was done"}
            if state == "done" and len(note) < MIN_STATE_NOTE:
                return {"success": False, "gate": "mandatory_escalation",
                        "error": "closing a mandatory escalation needs a note of at least "
                                 f"{MIN_STATE_NOTE} characters saying what was done"}
        now = _utcnow()
        node["response_state"] = state
        node["state_changed_at"] = now
        node["state_changed_by"] = str(actor or "")[:128]
        node["state_note"] = note if state != "open" else ""
        node["updated_at"] = now
        save_graph(case_dir, graph)
    return {"success": True, "node_id": node_id, "response_state": state}


# A withdrawal must say why: the reason is the only record of what the
# run stopped asserting and on what grounds. Shorter than this is a label,
# not an explanation.
MIN_WITHDRAW_REASON = 20


def supersede(
    case_dir: str | os.PathLike,
    old_id: str,
    new_id: str = "",
    *,
    reason: str = "",
) -> dict[str, Any]:
    """Mark old node superseded by new after reconciliation. Never deletes.

    With no ``new_id`` (or the node's own id) the node is withdrawn instead:
    a belief the run can no longer support and has nothing to replace it
    with. It leaves the current beliefs, so no gate or report counts it, and
    stays on the graph with the reason, which is required.
    """
    with _LOCK:
        graph = load_graph(case_dir)
        old = get_node(graph, old_id)
        if not old:
            return {"success": False, "error": f"unknown old_id: {old_id}"}
        if old.get("kind") == "recommendation":
            return {"success": False, "gate": "recommendation_state",
                    "error": (f"{old_id} is a recommendation: it is closed with "
                              "update_recommendation (done, with a note for a mandatory "
                              "escalation), never superseded or withdrawn")}
        if old.get("status") in ("superseded", "withdrawn"):
            return {
                "success": False,
                "error": f"{old_id} already {old.get('status')}",
            }
        now = _utcnow()
        if not new_id or new_id == old_id:
            if len((reason or "").strip()) < MIN_WITHDRAW_REASON:
                return {
                    "success": False,
                    "error": (f"withdrawing {old_id} needs a reason of at least "
                              f"{MIN_WITHDRAW_REASON} characters: what the run "
                              "stopped asserting and why the evidence does not "
                              "support it"),
                }
            old["status"] = "withdrawn"
            old["updated_at"] = now
            old["withdraw_reason"] = reason.strip()[:1000]
            graph["nodes"][old_id] = old
            path = save_graph(case_dir, graph)
            return {
                "success": True,
                "old_id": old_id,
                "withdrawn": True,
                "path": str(path),
            }
        new = get_node(graph, new_id)
        if not new:
            return {"success": False, "error": f"unknown new_id: {new_id}"}
        # The typed indicators of a revised belief belong to its successor
        # unless the successor already states the value.
        carried = [r for r in (old.get("indicators") or []) if isinstance(r, dict)]
        if carried and new.get("kind") in ("claim", "conclusion"):
            have = {(r.get("type"), str(r.get("value") or "").lower())
                    for r in (new.get("indicators") or []) if isinstance(r, dict)}
            merge_indicator_rows(new, [dict(r, carried_from=old_id) for r in carried
                                       if (r.get("type"), str(r.get("value") or "").lower()) not in have])
        # So do the rows it was refused, unless the successor carries the
        # value they stood for (merge_dropped_rows resolves those).
        refused = [d for d in (old.get("indicators_dropped") or []) if isinstance(d, dict)]
        if refused and new.get("kind") in ("claim", "conclusion"):
            own = {(d.get("type"), str(d.get("value") or "").lower())
                   for d in (new.get("indicators_dropped") or []) if isinstance(d, dict)}
            merge_dropped_rows(new, [dict(d, carried_from=old_id) for d in refused
                                     if (d.get("type"), str(d.get("value") or "").lower()) not in own])
        # A recommendation that rests on the revised belief rests on its
        # successor; the swap is recorded on the recommendation.
        for rid, rec in list(graph.get("nodes", {}).items()):
            if not isinstance(rec, dict) or rec.get("kind") != "recommendation" \
                    or old_id not in (rec.get("basis_ids") or []):
                continue
            rec["basis_ids"] = list(dict.fromkeys(new_id if b == old_id else b for b in rec["basis_ids"]))
            rec["basis_carried_from"] = list(dict.fromkeys([*(rec.get("basis_carried_from") or []), old_id]))
            graph["edges"].append({"from": new_id, "to": rid, "type": "derived_from",
                                   "meta": {"carried_from": old_id}})
        old["status"] = "superseded"
        old["updated_at"] = now
        old["superseded_by"] = new_id
        old["supersede_reason"] = (reason or "")[:1000]
        graph["nodes"][old_id] = old
        graph["edges"].append({
            "from": new_id,
            "to": old_id,
            "type": "supersedes",
            "meta": {"reason": (reason or "")[:500]},
        })
        path = save_graph(case_dir, graph)
        # A question the old belief answered is answered by its successor:
        # the task keeps its answer instead of being reopened at close-out.
        try:
            from core.investigation_tasks import carry_links_on_supersede
            carry_links_on_supersede(case_dir, old_id, new_id)
        except Exception:  # noqa: BLE001 - the task store must never fail a supersession
            pass
        return {
            "success": True,
            "old_id": old_id,
            "new_id": new_id,
            "path": str(path),
        }


def revalidate(
    case_dir: str | os.PathLike,
    node_id: str,
    *,
    call_ids: list[int],
    note: str = "",
    trace: str = "",
) -> dict[str, Any]:
    """Record that a belief under review was re-checked against the current
    evidence and still holds. Never deletes: the review that questioned it
    stays on the node as history.

    ``needs_review`` is set when evidence a belief cites changed or an
    analyst fact naming its entities moved, and was cleared only by
    superseding the belief or promoting it. A belief the investigator
    re-read and found unchanged had no verb, so the report kept listing it
    under gaps and every rerun kept starting an investigator for it.
    ``call_ids`` are the calls that re-read the evidence; the claim tool
    holds them to the citation test before this is called, so the graph
    records what it is handed. ``trace`` names the trace the calls belong
    to, since the graph outlives a run's trace.

    A node that went under review only through this belief (a conclusion,
    a recommendation, a claim resting on an observation: it carries the
    bases it was marked for in ``invalidated_via``) returns with it once
    every belief it derives from is current again. A node questioned in
    its own right carries no such stamp and needs its own re-validation.
    A task that was reopened because of these beliefs is answered again
    once every belief it rests on is current.
    """
    ids: list[int] = []
    for c in call_ids or []:
        try:
            ids.append(int(c))
        except (TypeError, ValueError):
            continue
    if not ids:
        return {"success": False,
                "error": "call_ids required: the calls that re-read the evidence "
                         "the belief rests on"}
    with _LOCK:
        graph = load_graph(case_dir)
        node = get_node(graph, node_id)
        if not node:
            return {"success": False, "error": f"unknown node_id: {node_id}"}
        if node.get("status") != "needs_review":
            return {"success": False,
                    "error": (f"{node_id} is {node.get('status')}: only a belief "
                              "under review (needs_review) can be re-validated")}
        now = _utcnow()

        def _clear(n: dict[str, Any], via: str = "") -> None:
            history = list(n.get("review_history") or [])
            record = {
                "invalidation_reason": n.get("invalidation_reason") or "",
                "invalidated_at": n.get("invalidated_at"),
                "invalidated_by": n.get("invalidated_by"),
                "revalidated_at": now,
                "call_ids": ids,
                "trace": trace or "",
                "note": (note or "")[:1000],
            }
            if via:
                record["via"] = via
            history.append({k: v for k, v in record.items() if v not in (None, "", [])
                            or k in ("invalidation_reason", "revalidated_at", "call_ids")})
            n["review_history"] = history
            n["status"] = "unchanged"
            n["updated_at"] = now
            n["revalidated_at"] = now
            n["revalidation_call_ids"] = ids
            for stale in ("invalidation_reason", "invalidated_at", "invalidated_by",
                          "invalidated_via"):
                n.pop(stale, None)

        _clear(node)
        graph["nodes"][node_id] = node
        nodes = graph.get("nodes") or {}
        edges = graph.get("edges") or []
        also: list[str] = []
        queue = [node_id]
        while queue:
            src = queue.pop(0)
            for edge in edges:
                if edge.get("type") != "derived_from" or edge.get("from") != src:
                    continue
                tgt = nodes.get(edge.get("to"))
                if (not tgt or tgt.get("status") != "needs_review"
                        or not tgt.get("invalidated_via")):
                    continue
                # A superseded or withdrawn base keeps its edge by design
                # and holds nothing under review.
                parents = [e.get("from") for e in edges
                           if e.get("type") == "derived_from" and e.get("to") == tgt.get("id")
                           and (nodes.get(e.get("from")) or {}).get("status")
                           not in ("superseded", "withdrawn")]
                if all((nodes.get(p) or {}).get("status") in CURRENT_BELIEF_STATUSES
                       for p in parents):
                    _clear(tgt, via=src)
                    also.append(str(tgt.get("id")))
                    queue.append(str(tgt.get("id")))
        path = save_graph(case_dir, graph)
        current = {nid for nid, n in nodes.items()
                   if isinstance(n, dict) and n.get("status") in CURRENT_BELIEF_STATUSES}
        gone = {nid for nid, n in nodes.items()
                if isinstance(n, dict) and n.get("status") in ("superseded", "withdrawn")}
    restored: list[str] = []
    try:
        from core.investigation_tasks import restore_tasks_for_claims
        restored = restore_tasks_for_claims(case_dir, [node_id] + also, current,
                                            gone).get("restored") or []
    except Exception:  # noqa: BLE001 - the task store must never fail a re-validation
        restored = []
    return {"success": True, "node_id": node_id, "status": "unchanged",
            "also_revalidated": also, "restored_tasks": restored, "path": str(path)}


def resolve_conflict(
    case_dir: str | os.PathLike,
    conflict_id: str,
    *,
    winning_claim_id: str,
    reason: str = "",
) -> dict[str, Any]:
    """Mark conflict resolved; supersede losing claims; keep winner active."""
    with _LOCK:
        graph = load_graph(case_dir)
        conflict = get_node(graph, conflict_id)
        if not conflict or conflict.get("kind") != "conflict":
            return {"success": False, "error": f"not a conflict: {conflict_id}"}
        ids = list(conflict.get("conflicting_claim_ids") or [])
        if winning_claim_id not in ids:
            return {
                "success": False,
                "error": f"winning_claim_id {winning_claim_id} not in conflict",
            }
        now = _utcnow()
        conflict["status"] = "superseded"  # closed conflict finding
        conflict["reconciliation_status"] = "resolved"
        conflict["winning_claim_id"] = winning_claim_id
        conflict["updated_at"] = now
        conflict["resolve_reason"] = (reason or "")[:1000]
        graph["nodes"][conflict_id] = conflict
        graph["edges"].append({
            "from": winning_claim_id,
            "to": conflict_id,
            "type": "resolves",
            "meta": {"reason": (reason or "")[:500]},
        })
        path = save_graph(case_dir, graph)

    losers = [i for i in ids if i != winning_claim_id]
    results = []
    for lid in losers:
        results.append(supersede(
            case_dir, lid, winning_claim_id,
            reason=reason or f"resolved via {conflict_id}",
        ))
    return {
        "success": True,
        "conflict_id": conflict_id,
        "winning_claim_id": winning_claim_id,
        "supersede_results": results,
        "path": str(path),
    }


# ── Contradiction detection ──────────────────────────────────────────────────

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _claim_polarity(statement: str) -> str | None:
    """Return 'auth_success' | 'auth_none' | None for hard-contradiction pairs."""
    from core.auth_ontology import (
        claim_auth_none_regex,
        claim_auth_success_regex,
    )
    s = statement or ""
    has_none = bool(claim_auth_none_regex().search(s))
    has_success = bool(claim_auth_success_regex().search(s))
    # Prefer negative polarity when both match ("no successful authentication").
    if has_none:
        return "auth_none"
    if has_success:
        return "auth_success"
    return None


def _shared_context(a: dict, b: dict) -> bool:
    """True if claims share host or an IP — avoid unrelated pairings."""
    ha = (a.get("host") or "").strip().lower()
    hb = (b.get("host") or "").strip().lower()
    if ha and hb and ha == hb:
        return True
    ips_a = set(_IP_RE.findall(a.get("statement") or ""))
    ips_b = set(_IP_RE.findall(b.get("statement") or ""))
    if ips_a and ips_b and ips_a & ips_b:
        return True
    if not ha and not hb:
        return True
    return False


def _existing_conflict_covers(
    graph: dict[str, Any], id_a: str, id_b: str
) -> bool:
    for n in graph.get("nodes", {}).values():
        if n.get("kind") != "conflict":
            continue
        if n.get("status") not in ("conflict", "superseded"):
            continue
        ids = set(n.get("conflicting_claim_ids") or [])
        if id_a in ids and id_b in ids:
            return True
    return False


def detect_hard_contradictions(
    case_dir: str | os.PathLike,
    *,
    auto_create: bool = False,
) -> dict[str, Any]:
    """Find active claim pairs that contradict on authentication success.

    When auto_create=True, opens Conflict nodes for new pairs (never supersedes).
    """
    graph = load_graph(case_dir)
    claims = [n for n in list_nodes(graph, kind="claim")
              if n.get("status") in CURRENT_BELIEF_STATUSES | {"needs_review"}]
    conclusions = [n for n in list_nodes(graph, kind="conclusion")
                   if n.get("status") in CURRENT_BELIEF_STATUSES | {"needs_review"}]
    candidates = claims + conclusions

    by_polarity: dict[str, list[dict]] = {"auth_success": [], "auth_none": []}
    for n in candidates:
        pol = _claim_polarity(n.get("statement") or "")
        if pol:
            by_polarity[pol].append(n)

    pairs: list[dict[str, Any]] = []
    created: list[dict[str, Any]] = []
    for a in by_polarity["auth_success"]:
        for b in by_polarity["auth_none"]:
            if not _shared_context(a, b):
                continue
            if _existing_conflict_covers(graph, a["id"], b["id"]):
                continue
            pair = {
                "claim_a": a["id"],
                "claim_b": b["id"],
                "kind": "auth_success_vs_none",
                "statement_a": a.get("statement", "")[:200],
                "statement_b": b.get("statement", "")[:200],
            }
            pairs.append(pair)
            if auto_create:
                r = add_conflict(
                    case_dir,
                    statement=(
                        f"Contradiction: successful authentication claim "
                        f"({a['id']}) vs no-success claim ({b['id']})"
                    ),
                    claim_ids=[a["id"], b["id"]],
                    possible_explanations=[
                        "Different evidence coverage windows between runs",
                        "Log size limit / truncated Security.evtx",
                        "SIEM vs disk source mismatch",
                    ],
                    evidence_still_required=[
                        "Reconcile EVTX/SIEM coverage for the disputed window",
                    ],
                    reasoning="Auto-detected hard contradiction (auth polarity)",
                )
                if r.get("success"):
                    created.append(r)
                    graph = load_graph(case_dir)

    return {
        "success": True,
        "pairs": pairs,
        "conflicts_created": created,
        "pair_count": len(pairs),
    }


# ── Claim statement validation ───────────────────────────────────────────────

_TEMPORAL_FIRST_RE = re.compile(
    r"\b(?:first|earliest|initial)\b.{0,40}\b(?:attacker|access|activity|"
    r"logon|login|session|compromise|evidence)\b"
    r"|\b(?:first|earliest)\s+(?:evidence|activity|access)\b",
    re.IGNORECASE,
)

_TEMPORAL_QUALIFIERS = (
    "first observed activity",
    "first successful authentication",
    "first interactive session",
    "first malware execution",
    "first persistence",
    "first persistence artifact",
    "first confirmed compromise",
    "earliest successful authentication",
    "earliest interactive session",
    "earliest observed activity",
)


def validate_claim_statement(
    statement: str,
    *,
    scope: str = "host",
    temporal_qualifier: str | None = None,
    kind: str = "claim",
) -> list[str]:
    """Return validation errors (empty = ok). Used at promotion time."""
    errors: list[str] = []
    text = statement or ""

    if _NEGATIVE_COMPROMISE_RE.search(text):
        errors.append(
            "negative_compromise_wording: use "
            f"'{_PREFERRED_NEGATIVE_HINT}' instead of 'not compromised'"
        )

    if _TEMPORAL_FIRST_RE.search(text):
        tq = (temporal_qualifier or "").strip().lower()
        if not tq or not any(q in tq for q in _TEMPORAL_QUALIFIERS):
            errors.append(
                "temporal_qualifier_required: statements with first/earliest "
                "must set temporal_qualifier to an explicit meaning, e.g. "
                + ", ".join(f"'{q}'" for q in _TEMPORAL_QUALIFIERS[:4])
                + ", ..."
            )

    if scope == "host" and kind in ("claim", "conclusion") and _ESTATE_REC_RE.search(text):
        errors.append(
            "host_vs_estate_scope: host-scoped claims must not embed "
            "estate-wide recommendations (domain-wide, krbtgt, etc.). "
            "Put those in the Estate Report; soft-reference only."
        )

    return errors
