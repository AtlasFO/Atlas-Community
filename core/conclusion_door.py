"""The conclusion door (ATLAS_CONCLUSION_DOOR): one conclusion resting on
named, recorded beliefs.

A conclusion is recorded through ``promote`` only. It names its basis (the
claims, conclusions or Atlas-written observations it rests on); every name
it states must stand in a basis; its statement passes the record-time gates
that judge a statement (unless it keeps the words of one recorded claim,
whose verdicts it then carries); an absence covers only the hosts its bases'
complete reads reached; and its tier is never stronger than its weakest
basis. The bound is stored on the node and re-applied on every load
(core.claim_graph._normalize_graph), so every reader sees the bounded tier.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Iterable, Optional

from core.envfile import env_flag

TIER_RANK = {"UNCONFIRMED": 1, "SUSPECTED": 2, "LIKELY": 3, "CONFIRMED": 4}
REVIEW_CAP = "LIKELY"
_ID_RE = re.compile(r"[A-Z]\d{4,6}")


def door_on() -> bool:
    return env_flag("ATLAS_CONCLUSION_DOOR", True)


def _weaker(a: str, b: str) -> str:
    return a if TIER_RANK.get(a, 0) <= TIER_RANK.get(b, 0) else b


# ── the bound, applied on every load and save ────────────────────────────

def _successor(nodes: dict, nid: str) -> tuple[Optional[dict], str]:
    """The current node a basis id stands for, following supersession
    (cycle-safe), and its id; (None, id) for an unknown id."""
    seen: set[str] = set()
    cur = nid
    while cur and cur not in seen:
        seen.add(cur)
        node = nodes.get(cur)
        if not isinstance(node, dict):
            return None, cur
        nxt = str(node.get("superseded_by") or "")
        if node.get("status") == "superseded" and nxt and nxt != cur:
            cur = nxt
            continue
        return node, cur
    return nodes.get(cur), cur


def basis_tier(nodes: dict, basis_ids: Iterable[str]) -> tuple[str, str]:
    """(weakest tier, the id that sets it) over a basis; a withdrawn or
    unknown basis counts as UNCONFIRMED."""
    worst, by = "CONFIRMED", ""
    for b in basis_ids:
        node, cur = _successor(nodes, str(b))
        tier = ("UNCONFIRMED" if node is None or node.get("status") == "withdrawn"
                else str(node.get("confidence") or "UNCONFIRMED").upper())
        if TIER_RANK.get(tier, 0) < TIER_RANK.get(worst, 0):
            worst, by = tier, cur
    return worst, by


def apply_bounds(nodes: dict) -> None:
    """Bound every conclusion with a basis at its weakest basis and its
    review cap; a legacy conclusion promoted from one claim gets that claim
    as its basis. A kept-words conclusion reports its basis's citation
    status."""
    if not door_on():
        return
    # A conclusion may rest on another conclusion that comes later in node
    # order; passes repeat until no tier moves, so a chain is bounded on
    # this load, not the next one. Each pass can only lower a tier, so the
    # number of passes is bounded by the chain's length.
    for _ in range(len(nodes) + 1):
        before = [n.get("confidence") for n in nodes.values() if isinstance(n, dict)]
        _bound_pass(nodes)
        if before == [n.get("confidence") for n in nodes.values() if isinstance(n, dict)]:
            return


def _bound_pass(nodes: dict) -> None:
    for node in nodes.values():
        if not isinstance(node, dict) or node.get("kind") != "conclusion":
            continue
        if not node.get("basis_ids") and node.get("promoted_from_claim_id"):
            node["basis_ids"] = [str(node["promoted_from_claim_id"])]
            node.setdefault("requested_confidence", str(node.get("confidence") or "").upper())
        basis = [str(b) for b in node.get("basis_ids") or []]
        if not basis:
            continue
        requested = str(node.get("requested_confidence") or node.get("confidence") or "LIKELY").upper()
        node["requested_confidence"] = requested
        worst, by = basis_tier(nodes, basis)
        bound = _weaker(requested, worst)
        cap = str(node.get("review_cap") or "").upper()
        if cap:
            bound = _weaker(bound, cap)
        node["confidence"] = bound
        if bound != requested:
            node["tier_bound"] = {"by": by if bound == worst else "review", "tier": bound}
        else:
            node.pop("tier_bound", None)
        if node.get("kept_words") and len(basis) == 1:
            src, _cur = _successor(nodes, basis[0])
            if isinstance(src, dict) and src.get("citation_status"):
                node["citation_status"] = src["citation_status"]


def basis_changed(graph: dict, old_id: str, new_id: str = "") -> None:
    """A basis superseded or withdrawn: each conclusion resting on it rests
    on the successor; a withdrawn basis, or a kept-words basis replaced by
    different words, puts the conclusion under review (the model re-promotes
    from the successor or rewrites)."""
    if not door_on():
        return
    nodes = graph.get("nodes") or {}
    old = nodes.get(old_id) or {}
    new = nodes.get(new_id) or {} if new_id else {}
    for node in nodes.values():
        if not isinstance(node, dict) or node.get("kind") != "conclusion" \
                or old_id not in (node.get("basis_ids") or []):
            continue
        if node.get("status") in ("superseded", "withdrawn"):
            continue
        if not new_id:
            node["status"] = "needs_review"
            node["review_reason"] = f"basis {old_id} withdrawn"
            continue
        node["basis_ids"] = list(dict.fromkeys(new_id if b == old_id else b for b in node["basis_ids"]))
        node["basis_carried_from"] = list(dict.fromkeys([*(node.get("basis_carried_from") or []), old_id]))
        if node.get("kept_words") and _norm(new.get("statement")) != _norm(old.get("statement")):
            node["status"] = "needs_review"
            node["review_reason"] = f"basis {old_id} revised"


def _norm(text: Any) -> str:
    return " ".join(str(text or "").split()).casefold()


def kept_words_basis(node: dict, nodes: dict) -> Optional[dict]:
    """The one claim basis whose words a conclusion keeps, else None."""
    basis = [str(b) for b in node.get("basis_ids") or []]
    if len(basis) != 1:
        return None
    src = nodes.get(basis[0])
    if isinstance(src, dict) and src.get("kind") == "claim" and _norm(src.get("statement")) == _norm(
            node.get("statement")):
        return src
    return None


# ── the door ─────────────────────────────────────────────────────────────

def _split_ids(value: str) -> list[str]:
    return list(dict.fromkeys(m.group(0) for m in _ID_RE.finditer(str(value or "").upper())))


def _int_call(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _basis_objection(nid: str, node: Optional[dict], nodes: dict) -> str:
    from core.claim_graph import CURRENT_BELIEF_STATUSES
    if not node:
        return f"{nid} is not a node of this case"
    status = node.get("status")
    if status == "superseded":
        succ, cur = _successor(nodes, nid)
        return f"{nid} was superseded by {cur}: use {cur}" if succ is not None and cur != nid \
            else f"{nid} is superseded"
    if status not in CURRENT_BELIEF_STATUSES | {"needs_review"}:
        return f"{nid} is {status}: a conclusion rests on current beliefs only"
    kind = node.get("kind")
    if kind == "claim":
        if not node.get("source_finding_call_id"):
            return (f"{nid} has no cited tool call (it was not recorded with misc.record_finding): record it "
                    "with misc.record_finding, then use the new claim id")
        return ""
    if kind == "conclusion":
        return ""
    if kind == "observation":
        if any(isinstance(e, dict) and _int_call(e.get("call_id")) for e in node.get("evidence") or []):
            return ""
        return f"{nid} is an observation no tool call stands behind: rest the conclusion on a recorded claim"
    return f"{nid} is a {kind}: a conclusion rests on claims, conclusions or observations"


def _pool_texts(node: dict) -> list[str]:
    out = [str(node.get("statement") or "")]
    for e in node.get("evidence") or []:
        if isinstance(e, dict):
            out += [str(e.get("artifact") or ""), str(e.get("locator") or "")]
    for r in node.get("indicators") or []:
        if isinstance(r, dict) and r.get("value"):
            out.append(str(r["value"]))
    return out


def _lexicon(case_dir, nodes: dict) -> frozenset[str]:
    """The case lexicon (the accounts and hosts of the current beliefs)
    with the case's hosts: a plain word here is a name the bases must
    state."""
    out: set[str] = set()
    try:
        from core.answer_synthesis import case_name_lexicon
        out |= case_name_lexicon({"nodes": nodes})
    except Exception:  # noqa: BLE001
        pass
    try:
        from core.forensic_citation import known_case_hosts
        out |= {h.lower() for h in known_case_hosts(case_dir)}
    except Exception:  # noqa: BLE001
        pass
    return frozenset(out)


def _as_written(value: str, statement: str) -> str:
    """A name in the conclusion's own spelling (the pool compares a
    normalised form)."""
    m = re.search(re.escape(value), statement, re.I)
    return m.group(0) if m else value


def _unstated_objection(statement: str, basis_nodes: list[dict], nodes: dict, case_dir, log) -> tuple[str, list]:
    """The names the conclusion states that no basis states, with the
    claims that state each and, for a name no claim states, the calls whose
    rows show it."""
    from core.entities import NamePool, unstated
    lex = _lexicon(case_dir, nodes)
    pool = NamePool.from_texts(t for n in basis_nodes for t in _pool_texts(n))
    missing = unstated(statement, pool, lex)
    if not missing:
        return "", []
    from core.claim_graph import CURRENT_BELIEF_STATUSES
    basis_ids = {n.get("id") for n in basis_nodes}
    others = [(nid, NamePool.from_texts(_pool_texts(n))) for nid, n in nodes.items()
              if isinstance(n, dict) and n.get("kind") in ("claim", "conclusion") and nid not in basis_ids
              and n.get("status") in CURRENT_BELIEF_STATUSES | {"needs_review"}]
    entries = list(getattr(log, "_entries", None) or []) if log is not None else []
    rows, parts = [], []
    said: set[str] = set()
    for name in missing:
        value = _as_written(name.split("=", 1)[1] if "=" in name else name, statement)
        if value.casefold() in said:      # one value under two of the pool's keys
            continue
        said.add(value.casefold())
        claims = sorted(nid for nid, p in others if p.covers(name))
        calls: list[int] = []
        if not claims and entries:
            try:
                from tools._gates.citation_support import locate
                calls = locate(value, entries, limit=3, case_dir=case_dir)
            except Exception:  # noqa: BLE001
                calls = []
        rows.append({"value": value, "claims": claims, "calls": calls})
        if claims:
            parts.append(f"{value}: add {' or '.join(claims[:4])} to basis_ids")
        elif calls:
            parts.append(f"{value}: no claim states it; call{'s' if len(calls) > 1 else ''} "
                         f"{' and '.join(str(c) for c in calls)} show{'' if len(calls) > 1 else 's'} it, so record a finding citing "
                         f"{'one of them' if len(calls) > 1 else 'it'} and add the new claim id, or leave it out")
        else:
            parts.append(f"{value}: no claim states it and no call in the trace shows it: leave it out")
    head = "The conclusion names " + ", ".join(r["value"] for r in rows) + ", which no basis claim states. "
    return head + "; ".join(parts) + ".", rows


def _case_hosts(case_dir) -> list[str]:
    try:
        from core.forensic_citation import known_case_hosts
        return list(dict.fromkeys(known_case_hosts(case_dir)))
    except Exception:  # noqa: BLE001
        return []


def _expanded(basis_nodes: list[dict], nodes: dict) -> list[dict]:
    """The bases with each conclusion basis's own bases (transitively): a
    conclusion carries no analyst calls, its bases' searches are its reads."""
    out, seen, todo = [], set(), list(basis_nodes)
    while todo:
        n = todo.pop(0)
        if id(n) in seen:
            continue
        seen.add(id(n))
        out.append(n)
        if n.get("kind") == "conclusion":
            for b in n.get("basis_ids") or []:
                sub, _cur = _successor(nodes, str(b))
                if isinstance(sub, dict):
                    todo.append(sub)
    return out


def _hosts_read(basis_nodes: list[dict], log, case_dir, nodes: Optional[dict] = None) -> set[str]:
    """The case hosts the bases' analyst-cited complete evidence calls read
    (the host of each evidence path through the Evidence Links); never a
    label and never the hosts a statement names."""
    from core.forensic_citation import citation_class
    from tools._gates.citation_support import complete_view, has_output
    try:
        from core.provenance import call_provenance
    except Exception:  # noqa: BLE001
        return set()
    idx = log.index().by_call_id if log is not None else {}
    out: set[str] = set()
    for n in _expanded(basis_nodes, nodes or {}):
        cids = [int(c) for c in (n.get("analyst_call_ids") or n.get("input_call_ids") or []) if c]
        cids += [int(e["call_id"]) for e in n.get("evidence") or []
                 if isinstance(e, dict) and _int_call(e.get("call_id"))]
        for cid in dict.fromkeys(cids):
            entry = idx.get(cid)
            if not isinstance(entry, dict) or entry.get("type") != "tool_call":
                continue
            if citation_class(entry) != "evidence" or not has_output(entry) or not complete_view(entry):
                continue
            try:
                out |= {h.casefold() for h in call_provenance(entry, case_dir)["hosts"]}
            except Exception:  # noqa: BLE001
                pass
            # A call over a multi-host export or a copy: the hosts the
            # contents index says its rows or its copy came from.
            try:
                from core.contents_index import hosts_covered, index_on
                if index_on():
                    out |= {h.casefold() for h in hosts_covered(case_dir, cid, entry)}
            except Exception:  # noqa: BLE001
                pass
    return out


def _absence_objections(statement: str, basis_nodes: list[dict], log, case_dir,
                        nodes: Optional[dict] = None) -> list[str]:
    """An absence sentence covers the hosts it names, or every case host
    when it names none; the bases' complete reads must have reached them.
    A prescription is exempt (one definition, is_prescription)."""
    from tools._gates.universal_from_truncated import _P_ABSENCE_RE, _universal_sentences, is_prescription
    from core.forensic_citation import host_mentioned
    hosts = _case_hosts(case_dir)
    out = []
    read = None
    for sentence in _universal_sentences(statement):
        if not _P_ABSENCE_RE.search(sentence) or is_prescription(sentence):
            continue
        named = [h for h in hosts if host_mentioned(h, sentence)]
        need = named or hosts
        if not need:
            continue
        read = _hosts_read(basis_nodes, log, case_dir, nodes) if read is None else read
        missing = [h for h in need if h.casefold() not in read]
        if not missing:
            continue
        reached = sorted(h for h in hosts if h.casefold() in read)
        if named:
            out.append(f"'{sentence}' states an absence on {', '.join(named)}; its basis read "
                       f"{len(reached)}" + (f": {', '.join(reached)}" if reached else "")
                       + f". Rest it on claims whose searches read {', '.join(missing)}, or leave "
                       f"{'that host' if len(missing) == 1 else 'those hosts'} out")
        else:
            out.append(f"'{sentence}' states an absence without naming the hosts it covers, so it covers all "
                       f"{len(hosts)} hosts of the case; its basis read {len(reached)}"
                       + (f": {', '.join(reached)}" if reached else "")
                       + ". Name the hosts it holds for, or add basis claims whose searches read the others")
    return out


def absence_scope_missing(node: dict, need_text: str, case_dir) -> list[str]:
    """The case hosts a question's scope needs that an absence belief does
    not cover (the absence scope rule above, applied to a belief that answers
    a yes/no part "no"). The scope is the hosts ``need_text`` names, or every
    case host when it names none. The belief covers the hosts its absence
    sentences name; with none named, the host it was recorded on (a
    host-scoped claim), else every case host. Empty when the case lists no
    hosts."""
    from tools._gates.universal_from_truncated import _P_ABSENCE_RE, _universal_sentences, is_prescription
    from core.forensic_citation import host_mentioned
    hosts = _case_hosts(case_dir)
    if not hosts:
        return []
    need = [h for h in hosts if host_mentioned(h, need_text or "")] or hosts
    statement = str(node.get("statement") or "")
    sentences = [x for x in _universal_sentences(statement)
                 if _P_ABSENCE_RE.search(x) and not is_prescription(x)] or [statement]
    covered = {h for h in hosts if any(host_mentioned(h, x) for x in sentences)}
    if not covered:
        own = str(node.get("host") or "")
        covered = ({h for h in hosts if h.casefold() == own.casefold()}
                   if own and node.get("scope") != "estate" else set(hosts))
    return [h for h in need if h not in covered]


_VERDICT_RE = re.compile(r"VERDICT\W{0,12}(SUPPORTED|CHALLENGED|UNCERTAIN)", re.I)


def _evaluated(statement: str, log) -> bool:
    """A SUPPORTED reason.evaluate_finding of this statement exists."""
    if log is None:
        return False
    from tools._gates._match import find_reason_call, normalize_desc
    entry = find_reason_call(list(getattr(log, "_entries", None) or []), "reason_evaluate_finding",
                             normalize_desc(statement))
    if entry is None:
        return False
    m = _VERDICT_RE.search(str(entry.get("conclusion") or ""))
    return bool(m and m.group(1).upper() == "SUPPORTED")


def _statement_gates(statement: str, tier: str, basis_nodes: list[dict], log) -> list[dict]:
    """The record-time gates that judge a statement, on a conclusion
    context built from the bases. Plumbing and finding-shape gates and the
    evidence-strength contract are not run (the tier is bounded instead).
    Prescription sentences are left out of the universal gate's text."""
    from tools._gates import GateContext, contracts, quoted_text_grounding, universal_from_truncated
    from tools._gates.mitre_technique_validation import check as mitre_check
    cited, analyst, located, support = [], [], [], []
    for n in basis_nodes:
        cited += [int(c) for c in n.get("input_call_ids") or [] if c]
        cited += [int(c) for c in n.get("located_call_ids") or [] if c]
        analyst += [int(c) for c in n.get("analyst_call_ids") or [] if c]
        located += [int(c) for c in n.get("located_call_ids") or [] if c]
        support += [str(e.get("locator") or "") for e in n.get("evidence") or []
                    if isinstance(e, dict) and e.get("artifact") == "supporting_evidence"]
    host = next((str(n.get("host") or "") for n in basis_nodes if n.get("host")), "")

    def ctx_for(text: str):
        return GateContext(
            description=text, confidence=tier, tier=tier, source="conclusion", linked_call_id=0,
            tested_hypothesis_id="", log=log, idx=log.index(), window=log.last_n_window(30),
            reason_window=log.gate_window(30), input_call_ids=list(dict.fromkeys(cited)),
            analyst_call_ids=list(dict.fromkeys(analyst)), located_call_ids=list(dict.fromkeys(located)),
            supporting_evidence="\n".join(s for s in support if s), host=host)
    from tools._gates.universal_from_truncated import _universal_sentences, is_prescription
    prescriptions = [s for s in _universal_sentences(statement) if is_prescription(s)]
    universal_text = statement
    for s in prescriptions:
        universal_text = universal_text.replace(s, " ")
    out: list[dict] = []
    if universal_text.strip():
        hit = universal_from_truncated.check(ctx_for(universal_text))
        if hit:
            out.append(hit)
    ctx = ctx_for(statement)
    for check in (quoted_text_grounding.check, mitre_check):
        hit = check(ctx)
        if hit:
            out.append(hit)
    for name in ("completeness", "attribution", "transfer"):
        out += contracts.failures(name, ctx)
    return out


def promote(case_dir, *, basis_ids: str = "", statement: str = "", confidence: str = "", reasoning: str = "",
            gaps: Optional[list[str]] = None, supersedes: str = "", claim_id: str = "", log=None) -> dict[str, Any]:
    """Record a conclusion through the door: every objection at once, or
    the conclusion at its bounded tier."""
    from core.claim_graph import add_node, load_graph, supersede
    graph = load_graph(case_dir)
    nodes = graph.get("nodes") or {}
    basis = _split_ids(basis_ids)
    revise = _split_ids(supersedes)[:1]
    for cid in _split_ids(claim_id):
        node = nodes.get(cid) or {}
        if node.get("kind") == "conclusion" and not revise:
            revise = [cid]        # a conclusion id in claim_id: a revision
        elif cid not in basis:
            basis.append(cid)     # a claim id there: a single basis
    objections: list[str] = []
    old = None
    if revise:
        old = nodes.get(revise[0])
        if not isinstance(old, dict) or old.get("kind") != "conclusion":
            objections.append(f"supersedes={revise[0]} names no conclusion of this case")
            old = None
        elif old.get("status") in ("superseded", "withdrawn"):
            objections.append(f"{revise[0]} is already {old.get('status')}")
        elif not basis:
            basis = [str(b) for b in old.get("basis_ids") or []]
    if not basis:
        objections.append("basis_ids is empty: name the claims the conclusion rests on (C0004,C0009)")
    basis_nodes = []
    for b in basis:
        node = nodes.get(b)
        why = _basis_objection(b, node, nodes)
        if why:
            objections.append(why)
        elif node is not None:
            basis_nodes.append(node)
    statement = " ".join(str(statement or "").split())
    if not statement:
        if len(basis_nodes) == 1:
            statement = str(basis_nodes[0].get("statement") or "")
        elif basis:
            objections.append("a conclusion over several bases needs its own statement")
    if objections:
        return {"success": False, "gate": "conclusion_basis", "error": "; ".join(objections) + "."}
    requested = str(confidence or "").upper().strip()
    worst, by = basis_tier(nodes, basis)
    if requested not in TIER_RANK:
        requested = worst
    kept = (len(basis_nodes) == 1 and basis_nodes[0].get("kind") == "claim"
            and _norm(basis_nodes[0].get("statement")) == _norm(statement))
    names, unbacked = _unstated_objection(statement, basis_nodes, nodes, case_dir, log)
    refusals: list[dict] = []
    if names:
        refusals.append({"success": False, "gate": "conclusion_basis", "error": names, "unbacked": unbacked})
    for why in _absence_objections(statement, basis_nodes, log, case_dir, nodes):
        refusals.append({"success": False, "gate": "conclusion_scope", "error": why})
    cap = ""
    if not kept:
        cap = "" if _evaluated(statement, log) else REVIEW_CAP
        if log is not None:
            bound_for_gates = _weaker(_weaker(requested, worst), cap or "CONFIRMED")
            refusals += _statement_gates(statement, bound_for_gates, basis_nodes, log)
    if refusals:
        # Every objection at once, so one corrected call can clear them all.
        out = {"success": False, "gate": refusals[0].get("gate") or "conclusion_basis",
               "error": " ".join(str(r.get("error") or "").strip() for r in refusals if r.get("error"))}
        if unbacked:
            out["unbacked"] = unbacked
        if len(refusals) > 1:
            out["gates"] = [r.get("gate") for r in refusals]
        return out
    bound = _weaker(_weaker(requested, worst), cap or "CONFIRMED")
    evidence, seen = [], set()
    for n in basis_nodes:
        for e in n.get("evidence") or []:
            key = repr(sorted(e.items())) if isinstance(e, dict) else repr(e)
            if key not in seen:
                seen.add(key)
                evidence.append(e)
    first = basis_nodes[0]
    extra = {"basis_ids": basis, "requested_confidence": requested, "kept_words": kept}
    if cap:
        extra["review_cap"] = cap
    if revise:
        extra["supersedes"] = revise[0]
    if kept and first.get("citation_status"):
        extra["citation_status"] = first["citation_status"]
    res = add_node(case_dir, kind="conclusion", statement=statement, confidence=bound,
                   host=str(first.get("host") or ""), scope=str(first.get("scope") or "host"),
                   evidence=evidence, reasoning=reasoning or str(first.get("reasoning") or ""),
                   gaps=gaps, temporal_qualifier=first.get("temporal_qualifier"),
                   parent_ids=basis, edge_type="derived_from", extra=extra)
    if not res.get("success"):
        return res
    nid = res.get("node_id")
    if revise and nid:
        supersede(case_dir, revise[0], nid, reason="revised through the conclusion door")
    out = {"success": True, "node_id": nid, "kind": "conclusion", "confidence": bound, "basis_ids": basis}
    if bound != requested:
        if TIER_RANK[worst] <= TIER_RANK.get(cap or "CONFIRMED", 4):
            out["note"] = (f"recorded at {bound}: a conclusion is no stronger than its weakest basis "
                           f"({by} is {worst}).")
        else:
            out["note"] = (f"recorded at {bound}: its words are not one basis claim's own, and no "
                           "reason.evaluate_finding of this statement found it SUPPORTED.")
    if revise:
        out["supersedes"] = revise[0]
    return out
