"""MCP tools for the Investigation Claim Graph (epistemic state).

Namespace: claim.*
The LLM investigates with existing forensic tools; these tools promote and
structure conclusions for auditability. They do not replace investigation.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Optional

from fastmcp import FastMCP

mcp = FastMCP("claim")


def _case_dir_or_error(case_dir: str = "") -> tuple[Optional[str], Optional[dict]]:
    from core.claim_graph import resolve_case_dir
    cd = resolve_case_dir(case_dir or None)
    if not cd:
        return None, {
            "success": False,
            "error": (
                "No case directory resolved. Start the execution log "
                "(misc.start_execution_log) or pass case_dir=."
            ),
        }
    return cd, None


def _parse_evidence(evidence_json: str = "") -> list[dict] | None:
    if not (evidence_json or "").strip():
        return None
    try:
        data = json.loads(evidence_json)
    except json.JSONDecodeError as e:
        raise ValueError(f"evidence_json must be JSON array: {e}") from e
    if not isinstance(data, list):
        raise ValueError("evidence_json must be a JSON array of objects")
    return data


@mcp.tool()
def add_observation(
    statement: str,
    evidence_json: str = "",
    confidence: str = "CONFIRMED",
    host: str = "",
    reasoning: str = "",
    case_dir: str = "",
    attrs_json: str = "",
) -> dict:
    """
    Record a single-source Observation on the claim graph (low interpretation).

    evidence_json: JSON array of {artifact, locator, call_id?} objects.
    attrs_json: optional JSON object of structured attrs (e.g. auth event_class).
    Does not replace forensic investigation — structures what you observed.
    """
    from core.claim_graph import add_observation as _add

    cd, err = _case_dir_or_error(case_dir)
    if err:
        return err
    try:
        evidence = _parse_evidence(evidence_json)
    except ValueError as e:
        return {"success": False, "error": str(e)}
    attrs = None
    if (attrs_json or "").strip():
        try:
            attrs = json.loads(attrs_json)
        except json.JSONDecodeError as e:
            return {"success": False, "error": f"attrs_json must be JSON object: {e}"}
        if not isinstance(attrs, dict):
            return {"success": False, "error": "attrs_json must be a JSON object"}
    return _add(
        cd, statement,
        confidence=confidence, evidence=evidence, host=host, reasoning=reasoning,
        attrs=attrs,
    )


@mcp.tool()
def add_claim(
    statement: str,
    confidence: str = "LIKELY",
    observation_ids: str = "",
    evidence_json: str = "",
    host: str = "",
    scope: str = "host",
    reasoning: str = "",
    gaps: str = "",
    temporal_qualifier: str = "",
    case_dir: str = "",
) -> dict:
    """
    Record a Claim derived from observations/evidence.

    observation_ids: comma-separated observation node IDs (e.g. O0001,O0002).
    gaps: semicolon-separated evidence gaps.
    temporal_qualifier: required later for first/earliest claims
      (e.g. "first successful authentication", "first interactive session").
    scope: host | estate — host reports must use host.
    """
    from core.claim_graph import add_claim as _add

    cd, err = _case_dir_or_error(case_dir)
    if err:
        return err
    try:
        evidence = _parse_evidence(evidence_json)
    except ValueError as e:
        return {"success": False, "error": str(e)}
    # A claim that says nothing a standing belief does not already say is
    # not recorded twice: the tool answers with that belief's id instead.
    try:
        from core.claim_graph import load_graph
        from tools.misc import restated_belief
        same = restated_belief(load_graph(cd).get("nodes") or {}, statement, host)
    except Exception:  # noqa: BLE001 - the check is an aid; the claim is still recorded
        same = None
    if same is not None:
        sid = str(same.get("id"))
        return {"success": True, "node_id": sid, "restates": sid,
                "existing_statement": str(same.get("statement") or "")[:200],
                "note": (f"restates {sid}; nothing was recorded. Use {sid} where you meant to "
                         f"use this claim: link it to a task part or cite it. Record a new "
                         f"claim only for something it does not say.")}
    oids = [x.strip() for x in observation_ids.split(",") if x.strip()]
    gap_list = [x.strip() for x in gaps.split(";") if x.strip()]
    return _add(
        cd, statement,
        confidence=confidence,
        observation_ids=oids or None,
        evidence=evidence,
        host=host,
        scope=scope,
        reasoning=reasoning,
        gaps=gap_list or None,
        temporal_qualifier=temporal_qualifier or None,
    )


@mcp.tool()
def add_hypothesis(
    statement: str,
    claim_ids: str = "",
    confidence: str = "SUSPECTED",
    host: str = "",
    reasoning: str = "",
    gaps: str = "",
    case_dir: str = "",
) -> dict:
    """Record a competing Hypothesis linked to one or more claims."""
    from core.claim_graph import add_hypothesis as _add

    cd, err = _case_dir_or_error(case_dir)
    if err:
        return err
    cids = [x.strip() for x in claim_ids.split(",") if x.strip()]
    gap_list = [x.strip() for x in gaps.split(";") if x.strip()]
    return _add(
        cd, statement,
        claim_ids=cids or None,
        confidence=confidence,
        host=host,
        reasoning=reasoning,
        gaps=gap_list or None,
    )


@mcp.tool()
def add_conflict(
    statement: str,
    claim_ids: str,
    possible_explanations: str = "",
    evidence_still_required: str = "",
    confidence: str = "SUSPECTED",
    host: str = "",
    reasoning: str = "",
    case_dir: str = "",
) -> dict:
    """
    Record a Conflict Finding when claims or runs disagree.

    Never silently overwrites either claim. claim_ids: comma-separated, min 2.
    possible_explanations / evidence_still_required: semicolon-separated.
    Open conflicts must appear in the main report body.
    """
    from core.claim_graph import add_conflict as _add

    cd, err = _case_dir_or_error(case_dir)
    if err:
        return err
    cids = [x.strip() for x in claim_ids.split(",") if x.strip()]
    explanations = [
        x.strip() for x in possible_explanations.split(";") if x.strip()
    ]
    required = [
        x.strip() for x in evidence_still_required.split(";") if x.strip()
    ]
    return _add(
        cd, statement,
        claim_ids=cids,
        possible_explanations=explanations or None,
        evidence_still_required=required or None,
        confidence=confidence,
        host=host,
        reasoning=reasoning,
    )


@mcp.tool()
def promote_conclusion(
    claim_id: str,
    statement: str = "",
    confidence: str = "",
    reasoning: str = "",
    gaps: str = "",
    case_dir: str = "",
) -> dict:
    """Promote an active Claim to a Conclusion after gates/reconciliation.

    `claim_id`: the claim being promoted (C0004) - the conclusion rests on
    it, so there is no separate list of basis ids. `statement`: the
    conclusion's wording; empty keeps the claim's own. `confidence`: its
    tier; empty keeps the claim's. `reasoning`: why the claim is now a
    conclusion. `gaps`: semicolon-separated open gaps.
    """
    from core.claim_graph import promote_conclusion as _promo

    cd, err = _case_dir_or_error(case_dir)
    if err:
        return err
    gap_list = [x.strip() for x in gaps.split(";") if x.strip()]
    return _promo(
        cd, claim_id,
        statement=statement or None,
        confidence=confidence or None,
        reasoning=reasoning,
        gaps=gap_list or None,
    )


@mcp.tool()
def supersede(
    old_id: str,
    new_id: str = "",
    reason: str = "",
    case_dir: str = "",
) -> dict:
    """Retire a belief. History kept; nothing is deleted.

    `old_id`: the node being retired (C0004). `new_id`: the node that
    replaces it (C0009) - the corrected or sharper claim recorded first,
    the id `record_finding` returned as `claim_id`. Leave `new_id` empty to
    withdraw the belief with no replacement: a claim the evidence cannot
    support. `reason` is then required (what was withdrawn and why). A
    retired claim no longer counts for any report gate; its trace entry
    remains for audit.
    A recommendation is never superseded: close it with update_recommendation
    (state done, with a note for a mandatory escalation).
    """
    from core.claim_graph import supersede as _sup

    cd, err = _case_dir_or_error(case_dir)
    if err:
        return err
    return _sup(cd, old_id, new_id, reason=reason)


def _iso(value) -> "datetime | None":
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


_ZERO_KEYS = ("matched_rows", "returned_rows", "hit_count")


def _found_nothing(entry: dict) -> bool:
    """A call whose result says it matched or returned nothing."""
    meta = entry.get("result_meta") or {}
    return isinstance(meta, dict) and any(meta.get(k) == 0 for k in _ZERO_KEYS)


def _names_any(text: str, names) -> bool:
    low = (text or "").casefold().replace("\\", "/")
    for name in names:
        n = str(name or "").casefold().replace("\\", "/").rstrip("/")
        if not n:
            continue
        base = n.rsplit("/", 1)[-1]
        if n in low or (base and base in low):
            return True
    return False


def _revalidation_refusal(node: dict, call_ids: list[int], log=None) -> dict | None:
    """Why a re-validation is refused, or None. The cited calls must exist
    in the trace, be evidence with recorded output rather than the run's
    own words, have found something, not predate the review that
    questioned the belief, have read what changed when the review names
    it, and show what the belief names: an identifier (the citation test
    every finding is held to) and, when the belief names artifacts, one of
    them. A belief that names neither is held to the artifacts its own
    evidence refs name."""
    from core.entities import artifact_tokens
    from tools._gates import lineage_required
    from tools._gates.citation_support import citation_supports, evidence_calls, has_output
    from tools._gates.lineage_relevance import entry_text

    if log is None:
        from core.execution_log import log as _elog
        log = _elog
    claim_id = str(node.get("id") or "")

    def refuse(why: str, **extra) -> dict:
        return {"success": False, "gate": "revalidation_citation", "claim_id": claim_id,
                "error": f"revalidation_citation: {why}", **extra}

    if node.get("status") != "needs_review":
        return refuse(f"{claim_id} is {node.get('status')}; only a belief under review "
                      "(needs_review) is re-validated")
    if not call_ids:
        return refuse("call_ids required: the _atlas_call_id values of the calls that "
                      "re-read the evidence the belief rests on")
    unknown = lineage_required.check_ids(log, call_ids)
    if unknown is not None:
        bad = unknown.get("unknown_cids") or []
        return refuse(f"call id(s) {', '.join(str(c) for c in bad) or '?'} are not in the "
                      "trace; call_ids names the calls that re-read the evidence, by their "
                      "_atlas_call_id", unknown_cids=bad)
    by_id = log.index().by_call_id
    cited = [by_id[c] for c in call_ids if c in by_id]
    evidence = [e for e in evidence_calls(cited) if has_output(e)]
    shown_ids = {e.get("call_id") for e in evidence}
    own = [c for c in call_ids if c not in shown_ids]
    if own:
        return refuse(f"call id(s) {', '.join(str(c) for c in own)} carry the run's own "
                      "words or left no output; cite the calls that read the evidence "
                      "(a query, a listing, a parse) after the change that raised the "
                      "review", call_ids=own)
    empty = [e.get("call_id") for e in evidence if _found_nothing(e)]
    if empty:
        return refuse(f"call id(s) {', '.join(str(c) for c in empty)} found nothing (0 "
                      "rows or hits): a re-read that finds nothing does not show the "
                      "belief holds. Read the evidence that carries it, or withdraw or "
                      "replace the belief with claim.supersede", call_ids=empty)
    since = _iso(node.get("invalidated_at")) or _iso(node.get("updated_at"))
    if since is not None:
        stale = [e.get("call_id") for e in evidence
                 if (_iso(e.get("ts")) or since) < since]
        if stale:
            return refuse(f"call id(s) {', '.join(str(c) for c in stale)} were made before "
                          f"the review was raised ({node.get('invalidated_at') or node.get('updated_at')}); "
                          "a re-validation cites a read of the evidence as it is now",
                          call_ids=stale)
    by = node.get("invalidated_by") or {}
    changed = list(by.get("added") or []) + list(by.get("changed") or [])
    if changed:
        texts = [entry_text(e, include_file=True) for e in evidence]
        if not any(_names_any(t, changed) for t in texts):
            listed = ", ".join(changed[:4]) + (", ..." if len(changed) > 4 else "")
            return refuse(f"the review was raised by evidence that was added or changed "
                          f"({listed}); none of the cited calls read it. Cite a call that "
                          "read one of those as it is now", changed_paths=changed[:8])
    statement = str(node.get("statement") or "")
    supports = citation_supports(statement, evidence,
                                 tool_calls=evidence_calls(list(log._entries)))
    from core.evidence_resolver import _claim_anchors
    anchors = sorted(_claim_anchors({"statement": statement}, demanding=True))
    if supports is False:
        named = (" (" + ", ".join(anchors[:6]) + ")") if anchors else ""
        return refuse("the cited output shows nothing the belief names" + named +
                      ": the evidence as it is now does not carry the belief. Withdraw "
                      "or replace it with claim.supersede, or record the corrected "
                      "statement with misc.record_finding and supersede this one with it")
    wanted = sorted(artifact_tokens(statement))
    if not wanted and not anchors:
        wanted = sorted({t for ev in (node.get("evidence") or []) if isinstance(ev, dict)
                         for t in artifact_tokens(str(ev.get("artifact") or ""))})
        if not wanted:
            return refuse("the belief names no identifier and no artifact a re-read "
                          "could show, so a re-validation cannot be judged; record the "
                          "belief again with what it rests on (misc.record_finding) and "
                          "supersede this one with it")
    if wanted:
        texts = [entry_text(e, include_file=True) for e in evidence]
        if not any(_names_any(t, wanted) for t in texts):
            return refuse("the cited output names none of the artifacts the belief rests "
                          f"on ({', '.join(wanted[:6])}): a re-read of something else "
                          "does not show the belief holds. Cite the call that read the "
                          "artifact as it is now, or withdraw or replace the belief with "
                          "claim.supersede", artifacts=wanted[:8])
    return None


@mcp.tool()
def revalidate(
    claim_id: str,
    call_ids: list[int],
    note: str = "",
    case_dir: str = "",
) -> dict:
    """A belief marked needs_review was re-checked and still holds.

    `claim_id`: the node under review (C0004, N0002). `call_ids`: the
    _atlas_call_id values of the calls that re-read the evidence it rests
    on, made after the change that raised the review; they are held to
    the citation test (the cited output must show what the belief names).
    `note`: what was compared, in a sentence. The cited calls must have
    found something, must show an identifier and an artifact the belief
    names, and must have read the evidence that raised the review when it
    names any. The belief returns to the current beliefs with the review
    kept as history; a conclusion, recommendation or dependent claim that
    went under review only through it returns once all its bases are
    current (`also_revalidated`), and a task reopened for it is answered
    again (`restored_tasks`). When the evidence no longer supports the
    belief, use `supersede` (a withdrawal, or the corrected finding
    recorded first as its replacement) instead.
    """
    from core.claim_graph import get_node, load_graph
    from core.claim_graph import revalidate as _reval

    cd, err = _case_dir_or_error(case_dir)
    if err:
        return err
    ids: list[int] = []
    for c in call_ids or []:
        try:
            ids.append(int(c))
        except (TypeError, ValueError):
            continue
    node = get_node(load_graph(cd), claim_id)
    if not node:
        return {"success": False, "error": f"unknown claim_id: {claim_id}"}
    refusal = _revalidation_refusal(node, ids)
    if refusal is not None:
        return refusal
    import os
    from core.execution_log import log as _elog
    trace = os.path.basename(str(getattr(_elog, "_path", "") or ""))
    return _reval(cd, claim_id, call_ids=ids, note=note, trace=trace)


@mcp.tool()
def resolve_conflict(
    conflict_id: str,
    winning_claim_id: str,
    reason: str = "",
    case_dir: str = "",
) -> dict:
    """Resolve a conflict: winner stays active; losers are superseded."""
    from core.claim_graph import resolve_conflict as _res

    cd, err = _case_dir_or_error(case_dir)
    if err:
        return err
    return _res(
        cd, conflict_id,
        winning_claim_id=winning_claim_id,
        reason=reason,
    )


@mcp.tool()
def detect_contradictions(
    auto_create: bool = False,
    case_dir: str = "",
) -> dict:
    """
    Scan the claim graph for hard contradictions (e.g. auth success vs no success).

    Never silently overwrites. When auto_create=true, opens Conflict Findings
    for new pairs. Always prefer explicit claim.add_conflict when you understand
    the disagreement.
    """
    from core.claim_graph import detect_hard_contradictions

    cd, err = _case_dir_or_error(case_dir)
    if err:
        return err
    return detect_hard_contradictions(cd, auto_create=auto_create)


@mcp.tool()
def snapshot(
    case_dir: str = "",
) -> dict:
    """Return active claims, conclusions, conflicts, and hypotheses for report grounding.

    This is the **Claim Graph subset** of Current Investigation State.
    Prefer misc.current_investigation_state for the full authoritative
    snapshot (memory, journal, projection staleness, findings summary).
    Pass either snapshot to the report writer so prose stays grounded.
    """
    from core.claim_graph import graph_snapshot_for_report

    cd, err = _case_dir_or_error(case_dir)
    if err:
        return err
    snap = graph_snapshot_for_report(cd)
    return {"success": True, **snap}


@mcp.tool()
def record_recommendation(
    action: str,
    phase: str,
    basis_ids: str,
    scope: str = "host",
    urgency: str = "soon",
    rationale: str = "",
    hosts: str = "",
    indicators: str = "",
    case_dir: str = "",
) -> dict:
    """Record what the responder should do, resting on named beliefs.

    `action`: one imperative sentence ("Isolate CORP-FILE01 from the network").
    `phase`: contain | eradicate | recover | harden | investigate (a next
    examination step, a preservation or legal-process request) | escalate
    (a decision handed to someone else).
    `basis_ids`: comma-separated claim/conclusion ids (C0004, N0001) this
    rests on — required. `scope`: host | network | estate; estate needs a
    basis that reaches beyond one host. `urgency`: now | soon | later.
    `hosts` / `indicators`: comma-separated. A restatement of an existing
    open recommendation is folded (`duplicate: true`), not added.
    """
    from core.claim_graph import add_recommendation

    cd, err = _case_dir_or_error(case_dir)
    if err:
        return err
    split = lambda s: [x.strip() for x in (s or "").split(",") if x.strip()]
    return add_recommendation(
        cd, action=action, phase=phase, scope=scope, urgency=urgency,
        basis_ids=split(basis_ids), source="recorded", rationale=rationale,
        hosts=split(hosts), indicators=split(indicators),
    )


@mcp.tool()
def add_indicators(
    claim_id: str,
    indicators: list[dict],
    case_dir: str = "",
) -> dict:
    """Attach typed indicators to a recorded claim or conclusion: each row
    {"type", "value", "side"} with optional "first_seen"/"last_seen", the
    same rows misc.record_finding takes. Every value must appear in the
    output of a call the claim cites; a value those outputs do not show is
    dropped and named in `dropped`. Use this when the pre-report check
    lists a finding without typed indicators, or when a finding named a
    value its rows left out."""
    from core.claim_graph import get_node, load_graph, set_claim_indicators
    from core.indicators import frame_for, validate

    cd, err = _case_dir_or_error(case_dir)
    if err:
        return err
    node = get_node(load_graph(cd), str(claim_id or "").strip())
    if not node or node.get("kind") not in ("claim", "conclusion"):
        return {"success": False, "error": f"not a claim or conclusion: {claim_id}"}
    cited = []
    if node.get("source_finding_call_id"):
        cited.append(int(node["source_finding_call_id"]))
    cited += [int(c) for c in (node.get("input_call_ids") or []) if c]
    cited += [int(e["call_id"]) for e in (node.get("evidence") or [])
              if isinstance(e, dict) and e.get("call_id")]
    checked = validate(indicators, call_ids=cited, case_dir=cd, frame=frame_for(cd))
    out = {"success": True, "claim_id": node["id"], "kept": checked["kept"],
           "dropped": checked["dropped"], "resided": checked["resided"]}
    if checked["kept"] or checked["dropped"]:
        # The refused rows stay on the claim: the indicator file lists them as
        # not exported, and a later row of the value they stood for clears them.
        r = set_claim_indicators(cd, node["id"], checked["kept"], dropped=checked["dropped"])
        if (r.get("success") and checked["kept"]
                and str(node.get("confidence") or "").upper() in ("CONFIRMED", "LIKELY")):
            # The rows the claim now carries fill the steps derived from it:
            # an open row is extended in place, a closed one gets a new row.
            try:
                from core.case_config import get_report_language
                from core.recommendations import (derive_from_claim, derive_from_finding_text,
                                                   derive_from_typed_rows)
                lang = get_report_language(cd)
                touched: list[str] = []
                for res in (derive_from_finding_text(cd, node["id"], str(node.get("statement") or ""),
                                                     host=str(node.get("host") or ""), language=lang),
                            derive_from_typed_rows(cd, node["id"], lang),
                            derive_from_claim(cd, node["id"])):
                    touched += (res.get("recorded") or []) + (res.get("folded") or [])
                if touched:
                    out["recommendations"] = sorted(set(touched))
            except Exception:  # noqa: BLE001 - the rows are attached whatever the plan does
                pass
        if not r.get("success"):
            return r
        out["indicators"] = r["indicators"]
    return out


@mcp.tool()
def update_recommendation(
    node_id: str,
    state: str,
    case_dir: str = "",
    note: str = "",
) -> dict:
    """Mark a recommendation open | done | dismissed. `note`: what was
    done; required to close a mandatory escalation, which is never
    dismissed."""
    from core.claim_graph import set_recommendation_state

    cd, err = _case_dir_or_error(case_dir)
    if err:
        return err
    return set_recommendation_state(cd, node_id, state, actor="investigation", note=note)


@mcp.tool()
def list_recommendations(case_dir: str = "") -> dict:
    """The current response plan, ordered: open first, then urgency, then
    how strong the basis is. Each item names the beliefs it rests on."""
    from core.recommendations import build_catalog

    cd, err = _case_dir_or_error(case_dir)
    if err:
        return err
    catalog = build_catalog(cd)
    return {"success": True, "total": catalog["total"], "open": catalog["open"],
            "open_now": catalog["open_now"],
            "recommendations": [
                {k: r[k] for k in ("id", "action", "phase", "scope", "urgency",
                                   "state", "source", "basis_confidence",
                                   "basis_ids" if "basis_ids" in r else "basis")}
                for r in catalog["recommendations"]]}

