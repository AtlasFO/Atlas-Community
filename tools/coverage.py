"""Detection coverage report.

`coverage_report()` walks the trace at end-of-investigation and emits a
checklist of TTPs checked, TTPs found (positive), TTPs deliberately skipped
(in a DAIR recommended_action but never executed), and TTPs that fall under
the case's relevant tactics but were never touched ("gaps").

The point: most autonomous IR agents only report positives. Pairing positive
findings with explicit negative + coverage data yields a richer, more honest
accuracy artifact.
"""
from __future__ import annotations
import re
from fastmcp import FastMCP

from core import output_safe

mcp = FastMCP("coverage")

_TID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def _extract_tids(text: str) -> set[str]:
    return set(_TID_RE.findall(text or ""))


def _format_markdown(checked, found, skipped, gaps, summary) -> str:
    def _bullet(tids):
        if not tids:
            return "  - _(none)_"
        return "\n".join(f"  - `{t}`" for t in sorted(tids))

    lines = [
        "# Detection Coverage Report",
        "",
        f"**Summary:** {summary}",
        "",
        f"## Checked ({len(checked)})",
        "TTPs that appeared in at least one finding (any tier).",
        _bullet(checked),
        "",
        f"## Found ({len(found)})",
        "TTPs in CONFIRMED or LIKELY findings.",
        _bullet(found),
        "",
        f"## Deliberately skipped ({len(skipped)})",
        "TTPs surfaced in a DAIR `recommended_actions` but never produced "
        "a downstream tool_call. Document the rationale for each.",
        _bullet(skipped),
        "",
        f"## Untouched gaps ({len(gaps)})",
        "TTPs in the MITRE table matching case-relevant tactics but never "
        "checked. Consider sweeping these in a follow-up Scan phase.",
        _bullet(sorted(gaps)[:40]) + ("\n  - …" if len(gaps) > 40 else ""),
    ]
    return "\n".join(lines) + "\n"


@mcp.tool()
@output_safe
def coverage_report(relevant_tactics: str = "") -> dict:
    """
    Emit a TTP coverage checklist over the current trace.

    relevant_tactics: optional comma-separated tactic names to scope the "gaps"
        calculation. If omitted, all tactics in the MITRE table are considered.
        Examples: "Credential Access, Lateral Movement, Persistence".

    Returns: {success, checked, found, skipped, gaps, summary, markdown,
              _atlas_call_id}.
    """
    from core.execution_log import log
    from tools.mitre import load_techniques

    idx = log.index()
    findings = idx.by_type.get("finding", [])
    dair_calls = idx.by_type.get("dair_call", [])
    tool_calls = idx.by_type.get("tool_call", [])

    # Checked: any T-ID appearing in a finding's description OR stamped on the
    # finding as a gate-validated technique (record_finding's mitre_techniques
    # channel). Reading only the description missed techniques the analyst
    # mapped structurally — the reason four consecutive runs reported 0 TTPs
    # despite mapping techniques via correlate.mitre_map.
    def _finding_tids(f: dict) -> set[str]:
        tids = set(_extract_tids(f.get("description", "")))
        for vt in (f.get("validated_techniques") or []):
            tid = (vt.get("technique_id") if isinstance(vt, dict) else vt) or ""
            if tid:
                tids.add(str(tid).upper())
        return tids

    checked: set[str] = set()
    found: set[str] = set()
    found_confident: set[str] = set()
    for f in findings:
        tids = _finding_tids(f)
        checked.update(tids)
        # Breadth counts techniques on ANY tier — tier states confidence in
        # the interpretation, not whether the technique was observed. An
        # honestly under-tiered run must not read as "no TTP
        # coverage". The CONFIRMED/LIKELY subset is still reported separately.
        found.update(tids)
        if (f.get("confidence") or "").upper() in {"CONFIRMED", "LIKELY"}:
            found_confident.update(tids)

    # Skipped: T-IDs recommended by DAIR but never executed as a tool_call.
    # Heuristic: a tool name in recommended_actions that maps to no tool_call
    # AFTER the dair_call that suggested it. T-IDs cited in recommended_actions
    # text count as "skipped" if never appearing in any subsequent finding.
    skipped: set[str] = set()
    seen_after: dict[str, int] = {}  # tid → call_id at which it first appears in checked
    for f in findings:
        cid = int(f.get("call_id") or 0)
        for tid in _finding_tids(f):
            if tid not in seen_after or cid < seen_after[tid]:
                seen_after[tid] = cid

    for d in dair_calls:
        d_cid = int(d.get("call_id") or 0)
        rec_actions = d.get("recommended_actions") or []
        text_blob = " ".join(str(a) for a in rec_actions)
        for tid in _extract_tids(text_blob):
            # Skipped iff: T-ID was recommended here but never appears in any
            # later checked entry.
            if tid not in seen_after or seen_after[tid] < d_cid:
                skipped.add(tid)

    # Gaps: T-IDs in MITRE table matching relevant tactics but never checked.
    techniques = (load_techniques().get("techniques") or {})
    if relevant_tactics:
        rt = {t.strip().lower() for t in relevant_tactics.split(",") if t.strip()}
        in_scope = {
            tid for tid, info in techniques.items()
            if any(t.lower() in (info.get("tactic") or "").lower() for t in rt)
        }
    else:
        in_scope = set(techniques.keys())

    gaps = in_scope - checked

    # Per-finding mapping status — the actionable, case-blind coverage view.
    # A fraction of the 762-technique table is the wrong target for a
    # single-host case; what matters is (a) every attack-shaped
    # CONFIRMED/LIKELY finding carries >=1 technique and (b) mapped
    # techniques show breadth relative to the run's own finding count.
    # Same vocabulary/thresholds as the pre_report gates (tools/reasoning).
    from tools.reasoning import (TTP_MIN_TACTICS, TTP_MIN_TECHNIQUES,
                                 TTP_UNMAPPED_BLOCK, finding_tactics,
                                 is_attack_finding)
    attack_findings = [f for f in findings if is_attack_finding(f)]
    unmapped = [f for f in attack_findings if not _finding_tids(f)]
    finding_mapping = {
        "attack_findings": len(attack_findings),
        "mapped": len(attack_findings) - len(unmapped),
        "unmapped_call_ids": sorted(int(f.get("call_id") or 0)
                                    for f in unmapped),
    }

    tactics: set[str] = set()
    for f in findings:
        tactics |= finding_tactics(f)
        for tid in _finding_tids(f):
            for part in str((techniques.get(tid) or {}).get("tactic")
                            or "").split(","):
                part = part.strip().lower().replace("-", " ")
                if part:
                    tactics.add(part)

    want_tids = min(TTP_MIN_TECHNIQUES, len(attack_findings)) \
        if attack_findings else 0
    targets = {
        "unmapped_tolerated": TTP_UNMAPPED_BLOCK,
        "min_techniques": want_tids,
        "min_tactics": TTP_MIN_TACTICS if attack_findings else 0,
        "meets_mapping": len(unmapped) <= TTP_UNMAPPED_BLOCK,
        "meets_breadth": (not attack_findings
                          or (len(found) >= want_tids
                              and len(tactics) >= TTP_MIN_TACTICS)),
    }

    # When no finding is attack-shaped, the breadth target is 0/0 and passes
    # vacuously. Say so explicitly: on ICS / memory-CTF / pure-artifact cases
    # this is correct leniency (the enterprise ATT&CK matrix has no applicable
    # technique), NOT a passed TTP gate — the reviewer must not read "0/0 met"
    # as evidence of coverage discipline.
    breadth_note = (
        " — no attack-shaped findings, so TTP breadth is NOT APPLICABLE to this "
        "case (not a satisfied coverage target)"
        if not attack_findings else "")
    summary = (
        f"{finding_mapping['mapped']}/{finding_mapping['attack_findings']} "
        f"attack-shaped findings mapped "
        f"({len(unmapped)} unmapped, {TTP_UNMAPPED_BLOCK} tolerated); "
        f"{len(found)} distinct technique(s) across {len(tactics)} tactic(s) "
        f"on findings of any tier ({len(found_confident)} on CONFIRMED/LIKELY) "
        f"(breadth target ≥{want_tids}/≥{targets['min_tactics']}{breadth_note}); "
        f"{len(checked)} TTPs checked in total, {len(skipped)} skipped, "
        f"{len(gaps)} untouched in scope."
    )

    markdown = _format_markdown(
        sorted(checked), sorted(found), sorted(skipped), gaps, summary
    )

    return {
        "success": True,
        "checked": sorted(checked),
        "found": sorted(found),
        "skipped": sorted(skipped),
        "gaps": sorted(gaps),
        "finding_mapping": finding_mapping,
        "distinct_techniques": len(found),
        "distinct_tactics": len(tactics),
        "targets": targets,
        "summary": summary,
        "markdown": markdown,
        "scope_techniques": len(in_scope),
        "table_size": len(techniques),
    }


# ── Evidence coverage ledger ─────────────────────────────
# The ledger of high-value evidence units gates degraded exit
# (core.coverage_ledger). Before these tools the agent was TOLD to "mark
# blocked units" by the stall nudges but had no verb for it, and could not
# even see the ledger — coverage_report above is the MITRE/TTP view, a
# different concept.


def _ledger_case_dir() -> str | None:
    try:
        from core.execution_log import log
        return log.case_dir()
    except Exception:
        return None


@mcp.tool()
@output_safe
def ledger_status() -> dict:
    """
    Evidence coverage ledger status: which high-value evidence units the exit
    floor tracks, their statuses (unseen | probed | answered | blocked), and
    the unseen gaps that block degraded exit / force-report.

    Use this when a stall nudge reports open coverage, before close-out, or
    to decide what to probe next. This is the EVIDENCE ledger — for the
    MITRE/TTP checklist use coverage.coverage_report.

    Returns: {success, stats, unseen, units, ready_for_degraded_exit}.
    """
    case_dir = _ledger_case_dir()
    if not case_dir:
        return {"success": False,
                "error": "no active case (start_execution_log first)"}
    from core.coverage_ledger import (
        coverage_stats, load_ledger, open_unit_paths, ready_for_degraded_exit,
    )
    ledger = load_ledger(case_dir)
    units = [
        {"path": u.get("path"), "status": u.get("status"),
         "kind": u.get("kind"), "reason": u.get("reason"),
         "note": u.get("note") or ""}
        for u in (ledger.get("units") or {}).values()
        if isinstance(u, dict)
    ]
    return {
        "success": True,
        "stats": coverage_stats(ledger),
        "unseen": open_unit_paths(case_dir, limit=20),
        "units": sorted(units, key=lambda u: (u["status"], u["path"] or "")),
        "ready_for_degraded_exit": bool(ready_for_degraded_exit(case_dir)),
    }


@mcp.tool()
@output_safe
def mark_blocked(path: str, reason: str) -> dict:
    """
    Mark ONE coverage-ledger unit as blocked with an auditable reason —
    e.g. the file is corrupt, empty, unparseable, or its media class is
    absent. Blocked counts toward the exit floor, so this is guarded: the
    trace must contain at least one real tool call that targeted the path
    (successful or failed). Attempt a probe first; blocked documents a
    failed attempt, it does not replace one.

    path: case-relative evidence path as shown by coverage.ledger_status
        (e.g. "evidence/WS02/.../Security.evtx"), or a delivered evidence
        item the pre-report check names as not read (a capture, an
        archive, a folder); an item a call has read is not blocked.
    reason: what was attempted and why the unit cannot be examined.

    Returns: {success, unit} or {success:false, error}.
    """
    case_dir = _ledger_case_dir()
    if not case_dir:
        return {"success": False,
                "error": "no active case (start_execution_log first)"}
    from core.coverage_ledger import mark_unit_blocked, mark_work_order_blocked
    result = mark_unit_blocked(case_dir, path, reason=reason)
    if not result.get("success") and "no coverage-ledger unit matches" in str(result.get("error") or ""):
        # The access workflow's work orders (winevt/Security on an opened
        # disk) are not ledger units; without this every route to closing
        # one was refused and the completeness gate could never clear
        #
        wo = mark_work_order_blocked(case_dir, path, reason=reason)
        if wo.get("success"):
            return wo
    # Non-disk containers that incorrectly entered mount_plan must not keep
    # blocking Access Stage / READY — settle or drop them when blocked.
    try:
        from core.artifact_kind import is_non_disk_container
        from core.mount_plan import (
            load_mount_plan,
            mark_image_access_failed,
            save_mount_plan,
        )
        if is_non_disk_container(path):
            mark_image_access_failed(
                case_dir,
                path,
                error=(reason or "non_disk_artifact")[:400],
                tool="coverage.mark_blocked",
            )
            plan = load_mount_plan(case_dir)
            images = [
                img for img in (plan.get("images") or [])
                if not (
                    isinstance(img, dict)
                    and is_non_disk_container(str(img.get("path") or ""))
                )
            ]
            if len(images) != len(plan.get("images") or []):
                plan["images"] = images
                save_mount_plan(case_dir, plan)
            if isinstance(result, dict):
                result["non_disk_media_settled"] = True
    except Exception:
        pass
    return result
