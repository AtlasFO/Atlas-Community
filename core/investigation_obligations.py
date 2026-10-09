"""Critical investigation obligations — CASE×profile must-touch set.

Obligations gate ``complete`` (not degraded exit). Task soft floor may unlock
degraded/incomplete paths; it must not declare complete while critical
artifacts were never searched.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Optional

from core.auth_ontology import case_session_auth_intent_regex

# Generic session/auth intent language only — never case principals, host
# stereotypes, or VPN product names.
# EID list comes from core.auth_ontology, not a hand-copied literal — a
# prior hardcoded copy here was silently missing 4778 (RDP reconnect /
# interactive session presence), found via
# tests/core/test_auth_ontology_consolidation.py's drift check.
_AUTH_SESSION_RE = case_session_auth_intent_regex()

from core.eventlog_layout import LAYOUTS as _EVENTLOG_LAYOUTS

# The Security log of either event-log layout, as a ledger unit path.
_SECURITY_UNIT_RE = re.compile(
    "(?i)" + "|".join(re.escape(l.security_log) for l in _EVENTLOG_LAYOUTS))


def _case_root(case_dir: str | os.PathLike | None) -> Optional[Path]:
    if not case_dir:
        return None
    try:
        return Path(case_dir).resolve()
    except Exception:
        return None


def _case_text(root: Path) -> str:
    bits: list[str] = []
    for name in ("CASE.md", "case.md"):
        p = root / name
        if p.is_file():
            try:
                bits.append(p.read_text(encoding="utf-8", errors="replace")[:20000])
            except Exception:
                pass
    try:
        from core.investigation_tasks import list_tasks
        for t in list_tasks(root) or []:
            if isinstance(t, dict):
                bits.append(str(t.get("text") or t.get("title") or "")[:500])
    except Exception:
        pass
    return "\n".join(bits)


def case_needs_windows_session_auth(case_dir: str | os.PathLike | None) -> bool:
    root = _case_root(case_dir)
    if root is None:
        return False
    return bool(_AUTH_SESSION_RE.search(_case_text(root)))


def _load_trace_tool_blobs(root: Path) -> list[str]:
    """Collect tool cmd / mcp_tool strings from the case trace (best-effort)."""
    analysis = root / "analysis"
    if not analysis.is_dir():
        return []
    out: list[str] = []
    # Atlas writes <CASE>_trace.json (agent/cli.py, core/execution_log.py).
    # This globbed *.jsonl only, so it always returned nothing and every
    # trace-derived obligation silently evaluated against an empty trace
    #. Both suffixes are accepted now.
    traces = sorted(analysis.glob("*_trace.json")) + sorted(
        analysis.glob("*_trace.jsonl"))
    for p in traces[-2:]:
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for row in _iter_trace_rows(text):
            e = row.get("entry") if isinstance(row.get("entry"), dict) else row
            if not isinstance(e, dict):
                continue
            if e.get("type") not in ("tool_call", None) and not e.get("cmd"):
                # still allow mcp tools stamped without type
                if not (e.get("mcp_tool") or e.get("tool")):
                    continue
            blob = " ".join(
                str(e.get(k) or "")
                for k in ("cmd", "mcp_tool", "tool", "args")
            )
            if blob.strip():
                out.append(blob)
    return out


def _iter_trace_rows(text: str):
    """Trace entries from either shape Atlas may have written.

    ``<CASE>_trace.json`` is a whole JSON document (an array of entries, or
    an object with an ``entries`` list); the older sidecar form is JSON
    Lines. Reading a .json document line-by-line yields nothing but parse
    errors, which is how an always-empty trace went unnoticed here.
    """
    stripped = (text or "").lstrip()
    if stripped[:1] in ("[", "{"):
        try:
            doc = json.loads(stripped)
        except Exception:  # noqa: BLE001
            doc = None
        if isinstance(doc, list):
            for row in doc:
                if isinstance(row, dict):
                    yield row
            return
        if isinstance(doc, dict):
            entries = doc.get("entries")
            if isinstance(entries, list):
                for row in entries:
                    if isinstance(row, dict):
                        yield row
                return
            yield doc
            return
    for line in (text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except Exception:  # noqa: BLE001
            continue
        if isinstance(row, dict):
            yield row


def _security_ledger_units(root: Path) -> list[dict[str, Any]]:
    try:
        from core.coverage_ledger import load_ledger
        units = (load_ledger(root).get("units") or {}).values()
    except Exception:
        return []
    out = []
    for u in units:
        if not isinstance(u, dict):
            continue
        path = str(u.get("path") or "")
        if _SECURITY_UNIT_RE.search(path):
            out.append(u)
    return out


def list_obligations(case_dir: str | os.PathLike | None) -> list[dict[str, Any]]:
    """Return obligation descriptors with ``met`` flags."""
    root = _case_root(case_dir)
    if root is None:
        return []
    items: list[dict[str, Any]] = []
    needs_auth = case_needs_windows_session_auth(root)
    try:
        from core.evidence_access import (
            media_entries,
            pending_media_open,
            profile_has_disk,
            winevt_search_attempted_in_cmds,
        )
        has_disk = profile_has_disk(root)
        entries = media_entries(root)
        pending = pending_media_open(root)
        opened = any(e.get("access_stage") == "opened" for e in entries)
    except Exception:
        has_disk, entries, pending, opened = False, [], [], False
        winevt_search_attempted_in_cmds = lambda _c: False  # type: ignore

    sec_units = _security_ledger_units(root)
    if needs_auth and (has_disk or sec_units):
        if sec_units:
            unmet_paths = [
                str(u.get("path"))
                for u in sec_units
                if str(u.get("status") or "") not in ("answered", "blocked")
            ]
            items.append({
                "id": "winevt_security_unit",
                "kind": "ledger_unit",
                "met": not unmet_paths,
                "detail": (
                    "Security event log ledger unit(s) must be answered or blocked "
                    f"(not merely probed). unmet={unmet_paths[:6]}"
                ),
            })
        elif has_disk and (opened or not pending):
            # Disk opened (or no pending) but no Security unit on ledger —
            # require an actual search of the Security log (either event-log
            # layout) before complete.
            blobs = _load_trace_tool_blobs(root)
            cmds = [{"cmd": b} for b in blobs]
            searched = winevt_search_attempted_in_cmds(cmds)
            items.append({
                "id": "winevt_security_search",
                "kind": "search",
                "met": bool(searched),
                "detail": (
                    "Disk media present/opened but the Windows Security event "
                    "log was never searched in the trace."
                    if not searched else
                    "Security event log search observed in trace."
                ),
            })
        elif has_disk and pending:
            # Access stage still pending — complete already blocked by access;
            # still surface obligation as unmet for diagnostics.
            items.append({
                "id": "winevt_security_search",
                "kind": "search",
                "met": False,
                "detail": (
                    "Disk media still pending open — open image then search "
                    "the Security event log before complete."
                ),
            })

    items.extend(_event_log_obligations(root))
    items.extend(_ioc_pivot_obligations(root))
    items.extend(_artifact_value_obligations(root))
    items.extend(_source_set_obligations(root))
    return items


def _source_set_obligations(root: Path) -> list[dict[str, Any]]:
    """A conclusion drawn from part of an evidence series is a conclusion
    about that part only (core/source_sets.py)."""
    try:
        from core.source_sets import partially_examined_series
        partial = partially_examined_series(root)
    except Exception:  # noqa: BLE001
        return []
    if not partial:
        return []
    return [{
        "id": "evidence_sets_complete",
        "kind": "coverage",
        "met": False,
        "detail": (
            f"{len(partial)} evidence series only partly examined: "
            + ", ".join(
                f"{s['directory']}/{s['pattern']} "
                f"({s['examined']}/{s['total']})" for s in partial[:5])
        ),
    }]


def _artifact_value_obligations(root: Path) -> list[dict[str, Any]]:
    """Two duties an analyst owes the evidence, from core/artifact_value.py.

    * The highest-value artifacts the case knows about must be read before
      the case is called complete. Reading whatever a listing happened to
      show first is triage by accident.
    * A belief may not assert an artifact is absent when the case's own
      index lists it — that is a false finding, and one that suppresses
      further work on exactly the evidence that mattered.
    """
    out: list[dict[str, Any]] = []
    try:
        from core.artifact_value import (
            contradicted_absence_claims, unexamined_high_value,
        )
    except Exception:  # noqa: BLE001
        return out

    try:
        clashes = contradicted_absence_claims(root)
    except Exception:  # noqa: BLE001
        clashes = []
    if clashes:
        out.append({
            "id": "absence_claims_supported",
            "kind": "contradiction",
            "met": False,
            "detail": (
                f"{len(clashes)} belief(s) assert an artifact is absent that "
                "this case's own index lists: "
                + ", ".join(
                    f"{c['claim_id']}→{c['artifact']}" for c in clashes[:6])
            ),
        })

    try:
        unread = unexamined_high_value(root)
    except Exception:  # noqa: BLE001
        unread = []
    if unread:
        out.append({
            "id": "high_value_artifacts_examined",
            "kind": "analysis",
            "met": False,
            "detail": (
                f"{len(unread)} high-value artifact(s) present and never "
                "opened: "
                + ", ".join(f"{a['name']}({a['score']})" for a in unread[:6])
            ),
        })
    return out


def _event_log_obligations(root: Path) -> list[dict[str, Any]]:
    """Event logs present in the case must actually be analysed.

    The Security.evtx obligations above only engage when the *case wording*
    implies session/auth intent (``case_needs_windows_session_auth``). That
    made an entirely basic duty conditional on how the question happened to
    be phrased: a run could hold event logs, never parse them, and still be
    called complete. Availability is what creates the duty —
    if event-log evidence exists, it gets analysed, whatever the case asks.
    """
    try:
        from core.artifact_value import (
            HIGH_VALUE_THRESHOLD, artifact_score, looks_empty,
        )
        from core.ioc_pivots import evidence_sources
        sources = evidence_sources(root)
    except Exception:  # noqa: BLE001
        return []

    # Every event-log channel is *not* a duty. A Windows host ships ~160 of
    # them; many are header-only (nothing written) and few carry the
    # answers. Demanding all of them made
    # this obligation unsatisfiable, which would have pinned every real run
    # at incomplete_coverage forever — the same useless signal as the
    # always-complete bug, inverted.
    #
    # The duty is the logs an analyst would actually be negligent to skip:
    # non-empty, and high-value under the shared value model. That keeps one
    # definition of "worth reading" across the obligations.
    logs: list[str] = []
    for rel, classes in sorted(sources.items()):
        if "eventlog" not in classes:
            continue
        name = rel.replace("\\", "/").rsplit("/", 1)[-1]
        try:
            size = (root / rel).stat().st_size
        except OSError:
            size = None
        if looks_empty(name, size):
            continue
        if artifact_score(name, size)[0] >= HIGH_VALUE_THRESHOLD:
            logs.append(rel)
    if not logs:
        return []

    blobs = " ".join(_load_trace_tool_blobs(root)).lower()
    unanalysed = [
        rel for rel in logs
        if rel.lower() not in blobs
        and rel.replace("\\", "/").rsplit("/", 1)[-1].lower() not in blobs
    ]
    return [{
        "id": "event_logs_analysed",
        "kind": "analysis",
        "met": not unanalysed,
        "detail": (
            f"{len(unanalysed)} of {len(logs)} high-value event log(s) never "
            f"appear in the trace: "
            f"{[r.rsplit('/', 1)[-1] for r in unanalysed[:6]]}"
            if unanalysed else
            f"all {len(logs)} high-value event log(s) analysed"
        ),
    }]


def _ioc_pivot_obligations(root: Path) -> list[dict[str, Any]]:
    """Indicators found mid-run, and those the analyst named, must be
    carried across the evidence.

    See core/ioc_pivots.py — a belief that names an IP, account or host
    creates a search obligation against the relevant sources the case
    actually holds, including other hosts' material; so does an indicator
    in the brief's prior knowledge.
    """
    try:
        from core.ioc_pivots import _ANALYST_ORIGIN, open_pivots
        pending = open_pivots(root)
    except Exception:  # noqa: BLE001
        return []
    if not pending:
        return []
    preview = [f"{p['ioc']} ({len(p['pending'])} source(s))"
               for p in pending[:6]]
    named = sum(1 for p in pending if p.get("origin") == _ANALYST_ORIGIN)
    return [{
        "id": "ioc_pivots_closed",
        "kind": "pivot",
        "met": False,
        "detail": (
            f"{len(pending)} indicator(s) not yet searched for across "
            "relevant evidence"
            + (f" ({named} named by the analyst in CASE.md; judge a hit "
               "against their statement)" if named else "")
            + f": {preview}"
        ),
    }]


def obligations_met_for_complete(case_dir: str | os.PathLike | None) -> bool:
    items = list_obligations(case_dir)
    if not items:
        return True
    return all(bool(i.get("met")) for i in items)


def unmet_obligation_summaries(
    case_dir: str | os.PathLike | None,
) -> list[str]:
    return [
        f"{i.get('id')}: {i.get('detail')}"
        for i in list_obligations(case_dir)
        if not i.get("met")
    ]
