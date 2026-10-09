"""The report a stopped run still owes, written from the case directory alone.

The exit path used to build the whole report before writing a single byte: a
projection with one live model call per narrative section, each under a long
timeout, and only then the first write. A run that died anywhere inside that
window left ``reports/`` empty although every finding a deterministic report
needs was already on disk.

So the deterministic report is written FIRST, with no network at all, and the
narrative projection is only ever an upgrade over a file that already exists.
Nothing here needs a live agent, which is what lets the same function run as
``atlas write-report`` once the run's own process is gone.

The exit report is deliberately *not* an official deliverable: its filename
and its recorded source stay disjoint from the ones ``Agent._report_written``
accepts, so a run that stopped early can never read as a finished one.
"""

from __future__ import annotations

import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# The analyst's own deliverable: the report tools write these filenames and
# record these sources.
# The loop's own close-out after the report gate passed writes the same
# projection the tools write; it is the case's deliverable, not an exit
# fallback.
CLOSE_OUT_SOURCE = "close_out"
OFFICIAL_SOURCES = frozenset({
    "write_final_report",
    "write_projected_final_report",
    "misc_write_final_report",
    "misc_write_projected_final_report",
    CLOSE_OUT_SOURCE,
})
OFFICIAL_NAMES = ("estate_report.md", "final_report.md", "report.md")
OFFICIAL_NAME_PREFIXES = ("estate_report", "final_report")
_OFFICIAL_SUFFIXES = (".md", ".html", ".pdf", ".txt")

# What the exit path records instead. Disjoint from the sets above by
# construction — an exit report that passed as an official one would turn
# every killed run into an apparently-complete one.
EXIT_SOURCE_ASSEMBLED = "auto_assembled_on_exit"
EXIT_SOURCE_PROJECTED = "projected_on_exit"
EXIT_SOURCE_PROJECTED_FALLBACKS = "projected_on_exit_with_fallbacks"
EXIT_SOURCES = frozenset({EXIT_SOURCE_ASSEMBLED, EXIT_SOURCE_PROJECTED,
                          EXIT_SOURCE_PROJECTED_FALLBACKS})

# Manifest stages, in the order a report passes through them.
STAGE_DETERMINISTIC = "deterministic"
STAGE_UPGRADING = "upgrading"
STAGE_COMPLETE = "complete"
STAGE_UPGRADE_FAILED = "upgrade_failed"


def exit_report_path(case_dir: str | os.PathLike) -> Path:
    """Where the exit report goes — a case-id filename, never an official one."""
    from core.paths import detect_case_id
    root = Path(case_dir)
    case_id = detect_case_id(root) or "CASE"
    return root / "reports" / f"{case_id}_investigation_report.md"


def is_host_deliverable(path: str | os.PathLike, case_dir: str | os.PathLike | None) -> bool:
    """Whether a report path names one host's report rather than the case's."""
    try:
        from core.claim_graph import infer_report_scope
        return infer_report_scope(str(path), case_dir).get("scope") == "host"
    except Exception:  # noqa: BLE001
        return False

def official_report_exists(case_dir: str | os.PathLike) -> bool:
    """Whether an official analyst deliverable is on disk for this case.

    The case-directory half of ``Agent._report_written`` (the other half is
    the run's own tool statistics, which only a live agent has): a projection
    deliverable recorded under an official source, or an official report
    filename with more than a stub in it.
    """
    root = Path(case_dir)
    try:
        from core.report_projection import load_manifest
        man = load_manifest(root) or {}
        path = str(man.get("last_assembled_path") or "")
        if str(man.get("last_deliverable_source") or "") in OFFICIAL_SOURCES and path:
            p = Path(path)
            # A per-host report is one deliverable of several, never the
            # case's report: a run that had written one host's report and
            # still owed the estate's was read as complete, and nothing
            # asked it for the report it still owed.
            if (p.is_file() and p.stat().st_size > 64
                    and not is_host_deliverable(path, root)):
                return True
    except Exception:  # noqa: BLE001
        pass
    try:
        reports = root / "reports"
        if not reports.is_dir():
            return False
        for p in reports.iterdir():
            if not p.is_file() or p.suffix.lower() not in _OFFICIAL_SUFFIXES:
                continue
            name = p.name.lower()
            if name in OFFICIAL_NAMES or name.startswith(OFFICIAL_NAME_PREFIXES):
                if p.stat().st_size > 64:
                    return True
    except Exception:  # noqa: BLE001
        pass
    return False


def write_exit_report(case_dir: str | os.PathLike, reason: str, *,
                      allow_llm: bool, agent=None,
                      force: bool = False) -> dict[str, Any]:
    """Write the deterministic report now; upgrade it to the narrative one
    only when ``allow_llm``, and only over a file that is already on disk.

    ``agent`` is optional — when a live agent is available its own tool
    statistics also count as "a report exists", but nothing here needs one.
    """
    root = Path(case_dir)
    reason = str(reason or "ended")
    if not force and _report_already_written(root, agent):
        return {"written": False, "skipped": "official_report_exists"}

    # What the floor owes without a model: the next steps that rest on what
    # is still open, and the indicator files its Indicators section points
    # at, both written before it is assembled, as the close-out does.
    _derive_next_steps(root)
    _write_indicator_files(root)
    out = exit_report_path(root)
    out.parent.mkdir(parents=True, exist_ok=True)
    _atomic_write(out, _with_banner(_deterministic_report(root), reason,
                                    narrative=False))
    record_report_stage(root, STAGE_DETERMINISTIC, reason, path=out,
                        source=EXIT_SOURCE_ASSEMBLED)
    result: dict[str, Any] = {
        "written": True, "path": str(out), "source": EXIT_SOURCE_ASSEMBLED,
        "stage": STAGE_DETERMINISTIC, "findings": _finding_count(root),
        "upgraded": False,
    }

    if allow_llm:
        record_report_stage(root, STAGE_UPGRADING, reason)
        try:
            from core.investigation_state import project_report_from_state
            proj = project_report_from_state(
                root, regenerate_stale=True, force_regenerate_all=False,
                output_path=str(out))
            md = (proj.get("markdown") or "") if proj.get("success") else ""
            if not md.strip():
                raise RuntimeError(str(proj.get("error")
                                       or "the projection produced no text"))
            source = (EXIT_SOURCE_PROJECTED_FALLBACKS
                      if ((proj.get("regenerate") or {}).get("fallbacks") or [])
                      else EXIT_SOURCE_PROJECTED)
            _atomic_write(out, _with_banner(md, reason, narrative=True))
            record_report_stage(root, STAGE_COMPLETE, reason, path=out,
                                source=source)
            result.update(source=source, stage=STAGE_COMPLETE, upgraded=True)
        except (Exception, KeyboardInterrupt) as e:  # noqa: BLE001
            # The floor is already on disk; a failed upgrade changes nothing
            # about the file, only what the manifest says about it.
            record_report_stage(root, STAGE_UPGRADE_FAILED, reason)
            result["stage"] = STAGE_UPGRADE_FAILED
            result["upgrade_error"] = str(e)
            print(f"atlas: exit-time projection failed ({e}); keeping the "
                  "report assembled from the findings", file=sys.stderr)

    _run_report_addons(root, out)
    return result


def hosts_owed_a_report(case_dir: str | os.PathLike) -> list[str]:
    """Hosts that carry claims and have no host report yet, in the order
    the claim graph names them. Both report name forms count as written."""
    root = Path(case_dir)
    try:
        from core.claim_graph import load_graph
        nodes = list((load_graph(root).get("nodes") or {}).values())
    except Exception:  # noqa: BLE001
        return []
    hosts: list[str] = []
    for n in nodes:
        if not isinstance(n, dict) or (n.get("kind") or n.get("type")) != "claim":
            continue
        h = str(n.get("host") or "").strip()
        if h and h not in hosts:
            hosts.append(h)
    reports = root / "reports"
    if not reports.is_dir():
        return hosts

    def _written(h: str) -> bool:
        if (reports / f"host_{h}_report.md").is_file():
            return True
        return any(p.name.endswith(f"_{h}_report.md") for p in reports.glob("*_report.md"))

    return [h for h in hosts if not _written(h)]


def close_out_reports(case_dir: str | os.PathLike, *, reason: str,
                      verdict: str = "", allow_llm: bool = True) -> dict[str, Any]:
    """Write the case's reports once the report gate has passed: one for
    each host that carries claims and has none yet, then the estate
    report, each the projection of the recorded findings, with the
    narrative sections when ``allow_llm``. The estate report is written
    last so the manifest's last deliverable is the case's own. Registered
    under CLOSE_OUT_SOURCE, an official source: the projection is the
    report whether the model or the loop asks for it.
    """
    root = Path(case_dir)
    reports = root / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    _derive_next_steps(root)
    # The indicator list is a deliverable of its own, owed on this path as on
    # the tool path, and written first: the reports point at it.
    indicator_files = _write_indicator_files(root)
    targets = [(reports / f"host_{h}_report.md", h) for h in hosts_owed_a_report(root)]
    targets.append((reports / "estate_report.md", ""))
    written: list[str] = []
    errors: dict[str, str] = {}
    for path, _host in targets:
        try:
            md = _projected_report(root, path, allow_llm=allow_llm)
            _atomic_write(path, _with_closeout_note(md, reason, verdict))
            _trace_report_write(path)
            written.append(str(path))
        except Exception as e:  # noqa: BLE001 - the next report is still written
            errors[str(path)] = str(e)
            print(f"atlas: close-out could not write {path.name} ({e})",
                  file=sys.stderr)
    if written:
        last = Path(written[-1])
        record_report_stage(root, STAGE_COMPLETE, reason, path=last,
                            source=CLOSE_OUT_SOURCE)
        _run_report_addons(root, last)
    return {"written": written, "errors": errors,
            "hosts": [h for _p, h in targets if h], "source": CLOSE_OUT_SOURCE,
            "indicator_files": indicator_files}


def _derive_next_steps(root: Path) -> None:
    """Record the next investigative steps that rest on what is still open,
    before a report reads the plan. Local: no model call."""
    try:
        from core.case_config import get_report_language
        from core.recommendations import derive_next_steps
        derive_next_steps(root, get_report_language(root))
    except Exception as e:  # noqa: BLE001 - the report is written whatever the plan does
        print(f"atlas: could not derive the next steps ({e})", file=sys.stderr)


def _write_indicator_files(root: Path) -> dict[str, Any]:
    """Write reports/<CASE_ID>_iocs.md and .csv from the recorded beliefs.
    Local: no model call."""
    try:
        from core.ioc_catalog import write_indicator_files
        return write_indicator_files(root) or {}
    except Exception as e:  # noqa: BLE001 - the report is written without them
        print(f"atlas: could not write the indicator files ({e})", file=sys.stderr)
        return {}


def _projected_report(root: Path, path: Path, *, allow_llm: bool) -> str:
    """The report for ``path`` (host or estate scope from its name): the
    projection with narrative sections, or the findings-only assembly."""
    if not allow_llm:
        return _deterministic_report(root)
    from core.investigation_state import project_report_from_state
    proj = project_report_from_state(
        root, regenerate_stale=True, force_regenerate_all=False,
        output_path=str(path))
    md = (proj.get("markdown") or "") if proj.get("success") else ""
    if not md.strip():
        raise RuntimeError(str(proj.get("error") or "the projection produced no text"))
    return md


def _with_closeout_note(markdown: str, reason: str, verdict: str) -> str:
    limited = bool(re.search(r"budget wrap-up|DOCUMENTED_LIMITATIONS \([1-9]",
                             verdict or ""))
    note = (
        f"> **Closed out by Atlas ({reason}).** reason.pre_report_check "
        "returned READY_TO_REPORT: true and the reports were written from "
        "the recorded findings."
        + (" Blocking issues that could not be resolved are documented as "
           "limitations." if limited else "")
        + "\n\n"
    )
    head, sep, tail = (markdown or "").partition("\n\n")
    return f"{head}{sep}{note}{tail}" if sep else note + (markdown or "")


def _trace_report_write(path: Path) -> None:
    """A tool_call entry for the write, so the trace shows the report the
    way it shows one the tools wrote."""
    try:
        from core.execution_log import log
        log.record_tool_call(cmd=f"<py>:close_out_report {path}", success=True,
                             truncated=False, retries=0, exit_code=0)
    except Exception:  # noqa: BLE001 - an unconfigured log loses only the entry
        pass

def record_report_stage(case_dir: str | os.PathLike, stage: str, reason: str,
                        *, path: Path | None = None, source: str = "") -> None:
    """Record how far report generation got, where it survives the process.

    ``upgrading`` is written *before* the narrative attempt on purpose: a
    process killed during generation leaves that value behind, and a stale
    ``upgrading`` on a case with no live run is how a died-mid-generation
    report is told apart from a finished one.
    """
    try:
        from core.report_projection import load_manifest, save_manifest
        man = load_manifest(case_dir) or {}
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        man["report_stage"] = stage
        man["report_stage_at"] = now
        man["report_stage_reason"] = reason
        if path is not None:
            man["last_assembled_at"] = now
            man["last_assembled_path"] = str(path)
            man["last_assembled_format"] = "markdown"
        if source:
            man["last_deliverable_source"] = source
        save_manifest(case_dir, man)
    except Exception as e:  # noqa: BLE001 - the report itself is written
        print(f"atlas: could not record the report stage: {e}", file=sys.stderr)


# ── internals ───────────────────────────────────────────────────────────────

def _report_already_written(case_dir: Path, agent) -> bool:
    if agent is not None:
        try:
            return bool(agent._report_written())
        except Exception:  # noqa: BLE001 - a half-dead agent still gets a report
            pass
    return official_report_exists(case_dir)


def _deterministic_report(case_dir: Path) -> str:
    """The findings-only report, built without a single network call.

    Runs through the same Layer-4 degraded-exit policy the report tool uses,
    so the Timeline-unavailable notice and the limitation bullets are in the
    document a reader opens, not only in the manifest.
    """
    from core.investigation_exit import (
        degraded_report_decision, inject_degraded_sections,
    )
    from core.report_assemble import (
        assemble_client_report, attack_timeline_readiness,
    )
    try:
        md = assemble_client_report(case_dir)
    except Exception as e:  # noqa: BLE001
        print(f"atlas: assembling the findings failed ({e})", file=sys.stderr)
        md = ""
    try:
        ready = attack_timeline_readiness(case_dir)
    except Exception as e:  # noqa: BLE001
        ready = {"ok": False, "finding_count": 1 if md.strip() else 0,
                 "error": f"Attack Timeline readiness could not be evaluated: {e}"}
    decision = degraded_report_decision(ready)
    if decision.get("action") != "degraded_write":
        return md
    # With no findings at all the assembled skeleton reads more finished than
    # the case is; the decision's partial stub says plainly what happened.
    return inject_degraded_sections(
        "" if decision.get("minimal_body") else md, decision)


def _with_banner(markdown: str, reason: str, *, narrative: bool) -> str:
    banner = (
        f"> **Written at run end ({reason}).** The investigation stopped "
        "before the analyst closed the case; this report is the projection "
        "of the findings recorded up to that point"
        + ("" if narrative else " without the narrative sections")
        + ".\n\n"
    )
    head, sep, tail = (markdown or "").partition("\n\n")
    return f"{head}{sep}{banner}{tail}" if sep else banner + (markdown or "")


def _atomic_write(path: Path, text: str) -> None:
    """Same-directory temp file + os.replace: a reader never sees half a
    report, and a process killed mid-write leaves the previous one intact.
    The dot prefix keeps a leftover temp out of the deliverable listings."""
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def _finding_count(case_dir: Path) -> int:
    try:
        from core.claim_graph import load_graph
        nodes = (load_graph(case_dir).get("nodes") or {}).values()
        return sum(1 for x in nodes
                   if isinstance(x, dict) and x.get("kind") == "claim"
                   and x.get("status") not in ("superseded", "withdrawn"))
    except Exception:  # noqa: BLE001
        return 0


def _run_report_addons(case_dir: Path, out: Path) -> None:
    """A report written here is still a report: the addons that produce
    something alongside a report run for it too, or this path quietly
    delivers less than the tool path does."""
    try:
        from core.plugins import dispatch_event
        outcomes = dispatch_event("report_finalized", case_dir=str(case_dir),
                                  report_path=str(out))
    except Exception as exc:  # noqa: BLE001 - the report itself is written
        print(f"atlas: report addons did not run: {exc!r}", file=sys.stderr)
        return
    for o in outcomes:
        if o.get("status") == "ok":
            r = o.get("result") or {}
            print(f"atlas: addon {o['addon']} wrote "
                  f"{r.get('path') or 'its artifact'}", file=sys.stderr)
        elif o.get("status") == "disabled":
            print(f"atlas: addon {o['addon']} is disabled — no "
                  f"{o['event']} artifact", file=sys.stderr)
        else:
            print(f"atlas: addon {o.get('addon')} failed on "
                  f"{o.get('event')}: {o.get('error')}", file=sys.stderr)
