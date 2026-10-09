"""Evidence-assessment latch — understand evidence before forensic tools.

Global contract (every case):
  1. What evidence is present / absent (classes + layout)?
  2. How can it be processed — or does it need processing at all?
  3. Are finished/parsed artifacts already on disk? If yes, use those.
  4. Only then may forensic parsers / mounts / hunters run.

Plane A's class profile alone is not enough — the agent must call
``misc_inventory_evidence`` which stamps this latch and returns a
deterministic processing assessment. Soft prompt text is not a substitute.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

SCHEMA_VERSION = "1.1"

# ONLY meta / discovery tools before assessment is complete.
# No dair, reason.*, hash, mounts, parsers — those consume or direct
# evidence work and must wait for the assessment answers.
INVENTORY_GATE_ALLOWLIST = frozenset({
    "misc_start_execution_log",
    "misc_export_execution_log",
    "misc_record_agent_message",
    "misc_record_self_correction",
    "misc_serve_dashboard",
    "misc_list_evidence_dir",  # discovery aid during assessment; does NOT stamp
    "misc_inventory_evidence",
    "misc_current_investigation_state",
    "misc_update_investigation_task",
    "brain_consult",
    "brain_search_notes",
    # Graders / accuracy may read GT after a run without re-inventory.
    "accuracy_accuracy_compare",
    "accuracy_accuracy_score",
    "atlas_load_namespaces",
    "atlas_finish",
})


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def inventory_path(case_dir: str | os.PathLike) -> Path:
    return Path(case_dir).resolve() / ".atlas" / "evidence_inventory.json"


def inventory_satisfied(case_dir: Optional[str]) -> bool:
    if not case_dir:
        return True  # fail-open without an active case
    # Non-path values (e.g. MagicMock in unit tests that patch the log) must
    # not spuriously engage the latch.
    if not isinstance(case_dir, (str, os.PathLike)):
        return True
    path = inventory_path(case_dir)
    if not path.is_file():
        return False
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    return bool(data.get("complete"))


def mark_inventory_complete(
    case_dir: str | os.PathLike,
    *,
    summary: Optional[dict[str, Any]] = None,
    assessment: Optional[dict[str, Any]] = None,
    source: str = "misc_inventory_evidence",
) -> Path:
    """Stamp the latch. ``assessment`` is the full deterministic processing
    assessment (already_processed / needs_processing / skip) — persist it:
    coverage_ledger and discovery_first read ``inventory["assessment"]`` from
    disk. Before only the summary was written and every
    consumer silently fell back to profile heuristics."""
    root = Path(case_dir).resolve()
    path = inventory_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": SCHEMA_VERSION,
        "case_id": root.name,
        "complete": True,
        "updated_at": _utcnow(),
        "source": source,
        "summary": summary or {},
        "assessment": assessment or {},
    }
    path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return path


def clear_inventory_stamp(case_dir: str | os.PathLike) -> None:
    path = inventory_path(case_dir)
    try:
        if path.is_file():
            path.unlink()
    except OSError:
        pass


def inventory_gate_refusal(tool_name: str) -> str:
    return (
        f"evidence-assessment gate: tool '{tool_name}' blocked until "
        f"misc_inventory_evidence has answered: what exists, what is already "
        f"parsed, what still needs processing, and what to skip. Call "
        f"misc_inventory_evidence now (list_evidence_dir may help explore, "
        f"but does not unlock forensic tools)."
    )


# ── Deterministic processing assessment (class-based, not tool-named) ─────

# Tokens that indicate an already-parsed export (matches profile indexer).
_PARSED_TOKENS = (
    "regripper", "mft", "usn", "usnjrnl", "evtx", "hayabusa", "chainsaw",
    "amcache", "timeline", "appcompat", "prefetch", "srum",
)

# Absent-class → tool-family skip hints (namespaces / families, not one tool).
_ABSENT_SKIP: dict[str, str] = {
    "disk": "No disk image — do not use image/volume openers (ewf/tsk/img/plaso).",
    "memory": "No memory image — do not use volatility / memory hunters.",
    "pcap": "No packet capture — do not use pcap/network dissectors.",
    "windows_eventlog": "No EVTX — do not run event-log path parsers "
                        "(parsed CSV event exports may still exist as tabular).",
    "email": "No email stores — skip mail extractors.",
    "live": "No live endpoint — skip live.*",
}
# Artifact classes a disk image holds as well as a package delivers them
# loose: with an image present, their absence as loose files says nothing
# about whether the case holds them.
_INSIDE_DISK_CLASSES = frozenset({"windows_eventlog", "email"})
_INSIDE_DISK_SKIP = ("Not delivered as loose files; the disk images may hold "
                     "them — open an image to find out.")


def _path_has_parsed_token(path: str) -> bool:
    low = (path or "").casefold().replace("\\", "/")
    return any(tok in low for tok in _PARSED_TOKENS)


def build_processing_assessment(
    *,
    present: list[str] | set[str],
    absent: list[str],
    counts: dict[str, Any],
    high_value_parsed: list[str],
    samples_by_class: dict[str, list[str]],
    top_level: Optional[list[dict[str, Any]]] = None,
    file_count: int = 0,
    ambiguous: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Build the evidence reference map + processing strategy.

    The catalog is what Atlas can fall back on — not a mandate to open every
    file. Relevance to case questions / incident time window decides depth.
    Out-of-window or unrelated items may be deferred; they stay listed so
    the agent can return to them later. Preference (parsed before re-parse)
    is processing order only.
    """
    present_set = set(present)
    parsed = list(high_value_parsed or [])
    has_parsed = bool(parsed)
    top = list(top_level or [])

    # 1) What exists — full tree is indexed; returned lists are the map
    what_exists = {
        "files_indexed": int(file_count or 0),
        "present_classes": sorted(present_set),
        "absent_classes": list(absent),
        "counts": counts or {},
        "sample_paths": {
            cls: list(paths)[:5]
            for cls, paths in (samples_by_class or {}).items()
        },
        "note": (
            "The full evidence/ tree was indexed into classes/counts. "
            "Lists below are the working catalog to draw from — not a "
            "requirement to deep-analyze every file."
        ),
    }

    # Reference catalog (top-level map — know what you can fall back to)
    available: list[dict[str, Any]] = []
    for entry in top:
        item: dict[str, Any] = {
            "path": entry.get("path") or entry.get("name"),
            "is_dir": bool(entry.get("is_dir")),
            "role": "catalog_entry",
        }
        if entry.get("class"):
            item["class"] = entry["class"]
        if entry.get("child_count") is not None:
            item["child_count"] = entry["child_count"]
            item["note"] = (
                "Directory — list when this area becomes relevant; "
                "children stay available via list_evidence_dir."
            )
        available.append(item)

    catalog = {
        "policy": (
            "This is the evidence REFERENCE MAP — what exists and what you "
            "can fall back on. Analyze what is relevant to the case "
            "questions and incident time window. Items wholly outside the "
            "window (e.g. VPN logs with no overlap to the attack period) "
            "or clearly unrelated may be deferred without deep analysis; "
            "keep them on the list for later. Do not invent paths that are "
            "not in the catalog. Do not claim evidence is missing when it "
            "is listed here or under already_processed / class samples."
        ),
        "files_indexed": int(file_count or 0),
        "top_level": available,
        "top_level_count": len(available),
        "class_counts": dict(counts or {}),
        "relevance_scoping": [
            "Select evidence by case questions + time window — not by "
            "opening every file.",
            "Defer out-of-window / unrelated items with a short reason; "
            "they remain available if pivots need them later.",
            "Prefer already_processed exports when they cover an artifact "
            "family; re-parse raw sources only for a proven gap.",
            "skip[] is only for ABSENT media classes (no memory → no vol), "
            "never for present files you chose not to deep-dive yet.",
        ],
    }

    # 2+3) Processing strategy (order)
    already_processed = {
        "available": has_parsed,
        "paths": parsed,
        "what_to_do": (
            "Primary fallbacks for common artifact families — query/read "
            "these finished exports when relevant. Do NOT re-run path "
            "parsers on their raw sources unless you prove a coverage gap."
            if has_parsed else
            "No high-value parsed exports indexed — list directories and "
            "use class samples when those areas become relevant."
        ),
    }

    reparse_not_required: list[dict[str, Any]] = []
    needs_processing: list[dict[str, Any]] = []

    if "tabular" in present_set:
        tabular_samples = list((samples_by_class or {}).get("tabular") or [])[:8]
        reparse_not_required.append({
            "class": "tabular",
            "meaning": "Already tabular — query when relevant; do not re-parse.",
            "reason": (
                f"{(counts or {}).get('tabular', '?')} tabular file(s) "
                "indexed (VPN/EDR/firewall CSVs, parser exports, …). "
                "Pull matching rows via table.table_query / table.table_grep. "
                "NEVER pass these paths to ez.ez_evtxecmd, EvtxECmd, RECmd, "
                "or AmcacheParser — wrong input kind."
            ),
            "count": (counts or {}).get("tabular"),
            "example_tabular": tabular_samples,
            "forbidden_tools": [
                "ez.ez_evtxecmd", "ez.ez_recmd_hive", "ez.ez_amcacheparser",
            ],
        })

    if has_parsed:
        reparse_not_required.append({
            "class": "parsed_exports",
            "meaning": "Finished exports ready to query when relevant.",
            "reason": (
                f"{len(parsed)} finished export(s) indexed as fallbacks."
            ),
            "count": len(parsed),
        })

    if "windows_eventlog" in present_set:
        evtx_parsed = [p for p in parsed if _path_has_parsed_token(p)
                       and any(t in p.casefold()
                               for t in ("evtx", "hayabusa", "chainsaw"))]
        if evtx_parsed:
            reparse_not_required.append({
                "class": "windows_eventlog",
                "meaning": "Prefer parsed event exports when event logs matter.",
                "reason": (
                    "Parsed event-log exports present — use those when "
                    "relevant; re-parse raw EVTX only for a proven gap."
                ),
                "example_parsed": evtx_parsed[:5],
                "raw_count": (counts or {}).get("windows_eventlog"),
            })
        else:
            raw_evtx = [
                p for p in list((samples_by_class or {}).get(
                    "windows_eventlog") or [])
                if str(p).casefold().endswith(".evtx")
                or str(p).rstrip("/\\").casefold().endswith("winevt/logs")
                or "/winevt/" in str(p).replace("\\", "/").casefold()
            ][:5]
            needs_processing.append({
                "class": "windows_eventlog",
                "reason": (
                    "Raw EVTX present and no parsed event export indexed — "
                    "when event logs are relevant, pass a real .evtx file "
                    "(or winevt/Logs dir) to ez.ez_evtxecmd. Do NOT pass "
                    "tabular samples (*.csv under evidence/) — those are "
                    "already-parsed exports for table.* only."
                ),
                "sample_raw": raw_evtx or list((samples_by_class or {}).get(
                    "windows_eventlog") or [])[:5],
                "do_not_use_as_evtx_input": list(
                    (samples_by_class or {}).get("tabular") or [])[:5],
            })

    if "file" in present_set:
        file_parsed = [p for p in parsed if _path_has_parsed_token(p)]
        if file_parsed:
            reparse_not_required.append({
                "class": "file",
                "meaning": "Prefer finished exports; raw extracts stay on the map.",
                "reason": (
                    f"{(counts or {}).get('file', '?')} loose/extract file(s) "
                    "indexed. Use matching finished exports when that family "
                    "is relevant; list dirs from the catalog as needed."
                ),
                "example_parsed": file_parsed[:8],
                "raw_count": (counts or {}).get("file"),
            })
        else:
            needs_processing.append({
                "class": "file",
                "reason": (
                    "Loose files/extracts present without indexed parsed "
                    "exports — path parsers may be required after listing "
                    "real basenames when that area is relevant."
                ),
                "sample_raw": list((samples_by_class or {}).get("file") or [])[:5],
            })

    if "disk" in present_set:
        needs_processing.append({
            "class": "disk",
            "reason": (
                "Disk image present — mount/open when case questions need "
                "image-level access not covered by extracts."
            ),
            "sample_raw": list((samples_by_class or {}).get("disk") or [])[:5],
        })

    if "memory" in present_set:
        unsure = list(ambiguous or [])
        # A raw image with no signature is a memory image only perhaps: say
        # which files those are, so a memory tool is neither forbidden nor
        # promised.
        reason = ("Memory image present — use when memory analysis is relevant."
                  if (counts or {}).get("memory") or not unsure else "")
        if unsure:
            reason = (reason + " " if reason else "") + (
                "Raw image(s) with no recognised disk or memory signature: "
                + ", ".join(unsure[:5]) + (" and more" if len(unsure) > 5 else "")
                + "; a memory tool (vol.*) or a disk tool (tsk.*) reading one "
                "settles which it is.")
        needs_processing.append({
            "class": "memory",
            "reason": reason,
            "sample_raw": list((samples_by_class or {}).get("memory") or [])[:5],
        })

    if "pcap" in present_set:
        needs_processing.append({
            "class": "pcap",
            "reason": "PCAP present — use when network capture analysis is relevant.",
            "sample_raw": list((samples_by_class or {}).get("pcap") or [])[:5],
        })

    if "email" in present_set:
        needs_processing.append({
            "class": "email",
            "reason": "Email stores present — use when mail analysis is relevant.",
            "sample_raw": list((samples_by_class or {}).get("email") or [])[:5],
        })

    skip = [
        {
            "class": cls,
            "reason": _INSIDE_DISK_SKIP,
            "meaning": "Not loose in the package; possibly inside the disk images.",
        } if cls in _INSIDE_DISK_CLASSES and "disk" in present_set else {
            "class": cls,
            "reason": _ABSENT_SKIP[cls],
            "meaning": "Tool family unavailable — media class not in the package.",
        }
        for cls in absent
        if cls in _ABSENT_SKIP
    ]

    first_actions: list[str] = [
        "Use catalog.top_level + already_processed as the evidence map "
        "you can fall back on.",
        "Scope deep analysis by case questions and time window — defer "
        "out-of-window / unrelated items (they stay on the list).",
    ]
    if has_parsed:
        first_actions.append(
            "When an artifact family is relevant, start from "
            "already_processed.paths (query/read); do not re-parse raw "
            "sources without a proven gap."
        )
    if "tabular" in present_set:
        first_actions.append(
            "Pull relevant tabular rows via table.* only "
            "(table.table_query / table.table_grep). Never feed tabular "
            "samples to EvtxECmd/RECmd/AmcacheParser."
        )
    first_actions.append(
        "Before any path parser: misc_list_evidence_dir on the parent — "
        "never invent basenames."
    )
    if needs_processing:
        first_actions.append(
            "Address needs_processing only when those classes become "
            "relevant and parsed exports do not cover the question."
        )
    if skip:
        first_actions.append(
            "Respect skip[] for ABSENT media — do not invent missing "
            "disk/memory/pcap."
        )

    return {
        "what_exists": what_exists,
        "catalog": catalog,
        # Back-compat alias used in earlier prompts/tests
        "coverage": catalog,
        "already_processed": already_processed,
        "no_processing_needed": reparse_not_required,
        "reparse_not_required": reparse_not_required,
        "needs_processing": needs_processing,
        "skip": skip,
        "recommended_first_actions": first_actions,
        "rule": (
            "Forensic tools unlock after this assessment. "
            "Catalog = reference map to draw from. "
            "Relevance/time-window scopes depth. "
            "Prefer already_processed over re-parse. "
            "Skip only absent media."
        ),
    }


def build_evidence_inventory(case_dir: str | os.PathLike) -> dict[str, Any]:
    """Run the mandatory evidence assessment and stamp the latch."""
    root = Path(case_dir).resolve()
    evidence = root / "evidence"
    if not evidence.is_dir():
        return {
            "success": False,
            "error": f"no evidence/ directory under {root}",
        }

    from core.evidence_profile import (
        classify_path,
        declared_kinds,
        ensure_evidence_profile,
        high_value_tabular_index,
        present_class_set,
    )

    profile = ensure_evidence_profile(root, refresh=True)
    declared = declared_kinds(root)
    present = sorted(present_class_set(profile))
    absent = list(profile.get("absent_classes") or [])
    samples = profile.get("samples") or {}
    counts = profile.get("counts") or {}
    file_count = int(profile.get("file_count") or 0)
    high_value = high_value_tabular_index(profile, limit=25)
    # Case-root tabular files (VPN/EDR CSVs) are finished exports even when
    # they lack MFTECmd/Hayabusa path tokens — keep them on already_processed.
    for name in sorted(os.listdir(evidence)):
        if name.startswith("."):
            continue
        full = evidence / name
        if full.is_file() and classify_path(full, declared.get(f"evidence/{name}", "")) == "tabular":
            rel = f"evidence/{name}"
            if rel not in high_value:
                high_value.append(rel)
    high_value = high_value[:40]

    top: list[dict[str, Any]] = []
    for name in sorted(os.listdir(evidence)):
        if name.startswith("."):
            continue
        full = evidence / name
        entry: dict[str, Any] = {
            "name": name,
            "path": f"evidence/{name}",
            "is_dir": full.is_dir(),
        }
        if full.is_file():
            try:
                entry["size"] = full.stat().st_size
                entry["class"] = classify_path(full, declared.get(f"evidence/{name}", ""))
            except OSError:
                pass
        else:
            try:
                kids = [c.name for c in sorted(full.iterdir())
                        if not c.name.startswith(".")]
            except OSError:
                kids = []
            entry["child_names"] = kids[:40]
            entry["child_count"] = len(kids)
            if len(kids) > 40:
                entry["children_truncated"] = True
        top.append(entry)

    assessment = build_processing_assessment(
        present=present,
        absent=absent,
        counts=counts,
        high_value_parsed=high_value,
        samples_by_class=samples,
        top_level=top,
        file_count=file_count,
        ambiguous=list(profile.get("ambiguous") or []),
    )

    mark_inventory_complete(root, summary={
        "present_classes": present,
        "absent_classes": absent,
        "top_level_count": len(top),
        "files_indexed": file_count,
        "high_value_count": len(high_value),
        "high_value_parsed": high_value,
        "needs_processing_classes": [
            x.get("class") for x in assessment["needs_processing"]
        ],
        "already_processed_count": len(high_value),
        "catalog_role": "reference_map",
    }, assessment=assessment)
    # Coverage ledger floor — built once inventory answers "what exists".
    try:
        from core.coverage_ledger import build_coverage_ledger
        build_coverage_ledger(root)
    except Exception:
        pass
    return {
        "success": True,
        "assessment": assessment,
        "present_classes": present,
        "absent_classes": absent,
        "counts": counts,
        "samples_by_class": samples,
        "high_value_parsed": high_value,
        "top_level": top,
        "inventory_path": str(inventory_path(root)),
        "note": (
            "Assessment unlocks forensic tools. "
            "catalog = reference map (what you can fall back on). "
            "Scope depth by case questions / time window; defer "
            "out-of-window items without deep analysis."
        ),
    }
