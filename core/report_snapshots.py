"""Immutable report snapshots for incremental reruns.

Layout after the first persist ``atlas rerun``::

    reports/
      initial_report/     # pre-rerun deliverables (never overwritten)
      rerun_NNNN/         # complete report pack after material rerun N
      diff_report.md      # cumulative investigation-state change history
      latest -> …         # symlink to highest rerun_* or initial_report

Current Investigation State (``.atlas/``) remains the source of truth.
Snapshot folders are historical projections only.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "1.0"

RESERVED_DIRS = frozenset({
    "initial_report",
    "latest",
    ".timeline_build",
    ".git",
})
RESERVED_FILES = frozenset({
    "diff_report.md",
    ".gitkeep",
})
_RERUN_DIR_RE = re.compile(r"^rerun_(\d{4})$")
_RUN_ID_RE = re.compile(r"^run-(\d+)$", re.IGNORECASE)

# Deliverable patterns to migrate / promote from reports/ root
_DELIVERABLE_SUFFIXES = (
    "_report.md",
    "_report.html",
    "_report_projection.json",
    "_reassessment.md",
    "_estate_report.md",
    "_investigation_report.md",
    "_trace.md",
)
_MODERN_DELIVERABLES = frozenset({
    "estate_report.md",
    "estate_report.html",
})


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def reports_dir(case_dir: str | os.PathLike) -> Path:
    return Path(case_dir).resolve() / "reports"


def initial_report_dir(case_dir: str | os.PathLike) -> Path:
    return reports_dir(case_dir) / "initial_report"


def diff_report_path(case_dir: str | os.PathLike) -> Path:
    return reports_dir(case_dir) / "diff_report.md"


def latest_link(case_dir: str | os.PathLike) -> Path:
    return reports_dir(case_dir) / "latest"


def snapshots_index_path(case_dir: str | os.PathLike) -> Path:
    return Path(case_dir).resolve() / ".atlas" / "report_snapshots_index.json"


def run_id_to_rerun_dirname(run_id: str) -> str:
    """Map journal ``run-0003`` → ``rerun_0003``."""
    m = _RUN_ID_RE.match((run_id or "").strip())
    if m:
        return f"rerun_{int(m.group(1)):04d}"
    digits = re.findall(r"\d+", run_id or "")
    n = int(digits[-1]) if digits else 1
    return f"rerun_{n:04d}"


def _stmt_hash(statement: str) -> str:
    return hashlib.sha256((statement or "").encode("utf-8")).hexdigest()[:16]


def _is_deliverable_name(name: str) -> bool:
    if name in RESERVED_FILES:
        return False
    if name.startswith("."):
        return False
    lower = name.lower()
    if lower in _MODERN_DELIVERABLES:
        return True
    if re.match(r"^host_.+_report\.(md|html)$", lower):
        return True
    if any(lower.endswith(suf) for suf in _DELIVERABLE_SUFFIXES):
        return True
    if lower.endswith(".md") and not lower.startswith("diff_"):
        return True
    if lower.endswith((".html", ".json")) and "report" in lower:
        return True
    if lower.endswith(".tsv") and "timeline" in lower:
        return True
    if lower.endswith(".json") and "trace" in lower:
        return True
    return False


def list_root_deliverables(case_dir: str | os.PathLike) -> list[Path]:
    """Files (not dirs) at reports/ root eligible for migrate/promote."""
    root = reports_dir(case_dir)
    if not root.is_dir():
        return []
    out: list[Path] = []
    for p in sorted(root.iterdir()):
        if p.is_symlink() and p.name == "latest":
            continue
        if p.is_dir():
            continue
        if p.name in RESERVED_FILES:
            continue
        if _is_deliverable_name(p.name):
            out.append(p)
    return out


def list_rerun_dirs(case_dir: str | os.PathLike) -> list[Path]:
    root = reports_dir(case_dir)
    if not root.is_dir():
        return []
    found: list[tuple[int, Path]] = []
    for p in root.iterdir():
        if not p.is_dir() or p.is_symlink():
            continue
        m = _RERUN_DIR_RE.match(p.name)
        if m:
            found.append((int(m.group(1)), p))
    return [p for _, p in sorted(found)]


def investigation_fingerprint(case_dir: str | os.PathLike) -> dict[str, Any]:
    """Structured, hashable investigation-state summary (not report prose)."""
    from core.claim_graph import load_graph
    from core.evidence_catalog import load_catalog
    from core.rerun_brief import load_memory

    graph = load_graph(case_dir)
    nodes_out: dict[str, Any] = {}
    needs_review: list[str] = []
    for nid, node in (graph.get("nodes") or {}).items():
        kind = node.get("kind") or ""
        if kind not in (
            "claim", "conclusion", "hypothesis", "conflict", "observation",
        ):
            continue
        entry = {
            "id": nid,
            "kind": kind,
            "status": node.get("status") or "",
            "confidence": (node.get("confidence") or "").upper(),
            "statement_hash": _stmt_hash(node.get("statement") or ""),
            "statement": (node.get("statement") or "")[:200],
            "superseded_by": node.get("superseded_by"),
        }
        nodes_out[nid] = entry
        if node.get("status") == "needs_review":
            needs_review.append(nid)

    catalog = load_catalog(case_dir)
    evidence_units = []
    for eid, unit in sorted((catalog.get("units") or {}).items()):
        if not isinstance(unit, dict):
            continue
        evidence_units.append({
            "id": eid,
            "path": unit.get("path") or "",
            "content_hash": unit.get("content_hash") or "",
            "size": unit.get("size"),
        })

    mem = load_memory(case_dir)
    analyst_ctx = []
    for e in mem.get("analyst_context") or []:
        analyst_ctx.append({
            "id": e.get("id"),
            "status": e.get("status"),
            "text_hash": _stmt_hash(e.get("text") or ""),
            "text": (e.get("text") or "")[:200],
            "supersedes": e.get("supersedes"),
        })

    payload = {
        "schema_version": SCHEMA_VERSION,
        "captured_at": _utcnow(),
        "nodes": nodes_out,
        "needs_review": sorted(needs_review),
        "evidence_units": evidence_units,
        "analyst_context": analyst_ctx,
    }
    digest = hashlib.sha256(
        json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()
    payload["fingerprint_sha256"] = digest
    return payload


def load_fingerprint_file(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def save_fingerprint(dest_dir: Path, fp: dict[str, Any]) -> Path:
    dest_dir.mkdir(parents=True, exist_ok=True)
    path = dest_dir / "investigation_fingerprint.json"
    path.write_text(json.dumps(fp, indent=2, ensure_ascii=False) + "\n",
                    encoding="utf-8")
    return path


def prior_fingerprint(case_dir: str | os.PathLike) -> dict[str, Any] | None:
    """Fingerprint from highest rerun_* or initial_report, else None."""
    reruns = list_rerun_dirs(case_dir)
    if reruns:
        loaded = load_fingerprint_file(
            reruns[-1] / "investigation_fingerprint.json"
        )
        if loaded:
            return loaded
    init = initial_report_dir(case_dir)
    if init.is_dir():
        loaded = load_fingerprint_file(init / "investigation_fingerprint.json")
        if loaded:
            return loaded
    return None


def diff_investigation_state(
    before: dict[str, Any] | None,
    after: dict[str, Any] | None,
) -> dict[str, Any]:
    """Compare two fingerprints into analyst-oriented change categories."""
    before = before or {}
    after = after or {}
    bn = before.get("nodes") or {}
    an = after.get("nodes") or {}
    if isinstance(bn, list):
        bn = {n.get("id"): n for n in bn if n.get("id")}
    if isinstance(an, list):
        an = {n.get("id"): n for n in an if n.get("id")}

    new_findings: list[dict[str, Any]] = []
    changed_findings: list[dict[str, Any]] = []
    withdrawn: list[dict[str, Any]] = []
    confidence_changes: list[dict[str, Any]] = []
    new_conflicts: list[dict[str, Any]] = []
    resolved_conflicts: list[dict[str, Any]] = []

    for nid, node in an.items():
        if nid not in bn:
            item = {
                "id": nid,
                "kind": node.get("kind"),
                "status": node.get("status"),
                "confidence": node.get("confidence"),
                "statement": node.get("statement"),
            }
            if node.get("kind") == "conflict" and node.get("status") == "conflict":
                new_conflicts.append(item)
            else:
                new_findings.append(item)
            continue
        old = bn[nid]
        status_changed = (old.get("status") != node.get("status"))
        conf_changed = (old.get("confidence") != node.get("confidence"))
        stmt_changed = (old.get("statement_hash") != node.get("statement_hash"))
        if conf_changed:
            confidence_changes.append({
                "id": nid,
                "kind": node.get("kind"),
                "from": old.get("confidence"),
                "to": node.get("confidence"),
                "statement": node.get("statement"),
            })
        if status_changed or stmt_changed:
            if node.get("status") == "superseded":
                withdrawn.append({
                    "id": nid,
                    "kind": node.get("kind"),
                    "status": node.get("status"),
                    "superseded_by": node.get("superseded_by"),
                    "statement": node.get("statement"),
                })
            elif (
                old.get("kind") == "conflict"
                and old.get("status") == "conflict"
                and node.get("status") != "conflict"
            ):
                resolved_conflicts.append({
                    "id": nid,
                    "kind": "conflict",
                    "from_status": old.get("status"),
                    "to_status": node.get("status"),
                    "statement": node.get("statement"),
                })
            else:
                changed_findings.append({
                    "id": nid,
                    "kind": node.get("kind"),
                    "from_status": old.get("status"),
                    "to_status": node.get("status"),
                    "from_confidence": old.get("confidence"),
                    "to_confidence": node.get("confidence"),
                    "statement": node.get("statement"),
                })

    for nid, old in bn.items():
        if nid in an:
            continue
        withdrawn.append({
            "id": nid,
            "kind": old.get("kind"),
            "status": "removed",
            "statement": old.get("statement"),
        })

    be = {
        u.get("id") or u.get("path"): u
        for u in (before.get("evidence_units") or [])
    }
    ae = {
        u.get("id") or u.get("path"): u
        for u in (after.get("evidence_units") or [])
    }
    evidence_added = [ae[k] for k in ae if k not in be]
    evidence_removed = [be[k] for k in be if k not in ae]
    evidence_changed = []
    for k in ae:
        if k in be and (be[k].get("content_hash") != ae[k].get("content_hash")):
            evidence_changed.append({
                "id": k,
                "path": ae[k].get("path"),
                "from_hash": be[k].get("content_hash"),
                "to_hash": ae[k].get("content_hash"),
            })

    bac = {e.get("id"): e for e in (before.get("analyst_context") or []) if e.get("id")}
    aac = {e.get("id"): e for e in (after.get("analyst_context") or []) if e.get("id")}
    ac_added = []
    ac_withdrawn = []
    ac_changed = []
    for eid, e in aac.items():
        if eid not in bac:
            ac_added.append(e)
        else:
            old = bac[eid]
            if old.get("status") != e.get("status") or old.get("text_hash") != e.get("text_hash"):
                if e.get("status") == "withdrawn" and old.get("status") != "withdrawn":
                    ac_withdrawn.append(e)
                else:
                    ac_changed.append({"id": eid, "from": old, "to": e})
    for eid, e in bac.items():
        if eid not in aac:
            ac_withdrawn.append(e)

    bnr = set(before.get("needs_review") or [])
    anr = set(after.get("needs_review") or [])

    return {
        "new_findings": new_findings,
        "changed_findings": changed_findings,
        "withdrawn_or_superseded": withdrawn,
        "new_conflicts": new_conflicts,
        "resolved_conflicts": resolved_conflicts,
        "confidence_changes": confidence_changes,
        "analyst_context_added": ac_added,
        "analyst_context_withdrawn": ac_withdrawn,
        "analyst_context_changed": ac_changed,
        "evidence_added": evidence_added,
        "evidence_changed": evidence_changed,
        "evidence_removed": evidence_removed,
        "needs_review_added": sorted(anr - bnr),
        "needs_review_cleared": sorted(bnr - anr),
        "fingerprint_before": before.get("fingerprint_sha256"),
        "fingerprint_after": after.get("fingerprint_sha256"),
    }


def material_change(diff: dict[str, Any]) -> bool:
    """True when investigation state (not merely prose) changed."""
    keys = (
        "new_findings",
        "changed_findings",
        "withdrawn_or_superseded",
        "new_conflicts",
        "resolved_conflicts",
        "confidence_changes",
        "analyst_context_added",
        "analyst_context_withdrawn",
        "analyst_context_changed",
        "evidence_added",
        "evidence_changed",
        "evidence_removed",
        "needs_review_added",
        "needs_review_cleared",
    )
    return any(diff.get(k) for k in keys)


def _ensure_diff_stub(case_dir: str | os.PathLike) -> Path:
    path = diff_report_path(case_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.is_file():
        path.write_text(
            "# Investigation Change History\n\n"
            "Cumulative record of investigation-state changes across reruns.\n"
            "Derived from Claim Graph, evidence catalog, analyst context, and "
            "journal — not from Markdown wording diffs.\n",
            encoding="utf-8",
        )
    return path


def _update_latest_symlink(case_dir: str | os.PathLike, target: Path) -> None:
    root = reports_dir(case_dir)
    root.mkdir(parents=True, exist_ok=True)
    link = latest_link(case_dir)
    try:
        rel = os.path.relpath(target, root)
    except ValueError:
        rel = str(target)
    if link.is_symlink() or link.exists():
        link.unlink()
    link.symlink_to(rel)


def resolve_latest_report_dir(case_dir: str | os.PathLike) -> Path:
    """Prefer ``reports/latest``; else highest rerun; else initial; else root."""
    root = reports_dir(case_dir)
    link = latest_link(case_dir)
    if link.is_symlink() or link.is_dir():
        try:
            resolved = link.resolve()
            if resolved.is_dir():
                return resolved
        except OSError:
            pass
    reruns = list_rerun_dirs(case_dir)
    if reruns:
        return reruns[-1]
    init = initial_report_dir(case_dir)
    if init.is_dir():
        return init
    return root


def _load_index(case_dir: str | os.PathLike) -> dict[str, Any]:
    path = snapshots_index_path(case_dir)
    if not path.is_file():
        return {"schema_version": SCHEMA_VERSION, "snapshots": []}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        data.setdefault("snapshots", [])
        return data
    except (OSError, json.JSONDecodeError):
        return {"schema_version": SCHEMA_VERSION, "snapshots": []}


def _save_index(case_dir: str | os.PathLike, index: dict[str, Any]) -> None:
    path = snapshots_index_path(case_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    index = dict(index)
    index["schema_version"] = SCHEMA_VERSION
    index["updated_at"] = _utcnow()
    path.write_text(json.dumps(index, indent=2, ensure_ascii=False) + "\n",
                    encoding="utf-8")


def ensure_initial_report_layout(
    case_dir: str | os.PathLike,
    *,
    fingerprint: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """On first rerun: move flat root deliverables into ``initial_report/``.

    Idempotent if ``initial_report/`` already exists.

    Pass ``fingerprint`` captured *before* Plane A so the baseline reflects
    the pre-rerun investigation state (not post-invalidation).
    """
    root = reports_dir(case_dir)
    root.mkdir(parents=True, exist_ok=True)
    init = initial_report_dir(case_dir)
    _ensure_diff_stub(case_dir)

    if init.is_dir():
        if not (init / "investigation_fingerprint.json").is_file():
            save_fingerprint(
                init, fingerprint or investigation_fingerprint(case_dir),
            )
        if not latest_link(case_dir).exists():
            target = list_rerun_dirs(case_dir)
            _update_latest_symlink(
                case_dir, target[-1] if target else init,
            )
        return {
            "migrated": False,
            "already_initialized": True,
            "initial_report": str(init),
            "moved": [],
        }

    init.mkdir(parents=True, exist_ok=True)
    moved: list[str] = []
    for src in list_root_deliverables(case_dir):
        dest = init / src.name
        if dest.exists():
            stem, suf = dest.stem, dest.suffix
            n = 2
            while dest.exists():
                dest = init / f"{stem}_dup{n}{suf}"
                n += 1
        shutil.move(str(src), str(dest))
        moved.append(src.name)

    fp = fingerprint or investigation_fingerprint(case_dir)
    save_fingerprint(init, fp)
    try:
        from core.claim_graph import graph_snapshot_for_report
        snap = graph_snapshot_for_report(case_dir)
        (init / "claim_snapshot.json").write_text(
            json.dumps(snap, indent=2, default=str, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
    except Exception:
        pass

    _update_latest_symlink(case_dir, init)
    index = _load_index(case_dir)
    index["initial_report"] = {
        "path": str(init),
        "migrated_at": _utcnow(),
        "files": moved,
        "fingerprint_sha256": fp.get("fingerprint_sha256"),
    }
    _save_index(case_dir, index)

    return {
        "migrated": True,
        "already_initialized": False,
        "initial_report": str(init),
        "moved": moved,
        "fingerprint_sha256": fp.get("fingerprint_sha256"),
    }


def _format_item_list(items: list[dict[str, Any]], *, case_dir: str | os.PathLike | None = None) -> list[str]:
    if not items:
        return ["(none)"]
    f_lookup: dict[str, str] = {}
    if case_dir is not None:
        try:
            from core.finding_index import load_index
            f_lookup = dict((load_index(case_dir).get("by_node_id") or {}))
        except Exception:
            f_lookup = {}
    lines = []
    for it in items:
        nid = it.get("id") or ""
        fid = it.get("finding_id") or f_lookup.get(nid) or ""
        kind = it.get("kind") or ""
        stmt = (it.get("statement") or it.get("text") or "")[:160]
        extra = ""
        if it.get("from_confidence") is not None:
            extra = f" ({it.get('from_confidence')} → {it.get('to_confidence')})"
        elif it.get("from_status") is not None:
            extra = f" [{it.get('from_status')} → {it.get('to_status')}]"
        elif it.get("superseded_by"):
            extra = f" → {it.get('superseded_by')}"
        if fid:
            label = f"**{fid}** (`{nid}`)" if nid else f"**{fid}**"
        else:
            label = f"**{nid}**" if nid else "-"
        if kind:
            label += f" ({kind})"
        lines.append(f"- {label}{extra}: {stmt}" if stmt else f"- {label}{extra}")
    return lines


def append_diff_report(
    case_dir: str | os.PathLike,
    *,
    run_id: str,
    diff: dict[str, Any],
    material: bool,
    plane_a: dict[str, Any] | None = None,
    regen_result: dict[str, Any] | None = None,
    trigger: str = "",
    snapshot_dir: str | None = None,
) -> Path:
    """Append one rerun section to cumulative ``diff_report.md``."""
    path = _ensure_diff_stub(case_dir)
    plane_a = plane_a or {}
    why = plane_a.get("why_summary") or []
    reasons = []
    if plane_a.get("new_analyst_context"):
        reasons.append("Analyst context")
    counts = ((plane_a.get("evidence_diff") or {}).get("counts") or {})
    if counts.get("added"):
        reasons.append("New evidence")
    if counts.get("changed"):
        reasons.append("Evidence modified")
    if counts.get("removed"):
        reasons.append("Evidence removed")
    if not reasons and trigger:
        reasons.append(trigger)
    if not reasons:
        reasons.append("Rerun")

    title_n = run_id_to_rerun_dirname(run_id).replace("rerun_", "")
    lines = [
        "",
        "---",
        "",
        f"## Rerun {title_n}",
        "",
        f"Timestamp: {_utcnow()}",
        f"Journal run: `{run_id}`",
        f"Reason: {', '.join(reasons)}",
    ]
    if snapshot_dir:
        lines.append(f"Report snapshot: `{snapshot_dir}`")
    if why:
        lines.append("")
        lines.append("Journal why:")
        for w in why[:15]:
            lines.append(f"- {w}")

    if not material:
        lines += [
            "",
            "### Outcome",
            "",
            "No material investigation-state changes — report snapshot skipped.",
            "",
        ]
        path.write_text(
            path.read_text(encoding="utf-8") + "\n".join(lines),
            encoding="utf-8",
        )
        return path

    def _sec(title: str, items: list) -> None:
        lines.append("")
        lines.append(f"### {title}")
        lines.append("")
        if items and isinstance(items[0], str):
            for x in items:
                lines.append(f"- `{x}`")
        else:
            lines.extend(
                _format_item_list(
                    items if isinstance(items, list) else [],
                    case_dir=case_dir,
                )
            )

    _sec("New Findings", diff.get("new_findings") or [])
    _sec("Changed Findings", diff.get("changed_findings") or [])
    _sec("Withdrawn or Superseded Findings",
         diff.get("withdrawn_or_superseded") or [])
    _sec("New Conflicts", diff.get("new_conflicts") or [])
    _sec("Resolved Conflicts", diff.get("resolved_conflicts") or [])

    conf = diff.get("confidence_changes") or []
    lines += ["", "### Confidence Changes", ""]
    if not conf:
        lines.append("(none)")
    else:
        for c in conf:
            lines.append(
                f"- **{c.get('id')}** ({c.get('kind')}): "
                f"{c.get('from')} → {c.get('to')}: "
                f"{(c.get('statement') or '')[:120]}"
            )

    ac_lines = []
    for e in diff.get("analyst_context_added") or []:
        ac_lines.append(
            f"- added **{e.get('id')}**: {(e.get('text') or '')[:160]}"
        )
    for e in diff.get("analyst_context_withdrawn") or []:
        ac_lines.append(
            f"- withdrawn **{e.get('id')}**: {(e.get('text') or '')[:160]}"
        )
    for e in diff.get("analyst_context_changed") or []:
        ac_lines.append(f"- changed **{e.get('id')}**")
    lines += ["", "### Analyst Context Changes", ""]
    lines.extend(ac_lines or ["(none)"])

    ev_bits = []
    for e in diff.get("evidence_added") or []:
        ev_bits.append(f"- added `{e.get('path') or e.get('id')}`")
    for e in diff.get("evidence_changed") or []:
        ev_bits.append(f"- changed `{e.get('path') or e.get('id')}`")
    for e in diff.get("evidence_removed") or []:
        ev_bits.append(f"- removed `{e.get('path') or e.get('id')}`")
    lines += ["", "### Evidence Changes", ""]
    lines.extend(ev_bits or ["(none)"])

    nr_a = diff.get("needs_review_added") or []
    nr_c = diff.get("needs_review_cleared") or []
    lines += ["", "### Needs Review", ""]
    if not nr_a and not nr_c:
        lines.append("(none)")
    else:
        for x in nr_a:
            lines.append(f"- marked needs_review: `{x}`")
        for x in nr_c:
            lines.append(f"- cleared needs_review: `{x}`")

    regen = (regen_result or {}).get("regenerated") or []
    lines += ["", "### Report Sections Updated", ""]
    if regen:
        for sid in regen:
            lines.append(f"- `{sid}` regenerated")
    else:
        lines.append("(none / not regenerated this pass)")

    lines.append("")
    path.write_text(
        path.read_text(encoding="utf-8") + "\n".join(lines),
        encoding="utf-8",
    )
    return path


def promote_rerun_snapshot(
    case_dir: str | os.PathLike,
    *,
    run_id: str,
    plane_a: dict[str, Any] | None = None,
    regen_result: dict[str, Any] | None = None,
    trigger: str = "",
    force_snapshot: bool = False,
    fp_before: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Compare state, optionally promote root deliverables into ``rerun_NNNN/``.

    When there is no material change, appends a short note to ``diff_report.md``
    and does **not** create a new snapshot directory.
    """
    plane_a = plane_a or {}
    run_id = run_id or plane_a.get("run_id") or "run-0001"
    rerun_name = run_id_to_rerun_dirname(run_id)
    dest = reports_dir(case_dir) / rerun_name

    before = fp_before if fp_before is not None else prior_fingerprint(case_dir)
    after = investigation_fingerprint(case_dir)
    diff = diff_investigation_state(before, after)
    is_material = force_snapshot or material_change(diff)

    root_files = list_root_deliverables(case_dir)
    if not is_material:
        append_diff_report(
            case_dir,
            run_id=run_id,
            diff=diff,
            material=False,
            plane_a=plane_a,
            regen_result=regen_result,
            trigger=trigger or "no material change",
        )
        return {
            "success": True,
            "material": False,
            "snapshot_created": False,
            "run_id": run_id,
            "rerun_dir": None,
            "diff": diff,
            "diff_report": str(diff_report_path(case_dir)),
            "root_deliverables_left": [p.name for p in root_files],
        }

    if not root_files and not force_snapshot:
        append_diff_report(
            case_dir,
            run_id=run_id,
            diff=diff,
            material=True,
            plane_a=plane_a,
            regen_result=regen_result,
            trigger=trigger or "investigation changed (no report files to snapshot)",
            snapshot_dir=None,
        )
        return {
            "success": True,
            "material": True,
            "snapshot_created": False,
            "run_id": run_id,
            "rerun_dir": None,
            "diff": diff,
            "note": "material state change but no root deliverables to promote",
            "diff_report": str(diff_report_path(case_dir)),
        }

    if dest.exists():
        n = 1
        m = _RERUN_DIR_RE.match(rerun_name)
        if m:
            n = int(m.group(1))
        while dest.exists():
            n += 1
            dest = reports_dir(case_dir) / f"rerun_{n:04d}"
            rerun_name = dest.name

    dest.mkdir(parents=True, exist_ok=True)
    moved: list[str] = []
    for src in list_root_deliverables(case_dir):
        target = dest / src.name
        shutil.move(str(src), str(target))
        moved.append(src.name)

    save_fingerprint(dest, after)
    try:
        from core.claim_graph import graph_snapshot_for_report
        snap = graph_snapshot_for_report(case_dir)
        (dest / "claim_snapshot.json").write_text(
            json.dumps(snap, indent=2, default=str, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
    except Exception:
        pass

    append_diff_report(
        case_dir,
        run_id=run_id,
        diff=diff,
        material=True,
        plane_a=plane_a,
        regen_result=regen_result,
        trigger=trigger,
        snapshot_dir=f"reports/{rerun_name}",
    )
    _update_latest_symlink(case_dir, dest)

    try:
        from core.report_projection import load_manifest, save_manifest
        man = load_manifest(case_dir)
        primary = None
        for name in moved:
            if name.endswith("_report.md") and "estate" not in name.lower():
                primary = dest / name
                break
        if primary is None:
            for name in moved:
                if name.endswith(".md"):
                    primary = dest / name
                    break
        if primary is not None:
            man["last_assembled_path"] = str(primary)
            man["last_assembled_at"] = _utcnow()
            save_manifest(case_dir, man)
    except Exception:
        pass

    index = _load_index(case_dir)
    index.setdefault("snapshots", []).append({
        "run_id": run_id,
        "rerun_dir": rerun_name,
        "path": str(dest),
        "created_at": _utcnow(),
        "files": moved,
        "fingerprint_sha256": after.get("fingerprint_sha256"),
        "material": True,
    })
    _save_index(case_dir, index)

    return {
        "success": True,
        "material": True,
        "snapshot_created": True,
        "run_id": run_id,
        "rerun_dir": str(dest),
        "moved": moved,
        "diff": diff,
        "diff_report": str(diff_report_path(case_dir)),
        "latest": str(resolve_latest_report_dir(case_dir)),
    }


def finalize_rerun_reports(
    case_dir: str | os.PathLike,
    *,
    plane_a: dict[str, Any],
    regen_result: dict[str, Any] | None = None,
    trigger: str = "",
    migrate: bool = True,
    fp_before: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Promote root deliverables / append diff after a persist rerun."""
    if migrate and not initial_report_dir(case_dir).is_dir():
        ensure_initial_report_layout(case_dir)

    return promote_rerun_snapshot(
        case_dir,
        run_id=plane_a.get("run_id") or "run-0001",
        plane_a=plane_a,
        regen_result=regen_result,
        trigger=trigger,
        fp_before=fp_before,
    )
