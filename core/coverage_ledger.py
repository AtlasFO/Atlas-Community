"""Coverage Ledger — high-value evidence units tracked for investigation progress.

Philosophy:
  Process audit ≠ belief ≠ coverage. Ledger disposition
  (``probed`` / ``answered`` / ``blocked``) is the soft-exit currency.
  Task↔claim progress is still required while the inbox has open work, but
  clearing the inbox or linking claims must **not** waive unseen HV units
  (B4 overshoot corrected). Without a task SoT, legacy ``unseen == 0`` applies.
  Access / inventory remain hard gates layered on top.

Statuses per unit: unseen | probed | answered | blocked.
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from core.artifact_kind import is_ewf_continuation_segment

SCHEMA_VERSION = "1.0"
LEDGER_NAME = "coverage_ledger.json"

# Shared noise under evidence/ — also applied by catalog/profile/orchestrator.
NOISE_DIR_NAMES = frozenset({
    ".git", "__pycache__", ".cache", "lost+found",
    "node_modules", "tools_temp_dir", ".venv", "venv",
    "site-packages", "__tests__", ".npm",
})
NOISE_NAME_SUFFIXES = (
    ":zone.identifier",
    ".zone.identifier",
)
NOISE_PATH_FRAGMENTS = (
    "/node_modules/",
    "/tools_temp_dir/",
    "/.git/",
    "/site-packages/",
)

# What counts as a high-value evidence unit is decided by the artifact
# value model (core.artifact_value): universal artifact types — Security.evtx,
# $MFT, Amcache, hives, textual logs — not a list of file names from earlier
# engagements: a list of export names is right for the case it came from
# and blind to every other case's firewall or VPN export.
_HV_MIN_SCORE = 45


def _is_high_value_name(name: str) -> bool:
    try:
        from core.artifact_value import artifact_score
        return artifact_score(name)[0] >= _HV_MIN_SCORE
    except Exception:  # noqa: BLE001
        return False

# Evidence classes that are containers of other evidence: nothing can be
# queried out of them until the run opens them, so they carry their own
# coverage. Wider than ioc_pivots' notion (which only asks "can I grep it").
_INTAKE_CONTAINER_CLASSES = frozenset({"disk", "memory"})
# The ledger's own kind label for an intake container (a disk or memory
# image): a unit nothing can query until a tool opens it.
CONTAINER_KIND = "container"

_CANONICAL_EVTX = frozenset({
    "security.evtx",
    "system.evtx",
    "application.evtx",
    "microsoft-windows-terminalservices-localsessionmanager%4operational.evtx",
    "microsoft-windows-terminalservices-remoteconnectionmanager%4operational.evtx",
    "microsoft-windows-smbserver%4security.evtx",
    "microsoft-windows-smbclient%4security.evtx",
})


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def ledger_path(case_dir: str | os.PathLike) -> Path:
    return Path(case_dir).resolve() / ".atlas" / LEDGER_NAME


def is_noise_path(path: str) -> bool:
    """True when path is tool-tree / Zone.Identifier / package noise."""
    if not path:
        return True
    low = path.replace("\\", "/").casefold()
    name = Path(low).name
    if name.endswith(NOISE_NAME_SUFFIXES) or ":zone.identifier" in name:
        return True
    if any(frag in low for frag in NOISE_PATH_FRAGMENTS):
        return True
    parts = [p for p in low.split("/") if p]
    return any(p in NOISE_DIR_NAMES for p in parts)


def empty_ledger(case_id: str = "") -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "case_id": case_id or "",
        "updated_at": _utcnow(),
        "units": {},
        "meta": {"source": "empty"},
    }


def load_ledger(case_dir: str | os.PathLike) -> dict[str, Any]:
    path = ledger_path(case_dir)
    if not path.is_file():
        return empty_ledger(Path(case_dir).name)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return empty_ledger(Path(case_dir).name)
    if not isinstance(data, dict):
        return empty_ledger(Path(case_dir).name)
    data.setdefault("units", {})
    return data


def save_ledger(case_dir: str | os.PathLike, data: dict[str, Any]) -> Path:
    root = Path(case_dir).resolve()
    path = ledger_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = dict(data)
    data["schema_version"] = SCHEMA_VERSION
    data["case_id"] = data.get("case_id") or root.name
    data["updated_at"] = _utcnow()
    path.write_text(
        json.dumps(data, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return path


# The case's own top-level directories. A unit path has to be able to name
# any of them: forcing every path under evidence/ made units for extracted
# artifacts point at files that do not exist, so nothing could ever mark them
# probed and the coverage floor could never be met.
# The trees a case names its files under. ``mnt/`` is where an opened image
# is read: once its filesystem is mounted every read targets
# ``mnt/<stem>/fs/...`` or the device ``mnt/<stem>/ewf/ewf1``, and the
# analyst names them relative to the case like everything else. Without it
# here such a read had no case-relative form, the image-credit lookup was
# handed a tail that lay under no mount, and the container sat unseen
# through the investigation of its own filesystem.
_CASE_SUBDIRS = ("evidence/", "analysis/", "exports/", "mnt/")


def _norm_rel(path: str) -> str:
    p = (path or "").replace("\\", "/").strip()
    if p.startswith("./"):
        p = p[2:]
    if p.startswith(_CASE_SUBDIRS):
        return p
    if p.startswith("/"):
        # absolute — recover the case-relative tail at the first case
        # directory the path names: a mounted image's own analysis/ or
        # exports/ folder must not hijack a path under mnt/.
        hits = [i for i in (p.find("/" + sub) for sub in _CASE_SUBDIRS) if i >= 0]
        if hits:
            return p[min(hits) + 1:]
    # A bare name is an evidence-tree path by convention: the inventory and
    # the profile both emit paths relative to evidence/.
    return f"evidence/{p}" if p else ""


def _unit_id(rel: str) -> str:
    """A stable id per path. Sanitising alone collapsed names that differ
    only in characters outside ASCII (``Müller.csv`` and ``Möller.csv``
    both became ``M_ller.csv``) and the second file silently left the
    ledger — so a short hash of the real path is appended whenever
    sanitising changed anything."""
    safe = re.sub(r"[^a-zA-Z0-9._/+-]+", "_", rel)
    if safe == rel and len(rel) <= 200:
        return safe
    import hashlib
    return f"{safe[:180]}-{hashlib.sha1(rel.encode('utf-8')).hexdigest()[:8]}"


def _add_unit(
    units: dict[str, Any],
    rel: str,
    *,
    kind: str,
    reason: str,
    task_ids: Optional[list[str]] = None,
) -> None:
    rel = _norm_rel(rel)
    if not rel or is_noise_path(rel):
        return
    uid = _unit_id(rel)
    if uid in units:
        existing = units[uid]
        for tid in task_ids or []:
            tids = existing.setdefault("task_ids", [])
            if tid not in tids:
                tids.append(tid)
        return
    units[uid] = {
        "id": uid,
        "path": rel,
        "kind": kind,
        "reason": reason,
        "status": "unseen",
        "task_ids": list(task_ids or []),
        "probed_at": None,
        "note": "",
    }


def _collect_candidate_paths(case_dir: Path) -> list[tuple[str, str, str]]:
    """Return (rel_path, kind, reason) candidates."""
    out: list[tuple[str, str, str]] = []
    seen: set[str] = set()

    def add(rel: str, kind: str, reason: str) -> None:
        rel = _norm_rel(rel)
        if not rel or rel in seen or is_noise_path(rel):
            return
        seen.add(rel)
        out.append((rel, kind, reason))

    # Intake containers first — the disk and memory images the case was
    # given. Every other branch seeds a file something can already be
    # *queried* from, so on an image case the floor could hold only the log
    # exports and report "all probed, none unseen" while a large image had
    # never been opened. A container is a unit in its own right: it is covered once
    # the run exported, listed or carved it (see the source-image expansion
    # in ``mark_paths``). Seeded before the bounded branches so the 80-unit
    # cap can never drop the largest piece of evidence in the case.
    try:
        from core.evidence_profile import ensure_evidence_profile
        profile = ensure_evidence_profile(str(case_dir))
        for f in (profile.get("files") or [])[:5000]:
            if not isinstance(f, dict):
                continue
            rel = str(f.get("path") or "").replace("\\", "/").lstrip("./")
            if not rel or str(f.get("class") or "") not in _INTAKE_CONTAINER_CLASSES:
                continue
            # Intake only: a raw image the run exported is derived, not
            # something the case was handed. And never invent a prefix —
            # a unit whose path does not exist can never be probed, and the
            # floor would then be unmeetable.
            if "/" not in rel:
                rel = f"evidence/{rel}"
            if not rel.startswith("evidence/") or is_noise_path(rel):
                continue
            if not (case_dir / rel).exists():
                continue
            # A split image's .E02+ are read through its .E01: seeding them
            # as units of their own left them unseen after the set was
            # opened and the exit floor named them as never examined.
            if is_ewf_continuation_segment(rel):
                continue
            add(rel, "container", "intake_container")
    except Exception:  # noqa: BLE001
        pass

    # Inventory already_processed / high_value
    try:
        inv_path = case_dir / ".atlas" / "evidence_inventory.json"
        if inv_path.is_file():
            inv = json.loads(inv_path.read_text(encoding="utf-8"))
            summary = inv.get("summary") or {}
            assessment = inv.get("assessment") or summary.get("assessment") or {}
            # build_evidence_inventory stores assessment separately sometimes
            ap = assessment.get("already_processed") or {}
            for p in ap.get("paths") or []:
                add(str(p), "tabular", "already_processed")
            for p in summary.get("high_value_parsed") or []:
                add(str(p), "tabular", "high_value_parsed")
    except Exception:
        pass

    # Also read assessment from the inventory payload written by misc
    try:
        from core.evidence_inventory_gate import inventory_path
        inv_path = inventory_path(case_dir)
        if inv_path.is_file():
            inv = json.loads(inv_path.read_text(encoding="utf-8"))
            # Some stamps only have summary; try loading full build result
            # from evidence_profile high_value
            from core.evidence_profile import (
                ensure_evidence_profile, high_value_tabular_index,
            )
            profile = ensure_evidence_profile(str(case_dir))
            for p in high_value_tabular_index(profile, limit=40):
                add(p, "tabular", "profile_high_value")
    except Exception:
        pass

    # Case-root tabular under evidence/
    evid = case_dir / "evidence"
    if evid.is_dir():
        try:
            for child in sorted(evid.iterdir()):
                if not child.is_file():
                    continue
                name = child.name
                if is_noise_path(name):
                    continue
                low = name.casefold()
                if low.endswith((".csv", ".tsv", ".xlsx")):
                    add(f"evidence/{name}", "tabular", "case_root_tabular")
        except OSError:
            pass

    # Canonical EVTX under winevt/logs (first host tree found)
    if evid.is_dir():
        try:
            for dirpath, dirnames, filenames in os.walk(evid):
                # prune noise
                dirnames[:] = [
                    d for d in dirnames
                    if d not in NOISE_DIR_NAMES and not d.startswith(".")
                ]
                base = Path(dirpath).name.casefold()
                parent = Path(dirpath).as_posix().replace("\\", "/").casefold()
                if base != "logs" or "winevt" not in parent:
                    continue
                for fn in filenames:
                    if fn.casefold() in _CANONICAL_EVTX or (
                            fn.casefold() == "security.evtx"):
                        full = Path(dirpath) / fn
                        try:
                            rel = full.relative_to(case_dir).as_posix()
                        except ValueError:
                            continue
                        add(rel, "eventlog", "canonical_evtx")
                # EVERY host's winevt tree contributes to the floor — in a
                # multi-host estate, covering WS01 says nothing about WS02
                #
        except OSError:
            pass

    # Artifacts the run extracted from a container. Every source above is
    # rooted at evidence/, so on a disk-image case — where evidence/ holds a
    # VMDK and every queryable artifact is carved into exports/ and parsed
    # into analysis/ — the ledger seeded zero units and then reported
    # "0 units — none unseen" while real sources sat unexamined. Added last
    # so intake evidence keeps priority under the 80-unit cap.
    try:
        from core.ioc_pivots import evidence_sources
        for rel in sorted(evidence_sources(case_dir)):
            low = rel.casefold()
            if not low.startswith(("analysis/", "exports/")):
                continue
            if low.endswith(".evtx"):
                add(rel, "eventlog", "run_extract")
            elif low.endswith((".csv", ".tsv", ".xlsx")):
                add(rel, "tabular", "run_extract")
            elif _is_high_value_name(Path(low).name):
                add(rel, "tabular", "run_extract_hv")
            if len(out) >= 80:
                break
    except Exception:  # noqa: BLE001
        pass

    # Name-heuristic hits from profile file list (bounded)
    try:
        from core.evidence_profile import ensure_evidence_profile
        profile = ensure_evidence_profile(str(case_dir))
        for f in (profile.get("files") or [])[:5000]:
            if not isinstance(f, dict):
                continue
            rel = str(f.get("path") or "")
            if not rel or is_noise_path(rel):
                continue
            low = rel.casefold()
            if _is_high_value_name(Path(low).name) or _is_high_value_name(low):
                kind = "eventlog" if low.endswith(".evtx") else "tabular"
                # The profile already knows what the file *is* — a delimited
                # export called .log is tabular whatever its suffix says.
                cls = str(f.get("class") or "")
                if cls in ("tabular", "windows_eventlog") or low.endswith(
                        (".csv", ".tsv", ".xlsx", ".evtx", ".json")):
                    add(rel if rel.startswith("evidence/") else f"evidence/{rel}",
                        kind, "name_heuristic")
            if len(out) >= 80:
                break
    except Exception:
        pass

    return out[:80]


def build_coverage_ledger(
    case_dir: str | os.PathLike,
    *,
    task_ids: Optional[list[str]] = None,
) -> dict[str, Any]:
    """(Re)build ledger units from inventory/profile/tasks; preserve statuses."""
    root = Path(case_dir).resolve()
    prev = load_ledger(root)
    prev_units = prev.get("units") or {}

    tids = list(task_ids or [])
    if not tids:
        try:
            tp = root / ".atlas" / "investigation_tasks.json"
            if tp.is_file():
                data = json.loads(tp.read_text(encoding="utf-8"))
                for t in data.get("tasks") or []:
                    if not isinstance(t, dict):
                        continue
                    st = (t.get("status") or "open").lower()
                    if st in ("open", "in_progress", "actionable", ""):
                        tid = str(t.get("id") or t.get("task_id") or "")
                        if tid:
                            tids.append(tid)
        except Exception:
            pass
        try:
            plan = root / ".atlas" / "investigation_plan.json"
            if plan.is_file():
                pdata = json.loads(plan.read_text(encoding="utf-8"))
                for tid in pdata.get("actionable_task_ids") or []:
                    if tid not in tids:
                        tids.append(str(tid))
        except Exception:
            pass

    units: dict[str, Any] = {}
    for rel, kind, reason in _collect_candidate_paths(root):
        uid = _unit_id(_norm_rel(rel))
        # What the run writes is covered by lineage: the call that fills a
        # directory under analysis/ or exports/ registers it as a derived
        # unit. A rebuild over an existing ledger therefore seeds no new
        # unit from those trees; otherwise the run's own query outputs and
        # unpacked archives would come back as unseen sources and hold the
        # report to a floor a fresh run never had. Only a first build seeds
        # extracts that were already on disk.
        if prev_units and uid not in prev_units and _norm_rel(rel).startswith(_DERIVED_ROOTS):
            continue
        _add_unit(units, rel, kind=kind, reason=reason, task_ids=tids)
        if uid in prev_units:
            old = prev_units[uid]
            if old.get("status") in ("probed", "answered", "blocked"):
                units[uid]["status"] = old["status"]
                units[uid]["probed_at"] = old.get("probed_at")
                units[uid]["note"] = old.get("note") or ""

    # Preserve blocked/answered units that disappeared from candidates, and
    # derived units, which are never among them.
    for uid, old in prev_units.items():
        if uid not in units and (old.get("status") in ("answered", "blocked")
                                 or old.get("kind") == "derived"):
            units[uid] = old

    # The delivered pieces of evidence, from the same file list: a view for
    # the report and the rerun beside the units, never part of the floor.
    try:
        from core.evidence_items import build_items
        from core.evidence_profile import ensure_evidence_profile
        items = build_items(ensure_evidence_profile(str(root)).get("files") or [],
                            prev.get("items"))
    except Exception:  # noqa: BLE001 - the floor stands without the items
        items = prev.get("items") or {}

    ledger = {
        "schema_version": SCHEMA_VERSION,
        "case_id": root.name,
        "updated_at": _utcnow(),
        "units": units,
        "items": items,
        "meta": {
            "source": "build_coverage_ledger",
            "task_ids": tids,
            "unit_count": len(units),
        },
    }
    save_ledger(root, ledger)
    return ledger


def coverage_fingerprint(ledger: dict[str, Any] | None) -> tuple:
    """Comparable signature for stall/progress (status + path set)."""
    units = (ledger or {}).get("units") or {}
    items = tuple(sorted(
        (str(u.get("path") or ""), str(u.get("status") or "unseen"))
        for u in units.values() if isinstance(u, dict)
    ))
    return items


def coverage_stats(ledger: dict[str, Any] | None) -> dict[str, int]:
    units = (ledger or {}).get("units") or {}
    stats = {"unseen": 0, "probed": 0, "answered": 0, "blocked": 0, "total": 0}
    for u in units.values():
        if not isinstance(u, dict):
            continue
        st = str(u.get("status") or "unseen")
        if st not in stats:
            st = "unseen"
        stats[st] += 1
        stats["total"] += 1
    return stats


def ready_for_degraded_exit(case_dir: str | os.PathLike | None) -> bool:
    """Soft finish floor: belief progress (when tasks open) **and** no unseen HV.

    Empty ledger (no inventory yet / no HV units) does **not** unlock exit —
    only an explicit empty-after-build with meta.unit_count==0 after inventory
    can unlock when there is simply nothing to cover.

    Access stage: disk media still pending open (planned/staged/absent)
    blocks the exit floor even when all tabular/EVTX units are probed —
    coverage is not accessibility.

    When ``.atlas/investigation_tasks.json`` exists with tasks:
      - actionable tasks must each be ``blocked_missing_evidence`` or carry
        ``related_claim_ids`` (belief progress), **and**
      - ledger ``unseen == 0`` (inbox-empty no longer waives coverage — B8).
    Without a task store, legacy ``unseen == 0`` remains.
    """
    if not case_dir:
        return True  # no case context — fail-open for non-case loops
    if not isinstance(case_dir, (str, os.PathLike)):
        return True
    root = Path(case_dir)
    if not (root / ".atlas").is_dir():
        return True
    # Require inventory first
    try:
        from core.evidence_inventory_gate import inventory_satisfied
        if not inventory_satisfied(str(root)):
            return False
    except Exception:
        return False

    try:
        from core.evidence_access import media_blocks_degraded_exit
        if media_blocks_degraded_exit(root):
            return False
    except Exception:
        pass

    ledger = load_ledger(root)
    if not ledger.get("units"):
        # Build once; if still empty, allow (nothing high-value to require)
        ledger = build_coverage_ledger(root)
    stats = coverage_stats(ledger)
    if stats["total"] == 0:
        # An empty ledger means "nothing high-value to require" ONLY when the
        # case really has nothing searchable. Unit seeding
        # (_collect_candidate_paths) is tabular-centric: a case whose
        # evidence is raw disk images plus extracted artifacts can build zero
        # units while holding event logs, hives and journals — and this
        # branch then handed it a clean coverage bill. If searchable
        # sources exist, an empty ledger is an under-seeded ledger, not a
        # covered case. Still blocked above when disk media pending open.
        try:
            from core.ioc_pivots import evidence_sources
            if evidence_sources(root):
                return False
        except Exception:  # noqa: BLE001
            pass
        return True

    disposed = stats["unseen"] == 0

    # Task progress gate while inbox has open work (B3). Disposition still
    # required (B8) — claim links / empty inbox never waive unseen HV.
    try:
        from core.investigation_tasks import (
            actionable_tasks,
            list_tasks,
            tasks_path,
        )
        if tasks_path(root).is_file():
            all_tasks = list_tasks(root)
            if all_tasks:
                open_work = actionable_tasks(root)
                if open_work:
                    for t in open_work:
                        if t.get("status") == "blocked_missing_evidence":
                            continue
                        if not (t.get("related_claim_ids") or []):
                            # Unlinked open tasks: only disposition can unlock
                            # (avoid permanent lock when claims never linked).
                            return disposed
                    # All open work has belief progress or blocked_missing —
                    # still need HV disposed.
                    return disposed
                # Inbox cleared — disposition only.
                return disposed
    except Exception:
        pass

    return disposed


def exit_block_reason(case_dir: str | os.PathLike | None) -> str:
    """Why the coverage floor is not met, in one sentence — "" when it is.

    The single verdict every report gate reads. ``reason.pre_report_check``
    used to append a blocker only when it could *name* unseen units, so a
    ledger with no units at all sailed through as ready while
    ``atlas_finish`` — reading the same state — classified the run
    ``incomplete_coverage``. A gate that trusts
    the verdict cannot disagree with another gate that trusts the verdict.
    """
    if not case_dir or ready_for_degraded_exit(case_dir):
        return ""
    root = Path(case_dir)
    # Concrete unseen units come first: they are the work, whatever else is
    # also true of the case.
    gaps = open_unit_paths(root, limit=6)
    if gaps:
        stats = coverage_stats(load_ledger(root))
        n = stats["unseen"] or len(gaps)
        units = (load_ledger(root).get("units") or {}).values()
        by_path = {str(u.get("path")): u for u in units if isinstance(u, dict)}
        return (f"{n} high-value evidence unit(s) were never examined: "
                + "; ".join(_gap_label(by_path.get(p, {"path": p})) for p in gaps))
    try:
        from core.evidence_inventory_gate import inventory_satisfied
        if not inventory_satisfied(str(root)):
            return ("the evidence inventory has not been run "
                    "(misc.inventory_evidence)")
    except Exception:  # noqa: BLE001
        pass
    try:
        from core.evidence_access import media_blocks_degraded_exit
        if media_blocks_degraded_exit(root):
            return ("disk media is still pending open — see "
                    ".atlas/mount_plan.json")
    except Exception:  # noqa: BLE001
        pass
    stats = coverage_stats(load_ledger(root))
    if stats["total"] == 0:
        n = 0
        try:
            from core.ioc_pivots import evidence_sources
            n = len(evidence_sources(root))
        except Exception:  # noqa: BLE001
            pass
        return (f"the coverage ledger holds no units while {n} searchable "
                "source(s) exist under evidence/, analysis/ and exports/ — "
                "it is under-seeded, not covered (coverage.coverage_report "
                "rebuilds it)")
    return ("open investigation tasks have no recorded progress "
            "(misc.update_investigation_task)")


def open_units(case_dir: str | os.PathLike, *, limit: int = 12) -> list[dict]:
    ledger = load_ledger(case_dir)
    unseen = [
        u for u in (ledger.get("units") or {}).values()
        if isinstance(u, dict) and u.get("status") == "unseen" and u.get("path")
    ]
    return unseen[:limit]


def open_unit_paths(case_dir: str | os.PathLike, *, limit: int = 12) -> list[str]:
    return [str(u.get("path")) for u in open_units(case_dir, limit=limit)]


def _gap_label(unit: dict) -> str:
    """A unit named for the blocker: a derived unit carries what it holds,
    since its path alone says nothing about why it must be looked at."""
    path = str(unit.get("path"))
    if unit.get("kind") == "derived" and unit.get("reason"):
        return f"{path} ({unit['reason']})"
    return path


# ── Derived outputs: what a tool produced is evidence too ─────────────
#
# An extraction, a carve or an export fills a directory the case did not
# come with. Nothing seeded a ledger unit for it, so a run could produce
# many files and finish without opening one. A successful call that
# names an output directory registers it as a unit of kind "derived", with
# what it holds in the reason, and a look at any file inside counts as
# probing it.

_DERIVED_SCAN_CAP = 20_000
_DERIVED_ROOTS = ("analysis/", "exports/")


def _describe_dir(abs_dir: Path) -> str:
    """``"N files: 12 jpg, 3 gif"`` for a directory, "" when it is empty.
    Scans at most _DERIVED_SCAN_CAP entries."""
    counts: dict[str, int] = {}
    total = 0
    for _root, _dirs, files in os.walk(abs_dir):
        for name in files:
            total += 1
            ext = name.rsplit(".", 1)[-1].lower() if "." in name[1:] else "no extension"
            counts[ext] = counts.get(ext, 0) + 1
            if total >= _DERIVED_SCAN_CAP:
                break
        if total >= _DERIVED_SCAN_CAP:
            break
    if not total:
        return ""
    top = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    summary = ", ".join(f"{n} {ext}" for ext, n in top[:6])
    if len(top) > 6:
        summary += ", ..."
    cap = "+" if total >= _DERIVED_SCAN_CAP else ""
    return f"{total}{cap} files: {summary}"


def _derived_candidates(arguments: dict, result: dict) -> list[str]:
    from core.paths import _OUTPUT_PARAM_NAMES
    out: list[str] = []
    for key in _OUTPUT_PARAM_NAMES:
        val = arguments.get(key)
        if isinstance(val, str) and val:
            out.append(val)
    val = result.get("output_dir")
    if isinstance(val, str) and val:
        out.append(val)
    arts = result.get("artifact_paths")
    if isinstance(arts, list):
        out.extend(os.path.dirname(a) for a in arts if isinstance(a, str) and "/" in a)
    return out


def _parse_result(result_text: str | None) -> Optional[dict]:
    """The JSON body of a rendered tool result, None for a failure."""
    text = result_text or ""
    if text.startswith(("TOOL ERROR", "ERROR")):
        return None
    idx = text.find("{")
    if idx < 0:
        return {}
    try:
        parsed = json.loads(text[idx:])
    except ValueError:
        return {}
    if not isinstance(parsed, dict):
        return {}
    return None if parsed.get("success") is False else parsed


def register_derived_outputs(
    case_dir: str | os.PathLike | None,
    *,
    tool_name: str,
    arguments: dict | None,
    result_text: str | None,
) -> list[str]:
    """Add a ledger unit for each directory under analysis/ or exports/
    that a successful tool call filled. Returns the case-relative paths
    added; a directory already in the ledger is left as it is."""
    if not case_dir or not (Path(case_dir) / ".atlas").is_dir():
        return []
    result = _parse_result(result_text)
    if result is None:
        return []
    args = arguments if isinstance(arguments, dict) else {}
    root = Path(case_dir).resolve()
    added: list[str] = []
    ledger: Optional[dict] = None
    for cand in _derived_candidates(args, result):
        abs_dir = Path(cand) if os.path.isabs(cand) else root / cand
        try:
            abs_dir = abs_dir.resolve()
        except OSError:
            continue
        if not abs_dir.is_dir():
            continue
        try:
            rel = abs_dir.relative_to(root).as_posix()
        except ValueError:
            continue
        if not rel.startswith(_DERIVED_ROOTS) or is_noise_path(rel):
            continue
        summary = _describe_dir(abs_dir)
        if not summary:
            continue
        if ledger is None:
            ledger = load_ledger(root)
        units = ledger.setdefault("units", {})
        if _unit_id(rel) in units:
            continue
        source = source_rel = ""
        from core.paths import INPUT_PATH_PARAM_NAMES
        # The archive tools name their input archive_path.
        for key in (*INPUT_PATH_PARAM_NAMES, "archive_path"):
            val = args.get(key)
            if isinstance(val, str) and val:
                source = os.path.basename(val.rstrip("/")) or val
                source_rel = _norm_rel(val)
                break
        reason = f"produced by {tool_name}" + (f" from {source}" if source else "") + f"; {summary}"
        _add_unit(units, rel, kind="derived", reason=reason)
        if source_rel and _unit_id(rel) in units:
            # What the directory was made from, case-relative: an archive
            # item is read through the folders it was extracted to.
            units[_unit_id(rel)]["source_rel"] = source_rel
        added.append(rel)
    if added and ledger is not None:
        save_ledger(root, ledger)
    return added


# ── B8: task answered ↔ relevant HV disposition ──────────────────────────

# ponytail: an English phrase list decides how broad a question is; the
# upgrade is a scope the model declares on the task.
_CATCH_ALL_TASK_RE = re.compile(
    r"(?i)\b(?:"
    r"beyond|any other|additional (?:accounts?|hosts?|attacker|activity)|"
    r"other attacker|identify any other|further movements?|"
    r"other hosts?|visible in the evidence (?:package|set|collection)"
    r")\b"
)

# Broad host/system questions (not a narrow question about one log source).
_BROAD_SYSTEM_RE = re.compile(
    r"(?i)\b(?:"
    r"what happened|how did .+ get (?:in|there)|"
    r"was the (?:\w+ )?(?:file ?server|server|host|system|machine|workstation|domain controller) compromised|"
    r"lateral (?:movement|authentication)|"
    r"attacker activity visible"
    r")\b"
)

_IP_TOKEN_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_PATH_TOKEN_RE = re.compile(
    r"(?i)(?:[A-Za-z]:\\[^\s\"']+|"
    r"[\w.\-]+\.(?:evtx|csv|vmdk|E01))"
)
_WORD_TOKEN_RE = re.compile(r"\b([A-Za-z][A-Za-z0-9_\-]{2,})\b")

_TOKEN_STOP = frozenset({
    "the", "and", "for", "was", "were", "are", "can", "what", "when", "where",
    "that", "this", "with", "from", "into", "onto", "than", "then", "them",
    "they", "have", "has", "had", "been", "being", "also", "any", "all",
    "other", "beyond", "above", "below", "identify", "investigate", "activity",
    "suspicious", "attacker", "account", "accounts", "known", "given", "there",
    "further", "movements", "hosts", "host", "domain", "domains", "files",
    "file", "text", "two", "how", "did", "get", "visible", "evidence",
    "package", "items", "additional", "compromised", "firewall", "logs",
    "logons", "authentication", "lateral", "movement", "pass", "the",
    "smb", "rdp", "winrm", "via", "using", "between", "across", "multiple",
})


def _host_stem(token: str) -> Optional[str]:
    """Alphabetic host stem, so a task naming ``file-srv02`` matches
    ``…/FILESRV02-flat.vmdk/…``."""
    t = (token or "").lower().replace("-", "")
    if not re.match(r"^[a-z][a-z0-9]+$", t):
        return None
    if not re.search(r"\d", t):
        return None
    stem = re.sub(r"\d+$", "", t)
    return stem if len(stem) >= 4 else None


def _extract_task_tokens(task_text: str) -> list[str]:
    text = task_text or ""
    out: list[str] = []
    for m in _IP_TOKEN_RE.finditer(text):
        out.append(m.group(0))
    for m in _PATH_TOKEN_RE.finditer(text):
        out.append(m.group(0))
    for m in _WORD_TOKEN_RE.finditer(text):
        w = m.group(1)
        if w.lower() in _TOKEN_STOP:
            continue
        if len(w) < 3:
            continue
        out.append(w)
    # Dedupe preserving order
    seen: set[str] = set()
    uniq: list[str] = []
    for t in out:
        key = t.lower()
        if key in seen:
            continue
        seen.add(key)
        uniq.append(t)
    return uniq


def _token_matches_path(token: str, path: str) -> bool:
    t = (token or "").lower().replace("\\", "/")
    p = (path or "").lower().replace("\\", "/")
    if not t or not p:
        return False
    if t in p:
        return True
    # Windows path fragment without drive
    t_base = t.rstrip("/").split("/")[-1]
    if len(t_base) >= 4 and t_base in p:
        return True
    stem = _host_stem(token)
    if stem and stem in p.replace("-", ""):
        return True
    return False


def relevant_ledger_units(
    case_dir: str | os.PathLike | None,
    task_text: str,
    *,
    task_id: Optional[str] = None,
) -> list[dict[str, Any]]:
    """HV units in scope for answering ``task_text`` (no artifact-name hardcode)."""
    if not case_dir:
        return []
    ledger = load_ledger(case_dir)
    units = [
        u for u in (ledger.get("units") or {}).values()
        if isinstance(u, dict) and u.get("path")
    ]
    if not units:
        return []
    text = task_text or ""
    catch_all = bool(_CATCH_ALL_TASK_RE.search(text))
    if catch_all:
        return units

    tokens = _extract_task_tokens(text)
    matched: list[dict[str, Any]] = []
    if tokens:
        for u in units:
            path = str(u.get("path") or "")
            if any(_token_matches_path(tok, path) for tok in tokens):
                matched.append(u)

    if matched:
        return matched

    if task_id:
        linked = [
            u for u in units
            if task_id in (u.get("task_ids") or [])
        ]
        if linked:
            return linked

    # Broad system questions with no path hit → all HV.
    # Narrow product questions (one firewall or VPN log) stay unconstrained here.
    if _BROAD_SYSTEM_RE.search(text):
        return units
    return []


def refuse_answered_unseen_coverage(
    case_dir: str | os.PathLike | None,
    task_text: str,
    *,
    task_id: Optional[str] = None,
    limit: int = 8,
) -> Optional[str]:
    """Refuse task ``answered`` while relevant ledger units remain ``unseen``.

    Escape: a read of each (probed), or ``coverage.mark_blocked`` once a read
    of one has failed.
    """
    if not case_dir:
        return None
    try:
        relevant = relevant_ledger_units(
            case_dir, task_text, task_id=task_id,
        )
    except Exception:
        return None
    pending = [u for u in relevant if str(u.get("status") or "unseen") == "unseen"]
    unseen = [str(u.get("path")) for u in pending]
    if not unseen:
        return None
    sample = ", ".join(unseen[:limit])
    more = f" (+{len(unseen) - limit} more)" if len(unseen) > limit else ""
    return (
        "relevant_coverage_unseen: cannot mark task answered while "
        f"{len(unseen)} relevant high-value coverage unit(s) remain unseen "
        f"[{sample}{more}]. Read each one ({_read_hints(pending)}). "
        "coverage.mark_blocked is for a unit whose read failed; it records "
        "that failure and does not replace the read. Claims alone are not "
        "disposition."
    )


def _any_path_match(unit_path: str, norms: set[str]) -> bool:
    """Path-identity match between a ledger unit and normalised input paths.

    Exact case-relative equality, or a suffix match at a path-segment
    boundary (covers absolute inputs whose ``evidence/`` anchor could not be
    stripped). Bare-basename matching is deliberately NOT supported: probing
    ``WS01/.../Security.evtx`` must never mark ``WS02/.../Security.evtx``.
    """
    for n in norms:
        if n == unit_path:
            return True
        if "/" in n and (
                unit_path.endswith("/" + n) or n.endswith("/" + unit_path)):
            return True
    return False


def _source_images_for(root: Path, paths: list[str],
                       plan: Optional[dict] = None) -> set[str]:
    """Normalised paths of the images the given paths reach.

    A run stops naming the image the moment it has a raw export: every later
    `fls`, `icat` and carve targets ``exports/<name>.raw``. It never names it
    either once the filesystem is mounted: every read targets a file under
    ``mnt/<stem>/fs`` or the device ``mnt/<stem>/ewf/ewf1``. Without this the
    container unit for the image would sit "unseen" through an entire
    investigation of its own filesystem, and the run would be sent back to
    touch the container for the ledger's sake. A caller resolving many calls
    passes the access plan it loaded once.
    """
    out: set[str] = set()
    try:
        from core.mount_plan import load_mount_plan, mount_dir_for
        if plan is None:
            plan = load_mount_plan(root)
    except Exception:  # noqa: BLE001
        return out
    wanted = {os.path.basename(str(p)).casefold() for p in paths if p}
    root_real = os.path.realpath(str(root))
    absolutes = []
    for p in paths:
        p = str(p or "")
        if p:
            absolutes.append(os.path.realpath(p if os.path.isabs(p) else os.path.join(root_real, p)))
    for img in plan.get("images") or []:
        if not isinstance(img, dict):
            continue
        source = str(img.get("source") or "")
        path = str(img.get("path") or "")
        if source and path and os.path.basename(path).casefold() in wanted:
            out.add(_norm_rel(source).casefold())
        if not path:
            continue
        mr = img.get("mount_result") or {}
        reach = [str(mr.get("mount_point") or ""), str(mr.get("ewf_device") or ""),
                 mount_dir_for(root_real, path, img)]
        reach = [os.path.realpath(r) for r in reach if r]
        if any(a == r or a.startswith(r + os.sep) for a in absolutes for r in reach):
            out.add(_norm_rel(path).casefold())
    return out


def mark_paths(
    case_dir: str | os.PathLike,
    paths: list[str],
    *,
    status: str = "probed",
    note: str = "",
    tool: str = "",
    call_id: str = "",
) -> dict[str, Any]:
    """Mark matching ledger units, and credit the evidence items the paths
    lie under (core.evidence_items); returns updated ledger."""
    root = Path(case_dir).resolve()
    ledger = load_ledger(root)
    units = ledger.setdefault("units", {})
    if not units:
        ledger = build_coverage_ledger(root)
        units = ledger.setdefault("units", {})

    norms = {_norm_rel(p).casefold() for p in paths if p}
    norms.discard("")
    norms |= _source_images_for(root, paths)
    changed = False
    for u in units.values():
        if not isinstance(u, dict):
            continue
        up = str(u.get("path") or "").replace("\\", "/").casefold()
        if not _any_path_match(up, norms) and not (
                u.get("kind") == "derived" and any(n.startswith(up + "/") for n in norms)):
            continue
        cur = u.get("status") or "unseen"
        # A finding that names a unit is the analyst's words, not a read: it
        # answers a unit a call has read and moves no other off its status.
        if status == "answered" and cur not in ("probed", "answered"):
            continue
        # answered stays; a read replaces blocked, which records a failed
        # examination and is no longer true once one succeeds.
        if status == "probed" and cur in ("probed", "answered"):
            continue
        rank = {"unseen": 0, "probed": 1, "answered": 2, "blocked": 2}
        if (status == "probed" and cur == "blocked") or rank.get(status, 0) >= rank.get(cur, 0):
            u["status"] = status
            u["probed_at"] = _utcnow()
            if note:
                u["note"] = note
            elif cur == "blocked":
                u["note"] = ""
            changed = True
    if status in ("probed", "answered"):
        try:
            from core.evidence_items import observe
            changed = observe(ledger, root, paths, tool=tool, call_id=call_id) or changed
        except Exception:  # noqa: BLE001 - the units stand without the items
            pass
    if changed:
        save_ledger(root, ledger)
    return ledger


# Extracted artifacts are named relative to analysis/ and exports/, so a
# regex anchored on evidence/ simply could not see a probe of them — units
# for run extracts would have stayed unseen forever. A mounted image is
# read under mnt/ the same way (see _CASE_SUBDIRS).
_CASE_REL_PREFIX = "(?:evidence|analysis|exports|mnt)"
_PATH_IN_TEXT = re.compile(
    rf"(?:{_CASE_REL_PREFIX}/[A-Za-z0-9._\-/%]+|"
    r"/[A-Za-z0-9._\-]+(?:/[A-Za-z0-9._\-]+)+|"
    r"[A-Za-z]:\\[\\A-Za-z0-9._\-]+)"
)
_CASE_REL_TOKEN = re.compile(rf"{_CASE_REL_PREFIX}/[^\s\"']+")

# Tools that enumerate/inspect evidence layout without examining content.
# Their calls (and especially their output) must not count as coverage:
# listing a directory that *mentions* Security.evtx is not probing it
#
NON_PROBE_TOOLS = frozenset({
    "misc_list_evidence_dir",
    "misc_inventory_evidence",
    "misc_current_investigation_state",
    # A stat reads no byte of the file. It was the box an analyst ticked
    # when the ledger would not credit the reads it had made through the
    # image's mount, and it left the image "probed" by its size and dates.
    "strings_stat_file",
    # A disk or memory image is examined when a call reaches a file inside
    # it, or for memory the structures a plugin walks. A call that reads no
    # file inside the container identifies it; it does not examine it.
    # Counted as probes, such a call would close the coverage floor over an
    # image whose files nobody has read.
    "tsk_mmls",               # the partition table
    "tsk_mmstat",             # the partition table's type
    # The filesystem opens, no file in it is read. It still opens the media
    # for the Access Stage (core.evidence_access): access asks whether the
    # filesystem opens, coverage whether a file inside it was reached.
    "tsk_fsstat",
    "vol_symbol_check",       # the file's existence and the symbol cache
    "ewf_info",               # the container's acquisition metadata
    "ewf_verify",             # integrity: every byte read, nothing learned
    "img_vmdk_chain_info",    # the snapshot chain's descriptors
    "img_bde_info",           # the encryption metadata
    # A conversion reads every byte and learns nothing; the export is
    # registered with its source image, so a read of the export credits it.
    "img_vmdk_export_raw",
    # Mounting stays a probe: later reads name only the mount point or the
    # device, and the plan maps those back to the image only under the
    # mnt/<stem>/ convention, so for a mount elsewhere the binding call is
    # the one contact the image gets.
})
# Namespaces whose tools read a unit without examining it. An integrity hash
# reads every byte to compare and learns nothing about the content; a run
# that had only hashed its disk images would be told it had nothing left
# unseen, and spend its turns on the tabular sources instead.
NON_PROBE_NAMESPACES = ("hash",)


def listed_tool_name(tool_name: str) -> str:
    """``tool_name`` as the tool list spells it. A trace names a tool by its
    server name (``tsk_tsk_mmls``, ``<py>:hash_hash_file``), the playbook by
    its dotted alias (``tsk.mmls``); the lists above hold the listed form."""
    name = (tool_name or "").strip()
    if name.startswith("<py>:"):
        name = name[len("<py>:"):]
    name = name.replace(".", "_")
    namespace, _, rest = name.partition("_")
    return rest if rest.startswith(namespace + "_") else name


def is_probe_tool(tool_name: str) -> bool:
    """Whether a call to ``tool_name`` counts as examining its input paths.
    Any spelling of the name does (listed, dotted or the server's)."""
    name = listed_tool_name(tool_name)
    if name in NON_PROBE_TOOLS:
        return False
    return name.split("_", 1)[0] not in NON_PROBE_NAMESPACES


# A listing, a stat, an identification or a hexdump names a path without
# reading the source's content.
_LISTING_TOOL_RE = re.compile(r"(?:^|_)(?:list|ls|stat|identify|inventory|fls|mmls|ils|hexdump|find)(?:_|$)")


def reads_content(tool_name: str) -> bool:
    """Whether a call to ``tool_name`` read the content of the paths it
    names: a probe (is_probe_tool) that is not a listing of them."""
    name = listed_tool_name(tool_name)
    return is_probe_tool(name) and not _LISTING_TOOL_RE.search(name)


def unseen_unit_paths_of_kind(case_dir: str | os.PathLike | None,
                              kind: str) -> list[str]:
    """Paths of the ledger's unseen units of one evidence kind, e.g. disk."""
    if not case_dir:
        return []
    try:
        units = (load_ledger(case_dir).get("units") or {}).values()
    except Exception:  # noqa: BLE001 - no ledger, nothing unseen to report
        return []
    return [str(u.get("path")) for u in units
            if isinstance(u, dict) and u.get("status") == "unseen"
            and str(u.get("kind") or "") == kind and u.get("path")]


def unseen_container_units(case_dir: str | os.PathLike | None) -> list[str]:
    """Paths of intake containers (disk and memory images) nobody has opened."""
    return unseen_unit_paths_of_kind(case_dir, CONTAINER_KIND)


def _blob_paths(blob: str) -> list[str]:
    """The path tokens in a tool cmd/args blob, as written."""
    found = list(_PATH_IN_TEXT.findall(blob or ""))
    found += [tok.rstrip("\",')}") for tok in _CASE_REL_TOKEN.findall(blob or "")]
    return [p for p in found if p]


def _paths_mentioned_in_blob(blob: str) -> set[str]:
    """Normalised path tokens from a tool cmd/args blob (path identity)."""
    norms = {_norm_rel(p).casefold() for p in _blob_paths(blob)}
    norms.discard("")
    return norms


# A trace entry of an analyst's tool call names its tool (``mcp_tool``, or
# ``<py>:<tool>`` as the command). A bare program or path as the command is
# a call the pre-run pass made itself; it examines nothing for the analyst.
_TOOL_NAME_RE = re.compile(r"^[a-z][a-z0-9]*_[a-z0-9_]+$")


def _entry_tool(entry: dict) -> str:
    """The listed name of the analyst tool a trace entry records, "" when no
    analyst tool made the call."""
    name = str(entry.get("mcp_tool") or "")
    if not name:
        cmd = str(entry.get("cmd") or "").split()
        first = cmd[0] if cmd else ""
        if first.startswith("<py>:") or _TOOL_NAME_RE.match(first):
            name = first
    return listed_tool_name(name) if name else ""


def _unit_rel(unit_path: str) -> str:
    """A unit's case-relative identity for path matching, "" for a bare name:
    a basename alone would match another host's identically named file."""
    up = str(unit_path or "").replace("\\", "/").casefold()
    if up and not up.startswith(_CASE_SUBDIRS):
        up = _norm_rel(up).casefold()
    return up if "/" in up else ""


def _entry_view(root: Path, entry: dict, plan: Optional[dict]) -> tuple:
    """What a trace entry names, worked out once per entry: its normalised
    paths, its text, and the images it reaches through the mount or export
    the access plan ties to them. A Python tool's command holds no path; its
    recorded arguments and evidence reference do."""
    blob = " ".join(str(entry.get(k) or "") for k in ("cmd", "args", "evidence_ref"))
    raw = _blob_paths(blob)
    norms = {_norm_rel(p).casefold() for p in raw} - {""}
    images = _source_images_for(root, raw, plan) if raw else set()
    return norms, blob.casefold().replace("\\", "/"), images


def _view_reaches(view: tuple, up: str) -> bool:
    """Whether an entry (its _entry_view) names the unit ``up``: by path
    identity (exact case-relative path or a path-segment suffix, never a
    bare basename; the whole path inside quoted or JSON arguments the token
    regex split apart counts too), or as the image a mount or export read
    belongs to."""
    norms, text, images = view
    return bool(up) and ((bool(norms) and _any_path_match(up, norms))
                         or up in text or up in images)


def _entry_reaches(root: Path, entry: dict, up: str, plan: Optional[dict]) -> bool:
    return _view_reaches(_entry_view(root, entry, plan), up)


# A filesystem that does not open is a failed read of its image; one that
# opens has not been read yet (NON_PROBE_TOOLS).
_OPEN_ATTEMPT_TOOLS = frozenset({"tsk_fsstat"})


def _read_attempts(root: Path, trace_entries: list[dict] | None,
                   plan: Optional[dict] = None) -> list[tuple[dict, tuple]]:
    """The analyst's calls in the trace that tried to read something (an
    examining tool, or an attempt to open an image's filesystem), with what
    each names. A call in the analyst's own words (a finding, a coverage
    verdict) names a path without reading it."""
    if plan is None:
        try:
            from core.mount_plan import load_mount_plan
            plan = load_mount_plan(root)
        except Exception:  # noqa: BLE001 - path identity still applies
            plan = {}
    from core.forensic_citation import own_words_entry
    out: list[tuple[dict, tuple]] = []
    for e in trace_entries or []:
        if e.get("type") != "tool_call" or own_words_entry(e):
            continue
        tool = _entry_tool(e)
        if tool and (is_probe_tool(tool) or tool in _OPEN_ATTEMPT_TOOLS):
            out.append((e, _entry_view(root, e, plan)))
    return out


def _calls_reaching(root: Path, unit_path: str, trace_entries: list[dict] | None,
                    plan: Optional[dict] = None) -> list[dict]:
    """The read attempts in the trace (_read_attempts) that named
    ``unit_path``, successful or not."""
    up = _unit_rel(unit_path)
    if not up:
        return []
    return [e for e, view in _read_attempts(root, trace_entries, plan)
            if _view_reaches(view, up)]


# A failed call is an attempt at the unit when the tool ran on it and failed.
# One an Atlas gate turned away, one with invalid arguments and a search
# verb's "no match" exit examined nothing. A gate that reports the unit's own
# emptiness is the exception: it looked at the unit and found nothing in it.
_NOT_AN_ATTEMPT = frozenset({"gate_refusal", "analyst_error", "expected_nonzero"})
_UNIT_STATE_GATES = ("[empty_tabular]",)


def _failed_attempt(entry: dict) -> bool:
    if entry.get("success") is not False:
        return False
    if str(entry.get("failure_class") or "") not in _NOT_AN_ATTEMPT:
        return True
    return str(entry.get("stderr") or "").startswith(_UNIT_STATE_GATES)


_NO_FS_TEXT = "cannot determine file system type"
_OFFSET_ARG_RE = re.compile(r"(?:^|\s)-o\s")
# A Python tool's recorded arguments (a JSON text, possibly cut short, or a
# mapping) naming a volume offset other than the first sector.
_OFFSET_KWARG_RE = re.compile(r"""(?:^|[\s{,"'])(?:offset_sectors|offset)["']?\s*:\s*["']?[1-9]""")


def _offset_given(entry: dict) -> bool:
    """Whether a read named a volume offset: ``-o`` on its command line, or
    a non-zero ``offset_sectors``/``offset`` among a Python tool's recorded
    arguments (the rule tools/sleuthkit applies to the call itself).

    The middleware keeps a call's arguments as JSON cut at 400 characters,
    keys sorted: a very long image path can push ``offset_sectors`` out of
    it and the record reads as "no offset". The program's own record of the
    same read (``fls -o N ...``) normally still names it, and a miss at the
    first sector needs every failed record to look offset-less."""
    return bool(_OFFSET_ARG_RE.search(str(entry.get("cmd") or ""))
                or _OFFSET_KWARG_RE.search(str(entry.get("args") or "")))


def _misses_at_sector_zero(root: Path, unit_path: str, failed: list[dict],
                           trace_entries: list[dict] | None,
                           plan: Optional[dict]) -> bool:
    """Every failed read of an image looked for a filesystem at its first
    sector while tsk.mmls found a partition table on it. Those reads asked
    the wrong place and say nothing about the volume."""
    if not failed or not all(
            _NO_FS_TEXT in f"{e.get('stderr') or ''} {e.get('error') or ''}".casefold()
            and not _offset_given(e)
            for e in failed):
        return False
    up = _unit_rel(unit_path)
    return any(e.get("type") == "tool_call" and e.get("success") is True
               and _entry_tool(e) in ("tsk_mmls", "tsk_mmstat")
               and _entry_reaches(root, e, up, plan)
               for e in trace_entries or [])


# What reading a unit means, by the ledger's kind, for the texts that ask
# for a read: an image's own description is not a read of it.
_KIND_LABEL = {CONTAINER_KIND: "an image", "tabular": "a table",
               "eventlog": "an event log", "derived": "an extraction folder"}


def read_hint(kind: str) -> str:
    """How a unit of the ledger kind ``kind`` is read."""
    if kind == CONTAINER_KIND:
        return ("open its filesystem: tsk.fls or tsk.resolve_path (a single "
                "volume is found by itself; tsk.mmls lists the offsets when "
                "there are several), a mount or an export; for a memory image "
                "a vol.* plugin. tsk.mmls, tsk.fsstat and vol.symbol_check "
                "identify an image without reading a file in it")
    if kind == "tabular":
        return "query it with table.table_query or table.table_grep (table.table_schema first)"
    if kind == "eventlog":
        return "parse it with an event-log parser"
    if kind == "derived":
        return "read a file inside it with an applicable tool"
    return "parse it with the tool for its file type"


def _read_hints(units: list[dict]) -> str:
    """One clause per kind among ``units``: how each is read."""
    kinds = list(dict.fromkeys(str(u.get("kind") or "") for u in units))
    if len(kinds) == 1:
        return read_hint(kinds[0])
    return "; ".join(f"{_KIND_LABEL.get(k, 'a file')}: {read_hint(k)}" for k in kinds)


def open_units_read_hint(case_dir: str | os.PathLike | None, *, limit: int = 8) -> str:
    """How the case's unseen units are read, one clause per kind, for the
    nudges and gates that name them; every kind's way when the ledger names
    none of them."""
    units = open_units(case_dir, limit=limit) if case_dir else []
    return _read_hints(units or [{"kind": k} for k in (CONTAINER_KIND, "tabular", "")])


# The tool a work order names first for a kind of unit; a memory image is
# a container like a disk image but is read by a plugin.
_READ_TOOL = {"image": "tsk.fls", "memory": "vol.pslist", "tabular": "table.table_query"}


def read_tools(case_dir: str | os.PathLike | None, *, limit: int = 8) -> list[str]:
    """The tools that read the case's unseen units, one per kind."""
    if not case_dir:
        return []
    ledger = load_ledger(case_dir)
    from core.evidence_items import find as _find_item
    tools: list[str] = []
    for u in open_units(case_dir, limit=limit):
        kind = str(u.get("kind") or "")
        if kind == CONTAINER_KIND:
            kind = str((_find_item(ledger, str(u.get("path") or "")) or {}).get("kind") or "image")
        tool = _READ_TOOL.get(kind)
        if tool and tool not in tools:
            tools.append(tool)
    return tools


def _is_tabular_tool(tool_name: str) -> bool:
    n = (tool_name or "").casefold().replace(".", "_")
    return n.startswith("table_") or n.startswith("table.")


def tabular_contact_ok(tool_name: str, result_text: str) -> bool:
    """True when a table.* result is real schema/query contact.

    ``unknown_columns`` / failed payloads must not advance coverage.
    Successful schema, or query/grep/pivot with valid columns (including
    legitimate zero-row negatives), counts as contact.
    """
    if not _is_tabular_tool(tool_name):
        return True
    text = (result_text or "").strip()
    if text.startswith(("TOOL ERROR", "ERROR", "TOOL INFO")):
        return False
    try:
        data = json.loads(text)
    except Exception:
        # Non-JSON success envelopes still go through observe via ``success``.
        return True
    if not isinstance(data, dict):
        return True
    if data.get("gate") in (
        "unknown_columns",
        "wrong_input_kind",
        "unsupported_where_dialect",
        "non_numeric_compare",
        "empty_tabular",
    ):
        return False
    if data.get("success") is False:
        return False
    # Zero-match filtered queries are truthful negatives, not coverage probes.
    # Schema results have no matched_rows/valid_zero — those still count.
    if data.get("valid_zero") is True or data.get("matched_rows") == 0:
        return False
    return True


def observe_tool_paths(
    case_dir: str | os.PathLike | None,
    *,
    tool_name: str = "",
    cmd_or_args: str = "",
    success: bool = True,
    result_text: str | None = None,
) -> Optional[dict[str, Any]]:
    """Mark ledger units probed when a successful tool call TARGETS their
    paths.

    ``cmd_or_args`` must contain only the tool's resolved arguments — never
    tool output. Paths that merely appear in result text (directory listings,
    refusal messages, search hits) are not probes; feeding output here forges
    the coverage floor and unlocks degraded exit without real work.

    For ``table.*`` tools, ``result_text`` is consulted so unknown-column /
    empty forged probes do not mark coverage.
    """
    if not case_dir or not success:
        return None
    if not is_probe_tool(tool_name or ""):
        return None
    if result_text is not None and not tabular_contact_ok(tool_name, result_text):
        return None
    found = _blob_paths(f"{tool_name} {cmd_or_args}")
    if not found:
        return None
    status = "probed"
    # A finding that names a unit answers it once a call has read it
    # (mark_paths).
    if "record_finding" in (tool_name or ""):
        status = "answered"
    try:
        from core.call_memo import trace_call_id_of
        return mark_paths(case_dir, found, status=status, tool=tool_name or "",
                          call_id=trace_call_id_of(result_text or ""))
    except Exception:
        return None


_WORK_ORDER_RE = re.compile(
    r"(?i)winevt|security\.evtx|secevent\.evt|terminalservices|security event log")


def mark_work_order_blocked(case_dir: str | os.PathLike, name: str, *,
                            reason: str) -> dict[str, Any]:
    """Disposition an access-workflow work order (the Security event log …)
    that is not a ledger unit. Guarded like a unit: the trace must show a real
    attempt at it first."""
    key = str(name or "").strip()
    if not _WORK_ORDER_RE.search(key):
        return {"success": False, "error": f"{key!r} is not a known work order"}
    try:
        from core.access_workflow import _trace_cmd_blobs, _case_root
        from core.evidence_access import winevt_search_attempted_in_cmds
        root = _case_root(case_dir)
        attempted = bool(root) and winevt_search_attempted_in_cmds(_trace_cmd_blobs(root))
    except Exception:  # noqa: BLE001
        attempted = False
    if not attempted:
        from core.eventlog_layout import locations
        return {"success": False,
                "error": (f"work order {key!r} cannot be blocked before a real attempt: "
                          f"resolve or list the log directory ({locations()}), search "
                          "the $MFT for it, or parse a log first.")}
    ledger = load_ledger(case_dir)
    orders = ledger.setdefault("meta", {}).setdefault("blocked_work_orders", {})
    orders[key] = {"reason": (reason or "")[:400], "at": _utcnow()}
    save_ledger(case_dir, ledger)
    return {"success": True, "work_order": key, "status": "blocked", "reason": orders[key]["reason"]}


def _partly_examined_under(root: Path, unit_rel: str) -> list[dict[str, Any]]:
    """Series under ``unit_rel`` that the trace shows read in part.

    The same view ``investigation_obligations`` reports as
    ``evidence_sets_complete``: a numbered series with some members named
    by a tool call and others never touched.
    """
    if not unit_rel:
        return []
    try:
        from core.source_sets import partially_examined_series
        partial = partially_examined_series(root, limit=500)
    except Exception:  # noqa: BLE001 - no series view, nothing to refuse on
        return []
    low = unit_rel.casefold()
    out: list[dict[str, Any]] = []
    for s in partial:
        d = str(s.get("directory") or "").replace("\\", "/").rstrip("/").casefold()
        if d == low or d.startswith(low + "/"):
            out.append(s)
    return out


def mark_unit_blocked(
    case_dir: str | os.PathLike,
    path: str,
    *,
    reason: str,
    trace_entries: list[dict] | None = None,
) -> dict[str, Any]:
    """Explicitly mark one ledger unit blocked, with an auditable reason.

    Blocked counts toward the degraded-exit floor, so this verb is guarded:
    blocked records a read that failed. The trace must hold a failed call
    of an examining tool on the path, and no successful one. An agent may
    not talk a unit into "blocked" without attempting it, nor block one a
    call has read.
    Returns {success, unit, error?}.
    """
    reason = (reason or "").strip()
    if len(reason) < 8:
        return {
            "success": False,
            "error": ("blocked requires a concrete reason "
                      "(what was attempted and why the unit cannot be "
                      "examined), min 8 chars"),
        }
    root = Path(case_dir).resolve()
    ledger = load_ledger(root)
    units = ledger.get("units") or {}
    norm = _norm_rel(path).casefold()
    target = None
    for u in units.values():
        if not isinstance(u, dict):
            continue
        up = str(u.get("path") or "").replace("\\", "/").casefold()
        if _any_path_match(up, {norm}):
            target = u
            break
    if target is None:
        # A delivered item that is no unit (a capture, an archive, a
        # folder of loose files) is blocked by the same rule.
        from core.evidence_items import find as _find_item
        item = _find_item(ledger, path)
        if item is not None:
            return _block_item(root, ledger, item, reason, trace_entries)
        # Directory prefix? Agents pass whole evidence trees.
        # Blocked is a per-unit verb documenting a FAILED EXAMINATION of that
        # unit; an inapplicable tool is not a coverage gap. Name the actual
        # units under the prefix so the agent can address them individually.
        contained = [
            str(u.get("path"))
            for u in units.values()
            if isinstance(u, dict)
            and str(u.get("path") or "").replace("\\", "/").casefold()
            .startswith(norm.rstrip("/") + "/")
        ]
        if contained:
            return {
                "success": False,
                "error": (
                    f"{path} is a directory prefix, not a ledger unit. "
                    "blocked applies to ONE evidence unit after a real "
                    "failed examination attempt (corrupt/unparseable/"
                    "unsupported format). An unavailable or inapplicable "
                    "TOOL is never a reason to block evidence — probe the "
                    f"units with an applicable tool instead. Units under "
                    f"this prefix: " + "; ".join(contained[:8])
                ),
                "contained_units": contained[:20],
            }
        return {
            "success": False,
            "error": f"no coverage-ledger unit matches path: {path}",
            "open_units": open_unit_paths(root, limit=8),
        }

    # A unit whose members were read in part is demonstrably readable.
    # Blocked records a failed examination and counts toward the exit floor,
    # so accepting it here would close every unread member under that label
    # — the very series the completeness obligation still reports as partly
    # examined. Refuse, and name what is left.
    unit_rel = str(target.get("path") or "").replace("\\", "/").rstrip("/")
    for s in _partly_examined_under(root, unit_rel):
        left = list(s.get("unexamined") or [])
        return {
            "success": False,
            "error": (
                f"refusing to mark blocked: {s['examined']} of {s['total']} "
                f"{s['pattern']} files under {s['directory']} were examined, "
                f"so the unit can be read. blocked documents a failed "
                f"examination and would close the {len(left)} unread ones "
                f"under that label. Examine them, or name each one whose "
                f"examination fails: " + "; ".join(left[:8])
                + (" ..." if len(left) > 8 else "")
            ),
            "unexamined": left[:20],
        }

    # blocked records a failed examination: a unit a call has read is not
    # blocked, and neither is one no call has tried. Calls are matched by
    # path identity, never a bare basename (multi-host EVTX twins).
    unit_path = str(target.get("path") or "")
    kind = str(target.get("kind") or "")
    trace_entries = _trace_or_log(trace_entries, root)
    try:
        from core.mount_plan import load_mount_plan
        plan = load_mount_plan(root)
    except Exception:  # noqa: BLE001 - path identity still applies
        plan = {}
    calls = _calls_reaching(root, unit_path, trace_entries, plan)
    refusal = _blocked_refusal(unit_path, kind, calls)
    if refusal is None and target.get("status") in ("probed", "answered"):
        refusal = (f"refusing to mark blocked: {unit_path} was read; blocked "
                   "records a failed examination, not a partial one.")
    if refusal is None and kind == CONTAINER_KIND and _misses_at_sector_zero(
            root, unit_path, [e for e in calls if _failed_attempt(e)],
            trace_entries, plan):
        refusal = (f"refusing to mark blocked: every failed read of {unit_path} "
                   "looked for a filesystem at the image's first sector ('Cannot "
                   "determine file system type', no offset_sectors) while tsk.mmls "
                   "lists a partition table on it. Read the volume at the "
                   "offset_sectors tsk.mmls gives; that read decides.")
    if refusal is not None:
        return {"success": False, "error": refusal}

    target["status"] = "blocked"
    target["probed_at"] = _utcnow()
    target["note"] = reason[:500]
    from core.evidence_items import find as _find_item
    item = _find_item(ledger, str(target.get("path") or ""))
    if item is not None and item.get("status") != "examined":
        item.update(status="blocked", blocked_reason=reason[:500])
    save_ledger(root, ledger)
    return {"success": True, "unit": dict(target)}


def _trace_or_log(trace_entries: list[dict] | None,
                  root: Optional[Path] = None) -> list[dict]:
    if trace_entries is not None:
        return trace_entries
    try:
        if root is not None:
            from core.execution_log import trace_tool_calls
            return trace_tool_calls(root) or []
        from core.execution_log import log as _elog
        return list(_elog._entries)
    except Exception:  # noqa: BLE001
        return []


def _blocked_refusal(path: str, kind: str, calls: list[dict]) -> Optional[str]:
    """Why ``path`` cannot be blocked on the examining calls that named it,
    None when one of them failed on it and none read it."""
    read = next((e for e in calls if e.get("success") is True
                 and is_probe_tool(_entry_tool(e))), None)
    if read is not None:
        by = f" by call {read['call_id']}" if read.get("call_id") else ""
        return (f"refusing to mark blocked: {path} was read{by}; blocked records "
                "a failed examination, not a partial one.")
    if not any(_failed_attempt(e) for e in calls):
        return (f"refusing to mark blocked: no tool call in the trace is a failed "
                f"attempt to read {path} (path identity: a same-named file under "
                "another tree does not count; a call a gate refused or one with "
                "invalid arguments read nothing). blocked records a read that "
                f"failed; it does not replace one. Read it - {read_hint(kind)} - "
                "and if that read fails, mark it blocked naming the failure.")
    return None


def _block_item(root: Path, ledger: dict[str, Any], item: dict[str, Any], reason: str,
                trace_entries: list[dict] | None) -> dict[str, Any]:
    """Block one evidence item after a failed attempt on it; an item a call
    has read is not blocked, it is examined."""
    if item.get("status") == "examined":
        by = item.get("examined_by") or {}
        return {"success": False,
                "error": (f"refusing to mark blocked: {item['path']} was read"
                          + (f" by call {by['call_id']}" if by.get("call_id") else "")
                          + "; blocked documents a failed examination, not a partial one.")}
    kind = CONTAINER_KIND if item.get("kind") in ("image", "memory") else ""
    calls = _calls_reaching(root, str(item.get("path") or ""), _trace_or_log(trace_entries, root))
    refusal = _blocked_refusal(str(item.get("path") or ""), kind, calls)
    if refusal is not None:
        return {"success": False, "error": refusal}
    item.update(status="blocked", blocked_reason=reason[:500])
    save_ledger(root, ledger)
    return {"success": True, "item": dict(item)}


def rederive_container_coverage(case_dir: str | os.PathLike) -> dict[str, Any]:
    """Recount every disk and memory image from the trace by the rule the
    live path applies call by call: a call that read a file in it examined
    it, blocked stands on a failed read with no successful one, anything
    else is unseen. The ledger is the trace's cache; statuses that disagree
    with the trace (credited by a call that reads nothing, blocked without
    a failed read, missed by an observation that failed) are brought back
    in line before a rerun reads them. Pure function of the trace and the
    access plan, so a second pass changes nothing.

    Returns the paths it moved: ``demoted`` (counted as read, no call read
    them), ``unblocked`` (blocked with no failed read, or with a successful
    one), ``credited`` (read, counted as unseen); an empty dict when the
    case has no trace."""
    root = Path(case_dir).resolve()
    try:
        from core.execution_log import trace_tool_calls
        entries = trace_tool_calls(root)
    except Exception:  # noqa: BLE001 - no trace, nothing to derive from
        entries = None
    # No call to count from (no trace, a log just opened, a document that
    # would not parse) says nothing about what was read: nothing is
    # recounted, rather than every examined image demoted.
    if not entries:
        return {}
    ledger = load_ledger(root)
    units = [u for u in (ledger.get("units") or {}).values()
             if isinstance(u, dict) and u.get("kind") == CONTAINER_KIND]
    items = [i for i in (ledger.get("items") or {}).values()
             if isinstance(i, dict) and i.get("kind") in ("image", "memory")]
    if not units and not items:
        return {}
    try:
        from core.mount_plan import load_mount_plan
        plan = load_mount_plan(root)
    except Exception:  # noqa: BLE001 - path identity still applies
        plan = {}
    moved: dict[str, list[str]] = {"demoted": [], "unblocked": [], "credited": []}
    changed = False

    def note(key: str, path: str) -> None:
        # An image's unit and item move together; the path is named once.
        if not any(path in v for v in moved.values()):
            moved[key].append(path)

    attempts = _read_attempts(root, entries, plan)

    def calls_on(paths: list[str]) -> tuple[list[dict], bool]:
        ups = [u for u in (_unit_rel(p) for p in paths) if u]
        calls = [e for e, view in attempts if any(_view_reaches(view, u) for u in ups)]
        reads = [e for e in calls if e.get("success") is True
                 and is_probe_tool(_entry_tool(e))]
        return reads, any(_failed_attempt(e) for e in calls)

    for u in units:
        path = str(u.get("path") or "")
        reads, failed = calls_on([path])
        cur = str(u.get("status") or "unseen")
        if reads:
            new = cur if cur in ("probed", "answered") else "probed"
        elif cur == "blocked" and failed:
            new = cur
        else:
            new = "unseen"
        if new == cur:
            continue
        note("unblocked" if cur == "blocked" else
             "credited" if new == "probed" else "demoted", path)
        u.update(status=new, probed_at=_utcnow() if new != "unseen" else None)
        if cur == "blocked":
            u["note"] = ""
        changed = True
    for it in items:
        path = str(it.get("path") or "")
        reads, failed = calls_on([path, *(it.get("segments") or [])])
        cur = str(it.get("status") or "unseen")
        if reads:
            # An item examined by a call the rule no longer counts names
            # the first call that did read it.
            by_tool = str((it.get("examined_by") or {}).get("tool") or "")
            if cur == "examined" and is_probe_tool(by_tool):
                continue
            if cur != "examined":
                note("unblocked" if cur == "blocked" else "credited", path)
                it.update(status="examined", examined_at=_utcnow(), blocked_reason="")
            from core.evidence_items import MAX_CALLS
            ids = [str(e["call_id"]) for e in reads if e.get("call_id")]
            it.update(examined_by={"call_id": ids[0] if ids else "",
                                   "tool": _entry_tool(reads[0])},
                      calls=list(dict.fromkeys(ids))[:MAX_CALLS])
            changed = True
        elif cur != "unseen" and not (cur == "blocked" and failed):
            note("unblocked" if cur == "blocked" else "demoted", path)
            it.update(status="unseen", touched=[], calls=[], examined_by=None,
                      examined_at=None, blocked_reason="")
            changed = True
    if changed:
        save_ledger(root, ledger)
    return {k: v for k, v in moved.items() if v}


def reset_unit_statuses(case_dir: str | os.PathLike) -> int:
    """Reset every ledger unit to unseen (unit list kept). Used by
    clear_case_run: a fresh run must re-earn its coverage floor — probes
    belong to the trace that recorded them, which the clear just deleted.
    Returns the number of units reset."""
    root = Path(case_dir).resolve()
    if not ledger_path(root).is_file():
        return 0
    ledger = load_ledger(root)
    units = ledger.get("units") or {}
    n = 0
    for u in units.values():
        if isinstance(u, dict) and u.get("status") != "unseen":
            u["status"] = "unseen"
            u["probed_at"] = None
            u["note"] = ""
            n += 1
    try:
        from core.evidence_items import reset as _reset_items
        n_items = _reset_items(ledger)
    except Exception:  # noqa: BLE001
        n_items = 0
    if n or n_items:
        save_ledger(root, ledger)
    return n


def exploration_fingerprint(case_dir: str | os.PathLike | None) -> tuple:
    """Cheap exploration signal: analysis artifact names + ledger probed set."""
    if not case_dir:
        return ()
    root = Path(case_dir)
    names: list[str] = []
    analysis = root / "analysis"
    if analysis.is_dir():
        try:
            from core.evidence_catalog import iter_output_files
            for p in iter_output_files(analysis):
                if p.is_file() and p.stat().st_size > 0:
                    rel = p.relative_to(root).as_posix()
                    if "trace" in rel or "transcript" in rel:
                        continue
                    names.append(f"{rel}:{p.stat().st_size}")
                if len(names) >= 200:
                    break
        except OSError:
            pass
    ledger = load_ledger(root)
    probed = tuple(sorted(
        str(u.get("path"))
        for u in (ledger.get("units") or {}).values()
        if isinstance(u, dict) and u.get("status") in (
            "probed", "answered", "blocked")
    ))
    return (tuple(names), probed)


def recent_gate_repair_active(entries: list[dict] | None, *, window: int = 12) -> bool:
    """True when recent tool failures are evidence_strength / citation repairs."""
    if not entries:
        return False
    hits = 0
    for e in entries[-window:]:
        if e.get("type") != "tool_call":
            continue
        if e.get("success") is not False:
            continue
        err = (e.get("stderr") or e.get("error") or "").lower()
        fc = (e.get("failure_class") or "").lower()
        if ("evidence_strength" in err or "citation" in err
                or "inline citation" in err or fc == "gate_refusal"):
            if "record_finding" in (e.get("cmd") or "") or "citation" in err:
                hits += 1
    return hits >= 1


def format_ledger_nudge(case_dir: str | os.PathLike | None) -> str:
    if not case_dir:
        return ""
    units = open_units(case_dir, limit=8)
    gaps = [str(u.get("path")) for u in units]
    stats = coverage_stats(load_ledger(case_dir))
    if not gaps:
        return (
            f"[coverage ledger] {stats.get('total', 0)} units — "
            f"none unseen (probed={stats.get('probed', 0)} "
            f"answered={stats.get('answered', 0)} "
            f"blocked={stats.get('blocked', 0)})."
        )
    lines = ", ".join(gaps[:6])
    return (
        f"[coverage ledger] {stats.get('unseen', 0)} high-value units still "
        f"unseen (total={stats.get('total', 0)}). Read each before any report "
        f"close-out ({_read_hints(units)}). Examples: {lines}"
    )
