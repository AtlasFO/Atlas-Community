"""Coverage Ledger — high-value evidence units tracked for investigation progress.

Philosophy:
  Process audit ≠ belief ≠ coverage. Ledger disposition
  (``probed`` / ``answered`` / ``blocked``) is the soft-exit currency.
  Task<->claim progress is still required while the inbox has open work, but
  clearing the inbox or linking claims must **not** waive unseen HV units.
  Without a task store, ``unseen == 0`` alone applies.
  Access / inventory remain hard gates layered on top.

Statuses per unit: unseen | probed | answered | blocked.
"""
from __future__ import annotations

from core.store_lock import STORE_LOCK as _STORE_LOCK, locked as _locked, write_atomic as _write_atomic

import functools
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Optional

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


def update_ledger(case_dir: str | os.PathLike, fn) -> Any:
    """Load the ledger, apply ``fn(ledger)``, save it, all under the store
    lock; returns what ``fn`` returned."""
    with _STORE_LOCK:
        led = load_ledger(case_dir)
        out = fn(led)
        save_ledger(case_dir, led)
        return out


def save_ledger(case_dir: str | os.PathLike, data: dict[str, Any]) -> Path:
    root = Path(case_dir).resolve()
    path = ledger_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = dict(data)
    data["schema_version"] = SCHEMA_VERSION
    data["case_id"] = data.get("case_id") or root.name
    data["updated_at"] = _utcnow()
    with _STORE_LOCK:
        _write_atomic(path, json.dumps(data, indent=2, ensure_ascii=False) + "\n")
    return path


# The case's own top-level directories. A unit path has to be able to name
# any of them: forcing every path under evidence/ would make units for
# extracted artifacts point at files that do not exist, so nothing could ever
# mark them probed and the coverage floor could never be met.
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


@_locked
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
                # A listing stays a listing across a rebuild (read_by, listed_by).
                units[uid].update({k: old[k] for k in ("read_by", "listed_by") if old.get(k)})

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
    try:
        from core.evidence_disposition import build_disposition, disposition_on
        if disposition_on():
            from core.evidence_profile import ensure_evidence_profile
            build_disposition(root, ledger, prev, ensure_evidence_profile(str(root)).get("files") or [])
    except Exception:  # noqa: BLE001 - the floor stands without the disposition
        pass
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
    """The artefact units by status; with ATLAS_EVIDENCE_DISPOSITION also
    the pending, read, partial and left items and classes
    (``item_pending`` ...), a surveyed but pending unit never counted as
    touched."""
    units = (ledger or {}).get("units") or {}
    stats = {"unseen": 0, "probed": 0, "answered": 0, "blocked": 0, "total": 0}
    try:
        from core.evidence_disposition import disposition_on, disposition_stats
        if disposition_on() and ((ledger or {}).get("classes") is not None):
            for level, counts in disposition_stats(ledger).items():
                if level != "artefact":
                    stats.update({f"{level}_{st}": n for st, n in counts.items()})
    except Exception:  # noqa: BLE001
        pass
    for u in units.values():
        # An extracted output is no part of the floor: what was read in it
        # is the trace's answer at read time (extracted_outputs).
        if not isinstance(u, dict) or u.get("kind") == "derived":
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
      - ledger ``unseen == 0`` (an empty inbox does not waive coverage).
    Without a task store, ``unseen == 0`` alone applies.
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

    # Task progress gate while the inbox has open work. Disposition is still
    # required — claim links / an empty inbox never waive unseen HV.
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

    The single verdict every report gate reads. A gate that appended a
    blocker only when it could *name* unseen units would let a ledger with
    no units at all pass as ready while ``atlas_finish`` — reading the same
    state — classifies the run ``incomplete_coverage``. Gates that all trust
    this verdict cannot disagree.
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
        and u.get("kind") != "derived"
    ]
    return unseen[:limit]


def open_unit_paths(case_dir: str | os.PathLike, *, limit: int = 12) -> list[str]:
    return [str(u.get("path")) for u in open_units(case_dir, limit=limit)]


def _gap_label(unit: dict) -> str:
    """A unit named for the blocker."""
    return str(unit.get("path"))


# ── Derived outputs: what a tool produced is evidence too ─────────────
#
# An extraction, a carve or an export fills a directory the case did not
# come with. Nothing seeded a ledger unit for it, so a run could produce
# many files and finish without opening one. A successful call that
# names an output directory registers it as a unit of kind "derived", with
# what it holds in the reason. Which of its files a call read is the
# trace's answer at read time (extracted_outputs), never a stored status:
# such a unit is no part of the coverage floor, and the finish and the
# report's Evidence Gaps name each file class no call read.

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
            if "." in name[1:]:
                ext = name.rsplit(".", 1)[-1].lower()
                # Only an extension-shaped key reaches the model's summary:
                # a name taken from the wire or an archive is sender's text.
                ext = ext if _EXTENSION_SHAPE.match(ext) else "other"
            else:
                ext = "no extension"
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
    from core.paths import output_paths
    out: list[str] = output_paths(arguments)
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


@_locked
def register_derived_outputs(
    case_dir: str | os.PathLike | None,
    *,
    tool_name: str,
    arguments: dict | None,
    result_text: str | None,
    atlas_read: bool = False,
) -> list[str]:
    """Add a ledger unit for each directory under analysis/ or exports/
    that a successful tool call filled. Returns the case-relative paths
    added; a directory already in the ledger is left as it is.
    ``atlas_read`` marks outputs Atlas wrote and read itself (the
    baseline's), also a unit an older run registered unmarked: no call owes
    them a read (extracted_outputs). Nothing else sets the mark."""
    if not case_dir or not (Path(case_dir) / ".atlas").is_dir():
        return []
    result = _parse_result(result_text)
    if result is None:
        return []
    args = arguments if isinstance(arguments, dict) else {}
    root = Path(case_dir).resolve()
    added: list[str] = []
    marked = False
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
        uid = _unit_id(rel)
        if uid in units:
            u = units[uid]
            if atlas_read and u.get("kind") == "derived" and not u.get("atlas_read"):
                u.update(status="answered", atlas_read=True)
                marked = True
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
        if atlas_read and uid in units:
            units[uid].update(status="answered", atlas_read=True)
        if source_rel and _unit_id(rel) in units:
            # What the directory was made from, case-relative: an archive
            # item is read through the folders it was extracted to.
            units[_unit_id(rel)]["source_rel"] = source_rel
        added.append(rel)
    if (added or marked) and ledger is not None:
        save_ledger(root, ledger)
    return added


def _class_of(name: str) -> str:
    """A file's class: its extension, as the registration counts them
    (_describe_dir's rule): only an extension-shaped tail is a class; a
    name taken from the wire or an archive (a query string, a percent
    escape after its last dot) is "other", a name with no dot "no
    extension"."""
    if "." not in name[1:]:
        return "no extension"
    ext = name.rsplit(".", 1)[-1].lower()
    return ext if _EXTENSION_SHAPE.match(ext) else "other"


def extracted_outputs(case_dir: str | os.PathLike | None,
                      entries: list[dict] | None = None, *, readers: bool = False) -> list[dict[str, Any]]:
    """Each extracted output (a derived unit, those Atlas read itself, marked
    atlas_read, left out) as {path, made, classes: {class: [read, total]},
    open: [classes no file of which was read and no code fact left], left:
    {class: {kind, basis}} for the classes a code fact leaves (_class_left:
    every file empty, every declared reader failed), sample: {class: its first
    file neither read nor failed by two reads, case-relative}, blocked: the
    recorded reason
    when a read of every member failed (coverage.mark_blocked) and no call
    has read one since, which leaves nothing open}, Atlas's own state files
    left out.

    A successful content read by the read rule (_read_attempts: the
    analyst's own words read nothing) reads the files it named
    (core.evidence_identity.call_reads: its inputs by identity, a registered
    copy by its entry) and the files its parser reported processing; a
    folder it was pointed at is listed, no file of it read. Computed from
    the trace at each call; no stored status decides.
    ponytail: the class is the file extension, so one read file clears a
    class of a hundred as a key (the counts still say 1 of 100); a class by
    name stem when that hides real gaps."""
    if not case_dir:
        return []
    root = Path(case_dir).resolve()
    units = [u for u in (load_ledger(root).get("units") or {}).values()
             if isinstance(u, dict) and u.get("kind") == "derived" and u.get("path")
             and not u.get("atlas_read")]
    if not units:
        return []
    from core.provenance import is_state_file
    folders: list[tuple[dict, str, dict[str, str]]] = []
    for u in units:
        d = os.path.realpath(root / str(u["path"]))
        files: dict[str, str] = {}
        for dirpath, _dirs, names in os.walk(d):
            for name in names:
                if not is_state_file(name) and len(files) < _DERIVED_SCAN_CAP:
                    files[os.path.realpath(os.path.join(dirpath, name))] = _class_of(name)
        if files:
            folders.append((u, d, files))
    if not folders:
        return []
    # What each content read read (core.evidence_identity.call_reads): a
    # file by its identity (a registered copy by its entry, any other file
    # by its case path); a folder a call was pointed at is listed, no file
    # of it read (a parser's own report of what it processed counts).
    from core.evidence_identity import Resolver, call_reads
    resolver = Resolver(root)
    copies = resolver.copies()

    def ident(real: str) -> tuple:
        rel = os.path.relpath(real, root).replace(os.sep, "/")
        eid = copies.get(rel.casefold())
        return ("entry", eid) if eid is not None else ("file", rel)
    idents = {f: ident(f) for _u, _d, files in folders for f in files}
    read_ids: set = set()
    failed: dict[str, int] = {}                             # per file, any reader: the offer
    failed_by: dict[tuple[str, str], list[dict]] = {}       # per (reader, file): the leave
    try:
        for e, _view in _read_attempts(root, _trace_or_log(entries, root)):
            tool = _entry_tool(e)
            if not reads_content(tool):
                continue
            reads = call_reads(root, e, resolver=resolver)
            if e.get("success") is True:
                read_ids |= reads["content"] | reads["processed"]
            elif failed_read_attempt(e):
                # A call a gate refused, one with invalid arguments, an
                # expected nonzero exit and a host fault tried nothing: the
                # file stays offered and no leave counts them. A failed read
                # of a folder says nothing of each file in it.
                for f, i in idents.items():
                    if i in reads["content"]:
                        failed[f] = failed.get(f, 0) + 1
                        failed_by.setdefault((listed_tool_name(tool), f), []).append(e)
    finally:
        resolver.close()
    read = {f for f, i in idents.items() if i in read_ids}
    out: list[dict[str, Any]] = []
    ctx = _reader_context(root) if readers else None   # once per call, for every offered file
    facts = _LeaveFacts(root, {p for _r, p in failed_by})   # built lazily, once per call
    for u, d, files in folders:
        classes: dict[str, list[int]] = {}
        sample: dict[str, str] = {}
        # A package's own wiring (_package_structure) is no content: a read of
        # it reads no content of its class, and it is never the offered file.
        structure = _package_structure(d, files)
        for f, cls in sorted(files.items()):
            c = classes.setdefault(cls, [0, 0])
            c[1] += 1
            seen = f in read
            c[0] += seen
            # The file a next read is offered on: one that has not failed two
            # reads (two calls), so the offer does not repeat a dead end, while
            # one failure (a wrong reader, a tool not loaded) keeps it offered.
            # A failed read of a folder says nothing of each file in it.
            if not seen and cls not in sample and failed.get(f, 0) < 2 and f not in structure:
                sample[cls] = str(PurePosixPath(str(u["path"]), *Path(os.path.relpath(f, d)).parts))
        made = str(u.get("reason") or "").split(";", 1)[0].removeprefix("produced by ").strip()
        # mark_blocked refuses a folder a call has read; a read since ends it.
        blocked = (str(u.get("note") or "the reads failed")
                   if u.get("status") == "blocked" and not any(n for n, _m in classes.values()) else "")
        # A class no call read that a code fact leaves (_class_left): recomputed
        # here each call like the counts, never stored, so a carver re-run, a
        # reader installed since or a new attacker entity take effect by themselves.
        # A class is read when a file of its content was read (a class of
        # structure parts alone: when any of them was).
        done: set[str] = set()
        left: dict[str, dict[str, str]] = {}
        for cls, (n, _m) in classes.items():
            members = [f for f, c in files.items() if c == cls]
            content = [f for f in members if f not in structure]
            if any(f in read for f in content) or (n and not content):
                done.add(cls)
            elif not blocked:
                basis = _class_left(d, members, failed_by, facts, structure)
                if basis:
                    left[cls] = basis
                    sample.pop(cls, None)
        out.append({"path": str(u["path"]), "made": made, "classes": classes, "blocked": blocked, "sample": sample,
                    "readers": _sample_readers(root, sample, ctx) if ctx and sample else {}, "left": left,
                    "open": [] if blocked else sorted((k for k in classes if k not in done and k not in left),
                                                      key=lambda k: (-classes[k][1], k))})
    return out


def images_read(case_dir: str | os.PathLike | None, entries: list[dict] | None = None) -> set[str]:
    """The images (case-relative, as the contents index lists them) a
    successful content read reached, by the read rule: the images its
    inputs named in-image (core.evidence_identity.call_reads: the image
    file, a handle, the readable form, an icat argument list, a path under a
    mount of it). A listing, a probe
    that reads no content, a failed read and the analyst's own words reach
    nothing (_read_attempts, reads_content). A read of an extracted file
    credits no image by itself: the extraction that wrote it (an icat, a
    carve) read the image and credits it as a read of its own, while the
    file a listing wrote is metadata and leaves "no file inside it was
    read" true. The one source of that line: the report's gap lines ask
    here, as extracted_outputs asks the same rule for its classes.
    (artifact_value.high_value_state keeps its own credit for ranked index
    *items* by name; that is a truth about items, not about images.)"""
    if not case_dir:
        return set()
    root = Path(case_dir).resolve()
    entries = _trace_or_log(entries, root)
    out: set[str] = set()
    for e, view in _read_attempts(root, entries):
        if e.get("success") is not True or not reads_content(_entry_tool(e)):
            continue
        out |= set(view.get("images", ()))
    return out


# -- the code-checked leave of an extracted class --
#
# A class no call read is left, with its basis shown beside its count, when
# a fact the code holds says a read would give nothing: every file of it is
# empty, or every reader that declares its content type failed on it.
# Nothing the model states leaves a class: a reason is checked by code,
# never taken from a word. The decision is per content type (libmagic),
# never per class key: one file's type speaks for no other. Unknown content
# (octet-stream, no libmagic) and text declare no media reader, so no "every
# reader failed" holds on them; they stay offered to the any-file tools. A
# copy of a file already read is no kind here: a hash call is a content read
# by the credit rule today, so the copy's class is never open (the pending
# credit-rule item decides what a hash credits; the kind returns with it).

# The media types no leave by failed readers holds on: unknown content and
# text (the text tools take any text; their failure is no fact of the format).
_UNTYPED = frozenset({"", "application/octet-stream", "inode/x-empty"})

# libmagic once per (path, size, mtime) while the process lives: the same
# files are typed on every recompute. ponytail: a flat dict cleared when it
# grows past the cap; an LRU if memory ever matters.
_TYPE_CACHE: dict[tuple[str, int, int], str] = {}
_TYPE_CACHE_CAP = 50_000


def _content_type_of(path: str) -> str:
    """The file's media type by content (tools.media_types.content_type),
    cached by (path, size, mtime)."""
    try:
        st = os.stat(path)
    except OSError:
        return ""
    key = (path, st.st_size, int(st.st_mtime))
    if key not in _TYPE_CACHE:
        if len(_TYPE_CACHE) >= _TYPE_CACHE_CAP:
            _TYPE_CACHE.clear()
        from tools.media_types import content_type
        _TYPE_CACHE[key] = content_type(path)
    return _TYPE_CACHE[key]


def _type_readers(media_type: str, facts: "_LeaveFacts") -> list[tuple[str, bool]]:
    """The readers that declare ``media_type`` as ``(listed name, installed)``;
    [] for unknown content and text."""
    if media_type in _UNTYPED or media_type.startswith("text/"):
        return []
    return [(listed_tool_name(r), installed) for r, installed in facts.readers_of(media_type)]


class _LeaveFacts:
    """The facts a leave is judged against, each loaded once per
    extracted_outputs call and only when a class asks for it: the readers
    table with the availability marks, the files a failed read names, the
    attacker entities as name tokens."""

    def __init__(self, root: Path, failed_paths: set[str]):
        self.root = root
        self.failed_paths = failed_paths
        self._readers: tuple | None = None
        self._entities: list | None = None

    def readers_of(self, media_type: str) -> list[tuple[str, bool]]:
        """Every reader that declares the type (dotted), each with its
        availability, less the readers the case or the operator chose not
        to run (tools.tool_capabilities.withheld_tools: a consent row that
        says off, a role not configured): those are no readers of this
        case. A reader missing its program or module stays in the set as
        unavailable: it cannot have failed, so its presence ends the leave."""
        if self._readers is None:
            try:
                from tools.tool_capabilities import (_not_installed, consent_withheld, readers_by_format,
                                                     registered_tool_schemas, withheld_tools)
                tools = registered_tool_schemas()
                self._readers = (tools, readers_by_format(tools), _not_installed() | consent_withheld(tools, self.root),
                                 withheld_tools(self.root, tools))
            except Exception:  # noqa: BLE001 - no registry: no reader is known to have failed
                self._readers = ()
        if not self._readers:
            return []
        from tools.tool_capabilities import is_installed, readers_of_type
        tools, table, gone, withheld = self._readers
        return [(r, is_installed(r, gone)) for r in readers_of_type(media_type, tools, table=table, installed=False)
                if is_installed(r, gone) or is_installed(r, withheld)]

    def entity_tokens(self) -> list:
        """The current attacker entities as whole-token patterns over a
        lower-cased name (the sweep's rule), [] without a claim graph."""
        if self._entities is None:
            self._entities = []
            try:
                from core.evidence_leave import attacker_entities
                for v in attacker_entities(self.root):
                    tail = str(v).replace("\\", "/").rstrip("/").rsplit("/", 1)[-1].lower()
                    if len(tail) >= 3:
                        self._entities.append((v, re.compile(r"(?<![a-z0-9])" + re.escape(tail) + r"(?![a-z0-9])")))
            except Exception:  # noqa: BLE001 - no graph: no entity blocks a leave
                pass
        return self._entities


def _class_left(unit_dir: str, members: list[str], failed_by: dict[tuple[str, str], list[dict]],
                facts: _LeaveFacts, structure: frozenset[str] | set[str] = frozenset()) -> dict[str, str]:
    """{"kind", "basis"} when a code fact leaves the class of ``members``
    (absolute paths under ``unit_dir``, no content of it read), else {}.
    Kinds: empty (every file of size 0); package_structure (every file is a
    package's own wiring, ``structure``: _package_structure); readers_failed
    (every reader that declares the content type of each file is installed
    and failed on at least min(2, files of that type) distinct files, a
    one-file type on two calls, by the call's own provenance). A current
    attacker entity as a whole token in a file's name below the unit folder
    (the name the carver or the archive gave, never the folder's own)
    blocks any leave: the class is read."""
    if not members:
        return {}
    basis = (_left_empty(members)
             or ({"kind": "package_structure",
                  "basis": "every file is its package's own wiring (the content-types stream, relationships with "
                           "no external target), declared in [Content_Types].xml"}
                 if all(f in structure for f in members) else {})
             or _left_readers_failed(members, failed_by, facts))
    if not basis:
        return {}
    for f in members:
        below = os.path.relpath(f, unit_dir).replace(os.sep, "/").lower()
        for _value, token in facts.entity_tokens():
            if token.search(below):
                return {}
    return basis


# Open Packaging Conventions (ECMA-376 Part 2, public): an Office Open XML
# package (docx, xlsx, pptx) declares each part's content type in its
# content-types stream at the package root, by extension (Default) or by part
# name (Override). Its relationships parts wire the parts together; one with
# an external target (a template, a link, an object outside the package) is
# content an analyst reads, so it stays a class to read. The stream is inside
# the evidence: it only names candidates, and each one is parsed and checked
# to be what it claims (a small UTF-8 file, no DTD or entity declaration, the
# format's own root element and namespace).
# ponytail: OPC only; an OpenDocument package's manifest (META-INF/manifest.xml)
# is the same kind of declaration, add it when a run unpacks one.
_OPC_TYPES_STREAM = "[Content_Types].xml"
_OPC_TYPES_NS = "http://schemas.openxmlformats.org/package/2006/content-types"
_OPC_RELS_NS = "http://schemas.openxmlformats.org/package/2006/relationships"
_OPC_RELATIONSHIPS = "application/vnd.openxmlformats-package.relationships+xml"
_OPC_MAX_BYTES = 64 * 1024
_OPC_MEMO: dict[tuple, Any] = {}


def _opc_part(path: str, root_tag: str, ns: str, read: Callable[[Any], Any]) -> Any:
    """``read`` of the root element of a small XML part whose root is
    ``root_tag`` in namespace ``ns``; None for a larger or missing file, one
    that is no regular file, a DTD or entity declaration, a parse error or
    another root. Memoised by path, size and modification time (the
    extracted outputs are computed each turn).

    The path is the evidence's: a FIFO or a device named like a part would
    block an open or a read, a symlink would lead out of the case. Only a
    regular file is opened (lstat), never through a link (O_NOFOLLOW),
    never waiting on an open (O_NONBLOCK), and read only when the opened
    file is still a regular one (fstat: it was not swapped in between)."""
    import stat
    import xml.etree.ElementTree as ET
    try:
        st = os.lstat(path)
    except OSError:
        return None
    if not stat.S_ISREG(st.st_mode):
        return None
    key = (path, st.st_size, st.st_mtime_ns, root_tag)
    if key in _OPC_MEMO:
        return _OPC_MEMO[key]
    out = None
    if st.st_size <= _OPC_MAX_BYTES:
        try:
            with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as fh:
                if not stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
                    raise ValueError("no regular file")
                data = fh.read(_OPC_MAX_BYTES + 1)
            low = data.lower()
            # Office writes these parts in UTF-8. A wide encoding (UTF-16 or
            # UTF-32, with a byte-order mark or without) would hide a
            # declaration from the byte search; each of its ASCII characters
            # carries a NUL byte, so a part holding one is refused.
            if b"\x00" not in data and b"<!doctype" not in low and b"<!entity" not in low:
                el = ET.fromstring(data)
                if el.tag == f"{{{ns}}}{root_tag}":
                    out = read(el)
        except (OSError, ET.ParseError, ValueError):
            out = None
    if len(_OPC_MEMO) > 20_000:
        _OPC_MEMO.clear()
    _OPC_MEMO[key] = out
    return out


def _opc_types(el: Any) -> tuple[dict[str, str], dict[str, str]]:
    defaults: dict[str, str] = {}
    overrides: dict[str, str] = {}
    for d in el.findall(f"{{{_OPC_TYPES_NS}}}Default"):
        defaults[str(d.get("Extension") or "").lower()] = str(d.get("ContentType") or "")
    for o in el.findall(f"{{{_OPC_TYPES_NS}}}Override"):
        overrides[str(o.get("PartName") or "").lower()] = str(o.get("ContentType") or "")
    return defaults, overrides


def _opc_internal_only(el: Any) -> bool:
    """A relationships document whose every relationship targets a part of
    the package (no TargetMode External)."""
    return all(r.tag == f"{{{_OPC_RELS_NS}}}Relationship"
               and str(r.get("TargetMode") or "Internal").strip().lower() != "external" for r in el)


def _package_structure(unit_dir: str, files: dict[str, str] | list[str]) -> set[str]:
    """The files below a derived unit that are an Office Open XML package's
    own wiring: its content-types stream, and each part the stream declares
    as relationships that is a relationships document with no external
    target. A package's root is the file's nearest folder, at or below the
    unit, that holds a content-types stream of the format's own shape."""
    if not any(os.path.basename(f) == _OPC_TYPES_STREAM for f in files):
        return set()
    unit = os.path.normpath(unit_dir)
    roots: dict[str, Any] = {}
    out: set[str] = set()
    for f in files:
        if not f.startswith(unit + os.sep):
            continue                    # a link out of the unit (the files are resolved): never read there
        d = os.path.dirname(f)
        while True:
            if d not in roots:
                roots[d] = _opc_part(os.path.join(d, _OPC_TYPES_STREAM), "Types", _OPC_TYPES_NS, _opc_types)
            if roots[d] is not None or os.path.normpath(d) == unit or not d.startswith(unit + os.sep):
                break
            d = os.path.dirname(d)
        if roots[d] is None:
            continue
        part = "/" + os.path.relpath(f, d).replace(os.sep, "/")
        if part.lower() == "/" + _OPC_TYPES_STREAM.lower():
            out.add(f)
            continue
        defaults, overrides = roots[d]
        name = part.rsplit("/", 1)[-1]
        kind = overrides.get(part.lower()) or (defaults.get(name.rsplit(".", 1)[-1].lower(), "") if "." in name else "")
        if kind == _OPC_RELATIONSHIPS and _opc_part(f, "Relationships", _OPC_RELS_NS, _opc_internal_only):
            out.add(f)
    return out


def _left_empty(members: list[str]) -> dict[str, str]:
    try:
        if all(os.path.getsize(f) == 0 for f in members):
            return {"kind": "empty", "basis": "every file is empty (size 0)"}
    except OSError:
        pass
    return {}


def _left_readers_failed(members: list[str], failed_by: dict[tuple[str, str], list[dict]],
                         facts: _LeaveFacts) -> dict[str, str]:
    if not any(f in facts.failed_paths for f in members):
        return {}
    groups: dict[str, list[str]] = {}
    for f in members:
        groups.setdefault(_content_type_of(f), []).append(f)
    parts: list[str] = []
    for media_type, files in groups.items():
        readers = _type_readers(media_type, facts)
        if not readers or any(not installed for _r, installed in readers):
            return {}                   # unknown, text, undeclared, or a declared reader not here: no fact
        need = min(2, len(files))
        for r, _installed in readers:
            calls = sorted(((f, e) for f in files for e in failed_by.get((r, f), ())),
                           key=lambda fe: int(fe[1].get("call_id") or 0))
            if len({f for f, _e in calls}) < need or len(calls) < 2:
                return {}
            first = calls[0][1]
            ids = ", ".join(str(e.get("call_id")) for _f, e in calls[:2])
            err = shown_name(str(first.get("stderr") or "").splitlines()[0] if first.get("stderr") else "", limit=80)
            parts.append(f"{r} on {len({f for f, _e in calls})} of {len(files)} {shown_name(media_type, quote=False)} "
                         f"files (calls {ids}, {err})")
    return {"kind": "readers_failed", "basis": "every installed reader failed: " + "; ".join(parts)}


def _reader_context(root: Path | None = None) -> tuple | None:
    """(registry, its table, the availability marks, the metadata set),
    computed once per extracted_outputs call for every offered file (a
    program lookup per advertised binary is the dear part); None when there
    is no registry (fail-open: the offers stand without readers). A reader
    whose case switch is off for this case (consent_withheld) is marked like
    one not installed: a read the case refuses is never offered."""
    try:
        from tools.tool_capabilities import (_not_installed, consent_withheld, metadata_only, readers_by_format,
                                             registered_tool_schemas)
        tools = registered_tool_schemas()
        return tools, readers_by_format(tools), _not_installed() | consent_withheld(tools, root), metadata_only(tools)
    except Exception:  # noqa: BLE001
        return None


def _sample_readers(root: Path, sample: dict[str, str], ctx: tuple) -> dict[str, list[list]]:
    """Per class, the installed readers that take its offered file
    (tools.tool_capabilities.class_readers: by the file's content, then its
    name), as ``[listed name, metadata only]`` pairs; {} for a class no
    declared reader takes."""
    out: dict[str, list[list]] = {}
    tools, table, gone, meta = ctx
    try:
        from tools.tool_capabilities import class_readers
        for cls, rel in sample.items():
            readers = class_readers(str(root / rel), tools, table=table, gone=gone, meta=meta)
            if readers:
                out[cls] = [[name, m] for name, m in readers]
    except Exception:  # noqa: BLE001 - the offer stands without its readers
        return out
    return out


def offered_open(outputs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The outputs cut to the open classes a next read is offered on (a
    file not failed by two reads). A class each file of which failed twice offers none, so
    a block repeated each turn never repeats it (the finish's list and the
    report still count it)."""
    out = []
    for o in outputs:
        keep = [k for k in o["open"] if k in (o.get("sample") or {})]
        if keep:
            out.append({**o, "open": keep})
    return out


def shown_name(s: object, *, quote: bool = True, limit: int = 200) -> str:
    """An evidence-derived name (a carved file's name, its class, what made
    it) as a block for the model shows it: JSON-quoted, so a newline or a
    control character in a name forges no line of Atlas's own block, and cut
    to ``limit`` characters with a middle ellipsis. ``quote`` False gives the
    escaped text without its quotes (a class key inside parentheses)."""
    text = str(s)
    if len(text) > limit:
        half = (limit - 3) // 2
        text = text[:half] + "..." + text[-half:]
    out = json.dumps(text, ensure_ascii=False)
    return out if quote else out[1:-1]


# A class key as a file extension looks: short, lower-case, no space or
# bracket. Anything else is a name's tail and is shown quoted.
_EXTENSION_SHAPE = re.compile(r"^[a-z0-9_+-]{1,16}$")


def _class_shown(k: str) -> str:
    """A class key in a line: bare when it is extension-shaped ("jpg" stays
    readable), else quoted and escaped like any evidence-derived name."""
    key = str(k)
    return key if _EXTENSION_SHAPE.match(key) else shown_name(key)


# The head of the model's list of unread extracted classes (the finish in
# both modes), so each reader gives the same next step. It offers a read of
# a named file, never a read of everything: a class that cannot bear on an
# open part or question may stay unread, and the report counts it.
EXTRACTED_OPEN_HEAD = ("Extracted file classes no call has read: read the named file of each class that can bear on "
                       "an open part or question; a class left unread is listed in the report with its count; a class "
                       "shown as left was left by a code fact (every installed reader failed on it, or every file "
                       "empty) and needs no read:")


def extracted_lines(outputs: list[dict[str, Any]], *, only_open: bool = False, named: int = 6) -> list[str]:
    """One line per extracted output with a class not wholly read: each such
    class as "n of m read", largest first (the report's form). ``only_open``
    gives the model's form: the classes no file of which was read, the
    largest ``named`` each as a read of its first file not failed by two
    reads, with the installed readers that take the file (``readers``, "with
    a or b", a metadata reader glossed so), the rest and those whose every
    file failed twice as counts."""
    lines = []
    for o in outputs:
        cls = o["classes"]
        left = o.get("left") or {}
        keys = o["open"] if only_open else sorted((k for k, (n, m) in cls.items() if n < m),
                                                   key=lambda k: (-cls[k][1], k))
        if keys:
            # Every evidence-derived string is shown quoted and escaped
            # (shown_name): a file name is the evidence's, not Atlas's.
            made = f" ({shown_name(o['made'])})" if o.get("made") else ""
            blocked = f"; blocked: {shown_name(o['blocked'])}" if o.get("blocked") else ""
            sample = (o.get("sample") or {}) if only_open else {}
            readers = o.get("readers") or {}

            def with_readers(k: str) -> str:
                names = [f"{n} (metadata only)" if meta else str(n) for n, meta in readers.get(k) or []]
                return f" with {' or '.join(names)}" if names else ""

            def left_of(k: str) -> str:
                # The basis is the code's text; its evidence-derived parts
                # (a path, a stderr line, a media type) came through shown_name.
                return f", left: {left[k]['kind']} ({left[k]['basis']})" if k in left else ""
            bits = [f"read {shown_name(sample[k])}{with_readers(k)} ({_class_shown(k)}, "
                    f"{cls[k][0]} of {cls[k][1]} read)"
                    if k in sample and i < named
                    else f"{_class_shown(k)} {cls[k][0]} of {cls[k][1]} read"
                    + (", every read of it failed" if only_open and k not in sample and k not in left else "")
                    + left_of(k)
                    for i, k in enumerate(keys)]
            if only_open:
                # The classes a code fact left, after the open ones, as counts:
                # the model sees what it need not read and why.
                bits += [f"{_class_shown(k)} {cls[k][0]} of {cls[k][1]} read{left_of(k)}"
                         for k in sorted(left, key=lambda k: (-cls[k][1], k))]
            lines.append(f"{shown_name(o['path'], quote=False)}{made}: " + ("; " if only_open else ", ").join(bits)
                         + blocked)
    return lines


# ── task answered requires a relevant HV disposition ─────────────────────

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


@_locked
def mark_paths(
    case_dir: str | os.PathLike,
    paths: list[str],
    *,
    status: str = "probed",
    note: str = "",
    tool: str = "",
    call_id: str = "",
    content: bool | None = None,
    reads: Optional[dict] = None,
) -> dict[str, Any]:
    """Mark matching ledger units, and credit the evidence items the paths
    lie under (core.evidence_items); returns updated ledger. ``content``:
    whether the call read content; a unit records the first listing call
    as ``listed_by`` and the first read as ``read_by``. ``reads``: what a
    call read (core.evidence_identity.call_reads); the units are matched by
    it (_view_reaches), and a unit the call reached only through a folder it
    listed is listed, not read. Without it ``paths`` are a text's own words
    (a finding naming what it answers) and are matched as such."""
    if content is None:
        content = reads_content(tool or "") if tool else True
    root = Path(case_dir).resolve()
    ledger = load_ledger(root)
    units = ledger.setdefault("units", {})
    if not units:
        ledger = build_coverage_ledger(root)
        units = ledger.setdefault("units", {})

    if reads is None and status == "probed":
        # Paths a caller names as read (no trace call at hand): read as one
        # call's input tokens would be.
        from core.evidence_identity import call_reads
        reads = call_reads(root, {"type": "tool_call", "mcp_tool": tool, "cmd": f"<py>:{tool}"},
                           {"paths": [str(p) for p in paths if p]})
    if reads is not None:
        read_part = {k: v for k, v in reads.items() if k != "listed"}
        reached = lambda up: _view_reaches(reads, up)            # noqa: E731
        read_it = lambda up: content and _view_reaches(read_part, up)  # noqa: E731
    else:
        named = _prose_units(root, paths)
        reached = named                                         # noqa: E731
        read_it = lambda up: content                            # noqa: E731
    changed = False
    for u in units.values():
        if not isinstance(u, dict):
            continue
        up = str(u.get("path") or "").replace("\\", "/").casefold()
        if not reached(up):
            continue
        # What was read in an extracted output is the trace's answer
        # (extracted_outputs): a call or a finding naming it moves nothing.
        if u.get("kind") == "derived" and status in ("probed", "answered"):
            continue
        cur = u.get("status") or "unseen"
        if status == "probed" and tool:
            key = "read_by" if read_it(up) else "listed_by"
            if not u.get(key):
                u[key] = {"call_id": call_id, "tool": tool}
                changed = True
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
    # A finding's own words credit no item (evidence_items.observe's rule);
    # a call credits the items of what it read.
    if reads is not None:
        try:
            from core.evidence_items import observe
            changed = observe(ledger, root, reads, tool=tool, call_id=call_id, content=content) or changed
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
    # The batch extract copies files out of images and reads none of them;
    # each copy is tied to its index entry, so a read of the copy credits it.
    "job_start_image_extract",
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
    its dotted alias (``tsk.mmls``); the lists above hold the listed form.
    A name after a colon (``<py>:<tool>``, ``<server>:<tool>``) is the tool."""
    name = (tool_name or "").strip().rsplit(":", 1)[-1]
    name = name.replace(".", "_")
    namespace, _, rest = name.partition("_")
    return rest if rest.startswith(namespace + "_") else name


def is_probe_tool(tool_name: str) -> bool:
    """Whether a call to ``tool_name`` counts as examining its input paths.
    Any spelling of the name does (listed, dotted or the server's). No name
    is no analyst tool: an entry the pre-run pass wrote examines nothing."""
    name = listed_tool_name(tool_name)
    if not name or name in NON_PROBE_TOOLS:
        return False
    return name.split("_", 1)[0] not in NON_PROBE_NAMESPACES


# A listing, a stat, an identification or a hexdump names a path without
# reading the source's content.
_LISTING_TOOL_RE = re.compile(r"(?:^|_)(?:list|ls|stat|identify|inventory|fls|mmls|ils|hexdump|find)(?:_|$)")


# Atlas's own tools whose names read like a listing but which parse their
# whole input: a log parser named an inventory, capture readers named an
# inventory and a list. Each reads all of its input (the whole log; every
# packet of the capture, no packet count), so a successful call read it.
# The exceptions to the lexical rule above; tests/core/test_listing_names.py
# pins every registered tool the rule names a listing.
CONTENT_READERS_NAMED_AS_LISTINGS = frozenset({
    "misc_device_install_inventory", "net_http_session_inventory", "net_tcpdump_list_connections"})


def is_listing_tool(tool_name: str) -> bool:
    """Whether a call to ``tool_name`` names paths without reading their
    content (the one definition reads_content and the work order's tool kind
    share)."""
    name = listed_tool_name(tool_name)
    return bool(_LISTING_TOOL_RE.search(name)) and name not in CONTENT_READERS_NAMED_AS_LISTINGS


def reads_content(tool_name: str) -> bool:
    """Whether a call to ``tool_name`` read the content of the paths it
    names: a probe (is_probe_tool) that is not a listing of them."""
    name = listed_tool_name(tool_name)
    return is_probe_tool(name) and not is_listing_tool(name)


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


@functools.lru_cache(maxsize=1)
def _own_program_tools() -> dict[str, str]:
    """The programs of the tools that read no content, each with its tool's
    listed name: the tool registry's one typed tool per program
    (core.wrapper_hints.MCP_WRAPPER_HINTS, a table importable without the
    server's middleware) where that tool is no probe."""
    try:
        from core.wrapper_hints import MCP_WRAPPER_HINTS
    except Exception:  # noqa: BLE001 - no registry: every entry keeps its tool
        return {}
    out: dict[str, str] = {}
    for program, hint in MCP_WRAPPER_HINTS.items():
        if "/" in hint:
            continue                      # several tools run it: none is its own
        tool = listed_tool_name(hint.split(".", 1)[-1])
        if tool and not is_probe_tool(tool):
            out[program] = tool
    return out


def _program(cmd: str) -> str:
    """The program a command line runs (its first word after sudo), by name."""
    words = [w for w in str(cmd or "").split() if w != "sudo"]
    return os.path.basename(words[0]) if words else ""


def _entry_tool(entry: dict) -> str:
    """The listed name of the analyst tool a trace entry records, "" when no
    analyst tool made the call. A sub-command a tool runs with the program of
    a tool that reads no content (the partition table a reader looks up for
    its volume offset, the filesystem probe behind a partition-table answer)
    is named by that program's own tool, whatever tool ran it: its success is
    no read for the outer tool, and a filesystem that does not open is an
    open attempt (_OPEN_ATTEMPT_TOOLS) under any tool."""
    name = str(entry.get("mcp_tool") or "")
    cmd = str(entry.get("cmd") or "")
    if name and cmd and not cmd.startswith(("<py>:", "[")):
        own = _own_program_tools().get(_program(cmd))
        if own:
            return own
    if not name:
        words = cmd.split()
        first = words[0] if words else ""
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


def _entry_view(root: Path, entry: dict, plan: Optional[dict] = None, resolver=None,
                args: Optional[dict] = None) -> dict:
    """What a trace call read and named (core.evidence_identity.call_reads),
    worked out once per call. ``plan`` is kept for the callers' signature:
    the access plan's reach is the identity module's."""
    from core.evidence_identity import call_reads
    return call_reads(root, entry, args, resolver=resolver)


def _view_reaches(view: dict, up: str) -> bool:
    """Whether a call (its _entry_view) reached the unit ``up``: a file by
    its case path (a registered copy by its own path too), a folder unit by
    being the folder the call was pointed at, an image by an in-image name
    of it (a handle, its readable form, an icat argument list, a mount, the
    image file); a folder unit also by a file of it the call named. A
    folder the call was pointed at reaches no unit below it (a search over
    evidence/ examined no file), and a copy extracted from an image is no
    read of the image: the extraction is."""
    if not up:
        return False
    if up in {i.casefold() for i in view.get("images", ())}:
        return True
    if up in {str(f).casefold() for f in view.get("folders", ())}:
        return True
    swept = set(view.get("folder", ())) - set(view.get("content", ())) - set(view.get("processed", ()))
    under = up + "/"
    return any(kind == "file" and (kind, ident) not in swept
               and (str(ident).casefold() == up or str(ident).casefold().startswith(under))
               for key in ("content", "listed", "processed")
               for kind, ident in (x for x in view.get(key, ()) if len(x) == 2))


def _prose_units(root: Path, paths: list[str]):
    """The unit test for paths in the analyst's own words (a finding's):
    path identity of the written paths, the images they reach."""
    norms = {_norm_rel(p).casefold() for p in paths if p}
    norms.discard("")
    norms |= _source_images_for(root, paths)
    return lambda up: _any_path_match(up, norms)


def _prose_view(root: Path, text: str, plan: Optional[dict]) -> tuple:
    """The paths a text in the analyst's own words names (a finding, a
    belief): the analyst names, nothing is read, so the text tokenizer
    stays here, never for a call."""
    raw = _blob_paths(text)
    norms = {_norm_rel(p).casefold() for p in raw} - {""}
    images = _source_images_for(root, raw, plan) if raw else set()
    return norms, text.casefold().replace("\\", "/"), images


def _prose_reaches(view: tuple, up: str) -> bool:
    norms, text, images = view
    return bool(up) and ((bool(norms) and _any_path_match(up, norms)) or up in text or up in images)


def _entry_reaches(root: Path, entry: dict, up: str, plan: Optional[dict]) -> bool:
    return _view_reaches(_entry_view(root, entry, plan), up)


# A background job's records, with the job's id: its start (and a repeat of
# it that the job deduplicated), its collect and its cancel. tools.jobs
# writes these commands (_start_job, _collect_impl, job_cancel), nothing else.
_JOB_RECORD_RE = re.compile(r"^\[background job ([A-Za-z0-9][A-Za-z0-9_.-]*)(?: (collected|cancelled))?\] ")


def _job_record(root: Optional[Path], job_id: str) -> Optional[tuple[str, dict, Path]]:
    """A background job's state as tools.jobs._job_state reads its runner's
    record under analysis/jobs/<id>, with that record; None without one."""
    if root is None or ".." in job_id:
        return None
    job_dir = Path(root) / "analysis" / "jobs" / job_id
    try:
        meta = json.loads((job_dir / "meta.json").read_text(encoding="utf-8"))
        from tools.jobs import _job_state
        return _job_state(job_dir, meta), meta, job_dir
    except Exception:  # noqa: BLE001 - no record of the job: no outcome to count
        return None


def _stopped_by_atlas(meta: dict) -> bool:
    """Atlas ended the job, not the evidence: the runner's record of every
    such stop (tools.jobs_runner, stopped_by_atlas), or what job records
    written before it carry for a cancel, the disk guard and a lost raw view."""
    return bool(meta.get("stopped_by_atlas") or meta.get("aborted_reason") or meta.get("view_lost"))


def _job_outcome(record: Optional[tuple[str, dict, Path]]) -> Optional[dict]:
    """A job's outcome for the read rule (_job_record): {"success": True}
    when the job finished, a failure with the last line of its log when it
    failed. None while it runs, when Atlas stopped it (a stop says nothing
    about the evidence) and when its runner died before recording an
    outcome."""
    if record is None:
        return None
    state, meta, job_dir = record
    if state not in ("finished", "failed") or _stopped_by_atlas(meta):
        return None
    if state == "finished":
        return {"success": True, "exit_code": 0}
    try:
        code = int((job_dir / "exit_code").read_text().strip())
    except (OSError, ValueError):
        code = -1
    last = ""
    try:
        with open(job_dir / "stdout.log", "rb") as fh:
            fh.seek(0, os.SEEK_END)
            fh.seek(max(0, fh.tell() - 4096))
            lines = [ln for ln in fh.read().decode("utf-8", "replace").splitlines() if ln.strip()]
        last = lines[-1].strip()[:300] if lines else ""
    except OSError:
        pass
    return {"success": False, "exit_code": code, "failure_class": "tool_error",
            "stderr": last or f"the job exited {code}"}


def resolved_entry(root, entry: dict, jobs: Optional[dict] = None) -> Optional[dict]:
    """A trace entry as the read rule sees it. The start of a background job
    stands for the job's outcome (_job_outcome): starting it read nothing,
    and a job still running, stopped by Atlas or never finished is neither a
    read nor an attempt, like a call a stop cut short: None then. So does a
    call that handed its work to a running job instead of doing it (its
    result entry names the job: deferred_to_job). The collect record of a
    job Atlas stopped and every cancel record are None too; the collect of a
    job that ended by itself is the call it is. Every other entry as it is.
    ``jobs`` keeps one record per job across a pass."""
    if entry.get("job_outcome_resolved"):
        return entry
    m = _JOB_RECORD_RE.match(str(entry.get("cmd") or ""))
    job_id, kind = (m.group(1), m.group(2)) if m else (str(entry.get("deferred_to_job") or ""), None)
    if not job_id:
        return entry
    if kind == "cancelled":
        return None
    if jobs is not None and job_id in jobs:
        record = jobs[job_id]
    else:
        record = _job_record(Path(root) if root else None, job_id)
        if jobs is not None:
            jobs[job_id] = record
    if kind == "collected":
        return None if record is not None and _stopped_by_atlas(record[1]) else entry
    outcome = _job_outcome(record)
    if outcome is None:
        return None
    return {**entry, **outcome, "job_outcome_resolved": True}


# A filesystem that does not open is a failed read of its image; one that
# opens has not been read yet (NON_PROBE_TOOLS).
_OPEN_ATTEMPT_TOOLS = frozenset({"tsk_fsstat"})


def _read_attempts(root: Path, trace_entries: list[dict] | None,
                   plan: Optional[dict] = None) -> list[tuple[dict, tuple]]:
    """The analyst's calls in the trace that tried to read something (an
    examining tool, or an attempt to open an image's filesystem), with what
    each names. A call in the analyst's own words (a finding, a coverage
    verdict) names a path without reading it. Each entry is taken as the
    read rule sees it (resolved_entry): a background job's start as its
    outcome."""
    if plan is None:
        try:
            from core.mount_plan import load_mount_plan
            plan = load_mount_plan(root)
        except Exception:  # noqa: BLE001 - path identity still applies
            plan = {}
    from core.evidence_identity import Resolver
    from core.forensic_citation import own_words_entry
    out: list[tuple[dict, dict]] = []
    jobs: dict = {}
    with Resolver(root) as resolver:
        for e in trace_entries or []:
            if e.get("type") != "tool_call" or own_words_entry(e):
                continue
            e = resolved_entry(root, e, jobs)
            if e is None:
                continue
            tool = _entry_tool(e)
            if tool and (is_probe_tool(tool) or tool in _OPEN_ATTEMPT_TOOLS):
                out.append((e, _entry_view(root, e, plan, resolver)))
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
    # A call a stop cut short neither read nor failed to read anything.
    if entry.get("success") is not False or entry.get("interrupted"):
        return False
    if str(entry.get("failure_class") or "") not in _NOT_AN_ATTEMPT:
        return True
    return str(entry.get("stderr") or "").startswith(_UNIT_STATE_GATES)


# A failure of the host, not of the file: the disk is at its floor or sudo
# asked for a password (failure classes the executor stamps); a call that
# ran out of time or was stopped carries the entry's own timed_out and
# interrupted marks (the executor's and the middleware's). None says
# anything about whether the reader parses the file.
_HOST_FAULTS = frozenset({"disk_floor", "sudo_auth"})


def failed_read_attempt(entry: dict) -> bool:
    """A failed call that tried the file it names: _failed_attempt (a gate
    refusal, a schema error, an expected nonzero exit and a stopped call read
    nothing) less a timed-out call and a host fault (_HOST_FAULTS), which
    say nothing about the file either. What a failed read counts as, for
    the offer of a next read and for the leave of an extracted class."""
    return (_failed_attempt(entry) and not entry.get("timed_out")
            and str(entry.get("failure_class") or "") not in _HOST_FAULTS)


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
    the wrong place and say nothing about the volume. mmls exits 0 when it
    finds a volume system; an older trace may hold its "no partition table"
    exit 1 recorded as a success, which found none."""
    if not failed or not all(
            _NO_FS_TEXT in f"{e.get('stderr') or ''} {e.get('error') or ''}".casefold()
            and not _offset_given(e)
            for e in failed):
        return False
    up = _unit_rel(unit_path)
    return any(e.get("type") == "tool_call" and e.get("success") is True
               and e.get("exit_code") in (0, None)
               and _entry_tool(e) in ("tsk_mmls", "tsk_mmstat")
               and _entry_reaches(root, e, up, plan)
               for e in trace_entries or [])


# What reading a unit means, by the ledger's kind, for the texts that ask
# for a read: an image's own description is not a read of it.
_KIND_LABEL = {CONTAINER_KIND: "an image", "tabular": "a table", "eventlog": "an event log"}


def read_hint(kind: str) -> str:
    """How a unit of the ledger kind ``kind`` is read."""
    if kind == CONTAINER_KIND:
        from core.deferred_intents import coverage_honesty_on
        if coverage_honesty_on():
            from core.contents_index import HANDLE_CLAUSE, image_handles_on
            how = (HANDLE_CLAUSE + " and the parser reads the extracted copy" if image_handles_on()
                   else "tsk.resolve_path then tsk.icat to extract it and the parser for its type")
            return (f"read a file inside it: {how}, or a mount or an export and a read there; for a memory image "
                    "a vol.* plugin. A listing (tsk.fls) and tsk.mmls, tsk.fsstat and "
                    "vol.symbol_check identify an image without reading a file in it")
        return ("open its filesystem: tsk.fls or tsk.resolve_path (a single "
                "volume is found by itself; tsk.mmls lists the offsets when "
                "there are several), a mount or an export; for a memory image "
                "a vol.* plugin. tsk.mmls, tsk.fsstat and vol.symbol_check "
                "identify an image without reading a file in it")
    if kind == "tabular":
        return "query it with table.table_query or table.table_grep (table.table_schema first)"
    if kind == "eventlog":
        return "parse it with an event-log parser"
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
        if kind == "image":
            from core.deferred_intents import coverage_honesty_on
            if coverage_honesty_on():
                tool = "tsk.icat"          # an extraction reads the image; a listing identifies it
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
    # A table_grep reads every row of the file whatever it finds, so one that
    # matched nothing is contact (it gained matched_rows with the count pass).
    if (data.get("matched_rows") == 0 and "grep" in str(tool_name)
            and data.get("selection") in ("survey", "all")):
        return True
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
    # The analyst's own words name paths without reading them (the read
    # rule's registry, as evidence_items applies it): a director summary or a
    # coverage verdict credits nothing; a finding still answers a unit a call
    # has read (mark_paths).
    from core.evidence_items import _own_words
    if "record_finding" not in (tool_name or "") and _own_words(tool_name or ""):
        return None
    if result_text is not None and not tabular_contact_ok(tool_name, result_text):
        return None
    # A finding that names a unit answers it once a call has read it
    # (mark_paths): its paths are its own words.
    if "record_finding" in (tool_name or ""):
        return _mark_named(case_dir, tool_name, cmd_or_args)
    try:
        from core.call_memo import trace_call_id_of
        call_id = trace_call_id_of(result_text or "")
        # A call whose own record stands for a background job (its start, a
        # repeat the job deduplicated, a hand-off to it, its collect) reads
        # what the job read: the job's outcome decides, by the rule the
        # recount applies (resolved_entry), not the call's own success.
        entry = _live_entry(call_id)
        if entry is not None and (_JOB_RECORD_RE.match(str(entry.get("cmd") or ""))
                                  or entry.get("deferred_to_job")):
            seen = resolved_entry(case_dir, entry)
            if seen is None or seen.get("success") is not True:
                return None
        reads, inputs = _live_reads(case_dir, tool_name or "", cmd_or_args, entry)
        if not inputs and not any(reads.get(k) for k in ("content", "listed", "processed", "images")):
            return None
        if entry is not None and reads_content(tool_name or ""):
            # An extraction's output is a copy of the entry it read
            # (core.evidence_identity.record_extraction).
            from core.evidence_identity import record_extraction
            try:
                args = json.loads(cmd_or_args) if str(cmd_or_args or "").lstrip().startswith("{") else None
            except ValueError:
                args = None
            try:
                record_extraction(case_dir, entry, args if isinstance(args, dict) else None, reads, call_id)
            except Exception:  # noqa: BLE001 - a copy not registered leaves the read as it is
                pass
        return mark_paths(case_dir, inputs, status="probed", tool=tool_name or "", call_id=call_id, reads=reads)
    except Exception:
        return None


def _mark_named(case_dir: str | os.PathLike, tool_name: str, text: str) -> Optional[dict[str, Any]]:
    """A finding answers the units its own words name, once a call has read
    them (mark_paths): the paths a text names, no read."""
    found = _blob_paths(f"{tool_name} {text}")
    return mark_paths(case_dir, found, status="answered", tool=tool_name or "") if found else None


def _live_reads(case_dir: str | os.PathLike, tool_name: str, cmd_or_args: str,
                entry: Optional[dict]) -> tuple[dict, list[str]]:
    """What a call that just ran read (core.evidence_identity.call_reads)
    and its input tokens: from its trace entry with the typed arguments the
    loop holds, or, when the result carried no call id, from the arguments
    alone."""
    from core.evidence_identity import call_reads
    from core.provenance import input_tokens
    try:
        args = json.loads(cmd_or_args) if str(cmd_or_args or "").lstrip().startswith("{") else None
    except ValueError:
        args = None
    if not isinstance(args, dict):
        args = None
    if entry is None:
        entry = {"type": "tool_call", "mcp_tool": tool_name, "cmd": cmd_or_args if args is None
                 else f"<py>:{tool_name}", "args": cmd_or_args if args is not None else None}
    return call_reads(case_dir, entry, args), input_tokens(entry, case_dir, args)


def _live_entry(call_id: str) -> Optional[dict]:
    """The live trace's entry of ``call_id``, None when there is none."""
    if not str(call_id or "").isdigit():
        return None
    try:
        from core.execution_log import log
        return (log.index().by_call_id or {}).get(int(call_id))
    except Exception:  # noqa: BLE001 - no live trace: the call's own success stands
        return None


_WORK_ORDER_RE = re.compile(
    r"(?i)winevt|security\.evtx|secevent\.evt|terminalservices|security event log")


@_locked
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


@_locked
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
    # Read or not is the trace's answer (the read rule), never a status the
    # ledger stored: a stored "probed" may stand on a call that read nothing.
    calls = _calls_reaching(root, unit_path, trace_entries, plan)
    refusal = _blocked_refusal(unit_path, kind, calls)
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

    target.update(status="blocked", probed_at=_utcnow(), note=reason[:500], read_by=None, listed_by=None)
    from core.evidence_items import find as _find_item
    item = _find_item(ledger, str(target.get("path") or ""))
    # The item the unit belongs to is blocked with it unless a call read the
    # item elsewhere (another segment of the image, another file of the folder).
    if item is not None and not _reads_and_failures(
            _read_attempts(root, trace_entries, plan),
            [str(item.get("path") or ""), *(item.get("segments") or [])])[0]:
        _mark_item_blocked(item, reason)
    save_ledger(root, ledger)
    return {"success": True, "unit": dict(target)}


def _mark_item_blocked(item: dict[str, Any], reason: str) -> None:
    """An item blocked on a failed read: no call read it, so no read or
    listing is recorded on it either."""
    item.update(status="blocked", blocked_reason=reason[:500], examined_by=None,
                read_by=None, listed_by=None)


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
    has read (the read rule over the trace, never the stored status) is not
    blocked, it is examined."""
    kind = CONTAINER_KIND if item.get("kind") in ("image", "memory") else ""
    ups = [u for u in (_unit_rel(p) for p in [str(item.get("path") or ""), *(item.get("segments") or [])]) if u]
    calls = [e for e, view in _read_attempts(root, _trace_or_log(trace_entries, root))
             if any(_view_reaches(view, u) for u in ups)]
    refusal = _blocked_refusal(str(item.get("path") or ""), kind, calls)
    if refusal is not None:
        return {"success": False, "error": refusal}
    _mark_item_blocked(item, reason)
    save_ledger(root, ledger)
    return {"success": True, "item": dict(item)}


@_locked
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
        return _reads_and_failures(attempts, paths)

    def by_of(e: Optional[dict]) -> Optional[dict]:
        return {"call_id": str(e.get("call_id") or ""), "tool": _entry_tool(e)} if e else None

    def read_and_listing(reads: list[dict]) -> dict:
        # The first read of content and the first listing, as the live path
        # records them (mark_paths): a listing identifies, a read reads.
        return {"read_by": by_of(next((e for e in reads if reads_content(_entry_tool(e))), None)),
                "listed_by": by_of(next((e for e in reads if not reads_content(_entry_tool(e))), None))}

    def put(rec: dict, want: dict) -> bool:
        # Only what differs is written, so a second pass writes nothing.
        diff = {k: v for k, v in want.items() if rec.get(k) != v}
        rec.update(diff)
        return bool(diff)

    from core.evidence_items import MAX_CALLS
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
        want = read_and_listing(reads)
        if new != cur:
            note("unblocked" if cur == "blocked" else
                 "credited" if new == "probed" else "demoted", path)
            want.update(status=new, probed_at=_utcnow() if new != "unseen" else None)
            if cur == "blocked":
                want["note"] = ""
        changed = put(u, want) or changed
    for it in items:
        path = str(it.get("path") or "")
        reads, failed = calls_on([path, *(it.get("segments") or [])])
        cur = str(it.get("status") or "unseen")
        if reads:
            # The calls the rule counts name the item, the first of them
            # first, whatever call the live path recorded.
            ids = [str(e["call_id"]) for e in reads if e.get("call_id")]
            want = {"status": "examined", "blocked_reason": "",
                    "examined_by": {"call_id": ids[0] if ids else "", "tool": _entry_tool(reads[0])},
                    "calls": list(dict.fromkeys(ids))[:MAX_CALLS], **read_and_listing(reads)}
            if cur != "examined":
                note("unblocked" if cur == "blocked" else "credited", path)
                want["examined_at"] = _utcnow()
        elif cur != "unseen" and not (cur == "blocked" and failed):
            note("unblocked" if cur == "blocked" else "demoted", path)
            want = {"status": "unseen", "touched": [], "calls": [], "examined_by": None,
                    "examined_at": None, "blocked_reason": "", "read_by": None, "listed_by": None}
        else:
            want = {"read_by": None, "listed_by": None}
        changed = put(it, want) or changed
    if changed:
        save_ledger(root, ledger)
    return {k: v for k, v in moved.items() if v}


def _reads_and_failures(attempts: list[tuple[dict, tuple]],
                        paths: list[str]) -> tuple[list[dict], bool]:
    """Of the read attempts ``attempts`` (_read_attempts), the successful
    calls of an examining tool that reached one of ``paths``, and whether an
    attempt on one of them failed: the rule an image is counted by."""
    ups = [u for u in (_unit_rel(p) for p in paths) if u]
    calls = [e for e, view in attempts if any(_view_reaches(view, u) for u in ups)]
    reads = [e for e in calls if e.get("success") is True
             and is_probe_tool(_entry_tool(e))]
    return reads, any(_failed_attempt(e) for e in calls)


def image_reads(case_dir: str | os.PathLike, entries: list[dict],
                paths: list[str]) -> tuple[bool, bool]:
    """Whether the trace entries ``entries`` read one of the images
    ``paths`` (or a segment of one) by the rule the recount counts them by,
    and whether an attempt on one of them failed."""
    root = Path(case_dir).resolve()
    from core.evidence_items import find as _find_item
    ledger = load_ledger(root)
    wanted = [str(p) for p in paths or []]
    for p in list(wanted):
        wanted.extend(str(s) for s in (_find_item(ledger, p) or {}).get("segments") or [])
    reads, failed = _reads_and_failures(_read_attempts(root, entries), wanted)
    return bool(reads), failed


# Plain-language names of the ledger's two kinds of image, so that a
# statement about "the disk images" reaches the disk images a recount moved:
# vocabulary of the report languages (English, German), not knowledge of any
# evidence. An image is named as one ("disk image", "memory dump",
# "Festplattenabbild"), by its file name, or as a bare "image" when the
# statement names no image of the other kind; a kind word alone ("access to
# the disk", "the disk share") names a device, not the evidence.
_KIND_WORD_RE = {
    "image": re.compile(r"(?i)\b(?:disks?|festplatt\w*|datentr(?:ä|ae)ger\w*)\b"),
    "memory": re.compile(r"(?i)\b(?:memory|ram|arbeitsspeicher\w*|hauptspeicher\w*|"
                         r"speicherabbild\w*)\b"),
}
_KIND_IMAGE_RE = {
    "image": re.compile(r"(?i)\b(?:disks?|festplatt\w*?|datentr(?:ä|ae)ger\w*?)[\s-]*"
                        r"(?:images?|abbild\w*)\b"),
    "memory": re.compile(r"(?i)\b(?:(?:memory|ram|arbeitsspeicher\w*?|hauptspeicher\w*?)[\s-]*"
                         r"(?:images?|dumps?|captures?|abbild\w*)|speicherabbild\w*)\b"),
}
_IMAGE_WORD_RE = re.compile(r"(?i)\b(?:images?|abbild\w*)\b")
# How close a coverage word sits to the words for an image to be about it.
_COVERAGE_WINDOW = 48


def _spans_near(a: list[tuple[int, int]], b: list[tuple[int, int]]) -> bool:
    return any(max(0, b0 - a1, a0 - b1) <= _COVERAGE_WINDOW
               for a0, a1 in a for b0, b1 in b)


def _word_spans(low: str, word: str) -> list[tuple[int, int]]:
    """Where ``word`` stands in ``low`` as a whole token."""
    if not word:
        return []
    return [m.span() for m in re.finditer(
        r"(?<![a-z0-9])" + re.escape(word) + r"(?![a-z0-9])", low)]


def _image_kind_and_name(ledger: dict[str, Any], path: str) -> tuple[str, str]:
    """An image's ledger kind ("image" for a disk image, "memory") and its
    file name, folded."""
    from core.evidence_items import find as _find_item
    kind = "memory" if (_find_item(ledger, path) or {}).get("kind") == "memory" else "image"
    return kind, str(path).replace("\\", "/").rsplit("/", 1)[-1].casefold()


def _about_spans(low: str, kind: str, name: str) -> list[tuple[int, int]]:
    """Where the folded text ``low`` speaks of an image of ``kind`` called
    ``name``: an image named with its kind, its file name, or a bare "image"
    when the text names no image of the other kind."""
    other = "memory" if kind == "image" else "image"
    spans = [m.span() for m in _KIND_IMAGE_RE[kind].finditer(low)] + _word_spans(low, name)
    if not _KIND_WORD_RE[other].search(low):
        spans += [m.span() for m in _IMAGE_WORD_RE.finditer(low)]
    return spans


def states_unread(case_dir: str | os.PathLike, text: str, paths: list[str]) -> bool:
    """Does ``text`` state that one of the images ``paths`` was not or could
    not be read (a coverage word other than "probed" next to a word for it)?
    A successful read of that image contradicts it."""
    from core.answer_synthesis import _COVERAGE_RE
    low = str(text or "").casefold()
    unread = [m.span() for m in _COVERAGE_RE.finditer(low) if m.group(0) != "probed"]
    if not unread:
        return False
    ledger = load_ledger(Path(case_dir).resolve())
    return any(_spans_near(unread, _about_spans(low, *_image_kind_and_name(ledger, p)))
               for p in paths or [])


def coverage_review_hits(case_dir: str | os.PathLike,
                         moved: dict[str, list[str]]) -> dict[str, dict[str, list[str]]]:
    """The current beliefs whose stated coverage the recount ``moved``
    (rederive_container_coverage's result) contradicts, each with the moved
    images it is about: ``{node id: {"recounted": [paths]}}``, the stamp
    ``core.dependency_index.mark_needs_review`` puts on it.

    A belief is about a moved image when it states that image's coverage (a
    coverage word, core.answer_synthesis, next to a word for the image's
    kind or its file name), or when it rests on the image (a call it cites
    reaches it, or it names its path) and carries a gap clause while the
    image was unblocked, or an absence clause while it was demoted: an
    absence resting on a read that never happened. It must also point at the
    image: rest on it, name its host or its file name (when no other image of
    the case shares that name), or name no host of the case at all (a
    statement about every image of that kind). A statement without such a
    clause, one of what an image showed, is never selected: a recount of
    whether the image was read does not undo it."""
    from core.answer_synthesis import _ABSENCE_RE, _COVERAGE_RE, _GAP_RE
    from core.claim_graph import CURRENT_BELIEF_STATUSES, load_graph
    from core.evidence_links import host_for_image, linked_hosts, resolve_host_label
    from core.evidence_noise import looks_like_evidence_gap_statement

    root = Path(case_dir).resolve()
    moves = {str(p): kind for kind, paths in (moved or {}).items() for p in paths or []}
    if not moves:
        return {}
    graph = load_graph(root)
    beliefs = [n for n in (graph.get("nodes") or {}).values()
               if isinstance(n, dict) and n.get("kind") in ("claim", "conclusion")
               and n.get("status") in CURRENT_BELIEF_STATUSES | {"needs_review"}]
    if not beliefs:
        return {}
    ledger = load_ledger(root)
    images = {str(u.get("path") or "") for u in (ledger.get("units") or {}).values()
              if isinstance(u, dict) and u.get("kind") == CONTAINER_KIND}
    images |= {str(i.get("path") or "") for i in (ledger.get("items") or {}).values()
               if isinstance(i, dict) and i.get("kind") in ("image", "memory")}
    names: dict[str, int] = {}
    for p in images - {""}:
        base = _image_kind_and_name(ledger, p)[1]
        names[base] = names.get(base, 0) + 1
    # The words of an image's path (its folders and the file's stem) that set
    # it apart from the case's other images, other than the words for where a
    # case keeps things and for images themselves: how a case without
    # Evidence Links names a host.
    from core.evidence_access import _MEDIA_LABEL_STOP
    segments = {p: {seg for seg in [*p.replace("\\", "/").casefold().split("/")[:-1],
                                    _image_kind_and_name(ledger, p)[1].rsplit(".", 1)[0]]
                    if len(seg) >= 3}
                for p in images - {""}}
    common = set.intersection(*segments.values()) if segments else set()
    distinct = {w for w in set().union(*segments.values()) - common
                if w not in _MEDIA_LABEL_STOP
                and not any(rx.fullmatch(w) for rx in (*_KIND_WORD_RE.values(), _IMAGE_WORD_RE))}
    case_lows = [p.replace("\\", "/").casefold() for p in images - {""}]
    per_kind: dict[str, int] = {}
    for p in images - {""}:
        kind = _image_kind_and_name(ledger, p)[0]
        per_kind[kind] = per_kind.get(kind, 0) + 1
    try:
        from core.mount_plan import load_mount_plan
        plan = load_mount_plan(root)
    except Exception:  # noqa: BLE001 - path identity still applies
        plan = {}
    try:
        from core.execution_log import trace_tool_calls
        by_call = {str(e.get("call_id")): e for e in trace_tool_calls(root) or []
                   if e.get("call_id") is not None}
    except Exception:  # noqa: BLE001 - the beliefs' own words still name images
        by_call = {}
    # A host is named by its label or an alias of it as a whole token; the
    # shorter forms a log uses are not, since two hosts may share one.
    labels = {h.casefold(): resolve_host_label(root, h).casefold()
              for h in linked_hosts(root) if len(str(h)) >= 3}
    targets = []
    for path, move in moves.items():
        kind, name = _image_kind_and_name(ledger, path)
        targets.append({
            "path": path, "move": move, "up": _unit_rel(path), "kind": kind, "name": name,
            "host": resolve_host_label(root, host_for_image(path, root)).casefold(),
            "low": path.replace("\\", "/").casefold(),
        })

    hits: dict[str, dict[str, list[str]]] = {}
    for node in beliefs:
        text = " ".join([str(node.get("statement") or "")]
                        + [str(g) for g in node.get("gaps") or [] if g])
        low = text.casefold()
        cov = [m.span() for m in _COVERAGE_RE.finditer(low)]
        gap = bool(_GAP_RE.search(low)) or looks_like_evidence_gap_statement(low)
        absent = bool(_ABSENCE_RE.search(low))
        if not (cov or gap or absent):
            continue
        cited = [str(c) for c in node.get("input_call_ids") or []]
        cited += [str(ev.get("call_id")) for ev in node.get("evidence") or []
                  if isinstance(ev, dict) and ev.get("call_id")]
        views = [_entry_view(root, by_call[c], plan) for c in dict.fromkeys(cited) if c in by_call]
        own = _prose_view(root, text, plan)
        fields = [str(h).strip().casefold() for h in [node.get("host"), *(node.get("hosts") or [])]
                  if isinstance(h, str) and str(h).strip()]
        named = {labels[f] for f in fields if f in labels}
        named |= {canon for label, canon in labels.items() if _word_spans(low, label)}
        # The belief's own host words, found as a whole token of an image's
        # path (host_for_image's fallback); without Evidence Links also the
        # words of its text that set one image's path apart. A host word no
        # image path of the case carries points nowhere: such a belief is
        # about every image of its kind only when the case has one.
        words = set(fields) | ({w for w in distinct if _word_spans(low, w)} if not labels else set())
        pointing = {w for w in words if any(_word_spans(pl, w) for pl in case_lows)}
        linked: list[str] = []
        for t in targets:
            rests = bool(t["up"]) and (any(_view_reaches(v, t["up"]) for v in views)
                                       or _prose_reaches(own, t["up"]))
            premise = _spans_near(cov, _about_spans(low, t["kind"], t["name"])) or (rests and (
                (t["move"] == "unblocked" and gap) or (t["move"] == "demoted" and absent)))
            if not premise:
                continue
            if (rests or (_word_spans(low, t["name"]) and names.get(t["name"], 0) == 1)
                    or (t["host"] and t["host"] in named)
                    or any(_word_spans(t["low"], w) for w in pointing)
                    or (not (named or pointing)
                        and (not words or per_kind.get(t["kind"], 0) == 1))):
                linked.append(t["path"])
        if linked:
            hits[str(node.get("id"))] = {"recounted": linked}
    return hits


_MOVE_WORDS = {
    "unblocked": ("counted as blocked although no read of {it} failed (or one succeeded)"),
    "demoted": "counted as read although no call read {it}",
    "credited": "read although counted as unread",
}


def recount_review_reason(paths: list[str], moved: dict[str, list[str]],
                          node_id: str = "") -> str:
    """The review reason of the belief ``node_id`` the recount ``moved`` put
    under review for the images ``paths``: what the recount found and how
    the review is settled, including when the read fails again (a re-record
    naming the belief replaces it, core.claim_graph.supersede)."""
    clauses = []
    for move, words in _MOVE_WORDS.items():
        mine = [p for p in paths if p in (moved.get(move) or [])]
        if not mine:
            continue
        more = len(mine) - 1
        shown = mine[0] + (f" and {more} more image{'s' if more > 1 else ''}" if more else "")
        clauses.append(f"{shown} {words.format(it='them' if more else 'it')}")
    one = len(paths) == 1
    replace = f"misc.record_finding(supersedes={node_id or '<this finding>'})"
    return ("coverage corrected: the recount from the trace found " + "; ".join(clauses)
            + "; this finding states coverage that rested on the old count. Read "
            + ("it" if one else "one of them")
            + ": if the read works, re-validate this finding citing that call, or record "
            f"what the read shows with {replace}; if the read fails, mark the image blocked "
            "naming the failure (coverage.mark_blocked) and record the limitation again the "
            "same way, citing that failed call.")


@_locked
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
        if isinstance(u, dict) and (u.get("status") != "unseen" or u.get("read_by") or u.get("listed_by")):
            # The reads it names were the cleared trace's calls.
            u.update(status="unseen", probed_at=None, note="", read_by=None, listed_by=None)
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
