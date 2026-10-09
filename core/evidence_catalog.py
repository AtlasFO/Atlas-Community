"""Evidence catalog + fingerprints for incremental investigation.

Tracks evidence *inputs* under ``<case>/evidence/`` (and optional registered
paths). Separate from ``analysis/evidence_index.db`` (tool-output FTS).

Storage: ``<case>/.atlas/evidence_catalog.json``
"""
from __future__ import annotations

import hashlib
import re
import json
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Optional

SCHEMA_VERSION = "1.0"

# Align with core.paths.FULL_HASH_MAX_GB — large images get sampled fingerprints.
try:
    from core.paths import FULL_HASH_MAX_GB as _FULL_HASH_MAX_GB
except Exception:  # pragma: no cover
    _FULL_HASH_MAX_GB = 16

_LOCK = threading.RLock()

# Skip noisy / non-evidence trees under evidence/
try:
    from core.coverage_ledger import NOISE_DIR_NAMES as _SKIP_DIR_NAMES
except Exception:  # pragma: no cover — import cycle fallback
    _SKIP_DIR_NAMES = frozenset({
        ".git", "__pycache__", ".cache", "lost+found",
        "node_modules", "tools_temp_dir", ".venv", "venv",
        "site-packages",
    })
_SKIP_SUFFIXES = frozenset({
    ".tmp", ".swp", ".lock",
})


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def atlas_dir(case_dir: str | os.PathLike) -> Path:
    return Path(case_dir).resolve() / ".atlas"


def catalog_path(case_dir: str | os.PathLike) -> Path:
    return atlas_dir(case_dir) / "evidence_catalog.json"


def empty_catalog(case_id: str = "") -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "case_id": case_id or "",
        "updated_at": _utcnow(),
        "units": {},
        "meta": {"bootstrap": False},
    }


def load_catalog(case_dir: str | os.PathLike) -> dict[str, Any]:
    path = catalog_path(case_dir)
    if not path.is_file():
        return empty_catalog()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return empty_catalog()
    if not isinstance(data, dict):
        return empty_catalog()
    data.setdefault("schema_version", SCHEMA_VERSION)
    data.setdefault("units", {})
    data.setdefault("meta", {})
    return data


def save_catalog(case_dir: str | os.PathLike, catalog: dict[str, Any]) -> Path:
    path = catalog_path(case_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    catalog = dict(catalog)
    catalog["updated_at"] = _utcnow()
    catalog["schema_version"] = SCHEMA_VERSION
    payload = json.dumps(catalog, indent=2, ensure_ascii=False) + "\n"
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(payload, encoding="utf-8")
    os.replace(tmp, path)
    return path


def evidence_id_for(rel_path: str, content_sha256: str) -> str:
    """Stable id: path-keyed so renames show as remove+add; hash in id for grit."""
    h = hashlib.sha256(f"{rel_path}\0{content_sha256}".encode()).hexdigest()[:16]
    return f"ev_{h}"


def fingerprint_file(
    abs_path: Path,
    *,
    force_full: bool = False,
) -> dict[str, Any]:
    """Return size/mtime/inode + content hash (full or sampled), and when the
    hash was taken (``hashed_at_ns``, read by the reuse check)."""
    hashed_at_ns = time.time_ns()
    st = abs_path.stat()
    size = int(st.st_size)
    mtime_ns = getattr(st, "st_mtime_ns", int(st.st_mtime * 1e9))
    inode = getattr(st, "st_ino", 0)
    max_bytes = 0
    if _FULL_HASH_MAX_GB and _FULL_HASH_MAX_GB > 0:
        max_bytes = int(_FULL_HASH_MAX_GB) * 1024 * 1024 * 1024
    mode = "full"
    digest = hashlib.sha256()
    if (not force_full) and max_bytes and size > max_bytes:
        mode = "sampled"
        # Head + mid + tail samples (64 MiB total budget)
        chunk = 8 * 1024 * 1024
        with open(abs_path, "rb") as fh:
            digest.update(fh.read(chunk))
            mid = max(0, (size // 2) - (chunk // 2))
            fh.seek(mid)
            digest.update(fh.read(chunk))
            tail = max(0, size - chunk)
            fh.seek(tail)
            digest.update(fh.read(chunk))
            digest.update(f"|size={size}|sampled".encode())
    else:
        with open(abs_path, "rb") as fh:
            while True:
                block = fh.read(1024 * 1024)
                if not block:
                    break
                digest.update(block)
    return {
        "content_sha256": digest.hexdigest(),
        "size": size,
        "mtime_ns": mtime_ns,
        "inode": inode,
        "fingerprint_mode": mode,
        "hashed_at_ns": hashed_at_ns,
    }


# A write within this long before a hash was taken can leave size and mtime as
# recorded on a coarse clock (FAT keeps two seconds, NFS caches attributes for
# a few): such a hash is taken again rather than trusted.
_RACY_WINDOW_NS = 5_000_000_000


def _reused_fingerprint(abs_path: Path, prev: dict[str, Any] | None) -> dict[str, Any] | None:
    """``prev``'s fingerprint when the file at ``abs_path`` is still the one
    it was taken from: same size, modification time and inode, and a hash
    taken well after the last write. None means read the file again.

    The quick check git and rsync use. It trusts a file that was changed in
    place and had its time set back (``touch -r``); the first scan of a file
    always reads it, and ``--full-hash`` reads every file again. A
    filesystem that reports no inode or no mtime cannot vouch for a file.
    """
    if (not isinstance(prev, dict) or prev.get("status") != "current"
            or not prev.get("content_sha256")
            or prev.get("fingerprint_mode") not in ("full", "sampled")):
        return None
    st = abs_path.stat()
    mtime_ns = getattr(st, "st_mtime_ns", int(st.st_mtime * 1e9))
    inode = getattr(st, "st_ino", 0)
    if not mtime_ns or not inode:
        return None
    if (prev.get("size"), prev.get("mtime_ns"), prev.get("inode")) != (int(st.st_size), mtime_ns, inode):
        return None
    hashed_at = prev.get("hashed_at_ns")
    # A unit recorded before the hash time was kept has no stamp: the stat
    # match alone decides for it.
    if hashed_at and mtime_ns >= int(hashed_at) - _RACY_WINDOW_NS:
        return None
    out = {k: prev[k] for k in ("content_sha256", "size", "mtime_ns", "inode",
                                "fingerprint_mode") if k in prev}
    if hashed_at:
        out["hashed_at_ns"] = int(hashed_at)
    return out


def iter_evidence_files(case_dir: str | os.PathLike) -> Iterator[tuple[str, Path]]:
    """Yield (relative_posix_path, absolute_path) under evidence/."""
    root = Path(case_dir).resolve()
    ev = root / "evidence"
    if not ev.is_dir():
        return
    for dirpath, dirnames, filenames in os.walk(ev, followlinks=True):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIR_NAMES]
        for name in filenames:
            if any(name.endswith(suf) for suf in _SKIP_SUFFIXES):
                continue
            if name.startswith("."):
                continue
            # ADS / browser Zone.Identifier sidecars are not evidence units
            if "zone.identifier" in name.casefold():
                continue
            abs_p = Path(dirpath) / name
            if not abs_p.is_file():
                continue
            try:
                rel = abs_p.resolve().relative_to(root).as_posix()
            except ValueError:
                # Symlink escaped case — still track with abs path key
                rel = abs_p.as_posix()
            yield rel, abs_p


# Atlas's own bookkeeping, written into the case by the run itself. It is
# never evidence: counting it would let a case "acquire" artifact classes
# from its own transcript, and searching it is circular — the trace mentions
# an indicator *because the run put it there*.
_ATLAS_OUTPUT_RE = re.compile(
    r"(?i)(_trace\.jsonl?$|(?:agent|chat)_transcript_.*\.jsonl?$|/tool-output/|"
    r"^tool-output/|/\.atlas/|^\.atlas/|report_projection|"
    r"\.trace-backups/|ioc_pivots\.json$|"
    # Run bookkeeping the agent drops into analysis/ alongside real output.
    r"(?:^|/)brain_(?:injection|consulted|auto_topics|learn_digest)\.json$|"
    r"(?:^|/)dashboard\.url$)"
)


def is_atlas_output(rel_path: str) -> bool:
    """True for files the run produced about itself, rather than about the case."""
    return bool(_ATLAS_OUTPUT_RE.search(str(rel_path or "").replace("\\", "/")))


# Directories no case may point into. A symlink is the normal way evidence
# of any size is attached to a case, so links are followed — but a case
# may point at *evidence*, not at the machine it runs on. These are the
# Filesystem Hierarchy Standard's own roots, not anyone's site layout.
_OS_ROOTS = frozenset({
    "/", "/bin", "/boot", "/dev", "/etc", "/lib", "/lib32", "/lib64",
    "/proc", "/root", "/run", "/sbin", "/sys", "/usr", "/var",
})
MAX_CASE_FILES = 250_000


def _opened_image_mount(path: str) -> bool:
    """A mount point inside the case's own output trees is an opened disk
    image — that is where the mount tools and Plane A put them — not a set
    of case files. Its contents are examined through the disk tools and
    cited by path, never catalogued; walking a mounted Windows installation
    turned every per-turn scan into minutes. Under ``evidence/`` a mount is
    attached evidence and is followed."""
    try:
        return os.path.ismount(path)
    except OSError:
        return False


def iter_output_files(base: Path, *, prune_mounts: bool = True) -> Iterator[Path]:
    """Files under one case directory, in a stable order, without descending
    into an opened image's mount point. The ``rglob`` replacement for the
    output trees: ``rglob`` walks straight into a mounted volume."""
    base = Path(base)
    if not base.is_dir():
        return
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames.sort()
        if prune_mounts:
            dirnames[:] = [d for d in dirnames
                           if not _opened_image_mount(os.path.join(dirpath, d))]
        for name in sorted(filenames):
            yield Path(dirpath) / name


def _may_follow(path: str, case_root_real: str) -> bool:
    """Whether a directory entry may be descended into.

    Refuses a symlink whose target is an operating-system root, the case
    directory itself, or any ancestor of it — each of those makes "scan the
    case" mean "scan the machine" (a link to /etc pulls thousands of system
    files into the case's evidence profile; a link to / would take the
    disk). Plain directories and links to attached collections pass.
    """
    try:
        if not os.path.islink(path):
            return True
        target = os.path.realpath(path)
    except OSError:
        return False
    if target in _OS_ROOTS:
        return False
    if any(target == r or target.startswith(r.rstrip("/") + "/")
           for r in _OS_ROOTS if r != "/"):
        return False
    case_root = case_root_real.rstrip("/")
    if target == case_root or case_root.startswith(target.rstrip("/") + "/"):
        return False                      # itself, or an ancestor
    return True


def iter_case_files(
    case_dir: str | os.PathLike,
    subdirs: tuple[str, ...] = ("evidence", "analysis", "exports"),
) -> Iterator[tuple[str, Path]]:
    """Yield (relative_posix_path, absolute_path) across the case's own dirs.

    The multi-directory sibling of ``iter_evidence_files``: extracted
    artifacts under ``analysis/`` are as searchable as the originals under
    ``evidence/``, so any question of the form "what does this case
    actually hold" has to see both.

    Follows symlinks, deliberately and necessarily — evidence of any real
    size is attached to a case by symlink or bind mount rather than copied
    (a KAPE export or a mounted image is never duplicated into the case).
    ``Path.rglob`` silently refuses to descend into a symlinked directory,
    so a check built on it reports an empty case on a symlinked KAPE
    collection.

    Unlike the bare ``os.walk(followlinks=True)`` elsewhere in this module,
    this one is cycle-safe: a symlink loop under a case dir would otherwise
    walk forever, and a run that hangs inside a scan is indistinguishable
    from a wedged tool call.
    """
    root = Path(case_dir)
    try:
        root_real = os.path.realpath(root)
    except OSError:
        root_real = str(root)
    walked = 0
    for sub in subdirs:
        base = root / sub
        if not base.is_dir():
            continue
        seen_dirs: set[tuple[int, int]] = set()
        for dirpath, dirnames, filenames in os.walk(base, followlinks=True):
            try:
                st = os.stat(dirpath)
                key = (st.st_dev, st.st_ino)
            except OSError:
                dirnames[:] = []
                continue
            if key in seen_dirs:      # symlink cycle — stop descending
                dirnames[:] = []
                continue
            seen_dirs.add(key)
            dirnames[:] = [
                d for d in dirnames
                if d not in _SKIP_DIR_NAMES
                and _may_follow(os.path.join(dirpath, d), root_real)
                and not (sub != "evidence"
                         and _opened_image_mount(os.path.join(dirpath, d)))
            ]
            walked += len(filenames)
            if walked > MAX_CASE_FILES:
                # A link into a multi-million-file share is not a case; stop
                # rather than turn every scan into a wedge.
                dirnames[:] = []
                continue
            for name in filenames:
                if name.startswith(".") or any(
                        name.endswith(suf) for suf in _SKIP_SUFFIXES):
                    continue
                abs_p = Path(dirpath) / name
                try:
                    rel = abs_p.relative_to(root).as_posix()
                except ValueError:
                    rel = abs_p.as_posix()
                yield rel, abs_p


# How often the scan reports its progress, at most.
_PROGRESS_SECONDS = 2.0


def scan_evidence(
    case_dir: str | os.PathLike,
    *,
    force_full_hash: bool = False,
    previous: dict[str, Any] | None = None,
    progress: Optional[Any] = None,
) -> dict[str, dict[str, Any]]:
    """Fingerprint all evidence files. Returns units keyed by evidence_id.

    A file the ``previous`` catalog fingerprinted and that has not changed
    since (``_reused_fingerprint``) keeps that fingerprint instead of being
    read again: a rerun over a large unchanged evidence set costs a stat per
    file, not hours of hashing. ``force_full_hash`` reads every file, in full.

    ``progress(done, total, done_bytes, total_bytes)``, when given, hears
    where the scan stands: before the first file, at most every
    ``_PROGRESS_SECONDS``, and after the last. A failing listener never
    stops the scan.
    """
    prev_by_path: dict[str, dict[str, Any]] = {}
    if not force_full_hash:
        for unit in ((previous or {}).get("units") or {}).values():
            if isinstance(unit, dict) and unit.get("path"):
                prev_by_path[unit["path"]] = unit
    files = list(iter_evidence_files(case_dir))
    sizes = [0] * len(files)
    if progress is not None:
        for n, (_rel, abs_p) in enumerate(files):
            try:
                sizes[n] = abs_p.stat().st_size
            except OSError:
                pass
    total_bytes, done_bytes, said_at = sum(sizes), 0, 0.0

    def report(done: int) -> None:
        nonlocal said_at
        if progress is None:
            return
        now = time.monotonic()
        if 0 < done < len(files) and now - said_at < _PROGRESS_SECONDS:
            return
        said_at = now
        try:
            progress(done, len(files), done_bytes, total_bytes)
        except Exception:  # noqa: BLE001 - a listener never stops the scan
            pass

    report(0)
    units: dict[str, dict[str, Any]] = {}
    for done, ((rel, abs_p), size) in enumerate(zip(files, sizes), 1):
        try:
            fp = (_reused_fingerprint(abs_p, prev_by_path.get(rel))
                  or fingerprint_file(abs_p, force_full=force_full_hash))
        except OSError as e:
            units[f"ev_err_{hashlib.sha256(rel.encode()).hexdigest()[:12]}"] = {
                "evidence_id": f"ev_err_{hashlib.sha256(rel.encode()).hexdigest()[:12]}",
                "path": rel,
                "status": "unreadable",
                "error": str(e)[:200],
            }
        else:
            eid = evidence_id_for(rel, fp["content_sha256"])
            units[eid] = {
                "evidence_id": eid,
                "path": rel,
                "status": "current",
                "parser_outputs": [],
                **fp,
            }
        done_bytes += size
        report(done)
    return units


def diff_catalogs(
    previous: dict[str, Any],
    current_units: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Compare prior catalog units to a fresh scan."""
    prev_units = previous.get("units") or {}
    # Index previous by path for rename/hash change detection
    prev_by_path = {
        u.get("path"): u for u in prev_units.values() if u.get("path")
    }
    cur_by_path = {u.get("path"): u for u in current_units.values() if u.get("path")}

    added: list[dict] = []
    changed: list[dict] = []
    removed: list[dict] = []
    unchanged: list[dict] = []
    touched: list[dict] = []  # same hash, metadata drift

    for path, cur in cur_by_path.items():
        prev = prev_by_path.get(path)
        if prev is None:
            added.append({"path": path, "evidence_id": cur["evidence_id"]})
            continue
        if prev.get("content_sha256") != cur.get("content_sha256"):
            changed.append({
                "path": path,
                "evidence_id": cur["evidence_id"],
                "previous_evidence_id": prev.get("evidence_id"),
                "previous_sha256": prev.get("content_sha256"),
                "content_sha256": cur.get("content_sha256"),
            })
        elif (
            prev.get("mtime_ns") != cur.get("mtime_ns")
            or prev.get("inode") != cur.get("inode")
            or prev.get("size") != cur.get("size")
        ):
            touched.append({
                "path": path,
                "evidence_id": cur["evidence_id"],
                "note": "metadata changed; content hash unchanged",
            })
        else:
            unchanged.append({
                "path": path,
                "evidence_id": cur["evidence_id"],
            })

    for path, prev in prev_by_path.items():
        if path not in cur_by_path:
            removed.append({
                "path": path,
                "evidence_id": prev.get("evidence_id"),
                "content_sha256": prev.get("content_sha256"),
            })

    return {
        "added": added,
        "changed": changed,
        "removed": removed,
        "unchanged": unchanged,
        "touched": touched,
        "counts": {
            "added": len(added),
            "changed": len(changed),
            "removed": len(removed),
            "unchanged": len(unchanged),
            "touched": len(touched),
            "total_current": len(current_units),
        },
    }


def update_catalog_from_scan(
    case_dir: str | os.PathLike,
    current_units: dict[str, dict[str, Any]],
    *,
    case_id: str = "",
    bootstrap: bool = False,
) -> dict[str, Any]:
    """Persist scanned units, preserving prior parser_outputs when hash matches."""
    with _LOCK:
        prev = load_catalog(case_dir)
        prev_by_path = {
            u.get("path"): u for u in (prev.get("units") or {}).values()
        }
        merged: dict[str, dict[str, Any]] = {}
        for eid, unit in current_units.items():
            path = unit.get("path")
            old = prev_by_path.get(path) if path else None
            if (
                old
                and old.get("content_sha256") == unit.get("content_sha256")
                and old.get("parser_outputs")
            ):
                unit = dict(unit)
                unit["parser_outputs"] = list(old["parser_outputs"])
            merged[eid] = unit
        catalog = {
            "schema_version": SCHEMA_VERSION,
            "case_id": case_id or prev.get("case_id") or "",
            "units": merged,
            "meta": {
                **(prev.get("meta") or {}),
                "bootstrap": bool(
                    bootstrap or (prev.get("meta") or {}).get("bootstrap")
                ),
                "unit_count": len(merged),
            },
        }
        save_catalog(case_dir, catalog)
        return catalog
