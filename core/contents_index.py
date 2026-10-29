"""The case's contents index: what every disk image of the case holds,
listed once at intake and joined with what the case's exports parsed.

One entry per file and place, from three origins:

- ``image``: listed inside a disk image by The Sleuth Kit (``fls -r -m /``
  per filesystem volume): the path inside the volume, the metadata address,
  size, MACB times and the deleted flag. Readable: it has an address.
- ``volume``: named by a full-volume listing among the exports (an MFTECmd
  or mactime CSV, bodyfile rows inside a timeline): it existed on the
  host's volume whether or not the collection copied it. Only the rows the
  value table scores are kept; the timeline keeps the rest searchable.
- ``export``: a source an export parsed that no image lists.

Table ``sources`` holds what each export parsed per host and source file
(rows, first and last time, parser kinds, event-log channels with their
event ids), joined to the image entry it was parsed from by the longest
common path suffix of at least three components. ``copies`` and ``partial``
belong to the run whose trace they cite and are emptied with it.

The index is a pointer and a disclosure, never a floor: nothing here asks
for a read, and the report gate and the completion obligation skip its rows
(their ``source`` starts with ``index:``). Built on stdlib ``sqlite3`` at
``.atlas/contents_index.db``; one module lock serialises the writes, as for
core/evidence_index.py.
"""
from __future__ import annotations

import csv
import fnmatch
import json
import os
import re
import sqlite3
import threading
from collections import Counter, defaultdict
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator, Optional

from core.envfile import env_flag

DB_NAME = "contents_index.db"

_WRITE_LOCK = threading.Lock()

_SCHEMA = """
CREATE TABLE IF NOT EXISTS entries (
    id INTEGER PRIMARY KEY, host TEXT, image TEXT, volume INTEGER,
    path TEXT COLLATE NOCASE, name TEXT, inode TEXT, size INTEGER,
    deleted INTEGER, is_dir INTEGER, mtime TEXT, atime TEXT, ctime TEXT,
    crtime TEXT, origin TEXT, version_of INTEGER, version_folder TEXT,
    score INTEGER, class TEXT);
CREATE INDEX IF NOT EXISTS entries_host_path ON entries(host, path);
CREATE INDEX IF NOT EXISTS entries_image_inode ON entries(image, inode);
CREATE INDEX IF NOT EXISTS entries_version_of ON entries(version_of) WHERE version_of IS NOT NULL;
CREATE INDEX IF NOT EXISTS entries_score ON entries(score);
CREATE TABLE IF NOT EXISTS sources (
    id INTEGER PRIMARY KEY, export TEXT, host TEXT, source_path TEXT,
    entry_id INTEGER, rows INTEGER, first TEXT, last TEXT, kinds TEXT,
    channels TEXT);
CREATE INDEX IF NOT EXISTS sources_entry_id ON sources(entry_id);
CREATE TABLE IF NOT EXISTS exports (
    path TEXT PRIMARY KEY, format TEXT, rows INTEGER, first TEXT, last TEXT,
    hosts TEXT, kinds TEXT);
CREATE TABLE IF NOT EXISTS copies (
    copy_path TEXT PRIMARY KEY, entry_id INTEGER, call_id INTEGER,
    size INTEGER, sha256 TEXT);
CREATE TABLE IF NOT EXISTS partial (
    source_id INTEGER, call_id INTEGER, rows_shown INTEGER);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
"""


# ── switches (read at call time) ─────────────────────────────────────────

def index_on() -> bool:
    """The index is built at intake and feeds the existing consumers."""
    return env_flag("ATLAS_CONTENTS_INDEX", True)


def host_view_on() -> bool:
    """The host-first view of unread content."""
    return index_on() and env_flag("ATLAS_INDEX_HOST_VIEW", True)


def copy_provenance_on() -> bool:
    """Extracted copies are credited and scored as their entries."""
    return index_on() and env_flag("ATLAS_COPY_PROVENANCE", True)


def opens_media_on() -> bool:
    """The intake listing records each listed image as opened. Its own
    switch, default on; the index lookup replaces the access guard the
    open removes."""
    return index_on() and env_flag("ATLAS_INDEX_OPENS_MEDIA", True)


def index_status_on() -> bool:
    """The evidence gaps group the index's rows by class."""
    return index_on() and env_flag("ATLAS_INDEX_STATUS", True)


# ── storage ──────────────────────────────────────────────────────────────

def db_path(case_dir: str | os.PathLike) -> Path:
    return Path(case_dir) / ".atlas" / DB_NAME


def _connect(case_dir: str | os.PathLike, create: bool = False) -> Optional[sqlite3.Connection]:
    p = db_path(case_dir)
    if not p.is_file() and not create:
        return None
    p.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(p), timeout=30)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.executescript(_SCHEMA)
    return con


def _meta_get(con: sqlite3.Connection, key: str) -> dict[str, Any]:
    row = con.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    try:
        return json.loads(row[0]) if row else {}
    except (TypeError, ValueError):
        return {}


def _meta_set(con: sqlite3.Connection, key: str, value: dict[str, Any]) -> None:
    con.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", (key, json.dumps(value)))


# {(root, path): relative path} for the answers that needed no filesystem
# (a path under the root, taken apart lexically): the read rule asks the
# same tokens for every call of a trace. Bounded.
_REL_MEMO: dict[tuple[str, str], str] = {}


def _rel(root: Path, path: str | os.PathLike) -> str:
    key = (str(root), str(path))
    hit = _REL_MEMO.get(key)
    if hit is not None:
        return hit
    p = Path(os.path.expanduser(str(path)))
    if not p.is_absolute():
        p = root / p
    for base in (root, root.resolve()):
        try:
            out = p.relative_to(base).as_posix()
        except ValueError:
            continue
        if len(_REL_MEMO) > 100_000:
            _REL_MEMO.clear()
        _REL_MEMO[key] = out
        return out
    try:
        return p.resolve().relative_to(root.resolve()).as_posix()
    except (ValueError, OSError):
        return p.as_posix()


def _iso(epoch: str) -> str:
    try:
        n = int(epoch)
    except (TypeError, ValueError):
        return ""
    if n <= 0:
        return ""
    try:
        return datetime.fromtimestamp(n, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return ""


# ── the image listing ────────────────────────────────────────────────────

def _run(cmd: list[str], timeout: int) -> dict[str, Any]:
    """One listing call through the executor (recorded in the trace and
    fed to the evidence index like any tool's output)."""
    from core.executor import run
    return run(cmd, needs_sudo=False, timeout=timeout)


def _disk_images(root: Path) -> list[dict[str, Any]]:
    try:
        from core.mount_plan import load_mount_plan
        images = load_mount_plan(root).get("images") or []
    except Exception:  # noqa: BLE001
        return []
    # An earlier state of another image (a snapshot base) is read on demand
    # through its own view, not listed at intake.
    return [img for img in images if isinstance(img, dict) and img.get("path")
            and img.get("media_role", "disk") == "disk" and img.get("action") != "skip"
            and not img.get("earlier_state_of")]


def _fingerprint(path: str) -> str:
    try:
        st = os.stat(path)
    except OSError:
        return ""
    return f"{st.st_size}:{int(st.st_mtime)}"


def _trace_call_ids(root: Path) -> Optional[set[int]]:
    """The call ids of the case's current trace; None when no trace is
    configured for this case (a listing would have nowhere to be recorded)."""
    try:
        from core.execution_log import log, trace_tool_calls
        if not log.trace_path():
            return None
        if log.case_dir() and Path(log.case_dir()).resolve() != root.resolve():
            return None
        return {int(e["call_id"]) for e in trace_tool_calls(root) or [] if str(e.get("call_id") or "").isdigit()}
    except Exception:  # noqa: BLE001
        return None


def _failure_reason(res: dict[str, Any]) -> str:
    """A listing failure as a short reason class for the view."""
    err = " ".join(str(res.get("stderr") or res.get("error") or "").split())
    if res.get("timed_out"):
        return "listing timed out"
    if re.search(r"(?i)transport endpoint is not connected", err):
        return "the raw view stopped answering (its daemon is gone)"
    if re.search(r"(?i)cannot determine file system type|unsupported (?:image|file system)", err):
        return "no filesystem The Sleuth Kit can open"
    if re.search(r"(?i)not installed|no such file or directory: '?(?:fls|mmls)", err):
        return "The Sleuth Kit is not installed"
    return ("fls failed: " + err)[:160] if err else f"fls failed (exit {res.get('exit_code')})"


def _listing_lines(res: dict[str, Any]) -> tuple[list[str], str]:
    """The listing's lines from the spill file the executor wrote, and a
    failure reason when the spill failed: a truncated result without a
    spill file holds only the head of the listing."""
    spill = str(res.get("stdout_file") or "")
    if spill:
        try:
            with open(spill, encoding="utf-8", errors="replace") as fh:
                return fh.read().splitlines(), ""
        except OSError:
            return str(res.get("stdout") or "").splitlines(), "spill failed"
    lines = str(res.get("stdout") or "").splitlines()
    return lines, ("spill failed" if res.get("truncated") else "")


def parse_bodyfile(lines: Iterable[str], volume: int = 0) -> list[dict[str, Any]]:
    """``md5|name|inode|mode|uid|gid|size|atime|mtime|ctime|crtime`` rows
    (The Sleuth Kit's bodyfile format) as entries. The name may itself
    hold a ``|``. ``$FILE_NAME`` attribute rows are skipped, alternate data
    streams kept as ``name:stream``, a ``(deleted)`` suffix is the flag."""
    out: list[dict[str, Any]] = []
    for line in lines:
        parts = line.rstrip("\r\n").split("|")
        if len(parts) < 11:
            continue
        name = "|".join(parts[1:-9])
        inode, mode, _uid, _gid, size, atime, mtime, ctime, crtime = parts[-9:]
        if name.endswith(" ($FILE_NAME)"):
            continue
        deleted = 0
        m = re.search(r" \(deleted(?:-realloc)?\)$", name)
        if m:
            name, deleted = name[:m.start()], 1
        path = name.lstrip("/")
        if not path or path.rsplit("/", 1)[-1] in (".", ".."):
            continue
        try:
            nbytes = int(size)
        except ValueError:
            nbytes = None
        out.append({
            "path": path, "name": path.rsplit("/", 1)[-1], "inode": inode.strip(),
            "size": nbytes, "deleted": deleted, "is_dir": int(mode[:1] == "d" or mode[2:3] == "d"),
            "atime": _iso(atime), "mtime": _iso(mtime), "ctime": _iso(ctime), "crtime": _iso(crtime),
            "volume": volume,
        })
    return out


def fold_versions(rows: list[dict[str, Any]]) -> None:
    """Mark mirror trees: a top-level directory of a volume whose files
    repeat, at the same relative paths, at least half of the files under a
    larger top-level directory is a version set of it. Each repeated file
    gets ``_live`` (the index of the live row) and ``version_folder`` (the
    mirror's own folder name). Structural only: no collector or folder name
    is known here, so a mirror that is its own dataset stays findable by
    name and is folded for the count alone."""
    by_volume: dict[int, list[int]] = defaultdict(list)
    for i, r in enumerate(rows):
        if not r.get("is_dir"):
            by_volume[r.get("volume") or 0].append(i)
    for idxs in by_volume.values():
        tops: dict[str, dict[str, int]] = defaultdict(dict)
        for i in idxs:
            top, sep, rest = rows[i]["path"].partition("/")
            if sep and rest:
                tops[top][rest.casefold()] = i
        live: list[str] = []
        for top in sorted(tops, key=lambda t: -len(tops[t])):
            files = tops[top]
            best: Optional[tuple[str, int]] = None
            for cand in live:
                shared = len(files.keys() & tops[cand].keys())
                if shared * 2 >= len(tops[cand]) and (best is None or shared > best[1]):
                    best = (cand, shared)
            if best is None:
                live.append(top)
                continue
            for rest, i in files.items():
                j = tops[best[0]].get(rest)
                if j is not None:
                    rows[i]["_live"] = j
                    rows[i]["version_folder"] = top


def _volume_offsets(root: Path, image: str, readable: str, timeout: int) -> tuple[list[int], str, bool]:
    """The filesystem volumes to list: the offset a tool already succeeded
    at, else the volumes the partition table names, else offset 0 (a
    volume image without a partition table); and whether they are every
    volume the image holds (False for the remembered offset alone: the
    partition table was not read, so other volumes may be unlisted)."""
    try:
        from core.mount_plan import volume_offset
        known = volume_offset(root, image)
    except Exception:  # noqa: BLE001
        known = None
    if known is not None:
        return [int(known)], "", False
    from tools.sleuthkit import _MMLS_ROW_RE, _NOT_A_VOLUME_RE
    res = _run(["mmls", readable], timeout)
    offsets = []
    for line in str(res.get("stdout") or "").splitlines():
        m = _MMLS_ROW_RE.match(line)
        if m and not _NOT_A_VOLUME_RE.search(m.group(6)):
            offsets.append(int(m.group(3)))
    note = "" if res.get("success") else "mmls found no partition table"
    # mmls exits 1 without a word for a volume with no partition table
    # (tools.sleuthkit.tsk_mmls); any other failure (a timeout, an error it
    # prints) says nothing about the volumes the image holds.
    no_table = (res.get("exit_code") == 1 and not res.get("timed_out")
                and not str(res.get("stdout") or "").strip() and not str(res.get("stderr") or "").strip())
    return offsets or [0], note, bool(res.get("success")) or no_table


# The one listing failure kept until the image or its view changes: the
# filesystem itself is not one the Sleuth Kit opens. Anything else (a view
# that stopped, a timeout, a spill, an image not yet readable) is listed
# again on the next intake.
_SETTLED_REASONS = ("no filesystem The Sleuth Kit can open",)


def _readable(root: Path, image: str) -> tuple[str, str]:
    """(path The Sleuth Kit reads, failure reason): an EWF image through the
    raw device its mount exposes right now, natively only when this Sleuth
    Kit build reads EWF; a disk container through its raw view (started
    when it is not up), or no path and why it has none."""
    if not os.path.exists(image):
        return "", "image file missing"
    try:
        from core.mount_plan import ewf_device_for, is_ewf_image, raw_device_for
    except Exception:  # noqa: BLE001
        return image, ""
    if not is_ewf_image(image):
        device, why = raw_device_for(root, image)
        if device:
            return device, ""
        return ("", why) if why else (image, "")
    device = ewf_device_for(root, image)
    if device:
        return device, ""
    from tools.sleuthkit import tsk_image_types
    if "ewf" in tsk_image_types():
        return image, ""
    return "", "EWF container not mounted"


def _tell(progress: Any, text: str) -> None:
    """Pass a status line to the intake's listener; a listener that fails
    never stops the index."""
    if progress is None:
        return
    try:
        progress(text)
    except Exception:  # noqa: BLE001 - a status line is never worth a listing
        pass


def _list_image(root: Path, image: str, readable: Optional[str] = None,
                reason: str = "", progress: Any = None) -> dict[str, Any]:
    out: dict[str, Any] = {"rows": [], "listed": False, "complete": False, "reason": "",
                           "call_ids": [], "volumes": [], "settled": False, "volumes_all": False}
    if readable is None:
        readable, reason = _readable(root, image)
    if not readable:
        out["reason"] = reason
        return out
    from tools.sleuthkit import _metadata_timeout
    timeout = _metadata_timeout(image)
    offsets, note, out["volumes_all"] = _volume_offsets(root, image, readable, timeout)
    reasons: list[str] = []
    complete = True
    for n, off in enumerate(offsets, 1):
        # One listing takes minutes on a large volume: the intake's record
        # names the one that runs, replacing the previous step's line. The
        # offsets are filesystem volumes (a partition, or the whole image
        # when it has no partition table).
        _tell(progress, f"indexing the contents of {Path(image).name}, "
                        f"volume {n} of {len(offsets)}")
        res = _run(["fls", "-r", "-m", "/", "-o", str(off), readable], timeout)
        if res.get("_atlas_call_id"):
            out["call_ids"].append(int(res["_atlas_call_id"]))
        lines, spill = _listing_lines(res)
        rows = parse_bodyfile(lines, off)
        if rows:
            out["rows"] += rows
            out["volumes"].append(off)
        if spill:
            complete = False
            reasons.append(spill)
        elif not res.get("success"):
            complete = False
            reasons.append(_failure_reason(res))
    out["listed"] = bool(out["rows"])
    out["complete"] = out["listed"] and complete
    # Settled: every failure is the filesystem's own, the same on any retry.
    out["settled"] = bool(reasons) and all(r in _SETTLED_REASONS for r in reasons)
    if note and not out["listed"]:
        reasons.insert(0, note)
    out["reason"] = "; ".join(dict.fromkeys(reasons))
    return out


def _source_fp(root: Path, image: str) -> str:
    """The files a container's view reads, with their sizes and times: a
    listing settled on one view is not settled on another."""
    try:
        from core.mount_plan import _container_entry
        entry = _container_entry(root, image)
    except Exception:  # noqa: BLE001
        entry = None
    files = ((entry or {}).get("container") or {}).get("files") or {}
    return json.dumps(sorted(files.items())) if files else ""


def _next_ids(con: sqlite3.Connection, n: int) -> int:
    """The first of ``n`` fresh entry ids. Ids are never reused after an
    image is listed again, so a copy or a source that still names an old
    id can never name another file."""
    start = max(int(con.execute("SELECT COALESCE(MAX(id), 0) FROM entries").fetchone()[0]) + 1,
                int(_meta_get(con, "ids").get("next") or 1))
    _meta_set(con, "ids", {"next": start + n})
    return start


def _insert_entries(con: sqlite3.Connection, host: str, image: str, rows: list[dict[str, Any]],
                    origin: str) -> int:
    from core.artifact_value import artifact_score
    start = _next_ids(con, len(rows))
    batch = []
    for n, r in enumerate(rows):
        score, why = artifact_score(r["path"], r.get("size"), is_dir=bool(r.get("is_dir")))
        live = r.get("_live")
        batch.append((start + n, host, image, r.get("volume") or 0, r["path"], r["name"],
                      r.get("inode") or "", r.get("size"), r.get("deleted") or 0, r.get("is_dir") or 0,
                      r.get("mtime") or "", r.get("atime") or "", r.get("ctime") or "",
                      r.get("crtime") or "", origin, None if live is None else start + live,
                      r.get("version_folder") or "", score, why))
    con.executemany("INSERT INTO entries VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", batch)
    return len(batch)


def _build_images(con: sqlite3.Connection, root: Path, out: dict[str, Any],
                  progress: Any = None) -> bool:
    """List every disk image whose fingerprint changed or whose listing
    call is not in the current trace; True when any image's entries changed.
    A failed relist keeps the prior entries."""
    trace_ids = _trace_call_ids(root)
    if trace_ids is None:
        return False
    try:
        from core.evidence_links import host_for_image
    except Exception:  # noqa: BLE001
        host_for_image = None  # type: ignore[assignment]
    changed = False
    for img in _disk_images(root):
        abs_path = str(img["path"])
        rel = _rel(root, abs_path)
        key = f"image:{rel}"
        prior = _meta_get(con, key)
        fp = _fingerprint(abs_path)
        ids = set(prior.get("call_ids") or [])
        readable, why = _readable(root, abs_path)
        source_fp = _source_fp(root, abs_path)
        # A complete listing stands; a failed or partial one stands only when
        # it failed on the filesystem itself, read the same way from the same
        # files. A listing that failed on a stopped view, a timeout or an
        # image not yet readable is listed again.
        readable_rel = _rel(root, readable) if readable else ""
        settled = (bool(prior.get("settled")) and prior.get("readable") == readable_rel
                   and prior.get("source_fp", "") == source_fp)
        if (prior and prior.get("fingerprint") == fp and ids and ids <= trace_ids
                and ((prior.get("listed") and prior.get("complete")) or settled)):
            out["kept"].append(rel)
            continue
        listing = _list_image(root, abs_path, readable, why, progress=progress)
        host = host_for_image(rel, root) if host_for_image else ""
        meta = {"fingerprint": fp, "built_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "listed": int(listing["listed"]), "complete": int(listing["complete"]),
                "reason": listing["reason"], "call_ids": listing["call_ids"],
                "volumes": listing["volumes"], "host": host, "readable": readable_rel,
                "source_fp": source_fp, "settled": int(listing["settled"]),
                "volumes_all": int(bool(listing.get("volumes_all")))}
        if not listing["listed"] and prior.get("listed"):
            # The relist failed: the prior entries stand, marked as from a
            # listing the current trace does not hold.
            prior.update(stale_trace=1, reason=listing["reason"], call_ids=listing["call_ids"])
            _meta_set(con, key, prior)
            out["failed"].append((rel, listing["reason"]))
            continue
        con.execute("DELETE FROM entries WHERE image = ? AND origin = 'image'", (rel,))
        fold_versions(listing["rows"])
        meta["entries"] = _insert_entries(con, host, rel, listing["rows"], "image")
        _meta_set(con, key, meta)
        changed = True
        if listing["listed"] and opens_media_on():
            # The listing is the open of the image's filesystem: the
            # access stage records it as a TSK open, success only; a failed
            # listing leaves the image planned and never access_failed.
            try:
                from core.mount_plan import mark_image_opened
                mark_image_opened(root, abs_path, tool="tsk.fls")
            except Exception:  # noqa: BLE001
                pass
        (out["listed"] if listing["listed"] else out["failed"]).append(
            rel if listing["listed"] else (rel, listing["reason"]))
    if changed:
        # What the images hold changed: readers caching a view of the
        # listing (the evidence profile, the digest) key on this, never on
        # the database file, which reads write to mid-run.
        _meta_set(con, "listing_generation", {"n": int(_meta_get(con, "listing_generation").get("n") or 0) + 1})
    return changed


def listing_generation(case_dir: str | os.PathLike) -> int:
    """The number of listing changes the index went through (0 for none or
    no index): bumped only when a build lists an image anew."""
    if not db_path(case_dir).is_file():
        return 0
    con = _connect(case_dir)
    if con is None:
        return 0
    with closing(con):
        return int(_meta_get(con, "listing_generation").get("n") or 0)


# ── exports ──────────────────────────────────────────────────────────────
#
# Formats recognised by the column names their tools publish (public format
# knowledge, not case data): plaso's l2tcsv and dynamic output, EvtxECmd's
# CSV, MFTECmd's $MFT CSV and The Sleuth Kit's mactime CSV.

_FORMATS: tuple[tuple[str, frozenset[str]], ...] = (
    ("l2tcsv", frozenset({"date", "time", "source", "sourcetype", "desc", "filename", "format", "host"})),
    ("dynamic", frozenset({"display_name", "parser", "datetime"})),
    ("evtxecmd", frozenset({"channel", "eventid", "timecreated", "sourcefile"})),
    ("mftecmd", frozenset({"parentpath", "filename", "filesize", "entrynumber"})),
    ("mactime", frozenset({"file name", "size", "meta"})),
)
_HOST_COLS = ("host", "hostname", "computer", "_host")
_TYPE_PREFIX_RE = re.compile(r"^[A-Z][A-Z0-9_]{1,7}:(?=/|\\)")
_DRIVE_RE = re.compile(r"^/?[A-Za-z]:(?=/|$)")
_EID_RE = re.compile(r"^\[(\d+) /")
_VOLUME_KINDS = re.compile(r"(?i)mactime|bodyfile")


def norm_source(path: str) -> str:
    """A parsed source's path as the volume knows it: either separator, no
    parser type prefix ("OS:", "TSK:"), no drive letter, no leading slash."""
    p = _TYPE_PREFIX_RE.sub("", str(path or "").strip()).replace("\\", "/")
    p = _DRIVE_RE.sub("", p)
    return re.sub(r" \(deleted(?:-realloc)?\)$", "", p).strip("/")


def _sniff(path: Path) -> tuple[str, dict[str, int]]:
    try:
        with path.open(encoding="utf-8", errors="replace", newline="") as fh:
            header = next(csv.reader(fh), [])
    except (OSError, csv.Error):
        return "", {}
    cols = {str(c).strip().lstrip("﻿").lower(): n for n, c in enumerate(header)}
    for fmt, needed in _FORMATS:
        if needed <= cols.keys():
            return fmt, cols
    return "", cols


def _tabular_files(root: Path) -> list[tuple[str, Path]]:
    try:
        from core.evidence_catalog import iter_case_files
        return [(rel, p) for rel, p in iter_case_files(root) if p.suffix.lower() == ".csv"]
    except Exception:  # noqa: BLE001
        return []


def _iso_cell(value: str, date: str = "") -> str:
    v = str(value or "").strip()
    if date:
        m = re.match(r"(\d{1,2})/(\d{1,2})/(\d{4})", date.strip())
        if not m:
            return ""
        return f"{m.group(3)}-{int(m.group(1)):02d}-{int(m.group(2)):02d}T{v[:8]}Z"
    m = re.match(r"(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})", v)
    return f"{m.group(1)}T{m.group(2)}Z" if m else ""


class _HostMap:
    """An export's host cell as the case's own host label, when one label
    names it; the cell as written otherwise."""

    def __init__(self, labels: list[str]):
        self.labels = labels
        self.seen: dict[str, str] = {}

    def __call__(self, value: str) -> str:
        value = str(value or "").strip()
        if value not in self.seen:
            hit = ""
            try:
                from core.forensic_citation import host_mentioned
                found = [h for h in self.labels if host_mentioned(h, value)]
                hit = found[0] if len(found) == 1 else ""
            except Exception:  # noqa: BLE001
                pass
            self.seen[value] = hit or value
        return self.seen[value]


def _scan_export(rel: str, path: Path, fmt: str, cols: dict[str, int], file_host: str,
                 hostmap: _HostMap) -> tuple[dict, list[dict]]:
    """One streaming pass: per (host, source) the rows, time span, kinds
    and channels, and the volume rows of a full-volume listing."""
    sources: dict[tuple[str, str], dict[str, Any]] = {}
    raw: dict[str, str] = {}              # each source as the parser wrote it
    volume: list[dict[str, Any]] = []
    total = 0
    span = ["", ""]

    def col(row: list[str], name: str) -> str:
        n = cols.get(name)
        return row[n] if n is not None and n < len(row) else ""

    host_col = next((c for c in _HOST_COLS if c in cols), "")
    with path.open(encoding="utf-8", errors="replace", newline="") as fh:
        reader = csv.reader(fh)
        next(reader, None)
        for row in reader:
            total += 1
            host = hostmap(col(row, host_col)) if host_col and col(row, host_col).strip() else file_host
            if fmt == "mftecmd":
                parent = col(row, "parentpath").replace("\\", "/").lstrip(".").strip("/")
                volume.append({"host": host, "path": norm_source(f"{parent}/{col(row, 'filename')}"),
                               "size": col(row, "filesize"), "inode": col(row, "entrynumber"),
                               "is_dir": col(row, "isdirectory").strip().casefold() == "true"})
                continue
            if fmt == "mactime":
                volume.append({"host": host, "path": norm_source(col(row, "file name")),
                               "size": col(row, "size"), "inode": col(row, "meta"),
                               "is_dir": col(row, "mode").strip().startswith("d")})
                continue
            if fmt == "l2tcsv":
                src, kind = col(row, "filename"), col(row, "format") or col(row, "sourcetype")
                when = _iso_cell(col(row, "time"), col(row, "date"))
                if _VOLUME_KINDS.search(kind):
                    m = re.search(r"(?i)size:\s*(\d+)", col(row, "extra"))
                    volume.append({"host": host, "path": norm_source(col(row, "desc")),
                                   "size": m.group(1) if m else "", "inode": col(row, "inode")})
                    continue
                m = _EID_RE.match(col(row, "desc"))
                eid = m.group(1) if m else ""
                channel = ""
            elif fmt == "dynamic":
                src, kind = col(row, "display_name"), col(row, "parser")
                when, eid, channel = _iso_cell(col(row, "datetime")), "", ""
            else:  # evtxecmd
                src, kind = col(row, "sourcefile"), "evtx"
                when, eid, channel = _iso_cell(col(row, "timecreated")), col(row, "eventid").strip(), col(row, "channel")
            cell, src = src, norm_source(src)
            if not src:
                continue
            raw.setdefault(src, cell)
            acc = sources.setdefault((host, src), {"rows": 0, "first": "", "last": "",
                                                   "kinds": Counter(), "channels": defaultdict(Counter)})
            acc["rows"] += 1
            if when:
                acc["first"] = min(acc["first"] or when, when)
                acc["last"] = max(acc["last"], when)
                span[0] = min(span[0] or when, when)
                span[1] = max(span[1], when)
            acc["kinds"][kind] += 1
            if src.lower().endswith(".evtx") and (eid or channel):
                ch = channel or src.rsplit("/", 1)[-1][:-5].replace("%4", "/")
                acc["channels"][ch][eid or "?"] += 1
    kinds = Counter()
    for acc in sources.values():
        kinds.update(acc["kinds"])
    summary = {"path": rel, "format": fmt, "rows": total, "first": span[0], "last": span[1],
               "hosts": sorted({h for h, _s in sources} | {v["host"] for v in volume}),
               "kinds": dict(kinds.most_common(12)), "sources": sources, "raw": raw}
    return summary, volume


class _SuffixJoin:
    """Image entries of one host by their last three path components, so a
    source path is matched to the entry with the longest common suffix (at
    least three components): a plaso mount prefix and a drive letter fall
    away without being known."""

    def __init__(self, con: sqlite3.Connection):
        self.con = con
        self.maps: dict[str, dict[tuple, list[tuple[int, list[str]]]]] = {}

    def _map(self, host: str) -> dict[tuple, list[tuple[int, list[str]]]]:
        key = host.casefold()
        if key not in self.maps:
            m: dict[tuple, list[tuple[int, list[str]]]] = defaultdict(list)
            for row in self.con.execute(
                    "SELECT id, path FROM entries WHERE origin = 'image' AND version_of IS NULL "
                    "AND host = ? COLLATE NOCASE", (host,)):
                comps = row["path"].casefold().split("/")
                if len(comps) >= 3:
                    m[tuple(comps[-3:])].append((row["id"], comps))
            self.maps[key] = m
        return self.maps[key]

    def __call__(self, host: str, path: str) -> Optional[int]:
        comps = path.casefold().split("/")
        if len(comps) < 3:
            return None
        best, best_len, best_comps, tie = None, 0, None, False
        for eid, ecomps in self._map(host).get(tuple(comps[-3:]), ()):
            n = 0
            while n < min(len(comps), len(ecomps)) and comps[-1 - n] == ecomps[-1 - n]:
                n += 1
            if n > best_len:
                best, best_len, best_comps, tie = eid, n, ecomps, False
            elif n == best_len and ecomps != best_comps:
                tie = True
        # Two different paths of one host with an equally long tail (a live
        # path and its copy under another root): the source is not one
        # entry. The same path listed twice (a deleted and a live entry) is
        # one path, joined to the first.
        return None if tie else best


def resolve_source(case_dir: str | os.PathLike, host: str, source_path: str) -> Optional[dict[str, str]]:
    """The image entry an export row's source path stands for, by the
    exports' join rule (_join_sources): the file the case names (a
    registered copy, a handle) first, else the longest common tail of at
    least three path components on the host's images (every listed host
    when none is named): ``{host, image, inner_path}``, or None when no
    listed image holds it."""
    con = _connect(case_dir)
    if con is None:
        return None
    path = norm_source(source_path)
    with closing(con):
        from core.evidence_identity import Resolver
        eid = _named_source(Resolver(case_dir, con), source_path)
        if eid is not None:
            row = con.execute("SELECT host, image, path FROM entries WHERE id = ?", (eid,)).fetchone()
            return {"host": row["host"] or host, "image": row["image"], "inner_path": row["path"]}
        join = _SuffixJoin(con)
        hosts = [host] if host else [r[0] for r in con.execute(
            "SELECT DISTINCT host FROM entries WHERE origin = 'image' AND host IS NOT NULL AND host != ''")]
        found = []
        for h in hosts:
            eid = join(h, path)
            if eid is not None:
                row = con.execute("SELECT host, image, path FROM entries WHERE id = ?", (eid,)).fetchone()
                if row:
                    found.append({"host": row["host"] or h, "image": row["image"], "inner_path": row["path"]})
    return found[0] if len(found) == 1 else None


def _build_exports(con: sqlite3.Connection, root: Path, images_changed: bool, out: dict[str, Any],
                   only: Optional[set[str]] = None) -> None:
    """Scan each tabular export whose fingerprint changed (one streaming
    pass), and join every source anew when an image was listed again.
    ``only``: these case-relative files alone (a parser's own output at
    result time); nothing else is dropped or rescanned."""
    if only is not None:
        files = [(rel, root / rel) for rel in sorted(only) if (root / rel).is_file()]
    else:
        files = _tabular_files(root)
        present = {rel for rel, _p in files}
        for (old,) in con.execute("SELECT path FROM exports").fetchall():
            if old not in present:
                _drop_export(con, old)
    try:
        from core.forensic_citation import host_mentioned, known_case_hosts
        labels = list(dict.fromkeys(known_case_hosts(root)))
    except Exception:  # noqa: BLE001
        labels, host_mentioned = [], None  # type: ignore[assignment]
    hostmap = _HostMap(labels)
    join = _SuffixJoin(con)
    from core.evidence_identity import Resolver
    resolver = Resolver(root, con)
    if images_changed:
        _rejoin(con, join, resolver)
    for rel, path in files:
        key = f"export:{rel}"
        fp = _fingerprint(str(path))
        prior = _meta_get(con, key)
        if prior.get("fingerprint") == fp and prior.get("join") == _JOIN_RULE:
            continue
        fmt, cols = _sniff(path)
        if not fmt:
            _meta_set(con, key, {"fingerprint": fp, "format": "", "join": _JOIN_RULE})
            continue
        from core.evidence_links import host_of_path, host_of_path_on
        if host_of_path_on():
            one = host_of_path(root, rel, labels)
            named = [one] if one else []
        else:
            named = [h for h in labels if host_mentioned and host_mentioned(h, path.name)]
        try:
            summary, volume = _scan_export(rel, path, fmt, cols, named[0] if len(named) == 1 else "", hostmap)
        except (OSError, csv.Error):
            continue
        # What a table view showed of this file's sources stays shown when
        # the file is scanned again (a parse wrote it anew): it is a fact
        # about the source files, re-linked by source path to the new rows.
        # A source the new file no longer holds loses its tie.
        seen = con.execute("SELECT s.host, s.source_path, p.call_id, p.rows_shown FROM partial p "
                           "JOIN sources s ON s.id = p.source_id WHERE s.export = ?", (rel,)).fetchall()
        _drop_export(con, rel)
        joined = _join_sources(resolver, join, summary.pop("sources"), summary.pop("raw", {}))
        summary["hosts"] = sorted({h for h, _s, _e, _a in joined if h} | {v["host"] for v in volume})
        for host, src, entry_id, acc in joined:
            if entry_id is None:
                entry_id = _insert_one(con, host, rel, src, None, "export")
            con.execute(
                "INSERT INTO sources (export, host, source_path, entry_id, rows, first, last, kinds, channels) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (rel, host, src, entry_id, acc["rows"], acc["first"], acc["last"],
                 json.dumps(dict(acc["kinds"])), json.dumps({c: dict(v) for c, v in acc["channels"].items()})))
        for host, src, call_id, shown in seen:
            sid = con.execute("SELECT id FROM sources WHERE export = ? AND source_path = ? "
                              "ORDER BY host IS ? DESC LIMIT 1", (rel, src, host)).fetchone()
            if sid is not None:
                con.execute("INSERT INTO partial VALUES (?,?,?)", (sid[0], call_id, shown))
        _store_volume_rows(con, rel, volume, join, _export_volume(root, rel, resolver) if volume else None)
        con.execute("INSERT OR REPLACE INTO exports VALUES (?,?,?,?,?,?,?)",
                    (rel, fmt, summary["rows"], summary["first"], summary["last"],
                     json.dumps(summary["hosts"]), json.dumps(summary["kinds"])))
        _meta_set(con, key, {"fingerprint": fp, "format": fmt, "join": _JOIN_RULE})
        out["exports"].append(rel)


# The rule a table's sources were joined by; a table joined by an older rule
# is scanned again even when the file is unchanged. 3: a volume listing's
# rows are tied to the entries of the volume it was parsed from.
_JOIN_RULE = 3


def _source_cells(cell: str) -> list[str]:
    """A stored source path as a token: the cell as written, or the
    normalised path with its root slash back (norm_source drops it)."""
    cell = str(cell or "")
    return [cell] if cell.startswith("/") or "::" in cell else [cell, "/" + cell]


def _named_source(resolver, cell: str) -> Optional[int]:
    """The one entry a source names by identity (core.evidence_identity:
    a registered copy, a handle, the readable form), else None."""
    for c in _source_cells(cell):
        eid = resolver.source_entry(c)
        if eid is not None:
            return eid
    return None


def _join_sources(resolver, join: "_SuffixJoin", sources: dict[tuple[str, str], dict[str, Any]],
                  raw: dict[str, str]) -> list[tuple[str, str, Optional[int], dict[str, Any]]]:
    """(host, source path, entry id or None, accumulator) per source of one
    table. A file the case can name (core.evidence_identity) is one source
    with its own entry and that entry's host, whatever host each row's own
    host cell gave it: an event log's Computer field carries every name the
    machine had, so one log otherwise splits into one source per name and a
    name no label maps is joined to another file. Only a source the case
    cannot name (a path in the original host's namespace: a timeline made
    elsewhere) keeps the row's host and the suffix join."""
    named = {src: _named_source(resolver, raw.get(src, src)) for _h, src in sources}
    one: dict[str, list] = {}
    out: list[tuple[str, str, Optional[int], dict[str, Any]]] = []
    for (host, src), acc in sources.items():
        eid = named[src]
        if eid is None:
            out.append((host, src, join(host, src), acc))
        elif src in one:
            _merge_acc(one[src][1], acc)
        else:
            one[src] = [eid, acc]
    hosts = resolver.where(e for e, _a in one.values())
    for src, (eid, acc) in one.items():
        out.append((str((hosts.get(eid) or ("",))[0] or ""), src, eid, acc))
    return out


def _merge_acc(into: dict[str, Any], acc: dict[str, Any]) -> None:
    into["rows"] += acc["rows"]
    firsts = [f for f in (into["first"], acc["first"]) if f]
    into["first"] = min(firsts) if firsts else ""
    into["last"] = max(into["last"], acc["last"])
    into["kinds"].update(acc["kinds"])
    for ch, ids in acc["channels"].items():
        into["channels"][ch].update(ids)


def _rejoin(con: sqlite3.Connection, join: _SuffixJoin, resolver) -> None:
    """After an image was listed again its entries have new ids: every
    source is joined anew (by identity first, _join_sources' rule), an
    export-only entry gives way to the image entry that now holds its file,
    and a source that lost its image entry gets an export-only entry of its
    own."""
    for s in con.execute("SELECT id, export, host, source_path, entry_id FROM sources").fetchall():
        eid = _named_source(resolver, s["source_path"])
        if eid is None:
            eid = join(s["host"] or "", s["source_path"])
        old = con.execute("SELECT origin FROM entries WHERE id = ?", (s["entry_id"],)).fetchone() \
            if s["entry_id"] is not None else None
        if eid is None:
            if old is not None and old["origin"] == "export":
                continue
            eid = _insert_one(con, s["host"] or "", s["export"], s["source_path"], None, "export")
        elif old is not None and old["origin"] == "export":
            con.execute("DELETE FROM entries WHERE id = ?", (s["entry_id"],))
        con.execute("UPDATE sources SET entry_id = ? WHERE id = ?", (eid, s["id"]))


def _insert_one(con: sqlite3.Connection, host: str, image: str, path: str, size: Optional[int],
                origin: str, inode: str = "", is_dir: bool = False) -> int:
    from core.artifact_value import artifact_score
    score, why = artifact_score(path, size, is_dir=is_dir)
    eid = _next_ids(con, 1)
    con.execute(
        "INSERT INTO entries (id, host, image, volume, path, name, inode, size, deleted, is_dir, mtime, atime, "
        "ctime, crtime, origin, version_of, version_folder, score, class) "
        "VALUES (?,?,?,0,?,?,?,?,0,?,'','','','',?,NULL,'',?,?)",
        (eid, host, image, path, path.rsplit("/", 1)[-1], inode, size, int(bool(is_dir)), origin, score, why))
    return eid


def _store_volume_rows(con: sqlite3.Connection, export: str, rows: list[dict[str, Any]],
                       join: _SuffixJoin, source: Optional[tuple[str, Any]] = None) -> None:
    """A full-volume listing's rows the value table scores and no image
    lists: files that existed on the host's volume and were not collected.
    The rest stay searchable in the export itself. ``source``: the (image,
    volume) the listing was parsed from (_export_volume); a row at a path
    that volume's own entries hold is that entry, whatever its length (the
    suffix join needs three components, so root and second-level files were
    never tied); without a source only the suffix join ties a row."""
    from core.artifact_value import artifact_score
    for r in rows:
        try:
            size = int(str(r.get("size") or "").strip() or 0)
        except ValueError:
            size = None
        if not r["path"] or artifact_score(r["path"], size, is_dir=bool(r.get("is_dir")))[0] <= 0:
            continue
        if source is not None and con.execute(
                "SELECT 1 FROM entries WHERE origin = 'image' AND image = ? AND volume IS ? AND version_of IS NULL "
                "AND path = ? COLLATE NOCASE LIMIT 1", (source[0], source[1], r["path"])).fetchone():
            continue
        if join(r["host"], r["path"]) is not None:
            continue
        _insert_one(con, r["host"], export, r["path"], size, "volume", str(r.get("inode") or ""),
                    is_dir=bool(r.get("is_dir")))


def _export_volume(root: Path, rel: str, resolver) -> Optional[tuple[str, Any]]:
    """(image, volume) the call that wrote the export (the attribution
    ledger, core.provenance) read its content from, when that is one volume
    of one image; None otherwise (no producing call known, a read listed
    only, several volumes)."""
    try:
        from core.evidence_identity import call_reads
        from core.execution_log import trace_entries
        from core.provenance import load_ledger
        cid = (load_ledger(root).get(rel) or {}).get("call")
        if cid is None:
            return None
        entry = next((e for e in trace_entries(root) or [] if e.get("type") == "tool_call"
                      and str(e.get("call_id")) == str(cid)), None)
        if entry is None:
            return None
        reads = call_reads(root, entry, resolver=resolver)
        ids = [x[1] for x in reads["content"] if x[0] == "entry"]
        pairs = {(img, vol) for _h, img, vol, _p in resolver.where(ids).values()}
        return next(iter(pairs)) if len(pairs) == 1 else None
    except Exception:  # noqa: BLE001 - no source: the suffix join alone
        return None


def _drop_export(con: sqlite3.Connection, rel: str) -> None:
    con.execute("DELETE FROM partial WHERE source_id IN (SELECT id FROM sources WHERE export = ?)", (rel,))
    con.execute("DELETE FROM sources WHERE export = ?", (rel,))
    con.execute("DELETE FROM entries WHERE image = ? AND origin IN ('volume', 'export')", (rel,))
    con.execute("DELETE FROM exports WHERE path = ?", (rel,))


# The rule a directory's score was given by: a directory scores only as a
# folder artifact (core.artifact_value.artifact_score, is_dir). An index
# built by an older rule has its directory rows scored again, once.
SCORE_RULE = 2
_RESCORE_BATCH = 5000


def _rescore_dirs(con: sqlite3.Connection) -> int:
    """Score the index's directory rows again by the current rule, once per
    rule version: in the writer's path (build, at start and resume), under
    its write lock, in one immediate transaction that re-reads the flag and
    sets it with the last batch, so a second process waits and finds it set
    and a crash midway leaves the old scores and no flag (the next start
    redoes it: the score is a function of path, size and is_dir). Returns
    the rows changed."""
    from core.artifact_value import artifact_score
    con.commit()
    con.execute("BEGIN IMMEDIATE")
    try:
        if int(_meta_get(con, "score_rule").get("version") or 0) >= SCORE_RULE:
            con.rollback()
            return 0
        changed = 0
        batch: list[tuple] = []
        rows = con.execute("SELECT id, path, size, score, class FROM entries WHERE is_dir = 1").fetchall()
        for r in rows:
            score, why = artifact_score(r["path"], r["size"], is_dir=True)
            if score != r["score"] or (why or "") != (r["class"] or ""):
                batch.append((score, why, r["id"]))
            if len(batch) >= _RESCORE_BATCH:
                con.executemany("UPDATE entries SET score = ?, class = ? WHERE id = ?", batch)
                changed += len(batch)
                batch = []
        if batch:
            con.executemany("UPDATE entries SET score = ?, class = ? WHERE id = ?", batch)
            changed += len(batch)
        _meta_set(con, "score_rule", {"version": SCORE_RULE})
        con.commit()
        return changed
    except BaseException:
        con.rollback()
        raise


def build(case_dir: str | os.PathLike, progress: Any = None) -> dict[str, Any]:
    """Build or refresh the index: list the disk images of the mount plan
    whose fingerprint changed or whose listing call the current trace does
    not hold, then scan the tabular exports that changed. Every per-image
    failure is a ``meta`` row with its reason; the builder goes on with the
    next image. Called from Plane A after the mount plan is built. With no
    trace configured for this case (a listing would have no call to cite)
    no image is listed: the index then holds the exports only.

    Memory: one image's listing is read whole from its spill file and held
    as one dict per row until it is inserted, a few hundred MB for a
    500,000-entry volume; it is freed before the next image.

    ``progress(text)``, when given, hears a short line as each volume's
    listing starts and before the exports are joined and scanned (the
    intake's status record); an image kept unchanged says nothing."""
    out: dict[str, Any] = {"listed": [], "kept": [], "failed": [], "exports": []}
    if not index_on():
        return out
    root = Path(case_dir)
    if not _disk_images(root) and not _tabular_files(root) and not db_path(root).is_file():
        return out
    with _WRITE_LOCK, closing(_connect(root, create=True)) as con:
        # A failed rescore (a lock another process held past the busy
        # timeout, any error) is rolled back and left for the next start (its
        # flag stays unset); this start still lists and scans.
        try:
            out["rescored"] = _rescore_dirs(con)
        except Exception as exc:  # noqa: BLE001
            out["rescore_error"] = f"{type(exc).__name__}: {exc}"[:300]
        changed = _build_images(con, root, out, progress=progress)
        _tell(progress, "joining the parsed exports to the listings")
        _build_exports(con, root, changed, out)
        con.commit()
    try:
        from core.export_profile import profile_on, write_profiles
        if profile_on():
            write_profiles(root)
    except Exception:  # noqa: BLE001 - a profile is a disclosure, never a precondition
        pass
    return out


def register_exports(case_dir: str | os.PathLike, paths: Iterable[str]) -> list[str]:
    """Join the rows of tables a parser just wrote to the index entries they
    came from (the sources a table view marks partly seen, observe_result),
    at result time: Plane A scans exports only at the start of a run, so an
    output written during the run had no sources and no row of it could ever
    count as looked at. One streaming pass per changed file. Returns the
    files scanned."""
    if not index_on():
        return []
    root = Path(case_dir)
    only = {_rel(root, p) for p in paths if p}
    if not only:
        return []
    out: dict[str, Any] = {"exports": []}
    with _WRITE_LOCK, closing(_connect(root, create=True)) as con:
        _build_exports(con, root, False, out, only=only)
        con.commit()
    return out["exports"]


def reset_run_scoped(case_dir: str | os.PathLike) -> int:
    """Empty ``copies`` and ``partial`` (they cite the trace a fresh start
    archives); the entries, sources, exports and meta stand."""
    con = _connect(case_dir)
    if con is None:
        return 0
    with _WRITE_LOCK, closing(con):
        n = (con.execute("DELETE FROM copies").rowcount or 0) + (con.execute("DELETE FROM partial").rowcount or 0)
        con.commit()
    return n


# ── reading the index ────────────────────────────────────────────────────

def _multi_volume(con: sqlite3.Connection) -> set[str]:
    """The images listed with more than one filesystem: the distinct offsets
    in each image meta's ``volumes``, which the build writes in the same
    transaction as the image's rows (a partition table naming one start
    twice lists it twice). One meta row per image, no pass over the
    entries; a value that does not parse is skipped, as in _meta_get."""
    out = set()
    for key, value in con.execute("SELECT key, value FROM meta WHERE key LIKE 'image:%'"):
        try:
            if len(set(json.loads(value).get("volumes") or ())) > 1:
                out.add(key[6:])
        except (TypeError, ValueError, AttributeError):
            continue
    return out


def _under(folder: Any) -> tuple[str, tuple]:
    """The rows below a folder row, from its host, image, volume and path:
    an SQL condition and its arguments, a range on entries_host_path.

    ``path`` is COLLATE NOCASE, which folds ASCII A-Z only, as LIKE does
    here (no ICU, case_sensitive_like off), and "0" is "/" + 1, so
    [p + "/", p + "0") holds exactly the paths that start with p + "/" in
    any ASCII case: the set ``path LIKE 'p/%'`` matches, with nothing to
    escape ("%" and "_" are plain characters in a range) and no pattern
    length limit. The host is named because the index starts with it:
    without it SQLite reads every row of the image, once per folder. It
    narrows nothing the image does not, since every row of an image
    carries the image's one host (_build_images)."""
    p = folder["path"]
    return ("host IS ? AND path >= ? AND path < ? AND image = ? AND volume IS ?",
            (folder["host"], p + "/", p + "0", folder["image"], folder["volume"]))


def class_handles(case_dir: str | os.PathLike, host: str, label: str, limit: int = 4,
                  image: str = "") -> tuple[list[str], int]:
    """Handles of a host's live files of one content class (by its label,
    case-insensitive; the empty variant too), highest value first, at most
    ``limit``, and how many the class holds. With no host, ``image`` names
    the image whose files are meant (an image no evidence link ties to a
    host)."""
    con = _connect(case_dir)
    if con is None or not (host or image) or not label:
        return [], 0
    lab = str(label).strip().casefold()
    who = "host = ? COLLATE NOCASE" if host else "image = ? COLLATE NOCASE"
    where = (f"origin = 'image' AND {who} AND is_dir = 0 AND deleted = 0 "
             "AND version_of IS NULL AND (lower(class) = ? OR lower(class) = ?)")
    args = (host or image, lab, lab + " (appears empty)")
    with closing(con):
        multi = _multi_volume(con)
        total = int(con.execute(f"SELECT COUNT(*) FROM entries WHERE {where}", args).fetchone()[0])
        rows = con.execute(f"SELECT image, volume, path FROM entries WHERE {where} ORDER BY score DESC, path LIMIT ?",
                           (*args, int(limit))).fetchall()
    return [handle_for(r[0], r[1] or 0, r[2], r[0] in multi) for r in rows], total


def holds_path(case_dir: str | os.PathLike, host: str, path: str, image: str = "") -> Optional[bool]:
    """Whether a host's listed images hold ``path`` (an inner path, either
    separator, case-insensitive, whole or as a trailing part); None when no
    listing of the host's images is indexed (nothing to check against).
    With no host, ``image`` names the image whose own listing is checked (an
    image no evidence link ties to a host is still listed)."""
    con = _connect(case_dir)
    if con is None:
        return None
    p = str(path or "").replace("\\", "/").strip().strip("/").casefold()
    who, key = ("host = ? COLLATE NOCASE", host) if host or not image else ("image = ? COLLATE NOCASE", image)
    with closing(con):
        if not con.execute(f"SELECT 1 FROM entries WHERE origin = 'image' AND {who} LIMIT 1",
                           (key,)).fetchone():
            return None
        row = con.execute(f"SELECT 1 FROM entries WHERE origin = 'image' AND {who} "
                          "AND (lower(path) = ? OR lower(path) LIKE ? ESCAPE '\\') LIMIT 1",
                          (key, p, "%/" + _like_escape(p))).fetchone()
    return bool(row)


def input_entries(case_dir: str | os.PathLike, image: str,
                  names: Iterable[str]) -> Optional[list[tuple[int, str, bool]]]:
    """(volume, path, deleted) of the entries of ``image`` whose name is one
    of ``names`` (case-insensitive; "*" stands for any run of characters; a
    name holding "/" is matched as the path's tail), deleted ones included;
    None when the index cannot say that a name is absent: no listing of the
    image, a listing that is not complete, or one that did not read the
    partition table (volumes_all), so that a volume may be unlisted."""
    con = _connect(case_dir)
    if con is None:
        return None
    with closing(con):
        meta = _meta_get(con, f"image:{image}")
        if not (meta.get("listed") and meta.get("complete") and meta.get("volumes_all")):
            return None
        conds, args = [], [image]
        for n in names:
            n = str(n).replace("\\", "/").strip("/").casefold()
            if not n:
                continue
            pat = _like_escape(n).replace("*", "%")
            if "/" in n:
                conds.append("(lower(path) LIKE ? ESCAPE '\\' OR lower(path) LIKE ? ESCAPE '\\')")
                args += [pat, "%/" + pat]
            else:
                conds.append("lower(name) LIKE ? ESCAPE '\\'")
                args.append(pat)
        if not conds:
            return None
        rows = con.execute("SELECT volume, path, deleted FROM entries WHERE origin = 'image' "
                           f"AND image = ? COLLATE NOCASE AND is_dir = 0 AND ({' OR '.join(conds)})",
                           args).fetchall()
    return [(int(v or 0), str(p), bool(d)) for v, p, d in rows]


def handle_for(image: str, volume: int, path: str, multi: bool) -> str:
    """``<image>::<path>``, with ``@<offset>`` after the image when it holds
    several filesystems."""
    return f"{image}{'@' + str(volume) if multi else ''}::{path}"


def _row_dict(row: sqlite3.Row, multi: set[str]) -> dict[str, Any]:
    d = dict(row)
    d["handle"] = (handle_for(d["image"], d["volume"] or 0, d["path"], d["image"] in multi)
                   if d.get("origin") == "image" else "")
    return d


def scored_rows(case_dir: str | os.PathLike, min_score: int) -> list[dict[str, Any]]:
    """Live entries (versions folded) with ``score >= min_score``, not
    deleted, each with its handle, its version count and folder names, the
    copies made of it and whether timeline rows of it were shown."""
    con = _connect(case_dir)
    if con is None:
        return []
    with closing(con):
        multi = _multi_volume(con)
        versions: dict[int, list[str]] = defaultdict(list)
        for r in con.execute("SELECT version_of, version_folder FROM entries WHERE version_of IS NOT NULL "
                             "AND score >= ?", (min_score,)):
            versions[r[0]].append(r[1])
        copies: dict[int, list[str]] = defaultdict(list)
        for r in con.execute("SELECT entry_id, copy_path FROM copies"):
            copies[r[0]].append(r[1])
        partial = {r[0] for r in con.execute(
            "SELECT DISTINCT s.entry_id FROM partial p JOIN sources s ON s.id = p.source_id")}
        out = []
        for row in con.execute("SELECT * FROM entries WHERE score >= ? AND version_of IS NULL AND deleted = 0",
                               (min_score,)):
            d = _row_dict(row, multi)
            if d["is_dir"]:
                # A folder read as a whole is sized by the files it holds.
                cond, args = _under(d)
                d["size"] = int(con.execute(f"SELECT COUNT(*) FROM entries WHERE {cond} AND is_dir = 0",
                                            args).fetchone()[0])
            d["versions"] = len(versions.get(d["id"], ()))
            d["version_folders"] = sorted(set(versions.get(d["id"], ())))
            d["copies"] = copies.get(d["id"], [])
            d["partial"] = d["id"] in partial
            out.append(d)
        return out


def failed_images(case_dir: str | os.PathLike) -> list[tuple[str, str]]:
    """(image, reason) for each image the builder could not list."""
    con = _connect(case_dir)
    if con is None:
        return []
    with closing(con):
        out = []
        for key, value in con.execute("SELECT key, value FROM meta WHERE key LIKE 'image:%' ORDER BY key"):
            try:
                m = json.loads(value)
            except ValueError:
                continue
            if not m.get("listed"):
                out.append((key[6:], str(m.get("reason") or "not listed")))
        return out


def listed_images(case_dir: str | os.PathLike) -> list[dict[str, Any]]:
    """Each listed image with its host label, entry count and completeness."""
    con = _connect(case_dir)
    if con is None:
        return []
    with closing(con):
        out = []
        for key, value in con.execute("SELECT key, value FROM meta WHERE key LIKE 'image:%' ORDER BY key"):
            try:
                m = json.loads(value)
            except ValueError:
                continue
            if m.get("listed"):
                out.append({"image": key[6:], "host": str(m.get("host") or ""),
                            "entries": int(m.get("entries") or 0), "complete": bool(m.get("complete")),
                            "reason": str(m.get("reason") or "")})
        return out


_GLOB_CHARS = re.compile(r"[*?\[]")


def listing_shape_on() -> bool:
    """C2 item 2 (ATLAS_LISTING_SHAPE): a listing's shape reaches the model
    (the standing per-host digest, a directory summary where rows would be
    cut, a spilled listing returned as its summary)."""
    return index_on() and env_flag("ATLAS_LISTING_SHAPE", True)


# Display bounds of one rendering (never a cap on what is listed or read):
# the summary's directory lines and the digest's host lines; each rendering
# states its total and how to list the rest.
SUMMARY_DIRS = 40
DIGEST_HOSTS = 24
# A directory is rare when at most this share of the listed hosts hold its
# path: a mechanism constant over the listing's structure (no path, name or
# extension), so a tree one host holds stands out of the trees every host
# holds. At least one host.
RARE_SHARE = 0.10


def is_specific(k: int, n: int, share: float = RARE_SHARE) -> bool:
    """Whether a value ``k`` of ``n`` hosts hold is specific to them: at
    most ``share`` of the hosts, with a floor of one host so one- to
    three-host cases still have specific values. The one rarity rule of
    joins, the frontier's host-pass trigger and evidence reopening."""
    import math
    return int(k) <= max(1, math.ceil(share * int(n)))


def _ext(name: str) -> str:
    base = str(name or "").rsplit("/", 1)[-1]
    return base.rsplit(".", 1)[-1].lower() if "." in base.strip(".") else ""


def directory_summary(entries: Iterable[dict[str, Any]], bound: int = SUMMARY_DIRS,
                      multi: set[str] | None = None) -> dict[str, Any]:
    """Per (host, directory) of file entries (``path``, optional ``host``,
    ``image``, ``volume``, ``mtime``): the file count, the commonest
    extensions, the oldest and newest time, two example names and one
    handle; the largest directories first, ``bound`` of them, with the
    totals."""
    acc: dict[tuple[str, str], dict[str, Any]] = {}
    files = 0
    for e in entries:
        path = str(e.get("path") or "").replace("\\", "/").strip("/")
        if not path or e.get("is_dir"):
            continue
        files += 1
        d, _, base = path.rpartition("/")
        key = (str(e.get("host") or ""), d)
        a = acc.get(key)
        if a is None:
            a = acc[key] = {"host": key[0], "dir": d or "/", "files": 0, "exts": {}, "oldest": "", "newest": "",
                            "examples": [], "image": str(e.get("image") or ""), "volume": e.get("volume") or 0}
        a["files"] += 1
        x = _ext(base)
        if x:
            a["exts"][x] = a["exts"].get(x, 0) + 1
        t = str(e.get("mtime") or "")
        if t:
            a["oldest"] = t if not a["oldest"] or t < a["oldest"] else a["oldest"]
            a["newest"] = t if t > a["newest"] else a["newest"]
        if len(a["examples"]) < 2:
            a["examples"].append(base)
    rows = sorted(acc.values(), key=lambda a: (-a["files"], a["host"], a["dir"]))
    out = []
    for a in rows[:max(1, bound)]:
        exts = sorted(a["exts"].items(), key=lambda kv: (-kv[1], kv[0]))[:4]
        row = {"host": a["host"], "dir": a["dir"], "files": a["files"],
               "extensions": {k: v for k, v in exts}, "oldest": a["oldest"], "newest": a["newest"],
               "examples": a["examples"]}
        if a["image"]:
            row["handle"] = handle_for(a["image"], a["volume"] or 0, a["dir"], a["image"] in (multi or ()))
        out.append(row)
    return {"total_files": files, "total_dirs": len(rows), "dirs": out}


def summary_lines(summary: dict[str, Any]) -> list[str]:
    """One line per directory of a directory_summary."""
    lines = []
    for d in summary.get("dirs") or []:
        exts = ", ".join(f"{k} {v}" for k, v in (d.get("extensions") or {}).items())
        when = (f"; {d['oldest']} to {d['newest']}" if d.get("oldest") and d["oldest"] != d.get("newest")
                else (f"; {d['newest']}" if d.get("newest") else ""))
        lines.append(f"{(d['host'] + ' ') if d.get('host') else ''}{d['dir']}: {d['files']} files"
                     f"{' (' + exts + ')' if exts else ''}{when}; e.g. {', '.join(d.get('examples') or [])}"
                     + (f"; handle {d['handle']}" if d.get("handle") else ""))
    more = int(summary.get("total_dirs") or 0) - len(summary.get("dirs") or [])
    if more > 0:
        lines.append(f"{more} more directories (narrow with under=<directory> or a pattern)")
    return lines


def _find_where(pattern: str = "", host: str = "", under: str = "", name: str = "") -> tuple[str, list]:
    where, args = ["1=1"], []
    if host:
        where.append("(host = ? COLLATE NOCASE OR image = ? OR image LIKE ?)")
        args += [host, host.strip("/"), "%/" + host.strip("/").rsplit("/", 1)[-1]]
    if under:
        u = under.replace("\\", "/").strip("/")
        where.append("(path LIKE ? ESCAPE '\\')")
        args.append(_like_escape(u) + "/%")
    if name:
        where.append("name = ? COLLATE NOCASE")
        args.append(name)
    if pattern:
        p = pattern.replace("\\", "/")
        if _GLOB_CHARS.search(p):
            where.append("(lower(path) GLOB ? OR lower(name) GLOB ?)")
            args += [p.lower(), p.lower()]
        else:
            where.append("(path LIKE ? ESCAPE '\\')")
            args.append("%" + _like_escape(p) + "%")
    return " AND ".join(where), args


def find_summary(case_dir: str | os.PathLike, pattern: str = "", host: str = "", under: str = "",
                 bound: int = SUMMARY_DIRS) -> dict[str, Any]:
    """``find``'s matches as a directory_summary (one pass over the index,
    the matching files only)."""
    con = _connect(case_dir)
    if con is None:
        return {"total_files": 0, "total_dirs": 0, "dirs": []}
    sql, args = _find_where(pattern, host, under)
    with closing(con):
        multi = _multi_volume(con)
        rows = con.execute(f"SELECT host, image, volume, path, mtime, is_dir FROM entries WHERE {sql} "
                           "AND version_of IS NULL", args)
        return directory_summary((dict(r) for r in rows), bound, multi)


_DIGEST_CACHE: dict[tuple, dict[str, Any]] = {}


def listing_digest(case_dir: str | os.PathLike, hosts: Iterable[str] | None = None,
                   bound: int = DIGEST_HOSTS) -> dict[str, Any]:
    """Per listed host one line: its file count, its six commonest
    extensions and its three largest rare branches (the topmost directory
    held by at most RARE_SHARE of the listed hosts, ranked by the files
    below it). Hosts with the most files under rare branches first,
    ``bound`` lines, then the total and the call that lists any host.
    ``hosts`` restricts the lines to those hosts. Structure of the listing
    only. ``{"lines": [...], "hosts": n, "shown": m}``."""
    p = db_path(case_dir)
    if not p.is_file():
        return {"lines": [], "hosts": 0, "shown": 0}
    key = (str(p.resolve()), listing_generation(case_dir))
    per = _DIGEST_CACHE.get(key)
    if per is None:
        per = _digest_per_host(case_dir)
        _DIGEST_CACHE.clear()
        _DIGEST_CACHE[key] = per
    wanted = {h.casefold() for h in hosts} if hosts else None
    rows = [r for h, r in per.items() if wanted is None or h.casefold() in wanted]
    rows.sort(key=lambda r: (-r["rare_files"], -r["files"], r["host"]))
    lines = []
    for r in rows[:max(1, bound)]:
        exts = ", ".join(f"{k} {v:,}" for k, v in r["exts"])
        rare = "; ".join(f"{d} ({n:,} files)" for d, n in r["rare"]) or "none"
        lines.append(f"{r['host']}: {r['files']:,} files ({exts}); held by this host only or few: {rare}")
    if len(rows) > len(lines):
        lines.append(f"{len(rows) - len(lines)} more hosts not shown; tsk.index_find(host=<host>) lists any "
                     "host's files, under=<directory> one directory")
    return {"lines": lines, "hosts": len(rows), "shown": min(len(rows), max(1, bound))}


def _digest_per_host(case_dir: str | os.PathLike) -> dict[str, dict[str, Any]]:
    import math
    con = _connect(case_dir)
    if con is None:
        return {}
    files_by_host: dict[str, list[str]] = {}
    with closing(con):
        for r in con.execute("SELECT host, path FROM entries WHERE origin = 'image' AND is_dir = 0 "
                             "AND deleted = 0 AND version_of IS NULL AND host IS NOT NULL AND host != ''"):
            files_by_host.setdefault(str(r[0]), []).append(str(r[1]))
    holders: dict[str, int] = {}
    for paths in files_by_host.values():
        dirs: set[str] = set()
        for path in paths:
            parts = path.casefold().split("/")[:-1]
            for i in range(1, len(parts) + 1):
                dirs.add("/".join(parts[:i]))
        for d in dirs:
            holders[d] = holders.get(d, 0) + 1
    limit = max(1, math.ceil(RARE_SHARE * len(files_by_host)))
    out: dict[str, dict[str, Any]] = {}
    for host, paths in files_by_host.items():
        exts: dict[str, int] = {}
        branches: dict[str, int] = {}
        for path in paths:
            x = _ext(path)
            if x:
                exts[x] = exts.get(x, 0) + 1
            parts = path.split("/")[:-1]
            for i in range(1, len(parts) + 1):
                d = "/".join(parts[:i])
                if holders.get(d.casefold(), 0) <= limit:
                    branches[d] = branches.get(d, 0) + 1
                    break
        rare = sorted(branches.items(), key=lambda kv: (-kv[1], kv[0]))
        out[host] = {"host": host, "files": len(paths),
                     "exts": sorted(exts.items(), key=lambda kv: (-kv[1], kv[0]))[:6],
                     "rare": rare[:3], "rare_files": sum(n for _d, n in rare)}
    return out


def find(case_dir: str | os.PathLike, pattern: str = "", host: str = "", under: str = "", name: str = "",
         state: str = "", limit: int = 40, offset: int = 0) -> dict[str, Any]:
    """Rows of the index: ``pattern`` a case-insensitive substring or glob
    over the path (or the name), ``host`` a host label or an image path (a
    host-less image is found by its path), ``under`` a directory prefix,
    ``name`` an exact file name, ``state`` one of unread (not read, not
    shown: skipped ones included), partial (timeline rows shown), read, or
    skipped (no export covers it and no read). ``total`` is exact and
    ``offset`` pages through it."""
    con = _connect(case_dir)
    if con is None:
        return {"total": 0, "rows": []}
    sql, args = _find_where(pattern, host, under, name)
    with closing(con):
        multi = _multi_volume(con)
        order = " ORDER BY version_of IS NOT NULL, score DESC, size DESC, id"
        if state:
            rows = [_row_dict(r, multi) for r in con.execute(f"SELECT * FROM entries WHERE {sql}{order}", args)]
            _annotate(con, case_dir, rows, multi)
            wanted = {"unread": ("unread", "skipped")}.get(state, (state,))
            rows = [r for r in rows if r["state"] in wanted]
            total = len(rows)
            rows = rows[offset:offset + limit]
        else:
            total = int(con.execute(f"SELECT COUNT(*) FROM entries WHERE {sql}", args).fetchone()[0])
            rows = [_row_dict(r, multi) for r in con.execute(
                f"SELECT * FROM entries WHERE {sql}{order} LIMIT ? OFFSET ?", [*args, limit, offset])]
            _annotate(con, case_dir, rows, multi)
    return {"total": total, "rows": rows}


def _like_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _annotate(con: sqlite3.Connection, case_dir: str | os.PathLike, rows: list[dict[str, Any]],
              multi: set[str], reads: Optional[list[dict[str, Any]]] = None) -> None:
    """Each row's export coverage, version count, live handle and read
    state (read, partial, skipped, unread) from the trace (``reads``:
    examined_items' reading calls, taken once for several row lists)."""
    if not rows:
        return
    ids = [r["id"] for r in rows]
    cover: dict[int, dict[str, Any]] = {}
    partial: set[int] = set()
    versions: Counter = Counter()
    live: dict[int, str] = {}
    for chunk in (ids[i:i + 500] for i in range(0, len(ids), 500)):
        q = ",".join("?" * len(chunk))
        for s in con.execute(f"SELECT * FROM sources WHERE entry_id IN ({q})", chunk):
            cover.setdefault(s["entry_id"], {"in": s["export"], "rows": s["rows"], "first": s["first"],
                                             "last": s["last"]})
        for p in con.execute(f"SELECT DISTINCT s.entry_id FROM partial p JOIN sources s ON s.id = p.source_id "
                             f"WHERE s.entry_id IN ({q})", chunk):
            partial.add(p[0])
        for v in con.execute(f"SELECT version_of, COUNT(*) FROM entries WHERE version_of IN ({q}) "
                             f"GROUP BY version_of", chunk):
            versions[v[0]] = v[1]
    want_live = sorted({r["version_of"] for r in rows if r.get("version_of")})
    for chunk in (want_live[i:i + 500] for i in range(0, len(want_live), 500)):
        q = ",".join("?" * len(chunk))
        for r in con.execute(f"SELECT * FROM entries WHERE id IN ({q})", chunk):
            live[r["id"]] = _row_dict(r, multi)["handle"]
    from core.artifact_value import examined_items
    read = examined_items(case_dir, [{"name": r["name"], "lpath": r["path"], "host": r["host"],
                                      "handle": r["handle"], "index_id": r["id"],
                                      "kind": "directory" if r["is_dir"] else "file"}
                                     for r in rows], reads)
    for r, was_read in zip(rows, read):
        r["export"] = cover.get(r["id"])
        r["versions"] = versions.get(r["id"], 0)
        if r.get("version_of"):
            r["version_of"] = live.get(r["version_of"], r["version_of"])
        r["state"] = ("read" if was_read else "partial" if r["id"] in partial
                      else "unread" if r["id"] in cover else "skipped")


def processed_entries(case_dir: str | os.PathLike) -> dict[int, tuple[str, str, Optional[int]]]:
    """The index entries a parser reported processing, from the ``processed``
    stamp its own wrapper put on the parse entry (the tool's own report of
    the files it read): {entry id: (output, filter, rows kept or None)}; a
    parse that kept rows of an entry wins over one that kept none, else the
    latest. A parse with no such report stamps nothing and names no entry
    here; nor does a parse whose output a later parse wrote over
    (overwritten_entries)."""
    return _parse_stamps(case_dir)[0]


def overwritten_entries(case_dir: str | os.PathLike) -> dict[int, tuple[str, int]]:
    """The index entries a parse processed into an output that a later
    parse wrote over, and that no live parse holds: {entry id: (output, the
    overwriting call)}. Their rows are in no output any more: the step is
    a parse into an output of their own, never a query of that output."""
    return _parse_stamps(case_dir)[1]


def _parse_stamps(case_dir: str | os.PathLike) -> tuple[dict[int, tuple[str, str, Optional[int]]],
                                                        dict[int, tuple[str, int]]]:
    live, gone = _parse_stamp_idents(case_dir)
    return ({int(i): v for (k, i), v in live.items() if k == "entry"},
            {int(i): v for (k, i), v in gone.items() if k == "entry"})


def _parse_stamp_idents(case_dir: str | os.PathLike) -> tuple[dict[tuple, tuple[str, str, Optional[int]]],
                                                               dict[tuple, tuple[str, int]]]:
    """_parse_stamps over every identity a stamp names (an index entry, a
    case file by its path: core.evidence_identity.identify)."""
    from core.evidence_identity import identify
    from core.execution_log import trace_entries
    stamps = [(int(e.get("call_id") or 0), e["processed"]) for e in trace_entries(case_dir) or []
              if e.get("type") == "tool_call" and isinstance(e.get("processed"), dict)]
    last = {str(st.get("output") or ""): cid for cid, st in stamps if st.get("output")}
    out: dict[tuple, tuple[str, str, Optional[int]]] = {}
    gone: dict[tuple, tuple[str, int]] = {}
    for cid, stamp in stamps:
        output = str(stamp.get("output") or "")
        over = last.get(output, cid) if output else cid
        for f in stamp.get("files") or []:
            rows = (f or {}).get("rows")
            rows = int(rows) if isinstance(rows, int) else None
            for ident in identify(case_dir, str((f or {}).get("path") or "")):
                if len(ident) != 2 or ident[0] not in ("entry", "file"):
                    continue
                if over != cid:
                    gone[ident] = (output, over)
                    continue
                prior = out.get(ident)
                if prior is None or rows != 0 or prior[2] == 0:
                    out[ident] = (output, str(stamp.get("filter") or ""), rows)
    return out, {i: g for i, g in gone.items() if i not in out}


def parsed_entry_outputs(case_dir: str | os.PathLike) -> dict[int, str]:
    """{entry id: output} of every entry a parser processed: named by a
    parser's own report (processed_entries) or holding rows in a joined
    table (sources). Whether a row of it was looked at is the reader's
    question (partial, read)."""
    live, gone = _parse_stamps(case_dir)
    out = {eid: o for eid, (o, _f, _rows) in live.items()}
    for eid, (o, _call) in gone.items():
        out.setdefault(eid, o)
    con = _connect(case_dir)
    if con is not None:
        with closing(con):
            for eid, export in con.execute("SELECT entry_id, export FROM sources WHERE entry_id IS NOT NULL"):
                out.setdefault(int(eid), str(export))
    return out


def read_state_by_class(case_dir: str | os.PathLike, images: list[str],
                        files: Optional[dict[str, dict[str, list[str]]]] = None
                        ) -> dict[str, dict[str, dict[str, Any]]]:
    """Per image, per content class of its live entries, how many the trace
    shows read and partly read (each entry's read state, _annotate), and how
    many a parser processed with no row of them looked at (``parsed``: rows
    of the entry stand in a joined table, or the parser's own report names
    the entry, and none was shown), with those tables and the filters the
    parses ran with: {image: {label: {"total", "read", "partial", "parsed",
    "outputs", "filters"}}}, labels without the empty mark. ``files``: case
    files outside the images by class ({key: {label: [case paths]}}, a
    collected tree's or a loose file's members), counted by the same rule
    under their key: read when a successful content read named the file
    (core.evidence_identity), parsed when only a parser's own report did; a
    case file has no partly read state (no joined table holds its rows).
    One pass over the trace serves every image and file; the rows are taken
    one image at a time."""
    files = {k: v for k, v in (files or {}).items() if any(v.values())}
    con = _connect(case_dir) if images else None
    if con is None and not files:
        return {}
    from core.artifact_value import _first_reads, reading_calls
    try:
        parses, gone = _parse_stamp_idents(case_dir)
    except Exception:  # noqa: BLE001
        parses, gone = {}, {}
    out: dict[str, dict[str, dict[str, Any]]] = {}
    reads = None
    if con is not None:
        with closing(con):
            multi = _multi_volume(con)
            reads = reading_calls(case_dir, [str(_meta_get(con, f"image:{i}").get("host") or "") for i in images])
            from core.evidence_disposition import suffix_classes
            for image in images:
                rows = [_row_dict(r, multi) for r in con.execute(
                    "SELECT * FROM entries WHERE origin = 'image' AND image = ? AND is_dir = 0 AND deleted = 0 "
                    "AND version_of IS NULL AND class IS NOT NULL AND class != ''", (image,))]
                labelled = [(str(r["class"]).removesuffix(" (appears empty)"), r) for r in rows]
                # The format classes counted by name where the class column
                # holds no such label (a mail store, a capture): their members
                # as the disposition counts them (_image_classes).
                present = {lbl for lbl, _r in labelled}
                for label, sufs in suffix_classes().items():
                    if label in present:
                        continue
                    like = " OR ".join("lower(name) LIKE ?" for _ in sufs)
                    extra = [_row_dict(r, multi) for r in con.execute(
                        "SELECT * FROM entries WHERE origin = 'image' AND image = ? AND is_dir = 0 AND deleted = 0 "
                        f"AND version_of IS NULL AND ({like})", (image, *[f"%{s}" for s in sufs]))]
                    rows += extra
                    labelled += [(label, r) for r in extra]
                _annotate(con, case_dir, rows, multi, reads)
                for label, r in labelled:
                    ident = ("entry", int(r["id"]))
                    _tally(out.setdefault(image, {}), label,
                           r.get("state") or "", parses.get(ident),
                           (r.get("export") or {}).get("in") if r.get("state") == "unread" else "",
                           (gone.get(ident) or ("",))[0])
    if files:
        first = _first_reads(reads if reads is not None else reading_calls(case_dir, []))
        for key, labels in files.items():
            for label, rels in labels.items():
                for rel in rels:
                    ident = ("file", rel)
                    _tally(out.setdefault(key, {}), label, "read" if ident in first else "", parses.get(ident), "",
                           (gone.get(ident) or ("",))[0])
    return out


def _tally(by_label: dict[str, dict[str, Any]], label: str, state: str,
           parse: Optional[tuple[str, str, Optional[int]]], export: str, gone_output: str) -> None:
    """Count one file of a class into read_state_by_class's counts: its
    read state (read, partial), else a parse of it (the parser's report:
    no row kept under a filter, or parsed into an output; rows in a joined
    table), else an output a later parse wrote over."""
    acc = by_label.setdefault(label, {"total": 0, "read": 0, "partial": 0, "parsed": 0, "outputs": [],
                                      "filters": [], "no_rows": 0, "no_rows_filters": [], "overwritten": 0,
                                      "overwritten_outputs": []})
    acc["total"] += 1
    acc["read"] += state == "read"
    acc["partial"] += state == "partial"
    if state in ("read", "partial"):
        return
    if parse and parse[2] == 0 and not export:
        # Processed under a filter that kept no row of it: its output holds
        # nothing to query.
        acc["no_rows"] += 1
        if parse[1] and parse[1] not in acc["no_rows_filters"]:
            acc["no_rows_filters"].append(parse[1])
        return
    if parse or export:
        acc["parsed"] += 1
        for o in (export, parse[0] if parse else ""):
            if o and o not in acc["outputs"]:
                acc["outputs"].append(o)
        if parse and parse[1] and parse[1] not in acc["filters"]:
            acc["filters"].append(parse[1])
    elif gone_output:
        # Parsed into an output a later parse wrote over: no output holds
        # its rows now.
        acc["overwritten"] += 1
        if gone_output not in acc["overwritten_outputs"]:
            acc["overwritten_outputs"].append(gone_output)


def find_rows(case_dir: str | os.PathLike, **kw: Any) -> list[dict[str, Any]]:
    """``find``'s rows in the shape of the tool result."""
    res = find(case_dir, **kw)
    return [_public_row(r) for r in res["rows"]]


def _public_row(r: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {
        "handle": r["handle"] or f"{r['image']}::{r['path']}", "host": r["host"] or "",
        "size": r["size"], "modified": r["mtime"] or "", "deleted": bool(r["deleted"]),
        "is_dir": bool(r["is_dir"]), "image": r["image"], "offset_sectors": r["volume"] or 0,
        "inode": r["inode"], "origin": r["origin"],
        "versions": r.get("versions", 0), "class": r["class"] or "",
        "export": r.get("export"), "state": r.get("state", "")}
    if r.get("version_of"):
        out["version_of"] = r["version_of"]
        out["version_folder"] = r["version_folder"]
    return out


def find_by_names(case_dir: str | os.PathLike, names: Iterable[str],
                  hosts: Optional[Iterable[str]] = None) -> list[dict[str, Any]]:
    """Live, not deleted entries whose name or name stem is one of
    ``names`` (any score), on ``hosts`` when given (a host-less image
    stands for any host)."""
    wanted = {n.lower() for n in names if n}
    con = _connect(case_dir)
    if con is None or not wanted:
        return []
    hostset = {h.casefold() for h in hosts} if hosts is not None else None
    names = sorted(wanted)
    cond = " OR ".join(["lower(name) = ?", "lower(name) LIKE ? ESCAPE '\\'"] * len(names))
    args: list[str] = []
    for n in names:
        args += [n, _like_escape(n) + ".%"]
    with closing(con):
        multi = _multi_volume(con)
        out = []
        for row in con.execute("SELECT * FROM entries WHERE version_of IS NULL AND deleted = 0 AND is_dir = 0 "
                               f"AND ({cond})", args):
            name = str(row["name"] or "").lower()
            if name not in wanted and name.rsplit(".", 1)[0] not in wanted:
                continue
            h = str(row["host"] or "").casefold()
            if hostset is not None and h and h not in hostset:
                continue
            out.append(_row_dict(row, multi))
        return out


def class_absence_candidates(case_dir: str | os.PathLike, host: str, words: Iterable[str]) -> list[dict[str, Any]]:
    """The unread paths on ``host`` that an absence statement's class words
    name: a path counts when it holds at least two of the words (or the one
    word given), most words first. The consumer is the absence gate."""
    words = [w for w in dict.fromkeys(str(w).casefold() for w in words) if w]
    if not words:
        return []
    need = min(2, len(words))
    score: Counter = Counter()
    rows: dict[str, dict[str, Any]] = {}
    for w in words:
        hit: set[str] = set()
        # Every unread row of the word (the state filter reads them all
        # anyway), so the count a refusal states is exact.
        for r in find(case_dir, pattern=w, host=host, state="unread", limit=1_000_000)["rows"]:
            key = r["handle"] or r["path"]
            hit.add(key)
            rows.setdefault(key, {"handle": r["handle"], "path": r["path"], "size": r["size"], "state": r["state"]})
        score.update(hit)
    return [rows[k] for k, n in score.most_common() if n >= need]


# ── copies and partial views ─────────────────────────────────────────────

def record_copy(case_dir: str | os.PathLike, copy_path: str, entry_id: int, call_id: Optional[int],
                size: Optional[int], sha256: str = "") -> None:
    """Tie an extracted copy (case-relative path) to the entry it came from."""
    con = _connect(case_dir, create=True)
    if con is None:
        return
    with _WRITE_LOCK, closing(con):
        con.execute("INSERT OR REPLACE INTO copies VALUES (?,?,?,?,?)",
                    (_rel(Path(case_dir), copy_path), int(entry_id), call_id, size, sha256))
        con.commit()


def copy_source(case_dir: str | os.PathLike, path: str) -> Optional[dict[str, Any]]:
    """Provenance of an extracted copy: ``{entry_id, host, image,
    inner_path, call_id, size, sha256}``, None when the index knows no such
    copy."""
    con = _connect(case_dir)
    if con is None:
        return None
    with closing(con):
        row = con.execute(
            "SELECT c.entry_id, c.call_id, c.size, c.sha256, e.host, e.image, e.path FROM copies c "
            "JOIN entries e ON e.id = c.entry_id WHERE c.copy_path = ?", (_rel(Path(case_dir), path),)).fetchone()
    if row is None:
        return None
    return {"entry_id": row["entry_id"], "host": row["host"] or "", "image": row["image"],
            "inner_path": row["path"], "call_id": row["call_id"], "size": row["size"], "sha256": row["sha256"]}


_COPY_SHA: dict[tuple[str, int, int], str] = {}
# A copy's sha256 field when the copy was registered by its size alone.
SIZE_ONLY = "size-only"
_SHA256_RE = re.compile(r"[0-9a-f]{64}")


def file_sha256(path: str | os.PathLike) -> str:
    """The sha256 of a file, remembered per version (path, size, mtime) for
    the process: a copy is hashed once, not at every lookup."""
    import hashlib
    st = os.stat(path)
    key = (str(path), st.st_size, st.st_mtime_ns)
    hit = _COPY_SHA.get(key)
    if hit is None:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        hit = h.hexdigest()
        if len(_COPY_SHA) > 10_000:
            _COPY_SHA.clear()
        _COPY_SHA[key] = hit
    return hit


def copy_unchanged(case_dir: str | os.PathLike, record: dict[str, Any], path: str) -> bool:
    """Whether the file at ``path`` is still the copy ``record`` (copy_source)
    registered: its size, and its sha256 when one was stored (a copy
    registered by its size alone carries SIZE_ONLY). A later writer of the
    same path makes it another file."""
    try:
        full = Path(case_dir) / _rel(Path(case_dir), path)
        size = full.stat().st_size
        if record.get("size") is not None and size != int(record["size"]):
            return False
        sha = str(record.get("sha256") or "")
        return not _SHA256_RE.fullmatch(sha) or file_sha256(full) == sha
    except OSError:
        return False


_COPY_MAP: dict[str, tuple[tuple, dict[str, dict[str, str]]]] = {}


def _index_version(case_dir: str | os.PathLike) -> tuple:
    """The index files' size and mtime (the database and its write-ahead
    log): what the per-index memos are keyed by."""
    p = db_path(case_dir)
    try:
        return tuple((os.stat(f).st_size, os.stat(f).st_mtime_ns) if os.path.exists(f) else ()
                     for f in (str(p), str(p) + "-wal"))
    except OSError:
        return ()


def copy_map(case_dir: str | os.PathLike) -> dict[str, dict[str, str]]:
    """Every registered copy by its case-relative path (case-folded): the
    image, inner path and host it came from. Remembered while the index
    files are unchanged (the work-order matcher reads it per trace call)."""
    p = db_path(case_dir)
    sig = _index_version(case_dir)
    key = str(p)
    hit = _COPY_MAP.get(key)
    if hit is not None and hit[0] == sig:
        return hit[1]
    out: dict[str, dict[str, str]] = {}
    con = _connect(case_dir)
    if con is not None:
        with closing(con):
            for r in con.execute("SELECT c.copy_path, e.image, e.path, e.host FROM copies c "
                                 "JOIN entries e ON e.id = c.entry_id"):
                out[str(r[0]).casefold()] = {"image": r[1], "inner_path": r[2], "host": r[3] or "",
                                             "copy_path": str(r[0])}
    _COPY_MAP[key] = (sig, out)
    return out


def copies_under(case_dir: str | os.PathLike, folder: str, tool: str = "") -> list[dict[str, str]]:
    """The registered copies inside a folder a call names (a parser run over
    an extraction folder reads them): each ``{copy_path, image, inner_path,
    host}``. With ``tool``, only the copies its input kind takes
    (core.input_kind.reads_kind); a tool the registry does not know takes
    every copy."""
    rel = _rel(Path(case_dir), str(folder or "")).replace("\\", "/").strip("/").casefold()
    if not rel or "/" not in rel and rel in ("analysis", "exports", "evidence"):
        return []
    # Remembered per index version, folder and tool: the input-kind test
    # opens each copy (a hive's magic), too dear for every trace call that
    # names the folder.
    key = (str(db_path(case_dir)), _index_version(case_dir), rel, str(tool or ""))
    hit = _COPIES_UNDER.get(key)
    if hit is not None:
        return [dict(o) for o in hit]
    prefix = rel + "/"
    out = [dict(v) for k, v in copy_map(case_dir).items() if k.startswith(prefix)]
    if tool and out:
        from core.input_kind import reads_kind
        out = [o for o in out if reads_kind(tool, str(Path(case_dir) / o["copy_path"])) is not False]
    if len(_COPIES_UNDER) > 512:
        _COPIES_UNDER.clear()
    _COPIES_UNDER[key] = [dict(o) for o in out]
    return out


_COPIES_UNDER: dict[tuple, list[dict[str, str]]] = {}


# The live entry at a path inside an image's volume, keyed by the host first:
# every row of an image carries the image's host (one host per listing in
# _insert_entries), and entries_host_path (host, path) narrows the lookup to
# the path's few rows; image and volume then tell apart two images of one
# host and the volumes of one image. Keyed by the image alone the planner
# has only entries_image_inode and visits every row of the image per lookup
# (hundreds of thousands on a full disk). ``host IS ?`` keeps a NULL host
# (a row another writer left without one) findable; the index serves IS as
# it serves =.
_LIVE_ENTRY_SQL = ("SELECT id FROM entries WHERE host IS ? AND path = ? COLLATE NOCASE AND image = ? "
                   "AND volume IS ? AND origin = 'image' AND version_of IS NULL ORDER BY deleted, id LIMIT 1")


def _live_entry_at(con: sqlite3.Connection, host: Optional[str], image: str, volume: int,
                   path: str) -> Optional[int]:
    row = con.execute(_LIVE_ENTRY_SQL, (host, path, image, volume)).fetchone()
    return int(row[0]) if row else None


def entry_id_of(case_dir: str | os.PathLike, image: str, volume: int, path: str,
                host: Optional[str] = None) -> Optional[int]:
    """The live index entry at a path inside an image's volume. ``host`` is
    the image's host as its rows carry it; without it, one row of the image
    says which (one indexed probe)."""
    con = _connect(case_dir)
    if con is None:
        return None
    with closing(con):
        if host is None:
            one = con.execute("SELECT host FROM entries WHERE image = ? LIMIT 1", (image,)).fetchone()
            if one is None:
                return None
            host = one[0]
        return _live_entry_at(con, host, image, volume, path)


def record_folder_copy(case_dir: str | os.PathLike, folder_copy: str, entry_id: int, call_id: Optional[int]) -> int:
    """Tie a folder copy to its entry and every file inside it to its own
    entry (the folder's path in the image joined with the file's path in
    the copy), so a read of one file in the copy credits that file. One
    connection: the walk and the lookups are reads and run outside the
    write lock; the rows go in with one statement and one commit. Returns
    the number of files tied; the folder itself is tied either way."""
    con = _connect(case_dir)
    if con is None:
        return 0
    case = Path(case_dir)
    root = Path(folder_copy)
    rows = [(_rel(case, folder_copy), int(entry_id), call_id, None, "")]
    with closing(con):
        folder = con.execute("SELECT host, image, volume, path FROM entries WHERE id = ?",
                             (int(entry_id),)).fetchone()
        if folder is not None:
            for f in sorted(p for p in root.rglob("*") if p.is_file()):
                inner = f"{folder['path']}/{f.relative_to(root).as_posix()}"
                eid = _live_entry_at(con, folder["host"], folder["image"], folder["volume"], inner)
                if eid is None:
                    continue
                try:
                    size = f.stat().st_size
                except OSError:
                    size = None
                rows.append((_rel(case, str(f)), eid, call_id, size, ""))
        with _WRITE_LOCK:
            con.executemany("INSERT OR REPLACE INTO copies VALUES (?,?,?,?,?)", rows)
            con.commit()
    return len(rows) - 1


def handle_parts(case_dir: str | os.PathLike, value: str) -> Optional[dict[str, str]]:
    """A handle's image (case-relative, when it names one image of the
    case), host and inner path; None for anything that is not a handle."""
    m = HANDLE_RE.match(str(value or "").strip())
    if not m or not looks_like_handle(value):
        return None
    img, _err = _match_image(Path(case_dir), m.group("image"))
    return {"image": img["rel"] if img else m.group("image"), "host": img["host"] if img else "",
            "matched": img is not None,
            "inner_path": m.group("path").replace("\\", "/").strip().strip("/")}


def copy_paths(case_dir: str | os.PathLike) -> set[str]:
    """The case-relative paths of every registered copy."""
    con = _connect(case_dir)
    if con is None:
        return set()
    with closing(con):
        return {r[0] for r in con.execute("SELECT copy_path FROM copies")}


# The column a parsed timeline row names its source file in, by format
# (plaso l2tcsv, plaso dynamic, EvtxECmd): public column names.
_SOURCE_COLS = ("filename", "display_name", "sourcefile")
_ROW_KEYS = ("rows", "hits", "matches", "results")


def _sources_at(path: Path, ordinals: list[int]) -> list[str]:
    """The source column's value at each data-row ordinal (1-based, the
    table tools' ``_row``) of a CSV: one pass, stopping at the highest
    ordinal asked for; "" for a row without one, [] when the table names
    no source column or cannot be read."""
    if not ordinals:
        return []
    want = set(ordinals)
    last = max(want)
    out: list[str] = []
    try:
        with path.open(encoding="utf-8", errors="replace", newline="") as fh:
            reader = csv.reader(fh)
            header = [str(c).strip().lstrip("\ufeff").lower() for c in next(reader, [])]
            col = next((header.index(c) for c in _SOURCE_COLS if c in header), None)
            if col is None:
                return []
            for n, cells in enumerate(reader, start=1):
                if n in want:
                    out.append(cells[col] if col < len(cells) else "")
                if n >= last:
                    break
    except (OSError, csv.Error):
        return []
    return out


def observe_result(case_dir: str | os.PathLike, tool: str, result: Any, shown_row_ids: Optional[list],
                   call_id: Optional[int], export: str = "") -> int:
    """Mark the sources whose rows a table result showed as partially seen
    (``partial``), with the call id and the count of shown rows. The rows
    come from the un-rendered result; ``shown_row_ids`` are the ones the
    view printed (every returned row when None, an upper bound). Partial
    never counts as read. Returns the number of sources marked."""
    if not index_on() or not isinstance(result, dict) or call_id is None:
        return 0
    rows = next((result[k] for k in _ROW_KEYS if isinstance(result.get(k), list)), None)
    if not rows:
        return 0
    export = export or str(result.get("path") or result.get("file") or "")
    if not export:
        return 0
    con = _connect(case_dir)
    if con is None:
        return 0
    rel = _rel(Path(case_dir), export)
    wanted = None if shown_row_ids is None else set(shown_row_ids)
    counts: Counter = Counter()
    with _WRITE_LOCK, closing(con):
        by_path: dict[str, list[int]] = defaultdict(list)
        for s in con.execute("SELECT id, source_path FROM sources WHERE export = ?", (rel,)):
            by_path[str(s["source_path"]).casefold()].append(s["id"])
        if not by_path:
            return 0
        missing: list[int] = []
        for i, row in enumerate(rows):
            if not isinstance(row, dict) or (wanted is not None and row.get("_row", i) not in wanted):
                continue
            low = {str(k).lower(): v for k, v in row.items()}
            src = next((low[c] for c in _SOURCE_COLS if c in low and low[c]), "")
            if not src and isinstance(row.get("_row"), int):
                # The view chose its columns and left the source out: the
                # row's own ordinal names it in the table.
                missing.append(int(row["_row"]))
                continue
            for sid in by_path.get(norm_source(str(src)).casefold(), ()):
                counts[sid] += 1
        for src in _sources_at(Path(case_dir) / rel, missing):
            for sid in by_path.get(norm_source(str(src)).casefold(), ()):
                counts[sid] += 1
        con.executemany("INSERT INTO partial VALUES (?,?,?)", [(sid, call_id, n) for sid, n in counts.items()])
        con.commit()
    return len(counts)


# ── the host-first view (the map the director reads) ─────────────────────
#
# Organised by host, never by a rank over the whole estate: a cut at ten of
# thousands of rows ranked by value shows the ties' alphabetical order. The
# host order is seeded from the case's own text before any claim exists:
# the hosts the open questions name, then the hosts the brief's narrative
# names (core.case_knowledge.narrative_sections, which leaves the inventory
# sections out: they name every image), each by mention count, then unread
# count. Then the hosts the run's active claims name, by claim count, with
# VIEW_RESERVED of the VIEW_HOSTS slots kept for them (unused ones go back
# to the seed), so a finding can bring a host forward and a wrong early
# claim moves at most those slots. Free slots take the remaining hosts by
# unread count. Never by name.

VIEW_HOSTS = 12
VIEW_RESERVED = 4
_VIEW_ITEMS = 14


def _mentions(hosts: list[str], texts: Iterable[str]) -> Counter:
    from core.forensic_citation import host_mentioned
    out: Counter = Counter()
    for text in texts:
        for line in str(text or "").splitlines():
            for h in hosts:
                if line.strip() and host_mentioned(h, line):
                    out[h] += 1
    return out


def _seed_texts(case_dir: str | os.PathLike) -> tuple[list[str], list[str]]:
    """The open questions' text and the brief's narrative sections."""
    questions: list[str] = []
    try:
        from core.investigation_tasks import actionable_tasks
        for t in actionable_tasks(case_dir):
            questions.append(str(t.get("text") or ""))
            questions += [str(p.get("text") or "") for p in t.get("parts") or [] if isinstance(p, dict)]
    except Exception:  # noqa: BLE001
        pass
    brief: list[str] = []
    try:
        from core.case_knowledge import narrative_sections
        from core.investigation_tasks import read_case_markdown
        brief = [body for _h, body in narrative_sections(read_case_markdown(case_dir))]
    except Exception:  # noqa: BLE001
        pass
    return questions, brief


def _claim_hosts(case_dir: str | os.PathLike) -> Counter:
    out: Counter = Counter()
    try:
        from core.claim_graph import load_graph
        nodes = (load_graph(case_dir).get("nodes") or {}).values()
    except Exception:  # noqa: BLE001
        return out
    for n in nodes:
        if not isinstance(n, dict) or n.get("kind", "claim") not in ("claim", "conclusion"):
            continue
        if n.get("status") in ("superseded", "withdrawn"):
            continue
        for h in {str(h).strip() for h in [n.get("host"), *(n.get("hosts") or [])] if str(h or "").strip()}:
            out[h] += 1
    return out


def _view_model(case_dir: str | os.PathLike) -> Optional[dict[str, Any]]:
    """The hosts in view order with their unread index items and tags, the
    hosts left for the roll-up and the images not listed; None when the
    index is off or holds nothing."""
    if not index_on() or not db_path(case_dir).is_file():
        return None
    from core.artifact_value import high_value_state
    items = [i for i in high_value_state(case_dir)["items"]
             if i.get("state") == "open" and str(i.get("source") or "").startswith("index:")]
    by_label: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for i in items:
        by_label[str(i.get("host") or i.get("image") or "")].append(i)
    failed = failed_images(case_dir)
    if not by_label and not failed:
        return {"order": [], "items": {}, "tags": {}, "rest": [], "failed": []}
    try:
        from core.forensic_citation import known_case_hosts
        case_hosts = list(dict.fromkeys(known_case_hosts(case_dir)))
    except Exception:  # noqa: BLE001
        case_hosts = []
    labels = list(dict.fromkeys(case_hosts + [h for h in by_label if h]))
    questions, brief = _seed_texts(case_dir)
    in_q, in_b = _mentions(labels, questions), _mentions(labels, brief)
    claims = _claim_hosts(case_dir)
    unread = {h: len(v) for h, v in by_label.items()}

    def _key(counter: Counter):
        return lambda h: (-counter[h], -unread.get(h, 0))
    canon = {h.casefold(): h for h in by_label}

    def _present(hosts: Iterable[str]) -> list[str]:
        return [canon[h.casefold()] for h in hosts if h.casefold() in canon]
    seed = _present(sorted([h for h in labels if in_q[h]], key=_key(in_q)))
    seed += [h for h in _present(sorted([h for h in labels if in_b[h]], key=_key(in_b))) if h not in seed]
    claim_named = Counter({canon[h.casefold()]: n for h, n in claims.items() if h.casefold() in canon})
    extra = [h for h in sorted(claim_named, key=_key(claim_named)) if h not in seed]
    reserved = extra[:VIEW_RESERVED]
    order = seed[:VIEW_HOSTS - len(reserved)] + reserved
    rest = sorted((h for h in by_label if h not in order), key=lambda h: -unread[h])
    while len(order) < VIEW_HOSTS and rest:
        order.append(rest.pop(0))
    tags: dict[str, list[str]] = {}
    for h in order:
        t = []
        if in_q.get(h):
            t.append("question")
        if in_b.get(h):
            t.append("brief")
        if claim_named.get(h):
            t.append(f"{claim_named[h]} finding{'s' if claim_named[h] != 1 else ''}")
        if h not in case_hosts and "/" in h:
            t.append("no host in the links")
        tags[h] = t
    return {"order": order, "items": by_label, "tags": tags, "rest": rest, "failed": failed}


def _size(n: Any) -> str:
    try:
        n = int(n)
    except (TypeError, ValueError):
        return ""
    if n >= 1 << 30:
        return f"{n / (1 << 30):.1f} GB"
    if n >= 1 << 20:
        return f"{n // (1 << 20)} MB"
    if n >= 1 << 10:
        return f"{n // (1 << 10)} KB"
    return f"{n} bytes"


def _item_text(name: str, group: list[dict[str, Any]]) -> str:
    first = group[0]
    notes: list[str] = []
    if first.get("kind") == "directory":
        measure = f"{first.get('size') or 0} files"
    else:
        measure = _size(first.get("size")) if len(group) == 1 else ""
    if len(group) > 1:
        notes.append(f"{len(group)} places")
    if any(i.get("partial") for i in group):
        notes.append("timeline rows only")
    folders = sorted({f for i in group for f in i.get("version_folders") or []})
    copies = sum(int(i.get("versions") or 0) for i in group)
    if copies:
        notes.append(f"{copies} cop{'ies' if copies != 1 else 'y'} under "
                     + ", ".join(folders[:3]) + (f" +{len(folders) - 3}" if len(folders) > 3 else ""))
    if all(i.get("origin") == "volume" for i in group):
        notes.append("in a volume listing, not collected")
    elif all(i.get("origin") == "export" for i in group):
        notes.append("only in an export's rows")
    inner = "; ".join(([measure] if measure and first.get("kind") == "directory" else []) + notes)
    return name + (f" {measure}" if measure and first.get("kind") != "directory" else "") \
        + (f" ({inner})" if inner else "")


def _host_line(label: str, tags: list[str], items: list[dict[str, Any]]) -> str:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for i in sorted(items, key=lambda i: (-int(i.get("score") or 0), -int(i.get("size") or 0))):
        grouped.setdefault(str(i.get("name") or ""), []).append(i)
    parts = [_item_text(n, g) for n, g in list(grouped.items())[:_VIEW_ITEMS]]
    more = len(grouped) - _VIEW_ITEMS
    ready = next((i.get("handle") for g in grouped.values() for i in g if i.get("handle")), "")
    return (f"- {label}" + (f" [{'; '.join(tags)}]" if tags else "") + ": " + ", ".join(parts)
            + (f", +{more} more" if more > 0 else "")
            + (f"; ready: {ready}" if ready and image_handles_on() else ""))


VIEW_READ_LINE = ("Read one: tsk.index_find(host, pattern) gives its image, offset_sectors and inode; "
                  "tsk.icat(image, inode, output_path) extracts it for any parser.")
VIEW_READ_LINE_HANDLES = ("Read one: pass its handle <image>::<path> as the file argument of any parser (the "
                          "file is extracted first); tsk.index_find(host, pattern) lists handles.")


def _read_line() -> str:
    line = VIEW_READ_LINE_HANDLES if image_handles_on() else VIEW_READ_LINE
    return line + (" " + EXTRACT_MANY_LINE if extract_job_on() else "")


def host_view(case_dir: str | os.PathLike, *, max_hosts: int = VIEW_HOSTS, header: bool = True) -> str:
    """The host-first view of the unread content inside the images: one
    line per host in view order with its unread classes (versions folded),
    the images not listed with their reason, one roll-up line for the rest
    and how to read one. "" when the index has nothing unread."""
    model = _view_model(case_dir)
    if not model or (not model["order"] and not model["failed"]):
        return ""
    lines: list[str] = []
    if header:
        lines.append("CONTENTS OF THE IMAGES (listed at intake; unread = no reader call has opened it; "
                     "timeline rows are a partial view):")
        lines.append("Hosts the questions and the brief name, then hosts your findings name, and what is "
                     "unread inside their image:")
    shown = model["order"][:max_hosts]
    skipped = _skipped_by_host(case_dir)
    for h in shown:
        line = _host_line(h, model["tags"].get(h, []), model["items"][h])
        dirs = skipped.get(h.casefold()) or []
        if dirs:
            # The directories of text and structured files the host's
            # exports did not parse, the two largest.
            line += "; skipped by the exports: " + ", ".join(
                f"{d['dir']} ({d['files']} files, {_size(d['bytes'])})" for d in dirs[:2]) + (
                f", +{len(dirs) - 2} more" if len(dirs) > 2 else "")
        lines.append(line)
    if model["failed"]:
        lines.append("- not listed: " + ", ".join(f"{img} ({why})" for img, why in model["failed"][:8])
                     + (f", +{len(model['failed']) - 8} more" if len(model["failed"]) > 8 else ""))
    rest = model["rest"] + model["order"][max_hosts:]
    if rest:
        names: Counter = Counter()
        for h in rest:
            for n in {str(i.get("name") or "") for i in model["items"][h]}:
                names[n] += 1
        top = ", ".join(f"{n} on {c} host{'s' if c != 1 else ''}" for n, c in names.most_common(3))
        lines.append(f"Other images: {len(rest)} host(s), {sum(len(model['items'][h]) for h in rest)} "
                     f"high-value file(s) unread ({top}).")
    if shown:
        lines.append(_read_line())
    return "\n".join(lines)


def _skipped_by_host(case_dir) -> dict[str, list[dict[str, Any]]]:
    try:
        from core.export_profile import export_profile, profile_on
        if not profile_on():
            return {}
        out: dict[str, list[dict[str, Any]]] = {}
        for p in export_profile(case_dir).get("exports", []):
            for host, dirs in (p.get("skipped") or {}).items():
                out.setdefault(str(host).casefold(), []).extend(dirs)
        return {h: sorted(v, key=lambda d: -d["bytes"]) for h, v in out.items()}
    except Exception:  # noqa: BLE001
        return {}


def view_digest(case_dir: str | os.PathLike) -> list[str]:
    """The view as small values for the director's state signature: each
    host in view with its unread count, and the images not listed."""
    model = _view_model(case_dir)
    if not model:
        return []
    return ([f"{h}:{len(model['items'][h])}" for h in model["order"]]
            + [f"rest:{sum(len(model['items'][h]) for h in model['rest'])}"]
            + [f"unlisted:{img}" for img, _why in model["failed"]])


def view_items(case_dir: str | os.PathLike, limit: int = 12) -> list[dict[str, Any]]:
    """The unread index items in view order (hosts in order, richest
    first on each), for the director's proposals."""
    model = _view_model(case_dir)
    if not model:
        return []
    out: list[dict[str, Any]] = []
    for h in model["order"]:
        out += sorted(model["items"][h], key=lambda i: (-int(i.get("score") or 0), -int(i.get("size") or 0)))[:3]
    return out[:limit]


# ── image handles: the one-call read ─────────────────────────────────────
#
# ``<image>::<path inside the volume>``, the image as its case-relative
# path, basename or stem, or the host label the Evidence Links give it when
# that host has exactly one image; ``<image>@<offset>::`` names a volume
# when an image holds several filesystems. "::" occurs in no case path
# Atlas writes, and the image part must resolve to an image of the case, so
# an IPv6 address or an alternate data stream is never taken for a handle.

HANDLE_CLAUSE = "read one with its handle <image>::<path>; tsk_index_find lists handles"
HANDLE_CLAUSE_OFF = "tsk.resolve_path on the image, tsk.icat to a copy, then the parser"
HANDLES_OFF_REFUSAL = ("image handles are off in this run; read the file with tsk_resolve_path "
                       "and tsk_icat")
EXTRACT_ROOT = "analysis/extracted"

# The image part may hold spaces (an image path as stored, handle_for), never
# a colon (a drive letter is no image); whether it names an image of the case
# is the resolver's question (names_case_image, resolve).
HANDLE_RE = re.compile(r"^(?P<image>[^:\n]+?)(?:@(?P<offset>\d+))?::(?P<path>[^\n]+)$")


def image_handles_on() -> bool:
    """Handles resolve in the Toolbox. Defaults to the DAIR no-deferral
    switch at call time, so handles are never on while the DAIR gate defers."""
    from core.deferred_intents import dair_no_defer_on
    return index_on() and env_flag("ATLAS_IMAGE_HANDLES", default=dair_no_defer_on())


def handle_clause() -> str:
    """The handle clause of the framing lines: the handle when it resolves,
    the two-step read otherwise."""
    return HANDLE_CLAUSE if image_handles_on() else HANDLE_CLAUSE_OFF


def looks_like_handle(value: Any) -> bool:
    return isinstance(value, str) and "::" in value and bool(HANDLE_RE.match(value.strip()))


def names_case_image(case_dir: str | os.PathLike | None, value: Any) -> bool:
    """Whether a handle-shaped value's image part names one image of the case
    (text with "::" that names no image is no handle)."""
    if not case_dir or not looks_like_handle(value):
        return False
    m = HANDLE_RE.match(str(value).strip())
    try:
        return _match_image(Path(case_dir), m.group("image").split("@", 1)[0])[0] is not None
    except Exception:  # noqa: BLE001
        return False


def _case_images(root: Path) -> list[dict[str, Any]]:
    """Every disk image of the plan with its case-relative path and host."""
    try:
        from core.evidence_links import host_for_image
    except Exception:  # noqa: BLE001
        host_for_image = None  # type: ignore[assignment]
    out = []
    for img in _disk_images(root):
        rel = _rel(root, str(img["path"]))
        out.append({"rel": rel, "abs": str(img["path"]),
                    "host": host_for_image(rel, root) if host_for_image else ""})
    return out


def _match_image(root: Path, part: str) -> tuple[Optional[dict[str, Any]], str]:
    images = _case_images(root)
    want = part.replace("\\", "/").strip("/").casefold()
    exact = [i for i in images if i["rel"].casefold() == want or i["abs"].casefold() == want]
    by_name = [i for i in images if Path(i["rel"]).name.casefold() == want
               or Path(i["rel"]).stem.casefold() == want]
    by_host = [i for i in images if i["host"] and i["host"].casefold() == want]
    for group in (exact, by_name):
        if len(group) == 1:
            return group[0], ""
    if len(by_host) == 1:
        return by_host[0], ""
    if len(by_host) > 1:
        return None, (f"host label '{part}' names {len(by_host)} images: "
                      + ", ".join(i["rel"] for i in by_host) + ". Name the image.")
    if len(by_name) > 1:
        return None, (f"'{part}' names {len(by_name)} images: " + ", ".join(i["rel"] for i in by_name)
                      + ". Name the image by its path.")
    listing = ", ".join(f"{i['rel']} ({i['host']})" if i["host"] else i["rel"] for i in images[:12])
    return None, (f"image handle names no image of this case: '{part}'. Images: "
                  + (listing or "none") + (", ..." if len(images) > 12 else ""))


def _handle_rows(con: sqlite3.Connection, image: str, inner: str, offset: Optional[int]) -> list[sqlite3.Row]:
    """The entries of ``image`` at a handle's inner path: case-insensitive,
    on the handle's volume when it names one, the path as written, else
    with the collection root folder the handle carries and the image lacks
    taken off, else with the one the image carries and the handle lacks
    put on. The one lookup resolve and handle_missing share."""
    q = ("SELECT * FROM entries WHERE image = ? AND origin = 'image' AND path = ? COLLATE NOCASE"
         + (" AND volume = ?" if offset is not None else "")
         + " ORDER BY version_of IS NOT NULL, deleted")

    def _lookup(p: str) -> list[sqlite3.Row]:
        return con.execute(q, [image, p] + ([offset] if offset is not None else [])).fetchall()
    rows = _lookup(inner)
    comps = inner.split("/")
    for k in range(1, len(comps)):           # the handle carries a root folder the image lacks
        if rows:
            break
        rows = _lookup("/".join(comps[k:]))
    if not rows and len(comps) >= 2:          # the image carries a root folder the handle lacks
        rows = [r for r in con.execute(
            "SELECT * FROM entries WHERE image = ? AND origin = 'image' AND path LIKE ? ESCAPE '\\'"
            + (" AND volume = ?" if offset is not None else "")
            + " ORDER BY version_of IS NOT NULL, deleted",
            [image, "%/" + _like_escape(inner)] + ([offset] if offset is not None else []))
            if str(r["path"]).count("/") == inner.count("/") + 1]
    return rows


def handle_missing(case_dir: str | os.PathLike, handle: str) -> bool:
    """True when a handle names an image of the case whose listing is
    complete and no entry of it is at the handle's path (resolve's lookup,
    _handle_rows, deleted entries and versions included): a read of it can
    never run. False when the handle or its image is unknown, the listing
    is not complete (resolve walks the filesystem then), or the path is
    there."""
    m = HANDLE_RE.match(str(handle or "").strip())
    if not m:
        return False
    root = Path(case_dir)
    img, _err = _match_image(root, m.group("image"))
    con = _connect(root) if img is not None else None
    if con is None:
        return False
    inner = m.group("path").replace("\\", "/").strip().strip("/")
    offset = int(m.group("offset")) if m.group("offset") else None
    with closing(con):
        meta = _meta_get(con, f"image:{img['rel']}")
        if not meta.get("listed") or not meta.get("complete"):
            return False
        return not _handle_rows(con, img["rel"], inner, offset)


def resolve(case_dir: str | os.PathLike, handle: str) -> dict[str, Any]:
    """What a handle names: ``{image, abs, offset, inode, path, size,
    is_dir, entry_id, mounted_path}``, or ``{"walk": True, ...}`` when the
    index does not know the path on a listing that is not complete, or
    ``{"error": ...}`` naming the images, the near names or the images an
    ambiguous host label could mean. The inner path matches case-
    insensitively, with either separator, with or without a leading "/" and
    with or without a collection root folder."""
    m = HANDLE_RE.match(str(handle or "").strip())
    if not m:
        return {"error": f"not an image handle: '{handle}'"}
    root = Path(case_dir)
    img, err = _match_image(root, m.group("image"))
    if img is None:
        return {"error": err}
    inner = m.group("path").replace("\\", "/").strip().strip("/")
    offset = int(m.group("offset")) if m.group("offset") else None
    base = {"image": img["rel"], "abs": img["abs"], "host": img["host"], "path": inner, "handle": handle}
    con = _connect(root)
    meta = {}
    rows: list[sqlite3.Row] = []
    if con is not None:
        with closing(con):
            meta = _meta_get(con, f"image:{img['rel']}")
            rows = _handle_rows(con, img["rel"], inner, offset)
            near = []
            if not rows:
                name = inner.split("/")[-1]
                near = [r[0] for r in con.execute(
                    "SELECT path FROM entries WHERE image = ? AND version_of IS NULL AND "
                    "(name = ? COLLATE NOCASE OR name LIKE ? ESCAPE '\\') LIMIT 8",
                    (img["rel"], name, _like_escape(name[:4]) + "%"))]
    live = [r for r in rows if r["version_of"] is None] or rows
    volumes = sorted({r["volume"] for r in live})
    if len(volumes) > 1:
        return {"error": f"'{inner}' is on {len(volumes)} volumes of {img['rel']}: name one, "
                + ", ".join(f"{img['rel']}@{v}::{live[0]['path']}" for v in volumes)}
    if not live:
        if not meta.get("listed") or not meta.get("complete"):
            refusal = _live_read_refusal(root, img)
            return {"error": refusal} if refusal else {**base, "walk": True, "offset": offset}
        return {"error": f"'{inner}' is not in the contents of {img['rel']}."
                + (" Near: " + ", ".join(near) if near else " tsk_index_find(host, pattern) lists what it holds.")}
    r = live[0]
    out = {**base, "path": r["path"], "offset": r["volume"] or 0, "inode": r["inode"], "size": r["size"],
           "is_dir": bool(r["is_dir"]), "entry_id": r["id"], "mounted_path": ""}
    try:
        from core.mount_plan import load_mount_plan, mounted_volumes
        mounted = [v for v in mounted_volumes(root) if v.get("mount_point")
                   and os.path.realpath(str(v.get("path") or "")) == os.path.realpath(img["abs"])]
        if mounted and len({x["volume"] for x in rows} | set(_image_volumes(root, img["rel"]))) > 1:
            # Several filesystems in the image: the mount is in place only for
            # the partition it was mounted from.
            plan = {os.path.realpath(str(i.get("path") or "")): i.get("mount_result") or {}
                    for i in load_mount_plan(root).get("images") or [] if isinstance(i, dict)}
            mr = plan.get(os.path.realpath(img["abs"])) or {}
            at = mr.get("ntfs_offset_sectors")
            if at is None and mr.get("volume_offset_bytes") is not None:
                at = int(mr["volume_offset_bytes"]) // 512
            mounted = mounted if at is not None and int(at) == int(r["volume"] or 0) else []
        for v in mounted:
            cand = os.path.join(v["mount_point"], r["path"])
            if os.path.exists(cand):
                out["mounted_path"] = cand
    except Exception:  # noqa: BLE001
        pass
    if not out["mounted_path"]:
        refusal = _live_read_refusal(root, img)
        if refusal:
            return {"error": refusal}
    return out


def _image_volumes(root: Path, image: str) -> list[int]:
    con = _connect(root)
    if con is None:
        return []
    with closing(con):
        return [r[0] for r in con.execute("SELECT DISTINCT volume FROM entries WHERE image = ? AND origin = 'image'",
                                          (image,))]


def _live_read_refusal(root: Path, img: dict[str, Any]) -> str:
    """Why the image cannot be read right now, checked at read time: an
    Expert Witness container needs the raw device its mount exposes (the
    index may have been built while one was mounted), unless this Sleuth Kit
    build reads EWF itself; a disk container needs its raw view, which is
    started here when it is down. Nothing is remounted here."""
    try:
        from core.mount_plan import ewf_device_for, is_ewf_image, mount_dir_for, raw_device_for
        if not is_ewf_image(img["abs"]):
            device, why = raw_device_for(root, img["abs"])
            if device or not why:
                return ""
            from core.raw_views import read_refusal
            return read_refusal(img["rel"], why)
        if ewf_device_for(root, img["abs"]):
            return ""
        from tools.sleuthkit import tsk_image_types
        if "ewf" in tsk_image_types():
            return ""
        where = _rel(root, os.path.join(mount_dir_for(root, img["abs"]), "ewf", "ewf1"))
    except Exception:  # noqa: BLE001
        return ""
    return (f"{img['rel']} is an Expert Witness container and no raw device is mounted for it now "
            f"(expected {where}): mount it with ewf.mount_full_image or ewf.ewf_mount, then read the "
            "handle again")


def copy_target(case_dir: str | os.PathLike, resolved: dict[str, Any]) -> str:
    """Where an extraction puts its copy: under the extraction root, by the
    image's stem and the path inside the image, so the copy keeps its source
    name and scores as its source by construction."""
    stem = Path(resolved["image"]).stem
    return str(Path(case_dir) / EXTRACT_ROOT / stem / resolved["path"])


def reusable_copy(case_dir: str | os.PathLike, entry_id: int, size: Optional[int]) -> Optional[dict[str, Any]]:
    """A copy already made of this entry that still exists with its size."""
    con = _connect(case_dir)
    if con is None:
        return None
    with closing(con):
        rows = con.execute("SELECT * FROM copies WHERE entry_id = ?", (entry_id,)).fetchall()
    for r in rows:
        p = Path(case_dir) / r["copy_path"]
        try:
            if p.is_dir() or (p.is_file() and (size is None or p.stat().st_size == size)):
                return {"copy_path": r["copy_path"], "call_id": r["call_id"]}
        except OSError:
            continue
    return None


def extract_job_on() -> bool:
    """The batch extract job (tools/jobs.py job_start_image_extract)."""
    return index_on() and env_flag("ATLAS_IMAGE_EXTRACT_JOB", True)


EXTRACT_MANY_LINE = ("Read many: job.job_start_image_extract(images, paths) copies one path or glob from "
                     "several images into one folder for one parser call.")


def entries_matching(case_dir: str | os.PathLike, image: str, pattern: str) -> list[dict[str, Any]]:
    """The live entries of one image (case-relative path) that a volume-
    relative path names: a glob over the path (``*`` crosses folders and is
    the only wildcard; ``?`` and ``[`` match themselves), a
    folder when it ends in "/", else the exact path; either separator, any
    case. When nothing matches, the same pattern under one root folder the
    image carries. Per volume and path the allocated entry stands before a
    deleted one. Each row: ``{entry_id, path, volume, inode, size, is_dir}``,
    a folder's size the sum of the files under it."""
    p = str(pattern or "").replace("\\", "/").strip()
    want_dir = p.endswith("/")
    p = p.strip("/")
    if not p:
        return []
    con = _connect(case_dir)
    if con is None:
        return []
    base = "SELECT * FROM entries WHERE image = ? AND origin = 'image' AND version_of IS NULL"
    if want_dir:
        base += " AND is_dir = 1"
    with closing(con):
        def _rows(pat: str) -> list[sqlite3.Row]:
            if "*" in pat:
                # Only * is a wildcard: a ? or [ in a file name stays itself.
                lit = re.sub(r"([?\[])", r"[\1]", pat.lower())
                q, arg = " AND lower(path) GLOB ?", lit
            else:
                q, arg = " AND path = ? COLLATE NOCASE", pat
            return con.execute(base + q + " ORDER BY volume, path, deleted, id", (image, arg)).fetchall()
        rows = _rows(p) or [r for r in _rows("*/" + p) if str(r["path"]).count("/") == p.count("/") + 1]
        out: list[dict[str, Any]] = []
        seen: set[tuple] = set()
        for r in rows:
            key = (r["volume"], str(r["path"]).casefold())
            if key in seen:
                continue
            seen.add(key)
            size = r["size"]
            if r["is_dir"]:
                cond, args = _under(r)
                size = int(con.execute(f"SELECT COALESCE(SUM(size), 0) FROM entries WHERE {cond} "
                                       "AND origin = 'image' AND version_of IS NULL AND is_dir = 0",
                                       args).fetchone()[0])
            out.append({"entry_id": r["id"], "path": r["path"], "volume": r["volume"] or 0, "inode": r["inode"],
                        "size": size, "is_dir": bool(r["is_dir"])})
    return out


# ── the run's numbers and the hosts a call covered ──────────────────────

def inside_counts(case_dir: str | os.PathLike) -> dict[str, Any]:
    """The contents index's unit model for the run status and the evidence
    table: images, listed images, files listed, high-value files, and of
    those read, shown only as timeline rows (partial), untouched with an
    export covering them, and skipped by every export; per image its
    high-value files and how many were read."""
    out: dict[str, Any] = {"images": len(_disk_images(Path(case_dir))), "listed": len(listed_images(case_dir)),
                           "files": 0, "high_value": 0, "read": 0, "partial": 0, "untouched": 0, "skipped": 0,
                           "per_image": {}}
    con = _connect(case_dir)
    if con is None:
        return out
    with closing(con):
        out["files"] = int(con.execute("SELECT COUNT(*) FROM entries WHERE origin = 'image' AND is_dir = 0 "
                                       "AND version_of IS NULL").fetchone()[0])
        covered = {r[0] for r in con.execute("SELECT DISTINCT entry_id FROM sources WHERE entry_id IS NOT NULL")}
    from core.artifact_value import HIGH_VALUE_THRESHOLD, examined_items
    rows = [r for r in scored_rows(case_dir, HIGH_VALUE_THRESHOLD) if r["origin"] == "image"]
    read = examined_items(case_dir, [{"name": r["name"], "lpath": r["path"], "host": r["host"], "handle": r["handle"],
                                      "index_id": r["id"], "kind": "directory" if r["is_dir"] else "file"}
                                     for r in rows])
    out["high_value"] = len(rows)
    for r, was_read in zip(rows, read):
        state = ("read" if was_read else "partial" if r["partial"] else "untouched" if r["id"] in covered
                 else "skipped")
        out[state] += 1
        img = out["per_image"].setdefault(r["image"], {"high_value": 0, "read": 0})
        img["high_value"] += 1
        img["read"] += int(was_read)
    return out


def export_facts(case_dir: str | os.PathLike) -> dict[str, dict[str, Any]]:
    """Per tabular export the index parsed: {rows, first, last, hosts}."""
    con = _connect(case_dir)
    if con is None:
        return {}
    out: dict[str, dict[str, Any]] = {}
    try:
        for r in con.execute("SELECT path, rows, first, last, hosts FROM exports"):
            try:
                hosts = [h for h in json.loads(r["hosts"] or "[]") if h]
            except ValueError:
                hosts = []
            out[str(r["path"]).strip("/")] = {"rows": int(r["rows"] or 0), "first": r["first"] or "",
                                              "last": r["last"] or "", "hosts": hosts}
    except sqlite3.Error:
        return {}
    finally:
        con.close()
    return out


def export_paths(case_dir: str | os.PathLike) -> set[str]:
    """The case-relative paths of the tabular exports the index parsed."""
    con = _connect(case_dir)
    if con is None:
        return set()
    try:
        return {str(r[0]).strip("/") for r in con.execute("SELECT path FROM exports")}
    except sqlite3.Error:
        return set()
    finally:
        con.close()


def copied_entries(case_dir: str | os.PathLike, call_ids: list[int]) -> list[int]:
    """The index entries these calls copied out of the images: the files
    one item's own calls read whole (agent.frontier counts them with the
    rows its calls showed)."""
    ids = sorted({int(c) for c in call_ids or [] if str(c).isdigit()})
    if not ids:
        return []
    con = _connect(case_dir)
    if con is None:
        return []
    marks = ",".join("?" * len(ids))
    try:
        return [int(r[0]) for r in con.execute(
            f"SELECT DISTINCT entry_id FROM copies WHERE call_id IN ({marks}) AND entry_id IS NOT NULL", ids)]
    except sqlite3.Error:
        return []
    finally:
        con.close()


def hosts_covered(case_dir: str | os.PathLike, call_id: int, entry: dict | None = None) -> list[str]:
    """The hosts a cited call's evidence reached by the index's account:
    the hosts of the sources whose rows it showed, the host of a copy it
    read, and for an unfiltered read of a whole export, or a filtered
    search of it that matched no row anywhere in the file, that export's
    hosts (the search read every row of each)."""
    con = _connect(case_dir)
    if con is None:
        return []
    hosts: set[str] = set()
    with closing(con):
        for r in con.execute("SELECT DISTINCT s.host FROM partial p JOIN sources s ON s.id = p.source_id "
                             "WHERE p.call_id = ?", (int(call_id),)):
            if r[0]:
                hosts.add(str(r[0]))
        if entry is None:
            try:
                from core.execution_log import log
                entry = log.index().by_call_id.get(int(call_id))
            except Exception:  # noqa: BLE001
                entry = None
        if isinstance(entry, dict):
            blob = " ".join(str(entry.get(k) or "") for k in ("cmd", "args")).casefold()
            for r in con.execute("SELECT c.copy_path, e.host FROM copies c JOIN entries e ON e.id = c.entry_id"):
                if r[1] and str(r[0]).casefold() in blob:
                    hosts.add(str(r[1]))
            from core.indicators import _parsed_args
            args = _parsed_args(entry)[0] if isinstance(entry.get("args"), str) else {}
            whole = isinstance(args, dict) and args.get("path") and not any(
                args.get(k) for k in ("where", "pattern", "patterns", "query", "time_start", "time_end"))
            meta = entry.get("result_meta") or {}
            nothing = (isinstance(args, dict) and args.get("path") and meta.get("matched_rows") == 0
                       and not meta.get("matched_rows_all") and not meta.get("scan_capped"))
            if whole or nothing:
                row = con.execute("SELECT hosts FROM exports WHERE path = ?",
                                  (_rel(Path(case_dir), str(args["path"])),)).fetchone()
                if row:
                    hosts |= {str(h) for h in json.loads(row[0] or "[]") if h}
    return sorted(hosts)
