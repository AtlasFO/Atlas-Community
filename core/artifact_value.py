"""Forensic value of an artifact, and whether the case honoured it.

Why this exists
===============
Enumeration order is not investigative priority. A run that lists hundreds
of event logs and parses the first two it happens to see has not triaged
anything — it has read the top of a directory listing. From an MFT listing
it produced itself, such a run extracts two empty operational logs while
``Security.evtx``, the PowerShell operational logs, ``DNS Server.evtx`` and
``TaskScheduler`` sit untouched in the same listing, then reports those
artifacts as *absent* and builds an anti-forensics narrative on top of the
gap.

Two general capabilities close that, and neither is a per-case script:

**Value, not order.** ``artifact_score`` ranks a candidate by what kind of
artifact it is — the same judgement an analyst applies when they see
``Security.evtx`` next to ``Biometrics``. The table below is forensic
domain knowledge, expressed once, and it applies to whatever a case
happens to contain.

**Presence beats assertion.** An investigation may only claim an artifact
is absent if the case's own index does not list it. A report that calls
``Security.evtx`` absent while a CSV Atlas wrote itself lists it
contradicts itself; ``contradicted_absence_claims`` makes that
self-contradiction a blocking obligation rather than a narrative.

Size matters too, but only as a signal about emptiness: a ``.evtx`` of
exactly 69,632 bytes is a header plus one empty chunk — parsing it is not
coverage of that channel.
"""
from __future__ import annotations

import csv
import os
import re
from pathlib import Path
from typing import Any, Iterable, Optional

# ── the value model ──────────────────────────────────────────────────────
#
# (weight, pattern, why). Weight is "how much investigative answer per
# artifact", not popularity: an authentication log outranks a driver-install
# log because more questions terminate in it. First match wins, so specific
# channels are listed before the generic family fallbacks.
_VALUE_RULES: tuple[tuple[int, re.Pattern[str], str], ...] = (
    (98, re.compile(r"(?i)(^|[\\/])security\.evtx$"),
     "authentication, logon sessions, privilege use, object access"),
    (95, re.compile(r"(?i)powershell.*operational\.evtx$|^windows powershell\.evtx$"),
     "script block logging — attacker tooling executes here"),
    (92, re.compile(r"(?i)(^|[\\/])system\.evtx$"),
     "service installs, driver loads, system-level persistence"),
    (90, re.compile(r"(?i)sysmon.*operational\.evtx$"),
     "process creation, network connections, image loads"),
    (88, re.compile(r"(?i)taskscheduler.*operational\.evtx$"),
     "scheduled-task persistence"),
    (86, re.compile(r"(?i)(?:terminalservices|remoteconnectionmanager|localsessionmanager).*\.evtx$"),
     "RDP session history — lateral movement"),
    # The $MFT itself, an exported copy ("mft.csv", "MFT.body"): never the
    # mirror ($MFTMirr) or another name that merely starts with the letters.
    (85, re.compile(r"(?i)(^|[\\/])\$?mft$|\$mft(?![a-z0-9])|(^|[\\/])mft\."),
     "full filesystem timeline"),
    (84, re.compile(r"(?i)(^|[\\/])(ntuser|usrclass)\.dat$"),
     "per-user execution and interaction history"),
    (83, re.compile(r"(?i)dns[ _-]?server\.evtx$|dnsserver.*\.evtx$"),
     "name resolution — exfiltration and C2 destinations"),
    # The machine hives and their .hve exports; Syscache.hve is a lookup
    # cache of executables, read with Amcache at its own rank below.
    (82, re.compile(r"(?i)(^|[\\/])(system|software|sam|security)$|(?<!syscache)\.hve$"),
     "registry hives — services, run keys, device history"),
    (80, re.compile(r"(?i)amcache\.hve$"),
     "program execution evidence including deleted binaries"),
    (60, re.compile(r"(?i)syscache\.hve$"),
     "executable lookup cache — corroborates Amcache"),
    (78, re.compile(r"(?i)(^|[\\/])prefetch([\\/]|$)|\.pf$"),
     "execution counts and first/last run times"),
    (76, re.compile(r"(?i)srudb\.dat$|srum"),
     "per-process network byte counts — data volume moved"),
    (74, re.compile(r"(?i)\$usnjrnl|usnjrnl|\$j$"),
     "file create/delete/rename journal"),
    (72, re.compile(r"(?i)(^|[\\/])application\.evtx$"),
     "application crashes and installs"),
    # Deleted files: what the user removed and when (ez.rbcmd parses the
    # $I records; XP keeps INFO2).
    (76, re.compile(r"(?i)(^|[\\/])\$i[a-z0-9]{6}(?:\.|$)|(^|[\\/])info2$"),
     "recycle bin — what was deleted, from where, when"),
    # Device installs: every USB device ever plugged in, with first-connect
    # times (misc.device_install_inventory).
    (75, re.compile(r"(?i)(^|[\\/])setupapi(?:\.dev)?\.log$"),
     "device installs — USB history with first-connect times"),
    # What was opened: the Recent folder, its Jump Lists and shortcuts
    # (ez.lecmd / ez.jlecmd read the directories).
    (74, re.compile(r"(?i)(^|[\\/])recent$|(^|[\\/])(?:automatic|custom)destinations$"
                    r"|\.(?:automatic|custom)destinations-ms$"),
     "recent files and jump lists — what was opened, from where, when"),
    # Browser history stores (hindsight, sqlite): Chrome and Edge keep
    # History with no extension.
    (72, re.compile(r"(?i)(^|[\\/])(?:places\.sqlite|history|webcachev\d*\.dat|index\.dat)$"),
     "browser history — what was searched, visited and downloaded"),
    (70, re.compile(r"(?i)defender.*operational\.evtx$|windefend.*\.evtx$"),
     "AV detections and exclusions"),
    (70, re.compile(r"(?i)(^|[\\/])(?:stickynotes\.snt|plum\.sqlite)$"),
     "sticky notes — the user's own notes"),
    # The optical-disc staging folder: files queued for burning.
    (70, re.compile(r"(?i)(^|[\\/])(?:burn|cd burning)$"),
     "disc-burn staging — files queued for an optical disc"),
    (68, re.compile(r"(?i)smb(?:server|client).*\.evtx$"),
     "share access — staging and collection"),
    # Costly to export and search; under the threshold until a question
    # names it (which lifts it to 100).
    (68, re.compile(r"(?i)(^|[\\/])windows\.edb$"),
     "search index — file names and content the user indexed"),
    # No parser here yet: known, not demanded of every investigation.
    (66, re.compile(r"(?i)(^|[\\/])thumbcache_\d+\.db$"),
     "thumbnail cache — images of files since deleted"),
    (66, re.compile(r"(?i)(^|[\\/])(?:cookies|login data|web data|cookies\.sqlite"
                    r"|formhistory\.sqlite|downloads\.sqlite)$"),
     "browser stores — credentials, forms, cookies"),
    (64, re.compile(r"(?i)firewall.*\.evtx$|windows firewall"),
     "host firewall rule changes"),
    (60, re.compile(r"(?i)grouppolicy.*operational\.evtx$"),
     "policy application — domain-wide changes"),
    (55, re.compile(r"(?i)\.evtx$"),
     "event log channel"),
    (45, re.compile(r"(?i)\.(log|txt|csv|json|xml)$"),
     "textual log"),
)

# Component-store and servicing payload: an assembly directory or package
# named after the component it ships (a public-key token or hash of sixteen
# hex digits between separators) and its manifests, catalogs and update
# metadata. They carry the name of the channel they install, never its
# records - an RDP client package is not RDP session history.
_PAYLOAD_RE = re.compile(
    r"(?i)(?:^|[_~])[0-9a-f]{16}(?:[_~.]|$)|\.(?:manifest|mum|cat|mui)$")

# A .evtx that has never been written past its header sits at one chunk.
# Parsing it proves nothing about that channel, so it must not be mistaken
# for coverage of it.
_EMPTY_EVTX_SIZES = frozenset({69632, 65536, 71680})

_ABSENCE_RE = re.compile(
    r"(?i)\b("
    r"no\s+|not\s+present|not\s+found|absent|absence\s+of|missing|"
    r"never\s+(?:present|created|written)|unavailable|does\s+not\s+exist|"
    r"were\s+not\s+recovered|was\s+not\s+recovered|lack\s+of"
    r")"
)

# Column names an artifact listing may use for name and size.
_NAME_COLS = ("filename", "name", "file", "path", "filepath", "file_name")
_SIZE_COLS = ("filesize", "size", "file_size", "bytes", "length")

MAX_INDEXED_ROWS = 200_000
HIGH_VALUE_THRESHOLD = 70


def artifact_score(name: str, size: Optional[int] = None) -> tuple[int, str]:
    """(score, rationale) for an artifact, from its identity — not its
    position in a listing. Unknown artifacts score 0."""
    text = str(name or "").replace("\\", "/")
    base = text.rsplit("/", 1)[-1]
    # A Jump List is named by a sixteen-hex AppID; it is not a component
    # store payload, whatever its name looks like.
    if _PAYLOAD_RE.search(base) and not base.lower().endswith("destinations-ms"):
        return 0, ""
    for weight, pattern, why in _VALUE_RULES:
        if pattern.search(base) or pattern.search(text):
            if looks_empty(base, size):
                # Still identifiable, but nothing in it to find.
                return max(1, weight // 10), f"{why} (appears empty)"
            return weight, why
    return 0, ""


def looks_empty(name: str, size: Optional[int]) -> bool:
    """True when the artifact is present but holds no content worth reading."""
    if size is None:
        return False
    try:
        size = int(size)
    except (TypeError, ValueError):
        return False
    if size <= 0:
        return True
    if str(name or "").lower().endswith(".evtx") and size in _EMPTY_EVTX_SIZES:
        return True
    return False


def rank_artifacts(entries: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Sort artifact descriptors by investigative value, richest first."""
    scored: list[dict[str, Any]] = []
    for e in entries:
        name = str(e.get("name") or "")
        size = e.get("size")
        score, why = artifact_score(name, size)
        if score <= 0:
            continue
        item = dict(e)
        item["score"] = score
        item["why"] = why
        item["empty"] = looks_empty(name, size)
        scored.append(item)
    scored.sort(key=lambda i: (-i["score"], -(i.get("size") or 0), i["name"]))
    return scored


# ── what an opened volume holds ──────────────────────────────────────────
#
# Where a platform keeps the artifacts the value table names, relative to
# the volume root. A mounted image is not walked — a FUSE mount of a large
# image answers a full walk in minutes, and this check runs every few turns
# — but these places are looked at directly, in whatever case the
# filesystem spells them. Knowledge of the platforms, not of any case; only
# artifacts the value table scores are worth listing.
# A pattern ending in "/" names a directory artifact (the Recent folder,
# a Jump List folder, the burn staging folder): read as a whole by the
# parsers that handle it, counted by the files it holds. Singletons and
# directories come before the file families (event logs, Prefetch,
# Recycle Bin records) so a large family cannot crowd them out of the cap;
# each pattern has a cap of its own inside the volume's.
_VOLUME_ARTIFACT_PATHS: tuple[str, ...] = (
    "$MFT",
    "Windows/System32/config/SAM",
    "Windows/System32/config/SYSTEM",
    "Windows/System32/config/SOFTWARE",
    "Windows/System32/config/SECURITY",
    "Windows/AppCompat/Programs/Amcache.hve",
    "Windows/System32/sru/SRUDB.dat",
    "Windows/inf/setupapi.dev.log",
    "Windows/setupapi.log",
    "ProgramData/Microsoft/Search/Data/Applications/Windows/Windows.edb",
    "Documents and Settings/All Users/Application Data/Microsoft/Search/Data/Applications/Windows/Windows.edb",
    "Users/*/NTUSER.DAT",
    "Users/*/AppData/Local/Microsoft/Windows/UsrClass.dat",
    "Documents and Settings/*/NTUSER.DAT",
    "Documents and Settings/*/Local Settings/Application Data/Microsoft/Windows/UsrClass.dat",
    "Users/*/AppData/Roaming/Microsoft/Windows/Recent/",
    "Users/*/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/",
    "Users/*/AppData/Roaming/Microsoft/Windows/Recent/CustomDestinations/",
    "Documents and Settings/*/Recent/",
    "Users/*/AppData/Local/Microsoft/Windows/Burn/Burn/",
    "Documents and Settings/*/Local Settings/Application Data/Microsoft/CD Burning/",
    "Users/*/AppData/Roaming/Microsoft/Sticky Notes/StickyNotes.snt",
    "Users/*/AppData/Local/Packages/Microsoft.MicrosoftStickyNotes_*/LocalState/plum.sqlite",
    "Users/*/AppData/Local/Google/Chrome/User Data/*/History",
    "Users/*/AppData/Local/Microsoft/Edge/User Data/*/History",
    "Users/*/AppData/Roaming/Mozilla/Firefox/Profiles/*/places.sqlite",
    "Users/*/AppData/Local/Microsoft/Windows/WebCache/WebCacheV01.dat",
    "Documents and Settings/*/Local Settings/Application Data/Google/Chrome/User Data/*/History",
    "Documents and Settings/*/Application Data/Mozilla/Firefox/Profiles/*/places.sqlite",
    "Documents and Settings/*/Local Settings/History/History.IE5/index.dat",
    "Users/*/AppData/Local/Microsoft/Windows/Explorer/thumbcache_*.db",
    "$Recycle.Bin/*/$I*",
    "RECYCLER/*/INFO2",
    "Windows/System32/winevt/Logs/*.evtx",
    "Windows/Prefetch/*.pf",
)
_VOLUME_ARTIFACT_CAP = 1200
_VOLUME_PATTERN_CAP = 100
_MEMBER_IGNORED = frozenset({"desktop.ini", "thumbs.db"})


def _iglob_volume(root: Path, pattern: str) -> list[Path]:
    """Files matching ``pattern`` under ``root`` (directories when the
    pattern ends in "/"), each path component matched without regard to
    case: an XP volume spells WINDOWS/system32, a later one
    Windows/System32. One directory read per component."""
    import fnmatch
    want_dir = pattern.endswith("/")
    parts = [p for p in pattern.split("/") if p]
    level: list[Path] = [root]
    for i, comp in enumerate(parts):
        last = i == len(parts) - 1
        want = comp.casefold()
        nxt: list[Path] = []
        for d in level:
            try:
                with os.scandir(d) as it:
                    for ent in it:
                        if not fnmatch.fnmatchcase(ent.name.casefold(), want):
                            continue
                        try:
                            if last and not want_dir and ent.is_file(follow_symlinks=False):
                                nxt.append(Path(ent.path))
                            elif (not last or want_dir) and ent.is_dir(follow_symlinks=False):
                                nxt.append(Path(ent.path))
                        except OSError:
                            continue
            except OSError:
                continue
        level = nxt
        if not level:
            return []
    return level


def _member_files(directory: Path) -> int:
    """How many files a directory artifact holds, the housekeeping files
    every special folder carries left out: an idle Recent folder holds its
    two Jump List subfolders and a desktop.ini and is empty."""
    n = 0
    try:
        with os.scandir(directory) as it:
            for ent in it:
                try:
                    if ent.is_file(follow_symlinks=False) and ent.name.casefold() not in _MEMBER_IGNORED:
                        n += 1
                except OSError:
                    continue
    except OSError:
        return 0
    return n


def _mounted_volumes(case_dir: str | os.PathLike) -> list[tuple[str, Path, str]]:
    """``(stem, mount point, image path)`` for every image whose filesystem
    is mounted right now, by the mount plan's own liveness rule (a
    directory the plan created for a mount that is gone is not a volume)."""
    try:
        from core.mount_plan import mounted_volumes
        return [(v["stem"], Path(v["mount_point"]), str(v.get("path") or ""))
                for v in mounted_volumes(case_dir) if v.get("mount_point")]
    except Exception:  # noqa: BLE001 - no plan, no volumes
        return []


def _volume_host(image_path: str, case_dir: str | os.PathLike) -> str:
    """The host a volume belongs to, from the Evidence Links; empty when
    they say nothing. An image's stem is a file name, never a host, so a
    belief about a named host is compared with what the links say."""
    if not image_path:
        return ""
    try:
        from core.evidence_links import host_for_image
        return host_for_image(image_path, case_dir)
    except Exception:  # noqa: BLE001
        return ""


def volume_artifacts(case_dir: str | os.PathLike) -> list[dict[str, Any]]:
    """The value table's artifacts present on the case's mounted volumes:
    name, size, host (the volume's stem), the case-relative path the run
    would name, and the absolute one."""
    root = Path(case_dir).resolve()
    out: list[dict[str, Any]] = []
    for stem, mp, image in _mounted_volumes(root):
        host = _volume_host(image, root)
        n = 0
        for pattern in _VOLUME_ARTIFACT_PATHS:
            is_dir = pattern.endswith("/")
            comps = [c for c in pattern.split("/") if c]
            # A member of a globbed family is read by a parser pointed at
            # its folder, so the folder credits it; when the folder itself
            # is a wildcard (a Recycle Bin SID folder) so does its parent.
            family = not is_dir and "*" in comps[-1]
            roots_up = 2 if (family and len(comps) >= 2 and "*" in comps[-2]) else 1
            k = 0
            for p in _iglob_volume(mp, pattern):
                try:
                    size = _member_files(p) if is_dir else p.stat().st_size
                except OSError:
                    continue
                try:
                    rel = p.resolve().relative_to(root).as_posix()
                except ValueError:
                    rel = str(p)
                item = {"name": p.name, "size": size, "host": host, "stem": stem,
                        "path": rel, "abs": str(p),
                        "kind": "directory" if is_dir else "file"}
                if family:
                    parents = []
                    q = Path(rel)
                    for _ in range(roots_up):
                        q = q.parent
                        parents.append(q.as_posix())
                    item["roots"] = parents
                out.append(item)
                n += 1
                k += 1
                if k >= _VOLUME_PATTERN_CAP or n >= _VOLUME_ARTIFACT_CAP:
                    break
            if n >= _VOLUME_ARTIFACT_CAP:
                break
    return out


# ── what the case knows exists ───────────────────────────────────────────

def known_artifacts(case_dir: str | os.PathLike) -> dict[str, dict[str, Any]]:
    """Every artifact the case has evidence of, keyed by lowercase name
    for a pathless sighting (a listing row) and by case-relative path for
    one found on a volume.

    Two sources, both things the run produced or was given: listings it
    generated (MFT/directory CSVs under analysis/, which is how a run learns
    what exists inside a disk image without extracting it) and files present
    on disk. A run that has listed an artifact cannot claim not to know
    about it.
    """
    root = Path(case_dir)
    out: dict[str, dict[str, Any]] = {}

    def _add(name: str, size: Optional[int], where: str, host: str = "",
             path: str = "", abs_path: str = "", kind: str = "file",
             roots: Optional[list[str]] = None) -> None:
        base = str(name or "").replace("\\", "/").rsplit("/", 1)[-1].strip()
        if not base or len(base) > 200:
            return
        # A sighting with a path is its own entry (every profile's NTUSER.DAT,
        # every volume's SYSTEM); a pathless one (a listing row) folds by name.
        key = path.lower() if path else base.lower()
        prev = out.get(key)
        # Keep the largest sighting: an empty copy must not mask a full one.
        if prev is not None and (prev.get("size") or 0) >= (size or 0):
            return
        out[key] = {"name": base, "size": size, "source": where, "host": host,
                    "path": path, "abs": abs_path, "kind": kind,
                    "roots": list(roots or [])}

    # What an opened volume holds: the value table's artifacts at the
    # places the platform keeps them, looked at directly on the mount. Once
    # an image is mounted every read goes through its filesystem and the
    # image is one coverage unit, so without this a run could investigate a
    # volume for an hour and never be told its registry hives were unread.
    # The volume's host is what the Evidence Links say about its image;
    # the image's stem is a file name and stays in the source.
    for art in volume_artifacts(root):
        _add(art["name"], art["size"], f"mount:{art.get('stem') or ''}", art.get("host") or "",
             path=art["path"], abs_path=art["abs"], kind=art.get("kind", "file"),
             roots=art.get("roots"))

    analysis = root / "analysis"
    if analysis.is_dir():
        rows_seen = 0
        for csv_path in sorted(analysis.glob("*.csv")):
            try:
                with csv_path.open(encoding="utf-8", errors="replace",
                                   newline="") as fh:
                    reader = csv.DictReader(fh)
                    cols = {(c or "").strip().lstrip("﻿").lower(): c
                            for c in (reader.fieldnames or [])}
                    name_col = next((cols[c] for c in _NAME_COLS if c in cols),
                                    None)
                    if not name_col:
                        continue
                    size_col = next((cols[c] for c in _SIZE_COLS if c in cols),
                                    None)
                    host_col = cols.get("_host") or cols.get("host")
                    for row in reader:
                        rows_seen += 1
                        if rows_seen > MAX_INDEXED_ROWS:
                            break
                        size: Optional[int] = None
                        if size_col:
                            try:
                                size = int(str(row.get(size_col) or "").strip()
                                           or 0)
                            except (TypeError, ValueError):
                                size = None
                        _add(str(row.get(name_col) or ""), size,
                             f"listing:{csv_path.name}",
                             str(row.get(host_col) or "") if host_col else "")
            except (OSError, csv.Error):
                continue

    # Shared case-wide scanner, not rglob: rglob does not descend symlinked
    # directories, and evidence of any size is symlinked into a case rather
    # than copied, so rglob would index a symlinked collection as empty.
    try:
        from core.evidence_catalog import iter_case_files
        for rel, abs_p in iter_case_files(root):
            try:
                _add(abs_p.name, abs_p.stat().st_size,
                     f"file:{rel.split('/', 1)[0]}")
            except OSError:
                continue
    except Exception:  # noqa: BLE001
        pass
    return out


def _trace_text(case_dir: str | os.PathLike) -> str:
    """The calls of the run that read content, as one lowercase blob: a
    listing, a stat or a hash names an artifact without reading it
    (core.coverage_ledger.reads_content, the rule the coverage units use)."""
    try:
        from core.coverage_ledger import reads_content
        from core.investigation_obligations import _iter_trace_rows
    except Exception:  # noqa: BLE001
        return ""
    analysis = Path(case_dir) / "analysis"
    traces = sorted(analysis.glob("*_trace.json")) + sorted(analysis.glob("*_trace.jsonl"))
    out: list[str] = []
    for p in traces[-2:]:
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for row in _iter_trace_rows(text):
            e = row.get("entry") if isinstance(row.get("entry"), dict) else row
            if not isinstance(e, dict) or (e.get("type") not in ("tool_call", None) and not e.get("cmd")):
                continue
            tool = str(e.get("mcp_tool") or e.get("tool") or "")
            if not tool:
                cmd = str(e.get("cmd") or "")
                tool = cmd[5:] if cmd.startswith("<py>:") else (cmd.split() or [""])[0]
            if not tool or not reads_content(tool.split(":")[-1]):
                continue
            blob = " ".join(str(e.get(k) or "") for k in ("cmd", "mcp_tool", "tool", "args"))
            if blob.strip():
                out.append(blob)
    return " ".join(out).lower()


def unexamined_high_value(
    case_dir: str | os.PathLike,
    *,
    threshold: int = HIGH_VALUE_THRESHOLD,
    limit: int = 12,
) -> list[dict[str, Any]]:
    """High-value artifacts the case knows exist but never opened.

    Empty artifacts are excluded — the point is unread *content*, not
    unopened filenames.
    """
    known = known_artifacts(case_dir)
    if not known:
        return []
    blob = _trace_text(case_dir)
    blocked = _blocked_basenames(case_dir)
    named = question_named_artifacts(case_dir)
    candidates = [
        {"name": v["name"], "size": v.get("size"), "host": v.get("host", ""),
         "source": v.get("source", ""), "path": v.get("path", ""),
         "abs": v.get("abs", ""), "kind": v.get("kind", "file"),
         "roots": v.get("roots") or []}
        for v in known.values()
    ]
    # A listing row of a file the volume also shows is the same artifact:
    # the sighting with a path is the one that can be read and credited.
    with_path = {c["name"].casefold() for c in candidates if c.get("path")}
    candidates = [c for c in candidates
                  if c.get("path") or c["name"].casefold() not in with_path]
    ranked = rank_artifacts(candidates)
    # What the case's own questions name outranks the value table: the
    # author pointed at it, whatever kind of artifact it is.
    if named:
        # Every artifact of that name is lifted: the same index on two
        # volumes is two things to read.
        lifted: set[str] = set()
        for item in ranked:
            if item["name"].casefold() in named:
                item["score"] = 100
                item["why"] = "named in the case's own questions"
                lifted.add(item.get("path") or item["name"].casefold())
        for v in known.values():
            key = v["name"].casefold()
            if key not in named or (v.get("path") or key) in lifted:
                continue
            if not v.get("path") and key in with_path:
                continue      # a listing row of a file the volume shows: read by path
            ranked.append({"name": v["name"], "size": v.get("size"), "host": v.get("host", ""),
                           "source": v.get("source", ""), "path": v.get("path", ""),
                           "abs": v.get("abs", ""), "kind": v.get("kind", "file"),
                           "roots": v.get("roots") or [],
                           "empty": looks_empty(v["name"], v.get("size")),
                           "score": 100, "why": "named in the case's own questions"})
        ranked.sort(key=lambda i: (-i["score"], -(i.get("size") or 0), i["name"]))
    out: list[dict[str, Any]] = []
    for item in ranked:
        if item["score"] < threshold or item.get("empty"):
            continue
        if _examined_in_trace(item, blob):
            continue
        if item["name"].casefold() in blocked:
            continue                      # the run tried and said why
        out.append(item)
        if len(out) >= limit:
            break
    return out


_EXTRACTED_RE: dict[str, re.Pattern[str]] = {}


def _examined_in_trace(item: dict[str, Any], blob: str) -> bool:
    """Has the run read this artifact?

    One known by name alone is read when its name appears in what the run
    did. One found on a mounted volume is read in place, by its path, or
    extracted under analysis/ or exports/ under its own name; its bare name
    is a common word there ("system", "software", "sam") that appears in
    any trace, so it proves nothing on its own.
    """
    name = str(item.get("name") or "").lower()
    path = str(item.get("path") or "").lower()
    if not path:
        # A whole name in a read, not a word inside another one: "history"
        # occurs in any trace.
        return bool(name) and re.search(
            r"(?:^|[\s\"'/\\=,;(\[])" + re.escape(name) + r"(?=$|[\s\"',;)\]/\\])", blob) is not None
    # The path ends where the call's argument ends: a listing of
    # config/systemprofile has not read SYSTEM, a read of SAM.LOG1 has not
    # read SAM. A directory artifact is read by any call under it.
    tail = r"(?=$|[\s\"',;)\]/])" if item.get("kind") == "directory" else r"(?=$|[\s\"',;)\]])"
    for p in (path, str(item.get("abs") or "").lower()):
        if p and re.search(re.escape(p) + tail, blob):
            return True
    # A member of a globbed family is read by a parser pointed at its
    # folder (ez.pecmd on Prefetch, ez.rbcmd on $Recycle.Bin): the folder
    # named as such, not one of its other members.
    for root_dir in item.get("roots") or []:
        r = str(root_dir).lower()
        if r and re.search(re.escape(r) + r"(?=/?(?:$|[\s\"',;)\]]))", blob):
            return True
    pat = _EXTRACTED_RE.get(name)
    if pat is None:
        pat = re.compile(r"(?:analysis|exports)/[^\s\"']*" + re.escape(name)
                         + r"(?=$|[\s\"',;)])")
        _EXTRACTED_RE[name] = pat
    return pat.search(blob) is not None


def _blocked_basenames(case_dir: str | os.PathLike) -> set[str]:
    """Names of the coverage units the run marked blocked after a real
    attempt: owed no longer, whatever their value."""
    try:
        from core.coverage_ledger import load_ledger
        units = (load_ledger(case_dir).get("units") or {}).values()
    except Exception:  # noqa: BLE001
        return set()
    out: set[str] = set()
    for u in units:
        if isinstance(u, dict) and str(u.get("status") or "") == "blocked":
            base = str(u.get("path") or "").replace("\\", "/").rsplit("/", 1)[-1]
            if base:
                out.add(base.casefold())
    return out


def question_named_artifacts(case_dir: str | os.PathLike) -> set[str]:
    """File names the case's investigation questions name (casefolded
    basenames): a sync database or a search index the author asked about
    is high value for this case whether or not the value table knows it."""
    try:
        from core.entities import artifact_tokens
        from core.investigation_tasks import list_tasks, tasks_path
        if not tasks_path(case_dir).is_file():
            return set()
        tasks = list_tasks(case_dir)
    except Exception:  # noqa: BLE001
        return set()
    out: set[str] = set()
    for t in tasks:
        if not isinstance(t, dict) or t.get("status") == "dropped":
            continue
        out |= {tok for tok in artifact_tokens(str(t.get("text") or "")) if "." in tok}
    return out


def _case_hosts(case_dir) -> list[str]:
    try:
        from core.forensic_citation import known_case_hosts
        return list(known_case_hosts(case_dir))
    except Exception:  # noqa: BLE001
        return []


_CONTAINER_RE = re.compile(
    r"(?i)\b(?:from|in|within|inside|across|on|at|under|into|searched|"
    r"scanned|parsed|examined|queried|of)\b")


def _names_a_container(statement: str, base: str) -> bool:
    """Is this file named as the place that was searched, not as the thing
    found missing? "hash X absent from a.csv, b.csv" is about X; the CSVs
    are containers. Treating them as the missing thing raises a false clash
    that costs the model turns re-recording a correct claim.
    """
    low = statement.lower()
    i = low.find(base.lower())
    if i < 0:
        return False
    before = low[:i]
    last_absence = None
    for m in _ABSENCE_RE.finditer(before):
        last_absence = m
    if last_absence is None:
        return False
    between = before[last_absence.end():]
    # a sentence boundary, not the dot of a file extension
    if re.search(r"[.;](?:\s|$)", between):
        return False
    return bool(_CONTAINER_RE.search(between))


_ABSENT_BEFORE = (
    r"(?:no|not\s+any|without|missing|absent|lack\s+of|absence\s+of|"
    r"could\s+not\s+(?:find|locate)|unable\s+to\s+(?:find|locate)|"
    r"never\s+(?:found|present|created|written))"
    r"(?:\s+(?:the|a|an|any|such|file|log|artifact|copy\s+of))*\s+"
)
_ABSENT_AFTER = (
    r"\s+(?:(?:is|was|were|are|being)\s+)?(?:not\s+(?:present|found|there|available|"
    r"recovered|located|on\s+disk|in\s+the\s+image)|absent|missing|unavailable|"
    r"(?:does|did)\s+not\s+exist|never\s+(?:existed|present|written|created)|"
    r"could\s+not\s+be\s+(?:found|located|recovered))\b"
)


def _absent_target(statement: str, base: str) -> bool:
    """Does the statement say this artifact itself is absent — not that
    something was absent *in* it? "No EID 1102 records in Security.csv"
    is a search result about the log; "Security.evtx not present" is a
    claim about the log."""
    name = re.escape(base)
    low = statement or ""
    if re.search(_ABSENT_BEFORE + name + r"\b", low, re.IGNORECASE):
        return True
    if re.search(r"\b" + name + _ABSENT_AFTER, low, re.IGNORECASE):
        return True
    return False


def contradicted_absence_claims(
    case_dir: str | os.PathLike,
    *,
    limit: int = 10,
) -> list[dict[str, Any]]:
    """Beliefs asserting an artifact is absent that the case's own index lists.

    This is the self-contradiction that turns a triage gap into a false
    narrative: an event log named absent in a claim while the run's own MFT
    listing records it with a size.
    """
    try:
        from core.claim_graph import load_graph
        from core.entities import extract
    except Exception:  # noqa: BLE001
        return []
    try:
        nodes = [n for n in (load_graph(case_dir).get("nodes") or {}).values()
                 if isinstance(n, dict)]
    except Exception:  # noqa: BLE001
        return []
    # The index (a volume scan and a listing read) is built only when a
    # belief asserts an absence at all.
    if not any(_ABSENCE_RE.search(str(n.get("statement") or "")) for n in nodes
               if n.get("status") not in ("superseded", "withdrawn")):
        return []
    known = known_artifacts(case_dir)
    if not known:
        return []
    # A volume the links tie to no host cannot answer a claim about a named
    # host when the case holds several volumes or names several hosts:
    # which host the volume is is unknown, and a clash guessed wrong made a
    # model retract a true claim. The hosts are the linked labels and the
    # host tags on the beliefs, since a brief need not carry Evidence Links.
    hosts = {h.casefold() for h in _case_hosts(case_dir) if h}
    hosts |= {str(n.get("host") or "").strip().casefold() for n in nodes
              if str(n.get("host") or "").strip()}
    ambiguous_volume = len(_mounted_volumes(case_dir)) > 1 or len(hosts) > 1
    out: list[dict[str, Any]] = []
    for node in nodes:
        if not isinstance(node, dict):
            continue
        if node.get("status") in ("superseded", "withdrawn"):
            continue
        statement = str(node.get("statement") or "")
        if not _ABSENCE_RE.search(statement):
            continue
        for ent in extract(statement):
            if not ent.startswith("file:"):
                continue
            base = ent.split(":", 1)[1].lower()
            hits = [v for v in known.values()
                    if str(v.get("name") or "").lower() == base
                    and not looks_empty(v["name"], v.get("size"))]
            if not hits:
                continue
            if not _absent_target(statement, base):
                continue      # the file is where the search ran, not what is missing
            claim_host = str(node.get("host") or "").strip()
            for hit in hits:
                # "No X on host A" is not contradicted by X existing on host B.
                # A false clash nudged turn after turn makes the model
                # supersede a correct claim just to silence it.
                hit_host = str(hit.get("host") or "").strip()
                if claim_host and hit_host and hit_host.casefold() != claim_host.casefold():
                    continue
                if (claim_host and not hit_host and ambiguous_volume
                        and str(hit.get("source") or "").startswith("mount:")):
                    continue
                if claim_host and not hit_host:
                    try:
                        from core.forensic_citation import host_mentioned
                        src = str(hit.get("source") or "") + " " + str(hit.get("name") or "")
                        others = [h for h in _case_hosts(case_dir)
                                  if h.casefold() != claim_host.casefold()]
                        if any(host_mentioned(h, src) for h in others) \
                                and not host_mentioned(claim_host, src):
                            continue
                    except Exception:  # noqa: BLE001
                        pass
                score, _ = artifact_score(hit["name"], hit.get("size"))
                if score <= 0:
                    continue
                out.append({
                    "claim_id": node.get("id"),
                    "artifact": hit["name"],
                    "size": hit.get("size"),
                    "indexed_by": hit.get("source", ""),
                    "statement": statement[:220],
                })
                break
            if len(out) >= limit:
                return out
    return out


def format_value_nudge(
    unexamined: Iterable[dict[str, Any]],
    contradictions: Iterable[dict[str, Any]] = (),
) -> str:
    """What the loop tells the model: read the valuable things, and stop
    asserting an absence the case itself disproves."""
    items = list(unexamined)
    clashes = list(contradictions)
    if not items and not clashes:
        return ""
    lines: list[str] = []
    if clashes:
        lines.append(
            "[artifact contradiction] A recorded belief says an artifact is "
            "absent, but this case's own index lists it. Re-examine the "
            "artifact and correct or withdraw the claim — an absence "
            "asserted over evidence you already hold is a false finding:")
        for c in clashes[:6]:
            size = c.get("size")
            lines.append(
                f"- {c['claim_id']}: claims absence of {c['artifact']}"
                + (f" — indexed at {size:,} bytes" if size else "")
                + f" ({c.get('indexed_by', '')})")
    if items:
        lines.append(
            "[artifact value] These artifacts are present and unread, "
            "ordered by how much of the investigation they can answer. "
            "Enumeration order is not priority — work down this list, or "
            "record why an entry cannot be recovered:")
        for a in items[:8]:
            size = a.get("size")
            if a.get("kind") == "directory":
                measure = f" ({size:,} file{'s' if size != 1 else ''})" if size else ""
            else:
                measure = f" ({size:,} bytes)" if size else ""
            lines.append(
                f"- {a['name']}"
                + measure
                + (f" at {a['path']}" if a.get("path") else "")
                + (f" [{a['host']}]" if a.get("host") and not a.get("path") else "")
                + f" — {a['why']}")
    return "\n".join(lines)
