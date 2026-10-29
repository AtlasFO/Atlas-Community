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
import json
import os
import re
from pathlib import Path
from typing import Any, Iterable, Optional

# The extensions of plain-text files (universal file-format knowledge): the
# textual-log class below, and the formats the generic text tools read
# (tools.tool_capabilities.readers_by_format).
TEXT_FORMATS = ("log", "txt", "csv", "tsv", "json", "jsonl", "ndjson", "xml")

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
    # Amcache.hve stands before the hives rule, which takes every other
    # .hve: it is its own class with its own parser (first match wins).
    (80, re.compile(r"(?i)amcache\.hve$"),
     "program execution evidence including deleted binaries"),
    # The machine hives and their .hve exports; Syscache.hve is a lookup
    # cache of executables, read with Amcache at its own rank below.
    (82, re.compile(r"(?i)(^|[\\/])(system|software|sam|security)$|(?<!syscache)\.hve$"),
     "registry hives — services, run keys, device history"),
    (60, re.compile(r"(?i)syscache\.hve$"),
     "executable lookup cache — corroborates Amcache"),
    (78, re.compile(r"(?i)(^|[\\/])prefetch([\\/]|$)|\.pf$"),
     "execution counts and first/last run times"),
    # The SRUM store is the database in the service's own folder
    # (System32\sru: SRUDB.dat and its transaction logs). A library or a
    # service binary carrying "srum" in its name holds no usage data.
    (76, re.compile(r"(?i)(^|[\\/])srudb\.dat$|(^|[\\/])sru[\\/][^\\/]+$"),
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
    (45, re.compile(r"(?i)\.(" + "|".join(TEXT_FORMATS) + r")$"),
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

# Column names an artifact listing may use for name, size and the folder
# the name sits in.
_NAME_COLS = ("filename", "name", "file", "path", "filepath", "file_name")
_SIZE_COLS = ("filesize", "size", "file_size", "bytes", "length")
_PARENT_COLS = ("parentpath", "parent_path", "parent path", "directory")
# The ways a listing writes the root of the image it lists: a drive letter,
# "./", the NT long-path, device and volume prefixes, a leading "/".
# Universal path shapes, not a case's.
_ROOT_PREFIX_RE = re.compile(
    r"(?i)^(?:\./+|//\?/|[a-z]:/+|/*device/harddiskvolume\d+/+|/*volume\{[^}]*\}/+|/+)+")

MAX_INDEXED_ROWS = 200_000
HIGH_VALUE_THRESHOLD = 70


def artifact_score(name: str, size: Optional[int] = None, *, is_dir: bool = False) -> tuple[int, str]:
    """(score, rationale) for an artifact, from its identity — not its
    position in a listing. Unknown artifacts score 0. A directory
    (``is_dir``, ``name`` its path) scores only when it is one of the
    platform's folder artifacts (a "/"-ending entry of
    _VOLUME_ARTIFACT_PATHS: a profile's Recent folder, Prefetch, the burn
    staging folder): a folder named like a file artifact (System, SAM,
    History) is no hive and no browser history."""
    text = str(name or "").replace("\\", "/")
    base = text.rsplit("/", 1)[-1]
    if is_dir and not is_folder_artifact(text):
        return 0, ""
    # A Jump List is named by a sixteen-hex AppID; it is not a component
    # store payload, whatever its name looks like.
    if _PAYLOAD_RE.search(base) and not base.lower().endswith("destinations-ms"):
        return 0, ""
    for weight, pattern, why in _VALUE_RULES:
        if pattern.search(base) or pattern.search(text):
            # A directory's own size says nothing of what it holds.
            if not is_dir and looks_empty(base, size):
                # Still identifiable, but nothing in it to find.
                return max(1, weight // 10), f"{why} (appears empty)"
            return weight, why
    return 0, ""


_FOLDER_ARTIFACTS: Optional[list[list[str]]] = None


def is_folder_artifact(path: str) -> bool:
    """Whether a directory's path is one of the platform's folder artifacts
    (the "/"-ending entries of _VOLUME_ARTIFACT_PATHS), each component
    matched without regard to case as _iglob_volume matches it, on the
    path's last components (a listing may keep a drive or volume label in
    front)."""
    import fnmatch
    global _FOLDER_ARTIFACTS
    if _FOLDER_ARTIFACTS is None:
        _FOLDER_ARTIFACTS = [[c.casefold() for c in p.split("/") if c]
                             for p in _VOLUME_ARTIFACT_PATHS if p.endswith("/")]
    comps = [c.casefold() for c in str(path or "").replace("\\", "/").split("/") if c]
    return any(len(comps) >= len(want) and all(fnmatch.fnmatchcase(c, w) for c, w in zip(comps[-len(want):], want))
               for want in _FOLDER_ARTIFACTS)


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
        # A folder read as a whole ranks as the members it holds; any other
        # directory only as a folder artifact of its own (artifact_score).
        family = "members" in e
        is_dir = (e.get("kind") == "directory" or bool(e.get("is_dir"))) and not family
        if is_dir and e.get("index_id") is not None:
            # An index directory row's size is the listing's size of the
            # directory itself, not of what it holds: no "appears empty"
            # from it. A volume folder's size is its member count and stays.
            size = None
        where = e.get("score_as") or ((e.get("path") or e.get("lpath") or name) if is_dir else name)
        score, why = artifact_score(where, size, is_dir=is_dir)
        if score <= 0:
            continue
        item = dict(e)
        item["score"] = score
        item["why"] = why
        item["empty"] = looks_empty(name, size)
        scored.append(item)
    scored.sort(key=_rank_order)
    return scored


def _rank_order(item: dict[str, Any]) -> tuple:
    """Richest first; equal ones by name, host and where they sit, so two
    profiles' copies of one file keep a stable order."""
    return (-item["score"], -(item.get("size") or 0), item["name"], item.get("host") or "",
            item.get("path") or item.get("lpath") or "")


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
    # Read as one artifact by a parser pointed at it (_FOLDER_FAMILIES).
    "Windows/Prefetch/",
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

def _listing_path(value: str, parent: str = "") -> str:
    """A listing row's path inside its image ("Users/jane.doe/NTUSER.DAT"):
    the name column when it holds a whole path, else the parent column and
    the name; "" when the row gives no folder."""
    v = str(value or "").replace("\\", "/").strip()
    if "/" not in v:
        folder = str(parent or "").replace("\\", "/").strip().rstrip("/")
        if not folder:
            return ""
        v = f"{folder}/{v}"
    return _ROOT_PREFIX_RE.sub("", v).strip("/")


def known_artifacts(case_dir: str | os.PathLike) -> dict[str, dict[str, Any]]:
    """Every artifact the case has evidence of, keyed by case-relative path
    for one found on a volume, by host and path inside the image for a
    listing row ("CORP-WS01|users/jane.doe/ntuser.dat"; the host is "" when
    the listing does not say), and by lowercase name for a sighting that
    gives neither.

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
             roots: Optional[list[str]] = None, lpath: str = "",
             scope: str = "", extra: Optional[dict[str, Any]] = None) -> None:
        base = str(name or "").replace("\\", "/").rsplit("/", 1)[-1].strip()
        if not base or len(base) > 200:
            return
        # A sighting with a path is its own entry (every profile's NTUSER.DAT,
        # every volume's SYSTEM), and so is a listing row on its host and
        # path in the image: two profiles' or two hosts' copies are two
        # things to read. Only a row that says neither folds by name. An
        # index row of an image no host is linked to is keyed by its image.
        if path:
            key = path.lower()
        elif host or lpath:
            key = f"{(host or scope).casefold()}|{(lpath or base).lower()}"
        else:
            key = base.lower()
        prev = out.get(key)
        # Keep the largest sighting: an empty copy must not mask a full one.
        if prev is not None and (prev.get("size") or 0) >= (size or 0):
            return
        out[key] = {"name": base, "size": size, "source": where, "host": host,
                    "path": path, "abs": abs_path, "kind": kind,
                    "roots": list(roots or []), "lpath": lpath, **(extra or {})}

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
        case_hosts = _case_hosts(root)
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
                    parent_col = next((cols[c] for c in _PARENT_COLS if c in cols), None)
                    # No listing tool writes a host column: a listing is the
                    # host's whose name its file name carries, when it carries
                    # exactly one case host's. One that names none stays
                    # hostless; its file name is no host.
                    file_host = ""
                    if not host_col:
                        try:
                            from core.evidence_links import host_of_path, host_of_path_on
                            if host_of_path_on():
                                file_host = host_of_path(None, csv_path.name, list(case_hosts))
                            else:
                                from core.forensic_citation import host_mentioned
                                hit = [h for h in case_hosts if host_mentioned(h, csv_path.name)]
                                file_host = hit[0] if len(hit) == 1 else ""
                        except Exception:  # noqa: BLE001
                            file_host = ""
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
                        raw = str(row.get(name_col) or "")
                        _add(raw, size, f"listing:{csv_path.name}",
                             str(row.get(host_col) or "").strip() if host_col else file_host,
                             lpath=_listing_path(raw, str(row.get(parent_col) or "") if parent_col else ""))
            except (OSError, csv.Error):
                continue

    # The contents index (core.contents_index): what the case's disk images
    # hold, listed at intake, the rows the value table scores at or above
    # the threshold; every other name stays queryable through its find.
    # A copy extracted from an entry is that entry: its path is attached
    # (``copy``) and the copy is no file entry of its own.
    copies: set[str] = set()
    try:
        from core import contents_index as _ci
        if _ci.index_on():
            for r in _ci.scored_rows(root, HIGH_VALUE_THRESHOLD):
                _add(r["name"], r["size"], f"index:{r['origin']}", r["host"] or "",
                     kind="directory" if r["is_dir"] else "file", lpath=r["path"],
                     scope=r["image"], extra={
                         "handle": r["handle"], "image": r["image"], "versions": r["versions"],
                         "version_folders": r["version_folders"], "score_as": r["path"],
                         "partial": r["partial"], "index_id": r["id"], "origin": r["origin"],
                         "copy": r["copies"] if _ci.copy_provenance_on() else []})
            if _ci.copy_provenance_on():
                copies = {c.casefold() for c in _ci.copy_paths(root)}
    except Exception:  # noqa: BLE001 - the index is an addition, never a precondition
        pass

    # Shared case-wide scanner, not rglob: rglob does not descend symlinked
    # directories, and evidence of any size is symlinked into a case rather
    # than copied, so rglob would index a symlinked collection as empty.
    try:
        from core.evidence_catalog import iter_case_files
        for rel, abs_p in iter_case_files(root):
            if copies and rel.casefold() in copies:
                continue
            try:
                _add(abs_p.name, abs_p.stat().st_size,
                     f"file:{rel.split('/', 1)[0]}")
            except OSError:
                continue
    except Exception:  # noqa: BLE001
        pass
    return out


# ── what the run owes ────────────────────────────────────────────────────
#
# Artifact classes read as a folder: a parser pointed at the folder reads
# every member (Prefetch files, the Recycle Bin's $I records or XP's INFO2,
# a profile's Jump Lists), so the folder is the one thing to read on a host,
# however many members it holds, and the one thing to name when it is not
# read. (member name, levels from a member up to that folder, the folder's
# name.) Platform layout, as _VOLUME_ARTIFACT_PATHS is; a member kept in a
# folder of another name is a copy and is read on its own.
_FOLDER_FAMILIES: tuple[tuple[re.Pattern[str], int, str], ...] = (
    (re.compile(r"(?i)\.pf$"), 1, "Prefetch"),
    (re.compile(r"(?i)^\$i[a-z0-9]{6}(?:\.|$)"), 2, "$Recycle.Bin"),
    (re.compile(r"(?i)^info2$"), 2, "RECYCLER"),
    (re.compile(r"(?i)\.automaticdestinations-ms$"), 1, "AutomaticDestinations"),
    (re.compile(r"(?i)\.customdestinations-ms$"), 1, "CustomDestinations"),
)

# How long a recorded reason must be to count, as for any acknowledged
# limitation the report gate accepts (tools/reasoning._MIN_ACK_JUSTIFICATION).
_MIN_REASON = 40


def _family_unit(c: dict[str, Any]) -> Optional[dict[str, Any]]:
    """The folder a family member is read through, as an artifact of its
    own (a directory, ranked as its members by ``score_as``); None for an
    artifact read on its own."""
    name = str(c.get("name") or "")
    for pattern, up, folder_name in _FOLDER_FAMILIES:
        if not pattern.search(name):
            continue
        host = str(c.get("host") or "")
        where = str(c.get("path") or c.get("lpath") or "")
        parts = where.split("/") if where else []
        folder = "/".join(parts[:-up]) if len(parts) > up else ""
        if folder and folder.rsplit("/", 1)[-1].casefold() != folder_name.casefold():
            return None
        unit: dict[str, Any] = {
            "name": folder.rsplit("/", 1)[-1] if folder else folder_name, "size": 0,
            "host": host, "source": c.get("source", ""), "path": "", "lpath": "", "abs": "",
            "kind": "directory", "roots": [], "score_as": name, "members": []}
        if c.get("path") and folder:
            unit["path"], unit["key"] = folder, folder.lower()
            abs_path = str(c.get("abs") or "")
            for _ in range(up):
                abs_path = os.path.dirname(abs_path)
            unit["abs"] = abs_path
        else:
            unit["lpath"] = folder
            unit["key"] = (f"{host.casefold()}|{(folder or folder_name).lower()}"
                           if host or folder else folder_name.lower())
        return unit
    return None


def _collapse_families(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The candidates with every family member replaced by its folder,
    sized by the members that are not empty. A row of the folder itself is
    that folder."""
    units: dict[str, dict[str, Any]] = {}
    rest: list[dict[str, Any]] = []
    for c in candidates:
        unit = _family_unit(c)
        if unit is None:
            rest.append(c)
            continue
        u = units.setdefault(unit["key"], unit)
        if not looks_empty(c["name"], c.get("size")):
            u["size"] += 1
            u["members"].append(c["name"])
    return [c for c in rest if c["key"] not in units] + list(units.values())


# Where an extraction put its copy: the executor's own note on a call that
# wrote its output to a file, or a Python tool's output_path argument.
_WROTE_RE = re.compile(r"(?i)(?:output written to |\"output_path\":\s*\")([^\s\"]+)")


def _trace_calls(case_dir: str | os.PathLike) -> tuple[list[dict[str, Any]], list[str]]:
    """What the case's trace (core.execution_log.trace_entries) says about
    reading, in trace order: each call that read content, as {"call_id",
    "text", "error", "failed", "ref", "wrote"} ("failed" for an attempt that
    failed, "ref" the image it ran against, "wrote" the copies it extracted),
    and the texts in which the run may have recorded why an artifact is not
    read (each reason.synthesize's input and conclusion).

    A listing, a stat or a hash names an artifact without reading it
    (core.coverage_ledger.reads_content, the rule the coverage units use);
    an extraction whose arguments name its copy reads it, as it always did
    here (the event-log obligation asks for the parse). A refusal, an
    argument error or a call a stop cut short is no attempt
    (core.coverage_ledger._failed_attempt)."""
    try:
        from core.coverage_ledger import _entry_tool, _failed_attempt, reads_content, resolved_entry
        from core.evidence_identity import Resolver, call_reads
        from core.execution_log import trace_entries
        entries = trace_entries(case_dir) or []
    except Exception:  # noqa: BLE001
        return [], []
    resolver = Resolver(case_dir)
    calls: list[dict[str, Any]] = []
    statements: list[str] = []
    jobs: dict = {}
    for e in entries:
        # As the read rule sees the call: a background job's start by the
        # job's outcome, nothing while it runs (resolved_entry).
        e = resolved_entry(case_dir, e, jobs) if e.get("type") == "tool_call" else e
        if e is None:
            continue
        if e.get("type") == "reason_call":
            if e.get("tool") == "reason_synthesize":
                inputs = e.get("inputs")
                statements.append(str(inputs.get("user_message") or "") if isinstance(inputs, dict)
                                  else str(inputs or ""))
                statements.append(str(e.get("conclusion") or ""))
            continue
        if e.get("type") not in ("tool_call", None) and not e.get("cmd"):
            continue
        if e.get("source") == "coverage":
            continue                      # parsed for the sweep, never read by a model
        tool = str(e.get("mcp_tool") or e.get("tool") or "")
        if not tool:
            cmd = str(e.get("cmd") or "")
            tool = cmd[5:] if cmd.startswith("<py>:") else (cmd.split() or [""])[0]
        # The rule's name for an analyst tool's call (a sub-command by its own
        # program's tool); a pre-run call by its program.
        if not tool or not reads_content(_entry_tool(e) or tool.split(":")[-1]):
            continue
        # The image a call ran against says which host it read.
        text = " ".join(str(e.get(k) or "") for k in
                        ("cmd", "mcp_tool", "tool", "args", "evidence_ref")).lower()
        if not text.strip():
            continue
        failed = e.get("success") is False
        if failed and not _failed_attempt(e):
            continue
        # A call over a folder reads no file of it (call_reads lists them):
        # what a parser processed there is the parser's own report (the
        # ``processed`` stamp), and a processed file whose rows nobody looked
        # at is "parsed", never read (core.contents_index.read_state_by_class).
        wrote = [] if failed else _WROTE_RE.findall(
            f"{e.get('stdout_excerpt') or ''} {e.get('args') or ''}")
        calls.append({"call_id": e.get("call_id"), "text": text, "failed": failed,
                      "tool": _entry_tool(e) or tool.split(":")[-1],
                      "error": " ".join(str(e.get("stderr") or e.get("error") or "").split()),
                      "ref": str(e.get("evidence_ref") or ""), "wrote": [w.lower() for w in wrote],
                      "reads": call_reads(case_dir, e, resolver=resolver)})
    _where(resolver, calls)
    resolver.close()
    return calls, statements


def _where(resolver, calls: list[dict[str, Any]]) -> None:
    """Stamp each call with where its entries lie ({id: (host, image,
    volume, path)}), one batched lookup for the trace: a folder item is
    read through any entry under it."""
    ids = {i for c in calls for k in ("content", "folder") for t, i in (x[:2] for x in c["reads"].get(k, ()) if len(x) == 2) if t == "entry"}
    where = resolver.where(ids) if ids else {}
    for c in calls:
        c["where"] = where


def _hosts_in(text: str, hosts: Iterable[str]) -> set[str]:
    """The case hosts a text names (casefolded)."""
    try:
        from core.forensic_citation import host_mentioned
    except Exception:  # noqa: BLE001
        return set()
    return {h.casefold() for h in hosts if host_mentioned(h, text)}


def _attribute_hosts(calls: list[dict[str, Any]], hosts: list[str],
                     case_dir: str | os.PathLike) -> None:
    """Stamp each call with the case hosts it read ("hosts"): the ones its
    text names once the case directory's own path is taken out (a case
    directory named after a host would name it in every call), the one the
    Evidence Links give the image it ran against, and, for a call naming
    neither, the hosts of the call that extracted a copy it reads (an
    extraction from one host's image into exports/, then a parse of the
    copy). None: a call that says nothing of its host reads every host's.

    ponytail: a host's short form that is a word (CORP-DATA as "data")
    attributes a call that uses the word to that host; the blocker's full
    labels are what a run copies."""
    # Absolute spellings only: a relative one (".") would cut every dot.
    roots = sorted({r.rstrip("/") for r in (str(case_dir).lower(),
                                            str(Path(case_dir).resolve()).lower())
                    if os.path.isabs(r) and len(r) > 1},
                   key=len, reverse=True)

    def _strip(text: str) -> str:
        for r in roots:
            text = text.replace(r, " ")
        return text

    linked: dict[str, str] = {}
    copies: dict[str, set[str]] = {}
    for call in calls:
        named = _hosts_in(_strip(call["text"]), hosts)
        if call["ref"]:
            if call["ref"] not in linked:
                linked[call["ref"]] = _volume_host(call["ref"], case_dir).casefold()
            if linked[call["ref"]]:
                named.add(linked[call["ref"]])
        if not named:
            for copy, owners in copies.items():
                if copy in call["text"]:
                    named |= owners
        call["hosts"] = named
        for wrote in call["wrote"] if named else ():
            copy = _strip(wrote).strip().lstrip("/")
            if copy:
                copies[copy] = named


_UNRESOLVABLE_WORD_RE = re.compile(r"(?i)\bunresolvable\b")
_WAIVER_HEAD_RE = re.compile(
    r"(?i)^\s*(?:[-*\u2022]|\d+[.)])?\s*unresolvable(?:\s*\([^)]*\))?\s*:?\s*")
# Outside a section the word counts where it opens the line (the form the
# gate and the nudge prescribe) or states the dead-end ("... is
# unresolvable: ...", "unresolvable because ...").
_WAIVER_STATED_RE = re.compile(r"(?i)\bunresolvable\s*(?:[:\u2014\u2013-]|because\b)")
_WAIVER_SPLIT_RE = re.compile(r"\s[\u2014\u2013-]+\s|:\s")


def _waivers(statements: Iterable[str], hosts: Iterable[str]) -> list[dict[str, Any]]:
    """Every line in which the run recorded why something is not read: a
    line of an UNRESOLVABLE (or acknowledged, documented or accepted
    limitations) section, or one that opens with UNRESOLVABLE or states it;
    not one that negates the word ("not unresolvable") or whose subject is
    none ("UNRESOLVABLE: none - every blocker is actionable"). Each with its
    subject (what precedes the first dash or colon: the artifact, in the
    form the gate asks for), its reason (what follows, else the whole line)
    and the case hosts it names, in its subject if there are any there
    (none: every host's copy)."""
    try:
        from tools.reasoning import (_UNRESOLVABLE_SECTION_RE, _acknowledges_nothing,
                                     _blocker_items, _negated_at)
    except Exception:  # noqa: BLE001
        return []
    hosts = list(hosts)
    lines: list[str] = []
    for text in statements:
        for m in _UNRESOLVABLE_SECTION_RE.finditer(text or ""):
            lines += _blocker_items(m.group(1))
        lines += [ln for ln in (text or "").splitlines()
                  if _WAIVER_HEAD_RE.match(ln) or _WAIVER_STATED_RE.search(ln)]
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for ln in lines:
        word = _UNRESOLVABLE_WORD_RE.search(ln)
        if word and _negated_at(ln, word.start()):
            continue
        body = _WAIVER_HEAD_RE.sub("", ln, count=1).strip()
        if len(body) < 3 or body in seen or _acknowledges_nothing(body):
            continue
        seen.add(body)
        parts = _WAIVER_SPLIT_RE.split(body, maxsplit=1)
        subject = parts[0].strip()
        # The hosts the subject names; a reason that names others (as a
        # contrast, "unlike CORP-WS01") does not widen it.
        out.append({"text": body, "subject": subject, "low": subject.lower(),
                    "reason": (parts[1] if len(parts) == 2 else body).strip(),
                    "hosts": _hosts_in(subject, hosts) or _hosts_in(body, hosts)})
    return out


_NAME_BEFORE = r"(?:^|[\s\"'`*(\[/\\=,;:])"
_NAME_AFTER = r"(?=$|[\s\"'`*,;:)\]/\\\u2014\u2013]|\.(?:\s|$))"


def _named_in(item: dict[str, Any], text: str, low: str) -> bool:
    """Does a statement name this artifact: by the path a read would name
    (_examined_in_trace) or by its whole name? A name with no extension
    ("SYSTEM", "History") counts only as the case spells it, since in prose
    it is a common word; "Security.evtx" names the log, not the SECURITY
    hive."""
    if (item.get("path") or item.get("lpath")) and _examined_in_trace(item, low):
        return True
    name = str(item.get("name") or "")
    if not name or name.lower() not in low:
        return False
    hay, needle = (low, name.lower()) if "." in name.strip(".") else (text, name)
    return re.search(_NAME_BEFORE + re.escape(needle) + _NAME_AFTER, hay) is not None


_EXTRACT_TOKEN_RE = re.compile(r"(?:analysis|exports)/[^\s\"']+")


def _extracted_names(blob: str) -> set[str]:
    """Names of the copies under analysis/ or exports/ a text names."""
    return {tok.rstrip(",;)]").rsplit("/", 1)[-1] for tok in _EXTRACT_TOKEN_RE.findall(blob)}


_HV_MEMO: dict[tuple, tuple[tuple, dict[str, Any]]] = {}


def _hv_signature(case_dir: str | os.PathLike) -> Optional[tuple]:
    """What high_value_state reads, as a cheap signature: the live trace's
    length and newest entry, the contents index's files, the mount plan,
    the Evidence Links, the case directories' own times and the switches.
    None (no memo) unless the live trace is this case's: a case read from
    disk or by a test that changes files between calls is recomputed."""
    try:
        from core.execution_log import _case_dir_for_trace, log
        live = log.trace_path()
        root = os.path.realpath(str(case_dir))
        if not live or os.path.realpath(_case_dir_for_trace(live)) != root:
            return None
        with log._lock:
            n = len(log._entries)
            last = log._entries[-1] if n else {}
            tail = (last.get("call_id"), last.get("ts"), last.get("success"))
    except Exception:  # noqa: BLE001
        return None

    def _st(p: str) -> tuple:
        try:
            st = os.stat(p)
            return (st.st_size, st.st_mtime_ns)
        except OSError:
            return ()
    files = [os.path.join(root, ".atlas", f) for f in (
        "contents_index.db", "contents_index.db-wal", "mount_plan.json", "evidence_links.json")]
    dirs = [os.path.join(root, d) for d in ("analysis", "exports", "evidence")]
    try:
        from core.contents_index import copy_provenance_on, index_on
        from core.deferred_intents import blocker_items_on
        flags = (index_on(), copy_provenance_on(), blocker_items_on())
    except Exception:  # noqa: BLE001
        flags = ()
    return (n, tail, tuple(_st(p) for p in files + dirs), flags)


def high_value_state(
    case_dir: str | os.PathLike,
    *,
    threshold: int = HIGH_VALUE_THRESHOLD,
) -> dict[str, Any]:
    """high_value_state_uncached, remembered while nothing it reads has
    changed: the director block, the digest, the proposals, the gaps and
    the gates all ask within one turn, and with the contents index the
    answer covers thousands of rows."""
    import copy as _copy
    sig = _hv_signature(case_dir)
    key = (os.path.realpath(str(case_dir)), threshold)
    if sig is not None:
        hit = _HV_MEMO.get(key)
        if hit is not None and hit[0] == sig:
            return _copy.deepcopy(hit[1])
    out = high_value_state_uncached(case_dir, threshold=threshold)
    if sig is not None:
        _HV_MEMO.clear()
        _HV_MEMO[key] = (sig, _copy.deepcopy(out))
    return out


def high_value_state_uncached(
    case_dir: str | os.PathLike,
    *,
    threshold: int = HIGH_VALUE_THRESHOLD,
) -> dict[str, Any]:
    """How the case stands with each high-value artifact it knows exists.

    ``items`` are the ones nobody read, richest first, each with a
    ``state``: "open" (no read, no failed attempt, no recorded reason),
    "failed" (a read of it failed: ``call_id``, and the error as
    ``reason``) or "waived" (an UNRESOLVABLE statement in reason.synthesize
    names it: its reason as ``reason``). ``read`` counts the ones read.
    ``short_waivers`` are statements that name an open artifact with a
    reason too short to count, ``unmatched_waivers`` ones with a reason that
    name no artifact the case lists.

    Empty artifacts are left out: the point is unread content, not unopened
    file names. A family read as a folder (Prefetch, the Recycle Bin, a
    profile's Jump Lists) is one artifact per host and folder, read by any
    read of it or of a member. A read, a failure or a statement that names
    case hosts answers for those hosts' listing rows only; a file on a
    mounted volume is one file wherever a call came from.
    """
    out: dict[str, Any] = {"items": [], "read": 0, "short_waivers": [], "unmatched_waivers": [],
                           "read_hosts": []}
    known = known_artifacts(case_dir)
    if not known:
        return out

    def _candidate(key: str, v: dict[str, Any]) -> dict[str, Any]:
        c = {"key": key, "name": v["name"], "size": v.get("size"), "host": v.get("host", ""),
             "source": v.get("source", ""), "path": v.get("path", ""), "lpath": v.get("lpath", ""),
             "abs": v.get("abs", ""), "kind": v.get("kind", "file"), "roots": v.get("roots") or []}
        # The contents index's keys (core.contents_index): how to read the
        # entry, its folded versions, the path it scores as and its copies.
        c.update({k: v[k] for k in _INDEX_KEYS if k in v})
        return c

    candidates = _collapse_families([_candidate(k, v) for k, v in known.items()])
    # A listing row of a file a volume of its host also shows is the same
    # artifact: the sighting with a path is the one that can be read and
    # credited. A row with its path in the image is that file on the volume
    # only; a row with a name alone, any file of that name there.
    on_volume: dict[str, list[dict[str, Any]]] = {}
    for c in candidates:
        if c.get("path"):
            on_volume.setdefault(c["name"].casefold(), []).append(c)

    def _shown_on_volume(c: dict[str, Any]) -> bool:
        if c.get("path"):
            return False
        tail = "/" + str(c.get("lpath") or "").lower()
        return any(_same_host(c.get("host"), v.get("host"))
                   and (tail == "/" or str(v["path"]).lower().endswith(tail))
                   for v in on_volume.get(c["name"].casefold(), ()))

    ranked = rank_artifacts(c for c in candidates if not _shown_on_volume(c))
    ranked = [i for i in ranked if i["score"] >= threshold and not i.get("empty")]
    if not ranked:
        return out

    calls, statements = _trace_calls(case_dir)
    hosts = sorted({str(i.get("host") or "") for i in ranked} - {""} | set(_case_hosts(case_dir)))
    _attribute_hosts(calls, hosts, case_dir)
    reads = [c for c in calls if not c["failed"]]
    failed = [c for c in calls if c["failed"]]
    for call in failed:
        call["extracted"] = _extracted_names(call["text"])
    from core.deferred_intents import blocker_items_on
    # With reviewer blockers as work items no UNRESOLVABLE statement waives an
    # artefact: one not read is an item that failed or was never adopted.
    waivers = [] if blocker_items_on() else _waivers(statements, hosts)
    used: set[int] = set()
    blobs: dict[str, tuple[str, set[str]]] = {}

    def _scope(item: dict[str, Any]) -> str:
        return "" if item.get("path") else str(item.get("host") or "").casefold()

    def _scoped(calls: list[dict[str, Any]], scope: str) -> list[dict[str, Any]]:
        return [c for c in calls if not scope or not c["hosts"] or scope in c["hosts"]]

    # The index entries a parser processed (its own report, or rows in a
    # joined table): parsed, not "no read attempted"; the disposition lists
    # them per output with their next step (core.evidence_disposition).
    try:
        from core.contents_index import index_on, parsed_entry_outputs
        parsed_ids = parsed_entry_outputs(case_dir) if index_on() else {}
    except Exception:  # noqa: BLE001
        parsed_ids = {}

    def _blob(item: dict[str, Any]) -> tuple[str, set[str]]:
        scope = _scope(item)
        if scope not in blobs:
            blob = " ".join(c["text"] for c in _scoped(reads, scope))
            blobs[scope] = (blob, _extracted_names(blob))
        return blobs[scope]

    first = _first_reads(reads)

    def _was_read(item: dict[str, Any]) -> bool:
        if _identified(item):
            return _read_by(item, reads, first=first) is not None or _unregistered_copy(item, _blob(item)[0])
        return _item_read(item, *_blob(item))

    def _failed_by(item: dict[str, Any]) -> Optional[dict[str, Any]]:
        if _identified(item):
            return _read_by(item, failed)
        return next((c for c in _scoped(failed, _scope(item))
                     if _item_read(item, c["text"], c["extracted"])), None)

    for item in ranked:
        if _was_read(item):
            out["read"] += 1
            if str(item.get("source") or "").startswith("index:") and item.get("host") \
                    and item["host"] not in out["read_hosts"]:
                out["read_hosts"].append(item["host"])
            continue
        fail = _failed_by(item)
        if fail is not None:
            item.update(state="failed", call_id=fail["call_id"],
                        reason=fail["error"][:240] or "the call failed")
            out["items"].append(item)
            continue
        folder_fail = _failed_over_folder(item, failed) if _identified(item) else None
        if folder_fail is not None:
            # Still open (the file's own read is still asked for), but the
            # gap says what was tried: its folder went to a parser that failed.
            item["failed_folder_call"] = {"call_id": folder_fail["call_id"], "tool": folder_fail.get("tool") or "",
                                          "error": folder_fail["error"][:240] or "the call failed"}
        if item.get("index_id") in parsed_ids:
            # Still open (nobody read it whole), but no "no read was
            # attempted" gap: its next step is the output it was parsed into,
            # or some of its rows there were already shown (partial).
            item["parsed_into"] = parsed_ids[item["index_id"]]
        host = str(item.get("host") or "").casefold()
        short = None
        for n, w in enumerate(waivers):
            if host and w["hosts"] and host not in w["hosts"]:
                continue
            if not _named_in(item, w["subject"], w["low"]):
                continue
            used.add(n)
            if len(w["reason"]) >= _MIN_REASON:
                item.update(state="waived", reason=w["reason"])
                break
            short = short or w["text"]
        else:
            item["state"] = "open"
            if short and short not in out["short_waivers"]:
                out["short_waivers"].append(short)
        out["items"].append(item)
    # A reason that names nothing the case lists (the artifact spelt another
    # way, or something that is no artifact): said back, so a run that tried
    # learns why it did not count.
    out["unmatched_waivers"] = [
        w["text"] for n, w in enumerate(waivers)
        if n not in used and len(w["reason"]) >= _MIN_REASON
        and not any(_named_in(i, w["subject"], w["low"]) for i in ranked)]
    return out


_INDEX_KEYS = ("handle", "image", "versions", "version_folders", "score_as", "partial", "index_id",
               "origin", "copy")


def _identified(item: dict[str, Any]) -> bool:
    """Whether the case can name this artifact (core.evidence_identity): an
    index entry (and a folder of index entries), or a file on a mounted
    volume by its case path. A listing row known by name and inner path
    alone, or a case file known by name, cannot be named that way."""
    return item.get("index_id") is not None or bool(item.get("path")) \
        or str(item.get("source") or "").startswith("index:")


def _first_reads(calls: list[dict[str, Any]]) -> dict:
    """{identity: the first call that read it by name} over ``calls``: a
    file artifact's read is one lookup (_read_by walks the calls for a
    folder artifact)."""
    out: dict = {}
    for c in calls:
        for ident in c["reads"]["content"]:
            out.setdefault(ident, c)
    return out


def _read_by(item: dict[str, Any], calls: list[dict[str, Any]], *, swept: bool = True,
             first: Optional[dict] = None) -> Optional[dict[str, Any]]:
    """The first call that read this artifact by its identity (what the
    call named, core.evidence_identity.call_reads): an index entry by its
    entry, a volume file by its case path; a folder artifact (a family's
    folder, a directory) by any file under it, also through the folder the
    call was pointed at (``swept``: a parser over the folder reads the
    folder, though no file of it on its own)."""
    eid = item.get("index_id")
    path = str(item.get("path") or "")
    folder = item.get("kind") == "directory"
    lpath = str(item.get("lpath") or "").casefold().strip("/")
    host = str(item.get("host") or "").casefold()
    if not folder and first is not None:
        return (first.get(("entry", eid)) if eid is not None else None) or \
            (first.get(("file", path)) if path else None)
    for c in calls:
        reads = c["reads"]
        got = reads["content"] | (reads.get("folder", frozenset()) if swept and folder else frozenset())
        if not folder:
            if (eid is not None and ("entry", eid) in got) or (path and ("file", path) in got):
                return c
            continue
        if path and (path in reads.get("folders", ()) or any(
                k == "file" and (i == path or i.startswith(path + "/")) for k, i in (x for x in got if len(x) == 2))):
            return c
        if eid is not None and ("entry", eid) in got:
            return c
        if lpath and not path:
            for k, i in (x for x in got if len(x) == 2):
                if k != "entry":
                    continue
                h, _img, _vol, p = c["where"].get(i) or ("", "", None, "")
                p = str(p or "").casefold().strip("/")
                if (not host or str(h or "").casefold() == host) and (p == lpath or p.startswith(lpath + "/")):
                    return c
    return None


def _failed_over_folder(item: dict[str, Any], failed: list[dict[str, Any]]) -> Optional[dict[str, Any]]:
    """The first failed call given a folder that holds this file artifact (a
    parser pointed at a profile or a log folder that crashed). The item stays
    open, its own read still asked for; the gap says what was tried."""
    path = str(item.get("path") or "").rstrip("/")
    if not path or item.get("kind") == "directory":
        return None
    for c in failed:
        named = {str(i).rstrip("/") for k, i in (x for x in c["reads"]["content"] | c["reads"].get("listed", frozenset())
                                                 if len(x) == 2) if k == "file"}
        named |= {str(f).rstrip("/") for f in c["reads"].get("folders", ())}
        if any(n and path.startswith(n + "/") for n in named):
            return c
    return None


def _unregistered_copy(item: dict[str, Any], text: str) -> bool:
    """A file on a mounted volume (no index entry) extracted by a call that
    registers no copy (icat <image> <inode> analysis/SYSTEM) and read there:
    nothing ties that copy to its source but its name.
    ponytail: the copy's name credits the file of that name on the hosts the
    call names; registered copies (the index's) never need this."""
    return item.get("index_id") is None and bool(item.get("path")) and item.get("kind") != "directory" \
        and _extracted(str(item.get("name") or "").lower()).search(text) is not None


def _item_read(item: dict[str, Any], text: str, extracted: set[str]) -> bool:
    """Does a reading text name an artifact the case cannot name by
    identity (_identified is false: a listing row known by name and inner
    path, a case file by name): its path in the image, a copy extracted
    under its own name, a member of its folder. Every other artifact is
    read by identity (_read_by), never by the text."""
    return (_examined_in_trace(item, text)
            or any(m.lower() in extracted for m in item.get("members") or ()))


def reading_calls(case_dir: str | os.PathLike, hosts: Iterable[str]) -> list[dict[str, Any]]:
    """The trace's successful reading calls (_trace_calls), each stamped
    with the hosts it read among ``hosts`` and the case's (_attribute_hosts)."""
    calls, _statements = _trace_calls(case_dir)
    _attribute_hosts(calls, sorted(set(hosts) - {""} | set(_case_hosts(case_dir))), case_dir)
    return [c for c in calls if not c["failed"]]


def examined_items(case_dir: str | os.PathLike, items: list[dict[str, Any]],
                   reads: Optional[list[dict[str, Any]]] = None) -> list[bool]:
    """For each listing-shaped item ({name, lpath, host, kind, handle}),
    whether a successful reading call of the trace names it, scoped to the
    hosts the call read as for high_value_state. ``reads``: reading_calls
    taken once for several lists, whose hosts it covers."""
    if not items:
        return []
    if reads is None:
        reads = reading_calls(case_dir, (str(i.get("host") or "") for i in items))
    blobs: dict[str, tuple[str, set[str]]] = {}
    out = []
    first = _first_reads(reads)
    for item in items:
        scope = str(item.get("host") or "").casefold()
        if _identified(item):
            if _read_by(item, reads, first=first) is not None:
                out.append(True)
                continue
            if scope not in blobs:
                blob = " ".join(c["text"] for c in reads if not scope or not c["hosts"] or scope in c["hosts"])
                blobs[scope] = (blob, _extracted_names(blob))
            out.append(_unregistered_copy(item, blobs[scope][0]))
            continue
        if scope not in blobs:
            blob = " ".join(c["text"] for c in reads if not scope or not c["hosts"] or scope in c["hosts"])
            blobs[scope] = (blob, _extracted_names(blob))
        out.append(_item_read(item, *blobs[scope]))
    return out


def unexamined_high_value(
    case_dir: str | os.PathLike,
    *,
    threshold: int = HIGH_VALUE_THRESHOLD,
    limit: int = 12,
) -> list[dict[str, Any]]:
    """High-value artifacts the case knows exist that nobody read, tried to
    read or explained (high_value_state's "open" ones), richest first."""
    items = high_value_state(case_dir, threshold=threshold)["items"]
    return [i for i in items if i["state"] == "open"][:limit]


def group_unread(items: Iterable[dict[str, Any]]) -> list[tuple[dict[str, Any], list[str]]]:
    """high_value_state items one per artifact, state and reason, each with
    the hosts it stands on, in the order given: every host's copy of one
    log at one place in the image are one entry."""
    groups: dict[tuple, tuple[dict[str, Any], list[str]]] = {}
    for i in items:
        key = (i["name"], i.get("path") or i.get("lpath") or "", i.get("state"),
               i.get("reason") or "", i.get("call_id"))
        hosts = groups.setdefault(key, (i, []))[1]
        if i.get("host") and i["host"] not in hosts:
            hosts.append(i["host"])
    return [(i, sorted(hosts)) for i, hosts in groups.values()]


_GAP_T = {
    "en": {
        "open": "- Not opened: {what}: no read was attempted and no reason was recorded.",
        "failed": "- Not opened: {what}: the read failed (call {call}: {reason})",
        "folder_failed": "- Not opened: {what}: its folder was given to {tool}, which failed (call {call}: {reason})",
        "waived": "- Not opened: {what}: {reason}",
        "at": " at {where}", "on": " on {hosts}",
        "class": "- Not opened inside the images: {why}: {files} ({names}) on {hosts}: no read was "
                 "attempted and no reason was recorded.",
        "files": "{n} file(s)", "hosts": "{n} host(s) ({names})",
        "untouched": "- {host}: the image was listed at intake ({n} entries); no file inside it was read.",
        "unlisted": "- {image}: not listed at intake ({reason}); its contents are unknown to the index.",
    },
    "de": {
        "open": "- Nicht geöffnet: {what}: weder ein Leseversuch noch ein Grund ist festgehalten.",
        "failed": "- Nicht geöffnet: {what}: das Lesen schlug fehl (Aufruf {call}: {reason})",
        "folder_failed": "- Nicht geöffnet: {what}: sein Ordner ging an {tool}, das fehlschlug (Aufruf {call}: {reason})",
        "waived": "- Nicht geöffnet: {what}: {reason}",
        "at": " unter {where}", "on": " auf {hosts}",
        "class": "- In den Images nicht geöffnet: {why}: {files} ({names}) auf {hosts}: weder ein "
                 "Leseversuch noch ein Grund ist festgehalten.",
        "files": "{n} Datei(en)", "hosts": "{n} Host(s) ({names})",
        "untouched": "- {host}: das Image wurde bei der Aufnahme gelistet ({n} Einträge); keine Datei "
                     "darin wurde gelesen.",
        "unlisted": "- {image}: bei der Aufnahme nicht gelistet ({reason}); sein Inhalt ist dem Index "
                    "unbekannt.",
    },
}


def _index_gap_lines(items: list[dict[str, Any]], read_hosts: list[str], case_dir: str | os.PathLike,
                     tx: dict[str, str], host: str) -> list[str]:
    """The contents index's unread rows grouped by class across hosts (one
    line per class, not per file and host: an estate's index holds
    thousands), then each listed image no read reached (the read rule,
    coverage_ledger.images_read: a read of the image or of a file extracted
    from it; a host a ranked item was read on counts too), then each image
    the intake could not list with its reason."""
    from core.contents_index import failed_images, listed_images
    try:
        from core.coverage_ledger import images_read
        reached = {str(i).replace("\\", "/").casefold() for i in images_read(case_dir)}
    except Exception:  # noqa: BLE001 - an unreadable trace credits nothing
        reached = set()
    by_class: dict[str, list[dict[str, Any]]] = {}
    for i in items:
        by_class.setdefault(str(i.get("why") or i.get("name") or ""), []).append(i)

    def _names(values: list[str], k: int = 4) -> str:
        uniq = list(dict.fromkeys(v for v in values if v))
        return ", ".join(uniq[:k]) + (f", +{len(uniq) - k}" if len(uniq) > k else "")
    out = []
    for why, group in sorted(by_class.items(), key=lambda kv: (-max(i["score"] for i in kv[1]), -len(kv[1]))):
        hosts = [str(i.get("host") or i.get("image") or "") for i in group]
        out.append(tx["class"].format(
            why=why, files=tx["files"].format(n=len(group)),
            names=_names([f"`{i['name']}`" for i in group]),
            hosts=tx["hosts"].format(n=len(set(hosts)), names=_names(sorted(set(hosts))))))
    read = {h.casefold() for h in read_hosts}
    for img in listed_images(case_dir):
        label = img["host"] or img["image"]
        if host and label.casefold() not in (host, ""):
            continue
        if img["host"] and img["host"].casefold() in read:
            continue
        if str(img["image"]).replace("\\", "/").casefold() in reached:
            continue
        out.append(tx["untouched"].format(host=label, n=img["entries"]))
    for image, reason in failed_images(case_dir):
        out.append(tx["unlisted"].format(image=image, reason=reason))
    return out


def gap_lines(case_dir: str | os.PathLike, language: str = "en", named: str = "",
              host: str = "") -> list[str]:
    """Evidence Gaps: each high-value artifact the case lists that nobody
    read, with the reason the run recorded, the read that failed, or that
    there is neither. A delivered file the evidence-item gap lines
    (``named``) already list is not listed twice; a host's report lists
    that host's artifacts and the ones of no known host."""
    try:
        state = high_value_state(case_dir)
        items = state["items"]
    except Exception:  # noqa: BLE001 - the report is written without them
        return []
    tx = _GAP_T["de" if language == "de" else "en"]
    host = host.strip().casefold()
    out: list[str] = []
    try:
        from core.contents_index import index_status_on
        grouped = index_status_on()
    except Exception:  # noqa: BLE001
        grouped = False
    try:
        # With the class level in the ledger, every class stands there as
        # read, partly read, left with its reason or undecided (the
        # disposition's report lines); the index's own class lines would
        # say "no reason" beside a recorded one.
        from core.coverage_ledger import load_ledger
        from core.evidence_disposition import disposition_on
        ledger_classes = disposition_on() and load_ledger(case_dir).get("classes") is not None
    except Exception:  # noqa: BLE001
        ledger_classes = False
    if grouped and ledger_classes:
        items = [i for i in items if not (i["state"] == "open"
                                          and str(i.get("source") or "").startswith("index:"))]
        try:
            index_lines = _index_gap_lines([], state.get("read_hosts") or [], case_dir, tx, host)
        except Exception:  # noqa: BLE001
            index_lines = []
    elif grouped:
        index_open = [i for i in items if i["state"] == "open" and not i.get("parsed_into")
                      and str(i.get("source") or "").startswith("index:")
                      and (not host or str(i.get("host") or "").casefold() in ("", host))]
        items = [i for i in items if not (i["state"] == "open"
                                          and str(i.get("source") or "").startswith("index:"))]
        try:
            index_lines = _index_gap_lines(index_open, state.get("read_hosts") or [], case_dir, tx, host)
        except Exception:  # noqa: BLE001
            index_lines = []
    else:
        index_lines = []
    # A parsed item is no gap of its own here: "Evidence not analysed" lists
    # it per output with its next step (core.evidence_disposition).
    items = [i for i in items if not (i.get("state") == "open" and i.get("parsed_into"))]
    for item, hosts in group_unread(i for i in items if not (
            str(i.get("source") or "").startswith("file:") and f"/{i['name']}`" in named)
            and (not host or str(i.get("host") or "").casefold() in ("", host))):
        where = item.get("path") or item.get("lpath") or ""
        what = (f"`{item['name']}`" + (tx["at"].format(where=f"`{where}`") if where else "")
                + (tx["on"].format(hosts=", ".join(hosts)) if hosts else ""))
        reason = " ".join(str(item.get("reason") or "").split())[:300]
        ff = item.get("failed_folder_call") if item.get("state") == "open" else None
        if item["state"] == "open" and not ff and ledger_classes:
            # With the class level in the ledger, the file's class states
            # its decision (read, left with a reason, or undecided under
            # the "Evidence not decided" heading): no "no reason recorded"
            # line beside it.
            continue
        if ff:
            out.append(tx["folder_failed"].format(what=what, tool=ff["tool"], call=ff["call_id"],
                                                  reason=" ".join(str(ff["error"]).split())[:300]))
            continue
        out.append(tx[item["state"]].format(what=what, call=item.get("call_id"), reason=reason))
    return out + index_lines


def _same_host(a: Any, b: Any) -> bool:
    """Two sightings may be one artifact unless both name a host and the
    hosts differ: a volume the Evidence Links tie to no host, or a listing
    whose name carries none, is not on another host."""
    a, b = str(a or "").strip().casefold(), str(b or "").strip().casefold()
    return not a or not b or a == b


_EXTRACTED_RE: dict[str, re.Pattern[str]] = {}


def _examined_in_trace(item: dict[str, Any], blob: str) -> bool:
    """Has the run read this artifact?

    One known by name alone is read when its name appears in what the run
    did. One found on a mounted volume is read in place, by its path, or
    extracted under analysis/ or exports/ under its own name; its bare name
    is a common word there ("system", "software", "sam") that appears in
    any trace, so it proves nothing on its own. A listing row with its path
    in the image is read through that path (a mounted volume's, an
    extract's, a parser's argument, with either separator) or through a
    copy extracted under its own name.
    """
    name = str(item.get("name") or "").lower()
    path = str(item.get("path") or "").lower()
    lpath = str(item.get("lpath") or "").lower()
    # Every way below names the artifact, or the folder a family member is
    # read through: a text that holds neither has not read it.
    if not any(n and n in blob for n in [name, *(str(r).lower() for r in item.get("roots") or [])]):
        return False
    if lpath and not path:
        comps = [re.escape(c) for c in lpath.split("/") if c]
        # A folder row is read by any call under it.
        end = (r"(?=$|[\s\"',;)\]/\\])" if item.get("kind") == "directory"
               else r"[/\\]?(?=$|[\s\"',;)\]])")
        if comps and re.search(r"(?:^|[\s\"'=/\\])" + r"[/\\]+".join(comps) + end, blob):
            return True
        # ponytail: an unmounted image is read by extracting the file (icat
        # <image> <inode> exports/NTUSER.DAT) and parsing the copy, and no
        # call names the in-image path; the copy's name credits every row of
        # that name on the hosts the call names, or on every host when it
        # names none (high_value_state). Map the listing's entry number to the
        # icat inode, and a copy to the call that wrote it, when one profile's
        # or one host's copy must not stand for another's.
        return _extracted(name).search(blob) is not None
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
    return _extracted(name).search(blob) is not None


def _extracted(name: str) -> re.Pattern[str]:
    """A copy of ``name`` under analysis/ or exports/ named in a call."""
    pat = _EXTRACTED_RE.get(name)
    if pat is None:
        pat = re.compile(r"(?:analysis|exports)/[^\s\"']*" + re.escape(name)
                         + r"(?=$|[\s\"',;)])")
        _EXTRACTED_RE[name] = pat
    return pat


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
    try:
        from core.contents_index import find_by_names, index_on
        scoped = index_on()
    except Exception:  # noqa: BLE001
        scoped = False
    case_hosts = list(dict.fromkeys(_case_hosts(case_dir)))
    out: list[dict[str, Any]] = []
    for node in nodes:
        if not isinstance(node, dict):
            continue
        if node.get("status") in ("superseded", "withdrawn"):
            continue
        statement = str(node.get("statement") or "")
        if not _ABSENCE_RE.search(statement):
            continue
        # The claim's hosts: its host field or hosts list, else (with the
        # contents index) the case hosts its statement names.
        claim_hosts = [str(h).strip() for h in ([node.get("host")] + list(node.get("hosts") or []))
                       if str(h or "").strip()]
        if not claim_hosts and scoped:
            named = _hosts_in(statement, case_hosts)
            claim_hosts = [h for h in case_hosts if h.casefold() in named]
        claim_set = {h.casefold() for h in claim_hosts}
        for ent in extract(statement):
            if not ent.startswith("file:"):
                continue
            base = ent.split(":", 1)[1].lower()
            hits = [v for v in known.values()
                    if str(v.get("name") or "").lower() == base
                    and not looks_empty(v["name"], v.get("size"))]
            if scoped:
                # The index answers below the value threshold too: a text
                # log a statement calls absent is looked up on its host.
                seen = {(str(v.get("host") or "").casefold(), str(v.get("lpath") or "").lower()) for v in hits}
                for r in find_by_names(case_dir, [base], hosts=claim_hosts or None):
                    if r["name"].lower() != base or looks_empty(r["name"], r["size"]):
                        continue
                    if (str(r["host"] or "").casefold(), r["path"].lower()) in seen:
                        continue
                    hits.append({"name": r["name"], "size": r["size"], "host": r["host"] or "",
                                 "source": f"index:{r['origin']}", "path": "", "lpath": r["path"],
                                 "handle": r["handle"]})
            if not hits:
                continue
            if not _absent_target(statement, base):
                continue      # the file is where the search ran, not what is missing
            claim_host = claim_hosts[0] if len(claim_hosts) == 1 else ""
            if scoped and not claim_hosts and len(case_hosts) >= 2:
                # No host named in a case of several hosts: not a clash but
                # a proposal naming the hosts that hold the file.
                holders = sorted({str(h.get("host") or "") for h in hits} - {""})
                hit = hits[0]
                out.append({"claim_id": node.get("id"), "artifact": hit["name"], "size": hit.get("size"),
                            "indexed_by": hit.get("source", ""), "statement": statement[:220],
                            "host": "", "claim_host": "", "path": str(hit.get("path") or ""),
                            "hostless": True, "hosts": holders})
                if len(out) >= limit:
                    return out
                continue
            for hit in hits:
                # "No X on host A" is not contradicted by X existing on host B.
                # A false clash nudged turn after turn makes the model
                # supersede a correct claim just to silence it.
                hit_host = str(hit.get("host") or "").strip()
                if claim_set and hit_host and hit_host.casefold() not in claim_set:
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
                folder = hit.get("kind") == "directory" or bool(hit.get("is_dir"))
                score, _ = artifact_score(
                    (hit.get("path") or hit.get("lpath") or hit["name"]) if folder else hit["name"],
                    hit.get("size"), is_dir=folder)
                if score <= 0:
                    continue
                out.append({
                    "claim_id": node.get("id"),
                    "artifact": hit["name"],
                    "size": hit.get("size"),
                    "indexed_by": hit.get("source", ""),
                    "statement": statement[:220],
                    # Where the index saw it and the claim's own host: the
                    # work order reads it there (additive keys).
                    "host": claim_host or str(hit.get("host") or ""),
                    "claim_host": claim_host,
                    "path": str(hit.get("path") or ""),
                })
                break
            if len(out) >= limit:
                return out
    return out


def format_value_nudge(
    unexamined: Iterable[dict[str, Any]],
    contradictions: Iterable[dict[str, Any]] = (),
    *,
    view: str = "",
) -> str:
    """What the loop tells the model: read the valuable things, and stop
    asserting an absence the case itself disproves. ``view`` is the first
    host lines of the contents index's host-first view."""
    items = list(unexamined)
    clashes = list(contradictions)
    if not items and not clashes and not view:
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
        from core.deferred_intents import blocker_items_on
        lines.append(
            "[artifact value] These artifacts are present and unread, "
            "ordered by how much of the investigation they can answer. "
            "Enumeration order is not priority — work down this list. One "
            + ("you cannot read: run the read and let it fail, or leave it; the report lists it "
               "as not read:" if blocker_items_on() else
               "you cannot or need not read: state 'UNRESOLVABLE: <artifact> "
               "[<host>] — <why it is not read>' in reason.synthesize, and the "
               "report lists it with that reason:"))
        for a in items[:8]:
            size = a.get("size")
            if a.get("kind") == "directory":
                measure = f" ({size:,} file{'s' if size != 1 else ''})" if size else ""
            else:
                measure = f" ({size:,} bytes)" if size else ""
            where = a.get("path") or a.get("lpath")
            lines.append(
                f"- {a['name']}"
                + measure
                + (f" at {where}" if where else "")
                + (f" [{a['host']}]" if a.get("host") and not a.get("path") else "")
                + f" — {a['why']}")
    if view:
        lines.append("[artifact value] Unread inside the case's images, by host (the hosts the "
                     "questions and the brief name first; tsk.index_find reaches any other):")
        lines.append(view)
    return "\n".join(lines)
