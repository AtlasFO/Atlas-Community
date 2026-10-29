"""What each export of the case covers (ATLAS_EXPORT_PROFILE): its rows,
time span, hosts and parser kinds, the event-log channels it carries with
their event-id histogram, the sources it parsed, and per host the content
of the image listing it skipped.

The per-export aggregates are kept in ``.atlas/export_profile.json``
(written after each contents-index build); the per-source rows live in the
contents index (core.contents_index, table ``sources``) and are joined here.
An export with no profile row (an unknown format, the builder off) has none:
a consumer credits it and says the coverage is not profiled.
"""
from __future__ import annotations

import json
import os
from collections import Counter, defaultdict
from contextlib import closing
from pathlib import Path
from typing import Any

from core.envfile import env_flag

FILE_NAME = "export_profile.json"

# The value table's own textual rule (core.artifact_value: logs, text,
# delimited and structured files) plus event logs: the content an export of
# a host could have parsed. Format knowledge, not case knowledge.
_TEXTUAL_EXT = (".log", ".txt", ".csv", ".json", ".xml", ".evtx")


def profile_on() -> bool:
    try:
        from core.contents_index import index_on
        return index_on() and env_flag("ATLAS_EXPORT_PROFILE", True)
    except Exception:  # noqa: BLE001
        return False


def profile_path(case_dir: str | os.PathLike) -> Path:
    return Path(case_dir) / ".atlas" / FILE_NAME


def write_profiles(case_dir: str | os.PathLike) -> dict[str, Any]:
    """Rebuild ``.atlas/export_profile.json`` from the contents index's
    exports and sources: per export its rows, first and last time, hosts,
    kinds, channels with event-id counts and source count."""
    from core.contents_index import _connect
    con = _connect(case_dir)
    out: dict[str, Any] = {"exports": {}}
    if con is None:
        return out
    with closing(con):
        channels: dict[str, dict[str, Counter]] = defaultdict(lambda: defaultdict(Counter))
        nsources: Counter = Counter()
        for s in con.execute("SELECT export, channels FROM sources"):
            nsources[s[0]] += 1
            try:
                for ch, hist in (json.loads(s[1] or "{}") or {}).items():
                    channels[s[0]][ch].update({str(k): int(v) for k, v in (hist or {}).items()})
            except (TypeError, ValueError):
                continue
        for e in con.execute("SELECT * FROM exports"):
            path = e["path"]
            out["exports"][path] = {
                "path": path, "format": e["format"], "rows": e["rows"], "first": e["first"], "last": e["last"],
                "hosts": json.loads(e["hosts"] or "[]"), "kinds": json.loads(e["kinds"] or "{}"),
                "channels": {ch: dict(h.most_common()) for ch, h in channels[path].items()},
                "sources": nsources[path]}
    p = profile_path(case_dir)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(out, indent=1), encoding="utf-8")
    os.replace(tmp, p)
    return out


def _load(case_dir) -> dict[str, Any]:
    try:
        return json.loads(profile_path(case_dir).read_text(encoding="utf-8")).get("exports") or {}
    except (OSError, ValueError, AttributeError):
        return {}


def _rel(case_dir, export: str) -> str:
    from core.contents_index import _rel as rel
    return rel(Path(case_dir), export)


def _skipped(case_dir, export: str, hosts: list[str]) -> dict[str, list[dict[str, Any]]]:
    """Per host the export covers, the directories of textual or structured
    files in the image listing that none of its sources lies in, largest
    first: what the export skipped on a host it did parse."""
    from core.contents_index import _connect
    con = _connect(case_dir)
    if con is None:
        return {}
    out: dict[str, list[dict[str, Any]]] = {}
    with closing(con):
        covered: dict[str, set[str]] = defaultdict(set)
        for r in con.execute("SELECT s.host, e.path FROM sources s JOIN entries e ON e.id = s.entry_id "
                             "WHERE s.export = ? AND e.origin = 'image'", (export,)):
            covered[str(r[0] or "").casefold()].add(str(r[1]).rsplit("/", 1)[0].casefold())
        for host in hosts:
            key = str(host or "").casefold()
            if key not in covered:
                continue
            dirs: dict[str, list[int]] = {}
            for r in con.execute("SELECT path, size FROM entries WHERE host = ? COLLATE NOCASE AND origin = 'image' "
                                 "AND is_dir = 0 AND version_of IS NULL AND deleted = 0", (host,)):
                path = str(r[0])
                if not path.lower().endswith(_TEXTUAL_EXT) or "/" not in path:
                    continue
                d = path.rsplit("/", 1)[0]
                if d.casefold() in covered[key]:
                    continue
                acc = dirs.setdefault(d, [0, 0])
                acc[0] += 1
                acc[1] += int(r[1] or 0)
            rows = sorted(({"dir": d, "files": n, "bytes": b} for d, (n, b) in dirs.items()),
                          key=lambda x: (-x["bytes"], -x["files"]))
            if rows:
                out[host] = rows
    return out


def export_profile(case_dir: str | os.PathLike, export: str = "", host: str = "") -> dict[str, Any]:
    """One export's profile (``{}`` when it has none), or with no export
    ``{"exports": [...]}`` for every profiled export (on ``host`` when
    given). Each carries its skipped-content groups per host."""
    if not profile_on():
        return {} if export else {"exports": []}
    profiles = _load(case_dir)
    if export:
        p = profiles.get(_rel(case_dir, export)) or profiles.get(export)
        if not p:
            return {}
        p = dict(p)
        p["skipped"] = _skipped(case_dir, p["path"], [h for h in p.get("hosts") or [] if not host
                                                      or str(h).casefold() == host.casefold()])
        return p
    out = []
    for path, p in sorted(profiles.items()):
        if host and host.casefold() not in {str(h).casefold() for h in p.get("hosts") or []}:
            continue
        p = dict(p)
        p["skipped"] = _skipped(case_dir, path, [host] if host else list(p.get("hosts") or []))
        out.append(p)
    return {"exports": out}


def channel_ids(case_dir: str | os.PathLike, export: str) -> dict[str, set[str]] | None:
    """The event ids per channel an export carries, None when the export
    has no profile row."""
    p = export_profile(case_dir, export)
    if not p:
        return None
    return {ch: set(h) for ch, h in (p.get("channels") or {}).items()}


def inventory_lines(case_dir: str | os.PathLike, limit: int = 12) -> list[str]:
    """One line per export for the inventory result: host(s), rows, span,
    sources, top kinds."""
    lines = []
    exports = export_profile(case_dir).get("exports", [])
    for p in exports[:limit]:
        kinds = ", ".join(f"{k} {v}" for k, v in list((p.get("kinds") or {}).items())[:3])
        lines.append(f"{p['path']}: {', '.join(p.get('hosts') or []) or 'no host'}; {p.get('rows')} rows"
                     + (f" {p.get('first')} to {p.get('last')}" if p.get("first") else "")
                     + f"; {p.get('sources')} sources" + (f"; {kinds}" if kinds else ""))
    if len(exports) > limit:
        lines.append(f"+{len(exports) - limit} more exports (export_profile lists them)")
    return lines


def claim_event_ids(text: str) -> list[str]:
    """The event ids a claim names after an event cue ("event ids 4663 and
    4656", "event 4663", "EID 4624"): core.entities' one extractor."""
    from core.entities import event_ids
    return event_ids(text)


def _export_read(case_dir, entry: dict) -> str:
    """The export a call read: a profiled export its arguments or command
    name, whatever the tool (a text search over the export reads it as much
    as a table query does); else a table tool's path argument (an export
    with no profile row); "" for any other call."""
    blob = " ".join(str(entry.get(k) or "") for k in ("cmd", "args")).replace("\\", "/").casefold()
    if case_dir and blob.strip():
        named = [p for p in _load(case_dir) if p.casefold() in blob]
        if named:
            return max(named, key=len)
    tool = str(entry.get("mcp_tool") or entry.get("cmd") or "")
    if "table" not in tool:
        return ""
    from core.indicators import _parsed_args
    args, _keys = _parsed_args(entry)
    return str((args or {}).get("path") or "") if isinstance(args, dict) else ""


def export_covers(case_dir, entry: dict, channel_rx, event_ids: list[str]) -> tuple[bool | None, str]:
    """Whether a call that matched an event-log source counts as a search
    of it: ``(True, "")`` for a read of the log itself or an export whose
    profile carries the channel and every named event id; ``(False, why)``
    for an export that does not; ``(None, advisory)`` for an export with no
    profile row (credited, with the advisory)."""
    export = _export_read(case_dir, entry)
    if not export or not profile_on():
        return True, ""
    prof = channel_ids(case_dir, export)
    if prof is None:
        return None, (f"coverage of {export} is not profiled; a filtered export may not carry what this claim "
                      "says is absent; read the log itself to settle it.")
    chans = [ch for ch in prof if channel_rx.search(ch) or channel_rx.search(ch.replace("/", "%4") + ".evtx")]
    if not chans:
        return False, f"{export} carries no rows of that log"
    have = set().union(*(prof[ch] for ch in chans))
    lacking = [i for i in event_ids if i not in have]
    if not lacking:
        return True, ""
    shown = sorted(have, key=lambda x: int(x) if x.isdigit() else 0)[:12]
    return False, (f"{export} carries from {', '.join(chans)} only event ids {', '.join(shown)} (export "
                   f"profile); the claim's ids {', '.join(lacking)} are not in it, so the export is silent about them")
