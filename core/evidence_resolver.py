"""Deterministic evidence resolution for forensic report findings.

Provenance-first order (never silent heuristic as direct evidence):

1. Direct ``record_ref`` / unique event reference → exact Timeline / tool row
2. ``call_id`` → exact tool output (evidence_index / trace); Timeline only if
   the link is deterministic
3. Artifact + locator → exact normalized/raw tool output
4. Controlled correlation (host + timestamp + attributes) only when no
   explicit provenance — **labeled** ``correlated``, never as direct support
5. If unresolved: explicit note + retain source/trace refs (no nearby guess)

Representative selection is claim-aware (homogeneous vs multi-component).
Raw lines are copied from artifacts only — never invented or paraphrased.
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable

from core.input_kind import open_text
from core.auth_ontology import (
    WINDOWS_AUTH_BRUTE_EIDS,
    WINDOWS_AUTH_FAILURE_EIDS,
    WINDOWS_AUTH_RELATED_EIDS,
    eid_alt,
)

SCHEMA_VERSION = "1.0"

_HOMOGENEOUS_MAX_SHOW = 6
_HOMOGENEOUS_THRESHOLD = 12
_COMPONENT_MAX = 4

_RECORD_REF_RE = re.compile(
    r"(?i)\b(?:record_ref|evidence_reference|event_ref)\s*[:=]\s*"
    r"([^\s,;\"']+)"
)
_CALL_ID_RE = re.compile(r"(?i)\bcall[_ ]?id\s*[=:]?\s*(\d+)\b")
_LINE_RE = re.compile(r"(?i)\bline\s*[:=]?\s*(\d+)\b")
# Case-relative forensic paths cited in findings / supporting_evidence.
_CASE_PATH_RE = re.compile(
    r"(?i)\b((?:evidence|analysis)/[A-Za-z0-9_./\-]+\."
    r"(?:csv|tsv|txt|json|jsonl|log|evtx))\b"
)
_SOURCE_FILE_RE = re.compile(
    r"(?i)(?:Source File|artifact)\s*[:=]\s*"
    r"((?:evidence|analysis)/[A-Za-z0-9_./\-]+|"
    r"[A-Za-z0-9_.\-]+\.(?:csv|tsv|txt|json|log))"
)
# Only joiners used in compound citations — never ``/`` (path separator).
_COMPOUND_SPLIT_RE = re.compile(
    r"\s*(?:\+|\band\b)\s*",
    re.I,
)

_COMPONENT_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("rdp_access", re.compile(
        r"(?i)\b(?:RDP|remote\s+desktop|logon\s+type\s*10|T1133)\b")),
    ("authentication", re.compile(
        rf"(?i)\b(?:{eid_alt(WINDOWS_AUTH_RELATED_EIDS)}|Kerberos|NTLM|logon|authenticat)\b")),
    ("lateral_movement", re.compile(
        r"(?i)\b(?:lateral|SMB|admin\s+share|T1021|network\s+logon|"
        r"logon\s+type\s*3)\b")),
    ("execution", re.compile(
        r"(?i)\b(?:execut|PowerShell|cmd\.exe|process\s+creation|T1059)\b")),
    ("malware_detection", re.compile(
        r"(?i)\b(?:Defender|malware|ransom|Trojan|detection|1116|1117)\b")),
    ("encryption", re.compile(
        r"(?i)\b(?:encrypt|ransom(?:ware)?\s+file|T1486)\b")),
    ("credential_access", re.compile(
        r"(?i)\b(?:credential|LSASS|DCSync|T1003|mimikatz)\b")),
    ("persistence", re.compile(
        r"(?i)\b(?:scheduled\s+task|persistence|Run\s+key|T1053|T1547)\b")),
    ("brute_force", re.compile(
        r"(?i)\b(?:brute.?force|password\s+spray|spray|T1110|"
        r"wrong\s+password|4776)\b")),
]

# Locator substrings that widen the artifact scan (see "3) Artifact +
# locator" below) — brute-force/auth-failure evidence needs more lines
# scanned to catch repeated failed-logon entries. EIDs sourced from
# auth_ontology, not hardcoded here, so this can't silently drift out of
# sync with the canonical list the way it once did.
_AUTH_WIDEN_LOCATOR_TOKENS: tuple[str, ...] = (
    ("spray", "brute") + WINDOWS_AUTH_FAILURE_EIDS + WINDOWS_AUTH_BRUTE_EIDS
)


@dataclass
class EvidenceEvent:
    text: str
    source: str = ""
    line: int | None = None
    record_ref: str = ""
    call_id: int | None = None
    component: str = ""
    provenance: str = "direct"  # direct | correlated | unresolved_ref
    timestamp: str = ""
    host: str = ""
    # How much of the claim this record carries: 0 = nothing in common,
    # 1 = a date or address, ≥2 = a timestamp, identifier or event id.
    relevance: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class EvidencePack:
    node_id: str = ""
    events: list[EvidenceEvent] = field(default_factory=list)
    observed_count: int | None = None
    timeframe_start: str = ""
    timeframe_end: str = ""
    unresolved_note: str = ""
    retained_refs: list[str] = field(default_factory=list)
    selection_mode: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "node_id": self.node_id,
            "events": [e.to_dict() for e in self.events],
            "observed_count": self.observed_count,
            "timeframe_start": self.timeframe_start,
            "timeframe_end": self.timeframe_end,
            "unresolved_note": self.unresolved_note,
            "retained_refs": list(self.retained_refs),
            "selection_mode": self.selection_mode,
        }


def _case_root(case_dir: str | os.PathLike) -> Path:
    return Path(case_dir).resolve()


def _evidence_index_path(case_dir: Path) -> Path:
    return case_dir / "analysis" / "evidence_index.db"


def _trace_paths(case_dir: Path) -> list[Path]:
    analysis = case_dir / "analysis"
    if not analysis.is_dir():
        return []
    return sorted(
        analysis.glob("*_trace.json"),
        key=lambda p: p.stat().st_mtime,
    )


def _load_trace_by_call_id(case_dir: Path, call_id: int) -> dict[str, Any] | None:
    for tp in _trace_paths(case_dir):
        try:
            data = json.loads(tp.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        for e in data.get("entries") or []:
            if e.get("call_id") == call_id:
                return e
    return None


def _windows_for_call_id(
    case_dir: Path, call_id: int, *, limit: int = 40,
) -> list[dict[str, Any]]:
    db = _evidence_index_path(case_dir)
    if not db.is_file():
        return []
    try:
        conn = sqlite3.connect(str(db), timeout=10.0)
        rows = conn.execute(
            "SELECT s.call_id, s.tool, s.source_path, w.line_start, "
            "w.line_end, w.event_time, w.raw_text "
            "FROM sources s JOIN windows w ON w.source_id = s.source_id "
            "WHERE s.call_id = ? ORDER BY w.line_start LIMIT ?",
            (int(call_id), max(1, limit)),
        ).fetchall()
        conn.close()
    except sqlite3.Error:
        return []
    return [
        {
            "call_id": r[0],
            "tool": r[1],
            "source_path": r[2],
            "line_start": r[3],
            "line_end": r[4],
            "event_time": r[5],
            "raw_text": r[6],
        }
        for r in rows
    ]


# Parsed timeline per file, keyed by path and stamped with the file's size
# and mtime. The events are read once per report: every claim's resolution
# used to parse the whole file again, and with a large events.jsonl the
# exit-time report assembly took most of an hour and gigabytes of memory.
_TIMELINE_CACHE: dict[str, tuple[int, int, list[dict[str, Any]]]] = {}
# Every event field the resolver reads (see _event_from_timeline,
# _find_timeline_by_record_ref and the correlation loops).
_EVENT_FIELDS = ("timestamp", "host", "user", "event_type", "title", "description",
                 "source_artifact", "source_identifier", "evidence_reference",
                 "record_ref", "facts", "line", "call_id", "call_ids", "artifacts",
                 "record_refs", "event", "machine", "source_label", "original_tool")


def _load_jsonl_cached(path: Path) -> list[dict[str, Any]]:
    try:
        st = path.stat()
    except OSError:
        return []
    key = str(path)
    hit = _TIMELINE_CACHE.get(key)
    if hit and hit[0] == st.st_mtime_ns and hit[1] == st.st_size:
        return hit[2]
    out: list[dict[str, Any]] = []
    intern: dict[str, str] = {}

    def _compact(ev: dict) -> dict:
        # Only the fields the resolver reads, with the values that repeat
        # across hundreds of thousands of events (host, user, type, source)
        # shared instead of copied; copied, they cost gigabytes.
        slim = {}
        for k in _EVENT_FIELDS:
            v = ev.get(k)
            if v is None:
                continue
            if isinstance(v, str) and len(v) <= 80:
                v = intern.setdefault(v, v)
            slim[k] = v
        return slim
    try:
        with path.open(encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(ev, dict):
                    out.append(_compact(ev))
    except OSError:
        return []
    _TIMELINE_CACHE.clear()          # one timeline per process is plenty
    _TIMELINE_CACHE[key] = (st.st_mtime_ns, st.st_size, out)
    return out


def _timeline_events_jsonl(case_dir: Path) -> list[dict[str, Any]]:
    candidates = [
        case_dir / "reports" / ".timeline_build" / "events.jsonl",
        case_dir / "analysis" / ".timeline_build" / "events.jsonl",
    ]
    reports = case_dir / "reports"
    if reports.is_dir():
        for p in reports.rglob("events.jsonl"):
            if ".timeline_build" in str(p):
                candidates.append(p)
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for path in candidates:
        key = str(path)
        if not path.is_file() or key in seen:
            continue
        seen.add(key)
        out = _load_jsonl_cached(path)
        if out:
            break
    if out:
        return out
    # Fallback: master_timeline.tsv (with optional Line / RecordRef columns)
    return _timeline_events_from_tsv(case_dir)


def _timeline_events_from_tsv(case_dir: Path) -> list[dict[str, Any]]:
    candidates = [
        case_dir / "analysis" / "master_timeline.tsv",
        case_dir / "reports" / "master_timeline.tsv",
        case_dir / "exports" / "master_timeline.tsv",
    ]
    for path in candidates:
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rows = text.splitlines()
        if len(rows) < 2:
            continue
        header = [h.strip() for h in rows[0].split("\t")]
        idx = {h.lower(): i for i, h in enumerate(header)}

        def _col(parts: list[str], *names: str) -> str:
            for name in names:
                i = idx.get(name.lower())
                if i is not None and i < len(parts):
                    return parts[i]
            return ""

        out: list[dict[str, Any]] = []
        for row in rows[1:]:
            if not row.strip():
                continue
            parts = row.split("\t")
            line_s = _col(parts, "Line", "line")
            line_n = None
            if line_s:
                try:
                    line_n = int(line_s)
                except ValueError:
                    pass
            ref = _col(parts, "RecordRef", "record_ref")
            facts: dict[str, Any] = {}
            if line_n is not None:
                facts["line"] = line_n
            out.append({
                "timestamp": _col(parts, "Timestamp", "timestamp"),
                "host": _col(parts, "Machine", "host"),
                "user": _col(parts, "User", "user"),
                "title": _col(parts, "Event", "title", "event"),
                "source_artifact": _col(parts, "Source", "source"),
                "description": _col(parts, "Description", "description"),
                "record_ref": ref,
                "facts": facts,
            })
        if out:
            return out
    return []


def _find_timeline_by_record_ref(
    events: list[dict[str, Any]], record_ref: str,
) -> dict[str, Any] | None:
    if not record_ref:
        return None
    for ev in events:
        if (ev.get("record_ref") or "") == record_ref:
            return ev
        if (ev.get("evidence_reference") or "") == record_ref:
            return ev
        if (ev.get("source_identifier") or "") == record_ref:
            return ev
        facts = ev.get("facts") or {}
        if isinstance(facts, dict) and str(facts.get("record_ref") or "") == record_ref:
            return ev
    return None


def _format_timeline_event(ev: dict[str, Any]) -> str:
    parts = [
        ev.get("timestamp") or ev.get("Timestamp") or "",
        ev.get("host") or ev.get("Machine") or "",
        ev.get("user") or ev.get("User") or "",
        ev.get("title") or ev.get("Event") or ev.get("event_type") or "",
        ev.get("source_artifact") or ev.get("Source") or "",
        (ev.get("description") or ev.get("Description") or "").replace("\n", " "),
    ]
    return "\t".join(str(p) for p in parts)


def _event_from_timeline(
    ev: dict[str, Any], *, provenance: str = "direct", component: str = "",
) -> EvidenceEvent:
    line = None
    facts = ev.get("facts") if isinstance(ev.get("facts"), dict) else {}
    if facts.get("line") is not None:
        try:
            line = int(facts["line"])
        except (TypeError, ValueError):
            pass
    src = ev.get("source_artifact") or ev.get("Source") or "master_timeline.tsv"
    ref = (
        ev.get("record_ref")
        or ev.get("RecordRef")
        or ev.get("evidence_reference")
        or ""
    )
    return EvidenceEvent(
        text=_format_timeline_event(ev),
        source=str(src),
        line=line,
        record_ref=str(ref),
        component=component,
        provenance=provenance,
        timestamp=str(ev.get("timestamp") or ev.get("Timestamp") or ""),
        host=str(ev.get("host") or ev.get("Machine") or ""),
    )


def _extract_refs_from_node(node: dict[str, Any]) -> dict[str, Any]:
    record_refs: list[str] = []
    call_ids: list[int] = []
    artifacts: list[dict[str, Any]] = []

    def _add_call(c: Any) -> None:
        try:
            ci = int(c)
        except (TypeError, ValueError):
            return
        if ci and ci not in call_ids:
            call_ids.append(ci)

    for cid in node.get("input_call_ids") or []:
        _add_call(cid)
    # Do NOT treat source_finding_call_id (the misc.record_finding call) as
    # evidence provenance — it never resolves to forensic events and pollutes
    # Attack Timeline readiness with empty/banner windows.

    for item in node.get("evidence") or []:
        if not isinstance(item, dict):
            continue
        if item.get("call_id"):
            _add_call(item["call_id"])
        art = str(item.get("artifact") or "")
        loc = str(item.get("locator") or "")
        blob = f"{art} {loc}"
        for m in _RECORD_REF_RE.finditer(blob):
            record_refs.append(m.group(1))
        if ":" in loc and not loc.startswith("call_id"):
            if re.search(r"\.\w{2,5}:\d+", loc) or loc.count(":") >= 2:
                if loc not in record_refs:
                    record_refs.append(loc)
        for m in _CALL_ID_RE.finditer(blob):
            _add_call(m.group(1))
        if art and art not in ("supporting_evidence", "trace_call", "timeline"):
            lm = _LINE_RE.search(loc)
            # Compound ``A.csv + B.csv`` → one artifact entry per file
            for part in split_artifact_names(art) or [art]:
                artifacts.append({
                    "artifact": part,
                    "locator": loc,
                    "call_id": item.get("call_id"),
                    "line": lm.group(1) if lm else None,
                })
        elif art == "supporting_evidence" and loc:
            for m in _RECORD_REF_RE.finditer(loc):
                record_refs.append(m.group(1))
            # Persist path citations from prose into resolvable artifact refs.
            lm = _LINE_RE.search(loc)
            for path in extract_case_paths_from_text(loc):
                artifacts.append({
                    "artifact": path,
                    "locator": loc[:500],
                    "call_id": item.get("call_id"),
                    "line": lm.group(1) if lm else None,
                })

    seen: set[str] = set()
    uniq_refs = []
    for r in record_refs:
        if r not in seen:
            seen.add(r)
            uniq_refs.append(r)

    return {
        "record_refs": uniq_refs,
        "call_ids": call_ids,
        "artifacts": artifacts,
    }


def _detect_components(node: dict[str, Any]) -> list[str]:
    text = " ".join([
        str(node.get("statement") or ""),
        str(node.get("reasoning") or ""),
    ])
    hits = [name for name, rx in _COMPONENT_PATTERNS if rx.search(text)]
    return hits or ["general"]


def _is_homogeneous(components: list[str], event_count: int) -> bool:
    if event_count < _HOMOGENEOUS_THRESHOLD:
        return False
    if components == ["brute_force"]:
        return True
    if len(components) == 1 and components[0] in (
        "brute_force", "authentication", "lateral_movement",
    ):
        return True
    return len(components) == 1


def _select_homogeneous(events: list[EvidenceEvent]) -> list[EvidenceEvent]:
    if len(events) <= _HOMOGENEOUS_MAX_SHOW:
        return events
    n = len(events)
    idxs = {0, n - 1}
    mid_count = min(4, _HOMOGENEOUS_MAX_SHOW - 2)
    for i in range(mid_count):
        idxs.add(1 + int((n - 2) * (i + 1) / (mid_count + 1)))
    return [events[i] for i in sorted(idxs)]


def _select_multi_component(
    events: list[EvidenceEvent], components: list[str],
) -> list[EvidenceEvent]:
    by_comp: dict[str, list[EvidenceEvent]] = {c: [] for c in components}
    unlabeled: list[EvidenceEvent] = []
    for ev in events:
        c = ev.component or "general"
        if c in by_comp:
            by_comp[c].append(ev)
        else:
            unlabeled.append(ev)
    out: list[EvidenceEvent] = []
    pat = dict(_COMPONENT_PATTERNS)
    for c in components:
        chunk = by_comp.get(c) or []
        if not chunk and unlabeled:
            rx = pat.get(c)
            matched = (
                [e for e in unlabeled if rx and rx.search(e.text)]
                if rx else []
            )
            chunk = matched or unlabeled[:_COMPONENT_MAX]
            used = {id(e) for e in chunk}
            unlabeled = [e for e in unlabeled if id(e) not in used]
        out.extend(chunk[:_COMPONENT_MAX])
    if not out:
        return events[:_HOMOGENEOUS_MAX_SHOW]
    seen: set[str] = set()
    deduped = []
    for e in out:
        key = e.text[:200]
        if key in seen:
            continue
        seen.add(key)
        deduped.append(e)
    return deduped


def _rel_source(case_dir: Path, path: Path) -> str:
    try:
        return str(path.relative_to(case_dir))
    except ValueError:
        return str(path)


def split_artifact_names(artifact: str) -> list[str]:
    """Split compound citations like ``A.csv + B.csv`` into path parts."""
    raw = (artifact or "").strip()
    if not raw:
        return []
    # Strip wrapper labels that are not paths
    if raw in ("supporting_evidence", "trace_call", "timeline"):
        return []
    parts = [
        p.strip().strip("'\"")
        for p in _COMPOUND_SPLIT_RE.split(raw)
        if p and p.strip()
    ]
    # Drop empty / operator-only fragments
    out = [p for p in parts if p and p not in ("+", "and", "/")]
    return out or ([raw] if raw else [])


def extract_case_paths_from_text(text: str) -> list[str]:
    """Pull ``evidence/…`` / ``analysis/…`` paths from free-form citations."""
    blob = text or ""
    found: list[str] = []
    for rx in (_CASE_PATH_RE, _SOURCE_FILE_RE):
        for m in rx.finditer(blob):
            p = m.group(1).strip().rstrip(").,;")
            if p and p not in found:
                found.append(p)
    return found


def resolve_artifact_path(case_dir: Path, artifact: str) -> Path | None:
    """Locate an artifact under the case (evidence/ + analysis/, not analysis-only)."""
    raw = (artifact or "").strip().strip("'\"")
    if not raw or raw in ("supporting_evidence", "trace_call", "timeline"):
        return None
    path = Path(raw)
    if path.is_file():
        return path
    cand = case_dir / raw
    if cand.is_file():
        return cand
    # Strip leading ./ 
    if raw.startswith("./"):
        cand = case_dir / raw[2:]
        if cand.is_file():
            return cand
    name = Path(raw).name
    if not name:
        return None
    for sub in ("evidence", "analysis"):
        root = case_dir / sub
        if not root.is_dir():
            continue
        # Prefer shallow exact relative match
        direct = root / raw.split("/", 1)[-1] if "/" in raw else root / name
        if direct.is_file():
            return direct
        try:
            hits = sorted(root.rglob(name))
        except OSError:
            hits = []
        if hits:
            # Prefer paths that contain more of the original relative hint
            hint = raw.lower().replace("\\", "/")
            hits.sort(
                key=lambda p: (
                    0 if hint in str(p).lower().replace("\\", "/") else 1,
                    len(str(p)),
                )
            )
            return hits[0]
    return None


def _read_one_artifact_file(
    case_dir: Path,
    path: Path,
    *,
    line_no: int | None = None,
    locator: str = "",
    max_lines: int = 20,
) -> list[EvidenceEvent]:
    try:
        if line_no and line_no > 0:
            with open_text(path) as f:
                for i, row in enumerate(f, start=1):
                    if i == line_no:
                        return [EvidenceEvent(
                            text=row.rstrip("\n"),
                            source=_rel_source(case_dir, path),
                            line=i,
                            provenance="direct",
                        )]
                    if i > line_no:
                        break
            return []

        token = (locator or "").strip()
        if not token or token.startswith("call_id"):
            return []
        tokens = [t for t in re.split(r"[\s,;|]+", token) if len(t) >= 6][:6]
        # Prefer forensic tokens (IPs, event ids, account-ish) over filler
        if not tokens:
            return []

        found: list[EvidenceEvent] = []
        with open_text(path) as f:
            for i, row in enumerate(f, start=1):
                if any(t in row for t in tokens):
                    found.append(EvidenceEvent(
                        text=row.rstrip("\n"),
                        source=_rel_source(case_dir, path),
                        line=i,
                        provenance="direct",
                    ))
                    if len(found) >= max_lines:
                        break
        return found
    except OSError:
        return []


def _read_artifact_lines(
    case_dir: Path,
    artifact: str,
    *,
    line_no: int | None = None,
    locator: str = "",
    max_lines: int = 20,
) -> list[EvidenceEvent]:
    names = split_artifact_names(artifact)
    if not names and artifact:
        names = extract_case_paths_from_text(artifact)
    if not names:
        return []
    out: list[EvidenceEvent] = []
    per = max(1, max_lines // max(1, len(names)))
    for name in names:
        local_line = line_no
        file_name = name
        m = re.search(r":(\d+)$", name)
        if m and local_line is None:
            try:
                local_line = int(m.group(1))
                file_name = name[: m.start()]
            except ValueError:
                pass
        path = resolve_artifact_path(case_dir, file_name)
        if path is None:
            continue
        out.extend(_read_one_artifact_file(
            case_dir, path,
            line_no=local_line,
            locator=locator,
            max_lines=per,
        ))
        if len(out) >= max_lines:
            break
    return out[:max_lines]


def _resolve_call_id(
    case_dir: Path, call_id: int, *, component: str = "",
) -> list[EvidenceEvent]:
    from core.evidence_noise import is_tool_metadata_text, is_weak_timeline_event_text

    events: list[EvidenceEvent] = []
    windows = _windows_for_call_id(case_dir, call_id, limit=30)
    preferred: list[EvidenceEvent] = []
    fallback: list[EvidenceEvent] = []
    for w in windows:
        raw = (w.get("raw_text") or "").strip()
        if not raw or is_tool_metadata_text(raw):
            continue
        src = w.get("source_path") or f"evidence_index call_id={call_id}"
        # A window is several records. Judged as one blob, any record's
        # match carried every other record in it into the finding — an MFT
        # row about a stranger's encrypted file rode into the account
        # finding on the line beneath it. One event per record.
        start = w.get("line_start")
        rows = [ln for ln in raw.splitlines() if ln.strip()][:12] or [raw]
        for i, text in enumerate(rows):
            if len(text) > 2000:
                text = text[:2000] + " …"
            ev = EvidenceEvent(
                text=text,
                source=str(src),
                line=(start + i) if isinstance(start, int) else start,
                call_id=call_id,
                component=component,
                provenance="direct",
                timestamp=str(w.get("event_time") or "") if i == 0 else "",
            )
            if is_weak_timeline_event_text(text):
                fallback.append(ev)
            else:
                preferred.append(ev)
    events = preferred or fallback
    if events:
        return events[:24]

    entry = _load_trace_by_call_id(case_dir, call_id)
    if not entry:
        return []
    spill = entry.get("stdout_spill") or entry.get("spill_path") or ""
    if spill:
        sp = Path(spill)
        if not sp.is_file():
            sp = case_dir / spill
        if sp.is_file():
            try:
                raw = sp.read_text(encoding="utf-8", errors="replace")
                lines = [
                    ln for ln in raw.splitlines()
                    if ln.strip() and not is_tool_metadata_text(ln)
                    and not is_weak_timeline_event_text(ln)
                ][:8]
                if not lines:
                    lines = [
                        ln for ln in raw.splitlines()
                        if ln.strip() and not is_tool_metadata_text(ln)
                    ][:8]
                if lines:
                    return [EvidenceEvent(
                        text=ln[:2000],
                        source=str(spill),
                        line=i + 1,
                        call_id=call_id,
                        component=component,
                        provenance="direct",
                    ) for i, ln in enumerate(lines)]
            except OSError:
                pass
    excerpt = (entry.get("stdout_excerpt") or "").strip()
    if excerpt and not is_tool_metadata_text(excerpt):
        rows = [ln for ln in excerpt.splitlines()
                if ln.strip() and not is_tool_metadata_text(ln)][:12] or [excerpt]
        return [EvidenceEvent(
            text=ln[:2000],
            source=f"trace call_id={call_id}",
            line=i + 1,
            call_id=call_id,
            component=component,
            provenance="direct",
        ) for i, ln in enumerate(rows)]
    return []


def _supporting_evidence_prose_events(
    node: dict[str, Any],
    *,
    max_events: int = 8,
) -> list[EvidenceEvent]:
    """Turn supporting_evidence locator prose into direct cited text events.

    A line the finding tool cited itself carries a mark saying so; the
    finding keeps it, the citation a reader sees does not."""
    from core.forensic_citation import strip_machine_citation_mark
    out: list[EvidenceEvent] = []
    for item in node.get("evidence") or []:
        if not isinstance(item, dict):
            continue
        if str(item.get("artifact") or "") != "supporting_evidence":
            continue
        loc = strip_machine_citation_mark(str(item.get("locator") or "")).strip()
        if len(loc) < 24:
            continue
        # Keep a few substantive lines / chunks — never invent content.
        chunks = [c.strip() for c in re.split(r"[\n;]+", loc) if len(c.strip()) >= 20]
        if not chunks:
            chunks = [loc[:800]]
        for ch in chunks[:max_events]:
            out.append(EvidenceEvent(
                text=ch[:1200],
                source="supporting_evidence",
                call_id=item.get("call_id"),
                component="general",
                provenance="direct",
            ))
        if out:
            break
    return out[:max_events]


def _controlled_correlation(
    case_dir: Path,
    node: dict[str, Any],
    *,
    components: list[str],
) -> list[EvidenceEvent]:
    host = (node.get("host") or "").strip().lower()
    stmt = (node.get("statement") or "") + " " + (node.get("reasoning") or "")
    ips = re.findall(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
        stmt,
    )
    if not host and not ips:
        return []

    tl_events = _timeline_events_jsonl(case_dir)
    if not tl_events:
        return []

    matched: list[EvidenceEvent] = []
    pat = dict(_COMPONENT_PATTERNS)
    for ev in tl_events:
        ev_host = (ev.get("host") or "").lower()
        desc = (ev.get("description") or "") + " " + (ev.get("title") or "")
        host_ok = (not host) or (host in ev_host) or (ev_host and ev_host in host)
        ip_ok = (not ips) or any(ip in desc for ip in ips)
        if host and not host_ok:
            continue
        comp_hit = ""
        for c in components:
            rx = pat.get(c)
            if rx and rx.search(desc + " " + stmt):
                comp_hit = c
                break
        if not comp_hit and not ip_ok:
            continue
        matched.append(_event_from_timeline(
            ev, provenance="correlated", component=comp_hit or "general",
        ))
        if len(matched) >= 20:
            break
    return matched


_ANCHOR_DATE_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}\b")
_ANCHOR_TIME_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}(?::\d{2})?")
_ANCHOR_IP_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
_ANCHOR_SID_RE = re.compile(r"\bS-1-5-21(?:-\d+){3,4}\b")
# "Event ID 4624", "event 4624" and the analyst's shorthand "EID 4624".
_ANCHOR_EVENT_RE = re.compile(
    r"(?i)\b(?:event\s*(?:id)?|eid)\s*[:#]?\s*(\d{3,5})\b")
_ANCHOR_HASH_RE = re.compile(r"\b(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})\b", re.I)
# A name introduced by what it is: "process svc.exe", "account jdoe". Cues
# chain ("the service binary svc.exe" names svc.exe, not "binary"), and a cue
# followed by grammar rather than a name ("the service were both deployed")
# names nothing - those words are stopped below, or every finding phrased
# that way rests on an "identifier" no tool output can contain.
# A malware class noun introduces a family or tool name the same way
# "account" introduces a principal ("the beacon Cobalt Strike", "trojan
# Emotet"): the name is then something a scanner or a lookup would have
# printed, and a finding that rests on it is asked to cite that output.
_ANCHOR_NAME_RE = re.compile(
    r"(?i)(?:(?:account|user|principal|named?|file|process|binary|executable|"
    r"driver|service|malware|implant|beacon|trojan|backdoor|loader|stealer|"
    r"ransomware|rootkit|toolkit|framework|family)\s+)+"
    r"['\"`]?([A-Za-z][\w.$-]{3,63}(?:\.\w{2,4})?)")
# DOMAIN\name only — a NetBIOS domain, one backslash, a principal, and no
# further path. Matching "anything after a backslash" turned every segment
# of a cited path (\shares\all\USERS\…) into an "anchor", so an MFT row
# from a share matched a finding about an account because both said USERS.
_ANCHOR_QUAL_RE = re.compile(
    r"(?<![\\\w])[A-Z][A-Z0-9-]{1,15}\\+([A-Za-z][\w.$-]{2,63})(?![\\\w.])")
# Words that name places every Windows system has, not things in this case.
_ANCHOR_STOP = frozenset({
    "users", "user", "shares", "share", "downloads", "documents", "desktop",
    "windows", "system32", "temp", "public", "programdata", "appdata",
    "local", "roaming", "microsoft", "file", "files", "folder", "directory",
    "root", "creation", "created", "account", "accounts", "logon", "host",
    # Atlas's own case layout and the signer name on every Windows binary:
    # a finding that mentions its own output path or "Microsoft Corporation"
    # is not anchored on them.
    "analysis", "exports", "reports", "evidence", "cases", "home", "mnt",
    "tool-output", "corporation", "inc",
    # Grammar that follows a name cue in prose ("the service were", "the
    # file that", "process running"): not names, so never anchors.
    "were", "been", "being", "that", "this", "these", "those", "which",
    "with", "from", "into", "onto", "over", "under", "both", "each", "also",
    "then", "than", "only", "name", "named", "names", "running", "listed",
    "shown", "found", "present", "absent", "observed", "seen", "installed",
    "started", "stopped", "launched", "executed", "executing", "deleted",
    "modified", "accessed", "hosted", "called", "known", "whose", "where",
    "when", "while", "after", "before", "during", "between", "against",
    "principal", "binary", "executable", "driver", "service", "services",
    "process", "processes", "image", "path", "entry", "record", "object",
    "throughout", "within", "across", "using", "used", "still", "already",
    "later", "earlier", "again", "itself", "themselves", "here", "there",
    # Generic nouns a malware-class cue is followed by in prose ("beacon
    # deployment", "malware family", "trojan sample"): what kind of thing
    # it is, not which one.
    "deployment", "timeline", "activity", "traffic", "sample", "samples",
    "payload", "variant", "family", "families", "campaign", "infrastructure",
    "operator", "actor", "actors", "attribution", "detected", "identified",
    "attributable", "malware", "implant", "beacon", "trojan", "backdoor",
    "loader", "stealer", "ransomware", "rootkit", "toolkit", "framework",
    "infection", "execution", "persistence", "behaviour", "behavior",
})
# An OS or product build ("6.3.9600", "10.0.19041") is as checkable as a
# date: a finding that quotes one the cited output never printed has made
# it up. Not the tail of an address: "61.24.102" inside "194.61.24.102" is
# the address, already anchored whole, and no output prints the tail alone.
_ANCHOR_VERSION_RE = re.compile(
    r"(?<![\d.])\d{1,2}\.\d{1,2}\.\d{3,6}(?:\.\d{1,6})?(?![\d.])")
# A name a tool could have printed as an identifier: it carries a digit, a
# dot, an underscore, a dollar, a hyphen, a backslash or a capital
# ("svc_update.exe", "Administrator", "S-1-5-..."). A plain lower-case word
# after a cue ("process migration", "account throughout") is prose the cue
# grammar could not tell from a name; it may still satisfy a citation when
# the output happens to print it, but its absence is no ground to refuse
# one - nothing forensic ever prints "throughout".
_IDENTIFIER_SHAPE_RE = re.compile(r"[\d._$\\-]|^[A-Z]")


def _case_path_words() -> set[str]:
    """Segments of the active case's own path (its name, its parents)."""
    try:
        from core.paths import active_case_dir
        case = active_case_dir()
    except Exception:  # noqa: BLE001
        return set()
    if not case:
        return set()
    return {p.lower() for p in str(case).replace("\\", "/").split("/") if len(p) >= 3}


def _claim_anchors(node: dict[str, Any], *, demanding: bool = False) -> set[str]:
    """Identifiers a claim rests on: dates, IPs, SIDs, event ids, hashes,
    builds, named accounts/files. Lower-cased.

    With ``demanding`` only the identifiers whose absence from a cited
    output can count against the citation: the typed ones and the names
    shaped like identifiers (_IDENTIFIER_SHAPE_RE). Every anchor can still
    satisfy a citation; a plain word after a name cue cannot demand one.
    """
    text = " ".join(str(node.get(k) or "") for k in ("statement", "reasoning"))
    out: set[str] = set()
    for rx in (_ANCHOR_DATE_RE, _ANCHOR_IP_RE, _ANCHOR_SID_RE, _ANCHOR_HASH_RE,
               _ANCHOR_VERSION_RE):
        out.update(m.group(0).lower() for m in rx.finditer(text))
    # "2031-02-04T10:54:25" and "2031-02-04 10:54:25" are one moment.
    out.update(m.group(0).lower().replace("t", " ")
               for m in _ANCHOR_TIME_RE.finditer(text))
    out.update(m.group(1) for m in _ANCHOR_EVENT_RE.finditer(text))
    for rx in (_ANCHOR_NAME_RE, _ANCHOR_QUAL_RE):
        for m in rx.finditer(text):
            name = m.group(1).rstrip(".,;:")
            if demanding and not _IDENTIFIER_SHAPE_RE.search(name):
                continue
            out.add(name.lower())
    stop = _ANCHOR_STOP | _case_path_words()
    return {a for a in out if len(a) >= 3 and a not in stop}


def _shares_anchor(text: str, anchors: set[str]) -> bool:
    low = (text or "").lower()
    return any(a in low for a in anchors)


def resolve_claim_evidence(
    case_dir: str | os.PathLike,
    node: dict[str, Any],
    *,
    max_events: int = 24,
) -> EvidencePack:
    """Resolve supporting evidence for one claim/conclusion node."""
    root = _case_root(case_dir)
    pack = EvidencePack(node_id=str(node.get("id") or ""))
    refs = _extract_refs_from_node(node)
    components = _detect_components(node)

    retained: list[str] = []
    for r in refs["record_refs"]:
        retained.append(f"record_ref={r}")
    for c in refs["call_ids"]:
        retained.append(f"call_id={c}")
    for a in refs["artifacts"]:
        bit = f"artifact={a.get('artifact')}"
        if a.get("locator"):
            bit += f" locator={a.get('locator')}"
        retained.append(bit)
    pack.retained_refs = retained

    collected: list[EvidenceEvent] = []
    tl_events = _timeline_events_jsonl(root)
    pat = dict(_COMPONENT_PATTERNS)
    anchors = _claim_anchors(node)
    bystanders: list[EvidenceEvent] = []

    # 0) What the analyst cited when recording the finding, when it names
    #    a record (a timestamp or an event id). Used to be a fallback behind
    # call windows — so "file01 Security.evtx EventID 4720 
    #    10:54:25" lost out to mid-field CSV fragments from a grep spill.
    try:
        from core.forensic_citation import normalize_timestamp as _nts
        for ev in _supporting_evidence_prose_events(node, max_events=4):
            if _nts(ev.text) or _ANCHOR_EVENT_RE.search(ev.text):
                collected.append(ev)
    except Exception:  # noqa: BLE001
        pass

    # 1) Direct record_ref
    for ref in refs["record_refs"]:
        ev = _find_timeline_by_record_ref(tl_events, ref)
        if not ev:
            continue
        comp = "general"
        blob = (ev.get("description") or "") + " " + (ev.get("title") or "")
        for c in components:
            rx = pat.get(c)
            if rx and rx.search(blob):
                comp = c
                break
        collected.append(_event_from_timeline(
            ev, provenance="direct", component=comp,
        ))

    # 2) call_id → tool output; timeline only if facts.call_id links deterministically
    for cid in refs["call_ids"]:
        linked_tl = None
        for ev in tl_events:
            facts = ev.get("facts") if isinstance(ev.get("facts"), dict) else {}
            try:
                if int(facts.get("call_id") or 0) == int(cid):
                    linked_tl = ev
                    break
            except (TypeError, ValueError):
                pass
        if linked_tl is not None:
            collected.append(_event_from_timeline(
                linked_tl, provenance="direct",
                component=components[0],
            ))
        # input_call_ids are lineage — every recent call, inferred — not
        # evidence for this statement. Without the anchor test an
        # account-creation finding would cite domain-controller replication
        # events only because a DCSync grep ran in the same window. A window
        # that shares nothing with the claim is kept
        # only as a labelled correlation, never as a cited record.
        for ev in _resolve_call_id(root, cid, component=components[0]):
            if anchors and not _shares_anchor(ev.text, anchors):
                ev.provenance = "correlated"
                bystanders.append(ev)
                continue
            collected.append(ev)

    # 3) Artifact + locator
    for art in refs["artifacts"]:
        line_no = None
        if art.get("line"):
            try:
                line_no = int(art["line"])
            except (TypeError, ValueError):
                pass
        scan_limit = 8
        if "brute_force" in components or any(
            t in (art.get("locator") or "").lower()
            for t in _AUTH_WIDEN_LOCATOR_TOKENS
        ):
            scan_limit = 40
        collected.extend(_read_artifact_lines(
            root,
            str(art.get("artifact") or ""),
            line_no=line_no,
            locator=str(art.get("locator") or ""),
            max_lines=scan_limit,
        ))

    def _strength(e: EvidenceEvent) -> int:
        low = (e.text or "").lower()
        score = 0
        for a in anchors:
            if a in low:
                # a full timestamp or an identifier says more than a date
                score += 3 if (":" in a or a.startswith("s-1-5") or len(a) >= 32) \
                    else 1
        return score

    if anchors:
        for e in collected:
            e.relevance = _strength(e)
        collected.sort(key=_strength, reverse=True)
    seen: set[str] = set()
    unique: list[EvidenceEvent] = []
    for e in collected:
        key = e.text[:240]
        if not key or key in seen:
            continue
        seen.add(key)
        unique.append(e)

    if unique:
        pack.observed_count = len(unique)
        stamps = [e.timestamp for e in unique if e.timestamp]
        if stamps:
            pack.timeframe_start = min(stamps)
            pack.timeframe_end = max(stamps)
        if _is_homogeneous(components, len(unique)):
            pack.selection_mode = "homogeneous"
            pack.events = _select_homogeneous(unique)[:max_events]
        elif len(components) > 1:
            pack.selection_mode = "multi_component"
            pack.events = _select_multi_component(unique, components)[:max_events]
        else:
            pack.selection_mode = "exact"
            pack.events = unique[:max_events]
        return pack

    if bystanders:
        pack.selection_mode = "correlated"
        pack.observed_count = len(bystanders)
        pack.events = bystanders[:max_events]
        pack.unresolved_note = (
            "No cited record shares an identifier (date, host, account, "
            "event id, hash) with this claim. The tool output below ran in "
            "the same window and is labelled *correlated*; it is not direct "
            "supporting evidence."
        )
        return pack

    # 3b) Analyst supporting_evidence prose when call_id/artifact failed —
    # prefer cited prose over a correlated RAW EVENT flood (I5).
    prose = _supporting_evidence_prose_events(node, max_events=max_events)
    if prose:
        pack.selection_mode = "supporting_evidence_prose"
        pack.observed_count = len(prose)
        pack.events = prose
        pack.unresolved_note = (
            "Tool call_id / artifact paths did not resolve to raw rows; "
            "showing analyst supporting_evidence prose as cited text "
            "(not host/time heuristic RAW EVENTs)."
        )
        return pack

    # 4) Controlled correlation — labeled only
    correlated = _controlled_correlation(root, node, components=components)
    if correlated:
        pack.selection_mode = "correlated"
        pack.observed_count = len(correlated)
        selected = (
            _select_homogeneous(correlated)
            if _is_homogeneous(components, len(correlated))
            else correlated[:max_events]
        )
        for e in selected:
            e.provenance = "correlated"
        pack.events = selected
        pack.unresolved_note = (
            "No explicit provenance (record_ref / call_id / artifact+locator) "
            "resolved to an exact event. The events below are labeled "
            "*correlated* (host/time/attribute match) and must not be treated "
            "as direct supporting evidence without analyst verification."
        )
        return pack

    # 5) Unresolved
    pack.selection_mode = "empty"
    pack.unresolved_note = (
        "Supporting raw event(s) could not be deterministically resolved "
        "from Current Investigation State evidence references. "
        "Retained source/trace references are listed below; no nearby or "
        "heuristic event was selected."
    )
    return pack


# Heading for a rendered evidence block. Replaces the old "[RAW EVENT]"
# per-event marker: what follows is a list of citations, not a dump.
EVIDENCE_BLOCK_MARKER = "**Cited records**"


def format_evidence_markdown(
    pack: EvidencePack | dict[str, Any],
    *,
    compact: bool = False,
    limit: int = 8,
    known_hosts: Iterable[str] = (),
) -> str:
    """Render an EvidencePack as Markdown citations with provenance.

    Never invents line numbers or RecordRefs — only renders fields present
    on the resolved event. ``compact`` renders just the citation bullets
    (no marker, no event counts) for the finding block of a report.
    """
    if isinstance(pack, dict):
        events = pack.get("events") or []
        note = pack.get("unresolved_note") or ""
        observed = pack.get("observed_count")
        t0 = pack.get("timeframe_start") or ""
        t1 = pack.get("timeframe_end") or ""
        mode = pack.get("selection_mode") or ""
        retained = pack.get("retained_refs") or []
    else:
        events = [e.to_dict() for e in pack.events]
        note = pack.unresolved_note
        observed = pack.observed_count
        t0 = pack.timeframe_start
        t1 = pack.timeframe_end
        mode = pack.selection_mode
        retained = pack.retained_refs

    lines: list[str] = []
    if observed and observed > len(events) and not compact:
        lines.append(f"**Observed Events:** {observed}")
        if t0 or t1:
            lines.append(f"**Timeframe:** {t0 or '?'} → {t1 or '?'}")
        if mode == "homogeneous":
            lines.append(
                "**Representative Evidence:** (first / samples / last)"
            )
        lines.append("")

    if note:
        lines.append(f"*{note}*")
        lines.append("")

    if not events:
        if retained:
            lines.append("Retained references:")
            for r in retained[:20]:
                lines.append(f"- `{r}`")
        else:
            lines.append(
                "*Supporting raw event(s) could not be deterministically "
                "resolved; no invented events are shown.*"
            )
        return "\n".join(lines).rstrip() + "\n"

    # Rendered as citations, not as a transcript of tool output. The old
    # per-event field template assigned meaning by column position and
    # published whatever landed in each slot — "Timestamp: d/d 1234-128-1",
    # "Machine: Documents and Settings" — and pasted hexdumps in as
    # descriptions. core.forensic_citation only labels a field once the
    # value has been validated as that kind of thing, and degrades to a
    # quoted excerpt otherwise.
    from core.forensic_citation import render_citations

    event_dicts = [ev for ev in events if isinstance(ev, dict)]
    body = render_citations(event_dicts, known_hosts=known_hosts, limit=limit)
    if compact:
        out = []
        if note and mode == "correlated":
            out.append(f"*{note}*")
        if body:
            out.append(body)
        return "\n".join(out).rstrip() + "\n" if out else ""
    if body:
        lines.append(EVIDENCE_BLOCK_MARKER)
        lines.append("")
        lines.append(body)
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def _parse_tsv_event_fields(text: str) -> dict[str, str]:
    """Best-effort parse of tab-separated timeline row → display fields."""
    if not text or "\t" not in text:
        return {}
    parts = text.split("\t")
    # Skip header-like rows
    if parts and parts[0].strip().lower() in ("timestamp", "datetime"):
        return {}
    out: dict[str, str] = {}
    if len(parts) >= 1 and parts[0].strip():
        out["timestamp"] = parts[0].strip()
    if len(parts) >= 2 and parts[1].strip():
        out["machine"] = parts[1].strip()
    if len(parts) >= 3 and parts[2].strip():
        out["user"] = parts[2].strip()
    if len(parts) >= 4 and parts[3].strip():
        out["event"] = parts[3].strip()
    if len(parts) >= 5 and parts[4].strip():
        out["source_label"] = parts[4].strip()
    if len(parts) >= 6 and parts[5].strip():
        out["description"] = parts[5].strip()
    return out


def resolve_nodes_evidence(
    case_dir: str | os.PathLike,
    nodes: Iterable[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Batch-resolve evidence. Returns node_id → pack dict."""
    out: dict[str, dict[str, Any]] = {}
    for n in nodes:
        nid = str(n.get("id") or "")
        if not nid:
            continue
        out[nid] = resolve_claim_evidence(case_dir, n).to_dict()
    return out
