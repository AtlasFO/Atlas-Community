"""Per-case FTS5 evidence index over full tool output.

Atlas's output cap keeps ~10% of a large tool output in context; the rest
streams to a spill file that nothing searched afterwards. This module makes
the accumulated output queryable: every tool call's FULL text is chunked
into windows, stamped with a best-effort event time, and indexed in a
per-case SQLite FTS5 database at <case>/analysis/evidence_index.db. The
`search` namespace (tools/search_tools.py) exposes it to the analyst, and
every hit carries the originating `call_id` so findings keep Atlas's
citation lineage.

Built on stdlib `sqlite3`. The chunk-into-windows and batch-insert shape of
the ingestion below follows Mulder (Apache-2.0, commit 1246de42,
server/extract_helpers.py), as does the decision to serialise every write
rather than let callers contend; here that is a module lock instead of its
`_WriteQueue`, the same guarantee without a thread. Mulder's SQLAlchemy
CaseDB was deliberately not vendored, and the query sanitiser and timestamp
reader below are Atlas's own — see their own sections.

Concurrency contract: WRITES HAPPEN ONLY IN THE MCP SERVER PROCESS —
core.executor._log_tool for normal tools and tools.jobs.job_collect for
background jobs. tools/jobs_runner.py (a separate process) must never
import this module. WAL + busy_timeout remain as belt-and-braces only.
"""
from __future__ import annotations

import hashlib
import os
import re
import sqlite3
import threading
import time
from datetime import datetime, timezone
from typing import Any, Optional

# Per-source ingestion cap. bulk_extractor/strings spills reach hundreds of
# MB; 4096-char windows over a 500 MB dump would be ~125k rows for one
# source. Precedent: core/brain/gt_exposure.py caps spill reads at 256 KiB.
MAX_INDEXED_BYTES = int(
    os.environ.get("ATLAS_EVIDENCE_INDEX_MAX_BYTES") or 8_000_000)
# Outputs smaller than this are already fully visible in the agent's context
# window — indexing them is pure noise.
MIN_INDEXED_BYTES = 200

_WINDOW_CHAR_BUDGET = 4096
_INSERT_BATCH_SIZE = 5000

# One writer at a time in this process (the Mulder _WriteQueue guarantee).
_WRITE_LOCK = threading.Lock()

_SCHEMA = """
CREATE TABLE IF NOT EXISTS sources (
    source_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    call_id     INTEGER,
    tool        TEXT,
    source_path TEXT,
    source_hash TEXT,
    line_count  INTEGER,
    byte_count  INTEGER,
    truncated   INTEGER DEFAULT 0,
    ingested_at TEXT
);
CREATE TABLE IF NOT EXISTS windows (
    window_id  INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id  INTEGER NOT NULL REFERENCES sources(source_id),
    line_start INTEGER,
    line_end   INTEGER,
    event_time TEXT,
    raw_text   TEXT
);
CREATE INDEX IF NOT EXISTS ix_windows_source ON windows(source_id);
CREATE INDEX IF NOT EXISTS ix_windows_time ON windows(event_time);
CREATE VIRTUAL TABLE IF NOT EXISTS windows_fts
    USING fts5(raw_text, content=windows, content_rowid=window_id);
"""


# ── DB location / connection ────────────────────────────────────────────────

def db_path() -> Optional[str]:
    """Index DB path in the active case's analysis/ dir, or None when no
    execution log is configured (no case → nowhere sane to index)."""
    try:
        from core.execution_log import log
        trace_dir = log.trace_dir()
    except Exception:
        return None
    if not trace_dir:
        return None
    path = os.path.join(trace_dir, "evidence_index.db")
    from core.paths import assert_output_safe
    assert_output_safe(path)
    return path


def _connect(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path, timeout=30.0)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=30000")
    conn.executescript(_SCHEMA)
    return conn


# ── Query sanitising ────────────────────────────────────────────────────────
# A query reaches this module from a model, and FTS5 is unforgiving: a bare
# `spinlock.exe` is a syntax error, not a search for a filename. The job is to
# hand SQLite something it will parse while keeping the operators the caller
# meant.
#
# The pass below scans the query into typed pieces and renders each by its
# type, rather than testing each whitespace token for special characters. The
# difference is not stylistic: a scanner sees a quote that never closes and a
# trailing operator, both of which a per-token test cannot, and both of which
# a model produces often enough to matter.

# FTS5 spells a proximity search NEAR(a b, 3); a bare "NEAR/3" is not its
# syntax and is quoted like any other term with a slash in it.
_OPERATORS = frozenset({"AND", "OR", "NOT", "NEAR"})
# What FTS5 reads as syntax rather than as text.
_NEEDS_QUOTING = re.compile(r'["./$:^{}()*+\-~]')
_SCAN = re.compile(r'"(?P<phrase>[^"]*)"?|(?P<bare>\S+)')


def _scan_query(query: str):
    """Yield ``(kind, text)`` for each piece: phrase, operator or term.

    A phrase keeps whatever it contains, including the spaces that are the
    reason it was quoted. A quote that is never closed still yields a phrase,
    which is the reading that loses the least of what the caller wrote.
    """
    for m in _SCAN.finditer(query):
        phrase = m.group("phrase")
        if phrase is not None:
            # An empty phrase is kept: FTS5 accepts it and matches nothing,
            # which is the answer the caller asked for.
            yield "phrase", phrase
            continue
        bare = m.group("bare")
        if bare in _OPERATORS:
            yield "operator", bare
        else:
            yield "term", bare


def _sanitize_fts5_query(query: str) -> str:
    """``query`` in a form FTS5 will parse, meaning preserved where possible.

    A pipe is read as OR. Models write regex-style alternation constantly, and
    FTS5 has no pipe operator at all, so the alternative to translating it is
    a syntax error on a query whose intent was never in doubt.
    """
    text = str(query or "")
    if "|" in text:
        parts = [seg.strip() for seg in text.replace("\\|", "|").split("|")]
        text = " OR ".join(seg for seg in parts if seg)

    out: list[str] = []
    for kind, piece in _scan_query(text):
        if kind == "phrase":
            out.append('"' + piece.replace('"', '""') + '"')
        elif kind == "operator":
            out.append(piece)
        elif _NEEDS_QUOTING.search(piece):
            out.append('"' + piece.replace('"', '""') + '"')
        else:
            out.append(piece)

    # An expression cannot begin or end on a binary operator; FTS5 rejects the
    # whole query for it, and a model that ends on "AND" meant the terms.
    while out and out[0] in _OPERATORS:
        out.pop(0)
    while out and out[-1] in _OPERATORS:
        out.pop()
    return " ".join(out)


# ── Timestamp reading ───────────────────────────────────────────────────────
# The index reads three forms, in this order of trust: an ISO-8601 moment, a
# syslog line (no year, so the caller supplies one), and a US-ordered date as
# Plaso exports it. Each is a row in one table, read by one loop; the first
# form found in the window is the window's time.

_MONTHS = {m: i for i, m in enumerate(
    ("Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), start=1)}


def _read_iso(m: re.Match, _year: Optional[int]) -> datetime:
    return datetime.fromisoformat(m.group(0))


def _read_syslog(m: re.Match, year: Optional[int]) -> datetime:
    month, day, hour, minute, second = m.groups()
    return datetime(year=year or datetime.now(timezone.utc).year,
                    month=_MONTHS[month], day=int(day), hour=int(hour),
                    minute=int(minute), second=int(second))


def _read_us_ordered(m: re.Match, _year: Optional[int]) -> datetime:
    month, day, year, hour, minute, second = (int(g) for g in m.groups())
    return datetime(year, month, day, hour, minute, second)


_TIME_FORMS = (
    (re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}"), _read_iso),
    (re.compile(r"(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"
                r"\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})"), _read_syslog),
    (re.compile(r"(\d{2})/(\d{2})/(\d{4})\s+(\d{2}):(\d{2}):(\d{2})"), _read_us_ordered),
)


def _iso(moment: datetime) -> str:
    return moment.isoformat()


def _parse_timestamp(text: str,
                     reference_year: Optional[int] = None) -> Optional[str]:
    """The first moment ``text`` states, as an ISO-8601 string, or None.

    ISO-8601 sorts as a string, which is why it is what goes in the column:
    a range query over the index is a string comparison. A form that matches
    but names an impossible date (month 13, second 99) is skipped rather than
    raised.
    """
    for pattern, read in _TIME_FORMS:
        m = pattern.search(text)
        if not m:
            continue
        try:
            return _iso(read(m, reference_year))
        except ValueError:
            continue
    return None


# ── Ingestion ────────────────────────────────────────────────────────────────

def index_output(call_id: int, tool: str, text: str,
                 source_path: str = "") -> dict:
    """Chunk `text` into windows and index it under the given call_id.

    Returns a summary dict; raises on DB errors (callers hook this in
    best-effort try/except — indexing must never fail a tool call).
    """
    path = db_path()
    if path is None:
        return {"status": "no_case", "windows_indexed": 0}
    if not text or len(text) < MIN_INDEXED_BYTES:
        return {"status": "skipped_small", "windows_indexed": 0}

    truncated = len(text) > MAX_INDEXED_BYTES
    if truncated:
        text = text[:MAX_INDEXED_BYTES]

    line_count = text.count("\n") + 1
    source_hash = ("blake2b:" + hashlib.blake2b(
        text.encode("utf-8", errors="replace"), digest_size=32).hexdigest())

    with _WRITE_LOCK:
        conn = _connect(path)
        try:
            cur = conn.execute(
                "INSERT INTO sources (call_id, tool, source_path, "
                "source_hash, line_count, byte_count, truncated, "
                "ingested_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (call_id, tool, source_path, source_hash, line_count,
                 len(text), int(truncated),
                 time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())))
            source_id = cur.lastrowid

            batch: list[tuple] = []
            lines_before = 0
            for offset in range(0, len(text), _WINDOW_CHAR_BUDGET):
                chunk = text[offset:offset + _WINDOW_CHAR_BUDGET]
                lines_in_chunk = chunk.count("\n")
                if chunk.strip():
                    batch.append((source_id, lines_before + 1,
                                  lines_before + lines_in_chunk + 1,
                                  _parse_timestamp(chunk), chunk))
                lines_before += lines_in_chunk
                if len(batch) >= _INSERT_BATCH_SIZE:
                    _insert_windows(conn, batch)
                    batch = []
            if batch:
                _insert_windows(conn, batch)
            conn.commit()
            windows = conn.execute(
                "SELECT count(*) FROM windows WHERE source_id = ?",
                (source_id,)).fetchone()[0]
        finally:
            conn.close()

    return {"status": "indexed", "source_id": source_id,
            "windows_indexed": windows, "line_count": line_count,
            "truncated": truncated}


def _insert_windows(conn: sqlite3.Connection, batch: list[tuple]) -> None:
    """Insert a window batch plus its FTS rows (external-content FTS5 tables
    are not populated automatically)."""
    for row in batch:
        cur = conn.execute(
            "INSERT INTO windows (source_id, line_start, line_end, "
            "event_time, raw_text) VALUES (?, ?, ?, ?, ?)", row)
        conn.execute(
            "INSERT INTO windows_fts (rowid, raw_text) VALUES (?, ?)",
            (cur.lastrowid, row[4]))


# ── Search ───────────────────────────────────────────────────────────────────

def search(query: str, tool: Optional[str] = None,
           time_start: Optional[str] = None, time_end: Optional[str] = None,
           max_results: int = 100) -> dict:
    """Full-text search over all indexed tool output.

    Supports terms (`spinlock.exe`), phrases (`"brute force"`), boolean
    (`4624 AND logon`) and pipe-alternatives (`cmd|powershell`). Results
    are relevance-ranked and carry the originating call_id.
    """
    path = db_path()
    if path is None or not os.path.exists(path):
        return {"success": False, "results": [],
                "error": "no evidence index for this case yet — it fills "
                         "as tools run"}
    sanitized = _sanitize_fts5_query(query or "")
    if not sanitized.strip():
        return {"success": False, "results": [], "error": "empty query"}

    sql = (
        "SELECT s.call_id, s.tool, s.source_path, w.line_start, "
        "w.line_end, w.event_time, "
        "snippet(windows_fts, 0, '>>', '<<', ' … ', 32) "
        "FROM windows_fts "
        "JOIN windows w ON w.window_id = windows_fts.rowid "
        "JOIN sources s ON s.source_id = w.source_id "
        "WHERE windows_fts MATCH ?")
    params: list[Any] = [sanitized]
    if tool:
        sql += " AND s.tool = ?"
        params.append(tool)
    if time_start:
        sql += " AND w.event_time >= ?"
        params.append(time_start)
    if time_end:
        sql += " AND w.event_time <= ?"
        params.append(time_end)
    sql += " ORDER BY rank LIMIT ?"
    params.append(max(1, min(int(max_results), 500)))

    conn = _connect(path)
    try:
        rows = conn.execute(sql, params).fetchall()
    except sqlite3.OperationalError as e:
        return {"success": False, "results": [],
                "error": f"FTS query error: {e}",
                "sanitized_query": sanitized}
    finally:
        conn.close()

    results = [{"call_id": r[0], "tool": r[1], "source_path": r[2],
                "line_start": r[3], "line_end": r[4], "event_time": r[5],
                "snippet": r[6]} for r in rows]
    return {"success": True, "query": sanitized, "results": results,
            "result_count": len(results)}


def find_in_calls(query: str, call_ids: list[int], *, limit: int = 50) -> list[tuple[int, str]]:
    """Windows of the given calls' output that match ``query``, each joined
    with the next window of the same source (windows do not overlap, so a
    value can straddle two). A hit here is a location to confirm on the
    text, not a proof: the tokenizer splits on dots and slashes."""
    path = db_path()
    ids = [int(c) for c in call_ids if str(c).strip().lstrip("-").isdigit()]
    if path is None or not os.path.exists(path) or not ids:
        return []
    sanitized = _sanitize_fts5_query(query or "")
    if not sanitized.strip():
        return []
    marks = ",".join("?" for _ in ids)
    sql = (
        "SELECT s.call_id, w.window_id, w.source_id, w.raw_text FROM windows_fts "
        "JOIN windows w ON w.window_id = windows_fts.rowid "
        "JOIN sources s ON s.source_id = w.source_id "
        f"WHERE windows_fts MATCH ? AND s.call_id IN ({marks}) ORDER BY rank LIMIT ?")
    conn = _connect(path)
    try:
        try:
            rows = conn.execute(sql, [sanitized, *ids, max(1, min(int(limit), 500))]).fetchall()
        except sqlite3.OperationalError:
            return []
        out = []
        for call_id, window_id, source_id, text in rows:
            nxt = conn.execute(
                "SELECT raw_text FROM windows WHERE source_id = ? AND window_id > ? "
                "ORDER BY window_id LIMIT 1", (source_id, window_id)).fetchone()
            out.append((int(call_id), (text or "") + (nxt[0] if nxt and nxt[0] else "")))
        return out
    finally:
        conn.close()


def find_windows(query: str, *, limit: int = 200) -> list[tuple[int, str, str]]:
    """``(call_id, tool, text)`` for every indexed window matching
    ``query``, each joined with the next window of its source, as
    find_in_calls does for a set of calls. A hit is a location to confirm
    on the text, not a proof."""
    path = db_path()
    if path is None or not os.path.exists(path):
        return []
    sanitized = _sanitize_fts5_query(query or "")
    if not sanitized.strip():
        return []
    sql = ("SELECT s.call_id, s.tool, w.window_id, w.source_id, w.raw_text FROM windows_fts "
           "JOIN windows w ON w.window_id = windows_fts.rowid "
           "JOIN sources s ON s.source_id = w.source_id "
           "WHERE windows_fts MATCH ? ORDER BY rank LIMIT ?")
    conn = _connect(path)
    try:
        try:
            rows = conn.execute(sql, [sanitized, max(1, min(int(limit), 2000))]).fetchall()
        except sqlite3.OperationalError:
            return []
        out = []
        for call_id, tool, window_id, source_id, text in rows:
            nxt = conn.execute(
                "SELECT raw_text FROM windows WHERE source_id = ? AND window_id > ? "
                "ORDER BY window_id LIMIT 1", (source_id, window_id)).fetchone()
            out.append((int(call_id), str(tool or ""), (text or "") + (nxt[0] if nxt and nxt[0] else "")))
        return out
    finally:
        conn.close()


def stats() -> dict:
    """Index size summary (sources/windows counts, per-tool breakdown)."""
    path = db_path()
    if path is None or not os.path.exists(path):
        return {"success": True, "sources": 0, "windows": 0, "tools": {}}
    conn = _connect(path)
    try:
        sources = conn.execute("SELECT count(*) FROM sources").fetchone()[0]
        windows = conn.execute("SELECT count(*) FROM windows").fetchone()[0]
        tools = dict(conn.execute(
            "SELECT tool, count(*) FROM sources GROUP BY tool "
            "ORDER BY count(*) DESC").fetchall())
    finally:
        conn.close()
    return {"success": True, "db_path": path, "sources": sources,
            "windows": windows, "tools": tools}
