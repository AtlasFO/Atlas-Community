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
from datetime import date, datetime, timedelta, timezone
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

# The index's file under the trace directory; SQLite keeps its journal
# beside it under the same name plus a suffix (-wal, -shm, -journal).
INDEX_FILE = "evidence_index.db"


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
    path = os.path.join(trace_dir, INDEX_FILE)
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
# The index reads three forms, in this order of trust: an ISO-8601 moment
# (converted to UTC when it states an offset), a syslog line (no year, so the
# caller supplies one), and a US-ordered date as Plaso and US-locale exports
# write it (one- or two-digit month and day, 24-hour or AM/PM clock); then
# an ISO moment to the minute and a slashed year-first moment, after the
# others so a text that one of them reads keeps that reading. Each is a row in
# one table, read by one loop; the first form found in the window is the
# window's time.

# The zone a moment written to the minute may carry: "Z" or a "+" offset
# within +14:00 (a "-" after a minute begins a span's end). Shared with
# core.incident_window's statement reader.
MINUTE_ZONE = r"(Z|\+(?:0\d|1[0-4]):?[0-5]\d(?![:\d]))?"

_MONTHS = {m: i for i, m in enumerate(
    ("Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), start=1)}


def _read_iso(m: re.Match, _year: Optional[int]) -> datetime:
    """The moment as written, or converted to UTC when the text states an
    offset ("Z", "+02:00", "-0500"); a time without an offset stays as
    written, since its zone is unknown. Sub-second digits are dropped."""
    moment = datetime.fromisoformat(m.group(1).replace("/", "-"))
    zone = m.group(2)
    if not zone:
        return moment
    if zone.upper() != "Z":
        sign = -1 if zone[0] == "-" else 1
        digits = zone[1:].replace(":", "")
        moment -= sign * timedelta(hours=int(digits[:2]), minutes=int(digits[2:]))
    return moment


def _read_syslog(m: re.Match, year) -> datetime:
    """A month-day-clock form names no year: with none known it is no
    moment (ValueError, skipped), never one in the year the run happens to
    be in. ``year`` is the evidence file's modification date (evidence_date)
    or a year the text states (year_hint), as index_output passes it. A log
    never carries a time after its file's last write: a month-day that
    falls after the modification date's month-day belongs to the year
    before (a December log read in January included). Ceilings: an evidence
    file staged without its own mtime carries the staging date, and the
    staging year wins where the text states none; an evidence image's mtime
    is its acquisition date, later than the log lines inside it, so a log
    older than a year inside an image takes the image's year (its
    acquisition, never the run's year)."""
    month, day, hour, minute, second = m.groups()
    if not year:
        raise ValueError("a yearless form is no moment")
    if isinstance(year, date):
        y = year.year - (1 if (_MONTHS[month], int(day)) > (year.month, year.day) else 0)
    else:
        y = int(year)
    return datetime(year=y, month=_MONTHS[month], day=int(day), hour=int(hour),
                    minute=int(minute), second=int(second))


# A full-dated form in a text: the year the yearless forms in the same text
# belong to, when the text states exactly one. An FTP listing writes the
# age-old rows with a year beside the recent ones with a clock; a tool
# banner's ctime form ("Tue Jun 03 08:41:19 2031") is not a dated record and
# names no year for the records; a text that states two years (a
# certificate's validity beside a listing) names none.
_YEAR_HINT_RE = re.compile(
    r"(?<!\d)(?P<iso>\d{4})-\d{2}-\d{2}(?!\d)"
    r"|(?<![\d/])(?P<yf>\d{4})/\d{2}/\d{2}(?![\d/])"
    r"|(?<!\d)\d{1,2}/\d{1,2}/(?P<us>\d{4})(?!\d)"
    r"|\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+(?P<md>\d{4})\b")


def year_hint(text: str) -> Optional[int]:
    """The one year the full-dated forms of ``text`` state, or None when
    they state none or more than one."""
    years = {int(next(v for v in m.groups() if v)) for m in _YEAR_HINT_RE.finditer(text or "")}
    years = {y for y in years if 1970 <= y <= 2100}
    return years.pop() if len(years) == 1 else None


def evidence_date(tokens) -> Optional[date]:
    """The newest modification date among the evidence files ``tokens`` name
    (paths under the case's evidence/ or mnt/ that exist), or None. An
    export carries the run's date and says nothing; the evidence file keeps
    the date it was acquired with (see _read_syslog for the staged copy)."""
    path = db_path()
    if not path:
        return None
    root = os.path.dirname(os.path.dirname(path))
    roots = [os.path.join(root, "evidence"), os.path.join(root, "mnt")]
    roots += [os.path.realpath(r) for r in list(roots)]
    best: Optional[date] = None
    for tok in tokens or ():
        tok = str(tok or "").strip().strip("'\"")
        if not tok:
            continue
        absolute = os.path.normpath(tok if os.path.isabs(tok) else os.path.join(root, tok))
        forms = (absolute, os.path.realpath(absolute))
        if not any(f == r or f.startswith(r.rstrip(os.sep) + os.sep) for f in forms for r in roots):
            continue
        try:
            when = datetime.fromtimestamp(os.stat(absolute).st_mtime, timezone.utc).date()
        except OSError:
            continue
        best = when if best is None or when > best else best
    return best


def _read_us_ordered(m: re.Match, _year: Optional[int]) -> datetime:
    """Month first, as Plaso and US-locale exports write it; a 12-hour clock
    ("10:16:00 PM", Windows Event Viewer and many SIEM exports) is read
    into 24 hours. Ceiling: a day-first date (DD/MM/YYYY) reads as month
    first, or is skipped when its day exceeds 12."""
    month, day, year, hour, minute, second = (int(g) for g in m.groups()[:6])
    marker = (m.group(7) or "").upper()
    if marker:
        if not 1 <= hour <= 12:
            raise ValueError("a 12-hour clock reads 1 to 12")
        hour = hour % 12 + (12 if marker == "PM" else 0)
    return datetime(year, month, day, hour, minute, second)


# The ISO offset follows the entity extractor's rule: within +-14:00 and
# never followed by ":" or a digit, so a seconds range ("10:16:00-10:48:00")
# is not read as a moment with an offset.
_TIME_FORMS = (
    (re.compile(r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})(?:\.\d+)?"
                r"(Z|[+-](?:0\d|1[0-4]):?[0-5]\d(?![:\d]))?"), _read_iso),
    (re.compile(r"(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"
                r"\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})"), _read_syslog),
    (re.compile(r"(?<!\d)(\d{1,2})/(\d{1,2})/(\d{4})\s+(\d{1,2}):(\d{2}):(\d{2})"
                r"(?:\s?([AaPp][Mm])\b)?"), _read_us_ordered),
    # An ISO moment to the minute ("2031-03-10 14:02", "...T14:02Z"), as
    # people and many reports write it; last, so a text with a moment to the
    # second keeps its second reading. After a minute only "Z" or a "+" offset is a
    # zone: "09:00-10:30" is a span whose end is not read, never a negative
    # offset (logs that carry zones write seconds).
    (re.compile(r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2})(?![:\d])" + MINUTE_ZONE), _read_iso),
    # Year first with slashes, as vendor and appliance logs write it: year
    # first leaves no day-month doubt. Same zone rules as the ISO forms.
    (re.compile(r"(?<![\d/])(\d{4}/\d{2}/\d{2}[T ]\d{2}:\d{2}:\d{2})(?:\.\d+)?"
                r"(Z|[+-](?:0\d|1[0-4]):?[0-5]\d(?![:\d]))?"), _read_iso),
    (re.compile(r"(?<![\d/])(\d{4}/\d{2}/\d{2}[T ]\d{2}:\d{2})(?![:\d])" + MINUTE_ZONE), _read_iso),
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
                 source_path: str = "", reference_year=None) -> dict:
    """Chunk `text` into windows and index it under the given call_id.

    A window's event_time is the first moment its text states. A form that
    names no year (syslog, an FTP listing's recent rows) takes
    ``reference_year`` first (the caller's evidence_date of the files the
    call read, with the year-before rule of _read_syslog), else the one year
    the whole text states (year_hint), else no time at all; never the year
    the run happens in.

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
    year = reference_year or year_hint(text)

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
                                  _parse_timestamp(chunk, year), chunk))
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
    limit = max(1, min(int(max_results), 500))
    params.append(limit)

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
    # A result that fills the limit may have more matches behind it: say so,
    # so no reader takes the rows for all there are.
    return {"success": True, "query": sanitized, "results": results,
            "result_count": len(results), "hit_cap_reached": len(results) >= limit}


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


def indexed_call_ids() -> set[int]:
    """The call ids whose output the index holds (whole or cut at
    MAX_INDEXED_BYTES), so a reader knows which spills it must scan itself."""
    path = db_path()
    if path is None or not os.path.exists(path):
        return set()
    conn = _connect(path)
    try:
        try:
            rows = conn.execute("SELECT DISTINCT call_id FROM sources").fetchall()
        except sqlite3.OperationalError:
            return set()
        return {int(r[0]) for r in rows if r[0] is not None}
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
