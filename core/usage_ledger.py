"""A ledger of every model request: who spent which tokens on which case.

Written by the transport at the point where the client already adds a
request to its totals, so every role and every rung of the starvation
ladder is one row. The row's case, run, command and user come from a
process context that the agent factory sets and exports to the
environment, so a child process (the brain learner) inherits it; a
dashboard request that calls a model on its own sets the context around
the call. Without a case id nothing is recorded: a unit test, a probe or
a capability check never writes.

The store is one SQLite file (``ATLAS_USAGE_DB``, absolute, or
``~/.config/atlas/usage.db``) in WAL mode with one short connection per
insert: several runs write at once and the dashboard reads meanwhile. A
failed write is reported once per process and never raises.

A run from before the ledger existed is added once from its case folder
(core.usage_import); ``settled_runs`` remembers every run so added and every
run whose rows were deleted, so neither is ever added again.
"""
from __future__ import annotations

import contextvars
import json
import os
import sqlite3
import sys
from contextlib import contextmanager
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator, Optional

ENV_DB = "ATLAS_USAGE_DB"
ENV_CONTEXT = "ATLAS_USAGE_CONTEXT"
DEFAULT_DB = "~/.config/atlas/usage.db"
FIELDS = ("case_id", "run_id", "command", "started_by")
STATUSES = ("ok", "starved", "cut")
_TIMEOUT = 3.0

_SCHEMA = """
CREATE TABLE IF NOT EXISTS llm_usage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    case_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    command TEXT NOT NULL,
    started_by TEXT NOT NULL,
    role TEXT NOT NULL,
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    input_tokens INTEGER NOT NULL,
    output_tokens INTEGER NOT NULL,
    cached_tokens INTEGER NOT NULL,
    reasoning_tokens INTEGER NOT NULL,
    usage_reported INTEGER NOT NULL,
    status TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_usage_ts ON llm_usage(ts);
CREATE INDEX IF NOT EXISTS idx_usage_case ON llm_usage(case_id, run_id);
CREATE TABLE IF NOT EXISTS settled_runs (
    case_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    how TEXT NOT NULL,
    row_count INTEGER NOT NULL,
    ts TEXT NOT NULL,
    PRIMARY KEY (case_id, run_id)
);
"""
_INSERT = ("INSERT INTO llm_usage (ts, case_id, run_id, command, started_by, "
           "role, provider, model, input_tokens, output_tokens, cached_tokens, "
           "reasoning_tokens, usage_reported, status) "
           "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")

_ctx: contextvars.ContextVar[Optional[dict]] = contextvars.ContextVar(
    "atlas_usage_context", default=None)
_warned: set[str] = set()


def _warn_once(key: str, message: str) -> None:
    if key in _warned:
        return
    _warned.add(key)
    sys.stderr.write(f"[Atlas WARN] usage ledger: {message}\n")


def db_path() -> Path:
    raw = (os.environ.get(ENV_DB) or "").strip()
    if raw:
        p = Path(raw).expanduser()
        if p.is_absolute():
            return p
        _warn_once("relative", f"{ENV_DB}={raw!r} is not an absolute path; "
                               f"using {DEFAULT_DB}")
    return Path(DEFAULT_DB).expanduser()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _connect() -> sqlite3.Connection:
    """A writer's connection in autocommit mode; a statement group that must
    hold together runs inside ``_immediate``. Every connect creates what is
    missing, so a ledger removed under a live process is recreated."""
    path = db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), timeout=_TIMEOUT, isolation_level=None)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript(_SCHEMA)
    except BaseException:
        conn.close()
        raise
    return conn


@contextmanager
def _immediate(conn: sqlite3.Connection) -> Iterator[None]:
    """One write transaction, taken before the first read inside it, so two
    writers never both decide on what they read."""
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield
    except BaseException:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise
    conn.execute("COMMIT")


def _from_env() -> dict:
    raw = os.environ.get(ENV_CONTEXT) or ""
    try:
        data = json.loads(raw) if raw else {}
    except ValueError:
        data = {}
    if not isinstance(data, dict):
        data = {}
    return {k: str(data.get(k) or "") for k in FIELDS}


def current() -> dict:
    """The context this process records under: the context variable when
    set, else what the environment carries."""
    ctx = _ctx.get()
    return dict(ctx) if ctx is not None else _from_env()


def configure(**fields: Any) -> dict:
    """Merge fields into the context and export it to the environment, so a
    child process inherits it."""
    ctx = current()
    ctx.update({k: str(v or "") for k, v in fields.items() if k in FIELDS})
    _ctx.set(ctx)
    os.environ[ENV_CONTEXT] = json.dumps(ctx)
    return ctx


@contextmanager
def context(**fields: Any) -> Iterator[dict]:
    """A context for the calls inside the block, in this thread or task
    only; the environment is untouched."""
    ctx = current()
    ctx.update({k: str(v or "") for k, v in fields.items() if k in FIELDS})
    token = _ctx.set(ctx)
    try:
        yield ctx
    finally:
        _ctx.reset(token)


def reset() -> None:
    _ctx.set(None)
    os.environ.pop(ENV_CONTEXT, None)


def record(*, role: str, provider: str, model: str, input_tokens: int,
           output_tokens: int, cached_tokens: int = 0, reasoning_tokens: int = 0,
           usage_reported: bool = True, status: str = "ok") -> bool:
    ctx = current()
    if not ctx.get("case_id"):
        return False
    try:
        conn = _connect()
        try:
            conn.execute(_INSERT, (
                _now(), ctx["case_id"], ctx.get("run_id", ""), ctx.get("command", ""),
                ctx.get("started_by", ""), str(role or ""), str(provider or ""),
                str(model or ""), int(input_tokens or 0), int(output_tokens or 0),
                int(cached_tokens or 0), int(reasoning_tokens or 0),
                1 if usage_reported else 0,
                status if status in STATUSES else "ok"))
        finally:
            conn.close()
        return True
    except Exception as exc:  # noqa: BLE001
        _warn_once("write", f"write failed: {exc!r}")
        return False


# ── reading (the dashboard) ──────────────────────────────────────────────

def _open_reader() -> Optional[sqlite3.Connection]:
    path = db_path()
    if not path.exists():
        return None
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=_TIMEOUT)
    conn.row_factory = sqlite3.Row
    return conn


def daily_rows(since: str) -> list[dict]:
    """Rows grouped by UTC day, case, run, command, user, provider and
    model, from the ISO date `since` on. A missing file reads as empty; a
    locked or corrupt one raises, so the page says so instead of showing
    nothing."""
    conn = _open_reader()
    if conn is None:
        return []
    try:
        rows = conn.execute(
            "SELECT substr(ts, 1, 10) AS day, case_id, run_id, command, "
            "started_by, provider, model, COUNT(*) AS calls, "
            "SUM(input_tokens) AS input, SUM(output_tokens) AS output, "
            "SUM(cached_tokens) AS cached, SUM(reasoning_tokens) AS reasoning, "
            "SUM(CASE WHEN usage_reported = 0 THEN 1 ELSE 0 END) AS unreported, "
            "MIN(ts) AS first_ts FROM llm_usage WHERE ts >= ? "
            "GROUP BY day, case_id, run_id, command, started_by, provider, model",
            (since,)).fetchall()
    except sqlite3.OperationalError as exc:
        if "no such table" in str(exc):
            return []
        raise
    finally:
        conn.close()
    return [dict(r) for r in rows]


def totals(case_id: str, run_id: str = "") -> dict:
    """Input, output and cached tokens and the number of calls the ledger
    holds for a case, or for one run of it (the case/run index answers it).
    A missing ledger reads as zeros."""
    out = {"input_tokens": 0, "output_tokens": 0, "cached_tokens": 0, "calls": 0}
    conn = _open_reader()
    if conn is None:
        return out
    sql = ("SELECT COUNT(*), SUM(input_tokens), SUM(output_tokens), SUM(cached_tokens) "
           "FROM llm_usage WHERE case_id = ?")
    args: list = [case_id]
    if run_id:
        sql += " AND run_id = ?"
        args.append(run_id)
    try:
        row = conn.execute(sql, args).fetchone()
    except sqlite3.OperationalError as exc:
        if "no such table" in str(exc):
            return out
        raise
    finally:
        conn.close()
    out.update(calls=int(row[0] or 0), input_tokens=int(row[1] or 0),
               output_tokens=int(row[2] or 0), cached_tokens=int(row[3] or 0))
    return out


def run_keys() -> set[tuple[str, str]]:
    """Every (case id, run id) the ledger has rows for, and every run it
    settled: imported from a case folder, or deleted by the user."""
    conn = _open_reader()
    if conn is None:
        return set()
    try:
        rows = conn.execute("SELECT case_id, run_id FROM llm_usage UNION "
                            "SELECT case_id, run_id FROM settled_runs").fetchall()
    except sqlite3.OperationalError as exc:
        if "no such table" in str(exc):
            return set()
        raise
    finally:
        conn.close()
    return {(r["case_id"], r["run_id"]) for r in rows}


def import_run(case_id: str, run_id: str, rows: list[dict]) -> bool:
    """Add a past run's calls unless the ledger already knows the run: it has
    rows for it (recorded as it ran) or settled it before. True when added;
    the run is settled either way it was added, even with no calls."""
    conn = _connect()
    try:
        with _immediate(conn):
            known = conn.execute(
                "SELECT 1 FROM llm_usage WHERE case_id = ? AND run_id = ? UNION ALL "
                "SELECT 1 FROM settled_runs WHERE case_id = ? AND run_id = ? LIMIT 1",
                (case_id, run_id, case_id, run_id)).fetchone()
            if known:
                return False
            conn.executemany(_INSERT, [(
                r["ts"], case_id, run_id, str(r.get("command") or ""),
                str(r.get("started_by") or ""), str(r.get("role") or ""),
                str(r.get("provider") or ""), str(r.get("model") or ""),
                int(r.get("input_tokens") or 0), int(r.get("output_tokens") or 0),
                int(r.get("cached_tokens") or 0), int(r.get("reasoning_tokens") or 0),
                1 if r.get("usage_reported", True) else 0,
                r.get("status") if r.get("status") in STATUSES else "ok")
                for r in rows])
            conn.execute("INSERT INTO settled_runs (case_id, run_id, how, row_count, ts) "
                         "VALUES (?, ?, 'imported', ?, ?)",
                         (case_id, run_id, len(rows), _now()))
        return True
    finally:
        conn.close()


def relabel_provider(old: str, new: str, model: str) -> int:
    """Move one model's rows from one provider label to another."""
    path = db_path()
    if not path.exists():
        return 0
    conn = _connect()
    try:
        cur = conn.execute("UPDATE llm_usage SET provider = ? WHERE provider = ? "
                           "AND model = ?", (new, old, model))
        return int(cur.rowcount)
    finally:
        conn.close()


def models_seen() -> list[tuple[str, str]]:
    conn = _open_reader()
    if conn is None:
        return []
    try:
        rows = conn.execute("SELECT DISTINCT provider, model FROM llm_usage "
                            "ORDER BY provider, model").fetchall()
    except sqlite3.OperationalError as exc:
        if "no such table" in str(exc):
            return []
        raise
    finally:
        conn.close()
    return [(r["provider"], r["model"]) for r in rows]


def clear(before: Optional[str] = None) -> int:
    """Remove every row, or the rows before an ISO date (UTC). The runs the
    removed rows belong to are settled, so the history import never adds
    them back. A locked or unreadable ledger raises: a clear that did
    nothing must not read as done."""
    path = db_path()
    if not path.exists():
        return 0
    where, args = ("WHERE ts < ?", (date.fromisoformat(before).isoformat(),)) \
        if before else ("", ())
    conn = _connect()
    try:
        with _immediate(conn):
            conn.execute(
                "INSERT OR IGNORE INTO settled_runs (case_id, run_id, how, row_count, ts) "
                f"SELECT DISTINCT case_id, run_id, 'deleted', 0, ? FROM llm_usage {where}",
                (_now(), *args))
            cur = conn.execute(f"DELETE FROM llm_usage {where}", args)
        return int(cur.rowcount)
    finally:
        conn.close()


# ── periods, prices, aggregation ─────────────────────────────────────────

def price_key(provider: str, model: str) -> str:
    return f"{provider}|{model}"


def period_key(day: str, period: str) -> str:
    """`YYYY-MM`, or the ISO week `YYYY-Www` with the ISO year."""
    if period == "week":
        iso_year, iso_week, _ = date.fromisoformat(day).isocalendar()
        return f"{iso_year}-W{iso_week:02d}"
    return day[:7]


def window_start(period: str, months: int, today: Optional[date] = None) -> date:
    """The first day of the oldest month in the window, or the Monday of
    the week that day falls in."""
    today = today or datetime.now(timezone.utc).date()
    months = max(1, min(int(months), 60))
    year, month = today.year, today.month - (months - 1)
    while month <= 0:
        year -= 1
        month += 12
    first = date(year, month, 1)
    if period == "week":
        return first - timedelta(days=first.weekday())
    return first


def row_cost(row: dict, prices: dict) -> Optional[float]:
    """Cost of an aggregated row at today's prices, or None without a price.
    Cached tokens sit inside the input count on OpenAI-compatible endpoints
    and are priced at the cached rate; the clamp covers a gateway that
    reports them outside the count."""
    p = prices.get(price_key(row.get("provider", ""), row.get("model", "")))
    if not p:
        return None
    p_in = float(p.get("input") or 0.0)
    p_out = float(p.get("output") or 0.0)
    cached_price = p.get("cached")
    p_cached = p_in if cached_price in (None, "") else float(cached_price)
    inp = int(row.get("input") or 0)
    cached = int(row.get("cached") or 0)
    out = int(row.get("output") or 0)
    return (max(inp - cached, 0) * p_in + cached * p_cached + out * p_out) / 1e6


def _bucket() -> dict:
    return {"calls": 0, "input": 0, "output": 0, "cached": 0, "reasoning": 0,
            "unreported": 0, "cost": 0.0, "unpriced": 0}


def _add(bucket: dict, row: dict, cost: Optional[float]) -> None:
    for k in ("calls", "input", "output", "cached", "reasoning", "unreported"):
        bucket[k] += int(row.get(k) or 0)
    if cost is None:
        bucket["unpriced"] += int(row.get("calls") or 0)
    else:
        bucket["cost"] += cost


def aggregate(rows: list[dict], period: str, prices: dict) -> dict:
    """Periods newest first, each with its runs newest first; the per-case
    table; the total. A row counts in the period of its own day."""
    periods: dict[str, dict] = {}
    cases: dict[str, dict] = {}
    total = _bucket()
    unpriced_models: set[str] = set()
    for row in rows:
        cost = row_cost(row, prices)
        key = price_key(row.get("provider", ""), row.get("model", ""))
        if cost is None:
            unpriced_models.add(key)
        pk = period_key(row["day"], period)
        per = periods.setdefault(pk, {"key": pk, "runs": {}, **_bucket()})
        rk = (row["case_id"], row["run_id"], row["command"], row["started_by"])
        run = per["runs"].setdefault(rk, {
            "case_id": row["case_id"], "run_id": row["run_id"],
            "command": row["command"], "started_by": row["started_by"],
            "started": row["first_ts"], "models": set(), **_bucket()})
        run["models"].add(key)
        run["started"] = min(run["started"], row["first_ts"])
        _add(run, row, cost)
        _add(per, row, cost)
        case = cases.setdefault(row["case_id"], {"case_id": row["case_id"],
                                                 "runs": set(), **_bucket()})
        case["runs"].add(rk)
        _add(case, row, cost)
        _add(total, row, cost)
    out_periods = []
    for pk in sorted(periods, reverse=True):
        per = periods[pk]
        runs = sorted(per["runs"].values(), key=lambda r: r["started"], reverse=True)
        for r in runs:
            r["models"] = sorted(r["models"])
        per["runs"] = runs
        out_periods.append(per)
    all_runs: set = set()
    out_cases = []
    for case in sorted(cases.values(), key=lambda c: c["cost"], reverse=True):
        all_runs |= case["runs"]
        case["runs"] = len(case["runs"])
        out_cases.append(case)
    total["runs"] = len(all_runs)
    return {"period": period, "periods": out_periods, "cases": out_cases,
            "total": total, "unpriced_models": sorted(unpriced_models)}
