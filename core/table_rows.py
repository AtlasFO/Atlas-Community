"""The shared vocabulary of tabular tool results.

Which keys of a search result echo the request and show no row, which
columns of a parsed table hold its time, and how a row's time is read as
one sortable string. The column names are format knowledge, the way a
parser's column order is: what the published tools (Plaso l2tcsv, EvtxECmd,
MFTECmd, PECmd, RECmd, common SIEM exports) call their time columns. Nothing
here says what to look for in a table.

Import rule: ``core.indicators`` imports this module, so this module never
imports ``core.indicators``. Its one dependency is the timestamp parser of
``core.evidence_index``, which imports neither.
"""
from __future__ import annotations

import collections
import re
from collections.abc import Iterable, Sequence
from datetime import datetime
from typing import Any

from core.evidence_index import _parse_timestamp

# Keys of a search result that repeat or summarise the request's terms and
# show no row: the request echo every search tool returns, and the term
# summary and distribution lines of the table view (whose ``by_term`` names
# the terms). A reader strips them before deciding what a call printed, so a
# term that matched no row is never read as seen in the evidence.
ECHO_KEYS: frozenset[str] = frozenset({
    "query", "sanitized_query", "pattern", "patterns", "term", "terms", "keyword",
    "keywords", "search", "needle", "regex", "expression",
    "terms_with_no_row", "terms_matched_not_returned", "terms_not_settled", "distribution",
})

# The time columns of published tool outputs, lower-cased, in preference
# order: generic names, then the EZ tools' names (EvtxECmd, PECmd, RECmd,
# MFTECmd), then SIEM and session-broker exports. Plaso's l2tcsv splits the
# moment over ``date`` and ``time``, which time_columns joins. A record
# counter (``recordid``) is not a time and is not here: a profile that read
# it as one reported a record-id span as the file's time span.
TIME_COLUMNS: tuple[str, ...] = (
    "datetime", "timestamp", "@timestamp", "time", "date",
    "timecreated", "lastrun", "lastwritetimestamp", "created0x10", "lastmodified0x10",
    "startdatetime", "devicedatetime", "startdate", "createddate", "starttime",
)


def _clean(header: str) -> str:
    return str(header or "").lstrip("\ufeff").strip().lower()


def time_columns(headers: Sequence[str],
                 sample: Iterable[Sequence[str]] = ()) -> list[int]:
    """The indices of the columns that hold a row's time, in the order they
    are joined: Plaso's ``date`` plus ``time`` pair; else the first name of
    TIME_COLUMNS present; else the first header containing "time" or "date"
    whose sampled values all parse (at least one non-empty value; without a
    sample this rule finds nothing). Empty when the table has no time."""
    names = [_clean(h) for h in headers]
    if "date" in names and "time" in names:
        return [names.index("date"), names.index("time")]
    for name in TIME_COLUMNS:
        if name in names:
            return [names.index(name)]
    for i, name in enumerate(names):
        if "time" not in name and "date" not in name:
            continue
        cells = [str(row[i]).strip() for row in sample if i < len(row)]
        values = [c for c in cells if c]
        if values and all(_parse_timestamp(v) for v in values):
            return [i]
    return []


def row_time(row: Sequence[str], cols: Sequence[int]) -> str:
    """The moment a row states in its time columns, as an ISO-8601 string
    (so a window or an order over rows is a string comparison), or "" when
    the cells hold no readable time. The cells are joined with a space, so
    Plaso's date and time read as one moment. A stated offset is converted
    to UTC; a slashed date reads month first (US order), the parser's
    ceiling for a day-first export."""
    cells = [str(row[i]).strip() for i in cols if i < len(row)]
    text = " ".join(c for c in cells if c)
    if not text:
        return ""
    return _parse_timestamp(text) or ""


# ── the row view: selection, layout, distribution ───────────────────────────
#
# What the toolbox renders of a result's row list so that it fits the
# session's limit by construction: which rows to show when not all fit, how
# a row becomes one line, and where the rows lie in time before any row is
# shown. Everything below is computed from the rows at hand; nothing names
# an artefact, an event id or a host.

# A row's own bookkeeping, never a column of the table.
INTERNAL_KEYS = frozenset({"_sheet", "_row", "_matched_columns", "_n", "_tier", "_why"})
# More column roles by header name, format knowledge like TIME_COLUMNS: the
# host, the path and the source columns of published tool outputs, and the
# bookkeeping columns of l2tcsv and EvtxECmd that say nothing about the
# record (dropped from the default line, shown as col~"..." on a row whose
# match lies in them).
HOST_COLUMNS = frozenset({"host", "hostname", "computer", "computername", "device",
                          "devicename", "machine", "machinename"})
PATH_COLUMNS = frozenset({"filename", "path", "fullpath", "filepath", "sourcefile",
                          "sourcefilename", "parentpath", "keypath", "hivepath"})
SOURCE_COLUMNS = ("source", "sourcetype", "channel", "provider", "eventid",
                  "logname", "parser", "datatype", "eventtype")
LOW_VALUE_COLUMNS = frozenset({"timezone", "macb", "short", "version", "inode", "notes",
                               "format", "extra", "recordnumber", "eventrecordid", "processid",
                               "threadid", "level", "keywords", "extradataoffset",
                               "hiddenrecord", "chunknumber"})
_EMPTY_CELLS = frozenset({"", "-", "None", "null"})


def _fold(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", str(name).lower())


def source_columns(headers: Sequence[str]) -> list[str]:
    """The columns that define a row's source group: Plaso's ``source`` plus
    ``sourcetype``, EvtxECmd's ``Channel`` plus ``EventId``, else up to two
    of the generic source names."""
    folded = {_fold(h): h for h in headers}
    if "source" in folded and "sourcetype" in folded:
        return [folded["source"], folded["sourcetype"]]
    if "channel" in folded and "eventid" in folded:
        return [folded["channel"], folded["eventid"]]
    return [folded[n] for n in SOURCE_COLUMNS if n in folded][:2]


def time_column_names(headers: Sequence[str], sample: Iterable[Sequence[str]] = ()) -> list[str]:
    """time_columns as header names."""
    return [headers[i] for i in time_columns(headers, sample)]


def cell(value: Any) -> str:
    """A value as a cell's text: "" only for a missing value (None) and an
    empty string. A JSON row's 0, 0.0 and False are values, never empty."""
    return "" if value is None else str(value)


def row_moment(row: dict, tcols: Sequence[str]) -> str:
    """The row's time as "YYYY-MM-DD HH:MM:SS", or "" (row_time over the
    named columns of a mapping row)."""
    cells = [cell(row.get(c)) for c in tcols]
    iso = row_time(cells, list(range(len(cells)))) if any(cells) else ""
    return iso.replace("T", " ") if iso else ""


def record_moment(row: dict) -> str:
    """The moment a mapping row (a csv.DictReader record) states, as
    "YYYY-MM-DD HH:MM:SS", or "": its time columns picked from its own
    headers (a leading byte-order mark ignored) and its own cells as the
    sample."""
    headers = [k.lstrip("\ufeff") if isinstance(k, str) else str(k) for k in row]
    cleaned = dict(zip(headers, row.values()))
    return row_moment(cleaned, time_column_names(headers, [[cell(v) for v in cleaned.values()]]))


def split_alternatives(pattern: str | None, ignore_case: bool = True) -> list[tuple[str, re.Pattern]]:
    """The top-level alternatives of a search pattern with their regexes, as
    the table tool splits them; one entry for a single-term pattern, none
    for a pattern that does not compile."""
    if not pattern:
        return []
    flags = re.IGNORECASE if ignore_case else 0
    try:
        from tools.tabular import _alternatives
        alts = _alternatives(pattern, flags)
    except Exception:  # noqa: BLE001
        alts = None
    if alts:
        return alts
    try:
        return [(pattern, re.compile(pattern, flags))]
    except re.error:
        return []


def term_set(row: Any, alts: list[tuple[str, re.Pattern]]) -> set[int]:
    """The alternatives that match a row (its cells, or its text)."""
    cells = ([str(v) for k, v in row.items() if k not in INTERNAL_KEYS and v]
             if isinstance(row, dict) else [str(row)])
    return {i for i, (_src, rx) in enumerate(alts) if any(rx.search(c) for c in cells)}


def select(n: int, times: list[str | None], term_sets: list[set[int]], groups: list[str],
           k: int, n_terms: int) -> list[tuple[int, int]]:
    """``(tier, index)`` pairs of up to ``k`` rows out of ``n``: tier 1 the
    first row of each term with rows, rarest term first; tier 2 the first
    row of each source group not yet shown, smallest group first; tier 3
    the last row of each term, rarest first; tier 4 rows spread evenly over
    the time order of the rest. A term with few rows is specific and keeps
    its anchors when room is short; a frequent one is described by its
    count and span in the term lines. When the set is larger than the room,
    a third of the room (at least three rows) stays for the spread, so a
    cluster inside a frequent term is not crowded out by anchors."""
    order = sorted(range(n), key=lambda i: (times[i] is None, times[i] or "", i))
    chosen: list[tuple[int, int]] = []
    seen: set[int] = set()
    reserve = max(3, k // 3) if n > k else 0
    anchor_room = max(0, k - reserve)

    def add(i: int | None, tier: int, limit: int) -> None:
        if i is not None and i not in seen and len(chosen) < limit:
            seen.add(i)
            chosen.append((tier, i))

    count = [sum(1 for s in term_sets if a in s) for a in range(n_terms)]
    by_rarity = sorted((a for a in range(n_terms) if count[a]), key=lambda a: (count[a], a))
    firsts: dict[str, int] = {}
    for i in order:
        firsts.setdefault(groups[i], i)
    gsize = collections.Counter(groups)
    for a in by_rarity:
        add(next((i for i in order if a in term_sets[i]), None), 1, anchor_room)
    for _g, i in sorted(firsts.items(), key=lambda kv: (gsize[kv[0]], kv[1])):
        add(i, 2, anchor_room)
    for a in by_rarity:
        add(next((i for i in reversed(order) if a in term_sets[i]), None), 3, anchor_room)
    free = k - len(chosen)
    if free > 0:
        rest = [i for i in order if i not in seen]
        if rest:
            if free >= len(rest):
                picks = rest
            elif free == 1:
                picks = [rest[len(rest) // 2]]
            else:
                picks = [rest[round(j * (len(rest) - 1) / (free - 1))] for j in range(free)]
            for i in dict.fromkeys(picks):
                add(i, 4, k)
    return chosen


def clip_head(s: str, n: int) -> str:
    return s if len(s) <= n else s[:max(1, n - 1)] + "…"


def clip_tail(s: str, n: int) -> str:
    return s if len(s) <= n else "…" + s[-max(1, n - 1):]


def kwic(s: str, rx: re.Pattern | None, n: int) -> str:
    """The cell's head and, when the match lies past the first half of the
    room, a window around the first match: the head names the record (an
    event log message begins with its event id), the window shows why the
    row matched."""
    if len(s) <= n:
        return s
    m = rx.search(s) if rx is not None else None
    if not m or m.start() < n // 2:
        return clip_head(s, n)
    head = max(24, n * 35 // 100)
    room = n - head - 3
    start = max(head, min(m.start() - room // 3, len(s) - room))
    end = start + room
    return s[:head] + " … " + s[start:end] + ("…" if end < len(s) else "")


def _is_head_of(a: str, b: str) -> bool:
    a = a.rstrip(".… ").strip()
    return bool(a) and a != b and b.startswith(a)


class Layout:
    """The column plan for one result's rows: the time columns, the columns
    shown on a line, the values the same in every row, the per-row budget."""

    def __init__(self, rows: list[dict], bound: int):
        headers: list[str] = []
        for r in rows:
            for h in r:
                if h not in INTERNAL_KEYS and h not in headers:
                    headers.append(h)
        self.headers = headers
        sample = [[cell(r.get(h)) for h in headers] for r in rows[:50]]
        self.tcols = time_column_names(headers, sample)
        self.scols = source_columns(headers)
        self.same: dict[str, str] = {}
        shown: list[str] = []
        for h in headers:
            if h in self.tcols:
                continue
            vals = [cell(r.get(h)) for r in rows]
            if not [v for v in vals if v.strip() not in _EMPTY_CELLS]:
                continue
            if len(set(vals)) == 1:
                if _fold(h) not in LOW_VALUE_COLUMNS or _fold(h) == "timezone":
                    self.same[h] = vals[0]
                continue
            if _fold(h) in LOW_VALUE_COLUMNS:
                continue
            shown.append(h)
        # The source columns read as one field, joined the way Plaso prints
        # them, only while each of them is short: the joined cell is written
        # with the short cells. A long one (an event log channel's full name)
        # keeps every source column its own, the long one tail-clipped like
        # a path (its end names the log), so no source value is lost.
        joined = [h for h in self.scols if h in shown]
        self.joined = joined if len(joined) > 1 and all(
            max((len(cell(r.get(h))) for r in rows), default=0) <= 32 for h in joined) else []
        if self.joined:
            shown = [h for h in shown if h not in self.joined[1:]]
        # A column whose every value begins another shown column's value adds
        # nothing (l2tcsv's short is the head of desc).
        drop: set[str] = set()
        for h in shown:
            for o in shown:
                if o == h or o in drop:
                    continue
                if all(_is_head_of(cell(r.get(h)), cell(r.get(o))) for r in rows):
                    drop.add(h)
                    break
        self.cols = [h for h in shown if h not in drop]
        self.row_budget = max(160, min(360, bound // 34))
        lens = {h: max((len(cell(r.get(h))) for r in rows), default=0) for h in self.cols}
        self.short = [h for h in self.cols if lens[h] <= 32]
        self.paths = [h for h in self.cols if (_fold(h) in PATH_COLUMNS or h in self.scols) and h not in self.short]
        self.long = [h for h in self.cols if h not in self.short and h not in self.paths]

    def header_line(self) -> str:
        names = (["time"] if self.tcols else []) + [
            "/".join(self.joined) if (self.joined and h == self.joined[0]) else h for h in self.cols]
        return " | ".join(names)

    def line(self, row: dict, n: int | None, rx: re.Pattern | None) -> str:
        parts: list[str] = []
        if self.tcols:
            parts.append(row_moment(row, self.tcols) or " ".join(cell(row.get(c)) for c in self.tcols) or "-")
        budget = self.row_budget - (len(parts[0]) if parts else 0)
        fixed = {h: cell(row.get(h)) or "-" for h in self.short}
        if self.joined and self.joined[0] in fixed:
            fixed[self.joined[0]] = "/".join(cell(row.get(c)) or "-" for c in self.joined)
        budget -= sum(len(v) + 3 for v in fixed.values())
        matched = set(row.get("_matched_columns") or [])
        cells: dict[str, str] = {}
        for h in self.paths:
            cells[h] = clip_tail(cell(row.get(h)) or "-", 64)
            budget -= len(cells[h]) + 3
        if self.long:
            # A matched long cell gets the larger share and a window around
            # its match; the others share what is left.
            first = next((h for h in self.long if h in matched), self.long[0])
            share_first = max(60, int(budget * (0.7 if len(self.long) > 1 else 1.0)))
            for h in self.long:
                v = cell(row.get(h)) or "-"
                cap = share_first if h == first else max(24, (budget - share_first) // max(1, len(self.long) - 1))
                cells[h] = kwic(v, rx, cap) if h in matched else clip_head(v, cap)
        for h in self.cols:
            parts.append(fixed[h] if h in fixed else cells.get(h, "-"))
        extra = [f"{h}~{kwic(cell(row.get(h)), rx, 80)}" for h in matched
                 if h not in self.cols and h not in self.tcols and h in row and _fold(h) in LOW_VALUE_COLUMNS]
        text = " | ".join(parts + extra)
        return (f"#{n} " if n is not None else "") + text

    def body(self, row: dict, rx: re.Pattern | None) -> tuple[str, str]:
        """``(time, the rest of the line)`` for grouping."""
        full = self.line(row, None, rx)
        if self.tcols and " | " in full:
            t, rest = full.split(" | ", 1)
            return t, rest
        return "", full


def _period(times: list[str]) -> str:
    """" every <gap>" when the gaps between the distinct times are regular."""
    try:
        ts = sorted({datetime.fromisoformat(t) for t in times})
    except (TypeError, ValueError):
        return ""
    gaps = [(b - a).total_seconds() for a, b in zip(ts, ts[1:])]
    if len(gaps) < 2 or min(gaps) <= 0:
        return ""
    mean = sum(gaps) / len(gaps)
    if max(abs(g - mean) for g in gaps) > 0.1 * mean:
        return ""
    for unit, sec in (("d", 86400), ("h", 3600), ("min", 60), ("s", 1)):
        if mean >= sec:
            return f" every {mean / sec:.3g}{unit}"
    return ""


def collapse(lay: Layout, rows: list[dict], idx: list[int], order_rank: dict[int, int],
             rx: re.Pattern | None) -> tuple[list[str], set[int]]:
    """Lines for the rows ``idx`` (in time order), and the indices shown
    inside a group rather than on a line of their own. Adjacent rows
    identical in every shown cell but the time share one line: the ordinals,
    the count, the first and last time, the gap when the ordinals are
    contiguous and the gaps regular, then the first row's cells. The count
    comes first and the gap last, so "x13 ... every 1d" reads as thirteen
    rows before it reads as daily."""
    out: list[str] = []
    group: list[int] = []
    members: set[int] = set()

    def flush() -> None:
        if not group:
            return
        if len(group) == 1:
            out.append(lay.line(rows[group[0]], order_rank[group[0]], rx))
        else:
            members.update(group[1:])
            ords = [order_rank[i] for i in group]
            times = [lay.body(rows[i], rx)[0] for i in group]
            contiguous = ords == list(range(ords[0], ords[0] + len(ords)))
            span = f"#{ords[0]}-#{ords[-1]}" if contiguous else "#" + ",#".join(map(str, ords))
            per = _period(times) if contiguous else ""
            out.append(f"{span} x{len(group)} {times[0]} .. {times[-1]}{per} | {lay.body(rows[group[0]], rx)[1]}")
        group.clear()

    prev = None
    for i in idx:
        sig = lay.body(rows[i], rx)[1]
        if prev is not None and sig != prev:
            flush()
        group.append(i)
        prev = sig
    flush()
    return out, members


def _peak(day_counts: collections.Counter):
    """``(day, count)`` when one day stands out inside a source or a term:
    the single largest count, at least two rows and at least twice the
    median day; None for an even spread. A presentation constant, the same
    for every case."""
    if len(day_counts) < 2:
        return None
    ranked = sorted(day_counts.items(), key=lambda kv: (-kv[1], kv[0]))
    vals = sorted(day_counts.values())
    median = vals[len(vals) // 2]
    (d, c), (_d2, c2) = ranked[0], ranked[1]
    return (d, c) if c >= 2 and c > c2 and c >= 2 * median else None


def _stand_out_day(timed: list[int], times: list, groups: list[str], term_sets: list[set[int]],
                   days: collections.Counter, median: int):
    """``(day, rows)`` of the one day that stands out, or None: days ranked
    by distinct source groups, then distinct terms, then rows; the first is
    named when it is alone on the first key that separates it from the
    second (for rows: at least twice the median and more than the runner-up).
    Half of all days are above the median, so a rows-only rule would always
    present routine days as peaks."""
    per: dict[str, list] = collections.defaultdict(lambda: [set(), set(), 0])
    for i in timed:
        d = per[times[i][:10]]
        d[0].add(groups[i])
        d[1] |= term_sets[i]
        d[2] += 1
    if len(per) == 1:
        day = next(iter(per))
        return day, days[day]
    ranked = sorted(per.items(), key=lambda kv: (-len(kv[1][0]), -len(kv[1][1]), -kv[1][2], kv[0]))
    (d1, a), (_d2, b) = ranked[0], ranked[1]
    if len(a[0]) != len(b[0]) or len(a[1]) != len(b[1]):
        return d1, days[d1]
    if a[2] >= 2 * median and a[2] > b[2]:
        return d1, days[d1]
    return None


def distribution(idx: Iterable[int], times: list, groups: list[str], term_sets: list[set[int]],
                 alts: list[tuple[str, re.Pattern]], basis: str) -> dict | None:
    """Where the rows ``idx`` lie in time: the span, the counts per day (per
    month beyond 31 days), the one day that stands out, per source group
    (rarest first) its count, span and own stand-out day, per term its
    stand-out day and sources. ``basis`` says what the rows are ("all
    matching rows", "the returned rows only"). None without a timed row."""
    idx = list(idx)
    timed = [i for i in idx if times[i]]
    if not timed:
        return None
    days = collections.Counter(times[i][:10] for i in timed)
    unit = "day" if len(days) <= 31 else "month"
    counts = days if unit == "day" else collections.Counter(times[i][:7] for i in timed)
    vals = sorted(days.values())
    median = vals[len(vals) // 2]
    # One pass groups the rows by source and by term (a count pass hands
    # every match of a large file here).
    of_group: dict[str, list[int]] = collections.defaultdict(list)
    of_term: dict[int, list[int]] = collections.defaultdict(list)
    for i in timed:
        of_group[groups[i]].append(i)
        for a in term_sets[i]:
            of_term[a].append(i)
    by_source = []
    for g in sorted(of_group, key=lambda g: (len(of_group[g]), g)):
        mine = of_group[g]
        gd = collections.Counter(times[i][:10] for i in mine)
        by_source.append({"source": g or "-", "rows": len(mine), "first": min(times[i] for i in mine),
                          "last": max(times[i] for i in mine), "stands_out": _peak(gd), "days": len(gd)})
    by_term: dict[str, dict] = {}
    for a, (src, _rx) in enumerate(alts if len(alts) > 1 else []):
        mine = of_term.get(a, [])
        if mine:
            td = collections.Counter(times[i][:10] for i in mine)
            srcs = collections.Counter(groups[i] for i in mine)
            by_term[src] = {"stands_out": _peak(td), "days": len(td),
                            "sources": dict(srcs.most_common(3))}
    return {"basis": basis, "rows": len(timed), "untimed": len(idx) - len(timed), "median": median,
            "days": len(days), "first": min(times[i] for i in timed), "last": max(times[i] for i in timed),
            "unit": unit, "counts": sorted(counts.items()),
            "stands_out": _stand_out_day(timed, times, groups, term_sets, days, median),
            "by_source": by_source, "by_term": by_term}


def distribution_lines(d: dict | None, level: int = 0) -> list[str]:
    """The distribution as lines for the view. Level 0 is complete; level 1
    keeps the ten days with the most rows and six source lines; level 2
    keeps the span, the stand-out line and three source lines. Source lines
    run rarest first at every level, so a rare source is never the one that
    is dropped. Every date is written in full."""
    if not d:
        return []
    counts = d["counts"]
    if level >= 1 and len(counts) > 10:
        keep = {k for k, _v in sorted(counts, key=lambda kv: -kv[1])[:10]}
        counts = [kv for kv in counts if kv[0] in keep]
        per = f"per {d['unit']}, the ten with the most rows: "
    else:
        per = f"per {d['unit']}: "
    head = f"{d['rows']} rows {d['first']} .. {d['last']} ({d['basis']})"
    if d["untimed"]:
        head += f"; {d['untimed']} without a readable time"
    lines = [head]
    if d["stands_out"]:
        k0, v0 = d["stands_out"]
        lines.append(f"day that stands out: {k0} ({v0} rows; most distinct sources and terms; "
                     f"median {d['median']} rows per day over {d['days']} days)")
    elif d["days"] > 1:
        lines.append(f"no day stands out: {d['days']} days, median {d['median']} rows per day")
    if level < 2:
        lines.append(per + ", ".join(f"{k} {v}" for k, v in counts))
    srcs = d["by_source"][: (6 if level == 1 else 3 if level >= 2 else 12)]
    for sd in srcs:
        span = sd["first"] if sd["first"] == sd["last"] else f"{sd['first']} .. {sd['last']}"
        busy = (f", stands out {sd['stands_out'][0]} ({sd['stands_out'][1]})" if sd["stands_out"]
                else (f", on {sd['days']} days" if sd["days"] > 1 else ""))
        lines.append(f"source {sd['source']}: {sd['rows']} row{'s' if sd['rows'] != 1 else ''} {span}{busy}")
    more = len(d["by_source"]) - len(srcs)
    if more > 0:
        lines.append(f"{more} more sources")
    return lines


def term_lines(alts: list[tuple[str, re.Pattern]], times: list, groups: list[str],
               term_sets: list[set[int]], by_term: dict | None) -> tuple[list[str], list[str]]:
    """One line per term with rows over the rows at hand (its count, span,
    stand-out day and top sources), and the terms without a returned row."""
    lines: list[str] = []
    empty: list[str] = []
    for a, (src, _rx) in enumerate(alts):
        idx = [i for i in range(len(term_sets)) if a in term_sets[i]]
        if not idx:
            empty.append(src)
            continue
        ts = sorted(t for t in (times[i] for i in idx) if t)
        first, last = (ts[0], ts[-1]) if ts else ("", "")
        span = f" {first}..{last}" if first and last and first != last else (f" {first}" if first else "")
        srcs = collections.Counter(groups[i] for i in idx)
        top = ", ".join(f"{g or '-'} {c}" for g, c in srcs.most_common(3))
        busy = ""
        meta = (by_term or {}).get(src)
        if meta and meta["days"] > 1:
            busy = (f", stands out {meta['stands_out'][0]} ({meta['stands_out'][1]})" if meta["stands_out"]
                    else f", on {meta['days']} days")
        lines.append(clip_head(f"{src}: {len(idx)} row{'s' if len(idx) != 1 else ''}{span}{busy} ({top})", 240))
    return lines, empty


def count_term_lines(terms: list[dict], by_term: dict | None) -> list[str]:
    """One line per term with rows from the tool's own count of every match:
    its count, span, stand-out day and top sources."""
    lines: list[str] = []
    for t in terms:
        n = int(t.get("rows") or 0)
        if not n:
            continue
        first, last = str(t.get("first") or ""), str(t.get("last") or "")
        span = f" {first}..{last}" if first and last and first != last else (f" {first}" if first else "")
        meta = (by_term or {}).get(t.get("term"))
        busy = top = ""
        if meta:
            if meta.get("days", 0) > 1:
                busy = (f", stands out {meta['stands_out'][0]} ({meta['stands_out'][1]})" if meta.get("stands_out")
                        else f", on {meta['days']} days")
            top = " (" + ", ".join(f"{g or '-'} {c}" for g, c in (meta.get("sources") or {}).items()) + ")"
        lines.append(clip_head(f"{t.get('term')}: {n} row{'s' if n != 1 else ''}{span}{busy}{top}", 240))
    return lines
