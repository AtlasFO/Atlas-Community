"""Stacking (C2 item 3, ATLAS_STACK): count a column's values across the
units of a population (by default the hosts) and read the values few units
hold. The model chooses the column, the filter and the population; code
holds no list of dimensions to stack.

Populations: tables (one, a glob or a list; each table's host from the
Evidence Links, else a host column of its rows), the contents index
(``"index"``: host, path, directory, name, extension, size, mtime,
deleted) and a prior call's saved output (``"call:N"``: a JSON array or a
table; nested ``__children`` are flattened).

Over several tables a delimited text table is counted in one native pass
(gawk splitting the fields and keeping one counter per distinct key,
behind a fixed-string grep when the filter names a literal value); Python
then reads the distinct keys only. Without gawk, several tables are
counted only when a literal filter lets grep narrow them first; otherwise
the call is refused with the reason. One table keeps the row loop
table_pivot always used."""
from __future__ import annotations

import csv
import glob as _glob
import json
import os
import re
import shutil
import subprocess
from typing import Any, Iterable, Optional

INDEX_COLUMNS = ("host", "path", "directory", "name", "extension", "size", "mtime", "deleted")
_SEP = "\x1f"
_REC = "\x1e"


def stack_on() -> bool:
    from core.envfile import env_flag
    return env_flag("ATLAS_STACK", True)


def population_word(tool_name: str, key: str, value: object) -> bool:
    """A table_pivot ``path`` that names a population, not one file: the
    contents index, a prior call's output or a glob. The path gates leave it
    to the stack, which resolves it against the case itself."""
    if key != "path" or not str(tool_name or "").endswith("table_pivot") or not isinstance(value, str):
        return False
    v = value.strip()
    return stack_on() and (v == "index" or v.startswith("call:") or any(c in v for c in "*?["))


def _unit_names(units: set[str]) -> list[str]:
    return sorted(units)[:5]


class _Acc:
    """Per group: the units holding it, its rows, first and last time."""

    def __init__(self) -> None:
        self.groups: dict[tuple, dict[str, Any]] = {}
        self.file_order = False

    def add(self, combo: tuple, unit: str, rows: int = 1, first: str = "", last: str = "",
            ordered: bool = True) -> None:
        g = self.groups.get(combo)
        if g is None:
            if len(self.groups) >= MAX_STACK_KEYS:
                raise TooManyValues("")
            g = self.groups[combo] = {"units": set(), "rows": 0, "first": "", "last": ""}
        g["units"].add(unit or "")
        g["rows"] += rows
        if not ordered:
            # Times not written in an order text sorts by: first and last
            # in file order, never a guessed earliest and latest.
            self.file_order = True
            g["first"] = g["first"] or first
            g["last"] = last or g["last"]
            return
        for t in (first, last):
            if t:
                g["first"] = t if not g["first"] or t < g["first"] else g["first"]
                g["last"] = t if t > g["last"] else g["last"]


def _resolve_tables(case_dir: str, spec: list[str]) -> tuple[list[str], list[str]]:
    """Existing table paths for a list of paths or globs, and the missing."""
    found, missing = [], []
    for s in spec:
        base = s if os.path.isabs(s) else os.path.join(case_dir, s)
        hits = sorted(_glob.glob(base, recursive=True)) if any(c in s for c in "*?[") else (
            [base] if os.path.isfile(base) else [])
        # Only the case's own tables: a list is not seen by the path gates.
        root = os.path.realpath(case_dir) + os.sep
        inside = [h for h in hits if os.path.realpath(h).startswith(root)]
        if inside:
            found += [h for h in inside if os.path.isfile(h) and h not in found]
        else:
            missing.append(s)
    return found, missing


def _rel(case_dir: str, path: str) -> str:
    try:
        rel = os.path.relpath(os.path.realpath(path), os.path.realpath(case_dir))
        return path if rel.startswith("..") else rel.replace(os.sep, "/")
    except ValueError:
        return path


def _index_rows(case_dir: str) -> Iterable[dict[str, str]]:
    from contextlib import closing
    from core.contents_index import _connect, _ext
    con = _connect(case_dir)
    if con is None:
        return
    with closing(con):
        for r in con.execute("SELECT host, path, name, size, mtime, deleted FROM entries "
                             "WHERE origin = 'image' AND is_dir = 0 AND version_of IS NULL"):
            path = str(r["path"] or "")
            yield {"host": str(r["host"] or ""), "path": path, "directory": path.rpartition("/")[0],
                   "name": str(r["name"] or ""), "extension": _ext(path), "size": str(r["size"] or ""),
                   "mtime": str(r["mtime"] or ""), "deleted": str(r["deleted"] or 0)}


def _flatten(items: Any) -> list[dict]:
    """A record list with its nested records, as text cells (the split of
    core.indicators.flat_records)."""
    from core.indicators import flat_records
    return [{k: ("" if v is None else str(v)) for k, v in r.items()} for r in flat_records(items, mark=False)]


def _call_rows(call_id: int) -> tuple[list[dict], str, str]:
    """A prior call's saved output as rows, its host and an error."""
    from core.execution_log import log
    entry = (log.index().by_call_id or {}).get(int(call_id))
    if not isinstance(entry, dict):
        return [], "", f"call {call_id} is not in this run's trace"
    text = ""
    spill = str(entry.get("stdout_file") or "")
    if spill and os.path.isfile(spill):
        try:
            with open(spill, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            text = ""
    text = text or str(entry.get("stdout_excerpt") or entry.get("stdout") or "")
    host = ""
    try:
        from core.provenance import call_provenance
        hosts = list(call_provenance(entry, None).get("hosts") or [])
        host = hosts[0] if len(hosts) == 1 else ""
    except Exception:  # noqa: BLE001
        host = ""
    try:
        data = json.loads(text)
    except ValueError:
        data = None
    if isinstance(data, dict):
        data = next((data[k] for k in ("rows", "hits", "results", "matches", "data") if isinstance(data.get(k), list)),
                    None)
    if isinstance(data, list):
        return _flatten(data), host, ""
    lines = text.splitlines()
    if len(lines) > 1:
        try:
            dialect = csv.Sniffer().sniff("\n".join(lines[:20]), delimiters=",\t;|")
        except csv.Error:
            dialect = csv.excel
        return [dict(r) for r in csv.DictReader(lines, dialect=dialect)], host, ""
    return [], host, f"call {call_id}'s output is neither a JSON array nor a table"


def _gawk() -> str:
    return shutil.which("gawk") or ""


# Per distinct key: rows, the time cells of its first and last row in file
# order and its lexically smallest and largest (ISO times order as text; the
# reader takes the earliest and latest of the four). A key count above
# maxkeys ends the pass with the overflow mark: one call's memory bound.
_AWK = r'''
function uq(s) { if (s ~ /^".*"$/) { s = substr(s, 2, length(s) - 2); gsub(/""/, "\"", s) } return s }
BEGIN {
  nk = split(keycols, K, ","); nt = (timecols == "") ? 0 : split(timecols, T, ",")
  if (delim == "\t") FS = "\t"; else FPAT = "([^" delim "]*)|(\"([^\"]|\"\")*\")"
}
{
  sub(/\r$/, "")
  if (pre) { p = index($0, ":"); if (substr($0, 1, p - 1) == "1") next; $0 = substr($0, p + 1) }
  else if (NR == 1) next
  t = ""; for (i = 1; i <= nt; i++) t = t (i > 1 ? SEP : "") uq($(T[i]))
  if (ws != "" || we != "") {
    tt = uq($(T[1])); if (substr(tt, 11, 1) == "T") tt = substr(tt, 1, 10) " " substr(tt, 12)
    if (tt == "" || (ws != "" && tt < ws) || (we != "" && tt > we)) next
  }
  key = uq($(K[1])); for (i = 2; i <= nk; i++) key = key SEP uq($(K[i]))
  if (!(key in c)) {
    if (++n > maxkeys) { print "\035OVERFLOW"; over = 1; exit 3 }
    f[key] = t; lo[key] = t; hi[key] = t
  }
  c[key]++; l[key] = t
  if (t != "" && (lo[key] == "" || t < lo[key])) lo[key] = t
  if (t > hi[key]) hi[key] = t
}
END { if (over) exit 3; for (k in c) print k REC c[k] REC f[k] REC l[k] REC lo[k] REC hi[k] }
'''

# One call's bound on distinct values (a behaviour guard per call, never a
# cap on a run): a stack over a near-unique column (a path, a time) holds
# one counter per row and would exhaust memory before saying anything
# readable; the call is refused with how to narrow it instead.
MAX_STACK_KEYS = 300_000


class TooManyValues(Exception):
    pass


def _native_table(path: str, headers: list[str], keycols: list[str], timecols: list[str],
                  literal: str, window: Optional[tuple[str, str]] = None
                  ) -> Optional[Iterable[tuple[dict, int, list[list[str]]]]]:
    """One native pass over a delimited text table, streamed: per distinct
    value tuple of ``keycols`` its rows and the time cells of its first,
    last, smallest and largest row. None when gawk cannot stand in (no gawk,
    an encoding or a layout it does not read): the caller decides how else
    to count. Raises TooManyValues past MAX_STACK_KEYS.

    ponytail: counted by line; a quoted cell holding a line break splits
    its row, which then counts under a broken key."""
    from core.input_kind import open_text, text_encoding
    from tools.tabular import _GREP_ENCODINGS, _csv_dialect, _kind
    gawk = _gawk()
    if not gawk or _kind(path) not in ("csv",):
        return None
    encoding = text_encoding(path)
    if encoding not in _GREP_ENCODINGS:
        return None
    try:
        with open_text(path, newline="") as fh:
            sample = fh.read(65536)
    except OSError:
        return None
    delim = str(getattr(_csv_dialect(sample), "delimiter", ",") or ",")
    idx = {h: i + 1 for i, h in enumerate(headers)}
    if any(c not in idx for c in keycols + timecols):
        return None
    env = {**os.environ, "LC_ALL": "C"}
    awk = [gawk, "-v", f"keycols={','.join(str(idx[c]) for c in keycols)}",
           "-v", f"timecols={','.join(str(idx[c]) for c in timecols)}", "-v", f"delim={delim}",
           "-v", f"SEP={_SEP}", "-v", f"REC={_REC}", "-v", f"pre={1 if literal else 0}",
           "-v", f"maxkeys={MAX_STACK_KEYS}",
           "-v", f"ws={(window or ('', ''))[0]}", "-v", f"we={'' if not window or window[1] == '9999' else window[1]}",
           _AWK]
    try:
        grep = None
        if literal:
            grep = subprocess.Popen([shutil.which("grep") or "grep", "-a", "-F", "-i", "-n", "--", literal, path],
                                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env)
            proc = subprocess.Popen(awk, stdin=grep.stdout, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                    env=env)
            grep.stdout.close()
        else:
            proc = subprocess.Popen([*awk, path], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env)
    except OSError:
        return None

    def rows():
        try:
            for raw in proc.stdout:
                line = raw.decode(encoding, "replace").rstrip("\n")
                if line == "\x1dOVERFLOW":
                    raise TooManyValues(", ".join(keycols))
                parts = line.split(_REC)
                if len(parts) != 6:
                    continue
                vals = parts[0].split(_SEP)
                if len(vals) != len(keycols):
                    continue
                times = [p.split(_SEP) for p in parts[2:]] if timecols else []
                yield dict(zip(keycols, vals)), int(parts[1] or 0), times
        finally:
            proc.stdout.close()
            proc.wait()
            if grep is not None:
                grep.wait()
    return rows()


def _grep_rows(path: str, headers: list[str], literal: str) -> Optional[Iterable[dict]]:
    """The rows of a delimited text table that hold ``literal`` (a native
    fixed-string grep; Python parses the matching lines only). None when
    grep cannot stand in."""
    from core.input_kind import open_text, text_encoding
    from tools.tabular import _GREP_ENCODINGS, _csv_dialect, _kind
    grep = shutil.which("grep")
    encoding = text_encoding(path)
    if not grep or _kind(path) != "csv" or encoding not in _GREP_ENCODINGS or not literal.isascii():
        return None
    try:
        with open_text(path, newline="") as fh:
            dialect = _csv_dialect(fh.read(65536))
    except OSError:
        return None

    def rows():
        proc = subprocess.Popen([grep, "-a", "-F", "-i", "-n", "--", literal, path], stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, env={**os.environ, "LC_ALL": "C"})
        try:
            for raw in proc.stdout:
                num, _, body = raw.partition(b":")
                if num == b"1":
                    continue
                try:
                    cells = next(csv.reader([body.decode(encoding, "replace").rstrip("\r\n")], dialect))
                except (csv.Error, StopIteration):
                    continue
                yield dict(zip(headers, cells))
        finally:
            proc.stdout.close()
            proc.wait()
    return rows()


# A time cell written so text order is time order: ISO-8601 or an epoch.
_ORDERED_TIME_RE = re.compile(r"^\s*(?:\d{4}-\d{2}-\d{2}(?:[T ][\d:.]+)?(?:Z|[+-]\d{2}:?\d{2})?|\d{9,13}(?:\.\d+)?)\s*$")


_TIME_SAMPLE_ROWS = 200


_ISO_RE = re.compile(r"^\s*\d{4}-\d{2}-\d{2}(?:[T ][\d:.]+)?(?:Z|[+-]\d{2}:?\d{2})?\s*$")


def _table_ordered(path: str, tcols: list[str], iso_only: bool = False) -> bool:
    """Whether a table's time cells sort as text, decided once per table
    from its first rows: every sampled cell ISO-8601 or an epoch, and an
    epoch column of one digit length (epochs of different lengths do not
    sort as text)."""
    if not tcols:
        return True
    from tools.tabular import _iter_rows
    lengths: dict[str, set[int]] = {}
    seen = 0
    try:
        for i, (_s, row) in enumerate(_iter_rows(path, None)):
            if i >= _TIME_SAMPLE_ROWS:
                break
            for c in tcols:
                cell = str(row.get(c, "") or "").strip()
                if not cell:
                    continue
                seen += 1
                if not (_ISO_RE if iso_only else _ORDERED_TIME_RE).match(cell):
                    return False
                if cell.split(".")[0].isdigit():
                    lengths.setdefault(c, set()).add(len(cell.split(".")[0]))
    except Exception:  # noqa: BLE001
        return False
    return seen > 0 and all(len(n) == 1 for n in lengths.values())


def _literal(preds) -> str:
    """A fixed string every matching row holds: the value of the first
    equality filter (the grep narrowing of the native pass)."""
    for _col, op, val in preds:
        if op == "=" and str(val).strip():
            return str(val).strip()
    return ""


def stack(case_dir: str, path: Any, group_by: list[str], where: list[str] | None, order: str,
          across: str | None, top: int, offset: int, time_start: str | None = None,
          time_end: str | None = None) -> dict[str, Any]:
    """The stack result (see the module docstring); refused when the
    columns hold more distinct values than one call keeps. time_start and
    time_end bound the rows counted to one period of the time column, as in
    the other table tools."""
    try:
        return _stack(case_dir, path, group_by, where, order, across, top, offset, time_start, time_end)
    except TooManyValues:
        return {"success": False, "gate": "stack_too_many_values",
                "error": (f"too many distinct values in {', '.join(group_by or [])} (over {MAX_STACK_KEYS:,} "
                          "in this call). Call again narrowed by one or more of: "
                          'where=["<column>=<value>"] (a column whose value the rows you want share), '
                          "a narrower path=<glob> (fewer tables), "
                          "time_start=<date> and time_end=<date> (one period)."),
                "narrow_with": ['where=["<column>=<value>"]', "path=<glob>", "time_start=<date>",
                                "time_end=<date>"]}


def _stack(case_dir: str, path: Any, group_by: list[str], where: list[str] | None, order: str,
           across: str | None, top: int, offset: int, time_start: str | None = None,
           time_end: str | None = None) -> dict[str, Any]:
    from core import table_rows as T
    from tools.tabular import (MAX_RETURN_ROWS, _canonicalize_names, _canonicalize_preds, _iter_rows,
                               _matches, _parse_where, _peek_headers, _strip_ident_quotes)
    if order not in ("common", "rare"):
        return {"success": False, "error": "order is common (most rows first) or rare (fewest hosts first)"}
    if not group_by:
        return {"success": False, "error": "group_by names the column(s) to count"}
    try:
        preds = _parse_where(where or [])
    except (ValueError, Exception) as e:  # noqa: BLE001
        return {"success": False, "error": str(e)}
    group_by = [_strip_ident_quotes(c) for c in group_by]
    from tools.tabular import _window
    window = _window(time_start, time_end)

    def in_window(when: str) -> bool:
        return not window or bool(when and window[0] <= when <= window[1])
    across_col = "" if not across or str(across).lower() == "host" else str(across)
    acc = _Acc()
    sources: list[dict[str, Any]] = []
    errors: list[str] = []
    call_ids: list[int] = []
    spec = path if isinstance(path, list) else [path]

    def rows_into(rows: Iterable[dict], unit_default: str, label: str, tcols: list[str]) -> None:
        n = 0
        for row in rows:
            if not _matches(row, preds):
                continue
            n += 1
            unit = str(row.get(across_col, "")) if across_col else (
                unit_default or next((str(row[c]) for c in ("host", "hostname", "computer", "_host")
                                      if row.get(c)), ""))
            when = ""
            if tcols:
                when = (T.row_moment(row, tcols) or "").replace("T", " ")
            if window and not in_window(when):
                n -= 1
                continue
            acc.add(tuple(str(row.get(c, "")) for c in group_by), unit or label, 1, when, when)
        sources.append({"source": label, "unit": unit_default or "(per row)", "rows": n})

    special = [s for s in spec if isinstance(s, str) and (s == "index" or s.startswith("call:"))]
    tables_spec = [s for s in spec if isinstance(s, str) and s not in special]
    for s in special:
        if s == "index":
            unknown = [c for c in group_by + [c for c, _o, _v in preds] + ([across_col] if across_col else [])
                       if c not in INDEX_COLUMNS]
            if unknown:
                return {"success": False, "error": f"the index's columns are {', '.join(INDEX_COLUMNS)}; "
                                                   f"not {', '.join(unknown)}"}
            rows_into(_index_rows(case_dir), "", "index", ["mtime"])
        else:
            try:
                cid = int(s.split(":", 1)[1])
            except ValueError:
                errors.append(f"{s}: not a call id")
                continue
            rows, host, err = _call_rows(cid)
            if err:
                errors.append(err)
                continue
            call_ids.append(cid)
            rows_into(rows, host, s, [])
    tables, missing = _resolve_tables(case_dir, tables_spec)
    errors += [f"{m}: no such table in the case" for m in missing]
    literal = _literal(preds)
    if len(tables) > 1 and not _gawk() and not literal:
        return {"success": False, "gate": "stack_needs_native",
                "error": ("a stack over several tables counts each in one native pass, and gawk is not "
                          "installed here: name a filter with a literal value (column=value) so grep can "
                          "narrow each table first, or stack one table at a time"),
                "tables": len(tables)}
    from core.evidence_links import host_of_path
    for tpath in tables:
        rel = _rel(case_dir, tpath)
        host = host_of_path(case_dir, rel)
        try:
            headers = _peek_headers(tpath)
        except Exception as e:  # noqa: BLE001
            errors.append(f"{rel}: {type(e).__name__}: {e}")
            continue
        gb = _canonicalize_names(group_by, headers)
        tp = _canonicalize_preds(preds, headers)
        missing_cols = [c for c in gb + [c for c, _o, _v in tp] if c not in headers]
        if missing_cols:
            errors.append(f"{rel}: no column {', '.join(missing_cols)}")
            continue
        unit_col = across_col and (_canonicalize_names([across_col], headers)[0])
        if not host and not unit_col:
            unit_col = next((h for h in headers if h.lower() in ("host", "hostname", "computer", "_host")), "")
        tcols = T.time_column_names(headers, [])
        keycols = list(dict.fromkeys(gb + [c for c, _o, _v in tp] + ([unit_col] if unit_col else [])))
        ordered = _table_ordered(tpath, tcols[:2])
        iso = _table_ordered(tpath, tcols[:1], iso_only=True) if window else True
        if window and not tcols:
            errors.append(f"{rel}: no time column, so time_start/time_end cannot bound it")
            continue
        if window and not iso and len(tables) > 1:
            errors.append(f"{rel}: its time column is not ISO-8601, so the one-pass count cannot apply "
                          "time_start/time_end; stack this table alone")
            continue
        native = _native_table(tpath, headers, keycols, tcols[:2], literal, window) \
            if (len(tables) > 1 or literal) and iso else None
        if native is not None:
            n = 0
            tidx = list(range(len(tcols[:2])))
            for vals, count, times in native:
                if not _matches(vals, tp):
                    continue
                n += count
                unit = vals.get(unit_col, "") if unit_col else host
                if times and not ordered:
                    f, lt = (T.row_time(c, tidx).replace("T", " ") if c else "" for c in times[:2])
                    acc.add(tuple(vals.get(c, "") for c in gb), unit or rel, count, f, lt, ordered=False)
                    continue
                seen = sorted(t for t in (T.row_time(c, tidx).replace("T", " ") for c in times if c) if t)
                acc.add(tuple(vals.get(c, "") for c in gb), unit or rel, count,
                        seen[0] if seen else "", seen[-1] if seen else "")
            sources.append({"source": rel, "unit": host or unit_col or rel, "rows": n, "counted": "native"})
            continue
        narrowed = _grep_rows(tpath, headers, literal) if literal else None
        if len(tables) > 1 and narrowed is None:
            errors.append(f"{rel}: not counted (a layout or an encoding the native pass does not read)")
            continue
        preds_t = tp
        n = 0
        try:
            for row in (narrowed if narrowed is not None else (r for _s, r in _iter_rows(tpath, None))):
                if not _matches(row, preds_t):
                    continue
                when = (T.row_moment(row, tcols) or "").replace("T", " ") if tcols else ""
                if window and not in_window(when):
                    continue
                n += 1
                unit = str(row.get(unit_col, "")) if unit_col else host
                acc.add(tuple(str(row.get(c, "")) for c in gb), unit or rel, 1, when or "", when or "",
                        ordered=ordered)
        except TooManyValues:
            raise
        except Exception as e:  # noqa: BLE001
            errors.append(f"{rel}: {type(e).__name__}: {e}")
            continue
        sources.append({"source": rel, "unit": host or unit_col or rel, "rows": n,
                        "counted": "grep" if narrowed is not None else "rows"})
    groups = acc.groups
    if order == "rare":
        ranked = sorted(groups.items(), key=lambda kv: (len(kv[1]["units"]), -kv[1]["rows"], kv[0]))
    else:
        ranked = sorted(groups.items(), key=lambda kv: (-kv[1]["rows"], kv[0]))
    top = max(1, min(int(top or 25), MAX_RETURN_ROWS))
    offset = max(0, int(offset or 0))
    page = ranked[offset:offset + top]
    out_groups = []
    for combo, g in page:
        row = {c: v for c, v in zip(group_by, combo)}
        row.update({"units": len(g["units"]), "unit_names": _unit_names(g["units"]), "rows": g["rows"]})
        if g["first"]:
            row["first"], row["last"] = g["first"], g["last"]
        out_groups.append(row)
    result: dict[str, Any] = {
        "success": bool(sources) or not errors, "group_by": group_by, "order": order,
        "across": across_col or "host", "distinct_groups": len(groups),
        "tail_1": sum(1 for g in groups.values() if len(g["units"]) == 1),
        "tail_2": sum(1 for g in groups.values() if len(g["units"]) == 2),
        "units_total": len({u for g in groups.values() for u in g["units"]}),
        "groups": out_groups, "offset": offset, "sources": sources,
    }
    if acc.file_order:
        result["time_order"] = ("file order: the time column is not written in an order text sorts by (a "
                                "month-first or day-first date), so first and last are the first and last "
                                "rows in the file, not the earliest and latest")
    if offset + len(page) < len(ranked):
        result["next_offset"] = offset + len(page)
    if errors:
        result["errors"] = errors
    if call_ids:
        # A finding resting on this stack cites the evidence calls behind it.
        result["source_call_ids"] = call_ids
    if not sources and errors:
        result["error"] = "; ".join(errors[:5])
    return result
