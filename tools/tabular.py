"""Tabular evidence reader — typed access to xlsx / csv / tsv / jsonl exports.

SIEM, EDR, and cloud-audit evidence routinely arrives as spreadsheet or
JSON-lines exports. These tools give the analyst schema discovery, filtered
queries, group-by pivots, and regex grep over such files without dropping to
raw python/openpyxl shell one-liners the MCP-routing gate can't audit.

Read-only with respect to evidence; the only write path is the optional
``output_csv`` spill (validated by @output_safe). Backed by openpyxl for
workbooks and the stdlib for csv/tsv/jsonl — no pandas.
"""
from __future__ import annotations

import csv
import heapq
import json
import os
import re
from typing import Iterator, Optional

from fastmcp import FastMCP

from core import output_safe
from core.input_kind import looks_delimited, open_text, text_encoding
from core.envfile import env_int
from core.paths import MAX_TOOL_OUTPUT_LINES, OUTPUT_CAP

mcp = FastMCP("table")

# Bounded work per call: rows returned, payload size. A scan reads every row
# unless an operator sets ATLAS_TABLE_MAX_SCAN_ROWS (0 or unset: no bound): a
# scan stopped on volume would report part of a file as the whole of it, and
# a search of a timeline longer than the bound would come back empty for what
# lies past it.
MAX_SCAN_ROWS = env_int("ATLAS_TABLE_MAX_SCAN_ROWS", 0)
MAX_RETURN_ROWS = MAX_TOOL_OUTPUT_LINES
_CELL_CAP = 512  # per-cell chars in returned rows

_XLSX_EXTS = {".xlsx", ".xlsm", ".xltx", ".xltm"}
_CSV_EXTS = {".csv", ".tsv", ".txt"}
_JSONL_EXTS = {".jsonl", ".ndjson", ".json"}


def _kind(path: str) -> str | None:
    ext = os.path.splitext(path)[1].lower()
    if ext in _XLSX_EXTS:
        return "xlsx"
    if ext in _CSV_EXTS:
        return "csv"
    if ext in _JSONL_EXTS:
        return "jsonl"
    # A delimited export is a table whatever a vendor named it (.log, .out,
    # .export, no extension): the same sniff the byte-scanner gate uses to
    # send the agent *here*, so no text file is refused by both sides.
    if ext not in _BINARY_EXTS and looks_delimited(path):
        return "csv"
    return None


_BINARY_EXTS = frozenset({
    ".hve", ".evtx", ".vmdk", ".e01", ".raw", ".dd", ".bin", ".exe", ".dll",
    ".sys", ".dat", ".hive", ".reg", ".pf", ".lnk", ".zip", ".7z", ".gz",
})


def _refuse_nontabular(path: str) -> dict | None:
    """Refuse binary / non-tabular inputs before the CSV/XLSX parsers choke.

    A binary export (an Amcache hive, say) sent to table_* fails with
    'line contains NUL' / JSONDecodeError. Classification belongs here —
    not a per-artifact special case.
    """
    if not path:
        return None
    if not os.path.isfile(path):
        # Directories are never tabular row sources.
        if os.path.isdir(path):
            return {
                "success": False,
                "gate": "wrong_input_kind",
                "error": (
                    f"{path!r} is a directory — table.* tools read a single "
                    "tabular file (csv/tsv/xlsx/jsonl), not a folder. Pick "
                    "one file under it (misc.list_evidence_dir) or use a "
                    "directory-aware parser."
                ),
            }
        return None
    ext = os.path.splitext(path)[1].lower()
    kind = _kind(path)
    if ext in _BINARY_EXTS or kind is None:
        return {
            "success": False,
            "gate": "wrong_input_kind",
            "error": (
                f"{path!r} is not a tabular export (csv/tsv/xlsx/jsonl, or "
                "text whose lines share a delimiter). "
                "Do not send binary/registry/EVTX/disk images to table.*. "
                "Use the typed parser for this artifact class — SQLite "
                "databases: ez.sqlecmd; registry hives: ez.recmd_hive; EVTX: "
                "ez.evtxecmd; $MFT: ez.mftecmd — or query a parsed CSV under "
                "analysis/ / evidence Tools exports. XML, JSON or other text "
                "documents: strings.read_text."
            ),
        }
    # Binary probe for mislabeled *text* formats only. xlsx is a ZIP
    # container and legitimately contains NUL bytes in its binary framing.
    # UTF-16 exports (reg export, PowerShell Out-File) also contain NUL in
    # every other byte and are text — text_encoding tells the two apart.
    if kind in ("csv", "jsonl") and text_encoding(path) is None:
        return {
            "success": False,
            "gate": "wrong_input_kind",
            "error": (
                f"{path!r} contains NUL bytes and is not UTF-16 — treating "
                "as binary, not tabular text. Use a binary-aware tool or a "
                "clean CSV export of this artifact."
            ),
        }
    return None


def _cell(value) -> str:
    if value is None:
        return ""
    return str(value)


def _parse_embedded_csv(cells: list) -> list[str]:
    """One workbook row whose cell(s) hold a raw CSV line → real fields.

    Elastic/Kibana "export to xlsx" ships each record as a single cell
    containing the comma-separated line. Occasionally the line spills across
    a few extra cells — rejoin before parsing."""
    joined = ",".join(_cell(c) for c in cells if c is not None)
    return next(csv.reader([joined]), [])


def _iter_xlsx(path: str, sheet: Optional[str]) -> Iterator[tuple[str, list[str], list]]:
    """Yields (sheet_name, header, row_values) per data row, streaming."""
    import openpyxl
    wb = openpyxl.load_workbook(path, read_only=True, data_only=True)
    try:
        names = [sheet] if sheet else wb.sheetnames
        for name in names:
            if name not in wb.sheetnames:
                raise ValueError(
                    f"sheet {name!r} not in workbook (has: {wb.sheetnames})")
            ws = wb[name]
            header: list[str] | None = None
            embedded_csv = False
            for row in ws.iter_rows(values_only=True):
                if header is None:
                    # Embedded-CSV export: the whole header line sits in the
                    # first cell.
                    embedded_csv = bool(row) and _cell(row[0]).count(",") >= 3
                    cells = _parse_embedded_csv(list(row)) if embedded_csv \
                        else list(row)
                    header = [_cell(c) or f"col{i+1}"
                              for i, c in enumerate(cells)]
                    continue
                yield name, header, (_parse_embedded_csv(list(row))
                                     if embedded_csv else list(row))
    finally:
        wb.close()


_UNTERMINATED_MAX_BYTES = env_int("ATLAS_TABLE_UNTERMINATED_MAX_BYTES", 256 * 1024 * 1024)


def _iter_unterminated(path: str) -> Iterator[tuple[str, list[str], list]] | None:
    """Rows of a delimited export that has no line terminators, or None."""
    from core.input_kind import unterminated_records, unterminated_separator
    try:
        if os.path.getsize(path) > _UNTERMINATED_MAX_BYTES:
            return None
    except OSError:
        return None
    with open_text(path, newline="") as f:
        text = f.read()
    sep = unterminated_separator(text)
    found = unterminated_records(text, sep) if sep else None
    if not found:
        return None
    header, records = found
    header = [(c or "").strip().lstrip("\ufeff") or f"col{i+1}"
              for i, c in enumerate(header)]
    width = len(header)
    # Sparse records map onto the leading header columns; the rest are
    # empty, so the schema shows every column the export can carry.
    return (("-", header, rec + [""] * (width - len(rec)) if len(rec) < width else rec)
            for rec in records)


def _iter_csv(path: str, _sheet: Optional[str]) -> Iterator[tuple[str, list[str], list]]:
    with open_text(path, newline="") as f:
        sample = f.read(65536)
        f.seek(0)
        # At most one line break in 64 KB of a delimited file: the records
        # were written without terminators (the one break is the header's).
        if sample.count("\n") + sample.count("\r") <= 1:
            rows = _iter_unterminated(path)
            if rows is not None:
                yield from rows
                return
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
        except csv.Error:
            dialect = csv.excel
        reader = csv.reader(f, dialect)
        header: list[str] | None = None
        for row in reader:
            if header is None:
                header = [
                    (c or "").strip().lstrip("\ufeff") or f"col{i+1}"
                    for i, c in enumerate(row)
                ]
                continue
            yield "-", header, row


def _iter_jsonl(path: str, _sheet: Optional[str]) -> Iterator[tuple[str, list[str], list]]:
    """JSON Lines, or a single top-level JSON array of objects."""
    with open_text(path) as f:
        first = f.read(1)
        f.seek(0)
        if first == "[":
            records = json.load(f)
            if not isinstance(records, list):
                raise ValueError("top-level JSON is not an array of objects")
            for rec in records:
                if isinstance(rec, dict):
                    keys = list(rec.keys())
                    yield "-", keys, [rec.get(k) for k in keys]
            return
        for line in f:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            if isinstance(rec, dict):
                keys = list(rec.keys())
                yield "-", keys, [rec.get(k) for k in keys]


_ITERATORS = {"xlsx": _iter_xlsx, "csv": _iter_csv, "jsonl": _iter_jsonl}


def _iter_rows(path: str, sheet: Optional[str]) -> Iterator[tuple[str, dict]]:
    """Yields (sheet_name, {column: str_value}); stops at the scan-row
    bound when an operator set one."""
    kind = _kind(path)
    if kind is None:
        base = os.path.basename(path)
        hint = (
            "Use table.* only on CSV/TSV/JSON/XLSX. "
            "For $MFT use ez.ez_mftecmd then query the CSV output; "
            "for NTUSER.DAT/hives use ez.ez_recmd_*; "
            "for .evtx use ez.ez_evtxecmd."
        )
        if base.upper() in ("$MFT", "$LOGFILE", "$MFTMIRR") or base.upper().startswith("$"):
            hint = (
                f"{base!r} is a raw NTFS metadata file, not a table. "
                "Call ez.ez_mftecmd (or open an MFTECmd CSV the evidence "
                "already carries) "
                "then table.table_query on the CSV — never table.* on $MFT."
            )
        elif base.upper() in ("NTUSER.DAT", "USRCLASS.DAT") or base.upper().endswith(".DAT"):
            hint = (
                f"{base!r} is a registry hive, not a table. "
                "Use ez.ez_recmd_hive / ez.ez_recmd_batch."
            )
        raise ValueError(
            f"unsupported extension for {path!r} — supported: "
            f"{sorted(_XLSX_EXTS | _CSV_EXTS | _JSONL_EXTS)}. {hint}")
    scanned = 0
    for sheet_name, header, values in _ITERATORS[kind](path, sheet):
        scanned += 1
        if MAX_SCAN_ROWS and scanned > MAX_SCAN_ROWS:
            raise _ScanCapReached(scanned - 1)
        values = _repair_unquoted_timestamp(values, len(header))
        row = {header[i] if i < len(header) else f"col{i+1}": _cell(v)
               for i, v in enumerate(values)}
        yield sheet_name, row


class _ScanCapReached(Exception):
    def __init__(self, scanned: int):
        self.scanned = scanned


def _scan_fields(scanned: int, capped: bool, found: int) -> dict:
    """How much of the file a scan read. A scan stopped at the bound that
    found nothing says nothing about the rows past it."""
    out = {"rows_scanned": scanned, "scanned_rows": scanned,
           "scan_capped": capped,
           "scan_capped_at": MAX_SCAN_ROWS if capped else None}
    if capped and not found:
        out["inconclusive"] = True
        out["note"] = (f"Only the first {scanned} rows were scanned "
                       "(ATLAS_TABLE_MAX_SCAN_ROWS); nothing found there says "
                       "nothing about the rest of the file.")
    return out


# Kibana/Elastic CSV exports leave the human-readable timestamp UNQUOTED
# ("May 16, 2026 @ 09:00:01.000, …") — its embedded comma shifts every field
# right by one. Detect the split signature and rejoin.
_KIBANA_TS_TAIL_RE = re.compile(r"^\s*\d{4} @ \d{2}:\d{2}")


def _repair_unquoted_timestamp(values: list, ncols: int) -> list:
    if (len(values) == ncols + 1 and len(values) >= 2
            and _KIBANA_TS_TAIL_RE.match(_cell(values[1]))):
        # plain comma: the split kept the original spacing in values[1]
        return [f"{_cell(values[0])},{_cell(values[1])}"] + list(values[2:])
    return values


# where-predicate grammar: "<column><op><value>", longest operator first.
_OPS = ("!=", ">=", "<=", "~", "=", ">", "<")


def _strip_ident_quotes(name: str) -> str:
    """Strip SQL-style identifier quotes models often emit (`col`, "col")."""
    s = (name or "").strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "`\"'":
        s = s[1:-1].strip()
    return s.lstrip("\ufeff")


_SQL_TREE_RE = re.compile(
    r"\bOR\b|\bAND\b|\bREGEXP\b|\bLIKE\b|\bIN\s*\(",
    re.IGNORECASE,
)


def _or_rewrite_hint(raw: str) -> str | None:
    """Suggest splitting a simple ``col=a OR col=b`` into two queries."""
    m = re.search(
        r"^(.+?)(!=|=|~|>=|<=|>|<)(.+?)\s+OR\s+(.+?)(!=|=|~|>=|<=|>|<)(.+)$",
        raw.strip(),
        re.IGNORECASE,
    )
    if not m:
        return None
    left = f"{m.group(1).strip()}{m.group(2)}{m.group(3).strip()}"
    right = f"{m.group(4).strip()}{m.group(5)}{m.group(6).strip()}"
    return (
        f"Run two table.table_query calls (or table_grep): "
        f"where=[{left!r}] then where=[{right!r}]. "
        "List items are ANDed; OR is not supported in one call."
    )


def _refuse_sql_where_tree(where: list[str]) -> dict | None:
    """Refuse SQL boolean/REGEXP trees the tiny where dialect cannot express.

    Models emit ``col='x' OR col='y'``; the parser previously took the first
    ``=`` and treated the rest as a literal value → success + 0 rows + forged
    coverage contact. Fail hard with a repair hint instead.
    """
    for raw in where or []:
        if not isinstance(raw, str):
            continue
        if _SQL_TREE_RE.search(raw):
            rewrite = _or_rewrite_hint(raw)
            return {
                "success": False,
                "gate": "unsupported_where_dialect",
                "error": (
                    f"where predicate {raw!r} uses SQL boolean/REGEXP syntax "
                    "that table.table_query does not support. Pass separate "
                    "list items (ANDed): ['col=value', 'col2~regex']. "
                    "OR filters = two queries (or table_grep)."
                ),
                "hint": rewrite or (
                    "where=['Source User=admin'] — not "
                    "`Source User`='admin' OR ..."
                ),
                "rewrite_hint": rewrite,
            }
    return None


def _doubled_escape_hint(where: list[str] | None) -> str:
    """Why a regex predicate may have matched nothing: a doubled backslash.

    A model writing JSON escapes ``\\d`` once for JSON and once more out of
    habit, so the pattern that arrives is ``\\\\d``: a literal backslash
    followed by ``d``, which matches no row. The result stays an honest
    zero; this names the likely cause so the retry is the right one.
    """
    for raw in where or []:
        idx = raw.find("~")
        if idx > 0 and "\\\\" in raw[idx + 1:]:
            return ("No row matched, and the pattern carries a doubled "
                    "backslash (a regex \\d is written \"\\\\d\" once in "
                    "JSON, not twice); retry with single escaping if that "
                    "was not meant literally.")
    return ""


def _parse_where(where: list[str]):
    preds = []
    for raw in where:
        for op in _OPS:
            idx = raw.find(op)
            if idx > 0:
                col, val = raw[:idx].strip(), raw[idx + len(op):].strip()
                col = _strip_ident_quotes(col)
                # Values may also be quoted (including ~ regex patterns).
                if len(val) >= 2 and val[0] == val[-1] and val[0] in "`\"'":
                    val = val[1:-1]
                if op == "~":
                    rx = re.compile(val, re.IGNORECASE)
                    preds.append((col, op, rx))
                else:
                    preds.append((col, op, val))
                break
        else:
            raise ValueError(
                f"unparseable predicate {raw!r} — use column=value, "
                f"column!=value, column~regex, or column >/</>=/<= number")
    return preds


_ISO_TS_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?)?(?:Z|[+-]\d{2}:?\d{2})?$")


def _iso_like(text: str) -> bool:
    """An ISO-8601 date or timestamp: ordered comparison works on the text."""
    return bool(_ISO_TS_RE.match(str(text or "").strip()))


def _refuse_non_numeric_compare(preds, headers: list[str]) -> dict | None:
    """Refuse >/</>=/<= when neither side looks numeric or ISO-8601."""
    for col, op, val in preds:
        if op not in (">", "<", ">=", "<="):
            continue
        if _to_num(val) is not None or _iso_like(val):
            continue
        return {
            "success": False,
            "gate": "non_numeric_compare",
            "error": (
                f"Predicate {col}{op}{val!r} uses a numeric comparator but "
                f"the value is neither a number nor an ISO-8601 date/time. "
                f"table.table_query >/</>=/<= compare numbers, or ISO "
                f"timestamps such as 2031-02-04 or 2031-02-04T10:00:00Z; "
                f"otherwise use column~regex or exact column=value."
            ),
            "available_columns": (headers or [])[:40],
            "hint": "table.table_schema → column~'2031-02-04' (not >= 'Feb 4')",
        }
    return None


def _norm_header(name: str) -> str:
    """BOM-strip + identifier-quote strip + casefold for column identity."""
    return _strip_ident_quotes(name).casefold()


def _alnum_fold(name: str) -> str:
    """Casefold and strip non-alphanumerics for fuzzy column identity."""
    return re.sub(r"[^a-z0-9]+", "", _norm_header(name))


# Generic DFIR column synonym groups (observation semantics, not products).
# A requested name rewrites to a header only when exactly one header in the
# file falls in the same group — ambiguous matches stay refused.
# Source vs destination IP stay in separate groups so dual-IP tables do not
# make every IP synonym ambiguous.
_COLUMN_SYNONYM_GROUPS: tuple[frozenset[str], ...] = (
    frozenset({
        "user", "username", "sourceuser", "srcuser", "accountname", "account",
        "subjectusername", "targetusername", "logonuser", "fromuser",
    }),
    frozenset({
        "time", "timestamp", "timecreated", "timegenerated", "receivetime",
        "generatetime", "updatetimestamp", "eventtime", "datetime", "date",
    }),
    # Source / client IP — keep RemoteIP out (MDE uses Remote* for peer).
    frozenset({
        "ip", "ipaddress", "sourceip", "srcip", "clientip", "requestsourceip",
        "publicip",
    }),
    # Destination / remote peer (MDE Destination* ↔ Remote*).
    frozenset({
        "destip", "dstip", "destinationip", "destinationipaddress",
        "remoteip", "remoteipaddress", "targetip",
    }),
    frozenset({
        "destport", "dstport", "destinationport", "remoteport", "targetport",
    }),
    frozenset({
        "host", "hostname", "computer", "computername", "device", "devicename",
        "machine", "machinename", "endpoint",
    }),
    # Peer / destination device (do not merge into DeviceName — distinct).
    frozenset({
        "destinationdevicename", "destinationdevice", "remotedevicename",
        "remotedevice", "targetdevicename", "targetdevice",
    }),
    frozenset({"domain", "vsys", "tenant", "realm"}),
    frozenset({"eventid", "eid"}),
    frozenset({"provider", "providername"}),
    frozenset({"recordid", "eventrecordid", "recordnumber"}),
    frozenset({
        "path", "fullpath", "filepath", "filename", "name", "parentpath",
        "parentfullpath",
    }),
    frozenset({"reason", "updatereasons", "usnreason", "failurereason"}),
    frozenset({"rule", "detections", "ruletitle", "detection"}),
    frozenset({"result", "status", "outcome", "actiontype", "eventtype"}),
    frozenset({"logontype", "logon_type", "logontypeid"}),
)

# Process-local pending schema binds (also persisted under case/.atlas when
# a case root is inferable). Keyed by abspath (any sheet for that file).
_PENDING_SCHEMA_BIND: dict[str, dict] = {}


def _bind_key(path: str) -> str:
    return os.path.abspath(path)


def _load_bind_state(case_dir: str) -> dict:
    path = os.path.join(case_dir, ".atlas", "tabular_schema_bind.json")
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError, TypeError):
        return {}


def _save_bind_state(case_dir: str, state: dict) -> None:
    atlas = os.path.join(case_dir, ".atlas")
    try:
        os.makedirs(atlas, exist_ok=True)
        path = os.path.join(atlas, "tabular_schema_bind.json")
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(state, fh, indent=2, sort_keys=True)
        os.replace(tmp, path)
    except OSError:
        pass


def _bind_entry(path: str) -> dict:
    """Process + durable bind record for a tabular path."""
    key = _bind_key(path)
    entry = _PENDING_SCHEMA_BIND.get(key)
    if isinstance(entry, dict):
        return entry
    case_dir = _infer_case_dir_from_path(path)
    if case_dir:
        entry = _load_bind_state(case_dir).get(key)
        if isinstance(entry, dict):
            _PENDING_SCHEMA_BIND[key] = entry
            return entry
    return {}


def _write_bind_entry(path: str, entry: dict) -> None:
    key = _bind_key(path)
    _PENDING_SCHEMA_BIND[key] = entry
    case_dir = _infer_case_dir_from_path(path)
    if case_dir:
        state = _load_bind_state(case_dir)
        state[key] = entry
        _save_bind_state(case_dir, state)


def _mark_pending_schema_bind(
    path: str, *, missing: list[str], available: list[str],
) -> None:
    """After unknown_columns, require table.table_schema before next query."""
    prev = _bind_entry(path)
    entry = {
        "pending": True,
        "schema_seen": True,  # peek/available_columns established file SoT
        "unknown_columns": list(missing)[:20],
        "available_columns": list(available)[:40],
    }
    if prev.get("schema_seen"):
        entry["schema_seen"] = True
    _write_bind_entry(path, entry)


def _clear_pending_schema_bind(path: str) -> None:
    """Clear pending latch after table_schema; keep schema_seen for exhaust."""
    prev = _bind_entry(path)
    entry = {
        "pending": False,
        "schema_seen": True,
        "unknown_columns": [],
        "available_columns": list(prev.get("available_columns") or [])[:40],
        "schema_cleared": True,
    }
    _write_bind_entry(path, entry)


def _pending_schema_bind(path: str) -> dict | None:
    entry = _bind_entry(path)
    if isinstance(entry, dict) and entry.get("pending"):
        return entry
    return None


def _schema_seen(path: str) -> bool:
    entry = _bind_entry(path)
    return bool(entry.get("schema_seen") or entry.get("schema_cleared"))


def _closest_headers(
    missing: list[str], headers: list[str], *, n: int = 3,
) -> dict[str, list[str]]:
    """Suggest file-local headers (difflib) — never auto-bind ambiguous ones."""
    try:
        from difflib import get_close_matches
    except Exception:
        return {}
    out: dict[str, list[str]] = {}
    hdrs = [str(h) for h in headers]
    for m in missing:
        hits = get_close_matches(str(m), hdrs, n=n, cutoff=0.45)
        if not hits:
            # containment fallback: DestinationDevice ↔ RemoteDeviceName
            ml = _alnum_fold(m)
            hits = [
                h for h in hdrs
                if ml and (_alnum_fold(h) in ml or ml in _alnum_fold(h))
            ][:n]
        if hits:
            out[str(m)] = hits
    return out


def _schema_first_redirect(path: str) -> dict | None:
    """Hard redirect when a prior unknown_columns left a pending schema bind."""
    pending = _pending_schema_bind(path)
    if not pending:
        return None
    sample = pending.get("available_columns") or []
    missing = pending.get("unknown_columns") or []
    return {
        "success": False,
        "gate": "schema_first_required",
        "error": (
            f"Prior table.* call on {path!r} hit unknown_columns "
            f"{missing!r}. Call table.table_schema on this path next, then "
            "retry table_query/table_pivot using exact headers from the "
            "schema (or available_columns)."
        ),
        "available_columns": sample,
        "unknown_columns": missing,
        "redirect_to": "table.table_schema",
        "next_required_tool": "table.table_schema",
        "hint": "table.table_schema → table.table_query with real headers",
    }


# When several headers share a synonym group, prefer these alnum names first.
_SYNONYM_PREFER: dict[str, tuple[str, ...]] = {
    "timestamp": (
        "receivetime", "timegenerated", "timecreated", "timestamp",
        "eventtime", "datetime", "time", "generatetime", "date",
    ),
    "time": (
        "receivetime", "timegenerated", "timecreated", "timestamp",
        "eventtime", "datetime", "time", "generatetime", "date",
    ),
}


def _infer_case_dir_from_path(path: str) -> Optional[str]:
    """Walk parents for a case root (CASE.md / .atlas / evidence+analysis)."""
    cur = os.path.dirname(os.path.abspath(path))
    for _ in range(10):
        if (
            os.path.isfile(os.path.join(cur, "CASE.md"))
            or os.path.isdir(os.path.join(cur, ".atlas"))
            or (
                os.path.isdir(os.path.join(cur, "evidence"))
                and os.path.isdir(os.path.join(cur, "analysis"))
            )
        ):
            return cur
        parent = os.path.dirname(cur)
        if parent == cur:
            break
        cur = parent
    return None


def _schema_cache_key(path: str, sheet: Optional[str]) -> str:
    try:
        st = os.stat(path)
        stamp = f"{int(st.st_mtime_ns)}:{st.st_size}"
    except OSError:
        stamp = "0:0"
    return f"{os.path.abspath(path)}|{stamp}|{sheet or ''}"


def _load_schema_cache(case_dir: str) -> dict:
    cache_path = os.path.join(case_dir, ".atlas", "tabular_schema_cache.json")
    try:
        with open(cache_path, encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError, TypeError):
        return {}


def _save_schema_cache(case_dir: str, cache: dict) -> None:
    atlas = os.path.join(case_dir, ".atlas")
    try:
        os.makedirs(atlas, exist_ok=True)
        cache_path = os.path.join(atlas, "tabular_schema_cache.json")
        tmp = cache_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(cache, fh, indent=2, sort_keys=True)
        os.replace(tmp, cache_path)
    except OSError:
        pass


def _cache_headers(path: str, sheet: Optional[str], headers: list[str]) -> None:
    """Persist peeked/schema headers as SoT for later binds (best-effort)."""
    if not headers:
        return
    case_dir = _infer_case_dir_from_path(path)
    if not case_dir:
        return
    cache = _load_schema_cache(case_dir)
    cache[_schema_cache_key(path, sheet)] = {
        "columns": list(headers),
        "path": os.path.abspath(path),
        "sheet": sheet,
    }
    # Bound growth: keep newest ~200 entries
    if len(cache) > 220:
        # Drop keys that look stale (no mtime match) first — simple trim
        for k in list(cache.keys())[:-200]:
            cache.pop(k, None)
    _save_schema_cache(case_dir, cache)


def _cached_headers(path: str, sheet: Optional[str]) -> list[str] | None:
    case_dir = _infer_case_dir_from_path(path)
    if not case_dir:
        return None
    entry = _load_schema_cache(case_dir).get(_schema_cache_key(path, sheet))
    if not isinstance(entry, dict):
        return None
    cols = entry.get("columns")
    return list(cols) if isinstance(cols, list) and cols else None


def _peek_headers(path: str, sheet: Optional[str] = None) -> list[str]:
    """Return column headers — cache hit, else first-row peek + cache write."""
    cached = _cached_headers(path, sheet)
    if cached is not None:
        return cached
    for sheet_name, row in _iter_rows(path, sheet):
        del sheet_name
        headers = list(row.keys())
        _cache_headers(path, sheet, headers)
        return headers
    return []


def _resolve_column_name(requested: str, headers: list[str]) -> str | None:
    """Map a requested column to a real header.

    Order: exact casefold → alphanumeric fold (unique) → synonym group
    (unique header in group). Ambiguous synonym hits return None so the
    unknown_columns gate can surface available headers instead of guessing.
    """
    want = _norm_header(requested)
    if not want:
        return None
    for h in headers:
        if _norm_header(h) == want:
            return h

    want_alnum = _alnum_fold(requested)
    if want_alnum:
        alnum_hits = [h for h in headers if _alnum_fold(h) == want_alnum]
        if len(alnum_hits) == 1:
            return alnum_hits[0]

    group = next((g for g in _COLUMN_SYNONYM_GROUPS if want_alnum in g), None)
    if group is not None:
        hits = [h for h in headers if _alnum_fold(h) in group]
        if len(hits) == 1:
            return hits[0]
        if len(hits) > 1:
            # Prefer primary *time* columns when several synonyms exist
            # (e.g. Receive Time + Generate Time both match "Timestamp").
            # Do NOT prefer among subject/target user or src/dst IP — those
            # are distinct fields and must stay ambiguous/refused.
            prefer = _SYNONYM_PREFER.get(want_alnum)
            if prefer is None and group & set(_SYNONYM_PREFER):
                # Request used a group member not listed as a prefer key
                # (e.g. "datetime") — still apply time preference.
                prefer = next(
                    _SYNONYM_PREFER[k]
                    for k in ("timestamp", "time")
                    if k in group or k in _SYNONYM_PREFER
                )
            if prefer and any(_alnum_fold(h) in prefer for h in hits):
                rank = {n: i for i, n in enumerate(prefer)}
                hits_sorted = sorted(
                    hits,
                    key=lambda h: rank.get(_alnum_fold(h), 10_000),
                )
                if rank.get(_alnum_fold(hits_sorted[0]), 10_000) < 10_000:
                    return hits_sorted[0]
    return None


def _column_rewrites(
    requested: list[str], headers: list[str],
) -> dict[str, str]:
    """Map requested→canonical when the names differ after resolve."""
    out: dict[str, str] = {}
    for raw in requested:
        if not raw:
            continue
        real = _resolve_column_name(raw, headers)
        if real and _norm_header(raw) != _norm_header(real):
            out[raw] = real
    return out


def _unknown_columns_refusal(
    path: str,
    *,
    sheet: Optional[str],
    requested: list[str],
) -> dict | None:
    """Refuse queries that name columns absent from the file schema (I4).

    Headers are peeked / cache-bound automatically (schema SoT). Unambiguous
    synonym rewrites apply before refusal. After ``table.table_schema`` has
    cleared the bind latch, repeating absent columns escalates to
    ``schema_columns_absent`` (exhaust — do not invent another name).
    """
    req = [c for c in requested if c]
    if not req:
        return None
    try:
        headers = _peek_headers(path, sheet)
    except Exception as e:
        return {"success": False, "error": f"{type(e).__name__}: {e}"}
    if not headers:
        _mark_pending_schema_bind(path, missing=req, available=[])
        return {
            "success": False,
            "gate": "unknown_columns",
            "error": (
                f"{path!r} has no header row / columns — cannot validate "
                f"requested fields {req!r}."
            ),
            "available_columns": [],
            "schema_columns": [],
            "redirect_to": "table.table_schema",
            "next_required_tool": "table.table_schema",
            "hint": "table.table_schema → table.table_query with real headers",
        }
    missing = [c for c in req if _resolve_column_name(c, headers) is None]
    if not missing:
        return None
    sample = headers[:40]
    closest = _closest_headers(missing, headers)
    # B1 residual / I4: successful peek IS the file-local schema SoT.
    # Do not require a separate table.table_schema hop or invent loop —
    # surface schema_columns in-band and exhaust (change file/question).
    _write_bind_entry(path, {
        "pending": False,
        "schema_seen": True,
        "schema_cleared": True,
        "unknown_columns": [],
        "available_columns": sample,
    })
    return {
        "success": False,
        "gate": "schema_columns_absent",
        "error": (
            f"Column(s) {missing!r} are not in the schema for {path!r} "
            f"(auto-peeked headers are authoritative). Do not invent "
            f"alternate names — use schema_columns / available_columns or "
            f"query a different file. Closest headers: {closest!r}."
        ),
        "unknown_columns": missing,
        "available_columns": sample,
        "schema_columns": list(headers),
        "closest_columns": closest,
        "hint": (
            "Pick exact headers from schema_columns / available_columns, "
            "or switch to a file that actually has these fields."
        ),
    }


def _canonicalize_preds(preds, headers: list[str]):
    """Rewrite predicate column names to canonical header spelling."""
    out = []
    for col, op, val in preds:
        real = _resolve_column_name(col, headers) or col
        out.append((real, op, val))
    return out


def _canonicalize_names(names: Optional[list[str]], headers: list[str]) -> list[str]:
    if not names:
        return []
    return [(_resolve_column_name(n, headers) or n) for n in names]


def _to_num(text: str):
    try:
        return float(text)
    except (TypeError, ValueError):
        return None


def _matches(row: dict, preds) -> bool:
    for col, op, val in preds:
        cell = row.get(col)
        if cell is None:
            return False
        if op == "=":
            if cell.strip().lower() != str(val).lower():
                return False
        elif op == "!=":
            if cell.strip().lower() == str(val).lower():
                return False
        elif op == "~":
            if not val.search(cell):
                return False
        else:  # ordered comparison: numbers, or ISO-8601 timestamps as text
            a, b = _to_num(cell), _to_num(val)
            if a is None or b is None:
                if _iso_like(val) and _iso_like(cell):
                    a, b = cell.strip(), str(val).strip()
                else:
                    return False
            if op == ">" and not a > b:
                return False
            if op == "<" and not a < b:
                return False
            if op == ">=" and not a >= b:
                return False
            if op == "<=" and not a <= b:
                return False
    return True


def _clip_row(row: dict, columns: Optional[list[str]]) -> dict:
    if columns:
        row = {c: row.get(c, "") for c in columns}
    return {k: (v[:_CELL_CAP] + "…" if len(v) > _CELL_CAP else v)
            for k, v in row.items()}


def _payload_capped(rows: list[dict]) -> tuple[list[dict], bool]:
    """Drop tail rows until the JSON payload fits inside OUTPUT_CAP."""
    while rows and len(json.dumps(rows)) > OUTPUT_CAP:
        rows = rows[:max(1, len(rows) // 2)]
        if len(rows) == 1 and len(json.dumps(rows)) > OUTPUT_CAP:
            return [], True
    return rows, False


def _spill_csv(rows: list[dict], output_csv: str) -> str | None:
    """Write matched rows to CSV. Skip writing when there are no matches.

    Empty fieldnames produced a 2-byte ``\\r\\n`` file that later failed as
    'no header' evidence and poisoned Evaluate/coverage. A
    zero-match query is still a successful query — it just has no spill.
    """
    from core.paths import assert_output_safe
    assert_output_safe(output_csv)
    if not rows:
        return None
    os.makedirs(os.path.dirname(output_csv) or ".", exist_ok=True)
    cols: list[str] = []
    for r in rows:
        for k in r:
            if k not in cols:
                cols.append(k)
    if not cols:
        return None
    with open(output_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)
    return output_csv


def _refuse_empty_tabular(path: str) -> dict | None:
    """Refuse tiny/headerless spills that are not real tabular evidence."""
    try:
        size = os.path.getsize(path)
    except OSError:
        return None
    if size > 2:
        return None
    return {
        "success": False,
        "gate": "empty_tabular",
        "error": (
            f"{path!r} is empty or has no header row ({size} bytes). "
            "This is usually a zero-match spill — query the source evidence "
            "file instead of the empty analysis export."
        ),
        "hint": "table.table_query on the original evidence path",
    }


@mcp.tool()
@output_safe
def table_schema(path: str, sample_rows: int = 200) -> dict:
    """
    Discover the structure of a tabular evidence file (xlsx/csv/tsv/jsonl):
    sheets, column names, row counts, and per-column example values sampled
    from the first rows. Always start here before table_query.
    """
    bad = _refuse_nontabular(path)
    if bad:
        return bad
    if not os.path.isfile(path):
        return {"success": False, "error": f"file not found: {path}"}
    empty = _refuse_empty_tabular(path)
    if empty:
        return empty
    sheets: dict[str, dict] = {}
    try:
        for sheet_name, row in _iter_rows(path, None):
            info = sheets.setdefault(
                sheet_name, {"columns": list(row.keys()), "rows": 0,
                             "examples": {}})
            info["rows"] += 1
            if info["rows"] <= sample_rows:
                for k, v in row.items():
                    if v and k not in info["examples"]:
                        info["examples"][k] = v[:80]
    except _ScanCapReached as cap:
        for info in sheets.values():
            info["row_count_truncated_at"] = cap.scanned
    except Exception as e:
        return {"success": False, "error": f"{type(e).__name__}: {e}"}
    # Persist per-sheet headers as schema SoT for later query binds.
    for sheet_name, info in sheets.items():
        cols = list(info.get("columns") or [])
        if sheet_name in ("-", "", None):
            _cache_headers(path, None, cols)
        else:
            _cache_headers(path, sheet_name, cols)
    # Single-sheet workbooks: also bind the default (sheet=None) key.
    if len(sheets) == 1:
        only = next(iter(sheets.values()))
        _cache_headers(path, None, list(only.get("columns") or []))
    # Clear schema-first latch — caller may now query with real headers.
    _clear_pending_schema_bind(path)
    return {"success": True, "path": path, "format": _kind(path),
            "sheets": sheets,
            "hint": "Query with table.table_query(path, sheet=…, "
                    "where=['column=value', 'column~regex'])."}


@mcp.tool()
@output_safe
def table_query(
    path: str,
    sheet: Optional[str] = None,
    columns: Optional[list[str]] = None,
    where: Optional[list[str]] = None,
    sort_by: Optional[str] = None,
    descending: bool = False,
    limit: int = 50,
    offset: int = 0,
    output_csv: Optional[str] = None,
) -> dict:
    """
    Filter/sort rows from a tabular evidence file (xlsx/csv/tsv/jsonl).
    where: list of predicates ANDed together — 'column=value' (case-insensitive
      equals), 'column!=value', 'column~regex', 'column>num' (also < >= <=).
    columns: restrict returned columns. sort_by: column name (numeric-aware).
    output_csv: also write ALL matching rows (uncapped) to this CSV under
      analysis/ or exports/ — use it when the match count exceeds the return cap.
    """
    bad = _refuse_nontabular(path)
    if bad:
        return bad
    if not os.path.isfile(path):
        return {"success": False, "error": f"file not found: {path}"}
    empty = _refuse_empty_tabular(path)
    if empty:
        return empty
    schema_first = _schema_first_redirect(path)
    if schema_first:
        return schema_first
    dialect_refuse = _refuse_sql_where_tree(where or [])
    if dialect_refuse:
        return dialect_refuse
    try:
        preds = _parse_where(where or [])
    except (ValueError, re.error) as e:
        return {"success": False, "error": str(e)}
    if columns:
        columns = [_strip_ident_quotes(c) for c in columns]
    if sort_by:
        sort_by = _strip_ident_quotes(sort_by)
    requested_cols = [c for c, _op, _v in preds]
    if columns:
        requested_cols.extend(columns)
    if sort_by:
        requested_cols.append(sort_by)
    refused = _unknown_columns_refusal(
        path, sheet=sheet, requested=requested_cols,
    )
    if refused:
        return refused
    try:
        headers = _peek_headers(path, sheet)
    except Exception:
        headers = []
    cmp_refuse = _refuse_non_numeric_compare(preds, headers)
    if cmp_refuse:
        return cmp_refuse
    rewrites = _column_rewrites(requested_cols, headers) if headers else {}
    if headers:
        preds = _canonicalize_preds(preds, headers)
        if columns:
            columns = _canonicalize_names(columns, headers)
        if sort_by:
            sort_by = _resolve_column_name(sort_by, headers) or sort_by
    limit = max(1, min(limit, MAX_RETURN_ROWS))
    offset = max(0, offset)
    total = scanned = 0
    scan_capped = False

    def matches():
        nonlocal total, scanned, scan_capped
        try:
            for sheet_name, row in _iter_rows(path, sheet):
                scanned += 1
                if _matches(row, preds):
                    total += 1
                    row["_sheet"] = sheet_name
                    yield row
        except _ScanCapReached:
            scan_capped = True

    def key(r):
        v = r.get(sort_by, "")
        n = _to_num(v)
        return (0, n, "") if n is not None else (1, 0.0, v.lower())

    # Every match is held only when all of them are written out. Otherwise
    # the requested window is, or under sort_by the head of the order up to
    # it: a broad query over a long file costs counting, not memory.
    keep = offset + limit
    try:
        if output_csv:
            matched = list(matches())
            if sort_by:
                matched.sort(key=key, reverse=descending)
        elif sort_by:
            pick = heapq.nlargest if descending else heapq.nsmallest
            matched = pick(keep, matches(), key=key)
        else:
            matched = []
            for row in matches():
                if len(matched) < keep:
                    matched.append(row)
    except Exception as e:
        return {"success": False, "error": f"{type(e).__name__}: {e}"}

    spilled = None
    if output_csv:
        try:
            spilled = _spill_csv(matched, output_csv)
        except Exception as e:
            return {"success": False, "error": f"output_csv write failed: {e}"}
    requested = matched[offset:offset + limit]
    window = [_clip_row(r, columns) for r in requested]
    window, payload_overflow = _payload_capped(window)
    result = {
        "success": True, "path": path, "sheet": sheet,
        "matched_rows": total,
        "returned_rows": len(window),
        "offset": offset,
        "rows": window,
        **_scan_fields(scanned, scan_capped, total),
        "payload_capped": payload_overflow or len(window) < len(requested),
        "output_csv": spilled,
        "valid_zero": total == 0 and not scan_capped,
        "schema_columns": list(headers) if headers else None,
        "hint": ("All matches written to output_csv." if spilled else
                 "Pass output_csv=<analysis path> to spill all matches "
                 "beyond the return cap."),
    }
    if rewrites:
        result["columns_rewritten"] = rewrites
    if total == 0:
        escape_hint = _doubled_escape_hint(where)
        if escape_hint:
            result["hint"] = escape_hint
    return result


@mcp.tool()
@output_safe
def table_pivot(
    path: str,
    group_by: list[str],
    sheet: Optional[str] = None,
    where: Optional[list[str]] = None,
    top: int = 25,
) -> dict:
    """
    Group-by / count over a tabular evidence file: frequency of each distinct
    value combination of the group_by columns (after optional where filter),
    highest count first. The fastest way to find the loudest talkers in a
    SIEM export (src_ip × dst_ip, user × host, event_id …).
    """
    bad = _refuse_nontabular(path)
    if bad:
        return bad
    if not os.path.isfile(path):
        return {"success": False, "error": f"file not found: {path}"}
    empty = _refuse_empty_tabular(path)
    if empty:
        return empty
    schema_first = _schema_first_redirect(path)
    if schema_first:
        return schema_first
    dialect_refuse = _refuse_sql_where_tree(where or [])
    if dialect_refuse:
        return dialect_refuse
    try:
        preds = _parse_where(where or [])
    except (ValueError, re.error) as e:
        return {"success": False, "error": str(e)}
    if group_by:
        group_by = [_strip_ident_quotes(c) for c in group_by]
    requested_cols = list(group_by or []) + [c for c, _o, _v in preds]
    refused = _unknown_columns_refusal(
        path, sheet=sheet, requested=requested_cols,
    )
    if refused:
        return refused
    try:
        headers = _peek_headers(path, sheet)
    except Exception:
        headers = []
    cmp_refuse = _refuse_non_numeric_compare(preds, headers)
    if cmp_refuse:
        return cmp_refuse
    rewrites = _column_rewrites(requested_cols, headers) if headers else {}
    if headers:
        preds = _canonicalize_preds(preds, headers)
        group_by = _canonicalize_names(group_by, headers)
    from collections import Counter
    counts: Counter = Counter()
    scanned = 0
    scan_capped = False
    try:
        for _sheet_name, row in _iter_rows(path, sheet):
            scanned += 1
            if _matches(row, preds):
                counts[tuple(row.get(c, "") for c in group_by)] += 1
    except _ScanCapReached:
        scan_capped = True
    except Exception as e:
        return {"success": False, "error": f"{type(e).__name__}: {e}"}
    top = max(1, min(top, MAX_RETURN_ROWS))
    groups = [
        {**{c: v for c, v in zip(group_by, combo)}, "count": n}
        for combo, n in counts.most_common(top)
    ]
    result = {
        "success": True, "path": path, "group_by": group_by,
        "distinct_groups": len(counts),
        **_scan_fields(scanned, scan_capped, len(counts)),
        "groups": groups,
        "schema_columns": list(headers) if headers else None,
    }
    if rewrites:
        result["columns_rewritten"] = rewrites
    return result


@mcp.tool()
@output_safe
def table_grep(
    path: str,
    pattern: str,
    sheet: Optional[str] = None,
    max_hits: int = 50,
    ignore_case: bool = True,
) -> dict:
    """
    Regex search across ALL cells of a tabular evidence file; returns each
    matching row with the column that hit. Use for IOC sweeps over SIEM/EDR
    exports (an IP, a username, a hash) when you don't yet know the schema.
    """
    bad = _refuse_nontabular(path)
    if bad:
        return bad
    if not os.path.isfile(path):
        return {"success": False, "error": f"file not found: {path}"}
    empty = _refuse_empty_tabular(path)
    if empty:
        return empty
    try:
        rx = re.compile(pattern, re.IGNORECASE if ignore_case else 0)
    except re.error as e:
        return {"success": False, "error": f"bad regex: {e}"}
    hits: list[dict] = []
    scanned = 0
    scan_capped = False
    max_hits = max(1, min(max_hits, MAX_RETURN_ROWS))
    try:
        for sheet_name, row in _iter_rows(path, sheet):
            scanned += 1
            hit_cols = [k for k, v in row.items() if v and rx.search(v)]
            if hit_cols:
                hits.append({"_sheet": sheet_name, "_row": scanned,
                             "_matched_columns": hit_cols,
                             **_clip_row(row, None)})
                if len(hits) >= max_hits:
                    break
    except _ScanCapReached:
        scan_capped = True
    except Exception as e:
        return {"success": False, "error": f"{type(e).__name__}: {e}"}
    hits, _ = _payload_capped(hits)
    return {"success": True, "path": path, "pattern": pattern, "hits": hits,
            "hit_count": len(hits), "max_hits": max_hits,
            "hit_cap_reached": len(hits) >= max_hits,
            **_scan_fields(scanned, scan_capped, len(hits))}
