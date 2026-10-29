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
import shutil
import subprocess
from typing import Iterable, Iterator, Optional

from fastmcp import FastMCP

from tools import media_types as MT

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


def _iter_rows(path: str, sheet: Optional[str], stats: Optional[dict] = None) -> Iterator[tuple[str, dict]]:
    """Yields (sheet_name, {column: str_value}); stops at the scan-row
    bound when an operator set one. ``stats`` (a dict) counts the rows
    bound and the ragged ones: a row with more or fewer fields than the
    header is bound by position, so its values may sit under the wrong
    names (_ragged_fields says so in the result)."""
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
        if stats is not None:
            stats["rows"] = stats.get("rows", 0) + 1
            if len(values) != len(header):
                stats["ragged"] = stats.get("ragged", 0) + 1
        row = {header[i] if i < len(header) else f"col{i+1}": _cell(v)
               for i, v in enumerate(values)}
        yield sheet_name, row


class _ScanCapReached(Exception):
    def __init__(self, scanned: int):
        self.scanned = scanned


def _ragged_fields(stats: Optional[dict]) -> dict:
    """What a scan says about rows whose field count differs from the
    header's: their count and share, and that such rows are bound by
    position. Nothing when every row fits the header. A code fact: an
    export whose records carry their own field sets (optional fields left
    out, or written in another order) reads as a column that is empty in
    every row; the reader decides."""
    n = int((stats or {}).get("ragged") or 0)
    rows = int((stats or {}).get("rows") or 0)
    if not n or not rows:
        return {}
    return {"ragged_rows": n, "ragged_share": round(n / rows, 3),
            "ragged_note": (f"{n} of {rows} rows carry a different number of fields than the header (the first "
                            "row); their values are bound to columns by position and may sit under the wrong "
                            "name, so a column empty in every row can be this binding rather than the data. "
                            "Fields beyond the header's width are named col<N> by position; read a few raw "
                            "rows to see each row's own field order before trusting a column.")}


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

    Models emit ``col='x' OR col='y'``; a parser taking the first
    ``=`` would treat the rest as a literal value → success + 0 rows + forged
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
    # Destination / remote peer (MDE Destination* <-> Remote*).
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
            # containment fallback: DestinationDevice <-> RemoteDeviceName
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
    """Refuse queries that name columns absent from the file schema.

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
    # A successful peek IS the file-local schema source of truth.
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


# What a clipped matched cell keeps: its head (an event-log message begins
# with its event id) and a window around the first match (why the row
# matched), so the trace holds the matched text.
_CLIP_HEAD_CHARS = 200
_CLIP_WINDOW_CHARS = 300


def _clip_cell(value: str, rx: Optional[re.Pattern]) -> str:
    """A cell longer than _CELL_CAP: its first _CLIP_HEAD_CHARS and a window
    of _CLIP_WINDOW_CHARS around the first match when the match lies past
    the head (ATLAS_TABLE_CLIP_AT_MATCH); else its head."""
    if len(value) <= _CELL_CAP:
        return value
    from core.envfile import env_flag
    m = rx.search(value) if (rx is not None and env_flag("ATLAS_TABLE_CLIP_AT_MATCH")) else None
    if not m or m.start() < _CLIP_HEAD_CHARS:
        return value[:_CELL_CAP] + "…"
    start = max(_CLIP_HEAD_CHARS, min(m.start() - _CLIP_WINDOW_CHARS // 3, len(value) - _CLIP_WINDOW_CHARS))
    end = start + _CLIP_WINDOW_CHARS
    return value[:_CLIP_HEAD_CHARS] + " … " + value[start:end] + ("…" if end < len(value) else "")


def _clip_row(row: dict, columns: Optional[list[str]], rx: Optional[re.Pattern] = None,
              matched: Iterable[str] = ()) -> dict:
    if columns:
        row = {c: row.get(c, "") for c in columns}
    matched = set(matched)
    return {k: (_clip_cell(v, rx if k in matched else None) if len(v) > _CELL_CAP else v)
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


@mcp.tool(meta={"reads": list(MT.SPREADSHEET_OOXML)})      # openpyxl: the OOXML spreadsheets (csv is text, undeclared)
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
    timed = _time_args_on()
    from core import table_rows as T
    tcols_of: dict[str, list[str]] = {}
    widths: dict = {}
    try:
        for sheet_name, row in _iter_rows(path, None, widths):
            info = sheets.setdefault(
                sheet_name, {"columns": list(row.keys()), "rows": 0,
                             "examples": {}})
            info["rows"] += 1
            if info["rows"] <= sample_rows:
                for k, v in row.items():
                    if v and k not in info["examples"]:
                        info["examples"][k] = v[:80]
            if timed:
                # The time columns (one definition) and the span of
                # their parsed moments over every row the pass reads.
                if sheet_name not in tcols_of:
                    tcols_of[sheet_name] = T.time_column_names(list(row.keys()), [list(row.values())])
                    info["time_columns"] = tcols_of[sheet_name]
                if tcols_of[sheet_name]:
                    m = T.row_moment(row, tcols_of[sheet_name])
                    if m:
                        span = info.setdefault("time_span", {"first": m, "last": m})
                        if m < span["first"]:
                            span["first"] = m
                        if m > span["last"]:
                            span["last"] = m
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
            "sheets": sheets, **_ragged_fields(widths),
            "hint": "Query with table.table_query(path, sheet=…, "
                    "where=['column=value', 'column~regex'])."}


@mcp.tool(meta={"reads": list(MT.SPREADSHEET_OOXML)})
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
    time_start: Optional[str] = None,
    time_end: Optional[str] = None,
) -> dict:
    """
    Filter/sort rows from a tabular evidence file (xlsx/csv/tsv/jsonl).
    where: list of predicates ANDed together — 'column=value' (case-insensitive
      equals), 'column!=value', 'column~regex', 'column>num' (also < >= <=).
    columns: restrict returned columns. sort_by: column name (numeric-aware;
      a time column sorts by the parsed time).
    time_start / time_end: one period (ISO date or date and time; a date
      alone as the end takes the whole day) over the table's time columns.
    offset: the next rows of the same query.
    output_csv: writes every matching row to this CSV under analysis/ or exports/.
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
    window = _window(time_start, time_end) if _time_args_on() else None
    from core import table_rows as T
    tcols: list[str] = []
    if (window or sort_by) and headers and _time_args_on():
        sample: list[list[str]] = []
        try:
            for _sn, r in _iter_rows(path, sheet):
                sample.append([str(r.get(h) or "") for h in headers])
                if len(sample) >= 20:
                    break
        except Exception:  # noqa: BLE001
            sample = []
        tcols = T.time_column_names(headers, sample)

    def finish(result: dict) -> dict:
        # The one tail of both row paths. hit_cap_reached: the result does not
        # hold every match (table_grep's test); the view's "N of M" and its
        # next step read it.
        result["hit_cap_reached"] = result["returned_rows"] < result["matched_rows"]
        if rewrites:
            result["columns_rewritten"] = rewrites
        if not result["matched_rows"]:
            escape_hint = _doubled_escape_hint(where)
            if escape_hint:
                result["hint"] = escape_hint
        return result

    if _survey_on() and not offset and not sort_by and not output_csv and not window:
        try:
            result = _query_counted(path, sheet, preds, columns, limit)
        except Exception as e:  # noqa: BLE001
            return {"success": False, "error": f"{type(e).__name__}: {e}"}
        result["schema_columns"] = list(headers) if headers else None
        result["hint"] = ("Every match is counted; when more match than limit the rows are a survey of all of "
                          "them.")
        return finish(result)
    total = scanned = total_all = 0
    scan_capped = False
    widths: dict = {}

    def matches():
        nonlocal total, scanned, scan_capped, total_all
        try:
            for sheet_name, row in _iter_rows(path, sheet, widths):
                scanned += 1
                if _matches(row, preds):
                    total_all += 1
                    if window is not None:
                        moment = T.row_moment(row, tcols) if tcols else ""
                        if not moment or not (window[0] <= moment <= window[1]):
                            continue
                    total += 1
                    # The record's place, numbered as the survey path numbers it
                    # (_count_rows: the data row's ordinal in the file), so a page,
                    # a sort or a column list name one record one way.
                    row["_sheet"] = sheet_name
                    row["_row"] = scanned
                    yield row
        except _ScanCapReached:
            scan_capped = True

    by_time = bool(sort_by and sort_by in tcols)

    def key(r):
        if by_time:
            # A time column sorts by the parsed moment, across months and years.
            m = T.row_moment(r, [sort_by])
            return (0 if m else 1, 0.0, m)
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
            spilled = _spill_csv([{k: v for k, v in r.items() if k != "_row"} for r in matched], output_csv)
        except Exception as e:
            return {"success": False, "error": f"output_csv write failed: {e}"}
    requested = matched[offset:offset + limit]
    window_rows = [{"_sheet": r.get("_sheet") or "-", "_row": r.get("_row"),
                    **_clip_row({k: v for k, v in r.items() if k not in ("_sheet", "_row")}, columns)}
                   for r in requested]
    window_rows, payload_overflow = _payload_capped(window_rows)
    result = {
        "success": True, "path": path, "sheet": sheet,
        "matched_rows": total,
        **({"matched_rows_all": total_all, "time_start": time_start, "time_end": time_end}
           if window is not None else {}),
        "returned_rows": len(window_rows),
        "offset": offset,
        "rows": window_rows,
        **_scan_fields(scanned, scan_capped, total), **_ragged_fields(widths),
        "payload_capped": payload_overflow or len(window_rows) < len(requested),
        "output_csv": spilled,
        "valid_zero": total == 0 and not scan_capped,
        "schema_columns": list(headers) if headers else None,
    }
    if spilled:
        result["hint"] = "All matches written to output_csv."
    return finish(result)


def _pivot_table(
    path: str,
    group_by: list[str],
    sheet: Optional[str] = None,
    where: Optional[list[str]] = None,
    top: int = 25,
) -> dict:
    """table_pivot over one table: frequency of each distinct value
    combination of the group_by columns, highest count first."""
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
    widths: dict = {}
    try:
        for _sheet_name, row in _iter_rows(path, sheet, widths):
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
        **_scan_fields(scanned, scan_capped, len(counts)), **_ragged_fields(widths),
        "groups": groups,
        "schema_columns": list(headers) if headers else None,
    }
    if rewrites:
        result["columns_rewritten"] = rewrites
    return result


def _stack_on_at_import() -> bool:
    try:
        from core.stack import stack_on
        return stack_on()
    except Exception:  # noqa: BLE001
        return False


if _stack_on_at_import():
    @mcp.tool()
    @output_safe
    def table_pivot(
        path: str | list[str],
        group_by: list[str],
        sheet: Optional[str] = None,
        where: Optional[list[str]] = None,
        top: int = 25,
        order: str = "common",
        across: Optional[str] = None,
        offset: int = 0,
        time_start: Optional[str] = None,
        time_end: Optional[str] = None,
    ) -> dict:
        """
        Group-by / count: frequency of each distinct value combination of the
        group_by columns (after optional where filter). The fastest way to find
        the loudest talkers in a SIEM export (src_ip x dst_ip, user x host,
        event_id ...), and to stack: count a column across hosts and read the
        values few hosts hold (order="rare"). Rare is not malicious; a filter
        narrows the population first.
        path: one table, a glob or a list of tables (each counted under its
            host), "index" (the files inside the images: host, path, directory,
            name, extension, size, mtime, deleted) or "call:N" (a prior call's
            saved output).
        order: common (most rows first) or rare (fewest hosts first; each group
            gives its hosts, rows and first and last time).
        across: the unit counted per value, a column name; default the host.
        offset: pages through the groups.
        time_start / time_end: one period (ISO date or date and time; a date
            alone as the end takes the whole day) over the time column.
        """
        from core.stack import stack
        many = isinstance(path, list) or any(c in str(path) for c in "*?[")
        special = isinstance(path, str) and (path == "index" or path.startswith("call:"))
        if many or special or order != "common" or across or offset or time_start or time_end:
            from core.paths import active_case_dir
            case = active_case_dir() or os.getcwd()
            return stack(case, path, group_by, where, order, across, top, offset, time_start, time_end)
        return _pivot_table(path, group_by, sheet, where, top)
else:
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
        return _pivot_table(path, group_by, sheet, where, top)


def _case_rel(path: str) -> str:
    """A table named by its path inside the case: two hosts' tables often
    share a file name, so the base name alone would merge them."""
    try:
        from core.paths import active_case_dir
        case = active_case_dir()
        if case:
            rel = os.path.relpath(os.path.realpath(path), os.path.realpath(case))
            if not rel.startswith(".."):
                return rel.replace(os.sep, "/")
    except Exception:  # noqa: BLE001
        pass
    return path


@mcp.tool()
@output_safe
def table_grep(
    path: str,
    pattern: str,
    sheet: Optional[str] = None,
    max_hits: int = 50,
    ignore_case: bool = True,
    sources: Optional[list[str]] = None,
    time_start: Optional[str] = None,
    time_end: Optional[str] = None,
    order: str = "asc",
    offset: Optional[int] = None,
    output_csv: Optional[str] = None,
) -> dict:
    """
    Regex search across ALL cells of a tabular evidence file; returns each
    matching row with the column that hit. Use for IOC sweeps over SIEM/EDR
    exports (an IP, a username, a hash) when you don't yet know the schema.
    Every match of the file is counted: matched_rows, per term (for a
    pattern of alternatives a|b|c) its rows and first and last time, the
    sources and the days the matches fall on. When more rows match than
    max_hits, the rows returned are a survey of all of them (the first row
    of each term and of each source, the last row of each term, the rest
    spread over time); _n is a row's place in the time order of every match.
    sources: other tables to count the same pattern in. The result is then
    complete as it stands: a "counted" line naming each table and its
    matching rows, and per table its terms with their rows and first and
    last time; it returns no rows (grep one table without sources for
    them).
    time_start / time_end: one period (ISO date or date and time; a date
    alone as the end takes the whole day); matched_rows then counts the
    window and matched_rows_all every match.
    order / offset: rows in time order page by page: offset=0 (oldest
    first) or order="desc" (newest first), then offset=<n> for the next
    page; without either, more matches than max_hits give the survey.
    output_csv: writes every matching row (in the window) to this CSV under
    analysis/ or exports/.
    """
    if sources and _survey_on() and (time_start or time_end):
        return {"success": False, "error": ("sources= counts each table whole and takes no time window: "
                                            "drop time_start/time_end, or search one table with the window")}
    if sources and _survey_on():
        counts = [count_matches(p, pattern, ignore_case)
                  for p in dict.fromkeys([path, *[str(x) for x in sources if x]])]
        # One self-contained line first: the answer, not a rows section
        # that looks cut off.
        parts = [f"{_case_rel(str(c.get('path') or ''))}: "
                 + (f"error ({c['error']})" if c.get("error") else f"{c.get('matched_rows', 0)}")
                 for c in counts]
        return {"success": True, "pattern": pattern,
                "counted": f"counted in {len(counts)} tables: " + ", ".join(parts),
                "counts": counts,
                "note": "counts only, complete; no rows are returned for a count across tables"}
    bad = _refuse_nontabular(path)
    if bad:
        return bad
    if not os.path.isfile(path):
        return {"success": False, "error": f"file not found: {path}"}
    empty = _refuse_empty_tabular(path)
    if empty:
        return empty
    flags = re.IGNORECASE if ignore_case else 0
    try:
        rx = re.compile(pattern, flags)
    except re.error as e:
        return {"success": False, "error": f"bad regex: {e}"}
    max_hits = max(1, min(max_hits, MAX_RETURN_ROWS))
    paging = _time_args_on() and (time_start or time_end or offset is not None or order == "desc" or output_csv)
    if _survey_on() or paging:
        return _grep_counted(path, pattern, sheet, max_hits, rx, flags,
                             window=_window(time_start, time_end) if paging else None,
                             order=order if paging else "asc",
                             offset=offset if paging else None,
                             output_csv=output_csv if paging else None)
    hits: list[dict] = []
    scanned = 0
    scan_capped = False
    # A pattern of several alternatives is several searches in one scan. Once
    # the rows to show are collected the scan goes on for the alternatives no
    # row has matched yet, and stops when every one has or at the end of the
    # file: a frequent alternative fills the hit cap in the first rows, and a
    # search that stopped there would say nothing about the others.
    alts = _alternatives(pattern, flags)
    seen: set[int] = set()
    rest: Optional[re.Pattern] = None
    ended = grep_tried = settled = False
    widths: dict = {}
    try:
        for sheet_name, row in _iter_rows(path, sheet, widths):
            scanned += 1
            if len(hits) < max_hits:
                hit_cols = [k for k, v in row.items() if v and rx.search(v)]
                if hit_cols:
                    hits.append({"_sheet": sheet_name, "_row": scanned,
                                 "_matched_columns": hit_cols,
                                 **_clip_row(row, None, rx, hit_cols)})
                    if alts:
                        _mark_alternatives(alts, seen, [row[k] for k in hit_cols])
                    if len(hits) >= max_hits and (not alts or len(seen) == len(alts)):
                        break
                continue
            if not grep_tried:
                grep_tried = True
                if _grep_settle(path, alts, seen, flags):
                    settled = True
                    break
            if rest is None:
                rest = _alternation([a for i, a in enumerate(alts) if i not in seen], flags)
            cells = [v for v in row.values() if v]
            if any(rest.search(v) for v in cells):
                before = len(seen)
                _mark_alternatives(alts, seen, cells)
                if len(seen) == len(alts):
                    break
                if len(seen) != before:
                    rest = None
        else:
            ended = True
    except _ScanCapReached:
        scan_capped = True
    except Exception as e:
        return {"success": False, "error": f"{type(e).__name__}: {e}"}
    # hit_cap_reached: the result does not show every row that matched,
    # because the scan stopped at max_hits (decided before any row is dropped)
    # or because rows were dropped to fit the output (payload_capped).
    stopped_at_cap = len(hits) >= max_hits
    shown, _ = _payload_capped(hits)
    payload_capped = len(shown) < len(hits)
    hits = shown
    out = {"success": True, "path": path, "pattern": pattern}
    if alts and (stopped_at_cap or payload_capped):
        out["alternatives"] = _alternatives_field(
            alts, seen, resolved=ended or settled or len(seen) == len(alts))
    return {**out, "hits": hits,
            "hit_count": len(hits), "max_hits": max_hits,
            "hit_cap_reached": stopped_at_cap or payload_capped,
            "payload_capped": payload_capped,
            **_scan_fields(scanned, scan_capped, len(hits)), **_ragged_fields(widths)}


def _alternatives(pattern: str, flags: int) -> Optional[list[tuple[str, re.Pattern]]]:
    """The top-level alternatives of ``pattern`` ("a|b(c|d)|e" gives a,
    b(c|d) and e), each with its own compiled regex; None for a pattern of
    one alternative, or one whose parts do not stand alone (a backreference
    across them, a verbose pattern whose comments may hold a bar)."""
    if "(?x" in pattern or re.search(r"\\[1-9]|\(\?P=", pattern):
        return None
    # Leading global flags apply to every alternative: each carries them as a
    # scoped group, so the alternatives still combine into one pattern.
    lead = re.match(r"\(\?([a-zA-Z]+)\)", pattern)
    letters = lead.group(1) if lead else ""
    if set(letters) - set("ims"):
        return None
    body = pattern[lead.end():] if lead else pattern
    parts: list[str] = []
    cur: list[str] = []
    depth, in_class, i = 0, False, 0
    while i < len(body):
        ch = body[i]
        if ch == "\\":
            cur.append(body[i:i + 2])
            i += 2
            continue
        if in_class:
            in_class = ch != "]"
        elif ch == "[":
            # A "]" right after "[" or "[^" is a literal member.
            j = i + 1 + (body[i + 1:i + 2] == "^")
            j += body[j:j + 1] == "]"
            cur.append(body[i:j])
            i, in_class = j, True
            continue
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        elif ch == "|" and depth == 0:
            parts.append("".join(cur))
            cur = []
            i += 1
            continue
        cur.append(ch)
        i += 1
    parts.append("".join(cur))
    if len(parts) < 2:
        return None
    try:
        return [(p, re.compile(f"(?{letters}:{p})" if letters else p, flags)) for p in parts]
    except re.error:
        return None


# The encodings in which an ASCII pattern meets the same bytes grep reads.
_GREP_ENCODINGS = frozenset({"utf-8", "utf-8-sig", "cp1252"})
# What reads a line differently from a cell: anchors (a cell ends inside the
# line, and "$" does not match before a CR), and escapes or classes that
# reach a line break inside a quoted cell or a byte grep sees one by one.
# Over-cautious on purpose: such an alternative only costs the row loop.
_GREP_LINE_UNSAFE = re.compile(r"[$^]|\\[AZsWDnrvfxuUN0-7]|\[\^|\(\?[a-zA-Z]*s")


def _grep_settle(path: str, alts: list[tuple[str, re.Pattern]], seen: set[int],
                 flags: int) -> bool:
    """Settle the alternatives no row has matched yet with GNU grep (-P),
    which reads a delimited file at disk speed where the row loop runs the
    regex over every cell of every row: minutes for a wide timeline of a
    gigabyte. Each pass searches the unseen alternatives, tells which one a
    match belongs to with that alternative's own regex, and starts again for
    the rest as soon as one is found; a pass with no match at all leaves
    them absent from the file.
    True when every alternative is settled. False when grep cannot stand in
    for the row loop here (not a delimited text table in an ASCII-compatible
    encoding, a row bound set, an alternative grep would read differently:
    non-ASCII, or a quote, which a CSV cell doubles; grep missing, failing,
    or matching what the alternatives do not), and the caller scans on.
    Accepted gap: grep -i folds ASCII only in the C locale, where Python's
    case-insensitive match also folds a few non-ASCII look-alikes (a long s,
    the Kelvin sign) and its \\w and \\d take non-ASCII letters and digits;
    an indicator written with such a character in the one cell that holds it
    reads as unmatched here."""
    if MAX_SCAN_ROWS or _kind(path) != "csv":
        return False
    encoding = text_encoding(path)
    grep = shutil.which("grep")
    if encoding not in _GREP_ENCODINGS or not grep:
        return False
    rest = [i for i in range(len(alts)) if i not in seen]
    if any(not alts[i][0].isascii() or '"' in alts[i][0] or "'" in alts[i][0]
           or _line_unsafe(alts[i][1].pattern) for i in rest):
        return False
    env = {**os.environ, "LC_ALL": "C"}
    case = ["-i"] if flags & re.IGNORECASE else []
    while rest:
        pattern = "|".join(f"(?:{alts[i][1].pattern})" for i in rest)
        try:
            proc = subprocess.Popen([grep, "-a", "-o", "-P", *case, "-e", pattern, "--", path],
                                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env)
        except (OSError, ValueError):
            return False
        before, tested, found = len(seen), set(), False
        try:
            for line in proc.stdout:
                if line in tested:
                    continue
                if len(tested) < 50_000:
                    tested.add(line)
                text = line.decode(encoding, "replace").rstrip("\r\n")
                _mark_alternatives(alts, seen, [text])
                # A found alternative would go on printing every occurrence:
                # search again for the rest only.
                if len(seen) > before:
                    found = True
                    break
        finally:
            # Killed only when it was stopped early: after its last line a grep
            # may still be exiting, and a kill would turn its exit 1 into -9.
            if found and proc.poll() is None:
                proc.kill()
            code = proc.wait()
            proc.stdout.close()
        rest = [i for i in rest if i not in seen]
        if not rest:
            return True
        if found:
            continue
        if code == 1:
            return True                  # no line of the file holds any of them
        return False                     # an error, or matches no alternative claims
    return True


def _alternation(alts: list[tuple[str, re.Pattern]], flags: int) -> re.Pattern:
    return re.compile("|".join(f"(?:{a.pattern})" for _, a in alts), flags)


def _mark_alternatives(alts: list[tuple[str, re.Pattern]], seen: set[int],
                       cells: list[str]) -> None:
    for i, (_, arx) in enumerate(alts):
        if i not in seen and any(arx.search(c) for c in cells):
            seen.add(i)


def _alternatives_field(alts: list[tuple[str, re.Pattern]], seen: set[int], *,
                        resolved: bool) -> dict:
    """Which alternatives of a search that stopped at its cap match a row of
    the file. Only an answer the scan established is listed: an alternative
    no row matched is named only when the whole file was read."""
    out: dict = {"matched": [src for i, (src, _) in enumerate(alts) if i in seen]}
    if resolved:
        out["unmatched"] = [src for i, (src, _) in enumerate(alts) if i not in seen]
        out["note"] = ("The rows shown stop at the cap. 'matched' lists the alternatives "
                       "of the pattern that match at least one row of this file, shown or "
                       "not; 'unmatched' those that match no row anywhere in it. Search a "
                       "matched alternative on its own to see its rows.")
    else:
        out["unresolved"] = len(alts) - len(seen)
        out["note"] = ("The rows shown stop at the cap, and the scan stopped at its row "
                       "bound before every alternative was seen: 'matched' lists those "
                       "found; nothing is said about the unresolved ones.")
    return out


# ── the grep guard reads a pattern token by token ──────────────────────────

_LINE_UNSAFE_ESCAPES = frozenset("AZsWDnrvfxuUN01234567")


def _line_unsafe(pattern: str) -> bool:
    """Whether grep would read ``pattern`` over a line differently from the
    row loop over a cell (ATLAS_GREP_GUARD_TOKENS; off: the regex test).
    Read token by token: a backslash and the next character are one token,
    so the escaped backslash of a Windows path is a literal and not the
    class it would look like to a regex over the pattern text. Refused: an
    escape that reaches a line break, a byte or a class (the letters above),
    an anchor outside a class, a negated class, the dot-all flag."""
    from core.envfile import env_flag
    if not env_flag("ATLAS_GREP_GUARD_TOKENS"):
        return bool(_GREP_LINE_UNSAFE.search(pattern))
    i, in_class = 0, False
    while i < len(pattern):
        ch = pattern[i]
        if ch == "\\":
            if pattern[i + 1:i + 2] in _LINE_UNSAFE_ESCAPES:
                return True
            i += 2
            continue
        if in_class:
            in_class = ch != "]"
        elif ch == "[":
            if pattern[i + 1:i + 2] == "^":
                return True
            j = i + 1 + (pattern[i + 1:i + 2] == "]")
            i, in_class = j, True
            continue
        elif ch in "^$":
            return True
        elif ch == "(" and pattern[i + 1:i + 2] == "?":
            flags = re.match(r"[a-zA-Z-]*", pattern[i + 2:]).group(0)
            if "s" in flags.split("-", 1)[0]:
                return True
        i += 1
    return False


# ── the count pass (ATLAS_TABLE_SURVEY) ────────────────────────────────────
#
# A search counts every match of the file: per term its rows, first and last
# time, per source group its rows, the distribution over time, and returns a
# survey of the whole match set when more rows match than the page holds.
# One small record per match; the rows returned are parsed per cell. The
# behaviour guard ATLAS_TABLE_FULL_PARSE_LINES chooses how a delimited text
# file is counted (every matching line parsed, or above the bound one
# streamed pass reading each line's time and source from its prefix); it is
# never a cap: every call reads to the end and names the path it took.

def _survey_on() -> bool:
    from core.envfile import env_flag
    return env_flag("ATLAS_TABLE_SURVEY")


def _full_parse_lines() -> int:
    return max(0, env_int("ATLAS_TABLE_FULL_PARSE_LINES", 20_000))


def _csv_dialect(sample: str):
    try:
        return csv.Sniffer().sniff(sample, delimiters=",;\t|")
    except csv.Error:
        return csv.excel


class _Count:
    """Every match of one search: its row number, time, source group and
    term bits, and the clipped row while the rows are held."""

    def __init__(self, alts: list[tuple[str, re.Pattern]]):
        self.alts = alts
        self.rownos: list[int] = []
        self.times: list[str | None] = []
        self.groups: list[str] = []
        self.bits: list[int] = []
        self.offsets: list[int] = []
        self.rows: list[dict] | None = []
        self.sheet: list[str] = []
        self.count_path = "rows"
        self.count_basis = "rows"
        self.row_numbering = "rows"
        self.unparsed = 0
        self.scanned = 0
        self.widths: dict = {}          # rows bound and ragged ones (_ragged_fields)
        self.scan_capped = False
        self.file_order = False
        self.has_time = False
        self.has_source = False
        self.ready = None

    def bits_of(self, cells: Iterable[str]) -> int:
        if len(self.alts) < 2:
            return 1
        cells = [c for c in cells if c]
        return sum(1 << a for a, (_s, arx) in enumerate(self.alts) if any(arx.search(c) for c in cells))


def _roles(headers: list[str], sample: list[list[str]]) -> tuple[list[str], list[str]]:
    from core import table_rows as T
    return T.time_column_names(headers, sample), T.source_columns(headers)


def _moment(row: dict, tcols: list[str]) -> str | None:
    from core import table_rows as T
    return (T.row_moment(row, tcols) or None) if tcols else None


def _count_rows(path: str, sheet: Optional[str], test, clip, cnt: _Count) -> None:
    """The row loop: every row, the test per cell (``test(row)`` gives the
    matched columns or nothing); rows are held while the matches stay within
    the parse bound and fetched again by number otherwise."""
    bound = _full_parse_lines()
    tcols = scols = None
    try:
        for sheet_name, row in _iter_rows(path, sheet, cnt.widths):
            cnt.scanned += 1
            if tcols is None:
                headers = list(row)
                tcols, scols = _roles(headers, [[row.get(h) or "" for h in headers]])
                cnt.has_time, cnt.has_source = bool(tcols), bool(scols)
            hit_cols = test(row)
            if hit_cols is None:
                continue
            cnt.rownos.append(cnt.scanned)
            cnt.sheet.append(sheet_name)
            cnt.times.append(_moment(row, tcols))
            cnt.groups.append("/".join(str(row.get(c) or "") for c in scols))
            cnt.bits.append(cnt.bits_of(row[k] for k in hit_cols))
            if cnt.rows is not None:
                if len(cnt.rows) < max(bound, 1):
                    cnt.rows.append({"_sheet": sheet_name, "_row": cnt.scanned, "_matched_columns": hit_cols,
                                     **clip(row, hit_cols)})
                else:
                    cnt.rows = None
    except _ScanCapReached:
        cnt.scan_capped = True


def _rows_by_number(path: str, sheet: Optional[str], wanted: set[int], test, clip) -> dict[int, dict]:
    """The rows numbered ``wanted``, read again (the row loop's numbering)."""
    out: dict[int, dict] = {}
    n = 0
    try:
        for sheet_name, row in _iter_rows(path, sheet):
            n += 1
            if n in wanted:
                hit_cols = test(row) or []
                out[n] = {"_sheet": sheet_name, "_row": n, "_matched_columns": hit_cols, **clip(row, hit_cols)}
                if len(out) == len(wanted):
                    break
    except _ScanCapReached:
        pass
    return out


def _grep_ready(path: str, alts: list[tuple[str, re.Pattern]]):
    """``(grep, encoding, dialect, headers, header_text)`` when GNU grep can
    stand in for the row loop on this file and pattern (_grep_settle's
    conditions), else None."""
    if MAX_SCAN_ROWS or _kind(path) != "csv":
        return None
    encoding = text_encoding(path)
    grep = shutil.which("grep")
    if encoding not in _GREP_ENCODINGS or not grep:
        return None
    if any(not src.isascii() or '"' in src or "'" in src or _line_unsafe(arx.pattern) for src, arx in alts):
        return None
    try:
        with open_text(path, newline="") as f:
            sample = f.read(65536)
    except OSError:
        return None
    if sample.count("\n") + sample.count("\r") <= 1:
        return None            # records without terminators: the row loop splits them
    dialect = _csv_dialect(sample)
    first = sample.splitlines()[0] if sample else ""
    try:
        head = next(csv.reader([first], dialect))
    except (csv.Error, StopIteration):
        return None
    headers = [(c or "").strip().lstrip("\ufeff") or f"col{i+1}" for i, c in enumerate(head)]
    if not _lines_are_records(path, dialect):
        return None            # grep's line numbers are not the records' ordinals here: the row loop
    return grep, encoding, dialect, headers, first


# Per file version (path, size, modification time): whether every record is
# one line. Bounded by clearing; an entry is a few dozen bytes.
_ONE_LINE_RECORDS: dict[tuple, bool] = {}


def _lines_are_records(path: str, dialect) -> bool:
    """Whether every record of the file is one line, so that a grep line
    number minus one is the record ordinal the row loop gives (``_row``,
    which a table view's reader maps back to the row's source): a cell
    holding a quoted line break makes its record two lines and shifts every
    later line number by one. One reader pass per file version."""
    try:
        st = os.stat(path)
    except OSError:
        return False
    key = (os.path.abspath(path), st.st_size, st.st_mtime_ns)
    hit = _ONE_LINE_RECORDS.get(key)
    if hit is None:
        records, hit = 0, True
        try:
            with open_text(path, newline="") as f:
                reader = csv.reader(f, dialect)
                for records, _row in enumerate(reader, 1):
                    if reader.line_num != records:
                        hit = False
                        break
        except (csv.Error, OSError):
            hit = False
        # The reader also ends a line at a lone "\r", grep at "\n" only.
        hit = hit and _line_count(path) in (records, records - 1)
        if len(_ONE_LINE_RECORDS) >= 256:
            _ONE_LINE_RECORDS.clear()
        _ONE_LINE_RECORDS[key] = hit
    return hit


def _grep_proc(grep: str, pattern: str, path: str, flags: int, *opts: str):
    case = ["-i"] if flags & re.IGNORECASE else []
    return subprocess.Popen([grep, "-a", *opts, "-P", *case, "-e", pattern, "--", path],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            env={**os.environ, "LC_ALL": "C"})


def _grep_count_lines(grep: str, pattern: str, path: str, flags: int) -> int | None:
    proc = _grep_proc(grep, pattern, path, flags, "-c")
    out, _ = proc.communicate()
    if proc.returncode not in (0, 1):
        return None
    try:
        return int(out.decode().strip() or 0)
    except ValueError:
        return None


def _line_count(path: str) -> int:
    n = 0
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            n += block.count(b"\n")
    return n


def _count_grep_parsed(path: str, ready, rx: re.Pattern, flags: int, pattern: str, clip,
                       cnt: _Count) -> bool:
    """Path 2: every matching line parsed with the file's dialect and kept
    only when a cell matches (the row loop's own test). False when a line
    does not parse to the header's columns (a cell holding a line break, a
    shifted export): the caller takes the row loop."""
    grep, encoding, dialect, headers, _first = ready
    tcols, scols = _roles(headers, [])
    cnt.has_time, cnt.has_source = bool(tcols), bool(scols)
    proc = _grep_proc(grep, pattern, path, flags, "-n")
    ok = True
    try:
        for raw in proc.stdout:
            num, _, text = raw.partition(b":")
            if num == b"1":
                continue
            line = text.decode(encoding, "replace").rstrip("\r\n")
            try:
                cells = next(csv.reader([line], dialect))
            except (csv.Error, StopIteration):
                ok = False
                break
            if len(cells) != len(headers):
                ok = False
                break
            row = dict(zip(headers, cells))
            hit_cols = [k for k, v in row.items() if v and rx.search(v)]
            if not hit_cols:
                continue                 # matched across two cells only
            rowno = int(num) - 1
            cnt.rownos.append(rowno)
            cnt.sheet.append("-")
            cnt.times.append(_moment(row, tcols))
            cnt.groups.append("/".join(str(row.get(c) or "") for c in scols))
            cnt.bits.append(cnt.bits_of(row[k] for k in hit_cols))
            cnt.rows.append({"_sheet": "-", "_row": rowno, "_matched_columns": hit_cols, **clip(row, hit_cols)})
    finally:
        if not ok and proc.poll() is None:
            proc.kill()
        code = proc.wait()
        proc.stdout.close()
    if not ok or code not in (0, 1):
        return False
    cnt.count_path, cnt.count_basis, cnt.row_numbering = "grep-parsed", "rows", "lines"
    return True


def _count_grep_lines(path: str, ready, flags: int, pattern: str, cnt: _Count) -> bool:
    """Path 3, above the parse bound: one streamed pass; every matching line
    gets its number, byte offset, term bits (each term's regex on the raw
    line) and its time and source cells read from the line's prefix (the
    CSV reader only when a quote lies in the prefix). Exact by line. False
    when a line's prefix does not parse or its time cell does not read
    where the header names a time column (a continuation line of a cell
    holding a line break): the caller takes path 2."""
    from core import table_rows as T
    grep, encoding, dialect, headers, _first = ready
    tcols, scols = _roles(headers, [])
    cnt.has_time, cnt.has_source = bool(tcols), bool(scols)
    tidx = [headers.index(c) for c in tcols]
    sidx = [headers.index(c) for c in scols]
    need = max(tidx + sidx) + 1 if (tidx or sidx) else 0
    delim = str(getattr(dialect, "delimiter", ",")).encode(encoding)
    quote = str(getattr(dialect, "quotechar", '"') or '"').encode(encoding)
    proc = _grep_proc(grep, pattern, path, flags, "-b", "-n")
    try:
        for raw in proc.stdout:
            parts = raw.split(b":", 2)
            if len(parts) < 3 or parts[0] == b"1":
                continue
            num, off, text = parts
            text = text.rstrip(b"\r\n")
            cells: list[str] | None = None
            if need:
                cut = text.split(delim, need)
                head = text[: len(text) - len(cut[-1])] if len(cut) > need else text
                if len(cut) > need and quote not in head:
                    cells = [c.decode(encoding, "replace") for c in cut[:need]]
                else:
                    try:
                        full = next(csv.reader([text.decode(encoding, "replace")], dialect))
                    except (csv.Error, StopIteration):
                        full = []
                    cells = full[:need] if len(full) == len(headers) else None
            when = None
            if tidx and cells is not None:
                iso = T.row_time(cells, tidx)
                when = iso.replace("T", " ") if iso else None
            if need and (cells is None or (tidx and when is None)):
                cnt.unparsed += 1
            cnt.rownos.append(int(num) - 1)
            cnt.offsets.append(int(off))
            cnt.sheet.append("-")
            cnt.times.append(when)
            cnt.groups.append("/".join(cells[i] for i in sidx) if (cells is not None and sidx) else "")
            cnt.bits.append(cnt.bits_of([text.decode(encoding, "replace")]))
    finally:
        code = proc.wait()
        proc.stdout.close()
    if code not in (0, 1) or cnt.unparsed:
        return False
    cnt.rows = None
    cnt.count_path, cnt.count_basis, cnt.row_numbering = "grep-lines", "lines", "lines"
    timed = [t for t in cnt.times if t]
    cnt.file_order = any(b < a for a, b in zip(timed, timed[1:]))
    return True


def _rows_at_offsets(path: str, ready, offsets: dict[int, int], rx: re.Pattern, clip) -> dict[int, dict] | None:
    """The lines starting at the given byte offsets, parsed per cell (index
    -> row); None when one does not parse to the header's columns."""
    _grep, encoding, dialect, headers, _first = ready
    out: dict[int, dict] = {}
    with open(path, "rb") as fh:
        for i, (off, rowno) in offsets.items():
            fh.seek(off)
            line = fh.readline().decode(encoding, "replace").rstrip("\r\n")
            try:
                cells = next(csv.reader([line], dialect))
            except (csv.Error, StopIteration):
                return None
            if len(cells) != len(headers):
                return None
            row = dict(zip(headers, cells))
            hit_cols = [k for k, v in row.items() if v and rx.search(v)]
            out[i] = {"_sheet": "-", "_row": rowno, "_matched_columns": hit_cols, **clip(row, hit_cols)}
    return out


def _count_pass(path: str, sheet: Optional[str], pattern: str, rx: re.Pattern, flags: int,
                alts: list[tuple[str, re.Pattern]], clip) -> _Count:
    """Count every match of ``pattern`` in the file: the grep paths when
    the guard admits the file and pattern, else the row loop. A fallback
    keeps the number of lines the streamed path could not read."""
    def test(row: dict) -> list[str] | None:
        return [k for k, v in row.items() if v and rx.search(v)] or None

    unparsed = 0
    ready = _grep_ready(path, alts)
    if ready is not None:
        lines = _grep_count_lines(ready[0], pattern, path, flags)
        if lines is not None:
            if rx.search(ready[4]):
                lines -= 1               # the header line
            if lines > _full_parse_lines():
                cnt = _Count(alts)
                if _count_grep_lines(path, ready, flags, pattern, cnt):
                    cnt.scanned = max(0, _line_count(path) - 1)
                    cnt.ready = ready
                    return cnt
                # A matching line whose prefix or time cell did not read (a
                # continuation line, but also a row with an empty time cell)
                # sends the count to path 2: exact per cell, slower.
                unparsed = cnt.unparsed
            cnt = _Count(alts)
            cnt.unparsed = unparsed
            if _count_grep_parsed(path, ready, rx, flags, pattern, clip, cnt):
                cnt.scanned = max(0, _line_count(path) - 1)
                return cnt
    cnt = _Count(alts)
    cnt.unparsed = unparsed
    _count_rows(path, sheet, test, clip, cnt)
    return cnt


def _ranked(cnt: _Count) -> list[int]:
    """Match indices in the order ``_n`` counts: time order (file order
    among equal or missing times), or file order when the streamed path
    found the file out of time order."""
    n = len(cnt.rownos)
    if cnt.file_order:
        return list(range(n))
    return sorted(range(n), key=lambda i: (cnt.times[i] is None, cnt.times[i] or "", i))


def _term_sets(cnt: _Count) -> list[frozenset[int]]:
    cache: dict[int, frozenset[int]] = {}
    out = []
    for b in cnt.bits:
        s = cache.get(b)
        if s is None:
            s = cache[b] = frozenset(a for a in range(max(1, len(cnt.alts))) if b >> a & 1)
        out.append(s)
    return out


def _choose(cnt: _Count, k: int) -> tuple[list[tuple[int | None, int]], list[frozenset[int]]]:
    """The matches to return: every one when they fit, else the survey
    (core.table_rows.select) of the whole match set."""
    from core import table_rows as T
    n = len(cnt.rownos)
    tsets = _term_sets(cnt)
    if n <= k:
        return [(None, i) for i in range(n)], tsets
    times = [None] * n if cnt.file_order else cnt.times
    return T.select(n, times, tsets, cnt.groups, k, max(1, len(cnt.alts))), tsets


def _fetch_rows(path: str, sheet: Optional[str], cnt: _Count, idx: list[int], rx: re.Pattern, test,
                clip, whole: bool = False) -> dict[int, dict] | None:
    """The rows at the count's indices; ``whole`` reads them again from the
    file instead of taking the count pass's clipped copies."""
    if not whole and cnt.rows is not None and len(cnt.rows) == len(cnt.rownos):
        return {i: cnt.rows[i] for i in idx}
    if cnt.offsets:
        return _rows_at_offsets(path, cnt.ready, {i: (cnt.offsets[i], cnt.rownos[i]) for i in idx},
                                rx, clip)
    by_no = _rows_by_number(path, sheet, {cnt.rownos[i] for i in idx}, test, clip)
    return {i: by_no[cnt.rownos[i]] for i in idx if cnt.rownos[i] in by_no}


def _count_fields(cnt: _Count, tsets: list[frozenset[int]], *, with_terms: bool) -> tuple[dict, dict]:
    """The counts before the rows (match span, path, terms) and after them
    (sources, distribution), in the dict's key order."""
    import collections
    from core import table_rows as T
    n = len(cnt.rownos)
    timed = sorted(t for t in cnt.times if t)
    before: dict = {}
    if timed:
        before["match_span"] = {"first": timed[0], "last": timed[-1]}
    before["untimed_rows"] = n - len(timed)
    before["count_path"] = cnt.count_path
    before["count_basis"] = cnt.count_basis
    before["unparsed_lines"] = cnt.unparsed
    before["row_numbering"] = cnt.row_numbering
    if with_terms and len(cnt.alts) > 1:
        terms, empty = [], []
        for a, (src, _rx) in enumerate(cnt.alts):
            mine = [cnt.times[i] for i in range(n) if a in tsets[i]]
            if not mine:
                empty.append(src)
                continue
            ts = sorted(t for t in mine if t)
            terms.append({"term": src, "rows": len(mine), "first": ts[0] if ts else "",
                          "last": ts[-1] if ts else ""})
        before["terms"] = terms
        if not cnt.scan_capped:
            before["terms_with_no_row"] = empty
    after: dict = {}
    if cnt.has_source and n:
        after["sources"] = dict(collections.Counter(cnt.groups).most_common(8))
    basis = "all matching lines" if cnt.count_basis == "lines" else "all matching rows"
    if cnt.scan_capped:
        basis = "the matching rows of the rows scanned"
    dist = T.distribution(range(n), cnt.times, cnt.groups, tsets, cnt.alts, basis) if n else None
    if dist:
        after["distribution"] = dist
    return before, after


def _time_args_on() -> bool:
    """ATLAS_TABLE_TIME_ARGS: time windows, order and paging."""
    from core.envfile import env_flag
    return env_flag("ATLAS_TABLE_TIME_ARGS", True)


def _window(time_start: Optional[str], time_end: Optional[str]) -> tuple[str, str] | None:
    """(start, end) as "YYYY-MM-DD HH:MM:SS" strings for a comparison with
    the rows' moments; a date alone as the end covers that whole day."""
    if not time_start and not time_end:
        return None
    from core.table_rows import _parse_timestamp

    def norm(value: Optional[str], end: bool) -> str:
        v = str(value or "").strip()
        if not v:
            return "9999" if end else ""
        iso = (_parse_timestamp(v) or v).replace("T", " ")
        if end and len(v) <= 10:
            iso = iso[:10] + " 23:59:59.999999"
        return iso
    return norm(time_start, False), norm(time_end, True)


def _subset(cnt: _Count, keep: list[int]) -> _Count:
    """A count of only the matches ``keep`` (a window of them)."""
    out = _Count(cnt.alts)
    for attr in ("rownos", "times", "groups", "bits", "sheet"):
        src = getattr(cnt, attr)
        setattr(out, attr, [src[i] for i in keep] if len(src) == len(cnt.rownos) else list(src))
    out.offsets = [cnt.offsets[i] for i in keep] if cnt.offsets else []
    out.rows = ([cnt.rows[i] for i in keep] if cnt.rows is not None and len(cnt.rows) == len(cnt.rownos)
                else None)
    for attr in ("count_path", "count_basis", "row_numbering", "unparsed", "scanned", "scan_capped",
                 "file_order", "has_time", "has_source", "ready"):
        setattr(out, attr, getattr(cnt, attr))
    return out


def _grep_counted(path: str, pattern: str, sheet: Optional[str], max_hits: int, rx: re.Pattern,
                  flags: int, *, window: tuple[str, str] | None = None, order: str = "asc",
                  offset: Optional[int] = None, output_csv: Optional[str] = None) -> dict:
    """table_grep with ATLAS_TABLE_SURVEY on: the count pass, then every
    match or the survey of the match set; with the time arguments a window first, then a
    page in time order (oldest or newest first) or every row to a file."""
    alts = _alternatives(pattern, flags) or [(pattern, rx)]

    def test(row: dict) -> list[str] | None:
        return [k for k, v in row.items() if v and rx.search(v)] or None

    def clip(row: dict, hit_cols: list[str]) -> dict:
        return _clip_row(row, None, rx, hit_cols)

    order = "desc" if str(order or "").lower() == "desc" else "asc"
    page = offset is not None or order == "desc"
    matched_all = None
    try:
        cnt = _count_pass(path, sheet, pattern, rx, flags, alts, clip)
        if window is not None:
            lo, hi = window
            matched_all = len(cnt.rownos)
            cnt = _subset(cnt, [i for i, t in enumerate(cnt.times) if t and lo <= t <= hi])
        if page:
            ranked = _ranked(cnt)
            if order == "desc":
                ranked = ranked[::-1]
            start = max(0, int(offset or 0))
            chosen = [(None, i) for i in ranked[start:start + max_hits]]
            tsets = _term_sets(cnt)
        else:
            chosen, tsets = _choose(cnt, max_hits)
        rows = _fetch_rows(path, sheet, cnt, [i for _t, i in chosen], rx, test, clip)
        if rows is None:                 # a read-back line did not parse: every line parsed instead
            ready = cnt.ready
            cnt = _Count(alts)
            if not _count_grep_parsed(path, ready, rx, flags, pattern, clip, cnt):
                cnt = _Count(alts)
                _count_rows(path, sheet, test, clip, cnt)
            else:
                cnt.scanned = max(0, _line_count(path) - 1)
            chosen, tsets = _choose(cnt, max_hits)
            rows = _fetch_rows(path, sheet, cnt, [i for _t, i in chosen], rx, test, clip) or {}
    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": f"{type(e).__name__}: {e}"}
    rank = {i: r + 1 for r, i in enumerate(_ranked(cnt))}
    tier = {i: t for t, i in chosen}
    hits = []
    written = None
    if output_csv:
        # The file holds the rows whole: clipping is a property of the view.
        every = _fetch_rows(path, sheet, cnt, _ranked(cnt), rx, test, lambda row, _cols: dict(row),
                            whole=True) or {}
        written = _spill_csv([every[i] for i in _ranked(cnt) if i in every], output_csv)
    for i in sorted((i for _t, i in chosen if i in rows), key=lambda i: rank[i], reverse=order == "desc"):
        h = dict(rows[i])
        extra = {"_n": rank[i]}
        if tier[i] is not None:
            extra["_tier"] = tier[i]
        hits.append({**{k: h.pop(k) for k in ("_sheet", "_row", "_matched_columns") if k in h}, **extra, **h})
    shown, _ = _payload_capped(hits)
    payload_capped = len(shown) < len(hits)
    n = len(cnt.rownos)
    before, after = _count_fields(cnt, tsets, with_terms=True)
    out = {"success": True, "path": path, "pattern": pattern,
           "selection": "page" if page else ("survey" if n > max_hits else "all"),
           "matched_rows": n}
    if matched_all is not None:
        out["matched_rows_all"] = matched_all
    out.update({"returned_rows": len(shown),
                "hit_count": len(shown), "max_hits": max_hits,
                "hit_cap_reached": len(shown) < n, "payload_capped": payload_capped})
    if _time_args_on():
        out.update({"offset": offset, "order": "file" if cnt.file_order else order,
                    "time_start": window[0] if window and window[0] else None,
                    "time_end": window[1] if window and window[1] != "9999" else None})
    else:
        out["order"] = "file" if cnt.file_order else "asc"
    out.update({**before, "hits": shown, **after, **_scan_fields(cnt.scanned, cnt.scan_capped, n)})
    if output_csv:
        out["output_csv"] = written
    return out


def count_matches(path: str, pattern: str, ignore_case: bool = True) -> dict:
    """The per-file count of a search, without rows: per term its rows and
    first and last time, the match span and the path the count took. The
    primitive of the on-demand count (table_grep's ``sources``) and of the
    loop's estate count."""
    bad = _refuse_nontabular(path)
    if bad:
        return {"path": path, "error": bad.get("error") or "not a table"}
    if not os.path.isfile(path):
        return {"path": path, "error": "file not found"}
    flags = re.IGNORECASE if ignore_case else 0
    try:
        rx = re.compile(pattern, flags)
    except re.error as e:
        return {"path": path, "error": f"bad regex: {e}"}
    alts = _alternatives(pattern, flags) or [(pattern, rx)]
    try:
        cnt = _count_pass(path, None, pattern, rx, flags, alts, lambda row, _h: {})
    except Exception as e:  # noqa: BLE001
        return {"path": path, "error": f"{type(e).__name__}: {e}"}
    tsets = _term_sets(cnt)
    n = len(cnt.rownos)
    terms = []
    for a, (src, _rx) in enumerate(alts):
        mine = sorted(t for i, t in enumerate(cnt.times) if a in tsets[i] and t)
        rows = sum(1 for s in tsets if a in s)
        terms.append({"term": src, "rows": rows, "first": mine[0] if mine else "",
                      "last": mine[-1] if mine else ""})
    timed = sorted(t for t in cnt.times if t)
    out = {"path": path, "matched_rows": n, "count_basis": cnt.count_basis, "count_path": cnt.count_path}
    if timed:
        out["match_span"] = {"first": timed[0], "last": timed[-1]}
    out["terms"] = terms
    if cnt.scan_capped:
        out["scan_capped"] = True
    return out


def _query_counted(path: str, sheet: Optional[str], preds, columns: Optional[list[str]], limit: int) -> dict:
    """table_query's filter with ATLAS_TABLE_SURVEY on and no offset,
    sort_by or output_csv: every match counted (the row loop, the predicates
    are Python), every one returned when they fit, else the survey."""
    pred_cols = list(dict.fromkeys(c for c, _op, _v in preds))

    def test(row: dict) -> list[str] | None:
        return [c for c in pred_cols if c in row] if _matches(row, preds) else None

    def clip(row: dict, _hit_cols: list[str]) -> dict:
        return _clip_row(row, columns)

    cnt = _Count([])
    _count_rows(path, sheet, test, clip, cnt)
    chosen, tsets = _choose(cnt, limit)
    rows = _fetch_rows(path, sheet, cnt, [i for _t, i in chosen], None, test, clip) or {}
    rank = {i: r + 1 for r, i in enumerate(_ranked(cnt))}
    tier = {i: t for t, i in chosen}
    out_rows = []
    for i in sorted((i for _t, i in chosen if i in rows), key=lambda i: rank[i]):
        r = dict(rows[i])
        r.pop("_matched_columns", None)
        out_rows.append({"_sheet": r.pop("_sheet", "-"), "_row": r.pop("_row", cnt.rownos[i]), "_n": rank[i],
                         **({"_tier": tier[i]} if tier[i] is not None else {}), **r})
    window, _ = _payload_capped(out_rows)
    n = len(cnt.rownos)
    before, after = _count_fields(cnt, tsets, with_terms=False)
    return {"success": True, "path": path, "sheet": sheet,
            "selection": "survey" if n > limit else "all",
            "matched_rows": n, "returned_rows": len(window), "offset": 0,
            "order": "file" if cnt.file_order else "asc", **before,
            "rows": window, **after,
            **_scan_fields(cnt.scanned, cnt.scan_capped, n), **_ragged_fields(cnt.widths),
            "payload_capped": len(window) < len(out_rows), "output_csv": None,
            "valid_zero": n == 0 and not cnt.scan_capped}


def _indicator_terms(ioc: str) -> list[tuple[str, str]]:
    """``(label, regex)`` of the fixed strings an indicator is counted by:
    its value as written; for a path or a registry key the full value with
    either separator and, labelled ``name``, its last component."""
    kind, _, value = str(ioc or "").partition(":")
    if not value:
        return []
    if kind in ("path", "reg"):
        parts = [p for p in re.split(r"[\\/]+", value.rstrip("\\/")) if p]
        full = r"[\\/]+".join(re.escape(p) for p in parts)
        out = [("full", full)]
        if len(parts) > 1:
            out.append(("name", re.escape(parts[-1])))
        return out
    return [("full", re.escape(value))]


def _indicator_strings(ioc: str) -> list[tuple[str, list[str]]]:
    """``(label, fixed strings)`` an indicator is counted by, the literal
    forms of ``_indicator_terms``: a path's full value with each separator
    spelling (one, the other, a doubled backslash as an escaped export
    writes it), and its last component."""
    kind, _, value = str(ioc or "").partition(":")
    if not value:
        return []
    if kind in ("path", "reg"):
        parts = [p for p in re.split(r"[\\/]+", value.rstrip("\\/")) if p]
        out = [("full", list(dict.fromkeys(sep.join(parts) for sep in ("\\", "/", "\\\\"))))]
        if len(parts) > 1:
            out.append(("name", [parts[-1]]))
        return out
    return [("full", [value])]


def estate_native_on() -> bool:
    """The estate count's one native pass per table (ATLAS_ESTATE_COUNT_NATIVE)."""
    from core.envfile import env_flag
    return env_flag("ATLAS_ESTATE_COUNT_NATIVE", True)


def _count_native(path: str, plan: list[tuple[str, str, list[str]]]) -> list[dict] | None:
    """One pass of GNU grep over a delimited text table for every fixed
    string of the plan at once (``-F -i -f``); Python then reads only the
    matching lines: which strings each holds and its time, for each plan
    entry's rows and first and last time. None when grep cannot stand in
    (no grep, an encoding or a layout it cannot read): the caller counts
    with the row loop.

    ponytail: counted by line, as the streamed count path is; a matching
    line that continues a cell holding a line break counts as a row without
    a time."""
    import tempfile
    from core import table_rows as T
    if MAX_SCAN_ROWS or _kind(path) != "csv" or not os.path.isfile(path):
        return None
    encoding = text_encoding(path)
    grep = shutil.which("grep")
    if encoding not in _GREP_ENCODINGS or not grep:
        return None
    try:
        with open_text(path, newline="") as f:
            sample = f.read(65536)
    except OSError:
        return None
    if sample.count("\n") + sample.count("\r") <= 1:
        return None
    dialect = _csv_dialect(sample)
    try:
        head = next(csv.reader([sample.splitlines()[0]], dialect))
    except (csv.Error, StopIteration, IndexError):
        return None
    headers = [(c or "").strip().lstrip("\ufeff") or f"col{i+1}" for i, c in enumerate(head)]
    tidx = [headers.index(c) for c in _roles(headers, [])[0]]
    need = max(tidx) + 1 if tidx else 0
    forms: dict[str, list[int]] = {}
    for i, (_ioc, _label, strings) in enumerate(plan):
        for s in strings:
            forms.setdefault(s.lower(), []).append(i)
    if not forms:
        return None
    ascii_only = all(f.isascii() for f in forms)
    if not ascii_only and encoding not in ("utf-8", "utf-8-sig"):
        return None              # grep folds non-ASCII case only in UTF-8: the row loop counts
    delim = str(getattr(dialect, "delimiter", ","))
    quote = str(getattr(dialect, "quotechar", '"') or '"')
    stats = [{"rows": 0, "first": "", "last": ""} for _ in plan]
    times: dict[tuple, str] = {}
    with tempfile.NamedTemporaryFile("w", encoding=encoding if encoding != "utf-8-sig" else "utf-8",
                                     suffix=".terms", delete=False) as tf:
        tf.write("\n".join(forms) + "\n")
    try:
        env = {**os.environ, "LC_ALL": "C" if ascii_only else "C.UTF-8"}
        proc = subprocess.Popen([grep, "-a", "-F", "-i", "-n", "-f", tf.name, "--", path],
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env)
        try:
            for raw in proc.stdout:
                num, _, body = raw.partition(b":")
                if num == b"1":
                    continue                 # the header line
                text = body.decode(encoding, "replace").rstrip("\r\n")
                low = text.lower()
                hit = {i for f, idx in forms.items() if f in low for i in idx}
                if not hit:
                    continue                 # grep folded a case Python does not
                when = ""
                if need:
                    cut = text.split(delim, need)
                    if len(cut) > need and quote not in text[: len(text) - len(cut[-1])]:
                        cells = cut[:need]
                    else:
                        try:
                            cells = next(csv.reader([text], dialect))[:need]
                        except (csv.Error, StopIteration):
                            cells = []
                    key = tuple(cells[i] for i in tidx if i < len(cells))
                    when = times.get(key)
                    if when is None:
                        iso = T.row_time(cells, tidx) if cells else ""
                        when = times[key] = iso.replace("T", " ") if iso else ""
                for i in hit:
                    s = stats[i]
                    s["rows"] += 1
                    if when:
                        if not s["first"] or when < s["first"]:
                            s["first"] = when
                        if when > s["last"]:
                            s["last"] = when
        finally:
            code = proc.wait()
            proc.stdout.close()
    finally:
        try:
            os.unlink(tf.name)
        except OSError:
            pass
    return stats if code in (0, 1) else None


def count_values(case_dir: str, values: list[str], sources: list[str], kinds: dict[str, str] | None = None) -> dict:
    """``count_indicators`` for bare values, keyed back by the value. The
    count reads ``kind:value`` indicators and counts nothing for a bare
    one, so each value is given its form here: a value whose kind is a file
    (or not given) and that carries a path separator, never a URL, counts as
    a path (its full value and its last component); any other value counts
    as written. ``kinds`` maps a value to its kind (``account``, ``file``,
    ...)."""
    kinds = kinds or {}
    keyed: dict[str, str] = {}
    for v in values:
        kind = str(kinds.get(v) or "")
        is_path = kind in ("", "file", "path") and ("\\" in v or "/" in v) and "://" not in v
        keyed[f"path:{v}" if is_path else f"{kind or 'value'}:{v}"] = v
    res = count_indicators(case_dir, list(keyed), sources)
    return {"counts": {keyed[k]: per for k, per in (res.get("counts") or {}).items()},
            "errors": res.get("errors") or {}}


def count_indicators(case_dir: str, indicators: list[str], sources: list[str]) -> dict:
    """The estate count: per indicator and per table, the rows that contain
    it (case-insensitive, fixed strings), with first and last time; a path
    or registry indicator also by its last component. One count pass per
    table (count_matches); no rows. ``{"counts": {ioc: {source: {"full",
    "name", "first", "last"}}}, "errors": {source: text}}``."""
    import os as _os
    plan: list[tuple[str, str, str]] = []           # (ioc, label, regex)
    for ioc in indicators:
        plan += [(ioc, label, rx) for label, rx in _indicator_terms(ioc)]
    out: dict = {"counts": {ioc: {} for ioc in indicators}, "errors": {}}
    if not plan:
        return out
    pattern = "|".join(rx for _i, _l, rx in plan)
    fixed = [(ioc, label, strings) for ioc in indicators for label, strings in _indicator_strings(ioc)]
    for src in sources:
        path = src if _os.path.isabs(src) else _os.path.join(str(case_dir), src)
        native = _count_native(path, fixed) if estate_native_on() else None
        if native is not None:
            for (ioc, label, _strings), term in zip(fixed, native):
                if not term["rows"]:
                    continue
                slot = out["counts"][ioc].setdefault(src, {"full": 0, "name": 0, "first": "", "last": ""})
                slot[label] = int(term["rows"])
                if term["first"] and (not slot["first"] or term["first"] < slot["first"]):
                    slot["first"] = term["first"]
                if term["last"] and term["last"] > slot["last"]:
                    slot["last"] = term["last"]
            continue
        res = count_matches(path, pattern, ignore_case=True)
        if res.get("error"):
            out["errors"][src] = res["error"]
            continue
        for (ioc, label, _rx), term in zip(plan, res.get("terms") or []):
            if not term.get("rows"):
                continue
            slot = out["counts"][ioc].setdefault(src, {"full": 0, "name": 0, "first": "", "last": ""})
            slot[label] = int(term["rows"])
            if term.get("first") and (not slot["first"] or term["first"] < slot["first"]):
                slot["first"] = term["first"]
            if term.get("last") and term["last"] > slot["last"]:
                slot["last"] = term["last"]
    return out
