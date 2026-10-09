"""Refuse wrong input *kinds* before forensic parsers run.

Agents often pass pre-parsed KAPE/EZTools outputs (``*.regripper.txt``,
``all-evtx.csv``) into hive/EVTX parsers. Obscure subprocess errors then
pollute reports as “parser failure / missing evidence”. Refuse early with an
actionable redirect instead.

Middleware also enforces this as ``gate: wrong_input_kind`` (TOOL INFO) and
quarantines identical tool+path retries so CSV→EvtxECmd storms cannot
inflate investigate-latch debt.
"""
from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from typing import Any, Optional

FAILURE_CLASS = "wrong_input_kind"
GATE = "wrong_input_kind"

_EVTX_TOOL_RE = re.compile(
    r"(?i)(?:evtxecmd|evtx_?ecmd|chainsaw_hunt|hayabusa|sigma_hunt|"
    r"ez_ez_evtx|misc_chainsaw_hunt|misc_hayabusa|misc_evtx_)"
)
_HIVE_TOOL_RE = re.compile(
    r"(?i)(?:recmd|regripper|amcacheparser|appcompatcache|"
    r"ez_ez_recmd|ez_ez_amcache|ez_ez_appcompat)"
)
# The mirror image of the two above. Those catch a *parser* pointed at
# already-parsed text; this catches a *raw byte scanner* pointed at
# structured text. strings/hexdump exist to recover strings from binary
# containers — running them over a CSV the case just produced is a category
# error that always "succeeds": exit 0, plausible output, no error to
# investigate. A run can burn most of its grep calls doing exactly that
# against its own exports, half of them truncated, while the structured
# query tools that answer those questions properly go unused.
_RAW_SCAN_TOOL_RE = re.compile(
    r"(?i)(?:strings_(?!read_text)|_strings(?!_read_text)|hexdump|xxd|"
    r"bulk_extractor|foremost|scalpel)"
)
# Structured documents a table tool cannot query (no rows and columns): the
# text reader decodes them.
_DOCUMENT_EXT = frozenset({".xml", ".json", ".yaml", ".yml"})

_RAW_SCAN_PARAMS = (
    "path", "file_path", "input_path", "source_path", "target", "image",
)

# Extensions whose content is structured by construction — a table tool can
# answer questions about them that a byte scanner cannot.
_STRUCTURED_EXT = frozenset({
    ".csv", ".tsv", ".psv", ".json", ".jsonl", ".ndjson", ".xml", ".yaml",
    ".yml", ".parquet", ".sqlite", ".db",
})

_EVTX_PARAMS = (
    "evtx_path", "path", "input_path", "source_path", "file_path",
    "directory", "dir_path",
)
_HIVE_PARAMS = (
    "hive_path", "amcache_path", "system_hive", "path", "input_path",
    "source_path", "file_path",
)


_BOMS = (
    (b"\xef\xbb\xbf", "utf-8-sig"),
    (b"\xff\xfe", "utf-16"),
    (b"\xfe\xff", "utf-16"),
)


def text_encoding(path: str | os.PathLike) -> str | None:
    """The encoding a text export was written in, or None when it is binary.

    Windows writes a lot of its text as UTF-16: ``reg export``, PowerShell's
    ``Out-File`` and ``Export-Csv -Encoding Unicode``, ``wevtutil`` output.
    Every reader here decoded as UTF-8 and every binary probe treated a NUL
    byte as proof of a binary file, so such an export was refused by the
    table tools ("contains NUL bytes") and unreadable by anything else. Exports without a BOM in a Windows code page
    (an umlaut in a user name) lost those characters to U+FFFD, and a
    grep for the real name silently missed.

    BOM first; then bare UTF-16 recognised by NUL in every other byte;
    then strict UTF-8; then cp1252, the Windows default for the rest.
    """
    try:
        with open(path, "rb") as fh:
            head = fh.read(4096)
    except OSError:
        return None
    if not head:
        return "utf-8"
    for bom, enc in _BOMS:
        if head.startswith(bom):
            return enc
    if b"\x00" in head:
        half = max(1, len(head) // 2)
        even, odd = head[0::2].count(0), head[1::2].count(0)
        if len(head) >= 64:              # a few bytes cannot show the pattern
            if odd >= 0.6 * half and even <= 0.05 * half:
                return "utf-16-le"
            if even >= 0.6 * half and odd <= 0.05 * half:
                return "utf-16-be"
        return None
    try:
        head.decode("utf-8")
        return "utf-8"
    except UnicodeDecodeError as e:
        # A multi-byte sequence cut by the sample boundary is still UTF-8.
        return "utf-8" if e.start >= len(head) - 3 else "cp1252"


def open_text(path: str | os.PathLike, **kwargs):
    """``open()`` for an evidence text file in the encoding it was written
    in. Undecodable bytes are replaced rather than raised: a citation
    reader must never fail on one odd byte in a 2 GB export."""
    kwargs.setdefault("encoding", text_encoding(path) or "utf-8")
    kwargs.setdefault("errors", "replace")
    return open(path, **kwargs)


def read_text_head(path: str | os.PathLike, nbytes: int) -> str | None:
    """The first ``nbytes`` of a text file decoded properly; None if binary."""
    enc = text_encoding(path)
    if enc is None:
        return None
    try:
        with open(path, "rb") as fh:
            head = fh.read(nbytes)
    except OSError:
        return None
    return head.decode(enc, errors="replace")


def _looks_like_text_file(path: str, *, sample: int = 256) -> bool:
    enc = text_encoding(path)
    if enc is None:
        return False
    if enc.startswith("utf-16"):
        return True
    try:
        with open(path, "rb") as f:
            chunk = f.read(sample)
    except OSError:
        return False
    if not chunk:
        return True
    printable = sum(1 for b in chunk if 9 <= b <= 13 or 32 <= b <= 126 or b >= 0x80)
    return printable / len(chunk) >= 0.85


def _hive_magic_ok(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(4) == b"regf"
    except OSError:
        return False


def _evtx_magic_ok(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(7) == b"ElfFile"
    except OSError:
        return False


def _with_gate(payload: dict[str, Any]) -> dict[str, Any]:
    out = dict(payload)
    out.setdefault("gate", GATE)
    out.setdefault("failure_class", FAILURE_CLASS)
    out.setdefault(
        "use_instead",
        "table.table_query / table.table_grep (tabular) or the correct raw "
        "artifact path",
    )
    out.setdefault(
        "summary",
        "Wrong input kind — do not retry this tool on the same path. "
        "Use use_instead / table.* on tabular exports.",
    )
    return out


def refuse_preparsed_hive(path: str) -> Optional[dict[str, Any]]:
    """Return an error dict if ``path`` is not a raw registry hive."""
    if not path:
        return None
    if not os.path.exists(path):
        # Fail closed: invented / missing hive paths must not fall through
        # to the parser (Amcache at System32/config/... phantom).
        return _with_gate({
            "success": False,
            "error": (
                f"{path!r} does not exist. Discover the real hive path "
                f"(typically AppCompat/Programs/Amcache.hve or "
                f"Windows/System32/config/{{SYSTEM,SOFTWARE,…}}) before "
                f"calling a hive parser — do not invent locations."
            ),
            "failure_class": "missing_input",
            "use_instead": "misc.list_directory / discovery on evidence/",
        })
    if os.path.isdir(path):
        return _with_gate({
            "success": False,
            "error": (
                f"{path!r} is a directory, not a registry hive. Pass a hive "
                f"file (SYSTEM/SOFTWARE/SAM/SECURITY/NTUSER.DAT/Amcache.hve) "
                f"or use ez.recmd_dir on a hives directory."
            ),
        })
    name = Path(path).name.casefold()
    norm = path.replace("\\", "/").casefold()
    if name.endswith(".regripper.txt") or (
        "/regripper/" in norm and name.endswith(".txt")
    ):
        return _with_gate({
            "success": False,
            "error": (
                f"{path!r} looks like RegRipper *output*, not a hive. "
                f"Grep/read it with table.table_grep / table.table_query. "
                f"For a fresh parse, pass the raw hive from the host's raw "
                f"extract: …/Windows/System32/config/ (or Amcache.hve)."
            ),
            "use_instead": "table.table_grep / table.table_query",
        })
    if name.endswith((".csv", ".tsv", ".json", ".jsonl", ".xlsx")):
        return _with_gate({
            "success": False,
            "error": (
                f"{path!r} is tabular/text output, not a registry hive. "
                f"Use table.* tools on this file instead of hive parsers."
            ),
            "use_instead": "table.table_query / table.table_grep",
        })
    if not _hive_magic_ok(path):
        if _looks_like_text_file(path) or name.endswith(".txt"):
            return _with_gate({
                "success": False,
                "error": (
                    f"{path!r} is not a registry hive (missing 'regf' signature). "
                    f"If this is already-parsed text, use table.table_grep. "
                    f"Otherwise pass the raw hive binary."
                ),
            })
        return _with_gate({
            "success": False,
            "error": (
                f"{path!r} is not a registry hive (missing 'regf' signature). "
                f"Pass SYSTEM/SOFTWARE/SAM/SECURITY/NTUSER.DAT/Amcache.hve."
            ),
        })
    return None


def refuse_preparsed_evtx(path: str) -> Optional[dict[str, Any]]:
    """Return an error dict if ``path`` is not raw EVTX (file or dir of EVTX)."""
    if not path:
        return None
    if not os.path.exists(path):
        return _with_gate({
            "success": False,
            "error": (
                f"{path!r} does not exist. Discover the real .evtx path "
                f"(usually winevt/Logs/) before calling EvtxECmd — do not "
                f"invent locations under System32 or evidence roots."
            ),
            "failure_class": "missing_input",
            "use_instead": "misc.list_directory / discovery on evidence/",
        })
    if os.path.isdir(path):
        try:
            entries = list(os.scandir(path))
        except OSError:
            return None
        if not entries:
            return None
        if any(e.is_file() and e.name.casefold().endswith(".evtx")
               for e in entries):
            return None
        return _with_gate({
            "success": False,
            "error": (
                f"{path!r} has no .evtx files at the top level. "
                f"If you have EvtxECmd CSV output (e.g. all-evtx.csv), use "
                f"table.table_grep / table.table_query instead of re-parsing."
            ),
            "use_instead": "table.table_grep / table.table_query",
        })
    name = Path(path).name.casefold()
    if name.endswith((".csv", ".tsv", ".json", ".jsonl", ".xlsx", ".txt")):
        return _with_gate({
            "success": False,
            "error": (
                f"{path!r} looks like parsed event-log *output*, not an .evtx. "
                f"Use table.table_grep / table.table_query on this file. "
                f"Raw logs sit in the host's raw extract under "
                f"…/Windows/System32/winevt/Logs/."
            ),
            "use_instead": "table.table_grep / table.table_query",
            "discovery_next": {
                "tool": "table.table_grep",
                "arguments": {"path": path, "pattern": ".", "max_hits": 20},
                "reason": (
                    "This path is already tabular. Query/grep it — never "
                    "pass CSV/TSV/JSON to EvtxECmd."
                ),
            },
        })
    if not _evtx_magic_ok(path):
        # Whatever the name says, a file without the signature is not an
        # event log, and an in-process parser handed one walks it as if it
        # were: a raw disk image of tens of gigabytes took a whole run down
        # that way. Text gets the table hint; anything else is told what
        # would produce an event log from it.
        if _looks_like_text_file(path):
            return _with_gate({
                "success": False,
                "error": (
                    f"{path!r} is not an EVTX log (no ElfFile signature). "
                    f"Use table.* if this is CSV/text output."
                ),
                "use_instead": "table.table_query / table.table_grep",
            })
        if name.endswith(".evtx"):
            return _with_gate({
                "success": False,
                "error": (
                    f"{path!r} has a .evtx name but no ElfFile signature "
                    f"(truncated/corrupt or wrong file)."
                ),
            })
        return _with_gate({
            "success": False,
            "error": (
                f"{path!r} is not an EVTX log (no ElfFile signature at "
                f"offset 0). A disk image or another container holds event "
                f"logs inside a filesystem: extract the .evtx first "
                f"(tsk.fls to find winevt/Logs, tsk.icat to copy it out), "
                f"then parse the extracted file."
            ),
            "failure_class": "wrong_input_kind",
            "use_instead": "tsk.fls / tsk.icat, then this tool on the .evtx",
        })
    return None


def refuse_raw_scan_of_structured_text(path: str) -> Optional[dict[str, Any]]:
    """Refuse a byte scanner aimed at text a table tool should query.

    Deliberately narrow. ``strings`` over a disk image, memory dump, EVTX,
    hive or any other binary container is exactly right and must stay
    untouched — the check only fires when the target is *text*, because
    only then is a structured query strictly better. On text, a byte
    scanner is at best grep with extra steps: it cannot filter by column,
    cannot aggregate, and truncates long output, so a subset of the file gets mistaken for the
    answer.
    """
    if not path or not os.path.isfile(path):
        return None
    if not _looks_like_text_file(path):
        return None  # binary container — raw scanning is the right tool
    ext = os.path.splitext(path)[1].lower()
    structured = ext in _STRUCTURED_EXT
    if not structured:
        # Delimited text without a telling extension (exported logs often
        # land as .log/.txt): treat as structured only when the first lines
        # agree on a separator, which is what makes column queries possible.
        structured = looks_delimited(path)
    if not structured:
        return None
    if ext in _DOCUMENT_EXT and not looks_delimited(path):
        return {
            "error": (
                f"{os.path.basename(path)} is a text document, not a binary "
                "container. A byte scanner returns its bytes as fragments and "
                "cannot decode UTF-16 — read it as text instead."
            ),
            "use_instead": "strings.read_text",
            "discovery_next": {
                "tool": "strings.read_text",
                "arguments": {"file_path": path, "max_lines": 200},
                "reason": "Text document — read it decoded; do not scan raw bytes.",
            },
        }
    return {
        "error": (
            f"{os.path.basename(path)} is structured text, not a binary "
            "container. A byte scanner cannot filter by field, cannot "
            "aggregate, and truncates its output — query it instead so the "
            "whole file answers the question rather than the first N hits."
        ),
        "use_instead": "table.table_query / table.table_grep",
        "discovery_next": {
            "tool": "table.table_grep",
            "arguments": {"path": path, "pattern": ".", "max_hits": 20},
            "reason": (
                "Structured text — query columns and aggregate; do not "
                "scan raw bytes."
            ),
        },
    }


_SNIFF_BYTES = 262_144      # two lines of a 60 000-column export fit
_SNIFF_SEPS = (";", "\t", ",", "|")


# Field shapes a record can open with. Learned from the first record of each
# file, never assumed: knowledge about what dates, times and addresses look
# like, not about any exporter.
_SHAPE_RES = (
    ("int", re.compile(r"^-?\d{1,12}$")),
    ("date", re.compile(r"^(?:\d{1,2}[A-Za-z]{3}\d{2,4}|\d{4}-\d{2}-\d{2}"
                        r"|\d{1,2}[./]\d{1,2}[./]\d{2,4})$")),
    ("time", re.compile(r"^\d{1,2}:\d{2}(?::\d{2})?(?:\.\d+)?$")),
    ("ip", re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")),
)


_GLUED_COUNTER_RE = re.compile(r"^(.*?[^\d\s])(\d{1,12})$")


def _shape(field: str) -> str:
    for name, rx in _SHAPE_RES:
        if rx.match(field):
            return name
    return "text"


def unterminated_records(text: str, sep: str, *, prefix: int = 3,
                         min_records: int = 3):
    """``(header, records)`` for a delimited export whose records were
    written without any line terminator, or None when the text is not one.

    Some firewall exports are a single line: a wide header followed by
    thousands of records with nothing between them. No reader turns that
    into rows, so the traffic is only ever grepped as one line and cut at
    the output cap. Records are recovered from the *shape* of
    the first record's leading fields — the record that starts right after
    the header names — an integer, a date, a time, an address: whatever
    this file's records open with. The header is everything before it.

    Known limit: when a record's last field is itself a number and the next
    record's counter is glued to it ("…;18446744073709551615;1" + "2;4Feb…"),
    the two digit strings cannot be told apart; the leading counter column
    then carries both. Every other column is aligned.
    """
    # The one line break such a file may still have sits between the header
    # and the first record; it separates fields like everything else here.
    for eol in ("\r\n", "\n", "\r"):
        text = text.replace(eol, sep)
    fields = text.strip(sep).split(sep)
    if len(fields) < 3 * prefix + min_records:
        return None
    # The header is names; the first record is the first place where the
    # next `prefix` fields carry at least two typed shapes.
    start = None
    for i in range(1, min(len(fields) - prefix, 4096)):
        shapes = [_shape(f) for f in fields[i:i + prefix]]
        # The record begins *at* a typed field; a window that merely ends
        # in one still sits on the last header names.
        if shapes[0] != "text" and sum(sh != "text" for sh in shapes) >= 2:
            start = i
            break
    if start is None or start < 2:
        return None
    header = fields[:start]
    signature = tuple(_shape(f) for f in fields[start:start + prefix])
    if signature[0] == "int":
        # A record whose last field carries no trailing separator swallows
        # the next record's counter ("inbound" + "63013"); a text field
        # ending in digits right before this file's date/time opener is
        # two fields.
        tail = signature[1:]
        repaired: list[str] = []
        i = 0
        while i < len(fields):
            f = fields[i]
            m = _GLUED_COUNTER_RE.match(f) if i + len(tail) < len(fields) else None
            if (m and i >= start
                    and tuple(_shape(x) for x in fields[i + 1:i + 1 + len(tail)]) == tail):
                repaired.append(m.group(1))
                repaired.append(m.group(2))
            else:
                repaired.append(f)
            i += 1
        fields = repaired
    starts = [start]
    j = start + 3
    n = len(fields)
    while j < n - prefix + 1:
        if (_shape(fields[j]) == signature[0]
                and tuple(_shape(f) for f in fields[j:j + prefix]) == signature
                and j - starts[-1] >= 3):
            starts.append(j)
            j += 3
        else:
            j += 1
    if len(starts) < min_records:
        return None
    records = [fields[a:b] for a, b in zip(starts, starts[1:] + [n])]
    lengths = sorted(len(r) for r in records)
    median = lengths[len(lengths) // 2]
    if median < 3 or median > len(header):
        return None
    return header, records


def unterminated_separator(text: str) -> str | None:
    """The separator of a one-line delimited text, or None."""
    best = max(_SNIFF_SEPS, key=lambda sp: text.count(sp))
    return best if text.count(best) >= 20 else None


def looks_delimited(path: str | os.PathLike, *, lines: int = 5) -> bool:
    """True when the first lines of a text file agree on a field separator.

    The one definition of "delimited text" every gate shares. The table
    tools, the byte-scanner refusal and the evidence profile each judged
    this differently, so a semicolon-delimited firewall ``.log`` was
    refused by ``strings`` ("query it instead") *and* by ``table_schema``
    ("not a tabular export"): no typed tool would take the file and the
    agent fell back to ``cat``, which truncates it at the output cap.
    Whatever this says, the table tools accept and the
    byte scanners refuse — there is no file both turn away.

    A line may hold one separator more or fewer than the others (a quoted
    field with an embedded comma); a possibly cut-off last line of the
    sample is ignored.
    """
    text = read_text_head(path, _SNIFF_BYTES)
    if not text:
        return False                      # binary, missing or empty
    rows = [ln for ln in text.splitlines() if ln.strip()]
    if len(rows) > 2:
        rows.pop()                        # the last sampled line may be cut
    rows = rows[:lines]
    if len(rows) < 3:
        # One line — or a header line and one endless line of records: a
        # delimited export whose records lost their line terminators is
        # still a table (see unterminated_records).
        joined = "\n".join(rows)
        sep = unterminated_separator(joined) if rows else None
        endless = len(rows) == 1 or (
            rows[-1].count(sep) >= 3 * max(1, rows[0].count(sep)) if sep else False)
        if sep and endless and unterminated_records(joined, sep) is not None:
            return True
        if len(rows) < 2:
            return False
    for sep in _SNIFF_SEPS:
        counts = [r.count(sep) for r in rows]
        if counts[0] >= 2 and max(counts) - min(counts) <= 1:
            return True
    return False


def _norm(path: str) -> str:
    return os.path.normpath(os.path.expanduser((path or "").strip()))


def _knowledge_path(case_dir: str | os.PathLike) -> Path:
    return Path(case_dir).resolve() / ".atlas" / "wrong_input_kind.json"


def _load_quarantine(case_dir: str | os.PathLike | None) -> dict[str, Any]:
    if not case_dir:
        return {"entries": {}}
    path = _knowledge_path(case_dir)
    if not path.is_file():
        return {"entries": {}}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"entries": {}}
    if not isinstance(data, dict):
        return {"entries": {}}
    data.setdefault("entries", {})
    return data


def _save_quarantine(case_dir: str | os.PathLike, data: dict[str, Any]) -> None:
    path = _knowledge_path(case_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(
        json.dumps(data, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    os.replace(tmp, path)


def quarantine_key(tool_name: str, path: str) -> str:
    return f"{(tool_name or '').strip()}::{_norm(path)}"


def remember_wrong_kind(
    case_dir: str | os.PathLike | None,
    tool_name: str,
    path: str,
    *,
    error: str = "",
) -> int:
    if not case_dir or not path:
        return 0
    try:
        data = _load_quarantine(case_dir)
        key = quarantine_key(tool_name, path)
        prev = (data.get("entries") or {}).get(key) or {}
        count = int(prev.get("count") or 0) + 1
        data.setdefault("entries", {})[key] = {
            "count": count,
            "last_at": time.time(),
            "error": (error or prev.get("error") or "")[:400],
        }
        _save_quarantine(case_dir, data)
        return count
    except OSError:
        return 1


def wrong_kind_count(
    case_dir: str | os.PathLike | None, tool_name: str, path: str,
) -> int:
    if not case_dir:
        return 0
    data = _load_quarantine(case_dir)
    hit = (data.get("entries") or {}).get(quarantine_key(tool_name, path)) or {}
    return int(hit.get("count") or 0)


def _check_path_for_tool(tool_name: str, path: str) -> Optional[dict[str, Any]]:
    name = tool_name or ""
    if _EVTX_TOOL_RE.search(name):
        return refuse_preparsed_evtx(path)
    if _HIVE_TOOL_RE.search(name):
        return refuse_preparsed_hive(path)
    if _RAW_SCAN_TOOL_RE.search(name):
        return refuse_raw_scan_of_structured_text(path)
    return None


def build_wrong_kind_refusal(
    tool_name: str,
    *,
    param: str,
    path: str,
    detail: dict[str, Any],
    repeat: bool = False,
) -> dict[str, Any]:
    return _with_gate({
        "success": False,
        "error": (
            f"{tool_name} refused: wrong input kind for {param}={path!r}"
            + (" (repeat — do not retry the same tool on this path)."
               if repeat else ".")
            + " "
            + str(detail.get("error") or "")
        ),
        "param": param,
        "path": path,
        "use_instead": detail.get("use_instead")
        or "table.table_query / table.table_grep",
        "discovery_next": detail.get("discovery_next") or {
            "tool": "table.table_grep",
            "arguments": {
                "path": path,
                "pattern": ".",
                "max_hits": 20,
            },
            "reason": (
                "Tabular/preparsed input — query it; do not pass to "
                "EVTX/hive parsers."
            ),
        },
        "principle": (
            "Tabular class / preparsed exports are never inputs to "
            "EvtxECmd, RECmd, or AmcacheParser."
        ),
    })


def check_tool_input_kind(
    tool_name: str,
    args: dict,
    *,
    case_dir: str | os.PathLike | None = None,
) -> None:
    """Raise ``ValueError`` with JSON refusal when input kind is wrong.

    Caller turns that into ToolError + PROTOCOL_MARKER (TOOL INFO).
    """
    name = tool_name or ""
    if _EVTX_TOOL_RE.search(name):
        params = _EVTX_PARAMS
    elif _HIVE_TOOL_RE.search(name):
        params = _HIVE_PARAMS
    elif _RAW_SCAN_TOOL_RE.search(name):
        params = _RAW_SCAN_PARAMS
    else:
        return

    for key in params:
        val = args.get(key)
        if not isinstance(val, str) or not val.strip():
            continue
        path = _norm(val)
        if not os.path.exists(path):
            continue
        detail = _check_path_for_tool(name, path)
        if not detail:
            continue
        repeat = wrong_kind_count(case_dir, name, path) >= 1
        if case_dir:
            remember_wrong_kind(
                case_dir, name, path, error=str(detail.get("error") or ""))
        raise ValueError(
            json.dumps(
                build_wrong_kind_refusal(
                    name, param=key, path=path, detail=detail, repeat=repeat),
                ensure_ascii=False,
            )
        )


# ── ESE databases and legacy .evt logs ────────────────────────────────
# Both are told by their header: ESE files carry 0xef 0xcd 0xab 0x89 at
# offset 4, pre-Vista event logs the ASCII "LfLe" there, .evtx files
# "ElfFile" at offset 0. A parsed CSV or a hive handed to either exporter
# fails obscurely; the header check refuses it and names the right tool.
_ESE_MAGIC = b"\xef\xcd\xab\x89"
_EVT_MAGIC = b"LfLe"
_EVTX_MAGIC = b"ElfFile"


def _head8(path: str) -> bytes:
    try:
        with open(path, "rb") as f:
            return f.read(8)
    except OSError:
        return b""


def refuse_non_ese(path: str) -> Optional[dict[str, Any]]:
    """Error dict unless ``path`` is an ESE database (SRUDB.dat,
    WebCacheV01.dat, Windows.edb, ...); a directory is left to the caller."""
    if not path or os.path.isdir(path):
        return None
    if not os.path.exists(path):
        return _with_gate({
            "success": False,
            "error": (f"{path!r} does not exist. Discover the real path (SRUM lives at "
                      "Windows/System32/sru/SRUDB.dat, WebCache under the user's "
                      "AppData/Local/Microsoft/Windows/WebCache) before calling an ESE parser."),
            "failure_class": "missing_input",
        })
    if _head8(path)[4:8] != _ESE_MAGIC:
        return _with_gate({
            "success": False,
            "error": (f"{path!r} is not an ESE database (no ESE header at offset 4). A parsed "
                      "CSV, a hive or a log is not the database; pass the .dat/.edb file itself."),
        })
    return None


def refuse_non_evt(path: str) -> Optional[dict[str, Any]]:
    """Error dict unless ``path`` is a legacy .evt event log; an .evtx is
    sent to its own parsers."""
    if not path:
        return None
    if not os.path.exists(path):
        return _with_gate({
            "success": False,
            "error": (f"{path!r} does not exist. Legacy logs live at Windows/System32/config/"
                      "*.Evt (AppEvent, SecEvent, SysEvent); discover the real path first."),
            "failure_class": "missing_input",
        })
    if os.path.isdir(path):
        return _with_gate({"success": False,
                           "error": f"{path!r} is a directory; pass one .evt file"})
    head = _head8(path)
    if head[:7] == _EVTX_MAGIC:
        return _with_gate({
            "success": False,
            "error": (f"{path!r} is an .evtx log (Vista and later); use ez.evtxecmd, "
                      "misc.chainsaw_hunt or hayabusa.triage"),
        })
    if head[4:8] != _EVT_MAGIC:
        return _with_gate({
            "success": False,
            "error": f"{path!r} is not a legacy .evt event log (no LfLe header at offset 4).",
        })
    return None


# ── NTFS directory index ($I30) ───────────────────────────────────────
# A directory's index allocation stream is a run of 4 KiB records that each
# start with "INDX" (a record never used is all zeros); an MFT record starts
# with "FILE". Public NTFS on-disk format knowledge. INDXParse reads only the
# former and fails on anything else.
_EXTRACT_I30 = ("locate the directory with tsk.resolve_path or tsk.fls, extract its $I30 "
                "index allocation with tsk.icat on the image with inode '<dir-inode>-160' "
                "(and the volume's offset_sectors) into analysis/, then call this tool on "
                "that file")


def refuse_non_indx(path: str) -> Optional[dict[str, Any]]:
    """Error dict unless ``path`` holds INDX records, a directory's $I30
    index allocation stream, the only input INDXParse reads."""
    def refuse(error: str, use_instead: str, **extra) -> dict[str, Any]:
        return _with_gate({"success": False, "error": error + _EXTRACT_I30 + ".",
                           "use_instead": use_instead, "summary": (
                               "Wrong input kind - do not retry this tool on the same path; "
                               "use use_instead."), **extra})

    extract = "tsk.icat <image> '<dir-inode>-160', then this tool on the extracted file"
    if not path or not os.path.exists(path):
        return refuse(f"{path!r} does not exist; ", extract, failure_class="missing_input")
    if os.path.isdir(path):
        return refuse(f"{path!r} is a directory, not its index; ", extract)
    try:
        with open(path, "rb") as f:
            head = f.read(4096)
    except OSError as exc:
        return refuse(f"{path!r} cannot be read ({exc}); ", extract)
    if head[:4] == b"INDX" or (head and not any(head)):
        return None
    if head[:4] == b"FILE":
        return refuse(f"{path!r} holds MFT records, not a directory index. Deleted MFT "
                      "records are ez.mftecmd's job; for what a directory's index keeps "
                      "in its slack, ", "ez.mftecmd, or " + extract)
    from core.artifact_kind import head_signature
    if head_signature(path) == "disk":
        return refuse(f"{path!r} is a disk or volume image, not a directory index; ", extract)
    return refuse(f"{path!r} does not start with an INDX record; ", extract)
