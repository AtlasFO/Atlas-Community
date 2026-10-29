"""When a finding's citation supports it - one answer for every reader.

The record-time advisory (tools.misc), the report gate (tools.reasoning)
and the duplicate guard that decides whether a re-record is a repair all
ask the same question of a finding and the calls it cites, so they ask it
here. Trace entries are immutable: the only way a recorded finding's
citations can change is a re-record, so every reader of a citation must
agree on what "supports" means or a finding is accepted by one and then
blocked by another with no way back.

A positive claim is supported when the cited evidence shows an identifier
the claim rests on (core.evidence_resolver anchors: a date, an address, an
account, a file, an event id). Only what a forensic tool produced counts as
the cited evidence: a call carrying the analyst's own words - the finding's
own record call, a reasoning step, a claim snapshot - restates the claim and
would let it support itself (core.forensic_citation.own_words_entry), and an
outside lookup echoes the value it was asked about, so it never shows that
the value was present (core.forensic_citation.citation_class).

An absence claim rests on the search that would have found what it says is
missing, and its identifiers are exactly what that search did not print.
Demanding them in the output refuses every well-founded negative by
construction. So an absence claim is supported when a cited evidence call
is that search: one the analyst saw whole (universal_from_truncated's
notion of a complete view) and over what the claim is about - the sources
its category requires when it falls in a gated category
(tools._gates._manifests), otherwise a call that shares the claim's scope:
an identifier it names (a date, an address, an event id, a host) or an
artifact it or its supporting evidence names. A claim that names nothing
checkable takes any cited complete evidence call. An absence claim whose
cited calls are all cut short, or carry no evidence output at all, is
unsupported: "we looked" has to point at a look that could have found it.
A claim of either kind whose cited searches left no recorded output cannot
be judged and is not flagged.
"""
from __future__ import annotations

import json
import os
import re
import unicodedata
from datetime import datetime, timedelta
from email.utils import parsedate_tz
from typing import Any, Optional

from core.indicators import SPILL_READ_CHARS  # noqa: F401  (the one reader's reach; kept for importers)

from ._manifests import absence_grounding, searches_of


def _rows_on() -> bool:
    from core.envfile import env_flag
    return env_flag("ATLAS_CITATION_ROWS")


def _wiring_on() -> bool:
    """Lineage by wiring needs the row test: forced off when ROWS is off."""
    from core.envfile import env_flag
    return _rows_on() and env_flag("ATLAS_LINEAGE_WIRING")


def _disclosure_on() -> bool:
    """The report-time check as disclosure, effective only with the wiring:
    the lowering never goes without its replacement."""
    from core.envfile import env_flag
    return _wiring_on() and env_flag("ATLAS_CITATION_DISCLOSURE")


def call_output_text(entry: dict) -> str:
    """What a recorded tool call printed, read with the program's one
    echo-free reader (core.indicators.printed_text): never the command line,
    which is the analyst's own text, and never the request a search tool
    echoes back."""
    from core.indicators import printed_text
    return printed_text(entry)


def has_output(entry: dict) -> bool:
    return bool(entry.get("stdout_excerpt") or entry.get("stdout_file"))


def evidence_calls(entries) -> list[dict]:
    """The tool calls among ``entries`` whose output is evidence: neither
    the run's own words nor an outside lookup, whose output echoes the
    value it was asked about (core.forensic_citation.citation_class). A
    lookup grounds what a provider says, which the external-knowledge gate
    judges; that a value was present is shown only by evidence."""
    from core.forensic_citation import citation_class
    return [e for e in entries
            if isinstance(e, dict) and e.get("type") == "tool_call"
            and citation_class(e) == "evidence"]


def cited_ids(finding: dict) -> list[int]:
    """Every call a finding rests on: its lineage, its linked call and, with
    the wiring on, the calls Atlas located beside them."""
    out: list[int] = []
    located = list(finding.get("located_call_ids") or []) if _wiring_on() else []
    for c in list(finding.get("input_call_ids") or []) + [finding.get("linked_call_id")] + located:
        try:
            ci = int(c)
        except (TypeError, ValueError):
            continue
        if ci and ci not in out:
            out.append(ci)
    return out


def is_absence_claim(statement: str) -> bool:
    """A statement about all rows or about something being absent - the
    one grammar every gate on negatives reads (universal_from_truncated)."""
    from .universal_from_truncated import is_universal_or_negative
    return is_universal_or_negative(statement or "")


def complete_view(entry: dict) -> bool:
    """The analyst saw everything this call returned, and it ran."""
    from .universal_from_truncated import incomplete_reason
    return entry.get("success") is not False and not incomplete_reason(entry)


def absence_searches(statement: str, evidence: list[dict], *, tool_calls: list[dict],
                     supporting_evidence: str = "") -> list[dict]:
    """The calls among the cited ``evidence`` that ground ``statement`` as
    an absence claim: complete views that searched the sources its category
    requires, or - outside the gated categories - complete views that share
    the claim's scope (an identifier or an artifact the claim or its
    supporting evidence names; any complete view when it names none). Empty
    when the statement is not an absence claim."""
    if not is_absence_claim(statement):
        return []
    complete = [e for e in evidence if has_output(e) and complete_view(e)]
    grounding = absence_grounding(statement, supporting_evidence, tool_calls)
    if grounding:
        return searches_of(grounding, complete, statement or "", _active_case_dir() or None)
    from core.entities import artifact_tokens
    from core.evidence_resolver import _claim_anchors, _shares_anchor
    from .lineage_relevance import entry_text
    described = artifact_tokens(f"{statement or ''} {supporting_evidence or ''}")
    anchors = _claim_anchors({"statement": statement or "",
                              "reasoning": supporting_evidence or ""})
    if not described and not anchors:
        return complete
    return [e for e in complete
            if (described & artifact_tokens(entry_text(e)))
            or _shares_anchor(call_output_text(e), anchors)]


# ── the row test: when a call shows a claim ──────────────────────────────
#
# One definition for every reader: a call shows a claim when it is evidence,
# it ran, and one of its printed rows holds a strong entity of the claim
# that is not merely what the call was asked to read and, when the claim
# states minute times, one of those times in the same row.

# A node id of the claim graph and an ATT&CK id are the run's own labels,
# never something a tool output shows.
_OWN_LABEL_RE = re.compile(r"(?i)^(?:[cnoh]\d{4,6}|f-\d{2,5}|t\d{4}(?:\.\d{3})?)$")
# An identifier-shaped word for the fallback: it starts with a letter and
# carries a hyphen, an underscore, a dot, a dollar sign or a digit
# ("Updater-Sync", "svc_backup", "setup.log", "ADMIN$", "x64dbg"); a plain
# capitalised word is prose, and a word plus a one- or two-digit suffix
# ("Win-10") is a version. Lexical shape, not case knowledge.
_NAME_WORD_RE = re.compile(r"^(?![A-Za-z]+-\d{1,2}$)[A-Za-z][\w.$\\-]*[-_.$\d]")
_CLOCK_RANGE_RE = re.compile(r"(\d{1,2}:\d{2}(?::\d{2})?)-(\d{1,2}:\d{2}(?::\d{2})?)")
_WORD_RE = re.compile(r"[A-Za-z0-9][\w.$\\-]{3,}")
_DATE_OR_CLOCK_RE = re.compile(r"^(?:\d{4}-\d{2}-\d{2}|\d{2}/\d{2}/\d{4}|\d{1,2}:\d{2}(?::\d{2})?)$")
# A time as a row prints it: ISO with a T or a space, or a US-ordered date
# with a clock elsewhere in the row (Plaso's l2tcsv date and time cells).
_ISO_MINUTE_RE = re.compile(r"(\d{4}-\d{2}-\d{2})[t ](\d{2}:\d{2})")
_US_DATE_RE = re.compile(r"\b(\d{2})/(\d{2})/(\d{4})\b")
_CLOCK_RE = re.compile(r"\b(\d{2}:\d{2})(?::\d{2})?\b")
# A date written with an English month name, as mail headers (RFC 2822,
# "Tue, 04 Mar 2031 09:12:44 -0400") and mbox separator lines (C asctime,
# "Tue Mar  4 09:12:44 2031") print it. The month names are the formats'
# own fixed English abbreviations, not case knowledge.
_MONTH = r"(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*"
_MONTH_DATE_RE = re.compile(rf"\b\d{{1,2}} {_MONTH} \d{{4}} \d{{1,2}}:\d{{2}}(?::\d{{2}})?(?: [+-]\d{{4}})?"
                            rf"|\b{_MONTH} +\d{{1,2}} \d{{1,2}}:\d{{2}}(?::\d{{2}})? \d{{4}}", re.I)
# An event id stands in an event-id position: after its cue word, as the
# value of an event-id key or element, or in Plaso's bracketed id column.
# A bare number equal to it (a process id, a record number) is not the
# event.
_EID_CONTEXT = (r"(?:\bevent[\W_]{0,3}(?:id|code)\b|\beid\b|<eventid\b[^>]*>|\"(?:event[_ ]?id|eid|eventidcode)\"\s*:\s*\"?)"
                r"[\W_]{0,8}{eid}\b|\[{eid}\s*/")
_KIND_OF = {"md5": "hash", "sha1": "hash", "sha256": "hash", "hex": "hash"}
_ROW_CACHE: dict[tuple[str, int], tuple[tuple, list[str]]] = {}
_ROW_CACHE_CHARS = [0]


def claim_terms(statement: str, hosts=(), *, host: str = "") -> dict[str, Any]:
    """What a row would have to show for ``statement``: its strong entities
    (checkable entities without hosts and times), its minute times, the
    case hosts it names (the claim's own host included) and, for the
    fallback, its identifier-shaped words. Without ``hosts`` the active
    case's hosts are read here, so every reader (citation_supports, locate,
    citation_status, the report's lines) judges host affinity alike."""
    from core.entities import checkable_entities
    hosts = list(hosts or ()) or _active_case_hosts()
    ents = checkable_entities(statement, hosts)
    strong = {e for e in ents if not e.startswith(("host:", "ts:"))}
    times = {e.split(":", 1)[1].replace("T", " ") for e in ents if e.startswith("ts:")}
    named = {e.split(":", 1)[1] for e in ents if e.startswith("host:")}
    if host:
        named.add(host)
    from core.evidence_resolver import _ANCHOR_STOP
    values = {e.split(":", 1)[1].lower() for e in strong}
    names = set()
    # A clock range is two times, not one word ("10:16-10:48").
    spaced = _CLOCK_RANGE_RE.sub(r"\1 to \2", statement or "")
    for w in _WORD_RE.findall(spaced):
        word = w.rstrip(".,;:")
        if (len(word) >= 4 and _NAME_WORD_RE.match(word) and word.lower() not in _ANCHOR_STOP
                and not _OWN_LABEL_RE.match(word) and not _DATE_OR_CLOCK_RE.match(word)
                and word.lower() not in values
                and not any(word.lower() == h.lower() for h in named)):
            names.add(word.lower())
    return {"strong": strong, "times": times, "hosts": named, "names": names, "one_host": _one_host(hosts)}


def _row_times(row: str) -> set[str]:
    """The minutes a row states, as "YYYY-MM-DD HH:MM": ISO, a US-ordered
    date with a clock in the row, or a month-name date (the minute as
    written and, when the row prints an offset, its UTC minute too)."""
    out = {f"{d} {t}" for d, t in _ISO_MINUTE_RE.findall(row)}
    dates = _US_DATE_RE.findall(row)
    if dates:
        clocks = _CLOCK_RE.findall(row)
        for mm, dd, yyyy in dates:
            out |= {f"{yyyy}-{mm}-{dd} {c}" for c in clocks}
    for m in _MONTH_DATE_RE.finditer(row):
        p = parsedate_tz(m.group(0))
        if not p:
            continue
        try:
            moment = datetime(*p[:5])
        except ValueError:
            continue
        out.add(moment.strftime("%Y-%m-%d %H:%M"))
        if p[9]:
            out.add((moment - timedelta(seconds=p[9])).strftime("%Y-%m-%d %H:%M"))
    return out


def _one_host(hosts) -> bool:
    """Whether the case holds one host, so a row of its evidence needs no
    host label to belong to it: the Evidence Links name exactly one host,
    or they name none and the coverage ledger holds one container (disk or
    memory image). Unknown (no links, no ledger, no case) is not one. Known
    limit: one image beside unlinked folders of other hosts reads as one
    host (the ledger counts containers, not folders)."""
    labels = {str(h).casefold() for h in hosts or () if h}
    if labels:
        return len(labels) == 1
    return _ledger_containers(_active_case_dir()) == 1


_CONTAINERS: dict[str, tuple[int, int]] = {}


def _ledger_containers(case_dir: str) -> int:
    """How many container units the case's coverage ledger holds, read once
    per version of the ledger file; 0 when there is no case or ledger."""
    if not case_dir:
        return 0
    from core.coverage_ledger import CONTAINER_KIND, ledger_path, load_ledger
    path = ledger_path(case_dir)
    try:
        stamp = path.stat().st_mtime_ns
    except OSError:
        return 0
    hit = _CONTAINERS.get(str(path))
    if hit and hit[0] == stamp:
        return hit[1]
    units = load_ledger(case_dir).get("units") or {}
    n = sum(1 for u in units.values() if isinstance(u, dict) and u.get("kind") == CONTAINER_KIND)
    _CONTAINERS[str(path)] = (stamp, n)
    return n


def _entity_in_row(entity: str, row: str, eid_columns=None) -> bool:
    kind, _, value = entity.partition(":")
    if kind == "eid":
        # An event id stands in an event-id position in the row, or in the
        # column a table's header names as its event-id field.
        if re.search(_EID_CONTEXT.replace("{eid}", re.escape(value)), row) is not None:
            return True
        return eid_columns is not None and _eid_in_columns(value, row, eid_columns)
    from core.indicators import _found
    if kind in ("account", "email"):
        return _account_in_row(value, row)
    return _found(_KIND_OF.get(kind, kind), value, row)


def _account_in_row(value: str, row: str) -> bool:
    """DOMAIN\\user, domain.tld\\user and user@domain.tld are one account,
    whichever form the claim and the row use: the row must hold the user in
    one of those three forms, under a domain whose first label is the
    claim's. A bare user name is not an account sighting (it is also a
    profile path segment or a service name), and "Users\\jane.doe" is a
    profile path, not the account CORP\\jane.doe."""
    value = value.lower()
    if "@" in value:
        user, _, domain = value.partition("@")
    else:
        domain, _, user = value.replace("\\", "/").rpartition("/")
    label = domain.split(".")[0]
    if not user or not label:
        return False
    u, d = re.escape(user), re.escape(label)
    slashed = rf"(?<![a-z0-9._-]){d}(?:\.[a-z0-9-]+)*(?:\\{{1,2}}|/){u}(?![a-z0-9-])"
    at_form = rf"(?<![a-z0-9._-]){u}@{d}(?:\.[a-z0-9-]+)*(?![a-z0-9-])"
    return re.search(slashed, row) is not None or re.search(at_form, row) is not None


def _anchor_times(row: str, next_row: str = "") -> set[str]:
    """The minutes an anchor row binds: its own, or, when it states none, the
    row printed after it. Block output (RegRipper, RBCmd, samparse) prints a
    record's name on one line and its time on the next; the row before is
    never borrowed, since it belongs to the record above. Known limit: in a
    table of one record per row, an anchor row without a time borrows the
    next record's; the presence check is a floor, and the evaluator reads
    the whole call (cited_output)."""
    return _row_times(row) or (_row_times(next_row) if next_row else set())


def row_shows(terms: dict[str, Any], row: str, *, exclude=(), eid_columns=None,
              next_row: str = "") -> dict[str, Any] | None:
    """Whether one printed row shows the claim's terms: the strong entities
    it holds (those in ``exclude``, the file names of what the call was asked
    to read, do not count) and, when the claim states minute times, one of
    them in the same row, or in ``next_row`` when this row states no time
    (_anchor_times). Without a strong entity, the fallback: an
    identifier-shaped word of the claim with one of its times, and the
    claim's host in the row unless the case holds one host (_one_host).
    None when the row shows nothing."""
    row = (row or "").lower()
    if not row:
        return None
    found = {e for e in terms["strong"] if e not in exclude and _entity_in_row(e, row, eid_columns)}
    times = terms["times"] & _anchor_times(row, (next_row or "").lower()) if terms["times"] else set()
    if found:
        if terms["times"] and not times:
            return None
        return {"strong": found, "times": times}
    if not terms["strong"] and terms["names"] and terms["times"] and times and terms["hosts"]:
        from core.forensic_citation import host_mentioned
        names = {n for n in terms["names"] if re.search(r"(?<![\w.-])" + re.escape(n) + r"(?![\w-])", row)}
        if names and (terms.get("one_host") or any(host_mentioned(h, row) for h in terms["hosts"])):
            return {"strong": set(), "times": times, "names": names}
    return None


def unseen_terms(statement: str, tool_calls: list[dict], *, hosts=(), host: str = "",
                 case_dir=None) -> tuple[list[str], list[str]]:
    """``(unseen, all)``: the statement's strong entities and minute times
    that no printed row of the trace's evidence calls holds at all, each on
    its own, and every one of them, as written for a message. A value a row
    holds only because the call was asked to read it does not count."""
    terms = claim_terms(statement, hosts, host=host)
    # Entities first, then times, each sorted: the order the line prints.
    every = {e: e.partition(":")[2] for e in sorted(terms["strong"])} | {
        f"ts:{t}": t for t in sorted(terms["times"])}
    left = set(every)
    for entry in evidence_calls(tool_calls):
        if not left:
            break
        if entry.get("success") is False or not has_output(entry):
            continue
        excluded, _hosts = _read_paths(entry, case_dir)
        rows, eid_rows = call_view(entry)
        for i, row in enumerate(rows):
            low = row.lower()
            left -= {v for v in left if (v[3:] in _row_times(low) if v.startswith("ts:")
                                         else v not in excluded and _entity_in_row(v, low, eid_rows.get(i)))}
            if not left:
                break
    return [every[v] for v in every if v in left], list(every.values())


def call_rows(entry: dict) -> list[str]:
    """The printed rows of a call (call_view)."""
    return call_view(entry)[0]


def call_view(entry: dict) -> tuple[list[str], dict[int, tuple[str, frozenset[int]]]]:
    """The printed rows of a call and, for the rows of a table whose column
    header names an event-id field, where that field is (_event_id_columns),
    cached per call for the process (a whole-trace
    locate reads every call once). ponytail: the cache is bounded by total
    characters (ATLAS_CITATION_ROW_CACHE_CHARS); an inverted entity index
    replaces it when traces reach thousands of calls."""
    from core.envfile import env_int
    from core.indicators import _output_text, _rows_of, printed_rows
    cid = entry.get("call_id")
    key = (str(entry.get("stdout_file") or ""), len(str(entry.get("stdout_excerpt") or "")))
    # Call ids restart per case: a process that serves several cases keys
    # the cache by the case as well.
    slot = (_active_trace_dir(), cid) if isinstance(cid, int) else None
    if slot is not None:
        hit = _ROW_CACHE.get(slot)
        if hit is not None and hit[0] == key:
            return hit[1], hit[2]
    rows = printed_rows(entry)
    headers: list[str] = []
    try:
        from core.indicators import SPILL_READ_CHARS
        raw = _output_text(entry, SPILL_READ_CHARS)
        if raw.lstrip()[:1] == "{":
            headers = _rows_of(entry, raw)[1]
    except Exception:  # noqa: BLE001
        headers = []
    eid = _event_id_columns(headers, rows)
    if slot is not None:
        size = sum(len(r) for r in rows)
        bound = env_int("ATLAS_CITATION_ROW_CACHE_CHARS", 50_000_000)
        if _ROW_CACHE_CHARS[0] + size > bound:
            _ROW_CACHE.clear()
            _ROW_CACHE_CHARS[0] = 0
        _ROW_CACHE[slot] = (key, rows, eid)
        _ROW_CACHE_CHARS[0] += size
    return rows, eid


# A column header that names the event-id field of a log export or a count
# table (EvtxECmd's EventId, Windows' EventID, "Event ID", EventIdCode):
# format knowledge, like the event-id keys of _EID_CONTEXT.
_EID_HEADER_RE = re.compile(r"^\W*(?:event[\s_]?id(?:code)?|eid|event[\s_]?code)\W*$", re.I)
_TEXT_DELIMS = ("\t", ",", "|")


def _split_cells(line: str, delim: str) -> list[str]:
    return [c.strip().strip("\"'") for c in (line.split(delim) if delim else line.split())]


def _event_id_columns(headers: list[str], rows: list[str]) -> dict[int, tuple[str, frozenset[int]]]:
    """Which printed rows keep their event ids in a column, and where:
    {row index: ("json", indexes)} for every row of a JSON result whose
    header list names an event-id field (its rows are lists), and
    {row index: (delimiter, indexes)} for the rows under a text table's
    header line naming one (tab, comma, pipe or whitespace separated),
    wherever in the output the header stands (after summary lines too),
    until the table ends: a row with a different number of cells. Empty
    when no table names an event-id field."""
    cols = frozenset(i for i, h in enumerate(headers or []) if _EID_HEADER_RE.match(str(h)))
    if cols:
        return {i: ("json", cols) for i in range(len(rows))}
    out: dict[int, tuple[str, frozenset[int]]] = {}
    table: tuple[str, frozenset[int], int] | None = None
    for i, row in enumerate(rows):
        if table is not None:
            delim, tcols, width = table
            if len(_split_cells(row, delim)) == width:
                out[i] = (delim, tcols)
                continue
            table = None
        delim = next((d for d in _TEXT_DELIMS if d in row), "")
        cells = _split_cells(row, delim)
        hcols = frozenset(j for j, c in enumerate(cells) if _EID_HEADER_RE.match(c))
        if hcols and len(cells) > 1:
            table = (delim, hcols, len(cells))
    return out


def _eid_in_columns(value: str, row: str, where: tuple[str, frozenset[int]]) -> bool:
    """The row holds ``value`` as the cell of an event-id column."""
    delim, cols = where
    if delim == "json":
        try:
            cells = json.loads(row)
        except ValueError:
            return False
        if not isinstance(cells, list):
            return False
        return any(i < len(cells) and str(cells[i]).strip() == value for i in cols)
    cells = _split_cells(row, delim)
    return any(i < len(cells) and cells[i] == value for i in cols)


_READ_PATHS: dict[tuple[str, int], tuple[frozenset[str], frozenset[str]]] = {}
_LINKS_STAMP: dict[str, tuple[int, int]] = {}


def _forget_read_paths_on_new_links(where: str, case_dir) -> None:
    """The hosts behind a call's paths come from the case's evidence links:
    when that file changes (a host linked or relabelled), the memo for the
    case and the provenance classes cached with it are dropped."""
    from core.evidence_links import links_path
    root = str(case_dir) if case_dir else os.path.dirname(where)
    try:
        st = os.stat(links_path(root))
        stamp = (st.st_mtime_ns, st.st_size)
    except OSError:
        stamp = (0, 0)
    seen = _LINKS_STAMP.get(where)
    if seen == stamp:
        return
    _LINKS_STAMP[where] = stamp
    if seen is None:
        return
    for key in [k for k in _READ_PATHS if k[0] == where]:
        del _READ_PATHS[key]
    from core.provenance import reset_cache
    reset_cache()


def _read_paths(entry: dict, case_dir=None) -> tuple[frozenset[str], frozenset[str]]:
    """``(excluded file entities, hosts)`` of a call: the names of the files
    it was asked to read (a claim naming only the file a grep was pointed at
    is not shown by that grep) and the case hosts behind its evidence paths
    (host affinity, lower-cased), both from core.provenance.call_provenance.
    Memoized per case and call id: what a recorded call read does not change,
    and a whole-trace locate asks for every call once per finding.
    ponytail: unbounded per process, one small entry per call; bound it if a
    process serves many large cases."""
    cid = entry.get("call_id")
    where = str(case_dir or _active_trace_dir())
    if where:
        _forget_read_paths_on_new_links(where, case_dir)
    slot = (where, cid) if isinstance(cid, int) and where else None
    if slot is not None and slot in _READ_PATHS:
        return _READ_PATHS[slot]
    try:
        from core.provenance import call_provenance
        prov = call_provenance(entry, case_dir)
    except Exception:  # noqa: BLE001
        return frozenset(), frozenset()
    excluded: set[str] = set()
    for path in prov["paths"]:
        base = path.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1].lower()
        if base:
            excluded.add(f"file:{base}")
            excluded.add(f"path:{path.lower()}")
    out = (frozenset(excluded), frozenset(h.lower() for h in prov["hosts"]))
    if slot is not None:
        _READ_PATHS[slot] = out
    return out


def call_shows(terms: dict[str, Any], entry: dict, *, case_dir=None) -> dict[str, Any] | None:
    """The best row of ``entry`` that shows the claim's terms (row_shows), or
    None: a call that is not evidence or did not run shows nothing; a call
    that read evidence of a case host does not show a claim that names
    hosts but not that one."""
    from core.forensic_citation import citation_class
    if not isinstance(entry, dict) or entry.get("success") is False or citation_class(entry) != "evidence":
        return None
    excluded, hosts = _read_paths(entry, case_dir)
    # Host labels compare case-insensitively: a claim may write a host in
    # another case than the Evidence Links label.
    if terms["hosts"] and hosts and not ({h.lower() for h in terms["hosts"]} & hosts):
        return None
    best = None
    rows, eid_rows = call_view(entry)
    for i, row in enumerate(rows):
        hit = row_shows(terms, row, exclude=excluded, eid_columns=eid_rows.get(i),
                        next_row=rows[i + 1] if i + 1 < len(rows) else "")
        if hit and (best is None or (len(hit["strong"]), len(hit["times"])) > (len(best["strong"]), len(best["times"]))):
            best = hit
    return best


def locate(statement: str, entries: list[dict], hosts=(), *, exclude=(), claim_host: str = "",
           limit: int = 3, case_dir=None) -> list[int]:
    """The evidence calls of the whole trace whose rows show ``statement``,
    best first (most strong entities, then times, then newest), at most
    ``limit`` of them; ``exclude`` are the ids already cited."""
    # Every statement with a strong entity (or a time-bound name) is located,
    # whether or not the universal or negative grammar flags it; one with
    # neither, a genuine absence among them, never is. Ceiling: a flagged
    # statement whose only strong entity is what it calls absent counts a
    # row holding that entity as showing it.
    terms = claim_terms(statement, hosts, host=claim_host)
    if not terms["strong"] and not (terms["names"] and terms["times"]):
        return []
    skip = {int(c) for c in exclude if c is not None}
    scored: list[tuple[tuple, int]] = []
    for e in entries:
        if not isinstance(e, dict) or e.get("type") != "tool_call" or not has_output(e):
            continue
        cid = int(e.get("call_id") or 0)
        if not cid or cid in skip:
            continue
        hit = call_shows(terms, e, case_dir=case_dir)
        if hit:
            scored.append(((len(hit["strong"]), len(hit["times"]), cid), cid))
    scored.sort(reverse=True)
    return [cid for _k, cid in scored[:limit]]


# A hash bound to files. A file written with its own digest in parentheses
# ("a.jpg (MD5 H)", "a.jpg (SHA256: H, 4096 bytes)") or a digest written with
# its file ("H (a.jpg)") is a pair of that one name, read first; the
# parenthesis is then taken out. In what is left, a clause (split at "; ",
# " (", ") ", ", ", ". " and dashes) holding exactly one full-length hash
# (the MD5, SHA-1 and SHA-256 lengths) and one or more file names (a
# basename with a public file extension, core.entities.FILE_EXTENSIONS) says
# those files have that hash. Lexical shapes only, no knowledge of a case.
# ponytail: a name set off from its hash by that punctuation outside these
# two parenthetical forms, an abbreviated hash, or a clause with two hashes
# forms no pair, and the check is silent there.
_PAIR_SPLIT_RE = re.compile(r";|\s\(|\)(?=\s|$|[.,;:](?:\s|$))|,\s|\.\s|\s[-\u2013\u2014]\s|[\u2013\u2014]")
_PAIR_HASH = r"(?:[0-9a-f]{64}|[0-9a-f]{40}|[0-9a-f]{32})"
_PAIR_HASH_RE = re.compile(r"(?<![0-9a-f])" + _PAIR_HASH + r"(?![0-9a-f])", re.I)
# A file name is at most 255 characters (the common file-system limit),
# which also bounds the backtracking over a long dotted token.
_PAIR_NAME = r"[^\s/\\:*?\"'<>|`,;]{1,255}\.[A-Za-z0-9]{1,8}"
_PAIR_NAME_RE = re.compile(r"[^\s/\\:*?\"'<>|`,;]{1,255}\.([A-Za-z0-9]{1,8})(?![\w])")
_PAREN_NAME_DIGEST_RE = re.compile(r"(" + _PAIR_NAME + r")\s*(\([^()]*\))")
_PAREN_DIGEST_NAME_RE = re.compile(r"(?<![0-9a-f])(" + _PAIR_HASH + r")\s*(\(\s*(" + _PAIR_NAME + r")\s*\))", re.I)
# Each name of a clause must share a row with its hash ("A and B share MD5
# H" says both have it): replayed over every finding with a pair on the
# recorded traces, no true pairing was refused this way.
# Known false refusals: a second file named in the clause for another reason
# ("H is the MD5 of a.exe extracted from b.zip", "a.exe launched by b.exe has
# MD5 H") is held to the digest too (tests pin them).
PAIR_EACH_NAME = True


def _file_names(text: str) -> list[str]:
    """The file names ``text`` holds, lower-cased, in order."""
    from core.entities import FILE_EXTENSIONS
    return list(dict.fromkeys(
        m.group(0).lower().rstrip(".") for m in _PAIR_NAME_RE.finditer(text)
        if m.group(1).lower() in FILE_EXTENSIONS and not _PAIR_HASH_RE.fullmatch(m.group(0).split(".")[0])))


def hash_pairs(statement: str) -> list[tuple[str, tuple[str, ...]]]:
    """(hash, file names) for each parenthetical pair and each clause of
    ``statement`` that binds file names to one hash, lower-cased, in order."""
    text = statement or ""
    out: list[tuple[str, tuple[str, ...]]] = []
    spans: list[tuple[int, int]] = []
    for m in _PAREN_NAME_DIGEST_RE.finditer(text):
        digests = {h.lower() for h in _PAIR_HASH_RE.findall(m.group(2))}
        names = _file_names(m.group(1))
        if len(digests) == 1 and names:
            out.append((digests.pop(), (names[-1],)))
            spans.append(m.span(2))
    for m in _PAREN_DIGEST_NAME_RE.finditer(text):
        names = _file_names(m.group(3))
        if names and not any(a <= m.start(2) < b for a, b in spans):
            out.append((m.group(1).lower(), (names[-1],)))
            spans.append(m.span(2))
    for a, b in sorted(spans, reverse=True):
        text = text[:a] + " " + text[b:]
    for clause in _PAIR_SPLIT_RE.split(text):
        hashes = {h.lower() for h in _PAIR_HASH_RE.findall(clause)}
        if len(hashes) != 1:
            continue
        names = tuple(_file_names(clause))
        if names:
            out.append((hashes.pop(), names))
    return list(dict.fromkeys(out))


def _digest_records(data: dict) -> bool:
    """A record in one of the result's top-level lists holds a digest: the
    records are rows of their own (a folder's hashes), not parts of one."""
    return any(isinstance(v, list) and any(
        isinstance(r, dict) and any(isinstance(x, str) and _PAIR_HASH_RE.fullmatch(x.strip()) for x in r.values())
        for r in v) for v in data.values())


def _pair_rows(entry: dict) -> list[str]:
    """The rows a pair is looked for in: the call's printed rows, or for a
    record result (a JSON object that is no result set and whose listed
    records hold no digest: a hash of one file beside the files of the same
    content) the whole call as one row, since every field of it is said of
    the one subject."""
    rows = call_rows(entry)
    try:
        import json as _json
        from core.indicators import _ROW_KEYS, SPILL_READ_CHARS, _output_text
        raw = _output_text(entry, SPILL_READ_CHARS).lstrip()
        if raw[:1] == "{":
            data = _json.loads(raw)
            if (isinstance(data, dict) and not any(isinstance(data.get(k), list) for k in _ROW_KEYS)
                    and not _digest_records(data)):
                return [" ".join(rows)]
    except (ValueError, TypeError):
        pass
    return rows


def _name_in_row(name: str, row: str) -> bool:
    return re.search(r"(?<![\w-])" + re.escape(name) + r"(?![\w-])", row) is not None


def _pair_names_shown(entry: dict, digest: str, names: tuple[str, ...]) -> set[str]:
    """The names of the pair that stand in one row of ``entry`` with the hash."""
    out: set[str] = set()
    for row in _pair_rows(entry):
        if digest in row:
            out |= {n for n in names if _name_in_row(n, row)}
    return out


def unshown_pairs(statement: str, cited: list[dict]) -> list[tuple[str, tuple[str, ...]]]:
    """The pairs of ``statement`` no row of the ``cited`` calls shows: with
    PAIR_EACH_NAME the names not shown with their hash, else all the names
    of a clause none of whose names is."""
    out: list[tuple[str, tuple[str, ...]]] = []
    for digest, names in hash_pairs(statement):
        shown: set[str] = set()
        for e in cited:
            if isinstance(e, dict) and e.get("success") is not False:
                shown |= _pair_names_shown(e, digest, names)
        missing = tuple(n for n in names if n not in shown)
        if missing and (PAIR_EACH_NAME or len(missing) == len(names)):
            out.append((digest, missing))
    return out


def pair_showing_calls(pairs: list[tuple[str, tuple[str, ...]]], tool_calls: list[dict], *,
                       exclude=()) -> dict[tuple[str, str], int]:
    """For each (hash, name) of ``pairs``, the newest evidence call of the
    trace (not in ``exclude``) whose row shows them together."""
    from core.forensic_citation import citation_class
    skip = {int(c) for c in exclude if c is not None}
    out: dict[tuple[str, str], int] = {}
    want = [(d, n) for d, names in pairs for n in names]
    for e in reversed(tool_calls or []):
        if not want:
            break
        cid = int(e.get("call_id") or 0) if isinstance(e, dict) else 0
        if (not cid or cid in skip or e.get("type") != "tool_call" or e.get("success") is False
                or not has_output(e) or citation_class(e) != "evidence"):
            continue
        for d, n in list(want):
            if n in _pair_names_shown(e, d, (n,)):
                out[(d, n)] = cid
                want.remove((d, n))
    return out


def pair_detail(pairs, showing: dict[tuple[str, str], int], finding_call_id: int = 0) -> str:
    """What a pair status says: which call shows each file with its hash
    (and that it ran after the finding), or that no call does."""
    parts = []
    for d, names in pairs:
        for n in names:
            cid = showing.get((d, n))
            if cid:
                later = ", which ran after this finding," if finding_call_id and cid > finding_call_id else ""
                parts.append(f"call {cid}{later} shows {n} with {d[:16]}")
            else:
                parts.append(f"no call shows {n} with {d[:16]} in one row")
    return "a hash bound to a file: " + "; ".join(parts)


# The detail a not_checkable status carries when the claim names only the
# file its cited call read.
READ_FILE_DETAIL = ("the cited call read the file the finding names; the statement names no value "
                    "a row could show")


def citation_status(statement: str, cited: list[dict], located: list[int], host: str,
                    tool_calls: list[dict], *, hosts=(), case_dir=None,
                    finding_call_id: int = 0) -> tuple[str, list[int], str]:
    """The one computation of a finding's citation status, its located ids
    and a detail: ``cited`` (an analyst-cited evidence call shows it),
    ``located`` (no cited call does, a call of the trace does),
    ``not_shown`` (no call shows it), ``not_checkable`` (nothing a tool
    output could show), or ``own_words`` (it cites only the run's own words
    or lookups and names something checkable). ``located`` are ids known
    already (record time); they are re-checked, and the whole trace is
    searched when they do not show the claim.

    Order: the cited rows, then the absence branch (a flagged statement
    whose cited complete search grounds it is cited), then the located ids
    and the whole-trace locate. Every statement with a strong entity (or a
    time-bound name) is located when neither settles it, whether or not the
    universal or negative grammar flags it. A statement whose only
    strong entities are files its cited call read is not_checkable with
    READ_FILE_DETAIL: the read is not a sighting of the name and no row
    entity stands for the content. A statement whose cited rows show it but
    bind a file to a hash no cited row shows them together in
    (unshown_pairs) is located by the calls that do, with pair_detail
    (naming a call that ran after ``finding_call_id``), or not_shown."""
    terms = claim_terms(statement, hosts, host=host)
    checkable = bool(terms["strong"]) or bool(terms["names"] and terms["times"])
    cited_evidence = evidence_calls(cited)
    evidence = [e for e in cited_evidence if has_output(e)]
    read_file_only = bool(terms["strong"]) and any(
        terms["strong"] <= _read_paths(e, case_dir)[0] for e in cited_evidence)
    if checkable and any(call_shows(terms, e, case_dir=case_dir) for e in evidence):
        missing = unshown_pairs(statement, evidence)
        if not missing:
            return "cited", [], ""
        showing = pair_showing_calls(missing, tool_calls, exclude=[e.get("call_id") for e in cited])
        detail = pair_detail(missing, showing, finding_call_id)
        if len(showing) == sum(len(names) for _d, names in missing):
            return "located", sorted(set(showing.values())), detail
        return "not_shown", [], detail
    absence = is_absence_claim(statement)
    # A flagged statement whose cited complete search grounds it is cited,
    # before any other call's row is looked at: a row elsewhere that holds
    # what an absence calls missing contradicts it and must not relabel the
    # finding as located (nor lower its tier).
    if absence and citation_supports(statement, cited, tool_calls=tool_calls, host=host,
                                     hosts=hosts) is True:
        return "cited", [], ""
    if checkable:
        by = {int(e.get("call_id") or 0): e for e in tool_calls if isinstance(e, dict)}
        kept = [int(c) for c in located if int(c) in by and call_shows(terms, by[int(c)], case_dir=case_dir)]
        if kept:
            return "located", kept, ""
        found = locate(statement, tool_calls, hosts, exclude=cited_ids({"input_call_ids": [
            e.get("call_id") for e in cited]}), claim_host=host, case_dir=case_dir)
        if found:
            return "located", found, ""
    # A quotation of the statement standing in a cited call's rows is a
    # sighting too (quote_rows): a statement whose checkable content is its
    # quoted text, or a time and a name no row test binds, is cited by the
    # call that printed the words. Judged after the located ids and the
    # trace locate, so a statement another call shows by its rows stays
    # "located" (the located lowering's superset holds); and never for a
    # statement that names a value a row could show besides the quotation.
    if not absence and _quotation_shown(statement, terms, cited_evidence, case_dir):
        return "cited", [], ""
    if absence:
        if cited and not cited_evidence:
            return "own_words", [], ""
        return "not_shown", [], ""
    if not checkable:
        return "not_checkable", [], ""
    if read_file_only:
        return "not_checkable", [], READ_FILE_DETAIL
    if cited and not cited_evidence:
        return "own_words", [], ""
    return "not_shown", [], ""


# Quoted text a statement presents as verbatim: paired double quotes,
# straight or curly. Its words are runs of 2+ word characters, casefolded,
# in any script.
_QUOTED_RE = re.compile(r'"([^"\n]*)"|“([^”\n]*)”')
_WORD_TOKEN_RE = re.compile(r"\w{2,}")
_NON_ASCII_RE = re.compile(r"[^\x00-\x7f]")


def _word_tokens(text: str) -> list[str]:
    return _WORD_TOKEN_RE.findall(str(text or "").casefold())


def quoted_values(statement: str) -> list[str]:
    """The quotations of a statement a row must show, each as its word tokens
    joined by one space: a quotation of two or more words, or one word that
    holds a non-ASCII letter (a script written without spaces; a one-word
    quotation with a diacritic, "café", is a value by the same rule: the
    strict direction). An ellipsis splits a quotation into parts. A
    one-word ASCII quotation ("staging") is a label, not a value: the
    presence check leaves it to the evaluator."""
    out: list[str] = []
    for m in _QUOTED_RE.finditer(statement or ""):
        body = m.group(1) if m.group(1) is not None else m.group(2)
        for part in re.split(r"\.\.\.|…", body):
            toks = _word_tokens(part)
            if len(toks) >= 2 or (len(toks) == 1 and _NON_ASCII_RE.search(toks[0])):
                out.append(" ".join(toks))
    return list(dict.fromkeys(out))


def quote_rows(quotes: list[str], rows: list[str]) -> dict[str, list[int]]:
    """{quotation: the indexes of the rows that show it}. A quotation of three
    or more words may run across row breaks (a tool cuts long text into
    lines, strings at a non-ASCII apostrophe); a shorter one must stand in
    one row, a single word as a substring of it."""
    toks = [_word_tokens(r) for r in rows]
    out: dict[str, list[int]] = {}
    stream: list[str] = []
    owner: list[int] = []
    for i, t in enumerate(toks):
        stream += t
        owner += [i] * len(t)
    joined = " " + " ".join(stream) + " "
    starts: dict[int, int] = {}
    pos = 1
    for j, t in enumerate(stream):
        starts[pos] = j
        pos += len(t) + 1
    for q in quotes:
        words = q.split()
        if len(words) >= 3:
            k = joined.find(" " + q + " ")
            if k >= 0 and k + 1 in starts:
                first = starts[k + 1]
                out[q] = sorted(set(owner[first:first + len(words)]))
        elif len(words) == 2:
            hit = [i for i, t in enumerate(toks) if (" " + q + " ") in (" " + " ".join(t) + " ")]
            if hit:
                out[q] = hit
        else:
            hit = [i for i, r in enumerate(rows) if q in str(r).casefold()]
            if hit:
                out[q] = hit
    return out


def _quotation_shown(statement: str, terms: dict[str, Any], evidence: list[dict], case_dir=None) -> bool:
    """Whether a quotation of ``statement`` is its sighting in the rows of
    one of ``evidence`` (the cited evidence calls): only when the statement
    names no strong entity outside the files those calls read (an address
    or a hash beside the quotation is the row test's to find, and a
    quotation must not stand in for it), and, when it states minute times,
    with one of them in a row the quotation spans (row_shows' time
    binding). Host affinity as call_shows applies."""
    quotes = quoted_values(statement)
    if not quotes:
        return False
    read: set[str] = set()
    for entry in evidence:
        read |= _read_paths(entry, case_dir)[0]
    if terms["strong"] - read:
        return False
    wanted = {h.lower() for h in terms["hosts"]}
    for entry in evidence:
        if entry.get("success") is False or not has_output(entry):
            continue
        _excluded, call_hosts = _read_paths(entry, case_dir)
        if wanted and call_hosts and not (wanted & call_hosts):
            continue
        rows = call_view(entry)[0]
        for _q, ix in quote_rows(quotes, rows).items():
            if not terms["times"] or any(terms["times"] & _row_times(rows[i]) for i in ix):
                return True
    return False


def shown_values(statement: str, own: list[dict], *, hosts=(), host: str = "", case_dir=None,
                 tool_calls: list[dict] | None = None, supporting_evidence: str = "") -> dict[str, Any]:
    """The presence check a CONFIRMED statement must pass (record_finding):
    every checkable entity, minute time and quotation it states stands in a
    row of its own cited evidence calls (``own``), a time only in a row that
    also holds one of its entities or quotations, or in the row printed
    after that row when it states no time of its own (_anchor_times). A
    statement with no entity and no quotation binds its times to a row
    holding one of its identifier-shaped names; one without a name either
    shows a time in any of its cited rows. A sentence the absence
    grammar flags is judged by its cited complete search instead
    (citation_supports). Files a cited call was asked to read are its
    source, not values. The check is about presence, never meaning: a value
    shown in another role (the source address where the statement says
    destination) passes, and identifier names, counts and the reading of a
    row are the evaluator's. Returns {"unshown": [...], "unsupported": [the
    absence sentences no cited complete search grounds], "shown": n}."""
    from .universal_from_truncated import split_sentences
    hosts = list(hosts or ()) or _active_case_hosts()
    strong: set[str] = set()
    times: set[str] = set()
    quotes: list[str] = []
    named_hosts: set[str] = {host} if host else set()
    names: set[str] = set()
    unsupported: list[str] = []
    for sentence in split_sentences(statement):
        if is_absence_claim(sentence):
            if citation_supports(sentence, own, tool_calls=list(tool_calls or []),
                                 supporting_evidence=supporting_evidence, host=host,
                                 hosts=hosts) is not True:
                unsupported.append(sentence)
            continue
        terms = claim_terms(sentence, hosts, host=host)
        strong |= terms["strong"]
        times |= terms["times"]
        named_hosts |= terms["hosts"]
        names |= terms["names"]
        quotes += [q for q in quoted_values(sentence) if q not in quotes]
    # What anchors a time: the statement's entities or quotations; without
    # either, its names; without a name either, any row.
    by_name = not strong and not quotes
    read: set[str] = set()
    shown: set[str] = set()
    for entry in evidence_calls(own):
        if entry.get("success") is False or not has_output(entry):
            continue
        excluded, call_hosts = _read_paths(entry, case_dir)
        read |= strong & excluded
        if named_hosts and call_hosts and not ({h.lower() for h in named_hosts} & call_hosts):
            continue
        rows, eid_rows = call_view(entry)
        qmap = quote_rows(quotes, rows)
        for i, row in enumerate(rows):
            ents = {e for e in strong if e not in excluded and _entity_in_row(e, row, eid_rows.get(i))}
            quoted = {f"quote:{q}" for q, ix in qmap.items() if i in ix}
            anchored = bool(ents or quoted)
            if by_name and times:
                low = row.lower()
                anchored = not names or any(
                    re.search(r"(?<![\w.-])" + re.escape(n) + r"(?![\w-])", low) for n in names)
            if anchored:
                shown |= ents | quoted
                seen = _anchor_times(row, rows[i + 1] if i + 1 < len(rows) else "")
                shown |= {f"ts:{t}" for t in times if t in seen}
    values = (strong - read) | {f"ts:{t}" for t in times} | {f"quote:{q}" for q in quotes}
    return {"unshown": sorted(v for v in values if v not in shown), "unsupported": unsupported,
            "shown": len(values & shown),
            "quotes_shown": len({v for v in values & shown if v.startswith("quote:")})}


# How the evaluator reads a cited call (cited_output): a long row as its
# head, which names the record, and a window around each value the finding
# names, "…" for what is left out; a call no row of which matches, by its
# first rows.
_ROW_HEAD, _ROW_WINDOW, _HEAD_ROWS = 100, 90, 3
# A word of prose joined by hyphens ("anti-forensic"): no identifier. Known
# limit: a lowercase hyphenated tool name (ssh-keygen, apt-get) has the same
# shape and escapes the names advisory, which is advisory only.
_PROSE_HYPHEN_RE = re.compile(r"[a-z]+(?:-[a-z]+)+")
# A date or a clock in a statement (ISO, US, a time of day).
_DATE_PART_RE = re.compile(r"\d{4}-\d{2}-\d{2}(?:[T ]\d{1,2}:\d{2}(?::\d{2}(?:\.\d+)?)?)?|\d{1,2}/\d{1,2}/\d{4}|"
                           r"\d{1,2}:\d{2}(?::\d{2}(?:\.\d+)?)?")


# Characters that would start a new line or hide text inside a shown row:
# the line and paragraph breaks (LF, CR, VT, FF, NEL, LS, PS), the control
# characters, and the format characters (category Cf: a zero-width joiner,
# a direction override). Each is shown as a visible escape, so a row stays
# one line, can never read as one of Atlas's own lines of the block, and
# keeps its own characters: a right-to-left override in a file name or a
# look-alike letter in a domain is an indicator the evaluator must see.
_INVISIBLE_RE = re.compile("[\x00-\x1f\x7f\x85\u2028\u2029]")
_ESCAPES = {"\n": "\\n", "\r": "\\r", "\t": "\\t"}


def _escape(c: str) -> str:
    code = ord(c)
    return _ESCAPES.get(c) or (f"\\x{code:02x}" if code < 0x100 else
                               f"\\u{code:04x}" if code < 0x10000 else f"\\U{code:08x}")


def _visible(text: str) -> str:
    """``text`` as one line of visible characters, its own characters kept:
    any "cited output" phrase (a copy of Atlas's marker, found on a folded
    copy, tools._gates._match.neutral_request_text) rewritten as the
    analyst's words, then every break, control and format character shown
    as an escape, so evidence text can neither forge Atlas's lines nor its
    block."""
    from ._match import neutral_request_text
    shown = neutral_request_text(str(text or ""))
    if shown.isascii():
        return _INVISIBLE_RE.sub(lambda m: _escape(m.group()), shown)
    return "".join(_escape(c) if _INVISIBLE_RE.match(c) or unicodedata.category(c) == "Cf" else c
                   for c in shown)


def _display_row(row: Any) -> str:
    """A row as printed, one visible line (_visible); a record as key=value
    pairs, without Atlas's own row annotations (keys starting "_") and empty
    cells."""
    if isinstance(row, dict):
        text = " | ".join(f"{k}={v}" for k, v in row.items()
                          if not str(k).startswith("_") and v not in (None, "", "-", [], {}))
    else:
        text = row if isinstance(row, str) else json.dumps(row, ensure_ascii=False, default=str)
    return _visible(text)


# How much of a long row the windows around the finding's words may add up
# to: the head and the value windows always show, word windows only while
# the row stays under this. ponytail: one bound for every row; a budget
# from the room if the rows crowd it out.
_ROW_BOUND = 600


def _merged(spans) -> list[list[int]]:
    out: list[list[int]] = []
    for a, b in sorted(spans):
        if out and a <= out[-1][1]:
            out[-1][1] = max(out[-1][1], b)
        else:
            out.append([a, b])
    return out


def _witness(text: str, needles, words=()) -> str:
    """The row's head and a window around each needle (the values the row
    matched, always) and each word (the finding's words it holds, while the
    shown text stays under _ROW_BOUND), merged."""
    if len(text) <= _ROW_HEAD + 2 * _ROW_WINDOW:
        return text
    low = text.casefold()

    def span(n):
        k = low.find(str(n).casefold()) if n else -1
        return (max(0, k - _ROW_WINDOW), min(len(text), k + len(str(n)) + _ROW_WINDOW)) if k >= 0 else None

    spans = [(0, _ROW_HEAD)] + [s for s in map(span, needles) if s]
    for w in words:
        s = span(w)
        if s and sum(b - a for a, b in _merged(spans + [s])) <= _ROW_BOUND:
            spans.append(s)
    merged = _merged(spans)
    return " … ".join(text[a:b] for a, b in merged) + (" …" if merged[-1][1] < len(text) else "")


def _rows_word(n: int) -> str:
    return f"{n} row" if n == 1 else f"{n} rows"


def _needle(value: str) -> str:
    kind, _, text = value.partition(":")
    if kind == "quote":
        return text.split()[0]
    if kind == "ts":
        return text.split()[-1]
    return text


def cited_output(finding: str, evidence: str, call_ids, *, host: str = "", case_dir=None,
                 room: int | None = None) -> str:
    """What the cited calls printed, for the evaluator beside the analyst's
    account: per call a header (the host its evidence paths belong to, its
    rows, how many match a value the finding or its evidence names, how many
    are shown) and its rows, read with the echo-free reader the view uses, so
    a row's #n is its place in the output and the call's own request is never
    output. A call whose rows fit its share of ``room`` is shown whole: an
    unshown row is what made the evaluator read a value as unobserved when a
    claim binds values (an identifier with the record that types it) or lists items the
    matcher does not extract (folder names, subjects). A larger call shows
    one witness per value, then the rows holding the most of the finding's
    values and then its words, and its header counts the rows left out. A long row shows its
    head and a window around each matched value and each word of the
    finding it holds (the field that binds a value, such as the account
    beside a command, stays visible). Every row is one visible line
    (_visible). A call that is the run's own words gives no rows; a
    background job's start stands for its outcome. The last lines name what
    Atlas's matcher found in no cited row: the finding's entities, times and
    quotations, and, as an advisory, its identifier names. The matcher can
    miss a value printed in another form; the rows decide. ``room`` bounds
    the rows in characters: rows past it are counted, never dropped
    unsaid."""
    from core.coverage_ledger import resolved_entry
    from core.execution_log import log
    from core.forensic_citation import citation_class
    from core.indicators import SPILL_READ_CHARS, _output_text, _row_text, _rows_of
    case_dir = case_dir or _active_case_dir() or None
    hosts = _active_case_hosts()
    by = log.index().by_call_id or {}
    finding_text = str(finding or "").replace("\\\\", "\\")
    text = f"{finding_text}\n{evidence or ''}"
    sel = claim_terms(text, hosts, host=host)
    names = set(claim_terms(finding_text, hosts, host=host)["names"])
    quotes = quoted_values(text)
    # Sizes, offsets, ports and ids name rows; the parts of a date or a clock
    # (a year is in every row of a timeline) do not, so they are taken out.
    undated = _DATE_PART_RE.sub(" ", text)
    nums = {t for t in _word_tokens(undated) if len(t) >= 4 and any(ch.isdigit() for ch in t)}
    # The finding's own words: a long row's window opens around each one
    # the row holds, so what binds a value (an account, a key name) is shown
    # even when the matcher has no term for it.
    words = {t for t in _word_tokens(finding_text) if len(t) >= 4}
    room = room if room is not None else 10 ** 9
    lines: list[str] = []
    used = 0
    cited: list[dict] = []
    names_seen: set[str] = set()
    times_seen: set[str] = set()
    all_rows: list[str] = []
    ids: list[int] = []
    for c in call_ids or []:
        try:
            ids.append(int(c))
        except (TypeError, ValueError):
            continue
    order = list(dict.fromkeys(c for c in ids if c > 0))
    for k, cid in enumerate(order):
        entry = by.get(cid)
        if not isinstance(entry, dict):
            lines.append(f"[call {cid}] not in this run's trace")
            continue
        if entry.get("type") != "tool_call" or citation_class(entry) == "own_words":
            # A reason call, or a tool call that is the run restating itself
            # (a record, a note, a hypothesis made through a tool): named,
            # never shown as rows.
            what = (entry.get("tool") or entry.get("mcp_tool")
                    or str(entry.get("cmd") or "").split(" ", 1)[0].replace("<py>:", "")
                    or entry.get("type") or "entry")
            lines.append(f"[call {cid}] the run's own words ({what}), not tool output")
            continue
        seen = resolved_entry(case_dir, entry)
        if seen is None:
            lines.append(f"[call {cid}] no outcome yet (a job still running, or stopped by Atlas)")
            continue
        if seen.get("success") is False:
            lines.append(f"[call {cid}] failed: {_visible(str(seen.get('stderr') or 'no output')[:160])}")
            continue
        cited.append(entry)
        tool = str(entry.get("mcp_tool") or str(entry.get("cmd") or "").split(" ", 1)[0]).replace("<py>:", "")
        target = _visible(str(entry.get("evidence_ref") or ""))
        lookup = citation_class(entry) == "external_lookup"
        excluded, call_hosts = _read_paths(entry, case_dir)
        # The host the call's evidence paths belong to, by the case's label:
        # a row of a host's log rarely prints the host's name.
        of_host = ", ".join(next((h for h in hosts if h.lower() == c), c) for c in sorted(call_hosts))
        head = f"[call {cid}] {tool}" + (f" on {target}" if target else "") + (
            f" of host {of_host}" if of_host else "") + (
            " (outside lookup: what a provider returned for the value it was asked about)" if lookup else "")
        rows, eid_rows = call_view(entry)
        raw_rows = [r for r in _rows_of(entry, _output_text(entry, SPILL_READ_CHARS))[0] if _row_text(r).strip()]
        shown_rows = [_display_row(r) for r in (raw_rows if len(raw_rows) == len(rows) else rows)]
        sf = str(entry.get("stdout_file") or "")
        size = os.path.getsize(sf) if sf and os.path.exists(sf) else 0
        cut = f", read to {SPILL_READ_CHARS:,} of {size:,} characters" if size > SPILL_READ_CHARS else ""
        if not rows:
            lines.append(f"{head}: printed no row{cut}")
            continue
        qmap = quote_rows(quotes, rows)
        hits: list[tuple[int, set[str]]] = []
        all_rows += rows
        bound: dict[int, set[str]] = {}
        for i, row in enumerate(rows):
            times_seen |= _row_times(row)
            h = {e for e in sel["strong"] if e not in excluded and _entity_in_row(e, row, eid_rows.get(i))}
            hn = {n for n in names if re.search(r"(?<![\w.-])" + re.escape(n) + r"(?![\w-])", row)}
            names_seen |= hn
            h |= {f"name:{n}" for n in hn}
            h |= {f"quote:{q}" for q, ix in qmap.items() if i in ix}
            toks = set(_word_tokens(row))
            h |= {f"num:{n}" for n in nums if n in toks}
            bound[i] = words & toks
            if h:
                h |= {f"ts:{t}" for t in sel["times"] if t in _row_times(row)}
                hits.append((i, h))
        # A word of the finding every row holds (the host of a host's log)
        # binds nothing in particular and opens no window.
        if len(rows) > 1:
            common = set.intersection(*bound.values()) if bound else set()
            bound = {i: b - common for i, b in bound.items()}
        # A name or a number every row holds (the host of a host's log, the
        # source of every record) picks no row: it is no match term here.
        # Known limit: a time is added above, before this filter, so a row
        # whose only other term was such a name still picks on its time;
        # that costs block room, not correctness.
        if len(rows) > 1:
            weak = {t for t in set().union(*(h for _i, h in hits)) if t.startswith(("name:", "num:"))
                    and sum(1 for _i, h in hits if t in h) == len(rows)} if hits else set()
            hits = [(i, h - weak) for i, h in hits if h - weak]
        byrow = dict(hits)
        whole = [f"  #{i + 1} {_witness(shown_rows[i], [_needle(v) for v in byrow.get(i, ())], sorted(bound.get(i, ())))}"
                 for i in range(len(rows))]
        matched = (f"{len(hits)} match the finding's values" if hits
                   else "Atlas's matcher matched none of the finding's values")
        # The call's share of the room: what is left over the calls still to
        # come, so a small call leaves what it does not use to the next.
        share = max(room - used, 0) // max(len(order) - k, 1)
        if sum(len(line) for line in whole) <= share:
            # A spill read only in part is shown whole as far as it was read:
            # never "all shown", which would license a count or an absence.
            shown_all = "; the rows read are shown" if cut else ", all shown"
            lines.append(f"{head}: {_rows_word(len(rows))}{cut}{shown_all}; {matched}")
            lines += whole
            used += sum(len(line) for line in whole)
            continue
        # Over its share: every value keeps one witness (the rows holding the
        # most values first, and every row a shown quotation spans, since a
        # tool may cut a quoted line in two), then the rows holding the most
        # of the finding's values, then of its words; a row holding neither
        # is added only when nothing matched (the call's first rows). Shown
        # at their places, never more than the share.
        covered: set[str] = set()
        chosen: list[int] = []
        for i, h in sorted(hits, key=lambda x: (-len(x[1]), x[0])):
            if h - covered:
                chosen.append(i)
                covered |= h
        for q, ix in qmap.items():
            if f"quote:{q}" in covered:
                chosen += [i for i in ix if i not in chosen and i in byrow]
        rest = sorted((i for i in range(len(rows)) if i not in chosen and (i in byrow or bound.get(i))),
                      key=lambda i: (-len(byrow.get(i, ())), -len(bound.get(i, ())), i))
        if not chosen and not rest:
            rest = list(range(min(_HEAD_ROWS, len(rows))))
        out: dict[int, str] = {}
        spent = 0
        for i in chosen + rest:
            if spent + len(whole[i]) > share:
                continue        # a row too long for the share leaves it to the smaller rows after it
            out[i] = whole[i]
            spent += len(whole[i])
        used += spent
        lines.append(f"{head}: {_rows_word(len(rows))}{cut}; {matched}; shown {len(out)} (the rows holding the "
                     f"most of the finding's values and words); {len(rows) - len(out)} not shown: the "
                     "evaluator's room")
        lines += [out[i] for i in sorted(out)]
    if not lines:
        return "(no call cited)"
    tool_calls = [e for e in getattr(log, "_entries", []) if isinstance(e, dict) and e.get("type") == "tool_call"]
    check = shown_values(finding_text, cited, hosts=hosts, host=host, case_dir=case_dir,
                         tool_calls=tool_calls, supporting_evidence=evidence or "")
    # What no cited row holds at all. The CONFIRMED check is stricter (a time
    # only in a row with the finding's values, an entity by its type's rule:
    # an address followed by a port is no match there); this line names only
    # what no row holds even as text, so it never denies a row the evaluator
    # sees. Known limit, the same way: a short value inside a longer one
    # (10.0.0.1 inside 10.0.0.12) is held as text and goes unnamed here,
    # while the CONFIRMED check still counts it unshown.
    unshown = [v for v in check["unshown"]
               if (v[3:] not in times_seen if v.startswith("ts:")
                   else v.startswith("quote:") or not any(v.partition(":")[2] in r for r in all_rows))]
    if unshown:
        lines.append("Atlas's matcher found no cited row holding: "
                     + "; ".join(("event id " if v.startswith("eid:") else "") + v.partition(":")[2]
                                 for v in unshown))
    for sentence in check["unsupported"][:2]:
        lines.append(f"Atlas found no complete cited search for: '{_visible(sentence[:160])}'")
    low = finding_text.casefold()
    advisory = []
    for n in sorted(names - names_seen):
        k = low.find(n)
        if k >= 0 and not _PROSE_HYPHEN_RE.fullmatch(finding_text[k:k + len(n)]):
            advisory.append(finding_text[k:k + len(n)])
    if advisory:
        lines.append("Names not matched in any cited row (advisory): " + "; ".join(advisory[:8]))
    return "\n".join(lines)


def showing_call(value: str, tool_calls: list[dict], *, case_dir=None) -> int:
    """The newest evidence call of the trace whose row shows ``value`` (an
    entity as claim_terms names it, or "quote:<words>"), 0 when none does:
    the call to cite for it."""
    kind, _, text = value.partition(":")
    for entry in reversed(evidence_calls(tool_calls)):
        if entry.get("success") is False or not has_output(entry):
            continue
        rows, eid_rows = call_view(entry)
        if kind == "quote":
            if quote_rows([text], rows):
                return int(entry.get("call_id") or 0)
            continue
        excluded, _hosts = _read_paths(entry, case_dir)
        if value in excluded:
            continue
        if any(_entity_in_row(value, row, eid_rows.get(i)) for i, row in enumerate(rows)):
            return int(entry.get("call_id") or 0)
    return 0


def _active_case_dir() -> str:
    """The case directory the execution log is writing, or ""."""
    try:
        from core.execution_log import log
        return str(log.case_dir() or "")
    except Exception:  # noqa: BLE001
        return ""


def _active_trace_dir() -> str:
    """The directory of the trace the execution log is writing, or "": it
    names the case without touching the disk."""
    try:
        from core.execution_log import log
        return str(log.trace_dir() or "")
    except Exception:  # noqa: BLE001
        return ""


def _active_case_hosts() -> list[str]:
    """The hosts of the case the execution log is writing, or none."""
    from core.forensic_citation import known_case_hosts
    return known_case_hosts(_active_case_dir() or None)


def citation_supports(statement: str, cited: list[dict], *, tool_calls: list[dict],
                      supporting_evidence: str = "", host: str = "", hosts=()) -> Optional[bool]:
    """Whether the cited calls support ``statement``.

    For a positive claim, True when a cited evidence call shows it by the
    row test (call_shows: a strong entity of the claim in one printed row,
    with one of the claim's minute times when it states any); None when the
    claim names nothing checkable, or when its cited calls left no output;
    False otherwise, a claim citing only outside lookups included. A
    statement the absence grammar flags is judged by rows first too, and by
    the absence branch only when no cited row shows it: True when a cited
    evidence call is the complete search
    that grounds it (absence_searches); False when its cited calls are cut
    short, about something else, or not evidence at all; None when the
    searches it cites left no recorded output to judge against. With
    ATLAS_CITATION_ROWS off the anchor test decides. Without
    ``hosts``, claim_terms reads the active case's hosts.
    """
    from core.evidence_resolver import _claim_anchors, _shares_anchor
    evidence = evidence_calls(cited)
    shown = [e for e in evidence if has_output(e)]
    node = {"statement": statement or ""}
    absence = is_absence_claim(statement)
    if _rows_on():
        # Rows first, then the absence branch: a statement the universal or
        # negative grammar flags is often a positive claim with a caveat
        # ("x.exe ran on CORP-WS01; no persistence was found"), and its rows
        # show the positive part.
        terms = claim_terms(statement, hosts, host=host)
        checkable = bool(terms["strong"]) or bool(terms["names"] and terms["times"])
        if checkable and any(call_shows(terms, e) for e in shown):
            return True
        if not absence:
            if not checkable:
                return None
            if not shown:
                from core.forensic_citation import external_lookup_entry
                return False if any(external_lookup_entry(e) and has_output(e) for e in cited) else None
            return False
    elif shown and _shares_anchor(" ".join(call_output_text(e) for e in shown),
                                  _claim_anchors(node)):
        return True
    if absence:
        # An absence demands its search, whether or not the claim names
        # identifiers. One whose citations are all the run's own words rests
        # on itself; one whose cited searches left no recorded output, or
        # that cites nothing at all, cannot be judged here, as for any claim.
        if absence_searches(statement, shown, tool_calls=tool_calls,
                            supporting_evidence=supporting_evidence):
            return True
        if not cited:
            return None      # nothing cited: lineage_required's question, not this one
        if not evidence:
            return False     # only the run's own words cited: no search behind it
        return None if not shown else False
    if not shown:
        # Lookups printed output, all of it restating what they were asked:
        # the claim's identifiers are unshown, not unjudgeable.
        from core.forensic_citation import external_lookup_entry
        if (any(external_lookup_entry(e) and has_output(e) for e in cited)
                and _claim_anchors(node, demanding=True)):
            return False
        return None
    if not _claim_anchors(node, demanding=True):
        return True
    return False


def calls_showing(statement: str, tool_calls: list[dict], *, exclude=(),
                  complete_only: bool = False, limit: int = 3,
                  supporting_evidence: str = "") -> list[dict]:
    """The calls in the trace that would support ``statement`` if cited,
    each ``{"call_id", "why"}``: for an absence claim the searches of its
    sources first, then for any claim the calls whose output shows its
    identifiers, newest first within each group. With ``complete_only`` a
    call the analyst saw only part of is left out - a universal or negative
    statement cannot rest on it (universal_from_truncated), so suggesting
    it sends the analyst into that refusal.
    """
    from core.entities import artifact_tokens
    from core.evidence_resolver import _claim_anchors
    from .lineage_relevance import entry_text
    skip = {int(c) for c in exclude if c is not None}
    pool = [e for e in evidence_calls(tool_calls[-300:])
            if e.get("success") is not False and has_output(e)
            and int(e.get("call_id") or 0) not in skip
            and not (complete_only and not complete_view(e))]
    out: list[dict] = []
    seen: set[int] = set()

    def _add(e: dict, why: str) -> bool:
        cid = int(e.get("call_id") or 0)
        if cid in seen:
            return False
        seen.add(cid)
        out.append({"call_id": cid, "why": why})
        return len(out) >= limit

    if is_absence_claim(statement):
        grounding = absence_grounding(statement, supporting_evidence, tool_calls)
        if grounding:
            what = grounding["category"].lower().replace("_", "/")
            for e in reversed(searches_of(grounding, pool, statement or "", _active_case_dir() or None)):
                if _add(e, f"searched the {what} sources"):
                    return out
        described = artifact_tokens(f"{statement} {supporting_evidence or ''}")
        if described:
            for e in reversed(pool):
                shared = described & artifact_tokens(entry_text(e))
                if shared and _add(e, "read " + ", ".join(sorted(shared)[:3])):
                    return out
    anchors = _claim_anchors({"statement": statement or ""})
    if not anchors:
        return out
    for e in reversed(pool):
        low = call_output_text(e).lower()
        shared = sorted(a for a in anchors if a in low)
        if shared and _add(e, "shows " + ", ".join(shared[:5])):
            break
    return out
