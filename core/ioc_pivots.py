"""IOC pivot ledger — every new indicator re-opens the evidence.

The problem this exists to solve
================================
An investigation that finds a new indicator half-way through has, at that
moment, *already looked at* most of its evidence — but it looked with older
questions. A username discovered in a registry hive at turn 40 was not a
search term when the event logs were triaged at turn 12. Nothing in the loop
noticed, so the run closed with the indicator never carried back across the
material that could corroborate it.

The rule this module encodes is deliberately general — it is not a per-case
script, and it names no case principal, host or filename:

    every indicator that appears in a belief must be searched for in every
    *relevant, available* evidence source, and stays an open obligation
    until it has been.

Relevance is computed, not written down per case: an indicator's **type**
(from ``core.entities``) is crossed with an evidence source's **class**
(derived from its own path). A new external IP re-opens the network logs; a
new account re-opens the event logs, registry hives and auth logs; a new
host re-opens *other* hosts' material, which is what makes cross-host
correlation happen at all. Whatever evidence a case actually has is what
gets re-searched — nothing more, nothing less.

Storage: ``<case>/.atlas/ioc_pivots.json``. Open pivots are surfaced as
investigation obligations (they block ``complete``) and as a loop nudge
listing the concrete searches still owed, so the model does the work rather
than being told it failed at the end.

A source that cannot be examined is not owed a search. That verdict is the
coverage ledger's (``coverage.mark_blocked``, after a real attempt, with the
reason); the pivot ledger reads it on every refresh rather than keeping a
second verb for the same fact.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Iterable

SCHEMA_VERSION = "1.0"

# Caps keep the (indicator x source) matrix bounded on estate-sized cases.
# Both are generous relative to a real case and exist only so a pathological
# trace cannot explode the ledger.
MAX_PIVOTS = 40
MAX_TARGETS_PER_PIVOT = 12

# The origin of an indicator the analyst named in CASE.md.
from core.case_knowledge import ORIGIN as _ANALYST_ORIGIN  # noqa: E402

# ── evidence source classes ──────────────────────────────────────────────
#
# Classified from the source's own path, so a case gets the classes its
# evidence actually warrants. A source may hold several classes (an
# EvtxECmd CSV is both eventlog and tabular). Each class has a structural
# pattern (extensions, fixed file and directory names, $-prefixed NTFS
# files) and words that must be a whole part of the path, split at / _ - .
# and spaces with camelCase kept whole: "ProfileList" is not a file list,
# "FileList" is.
_CLASS_PATTERNS: tuple[tuple[str, re.Pattern[str], frozenset[str]], ...] = (
    ("eventlog", re.compile(r"(?i)(\.evtx$|\.evt$|/winevt/)"),
     frozenset({"evtxecmd", "evtexport", "hayabusa", "chainsaw", "evtx", "eventlog",
                "eventlogs"})),
    ("network", re.compile(r"(?i)(conn\.log|\.pcap(ng)?$)"),
     frozenset({"firewall", "fw", "fwlog", "proxy", "squid", "dns", "netflow", "zeek",
                "suricata", "traffic", "vpn", "pcap", "pcapng"})),
    ("registry", re.compile(
        r"(?i)(ntuser\.dat|usrclass\.dat|/system$|/software$|/sam$|/security$|\.hve$)"),
     frozenset({"regripper", "recmd", "amcache", "shimcache", "syscache"})),
    ("filesystem", re.compile(r"(?i)(\$mft|\$usnjrnl|\$logfile|\.pf$)"),
     frozenset({"usnjrnl", "bodyfile", "mactime", "fls", "filelist", "prefetch", "lnk",
                "jumplist", "jumplists", "srum", "mft", "mftecmd"})),
    ("auth", re.compile(r"(?i)(auth\.log|secure$|wtmp|btmp|lastlog|sudo\.log)"),
     frozenset({"sshd", "login", "logins", "logon", "logons", "auth"})),
    # Every segment of a split image is a container: EnCase .E01-.E99 and
    # .Ex01-.Ex99, SMART .s01-.s99. A raw split (.001) is left out: a
    # rotated log has the same shape.
    ("disk", re.compile(r"(?i)\.(vmdk|e\d\d|ex\d\d|s\d\d|aff4?|vhdx?|dd|raw|img|bin)$"),
     frozenset()),
    # A super-timeline merges every source: relevant to every indicator.
    ("timeline", re.compile(r"(?!)"),
     frozenset({"plaso", "psort", "l2t", "supertimeline", "timeline"})),
)
_NAME_PART_SPLIT = re.compile(r"[/_\-.\s]+")

# Indicator type -> evidence classes worth re-searching for it. The left
# side is core.entities' vocabulary; the right side is the class vocabulary
# above. This is the one policy table in the module, and it is about
# *forensic kinds*, not about any particular case.
_RELEVANCE: dict[str, tuple[str, ...]] = {
    "ip": ("network", "eventlog", "auth", "timeline", "generic"),
    "url": ("network", "eventlog", "timeline", "generic"),
    "domain": ("network", "eventlog", "timeline", "generic"),
    "email": ("network", "timeline", "generic"),
    "account": ("eventlog", "registry", "auth", "filesystem", "timeline", "generic"),
    "user": ("eventlog", "registry", "auth", "filesystem", "timeline", "generic"),
    "host": ("eventlog", "network", "auth", "registry", "timeline", "generic"),
    "file": ("filesystem", "eventlog", "registry", "timeline", "generic"),
    "path": ("filesystem", "eventlog", "registry", "timeline", "generic"),
    "reg": ("registry", "eventlog", "timeline", "generic"),
    "md5": ("filesystem", "timeline", "generic"),
    "sha1": ("filesystem", "timeline", "generic"),
    "sha256": ("filesystem", "timeline", "generic"),
}

# A derived table (under analysis/ or exports/) that no class fits is owed a
# search for an indicator only when it holds one of the indicator's search
# terms (_table_holds): a table of unknown content may hold anything, but a
# parser's many per-key tables must not each become a search every
# indicator owes. The check is the literal search the model would run, on
# the model's own indicator; it decides which tables the model is sent to,
# never what a search found.
from core.indicators import _FILE_TERMS as _TABLE_TERMS  # noqa: E402  (one cache for the byte scan)

# Indicator types that are never worth pivoting on: too generic to narrow a
# search, or an artifact of prose rather than an indicator.
_NON_PIVOT_TYPES = frozenset({"ts", "cve", "technique", "flag", "hex"})

# A raw disk image is a *container*, not something you grep for an
# indicator — its contents become sources once extracted.
_CONTAINER_CLASSES = frozenset({"disk"})

_LOOPBACK_IP_RE = re.compile(r"^(?:0\.|127\.|255\.)")
# Multicast, link-local and broadcast addresses: every capture carries them,
# none is anyone's infrastructure. Nor is an address of the form a.0.0.0: a
# /8 network identifier names no endpoint (and is the shape of a version
# string, "15.0.0.0").
_NON_ROUTABLE_IP_RE = re.compile(r"^(?:169\.254\.|22[4-9]\.|23\d\.)|\.255$|\.0\.0\.0$")
# RFC 1918 space: an address that recurs unrecorded matters more when it is
# not the site's own.
_PRIVATE_IP_RE = re.compile(r"^(?:10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)")

# Atlas's own record of what Atlas did. Never a pivot target: an indicator
# appears in the trace *because the run wrote it there*, so "search the
# transcript for 203.0.113.44" is circular — and worse, observe_search would
# close the pivot the moment the trace mentioned both, marking work done
# that was never done.
from core.entities import is_format_namespace_url
from core.evidence_catalog import is_atlas_output


def pivots_path(case_dir: str | os.PathLike) -> Path:
    return Path(case_dir) / ".atlas" / "ioc_pivots.json"


def empty_ledger() -> dict[str, Any]:
    return {"schema_version": SCHEMA_VERSION, "pivots": {}}


def load_pivots(case_dir: str | os.PathLike) -> dict[str, Any]:
    p = pivots_path(case_dir)
    if not p.is_file():
        return empty_ledger()
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return empty_ledger()
    if not isinstance(data, dict):
        return empty_ledger()
    data.setdefault("pivots", {})
    return data


def save_pivots(case_dir: str | os.PathLike, ledger: dict[str, Any]) -> Path:
    p = pivots_path(case_dir)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(ledger, indent=2, ensure_ascii=False) + "\n",
                   encoding="utf-8")
    os.replace(tmp, p)
    return p


# ── classification ───────────────────────────────────────────────────────

def source_classes(rel_path: str) -> set[str]:
    """Forensic classes a source belongs to, from its path alone."""
    norm = str(rel_path or "").replace("\\", "/")
    parts = set(_NAME_PART_SPLIT.split(norm.lower()))
    found = {name for name, pat, words in _CLASS_PATTERNS
             if pat.search(norm) or parts & words}
    if not found:
        found.add("generic")
    return found


def _derived(rel_path: str) -> bool:
    top = str(rel_path or "").replace("\\", "/").lstrip("./").split("/", 1)[0].lower()
    return top in ("analysis", "exports")


def ioc_type(ioc: str) -> str:
    return str(ioc or "").split(":", 1)[0]


def ioc_value(ioc: str) -> str:
    return str(ioc or "").split(":", 1)[1] if ":" in str(ioc or "") else ""


def _search_terms(ioc: str) -> list[str]:
    """Concrete strings a search for this indicator would contain.

    An ``account:corp/jdoe`` is searched for as ``jdoe`` (and as the full
    pair); a path or a registry key is searched for by its last component as
    well as in full, because that is how an analyst actually greps, and the
    last component reads the same whichever separator a record writes (the
    ledger keeps forward slashes, a Windows record backslashes). The last
    component comes last; the pivot nudge prints it (``pattern_term``).
    """
    kind, value = ioc_type(ioc), ioc_value(ioc)
    if not value:
        return []
    terms = [value]
    if kind == "account" and "/" in value:
        terms.append(value.split("/", 1)[1])
    if kind in ("path", "reg"):
        base = re.split(r"[\\/]+", value.rstrip("\\/"))[-1]
        if base and base != value:
            terms.append(base)
    elif kind == "url" and "/" in value:
        base = value.rstrip("/").rsplit("/", 1)[-1]
        if base:
            terms.append(base)
    return [t for t in terms if len(t) >= 3 and not _UNSEARCHABLE_RE.search(t)]


# A term no search could contain: a control character (a tab or a newline
# that reached the value unescaped), or the text escape of one before a
# capitalised word ("\tOperator"). A space or a lowercase "\temp" in a
# path is searchable.
_UNSEARCHABLE_RE = re.compile(r"[\x00-\x1f\x7f]|\\[tnr](?=[A-Z])")


def _is_pivotable(ioc: str) -> bool:
    kind, value = ioc_type(ioc), ioc_value(ioc)
    if kind in _NON_PIVOT_TYPES or not value:
        return False
    if not _search_terms(ioc):
        return False
    if kind not in _RELEVANCE:
        return False
    if kind == "ip" and (_LOOPBACK_IP_RE.match(value) or _NON_ROUTABLE_IP_RE.search(value)):
        return False
    # Single characters and ultra-common tokens make useless search terms.
    return len(value) >= 3


# ── inputs: indicators from beliefs, sources from the case ───────────────

def case_file_names(case_dir: str | os.PathLike) -> set[str]:
    """Basenames of the case's own files: evidence, exports, analysis."""
    names: set[str] = set()
    try:
        from core.evidence_catalog import iter_case_files
        for rel, _abs in iter_case_files(case_dir):
            names.add(rel.rsplit("/", 1)[-1].casefold())
    except Exception:  # noqa: BLE001
        pass
    return names


def _url_key(value: str) -> str:
    """A URL stripped of what cannot end one.

    The same link reaches the extractor with trailing escape and punctuation
    characters from the JSON it was read out of, so the published form and
    the extracted form are the same URL spelled differently.
    """
    return str(value or "").casefold().rstrip("\\\"',.;:)]}> \t")


def own_tool_urls(case_dir: str | os.PathLike | None) -> set[str]:
    """URLs Atlas emitted about itself, which are not evidence about the case.

    Atlas writes its own dashboard link into the case's trace, so the link
    recurs across calls and ranks as a high-signal indicator — the top one on
    a real run, ahead of anything the evidence actually contains. The gate
    then refuses to report until a finding names it, and no finding ever can:
    it says nothing about the case.

    Read from the record Atlas already keeps of that URL rather than matched
    by shape. A loopback address is not per se uninteresting — a web server
    configuration on a seized disk may genuinely reference one — so only the
    address Atlas itself published is dropped.
    """
    if not case_dir:
        return set()
    urls: set[str] = set()

    try:
        marker = Path(case_dir) / "analysis" / "dashboard.url"
        if marker.is_file():
            for line in marker.read_text(encoding="utf-8",
                                         errors="ignore").splitlines():
                line = line.strip()
                if line.lower().startswith(("http://", "https://")):
                    urls.add(_url_key(line))
    except Exception:  # noqa: BLE001
        pass
    return urls


def _ioc_key(value: str) -> str:
    """Comparable form of an indicator: lower-cased last path/domain segment,
    so ``EXAMPLE\\tempadmin`` meets the catalog's ``tempadmin`` and
    ``C:\\Users\\x\\evil.exe`` meets ``evil.exe``."""
    v = str(value or "").casefold().replace("\\", "/").rstrip("/")
    return v.rsplit("/", 1)[-1] or v


def _format_namespace(ent: str) -> bool:
    """A URL a namespace authority publishes as a document-format
    identifier: in every document of the format, so the evidence scan never
    demands a ruling on it. Only the scan asks; a belief that names one is
    the analyst's explicit statement and is read like any other."""
    return ioc_type(ent) == "url" and is_format_namespace_url(ioc_value(ent))


def indicators_from_beliefs(case_dir: str | os.PathLike) -> dict[str, str]:
    """Pivotable indicators mentioned by recorded beliefs.

    Returns ``{ioc: origin}`` where origin is the claim id it first appeared
    in — used only to explain *why* a pivot exists.

    Only what the IOC catalog attributes to attacker activity is a pivot.
    Beliefs come from findings alone: a disposition (a narration entry
    recording a search that found nothing) never reaches the claim graph,
    so writing down a clean miss cannot open the pivot it closed.
    Extracting every entity from every statement turned the case's own
    file names (``dc-01.vmdk``, ``dc-01_mft.csv``), the exporter's
    ``svchost.exe`` and a ``host:windows`` parsed out of a path into
    indicators, and the run then spent a batch every few turns searching
    all sources for them and recording "not found" findings.
    """
    from core.entities import domains_in, extract

    out: dict[str, str] = {}
    own = case_file_names(case_dir)

    def _is_case_file(ent: str) -> bool:
        kind, value = ioc_type(ent), ioc_value(ent)
        if kind not in ("file", "path"):
            return False
        base = value.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1].casefold()
        return base in own


    try:
        from core.ioc_catalog import build_catalog
        cat = build_catalog(case_dir)
        # A search obligation is internal work, not a deliverable: a value
        # the prose attributes to the attacker is searched for even before
        # the analyst types it. The owner's own assets are not: they are
        # affected assets, and searching every source for the file server's
        # own address is the flood this set exists to stop.
        # The sighted catalogue lists a value no call shows yet as context:
        # it is still searched for, so the seeds do not shrink.
        # A value the prose names with no side (the neutral frame: no
        # owner, so no verb makes it the attacker's) is attributed to
        # nobody and seeds no search either.
        attributed = {_ioc_key(str(i.get("value") or ""))
                      for i in list(cat.get("iocs") or []) + list(cat.get("review") or [])
                      + list(cat.get("context") or [])
                      if isinstance(i, dict) and i.get("side") != "victim"
                      and not (i.get("source") == "prose" and i.get("side") == "undetermined")}
    except Exception:  # noqa: BLE001
        attributed = set()
    # The catalog is the one definition of "attacker indicator". Falling back
    # to every entity in every belief while the catalog was still empty
    # opened pivots on a firewall's own management address and on encrypted
    # victim documents — nothing to pivot on is the right answer when
    # nothing is attributed yet.
    if not attributed:
        return out
    try:
        from core.claim_graph import load_graph
        graph = load_graph(case_dir)
        for node in (graph.get("nodes") or {}).values():
            if not isinstance(node, dict) or node.get("status") in ("superseded", "withdrawn"):
                continue
            statement = str(node.get("statement") or "")
            # Sites come from the opt-in reader: extract() has no domain type.
            ents = list(extract(statement)) + [f"domain:{d}" for d in sorted(domains_in(statement))]
            for ent in ents:
                if (_is_pivotable(ent) and ent not in out and not _is_case_file(ent)
                        and _ioc_key(ioc_value(ent)) in attributed):
                    out[ent] = str(node.get("id") or "claim")
    except Exception:  # noqa: BLE001
        pass
    return out


# Ranking weight for an indicator the run has seen but not recorded. External
# network/identity indicators outrank internal IPs, which recur as ordinary
# infrastructure noise.
_INDICATOR_WEIGHT = {"url": 5, "domain": 5, "email": 5, "account": 4, "user": 4,
                     "md5": 3, "sha1": 3, "sha256": 3, "file": 2, "ip": 1}


def _indicator_weight(kind: str, value: str) -> int:
    if kind == "ip" and not _PRIVATE_IP_RE.match(value):
        return 3  # an outside address the analyst never named: a C2 shape
    return _INDICATOR_WEIGHT.get(kind, 0)


# The executor keeps each call's whole stdout on disk while the model sees a
# capped excerpt; a beacon that starts late in a large capture summary is in
# the file and in no excerpt. The full entity extractor is minutes on a file
# that size, so the file is swept with three narrow patterns for the kinds
# that survive truncation (addresses, URLs, mail addresses) and only the
# unique matches go through the extractor. Scanned once per file.
_SPILL_SCAN_CAP = 32 * 1024 * 1024
_SPILL_TOKEN_RES = (
    # Not the head of a longer dotted run (an OID, a version string); one
    # trailing port part stays an address, as core.entities reads it.
    re.compile(rb"(?<!\d\.)\b(?:\d{1,3}\.){3}\d{1,3}\b(?!\.\d{1,5}\.\d)(?!\.\d{6})"),
    # A backslash is no URL character: in a JSON spill an escaped quote
    # follows the link, and a token that keeps the backslash names a URL no
    # finding can ever match.
    re.compile(rb"https?://[^\s'\"<>\\]{4,200}", re.I),
    re.compile(rb"[\w.+-]{1,64}@[\w-]{1,63}(?:\.[\w-]{1,63})+"),
)
_spill_cache: dict[tuple, frozenset] = {}


_SPILL_HEAD_BYTES = 64 * 1024


def _spilled_entities(path: str, entry: dict | None = None, rows: str | None = None,
                      drop: frozenset | None = None) -> frozenset:
    """Discriminative network and identity entities in a retained full tool
    output. With the call's ``entry``, the head of a JSON spill (before its
    first nested container) loses the request fields and the alternatives
    object first, through the one echo-free reader's rule, so an echoed
    pattern recurring in three search spills is not read as evidence. With
    ``rows`` (the spill's rows, core.indicators.rows_text) those are swept
    instead of the file's bytes, by the same three patterns. ``drop``: the
    tool's own lines (own_text_lines), left out before the sweep."""
    try:
        st = os.stat(path)
    except OSError:
        return frozenset()
    key = (path, st.st_size, st.st_mtime_ns, (entry or {}).get("call_id"), rows is not None,
           hash(drop) if drop else 0)
    hit = _spill_cache.get(key)
    if hit is not None:
        return hit
    from core.entities import discriminative, extract
    if rows is not None:
        data = _without_lines(rows, drop).encode("utf-8", "replace")
    else:
        try:
            with open(path, "rb") as f:
                data = f.read(_SPILL_SCAN_CAP)
        except OSError:
            return frozenset()
        if drop:
            data = _without_lines(data.decode("utf-8", "replace"), drop).encode("utf-8", "replace")
    if rows is None and entry and data.lstrip()[:1] == b"{":
        from core.indicators import _argument_keys, _without_echo_fields, request_strings
        head = data[:_SPILL_HEAD_BYTES].decode("utf-8", "replace")
        stripped = _without_echo_fields(head, request_strings(entry), _argument_keys(entry))
        data = stripped.encode("utf-8", "replace") + data[_SPILL_HEAD_BYTES:]
    tokens: set[bytes] = set()
    for rx in _SPILL_TOKEN_RES:
        tokens.update(rx.findall(data))
        if len(tokens) > 20000:
            break
    text = " ".join(t.decode("utf-8", "replace") for t in tokens)
    ents = frozenset(discriminative(extract(text)))
    if len(_spill_cache) > 512:
        _spill_cache.clear()
    _spill_cache[key] = ents
    return ents


def _without_lines(text: str, drop: frozenset | None) -> str:
    """``text`` less the lines whose stripped form is in ``drop``."""
    if not drop:
        return text
    return "\n".join(ln for ln in text.splitlines() if ln.strip() not in drop)


# The first and last lines of a retained output, by file version: what
# own_text_lines compares across a tool's outputs. ponytail: a small dict
# cleared when full, like _SEEN_MEMO.
_LINES_CACHE: dict[tuple, tuple[list[str], list[str]]] = {}
_EDGE_LINES = 64


def _output_lines(entry: dict) -> tuple[list[str], list[str]]:
    """(head, tail) of a call's output as stripped lines, at most _EDGE_LINES
    each: the retained file when the scan takes it whole (SPILL_READ_CHARS),
    else the excerpt. A short output's head and tail overlap."""
    from core.indicators import SPILL_READ_CHARS
    spill = str(entry.get("stdout_file") or "")
    if spill:
        try:
            st = os.stat(spill)
            key = (spill, st.st_size, st.st_mtime_ns)
            hit = _LINES_CACHE.get(key)
            if hit is not None:
                return hit
            if st.st_size <= SPILL_READ_CHARS:
                with open(spill, "rb") as f:
                    lines = [ln.strip() for ln in f.read(SPILL_READ_CHARS).decode("utf-8", "replace").splitlines()]
                out = (lines[:_EDGE_LINES], lines[-_EDGE_LINES:])
                if len(_LINES_CACHE) > 512:
                    _LINES_CACHE.clear()
                _LINES_CACHE[key] = out
                return out
        except OSError:
            pass
    lines = [ln.strip() for ln in str(entry.get("stdout_excerpt") or "").splitlines()]
    return lines[:_EDGE_LINES], lines[-_EDGE_LINES:]


def own_text_lines(entries, *, min_outputs: int = 3) -> dict:
    """{call id: the lines that are the tool's own text}. A tool that
    printed at least ``min_outputs`` successful outputs over at least two
    distinct requests has own text in its head block (the lines from the
    start of every output that agree, up to the first that differs) and
    its tail block (the same from the end): a banner, a trailer with the
    tool's name and links. A record line never sits there in every output
    of different inputs; a block that covers a whole output tells banner
    from data by nothing and is not taken. The request echo is not this
    rule's business (core.indicators.rows_text takes it out). ponytail: a
    value only one tool ever prints, at a fixed place in each of its
    outputs, is taken as that tool's text; _seen_by_calls restores a value
    another tool's rows corroborate."""
    from core.coverage_ledger import _entry_tool
    from core.forensic_citation import own_words_entry
    from core.indicators import request_strings
    by_tool: dict[str, list[dict]] = {}
    for e in entries or []:
        if not isinstance(e, dict) or e.get("type") != "tool_call" or e.get("success") is False \
                or own_words_entry(e):
            continue
        cmd = str(e.get("cmd") or "")
        name = _entry_tool(e) or str(e.get("mcp_tool") or "") or (cmd.split() or ["?"])[0]
        by_tool.setdefault(name, []).append(e)
    out: dict = {}
    for calls in by_tool.values():
        if len(calls) < min_outputs or len({request_strings(e) for e in calls}) < 2:
            continue
        edges = [_output_lines(e) for e in calls]
        if any(not head for head, _tail in edges):
            continue
        shortest = min(min(len(head), len(tail)) for head, tail in edges)
        head_block: list[str] = []
        for i in range(shortest):
            line = edges[0][0][i]
            if line and all(h[i] == line for h, _t in edges[1:]):
                head_block.append(line)
            else:
                break
        tail_block: list[str] = []
        for i in range(1, shortest + 1):
            line = edges[0][1][-i]
            if line and all(t[-i] == line for _h, t in edges[1:]):
                tail_block.append(line)
            else:
                break
        if len(head_block) + len(tail_block) >= shortest:
            # The blocks meet: at least one output would be own text
            # throughout, which tells banner from data by nothing.
            continue
        own = set(head_block) | set(tail_block)
        if own:
            for e in calls:
                out[e.get("call_id")] = frozenset(own)
    return out


# Commands whose output is a listing of what is on a disk. What they print
# are names, never traffic: a folder called 1.0.0.1 is a module version,
# and it recurs in every listing of every image. Only files and paths are
# read from them.
LISTING_TOOLS = frozenset({
    "fls", "ls", "find", "tree", "dir", "mmls", "fsstat", "istat", "ils",
    "ffind", "ifind",
})


def _lists_names(cmd: str) -> bool:
    first = (cmd or "").split(None, 1)[:1]
    return bool(first) and os.path.basename(first[0]) in LISTING_TOOLS


# The scan's per-call extraction, by case and by a digest of its tool calls
# (id, outcome, spill, excerpt length and head): the blocker, the knowledge
# index and the report's Limitations read the same trace version several
# times. ponytail: a small dict cleared when full.
_SEEN_MEMO: dict[tuple, dict[str, set]] = {}


def _seen_by_calls(entries, case_dir=None) -> dict[str, set]:
    """{entity: the distinct tool call ids whose printed rows hold it}: the
    rows only, never the command line nor a tool's own banner or trailer
    lines (own_text_lines); no case file, own tool URL, own container digest
    or document-format namespace; a URL cut short beside its whole in the
    same call left out. Read once per trace version."""
    from collections import defaultdict

    from core.entities import discriminative, extract, scan_text
    from core.forensic_citation import own_words_entry

    import hashlib
    rows = [e for e in entries or [] if isinstance(e, dict)]
    sig = hashlib.sha1("\x1f".join(
        f"{e.get('call_id')}|{e.get('success')}|{e.get('stdout_file') or ''}|"
        f"{len(str(e.get('stdout_excerpt') or ''))}|{str(e.get('stdout_excerpt') or '')[:64]}"
        for e in rows if e.get("type") == "tool_call").encode("utf-8", "replace")).hexdigest()
    # What the scan also reads of the case (its container digests from the
    # mount plan and the catalog) may change while the trace does not.
    stamps: tuple = ()
    if case_dir:
        from core.evidence_catalog import catalog_path
        from core.mount_plan import mount_plan_path
        for path in (mount_plan_path(case_dir), catalog_path(case_dir)):
            try:
                stamps += (os.stat(path).st_mtime_ns,)
            except OSError:
                stamps += (0,)
    key = (str(case_dir or ""), sig, stamps)
    hit = _SEEN_MEMO.get(key)
    if hit is not None:
        return hit
    own = case_file_names(case_dir) if case_dir else set()
    own_urls = own_tool_urls(case_dir)
    own_digests = _container_digests(case_dir) if case_dir else set()
    # A tool's own banner and trailer lines are no evidence, however many
    # outputs repeat them (own_text_lines).
    own_lines = own_text_lines(rows)

    def _is_case_file(ent: str) -> bool:
        kind, value = ioc_type(ent), ioc_value(ent)
        if kind not in ("file", "path"):
            return False
        base = value.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1].casefold()
        return base in own

    from core.coverage_ledger import _entry_tool
    seen: dict[str, set] = defaultdict(set)
    tools_of: dict[str, set] = {}
    from_own: dict[str, set] = {}
    for e in rows:
        if e.get("type") != "tool_call" or e.get("success") is False or own_words_entry(e):
            continue
        # The rows the call printed, never its header: a result set's
        # counts and notes are Atlas's own words about the result
        # (core.indicators.rows_text), however often they recur.
        from core.indicators import SPILL_READ_CHARS, rows_text
        drop = own_lines.get(e.get("call_id"))
        shown = _without_lines(rows_text(e, text=str(e.get("stdout_excerpt") or ""), windowed=True), drop)
        ents = discriminative(extract(scan_text(shown)))
        spill = str(e.get("stdout_file") or "")
        if spill:
            try:
                whole = os.path.getsize(spill) <= SPILL_READ_CHARS
            except OSError:
                whole = False
            # A spill the reader takes whole is swept over its rows; a
            # larger one by bytes, its head stripped of the request.
            ents |= _spilled_entities(spill, e, rows_text(e) if whole else None, drop=drop)
        if _lists_names(str(e.get("cmd") or "")):
            ents = {x for x in ents if ioc_type(x) in ("file", "path")}
        for ent in _without_cut_urls(ents):
            if (_is_pivotable(ent) and not _is_case_file(ent)
                    and _url_key(ioc_value(ent)) not in own_urls
                    and ioc_value(ent).casefold() not in own_digests
                    and not _format_namespace(ent)):
                seen[ent].add(e.get("call_id"))
                tools_of.setdefault(ent, set()).add(_entry_tool(e) or str(e.get("mcp_tool") or ""))
        if drop:
            # What the dropped lines held, kept apart: a value another tool's
            # rows corroborate is evidence after all (restored below).
            own_ents = discriminative(extract(scan_text("\n".join(sorted(drop)))))
            for ent in _without_cut_urls(own_ents):
                if _is_pivotable(ent) and not _is_case_file(ent):
                    from_own.setdefault(ent, set()).add((e.get("call_id"), _entry_tool(e) or str(e.get("mcp_tool") or "")))
    for ent, calls in from_own.items():
        tools = {t for _c, t in calls}
        if seen.get(ent) and (tools_of.get(ent, set()) - tools):
            seen[ent].update(c for c, _t in calls)
    if len(_SEEN_MEMO) > 32:
        _SEEN_MEMO.clear()
    _SEEN_MEMO[key] = dict(seen)
    return _SEEN_MEMO[key]


def _rulings(entries, case_dir=None, *, dispositions: bool = True) -> tuple[set[str], str]:
    """The entities the run's rulings name and their text, casefolded: every
    asserted finding (a withdrawn one is no ruling) and, with
    ``dispositions``, every disposition; plain narration is neither, or
    announcing a search would silence the demand for its result."""
    from core.claim_graph import asserted_finding_entries
    from core.entities import extract
    from core.execution_log import is_disposition
    rows = [e for e in entries or [] if isinstance(e, dict)]
    asserted = {id(f) for f in asserted_finding_entries([e for e in rows if e.get("type") == "finding"], case_dir)}
    recorded: set[str] = set()
    named: list[str] = []
    for e in rows:
        if (e.get("type") == "finding" and id(e) in asserted) or (dispositions and is_disposition(e)):
            desc = str(e.get("description") or e.get("content") or "")
            recorded.update(extract(desc))
            named.append(desc)
    return recorded, "\n".join(named).casefold()


def _named(ent: str, recorded: set[str], text: str) -> bool:
    """Whether a ruling names ``ent``: as the extractor reads it, or quoted
    as printed (an account is shown as domain/user, not as the DOMAIN\\user
    it was read from), so a demand is never met only by guessing the
    spelling."""
    if ent in recorded:
        return True
    # A URL written without its query, fragment or trailing slash names
    # the same resource; a deeper path does not.
    if ioc_type(ent) == "url":
        bare = re.split(r"[?#]", ioc_value(ent).casefold(), maxsplit=1)[0].rstrip("/")
        if bare and re.search(rf"(?<![\w.]){re.escape(bare)}(?![\w/-])(?!\.\w)", text):
            return True
    # A trailing dot ends a sentence as often as it continues a name, so
    # only a dot that carries on into another word disqualifies a match.
    return bool(text) and re.search(
        rf"(?<![\w.]){re.escape(ioc_value(ent).casefold())}(?!\w)(?!\.\w)", text) is not None


def unrecorded_evidence_indicators(entries, case_dir=None, *,
                                   min_calls: int = 3,
                                   limit: int | None = None,
                                   dispositions: bool = True) -> list[dict]:
    """Discriminative indicators that recur across the run's tool output but
    appear in no recorded finding or disposition.

    The pivot ledger above seeds from beliefs, so an indicator the analyst
    never wrote down never enters it. This is the reverse view — what the
    evidence keeps showing that the analyst has not recorded — the gap behind
    a run that reads a C2 domain or a compromised account dozens of times and
    reports without a finding about it.

    ``entries`` is the execution-log trace (tool_call and finding entries).
    Returns ``[{value, kind, calls}]`` ranked by indicator type then how many
    distinct successful tool calls surfaced it, each seen in at least
    ``min_calls`` distinct calls. This is the whole population; what a gate
    may ask for out of it is ``unrecorded_demand``'s decision.

    The rows are read, never the call's command line (the run's own words,
    as a result set's header is). The case's own container digests (an
    image's acquisition hash) are no indicator. A URL a longer URL of the
    same call's output continues inside its host is that URL cut short (a
    strings pass breaks a UTF-16 run). With ``dispositions`` False only
    findings count as rulings (ruled_out_without_finding).
    """
    seen = _seen_by_calls(entries, case_dir)
    recorded, text = _rulings(entries, case_dir, dispositions=dispositions)
    # How crowded a kind is has to be read off the evidence, not off what is
    # left to ask about: counting only the unrecorded would let a kind too
    # crowded to ask about become askable as the analyst rules on it, so
    # obeying the invitation to record the one that matters would turn the
    # rest into a demand.
    # A kind's population counts its demandable members and its members
    # below DEMAND_WEIGHT apart: fifteen private addresses must not make the
    # address kind dense and hide the one outside address it holds.
    population: dict[tuple[str, bool], int] = {}

    def _slot(ent: str) -> tuple[str, bool]:
        return ioc_type(ent), _indicator_weight(ioc_type(ent), ioc_value(ent)) >= DEMAND_WEIGHT
    for ent, cids in seen.items():
        if len(cids) >= min_calls:
            population[_slot(ent)] = population.get(_slot(ent), 0) + 1

    out = [{"value": ioc_value(ent), "kind": ioc_type(ent), "calls": len(cids),
            "kind_population": population.get(_slot(ent), 0)}
           for ent, cids in seen.items()
           if len(cids) >= min_calls and not _named(ent, recorded, text)]
    out.sort(key=lambda d: (_indicator_weight(d["kind"], d["value"]), d["calls"]),
             reverse=True)
    return out[:limit]


def _container_digests(case_dir) -> set[str]:
    """The digests of the case's own containers: an image's acquisition hashes
    and full preflight digest (the mount plan), and the catalog's full
    fingerprint of a disk or memory image (a container unit of the coverage
    ledger, or a path read as a disk image). A plain evidence file's digest
    is not among them: a sample supplied as evidence keeps its hash
    demanded."""
    out: set[str] = set()
    try:
        from core.mount_plan import load_mount_plan
        for img in load_mount_plan(case_dir).get("images") or []:
            pre = img.get("hash_preflight") if isinstance(img, dict) else None
            if isinstance(pre, dict):
                out |= {str(v).casefold() for v in (pre.get("acquisition_hashes") or {}).values() if v}
                if pre.get("full_hash") and pre.get("md5"):
                    out.add(str(pre["md5"]).casefold())
    except Exception:  # noqa: BLE001 - no plan, no image digests
        pass
    try:
        # A container is what the coverage ledger took in as one (a disk or a
        # memory image), else a path the classifier reads as a disk image.
        from core.coverage_ledger import CONTAINER_KIND, load_ledger
        from core.evidence_catalog import load_catalog
        held = {str(u.get("path") or "").replace("\\", "/") for u in (load_ledger(case_dir).get("units") or {}).values()
                if isinstance(u, dict) and u.get("kind") == CONTAINER_KIND}
        for unit in (load_catalog(case_dir).get("units") or {}).values():
            path = str(unit.get("path") or "").replace("\\", "/") if isinstance(unit, dict) else ""
            if (path and unit.get("fingerprint_mode") == "full" and unit.get("content_sha256")
                    and (path in held or "disk" in source_classes(path))):
                out.add(str(unit["content_sha256"]).casefold())
    except Exception:  # noqa: BLE001
        pass
    return out


def _without_cut_urls(ents: set[str]) -> set[str]:
    """``ents`` without a URL that ends at its host and that a longer URL of
    the same set continues inside the host ("https://www.ex" beside
    "https://www.example.com/a"): one call's output, so a fragment and its
    whole are the same printed link. Known limit: a bare-host URL a longer
    host of the same output continues ("https://a.example" beside
    "https://a.example.org/x") is dropped there too; the longer one stays."""
    import bisect
    urls = sorted(ioc_value(x).casefold() for x in ents if ioc_type(x) == "url")

    def cut(u: str) -> bool:
        if "/" in u.split("://", 1)[-1]:
            return False
        i = bisect.bisect_right(urls, u)
        return i < len(urls) and urls[i].startswith(u) and re.match(r"[a-z0-9.-]", urls[i][len(u)]) is not None
    return {x for x in ents if not (ioc_type(x) == "url" and cut(ioc_value(x).casefold()))}


def ruled_out_without_finding(entries, case_dir=None, *, min_calls: int = 3) -> list[dict]:
    """The recurring values of a demandable kind (DEMAND_WEIGHT) that a
    disposition ruled out and no asserted finding names, each with the first
    disposition call naming it and that disposition's clause about it (its
    stated reason, as written, cut at 160 characters). One scan of the trace
    (_seen_by_calls). A disposition is kept out of the findings and the
    report, so the report's Limitations list these
    (investigation_exit.open_limit_lines)."""
    from core.entities import extract
    from core.execution_log import is_disposition
    seen = _seen_by_calls(entries, case_dir)
    recorded, text = _rulings(entries, case_dir, dispositions=False)
    rulings = [(e, str(e.get("description") or e.get("content") or "")) for e in entries or [] if is_disposition(e)]
    out = []
    for ent, cids in seen.items():
        if (len(cids) < min_calls or _indicator_weight(ioc_type(ent), ioc_value(ent)) < DEMAND_WEIGHT
                or _named(ent, recorded, text)):
            continue
        for e, desc in rulings:
            if _named(ent, extract(desc), desc.casefold()):
                low = ioc_value(ent).casefold()
                clause = next((c for c in re.split(r"(?<=[.;])\s+", desc) if low in c.casefold()), desc)
                out.append({"value": ioc_value(ent), "kind": ioc_type(ent), "calls": len(cids),
                            "disposition": e.get("call_id"), "reason": " ".join(clause.split())[:160]})
                break
    out.sort(key=lambda d: (_indicator_weight(d["kind"], d["value"]), d["calls"]), reverse=True)
    return out


# A ruling may be demanded on a recurring, unrecorded indicator only while
# the demand can be met. The evidence itself sets the population: a capture
# of ordinary browsing shows hundreds of distinct addresses and URLs, each in
# many calls, and ruling on them one by one clears nothing because the
# evidence supplies the next set. Recurrence separates nothing inside such a
# population, so the mechanism stops asking rather than pretend it can. The
# bound is per kind because populations differ by evidence class: process
# names saturate on any event log while the one URL in it stays askable.
UNRECORDED_DEMAND_CAP = 12
# Only a value of a kind that carries an investigative handle is demanded:
# weight DEMAND_WEIGHT or more in _INDICATOR_WEIGHT (an address outside the
# site, a URL, a domain, a mail address, an account, a hash). A file name or
# a private address recurs in every listing, process table and log of its
# host, so recurrence says nothing of it: never a blocking demand, named in
# the bulk line (listed whole while its kind is sparse). Without this the
# demand flips onto such names whenever other noise leaves a kind sparse.
DEMAND_WEIGHT = 3


def unrecorded_demand(candidates, *, cap: int = UNRECORDED_DEMAND_CAP
                      ) -> tuple[list[dict], list[dict]]:
    """Split ``unrecorded_evidence_indicators`` output into what a gate may
    demand a ruling on and what it may only mention.

    Returns ``(demand, bulk)``, each in the ranking it was given. A value
    below DEMAND_WEIGHT is bulk. A kind with more than ``cap`` members is
    bulk in full; if the sparse kinds together exceed ``cap``, everything is
    bulk and nothing is demanded.
    """
    from collections import Counter

    every = list(candidates or [])
    low = [d for d in every if _indicator_weight(d["kind"], d["value"]) < DEMAND_WEIGHT]
    cands = [d for d in every if _indicator_weight(d["kind"], d["value"]) >= DEMAND_WEIGHT]
    left = Counter(d["kind"] for d in cands)
    # The producer reports how many of a kind the evidence shows; falling back
    # to what is still unrecorded keeps a hand-built list working.
    dense = {k for k in left
             if max([int(d.get("kind_population") or 0) for d in cands
                     if d["kind"] == k] + [left[k]]) > cap}
    demand = [d for d in cands if d["kind"] not in dense]
    if len(demand) > cap:
        return [], cands + low
    return demand, [d for d in cands if d["kind"] in dense] + low


def describe_unrecorded_bulk(bulk) -> str:
    """One line for indicators mentioned but not demanded: counts per kind
    and the values seen most often."""
    from collections import Counter

    rows = list(bulk or [])
    kinds = Counter(d["kind"] for d in rows)
    # Ties broken by value so the same evidence names the same three in every
    # process, rather than following dictionary order.
    top = sorted(rows, key=lambda d: (-int(d.get("calls") or 0), str(d["value"])))[:3]
    # The values of a kind that is never demanded (unrecorded_demand), named
    # whole while their kind is sparse, so a lead among them stays in view.
    low = [d for d in rows if _indicator_weight(d["kind"], d["value"]) < DEMAND_WEIGHT
           and int(d.get("kind_population") or 0) <= UNRECORDED_DEMAND_CAP]
    return (", ".join(f"{n} {k}" for k, n in kinds.most_common())
            + "; seen most: " + ", ".join(str(d["value"]) for d in top)
            + ("; file names and private addresses, never asked for one by one: "
               + ", ".join(f"{d['value']} ({d['kind']})" for d in low) if low else ""))


def evidence_sources(case_dir: str | os.PathLike) -> dict[str, set[str]]:
    """``{rel_path: classes}`` for every searchable source in the case.

    Containers (raw disk images) are excluded: an indicator is not grepped
    out of a VMDK, it is searched in what was extracted from it.
    """
    root = Path(case_dir)
    out: dict[str, set[str]] = {}

    def _add(rel: str) -> None:
        rel = str(rel).replace("\\", "/").lstrip("./")
        if not rel or rel in out:
            return
        if is_atlas_output(rel):
            return
        classes = source_classes(rel)
        if classes & _CONTAINER_CLASSES:
            return
        out[rel] = classes

    try:
        from core.evidence_catalog import load_catalog
        catalog = load_catalog(root)
        for item in (catalog.get("evidence") or {}).values():
            if isinstance(item, dict) and item.get("path"):
                _add(str(item["path"]))
    except Exception:
        pass

    # Extracted/parsed artifacts live under analysis/ and exports/ and are
    # every bit as searchable as the originals. Walked via the case-wide
    # scanner rather than rglob: rglob will not descend a symlinked
    # directory, and real evidence is attached to a case by symlink rather
    # than copied — which made this return nothing at all on a KAPE
    # collection.
    try:
        from core.evidence_catalog import iter_case_files
        for rel, abs_p in iter_case_files(root):
            try:
                if abs_p.stat().st_size > 0:
                    _add(rel)
            except OSError:
                continue
    except Exception:  # noqa: BLE001
        pass
    return out


def _source_is_about_host(rel_path: str, host: str, case_dir=None) -> bool:
    """True when a source path belongs to ``host``: the one path matcher
    (core.evidence_links.host_of_path) over the case's hosts and ``host``,
    so a longer case label that holds it wins."""
    from core.evidence_links import host_of_path, host_of_path_on
    path = str(rel_path or "").replace("\\", "/")
    if not host_of_path_on():
        from core.forensic_citation import host_mentioned
        return host_mentioned(host, path)
    try:
        from core.forensic_citation import known_case_hosts
        hosts = list(dict.fromkeys([*(known_case_hosts(case_dir) if case_dir else []), host]))
    except Exception:  # noqa: BLE001
        hosts = [host]
    return host_of_path(case_dir, path, hosts).casefold() == str(host or "").casefold() != ""


def _table_holds(path: Path, terms: list[str]) -> set[str]:
    """The terms whose literal text the file holds: the program's one cached
    byte scan (core.indicators.file_holds), shared with the sighting lookup."""
    from core.indicators import file_holds
    return file_holds(path, terms)


def generic_fit(ioc: str, sources: dict[str, set[str]],
                root: str | os.PathLike | None) -> tuple[list[str], int]:
    """The unclassified derived tables that hold one of the indicator's
    search terms, richest first, and how many were read and hold none of
    them. Without a case root no table is read, and none is owed."""
    wanted = set(_RELEVANCE.get(ioc_type(ioc), ()))
    if "generic" not in wanted or root is None:
        return [], 0
    try:
        from core.artifact_value import artifact_score
    except Exception:  # noqa: BLE001
        def artifact_score(_n, _s=None):  # type: ignore[misc]
            return (0, "")
    terms = [t.lower() for t in _search_terms(ioc)]
    held: list[tuple[int, str]] = []
    absent = 0
    for rel, classes in sources.items():
        if classes != {"generic"} or not _derived(rel):
            continue
        if _table_holds(Path(root) / rel, terms):
            held.append((-artifact_score(rel.rsplit("/", 1)[-1])[0], rel))
        else:
            absent += 1
    return [rel for _, rel in sorted(held)], absent


def relevant_targets(
    ioc: str,
    sources: dict[str, set[str]],
    *,
    limit: int = MAX_TARGETS_PER_PIVOT,
    root: str | os.PathLike | None = None,
) -> list[str]:
    """Sources worth re-searching for this indicator: the classed sources
    and intake material of its kinds, then the unclassified derived tables
    that hold one of its search terms (generic_fit)."""
    kind = ioc_type(ioc)
    wanted = set(_RELEVANCE.get(kind, ()))
    if not wanted:
        return []
    value = ioc_value(ioc).lower()
    try:
        from core.artifact_value import artifact_score
    except Exception:  # noqa: BLE001
        def artifact_score(_n, _s=None):  # type: ignore[misc]
            return (0, "")

    hits: list[tuple[int, int, str]] = []
    for rel, classes in sources.items():
        if not (classes & wanted):
            continue
        if classes == {"generic"} and _derived(rel):
            continue
        # A host indicator is most interesting in *other* hosts' material —
        # that is what makes cross-host correlation happen.
        rank = 0
        if kind == "host":
            rank = 2 if _source_is_about_host(rel, value, root) else 1
        # Prefer sources of the indicator's primary class.
        primary = _RELEVANCE[kind][0]
        if primary in classes:
            rank -= 1
        # Within a class, richer artifacts first. Without this, "search for
        # this account" pointed at ETW RtBackup trace buffers ahead of
        # Security.evtx purely because both are eventlog-class — the value
        # model and the pivot ledger were not talking to each other
        #
        score = artifact_score(rel.rsplit("/", 1)[-1])[0]
        hits.append((rank, -score, rel))
    hits.sort()
    out = [rel for _, _, rel in hits]
    out += generic_fit(ioc, sources, root)[0]
    return out[:limit]


# ── the ledger ───────────────────────────────────────────────────────────

def _blocked_sources(case_dir: str | os.PathLike) -> dict[str, str]:
    """``{rel_path (casefolded): reason}`` for every coverage-ledger unit
    marked blocked. A source the analyst could not examine cannot be
    searched for an indicator either."""
    try:
        from core.coverage_ledger import load_ledger
        units = load_ledger(case_dir).get("units") or {}
    except Exception:  # noqa: BLE001 — a ledger problem must not stop pivots
        return {}
    return {
        str(u["path"]).replace("\\", "/").casefold(): str(u.get("note") or "")
        for u in units.values()
        if isinstance(u, dict) and u.get("status") == "blocked" and u.get("path")
    }


def refresh_pivots(
    case_dir: str | os.PathLike,
    *,
    persist: bool = True,
) -> dict[str, Any]:
    """Re-derive pivots from current beliefs and evidence; keep statuses."""
    ledger = load_pivots(case_dir)
    prev = ledger.get("pivots") or {}
    # Each source of indicators has its own room. The analyst's are owed a
    # search before any belief exists, so a later belief never pushes them
    # out; and a brief that describes the estate (hosts, admin accounts)
    # never pushes out what the run's own findings attribute to the
    # attacker. The operator's threat context takes at most half a ledger
    # (core.threat_context.pivot_indicators): its sweep covers every row.
    analyst: dict[str, str] = {}
    try:
        from core.case_knowledge import prior_indicators
        analyst = prior_indicators(case_dir)
    except Exception:  # noqa: BLE001 — a brief problem must not stop pivots
        pass
    intel: dict[str, str] = {}
    try:
        from core.threat_context import pivot_indicators
        intel = {ioc: row_id for ioc, row_id in pivot_indicators(case_dir).items()
                 if ioc not in analyst}
    except Exception:  # noqa: BLE001
        pass
    beliefs = {ioc: origin for ioc, origin in indicators_from_beliefs(case_dir).items()
               if ioc not in analyst and ioc not in intel}
    chosen = (list(analyst.items())[:MAX_PIVOTS] + list(intel.items())
              + list(beliefs.items())[:MAX_PIVOTS])
    sources = evidence_sources(case_dir)
    blocked = _blocked_sources(case_dir)

    from core.deferred_intents import estate_count_on
    if estate_count_on():
        # The estate count (ATLAS_ESTATE_COUNT): the indicators are kept with
        # their counts and the calls that showed their rows; no search is
        # owed, so no target is built.
        kept: dict[str, Any] = {}
        for ioc, origin in chosen:
            old = prev.get(ioc) or {}
            kept[ioc] = {"origin": old.get("origin") or origin, "targets": {},
                         "counts": old.get("counts") or {}, "shown": old.get("shown") or {}}
        for ioc, old in prev.items():
            if ioc not in kept and (old.get("counts") or old.get("shown")):
                kept[ioc] = {"origin": old.get("origin", ""), "targets": {},
                             "counts": old.get("counts") or {}, "shown": old.get("shown") or {}}
        ledger["pivots"] = kept
        if persist:
            try:
                save_pivots(case_dir, ledger)
            except OSError:
                pass
        return ledger
    pivots: dict[str, Any] = {}
    for ioc, origin in chosen:
        targets = relevant_targets(ioc, sources, root=case_dir)
        if not targets:
            continue
        old = prev.get(ioc) or {}
        old_targets = old.get("targets") or {}
        reasons = dict(old.get("blocked_reasons") or {})
        statuses: dict[str, str] = {}
        for t in targets:
            status = str(old_targets.get(t) or "pending")
            if status == "pending" and t.casefold() in blocked:
                status = "blocked"
                reasons[t] = blocked[t.casefold()][:200]
            statuses[t] = status
        # A source already searched or blocked stays on the pivot even when
        # it is no longer a target: a new rule does not un-search it.
        for t, s in old_targets.items():
            if s in ("searched", "blocked") and t not in statuses:
                statuses[t] = s
        pivots[ioc] = {"origin": old.get("origin") or origin, "targets": statuses}
        if reasons:
            pivots[ioc]["blocked_reasons"] = reasons
        # Visible, not owed: the unclassified derived tables that hold none
        # of the indicator's search terms (the literal string is absent from
        # the file; nothing is said about the table's worth), and those that
        # hold one but fall beyond the target limit.
        held, absent = generic_fit(ioc, sources, case_dir)
        if absent:
            pivots[ioc]["generic_checked_absent"] = absent
        left_out = sum(1 for t in held if t not in statuses)
        if left_out:
            pivots[ioc]["generic_unowed"] = left_out
    # Never drop a pivot whose work was already done or explicitly blocked —
    # a belief being superseded does not un-search the evidence.
    for ioc, old in prev.items():
        if ioc in pivots:
            continue
        done = {t: s for t, s in (old.get("targets") or {}).items()
                if s in ("searched", "blocked")}
        if done:
            pivots[ioc] = {"origin": old.get("origin", ""), "targets": done}
            if old.get("blocked_reasons"):
                pivots[ioc]["blocked_reasons"] = old["blocked_reasons"]

    ledger["pivots"] = pivots
    if persist:
        try:
            save_pivots(case_dir, ledger)
        except OSError:
            pass
    return ledger


_REGEX_ESCAPE_RE = re.compile(r"\\([^\w])")


def _indicator_searched(ioc: str, text: str) -> bool:
    """Does the (lower-cased, unescaped) call text search for this indicator?

    Exact term, or every name part of it, or any log-side form of a host
    ("srv01" searches CORP-SRV01).
    """
    terms = [t.lower() for t in _search_terms(ioc)]
    if any(t in text for t in terms):
        return True
    kind = ioc_type(ioc)
    if kind == "host":
        try:
            from core.forensic_citation import host_name_forms
            if any(f in text for f in host_name_forms(ioc_value(ioc))):
                return True
        except Exception:  # noqa: BLE001
            pass
    for t in terms:
        parts = [x for x in re.split(r"[^a-z0-9]+", t) if len(x) >= 3 and not x.isdigit()]
        if len(parts) >= 2 and all(x in text for x in parts):
            return True
    return False


def _target_searched(target: str, text: str) -> bool:
    """Does the call text name this source — as written, by basename, or by
    the stem a parsed product of it carries (Security.evtx → Security.csv)?"""
    low = target.lower()
    if low in text:
        return True
    base = low.replace("\\", "/").rsplit("/", 1)[-1]
    if base and base in text:
        return True
    stem = base.rsplit(".", 1)[0] if "." in base else ""
    return bool(stem) and len(stem) >= 4 and stem in text


# A search result that says it stopped early: a table search at its hit cap
# or at its row bound saw only the rows before it.
_STOPPED_EARLY_RE = re.compile(r'"(?:hit_cap_reached|scan_capped)"\s*:\s*true')


def _stopped_early_view(blob: str, result: str) -> str | None:
    """What a search that stopped early showed: its printed rows, read with
    the program's one echo-free reader (core.indicators.printed_rows), so
    neither the call's own arguments echoed back at the top of the result,
    the shared echo keys, the term lines nor the alternatives block name an
    indicator whose rows were never shown. None for a search that did not
    stop early, or whose call cannot be read back."""
    if not result or not _STOPPED_EARLY_RE.search(result):
        return None
    try:
        tool, raw_args = blob.split(" ", 1)
    except ValueError:
        return None
    from core.indicators import _parsed_args
    args = _parsed_args({"args": raw_args})[0]
    if not isinstance(args, dict) or not args:
        # Not even a cut argument text: the call cannot be read back.
        return None
    from core.indicators import printed_text
    entry = {"cmd": f"<py>:{tool}", "args": json.dumps(args, default=str), "stdout_excerpt": result}
    view = printed_text(entry, text=result)
    return _REGEX_ESCAPE_RE.sub(r"\1", view.lower().replace("\\\\", "\\"))


def _capped_result_hint() -> str:
    """How the nudge describes a table.grep result that stopped at its hit
    limit: by the keys the result the model holds carries, the compact
    view's term lines and absence lists when the view is on, the
    alternatives block otherwise."""
    from core.tool_result_view import _view_on
    if _view_on():
        return ("A table.grep result that stops at its hit limit says per term how many "
                "rows it has (terms) and which terms no row of the whole file holds "
                "(terms_with_no_row): those are settled for that source. A term with "
                "rows that were not shown (terms_matched_not_returned) and the terms "
                "the result could not settle (terms_not_settled) are still owed: "
                "search such a term alone (pattern=<term>).")
    return ("A table.grep result that stops at its hit limit lists the pattern's "
            "alternatives: each one it calls matched or unmatched is settled for "
            "that source (unmatched: no row of the whole file holds it), and only "
            "the unresolved ones, left when the scan stopped at its row bound, "
            "are still owed: search that file with strings.grep.")


def _absent_terms(result: str) -> set[str]:
    """The terms a search result says match no row of the whole file (its
    alternatives block's ``unmatched``, the view's ``terms_with_no_row``),
    as the analyst would write them: an indicator among them is settled
    for that source, since the whole file was read for it."""
    if not result:
        return set()
    try:
        data = json.loads(result)
    except ValueError:
        return set()
    if not isinstance(data, dict):
        return set()
    terms: list[str] = []
    blk = data.get("alternatives")
    if isinstance(blk, dict) and isinstance(blk.get("unmatched"), list):
        terms += [str(t) for t in blk["unmatched"]]
    if isinstance(data.get("terms_with_no_row"), list):
        terms += [str(t) for t in data["terms_with_no_row"]]
    return {_REGEX_ESCAPE_RE.sub(r"\1", t.lower().replace("\\\\", "\\")) for t in terms}


def _view_annotation(result: str) -> dict | None:
    """The trace annotation of the view the model saw (view_terms_shown,
    view_complete), reached through the call id stamped on the result; None
    when the result carries no id or the entry no annotation."""
    try:
        from core.call_memo import trace_call_id_of
        from core.execution_log import log
        cid = trace_call_id_of(result or "")
        entry = (log.index().by_call_id or {}).get(int(cid)) if cid else None
    except Exception:  # noqa: BLE001
        return None
    if isinstance(entry, dict) and isinstance(entry.get("view_terms_shown"), list):
        return entry
    return None


def _indicator_shown(ioc: str, view: str) -> bool:
    """Does a search result show this indicator: one of its exact terms, or a
    log-side form of a host? Not its name parts: over many rows the parts of
    a path or a URL turn up by chance."""
    if any(t.lower() in view for t in _search_terms(ioc)):
        return True
    if ioc_type(ioc) == "host":
        try:
            from core.forensic_citation import host_name_forms
            return any(f in view for f in host_name_forms(ioc_value(ioc)))
        except Exception:  # noqa: BLE001
            return False
    return False


def observe_search(
    case_dir: str | os.PathLike,
    *,
    blob: str,
    result: str = "",
    persist: bool = True,
) -> list[str]:
    """Mark pivots searched from one tool call's arguments/command text.

    A pivot-target pair counts as searched when a single tool call mentions
    both the indicator and the target — that is exactly the shape of
    "grep this indicator in that source". A search whose ``result`` says it
    stopped early (its hit cap, its row bound) searched only part of the
    source: of the indicators it names, only those its result shows count,
    and the rest stay owed.
    """
    # The call is read the way an analyst wrote it: a regex escape is not
    # part of the indicator ("10\\.0\\.0\\.5" searches 10.0.0.5), and a
    # search over what was parsed out of a source (Security.csv) is a
    # search of that source (Security.evtx). Otherwise a pivot stays pending
    # through any number of such searches and is asked for again.
    # JSON-serialised arguments double every backslash; undo that first.
    text = _REGEX_ESCAPE_RE.sub(r"\1", (blob or "").lower().replace("\\\\", "\\"))
    if not text:
        return []
    ledger = load_pivots(case_dir)
    pivots = ledger.get("pivots") or {}
    # What the search settled: with the view's annotation on the trace entry,
    # an indicator counts as shown only when one of its terms has a shown
    # row; without it, the printed rows of a result that stopped early. A
    # term the result says has no row anywhere is settled too: the whole
    # file was read for it.
    note = _view_annotation(result)
    from core.deferred_intents import estate_count_on
    if estate_count_on():
        return _observe_shown(case_dir, ledger, pivots, text, blob, result, note, persist)
    shown = None if note is not None else _stopped_early_view(blob, result)
    absent = _absent_terms(result)
    shown_terms = ({_REGEX_ESCAPE_RE.sub(r"\1", str(t).lower().replace("\\\\", "\\"))
                    for t in note["view_terms_shown"]} if note is not None else set())
    closed: list[str] = []
    for ioc, entry in pivots.items():
        if not _indicator_searched(ioc, text):
            continue
        settled_absent = any(t.lower() in absent for t in _search_terms(ioc))
        if note is not None:
            if not note.get("view_complete") and not settled_absent \
                    and not any(t.lower() in shown_terms for t in _search_terms(ioc)):
                continue
        elif shown is not None and not settled_absent and not _indicator_shown(ioc, shown):
            continue
        for target, status in list((entry.get("targets") or {}).items()):
            if status != "pending":
                continue
            if _target_searched(target, text):
                entry["targets"][target] = "searched"
                closed.append(f"{ioc} -> {target}")
    if closed and persist:
        try:
            save_pivots(case_dir, ledger)
        except OSError:
            pass
    return closed


def _observe_shown(case_dir, ledger: dict, pivots: dict, text: str, blob: str, result: str,
                   note: dict | None, persist: bool) -> list[str]:
    """Under the estate count, a search shows an indicator's rows on a
    source when one of the indicator's terms is in the trace entry's
    ``view_terms_shown``; without the annotation, when the printed rows of
    the result (the echoed request removed) hold it. Recorded as
    ``shown[source] = call id``."""
    from core.call_memo import trace_call_id_of
    from core.coverage_ledger import _blob_paths
    paths = _blob_paths(blob or "")
    if not paths:
        return []
    source = paths[0].replace("\\", "/")
    cid = trace_call_id_of(result or "") or "?"
    shown_terms = ({_REGEX_ESCAPE_RE.sub(r"\1", str(t).lower().replace("\\\\", "\\"))
                    for t in note["view_terms_shown"]} if note is not None else set())
    view = None if note is not None else (_stopped_early_view(blob, result) or result)
    closed: list[str] = []
    for ioc, entry in pivots.items():
        if not _indicator_searched(ioc, text):
            continue
        if note is not None:
            if not any(t.lower() in shown_terms for t in _search_terms(ioc)):
                continue
        elif not view or not _indicator_shown(ioc, view):
            continue
        shown = entry.setdefault("shown", {})
        if source not in shown:
            shown[source] = cid
            closed.append(f"{ioc} -> {source}")
    if closed and persist:
        try:
            save_pivots(case_dir, ledger)
        except OSError:
            pass
    return closed


def record_counts(case_dir: str | os.PathLike, counts: dict[str, dict]) -> None:
    """Store an estate count on the ledger: ``counts[ioc][source]``."""
    ledger = load_pivots(case_dir)
    pivots = ledger.setdefault("pivots", {})
    for ioc, per in counts.items():
        entry = pivots.setdefault(ioc, {"origin": "", "targets": {}})
        entry.setdefault("counts", {}).update(per)
    save_pivots(case_dir, ledger)


def count_lines(case_dir: str | os.PathLike, counts: dict[str, dict], *, sources: list[str],
                new_tables: list[str] | None = None) -> list[str]:
    """The [estate counts] block: one line per indicator with rows, fewest
    hosts first, its rows per host with first and last time; a path
    indicator's full and name-only numbers; the indicators with no row
    anywhere on one line. Hosts come from the table's own path. A pass
    over ``new_tables`` (the tables that appeared since the last) names
    the tables instead: one line per indicator, its new tables with rows,
    most rows first, the first three named and the rest counted (a parser
    that writes one table per log leaves dozens at once)."""
    from core.forensic_citation import host_mentioned, known_case_hosts
    hosts = known_case_hosts(case_dir)

    # ponytail: the host comes from the table's own path, so a merged
    # timeline holding several hosts is credited to the one its path names
    # (or to the path itself); a per-row host column would split it.
    def host_of(src: str) -> str:
        return next((h for h in hosts if host_mentioned(h, src)), "") or src

    def span(c: dict) -> str:
        f, la = str(c.get("first") or "")[:16], str(c.get("last") or "")[:16]
        return f" ({f} .. {la})" if f and la and f != la else (f" ({f})" if f else "")
    rows, zero = [], []
    for ioc, per in counts.items():
        kind, value = ioc_type(ioc), ioc_value(ioc)
        full = {s: c for s, c in per.items() if c.get("full")}
        name = {s: c for s, c in per.items() if c.get("name")}
        if not full and not name:
            zero.append(f"{kind} {value}")
            continue
        if new_tables:
            hit = sorted(((s, per[s]) for s in new_tables if per.get(s)),
                         key=lambda sc: -int(sc[1].get("full") or sc[1].get("name") or 0))
            if not hit:
                zero.append(f"{kind} {value}")
                continue
            if len(new_tables) == 1:
                s, c = hit[0]
                rows.append((1, f"- new table {s}: {value} {c.get('full') or c.get('name')} rows{span(c)}"))
            else:
                shown, more = hit[:3], hit[3:]
                rows.append((1, f"- new tables: {value} " + "; ".join(
                    f"{c.get('full') or c.get('name')} rows {s}{span(c)}" for s, c in shown)
                    + (f"; and {len(more)} more tables, "
                       f"{sum(int(c.get('full') or c.get('name') or 0) for _s, c in more)} rows" if more else "")))
            continue
        by_host: dict[str, list] = {}
        for s, c in full.items():
            by_host.setdefault(host_of(s), []).append(c)
        hosts_txt = ", ".join(f"{sum(int(c['full']) for c in cs)} rows {h}{span(cs[0])}"
                              for h, cs in sorted(by_host.items(), key=lambda kv: -sum(int(c['full']) for c in kv[1])))
        other = len(sources) - len(full)
        if kind in ("path", "reg"):
            nh = {host_of(s) for s in name}
            line = (f"- {kind} {value}: full path " + (hosts_txt or "0 rows")
                    + f"; name only {sum(int(c['name']) for c in name.values())} rows on {len(nh)} hosts")
        else:
            line = f"- {kind} {value}: {hosts_txt}" + (f"; 0 rows on {other} other tables" if other > 0 else "")
        rows.append((len(by_host) or 99, line))
    if not rows and not zero:
        return []
    out = ["[estate counts] rows that contain each indicator, per host (case-insensitive):"]
    out += [line for _n, line in sorted(rows, key=lambda r: r[0])]
    if zero:
        where = "anywhere" if not new_tables else (
            "in the new table" if len(new_tables) == 1 else f"in the {len(new_tables)} new tables")
        out.append(f"- 0 rows {where}: {len(zero)} indicators ({', '.join(zero[:6])}"
                   + (", ..." if len(zero) > 6 else "") + ")")
    out.append("Counts are not rows: read the rows with table_grep on the host's table.")
    return out


def open_pivots(case_dir: str | os.PathLike) -> list[dict[str, Any]]:
    """Indicators with evidence still un-searched, worst first; none under
    the estate count, which owes no search (ATLAS_ESTATE_COUNT)."""
    from core.deferred_intents import estate_count_on
    if estate_count_on():
        return []
    ledger = load_pivots(case_dir)
    out: list[dict[str, Any]] = []
    for ioc, entry in (ledger.get("pivots") or {}).items():
        # Insertion order is relevance order (refresh_pivots stores targets
        # as relevant_targets ranked them). Sorting alphabetically here threw
        # that away: on a host with a hundred-odd event-log channels the nudge's
        # display cap then showed Application.evtx and cut off Security.evtx
        # — the ranking was computed and then discarded one function later
        #
        pending = [t for t, s in (entry.get("targets") or {}).items()
                   if s == "pending"]
        if pending:
            out.append({
                "ioc": ioc,
                "origin": entry.get("origin", ""),
                "pending": pending,
            })
    out.sort(key=lambda p: (-len(p["pending"]), p["ioc"]))
    return out


_GAP_T = {
    "en": ("- Not searched for in every relevant source ({n} indicator(s)): {items}",
           " and {m} more", ("source", "sources"), ", named in the brief"),
    "de": ("- Nicht in jeder relevanten Quelle gesucht ({n} Indikator(en)): {items}",
           " und {m} weitere", ("Quelle", "Quellen"), ", in der Fallbeschreibung genannt"),
}


def gap_lines(case_dir: str | os.PathLike, language: str = "en", host: str = "") -> list[str]:
    """Evidence Gaps: the indicators the findings or the brief name that
    were not searched for in every relevant source the case holds, the most
    owed first (open_pivots), one the analyst named marked as such; a host's
    report counts that host's sources only. Nothing when none is open."""
    from core.deferred_intents import estate_count_on
    if estate_count_on():
        return _counted_never_shown(case_dir, language, host)
    try:
        pending = open_pivots(case_dir)
    except Exception:  # noqa: BLE001 - the report is written without it
        return []
    rows = []
    for p in pending:
        k = sum(1 for t in p["pending"] if not host or _source_is_about_host(t, host, case_dir))
        if k:
            # An indicator's value is evidence text: one line, no code fence.
            value = " ".join((ioc_value(p["ioc"]) or p["ioc"]).replace("`", "").split())
            rows.append((value, k, p.get("origin") == _ANALYST_ORIGIN))
    if not rows:
        return []
    line, more, (one, many), briefed = _GAP_T["de" if language == "de" else "en"]
    items = ", ".join(f"`{v}` ({k} {one if k == 1 else many}{briefed if named else ''})"
                      for v, k, named in rows[:6])
    return [line.format(n=len(rows), items=items)
            + (more.format(m=len(rows) - 6) if len(rows) > 6 else "")]


def _counted_never_shown(case_dir, language: str, host: str) -> list[str]:
    """Evidence Gaps under the estate count: indicators with rows counted on
    a source no call showed them on."""
    try:
        pivots = load_pivots(case_dir).get("pivots") or {}
    except Exception:  # noqa: BLE001
        return []
    from core.forensic_citation import host_mentioned, known_case_hosts
    hosts = known_case_hosts(case_dir)
    items = []
    for ioc, entry in pivots.items():
        shown = entry.get("shown") or {}
        for src, c in (entry.get("counts") or {}).items():
            n = int(c.get("full") or 0)
            if not n or src in shown or (host and not _source_is_about_host(src, host, case_dir)):
                continue
            where = next((h for h in hosts if host_mentioned(h, src)), src)
            items.append(f"`{ioc_value(ioc)}` ({n} rows on {where})")
    if not items:
        return []
    head = ("- Zeilen gezählt, nie gezeigt: " if language == "de" else "- Rows counted, never shown: ")
    return [head + ", ".join(items[:8]) + (f" (+{len(items) - 8})" if len(items) > 8 else "")]


def pivot_stats(case_dir: str | os.PathLike) -> dict[str, int]:
    ledger = load_pivots(case_dir)
    stats = {"pivots": 0, "pending": 0, "searched": 0, "blocked": 0}
    for entry in (ledger.get("pivots") or {}).values():
        stats["pivots"] += 1
        for status in (entry.get("targets") or {}).values():
            if status in stats:
                stats[status] += 1
    return stats


# A nudge's searches: one pattern per source naming every indicator owed
# there, printed whole or not at all, bounded by the size of the patterns
# (not by a count of indicators). A search that names several indicators
# credits each of them (observe_search), so one scan of a large table does
# the work of many.
_NUDGE_PATTERN_BUDGET = 4000
# The characters a Python regex reads as syntax. A dot, a dash or a space in
# an indicator stays as written: a dot matching any character only widens a
# sweep whose rows are read, and every escape is one the model may double.
_PATTERN_SYNTAX_RE = re.compile(r"([\\()\[\]{}+*?^$|])")


def pattern_term(ioc: str) -> str:
    """An indicator as one alternative of a search pattern: a path or a
    registry key by its last component (``_search_terms``), which matches
    either separator and is credited by construction; it is less precise
    (the same name in another folder also hits) and the rows a hit returns
    show the full path to judge. Any other indicator, and a last component
    too short to be a term, as its full value."""
    terms = _search_terms(ioc)
    value = terms[-1] if ioc_type(ioc) in ("path", "reg") and terms else ioc_value(ioc)
    return _PATTERN_SYNTAX_RE.sub(r"\\\1", value)


def format_pivot_nudge(pivots: Iterable[dict[str, Any]], *, limit: int = 6,
                       case_dir: str | os.PathLike | None = None) -> str:
    """The message the loop shows the model: the searches still owed, one per
    source, each with a pattern naming every indicator owed there (``limit``
    sources at most, the ones owing the most first). What a hit means depends
    on who named the indicator: one a finding or the threat context named is
    corroborated by a hit; one the analyst named is judged against the
    analyst's statement, which may describe the estate's own infrastructure
    rather than a suspicion. With ``case_dir`` the statement is read from the
    brief as it stands now, so a fact added mid-run is quoted, not just
    keyed; only a nudge that shows an analyst-named indicator pays for that
    read."""
    pivots = list(pivots)
    if not pivots:
        return ""
    by_source: dict[str, list[dict[str, Any]]] = {}
    for p in pivots:
        for target in p.get("pending") or []:
            by_source.setdefault(target, []).append(p)
    # Most owed first; equal counts keep the order the pivots ranked them in.
    order = sorted(by_source, key=lambda t: -len(by_source[t]))
    shown: list[tuple[str, str]] = []
    used = 0
    for target in order:
        if len(shown) >= limit:
            break
        pattern = "|".join(dict.fromkeys(pattern_term(p["ioc"]) for p in by_source[target]))
        if shown and used + len(pattern) > _NUDGE_PATTERN_BUDGET:
            continue
        shown.append((target, pattern))
        used += len(pattern)
    in_shown = {p["ioc"] for target, _ in shown for p in by_source[target]}
    items = [p for p in pivots if p["ioc"] in in_shown]
    named_by_analyst = [p for p in items if p.get("origin") == _ANALYST_ORIGIN]
    statements: dict[str, dict[str, str]] = {}
    if named_by_analyst and case_dir is not None:
        try:
            from core.case_knowledge import indicator_statements
            statements = indicator_statements(case_dir)
        except Exception:  # noqa: BLE001 — a brief problem must not stop the nudge
            statements = {}
    lines = [
        "[ioc pivot] These indicators are not yet searched for across the "
        "evidence. Search each source below once, with the pattern given for "
        "it: it names every indicator owed there, joined with |, and one call "
        "credits every indicator it names in that source. The pattern is a "
        "Python regex: table.grep takes it as its pattern, strings.grep takes "
        "it or the list of its terms; an .evtx is parsed first (ez.evtxecmd, or "
        "misc.evtx_dump with an output_path) and its output searched. Copy it "
        "unchanged: a path or a registry key is searched by its last component "
        "as printed, every other indicator written out in full (a shortened "
        "form or a character class credits nothing). "
        + _capped_result_hint()
        + (" For an indicator a finding or the threat context named, a "
           "corroborating hit is a finding (misc.record_finding)."
           if len(named_by_analyst) < len(items) else "")
        + (" For an indicator the analyst named"
           + (" (their statement is quoted below it where it stands in "
              "CASE.md)" if statements else " in CASE.md")
           + ", what a hit means depends on "
           "the statement. If it is a suspicion or an indicator seen "
           "elsewhere, a hit in this evidence is a finding: record it now "
           "with misc.record_finding (SUSPECTED or LIKELY while a binding is "
           "still open), citing the call. If it describes the environment (a "
           "known host or account), a hit that shows it doing its stated job "
           "is a disposition naming the statement; anything else it does is "
           "judged like any other hit, and a suspicious one is a finding now."
           if named_by_analyst else "")
        + " A clean miss is a disposition, not a "
        "finding: record it with misc.record_agent_message(content=..., "
        "disposition=True), naming the indicators and the sources searched. "
        "A finding that only documents a search is a false conclusion, and "
        "the indicators it names re-open this queue. If a source genuinely "
        "cannot be examined (corrupt, empty, unparseable), record the "
        "failed attempt with coverage.mark_blocked(path, reason); a source "
        "blocked there is no longer owed here.",
        "Indicators:",
    ]
    for p in items:
        kind, value = ioc_type(p["ioc"]), ioc_value(p["ioc"])
        if p.get("origin") == _ANALYST_ORIGIN:
            fact = statements.get(p["ioc"]) or {}
            lines.append(f"- {kind} {value}, named by the analyst in CASE.md")
            if fact.get("text"):
                said = " ".join(str(fact["text"]).split())
                said = said if len(said) <= 200 else said[:199].rstrip() + "…"
                lines.append(f"    statement{' ' + fact['id'] if fact.get('id') else ''}: "
                             f"\"{said}\"")
        else:
            lines.append(f"- {kind} {value}"
                         + (f" (from {p['origin']})" if p.get("origin") else ""))
    lines.append("Searches owed, one per source:")
    for target, pattern in shown:
        lines.append(f"- {target} ({len(by_source[target])} owed): pattern {pattern}")
    rest = [t for t in by_source if t not in {target for target, _ in shown}]
    if rest:
        pairs = sum(len(by_source[t]) for t in rest)
        lines.append(f"({len(rest)} more source{'s' if len(rest) != 1 else ''}, {pairs} more "
                     f"indicator search{'es' if pairs != 1 else ''}: in a later reminder)")
    return "\n".join(lines)
