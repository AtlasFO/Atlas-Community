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
_TABLE_TERMS: dict[tuple[str, int, int], dict[str, bool]] = {}
_SCAN_CHUNK = 1 << 20

# Indicator types that are never worth pivoting on: too generic to narrow a
# search, or an artifact of prose rather than an indicator.
_NON_PIVOT_TYPES = frozenset({"ts", "cve", "technique", "flag", "hex"})

# A raw disk image is a *container*, not something you grep for an
# indicator — its contents become sources once extracted.
_CONTAINER_CLASSES = frozenset({"disk"})

_LOOPBACK_IP_RE = re.compile(r"^(?:0\.|127\.|255\.)")
# Multicast, link-local and broadcast addresses: every capture carries them,
# none is anyone's infrastructure.
_NON_ROUTABLE_IP_RE = re.compile(r"^(?:169\.254\.|22[4-9]\.|23\d\.)|\.255$")
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
    pair); a path is searched for by basename as well as in full, because
    that is how an analyst actually greps.
    """
    kind, value = ioc_type(ioc), ioc_value(ioc)
    if not value:
        return []
    terms = [value]
    if kind == "account" and "/" in value:
        terms.append(value.split("/", 1)[1])
    if kind in ("path", "reg", "url") and "/" in value:
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
        attributed = {_ioc_key(str(i.get("value") or ""))
                      for i in list(cat.get("iocs") or []) + list(cat.get("review") or [])
                      if isinstance(i, dict) and i.get("side") != "victim"}
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
    re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    # A backslash is no URL character: in a JSON spill an escaped quote
    # follows the link, and a token that keeps the backslash names a URL no
    # finding can ever match.
    re.compile(rb"https?://[^\s'\"<>\\]{4,200}", re.I),
    re.compile(rb"[\w.+-]{1,64}@[\w-]{1,63}(?:\.[\w-]{1,63})+"),
)
_spill_cache: dict[tuple, frozenset] = {}


def _spilled_entities(path: str) -> frozenset:
    """Discriminative network and identity entities in a retained full tool
    output."""
    try:
        st = os.stat(path)
    except OSError:
        return frozenset()
    key = (path, st.st_size, st.st_mtime_ns)
    hit = _spill_cache.get(key)
    if hit is not None:
        return hit
    from core.entities import discriminative, extract
    try:
        with open(path, "rb") as f:
            data = f.read(_SPILL_SCAN_CAP)
    except OSError:
        return frozenset()
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


def unrecorded_evidence_indicators(entries, case_dir=None, *,
                                   min_calls: int = 3,
                                   limit: int | None = None) -> list[dict]:
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
    """
    from collections import defaultdict

    from core.claim_graph import asserted_finding_entries
    from core.entities import discriminative, extract, scan_text
    from core.execution_log import is_disposition
    from core.forensic_citation import own_words_entry

    own = case_file_names(case_dir) if case_dir else set()
    own_urls = own_tool_urls(case_dir)
    # A ruling the run has since withdrawn is no ruling; a call that echoed
    # the run's own state (a claim snapshot) showed no evidence.
    asserted = {id(f) for f in asserted_finding_entries(
        [e for e in entries or [] if isinstance(e, dict) and e.get("type") == "finding"],
        case_dir)}

    def _is_case_file(ent: str) -> bool:
        kind, value = ioc_type(ent), ioc_value(ent)
        if kind not in ("file", "path"):
            return False
        base = value.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1].casefold()
        return base in own

    recorded: set[str] = set()          # entities a finding or disposition names
    named: list[str] = []               # their text, for values quoted as printed
    seen: dict[str, set] = defaultdict(set)  # entity -> distinct tool call_ids
    for e in entries or []:
        if not isinstance(e, dict):
            continue
        kind = e.get("type")
        # A ruling is a finding or a disposition; plain narration is neither,
        # or announcing a search would silence the demand for its result.
        if kind == "finding" or is_disposition(e):
            if kind == "finding" and id(e) not in asserted:
                continue
            desc = str(e.get("description") or e.get("content") or "")
            recorded.update(extract(desc))
            named.append(desc)
        elif (kind == "tool_call" and e.get("success") is not False
              and not own_words_entry(e)):
            blob = (f"{e.get('cmd') or ''} "
                    f"{scan_text(str(e.get('stdout_excerpt') or ''))}")
            ents = discriminative(extract(blob))
            spill = str(e.get("stdout_file") or "")
            if spill:
                ents |= _spilled_entities(spill)
            if _lists_names(str(e.get("cmd") or "")):
                ents = {x for x in ents if ioc_type(x) in ("file", "path")}
            for ent in ents:
                if (_is_pivotable(ent) and not _is_case_file(ent)
                        and _url_key(ioc_value(ent)) not in own_urls
                        and not _format_namespace(ent)):
                    seen[ent].add(e.get("call_id"))

    # A finding that quotes the value as it was shown has named it, whether
    # or not the extractor reads that spelling back as the same entity (an
    # account is shown as domain/user, not as the DOMAIN\user it was read
    # from). Otherwise a demand could be met only by guessing the spelling.
    text = "\n".join(named).casefold()

    def _recorded(ent: str) -> bool:
        if ent in recorded:
            return True
        # A trailing dot ends a sentence as often as it continues a name, so
        # only a dot that carries on into another word disqualifies a match.
        return bool(text) and re.search(
            rf"(?<![\w.]){re.escape(ioc_value(ent).casefold())}(?!\w)(?!\.\w)",
            text) is not None

    # How crowded a kind is has to be read off the evidence, not off what is
    # left to ask about: counting only the unrecorded would let a kind too
    # crowded to ask about become askable as the analyst rules on it, so
    # obeying the invitation to record the one that matters would turn the
    # rest into a demand.
    population: dict[str, int] = {}
    for ent, cids in seen.items():
        if len(cids) >= min_calls:
            population[ioc_type(ent)] = population.get(ioc_type(ent), 0) + 1

    out = [{"value": ioc_value(ent), "kind": ioc_type(ent), "calls": len(cids),
            "kind_population": population[ioc_type(ent)]}
           for ent, cids in seen.items()
           if len(cids) >= min_calls and not _recorded(ent)]
    out.sort(key=lambda d: (_indicator_weight(d["kind"], d["value"]), d["calls"]),
             reverse=True)
    return out[:limit]


# A ruling may be demanded on a recurring, unrecorded indicator only while
# the demand can be met. The evidence itself sets the population: a capture
# of ordinary browsing shows hundreds of distinct addresses and URLs, each in
# many calls, and ruling on them one by one clears nothing because the
# evidence supplies the next set. Recurrence separates nothing inside such a
# population, so the mechanism stops asking rather than pretend it can. The
# bound is per kind because populations differ by evidence class: process
# names saturate on any event log while the one URL in it stays askable.
UNRECORDED_DEMAND_CAP = 12


def unrecorded_demand(candidates, *, cap: int = UNRECORDED_DEMAND_CAP
                      ) -> tuple[list[dict], list[dict]]:
    """Split ``unrecorded_evidence_indicators`` output into what a gate may
    demand a ruling on and what it may only mention.

    Returns ``(demand, bulk)``, each in the ranking it was given. A kind with
    more than ``cap`` members is bulk in full; if the sparse kinds together
    exceed ``cap``, everything is bulk and nothing is demanded.
    """
    from collections import Counter

    cands = list(candidates or [])
    left = Counter(d["kind"] for d in cands)
    # The producer reports how many of a kind the evidence shows; falling back
    # to what is still unrecorded keeps a hand-built list working.
    dense = {k for k in left
             if max([int(d.get("kind_population") or 0) for d in cands
                     if d["kind"] == k] + [left[k]]) > cap}
    demand = [d for d in cands if d["kind"] not in dense]
    if len(demand) > cap:
        return [], cands
    return demand, [d for d in cands if d["kind"] in dense]


def describe_unrecorded_bulk(bulk) -> str:
    """One line for indicators mentioned but not demanded: counts per kind
    and the values seen most often."""
    from collections import Counter

    rows = list(bulk or [])
    kinds = Counter(d["kind"] for d in rows)
    # Ties broken by value so the same evidence names the same three in every
    # process, rather than following dictionary order.
    top = sorted(rows, key=lambda d: (-int(d.get("calls") or 0), str(d["value"])))[:3]
    return (", ".join(f"{n} {k}" for k, n in kinds.most_common())
            + "; seen most: " + ", ".join(str(d["value"]) for d in top))


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


def _source_is_about_host(rel_path: str, host: str) -> bool:
    """True when a source path belongs to ``host`` — one matcher for the
    whole codebase (core.forensic_citation.host_mentioned)."""
    from core.forensic_citation import host_mentioned
    return host_mentioned(host, str(rel_path or "").replace("\\", "/"))


def _table_holds(path: Path, terms: list[str]) -> set[str]:
    """The terms whose literal text the file holds, read as bytes in UTF-8
    and UTF-16LE, case-insensitive for ASCII letters. Cached per file state
    (real path, size, mtime) and term for the process, so a refresh every
    turn reads a table again only for a term it was not yet asked about."""
    try:
        st = path.stat()
    except OSError:
        return set()
    key = (os.path.realpath(path), st.st_size, st.st_mtime_ns)
    known = _TABLE_TERMS.setdefault(key, {})
    todo = [t for t in dict.fromkeys(terms) if t not in known]
    if todo:
        forms = {t: (t.encode("utf-8"), t.encode("utf-16-le")) for t in todo}
        keep = max(len(b) for pair in forms.values() for b in pair) - 1
        found: set[str] = set()
        tail = b""
        try:
            with open(path, "rb") as fh:
                while len(found) < len(todo):
                    chunk = fh.read(_SCAN_CHUNK)
                    if not chunk:
                        break
                    buf = tail + chunk.lower()
                    for t, pair in forms.items():
                        if t not in found and (pair[0] in buf or pair[1] in buf):
                            found.add(t)
                    tail = buf[-keep:] if keep > 0 else b""
        except OSError:
            return {t for t in terms if known.get(t)}
        for t in todo:
            known[t] = t in found
    return {t for t in terms if known.get(t)}


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
            rank = 2 if _source_is_about_host(rel, value) else 1
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
    # The analyst's own indicators first: they are owed a search before any
    # belief exists, and the cap below must never push them out in favour
    # of something a later belief mentioned.
    indicators: dict[str, str] = {}
    try:
        from core.case_knowledge import prior_indicators
        indicators.update(prior_indicators(case_dir))
    except Exception:  # noqa: BLE001 — a brief problem must not stop pivots
        pass
    # Then the operator's threat context, at most half the ledger: the
    # sweep covers every row, and the run's own indicators keep their room.
    try:
        from core.threat_context import pivot_indicators
        for ioc, row_id in pivot_indicators(case_dir).items():
            indicators.setdefault(ioc, row_id)
    except Exception:  # noqa: BLE001
        pass
    indicators.update(indicators_from_beliefs(case_dir))
    sources = evidence_sources(case_dir)
    blocked = _blocked_sources(case_dir)

    pivots: dict[str, Any] = {}
    for ioc, origin in list(indicators.items())[:MAX_PIVOTS]:
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


def observe_search(
    case_dir: str | os.PathLike,
    *,
    blob: str,
    persist: bool = True,
) -> list[str]:
    """Mark pivots searched from one tool call's arguments/command text.

    A pivot-target pair counts as searched when a single tool call mentions
    both the indicator and the target — that is exactly the shape of
    "grep this indicator in that source".
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
    closed: list[str] = []
    for ioc, entry in pivots.items():
        if not _indicator_searched(ioc, text):
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


def open_pivots(case_dir: str | os.PathLike) -> list[dict[str, Any]]:
    """Indicators with evidence still un-searched, worst first."""
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


def pivot_stats(case_dir: str | os.PathLike) -> dict[str, int]:
    ledger = load_pivots(case_dir)
    stats = {"pivots": 0, "pending": 0, "searched": 0, "blocked": 0}
    for entry in (ledger.get("pivots") or {}).values():
        stats["pivots"] += 1
        for status in (entry.get("targets") or {}).values():
            if status in stats:
                stats[status] += 1
    return stats


def format_pivot_nudge(pivots: Iterable[dict[str, Any]], *, limit: int = 5) -> str:
    """The message the loop shows the model: concrete searches still owed."""
    items = list(pivots)[:limit]
    if not items:
        return ""
    lines = [
        "[ioc pivot] New indicators were recorded but not carried back "
        "across the evidence. Each indicator below must be searched for in "
        "the listed sources (grep / table query / EVTX filter as "
        "appropriate). A corroborating hit is a finding "
        "(misc.record_finding). A clean miss is a disposition, not a "
        "finding: record it with misc.record_agent_message(content=..., "
        "disposition=True), naming the indicator and the sources searched. "
        "A finding that only documents a search is a false conclusion, and "
        "the indicators it names re-open this queue. If a source genuinely "
        "cannot be examined (corrupt, empty, unparseable), record the "
        "failed attempt with coverage.mark_blocked(path, reason); a source "
        "blocked there is no longer owed here.",
    ]
    for p in items:
        kind, value = ioc_type(p["ioc"]), ioc_value(p["ioc"])
        lines.append(f"- {kind} {value}"
                     + (f" (from {p['origin']})" if p.get("origin") else ""))
        for target in p["pending"][:6]:
            lines.append(f"    search in: {target}")
    return "\n".join(lines)
